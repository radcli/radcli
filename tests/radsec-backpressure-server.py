#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Peer for tests/dae-radsec-backpressure.c: shrinks its own SO_RCVBUF
# immediately after accepting, then sends a burst of small Disconnect-
# Request messages back-to-back WITHOUT reading anything the client sends
# back -- filling the TCP window on the direction that matters (radcli's
# own reply sends) well before it would take with a default, un-shrunk
# buffer. See dae-radsec-backpressure.c's header comment for the full
# rationale.
#
# After the burst, drains and verifies whatever replies eventually arrive
# (there is no guarantee here that every one of them does, if radcli's
# send-side genuinely blocks/times out and gives up on the session as a
# result -- this script's own job is only to create the condition and
# report what it saw, not to assert pass/fail itself; that is
# dae-radsec-backpressure.c's job, via timing).
#
# Usage:
#   python3 radsec-backpressure-server.py --port P --cert C --key K
#                                         --count N --secret radsec

import argparse
import socket
import ssl
import struct
import sys
import importlib.util
import os

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('dae_client', os.path.join(_here, 'dae-client.py'))
dae_client = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dae_client)


def main():
    parser = argparse.ArgumentParser(description='DAE-over-RadSec backpressure test peer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--secret', default='radsec')
    parser.add_argument('--count', type=int, required=True)
    parser.add_argument('--timeout', type=float, default=15.0)
    args = parser.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    listener.settimeout(args.timeout)

    raw_conn, _addr = listener.accept()

    # Shrink our own receive buffer *before* the TLS handshake even starts,
    # so the client's write-side window is small for the entire connection,
    # not just once traffic happens to have already filled a large one.
    # Linux enforces a floor (net.ipv4.tcp_rmem's minimum) regardless of
    # what is requested here; asking for something far below any plausible
    # floor still reliably gets the smallest the kernel allows, which is
    # still a small fraction of the default (often autotuned into the
    # hundreds of KB).
    raw_conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)

    raw_conn.settimeout(args.timeout)
    conn = ctx.wrap_socket(raw_conn, server_side=True)

    sent = 0
    for i in range(args.count):
        attrs = (dae_client.encode_attr(1, ('backpressure-user-%d' % i).encode()) +
                dae_client.encode_attr(44, ('backpressure-sess-%d' % i).encode()))
        packet = dae_client.build_packet(dae_client.DISCONNECT_REQUEST, i & 0xff, args.secret,
                                         attrs, 'correct', 'correct', False)
        try:
            conn.sendall(packet)
            sent += 1
        except (socket.timeout, ssl.SSLError, ConnectionError) as e:
            # Expected if the peer we are provoking has already given up on
            # the session by the time we are still trying to send more of
            # the burst -- not this script's failure to report.
            sys.stderr.write('radsec-backpressure-server: send #%d stopped early: %s\n' % (i, e))
            break

    print('radsec-backpressure-server: sent %d/%d burst messages' % (sent, args.count), flush=True)

    # Best-effort drain of whatever replies do eventually show up (relevant
    # once the fix this test is meant to drive is in place: queued replies
    # should flush out once dae-radsec-backpressure.c is done with its own
    # measurement and stops needing to reason about timing). Not required
    # for the C test's own pass/fail verdict.
    conn.settimeout(2.0)
    drained = 0
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            drained += len(data)
    except (socket.timeout, ssl.SSLError, ConnectionError):
        pass
    print('radsec-backpressure-server: drained %d bytes of replies after the burst' % drained,
          flush=True)


if __name__ == '__main__':
    main()
