#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Peer for tests/dae-radsec-stress.c: a single-threaded, purely blocking
# (no asyncio, no O_NONBLOCK) TLS "AAA server" that accepts the one
# connection radcli/dae-radsec-stress dials out, then answers a stream of
# alternating Access-Request/Accounting-Request messages while also
# interleaving unsolicited Disconnect-Request/CoA-Request messages on the
# exact same connection -- the realistic mixed traffic pattern the stress
# test's state-machine assertions are about.
#
# Reuses tests/dae-client.py's CoA/Disconnect wire-format helpers
# (build_packet(), the RFC 5176 SS2.3/Accounting-Request-style
# Authenticator convention) instead of a second, independently-written
# copy of the same security-sensitive packet construction. Access-Accept/
# Access-Reject/Accounting-Response use a different, simpler Response
# Authenticator convention (RFC 2865 SS3): MD5(header with the *request's*
# own Authenticator substituted in, plus reply attributes, plus secret) --
# implemented directly below (build_reply()), since dae-client.py has no
# equivalent (it only ever builds CoA/Disconnect-style requests).
#
# Reads exactly one RADIUS packet at a time by its own wire Length field
# (RFC 6613/6614 framing), not by assuming one recv() call returns exactly
# one packet the way lib/tls.c's tls_recvfrom() simplifies for radcli's own
# receive side -- this script is the peer under no such obligation, and
# TLS record boundaries are not guaranteed to align with recv() calls in
# general.
#
# Usage:
#   python3 radsec-stress-server.py --port P --cert C --key K
#                                   --ordinary N --dae-every K --secret radsec

import argparse
import socket
import ssl
import struct
import sys
import hashlib
import importlib.util
import os

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('dae_client', os.path.join(_here, 'dae-client.py'))
dae_client = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dae_client)

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCOUNTING_REQUEST = 4
ACCOUNTING_RESPONSE = 5


def recvall(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('peer closed while %d/%d bytes were read' % (len(buf), n))
        buf += chunk
    return buf


def recv_one_packet(sock):
    """Reads exactly one RADIUS packet, using its own wire Length field to
    know where it ends -- correct regardless of how TLS/TCP happened to
    chunk it, unlike assuming one recv() == one packet."""
    header = recvall(sock, 4)
    length = struct.unpack('!H', header[2:4])[0]
    if length < 20:
        raise ValueError('wire Length %d is smaller than a RADIUS header' % length)
    rest = recvall(sock, length - 4)
    return header + rest


def build_reply(code, ident, request_vector, attrs, secret):
    """RFC 2865 SS3 Response Authenticator: MD5(Code+Id+Length+<the
    request's own Authenticator>+Attributes+Secret). The same formula RFC
    2866/5176 use for Accounting-Response/CoA-ACK/Disconnect-ACK too --
    the only thing that varies across packet types is how the *request's*
    own Authenticator was derived, which this function does not need to
    know: it just uses whatever 16 bytes the request actually carried."""
    header = struct.pack('!BBH', code, ident, 20 + len(attrs))
    digest = hashlib.md5(header + request_vector + attrs + secret.encode()).digest()
    return header + digest + attrs


def main():
    parser = argparse.ArgumentParser(description='DAE-over-RadSec stress test peer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--secret', default='radsec')
    parser.add_argument('--ordinary', type=int, required=True,
                        help='total Access-Request/Accounting-Request messages to answer')
    parser.add_argument('--dae-every', type=int, required=True,
                        help='send one unsolicited Disconnect/CoA message after every this '
                             'many ordinary requests answered')
    parser.add_argument('--timeout', type=float, default=25.0)
    args = parser.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    listener.settimeout(args.timeout)

    raw_conn, _addr = listener.accept()
    raw_conn.settimeout(args.timeout)
    conn = ctx.wrap_socket(raw_conn, server_side=True)

    access_count = 0
    dae_sent = 0
    dae_acked = 0
    answered = 0
    expected_dae = args.ordinary // args.dae_every
    # request_vector each outstanding DAE Identifier was sent with, keyed by
    # Identifier -- NOT a simple "expect the ack right after the request":
    # the client has independent sender threads issuing their own next
    # Access-Request/Accounting-Request concurrently with the dispatch
    # thread flushing this DAE message's queued ACK, and either can
    # legitimately reach the wire first. Dispatching every received packet
    # by its own Code, rather than by a fixed expected sequence, is what
    # makes this peer correct under that real concurrency instead of
    # misreading an ordinary request as if it were the DAE ack.
    pending_dae = {}

    DAE_REPLY_CODES = (dae_client.DISCONNECT_ACK, dae_client.DISCONNECT_NAK,
                       dae_client.COA_ACK, dae_client.COA_NAK)

    while answered < args.ordinary or dae_acked < expected_dae:
        pkt = recv_one_packet(conn)
        code, ident = pkt[0], pkt[1]
        request_vector = pkt[4:20]

        if code == ACCESS_REQUEST:
            reply_code = ACCESS_ACCEPT if (access_count % 2 == 0) else ACCESS_REJECT
            access_count += 1
            conn.sendall(build_reply(reply_code, ident, request_vector, b'', args.secret))
            answered += 1
        elif code == ACCOUNTING_REQUEST:
            conn.sendall(build_reply(ACCOUNTING_RESPONSE, ident, request_vector, b'', args.secret))
            answered += 1
        elif code in DAE_REPLY_CODES:
            if ident not in pending_dae:
                sys.stderr.write('radsec-stress-server: ACK/NAK with unknown/already-'
                                 'acked Identifier %d, aborting\n' % ident)
                sys.exit(1)
            dae_idx, req_auth = pending_dae.pop(ident)
            ok = dae_client.response_authenticator_ok(pkt, req_auth, args.secret)
            if not ok:
                sys.stderr.write('radsec-stress-server: DAE #%d ack/nak verification '
                                 'failed (id=%d)\n' % (dae_idx, ident))
                sys.exit(1)
            dae_acked += 1
        else:
            sys.stderr.write('radsec-stress-server: unexpected Code %d, aborting\n' % code)
            sys.exit(1)

        if (answered > 0 and answered % args.dae_every == 0 and
                dae_sent < expected_dae and (answered // args.dae_every) > dae_sent):
            dae_code = (dae_client.DISCONNECT_REQUEST if dae_sent % 2 == 0
                       else dae_client.COA_REQUEST)
            dae_id = 200 + dae_sent  # kept out of the 0..255 range ordinary Identifiers cycle through
            dae_id &= 0xff
            attrs = (dae_client.encode_attr(1, ('stress-user-%d' % dae_sent).encode()) +
                    dae_client.encode_attr(44, ('stress-sess-%d' % dae_sent).encode()))
            packet = dae_client.build_packet(dae_code, dae_id, args.secret, attrs,
                                             'correct', 'correct', False)
            pending_dae[dae_id] = (dae_sent, packet[4:20])
            conn.sendall(packet)
            dae_sent += 1

    print('radsec-stress-server: answered %d ordinary requests, sent/acked %d/%d DAE messages' %
          (answered, dae_sent, dae_acked), flush=True)


if __name__ == '__main__':
    main()
