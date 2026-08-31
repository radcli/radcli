#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# A spec-conformant RFC 5176-over-RadSec Dynamic Authorization Client (DAC)
# test double, for tests/dae-radsec-tests.sh. Unlike tests/dae-client.py (a
# hostile UDP DAC that connects OUT to a listening raddaeserver), the roles
# here are reversed, matching RFC 6614 SS2.5/SS2.1 and RFC 7360 SS3.1: under
# RadSec there is no separate DAE listener at all, so this script plays the
# AAA server's role -- it listens with TLS and ACCEPTS the connection
# radcli/raddaeserver itself dials out (its ordinary authserver connection,
# forced eagerly by radcli_dae_start() under RadSec, REQ-DAE-INIT-010) --
# then sends a Disconnect-Request/CoA-Request back down that SAME accepted
# TLS socket, exactly as RFC 6614 SS2.5 describes ("RADIUS/TLS servers
# transmit the same packet types on connections they have accepted").
#
# Reuses tests/dae-client.py's wire-format helpers (build_packet(),
# response_authenticator_ok()) instead of a second, independently-written
# copy of the same security-sensitive packet construction.
#
# Usage:
#   python3 dae-tls-client.py --host H --port P --cert C --key K
#                             [--secret radsec] [--code disconnect|coa]
#                             [--id N] [--attr Name=Value]... [--timeout S]
#
# Prints one line, exactly like dae-client.py:
#   REPLY code=<N> id=<N> auth=ok|bad attrs=<hex>
#   NO-REPLY

import argparse
import binascii
import importlib.util
import os
import socket
import ssl
import sys

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location('dae_client', os.path.join(_here, 'dae-client.py'))
dae_client = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dae_client)


def main():
    parser = argparse.ArgumentParser(description='RadSec Dynamic Authorization Client test double')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--secret', default='radsec',
                        help="the RFC 6614/7360 fixed secret ('radsec' for TLS, "
                             "'radius/dtls' for DTLS -- this script only speaks TLS)")
    parser.add_argument('--code', choices=['disconnect', 'coa'], default='disconnect')
    parser.add_argument('--id', type=int, default=1)
    parser.add_argument('--attr', action='append', default=[], metavar='Name=Value')
    parser.add_argument('--timeout', type=float, default=5.0)
    args = parser.parse_args()

    code = dae_client.DISCONNECT_REQUEST if args.code == 'disconnect' else dae_client.COA_REQUEST
    attrs = b''.join(dae_client.parse_named_attr(spec) for spec in args.attr)
    packet = dae_client.build_packet(code, args.id, args.secret, attrs, 'correct', 'correct', False)
    request_auth = packet[4:20]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    listener.settimeout(args.timeout)

    try:
        raw_conn, _addr = listener.accept()
    except socket.timeout:
        print('NO-REPLY', flush=True)
        return
    raw_conn.settimeout(args.timeout)

    try:
        conn = ctx.wrap_socket(raw_conn, server_side=True)
    except ssl.SSLError as e:
        sys.stderr.write('dae-tls-client: TLS handshake failed: %s\n' % e)
        print('NO-REPLY', flush=True)
        return

    try:
        conn.sendall(packet)
        reply = conn.recv(4096)
    except (socket.timeout, ssl.SSLError, ConnectionError):
        print('NO-REPLY', flush=True)
        return

    if not reply:
        print('NO-REPLY', flush=True)
        return

    auth_ok = dae_client.response_authenticator_ok(reply, request_auth, args.secret)
    reply_code = reply[0] if len(reply) >= 1 else -1
    reply_id = reply[1] if len(reply) >= 2 else -1
    print('REPLY code=%d id=%d auth=%s attrs=%s' %
          (reply_code, reply_id, 'ok' if auth_ok else 'bad',
           binascii.hexlify(reply[20:]).decode()), flush=True)


if __name__ == '__main__':
    main()
