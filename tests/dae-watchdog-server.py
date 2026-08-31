#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Peer for tests/dae-radsec-watchdog.c: unlike tests/dae-tls-client.py (which
# immediately sends its own Disconnect-Request/CoA-Request down the accepted
# RadSec connection and waits for exactly one reply), this script sends
# nothing on its own -- it accepts the connection radcli/dae-radsec-watchdog
# dials out (forced eagerly by radcli_dae_start(), REQ-DAE-INIT-010) and then
# waits, passively, for an unprompted RFC 5997 Status-Server (Code 12) to
# arrive: exactly what radcli_ctx_send_watchdog() is supposed to produce on
# its own, without this script asking for it first.
#
# Verifies the received packet's Message-Authenticator (RFC 2869 SS5.14)
# against the RFC 6614 SS2.3/RFC 7360 SS3.2 fixed RadSec secret, using the
# same HMAC-MD5-over-zeroed-attribute construction radcli itself uses
# (lib/request.c's add_msg_auth_attr(), lib/sendserver.c). Optionally replies
# with an Access-Accept (--reply), to confirm radcli's own dispatch() side
# absorbs an unsolicited, unmatched reply without disruption (checked by the
# driving shell test via raddaeserver's own log, not by this script).
#
# Usage:
#   python3 dae-watchdog-server.py --host H --port P --cert C --key K
#                                  [--secret radsec] [--timeout S] [--reply]
#
# Prints one line:
#   WATCHDOG code=<N> id=<N> msgauth=ok|bad|absent
#   NO-WATCHDOG <reason>

import argparse
import hashlib
import hmac
import os
import socket
import ssl
import struct
import sys

ATTR_MESSAGE_AUTHENTICATOR = 80
STATUS_SERVER = 12
ACCESS_ACCEPT = 2


def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def message_authenticator_ok(pkt, secret):
    """Finds the (first) Message-Authenticator attribute in pkt's attributes
    and verifies it: HMAC-MD5 over the whole packet with that attribute's
    value zeroed and the packet's own (real, not zeroed) Request
    Authenticator in place -- RFC 2869 SS5.14, the same construction
    lib/sendserver.c's add_msg_auth_attr() uses to build one. Returns
    'ok'/'bad'/'absent'."""
    body = pkt[20:]
    off = 0
    ma_off = None
    ma_value = None
    while off + 2 <= len(body):
        attr_type = body[off]
        attr_len = body[off + 1]
        if attr_len < 2 or off + attr_len > len(body):
            break
        if attr_type == ATTR_MESSAGE_AUTHENTICATOR:
            ma_off = off
            ma_value = body[off + 2:off + attr_len]
        off += attr_len
    if ma_off is None:
        return 'absent'
    zeroed = body[:ma_off + 2] + bytes(len(ma_value)) + body[ma_off + 2 + len(ma_value):]
    zeroed_pkt = pkt[:20] + zeroed
    calc = hmac.new(secret.encode(), zeroed_pkt, hashlib.md5).digest()
    return 'ok' if hmac.compare_digest(calc, ma_value) else 'bad'


def build_access_accept(ident, request_auth, secret):
    header = struct.pack('!BBH', ACCESS_ACCEPT, ident, 20)
    resp_auth = hashlib.md5(header + request_auth + secret.encode()).digest()
    return header[:4] + resp_auth


def main():
    parser = argparse.ArgumentParser(description='DAE-over-RadSec watchdog test peer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--secret', default='radsec')
    parser.add_argument('--timeout', type=float, default=15.0)
    parser.add_argument('--reply', action='store_true',
                        help='send back an Access-Accept, to confirm radcli '
                             'absorbs an unsolicited reply cleanly')
    args = parser.parse_args()

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
        print('NO-WATCHDOG accept-timeout', flush=True)
        return
    raw_conn.settimeout(args.timeout)

    try:
        conn = ctx.wrap_socket(raw_conn, server_side=True)
    except ssl.SSLError as e:
        sys.stderr.write('dae-watchdog-server: TLS handshake failed: %s\n' % e)
        print('NO-WATCHDOG handshake-failed', flush=True)
        return

    try:
        header = recv_exact(conn, 20)
        if header is None:
            print('NO-WATCHDOG connection-closed', flush=True)
            return
        code, ident, length = struct.unpack('!BBH', header[:4])
        request_auth = header[4:20]
        rest = recv_exact(conn, length - 20) if length > 20 else b''
        if rest is None:
            print('NO-WATCHDOG connection-closed-mid-packet', flush=True)
            return
        pkt = header + rest
    except (socket.timeout, ssl.SSLError, ConnectionError) as e:
        print('NO-WATCHDOG %s' % e, flush=True)
        return

    if code != STATUS_SERVER:
        print('NO-WATCHDOG unexpected-code=%d' % code, flush=True)
        return

    msgauth = message_authenticator_ok(pkt, args.secret)

    if args.reply:
        try:
            conn.sendall(build_access_accept(ident, request_auth, args.secret))
        except (socket.timeout, ssl.SSLError, ConnectionError) as e:
            sys.stderr.write('dae-watchdog-server: reply send failed: %s\n' % e)

    print('WATCHDOG code=%d id=%d msgauth=%s' % (code, ident, msgauth), flush=True)


if __name__ == '__main__':
    main()
