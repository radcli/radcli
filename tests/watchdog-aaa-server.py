#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Peer for tests/watchdog-aaa.c: unlike tests/dae-watchdog-server.py (a
# DAE-over-RadSec peer that accepts exactly one connection and never answers
# ordinary AAA traffic), this script is a plain RadSec RADIUS server -- it
# answers both ordinary Access-Request traffic and an RFC 5997 Status-Server
# watchdog with a normal Access-Accept-shaped reply. tests/watchdog-aaa.c
# drives radcli purely through radcli_request_new()/_perform() (ordinary AAA)
# and radcli_ctx_dispatch()'s internal watchdog send -- never radcli_dae_*() -- so this peer
# never needs to speak DAE either.
#
# Accepts connections in a loop (not just once, --accepts N): tests/
# watchdog-aaa.c's dead-peer-reconnect check (its phase 4) sends nothing at
# all for well over 2.5x watchdog-interval, which this script's own
# --timeout read timeout on the now-idle first connection naturally times
# out on -- moving this script back to accept() -- before radcli's own
# elapsed-time-based dead-peer detection (lib/dae.c's
# radcli2_priv_dae_send_watchdog(), REQ-WATCHDOG-NET-003) forces a reconnect and dials
# a *second* connection this script needs to still be waiting for. --timeout
# is kept short relative to that phase's wait for exactly this reason (see
# its --help text below).
#
# Usage:
#   python3 watchdog-aaa-server.py --host H --port P --cert C --key K
#                                  [--secret radsec] [--timeout S]
#                                  [--accept-timeout S] [--accepts N]
#
# Prints flushed log lines:
#   ACCEPT n
#   AUTH id=N msgauth=ok|bad|absent
#   WATCHDOG id=N msgauth=ok|bad|absent
#   DONE

import argparse
import hashlib
import hmac
import socket
import ssl
import struct
import sys

ATTR_MESSAGE_AUTHENTICATOR = 80
ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
STATUS_SERVER = 12


def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def message_authenticator_ok(pkt, secret):
    """See tests/dae-watchdog-server.py's identical helper: HMAC-MD5 over
    the packet with its own Message-Authenticator zeroed (RFC 2869 SS5.14),
    the same construction lib/sendserver.c's add_msg_auth_attr() uses."""
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
    """RFC 2865 SS3 Response Authenticator plus an RFC 3579 SS3.2
    Message-Authenticator (radcli's RADCLI_OPT_REQUIRE_MESSAGE_AUTHENTICATOR
    defaults to required, unlike tests/dae-watchdog-server.py's identical-
    looking helper, whose reply is never actually decoded -- only ID-matched
    away -- so it could skip this)."""
    ma_hdr = bytes([ATTR_MESSAGE_AUTHENTICATOR, 18])
    body_zeroed = ma_hdr + bytes(16)
    length = 20 + len(body_zeroed)
    header_no_auth = struct.pack('!BBH', ACCESS_ACCEPT, ident, length)
    # RFC 3579 SS3.2: computed with the REQUEST Authenticator in the
    # Authenticator field, not the Response Authenticator being computed
    # below.
    ma = hmac.new(secret.encode(), header_no_auth + request_auth + body_zeroed,
                  hashlib.md5).digest()
    body = ma_hdr + ma
    resp_auth = hashlib.md5(header_no_auth + request_auth + body + secret.encode()).digest()
    return header_no_auth + resp_auth + body


def recv_one_packet(conn):
    """Reads one RADIUS packet, or None on a closed/errored connection."""
    header = recv_exact(conn, 20)
    if header is None:
        return None
    code, ident, length = struct.unpack('!BBH', header[:4])
    request_auth = header[4:20]
    rest = recv_exact(conn, length - 20) if length > 20 else b''
    if rest is None:
        return None
    return code, ident, request_auth, header + rest


def serve_connection(conn, args, log):
    conn.settimeout(args.timeout)
    while True:
        try:
            pkt = recv_one_packet(conn)
        except (socket.timeout, ssl.SSLError, ConnectionError) as e:
            log('CONN-END %s' % e)
            return

        if pkt is None:
            log('CONN-END closed')
            return

        code, ident, request_auth, raw = pkt
        msgauth = message_authenticator_ok(raw, args.secret)

        if code == ACCESS_REQUEST:
            log('AUTH id=%d msgauth=%s' % (ident, msgauth))
            try:
                conn.sendall(build_access_accept(ident, request_auth, args.secret))
            except (socket.timeout, ssl.SSLError, ConnectionError) as e:
                log('AUTH-REPLY-FAILED %s' % e)
                return
        elif code == STATUS_SERVER:
            log('WATCHDOG id=%d msgauth=%s' % (ident, msgauth))
            try:
                conn.sendall(build_access_accept(ident, request_auth, args.secret))
            except (socket.timeout, ssl.SSLError, ConnectionError) as e:
                log('WATCHDOG-REPLY-FAILED %s' % e)
                return
        else:
            log('UNEXPECTED code=%d id=%d' % (code, ident))


def main():
    parser = argparse.ArgumentParser(description='Plain RadSec AAA + watchdog test peer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--secret', default='radsec')
    parser.add_argument('--timeout', type=float, default=30.0,
                        help='per-connection read timeout -- kept short '
                             'relative to --accept-timeout so this script '
                             'gives up on an idle first connection and '
                             'returns to accept() well before radcli\'s own '
                             'much-longer dead-peer wait forces a reconnect '
                             '(tests/watchdog-aaa.c phase 4)')
    parser.add_argument('--accept-timeout', type=float, default=30.0,
                        help='listener accept() timeout, independent of '
                             '--timeout')
    parser.add_argument('--accepts', type=int, default=1,
                        help='number of TLS connections to accept before exiting')
    args = parser.parse_args()

    def log(msg):
        print(msg, flush=True)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    listener.settimeout(args.accept_timeout)

    for n in range(1, args.accepts + 1):
        try:
            raw_conn, _addr = listener.accept()
        except socket.timeout:
            log('NO-ACCEPT accept-timeout')
            return
        raw_conn.settimeout(args.timeout)

        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except ssl.SSLError as e:
            sys.stderr.write('watchdog-aaa-server: TLS handshake failed: %s\n' % e)
            log('NO-ACCEPT handshake-failed')
            return

        log('ACCEPT %d' % n)
        serve_connection(conn, args, log)

    log('DONE')


if __name__ == '__main__':
    main()
