#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# TLS (or, with --plain, TCP) peer for tests/session-framing.c: answers
# every Access-Request with an Access-Accept and every Accounting-Request
# with an Accounting-Response, laid out in TLS records or TCP segments in a
# way that only Length-field framing (RFC 6614 SS3.4 (1), RFC 6613 SS2.6.4)
# can take apart. All requests must arrive on one connection.
#
#   split     each reply is sent in two writes, the first holding only part
#             of the RADIUS header
#   coalesce  reads --batch requests, then sends in one write, for each, an
#             unauthenticated stray Access-Accept followed by the real reply
#   badlen    answers the first request with a packet whose Length is 4 (an
#             RFC 6613 SS2.6.4 framing error), then reports whether the next
#             request arrives on the same connection or a new one, and
#             answers it if new
#
# Prints READY once listening, then DONE replied=N on success, or
# SECOND-CONNECTION/SAME-CONNECTION in badlen mode.

import argparse
import hashlib
import hmac
import select
import socket
import ssl
import struct
import sys
import time

ACCESS_ACCEPT = 2
ACCOUNTING_REQUEST = 4
ACCOUNTING_RESPONSE = 5
ATTR_MESSAGE_AUTHENTICATOR = 80


def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except (ssl.SSLError, ConnectionError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_packet(conn):
    header = recv_exact(conn, 20)
    if header is None:
        return None
    length = struct.unpack('!H', header[2:4])[0]
    rest = recv_exact(conn, length - 20) if length > 20 else b''
    if rest is None:
        return None
    return header + rest


def build_access_accept(ident, request_auth, secret):
    ma_hdr = bytes([ATTR_MESSAGE_AUTHENTICATOR, 18])
    body_zeroed = ma_hdr + bytes(16)
    header_no_auth = struct.pack('!BBH', ACCESS_ACCEPT, ident, 20 + len(body_zeroed))
    ma = hmac.new(secret, header_no_auth + request_auth + body_zeroed, hashlib.md5).digest()
    body = ma_hdr + ma
    resp_auth = hashlib.md5(header_no_auth + request_auth + body + secret).digest()
    return header_no_auth + resp_auth + body


def build_accounting_response(ident, request_auth, secret):
    header_no_auth = struct.pack('!BBH', ACCOUNTING_RESPONSE, ident, 20)
    resp_auth = hashlib.md5(header_no_auth + request_auth + secret).digest()
    return header_no_auth + resp_auth


def reply_for(pkt, secret):
    if pkt[0] == ACCOUNTING_REQUEST:
        return build_accounting_response(pkt[1], pkt[4:20], secret)
    return build_access_accept(pkt[1], pkt[4:20], secret)


def stray_for(pkt):
    # A well-formed packet that matches no request: wrong Identifier, and an
    # all-zero Response Authenticator.
    return struct.pack('!BBH', ACCESS_ACCEPT, pkt[1] ^ 0x55, 20) + bytes(16)


def accept_conn(listener, ctx):
    raw, _addr = listener.accept()
    raw.settimeout(listener.gettimeout())
    if ctx is None:
        return raw
    return ctx.wrap_socket(raw, server_side=True)


def serve_split(conn, args):
    for _ in range(args.requests):
        pkt = recv_packet(conn)
        if pkt is None:
            print('NO-REQUEST', flush=True)
            return
        reply = reply_for(pkt, args.secret)
        conn.sendall(reply[:3])
        time.sleep(0.1)
        conn.sendall(reply[3:])
    print('DONE replied=%d' % args.requests, flush=True)


def serve_coalesce(conn, args):
    replied = 0
    while replied < args.requests:
        out = b''
        for _ in range(args.batch):
            pkt = recv_packet(conn)
            if pkt is None:
                print('NO-REQUEST', flush=True)
                return
            out += stray_for(pkt) + reply_for(pkt, args.secret)
        conn.sendall(out)
        replied += args.batch
    print('DONE replied=%d' % replied, flush=True)


def serve_badlen(listener, ctx, conn, args):
    pkt = recv_packet(conn)
    if pkt is None:
        print('NO-REQUEST', flush=True)
        return
    conn.sendall(struct.pack('!BBH', ACCESS_ACCEPT, pkt[1], 4) + bytes(16))

    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        watch = [listener] + ([conn] if conn is not None else [])
        ready, _, _ = select.select(watch, [], [], deadline - time.monotonic())
        if conn is not None and (conn in ready or (ctx is not None and conn.pending())):
            if recv_packet(conn) is not None:
                print('SAME-CONNECTION', flush=True)
                return
            conn = None  # closed by the client
            continue
        if listener in ready:
            second = accept_conn(listener, ctx)
            pkt = recv_packet(second)
            if pkt is None:
                print('NO-REQUEST second connection', flush=True)
                return
            second.sendall(reply_for(pkt, args.secret))
            print('SECOND-CONNECTION', flush=True)
            # Let the client read the reply before the socket goes away.
            recv_exact(second, 1)
            return
    print('NO-REQUEST timeout', flush=True)


def main():
    parser = argparse.ArgumentParser(description='TCP/TLS framing test peer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--plain', action='store_true', help='plain TCP, no TLS')
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--mode', choices=['split', 'coalesce', 'badlen'], required=True)
    parser.add_argument('--requests', type=int, default=2)
    parser.add_argument('--batch', type=int, default=1)
    parser.add_argument('--secret', default='radsec')
    parser.add_argument('--timeout', type=float, default=15.0)
    args = parser.parse_args()
    args.secret = args.secret.encode()

    ctx = None
    if not args.plain:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(2)
    listener.settimeout(args.timeout)
    print('READY', flush=True)

    try:
        conn = accept_conn(listener, ctx)
    except (socket.timeout, ssl.SSLError) as e:
        print('NO-CONNECTION %s' % e, flush=True)
        return

    try:
        if args.mode == 'split':
            serve_split(conn, args)
        elif args.mode == 'coalesce':
            serve_coalesce(conn, args)
        else:
            serve_badlen(listener, ctx, conn, args)
    except (socket.timeout, ssl.SSLError, ConnectionError) as e:
        sys.stderr.write('session-framing-server: %s\n' % e)
        print('NO-REQUEST %s' % e, flush=True)


if __name__ == '__main__':
    main()
