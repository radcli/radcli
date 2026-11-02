#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# TCP (--plain) or TLS peer for tests/session-timeout.c, recording what a
# client sends over each connection:
#
#   once   never answers; counts the copies of the first request received
#          on the first connection, which stays open, and the connections
#          opened, until --timeout; prints COPIES=n CONNECTIONS=m
#   drop   reads the first request and closes the connection unanswered;
#          answers the request when it arrives again on a new connection;
#          prints RESENT-ON-NEW, or NOT-RESENT on timeout
#   stall  answers the first request, reads the second and closes the
#          connection unanswered; then accepts new TCP connections but never
#          sends a byte on them (a TLS handshake that never completes);
#          prints STALLED after --timeout
#
# Prints READY once listening.

import argparse
import hashlib
import hmac
import select
import socket
import ssl
import struct
import time

ACCESS_ACCEPT = 2
ATTR_MESSAGE_AUTHENTICATOR = 80


def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except (ssl.SSLError, ConnectionError, socket.timeout):
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


def build_access_accept(pkt, secret):
    ident, request_auth = pkt[1], pkt[4:20]
    ma_hdr = bytes([ATTR_MESSAGE_AUTHENTICATOR, 18])
    body_zeroed = ma_hdr + bytes(16)
    header_no_auth = struct.pack('!BBH', ACCESS_ACCEPT, ident, 20 + len(body_zeroed))
    ma = hmac.new(secret, header_no_auth + request_auth + body_zeroed, hashlib.md5).digest()
    body = ma_hdr + ma
    resp_auth = hashlib.md5(header_no_auth + request_auth + body + secret).digest()
    return header_no_auth + resp_auth + body


def accept_conn(listener, ctx):
    raw, _addr = listener.accept()
    raw.settimeout(listener.gettimeout())
    if ctx is None:
        return raw
    return ctx.wrap_socket(raw, server_side=True)


def serve_once(listener, ctx, conn, args):
    first = recv_packet(conn)
    if first is None:
        print('NO-REQUEST', flush=True)
        return
    copies, conns, extra = 1, 1, []
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        watch = [listener] + ([conn] if conn is not None else [])
        ready, _, _ = select.select(watch, [], [], max(0, deadline - time.monotonic()))
        if listener in ready:
            raw, _addr = listener.accept()
            extra.append(raw)
            conns += 1
        if conn is not None and conn in ready:
            pkt = recv_packet(conn)
            if pkt is None:
                conn = None
            elif pkt == first:
                copies += 1
    print('COPIES=%d CONNECTIONS=%d' % (copies, conns), flush=True)


def serve_drop(listener, ctx, conn, args):
    first = recv_packet(conn)
    if first is None:
        print('NO-REQUEST', flush=True)
        return
    conn.close()
    try:
        second = accept_conn(listener, ctx)
    except (socket.timeout, ssl.SSLError):
        print('NOT-RESENT', flush=True)
        return
    pkt = recv_packet(second)
    if pkt is None or pkt[1] != first[1]:
        print('NOT-RESENT', flush=True)
        return
    second.sendall(build_access_accept(pkt, args.secret))
    print('RESENT-ON-NEW', flush=True)
    recv_exact(second, 1)  # let the client read the reply


def serve_stall(listener, ctx, conn, args):
    pkt = recv_packet(conn)
    if pkt is None:
        print('NO-REQUEST', flush=True)
        return
    conn.sendall(build_access_accept(pkt, args.secret))
    if recv_packet(conn) is None:
        print('NO-REQUEST second', flush=True)
        return
    conn.close()
    stalled = []
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([listener], [], [], max(0, deadline - time.monotonic()))
        if listener in ready:
            raw, _addr = listener.accept()
            stalled.append(raw)
    print('STALLED', flush=True)


def main():
    parser = argparse.ArgumentParser(description='session reconnect test peer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--plain', action='store_true', help='plain TCP, no TLS')
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--mode', choices=['once', 'drop', 'stall'], required=True)
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
    listener.listen(4)
    listener.settimeout(args.timeout)
    print('READY', flush=True)

    try:
        conn = accept_conn(listener, ctx)
    except (socket.timeout, ssl.SSLError) as e:
        print('NO-CONNECTION %s' % e, flush=True)
        return

    {'once': serve_once, 'drop': serve_drop, 'stall': serve_stall}[args.mode](
        listener, ctx, conn, args)


if __name__ == '__main__':
    main()
