#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# TCP (--plain) or TLS peer for tests/session-timeout.c, recording what a
# client sends over each connection:
#
#   once   never answers; counts the copies of the first request received
#          on the first connection, which stays open, and the connections
#          opened, until --timeout; prints COPIES=n CONNECTIONS=m
#
# Prints READY once listening.

import argparse
import select
import socket
import ssl
import struct
import time

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


def main():
    parser = argparse.ArgumentParser(description='session reconnect test peer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--plain', action='store_true', help='plain TCP, no TLS')
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--mode', choices=['once'], required=True)
    parser.add_argument('--timeout', type=float, default=15.0)
    args = parser.parse_args()

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

    serve_once(listener, ctx, conn, args)


if __name__ == '__main__':
    main()
