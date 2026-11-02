#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# TCP (--plain) or TLS peer for tests/nonblock-backpressure.c. Shrinks its
# receive buffer before the handshake, answers the client's first request,
# then stops reading for --hold seconds so the client's send window fills,
# and restores the buffer. Afterwards it reads every request until the client closes the
# connection, checking each one's framing and Message-Authenticator, and
# answers each with an Access-Accept whose Reply-Message echoes the
# request's User-Name.
#
# User-Names are "<batch>-<n>" (old-0, old-1, ..., new-0, ...). Prints
# READY once listening, then one line:
#   VERDICT ok old=<m> new=<n>   old-0..old-(m-1) and new-0..new-(n-1),
#                                each exactly once, in that order, intact
#   VERDICT <reason>             anything else

import argparse
import hashlib
import hmac
import importlib.util
import os
import socket
import ssl
import struct
import time

_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    'session_timeout_server', os.path.join(_here, 'session-timeout-server.py'))
sts = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sts)

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ATTR_USER_NAME = 1
ATTR_REPLY_MESSAGE = 18
ATTR_MESSAGE_AUTHENTICATOR = 80


def parse_attrs(pkt):
    """Return [(type, offset, value)], or None if the attributes are not
    framed exactly by the packet's Length."""
    attrs, pos = [], 20
    while pos < len(pkt):
        if pos + 2 > len(pkt) or pkt[pos + 1] < 2 or pos + pkt[pos + 1] > len(pkt):
            return None
        attrs.append((pkt[pos], pos, pkt[pos + 2:pos + pkt[pos + 1]]))
        pos += pkt[pos + 1]
    return attrs


def check_request(pkt, secret):
    """Return the request's User-Name if it is an intact Access-Request
    (RFC 3579 SS3.2 Message-Authenticator verifies every byte), else None."""
    if pkt[0] != ACCESS_REQUEST:
        return None
    attrs = parse_attrs(pkt)
    if attrs is None:
        return None
    names = [v for t, _o, v in attrs if t == ATTR_USER_NAME]
    mas = [(o, v) for t, o, v in attrs if t == ATTR_MESSAGE_AUTHENTICATOR]
    if len(names) != 1 or len(mas) != 1 or len(mas[0][1]) != 16:
        return None
    off = mas[0][0]
    zeroed = pkt[:off + 2] + bytes(16) + pkt[off + 18:]
    if not hmac.compare_digest(hmac.new(secret, zeroed, hashlib.md5).digest(), mas[0][1]):
        return None
    return names[0].decode()


def build_accept(pkt, secret, echo):
    ident, request_auth = pkt[1], pkt[4:20]
    # Message-Authenticator first, as radcli requires over TCP.
    echo_attr = bytes([ATTR_REPLY_MESSAGE, 2 + len(echo)]) + echo
    body = bytes([ATTR_MESSAGE_AUTHENTICATOR, 18]) + bytes(16) + echo_attr
    hdr = struct.pack('!BBH', ACCESS_ACCEPT, ident, 20 + len(body))
    ma = hmac.new(secret, hdr + request_auth + body, hashlib.md5).digest()
    body = bytes([ATTR_MESSAGE_AUTHENTICATOR, 18]) + ma + echo_attr
    resp_auth = hashlib.md5(hdr + request_auth + body + secret).digest()
    return hdr + resp_auth + body


def verdict(names):
    """Check that names is old-0.. then new-0.., each exactly once."""
    expect = {'old': 0, 'new': 0}
    batch = 'old'
    for name in names:
        b, _sep, n = name.partition('-')
        if b == 'new' and batch == 'old':
            batch = 'new'
        if b != batch or not n.isdigit() or int(n) != expect[b]:
            return 'out of sequence at %s after old=%d new=%d' % (
                name, expect['old'], expect['new'])
        expect[b] += 1
    return 'ok old=%d new=%d' % (expect['old'], expect['new'])


def main():
    parser = argparse.ArgumentParser(description='RADCLI_REQUEST_NONBLOCK backpressure peer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--plain', action='store_true', help='plain TCP, no TLS')
    parser.add_argument('--cert')
    parser.add_argument('--key')
    parser.add_argument('--secret', default='radsec')
    parser.add_argument('--hold', type=float, required=True)
    parser.add_argument('--timeout', type=float, default=30.0)
    args = parser.parse_args()
    secret = args.secret.encode()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # A small MSS: the client's kernel checks for send-buffer room only
    # between segments, so with loopback's own (larger than any request)
    # every write would be all-or-nothing, and no packet partly sent when
    # the window fills.
    listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 536)
    listener.bind((args.host, args.port))
    listener.listen(1)
    listener.settimeout(args.timeout)
    print('READY', flush=True)

    conn, _addr = listener.accept()
    # Linux raises this to its floor: still far below an autotuned buffer.
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
    conn.settimeout(args.timeout)
    if not args.plain:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
        conn = ctx.wrap_socket(conn, server_side=True)

    warmup = sts.recv_packet(conn)
    if warmup is None or check_request(warmup, secret) != 'warmup':
        print('VERDICT no intact warm-up request', flush=True)
        return
    conn.sendall(build_accept(warmup, secret, b'warmup'))

    time.sleep(args.hold)
    # Draining at the floor would outlast the client's timeout.
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)

    names = []
    while True:
        pkt = sts.recv_packet(conn)
        if pkt is None:
            break
        name = check_request(pkt, secret)
        if name is None:
            print('VERDICT corrupt request after %s' % (names[-1:] or ['warm-up']),
                  flush=True)
            return
        names.append(name)
        conn.sendall(build_accept(pkt, secret, name.encode()))
    print('VERDICT %s' % verdict(names), flush=True)


if __name__ == '__main__':
    main()
