#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Dedicated reproducer peer for tests/request-tls-secret.c: proves
# radcli_encode_request() (lib/request.c) uses the RFC 6614 SS2.3/RFC 7360
# SS3.2 fixed RadSec secret ("radsec"/"radius/dtls") -- not whatever (empty,
# ordinarily) secret is configured on the authserver -- for BOTH halves of
# an Access-Request that depend on it:
#
#   1. the Message-Authenticator attribute (RFC 2869 SS5.14 HMAC-MD5)
#   2. the User-Password attribute's RFC 2865 SS5.2 encryption
#
# Before the fix, radcli_request_new()/_perform() read their secret straight
# from the configured authserver value (empty, since a TLS authserver
# cannot carry an inline secret outside PSK form) and passed that -- not
# rh->so.static_secret -- into radcli_encode_request(), so both the
# Message-Authenticator and the encrypted User-Password were computed with
# the wrong key. This script decodes both directly against the known-correct
# secret and reports each independently, rather than just accepting or
# rejecting the packet, so a partial fix (one symptom but not the other)
# would still be caught.
#
# Usage:
#   python3 request-tls-secret-server.py --port P --cert C --key K
#                                        [--secret radsec] [--expect-password test]
#
# Prints one line:
#   AUTH id=N msgauth=ok|bad|absent password=ok|bad

import argparse
import hashlib
import hmac
import socket
import ssl
import struct
import sys

ATTR_USER_NAME = 1
ATTR_USER_PASSWORD = 2
ATTR_MESSAGE_AUTHENTICATOR = 80
ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2


def recv_exact(conn, n):
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def parse_attrs(body):
    attrs = []
    off = 0
    while off + 2 <= len(body):
        t = body[off]
        length = body[off + 1]
        if length < 2 or off + length > len(body):
            break
        attrs.append((t, body[off + 2:off + length]))
        off += length
    return attrs


def message_authenticator_ok(pkt, secret):
    """See tests/dae-watchdog-server.py's identical helper."""
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


def decrypt_user_password(ciphertext, secret, request_auth):
    """RFC 2865 SS5.2: p_i = c_i XOR MD5(secret + prev), prev = Request
    Authenticator for i=1, c_{i-1} otherwise; NUL padding stripped."""
    secret_b = secret.encode()
    plaintext = b''
    prev = request_auth
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        b = hashlib.md5(secret_b + prev).digest()
        plaintext += bytes(x ^ y for x, y in zip(block, b))
        prev = block
    return plaintext.rstrip(b'\x00')


def build_access_accept(ident, request_auth, secret):
    ma_hdr = bytes([ATTR_MESSAGE_AUTHENTICATOR, 18])
    body_zeroed = ma_hdr + bytes(16)
    length = 20 + len(body_zeroed)
    header_no_auth = struct.pack('!BBH', ACCESS_ACCEPT, ident, length)
    ma = hmac.new(secret.encode(), header_no_auth + request_auth + body_zeroed,
                  hashlib.md5).digest()
    body = ma_hdr + ma
    resp_auth = hashlib.md5(header_no_auth + request_auth + body + secret.encode()).digest()
    return header_no_auth + resp_auth + body


def main():
    parser = argparse.ArgumentParser(description='radcli_encode_request() TLS-secret reproducer peer')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    parser.add_argument('--secret', default='radsec')
    parser.add_argument('--expect-password', default='test')
    parser.add_argument('--timeout', type=float, default=15.0)
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
        print('NO-AUTH accept-timeout', flush=True)
        return
    raw_conn.settimeout(args.timeout)

    try:
        conn = ctx.wrap_socket(raw_conn, server_side=True)
    except ssl.SSLError as e:
        sys.stderr.write('request-tls-secret-server: TLS handshake failed: %s\n' % e)
        print('NO-AUTH handshake-failed', flush=True)
        return

    try:
        header = recv_exact(conn, 20)
        if header is None:
            print('NO-AUTH connection-closed', flush=True)
            return
        code, ident, length = struct.unpack('!BBH', header[:4])
        request_auth = header[4:20]
        rest = recv_exact(conn, length - 20) if length > 20 else b''
        if rest is None:
            print('NO-AUTH connection-closed-mid-packet', flush=True)
            return
        pkt = header + rest
    except (socket.timeout, ssl.SSLError, ConnectionError) as e:
        print('NO-AUTH %s' % e, flush=True)
        return

    if code != ACCESS_REQUEST:
        print('NO-AUTH unexpected-code=%d' % code, flush=True)
        return

    msgauth = message_authenticator_ok(pkt, args.secret)

    password_status = 'absent'
    for t, v in parse_attrs(pkt[20:]):
        if t == ATTR_USER_PASSWORD:
            decrypted = decrypt_user_password(v, args.secret, request_auth)
            password_status = 'ok' if decrypted == args.expect_password.encode() else 'bad'
            break

    try:
        conn.sendall(build_access_accept(ident, request_auth, args.secret))
    except (socket.timeout, ssl.SSLError, ConnectionError) as e:
        sys.stderr.write('request-tls-secret-server: reply send failed: %s\n' % e)

    print('AUTH id=%d msgauth=%s password=%s' % (ident, msgauth, password_status), flush=True)


if __name__ == '__main__':
    main()
