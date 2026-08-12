#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Minimal RADIUS server for testing Message-Authenticator handling and
# Accounting-Request delivery, without root or a real freeradius/radiusd.
# Sends Access-Accept responses with configurable Message-Authenticator:
#   correct  - valid HMAC-MD5 (per RFC 3579), placed first per BLAST RADIUS spec
#   absent   - no Message-Authenticator attribute in the response
#   wrong    - attribute present (first) but value is all-zeros (deliberately incorrect)
# Accounting-Requests get an empty Accounting-Response (no Message-Authenticator
# handling, per REQ-NET-SEC-008).
#
# Usage:
#   python3 radius-server.py [--port 1812] [--secret testing123] \
#                            [--msg-auth correct|absent|wrong] [--no-reply]
#
# --no-reply logs every received Access-/Accounting-Request (proving it was
# delivered) but never sends a response -- used to test a client's
# non-blocking/fire-and-forget path (see acct-async-tests.sh) without relying
# on an unreachable-host timeout.
#
# --transport tls speaks RADIUS/TLS (RFC 6614) instead of plain UDP: the same
# Access-Accept packet bytes are framed over a TLS-wrapped TCP stream instead
# of individual UDP datagrams, so a test doesn't need a full TLS-capable RADIUS
# server (freeradius + root + network namespaces) just to exercise the
# client-side TLS handshake/hostname-verification path (see
# tls-verify-hostname-tests.sh).

import argparse
import hashlib
import hmac
import socket
import ssl
import struct

# RADIUS codes
ACCESS_REQUEST      = 1
ACCESS_ACCEPT       = 2
ACCOUNTING_REQUEST  = 4
ACCOUNTING_RESPONSE = 5

# Attribute types
ATTR_SERVICE_TYPE        = 6   # value 2 = Framed-User
ATTR_FRAMED_PROTOCOL     = 7   # value 1 = PPP
ATTR_FRAMED_IP_ADDRESS   = 8
ATTR_MESSAGE_AUTHENTICATOR = 80

MA_LEN = 16  # HMAC-MD5 digest size

def build_uint32_attr(attr_type, value):
    return struct.pack('!BBL', attr_type, 6, value)

def build_ipv4_attr(attr_type, addr_str):
    parts = [int(x) for x in addr_str.split('.')]
    return struct.pack('!BBBBBB', attr_type, 6, *parts)

def build_reply_attrs(attrs_mode='normal'):
    if attrs_mode == 'malformed-type-zero':
        # Valid attrs followed by an attr with type=0 (always invalid per RFC 2865)
        attrs  = build_uint32_attr(ATTR_SERVICE_TYPE, 2)
        attrs += build_uint32_attr(ATTR_FRAMED_PROTOCOL, 1)
        attrs += build_ipv4_attr(ATTR_FRAMED_IP_ADDRESS, '192.168.1.190')
        attrs += struct.pack('!BBL', 0, 6, 0)   # type=0, len=6
        return attrs
    if attrs_mode == 'malformed-len-one':
        # Valid attrs followed by an attr whose length field is 1 (< 2 minimum)
        attrs  = build_uint32_attr(ATTR_SERVICE_TYPE, 2)
        attrs += build_uint32_attr(ATTR_FRAMED_PROTOCOL, 1)
        attrs += build_ipv4_attr(ATTR_FRAMED_IP_ADDRESS, '192.168.1.190')
        attrs += struct.pack('!BB', ATTR_SERVICE_TYPE, 1)  # len=1 < 2
        return attrs
    if attrs_mode == 'malformed-overflow':
        # Valid attrs followed by an attr that declares len=255 but the packet
        # is truncated to only 7 bytes for it (type+len+5 payload bytes).
        # total_len is set honestly for those 7 bytes; the attr loop detects
        # that 255 > pb_len (7) and rejects the packet.
        attrs  = build_uint32_attr(ATTR_SERVICE_TYPE, 2)
        attrs += build_uint32_attr(ATTR_FRAMED_PROTOCOL, 1)
        attrs += build_ipv4_attr(ATTR_FRAMED_IP_ADDRESS, '192.168.1.190')
        attrs += struct.pack('!BB', ATTR_SERVICE_TYPE, 255) + b'\x00' * 5
        return attrs
    if attrs_mode == 'unknown-attrs':
        # Normal attrs plus two attributes with types unknown to the dictionary.
        # rc_avpair_gen2 must skip them and still decode Framed-Protocol.
        attrs  = build_uint32_attr(ATTR_SERVICE_TYPE, 2)
        attrs += build_uint32_attr(ATTR_FRAMED_PROTOCOL, 1)
        attrs += build_ipv4_attr(ATTR_FRAMED_IP_ADDRESS, '192.168.1.190')
        attrs += struct.pack('!BBL', 250, 6, 0)  # unknown type
        attrs += struct.pack('!BBL', 251, 6, 0)  # unknown type
        return attrs
    if attrs_mode == 'int-badlen':
        # Service-Type sent with length=5 instead of the correct 6 (4-byte INTEGER
        # + 2-byte header = 6).  rc_avpair_gen2 must skip it (bad length) and still
        # decode Framed-Protocol.
        attrs  = struct.pack('!BB', ATTR_SERVICE_TYPE, 5) + b'\x00' * 3  # len=5
        attrs += build_uint32_attr(ATTR_FRAMED_PROTOCOL, 1)
        attrs += build_ipv4_attr(ATTR_FRAMED_IP_ADDRESS, '192.168.1.190')
        return attrs
    if attrs_mode == 'vsa-unknown-subattrs':
        # VSA envelope for DSL-Forum (vendor 3561, registered in the dictionary
        # but with no sub-attributes defined).  rc_avpair_gen2 processes the
        # envelope, finds vendor 3561 known, then recurses into the sub-attrs.
        # Sub-attribute type 1 is unknown to the dictionary so it is skipped;
        # the recursive call returns *out=NULL with rc=0 (success, not an error).
        # The outer loop must treat that as a valid empty result and continue
        # decoding Framed-Protocol.
        DSL_FORUM_VENDOR = 3561
        sub_attr = struct.pack('!BBL', 1, 6, 0)        # sub-type=1, sub-len=6
        vsa_len  = 2 + 4 + len(sub_attr)               # type(1)+len(1)+vendor(4)+sub
        attrs  = struct.pack('!BB', 26, vsa_len) + struct.pack('!L', DSL_FORUM_VENDOR) + sub_attr
        attrs += build_uint32_attr(ATTR_FRAMED_PROTOCOL, 1)
        attrs += build_ipv4_attr(ATTR_FRAMED_IP_ADDRESS, '192.168.1.190')
        return attrs
    # normal
    attrs  = build_uint32_attr(ATTR_SERVICE_TYPE, 2)
    attrs += build_uint32_attr(ATTR_FRAMED_PROTOCOL, 1)
    attrs += build_ipv4_attr(ATTR_FRAMED_IP_ADDRESS, '192.168.1.190')
    return attrs

def build_ma_attr(value=None):
    """Build a Message-Authenticator TLV (type=80, len=18, value=16 bytes)."""
    v = value if value is not None else bytes(MA_LEN)
    return struct.pack('!BB', ATTR_MESSAGE_AUTHENTICATOR, 2 + MA_LEN) + v

def compute_response_authenticator(code, ident, length, req_auth, attrs, secret):
    """Response Authenticator = MD5(Code+ID+Length+RequestAuth+Attrs+Secret)."""
    data = (struct.pack('!BBH', code, ident, length) +
            req_auth + attrs + secret.encode())
    return hashlib.md5(data).digest()

def compute_hmac_md5(packet, secret):
    """HMAC-MD5 over the full packet (MA value must already be zeroed)."""
    return hmac.new(secret.encode(), packet, hashlib.md5).digest()

def handle_packet(data, secret, msg_auth_mode, attrs_mode='normal', no_reply=False):
    """
    Parse an Access-Request or Accounting-Request and build the matching
    reply. Returns the response bytes, or None if the packet's code is not
    recognized or --no-reply was requested (the packet is still logged as
    received either way -- see the print() below -- it is simply not
    answered, e.g. to test a non-blocking/fire-and-forget client path).
    """
    if len(data) < 20:
        return None

    code, ident, _pkt_len = struct.unpack('!BBH', data[:4])
    req_auth = data[4:20]

    if code not in (ACCESS_REQUEST, ACCOUNTING_REQUEST):
        return None

    code_name = 'Access-Request' if code == ACCESS_REQUEST else 'Accounting-Request'
    print(f"radius-server: received {code_name} id={ident}", flush=True)

    if no_reply:
        return None

    if code == ACCOUNTING_REQUEST:
        # No Message-Authenticator handling for accounting (REQ-NET-SEC-008);
        # an empty Accounting-Response is enough to exercise the reply path.
        total_len = 20
        resp_auth = compute_response_authenticator(
            ACCOUNTING_RESPONSE, ident, total_len, req_auth, b'', secret)
        return struct.pack('!BBH', ACCOUNTING_RESPONSE, ident, total_len) + resp_auth

    # Build attribute payload.  Per draft-ietf-radext-deprecating-radius,
    # Message-Authenticator MUST be the first attribute in the response.
    reply_attrs = build_reply_attrs(attrs_mode)
    if msg_auth_mode == 'absent':
        attrs = reply_attrs
        ma_offset = None
    elif msg_auth_mode in ('not-first', 'wrong-not-first'):
        # MA placed after the other attributes (not first)
        ma_placeholder = build_ma_attr()   # 18 bytes, value = 00..0
        attrs = reply_attrs + ma_placeholder
        # MA value starts at: header(20) + len(reply_attrs) + type(1) + len(1)
        ma_offset = 20 + len(reply_attrs) + 2
    else:
        # correct or wrong: MA is first
        ma_placeholder = build_ma_attr()   # 18 bytes, value = 00..0
        attrs = ma_placeholder + reply_attrs
        # MA value starts at: header(20) + type(1) + len(1) = offset 22
        ma_offset = 22

    total_len = 20 + len(attrs)

    if msg_auth_mode in ('correct', 'not-first'):
        # RFC 3579 §3.2: MA in responses is computed over the packet with the
        # Request Authenticator (from the Access-Request) in the Authenticator
        # field — NOT the Response Authenticator.  Build a scratch packet with
        # req_auth and zeroed MA, compute the HMAC, then fill in the result.
        scratch = bytearray(
            struct.pack('!BBH', ACCESS_ACCEPT, ident, total_len) + req_auth + attrs)
        ma_value = compute_hmac_md5(bytes(scratch), secret)
        scratch[ma_offset:ma_offset + MA_LEN] = ma_value
        attrs = bytes(scratch[20:])   # attrs now carry the real MA value

    # Compute Response Authenticator over the final attributes (MA filled in)
    resp_auth = compute_response_authenticator(
        ACCESS_ACCEPT, ident, total_len, req_auth, attrs, secret)

    # Assemble final packet with Response Authenticator in the header
    packet = struct.pack('!BBH', ACCESS_ACCEPT, ident, total_len) + resp_auth + attrs
    # 'wrong':  MA value stays as 16 zero bytes — deliberately incorrect
    # 'absent': no MA attribute at all

    return packet

def run(port, secret, msg_auth_mode, attrs_mode='normal', no_reply=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    print(f"radius-server: listening on port {port}, msg-auth={msg_auth_mode}, "
          f"attrs={attrs_mode}, no-reply={no_reply}", flush=True)

    while True:
        data, addr = sock.recvfrom(4096)
        response = handle_packet(data, secret, msg_auth_mode, attrs_mode, no_reply)
        if response is not None:
            sock.sendto(response, addr)

def recv_exact(conn, n):
    """Read exactly n bytes from a stream socket, or return None on EOF."""
    buf = b''
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_radius_packet(conn):
    """Read one RADIUS PDU from a stream socket, framed by its own header
    Length field (RFC 6614 uses no additional TCP-level framing)."""
    header = recv_exact(conn, 4)
    if header is None:
        return None
    (pkt_len,) = struct.unpack('!H', header[2:4])
    if pkt_len < 20:
        return None
    rest = recv_exact(conn, pkt_len - 4)
    if rest is None:
        return None
    return header + rest

def run_tls(port, secret, msg_auth_mode, tls_cert, tls_key, attrs_mode='normal'):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
    # This server only exercises the client's verification of the server's
    # certificate/hostname; it does not need (and does not request) a client
    # certificate.
    ctx.verify_mode = ssl.CERT_NONE

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)
    print(f"radius-server: listening (TLS) on port {port}, msg-auth={msg_auth_mode}, attrs={attrs_mode}",
          flush=True)

    while True:
        conn, addr = sock.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls_conn:
                while True:
                    data = recv_radius_packet(tls_conn)
                    if data is None:
                        break
                    response = handle_packet(data, secret, msg_auth_mode, attrs_mode)
                    if response is not None:
                        tls_conn.sendall(response)
        except (ssl.SSLError, OSError) as e:
            # Expected outcome of the hostname-mismatch tests: the client
            # aborts the handshake. Depending on how the client tears down
            # the connection this surfaces either as an SSLError (a TLS
            # alert was sent) or a plain OSError such as
            # ConnectionResetError (the client just dropped the TCP
            # connection) -- either way it must not take the accept loop
            # down with it, or every later connection would see
            # "Connection refused" instead of a fresh handshake attempt.
            print(f"radius-server: connection with {addr} failed: {e}", flush=True)
        finally:
            conn.close()

def main():
    parser = argparse.ArgumentParser(
        description='Minimal RADIUS server for Message-Authenticator testing')
    parser.add_argument('--port', type=int, default=1812)
    parser.add_argument('--secret', default='testing123')
    parser.add_argument('--msg-auth', dest='msg_auth',
                        choices=['correct', 'absent', 'wrong', 'not-first', 'wrong-not-first'],
                        default='correct')
    parser.add_argument('--attrs', dest='attrs',
                        choices=['normal', 'malformed-type-zero', 'malformed-len-one',
                                 'malformed-overflow', 'unknown-attrs', 'int-badlen',
                                 'vsa-unknown-subattrs'],
                        default='normal')
    parser.add_argument('--transport', choices=['udp', 'tls'], default='udp')
    parser.add_argument('--tls-cert', help='PEM certificate file (required for --transport tls)')
    parser.add_argument('--tls-key', help='PEM private key file (required for --transport tls)')
    parser.add_argument('--no-reply', action='store_true',
                        help='Log each received Access-/Accounting-Request but send no response '
                             '(models a slow/unresponsive accounting server for testing a '
                             'non-blocking client path). UDP transport only.')
    args = parser.parse_args()

    if args.transport == 'tls':
        if not args.tls_cert or not args.tls_key:
            parser.error('--transport tls requires --tls-cert and --tls-key')
        if args.no_reply:
            parser.error('--no-reply is only supported with --transport udp')
        run_tls(args.port, args.secret, args.msg_auth, args.tls_cert, args.tls_key, args.attrs)
    else:
        run(args.port, args.secret, args.msg_auth, args.attrs, args.no_reply)

if __name__ == '__main__':
    main()
