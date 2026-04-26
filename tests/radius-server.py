#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# Minimal RADIUS server for testing Message-Authenticator handling.
# Sends Access-Accept responses with configurable Message-Authenticator:
#   correct  - valid HMAC-MD5 (per RFC 3579), placed first per BLAST RADIUS spec
#   absent   - no Message-Authenticator attribute in the response
#   wrong    - attribute present (first) but value is all-zeros (deliberately incorrect)
#
# Usage:
#   python3 radius-server.py [--port 1812] [--secret testing123] \
#                            [--msg-auth correct|absent|wrong]

import argparse
import hashlib
import hmac
import socket
import struct

# RADIUS codes
ACCESS_REQUEST = 1
ACCESS_ACCEPT  = 2

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

def handle_packet(data, secret, msg_auth_mode, attrs_mode='normal'):
    """
    Parse an Access-Request and build an Access-Accept response.
    Returns the response bytes, or None if the packet is not an Access-Request.
    """
    if len(data) < 20:
        return None

    code, ident, _pkt_len = struct.unpack('!BBH', data[:4])
    req_auth = data[4:20]

    if code != ACCESS_REQUEST:
        return None

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

def run(port, secret, msg_auth_mode, attrs_mode='normal'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    print(f"radius-server: listening on port {port}, msg-auth={msg_auth_mode}, attrs={attrs_mode}",
          flush=True)

    while True:
        data, addr = sock.recvfrom(4096)
        response = handle_packet(data, secret, msg_auth_mode, attrs_mode)
        if response is not None:
            sock.sendto(response, addr)

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
    args = parser.parse_args()
    run(args.port, args.secret, args.msg_auth, args.attrs)

if __name__ == '__main__':
    main()
