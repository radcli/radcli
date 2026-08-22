#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
#
# A hostile RFC 5176 dynamic-authorization client (DAC), for testing
# radcli_ctx_dispatch()'s/radcli_dae_process()'s validation pipeline without
# a real FreeRADIUS or strongSwan DAC -- the same reason tests/radius-server.py
# exists on the other side of the wire: "to craft responses that a real
# server such as FreeRADIUS would not produce". A real DAC will not send a
# Disconnect-Request with a deliberately wrong Message-Authenticator on
# request; this one will.
#
# Python 3, standard library only, no dependency on radcli itself, so a bug
# in the library cannot mask itself by being on both ends of the test.
#
# Usage:
#   python3 dae-client.py [--host H] [--port 3799] [--secret S]
#                         [--code disconnect|coa] [--id N] [--source-port N]
#                         [--attr Name=Value]...       (repeatable)
#                         [--proxy-state HEX]...       (repeatable)
#                         [--authenticator correct|wrong]
#                         [--msg-auth correct|absent|wrong]
#                         [--event-timestamp now|stale|future|absent]
#                         [--repeat N] [--truncate N] [--bad-length]
#                         [--timeout SECONDS]
#
# Prints one line per attempt (there are --repeat of them) to stdout:
#   REPLY code=<N> id=<N> auth=ok|bad attrs=<hex>
#   NO-REPLY
# so a driving shell test can grep the exact outcome of each send without
# this script itself deciding pass/fail -- see doc/dae-test-client.md.

import argparse
import binascii
import hashlib
import hmac
import socket
import struct
import time

DISCONNECT_REQUEST = 40
DISCONNECT_ACK = 41
DISCONNECT_NAK = 42
COA_REQUEST = 43
COA_ACK = 44
COA_NAK = 45

ATTR_MESSAGE_AUTHENTICATOR = 80
ATTR_PROXY_STATE = 33
ATTR_EVENT_TIMESTAMP = 55

MA_LEN = 16

# Enough of the dictionary to build the attributes these tests need;
# (type, wire-kind) -- 'string' is raw bytes, 'integer'/'date' a 4-byte
# big-endian value, 'ipaddr' a dotted-quad, 'ipv6addr' an IPv6 literal.
ATTR_TYPES = {
    'User-Name': (1, 'string'),
    'NAS-IP-Address': (4, 'ipaddr'),
    'NAS-Port': (5, 'integer'),
    'Framed-IP-Address': (8, 'ipaddr'),
    'NAS-Identifier': (32, 'string'),
    'Proxy-State': (33, 'string'),
    'Acct-Session-Id': (44, 'string'),
    'Event-Timestamp': (55, 'date'),
    'Chargeable-User-Identity': (89, 'string'),
    'NAS-IPv6-Address': (95, 'ipv6addr'),
    'Error-Cause': (101, 'integer'),
    'Framed-IPv6-Address': (168, 'ipv6addr'),
    'Message-Authenticator': (ATTR_MESSAGE_AUTHENTICATOR, 'string'),
}


def encode_value(kind, value):
    if kind == 'string':
        return value.encode() if isinstance(value, str) else value
    if kind in ('integer', 'date'):
        return struct.pack('!L', int(value) & 0xffffffff)
    if kind == 'ipaddr':
        return socket.inet_aton(value)
    if kind == 'ipv6addr':
        return socket.inet_pton(socket.AF_INET6, value)
    raise ValueError('unknown attribute kind %r' % kind)


def encode_attr(attr_type, value_bytes):
    if len(value_bytes) > 253:
        raise ValueError('attribute value too long')
    return struct.pack('!BB', attr_type, 2 + len(value_bytes)) + value_bytes


def parse_named_attr(spec):
    """'Name=Value' -> (type, bytes), using ATTR_TYPES for the wire kind, or
    a bare numeric Name for an attribute this table does not know (encoded
    as a raw string)."""
    name, _, value = spec.partition('=')
    if name in ATTR_TYPES:
        attr_type, kind = ATTR_TYPES[name]
        return encode_attr(attr_type, encode_value(kind, value))
    if name.isdigit():
        return encode_attr(int(name), value.encode())
    raise SystemExit('dae-client: unknown attribute name %r (not in the '
                      'built-in table, and not numeric)' % name)


def build_event_timestamp(mode):
    if mode == 'absent':
        return b''
    now = int(time.time())
    if mode == 'now':
        ts = now
    elif mode == 'stale':
        ts = now - 3600
    elif mode == 'future':
        ts = now + 3600
    else:
        raise SystemExit('dae-client: unknown --event-timestamp value %r' % mode)
    return encode_attr(ATTR_EVENT_TIMESTAMP, struct.pack('!L', ts))


def build_packet(code, ident, secret, attrs, authenticator_mode, msg_auth_mode, bad_length):
    """Builds a Disconnect-Request/CoA-Request the way a real DAC does:
    Message-Authenticator (if not 'absent') computed with the Authenticator
    field treated as sixteen zero octets, then the Request Authenticator
    hashed over the finished packet (RFC 5176 SS2.3, RFC 2869 SS5.14 -- the
    Accounting-Request convention: both quantities are themselves derived
    from a hash of the packet, so a fixed zero placeholder is the only
    non-circular order)."""
    secret_b = secret.encode()
    zero_auth = bytes(16)

    body = attrs
    if msg_auth_mode != 'absent':
        placeholder = struct.pack('!BB', ATTR_MESSAGE_AUTHENTICATOR, 2 + MA_LEN) + bytes(MA_LEN)
        wire_len = 20 + len(body) + len(placeholder)
        zero_ma_pkt = struct.pack('!BBH', code, ident, wire_len) + zero_auth + body + placeholder
        ma_value = hmac.new(secret_b, zero_ma_pkt, hashlib.md5).digest()
        if msg_auth_mode == 'wrong':
            ma_value = bytes((b + 1) % 256 for b in ma_value)  # deliberately incorrect
        elif msg_auth_mode != 'correct':
            raise SystemExit('dae-client: unknown --msg-auth value %r' % msg_auth_mode)
        body = body + struct.pack('!BB', ATTR_MESSAGE_AUTHENTICATOR, 2 + MA_LEN) + ma_value

    wire_len = 20 + len(body)
    if bad_length:
        wire_len += 4096  # the wire Length field lies about how much follows

    header = struct.pack('!BBH', code, ident, wire_len)
    request_auth = hashlib.md5(header + zero_auth + body + secret_b).digest()
    if authenticator_mode == 'wrong':
        request_auth = bytes((b + 1) % 256 for b in request_auth)
    elif authenticator_mode != 'correct':
        raise SystemExit('dae-client: unknown --authenticator value %r' % authenticator_mode)

    return header + request_auth + body


def response_authenticator_ok(reply, request_auth, secret):
    if len(reply) < 20:
        return False
    received = reply[4:20]
    calc = hashlib.md5(reply[:4] + request_auth + reply[20:] + secret.encode()).digest()
    return hmac.compare_digest(received, calc)


def main():
    parser = argparse.ArgumentParser(description='Hostile RFC 5176 dynamic-authorization client')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=3799)
    parser.add_argument('--secret', default='testing123')
    parser.add_argument('--code', choices=['disconnect', 'coa'], default='disconnect')
    parser.add_argument('--id', type=int, default=1)
    parser.add_argument('--source-port', type=int, default=0)
    parser.add_argument('--attr', action='append', default=[], metavar='Name=Value')
    parser.add_argument('--proxy-state', action='append', default=[], metavar='HEX')
    parser.add_argument('--authenticator', choices=['correct', 'wrong'], default='correct')
    parser.add_argument('--msg-auth', dest='msg_auth', choices=['correct', 'absent', 'wrong'],
                        default='correct')
    parser.add_argument('--event-timestamp', dest='event_timestamp',
                        choices=['now', 'stale', 'future', 'absent'], default='absent')
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--truncate', type=int, default=None,
                        help='send only the first N bytes of the packet')
    parser.add_argument('--bad-length', action='store_true',
                        help='the wire Length field claims more bytes than were sent')
    parser.add_argument('--timeout', type=float, default=2.0)
    args = parser.parse_args()

    code = DISCONNECT_REQUEST if args.code == 'disconnect' else COA_REQUEST

    attrs = b''.join(parse_named_attr(spec) for spec in args.attr)
    attrs += b''.join(encode_attr(ATTR_PROXY_STATE, binascii.unhexlify(h)) for h in args.proxy_state)
    attrs += build_event_timestamp(args.event_timestamp)

    packet = build_packet(code, args.id, args.secret, attrs, args.authenticator,
                          args.msg_auth, args.bad_length)
    if args.truncate is not None:
        packet = packet[:args.truncate]

    # The Request Authenticator this attempt actually sent (needed to check
    # a reply's Response Authenticator) -- re-read from the built packet
    # rather than recomputed, so --authenticator wrong is reflected too.
    request_auth = packet[4:20] if len(packet) >= 20 else bytes(16)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', args.source_port))
    sock.settimeout(args.timeout)

    for _ in range(args.repeat):
        sock.sendto(packet, (args.host, args.port))
        try:
            reply, _addr = sock.recvfrom(4096)
        except socket.timeout:
            print('NO-REPLY', flush=True)
            continue
        auth_ok = response_authenticator_ok(reply, request_auth, args.secret)
        reply_code = reply[0] if len(reply) >= 1 else -1
        reply_id = reply[1] if len(reply) >= 2 else -1
        print('REPLY code=%d id=%d auth=%s attrs=%s' %
              (reply_code, reply_id, 'ok' if auth_ok else 'bad',
               binascii.hexlify(reply[20:]).decode()), flush=True)


if __name__ == '__main__':
    main()
