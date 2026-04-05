# RADIUS test server (`tests/radius-server.py`)

A minimal RADIUS server written in Python 3 (stdlib only) used by the test suite
to craft responses that a real server such as FreeRADIUS would not produce.
Currently used by `tests/msg-auth-tests.sh` to test Message-Authenticator handling.

## Invocation

```
python3 tests/radius-server.py [--port PORT] [--secret SECRET] \
                               [--msg-auth correct|absent|wrong]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--port` | 1812 | UDP port to listen on |
| `--secret` | `testing123` | Shared secret (must match the client config) |
| `--msg-auth` | `correct` | How to handle the Message-Authenticator attribute in the reply |

The server accepts one UDP packet at a time, sends one reply, and loops forever.
It exits when killed (SIGTERM/SIGKILL).

---

## RADIUS packet structure

Every RADIUS packet starts with a fixed 20-byte header, followed by zero or more
attributes encoded as type-length-value (TLV) triples:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      | Identifier    |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                     Authenticator (16)                        |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Attributes ...
```

**Code** (1 byte): packet type.  Relevant codes:

| Code | Name |
|------|------|
| 1 | Access-Request |
| 2 | Access-Accept |
| 3 | Access-Reject |
| 11 | Access-Challenge |

**Identifier** (1 byte): copied from the request into the reply so the client can
match responses to requests.

**Length** (2 bytes, big-endian): total packet length including the header.

**Authenticator** (16 bytes): its meaning differs between request and reply (see
below).

**Attributes**: a sequence of TLVs, each structured as:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
|     Type      |    Length     |  Value ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

`Length` includes the two header bytes, so a 4-byte integer attribute has
`Length = 6` (2 header + 4 value).

---

## The two Authenticator fields

### Request Authenticator (inside Access-Request)

The client fills this with 16 random bytes.  It serves as a nonce: the server
uses it when computing the Response Authenticator and when verifying the
Message-Authenticator sent by the client.

### Response Authenticator (inside Access-Accept / Access-Reject / …)

Computed by the server over the entire reply packet:

```
ResponseAuth = MD5(Code || Identifier || Length || RequestAuth || Attributes || Secret)
```

The MD5 input is the concatenation of: the reply's code, identifier, and length
(from the reply header); the **request**'s authenticator (16 bytes); all reply
attributes; and the shared secret.  The result is placed in bytes 4–19 of the
reply.

The client recomputes the same MD5 to verify that the response came from a server
that knows the shared secret.

In the server:

```python
def compute_response_authenticator(code, ident, length, req_auth, attrs, secret):
    data = struct.pack('!BBH', code, ident, length) + req_auth + attrs + secret.encode()
    return hashlib.md5(data).digest()
```

---

## Message-Authenticator attribute (type 80, RFC 3579)

The Message-Authenticator attribute (attribute type 80) carries an HMAC-MD5
over the entire packet.  Its purpose is to authenticate the packet contents,
closing an MD5-prefix attack (BLAST RADIUS / CVE-2024-3596) that is possible
when only the Response Authenticator is used.

The attribute is 18 bytes long:

```
+------+------+--------------------------------------------------+
| 0x50 | 0x12 |  HMAC-MD5 (16 bytes)                            |
+------+------+--------------------------------------------------+
  type   len
  (80)   (18)
```

The HMAC-MD5 is computed over the **complete** packet with the 16 value bytes of
this attribute set to all-zeros:

```
MA = HMAC-MD5(packet_with_MA_zeroed, secret)
```

Per `draft-ietf-radext-deprecating-radius` (the BLAST RADIUS mitigation), the
Message-Authenticator MUST be the **first** attribute in Access-Accept /
Access-Reject / Access-Challenge replies.  radcli enforces this by checking that
the first attribute byte is type 80 before trusting the value.

In the server:

```python
def compute_hmac_md5(packet, secret):
    return hmac.new(secret.encode(), packet, hashlib.md5).digest()
```

---

## Packet construction order

Building a reply involves a circular dependency: the Response Authenticator
covers the attributes (including MA), but the MA covers the full packet
(including the Response Authenticator).  The dependency is broken by using
all-zeros as the MA placeholder during both computations, then filling in the
real MA at the end:

```
1. Build reply attributes with MA value = 00 00 ... 00  (16 zero bytes)
2. ResponseAuth = MD5(code + id + len + RequestAuth + attrs + secret)
3. Assemble packet = header(code+id+len) + ResponseAuth + attrs
   (MA value is still all-zeros in the assembled packet)
4. MA = HMAC-MD5(packet, secret)   ← packet still has zero MA
5. Write MA into packet at the known offset
```

This is why `handle_packet` builds `attrs` first, computes `resp_auth`, assembles
the `bytearray`, and only then overwrites the MA field:

```python
# Step 1 – MA placeholder first (position check requires it to be first)
ma_placeholder = build_ma_attr()          # type=80, len=18, value=00*16
attrs = ma_placeholder + build_reply_attrs()
ma_offset = 22                            # 20 (header) + 2 (type+len)

# Step 2+3 – Response Authenticator and packet assembly
resp_auth = compute_response_authenticator(ACCESS_ACCEPT, ident, total_len,
                                           req_auth, attrs, secret)
packet = bytearray(struct.pack('!BBH', ACCESS_ACCEPT, ident, total_len)
                   + resp_auth + attrs)

# Step 4+5 – fill in real MA (packet still has zero MA at ma_offset)
ma_value = compute_hmac_md5(bytes(packet), secret)
packet[ma_offset:ma_offset + MA_LEN] = ma_value
```

---

## `--msg-auth` modes

| Mode | What the server sends |
|------|-----------------------|
| `correct` | MA present, first, with valid HMAC-MD5 |
| `absent` | No MA attribute at all |
| `wrong` | MA present, first, but value is 16 zero bytes (invalid HMAC) |
| `not-first` | MA present, valid HMAC-MD5, but placed after the other attributes |

`wrong` is produced by skipping steps 4+5 above: the MA attribute is present in
the packet (so the "first attribute" position check passes) but its value is
never filled in, so the HMAC comparison in the client fails.

`not-first` places the MA attribute after `build_reply_attrs()` instead of
before it.  The HMAC is still computed correctly, so value verification passes —
but radcli rejects the packet because `recv_buffer[AUTH_HDR_LEN]` is not type 80.

---

## Adding a new test scenario

Typical extension points:

**Different response code** (e.g. Access-Reject):  change `ACCESS_ACCEPT` to `3`
in `handle_packet`.

**Additional attributes**: add a `build_*_attr` helper following the same
`struct.pack('!BB...', type, length, value...)` pattern, then append it in
`build_reply_attrs`.

**New `--msg-auth` mode**: add a choice to the `argparse` definition and a
corresponding branch after the `packet` assembly in `handle_packet`.

**Inspect the incoming request**: the raw request bytes are in `data`; the
attributes start at `data[20:]` and can be walked with a `while` loop reading
`type = data[pos]`, `length = data[pos+1]`, `value = data[pos+2:pos+length]`,
`pos += length`.
