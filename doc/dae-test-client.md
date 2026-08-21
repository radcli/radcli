# RFC 5176 dynamic-authorization test client (`tests/dae-client.py`)

A hostile Dynamic Authorization Client (DAC) written in Python 3 (stdlib only),
used by `tests/dae-tests.sh` to exercise `radcli_ctx_dispatch()`'s/
`radcli_dae_process()`'s validation pipeline against `src/raddaeserver.c`
without root, a network namespace, or a real FreeRADIUS/strongSwan DAC. The
same reason `tests/radius-server.py` exists on the other side of the wire: a
real DAC will not send a Disconnect-Request with a deliberately wrong
Message-Authenticator on request; this one will.

## Invocation

```
python3 tests/dae-client.py [--host H] [--port 3799] [--secret S]
                            [--code disconnect|coa] [--id N] [--source-port N]
                            [--attr Name=Value]...       (repeatable)
                            [--proxy-state HEX]...       (repeatable)
                            [--authenticator correct|wrong]
                            [--msg-auth correct|absent|wrong]
                            [--event-timestamp now|stale|future|absent]
                            [--repeat N] [--truncate N] [--bad-length]
                            [--timeout SECONDS]
```

| Option | Default | Meaning |
|--------|---------|---------|
| `--host` | `127.0.0.1` | Where to send the request |
| `--port` | 3799 | UDP port (RFC 5176's registered port) |
| `--secret` | `testing123` | Shared secret |
| `--code` | `disconnect` | `disconnect` (40) or `coa` (43) |
| `--id` | 1 | RADIUS Identifier |
| `--source-port` | 0 (kernel-assigned) | UDP source port to send from |
| `--attr` | none | `Name=Value`, repeatable; see the attribute table below |
| `--proxy-state` | none | Hex-encoded Proxy-State value, repeatable |
| `--authenticator` | `correct` | `wrong` flips every byte of the Request Authenticator after computing it correctly |
| `--msg-auth` | `correct` | `absent` omits the attribute; `wrong` flips every byte of a correctly-computed HMAC |
| `--event-timestamp` | `absent` | Adds an Event-Timestamp attribute: `now`, `stale` (-3600s), or `future` (+3600s) |
| `--repeat` | 1 | Send the identical packet (same Identifier, source port, Request Authenticator) this many times, each time waiting for a reply |
| `--truncate` | none | Send only the first N bytes of the packet |
| `--bad-length` | off | The wire Length field claims 4096 bytes more than were actually sent |
| `--timeout` | 2.0 | Seconds to wait for a reply before printing `NO-REPLY` |

For each attempt (`--repeat` of them), the script prints exactly one line to
stdout and does not itself decide pass/fail — a driving shell test greps the
line it expects:

```
REPLY code=<N> id=<N> auth=ok|bad attrs=<hex>
NO-REPLY
```

`auth=ok`/`auth=bad` is the client's own independent recomputation of the
reply's Response Authenticator (RFC 5176 §2.3) against the Request
Authenticator this attempt actually sent — not merely "a reply arrived".

### The `--attr` name table

`--attr` looks a name up in a small built-in table (not radcli's dictionary,
deliberately: this script has no dependency on radcli) covering the
attributes the DAE test matrix needs:

| Name | Type | Attribute |
|------|------|-----------|
| `User-Name` | string | 1 |
| `NAS-IP-Address` | ipaddr | 4 |
| `NAS-Port` | integer | 5 |
| `Framed-IP-Address` | ipaddr | 8 |
| `NAS-Identifier` | string | 32 |
| `Proxy-State` | string | 33 |
| `Acct-Session-Id` | string | 44 |
| `Event-Timestamp` | date | 55 |
| `Chargeable-User-Identity` | string | 89 |
| `NAS-IPv6-Address` | ipv6addr | 95 |
| `Error-Cause` | integer | 101 |
| `Framed-IPv6-Address` | ipv6addr | 168 |
| `Message-Authenticator` | string | 80 |

A numeric name (`--attr 26=...`) is encoded as a raw string with that
attribute number, for anything not in the table above.

---

## Packet construction

Disconnect-Request/CoA-Request derive their Request Authenticator from a hash
of the packet, the same way Accounting-Request does (RFC 5176 §2.3), rather
than filling it with random bytes the way Access-Request does. That makes the
build order fixed rather than a free choice:

1. **Attributes** (`--attr`, `--proxy-state`, `--event-timestamp`) are encoded
   first.
2. **Message-Authenticator**, unless `--msg-auth absent`, is computed as
   HMAC-MD5 over the packet *with the Authenticator field treated as sixteen
   zero octets* (RFC 2869 §5.14's Access-Request convention, which applies
   here for the same non-circularity reason it applies to Accounting-Request:
   the real Request Authenticator is itself hashed over the attributes
   including this one, so a fixed placeholder is the only order that isn't
   circular). `--msg-auth wrong` flips every byte of the correctly-computed
   value afterward.
3. **Request Authenticator** is `MD5(Code‖Identifier‖Length‖16 zero
   octets‖Attributes‖Secret)`, written into the Authenticator field only after
   step 2 is complete. `--authenticator wrong` flips every byte of the
   correctly-computed value afterward.
4. `--truncate`/`--bad-length`, if given, are applied last, after the packet
   is otherwise wire-correct — so a truncated or over-length-claiming packet
   still carries a Request Authenticator computed over exactly what a correct
   packet of that content would have had, isolating the bounds check from the
   authenticator check.

```python
def build_packet(code, ident, secret, attrs, authenticator_mode, msg_auth_mode, bad_length):
    zero_auth = bytes(16)
    body = attrs
    if msg_auth_mode != 'absent':
        placeholder = struct.pack('!BB', 80, 18) + bytes(16)
        wire_len = 20 + len(body) + len(placeholder)
        zero_ma_pkt = struct.pack('!BBH', code, ident, wire_len) + zero_auth + body + placeholder
        ma_value = hmac.new(secret.encode(), zero_ma_pkt, hashlib.md5).digest()
        if msg_auth_mode == 'wrong':
            ma_value = bytes((b + 1) % 256 for b in ma_value)
        body = body + struct.pack('!BB', 80, 18) + ma_value

    wire_len = 20 + len(body)
    if bad_length:
        wire_len += 4096

    header = struct.pack('!BBH', code, ident, wire_len)
    request_auth = hashlib.md5(header + zero_auth + body + secret.encode()).digest()
    if authenticator_mode == 'wrong':
        request_auth = bytes((b + 1) % 256 for b in request_auth)

    return header + request_auth + body
```

## Reply verification

A Disconnect-ACK/NAK or CoA-ACK/NAK's Response Authenticator is computed the
same way a reply to an Accounting-Request is (RFC 5176 §2.3): over the
reply's own header fields, but with the **request's** Authenticator in the
Authenticator field, followed by the reply's attributes and the secret:

```python
def response_authenticator_ok(reply, request_auth, secret):
    received = reply[4:20]
    calc = hashlib.md5(reply[:4] + request_auth + reply[20:] + secret.encode()).digest()
    return hmac.compare_digest(received, calc)
```

## Malformed-packet options and the requirements they exercise

| Option | Requirement |
|--------|-------------|
| `--authenticator wrong` | REQ-DAE-SEC-002 (Request Authenticator verified before delivery) |
| `--msg-auth wrong` | REQ-DAE-SEC-003 (Message-Authenticator verified when present) |
| `--msg-auth absent` | REQ-DAE-SEC-003 (accepted by default, rejected under `dae-require-message-authenticator`) |
| `--event-timestamp stale`/`future` | REQ-DAE-SEC-004 (two-sided freshness against `dae-max-clock-skew`) |
| `--truncate N` | Bounds checking on a packet shorter than a valid header/attribute region |
| `--bad-length` | Bounds checking on a wire Length field that overstates the packet |
| `--repeat N` | REQ-DAE-SEC-005/006 (duplicate suppression): identical Identifier, source port, and Request Authenticator, which is what RFC 5176 §2.3 requires a real retransmission to do |
