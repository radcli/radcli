---
title: radcli2.h opaque attribute-value list construction, access, and iteration
generator: requirements-from-implementation
id-prefix: REQ-AVP2
categories:
  INIT: radcli_avp_list construction and destruction
  DATA: radcli_avp_add_*/radcli_avp_get/radcli_avp_iter_* construction, lookup, and iteration contracts
  ERR: type-validation and allocation-failure return contracts
sources:
  - lib/avp.c
  - include/radcli/radcli2.h
  - lib/radcli.map.in
---

# radcli2.h Attribute-List Requirements

This document covers the opaque, `radcli_`-prefixed attribute-value list API in
`lib/avp.c`/`include/radcli/radcli2.h`: constructing a `radcli_avp_list`, adding
typed attributes to it (`radcli_avp_add_*`), looking one up by definition/index
(`radcli_avp_get`), iterating it (`radcli_avp_list_iter`/`radcli_avp_iter_next`),
and releasing it. It is the `radcli2.h` counterpart to `attrs.md`'s legacy
`VALUE_PAIR`/`rc_avpair_*` document — the two share no source files, no
lifecycle, and no ABI-versioning history (`radcli_avp_*` symbols are new
additions to `lib/radcli.map`'s single version node, not migrations of existing
ones), which is why this is a separate document rather than a new section of
`attrs.md`.

**Not yet covered by this document** (tracked as a gap, not silently assumed
fine): `radcli_dict_lookup()`/`radcli_dict_lookup_oid()`/`radcli_dict_lookup_num()`
and the `radcli_attr_def_*` accessors (dictionary-lookup half of `radcli2.h`,
arguably `dict.md`'s concern); `radcli_avp_decode()`/`radcli_avp_encode_rfc2865()`
(the internal-only wire codec declared in `lib/avp.h`, not exported via
`lib/radcli.map` — RADIUS wire framing belongs to `net.md`'s scope per
`attrs.md`'s own NET/wire-framing split) in general — REQ-AVP2-DATA-010/011
below are a narrow exception, stating only the `RADCLI_TYPE_INTEGER64`-specific
slice of that codec's contract (byte order and strict length validation),
since it is otherwise untestable from the public API and belongs to the type
system this document already owns. The rest of the codec (`RADCLI_TYPE_INTEGER`/
`_IPADDR`/`_DATE` byte order, VSA envelope framing, encryption) is left for a
follow-up document rather than retroactively written here.

---

## INIT — construction and destruction

### REQ-AVP2-INIT-001 — radcli_avp_list_new/free is a matched allocate/release pair; NULL is a valid no-op free

**Requirement:** `radcli_avp_list_new()` MUST return a new, empty list or `NULL`
on allocation failure. `radcli_avp_list_free()` MUST release the list and every
attribute added to it, and MUST accept `NULL` as a no-op, so that a caller does
not need to guard every teardown path with a separate NULL check (mirrors
`REQ-ATTR-DATA-012`'s `rc_avpair_free()` contract for the legacy API).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:103 (`radcli_avp_list_new`), lib/avp.c:114 (`radcli_avp_list_free`)
**Acceptance:** [INIT] unit, local — `tests/avp.c` constructs a list, adds
attributes, frees it, then calls `radcli_avp_list_free(NULL)` and confirms no
crash.
**Links:** REQ-ATTR-DATA-012

---

## DATA — construction, lookup, and iteration

### REQ-AVP2-DATA-002 — radcli_avp_add_bytes is the primitive every typed setter is defined in terms of

**Requirement:** `radcli_avp_add_str()`/`_uint32()`/`_ipaddr()`/`_in6()` MUST
validate `def`'s `radcli_attr_type` against the type(s) each accepts, then
delegate to `radcli_avp_add_bytes()` for the actual append; `radcli_avp_add_bytes()`
itself MUST accept any type, since the underlying storage is always
length-carrying bytes regardless of interpretation.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:168 (`radcli_avp_add_bytes`), lib/avp.c:196-247 (typed wrappers)
**Acceptance:** [DATA] unit, local — `tests/avp.c` adds one attribute of each
accepted type, then confirms each typed setter rejects a `def` of the wrong
`radcli_attr_type` (negative case).
**Links:** REQ-AVP2-ERR-007

### REQ-AVP2-DATA-003 — radcli_avp_add_* always appends to the list tail

**Requirement:** Every successful `radcli_avp_add_*()` call MUST append the new
attribute after every attribute already in the list, so that iteration order
(`radcli_avp_list_iter()`/`radcli_avp_iter_next()`) matches insertion order.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:189 (`list_add_tail(&list->head, &a->node)`)
**Acceptance:** [DATA] unit, local — `tests/avp.c`'s "wire order is preserved"
section adds five attributes and confirms the iterator yields them in the same
order.
**Links:** REQ-AVP2-DATA-005

### REQ-AVP2-DATA-004 — radcli_avp_get is a linear scan returning the idx-th occurrence

**Requirement:** `radcli_avp_get(list, def, idx)` MUST return the `idx`-th
(0-based) attribute in `list` whose definition is `def`, in list order, or
`NULL` if fewer than `idx+1` occurrences exist. It MUST NOT allocate.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:251-266
**Acceptance:** [DATA] unit, local — `tests/avp.c`'s "repeated attributes"
section adds two `User-Name` attributes and confirms `idx=0`/`idx=1` each
resolve to the correct one, and that `idx=1` returns `NULL` before the second
is added.
**Links:** REQ-ATTR-DATA-010 (the analogous legacy-API requirement)

### REQ-AVP2-DATA-005 — radcli_avp_iter resolves position at construction; exhaustion is sticky

**Requirement:** `radcli_avp_list_iter(list)` MUST return an iterator already
positioned at `list`'s first attribute (or yielding nothing, if `list` is `NULL`
or empty). `radcli_avp_iter_next(it)` MUST return the current attribute and
advance; once it has returned `NULL` because the list is exhausted, every
subsequent call on that same iterator MUST also return `NULL` — it MUST NOT
re-derive a position from the list and restart.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:270-298 (`radcli_avp_list_iter`, `radcli_avp_iter_next`)
**Acceptance:** [DATA] unit, local — `tests/avp.c`: empty-list iterator yields
`NULL` immediately; a `NULL`-list iterator yields `NULL` immediately; after
draining a 5-attribute list, two further consecutive `radcli_avp_iter_next()`
calls both return `NULL` (the sticky-exhaustion case, chosen specifically
because it is the property the construction-time-resolved-position design
exists to guarantee, not an incidental side effect).
**Links:** REQ-AVP2-DATA-003, REQ-AVP2-DATA-006

### REQ-AVP2-DATA-006 — independent iterators over one list do not share position

**Requirement:** Two `radcli_avp_iter` values obtained from
`radcli_avp_list_iter()` on the same list (or copies of one, taken before either
is advanced) MUST advance independently — advancing one MUST NOT affect the
position of another, as long as the underlying list is not mutated while either
is in use (mutation during concurrent iteration is out of scope; see
`lib/avp.c`'s struct-level locking note).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:63-75 (locking/lifetime comment), lib/avp.c:270-298
**Acceptance:** [DATA] unit, local — `tests/avp.c`'s "two independent iterators"
section fully drains one iterator, then confirms a freshly-constructed second
iterator over the same list still starts at the first attribute.
**Links:** REQ-AVP2-DATA-005

---

## ERR — type validation and failure returns

### REQ-AVP2-ERR-007 — a type-mismatched or NULL def is rejected without mutating the list

**Requirement:** `radcli_avp_add_str()`/`_uint32()`/`_ipaddr()`/`_in6()` MUST
return `-1` and leave the list unmodified if `def` is `NULL` or its
`radcli_attr_type` does not match what that setter accepts (e.g.
`radcli_avp_add_uint32()` on a `RADCLI_TYPE_STRING` attribute); `radcli_avp_add_in6()`
MUST additionally reject a non-zero `prefix` for `RADCLI_TYPE_IPV6ADDR` and a
`prefix` over 128 for `RADCLI_TYPE_IPV6PREFIX`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:196-247
**Acceptance:** [ERR] unit, local — `tests/avp.c`'s "setters MUST reject a
definition of the wrong type" section exercises every rejection case listed
above.
**Links:** REQ-AVP2-DATA-002

### REQ-AVP2-ERR-008 — allocation failure returns NULL/-1 and logs, without partial mutation

**Requirement:** `radcli_avp_list_new()` MUST return `NULL` on allocation
failure. `radcli_avp_add_bytes()` (and, transitively, every typed setter built
on it) MUST return `-1` on allocation failure without adding a partially
constructed attribute to the list. Both MUST log via `rc_log(LOG_CRIT, ...)`
before returning, so the failure is diagnosable without the caller needing to
add its own logging at every call site.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:103-109 (`radcli_avp_list_new`), lib/avp.c:168-192
(`radcli_avp_add_bytes`)
**Acceptance:** [ERR] not exercised by the current local test suite (would
require fault-injecting `calloc()`); `Needs-domain-check` whether this project
wants a dedicated allocation-failure test harness, or accepts code inspection
as sufficient for this category, same as the rest of `lib/`'s allocation
call sites.
**Links:** REQ-GEN-MEM-001 (general.md's allocator-choice requirement)

### REQ-AVP2-DATA-009 — radcli_avp_add_uint64/get_uint64 is the typed setter/getter pair for RADCLI_TYPE_INTEGER64 (RFC 8044 SS3.3)

**Requirement:** `radcli_avp_add_uint64()` MUST append a `RADCLI_TYPE_INTEGER64`
attribute storing `value` as 8 raw (host-order) bytes, and MUST return `-1`
without mutating the list if `def` is `NULL` or not `RADCLI_TYPE_INTEGER64` —
the same type-checked-setter contract REQ-AVP2-ERR-007 states for the
32-bit setters, extended to the one type only `radcli_avp_add_uint64()`
accepts. `radcli_avp_get_uint64()` MUST return `-1` if `a` is `NULL`, `a`'s
type is not `RADCLI_TYPE_INTEGER64`, or the stored length is not exactly 8
bytes, and otherwise MUST write the stored value to `*out` (if non-NULL).
`RADCLI_TYPE_INTEGER64` implements RFC 8044 SS3.3's "integer64" data type;
`MIP6-Feature-Vector` (RFC 5447 SS4.2.5, `etc/dictionary` attribute 124) is,
per IANA, the only standard attribute of this type — see REQ-DICT-DATA-010.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:215-219 (`radcli_avp_add_uint64`), lib/avp.c:333-346
(`radcli_avp_get_uint64`)
**Acceptance:** [DATA] positive, local — `tests/avp.c`'s "Phase 2:
RADCLI_TYPE_INTEGER64, radcli_avp_add_uint64()/_get_uint64()" section adds
and reads back `0x0123456789abcdef` through a `Test-Int64` attribute. [ERR]
negative, local — the same section confirms `radcli_avp_add_uint64()` is
rejected against a `RADCLI_TYPE_STRING` (`User-Name`) definition.
**Links:** REQ-AVP2-ERR-007, REQ-DICT-DATA-010

### REQ-AVP2-DATA-010 — radcli_avp_decode() enforces an exact 8-octet wire length for RADCLI_TYPE_INTEGER64, skipping a malformed instance rather than storing it

**Requirement:** When decoding an attribute whose dictionary type is
`RADCLI_TYPE_INTEGER64`, `radcli_avp_decode()` MUST require the wire
attribute's value to be exactly 8 octets (RFC 8044 SS3.3); on any other
length it MUST log a warning and skip the attribute entirely (as for an
unrecognised attribute), never storing a truncated or oversized value for
`radcli_avp_get_uint64()` to reject later. This is deliberately stricter
than the four-octet numeric types (`RADCLI_TYPE_INTEGER`/`_IPADDR`/`_DATE`),
which do store a wrong-length value raw for the getter to reject — justified
because no `VALUE_PAIR`-based caller could ever have been compiled against
`RADCLI_TYPE_INTEGER64` in the first place (it has no legacy `rc_attr_type`
counterpart), so there is no compatibility reason to keep a malformed one
around.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:703-720 (`avp_decode_into()`'s `RADCLI_TYPE_INTEGER64`
branch)
**Acceptance:** [ERR] negative, local — `tests/avp-codec.c`'s "decode: an
integer64 attribute with the wrong wire length is skipped outright" section
decodes a 7-byte `Test-Int64` value and confirms the resulting list is empty
(`avp_list_empty()`), not a stored malformed attribute.
**Links:** REQ-AVP2-DATA-009

### REQ-AVP2-DATA-011 — radcli_avp_encode_rfc2865() encodes RADCLI_TYPE_INTEGER64 as 8 octets, network byte order, high word first

**Requirement:** `radcli_avp_encode_rfc2865()` MUST encode a
`RADCLI_TYPE_INTEGER64` attribute's value on the wire as 8 octets in network
byte order — the high 32 bits followed by the low 32 bits, each
individually converted with `htonl()` — per RFC 8044 SS3.3. The decode side
(REQ-AVP2-DATA-010) MUST reverse this exactly (`ntohl()` on each half,
high half shifted into bits 63:32).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:921-937 (`radcli_avp_encode_rfc2865()`'s
`RADCLI_TYPE_INTEGER64` branch)
**Acceptance:** [DATA] positive, local — `tests/avp-codec.c`'s "round trip:
RADCLI_TYPE_INTEGER64, 8-octet network byte order" section encodes
`0x0123456789abcdef` and confirms the wire bytes are big-endian with the
high word first (`01 23 45 67 89 ab cd ef`), then decodes them back to the
same value.
**Links:** REQ-AVP2-DATA-009, REQ-AVP2-DATA-010

### REQ-AVP2-DATA-012 — radcli_avp_add_gigawords64/get_gigawords64 split/reassemble a 64-bit value across an Octets/Gigawords attribute pair (RFC 2866/RFC 2869), omitting a zero Gigawords half

**Requirement:** `radcli_avp_add_gigawords64(ctx, list, octets, value)` MUST
add `octets` (which MUST be `RADCLI_TYPE_INTEGER`) as a 32-bit attribute
holding `value`'s low 32 bits, unconditionally. If `value > UINT32_MAX`, it
MUST additionally add `octets`'s dictionary-configured Gigawords counterpart
(REQ-DICT-DATA-011) as a 32-bit attribute holding `value`'s high 32 bits;
when `value` fits in 32 bits, the Gigawords attribute MUST be omitted
entirely (not added as zero), matching how a real NAS reports it. This
implements RFC 2866 SS5.3/5.4 (Acct-Input/Output-Octets) paired with RFC
2869 SS5.1/5.2 (Acct-Input/Output-Gigawords) — not `RADCLI_TYPE_INTEGER64`;
no standard RADIUS accounting attribute uses that type.
`radcli_avp_get_gigawords64(ctx, list, octets, out)` MUST reverse this:
read `octets`'s value as the low 32 bits, and — if the paired Gigawords
attribute is present in `list` — its value as the high 32 bits (treated as
`0` if absent), combining them into `*out`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:400-428 (`radcli_avp_add_gigawords64`), lib/avp.c:431-457
(`radcli_avp_get_gigawords64`)
**Acceptance:** [DATA] positive, local — `tests/avp.c`'s counter64 section:
a value over 2^32 (`5000000000`) round-trips through both the Octets and
Gigawords attributes; a value under 2^32 (`42`) round-trips through Octets
alone, with the Gigawords attribute confirmed absent from the list. [DATA]
positive, requires a real FreeRADIUS server — `tests/request-freeradius.c`
SS4 round-trips an `Acct-Input-Octets`/`-Gigawords` pair over 2^32 through a
live accounting exchange.
**Links:** REQ-DICT-DATA-011, REQ-AVP2-ERR-013

### REQ-AVP2-ERR-013 — radcli_avp_add_gigawords64/get_gigawords64 reject an octets attribute with no configured Gigawords counterpart

**Requirement:** Both `radcli_avp_add_gigawords64()` and
`radcli_avp_get_gigawords64()` MUST return `-1` without side effects if
`octets` has no `gigawords=` counterpart configured in the dictionary
(`rc_dict_attr_gigawords()` returns `NULL`) — a silent truncation to 32 bits
is never acceptable. `radcli_avp_add_gigawords64()` MUST also reject a `NULL`
`ctx`/`octets`, or an `octets` whose type is not `RADCLI_TYPE_INTEGER`, the
same way. `radcli_avp_get_gigawords64()` MUST additionally return `-1` if the
Gigawords attribute is present in `list` but is not itself a valid 32-bit
integer (present-but-malformed is an error, not treated as absent).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:406-414 (`radcli_avp_add_gigawords64` validation),
lib/avp.c:437-450 (`radcli_avp_get_gigawords64` validation)
**Acceptance:** [ERR] negative, local — `tests/avp.c`'s counter64 section
confirms both `radcli_avp_add_gigawords64()` and `radcli_avp_get_gigawords64()`
are rejected against `Test-Counter-Unpaired` (an `ATTRIBUTE` line with no
`gigawords=` option).
**Links:** REQ-AVP2-DATA-012, REQ-DICT-DATA-011
