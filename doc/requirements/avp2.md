---
title: radcli2.h opaque attribute-value list construction, access, and iteration
generator: requirements-from-implementation
id-prefix: REQ-AVP2
categories:
  INIT: radcli_avp_list construction and destruction
  DATA: radcli_avp_add_*/radcli_avp_get/radcli_avp_iter_* construction, lookup, and iteration contracts
  ERR: type-validation and allocation-failure return contracts
  SEC: radcli_avp_decode/radcli_avp_encode attribute-encryption (RFC 2865 SS5.2, RFC 2868 SS3.5/RFC 2548) contracts
sources:
  - lib/avp.c
  - lib/avp.h
  - include/radcli/radcli2.h
  - lib/radcli2.map.in
---

# radcli2.h Attribute-List Requirements

This document covers the opaque, `radcli_`-prefixed attribute-value list API in
`lib/avp.c`/`include/radcli/radcli2.h`: constructing a `radcli_avp_list`, adding
typed attributes to it (`radcli_avp_add_*`), looking one up by definition/index
(`radcli_avp_get`), iterating it (`radcli_avp_list_iter`/`radcli_avp_iter_next`),
and releasing it. It is the `radcli2.h` counterpart to `attrs.md`'s legacy
`VALUE_PAIR`/`rc_avpair_*` document — the two share no source files, no
lifecycle, and no ABI-versioning history (`radcli_avp_*` symbols are new
additions to `lib/radcli2.map`'s single version node, not migrations of existing
ones), which is why this is a separate document rather than a new section of
`attrs.md`. The dictionary-lookup half of `radcli2.h`
(`radcli_dict_lookup()`/`_lookup_oid()`/`_lookup_num()`/`_lookup_value()` and
the `radcli_attr_def_*` accessors) is `dict2.md`'s scope, not this document's
— see that document for why it is a separate file rather than a section here
or in `dict.md`.

`radcli_avp_decode()`/`radcli_avp_encode()` — the internal-only wire
codec declared in `lib/avp.h`, not exported via `lib/radcli2.map` — are also
this document's scope, not `net.md`'s: although RADIUS wire framing is
generally `net.md`'s concern, this particular codec shares no other source
file with `net.md` (it is `lib/avp.c`-only, called into by `lib/request.c`
and `lib/aaa2.c`, `net2.md`'s scope, the same way `net.md` calls into the
legacy `lib/avpair.c`/`lib/sendserver.c` codec instead), and its correctness
depends entirely on the `radcli_attr_type` system this document already
owns. `net2.md` cites it as this document's gap rather than re-deriving it.
REQ-AVP2-DATA-026 through REQ-AVP2-ERR-032 below state that codec's contract
in full; REQ-AVP2-DATA-010/011 already stated the `RADCLI_TYPE_INTEGER64`/
`RADCLI_TYPE_IFID`-specific slice of it before the rest was written up.

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
**Source:** lib/avp.c:126-135 (`radcli_avp_list_new`), lib/avp.c:137-189 (`radcli_avp_list_free`)
**Acceptance:** [INIT] unit, local — `tests/avp.c` constructs a list, adds
attributes, frees it, then calls `radcli_avp_list_free(NULL)` and confirms no
crash.
**Links:** REQ-ATTR-DATA-012

---

## DATA — construction, lookup, and iteration

### REQ-AVP2-DATA-002 — radcli_avp_add_bytes is the primitive every typed setter is defined in terms of

**Requirement:** `radcli_avp_add_str()`/`_uint32()`/`_ip4()`/`_ip6()` MUST
validate `def`'s `radcli_attr_type` against the type(s) each accepts, then
delegate to `radcli_avp_add_bytes()` for the actual append; `radcli_avp_add_bytes()`
itself MUST accept any type, since the underlying storage is always
length-carrying bytes regardless of interpretation.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:191 (`radcli_avp_add_bytes`), lib/avp.c:242-318 (typed wrappers: `_add_str`/`_add_uint32`/`_add_uint64`/`_add_ip4`/`_add_ip6`)
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
**Source:** lib/avp.c:218 (`list_add_tail(&list->head, &a->node)`)
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
**Source:** lib/avp.c:449-466
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
**Source:** lib/avp.c:468-476 (`radcli_avp_list_iter`), lib/avp.c:478-498 (`radcli_avp_iter_next`)
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
**Source:** lib/avp.c:71-84 (locking/lifetime comment), lib/avp.c:468-498
**Acceptance:** [DATA] unit, local — `tests/avp.c`'s "two independent iterators"
section fully drains one iterator, then confirms a freshly-constructed second
iterator over the same list still starts at the first attribute.
**Links:** REQ-AVP2-DATA-005

---

## ERR — type validation and failure returns

### REQ-AVP2-ERR-007 — a type-mismatched or NULL def is rejected without mutating the list

**Requirement:** `radcli_avp_add_str()`/`_uint32()`/`_ip4()`/`_ip6()` MUST
return `-1` and leave the list unmodified if `def` is `NULL` or its
`radcli_attr_type` does not match what that setter accepts (e.g.
`radcli_avp_add_uint32()` on a `RADCLI_TYPE_STRING` attribute); `radcli_avp_add_ip6()`
MUST additionally reject a non-zero `prefix` for `RADCLI_TYPE_IPV6ADDR` and a
`prefix` over 128 for `RADCLI_TYPE_IPV6PREFIX`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:242-318
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
**Source:** lib/avp.c:126-135 (`radcli_avp_list_new`), lib/avp.c:191-221
(`radcli_avp_add_bytes`)
**Acceptance:** [ERR] not exercised by the current local test suite (would
require fault-injecting `calloc()`); `Needs-domain-check` whether this project
wants a dedicated allocation-failure test harness, or accepts code inspection
as sufficient for this category, same as the rest of `lib/`'s allocation
call sites.
**Links:** REQ-GEN-MEM-001 (general.md's allocator-choice requirement)

### REQ-AVP2-DATA-009 — radcli_avp_add_uint64/get_uint64 is the typed setter/getter pair for RADCLI_TYPE_INTEGER64 (RFC 8044 SS3.3) and RADCLI_TYPE_IFID (RFC 8044 SS3.7)

**Requirement:** `radcli_avp_add_uint64()` MUST append a `RADCLI_TYPE_INTEGER64`
or `RADCLI_TYPE_IFID` attribute storing `value` as 8 raw (host-order) bytes,
and MUST return `-1` without mutating the list if `def` is `NULL` or neither
of those two types — the same type-checked-setter contract REQ-AVP2-ERR-007
states for the 32-bit setters, extended to the two types
`radcli_avp_add_uint64()` accepts. `radcli_avp_get_uint64()` MUST return
`-1` if `a` is `NULL`, `a`'s type is neither `RADCLI_TYPE_INTEGER64` nor
`RADCLI_TYPE_IFID`, or the stored length is not exactly 8 bytes, and
otherwise MUST write the stored value to `*out` (if non-NULL).
`RADCLI_TYPE_INTEGER64` implements RFC 8044 SS3.3's "integer64" data type;
`MIP6-Feature-Vector` (RFC 5447 SS4.2.5, `etc/dictionary` attribute 124) is,
per IANA, the only standard attribute of this type — see REQ-DICT2-DATA-007.
`RADCLI_TYPE_IFID` implements RFC 8044 SS3.7's "ifid" data type (an 8-octet
IPv6 interface identifier, e.g. `Framed-Interface-Id`, RFC 3162 SS2.3,
`etc/dictionary` attribute 96 — see REQ-DICT2-DATA-008); it shares this
setter/getter pair with `RADCLI_TYPE_INTEGER64` rather than getting its own,
because both are byte-for-byte identical on the wire (8 raw octets), even
though an interface identifier is not itself an arithmetic quantity.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:272-282 (`radcli_avp_add_uint64`), lib/avp.c:524-539
(`radcli_avp_get_uint64`)
**Acceptance:** [DATA] positive, local — `tests/avp.c`'s "Phase 2:
RADCLI_TYPE_INTEGER64, radcli_avp_add_uint64()/_get_uint64()" section adds
and reads back `0x0123456789abcdef` through a `Test-Int64` attribute; a
parallel section does the same through an `ifid`-typed attribute. [ERR]
negative, local — the same sections confirm `radcli_avp_add_uint64()` is
rejected against a `RADCLI_TYPE_STRING` (`User-Name`) definition.
**Links:** REQ-AVP2-ERR-007, REQ-DICT2-DATA-007, REQ-DICT2-DATA-008

### REQ-AVP2-DATA-010 — radcli_avp_decode() enforces an exact wire length for every fixed-length numeric type, skipping a malformed instance rather than storing it

**Requirement:** When decoding an attribute whose dictionary type is
`RADCLI_TYPE_INTEGER64`/`RADCLI_TYPE_IFID` (RFC 8044 SS3.3/SS3.7, 8 octets)
or `RADCLI_TYPE_INTEGER`/`RADCLI_TYPE_IPADDR`/`RADCLI_TYPE_DATE` (4 octets),
`radcli_avp_decode()` MUST require the wire attribute's value to be exactly
that width; on any other length it MUST log a warning and skip the
attribute entirely (as for an unrecognised attribute), never storing a
truncated or oversized value for `radcli_avp_get_uint64()`/
`radcli_avp_get_uint32()` to reject later. All five types share this one
policy — there is no fixed-length numeric type this document treats more
permissively.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`avp_decode_into()`'s `RADCLI_TYPE_INTEGER64`/
`RADCLI_TYPE_IFID` branch and its `RADCLI_TYPE_INTEGER`/`_IPADDR`/`_DATE`
sibling, both length-gated the same way)
**Acceptance:** [ERR] negative, local — `tests/avp-codec.c`'s "decode: an
integer64/ifid attribute with the wrong wire length is skipped outright"
section decodes a 7-byte `Test-Int64` value, an equally short `ifid`-typed
value, and a 3-byte `Session-Timeout` (`RADCLI_TYPE_INTEGER`) value, and
confirms each produces an empty list (`avp_list_empty()`), not a stored
malformed attribute.
**Links:** REQ-AVP2-DATA-009

### REQ-AVP2-DATA-011 — radcli_avp_encode() encodes RADCLI_TYPE_INTEGER64/RADCLI_TYPE_IFID as 8 octets, network byte order, high word first

**Requirement:** `radcli_avp_encode()` MUST encode a
`RADCLI_TYPE_INTEGER64` or `RADCLI_TYPE_IFID` attribute's value on the wire
as 8 octets in network byte order — the high 32 bits followed by the low 32
bits, each individually converted with `htonl()` — per RFC 8044 SS3.3/SS3.7.
The decode side (REQ-AVP2-DATA-010) MUST reverse this exactly (`ntohl()` on
each half, high half shifted into bits 63:32).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:1318-1333 (`radcli_avp_encode()`'s
`RADCLI_TYPE_INTEGER64`/`RADCLI_TYPE_IFID` branch)
**Acceptance:** [DATA] positive, local — `tests/avp-codec.c`'s "round trip:
RADCLI_TYPE_INTEGER64, 8-octet network byte order" section encodes
`0x0123456789abcdef` and confirms the wire bytes are big-endian with the
high word first (`01 23 45 67 89 ab cd ef`), then decodes them back to the
same value; a parallel section does the same for an `ifid`-typed attribute.
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
**Source:** lib/avp.c:798-825 (`radcli_avp_add_gigawords64`), lib/avp.c:827-852
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
**Source:** lib/avp.c:804-812 (`radcli_avp_add_gigawords64` validation),
lib/avp.c:835-848 (`radcli_avp_get_gigawords64` validation, including the
present-but-malformed Gigawords check)
**Acceptance:** [ERR] negative, local — `tests/avp.c`'s counter64 section
confirms both `radcli_avp_add_gigawords64()` and `radcli_avp_get_gigawords64()`
are rejected against `Test-Counter-Unpaired` (an `ATTRIBUTE` line with no
`gigawords=` option).
**Links:** REQ-AVP2-DATA-012, REQ-DICT-DATA-011

### REQ-AVP2-DATA-034 — radcli_avp_add_gigawords64_by_num/get_gigawords64_by_num are radcli_avp_add_gigawords64/get_gigawords64's _by_num() wrappers

**Requirement:** `radcli_avp_add_gigawords64_by_num(ctx, list, attrid,
vendor, value)` MUST be equivalent to `radcli_avp_add_gigawords64(ctx,
list, radcli_dict_lookup_num(ctx, attrid, vendor), value)`, and
`radcli_avp_get_gigawords64_by_num(ctx, list, attrid, vendor, out)` MUST be
equivalent to `radcli_avp_get_gigawords64(ctx, list,
radcli_dict_lookup_num(ctx, attrid, vendor), out)` — both returning `-1`
without side effects if the numeric lookup resolves to no attribute. Unlike
the other `_by_num()` wrappers, only one attribute ID is taken (`attrid`/
`vendor` identify the *octets* attribute only) — the Gigawords counterpart
is resolved from `octets`'s own dictionary entry either way
(REQ-AVP2-DATA-012), so a second ID has no meaning here. This is the
`_by_num()` counterpart to `radcli_avp_add_gigawords64()`/
`radcli_avp_get_gigawords64()` (REQ-AVP2-DATA-012) that REQ-AVP2-DATA-033
flagged as missing.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`radcli_avp_add_gigawords64_by_num`,
`radcli_avp_get_gigawords64_by_num`)
**Acceptance:** [DATA] positive/negative, local — `tests/avp.c`'s counter64
section round-trips a value over 2^32 through `Test-Octets`(252)/vendor 0
via the `_by_num()` pair, confirms rejection against `Test-Octets-
Unpaired`(254) (no `gigawords=` counterpart), and confirms rejection
against an unresolvable attribute ID (9999).
**Links:** REQ-AVP2-DATA-012, REQ-AVP2-ERR-013, REQ-AVP2-DATA-033

### REQ-AVP2-DATA-035 — radcli_avp_concat_str()/_by_num() follow snprintf()'s buffer-sizing contract

**Requirement:** Both `radcli_avp_concat_str()` and
`radcli_avp_concat_str_by_num()` MUST accept `buf == NULL` and/or
`buflen == 0` as a pure size query (nothing is written in that case),
exactly as `snprintf(NULL, 0, ...)` does, and MUST always return the number
of bytes the joined result would occupy (excluding the NUL terminator) --
whether or not it fit in `buf`. Whenever the returned value is `>= buflen`
(truncation occurred, including the `buf == NULL`/`buflen == 0` case),
`buf`, if non-`NULL` and `buflen > 0`, MUST still hold a valid,
NUL-terminated prefix of the would-be result (whatever fit) -- never an
unterminated buffer, never partially-written garbage past the terminator.
This replaces the withdrawn REQ-AVP2-ERR-018, which required `-1` for these
same inputs: there is no longer any buffer-size-related failure case for
this function family, matching a real caller's actual use of it --
`snprintf()`'s two-call idiom (size query, then allocate-and-fill) works
unmodified against these functions.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`radcli_avp_concat_str()`'s `used`/`total` tracking
and `buf != NULL && buflen > 0` write guards; `radcli_avp_concat_str_by_num()`
delegates to it directly once `def` is resolved)
**Acceptance:** [DATA] positive, local — `tests/avp.c`'s concat section
joins two `Framed-Route` occurrences into a 10-byte buffer too small to
hold the joined result via both functions, confirms each returns the full
untruncated length (not `-1`) and leaves the buffer NUL-terminated within
bounds (`strlen(buf) < sizeof(buf)`); confirms a `NULL` buf and a `0`
buflen each return that same full length via both functions, with nothing
written.
**Links:** REQ-AVP2-DATA-017, REQ-AVP2-ERR-018, REQ-AVP2-DATA-036

### REQ-AVP2-DATA-036 — radcli_avp_concat_str_by_num() is radcli_avp_concat_str()'s _by_num() wrapper

**Requirement:** `radcli_avp_concat_str_by_num(buf, buflen, l, ctx, attrid,
vendor, sep)` MUST be equivalent to `radcli_avp_concat_str(buf, buflen, l,
radcli_dict_lookup_num(ctx, attrid, vendor), sep)` when the numeric lookup
resolves to an attribute. Unlike every other `_by_num()` wrapper in this
document, an unresolvable `(attrid, vendor)` here is NOT itself a failure:
`buf` (if non-`NULL` and `buflen > 0`) MUST be set to an empty string and
`0` returned -- the same "unknown/absent, not a failure" shape
REQ-AVP2-DATA-017 already gives "no occurrence present" -- rather than
reaching `radcli_avp_concat_str()`'s `def == NULL` failure path, since a
caller passing a well-known `PW_*` constant should not have to separately
handle "not in this dictionary" as an error, matching this function's
legacy-ID convenience role (the same reasoning REQ-AVP2-DATA-017 already
gives for legacy `rc_aaa()`'s `msg`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`radcli_avp_concat_str_by_num()`)
**Acceptance:** [DATA] positive/negative, local — `tests/avp.c` confirms
`radcli_avp_concat_str_by_num()` and `radcli_avp_concat_str()` (given the
same resolved `def`) return identical output for the same list; confirms
an attribute ID with no dictionary entry produces an empty string and `0`,
not a failure.
**Links:** REQ-AVP2-DATA-017, REQ-AVP2-DATA-035, REQ-AVP2-DATA-033

### REQ-AVP2-DATA-013 — radcli_avp_get_cstr() returns an owned, NUL-terminated view with no allocation

**Requirement:** `radcli_avp_get_cstr()` MUST return a pointer to `a`'s
stored bytes followed by a NUL terminator, without allocating memory or
copying the value; the returned pointer MUST remain valid for as long as
the `radcli_avp_list` `a` belongs to is not freed, and MUST NOT be freed by
the caller. Valid for every attribute type, the same as
`radcli_avp_get_bytes()`. `radcli_avp_add_bytes()` MUST allocate one byte
beyond the attribute's real length so this terminator always exists.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`radcli_avp_add_bytes()`'s allocation size,
`radcli_avp_get_cstr()`)
**Acceptance:** [DATA] positive, local — `tests/avp.c` adds a `User-Name`
value of `"alice"` and confirms `radcli_avp_get_cstr()` returns a string
comparing equal to it.
**Links:** REQ-AVP2-DATA-002, REQ-AVP2-ERR-014

### REQ-AVP2-ERR-014 — radcli_avp_get_cstr() rejects a value containing an embedded NUL byte

**Requirement:** `radcli_avp_get_cstr()` MUST return `NULL` (logging at
`LOG_WARNING`), rather than a pointer that reads as a shorter, complete
string, if `a`'s stored bytes contain a NUL byte before the real end of the
value. A truncated-looking success is not acceptable here: a caller using
this accessor for a trust decision (e.g. matching a server-supplied group
name) must not see `"admin"` for a value that was actually
`"admin\0attacker"`. `radcli_avp_get_bytes()` remains available for an
attribute where an embedded NUL is legitimate.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`radcli_avp_get_cstr()`'s `memchr()` check)
**Acceptance:** [ERR] negative, local — `tests/avp.c` adds a `User-Name`
value of `"admin\0attacker"` (14 bytes) and confirms `radcli_avp_get_cstr()`
returns `NULL` while `radcli_avp_get_bytes()` still returns the full 14
bytes.
**Links:** REQ-AVP2-DATA-013

### REQ-AVP2-DATA-015 — radcli_avp_get_by_num()/get_*_by_num() fold radcli_dict_lookup_num() + radcli_avp_get() + the typed getter into one call

**Requirement:** `radcli_avp_get_by_num(list, ctx, attrid, vendor, idx)` MUST
be equivalent to `radcli_avp_get(list, radcli_dict_lookup_num(ctx, attrid,
vendor), idx)`. Each typed sibling
(`radcli_avp_get_uint32_by_num()`/`_get_uint64_by_num()`/`_get_in6_by_num()`/
`_get_bytes_by_num()`/`_get_cstr_by_num()`) MUST be equivalent to calling
`radcli_avp_get_by_num()` with `idx` fixed at `0` (the first occurrence)
followed by the matching un-suffixed typed getter
(`radcli_avp_get_uint32()`, etc.) on the result. This is the receive-side
mirror of `radcli_avp_add_*_by_num()` (REQ-GEN-STYLE-002), closing the gap
that made decoding a reply require caching a `radcli_attr_def*` per
attribute of interest instead of a single call per well-known attribute.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`radcli_avp_get_by_num()` and the five typed
`_by_num()` getters)
**Acceptance:** [DATA] positive, local — `tests/avp.c` adds a `NAS-IP-
Address`, a `Framed-IPv6-Address`, and a `User-Name` by number, then
confirms `radcli_avp_get_uint32_by_num()`/`_get_in6_by_num()`/
`_get_bytes_by_num()`/`_get_cstr_by_num()` each round-trip the value added,
and that `radcli_avp_get_by_num()`'s `idx` parameter correctly addresses a
second occurrence of the same attribute.
**Links:** REQ-AVP2-DATA-002, REQ-AVP2-DATA-004

### REQ-AVP2-ERR-016 — radcli_avp_get_*_by_num() fails on an unresolvable attribute ID or a missing occurrence, without crashing

**Requirement:** Every function in the REQ-AVP2-DATA-015 family MUST return
its failure value (`NULL` for `radcli_avp_get_by_num()`/`_get_cstr_by_num()`,
`-1` for the other typed getters) both when `attrid`/`vendor` resolves to no
attribute in `ctx`'s loaded dictionary, and when the resolved attribute has
no occurrence (at `idx`, for the plain finder; at index 0, for the typed
getters) in `list` -- two different causes producing the same failure
shape, neither of which may crash or read uninitialized memory into an
`out` parameter.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`radcli_avp_get_by_num()`'s `def == NULL` check;
`radcli_avp_get()`'s existing not-found return)
**Acceptance:** [ERR] negative, local — `tests/avp.c` calls
`radcli_avp_get_uint32_by_num()`/`_get_cstr_by_num()` with an attribute ID
absent from the test dictionary (fails: no such attribute), and with
`Session-Timeout` (present in the dictionary, never added to the list this
call searches; fails: no occurrence).
**Links:** REQ-AVP2-DATA-015

### REQ-AVP2-DATA-017 — radcli_avp_concat_str() joins every occurrence of an attribute as text

**Requirement:** `radcli_avp_concat_str(buf, buflen, list, def, sep)` MUST
write every occurrence of `def` in `list`, in list order, into `buf`, each
pair of consecutive occurrences separated by `sep` (verbatim, no separator
at all if `sep` is `NULL` or empty), NUL-terminated whenever `buf` is
non-`NULL` and `buflen > 0`. If `list` has no occurrence of `def`, this is
NOT a failure: `buf` MUST be set to an empty string and `0` returned,
matching legacy `rc_aaa()`'s `msg` parameter (`lib/buildreq.c`), which
started as `'\0'` and simply stayed that way when no `Reply-Message`
arrived -- this function generalizes that one hardcoded case to any
attribute. An occurrence whose value contains an embedded NUL byte MUST be
skipped (the same policy `radcli_avp_get_cstr()` already applies), not
treated as a failure. `def == NULL` MUST return `-1` (the one genuine
failure case: an invalid attribute pointer, distinct from "no occurrence
present"). See REQ-AVP2-DATA-035 for the exact return-value contract
(`snprintf()`-style sizing) and REQ-AVP2-DATA-036 for
`radcli_avp_concat_str_by_num()`, its `_by_num()` wrapper.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`radcli_avp_concat_str()`)
**Acceptance:** [DATA] positive, local — `tests/avp.c` adds two `Framed-
Route` occurrences and confirms they are joined with a `"\n"` separator in
list order via both `radcli_avp_concat_str()` and
`radcli_avp_concat_str_by_num()`, confirming they agree exactly; confirms
an attribute with zero occurrences produces an empty string and a `0`
return rather than a failure; confirms `def == NULL` returns `-1`.
**Links:** REQ-AVP2-DATA-015, REQ-AVP2-DATA-035, REQ-AVP2-DATA-036

### REQ-AVP2-ERR-018 — WITHDRAWN

**Status:** WITHDRAWN — superseded by REQ-AVP2-DATA-035 (snprintf()-style
buffer-sizing contract).
**Links:** REQ-AVP2-DATA-035

### REQ-AVP2-DATA-019 — radcli_avp_list_error() reports a sticky, aggregate failure flag without changing any add call's own behavior

**Requirement:** `radcli_avp_list_error(list)` MUST return non-zero once
any `radcli_avp_add_*()`/`_by_num()` call on `list` has ever failed (the
first failure, not just the most recent), and `0` if `list` is non-NULL and
every add call on it so far has succeeded. This flag MUST be purely
observational: it MUST NOT change any `radcli_avp_add_*()`/`_by_num()`
call's own return value or the list's contents -- a call that would have
succeeded MUST still succeed after an earlier, unrelated call on the same
list failed. This lets a caller build a whole request as a flat sequence
of add calls with one aggregate check instead of one check per call site;
the non-blocking
constraint exists because an earlier implementation attempt that made a
failed list "poison" all subsequent adds broke the existing, documented
per-call-independent contract every `radcli_avp_add_*()` already has
(REQ-AVP2-ERR-007) -- confirmed by `tests/avp.c`'s pre-existing negative
tests (deliberately rejected adds followed by unrelated valid ones)
failing against that implementation before this constraint was added.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`avp_list_fail()`, `radcli_avp_list_error()`,
`struct radcli_avp_list_st.error`)
**Acceptance:** [DATA] positive, local — `tests/avp.c` confirms
`radcli_avp_list_error()` is `0` on a fresh list; confirms it becomes
non-zero after a deliberately rejected `radcli_avp_add_uint32()` (wrong
type); confirms a subsequent, unrelated `radcli_avp_add_str()` on the same
list still succeeds; confirms the flag remains non-zero afterward (sticky
to the first failure).
**Links:** REQ-AVP2-ERR-007, REQ-AVP2-ERR-020

### REQ-AVP2-ERR-020 — radcli_avp_list_error(NULL) is itself an error

**Requirement:** `radcli_avp_list_error(NULL)` MUST return non-zero,
matching how every `radcli_avp_add_*()`/`_by_num()` already treats a `NULL`
list as failure -- so a caller does not need a separate `if (list == NULL)`
check immediately after `radcli_avp_list_new()` before relying on
`radcli_avp_list_error()` as its one aggregate check.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c (`radcli_avp_list_error()`'s `list == NULL` check)
**Acceptance:** [ERR] negative, local — `tests/avp.c` confirms
`radcli_avp_list_error(NULL)` is non-zero.
**Links:** REQ-AVP2-DATA-019

### REQ-AVP2-DATA-021 — radcli_avp_add_ip4prefix()/_get_ip4prefix() (and their _by_num() variants) are the typed setter/getter pair for RADCLI_TYPE_IPV4PREFIX (RFC 8044 SS3.9)

**Requirement:** `radcli_avp_add_ip4prefix(l, def, value, prefix)` MUST append
a `RADCLI_TYPE_IPV4PREFIX` attribute as `reserved(1)=0 + prefix-len(1) +
address(4)` (RFC 8044 SS3.9), and MUST return `-1` without mutating the list
if `def` is `NULL`, `def`'s type is not `RADCLI_TYPE_IPV4PREFIX`, or `prefix`
exceeds 32 — the same type-checked-setter contract REQ-AVP2-ERR-007 states
for the other typed setters. `radcli_avp_get_ip4prefix(a, out, prefix)` MUST
reverse this, tolerating a wire value shorter than the full 6 bytes (only
`reserved(1)` + `prefix-len(1)` mandatory, zero-padding the address) the same
way `radcli_avp_get_ip6()` tolerates a short `RADCLI_TYPE_IPV6PREFIX` value,
and MUST return `-1` for a `NULL`/wrong-typed `a`.
`radcli_avp_add_ip4prefix_by_num()`/`radcli_avp_get_ip4prefix_by_num()` are
this pair's `_by_num()` wrappers, per REQ-AVP2-DATA-015/REQ-GEN-STYLE-002.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:320-337 (`radcli_avp_add_ip4prefix`), lib/avp.c:579-604
(`radcli_avp_get_ip4prefix`), lib/avp.c:410-419
(`radcli_avp_add_ip4prefix_by_num`), lib/avp.c:709-717
(`radcli_avp_get_ip4prefix_by_num`)
**Acceptance:** [DATA] positive, local — `tests/avp.c`'s "Phase 3:
RADCLI_TYPE_IPV4PREFIX" section (`tests/avp.c:363-408`) round-trips a
`/24` prefix through `radcli_avp_add_ip4prefix()`/`_get_ip4prefix()`; a
parallel section in `tests/avp-codec-freeradius.c:363` exercises
`radcli_avp_get_ip4prefix()` against a live-decoded attribute. [ERR]
negative, local — the same `tests/avp.c` section confirms
`radcli_avp_add_ip4prefix()` rejects an `IPADDR`-typed `def` and a `prefix`
over 32, and confirms `radcli_avp_add_ip4()`/`radcli_avp_get_ip6()` each
reject an `IPV4PREFIX`-typed attribute.
**Links:** REQ-AVP2-ERR-007, REQ-AVP2-DATA-015

### REQ-AVP2-DATA-022 — radcli_avp_get_ip6()/_get_ip6_by_num() is the typed getter for RADCLI_TYPE_IPV6ADDR and RADCLI_TYPE_IPV6PREFIX

**Requirement:** `radcli_avp_get_ip6(a, out, prefix)` MUST return `-1` for a
`NULL`/wrong-typed `a`. For `RADCLI_TYPE_IPV6ADDR` it MUST require exactly 16
stored bytes and report `*prefix = 128`; for `RADCLI_TYPE_IPV6PREFIX` it MUST
accept a wire value from 2 to 18 bytes (`reserved(1) + prefix-len(1) +
address(0..16)`), zero-padding a short address, and report the stored
prefix-length octet — this is the receive-side counterpart to
`radcli_avp_add_ip6()` (REQ-AVP2-ERR-007), which itself is documented but
whose getter had no requirement. `radcli_avp_get_ip6_by_num()` is this
getter's `_by_num()` wrapper (REQ-AVP2-DATA-015).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:542-577 (`radcli_avp_get_ip6`), lib/avp.c:698-706
(`radcli_avp_get_ip6_by_num`)
**Acceptance:** [DATA] positive, local — `tests/avp.c:263,272` round-trips
both an `IPV6ADDR` and an `IPV6PREFIX` value; `tests/avp.c:585` round-trips
`radcli_avp_get_ip6_by_num()` against a `Framed-IPv6-Address` added by
number; `tests/avp-codec.c:172` and `tests/avp-legacy.c:127` exercise it
against a live-decoded attribute.
**Links:** REQ-AVP2-ERR-007, REQ-AVP2-DATA-015

### REQ-AVP2-DATA-023 — radcli_avp_add_username() composes a User-Name from a username and an optional realm

**Requirement:** `radcli_avp_add_username(l, ctx, username, realm)` MUST add
a `User-Name` attribute holding `username` unchanged if `realm` is `NULL` and
`ctx` has no `default_realm` configured, or `"username@realm"` (explicit
`realm` argument taking priority over `ctx`'s configured `default_realm`)
otherwise — a convenience wrapper over `radcli_avp_add_str()`
(REQ-AVP2-DATA-002) for the common `user@realm` composition a caller would
otherwise build with `snprintf()` at every call site. It MUST return `-1`
without mutating the list if `ctx`'s dictionary has no `User-Name` attribute
or `username` is `NULL`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:421-447 (`radcli_avp_add_username`)
**Acceptance:** not exercised by the current local test suite (no
`tests/avp*.c`/`tests/ctx.c` call site found by inspection) —
`Needs-domain-check` whether this project wants dedicated coverage before
this graduates from code-inspection-only, same open question
REQ-AVP2-ERR-008 already flags for allocation-failure paths.
**Links:** REQ-AVP2-DATA-002

### REQ-AVP2-DATA-024 — radcli_avp_add_bytes_by_num() is radcli_avp_add_bytes()'s _by_num() wrapper

**Requirement:** `radcli_avp_add_bytes_by_num(l, ctx, attrid, vendor, value,
len)` MUST be equivalent to `radcli_avp_add_bytes(l, radcli_dict_lookup_num(ctx,
attrid, vendor), value, len)`, returning `-1` without mutating the list if
the numeric lookup resolves to no attribute — the `_by_num()` counterpart to
`radcli_avp_add_bytes()` (REQ-AVP2-DATA-002), completing the `_by_num()`
family REQ-AVP2-DATA-015 otherwise only states for the getters.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:348-357 (`radcli_avp_add_bytes_by_num`)
**Acceptance:** [DATA] positive, local — `tests/avp.c`'s "_by_num() family"
section (around `tests/avp.c:575-590`) adds attributes via the sibling
`_add_str_by_num()`/`_add_uint32_by_num()`/`_add_ip4_by_num()`/
`_add_ip6_by_num()` wrappers, all built the same way `radcli_avp_add_bytes_by_num()`
is; no test exercises `radcli_avp_add_bytes_by_num()` itself by name —
`Needs-domain-check` whether dedicated coverage is wanted, same as
REQ-AVP2-DATA-023.
**Links:** REQ-AVP2-DATA-002, REQ-AVP2-DATA-015

### REQ-AVP2-DATA-025 — radcli_avp_def() returns an attribute's dictionary definition

**Requirement:** `radcli_avp_def(a)` MUST return the `radcli_attr_def` that
`a` was added against (the same pointer originally passed to whichever
`radcli_avp_add_*()`/`_by_num()` call created it), or `NULL` if `a` is
`NULL`. This is the accessor that lets a caller iterating a list with
`radcli_avp_list_iter()`/`radcli_avp_iter_next()` (REQ-AVP2-DATA-005)
recover each attribute's identity without having pre-selected a `def` to
search for via `radcli_avp_get()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:500-504 (`radcli_avp_def`)
**Acceptance:** [DATA] positive, local — `tests/avp.c:142,147` confirm
`radcli_avp_def()` returns the expected definition for a `User-Name` and a
`NAS-IP-Address` attribute just added; `tests/avp.c:181` confirms it during
iteration.
**Links:** REQ-AVP2-DATA-005, REQ-AVP2-DATA-004

### REQ-AVP2-DATA-033 — every attribute-keyed accessor exists in both a `radcli_attr_def`-taking form and a `_by_num()` form

**Requirement:** For every `radcli_avp_add_*`/`radcli_avp_get_*`/
`radcli_avp_concat_*` function whose behaviour is parameterised by a single
target attribute (i.e. every function taking a `const radcli_attr_def *def`
directly, or the `(ctx, attrid, vendor)` triple that resolves to one via
`radcli_dict_lookup_num()`), the library MUST provide both forms: the
`def`-taking form for a caller that already holds (or caches, e.g. across a
loop) a `radcli_attr_def *`, and the `_by_num()` form for a caller that only
has the numeric attribute/vendor ID, with the two equivalent under
`def == radcli_dict_lookup_num(ctx, attrid, vendor)` — the relationship
REQ-AVP2-DATA-015 and REQ-AVP2-DATA-024 already state for the pairs that
have it. This is a 1:1 mapping in both directions: a `_by_num()` function
MUST NOT exist without a `def`-taking counterpart, and a `def`-taking
function parameterised by a single attribute MUST NOT exist without a
`_by_num()` counterpart, so that neither calling convention is a dead end
for a function this rule covers.
**Strength:** MUST
**Status:** DERIVED — no known exceptions. `radcli_avp_add_gigawords64()`/
`radcli_avp_get_gigawords64()` were closed by REQ-AVP2-DATA-034 (adds their
`_by_num()` siblings); `radcli_avp_concat_str_by_num()` was closed by
REQ-AVP2-DATA-036 (adds its `def`-taking sibling,
`radcli_avp_concat_str()`, REQ-AVP2-DATA-017).
**Source:** include/radcli/radcli2.h:300-357 (`radcli_avp_add_bytes()` /
`_add_str()` / `_add_uint32()` / `_add_uint64()` / `_add_ip4()` / `_add_ip6()`
/ `_add_ip4prefix()`, each paired with an `_by_num()` sibling at
radcli2.h:337-360); radcli2.h:399-454 (`radcli_avp_get_uint32()` /
`_get_uint64()` / `_get_ip6()` / `_get_ip4prefix()` / `_get_bytes()`, each
paired via `radcli_avp_get()` + `_by_num()` per REQ-AVP2-DATA-015);
radcli2.h (`radcli_avp_concat_str()`/`_concat_str_by_num()`, paired per
REQ-AVP2-DATA-036); radcli2.h (`radcli_avp_add_gigawords64()`/
`_get_gigawords64()`, paired with `_add_gigawords64_by_num()`/
`_get_gigawords64_by_num()` per REQ-AVP2-DATA-034)
**Acceptance:** [DATA] positive, local — `tests/avp2-api-symmetry-tests.sh`
automates this completeness check: it parses every
`radcli_avp_(add|get|concat)*` declaration in `include/radcli/radcli2.h`,
pairs every `_by_num()` name against a same-named `def`-taking declaration
and vice versa (restricted, by a signature check for `radcli_attr_def`, to
functions actually parameterised by a single target attribute — this is
what excludes `radcli_avp_get_uint32()` et al., which take an
already-resolved `radcli_avp *`, and `radcli_avp_add_username()`, which
takes no single target attribute, without needing a hardcoded exception
list), and fails listing any unpaired name. Registered in
`tests/meson.build`'s `shell_tests` so a future addition that forgets the
sibling function is caught automatically instead of waiting for another
manual audit.
**Links:** REQ-AVP2-DATA-002, REQ-AVP2-DATA-015, REQ-AVP2-DATA-017,
REQ-AVP2-DATA-024, REQ-AVP2-DATA-012, REQ-AVP2-ERR-013, REQ-AVP2-DATA-034,
REQ-AVP2-DATA-035, REQ-AVP2-DATA-036

---

## radcli_avp_decode()/radcli_avp_encode() — internal wire codec

The requirements below state the rest of the internal-only wire codec this
document's introduction flags as its own scope: `radcli_avp_decode()`
(parses a received RADIUS attribute region into a `radcli_avp_list`) and
`radcli_avp_encode()` (writes a `radcli_avp_list` out as RFC 2865
TLV attribute bytes, no packet header). Neither is exported via
`lib/radcli2.map`; both are called by `lib/request.c`/`lib/aaa2.c`
(`net2.md`'s scope, cited not owned here). They mirror `lib/avpair.c`'s
`rc_avpair_gen2()`/`lib/sendserver.c`'s `rc_pack_list()` framing rules
(RFC 2865 TLV attributes, RFC 2865 §5.26 VSA envelope with a 4-octet
Vendor-Id) but are an independent implementation with an independent test
suite (`tests/avp-codec.c`), not a shared code path.

### REQ-AVP2-DATA-026 — radcli_avp_decode()/radcli_avp_encode() encode RADCLI_TYPE_INTEGER/_IPADDR/_DATE as 4 octets, network byte order

**Requirement:** For an attribute whose `radcli_attr_type` is
`RADCLI_TYPE_INTEGER`, `RADCLI_TYPE_IPADDR`, or `RADCLI_TYPE_DATE`,
`radcli_avp_decode()` MUST convert the wire's 4-octet network-byte-order
value with `ntohl()` before storing it (so it lands in memory in the same
host-byte-order convention `radcli_avp_add_uint32()`/`radcli_avp_get_uint32()`
already use — matching legacy `VALUE_PAIR->lvalue`'s convention), and
`radcli_avp_encode()` MUST reverse this with `htonl()` on encode.
This is the 4-octet counterpart to REQ-AVP2-DATA-010/011's 8-octet
`RADCLI_TYPE_INTEGER64`/`RADCLI_TYPE_IFID` byte-order contract.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:1124-1132 (decode's `RADCLI_TYPE_INTEGER`/`_IPADDR`/
`_DATE` branch), lib/avp.c:1334-1344 (`radcli_avp_encode()`'s mirror
branch)
**Acceptance:** [DATA] positive, local — `tests/avp-codec.c:113-187`'s
round-trip section encodes a `NAS-IP-Address` (`RADCLI_TYPE_IPADDR`) and a
`Session-Timeout` (`RADCLI_TYPE_INTEGER`) through `radcli_avp_encode()`
then decodes the resulting bytes back with `radcli_avp_decode()`, confirming
both attributes round-trip to the original value.
**Links:** REQ-AVP2-DATA-009, REQ-AVP2-DATA-010, REQ-AVP2-DATA-011

### REQ-AVP2-DATA-028 — VSA sub-attributes are decoded by recursing with a 4-octet Vendor-Id envelope stripped, and re-added under the vendor's own attribute space

**Requirement:** When `radcli_avp_decode()` encounters a top-level
(`vendorspec == 0`) attribute numbered `26` (`PW_VENDOR_SPECIFIC`, RFC 2865
§5.26), it MUST read the following 4 octets as the Vendor-Id (network byte
order), then recursively decode the remaining bytes as a nested
attribute region scoped to that vendor — so each VSA sub-attribute is
looked up and stored via `radcli_dict_lookup_num(ctx, subattrid, vendor)`,
not `radcli_dict_lookup_num(ctx, subattrid, 0)`. `radcli_avp_encode()`
MUST reverse this: for an attribute definition whose vendor is non-zero, it
MUST emit the `26`/length/Vendor-Id envelope before the sub-attribute's own
type/length/value, and MUST patch the envelope's length byte to cover the
sub-attribute once known. A `26`-numbered attribute encountered while
already inside a VSA (`vendorspec != 0`) is not itself recursed into again
— RFC 2865's VSA envelope is one level deep in this implementation.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:1017-1032 (decode's VSA-envelope branch, the recursive
`avp_decode_into()` call), lib/avp.c:1303-1310,1354-1356 (encode's VSA
envelope emission and length patch-back)
**Acceptance:** [DATA] positive, local — `tests/avp-codec.c:113-187`'s
round-trip section includes an `Agent-Circuit-Id`-style VSA attribute
alongside non-VSA ones, confirming it round-trips through both directions
in the same call as everything else.
**Links:** REQ-AVP2-DATA-002

### REQ-AVP2-ERR-029 — a structurally malformed attribute region aborts the whole decode; an unrecognised attribute, unrecognised vendor, or undersized VSA envelope is skipped instead

**Requirement:** `radcli_avp_decode()` MUST return `-1` (aborting the entire
decode, no partial `*out`) if the attribute region is truncated below 2
bytes, an attribute's length byte is less than 2, or an attribute's declared
length exceeds the bytes remaining in the region — these indicate the
region itself cannot be parsed, not that one attribute is unrecognised.
By contrast, `radcli_avp_decode()` MUST treat each of the following as
non-fatal — log at `LOG_WARNING` and skip just that attribute (or, for a
VSA envelope, that whole VSA and all its sub-attributes), continuing to
decode the rest of the region, returning `0` with a `*out` that omits only
the skipped attribute(s): an attribute ID unrecognised in `ctx`'s loaded
dictionary (standard or vendor-specific); a VSA envelope shorter than the
4 bytes needed for its Vendor-Id; and a VSA whose Vendor-Id resolves to no
loaded `VENDOR`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:997-1006 (structural framing checks, hard failure),
lib/avp.c:1017-1044 (VSA-envelope-too-short and unknown-vendor skip paths),
lib/avp.c:1035-1045 (unrecognised-attribute skip path)
**Acceptance:** [ERR] negative, local — `tests/avp-codec.c:314-335` confirms
a 1-byte region, a length-byte-of-1 attribute, and an attribute whose
declared length exceeds the buffer are all hard decode failures (`-1`).
`tests/avp-codec.c:339-366` confirms an unrecognised attribute ID and an
undersized VSA envelope are each skipped, yielding a successful decode of
an empty list rather than a failure. `tests/avp-codec.c:369-384` confirms a
VSA for an unrecognised vendor is skipped whole.
**Links:** REQ-AVP2-DATA-028

### REQ-AVP2-SEC-030 — radcli_avp_decode() transparently reverses RFC 2868 §3.5/RFC 2548 salt-encryption for an "encrypt=Tunnel-Password"-flagged attribute, given a secret and request authenticator

**Requirement:** For an attribute the dictionary flags `encrypt=Tunnel-Password`
(`Tunnel-Password`, `MS-MPPE-Send-Key`, `MS-MPPE-Recv-Key` in the bundled
dictionary — `radcli_dict_flags_by_id()`'s `encrypt_type == 2`),
`radcli_avp_decode()` MUST reverse the RFC 2868 §3.5/RFC 2548 §2.4.2-2.4.3
salt-encryption keystream (`b(1) = MD5(secret‖request_authenticator‖salt)`,
`b(i) = MD5(secret‖ciphertext(i-1))` for `i > 1`, XORed against each
16-byte ciphertext block) using the caller-supplied `secret`/
`request_authenticator` and the attribute's own embedded 2-octet salt, and
store the decrypted plaintext (a `has_tag`-flagged attribute's leading Tag
octet, if present per the dictionary's `has_tag` option, is skipped before
the salt) so `radcli_avp_get_bytes()` returns it as plaintext. If `secret`
or `request_authenticator` is `NULL`, the attribute MUST instead be skipped
(logged, not a hard decode error — REQ-AVP2-ERR-029's non-fatal-skip
contract) rather than stored ciphertext or rejected as malformed framing.
Only decryption is implemented; `radcli_avp_encode()` never
originates an `encrypt=Tunnel-Password`-flagged attribute (REQ-AVP2-ERR-032).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:909-943 (`salt_decrypt`), lib/avp.c:1047-1091
(`avp_decode_into()`'s salt-encryption branch)
**Acceptance:** [SEC] positive, local — `tests/avp-codec.c:385-490`
decrypts a `Tunnel-Password` attribute against test vectors computed
independently in Python (`hashlib.md5`), not derived from this
implementation, confirming the algorithm is RFC-correct rather than merely
self-consistent. [ERR] negative, local — the same section
(`tests/avp-codec.c:491`) confirms decoding with the wrong secret does not
raise a hard error and does not yield the correct plaintext.
**Links:** REQ-AVP2-ERR-029, REQ-AVP2-ERR-032

### REQ-AVP2-SEC-031 — radcli_avp_encode() implements RFC 2865 §5.2 User-Password encryption for an "encrypt=User-Password"-flagged attribute, padding to a 16-byte boundary and rejecting rather than truncating an over-length password

**Requirement:** For an attribute the dictionary flags `encrypt=User-Password`
(`radcli_dict_flags_by_id()`'s `encrypt_type == 1`), `radcli_avp_encode()`
MUST encrypt the stored value per RFC 2865 §5.2 (`b(1) =
MD5(secret‖request_authenticator)`, `b(i) = MD5(secret‖ciphertext(i-1))` for
`i > 1`, XORed against each 16-byte plaintext block, zero-padded up to a
multiple of 16 bytes — a zero-length password still encodes one all-zero
16-byte block), returning `-1` without writing partial output if `secret` or
`request_authenticator` is `NULL`, or if the stored value exceeds
`AUTH_PASS_LEN` (128) bytes. The over-length case MUST be rejected outright,
not silently truncated to `AUTH_PASS_LEN` the way legacy `rc_pack_list()`
does — truncating would authenticate a different, shorter password than the
caller believes it sent. If `n_encrypted` is non-`NULL`, it MUST be
incremented once per attribute routed through this path, letting a caller
cross-check the count against how many `User-Password`-like attributes its
own list should contain.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:945-981 (`user_password_encrypt`), lib/avp.c:1238-1285
(`radcli_avp_encode()`'s `encrypt_type == 1` branch)
**Acceptance:** [SEC] positive, local — `tests/avp-codec.c:775-825` encrypts
a 7-byte (one block) and a 20-byte (two block) password against vectors
computed independently in Python (`hashlib.md5`), confirming both the
ciphertext and `n_encrypted`. [ERR] negative, local —
`tests/avp-codec.c:826-860` confirms a password one byte over
`AUTH_PASS_LEN` is rejected rather than truncated;
`tests/avp-codec.c:861-878` confirms encoding without a secret is refused
rather than sent as plaintext.
**Links:** REQ-AVP2-SEC-030, REQ-AVP2-ERR-032

### REQ-AVP2-ERR-032 — radcli_avp_encode() refuses any dictionary-flagged encryption it does not implement, rather than sending it unencrypted

**Requirement:** `radcli_avp_encode()` MUST consult
`radcli_dict_flags_by_id()` for every attribute it encodes and treat the
result as a whitelist, not a blocklist: an attribute is encoded unencrypted
only when the dictionary carries no `encrypt=` flag for it at all
(`encrypt_type == 0`); `encrypt_type == 1` (`User-Password`) is encrypted
per REQ-AVP2-SEC-031; every other non-zero `encrypt_type` (`2`,
`Tunnel-Password`, today) MUST cause `radcli_avp_encode()` to log at
`LOG_ERR` and return `-1` without writing any output, rather than falling
back to sending the value in the clear. This whitelist design means a
dictionary addition can never silently cause `radcli_avp_encode()`
to start sending something in the clear that the *code* does not yet know
how to encrypt — it can only fail closed. It cannot, by itself, catch a
dictionary that is simply missing an `encrypt=` flag it should carry; that
gap is what `n_encrypted` (REQ-AVP2-SEC-031) exists for.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avp.c:1220-1290 (`radcli_avp_encode()`'s
`switch (fl ? fl->encrypt_type : 0)`, `default:` branch)
**Acceptance:** not exercised by the current local test suite
(`tests/avp-codec.c` exercises `encrypt_type == 0`/`1` but the bundled
dictionary defines no attribute with `encrypt_type == 2` on the encode
side to construct a negative fixture from) — `Needs-domain-check` whether
this project wants a dedicated fixture (e.g. a test-dictionary attribute
flagged `encrypt=Tunnel-Password`) added to `tests/avp-codec.c`, same
open-coverage pattern REQ-AVP2-ERR-008/DATA-023 already flag.
**Links:** REQ-AVP2-SEC-030, REQ-AVP2-SEC-031
