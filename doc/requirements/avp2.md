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
arguably `dict.md`'s concern); `radcli_avp_decode()`/`radcli_avp_encode()`
(the internal-only wire codec declared in `lib/avp.h`, not exported via
`lib/radcli.map` — RADIUS wire framing belongs to `net.md`'s scope per
`attrs.md`'s own NET/wire-framing split). Both are left for a follow-up
document rather than retroactively written here.

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
