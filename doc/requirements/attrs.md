---
title: attribute-list construction, access, and the auth/acct/aaa request-building flow
generator: requirements-from-implementation
id-prefix: REQ-ATTR
categories:
  DATA: VALUE_PAIR list construction, encoding, decoding, and accessor contracts
  NET: request building for rc_auth/rc_auth_proxy/rc_acct/rc_acct_proxy/rc_check/rc_aaa* (up to, not including, wire transmission)
  SEC: shared-secret and request-authenticator handling via RC_AAA_CTX/SEND_DATA
  ERR: error propagation and failure-return contracts
sources:
  - lib/avpair.c
  - lib/buildreq.c
  - lib/aaa_ctx.c
  - include/radcli/radcli.h
  - include/includes.h
  - lib/radcli.map.in
---

# Attribute-List and Request-Building Requirements

This document covers the part of radcli between "the caller has a parsed `rc_handle`"
and "bytes go on the wire": building, editing, encoding, decoding, and inspecting
`VALUE_PAIR` attribute lists (`lib/avpair.c`), and the `rc_auth`/`rc_auth_proxy`/
`rc_acct`/`rc_acct_proxy`/`rc_check`/`rc_aaa*` call flow that turns a
`VALUE_PAIR` list plus configuration into a `SEND_DATA` request and dispatches it
(`lib/buildreq.c`), plus the `RC_AAA_CTX` handle that lets a caller recover the secret
and request-authenticator vector used by a completed request for building an
idempotent retry (`lib/aaa_ctx.c`). "NET" here means *preparing* data the network
layer will send — selecting a server list, filling in NAS-Port/Acct-Delay-Time,
building the `SEND_DATA` record, and handling per-server retry/failover/broadcast
control flow — not RADIUS wire framing, packet authentication, or socket I/O, which
belong to `net.md` (`lib/sendserver.c`, `lib/tls.c`) and are only cross-referenced
here. `general.md`'s `REQ-GEN-SEC-006` (secret handling), `REQ-GEN-MEM-*` (allocator
and string/buffer safety), and `REQ-GEN-ABI-*` (symbol/struct stability) apply
throughout and are linked rather than restated.

---

## DATA — VALUE_PAIR list construction, encoding, decoding, and accessors

### REQ-ATTR-DATA-001 — Attribute identity is a 64-bit vendor+attribute-ID encoding

**Requirement:** `VALUE_PAIR.attribute` and `DICT_ATTR.value` MUST encode a
standard or vendor-specific attribute as a single `uint64_t`: the vendor PEN in
the upper 32 bits and the attribute ID in the lower 32 bits, built with
`RADCLI_VENDOR_ATTR_SET(attr, vendor)` and decomposed with the `VENDOR(x)`/
`ATTRID(x)` macros. Standard (non-vendor) attributes have vendor `0` in the
upper bits.
**Strength:** MUST
**Status:** DERIVED
**Source:** include/radcli/radcli.h:63-68, 499
**Acceptance:** [DATA] unit, local — round-trip `VENDOR(RADCLI_VENDOR_ATTR_SET(a, v)) == v` and `ATTRID(RADCLI_VENDOR_ATTR_SET(a, v)) == a` for representative `a`/`v` pairs, including `v = 0`.
**Links:** REQ-ATTR-DATA-002, REQ-ATTR-DATA-018

### REQ-ATTR-DATA-002 — New pairs MUST be validated against the loaded dictionary

**Requirement:** `rc_avpair_new()` (and therefore `rc_avpair_add()`) MUST look
up the requested attribute (and, if `vendorspec != VENDOR_NONE`, the vendor)
via `rc_dict_getattr()`/`rc_dict_getvend()` and fail (return `NULL`, logging at
`LOG_ERR`) if either is not present in the dictionary loaded into `rh`,
before any `VALUE_PAIR` is allocated.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:196-217
**Acceptance:** [DATA] negative, local — `rc_avpair_new()`/`rc_avpair_add()` with an attribute ID or vendor ID absent from the loaded dictionary returns `NULL`.
**Links:** REQ-ATTR-SEC-036, REQ-DICT-* (dict.md)

### REQ-ATTR-DATA-003 — rc_avpair_assign enforces per-type encoding and length rules

**Requirement:** `rc_avpair_assign()` MUST encode `pval`/`len` according to
`vp->type`: `PW_TYPE_STRING` computes `len` from `strlen()` when `len == -1`,
rejects (`-1`) lengths exceeding `AUTH_STRING_LEN` (253) for standard
attributes or `AUTH_STRING_LEN - VSA_HDR_LEN` (247) for vendor-specific ones,
and NUL-terminates `vp->strvalue`; `PW_TYPE_DATE`/`PW_TYPE_INTEGER`/
`PW_TYPE_IPADDR` copy a raw `uint32_t` from `*pval` into `vp->lvalue` with no
range check; `PW_TYPE_IPV6ADDR` requires `len == 16` exactly; `PW_TYPE_IPV6PREFIX`
requires `2 <= len <= 18`; any other `vp->type` is rejected as "no attribute ...
in dictionary".
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:135-183; include/includes.h:151-152 (`VSA_HDR_LEN`)
**Acceptance:** [DATA] unit, local — for each `rc_attr_type`, a length one byte over the limit is rejected (`-1`) and a length at the limit succeeds; an `IPV6ADDR` assign with `len != 16` and an `IPV6PREFIX` assign with `len` outside `[2,18]` are rejected.
**Links:** REQ-ATTR-DATA-004

### REQ-ATTR-DATA-004 — VSA string budget is 6 bytes smaller than a standard attribute's

**Requirement:** The maximum `PW_TYPE_STRING` value length accepted by
`rc_avpair_assign()` MUST be `AUTH_STRING_LEN - VSA_HDR_LEN` (247 bytes) when
`VENDOR(vp->attribute) != 0`, versus `AUTH_STRING_LEN` (253 bytes) for a
standard attribute, reflecting the 6-byte Vendor-Specific envelope
(4-byte vendor ID + 1-byte sub-type + 1-byte sub-length) `net.md`'s wire
encoder must still fit inside a 255-byte RADIUS attribute.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:146; include/includes.h:151-152
**Acceptance:** [DATA] unit, local — a 248-byte string value assigned to a vendor-specific `PW_TYPE_STRING` attribute is rejected; a 253-byte string assigned to a standard one succeeds.
**Links:** REQ-ATTR-DATA-003, REQ-NET-DATA-* (packet packing, net.md)

### REQ-ATTR-DATA-005 — Digest-Auth pseudo-attributes are repacked into PW_DIGEST_ATTRIBUTES

**Requirement:** When `rc_avpair_new()` or `rc_avpair_parse()` builds a pair
whose attribute is one of `PW_DIGEST_REALM`..`PW_DIGEST_USER_NAME` (1063-1072,
radcli-internal convenience IDs, not on-wire values), the implementation MUST
re-pack the value as a 2-byte-prefixed sub-TLV (`strvalue[0]` = sub-type
`attribute - PW_DIGEST_REALM + 1`, `strvalue[1]` = total length including the
2-byte header) and rewrite `vp->attribute`/`pair->attribute` to
`PW_DIGEST_ATTRIBUTES` (207), so the caller can build Digest attributes with
symbolic per-field names while the wire encoder in `net.md` sees a single
`PW_DIGEST_ATTRIBUTES` pair.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:226-249 (rc_avpair_new), lib/avpair.c:816-840 (rc_avpair_parse)
**Acceptance:** [DATA] unit, local — `rc_avpair_add(rh, &list, PW_DIGEST_REALM, "example.com", -1, 0)` yields a list entry with `attribute == PW_DIGEST_ATTRIBUTES`, `strvalue[0] == 1`, `strvalue[1] == 2 + strlen("example.com")`.
**Links:** REQ-ATTR-DATA-006

### REQ-ATTR-DATA-006 — Digest value overflow is truncated, not rejected (accepted, intentional)

**Requirement:** Both Digest-repacking sites (`rc_avpair_new()` and
`rc_avpair_parse()`) MUST silently clamp `lvalue` to `AUTH_STRING_LEN - 2`
when the supplied Digest sub-field value is longer, rather than returning an
error as `rc_avpair_assign()`'s `PW_TYPE_STRING` path does for an equivalent
over-length standard string (`REQ-ATTR-DATA-003`).
**Strength:** MUST (as implemented, confirmed intentional)
**Status:** DERIVED
**Source:** lib/avpair.c:239-240 (rc_avpair_new), lib/avpair.c:829-830 (rc_avpair_parse); contrast lib/avpair.c:146-149 (rc_avpair_assign, which rejects)
**Acceptance:** [DATA] unit, local — assigning a 260-byte value to
`PW_DIGEST_REALM` succeeds and returns a pair with `lvalue == AUTH_STRING_LEN`
(251+2), not an error.
**Links:** REQ-ATTR-DATA-003, REQ-ATTR-DATA-005

### REQ-ATTR-DATA-007 — rc_avpair_insert links a single node into a list, aborting on caller misuse

**Requirement:** `rc_avpair_insert(a, p, b)` MUST insert `b` immediately after
`p` in list `a`, or at the end of `a` when `p == NULL`, or make `b` the sole
element when `*a == NULL`. It MUST `abort()` the process if `b->next != NULL`
on entry, since that indicates the caller is passing a node that is already
linked into some list (a state this function cannot safely splice from).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:532-578
**Acceptance:** [DATA][ERR] unit, local — inserting a fresh (`next == NULL`) node at `p == NULL` appends it as the new tail; inserting after a specific `p` places it immediately after `p`; passing a node with `next != NULL` aborts the process (verified via a crash/signal test, not a return-code check).
**Links:** REQ-ATTR-DATA-008

### REQ-ATTR-DATA-008 — rc_avpair_add always appends to the list tail

**Requirement:** `rc_avpair_add()` MUST construct the pair via
`rc_avpair_new()` and, on success, insert it at the end of `*list` via
`rc_avpair_insert(list, NULL, vp)` — never at the head or at an arbitrary
position — matching its documented "always appends" contract.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:32-59
**Acceptance:** [DATA] unit, local — two successive `rc_avpair_add()` calls on the same list produce a list whose iteration order (via `rc_avpair_next()`) matches call order.
**Links:** REQ-ATTR-DATA-007

### REQ-ATTR-DATA-009 — rc_avpair_remove deletes the first matching pair only

**Requirement:** `rc_avpair_remove(list, attrid, vendorspec)` MUST scan `*list`
for the first node whose `attribute` equals `RADCLI_VENDOR_ATTR_SET(attrid, vendorspec)`
(or plain `attrid` when `vendorspec == VENDOR_NONE`), unlink and free exactly
that one node, and leave the rest of the list (including any further matches)
untouched; it MUST be a no-op if no match is found.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:69-101
**Acceptance:** [DATA] unit, local — a list with two pairs sharing the same `(attrid, vendorspec)` has exactly one removed by a single `rc_avpair_remove()` call; calling it again removes the second.
**Links:** REQ-ATTR-DATA-001

### REQ-ATTR-DATA-010 — rc_avpair_get / rc_avpair_next are linear-scan/iteration primitives

**Requirement:** `rc_avpair_get(vp, attrid, vendorspec)` MUST return the first
node from `vp` onward whose `attribute` matches (by the same encoding as
REQ-ATTR-DATA-009), or `NULL` if none matches. `rc_avpair_next(t)` MUST return
`t->next` (a thin accessor) so calling code that must not depend on
`VALUE_PAIR`'s internal layout can still walk the list.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:112-115, 480-489; include/radcli/radcli.h:490-494 (doc note directing callers to the accessor API instead of the struct)
**Acceptance:** [DATA] unit, local — `rc_avpair_get()` on a list with a known matching third element returns that element; on an empty or non-matching list returns `NULL`. Iterating via `rc_avpair_next()` from the list head visits every element exactly once and terminates at `NULL`.

### REQ-ATTR-DATA-011 — rc_avpair_copy performs an atomic, all-or-nothing shallow copy

**Requirement:** `rc_avpair_copy(p)` MUST allocate one new `VALUE_PAIR` per
source node, copy all fields by struct assignment (`*vp = *p`), and relink the
copies into a new list preserving source order. If any allocation in the
middle of the list fails, it MUST free every node allocated so far in this
call and return `NULL` rather than returning a partial list.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:497-521
**Acceptance:** [DATA][ERR] unit, local — copying a non-empty list yields a list of equal length with field-identical, but pointer-distinct, nodes; a simulated allocation failure partway through leaves no leaked nodes and returns `NULL`.
**Links:** REQ-GEN-MEM-002

### REQ-ATTR-DATA-012 — rc_avpair_free releases an entire list; NULL is a valid no-op input

**Requirement:** `rc_avpair_free(pair)` MUST walk the list from `pair` to its
end, calling `free()` on every node, and MUST accept `pair == NULL` as a
no-op (no crash, no error).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:584-594
**Acceptance:** [DATA] unit, local — `rc_avpair_free(NULL)` returns without incident; freeing an N-node list does not leak (verified under a leak detector).

### REQ-ATTR-DATA-013 — rc_avpair_parse decodes a "name = value[, ...]" text line per attribute type

**Requirement:** `rc_avpair_parse()` MUST tokenize `buffer` into
`name`/`=`/`value` triples separated by whitespace/commas/newline, resolve
`name` via `rc_dict_findattr()`, and decode `value` per the resolved
`rc_attr_type`: `PW_TYPE_STRING` via `rc_avpair_assign()` (quoted or bare,
per `rc_fieldcpy()`'s `"`-aware tokenizing); `PW_TYPE_INTEGER` as a decimal
literal when the first value character is a digit, otherwise via
`rc_dict_findval()` symbolic lookup; `PW_TYPE_IPADDR`/`PW_TYPE_IPV6ADDR` via
`inet_pton()`; `PW_TYPE_IPV6PREFIX` as `addr/prefixlen`; `PW_TYPE_DATE` via
`rc_str2tm()` against today's date at midnight local time.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:650-867
**Acceptance:** [DATA] unit, local — one representative parse per `rc_attr_type` produces a `VALUE_PAIR` with the expected `lvalue`/`strvalue`; a quoted string value containing a comma is parsed as one token, not split.
**Links:** REQ-ATTR-ERR-038, REQ-DICT-* (rc_dict_findattr/rc_dict_findval, dict.md)

### REQ-ATTR-DATA-014 — rc_avpair_tostr renders one pair as printable name/value strings, per type

**Requirement:** `rc_avpair_tostr()` MUST write `pair->name` into `name` and a
type-appropriate printable rendering into `value`: `PW_TYPE_STRING` octal-escapes
(`\NNN`) non-printable bytes and truncates to fit `lv`; `PW_TYPE_INTEGER`
prefers the symbolic name from `rc_dict_getval()`, falling back to a decimal
literal; `PW_TYPE_IPADDR` via `inet_ntoa()`; `PW_TYPE_IPV6ADDR`/`PW_TYPE_IPV6PREFIX`
via `inet_ntop()` (the latter appending `/prefixlen`); `PW_TYPE_DATE` via
`strftime()` with format `"%m/%d/%y %H:%M:%S"`. For `PW_TYPE_STRING` pairs
whose `attribute == PW_DIGEST_ATTRIBUTES`, it MUST skip the 2-byte sub-TLV
header written by REQ-ATTR-DATA-005 before rendering. It MUST return `-1`
(without touching `name`/`value` beyond zeroing them) if `pair` is `NULL` or
has an empty `name`, or if `pair->type` is not one of the above.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:879-988
**Acceptance:** [DATA] unit, local — one round-trip test per `rc_attr_type` (`rc_avpair_add()` then `rc_avpair_tostr()`) produces the expected string; `rc_avpair_tostr(rh, NULL, ...)` returns `-1`.
**Links:** REQ-ATTR-DATA-005

### REQ-ATTR-DATA-015 — rc_avpair_log formats a whole list into a caller buffer, stopping at capacity

**Requirement:** `rc_avpair_log()` MUST call `rc_avpair_tostr()` on each pair
in turn and append a `"%-32s = '%s'\n"`-formatted line to `buf`, stopping
(returning `buf` as-is, without appending further lines) once the next line's
estimated size would not fit in the remaining `buf_len`, and MUST return
`NULL` if any pair fails to stringify.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:1000-1018
**Acceptance:** [DATA] unit, local — logging a list that fits well within `buf_len` renders every pair; logging into a deliberately small `buf_len` stops before the buffer's declared capacity is exceeded (see REQ-ATTR-DATA-016 for the case where this guarantee can be violated).

### REQ-ATTR-DATA-016 — rc_avpair_log() MUST bound each rendered line by the actual written length, not a fixed-width estimate

**Requirement:** `rc_avpair_log()` MUST render each pair with
`snprintf(buf + len, buf_len - len, "%-32s = '%s'\n", name, value)` and use
`snprintf()`'s own return value to determine both whether the line fit and
how far `len` advances, rather than a pre-computed size estimate. The
previous estimate (`nlen = len + 32 + 3 + strlen(value) + 2 + 2`) assumed the
rendered name occupies exactly 32 bytes (matching `%-32s`'s *minimum* field
width), but `%-32s` does not truncate a longer name — `pair->name` can be up
to `RC_NAME_LENGTH` (64) bytes from the dictionary — so for a pair whose name
exceeded 32 bytes, the actual bytes the previous `sprintf()` wrote could
exceed the estimate used to decide whether the line fit in `buf`, and
`sprintf()` (not `snprintf()`) had no bound of its own.
**Strength:** MUST NOT (write past `buf_len`) ; MUST (use snprintf's actual
return value for bounds tracking) — per `REQ-GEN-MEM-004`
**Status:** DERIVED
**Source:** lib/avpair.c:1000-1017
**Acceptance:** [DATA][MEM] negative, local — construct a pair whose
dictionary name is longer than 32 bytes; `rc_avpair_log()` does not overrun
`buf` regardless of `buf_len`, verified under ASan.
**Links:** REQ-GEN-MEM-004, REQ-ATTR-DATA-015

### REQ-ATTR-DATA-017 — Typed accessors validate `vp->type` and never allocate

**Requirement:** `rc_avpair_get_uint32()` MUST return `0` and set `*res` (if
non-NULL) only when `vp->type` is `PW_TYPE_DATE`, `PW_TYPE_INTEGER`, or
`PW_TYPE_IPADDR`, else `-1`. `rc_avpair_get_in6()` MUST return `0` for
`PW_TYPE_IPV6ADDR` (fixed 16-byte copy) or `PW_TYPE_IPV6PREFIX` (validating
`2 <= vp->lvalue <= 18` first), else `-1`. `rc_avpair_get_raw()` MUST return
`0` and set `*res` to a pointer *into* `vp->strvalue` (not a copy) for
`PW_TYPE_STRING`/`PW_TYPE_IPV6ADDR`/`PW_TYPE_IPV6PREFIX`, else `-1`.
`rc_avpair_get_attr()` MUST unconditionally report `vp->type`/`vp->attribute`
and never fail. None of the four allocate memory.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:1030-1109
**Acceptance:** [DATA][ERR] unit, local — each accessor called with a `vp->type` outside its valid set returns `-1` and does not write through a non-NULL output pointer; `rc_avpair_get_raw()`'s returned pointer, when written through, is observed to mutate the original `vp->strvalue` (proving it is not a copy).
**Links:** REQ-ATTR-DATA-001

### REQ-ATTR-DATA-018 — rc_avpair_gen decodes wire attribute bytes, recursing one level for VSAs

**Requirement:** `rc_avpair_gen()`/`rc_avpair_gen2()` MUST decode a raw
attribute-region buffer (the bytes following the 20-byte RADIUS header) into
`VALUE_PAIR` nodes: each TLV's 1-byte type and 1-byte length are validated
(`length >= 2` and `<=` remaining buffer) before consuming it; type
`PW_VENDOR_SPECIFIC` (26) at `vendorspec == 0` MUST be treated as a
Vendor-Specific envelope — its 4-byte vendor PEN validated via
`rc_dict_getvend()`, and its remaining bytes recursively decoded by a nested
`rc_avpair_gen2()` call with `vendorspec` set to that PEN — exactly one level
deep (a VSA payload is not itself scanned for a further nested VSA envelope
beyond what a normal attribute-ID lookup under that vendor would find).
Attribute IDs not found via `rc_dict_getattr()` under the current
`vendorspec`, and attributes whose wire length does not match their declared
`rc_attr_type`'s fixed size (`INTEGER`/`IPADDR`/`DATE` != 4 bytes,
`IPV6ADDR` != 16 bytes, `IPV6PREFIX` outside `[2,18]`), MUST be logged
(`LOG_WARNING`/`LOG_ERR`) and skipped, not treated as a hard decode failure.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:266-434, 459-471
**Acceptance:** [DATA] unit, local — decoding a buffer containing one recognized attribute, one attribute with an unknown ID, and one VSA envelope with two recognized sub-attributes yields a list with 3 entries (the unknown one skipped) in wire order; a VSA whose declared vendor PEN is not in the dictionary is skipped, not a hard error.
**Links:** REQ-ATTR-DATA-001, REQ-ATTR-ERR-039

### REQ-ATTR-DATA-019 — rc_avpair_gen's hard-error path frees the whole list, including any caller-supplied prefix

**Requirement:** On a hard decode error (a malformed length field for the
outer TLV being parsed, or a `malloc`/`calloc` failure while building a
decoded node), `rc_avpair_gen2()` MUST call `rc_avpair_free()` on the entire
`head` list — which includes whatever `VALUE_PAIR` list the caller passed in
via the `pair` parameter for the *first* (non-recursive) call — and return
`-1`, and `rc_avpair_gen()` MUST then return `NULL`. A caller that passed a
non-NULL `pair` into `rc_avpair_gen()` and receives `NULL` back MUST NOT
reuse or re-free that original list; it has already been freed.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:280-282, 428-434, 459-471
**Acceptance:** [DATA][ERR] negative, local — call `rc_avpair_gen(rh, existing_list, malformed_bytes, len, 0)` with a length byte that overruns the buffer; verify the return is `NULL` and (under a leak/use-after-free detector) that `existing_list`'s nodes were freed exactly once, not leaked and not double-freed by the caller.
**Links:** REQ-GEN-MEM-002, REQ-ATTR-ERR-039

### REQ-ATTR-DATA-020 — VALUE_PAIR.pad is reserved for future ABI-additive growth

**Requirement:** The 32-byte `pad` field at the end of `VALUE_PAIR` MUST NOT
be read or written by any function in `lib/` as if it held attribute data
today; it exists so a future field can be added to `VALUE_PAIR` without
changing the struct's size (an ABI-additive change under REQ-GEN-ABI-002),
not as usable storage in the current implementation.
**Strength:** MUST NOT (use today) 
**Status:** DERIVED
**Source:** include/radcli/radcli.h:504 (`char pad[32]; //!< unused pad`)
**Acceptance:** [DATA][ABI] code-review — no new code reads/writes `VALUE_PAIR.pad`; any change that gives it meaning is reviewed as a `REQ-GEN-ABI-002` struct-layout change even though the total `sizeof(VALUE_PAIR)` does not change.
**Links:** REQ-GEN-ABI-002

---

## NET — request building (server selection, SEND_DATA, per-server control flow)

### REQ-ATTR-NET-021 — rc_buildreq populates a SEND_DATA record's transport-selection fields, not its pair lists

**Requirement:** `rc_buildreq()` MUST set `data->server`, `data->secret`,
`data->svc_port`, `data->timeout`, `data->retries`, `data->code`, and a fresh
per-call `data->seq_nbr` from `rc_get_id()` (`random() & UCHAR_MAX`); it MUST
NOT touch `data->send_pairs`/`data->receive_pairs`, which callers (or
`rc_aaa_ctx_server()`) are responsible for initializing before/after calling
it.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:21-57
**Acceptance:** [NET] unit, local — calling `rc_buildreq()` on a `SEND_DATA` whose `send_pairs`/`receive_pairs` were pre-set leaves those two fields unchanged; two successive calls typically (not guaranteed) produce different `seq_nbr` values, since `seq_nbr` is not a security-sensitive nonce, only a retransmission-matching ID (see REQ-NET-* in net.md for how it's used on the wire).
**Links:** REQ-ATTR-NET-025

### REQ-ATTR-NET-022 — rc_aaa_ctx picks authserver vs. acctserver by transport and request code

**Requirement:** For a given `request_type`, `rc_aaa_ctx()` MUST select the
`"authserver"` list when `rh->so_type` is `RC_SOCKET_TLS`/`RC_SOCKET_DTLS`
*or* `request_type != PW_ACCOUNTING_REQUEST`, and the `"acctserver"` list
otherwise (plain accounting request over UDP/TCP), then forward to
`rc_aaa_ctx_server()`. It MUST return `ERROR_RC` if the selected list is
empty/unconfigured (`rc_conf_srv()` returns `NULL`). This selection logic is
factored into the internal helper `rc_select_aaa_server()`, shared verbatim
by `rc_aaa_ctx()` and `rc_acct_async()` (`REQ-ATTR-NET-030`) — both MUST
apply the identical authserver/acctserver rule, not divergent copies.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:69-85 (`rc_select_aaa_server`), lib/buildreq.c:166-179 (`rc_aaa_ctx`)
**Acceptance:** [NET] unit, local — with `so_type == RC_SOCKET_TLS`, an accounting-type request still selects `authserver`; with `so_type == RC_SOCKET_UDP`, it selects `acctserver`; with no `acctserver` configured, `rc_acct()` returns `ERROR_RC` before any packet is built.
**Links:** REQ-NET-* (transport type / TLS-DTLS shared-port behavior, net.md), REQ-ATTR-NET-030

### REQ-ATTR-NET-023 — rc_aaa_ctx_server auto-fills NAS-Port and seeds Acct-Delay-Time before its retry loop

**Requirement:** `rc_aaa_ctx_server()` MUST add a `PW_NAS_PORT` pair with
value `nas_port` only if `add_nas_port != 0` *and* `data.send_pairs` does not
already contain one (caller-supplied NAS-Port is never overwritten). For
`request_type == PW_ACCOUNTING_REQUEST`, it MUST ensure a
`PW_ACCT_DELAY_TIME` pair exists — creating one with value `0` and recording
the creation time as `start_time` if absent, or, if the caller already
supplied one, computing `start_time` by subtracting the *existing* pair's
value from the current time so that later delay computation is consistent
whether or not the caller pre-seeded the field. Both happen once, before the
per-server retry loop begins. This fill logic is factored into the internal
helper `rc_fill_acct_pairs()`, shared verbatim by `rc_aaa_ctx_server()` and
`rc_aaa_ctx_server_async()` (`REQ-ATTR-NET-030`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:102-140 (`rc_fill_acct_pairs`), lib/buildreq.c:222-224 (call site in `rc_aaa_ctx_server`)
**Acceptance:** [NET] unit, local — an accounting request with no `PW_NAS_PORT`/`PW_ACCT_DELAY_TIME` gets both added; one with a caller-supplied `PW_NAS_PORT` keeps the caller's value; one with a caller-supplied non-zero `PW_ACCT_DELAY_TIME` does not get a second such pair added.
**Links:** REQ-ATTR-NET-024, REQ-ATTR-NET-030

### REQ-ATTR-NET-024 — Acct-Delay-Time is recomputed on every retransmission attempt

**Requirement:** `rc_aaa_ctx_server()` MUST recompute `dtime =
rc_getmtime() - start_time` and write it into the `PW_ACCT_DELAY_TIME` pair
via `rc_avpair_assign()` immediately before *every* per-server transmission
attempt in its retry loop (not only the first), so a request retried against
a second server reports actual elapsed wait time, not a stale value from the
first attempt.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:190-193
**Acceptance:** [NET] unit, local (with a fake clock/mockable `rc_getmtime()`) — a two-server accounting request that times out against the first server and succeeds against the second carries a larger `PW_ACCT_DELAY_TIME` value in the second attempt than the first.
**Links:** REQ-ATTR-NET-023

### REQ-ATTR-NET-025 — rc_aaa_ctx_server stops on OK/CHALLENGE/REJECT, fails over only on TIMEOUT/NETUNREACH

**Requirement:** `rc_aaa_ctx_server()` MUST iterate `aaaserver->name[]`/
`port[]`/`secret[]` in index order (via `rc_buildreq()` + `rc_send_server_ctx()`
per index), returning immediately on the first `OK_RC`, `CHALLENGE_RC`, or
`REJECT_RC` result. For any other result it MUST discard `data.receive_pairs`
and advance to the next server index, but MUST continue the loop *only*
while the result was `TIMEOUT_RC` or `NETUNREACH_RC` and unvisited servers
remain (`servernum < aaaserver->max`); any other non-terminal result ends the
loop and is returned as-is.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:184-218
**Acceptance:** [NET][ERR] unit, local — a 3-server list where server 0 returns `TIMEOUT_RC` and server 1 returns `OK_RC` yields an overall `OK_RC` using server 1's response, without contacting server 2; a list where server 0 returns `BADRESP_RC` yields `BADRESP_RC` immediately, without trying server 1.
**Links:** REQ-ATTR-ERR-039

### REQ-ATTR-NET-026 — Accounting-Response attributes MUST be consumed internally by radcli, not returned to the caller

**Requirement:** On success, `rc_aaa_ctx_server()` MUST set `*received =
data.receive_pairs` only when `request_type != PW_ACCOUNTING_REQUEST`; for
`PW_ACCOUNTING_REQUEST` it MUST unconditionally free `data.receive_pairs`
itself and leave the caller's `*received` untouched, regardless of whether
the caller passed a non-NULL `received` pointer. An Accounting-Response's
attributes (RFC 2866 defines none beyond the header that an application
needs) are radcli's own concern to validate or ignore internally — e.g. as
part of Response Authenticator / Message-Authenticator verification
(`net.md`) — not something the library hands back to the caller. `rc_acct()`/
`rc_acct_proxy()` never pass a `received` pointer (they call `rc_aaa()` with
`received = NULL`); a direct caller of `rc_aaa()`/`rc_aaa_ctx()`/
`rc_aaa_ctx_server()` with `request_type = PW_ACCOUNTING_REQUEST` and a
non-NULL `received` MUST NOT expect accounting-response attributes to be
returned through it.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:197-203
**Acceptance:** [NET][ERR] unit, local — call `rc_aaa_ctx()` directly with
`request_type = PW_ACCOUNTING_REQUEST` and a non-NULL `received` pointing at
a sentinel value; confirm the sentinel is unchanged after a successful call.
**Links:** REQ-ATTR-NET-025

### REQ-ATTR-NET-027 — rc_auth/rc_auth_proxy/rc_acct/rc_acct_proxy/rc_aaa/rc_aaa_ctx form a fixed delegation chain

**Requirement:** `rc_auth()` MUST call `rc_aaa(rh, nas_port, send, received, msg, 1, PW_ACCESS_REQUEST)`;
`rc_auth_proxy()` MUST call `rc_aaa(rh, 0, send, received, msg, 0, PW_ACCESS_REQUEST)`
(no NAS-Port auto-fill, no NAS-derived nas_port, unsuited for local NAS
context — a proxy forwards someone else's request); `rc_acct()` MUST call
`rc_aaa(rh, nas_port, send, NULL, NULL, 1, PW_ACCOUNTING_REQUEST)`;
`rc_acct_proxy()` MUST call `rc_aaa(rh, 0, send, NULL, NULL, 0, PW_ACCOUNTING_REQUEST)`;
`rc_aaa()` MUST call `rc_aaa_ctx(rh, NULL, ...)` (never exposing a context to
these five simpler entry points); `rc_aaa_ctx()` MUST resolve the server list
(REQ-ATTR-NET-022) and forward to `rc_aaa_ctx_server()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:83-104, 234-310
**Acceptance:** [NET] unit, local — `rc_auth()`'s and `rc_acct()`'s `add_nas_port`/`request_type` arguments to the underlying `rc_aaa()` call match the values above (verifiable via a call-count/argument-capturing stub of `rc_aaa_ctx_server()` in a test build).
**Links:** REQ-ATTR-NET-022, REQ-ATTR-NET-025

### REQ-ATTR-NET-028 — rc_check builds a single-target Status-Server request, bypassing config server-list lookup

**Requirement:** `rc_check(rh, host, secret, port, msg)` MUST build a
`PW_STATUS_SERVER` request carrying a `PW_SERVICE_TYPE = PW_ADMINISTRATIVE`
attribute and send it to exactly the caller-supplied `host`/`secret`/`port`
via `rc_send_server()` (the non-`_ctx`, no-`RC_AAA_CTX`, single-attempt
entry point) — it MUST NOT consult `rc_conf_srv()`'s `"authserver"`/
`"acctserver"` lists or perform the multi-server failover of
REQ-ATTR-NET-025. It MUST free `data.receive_pairs` itself; there is no
output parameter for received attributes.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:322-354
**Acceptance:** [NET] unit, local — `rc_check()` never invokes `rc_conf_srv()` (verifiable via a stub that fails the test if called); a `rc_check()` call against an unreachable single host does not attempt a second host, even if `authserver`/`acctserver` in the config would provide one.
**Links:** REQ-ATTR-NET-025

### REQ-ATTR-NET-029 — The `msg` output buffer contract requires PW_MAX_MSG_SIZE capacity

**Requirement:** Every function in this document that accepts a `char *msg`
parameter (`rc_auth`, `rc_auth_proxy`, `rc_aaa`, `rc_aaa_ctx`,
`rc_aaa_ctx_server`, `rc_check`) MUST be called with `msg == NULL` or `msg`
pointing at a caller-allocated buffer of at least `PW_MAX_MSG_SIZE` (4096)
bytes, since the transport layer (`net.md`) writes the concatenation of every
received `PW_REPLY_MESSAGE` attribute into it with no length parameter to
bound the write to a smaller caller buffer.
**Strength:** MUST
**Status:** DERIVED
**Source:** include/radcli/radcli.h:70 (`PW_MAX_MSG_SIZE`), 655-667 (declarations); lib/buildreq.c:76, 123, 226, 248, 270, 318 (Doxygen `@param msg` notes: "must point to a buffer of PW_MAX_MSG_SIZE bytes"); all `msg` parameters passed through unchanged to `rc_send_server`/`rc_send_server_ctx`
**Acceptance:** [NET][SEC] code-review — every call site passing a non-NULL `msg` allocates it as `char msg[PW_MAX_MSG_SIZE]` or equivalent; flagged as a precondition, not independently enforced by this document's functions (no length is passed in, so a too-small buffer cannot be detected here — see `net.md` for the write itself).
**Links:** REQ-NET-* (msg write, net.md)

### REQ-ATTR-NET-030 — rc_acct_async addresses every configured accounting server unconditionally, without waiting for or judging any reply

**Requirement:** `rc_acct_async()` MUST select the server list via
`rc_select_aaa_server()` (the same authserver/acctserver rule as
`REQ-ATTR-NET-022`) and MUST return `ERROR_RC` if none is configured. It
MUST then fill `PW_NAS_PORT`/`PW_ACCT_DELAY_TIME` via `rc_fill_acct_pairs()`
(`REQ-ATTR-NET-023`, with `add_nas_port` fixed at `1`) and, for *every*
index in `aaaserver->name[]`/`port[]`/`secret[]` in order, recompute
`Acct-Delay-Time` (`REQ-ATTR-NET-024`'s per-attempt recompute rule) and call
`rc_buildreq()` + `rc_send_server_ctx(..., no_wait=1)` — the fire-and-forget
mode of `REQ-NET-NET-017`. Unlike `rc_aaa_ctx_server()` (`REQ-ATTR-NET-025`),
it MUST NOT stop after the first successful send: every configured server is
contacted regardless of the per-server result, since a `no_wait` send has no
reply to distinguish "delivered" from "accepted." It MUST count a server as
reached only when the per-server result is `OK_RC` (per `REQ-NET-NET-017`,
`no_wait` never yields `TIMEOUT_RC`), and MUST return `OK_RC` overall if at
least one server was reached, `ERROR_RC` only if every server's send failed
outright.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:373-420 (`rc_aaa_ctx_server_async`), lib/buildreq.c:440-449
(`rc_acct_async`)
**Acceptance:** [NET] unit, local — a 2-server `acctserver` list with the first
unreachable and the second reachable yields `OK_RC` and the second server MUST still be
contacted even though it comes after the first send returned a terminal state; a config
with no `acctserver` (and no TLS/DTLS `authserver` fallback trigger) returns `ERROR_RC`
before any packet is built. `tests/acct-async-tests.sh` — end-to-end via
`src/radiusclient -A`, asserting completion in well under `radius_timeout` against an
unreachable first server, i.e. no blocking failover wait (contrast with
`REQ-ATTR-NET-025`'s blocking failover for `rc_acct()`).
**Links:** REQ-ATTR-NET-022, REQ-ATTR-NET-023, REQ-ATTR-NET-024, REQ-ATTR-NET-025 (the
blocking counterpart this deliberately does not follow), REQ-NET-NET-017 (net.md; the
`timeout=0` transport contract this depends on)

---

## SEC — shared-secret and request-authenticator handling

### REQ-ATTR-SEC-031 — RC_AAA_CTX captures the secret and request-authenticator vector of one completed request

**Requirement:** When a caller passes a non-NULL `ctx` to `rc_aaa_ctx()`/
`rc_aaa_ctx_server()`, the returned `RC_AAA_CTX` MUST hold the shared secret
string used for that specific request (`ctx->secret`, up to
`MAX_SECRET_LENGTH` bytes) and the `AUTH_VECTOR_LEN`-byte request
authenticator vector used in that request's header, so the caller can later
construct a follow-up request (e.g. a retry using the same authenticator to
re-derive a User-Password/CHAP/Message-Authenticator value) without having to
re-look-up the secret or regenerate a vector out of band. Passing `ctx == NULL`
MUST skip capturing this information entirely (no allocation).
**Strength:** MUST
**Status:** DERIVED
**Source:** include/radcli/radcli.h:527-537; include/includes.h:206-210; lib/aaa_ctx.c:41-55
**Acceptance:** [SEC] unit, local — a successful `rc_aaa_ctx()` call with non-NULL `ctx` yields a `*ctx` whose `rc_aaa_ctx_get_secret()` equals the secret configured for the server actually used, and whose `rc_aaa_ctx_get_vector()` is `AUTH_VECTOR_LEN` bytes.
**Links:** REQ-GEN-SEC-006, REQ-NET-SEC-* (request authenticator generation, net.md)

### REQ-ATTR-SEC-032 — The secret/vector accessors return borrowed pointers, not copies

**Requirement:** `rc_aaa_ctx_get_secret()` and `rc_aaa_ctx_get_vector()` MUST
return a pointer directly into the `RC_AAA_CTX`'s own storage; they MUST NOT
allocate or copy. The returned pointer's validity is therefore bounded by the
`ctx`'s lifetime — it becomes dangling the instant `rc_aaa_ctx_free(ctx)` is
called.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/aaa_ctx.c:41-55
**Acceptance:** [SEC][MEM] code-review — no call site retains a pointer returned by either accessor past the matching `rc_aaa_ctx_free()` call (a use-after-free check under ASan on any new test exercising this).
**Links:** REQ-ATTR-SEC-033

### REQ-ATTR-SEC-033 — rc_aaa_ctx_free must be paired with every non-NULL ctx the caller received

**Requirement:** `rc_aaa_ctx_free(ctx)` MUST release the `RC_AAA_CTX` via a
plain `free()`. Every `RC_AAA_CTX *` a caller receives (non-NULL) from
`rc_aaa_ctx()`/`rc_aaa_ctx_server()` MUST eventually be passed to
`rc_aaa_ctx_free()` exactly once to avoid leaking memory that contains a
copy of the shared secret.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/aaa_ctx.c:58-65
**Acceptance:** [SEC][MEM] unit, local — a call sequence obtaining and freeing an `RC_AAA_CTX` shows no leak under a leak detector; `rc_aaa_ctx_free()` is idempotent-unsafe like `free()` (double-free is caller error, not guarded against — consistent with REQ-GEN-MEM-003's cleanup-label convention, not a distinct guarantee here).

### REQ-ATTR-SEC-034 — rc_aaa_ctx_free() MUST zero the secret and vector before releasing memory

**Requirement:** `rc_aaa_ctx_free()` MUST overwrite `*ctx` (both
`ctx->secret` and `ctx->request_vector`) with zero before calling `free()`.
`RC_AAA_CTX` is explicitly designed to hold the secret past the original
request (for retries) — a long(er)-lived, purpose-built secret container,
not an ephemeral stack buffer — which makes zero-before-free more important
here than for shorter-lived buffers, not less.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/aaa_ctx.c:62-67 (`memset(ctx, '\0', sizeof(*ctx))` before
`free(ctx)`)
**Acceptance:** [SEC] unit, local — after `rc_aaa_ctx_free(ctx)`, the memory
formerly holding `ctx->secret` is all-zero (verifiable via a debug build that
captures the pointer before free, or ASan use-after-free inspection).
**Links:** REQ-GEN-SEC-006, REQ-ATTR-SEC-031

### REQ-ATTR-SEC-035 — SEND_DATA.secret is a borrowed pointer into configuration storage

**Requirement:** `rc_buildreq()` MUST store the `secret` pointer it is given
directly into `data->secret` without copying the string; every call site in
this document (`rc_aaa_ctx_server()`, `rc_check()`) passes a pointer that
aliases a `SERVER->secret[]` entry owned by the parsed configuration (`rh`),
or, for `rc_check()`, the caller's own `secret` argument. `SEND_DATA.secret`'s
validity is therefore tied to whichever object actually owns the string, not
to the `SEND_DATA`/request lifetime.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:50-52, 186-188, 347-348; include/radcli/radcli.h:512-523
**Acceptance:** [SEC][MEM] code-review — no code in this document frees or mutates `data->secret`; freeing the `rc_handle`/`SERVER` that owns the underlying secret string before the `SEND_DATA` using it is fully processed is a use-after-free bug in the *caller*, not something `rc_buildreq()` guards against.
**Links:** REQ-GEN-SEC-006, REQ-ATTR-SEC-031

### REQ-ATTR-SEC-036 — Dictionary validation is identity-only, not a content/size security control

**Requirement:** The dictionary-lookup gate performed by `rc_avpair_new()`
(REQ-ATTR-DATA-002) MUST be understood as validating only that the attribute
ID and vendor ID are *known* — it is not a defense against oversized,
malicious, or attacker-influenced *values*. Value-content and length
validation is entirely the per-type logic in `rc_avpair_assign()`
(REQ-ATTR-DATA-003); a value that passes dictionary identity validation can
still be rejected (or, per REQ-ATTR-DATA-006, silently truncated) by the
type-specific checks.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:196-261
**Acceptance:** [SEC] code-review — no reviewer should treat "the attribute exists in the dictionary" as evidence that its value has been bounds-checked; the two checks are independent and both required.
**Links:** REQ-ATTR-DATA-002, REQ-ATTR-DATA-003

---

## ERR — error propagation and failure-return contracts

### REQ-ATTR-ERR-037 — Pair-construction failures return NULL after logging; callers MUST check the return

**Requirement:** `rc_avpair_new()` and `rc_avpair_add()` MUST return `NULL`
(after an `rc_log(LOG_ERR, ...)` or `rc_log(LOG_CRIT, ...)` call describing
the cause) on: an attribute ID not in the dictionary, a vendor ID not in the
dictionary, any `rc_avpair_assign()` failure (REQ-ATTR-DATA-003), or a
`malloc()` failure for the new node. Every call site in `lib/buildreq.c`
checks this return value before using the result (e.g.
`rc_aaa_ctx_server()`'s NAS-Port/Acct-Delay-Time seeding:
`if (rc_avpair_add(...) == NULL) return ERROR_RC;`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:196-261; lib/buildreq.c:155-157, 168-172
**Acceptance:** [ERR] negative, local — `rc_avpair_new()`/`rc_avpair_add()` with each of the failure conditions above returns `NULL`, and does not leak the partially-constructed node (checked under a leak detector for the `rc_avpair_assign()`-failure path, which explicitly `free(vp)`s before returning).
**Links:** REQ-GEN-MEM-002, REQ-ATTR-DATA-002, REQ-ATTR-DATA-003

### REQ-ATTR-ERR-038 — rc_avpair_parse errors are all-or-nothing for the entire input

**Requirement:** On the *first* syntax or semantic error anywhere in
`buffer` (unknown attribute name, missing `=`, unknown symbolic integer
value, invalid IPv4/IPv6 literal, invalid IPv6 prefix, unknown attribute
type, or allocation failure), `rc_avpair_parse()` MUST return `-1` and, if
`*first_pair` already holds one or more successfully-parsed pairs from
*earlier* in the same buffer, free that entire list via `rc_avpair_free()`
and reset `*first_pair` to `NULL` — a caller never receives a partial list
representing "everything up to the error."
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/avpair.c:650-867 (every `return -1` branch pairs with `rc_avpair_free(*first_pair); *first_pair = NULL;` when `*first_pair` is non-NULL)
**Acceptance:** [ERR] negative, local — a buffer with two valid `name = value` pairs followed by a third with an unknown attribute name causes `rc_avpair_parse()` to return `-1` with `*first_pair == NULL`, not a 2-element list.
**Links:** REQ-ATTR-DATA-013

### REQ-ATTR-ERR-039 — rc_send_status codes are propagated, not reinterpreted, by this document's functions

**Requirement:** The `rc_send_status` values (`OK_RC`, `TIMEOUT_RC`,
`REJECT_RC`, `CHALLENGE_RC`, `ERROR_RC`, `NETUNREACH_RC`, `BADRESP_RC`,
`BADRESPID_RC`) returned by `rc_auth`/`rc_auth_proxy`/`rc_acct`/
`rc_acct_proxy`/`rc_check`/`rc_aaa`/`rc_aaa_ctx`/`rc_aaa_ctx_server` MUST be
exactly the value the underlying transport call (`rc_send_server`/
`rc_send_server_ctx`, documented in `net.md`) produced, except for
`ERROR_RC`, which this document's own code originates directly in a small
number of pre-transmission failure cases: no matching server list
(REQ-ATTR-NET-022), and `rc_avpair_add()`/`rc_avpair_assign()` failure while
auto-filling NAS-Port/Acct-Delay-Time (REQ-ATTR-NET-023).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/buildreq.c:90-99 (rc_aaa_ctx server selection), 150-177 (NAS-Port/Acct-Delay-Time seeding), 184-218 (rc_aaa_ctx_server, propagating `result` from `rc_send_server_ctx`); include/radcli/radcli.h:475-484 (`rc_send_status`)
**Acceptance:** [ERR] code-review — every non-`ERROR_RC` return value observed from a function in this document traces back to a `rc_send_server`/`rc_send_server_ctx` return, not a value invented in `lib/avpair.c`/`lib/buildreq.c`/`lib/aaa_ctx.c`.
**Links:** REQ-ATTR-NET-025, REQ-NET-* (net.md, origin of the non-`ERROR_RC` values)

---

## Phase 5 — Completeness and Gap Analysis

**Coverage check.** Every symbol exported under `lib/avpair.c`, `lib/buildreq.c`,
and `lib/aaa_ctx.c` in `lib/radcli.map.in`, and every corresponding declaration in
`include/radcli/radcli.h`, is cited by at least one requirement above:

| Symbol | Requirement(s) |
|---|---|
| `rc_avpair_add` | DATA-008, ERR-037 |
| `rc_avpair_assign` | DATA-003, DATA-004 |
| `rc_avpair_new` | DATA-002, DATA-003, DATA-005, DATA-006, ERR-037 |
| `rc_avpair_gen` | DATA-018, DATA-019 |
| `rc_avpair_remove` | DATA-009 |
| `rc_avpair_get` | DATA-010 |
| `rc_avpair_copy` | DATA-011 |
| `rc_avpair_insert` | DATA-007 |
| `rc_avpair_free` | DATA-012 |
| `rc_avpair_parse` | DATA-013, DATA-005, DATA-006, ERR-038 |
| `rc_avpair_tostr` | DATA-014 |
| `rc_avpair_log` | DATA-015, DATA-016 |
| `rc_avpair_next` | DATA-010 |
| `rc_avpair_get_uint32` | DATA-017 |
| `rc_avpair_get_in6` | DATA-017 |
| `rc_avpair_get_raw` | DATA-017 |
| `rc_avpair_get_attr` | DATA-017 |
| `rc_buildreq` | NET-021 |
| `rc_auth` | NET-027, NET-029 |
| `rc_auth_proxy` | NET-027, NET-029 |
| `rc_acct` | NET-027 |
| `rc_acct_proxy` | NET-027 |
| `rc_check` | NET-028, NET-029 |
| `rc_aaa` | NET-027, NET-029 |
| `rc_aaa_ctx` | NET-022, NET-027, NET-029, SEC-031 |
| `rc_aaa_ctx_server` | NET-025, NET-026, NET-029, SEC-031 |
| `rc_aaa_ctx_free` | SEC-033, SEC-034 |
| `rc_aaa_ctx_get_secret` | SEC-031, SEC-032 |
| `rc_aaa_ctx_get_vector` | SEC-031, SEC-032 |
| `VALUE_PAIR` (struct) | DATA-001, DATA-020 |
| `SEND_DATA` (struct) | NET-021, SEC-035 |
| `RC_AAA_CTX` (opaque) | SEC-031 |
| `VENDOR`/`ATTRID`/`RADCLI_VENDOR_ATTR_SET` (macros) | DATA-001 |

No public symbol in this document's scope is without a citing requirement.

**Internal helpers not separately ID'd.** `rc_get_id()`, `rc_avpair_gen2()`,
and `rc_fieldcpy()` are `static` (not exported — absent from
`lib/radcli.map.in`), so they have no requirement ID of their own; their
essential behavior is captured within the public-function requirements that
depend on them (NET-021 through NET-028, DATA-013, DATA-018/019) per this
protocol's Phase 3 guidance that essential-but-internal behavior belongs in
the requirement for the public contract it implements, not as a separate
entry for an implementation detail a reimplementation could restructure.

**Undocumented behavior.** No behavior in the three source files was found
with *no* evident purpose and *no* documentation. No `[UNDOCUMENTED]` flags
are raised in this document.

**Missing error cases.** Reviewed for gaps: `rc_avpair_tostr()`'s `-1`
return for `pair->type` outside the six known types is covered (DATA-014);
`rc_avpair_get_*` accessors' type-mismatch `-1` returns are covered
(DATA-017); allocation-failure paths in `rc_avpair_new`, `rc_avpair_copy`,
`rc_avpair_parse`, and `rc_avpair_gen2` are covered (ERR-037, DATA-011,
ERR-038, DATA-019). One gap remains open rather than closed: `rc_check()`
and `rc_aaa_ctx_server()` have no requirement describing what happens if
`rc_conf_int(rh, "radius_timeout"/"radius_retries")` returns an unexpected
value (e.g. a misconfigured negative number) — that belongs to `config.md`
(`rc_conf_int()`'s own contract), not here; this document only notes that
`buildreq.c` passes the value through to `rc_buildreq()` uninspected (see
lib/buildreq.c:140-141, 328-329).

**Cross-cutting concerns.** Thread safety: none of `avpair.c`/`buildreq.c`/
`aaa_ctx.c` touch process-wide state (no `static`/global mutable data beyond
the pre-existing `radcli_debug` flag covered by `REQ-GEN-SEC-005`); every
function operates on caller-supplied `VALUE_PAIR`/`SEND_DATA`/`RC_AAA_CTX`/
`rc_handle` objects, so concurrent calls are safe exactly to the extent the
caller doesn't share a single such object across threads without its own
synchronization — this is `general.md`'s `REQ-GEN-SEC-005` restated, not a
new per-function guarantee. Resource lifecycle: covered per-object above
(DATA-012 for `VALUE_PAIR` lists, SEC-033 for `RC_AAA_CTX`); `SEND_DATA` is
always caller/callee-stack-allocated in this document's code (never
heap-allocated or returned), so it has no separate free contract. Error
propagation: covered by the ERR category above (ERR-037 through ERR-039).
