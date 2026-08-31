---
title: radcli2.h dictionary lookup and attribute-definition accessor requirements
generator: requirements-from-implementation
id-prefix: REQ-DICT2
categories:
  DATA: radcli_dict_lookup*/radcli_attr_def_* lookup, accessor, and OID contracts
  ERR: NULL-argument, malformed-input, and not-found return contracts
sources:
  - lib/dict2.c
  - lib/dict2-parse.c
  - lib/dict2.h
  - include/radcli/radcli2.h
  - lib/radcli2.map.in
  - tests/dict.c
---

# radcli2.h Dictionary Lookup Requirements

This document covers the opaque, `radcli_`-prefixed dictionary-lookup half of
`radcli2.h`: resolving a `radcli_attr_def` by name (`radcli_dict_lookup()`), by
RFC 6929 §2.7 OID notation (`radcli_dict_lookup_oid()`), by legacy numeric
ID/vendor (`radcli_dict_lookup_num()`), resolving a scoped `VALUE` name
(`radcli_dict_lookup_value()`), and reading an already-resolved definition back
(`radcli_attr_def_name()`/`_type()`/`_oid()`). All seven symbols are
implemented in `lib/dict2.c` and exported from `lib/radcli2.map`'s single
version node.

This document exists to close the gap `avp2.md` explicitly flagged as
"not yet covered" when it was written: these symbols were originally left
unassigned to a document because they straddle `avp2.md` (`radcli2.h`, the
same header) and `dict.md` (`lib/dict2.c`, the dictionary implementation).
`dict.md` resolves that split explicitly (see its "Implementation split"
section): the legacy `rc_dict_*()` ABI it owns is a frozen, pointer-returning
API with a `DICT_ATTR`/`DICT_VALUE`/`DICT_VENDOR` shadow-struct lifecycle;
`radcli_dict_lookup*()`/`radcli_attr_def_*()` have no such ABI history (new
`radcli2.h` symbols, not migrations) and resolve straight to `lib/dict2.h`'s
internal lookup functions with no shadow struct ever materialized — different
enough contracts to warrant their own document rather than a new section of
either `dict.md` or `avp2.md`. It shares no source files with `avp2.md`
(`lib/avp.c`, `radcli_avp_list`/`radcli_avp_add_*`) beyond the same header,
and no source files with `dict.md`'s `INIT`/`CFG` categories (dictionary
*loading* — `radcli_ctx_read_dictionary()` and friends — is `config2.md`'s
and `dict.md`'s scope, not this document's; this document assumes a
dictionary is already loaded on the `radcli_ctx` passed in).

**Not covered here:** `radcli_dict_lookup_value()`'s `VALUE`-side sibling
lookups by attribute (`radcli_dict_value_by_attr()`) and the `DICT_ATTR`
gigawords/flags side tables (`radcli_dict_attr_gigawords()`,
`radcli_dict_flags_by_id()`) are internal-only (unexported, not declared in
`radcli2.h`) and already covered by `dict.md` (REQ-DICT-DATA-011 and
neighbors) as part of the dictionary's own construction; they are cited here
only where a `radcli_dict_lookup*()` contract depends on them.

**Legacy vs. `radcli2.h` (REQ-DICT2-DATA-007/008):** two `ATTRIBUTE`
type-token keywords parsed by `lib/dict2-parse.c` -- `integer64` and `ifid`
-- are stated here rather than in `dict.md`, even though the grammar itself
is shared parser code, because their only observable effect is through
`radcli2.h`'s `radcli_attr_type` enum: `radcli_dict_type_to_legacy()`
(`lib/dict2.h`) maps any dictionary type `>= PW_TYPE_MAX` -- which both are
-- down to `PW_TYPE_STRING` for the legacy `DICT_ATTR` shadow, so a
`rc_dict_*()` caller can never distinguish either from an ordinary opaque
string. `dict.md` states this exclusion in its own "Legacy vs. `radcli2.h`"
note, where `REQ-DICT-DATA-010`/`-012` are now `WITHDRAWN` in favor of
`REQ-DICT2-DATA-007`/`-008` below.

---

## DATA — lookup, accessor, and OID contracts

### REQ-DICT2-DATA-001 — radcli_dict_lookup() is a case-insensitive name lookup

**Requirement:** `radcli_dict_lookup(ctx, name)` MUST return the
`radcli_attr_def` for the dictionary attribute named `name` on `ctx`'s loaded
dictionary, matching case-insensitively (the same matching rule the legacy
`rc_dict_findattr()` dictionary lookup already uses), or `NULL` if no
attribute with that name is loaded.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:428-433 (`radcli_dict_lookup`), lib/dict2.c:118-133
(`radcli_dict_attr_by_name`, the case-folding `HASH_FIND` it delegates to)
**Acceptance:** [DATA] positive, local — `tests/dict.c:351` resolves
`"Test-Std-Attr"` by name; `tests/dict.c:226-233` confirms
`"framed-protocol"`/`"FRAMED-PROTOCOL"` both resolve despite the differing
case.
**Links:** REQ-DICT2-DATA-004

### REQ-DICT2-DATA-002 — radcli_dict_lookup_num() looks up by legacy numeric attribute ID and vendor PEN

**Requirement:** `radcli_dict_lookup_num(ctx, attrid, vendor)` MUST return the
`radcli_attr_def` for the dictionary attribute whose legacy numeric ID is
`attrid` under vendor `vendor` (`0` for a standard, non-vendor-specific
attribute), or `NULL` if no such attribute is loaded. It MUST be non-NULL for
any RFC 2865/2866/2869 standard attribute ID on a context that has the
built-in dictionary loaded (every `radcli_ctx_read_config()` context, and
every `radcli_ctx_new()` context unless created with
`RADCLI_CTX_NO_BUILTIN_DICT`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:435-441 (`radcli_dict_lookup_num`), lib/dict2.c:135-144
(`radcli_dict_attr_by_id`, the `RADCLI_VENDOR_ATTR_SET()`-keyed `HASH_FIND` it
delegates to)
**Acceptance:** [DATA] positive, local — `tests/dict.c:362-366` resolves
attribute `250` (vendor `0`) to the same definition `radcli_dict_lookup()`
returns by name; `lib/avp.c`'s `_by_num()` wrapper family (REQ-AVP2-DATA-015)
exercises it transitively against every RFC 2865/2866/2869 attribute the
local test suite adds by number.
**Links:** REQ-DICT2-DATA-001, REQ-DICT2-DATA-003, REQ-AVP2-DATA-015

### REQ-DICT2-DATA-003 — radcli_dict_lookup_oid() parses RFC 6929 §2.7 OID text and is equivalent to radcli_dict_lookup_num() for the one- and three-component forms it can resolve

**Requirement:** `radcli_dict_lookup_oid(ctx, oid)` MUST parse `oid` as a
dot-separated sequence of unsigned decimal integers (up to 5 components,
RFC 6929 §2.7's deepest form: `vendor(26).vendor-id.extended-type(241).
ext-attr.tlv-type`), then resolve it as follows: a single component `N` MUST
be equivalent to `radcli_dict_lookup_num(ctx, N, 0)`; three components
`26.<vendor>.<type>` MUST be equivalent to
`radcli_dict_lookup_num(ctx, <type>, <vendor>)`. Every other well-formed
component count (2, 4, or 5 components, or a 3-component OID whose first
component is not `26`) MUST return `NULL` — well-formed but unresolvable,
since the bundled dictionary carries no RFC 6929 extended/long-extended/
TLV-nested attributes to match against, and a 2-component `26.<vendor>` names
a vendor rather than an attribute.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:392-425 (`parse_oid`), lib/dict2.c:443-466
(`radcli_dict_lookup_oid`)
**Acceptance:** [DATA] positive, local — `tests/dict.c:369-373` resolves
standard OID `"250"`; `tests/dict.c:381-389` resolves vendor OID
`"26.19999.5"`. [ERR] negative, local — `tests/dict.c:409-416` confirms a
well-formed 2-component `"241.1"` (extended attribute, unloaded) and
`"26.19999"` (vendor-only) both miss without crashing.
**Links:** REQ-DICT2-DATA-002, REQ-DICT2-ERR-008

### REQ-DICT2-DATA-004 — radcli_attr_def_name()/_type() read back an already-resolved definition's name and wire type

**Requirement:** `radcli_attr_def_name(def)` MUST return `def`'s canonical
dictionary name (never `NULL` for a non-`NULL` def). `radcli_attr_def_type(def)`
MUST return `def`'s `radcli_attr_type` as recorded in the dictionary. Both
accept any `def` returned by `radcli_dict_lookup()` or a sibling lookup
function, and neither allocates or may fail for a valid, non-NULL `def`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:468-472 (`radcli_attr_def_name`), lib/dict2.c:474-478
(`radcli_attr_def_type`), lib/dict2.c:333-380 (`dict_type_to_radcli`, the
`rc_attr_type` -> `radcli_attr_type` mapping `_type()` applies)
**Acceptance:** [DATA] positive, local — `tests/dict.c:352,356` confirm the
name and `RADCLI_TYPE_INTEGER` type of a standard-typed attribute;
`tests/dict.c:386` confirms `RADCLI_TYPE_STRING` for a vendor attribute.
**Links:** REQ-DICT2-DATA-001

### REQ-DICT2-DATA-005 — radcli_attr_def_oid() renders the same RFC 6929 §2.7 OID text radcli_dict_lookup_oid() would parse back to the same definition

**Requirement:** `radcli_attr_def_oid(def, buf, buflen)` MUST render `def`'s
OID as `"<attrid>"` for a standard attribute (vendor `0`) or
`"26.<vendor>.<attrid>"` for a vendor-specific attribute, writing at most
`buflen` bytes (NUL-terminated) into `buf` and returning the number of
characters the full text would occupy excluding the terminator, exactly as
`snprintf()` does — so a caller can size a buffer with a `NULL`/`0` probe
call first. Passing the returned text back through `radcli_dict_lookup_oid()`
on the same dictionary MUST resolve to the same `def` (round-trip).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:480-494 (`radcli_attr_def_oid`)
**Acceptance:** [DATA] positive, local — `tests/dict.c:374-377` round-trips a
standard attribute's OID (`"250"`); `tests/dict.c:390-393` round-trips a
vendor attribute's OID (`"26.19999.5"`) through `radcli_dict_lookup_oid()`.
**Links:** REQ-DICT2-DATA-003, REQ-DICT2-ERR-010

### REQ-DICT2-DATA-006 — radcli_dict_lookup_value() resolves a VALUE name scoped to one attribute, case-insensitively

**Requirement:** `radcli_dict_lookup_value(ctx, def, name, out)` MUST resolve
`name` as a `VALUE` defined for `def`'s attribute specifically (not any
attribute in the dictionary that happens to define a `VALUE` of that name —
two different attributes may each define a same-named `VALUE`, e.g. both
defining `"One"` with different numbers), matching case-insensitively like
every other dict2 name lookup (REQ-DICT2-DATA-001), writing the resolved
number to `*out` and returning `0` on success.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:496-511 (`radcli_dict_lookup_value`), lib/dict2.c:179-193
(`radcli_dict_value_by_attr_name`, the attribute-name-scoped `HASH_FIND` it
delegates to)
**Acceptance:** [DATA] positive, local — `tests/dict.c:443-448` resolves
`Test-Std-Attr`'s `"One"`/`"Two"` to their distinct numbers;
`tests/dict.c:451-454` confirms case-insensitive matching (`"oNe"`);
`tests/dict.c:456-461` is the scoping proof — `Test-Std-Attr2`'s own `"One"`
resolves to a different number (`100`) than `Test-Std-Attr`'s `"One"` (`1`),
confirming the two do not collide.
**Links:** REQ-DICT2-DATA-001, REQ-DICT2-ERR-010

### REQ-DICT2-DATA-007 — the `integer64` `ATTRIBUTE` type-token keyword (RFC 8044 §3.3) resolves to `RADCLI_TYPE_INTEGER64`, unreachable through the legacy attribute API

**Requirement:** `lib/dict2-parse.c`'s dictionary-file parser MUST accept
`integer64` (RFC 8044 §3.3's 8-octet, network-byte-order integer data type —
e.g. `MIP6-Feature-Vector`, RFC 5447 §4.2.5, `etc/dictionary`'s only
standard user of it) as an `ATTRIBUTE` line's type token, parsing it to the
internal sentinel `PW_TYPE_MAX`, which `dict_type_to_radcli()` (`lib/dict2.c`)
maps to `RADCLI_TYPE_INTEGER64` — so `radcli_attr_def_type()`
(REQ-DICT2-DATA-004) reports `RADCLI_TYPE_INTEGER64` for such an attribute's
`radcli_attr_def`. `PW_TYPE_MAX` MUST NOT be a legal value for
`rc_dict_addattr()` (the legacy, programmatic `rc_attr_type`-based attribute
API, `dict.md`'s scope) to accept — `type < 0 || type >= PW_TYPE_MAX` is
rejected there — so a `VALUE_PAIR`-based caller can never construct a
`DICT_ATTR` of this type; only the bundled dictionary file, parsed directly,
can. This is the reason this requirement lives here rather than in `dict.md`
despite the grammar being shared parser code: a legacy caller has no way to
observe `RADCLI_TYPE_INTEGER64` correctly even by inspecting a
`DICT_ATTR.type` shadow, since `radcli_dict_type_to_legacy()` collapses any
type `>= PW_TYPE_MAX` to `PW_TYPE_STRING`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c:318-330 (`"integer64"` token parsing);
lib/dict2-parse.c:811 (`radcli_dict_attr_add()`'s -- `rc_dict_addattr()`'s
real implementation -- `type >= PW_TYPE_MAX` rejection); lib/dict2.c:333-359
(`dict_type_to_radcli()`'s `PW_TYPE_MAX` -> `RADCLI_TYPE_INTEGER64` mapping)
**Acceptance:** [DATA] positive, local — a synthetic `integer64` line
(`Test-Int64-Attr`, `tests/dict.c`'s Phase 2 section, `tests/dict.c:98-107`)
loads and `radcli_attr_def_type()` reports `RADCLI_TYPE_INTEGER64`
(`tests/dict.c:484-495`). `[UNDOCUMENTED]` gap: no test loads the built-in
dictionary and looks up `MIP6-Feature-Vector` (124) itself by name —
coverage is via the synthetic attribute only, not the one real standard
user of this type. [ERR] negative, local — `tests/dict.c`'s
`bad_integer64_dict` (`"integer65"`, an unrecognised type token similar to
but distinct from `"integer64"`) confirms the type-token match is exact, not
a prefix match; `tests/avp-legacy.c` confirms `rc_avpair_add()` cannot be
made to construct a `VALUE_PAIR` of this type.
**Links:** REQ-DICT2-DATA-004, REQ-AVP2-DATA-009

### REQ-DICT2-DATA-008 — the `ifid` `ATTRIBUTE` type-token keyword (RFC 8044 §3.7) resolves to `RADCLI_TYPE_IFID`, unreachable through the legacy attribute API

**Requirement:** `lib/dict2-parse.c`'s dictionary-file parser MUST accept
`ifid` (RFC 8044 §3.7's 8-octet, network-byte-order IPv6 interface
identifier data type — e.g. `Framed-Interface-Id`, RFC 3162 §2.3,
`etc/dictionary` attribute 96) as an `ATTRIBUTE` line's type token, parsing
it to the internal sentinel `PW_TYPE_MAX + 3`, which `dict_type_to_radcli()`
maps to `RADCLI_TYPE_IFID` — so `radcli_attr_def_type()` reports
`RADCLI_TYPE_IFID` for such an attribute. Same `rc_dict_addattr()` rejection
and legacy-shadow-collapse-to-`PW_TYPE_STRING` unreachability as
REQ-DICT2-DATA-007: `PW_TYPE_MAX + 3` is `>= PW_TYPE_MAX`, so no
`VALUE_PAIR`-based caller can ever construct or correctly observe a
`DICT_ATTR` of this type. `RADCLI_TYPE_IFID` is read/written with the same
`radcli_avp_add_uint64()`/`radcli_avp_get_uint64()` pair as
`RADCLI_TYPE_INTEGER64` (REQ-AVP2-DATA-009), since both are 8 raw octets on
the wire, even though an interface identifier is not itself a numeric
quantity.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c:354-364 (`"ifid"` token parsing); lib/dict2.c:370-374
(`dict_type_to_radcli()`'s `PW_TYPE_MAX + 3` -> `RADCLI_TYPE_IFID` mapping)
**Acceptance:** [DATA] positive, local — a synthetic `ifid` line
(`tests/dict.c:126-127`) loads and `radcli_attr_def_type()` reports
`RADCLI_TYPE_IFID` (`tests/dict.c:564-577`); `radcli_avp_add_uint64()`/
`_get_uint64()` round-trip a value through it. `[UNDOCUMENTED]` gap: no test
loads the built-in dictionary and looks up `Framed-Interface-Id` (96) itself
by name — coverage is via the synthetic attribute only. [ERR] negative,
local — `tests/dict.c`'s `bad_ifid_dict` (`"ifidx"`, an unrecognised type
token similar to but distinct from `"ifid"`) confirms the type-token match
is exact, not a prefix match.
**Links:** REQ-DICT2-DATA-004, REQ-DICT2-DATA-007, REQ-AVP2-DATA-009

---

## ERR — NULL-argument, malformed-input, and not-found return contracts

### REQ-DICT2-ERR-007 — a NULL ctx/name/def is rejected without crashing, returning NULL

**Requirement:** `radcli_dict_lookup()`, `radcli_dict_lookup_oid()`, and
`radcli_dict_lookup_num()` MUST return `NULL` (never crash or dereference)
if `ctx` is `NULL`, or (for the name/OID-taking pair) if `name`/`oid` is
`NULL`. `radcli_attr_def_name()`/`_type()` MUST similarly tolerate a `NULL`
`def` (see REQ-AVP2-DATA-025 for `radcli_avp_def()`'s identical NULL-in
contract on the `radcli_avp` side): `radcli_attr_def_name(NULL)` returns
`NULL`, `radcli_attr_def_type(NULL)` returns `RADCLI_TYPE_STRING` (the type
mapper's default case, applied to `def`'s absence the same way it is applied
to an unrecognised stored type).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:428-433, lib/dict2.c:435-441, lib/dict2.c:443-450
(the three lookup functions' leading `NULL` guards), lib/dict2.c:468-478
(`radcli_attr_def_name`/`_type`'s ternary `NULL` handling)
**Acceptance:** [ERR] negative, local — `tests/dict.c:421-425` confirms
`radcli_dict_lookup(NULL, "Test-Std-Attr")`,
`radcli_dict_lookup(ctx, NULL)`, `radcli_dict_lookup_num(NULL, 250, 0)`, and
`radcli_dict_lookup_oid(NULL, "250")` all return `NULL` rather than crashing.
**Links:** REQ-DICT2-DATA-001, REQ-DICT2-DATA-002, REQ-DICT2-DATA-003

### REQ-DICT2-ERR-008 — radcli_dict_lookup_oid() rejects a malformed OID without crashing

**Requirement:** `radcli_dict_lookup_oid()` MUST return `NULL` for an empty
string, a component containing a non-digit character, a component
overflowing `uint32_t`, or more than 5 dot-separated components — the same
failure shape (`NULL`, no crash) as a well-formed-but-unresolvable OID
(REQ-DICT2-DATA-003), so a caller cannot distinguish "malformed" from "valid
but absent" without separately validating the input first.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:392-425 (`parse_oid`'s rejection paths)
**Acceptance:** [ERR] negative, local — `tests/dict.c:397-408` confirms an
empty string (`""`), an over-long OID (`"1.2.3.4.5.6"`, 6 components), and a
non-numeric component (`"250x"`) are all rejected.
**Links:** REQ-DICT2-DATA-003

### REQ-DICT2-ERR-009 — radcli_attr_def_oid(NULL, ...) reports failure via a negative return, distinct from snprintf()'s own truncation signaling

**Requirement:** `radcli_attr_def_oid(def, buf, buflen)` MUST return a
negative value if `def` is `NULL`, distinguishable from the non-negative
`snprintf()`-style length `radcli_attr_def_oid()` returns for a valid `def`
(including the case where `buflen` is too small to hold the full text —
that case is truncation, reported the normal `snprintf()` way, and is not
itself an error).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:480-486 (`radcli_attr_def_oid`'s `a == NULL` check
returning `-1` before the `snprintf()` calls)
**Acceptance:** not exercised by the current local test suite (`tests/dict.c`
only exercises the non-NULL-`def` round-trip path) — `Needs-domain-check`
whether this project wants a dedicated `radcli_attr_def_oid(NULL, ...)` test
case, same open-coverage pattern `REQ-AVP2-DATA-023`/`-024` already flag for
other `radcli2.h` accessors.
**Links:** REQ-DICT2-DATA-005

### REQ-DICT2-ERR-010 — radcli_dict_lookup_value() rejects a NULL argument or an unresolvable name/attribute, without writing to *out

**Requirement:** `radcli_dict_lookup_value(ctx, def, name, out)` MUST return
`-1` without writing to `*out` if `ctx`, `def`, `name`, or `out` is `NULL`,
if `def`'s attribute defines no `VALUE` named `name`, or if `name` is
defined for a *different* attribute than `def` (the scoping case —
REQ-DICT2-DATA-006's negative counterpart).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2.c:496-511 (`radcli_dict_lookup_value`'s guard clause
and not-found return)
**Acceptance:** [ERR] negative, local — `tests/dict.c:463-467` confirms
`Test-Std-Attr2`'s lookup of `"Two"` (defined only for `Test-Std-Attr`)
fails; `tests/dict.c:468-471` confirms an unknown name
(`"Not-A-Real-Value"`) fails; `tests/dict.c:472-477` confirms a `NULL`
`ctx`/`def`/`name`/`out` is each individually rejected.
**Links:** REQ-DICT2-DATA-006
