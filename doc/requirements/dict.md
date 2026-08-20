---
title: dictionary loading, parsing, and lookup requirements
generator: requirements-from-implementation
id-prefix: REQ-DICT
categories:
  INIT: dictionary loading entry points ($FILE / buffer / $INCLUDE / built-in RFC dictionary)
  DATA: DICT_ATTR/DICT_VALUE/DICT_VENDOR construction, encoding, and lookup semantics
  ERR: parse-error, validation, and allocation-failure behavior
  CFG: interaction with rc_read_config and the build-time dictionary generator
sources:
  - lib/dict.c
  - lib/dict_rfc_gen.h
  - lib/gen-dict.awk
  - include/radcli/radcli.h
  - include/includes.h
  - lib/config.c
  - etc/dictionary
  - doc/requirements/general.md
  - doc/requirements/README.md
---

# Dictionary Loading, Parsing, and Lookup Requirements

This document covers the RADIUS **dictionary** subsystem: parsing dictionary
files/buffers into `DICT_ATTR`/`DICT_VALUE`/`DICT_VENDOR` lists on an
`rc_handle`, `$INCLUDE` resolution, the built-in compiled-in RFC dictionary,
and the `rc_dict_*` lookup/construction API. It does **not** cover how
`VALUE_PAIR`s are built, encoded onto the wire, or matched against a dictionary
entry at packet-construction/parsing time — that is `attrs.md`'s scope
(`lib/avpair.c`, `lib/buildreq.c`). Where a dictionary behavior is a
precondition for attribute handling (e.g. a name must resolve via
`rc_dict_findattr` before `rc_avpair_add` can encode it), this document states
the dictionary-side guarantee and `attrs.md` states the attribute-side
consumption of it.

Cross-cutting memory-safety and unsafe-string-function rules
(`REQ-GEN-MEM-002`, `REQ-GEN-MEM-004`) apply throughout `lib/dict.c` and are
linked from individual requirements below rather than restated.

---

## INIT — dictionary loading entry points

### REQ-DICT-INIT-001 — `rc_read_dictionary` parses a named file and guards against re-reading the same top-level file

**Requirement:** `rc_read_dictionary(rh, filename)` MUST open `filename`,
parse it with the dictionary grammar (see DATA requirements below), and
return `0` on success or `-1` on failure (open failure or any parse error).
If `filename` is identical (via `strcmp`) to `rh->first_dict_read` — the
filename recorded on the first successful call — the function MUST return
`0` immediately without reopening or reparsing the file. On the first
successful call, `filename` MUST be recorded via `strdup()` into
`rh->first_dict_read`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:521-544 (`rc_read_dictionary`); include/includes.h:196
(`first_dict_read` field)
**Acceptance:** [INIT] positive, local — load a dictionary file twice via two
`rc_read_dictionary` calls with the same path; second call returns `0` without
duplicating entries (list length unchanged). Negative — call with a
nonexistent path; returns `-1` and logs `LOG_ERR` with `strerror(errno)`
(dict.c:531-533).
**Links:** REQ-DICT-INIT-004, REQ-DICT-DATA-008

### REQ-DICT-INIT-002 — `rc_read_dictionary_from_buffer` parses an in-memory buffer and disables `$INCLUDE`

**Requirement:** `rc_read_dictionary_from_buffer(rh, buf, size)` MUST open
`buf` (length `size`) as a stream via `fmemopen()` and parse it with the same
grammar as `rc_read_dictionary`, passing a `NULL` filename to the internal
parser. Because the `$INCLUDE` branch is gated on `filename != NULL`
(dict.c:394), a buffer-sourced dictionary MUST NOT process `$INCLUDE`
directives — such a line is silently skipped by falling through the
`strcmp(tok, ...)` chain with no match (no other branch matches `$INCLUDE`,
so it is ignored) rather than being an error.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:556-573 (`rc_read_dictionary_from_buffer`);
lib/dict.c:394-427 (`$INCLUDE` branch guarded by `filename != NULL`)
**Acceptance:** [INIT] positive, local — call with a buffer containing a
single `$INCLUDE some/path` line; call returns `0` (line ignored, not an
error) and no attributes from `some/path` are loaded.
**Links:** REQ-DICT-CFG-001

### REQ-DICT-INIT-003 — built-in RFC dictionary is loaded unconditionally before any config-specified dictionary

**Requirement:** `rc_read_config()` MUST load the compiled-in RFC 2865/2866/…
dictionary (`rc_rfc_dictionary`, generated into `lib/dict_rfc_gen.h`) via
`rc_read_dictionary_from_buffer()` before consulting the `dictionary` config
option. If this built-in load fails, `rc_read_config()` MUST treat it as fatal
(`rc_destroy()` the handle and return `NULL`) rather than continuing without a
dictionary. The `dictionary` config option, if present, names an *additional*
file loaded afterward via `rc_read_dictionary()`; its absence MUST NOT be an
error.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:764-780
**Acceptance:** [INIT] positive, local — `rc_read_config()` on a config file
with no `dictionary` line still resolves standard attribute names (e.g.
`User-Name`) via `rc_dict_findattr()`. [ERR] negative — build a binary against
a corrupted `rc_rfc_dictionary` (or intercept `fmemopen` to fail) and confirm
`rc_read_config()` returns `NULL`.
**Links:** REQ-DICT-CFG-002, REQ-DICT-INIT-002

### REQ-DICT-INIT-004 — `$INCLUDE` paths resolve relative to the including file's directory; absolute paths are used verbatim

**Requirement:** When `rc_dict_init()` encounters `$INCLUDE <path>` while
parsing a file (not a buffer — see REQ-DICT-INIT-002), it MUST recursively
call `rc_read_dictionary()` on the resolved path. If `<path>` begins with
`/`, it MUST be used unmodified. Otherwise it MUST be resolved by taking the
directory portion of the *including* file's own path (up to and including the
last `/`) and appending `<path>`; if the including filename has no `/`, the
raw token is used as read into `ifilename`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:394-427
**Acceptance:** [INIT] positive, local — a dictionary at `dir/a` containing
`$INCLUDE b` successfully loads `dir/b`; a dictionary containing
`$INCLUDE /abs/path` loads `/abs/path` regardless of the including file's
location.
**Links:** REQ-DICT-INIT-001, REQ-DICT-INIT-005

### REQ-DICT-INIT-005 — `$INCLUDE` path length is bounded by `RC_MAX(1024, PATH_MAX)`, not truncated to 63 characters

**Requirement:** The resolved `$INCLUDE` path MUST be copied into a buffer
sized `RC_MAX(1024, PATH_MAX)` bytes (`ifilename`, dict.c:166) using
`strlcpy()`/`strlcat()`, so that include paths up to that bound (typically
4095+ bytes on Linux, since `PATH_MAX` is usually 4096) are preserved intact.
This corrects a prior defect (see commit `d5b1713`, "dict: fix `$INCLUDE`
path truncation to 63 chars") where the include path was read with
`sscanf("%63s", ...)` into a smaller, `AUTH_ID_LEN`(64)-derived buffer;
current code MUST NOT reintroduce a fixed-63/64-byte bound for `$INCLUDE`
paths specifically (the 64-byte `RC_NAME_LENGTH` bound legitimately applies
to attribute/value/vendor *names*, not include paths — see REQ-DICT-ERR-001).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:166, 399-422; git log `d5b1713` (regression this
supersedes)
**Acceptance:** [INIT] positive, local — a dictionary with
`$INCLUDE some/very/long/relative/path...` (>63, <1024 bytes total including
the including file's own directory prefix) loads successfully with the full
path intact (verifiable by making the included file's basename alone
non-existent so a truncated path would fail to open while the full path
succeeds).
**Links:** REQ-DICT-INIT-004, REQ-GEN-MEM-004

---

## DATA — DICT_ATTR/DICT_VALUE/DICT_VENDOR construction, encoding, and lookup semantics

### REQ-DICT-DATA-001 — `ATTRIBUTE` lines require name, numeric value, and a type from a fixed set

**Requirement:** An `ATTRIBUTE` line MUST supply at least `NAME VALUE TYPE`
(a fourth, optional option-list token MAY follow — see REQ-DICT-DATA-003 for
`vendor=`/bare-vendor-name and REQ-DICT-DATA-009 for `has_tag`/`encrypt=`).
`VALUE` MUST begin with a digit (checked via `isdigit()` on the first
character only — see REQ-DICT-ERR-002 for the resulting weak validation).
`TYPE` MUST be one of `string`, `integer`, `uint32`, `ipaddr`, `ipv4addr`,
`ipv6addr`, `ipv6prefix`, or `date`; `ipaddr`/`ipv4addr` are synonyms both
mapping to `PW_TYPE_IPADDR`, and `uint32`/`integer` are synonyms both mapping
to `PW_TYPE_INTEGER` (`uint32` is the spelling FreeRADIUS's newer
dictionaries, e.g. `share/dictionary/radius/dictionary.rfc2868`, use for the
same type). Any other type keyword MUST be rejected.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:209-332 (`ATTRIBUTE` branch); include/radcli/radcli.h:120-128
(`rc_attr_type`/`PW_TYPE_*`)
**Acceptance:** [DATA] positive, local — `ATTRIBUTE Foo 1 ipv4addr` and
`ATTRIBUTE Foo 1 ipaddr` both produce a `DICT_ATTR` with `type ==
PW_TYPE_IPADDR`; `ATTRIBUTE Foo 1 uint32` produces a `DICT_ATTR` with `type
== PW_TYPE_INTEGER`, same as `ATTRIBUTE Foo 1 integer`. [ERR] negative —
`ATTRIBUTE Foo 1 bogus-type` causes `rc_dict_init()` to return `-1`.

### REQ-DICT-DATA-002 — vendor-scoped attribute IDs are encoded as `(id | PEN << 32)` in a 64-bit value

**Requirement:** For a vendor-scoped attribute, `DICT_ATTR.value` (a
`uint64_t`) MUST be computed as
`RADCLI_VENDOR_ATTR_SET(attr_id, vendor_pec)` = `attr_id | ((uint64_t)vendor_pec
<< VENDOR_BIT_SIZE)` with `VENDOR_BIT_SIZE == 32`, so that the low 32 bits
hold the RFC-scoped attribute number and the high 32 bits hold the vendor's
IANA Private Enterprise Number. Attribute IDs are therefore unique per
`(vendor_pec, attr_id)` pair, not globally; the same numeric `attr_id` under
two different vendors (or under vendor 0, i.e. standard/RFC space) MUST
produce distinct `DICT_ATTR.value`s and MUST be independently resolvable via
`rc_dict_getattr()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** include/radcli/radcli.h:63-67 (`RADCLI_VENDOR_ATTR_SET`,
`VENDOR_BIT_SIZE`, `VENDOR()`); lib/dict.c:323-327, 61-62
**Acceptance:** [DATA] positive, local — load `VENDOR V 99` /
`BEGIN-VENDOR V` / `ATTRIBUTE X 1 integer` / `END-VENDOR V` plus a top-level
`ATTRIBUTE Y 1 integer`; `rc_dict_getattr(rh, RADCLI_VENDOR_ATTR_SET(1, 99))`
returns the `X` entry and `rc_dict_getattr(rh, RADCLI_VENDOR_ATTR_SET(1, 0))`
returns the `Y` entry — no collision despite both using numeric ID `1`.

### REQ-DICT-DATA-003 — `BEGIN-VENDOR`/`END-VENDOR` scopes subsequent `ATTRIBUTE` lines to a vendor; a per-line `vendor=` option overrides it for one line

**Requirement:** A `BEGIN-VENDOR <name>` line MUST look up `<name>` via
`rc_dict_findvend()` (case-insensitive) and, if found, set the parser's
current vendor context to that vendor's PEN for all subsequent `ATTRIBUTE`
lines until the matching `END-VENDOR` resets the context to `0`
(unscoped/standard). If `<name>` is not a previously-declared `VENDOR`, the
parse MUST fail (`-1`). Independently, an `ATTRIBUTE` line's optional fourth
token MAY contain a comma-separated option list including `vendor=<name>` (or
bare `<name>`); when present, that vendor (again resolved via
`rc_dict_findvend()`) is used for that single `ATTRIBUTE` line instead of the
ambient `BEGIN-VENDOR` context.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:294-312 (per-line `vendor=` option), 429-457
(`BEGIN-VENDOR`/`END-VENDOR`)
**Acceptance:** [DATA] positive, local — verify an `ATTRIBUTE` line inside a
`BEGIN-VENDOR`/`END-VENDOR` block picks up the block's PEN; verify a
top-level `ATTRIBUTE Foo 1 integer vendor=V` line picks up `V`'s PEN despite
no enclosing `BEGIN-VENDOR`. [ERR] negative — `BEGIN-VENDOR Unknown` (no
prior `VENDOR Unknown ...` line) returns `-1`.
**Links:** REQ-DICT-DATA-004

### REQ-DICT-DATA-004 — `VENDOR` registers a name/PEN pair that later `BEGIN-VENDOR`/`vendor=` references must resolve against

**Requirement:** A `VENDOR <name> <pec>` line MUST create a `DICT_VENDOR`
entry with that name and numeric PEN, independent of and available to any
later `ATTRIBUTE`/`BEGIN-VENDOR` line in the same or an included file (list
order is load order, see REQ-DICT-DATA-005). `<pec>` MUST begin with a digit;
non-numeric values are rejected.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:458-506
**Acceptance:** [DATA] positive, local — `VENDOR V 99` followed anywhere
later by `BEGIN-VENDOR V` succeeds; `rc_dict_findvend(rh, "v")` (any case)
returns the entry with `vendorpec == 99`.
**Links:** REQ-DICT-DATA-003, REQ-DICT-DATA-006

### REQ-DICT-DATA-005 — parsed/added entries are prepended; lookups return the most-recently-loaded match on name/value collision

**Requirement:** Every successful `ATTRIBUTE`/`VALUE`/`VENDOR` parse, and
every `rc_dict_addattr()`/`rc_dict_addval()`/`rc_dict_addvend()` call, MUST
insert the new `DICT_ATTR`/`DICT_VALUE`/`DICT_VENDOR` node at the *head* of
`rh->dictionary_attributes`/`dictionary_values`/`dictionary_vendors`
(`node->next = rh->list; rh->list = node`). Because the lookup functions
(`rc_dict_getattr`, `rc_dict_findattr`, `rc_dict_findval`, `rc_dict_findvend`,
`rc_dict_getvend`, `rc_dict_getval`) all scan from the head forward and
return on first match, a later-loaded entry with the same name/value/ID as an
earlier one MUST shadow the earlier one for all lookup purposes — the earlier
entry is not removed, just unreachable by lookup. This gives the built-in RFC
dictionary + subsequently-loaded config `dictionary` file (REQ-DICT-INIT-003)
override semantics: user-supplied redefinitions of a standard attribute take
priority over the built-in one.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:66-67, 108-109, 143-145 (`rc_dict_addattr`/`addval`/`addvend`
head-insertion); 330-331, 391-392, 504-506 (parser head-insertion);
581-696 (head-to-tail scan in all lookup functions)
**Acceptance:** [DATA] positive, local — load the built-in dictionary, then
load a second dictionary redefining `User-Name`'s numeric ID; `rc_dict_findattr(rh,
"User-Name")` returns the second definition's `value`, not the built-in one.
**Links:** REQ-DICT-INIT-003, REQ-DICT-DATA-007

### REQ-DICT-DATA-006 — all dictionary name lookups, including `rc_dict_getval`'s attribute-name match, MUST be case-insensitive

**Requirement:** `rc_dict_findattr()`, `rc_dict_findval()`, `rc_dict_findvend()`,
and `rc_dict_getval()` MUST all compare their name argument against stored
names using `strcasecmp()` (case-insensitive). `rc_dict_getattr()` matches by
exact 64-bit encoded numeric value (`==`), and `rc_dict_getvend()` matches by
exact 32-bit PEN (`==`) — both case-independent since they take no string.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:604-618 (`rc_dict_findattr`); 627-640
(`rc_dict_findval`); 648-656 (`rc_dict_findvend`); 681-696 (`rc_dict_getval`)
**Acceptance:** [DATA] positive, local — `rc_dict_findattr(rh, "user-name")`
and `rc_dict_findattr(rh, "User-Name")` both resolve the same entry;
`rc_dict_getval(rh, 1, "user-name")` resolves the same entry as
`rc_dict_getval(rh, 1, "User-Name")`.
**Links:** REQ-DICT-DATA-004

### REQ-DICT-DATA-007 — `rc_dict_addattr`/`addval`/`addvend` build dictionary entries programmatically under the same name-length and type-range checks as file parsing

**Requirement:** `rc_dict_addattr(rh, namestr, value, type, vendorspec)`,
`rc_dict_addval(rh, attrstr, namestr, value)`, and `rc_dict_addvend(rh,
namestr, vendorspec)` MUST allow constructing `DICT_ATTR`/`DICT_VALUE`/
`DICT_VENDOR` entries directly (no dictionary file/buffer involved), enforcing
`strlen(name) > RC_NAME_LENGTH` rejection (returns `NULL`) and, for
`rc_dict_addattr`, `type < 0 || type >= PW_TYPE_MAX` rejection, matching the
bounds the file/buffer parser enforces (REQ-DICT-ERR-001, REQ-DICT-DATA-001).
`rc_dict_addattr()`'s `value`/`vendorspec` are combined via
`RADCLI_VENDOR_ATTR_SET()` exactly as in file parsing (REQ-DICT-DATA-002).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:38-146
**Acceptance:** [DATA] positive, local — `rc_dict_addattr(rh, "X-Attr", 1,
PW_TYPE_INTEGER, 0)` returns a non-NULL `DICT_ATTR*` findable via
`rc_dict_findattr(rh, "X-Attr")`. [ERR] negative — a 65+ character name or
`type == PW_TYPE_MAX` returns `NULL`.
**Links:** REQ-DICT-DATA-005, REQ-DICT-ERR-001

### REQ-DICT-DATA-008 — `rc_dict_free` releases all three dictionary lists and resets the handle to an empty dictionary state

**Requirement:** `rc_dict_free(rh)` MUST walk and `free()` every node in
`rh->dictionary_attributes`, `rh->dictionary_values`, `rh->dictionary_vendors`,
and `rh->dictionary_encrypt` (the `encrypt=`/`has_tag` side list — see
REQ-DICT-DATA-009), then set all four list heads to `NULL`, leaving `rh` in a
state where dictionary lookups return no matches until a new
`rc_read_dictionary()`/`rc_read_dictionary_from_buffer()`/`rc_dict_add*()`
call repopulates them. It MUST NOT free `rh->first_dict_read` (that string is
owned and released separately, e.g. `rc_destroy()`/`config.c:1177`) —
callers wanting a fully-reset "no dictionary has ever been read" state must
also clear `first_dict_read` themselves if they intend to call
`rc_read_dictionary()` again with the same filename and have it re-parse.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:786-813; lib/config.c:1177-1179
**Acceptance:** [DATA] positive, local — after `rc_dict_free(rh)`,
`rc_dict_findattr(rh, "User-Name")` returns `NULL`. [REVIEW-adjacent, not
flagged] — calling `rc_read_dictionary(rh, samepath)` again after
`rc_dict_free()` but without clearing `first_dict_read` returns `0` without
reloading anything (per REQ-DICT-INIT-001), which is an easy-to-hit caller
pitfall worth noting in the `rc_dict_free()` Doxygen comment (currently
absent — see REQ-GEN-ABI-003).
**Links:** REQ-DICT-INIT-001

### REQ-DICT-DATA-009 — an `ATTRIBUTE` line's option list MAY carry `has_tag` and/or `encrypt=`, recorded per-attribute and queryable independently of `DICT_ATTR`

**Requirement:** In addition to `vendor=`/bare-vendor-name (REQ-DICT-DATA-003),
the comma-separated option list on an `ATTRIBUTE` line's fourth token MAY
contain:
- `has_tag` (RFC 2868 SS3.1 tunnel-attribute tagging) — a bare flag, no value.
- `encrypt=Tunnel-Password` — sets the RFC 2868 SS3.5 / RFC 2548
  SS2.4.2-2.4.3 salt-encryption scheme (internally represented as
  `encrypt_type == 2`). This is the spelling FreeRADIUS's own dictionaries
  use for this scheme (e.g. `dictionary.rfc2868`'s `Tunnel-Password` line:
  `string has_tag,encrypt=Tunnel-Password`; `dictionary.microsoft`'s
  `MPPE-Send-Key`/`MPPE-Recv-Key` lines use the same spelling despite not
  being named "Tunnel-Password" themselves — the name identifies the scheme,
  not the attribute it's declared on). No numeric spelling is accepted: this
  grammar has no prior release to stay compatible with, so there is exactly
  one way to write it. Any other `encrypt=` value MUST be rejected — no other
  scheme is implemented (see `lib/avp.c`'s `radcli_avp_decode()`).
Both flags MAY appear on the same line, in either order, and are independent
of any `vendor=`/bare-vendor-name token also present. Neither flag is stored
on the public `DICT_ATTR` struct (`include/radcli/radcli.h`); both live in the
internal `struct dict_encrypt_flag` side list keyed by `DICT_ATTR*` identity
(`rh->dictionary_encrypt`), queryable via `rc_dict_attr_has_tag()`/
`rc_dict_attr_encrypt_type()` (`include/includes.h`, internal only — not
exported). An attribute with neither flag set returns `0`/false from both
accessors. `radcli_avp_decode()` (`lib/avp.c`) consults `rc_dict_attr_has_tag()`
to decide whether a salt-encrypted attribute's ciphertext is preceded by a
one-octet Tag, rather than checking the attribute's identity.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:322-405 (`has_tag`/`encrypt=` option parsing), 817-845
(`rc_dict_attr_encrypt_type`/`rc_dict_attr_has_tag`); include/includes.h
(`struct dict_encrypt_flag`, accessor declarations); lib/avp.c:453-464
(`avp_decode_into()`'s use of `rc_dict_attr_has_tag()`)
**Acceptance:** [DATA] positive, local — loading a verbatim excerpt of
FreeRADIUS's `share/dictionary/radius/dictionary.rfc2868` (which uses `uint32`
and `has_tag`/`encrypt=Tunnel-Password` throughout) succeeds; its
`Tunnel-Password` line reports `rc_dict_attr_encrypt_type() == 2` and
`rc_dict_attr_has_tag() == 1`, identical to radcli's own `etc/dictionary`
(same spelling: `encrypt=Tunnel-Password,has_tag`); its `Tunnel-Type` line
reports `has_tag == 1`, `encrypt_type == 0`. [DATA] positive — a
Tunnel-Password AVP salt-encrypted per RFC 2868 decodes to the same
plaintext whether its definition came from radcli's own `etc/dictionary` or
the real upstream excerpt (option token order differs between the two: flags
first in the real file, `encrypt=` first in radcli's). [ERR] negative —
`ATTRIBUTE Foo 1 string encrypt=Bogus-Name` and `ATTRIBUTE Foo 1 string
encrypt=2` both cause `rc_dict_init()` to return `-1` — the numeric spelling
is not a recognised name.
**Links:** REQ-DICT-DATA-001, REQ-DICT-DATA-003

---

## ERR — parse-error, validation, and allocation-failure behavior

### REQ-DICT-ERR-001 — names longer than `RC_NAME_LENGTH` (64) MUST be rejected, both by `rc_dict_add*()` and by dictionary-file parsing

**Requirement:** `rc_dict_addattr()`, `rc_dict_addval()`, `rc_dict_addvend()`,
and `rc_dict_init()`'s `ATTRIBUTE`/`VALUE`/`VENDOR` line handlers MUST all
reject (return `NULL`/`-1`, log `LOG_ERR`) any name/attribute token whose
`strlen()` exceeds `RC_NAME_LENGTH` (64).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:42-46 (`rc_dict_addattr`), 85-95 (`rc_dict_addval`),
126-130 (`rc_dict_addvend`); lib/dict.c:170-185 (`rc_dict_init` buffer
declarations), 243 (`ATTRIBUTE` length check, before `strlcpy`), 367,375
(`VALUE` attr/name length checks, before `strlcpy`), 490 (`VENDOR` length
check, before `strlcpy`)
**Acceptance:** [ERR] negative, local — a 65-character name to
`rc_dict_addattr()` returns `NULL`; a dictionary file containing `ATTRIBUTE
<65-char-name> 1 integer` is rejected by `rc_dict_init()` (returns `-1`,
logs "invalid name length").
**Links:** REQ-DICT-DATA-007, REQ-GEN-MEM-004

### REQ-DICT-ERR-002 — numeric fields MUST be validated in full, not just by their first character

**Requirement:** Wherever the parser expects a numeric token (`ATTRIBUTE`'s
value, `VALUE`'s value, `VENDOR`'s PEC), it MUST reject the line unless every
character of the token is a digit, then convert with `atoi()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:159-168 (`is_unsigned_decimal()` helper, validates
every character); call sites at lib/dict.c:263 (`ATTRIBUTE`), 387 (`VALUE`),
501 (`VENDOR`)
**Acceptance:** [ERR] negative, local — `ATTRIBUTE Foo abc integer` is
rejected (not a digit); `ATTRIBUTE Foo 12abc integer` is also rejected
(trailing non-digit characters).
**Links:** REQ-DICT-DATA-001

### REQ-DICT-ERR-003 — any parse error aborts the entire `rc_dict_init()` call (and any nested `$INCLUDE`) with no partial rollback

**Requirement:** On the first malformed line (missing required tokens per
line type, invalid numeric field, unknown `TYPE` keyword, or an unresolved
vendor reference in `vendor=`/`BEGIN-VENDOR`), `rc_dict_init()` MUST return
`-1` immediately without processing further lines of that file. Because
`$INCLUDE` recursion propagates the `-1` up through `rc_read_dictionary()`
(dict.c:424-427), an error in an included file aborts the entire top-level
load. Entries already inserted into `rh->dictionary_*` from lines processed
*before* the failing line (in this file or an earlier-processed included
file) are NOT rolled back — the handle is left with a partially-populated,
inconsistent dictionary after a failed load.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:185-509 (`rc_dict_init` — every validation branch
`return -1`s directly, no cleanup); dict.c:424-427 (`$INCLUDE` error
propagation)
**Acceptance:** [ERR] negative, local — a dictionary with a valid
`ATTRIBUTE` line followed by a malformed one: `rc_read_dictionary()` returns
`-1`, but `rc_dict_findattr()` for the *first* (valid) attribute still
succeeds, demonstrating no rollback. Callers MUST treat a `-1` return as
"dictionary state is undefined/partial" and typically call `rc_destroy()`
rather than continue (see REQ-DICT-INIT-003's `rc_read_config()` usage,
which does exactly this).
**Links:** REQ-DICT-INIT-003

### REQ-DICT-ERR-004 — `fopen()`/`fmemopen()` failure and allocation failures are reported via `rc_log()` and a negative/`NULL` return, never a crash

**Requirement:** `rc_read_dictionary()` MUST log `LOG_ERR` with
`strerror(errno)` and return `-1` if `fopen()` fails. `rc_read_dictionary_from_buffer()`
MUST do the same (`LOG_ERR`) if `fmemopen()` fails. Every `malloc()` call in
`rc_dict_init()` and `rc_dict_addattr()`/`addval()`/`addvend()` MUST be
checked; on failure, `rc_log(LOG_CRIT, ...)` MUST be logged and the function
MUST return `-1`/`NULL` rather than dereferencing the failed allocation.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict.c:529-534, 561-566 (open failures); 56-59, 98-101,
133-138 (`rc_dict_add*` allocation checks); 315-319, 381-385, 494-499
(parser allocation checks)
**Acceptance:** [ERR] negative, local — point `rc_read_dictionary()` at a
nonexistent path; confirm `-1` return and an `LOG_ERR` log line containing
the path and `strerror`.
**Links:** REQ-GEN-MEM-002

---

## CFG — interaction with `rc_read_config` and the build-time dictionary generator

### REQ-DICT-CFG-001 — the `dictionary` config keyword names an optional, additional dictionary file loaded after the built-in one

**Requirement:** `rc_read_config()` MUST read the `dictionary` option via
`rc_conf_str(rh, "dictionary")`; if set, the named file MUST be loaded with
`rc_read_dictionary()` (so it — unlike the built-in buffer load — MAY use
`$INCLUDE`, per REQ-DICT-INIT-002/004) after the built-in RFC dictionary has
already been loaded (REQ-DICT-INIT-003), so its entries can shadow built-in
ones per REQ-DICT-DATA-005. If unset, `rc_read_config()` proceeds with only
the built-in dictionary loaded — this MUST NOT be treated as an error.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:773-780
**Acceptance:** [CFG] positive, local — a config file with no `dictionary`
line still yields a working `rh` with standard attributes resolvable;
a config file with `dictionary /path/to/extra` makes both built-in and
`/path/to/extra`'s attributes resolvable, with `/path/to/extra` taking
priority on name collision.
**Links:** REQ-DICT-INIT-003, REQ-DICT-DATA-005

### REQ-DICT-CFG-002 — the built-in dictionary is generated at build time from `etc/dictionary` by `gen-dict.awk`, with `$INCLUDE` lines stripped

**Requirement:** `lib/dict_rfc_gen.h`'s `rc_rfc_dictionary[]` string literal
MUST be produced by running `gen-dict.awk` over `etc/dictionary` (invoked as
part of the Meson build, not committed by hand — see file header "do not
edit"). The generator MUST drop any line beginning with `$INCLUDE` (so the
compiled-in dictionary is self-contained and has no runtime file
dependency), and MUST escape backslashes and double quotes in every other
line so the result is a valid C string literal, one dictionary line per
`"...\n"` segment. Because `$INCLUDE` is stripped rather than resolved, if
`etc/dictionary` itself ever grows a top-level `$INCLUDE` (it currently has
none — verified empty grep match), that included content would silently be
absent from the compiled-in dictionary; this is an implicit constraint on
`etc/dictionary`'s structure, not enforced by any build-time check.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/gen-dict.awk:1-23; lib/dict_rfc_gen.h:1-2; etc/dictionary
(no `$INCLUDE` lines present, confirmed by inspection)
**Acceptance:** [CFG] build-time, local — `awk -f lib/gen-dict.awk
etc/dictionary` reproduces `lib/dict_rfc_gen.h` byte-for-byte (modulo the
"do not edit" header line). [REVIEW-adjacent, not flagged] — no automated
check currently guards against a future `$INCLUDE` being silently dropped;
consider a build-time grep/assertion if `etc/dictionary` gains includes.
**Links:** REQ-DICT-INIT-003, REQ-DICT-INIT-002

---

## Phase 5 — Completeness and Gap Analysis

**Public API coverage** (every `rc_dict_*`/`rc_read_dictionary*` symbol in
`include/radcli/radcli.h` and `lib/radcli.map.in`):

| Symbol | Covered by |
|---|---|
| `rc_read_dictionary` | REQ-DICT-INIT-001, -004, -005 |
| `rc_read_dictionary_from_buffer` | REQ-DICT-INIT-002 |
| `rc_dict_addattr` | REQ-DICT-DATA-002, -007, REQ-DICT-ERR-001 |
| `rc_dict_addval` | REQ-DICT-DATA-007, REQ-DICT-ERR-001 |
| `rc_dict_addvend` | REQ-DICT-DATA-007, REQ-DICT-ERR-001 |
| `rc_dict_getattr` | REQ-DICT-DATA-002, -005, -006 |
| `rc_dict_findattr` | REQ-DICT-DATA-005, -006 |
| `rc_dict_findval` | REQ-DICT-DATA-006 |
| `rc_dict_findvend` | REQ-DICT-DATA-004, -006 |
| `rc_dict_getvend` | REQ-DICT-DATA-006 |
| `rc_dict_getval` | REQ-DICT-DATA-006 |
| `rc_dict_free` | REQ-DICT-DATA-008 |

All 12 public symbols in this subsystem have at least one citing requirement.
No `[UNDOCUMENTED]` gap was found at the API-surface level.

**Data structures**: `DICT_ATTR`, `DICT_VALUE`, `DICT_VENDOR` (transparent,
public — `include/radcli/radcli.h:441-468`) are covered by REQ-DICT-DATA-002,
-005, -007. `rc_handle`'s dictionary-related fields
(`first_dict_read`/`dictionary_attributes`/`dictionary_values`/`dictionary_vendors`,
`include/includes.h:196-199`) are internal/opaque (not in the public header)
but are cited throughout as the state the public API manipulates.

**Constants**: `RC_NAME_LENGTH` (64), `AUTH_ID_LEN` (64), `VENDOR_BIT_SIZE`
(32), `RADCLI_VENDOR_MASK`, `RADCLI_VENDOR_ATTR_SET()`, `VENDOR()` are all
public-header configuration/encoding surfaces, covered by REQ-DICT-DATA-002,
REQ-DICT-ERR-001. `PW_TYPE_*`/`rc_attr_type` covered by REQ-DICT-DATA-001,
-007.

**Gaps / flags carried from the body of this document**:

- `[REVIEW]` REQ-DICT-DATA-006 — `rc_dict_getval()`'s case-sensitive
  `attrname` match is inconsistent with the case-insensitive matching of
  every sibling lookup function; unclear if intentional.
- `[REVIEW]` REQ-DICT-ERR-001 — in-parser name-length validation
  (`rc_dict_init()`) is dead code: the preceding fixed-size `strlcpy()` into
  an `AUTH_ID_LEN`-sized buffer already truncates any over-long token before
  the `> RC_NAME_LENGTH` check can observe the original length, so
  dictionary-file names are silently truncated to 63 characters rather than
  rejected — unlike `rc_dict_addattr()`/`addval()`/`addvend()`, which check
  the caller's untruncated string and do reject.
- `[REVIEW]` REQ-DICT-ERR-002 — numeric field validation checks only the
  first character is a digit; a value like `12abc` is silently accepted as
  `12` via `atoi()`.
- No `[UNDOCUMENTED]` behaviors were found — every parser branch and lookup
  function corresponds to a documented dictionary-file construct or a
  Doxygen-commented public function.
- No `[AMBIGUOUS]` items requiring two competing interpretations were found;
  the REVIEW items above have a single clear current behavior, just an open
  question about whether that behavior is the intended contract.
