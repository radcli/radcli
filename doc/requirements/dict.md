---
title: dictionary loading, parsing, and legacy rc_dict_* lookup requirements
generator: requirements-from-implementation
id-prefix: REQ-DICT
categories:
  INIT: dictionary loading entry points ($FILE / buffer / $INCLUDE / built-in RFC dictionary)
  DATA: DICT_ATTR/DICT_VALUE/DICT_VENDOR construction, encoding, and lookup semantics
  ERR: parse-error, validation, and allocation-failure behavior
  CFG: interaction with rc_read_config and the build-time dictionary generator
sources:
  - lib/legacy/dict.c
  - lib/legacy/compat.c
  - lib/dict2.c
  - lib/dict2-parse.c
  - lib/dict2.h
  - lib/uthash/uthash.h
  - lib/dict_rfc_gen.h
  - lib/gen-dict.awk
  - include/radcli/radcli.h
  - include/includes.h
  - lib/config.c
  - etc/dictionary
  - doc/requirements/general.md
  - doc/requirements/README.md
---

# Dictionary Loading, Parsing, and Legacy Lookup Requirements

This document covers the **legacy** RADIUS dictionary API: the `rc_dict_*`
lookup/construction functions and `rc_read_dictionary()`/
`rc_read_dictionary_from_buffer()`/`rc_dict_free()`, all declared in
`include/radcli/radcli.h` and all resolving to `DICT_ATTR`/`DICT_VALUE`/
`DICT_VENDOR` (transparent, pointer-returned, frozen-ABI structs) — together
with the dictionary-file grammar (`ATTRIBUTE`/`VALUE`/`VENDOR`/`$INCLUDE`
lines, the built-in compiled-in RFC dictionary) that underlies it, since that
grammar has no meaning independent of some API surface to expose it through.
`radcli2.h`'s parallel, opaque lookup API (`radcli_dict_lookup()` and
siblings) is `dict2.md`'s document instead — see its own intro for why it is
a separate file rather than a section here, and this document's "Legacy vs.
`radcli2.h`" note below for the reverse direction: where a dictionary-file
feature exists but is only observable through `radcli2.h`, this document
states just enough to record that the legacy API cannot see it, and
`dict2.md` owns the feature's actual contract. This document does **not**
cover how `VALUE_PAIR`s are built, encoded onto the wire, or matched against
a dictionary entry at packet-construction/parsing time — that is `attrs.md`'s
scope. Where a dictionary behavior is a precondition for attribute handling
(e.g. a name must resolve via `rc_dict_findattr` before `rc_avpair_add` can
encode it), this document states the dictionary-side guarantee and
`attrs.md` states the attribute-side consumption of it.

**Implementation split (as of the dict2 rewrite):** `lib/dict2.c`/
`lib/dict2-parse.c`/`lib/dict2.h` are the canonical implementation --
parsing, `$INCLUDE` resolution, and O(1) uthash-indexed lookup by
name/id/vendor (`lib/uthash/uthash.h`, BSD-1-Clause, vendored the way
`lib/ccan/list/` already was) in place of the former linear-scanned
`next`-chains. `rc_read_dictionary()`, `rc_read_dictionary_from_buffer()`,
and `rc_dict_free()` -- the only three entry points any external caller
checked (including ocserv's `src/acct/radius.c`/`src/auth/radius.c`)
actually uses -- keep their existing public names/signatures and identical
documented behavior (guard/`$INCLUDE`/ownership semantics unchanged), but
are now one-line wrappers in `lib/legacy/compat.c` around
`radcli2_priv_read_dictionary()`/`_from_buffer()`/`radcli2_priv_dict_free()`
-- the real implementations, living in `lib/dict2-parse.c`/`lib/dict2.c`
respectively. That wrapper indirection (unlike `lib/legacy/dict.c`'s direct
`rc_dict_add*()`/`find*()`/`get*()` shims) exists purely for symbol
versioning: `radcli2_priv_read_dictionary()` is also called directly by
`radcli_ctx_read_dictionary()` (`config2.md`) inside `libradcli2`, so the
`rc_*`-named, `RADCLI_10`-versioned symbol a pre-split `libradcli.so`
consumer's relocation records expect has to stay physically defined in
`libradcli` itself rather than resolve into `libradcli2` at load time -- see
`lib/legacy/compat.c`'s file comment. `lib/legacy/dict.c` (relocated
there, with the rest of the `VALUE_PAIR`-based sources, from its original
`lib/dict.c` path, in the same reorganization that split this document's
scope from `dict2.md`'s) is now a thin compatibility shim, containing only
the `rc_dict_*()` symbols declared in `include/radcli/radcli.h`:
`rc_dict_addattr`/`addval`/`addvend`/`getattr`/`findattr`/`findval`/`getval`/
`findvend`/`getvend` forward to `lib/dict2.h` and lazily materialize a cached
`DICT_ATTR`/`DICT_VALUE`/`DICT_VENDOR` shadow struct, kept only because those
structs are frozen public ABI returned by pointer. No public symbol, struct
layout, or documented behavior changed; every requirement below still holds
of the public API. `radcli2.h`'s `radcli_dict_lookup()`/`_lookup_num()`/
`_lookup_oid()` (`dict2.md`'s scope) have no such ABI constraint and, along
with `radcli_attr_def_name()`/`_type()`/`_oid()` and their
`dict_type_to_radcli()`/`parse_oid()` helpers, live in `lib/dict2.c` entirely
-- not just their lookups; `lib/legacy/dict.c` never defines them, since
none of them appear in `radcli.h`. They resolve straight to the lookup
functions declared in `lib/dict2.h` -- no legacy `DICT_ATTR` shadow is ever
materialized for a `radcli2.h` caller. `lib/avp.c`'s casts
of a `radcli_attr_def*` (which `radcli_dict_lookup()`/etc. hand back) use
`(const struct radcli_dict_attr *)`, not `(const DICT_ATTR *)`, and its
`radcli_dict_flags_by_id()`/`radcli_dict_attr_gigawords()` calls go straight
to `lib/dict2.h` rather than through any `DICT_ATTR*`-typed wrapper --
`lib/legacy/dict.c` never defined `rc_dict_attr_encrypt_type()`/
`_has_tag()`/`_gigawords()` shims for `lib/avp.c` to begin with, since those
would have taken a genuine `DICT_ATTR*`, not the opaque `radcli_attr_def`
`lib/avp.c` actually holds. `src/radacct.c` is the one external-style
consumer that stays on the `rc_dict_*()` shim rather than calling
`lib/dict2.h` directly, for the same reason ocserv does: it is a separate
executable linking against `libradcli`'s public shared-library ABI, and
`lib/dict2.h`'s functions are deliberately unexported, so calling them
directly would be a link error, not a design choice.

**Legacy vs. `radcli2.h`:** a dictionary-file feature whose only observable
effect is through `radcli2.h`'s opaque type system -- the `integer64`/`ifid`
`ATTRIBUTE` type-token keywords -- is `dict2.md`'s to state in full
(`REQ-DICT2-DATA-007`/`-008`), not this document's, even though the grammar
itself is parsed by the same `lib/dict2-parse.c` this document otherwise
owns: a legacy caller has no way to observe either type correctly, because
`radcli_dict_type_to_legacy()` (`lib/dict2.h`) maps any type `>= PW_TYPE_MAX`
-- which both sentinels are -- down to `PW_TYPE_STRING` for the lazily
materialized `DICT_ATTR` shadow, so the "requirement" from a legacy-API
point of view is only ever "opaque bytes, safely, never a crash or the wrong
numeric interpretation" -- not worth a `REQ-DICT-*` of its own. `REQ-DICT-DATA-010`
and `REQ-DICT-DATA-012` previously stated these two keywords here and are now
`WITHDRAWN` in favor of `dict2.md`'s versions, per the ID-stability rule in
`README.md` ("mark WITHDRAWN, do not renumber"). The `gigawords=` pairing
(`REQ-DICT-DATA-011`) and the `has_tag`/`encrypt=` flags (`REQ-DICT-DATA-009`)
stay here despite also being consulted by `radcli2.h`'s codec
(`avp2.md`'s `radcli_avp_add_gigawords64()`/`radcli_avp_decode()`/
`radcli_avp_encode()`): unlike `integer64`/`ifid`, both remain fully meaningful
to a legacy caller too -- `rc_dict_attr_gigawords()` and `lib/legacy/send.c`'s
`rc_pack_list()` (relocated from its original `lib/sendserver.c` path)
consult them directly, so they are genuinely shared dictionary-file
semantics, not a `radcli2.h`-exclusive one wearing dictionary-grammar
clothing.

Cross-cutting memory-safety and unsafe-string-function rules
(`REQ-GEN-MEM-002`, `REQ-GEN-MEM-004`) apply throughout `lib/legacy/dict.c`/
`lib/dict2.c` and are linked from individual requirements below rather than
restated.

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
**Source:** lib/legacy/compat.c:115-118 (`rc_read_dictionary()`, a one-line
wrapper kept for symbol-versioning reasons -- see the file's header comment);
lib/dict2-parse.c:743-766 (`radcli2_priv_read_dictionary()`, the real
implementation both this wrapper and `radcli_ctx_read_dictionary()`
(`config2.md`) call); include/includes.h (`first_dict_read` field)
**Acceptance:** [INIT] positive, local — load a dictionary file twice via two
`rc_read_dictionary` calls with the same path; second call returns `0` without
duplicating entries (list length unchanged). Negative — call with a
nonexistent path; returns `-1` and logs `LOG_ERR` with `strerror(errno)`
(lib/dict2-parse.c:754-758).
**Links:** REQ-DICT-INIT-004, REQ-DICT-DATA-008

### REQ-DICT-INIT-002 — `rc_read_dictionary_from_buffer` parses an in-memory buffer and disables `$INCLUDE`

**Requirement:** `rc_read_dictionary_from_buffer(rh, buf, size)` MUST open
`buf` (length `size`) as a stream via `fmemopen()` and parse it with the same
grammar as `rc_read_dictionary`, passing a `NULL` filename to the internal
parser. Because the `$INCLUDE` branch is gated on `filename != NULL`
(lib/dict2-parse.c:601-602), a buffer-sourced dictionary MUST NOT process
`$INCLUDE` directives — such a line is silently skipped by falling through
the `strcmp(tok, ...)` chain with no match (no other branch matches
`$INCLUDE`, so it is ignored) rather than being an error.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/legacy/compat.c:120-123 (`rc_read_dictionary_from_buffer()`
wrapper); lib/dict2-parse.c:778-798
(`radcli2_priv_read_dictionary_from_buffer()`, the real implementation);
lib/dict2-parse.c:601-602 (`$INCLUDE` branch guarded by `filename != NULL`)
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
**Source:** lib/config.c:740-747 (`radcli2_priv_load_builtin_dict()`),
858-868 (`radcli2_priv_read_config()`'s call to it, then the `dictionary`
option)
**Acceptance:** [INIT] positive, local — `rc_read_config()` on a config file
with no `dictionary` line still resolves standard attribute names (e.g.
`User-Name`) via `rc_dict_findattr()`. [ERR] negative — build a binary against
a corrupted `rc_rfc_dictionary` (or intercept `fmemopen` to fail) and confirm
`rc_read_config()` returns `NULL`.
**Links:** REQ-DICT-CFG-002, REQ-DICT-INIT-002

### REQ-DICT-INIT-004 — `$INCLUDE` paths resolve relative to the including file's directory; absolute paths are used verbatim

**Requirement:** When `rc_dict_init()` encounters `$INCLUDE <path>` while
parsing a file (not a buffer — see REQ-DICT-INIT-002), it MUST recursively
call `radcli2_priv_read_dictionary()` (the shared implementation behind both
`rc_read_dictionary()` and `radcli_ctx_read_dictionary()`) on the resolved
path. If `<path>` begins with `/`, it MUST be used unmodified. Otherwise it
MUST be resolved by taking the directory portion of the *including* file's
own path (up to and including the last `/`) and appending `<path>`; if the
including filename has no `/`, the raw token is used as read into
`ifilename`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c:601-633
**Acceptance:** [INIT] positive, local — a dictionary at `dir/a` containing
`$INCLUDE b` successfully loads `dir/b`; a dictionary containing
`$INCLUDE /abs/path` loads `/abs/path` regardless of the including file's
location.
**Links:** REQ-DICT-INIT-001, REQ-DICT-INIT-005

### REQ-DICT-INIT-005 — `$INCLUDE` path length is bounded by `RC_MAX(1024, PATH_MAX)`, not truncated to 63 characters

**Requirement:** The resolved `$INCLUDE` path MUST be copied into a buffer
sized `RC_MAX(1024, PATH_MAX)` bytes (`ifilename`, lib/dict2-parse.c:163)
using `strlcpy()`/`strlcat()`, so that include paths up to that bound
(typically 4095+ bytes on Linux, since `PATH_MAX` is usually 4096) are
preserved intact. This corrects a prior defect (see commit `d5b1713`, "dict:
fix `$INCLUDE` path truncation to 63 chars") where the include path was read
with `sscanf("%63s", ...)` into a smaller, `AUTH_ID_LEN`(64)-derived buffer;
current code MUST NOT reintroduce a fixed-63/64-byte bound for `$INCLUDE`
paths specifically (the 64-byte `RC_NAME_LENGTH` bound legitimately applies
to attribute/value/vendor *names*, not include paths — see REQ-DICT-ERR-001).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c:163, 619-627; git log `d5b1713` (regression
this supersedes)
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
**Source:** lib/dict2-parse.c:210-521 (`ATTRIBUTE` branch); include/radcli/radcli.h:120-128
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
**Source:** include/radcli/radcli.h:65 (`RADCLI_VENDOR_ATTR_SET`,
`VENDOR_BIT_SIZE`, `VENDOR()`); lib/dict2-parse.c:469-471, 828 (parser's
`RADCLI_VENDOR_ATTR_SET()` call sites)
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
**Source:** lib/dict2-parse.c:446-452 (per-line `vendor=` option), 636-664
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
**Source:** lib/dict2-parse.c:665-712 (`VENDOR` branch)
**Acceptance:** [DATA] positive, local — `VENDOR V 99` followed anywhere
later by `BEGIN-VENDOR V` succeeds; `rc_dict_findvend(rh, "v")` (any case)
returns the entry with `vendorpec == 99`.
**Links:** REQ-DICT-DATA-003, REQ-DICT-DATA-006

### REQ-DICT-DATA-005 — a redefinition identical to an already-loaded entry is deduplicated; a conflicting one fails the load

**Requirement:** Every successful `ATTRIBUTE`/`VALUE`/`VENDOR` parse, and
every `rc_dict_addattr()`/`rc_dict_addval()`/`rc_dict_addvend()` call, MUST
first look up an already-loaded entry with the same primary key -- name for
`ATTRIBUTE`/`VENDOR`, attribute+numeric-value for `VALUE` (deliberately not
`attrs_by_id`/`vendors_by_pec`: several distinct *names* may legitimately
share one numeric id, e.g. the built-in `Password`/`User-Password` alias
pair for attribute 2, so a same-id-different-name pair is not a conflict).
If none exists, the candidate is inserted normally. If one exists with an
identical definition (same id/vendor/type for an attribute, same value-name
for a VALUE, same PEC for a vendor), the candidate MUST be discarded without
being inserted and without error -- this is what makes loading the same
dictionary content twice (e.g. the built-in RFC dictionary and a
`dictionary=` file that repeats some of the same standard attributes,
REQ-DICT-INIT-003) cost no extra memory. If one exists with a *conflicting*
definition, the candidate MUST be discarded, a warning naming both
definitions MUST be logged, and the whole parse/add call MUST fail. This
means a `dictionary=` file can no longer silently override a built-in
attribute's definition by redeclaring it differently -- a conflicting
redeclaration is now a load error, not an override.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c's `dict2_check_attr`/`dict2_check_value`/
`dict2_check_vendor` (shared between `dict2_parse()`'s three `ATTRIBUTE`/
`VALUE`/`VENDOR` branches and `radcli_dict_attr_add`/`value_add`/`vendor_add`)
**Acceptance:** [DATA] positive, local — loading the same dictionary buffer
twice succeeds both times and yields the same single entry (no duplicate
allocation) on lookup. [ERR] negative — loading a dictionary, then a second
one redefining the same attribute name with a different numeric id, fails
the second load and logs a warning naming both definitions;
`rc_dict_findattr()` still returns the first (only) definition. Symmetric
cases for `VALUE` (same attribute+number, different name) and `VENDOR`
(same name, different PEC).
**Links:** REQ-DICT-INIT-003, REQ-DICT-DATA-007

### REQ-DICT-DATA-006 — all dictionary name lookups, including `rc_dict_getval`'s attribute-name match, MUST be case-insensitive

**Requirement:** `rc_dict_findattr()`, `rc_dict_findval()`, `rc_dict_findvend()`,
and `rc_dict_getval()` MUST all compare their name argument against stored
names using `strcasecmp()` (case-insensitive). `rc_dict_getattr()` matches by
exact 64-bit encoded numeric value (`==`), and `rc_dict_getvend()` matches by
exact 32-bit PEN (`==`) — both case-independent since they take no string.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/legacy/dict.c:119-179 (`rc_dict_findattr`/`findval`/
`findvend`/`getval` shim, forwarding to the `radcli_dict_*_by_name`/
`_by_attr` lookups below); lib/dict2.h:65 (`dict2_lc()`, the lowercased hash
key every name lookup builds before `HASH_FIND()`); lib/dict2.c:118-133
(`radcli_dict_attr_by_name`), 146-161 (`radcli_dict_value_by_name`),
163-177 (`radcli_dict_value_by_attr`), 195-210 (`radcli_dict_vendor_by_name`)
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
**Source:** lib/legacy/dict.c:59-113 (`rc_dict_addattr`/`addval`/`addvend`
shim); lib/dict2-parse.c:800-940 (`radcli_dict_attr_add`/`value_add`/
`vendor_add`)
**Acceptance:** [DATA] positive, local — `rc_dict_addattr(rh, "X-Attr", 1,
PW_TYPE_INTEGER, 0)` returns a non-NULL `DICT_ATTR*` findable via
`rc_dict_findattr(rh, "X-Attr")`. [ERR] negative — a 65+ character name or
`type == PW_TYPE_MAX` returns `NULL`.
**Links:** REQ-DICT-DATA-005, REQ-DICT-ERR-001

### REQ-DICT-DATA-008 — `rc_dict_free` releases the whole dictionary and resets the handle to an empty dictionary state

**Requirement:** `rc_dict_free(rh)` MUST empty and free every one of
`rh->dict`'s six uthash tables (attributes by name/id, values by name/
attribute, vendors by name/PEC) plus the `encrypt=`/`has_tag`/`gigawords=`
side tables (REQ-DICT-DATA-009, REQ-DICT-DATA-011), free every entry's
lazily-materialized legacy `DICT_ATTR`/`DICT_VALUE`/`DICT_VENDOR` shadow
(freed by `rc_dict_free()` itself, never by a caller of
`rc_dict_findattr()`/etc.), then free `rh->dict` and set it `NULL`, leaving
`rh` in a state where dictionary lookups return no matches until a new
`rc_read_dictionary()`/`rc_read_dictionary_from_buffer()`/`rc_dict_add*()`
call repopulates them (lazily reallocating `rh->dict`). It MUST NOT free
`rh->first_dict_read` (that string is owned and released separately, e.g.
`rc_destroy()`/`lib/config.c`'s `rc_config_free()`) — callers wanting a
fully-reset "no dictionary has ever been read" state must also clear
`first_dict_read` themselves if they intend to call `rc_read_dictionary()`
again with the same filename and have it re-parse.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/legacy/compat.c:125-128 (`rc_dict_free()` wrapper);
lib/dict2.c:51-116 (`radcli2_priv_dict_free()`, the real implementation);
lib/config.c:1311-1313 (`rc_config_free()`'s separate
`free(rh->first_dict_read)`)
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
- `has_tag` (RFC 2868's one-octet "Tag" field, shared by all ten tunnel
  attributes, e.g. SS3.1 Tunnel-Type, SS3.2 Tunnel-Medium-Type, SS3.5
  Tunnel-Password) — a bare flag, no value.
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
on the public `DICT_ATTR` struct (`include/radcli/radcli.h`), nor on
`lib/dict2.h`'s `struct radcli_dict_attr`; both live in the internal
`struct radcli_dict_flags` side table, keyed by attribute id (not by node
identity — see REQ-DICT-DATA-005's comment on `struct radcli_dict_flags`),
queryable via `radcli_dict_flags_by_id()` (`lib/dict2.h`, internal only —
not exported). An attribute with neither flag set has no
`struct radcli_dict_flags` entry at all (`radcli_dict_flags_by_id()` returns
`NULL`). `radcli_avp_decode()` (`lib/avp.c`) consults the `has_tag` flag via
`radcli_dict_flags_by_id()` to decide whether a salt-encrypted attribute's
ciphertext is preceded by a one-octet Tag, rather than checking the
attribute's identity; `lib/legacy/send.c`'s `rc_pack_list()` consults
`encrypt_type` the same way to refuse sending an attribute it cannot
encrypt. (An earlier `rc_dict_attr_encrypt_type()`/`rc_dict_attr_has_tag()`
pair of internal, unexported shim functions in `lib/legacy/dict.c` existed only to
let those two call sites reach this table through a `DICT_ATTR*`-typed
wrapper; once both were migrated to call `radcli_dict_flags_by_id()`
directly, the wrapper functions had zero remaining callers and were
removed — dead code, not a behavior change, since they were never part of
the public ABI.)
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c:374-409 (`has_tag`/`encrypt=` option parsing),
493-503 (`flags_by_attr_id` `HASH_ADD()`); lib/dict2.c:223-232
(`radcli_dict_flags_by_id`); lib/avp.c:1048 (`avp_decode_into()`'s
`radcli_dict_flags_by_id()` call), 1222 (`radcli_avp_encode()`'s);
lib/legacy/send.c (`rc_pack_list()`'s `radcli_dict_flags_by_id()` call)
**Acceptance:** [DATA] positive, local — loading a verbatim excerpt of
FreeRADIUS's `share/dictionary/radius/dictionary.rfc2868` (which uses `uint32`
and `has_tag`/`encrypt=Tunnel-Password` throughout) succeeds; its
`Tunnel-Password` line reports `encrypt_type == 2` and `has_tag == 1` (via
`tests/avp-codec.c`'s local `def_encrypt_type()`/`def_has_tag()` helpers,
which call `radcli_dict_flags_by_id()` directly since `radcli_dict_lookup()`
hands back a `struct radcli_dict_attr*`, not a `DICT_ATTR*`), identical to
radcli's own `etc/dictionary` (same spelling:
`encrypt=Tunnel-Password,has_tag`); its `Tunnel-Type` line reports
`has_tag == 1`, `encrypt_type == 0`. [DATA] positive — a
Tunnel-Password AVP salt-encrypted per RFC 2868 decodes to the same
plaintext whether its definition came from radcli's own `etc/dictionary` or
the real upstream excerpt (option token order differs between the two: flags
first in the real file, `encrypt=` first in radcli's). [ERR] negative —
`ATTRIBUTE Foo 1 string encrypt=Bogus-Name` and `ATTRIBUTE Foo 1 string
encrypt=2` both cause `rc_dict_init()` to return `-1` — the numeric spelling
is not a recognised name.
**Links:** REQ-DICT-DATA-001, REQ-DICT-DATA-003

### REQ-DICT-DATA-010 — WITHDRAWN — an `ATTRIBUTE` line's type token MAY be `integer64` (RFC 8044 SS3.3)

**Status:** WITHDRAWN — superseded by `dict2.md`'s `REQ-DICT2-DATA-007`. This
ID previously stated the `"integer64"` `ATTRIBUTE` type-token grammar and its
`RADCLI_TYPE_INTEGER64` mapping here; per this document's "Legacy vs.
`radcli2.h`" note above, that mapping has no observable meaning to any
legacy-API caller (`radcli_dict_type_to_legacy()` collapses it to
`PW_TYPE_STRING`), so it is now stated in full in `dict2.md` instead,
alongside the other `radcli2.h`-exclusive type keyword (`REQ-DICT2-DATA-008`,
`ifid`). Kept here, WITHDRAWN rather than deleted, per `README.md`'s
ID-stability rule ("mark WITHDRAWN, do not renumber").
**Links:** REQ-DICT2-DATA-007

### REQ-DICT-DATA-011 — an `ATTRIBUTE` line's option list MAY carry `gigawords=<attrid>`, pairing it with a 64-bit-counter Gigawords attribute (RFC 2866/RFC 2869)

**Requirement:** In addition to `has_tag`/`encrypt=` (REQ-DICT-DATA-009), the
comma-separated option list on an `ATTRIBUTE` line MAY contain
`gigawords=<attrid>`, naming — within that line's own vendor scope, if any —
the attribute id of this attribute's Gigawords counterpart for RFC 2866
SS5.3/5.4 Acct-Input/Output-Octets + RFC 2869 SS5.1/5.2 Acct-Input/Output-Gigawords-style
64-bit accounting (e.g. `Acct-Input-Octets`'s `gigawords=52` names
`Acct-Input-Gigawords`). `<attrid>` MUST be a decimal integer in `1..255`;
anything else (non-numeric, `0`, or `> 255`) MUST cause `rc_dict_init()` to
return `-1`. The pairing is recorded, vendor-combined via
`RADCLI_VENDOR_ATTR_SET()`, in the internal `struct radcli_dict_gigawords`
side table (`rh->dict->gigawords_by_attr_id`, `lib/dict2.h`) keyed by the
octets attribute's id, not stored on `DICT_ATTR` or on `lib/dict2.h`'s
`struct radcli_dict_attr`, and resolved lazily to a
`struct radcli_dict_attr`/`DICT_ATTR*` by `radcli_dict_attr_gigawords()`/
`rc_dict_attr_gigawords()` rather than at parse time, since the named
counterpart's own `ATTRIBUTE` line may not have been parsed yet.
**Behavior note (dict2 rewrite):** the pre-dict2 implementation keyed
`dictionary_gigawords` by the octets `DICT_ATTR*`'s pointer identity (exact
struct instance from the `ATTRIBUTE` line that set `gigawords=`), not by id
value -- unlike `encrypt=`/`has_tag` (REQ-DICT-DATA-009), which already
matched by id. This was not exercised by any existing test and is not
documented as intentional anywhere the requirements-extraction process could
find; `lib/dict2-parse.c` deliberately matches by id instead (identical to
`encrypt=`/`has_tag`'s existing "sticky" semantics: a redefinition of the
same id that omits `gigawords=` does not lose the pairing), for
consistency with REQ-DICT-DATA-009 and because it avoids a seventh hash
table needed only to reconstruct the discarded pointer-identity behavior.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c:420-442 (`gigawords=` option parsing), 506-519
(`struct radcli_dict_gigawords` construction); lib/dict2.c:245-257
(`radcli_dict_attr_gigawords()`), 234-243 (`radcli_dict_gigawords_by_id()`),
called directly by `lib/avp.c`'s `radcli_avp_add_gigawords64()`/
`_get_gigawords64()`; lib/dict2.h (`struct radcli_dict_gigawords`)
**Acceptance:** [DATA] positive, local — `tests/dict.c`'s `counter64_dict`
(`Test-Counter-Octets` (252) `gigawords=253` paired with
`Test-Counter-Gigawords` (253)) loads; `radcli_avp_add_gigawords64()`/
`_get_gigawords64()` (`tests/avp.c`) confirm the pairing resolves through
`rc_dict_attr_gigawords()`. [DATA] positive, requires a real FreeRADIUS
server (`tests/request-freeradius.c`, SS4) — `etc/dictionary`'s actual
`Acct-Input-Octets`(42, `gigawords=52`)/`Acct-Input-Gigawords`(52) pair
round-trips a value over 2^32 through a live server via
`radcli_avp_add_gigawords64()`. [ERR] negative, local — `tests/dict.c`'s
`bad_gigawords_dict` (`gigawords=notanumber`) is rejected. `[UNDOCUMENTED]`
gap: the numeric-range validation (`v <= 0 || v > 0xff`, lib/dict2-parse.c:436) has
no dedicated `gigawords=0`/`gigawords=256` negative test. No test exercises
the pointer-identity-vs-id-matching behavior note above either (a
redefinition of an id that had `gigawords=` set, via a second `ATTRIBUTE`
line without it).
**Links:** REQ-DICT-DATA-009, REQ-AVP2-DATA-012

### REQ-DICT-DATA-012 — WITHDRAWN — an `ATTRIBUTE` line's type token MAY be `ifid` (RFC 8044 SS3.7)

**Status:** WITHDRAWN — superseded by `dict2.md`'s `REQ-DICT2-DATA-008`, for
the same reason as `REQ-DICT-DATA-010` above: the `"ifid"` type token's
`RADCLI_TYPE_IFID` mapping is unobservable through the legacy API. Kept
here, WITHDRAWN rather than deleted, per `README.md`'s ID-stability rule.
**Links:** REQ-DICT2-DATA-008

### REQ-DICT-DATA-013 — an `ATTRIBUTE` line's type token MAY be `enum`, a synonym for `integer`/`uint32`

**Requirement:** `rc_dict_init()`'s `ATTRIBUTE` type token MUST accept `enum`
as a third synonym for `PW_TYPE_INTEGER`, alongside `integer` and `uint32`
(REQ-DICT-DATA-001). `enum` is IANA's RADIUS Attribute Types registry name
for the Data Type of an attribute whose 4-octet integer value is drawn from
a fixed set of named constants (e.g. `Service-Type`, `NAS-Port-Type`) -- it
is not one of RFC 8044's distinct wire data types, so it introduces no new
`radcli_attr_type` value: an `enum`-typed attribute resolves to
`RADCLI_TYPE_INTEGER` exactly like an `integer`-typed one, read/written with
the same `radcli_avp_add_uint32()`/`radcli_avp_get_uint32()` pair.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c:277-286 (`"enum"` token parsing)
**Acceptance:** [DATA] positive, local -- `ATTRIBUTE Foo 1 enum` produces a
`DICT_ATTR` with `type == PW_TYPE_INTEGER`, and `radcli_attr_def_type()`
reports `RADCLI_TYPE_INTEGER`, identical to `ATTRIBUTE Foo 1 integer`.
**Links:** REQ-DICT-DATA-001

---

## ERR — parse-error, validation, and allocation-failure behavior

### REQ-DICT-ERR-001 — names longer than `RC_NAME_LENGTH` (64) MUST be rejected, both by `rc_dict_add*()` and by dictionary-file parsing

**Requirement:** `rc_dict_addattr()`, `rc_dict_addval()`, `rc_dict_addvend()`,
and `rc_dict_init()`'s `ATTRIBUTE`/`VALUE`/`VENDOR` line handlers MUST all
reject (return `NULL`/`-1`, log `LOG_ERR`) any name/attribute token whose
`strlen()` exceeds `RC_NAME_LENGTH` (64).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c:805 (`radcli_dict_attr_add`), 854,860
(`radcli_dict_value_add`), 907 (`radcli_dict_vendor_add`) -- the real
implementation behind `lib/legacy/dict.c`'s `rc_dict_addattr`/`addval`/
`addvend` shim; lib/dict2-parse.c:233 (`ATTRIBUTE` length check, before
`strlcpy`), 541,549 (`VALUE` attr/name length checks, before `strlcpy`), 681
(`VENDOR` length check, before `strlcpy`)
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
**Source:** lib/dict2-parse.c:31-45 (`is_unsigned_decimal()` helper,
validates every character); call sites at lib/dict2-parse.c:253
(`ATTRIBUTE`), 561 (`VALUE`), 692 (`VENDOR`)
**Acceptance:** [ERR] negative, local — `ATTRIBUTE Foo abc integer` is
rejected (not a digit); `ATTRIBUTE Foo 12abc integer` is also rejected
(trailing non-digit characters).
**Links:** REQ-DICT-DATA-001

### REQ-DICT-ERR-003 — any parse error aborts the entire `rc_dict_init()` call (and any nested `$INCLUDE`) with no partial rollback

**Requirement:** On the first malformed line (missing required tokens per
line type, invalid numeric field, unknown `TYPE` keyword, or an unresolved
vendor reference in `vendor=`/`BEGIN-VENDOR`), `dict2_parse()` (the
`rc_dict_init()`-descended parser, `lib/dict2-parse.c`) MUST return `-1`
immediately without processing further lines of that file. Because
`$INCLUDE` recursion propagates the `-1` up through
`radcli2_priv_read_dictionary()` (shared by `rc_read_dictionary()` and
`radcli_ctx_read_dictionary()`), an error in an included file aborts the
entire top-level load. Entries already inserted into `rh->dict`'s uthash
tables from lines processed *before* the failing line (in this file or an
earlier-processed included file) are NOT rolled back — the handle is left
with a partially-populated, inconsistent dictionary after a failed load.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dict2-parse.c:156-734 (`dict2_parse` — every validation
branch `goto error`s directly, no cleanup); lib/dict2-parse.c:631
(`$INCLUDE` error propagation, `radcli2_priv_read_dictionary(rh, ifilename)
< 0`)
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
**Source:** lib/dict2-parse.c:754-758, 786-790 (open failures,
`radcli2_priv_read_dictionary()`/`_from_buffer()`, called by the
`rc_read_dictionary()`/`_from_buffer()` wrappers in `lib/legacy/compat.c`);
lib/dict2-parse.c:820, 869, 916 (`radcli_dict_attr_add`/`value_add`/
`vendor_add` allocation checks, behind the `lib/legacy/dict.c`
`rc_dict_add*` shim); lib/dict2-parse.c:459, 494, 507, 571, 702 (parser
allocation checks)
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
already been loaded (REQ-DICT-INIT-003). A standard attribute the named file
redeclares identically to the built-in definition is deduplicated, at no
extra cost; one it redeclares with a conflicting definition fails the whole
`rc_read_config()` call, per REQ-DICT-DATA-005 — the named file can no
longer silently override a built-in attribute's definition. If unset,
`rc_read_config()` proceeds with only the built-in dictionary loaded — this
MUST NOT be treated as an error.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:858-868
**Acceptance:** [CFG] positive, local — a config file with no `dictionary`
line still yields a working `rh` with standard attributes resolvable;
a config file with `dictionary /path/to/extra` makes both built-in and
`/path/to/extra`'s attributes resolvable, and `/path/to/extra` redeclaring a
built-in attribute identically (e.g. copying its exact `ATTRIBUTE` line) is
harmless. [ERR] negative — `/path/to/extra` redeclaring a built-in
attribute's name with a different id makes `rc_read_config()` return `NULL`.
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

- The three `[REVIEW]` items previously carried here (REQ-DICT-DATA-006's
  `rc_dict_getval()` case-sensitivity, REQ-DICT-ERR-001's pre-truncation
  length-check "dead code" claim, REQ-DICT-ERR-002's first-character-only
  numeric validation claim) do not match the current implementation, ported
  verbatim into `lib/dict2-parse.c`'s `dict2_parse()`: `rc_dict_getval()`
  compares `attrname` with `strcasecmp()` (case-insensitive, consistent with
  every sibling lookup, REQ-DICT-DATA-006's own main text); every
  `ATTRIBUTE`/`VALUE`/`VENDOR` length check runs against the original
  `strtok_r()` token before any truncating `strlcpy()`, exactly as
  REQ-DICT-ERR-001's main text and REQ-DICT-INIT-005 already describe; and
  `is_unsigned_decimal()` (`lib/dict2-parse.c`) rejects on the first
  non-digit character anywhere in the
  token, not just the first character, matching REQ-DICT-ERR-002's own main
  text. Resolved as stale flags, not as changes made in the dict2 rewrite.
- `REQ-DICT-DATA-010`/`-012` are `WITHDRAWN` (superseded by `dict2.md`'s
  `REQ-DICT2-DATA-007`/`-008`) as part of splitting this document down to
  the legacy `rc_*` API and its dictionary-file substrate — see this
  document's "Legacy vs. `radcli2.h`" note near the top.
- `[UNDOCUMENTED]` gap, pre-existing and not resolved by this pass:
  `lib/dict2-parse.c` also parses `ipv4prefix` (RFC 8044 §3.9) and `text`
  (RFC 8044 §3.1) `ATTRIBUTE` type-token keywords (`PW_TYPE_MAX + 1`/`+ 2`,
  alongside the `integer64`/`ifid` sentinels `REQ-DICT2-DATA-007`/`-008`
  cover), neither of which has any `REQ-DICT-*`/`REQ-DICT2-*`/`REQ-AVP2-*`
  stating its dictionary-grammar acceptance, even though
  `RADCLI_TYPE_IPV4PREFIX`'s `radcli2.h`-side consequence is already
  documented (`REQ-AVP2-DATA-021`) and `RADCLI_TYPE_TEXT` is declared in
  `radcli2.h` but has no citing requirement anywhere. Flagged, not fixed
  here — out of scope for a legacy/`radcli2.h` document split, and the
  `RADCLI_TYPE_TEXT` gap in particular reaches into `avp2.md` as well as
  whichever of this document or `dict2.md` would state the grammar side.
- No other `[UNDOCUMENTED]` behaviors were found — every remaining parser
  branch and lookup function corresponds to a documented dictionary-file
  construct or a Doxygen-commented public function.
- No `[AMBIGUOUS]` items requiring two competing interpretations were found;
  the REVIEW items above have a single clear current behavior, just an open
  question about whether that behavior is the intended contract.
