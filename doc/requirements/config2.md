---
title: radcli2.h context/config construction requirements
generator: requirements-from-implementation
id-prefix: REQ-CONFIG2
categories:
  INIT: radcli_ctx_new/_read_config/_free construction and destruction lifecycle
  CFG: radcli_ctx_set_opt_str/_set_opt_int/_get_opt_str/_get_opt_int/_apply option grammar, validation, and readback
  DATA: radcli_ctx_read_dictionary/_read_dictionary_from_buffer and the shared radcli_opt_id/rc_option_id enum generation
  SECRET: radcli_ctx_set_secret/_set_tls_psk shared secret and TLS PSK credentials
sources:
  - lib/config2.c (radcli_ctx_new, radcli_ctx_read_config, radcli_ctx_free,
    radcli_ctx_set_opt_str, radcli_ctx_set_opt_int, radcli_ctx_get_opt_str,
    radcli_ctx_get_opt_int, radcli_ctx_apply, radcli_ctx_read_dictionary,
    radcli_ctx_read_dictionary_from_buffer, radcli_ctx_set_secret,
    radcli_ctx_set_tls_psk)
  - include/radcli/radcli2.h
  - include/radcli/radcli-defs.h
  - include/includes.h (struct rc_conf's tls_psk_identity/tls_psk_key/tls_psk_key_len)
  - lib/options.h
  - lib/radcli2.map.in
  - lib/tls.c (rc_init_tls(), cited not owned)
---

# radcli2.h Context/Config Construction Requirements

This document covers the `radcli_ctx_*` entry point in `lib/config2.c`/
`include/radcli/radcli2.h`: creating a context (`radcli_ctx_new()`,
`radcli_ctx_read_config()`), configuring it programmatically
(`radcli_ctx_set_opt_str()`, `radcli_ctx_set_opt_int()`,
`radcli_ctx_get_opt_str()`, `radcli_ctx_get_opt_int()`, `radcli_ctx_apply()`),
loading an additional dictionary (`radcli_ctx_read_dictionary()`), and
releasing it (`radcli_ctx_free()`). It is the `radcli2.h` counterpart to
`config.md` — both document the same underlying `struct rc_conf` lifecycle
and option grammar (`config.md` for the legacy `rc_new`/`rc_read_config`/
`rc_add_config` entry point, this document for the typed `radcli_ctx_*` one)
— but `radcli_ctx_*` is implemented as a thin layer directly over the
`config.md`-documented functions rather than a second parser: every
requirement below that concerns grammar/validation defers to the
corresponding `REQ-CONFIG-*` requirement instead of restating it.

This document also covers `radcli_ctx_set_secret()`/`radcli_ctx_set_tls_psk()`
(`lib/config2.c`), which set the shared secret and TLS PSK credentials
directly on a `radcli_ctx`'s configured `authserver`/`acctserver`, instead of
embedding them in the `host:port:secret`/`host:port:psk@username@hexkey`
form `RADCLI_OPT_AUTHSERVER`'s value takes for the legacy API
(`REQ-CONFIG-CFG-007`, `net.md` `REQ-NET-SEC-011`), and their config-file
counterparts — the `secret` and `tls-psk-identity`/`tls-psk-key` options
(`REQ-CONFIG2-SECRET-003`, `REQ-CONFIG2-SECRET-004`).

---

## INIT — construction and destruction

### REQ-CONFIG2-INIT-001 — `radcli_ctx_new()` MUST combine `rc_new()` and `rc_config_init()` into one call, and load the built-in dictionary unless told not to

**Requirement:** `radcli_ctx_new(flags)` MUST call `rc_new()` and then
`rc_config_init()` on the result, returning `NULL` if either fails (matching
`rc_config_init()`'s own contract of destroying the handle on failure, so no
extra cleanup is needed on the `NULL` path). The returned context has
`config_options` already populated, ready for `radcli_ctx_set_opt_str()`/
`_set_opt_int()` without a separate initialization call — a new-API caller
never needs to know `rc_config_init()` exists as a distinct step. Unless
`flags` has `RADCLI_CTX_NO_BUILTIN_DICT` set, `radcli_ctx_new()` MUST also
load the built-in RFC 2865/2866/2869 dictionary, the same one
`radcli_ctx_read_config()` always loads (`REQ-CONFIG-INIT-003`) — so
`radcli_dict_lookup_num()` is non-NULL for a well-known attribute ID
immediately after `radcli_ctx_new(0)`, with no config file and no separate
`radcli_ctx_read_dictionary()` call. An unrecognised bit in `flags` MUST be
rejected, returning `NULL`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_ctx_new()`; lib/config.c's
`radcli2_priv_load_builtin_dict()` (shared with `radcli2_priv_read_config()`)
**Acceptance:** [INIT] positive, local — `radcli_ctx_new(0)` returns
non-NULL, `radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1")`
immediately succeeds on it, and `radcli_dict_lookup_num(ctx, PW_USER_NAME, 0)`
is non-NULL. [DATA] negative — `radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT)`
returns a context for which the same lookup is `NULL`. [ERR] negative — an
unrecognised `flags` bit makes `radcli_ctx_new()` return `NULL`.
**Links:** REQ-CONFIG-INIT-002, REQ-CONFIG-INIT-003

### REQ-CONFIG2-INIT-002 — `radcli_ctx_read_config()` MUST behave like `rc_read_config()` for `flags` 0

**Requirement:** `radcli_ctx_read_config(filename, 0)` MUST behave
identically to `rc_read_config(filename)` in every respect — same grammar,
same transport initialization, same built-in-then-`dictionary=`-file
dictionary auto-load (`REQ-CONFIG-INIT-003`/`006`) — since `radcli_ctx` and
`rc_handle` are the same `struct rc_conf` (`radcli2.h`'s top-of-file design
statement) and this function passes through to the same parsing code as
`rc_read_config()`, not a reimplementation. A caller never needs to call
`radcli_ctx_read_dictionary()` separately for the file's own `dictionary=`
option. A `flags` value with `RADCLI_CTX_NO_BUILTIN_DICT` set (mirroring
`radcli_ctx_new()`'s flag, `REQ-CONFIG2-INIT-001`) MUST skip the built-in
dictionary auto-load while leaving every other behavior — grammar, transport
initialization, `dictionary=`-file auto-load — unchanged; an unrecognised
`flags` bit MUST make the call return `NULL`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_ctx_read_config()`
**Acceptance:** [INIT] positive, local — a config file with `dictionary=`
set makes both the built-in and the named file's attributes resolvable via
`radcli_dict_lookup()` immediately after `radcli_ctx_read_config()` returns,
with no further call.
**Links:** REQ-CONFIG-INIT-003, REQ-CONFIG-INIT-006

### REQ-CONFIG2-INIT-003 — `radcli_ctx_free(NULL)` MUST be a no-op, unlike `rc_destroy(NULL)`

**Requirement:** `radcli_ctx_free()` MUST check `ctx != NULL` before calling
`rc_destroy()`. This is a deliberate difference from the legacy API:
`rc_destroy(NULL)` dereferences its argument unconditionally in
`rc_dict_free()` (`struct radcli_dict *d = rh->dict;` with no prior NULL
check) and crashes — a pre-existing gap in `rc_destroy()`, not fixed here,
but not reproduced in the new API either, matching every other
`radcli_*_free()` in `radcli2.h` (`radcli_avp_list_free()`,
`radcli_request_free()`, `radcli_dae_request_free()`, `radcli_dae_free()`),
all of which document "NULL is accepted and ignored".
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_ctx_free()`; lib/dict2.c's `rc_dict_free()`
(the crash `rc_destroy(NULL)` would hit, cited for context, not changed)
**Acceptance:** [INIT] negative, local — `radcli_ctx_free(NULL)` returns
without crashing.

---

## CFG — option grammar and validation

### REQ-CONFIG2-CFG-001 — `radcli_opt_id` MUST share its ordinal position with `rc_option_id`, both generated from `RC_OPTION_TABLE`

**Requirement:** `radcli-defs.h`'s `RC_OPTION_TABLE` X-macro list MUST be
the single source both `lib/options.h`'s internal `rc_option_id` enum and
`radcli2.h`'s public `radcli_opt_id` enum are generated from, in the same
order, so `(rc_option_id)opt` and the corresponding `radcli_opt_id` always
index the same slot in a `struct rc_conf`'s `config_options[]` array. This
is what lets `radcli_ctx_set_opt_str()`/`_set_opt_int()` reach the option's
name (and therefore `rc_add_config()`'s existing grammar) via a simple array
index instead of a second name-to-id mapping table that could drift from
the first.
**Strength:** MUST
**Status:** DERIVED
**Source:** include/radcli/radcli-defs.h; lib/options.h's `rc_option_id`
generation; include/radcli/radcli2.h's `radcli_opt_id` generation
**Acceptance:** [CFG] positive, local — for every option in
`RC_OPTION_TABLE`, `radcli_ctx_set_opt_str(ctx, RADCLI_OPT_X, v)` followed by
`rc_conf_str(ctx, "x")` (the same option's legacy string name) returns `v`.
**Links:** REQ-CONFIG-CFG-016

### REQ-CONFIG2-CFG-002 — `radcli_ctx_set_opt_str()`/`_set_opt_int()` MUST reject a type mismatch instead of forwarding it to the wrong setter

**Requirement:** `radcli_ctx_set_opt_str()` MUST return `-1` without calling
`rc_add_config()` if `opt`'s `RC_OPTION_TABLE` type is not `OT_STR` or
`OT_SRV`; `radcli_ctx_set_opt_int()` MUST return `-1` if `opt`'s type is not
`OT_INT`. Both MUST also return `-1` (not crash) for a `NULL` `ctx`, a `ctx`
whose `config_options` is not yet allocated, or an `opt` value `>=
RADCLI_OPT_COUNT`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_opt_lookup()`,
`radcli_ctx_set_opt_str()`/`_set_opt_int()`
**Acceptance:** [CFG] negative, local — `radcli_ctx_set_opt_str(ctx,
RADCLI_OPT_RADIUS_TIMEOUT, "5")` (an `OT_INT` option) returns `-1`;
`radcli_ctx_set_opt_int(ctx, RADCLI_OPT_DICTIONARY, 1)` (an `OT_STR` option)
returns `-1`; `radcli_ctx_set_opt_str(NULL, RADCLI_OPT_AUTHSERVER, "x")` and
`radcli_ctx_set_opt_str(ctx, (radcli_opt_id)RADCLI_OPT_COUNT, "x")` both
return `-1` without crashing.

### REQ-CONFIG2-CFG-003 — a value accepted by `radcli_ctx_set_opt_str()`/`_set_opt_int()` MUST parse exactly as `rc_add_config()` would parse the same name/value

**Requirement:** Once `radcli_ctx_set_opt_str()`/`_set_opt_int()` pass their
own type check and the already-set/single-server checks
(`REQ-CONFIG2-CFG-005`), they MUST hand the option's name (from
`config_options[opt].name`) and value straight to `rc_add_config()` — for
`_set_opt_int()`, the `long` value is first formatted with `%ld` into a
string, so an `OT_SRV` option like `authserver` gets `set_option_srv()`'s
full `host[:port:secret]` grammar for a *single* host (`REQ-CONFIG-CFG-007`)
exactly as `rc_add_config(ctx, "authserver", val, ...)` would give it, not a
reimplementation. This includes value-range validation, not just grammar:
`RADCLI_OPT_WATCHDOG_INTERVAL` rejecting 1-5 is `set_option_int()`'s own
check (`REQ-WATCHDOG-CFG-001`), inherited here rather than restated.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_ctx_set_opt_str()`/`_set_opt_int()`
**Acceptance:** [CFG] positive, local — `radcli_ctx_set_opt_str(ctx,
RADCLI_OPT_AUTHSERVER, "127.0.0.1:1812:secret")` followed by
`radcli_ctx_apply()` and a request against that context reaches
`127.0.0.1:1812` using `secret`, matching what the equivalent
`rc_add_config()` call would produce. [CFG] negative, local —
`radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 5)` fails the
same way `rc_add_config(ctx, "watchdog-interval", "5", ...)` would
(`tests/watchdog-aaa.c`'s phase 2, see `REQ-WATCHDOG-CFG-001`).
**Links:** REQ-CONFIG-CFG-007, REQ-CONFIG-CFG-009, REQ-WATCHDOG-CFG-001

### REQ-CONFIG2-CFG-004 — `radcli_ctx_apply()` MUST be a direct alias for `rc_apply_config()`

**Requirement:** `radcli_ctx_apply(ctx)` MUST behave identically to
`rc_apply_config(ctx)` — same `serv-type` transport selection
(`REQ-CONFIG-INIT-004`), same `nas-ip` validation, same TLS/DTLS
initialization.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_ctx_apply()`
**Acceptance:** [CFG] positive, local — a context configured with
`RADCLI_OPT_AUTHSERVER`, `RADCLI_OPT_RADIUS_TIMEOUT`, and
`RADCLI_OPT_RADIUS_RETRIES` set, then `radcli_ctx_apply()`d, is usable by
`radcli_request_new()` exactly as a `rc_read_config()`-produced handle is by
`rc_auth()`.

### REQ-CONFIG2-CFG-005 — `radcli_ctx_set_opt_str()`/`_set_opt_int()` MUST reject setting an already-set option again, and MUST limit server options to exactly one server

**Requirement:** `radcli_ctx_set_opt_str()`/`_set_opt_int()` MUST return
`-1` without any effect if the target option is already set —
`option->val != NULL` for `OT_STR`/`OT_INT`, or (since `rc_config_init()`
pre-allocates an empty `SERVER` struct for `authserver`/`acctserver`)
`((SERVER *)option->val)->max > 0` for `OT_SRV`. For an `OT_SRV` option,
`radcli_ctx_set_opt_str()` MUST additionally reject, in a single call, any
value containing a `,` or whitespace character (the separators
`set_option_srv()` itself splits a value on) — so `RADCLI_OPT_AUTHSERVER`/
`RADCLI_OPT_ACCTSERVER` can end up naming at most one server, never a
failover list, matching the new API's one-server-per-context design
(`radcli_request_new()`, `REQ-NET2-INIT-003`). This is a deliberate
strengthening over `rc_add_config()`/`rc_read_config()`, whose equivalent
"duplicate option" check (`option->status != ST_UNDEF`) is unreachable dead
code today: nothing in `lib/config.c` ever sets `status` away from
`ST_UNDEF`, so a config file or a sequence of `rc_add_config()` calls
silently keeps the *last* value for `OT_STR`/`OT_INT` (leaking the earlier
allocation) and *accumulates* every repeated `authserver`/`acctserver` into
one list for `OT_SRV`. That legacy behavior is unchanged — this requirement
applies to `radcli_ctx_set_opt_str()`/`_set_opt_int()` only, **not** to
`radcli_ctx_read_config()`, which remains a direct alias of
`rc_read_config()` (`REQ-CONFIG2-INIT-002`) and keeps the legacy
accumulate/last-wins behavior for a config file loaded through it.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c's `radcli_opt_already_set()`,
`radcli_ctx_set_opt_str()`/`_set_opt_int()`
**Acceptance:** [CFG] negative, local — `radcli_ctx_set_opt_int(ctx,
RADCLI_OPT_RADIUS_TIMEOUT, 5)` followed by `radcli_ctx_set_opt_int(ctx,
RADCLI_OPT_RADIUS_TIMEOUT, 6)` returns `-1` from the second call, and
`rc_conf_int(ctx, "radius_timeout")` still reads `5`; a single
`radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1")`
followed by a second `radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER,
"127.0.0.2:1")` returns `-1` from the second call and leaves
`rc_conf_srv(ctx, "authserver")->max == 1`; a single
`radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER,
"127.0.0.1:1,127.0.0.2:1")` call returns `-1` and leaves the option unset,
so a subsequent single-host call still succeeds. [CFG] positive — a config
file with two `authserver` lines loaded via `radcli_ctx_read_config()`
still succeeds, with `rc_conf_srv(ctx, "authserver")->max == 2`, same as
`rc_read_config()` would produce.
**Links:** REQ-NET2-INIT-003, REQ-CONFIG-CFG-003, REQ-CONFIG2-INIT-002

### REQ-CONFIG2-CFG-006 — `radcli_ctx_get_opt_str()`/`_get_opt_int()` MUST read back the value set by the matching typed setter, and reject a type mismatch or unset option instead of crashing

**Requirement:** `radcli_ctx_get_opt_str(ctx, opt)` MUST return the option's
currently stored string value (the same characters most recently accepted by
`radcli_ctx_set_opt_str()` for that `opt`, or `radcli_ctx_read_config()`/
`rc_add_config()` if set that way instead), and MUST return `NULL` if `opt`'s
`RC_OPTION_TABLE` type is not `OT_STR`, or if the option has not been set yet
(`o->val == NULL`). It MUST NOT dereference `ctx`/`opt` before validating them
— an out-of-range `opt` or a `ctx` `radcli_opt_lookup()` cannot resolve MUST
also return `NULL`, mirroring `radcli_ctx_set_opt_str()`'s own `NULL`/
out-of-range handling (`REQ-CONFIG2-CFG-002`). `radcli_ctx_get_opt_int(ctx,
opt, out)` MUST behave the same way for an `OT_INT` option, writing the
stored `long` value to `*out` and returning `0` on success, and returning
`-1` without touching `*out` for a type mismatch, an unset option, a `NULL`
`out`, or an out-of-range `opt`. Neither getter has a distinct return value
for "unset" versus "wrong type" versus "out of range" — same coarse-grained
failure shape as the setters, since a caller checking a getter's result
already knows which `opt` it asked for.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c:175-193 (`radcli_ctx_get_opt_str()`,
`radcli_ctx_get_opt_int()`)
**Acceptance:** [CFG] positive, local — `tests/ctx.c`: `radcli_ctx_get_opt_str()`
round-trips a value set via `radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DICTIONARY,
...)`; `radcli_ctx_get_opt_int()` round-trips a value set via
`radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5)` through its `long
*out` parameter. [ERR] negative, local — `tests/ctx.c` confirms both getters
return their failure value for an unset option, a type-mismatched option
(`_get_opt_str()` against an `OT_INT`/`OT_SRV` option, `_get_opt_int()`
against an `OT_STR`/`OT_SRV` option), a `NULL` `out` (`_get_opt_int()`), and
an out-of-range `opt` (`(radcli_opt_id)RADCLI_OPT_COUNT`), without crashing.
[CFG] positive, local — `tests/ctx.c`: for an option `radcli2_priv_apply_config()`
materializes a default into (`watchdog-interval`, `REQ-CONFIG-CFG-021`),
`radcli_ctx_get_opt_int()` reports it unset before `radcli_ctx_apply()` and
reports the default afterward — the getter has no default-substitution logic
of its own, it simply reads whatever the table holds by that point.
**Links:** REQ-CONFIG2-CFG-002, REQ-CONFIG-CFG-021

---

## DATA — supplemental dictionary loading

### REQ-CONFIG2-DATA-001 — `radcli_ctx_read_dictionary()` MUST be a direct alias for `rc_read_dictionary()`

**Requirement:** `radcli_ctx_read_dictionary(ctx, path)` MUST behave
identically to `rc_read_dictionary(ctx, path)`, including the
same-filename-twice no-op guard (`REQ-DICT-INIT-001`) and the
dedup-or-conflict-error semantics for a redefinition of an already-loaded
attribute (`REQ-DICT-DATA-005`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_ctx_read_dictionary()`
**Acceptance:** [DATA] positive, local — `radcli_ctx_read_dictionary(ctx,
path)` followed by `radcli_dict_lookup()` finds an attribute the named file
defines. [ERR] negative — the same file loaded a second time via a
conflicting redefinition fails, per `REQ-DICT-DATA-005`.
**Links:** REQ-DICT-INIT-001, REQ-DICT-DATA-005

### REQ-CONFIG2-DATA-002 — `radcli_ctx_read_dictionary_from_buffer()` MUST be a direct alias for `rc_read_dictionary_from_buffer()`

**Requirement:** `radcli_ctx_read_dictionary_from_buffer(ctx, buf, size)`
MUST behave identically to `rc_read_dictionary_from_buffer(ctx, buf, size)`
-- the from-buffer counterpart to `radcli_ctx_read_dictionary()`
(`REQ-CONFIG2-DATA-001`), so a `radcli2.h`-only caller with dictionary text
already in memory is not forced to reach into `radcli.h` for this one
operation (`REQ-GEN-TEST-006`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_ctx_read_dictionary_from_buffer()`
**Acceptance:** [DATA] positive, local — `radcli_ctx_read_dictionary_from_buffer(ctx,
buf, size)` followed by `radcli_dict_lookup()` finds an attribute the buffer
defines (`tests/ctx.c`).
**Links:** REQ-CONFIG2-DATA-001, REQ-GEN-TEST-006

---

## SECRET — shared secret and TLS PSK

### REQ-CONFIG2-SECRET-001 — `radcli_ctx_set_secret()` MUST set the first server-list entry's secret for each target in `target_mask`, requiring that server type to already be configured

**Requirement:** `radcli_ctx_set_secret(ctx, target_mask, secret)` MUST, for
each of `RADCLI_SECRET_AUTH`/`RADCLI_SECRET_ACCT` present in `target_mask`,
overwrite `SERVER->secret[0]` of the `authserver`/`acctserver` list
(`rc_conf_srv()`) — index 0 specifically, matching the new API's
single-server-per-context design (`REQ-NET2-INIT-003`). It MUST fail (`-1`,
no partial effect for that target) if the corresponding server list has no
entry yet (`serv->max == 0` — `RADCLI_OPT_AUTHSERVER`/`_ACCTSERVER` not yet
set via `radcli_ctx_set_opt_str()` or a config file). `target_mask` of `0`
or carrying any bit outside `RADCLI_SECRET_AUTH|RADCLI_SECRET_ACCT` MUST be
rejected before touching either server. Passing both bits — the common
single-secret-for-both case — sets both in the one call, unlike the legacy
API's `authserver`/`acctserver` lines, which each need their own inline
secret.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_set_one_secret()`, `radcli_ctx_set_secret()`
**Acceptance:** [SECRET] positive, local — with both `authserver` and
`acctserver` configured, `radcli_ctx_set_secret(ctx, RADCLI_SECRET_AUTH |
RADCLI_SECRET_ACCT, "shared")` makes both `rc_conf_srv(ctx,
"authserver")->secret[0]` and `rc_conf_srv(ctx, "acctserver")->secret[0]`
equal `"shared"`. [ERR] negative — called before `authserver` is configured,
with `RADCLI_SECRET_AUTH` set, returns `-1`.
**Links:** REQ-CONFIG-CFG-018, REQ-NET2-INIT-003

### REQ-CONFIG2-SECRET-002 — `radcli_ctx_set_tls_psk()` MUST take identity and key as independent byte buffers, and `radcli_ctx_apply()`'s TLS/DTLS setup MUST prefer them over any `psk@username@hexkey` string

**Requirement:** `radcli_ctx_set_tls_psk(ctx, identity, identity_len, key,
keylen)` MUST copy `identity` into a heap-allocated, NUL-terminated buffer
(`ctx->tls_psk_identity`) and `key` into a heap-allocated buffer of exactly
`keylen` bytes (`ctx->tls_psk_key`/`tls_psk_key_len`) — neither derived from
nor written into `SERVER->secret[]`. `rc_init_tls()` (`lib/tls.c`) MUST
check `rh->tls_psk_key != NULL` before falling back to parsing
`authservers->secret[0]` as `"psk@username@hexkey"`; when set, it MUST call
`gnutls_psk_set_client_credentials()` with `GNUTLS_PSK_KEY_RAW` and the
stored bytes directly, performing no string parsing (no `psk@` prefix
check, no splitting on `@`) at all. This is what lets an identity
containing `@`, or a key that is not (or cannot safely be) hex-text, be
configured — both impossible to represent unambiguously via the legacy
inline form (`lib/tls.c`'s `rc_init_tls()`, legacy branch: splitting
`psk@username@hexkey` on the first `@` after the prefix misparses a
`username` that itself contains `@`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config2.c's `radcli_ctx_set_tls_psk()`; lib/tls.c's
`rc_init_tls()`, the `rh->tls_psk_key != NULL` branch (`psk_done` label)
**Acceptance:** [SECRET] positive, local — a context with `serv-type=tls`,
`authserver` set (any reachable-or-not host:port, since the TLS handshake is
deferred to first send), and `radcli_ctx_set_tls_psk()` called with an
identity containing `@` and a key containing an embedded `0x00` byte, then
`radcli_ctx_apply()` succeeds (the GnuTLS PSK credential is accepted).
**Links:** REQ-CONFIG2-SECRET-001

### REQ-CONFIG2-SECRET-003 — the `secret` config option MUST set `authserver`/`acctserver`'s secret only when not already set inline

**Requirement:** The `secret` option (`RADCLI_OPT_SECRET`, `RC_OPTION_TABLE`)
is the config-file counterpart of `radcli_ctx_set_secret(ctx,
RADCLI_SECRET_AUTH|RADCLI_SECRET_ACCT, secret)`: when set,
`radcli2_priv_apply_config()` (`lib/config.c`, called by both
`radcli_ctx_apply()` and `radcli_ctx_read_config()`/`rc_read_config()`) MUST
copy it into `SERVER->secret[0]` of `authserver` and/or `acctserver`, but
*only* for a server list that is configured (`max > 0`) and whose
`secret[0]` is not already set — an inline `host:port:secret` value always
takes priority, the same way the legacy `servers` file already only applies
"when the secret is not specified inline" (`REQ-CONFIG-CFG-007`). Unlike
`radcli_ctx_set_secret()`, this option MUST NOT overwrite an already-set
`secret[0]` (there is no call-order to rely on for a config-file line, so
the more specific per-server form wins instead). Note that `secret[0]` set
this way, like an inline `:secret`, is inert when `serv-type` is `tls`/
`dtls`: `rc_find_server_addr()` never needs it there
(`REQ-CONFIG-CFG-019`), and `radcli_transport_exchange()` always overwrites
it with the RFC 6614/7360 fixed secret before it would ever be used
(`net.md` `REQ-NET-SEC-011`) — so the `secret` option, like the legacy
inline form, has no effect under TLS/DTLS.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c's `apply_secret_fallback()`/`apply_secret_fallback_one()`
**Acceptance:** [SECRET] positive, local — a config (or
`radcli_ctx_set_opt_str()` sequence) with `authserver`/`acctserver` set
(no inline secret) and `secret` set, followed by `radcli_ctx_apply()`,
leaves both `rc_conf_srv(ctx, "authserver")->secret[0]` and
`rc_conf_srv(ctx, "acctserver")->secret[0]` equal to `secret`'s value.
[SECRET] negative — an `authserver` with an inline `host:port:secret2`
plus a `secret` option keeps `secret[0]` equal to `secret2` after apply.
[SECRET] positive, local — under `serv-type tls`, an `authserver` with
neither an inline secret nor a `secret` option still resolves successfully
via `rc_find_server_addr()` (`REQ-CONFIG-CFG-019`'s acceptance test).
**Links:** REQ-CONFIG2-SECRET-001, REQ-CONFIG-CFG-007, REQ-CONFIG-CFG-019

### REQ-CONFIG2-SECRET-004 — the `tls-psk-identity`/`tls-psk-key` config options MUST supply TLS PSK credentials as two independent values, ranked below `radcli_ctx_set_tls_psk()` and above the embedded `psk@username@hexkey` form

**Requirement:** `tls-psk-identity` (plain text) and `tls-psk-key` (hex
text) are the config-file counterpart of `radcli_ctx_set_tls_psk()`: when
both are set, `rc_init_tls()` (`lib/tls.c`) MUST call
`gnutls_psk_set_client_credentials()` with `GNUTLS_PSK_KEY_HEX` and these
two config strings directly — no hex-decoding performed by radcli itself.
This tier MUST be checked after `rh->tls_psk_key != NULL` (set via
`radcli_ctx_set_tls_psk()`, which always wins if both are somehow set) and
before falling back to parsing `authservers->secret[0]` as
`psk@username@hexkey`. Setting only one of the two options MUST be
rejected (`rc_init_tls()` returns `-1`) rather than silently ignored.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c's `rc_init_tls()`, the `tls-psk-identity`/
`tls-psk-key` tier between the `rh->tls_psk_key != NULL` block and the
`psk@` parsing fallback
**Acceptance:** [SECRET] positive, local — a context with `serv-type=tls`,
`authserver` set, and `tls-psk-identity`/`tls-psk-key` (hex) set via
`radcli_ctx_set_opt_str()` (no `radcli_ctx_set_tls_psk()` call), then
`radcli_ctx_apply()` succeeds. [ERR] negative — only `tls-psk-identity` set
(no `tls-psk-key`) makes `radcli_ctx_apply()` fail.
**Links:** REQ-CONFIG2-SECRET-002

### REQ-CONFIG2-SECRET-005 — the inline `host:port:secret`/`host:port:psk@username@hexkey` form of `authserver`/`acctserver`, and the `servers`/`servers-tls` credentials files, MUST remain parseable, but MUST NOT be presented in the shipped example configs as the documented way to set a secret or PSK

**Requirement:** `set_option_srv()`'s `host[:port[:secret]]` grammar
(`REQ-CONFIG-CFG-007`), including the `psk@username@hexkey` convention
`rc_init_tls()` parses out of it (`net.md` `REQ-NET-SEC-011`), and the
`servers` credentials-file fallback (`REQ-CONFIG-CFG-018`) MUST continue to
be accepted by `rc_read_config()`/`radcli_ctx_read_config()` unchanged —
existing config files that embed a secret or PSK inline in `authserver`/
`acctserver`, or that point `servers`/`servers-tls` at a hostname-to-secret
mapping file, MUST NOT break. However, `etc/radiusclient.conf.in` and
`etc/radiusclient-tls.conf.in` (the shipped example configs, install
targets for `@pkgsysconfdir@/radiusclient.conf`/`radiusclient-tls.conf`)
MUST document `authserver`/`acctserver` using only the `host[:port]` form,
MUST NOT show `:secret` or `:psk@username@hexkey` in their examples, and
MUST NOT set or document `servers`/`servers-tls` as an active default. The
`secret` (`REQ-CONFIG2-SECRET-003`) and `tls-psk-identity`/`tls-psk-key`
(`REQ-CONFIG2-SECRET-004`) options are the only documented way to configure
a secret or PSK from a config file; the inline suffix form and the
`servers`/`servers-tls` files are retained solely so a config file carried
over from an older radcli, radiusclient-ng, or freeradius-client install
keeps working, not as alternatives a new config file should be written to
use.
**Strength:** MUST
**Status:** DERIVED
**Source:** etc/radiusclient.conf.in, etc/radiusclient-tls.conf.in
(`authserver`/`acctserver`/`secret`/`tls-psk-identity`/`tls-psk-key`
comments, no `servers`/`servers-tls` line); tests/example-config-tests.sh
(enforces the above); lib/config.c's `set_option_srv()` (cited not owned,
see `REQ-CONFIG-CFG-007`) and `radcli2_priv_find_server_addr()`'s
`servers`-file fallback (cited not owned, see `REQ-CONFIG-CFG-018`)
**Acceptance:** [SECRET] positive, local — a config file using only
`authserver host[:port]` plus `secret`/`tls-psk-identity`/`tls-psk-key`
loads and applies successfully (covered by `REQ-CONFIG2-SECRET-003`/`-004`'s
acceptance tests). [SECRET] negative, local — `tests/example-config-tests.sh`
greps both shipped `.conf.in` files and fails the build if either documents
`authserver`/`acctserver` with an inline `:secret` directive, mentions
`psk@`, or sets `servers`/`servers-tls` as an active option. [SECRET]
regression, local — a
config file using the legacy `authserver host:port:secret` inline form (no
`secret` option present) still loads and `rc_conf_srv(ctx,
"authserver")->secret[0]` equals `"secret"` (`REQ-CONFIG-CFG-007`'s existing
acceptance test, unchanged); a config file using a `servers` file (no
inline secret, no `secret` option) still resolves the secret from it
(`REQ-CONFIG-CFG-018`'s existing acceptance test, unchanged).
**Links:** REQ-CONFIG-CFG-007, REQ-CONFIG-CFG-018, REQ-NET-SEC-011,
REQ-CONFIG2-SECRET-003, REQ-CONFIG2-SECRET-004
