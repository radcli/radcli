---
title: configuration loading and handle lifecycle requirements
generator: requirements-from-implementation
id-prefix: REQ-CONFIG
categories:
  INIT: handle allocation, transport initialisation, and teardown lifecycle
  CFG: configuration file/option grammar and semantics
  SEC: security-relevant defects and boundaries in config handling
  ERR: error handling and failure-path behavior
  DATA: option storage, ownership, and lifetime
sources:
  - lib/config.c
  - lib/options.h
  - include/radcli/radcli.h
  - lib/radcli.map.in
  - lib/ip_util.c (rc_own_bind_addr, referenced from rc_apply_config)
  - etc/radiusclient.conf
  - etc/radiusclient-tls.conf
---

# Configuration Loading and Handle Lifecycle Requirements

This document covers `lib/config.c`: the `rc_handle` allocation/teardown lifecycle
(`rc_new`, `rc_destroy`), the config-file and programmatic option grammar
(`rc_read_config`, `rc_add_config`, `rc_config_init`, `rc_apply_config`,
`rc_test_config`), typed option accessors (`rc_conf_str`, `rc_conf_int`,
`rc_conf_srv`), server/secret resolution (`rc_find_server_addr`), and
`rc_config_free`/`rc_get_socket_type`. It explicitly excludes: dictionary file
*parsing* itself (triggered from `rc_read_config` via `rc_read_dictionary` /
`rc_read_dictionary_from_buffer`, but the grammar and attribute table belong to
`dict.md`, not yet generated); TLS/DTLS handshake and PSK-credential parsing
(`rc_init_tls` in `lib/tls.c` — `net.md`, not yet generated) — config.c only
registers and stores the `tls-*`/`require-message-authenticator` option
*strings*, it does not interpret them; and socket I/O itself (`plain_sendto`
etc. are trivial wrappers assigned into `rh->so`, covered by `net.md`). Two
requirements below (`REQ-CONFIG-SEC-001`, `REQ-CONFIG-SEC-002`) document
apparent memory-safety and logic defects found while tracing `set_option_srv`
and `rc_find_server_addr`; per the protocol these are recorded as `[REVIEW]`,
not silently "fixed" or omitted.

All twelve public symbols declared under `/* config.c */` in
`include/radcli/radcli.h:698-715` (`rc_add_config`, `rc_config_init`,
`rc_read_config`, `rc_conf_str`, `rc_conf_int`, `rc_conf_srv`,
`rc_test_config`, `rc_apply_config`, `rc_find_server_addr`, `rc_config_free`,
`rc_new`, `rc_destroy`, `rc_get_socket_type` — thirteen counting both) are
present verbatim under the `RADCLI_@LIBMAJOR@` node in `lib/radcli.map.in`
lines 32-43 and 71; see `REQ-GEN-ABI-001`.

---

## INIT — handle allocation, transport initialisation, and teardown

### REQ-CONFIG-INIT-001 — `rc_new()` MUST perform process-wide crypto/RNG init exactly once, gated by a reference count

**Requirement:** `rc_new()` MUST allocate and zero-initialise a new `rc_handle`
via `calloc()`, and MUST perform the one-time process setup (`gnutls_global_init()`
on GnuTLS < 3.3.0, and seeding `srandom()` from `time()+getpid()`) only when the
internal reference counter `_initialized` is `0`, incrementing it on every call
regardless. `rc_destroy()` MUST decrement the same counter and call
`gnutls_global_deinit()` only when it reaches `0` again.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:1182 (`_initialized`), lib/config.c:1188-1213 (`rc_new`),
lib/config.c:1219-1234 (`rc_destroy`)
**Acceptance:** [INIT] unit, local — creating and destroying two `rc_handle`s
sequentially calls `gnutls_global_init`/`gnutls_global_deinit` at most once each
(observable only on GnuTLS < 3.3.0 builds); `srandom()` reseeded on the first
`rc_new()` of the process only.
**Links:** REQ-GEN-SEC-005 (process-wide state) — `_initialized` is itself a
`static` file-scope mutable counter distinct from the `radcli_debug` exception
that `REQ-GEN-SEC-005` names as the *sole* accepted exception; see
`REQ-CONFIG-SEC-004` below for the discrepancy this raises.

### REQ-CONFIG-INIT-002 — `rc_config_init()` MUST prepare a handle for programmatic (file-less) configuration

**Requirement:** Given an `rh` from `rc_new()`, `rc_config_init()` MUST allocate
and populate `rh->config_options` from `config_options_default`, and MUST
pre-allocate zeroed `SERVER` structures for the `authserver` and `acctserver`
options so that subsequent `rc_add_config()` calls populate them. On any
allocation failure it MUST call `rc_destroy(rh)` and return `NULL`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:374-414
**Acceptance:** [INIT] positive, local — `rc_config_init(rc_new())` followed by
`rc_add_config(rh, "authserver", "host:1812:secret", ...)` succeeds without a
config file; [INIT] negative — a forced `calloc` failure path calls
`rc_destroy` and returns `NULL` (code inspection; not practically triggerable
without fault injection).
**Links:** REQ-CONFIG-CFG-009

### REQ-CONFIG-INIT-003 — `rc_read_config()` MUST parse the file, validate it, initialise the transport, and load dictionaries in one call

**Requirement:** `rc_read_config(filename)` MUST, in order: (1) allocate a
handle via `rc_new()` and its option table; (2) open `filename` read-only and
parse every non-blank, non-comment line as `name value`; (3) call
`rc_test_config()`, which validates mandatory options and calls
`rc_apply_config()` to initialise the transport; (4) apply `clientdebug` to the
global debug level; (5) load the built-in RFC dictionary, then the optional
`dictionary` file. Any failure at any step MUST close the file handle (if
open), destroy the partially-built `rh`, and return `NULL` — never a
partially-initialised handle.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:644-783
**Acceptance:** [INIT] positive, local — `rc_read_config("etc/radiusclient.conf")`
against a syntactically valid file with a reachable `authserver` returns a
non-NULL handle with `rc_get_socket_type() == RC_SOCKET_UDP` by default;
[INIT] negative — a nonexistent path or a file missing `authserver` returns
`NULL` (`lib/config.c:666-671`, `lib/config.c:876-878`).
**Links:** REQ-CONFIG-INIT-004, REQ-CONFIG-INIT-006, REQ-CONFIG-ERR-001

### REQ-CONFIG-INIT-004 — `rc_apply_config()` MUST select and initialise exactly one transport from `serv-type`

**Requirement:** `rc_apply_config()` MUST read `serv-type` (falling back to the
legacy alias `serv-auth-type`, then to `"udp"` if neither is set) and MUST
initialise `rh->so`/`rh->so_type` for exactly one of: `udp` (default UDP
socket ops), `tcp` (connect-then-send TCP socket ops), `tls` or `dtls` (via
`rc_init_tls()`, only when built `HAVE_GNUTLS`). Any other value MUST cause
`rc_apply_config()` to log `LOG_CRIT` and return `-1` without partially setting
`rh->so`. It MUST also resolve and cache `rh->own_bind_addr` (from `bindaddr`)
and, if `nas-ip` is set, validate and cache `rh->nas_addr`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:545-597 (transport dispatch lines 569-588);
lib/config.c:550-560 (bind/nas-ip)
**Acceptance:** [INIT] positive, local — `serv-type udp/tcp` selects
`RC_SOCKET_UDP`/`RC_SOCKET_TCP` (`rc_get_socket_type()`); [INIT] negative,
local — `serv-type bogus` makes `rc_apply_config()` return `-1` (`lib/config.c:585-587`).
**Links:** REQ-CONFIG-CFG-012, REQ-CONFIG-CFG-013

### REQ-CONFIG-INIT-005 — `rc_destroy()` MUST release dictionary, TLS, and config state in that order before freeing the handle

**Requirement:** `rc_destroy(rh)` MUST call, in order, `rc_dict_free(rh)`,
`rc_deinit_tls(rh)` (when `HAVE_GNUTLS`), `rc_config_free(rh)`, and finally
`free(rh)`. `rc_destroy(NULL)` MUST NOT be assumed safe by callers unless the
called functions handle `NULL` (not verified here; see `dict.md`/`net.md` for
`rc_dict_free`/`rc_deinit_tls` NULL-handling). Every `rc_new()`-produced handle
that a caller stops using MUST eventually reach `rc_destroy()` exactly once —
double-destroy or leaked handles are caller bugs this API cannot detect.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:1219-1234
**Acceptance:** [INIT] positive, local — after `rc_destroy(rh)`,
`rh->config_options` and `rh->first_dict_read` are `NULL`'d by
`rc_config_free()` (observable via a debug build reading freed-then-nulled
fields is unsafe to assert directly; verify via ASan-clean run of `rc_destroy`
under `tests/`).
**Links:** REQ-CONFIG-DATA-001, REQ-GEN-MEM-003

### REQ-CONFIG-INIT-006 — `rc_read_config()` MUST load the built-in RFC 2865/2866/2869 dictionary before any user dictionary

**Requirement:** `rc_read_config()` MUST call
`rc_read_dictionary_from_buffer(rh, rc_rfc_dictionary, ...)` unconditionally,
before consulting the `dictionary` option, so that standard attributes are
always available even when no `dictionary` file is configured. If the
built-in load fails, `rc_read_config()` MUST fail (destroy `rh`, return
`NULL`) without attempting the user dictionary.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:764-780
**Acceptance:** [INIT] positive, local — `rc_read_config()` on a config file
with no `dictionary` line still resolves standard attribute names (e.g.
`User-Name`) via `rc_dict_findattr`. See `dict.md` (not yet generated) for the
dictionary grammar itself.
**Links:** REQ-CONFIG-CFG-015

---

## CFG — configuration file/option grammar and semantics

### REQ-CONFIG-CFG-001 — Each config-file line MUST be `<name><whitespace><value>`; blank and `#`-comment lines are skipped

**Requirement:** `rc_read_config()`'s line loop MUST skip a line whose first
character is `\n`, `#`, or `\0`, and otherwise MUST require the option name (up
to the first run of tab/space) to be followed by a value; a line with no
whitespace separator (`strcspn(p, "\t ") == 0`, i.e. the *first* character is
already whitespace, meaning an empty name) MUST be rejected as "bogus format"
and abort the whole load.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:674-692
**Acceptance:** [CFG] positive, local — a well-formed line like
`authserver localhost` parses; [CFG] negative — a line starting with a tab/space
(empty option name) fails the load with "bogus format" (`lib/config.c:685-690`).

### REQ-CONFIG-CFG-002 — Config lines longer than the 511-byte line buffer MUST be rejected with a clear diagnostic, not silently mis-parsed

**Requirement:** `rc_read_config()` reads each line into a fixed
`char buffer[512]` via `fgets()`. It MUST only strip the buffer's last
character when that character actually is the trailing newline `fgets()`
left in place — never unconditionally. When a physical line is ≥511 bytes,
`fgets()` returns a partial line with no trailing newline; in that case
`rc_read_config()` MUST log a "line too long" diagnostic (naming the file and
line number) and discard the remainder of that physical line up to and
including its terminating `\n` before continuing, so the remainder is never
misparsed as a bogus separate config line.
**Strength:** MUST NOT (strip a non-newline character) ; MUST (report and
resynchronize on an over-long line)
**Status:** DERIVED
**Source:** lib/config.c:647 (`buffer[512]`), lib/config.c:673-700
**Acceptance:** [CFG][ERR] negative, local — a config file containing one line
≥511 bytes causes `rc_read_config()` to log "line too long" for that line and
continue parsing the rest of the file; a config file whose last line lacks a
trailing newline parses that line's full, uncorrupted content.
**Links:** REQ-GEN-MEM-004 (bounded string handling)

### REQ-CONFIG-CFG-003 — Duplicate option definitions MUST be rejected, in both file parsing and `rc_add_config()`

**Requirement:** Before setting an option's value, both the file-parsing loop
in `rc_read_config()` and `rc_add_config()` MUST check `option->status !=
ST_UNDEF` and, if already set, log an error ("duplicate option line" /
"duplicate option") and fail the whole operation rather than silently
overwriting or accumulating (except `OT_SRV`, see `REQ-CONFIG-CFG-007`, whose
`set_option_srv()` is itself never invoked a second time for the same option
because of this very check).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:701-706 (file), lib/config.c:317-321 (`rc_add_config`)
**Acceptance:** [CFG] negative, local — a config file with `authserver` listed
twice fails to load; `rc_add_config()` called twice for the same option name
returns `-1` the second time.

### REQ-CONFIG-CFG-004 — An unrecognized option keyword MUST abort the entire config load

**Requirement:** `rc_read_config()` MUST treat any option name not present in
`config_options_default` as fatal for the whole file: it logs "unrecognized
keyword", closes the file, destroys the partially-built handle, and returns
`NULL`. There is no "skip unknown option and continue" mode.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:694-699; lib/options.h:29-64 (the recognised name
table)
**Acceptance:** [CFG] negative, local — a config file containing a misspelled
option name (e.g. `authservr`) makes `rc_read_config()` return `NULL`.

### REQ-CONFIG-CFG-005 — String option values MUST be trimmed of surrounding whitespace before storage

**Requirement:** For each config line, after the option name is isolated, the
value MUST have leading whitespace skipped and trailing whitespace stripped
(back to the last non-whitespace character) before being handed to the
type-specific setter, so `"authserver \tlocalhost  \n"` stores `"localhost"`,
not the padded string.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:708-714
**Acceptance:** [CFG] positive, local — a line with trailing spaces stores a
trimmed value (`rc_conf_str()` returns the trimmed string, no trailing
whitespace).

### REQ-CONFIG-CFG-006 — Integer option values MUST be parsed with `atoi()`; non-numeric text is silently interpreted as `0`

**Requirement:** `set_option_int()` MUST convert the value string with
`atoi()`; there is no numeric-validity check beyond requiring a non-`NULL`
value string. A malformed value like `radius_timeout abc` therefore stores
`0`, not an error, at parse time. For `radius_timeout` and `radius_retries`
specifically, `rc_test_config()` catches the resulting `0` as `<= 0` and fails
the load (`REQ-CONFIG-CFG-010`); other integer options (`clientdebug`,
`radius_deadtime`, `login_tries`, `login_timeout`) have no such downstream
check and would silently accept `0` from malformed input.
**Strength:** MUST (documents `atoi()`'s established, essential behavior — a
correct reimplementation could reasonably choose to validate instead, but
callers of the current library depend on the "malformed → 0" behavior not
erroring)
**Status:** DERIVED
**Source:** lib/config.c:90-108
**Acceptance:** [CFG] positive, local — `radius_timeout 10` yields
`rc_conf_int(rh, "radius_timeout") == 10`; [CFG] negative, local —
`clientdebug notanumber` loads successfully with `rc_conf_int(rh,
"clientdebug") == 0`.
**Links:** REQ-CONFIG-CFG-010

### REQ-CONFIG-CFG-007 — `authserver`/`acctserver` values MUST follow `host[:port[:secret]]` grammar, comma/whitespace-separated, with RFC-default port fallback

**Requirement:** `set_option_srv()` MUST accept a comma/space/tab-separated
list of server entries, each either `host`, `host:port`, `host:port:secret`,
`[ipv6]`, `[ipv6]:port`, or `[ipv6]:port:secret`. When no port is given, it
MUST resolve the default via `getservbyname("radius"/"radacct", "udp")`,
falling back to the compiled-in `PW_AUTH_UDP_PORT`/`PW_ACCT_UDP_PORT` if the
service database has no entry; the option name (`authserver` vs `acctserver`)
selects which pair is used, and any other option name reaching this code path
is a fatal "no default port" error.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:112-234 (grammar 140-212, default port 195-212)
**Acceptance:** [CFG] positive, local — `authserver host1,[::1]:1812:sec,
host2:1813` parses into three `SERVER` entries with expected
name/port/secret; [CFG] positive — `authserver localhost` (no port) resolves
to `PW_AUTH_UDP_PORT` (1812) when `/etc/services` has no `radius/udp` entry.

### REQ-CONFIG-CFG-008 — The legacy `auth_order` option MUST accept only `local`/`radius`, optionally followed by the other keyword

**Requirement:** `set_option_auo()` MUST accept a first token of exactly
`"local"` or `"radius"` (via `strncmp` on 5/6 chars) setting
`AUTH_LOCAL_FST`/`AUTH_RADIUS_FST`, and an optional second token that MUST be
the *other* keyword (`local` after `radius`, or `radius` after `local`),
setting the corresponding `_SND` flag; any other first or second token MUST
fail with "unknown keyword" / "unknown or unexpected keyword".
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:239-292
**Acceptance:** [CFG] positive, local — `auth_order radius,local` parses to
`AUTH_RADIUS_FST | AUTH_LOCAL_SND`; [CFG] negative — `auth_order radius,radius`
fails to load.

### REQ-CONFIG-CFG-009 — `rc_add_config()` MUST apply the identical per-type grammar as file parsing, for programmatic configuration

**Requirement:** `rc_add_config(rh, option_name, option_val, source, line)`
MUST look up `option_name` via `find_option(rh, option_name, OT_ANY)`,
reject an already-set option, and dispatch to the same
`set_option_str`/`set_option_int`/`set_option_srv`/`set_option_auo` helpers
used by the file parser (switched on `option->type`), so a program calling
`rc_add_config()` gets exactly the same value grammar and validation as a
config-file line.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:307-350
**Acceptance:** [CFG] positive, local — `rc_add_config(rh, "authserver",
"host:1812:sec", __FILE__, __LINE__)` populates the `SERVER` list identically
to the equivalent file line.
**Links:** REQ-CONFIG-INIT-002

### REQ-CONFIG-CFG-010 — `rc_test_config()` MUST require a non-empty `authserver` list and positive `radius_timeout`/`radius_retries` before applying the transport

**Requirement:** `rc_test_config()` MUST fail (log `LOG_ERR`, return `-1`)
if `authserver` resolves to no `SERVER` entries, if `rc_conf_int(rh,
"radius_timeout") <= 0`, or if `rc_conf_int(rh, "radius_retries") <= 0`. Only
after all three checks pass does it call `rc_apply_config()`, whose result it
also propagates as its own return value.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:869-904
**Acceptance:** [CFG] negative, local — a config file with no `authserver`
line, or `radius_timeout 0`, fails `rc_read_config()` (which calls
`rc_test_config()` internally).
**Links:** REQ-CONFIG-INIT-003, REQ-CONFIG-CFG-006

### REQ-CONFIG-CFG-011 — `rc_test_config()` MUST suppress the "no acctserver specified" debug log under TLS/DTLS

**Requirement:** `rc_test_config()`'s missing-`acctserver` branch MUST log
`LOG_DEBUG` "no acctserver specified" unless the configured transport is
TLS/DTLS. This can't be decided from `rh->so_type`, since that field is only
set by the same function's later call to `rc_apply_config()`
(`REQ-CONFIG-INIT-004`); instead, the check reads the `serv-type`/
`serv-auth-type` config string directly (the same fallback order
`rc_apply_config()` itself uses) and suppresses the log only when that
string is `"tls"` or `"dtls"` (case-insensitively).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:897-910 (check); lib/config.c:562-567
(`rc_apply_config()`'s own `serv-type`/`serv-auth-type` fallback, mirrored
here)
**Acceptance:** [CFG] negative, local — load a `serv-type tls` config with no
`acctserver`; the `LOG_DEBUG` "no acctserver specified" line is not emitted.
A `serv-type udp`/absent config with no `acctserver` still emits it.
**Links:** REQ-CONFIG-INIT-004

### REQ-CONFIG-CFG-012 — `serv-auth-type` MUST be honored as a fallback alias for `serv-type`

**Requirement:** `rc_apply_config()` MUST read `serv-type` first and, only if
unset (`NULL`), fall back to `serv-auth-type` before defaulting to `"udp"`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:562-567; lib/options.h:34 (comment: "alias for
serv-type")
**Acceptance:** [CFG] positive, local — a config file with only
`serv-auth-type tcp` (no `serv-type`) selects `RC_SOCKET_TCP`.

### REQ-CONFIG-CFG-013 — `nas-ip` MUST be a literal IPv4 or IPv6 address, validated at `rc_apply_config()` time

**Requirement:** If `nas-ip` is set, `rc_apply_config()` MUST parse it with
`inet_pton(AF_INET, ...)` and, on failure, `inet_pton(AF_INET6, ...)`; if
neither succeeds it MUST log `LOG_CRIT` "invalid IP address for nas-ip" and
`rc_apply_config()` MUST return `-1` (there is no hostname-resolution
fallback for `nas-ip`, unlike `bindaddr`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:515-527 (`set_addr`), lib/config.c:555-560
**Acceptance:** [CFG] negative, local — `nas-ip not-an-address` makes
`rc_read_config()`/`rc_apply_config()` fail; [CFG] positive — `nas-ip
10.0.0.1` and `nas-ip ::1` both succeed.

### REQ-CONFIG-CFG-014 — `clientdebug` MUST set the global debug verbosity when positive

**Requirement:** After successful validation, `rc_read_config()` MUST read
`clientdebug` via the internal non-complaining accessor and, if `> 0`, assign
it to the process-wide `radcli_debug` variable.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:757-762
**Acceptance:** [CFG] positive, local — `clientdebug 3` in the config file
results in `radcli_debug == 3` after `rc_read_config()` returns.
**Links:** REQ-GEN-SEC-005 (accepted global-state exception)

### REQ-CONFIG-CFG-015 — `dictionary` MUST name an additional attribute dictionary loaded after the built-in RFC dictionary

**Requirement:** If the `dictionary` option is set, `rc_read_config()` MUST
call `rc_read_dictionary(rh, p)` after the built-in RFC dictionary has loaded
successfully, and MUST fail the whole config load if that call fails.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:773-780
**Acceptance:** [CFG] negative, local — `dictionary /nonexistent/path` makes
`rc_read_config()` return `NULL`. See `dict.md` (not yet generated) for
dictionary file grammar.
**Links:** REQ-CONFIG-INIT-006

### REQ-CONFIG-CFG-016 — `rc_conf_str`/`rc_conf_int`/`rc_conf_srv` MUST look up an option by name *and* required type; a name/type mismatch is reported identically to an unknown name

**Requirement:** Each accessor MUST call `find_option(rh, optname, <type
mask>)`, which matches only an option whose declared `type` bitmask intersects
the requested mask (`OT_STR` for `rc_conf_str`, `OT_INT|OT_AUO` for
`rc_conf_int`, `OT_SRV` for `rc_conf_srv`). If the name exists but was
declared with a different type, `find_option()` returns `NULL` exactly as it
would for a nonexistent name, and the accessor logs `LOG_CRIT` "unknown config
option requested" — there is no distinct diagnostic for "wrong type" versus
"no such option".
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:47-61 (`find_option`), lib/config.c:791-803,
812-829, 849-861
**Acceptance:** [CFG] negative, local — `rc_conf_srv(rh, "radius_timeout")`
(an `OT_INT` option) returns `NULL` and logs "unknown config option requested"
even though `radius_timeout` is a real, recognised option name.
**Links:** REQ-CONFIG-ERR-003

### REQ-CONFIG-CFG-017 — `rc_get_socket_type()` MUST report the transport selected by the most recent `rc_apply_config()`

**Requirement:** `rc_get_socket_type(rh)` MUST return `rh->so_type` exactly as
last set by `rc_apply_config()` (`RC_SOCKET_UDP`/`TCP`/`TLS`/`DTLS`); it
performs no independent computation.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:1243-1246
**Acceptance:** [CFG] positive, local — after `rc_read_config()` with
`serv-type dtls` (GnuTLS build), `rc_get_socket_type()` returns
`RC_SOCKET_DTLS`.
**Links:** REQ-CONFIG-INIT-004

### REQ-CONFIG-CFG-018 — `rc_find_server_addr()` MUST fall back to a `servers` credentials file, matched by resolved address rather than string comparison, when no inline secret is configured

**Requirement:** If no `SERVER` entry in the in-memory `authserver`/
`acctserver` list supplies a secret for the requested name, and the `servers`
option is set, `rc_find_server_addr()` MUST open that file and, for each
`hostname secret` line (or `name1/name2 secret` paired form used to
disambiguate which side is the local NAS via `rc_is_myname()`), resolve
`hostname`/`name1`/`name2` with `rc_getaddrinfo()` and accept the line only if
one of its resolved addresses matches an address of the originally requested
`server_name` (via `find_match()`) — not by comparing the configured and
requested strings directly.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:1053-1120 (file fallback), lib/config.c:906-935
(`find_match`), lib/config.c:971-991 (`rc_is_myname`)
**Acceptance:** [CFG] positive, local — a `servers` file entry for a hostname
that resolves to the same address as the requested `server_name` (even under
a different spelling) supplies the secret. [CFG] negative — no match found in
either the inline config or the `servers` file makes `rc_find_server_addr()`
return `-1` and clear the output `secret` buffer (`lib/config.c:1121-1128`).
**Links:** REQ-CONFIG-SEC-002

---

## SEC — security-relevant defects and boundaries in config handling

### REQ-CONFIG-SEC-001 — `set_option_srv()` MUST NOT write past the `RC_SERVER_MAX`-sized `SERVER` arrays

**Requirement:** A `SERVER`'s `name[]`, `port[]`, and `secret[]` arrays are
declared `[RC_SERVER_MAX]` (`RC_SERVER_MAX` = 8, `include/radcli/radcli.h:81,
97-99`), so valid indices are `0..7`. `set_option_srv()` MUST refuse to write
a 9th entry: the loop's guard is `if (serv->max >= RC_SERVER_MAX) goto fail;`,
checked before writing at index `serv->max` and incrementing, so the 9th
comma-separated server token in a single `authserver`/`acctserver` value is
rejected instead of being written to `name[8]`/`port[8]`/`secret[8]` — one
element past the end of each 8-element array.
**Strength:** MUST NOT (write past the array)
**Status:** DERIVED
**Source:** lib/config.c:112-146 (loop and guard, guard at line 143);
lib/config.c:214-220 (writes at `serv->name[serv->max]` /
`serv->port[serv->max]` / `serv->secret[serv->max]`, increment at line 220);
include/radcli/radcli.h:81 (`RC_SERVER_MAX 8`), :97-99 (array declarations)
**Acceptance:** [SEC] negative, local, best run under ASan/Valgrind — a config
file with `authserver h1,h2,h3,h4,h5,h6,h7,h8,h9` (9 comma-separated hosts)
now fails cleanly at the 9th token ("cannot set more than 8 servers") instead
of writing past the array.
**Links:** REQ-GEN-MEM-002

### REQ-CONFIG-SEC-002 — `rc_find_server_addr()`'s in-memory secret lookup MUST use an exact-name comparison, not a length-bounded prefix comparison

**Requirement:** The secret configured for a specific `authserver`/
`acctserver` entry MUST be returned only when the requested `server_name`
exactly matches that entry's configured name: `strcmp(server_name,
servers->name[servernum]) == 0`.
**Strength:** MUST NOT (return a secret for anything other than an exact name
match)
**Status:** DERIVED
**Source:** lib/config.c:1031-1045 (`strcmp`)
**Acceptance:** [SEC] negative, local — configure `authserver
short.example,long.example.evil:1812:secretB` and call
`rc_find_server_addr(rh, "long.example", ...)`; confirm it does not match
`long.example.evil` (returns not-found rather than `secretB`).
**Links:** REQ-GEN-SEC-006 (shared-secret handling), REQ-CONFIG-CFG-018

### REQ-CONFIG-SEC-003 — TLS/DTLS and Message-Authenticator config options MUST be treated as opaque strings by config.c; interpretation is out of scope here

**Requirement:** `tls-ca-file`, `tls-cert-file`, `tls-key-file`,
`tls-verify-hostname`, and `require-message-authenticator` MUST be registered
as `OT_STR` options (`lib/options.h:37-41`) and exposed unmodified via
`rc_conf_str()`. `config.c` MUST NOT itself interpret their values (e.g. no
boolean parsing of `tls-verify-hostname`/`require-message-authenticator`
happens in this file) — that parsing is performed by `lib/tls.c:396`
(`tls-verify-hostname`) and `lib/sendserver.c:882`
(`require-message-authenticator`), which is `net.md`'s responsibility, not
`config.md`'s.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/options.h:37-41; lib/config.c doc comment lines 620-631 (lists
the options without parsing their values); grep confirms no reference to
these option names outside `lib/config.c`'s Doxygen comment and
`lib/tls.c`/`lib/sendserver.c`
**Acceptance:** [SEC] code-review — `grep -n 'tls-verify-hostname\|require-message-authenticator' lib/config.c`
shows only the Doxygen comment, no parsing logic.
**Links:** REQ-GEN-SEC-006

### REQ-CONFIG-SEC-004 — `_initialized` is an accepted exception to `REQ-GEN-SEC-005`'s "no new global state" rule

**Requirement:** `_initialized` (`static int`, `lib/config.c:1182`) is a
process-wide reference count guarding GnuTLS global init/deinit and
`srandom()` seeding idempotency across multiple `rc_handle` instances in one
process. It is an accepted, documented exception to `REQ-GEN-SEC-005`,
alongside `radcli_debug`: it has no correctness impact on any individual
`rc_handle`'s behavior (it only guards one-time process-wide init/deinit
calls) and is not a precedent for adding further arbitrary global state.
**Strength:** N/A (accepted exception, not a defect)
**Status:** DERIVED
**Source:** lib/config.c:1182 (`static int _initialized = 0;`);
doc/requirements/general.md `REQ-GEN-SEC-005`
**Acceptance:** [SEC] documentation consistency — `general.md`'s
`REQ-GEN-SEC-005` enumerates this exception explicitly alongside
`radcli_debug`.
**Links:** REQ-GEN-SEC-005, REQ-CONFIG-INIT-001

---

## ERR — error handling and failure-path behavior

### REQ-CONFIG-ERR-001 — Every failure during `rc_read_config()` MUST close the file and fully destroy the partially-built handle before returning `NULL`

**Requirement:** Every failure branch in `rc_read_config()` (open failure,
parse failure, unrecognized option, duplicate option, out-of-memory in a
setter, `rc_test_config()` failure, dictionary load failure) MUST reach
`rc_destroy(rh)` (and `fclose(configfd)` first, if the file is still open)
before returning `NULL`. No caller-visible handle is ever left half
initialised.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:666-671, 686-690, 695-699, 702-706, 719-748, 752-755,
768-771, 775-779
**Acceptance:** [ERR] negative, local, ASan-clean — every failure path listed
above, exercised individually, leaks no memory (verified by running each
failing-config-file case under `tests/` with ASan/LeakSanitizer).
**Links:** REQ-CONFIG-INIT-003, REQ-GEN-MEM-003

### REQ-CONFIG-ERR-002 — Allocation failures in option setters MUST be checked, logged at `LOG_CRIT`, and propagated as `-1`

**Requirement:** `set_option_str()`, `set_option_int()`, and `set_option_srv()`
MUST check the return of every `strdup()`/`malloc()`/`calloc()` call, log
`LOG_CRIT "... out of memory"` on failure, and return `-1` (or `goto fail` for
`set_option_srv()`, which additionally frees any `SERVER` it allocated in that
same call before returning).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:76-80, 99-102, 122-127, 131-136, 172-175, 187-191,
215-218
**Acceptance:** [ERR][MEM] code-review — every allocation in these three
functions is followed by a NULL check before use.
**Links:** REQ-GEN-MEM-002

### REQ-CONFIG-ERR-003 — Accessors on an unknown option name MUST log `LOG_CRIT` and return a safe default (`NULL`/`0`), never crash

**Requirement:** `rc_conf_str()`, `rc_conf_int()` (via `rc_conf_int_2()`), and
`rc_conf_srv()` MUST return `NULL` (string/server pointer accessors) or `0`
(integer accessor) and log `LOG_CRIT "unknown config option requested"` when
`find_option()` finds no match — including the type-mismatch case described in
`REQ-CONFIG-CFG-016`. `rc_conf_int()` additionally logs `LOG_ERR "... was not
set"` (not `LOG_CRIT`) when the option is recognised but has no value yet,
distinguishing "never heard of this option" from "known option, unset value" —
both still return `0`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:791-803, 812-829, 849-861
**Acceptance:** [ERR] negative, local — `rc_conf_str(rh, "no-such-option")`
returns `NULL` without crashing; `rc_conf_int(rh, "radius_deadtime")` before
it is set in the config returns `0` with a `LOG_ERR`, not `LOG_CRIT`, log line.
**Links:** REQ-CONFIG-CFG-016

---

## DATA — option storage, ownership, and lifetime

### REQ-CONFIG-DATA-001 — `rc_config_free()` MUST release every option's stored value, including per-server arrays, but MUST NOT touch dictionary state

**Requirement:** `rc_config_free()` MUST iterate `rh->config_options[0..NUM_OPTIONS)`
and, for each non-`NULL` value, free it — for `OT_SRV` options, freeing each
`serv->name[j]`/`serv->secret[j]` individually before freeing the `SERVER`
struct itself; for all other types, a single `free()` of `option->val`. It
MUST then free `rh->config_options` and `rh->first_dict_read`, and NULL both
fields on `rh`. Per its own doc comment, it MUST NOT free any dictionary
attribute/vendor entries — only `rc_destroy()` (which calls `rc_dict_free()`
separately, first) fully releases a handle.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:1144-1180 (doc comment 1144-1153, body 1154-1180)
**Acceptance:** [DATA][MEM] negative, local, ASan/LeakSanitizer-clean — after
`rc_config_free(rh)` on a fully-populated handle (multiple `authserver`
entries with secrets, several string/int options set), no leaks are reported
for config-table memory; dictionary entries loaded via `rc_read_dictionary`
remain valid and readable until a subsequent `rc_dict_free()`/`rc_destroy()`.
**Links:** REQ-CONFIG-INIT-005, REQ-GEN-MEM-003

### REQ-CONFIG-DATA-002 — `authserver` and `acctserver` are independent `SERVER` lists, each bounded to `RC_SERVER_MAX` (8) entries

**Requirement:** `authserver` and `acctserver` MUST be stored as two separate
`SERVER` structures (via two separate `OT_SRV` options), each with its own
`max` counter bounded — subject to the off-by-one in `REQ-CONFIG-SEC-001` — by
`RC_SERVER_MAX`. Configuring one list MUST have no effect on the other's
entries or count.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/options.h:44-45 (`authserver`, `acctserver` as distinct
`OT_SRV` entries); include/radcli/radcli.h:81 (`RC_SERVER_MAX`)
**Acceptance:** [DATA] positive, local — a config with 3 `authserver` hosts
and 1 `acctserver` host yields `rc_conf_srv(rh,"authserver")->max == 3` and
`rc_conf_srv(rh,"acctserver")->max == 1`, independently.
**Links:** REQ-CONFIG-SEC-001, REQ-CONFIG-CFG-007

---

## Phase 5 — completeness check

Every symbol declared under `/* config.c */` in `include/radcli/radcli.h:698-715`
and mirrored in `lib/radcli.map.in` (lines 32-43, 71) is cited by at least one
requirement above:

| Symbol | Cited by |
|---|---|
| `rc_add_config` | REQ-CONFIG-CFG-009, REQ-CONFIG-INIT-002 |
| `rc_config_init` | REQ-CONFIG-INIT-002 |
| `rc_read_config` | REQ-CONFIG-INIT-003, -004, -006, REQ-CONFIG-CFG-001..015 (parsing helpers it drives), REQ-CONFIG-ERR-001 |
| `rc_conf_str` | REQ-CONFIG-CFG-016, REQ-CONFIG-ERR-003, REQ-CONFIG-SEC-003 |
| `rc_conf_int` | REQ-CONFIG-CFG-006, -016, REQ-CONFIG-ERR-003 |
| `rc_conf_srv` | REQ-CONFIG-CFG-007, -016, REQ-CONFIG-DATA-002 |
| `rc_test_config` | REQ-CONFIG-CFG-010, -011 |
| `rc_apply_config` | REQ-CONFIG-INIT-004, REQ-CONFIG-CFG-012, -013 |
| `rc_find_server_addr` | REQ-CONFIG-CFG-018, REQ-CONFIG-SEC-002 |
| `rc_config_free` | REQ-CONFIG-DATA-001 |
| `rc_new` | REQ-CONFIG-INIT-001 |
| `rc_destroy` | REQ-CONFIG-INIT-005 |
| `rc_get_socket_type` | REQ-CONFIG-CFG-017 |

No gap remains: all thirteen public config.c symbols have at least one citing
requirement. Two internal-only helpers worth naming for future maintainers
tracing this document — `find_option()` and the four `set_option_*()`
functions — are `/// @cond INTERNAL` and correctly absent from
`include/radcli/radcli.h`/`lib/radcli.map.in`; they are cited as evidence
throughout but are not themselves public API requiring their own top-level
requirement.
