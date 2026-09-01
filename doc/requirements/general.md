---
title: general and cross-cutting requirements
generator: requirements-elicitation
process: n/a (library-wide)
id-prefix: REQ-GEN
categories:
  SEC: process-state neutrality and privilege/security invariants
  ABI: public symbol and ABI stability
  MEM: allocator and string/buffer safety rules
  TECH: canonical technology stack constraints
  STYLE: code style and structure rules enforced by CI or review
  TEST: test quality requirements
sources:
  - AGENTS.md
  - contrib/ai/personas/radcli-core-dev.md
  - lib/radcli.map
  - lib/radcli.map.in
  - devel/ABI-x86_64.dump
  - lib/radcli2.map
  - lib/radcli2.map.in
  - devel/ABI2-x86_64.dump
  - .github/workflows/tests.yaml
  - lib/config.c, lib/options.h (cited not owned -- internal config-access
    convention, REQ-GEN-STYLE-011)
---

# General and Cross-Cutting Requirements

radcli is a library linked directly into a caller's process, not an application
that owns its own process — see `AGENTS.md`'s Project Overview. Unlike a
multi-process application's cross-cutting document (which typically covers
inter-process invariants), this document's most important entries are the
opposite: constraints on what radcli must **never** do to the process it is
linked into, because it cannot know what else that process depends on.

Process-specific behavioral requirements (config parsing, dictionary loading,
attribute handling, transport) belong in their own documents (`config.md`,
`dict.md`, `attrs.md`, `net.md`, `util.md`), even when they carry security
implications. A requirement belongs here only when it applies regardless of
which subsystem is being changed.

`contrib/ai/personas/radcli-core-dev.md`'s "Protocol: Design Review" checklists
(Locality of complexity, Dependency growth, ABI stability, Design simplicity,
Process-state neutrality, Canonical technology choices) are the working
quick-reference for this document; the entries below are their authoritative,
ID'd, testable form.

---

## SEC — process-state neutrality and privilege/security invariants

### REQ-GEN-SEC-001 — radcli MUST NOT install or modify process-wide signal handlers

**Requirement:** No function in `lib/` MUST call `signal()` or `sigaction()` on
any signal, including `SIGPIPE`, at any point during the library's lifetime
(init, request handling, teardown). A write to a peer that has reset the
connection (e.g. the close-notify `gnutls_bye()` sends when tearing down a
session whose server just died) can raise `SIGPIPE`; silencing it process-wide
would override a decision that belongs to the embedding application, which may
depend on `SIGPIPE`'s default behavior or its own handler elsewhere in the same
process.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Process-state neutrality");
verified against current source — no `signal(`/`sigaction(` call exists in
`lib/*.c` as of this writing.
**Acceptance:** [SEC] negative, local — `grep -n 'signal(\|sigaction(' lib/*.c`
returns no matches. `tests/tls-idle-restart.c`'s own `signal(SIGPIPE, SIG_IGN)`
is a test-binary concern, not library code, and must stay out of `lib/`.
**Links:** REQ-NET-SEC-* (tls.c session teardown, see `net.md`)

### REQ-GEN-SEC-002 — radcli MUST NOT call fork() or spawn threads on its own initiative

**Requirement:** No function in `lib/` MUST call `fork()`, `vfork()`, or create
a thread (`pthread_create()` or equivalent) except as a direct, synchronous
response the caller explicitly requested (radcli has no such API today — this
requirement forbids adding one implicitly, e.g. as a hidden implementation
detail of a "simple" retry or background-refresh feature). radcli MUST remain
safe to call *from* threads the caller creates, which is a distinct property
from spawning its own.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Process-state neutrality");
verified — no `fork(`/`pthread_create(` call exists in `lib/*.c`.
**Acceptance:** [SEC] negative, local — `grep -n 'fork(\|pthread_create(' lib/*.c`
returns no matches.
**Links:** REQ-GEN-SEC-004

### REQ-GEN-SEC-003 — radcli MUST NOT use process-wide timers

**Requirement:** No function in `lib/` MUST call `alarm()`, `setitimer()`,
`timer_create()`, or any other global/process-wide timer facility. Any timeout
behavior (e.g. watchdog-interval deadline tracking, request retries) MUST be
implemented with per-call state (timestamps stored in `rh`/`tls_st`/`SEND_DATA`)
and `select()`/`poll()`-style waits scoped to the call in progress, never a
mechanism that could fire a signal into caller code unrelated to radcli.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Process-state neutrality");
verified — no `alarm(`/`setitimer(` call exists in `lib/*.c`. Compare
`lib/dae.c`'s `radcli_ctx_get_poll()`/`radcli2_priv_dae_send_watchdog()`
(`REQ-WATCHDOG-NET-002`/`003`, `doc/requirements/watchdog.md`), which compute
a watchdog-interval deadline from a stored `last_msg`/`last_recv` timestamp
comparison, not a signal-based timer.
**Acceptance:** [SEC] negative, local — `grep -n 'alarm(\|setitimer(\|timer_create(' lib/*.c`
returns no matches.
**Links:** REQ-WATCHDOG-NET-002, REQ-WATCHDOG-NET-003

### REQ-GEN-SEC-004 — radcli MUST NOT mutate ambient process state the caller may independently rely on

**Requirement:** No function in `lib/` MUST call `setlocale()`, `umask()`,
`chdir()`, `setenv()`/`putenv()`/`unsetenv()`, or otherwise change process-wide
settings that an embedding application configures for its own purposes. Any
locale-, path-, or environment-sensitive behavior radcli needs MUST be
implemented without changing the ambient value for the rest of the process
(e.g. resolve paths relative to a passed-in or configured directory, not by
`chdir()`-ing first).
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Process-state neutrality");
verified — no `setlocale(`/`umask(`/`chdir(`/`setenv(` call exists in `lib/*.c`.
**Acceptance:** [SEC] negative, local — `grep -n 'setlocale(\|umask(\|chdir(\|setenv(\|putenv(\|unsetenv(' lib/*.c`
returns no matches.

### REQ-GEN-SEC-005 — radcli MUST NOT introduce new library-owned global or `static` mutable state

**Requirement:** New library-owned process-wide mutable state (`static`
non-`const` variables at file scope or function scope, or globals declared in
headers) MUST NOT be added. One pre-existing instance in radcli2 core is an
accepted, maintainer-reviewed exception and MUST NOT be treated as precedent
for adding further global state:
  - `_initialized` (`lib/config.c:1182`, `static int`) — a process-wide
    reference count guarding GnuTLS global init/deinit idempotency across
    multiple `rc_handle` instances in one process. Accepted because it only
    guards one-time process-wide init/deinit calls; see `REQ-CONFIG-SEC-004`
    in `config.md`.

`rc_mksid()`'s `static char buf[15]`/`static unsigned short int cnt`
(`lib/legacy/compat.c`) is a second pre-existing instance, also accepted as-is:
the function is marked `@deprecated` in its own Doxygen comment, and the
non-reentrancy/cross-instance-sharing hazard this implies is an accepted,
documented property of a deprecated function rather than something requiring
a code change. See `util.md`'s Phase 5 gap analysis for the full citation.

Debug verbosity was formerly a third exception (`radcli_debug`, a plain
process-wide global read from every `DEBUG()` call site) but is no longer
global in radcli2 core: it's now the `debug` field on `struct rc_conf`
(`lib/includes.h`), so each `rc_handle`/`radcli_ctx` carries its own
verbosity and two handles in one process no longer interfere. The
`rc_setdebug()`/`radcli_legacy_debug` pair (`lib/legacy/compat.c`) remains a
process-wide global, but it is confined to the optional legacy-compat shim,
not radcli2 core, and only pre-seeds the `debug` field of handles
constructed after it's called (`rc_new()`/`rc_read_config()`) — see
`util.md`.

All correctness-relevant state MUST live in a caller-owned handle
(`rc_handle`, `SEND_DATA`, `RC_AAA_CTX`, `tls_st`), so that two `rc_handle`
instances in the same process (or the same instance used from multiple
threads under caller-provided synchronization) do not silently interfere with
each other.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Process-state neutrality");
lib/config.c:1182; lib/util.c:105-106; lib/includes.h (`struct rc_conf.debug`);
lib/legacy/compat.c (`radcli_legacy_debug`, `rc_setdebug()`)
**Acceptance:** [SEC] code-review — every new `static` non-`const` file- or
function-scope variable or new `extern` global declared in a header MUST be
justified in the same terms as the two accepted radcli2-core exceptions above
(no correctness impact beyond one-time process-wide init, no cross-`rc_handle`
interference for correctness-relevant state) or rejected. Legacy-shim-only
globals (`lib/legacy/*.c`) that exist purely for source compatibility with a
pre-`rc_handle` API and cannot take a handle argument, like
`radcli_legacy_debug`, are judged separately and are not precedent for radcli2
core.
**Links:** REQ-GEN-SEC-002, REQ-CONFIG-SEC-004 (config.md), util.md's Phase 5
gap analysis (rc_mksid)

### REQ-GEN-SEC-006 — Shared secrets MUST NOT be logged, retained beyond the request, or compared non-constant-time

**Requirement:** The RADIUS shared secret MUST NOT appear in any `rc_log()`/
`DEBUG()` output, error message, or buffer that outlives the request it
authenticates. Comparisons involving the shared secret or values derived from
it for authentication purposes MUST NOT use a data-dependent-timing function
(`strcmp`, `memcmp`) where timing leakage could reveal secret material to a
network attacker measuring response latency.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Security
Vulnerability Taxonomy" — RADIUS shared secret exposure)
**Acceptance:** [SEC] code-review — grep for the secret field
(`SEND_DATA.secret`/`rc_handle` secret storage) in every new `rc_log`/`DEBUG`
call site and every new comparison; flag any hit.
**Links:** REQ-NET-SEC-* (Message-Authenticator validation, see `net.md`)

### REQ-GEN-SEC-007 — `random()`, `rand()`, `srandom()`, and other non-cryptographic PRNGs MUST NOT be used

**Requirement:** No function in `lib/` or `src/` MUST call `rand()`, `random()`,
`srand()`, `srandom()`, `rand_r()`, `random_r()`, `initstate()`/`setstate()`,
or the `drand48`/`erand48`/`lrand48`/`nrand48`/`mrand48`/`jrand48`/`srand48`/
`seed48`/`lcong48` family. These are non-cryptographic, seed-predictable
generators; any RADIUS protocol field derived from one (Request Authenticator,
any value an off-path attacker could otherwise brute force or predict from
`time()`/`getpid()`) weakens response spoofing and replay resistance, since
guessing the next value narrows an attacker's search space independently of
the shared secret. This deliberately does not list the one-octet packet
Identifier: RFC 2865 §3 does not require it to be unpredictable ("aids in
matching requests and replies" is its only stated purpose), and RFC 5080
§2.1.1 requires LRU — rotating, not random — allocation instead, to
maximize time-before-reuse and avoid stale-duplicate misattribution. The
Identifier's allocation rule lives in net2.md's REQ-NET2-SEND-010/016 (LRU,
not CSPRNG). The ban on `rand()`/`random()`/etc. as a source is otherwise
unaffected. Any code path that needs a random
value not itself covered by RFC 2865/2866 packet-authenticator hashing MUST
obtain it through a CSPRNG: `rc_get_random_bytes(buf, len)` /
`rc_get_random_byte()` (`lib/rc-random.c`), which use
`gnutls_rnd(GNUTLS_RND_NONCE, ...)` when built with GnuTLS, `getentropy()`
otherwise, and treat a negative/nonzero return as fatal (`assert`). Neither
is public ABI (no `lib/radcli.map` entry; declared only in `rc-random.h`).
**Strength:** MUST NOT
**Status:** DERIVED — enforced
**Source:** Maintainer directive (2026-08-21): ban weak PRNGs project-wide,
require a CSPRNG alternative.
**Acceptance:** [SEC] negative, local —
`grep -nE '\b(rand|random|srand|srandom|rand_r|random_r|initstate|setstate|d?rand48|[jlmn]rand48|seed48|lcong48)\s*\(' lib/*.c lib/*.h src/*.c`
returns no matches other than `rc_get_random_bytes()`'s own use of
`gnutls_rnd`/`getentropy` (which does not match this pattern).
**Links:** REQ-GEN-SEC-005, REQ-CONFIG-SEC-004 (config.md), REQ-GEN-ABI-001,
REQ-NET-SEC-* (Request Authenticator generation, see `net.md`)

### REQ-GEN-SEC-008 — MD5-based RADIUS authenticators MUST NOT be described or relied upon as cryptographically unforgeable outside TLS/DTLS

**Requirement:** Any RADIUS or dynamic-authorization construct whose integrity
rests on MD5 -- the Request Authenticator and Response Authenticator (RFC 2865
§3, a keyed MD5 hash, not a modern MAC) and the Message-Authenticator (RFC 2869
§5.14, HMAC-MD5) -- MUST NOT be described, in code comments, requirement text,
or other documentation, as "unforgeable," "cryptographically secure," or
otherwise credited with forgery resistance equivalent to a modern MAC (e.g.
HMAC-SHA-256). MD5 collision and chosen-prefix attacks are practical (RFC
6151); Blast-RADIUS (CVE-2024-3596) is a direct exploitation of this weakness
against the Response Authenticator. Requirement or comment text MAY describe
these constructs as raising the bar against an attacker who does not know the
shared secret, but MUST NOT claim they close the threat model against an
attacker with cryptanalytic resources or control over packet content.
Unqualified "unforgeable"/"authenticated" language MUST be reserved for the
RadSec (TLS/DTLS) transport, whose session-level authentication does not
depend on MD5 at all (`REQ-DAE-INIT-007`).
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** RFC 2865 §3 (Request/Response Authenticator, keyed MD5); RFC 2869
§5.14 (Message-Authenticator, HMAC-MD5); RFC 6151 (MD5/HMAC-MD5 security
considerations); CVE-2024-3596 (Blast-RADIUS); maintainer directive
(2026-08-31), correcting `REQ-DAE-SEC-005`'s unforgeability assumption.
**Acceptance:** [SEC] documentation review -- grep `doc/requirements/*.md` for
`unforgeable` and confirm every remaining use is either qualified (e.g.
"unforgeable without the secret, at MD5's strength") or scoped to the RadSec/
TLS transport rather than the UDP MD5 path.
**Links:** REQ-DAE-SEC-002, REQ-DAE-SEC-005, REQ-DAE-SEC-008, REQ-DAE-INIT-007,
REQ-GEN-SEC-006

---

## ABI — public symbol and ABI stability

### REQ-GEN-ABI-001 — Every public function MUST be declared in both `include/radcli/radcli.h` and `lib/radcli.map`

**Requirement:** A function is part of radcli's public ABI if and only if it is
declared in `include/radcli/radcli.h` **and** listed under the `RADCLI_@LIBMAJOR@`
node in `lib/radcli.map.in`. Adding a function to one without the other MUST NOT
be merged — either the symbol is unreachable from outside the shared object
despite being declared (map omission), or it is exported without a supported
public declaration (header omission).
**Strength:** MUST
**Status:** DERIVED
**Source:** AGENTS.md ("ABI stability"); lib/radcli.map.in; lib/meson.build
(`compare-exported` target)
**Acceptance:** [ABI] unit, local — `ninja -C build compare-exported` passes.
**Links:** REQ-GEN-ABI-002

### REQ-GEN-ABI-002 — Symbol changes MUST be additive within `RADCLI_LIBMAJOR`; no symbol removal or signature change without a major bump

**Requirement:** All currently exported symbols live under a single version
node, `RADCLI_@LIBMAJOR@` (`lib/radcli.map.in`). A change MUST NOT remove an
existing symbol from this node, change an existing function's signature in a
binary-incompatible way, or change the layout of a public `struct` in a way
that breaks existing callers, unless `LIBMAJOR` is bumped as a deliberate,
separately-reviewed decision. New symbols MAY be added to the existing node.
**Strength:** MUST NOT (removal/incompatible change) ; MAY (additive)
**Status:** DERIVED
**Source:** AGENTS.md ("ABI stability"); lib/radcli.map.in (comment: "The
symbol version must be updated on every radcli library major number change.");
devel/ABI-x86_64.dump
**Acceptance:** [ABI] unit, local — `ninja -C build abi-check` against
`devel/ABI-x86_64.dump` reports no incompatible changes. After an intentional,
reviewed addition, `ninja -C build abi-dump` updates the reference dump in a 
separate commit focused on the symbol addition to separate automatically generated
changes from code.
**Links:** REQ-GEN-ABI-001

### REQ-GEN-ABI-003 — `include/radcli/radcli.h` public declarations carry Doxygen documentation, grouped under `@defgroup`/`@addtogroup`

**Requirement:** Every public enum, struct, and typedef declared in
`include/radcli/radcli.h` MUST have a Doxygen comment block at its
declaration. Every public function declared there MUST belong to a
`@defgroup` (one group per source file, declared once — either at the header
declaration or at the `.c` definition — with the rest of that group's members
using `@addtogroup`), so the generated man pages (`doc/man/`) stay in sync
with the header regardless of which file actually carries a given function's
prose (see REQ-GEN-STYLE-005 for where that prose belongs).
**Strength:** MUST
**Status:** DERIVED
**Source:** AGENTS.md ("Coding conventions"); contrib/ai/personas/radcli-core-dev.md
("Protocol: Change Propagation" — Group 1)
**Acceptance:** [STYLE] local — `ninja -C build` with `-Ddocs=enabled` (default)
regenerates man pages without Doxygen warnings for the changed header section.
**Links:** REQ-GEN-STYLE-005

`[REVIEW]` gap: as of the REQ-GEN-STYLE-005/006/007 migration (2026-08-28),
every function in `lib/legacy/compat.c` except `rc_mksid` (22 functions,
including `rc_getport`, `rc_own_hostname`, `rc_openlog`, `rc_new`,
`rc_read_dictionary`, ...) has no Doxygen comment at all, in either the
header or its `.c` definition — this requirement is not actually met for
that surface today. `lib/legacy/avpair.c` and `lib/legacy/buildreq.c`, by
contrast, already carry full documentation at their `.c` definitions
(confirmed during this migration) — not part of this gap. Not closed as
part of this migration: writing accurate documentation for
`compat.c`'s 22 functions is a separate effort from relocating existing
prose, and was explicitly deferred rather than rubber-stamped.

### REQ-GEN-ABI-004 — `libradcli2` carries the same ABI-stability contract as `libradcli`, under its own independent soversion

**Requirement:** `libradcli2.so` (`include/radcli/radcli2.h`'s `radcli_*`
API) is a separate shared object from `libradcli.so`, with its own
`lib/radcli2.map.in` version node (`RADCLI2_@LIBMAJOR2@`), its own
soversion (`lib/meson.build`'s `v2_current`/`v2_revision`/`v2_age`,
independent of `libradcli`'s `v_current`/`v_revision`/`v_age`), and its own
ABI baseline (`devel/ABI2-x86_64.dump`). REQ-GEN-ABI-001 and
REQ-GEN-ABI-002 apply to it identically, symbol-for-symbol, with
`radcli2.h`/`radcli2.map.in`/`ABI2-x86_64.dump` standing in for
`radcli.h`/`radcli.map.in`/`ABI-x86_64.dump`. `lib/radcli2.map.in` also
carries a second version node, `RADCLI2_PRIVATE`, for symbols that must be
exported across the `libradcli`/`libradcli2` boundary (either genuinely
internal helpers `lib/legacy/*.c` calls, or already-released `rc_*`
symbols whose implementation now lives in `libradcli2` under a
`radcli2_priv_*` name, wrapped back to their original name in
`lib/legacy/compat.c`) but are not part of the public `radcli2.h` API:
`RADCLI2_PRIVATE` is explicitly excluded from REQ-GEN-ABI-001/002's
stability promise, is not declared in any installed header, and MUST NOT
be relied on by any consumer outside this source tree — the same
convention `GLIBC_PRIVATE` and similar package-internal version nodes use
elsewhere. `libradcli.so` links against `libradcli2.so` and re-exports
none of its symbols directly; `-lradcli` consumers pick up `libradcli2.so`
transitively via their dynamic linker's needed-library resolution, and any
consumer calling `radcli2.h` functions directly MUST link `-lradcli2`
explicitly (`-Wl,--no-undefined -Wl,--as-needed` does not resolve a
program's own direct undefined references through another library's
transitive dependencies).
**Strength:** MUST
**Status:** DERIVED
**Source:** AGENTS.md ("ABI stability"); lib/radcli2.map.in; lib/meson.build;
devel/ABI2-x86_64.dump
**Acceptance:** [ABI] unit, local — `ninja -C build compare-exported2` passes
(radcli2.h/radcli2.map.in cross-check, mirroring REQ-GEN-ABI-001's
`compare-exported`); `ninja -C build abi-check2` against
`devel/ABI2-x86_64.dump` reports no incompatible changes, refreshed via
`ninja -C build abi-dump2` in a separate commit after an intentional,
reviewed addition (mirroring REQ-GEN-ABI-002).
**Links:** REQ-GEN-ABI-001, REQ-GEN-ABI-002
**Links:** REQ-GEN-ABI-001

---

## MEM — allocator and string/buffer safety rules

### REQ-GEN-MEM-001 — Library allocations use the standard allocator; `gnutls_malloc`/`gnutls_free` only where GnuTLS takes ownership

**Requirement:** New library allocations MUST use `malloc`/`calloc`/`realloc`/
`free`. `gnutls_malloc()`/`gnutls_free()` MUST be used only for memory passed to
a GnuTLS API that takes ownership of the buffer (e.g. `gnutls_datum_t` fields
consumed internally by GnuTLS). `malloc`-allocated memory MUST NOT be passed to
a GnuTLS API that will call `gnutls_free()` on it, and vice versa — the two
allocators are not guaranteed interchangeable.
**Strength:** MUST
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Memory Safety");
("Canonical technology choices" — Memory)
**Acceptance:** [MEM] code-review — every new `gnutls_malloc`/`gnutls_free`
call site is paired with a GnuTLS API that documents taking/releasing
ownership of that buffer.

### REQ-GEN-MEM-002 — Every allocation return value MUST be checked before use

**Requirement:** New code MUST check the return value of every
`malloc`/`calloc`/`realloc`/`gnutls_malloc` call before dereferencing the
result. A null-pointer dereference in a library is a denial-of-service
vulnerability for every calling application, not just radcli's own tests.
**Strength:** MUST
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Memory Safety")
**Acceptance:** [MEM] code-review / static-analyzer CI job (`scan-build`)
flags unchecked allocations.

### REQ-GEN-MEM-003 — Error paths use a single `goto cleanup`/`fail` label per function, matching the file's existing convention

**Requirement:** Functions with allocated resources on an error path MUST
release them via a single, named cleanup label reached by `goto`, rather than
duplicating free logic across multiple early `return` statements. New code
MUST match whichever label name (`cleanup`, `fail`, etc.) the file being edited
already uses.
**Strength:** MUST
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Memory Safety")
**Acceptance:** [MEM] code-review — flag functions with more than one distinct
partial-free sequence across different return points.

### REQ-GEN-MEM-004 — `strcpy`, `strcat`, `sprintf`, `gets`, and `scanf %s` MUST NOT appear in new or modified code

**Requirement:** These unbounded string functions MUST NOT be introduced or
reintroduced. String copying MUST use `strlcpy` (polyfilled as `rc_strlcpy` in
`lib/util.h`, aliased to `strlcpy` where the platform provides it — reached via
`#include "util.h"`). String concatenation MUST use `strlcat`, or build into a
sized buffer with `snprintf` from the start. Formatted output into a fixed
buffer MUST use `snprintf`, never `sprintf`.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Memory Safety" —
"Unsafe string and buffer functions — banned"); lib/util.h (`rc_strlcpy`)
**Acceptance:** [MEM] negative, local — `grep -n 'strcpy(\|strcat(\|sprintf(\|[^f]gets(' lib/*.c`
returns no matches in modified files; static-analyzer CI job also flags these.

### REQ-GEN-MEM-005 — RADIUS packet construction and parsing MUST use the `pkt_buf` API

**Requirement:** All new packet-building and packet-parsing code MUST use
`lib/util.h`'s `pkt_buf` interface (`pb_init`, `pb_init_read`, `pb_put_byte`,
`pb_put_bytes`, `pb_put_reserve`, `pb_pull`, `pb_peek_byte`) rather than raw
pointer arithmetic into a fixed buffer. Every `pkt_buf` operation returns `-1`
on overflow; that error MUST be propagated, never silently ignored. Raw pointer
writes (`*ptr++ = v`) MUST NOT be mixed with `pkt_buf` writes into the same
buffer region, since the bounds tracking would no longer be authoritative.
**Strength:** MUST
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Memory Safety" —
"Packet construction and parsing"; "Protocol: Security Vulnerability Taxonomy" —
"Buffer overflows in packet parsing", "Unsafe string/buffer operations")
**Acceptance:** [MEM][SEC] code-review — new packet code reviewed for `pkt_buf`
usage and propagated `-1` return checks.
**Links:** REQ-NET-DATA-* (packet packing, see `net.md`), REQ-UTIL-DATA-*
(`pkt_buf` implementation, see `util.md`)

### REQ-GEN-MEM-006 — Line-oriented file/stream parsing in `lib/` MUST use `getline()`, never `fgets()` into a fixed-size buffer

**Requirement:** New or modified code in `lib/` that reads a text file or
stream line-by-line (config files, dictionary files, credentials files, or
any future format) MUST use `getline()`, which grows its buffer to fit the
line rather than imposing a silent length limit. `fgets()` into a
fixed-size stack buffer MUST NOT be used for this purpose: a physical line at
or beyond the buffer's size makes `fgets()` return a partial line with no
trailing newline, and unless every caller specifically detects and handles
that split (which historically they did not — see the `Source` commits
below), the unread remainder is picked up by the next read and misparsed as
a bogus separate line, silently corrupting or truncating whatever value
happened to be mid-line — including a shared secret, in
`rc_find_server_addr()`'s case. A function converted to `getline()` MUST
`free()` its line buffer on every exit path (see REQ-GEN-MEM-003 — this
is the reason a function with multiple early-return error paths MUST route
them through a single cleanup label once it owns a `getline()`-allocated
buffer, rather than duplicating the `free()` at each one).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c (`rc_read_config()`, `rc_find_server_addr()`),
lib/dict.c (`rc_dict_init()`) — all three converted from a fixed `fgets()`
buffer to `getline()` after the fixed-buffer form was found to silently
truncate/misparse a physical line at or beyond the buffer size (`config.c`'s
511-byte limit; the `servers`-file 128-byte limit that could truncate a
secret; the dictionary parser's 1024-byte limit)
**Acceptance:** [MEM] negative, local — `grep -n 'fgets(' lib/*.c` returns no
matches; positive — a test file containing one physical line far longer than
the format's old fixed-buffer size (e.g. tests/config-unit.c's
`test_long_line_no_truncation`/`test_servers_file_long_line`,
tests/dict.c's long-comment-line case) parses correctly instead of being
truncated or corrupting the following line.
**Links:** REQ-GEN-MEM-003, REQ-CONFIG-CFG-002 (config.md)

---

## TECH — canonical technology stack constraints

### REQ-GEN-TECH-001 — Cryptography goes through GnuTLS/nettle only; no OpenSSL

**Requirement:** TLS/DTLS session management MUST be implemented in
`lib/tls.c` using GnuTLS. OpenSSL MUST NOT be introduced as a dependency.
GnuTLS utility calls (`gnutls_global_init`, `gnutls_rnd`) MAY appear outside
`lib/tls.c` — in `lib/config.c` and `lib/sendserver.c` — where they operate
independently of the session layer (global library init, nonce generation);
this is an accepted exception, not a violation.
**Strength:** MUST NOT (OpenSSL) ; MUST (GnuTLS for TLS/DTLS sessions)
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Canonical technology
choices" — Cryptography); lib/config.c:1195 (`gnutls_global_init`);
lib/sendserver.c:303 (`gnutls_rnd`)
**Acceptance:** [TECH] code-review — new cryptographic code reviewed for
GnuTLS-only usage; `meson.build`'s dependency list reviewed for no added
OpenSSL dependency.

### REQ-GEN-TECH-002 — Build system is Meson; no autotools or cmake

**Requirement:** The build MUST be described in `meson.build` files. Autotools
(`configure.ac`/`Makefile.am`) or CMake build definitions MUST NOT be added as
a parallel or replacement build system.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Canonical technology
choices" — Build); AGENTS.md ("Build System")
**Acceptance:** [TECH] code-review — no new `configure.ac`, `Makefile.am`, or
`CMakeLists.txt` in the patch.

### REQ-GEN-TECH-003 — New external dependencies require a recorded design decision

**Requirement:** A change MUST NOT introduce a new external library dependency
without a design-discussion issue on record approving it, and MUST NOT
duplicate functionality already present in `lib/` (e.g. re-implementing
`pkt_buf`, the dictionary parser, or the socket vtable under a different name).
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Design Review" —
Dependency growth)
**Acceptance:** [TECH] code-review — verdict recorded as *no new deps* |
*justified (link issue)* | *REJECT* per the Design Review protocol.

### REQ-GEN-TECH-004 — Production builds MUST NOT define `NDEBUG`

**Requirement:** radcli's own build (`meson.build` and all `meson.build`
files under `lib/`) MUST NOT define `NDEBUG` and MUST NOT set Meson's
`b_ndebug` option to `true` or `if-release` for any built-in buildtype,
including `release`. `assert()` MUST remain compiled in and live in every
build radcli ships, including production/release builds. This is a
deliberate choice, not an oversight: per REQ-GEN-STYLE-009, every `assert()`
in `lib/` encodes an invariant whose violation is a logic or security defect,
not a routine input-validation failure — silently compiling those checks out
in "optimized" builds would turn a loud, immediate abort at the point of
violation into undefined behavior or a silent security bypass one or more
calls later, which is strictly worse for a security-sensitive library. A
downstream packager who overrides this (e.g. by passing `-Db_ndebug=true`
independently) does so against radcli's own documented intent, not with it.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** Maintainer directive (2026-08-30); see also this document's
review of `lib/sendserver.c:314` (`net.md`/`REQ-NET-*`, forthcoming) for a
concrete case this policy was written to keep loud rather than latent.
**Acceptance:** [TECH] negative, local — `grep -rn 'NDEBUG\|b_ndebug'
meson.build lib/meson.build` finds no line that defines `NDEBUG` or sets
`b_ndebug` to a non-`false` value; `meson setup build --buildtype=release &&
ninja -C build && strings build/lib/libradcli2.so.*.*.* | grep -c
'Assertion.*failed'` (or an equivalent objdump/nm check for the
`__assert_fail` symbol) confirms assertions are still linked into a release
build.
**Links:** REQ-GEN-STYLE-009, REQ-GEN-STYLE-010

### REQ-GEN-TECH-005 — radcli's supported platform baseline guarantees a working CSPRNG (`getrandom()`/`getentropy()`, or GnuTLS's `gnutls_rnd()`)

**Requirement:** radcli's documented minimum supported platform MUST include
a functioning kernel/libc CSPRNG source: `getentropy(3)`/`getrandom(2)`
available and returning success for requests within their documented limits
(Linux kernel >= 3.17, glibc >= 2.25 or an equivalent libc, and no sandbox/
seccomp policy that denies the `getrandom` syscall), for any build configured
without GnuTLS (`-Dtls=disabled`); builds with GnuTLS additionally rely on
`gnutls_rnd(GNUTLS_RND_NONCE, ...)` succeeding, which carries the same
platform assumption transitively through GnuTLS's own entropy source.
Running radcli on a platform that does not meet this baseline (an
`ENOSYS`-returning `getentropy()`, a container profile that blocks
`getrandom(2)`, or a GnuTLS build with no usable entropy source) is
**unsupported**, not a runtime condition `lib/rc-random.c` is required to
handle gracefully. This requirement exists specifically to make
`rc_get_random_bytes()`/`rc_get_random_byte()`'s `assert(ret >= 0)` /
`assert(ret == 0)` (`lib/rc-random.c:50,53`) justified as unreachable under
the platforms radcli claims to support, per REQ-GEN-STYLE-009's "impossible
under our own assumptions" bar — without this requirement on record, that
assert would instead be a plausible, unhandled runtime failure on an
under-specified platform.
**Strength:** MUST
**Status:** DERIVED
**Source:** Maintainer directive (2026-08-30, in response to reviewing
`lib/rc-random.c:50,53`); lib/rc-random.c; meson.build (`get_option('tls')`
making the GnuTLS path optional, which is why the `getentropy()` fallback's
own platform assumption needs to be independently documented rather than
inherited from a GnuTLS requirement)
**Acceptance:** [TECH] doc-review — `AGENTS.md` or `README.md` states the
minimum kernel/libc baseline above in its supported-platforms section; no
code change is required as a consequence of this requirement by itself
(`lib/rc-random.c`'s existing asserts already match this policy once it is
on record).
**Links:** REQ-GEN-STYLE-009, REQ-GEN-SEC-007

### REQ-GEN-TECH-006 — nettle is a mandatory build dependency; no bundled MD5/HMAC-MD5 fallback

**Requirement:** nettle (`>=2.4`) MUST be a mandatory build dependency of
radcli. radcli MUST NOT ship or build a bundled fallback MD5/HMAC-MD5
implementation for platforms without nettle. Every use of MD5, HMAC-MD5, or
SHA-256 in `lib/` MUST go through nettle via the single `lib/rc-crypto.c`
wrapper -- no other file may include a nettle crypto header or a hand-rolled
digest implementation directly. This supersedes the `nettle` Meson feature
option's previous `auto`/"bundled fallback otherwise" behavior: nettle is no
longer optional, and the second, hand-rolled implementation it was an
alternative to no longer exists to fall back to.
**Strength:** MUST / MUST NOT
**Status:** DERIVED
**Source:** Maintainer directive (2026-08-31), given in the course of adding
`REQ-DAE-SEC-005`'s SHA-256 duplicate-suppression key: rather than adding a
third digest implementation choice (nettle SHA-256 vs. a new bundled one),
the bundled MD5/HMAC-MD5 fallback path is retired and nettle becomes the
single, mandatory crypto backend for these algorithms.
**Acceptance:** [TECH] doc/build review -- `meson_options.txt` has no
`nettle` feature option; `meson.build`'s `nettle_dep` is
`dependency('nettle', version: '>=2.4', required: true)`; `lib/md5.c`,
`lib/md5.h`, `lib/hmac.c`, `lib/hmac.h` do not exist in the tree; `grep -rn
HAVE_NETTLE lib/` has no hits outside `lib/rc-crypto.c`'s nettle-version
compatibility shim (`HAVE_DIGEST_LENGTH_ARG`, itself unrelated to nettle's
presence -- see `meson.build`'s comment on nettle >=3.10 dropping the
digest-length argument).
**Links:** REQ-GEN-TECH-001 (nettle was already an accepted crypto backend
alongside GnuTLS; this tightens its availability from MAY to MUST),
REQ-GEN-TECH-003 (not a *new* dependency -- nettle was already an optional
one; no new design-discussion issue required), REQ-DAE-SEC-005

---

## STYLE — code style and structure rules

### REQ-GEN-STYLE-001 — Public symbols are `rc_`-prefixed; macros are `UPPER_CASE`; C99; BSD-2-Clause for new files

**Requirement:** All public functions MUST be prefixed `rc_`. Macros MUST use
`UPPER_CASE`. New source files MUST compile as C99 and MUST carry a BSD
2-clause license header. Code MUST compile with `-Wall -Werror` with no new
warnings.
**Strength:** MUST
**Status:** DERIVED
**Source:** AGENTS.md ("Coding conventions")
**Acceptance:** [STYLE] local/CI — `ninja -C build` succeeds with no new
warnings; static-analyzer CI job (`scan-build`) is clean on the diff.

### REQ-GEN-STYLE-002 — A design change that increases caller-side setup burden requires justification

**Requirement:** radcli's purpose is RADIUS auth/accounting in ~50 lines of
caller code, with server/credential configuration in a single config file. A
proposed feature that requires the calling application to manage significant
new state, perform multi-step setup beyond `rc_read_config()` + attribute
building + `rc_auth()`/`rc_acct()`, or duplicate information that belongs in
the config file, MUST be justified against this goal or redesigned so the
added complexity lives in the library, not the caller.
**Strength:** SHOULD
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Design Review" —
Design simplicity)
**Acceptance:** [STYLE] code-review — verdict recorded as *preserves
simplicity* | *increases caller burden — justify or redesign*.

### REQ-GEN-STYLE-003 — Code comments explain *why*, not *what*; durable rationale that no reader can re-derive from the code belongs in `doc/requirements/`, not a comment

**Requirement:** A comment MUST NOT restate what code already says through its
own structure and naming (e.g. `/* increment i */` above `i++`). A comment MAY
explain a non-obvious *why* — a hidden constraint, a workaround for a specific
bug, an invariant a reader could not otherwise infer, or a warning about a
consequence that isn't local to the line — when that context cannot be made
self-evident by better naming or restructuring instead. When that "why" is a
durable, testable invariant that spans multiple functions, call sites, or
depends on history a passing reader has no way to reconstruct from the
immediate code (e.g. "this call path is now the *only* initializer for these
fields, because a prior refactor deferred the other one"), it MUST be captured
as a `doc/requirements/` entry rather than (or in addition to) an inline
comment — the comment, if kept, SHOULD be short and cite the requirement ID
rather than restate its full reasoning inline.
**Strength:** MUST (no restating code); SHOULD (durable cross-cutting
rationale lives in `doc/requirements/`, cited by ID from a short comment)
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Contribution Checklist"
— "No comments that merely restate what the code does; comments explain
*why*")
**Acceptance:** [STYLE] code-review — a comment that only restates the
following line/block is a review finding; a comment describing a
multi-function or historical invariant without a corresponding `REQ-*` entry
is a `[REVIEW]` gap to close, not grounds to expand the comment instead.
**Links:** REQ-NET-NET-016 (net.md) is an example of this split: the code
carries a two-line comment identifying the invariant (`tmps` must start
zeroed) and its ID; the full rationale — why this is the *only* place these
fields are ever initialized, and what silently breaks if it regresses — lives
in the requirement.

### REQ-GEN-STYLE-004 — Internal code resolving a compile-time-known attribute MUST use `radcli_dict_lookup_num()`, not `radcli_dict_lookup()` or `radcli_dict_lookup_oid()`

**Requirement:** When library-internal code (not end-user/application code)
needs a `radcli_attr_def*` for a specific, statically-known standard or
vendor attribute (e.g. NAS-Port, Framed-IP-Address, Message-Authenticator),
it MUST resolve it via `radcli_dict_lookup_num(ctx, PW_*, vendor)` using the
attribute's own `PW_*` constant from `radcli.h` (or a vendor type ID), not
`radcli_dict_lookup(ctx, "Name-String")` (a name-based dictionary scan) nor
`radcli_dict_lookup_oid(ctx, "id.vendor.type")` (which re-parses a string
into the same numeric form `_lookup_num()` already takes directly). This
rule applies only where the attribute identity is fixed at the call site; it
does NOT apply to code resolving an attribute whose numeric ID is itself a
runtime value not known until execution (e.g. `lib/sendserver.c`'s per-AVP
encoding loop, which already receives `vp->attribute` as a `uint32_t` and
calls `radcli_dict_attr_by_id()` directly — there is no name or OID string
to parse in the first place, so this rule is inapplicable, not violated).
`radcli_dict_lookup()`/`_lookup_oid()` remain the correct choice for code
resolving an attribute identity supplied at runtime as a name or OID string
(e.g. a config file's attribute-name line).
**Strength:** SHOULD
**Status:** DERIVED
**Source:** lib/dae.c (`build_reply()`/`radcli_dae_req_*()` family, migrated
from `radcli_dict_lookup(rh, "NAS-Port")` etc. to
`radcli_dict_lookup_num(rh, PW_NAS_PORT, 0)`); include/radcli/radcli2.h:104-141
(`radcli_dict_lookup`/`_lookup_oid`/`_lookup_num` doc comments — `_lookup_num()`
is documented as "equivalent to radcli_dict_lookup_oid() with the same
attribute expressed as an OID", i.e. the direct numeric path with no string
parsing)
**Acceptance:** [STYLE] code-review — a call to `radcli_dict_lookup()`/
`_lookup_oid()` with a literal string naming a `PW_*`-constant attribute is a
review finding; the fix is `radcli_dict_lookup_num()` with that constant.
**Links:** REQ-DICT-DATA-002 (dict.md; `RADCLI_VENDOR_ATTR_SET` encoding
`_lookup_num()` uses internally)

### REQ-GEN-STYLE-005 — Exported function documentation lives at the `.c` definition; exported type documentation stays at the header declaration

**Requirement:** "Public"/"exported" here means **declared in
`include/radcli/radcli.h` or `include/radcli/radcli2.h`** — the documented
API surface — not merely listed in `lib/radcli.map`/`radcli2.map`. The map
files additionally export a number of cross-translation-unit-only symbols
(e.g. `radcli2_priv_*`, `rc_getmtime`, `rc_str2tm`, `rc_strlcpy`,
`rc_md5_calc`, `rc_getaddrinfo`, `rc_own_bind_addr`, `rc_get_random_byte`/
`_bytes`) that are declared only in internal headers and are not part of the
public API; these are documented per REQ-GEN-STYLE-006, not this
requirement, regardless of their map membership. For every function
declared in the public header, its full Doxygen block (`@brief`/description,
`@param` for each parameter, `@return`) MUST be written at its
**definition** in the `.c` file, not at its prototype in the header. For
every enum, struct, or typedef declared in the public header, its Doxygen
block MUST stay at the header declaration, since it has no separate `.c`
definition site to hold it. The header MUST NOT carry **any** Doxygen
comment block (not even a one-line `@brief` pointer) on a function
prototype documented at its `.c` definition — the declaration is a bare,
uncommented prototype. Doxygen scans `lib/` and `include/radcli` together
(`doc/meson.build`'s `DOXY_INPUT` includes both) and merges a definition's
documentation onto its declaration automatically, so a header-side comment
is never necessary and would only be a second copy to keep in sync (or, if
it carries its own `@brief`, a second, competing brief description for the
same symbol).
**Strength:** MUST
**Status:** REVIEW
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Change
Propagation" — Group 1); doc/meson.build (`DOXY_INPUT`); lib/radcli2.map.in
(cross-TU-only exports not in radcli2.h)
**Acceptance:** [STYLE] local — `ninja -C build` with `-Ddocs=enabled`
regenerates man pages/HTML with no missing-documentation warnings; a grep
sweep of `include/radcli/radcli.h`/`radcli2.h` finds no `/**` comment block
immediately preceding a function prototype whose definition carries the
real documentation (only file/group-level and enum/struct/typedef doc
comments remain there).
**Links:** REQ-GEN-ABI-003

### REQ-GEN-STYLE-006 — Non-public types and functions carry doc-shaped comments marked so Doxygen does not extract them

**Requirement:** Enums, structs, typedefs, and functions that are **not**
part of the public API (not declared in `include/radcli/radcli.h`/
`radcli2.h` — see REQ-GEN-STYLE-005 for why map-file membership alone does
not make a symbol public) MUST carry a comment of the same descriptive
shape as public Doxygen documentation (purpose, `@param` for each
parameter, `@return` where applicable) at their definition, opened with
`/*-` instead of `/**`, so Doxygen's comment-block scanner does not treat it
as a documentation comment and it is excluded from generated output. This
applies uniformly whether or not the symbol additionally has `static`
linkage, and regardless of whether it is also listed in
`lib/radcli.map`/`radcli2.map` for cross-TU visibility — `EXTRACT_STATIC =
NO` already hides `static` symbols, but a non-`static` internal helper
(declared in an internal header such as `util.h`/`tls.h`/`avp.h`) is not
otherwise excluded, so the marker is what keeps it out of the generated
docs.
**Strength:** MUST
**Status:** REVIEW
**Source:** AGENTS.md ("Coding conventions" — existing `/*-` convention,
previously unenforced); doc/Doxyfile.in (`EXTRACT_STATIC = NO`)
**Acceptance:** [STYLE] local — grep sweep: every internal function/type
definition in `lib/*.c` is preceded by a `/*-` block, not `/**`; a doxygen
build produces no generated entries for these symbols.
**Links:** REQ-GEN-STYLE-005

### REQ-GEN-STYLE-007 — Internal function documentation: one-line purpose, optional one-sentence expansion, one sentence per parameter

**Requirement:** An internal function's `/*-` documentation block (per
REQ-GEN-STYLE-006) MUST open with a single line stating the function's
purpose, crisply enough to stand alone. If the purpose needs more context
than fits on that line, exactly one additional sentence MAY follow to
expand on it — not a multi-paragraph explanation. Each `@param` entry MUST
be a single crisp sentence describing that parameter's purpose (what it is
or controls), not a restatement of its name or type.
**Strength:** MUST (one-line purpose; one sentence per `@param`); MAY (one
expanding sentence)
**Status:** REVIEW
**Source:** user request 2026-08-28
**Acceptance:** [STYLE] code-review — a `/*-` block whose first line is not
a self-contained one-line purpose statement, that carries more than one
expanding sentence, or whose `@param` entries run longer than one sentence
or merely restate the parameter name, is a review finding.
**Links:** REQ-GEN-STYLE-006

### REQ-GEN-STYLE-008 — Definitions shared between radcli.h and radcli2.h live in a single radcli-defs.h

**Requirement:** Every plain-enum/struct/macro definition that both
`radcli.h` and `radcli2.h` need as a shared source of truth (the numeric
`PW_*` attribute IDs, the numeric `PW_*` VALUEs of well-known attributes,
and the `RC_OPTION_TABLE` X-macro option list) MUST live in one header,
`include/radcli/radcli-defs.h`, not be split across multiple per-topic
headers or hand-duplicated under a second, `RADCLI_`-prefixed name.
`radcli.h` and `radcli2.h` MUST both `#include <radcli/radcli-defs.h>`;
internal callers of the option table (e.g. `lib/options.h`) MUST do the
same. `radcli-defs.h` MUST declare nothing beyond these shared definitions
— no `rc_`/`RC_`- or `radcli_`/`RADCLI_`-prefixed function or opaque-type
declaration belongs in it.
**Strength:** MUST
**Status:** DERIVED
**Source:** include/radcli/radcli-defs.h; include/radcli/radcli2.h:28-41,56;
include/radcli/radcli.h:148-153; lib/options.h:10; include/meson.build:1
**Acceptance:** [STYLE] build, local — `include/radcli/radcli-defs.h` is
the only header `radcli.h`/`radcli2.h`/`lib/options.h` include for these
definitions; `include/meson.build`'s `install_headers()` call lists
`radcli-defs.h`; `meson setup build && ninja -C build` succeeds with no
missing-header errors.
**Links:** REQ-GEN-ABI-003, REQ-CONFIG2-CFG-001 (`RC_OPTION_TABLE`, cited
in config2.md)

### REQ-GEN-STYLE-009 — `assert()` marks a case that MUST be impossible given the codebase's current invariants, not a defensive input check

**Requirement:** `assert()` in `lib/` MUST be used only to encode a
condition the author has proven cannot occur given the invariants the
surrounding code currently maintains — never as a substitute for validating
data the function cannot otherwise trust (wire input, `errno`-reporting
syscalls whose failure is a normal operating condition, caller-supplied
values from outside `lib/`). The bar for "provably cannot occur" MUST
include forward-looking reasoning, not just the current call graph: before
adding or keeping an `assert()`, the author MUST be able to state which
specific invariant, maintained by which specific other code (a check earlier
in the same function, a precondition enforced by every caller, a type-level
guarantee), makes the asserted condition impossible — and MUST judge whether
a plausible future reorganization of that surrounding code (reordering a
check, adding a new caller, relaxing a clamp, changing which function
performs the length/bounds validation another function relies on) could
silently invalidate that invariant. If it could, and the resulting failure
mode would be a logic error or a security defect (an authentication or
integrity check silently skipped, a bounds violation, a use of
un-validated data as if it were validated) rather than merely a wrong
answer, the assert stays, precisely because it is one of the only compile-
and run-time backstops against that specific class of latent bug — a
reviewer changing the surrounding code and breaking the invariant SHOULD see
the assert fire in testing before the defect ships, per REQ-GEN-TEST-001's
sibling requirement that a regression be caught, not silently absorbed. An
`assert()` that instead exists to reject malformed or attacker-controlled
input (wire-format RADIUS attributes, config file contents, environment
values) is a defect in itself: it MUST be replaced with an explicit error
return, because REQ-GEN-TECH-004 keeps `assert()` compiled into every build
radcli ships, and a reachable failed assertion is `abort()` — a
denial-of-service the caller cannot recover from, on data that is not
actually a "this cannot happen" case.
**Strength:** MUST
**Status:** DERIVED
**Source:** Maintainer directive (2026-08-30); illustrated by
`lib/sendserver.c:314`'s former `assert(pb_pull(&rb, AUTH_HDR_LEN) == 0)`,
whose invariant ("the reply is at least `AUTH_HDR_LEN` bytes") was stated in
the function's own preceding comment but was not actually enforced on every
path that reached it. Fixed by gating both `decode_reply()` call sites on
`result == OK_RC` and replacing the assert with an explicit
`if (...) return ERROR_RC`; regression-tested by
`tests/malformed-packet-tests.sh`'s "short-header-length" case
(`tests/radius-server.py --attrs short-header-length`), which reproduces a
reply whose header `Length` field is under `AUTH_HDR_LEN` while the actual
UDP datagram is normal size, and asserts the client exits cleanly rather
than dying to a signal — this distinction matters because a plain nonzero-
exit-code check cannot tell a graceful rejection apart from an `abort()`.
**Acceptance:** [STYLE] code-review — every new or modified `assert()` in
`lib/` is reviewed with the specific invariant and its guaranteeing code
cited in the review comment (mirroring `REQ-GEN-ABI-*`'s citation
discipline), and an explicit judgment recorded on whether a plausible
future change to that guaranteeing code could invalidate the invariant. An
`assert()` whose condition can be reached with attacker-influenced wire or
config data along any call path is a review-blocking finding, not a style
nit.
**Links:** REQ-GEN-TECH-004, REQ-GEN-STYLE-010, REQ-GEN-TEST-001

### REQ-GEN-STYLE-010 — `assert()` MAY also be used to inform the static analyzer of an invariant it cannot otherwise derive

**Requirement:** Where the CI static-analyzer job (`scan-build`, referenced
in REQ-GEN-MEM-002's acceptance criterion) reports a false-positive
unreachable-condition or use-after-check finding because it lacks
information available to the author but not expressible in the local
control flow (e.g. a value's range is fixed by a `pkt_buf` invariant
established several calls earlier, or by a `switch` that is exhaustive over
an enum the analyzer does not know is exhaustive), an `assert()` stating
that invariant at the point of use MAY be added specifically to suppress the
false positive, in addition to — never instead of — the runtime invariant
reasoning REQ-GEN-STYLE-009 requires. Such an assert MUST cite, in an
adjacent comment, both the static-analyzer finding it suppresses and the
same invariant/guaranteeing-code justification REQ-GEN-STYLE-009 requires;
an assert added only to quiet the analyzer, without an accompanying runtime-
impossibility justification, MUST NOT be merged, since REQ-GEN-TECH-004
keeps it live at runtime regardless of why it was written.
**Strength:** MAY (add for analyzer guidance) ; MUST (cite the suppressed
finding and the underlying invariant when doing so)
**Status:** DERIVED
**Source:** Maintainer directive (2026-08-30); REQ-GEN-MEM-002 (`scan-build`
CI job)
**Acceptance:** [STYLE] code-review — an `assert()` justified by this
requirement carries a comment naming the specific analyzer warning it
addresses; `scan-build` output before/after is compared in the review to
confirm the assert actually changes the analyzer's finding rather than being
redundant.
**Links:** REQ-GEN-STYLE-009, REQ-GEN-MEM-002

### REQ-GEN-STYLE-011 — radcli2 code MUST read an already-applied config option via its compile-time `id`, never by a string name or with a runtime-supplied default

**Requirement:** Internal radcli2 code — `lib/config.c`, `lib/config2.c`,
`lib/tls.c`, `lib/dae.c`, `lib/sendserver.c`, `lib/request.c`, `lib/aaa2.c`,
`lib/ip_util.c` — MUST read an option whose name is known at compile time
via the `id`-indexed accessor (`rc_conf_int_id()`/`rc_conf_str_id()`,
`lib/options.h`), never via a string-name lookup
(`radcli2_priv_conf_str()`/`radcli2_priv_conf_int()`) and never via a
runtime-default-supplying variant. An option whose effective value needs a
non-zero default when unset MUST have that default materialized into the
config table once, during `radcli2_priv_apply_config()` — never substituted
at read-time by the accessor itself. `lib/legacy/*.c` is exempt: its public
`rc_conf_str()`/`rc_conf_int()`/`rc_add_config()` accept a caller-supplied
name at runtime by their own long-established contract, which is inherently
string-keyed and cannot be expressed as a compile-time `id`.
**Strength:** MUST
**Status:** DERIVED
**Source:** Maintainer directive; `rc_conf_int_def()`'s removal (formerly
`lib/config.c`, a string-keyed lookup with an inline runtime default, used
at exactly the 2 options — `watchdog-interval`, `dae-max-clock-skew` — that
needed one) is what exposed the gap this closes: every other internal
config read already used `rc_conf_int_id()` before this, `rc_conf_int_def()`
was the one inconsistent holdout.
**Acceptance:** [STYLE] negative, local — `grep -n 'radcli2_priv_conf_str(rh, "\|radcli2_priv_conf_int(rh, "\|rc_conf_int_def(' lib/config.c lib/config2.c lib/tls.c lib/dae.c lib/sendserver.c lib/request.c lib/aaa2.c lib/ip_util.c` returns no matches outside the accessor functions' own definitions. [STYLE] positive, local — `tests/ctx.c` confirms `watchdog-interval`'s default is visible via the *public* `radcli_ctx_get_opt_int()` after `radcli_ctx_apply()`, proving the default is materialized in the table rather than substituted only inside whichever internal reader used to supply it (`REQ-CONFIG-CFG-021`).
**Links:** REQ-CONFIG-CFG-021

---

## TEST — test quality requirements

### REQ-GEN-TEST-001 — New features and bug fixes MUST include a test; bug-fix tests MUST fail before the fix

**Requirement:** A new feature MUST include a test under `tests/`. A bug fix
MUST be accompanied by a test that reproduces the bug and is confirmed to fail
against the unmodified code before the fix is applied, and pass after.
**Strength:** MUST
**Status:** DERIVED
**Source:** AGENTS.md ("Coding conventions"; "Requirements-First Workflow");
contrib/ai/personas/radcli-core-dev.md ("Protocol: Testing" — Test-first for
bug fixes)
**Acceptance:** [TEST] local/CI — new/updated test present in `tests/` and
referenced from `.github/workflows/tests.yaml` or `meson.build`'s test list as
applicable.

### REQ-GEN-TEST-002 — "Tests pass" MUST NOT be reported when tests were skipped

**Requirement:** Most tests require root (Linux network namespaces,
`tests/ns.sh`) and a running `radiusd`/`freeradius`, and exit 77 (SKIP) when
those preconditions aren't met. A report of test results MUST distinguish
tests that ran and passed from tests that were skipped; it MUST NOT describe a
run containing skips as simply "passing" without listing which tests were
skipped and why full verification requires CI.
**Strength:** MUST
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Testing" — "Most
tests require root..."); AGENTS.md ("Testing")
**Acceptance:** [TEST] process check — any test-result summary lists ran/passed
vs. skipped separately.

### REQ-GEN-TEST-003 — Negative tests are mandatory for packet validation, Message-Authenticator, and shared-secret handling

**Requirement:** For any change touching packet validation, Message-Authenticator
verification, or shared-secret handling, a negative test (library correctly
rejects a tampered packet, a bad authenticator, or a replayed response) MUST be
written, and MUST be written before the corresponding positive test.
**Strength:** MUST
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Protocol: Testing" —
"Negative tests are the more important half for security code")
**Acceptance:** [TEST] code-review — patch touching these areas includes a
negative test; its absence blocks merge.
**Links:** REQ-GEN-SEC-006, REQ-NET-SEC-* (Message-Authenticator validation,
see `net.md`)

### REQ-GEN-TEST-004 — New server-side test fixtures SHOULD extend `tests/radius-server.py` and run as `${top_builddir}/src/radiusclient`'s peer, not a real `radiusd`/root-only setup

**Requirement:** A new test that needs a RADIUS server to talk to SHOULD reuse
or extend `tests/radius-server.py` (a stdlib-only Python 3 script that crafts
arbitrary/malformed responses) as the server, and MUST drive it with the real
`${top_builddir}/src/radiusclient` binary as the client — the pattern
`tests/msg-auth-tests.sh` already follows — rather than requiring a real
`radiusd`/FreeRADIUS install or `tests/ns.sh`'s root/network-namespace setup,
so the test can run under an unprivileged local user and in unprivileged CI
runners. This is a SHOULD, not a MUST: a test whose entire purpose is
verifying behavior against `tests/ns.sh`'s namespace isolation or against a
real FreeRADIUS server's interoperability quirks has no unprivileged
equivalent and is exempt.
**Strength:** SHOULD
**Status:** DERIVED
**Source:** tests/msg-auth-tests.sh:50,81 (`radius-server.py` +
`${top_builddir}/src/radiusclient` pattern); tests/ns.sh:35,39-40,46,51 (root
requirement, `exit 77` when absent); doc/radius-test-server.md
**Acceptance:** [TEST] code-review — a new test file that spawns a server
process is checked for whether `tests/radius-server.py` could serve instead of
`radiusd`/`ns.sh`; if not, the review records why (namespace- or
FreeRADIUS-specific behavior under test).
**Links:** REQ-GEN-TEST-002 (skip-vs-pass reporting for the root-requiring
tests this is meant to reduce reliance on), REQ-GEN-TEST-005

### REQ-GEN-TEST-005 — `doc/radius-test-server.md` MUST be updated in the same commit whenever `tests/radius-server.py`'s CLI or behavior changes

**Requirement:** A change to `tests/radius-server.py` that adds, removes, or
changes the meaning of a command-line option, or changes how it handles a
packet field (e.g. Message-Authenticator handling modes), MUST update
`doc/radius-test-server.md`'s option table and description in the same
commit. A change that only adds a new *caller* of the existing, unchanged
script (a new test script invoking it with existing options) does not require
a doc update.
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/radius-test-server.md (option table); tests/radius-server.py
**Acceptance:** [TEST] code-review — diff to `tests/radius-server.py` touching
its `argparse`/option handling is checked against `doc/radius-test-server.md`
for a matching update.
**Links:** REQ-GEN-TEST-004

### REQ-GEN-TEST-006 — A test file exercising `radcli2.h` SHOULD use only `radcli_*` entry points, not mix in `radcli.h`'s `rc_*` calls

**Requirement:** A test file whose subject is `radcli2.h`'s API SHOULD reach
every entry point it needs (context construction, dictionary loading, AVP
handling) through `radcli_*` functions, not `rc_*` ones from `radcli.h` --
even though `radcli_ctx` and `rc_handle` name the same underlying object
(`radcli2.h:44,76`; `lib/config2.c:30`) and so are freely interchangeable at
the type level, mixing the two APIs in one test file blurs which API is
actually under test and can silently depend on a legacy-side effect a
radcli2.h-only caller would never get. If a `radcli2.h`-only test needs an
operation with no `radcli_*` equivalent yet, that is a real API gap: add the
missing `radcli_ctx_*`/`radcli_*` entry point (as
`radcli_ctx_read_dictionary_from_buffer()` was added for exactly this,
`REQ-CONFIG2-DATA-002`) rather than reaching for the `rc_*` one.
This is a SHOULD, not a MUST: a test file whose explicit purpose is
validating the `radcli.h`/`radcli2.h` bridge itself -- e.g.
`tests/avp-legacy.c`'s `VALUE_PAIR` projection checks, or `tests/ctx.c`'s
`radcli_ctx`/`rc_handle` identity assertions -- is inherently about both
APIs at once and is exempt.
**Strength:** SHOULD
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Locality of complexity");
this requirement (introduced 2026-08-24, prompted by
`tests/avp-codec-freeradius.c` mixing `rc_new()`/`rc_config_init()`/
`rc_read_dictionary()`/`rc_read_dictionary_from_buffer()` with the
`radcli_*` AVP API)
**Acceptance:** [TEST] code-review — a `radcli2.h` test file's use of an
`rc_*` call is checked for a `radcli_*` equivalent; if one exists, the test
is expected to use it; if not, the review records the gap and either the
missing `radcli_*` entry point is added in the same change or the gap is
tracked explicitly. Swept across the full existing suite 2026-08-24:
`tests/aaa2.c`, `tests/avp.c`, `tests/avp-codec.c`,
`tests/avp-codec-freeradius.c`, `tests/dae.c`, `tests/dae-codec.c`,
`tests/request.c`, `tests/request-freeradius.c` converted to
`radcli_ctx_*` exclusively; `tests/dict.c` split into a `radcli2.h`-pure
file plus legacy-pure `tests/dict-legacy.c`; `tests/avp-legacy.c` and
`tests/ctx.c` remain exempt (the bridge is their explicit subject).
**Links:** REQ-CONFIG2-DATA-002
