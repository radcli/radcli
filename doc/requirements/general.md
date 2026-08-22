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
  - .github/workflows/tests.yaml
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
behavior (e.g. TLS reconnection throttling, request retries) MUST be
implemented with per-call state (timestamps stored in `rh`/`tls_st`/`SEND_DATA`)
and `select()`/`poll()`-style waits scoped to the call in progress, never a
mechanism that could fire a signal into caller code unrelated to radcli.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Process-state neutrality");
verified — no `alarm(`/`setitimer(` call exists in `lib/*.c`. Compare
`lib/tls.c`'s `TIME_ALIVE` reconnection throttle, which is implemented as a
stored timestamp comparison, not a signal-based timer.
**Acceptance:** [SEC] negative, local — `grep -n 'alarm(\|setitimer(\|timer_create(' lib/*.c`
returns no matches.
**Links:** REQ-NET-* (TLS restart throttling, see `net.md`)

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
headers) MUST NOT be added. Two pre-existing instances are accepted,
maintainer-reviewed exceptions and MUST NOT be treated as precedent for
adding further global state:
  - `radcli_debug` (`lib/log.c:14`, declared `extern` in `lib/util.h:93`, set
    from `lib/config.c:760` and read from `lib/sendserver.c:666`) — a single
    debug-verbosity flag with no correctness impact.
  - `_initialized` (`lib/config.c:1182`, `static int`) — a process-wide
    reference count guarding GnuTLS global init/deinit idempotency across
    multiple `rc_handle` instances in one process. Accepted because it only
    guards one-time process-wide init/deinit calls; see `REQ-CONFIG-SEC-004`
    in `config.md`.

`rc_mksid()`'s `static char buf[15]`/`static unsigned short int cnt`
(`lib/util.c:105-106`) is a third pre-existing instance, also accepted as-is:
the function is marked `@deprecated` in its own Doxygen comment, and the
non-reentrancy/cross-instance-sharing hazard this implies is an accepted,
documented property of a deprecated function rather than something requiring
a code change. See `util.md`'s Phase 5 gap analysis for the full citation.

All correctness-relevant state MUST live in a caller-owned handle
(`rc_handle`, `SEND_DATA`, `RC_AAA_CTX`, `tls_st`), so that two `rc_handle`
instances in the same process (or the same instance used from multiple
threads under caller-provided synchronization) do not silently interfere with
each other.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** contrib/ai/personas/radcli-core-dev.md ("Process-state neutrality");
lib/log.c:14; lib/util.h:93,95; lib/config.c:760,1182; lib/sendserver.c:666;
lib/util.c:105-106
**Acceptance:** [SEC] code-review — every new `static` non-`const` file- or
function-scope variable or new `extern` global declared in a header MUST be
justified in the same terms as the three accepted exceptions above (no
correctness impact beyond one-time process-wide init, no cross-`rc_handle`
interference for correctness-relevant state) or rejected.
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
generators; any RADIUS protocol field derived from one (packet identifier,
Request Authenticator, any value an off-path attacker could otherwise brute
force or predict from `time()`/`getpid()`) weakens response spoofing and
replay resistance, since guessing the next value narrows an attacker's search
space independently of the shared secret. Any code path that needs a random
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
reviewed addition, `ninja -C build abi-dump` updates the reference dump in the
same commit as the symbol addition.
**Links:** REQ-GEN-ABI-001

### REQ-GEN-ABI-003 — `include/radcli/radcli.h` public declarations carry Doxygen documentation

**Requirement:** Every public function declared in `include/radcli/radcli.h`
MUST have a Doxygen comment block with `@param` for each parameter and
`@return` describing the return value/error convention, grouped under a
`@defgroup` (one group per source file), so the generated man pages
(`doc/man/`) stay in sync with the header.
**Strength:** MUST
**Status:** DERIVED
**Source:** AGENTS.md ("Coding conventions"); contrib/ai/personas/radcli-core-dev.md
("Protocol: Change Propagation" — Group 1)
**Acceptance:** [STYLE] local — `ninja -C build` with `-Ddocs=enabled` (default)
regenerates man pages without Doxygen warnings for the changed header section.
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
