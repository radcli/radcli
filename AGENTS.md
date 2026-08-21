# AGENTS.md

This file provides guidance to AI Agents when working with code in this repository.

For maintainer-level work (bug investigation, code review, refactoring, design, release preparation,
or security triage), load the radcli-core-dev persona from
`contrib/ai/personas/radcli-core-dev.md` as a system prompt prefix.

For contributor-level work (preparing a patch, bug fix, or feature as an external contributor),
load the radcli-contributor persona from `contrib/ai/personas/radcli-contributor.md`.

## Project Overview

radcli is a C library for writing RADIUS clients, designed to enable RADIUS authentication and accounting in ~50 lines of C code. It was created for the openconnect VPN server (ocserv) and is source-compatible with freeradius-client and radiusclient-ng. It supports UDP, TCP, TLS (RFC 6614), and DTLS transports.

## Requirements-First Workflow

`doc/requirements/` is the normative description of what radcli must do (see
`doc/requirements/README.md` for the document map, ID scheme, and per-requirement
format). Unlike a multi-process application, radcli has no per-process split —
documents are organized by subsystem (`general.md` for library-wide invariants
such as process-state neutrality and ABI stability; `config.md`, `dict.md`,
`attrs.md`, `net.md`, `util.md` for the corresponding `lib/` source groups). For
any change that alters observable behavior — new feature, bug fix, or
behavior-changing refactor — work in this order:

1. **Requirement first.**
   - Find the requirement(s) covering the area you're changing (search
     `doc/requirements/` for the relevant `REQ-*` IDs, or use the document map to
     find the right file by process/subsystem).
   - If your change alters what an existing requirement describes, **update that
     requirement first**, re-applying the protocol in `contrib/ai/protocols/` that
     generated its document so the new entry matches the rest of the file. Do not
     leave a requirement describing the old behavior once the code changes — but do
     not break other requirements or use-cases in the process (see below). If a
     requirement is independently wrong and needs revising for reasons unrelated to
     this change, do that in its own dedicated merge request instead.
   - If no requirement covers the new behavior, add one in the appropriate document,
     following its existing ID prefix, category tags, and per-requirement format.
   - For bug fixes: if the bug is a violation of an existing requirement, cite its ID
     in the commit/MR. If the bug reveals a gap in the requirements, extend or add a
     requirement describing the *correct* behavior before fixing the code.
2. **Tests second.** Write or update the positive and negative tests implied by the
   requirement's **Acceptance** criteria (see "Testing New Functionality" below)
   *before* touching implementation code. For bug fixes, confirm the new test
   reproduces the bug and fails against the unmodified code.
3. **Code last.** Implement the change so the new/updated tests pass, and so the
   code, the requirement, and the doxygen documentation (where applicable) all agree.

Do not jump straight to step 3 — a code change with no corresponding requirement
update is incomplete, even if it builds and passes existing tests.

### Do not break existing requirements or use-cases

Before submitting a merge request, check that the change does not silently
invalidate requirements or use-cases other than the one you set out to change:

- Search `doc/requirements/` for `REQ-*` entries citing the files,
  functions, or config options you touched, and confirm each still holds. If one no
  longer holds, either your change is wrong, or that requirement was wrong to begin
  with (mark it `REVIEW` if unsure which) — never leave code and a `DERIVED`
  requirement contradicting each other.
- A requirement that's wrong for reasons unrelated to your change belongs in its own
  dedicated merge request — with rationale and evidence it doesn't break other
  use-cases — not bundled into this one.
- Run the full local test suite (`ninja -C build test`), not just the test for the
  area you changed — requirements frequently span files and a regression often shows
  up as a failure in a test you didn't expect to touch.

### Agent-runnable — verify before declaring a change complete

- [ ] Requirement cited (existing `REQ-*` ID) or added/updated for this
      change (see "Requirements-First Workflow" above)
- [ ] New feature or bug fix has a test under `tests/`; bug-fix test confirmed
      to fail against the unmodified code first (`REQ-GEN-TEST-001`)
- [ ] `ninja -C build` succeeds with `-Wall -Werror` and no new warnings
- [ ] Relevant test passes: `meson test -C build <test-name>` (root/`radiusd`
      tests may SKIP locally — report skips explicitly, don't call it a pass;
      see `REQ-GEN-TEST-002`)
- [ ] Full suite run where feasible: `ninja -C build test` / `sudo meson test -C build`
- [ ] Existing `doc/requirements/` entries citing the files/functions you
      touched still hold (none silently contradicted)
- [ ] If `include/radcli/radcli.h` or `lib/radcli.map` changed: `ninja -C build
      compare-exported` and `ninja -C build abi-check` both pass, and any
      intentional addition updated `devel/ABI-x86_64.dump` via `ninja -C build
      abi-dump` in the same commit (`REQ-GEN-ABI-001`/`002`)
- [ ] Every changed line is relevant to the change — no drive-by refactoring;
      note any adjacent improvement you noticed in the PR description instead
      of bundling it into the patch
- [ ] Commit message matches "Commit messages" below (crisp title, no body
      unless the *how* is non-obvious) and every comment added/touched in the
      diff matches the "Comments" rule under "Coding conventions" (explains a
      non-obvious *why*, doesn't restate the code) — re-read the diff against
      both before declaring the change complete

### Commit messages

- Crisp and focused on what was fixed or added — not a narration of the work.
- Title alone must give a complete overview: what was fixed/added, without needing
  the body to make sense.
- Body: no details beyond *what*, unless the *how* is genuinely unusual or
  non-obvious (i.e. not what a reader would expect from the title) — in that case,
  add a single sentence on the how. Otherwise, leave the body empty or omit it.
- `Resolves: #NNN` when the commit closes a GitHub issue (recommended, not mandatory).

### Human-judgment required — flag in the PR, do not decide unilaterally

- Any change that adds process-wide state ownership (signal handler, `fork()`,
  self-initiated thread, global timer) — `REQ-GEN-SEC-001..003`
- Any new library-owned global/`static` mutable state beyond the documented
  `radcli_debug` exception — `REQ-GEN-SEC-005`
- Any ABI-breaking change (symbol removal, incompatible signature/struct
  change) — requires a deliberate `LIBMAJOR` bump decision
- Any new external dependency
- TLS or DTLS behavior changes (cipher selection, version negotiation,
  certificate/hostname verification)
- Changes to Message-Authenticator or Response-Authenticator handling, or
  shared-secret storage/comparison

## Build System

Uses Meson.

```bash
# First time setup + build
meson setup build
ninja -C build

# Install
ninja -C build install

# Validate distribution tarball (also runs compare-exported + abi-check, see below)
meson dist -C build
```

Required Fedora/RHEL dependencies:
```
dnf install -y meson ninja-build nettle-devel gnutls-devel libabigail doxygen doxy2man
```

Key `meson setup` options (`-Doption=value`):
- `-Dtls=disabled` — disable TLS/DTLS (GnuTLS dependency). Note: this also
  drops `rc_memcmp()`'s constant-time compare (`gnutls_memcmp()`) for
  Response Authenticator/Message-Authenticator verification, falling back to
  plain `memcmp()` — a documented, accepted timing side-channel in this build
  mode (`REQ-NET-SEC-010`).
- `-Dnettle=disabled` — disable nettle (falls back to bundled MD5/HMAC)
- `-Dlegacy-compat=true` — install freeradius-client/radiusclient-ng compat headers and `.so` symlinks
- `-Ddocs=disabled` — skip Doxygen/doxy2man man page generation

## Source Layout

```
lib/          — library implementation (config.c, sendserver.c, tls.c, avpair.c,
                dict.c, buildreq.c, aaa_ctx.c, util.c, log.c, ip_util.c, ...)
include/radcli/radcli.h   — public API
include/radcli/version.h  — generated version header
lib/radcli.map            — exported symbol versions (ABI control)
devel/ABI-x86_64.dump     — saved ABI reference for abi-check
etc/          — installed dictionary files and sample config (radiusclient.conf,
                radiusclient-tls.conf, servers, servers-tls, dictionary.*)
src/          — command-line utilities (radiusclient, radacct, radembedded, etc.)
doc/          — Doxygen-generated man pages and HTML
tests/        — test scripts and C unit tests
```

## Testing

Tests require root (network namespaces) and a running `radiusd` / `freeradius` in PATH.

```bash
# Run all tests
sudo meson test -C build

# Run a single test script manually (from the build directory)
cd tests && srcdir=../tests ../tests/tls-tests.sh

# Run the C unit tests (these do NOT require root or radiusd)
./build/tests/avpair
./build/tests/dict
./build/tests/dict-add   # only built when GnuTLS is enabled
```

Tests use Linux network namespaces (`tests/ns.sh`) to create isolated client/server namespaces with veth pairs. Tests skip (exit 77, reported as SKIP by `meson test`) when not run as root, or when `radiusd`/`freeradius` is absent. TLS tests (`tls-tests.sh`, `tls-idle-restart-tests.sh`, `close-notify-tests.sh`) also need port 2083 to be ready and only build/run when GnuTLS is enabled.

Shell test scripts are in `tests/`; see `tests/*.sh` for the full list.

### ABI checks

```bash
ninja -C build abi-check        # compare against saved ABI dump
ninja -C build abi-dump         # update the reference ABI dump (devel/ABI-x86_64.dump)
ninja -C build compare-exported # verify headers and radcli.map export the same symbols
```

## Architecture

### Request flow

```
Application
  → rc_read_config()          # parse config, init transport (incl. TLS handshake)
  → rc_avpair_add()           # build VALUE_PAIR attribute list
  → rc_auth() / rc_acct()     # high-level helpers
      → rc_aaa()              # builds SEND_DATA, iterates server list
          → rc_send_server()  # packs packet, calls sfuncs->sendto/recvfrom
```

### Key data structures

- **`rc_handle` (`struct rc_conf`)** — opaque per-application context. Holds parsed config, dictionary, internal socket vtable (`rh->so`), and socket type (`rh->so_type`: UDP/TCP/TLS/DTLS).
- **`VALUE_PAIR`** — singly-linked list of RADIUS attributes. The `attribute` field is 64-bit: upper 32 bits = vendor ID, lower 32 bits = attribute ID. Use `VENDOR()` and `ATTRID()` macros to decompose.
- **`SEND_DATA`** — per-request context (server, port, secret, timeout, retries, send/recv `VALUE_PAIR` lists).
- **`RC_AAA_CTX`** — captures the secret and request authenticator vector from a completed request, enabling idempotent retries.
- **`rc_sockets_override` (`rh->so`)** — vtable of function pointers (`get_fd`, `close_fd`, `sendto`, `recvfrom`, `lock`, `unlock`). Internal-only: no public function sets or exposes it to a caller-supplied vtable; it is populated solely by `rc_apply_config()`/`rc_init_tls()` from radcli's own UDP/TCP tables or the GnuTLS wrappers in `lib/tls.c` (`REQ-NET-NET-002`).

### Transport abstraction (`lib/sendserver.c` + `lib/tls.c`)

All network I/O goes through `rh->so` function pointers, set by `rc_apply_config()` (called from `rc_read_config()`):
- UDP: `default_socket_funcs` — standard `sendto`/`recvfrom`
- TCP: `default_tcp_socket_funcs`
- TLS/DTLS: `tls_sendto` / `tls_recvfrom` wrappers around GnuTLS

**TLS reconnection** (`lib/tls.c`): The `tls_st` struct holds a persistent GnuTLS session. When a send or receive fails, `need_restart` is set. The next `tls_sendto()` call triggers `restart_session()`, which re-establishes the connection. `restart_session()` has a `TIME_ALIVE` (120s) time guard to throttle reconnection attempts.

`rc_check_tls(rh)` — call periodically from application threads to proactively detect dead sessions via heartbeat and reconnect. **ocserv does not call this**, which means idle session closure is only detected on the next request.

### Dictionary

Loaded from the `dictionary` config option. Attribute names map to numeric IDs via `DICT_ATTR` / `DICT_VALUE` / `DICT_VENDOR` linked lists hanging off `rc_handle`. Vendor-specific attributes use PEN-scoped IDs via `VENDOR_BIT_SIZE`. The dictionary is compiled into the library as a C string literal (generated from `etc/dictionary` at build time); applications that use only RFC-defined attributes need not ship a dictionary file. A custom dictionary can still be specified via the `dictionary` config option to extend or override the built-in one.

### ABI stability

Exported symbols are controlled by `lib/radcli.map`. When adding public functions, add them to the map **and** update `include/radcli/radcli.h`. Run `ninja -C build compare-exported` to validate consistency.

## CI

Six jobs run on every push (`.github/workflows/tests.yaml`):
- **static-analyzer** — clang static analysis (`scan-build`)
- **tests-asan** — build + `sudo meson test` with `-Db_sanitize=address`
- **tests-ubsan** — build + `sudo meson test` with `-Db_sanitize=undefined` plus extra sanitizer flags
- **tests** — standard build, `sudo meson test`, `ninja abi-check`, `ninja compare-exported`, `meson dist`
- **tests-msan** — clang build + `sudo meson test` with `-Db_sanitize=memory` (`-Dtls=disabled -Dnettle=disabled` to avoid uninstrumented external libs)
- **tests-notls** — build + `sudo meson test` with `-Dtls=disabled`

## Coding conventions

- C99, BSD 2-clause license for new files
- All public functions prefixed `rc_`, macros in `UPPER_CASE`
- Doxygen comments on all public API (`@param`, `@return`, `@defgroup`)
- Comments: prefer self-documenting code (meaningful names, short single-purpose
  functions) over comments. Where used, a comment should explain something not
  obvious from the code itself — a non-obvious constraint, the reason for an
  otherwise-surprising choice — not restate what the code already says. Code
  that implements a specific protocol behavior (e.g. an RFC 2865/2866/5176/6614
  requirement) must say which spec/section it implements, so a reader can verify
  the implementation against the source document.
- Compile with `-Wall -Werror`; CI runs ASan and UBSan as separate jobs
- New features must include a test; see `tests/` and `.github/workflows/tests.yaml`

## Personas

For extended AI-assisted workflows, load the appropriate persona as a system prompt
prefix before starting work.

- **Maintainers** (bug investigation, code review, refactoring, design):
  `contrib/ai/personas/radcli-core-dev.md`

- **External contributors** (feature additions, bug fixes, security fixes):
  `contrib/ai/personas/radcli-contributor.md`

These personas embed project-specific protocols for anti-hallucination, memory safety,
security vulnerability taxonomy, exhaustive path tracing, stack lifetime hazards, and
self-verification.
