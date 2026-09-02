---
title: radcli2.h transport/request-reply entry point (radcli_request_new()/_perform()/etc.)
generator: requirements-from-implementation
id-prefix: REQ-NET2
categories:
  INIT: radcli_request_new/_free construction and destruction, and server/type/secret selection
  NET: radcli_ctx_get_poll()/_dispatch() — descriptor exposure and
    validation-before-delivery, shared infrastructure serving DAE and
    RADCLI_REQUEST_SENDONLY traffic alike
  SEND: radcli_request_perform packet construction (Access-Request vs Accounting-Request)
  RECV: radcli_request_perform reply handling, and the radcli_request_code/_attrs/_server accessors
  ERR: rejection and failure-mapping contracts
  AAA: radcli_aaa autofill and multi-server fail-over
sources:
  - lib/request.c
  - lib/aaa2.c
  - include/radcli/radcli2.h
  - lib/radcli2.map.in
  - lib/sendserver.c (radcli_transport_exchange(), shared transport core; and
    the RADCLI_REQUEST_SENDONLY request registry/persistent socket)
  - lib/dae.c (radcli_ctx_get_poll()/_dispatch() implementation; the
    DAE-specific validation steps built atop it are cited not owned — see
    dae.md)
  - doc/requirements/config2.md (radcli_ctx construction and option storage, cited not owned)
  - doc/requirements/dae.md (the DAE-specific validation steps —
    source-address check, Request/Message-Authenticator, Event-Timestamp,
    duplicate suppression — that REQ-NET2-NET-002's pipeline invokes, and the
    DAE listener descriptor REQ-NET2-NET-001 reports alongside the
    request-registry one; cited not owned)
---

# radcli2.h Transport/Request-Reply Requirements

This document covers the `radcli_request_*` entry point in `lib/request.c`/
`include/radcli/radcli2.h`: constructing a request from configuration and a
`radcli_avp_list` (`radcli_request_new()`), sending it and awaiting the reply
(`radcli_request_perform()`), reading the outcome (`radcli_request_code()`,
`radcli_request_attrs()`, `radcli_request_server()`), and releasing it
(`radcli_request_free()`). It is the `radcli2.h` counterpart to `net.md` — both
document a full send/retry/receive/verify cycle built on the same
`radcli_transport_exchange()` core (`lib/sendserver.c`), `net.md` for the
legacy `rc_send_server()`/`rc_send_server_ctx()` entry point and this document
for `radcli_request_perform()` — but the two share no other source, no
lifecycle, and no ABI-versioning history (`radcli_request_*` symbols are new
additions to `lib/radcli2.map`'s single version node, not migrations of
existing ones). Both take a `radcli_ctx` built via `config2.md`'s
`radcli_ctx_new()`/`_read_config()`/`_apply()` as a given — this document
treats `radcli_ctx` construction as out of scope and reads option values
from it only through the internal `radcli2_priv_conf_*` accessors
(`lib/config.c`). `radcli_request_new()`/`_perform()` themselves do no
NAS-Port/Acct-Delay-Time auto-filling and no multi-server failover — see
`REQ-NET2-INIT-003` — that gap is `attrs.md`'s counterpart's job
(`rc_auth()`/`rc_acct()`/`rc_aaa_ctx()`) on the legacy side, and this
document's own `radcli_aaa()` (`lib/aaa2.c`, `AAA` category below) on the new
API side: a higher-level wrapper over `radcli_do_exchange()` (the packet-build/
transport-exchange primitive `radcli_request_perform()` itself is built from,
lib/request.c), added specifically because `radcli_request_new()`'s
single-server contract is by design and not going to change.

**Out of scope, owned elsewhere:** `radcli_transport_exchange()` itself
(declared in `include/includes.h`, not exported via `lib/radcli2.map`) is the
shared low-level send/retry/receive core for *both* this document's API and
`rc_send_server_ctx()`'s; its own contract (address fail-over, Response
Authenticator / Message-Authenticator verification, retry/timeout accounting)
is stated in full by `net.md` (REQ-NET-NET-009/018, REQ-NET-SEC-001 through
-015, REQ-NET-TEARDOWN-001 through -005) and only cited below where this
API's behavior depends on it. `radcli_avp_encode()`/`radcli_avp_decode()`
(the wire codec this API calls into) are likewise stated in full by
`avp2.md` (REQ-AVP2-DATA-026 through REQ-AVP2-ERR-032), cited below only
where this document's own behavior depends on them.

---

## INIT — construction and destruction

### REQ-NET2-INIT-001 — radcli_request_new validates ctx and code before touching configuration

**Requirement:** `radcli_request_new()` MUST return `NULL` without side
effects if `ctx` is `NULL`, or if `code` is neither `RADCLI_CODE_ACCESS_REQUEST`
nor `RADCLI_CODE_ACCOUNTING_REQUEST`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:79-86
**Acceptance:** [INIT] unit, local — `tests/request.c` calls
`radcli_request_new(NULL, RADCLI_CODE_ACCESS_REQUEST, send_list)` and
`radcli_request_new(ctx, (radcli_code)0, send_list)` and confirms both return
`NULL`.
**Links:** REQ-NET2-ERR-010

### REQ-NET2-INIT-002 — request type/server-option selection matches rc_select_aaa_server()'s TLS/DTLS rule

**Requirement:** `radcli_request_new()` MUST select the `"authserver"` option
and `AUTH` type when `code` is `RADCLI_CODE_ACCESS_REQUEST`, OR when the
handle's transport is `RC_SOCKET_TLS`/`RC_SOCKET_DTLS` (which carry both
request types over one connection to `authserver`); otherwise (a non-TLS/DTLS
Accounting-Request) it MUST select `"acctserver"` and `ACCT`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:88-98 (comment explicitly cross-references
`rc_select_aaa_server()`, lib/buildreq.c)
**Acceptance:** [INIT] unit, local — construct a handle with `so_type` forced
to `RC_SOCKET_TLS` and only `"authserver"` configured, call
`radcli_request_new()` with `RADCLI_CODE_ACCOUNTING_REQUEST`, confirm it
succeeds (i.e. did not look for `"acctserver"`).
**Links:** REQ-ATTR-* (rc_select_aaa_server()'s own requirement, attrs.md)

### REQ-NET2-INIT-003 — a request carries exactly one server; extra configured entries only warn

**Requirement:** `radcli_request_new()` MUST use only the first entry
(`servers->name[0]`/`port[0]`/`secret[0]`) of the resolved `"authserver"`/
`"acctserver"` configuration, regardless of how many entries are configured.
If more than one entry is configured, it MUST log at `LOG_WARNING` (not treat
it as an error), so a caller migrating a legacy multi-server config one entry
point at a time is not broken by the leftover entries.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:100-117 (comment: "By design, the new API carries
one server per handle...")
**Acceptance:** [INIT] unit, local — configure two `"authserver"` entries,
call `radcli_request_new()`, confirm `radcli_request_server()` on the result
equals the *first* configured name, and (if the test harness captures log
output) that a `LOG_WARNING` was emitted.
**Links:** REQ-NET2-RECV-009

### REQ-NET2-INIT-004 — no server configured for the selected type is a hard failure

**Requirement:** `radcli_request_new()` MUST return `NULL` if `rc_conf_srv()`
for the selected option returns `NULL` or an empty (`max == 0`) list.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:100-104
**Acceptance:** [INIT] unit, local — `tests/request.c`'s construction with no
`"authserver"`/`"acctserver"` configured confirms `radcli_request_new()`
returns `NULL`.

### REQ-NET2-INIT-005 — send is deep-copied; caller's list may be freed or reused immediately after the call

**Requirement:** `radcli_request_new()` MUST copy every attribute of `send`
(by definition and raw bytes, via `radcli_avp_get_bytes()`/`radcli_avp_add_bytes()`)
into request-owned storage before returning, so the caller may free or mutate
`send` immediately after the call returns without affecting a later
`radcli_request_perform()`. On a copy failure (allocation, or a rejected
`radcli_avp_add_bytes()` call) it MUST free the partial copy and return `NULL`
without allocating the request object.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:119-142; contract restated in include/radcli/radcli2.h's
`radcli_request_new()` doc comment ("send may be freed or reused by the
caller immediately after this call returns")
**Acceptance:** [INIT] unit, local — build a `send_list`, call
`radcli_request_new()`, immediately `radcli_avp_list_free(send_list)`, then
confirm the returned request is still usable (e.g. `radcli_request_server()`
succeeds; a full `radcli_request_perform()` round trip is covered by
`tests/request-freeradius.c` instead, since it needs a live server).

### REQ-NET2-INIT-006 — timeout/retries are read from configuration at construction time, not at perform time

**Requirement:** `radcli_request_new()` MUST capture `"radius_timeout"` and
`"radius_retries"` (`rc_conf_int()`) into the request at construction time;
`radcli_request_perform()` MUST use those captured values, not re-read
configuration.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:151-152 (capture), lib/request.c:218-219 (use)
**Acceptance:** [INIT] unit, local — construct a request, then change
`"radius_timeout"` in the handle's configuration, and confirm (by code
inspection / a mock transport) that the original value is what
`radcli_transport_exchange()` receives.

### REQ-NET2-INIT-007 — radcli_request_free is a matched release; NULL is a valid no-op

**Requirement:** `radcli_request_free()` MUST release the request's copied
`send` list, its decoded `reply_attrs` list (if any), scrub the copied secret
(`memset` before `free()`), and free the request itself; it MUST accept `NULL`
as a no-op.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:268-276
**Acceptance:** [INIT] unit, local — `tests/request.c` frees a constructed
request and calls `radcli_request_free(NULL)`, confirming no crash (ASan/UBSan
clean, per `REQ-GEN-MEM-*`).
**Links:** REQ-GEN-MEM-001

---

## NET — descriptor exposure and validated dispatch

### REQ-NET2-NET-001 — radcli exposes ctx's descriptor(s) and never drives a loop

**Requirement:** `radcli_ctx_get_poll(ctx, pfds, max_pfds, &nfds, &timeout_ms)`
MUST fill the caller-supplied `pfds` array (capacity `max_pfds`, MUST be at
least `RADCLI_CTX_MAX_POLLFDS` == 2, else the call fails) with the
descriptor(s) to watch and the direction(s) to watch each in, report how many
of them it used in `*nfds` (0 if there is nothing to watch yet), and radcli
MUST NOT call `poll()`, `select()`, `epoll_wait()`, or sleep on the caller's
behalf, so that any event loop (libev, libevent, epoll, plain `poll()`) can
host it. For TLS/DTLS, or for a UDP `ctx` with no `radcli_dae` active, this is
always exactly one descriptor: the session fd (TLS/DTLS, also carrying any
in-flight `RADCLI_REQUEST_SENDONLY` request traffic, REQ-NET2-SEND-013/016)
or the request-registry socket (UDP, REQ-NET2-SEND-016). A UDP `ctx` with an
active `radcli_dae` reports a second, independent descriptor for the DAE
listener alongside it — the two are genuinely different local sockets/ports
(dae.md's REQ-DAE-INIT-002) and cannot be merged into one without changing
the wire protocol; two is the maximum this API ever needs.

`radcli_ctx_dispatch()` reads whatever is ready — and, for the request-socket
and watchdog-deadline cases, transmits when due (REQ-NET2-SEND-013,
watchdog.md's REQ-WATCHDOG-NET-001) — without needing to know which of the
(up to two) descriptors `poll()` actually reported ready: like the pre-existing
DAE-socket path, it always attempts a non-blocking operation per slot and
tolerates "nothing there" (`EAGAIN`), so the caller never has to demultiplex
by hand. Once packet validation lands (REQ-NET2-NET-002), it demultiplexes and
invokes the registered `radcli_dae_handler`. There is deliberately no
per-object descriptor accessor (no `radcli_dae_fd()`, no per-`radcli_request`
one either — REQ-NET2-SEND-013): descriptors belong to the `radcli_ctx`, so
that a transport sharing one descriptor between DAE and ordinary requests
(already true for TLS/DTLS) never leaves an application holding a watcher on
a descriptor that silently starts meaning something else.
**Strength:** MUST
**Status:** DERIVED
**Source:** REQ-GEN-SEC-003
**Acceptance:** [NET] positive, unit, local — `tests/dae.c`: `radcli_ctx_get_poll()` reports `*nfds == 0` before `radcli_dae_start()` and after `radcli_dae_free()` (UDP, no in-flight requests), and a valid, `POLLIN`-watched descriptor in between; no polling symbol appears in `lib/dae.c`. `src/raddaeserver.c` is a real plain-`poll()`-loop application built on exactly this contract, driven end to end by `tests/dae-tests.sh`/`tests/dae-client.py`. [NET] positive, unit, local — `tests/request-poll-multi.c`: a UDP `ctx` with both an active `radcli_dae` and several in-flight `RADCLI_REQUEST_SENDONLY` requests reports exactly two descriptors (`*nfds == 2`), not one per request.
**Links:** REQ-GEN-SEC-003, REQ-DAE-NET-003, REQ-NET2-SEND-013, REQ-NET2-SEND-016, REQ-WATCHDOG-NET-001

### REQ-NET2-NET-002 — validation completes before the application sees a request

**Requirement:** `radcli_ctx_dispatch()` MUST perform, in order, the source-address
check, Request Authenticator verification, Message-Authenticator verification when
that attribute is present, the Event-Timestamp freshness check, and duplicate
suppression, and MUST NOT invoke the registered `radcli_dae_handler` unless all of
them pass, so that an application never has to implement RADIUS validation itself,
and never receives a request object that has not fully passed validation
(strengthened over an app-called receive function, which could in principle be
called on a partially validated result: this API has no such public
entry point at all).
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §§2.3, 3, 6.3
**Acceptance:** [NET][SEC] negative, unit, local — `tests/dae-codec.c` sends a bad Request Authenticator, a bad Message-Authenticator, a stale Event-Timestamp, and a request from an unauthorized source (a second handle whose `dae-server` excludes the only address the test can send from) and confirms none reaches the handler and none gets a reply. `tests/dae-tests.sh` repeats the same checks end to end against `src/raddaeserver.c`, driven by `tests/dae-client.py`.
**Links:** dae.md's REQ-DAE-SEC-001 … REQ-DAE-SEC-005

---

## SEND — packet construction

### REQ-NET2-SEND-008 — Access-Request uses a random Request Authenticator and carries Message-Authenticator

**Requirement:** For `RADCLI_CODE_ACCESS_REQUEST`, `radcli_request_perform()`
MUST fill the Request Authenticator with `rc_get_random_bytes()` output (not a
predictable value), encode attributes with `radcli_avp_encode()`
reserving `2 + MD5_DIGEST_SIZE` bytes, and append a Message-Authenticator
attribute via `add_msg_auth_attr()` before transmission — mirroring
`rc_send_server_ctx()`'s non-accounting path so the two share one proven
implementation of this framing, not a second copy. This mirroring extends to
*which* secret keys that HMAC: for a TLS/DTLS `authserver`, that MUST be the
RFC 6614/7360 fixed RadSec secret, exactly as `rc_send_server_ctx()` already
resolves it (`REQ-NET2-SEND-015`) — until fixed, `radcli_encode_request()`
used whatever secret was configured (empty, ordinarily) instead, a real
divergence this requirement's own text did not previously flag.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:202-216; cf. lib/sendserver.c:1051-1062
(`rc_send_server_ctx()`'s equivalent branch)
**Acceptance:** [SEND] interoperability, root+FreeRADIUS —
`tests/request-freeradius.c`'s Access-Request/Access-Accept check (needs
Message-Authenticator to be accepted by a real FreeRADIUS server).
**Links:** REQ-NET-SEC-* (net.md's Message-Authenticator requirements), REQ-NET2-SEND-015

### REQ-NET2-SEND-009 — Accounting-Request Authenticator is MD5(header+zero-vector+attrs+secret)

**Requirement:** For `RADCLI_CODE_ACCOUNTING_REQUEST`,
`radcli_request_perform()` MUST encode attributes against an all-zero vector,
then compute the transmitted Request Authenticator as
`rc_md5_calc()` over the fully-assembled header+attributes followed by the
shared secret (secret truncated to `MAX_SECRET_LENGTH` if longer), per RFC
2866 — mirroring `rc_send_server_ctx()`'s accounting path.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:179-201; cf. lib/sendserver.c:1029-1041
**Acceptance:** [SEND] interoperability, root+FreeRADIUS —
`tests/request-freeradius.c`'s Accounting-Request/Accounting-Response check
(a server that recomputes and rejects a mismatched Authenticator would fail
this test).

### REQ-NET2-SEND-010 — the request ID's source depends on whether the request shares ctx's persistent socket

**Requirement:** `radcli_encode_request()` (lib/request.c, shared by every
call path: the blocking `flags == 0` path via `radcli_do_exchange()`/
`radcli_transport_exchange()`, `radcli_aaa()`, and `RADCLI_REQUEST_SENDONLY`)
takes the packet's `id` octet as a required parameter and MUST use exactly
the value passed — it does not draw one itself, so each call site is
responsible for stating explicitly where its `id` comes from. The blocking
path and `radcli_aaa()` MUST pass an `id` drawn from `rc_get_random_byte()`
(lib/rc-random.c, dispatching to `gnutls_rnd()`/`getentropy()`), never from
`random()`/`rand()` (REQ-GEN-SEC-007's ban on weak PRNGs): each of those
gets its own per-call socket via `radcli_transport_exchange()`
(REQ-NET2-SEND-016's scope note), so no other concurrently in-flight request
can collide with it and a CSPRNG-random value is sufficient. For
`RADCLI_REQUEST_SENDONLY` specifically, `radcli_request_perform()` MUST pass
the Identifier `ctx`'s in-flight registry already reserved for it
(REQ-NET2-SEND-016's LRU allocation, reserved *before* this call — never
patched into the wire packet afterward, since `id` is itself covered by the
Message-Authenticator HMAC), since that request shares `ctx`'s persistent
socket with every other concurrently in-flight `RADCLI_REQUEST_SENDONLY`
request and needs the registry's collision-freedom and RFC 5080 §2.1.1
reuse-cooldown property, which a random draw does not provide. Neither RFC
2865 §3 nor RFC 5080 requires the Identifier itself to be unpredictable —
RFC 5080 §2.1.1 recommends LRU (rotating, not random) allocation for its
own, unrelated reason (minimizing stale-duplicate misattribution); see
REQ-NET2-SEND-016.
**Strength:** MUST
**Status:** DERIVED — narrowed 2026-09-01: neither RFC 2865 nor RFC 5080
requires the Identifier to be unpredictable, so `RADCLI_REQUEST_SENDONLY`'s
Identifier comes from LRU allocation, not a CSPRNG draw; see `general.md`'s
REQ-GEN-SEC-007, narrowed alongside this.
**Source:** lib/request.c (`radcli_encode_request()`'s `id` parameter and
its call sites); RFC 2865 §3; RFC 5080 §2.1.1
**Acceptance:** [SEND] unit, local — a request performed with `flags == 0`
or via `radcli_aaa()` is confirmed to still carry a `rc_get_random_byte()`-
sourced `id` (statistical/uniqueness testing `Needs-domain-check`, as
before). [SEND] unit, local — a `RADCLI_REQUEST_SENDONLY` request's `id` on
the wire is confirmed to equal the Identifier `radcli_ctx_get_poll()`/the
registry assigned it (REQ-NET2-SEND-016's acceptance), not an independent
random draw.
**Links:** REQ-GEN-SEC-007, REQ-NET2-SEND-016

### REQ-NET2-SEND-011 — a request may be performed at most once, regardless of flags

**Requirement:** `radcli_request_perform()` MUST return `RADCLI_ERROR`
immediately, without sending anything, if called on a request that has
already been performed (`r->performed` already set, regardless of which
`flags` value the prior call used) or if `r` is `NULL`. A caller needing a
retransmission with different content MUST construct a new
`radcli_request` via `radcli_request_new()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:306-308 (`radcli_request_perform()` checks/sets
`r->performed` before branching on `flags`); contract restated in
`include/radcli/radcli2.h`'s doc comment ("May be called only once per
request")
**Acceptance:** [SEND] unit, local — `tests/request.c` calls
`radcli_request_perform(r, 0)` twice on the same request (second call
without network access available) and confirms the second returns
`RADCLI_ERROR` without hanging or crashing; a second test constructs a
request, calls `radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)`, then
confirms both a second `radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)`
call and a `radcli_request_perform(r, 0)` call on the same (now-performed)
request return `RADCLI_ERROR`.
**Links:** REQ-NET2-ERR-012, REQ-NET2-SEND-012

### REQ-NET2-SEND-012 — RADCLI_REQUEST_SENDONLY transmits once, without blocking for a reply

**Requirement:** `radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)` MUST
build the same wire packet the default (`flags == 0`) call would (shared
`radcli_encode_request()` helper, same Request/Accounting-Request
Authenticator and Message-Authenticator rules as
REQ-NET2-SEND-008/009/010), then call `radcli_transport_send_async()` — a
single transmission to the first resolved address only (no DNS-level
fail-over, unlike the default flags), leaving the socket open rather than
closing it immediately. It MUST return `RADCLI_OK` once the packet is
handed to the socket layer, `RADCLI_ERROR` on any earlier failure (name
resolution, packet encoding, or the send itself), and MUST NEVER return
`RADCLI_TIMEOUT` (`radcli_request_perform()` itself never blocks for a
reply under this flag). `r->reply_code` and `r->reply_attrs` MUST remain
unchanged until (and unless) a later `radcli_ctx_dispatch()` call resolves
`r` (see REQ-NET2-SEND-013). This flag serves two distinct caller
patterns without a second flag or a second entry point: fire-and-forget
(call `radcli_request_free()` without ever calling `radcli_ctx_dispatch()`
— see REQ-NET2-SEND-014) and poll-driven async request/reply (drive
`radcli_ctx_get_poll()`/`radcli_ctx_dispatch()` — REQ-NET2-NET-001 —
to completion, reading the outcome with `radcli_request_done()`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:298-359 (`radcli_request_perform()`'s
`RADCLI_REQUEST_SENDONLY` branch calling `radcli_transport_send_async()`);
lib/sendserver.c's `radcli_transport_send_async()` (single address, `ctx`'s
persistent request socket left open and registered in `ctx`'s in-flight
registry rather than closed, lock held across calls — REQ-NET2-SEND-016)
**Acceptance:** [SEND] unit, local — `tests/request.c` sends a
`RADCLI_REQUEST_SENDONLY` Accounting-Request to an unreachable address
(192.0.2.1, RFC 5737), used purely as fire-and-forget (freed without
calling `radcli_ctx_dispatch()`), and confirms `RADCLI_OK` is returned
promptly (no timeout wait).
**Links:** REQ-NET2-SEND-008, REQ-NET2-SEND-009, REQ-NET2-SEND-010,
REQ-NET2-SEND-011, REQ-NET2-SEND-013, REQ-NET2-SEND-014

### REQ-NET2-SEND-013 — radcli_ctx_get_poll()/radcli_ctx_dispatch() drive a RADCLI_REQUEST_SENDONLY request's reply to completion; radcli_request_done() reads the outcome without I/O

**Requirement:** After `radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)`
returns `RADCLI_OK`, `r` is registered in `ctx`'s in-flight request registry
(REQ-NET2-SEND-016) under a collision-free RADIUS Identifier, and is driven
to completion entirely by the caller's normal `radcli_ctx_get_poll()`/
`radcli_ctx_dispatch()` loop (REQ-NET2-NET-001) — there is no
per-request descriptor, poll-events, or timeout accessor: `r`'s retransmit/
timeout deadline is one of the inputs `radcli_ctx_get_poll()`'s `timeout_ms`
already folds in (REQ-NET2-NET-001), and `radcli_ctx_dispatch()` is what
performs the non-blocking I/O, never `r`'s own accessor, matching how a DAE
packet or a watchdog send is already driven through the same one call
(watchdog.md's REQ-WATCHDOG-NET-001). Each `radcli_ctx_dispatch()` call MUST
attempt at most one non-blocking read from `ctx`'s request socket per
registered slot, retransmitting to the same address (never a different one —
no DNS fail-over under SENDONLY, per REQ-NET2-SEND-012) up to `r`'s
configured retry count once its deadline has passed, before marking it
`RADCLI_TIMEOUT`; on a validated reply (matched to a registry slot by source
address and Identifier, REQ-NET2-SEND-016) it MUST decode it with the same
Response Authenticator / Message-Authenticator verification and
`radcli_avp_decode()` call the default (`flags == 0`) path uses, populate
`r->reply_code`/`r->reply_attrs` identically, and mark the slot `RADCLI_OK`.
`radcli_request_done(r)` MUST perform no I/O of its own: it MUST return
`RADCLI_AGAIN` while `r`'s registry slot is still unresolved, and otherwise
the terminal result `radcli_ctx_dispatch()` already recorded
(`RADCLI_OK`/`RADCLI_TIMEOUT`/`RADCLI_ERROR`) — a caller may call it as often
as it likes between `dispatch()` calls without side effects. Calling
`radcli_request_done()` on a request never sent with `RADCLI_REQUEST_SENDONLY`
MUST return `RADCLI_ERROR` without touching `r->reply_code`/`r->reply_attrs`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c's `radcli_request_done()`; lib/dae.c's
`radcli_ctx_get_poll()`/`radcli_ctx_dispatch()`; lib/sendserver.c's
request-registry drain (replacing `radcli_transport_service_async()`'s old
per-call socket) and shared `decode_reply()` helper (also used by
`radcli_transport_exchange()`'s blocking path, untouched by this change)
**Acceptance:** [SEND] unit, local — `tests/request.c` drives
`radcli_ctx_get_poll()`/`radcli_ctx_dispatch()` through a real `poll()` loop
against the unreachable 192.0.2.1 and confirms `radcli_request_done()`
eventually returns `RADCLI_TIMEOUT` (never spinning past a small iteration
bound), and that `radcli_request_done()` returns `RADCLI_ERROR` for a
request performed via the default (`flags == 0`) path. [SEND] interop,
root+FreeRADIUS — `tests/request-freeradius.c` drives the same loop against
a real server and confirms the decoded Access-Accept matches the
synchronous path's own result byte-for-byte (same `Framed-IP-Address`).
[SEND] unit, local — `tests/request-poll-multi.c` performs several
concurrent `RADCLI_REQUEST_SENDONLY` requests on one `ctx` and confirms all
resolve correctly while genuinely sharing one descriptor
(`radcli_ctx_get_poll()` reports the same fd throughout, not one per
request).
**Links:** REQ-NET2-SEND-012, REQ-NET2-SEND-016, REQ-NET2-NET-001,
REQ-WATCHDOG-NET-001, REQ-GEN-SEC-003

### REQ-NET2-SEND-014 — radcli_request_free() releases a still-pending RADCLI_REQUEST_SENDONLY exchange's registry slot

**Requirement:** `radcli_request_free(r)` MUST vacate `r`'s slot in `ctx`'s
in-flight request registry (REQ-NET2-SEND-016), freeing its Identifier for
reuse by a later `radcli_request_perform()`, if `radcli_request_done(r)`
never reached a terminal result for `r` (including never having been called
at all) — this MUST NOT leak the slot. Unlike before this change, `r`'s own
lifetime carries no socket of its own to close: `ctx`'s persistent request
socket (REQ-NET2-SEND-016) outlives any individual request and is released
only by `radcli_ctx_free()`. This is what makes fire-and-forget under
`RADCLI_REQUEST_SENDONLY` (REQ-NET2-SEND-012) just "perform() then free()",
with no separate close step for the caller to remember. A request that
never called `radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)`, or whose
outcome already reached a terminal result, MUST be unaffected (no
double-release of an already-vacated slot).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c's `radcli_request_free()` calling into
lib/sendserver.c's registry-abort helper (replacing the old
`radcli_transport_async_abort()`, which used to close a private socket)
**Acceptance:** [SEND] unit, local — `tests/request.c`'s fire-and-forget
`RADCLI_REQUEST_SENDONLY` case calls `radcli_request_free()` without ever
calling `radcli_ctx_dispatch()`; the process exits cleanly, and a
follow-up request on the same `ctx` can reuse the same Identifier (proving
the slot, not just process exit, was actually vacated). [SEND] interop,
root+FreeRADIUS — `tests/request-freeradius.c`'s equivalent case, verified
server-side via the captured `radiusd` debug trace (REQ-NET2-SEND-012's
fire-and-forget acceptance note).
**Links:** REQ-NET2-SEND-012, REQ-NET2-SEND-016

### REQ-NET2-SEND-015 — `radcli_encode_request()` MUST use the RFC 6614/7360 fixed secret for a TLS/DTLS `radcli_ctx`

**Requirement:** `radcli_encode_request()` MUST resolve its effective secret
to `rh->so.static_secret` whenever `rh->so_type` is `RC_SOCKET_TLS` or
`RC_SOCKET_DTLS` and that field is set, overriding whatever secret its
caller passed in — before that secret is used for anything, since it feeds
both `radcli_avp_encode()`'s RFC 2865 §5.2 `User-Password` encryption and
`add_msg_auth_attr()`'s Message-Authenticator HMAC. This MUST hold
regardless of which of `radcli_encode_request()`'s two callers (blocking
`radcli_do_exchange()`, used by both `radcli_request_perform()` and
`radcli_aaa()`, or the `RADCLI_REQUEST_SENDONLY` path calling it directly)
is in use, and matches `REQ-CONFIG-CFG-019`'s already-established rule that
a TLS/DTLS `authserver`/`acctserver` carries no meaningful secret of its own
to resolve.
**Strength:** MUST
**Status:** DERIVED — fixes a bug, not a new feature: before this, both
`radcli_request_new()` (`r->secret`) and `radcli_aaa()` (`lib/aaa2.c`) fed
`radcli_encode_request()` whatever secret `servers->secret[0]` held (empty,
for an ordinarily-configured TLS/DTLS `authserver` with no inline secret —
the only form `rc_init_tls()` accepts outside PSK), so both the Access-
Request's own Message-Authenticator and its `User-Password` encryption were
silently keyed wrong for every TLS/DTLS radcli2-API request. The legacy
`rc_send_server_ctx()` path (`lib/legacy/send.c`) never had this bug: it
already applies this exact override *before* encoding, the same idiom
`lib/sendserver.c`'s `radcli_transport_exchange()`/
`radcli_transport_send_async()` apply too, just too late there to affect a
packet `radcli_encode_request()` already built.
**Source:** lib/request.c's `radcli_encode_request()`
**Acceptance:** [SEND] negative→positive, local — `tests/request-tls-secret.c`/
`tests/request-tls-secret-tests.sh`, against `tests/request-tls-secret-
server.py` (decodes the Access-Request's Message-Authenticator and
`User-Password` independently against the real RFC 6614 secret and reports
each on its own): confirmed failing (`msgauth=bad`, `password=bad`) against
the unfixed code, passing (`msgauth=ok`, `password=ok`) after.
**Links:** REQ-CONFIG-CFG-019, REQ-NET2-SEND-008

### REQ-NET2-SEND-016 — one ctx-owned socket serves every RADCLI_REQUEST_SENDONLY exchange, demultiplexed by a 256-slot Identifier registry

**Requirement:** A `radcli_ctx`'s UDP transport MUST open at most one
persistent, unconnected request socket, lazily on the first
`radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)` call that needs one,
kept open for `ctx`'s own lifetime (closed only by `radcli_ctx_free()`) —
not one private socket per request as before this change. This one socket
MUST serve *both* Access-Request and Accounting-Request traffic on the same
`ctx`: `plain_get_fd()` (`lib/config.c:544`) always binds to an ephemeral
port (`sin_port = 0`) independent of destination, and `rc_own_bind_addr()`
has no per-service-type variant, so a UDP request socket was never tied to
one server or request type in the first place — only the destination
address/port/secret recorded per in-flight registry slot (below)
distinguishes an Access-Request bound for `authserver` from an
Accounting-Request bound for `acctserver`. Consequently the
`RADCLI_CTX_MAX_INFLIGHT` (256) ceiling below is shared across auth and
acct traffic combined on one `ctx`, not doubled — a real, if generous,
narrowing versus the old one-socket-per-request model, which had no shared
limit at all. (A TLS/DTLS `ctx` needs no separate socket for this: it
already reuses its one established session fd, `sfuncs->get_active_fd()`,
unchanged by this requirement, and already carries both request types over
one connection per `REQ-NET2-INIT-002`.) Because one socket now serves
every concurrently outstanding request, `radcli_request_perform()` MUST
allocate each request a RADIUS
Identifier that does not collide with any other request currently
in flight on the same `ctx`, tracked in a fixed-size, `ctx`-owned in-flight
registry of `RADCLI_CTX_MAX_INFLIGHT` (256) slots — the RADIUS Identifier
is one octet (RFC 2865 §3), so 256 is a hard protocol ceiling on a single
socket's concurrency, not a tunable; this registry is instance state on
`ctx`, not library-global or `static` (REQ-GEN-SEC-005 compliant), and
mirrors dae.md's `RADCLI_DAE_SLOTS`/`struct radcli_dae_slot` in shape.
`radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)` MUST return
`RADCLI_ERROR` without sending anything if no free Identifier/slot is
available.

Collision-freedom MUST be achieved by construction, not by chance:
`radcli_request_perform()` MUST allocate `r`'s Identifier via
least-recently-used (LRU) selection among the registry's currently-free
slots — the slot that has been free the longest — per RFC 5080 §2.1.1
("Clients SHOULD allocate Identifiers via a least-recently-used (LRU)
method"), MUST NOT reuse an Identifier still recorded as in flight (RFC
5080 §2.1.1's own MUST NOT), and MUST NOT use `rc_get_random_byte()` or any
other random source for this selection: unlike the Request Authenticator
(REQ-NET2-SEND-008/009) or the default per-call `id` (REQ-NET2-SEND-010),
neither RFC 2865 §3 nor RFC 5080 requires the Identifier itself to be
unpredictable, and LRU allocation is strictly better than a random draw for
what RFC 5080 actually cares about here: maximizing the time before an
Identifier is reused, minimizing the chance a stale, delayed duplicate reply
from an earlier, already-completed request is misattributed to a new one
that just reused its Identifier. (REQ-GEN-SEC-007's project-wide ban on
`rand()`/`random()`/etc. as a source still applies to any code path that
*does* need randomness; it is simply not engaged here, since this
allocation uses none.) A round-robin cursor over the 256 slots, skipping
occupied ones, satisfies both RFC 5080 constraints with O(1) amortized cost
regardless of occupancy. Because the socket is shared and unconnected (not
`connect()`ed
to one peer the way a private per-request socket was), `radcli_ctx_dispatch()`
MUST explicitly validate each received datagram's source address against
the destination address `r`'s own registry slot recorded before accepting
it as that request's reply — the kernel-level source filtering a
`connect()`ed socket gave for free is replaced by this explicit check, the
same principle dae.md's REQ-DAE-SEC-001 already applies to the DAE
listener's own long-lived shared socket.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:544 (`plain_get_fd()`, ephemeral-port bind
independent of destination/type); lib/sendserver.c (`radcli_transport_send_async()`/registry
drain, replacing the old per-call `sfuncs->get_fd()`); lib/includes.h
(`struct rc_conf`'s `req_fd`/in-flight-registry fields); cf. lib/dae.c:98-112
(`RADCLI_DAE_SLOTS`/`struct radcli_dae_slot`, the precedent this mirrors)
**Acceptance:** [SEND] unit, local — `tests/request-poll-multi.c` performs
`RADCLI_CTX_MAX_INFLIGHT` concurrent `RADCLI_REQUEST_SENDONLY` requests on
one `ctx`, confirms `radcli_ctx_get_poll()` reports exactly one fd
throughout (not one per request), confirms one further
`radcli_request_perform()` fails with `RADCLI_ERROR` while all 256 slots
are occupied, and confirms a freed slot's Identifier becomes available
again once its request completes or is freed. [SEND] negative, unit,
local — a reply datagram spoofed from a source address that does not match
any registry slot's expected peer is confirmed silently discarded, not
matched to an in-flight request. [SEND] unit, local — freeing a request
mid-sequence (vacating a slot out of order) and then performing several new
`RADCLI_REQUEST_SENDONLY` requests confirms the vacated slot's Identifier is
reused only after every other, longer-free slot has been (LRU order, not
lowest-available-first or random), and that no Identifier still recorded as
in flight is ever reassigned (RFC 5080 §2.1.1's MUST NOT).
**Links:** REQ-GEN-SEC-005, REQ-GEN-SEC-007, REQ-DAE-SEC-001,
REQ-NET2-SEND-010, REQ-NET2-SEND-013, REQ-NET2-SEND-014

**Scope:** this requirement, and REQ-NET2-SEND-013/014's rewrite above,
apply only to `radcli2`'s async surface (`radcli_request_*`,
`radcli_ctx_get_poll()`/`_dispatch()`). The legacy `libradcli` API
(`rc_auth()`/`rc_acct()`, lib/legacy/buildreq.c) and its blocking
`radcli_transport_exchange()` core (lib/sendserver.c) are unaffected: they
continue to open and close one socket per call, exactly as before.

---

## RECV — reply handling and accessors

### REQ-NET2-RECV-012 — RADCLI_OK covers OK/REJECT/CHALLENGE; the reply code, not the RADCLI_* result, distinguishes them

**Requirement:** `radcli_request_perform()` MUST map
`radcli_transport_exchange()`'s `OK_RC`, `REJECT_RC`, and `CHALLENGE_RC`
outcomes all to `RADCLI_OK` (a validated reply was received — Response
Authenticator and, for AUTH, Message-Authenticator already verified inside
`radcli_transport_exchange()`); the caller MUST consult
`radcli_request_code()` (e.g. `RADCLI_CODE_ACCESS_REJECT`) to distinguish an
accept from a reject or challenge, not the `radcli_result` return value.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:223-232
**Acceptance:** [RECV] interoperability, root+FreeRADIUS —
`tests/request-freeradius.c` checks `radcli_request_perform()` returns
`RADCLI_OK` and `radcli_request_code()` reports `RADCLI_CODE_ACCESS_ACCEPT`
for a valid user, and (per this requirement, not currently exercised by that
test) would also return `RADCLI_OK` with `RADCLI_CODE_ACCESS_REJECT` for an
invalid one. `[UNDOCUMENTED-BY-TEST: the reject/challenge branches of this
mapping have no test coverage in this commit.]`

### REQ-NET2-RECV-013 — TIMEOUT_RC and every other transport outcome map to RADCLI_TIMEOUT / RADCLI_ERROR respectively

**Requirement:** `radcli_request_perform()` MUST return `RADCLI_TIMEOUT` if
`radcli_transport_exchange()` returns `TIMEOUT_RC` (no reply from any address
the server name resolved to), and `RADCLI_ERROR` for every other outcome
(including a `radcli_avp_decode()` failure on an otherwise-validated reply).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:223-237
**Acceptance:** [RECV] unit/integration — point the request at an
unreachable/black-holed address with a short timeout and confirm
`RADCLI_TIMEOUT`; `[UNDOCUMENTED-BY-TEST: not exercised by the current test
suite, which only reaches the success path against a live FreeRADIUS.]`

### REQ-NET2-RECV-014 — reply attributes are decoded with the request's own vector and secret

**Requirement:** When the reply carries a non-empty attribute region
(`recv_len > 0`), `radcli_request_perform()` MUST decode it with
`radcli_avp_decode()` using the *request's* Request Authenticator (the same
`vector` used to build the outgoing packet, per REQ-NET2-SEND-008/009 — never
the reply's own bytes) and the request's shared secret, matching RFC 2865's
requirement for decrypting salt-encrypted attributes (e.g. Tunnel-Password)
against the original request authenticator.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:228-230
**Acceptance:** [RECV] interoperability, root+FreeRADIUS —
`tests/request-freeradius.c`'s Framed-IP-Address decode check confirms
successful decoding against a live server's reply; a salt-encrypted attribute
is not currently exercised. `[UNDOCUMENTED-BY-TEST]`

### REQ-NET2-RECV-015 — accessors are safe on an unperformed or NULL request; code defaults to 0

**Requirement:** `radcli_request_code()` MUST return `0` if `r` is `NULL` or
has not yet had a successful `radcli_request_perform()` call.
`radcli_request_attrs()` MUST return `NULL` if `r` is `NULL` or carries no
decoded reply attributes. `radcli_request_server()` MUST return a non-NULL
empty string (never `NULL`) if `r` is `NULL`, and the configured server name
otherwise, valid even before `radcli_request_perform()` is called.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:241-265
**Acceptance:** [RECV] unit, local — `tests/request.c` calls all three
accessors on a freshly-constructed, not-yet-performed request and on `NULL`,
confirming the defaults above (including that `radcli_request_server()`
never returns `NULL`).

### REQ-NET2-RECV-016 — RADCLI_OK is the only success value; every other `radcli_result`, present or future, is failure

**Requirement:** `RADCLI_OK` MUST be `0`; every other `radcli_result` value
MUST be negative. Callers, tests, and library code MUST decide success by
testing `result == RADCLI_OK`, never by testing for the absence of one
specific non-OK value (e.g. `!= RADCLI_ERROR`) and treating anything else as
success -- that pattern silently treats an unhandled outcome (such as
`RADCLI_TIMEOUT`, or any outcome added later) as a validated reply. This
also means a future outcome can be added as a new negative value without
turning a caller's existing `!= RADCLI_OK` check into a security regression.
**Strength:** MUST
**Status:** NEW
**Source:** include/radcli/radcli2.h (`radcli_result` enum)
**Acceptance:** [RECV] unit, local — `tests/request.c` and `tests/aaa2.c`
already test each outcome by comparing against its own named constant
(`== RADCLI_OK`, `!= RADCLI_TIMEOUT`, `!= RADCLI_ERROR`), never a numeric
literal or an inverted single-value check; `src/radexample.c` demonstrates
the sanctioned caller pattern (`radcli_request_perform(r) == RADCLI_OK`).
`[UNDOCUMENTED-BY-TEST: no test exercises a caller that gets this wrong --
the requirement is enforced by convention and code review, not a runtime
check.]`

---

## ERR — rejection and failure-mapping contracts

### REQ-NET2-ERR-010 — construction failures are uniformly NULL, with no partial/leaked allocation

**Requirement:** Every `radcli_request_new()` failure path (invalid `ctx`,
invalid `code`, no server configured, attribute-copy failure, or the request
object's own `calloc()` failure) MUST return `NULL` and MUST NOT leak the
partially-built `send_copy` list.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:79-142 (every early return frees `send_copy` before
it, if allocated)
**Acceptance:** [ERR] would require fault-injecting `calloc()`/`radcli_avp_add_bytes()`
to exercise the leak-free property directly; `Needs-domain-check` per
`REQ-AVP2-ERR-008`'s precedent (same open question, same project).
**Links:** REQ-NET2-INIT-001, REQ-NET2-INIT-004, REQ-NET2-INIT-005

### REQ-NET2-ERR-011 — packet encoding overflow (RC_MAX_PACKET_LEN) fails the perform call before any I/O

**Requirement:** If `radcli_avp_encode()` returns a negative
(overflow/refusal) result for either request type, `radcli_request_perform()`
MUST return `RADCLI_ERROR` without calling `radcli_transport_exchange()` (no
packet is sent).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:189-190, lib/request.c:210-211
**Acceptance:** [ERR] unit, local — construct a request whose attributes
exceed `RC_MAX_PACKET_LEN` once encoded (e.g. a large binary attribute
repeated many times) and confirm `radcli_request_perform()` returns
`RADCLI_ERROR` with no observable network I/O.

### REQ-NET2-ERR-012 — a double-send or NULL-request perform is RADCLI_ERROR, not undefined behavior

**Requirement:** See REQ-NET2-SEND-011; restated here as the ERR-category
contract: `radcli_request_perform(NULL, flags)` for any `flags`, and a
second `radcli_request_perform()` call on the same request regardless of
which `flags` value either call used, MUST both return `RADCLI_ERROR`
deterministically, never crash or resend.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:306-308 (`radcli_request_perform()`)
**Acceptance:** [ERR] unit, local — same tests as REQ-NET2-SEND-011's
acceptance criteria; listed separately here because it is also the
NULL-safety/no-UB contract `REQ-GEN-MEM-002`-style requirements care about.
**Links:** REQ-NET2-SEND-011, REQ-NET2-SEND-012, REQ-GEN-MEM-002

---

## AAA — radcli_aaa() autofill and multi-server fail-over

`radcli_aaa()` (`lib/aaa2.c`) is the new API's counterpart to `radcli.h`'s
`rc_aaa()`/`rc_aaa_ctx()` (`attrs.md`): unlike `radcli_request_new()`, which
uses only the first configured server (`REQ-NET2-INIT-003`), it tries every
configured `"authserver"`/`"acctserver"` entry in order, and autofills
Acct-Delay-Time the way `rc_fill_acct_pairs()` does (unlike the legacy
`rc_aaa()`, it has no NAS-Port autofill -- callers add that attribute to
`send` themselves, like any other). It calls
`radcli_do_exchange()` — the packet-build/transport-exchange primitive
`radcli_request_perform()` is itself built from,
factored out of `lib/request.c` for this purpose — directly, once per server
attempted, rather than going through `radcli_request_new()`, so it shares the
exact Response Authenticator / Message-Authenticator wire logic instead of a
second copy of it.

### REQ-NET2-AAA-001 — radcli_aaa validates ctx, send, and code before touching configuration

**Requirement:** `radcli_aaa()` MUST return `RADCLI_ERROR` without side
effects if `ctx` or `send` is `NULL`, or if `code` is neither
`RADCLI_CODE_ACCESS_REQUEST` nor `RADCLI_CODE_ACCOUNTING_REQUEST` — the same
validation `radcli_request_new()` performs (`REQ-NET2-INIT-001`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/aaa2.c (`radcli_aaa()`, top of function)
**Acceptance:** [AAA] unit, local — `tests/aaa2.c` calls `radcli_aaa()` with
a `NULL` ctx, a `NULL` send, and an invalid code, confirming `RADCLI_ERROR`
in each case.

### REQ-NET2-AAA-002 — server/type selection matches radcli_request_new()'s TLS/DTLS rule

**Requirement:** `radcli_aaa()` MUST select `"authserver"`/`AUTH` when `code`
is `RADCLI_CODE_ACCESS_REQUEST` or the handle's transport is
`RC_SOCKET_TLS`/`RC_SOCKET_DTLS`, and `"acctserver"`/`ACCT` otherwise — the
same rule as `REQ-NET2-INIT-002` — and MUST return `RADCLI_ERROR` if the
selected option has no configured entries.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/aaa2.c (`radcli_aaa()`, server/type selection)
**Acceptance:** [AAA] unit, local — `tests/aaa2.c` confirms `RADCLI_ERROR`
with no `"authserver"` configured at all.
**Links:** REQ-NET2-INIT-002

### REQ-NET2-AAA-003 — every configured server is tried in order on timeout/unreachable, unlike radcli_request_new()

**Requirement:** Unlike `radcli_request_new()` (`REQ-NET2-INIT-003`),
`radcli_aaa()` MUST attempt every configured entry of the selected server
list in order, advancing to the next only when the current attempt's
`radcli_do_exchange()` result is a timeout or network-unreachable condition,
and MUST return `RADCLI_TIMEOUT` only once every configured entry has been
tried and none produced a validated reply.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/aaa2.c (`radcli_aaa()`, the server retry loop)
**Acceptance:** [AAA] unit, local — `tests/aaa2.c` configures two
unreachable `TEST-NET` (RFC 5737) authservers with a 1s timeout and 0
retries, and confirms `radcli_aaa()` takes roughly 2s (both tried) and
returns `RADCLI_TIMEOUT`, versus roughly 1s for a single configured entry.

### REQ-NET2-AAA-005 — Acct-Delay-Time is recomputed fresh on every attempt, accumulating real elapsed time across fail-over

**Requirement:** For `RADCLI_CODE_ACCOUNTING_REQUEST`, `radcli_aaa()` MUST
add an `Acct-Delay-Time` (`PW_ACCT_DELAY_TIME`) attribute to every attempt,
valued as the elapsed time since the *first* attempt (not reset on
fail-over to the next server), folding in any `Acct-Delay-Time` already
present in the caller's `send` as an initial offset to that starting point
— mirroring `rc_fill_acct_pairs()`'s (`lib/buildreq.c`) semantics for the
legacy API. Any `Acct-Delay-Time` in the caller's `send` is not itself
copied onto the wire; the freshly computed value replaces it.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/aaa2.c (`radcli_aaa()`'s `start_time` computation,
`build_attempt()`)
**Acceptance:** [AAA] unit, local — `tests/aaa2.c` exercises the
`RADCLI_CODE_ACCOUNTING_REQUEST` path against an unreachable acctserver and
confirms it completes within one timeout with no crash; verifying the exact
wire value needs a real or mock RADIUS server decoding the request (as
`tests/request-freeradius.c` does for `radcli_request_perform()`), not
currently exercised locally. `[UNDOCUMENTED-BY-TEST: wire-level value not
verified]`

### REQ-NET2-AAA-006 — a successful attempt's reply code and decoded attributes are returned via out-parameters, both optional

**Requirement:** On `RADCLI_OK`, `radcli_aaa()` MUST write the final reply's
RADIUS code to `*out_code` if `out_code` is non-`NULL`, and the decoded
reply attributes (or `NULL` if the reply carried none) to `*out_attrs` if
`out_attrs` is non-`NULL`; if `out_attrs` is `NULL`, any decoded attributes
MUST be freed internally rather than leaked. Both output parameters MUST be
independently optional.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/aaa2.c (`radcli_aaa()`, success path)
**Acceptance:** [AAA] `Needs-domain-check` — needs a real/mock server reply
to exercise the success path at all; not currently exercised locally, same
as `net2.md`'s existing `[UNDOCUMENTED-BY-TEST]` RECV-category notes.
`[UNDOCUMENTED-BY-TEST]`
