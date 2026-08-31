---
title: transport, socket abstraction, and wire-level response authentication requirements
generator: requirements-from-implementation
id-prefix: REQ-NET
categories:
  NET: transport abstraction, socket vtable, connection lifecycle, request/retry loop
  SEC: Message-Authenticator / Response Authenticator validation, TLS/DTLS credential and downgrade handling, secret handling at the wire level
  ERR: error/status code contract, malformed-packet rejection
  TEARDOWN: socket, TLS/DTLS session, and namespace teardown
sources:
  - lib/sendserver.c
  - lib/tls.c
  - lib/tls.h
  - lib/config.c (default_socket_funcs, default_tcp_socket_funcs, rc_apply_config, rc_get_socket_type)
  - lib/util.c (rc_set_netns, rc_reset_netns, rc_memcmp, rc_getmtime)
  - include/radcli/radcli.h (rc_send_server, rc_send_server_ctx, SEND_DATA, rc_socket_type, rc_send_status, rc_tls_fd, rc_check_tls, rc_get_socket_type)
  - include/includes.h (rc_sockets_override, struct rc_conf's so/so_type fields)
  - lib/radcli.map.in
  - doc/requirements/general.md (REQ-GEN-SEC-001/003/004/006, REQ-GEN-MEM-005)
  - doc/requirements/watchdog.md (rc_check_tls()'s RFC 5997 watchdog probe
    guarantee, cited not owned -- REQ-WATCHDOG-NET-004)
---

# Transport and Wire-Level Response Authentication Requirements

Scope: the socket abstraction (`rc_sockets_override`, `include/includes.h:167-182`) that lets
UDP, TCP, TLS and DTLS share one request/response code path in `lib/sendserver.c`; the
per-transport implementations (`default_socket_funcs`/`default_tcp_socket_funcs` in
`lib/config.c`, the GnuTLS-backed vtable installed by `rc_init_tls()` in `lib/tls.c`); the
retry/timeout loop in `rc_send_server_ctx()`; and RADIUS-level response authentication at the
wire — Response Authenticator (RFC 2865 §3) and Message-Authenticator (RFC 2869 §5.14, RFC 3579
§3.2) verification. Packet *construction* (`rc_send_server_ctx()` converts `data->send_pairs`
to a `radcli_avp_list` and encodes it with `radcli_avp_encode()`, `lib/avp.c`; the
legacy `rc_pack_list()` implements the same wire format but is no longer called from this path,
see `REQ-NET-SEC-003`) and *field-level* attribute parsing are exercised here only insofar as
they affect transport-level framing; `attrs.md` and `util.md` own the attribute/`pkt_buf`
contracts themselves (see `REQ-GEN-MEM-005`).

`rc_sockets_override` is declared in `include/includes.h`, not `include/radcli/radcli.h`, and
`include/meson.build:1` installs only `radcli/radcli.h`. It is therefore **not part of the
public ABI** — no exported function lets a caller supply a custom vtable; `rh->so` is populated
exclusively by `rc_apply_config()` (UDP/TCP) or `rc_init_tls()` (TLS/DTLS) based on the
`serv-type` config option. Requirements below describing the vtable are about radcli's internal
architecture, cited because `rc_send_server()`'s behavioral contract depends on it, not because
callers can extend it (`REQ-NET-NET-002`).

---

## NET — transport abstraction, connection lifecycle, retry loop

### REQ-NET-NET-001 — Transport is selected once, from config, and is opaque to `rc_send_server()`

**Requirement:** `rc_apply_config()` MUST select exactly one of UDP, TCP, TLS, or DTLS based on
the `serv-type`/`serv-auth-type` config option (default `udp` when unset) and populate
`rh->so`/`rh->so_type` accordingly, before any `rc_send_server()`/`rc_send_server_ctx()` call.
`rc_send_server_ctx()` MUST perform all I/O through `rh->so`'s function pointers
(`get_fd`, `sendto`, `recvfrom`, `close_fd`, `lock`, `unlock`) and MUST NOT contain
transport-specific branches (no `if (so_type == RC_SOCKET_TLS)` in `sendserver.c`), so that
switching transport is a config-only change.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:562-593 (`rc_apply_config`); lib/sendserver.c:496,503,509,532,685,727,
719,744,757,788,812,821,830,839,855 (all I/O and lock/unlock routed through `sfuncs`)
**Acceptance:** [NET] unit, local — `grep -n 'so_type' lib/sendserver.c` returns no matches
outside comments; a config with `serv-type=tcp` vs `serv-type=tls` reaches `rc_send_server_ctx()`
through the same code path with a different `rh->so`.
**Links:** REQ-CONFIG-* (serv-type parsing, see `config.md`)

### REQ-NET-NET-002 — `rc_sockets_override` MUST remain an internal abstraction, not a public extension point

**Requirement:** No function exported in `lib/radcli.map.in` MUST set or expose `rh->so` to a
caller-supplied vtable; `rc_sockets_override` (`include/includes.h:167-182`) MUST be populated
only by `rc_apply_config()`/`rc_init_tls()` from radcli's own UDP/TCP tables
(`default_socket_funcs`, `default_tcp_socket_funcs` in `lib/config.c:500-512`) or the GnuTLS
wrappers (`lib/tls.c:839-844`). Any future public API that exposes this vtable to callers MUST be
reconciled with `REQ-GEN-SEC-005` (no new library-owned global state) and `REQ-GEN-ABI-001`
(header+map co-declaration) before being added.
**Strength:** MUST
**Status:** DERIVED
**Source:** include/includes.h:167-182; lib/config.c:500-512; lib/tls.c:839-844;
lib/radcli.map.in (no `rc_set_sockets`/`rc_sockets_override`-related symbol); AGENTS.md
("Key data structures")
**Acceptance:** [NET] code-review — confirm no public setter exists; if one is added, it must
gain a new `REQ-NET-NET-*` entry and be reconciled with the vtable's internal-only status.
**Links:** REQ-GEN-SEC-005, REQ-GEN-ABI-001

### REQ-NET-NET-003 — UDP transport binds an ephemeral local port and lets the kernel route each datagram

**Requirement:** `plain_get_fd()` MUST create a `SOCK_DGRAM` socket, zero the caller-supplied
source port, and `bind()` it to `our_sockaddr` before use; `plain_sendto()`/`plain_recvfrom()`
MUST be thin wrappers over `sendto()`/`recvfrom()` with an explicit destination each call
(connectionless), so the same socket can receive replies from a server that responds from a
different local address/port than it was addressed on (RFC 2865 tolerates this).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:417-424,439-445,454-474,500-505
**Acceptance:** [NET] unit, local — a UDP round-trip against a test server on an unprivileged
port succeeds without the client `connect()`-ing the socket.

### REQ-NET-NET-004 — TCP transport binds an ephemeral local port, then explicitly `connect()`s on the first send

**Requirement:** `plain_tcp_get_fd()` MUST create a `SOCK_STREAM` socket, bind it to an ephemeral
local port, and defer the peer `connect()` to `plain_tcp_sendto()`, which MUST `connect()`
before calling `sendto()` and MUST return -1 (logging via `rc_log`) on connect failure without
calling `sendto()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:478-497,426-436,507-512
**Acceptance:** [NET] unit, local — with `serv-type=tcp` and an unreachable server, the first
`rc_send_server()` call fails at `plain_tcp_sendto()`'s `connect()`, not at socket creation.
**Links:** REQ-NET-ERR-001 (error propagation)

### REQ-NET-NET-005 — TLS/DTLS session establishment is deferred to first use

**Requirement:** `rc_init_tls()` MUST NOT open a socket or perform a handshake; it MUST only
validate configuration (CA file / cert+key / PSK), store `hostname`/`port`/`our_sockaddr` in
`st->ctx`, and set `need_restart = 1`. The actual `socket()`+`connect()`+`gnutls_handshake()`
sequence in `init_session()` MUST run only on the first `tls_get_fd()` or `tls_sendto()` call
that observes `need_restart != 0`, via `restart_session()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c:663-869 (`rc_init_tls`, comment at 831-837); lib/tls.c:87-95 (`tls_get_fd`);
lib/tls.c:152-165 (`tls_sendto`)
**Acceptance:** [NET] unit, local — `rc_apply_config()` with `serv-type=tls` and an unreachable
server returns success; the connection failure surfaces only on the first `rc_auth()`/`rc_acct()`
call.

### REQ-NET-NET-006 — Exactly one auth server is permitted when TLS or DTLS is configured

**Requirement:** `rc_init_tls()` MUST reject configuration (return -1, log at `LOG_ERR`) if
`rc_conf_srv(rh, "authserver")` yields more than one server (`authservers->max > 1`), since a
`tls_st` holds exactly one persistent session/hostname/port, not a server list to iterate like
UDP/TCP's `rc_find_server_addr()`-driven multi-server retry.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c:752-766
**Acceptance:** [NET] negative, local — a config with two `authserver` lines and `serv-type=tls`
fails `rc_apply_config()`/`rc_init_tls()`.

### REQ-NET-NET-007 — A broken TLS/DTLS session reconnects transparently on the next transport call

**Requirement:** When `tls_sendto()`/`tls_recvfrom()` observe a fatal GnuTLS error or an
unrecoverable `tls_wait_or_give_up()` timeout, they MUST set `st->ctx.need_restart = 1`. The next
`tls_get_fd()` or `tls_sendto()` call MUST invoke `restart_session()`, which tears down and
reinitializes the session via `init_session()` unconditionally — every call site
(`tls_get_fd()`, `tls_sendto()`, `tls_recvfrom()`, `radcli2_priv_tls_ensure_connected()`,
`radcli2_priv_tls_force_reconnect()`, and `rc_check_tls()`'s own `need_restart != 0` branch)
only ever invokes it once the session is already known to need it (a send/recv failure
already set `need_restart`, or `rc_init_tls()` preset it before the first connection), so
there is nothing to throttle: `restart_session()` carries no rate limit of its own.
(A previous revision of this requirement described a `TIME_ALIVE`-based throttle guarding a
*proactive*, `need_restart == 0` call from a TLS heartbeat probe — that call site no longer
exists, `rc_check_tls()`'s RFC 5997 watchdog probe reaches `restart_session()` only via
`radcli_ctx_send_watchdog()`'s own `need_restart`-setting `radcli2_priv_tls_force_reconnect()`,
`REQ-WATCHDOG-NET-004`/`REQ-WATCHDOG-NET-003` (`doc/requirements/watchdog.md`) — so the throttle
became unreachable dead code and was removed along with it.)
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c (`tls_wait_or_give_up`, `tls_sendto`/`tls_recvfrom`, `restart_session`)
**Acceptance:** [NET] unit, local — killing and restarting the TLS test server between two
`rc_auth()` calls causes the second call to reconnect and succeed, without the caller calling
`rc_check_tls()` (`tests/tls-idle-restart.c`, also the historical regression test for issue
#89's since-removed throttle: a reconnect attempt immediately following a just-failed one
must not be blocked).
**Links:** REQ-GEN-SEC-003 (no process-wide timers), REQ-WATCHDOG-NET-004, REQ-WATCHDOG-NET-003

### REQ-NET-NET-008 — `sendto()` may trigger a session restart; `rc_send_server_ctx()` MUST re-fetch the active fd before `poll()`ing

**Requirement:** After calling `sfuncs->sendto()`, `rc_send_server_ctx()` MUST call
`sfuncs->get_active_fd()` (when non-NULL) and use its return value as the fd to `poll()` on,
because a TLS/DTLS `sendto()` that observed `need_restart` may have replaced the underlying
socket via `restart_session()`; polling the fd captured before `sendto()` would wait on a closed
descriptor.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:697-706; lib/tls.c:98-104 (`tls_get_active_fd`)
**Acceptance:** [NET] unit, local — a TLS session restart triggered mid-`sendto()` still yields
a valid reply within the configured timeout, not a `poll()` hang or `EBADF`.

### REQ-NET-NET-009 — `rc_send_server_ctx()` retries up to `data->retries` times per configured server, using monotonic elapsed time for the timeout budget

**Requirement:** The send/poll/recv sequence MUST repeat until a reply with a matching sequence
ID is received (`rc_check_reply()` returns anything other than `BADRESPID_RC`) or
`retries` exceeds `data->retries`, at which point it MUST return `TIMEOUT_RC`. The remaining
timeout budget within a single attempt MUST be computed from `rc_getmtime()` (monotonic clock
when available), decremented across `EINTR`-interrupted `poll()` calls, not restarted.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:682-793; lib/util.c:69-85 (`rc_getmtime`)
**Acceptance:** [NET] unit, local — a server that never replies causes exactly
`data->retries + 1` transmissions before `TIMEOUT_RC`; interrupting the process with a
caller-installed non-fatal signal during `poll()` does not extend the wait past `data->timeout`.
**Links:** REQ-GEN-SEC-003

### REQ-NET-NET-010 — A response with a non-matching request ID is discarded and the wait continues, not treated as failure

**Requirement:** When `rc_check_reply()` returns `BADRESPID_RC` (RADIUS `id` field mismatch),
`rc_send_server_ctx()` MUST NOT terminate the wait; it MUST loop back to `poll()` for the
remaining timeout, because DTLS's UDP-like channel is shared and duplicate or out-of-order
packets (including stale replies from an earlier request) are expected.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:763-772 (comment explicitly cites DTLS duplicate/out-of-order
delivery)
**Acceptance:** [NET] unit, local — injecting a reply with a stale/foreign `id` followed by the
correct reply within the timeout window still yields `OK_RC`.
**Links:** REQ-NET-SEC-004 (this is not authentication — a spoofed ID-matching packet is still
subject to Response Authenticator/Message-Authenticator checks below)

### REQ-NET-NET-012 — `rc_get_socket_type()` reports the transport selected by `rc_apply_config()`/`rc_init_tls()`

**Requirement:** `rc_get_socket_type()` MUST return `rh->so_type` as set by transport
initialization (`RC_SOCKET_UDP`/`TCP`/`TLS`/`DTLS`), with no independent state of its own, so an
application can branch on transport (e.g. to decide whether `rc_check_tls()` is meaningful)
without inspecting config strings itself.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c:1243-1246; include/radcli/radcli.h:713; lib/radcli.map.in:43
**Acceptance:** [NET] unit, local — `rc_get_socket_type()` after `rc_apply_config()` with
`serv-type=dtls` returns `RC_SOCKET_DTLS`.

### REQ-NET-NET-013 — `rc_tls_fd()` and `rc_check_tls()` are no-ops (not errors) outside TLS/DTLS transport

**Requirement:** `rc_tls_fd()` MUST return -1, and `rc_check_tls()` MUST return 0 without
touching any session state, when `rh->so_type` is neither `RC_SOCKET_TLS` nor `RC_SOCKET_DTLS`,
so an application can call these unconditionally regardless of configured transport.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c:563-576 (`rc_tls_fd`), 596-619 (`rc_check_tls`)
**Acceptance:** [NET] unit, local — `rc_check_tls()` on a UDP-configured `rh` returns 0
immediately; `rc_tls_fd()` returns -1.

### REQ-NET-NET-015 — Namespace switching around socket creation is scoped to the call, not left ambient

**Requirement:** When the `namespace` config option is set, `rc_send_server_ctx()` and
`rc_init_tls()`/`rc_deinit_tls()` MUST call `rc_set_netns()` before creating/tearing down sockets
and `rc_reset_netns()` before returning on every exit path (success and error), restoring the
caller's original network namespace. This is a Linux-specific `setns(CLONE_NEWNET)` call, which
changes the *calling thread's* namespace for the duration; it is bounded by explicit set/reset
pairs rather than persisting as ambient state — compliant with `REQ-GEN-SEC-004`'s `chdir()`-style
ambient-state prohibition because it is symmetric (paired set/reset with no early-return that
skips the reset) and thread-scoped rather than process-wide, which `REQ-GEN-SEC-004`'s listed
examples (`chdir`, `setenv`) are not. Added in PR #29 (merged 2018-03-08) for Management-VRF-style
deployments where the RADIUS server is reachable only from a non-default network namespace; opt-in
via the `namespace` config option, with no effect when unset. C has no scope-guard/RAII mechanism
to enforce set/reset symmetry structurally, so this remains a code-review obligation for any future
change to these three functions' exit paths, not a compiler-enforced invariant.
**Strength:** MUST (symmetric set/reset on every exit path)
**Status:** DERIVED
**Source:** lib/sendserver.c:460-466,941-947; lib/tls.c:680-686,845-851,864-867 (`rc_init_tls`);
lib/tls.c:634-640,647-649 (`rc_deinit_tls`); lib/util.c:174-253 (`rc_set_netns`/`rc_reset_netns`);
tests/namespace-tests.sh (existing root-requiring test coverage, wired into `tests/meson.build`)
**Acceptance:** [NET][SEC] `tests/namespace-tests.sh` (root, CI-only per `REQ-GEN-TEST-002`) plus
code-review — every new early-return added to `rc_send_server_ctx()`, `rc_init_tls()`, or
`rc_deinit_tls()` between a `rc_set_netns()` call and function exit must be verified to still
reach the matching `rc_reset_netns()`.
**Links:** REQ-GEN-SEC-004

### REQ-NET-NET-016 — `restart_session()` MUST build the replacement session in a zero-initialized `tls_int_st`

**Requirement:** The local `struct tls_int_st tmps` that `restart_session()` passes to
`init_session()` MUST be zero-initialized before the call. `init_session()` sets some fields
(e.g. `skip_hostname_check`, per `REQ-NET-SEC-014`) only conditionally, with no corresponding
else-branch, relying entirely on the struct's starting state for every field it does not
unconditionally write. Because `REQ-NET-NET-005` routes all session (re)establishment —
including the first connection, not just reconnects — through `restart_session()`'s `tmps`, this
zero-initialization is the only initialization such fields ever receive.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c:522 (`tmps` declaration); lib/tls.c:396-399 (`skip_hostname_check`'s
conditional set, the field this was found to affect)
**Acceptance:** [SEC][NET] negative, local — with `tmps` left uninitialized, a config that never
sets `tls-verify-hostname` (the secure default) can intermittently accept a server certificate
whose hostname does not match, depending on leftover stack contents at the call site (varies by
optimization level and build). Confirmed via CI run
https://github.com/radcli/radcli/actions/runs/31953512049 (`tests` job, no sanitizer):
diagnostic logging read `skip_hostname_check` back as `1583919456` for a config that never
referenced the option, and `cert_verify_callback()` took the "skip" branch
(`gnutls_certificate_verify_peers2`) instead of the hostname-checking one.
**[REVIEW]** No tool in this project's current CI catches a regression of this requirement.
MemorySanitizer (`tests-msan`) is the mechanism that would normally catch an uninitialized-memory
read reaching a branch, but that job builds with `-Dtls=disabled`, so `lib/tls.c` is not compiled
into it at all. `scan-build` (`static-analyzer`) cannot see the call from `cert_verify_callback()`
either — it is reached only via a function pointer GnuTLS invokes internally
(`gnutls_certificate_set_verify_function`), an opaque callback edge outside the analyzer's
callgraph. Until `tests-msan` builds with TLS enabled (or some other tool-checkable acceptance is
found), enforcement of this requirement is code-review only.
**Links:** REQ-NET-SEC-014 (the specific field this left undefined), REQ-NET-NET-005 (why every
`init_session()` call goes through this path), REQ-NET-TEARDOWN-004 (the same `tmps`/
`restart_session()` pairing — covers failure-path safety, not initial-state correctness)

### REQ-NET-NET-017 — `rc_send_server_ctx()`'s `no_wait` parameter is an explicit fire-and-forget mode: transmit once and return `OK_RC` without waiting for a reply, never `TIMEOUT_RC`

**Requirement:** `radcli_transport_exchange()` (the socket/retry/receive step
`rc_send_server_ctx()` delegates to) takes an explicit `int no_wait` parameter rather than
inferring fire-and-forget mode
from a zero timeout. When `no_wait` is non-zero, immediately after the single `sendto()` call
succeeds the function MUST close the socket, capture the request's own secret/vector into `*ctx`
if non-NULL (`populate_ctx()`, mirroring the normal path's teardown obligations —
`REQ-NET-TEARDOWN-001`, `REQ-NET-SEC-009`), and return `OK_RC` — it MUST NOT enter the
`poll()`/retry-budget loop (`REQ-NET-NET-009`) at all, and MUST NOT consult or require any
particular value of `timeout`/`retries`. Because the retry/poll loop that produces `TIMEOUT_RC` is
structurally unreachable when `no_wait` is set, `TIMEOUT_RC` MUST NOT be returned under `no_wait` —
the only observable outcomes are `OK_RC` (send succeeded) or a send-failure code
(`ERROR_RC`/`NETUNREACH_RC`), preserving `REQ-NET-ERR-001`'s single, unconditional meaning for
`TIMEOUT_RC` everywhere else in the function.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:470 (`no_wait` parameter), lib/sendserver.c:625-630 (early
`SCLOSE`/`populate_ctx`/`OK_RC` branch, taken before the retry/poll loop that produces
`TIMEOUT_RC` at lines 692-702); lib/buildreq.c:363-411 (`rc_aaa_ctx_server_async()` calling
`rc_send_server_ctx(rh, NULL, &data, NULL, type, 1)` and treating only `OK_RC` as per-server
success). Note: `radcli2.h`'s `radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)` no longer
routes through this `no_wait` parameter at all -- it calls the separate
`radcli_transport_send_async()`/`radcli_transport_service_async()` pair instead, which leaves the
socket open rather than closing it immediately, so a later `radcli_request_wait()` can still read
the reply; see `REQ-NET2-SEND-012`/`013`/`014` in `net2.md` for that path's own contract. This
requirement (and `radcli_transport_exchange()`'s `no_wait` parameter itself) now describes the
legacy `rc_send_server_ctx()`/`rc_acct_async()` path only.
**Acceptance:** [NET] unit, local — calling `rc_send_server_ctx()` with `no_wait=1` against an
unreachable server returns `OK_RC` (not `TIMEOUT_RC`) without a `poll()` call blocking
(measurable: wall-clock duration of the call is well under any nonzero timeout value), regardless
of the `data->timeout`/`data->retries` values passed; `tests/acct-async-tests.sh` exercises this
end-to-end via `rc_acct_async()`, asserting completion in well under `radius_timeout`.
**Links:** REQ-NET-NET-009, REQ-NET-ERR-001, REQ-ATTR-NET-030 (attrs.md; the `rc_acct_async()`
caller contract)

### REQ-NET-NET-018 — A server name that resolves to multiple addresses is tried address-by-address, not just the first

**Requirement:** `radcli_transport_exchange()` (internal-only, declared in `include/includes.h`,
not `include/radcli/radcli.h`/`lib/radcli.map.in`) MUST iterate every address a server name
resolves to (every `struct addrinfo` in the list `rc_getaddrinfo()`/`rc_find_server_addr()`
returns, in the order returned), rather than only the first. For each address it MUST open a
fresh socket and re-derive the local source address (`rc_get_srcaddr()`) before use — not reuse
a socket or source address computed for a previous address — because addresses in the list can
differ in family (IPv4/IPv6). Each address gets its own send/retry/receive budget
(`data->retries` attempts, `REQ-NET-NET-009`'s per-attempt timeout semantics apply per address,
not once across the whole name); an address is abandoned in favor of the next only after its own
retry budget is exhausted (`TIMEOUT_RC`) or its socket cannot be opened/bound. `TIMEOUT_RC` MUST
only be returned once every address in the list has been exhausted this way. `no_wait` mode
(`REQ-NET-NET-017`) is unaffected by this requirement: it sends once, to the first resolved
address only, and returns without trying any other address, since there is no reply to judge a
second attempt by.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:477-716 (`radcli_transport_exchange()`'s `for (cur_addr = auth_addr;
cur_addr != NULL; cur_addr = cur_addr->ai_next)` loop, fresh `sfuncs->get_fd()`/
`rc_get_srcaddr()` per iteration, inner send/poll/retry loop scoped to `cur_addr`); lib/sendserver.c:1061-1066
(`rc_send_server_ctx()` delegating its socket/retry/receive step to `radcli_transport_exchange()`)
**Acceptance:** [NET] shell, local, no root — `tests/dns-failover-tests.sh` points `authserver` at
a name (`localhost`) that resolves to both an IPv4 and an IPv6 loopback address, with a mock
RADIUS server (`tests/radius-server.py`) listening on only whichever address `getaddrinfo()`
returns *second*; asserts the request still succeeds, and that it took roughly one exhausted
retry budget (not an instant reply, and not a hang across both addresses' budgets) — evidence
that the first address was actually tried and abandoned before the second answered.
**Links:** REQ-NET-NET-009 (the per-address retry/timeout budget this layers on top of),
REQ-NET-NET-017 (`no_wait`'s single-address exception to this requirement)

---

## SEC — Message-Authenticator, Response Authenticator, TLS/DTLS credential handling

Per `contrib/ai/personas/radcli-core-dev.md`'s Security Vulnerability Taxonomy, this file carries
radcli's most safety-critical requirements: response forgery, replay, and TLS/DTLS downgrade are
all reachable through this transport layer. Negative requirements (MUST NOT) are stated before
the corresponding positive (MUST) behavior, per `doc/requirements/README.md`.

### REQ-NET-SEC-001 — An Access-Request/Accounting-Request Authenticator MUST NOT be predictable, and MUST use a cryptographic RNG

**Requirement:** The Access-Request Authenticator MUST NOT be derived from a
non-cryptographic source (`rand()`/counters/time); it MUST be filled via
`rc_get_random_bytes()` (`lib/rc-random.c`), which uses
`gnutls_rnd(GNUTLS_RND_NONCE, ...)` when built with GnuTLS, or `getentropy()`
otherwise, and MUST treat a negative/nonzero return as fatal (`assert`) rather
than silently proceeding with a partially- or un-randomized buffer. A
predictable Request Authenticator would let an off-path attacker precompute a
valid User-Password obfuscation XOR-mask or Response Authenticator MD5 input.
**Strength:** MUST NOT (weak RNG) ; MUST (gnutls_rnd/getentropy, fail on error)
**Status:** DERIVED
**Source:** lib/rc-random.c:40 (`rc_get_random_bytes`); lib/sendserver.c:1036
(call site for Access-Request); REQ-GEN-TECH-001, REQ-GEN-SEC-007
**Acceptance:** [SEC] code-review — `rc_get_random_bytes()`'s only entropy
source is `gnutls_rnd`/`getentropy`; the `assert` is not compiled out
(`NDEBUG` builds are not the project's release configuration — flag if this
changes).
**Links:** REQ-GEN-TECH-001, REQ-GEN-SEC-007 (general.md)

### REQ-NET-SEC-002 — Accounting-Request Authenticator MUST be computed as MD5(code‖id‖length‖zero-vector‖attrs‖secret), never left zero or reused

**Requirement:** For `PW_ACCOUNTING_REQUEST`, `rc_send_server_ctx()` MUST zero
`auth->vector` before hashing, compute `vector = MD5(auth_header_with_zero_vector ‖ attrs ‖
secret)` per RFC 2866 §3, and place the digest in `auth->vector` before transmission — the
zeroing and the hash MUST happen in that order so the digest does not include stale/uninitialized
vector bytes from a previous request reusing the same stack buffer.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:632-648
**Acceptance:** [SEC] unit, local — capture an Accounting-Request on the wire and recompute
MD5(header‖attrs‖secret) with the vector field zeroed; it MUST equal the transmitted
`auth->vector`.

### REQ-NET-SEC-003 — Access-Request MUST carry a Message-Authenticator attribute, computed as HMAC-MD5 over the full packet with the placeholder zeroed

**Requirement:** For non-accounting requests, `add_msg_auth_attr()` MUST append an 18-byte
Message-Authenticator attribute (type 80, length 18, zeroed 16-byte placeholder), set
`auth->length` to include it, then compute `HMAC-MD5(secret, full_packet_including_zeroed_MA)`
per RFC 2869 §5.14 and overwrite the placeholder with the result — the length field MUST already
reflect the attribute's presence before the HMAC is computed, since the HMAC covers the whole
packet including its own (zeroed) slot.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c (`add_msg_auth_attr`); `rc_send_server_ctx()`'s non-accounting
branch (packing budget reserves 2+MD5_DIGEST_SIZE=18 bytes ahead of time, passed as `buflen` to
`radcli_avp_encode()`)
**Acceptance:** [SEC] unit, local — capture an Access-Request; verify it contains a
Message-Authenticator attribute whose value equals HMAC-MD5-secret over the packet with that
16-byte field zeroed.
**Links:** REQ-GEN-MEM-005 (packing uses `pkt_buf` via `radcli_avp_encode()`, lib/avp.c;
budget reserved for the attribute appended after it returns). `rc_pack_list()` (lib/sendserver.c)
implements the same wire format and is still used directly by `tests/pack.c`, but is no longer
called from `rc_send_server_ctx()`.

### REQ-NET-SEC-004 — A reply MUST NOT be accepted unless its Response Authenticator matches MD5(code‖id‖length‖request-vector‖attrs‖secret)

**Requirement:** `rc_check_reply()` MUST NOT treat any reply as valid based on source
address, matching ID, or well-formed attributes alone. It MUST substitute the *original
request's* vector into the reply's Authenticator field position, compute
MD5(reply-with-substituted-vector ‖ secret), and reject (`BADRESP_RC`) any reply whose received
Authenticator does not match — this is what prevents an off-path attacker who can guess/observe
the request ID from injecting a forged Access-Accept without knowing the shared secret.
**Strength:** MUST NOT (accept without this check) ; MUST (perform the check, reject on mismatch)
**Status:** DERIVED
**Source:** lib/sendserver.c:246-292
**Acceptance:** [SEC] negative, local — a forged reply with correct `id` but wrong or missing
Response Authenticator (or authenticator computed with a different secret) MUST be rejected with
`BADRESP_RC`, not accepted. Per `REQ-GEN-TEST-003`, this negative test is mandatory and must
precede any positive test.
**Links:** REQ-GEN-SEC-006, REQ-GEN-TEST-003

### REQ-NET-SEC-005 — Message-Authenticator comparison MUST NOT be skipped, and MUST be computed with the Request Authenticator substituted, per RFC 3579 §3.2

**Requirement:** `validate_message_authenticator()` MUST NOT compute HMAC-MD5 over the raw
received bytes; it MUST first substitute the *original Access-Request's* Authenticator
(`req_auth`, i.e. the value in `vector`, not the reply's own Response Authenticator) into the
copy's Authenticator field, and zero the Message-Authenticator attribute's value in that copy,
before computing HMAC-MD5(secret, copy). A reply whose Message-Authenticator attribute is present
but has the wrong length (not exactly `2 + MD5_DIGEST_SIZE`) MUST be rejected outright
(`return -1`), not silently ignored or truncated/read out of bounds.
**Strength:** MUST NOT (compare against unsubstituted bytes, or skip length check) ; MUST
(substitute request authenticator, validate length, reject on mismatch)
**Status:** DERIVED
**Source:** lib/sendserver.c:346-404 (`validate_message_authenticator`, doc comment at 350-355
cites RFC 3579 §3.2 explicitly)
**Acceptance:** [SEC] negative, local — a reply with a Message-Authenticator computed over the
Response Authenticator (a common implementation bug in third-party servers, deliberately
mismatched here) MUST be rejected; a reply with `attr_len != 18` for the Message-Authenticator
attribute MUST be rejected without reading past the declared length. Per `REQ-GEN-TEST-003`,
mandatory negative-first test.
**Links:** REQ-GEN-TEST-003

### REQ-NET-SEC-006 — Message-Authenticator MUST be verified whenever present, regardless of RADIUS response code

**Requirement:** `rc_send_server_ctx()` MUST call `validate_message_authenticator()` and reject
the reply (`ERROR_RC`) on mismatch whenever a `PW_MESSAGE_AUTHENTICATOR` attribute is present in
an `AUTH`-type reply — including Access-Reject and Access-Challenge, not only Access-Accept —
since an attacker able to forge a valid-looking reject/challenge (e.g. to trigger fallback to a
weaker method or DoS a legitimate login) is still a spoofing attack the Message-Authenticator
exists to prevent.
**Strength:** MUST NOT (accept a mismatched MA on any AUTH reply code) ; MUST (verify whenever
present)
**Status:** DERIVED
**Source:** lib/sendserver.c:862-877 (verification is inside `if (type == AUTH)`, gated only on
attribute presence via `rc_avpair_get`, not on `recv_auth->code`)
**Acceptance:** [SEC] negative, local — a forged Access-Reject carrying a
Message-Authenticator computed with the wrong secret MUST be rejected (`ERROR_RC`), not passed
through as `REJECT_RC`.

### REQ-NET-SEC-007 — BLAST RADIUS mitigation: Message-Authenticator MUST be the first attribute in an Access-* reply over RADIUS/UDP and RADIUS/TCP, unless explicitly disabled; MUST NOT be enforced over RADIUS/TLS or RADIUS/DTLS

**Requirement:** Per `draft-ietf-radext-deprecating-radius-10` Section 4 (the BLAST RADIUS
mitigation), for `AUTH`-type replies received over `RC_SOCKET_UDP`/`RC_SOCKET_TCP`,
`rc_send_server_ctx()` MUST reject (`ERROR_RC`) a reply whose first attribute is not
`PW_MESSAGE_AUTHENTICATOR` (or which has zero attributes), UNLESS the config option
`require-message-authenticator` is explicitly set to `false`/`no`. This check MUST run whether or
not a Message-Authenticator attribute was found anywhere else in the packet — a reply that
carries a *valid* Message-Authenticator attribute in a later position is still rejected by
default, because the MD5-prefix-collision attack BLAST RADIUS exploits works by prepending
attacker-controlled bytes before a genuine, valid Message-Authenticator. Conversely, per the same
Section 4 clause ("MUST NOT be applied to RADIUS/TLS or RADIUS/DTLS"), this presence/position
enforcement and the `require-message-authenticator` opt-out MUST NOT be applied when
`rh->so_type` is `RC_SOCKET_TLS` or `RC_SOCKET_DTLS` — those transports are already
integrity-protected end-to-end, so the MD5-prefix attack this mitigation defends against is not
reachable, and a reply missing or misordering Message-Authenticator MUST still be accepted
(subject to `REQ-NET-SEC-006`'s opportunistic validation, which still applies to all transports).
**Strength:** MUST NOT (accept non-first or absent MA by default, over UDP/TCP) ; MUST (enforce
position over UDP/TCP, respect the opt-out) ; MUST NOT (enforce presence/position over TLS/DTLS)
**Status:** DERIVED
**Source:** lib/sendserver.c:862-897 (the `rh->so_type != RC_SOCKET_TLS && rh->so_type !=
RC_SOCKET_DTLS` guard at 879 scopes the enforcement to UDP/TCP)
**Acceptance:** [SEC] negative, local — over UDP/TCP, a reply with a valid Message-Authenticator
attribute appended *after* another attribute MUST be rejected under default config, and accepted
when `require-message-authenticator=false` is set. Per `REQ-GEN-TEST-003`, negative test
mandatory. [SEC] positive, local — over TLS, a reply with Message-Authenticator absent, or present
but not first, MUST be accepted (`OK_RC`) regardless of `require-message-authenticator`; a reply
with a Message-Authenticator attribute present but cryptographically wrong MUST still be rejected
(exercises `REQ-NET-SEC-006`, unaffected by this requirement's transport scoping).
**Links:** REQ-GEN-TEST-003, REQ-NET-SEC-006, REQ-NET-NET-012 (`rh->so_type` is what this
requirement branches on), REQ-CONFIG-* (`require-message-authenticator` option, see `config.md`)

### REQ-NET-SEC-008 — Message-Authenticator enforcement (REQ-NET-SEC-006/007) applies only to `AUTH`-type exchanges, not `ACCT`

**Requirement:** `rc_send_server_ctx()` MUST NOT apply the Message-Authenticator presence,
position, or validity checks to Accounting-Response packets (`type == ACCT`); accounting
integrity relies solely on the Response Authenticator (`REQ-NET-SEC-004`), per RFC 2866, which
predates the Message-Authenticator/BLAST RADIUS mitigation and does not require it.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** lib/sendserver.c:865 (`if (type == AUTH)` gates the entire MA-verification block)
**Acceptance:** [SEC] unit, local — an Accounting-Response with no Message-Authenticator
attribute at all is accepted (`OK_RC`) as long as its Response Authenticator is valid.

### REQ-NET-SEC-009 — Shared secret MUST be zeroed from stack memory on every exit path of `rc_send_server_ctx()`, scrubbed by the buffer's owner rather than by `radcli_transport_exchange()`

**Requirement:** Every early-return and the final return path in `rc_send_server_ctx()`
(`lib/legacy/send.c`) that has already copied the shared secret into its local
`secret[MAX_SECRET_LENGTH + 1]` buffer MUST `memset()` it to zero before returning, including
error paths reached before `radcli_transport_exchange()` is even called (address-discovery
failure, attribute-conversion failure, packet-encoding overflow) as well as the single path after
`radcli_transport_exchange()` returns (covering every one of its outcomes — success, timeout, and
error — with one `memset()` rather than a separate one per outcome) — so a secret does not linger
in a stack frame that could be exposed by a later uninitialized-read bug or core dump.
`radcli_transport_exchange()` itself (`lib/sendserver.c`) deliberately does NOT scrub `secret`
before returning: it cannot know whether its caller still needs the secret (`radcli_request_perform()`,
the `radcli2.h` counterpart to this call, needs it one call later to decode salt-encrypted reply
attributes — see `REQ-NET2-RECV-014`, `net2.md`), so scrubbing is the responsibility of whichever
caller actually owns the buffer once it is done with it: `rc_send_server_ctx()` here, and
`radcli_request_free()` (`lib/request.c`) for the `radcli2.h` path.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/legacy/send.c:343,408,421,444,466 (5 `memset(secret, ...)` call sites — 4 before
`radcli_transport_exchange()` is reached, 1 single site after it covering all of its return
outcomes); lib/sendserver.c's doc comment above `radcli_transport_exchange()` (explains why that
function does not scrub `secret` itself); lib/request.c:534 (`radcli_request_free()`'s equivalent
scrub for the `radcli2.h` path, REQ-NET2-INIT-007, `net2.md`)
**Acceptance:** [MEM][SEC] code-review — any new early-return/`goto` added to
`rc_send_server_ctx()` (`lib/legacy/send.c`) after `secret[]` is populated must be checked for a
paired `memset(secret, '\0', sizeof(secret))`; `radcli_transport_exchange()` (`lib/sendserver.c`)
and `radcli_transport_send_async()` MUST NOT be assumed to scrub the caller's `secret` buffer on
the caller's behalf except where a function-local copy never reaches the caller (e.g.
`radcli_transport_send_async()`'s own early-failure path before `out->secret` is populated).
**Links:** REQ-GEN-SEC-006, REQ-GEN-MEM-003, REQ-NET2-INIT-007 (net2.md)

### REQ-NET-SEC-010 — Response Authenticator and Message-Authenticator comparisons use a constant-time compare under GnuTLS builds; the non-GnuTLS (`-Dtls=disabled`) fallback has a documented timing side-channel

**Requirement:** `rc_memcmp()` (`lib/util.h:28-35`) is used for both the Response Authenticator
compare (`REQ-NET-SEC-004`) and the Message-Authenticator compare (`REQ-NET-SEC-005`). When built
with GnuTLS it MUST call `gnutls_memcmp()`, which GnuTLS documents as side-channel resistant,
satisfying `REQ-GEN-SEC-006`'s "MUST NOT use a data-dependent-timing function" for secret-derived
comparisons. When built with `-Dtls=disabled` (`HAVE_GNUTLS` undefined — the build mode the
`tests-notls` CI job exercises), it falls back to plain `memcmp()`, which is not constant-time.
This is an accepted, documented limitation of `-Dtls=disabled` builds, noted in `AGENTS.md`'s
Build System section: `REQ-GEN-TECH-001` treats GnuTLS as the canonical/expected crypto backend,
and a hand-rolled constant-time fallback for the non-GnuTLS path is not planned.
**Strength:** MUST NOT (non-constant-time secret comparison) under `HAVE_GNUTLS`; accepted residual
risk under `-Dtls=disabled`
**Status:** DERIVED
**Source:** lib/util.h:28-35; lib/sendserver.c:283-284,402-403 (both call sites); meson.build:63-65
(`HAVE_GNUTLS` tied to `-Dtls`); .github/workflows/tests.yaml (`tests-notls` job builds with
`-Dtls=disabled`)
**Acceptance:** [SEC] documentation — `AGENTS.md`'s `-Dtls=disabled` option description notes this
residual timing side-channel.
**Links:** REQ-GEN-SEC-006, REQ-GEN-TECH-001

### REQ-NET-SEC-011 — TLS/DTLS transport MUST NOT proceed without either X.509 CA trust or a PSK credential configured

**Requirement:** `rc_init_tls()` MUST fail (`ret = -1`, `LOG_CRIT`) if neither a CA file (or
cert+key pair) nor a PSK key was configured — either via `authserver`'s secret in
`psk@user@hexkey` form, or via `radcli2.h`'s `radcli_ctx_set_tls_psk()`
(`doc/requirements/config2.md` `REQ-CONFIG2-SECRET-002`), which `rc_init_tls()` checks first and
which sets the same `st->psk_cred` this requirement's `cred_set` check reads regardless of which
path set it — `cred_set` MUST be nonzero before `init_session()` is reached. This prevents silently
establishing an anonymous/unauthenticated TLS session (GnuTLS would otherwise be willing to
negotiate anonymous key exchange under some priority strings) that provides confidentiality
without server authentication.
**Strength:** MUST NOT (proceed with `cred_set == 0`) ; MUST (fail closed)
**Status:** DERIVED
**Source:** lib/tls.c:401-460 (credential setup), 454-460 (`cred_set == 0` check)
**Acceptance:** [SEC] negative, local — a config with `serv-type=tls` and neither `tls-ca-file`
nor a `psk@...` secret fails `rc_apply_config()`.

### REQ-NET-SEC-012 — PSK priority string MUST exclude TLS 1.0 and non-PSK key exchange when PSK credentials are used

**Requirement:** When `st->psk_cred` is set, `init_session()` MUST call
`gnutls_priority_set_direct()` with `"NORMAL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:-VERS-TLS1.0"` —
disabling all non-PSK key exchange methods and TLS 1.0 — rather than relying on GnuTLS's
default priority string, which would otherwise permit certificate-based key exchange (irrelevant
without a certificate, but priority-string misconfiguration is a known downgrade vector) and
the deprecated TLS 1.0 protocol version.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c:401-413
**Acceptance:** [SEC] unit, local — a PSK-configured client's `ClientHello` cipher suite list
(captured via a test proxy) contains only PSK key-exchange suites and offers a minimum protocol
version above TLS 1.0.

### REQ-NET-SEC-013 — Certificate-based TLS/DTLS MUST verify the peer certificate chain and hostname unless explicitly disabled

**Requirement:** `cert_verify_callback()` MUST call `gnutls_certificate_verify_peers3()` with the
configured server hostname (from `authserver`) and reject the handshake
(`GNUTLS_E_CERTIFICATE_ERROR`) on any nonzero verification status, UNLESS
`tls-verify-hostname=false`/`no` is set, in which case it MUST fall back to
`gnutls_certificate_verify_peers2()` (chain/trust verification without hostname matching) rather
than skipping verification entirely — hostname checking, not chain trust, is the opt-out.
**Strength:** MUST NOT (accept an unverified or hostname-mismatched certificate by default) ;
MUST (verify chain always; verify hostname unless explicitly disabled)
**Status:** DERIVED
**Source:** lib/tls.c:261-303 (`cert_verify_callback`); lib/tls.c:396-399
(`tls-verify-hostname` parsing) [AMBIGUOUS — see below]
**Acceptance:** [SEC] negative, local — a server presenting a certificate for the wrong hostname
MUST fail the handshake under default config, and succeed (chain still validated) with
`tls-verify-hostname=false`.
**Links:** REQ-CONFIG-* (`tls-verify-hostname`, `tls-ca-file`, see `config.md`)

### REQ-NET-SEC-014 — `tls-verify-hostname` MUST only disable hostname checks for `"false"`/`"no"`, not for any other value

**Requirement:** The condition at `lib/tls.c:397` MUST be
`if (p && (strcasecmp(p, "false") == 0 || strcasecmp(p, "no") == 0))` — both branches require an
exact (case-insensitive) match. `skip_hostname_check` MUST NOT be set for any other configured
value of `tls-verify-hostname` (including `"true"`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c:396-399; matches the same two-`==0` pattern at
lib/sendserver.c:882-883
**Acceptance:** [SEC] negative, local — set `tls-verify-hostname=true` and confirm hostname
verification is still performed; set `tls-verify-hostname=no` and confirm it is skipped.
**Links:** REQ-NET-SEC-013, REQ-GEN-TEST-003, REQ-NET-NET-016 (the field this check writes was
found to be left undefined on the call path used for every session, not just reconnects)

### REQ-NET-SEC-015 — Session teardown sends a TLS/DTLS close-notify only after a completed handshake; radcli does not suppress the SIGPIPE this can raise

**Requirement:** `deinit_session()` MUST call `gnutls_bye(session, GNUTLS_SHUT_WR)` (retrying on
`GNUTLS_E_INTERRUPTED`) only when `ses->handshake_done` is set — never on a session whose
handshake never completed (e.g. `connect()` failure), where no negotiated cipher state exists for
`gnutls_bye()` to use meaningfully. Per `REQ-GEN-SEC-001`, radcli MUST NOT call
`signal()`/`sigaction()` to suppress the `SIGPIPE` this write can raise if the peer has already
reset the connection; that decision belongs entirely to the embedding application.
**Strength:** MUST (gate `gnutls_bye` on `handshake_done`) ; MUST NOT (install a signal handler
or pass `MSG_NOSIGNAL`-equivalent suppression to work around it)
**Status:** DERIVED
**Source:** lib/tls.c:306-329 (`deinit_session`, comment at 312-317 explains the
`handshake_done` gate); grep confirms no `MSG_NOSIGNAL`/`SO_NOSIGPIPE`/`signal(`/`sigaction(` in
`lib/*.c`
**Acceptance:** [SEC] negative, local — `grep -n 'MSG_NOSIGNAL\|SO_NOSIGPIPE' lib/*.c` returns no
matches; a TLS teardown against a session whose `connect()` failed does not call `gnutls_bye()`.
**Links:** REQ-GEN-SEC-001

---

## ERR — status code contract and malformed-reply rejection

### REQ-NET-ERR-001 — `rc_send_status` is the complete, exhaustive return-code contract for `rc_send_server()`/`rc_send_server_ctx()`

**Requirement:** Every return path in `rc_send_server_ctx()` MUST return one of
`NETUNREACH_RC(-4)`, `BADRESPID_RC(-3)`, `BADRESP_RC(-2)`, `ERROR_RC(-1)`, `OK_RC(0)`,
`TIMEOUT_RC(1)`, `REJECT_RC(2)`, `CHALLENGE_RC(3)` — no other integer value, and no undefined/
uninitialized `result` on any path. `BADRESPID_RC` MUST NOT itself be a terminal return value from
`rc_send_server_ctx()` (per `REQ-NET-NET-010`, it causes a retry-loop continuation internally,
never a caller-visible return), so in practice only the other seven values are observable by
callers.
**Strength:** MUST
**Status:** DERIVED
**Source:** include/radcli/radcli.h:473-484 (`rc_send_status` enum); lib/sendserver.c (every
`result = ...; goto cleanup/exit_error` site; `910-930` for the code-to-status mapping)
**Acceptance:** [ERR] code-review — every `return`/`goto cleanup` path in
`rc_send_server_ctx()` assigns `result` from the enumerated set before falling through to
`return result`.
**Links:** REQ-NET-NET-017 (the `no_wait` fire-and-forget mode holds to this same contract,
without exception — `no_wait` never produces `TIMEOUT_RC`)

### REQ-NET-ERR-002 — A reply whose declared RADIUS length is outside [20, 4096] is rejected before any further parsing

**Requirement:** `rc_check_reply()` MUST reject (`BADRESP_RC`) any reply whose `ntohs(auth->length)`
is less than `AUTH_HDR_LEN`-equivalent (20) or greater than 4096 (RFC 2865's maximum RADIUS
packet size), before computing the Response Authenticator digest — a too-short length would make
the subsequent `memcpy((char*)auth + totallen, secret, secretlen)` read/write outside the
received-packet region of `recv_buffer`; a too-large length is rejected as a defense-in-depth
sanity check even though `recv_buffer`/`RC_BUFFER_LEN` (8192) could technically hold more.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:257-263
**Acceptance:** [ERR][MEM] negative, local — a reply with `length` field set to 4 or to 8000
bytes MUST be rejected with `BADRESP_RC` without a crash/ASan violation.

### REQ-NET-ERR-003 — Every RADIUS attribute in a reply is bounds-checked (type≠0, length≥2, length fits remaining buffer) before `rc_avpair_gen()` parses it

**Requirement:** After the length/ID/digest checks, `rc_send_server_ctx()` MUST walk the reply's
attribute TLVs with `pb_peek_byte()`/`pb_pull()` and reject (`ERROR_RC`, with the secret zeroed
per `REQ-NET-SEC-009`) any attribute whose type is `0`, whose length is `< 2`, or whose length
exceeds the remaining declared packet length — before handing the buffer to
`rc_avpair_gen()` for attribute-value extraction, so a malformed attribute chain from an
untrusted network peer cannot cause `rc_avpair_gen()` to read past the packet boundary.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:801-845
**Acceptance:** [ERR][MEM] negative, local — a crafted reply with an attribute claiming length
255 but only 3 bytes remaining in the packet MUST be rejected with `ERROR_RC`, not passed to
`rc_avpair_gen()`.
**Links:** REQ-GEN-MEM-005, REQ-ATTR-* (`rc_avpair_gen`, see `attrs.md`)

### REQ-NET-ERR-004 — `recvfrom()`/`sendto()` interrupted by `EINTR` are retried transparently; other errors terminate the attempt

**Requirement:** Both the `sendto()` and `recvfrom()` call sites in `rc_send_server_ctx()` MUST
retry the same call when it fails with `errno == EINTR`, without counting it against
`data->retries` or returning to the caller — a signal delivered to the embedding application's
process (which radcli does not control or suppress, per `REQ-GEN-SEC-001`) MUST NOT surface as a
spurious RADIUS-layer failure. `EAGAIN` on `recvfrom()` MUST also `continue` the poll/recv loop
(non-blocking socket transiently not ready) rather than fail. Any other `errno` MUST close the
socket, zero the secret, and return `ERROR_RC` (or `NETUNREACH_RC` for `ENETUNREACH` on `sendto()`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:682-695 (sendto/EINTR, ENETUNREACH), 708-713 (poll/EINTR),
726-748 (recvfrom/EINTR/EAGAIN)
**Acceptance:** [ERR] unit, local — a `sendto()` returning `-1`/`EINTR` is retried without
incrementing the retry counter; `ENETUNREACH` maps specifically to `NETUNREACH_RC`, distinct from
generic `ERROR_RC`, so callers/`rc_aaa_ctx_server()` can distinguish "try next server" cases (see
`attrs.md`'s multi-server loop, `lib/buildreq.c:264`).
**Links:** REQ-GEN-SEC-001

### REQ-NET-ERR-005 — A short (`length < AUTH_HDR_LEN`) or truncated (`length < ntohs(auth->length)`) UDP/TCP/TLS read is rejected immediately, not padded or partially processed

**Requirement:** `rc_send_server_ctx()` MUST check the raw byte count returned by `recvfrom()`
against both `AUTH_HDR_LEN` (20) and the packet's own declared `length` field before doing
anything else with the buffer, rejecting with `ERROR_RC` if either check fails — a
transport that delivers fewer bytes than the RADIUS header requires, or fewer bytes than the
packet claims to contain, MUST NOT be treated as a valid (if short) reply.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:750-761
**Acceptance:** [ERR] negative, local — a reply truncated to 10 bytes, and a reply whose header
declares 200 bytes but whose UDP datagram contains only 50, both yield `ERROR_RC`.

### REQ-NET-ERR-006 — An oversized UDP datagram is trimmed to the RADIUS-declared length before parsing, not rejected

**Requirement:** If a UDP `recvfrom()` returns more bytes than `ntohs(recv_auth->length)`
declares (the datagram has trailing padding/garbage beyond the RADIUS packet), `rc_send_server_ctx()`
MUST silently trim `length` down to the declared value before attribute walking, rather than
rejecting the reply — RFC 2865 §3 allows this ("A Length greater than the length of the received
packet MUST cause the packet to be silently discarded... A Length less than or equal to the length
of the received packet should be processed").
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:796-799
**Acceptance:** [ERR] unit, local — a UDP datagram padded with 20 extra trailing bytes beyond its
declared RADIUS length still parses successfully, ignoring the padding.

### REQ-NET-ERR-007 — An unrecognized top-level RADIUS reply code yields `BADRESP_RC`, not silent acceptance or a crash

**Requirement:** After all authentication checks pass, `rc_send_server_ctx()`'s final `switch
(recv_auth->code)` MUST map `PW_ACCESS_ACCEPT`/`PW_PASSWORD_ACK`/`PW_ACCOUNTING_RESPONSE` to
`OK_RC`, `PW_ACCESS_REJECT`/`PW_PASSWORD_REJECT` to `REJECT_RC`, `PW_ACCESS_CHALLENGE` to
`CHALLENGE_RC`, and any other code (including codes reserved for RADIUS requests, like
`PW_ACCESS_REQUEST` itself, replayed back by a misbehaving or malicious peer) to `BADRESP_RC`
with a logged error, via an explicit `default:` case.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:910-930
**Acceptance:** [ERR] negative, local — a reply with `code = PW_STATUS_SERVER` (12, a code
radcli never sends as a request but which passes all other checks if forged with a valid
Response Authenticator) yields `BADRESP_RC`.

---

## TEARDOWN — socket, session, and namespace lifecycle

### REQ-NET-TEARDOWN-001 — The UDP/TCP socket opened for a request is closed via `sfuncs->close_fd` exactly once, on every exit path after `get_fd()` succeeds

**Requirement:** Every error and success path in `radcli_transport_exchange()` (the socket/retry/
receive step `rc_send_server_ctx()` and `radcli_request_perform()`
all delegate to) reached after `sfuncs->get_fd()` returns a valid descriptor MUST call
`SCLOSE(sockfd)` exactly once before returning — a plain UDP/TCP socket MUST NOT be leaked (never
closed) across repeated `rc_auth()`/`rc_acct()`/`radcli_request_*()` calls, and MUST NOT be closed
twice: closing an already-closed fd risks closing an unrelated descriptor that another allocation
(in this process, or another thread, since radcli is called from caller-created threads) has since
been given that same, now-freed fd number — a real hazard, not just a leak. The `SCLOSE(fd)` macro
itself enforces the "at most once" half of this: it calls `sfuncs->close_fd(fd)` (a no-op if
`close_fd` is NULL) and then sets `fd = -1`, so a later unconditional close guarded by
`if (sockfd >= 0)` (the shared `cleanup:` label) cannot repeat an already-done close — this is
enforced once, in the macro, rather than by convention at each of its call sites. This requirement
does not apply to the TLS/DTLS vtable, whose `close_fd` is intentionally NULL — see
`REQ-NET-TEARDOWN-002`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:33-36 (`SCLOSE(fd)` macro: closes via `sfuncs->close_fd` if set, then
`fd = -1`); call sites at lines 576, 586 (both `continue` to the next resolved address, which
re-acquires `sockfd` before it could reach `cleanup:`), 626, 650, 670, 682, 706 (mid-function
closes, each safe to immediately follow with `cleanup:`'s own guarded close since the macro already
nulled `sockfd`), and 845 (`cleanup:` label's own close, guarded by `if (sockfd >= 0)`);
lib/config.c:500-512 (`close_fd` set to `plain_close_fd` for UDP/TCP, so `SCLOSE` is a real
`close(2)`, not a no-op, for the default transport)
**Acceptance:** [TEARDOWN] code-review — every new early-return in `radcli_transport_exchange()`
after `get_fd()` succeeds must be checked for a preceding `SCLOSE(sockfd)` (no leak); the
no-double-close half no longer needs a per-call-site check, since the macro enforces it structurally.

### REQ-NET-TEARDOWN-002 — TLS/DTLS sockets are NOT closed per-request; they persist across calls and are torn down only by `rc_deinit_tls()`/session restart

**Requirement:** `default_socket_funcs`'s TLS/DTLS equivalent (`rh->so` as populated by
`rc_init_tls()`) MUST leave `close_fd` NULL, so `SCLOSE()` in `rc_send_server_ctx()` is a no-op
for TLS/DTLS transport — the underlying `gnutls_session_t`/socket is a long-lived connection
reused across many `rc_auth()`/`rc_acct()` calls, not opened and closed per request like UDP/TCP.
It MUST be torn down only by `deinit_session()`, invoked either from `restart_session()`
(replacing it with a fresh session) or `rc_deinit_tls()` (final, caller-invoked cleanup via
`rc_destroy()`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c:839-844 (`rh->so.close_fd` never assigned, i.e. stays NULL from the
`memset(&rh->so, 0, ...)` at line 678); lib/sendserver.c:32 (`SCLOSE` no-ops on NULL `close_fd`)
**Acceptance:** [TEARDOWN] unit, local — 100 consecutive `rc_auth()` calls over a TLS-configured
`rh` use the same underlying fd (via `rc_tls_fd()`), not a new one per call.
**Links:** REQ-NET-NET-007

### REQ-NET-TEARDOWN-003 — `rc_deinit_tls()` releases the session, both credential sets, and the `tls_st` itself, and is safe to call on a partially-initialized state

**Requirement:** `rc_deinit_tls()` MUST call `deinit_session()` only if `st->ctx.init != 0`
(guards against a `tls_st` that was allocated but never reached `init_session()`), MUST free
`st->x509_cred` and `st->psk_cred` independently (only one is normally set, but both are checked
unconditionally), and MUST `free(st)` unconditionally at the end — including when `st` is NULL
(the top-level `if (st)` guard makes the body a no-op, but the trailing `free(st)` is outside
that guard and MUST tolerate `free(NULL)`).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c:627-653
**Acceptance:** [TEARDOWN][MEM] unit, local — `rc_deinit_tls()` on an `rh` where `rc_init_tls()`
failed before allocating `st` (`rh->so.ptr == NULL`) does not crash; `rc_deinit_tls()` after a
successful PSK-only init does not attempt to free an unset `x509_cred`.
**Links:** REQ-GEN-MEM-002

### REQ-NET-TEARDOWN-004 — `restart_session()` never leaves `st->ctx` in a state pointing at a freed session on failure

**Requirement:** If `init_session()` (called from `restart_session()` to build a replacement
session into a local `tmps`) fails, `restart_session()` MUST return -1 without modifying
`st->ctx` at all — the old (broken but still-allocated) session remains in place, so a caller
retry loop sees a consistent, non-dangling `tls_st`. Only on `init_session()` success does
`restart_session()` deinit the old `st->ctx` and `memcpy` `tmps` over it. When the new session
happens to reuse the same fd number as the old one (`tmps.sockfd == st->ctx.sockfd`), it MUST
mark the old `ctx.sockfd` as `-1` before calling `deinit_session(&st->ctx)`, so that
`deinit_session()`'s `close(ses->sockfd)` does not close the fd the new session now owns.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c:519-553
**Acceptance:** [TEARDOWN][MEM] unit, local — force `init_session()` to fail during a restart
(e.g. unreachable server); `rc_tls_fd()` afterward still returns the previous session's fd, not
-1 or a closed descriptor. Force a restart where the kernel reissues the same fd number; the new
session's fd MUST remain open and usable afterward.
**Links:** REQ-GEN-MEM-003, REQ-NET-NET-016 (same `tmps`, covering its starting state rather
than the failure path)

### REQ-NET-TEARDOWN-005 — Namespace context is always restored before `rc_send_server_ctx()`/`rc_init_tls()`/`rc_deinit_tls()` return, even on every error branch

**Requirement:** See `REQ-NET-NET-015` for the full analysis; restated here as a teardown
obligation: every function that calls `rc_set_netns()` MUST reach a matching `rc_reset_netns()`
call on its way out, on both success and error paths, since `rc_reset_netns()` also `close()`s
the saved namespace file descriptor (`lib/util.c:244-248`) — skipping it on an error path is both
a namespace leak (thread stuck in the wrong netns) and a file descriptor leak.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/sendserver.c:460-466,932-947; lib/tls.c:680-686,845-851,864-867; lib/util.c:174-253
**Acceptance:** [TEARDOWN] code-review — same acceptance criterion as `REQ-NET-NET-015`.
**Links:** REQ-NET-NET-015

---

## Phase 5 — Completeness and gap analysis

Cross-referencing the API surface enumerated from `include/radcli/radcli.h`, `lib/radcli.map.in`,
and `include/includes.h` against the requirements above:

| Public symbol (map.in) | Covered by |
|---|---|
| `rc_send_server` | REQ-NET-NET-001, REQ-NET-ERR-001 (thin wrapper over `rc_send_server_ctx`, `lib/sendserver.c:231-234`) |
| `rc_tls_fd` | REQ-NET-NET-013 |
| `rc_check_tls` | REQ-NET-NET-013, REQ-WATCHDOG-NET-004 (`doc/requirements/watchdog.md`) |
| `rc_get_socket_type` | REQ-NET-NET-012 |
| `rc_find_server_addr` | Called from `rc_send_server_ctx()` (`lib/sendserver.c:485`) but implemented/owned by `config.md` (server-list resolution is a config concern, not transport) — cited here as a caller dependency only, not duplicated. |
| `rc_get_srcaddr` | Called at `lib/sendserver.c:523` for `discover_local_ip`; implementation lives in `lib/ip_util.c`, owned by `util.md` — cited as caller dependency only. |
| `rc_openlog`, `rc_setdebug` | Out of scope for `net.md` (logging config, owned by `util.md`/`config.md`); `DEBUG()`'s `rh->debug` read in `lib/sendserver.c` is a per-handle field, not the global `REQ-GEN-SEC-005` exception (that's now `radcli_legacy_debug`, confined to the legacy shim) — not re-litigated here. |

`rc_send_server_ctx` and `RC_AAA_CTX`/`populate_ctx()` are internal (`lib/sendserver.c`, not in
`radcli.map.in`) but are the actual implementation behind the exported `rc_send_server`/`rc_aaa`
family; their contract is captured through the `rc_send_server`-citing requirements above and
`populate_ctx()`'s secret/vector copy is covered implicitly by `REQ-NET-SEC-009`'s "the secret is
zeroed after `populate_ctx()` runs" ordering (`lib/sendserver.c:856-860`) — no separate
requirement was needed since `RC_AAA_CTX`'s own contract (constructed correctly, freed via
`rc_aaa_ctx_free()`) belongs to `attrs.md`.

`SEND_DATA` (`include/radcli/radcli.h:512-523`) is covered structurally by
`REQ-NET-NET-009` (`timeout`, `retries` fields) and `REQ-NET-SEC-*` (`secret`,
`code`, `seq_nbr` fields); `send_pairs`/`receive_pairs` are `attrs.md`'s concern.

`rc_sockets_override` and `struct rc_conf`'s `so`/`so_type` fields (`include/includes.h`) are
internal-only per `REQ-NET-NET-002`; every function pointer in the vtable (`get_fd`,
`get_active_fd`, `close_fd`, `sendto`, `recvfrom`, `lock`, `unlock`, `static_secret`, `ptr`) is
exercised by at least one requirement above (`REQ-NET-NET-001/003/004/008`,
`REQ-NET-TEARDOWN-001/002`, `REQ-NET-SEC-011`'s `static_secret` handling via
`sfuncs->static_secret` at `lib/sendserver.c:498-501`).

No open `[UNDOCUMENTED]`/`[REVIEW]` gaps remain in this document.
