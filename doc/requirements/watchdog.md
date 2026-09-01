---
title: RFC 5997/3539 connection-liveness watchdog — RadSec session keepalive and dead-peer detection
generator: requirements-elicitation
id-prefix: REQ-WATCHDOG
categories:
  CFG: watchdog-interval option validation
  NET: watchdog send (automatic, via radcli_ctx_dispatch())/advisory-poll/reconnect
    behavior, rc_check_tls() opt-in wrapper
sources:
  - RFC 5997 (Status-Server as a RADIUS request; watchdog use, RFC 3539 SS3.4)
  - RFC 3539 SS3.4 (failed-transport detection via a watchdog timer)
  - draft-ietf-radext-reverse-coa-08 SS4.2 (Tw watchdog timer, 15s recommended default)
  - RFC 6614 SS2.3 / RFC 7360 SS3.2 (fixed RadSec secret used to encode the watchdog)
  - lib/config.c (`set_option_int()`)
  - lib/dae.c (`radcli2_priv_dae_send_watchdog()`, called automatically from
    `radcli_ctx_dispatch()`; `radcli_ctx_get_poll()`)
  - lib/tls.c (`radcli2_priv_check_tls()` / `rc_check_tls()`, `tls_int_st.last_recv`,
    `radcli2_priv_tls_force_reconnect()`)
  - include/radcli/radcli2.h
  - include/radcli/radcli-defs.h
  - tests/dae-radsec-watchdog.c
  - tests/watchdog-aaa.c
  - doc/requirements/config2.md (radcli_ctx construction and option storage, cited not owned)
  - doc/requirements/dae.md (RFC 5176 CoA/Disconnect and RadSec session ownership, cited not owned)
  - doc/requirements/net.md (transport/session lifecycle, `restart_session()`, cited not owned)
---

# RFC 5997/3539 Connection-Liveness Watchdog Requirements

Scope: the RFC 5997 Status-Server watchdog radcli sends to keep an idle RadSec
(TLS/DTLS) session alive and to detect a peer that has stopped responding —
`watchdog-interval` option validation, the automatic send folded into
`radcli_ctx_dispatch()`, `radcli_ctx_get_poll()`'s watchdog-deadline advisory,
and `rc_check_tls()`'s opt-in wrapper around the same mechanism (there is no
longer a public, caller-invoked send function — see `REQ-WATCHDOG-NET-001`).
This document was split out of
`config.md`, `dae.md`, and `net.md` on 2026-08-30 to gather a cross-cutting
concern (the watchdog touches config validation, the RadSec session, and the
transport layer) into one place; see those documents' `WITHDRAWN` stubs for
the original IDs. It complements `dae.md` (RFC 5176 CoA/Disconnect, which
shares the same RadSec session but is a distinct concern) and `net.md`
(transport/session lifecycle, `restart_session()`, cited not owned here).

Every requirement below carries `DERIVED`.

## CFG — `watchdog-interval` option validation

### REQ-WATCHDOG-CFG-001 — `watchdog-interval` MUST be 0 or at least 6 seconds

**Requirement:** `set_option_int()` MUST refuse (log `LOG_ERR`, return `-1`,
leaving the option unset) a `watchdog-interval` value in `[1,5]`. `0`
(disables the watchdog, `REQ-WATCHDOG-NET-002`) and any value `>= 6` MUST be
accepted, unrestricted otherwise. This is the one exception to
`REQ-CONFIG-CFG-006`'s "no numeric-validity check beyond non-`NULL`" rule --
`set_option_int()` is also the single choke point both the config-file
reader and `radcli_ctx_set_opt_int()` (`REQ-CONFIG2-CFG-*`) funnel through,
so both paths agree.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/config.c's `set_option_int()`; user-specified floor, not
itself derived from RFC 3539 or draft-ietf-radext-reverse-coa-08 (neither
mandates a minimum Tw) -- chosen so `REQ-WATCHDOG-NET-003`'s 2.5x-interval
dead-peer threshold stays comfortably larger than the interval itself,
rather than being so close that ordinary jitter could false-positive a live
peer as dead.
**Acceptance:** [CFG] negative, local — `watchdog-interval 5` (config-file
or `radcli_ctx_set_opt_int()`) fails; [CFG] positive, local — `0` and `6`
both succeed (`tests/watchdog-aaa.c`'s phase 2, `radcli_ctx_set_opt_int()`
only -- the config-file path is exercised only by inspection of the shared
`set_option_int()` code, not a dedicated file-based test).
**Links:** REQ-CONFIG-CFG-006, REQ-CONFIG-CFG-021, REQ-WATCHDOG-NET-002, REQ-WATCHDOG-NET-003

## NET — watchdog send, advisory poll deadline, and dead-peer reconnect

### REQ-WATCHDOG-NET-001 — radcli_ctx_dispatch() sends an RFC 5997 watchdog on an established RadSec session once it is due

**Requirement:** `radcli_ctx_dispatch()` MUST, on every call, check whether
`watchdog-interval` has elapsed since ctx's TLS/DTLS session's last activity
(REQ-WATCHDOG-NET-002) and, if so, make one non-blocking attempt to send an
RFC 5997 Status-Server (Code 12) over that established session, built the
same way any other outbound request is (random Identifier and Request
Authenticator, a correct Message-Authenticator, no other attributes), using
the RFC 6614 §2.3/RFC 7360 §3.2 fixed RadSec secret. It MUST NOT wait for,
or attempt to correlate, any reply, and MUST NOT queue or retry a send that
would block — unlike a DAE reply (`REQ-DAE-SEC-013`), a dropped watchdog is
not a delivery failure worth that machinery: the next call to
`radcli_ctx_dispatch()` once the interval elapses again covers it. This
applies on any established RadSec `radcli_ctx`, not only one with dynamic
authorization active, matching `REQ-DAE-NET-001`'s reasoning for keeping
RadSec-session facilities at the ctx level rather than the `radcli_dae`
level. There is no public, caller-invoked send entry point (unlike before
this requirement's revision): sending a watchdog is folded into
`radcli_ctx_dispatch()`, the same call the application already makes for
DAE and request traffic (`REQ-DAE-NET-001`), rather than a second call the
application must separately remember to make on a schedule it computes
itself. This is not radcli calling itself unprompted (`REQ-GEN-SEC-003`
still holds): the send only ever happens inside a `radcli_ctx_dispatch()`
call the *application* makes, on the application's own schedule — driven by
`radcli_ctx_get_poll()`'s advisory `timeout_ms` (REQ-WATCHDOG-NET-002),
never by a radcli-owned timer, thread, or signal. The legacy `rc_check_tls()` (declared in `net.md`'s `radcli.h`, its guarantee
documented here as `REQ-WATCHDOG-NET-004`) reaches the identical send logic through
a separate, internal-linkage entry point it calls directly (not through
`radcli_ctx_dispatch()`, since a UDP/legacy caller may never call that at
all) — both call sites share one implementation, not two copies.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5997; draft-ietf-radext-reverse-coa-08 §4.2 ("a client SHOULD
maintain at least connection open to the server at all times", via an RFC
3539 §3.4 watchdog whose SHOULD-recommended packet is Status-Server) —
without this, a NAT/firewall reaping an idle RadSec DAE connection's state
would leave `REQ-DAE-INIT-010`'s reverse-path model unreachable until the
NAS happened to send ordinary AAA traffic again.
**Acceptance:** [NET] positive, local — `tests/dae-radsec-watchdog.c`/
`tests/dae-radsec-watchdog-tests.sh`: against `tests/dae-watchdog-server.py`
(a passive peer that sends nothing itself and waits for an unprompted
packet), driving `radcli_ctx_get_poll()`/`radcli_ctx_dispatch()` past the
configured `watchdog-interval` results in the peer observing Code 12 with a
Message-Authenticator that verifies against the fixed RadSec secret. [NET]
negative, unit, local — `tests/dae.c`: `radcli_ctx_dispatch()` called
repeatedly on a `NULL` ctx, or on a UDP-mode (non-RadSec) ctx, never sends a
watchdog (there is no session to send it on) and returns its ordinary
error/no-op result, not a watchdog-specific one. [NET] positive, local —
`tests/watchdog-aaa.c`/`tests/watchdog-aaa-tests.sh` (against
`tests/watchdog-aaa-server.py`, a peer that also answers ordinary
Access-Request traffic): confirms this works with no `radcli_dae` involved
at all, on a `radcli_ctx` driven purely through `radcli_request_new()`/
`_perform()`/`radcli_ctx_get_poll()`/`_dispatch()`.
**Links:** REQ-DAE-NET-001, REQ-WATCHDOG-NET-002, REQ-DAE-SEC-013, REQ-DAE-INIT-010

### REQ-WATCHDOG-NET-002 — `radcli_ctx_get_poll()` advises when a watchdog is due, radcli never times it itself

**Requirement:** For any RadSec (`serv-type=tls`/`dtls`) `radcli_ctx` with an
established session — whether or not dynamic authorization is active on it,
since this is a property of the TLS/DTLS session, not of DAE — and when no
more urgent, DAE-specific reason to call `radcli_ctx_dispatch()` already
applies (`REQ-DAE-SEC-013`'s queued-work case, when a `radcli_dae` is
active), `radcli_ctx_get_poll()`'s `timeout_ms` MUST report the number of
milliseconds remaining until `watchdog-interval` has elapsed since the
session's last activity (0 once it already has), so that a caller's own
event-loop timeout — never a timer radcli owns — is what actually waits
before the caller's next `radcli_ctx_dispatch()` call sends the watchdog
(`REQ-WATCHDOG-NET-001`). This MUST be
computed from the session's own last-send/receive timestamp (including a
send made via `REQ-WATCHDOG-NET-001`, and, when a `radcli_dae` is active,
the handshake `radcli_dae_start()` completes under `REQ-DAE-INIT-010`, which
MUST count as activity in its own right — an unestablished-but-just-connected
session must never be reported as already overdue). `watchdog-interval`
MUST default to 15 seconds (`draft-ietf-radext-reverse-coa-08`'s recommended
Tw, "instead of [RFC 3539's] default value of 30 seconds") when unset --
materialized into the config table once, at `radcli_ctx_apply()` time
(`REQ-CONFIG-CFG-021`), not substituted at read-time by whatever reads it.
`watchdog-interval = 0` MUST disable this deadline entirely, reverting
`timeout_ms` to `-1` for this branch exactly as before this option existed.
Unlike every other option this document covers, `watchdog-interval` carries
no `dae-` prefix and is not registered alongside them in
`include/radcli/radcli-defs.h`'s `RC_OPTION_TABLE` (it sits with the
`tls-*` options instead) — it names a RadSec-session property, not a DAE
one, and an application using it purely for connection liveness on a
DAE-less RadSec `radcli_ctx` should not have to reach for a `dae-`-prefixed
option to get it. Only meaningful under `serv-type=tls`/`dtls`: there is no
persistent, radcli-owned socket for a plain UDP client to keep alive this
way, so this option has no effect there (a UDP-specific keepalive target is
explicitly out of scope for this requirement).
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 3539 §3.4; draft-ietf-radext-reverse-coa-08 §4.2 ("The
watchdog timer (Tw)... SHOULD be initialized to 15 seconds"); REQ-GEN-SEC-003
(no library-owned timer — radcli computes the deadline, the caller's own
`poll()`/`select()` timeout is what waits)
**Acceptance:** [NET] positive, local — `tests/dae-radsec-watchdog.c`: right
after `radcli_dae_start()` completes (before any application-level traffic),
`timeout_ms` is already in `(0, watchdog-interval*1000]`, not `0` and not
`-1` — confirming the handshake itself counts as activity. Sending a
watchdog resets it back into that same range. After sleeping past the
configured interval with nothing else happening, `timeout_ms` reads `0`.
`watchdog-interval = 0` reverting to `-1` is exercised only by
inspection of `lib/dae.c`'s branch (`interval > 0` gate), not a dedicated
network test. [NET] positive, local — `tests/watchdog-aaa.c`: with no
`radcli_dae` involved at all, an ordinary Access-Accept resets `timeout_ms`
back near the full interval exactly as a watchdog reply would (RFC 3539
SS3.4: any peer message resets the watchdog timer), proving this deadline is
a RadSec-session property rather than something tied to DAE traffic
specifically.
**Links:** REQ-WATCHDOG-NET-001, REQ-WATCHDOG-NET-003, REQ-DAE-INIT-010, REQ-GEN-SEC-003, REQ-CONFIG-CFG-021

### REQ-WATCHDOG-NET-003 — the watchdog send MUST reconnect a session the peer has gone silent on for 2.5x watchdog-interval

**Requirement:** `lib/dae.c`'s internal watchdog-send helper
(`radcli2_priv_dae_send_watchdog()`, shared by `radcli_ctx_dispatch()`'s
automatic call — `REQ-WATCHDOG-NET-001` — and `rc_check_tls()`'s direct one
— `REQ-WATCHDOG-NET-004`) MUST track the timestamp of
the last record actually *received* on the session, separately from
`REQ-WATCHDOG-NET-002`'s last-activity (send-or-receive) clock. Before building
and sending, if `watchdog-interval > 0` and the elapsed time since that
last receive is `>= 2.5 * watchdog-interval`, it MUST force the session to
reconnect (a fresh TCP/TLS handshake, the same way an actual send/recv
error already does — `restart_session()` carries no throttle of its own to
bypass, `REQ-NET-NET-007`) before proceeding — the peer is presumed dead,
not merely slow. This MUST NOT
depend on any socket-level error: the specific condition this catches is a
connection that stays open (no FIN, no reset) while the peer answers
nothing at all, which the transport's own error-triggered reconnect never
sees on its own. Still radcli-owns-no-timer (`REQ-GEN-SEC-003`): this check
only ever runs lazily, inside a call the application itself already makes
on its own schedule (typically driven by `REQ-WATCHDOG-NET-002`'s `timeout_ms`),
never from a radcli-owned thread or signal.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c's `radcli2_priv_dae_send_watchdog()`; lib/tls.c's
`tls_int_st.last_recv` and `radcli2_priv_tls_force_reconnect()`
**Acceptance:** [NET] positive, local — `tests/watchdog-aaa.c`'s phase 4:
after the peer answers nothing at all for well over 2.5x watchdog-interval
(connection left open throughout, not closed), the next
`radcli_ctx_dispatch()` call once the watchdog is due still succeeds, and
`tests/watchdog-aaa-tests.sh` confirms the peer's log shows a *second* TLS
connection accepted -- the only observable proof that reconnection
specifically (not just "the call didn't fail") happened. Threshold
(2.5x) is a user-specified choice, not itself derived from RFC 3539 (which
leaves the failed-transport detection algorithm's exact multiplier
unspecified, only that it exist, SS3.4). This same mechanism is also
`REQ-WATCHDOG-NET-004`'s (`rc_check_tls()`'s) own implementation for a
TLS/DTLS `radcli_ctx` — not a separate TLS-heartbeat-based one, which has
been retired outright.
**Links:** REQ-WATCHDOG-NET-001, REQ-WATCHDOG-NET-002, REQ-WATCHDOG-CFG-001, REQ-GEN-SEC-003,
REQ-NET-NET-007, REQ-WATCHDOG-NET-004

### REQ-WATCHDOG-NET-004 — `rc_check_tls()`'s guarantee is opt-in idle-session detection via an RFC 5997 watchdog probe; it is never called implicitly by radcli itself

**Requirement:** `rc_check_tls()` MUST only be invoked by the application, on its own schedule
(e.g. a watchdog thread) — radcli MUST NOT call `rc_check_tls()` from `rc_send_server_ctx()`,
`rc_auth()`, or any other internal path. When called on an established session with
`need_restart` already set, it MUST reconnect via `restart_session()`, same as
`REQ-NET-NET-007`. Otherwise, once `watchdog-interval` (default 15s, floor 6s,
`REQ-WATCHDOG-CFG-001`) has elapsed since the session's last activity, it MUST send an RFC 5997
Status-Server watchdog via `lib/dae.c`'s internal `radcli2_priv_dae_send_watchdog()` — the same
helper `radcli_ctx_dispatch()` calls automatically (`REQ-WATCHDOG-NET-001`), called here directly
since a caller using only the legacy API may never call `radcli_ctx_dispatch()` at all (not radcli
calling *itself* proactively; the application is still the one that decided to call
`rc_check_tls()`), already both probes liveness and reconnects a peer gone silent for 2.5x that
interval on its own (`REQ-WATCHDOG-NET-003`) without `rc_check_tls()` needing separate
failure-handling logic. Unlike the TLS heartbeat this replaced, neither `restart_session()` nor
`radcli2_priv_dae_send_watchdog()` require the caller to hold the session lock externally — both
take it themselves — so this
requirement no longer imposes that obligation on the caller either. Idle-session breakage is
also, independently, always detected transparently on the next ordinary transport call via
`need_restart`/`tls_wait_or_give_up()` (`REQ-NET-NET-007`) whether or not `rc_check_tls()` is
ever called — this requirement documents what `rc_check_tls()` additionally guarantees *if*
called, not a promise that radcli calls it for the application.
**Strength:** MUST NOT (radcli-internal auto-invocation of `rc_check_tls()` itself) ; MUST (the
guarantee documented, if the caller does invoke it)
**Status:** DERIVED
**Source:** lib/tls.c's `radcli2_priv_check_tls()` (`rc_check_tls()`'s implementation); grep
confirms no `rc_check_tls(` call site inside `lib/*.c` other than its own definition
**Acceptance:** [NET] negative, local — `grep -n 'rc_check_tls(' lib/*.c` shows only the
function definition, no internal call site. [NET] positive, local — exercised indirectly via
`radcli2_priv_dae_send_watchdog()`'s own coverage (`tests/watchdog-aaa.c`, `tests/dae-radsec-
watchdog.c`), which is now also `rc_check_tls()`'s implementation, not a separate mechanism.
**Links:** REQ-GEN-SEC-002 (no radcli-spawned threads — a watchdog calling `rc_check_tls()` must
be the application's own thread), REQ-NET-NET-007, REQ-WATCHDOG-NET-001, REQ-WATCHDOG-NET-002,
REQ-WATCHDOG-NET-003

## Completeness

`rc_check_tls` (declared in `include/radcli/radcli.h`, owned by `net.md` per the document map)
is covered jointly by `net.md`'s `REQ-NET-NET-013` (no-op outside TLS/DTLS) and this document's
`REQ-WATCHDOG-NET-004` (the guarantee when it is TLS/DTLS and the caller does invoke it).
`radcli_ctx_dispatch()`'s automatic watchdog send and `radcli_ctx_get_poll()` (declared in
`include/radcli/radcli2.h`, owned by `dae.md` per the document map) are covered here rather than
in `dae.md`, since they are RadSec-session properties independent of DAE (`REQ-WATCHDOG-NET-001`
and `REQ-WATCHDOG-NET-002`'s own reasoning) — `dae.md` cites this document rather than
duplicating them.
