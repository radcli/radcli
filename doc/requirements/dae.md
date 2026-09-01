---
title: RFC 5176 dynamic authorization — receiving CoA and Disconnect requests
generator: requirements-elicitation
id-prefix: REQ-DAE
categories:
  INIT: listener construction, configuration validation, fixed-state allocation
  NET: socket ownership, descriptor exposure, request intake and reply transmission
  SEC: source authorization, authenticators, replay and duplicate suppression, secret handling
  DATA: request inspection, session selectors, reply construction, Proxy-State
  ERR: failure returns and Error-Cause mapping
  TEARDOWN: object lifetimes and resource release
sources:
  - RFC 5176
  - RFC 6614 (RadSec/TLS transport; DAE-over-RadSec transport-sharing and NAK behavior)
  - RFC 7360 (RadSec/DTLS transport; inherits RFC 6614 SS2's model per its SS2.2)
  - draft-ietf-radext-reverse-coa-08 (server-initiated CoA/Disconnect down a
    client-established RADIUS/(D)TLS connection; unsupported-feature signaling.
    Its connection-liveness watchdog guidance is cited by, and its requirements
    now live in, doc/requirements/watchdog.md)
  - include/radcli/radcli2.h
  - lib/dae.c
  - lib/tls.c
  - tests/dae.c
  - tests/dae-codec.c
  - tests/dae-freeradius-tests.sh
  - doc/requirements/config2.md (radcli_ctx construction and option storage, cited not owned)
  - doc/requirements/watchdog.md (RFC 5997/3539 connection-liveness watchdog
    on the RadSec session, cited not owned)
  - doc/requirements/net2.md (RADCLI_REQUEST_SENDONLY request registry sharing
    radcli_ctx_get_poll()/_dispatch() with DAE traffic, cited not owned)
---

# RFC 5176 Dynamic Authorization Requirements

Scope: the receive-only Dynamic Authorization Server role — accepting and answering
CoA-Request (43) and Disconnect-Request (40) packets, over RFC 5176/UDP port 3799
(`dae-accept = udp`, always available regardless of `serv-type`) or, when
`dae-accept = yes` and `serv-type` is `tls`/`dtls`, over that already-established
RadSec connection instead (RFC 6614 §2.1/§2.5, RFC 7360 §3.1). Construction
(`radcli_dae_new()`/`_set_handler()`/`_start()`/`_free()`, the ctx-level poll
surface, `INIT`/`NET`), the request-validation and reply pipeline (`SEC`, `DATA`,
`ERR`), the session-selector accessors, and the L0 buffer entry point
(`radcli_dae_process()`/`radcli_dae_reply_to_buffer()`) are all implemented and
tested (`tests/dae.c`, `tests/dae-codec.c`, and end to end via
`src/raddaeserver.c`/`tests/dae-client.py`/`tests/dae-tests.sh`, plus
`tests/dae-freeradius-tests.sh` against a real FreeRADIUS `radclient` as DAC, for
the UDP transport; `tests/dae-radsec-tests.sh`/`tests/dae-tls-client.py` for a
single-message RadSec exchange, `tests/dae-radsec-stress.c`/
`tests/radsec-stress-server.py` for concurrent mixed ordinary/DAE traffic, and
`tests/dae-radsec-backpressure.c`/`tests/radsec-backpressure-server.py` for the
dispatch-must-not-block property REQ-DAE-SEC-013 covers, for the RadSec
transport). Every requirement in this document now carries `Status: DERIVED`
(see `doc/requirements/README.md`'s status legend).
`REQ-DAE-ERR-003`'s guarantee stops at the synchronous send attempt,
though: it does not extend to REQ-DAE-SEC-013's
deferred-reply queue, where a reply `radcli_dae_reply()` already reported
success for (because it was accepted onto the queue) can still be dropped
later by that queue's overflow (oldest-dropped) policy. An application still
has no way to learn that a reply was lost that way -- REQ-DAE-ERR-003 covers
only a `radcli_dae_reply()` call that fails outright, not a later, silent
queue-overflow drop of a reply it already accepted.

No real-world Dynamic Authorization Client was found to validate the RadSec
transport against. RadSec-transport testing here is therefore against a
spec-conformant test double (`tests/dae-tls-client.py`), not a real DAC; the UDP
transport still has real-FreeRADIUS coverage via `tests/dae-freeradius-tests.sh`.

`radcli_dae_new()` takes a `radcli_ctx` (`dae-server`/`dae-secret`/etc. read
via the internal `radcli2_priv_conf_*` accessors, `lib/config.c`) built and
populated exactly as `config2.md` documents — this document treats that
construction as out of scope and covers only the DAE-specific validation and
dispatch built on top of it.

A narrower, already-published obligation is not covered by that exception: RFC
6614 §2.5 requires that "when an unwanted packet of type 'CoA-Request' or
'Disconnect-Request' is received, a RADIUS/TLS server needs to respond with a
'CoA-NAK' or 'Disconnect-NAK', respectively," carrying an Error-Cause of 406.
Unlike bis §6.1.1's generic, deferred Protocol-Error handling above, this applies
specifically when dynamic authorization itself is reachable (RadSec is in use)
but switched off (`dae-accept=no`) and a CoA/Disconnect-Request arrives anyway --
see `REQ-DAE-SEC-016`.

radcli implements the server (receiving) side only — there is no exported
request encoder. Encoding and sending CoA/Disconnect requests is a Dynamic
Authorization Client (DAC) responsibility, distinct from the receive-only
DAS role this document covers, and radcli does not provide it.

### INIT — listener construction and configuration validation

#### REQ-DAE-INIT-001 — dynamic authorization is opt-in

**Requirement:** radcli MUST NOT accept, parse, or act on any CoA-Request or
Disconnect-Request unless `dae-accept` is set to `yes` or `udp` in the
configuration, so that a library upgrade never silently exposes a
session-terminating channel in an application that did not ask for one. An
unrecognised `dae-accept` value MUST also fail construction, rather than silently
being treated as "off" or "on".
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** openconnect/ocserv#756 ("opt-in RFC 5176 listener")
**Acceptance:** [INIT] negative, unit, local — `tests/dae.c`: `dae-accept` unset and `dae-accept = no` both make `radcli_dae_new()` return `NULL` with no log; `dae-accept = sure` (unrecognised) also returns `NULL`, with an error logged. With no `radcli_dae` constructed, neither `radcli_ctx_dispatch()` nor `radcli_dae_process()` has anything to validate against, closing the loop -- see REQ-DAE-NET-002.
**Links:** REQ-DAE-INIT-002

#### REQ-DAE-INIT-002 — on UDP, construction MUST refuse without an explicit sender and secret

**Requirement:** When the DAE transport is RFC 5176/UDP, `radcli_dae_new()` MUST
fail, and MUST NOT construct a listener that could later bind a socket, when either
`dae-server` or `dae-secret` is unset while `dae-accept` is `yes` or `udp`, so that
authorization for a session-terminating channel is never inherited implicitly from
`authserver`/`acctserver`. (The RadSec transport has its own counterpart,
REQ-DAE-INIT-007: there, the authorized sender and secret are supplied by the TLS
session itself rather than by these two options.)
**Strength:** MUST
**Status:** DERIVED
**Source:** FreeRADIUS `clients.conf` guidance; strongSwan `charon.plugins.eap-radius.dae.secret`
**Acceptance:** [INIT] negative, unit, local — `tests/dae.c`: three configurations (neither set, only `dae-server`, only `dae-secret`) each make `radcli_dae_new()` return `NULL`.
**Links:** REQ-DAE-INIT-001, REQ-DAE-INIT-007, REQ-DAE-SEC-001

#### REQ-DAE-INIT-003 — `dae-server` accepts addresses and hostnames, never prefixes

**Requirement:** `dae-server` MUST accept literal IPv4/IPv6 addresses and
hostnames, and MUST reject any value carrying a network prefix (`/nn`), so that the
authorized sender set stays small, enumerable at configuration time, and incapable
of authorizing an unintended host.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c (`parse_dae_server_token()`)
**Acceptance:** [INIT] negative, unit, local — `tests/dae.c`: `dae-server = 192.0.2.0/24` makes `radcli_dae_new()` return `NULL`; `dae-server = 192.0.2.1` (and a second entry with a `:secret` override) succeeds. Only literal addresses are exercised in the unit test; a resolvable-hostname case needs real DNS and is not covered locally.
**Links:** REQ-DAE-INIT-004, REQ-DAE-SEC-001

#### REQ-DAE-INIT-004 — hostnames are resolved once, at configuration load

**Requirement:** A hostname in `dae-server` MUST be resolved when the configuration
is loaded, with every resulting address authorized, and MUST NOT be re-resolved
while the listener runs, because periodic re-resolution would require either
blocking the receive path or a library-owned timer.
**Strength:** MUST
**Status:** DERIVED
**Source:** REQ-GEN-SEC-003 (no process-wide timers)
**Acceptance:** [INIT] positive, local — `lib/dae.c`'s `add_dac_addrs()` calls `getaddrinfo()` exactly once, from `radcli_dae_new()`, and every resulting address is appended to `dae->dacs[]`; nothing in `lib/dae.c` re-resolves while the listener runs. `tests/dae-codec.c` (test 17) configures `dae-server = localhost` and confirms `radcli_dae_process()` accepts a request from each address family "localhost" resolves to on the test host (127.0.0.1 and/or ::1, via `getaddrinfo()` -- no real network DNS needed, only the system's own `/etc/hosts`-or-equivalent NSS "files" source); a family "localhost" doesn't resolve to on a given host is skipped with a warning rather than failed. Re-resolution after a configuration change taking effect only on reload is not separately exercised (there being no re-resolution code path to trigger is the property under test).
**Links:** REQ-GEN-SEC-003, REQ-DAE-INIT-003

#### REQ-DAE-INIT-005 — duplicate-suppression state is fixed at construction

**Requirement:** radcli MUST allocate, at listener construction, a fixed table of
256 slots, indexed by RADIUS Identifier and shared across every configured
dae-server entry, and MUST NOT grow, evict, or otherwise resize that state at
run time, so that the memory cost is constant and no packet-driven allocation
exists on an externally reachable path. The table is deliberately not
partitioned per configured sender: Request/Message-Authenticator verification
never binds the source address into its hash, so a per-sender table only
weakened duplicate suppression -- see REQ-DAE-SEC-005's requirement text for
why.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §2.3; lib/dae.c (`radcli_dae_new()`, `RADCLI_DAE_SLOTS`)
**Acceptance:** [INIT] unit, local — `radcli_dae_new()` (`lib/dae.c`) `calloc()`s `RADCLI_DAE_SLOTS` (256) slots once, at construction, shared by `struct radcli_dae_st` rather than per `struct radcli_dae_dac`; `radcli_ctx_dispatch()`'s duplicate suppression (REQ-DAE-SEC-005/006, tested in `tests/dae-codec.c`) indexes directly into this table and never grows or reallocates it. The specific 10,000-request heap-profile/ASan measurement is not run in this environment (no working sanitizer build here).
**Links:** REQ-DAE-SEC-005, REQ-GEN-SEC-005

#### REQ-DAE-INIT-006 — the listener owns no process-wide state

**Requirement:** The dynamic-authorization implementation MUST NOT install a signal
handler, call `fork()`, create a thread, arm a timer, or introduce library-owned
global or `static` mutable state; all listener state MUST live in the
caller-created object.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** REQ-GEN-SEC-001 … REQ-GEN-SEC-005
**Acceptance:** [INIT][SEC] unit, local — the `grep` sweep in `doc/requirements/README.md` ("Completeness") extended to `lib/dae.c` finds no `signal(`, `sigaction(`, `fork(`, `pthread_create(`, `alarm(`, `setitimer(`; `nm` shows no new writable globals (`rh->active_dae`/`rh->in_dispatch` live on the caller-owned `radcli_ctx`, not as library statics).
**Links:** REQ-GEN-SEC-001, REQ-GEN-SEC-002, REQ-GEN-SEC-003, REQ-GEN-SEC-005

#### REQ-DAE-INIT-007 — on RadSec, construction MUST refuse without verified peer identity

**Requirement:** When the DAE transport is RadSec (`dae-accept = yes` under
`serv-type = tls`/`dtls`), `radcli_dae_new()` MUST fail unless TLS peer
verification is enabled (`tls-verify-hostname`, or an equivalent certificate check),
since under this transport the peer's verified identity replaces `dae-server` as
the sole authorization for who may send a CoA/Disconnect-Request. This is the one
"refuse to start" condition specific to RadSec that has no UDP counterpart.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 6614 §2.1/§3.4(3) (single-connection model, no dae-server ACL to fall back to); REQ-DAE-INIT-002 (UDP counterpart)
**Acceptance:** [INIT] negative, unit, local — `radcli_dae_new()` (`lib/dae.c`) reads the same `tls-verify-hostname` value `lib/tls.c`'s `init_session()` already reads and refuses construction (`NULL`, error logged) when it is disabled, under `serv-type = tls`/`dtls` with `dae-accept = yes`.
**Links:** REQ-DAE-INIT-002

#### REQ-DAE-INIT-008 — UDP-only options left set under RadSec MUST warn, never silently disappear or fail construction

**Requirement:** When the DAE transport is RadSec, `dae-listen`, `dae-server`,
`dae-secret`, and `dae-require-message-authenticator` are inapplicable (RadSec
supplies the authorized peer via TLS verification and the secret via RFC 6614
§2.3/RFC 7360 §3.2's fixed string, already `lib/tls.c`'s `rh->so.static_secret`).
If any of them is still set, `radcli_dae_new()` MUST log a warning
naming the inapplicable option(s) and MUST proceed with construction rather than
failing because of them, so that switching `serv-type` from UDP to RadSec is a
configuration change an operator can make incrementally -- leaving the old options
in place while migrating -- without either a construction failure or the checks
those options once named silently ceasing to exist unremarked.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 6614 §2.3, RFC 7360 §3.2 (fixed secret replaces dae-secret); REQ-DAE-INIT-007
**Acceptance:** [INIT] positive, unit, local — under `serv-type = tls`/`dtls` with `dae-accept = yes` and peer verification enabled, setting `dae-listen`/`dae-server`/`dae-secret`/`dae-require-message-authenticator` still succeeds, with a warning logged naming each set option (`radcli_dae_new()`'s `inapplicable[]` sweep, `lib/dae.c`).
**Links:** REQ-DAE-INIT-007

#### REQ-DAE-INIT-009 — a secret longer than MAX_SECRET_LENGTH MUST fail construction, not truncate silently

**Requirement:** `radcli_dae_new()` MUST fail (return `NULL`, with an error logged
naming the offending option -- never the secret's own value, per REQ-DAE-SEC-009)
if `dae-secret`, or a `dae-server` entry's `:secret` override, is longer than
`MAX_SECRET_LENGTH` bytes, rather than silently truncating it the first time it is
used to verify a packet. Every fixed-size buffer downstream that hashes the secret
(Request Authenticator verification, Message-Authenticator HMAC, reply
construction) is sized to `MAX_SECRET_LENGTH`, matching the codebase-wide
convention (`lib/avp.c`, `lib/request.c`, `lib/sendserver.c`) of clamping the
secret's effective length to that bound before use; construction is where an
oversized value should be caught and reported, not the receive path of an
otherwise-valid packet.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c (`radcli_dae_new()`, `parse_dae_server_token()`); include/radcli/radcli.h (`MAX_SECRET_LENGTH`)
**Acceptance:** [INIT] negative, unit, local — `tests/dae.c`: a `dae-secret` of `MAX_SECRET_LENGTH + 1` bytes, and separately a `dae-server` `:secret` override of the same length, each make `radcli_dae_new()` return `NULL`.
**Links:** REQ-DAE-INIT-002, REQ-DAE-INIT-003, REQ-DAE-SEC-009

#### REQ-DAE-INIT-010 — RadSec construction is followed by an eager handshake, not a lazy one

**Requirement:** Under RadSec, `radcli_dae_start()` MUST force rh's TLS/DTLS
handshake to complete now (if it has not already), rather than relying on
`rc_init_tls()`'s ordinary lazy-connect-on-first-request behavior, so that
enabling dynamic authorization makes the NAS reachable immediately -- matching
the UDP listener's own immediate `bind()` -- instead of leaving CoA/Disconnect
unreachable until the application happens to make its first `rc_auth()`/
`rc_acct()` call.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/tls.c (`radcli2_priv_tls_ensure_connected()`); REQ-DAE-NET-001 (radcli_dae_start()'s UDP counterpart binds immediately)
**Acceptance:** [INIT] positive, unit, local — under `serv-type = tls`/`dtls` with `dae-accept = yes`, `radcli_dae_start()` returns 0 only once the handshake has actually completed (`radcli2_priv_tls_fd()` reports a valid descriptor immediately afterward), without any ordinary `rc_auth()`/`rc_acct()` call having been made first.
**Links:** REQ-DAE-NET-001

#### REQ-DAE-INIT-011 — the automatic NAS-Identifier check can be disabled at construction

**Requirement:** `radcli_dae_new()` MUST accept a `flags` parameter, and MUST
reject (return NULL for) any value carrying a bit outside the defined
`radcli_dae_flags` set, matching `radcli_ctx_new()`'s own unknown-flags
contract. `RADCLI_DAE_NO_NAS_CHECK` MUST disable REQ-DAE-SEC-018's automatic
NAS-Identifier check for every request `process_packet()` validates through
the resulting listener, for deployments where the `nas-identifier` config
value does not name anything a DAC can be expected to send (or where an
application wants to inspect the mismatch itself via
`radcli_dae_req_attrs()` before deciding).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c (`radcli_dae_new()`); config2.c's `radcli_ctx_new()` (the flags-parameter pattern this mirrors)
**Acceptance:** [INIT] positive and negative, unit, local — `tests/dae-codec.c` (test 11b) constructs a listener with `RADCLI_DAE_NO_NAS_CHECK` and `nas-identifier` configured, sends a request naming a different NAS-Identifier through `radcli_dae_process()`, and confirms it is returned as `RADCLI_DAE_NEW` (not NAKed) -- the flag actually suppresses REQ-DAE-SEC-018. The unknown-flags-bit rejection is not separately exercised locally.
**Links:** REQ-DAE-SEC-018

### NET — descriptor exposure, intake, and reply transmission

#### REQ-DAE-NET-001 — radcli exposes ctx's descriptor(s) and never drives a loop

**Requirement:** `radcli_ctx_get_poll(ctx, pfds, max_pfds, &nfds, &timeout_ms)`
MUST fill the caller-supplied `pfds` array (capacity `max_pfds`, MUST be at
least `RADCLI_CTX_MAX_POLLFDS` == 2, else the call fails) with the
descriptor(s) to watch and the direction(s) to watch each in, report how many
of them it used in `*nfds` (0 if there is nothing to watch yet), and radcli
MUST NOT call `poll()`, `select()`, `epoll_wait()`, or sleep on the caller's
behalf, so that any event loop (libev, libevent, epoll, plain `poll()`) can
host it. For TLS/DTLS, or for a UDP `ctx` with no `radcli_dae` active, this is
always exactly one descriptor: the session fd (TLS/DTLS, also carrying any
in-flight `RADCLI_REQUEST_SENDONLY` request traffic, net2.md's
REQ-NET2-SEND-013/016) or the request-registry socket (UDP,
REQ-NET2-SEND-016). A UDP `ctx` with an active `radcli_dae` reports a second,
independent descriptor for the DAE listener alongside it — the two are
genuinely different local sockets/ports (REQ-DAE-INIT-002) and cannot be
merged into one without changing the wire protocol; two is the maximum this
API ever needs.

`radcli_ctx_dispatch()` reads whatever is ready — and, for the request-socket
and watchdog-deadline cases, transmits when due (net2.md's REQ-NET2-SEND-013,
watchdog.md's REQ-WATCHDOG-NET-001) — without needing to know which of the
(up to two) descriptors `poll()` actually reported ready: like the pre-existing
DAE-socket path, it always attempts a non-blocking operation per slot and
tolerates "nothing there" (`EAGAIN`), so the caller never has to demultiplex
by hand. Once packet validation lands (REQ-DAE-NET-002), it demultiplexes and
invokes the registered `radcli_dae_handler`. There is deliberately no
per-object descriptor accessor (no `radcli_dae_fd()`, no per-`radcli_request`
one either — net2.md's REQ-NET2-SEND-013): descriptors belong to the
`radcli_ctx`, so that a transport sharing one descriptor between DAE and
ordinary requests (already true for TLS/DTLS) never leaves an application
holding a watcher on a descriptor that silently starts meaning something
else.
**Strength:** MUST
**Status:** DERIVED
**Source:** REQ-GEN-SEC-003
**Acceptance:** [NET] positive, unit, local — `tests/dae.c`: `radcli_ctx_get_poll()` reports `*nfds == 0` before `radcli_dae_start()` and after `radcli_dae_free()` (UDP, no in-flight requests), and a valid, `POLLIN`-watched descriptor in between; no polling symbol appears in `lib/dae.c`. `src/raddaeserver.c` is a real plain-`poll()`-loop application built on exactly this contract, driven end to end by `tests/dae-tests.sh`/`tests/dae-client.py`. [NET] positive, unit, local — `tests/request-poll-multi.c`: a UDP `ctx` with both an active `radcli_dae` and several in-flight `RADCLI_REQUEST_SENDONLY` requests reports exactly two descriptors (`*nfds == 2`), not one per request.
**Links:** REQ-GEN-SEC-003, REQ-DAE-NET-003, REQ-NET2-SEND-013, REQ-NET2-SEND-016, REQ-WATCHDOG-NET-001

#### REQ-DAE-NET-002 — validation completes before the application sees a request

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
**Links:** REQ-DAE-SEC-001 … REQ-DAE-SEC-005

#### REQ-DAE-NET-003 — the same pipeline is reachable without a radcli-owned socket

**Requirement:** `radcli_dae_process()` MUST apply the identical validation
pipeline to a caller-supplied buffer and source address, and MUST produce request
objects indistinguishable from those `radcli_ctx_dispatch()` produces when
validating a packet received on the socket `radcli_dae_start()` bound, so that an
application that owns its transport — or receives packets over IPC from a
privileged listener — gets the same guarantees.
**Strength:** MUST
**Status:** DERIVED
**Source:** openconnect/ocserv#756 (process-boundary question)
**Acceptance:** [NET] positive, unit, local — `tests/dae-codec.c` (tests 12-14) drives `radcli_dae_process()` directly (no `radcli_dae_start()` call at all) through both entry points' shared `process_packet()`: a new request, a retransmission (`RADCLI_DAE_DUPLICATE`), and a rejected bad-authenticator packet, matching `radcli_ctx_dispatch()`'s own three outcomes. The full `tests/dae-codec.c` matrix is not run twice end-to-end through both entry points on identical input for a literal side-by-side comparison.
**Links:** REQ-DAE-NET-002

#### REQ-DAE-NET-004 — replies go to the request's source, with its Identifier

**Requirement:** A reply MUST be sent to the source address and port the request
arrived from, MUST copy the request's Identifier, and MUST use the reply code
paired with the request code (40 → 41/42, 43 → 44/45), so that the sender can match
the reply to its outstanding request.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §§2.1, 3
**Acceptance:** [NET] positive, local — `tests/dae-tests.sh` exercises 40 → 41 (ACK) and 40 → 42 (`--nak`); `tests/dae-codec.c` exercises 43 → 45 (`radcli_dae_reply_error()` on a CoA-Request). Each time the reply arrives back on the same socket the request was sent from, with a matching Identifier. The 43 → 44 (CoA-ACK) pairing, and a dedicated case using `--source-port` to bind an explicitly different source port than the reply's destination, are not separately exercised.
**Links:** REQ-DAE-DATA-004, REQ-DAE-SEC-008

#### REQ-DAE-NET-005 — replies can be produced as bytes instead of being sent

**Requirement:** `radcli_dae_reply_to_buffer()` MUST produce the identical octets
`radcli_dae_reply()` would transmit, without performing I/O, so that an application
owning its transport can send them itself.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c (`build_reply()`, shared by `radcli_dae_reply()` and `radcli_dae_reply_to_buffer()`)
**Acceptance:** [NET] positive, unit, local — `tests/dae-codec.c` (test 12) verifies `radcli_dae_reply_to_buffer()`'s ACK independently, including its Response Authenticator; test 13 confirms it reproduces byte-for-byte the same reply for a duplicate regardless of the `ack`/`error_cause` arguments passed. `radcli_dae_reply_to_buffer()` and `radcli_dae_reply()` share `build_reply()` (`lib/dae.c`), the single encoder both funnel through, rather than being independently implemented and compared byte-for-byte against each other; a NAK-with-Error-Cause and a Proxy-State-mirroring case are not separately exercised through this entry point (both are exercised through `radcli_dae_reply()`/`_reply_error()` elsewhere in this file).
**Links:** REQ-DAE-NET-003

### SEC — authorization, authentication, and replay

#### REQ-DAE-SEC-001 — packets from unauthorized sources are discarded before parsing

**Requirement:** radcli MUST discard a packet whose source address is not in
`dae-server` without parsing its attributes, without computing any MD5 or HMAC over
its contents, and without sending any reply — not even an Error-Cause — so that
attacker-controlled bytes never reach the cryptographic path and a scanner learns
nothing about whether a listener exists.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §6.1
**Acceptance:** [SEC] negative, unit, local — `tests/dae-codec.c`: a correctly authenticated Disconnect-Request sent to a handle whose `dae-server` does not include the sender's address produces no reply and no handler invocation.
**Links:** REQ-DAE-INIT-003, REQ-DAE-SEC-002

#### REQ-DAE-SEC-002 — the Request Authenticator is verified before delivery

**Requirement:** radcli MUST verify the Request Authenticator of every
CoA-Request and Disconnect-Request as specified for Accounting-Request in RFC 5176
§2.3, using a constant-time comparison when built with GnuTLS (the project's
canonical TLS/crypto backend), and MUST silently discard the packet on mismatch.
A build without GnuTLS falls back to plain `memcmp()`, which is not constant-time
-- a known gap in that configuration, not one this requirement can close on its
own (`rc_memcmp()`, `lib/util.h`, is shared library-wide machinery, not something
`lib/dae.c` controls).
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §2.3
**Acceptance:** [SEC] negative, unit, local — `tests/dae-codec.c` flips a bit in a valid packet's Request Authenticator and confirms no reply and no handler invocation. The comparison (`lib/dae.c`'s `verify_request_authenticator()`) uses `rc_memcmp()` (`lib/util.h`): `gnutls_memcmp()` when built with GnuTLS, `memcmp()` otherwise -- asserted by inspection. `meson.build`'s `tls` option can disable GnuTLS, so the constant-time property is conditional on the build configuration, not universal.
**Links:** REQ-DAE-SEC-001, REQ-DAE-SEC-008

#### REQ-DAE-SEC-003 — Message-Authenticator is verified when present, and required only if configured

**Requirement:** When a request carries a Message-Authenticator attribute, radcli
MUST verify it and MUST silently discard the packet on mismatch. When the
attribute is absent, radcli MUST accept the request unless
`dae-require-message-authenticator` is enabled, in which case radcli MUST
silently discard it. The default (`dae-require-message-authenticator = no`)
follows RFC 5176 §3, which makes the attribute's use a MAY, because
interoperating senders exist that omit it; the opt-in exists because a
mandatory Message-Authenticator closes the forgery class Blast-RADIUS
(CVE-2024-3596) exploits, ahead of that becoming an RFC-level requirement.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §3; RFC 2869 §5.14; CVE-2024-3596
**Acceptance:** [SEC] negative and positive, unit, local — `tests/dae-codec.c` corrupts a valid packet's Message-Authenticator and confirms no reply and no handler invocation; every positive-path packet in that file carries a correct one and is accepted. `dae-require-message-authenticator = yes` rejecting an absent attribute is not covered by a test yet, though the check exists in `lib/dae.c`.
**Links:** REQ-DAE-SEC-002, REQ-DAE-INIT-002

#### REQ-DAE-SEC-004 — Event-Timestamp is checked two-sidedly when present

**Requirement:** When a request carries an Event-Timestamp attribute and
`dae-max-clock-skew` is non-zero, radcli MUST silently discard the request if the
absolute difference between that timestamp and local time exceeds the configured
skew — in either direction — and MUST accept a request that omits the attribute,
since RFC 5176 §6.3 makes inclusion a SHOULD. `dae-max-clock-skew` defaults to 300
when unset, materialized into the config table at `radcli_ctx_apply()` time
(`REQ-CONFIG-CFG-021`), not substituted at read-time by whatever reads it.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §6.3
**Acceptance:** [SEC] negative and positive, unit, local — `tests/dae-codec.c` sends an Event-Timestamp 120s stale against a 60s `dae-max-clock-skew` (discarded) and a fresh one (accepted). A future-dated timestamp, an absent attribute, and `dae-max-clock-skew = 0` are not separately covered by a test yet, though the two-sided (`diff < 0` negated) comparison and the `> 0` gate are both in `lib/dae.c`.
**Links:** REQ-DAE-SEC-005, REQ-CONFIG-CFG-021

#### REQ-DAE-SEC-005 — a duplicate never reaches the application twice

**Requirement:** radcli MUST treat a request as a duplicate when an SHA-256
digest radcli itself computes over the received packet (`Code||ID||Length||
Authenticator||Attributes`) matches a slot recorded within the retention
period, MUST answer it with the previously returned decision without
invoking the application again, and MUST discard it silently if the
original is still awaiting an application decision. The match runs against
one table shared by every configured `dae-server` entry, keyed on this
digest alone -- not source address, not source port, and not the wire's own
16-byte MD5 Request Authenticator (a secret-suffix MD5 MAC; `REQ-GEN-SEC-008`
already prohibits treating it as collision-resistant, and radcli has the
verified packet in hand at this point regardless, so hashing it again with
SHA-256 costs nothing).
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §2.3; REQ-GEN-SEC-008 (MD5 forgery risk, motivating the
independently-computed key); REQ-GEN-TECH-006 (nettle's SHA-256, via
`lib/rc-crypto.c`'s `rc_sha256_calc()`)
**Acceptance:** [SEC] positive, unit, local — `tests/dae-codec.c`: an exact retransmission (same packet bytes) after the original was ACKed produces one handler call total and an identical resent reply, whether sent from the same source port (test 5), a different one (test 5b), or spoofed as arriving from a different configured `dae-server` entry sharing the same secret (test 5c, via `radcli_dae_process()` since sending from two distinct source addresses needs more than one local interface); a retransmission arriving while the original is still PENDING (the handler deferred its reply) produces no reply and no second handler call, and the later deferred `radcli_dae_reply_error()` call still succeeds and is delivered.
**Links:** REQ-DAE-INIT-005, REQ-DAE-SEC-006, REQ-GEN-SEC-008, REQ-GEN-TECH-006

#### REQ-DAE-SEC-006 — retention is derived, not configured

**Requirement:** The duplicate-suppression retention period MUST equal
`dae-max-clock-skew` when the Event-Timestamp check is enabled, and 30 seconds when
it is disabled; radcli MUST NOT expose retention as a separate configuration
option, because its correct value follows from radcli's own matching rules rather
than from any property of the deployment.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c (`radcli_ctx_dispatch()`'s `retention` derivation); lib/options.h
**Acceptance:** [SEC] unit, local — `lib/options.h` registers no `dae-cache-time` option, so the config parser rejects one outright; `lib/dae.c`'s `radcli_ctx_dispatch()` derives `retention` as `dae->max_clock_skew` when positive, else 30. The exact t+59s-accepted/t+61s-reprocessed boundary is not exercised by a timing-based test yet (`tests/dae-codec.c`'s duplicate-suppression cases run well within the window).
**Links:** REQ-DAE-SEC-004, REQ-DAE-SEC-005

#### REQ-DAE-SEC-007 — attribute parsing is bounds-checked throughout

**Requirement:** All parsing of received dynamic-authorization packets MUST use the
`pkt_buf` interface from `lib/util.h`, and every overflow return MUST be propagated
rather than ignored, so that a malformed packet from an authorized sender cannot
read outside the receive buffer.
**Strength:** MUST
**Status:** DERIVED
**Source:** REQ-GEN-MEM-*; contrib/ai/personas/radcli-core-dev.md (packet construction and parsing)
**Acceptance:** [SEC] negative, local under ASan/UBSan — `process_packet()` (`lib/dae.c`) bounds-checks the fixed header itself (`AUTH_HDR_LEN`, the wire Length field never trusted past what was actually received) and hands every attribute byte to `radcli_avp_decode()` (`lib/avp.c`), which parses exclusively through `pkt_buf`/`pb_pull()` (`lib/util.h`) and propagates every bounds failure as a decode error rather than reading past it. `tests/dae-tests.sh` (tests 8/9) sweeps `--truncate` across six cut points (0, 1, 4, `AUTH_HDR_LEN-1`, `AUTH_HDR_LEN`, and mid-attribute) and `--bad-length` across three wire-Length deltas (understating by 10, overstating by 1, overstating by 4096, via `tests/dae-client.py`'s `--bad-length DELTA`), each asserted a silent discard with no reply. This suite runs, unchanged, as part of `meson test` under the existing `tests-asan`/`tests-ubsan` GitHub Actions jobs (`.github/workflows/tests.yaml`), giving the ASan/UBSan coverage this requirement asks for without a new CI job.
**Links:** REQ-GEN-MEM-001, REQ-UTIL-DATA-* (`pkt_buf`)

#### REQ-DAE-SEC-008 — the Response Authenticator is computed over the request's authenticator

**Requirement:** Every reply MUST carry a Response Authenticator computed as the
MD5 hash over the reply's Code, Identifier, Length, the *request's* Authenticator,
the reply attributes, and the shared secret, per RFC 5176 §2.3, so that the sender
can verify the reply is genuine.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §2.3
**Acceptance:** [SEC] positive, unit, local — `tests/dae-codec.c`'s `response_authenticator_ok()` independently recomputes the ACK's Response Authenticator from the raw reply bytes and fails the test on mismatch.
**Links:** REQ-DAE-NET-004

#### REQ-DAE-SEC-009 — secrets and authenticators are never logged

**Requirement:** The dynamic-authorization implementation MUST NOT write the shared
secret, the Request Authenticator, or the Message-Authenticator to any log at any
debug level.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** REQ-GEN-SEC-006; contrib/ai/personas/radcli-core-dev.md (shared-secret exposure)
**Acceptance:** [SEC] negative, unit, local — by inspection: no `rc_log()` call site in `lib/dae.c` passes a secret, Request Authenticator, or Message-Authenticator value. An automated end-to-end log-scraping test (`tests/dae-tests.sh` at maximum debug) is not implemented yet.
**Links:** REQ-GEN-SEC-006

#### REQ-DAE-SEC-010 — the listener socket is non-blocking

**Requirement:** The socket `radcli_dae_start()` binds MUST have `O_NONBLOCK` set,
so that a datagram discarded by the kernel between the readiness report and the
read -- or a second reader draining it first -- cannot block the application's
entire event loop inside a library that never owns it.
**Strength:** MUST
**Status:** DERIVED
**Source:** REQ-GEN-SEC-003
**Acceptance:** [SEC] unit, local — `tests/dae.c` checks `fcntl(fd, F_GETFL)` for `O_NONBLOCK` on the descriptor `radcli_ctx_get_poll()` reports after `radcli_dae_start()`.
**Links:** REQ-GEN-SEC-003, REQ-DAE-NET-001

#### REQ-DAE-SEC-011 — the listener socket is close-on-exec

**Requirement:** The socket `radcli_dae_start()` binds MUST have `FD_CLOEXEC` set,
so that it does not leak across `exec()` in an application that spawns children.
**Strength:** MUST
**Status:** DERIVED
**Source:** REQ-GEN-SEC-004
**Acceptance:** [SEC] unit, local — `tests/dae.c` checks `fcntl(fd, F_GETFD)` for `FD_CLOEXEC` on the descriptor `radcli_ctx_get_poll()` reports after `radcli_dae_start()`.
**Links:** REQ-GEN-SEC-004

#### REQ-DAE-SEC-012 — `radcli_ctx_dispatch()` is not reentrant

**Requirement:** Calling `radcli_ctx_dispatch()`, `radcli_dae_start()`, or
`radcli_dae_free()` from within a `radcli_dae_handler` that `radcli_ctx_dispatch()`
itself invoked MUST be rejected (for `radcli_ctx_dispatch()`) or is undefined (for
the other two), so that a handler cannot corrupt the dispatch loop it is running
inside of.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c (`radcli_ctx_dispatch()`'s `in_dispatch` reentrancy guard)
**Acceptance:** [SEC] negative, unit, local — `tests/dae-codec.c`: a handler that calls `radcli_ctx_dispatch()` on the same `ctx` observes it return -1, and the outer request is still answered normally once the handler returns. `radcli_dae_start()`/`radcli_dae_free()` called reentrantly from a handler remain untested (documented as undefined, not rejected).
**Links:** REQ-DAE-NET-002

#### REQ-DAE-SEC-013 — the RadSec reply queue is bounded, and dispatch never blocks to avoid it

**Requirement:** Under the RadSec transport, a queued but unsent reply MUST be
bounded, and MUST be dropped (the oldest one) rather than buffered without limit
when the queue is full, so that a DAC that stops reading cannot cause unbounded
memory growth on the NAS. Equally, `radcli_ctx_dispatch()` -- invoked by a
poll()-driven application only because its descriptor was reported readable --
MUST NOT itself block waiting to send a reply that cannot go out immediately: the
queue exists specifically so a slow-reading peer degrades to deferred replies and
bounded memory use, never to a multi-second stall of the caller's entire event
loop. A single non-blocking send attempt per reply, retried on a later
`radcli_ctx_dispatch()` call (prompted by `radcli_ctx_get_poll()` reporting
`POLLOUT` while anything is queued), is what makes both halves of this
requirement hold at once.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 6614 (implicit: a persistent connection means a reply born from processing inbound data can be delayed by outbound backpressure, unlike UDP's fire-and-forget replies); REQ-GEN-SEC-005 (no unbounded packet-driven allocation)
**Acceptance:** [SEC] positive and negative, local — `tests/dae-radsec-backpressure.c`/`tests/radsec-backpressure-server.py`: the peer shrinks its own TCP receive buffer and sends a 200-message burst of Disconnect-Requests without ever reading a reply, deterministically filling the send-side TCP window; every `radcli_ctx_dispatch()` call on the client side is timed and must return within a short bound (500ms) regardless -- proving it defers to `lib/dae.c`'s `radsec_reply_queue` (`radcli2_priv_tls_dae_send()`, one non-blocking attempt, `RADCLI_DAE_RADSEC_REPLY_QUEUE_SIZE` = 8 slots, oldest dropped on overflow) rather than blocking inside `tls_sendto()`'s ordinary retry-with-timeout path the way an outbound Access-Request legitimately may. UDP replies do not queue (a UDP `sendto()` on a non-blocking socket does not block the way a stalled TCP/TLS send can).
**Links:** REQ-DAE-NET-004

#### REQ-DAE-SEC-014 — Identifier space is separated per packet direction on a shared connection

**Requirement:** Under a transport where dynamic-authorization requests and
ordinary RADIUS requests share one connection (RadSec), the duplicate-suppression
table MUST be consulted only with a dynamic-authorization Identifier and MUST NOT
be cross-checked against an outstanding ordinary request's Identifier, or vice
versa, since the two 8-bit Identifier spaces are allocated independently by the two
ends.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §2.3 (Identifier scope); REQ-DAE-SEC-005
**Acceptance:** [SEC] unit, local, by construction — `lib/tls.c`'s `tls_recvfrom()` demux diverts any record coded Disconnect-Request/CoA-Request into `lib/dae.c`'s own duplicate-suppression table (`dae->slots[]`, keyed by that Identifier) before it can ever reach `radcli_transport_exchange()`'s reply-matching (`rc_check_reply()`, matched against its own `seq_nbr`, a wholly separate variable); every other code is left for `rc_check_reply()` and never touches `dae->slots[]`. The two Identifier spaces are consulted by disjoint code paths, not merely by convention.
**Links:** REQ-DAE-SEC-005

#### REQ-DAE-SEC-015 — a RadSec request is honoured only from the session it arrived on

**Requirement:** Under the RadSec transport, a dynamic-authorization packet MUST
only ever be honoured if it arrived on `radcli_ctx`'s own established and
TLS-verified session, exactly as an unauthorized UDP source is discarded
(REQ-DAE-SEC-001). This is what replaces `dae-server`'s source ACL under RadSec
(REQ-DAE-INIT-007 covers only the construction-time refusal to start without peer
verification enabled; this is the corresponding per-packet guarantee).
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 6614 §2.1 (one connection); REQ-DAE-SEC-001 (UDP counterpart); REQ-DAE-INIT-007
**Acceptance:** [SEC] unit, local, by construction — satisfied without a separate runtime check to write: `radcli2_priv_dae_on_radsec_packet()` (`lib/dae.c`) is reachable only from `lib/tls.c`'s own `gnutls_session_t` (via `tls_recvfrom()`'s inline demux or `radcli2_priv_tls_dae_poll()`), and one `rc_handle` holds exactly one such session (`tls_st.ctx`) -- there is no second session within this process a packet could instead have arrived on for `radcli_dae_new()`'s own `rh` to mistakenly honour. A packet replayed onto a genuinely different TLS/DTLS connection is, definitionally, a different `rc_handle`'s session, not reachable from this one at all.
**Links:** REQ-DAE-SEC-001, REQ-DAE-INIT-007

#### REQ-DAE-SEC-016 — dynamic authorization switched off under RadSec still answers with a protocol-level NAK, not silence

**Requirement:** Under the RadSec transport, when `dae-accept=no` (dynamic
authorization not enabled on this `radcli_ctx`) and a CoA-Request or
Disconnect-Request nonetheless arrives on the established session, radcli MUST
reply with the matching `CoA-NAK`/`Disconnect-NAK`, carrying an Error-Cause
attribute with the value 406 ("Unsupported Extension"), rather than
REQ-DAE-INIT-001's ordinary "MUST NOT accept, parse, or act on" silent-nothing
stance. This is a RadSec-specific exception to INIT-001: under UDP, a listener
that was never started has no packet to react to in the first place (nothing is
bound on port 3799), but under RadSec every packet type shares the one
already-established connection (RFC 6614 §2.1/§3.4(3), REQ-GEN's single-port
model), so silence is not available as a way to signal "not supported here" the
way an unopened UDP port's silence is -- the peer needs a positive, in-protocol
answer to know not to retry indefinitely.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 6614 §2.5 (published RFC, not the `bis` draft -- see this
document's header note)
**Acceptance:** [SEC] positive, unit, local -- with `dae-accept=no` (or unset,
or `dae-accept=udp`, i.e. no *RadSec* dynamic authorization active on this
`radcli_ctx`) and `serv-type=tls`/`dtls`, a Disconnect-Request/CoA-Request
arriving on the established session gets back a Disconnect-NAK/CoA-NAK with
Error-Cause 406 (`lib/dae.c`'s `send_radsec_unsupported_nak()`), not silence and
not a torn-down connection. This NAK is a fixed, publicly-computable response
(the RFC 6614/7360 secret it's signed with is itself a well-known constant, not
a real secret) and is sent for any packet carrying that Code regardless of
whether its own Request Authenticator verifies -- RFC 6614 §2.5 does not
condition this response on the incoming packet's own authenticity.
**Links:** REQ-DAE-INIT-001, REQ-DAE-ERR-001

#### REQ-DAE-SEC-017 — draft-ietf-radext-reverse-coa's own unsupported-feature signal does not replace REQ-DAE-SEC-016's NAK

**Requirement:** radcli MUST continue to answer with a NAK/Error-Cause 406 per
`REQ-DAE-SEC-016` whenever `dae-accept=no` and a CoA/Disconnect-Request
arrives on an established RadSec session, and MUST NOT instead adopt
`draft-ietf-radext-reverse-coa-08`'s own unsupported-feature guidance --
"[a client not configured for reverse CoA] will silently discard these
packets as per RFC2865, Section 3" -- as a replacement for that NAK. The two
are not actually the same case: the draft's silent-discard text describes a
*peer-identity-scoped* mismatch (§4.1: "Clients and servers implementing
reverse CoA MUST have a configuration flag which indicates that the other
party supports the reverse CoA functionality... This specification does not
define a way ... to negotiate this functionality on a per-connection
basis" -- i.e., *this specific peer* was never flagged as reverse-CoA-capable,
a case the draft leaves to plain RFC 2865 §3 unknown-Code handling), whereas
`dae-accept=no` is radcli deciding the *entire RadSec DAE feature* is off for
this `radcli_ctx`, independent of which peer is on the other end of the one
connection RFC 6614 §2.1 permits. RFC 6614 §2.5's NAK obligation is not
conditioned on any reverse-CoA-specific capability flag existing at all --
it predates and is independent of that later, narrower draft concept -- so it
continues to govern this case unconditionally.
**Strength:** MUST NOT
**Status:** DERIVED
**Source:** draft-ietf-radext-reverse-coa-08 §4.1; RFC 6614 §2.5 (REQ-DAE-SEC-016's
own source, which this requirement defers to)
**Acceptance:** [SEC] by construction, unit, local -- `lib/dae.c`'s
`send_radsec_unsupported_nak()` (REQ-DAE-SEC-016's mechanism) is unconditional
on any reverse-CoA capability flag: there is no `watchdog-interval`-style
"peer known to support this" state gating whether the NAK fires, so there is
no code path where a `dae-accept=no` NAK could regress into the draft's
silent-discard behavior by omission. This is a documentation-only
reconciliation, not a behavior change -- flagged here as a judgment call
(favoring the older, published RFC 6614 §2.5 obligation over the newer
draft's narrower baseline) for a maintainer to confirm, rather than something
resolved by testing.
**Links:** REQ-DAE-SEC-016, REQ-DAE-INIT-001

#### REQ-DAE-SEC-018 — NAS-Identifier mismatch is checked and NAKed automatically

**Requirement:** When the `nas-identifier` config option is set, radcli MUST
compare it against any NAS-Identifier attribute a validated CoA-Request or
Disconnect-Request carries, before ever invoking `radcli_dae_handler` (or, for
the L0 path, before `radcli_dae_process()` returns), unless
`RADCLI_DAE_NO_NAS_CHECK` was passed to `radcli_dae_new()`
(REQ-DAE-INIT-011). A mismatch MUST be answered automatically with a
Disconnect-NAK/CoA-NAK carrying Error-Cause 403 (RFC 5176 §3.5 "NAS
Identification Mismatch") and MUST NOT reach the handler; absence of either
the config option or the attribute is not a mismatch -- there is nothing to
check it against, and the request proceeds normally.

Deliberately excluded: NAS-IP-Address/NAS-IPv6-Address. Unlike
NAS-Identifier -- an opaque string both the NAS and the DAC's admin are
explicitly, statically configured with -- an address a DAC observes for a
NAS routinely differs from what the NAS itself is configured with (NAT,
containers, a proxy/load balancer in front of the NAS) for reasons outside
either party's control. radcli cannot know its own externally-meaningful
address any better than the config can state it, so comparing it
automatically would present an unreliable heuristic as if it were a real
security boundary.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §§3, 3.5
**Acceptance:** [SEC] positive and negative, unit, local — `tests/dae-codec.c` configures `nas-identifier` on the handle: test 10 confirms a request naming the matching NAS-Identifier reaches the handler and is ACKed; test 11 confirms a request naming a different NAS-Identifier is NAKed automatically (`RADCLI_DISCONNECT_NAK` carrying Error-Cause 403, verified by decoding the reply's attributes) without the handler being invoked; test 11b (REQ-DAE-INIT-011) confirms `RADCLI_DAE_NO_NAS_CHECK` suppresses this. Tests 1-9, run before `nas-identifier` is configured, exercise the "not configured" no-op case implicitly. NAS-IP-Address/NAS-IPv6-Address are not compared and have no test coverage of their own here (deliberately, per the exclusion above).
**Links:** REQ-DAE-INIT-011, REQ-DAE-ERR-001

### DATA — request inspection and reply construction

#### REQ-DAE-DATA-001 — the request exposes its code and full attribute list

**Requirement:** `radcli_dae_req_code()` MUST report the received packet code, and
`radcli_dae_req_attrs()` MUST expose every successfully decoded attribute as a
`radcli_avp_list`, so that an application can implement policy radcli does not
anticipate.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c (`radcli_dae_req_code()`, `radcli_dae_req_attrs()`)
**Acceptance:** [DATA] positive, unit, local — `tests/dae-codec.c`'s `counting_handler()` reads `radcli_dae_req_code()`/`radcli_dae_req_attrs()` on every accepted request and checks the code; attribute-list fidelity is exercised via the reply's mirrored Proxy-State (`radcli_avp_first()`/`_next()` walking `req->attrs`) rather than a dedicated four-attribute/VSA case.
**Links:** REQ-DAE-DATA-002

#### REQ-DAE-DATA-002 — session selectors are available without walking attributes

**Requirement:** radcli MUST provide typed accessors for the session-identification
attributes and combinations RFC 5176 §3 defines — at minimum Acct-Session-Id,
User-Name, Chargeable-User-Identity, Framed-IP-Address / Framed-IPv6-Address,
and NAS-Port (for the NAS-IP-Address/NAS-Identifier + NAS-Port combination used
when a session has no assigned Framed-IP-Address, e.g. some non-IP-assigning
NASes) — returning a clear "absent" indication when the attribute was not sent,
so that the common case needs no attribute iteration.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §3; openconnect/ocserv#756 (session matching priority)
**Acceptance:** [DATA] positive and negative, unit, local — `tests/dae-codec.c` (test 10) sends a request carrying Acct-Session-Id, User-Name, Framed-IP-Address, and NAS-Port together and confirms `radcli_dae_req_session_id()`/`_user_name()`/`_framed_ip()`/`_nas_port()` each return the sent value; test 11 confirms `_framed_ip()`/`_nas_port()` report absence (return -1) for a request that carried neither. `radcli_dae_req_framed_ip()` also accepts Framed-IPv6-Address, untested locally. Chargeable-User-Identity has no dedicated accessor -- an application reaches it, like any other attribute, via `radcli_dae_req_attrs()`. `tests/dae-freeradius-tests.sh` additionally confirms `_user_name()`/`_session_id()` against a Disconnect-Request encoded by a real, independent DAC (FreeRADIUS's `radclient`, not radcli's own `tests/dae-client.py`) -- interoperability, not just self-consistency, for User-Name and Acct-Session-Id specifically. Skips (exit 77) when `radclient` is absent from PATH.
**Links:** REQ-DAE-DATA-001, REQ-DAE-ERR-002

#### REQ-DAE-DATA-004 — Proxy-State is mirrored unmodified

**Requirement:** Every reply MUST include all Proxy-State attributes from the
request, in the order received and with contents unmodified, and MUST NOT include
Proxy-State attributes the request did not carry.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §3; RFC 2865 §5.33
**Acceptance:** [DATA] positive, unit, local — `tests/dae-codec.c`'s positive-path test sends one Proxy-State attribute and confirms the reply's bytes contain it; multiple distinct Proxy-State attributes and a no-Proxy-State request are not separately covered by a test yet, though `lib/dae.c`'s `send_reply()` mirrors every matching attribute in order by construction.
**Links:** REQ-DAE-NET-004

#### REQ-DAE-DATA-005 — the application chooses ACK or NAK, radcli chooses the code

**Requirement:** `radcli_dae_reply()` and `radcli_dae_reply_error()` MUST derive the
reply code from the request code and the application's accept/reject decision, and
`radcli_dae_reply_error()` MUST encode the supplied Error-Cause as attribute 101,
so that the application expresses intent rather than protocol encoding.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §§2.1, 3.5
**Acceptance:** [DATA] positive, unit, local — `tests/dae-codec.c`: `radcli_dae_reply(req, 1)` on a Disconnect-Request (code 40) yields code 41; `radcli_dae_reply_error()` on a CoA-Request (code 43) yields code 45. The reply-code derivation table's other three cells (Disconnect NAK -> 42, CoA ACK -> 44) are not separately exercised, though `radcli_dae_reply()`/`_reply_error()`'s code selection in `lib/dae.c` is unconditional on `req->code`, not on which case happened to be tested.
**Links:** REQ-DAE-NET-004, REQ-DAE-ERR-001

### ERR — failure behaviour

#### REQ-DAE-ERR-001 — unknown packet codes are silently discarded

**Requirement:** radcli MUST silently discard a packet whose Code is not
CoA-Request (43) or Disconnect-Request (40), without replying, per RFC 5176 §3's
requirement that a NAS silently discard packets with invalid Code fields.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §3
**Acceptance:** [ERR] negative, unit, local — `tests/dae-codec.c` sends code 4 (Accounting-Request) from an authorized sender and confirms no reply and no handler invocation. Codes 1, 41, and 255 are not separately covered, though `lib/dae.c`'s check is an explicit allow-list (`RADCLI_DISCONNECT_REQUEST`/`RADCLI_COA_REQUEST` only), not a deny-list of known-bad codes.
**Links:** REQ-DAE-SEC-001

#### REQ-DAE-ERR-002 — an unsupported request type is the application's NAK to send

**Requirement:** radcli MUST deliver a well-formed CoA-Request to the application
even when the application implements only disconnection, and MUST NOT synthesise a
rejection itself, so that the choice of Error-Cause 405 (Unsupported Service)
belongs to the application that knows what it supports.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §3.5
**Acceptance:** [ERR] positive, local — `tests/dae-tests.sh` runs `raddaeserver --nak=503`, which answers a request with the requested Error-Cause carried in the reply, driven entirely by the application's own choice of value (`radcli_dae_reply_error()`'s `error_cause` argument in `handle_request()`, `src/raddaeserver.c`) -- `lib/dae.c` never inspects or special-cases it. The specific case of a CoA-Request answered with code 45 and Error-Cause 405 is not separately exercised, though nothing in the code path distinguishes it from the tested Disconnect-Request/503 case.
**Links:** REQ-DAE-DATA-005

#### REQ-DAE-ERR-003 — a failed reply is reported, never silently dropped

**Requirement:** `radcli_dae_reply()` and `radcli_dae_reply_error()` MUST return a
distinguishable error when the reply cannot be transmitted, so that an application
can log or retry rather than assume delivery.
**Strength:** MUST
**Status:** DERIVED
**Source:** REQ-GEN-STYLE-* (error propagation)
**Acceptance:** [ERR] negative, local — `send_reply()`/`reply_and_record()` (`lib/dae.c`) already return -1 when the underlying `sendto()`/`radcli2_priv_tls_dae_send()` call fails, and `radcli_dae_reply()`/`_reply_error()` propagate that return value unchanged. `tests/dae-codec.c` (test 18) defers a request's reply, closes the dae's own socket out from under it, then confirms `radcli_dae_reply()` returns -1 rather than reporting success for a reply that was silently dropped.
**Links:** REQ-DAE-NET-004

### TEARDOWN — lifetimes

#### REQ-DAE-TEARDOWN-001 — the listener releases only what it created

**Requirement:** `radcli_dae_free()` MUST close the descriptor radcli opened in
`radcli_dae_start()`, if any, and MUST release the duplicate-suppression state. An
L0-only `radcli_dae` (one `radcli_dae_process()` is called on but `radcli_dae_start()`
never is) has no radcli-owned descriptor to close, since `radcli_dae_process()`
takes a buffer and source address, not a descriptor -- there is nothing for
`radcli_dae_free()` to accidentally take ownership of.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c (`radcli_dae_free()`)
**Acceptance:** [TEARDOWN] positive, local — `tests/dae.c`/`tests/dae-codec.c` each run a full new/start/free cycle (`dae-codec.c`'s under real traffic) without a leak report from the allocator's own perturbation (`MALLOC_PERTURB_`, `meson test`'s default); `tests/dae-codec.c`'s L0 block (tests 12-14) additionally runs a new/free cycle that never calls `radcli_dae_start()` at all. No dedicated ASan run, since this environment currently has no working sanitizer build.
**Links:** REQ-DAE-TEARDOWN-002

#### REQ-DAE-TEARDOWN-002 — request objects have an explicit, independent lifetime

**Requirement:** A `radcli_dae_request` MUST remain valid until
`radcli_dae_request_free()` is called, MUST NOT be invalidated by a subsequent
`radcli_ctx_dispatch()`, and MUST NOT be used after its listener has been freed.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/dae.c (`radcli_dae_request_free()`)
**Acceptance:** [TEARDOWN] positive, local — `tests/dae-codec.c`'s PENDING/deferred-reply case (test 6) keeps a request alive, unfreed, across one further `radcli_ctx_dispatch()` call (a duplicate arrival, silently dropped) before replying to and freeing it explicitly. Two requests received back to back both readable before either is freed, and the documented listener-freed-first misuse, are not separately covered.
**Links:** REQ-DAE-TEARDOWN-001
