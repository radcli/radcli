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
  - doc/plan-api-modernization.md
  - include/radcli/radcli2.h
  - lib/dae.c
  - tests/dae.c
  - tests/dae-codec.c
---

# RFC 5176 Dynamic Authorization Requirements

Scope: the receive-only Dynamic Authorization Server role — accepting and answering
CoA-Request (43) and Disconnect-Request (40) packets over RADIUS/UDP port 3799, per
RFC 5176 as published. Construction (`radcli_dae_new()`/`_set_handler()`/`_start()`/
`_free()`, the ctx-level poll surface, `INIT`/`NET`), the request-validation and
reply pipeline (`SEC`, `DATA`, `ERR`), the session-selector accessors, and the L0
buffer entry point (`radcli_dae_process()`/`radcli_dae_reply_to_buffer()`) are all
implemented and tested (`tests/dae.c`, `tests/dae-codec.c`, and end to end via
`src/raddaeserver.c`/`tests/dae-client.py`/`tests/dae-tests.sh`); their
requirements below carry `Status: DERIVED`. Only the RadSec-anticipating requirements
(decision C1's transport-switch invariants, the bounded reply queue,
Identifier-space separation) are not implemented yet and remain
`Status: PLANNED` (see `doc/requirements/README.md`'s status legend).

**Exception to the "published standards only" scope rule (decision C2):**
`REQ-DAE-INIT-007`, `REQ-DAE-SEC-013`, and `REQ-DAE-SEC-014` are sourced to
`draft-ietf-radext-radiusdtls-bis`, still an Internet-Draft, not a published RFC.
They are recorded as `PLANNED` requirements anyway -- unlike the rest of decision
C2's excluded material (e.g. bis §6.1.1's Protocol-Error/Error-Cause 406 handling
for packet types this library cannot process at all under RadSec, which has no
requirement here and is deferred entirely) -- because they constrain the *public
API and ABI surface* decision C1 already committed to (no `radcli_dae_fd()`, a
ctx-level poll surface, one shared descriptor), not the RadSec wire format itself.
Getting the shape of that commitment right now is cheaper than an ABI break later;
getting Protocol-Error's wire encoding right is not needed until the transport
exists. Revisit both the promotion and the deferral if bis's scope changes before
publication.

radcli implements the server (receiving) side only — there is no exported
request encoder; see `doc/plan-api-modernization.md`'s "No public DAC side" for the
rationale.

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
**Source:** doc/plan-api-modernization.md (decision D); openconnect/ocserv#756 ("opt-in RFC 5176 listener")
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
**Source:** doc/plan-api-modernization.md (decision D); FreeRADIUS `clients.conf` guidance; strongSwan `charon.plugins.eap-radius.dae.secret`
**Acceptance:** [INIT] negative, unit, local — `tests/dae.c`: three configurations (neither set, only `dae-server`, only `dae-secret`) each make `radcli_dae_new()` return `NULL`.
**Links:** REQ-DAE-INIT-001, REQ-DAE-INIT-007, REQ-DAE-SEC-001

#### REQ-DAE-INIT-003 — `dae-server` accepts addresses and hostnames, never prefixes

**Requirement:** `dae-server` MUST accept literal IPv4/IPv6 addresses and
hostnames, and MUST reject any value carrying a network prefix (`/nn`), so that the
authorized sender set stays small, enumerable at configuration time, and incapable
of authorizing an unintended host.
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/plan-api-modernization.md ("explicit addresses only — no networks")
**Acceptance:** [INIT] negative, unit, local — `tests/dae.c`: `dae-server = 192.0.2.0/24` makes `radcli_dae_new()` return `NULL`; `dae-server = 192.0.2.1` (and a second entry with a `:secret` override) succeeds. Only literal addresses are exercised in the unit test; a resolvable-hostname case needs real DNS and is not covered locally.
**Links:** REQ-DAE-INIT-004, REQ-DAE-SEC-001

#### REQ-DAE-INIT-004 — hostnames are resolved once, at configuration load

**Requirement:** A hostname in `dae-server` MUST be resolved when the configuration
is loaded, with every resulting address authorized, and MUST NOT be re-resolved
while the listener runs, because periodic re-resolution would require either
blocking the receive path or a library-owned timer.
**Strength:** MUST
**Status:** PLANNED
**Source:** doc/plan-api-modernization.md; REQ-GEN-SEC-003 (no process-wide timers)
**Acceptance:** [INIT] positive, local — a hostname resolving to two addresses authorizes both; changing the mapping afterwards has no effect until the configuration is reloaded.
**Links:** REQ-GEN-SEC-003, REQ-DAE-INIT-003

#### REQ-DAE-INIT-005 — duplicate-suppression state is fixed at construction

**Requirement:** radcli MUST allocate, at listener construction, a fixed table of
256 slots per configured sender, indexed by RADIUS Identifier, and MUST NOT grow,
evict, or otherwise resize that state at run time, so that the memory cost is
constant and no packet-driven allocation exists on an externally reachable path.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §2.3; doc/plan-api-modernization.md ("a fixed table, not a cache")
**Acceptance:** [INIT] unit, local — `add_dac_addrs()` (`lib/dae.c`) `calloc()`s `RADCLI_DAE_SLOTS` (256) slots per DAC once, at `radcli_dae_new()` time; `radcli_ctx_dispatch()`'s duplicate suppression (REQ-DAE-SEC-005/006, tested in `tests/dae-codec.c`) indexes directly into this table and never grows or reallocates it. The specific 10,000-request heap-profile/ASan measurement is not run in this environment (no working sanitizer build here).
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
**Status:** PLANNED
**Source:** doc/plan-api-modernization.md ("Security invariants across the transport switch")
**Acceptance:** [INIT] negative — `dae-accept = yes` under `serv-type = tls` with peer verification disabled fails construction. Depends on RadSec support (`draft-ietf-radext-radiusdtls-bis`), not yet implemented: today, `dae-accept = yes` under `serv-type = tls`/`dtls` always fails, for the more basic reason that the transport itself does not exist yet (see REQ-DAE-INIT-002's note).
**Links:** REQ-DAE-INIT-002

#### REQ-DAE-INIT-008 — UDP-only options left set under RadSec MUST warn, never silently disappear or fail construction

**Requirement:** When the DAE transport is RadSec, `dae-listen`, `dae-server`,
`dae-secret`, and `dae-require-message-authenticator` are inapplicable (RadSec
supplies the authorized peer via TLS verification and the secret via bis §3.1's
fixed string). If any of them is still set, `radcli_dae_new()` MUST log a warning
naming the inapplicable option(s) and MUST proceed with construction rather than
failing because of them, so that switching `serv-type` from UDP to RadSec is a
configuration change an operator can make incrementally -- leaving the old options
in place while migrating -- without either a construction failure or the checks
those options once named silently ceasing to exist unremarked.
**Strength:** MUST
**Status:** PLANNED
**Source:** doc/plan-api-modernization.md ("Under RadSec both are supplied by the transport instead... Leaving either option in the file after switching serv-type must therefore be a warning, not an error... dae-listen and dae-require-message-authenticator are likewise inapplicable under RadSec and warn rather than fail")
**Acceptance:** [INIT] positive — under `serv-type = tls`/`dtls` with `dae-accept = yes` and peer verification enabled, setting `dae-listen`/`dae-server`/`dae-secret`/`dae-require-message-authenticator` still succeeds, with a warning logged naming each set option. Depends on RadSec support, not yet implemented.
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

### NET — descriptor exposure, intake, and reply transmission

#### REQ-DAE-NET-001 — radcli exposes ctx's descriptor and never drives a loop

**Requirement:** `radcli_ctx_get_poll()` MUST report the descriptor to watch (or
`-1` if there is none), the direction(s) to watch it in, and radcli MUST NOT call
`poll()`, `select()`, `epoll_wait()`, or sleep on the caller's behalf, so that any
event loop (libev, libevent, epoll, plain `poll()`) can host it.
`radcli_ctx_dispatch()` reads whatever is ready and, once packet validation lands
(REQ-DAE-NET-002), demultiplexes and invokes the registered
`radcli_dae_handler`. There is deliberately no per-object descriptor accessor
(no `radcli_dae_fd()`): the descriptor belongs to the `radcli_ctx`, because a
future dynamic-authorization transport carried over the same session as ordinary
requests shares one descriptor between the two, and a `radcli_dae`-only accessor
would let an application watch a descriptor that silently starts meaning something
else (doc/plan-api-modernization.md, "Why there is no `radcli_dae_fd()`").
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/plan-api-modernization.md (decision C1, L2); REQ-GEN-SEC-003
**Acceptance:** [NET] positive, unit, local — `tests/dae.c`: `radcli_ctx_get_poll()` reports `fd == -1` before `radcli_dae_start()` and after `radcli_dae_free()`, and a valid, `POLLIN`-watched descriptor in between; no polling symbol appears in `lib/dae.c`. `src/raddaeserver.c` is a real plain-`poll()`-loop application built on exactly this contract, driven end to end by `tests/dae-tests.sh`/`tests/dae-client.py`.
**Links:** REQ-GEN-SEC-003, REQ-DAE-NET-003

#### REQ-DAE-NET-002 — validation completes before the application sees a request

**Requirement:** `radcli_ctx_dispatch()` MUST perform, in order, the source-address
check, Request Authenticator verification, Message-Authenticator verification when
that attribute is present, the Event-Timestamp freshness check, and duplicate
suppression, and MUST NOT invoke the registered `radcli_dae_handler` unless all of
them pass, so that an application never has to implement RADIUS validation itself,
and never receives a request object that has not fully passed validation
(strengthened over an app-called receive function, which could in principle be
called on a partially validated result: with decision C1 there is no such public
entry point at all).
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §§2.3, 3, 6.3; doc/plan-api-modernization.md (decision C1, L1)
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
**Source:** doc/plan-api-modernization.md (decision C, L0); openconnect/ocserv#756 (process-boundary question)
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
**Source:** doc/plan-api-modernization.md (decision C, L0)
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
**Source:** RFC 5176 §6.1; doc/plan-api-modernization.md
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
(CVE-2024-3596) exploits, ahead of that becoming an RFC-level requirement (see
`doc/plan-api-modernization.md`, "Message-Authenticator: optional per RFC 5176, hardening available").
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §3; RFC 2869 §5.14; doc/plan-api-modernization.md ("Message-Authenticator: optional per RFC 5176, hardening available")
**Acceptance:** [SEC] negative and positive, unit, local — `tests/dae-codec.c` corrupts a valid packet's Message-Authenticator and confirms no reply and no handler invocation; every positive-path packet in that file carries a correct one and is accepted. `dae-require-message-authenticator = yes` rejecting an absent attribute is not covered by a test yet, though the check exists in `lib/dae.c`.
**Links:** REQ-DAE-SEC-002, REQ-DAE-INIT-002

#### REQ-DAE-SEC-004 — Event-Timestamp is checked two-sidedly when present

**Requirement:** When a request carries an Event-Timestamp attribute and
`dae-max-clock-skew` is non-zero, radcli MUST silently discard the request if the
absolute difference between that timestamp and local time exceeds the configured
skew — in either direction — and MUST accept a request that omits the attribute,
since RFC 5176 §6.3 makes inclusion a SHOULD.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §6.3
**Acceptance:** [SEC] negative and positive, unit, local — `tests/dae-codec.c` sends an Event-Timestamp 120s stale against a 60s `dae-max-clock-skew` (discarded) and a fresh one (accepted). A future-dated timestamp, an absent attribute, and `dae-max-clock-skew = 0` are not separately covered by a test yet, though the two-sided (`diff < 0` negated) comparison and the `> 0` gate are both in `lib/dae.c`.
**Links:** REQ-DAE-SEC-005

#### REQ-DAE-SEC-005 — a duplicate never reaches the application twice

**Requirement:** radcli MUST treat a request as a duplicate when its source
address, source port, Identifier, and Request Authenticator all match a slot
recorded within the retention period, MUST answer it with the previously returned
decision without invoking the application again, and MUST discard it silently if
the original is still awaiting an application decision.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §2.3
**Acceptance:** [SEC] positive, unit, local — `tests/dae-codec.c`: an exact retransmission (same Identifier, source port, Request Authenticator) after the original was ACKed produces one handler call total and an identical resent reply; a retransmission arriving while the original is still PENDING (the handler deferred its reply) produces no reply and no second handler call, and the later deferred `radcli_dae_reply_error()` call still succeeds and is delivered.
**Links:** REQ-DAE-INIT-005, REQ-DAE-SEC-006

#### REQ-DAE-SEC-006 — retention is derived, not configured

**Requirement:** The duplicate-suppression retention period MUST equal
`dae-max-clock-skew` when the Event-Timestamp check is enabled, and 30 seconds when
it is disabled; radcli MUST NOT expose retention as a separate configuration
option, because its correct value follows from radcli's own matching rules rather
than from any property of the deployment.
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/plan-api-modernization.md ("Slot retention is derived, not configured")
**Acceptance:** [SEC] unit, local — `lib/options.h` registers no `dae-cache-time` option, so the config parser rejects one outright; `lib/dae.c`'s `radcli_ctx_dispatch()` derives `retention` as `dae->max_clock_skew` when positive, else 30. The exact t+59s-accepted/t+61s-reprocessed boundary is not exercised by a timing-based test yet (`tests/dae-codec.c`'s duplicate-suppression cases run well within the window).
**Links:** REQ-DAE-SEC-004, REQ-DAE-SEC-005

#### REQ-DAE-SEC-007 — attribute parsing is bounds-checked throughout

**Requirement:** All parsing of received dynamic-authorization packets MUST use the
`pkt_buf` interface from `lib/util.h`, and every overflow return MUST be propagated
rather than ignored, so that a malformed packet from an authorized sender cannot
read outside the receive buffer.
**Strength:** MUST
**Status:** PLANNED
**Source:** REQ-GEN-MEM-*; contrib/ai/personas/radcli-core-dev.md (packet construction and parsing)
**Acceptance:** [SEC] negative, local under ASan/UBSan — `--truncate` and `--bad-length` across a sweep of lengths produce clean rejections with no sanitiser report.
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
**Source:** doc/plan-api-modernization.md ("Security requirements to write before the code"); REQ-GEN-SEC-003
**Acceptance:** [SEC] unit, local — `tests/dae.c` checks `fcntl(fd, F_GETFL)` for `O_NONBLOCK` on the descriptor `radcli_ctx_get_poll()` reports after `radcli_dae_start()`.
**Links:** REQ-GEN-SEC-003, REQ-DAE-NET-001

#### REQ-DAE-SEC-011 — the listener socket is close-on-exec

**Requirement:** The socket `radcli_dae_start()` binds MUST have `FD_CLOEXEC` set,
so that it does not leak across `exec()` in an application that spawns children.
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/plan-api-modernization.md ("Security requirements to write before the code"); REQ-GEN-SEC-004
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
**Source:** doc/plan-api-modernization.md ("Three contracts this shape requires")
**Acceptance:** [SEC] negative, unit, local — `tests/dae-codec.c`: a handler that calls `radcli_ctx_dispatch()` on the same `ctx` observes it return -1, and the outer request is still answered normally once the handler returns. `radcli_dae_start()`/`radcli_dae_free()` called reentrantly from a handler remain untested (documented as undefined, not rejected).
**Links:** REQ-DAE-NET-002

#### REQ-DAE-SEC-013 — the RadSec reply queue is bounded

**Requirement:** Under the RadSec transport, a queued but unsent reply MUST be
bounded, and MUST be dropped rather than buffered without limit when the queue is
full, so that a DAC that stops reading cannot cause unbounded memory growth on the
NAS.
**Strength:** MUST
**Status:** PLANNED
**Source:** doc/plan-api-modernization.md ("Three contracts this shape requires")
**Acceptance:** [SEC] negative — filling the queue against a non-reading peer causes the oldest or newest reply to be dropped, not unbounded growth. Depends on RadSec support, not yet implemented; UDP replies do not queue.
**Links:** REQ-DAE-NET-004

#### REQ-DAE-SEC-014 — Identifier space is separated per packet direction on a shared connection

**Requirement:** Under a transport where dynamic-authorization requests and
ordinary RADIUS requests share one connection (RadSec), the duplicate-suppression
table MUST be consulted only with a dynamic-authorization Identifier and MUST NOT
be cross-checked against an outstanding ordinary request's Identifier, or vice
versa, since the two 8-bit Identifier spaces are allocated independently by the two
ends.
**Strength:** MUST
**Status:** PLANNED
**Source:** doc/plan-api-modernization.md ("Identifier-space separation")
**Acceptance:** [SEC] negative — a Disconnect-Request whose Identifier collides with an outstanding Access-Request's Identifier on the same session causes neither to be mismatched. Depends on RadSec support and Phase 4 async requests, neither implemented yet.
**Links:** REQ-DAE-SEC-005

#### REQ-DAE-SEC-015 — a RadSec request is honoured only from the session it arrived on

**Requirement:** Under the RadSec transport, `radcli_ctx_dispatch()` MUST discard
a dynamic-authorization packet arriving on any session other than the one this
`radcli_ctx` itself established and TLS-verified, without invoking the handler and
without a reply, exactly as an unauthorized UDP source is discarded
(REQ-DAE-SEC-001). This is what replaces `dae-server`'s source ACL under RadSec
(REQ-DAE-INIT-007 covers only the construction-time refusal to start without peer
verification enabled; this is the corresponding per-packet runtime check).
**Strength:** MUST
**Status:** PLANNED
**Source:** doc/plan-api-modernization.md ("Security invariants across the transport switch": *"A DAE request on an unverified or unexpected session is discarded exactly as an unauthorized source is"*; listed there as the row *"most at risk of being implemented as 'accept whatever arrives on the socket'"*)
**Acceptance:** [SEC] negative — a dynamic-authorization packet arriving on a session this handle did not itself open and verify (e.g. replayed onto an unrelated connection) produces no reply and no handler invocation. Depends on RadSec support, not yet implemented.
**Links:** REQ-DAE-SEC-001, REQ-DAE-INIT-007

### DATA — request inspection and reply construction

#### REQ-DAE-DATA-001 — the request exposes its code and full attribute list

**Requirement:** `radcli_dae_req_code()` MUST report the received packet code, and
`radcli_dae_req_attrs()` MUST expose every successfully decoded attribute as a
`radcli_avp_list`, so that an application can implement policy radcli does not
anticipate.
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/plan-api-modernization.md (decision C, L1)
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
**Acceptance:** [DATA] positive and negative, unit, local — `tests/dae-codec.c` (test 10) sends a request carrying Acct-Session-Id, User-Name, Framed-IP-Address, and NAS-Port together and confirms `radcli_dae_req_session_id()`/`_user_name()`/`_framed_ip()`/`_nas_port()` each return the sent value; test 11 confirms `_framed_ip()`/`_nas_port()` report absence (return -1) for a request that carried neither. `radcli_dae_req_framed_ip()` also accepts Framed-IPv6-Address, untested locally. Chargeable-User-Identity has no dedicated accessor -- an application reaches it, like any other attribute, via `radcli_dae_req_attrs()`.
**Links:** REQ-DAE-DATA-001, REQ-DAE-ERR-002

#### REQ-DAE-DATA-003 — NAS identity mismatch is detectable without RFC knowledge

**Requirement:** `radcli_dae_req_check_nas()` MUST compare any NAS-IP-Address,
NAS-IPv6-Address, and NAS-Identifier attributes in the request against the
configured local identity and MUST report the RFC 5176 §3.5 "NAS Identification
Mismatch" condition, so that an application never needs to know that the correct
Error-Cause is 403.
**Strength:** MUST
**Status:** DERIVED
**Source:** RFC 5176 §§3, 3.5
**Acceptance:** [DATA] negative and positive, unit, local — `tests/dae-codec.c` configures `nas-identifier`/`nas-ip` on the handle, then (test 10) confirms `radcli_dae_req_check_nas()` returns 0 for a request naming the matching NAS-Identifier, and (test 11) returns nonzero for one naming a different NAS-Identifier. `radcli_dae_reply_error(req, RADCLI_ERROR_NAS_IDENTIFICATION_MISMATCH)` chained onto that result is not separately asserted, though `radcli_dae_reply_error()`'s Error-Cause encoding is exercised elsewhere (test 6, a different cause value). NAS-IP-Address/NAS-IPv6-Address mismatches are not exercised locally.
**Links:** REQ-DAE-ERR-001

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
**Source:** RFC 5176 §3.5; doc/plan-api-modernization.md ("both codes are handled at the library level")
**Acceptance:** [ERR] positive, local — `tests/dae-tests.sh` runs `raddaeserver --nak=503`, which answers a request with the requested Error-Cause carried in the reply, driven entirely by the application's own choice of value (`radcli_dae_reply_error()`'s `error_cause` argument in `handle_request()`, `src/raddaeserver.c`) -- `lib/dae.c` never inspects or special-cases it. The specific case of a CoA-Request answered with code 45 and Error-Cause 405 is not separately exercised, though nothing in the code path distinguishes it from the tested Disconnect-Request/503 case.
**Links:** REQ-DAE-DATA-005

#### REQ-DAE-ERR-003 — a failed reply is reported, never silently dropped

**Requirement:** `radcli_dae_reply()` and `radcli_dae_reply_error()` MUST return a
distinguishable error when the reply cannot be transmitted, so that an application
can log or retry rather than assume delivery.
**Strength:** MUST
**Status:** PLANNED
**Source:** doc/plan-api-modernization.md; REQ-GEN-STYLE-* (error propagation)
**Acceptance:** [ERR] negative, local — replying on a closed descriptor returns an error distinct from success.
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
**Source:** doc/plan-api-modernization.md (decision C)
**Acceptance:** [TEARDOWN] positive, local — `tests/dae.c`/`tests/dae-codec.c` each run a full new/start/free cycle (`dae-codec.c`'s under real traffic) without a leak report from the allocator's own perturbation (`MALLOC_PERTURB_`, `meson test`'s default); `tests/dae-codec.c`'s L0 block (tests 12-14) additionally runs a new/free cycle that never calls `radcli_dae_start()` at all. No dedicated ASan run, since this environment currently has no working sanitizer build.
**Links:** REQ-DAE-TEARDOWN-002

#### REQ-DAE-TEARDOWN-002 — request objects have an explicit, independent lifetime

**Requirement:** A `radcli_dae_request` MUST remain valid until
`radcli_dae_request_free()` is called, MUST NOT be invalidated by a subsequent
`radcli_ctx_dispatch()`, and MUST NOT be used after its listener has been freed.
**Strength:** MUST
**Status:** DERIVED
**Source:** doc/plan-api-modernization.md (decision C, L1)
**Acceptance:** [TEARDOWN] positive, local — `tests/dae-codec.c`'s PENDING/deferred-reply case (test 6) keeps a request alive, unfreed, across one further `radcli_ctx_dispatch()` call (a duplicate arrival, silently dropped) before replying to and freeing it explicitly. Two requests received back to back both readable before either is freed, and the documented listener-freed-first misuse, are not separately covered.
**Links:** REQ-DAE-TEARDOWN-001
