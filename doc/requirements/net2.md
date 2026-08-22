---
title: radcli2.h transport/request-reply entry point (radcli_request_new()/_perform()/etc.)
generator: requirements-from-implementation
id-prefix: REQ-NET2
categories:
  INIT: radcli_request_new/_free construction and destruction, and server/type/secret selection
  SEND: radcli_request_perform packet construction (Access-Request vs Accounting-Request)
  RECV: radcli_request_perform reply handling, and the radcli_request_code/_attrs/_server accessors
  ERR: rejection and failure-mapping contracts
sources:
  - lib/request.c
  - include/radcli/radcli2.h
  - lib/radcli.map.in
  - lib/sendserver.c (radcli_transport_exchange(), shared transport core)
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
additions to `lib/radcli.map`'s single version node, not migrations of
existing ones). It is not `attrs.md`'s counterpart: unlike `rc_auth()`/
`rc_acct()`/`rc_aaa_ctx()`, this API does no NAS-Port/Acct-Delay-Time
auto-filling and no multi-server failover — see `REQ-NET2-INIT-003`.

**Not yet covered by this document** (tracked as a gap, not silently assumed
fine): `radcli_transport_exchange()` itself (declared in `include/includes.h`,
not exported via `lib/radcli.map`) is the shared low-level send/retry/receive
core for *both* this document's API and `rc_send_server_ctx()`'s; its own
contract (address fail-over, Response Authenticator / Message-Authenticator
verification, retry/timeout accounting) is `net.md`'s to state in full — it is
only cited below where this API's behavior depends on it, not re-derived.
`radcli_avp_encode_rfc2865()`/`radcli_avp_decode()` (the wire codec this API
calls into) are `avp2.md`'s declared gap, not re-opened here.

[UNDOCUMENTED]/process gap noted during derivation, not resolved by this
document: no `doc/requirements/` entry existed for this API before this
document (AGENTS.md's Requirements-First Workflow requires one before code);
`lib/request.c`'s and `radcli2.h`'s comments cite a "`doc/plan-api-modernization.md`
decision G" for the single-server-per-request design (see REQ-NET2-INIT-003)
that does not exist anywhere in the repository — the rationale below is
derived from the code and comment text itself, not from that missing file.

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
**Status:** DERIVED — `[REVIEW: rationale cites a non-existent
"doc/plan-api-modernization.md decision G"; derived here from code/comment
text alone, not from that document. See this document's top-level gap note.]`
**Source:** lib/request.c:100-117
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

## SEND — packet construction

### REQ-NET2-SEND-008 — Access-Request uses a random Request Authenticator and carries Message-Authenticator

**Requirement:** For `RADCLI_CODE_ACCESS_REQUEST`, `radcli_request_perform()`
MUST fill the Request Authenticator with `rc_get_random_bytes()` output (not a
predictable value), encode attributes with `radcli_avp_encode_rfc2865()`
reserving `2 + MD5_DIGEST_SIZE` bytes, and append a Message-Authenticator
attribute via `add_msg_auth_attr()` before transmission — mirroring
`rc_send_server_ctx()`'s non-accounting path so the two share one proven
implementation of this framing, not a second copy.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:202-216; cf. lib/sendserver.c:1051-1062
(`rc_send_server_ctx()`'s equivalent branch)
**Acceptance:** [SEND] interoperability, root+FreeRADIUS —
`tests/request-freeradius.c`'s Access-Request/Access-Accept check (needs
Message-Authenticator to be accepted by a real FreeRADIUS server).
**Links:** REQ-NET-SEC-* (net.md's Message-Authenticator requirements)

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

### REQ-NET2-SEND-010 — the request ID is unpredictable per call

**Requirement:** `radcli_request_perform()` MUST set the packet's `id` octet
from `random()`, not from a caller-visible or predictable counter.
**Strength:** MUST
**Status:** DERIVED — `[REVIEW: duplicates rc_get_id() (lib/buildreq.c) rather
than reusing it; same value/behavior today, but see the core-dev review's
reuse finding on this commit — a future ID-generation hardening in
rc_get_id() would not automatically apply here.]`
**Source:** lib/request.c:177
**Acceptance:** [SEND] not exercised by the current local test suite beyond
implicit coverage (a fixed/predictable ID would still interoperate with
FreeRADIUS); `Needs-domain-check` whether this project wants a dedicated
statistical/uniqueness test.

### REQ-NET2-SEND-011 — a request may be performed at most once, across either send function

**Requirement:** `radcli_request_perform()` and `radcli_request_send_noreply()`
share one `r->performed` flag: either call MUST return `RADCLI_ERROR`
immediately, without sending anything, if called on a request that has
already been performed by *either* function (`r->performed` already set) or
if `r` is `NULL`. A caller needing a retransmission with different content
MUST construct a new `radcli_request` via `radcli_request_new()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:236 (`radcli_request_perform()`), lib/request.c:267
(`radcli_request_send_noreply()`) — both check/set the same `r->performed`;
contract restated in `include/radcli/radcli2.h`'s doc comments ("May be
called only once per request")
**Acceptance:** [SEND] unit, local — `tests/request.c` calls
`radcli_request_perform()` twice on the same request (second call without
network access available) and confirms the second returns `RADCLI_ERROR`
without hanging or crashing; a second test constructs a request, calls
`radcli_request_send_noreply()`, then confirms both a second
`radcli_request_send_noreply()` call and a `radcli_request_perform()` call on
the same (now-performed) request return `RADCLI_ERROR`.
**Links:** REQ-NET2-ERR-012, REQ-NET2-SEND-012

### REQ-NET2-SEND-012 — radcli_request_send_noreply() transmits once, with no retry and no reply wait

**Requirement:** `radcli_request_send_noreply()` MUST build the same wire
packet `radcli_request_perform()` would (shared `do_exchange()` helper, same
Request/Accounting-Request Authenticator and Message-Authenticator rules as
REQ-NET2-SEND-008/009/010), then call `radcli_transport_exchange()` with
`no_wait = 1` — a single transmission to the first resolved address, no
retry loop, and no wait for a reply. It MUST return `RADCLI_OK` once the
packet is handed to the socket layer, `RADCLI_ERROR` on any earlier failure
(name resolution, packet encoding, or the send itself), and MUST NEVER
return `RADCLI_TIMEOUT` (there is no reply to time out on). `r->reply_code`
and `r->reply_attrs` MUST remain unchanged (this function does not decode a
reply).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:171-227 (`do_exchange()`), lib/request.c:260-274
(`radcli_request_send_noreply()`); lib/sendserver.c:622-627
(`radcli_transport_exchange()`'s `no_wait` branch, first-address-only, no
retry/poll)
**Acceptance:** [SEND] unit, local — `tests/request.c` sends a no-wait
Accounting-Request to an unreachable address (192.0.2.1, RFC 5737) and
confirms `RADCLI_OK` is returned promptly (no timeout wait).
**Links:** REQ-NET2-SEND-008, REQ-NET2-SEND-009, REQ-NET2-SEND-010,
REQ-NET2-SEND-011

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

**Requirement:** If `radcli_avp_encode_rfc2865()` returns a negative
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

### REQ-NET2-ERR-012 — a double-send or NULL-request send/perform is RADCLI_ERROR, not undefined behavior

**Requirement:** See REQ-NET2-SEND-011; restated here as the ERR-category
contract: `radcli_request_perform(NULL)`/`radcli_request_send_noreply(NULL)`,
a second call to either function on the same request, and a
`radcli_request_perform()` call after a prior `radcli_request_send_noreply()`
on the same request (or vice versa) MUST all return `RADCLI_ERROR`
deterministically, never crash or resend.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/request.c:236 (`radcli_request_perform()`), lib/request.c:267
(`radcli_request_send_noreply()`)
**Acceptance:** [ERR] unit, local — same tests as REQ-NET2-SEND-011's
acceptance criteria; listed separately here because it is also the
NULL-safety/no-UB contract `REQ-GEN-MEM-002`-style requirements care about.
**Links:** REQ-NET2-SEND-011, REQ-NET2-SEND-012, REQ-GEN-MEM-002
