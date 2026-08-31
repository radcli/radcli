# radcli Requirements

This directory contains structured, testable requirements derived from the radcli
implementation (`lib/`, `include/radcli/radcli.h`) and from the library-design
policy in `AGENTS.md` and `contrib/ai/personas/radcli-core-dev.md`. It complements
the prose in `AGENTS.md`'s "Architecture" section:

- **`AGENTS.md` "Architecture"** — narrative description of *how* radcli works
  (request flow, key data structures, transport abstraction, dictionary loading).
- **`doc/requirements/`** — normative description of *what must hold*, in atomic,
  testable statements with RFC 2119 keywords, source citations, and acceptance
  criteria.

Each requirement cites the source file/line it was derived from. When code and a
requirement disagree, treat it as a `[REVIEW]` item, not as an automatic override
— resolve by reading the cited source and, if still unclear, ask a maintainer.

## Why radcli's layout differs from a multi-process application's

radcli is a single library linked into a caller's process — it has no worker/main/
IPC split and does not reconcile against an externally-specified wire protocol
implementation (its own RFC 2865/2866/6614 framing is derived straight from
`lib/sendserver.c`/`lib/tls.c`/`lib/buildreq.c`, not reconciled against a second,
independent client). Its most safety-critical cross-cutting requirements are
therefore **generic library-design invariants** — it must never take unilateral
ownership of process-wide state the embedding application may also depend on
(signals, `fork()`, threads, timers, locale/cwd/env, globals) — plus ABI stability
of its exported symbol set. `general.md` makes these explicit and testable instead
of leaving them as persona-only prose.

## Generation protocols

These documents are generated and maintained using the reasoning protocols in
`contrib/ai/protocols/`:

| Document | Protocol | Produces |
|----------|----------|----------|
| `general.md` | `requirements-elicitation.md` | Library-invariant / cross-cutting requirements derived from `AGENTS.md` and `contrib/ai/personas/radcli-core-dev.md`'s Design Review checklists: process-state neutrality, ABI stability, memory/string safety, canonical technology choices. |
| `config.md`, `dict.md`, `attrs.md`, `net.md`, `util.md`, `avp2.md`, `net2.md`, `config2.md`, `dict2.md` | `requirements-from-implementation.md` | Requirements derived from the current `lib/`/`include/radcli/radcli.h` source: what each public function and data structure actually guarantees. |
| `dae.md` | `requirements-elicitation.md` | Requirements written ahead of implementation, from RFC 5176. Construction, the request-validation/reply pipeline, the session-selector accessors, the L0 buffer entry point, and the RadSec transport are now all implemented and tested, and every requirement in the document carries `DERIVED`. |
| `watchdog.md` | `requirements-elicitation.md` | Requirements for the RFC 5997/3539 connection-liveness watchdog on a RadSec session: `watchdog-interval` validation, `radcli_ctx_send_watchdog()`, `radcli_ctx_get_poll()`'s watchdog-deadline advisory, and `rc_check_tls()`'s opt-in wrapper. Split out of `config.md`/`dae.md`/`net.md` on 2026-08-30 to gather this cross-cutting concern into one place; every requirement carries `DERIVED`. |

When adding to or updating a document, re-apply the protocol that generated it —
do not hand-write requirements in a different style than the rest of the file.

## Document map

| Document | ID prefix | Sources |
|----------|-----------|---------|
| `general.md` | `REQ-GEN` | `AGENTS.md`, `contrib/ai/personas/radcli-core-dev.md`, `lib/radcli.map`, `devel/ABI-x86_64.dump` |
| `config.md` | `REQ-CONFIG` | `lib/config.c`, `include/radcli/radcli.h` (`rc_read_config`, `rc_apply_config`, `rc_conf_*`) |
| `dict.md` | `REQ-DICT` | `lib/legacy/dict.c`, `lib/legacy/compat.c`, `lib/dict2.c`, `lib/dict2-parse.c` (shared parser/lookup substrate, cited not owned by any `radcli2.h`-only document), `lib/dict_rfc_gen.h`, `lib/gen-dict.awk`, `include/radcli/radcli.h` (`rc_read_dictionary`, `rc_dict_*`) — the legacy `rc_*` dictionary API |
| `attrs.md` | `REQ-ATTR` | `lib/avpair.c`, `lib/buildreq.c`, `lib/aaa_ctx.c`, `include/radcli/radcli.h` (`VALUE_PAIR`, `rc_avpair_*`, `rc_auth`, `rc_acct`, `rc_aaa`, `rc_aaa_ctx_*`) |
| `net.md` | `REQ-NET` | `lib/sendserver.c`, `lib/tls.c`, `lib/tls.h`, `include/radcli/radcli.h` (`rc_send_server`, `SEND_DATA`, `rc_sockets_override`, `rc_check_tls`) |
| `util.md` | `REQ-UTIL` | `lib/util.c`, `lib/util.h` (`pkt_buf`), `lib/ip_util.c`, `lib/log.c`, `lib/rc-crypto.c` |
| `avp2.md` | `REQ-AVP2` | `lib/avp.c`, `lib/avp.h` (`radcli_avp_decode`/`radcli_avp_encode`, internal wire codec), `include/radcli/radcli2.h` (`radcli_avp_list`, `radcli_avp_add_*`, `radcli_avp_get`, `radcli_avp_iter`/`radcli_avp_list_iter`/`radcli_avp_iter_next`) |
| `net2.md` | `REQ-NET2` | `lib/request.c`, `lib/aaa2.c`, `include/radcli/radcli2.h` (`radcli_request_new`, `radcli_request_perform`, `radcli_request_code`, `radcli_request_attrs`, `radcli_request_server`, `radcli_request_free`, `radcli_aaa`), `lib/sendserver.c` (`radcli_transport_exchange`, cited not owned) |
| `config2.md` | `REQ-CONFIG2` | `lib/config2.c` (`radcli_ctx_new`, `radcli_ctx_read_config`, `radcli_ctx_free`, `radcli_ctx_set_opt_str`, `radcli_ctx_set_opt_int`, `radcli_ctx_apply`, `radcli_ctx_read_dictionary`, `radcli_ctx_set_secret`, `radcli_ctx_set_tls_psk`), `include/radcli/radcli2.h`, `include/radcli/radcli-defs.h`, `include/includes.h`, `lib/tls.c` (cited not owned) |
| `dict2.md` | `REQ-DICT2` | `lib/dict2.c` (`radcli_dict_lookup`, `radcli_dict_lookup_oid`, `radcli_dict_lookup_num`, `radcli_dict_lookup_value`, `radcli_attr_def_name`, `radcli_attr_def_type`, `radcli_attr_def_oid`), `lib/dict2-parse.c` (the `integer64`/`ifid` `ATTRIBUTE` type tokens, unreachable through the legacy API), `include/radcli/radcli2.h` — the `radcli2.h` dictionary-lookup API |
| `dae.md` | `REQ-DAE` | RFC 5176; `include/radcli/radcli2.h`; `lib/dae.c`; `tests/dae.c`; `tests/dae-codec.c`; `src/raddaeserver.c`; `tests/dae-client.py`; `tests/dae-tests.sh` |
| `watchdog.md` | `REQ-WATCHDOG` | RFC 5997; RFC 3539 §3.4; draft-ietf-radext-reverse-coa-08 §4.2; `lib/config.c`, `lib/dae.c` (`radcli_ctx_send_watchdog()`, `radcli_ctx_get_poll()`), `lib/tls.c` (`rc_check_tls()`); `tests/dae-radsec-watchdog.c`; `tests/watchdog-aaa.c` |

Every public symbol in `include/radcli/radcli.h` and `lib/radcli.map` MUST be cited
by at least one `REQ-*` across these documents (see "Completeness" below).

## ID scheme

```
REQ-<PREFIX><CATEGORY>-<NNN>
```

- `<PREFIX>` identifies the document (table above).
- `<CATEGORY>`:
  - `general.md` uses: `SEC` (security/privilege invariants, including
    process-state neutrality), `ABI` (public symbol/ABI stability), `MEM`
    (allocator and string/buffer safety rules), `TECH` (canonical technology
    choices), `STYLE`, `TEST`.
  - `config.md`, `dict.md`, `attrs.md`, `net.md`, `util.md` use the tags from
    `requirements-from-implementation.md`'s Phase 4 grouping: `INIT`, `CFG`,
    `NET`, `SEC`, `ERR`, `DATA`, `TEARDOWN` — whichever subset applies to that
    document's source files.
- `<NNN>` is a 3-digit sequence number, unique within `<PREFIX><CATEGORY>` and
  never reused (if a requirement is removed, mark it `WITHDRAWN`, do not
  renumber).

Examples: `REQ-GEN-SEC-001`, `REQ-NET-ERR-003`, `REQ-ATTR-DATA-012`,
`REQ-CONFIG-CFG-004`.

## Status legend

Every requirement carries a `Status`:

| Status | Meaning |
|--------|---------|
| `DERIVED` | Directly supported by current code/policy; no open questions. |
| `REVIEW` | Behavior observed but contradicts documentation, another requirement, or looks like a possible defect — needs a maintainer decision. |
| `AMBIGUOUS` | Cannot be classified as essential/incidental without domain knowledge; two interpretations given. |
| `UNDOCUMENTED` | Behavior exists in code with no doc, test, or evident purpose. |
| `WITHDRAWN` | Previously published requirement no longer applies; kept for ID stability, with a note explaining why. |

## Per-requirement format

```markdown
### REQ-<PREFIX><CAT>-<NNN> — <short title>

**Requirement:** <library/function> MUST/SHOULD/MAY <behavior> when
<condition>, so that <rationale>.
**Strength:** MUST | SHOULD | MAY | MUST NOT | SHOULD NOT
**Status:** DERIVED | REVIEW | AMBIGUOUS | UNDOCUMENTED | WITHDRAWN
**Source:** <file>:<line> [, ...]
**Acceptance:** <test path or description> — positive|negative|unit ;
  local | CI (root/full stack, if applicable)
**Links:** <other REQ-IDs this depends on or relates to>
```

## Completeness

Applying `requirements-from-implementation.md` Phase 5 to this repository means:

- Every declaration in `include/radcli/radcli.h` and every versioned symbol in
  `lib/radcli.map` has at least one citing `REQ-*`.
- `general.md`'s `REQ-GEN-SEC-*` process-state-neutrality requirements are
  cross-checked against a `grep` sweep of `lib/*.c` for `signal(`, `sigaction(`,
  `fork(`, `pthread_create(`, `alarm(`, `setitimer(`, `setlocale(`, `umask(`,
  `chdir(`, `setenv(` — the requirement's negative claim ("radcli does not do
  X") must hold against the current source, not just be aspirational.
- ABI-affecting requirements (`REQ-GEN-ABI-*`) are checked against `ninja -C
  build compare-exported` and `ninja -C build abi-check`.

## Conventions carried over from `contrib/ai/protocols/`

- **Negative requirements are mandatory for `SEC`, `ABI`, and `MEM` categories**
  in `general.md` — write the MUST NOT before the MUST.
- **A change that adds process-wide state ownership (signal handlers, `fork()`,
  self-initiated threads, global timers) is never `[UNDOCUMENTED]` or
  incidental** — it is a `REQ-GEN-SEC` violation, always essential, per
  `contrib/ai/personas/radcli-core-dev.md`'s Process-state neutrality checklist.
- **ABI acceptance criteria must cite the exact symbol name(s)** and the
  `RADCLI_LIBMAJOR` version node in `lib/radcli.map`, not vague descriptions.
