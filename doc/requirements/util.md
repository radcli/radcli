---
title: shared low-level utilities requirements
generator: requirements-from-implementation
id-prefix: REQ-UTIL
categories:
  DATA: buffer/string/data-format correctness
  ERR: error reporting and propagation
  SEC: security-relevant primitive guarantees (crypto, constant-time comparison)
sources:
  - lib/util.c
  - lib/util.h
  - lib/ip_util.c
  - lib/log.c
  - lib/rc-crypto.c
  - lib/rc-crypto.h
  - include/radcli/radcli.h
  - lib/radcli.map.in
---

# Shared Low-Level Utilities Requirements

This document covers radcli's shared, low-level building blocks: the bounded
packet-buffer API (`pkt_buf` in `lib/util.h`), the `rc_strlcpy` bounded-string
polyfill, IP address / hostname resolution helpers (`lib/ip_util.c`), the
`rc_log`/`DEBUG` logging macros and `struct rc_conf`'s per-handle `debug`
field (`lib/util.h`, `lib/includes.h`), and the
MD5/HMAC-MD5/SHA-256 primitives (`lib/rc-crypto.c`, backed unconditionally by
nettle per `REQ-GEN-TECH-006`) that `lib/sendserver.c` uses to compute the RADIUS
Response Authenticator (RFC 2865 §3), encrypt `User-Password` (RFC 2865
§5.2), and compute/verify the Message-Authenticator attribute (RFC 2869
§5.14, RFC 3579 §3.2). These are implementation-level requirements that
justify `general.md`'s `REQ-GEN-MEM-004` (banned unsafe string functions /
`rc_strlcpy`) and `REQ-GEN-MEM-005` (`pkt_buf` bounds checking) — this
document should be read together with those two entries, not as a
restatement of them. `radcli_legacy_debug` (`lib/legacy/compat.c`), the
process-wide backing store for the deprecated `rc_setdebug()`, is the
accepted global documented at `REQ-GEN-SEC-005` and is not re-flagged here
except where its read/write contract matters for this document's own
requirements; the `debug` field it seeds is per-handle, not global.

Most symbols covered here are **internal helpers**, not part of the public
ABI — see the per-requirement `Status`/citation for which of `rc_getport`,
`rc_own_hostname`, `rc_get_srcaddr`, `rc_openlog`, `rc_setdebug`, `rc_mksid`
(the only symbols from these files listed in `lib/radcli.map.in`) apply.

---

## DATA — buffer, string, and data-format correctness

### REQ-UTIL-DATA-001 — `pb_init`/`pb_init_read` MUST establish immutable `head`/`end` bounds for the buffer's lifetime

**Requirement:** `pb_init()` MUST set `head == data == tail == buf` and
`end == buf + cap`; `pb_init_read()` MUST set `head == data == buf`,
`tail == buf + len`, and `end == buf + cap`. No other `pkt_buf` function MUST
modify `head` or `end` after initialization — they are the caller-supplied
hard capacity limit that every subsequent write/read helper checks against.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:123-136 (`pb_init`, `pb_init_read`)
**Acceptance:** [DATA] unit, local — after `pb_init(&pb, buf, cap)`,
`pb.end - pb.head == cap` and `pb_tailroom(&pb) == cap`; no function in
`lib/util.h` besides these two writes `pb->head` or `pb->end`.
**Links:** REQ-GEN-MEM-005

### REQ-UTIL-DATA-002 — `pb_put_byte` MUST return -1 rather than write past `pb->end`

**Requirement:** `pb_put_byte()` MUST check `pb->tail >= pb->end` before
writing and return `-1` without modifying `*pb->tail` or advancing `tail`
when the buffer is full; on success it MUST write `v` at `tail` and advance
`tail` by exactly one byte.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:151-156
**Acceptance:** [DATA] unit, local — calling `pb_put_byte()` on a `pkt_buf`
with `pb_tailroom() == 0` returns `-1` and leaves `tail`/buffer contents
unchanged.
**Links:** REQ-GEN-MEM-005

### REQ-UTIL-DATA-003 — `pb_put_bytes` MUST reject negative length and overflowing writes without partial writes

**Requirement:** `pb_put_bytes(pb, src, n)` MUST return `-1` without calling
`memcpy()` or advancing `tail` when `n < 0` or `pb->tail + n > pb->end`; only
when the full `n`-byte write fits MUST it `memcpy()` all `n` bytes and
advance `tail` by `n`. There MUST be no code path that copies a truncated
prefix of `src` on overflow.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:158-164
**Acceptance:** [DATA] unit, local — `pb_put_bytes(&pb, src, pb_tailroom(&pb)+1)`
returns `-1` and `pb.tail` is unchanged; `pb_put_bytes(&pb, src, -1)` returns
`-1`.
**Links:** REQ-GEN-MEM-005

### REQ-UTIL-DATA-004 — `pb_put_reserve` MUST return NULL on overflow instead of a pointer past `end`

**Requirement:** `pb_put_reserve(pb, n)` MUST return `NULL` without advancing
`tail` when `n < 0` or `pb->tail + n > pb->end`. On success (including
`n == 0`) it MUST return the pre-advance value of `tail` and advance `tail`
by `n`, leaving any reserved region's contents uninitialized (the caller is
responsible for filling it before the buffer is transmitted or read).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:166-174
**Acceptance:** [DATA] unit, local — `pb_put_reserve(&pb, pb_tailroom(&pb)+1)`
returns `NULL`; `pb_put_reserve(&pb, 0)` returns the current `tail` pointer
without advancing it, matching `pb_put_bytes(pb, src, 0)`'s no-op success
(REQ-UTIL-DATA-008).
**Links:** REQ-GEN-MEM-005, lib/sendserver.c (attribute-length placeholder
pattern at `attr_len_ptr`)

### REQ-UTIL-DATA-005 — `pb_pull` MUST NOT advance `data` past `tail`

**Requirement:** `pb_pull(pb, n)` MUST return `-1` without modifying `data`
when `n < 0` or `pb->data + n > pb->tail` (i.e. fewer than `n` unconsumed
bytes remain). On success it MUST advance `data` by exactly `n`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:179-184
**Acceptance:** [DATA] unit, local — `pb_pull(&pb, pb_len(&pb)+1)` returns
`-1` and `pb.data` is unchanged.
**Links:** REQ-GEN-MEM-005

### REQ-UTIL-DATA-006 — `pb_peek_byte` MUST bounds-check against `tail`, not `end`, and MUST NOT advance `data`

**Requirement:** `pb_peek_byte(pb, offset, out)` MUST return `-1` without
writing `*out` when `offset < 0` or `pb->data + offset >= pb->tail` — i.e.
peeking is bounded by the *written/received* extent (`tail`), not the full
buffer capacity (`end`), since bytes between `tail` and `end` are unwritten
tailroom, not valid data. `data` MUST NOT be modified by this call
regardless of success or failure.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:187-192
**Acceptance:** [DATA] unit, local — after `pb_init_read(&pb, buf, len, cap)`
with `cap > len`, `pb_peek_byte(&pb, len, &out)` (offset at old `tail`)
returns `-1`, and `pb_peek_byte(&pb, len - 1, &out)` (last valid byte)
succeeds.
**Links:** REQ-GEN-MEM-005, REQ-UTIL-DATA-001

### REQ-UTIL-DATA-007 — `pb_written`/`pb_len`/`pb_tailroom` MUST report exact pointer-difference invariants

**Requirement:** For any valid `pkt_buf` state (`head <= data <= tail <= end`),
`pb_written() == tail - head`, `pb_len() == tail - data`, and
`pb_tailroom() == end - tail` MUST hold, and MUST be side-effect-free
(read-only). Callers rely on these to size subsequent operations (e.g.
`lib/sendserver.c`'s `return (int)pb_written(&pb)` as the final packet
length).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:140-147; lib/sendserver.c:165 (`return (int)pb_written(&pb)`)
**Acceptance:** [DATA] unit, local — construct a `pkt_buf`, perform a mix of
`pb_put_byte`/`pb_put_bytes`/`pb_pull` calls, and assert the three measurement
functions against manually tracked pointer arithmetic after each step.
**Links:** REQ-GEN-MEM-005

### REQ-UTIL-DATA-008 — Zero-length writes MUST succeed as a no-op, consistently across `pb_put_bytes` and `pb_put_reserve`

**Requirement:** `pb_put_bytes(pb, src, 0)` MUST fall through to
`memcpy(pb->tail, src, 0)` and return `0` without advancing `tail` — a
well-defined no-op even when `src` is a non-dereferenced pointer.
`pb_put_reserve(pb, 0)` MUST match this: it returns the current `tail`
pointer without advancing it, rather than rejecting the call, so the two
sibling `pkt_buf` write primitives have identical zero-length semantics.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:158-164 (`pb_put_bytes`), 166-174 (`pb_put_reserve`)
**Acceptance:** [DATA] unit, local — `pb_put_bytes(&pb, src, 0)` and
`pb_put_reserve(&pb, 0)` both succeed without advancing `pb->tail`.
**Links:** REQ-UTIL-DATA-004

### REQ-UTIL-DATA-009 — `rc_strlcpy` MUST always NUL-terminate the destination (when `siz != 0`) and report `strlen(src)`

**Requirement:** `rc_strlcpy(dst, src, siz)` MUST copy at most `siz - 1`
bytes from `src` into `dst`, MUST NUL-terminate `dst` whenever `siz != 0`
(including on truncation), and MUST return `strlen(src)` regardless of
truncation, so callers can detect truncation via `return value >= siz`. When
`siz == 0`, `dst` MUST NOT be written at all.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.c:139-163 (`rc_strlcpy`, compiled only when
`RC_NEED_STRLCPY` is defined — i.e. no platform `strlcpy()`, or under
MemorySanitizer per lib/util.h:37-43)
**Acceptance:** [DATA] unit, local — `rc_strlcpy(buf, "toolong", 4)` copies
`"too"` + NUL into a 4-byte `buf` and returns `7` (`>= 4`, signaling
truncation); `rc_strlcpy(buf, "ok", 0)` does not write to `buf`.
**Links:** REQ-GEN-MEM-004

### REQ-UTIL-DATA-010 — `rc_strlcpy` MUST be selected in place of the platform `strlcpy` under MemorySanitizer even when the platform provides one

**Requirement:** The build MUST define `RC_NEED_STRLCPY` and `#define
strlcpy rc_strlcpy` whenever `HAVE_STRLCPY` is unset, **or** when compiling
under Clang's MemorySanitizer (`__has_feature(memory_sanitizer)`), because
glibc's `strlcpy()` has no MSan interceptor and would leave shadow bits
unset, producing false-negative (missed) or false-positive MSan reports in
code that consumes the copied buffer.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:37-43
**Acceptance:** [DATA] build-config check, local — building with
`-fsanitize=memory` defines `RC_NEED_STRLCPY` regardless of the platform's
`HAVE_STRLCPY` value; `nm`/`grep` confirms `rc_strlcpy` (not the libc symbol)
is linked into the MSan build.
**Links:** REQ-GEN-MEM-004

### REQ-UTIL-DATA-011 — `rc_bin2hex` MUST require a destination buffer of at least `2*len+1` bytes and always NUL-terminate

**Requirement:** `rc_bin2hex(dst, dst_size, src, len)` MUST assert
`dst_size >= 2 * len + 1` (asserts are never compiled out in this codebase —
`lib/util.h:14` `#undef NDEBUG`), encode each source byte as two uppercase
hex digits, and write a terminating NUL after the last digit, returning a
pointer to that NUL.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:196-207, lib/util.h:13-15 (`#undef NDEBUG` — asserts
stay compiled in for security-sensitive parsing code)
**Acceptance:** [DATA] unit, local — `rc_bin2hex(buf, 5, "\xAB\xCD", 2)`
writes `"ABCD\0"`; calling with `dst_size < 2*len+1` aborts via `assert()`
rather than overflowing `dst`.
**Links:** REQ-GEN-MEM-004

### REQ-UTIL-DATA-012 — `rc_str2tm` MUST reject an unrecognized month rather than leaving `tm` in a caller-dependent state

**Requirement:** `rc_str2tm(valstr, tm)` matches the first 3 characters of
`valstr` against a 12-entry month-name table to set `tm->tm_mon`. If no entry
matches, `rc_str2tm()` MUST return `-1` without modifying `tm`, rather than
silently proceeding with whatever value `tm->tm_mon` already held on entry.
On a match, it reads `tm->tm_mday` from `atoi(&valstr[4])` and `tm->tm_year`
from `atoi(&valstr[7]) - 1900` and returns `0`. `rc_str2tm()` is internal
(declared in `lib/util.h` only, not part of the public ABI), so this
`void`→`int` signature change has no ABI impact.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.c:43-67 (`rc_str2tm`); lib/avpair.c:796-809
(`rc_avpair_parse`'s `PW_TYPE_DATE` case, checks the return value and
fails the parse on `-1`)
**Acceptance:** [DATA] unit, local — `rc_str2tm("Jan 01 2024", &tm)` returns
`0` and sets `tm.tm_mon==0, tm.tm_mday==1, tm.tm_year==124`;
`rc_str2tm("Xxx 01 2024", &tm)` returns `-1` and leaves `tm` untouched;
`rc_avpair_parse()` on a PW_TYPE_DATE attribute with an unrecognized month
token now fails with "invalid date" instead of silently producing today's
month.
**Links:** REQ-DICT-* (date-attribute formatting, if/when `dict.md` covers
`PW_TYPE_DATE` parsing)

### REQ-UTIL-DATA-013 — `rc_getaddrinfo` MUST select the DGRAM socket type and MUST map `PW_AI_*` flags to `getaddrinfo()` hints/service names

**Requirement:** `rc_getaddrinfo(host, flags)` MUST set
`hints.ai_socktype = SOCK_DGRAM`, MUST set `AI_PASSIVE` in `hints.ai_flags`
only when `PW_AI_PASSIVE` is set, and MUST select the `getaddrinfo()`
`service` argument as `"radius"` when `PW_AI_AUTH` is set or `"radius-acct"`
when `PW_AI_ACCT` is set (neither set → `service == NULL`, resolving the
host with no service-based port lookup). On `getaddrinfo()` failure it MUST
return `NULL`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/ip_util.c:28-50; lib/util.h:67-70 (`PW_AI_PASSIVE`,
`PW_AI_AUTH`, `PW_AI_ACCT`)
**Acceptance:** [DATA] unit, local — `rc_getaddrinfo("badname.invalid.", PW_AI_AUTH)`
returns `NULL`; a mock/stub `getaddrinfo()` confirms `service == "radius"`
for `PW_AI_AUTH` and `"radius-acct"` for `PW_AI_ACCT`.
**Links:** REQ-CONFIG-* (server resolution, see `config.md`)

**Note:** `rc_getaddrinfo` and `rc_own_bind_addr` are declared in
`lib/util.h`, not `include/radcli/radcli.h`, and are absent from
`lib/radcli.map.in` — internal helpers only, not public ABI.

### REQ-UTIL-DATA-014 — `rc_own_bind_addr` MUST prefer a pre-resolved bind address over re-resolving `bindaddr` on every call

**Requirement:** `rc_own_bind_addr(rh, lia)` MUST return
`rh->own_bind_addr` via `memcpy()` (sized by `SS_LEN`) without calling
`rc_getaddrinfo()` when `rh->own_bind_addr_set` is true. Only when unset
MUST it resolve the `"bindaddr"` config value: `NULL` or a value starting
with `'*'` maps to `AF_INET`/`INADDR_ANY`; otherwise it resolves via
`rc_getaddrinfo(txtaddr, PW_AI_PASSIVE)`, falling back to
`AF_INET`/`INADDR_ANY` and logging an error if resolution fails.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/ip_util.c:165-193
**Acceptance:** [DATA] unit, local — with `rh->own_bind_addr_set = 1`, no
`getaddrinfo()` call occurs and `lia` equals the stored address; with
`bindaddr` unset, `lia` is `INADDR_ANY`.
**Links:** REQ-CONFIG-*, REQ-NET-* (bind-address use in `sendserver.c`/`tls.c`)

### REQ-UTIL-DATA-015 — `rc_own_hostname` MUST use `rc_strlcpy`/`strlcpy` (never `strcpy`) to copy the resolved hostname into the caller's buffer

**Requirement:** The `HAVE_UNAME` code path of `rc_own_hostname(hostname, len)`
MUST copy `uts.nodename` into `hostname` via `strlcpy(hostname, uts.nodename, len)`
(resolved to `rc_strlcpy` when the platform lacks `strlcpy`, per
REQ-UTIL-DATA-010), bounding the copy to the caller-supplied `len`. It MUST
NOT use `strcpy()`.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/ip_util.c:81-111
**Acceptance:** [DATA] negative, local — `grep -n 'strcpy(' lib/ip_util.c`
returns no matches; a `uts.nodename` longer than the caller's `hostname`
buffer does not overflow it (truncates per REQ-UTIL-DATA-009).
**Links:** REQ-GEN-MEM-004

---

## ERR — error reporting and propagation

### REQ-UTIL-ERR-001 — Every `pkt_buf` write/read helper MUST signal failure via a distinguishable sentinel, never via silent truncation

**Requirement:** `pb_put_byte`, `pb_put_bytes`, `pb_pull` MUST return `-1` on
failure (`pb_put_reserve` MUST return `NULL`); `pb_peek_byte` MUST return
`-1` on failure and MUST NOT write `*out` in that case. None of these MUST
partially perform the requested operation before detecting the failure (see
REQ-UTIL-DATA-002 through -006) — the caller can treat any of these sentinel
values as "the whole operation did not happen."
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:151-192
**Acceptance:** [ERR] code-review — every call site in `lib/sendserver.c`
that invokes a `pb_*` function checks its return value before continuing
(cross-check against `REQ-GEN-MEM-005`'s "-1 MUST be propagated" clause).
**Links:** REQ-GEN-MEM-005

### REQ-UTIL-ERR-002 — `rc_getaddrinfo`/`rc_own_hostname`/`rc_get_srcaddr`/`rc_set_netns`/`rc_reset_netns` MUST log via `rc_log(LOG_ERR, ...)` before returning an error code, and MUST NOT include secret material in that log

**Requirement:** Each of these functions MUST call `rc_log(LOG_ERR, ...)`
(or, for `rc_getaddrinfo`, silently return `NULL` — see REQ-UTIL-ERR-003
[REVIEW]) describing the specific system call that failed
(`getaddrinfo`/`uname`/`gethostname`/`socket`/`connect`/`getsockname`/`open`/
`setns`/`close`) and its `errno`, before returning its failure sentinel
(`NULL`, `-1`, or `ERROR_RC`/`NETUNREACH_RC`). None of these functions handle
secret material, so REQ-GEN-SEC-006 does not constrain them further, but the
pattern they establish (log-then-return, no partial success state) is the
one `net.md`'s secret-handling code must deviate from carefully.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/ip_util.c:90-152 (rc_own_hostname, rc_get_srcaddr);
lib/util.c:184-222 (rc_set_netns), lib/util.c:238-252 (rc_reset_netns)
**Acceptance:** [ERR] code-review — each failure return path in the cited
functions has a preceding `rc_log(LOG_ERR, ...)` call except `rc_getaddrinfo`
(REQ-UTIL-ERR-003).
**Links:** REQ-GEN-SEC-006

### REQ-UTIL-ERR-003 — `rc_getaddrinfo` MUST log the `getaddrinfo()` error on failure

**Requirement:** Like its sibling functions in `lib/ip_util.c`
(`rc_own_hostname()`, `rc_get_srcaddr()`, `rc_own_ipaddress()`),
`rc_getaddrinfo()` MUST call `rc_log(LOG_ERR, ...)` with the host and
`gai_strerror()`-formatted reason before returning `NULL` on `getaddrinfo()`
failure, instead of silently dropping the error code.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/ip_util.c:28-51 (`rc_log(LOG_ERR, "rc_getaddrinfo: %s: %s", host, gai_strerror(err))`)
**Acceptance:** [ERR] code-review — `rc_getaddrinfo()` matches the logging
convention of its siblings in the same file.

### REQ-UTIL-ERR-004 — `DEBUG()` MUST be a complete no-op (no argument evaluation side effects beyond the guard) when the handle's `debug` field is zero

**Requirement:** The `DEBUG(rh, args...)` macro MUST expand to
`if((rh)->debug) rc_log(args)`, so that when `rh->debug == 0` the
`rc_log()`/`syslog()` call — and therefore any `snprintf`-style formatting
work implied by its arguments — MUST NOT execute. Call sites MUST NOT rely on
side effects inside `DEBUG()`'s arguments, since they are skipped whenever
debug logging is disabled (the common case in production).
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h (`#define DEBUG(rh, args...) if((rh)->debug) rc_log(args)`);
lib/includes.h (`struct rc_conf`'s `debug` field, default 0 via `calloc`)
**Acceptance:** [ERR] code-review — no `DEBUG(...)` call site in `lib/*.c`
contains an argument expression with an assignment or function call whose
result is depended on elsewhere.
**Links:** REQ-GEN-SEC-005 (per-handle `debug` field; `radcli_legacy_debug`
in `lib/legacy/compat.c` is the accepted legacy-shim-only global-state
exception)

---

## SEC — security-relevant primitive guarantees

### REQ-UTIL-SEC-001 — `rc_md5_calc` MUST compute the standard MD5 digest via nettle

**Requirement:** `rc_md5_calc(output, input, inputlen)` MUST compute the
standard MD5 digest (RFC 1321) of `input` into a 16-byte `output`, via
nettle's `md5_init`/`md5_update`/`md5_digest` (with the digest-length
argument present or absent per `HAVE_DIGEST_LENGTH_ARG`) -- the only
implementation in the tree since `REQ-GEN-TECH-006` made nettle mandatory
and retired the bundled fallback this requirement used to hold equivalent
to it. Callers computing the RADIUS Response Authenticator
(`lib/sendserver.c:281`) and encrypting `User-Password` (`lib/sendserver.c:119`)
depend on this being a correct RFC 1321 implementation to interoperate with
any RFC 2865-compliant server.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/rc-crypto.c (`rc_md5_calc`); lib/rc-crypto.h;
meson.build (mandatory `nettle_dep`, `HAVE_DIGEST_LENGTH_ARG` detection)
**Acceptance:** [SEC] unit, CI — a known-answer test (RFC 1321 test vectors,
e.g. MD5("") == d41d8cd98f00b204e9800998ecf8427e) run against `rc_md5_calc()`.
**Links:** REQ-GEN-TECH-001, REQ-GEN-TECH-006, REQ-NET-* (Response
Authenticator / User-Password encryption in `net.md`, when written)

### REQ-UTIL-SEC-002 — `rc_hmac_md5` MUST compute HMAC-MD5 via nettle

**Requirement:** `rc_hmac_md5(data, data_len, key, key_len, digest)` MUST
compute HMAC-MD5 (RFC 2104) into a 16-byte `digest`, via nettle's
`hmac_md5_set_key`/`hmac_md5_update`/`hmac_md5_digest` -- the only
implementation in the tree (`REQ-GEN-TECH-006`). `lib/sendserver.c`'s
`add_msg_auth_attr()` and `validate_message_authenticator()` depend on this
being a correct RFC 2104 implementation: a Message-Authenticator radcli
computes MUST verify successfully against any other RFC 2869 §5.14-compliant
implementation, and vice versa.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/rc-crypto.c (`rc_hmac_md5`); lib/rc-crypto.h;
lib/sendserver.c:340 (`add_msg_auth_attr`), lib/sendserver.c:402
(`validate_message_authenticator`)
**Acceptance:** [SEC] unit, CI — an HMAC-MD5 known-answer test (RFC 2104 test
vectors) run against `rc_hmac_md5()`.
**Links:** REQ-GEN-TECH-001, REQ-GEN-TECH-006, REQ-UTIL-SEC-001, REQ-NET-*
(Message-Authenticator compute/verify in `net.md`, when written),
REQ-GEN-TEST-003 (negative tests mandatory for Message-Authenticator handling)

### REQ-UTIL-SEC-003 — HMAC key lengths over 64 bytes MUST be pre-hashed to 16 bytes before padding

**Requirement:** RFC 2104 §2 requires that a key longer than the hash's
block size (64 bytes for MD5) be replaced with its own hash before
constructing the ipad/opad. `rc_hmac_md5()` relies on nettle's
`hmac_md5_set_key()` to implement this internally; radcli does not
re-implement the check itself (in practice the RADIUS shared secret, capped
at `MAX_SECRET_LENGTH`, is unlikely to exceed 64 bytes, but the primitive's
correctness does not depend on that being true).
**Strength:** MUST
**Status:** DERIVED
**Source:** nettle's `hmac_md5_set_key()`, called from lib/rc-crypto.c's
`rc_hmac_md5()`
**Acceptance:** [SEC] unit, local — `rc_hmac_md5()` with a 100-byte key
produces the same digest as `rc_hmac_md5()` with that key pre-hashed to 16
bytes via `rc_md5_calc()` and passed directly (i.e. the internal pre-hash
step is externally observable and testable).
**Links:** REQ-UTIL-SEC-002

### REQ-UTIL-SEC-004 — `rc_memcmp` MUST use a constant-time comparison when GnuTLS is available, and callers verifying digests/secrets MUST use it instead of `memcmp`

**Requirement:** `rc_memcmp(s1, s2, n)` MUST call `gnutls_memcmp()` when
`HAVE_GNUTLS` is defined, and MUST fall back to plain `memcmp()` only when
GnuTLS is unavailable (a build configuration with no constant-time-compare
primitive on hand). Code comparing RADIUS Response Authenticator digests or
Message-Authenticator digests against attacker-influenced network input
(`lib/sendserver.c:283` `rc_check_reply`, `lib/sendserver.c:404`
`validate_message_authenticator`) MUST call `rc_memcmp`, never `memcmp`
directly, per `REQ-GEN-SEC-006`'s ban on data-dependent-timing comparisons
of secret-derived values.
**Strength:** MUST
**Status:** DERIVED
**Source:** lib/util.h:28-35 (`rc_memcmp`); lib/sendserver.c:283, :404
(call sites)
**Acceptance:** [SEC] negative, local — `grep -n 'memcmp(' lib/sendserver.c`
shows only `rc_memcmp` at the two digest-verification sites, no bare
`memcmp`; code-review flags any new digest/secret comparison using
`memcmp`/`strcmp` directly.
**Links:** REQ-GEN-SEC-006

### REQ-UTIL-SEC-005 — WITHDRAWN — the bundled MD5/HMAC implementation MUST NOT be reachable when nettle is available

**Status:** WITHDRAWN — moot since `REQ-GEN-TECH-006` (2026-08-31) removed
the bundled fallback (`lib/md5.c`, `lib/hmac.c`) entirely and made nettle a
mandatory dependency: there is only one MD5/HMAC-MD5 implementation
(`lib/rc-crypto.c`) left to select between. This ID is retained per this
document's "never renumber" convention; do not reuse it.
**Links:** REQ-GEN-TECH-006

### REQ-UTIL-SEC-006 — `rc_get_random_bytes()`'s entropy source is not part of this document's scope but its consumers (`rc_md5_calc`/`rc_hmac_md5`) MUST treat the vector as opaque input [UNDOCUMENTED cross-reference]

**Requirement:** N/A — boundary note: `rc_get_random_bytes()`
(`lib/rc-random.c`, using `gnutls_rnd()`/`getentropy()`) generates the
Request Authenticator that `rc_md5_calc`/`rc_hmac_md5` consume, but the
function lives in and is covered by `lib/rc-random.c` / `net.md`, not
`lib/util.c`/`util.h`. Listed here so a completeness sweep of `util.md` does
not mistake its absence for a gap.
**Strength:** n/a
**Status:** DERIVED
**Source:** lib/rc-random.c
**Acceptance:** n/a (cross-reference only)
**Links:** REQ-NET-* (entropy source for Request Authenticator, `net.md`
when written)

---

## Phase 5 — Completeness and Gap Analysis

**Coverage check against Phase 1 enumeration:**

| Symbol | File | Public (map.in)? | Covered by |
|---|---|---|---|
| `pb_init`, `pb_init_read` | util.h | no (inline, internal) | REQ-UTIL-DATA-001 |
| `pb_written`, `pb_len`, `pb_tailroom` | util.h | no | REQ-UTIL-DATA-007 |
| `pb_put_byte` | util.h | no | REQ-UTIL-DATA-002, REQ-UTIL-ERR-001 |
| `pb_put_bytes` | util.h | no | REQ-UTIL-DATA-003, REQ-UTIL-DATA-008, REQ-UTIL-ERR-001 |
| `pb_put_reserve` | util.h | no | REQ-UTIL-DATA-004, REQ-UTIL-DATA-008, REQ-UTIL-ERR-001 |
| `pb_pull` | util.h | no | REQ-UTIL-DATA-005, REQ-UTIL-ERR-001 |
| `pb_peek_byte` | util.h | no | REQ-UTIL-DATA-006, REQ-UTIL-ERR-001 |
| `rc_bin2hex` | util.h | no | REQ-UTIL-DATA-011 |
| `rc_memcmp` | util.h | no | REQ-UTIL-SEC-004 |
| `rc_strlcpy` | util.h/util.c | no (internal polyfill; `strlcpy(3)` is the public-facing name via `#define`) | REQ-UTIL-DATA-009, REQ-UTIL-DATA-010 |
| `struct rc_conf.debug` | includes.h | no (per-handle field, not global) | REQ-UTIL-ERR-004 |
| `DEBUG` macro | util.h | n/a (macro) | REQ-UTIL-ERR-004 |
| `rc_log` macro | util.h | n/a (macro) | REQ-UTIL-ERR-002, REQ-UTIL-ERR-004 |
| `rc_str2tm` | util.c/util.h | no | REQ-UTIL-DATA-012 |
| `rc_getmtime` | util.c/util.h | no | [UNDOCUMENTED] — see below |
| `rc_mksid` | lib/legacy/compat.c | **yes** (radcli.map.in:69) | see below |
| `rc_set_netns` | util.c/util.h | no | REQ-UTIL-ERR-002 |
| `rc_reset_netns` | util.c/util.h | no | REQ-UTIL-ERR-002 |
| `rc_getaddrinfo` | ip_util.c/util.h | no | REQ-UTIL-DATA-013, REQ-UTIL-ERR-003 |
| `rc_getport` | ip_util.c | **yes** (radcli.map.in:58) | [UNDOCUMENTED] — see below |
| `rc_own_hostname` | ip_util.c | **yes** (radcli.map.in:59) | REQ-UTIL-DATA-015, REQ-UTIL-ERR-002 |
| `rc_get_srcaddr` | ip_util.c | **yes** (radcli.map.in:60) | REQ-UTIL-ERR-002 |
| `rc_own_bind_addr` | ip_util.c/util.h | no | REQ-UTIL-DATA-014 |
| `rc_setdebug` | legacy/compat.c | **yes** (radcli.map.in:63) | REQ-UTIL-ERR-004 (via `radcli_legacy_debug`, pre-seeds `struct rc_conf.debug` on handle construction) |
| `rc_openlog` | log.c | **yes** (radcli.map.in:61) | [UNDOCUMENTED] — see below |
| `rc_md5_calc` | rc-crypto.c | **yes** (radcli2.map.in:152) | REQ-UTIL-SEC-001 |
| `rc_hmac_md5` | rc-crypto.c | no | REQ-UTIL-SEC-002, REQ-UTIL-SEC-003 |
| `rc_sha256_calc` | rc-crypto.c | no | REQ-DAE-SEC-005 (dae.md; dedup key, not an util.md-owned use) |

**Gaps flagged:**

- **`rc_getport(type)`** [UNDOCUMENTED]: public ABI symbol
  (`lib/radcli.map.in:58`, declared `lib/ip_util.c:63-73`) with no dedicated
  requirement above. Behavior: looks up `"radius"`/`"radacct"` via
  `getservbyname(..., "udp")`, falling back to the compiled-in defaults
  `PW_AUTH_UDP_PORT`/`PW_ACCT_UDP_PORT` when no `/etc/services` entry exists.
  This is straightforward and low-risk, but as a public symbol it should get
  a requirement in a future revision of this document (not added here to
  avoid inflating coverage with a rubber-stamped entry written after the
  fact — flagging instead per Phase 5's intent).
- **`rc_mksid()`**: public ABI symbol (`lib/radcli.map.in:69`)
  marked `@deprecated` in its own Doxygen comment (`lib/legacy/compat.c`) —
  returns a pointer to a `static`, non-reentrant buffer overwritten on each
  call. Accepted as a documented exception to `general.md`'s
  `REQ-GEN-SEC-005`, alongside `_initialized` (and, in the optional legacy
  shim, `radcli_legacy_debug`): the
  non-reentrancy hazard is an accepted, documented property of a deprecated
  function. No dedicated `REQ-UTIL-*` requirement was written for it beyond
  this note, since its only normative content ("do not call concurrently, do
  not rely on the returned pointer surviving a subsequent call") is already
  captured by `general.md`'s enumeration.
- **`rc_openlog(ident)`** [UNDOCUMENTED]: public ABI symbol
  (`lib/radcli.map.in:61`, `lib/log.c:54-59`) with no dedicated requirement
  above — a thin `openlog(3)` wrapper (no-op under `_MSC_VER`). Low risk,
  flagged for the same reason as `rc_getport`.
- **`rc_getmtime()`**: internal-only (not in map.in), single-purpose
  monotonic-time wrapper (`lib/util.c:69-86`) used for interval/timeout
  arithmetic elsewhere in `lib/`. No dedicated requirement was written
  because its only essential behavior — "returns a monotonically
  non-decreasing double, or -1 on failure" — is fully captured by its
  `clock_gettime(CLOCK_MONOTONIC, ...)`/`gettimeofday()` fallback structure
  and has no bounds/security implications; flagged here rather than silently
  omitted so Phase 5 coverage is explicit. `[UNDOCUMENTED]`.

**Cross-cutting checks:**

- Thread safety: none of `pb_*`, `rc_strlcpy`, `rc_bin2hex`, `rc_memcmp`,
  `rc_md5_calc`, `rc_hmac_md5` touch shared/global state — each operates
  purely on caller-supplied buffers/contexts, consistent with
  `REQ-GEN-SEC-005`. `rc_mksid` is the one accepted exception in this file
  (radcli2 core), flagged above. `DEBUG()` itself now reads a per-handle
  `struct rc_conf.debug` field, not a global, so two `rc_handle`/`radcli_ctx`
  instances no longer interfere. The legacy-only `rc_setdebug()`
  (`lib/legacy/compat.c`) still writes a process-wide
  `radcli_legacy_debug`, accepted per `REQ-GEN-SEC-005` as a legacy-shim-only
  exception; concurrent
  `rc_setdebug()` calls from multiple threads race on a plain `unsigned int`
  write with no synchronization, but since it only gates a diagnostic log
  statement (no correctness impact per REQ-GEN-SEC-005's own framing), this
  is not flagged as a new issue.
- Process-state neutrality sweep (per `README.md`'s Completeness section):
  `grep -n 'signal(\|sigaction(\|fork(\|pthread_create(\|alarm(\|setitimer(\|setlocale(\|umask(\|chdir(\|setenv('`
  over `lib/util.c`, `lib/ip_util.c`, `lib/log.c`, `lib/rc-crypto.c` returns
  no matches — consistent with
  `REQ-GEN-SEC-001` through `REQ-GEN-SEC-004`. `lib/util.c`'s `rc_set_netns`/
  `rc_reset_netns` call Linux `setns()`, which is not in that grep list;
  `setns()` changes the calling *thread's* (not the whole process's) network
  namespace and is explicitly a caller-requested, synchronous operation (not
  ambient-state mutation radcli initiates on its own), so it is judged
  consistent with `REQ-GEN-SEC-004`'s intent rather than a violation — noted
  here rather than silently passed over.
