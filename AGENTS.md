# AGENTS.md

This file provides guidance to AI Agents when working with code in this repository.

For maintainer-level work (bug investigation, code review, refactoring, design, release preparation,
or security triage), load the radcli-core-dev persona from
`contrib/ai/personas/radcli-core-dev.md` as a system prompt prefix.

For contributor-level work (preparing a patch, bug fix, or feature as an external contributor),
load the radcli-contributor persona from `contrib/ai/personas/radcli-contributor.md`.

## Project Overview

radcli is a C library for writing RADIUS clients, designed to enable RADIUS authentication and accounting in ~50 lines of C code. It was created for the openconnect VPN server (ocserv) and is source-compatible with freeradius-client and radiusclient-ng. It supports UDP, TCP, TLS (RFC 6614), and DTLS transports.

## Build System

Uses autotools (autoconf/automake/libtool).

```bash
# First time setup
./autogen.sh
./configure

# Build
make

# Install
make install

# Validate distribution tarball (runs abi-check + full test suite)
make distcheck
```

Required Fedora/RHEL dependencies:
```
dnf install -y autoconf libtool automake nettle-devel gnutls-devel gettext-devel libabigail doxygen doxy2man
```

Key `./configure` options:
- `--without-tls` — disable TLS/DTLS (GnuTLS dependency)
- `--enable-legacy-compat` — create symlinks for freeradius-client and radiusclient-ng ABI compatibility

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
make check

# Run a single test script manually (from the build directory)
cd tests && srcdir=../tests ../tests/tls-tests.sh

# Run the C unit tests (these do NOT require root or radiusd)
./tests/avpair
./tests/dict
./tests/dict-add   # only built when GnuTLS is enabled
```

Tests use Linux network namespaces (`tests/ns.sh`) to create isolated client/server namespaces with veth pairs. Tests skip (exit 77) when not run as root, or when `radiusd`/`freeradius` is absent. TLS tests (`tls-tests.sh`, `tls-idle-restart-tests.sh`, `close-notify-tests.sh`) also need port 2083 to be ready and only build/run when GnuTLS is enabled.

The full set of shell test scripts: `basic-tests.sh`, `ipv6-tests.sh`, `tls-tests.sh`, `tls-idle-restart-tests.sh`, `failover-tests.sh`, `tcp-tests.sh`, `eap-tests.sh`, `no-server-file-tests.sh`, `reject-tests.sh`, `skip-unknown-vsa.sh`, `namespace-tests.sh`, `radembedded-tests.sh`, `radembedded-dict-tests.sh`, `ipv6-non-temp-addr-tests.sh`, `msg-auth-tests.sh`, `close-notify-tests.sh`.

### ABI checks

```bash
make abi-check    # compare against saved ABI dump
make abi-dump     # update the reference ABI dump (devel/ABI-x86_64.dump)
make compare-exported  # verify headers and radcli.map export the same symbols
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

- **`rc_handle` (`struct rc_conf`)** — opaque per-application context. Holds parsed config, dictionary, socket override vtable (`rh->so`), and socket type (`rh->so_type`: UDP/TCP/TLS/DTLS).
- **`VALUE_PAIR`** — singly-linked list of RADIUS attributes. The `attribute` field is 64-bit: upper 32 bits = vendor ID, lower 32 bits = attribute ID. Use `VENDOR()` and `ATTRID()` macros to decompose.
- **`SEND_DATA`** — per-request context (server, port, secret, timeout, retries, send/recv `VALUE_PAIR` lists).
- **`RC_AAA_CTX`** — captures the secret and request authenticator vector from a completed request, enabling idempotent retries.
- **`rc_sockets_override` (`rh->so`)** — vtable of function pointers (`get_fd`, `close_fd`, `sendto`, `recvfrom`, `lock`, `unlock`). TLS mode replaces these with GnuTLS wrappers in `lib/tls.c`.

### Transport abstraction (`lib/sendserver.c` + `lib/tls.c`)

All network I/O goes through `rh->so` function pointers, set by `rc_apply_config()` (called from `rc_read_config()`):
- UDP: `default_socket_funcs` — standard `sendto`/`recvfrom`
- TCP: `default_tcp_socket_funcs`
- TLS/DTLS: `tls_sendto` / `tls_recvfrom` wrappers around GnuTLS

**TLS reconnection** (`lib/tls.c`): The `tls_st` struct holds a persistent GnuTLS session. When a send or receive fails, `need_restart` is set. The next `tls_sendto()` call triggers `restart_session()`, which re-establishes the connection. `restart_session()` has a `TIME_ALIVE` (120s) time guard to throttle reconnection attempts.

`rc_check_tls(rh)` — call periodically from application threads to proactively detect dead sessions via heartbeat and reconnect. **ocserv does not call this**, which means idle session closure is only detected on the next request.

### Dictionary

Loaded from the `dictionary` config option. Attribute names map to numeric IDs via `DICT_ATTR` / `DICT_VALUE` / `DICT_VENDOR` linked lists hanging off `rc_handle`. Vendor-specific attributes use PEN-scoped IDs via `VENDOR_BIT_SIZE`. Dictionary files are installed to `$(datadir)/radcli/`; the bundled set is in `etc/`.

### ABI stability

Exported symbols are controlled by `lib/radcli.map`. When adding public functions, add them to the map **and** update `include/radcli/radcli.h`. Run `make compare-exported` to validate consistency.

## CI

Four jobs run on every push (`.github/workflows/tests.yaml`):
- **static-analyzer** — clang static analysis (`scan-build`)
- **tests-asan** — build + `sudo make check` with `-fsanitize=address`
- **tests-ubsan** — build + `sudo make check` with `-fsanitize=undefined,...`
- **tests** — standard build, `sudo make check`, `make abi-check`, `make distcheck`

## Coding conventions

- C99, BSD 2-clause license for new files
- All public functions prefixed `rc_`, macros in `UPPER_CASE`
- Doxygen comments on all public API (`@param`, `@return`, `@defgroup`)
- Compile with `-Wall -Werror`; CI runs ASan and UBSan as separate jobs
- New features must include a test; see `tests/` and `.github/workflows/tests.yaml`
