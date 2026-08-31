Legacy API
==========

This is the reference for radcli's legacy API (`#include <radcli/radcli.h>`,
the `rc_`/`RC_` prefix, source-compatible with radiusclient-ng and
freeradius-client). It is **frozen**: it receives bug fixes only, no new
functionality. New code should use the
[new API](../manual/index.html) instead.

If you maintain existing code against this API, see the
[migration guide](radcli2-migration.html) for a function-by-function map to
the new API and before/after examples of what moving over simplifies.

`radcli_ctx` (new API) and `rc_handle` (this API) are typedefs of the same
underlying struct, so the two APIs' functions can be mixed on the same
handle -- a codebase can migrate one call site at a time rather than all at
once.

## Introduction

radcli is a C library for adding RADIUS authentication and accounting to an
application in roughly 50 lines of code. All server addresses, credentials,
and transport choices (UDP, TCP, TLS, DTLS) live in a single configuration
file; the calling application needs no transport-specific code.

## Quick start

The normal call sequence is three steps:

1. **Load configuration** -- parses the config file and initialises the transport:
   @code{.c}
   rc_handle *rh = rc_read_config("/etc/radiusclient/radiusclient.conf");
   @endcode

2. **Build an attribute list** -- attach the attributes you want to send:
   @code{.c}
   VALUE_PAIR *send = NULL;
   rc_avpair_add(rh, &send, PW_USER_NAME,     username, -1, 0);
   rc_avpair_add(rh, &send, PW_USER_PASSWORD, password, -1, 0);
   @endcode

3. **Send the request** -- rc_auth() handles retries, failover, and response
   validation automatically:
   @code{.c}
   VALUE_PAIR *received = NULL;
   int result = rc_auth(rh, 0, send, &received, NULL);
   // result == OK_RC on success
   rc_avpair_free(send);
   rc_avpair_free(received);
   rc_destroy(rh);
   @endcode

The transport is selected entirely in the config file (`serv-type` = udp,
tcp, tls, or dtls); no code changes are required to switch. TLS and DTLS
additionally require certificate or PSK credentials to be set in the config
file (`tls-ca-file`, `tls-cert-file`, `tls-key-file`).

For accounting requests that must not block (e.g. sending Accounting-Stop
for open sessions while an application is shutting down), use
`rc_acct_async()` instead of `rc_acct()`: it addresses every configured
accounting server without waiting for a reply.

## Operation without a config file

Programmatic configuration (without a file) is also possible using
`rc_new()`, `rc_config_init()`, `rc_add_config()`, and `rc_apply_config()`.

## Background

RADIUS (Remote Authentication Dial In User Service, RFC 2865/2866) is a
protocol for carrying authentication, authorisation, and accounting
information between a Network Access Server and a shared Authentication
Server. radcli implements the client side, and is source-compatible with
freeradius-client and radiusclient-ng.
