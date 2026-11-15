New API
========

radcli adds RADIUS authentication and accounting to an application in
roughly 50 lines of code using a configuration file. All server addresses,
credentials, and transport choices (UDP, TCP, TLS, DTLS) live in that config
file, so the application carries no transport-specific code and does not
need to know or care which one is in use.

This page documents the current, recommended way to use radcli.

## Protocols and features

- **Authentication and accounting** (RFC 2865, RFC 2866, RFC 2869): PAP-style
  Access-Request/Accept/Reject/Challenge, and Accounting-Request/Response,
  including the Message-Authenticator attribute and Acct-Input/Output-Octets
  and -Gigawords pairing. It includes a built-in dictionary covering
  RFC 2865/2866/2869's attributes as well as RFC6929 and RFC 8044 data types;
  extendable with additional dictionaries via radcli_ctx_read_dictionary().
- **Transport**: plain UDP or TCP (RFC 6613), or **TLS/DTLS** ("RadSec",
  RFC 6614 for TLS and RFC 7360 for DTLS), selected purely through the
  config file's `serv-type` and requiring no transport-specific application
  code. TCP, TLS and DTLS carry every request over one persistent
  connection, reconnecting when it fails; over TCP and TLS a request is
  retransmitted only on a new connection. TLS/DTLS
  credentials are either X.509 (CA/certificate/key files) or a Pre-Shared
  Key, set programmatically with radcli_ctx_set_tls_psk() or via the config
  file's `tls-*` options.
- **Dynamic Authorization / DAC** (RFC 5176, \ref radcli-dae): a runnable
  CoA-Request/Disconnect-Request server built from radcli_dae_new(),
  radcli_dae_set_handler(), and radcli_dae_start(), driven through the
  same non-blocking poll surface as the rest of the API
  (radcli_ctx_get_poll()/radcli_ctx_dispatch()). Incoming requests from a
  Dynamic Authorization Client (DAC) go through a full validation pipeline --
  source-address authorization, Request Authenticator, Message-Authenticator,
  Event-Timestamp freshness, and duplicate suppression -- before the
  application's handler ever sees them. See
  [src/radexample-async-dae.c](radexample-async-dae_8c-example.html) for
  a working Disconnect server alongside an RFC 5997 watchdog. Requests
  arrive either on a separate RFC 5176 UDP listener, or, with
  `dae-accept yes` under `serv-type` tls or dtls, over the RadSec connection
  itself.

## Quick start

The normal call sequence is three steps:

1. **Load configuration** -- parses the config file and initialises the transport:
   @code{.c}
   radcli_ctx *ctx = radcli_ctx_read_config("/etc/radiusclient/radiusclient.conf", 0);
   @endcode

2. **Build an attribute list** -- attach the attributes you want to send.
   Each add call is independent; radcli_avp_list_error() gives one aggregate
   check for all of them instead of testing every call's return value:
   @code{.c}
   radcli_avp_list *send = radcli_avp_list_new();
   radcli_avp_add_str_by_num(send, ctx, PW_USER_NAME, 0, username);
   radcli_avp_add_bytes_by_num(send, ctx, PW_USER_PASSWORD, 0, password, password_len);
   radcli_avp_add_uint32_by_num(send, ctx, PW_NAS_PORT, 0, nas_port);

   if (radcli_avp_list_error(send)) {
           // one of the adds above failed
   }
   @endcode

3. **Send the request** -- radcli_aaa() handles retries, failover, and response
   validation automatically:
   @code{.c}
   radcli_code out_code;
   radcli_avp_list *recvd = NULL;
   int result = radcli_aaa(ctx, RADCLI_CODE_ACCESS_REQUEST, send, &out_code, &recvd);
   // result == RADCLI_OK on success
   radcli_avp_list_free(send);
   radcli_avp_list_free(recvd);
   radcli_ctx_free(ctx);
   @endcode

The transport is selected entirely in the config file (`serv-type` = udp,
tcp, tls, or dtls); no code changes are required to switch. TLS and DTLS
additionally require certificate or PSK credentials to be set in the config
file (`tls-ca-file`, `tls-cert-file`, `tls-key-file`), or programmatically
with radcli_ctx_set_tls_psk().

See [src/radexample.c](radexample_8c-example.html) for a complete, runnable
example, and [src/radexample-async-dae.c](radexample-async-dae_8c-example.html)
for an asynchronous version with Dynamic Authorization one.

A context, and every request and DAE object created from it, must be used
by one thread at a time; separate contexts are independent.

## Per-request timeout

radcli_aaa() and radcli_request_new() take the timeout and retry count from
the config file (`radius_timeout`, `radius_retries`).
radcli_request_set_timeout() overrides them for a single request, e.g. to
send a final Accounting-Stop once within a fixed deadline without changing
the context:
@code{.c}
radcli_request *r = radcli_request_new(ctx, RADCLI_CODE_ACCOUNTING_REQUEST, send);
radcli_request_set_timeout(r, 1000, 0);   // one attempt, 1s for the reply
radcli_request_perform(r, RADCLI_REQUEST_NONE);
radcli_request_free(r);
@endcode
Connecting a TCP/TLS/DTLS session still uses the configured `radius_timeout`.

## Asynchronous requests

An application built around an event loop sends a request with
radcli_request_perform() and one of two flags, then drives it from its own
loop:

- `RADCLI_REQUEST_SENDONLY` returns once the packet is sent, without waiting
  for the reply; it may still wait to connect a TCP/TLS/DTLS session.
- `RADCLI_REQUEST_SENDONLY_NONBLOCK` never waits for the network: what cannot
  be sent at once is queued and sent by radcli_ctx_dispatch(). Name
  resolution may still block.

radcli never polls by itself: radcli_ctx_get_poll() reports the descriptors
and the timeout to wait on, and radcli_ctx_dispatch() must be called when
either fires, including when only the timeout expires. radcli_request_done()
then reports the outcome without performing I/O:
@code{.c}
radcli_request_perform(r, RADCLI_REQUEST_SENDONLY_NONBLOCK);

while (radcli_request_done(r) == RADCLI_AGAIN) {
        struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
        size_t nfds;
        int timeout_ms;

        radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms);
        poll(pfds, nfds, timeout_ms);
        radcli_ctx_dispatch(ctx);
}
// RADCLI_OK: read the reply with radcli_request_code()/radcli_request_attrs()
@endcode
For a fire-and-forget notification, send with `RADCLI_REQUEST_SENDONLY` and
call radcli_request_free() right after radcli_request_perform() instead; a
`RADCLI_REQUEST_SENDONLY_NONBLOCK` request freed before radcli_ctx_dispatch()
sent it is never sent.

## Transitioning from earlier versions

Already using the legacy radcli API or even `freeradius-client.h`/`radiusclient-ng.h`?
See the [migration guide](radcli2-migration.html) for a function-by-function map and
before/after simplifications, or go straight to the
[legacy API reference](../manual-legacy/index.html) if you just need to look
something up.
