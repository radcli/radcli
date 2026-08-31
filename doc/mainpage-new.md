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
- **Transport**: plain UDP or TCP, or **TLS/DTLS** ("RadSec", RFC 6614 for
  TLS and RFC 7360 for DTLS), selected purely through the config file's
  `serv-type` and requiring no transport-specific application code. TLS/DTLS
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
  [src/radexample-advanced.c](radexample-advanced_8c-example.html) for
  a working Disconnect server alongside an RFC 5997 watchdog. DAC traffic
  today is UDP/3799 per RFC 5176.

## Getting started

Three steps: open a context from a config file, build the attributes to
send, exchange them with the server.

@code{.c}
radcli_ctx *ctx = radcli_ctx_read_config("/etc/radiusclient/radiusclient.conf", 0);

radcli_avp_list *send = radcli_avp_list_new();
radcli_avp_add_str_by_num(send, ctx, PW_USER_NAME, 0, username);
radcli_avp_add_bytes_by_num(send, ctx, PW_USER_PASSWORD, 0, password, password_len);
radcli_avp_add_uint32_by_num(send, ctx, PW_NAS_PORT, 0, nas_port);

radcli_code out_code;
radcli_avp_list *recvd = NULL;
radcli_aaa(ctx, RADCLI_CODE_ACCESS_REQUEST, send, &out_code, &recvd);
@endcode

See [src/radexample.c](radexample_8c-example.html) for a complete, runnable
example, and [src/radexample-advanced.c](radexample-advanced_8c-example.html)
for the Dynamic Authorization and watchdog one.

## Reference

Start with @ref radcli2-ctx "context construction and configuration", then @ref radcli2-dict "the dictionary" and @ref radcli2-avp "attribute-value pair handling" for building the attributes to send, and @ref radcli2-messaging "RADIUS messaging" to exchange them and read back a reply's. Everything here uses the `radcli_`/`RADCLI_` prefix (`#include <radcli/radcli2.h>`).

Already using the legacy radcli API (`freeradius-client.h`/`radiusclient-ng.h`)?
See the
[migration guide](radcli2-migration.html) for a function-by-function map and
before/after simplifications, or go straight to the
[legacy API reference](../manual-legacy/index.html) if you just need to look
something up.
