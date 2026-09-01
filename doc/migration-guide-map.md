API mapping {#radcli2-migration-map}
==============

## Concept map

| Legacy (radcli.h)                          | New (radcli2.h)                                      |
|---------------------------------------------|-------------------------------------------------------|
| `rc_handle`                                  | `radcli_ctx`                                         |
| `VALUE_PAIR` linked list, manual `malloc`/`free`, 253-byte value ceiling | `radcli_avp_list`/`radcli_avp` -- heap-allocated, length-carrying, add-only |
| `DICT_ATTR *` looked up by name/id, typically re-resolved on demand | `const radcli_attr_def *` looked up once and cached, then compared by pointer identity |
| Two-call setup: `rc_read_config()` + `rc_read_dictionary()` | One call: `radcli_ctx_read_config()` (loads the config's `dictionary=` option itself) |
| Per-call error checking on each `rc_avpair_add()` | Batch construction, one `radcli_avp_list_error()` check at the end |

## Function mapping

### Context, configuration, dictionary

| Legacy                                      | New                                                              |
|-----------------------------------------------|-------------------------------------------------------------------|
| `rc_new()` + `rc_config_init()`               | `radcli_ctx_new()`                                                 |
| `rc_read_config()` + `rc_read_dictionary()`   | `radcli_ctx_read_config()`                                         |
| `rc_add_config()`                             | `radcli_ctx_set_opt_str()` / `radcli_ctx_set_opt_int()`            |
| `rc_apply_config()`                            | `radcli_ctx_apply()`                                                |
| `rc_conf_str()` / `rc_conf_int()`             | `radcli_ctx_get_opt_str()` / `radcli_ctx_get_opt_int()`            |
| `rc_destroy()` / `rc_config_free()`           | `radcli_ctx_free()`                                                 |
| `rc_dict_findattr()` / `rc_dict_getattr()`    | `radcli_dict_lookup()` / `radcli_dict_lookup_num()` / `radcli_dict_lookup_oid()` |
| `rc_dict_findval()` / `rc_dict_getval()`      | `radcli_dict_lookup_value()`                                       |
| (server config lines only; no setter)          | `radcli_ctx_set_secret()`, `radcli_ctx_set_tls_psk()`               |

### Building an AVP list to send

| Legacy                                        | New                                                                |
|-------------------------------------------------|-----------------------------------------------------------------------|
| `rc_avpair_add()` (raw bytes, any type, `int len`) | `radcli_avp_add_str_by_num()` / `_add_bytes_by_num()` / `_add_uint32_by_num()` / `_add_uint64_by_num()` / `_add_ip4_by_num()` / `_add_ip6_by_num()` / `_add_ip4prefix_by_num()` -- typed, dictionary lookup folded into the call |
| same, once a `DICT_ATTR *`/def is already resolved | `radcli_avp_add_str()` / `_add_bytes()` / `_add_uint32()` / ... (no `_by_num` suffix, taking a cached `radcli_attr_def *`) |
| `rc_avpair_new()`                                | `radcli_avp_add_username()` (realm-aware User-Name specifically; otherwise use the typed adders above) |
| manual error check after every `rc_avpair_add()`  | `radcli_avp_list_error()` -- one check after building the whole list |

### Reading a received AVP list

| Legacy                                                              | New                                                                |
|-----------------------------------------------------------------------|-----------------------------------------------------------------------|
| `rc_avpair_get()` (by id/vendor) + `rc_avpair_next()` to walk the list | `radcli_avp_get()` (by def) or `radcli_avp_list_iter()`/`radcli_avp_iter_next()` to walk |
| `rc_avpair_get_uint32()`                                              | `radcli_avp_get_uint32()` / `radcli_avp_get_uint64()`                |
| `rc_avpair_get_in6()`                                                  | `radcli_avp_get_ip6()` / `radcli_avp_get_ip4prefix()`                |
| `rc_avpair_get_raw()`                                                  | `radcli_avp_get_bytes()` / `radcli_avp_get_cstr()`                  |
| `rc_avpair_get_attr()`                                                 | `radcli_avp_def()` + `radcli_attr_def_name()` / `_type()` / `_oid()` |
| manual concatenation loop over repeated occurrences of one attribute (e.g. Reply-Message) | `radcli_avp_concat_str_by_num()`                                     |
| `rc_avpair_free()`                                                     | `radcli_avp_list_free()`                                             |

### Sending a request / accounting / DAE

| Legacy                                    | New                                                                  |
|----------------------------------------------|--------------------------------------------------------------------------|
| `rc_auth()` / `rc_acct()` (single server)     | `radcli_request_new()` + `radcli_request_perform()`                       |
| `rc_aaa()` (multi-server fail-over, NAS-Port/Acct-Delay-Time autofill, folds in a reply-message out-parameter) | `radcli_aaa()` (same fail-over and Acct-Delay-Time autofill; add NAS-Port to `send` yourself with `radcli_avp_add_uint32_by_num()`, same as any other attribute; use `radcli_avp_concat_str_by_num()` separately for the reply message) |
| `rc_acct_async()` | `radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)` followed by `radcli_request_free(r)` without ever calling `radcli_ctx_dispatch()` -- fire-and-forget, one send, no retries, same as `rc_acct_async()` |
| (no equivalent) | `radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)` + `radcli_ctx_get_poll()`/`radcli_ctx_dispatch()`/`radcli_request_done()`: poll-driven async request/reply, for a caller built around an event loop that cannot block a thread on `radcli_request_perform(r, RADCLI_REQUEST_NONE)` |
| `rc_auth_proxy()` / `rc_acct_proxy()` | no direct equivalent yet |
| (no DAE support)                               | `radcli_dae_new()`, `radcli_dae_set_handler()`, `radcli_dae_start()`, `radcli_dae_req_*()`, `radcli_dae_reply()`/`_reply_error()` (RFC 5176 CoA/Disconnect) |

### No new-API equivalent, by design

These are transport/process-level internals the new API deliberately doesn't
expose (opaque `radcli_ctx` handles the transport itself). Keep using the
legacy header for them if you need them; there is nothing to migrate:
`rc_openlog()`, `rc_setdebug()`, `rc_own_hostname()`, `rc_mksid()`,
`rc_get_srcaddr()`, `rc_getport()`, `rc_get_socket_type()`, `rc_tls_fd()`,
`rc_check_tls()`, `rc_test_config()`.

See @ref radcli2-migration-examples "Simplification examples" for real
before/after code built on this mapping.
