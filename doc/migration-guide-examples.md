Simplification examples {#radcli2-migration-examples}
==============

The following are real before/after pairs, adapted from a RADIUS
authentication module mid-migration to the new API. See
@ref radcli2-migration-map "API mapping" for the function-by-function
table these draw from.

## One error check instead of one per call

Building an Access-Request used to mean checking every `rc_avpair_add()`
call individually:

\legacy_code_begin
@code{.c}
send = NULL;
if (rc_avpair_add(rh, &send, PW_USER_NAME, username, -1, 0) == NULL)
    goto fail;
if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, password, -1, 0) == NULL)
    goto fail;
if (rc_avpair_add(rh, &send, PW_NAS_IDENTIFIER, nas_id, -1, 0) == NULL)
    goto fail;
/* ... repeated for every attribute ... */
@endcode
\legacy_code_end

With the new API, every add is unconditional and a single check at the end
covers the whole batch:

\new_code_begin
@code{.c}
radcli_avp_list *send = radcli_avp_list_new();
radcli_avp_add_str_by_num(send, ctx, PW_USER_NAME, 0, username);
radcli_avp_add_bytes_by_num(send, ctx, PW_USER_PASSWORD, 0, password, password_len);
radcli_avp_add_str_by_num(send, ctx, PW_NAS_IDENTIFIER, 0, nas_id);
/* ... */
if (radcli_avp_list_error(send)) {
    radcli_avp_list_free(send);
    goto fail;
}
@endcode
\new_code_end

## Appending a realm to User-Name only when the caller didn't already supply one

The legacy pattern hand-rolls the "does it already have a realm" check and
the concatenation:

\legacy_code_begin
@code{.c}
char namebuf[256];
if (strchr(username, '@') == NULL && default_realm[0] != '\0')
    snprintf(namebuf, sizeof(namebuf), "%s@%s", username, default_realm);
else
    snprintf(namebuf, sizeof(namebuf), "%s", username);
rc_avpair_add(rh, &send, PW_USER_NAME, namebuf, -1, 0);
@endcode
\legacy_code_end

`radcli_avp_add_username()` does the check and, passed `NULL` for `realm`,
reaches for ctx's own `default_realm` config option, so an application whose
realm policy is just "whatever the config file says" never reads that option
out itself:

\new_code_begin
@code{.c}
radcli_avp_add_username(send, ctx, username, NULL);
@endcode
\new_code_end

## Reading a 64-bit accounting counter

RFC 2869's Acct-Input/Output-Gigawords exists because RADIUS has no 64-bit
counter attribute: a 64-bit octet count is really two 32-bit attributes, and
the legacy API leaves combining them to the caller:

\legacy_code_begin
@code{.c}
VALUE_PAIR *octets = rc_avpair_get(received, PW_ACCT_INPUT_OCTETS, 0);
VALUE_PAIR *giga = rc_avpair_get(received, PW_ACCT_INPUT_GIGAWORDS, 0);
uint64_t total = octets ? octets->lvalue : 0;
if (giga)
    total += (uint64_t)giga->lvalue << 32;
@endcode
\legacy_code_end

`radcli_avp_add_gigawords64()`/`radcli_avp_get_gigawords64()` do the
splitting/reassembly, including looking up octets' Gigawords counterpart
from the dictionary rather than trusting the caller to get the pairing
right:

\new_code_begin
@code{.c}
uint64_t total;
radcli_avp_get_gigawords64(ctx, received, d_acct_input_octets, &total);
@endcode
\new_code_end

## Reading an RFC 8044 64-bit or ifid attribute

The legacy `rc_attr_type` enum predates RFC 8044 and has no `integer64` or
`ifid` type -- attributes of those types come back as raw bytes that the
caller must byte-swap by hand:

\legacy_code_begin
@code{.c}
VALUE_PAIR *vp = rc_avpair_get(received, PW_SOME_INTEGER64_ATTR, 0);
uint64_t val = 0;
if (vp && vp->lvalue == 8) {
    unsigned char *p = (unsigned char *)vp->strvalue;
    for (int i = 0; i < 8; i++)
        val = (val << 8) | p[i];
}
@endcode
\legacy_code_end

The new dictionary understands `RADCLI_TYPE_INTEGER64`/`RADCLI_TYPE_IFID`
natively, so `radcli_avp_get_uint64_by_num()` returns the decoded value in
one call, byte order already handled:

\new_code_begin
@code{.c}
uint64_t val;
radcli_avp_get_uint64_by_num(received, ctx, PW_SOME_INTEGER64_ATTR, 0, &val);
@endcode
\new_code_end

## Looking up and reading a well-known attribute in one call

The legacy pattern is a lookup call whose result feeds a second call:

\legacy_code_begin
@code{.c}
VALUE_PAIR *vp = rc_avpair_get(received, PW_SESSION_TIMEOUT, 0);
uint32_t timeout = vp ? vp->lvalue : 0;
@endcode
\legacy_code_end

Which is manageable for one attribute, but the new API's `_by_num()`
accessors fold "find the attribute" and "read it as this type" into a
single typed call for every attribute type, including the ones (IPv6,
IPv6/IPv4 prefixes, raw bytes, C strings) where the legacy struct's shared
`lvalue`/`strvalue` fields otherwise need type-specific care:

\new_code_begin
@code{.c}
uint32_t timeout = 0;
radcli_avp_get_uint32_by_num(received, ctx, PW_SESSION_TIMEOUT, 0, &timeout);
@endcode
\new_code_end

For a reply attribute read repeatedly in a hot path, resolving its
`radcli_attr_def *` once with radcli_dict_lookup_num() and reusing it across
radcli_avp_get() calls (comparing by pointer identity, not attribute number)
avoids repeating that lookup -- see \ref radcli2-avp-by-num.

## Collecting a repeated attribute (Reply-Message) into one string

A server is free to send more than one Reply-Message in a single
Access-Accept/-Reject/-Challenge (RFC 2865 SS5.16 -- one attribute cannot
hold more than 253 bytes, so a longer message is split across several
occurrences), and applications that surface it to the end user -- as a
login-failure reason, or the prompt text of an interactive multi-factor
challenge -- need the whole message, not just the first fragment. That
means every occurrence has to be walked and joined, not just the first one
`rc_avpair_get()` would hand back:

\legacy_code_begin
@code{.c}
char msg[256] = "";
VALUE_PAIR *vp = received;
while ((vp = rc_avpair_get(vp, PW_REPLY_MESSAGE, 0)) != NULL) {
    strlcat(msg, vp->strvalue, sizeof(msg));
    strlcat(msg, " ", sizeof(msg));
    vp = vp->next;
}
@endcode
\legacy_code_end

\new_code_begin
@code{.c}
char msg[256];
radcli_avp_concat_str_by_num(msg, sizeof(msg), received, ctx,
                              PW_REPLY_MESSAGE, 0, " ");
@endcode
\new_code_end
