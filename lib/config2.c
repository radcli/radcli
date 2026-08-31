/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file config2.c
 * @brief radcli2.h's context/config construction API: a thin typed layer
 * over the lib/config.c functions (radcli2_priv_new/radcli2_priv_config_init/radcli2_priv_read_config/
 * radcli2_priv_apply_config/radcli2_priv_add_config/radcli2_priv_read_dictionary/radcli2_priv_destroy), sharing
 * their exact grammar/validation instead of a second copy of it.
 * radcli_ctx and rc_handle are the same struct rc_conf (radcli2.h), so no
 * conversion is needed between the two APIs' handles. See radcli2.h for
 * documentation. This is new code, so unlike lib/config.c it is under a
 * plain 2-clause BSD license (see COPYRIGHT).
 */

/**
 * @addtogroup radcli2-ctx
 *
 * @{
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include <options.h>
#include "util.h"

/** @brief Create an empty context, ready for radcli_ctx_set_opt_str()/
 *  _set_opt_int() and radcli_ctx_apply() -- the fully programmatic
 *  ("backup") way to configure radcli without a config file on disk.
 *
 * Allocates a context with no server, secret, or transport configured yet
 * -- radcli_ctx_apply() must succeed before it is usable for a request.
 * Also loads the built-in RFC 2865/2866/2869 dictionary, the same one
 * radcli_ctx_read_config() always loads, unless #RADCLI_CTX_NO_BUILTIN_DICT
 * is set in flags -- so radcli_dict_lookup_num() is non-NULL for
 * well-known attributes right away, without a separate
 * radcli_ctx_read_dictionary() call.
 *
 * @param flags a bitwise OR of #radcli_ctx_flags, or 0 for the common case.
 * @return the new context, or NULL on allocation failure, an unknown flags
 *  bit, or a failure loading the built-in dictionary.
 */
radcli_ctx *radcli_ctx_new(unsigned flags)
{
	rc_handle *rh;

	if (flags & ~(unsigned)RADCLI_CTX_NO_BUILTIN_DICT)
		return NULL;

	rh = radcli2_priv_new();
	if (rh == NULL)
		return NULL;

	/* radcli2_priv_config_init() already destroys rh and returns NULL on failure */
	rh = radcli2_priv_config_init(rh);
	if (rh == NULL)
		return NULL;

	if (!(flags & RADCLI_CTX_NO_BUILTIN_DICT) &&
	    radcli2_priv_load_builtin_dict(rh) != 0) {
		radcli2_priv_destroy(rh);
		return NULL;
	}

	return rh;
}

/** @brief Create a context by parsing a config file -- the main,
 *  recommended way to configure radcli.
 *
 * Parses filename, validates every option, initialises the transport
 * (including the TLS/DTLS handshake for TLS/DTLS transports), and loads
 * the built-in RFC 2865/2866/2869 dictionary plus the file's own
 * `dictionary=` option, if set -- radcli_ctx_read_dictionary() need not be
 * called separately for the common case, unless #RADCLI_CTX_NO_BUILTIN_DICT
 * is set in flags. Uses the same file format and recognised options as
 * radcli.h's rc_read_config(), so an existing radiusclient.conf written for
 * the legacy API loads unchanged.
 *
 * @param filename path to the configuration file.
 * @param flags a bitwise OR of #radcli_ctx_flags, or 0 for the common case.
 * @return the new context, or NULL on failure (missing/unreadable file,
 *  invalid option, an unknown flags bit, or transport initialisation
 *  failure).
 */
radcli_ctx *radcli_ctx_read_config(const char *filename, unsigned flags)
{
	if (flags & ~(unsigned)RADCLI_CTX_NO_BUILTIN_DICT)
		return NULL;

	return radcli2_priv_read_config(filename, !!(flags & RADCLI_CTX_NO_BUILTIN_DICT));
}

/** @brief Load an additional attribute dictionary.
 *
 * Parses path (ATTRIBUTE/VALUE/VENDOR lines, radcli's dictionary grammar)
 * into ctx's dictionary. Not needed for the common case:
 * radcli_ctx_read_config() already loads the file's own `dictionary=`
 * option. Useful for the programmatic ("backup") construction path, or to
 * load more than one supplemental dictionary.
 *
 * @param ctx a context from radcli_ctx_new() or radcli_ctx_read_config().
 * @param path path to the dictionary file.
 * @return 0 on success, -1 on failure (unreadable file, or a parse error --
 *  including a conflicting redefinition of an already-loaded attribute).
 */
int radcli_ctx_read_dictionary(radcli_ctx *ctx, const char *path)
{
	return radcli2_priv_read_dictionary(ctx, path);
}

/** @brief Load an additional attribute dictionary from an in-memory buffer.
 *
 * The from-buffer counterpart to radcli_ctx_read_dictionary(), for a
 * caller that has dictionary text already in memory rather than in a file
 * (e.g. a small, program-defined supplemental dictionary) -- added so a
 * radcli2.h-only caller is not forced to reach into radcli.h's
 * rc_read_dictionary_from_buffer() for this one operation.
 *
 * @param ctx a context from radcli_ctx_new() or radcli_ctx_read_config().
 * @param buf the dictionary text.
 * @param size buf's length in bytes.
 * @return 0 on success, -1 on failure (a parse error, including a
 *  conflicting redefinition of an already-loaded attribute).
 */
int radcli_ctx_read_dictionary_from_buffer(radcli_ctx *ctx, const char *buf, size_t size)
{
	return radcli2_priv_read_dictionary_from_buffer(ctx, buf, size);
}

/** @brief Validate the options set so far and initialise the transport.
 *
 * Call once, after all radcli_ctx_set_opt_str()/_set_opt_int() calls for
 * ctx have been made, to activate the configuration -- ctx is not usable
 * for a request before this succeeds. radcli_ctx_read_config() calls this
 * internally; do not call it again on a context obtained that way.
 *
 * @param ctx a context configured via radcli_ctx_set_opt_str()/_set_opt_int().
 * @return 0 on success, -1 on failure (e.g. no authserver configured, or an
 *  invalid radius_timeout/radius_retries).
 */
int radcli_ctx_apply(radcli_ctx *ctx)
{
	return radcli2_priv_apply_config(ctx);
}

/** @brief Release a context.
 * @param ctx a context from radcli_ctx_new() or radcli_ctx_read_config();
 *  NULL is accepted and ignored.
 */
void radcli_ctx_free(radcli_ctx *ctx)
{
	if (ctx != NULL)
		radcli2_priv_destroy(ctx);
}

/* radcli_opt_id (radcli2.h) shares its ordinal position with rc_option_id,
 * both generated from RC_OPTION_TABLE (radcli-defs.h) -- so
 * ctx->config_options[opt] is the same OPTION radcli2_priv_add_config(ctx, "the
 * option's name", ...) would look up by string. */
/*- Look up opt's OPTION table entry for ctx.
 *
 * @param ctx a context from radcli_ctx_new() or radcli_ctx_read_config().
 * @param opt the option to look up.
 * @return the option's OPTION entry, or NULL if ctx is NULL, has no
 * option table, or opt is out of range.
 -*/
static const OPTION *radcli_opt_lookup(const radcli_ctx *ctx, radcli_opt_id opt)
{
	if (ctx == NULL || ctx->config_options == NULL || (unsigned)opt >= OPT_COUNT)
		return NULL;
	return &ctx->config_options[opt];
}

/* radcli2.h's set_opt_* enforce a stricter contract than radcli2_priv_add_config():
 * every option, including authserver/acctserver, may be set at most once --
 * a second call fails instead of silently overwriting (RADCLI_OPT_TYPE_STR/RADCLI_OPT_TYPE_INT, which
 * radcli2_priv_add_config() itself does not actually guard against: option->status is
 * checked but never set) or accumulating into a multi-server list (RADCLI_OPT_TYPE_SRV).
 * This is what makes the new API's "one server per context" design
 * (radcli_request_new(), REQ-NET2-INIT-003) an enforced invariant instead
 * of an unenforced convention. Only applies to this typed setter path --
 * radcli_ctx_read_config() is a direct alias of radcli2_priv_read_config()
 * (REQ-CONFIG2-INIT-002) and keeps that function's existing behavior. */
/*- Report whether o already carries a value set by a previous typed setter
 * call.
 *
 * @param o the option to check.
 * @return nonzero if o is already set (or, for RADCLI_OPT_TYPE_SRV, already has a
 * configured server), zero otherwise.
 -*/
static int radcli_opt_already_set(const OPTION *o)
{
	if (o->val == NULL)
		return 0;
	if (o->type & RADCLI_OPT_TYPE_SRV)
		/* radcli2_priv_config_init() pre-allocates an empty SERVER struct for
		 * authserver/acctserver, so a non-NULL val alone does not mean
		 * a server was actually configured yet. */
		return ((SERVER *)o->val)->max > 0;
	return 1;
}

/** @brief Set a string-typed configuration option.
 *
 * Stores val for opt on ctx, validating it against opt's own grammar (e.g.
 * #RADCLI_OPT_AUTHSERVER accepts the "host[:port[:secret]]" form a config
 * file's `authserver` line does). Valid for any #radcli_opt_id whose
 * RC_OPTION_TABLE type is RADCLI_OPT_TYPE_STR or RADCLI_OPT_TYPE_SRV; use radcli_ctx_set_opt_int()
 * for an RADCLI_OPT_TYPE_INT option instead.
 *
 * @param ctx a context from radcli_ctx_new() or radcli_ctx_read_config().
 * @param opt the option to set.
 * @param val the value; for #RADCLI_OPT_AUTHSERVER/#RADCLI_OPT_ACCTSERVER,
 *  the shared secret is better set with radcli_ctx_set_secret() than
 *  embedded in this string.
 * @return 0 on success, -1 on failure (NULL ctx, opt out of range, wrong
 *  type for opt, or an invalid val for opt's grammar).
 */
int radcli_ctx_set_opt_str(radcli_ctx *ctx, radcli_opt_id opt, const char *val)
{
	const OPTION *o = radcli_opt_lookup(ctx, opt);

	if (o == NULL || !(o->type & (RADCLI_OPT_TYPE_STR | RADCLI_OPT_TYPE_SRV)))
		return -1;

	if (radcli_opt_already_set(o)) {
		rc_log(LOG_ERR, "radcli_ctx_set_opt_str: %s is already set", o->name);
		return -1;
	}

	if ((o->type & RADCLI_OPT_TYPE_SRV) && val != NULL && strpbrk(val, ", \t") != NULL) {
		/* The new API carries exactly one server per role
		 * (REQ-NET2-INIT-003) -- reject a comma/whitespace-separated
		 * multi-host value in one call, the same as a second call
		 * naming another host would be rejected above. */
		rc_log(LOG_ERR, "radcli_ctx_set_opt_str: %s must name a single "
				"server, not a list", o->name);
		return -1;
	}

	return radcli2_priv_add_config(ctx, o->name, val, "radcli_ctx_set_opt_str", 0);
}

/** @brief Set an integer-typed configuration option.
 * @param ctx a context from radcli_ctx_new().
 * @param opt the option to set; MUST be RADCLI_OPT_TYPE_INT in RC_OPTION_TABLE
 *  (e.g. #RADCLI_OPT_RADIUS_TIMEOUT, #RADCLI_OPT_RADIUS_RETRIES).
 * @param val the value.
 * @return 0 on success, -1 on failure (as radcli_ctx_set_opt_str()).
 */
int radcli_ctx_set_opt_int(radcli_ctx *ctx, radcli_opt_id opt, long val)
{
	const OPTION *o = radcli_opt_lookup(ctx, opt);
	char buf[32];

	if (o == NULL || !(o->type & RADCLI_OPT_TYPE_INT))
		return -1;

	if (radcli_opt_already_set(o)) {
		rc_log(LOG_ERR, "radcli_ctx_set_opt_int: %s is already set", o->name);
		return -1;
	}

	snprintf(buf, sizeof(buf), "%ld", val);
	return radcli2_priv_add_config(ctx, o->name, buf, "radcli_ctx_set_opt_int", 0);
}

/** @brief Read back a string-typed configuration option.
 *
 * Unlike radcli_ctx_set_opt_str(), only valid for an RADCLI_OPT_TYPE_STR opt --
 * #RADCLI_OPT_AUTHSERVER/#RADCLI_OPT_ACCTSERVER (RADCLI_OPT_TYPE_SRV) store a parsed
 * server list, not a string, so are not readable through this call.
 *
 * @param ctx a context from radcli_ctx_new() or radcli_ctx_read_config().
 * @param opt the option to read; MUST be RADCLI_OPT_TYPE_STR in RC_OPTION_TABLE
 *  (e.g. #RADCLI_OPT_DEFAULT_REALM, #RADCLI_OPT_DICTIONARY).
 * @return the option's value, or NULL if unset, ctx is NULL, opt is out of
 *  range, or opt is not RADCLI_OPT_TYPE_STR.
 */
const char *radcli_ctx_get_opt_str(const radcli_ctx *ctx, radcli_opt_id opt)
{
	const OPTION *o = radcli_opt_lookup(ctx, opt);

	if (o == NULL || !(o->type & RADCLI_OPT_TYPE_STR))
		return NULL;
	return (const char *)o->val;
}

/** @brief Read back an integer-typed configuration option.
 * @param ctx a context from radcli_ctx_new() or radcli_ctx_read_config().
 * @param opt the option to read; MUST be RADCLI_OPT_TYPE_INT in RC_OPTION_TABLE
 *  (e.g. #RADCLI_OPT_RADIUS_TIMEOUT, #RADCLI_OPT_RADIUS_RETRIES).
 * @param out set to the option's value on success; unchanged on failure.
 * @return 0 on success, -1 on failure (NULL ctx or out, opt out of range,
 *  opt not RADCLI_OPT_TYPE_INT, or opt unset).
 */
int radcli_ctx_get_opt_int(const radcli_ctx *ctx, radcli_opt_id opt, long *out)
{
	const OPTION *o = radcli_opt_lookup(ctx, opt);

	if (o == NULL || !(o->type & RADCLI_OPT_TYPE_INT) || out == NULL || o->val == NULL)
		return -1;

	*out = *((int *)o->val);
	return 0;
}

/* The new API is single-server-per-context, so only the first
 * (only) entry of the SERVER list named by optname needs a secret. */
/*- Set secret on the first entry of the SERVER list named by optname.
 *
 * @param ctx a context whose optname server is already configured.
 * @param optname "authserver" or "acctserver".
 * @param secret the shared secret to copy onto that server entry.
 * @return 0 on success, -1 if that server type has not been configured
 * yet or the secret could not be duplicated.
 -*/
static int radcli_set_one_secret(radcli_ctx *ctx, const char *optname, const char *secret)
{
	SERVER *serv = radcli2_priv_conf_srv(ctx, optname);
	char *dup;

	if (serv == NULL || serv->max == 0)
		return -1;

	dup = strdup(secret);
	if (dup == NULL)
		return -1;

	free(serv->secret[0]);
	serv->secret[0] = dup;
	return 0;
}

/** @brief Set the RADIUS shared secret for the configured authserver
 *  and/or acctserver.
 *
 * The equivalent, for the new API, of embedding a secret in the
 * `host:port:secret` form of #RADCLI_OPT_AUTHSERVER/#RADCLI_OPT_ACCTSERVER's
 * value -- but as a distinct call instead of a delimited string, and able
 * to set both server types' secret at once when they share one (the usual
 * case) via `RADCLI_SECRET_AUTH | RADCLI_SECRET_ACCT`, without embedding
 * anything in the authserver/acctserver value at all.
 *
 * @param ctx a context whose #RADCLI_OPT_AUTHSERVER and/or
 *  #RADCLI_OPT_ACCTSERVER (per target_mask) is already set -- via
 *  radcli_ctx_set_opt_str() or radcli_ctx_read_config() -- before this call.
 * @param target_mask a bitwise OR of one or both #radcli_secret_target
 *  values.
 * @param secret the shared secret, as a NUL-terminated string.
 * @return 0 on success, -1 on failure (NULL ctx/secret, target_mask empty
 *  or carrying an unrecognised bit, or the corresponding server not yet
 *  configured).
 */
int radcli_ctx_set_secret(radcli_ctx *ctx, unsigned target_mask, const char *secret)
{
	int ret = 0;

	if (ctx == NULL || secret == NULL || target_mask == 0 ||
	    (target_mask & ~(unsigned)(RADCLI_SECRET_AUTH | RADCLI_SECRET_ACCT)))
		return -1;

	if (target_mask & RADCLI_SECRET_AUTH)
		ret |= radcli_set_one_secret(ctx, "authserver", secret);
	if (target_mask & RADCLI_SECRET_ACCT)
		ret |= radcli_set_one_secret(ctx, "acctserver", secret);

	return ret == 0 ? 0 : -1;
}

/** @brief Set the RFC 6614/7360 TLS-transport Pre-Shared Key credentials
 *  for the configured authserver.
 *
 * The equivalent, for the new API, of the legacy
 * `authserver host:port:psk@username@hexkey` inline form -- but with
 * identity and key as independent byte buffers instead of a delimited
 * string, so a username containing `@` cannot be misparsed (the legacy
 * form splits on the first `@` after the `psk@` prefix) and the key never
 * needs to be hex-encoded by the caller. Only meaningful when
 * #RADCLI_OPT_SERV_TYPE is `tls` or `dtls`; takes priority over any
 * `psk@username@hexkey` embedded in #RADCLI_OPT_AUTHSERVER's value, should
 * both somehow be set.
 *
 * @param ctx a context, before radcli_ctx_apply().
 * @param identity the PSK identity; GnuTLS treats this as a NUL-terminated
 *  string once passed on, so an identity containing an embedded NUL byte is
 *  truncated there -- a GnuTLS API constraint, not an ambiguity this
 *  function introduces.
 * @param identity_len identity's length in bytes.
 * @param key the raw PSK key bytes (not hex-encoded text).
 * @param keylen key's length in bytes.
 * @return 0 on success, -1 on failure (NULL ctx/identity/key, or keylen 0).
 */
int radcli_ctx_set_tls_psk(radcli_ctx *ctx,
			    const void *identity, size_t identity_len,
			    const uint8_t *key, size_t keylen)
{
	char *id_copy;
	void *key_copy;

	if (ctx == NULL || identity == NULL || key == NULL || keylen == 0)
		return -1;

	id_copy = malloc(identity_len + 1);
	if (id_copy == NULL)
		return -1;
	memcpy(id_copy, identity, identity_len);
	id_copy[identity_len] = '\0';

	key_copy = malloc(keylen);
	if (key_copy == NULL) {
		free(id_copy);
		return -1;
	}
	memcpy(key_copy, key, keylen);

	free(ctx->tls_psk_identity);
	free(ctx->tls_psk_key);
	ctx->tls_psk_identity = id_copy;
	ctx->tls_psk_key = key_copy;
	ctx->tls_psk_key_len = keylen;

	return 0;
}

/** @} */
 /*
 * Local Variables:
 * c-basic-offset:8
 * c-style: whitesmith
 * End:
 */
