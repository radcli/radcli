/*
 * Copyright (c) 2026, Nikos Mavrogiannopoulos.  All rights reserved.
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

/* Unit test for radcli2.h's context/config construction API
 * (radcli_ctx_new()/_read_config()/_set_opt_str()/_set_opt_int()/_apply()/
 * _read_dictionary()/_free(), lib/config.c) -- no network I/O needed. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

static const char tmpl[] = "ctx-unit-XXXXXX";

static char *write_conf(const char *content)
{
	static char path[64];
	int fd;

	strcpy(path, tmpl);
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		exit(1);
	}
	if (write(fd, content, strlen(content)) != (ssize_t)strlen(content)) {
		perror("write");
		exit(1);
	}
	close(fd);
	return path;
}

int main(void)
{
	radcli_ctx *ctx;

	/* --- radcli_ctx_new() + programmatic ("backup") configuration --- */

	ctx = radcli_ctx_new(0);
	if (ctx == NULL) {
		fprintf(stderr, "error: radcli_ctx_new() failed\n");
		exit(1);
	}

	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1") != 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_str(RADCLI_OPT_AUTHSERVER) failed\n");
		exit(1);
	}
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) != 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_int(RADCLI_OPT_RADIUS_TIMEOUT) failed\n");
		exit(1);
	}
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) != 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_int(RADCLI_OPT_RADIUS_RETRIES) failed\n");
		exit(1);
	}

	/* Setting an int-typed option via _set_opt_str(), or a str-typed one
	 * via _set_opt_int(), must be rejected -- not silently misparsed. */
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_RADIUS_TIMEOUT, "5") == 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_str() accepted an RADCLI_OPT_TYPE_INT option\n");
		exit(1);
	}
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_DICTIONARY, 1) == 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_int() accepted an RADCLI_OPT_TYPE_STR option\n");
		exit(1);
	}

	if (radcli_ctx_apply(ctx) != 0) {
		fprintf(stderr, "error: radcli_ctx_apply() failed\n");
		exit(1);
	}

	/* A context built through radcli_ctx_new() must remain usable via
	 * radcli.h's functions: radcli_ctx and rc_handle are the same
	 * underlying struct. */
	if (rc_conf_int(ctx, "radius_timeout") != 5) {
		fprintf(stderr, "error: rc_conf_int() did not see the value set via "
				"radcli_ctx_set_opt_int()\n");
		exit(1);
	}

	radcli_ctx_free(ctx);

	/* --- a NULL ctx or an out-of-range opt must fail cleanly, not crash. --- */
	ctx = radcli_ctx_new(0);
	assert(ctx != NULL);
	if (radcli_ctx_set_opt_str(NULL, RADCLI_OPT_AUTHSERVER, "x") == 0 ||
	    radcli_ctx_set_opt_str(ctx, (radcli_opt_id)RADCLI_OPT_COUNT, "x") == 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_str() accepted a NULL ctx "
				"or out-of-range opt\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- setting an already-set option a second time must fail, for both
	 * scalar (RADCLI_OPT_TYPE_STR/RADCLI_OPT_TYPE_INT) and server (RADCLI_OPT_TYPE_SRV) options -- unlike
	 * rc_add_config(), whose equivalent check is dead code. --- */
	ctx = radcli_ctx_new(0);
	assert(ctx != NULL);
	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) == 0);
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 6) == 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_int() accepted setting "
				"an already-set option a second time\n");
		exit(1);
	}
	if (rc_conf_int(ctx, "radius_timeout") != 5) {
		fprintf(stderr, "error: a rejected second radcli_ctx_set_opt_int() "
				"call changed the stored value\n");
		exit(1);
	}
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1") == 0);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.2:1") == 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_str() accepted a second "
				"authserver, accumulating into a multi-server list\n");
		exit(1);
	}
	{
		SERVER *auth = rc_conf_srv(ctx, "authserver");
		if (auth == NULL || auth->max != 1 || strcmp(auth->name[0], "127.0.0.1") != 0) {
			fprintf(stderr, "error: a rejected second authserver call changed "
					"the server list\n");
			exit(1);
		}
	}
	radcli_ctx_free(ctx);

	/* --- the new API's server options must name exactly one server: a
	 * comma/whitespace-separated list in a single call is rejected too,
	 * not just a second call. --- */
	ctx = radcli_ctx_new(0);
	assert(ctx != NULL);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1,127.0.0.2:1") == 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_str() accepted a "
				"comma-separated multi-host authserver value\n");
		exit(1);
	}
	/* A single host is still accepted afterwards -- the rejected call must
	 * not have left the option partially set. */
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1") != 0) {
		fprintf(stderr, "error: authserver could not be set after a rejected "
				"multi-host attempt\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- radcli_ctx_read_config() is a direct alias of rc_read_config()
	 * and is NOT subject to the single-set/single-server restriction above:
	 * a config file with two authserver lines still loads, exactly as
	 * rc_read_config() would load it, accumulating into one list. --- */
	{
		const char conf[] =
			"authserver 127.0.0.1:1\n"
			"authserver 127.0.0.2:1\n"
			"radius_timeout 5\n"
			"radius_retries 1\n";
		char *conf_path = write_conf(conf);
		SERVER *auth;

		ctx = radcli_ctx_read_config(conf_path, 0);
		unlink(conf_path);
		if (ctx == NULL) {
			fprintf(stderr, "error: radcli_ctx_read_config() rejected a config "
					"file with two authserver lines (should still load, "
					"same as rc_read_config())\n");
			exit(1);
		}
		auth = rc_conf_srv(ctx, "authserver");
		if (auth == NULL || auth->max != 2) {
			fprintf(stderr, "error: radcli_ctx_read_config() did not "
					"accumulate two authserver lines the way "
					"rc_read_config() does\n");
			exit(1);
		}
		radcli_ctx_free(ctx);
	}

	/* --- radcli_ctx_read_config(): the main path, and dictionary
	 * auto-load without a separate radcli_ctx_read_dictionary() call. --- */
	{
		const char conf[] =
			"authserver 127.0.0.1:1\n"
			"radius_timeout 5\n"
			"radius_retries 1\n"
			"dictionary extra-dict-unit-tmp\n";
		const char extra_dict[] =
			"ATTRIBUTE Test-Ctx-Attr 12345 string\n";
		char *conf_path, *dict_path;
		const radcli_attr_def *d;

		dict_path = write_conf(extra_dict);
		rename(dict_path, "extra-dict-unit-tmp");

		conf_path = write_conf(conf);
		ctx = radcli_ctx_read_config(conf_path, 0);
		unlink(conf_path);
		unlink("extra-dict-unit-tmp");

		if (ctx == NULL) {
			fprintf(stderr, "error: radcli_ctx_read_config() failed\n");
			exit(1);
		}

		/* Standard attribute from the built-in dictionary. */
		d = radcli_dict_lookup(ctx, "User-Name");
		if (d == NULL) {
			fprintf(stderr, "error: built-in dictionary was not loaded by "
					"radcli_ctx_read_config()\n");
			exit(1);
		}

		/* dictionary= attribute, loaded without a separate
		 * radcli_ctx_read_dictionary() call. */
		d = radcli_dict_lookup(ctx, "Test-Ctx-Attr");
		if (d == NULL) {
			fprintf(stderr, "error: radcli_ctx_read_config() did not "
					"auto-load the dictionary= option\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- radcli_ctx_read_dictionary(): explicit supplemental load. --- */
	{
		const char extra_dict[] =
			"ATTRIBUTE Test-Extra-Attr 12346 string\n";
		char *dict_path;

		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);

		dict_path = write_conf(extra_dict);
		if (radcli_ctx_read_dictionary(ctx, dict_path) != 0) {
			fprintf(stderr, "error: radcli_ctx_read_dictionary() failed\n");
			exit(1);
		}
		unlink(dict_path);

		if (radcli_dict_lookup(ctx, "Test-Extra-Attr") == NULL) {
			fprintf(stderr, "error: radcli_ctx_read_dictionary() did not "
					"load the requested file\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- radcli_ctx_read_dictionary_from_buffer(): from-buffer counterpart,
	 * for dictionary text already in memory rather than in a file. --- */
	{
		const char extra_dict[] =
			"ATTRIBUTE Test-Extra-Buf-Attr 12347 string\n";

		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);

		if (radcli_ctx_read_dictionary_from_buffer(ctx, extra_dict, sizeof(extra_dict)) != 0) {
			fprintf(stderr, "error: radcli_ctx_read_dictionary_from_buffer() failed\n");
			exit(1);
		}

		if (radcli_dict_lookup(ctx, "Test-Extra-Buf-Attr") == NULL) {
			fprintf(stderr, "error: radcli_ctx_read_dictionary_from_buffer() did not "
					"load the requested buffer\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- radcli_ctx_new(0) MUST load the built-in RFC 2865/2866/2869
	 * dictionary itself, without a config file or a separate
	 * radcli_ctx_read_dictionary() call -- radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT)
	 * MUST skip it, and an unknown flags bit MUST be rejected. --- */
	{
		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);
		if (radcli_dict_lookup_num(ctx, PW_USER_NAME, 0) == NULL) {
			fprintf(stderr, "error: radcli_ctx_new(0) did not load the "
					"built-in dictionary\n");
			exit(1);
		}
		radcli_ctx_free(ctx);

		ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		assert(ctx != NULL);
		if (radcli_dict_lookup_num(ctx, PW_USER_NAME, 0) != NULL) {
			fprintf(stderr, "error: radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT) "
					"loaded the built-in dictionary anyway\n");
			exit(1);
		}
		radcli_ctx_free(ctx);

		if (radcli_ctx_new(0xf0u) != NULL) {
			fprintf(stderr, "error: radcli_ctx_new() accepted an unknown "
					"flags bit\n");
			exit(1);
		}
	}

	/* --- radcli_ctx_set_secret(): both server types in one call, the
	 * common single-secret case. --- */
	{
		SERVER *auth, *acct;

		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);

		/* No server configured yet: nothing to attach a secret to. */
		if (radcli_ctx_set_secret(ctx, RADCLI_SECRET_AUTH, "shared") == 0) {
			fprintf(stderr, "error: radcli_ctx_set_secret() succeeded with "
					"no authserver configured\n");
			exit(1);
		}

		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1") == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_ACCTSERVER, "127.0.0.1:2") == 0);

		if (radcli_ctx_set_secret(ctx, RADCLI_SECRET_AUTH | RADCLI_SECRET_ACCT, "shared") != 0) {
			fprintf(stderr, "error: radcli_ctx_set_secret() failed for both targets\n");
			exit(1);
		}

		auth = rc_conf_srv(ctx, "authserver");
		acct = rc_conf_srv(ctx, "acctserver");
		if (auth == NULL || acct == NULL ||
		    strcmp(auth->secret[0], "shared") != 0 ||
		    strcmp(acct->secret[0], "shared") != 0) {
			fprintf(stderr, "error: radcli_ctx_set_secret() did not set both "
					"authserver and acctserver secrets\n");
			exit(1);
		}

		/* An invalid target_mask (0, or an unrecognised bit) is rejected. */
		if (radcli_ctx_set_secret(ctx, 0, "x") == 0 ||
		    radcli_ctx_set_secret(ctx, 0xf0u, "x") == 0) {
			fprintf(stderr, "error: radcli_ctx_set_secret() accepted an "
					"invalid target_mask\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- "secret" config option (RADCLI_OPT_SECRET): the config-file
	 * counterpart of radcli_ctx_set_secret(), applied at radcli_ctx_apply()
	 * time -- fills in authserver/acctserver's secret[0] only when not
	 * already set inline. --- */
	{
		SERVER *auth, *acct;

		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);

		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1") == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_ACCTSERVER, "127.0.0.1:2:already-set") == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SECRET, "shared") == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) == 0);

		if (radcli_ctx_apply(ctx) != 0) {
			fprintf(stderr, "error: radcli_ctx_apply() failed with the "
					"\"secret\" option set\n");
			exit(1);
		}

		auth = rc_conf_srv(ctx, "authserver");
		acct = rc_conf_srv(ctx, "acctserver");
		if (auth == NULL || acct == NULL ||
		    strcmp(auth->secret[0], "shared") != 0) {
			fprintf(stderr, "error: the \"secret\" option did not fill in "
					"authserver's unset secret\n");
			exit(1);
		}
		if (strcmp(acct->secret[0], "already-set") != 0) {
			fprintf(stderr, "error: the \"secret\" option overwrote "
					"acctserver's inline secret\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- radcli_ctx_set_tls_psk(): bytes in, no "@"-splitting. An
	 * identity that itself contains "@" (the legacy inline
	 * psk@username@hexkey form cannot represent this unambiguously) round-
	 * trips correctly. --- */
	{
		static const char identity[] = "alice@example.com";
		static const uint8_t key[] = { 0x01, 0x02, 0x00, 0x03, 0xff };

		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);

		if (radcli_ctx_set_tls_psk(ctx, identity, strlen(identity), key, sizeof(key)) != 0) {
			fprintf(stderr, "error: radcli_ctx_set_tls_psk() failed\n");
			exit(1);
		}

		if (radcli_ctx_set_tls_psk(NULL, identity, strlen(identity), key, sizeof(key)) == 0 ||
		    radcli_ctx_set_tls_psk(ctx, identity, strlen(identity), key, 0) == 0) {
			fprintf(stderr, "error: radcli_ctx_set_tls_psk() accepted a NULL "
					"ctx or a zero-length key\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- radcli_ctx_apply() with serv-type=tls actually consumes the PSK
	 * identity/key set above (lib/tls.c's rc_init_tls()): the TCP connect
	 * and TLS handshake are deferred to first send, so this exercises the
	 * gnutls_psk_set_client_credentials(..., GNUTLS_PSK_KEY_RAW) wiring
	 * without needing a reachable server. An identity containing "@" and a
	 * key with an embedded 0x00 byte -- both impossible to represent via
	 * the legacy "psk@username@hexkey" string form -- must work. --- */
	{
		static const char identity[] = "alice@example.com";
		static const uint8_t key[] = { 0x01, 0x02, 0x00, 0x03, 0xff };

		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);

		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:2083") == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) == 0);
		assert(radcli_ctx_set_tls_psk(ctx, identity, strlen(identity), key, sizeof(key)) == 0);

		if (radcli_ctx_apply(ctx) != 0) {
			fprintf(stderr, "error: radcli_ctx_apply() failed to set up "
					"TLS PSK credentials from radcli_ctx_set_tls_psk()\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- "tls-psk-identity"/"tls-psk-key" config options: the config-file
	 * counterpart of radcli_ctx_set_tls_psk(), consumed by rc_init_tls()
	 * without a radcli_ctx_set_tls_psk() call. Also checks that setting
	 * only one of the pair is rejected. --- */
	{
		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);

		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:2083") == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_PSK_IDENTITY, "alice@example.com") == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_PSK_KEY, "0102000ffe") == 0);

		if (radcli_ctx_apply(ctx) != 0) {
			fprintf(stderr, "error: radcli_ctx_apply() failed to set up "
					"TLS PSK credentials from tls-psk-identity/tls-psk-key\n");
			exit(1);
		}

		radcli_ctx_free(ctx);

		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);

		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:2083") == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_PSK_IDENTITY, "alice@example.com") == 0);

		if (radcli_ctx_apply(ctx) == 0) {
			fprintf(stderr, "error: radcli_ctx_apply() accepted "
					"tls-psk-identity without tls-psk-key\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- radcli_ctx_get_opt_str()/_get_opt_int(): round-trip a value set
	 * via the corresponding setter, and fail cleanly (not crash) for an
	 * unset option, a wrong-typed option, or an out-of-range opt. --- */
	{
		long ival = -1;

		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1") == 0);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DICTIONARY, "extra-dict-unit-tmp") == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) == 0);

		if (strcmp(radcli_ctx_get_opt_str(ctx, RADCLI_OPT_DICTIONARY), "extra-dict-unit-tmp") != 0) {
			fprintf(stderr, "error: radcli_ctx_get_opt_str() did not "
					"round-trip the value set via radcli_ctx_set_opt_str()\n");
			exit(1);
		}
		if (radcli_ctx_get_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, &ival) != 0 || ival != 5) {
			fprintf(stderr, "error: radcli_ctx_get_opt_int() did not "
					"round-trip the value set via radcli_ctx_set_opt_int()\n");
			exit(1);
		}

		/* Unset option. */
		if (radcli_ctx_get_opt_str(ctx, RADCLI_OPT_NAS_IDENTIFIER) != NULL) {
			fprintf(stderr, "error: radcli_ctx_get_opt_str() returned non-NULL "
					"for an unset option\n");
			exit(1);
		}
		/* Wrong-typed option (RADCLI_OPT_TYPE_INT via the str getter, RADCLI_OPT_TYPE_STR via the
		 * int getter). */
		if (radcli_ctx_get_opt_str(ctx, RADCLI_OPT_RADIUS_TIMEOUT) != NULL) {
			fprintf(stderr, "error: radcli_ctx_get_opt_str() accepted an "
					"RADCLI_OPT_TYPE_INT option\n");
			exit(1);
		}
		ival = -1;
		if (radcli_ctx_get_opt_int(ctx, RADCLI_OPT_AUTHSERVER, &ival) == 0) {
			fprintf(stderr, "error: radcli_ctx_get_opt_int() accepted an "
					"RADCLI_OPT_TYPE_SRV option\n");
			exit(1);
		}
		/* out == NULL and out-of-range opt must fail cleanly, not crash. */
		if (radcli_ctx_get_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, NULL) == 0) {
			fprintf(stderr, "error: radcli_ctx_get_opt_int() accepted a "
					"NULL out parameter\n");
			exit(1);
		}
		if (radcli_ctx_get_opt_str(ctx, (radcli_opt_id)RADCLI_OPT_COUNT) != NULL ||
		    radcli_ctx_get_opt_int(ctx, (radcli_opt_id)RADCLI_OPT_COUNT, &ival) == 0) {
			fprintf(stderr, "error: the getters accepted an out-of-range opt\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- watchdog-interval's default (15) is materialized into the config
	 * table at radcli_ctx_apply() time (REQ-CONFIG-CFG-021), not just used
	 * as a runtime fallback internal readers substitute in -- so
	 * radcli_ctx_get_opt_int() sees it too, even though the application
	 * never called radcli_ctx_set_opt_int() for it. Before apply(), it is
	 * still correctly unset. --- */
	{
		long ival = -1;

		ctx = radcli_ctx_new(0);
		assert(ctx != NULL);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1") == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) == 0);
		assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) == 0);

		if (radcli_ctx_get_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, &ival) == 0) {
			fprintf(stderr, "error: radcli_ctx_get_opt_int() reported "
					"watchdog-interval as set before radcli_ctx_apply()\n");
			exit(1);
		}

		if (radcli_ctx_apply(ctx) != 0) {
			fprintf(stderr, "error: radcli_ctx_apply() failed\n");
			exit(1);
		}

		if (radcli_ctx_get_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, &ival) != 0 || ival != 15) {
			fprintf(stderr, "error: radcli_ctx_get_opt_int() did not report "
					"watchdog-interval's default (15) after radcli_ctx_apply(), "
					"even though it was never explicitly set\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	radcli_ctx_free(NULL); /* must be a no-op, not a crash */

	printf("ctx: all tests passed\n");
	return 0;
}
