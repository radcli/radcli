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

/* Unit test for radcli2.h's radcli_aaa() (lib/aaa2.c) -- the parts that need
 * no network I/O: validation, and the fail-over-across-every-configured-
 * server behavior that is the whole point of this wrapper (as opposed to
 * radcli_request_new()'s single-server decision G, already covered by
 * tests/request.c). A successful send/receive round trip against a real
 * server is out of scope here, same rationale as tests/request.c's own
 * comment: a fake/local server would only prove radcli agrees with itself. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>

#include <radcli/radcli2.h>

/* radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, ...) carries exactly
 * one server per role (REQ-NET2-INIT-003, lib/config2.c) -- a second call,
 * or a comma-separated value, is rejected (see tests/ctx.c). Only
 * radcli_ctx_read_config()'s file-based path still accumulates multiple
 * "authserver" lines the way rc_read_config() always has, so the
 * two-authserver failover test below goes through a temp config file
 * instead of radcli_ctx_set_opt_str(). */
static const char tmpl[] = "aaa2-unit-XXXXXX";

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

static double test_mtime(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

static char test_dict[] =
"ATTRIBUTE	User-Name		1	string\n"
"ATTRIBUTE	Acct-Delay-Time		41	integer\n";

int main(void)
{
	radcli_ctx *ctx;
	radcli_avp_list *send_list;
	const radcli_attr_def *d_user;
	radcli_code out_code;
	radcli_avp_list *out_attrs;
	double start, elapsed;

	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	assert(radcli_ctx_read_dictionary_from_buffer(ctx, test_dict, sizeof(test_dict)) == 0);

	d_user = radcli_dict_lookup(ctx, "User-Name");
	assert(d_user != NULL);

	send_list = radcli_avp_list_new();
	assert(send_list != NULL);
	assert(radcli_avp_add_str(send_list, d_user, "alice") == 0);

	/* --- NULL ctx/send must fail cleanly --- */
	if (radcli_aaa(NULL, RADCLI_CODE_ACCESS_REQUEST, send_list, NULL, NULL) != RADCLI_ERROR) {
		fprintf(stderr, "error: radcli_aaa(NULL, ...) did not return RADCLI_ERROR\n");
		exit(1);
	}
	if (radcli_aaa(ctx, RADCLI_CODE_ACCESS_REQUEST, NULL, NULL, NULL) != RADCLI_ERROR) {
		fprintf(stderr, "error: radcli_aaa(ctx, ..., NULL, ...) did not return RADCLI_ERROR\n");
		exit(1);
	}

	/* --- a reply-only code is not a valid request code --- */
	if (radcli_aaa(ctx, RADCLI_CODE_ACCESS_ACCEPT, send_list, NULL, NULL) != RADCLI_ERROR) {
		fprintf(stderr, "error: radcli_aaa() accepted RADCLI_CODE_ACCESS_ACCEPT as a request code\n");
		exit(1);
	}

	/* --- no authserver configured --- */
	if (radcli_aaa(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list, NULL, NULL) != RADCLI_ERROR) {
		fprintf(stderr, "error: radcli_aaa() with no authserver configured did not return RADCLI_ERROR\n");
		exit(1);
	}

	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 1) == 0);
	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) == 0);

	/* --- a single unreachable authserver: one timeout --- */
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "192.0.2.1:1812:testing123") == 0);
	assert(radcli_ctx_apply(ctx) == 0);

	start = test_mtime();
	if (radcli_aaa(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list, &out_code, &out_attrs) != RADCLI_TIMEOUT) {
		fprintf(stderr, "error: radcli_aaa() against a single unreachable "
				"server did not return RADCLI_TIMEOUT\n");
		exit(1);
	}
	elapsed = test_mtime() - start;
	if (elapsed > 1.5) {
		fprintf(stderr, "error: radcli_aaa() took %.2fs against a single "
				"1s-timeout server, expected ~1s\n", elapsed);
		exit(1);
	}

	radcli_ctx_free(ctx);

	/* --- two unreachable authservers: radcli_aaa() must fail over and try
	 * both (unlike radcli_request_new()'s decision G, tests/request.c),
	 * so this must take ~4s, not ~2 (2 attempts/server -- radius_retries=1,
	 * since radcli_ctx_read_config() routes through rc_test_config(),
	 * REQ-CONFIG-CFG-010, which unlike the direct radcli_ctx_apply() used
	 * in the single-authserver block above requires radius_retries > 0 --
	 * -- times 1s radius_timeout, times 2 servers). --- */
	{
		/* Both TEST-NET-1 and TEST-NET-2 (RFC 5737): reserved, never routed. */
		static const char conf[] =
			"authserver 192.0.2.1:1812:testing123\n"
			"authserver 198.51.100.1:1812:testing123\n"
			"radius_timeout 1\n"
			"radius_retries 1\n";
		char *conf_path = write_conf(conf);
		radcli_ctx *ctx2;
		const radcli_attr_def *d_user2;
		radcli_avp_list *send_list2;

		ctx2 = radcli_ctx_read_config(conf_path, 0);
		unlink(conf_path);
		assert(ctx2 != NULL);
		/* User-Name is part of the built-in RFC 2865 dictionary
		 * radcli_ctx_read_config() always loads -- no separate dictionary
		 * load needed, unlike the radcli_ctx_new()-based blocks in this
		 * file. */
		d_user2 = radcli_dict_lookup(ctx2, "User-Name");
		assert(d_user2 != NULL);

		send_list2 = radcli_avp_list_new();
		assert(send_list2 != NULL);
		assert(radcli_avp_add_str(send_list2, d_user2, "bob") == 0);

		start = test_mtime();
		if (radcli_aaa(ctx2, RADCLI_CODE_ACCESS_REQUEST, send_list2, NULL, NULL) != RADCLI_TIMEOUT) {
			fprintf(stderr, "error: radcli_aaa() against two unreachable "
					"servers did not return RADCLI_TIMEOUT\n");
			exit(1);
		}
		elapsed = test_mtime() - start;
		if (elapsed < 3.6) {
			fprintf(stderr, "error: radcli_aaa() with two configured "
					"authservers took only %.2fs -- expected ~4s "
					"(2 attempts/server, 1s radius_timeout, 2 servers), "
					"it looks like it did not fail over to the second "
					"entry\n", elapsed);
			exit(1);
		}
		if (elapsed > 5.0) {
			fprintf(stderr, "error: radcli_aaa() took %.2fs against two "
					"servers at 2 attempts each, expected ~4s\n", elapsed);
			exit(1);
		}

		radcli_avp_list_free(send_list2);
		radcli_ctx_free(ctx2);
	}

	/* --- issue #102 / REQ-CONFIG-CFG-010: radius_retries 0 through the
	 * config-file path (radcli_ctx_read_config()), which used to reject
	 * radius_retries 0 outright -- the two-authserver block above is
	 * pinned to radius_retries 1 for exactly that reason. This confirms
	 * both that the config now loads *and* that radcli_aaa() actually
	 * performs a single attempt with no retransmit against an
	 * unreachable server (elapsed ~1s, i.e. one radius_timeout, not ~2s
	 * as a silently-ignored retry would produce), not just that parsing
	 * accepts the value -- that half is already covered by
	 * tests/config-unit.c. --- */
	{
		static const char conf[] =
			"authserver 192.0.2.1:1812:testing123\n"
			"radius_timeout 1\n"
			"radius_retries 0\n";
		char *conf_path = write_conf(conf);
		radcli_ctx *ctx4;
		const radcli_attr_def *d_user4;
		radcli_avp_list *send_list4;

		ctx4 = radcli_ctx_read_config(conf_path, 0);
		unlink(conf_path);
		if (ctx4 == NULL) {
			fprintf(stderr, "error: radcli_ctx_read_config() rejected "
					"radius_retries 0 (issue #102 / REQ-CONFIG-CFG-010)\n");
			exit(1);
		}

		d_user4 = radcli_dict_lookup(ctx4, "User-Name");
		assert(d_user4 != NULL);

		send_list4 = radcli_avp_list_new();
		assert(send_list4 != NULL);
		assert(radcli_avp_add_str(send_list4, d_user4, "dave") == 0);

		start = test_mtime();
		if (radcli_aaa(ctx4, RADCLI_CODE_ACCESS_REQUEST, send_list4, NULL, NULL) != RADCLI_TIMEOUT) {
			fprintf(stderr, "error: radcli_aaa() with radius_retries 0 "
					"(config-file path) against an unreachable server did "
					"not return RADCLI_TIMEOUT\n");
			exit(1);
		}
		elapsed = test_mtime() - start;
		if (elapsed < 0.8) {
			fprintf(stderr, "error: radcli_aaa() with radius_retries 0 "
					"returned after only %.2fs -- expected ~1s (it should "
					"still make its one attempt and wait radius_timeout "
					"seconds for a reply, not fail immediately)\n", elapsed);
			exit(1);
		}
		if (elapsed > 1.5) {
			fprintf(stderr, "error: radcli_aaa() with radius_retries 0 took "
					"%.2fs -- expected ~1s (a single attempt, no "
					"retransmit); a ~2s result would mean radius_retries 0 "
					"was silently treated as if it allowed one retry\n",
					elapsed);
			exit(1);
		}

		radcli_avp_list_free(send_list4);
		radcli_ctx_free(ctx4);
	}

	/* --- an Accounting-Request exercises the Acct-Delay-Time autofill
	 * path; no live server to inspect wire content against, but this at
	 * least confirms the code path completes without crashing and still
	 * honors the single-timeout-per-server contract --- */
	{
		radcli_ctx *ctx3;
		const radcli_attr_def *d_user3;
		radcli_avp_list *send_list3;

		ctx3 = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		assert(ctx3 != NULL);
		assert(radcli_ctx_read_dictionary_from_buffer(ctx3, test_dict, sizeof(test_dict)) == 0);
		d_user3 = radcli_dict_lookup(ctx3, "User-Name");
		assert(d_user3 != NULL);

		assert(radcli_ctx_set_opt_int(ctx3, RADCLI_OPT_RADIUS_TIMEOUT, 1) == 0);
		assert(radcli_ctx_set_opt_int(ctx3, RADCLI_OPT_RADIUS_RETRIES, 0) == 0);
		assert(radcli_ctx_set_opt_str(ctx3, RADCLI_OPT_ACCTSERVER, "192.0.2.1:1813:testing123") == 0);
		assert(radcli_ctx_apply(ctx3) == 0);

		send_list3 = radcli_avp_list_new();
		assert(send_list3 != NULL);
		assert(radcli_avp_add_str(send_list3, d_user3, "carol") == 0);

		start = test_mtime();
		if (radcli_aaa(ctx3, RADCLI_CODE_ACCOUNTING_REQUEST, send_list3, NULL, NULL) != RADCLI_TIMEOUT) {
			fprintf(stderr, "error: radcli_aaa(RADCLI_CODE_ACCOUNTING_REQUEST) "
					"against an unreachable acctserver did not return "
					"RADCLI_TIMEOUT\n");
			exit(1);
		}
		elapsed = test_mtime() - start;
		if (elapsed > 1.5) {
			fprintf(stderr, "error: radcli_aaa(RADCLI_CODE_ACCOUNTING_REQUEST) "
					"took %.2fs, expected ~1s\n", elapsed);
			exit(1);
		}

		radcli_avp_list_free(send_list3);
		radcli_ctx_free(ctx3);
	}

	radcli_avp_list_free(send_list);

	printf("radcli2 radcli_aaa(): all tests passed\n");
	return 0;
}
