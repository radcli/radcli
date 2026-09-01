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

/* Unit test for radcli2.h's radcli_request_new()/_free() construction and
 * validation logic (lib/request.c) -- the parts that need no network I/O.
 * A successful send/receive round trip against a real server is instead
 * covered by tests/request-freeradius.c (needs root + FreeRADIUS), per this
 * project's interoperability-testing rule: a fake/local server would only
 * prove radcli agrees with itself, not with a real RADIUS implementation. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>

#include <radcli/radcli2.h>

static double test_mtime(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

/* radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, ...) carries exactly
 * one server per role (REQ-NET2-INIT-003, lib/config2.c) -- a second call,
 * or a comma-separated value, is rejected (see tests/ctx.c). Only
 * radcli_ctx_read_config()'s file-based path still accumulates multiple
 * "authserver" lines the way rc_read_config() always has, needed by the
 * two-authserver decision-G block below. */
static const char tmpl[] = "request-unit-XXXXXX";

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

static char test_dict[] =
"ATTRIBUTE	User-Name		1	string\n";

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_avp_list *send_list;
	const radcli_attr_def *d_user;
	radcli_request *r;

	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	assert(radcli_ctx_read_dictionary_from_buffer(ctx, test_dict, sizeof(test_dict)) == 0);

	d_user = radcli_dict_lookup(ctx, "User-Name");
	assert(d_user != NULL);

	send_list = radcli_avp_list_new();
	assert(send_list != NULL);
	assert(radcli_avp_add_str(send_list, d_user, "alice") == 0);

	/* --- no authserver/acctserver configured: NULL --- */

	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	if (r != NULL) {
		fprintf(stderr, "error: radcli_request_new() succeeded with no "
				"authserver configured\n");
		exit(1);
	}

	/* --- a reply-only code is not a valid request code: NULL --- */

	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_ACCEPT, send_list);
	if (r != NULL) {
		fprintf(stderr, "error: radcli_request_new() accepted "
				"RADCLI_CODE_ACCESS_ACCEPT as a request code\n");
		exit(1);
	}

	/* --- NULL ctx: NULL, not a crash --- */

	r = radcli_request_new(NULL, RADCLI_CODE_ACCESS_REQUEST, send_list);
	if (r != NULL) {
		fprintf(stderr, "error: radcli_request_new(NULL, ...) did not fail\n");
		exit(1);
	}

	/* --- with an authserver configured, construction succeeds and
	 * radcli_request_server() reports it, before any perform() --- */

	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 1) == 0);
	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "192.0.2.1:1812:testing123") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_ACCTSERVER, "192.0.2.1:1813:testing123") == 0);
	assert(radcli_ctx_apply(ctx) == 0);

	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	if (r == NULL) {
		fprintf(stderr, "error: radcli_request_new() failed with an "
				"authserver configured\n");
		exit(1);
	}

	/* radcli2.h documents that "send" is copied in and may be freed
	 * immediately once radcli_request_new() returns -- freeing it here,
	 * before radcli_request_perform() ever reads r's copy, is exactly
	 * the pattern tests/request-freeradius.c uses against a real server.
	 * If radcli_request_new() only aliased the caller's pointer instead
	 * of copying it, this would be a use-after-free the moment perform()
	 * below calls radcli_avp_encode(). */
	radcli_avp_list_free(send_list);

	if (strcmp(radcli_request_server(r), "192.0.2.1") != 0) {
		fprintf(stderr, "error: radcli_request_server() returned \"%s\" "
				"before perform(), expected \"192.0.2.1\"\n",
			radcli_request_server(r));
		exit(1);
	}
	if (radcli_request_code(r) != 0) {
		fprintf(stderr, "error: radcli_request_code() returned nonzero "
				"before perform()\n");
		exit(1);
	}
	if (radcli_request_attrs(r) != NULL) {
		fprintf(stderr, "error: radcli_request_attrs() returned non-NULL "
				"before perform()\n");
		exit(1);
	}

	/* 192.0.2.1 is TEST-NET-1 (RFC 5737): reserved, never routed, so this
	 * reliably times out instead of depending on any reachable server. */
	if (radcli_request_perform(r, 0) != RADCLI_TIMEOUT) {
		fprintf(stderr, "error: radcli_request_perform() against an "
				"unreachable server did not return RADCLI_TIMEOUT\n");
		exit(1);
	}

	/* Calling perform() a second time on an already-performed request
	 * must fail rather than resend. */
	if (radcli_request_perform(r, 0) != RADCLI_ERROR) {
		fprintf(stderr, "error: a second radcli_request_perform() call "
				"did not return RADCLI_ERROR\n");
		exit(1);
	}

	/* --- r above was performed via the blocking path (flags 0), which
	 * never touches r's async state: radcli_request_done() must report
	 * "no async exchange" (RADCLI_ERROR), not crash or somehow read stale
	 * state --- */

	if (radcli_request_done(r) != RADCLI_ERROR) {
		fprintf(stderr, "error: radcli_request_done() on a request never sent with "
				"RADCLI_REQUEST_SENDONLY did not return RADCLI_ERROR\n");
		exit(1);
	}

	radcli_request_free(r);

	/* --- radcli_request_perform() with RADCLI_REQUEST_SENDONLY, used as
	 * fire-and-forget: transmits once and returns RADCLI_OK without
	 * waiting, even though nothing is listening at 192.0.2.1 -- unlike
	 * the default flags, there is no reply to time out on. free()ing
	 * without ever calling radcli_request_wait() must not leak/hang --- */

	{
		radcli_avp_list *send_list2 = radcli_avp_list_new();

		assert(send_list2 != NULL);
		assert(radcli_avp_add_str(send_list2, d_user, "bob") == 0);

		r = radcli_request_new(ctx, RADCLI_CODE_ACCOUNTING_REQUEST, send_list2);
		radcli_avp_list_free(send_list2);
		if (r == NULL) {
			fprintf(stderr, "error: radcli_request_new(RADCLI_CODE_ACCOUNTING_REQUEST) "
					"failed with an acctserver configured\n");
			exit(1);
		}

		if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK) {
			fprintf(stderr, "error: radcli_request_perform(RADCLI_REQUEST_SENDONLY) did not "
					"return RADCLI_OK\n");
			exit(1);
		}

		/* Calling perform() a second time on an already-performed
		 * request must fail, regardless of flags. */
		if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_ERROR) {
			fprintf(stderr, "error: a second radcli_request_perform(RADCLI_REQUEST_SENDONLY) "
					"call did not return RADCLI_ERROR\n");
			exit(1);
		}
		if (radcli_request_perform(r, 0) != RADCLI_ERROR) {
			fprintf(stderr, "error: radcli_request_perform(0) after "
					"radcli_request_perform(RADCLI_REQUEST_SENDONLY) did not return "
					"RADCLI_ERROR\n");
			exit(1);
		}

		radcli_request_free(r); /* fire-and-forget: radcli_request_wait() never called */
	}

	/* --- radcli_request_perform() with RADCLI_REQUEST_SENDONLY, used for
	 * the poll-driven async request/reply path: driving
	 * radcli_ctx_get_poll()/radcli_ctx_dispatch() through a real poll()
	 * loop against 192.0.2.1 (never replies), reading the outcome with
	 * radcli_request_done(), ends in RADCLI_TIMEOUT, exactly as
	 * radcli_request_perform(r, 0)'s own blocking timeout test above did
	 * -- proving the two paths agree on the outcome, not just that async
	 * "doesn't crash". --- */

	{
		radcli_avp_list *send_list3 = radcli_avp_list_new();
		int rc, iterations = 0;

		assert(send_list3 != NULL);
		assert(radcli_avp_add_str(send_list3, d_user, "carol") == 0);

		r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list3);
		radcli_avp_list_free(send_list3);
		if (r == NULL) {
			fprintf(stderr, "error: radcli_request_new(RADCLI_CODE_ACCESS_REQUEST) "
					"failed with an authserver configured\n");
			exit(1);
		}

		if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK) {
			fprintf(stderr, "error: radcli_request_perform(RADCLI_REQUEST_SENDONLY) did not "
					"return RADCLI_OK for the async round trip\n");
			exit(1);
		}

		for (;;) {
			struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
			size_t nfds;
			int timeout_ms;

			if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0 ||
			    nfds == 0) {
				fprintf(stderr, "error: radcli_ctx_get_poll() failed or reported "
						"nothing to watch while a RADCLI_REQUEST_SENDONLY "
						"request was still in flight\n");
				exit(1);
			}
			poll(pfds, (nfds_t)nfds, timeout_ms);
			radcli_ctx_dispatch(ctx);

			rc = radcli_request_done(r);
			if (rc != RADCLI_AGAIN)
				break;

			/* Bound the loop: RADIUS_TIMEOUT=1s/RADIUS_RETRIES=0 above
			 * means this should resolve in a couple of iterations at
			 * most; a runaway loop here is itself the bug under test. */
			if (++iterations > 100) {
				fprintf(stderr, "error: radcli_request_done() never left "
						"RADCLI_AGAIN against an unreachable server\n");
				exit(1);
			}
		}

		if (rc != RADCLI_TIMEOUT) {
			fprintf(stderr, "error: radcli_request_done() against an unreachable "
					"server returned %d, expected RADCLI_TIMEOUT\n", rc);
			exit(1);
		}

		radcli_request_free(r);
	}

	radcli_ctx_free(ctx);

	/* --- by design, with more than one authserver entry configured,
	 * radcli_request_new() uses only the first -- no fail-over across
	 * the list, unlike rc_auth()/rc_acct() --
	 * so radcli_request_server() must report the first both before and
	 * after perform(), and a lone unreachable first entry must time out
	 * on its own single timeout, not one timeout per configured entry --- */

	{
		/* Both TEST-NET-1 and TEST-NET-2 (RFC 5737): reserved, never
		 * routed; only the first should ever be contacted.
		 *
		 * radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, ...) carries
		 * exactly one server per role (REQ-NET2-INIT-003) and rejects a
		 * comma-separated multi-host value (see tests/ctx.c) -- only
		 * radcli_ctx_read_config()'s file-based path still accumulates
		 * multiple "authserver" lines, so this goes through a temp config
		 * file instead, same as tests/aaa2.c's two-authserver block. That
		 * path routes through rc_test_config() (REQ-CONFIG-CFG-010), which
		 * requires radius_retries > 0 unlike the direct radcli_ctx_apply()
		 * the block above uses -- so radius_retries is 1 here (2 attempts),
		 * not 0, and the elapsed-time thresholds below are doubled to
		 * match. */
		static const char conf[] =
			"authserver 192.0.2.1:1812:testing123\n"
			"authserver 198.51.100.1:1812:testing123\n"
			"radius_timeout 1\n"
			"radius_retries 1\n";
		char *conf_path = write_conf(conf);
		radcli_ctx *ctx2;
		const radcli_attr_def *d_user2;
		radcli_avp_list *send_list3;
		radcli_request *r2;
		double start, elapsed;

		ctx2 = radcli_ctx_read_config(conf_path, 0);
		unlink(conf_path);
		assert(ctx2 != NULL);
		/* User-Name is part of the built-in RFC 2865 dictionary
		 * radcli_ctx_read_config() always loads. */
		d_user2 = radcli_dict_lookup(ctx2, "User-Name");
		assert(d_user2 != NULL);

		send_list3 = radcli_avp_list_new();
		assert(send_list3 != NULL);
		assert(radcli_avp_add_str(send_list3, d_user2, "carol") == 0);

		r2 = radcli_request_new(ctx2, RADCLI_CODE_ACCESS_REQUEST, send_list3);
		radcli_avp_list_free(send_list3);
		if (r2 == NULL) {
			fprintf(stderr, "error: radcli_request_new() failed with two "
					"authservers configured\n");
			exit(1);
		}
		if (strcmp(radcli_request_server(r2), "192.0.2.1") != 0) {
			fprintf(stderr, "error: radcli_request_server() before perform() "
					"returned \"%s\", expected the first configured "
					"server \"192.0.2.1\"\n", radcli_request_server(r2));
			exit(1);
		}

		start = test_mtime();
		if (radcli_request_perform(r2, 0) != RADCLI_TIMEOUT) {
			fprintf(stderr, "error: radcli_request_perform() with an "
					"unreachable first server did not return RADCLI_TIMEOUT\n");
			exit(1);
		}
		elapsed = test_mtime() - start;
		/* Two attempts against one server (~2s: radius_retries=1, 1s
		 * radius_timeout), not four (two servers): if this took over 3s,
		 * the second (unreachable) entry was tried too, which decision G
		 * forbids. */
		if (elapsed > 3.0) {
			fprintf(stderr, "error: radcli_request_perform() took %.2fs -- "
					"looks like it tried the second configured server "
					"too\n", elapsed);
			exit(1);
		}
		if (strcmp(radcli_request_server(r2), "192.0.2.1") != 0) {
			fprintf(stderr, "error: radcli_request_server() after perform() "
					"returned \"%s\", expected the first configured "
					"server \"192.0.2.1\" still -- no fail-over should "
					"have happened\n", radcli_request_server(r2));
			exit(1);
		}

		radcli_request_free(r2);
		radcli_ctx_free(ctx2);
	}

	printf("radcli2 request construction/validation: all tests passed\n");
	return 0;
}
