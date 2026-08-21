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

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

static double test_mtime(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

static char test_dict[] =
"ATTRIBUTE	User-Name		1	string\n";

int main(int argc, char **argv)
{
	rc_handle *rh;
	radcli_ctx *ctx;
	radcli_avp_list *send_list;
	const radcli_attr_def *d_user;
	radcli_request *r;

	rh = rc_new();
	assert(rh != NULL);
	rc_config_init(rh);
	assert(rc_read_dictionary_from_buffer(rh, test_dict, sizeof(test_dict)) == 0);
	ctx = rh;

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

	assert(rc_add_config(rh, "radius_timeout", "1", "config", 0) == 0);
	assert(rc_add_config(rh, "radius_retries", "0", "config", 0) == 0);
	assert(rc_add_config(rh, "authserver", "192.0.2.1:1812:testing123", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);

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
	if (radcli_request_perform(r) != RADCLI_TIMEOUT) {
		fprintf(stderr, "error: radcli_request_perform() against an "
				"unreachable server did not return RADCLI_TIMEOUT\n");
		exit(1);
	}

	/* Calling perform() a second time on an already-performed request
	 * must fail rather than resend. */
	if (radcli_request_perform(r) != RADCLI_ERROR) {
		fprintf(stderr, "error: a second radcli_request_perform() call "
				"did not return RADCLI_ERROR\n");
		exit(1);
	}

	radcli_request_free(r);

	/* --- radcli_request_free(NULL) is a no-op --- */
	radcli_request_free(NULL);

	rc_dict_free(rh);
	rc_destroy(rh);

	/* --- decision G (doc/plan-api-modernization.md): with more than one
	 * authserver entry configured, radcli_request_new() uses only the
	 * first -- no fail-over across the list, unlike rc_auth()/rc_acct() --
	 * so radcli_request_server() must report the first both before and
	 * after perform(), and a lone unreachable first entry must time out
	 * on its own single timeout, not one timeout per configured entry --- */

	{
		rc_handle *rh2;
		radcli_ctx *ctx2;
		const radcli_attr_def *d_user2;
		radcli_avp_list *send_list3;
		radcli_request *r2;
		double start, elapsed;

		rh2 = rc_new();
		assert(rh2 != NULL);
		rc_config_init(rh2);
		assert(rc_read_dictionary_from_buffer(rh2, test_dict, sizeof(test_dict)) == 0);
		ctx2 = rh2;
		d_user2 = radcli_dict_lookup(ctx2, "User-Name");
		assert(d_user2 != NULL);

		assert(rc_add_config(rh2, "radius_timeout", "1", "config", 0) == 0);
		assert(rc_add_config(rh2, "radius_retries", "0", "config", 0) == 0);
		/* Both TEST-NET-1 and TEST-NET-2 (RFC 5737): reserved, never
		 * routed; only the first should ever be contacted. */
		assert(rc_add_config(rh2, "authserver",
				     "192.0.2.1:1812:testing123,198.51.100.1:1812:testing123",
				     "config", 0) == 0);
		assert(rc_apply_config(rh2) == 0);

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
		if (radcli_request_perform(r2) != RADCLI_TIMEOUT) {
			fprintf(stderr, "error: radcli_request_perform() with an "
					"unreachable first server did not return RADCLI_TIMEOUT\n");
			exit(1);
		}
		elapsed = test_mtime() - start;
		/* One 1s timeout, not two: if this took over 1.5s, the second
		 * (unreachable) entry was tried too, which decision G forbids. */
		if (elapsed > 1.5) {
			fprintf(stderr, "error: radcli_request_perform() took %.2fs against "
					"a 1s timeout -- looks like it tried the second "
					"configured server too\n", elapsed);
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
		rc_dict_free(rh2);
		rc_destroy(rh2);
	}

	printf("radcli2 request construction/validation: all tests passed\n");
	return 0;
}
