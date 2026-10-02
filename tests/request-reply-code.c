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

/* radcli_request_code() must report 0 unless the request succeeded
 * (REQ-NET2-RECV-015). The peer, tests/radius-server.py --reply-code 42,
 * answers with a correctly authenticated reply whose code radcli does not
 * accept, so the request fails with RADCLI_ERROR -- through
 * radcli_request_perform() and through radcli_request_done() alike --
 * and that unaccepted code must not be reported as the request's outcome. */

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>

#include <radcli/radcli2.h>

static void die(const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(1);
}

static radcli_request *new_request(radcli_ctx *ctx)
{
	radcli_avp_list *send_list = radcli_avp_list_new();
	radcli_request *r;

	if (send_list == NULL ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "frank") != 0 ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_PASSWORD, 0, "test") != 0)
		die("attribute setup");
	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new");
	return r;
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_request *r;
	char authserver[160];
	int rc, iterations = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <port> <secret>\n", argv[0]);
		return 2;
	}

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");
	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s:%s", argv[1], argv[2]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 2) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) != 0 ||
	    radcli_ctx_apply(ctx) != 0)
		die("context setup");

	r = new_request(ctx);
	rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
	if (rc != RADCLI_ERROR) {
		fprintf(stderr, "error: radcli_request_perform() returned %d, expected "
				"RADCLI_ERROR\n", rc);
		return 1;
	}
	if (radcli_request_code(r) != 0) {
		fprintf(stderr, "error: radcli_request_code() returned %d after a failed "
				"radcli_request_perform(), expected 0\n",
			(int)radcli_request_code(r));
		return 1;
	}
	radcli_request_free(r);

	r = new_request(ctx);
	if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
		die("radcli_request_perform(RADCLI_REQUEST_SENDONLY)");
	while ((rc = radcli_request_done(r)) == RADCLI_AGAIN) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;

		if (++iterations > 100)
			die("radcli_request_done() never left RADCLI_AGAIN");
		if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0)
			die("radcli_ctx_get_poll");
		poll(pfds, (nfds_t)nfds, timeout_ms);
		if (radcli_ctx_dispatch(ctx) != 0)
			die("radcli_ctx_dispatch");
	}
	if (rc != RADCLI_ERROR) {
		fprintf(stderr, "error: radcli_request_done() returned %d, expected "
				"RADCLI_ERROR\n", rc);
		return 1;
	}
	if (radcli_request_code(r) != 0) {
		fprintf(stderr, "error: radcli_request_code() returned %d after "
				"radcli_request_done() failed, expected 0\n",
			(int)radcli_request_code(r));
		return 1;
	}
	radcli_request_free(r);

	radcli_ctx_free(ctx);
	printf("OK: radcli_request_code() is 0 after a failed request\n");
	return 0;
}
