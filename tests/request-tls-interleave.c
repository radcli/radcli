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

/* Every record read from a RadSec session reaches the request it belongs
 * to, whichever call reads it (REQ-NET2-NET-004): a blocking
 * radcli_request_perform() on a TLS ctx must hand the reply to an
 * in-flight RADCLI_REQUEST_SENDONLY request to that request instead of
 * discarding it. Request A is sent with RADCLI_REQUEST_SENDONLY and no
 * retries; once its reply has arrived, blocking request B is performed and
 * reads it first. A must then complete with its Access-Accept. Peer:
 * tests/watchdog-aaa-server.py, which answers each Access-Request in
 * order. */

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>

#include <radcli/radcli2.h>

static void die(const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(1);
}

static radcli_request *new_request(radcli_ctx *ctx, const char *user)
{
	radcli_avp_list *send_list = radcli_avp_list_new();
	radcli_request *r;

	if (send_list == NULL ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, user) != 0 ||
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
	radcli_request *a, *b;
	char authserver[64];
	int rc, iterations = 0;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <port> <tls-ca-file>\n", argv[0]);
		return 2;
	}

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");
	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[1]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[2]) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 2) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) != 0 ||
	    radcli_ctx_apply(ctx) != 0)
		die("context setup");

	a = new_request(ctx, "interleave-a");
	if (radcli_request_perform(a, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
		die("radcli_request_perform(a, RADCLI_REQUEST_SENDONLY)");

	/* Let A's reply arrive before B starts reading the session. */
	poll(NULL, 0, 300);

	b = new_request(ctx, "interleave-b");
	rc = radcli_request_perform(b, RADCLI_REQUEST_NONE);
	if (rc != RADCLI_OK || radcli_request_code(b) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "error: blocking request returned %d, code %d\n",
			rc, (int)radcli_request_code(b));
		return 1;
	}
	radcli_request_free(b);

	while ((rc = radcli_request_done(a)) == RADCLI_AGAIN) {
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
	if (rc != RADCLI_OK || radcli_request_code(a) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "error: the async request's reply, read during the "
				"blocking request, was lost (radcli_request_done() "
				"returned %d)\n", rc);
		return 1;
	}
	radcli_request_free(a);

	radcli_ctx_free(ctx);
	printf("OK: the async reply read by a blocking request reached its request\n");
	return 0;
}
