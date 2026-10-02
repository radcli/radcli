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

/* Reply validation on the RADCLI_REQUEST_SENDONLY path: a reply the
 * request-registry drain must discard, so the request times out instead of
 * completing. Run by tests/request-async-validation-tests.sh against
 * tests/radius-server.py in two modes:
 *
 * --stale-truncated: the complete valid reply under another Identifier
 * (discarded, but left in the client's receive buffer), then only the real
 * reply's header; a client that skips the length check authenticates that
 * header over the leftover bytes (REQ-NET2-SEND-017).
 *
 * --spoof-source: the valid reply, sent from another port than the server's;
 * the shared request socket is unconnected, so only an explicit source check
 * rejects it (REQ-NET2-SEND-016). */

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>
#include <unistd.h>

#include <radcli/radcli2.h>

static void die(const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(1);
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_avp_list *send_list;
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

	send_list = radcli_avp_list_new();
	if (send_list == NULL ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "erin") != 0 ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_PASSWORD, 0, "test") != 0)
		die("attribute setup");
	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new");

	if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
		die("radcli_request_perform(RADCLI_REQUEST_SENDONLY)");

	/* Both datagrams must be queued before the first dispatch, so one
	 * drain reads them back to back into the same buffer. */
	usleep(500000);

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

	if (rc != RADCLI_TIMEOUT) {
		fprintf(stderr, "error: a reply that must be discarded was accepted "
				"(radcli_request_done() returned %d, expected "
				"RADCLI_TIMEOUT)\n", rc);
		return 1;
	}

	radcli_request_free(r);
	radcli_ctx_free(ctx);
	printf("OK: reply discarded, request timed out\n");
	return 0;
}
