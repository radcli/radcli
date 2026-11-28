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

/* Reply validation on the RADCLI_REQUEST_SENDONLY path, run by
 * tests/request-async-validation-tests.sh against tests/radius-server.py,
 * which picks the peer's behaviour, the retry count, whether the request
 * must end in the Access-Accept, in RADCLI_TIMEOUT or in RADCLI_ERROR, and
 * optionally whether it is sent with RADCLI_REQUEST_SENDONLY_NONBLOCK
 * instead and the require-message-authenticator setting:
 *
 * --stale-truncated: the complete valid reply under another Identifier
 * (discarded, but left in the client's receive buffer), then only the real
 * reply's header; a client that skips the length check authenticates that
 * header over the leftover bytes (REQ-NET-ERR-005). Must time out.
 *
 * --short-datagrams-first: datagrams shorter than the header or than their
 * own Length ahead of the real reply, which must still be accepted
 * (REQ-NET-ERR-005).
 *
 * --spoof-source: the valid reply, sent from another port than the server's;
 * the shared request socket is unconnected, so only an explicit source check
 * rejects it (REQ-NET-NET-024). Must time out.
 *
 * --spoof-address: the same, sent from the server's port on another
 * address (REQ-NET-NET-024). Must time out.
 *
 * --other-port-first: a datagram from another port answers the first
 * transmission; the retransmission must still go to the server, whose reply
 * is accepted (REQ-NET-NET-024).
 *
 * --bad-resp-auth: the reply with a wrong Response Authenticator
 * (REQ-NET-SEC-004). Must time out.
 *
 * --forged-first: an Access-Reject with a wrong Response Authenticator
 * ahead of the real reply, which must still be accepted (REQ-NET-SEC-004).
 *
 * --msg-auth absent|not-first|wrong|resp-auth-vector|bad-length: a reply
 * whose Message-Authenticator fails verification (REQ-NET-SEC-005..007).
 * Must end in RADCLI_ERROR, unless require-message-authenticator is "no" and
 * only its presence or position is wrong. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
	int retries = 0, expect_timeout = 1, expect_error = 0;
	unsigned flags = RADCLI_REQUEST_SENDONLY;
	int rc, iterations = 0;

	if (argc < 3 || argc == 4 || argc > 7) {
		fprintf(stderr, "usage: %s <port> <secret> [<retries> accept|timeout|error "
				"[sendonly|nonblock [<require-message-authenticator>]]]\n", argv[0]);
		return 2;
	}
	if (argc >= 5) {
		retries = atoi(argv[3]);
		expect_timeout = strcmp(argv[4], "timeout") == 0;
		expect_error = strcmp(argv[4], "error") == 0;
	}
	if (argc >= 6 && strcmp(argv[5], "nonblock") == 0)
		flags = RADCLI_REQUEST_SENDONLY_NONBLOCK;

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");
	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s:%s", argv[1], argv[2]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 2) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, retries) != 0 ||
	    (argc == 7 && radcli_ctx_set_opt_str(ctx, RADCLI_OPT_REQUIRE_MESSAGE_AUTHENTICATOR,
						 argv[6]) != 0) ||
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

	if (radcli_request_perform(r, flags) != RADCLI_OK)
		die("radcli_request_perform()");

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

	if (expect_error) {
		if (rc != RADCLI_ERROR) {
			fprintf(stderr, "error: radcli_request_done() returned %d, code %d; "
					"expected RADCLI_ERROR\n", rc, (int)radcli_request_code(r));
			return 1;
		}
		radcli_request_free(r);
		radcli_ctx_free(ctx);
		printf("OK: the reply was rejected\n");
		return 0;
	}
	if (expect_timeout) {
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
	if (rc != RADCLI_OK || radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "error: radcli_request_done() returned %d, code %d; "
				"expected the Access-Accept that followed the discarded "
				"datagram\n", rc, (int)radcli_request_code(r));
		return 1;
	}

	radcli_request_free(r);
	radcli_ctx_free(ctx);
	printf("OK: datagram discarded, the real reply accepted\n");
	return 0;
}
