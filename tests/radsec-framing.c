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
 *
 * REQ-NET-NET-020: replies on a TLS session are delimited by their RADIUS
 * Length field, not by TLS record boundaries. Sends two Access-Requests to
 * tests/radsec-framing-server.py and expects an Access-Accept for each:
 *
 *   blocking  two sequential radcli_request_perform() calls
 *   sendonly  two RADCLI_REQUEST_SENDONLY requests in flight together,
 *             driven by radcli_ctx_get_poll()/radcli_ctx_dispatch()
 *   badlen    the first reply has an invalid Length and must fail the
 *             request; the second request must then succeed (the peer only
 *             answers it on a new connection)
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

#define NREQ 2

static void die(const char *msg) __attribute__((noreturn));

static void die(const char *msg)
{
	fprintf(stderr, "radsec-framing: %s\n", msg);
	exit(1);
}

static radcli_request *new_request(radcli_ctx *ctx)
{
	radcli_avp_list *send_list;
	radcli_request *r;

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "radcli-framing") != 0 ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_PASSWORD, 0, "test") != 0)
		die("radcli_avp_add_str_by_num");
	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new");
	return r;
}

static void expect_accept(radcli_request *r, int rc, const char *what)
{
	if (rc != RADCLI_OK || radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "radsec-framing: %s returned %d, code %d; expected an "
			"Access-Accept\n", what, rc, (int)radcli_request_code(r));
		exit(1);
	}
}

static void run_sendonly(radcli_ctx *ctx)
{
	radcli_request *r[NREQ];
	int rc[NREQ];
	int pending = NREQ;
	int iterations = 0;
	int i;

	for (i = 0; i < NREQ; i++) {
		r[i] = new_request(ctx);
		if (radcli_request_perform(r[i], RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
			die("radcli_request_perform(RADCLI_REQUEST_SENDONLY)");
		rc[i] = RADCLI_AGAIN;
	}

	while (pending > 0) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;

		if (++iterations > 200)
			die("requests never completed");
		if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0)
			die("radcli_ctx_get_poll");
		poll(pfds, (nfds_t)nfds, timeout_ms);
		if (radcli_ctx_dispatch(ctx) != 0)
			die("radcli_ctx_dispatch");
		for (i = 0; i < NREQ; i++) {
			if (rc[i] != RADCLI_AGAIN)
				continue;
			rc[i] = radcli_request_done(r[i]);
			if (rc[i] != RADCLI_AGAIN)
				pending--;
		}
	}

	for (i = 0; i < NREQ; i++) {
		expect_accept(r[i], rc[i], "RADCLI_REQUEST_SENDONLY request");
		radcli_request_free(r[i]);
	}
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_request *r;
	char authserver[64];
	const char *mode;
	int badlen;
	int i;

	if (argc != 4) {
		fprintf(stderr, "usage: %s <port> <tls-ca-file> blocking|sendonly|badlen\n", argv[0]);
		return 2;
	}
	mode = argv[3];
	badlen = strcmp(mode, "badlen") == 0;

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");

	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[1]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[2]) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, badlen ? 2 : 5) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) != 0)
		die("option setup failed");
	if (radcli_ctx_apply(ctx) != 0)
		die("radcli_ctx_apply");

	if (strcmp(mode, "sendonly") == 0) {
		run_sendonly(ctx);
	} else if (strcmp(mode, "blocking") == 0 || badlen) {
		for (i = 0; i < NREQ; i++) {
			int rc;

			r = new_request(ctx);
			rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
			if (badlen && i == 0) {
				if (rc == RADCLI_OK)
					die("a reply with an invalid Length was accepted");
			} else {
				expect_accept(r, rc, "radcli_request_perform()");
			}
			radcli_request_free(r);
		}
	} else {
		die("unknown mode");
	}

	radcli_ctx_free(ctx);
	printf("radsec-framing: %s passed\n", mode);
	return 0;
}
