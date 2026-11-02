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
 * REQ-NET-NET-020: replies on a TCP or TLS session are delimited by their
 * RADIUS Length field, not by how the peer split its writes; and
 * REQ-NET-NET-004: TCP carries every request over one connection. Sends two
 * requests to tests/session-framing-server.py, which answers only on its
 * first connection, and expects a reply for each:
 *
 *   blocking  two sequential radcli_request_perform() calls
 *   sendonly  two RADCLI_REQUEST_SENDONLY requests in flight together,
 *             driven by radcli_ctx_get_poll()/radcli_ctx_dispatch()
 *   acct      an Accounting-Request with no acctserver configured, then
 *             an Access-Request, both to the authserver
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
	fprintf(stderr, "session-framing: %s\n", msg);
	exit(1);
}

static radcli_request *new_request(radcli_ctx *ctx, radcli_code code)
{
	radcli_avp_list *send_list;
	radcli_request *r;

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "radcli-framing") != 0 ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_PASSWORD, 0, "test") != 0)
		die("radcli_avp_add_str_by_num");
	r = radcli_request_new(ctx, code, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new");
	return r;
}

static void expect_reply(radcli_request *r, int rc, radcli_code code, const char *what)
{
	if (rc != RADCLI_OK || radcli_request_code(r) != code) {
		fprintf(stderr, "session-framing: %s returned %d, code %d; expected "
			"code %d\n", what, rc, (int)radcli_request_code(r), (int)code);
		exit(1);
	}
}

static void run_sendonly(radcli_ctx *ctx, int nreq)
{
	radcli_request *r[NREQ];
	int rc[NREQ];
	int pending = nreq;
	int iterations = 0;
	int i;

	for (i = 0; i < nreq; i++) {
		r[i] = new_request(ctx, RADCLI_CODE_ACCESS_REQUEST);
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
		for (i = 0; i < nreq; i++) {
			if (rc[i] != RADCLI_AGAIN)
				continue;
			rc[i] = radcli_request_done(r[i]);
			if (rc[i] != RADCLI_AGAIN)
				pending--;
		}
	}

	for (i = 0; i < nreq; i++) {
		expect_reply(r[i], rc[i], RADCLI_CODE_ACCESS_ACCEPT, "RADCLI_REQUEST_SENDONLY request");
		radcli_request_free(r[i]);
	}
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_request *r;
	char authserver[64];
	const char *mode;
	int tls, badlen, rc;
	int i;

	if (argc != 5) {
		fprintf(stderr, "usage: %s tls <port> <tls-ca-file> blocking|sendonly|badlen\n"
				"       %s tcp <port> <secret> blocking|sendonly|badlen|acct\n",
			argv[0], argv[0]);
		return 2;
	}
	tls = strcmp(argv[1], "tls") == 0;
	mode = argv[4];
	badlen = strcmp(mode, "badlen") == 0;

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");

	if (tls) {
		snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[2]);
		if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
		    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[3]) != 0)
			die("TLS option setup failed");
	} else {
		snprintf(authserver, sizeof(authserver), "127.0.0.1:%s:%s", argv[2], argv[3]);
		if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tcp") != 0)
			die("TCP option setup failed");
	}
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, badlen ? 2 : 5) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) != 0)
		die("option setup failed");
	if (radcli_ctx_apply(ctx) != 0)
		die("radcli_ctx_apply");

	if (strcmp(mode, "sendonly") == 0) {
		run_sendonly(ctx, NREQ);
	} else if (strcmp(mode, "acct") == 0) {
		r = new_request(ctx, RADCLI_CODE_ACCOUNTING_REQUEST);
		rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
		expect_reply(r, rc, RADCLI_CODE_ACCOUNTING_RESPONSE, "Accounting-Request");
		radcli_request_free(r);
		run_sendonly(ctx, 1);
	} else if (strcmp(mode, "blocking") == 0 || badlen) {
		for (i = 0; i < NREQ; i++) {
			r = new_request(ctx, RADCLI_CODE_ACCESS_REQUEST);
			rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
			if (badlen && i == 0) {
				if (rc == RADCLI_OK)
					die("a reply with an invalid Length was accepted");
			} else {
				expect_reply(r, rc, RADCLI_CODE_ACCESS_ACCEPT, "radcli_request_perform()");
			}
			radcli_request_free(r);
		}
	} else {
		die("unknown mode");
	}

	radcli_ctx_free(ctx);
	printf("session-framing: %s passed\n", mode);
	return 0;
}
