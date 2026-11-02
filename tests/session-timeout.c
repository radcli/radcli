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
 * Requests left unanswered on a TCP/TLS session, against
 * tests/session-timeout-server.py, with radius_timeout 1 (2 in stall)
 * and radius_retries 1:
 *
 *   once-blocking, once-sendonly  the peer never answers and keeps the
 *       connection open; the request must end in RADCLI_TIMEOUT, whatever
 *       non-RADIUS TLS records arrive meanwhile (REQ-NET-NET-021), sent
 *       only once (REQ-NET-NET-022, RFC 6613 SS2.6.1)
 *   drop-sendonly  the peer closes the connection unanswered; the request
 *       must be resent over a new connection and succeed (REQ-NET-NET-022)
 *   stall  a TLS peer closes the connection unanswered and then never
 *       completes a new handshake; no radcli_ctx_dispatch() call may wait
 *       for it (REQ-NET2-NET-001), and the request must time out
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <time.h>

/* Longest a radcli_ctx_dispatch() call may take in stall mode. */
#define MAX_DISPATCH_MS 200

static void die(const char *msg) __attribute__((noreturn));

static void die(const char *msg)
{
	fprintf(stderr, "session-timeout: %s\n", msg);
	exit(1);
}

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static radcli_request *new_request(radcli_ctx *ctx)
{
	radcli_avp_list *send_list;
	radcli_request *r;

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "radcli-timeout") != 0)
		die("radcli_avp_add_str_by_num");
	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new");
	return r;
}

/* Drives r to its result through radcli_ctx_get_poll()/radcli_ctx_dispatch(),
 * failing if any dispatch call takes longer than max_dispatch_ms (if > 0). */
static int drive(radcli_ctx *ctx, radcli_request *r, double max_dispatch_ms)
{
	int iterations = 0;
	int rc;

	while ((rc = radcli_request_done(r)) == RADCLI_AGAIN) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;
		double start;

		if (++iterations > 10000)
			die("the request never completed");
		if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0)
			die("radcli_ctx_get_poll");
		poll(pfds, (nfds_t)nfds, timeout_ms);
		start = now_ms();
		if (radcli_ctx_dispatch(ctx) != 0)
			die("radcli_ctx_dispatch");
		if (max_dispatch_ms > 0 && now_ms() - start > max_dispatch_ms) {
			fprintf(stderr, "session-timeout: radcli_ctx_dispatch() took %.0f ms\n",
				now_ms() - start);
			exit(1);
		}
	}
	return rc;
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_request *r;
	char authserver[64];
	const char *mode;
	int tls, stall, rc;

	if (argc != 5) {
		fprintf(stderr, "usage: %s tls <port> <tls-ca-file> <mode>\n"
				"       %s tcp <port> <secret> <mode>\n", argv[0], argv[0]);
		return 2;
	}
	tls = strcmp(argv[1], "tls") == 0;
	mode = argv[4];
	stall = strcmp(mode, "stall") == 0;

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
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, stall ? 2 : 1) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 0) != 0)
		die("option setup failed");
	if (radcli_ctx_apply(ctx) != 0)
		die("radcli_ctx_apply");

	if (strcmp(mode, "once-blocking") == 0) {
		r = new_request(ctx);
		rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
		if (rc != RADCLI_TIMEOUT)
			die("an unanswered request did not time out");
	} else if (strcmp(mode, "once-sendonly") == 0) {
		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
			die("radcli_request_perform(RADCLI_REQUEST_SENDONLY)");
		if (drive(ctx, r, 0) != RADCLI_TIMEOUT)
			die("an unanswered request did not time out");
	} else if (strcmp(mode, "drop-sendonly") == 0) {
		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
			die("radcli_request_perform(RADCLI_REQUEST_SENDONLY)");
		rc = drive(ctx, r, 0);
		if (rc != RADCLI_OK || radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT)
			die("the request resent over a new connection did not succeed");
	} else if (stall) {
		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_NONE) != RADCLI_OK)
			die("the warm-up request failed");
		radcli_request_free(r);
		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
			die("radcli_request_perform(RADCLI_REQUEST_SENDONLY)");
		if (drive(ctx, r, MAX_DISPATCH_MS) == RADCLI_OK)
			die("a request whose server never answered succeeded");
	} else {
		die("unknown mode");
	}

	radcli_request_free(r);
	radcli_ctx_free(ctx);
	printf("session-timeout: %s passed\n", mode);
	return 0;
}
