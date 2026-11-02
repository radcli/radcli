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
 * tests/session-timeout-server.py, with radius_timeout 1 and
 * radius_retries 0:
 *
 *   once-blocking  the peer never answers and keeps the connection open;
 *       a blocking request must end in RADCLI_TIMEOUT, whatever non-RADIUS
 *       TLS records (such as TLS 1.3 session tickets) arrive meanwhile
 *       (REQ-NET-NET-021)
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *msg) __attribute__((noreturn));

static void die(const char *msg)
{
	fprintf(stderr, "session-timeout: %s\n", msg);
	exit(1);
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

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_request *r;
	char authserver[64];
	const char *mode;
	int tls, rc;

	if (argc != 5) {
		fprintf(stderr, "usage: %s tls <port> <tls-ca-file> <mode>\n"
				"       %s tcp <port> <secret> <mode>\n", argv[0], argv[0]);
		return 2;
	}
	tls = strcmp(argv[1], "tls") == 0;
	mode = argv[4];

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
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 1) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 0) != 0)
		die("option setup failed");
	if (radcli_ctx_apply(ctx) != 0)
		die("radcli_ctx_apply");

	if (strcmp(mode, "once-blocking") == 0) {
		r = new_request(ctx);
		rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
		if (rc != RADCLI_TIMEOUT)
			die("an unanswered request did not time out");
	} else {
		die("unknown mode");
	}

	radcli_request_free(r);
	radcli_ctx_free(ctx);
	printf("session-timeout: %s passed\n", mode);
	return 0;
}
