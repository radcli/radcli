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

/* Over a TLS/DTLS session every request in flight -- async, blocking or
 * watchdog -- needs its own Identifier (REQ-NET2-SEND-010). This fills the
 * ctx's in-flight registry directly (lib/ internals, like
 * tests/dae-codec.c) and checks, against tests/watchdog-aaa-server.py's
 * log, that:
 *   - with one Identifier free, a blocking request uses exactly that one;
 *   - with none free, a blocking request fails without sending and a due
 *     watchdog is skipped;
 *   - once one is freed, the watchdog uses exactly that one.
 * Prints the Identifiers it expects so tests/radsec-shared-ids-tests.sh
 * can compare them with the peer's log. */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>

static void die(const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(1);
}

static struct radcli_async_send_st owners[RADCLI_CTX_MAX_INFLIGHT];

static int reserve(rc_handle *rh)
{
	static int n;
	uint8_t id;

	return radcli2_priv_reqreg_reserve(rh, &owners[n++], &id);
}

static int blocking_request(radcli_ctx *ctx)
{
	radcli_avp_list *send_list = radcli_avp_list_new();
	radcli_request *r;
	int rc;

	if (send_list == NULL ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "ids") != 0 ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_PASSWORD, 0, "test") != 0)
		die("attribute setup");
	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new");
	rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
	radcli_request_free(r);
	return rc;
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	rc_handle *rh;
	char authserver[64];
	int i, free_slot;

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
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 6) != 0 ||
	    radcli_ctx_apply(ctx) != 0)
		die("context setup");
	rh = (rc_handle *)ctx;
	if (radcli2_priv_tls_ensure_connected(rh) != 0)
		die("TLS connection");

	/* All but one Identifier in flight. */
	free_slot = -1;
	for (i = 0; i < RADCLI_CTX_MAX_INFLIGHT - 1; i++)
		if (reserve(rh) < 0)
			die("filling the registry");
	for (i = 0; i < RADCLI_CTX_MAX_INFLIGHT; i++)
		if (!rh->reqreg->slots[i].valid)
			free_slot = i;
	if (blocking_request(ctx) != RADCLI_OK)
		die("blocking request with one Identifier free");
	printf("EXPECT AUTH id=%d\n", free_slot);

	/* None free: the blocking request must not be sent, and a due
	 * watchdog must be skipped. */
	free_slot = reserve(rh);
	if (free_slot < 0)
		die("taking the last Identifier");
	if (blocking_request(ctx) != RADCLI_ERROR) {
		fprintf(stderr, "error: a blocking request with every Identifier in "
				"flight did not fail\n");
		return 1;
	}
	poll(NULL, 0, 6500);
	if (radcli_ctx_dispatch(ctx) != 0)
		die("radcli_ctx_dispatch");

	/* One freed: the next watchdog -- one interval after the skipped one,
	 * which counts as that round's attempt -- uses it. */
	radcli2_priv_reqreg_release(rh, free_slot);
	poll(NULL, 0, 6500);
	if (radcli_ctx_dispatch(ctx) != 0)
		die("radcli_ctx_dispatch");
	poll(NULL, 0, 200);
	printf("EXPECT WATCHDOG id=%d\n", free_slot);

	radcli_ctx_free(ctx);
	return 0;
}
