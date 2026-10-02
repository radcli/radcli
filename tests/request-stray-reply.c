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

/* A blocking request that reads a reply with another Identifier first must
 * keep waiting for its own reply within the same attempt, not count that
 * reply as a failed attempt (REQ-NET-NET-010). The peer,
 * tests/radius-server.py --stray-first, sends a valid reply under the next
 * Identifier ahead of the real one; with radius_retries 0 there is no
 * second attempt, so the request only succeeds if the wait continued. */

#include <stdio.h>
#include <stdlib.h>

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
	int rc;

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
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "grace") != 0 ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_PASSWORD, 0, "test") != 0)
		die("attribute setup");
	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new");

	rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
	if (rc != RADCLI_OK || radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "error: radcli_request_perform() returned %d, code %d; "
				"expected the Access-Accept that followed the stray reply\n",
			rc, (int)radcli_request_code(r));
		return 1;
	}

	radcli_request_free(r);
	radcli_ctx_free(ctx);
	printf("OK: a reply with another Identifier did not end the wait\n");
	return 0;
}
