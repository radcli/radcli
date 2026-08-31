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
 * Dedicated reproducer for a radcli_encode_request() bug (lib/request.c):
 * radcli_request_new()/_perform() resolve their Message-Authenticator/
 * User-Password secret from the configured authserver value itself (empty,
 * since -- as REQ-CONFIG-CFG-019 already establishes -- a TLS authserver
 * ordinarily carries no inline secret at all, and cannot outside PSK form),
 * never the RFC 6614 SS2.3/RFC 7360 SS3.2 fixed RadSec secret
 * (rh->so.static_secret) radcli_transport_exchange() applies for every
 * other purpose on this same session. That leaves both the Access-Request's
 * Message-Authenticator HMAC and its User-Password RFC 2865 SS5.2
 * encryption keyed with the wrong secret -- silently, since nothing on the
 * client side ever checks either against a known-good value itself. This
 * one exchange is enough to reproduce it: peer (tests/request-tls-secret-
 * server.py) decodes both independently against the real secret and reports
 * each, rather than just accepting or rejecting the packet, so a fix that
 * only addresses one symptom does not pass.
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>

static void die(const char *msg) __attribute__((noreturn));

static void die(const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(1);
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	char authserver[64];
	radcli_avp_list *send_list;
	radcli_request *r;
	int rc;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <port> <tls-ca-file>\n", argv[0]);
		return 2;
	}

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");

	/* No inline secret on authserver -- the normal, documented way to
	 * configure a TLS authserver (REQ-CONFIG-CFG-019), and the only way:
	 * rc_init_tls() rejects any non-PSK-shaped secret outright. */
	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[1]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[2]) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) != 0) {
		fprintf(stderr, "request-tls-secret: option setup failed\n");
		return 1;
	}
	if (radcli_ctx_apply(ctx) != 0) {
		fprintf(stderr, "request-tls-secret: radcli_ctx_apply() failed\n");
		return 1;
	}

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "radcli-tls-secret") != 0)
		die("radcli_avp_add_str_by_num(PW_USER_NAME)");
	if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_PASSWORD, 0, "test") != 0)
		die("radcli_avp_add_str_by_num(PW_USER_PASSWORD)");

	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new(RADCLI_CODE_ACCESS_REQUEST)");

	rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
	if (rc != RADCLI_OK) {
		fprintf(stderr, "request-tls-secret: radcli_request_perform() "
				"returned %d, expected RADCLI_OK\n", rc);
		return 1;
	}
	if (radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "request-tls-secret: expected RADCLI_CODE_ACCESS_ACCEPT, "
				"got %d\n", (int)radcli_request_code(r));
		return 1;
	}

	radcli_request_free(r);
	radcli_ctx_free(ctx);

	printf("request-tls-secret: Access-Request sent, peer's own decode is authoritative\n");
	return 0;
}
