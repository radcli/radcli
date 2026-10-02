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

/* radcli_ctx_dispatch() must never wait to write to a RadSec session
 * (REQ-NET2-NET-005), whatever it is sending: a DAE reply, a
 * RADCLI_REQUEST_SENDONLY retransmit or a watchdog. The peer,
 * tests/radsec-backpressure-server.py, floods Disconnect-Requests and
 * then stops reading for a while (--hold); this test shrinks its own send
 * buffer (lib/ internals, like tests/dae-codec.c) so the DAE replies fill
 * the window, while one large RADCLI_REQUEST_SENDONLY request keeps
 * retransmitting into it. Every radcli_ctx_dispatch() call is timed. */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <syslog.h>

#define DISPATCH_BOUND_MS 500.0
#define RUN_SECONDS 9

static int g_dae_count;

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void dae_handler(radcli_dae_request *req, void *user)
{
	(void)user;
	g_dae_count++;
	radcli_dae_reply(req, 1);
	radcli_dae_request_free(req);
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_dae *dae;
	radcli_avp_list *send_list;
	radcli_request *r;
	char authserver[64];
	uint8_t filler[250];
	int sndbuf = 1, i, slow = 0;
	double max_ms = 0, end;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <port> <tls-ca-file>\n", argv[0]);
		return 2;
	}

	/* rc_log() is plain syslog(); show it in the test's own output. */
	openlog("radsec-send-backpressure", LOG_PID | LOG_PERROR, LOG_USER);

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		return 1;
	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[1]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[2]) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 2) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 5) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_DAE_MAX_CLOCK_SKEW, 60) != 0 ||
	    radcli_ctx_apply(ctx) != 0) {
		fprintf(stderr, "radsec-send-backpressure: context setup failed\n");
		return 1;
	}
	dae = radcli_dae_new(ctx, 0);
	if (dae == NULL)
		return 1;
	radcli_dae_set_handler(dae, dae_handler, NULL);
	if (radcli_dae_start(dae) != 0) {
		fprintf(stderr, "radsec-send-backpressure: radcli_dae_start() failed\n");
		return 1;
	}
	setsockopt(radcli2_priv_tls_fd((rc_handle *)ctx), SOL_SOCKET, SO_SNDBUF,
		   &sndbuf, sizeof(sndbuf));

	/* About 3 KB, so a retransmit needs real room in the window. */
	memset(filler, 'x', sizeof(filler));
	send_list = radcli_avp_list_new();
	if (send_list == NULL ||
	    radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "backpressure") != 0)
		return 1;
	for (i = 0; i < 12; i++)
		if (radcli_avp_add_bytes_by_num(send_list, ctx, PW_CLASS, 0, filler,
						sizeof(filler)) != 0)
			return 1;
	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL || radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK) {
		fprintf(stderr, "radsec-send-backpressure: async request failed\n");
		return 1;
	}

	end = now_ms() + RUN_SECONDS * 1000.0;
	while (now_ms() < end) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;
		double t0, dt;

		if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0)
			break;
		if (timeout_ms < 0 || timeout_ms > 200)
			timeout_ms = 200;
		poll(nfds ? pfds : NULL, (nfds_t)nfds, timeout_ms);

		t0 = now_ms();
		radcli_ctx_dispatch(ctx);
		dt = now_ms() - t0;
		if (dt > max_ms)
			max_ms = dt;
		if (dt > DISPATCH_BOUND_MS) {
			slow++;
			fprintf(stderr, "radsec-send-backpressure: radcli_ctx_dispatch() took "
					"%.1fms (bound %.1fms)\n", dt, DISPATCH_BOUND_MS);
			break;
		}
	}

	radcli_request_free(r);
	radcli_dae_free(dae);
	radcli_ctx_free(ctx);

	printf("radsec-send-backpressure: dae_count=%d max_dispatch_ms=%.1f %s\n",
	       g_dae_count, max_ms, slow ? "FAILED" : "PASSED");
	return slow ? 1 : 0;
}
