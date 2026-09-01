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
 * Test invariant (not "blocking vs non-blocking sockets" -- a poll-driven
 * app's actual contract): once radcli_ctx_get_poll() reports a
 * radcli_ctx's descriptor readable and the application dispatches into
 * radcli2 by calling radcli_ctx_dispatch(), that call MUST NOT perform a
 * blocking wait of its own -- no internal poll()-with-timeout for more
 * data, and none for write-readiness either. A single non-blocking read
 * attempt that comes back "record incomplete, try again once you're
 * readable again" is fine (that is TLS record reassembly, not blocking);
 * a multi-second wait for the peer to drain a full TCP send window is not.
 *
 * This is a targeted, single-purpose test (unlike tests/dae-radsec-
 * stress.c's realistic mixed load), isolating exactly this one property:
 * radcli_ctx_dispatch(), invoked purely because the descriptor was
 * readable, must never take more than a short, fixed bound to return --
 * regardless of whether sending a reply as a side effect of what it just
 * read would otherwise block.
 *
 * Mechanism: tests/radsec-backpressure-server.py shrinks its own
 * SO_RCVBUF immediately after accepting, then sends a burst of many
 * small Disconnect-Request messages back-to-back without ever reading
 * anything back -- filling the TCP window from this side (the direction
 * that matters: radcli's own reply sends) well before a typical default,
 * un-shrunk buffer would need anywhere near that much unread traffic to
 * fill. Each triggers this test's dae_handler(), which calls
 * radcli_dae_reply() (the reply-sending path under test) exactly once,
 * timed. If the reply's send would block, and the implementation being
 * tested does not honor the invariant above, ONE of these calls blocks
 * for close to radius_timeout seconds; if it honors the invariant, every
 * one returns within DISPATCH_BOUND_MS regardless.
 *
 * Requirement traceability: REQ-DAE-SEC-013 ("the RadSec reply queue is
 * bounded") in doc/requirements/dae.md is the closest existing
 * requirement -- its acceptance criteria did not previously cover *this*
 * property (dispatch() must not block at all while a reply is deferred),
 * only that the deferred-reply queue itself has a bound. This test
 * exercises the property that requirement's own rationale ("a DAC that
 * stops reading cannot cause unbounded memory growth on the NAS") only
 * half covers -- unbounded *memory* growth is one risk of a slow-reading
 * peer; unbounded *stall* of the caller's entire event loop is another,
 * and is what this test targets specifically.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <time.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

#define DISPATCH_BOUND_MS 500.0   /* generous even for a slow CI machine --
				    * the blocking bug this test targets takes
				    * multiple seconds (radius_timeout below),
				    * not merely "a bit slow". */
#define OVERALL_DEADLINE_SECONDS 20
#define EXPECTED_BURST 200        /* must be >> what the peer's shrunk
				    * SO_RCVBUF can hold unread, so the burst
				    * reliably provokes a full send window
				    * well before it's exhausted. */

static radcli_ctx *g_ctx;
static int g_dae_count = 0;
static int g_dae_bad_content = 0;
static double g_max_dispatch_ms = 0.0;
static int g_slow_dispatch_count = 0;

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void dae_handler(radcli_dae_request *req, void *user)
{
	char expected_user[64];
	const char *user_name;

	(void)user;

	snprintf(expected_user, sizeof(expected_user), "backpressure-user-%d", g_dae_count);
	user_name = radcli_dae_req_user_name(req);
	if (user_name == NULL || strcmp(user_name, expected_user) != 0) {
		g_dae_bad_content++;
		fprintf(stderr, "dae-radsec-backpressure: content mismatch on #%d: got %s\n",
			g_dae_count, user_name ? user_name : "(null)");
	}
	g_dae_count++;

	/* The call under test: this is exactly reply_and_record() -> send_reply()
	 * -> rh->so.sendto(), the path that must not block regardless of
	 * whether the underlying TCP write would otherwise stall. */
	radcli_dae_reply(req, 1);
	radcli_dae_request_free(req);
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_dae *dae;
	time_t deadline;
	char authserver[64];

	if (argc != 3) {
		fprintf(stderr, "usage: %s <port> <tls-ca-file>\n", argv[0]);
		return 2;
	}

	ctx = radcli_ctx_new(0);
	if (ctx == NULL) {
		fprintf(stderr, "dae-radsec-backpressure: radcli_ctx_new() failed\n");
		return 1;
	}
	g_ctx = ctx;

	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[1]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[2]) != 0 ||
	    /* Short on purpose: if the bug under test fires, a single blocked
	     * send takes this long. Long enough to be unambiguous against
	     * DISPATCH_BOUND_MS, short enough that a failing run doesn't
	     * itself take forever. */
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 3) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_DAE_MAX_CLOCK_SKEW, 60) != 0) {
		fprintf(stderr, "dae-radsec-backpressure: option setup failed\n");
		return 1;
	}
	if (radcli_ctx_apply(ctx) != 0) {
		fprintf(stderr, "dae-radsec-backpressure: radcli_ctx_apply() failed\n");
		return 1;
	}

	dae = radcli_dae_new(ctx, 0);
	if (dae == NULL) {
		fprintf(stderr, "dae-radsec-backpressure: radcli_dae_new() failed\n");
		return 1;
	}
	radcli_dae_set_handler(dae, dae_handler, NULL);
	if (radcli_dae_start(dae) != 0) {
		fprintf(stderr, "dae-radsec-backpressure: radcli_dae_start() failed "
				"(could not establish the RadSec session)\n");
		return 1;
	}

	deadline = time(NULL) + OVERALL_DEADLINE_SECONDS;
	while (g_dae_count < EXPECTED_BURST && time(NULL) < deadline) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;
		double t0, dt;

		if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0) {
			fprintf(stderr, "dae-radsec-backpressure: radcli_ctx_get_poll() failed\n");
			break;
		}
		if (nfds == 0) {
			poll(NULL, 0, 100);
			continue;
		}
		/* This poll() wait is legitimate and excluded from the timing
		 * bound below: it is exactly what the invariant under test
		 * permits -- waiting for readiness is the app's own idle
		 * time, not time spent inside a dispatched action. */
		poll(pfds, (nfds_t)nfds, (timeout_ms < 0) ? 1000 : timeout_ms);

		/* This is the one call under test. */
		t0 = now_ms();
		radcli_ctx_dispatch(ctx);
		dt = now_ms() - t0;

		if (dt > g_max_dispatch_ms)
			g_max_dispatch_ms = dt;
		if (dt > DISPATCH_BOUND_MS) {
			g_slow_dispatch_count++;
			fprintf(stderr, "dae-radsec-backpressure: radcli_ctx_dispatch() "
					"took %.1fms (bound %.1fms) -- it blocked instead "
					"of deferring a reply it could not send immediately\n",
				dt, DISPATCH_BOUND_MS);
			/* One confirmed violation already proves the point; no need
			 * to keep the run going for the full deadline. */
			break;
		}
	}

	radcli_dae_free(dae);
	radcli_ctx_free(ctx);

	printf("dae-radsec-backpressure: dae_count=%d/%d max_dispatch_ms=%.1f "
	       "slow_dispatch_count=%d %s\n",
	       g_dae_count, EXPECTED_BURST, g_max_dispatch_ms, g_slow_dispatch_count,
	       (g_slow_dispatch_count != 0 || g_dae_bad_content != 0) ? "FAILED" : "PASSED");

	return (g_slow_dispatch_count != 0 || g_dae_bad_content != 0) ? 1 : 0;
}
