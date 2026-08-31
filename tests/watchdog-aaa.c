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
 * RFC 3539 SS3.4 watchdog behavior for radcli_ctx_send_watchdog()/
 * radcli_ctx_get_poll(), driven entirely through ordinary AAA traffic
 * (radcli_request_new()/_perform(), RADCLI_CODE_ACCESS_REQUEST) -- unlike
 * tests/dae-radsec-watchdog.c, no radcli_dae_*() call appears anywhere in
 * this file: the watchdog machinery (REQ-WATCHDOG-NET-001/002) is a property of
 * any established RadSec radcli_ctx, DAE or not, and this test exists to
 * prove that on the "not" side. Peer: tests/watchdog-aaa-server.py, driven
 * by tests/watchdog-aaa-tests.sh.
 *
 * Phase 1: the watchdog deadline resets on ANY message received from the
 * peer, not only a watchdog round trip -- an ordinary Access-Accept counts
 * exactly the same as a watchdog reply would (RFC 3539 SS3.4: "any message
 * ... MUST reset the watchdog timer for the given peer").
 *
 * Phase 2: watchdog-interval cannot be set below 6 seconds (0 still
 * disables it) -- lib/config.c's set_option_int() rejects 1-5 outright,
 * for both radcli_ctx_set_opt_int() (checked here) and the config-file
 * reader.
 *
 * Phase 3: an unsolicited reply to a watchdog (the peer answering a
 * Status-Server exactly like a real RFC 5997-compliant server would) is
 * read and silently dropped -- radcli owns no request/reply correlation for
 * a watchdog (radcli_ctx_send_watchdog()'s doc comment, lib/dae.c), so the
 * stale reply is discarded on Identifier mismatch by the next exchange's
 * own read loop (lib/sendserver.c's rc_check_reply()) rather than answered
 * or reported as an error.
 *
 * Phase 4: if the peer goes silent -- no watchdog response, no other
 * message -- for 2.5x watchdog-interval, while the TCP/TLS connection
 * itself stays open (never a socket-level error, which the transport
 * already reconnects from on its own), radcli_ctx_send_watchdog() detects
 * this and forces a reconnect before sending the next watchdog on a fresh
 * connection (REQ-WATCHDOG-NET-003). This test simply sends nothing at all for
 * well over 2.5x the interval -- the peer's own read timeout
 * (tests/watchdog-aaa-server.py's --timeout, kept short for exactly this)
 * naturally ends its now-idle first connection and returns it to accept()
 * well before that; tests/watchdog-aaa-tests.sh confirms the peer saw a
 * *second* TLS connection accepted, which is the only observable proof
 * that reconnection specifically (not just "still works") happened.
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>

#define WATCHDOG_INTERVAL_SECS 6

static void die(const char *msg) __attribute__((noreturn));

static void die(const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(1);
}

/* One blocking Access-Request/Access-Accept round trip, exactly like any
 * ordinary AAA use of radcli2.h -- never a watchdog. Used both to establish
 * the RadSec session (serv-type=tls defers the TCP/TLS connect to first use,
 * unlike radcli_dae_start()'s eager handshake) and to generate the "ordinary
 * peer traffic" phase 1 and phase 3 need.
 *
 * @return 0 on a successful Access-Accept, -1 otherwise (a message already
 * printed to stderr).
 */
static int do_access_request(radcli_ctx *ctx, const char *username)
{
	radcli_avp_list *send_list;
	radcli_request *r;
	int rc;

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, username) != 0)
		die("radcli_avp_add_str_by_num(PW_USER_NAME)");
	if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_PASSWORD, 0, "test") != 0)
		die("radcli_avp_add_str_by_num(PW_USER_PASSWORD)");

	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new(RADCLI_CODE_ACCESS_REQUEST)");

	rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
	if (rc != RADCLI_OK) {
		fprintf(stderr, "error: radcli_request_perform() returned %d, "
				"expected RADCLI_OK\n", rc);
		radcli_request_free(r);
		return -1;
	}
	if (radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "error: expected RADCLI_CODE_ACCESS_ACCEPT, got %d\n",
			(int)radcli_request_code(r));
		radcli_request_free(r);
		return -1;
	}
	radcli_request_free(r);
	return 0;
}

/* Phase 2: RADCLI_OPT_WATCHDOG_INTERVAL rejects 1-5 outright (0 still
 * disables it, 6+ is unrestricted) -- no network needed, checked on a
 * throwaway radcli_ctx before the real one below ever contacts the peer.
 *
 * @return 0 if all three boundary values behaved as expected, -1 otherwise
 * (a message already printed to stderr).
 */
static int check_watchdog_interval_bounds(void)
{
	radcli_ctx *ctx;
	int ret = 0;

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 5) == 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_int(WATCHDOG_INTERVAL, 5) "
				"succeeded, expected -1 (below the 6s floor)\n");
		ret = -1;
	}
	radcli_ctx_free(ctx);

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 6) != 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_int(WATCHDOG_INTERVAL, 6) "
				"returned -1, expected 0 (at the 6s floor)\n");
		ret = -1;
	}
	radcli_ctx_free(ctx);

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 0) != 0) {
		fprintf(stderr, "error: radcli_ctx_set_opt_int(WATCHDOG_INTERVAL, 0) "
				"returned -1, expected 0 (0 always disables it)\n");
		ret = -1;
	}
	radcli_ctx_free(ctx);

	return ret;
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	char authserver[64];
	int fd, timeout_ms;
	unsigned events;
	int ret;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <port> <tls-ca-file>\n", argv[0]);
		return 2;
	}

	/* --- Phase 2: watchdog-interval cannot be set below 6 seconds --- */

	if (check_watchdog_interval_bounds() != 0) {
		fprintf(stderr, "watchdog-aaa: watchdog-interval boundary checks failed\n");
		return 1;
	}
	printf("OK: watchdog-interval rejects 1-5, accepts 0 and 6+\n");

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");

	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[1]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[2]) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 2) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL,
				   WATCHDOG_INTERVAL_SECS) != 0) {
		fprintf(stderr, "watchdog-aaa: option setup failed\n");
		return 1;
	}
	if (radcli_ctx_apply(ctx) != 0) {
		fprintf(stderr, "watchdog-aaa: radcli_ctx_apply() failed\n");
		return 1;
	}

	/* --- Phase 1: the watchdog deadline resets on ANY message from the
	 * peer, not only a watchdog round trip (RFC 3539 SS3.4) --- */

	if (do_access_request(ctx, "radcli-watchdog-aaa-1") != 0) {
		fprintf(stderr, "watchdog-aaa: initial Access-Request failed\n");
		return 1;
	}

	if (radcli_ctx_get_poll(ctx, &fd, &events, &timeout_ms) != 0 || fd < 0) {
		fprintf(stderr, "watchdog-aaa: radcli_ctx_get_poll() failed or "
				"reported no descriptor after the first Access-Request\n");
		return 1;
	}
	if (timeout_ms <= 0 || timeout_ms > WATCHDOG_INTERVAL_SECS * 1000) {
		fprintf(stderr, "watchdog-aaa: timeout_ms=%d right after the first "
				"Access-Request, expected in (0, %d]\n",
			timeout_ms, WATCHDOG_INTERVAL_SECS * 1000);
		return 1;
	}
	printf("OK: an ordinary Access-Accept counts as watchdog-relevant "
	       "activity (timeout_ms=%d)\n", timeout_ms);

	/* Sleep less than the full interval, then send a second, entirely
	 * unrelated Access-Request -- never a watchdog -- and confirm the
	 * deadline reset back near the full interval rather than continuing to
	 * count down from the first request. */
	poll(NULL, 0, 2000);

	if (do_access_request(ctx, "radcli-watchdog-aaa-2") != 0) {
		fprintf(stderr, "watchdog-aaa: second Access-Request failed\n");
		return 1;
	}

	if (radcli_ctx_get_poll(ctx, &fd, &events, &timeout_ms) != 0) {
		fprintf(stderr, "watchdog-aaa: radcli_ctx_get_poll() failed after "
				"the second Access-Request\n");
		return 1;
	}
	if (timeout_ms <= (WATCHDOG_INTERVAL_SECS - 1) * 1000) {
		fprintf(stderr, "watchdog-aaa: timeout_ms=%d after an ordinary "
				"Access-Request that followed a 2s sleep -- expected it "
				"reset back near the full %ds interval, not to keep "
				"counting down from the first request (RFC 3539 SS3.4: ANY "
				"peer message resets the watchdog timer, not only a "
				"watchdog reply)\n",
			timeout_ms, WATCHDOG_INTERVAL_SECS);
		return 1;
	}
	printf("OK: the watchdog deadline resets on any peer message, not only "
	       "a watchdog reply (timeout_ms=%d)\n", timeout_ms);

	/* --- Phase 3: an unsolicited reply to a watchdog is read and silently
	 * dropped -- it must never cause radcli to answer or error back to the
	 * peer, and must never disrupt the next ordinary exchange --- */

	ret = radcli_ctx_send_watchdog(ctx);
	if (ret <= 0) {
		fprintf(stderr, "watchdog-aaa: radcli_ctx_send_watchdog() returned "
				"%d, expected a positive byte count\n", ret);
		return 1;
	}
	printf("OK: radcli_ctx_send_watchdog() sent a Status-Server (%d bytes)\n", ret);

	/* The peer (tests/watchdog-aaa-server.py) replies to the watchdog
	 * exactly like a real RFC 5997-compliant server would. radcli owns no
	 * request/reply correlation for a watchdog, so that reply is left
	 * unread on the socket until the next exchange's own read loop reaches
	 * it -- where its Identifier won't match the new Access-Request's own,
	 * so lib/sendserver.c's rc_check_reply() discards it (immediately
	 * retransmitting the Access-Request rather than decoding it, the same
	 * as it would for any other stale/unrelated packet arriving mid-
	 * exchange) with no error surfacing here and nothing sent back to the
	 * peer in response to it. */
	if (do_access_request(ctx, "radcli-watchdog-aaa-3") != 0) {
		fprintf(stderr, "watchdog-aaa: Access-Request after an unsolicited "
				"watchdog reply failed -- the reply should have been "
				"silently absorbed, not disrupted the session\n");
		return 1;
	}
	printf("OK: an unsolicited watchdog reply was silently absorbed; the "
	       "next ordinary Access-Request still succeeded\n");

	/* --- Phase 4: a peer that goes silent -- no watchdog response, no
	 * other message -- for 2.5x watchdog-interval, while the connection
	 * itself stays open, is presumed dead and the connection reestablished
	 * (REQ-WATCHDOG-NET-003). This test sends nothing at all for that long; the
	 * peer's own read timeout on the resulting idle connection is what
	 * actually ends it server-side (see this file's header comment). --- */

	/* This test's own sleep -- not radcli waiting on anything itself
	 * (REQ-GEN-SEC-003): well past 2.5x the interval, with margin for
	 * scheduling jitter. */
	poll(NULL, 0, (int)(WATCHDOG_INTERVAL_SECS * 2.5 * 1000) + 2000);

	ret = radcli_ctx_send_watchdog(ctx);
	if (ret <= 0) {
		fprintf(stderr, "watchdog-aaa: radcli_ctx_send_watchdog() after the "
				"peer went silent returned %d, expected a positive byte "
				"count (a forced reconnect should have produced a fresh, "
				"usable session)\n", ret);
		return 1;
	}
	printf("OK: radcli_ctx_send_watchdog() succeeded after a forced "
	       "reconnect (%d bytes)\n", ret);

	if (do_access_request(ctx, "radcli-watchdog-aaa-4") != 0) {
		fprintf(stderr, "watchdog-aaa: Access-Request after the forced "
				"reconnect failed\n");
		return 1;
	}
	printf("OK: an ordinary Access-Request succeeded over the "
	       "reestablished connection\n");

	radcli_ctx_free(ctx);

	printf("watchdog-aaa: all checks passed\n");
	return 0;
}
