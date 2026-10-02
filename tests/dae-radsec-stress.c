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

/* Mixed-traffic stress test for DAE-over-RadSec (lib/tls.c's tls_recvfrom()
 * demux, lib/dae.c's radcli2_priv_dae_on_radsec_packet()/RadSec queue,
 * radcli_ctx_get_poll()/radcli_ctx_dispatch()) on one TLS connection.
 *
 * One thread -- a radcli_ctx is used by one thread at a time
 * (REQ-GEN-SEC-009) -- performs ordinary Access-Request/Accounting-Request
 * exchanges (blocking radcli_aaa()), with a radcli_ctx_get_poll()/
 * radcli_ctx_dispatch() round after each, while the peer
 * (tests/radsec-stress-server.py) interleaves unsolicited Disconnect-
 * Request/CoA-Request packets on the same connection. A DAE record can
 * therefore be read in both places it can arrive: inline inside a
 * radcli_aaa() call's own tls_recvfrom(), or by radcli_ctx_dispatch()
 * while the session is otherwise idle.
 *
 * Traceability (REQ-DAE-* IDs from doc/requirements/dae.md):
 *   REQ-DAE-SEC-012 and the RadSec invariant it implies (dae->handler()
 *     invoked ONLY from radcli_ctx_dispatch(), never inline from inside
 *     radcli_aaa()'s own call stack) -- verified directly: the handler
 *     fails the test if it runs while a radcli_aaa() call is in progress.
 *   REQ-DAE-DATA-001/002 (session selectors decoded correctly) -- verified
 *     per DAE message: User-Name/Acct-Session-Id must match exactly what
 *     the server sent for that specific message, not merely "some value".
 *   Implicit in the RadSec demux design: ordinary replies must never be
 *     misrouted to the DAE path, and DAE requests must never be
 *     misdelivered as an ordinary reply -- verified by asserting
 *     radcli_aaa()'s out_code is always exactly the expected reply family,
 *     never a DAE code or a timeout/error, for every single call.
 *
 * Coverage gap: RADCLI_DAE_RADSEC_QUEUE_SIZE's drop-oldest-on-overflow
 * behavior (lib/dae.c) is NOT exercised here, and neither is DTLS
 * (tests/radsec-stress-server.py, like tests/dae-tls-client.py, is
 * TLS-only: Python's ssl module has no DTLS support).
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <syslog.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

#define N_ORDINARY 50
#define DAE_EVERY 5 /* the peer sends one DAE message every this many ordinary requests it answers */
#define EXPECTED_DAE (N_ORDINARY / DAE_EVERY)
#define OVERALL_DEADLINE_SECONDS 30

static radcli_ctx *g_ctx;

/* Ordinary-request outcome counters. */
static int g_access_replies = 0;   /* out_code was ACCESS_ACCEPT or ACCESS_REJECT */
static int g_acct_replies = 0;     /* out_code was ACCOUNTING_RESPONSE */
static int g_ordinary_errors = 0;  /* timeout, error, or an unexpected/misrouted out_code */

/* DAE-side counters/flags. */
static int g_in_aaa = 0;           /* a radcli_aaa() call is in progress */
static int g_dae_count = 0;
static int g_dae_inside_aaa = 0;   /* handler invoked from inside radcli_aaa() */
static int g_dae_bad_content = 0;  /* User-Name/Acct-Session-Id did not match what was sent */
static int g_dae_reply_failed = 0; /* radcli_dae_reply() itself reported failure */

static void dae_handler(radcli_dae_request *req, void *user)
{
	char expected_user[64], expected_sid[64];
	const char *user_name, *sid;
	int n;

	(void)user;

	if (g_in_aaa)
		g_dae_inside_aaa++;

	n = g_dae_count; /* the peer numbers its DAE messages 0..EXPECTED_DAE-1, in order sent */
	g_dae_count++;

	snprintf(expected_user, sizeof(expected_user), "stress-user-%d", n);
	snprintf(expected_sid, sizeof(expected_sid), "stress-sess-%d", n);

	user_name = radcli_dae_req_user_name(req);
	sid = radcli_dae_req_session_id(req);

	if (user_name == NULL || strcmp(user_name, expected_user) != 0 ||
	    sid == NULL || strcmp(sid, expected_sid) != 0) {
		g_dae_bad_content++;
		fprintf(stderr, "dae-radsec-stress: content mismatch on DAE #%d: "
				"got User-Name=%s Acct-Session-Id=%s, expected %s/%s\n",
			n, user_name ? user_name : "(null)", sid ? sid : "(null)",
			expected_user, expected_sid);
	}

	if (radcli_dae_reply(req, 1) != 0)
		g_dae_reply_failed++;

	radcli_dae_request_free(req);
}

/* One ordinary exchange via blocking radcli_aaa(), Access-Request for even
 * i and Accounting-Request for odd i, tallied into the counters above. */
static void send_ordinary(int i)
{
	const radcli_attr_def *d_user = radcli_dict_lookup(g_ctx, "User-Name");
	radcli_avp_list *send_list;
	radcli_code code, out_code = 0;
	char name[64];
	int ret;

	send_list = radcli_avp_list_new();
	if (send_list == NULL) {
		g_ordinary_errors++;
		return;
	}
	snprintf(name, sizeof(name), "stress-iter%d", i);
	if (d_user != NULL)
		radcli_avp_add_str(send_list, d_user, name);

	code = (i % 2 == 0) ? RADCLI_CODE_ACCESS_REQUEST : RADCLI_CODE_ACCOUNTING_REQUEST;
	g_in_aaa = 1;
	ret = radcli_aaa(g_ctx, code, send_list, &out_code, NULL);
	g_in_aaa = 0;
	radcli_avp_list_free(send_list);

	if (ret != RADCLI_OK) {
		g_ordinary_errors++;
		fprintf(stderr, "dae-radsec-stress: iter %d: radcli_aaa() returned %d, "
				"not RADCLI_OK\n", i, ret);
	} else if (code == RADCLI_CODE_ACCESS_REQUEST) {
		if (out_code == RADCLI_CODE_ACCESS_ACCEPT || out_code == RADCLI_CODE_ACCESS_REJECT)
			g_access_replies++;
		else {
			g_ordinary_errors++;
			fprintf(stderr, "dae-radsec-stress: iter %d: Access-Request got "
					"unexpected reply code %d\n", i, (int)out_code);
		}
	} else {
		if (out_code == RADCLI_CODE_ACCOUNTING_RESPONSE)
			g_acct_replies++;
		else {
			g_ordinary_errors++;
			fprintf(stderr, "dae-radsec-stress: iter %d: Accounting-Request got "
					"unexpected reply code %d\n", i, (int)out_code);
		}
	}
}

/* One blocking poll(2) call sized from radcli_ctx_get_poll()'s own
 * timeout_ms (capped at max_timeout_ms), then one radcli_ctx_dispatch().
 * Returns -1 if get_poll() itself failed. */
static int poll_and_dispatch_once(int max_timeout_ms)
{
	struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
	size_t nfds;
	int timeout_ms;

	if (radcli_ctx_get_poll(g_ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0)
		return -1;
	if (timeout_ms < 0 || timeout_ms > max_timeout_ms)
		timeout_ms = max_timeout_ms;
	poll(nfds ? pfds : NULL, (nfds_t)nfds, timeout_ms);
	radcli_ctx_dispatch(g_ctx);
	return 0;
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_dae *dae;
	int i, fail = 0;
	time_t deadline;
	char authserver[64];

	if (argc != 3) {
		fprintf(stderr, "usage: %s <port> <tls-ca-file>\n", argv[0]);
		return 2;
	}

	/* rc_log() (lib/util.h) is plain syslog(); without LOG_PERROR here,
	 * every rc_log(LOG_ERR, ...) call on a failure path -- exactly what
	 * would explain a radcli_aaa()/radcli_dae_start() failure -- is
	 * invisible in this test's own captured output. */
	openlog("dae-radsec-stress", LOG_PID | LOG_PERROR, LOG_USER);

	ctx = radcli_ctx_new(0); /* built-in RFC 2865/2866/2869 dictionary --
				  * User-Name, Acct-Session-Id, Message-Authenticator */
	if (ctx == NULL) {
		fprintf(stderr, "dae-radsec-stress: radcli_ctx_new() failed\n");
		return 1;
	}
	g_ctx = ctx;

	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[1]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_ACCTSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[2]) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_DAE_MAX_CLOCK_SKEW, 60) != 0) {
		fprintf(stderr, "dae-radsec-stress: option setup failed\n");
		return 1;
	}
	if (radcli_ctx_apply(ctx) != 0) {
		fprintf(stderr, "dae-radsec-stress: radcli_ctx_apply() failed\n");
		return 1;
	}

	dae = radcli_dae_new(ctx, 0);
	if (dae == NULL) {
		fprintf(stderr, "dae-radsec-stress: radcli_dae_new() failed\n");
		return 1;
	}
	radcli_dae_set_handler(dae, dae_handler, NULL);
	if (radcli_dae_start(dae) != 0) {
		fprintf(stderr, "dae-radsec-stress: radcli_dae_start() failed "
				"(could not establish the RadSec session)\n");
		return 1;
	}

	for (i = 0; i < N_ORDINARY; i++) {
		send_ordinary(i);
		if (poll_and_dispatch_once(0) != 0) {
			fprintf(stderr, "dae-radsec-stress: radcli_ctx_get_poll() failed\n");
			fail = 1;
			break;
		}
	}

	/* The last DAE messages may still be in flight or queued. */
	deadline = time(NULL) + OVERALL_DEADLINE_SECONDS;
	while (!fail && g_dae_count < EXPECTED_DAE) {
		if (time(NULL) > deadline) {
			fprintf(stderr, "dae-radsec-stress: overall deadline exceeded "
					"(dae_count=%d/%d) -- treating as a hang\n",
				g_dae_count, EXPECTED_DAE);
			fail = 1;
			break;
		}
		if (poll_and_dispatch_once(200) != 0) {
			fprintf(stderr, "dae-radsec-stress: radcli_ctx_get_poll() failed\n");
			fail = 1;
		}
	}

	/* Let the queued ACK for the last DAE message reach the peer. */
	for (i = 0; i < 5; i++)
		poll_and_dispatch_once(50);

	radcli_dae_free(dae);
	radcli_ctx_free(ctx);

	if (g_ordinary_errors != 0) {
		fprintf(stderr, "FAIL: %d ordinary-request error(s)/misroute(s)\n", g_ordinary_errors);
		fail = 1;
	}
	if (g_access_replies + g_acct_replies != N_ORDINARY) {
		fprintf(stderr, "FAIL: expected %d total ordinary replies, got %d "
				"(access=%d acct=%d)\n",
			N_ORDINARY, g_access_replies + g_acct_replies,
			g_access_replies, g_acct_replies);
		fail = 1;
	}
	if (g_dae_count != EXPECTED_DAE) {
		fprintf(stderr, "FAIL: expected %d DAE messages delivered, got %d\n",
			EXPECTED_DAE, g_dae_count);
		fail = 1;
	}
	if (g_dae_inside_aaa != 0) {
		fprintf(stderr, "FAIL: dae_handler() was invoked from inside radcli_aaa() "
				"%d time(s) -- the RadSec queue's whole purpose is to "
				"prevent this\n", g_dae_inside_aaa);
		fail = 1;
	}
	if (g_dae_bad_content != 0) {
		fprintf(stderr, "FAIL: %d DAE message(s) decoded with the wrong "
				"User-Name/Acct-Session-Id\n", g_dae_bad_content);
		fail = 1;
	}
	if (g_dae_reply_failed != 0) {
		fprintf(stderr, "FAIL: radcli_dae_reply() itself failed %d time(s)\n",
			g_dae_reply_failed);
		fail = 1;
	}

	printf("dae-radsec-stress: ordinary=%d/%d (access=%d acct=%d) dae=%d/%d %s\n",
	       g_access_replies + g_acct_replies, N_ORDINARY,
	       g_access_replies, g_acct_replies, g_dae_count, EXPECTED_DAE,
	       fail ? "FAILED" : "PASSED");

	return fail;
}
