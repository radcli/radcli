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

/* Concurrency stress test for DAE-over-RadSec (lib/tls.c's tls_recvfrom()
 * demux, lib/dae.c's radcli2_priv_dae_on_radsec_packet()/RadSec queue,
 * radcli_ctx_get_poll()/radcli_ctx_dispatch()): a realistic mixed-traffic
 * client on one TLS connection, driven with poll(2) and blocking file
 * descriptors throughout (radcli's own TLS socket is always non-blocking
 * internally -- lib/tls.c's init_session() -- so "blocking file
 * descriptors" here means this test's OWN synchronization: pthread_join(),
 * a blocking poll(2) call sized from radcli_ctx_get_poll()'s own
 * timeout_ms, no busy-spin non-blocking polling loop anywhere in this file).
 *
 * Two sender threads continuously perform ordinary Access-Request/
 * Accounting-Request exchanges (radcli_aaa()) on the same radcli_ctx --
 * radcli_transport_exchange() serializes them behind the session's own
 * lock (lib/sendserver.c), so this also stresses that serialization itself,
 * not just the DAE path -- while the peer (tests/radsec-stress-server.py)
 * interleaves unsolicited Disconnect-Request/CoA-Request packets on the
 * exact same connection, exercising both places a RadSec DAE record can be
 * demuxed: inline inside an in-flight radcli_aaa() call's own
 * tls_recvfrom(), and via this test's dedicated poll-driven dispatch loop
 * when the session is otherwise idle.
 *
 * Traceability (this repository has no separate TC-NNN validation plan;
 * REQ-DAE-* IDs from doc/requirements/dae.md are the closest equivalent
 * and are used here instead):
 *   REQ-DAE-SEC-012 (radcli_ctx_dispatch() not reentrant) and the new
 *     RadSec invariant it implies (dae->handler() invoked ONLY from
 *     radcli_ctx_dispatch(), never inline from inside rc_auth()/rc_acct()/
 *     radcli_aaa()'s own call stack) -- verified directly: the handler
 *     records which thread invoked it and this test fails if it is ever a
 *     sender thread rather than the dedicated poll thread.
 *   REQ-DAE-DATA-001/002 (session selectors decoded correctly) -- verified
 *     per DAE message: User-Name/Acct-Session-Id must match exactly what
 *     the server sent for that specific message, not merely "some value".
 *   Implicit in the RadSec demux design (no single REQ-ID yet covers this
 *     end-to-end): ordinary replies (Access-Accept/Reject, Accounting-
 *     Response) must never be misrouted to the DAE path, and DAE requests
 *     must never be misdelivered as an ordinary reply -- verified by
 *     asserting radcli_aaa()'s out_code is always exactly the expected
 *     reply family, never a DAE code or a timeout/error, for every single
 *     call.
 *
 * Coverage gap, flagged rather than implemented without a corresponding
 * spec/TC-NNN: RADCLI_DAE_RADSEC_QUEUE_SIZE's drop-oldest-on-overflow
 * behavior (lib/dae.c) is NOT deterministically exercised here -- forcing
 * it reliably needs a way to stall this test's own dispatch loop while the
 * peer floods more than RADCLI_DAE_RADSEC_QUEUE_SIZE DAE messages without
 * any dispatch() call draining them, which needs a test-only
 * synchronization hook this codebase does not currently expose. DTLS is
 * also not covered (tests/radsec-stress-server.py, like
 * tests/dae-tls-client.py, is TLS-only: Python's ssl module has no DTLS
 * support).
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <syslog.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

#define N_PER_THREAD 25
#define N_SENDERS 2
#define DAE_EVERY 5 /* the peer sends one DAE message every this many ordinary requests it answers */
#define EXPECTED_ORDINARY (N_SENDERS * N_PER_THREAD)
#define EXPECTED_DAE (EXPECTED_ORDINARY / DAE_EVERY)
#define OVERALL_DEADLINE_SECONDS 30

static radcli_ctx *g_ctx;
static pthread_t g_poll_thread;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

/* Ordinary-request outcome counters. */
static int g_access_replies = 0;   /* out_code was ACCESS_ACCEPT or ACCESS_REJECT */
static int g_acct_replies = 0;     /* out_code was ACCOUNTING_RESPONSE */
static int g_ordinary_errors = 0;  /* timeout, error, or an unexpected/misrouted out_code */

/* DAE-side counters/flags. */
static int g_dae_count = 0;
static int g_dae_wrong_thread = 0; /* handler invoked from other than g_poll_thread */
static int g_dae_bad_content = 0;  /* User-Name/Acct-Session-Id did not match what was sent */
static int g_dae_reply_failed = 0; /* radcli_dae_reply() itself reported failure */

static void dae_handler(radcli_dae_request *req, void *user)
{
	char expected_user[64], expected_sid[64];
	const char *user_name, *sid;
	int n;

	(void)user;

	pthread_mutex_lock(&g_lock);

	if (!pthread_equal(pthread_self(), g_poll_thread))
		g_dae_wrong_thread++;

	n = g_dae_count; /* the peer numbers its DAE messages 0..EXPECTED_DAE-1, in order sent */
	g_dae_count++;

	pthread_mutex_unlock(&g_lock);

	snprintf(expected_user, sizeof(expected_user), "stress-user-%d", n);
	snprintf(expected_sid, sizeof(expected_sid), "stress-sess-%d", n);

	user_name = radcli_dae_req_user_name(req);
	sid = radcli_dae_req_session_id(req);

	if (user_name == NULL || strcmp(user_name, expected_user) != 0 ||
	    sid == NULL || strcmp(sid, expected_sid) != 0) {
		pthread_mutex_lock(&g_lock);
		g_dae_bad_content++;
		pthread_mutex_unlock(&g_lock);
		fprintf(stderr, "dae-radsec-stress: content mismatch on DAE #%d: "
				"got User-Name=%s Acct-Session-Id=%s, expected %s/%s\n",
			n, user_name ? user_name : "(null)", sid ? sid : "(null)",
			expected_user, expected_sid);
	}

	if (radcli_dae_reply(req, 1) != 0) {
		pthread_mutex_lock(&g_lock);
		g_dae_reply_failed++;
		pthread_mutex_unlock(&g_lock);
	}

	radcli_dae_request_free(req);
}

static void *sender_thread(void *arg)
{
	int idx = *(int *)arg;
	const radcli_attr_def *d_user;
	int i;

	d_user = radcli_dict_lookup(g_ctx, "User-Name");

	for (i = 0; i < N_PER_THREAD; i++) {
		radcli_avp_list *send_list;
		radcli_code code, out_code = 0;
		char name[64];
		int ret;

		send_list = radcli_avp_list_new();
		if (send_list == NULL) {
			pthread_mutex_lock(&g_lock);
			g_ordinary_errors++;
			pthread_mutex_unlock(&g_lock);
			continue;
		}
		snprintf(name, sizeof(name), "stress-sender%d-iter%d", idx, i);
		if (d_user != NULL)
			radcli_avp_add_str(send_list, d_user, name);

		code = (i % 2 == 0) ? RADCLI_CODE_ACCESS_REQUEST : RADCLI_CODE_ACCOUNTING_REQUEST;
		ret = radcli_aaa(g_ctx, code, send_list, &out_code, NULL);
		radcli_avp_list_free(send_list);

		pthread_mutex_lock(&g_lock);
		if (ret != RADCLI_OK) {
			g_ordinary_errors++;
			fprintf(stderr, "dae-radsec-stress: sender %d iter %d: "
					"radcli_aaa() returned %d, not RADCLI_OK\n", idx, i, ret);
		} else if (code == RADCLI_CODE_ACCESS_REQUEST) {
			if (out_code == RADCLI_CODE_ACCESS_ACCEPT || out_code == RADCLI_CODE_ACCESS_REJECT)
				g_access_replies++;
			else {
				g_ordinary_errors++;
				fprintf(stderr, "dae-radsec-stress: sender %d iter %d: "
						"Access-Request got unexpected reply code %d\n",
					idx, i, (int)out_code);
			}
		} else {
			if (out_code == RADCLI_CODE_ACCOUNTING_RESPONSE)
				g_acct_replies++;
			else {
				g_ordinary_errors++;
				fprintf(stderr, "dae-radsec-stress: sender %d iter %d: "
						"Accounting-Request got unexpected reply code %d\n",
					idx, i, (int)out_code);
			}
		}
		pthread_mutex_unlock(&g_lock);
	}
	return NULL;
}

/* One blocking poll(2) call sized from radcli_ctx_get_poll()'s own
 * timeout_ms, then one radcli_ctx_dispatch() -- never a non-blocking
 * busy-spin. Returns -1 if get_poll() itself failed. */
static int poll_and_dispatch_once(int fallback_timeout_ms)
{
	int fd, timeout_ms;
	unsigned events;
	struct pollfd pfd;

	if (radcli_ctx_get_poll(g_ctx, &fd, &events, &timeout_ms) != 0)
		return -1;
	if (fd < 0) {
		/* Not connected yet, or nothing to watch right now (e.g. the
		 * handshake radcli_dae_start() forces hasn't completed in the
		 * caller's view yet) -- still a genuine blocking wait, just
		 * with nothing to watch, so poll() on an empty set for a
		 * bounded slice instead of a tight loop. */
		poll(NULL, 0, fallback_timeout_ms);
		return 0;
	}
	pfd.fd = fd;
	pfd.events = (short)events;
	pfd.revents = 0;
	poll(&pfd, 1, (timeout_ms < 0) ? fallback_timeout_ms : timeout_ms);
	radcli_ctx_dispatch(g_ctx);
	return 0;
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_dae *dae;
	pthread_t senders[N_SENDERS];
	int sender_idx[N_SENDERS];
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

	/* Fixed for the rest of the run: dae_handler() checks every invocation
	 * against this exact thread, whichever thread happens to call
	 * poll_and_dispatch_once() below -- this thread, chosen once, here. */
	g_poll_thread = pthread_self();

	for (i = 0; i < N_SENDERS; i++) {
		sender_idx[i] = i;
		if (pthread_create(&senders[i], NULL, sender_thread, &sender_idx[i]) != 0) {
			fprintf(stderr, "dae-radsec-stress: pthread_create() failed\n");
			return 1;
		}
	}

	/* Dispatches until every expected DAE message has been delivered,
	 * regardless of whether the sender threads (still generating the
	 * ordinary traffic DAE messages are interleaved with) have finished
	 * yet -- a DAE message can legitimately arrive, and be queued, at any
	 * point relative to sender completion. */
	deadline = time(NULL) + OVERALL_DEADLINE_SECONDS;
	for (;;) {
		int senders_done;

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
			break;
		}
		pthread_mutex_lock(&g_lock);
		senders_done = (g_dae_count >= EXPECTED_DAE);
		pthread_mutex_unlock(&g_lock);
		if (senders_done) {
			/* One more drain: a message could have been queued by an
			 * in-flight sender's own tls_recvfrom() demux the instant
			 * before we checked the count above. */
			poll_and_dispatch_once(50);
			pthread_mutex_lock(&g_lock);
			senders_done = (g_dae_count >= EXPECTED_DAE);
			pthread_mutex_unlock(&g_lock);
			if (senders_done)
				break;
		}
	}

	for (i = 0; i < N_SENDERS; i++)
		pthread_join(senders[i], NULL);

	radcli_dae_free(dae);
	radcli_ctx_free(ctx);

	if (g_ordinary_errors != 0) {
		fprintf(stderr, "FAIL: %d ordinary-request error(s)/misroute(s)\n", g_ordinary_errors);
		fail = 1;
	}
	if (g_access_replies + g_acct_replies != EXPECTED_ORDINARY) {
		fprintf(stderr, "FAIL: expected %d total ordinary replies, got %d "
				"(access=%d acct=%d)\n",
			EXPECTED_ORDINARY, g_access_replies + g_acct_replies,
			g_access_replies, g_acct_replies);
		fail = 1;
	}
	if (g_dae_count != EXPECTED_DAE) {
		fprintf(stderr, "FAIL: expected %d DAE messages delivered, got %d\n",
			EXPECTED_DAE, g_dae_count);
		fail = 1;
	}
	if (g_dae_wrong_thread != 0) {
		fprintf(stderr, "FAIL: dae_handler() was invoked from a thread other "
				"than the dedicated poll thread %d time(s) -- the "
				"RadSec queue's whole purpose is to prevent this\n",
			g_dae_wrong_thread);
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
	       g_access_replies + g_acct_replies, EXPECTED_ORDINARY,
	       g_access_replies, g_acct_replies, g_dae_count, EXPECTED_DAE,
	       fail ? "FAILED" : "PASSED");

	return fail;
}
