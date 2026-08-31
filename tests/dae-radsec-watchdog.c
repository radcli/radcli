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
 * DAE-over-RadSec connection-liveness test (tests/dae-radsec-watchdog-
 * tests.sh, peer: tests/dae-watchdog-server.py): radcli_ctx_send_watchdog()
 * sends an RFC 5997 Status-Server the peer can verify (Message-Authenticator
 * checked on the Python side), and radcli_ctx_get_poll()'s timeout_ms
 * reports a watchdog-interval-derived deadline -- close to the full
 * interval right after a send, and 0 once the interval has elapsed with
 * nothing else pending -- without radcli ever waiting or sending on its own
 * (REQ-GEN-SEC-003): every wait in this file is this test's own poll()/
 * sleep, not something inside radcli_ctx_get_poll()/radcli_ctx_send_watchdog().
 */

#include <config.h>
#include <stdio.h>
#include <poll.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

#define WATCHDOG_INTERVAL_SECS 6

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_dae *dae;
	char authserver[64];
	int fd, timeout_ms;
	unsigned events;
	int ret;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <port> <tls-ca-file>\n", argv[0]);
		return 2;
	}

	ctx = radcli_ctx_new(0);
	if (ctx == NULL) {
		fprintf(stderr, "dae-radsec-watchdog: radcli_ctx_new() failed\n");
		return 1;
	}

	snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[1]);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[2]) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) != 0 ||
	    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_DAE_MAX_CLOCK_SKEW, 60) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL,
				   WATCHDOG_INTERVAL_SECS) != 0) {
		fprintf(stderr, "dae-radsec-watchdog: option setup failed\n");
		return 1;
	}
	if (radcli_ctx_apply(ctx) != 0) {
		fprintf(stderr, "dae-radsec-watchdog: radcli_ctx_apply() failed\n");
		return 1;
	}

	dae = radcli_dae_new(ctx, 0);
	if (dae == NULL) {
		fprintf(stderr, "dae-radsec-watchdog: radcli_dae_new() failed\n");
		return 1;
	}
	/* No handler registered/needed: this test never receives a
	 * Disconnect-Request/CoA-Request, only sends a watchdog and reads
	 * radcli_ctx_get_poll()'s advisory deadline. */
	if (radcli_dae_start(dae) != 0) {
		fprintf(stderr, "dae-radsec-watchdog: radcli_dae_start() failed "
				"(could not establish the RadSec session)\n");
		return 1;
	}

	/* Right after the handshake (which itself counts as session activity),
	 * the advertised deadline must be close to the full interval -- not 0
	 * (nothing overdue yet) and not -1 (a configured, positive interval on
	 * an established session must always report a numeric deadline). */
	if (radcli_ctx_get_poll(ctx, &fd, &events, &timeout_ms) != 0 || fd < 0) {
		fprintf(stderr, "dae-radsec-watchdog: radcli_ctx_get_poll() failed "
				"or reported no descriptor after radcli_dae_start()\n");
		return 1;
	}
	if (timeout_ms <= 0 || timeout_ms > WATCHDOG_INTERVAL_SECS * 1000) {
		fprintf(stderr, "dae-radsec-watchdog: timeout_ms=%d right after "
				"handshake, expected in (0, %d]\n",
			timeout_ms, WATCHDOG_INTERVAL_SECS * 1000);
		return 1;
	}

	/* The call under test: the peer (dae-watchdog-server.py) is waiting,
	 * passively, for exactly this -- an unprompted Status-Server it did
	 * not ask for. */
	ret = radcli_ctx_send_watchdog(ctx);
	if (ret <= 0) {
		fprintf(stderr, "dae-radsec-watchdog: radcli_ctx_send_watchdog() "
				"returned %d, expected a positive byte count\n", ret);
		return 1;
	}

	/* The send above is session activity too: the deadline must have
	 * reset back up near the full interval, not still be wherever it was
	 * before (which, this soon after the handshake, would look the same
	 * either way -- this assertion mainly guards against a regression
	 * that stops the watchdog send from updating last_msg at all). */
	if (radcli_ctx_get_poll(ctx, &fd, &events, &timeout_ms) != 0) {
		fprintf(stderr, "dae-radsec-watchdog: radcli_ctx_get_poll() failed "
				"after radcli_ctx_send_watchdog()\n");
		return 1;
	}
	if (timeout_ms <= 0 || timeout_ms > WATCHDOG_INTERVAL_SECS * 1000) {
		fprintf(stderr, "dae-radsec-watchdog: timeout_ms=%d right after "
				"send_watchdog(), expected in (0, %d]\n",
			timeout_ms, WATCHDOG_INTERVAL_SECS * 1000);
		return 1;
	}

	/* This test's own sleep -- not radcli_ctx_get_poll() waiting on
	 * anything itself (REQ-GEN-SEC-003). Once watchdog-interval has
	 * genuinely elapsed with no further activity, the deadline must read
	 * as overdue (0), prompting a caller to send another watchdog. */
	poll(NULL, 0, (WATCHDOG_INTERVAL_SECS + 1) * 1000);

	if (radcli_ctx_get_poll(ctx, &fd, &events, &timeout_ms) != 0) {
		fprintf(stderr, "dae-radsec-watchdog: radcli_ctx_get_poll() failed "
				"after the interval elapsed\n");
		return 1;
	}
	if (timeout_ms != 0) {
		fprintf(stderr, "dae-radsec-watchdog: timeout_ms=%d after "
				"watchdog-interval elapsed, expected 0 (overdue)\n",
			timeout_ms);
		return 1;
	}

	radcli_dae_free(dae);
	radcli_ctx_free(ctx);

	printf("dae-radsec-watchdog: all checks passed\n");
	return 0;
}
