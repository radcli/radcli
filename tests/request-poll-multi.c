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
 * Multiplexed poll-driven async request/reply coverage for radcli2.h
 * (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) +
 * radcli_ctx_get_poll()/radcli_ctx_dispatch()/radcli_request_done(),
 * lib/request.c + lib/dae.c), driven by tests/request-poll-multi-tests.sh
 * against tests/radius-server.py (see doc/radius-test-server.md) -- no root
 * or FreeRADIUS needed.
 *
 * tests/request.c already proves the poll-driven path against a single
 * unreachable server (the timeout branch) and tests/request-freeradius.c
 * proves it against a single real server (the success branch), but neither
 * exercises the scenario the poll-driven API actually exists for: a NAS
 * with several requests in flight at once, all serviced out of ONE
 * poll()/select() call on the caller's own event loop, rather than one
 * dedicated blocking call (or one dedicated poll loop) per request. This
 * program is that scenario: it sends NREQ Access-Requests with
 * RADCLI_REQUEST_SENDONLY before waiting on any of them, then drives all of
 * them to completion through a single shared radcli_ctx_get_poll() array,
 * calling poll() and radcli_ctx_dispatch() once per round -- proving that
 * NREQ concurrent exchanges genuinely share ctx's one request-registry
 * socket/session (REQ-NET2-SEND-016, LRU-allocated Identifiers,
 * REQ-NET2-SEND-010) without cross-wiring: radcli_ctx_dispatch() resolving
 * one request's reply must not disturb any other's still-pending state, and
 * each must independently decode its own, correct Access-Accept.
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <poll.h>

#define NREQ 5

static void die(const char *msg) __attribute__((noreturn));

static void die(const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(1);
}

int main(int argc, char **argv)
{
	const char *server_ip = argc > 1 ? argv[1] : "127.0.0.1";
	const char *port = argc > 2 ? argv[2] : "1812";
	const char *secret = argc > 3 ? argv[3] : "testing123";
	radcli_ctx *ctx;
	char authserver[160];
	radcli_avp_list *send_list;
	radcli_request *reqs[NREQ];
	int done[NREQ];
	int ndone = 0, iterations = 0, i;

	/* User-Name/User-Password/Framed-IP-Address are well-known RFC 2865
	 * attributes with PW_* constants in radcli-defs.h, so this test
	 * builds/reads them with the radcli_avp_*_by_num() convenience group
	 * (PW_* + radcli_ctx_new()'s built-in dictionary), exactly like
	 * src/radexample.c -- no radcli_dict_lookup() calls needed. */
	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");

	/* Generous timeout/retries: a slow CI machine replying to NREQ
	 * requests in sequence (tests/radius-server.py services one packet
	 * at a time) must not be mistaken for a lost packet. */
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) != 0)
		die("radcli_ctx_set_opt_int(radius_timeout)");
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 2) != 0)
		die("radcli_ctx_set_opt_int(radius_retries)");

	snprintf(authserver, sizeof(authserver), "%s:%s:%s", server_ip, port, secret);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0)
		die("radcli_ctx_set_opt_str(authserver)");

	if (radcli_ctx_apply(ctx) != 0)
		die("radcli_ctx_apply");

	/* --- construct and send all NREQ requests up front, each with
	 * RADCLI_REQUEST_SENDONLY, before waiting on any of them: this is
	 * what makes them genuinely concurrent from the caller's point of
	 * view, as opposed to NREQ sequential send-then-wait round trips --- */

	for (i = 0; i < NREQ; i++) {
		char username[64];

		snprintf(username, sizeof(username), "radcli-poll-multi-%d", i);

		send_list = radcli_avp_list_new();
		if (send_list == NULL)
			die("radcli_avp_list_new");
		if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, username) != 0)
			die("radcli_avp_add_str_by_num(PW_USER_NAME)");
		if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_PASSWORD, 0, "test") != 0)
			die("radcli_avp_add_str_by_num(PW_USER_PASSWORD)");

		reqs[i] = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
		radcli_avp_list_free(send_list);
		if (reqs[i] == NULL)
			die("radcli_request_new(RADCLI_CODE_ACCESS_REQUEST)");

		if (radcli_request_perform(reqs[i], RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
			die("radcli_request_perform(RADCLI_REQUEST_SENDONLY) did not return RADCLI_OK");
		if (radcli_request_done(reqs[i]) != RADCLI_AGAIN)
			die("radcli_request_done() did not return RADCLI_AGAIN right after a "
			    "successful RADCLI_REQUEST_SENDONLY send");

		done[i] = 0;
	}
	printf("OK: sent %d concurrent Access-Requests via RADCLI_REQUEST_SENDONLY\n", NREQ);

	/* --- service all of them out of a single shared ctx-level poll():
	 * one radcli_ctx_get_poll()/poll()/radcli_ctx_dispatch() sequence per
	 * round, covering every request still outstanding (they all share
	 * ctx's own request-registry socket/session, REQ-NET2-SEND-016), not
	 * one poll() loop per request --- */

	while (ndone < NREQ) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;

		if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0 ||
		    nfds == 0)
			die("radcli_ctx_get_poll() failed or reported nothing to watch "
			    "while requests were still in flight");

		if (poll(pfds, (nfds_t)nfds, timeout_ms) < 0)
			die("poll");

		radcli_ctx_dispatch(ctx);

		for (i = 0; i < NREQ; i++) {
			int rc;

			if (done[i])
				continue;

			rc = radcli_request_done(reqs[i]);
			if (rc == RADCLI_AGAIN)
				continue;

			if (rc != RADCLI_OK) {
				fprintf(stderr,
					"error: radcli_request_done() for request %d returned "
					"%d, expected RADCLI_OK\n", i, rc);
				exit(1);
			}
			done[i] = 1;
			ndone++;
		}

		/* Bound the loop: radius_timeout=5s/radius_retries=2 above means
		 * every request resolves within a handful of rounds; a runaway
		 * loop here (e.g. one request's completion starving another's
		 * progress) is itself the bug under test. */
		if (++iterations > 1000)
			die("poll loop did not converge -- a request's completion may "
			    "not be independent of the others");
	}
	printf("OK: all %d concurrent requests completed via a single shared poll() loop "
	       "(%d rounds)\n", NREQ, iterations);

	/* --- every request's own reply decoded correctly: proves the shared
	 * poll() loop above did not cross-wire any request's socket/state
	 * with another's --- */

	for (i = 0; i < NREQ; i++) {
		const radcli_avp_list *reply;
		uint32_t ip;

		if (radcli_request_code(reqs[i]) != RADCLI_CODE_ACCESS_ACCEPT) {
			fprintf(stderr, "error: request %d: expected RADCLI_CODE_ACCESS_ACCEPT, "
					"got %d\n", i, (int)radcli_request_code(reqs[i]));
			exit(1);
		}

		reply = radcli_request_attrs(reqs[i]);
		if (radcli_avp_get_uint32_by_num(reply, ctx, PW_FRAMED_IP_ADDRESS, 0, &ip) != 0) {
			fprintf(stderr, "error: request %d: Framed-IP-Address missing from "
					"its Access-Accept\n", i);
			exit(1);
		}
		if (ip != ((192u << 24) | (168u << 16) | (1u << 8) | 190u)) {
			fprintf(stderr, "error: request %d: Framed-IP-Address decoded as "
					"0x%08x, expected 192.168.1.190\n", i, ip);
			exit(1);
		}
		if (radcli_request_done(reqs[i]) != RADCLI_ERROR) {
			fprintf(stderr, "error: request %d: radcli_request_done() did not "
					"return RADCLI_ERROR when called again after already "
					"reaching a terminal result\n", i);
			exit(1);
		}

		radcli_request_free(reqs[i]);
	}
	printf("OK: every request's Access-Accept decoded independently and correctly\n");

	radcli_ctx_free(ctx);

	printf("radcli2 multiplexed poll-driven request/reply: all checks passed\n");
	return 0;
}
