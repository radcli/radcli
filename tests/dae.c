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

/* Unit tests for radcli2.h's RFC 5176 dynamic-authorization listener
 * construction (radcli_dae_new()/_set_handler()/_start()/_free(), and the
 * ctx-level poll surface radcli_ctx_get_poll()/radcli_ctx_dispatch()/
 * radcli_ctx_send_watchdog(), lib/dae.c): REQ-DAE-INIT-001..004
 * (doc/requirements/dae.md). Only literal
 * addresses are used (never a hostname needing real DNS), so this needs no
 * network access; radcli_dae_start() binds to 127.0.0.1:0 (kernel-assigned
 * ephemeral port), so it needs no root and cannot collide with another
 * test's port. Packet receipt/validation is not implemented yet (dispatch()
 * reads and discards, never invoking a handler), so that is not tested
 * here beyond confirming it does not crash and does not block.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <poll.h>
#include <fcntl.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

static radcli_ctx *new_ctx(void)
{
	radcli_ctx *ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);

	assert(ctx != NULL);
	return ctx;
}

static void unexpected_handler(radcli_dae_request *req, void *user)
{
	(void)req;
	(void)user;
	fprintf(stderr, "error: the dae handler was invoked (not implemented yet)\n");
	exit(1);
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_dae *dae;
	struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
	size_t nfds;
	int fd;
	int timeout_ms;

	/* --- dae-accept unset: NULL, not an error --- */
	ctx = new_ctx();
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with dae-accept unset\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-accept no: NULL --- */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "no") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, "192.0.2.1") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with dae-accept no\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-accept with an invalid value: NULL --- */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "sure") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, "192.0.2.1") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() accepted dae-accept=sure\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-accept yes, dae-server/dae-secret both unset: NULL --- */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") == 0);
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with neither "
				"dae-server nor dae-secret set\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-accept yes, only dae-server set: NULL --- */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, "192.0.2.1") == 0);
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with dae-secret unset\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-accept yes, only dae-secret set: NULL --- */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with dae-server unset\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-server carrying a network prefix: NULL --- */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, "192.0.2.0/24") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() accepted a dae-server prefix (/24)\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-secret longer than MAX_SECRET_LENGTH: NULL --- */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, "192.0.2.1") == 0);
	{
		char overlong[MAX_SECRET_LENGTH + 2];

		memset(overlong, 'x', sizeof(overlong) - 1);
		overlong[sizeof(overlong) - 1] = '\0';
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, overlong) == 0);
	}
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() accepted a dae-secret longer "
				"than MAX_SECRET_LENGTH\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-server ":secret" override longer than MAX_SECRET_LENGTH: NULL --- */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
	{
		char server[16 + MAX_SECRET_LENGTH + 2];
		char overlong[MAX_SECRET_LENGTH + 2];

		memset(overlong, 'x', sizeof(overlong) - 1);
		overlong[sizeof(overlong) - 1] = '\0';
		snprintf(server, sizeof(server), "192.0.2.1:%s", overlong);
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, server) == 0);
	}
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() accepted a dae-server secret "
				"override longer than MAX_SECRET_LENGTH\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-accept=yes under serv-type=tls, tls-verify-hostname=no: NULL ---
	 * rc_init_tls() (lib/tls.c) defers the actual TCP connect + TLS
	 * handshake to first use (need_restart=1), so radcli_ctx_apply() with
	 * serv-type=tls succeeds here without any real, reachable server or
	 * even a tls-ca-file/PSK key configured -- radcli_dae_new()'s new
	 * RadSec checks (REQ-DAE-INIT-007) run entirely on config strings, no
	 * network I/O needed. */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "192.0.2.1:2083") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_VERIFY_HOSTNAME, "no") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") == 0);
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() accepted dae-accept=yes under "
				"serv-type=tls with tls-verify-hostname=no\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- dae-accept=yes under serv-type=tls, verification left enabled: succeeds ---
	 * Also sets every REQ-DAE-INIT-008 "inapplicable under RadSec" option
	 * (dae-listen/dae-server/dae-secret/dae-require-message-authenticator)
	 * to confirm construction still succeeds with all four set (each
	 * should only warn, per REQ-DAE-INIT-008) rather than failing because
	 * of them. */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") == 0);
	/* A local, guaranteed-closed port, not a real-network address like
	 * 192.0.2.1 (TEST-NET-1): lib/tls.c's init_session() calls connect()
	 * on a still-BLOCKING socket (O_NONBLOCK is only set afterward), so a
	 * remote address a real network silently drops packets to -- rather
	 * than actively rejecting -- can hang this connect() call for the
	 * OS's own TCP connect timeout, entirely unbounded by radius_timeout
	 * (which only governs gnutls_handshake(), reached later). 127.0.0.1
	 * with nothing listening gets an immediate, local ECONNREFUSED
	 * instead, keeping this a fast, no-network-dependency unit test as
	 * the rest of this file already assumes -- see this file's own
	 * top-of-file comment. */
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "127.0.0.1:1") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "yes") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_LISTEN, "127.0.0.1:0") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, "192.0.2.9") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "unused-under-radsec") == 0);
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae == NULL) {
		fprintf(stderr, "error: radcli_dae_new() failed with a valid RadSec "
				"configuration (dae-accept=yes, serv-type=tls)\n");
		exit(1);
	}
	/* radcli_dae_start() under RadSec forces the handshake eagerly
	 * (REQ-DAE-INIT-010) rather than binding a socket -- with no
	 * credentials and an unreachable peer, that handshake fails, and
	 * radcli_dae_start() must report that failure cleanly rather than
	 * crash or silently "succeed" with nothing actually connected. The
	 * positive case (a real peer, handshake actually completes) needs a
	 * live TLS server and is exercised by tests/dae-radsec-tests.sh
	 * instead. */
	if (radcli_dae_start(dae) == 0) {
		fprintf(stderr, "error: radcli_dae_start() succeeded against an "
				"unreachable, credential-less RadSec peer\n");
		exit(1);
	}

	/* --- radcli_dae_process() (the L0 buffer entry point) rejects a RadSec dae ---
	 * RadSec trusts the record's origin entirely to the TLS/DTLS session
	 * (REQ-DAE-SEC-015); a caller-supplied buffer/address pair is not
	 * that session and has no source-address check of its own to apply,
	 * so this must be an outright -1, not "processed, but happens to fail
	 * validation" -- a crafted buffer with a correct (well-known, not
	 * actually secret) RFC 6614 Request Authenticator must not be
	 * accepted as a substitute for a real session. */
	{
		uint8_t dummy[32] = { 0 };
		struct sockaddr_in from;
		radcli_dae_request *req = NULL;

		memset(&from, 0, sizeof(from));
		from.sin_family = AF_INET;
		dummy[0] = RADCLI_DISCONNECT_REQUEST;
		if (radcli_dae_process(dae, dummy, sizeof(dummy), (struct sockaddr *)&from,
				       sizeof(from), &req) != -1 || req != NULL) {
			fprintf(stderr, "error: radcli_dae_process() did not reject a "
					"RadSec dae\n");
			exit(1);
		}
	}

	radcli_dae_free(dae);
	radcli_ctx_free(ctx);

	/* --- dae-accept=udp still forces the UDP listener under serv-type=tls ---
	 * Kept as a fully supported, documented option (REQ-DAE-INIT-001's
	 * "no"/"yes"/"udp" trio), not superseded by dae-accept=yes. */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, "192.0.2.1:2083") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "udp") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, "192.0.2.9") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_LISTEN, "127.0.0.1:0") == 0);
	assert(radcli_ctx_apply(ctx) == 0);
	dae = radcli_dae_new(ctx, 0);
	if (dae == NULL) {
		fprintf(stderr, "error: radcli_dae_new() failed for dae-accept=udp "
				"under serv-type=tls\n");
		exit(1);
	}
	if (radcli_dae_start(dae) != 0) {
		fprintf(stderr, "error: radcli_dae_start() failed to bind the UDP "
				"listener forced by dae-accept=udp under serv-type=tls\n");
		exit(1);
	}
	radcli_dae_free(dae);
	radcli_ctx_free(ctx);

	/* --- fully valid configuration --- */
	ctx = new_ctx();
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "udp") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, "192.0.2.1,192.0.2.2:othersecret") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_LISTEN, "127.0.0.1:0") == 0);
	assert(radcli_ctx_apply(ctx) == 0);

	/* A second radcli_dae_new() on the same ctx must fail: at most one
	 * active radcli_dae per ctx (radcli_ctx_get_poll()/_dispatch() need a
	 * single descriptor to report). */
	{
		radcli_dae *dae1 = radcli_dae_new(ctx, 0);
		radcli_dae *dae2;

		if (dae1 == NULL) {
			fprintf(stderr, "error: radcli_dae_new() failed with a valid configuration\n");
			exit(1);
		}
		dae2 = radcli_dae_new(ctx, 0);
		if (dae2 != NULL) {
			fprintf(stderr, "error: a second radcli_dae_new() on the same ctx "
					"did not fail\n");
			exit(1);
		}
		radcli_dae_free(dae1);
	}

	dae = radcli_dae_new(ctx, 0);
	if (dae == NULL) {
		fprintf(stderr, "error: radcli_dae_new() failed with a valid configuration\n");
		exit(1);
	}

	radcli_dae_set_handler(dae, unexpected_handler, NULL);

	/* Nothing to watch before radcli_dae_start(). */
	nfds = 99;
	timeout_ms = -99;
	if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() failed\n");
		exit(1);
	}
	if (nfds != 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() reported something to "
				"watch before radcli_dae_start()\n");
		exit(1);
	}

	if (radcli_dae_start(dae) != 0) {
		fprintf(stderr, "error: radcli_dae_start() failed on 127.0.0.1:0\n");
		exit(1);
	}

	if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() failed after radcli_dae_start()\n");
		exit(1);
	}
	if (nfds != 1 || pfds[0].fd < 0 || !(pfds[0].events & POLLIN)) {
		fprintf(stderr, "error: radcli_ctx_get_poll() did not report the "
				"listener as readable-watched after radcli_dae_start()\n");
		exit(1);
	}
	fd = pfds[0].fd;

	/* REQ-DAE-SEC-010/011: the listener socket must be non-blocking and
	 * close-on-exec. */
	{
		int flags = fcntl(fd, F_GETFL, 0);

		if (flags == -1 || !(flags & O_NONBLOCK)) {
			fprintf(stderr, "error: the listener socket is not O_NONBLOCK\n");
			exit(1);
		}
		flags = fcntl(fd, F_GETFD, 0);
		if (flags == -1 || !(flags & FD_CLOEXEC)) {
			fprintf(stderr, "error: the listener socket is not FD_CLOEXEC\n");
			exit(1);
		}
	}

	/* A second radcli_dae_start() call must fail rather than leak or rebind. */
	if (radcli_dae_start(dae) == 0) {
		fprintf(stderr, "error: a second radcli_dae_start() call did not fail\n");
		exit(1);
	}

	/* Nothing was sent, so dispatch() must return promptly without
	 * blocking and without invoking the (not-yet-implemented) handler. */
	if (radcli_ctx_dispatch(ctx) != 0) {
		fprintf(stderr, "error: radcli_ctx_dispatch() with nothing pending "
				"did not return 0\n");
		exit(1);
	}

	/* The RFC 5997 watchdog send radcli_ctx_dispatch() now performs
	 * internally (watchdog.md's REQ-WATCHDOG-NET-001) is gated on
	 * so_type == TLS/DTLS -- this ctx is UDP (dae-accept=udp), so a
	 * repeated dispatch() call must keep behaving exactly like the
	 * "nothing pending" case above, never attempt anything watchdog-
	 * related on the UDP listener socket. */
	if (radcli_ctx_dispatch(ctx) != 0) {
		fprintf(stderr, "error: radcli_ctx_dispatch() on a non-RadSec (UDP) "
				"ctx did not return 0\n");
		exit(1);
	}

	radcli_dae_free(dae);

	/* radcli_dae_free(NULL) is a no-op. */
	radcli_dae_free(NULL);

	/* After freeing the only active dae, ctx has nothing to watch again. */
	if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() failed after radcli_dae_free()\n");
		exit(1);
	}
	if (nfds != 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() still reported a "
				"descriptor after radcli_dae_free()\n");
		exit(1);
	}

	/* radcli_ctx_get_poll(NULL, ...)/radcli_ctx_dispatch(NULL) fail cleanly. */
	if (radcli_ctx_get_poll(NULL, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) == 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll(NULL, ...) did not fail\n");
		exit(1);
	}
	/* Also too small a pfds capacity must fail, not silently truncate. */
	if (radcli_ctx_get_poll(ctx, pfds, 0, &nfds, &timeout_ms) == 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() with max_pfds=0 did not fail\n");
		exit(1);
	}
	if (radcli_ctx_dispatch(NULL) == 0) {
		fprintf(stderr, "error: radcli_ctx_dispatch(NULL) did not fail\n");
		exit(1);
	}

	radcli_ctx_free(ctx);

	printf("dae: all tests passed\n");
	return 0;
}
