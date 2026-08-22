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
 * ctx-level poll surface radcli_ctx_get_poll()/radcli_ctx_dispatch(),
 * lib/dae.c): REQ-DAE-INIT-001..004 (doc/requirements/dae.md). Only literal
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

static rc_handle *new_rh(void)
{
	rc_handle *rh = rc_new();

	assert(rh != NULL);
	rc_config_init(rh);
	return rh;
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
	rc_handle *rh;
	radcli_dae *dae;
	int fd;
	unsigned events;
	int timeout_ms;

	/* --- dae-accept unset: NULL, not an error --- */
	rh = new_rh();
	dae = radcli_dae_new(rh);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with dae-accept unset\n");
		exit(1);
	}
	rc_destroy(rh);

	/* --- dae-accept no: NULL --- */
	rh = new_rh();
	assert(rc_add_config(rh, "dae-accept", "no", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-server", "192.0.2.1", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-secret", "testing123", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);
	dae = radcli_dae_new(rh);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with dae-accept no\n");
		exit(1);
	}
	rc_destroy(rh);

	/* --- dae-accept with an invalid value: NULL --- */
	rh = new_rh();
	assert(rc_add_config(rh, "dae-accept", "sure", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-server", "192.0.2.1", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-secret", "testing123", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);
	dae = radcli_dae_new(rh);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() accepted dae-accept=sure\n");
		exit(1);
	}
	rc_destroy(rh);

	/* --- dae-accept yes, dae-server/dae-secret both unset: NULL --- */
	rh = new_rh();
	assert(rc_add_config(rh, "dae-accept", "yes", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);
	dae = radcli_dae_new(rh);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with neither "
				"dae-server nor dae-secret set\n");
		exit(1);
	}
	rc_destroy(rh);

	/* --- dae-accept yes, only dae-server set: NULL --- */
	rh = new_rh();
	assert(rc_add_config(rh, "dae-accept", "yes", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-server", "192.0.2.1", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);
	dae = radcli_dae_new(rh);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with dae-secret unset\n");
		exit(1);
	}
	rc_destroy(rh);

	/* --- dae-accept yes, only dae-secret set: NULL --- */
	rh = new_rh();
	assert(rc_add_config(rh, "dae-accept", "yes", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-secret", "testing123", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);
	dae = radcli_dae_new(rh);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() succeeded with dae-server unset\n");
		exit(1);
	}
	rc_destroy(rh);

	/* --- dae-server carrying a network prefix: NULL --- */
	rh = new_rh();
	assert(rc_add_config(rh, "dae-accept", "yes", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-server", "192.0.2.0/24", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-secret", "testing123", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);
	dae = radcli_dae_new(rh);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() accepted a dae-server prefix (/24)\n");
		exit(1);
	}
	rc_destroy(rh);

	/* --- dae-secret longer than MAX_SECRET_LENGTH: NULL --- */
	rh = new_rh();
	assert(rc_add_config(rh, "dae-accept", "yes", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-server", "192.0.2.1", "config", 0) == 0);
	{
		char overlong[MAX_SECRET_LENGTH + 2];

		memset(overlong, 'x', sizeof(overlong) - 1);
		overlong[sizeof(overlong) - 1] = '\0';
		assert(rc_add_config(rh, "dae-secret", overlong, "config", 0) == 0);
	}
	assert(rc_apply_config(rh) == 0);
	dae = radcli_dae_new(rh);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() accepted a dae-secret longer "
				"than MAX_SECRET_LENGTH\n");
		exit(1);
	}
	rc_destroy(rh);

	/* --- dae-server ":secret" override longer than MAX_SECRET_LENGTH: NULL --- */
	rh = new_rh();
	assert(rc_add_config(rh, "dae-accept", "yes", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-secret", "testing123", "config", 0) == 0);
	{
		char server[16 + MAX_SECRET_LENGTH + 2];
		char overlong[MAX_SECRET_LENGTH + 2];

		memset(overlong, 'x', sizeof(overlong) - 1);
		overlong[sizeof(overlong) - 1] = '\0';
		snprintf(server, sizeof(server), "192.0.2.1:%s", overlong);
		assert(rc_add_config(rh, "dae-server", server, "config", 0) == 0);
	}
	assert(rc_apply_config(rh) == 0);
	dae = radcli_dae_new(rh);
	if (dae != NULL) {
		fprintf(stderr, "error: radcli_dae_new() accepted a dae-server secret "
				"override longer than MAX_SECRET_LENGTH\n");
		exit(1);
	}
	rc_destroy(rh);

	/* The dae-accept=yes + serv-type=tls/dtls rejection (RadSec attach is
	 * not implemented yet) is not exercised here: reaching it needs a
	 * fully initialized TLS transport (rc_apply_config()'s serv-type=tls
	 * path, lib/tls.c's rc_init_tls()), which needs real certificates --
	 * out of scope for this no-network-I/O unit test. The check itself is
	 * a single, direct rh->so_type comparison in radcli_dae_new(); the
	 * rest of this file exercises radcli_dae_new()'s other validation
	 * branches, which do not depend on a transport being initialized. */

	/* --- fully valid configuration --- */
	rh = new_rh();
	assert(rc_add_config(rh, "dae-accept", "udp", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-server", "192.0.2.1,192.0.2.2:othersecret", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-secret", "testing123", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-listen", "127.0.0.1:0", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);

	/* A second radcli_dae_new() on the same ctx must fail: at most one
	 * active radcli_dae per ctx (radcli_ctx_get_poll()/_dispatch() need a
	 * single descriptor to report). */
	{
		radcli_dae *dae1 = radcli_dae_new(rh);
		radcli_dae *dae2;

		if (dae1 == NULL) {
			fprintf(stderr, "error: radcli_dae_new() failed with a valid configuration\n");
			exit(1);
		}
		dae2 = radcli_dae_new(rh);
		if (dae2 != NULL) {
			fprintf(stderr, "error: a second radcli_dae_new() on the same ctx "
					"did not fail\n");
			exit(1);
		}
		radcli_dae_free(dae1);
	}

	dae = radcli_dae_new(rh);
	if (dae == NULL) {
		fprintf(stderr, "error: radcli_dae_new() failed with a valid configuration\n");
		exit(1);
	}

	radcli_dae_set_handler(dae, unexpected_handler, NULL);

	/* Nothing to watch before radcli_dae_start(). */
	fd = -99;
	events = 0xff;
	timeout_ms = -99;
	if (radcli_ctx_get_poll(rh, &fd, &events, &timeout_ms) != 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() failed\n");
		exit(1);
	}
	if (fd != -1 || events != 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() reported something to "
				"watch before radcli_dae_start()\n");
		exit(1);
	}

	if (radcli_dae_start(dae) != 0) {
		fprintf(stderr, "error: radcli_dae_start() failed on 127.0.0.1:0\n");
		exit(1);
	}

	if (radcli_ctx_get_poll(rh, &fd, &events, &timeout_ms) != 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() failed after radcli_dae_start()\n");
		exit(1);
	}
	if (fd < 0 || !(events & POLLIN)) {
		fprintf(stderr, "error: radcli_ctx_get_poll() did not report the "
				"listener as readable-watched after radcli_dae_start()\n");
		exit(1);
	}

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
	if (radcli_ctx_dispatch(rh) != 0) {
		fprintf(stderr, "error: radcli_ctx_dispatch() with nothing pending "
				"did not return 0\n");
		exit(1);
	}

	radcli_dae_free(dae);

	/* radcli_dae_free(NULL) is a no-op. */
	radcli_dae_free(NULL);

	/* After freeing the only active dae, ctx has nothing to watch again. */
	if (radcli_ctx_get_poll(rh, &fd, &events, &timeout_ms) != 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll() failed after radcli_dae_free()\n");
		exit(1);
	}
	if (fd != -1) {
		fprintf(stderr, "error: radcli_ctx_get_poll() still reported a "
				"descriptor after radcli_dae_free()\n");
		exit(1);
	}

	/* radcli_ctx_get_poll(NULL, ...)/radcli_ctx_dispatch(NULL) fail cleanly. */
	if (radcli_ctx_get_poll(NULL, &fd, &events, &timeout_ms) == 0) {
		fprintf(stderr, "error: radcli_ctx_get_poll(NULL, ...) did not fail\n");
		exit(1);
	}
	if (radcli_ctx_dispatch(NULL) == 0) {
		fprintf(stderr, "error: radcli_ctx_dispatch(NULL) did not fail\n");
		exit(1);
	}

	rc_destroy(rh);

	printf("dae: all tests passed\n");
	return 0;
}
