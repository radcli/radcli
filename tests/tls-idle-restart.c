/*
 * Copyright (c) 2026 Nikos Mavrogiannopoulos
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Test for TLS reconnection after server-side idle close (issue #89).
 *
 * Sequence:
 *  1. Make a successful RADIUS/TLS request (establishes session).
 *  2. Signal shell: "ready_to_kill" - shell kills radiusd (simulates idle FIN).
 *  3. Wait for shell: "server_killed".
 *  4. Make request 2 - fails because server closed the TLS connection.
 *     need_restart flag is set.
 *  5. Make request 3 - restart_session() is called, but server is still down,
 *     so init_session() fails; need_restart stays set.
 *  6. Signal shell: "restart_server".
 *  7. Wait for shell: "server_up" - shell has restarted radiusd.
 *  8. Make request 4 - this is the key: need_restart is still set from
 *     request 3's own failed attempt moments earlier. Originally (issue #89),
 *     a TIME_ALIVE-based rate-limit in restart_session() blocked this
 *     immediate retry regardless of need_restart, so the request failed even
 *     though the server was back up. The fix made restart_session() bypass
 *     that limit whenever need_restart is set; the throttle itself (along
 *     with the TLS heartbeat probe that was its only other caller) has since
 *     been removed outright, so restart_session() now always reinitializes
 *     unconditionally -- this test still guards the same regression: request
 *     4 must succeed.
 *
 * Exit code: 0 on success (request 4 succeeded), 1 on failure (bug present).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include <radcli/radcli.h>

#define STATE_READY_TO_KILL	"ready_to_kill"
#define STATE_SERVER_KILLED	"server_killed"
#define STATE_RESTART_SERVER	"restart_server"
#define STATE_SERVER_UP		"server_up"

#define POLL_INTERVAL_US	100000	/* 100ms */
#define POLL_TIMEOUT_S		30

static void create_flag(const char *statedir, const char *name)
{
	char path[512];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", statedir, name);
	f = fopen(path, "w");
	if (f == NULL) {
		fprintf(stderr, "tls-idle-restart: cannot create %s: %s\n",
			path, strerror(errno));
		exit(1);
	}
	fclose(f);
}

static void wait_for_flag(const char *statedir, const char *name)
{
	char path[512];
	int elapsed = 0;

	snprintf(path, sizeof(path), "%s/%s", statedir, name);
	while (access(path, F_OK) != 0) {
		usleep(POLL_INTERVAL_US);
		elapsed++;
		if (elapsed * POLL_INTERVAL_US >= POLL_TIMEOUT_S * 1000000) {
			fprintf(stderr,
				"tls-idle-restart: timed out waiting for %s\n",
				path);
			exit(1);
		}
	}
}

static int do_auth(void *rh, VALUE_PAIR *send, int nas_port)
{
	VALUE_PAIR *received = NULL;
	char msg[PW_MAX_MSG_SIZE];
	int ret;

	ret = rc_auth(rh, nas_port, send, &received, msg);
	if (received != NULL)
		rc_avpair_free(received);
	return ret;
}

int main(int argc, char **argv)
{
	int ch, nas_port = 5060;
	char *rc_conf = NULL;
	char *statedir = NULL;
	void *rh = NULL;
	VALUE_PAIR *send = NULL;
	int ret;
	int exit_code = 0;

	/* radcli does not touch process-wide signal disposition itself (that's
	 * for the application embedding it to decide) -- a write to a peer
	 * that already reset the connection (e.g. the graceful close_notify
	 * deinit_session() sends for a session whose server just died) would
	 * otherwise raise SIGPIPE, whose default disposition kills the
	 * process outright with no diagnostic output. */
	signal(SIGPIPE, SIG_IGN);

	while ((ch = getopt(argc, argv, "f:p:S:")) != -1) {
		switch (ch) {
		case 'f':
			rc_conf = optarg;
			break;
		case 'p':
			nas_port = atoi(optarg);
			break;
		case 'S':
			statedir = optarg;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (rc_conf == NULL || statedir == NULL) {
		fprintf(stderr,
			"Usage: tls-idle-restart -f conffile -S statedir [AV-pairs]\n");
		return 1;
	}

	if ((rh = rc_read_config(rc_conf)) == NULL) {
		fprintf(stderr, "tls-idle-restart: error opening config\n");
		return 1;
	}

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
		fprintf(stderr, "tls-idle-restart: error reading dictionary\n");
		exit_code = 1;
		goto cleanup;
	}

	for (int i = 0; i < argc; i++) {
		if (rc_avpair_parse(rh, argv[i], &send) < 0) {
			fprintf(stderr, "tls-idle-restart: can't parse: %s\n",
				argv[i]);
			exit_code = 1;
			goto cleanup;
		}
	}

	/* Request 1: must succeed to establish the TLS session. */
	ret = do_auth(rh, send, nas_port);
	if (ret != OK_RC) {
		fprintf(stderr,
			"tls-idle-restart: initial request failed (%d)\n", ret);
		exit_code = 1;
		goto cleanup;
	}

	/* Signal shell to kill radiusd (simulates server-side idle timeout). */
	create_flag(statedir, STATE_READY_TO_KILL);
	wait_for_flag(statedir, STATE_SERVER_KILLED);

	/*
	 * Request 2: server has sent FIN. The send may succeed at the TCP
	 * level but the receive will fail with GNUTLS_E_PREMATURE_TERMINATION,
	 * setting need_restart=1.  Expected to fail; not an error here.
	 */
	ret = do_auth(rh, send, nas_port);
	if (ret == OK_RC) {
		/*
		 * Occasionally the reconnect in tls_sendto() fires for a
		 * different reason and succeeds - that's acceptable.
		 * The bug only manifests on request 4 regardless.
		 */
		fprintf(stderr,
			"tls-idle-restart: request 2 unexpectedly succeeded\n");
	}

	/*
	 * Request 3: need_restart=1 from request 2.  restart_session() is
	 * called, but init_session() fails because the server is still down;
	 * need_restart stays set.  Expected to fail.
	 */
	ret = do_auth(rh, send, nas_port);
	if (ret == OK_RC) {
		fprintf(stderr,
			"tls-idle-restart: request 3 unexpectedly succeeded\n");
	}

	/* Signal shell to restart radiusd. */
	create_flag(statedir, STATE_RESTART_SERVER);
	wait_for_flag(statedir, STATE_SERVER_UP);

	/*
	 * Request 4: need_restart is still set from request 3's own failed
	 * attempt moments earlier.
	 *
	 * Bug (issue #89): a TIME_ALIVE-based rate-limit in restart_session()
	 * blocked this immediate retry regardless of need_restart, so
	 * gnutls_record_send() was called on the still-dead session and failed.
	 *
	 * Fix: bypass the rate-limit when need_restart is explicitly set (the
	 * rate-limit itself, along with the TLS heartbeat probe that was its
	 * only other caller, has since been removed outright -- restart_session()
	 * now always reinitializes unconditionally, so this is simply the
	 * default behavior rather than a special-cased bypass).
	 */
	ret = do_auth(rh, send, nas_port);
	if (ret != OK_RC) {
		fprintf(stderr,
			"tls-idle-restart: request 4 failed after server "
			"restart - reconnection was blocked (issue #89)\n");
		exit_code = 1;
		goto cleanup;
	}

	fprintf(stderr,
		"tls-idle-restart: successfully reconnected after server restart\n");

cleanup:
	rc_avpair_free(send);
	rc_destroy(rh);
	return exit_code;
}
