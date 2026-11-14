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

/* Unit test for radcli_request_set_timeout() (REQ-NET2-INIT-009). The
 * server is a local UDP socket that never replies, so the number of
 * datagrams it has queued is the number of attempts radcli made. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <poll.h>

#include <radcli/radcli2.h>

static double test_mtime(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

static int drain_count(int sfd)
{
	char buf[4096];
	int n = 0;

	while (recv(sfd, buf, sizeof(buf), MSG_DONTWAIT) >= 0)
		n++;
	return n;
}

static radcli_request *new_request(radcli_ctx *ctx, radcli_code code)
{
	radcli_avp_list *send = radcli_avp_list_new();
	radcli_request *r;

	assert(send != NULL);
	assert(radcli_avp_add_str(send, radcli_dict_lookup(ctx, "User-Name"), "alice") == 0);
	r = radcli_request_new(ctx, code, send);
	radcli_avp_list_free(send);
	assert(r != NULL);
	return r;
}

static int drive_to_completion(radcli_ctx *ctx, radcli_request *r)
{
	int rc, iterations = 0;

	while ((rc = radcli_request_done(r)) == RADCLI_AGAIN) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;

		if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0 ||
		    ++iterations > 100) {
			fprintf(stderr, "error: request never resolved\n");
			exit(1);
		}
		poll(pfds, (nfds_t)nfds, timeout_ms);
		radcli_ctx_dispatch(ctx);
	}
	return rc;
}

int main(void)
{
	struct sockaddr_in sa;
	socklen_t salen = sizeof(sa);
	char server[64];
	radcli_ctx *ctx;
	radcli_request *r;
	double start, elapsed;
	int sfd, rc, n;

	sfd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(sfd >= 0);
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	assert(bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) == 0);
	assert(getsockname(sfd, (struct sockaddr *)&sa, &salen) == 0);

	ctx = radcli_ctx_new(0);
	assert(ctx != NULL);
	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 1) == 0);
	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 2) == 0);
	snprintf(server, sizeof(server), "127.0.0.1:%u:testing123", ntohs(sa.sin_port));
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, server) == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_ACCTSERVER, server) == 0);
	assert(radcli_ctx_apply(ctx) == 0);

	/* --- invalid arguments are rejected --- */

	r = new_request(ctx, RADCLI_CODE_ACCOUNTING_REQUEST);
	if (radcli_request_set_timeout(NULL, 1, 0) != -1 ||
	    radcli_request_set_timeout(r, 0, 0) != -1 ||
	    radcli_request_set_timeout(r, -1, 0) != -1 ||
	    radcli_request_set_timeout(r, 1, -1) != -1) {
		fprintf(stderr, "error: radcli_request_set_timeout() accepted an invalid argument\n");
		exit(1);
	}

	/* --- SENDONLY_NONBLOCK: (1500ms, 0) replaces the context's (1s, 2), so
	 * one datagram and a timeout after ~1.5s, rather than three after ~3s.
	 * Once performed, the request no longer accepts an override. --- */

	if (radcli_request_set_timeout(r, 1500, 0) != 0) {
		fprintf(stderr, "error: radcli_request_set_timeout(r, 1500, 0) failed\n");
		exit(1);
	}
	start = test_mtime();
	assert(radcli_request_perform(r, RADCLI_REQUEST_SENDONLY_NONBLOCK) == RADCLI_OK);
	if (radcli_request_set_timeout(r, 1000, 0) != -1) {
		fprintf(stderr, "error: radcli_request_set_timeout() succeeded after perform()\n");
		exit(1);
	}
	rc = drive_to_completion(ctx, r);
	elapsed = test_mtime() - start;
	n = drain_count(sfd);
	if (rc != RADCLI_TIMEOUT || n != 1 || elapsed < 1.4 || elapsed > 2.5) {
		fprintf(stderr, "error: NONBLOCK request set to (1500ms, 0): rc=%d, %d datagrams, "
				"%.2fs; expected RADCLI_TIMEOUT, 1 datagram, ~1.5s\n", rc, n, elapsed);
		exit(1);
	}
	radcli_request_free(r);

	/* --- blocking perform: (500ms, 0) sends once and gives up well
	 * before the context's 1s timeout --- */

	r = new_request(ctx, RADCLI_CODE_ACCESS_REQUEST);
	assert(radcli_request_set_timeout(r, 500, 0) == 0);
	start = test_mtime();
	rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
	elapsed = test_mtime() - start;
	n = drain_count(sfd);
	if (rc != RADCLI_TIMEOUT || n != 1 || elapsed < 0.4 || elapsed > 0.9) {
		fprintf(stderr, "error: blocking request set to (500ms, 0): rc=%d, %d datagrams, "
				"%.2fs; expected RADCLI_TIMEOUT, 1 datagram, ~0.5s\n", rc, n, elapsed);
		exit(1);
	}
	radcli_request_free(r);

	/* --- the overrides above left the context alone: a request without
	 * one still makes 1 + radius_retries attempts --- */

	r = new_request(ctx, RADCLI_CODE_ACCOUNTING_REQUEST);
	assert(radcli_request_perform(r, RADCLI_REQUEST_SENDONLY_NONBLOCK) == RADCLI_OK);
	rc = drive_to_completion(ctx, r);
	n = drain_count(sfd);
	if (rc != RADCLI_TIMEOUT || n != 3) {
		fprintf(stderr, "error: request without an override: rc=%d, %d datagrams; "
				"expected RADCLI_TIMEOUT, 3 datagrams\n", rc, n);
		exit(1);
	}
	radcli_request_free(r);

	radcli_ctx_free(ctx);
	close(sfd);
	return 0;
}
