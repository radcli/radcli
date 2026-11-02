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
 * RADCLI_REQUEST_SENDONLY_NONBLOCK requests on a TCP/TLS session whose send
 * window is full (REQ-NET2-SEND-018, REQ-NET2-NET-005), against
 * tests/nonblock-backpressure-server.py, which stops reading after the
 * warm-up request. Both socket buffers are shrunk, so OLD requests of
 * about 4 KB each cannot all go out.
 *
 *   hold    every OLD request must complete with its own reply once the
 *       peer reads again; the peer checks it received all, intact, in order
 *   cancel  every OLD request is freed while the window is full, and
 *       RADCLI_CTX_MAX_INFLIGHT new requests then reuse every Identifier,
 *       overwriting their slots' packets; all must complete with their own
 *       replies, while the peer checks it received an intact prefix of the
 *       freed requests and then every new one
 *
 * The peer advertises a small MSS, so the packet at the head of the queue
 * when the window fills is partly written, as cancel needs it to be.
 *
 * In both, radcli_request_perform() and radcli_ctx_dispatch() must each
 * return within MAX_CALL_MS, and radcli_ctx_get_poll() must ask for POLLOUT
 * after the OLD requests are submitted: that is what proves the window
 * filled, since only queued packets make it ask.
 */

#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>

/* PW_USER_NAME, PW_REPLY_MESSAGE, PW_CLASS (RFC 2865 SS5.1, SS5.18, SS5.25) */
#define ATTR_USER_NAME 1
#define ATTR_REPLY_MESSAGE 18
#define ATTR_CLASS 25

#define MAX_CALL_MS 200
#define OLD 20
#define NEW 256 /* RADCLI_CTX_MAX_INFLIGHT: every Identifier */
#define FILLERS 15
#define FILLER_LEN 250

static void die(const char *msg) __attribute__((noreturn));

static void die(const char *msg)
{
	fprintf(stderr, "nonblock-backpressure: %s\n", msg);
	exit(1);
}

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static void check_duration(const char *what, double start)
{
	if (now_ms() - start > MAX_CALL_MS) {
		fprintf(stderr, "nonblock-backpressure: %s took %.0f ms\n", what,
			now_ms() - start);
		exit(1);
	}
}

/* A request named name, padded to about 4 KB with fill. */
static radcli_request *new_request(radcli_ctx *ctx, const char *name, char fill)
{
	uint8_t filler[FILLER_LEN];
	radcli_avp_list *send_list;
	radcli_request *r;
	int i;

	memset(filler, fill, sizeof(filler));
	send_list = radcli_avp_list_new();
	if (send_list == NULL ||
	    radcli_avp_add_str_by_num(send_list, ctx, ATTR_USER_NAME, 0, name) != 0)
		die("building a request");
	for (i = 0; fill != 0 && i < FILLERS; i++)
		if (radcli_avp_add_bytes_by_num(send_list, ctx, ATTR_CLASS, 0, filler,
						sizeof(filler)) != 0)
			die("building a request");
	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new");
	return r;
}

static radcli_request *submit(radcli_ctx *ctx, const char *batch, int n, char fill)
{
	radcli_request *r;
	char name[32];
	double start;

	snprintf(name, sizeof(name), "%s-%d", batch, n);
	r = new_request(ctx, name, fill);
	start = now_ms();
	if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY_NONBLOCK) != RADCLI_OK)
		die("radcli_request_perform(RADCLI_REQUEST_SENDONLY_NONBLOCK)");
	check_duration("radcli_request_perform()", start);
	return r;
}

/* Fails unless r's Access-Accept echoes r's own User-Name, as the peer's
 * Reply-Message: a reply matched to the wrong request would not. */
static void check_own_reply(radcli_ctx *ctx, radcli_request *r, const char *name)
{
	const char *echo;

	if (radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT)
		die("a request did not get an Access-Accept");
	echo = radcli_avp_get_cstr_by_num(radcli_request_attrs(r), ctx, ATTR_REPLY_MESSAGE, 0);
	if (echo == NULL || strcmp(echo, name) != 0) {
		fprintf(stderr, "nonblock-backpressure: %s got the reply for %s\n", name,
			echo ? echo : "(none)");
		exit(1);
	}
}

/* Drives r to its result, timing every radcli_ctx_dispatch() call. */
static void drive(radcli_ctx *ctx, radcli_request *r, const char *batch, int n)
{
	char name[32];
	int iterations = 0;
	int rc;

	while ((rc = radcli_request_done(r)) == RADCLI_AGAIN) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;
		double start;

		if (++iterations > 100000)
			die("a request never completed");
		if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0)
			die("radcli_ctx_get_poll");
		poll(pfds, (nfds_t)nfds, timeout_ms);
		start = now_ms();
		if (radcli_ctx_dispatch(ctx) != 0)
			die("radcli_ctx_dispatch");
		check_duration("radcli_ctx_dispatch()", start);
	}
	snprintf(name, sizeof(name), "%s-%d", batch, n);
	if (rc != RADCLI_OK) {
		fprintf(stderr, "nonblock-backpressure: %s ended in %d\n", name, rc);
		exit(1);
	}
	check_own_reply(ctx, r, name);
}

/* Reports the session's descriptor, and whether radcli_ctx_get_poll() asks
 * for POLLOUT on it. */
static int session_fd(radcli_ctx *ctx, int *pollout)
{
	struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
	size_t nfds;
	int timeout_ms;

	if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0 ||
	    nfds != 1)
		die("radcli_ctx_get_poll() did not report the session alone");
	*pollout = (pfds[0].events & POLLOUT) != 0;
	return pfds[0].fd;
}

int main(int argc, char **argv)
{
	radcli_request *old[OLD], *fresh[NEW];
	radcli_request *r;
	radcli_ctx *ctx;
	char authserver[64];
	int tls, cancel, i, fd, pollout;
	int sndbuf = 1, roomy = 1 << 20;

	if (argc != 5) {
		fprintf(stderr, "usage: %s tls <port> <tls-ca-file> hold|cancel\n"
				"       %s tcp <port> <secret> hold|cancel\n", argv[0], argv[0]);
		return 2;
	}
	tls = strcmp(argv[1], "tls") == 0;
	cancel = strcmp(argv[4], "cancel") == 0;
	if (!cancel && strcmp(argv[4], "hold") != 0)
		die("unknown mode");

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");
	if (tls) {
		snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[2]);
		if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
		    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[3]) != 0)
			die("TLS option setup failed");
	} else {
		snprintf(authserver, sizeof(authserver), "127.0.0.1:%s:%s", argv[2], argv[3]);
		if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tcp") != 0)
			die("TCP option setup failed");
	}
	/* The timeout outlasts the peer's hold and the drain that follows. */
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 20) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 0) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 0) != 0)
		die("option setup failed");
	if (radcli_ctx_apply(ctx) != 0)
		die("radcli_ctx_apply");

	r = new_request(ctx, "warmup", 0);
	if (radcli_request_perform(r, RADCLI_REQUEST_NONE) != RADCLI_OK)
		die("the warm-up request failed");
	check_own_reply(ctx, r, "warmup");
	radcli_request_free(r);

	/* Linux raises this to its floor, a few KB. */
	fd = session_fd(ctx, &pollout);
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) != 0)
		die("setsockopt(SO_SNDBUF)");

	for (i = 0; i < OLD; i++)
		old[i] = submit(ctx, "old", i, 'o');
	session_fd(ctx, &pollout);
	if (!pollout)
		die("no packet was queued: the send window never filled");

	if (cancel) {
		for (i = 0; i < OLD; i++)
			radcli_request_free(old[i]);
		for (i = 0; i < NEW; i++)
			fresh[i] = submit(ctx, "new", i, 'n');
	}

	/* The window has filled; at its floor, draining it would outlast
	 * the timeout (each packet waits on delayed ACKs). */
	if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &roomy, sizeof(roomy)) != 0)
		die("setsockopt(SO_SNDBUF)");

	if (!cancel) {
		for (i = 0; i < OLD; i++) {
			drive(ctx, old[i], "old", i);
			radcli_request_free(old[i]);
		}
	} else {
		for (i = 0; i < NEW; i++) {
			drive(ctx, fresh[i], "new", i);
			radcli_request_free(fresh[i]);
		}
	}

	radcli_ctx_free(ctx);
	printf("nonblock-backpressure: %s passed\n", argv[4]);
	return 0;
}
