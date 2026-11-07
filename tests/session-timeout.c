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
 * Requests left unanswered on a TCP/TLS session, against
 * tests/session-timeout-server.py, with radius_timeout 1 (2 in stall)
 * and radius_retries 1. SESSION_TIMEOUT_ADDRESS (tcp only) and
 * SESSION_TIMEOUT_NAMESPACE, if set, override the server address and set
 * the namespace option, for tests/namespace-reconnect-tests.sh:
 *
 *   once-blocking, once-sendonly  the peer never answers and keeps the
 *       connection open; the request must end in RADCLI_TIMEOUT, whatever
 *       non-RADIUS TLS records arrive meanwhile (REQ-NET-NET-021), sent
 *       only once (REQ-NET-NET-022, RFC 6613 SS2.6.1)
 *   drop-sendonly, drop-nonblock  the peer closes the connection unanswered;
 *       the request must be resent over a new connection and succeed
 *       (REQ-NET-NET-022)
 *   stall  a TLS peer closes the connection unanswered and then never
 *       completes a new handshake; no radcli_ctx_dispatch() call may wait
 *       for it (REQ-NET2-NET-001), and the request must time out
 *   nonblock-mute  a TLS peer never answers the handshake; neither
 *       radcli_request_perform(RADCLI_REQUEST_SENDONLY_NONBLOCK) nor any
 *       radcli_ctx_dispatch() call may wait for it (REQ-NET2-SEND-018),
 *       and the request must time out
 *   nonblock-burst  BURST requests submitted with
 *       RADCLI_REQUEST_SENDONLY_NONBLOCK before the connection is up, FREED of them freed before the first
 *       radcli_ctx_dispatch(); the rest must succeed, and the peer must
 *       receive only those (REQ-NET2-SEND-018)
 *
 * The dtls transport needs no peer process: the client binds a UDP socket
 * it never reads, standing in for a server that never answers the handshake.
 * Its modes are nonblock-mute, whose loop must not spin on an already
 * writable socket (REQ-NET-NET-023), and:
 *
 *   blocking-mute  radcli_request_perform(RADCLI_REQUEST_NONE) must fail
 *       without spending the wait on the CPU (REQ-NET-NET-023)
 *   sendfail-once  the first UDP send fails with EAGAIN on a writable
 *       socket; it must be retried well before the retransmission timer
 *       (REQ-NET-NET-023)
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Longest a radcli_ctx_dispatch() call may take in stall mode. */
#define MAX_DISPATCH_MS 200

/* sendfail-once: well before the 1000 ms retransmission timer. */
#define MAX_RETRY_MS 500

static int sends_to_fail;
static double first_send_ms;

/* nonblock-burst: more requests than the session queue has copies for. */
#define BURST 20
#define FREED 5

static void die(const char *msg) __attribute__((noreturn));

static void die(const char *msg)
{
	fprintf(stderr, "session-timeout: %s\n", msg);
	exit(1);
}

static double now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

/* Replaces libc's, for the sends GnuTLS makes. */
ssize_t sendmsg(int fd, const struct msghdr *msg, int flags)
{
	if (sends_to_fail > 0) {
		sends_to_fail--;
		errno = EAGAIN;
		return -1;
	}
	if (first_send_ms == 0)
		first_send_ms = now_ms();
	return syscall(SYS_sendmsg, fd, msg, flags);
}

static radcli_request *new_request(radcli_ctx *ctx)
{
	radcli_avp_list *send_list;
	radcli_request *r;

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str_by_num(send_list, ctx, PW_USER_NAME, 0, "radcli-timeout") != 0)
		die("radcli_avp_add_str_by_num");
	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new");
	return r;
}

/* Drives r to its result through radcli_ctx_get_poll()/radcli_ctx_dispatch(),
 * failing if any dispatch call takes longer than max_dispatch_ms (if > 0). */
static int drive(radcli_ctx *ctx, radcli_request *r, double max_dispatch_ms)
{
	int iterations = 0;
	int rc;

	while ((rc = radcli_request_done(r)) == RADCLI_AGAIN) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;
		double start;

		if (++iterations > 10000)
			die("the request never completed");
		if (radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0)
			die("radcli_ctx_get_poll");
		/* REQ-NET2-NET-001: nothing else would end a pending request. */
		if (timeout_ms < 0)
			die("radcli_ctx_get_poll() reported no deadline for a pending request");
		poll(pfds, (nfds_t)nfds, timeout_ms);
		start = now_ms();
		if (radcli_ctx_dispatch(ctx) != 0)
			die("radcli_ctx_dispatch");
		if (max_dispatch_ms > 0 && now_ms() - start > max_dispatch_ms) {
			fprintf(stderr, "session-timeout: radcli_ctx_dispatch() took %.0f ms\n",
				now_ms() - start);
			exit(1);
		}
	}
	return rc;
}

/* Performs r with RADCLI_REQUEST_SENDONLY_NONBLOCK, failing unless it returns
 * RADCLI_OK within MAX_DISPATCH_MS. */
static void perform_nonblock(radcli_request *r)
{
	double start = now_ms();

	if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY_NONBLOCK) != RADCLI_OK)
		die("radcli_request_perform(RADCLI_REQUEST_SENDONLY_NONBLOCK)");
	if (now_ms() - start > MAX_DISPATCH_MS) {
		fprintf(stderr, "session-timeout: radcli_request_perform() took %.0f ms\n",
			now_ms() - start);
		exit(1);
	}
}

/* Binds a UDP socket that is never read, returning its port in *port. */
static int silent_udp_peer(int *port)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		die("socket");
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    getsockname(fd, (struct sockaddr *)&addr, &len) != 0)
		die("bind");
	*port = ntohs(addr.sin_port);
	return fd;
}

int main(int argc, char **argv)
{
	radcli_request *burst[BURST];
	radcli_ctx *ctx;
	radcli_request *r;
	char authserver[64];
	const char *mode;
	const char *address = getenv("SESSION_TIMEOUT_ADDRESS");
	const char *netns = getenv("SESSION_TIMEOUT_NAMESPACE");
	int tls, dtls, stall, rc;
	int silent_fd = -1;

	if (argc != 5) {
		fprintf(stderr, "usage: %s tls <port> <tls-ca-file> <mode>\n"
				"       %s tcp <port> <secret> <mode>\n"
				"       %s dtls - - <mode>\n", argv[0], argv[0], argv[0]);
		return 2;
	}
	tls = strcmp(argv[1], "tls") == 0;
	dtls = strcmp(argv[1], "dtls") == 0;
	mode = argv[4];
	stall = strcmp(mode, "stall") == 0;

	ctx = radcli_ctx_new(0);
	if (ctx == NULL)
		die("radcli_ctx_new");
	if (dtls) {
		static const uint8_t psk[] = "0123456789abcdef";
		int port;

		silent_fd = silent_udp_peer(&port);
		snprintf(authserver, sizeof(authserver), "127.0.0.1:%d", port);
		if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "dtls") != 0 ||
		    radcli_ctx_set_tls_psk(ctx, "radcli", 6, psk, sizeof(psk) - 1) != 0)
			die("DTLS option setup failed");
	} else if (tls) {
		snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[2]);
		if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tls") != 0 ||
		    radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, argv[3]) != 0)
			die("TLS option setup failed");
	} else {
		snprintf(authserver, sizeof(authserver), "%s:%s:%s",
			 address ? address : "127.0.0.1", argv[2], argv[3]);
		if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, "tcp") != 0)
			die("TCP option setup failed");
	}
	if (netns != NULL && radcli_ctx_set_opt_str(ctx, RADCLI_OPT_NAMESPACE, netns) != 0)
		die("namespace option setup failed");
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, stall ? 2 : 1) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 1) != 0 ||
	    radcli_ctx_set_opt_int(ctx, RADCLI_OPT_WATCHDOG_INTERVAL, 0) != 0)
		die("option setup failed");
	if (radcli_ctx_apply(ctx) != 0)
		die("radcli_ctx_apply");

	if (strcmp(mode, "blocking-mute") == 0) {
		clock_t cpu_start = clock();
		double start = now_ms();
		double cpu_ms;

		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_NONE) == RADCLI_OK)
			die("a request whose server never answered succeeded");
		cpu_ms = (double)(clock() - cpu_start) * 1000.0 / CLOCKS_PER_SEC;
		if (cpu_ms > (now_ms() - start) / 2) {
			fprintf(stderr, "session-timeout: spent %.0f of %.0f ms on the CPU\n",
				cpu_ms, now_ms() - start);
			exit(1);
		}
	} else if (strcmp(mode, "once-blocking") == 0) {
		r = new_request(ctx);
		rc = radcli_request_perform(r, RADCLI_REQUEST_NONE);
		if (rc != RADCLI_TIMEOUT)
			die("an unanswered request did not time out");
	} else if (strcmp(mode, "once-sendonly") == 0) {
		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
			die("radcli_request_perform(RADCLI_REQUEST_SENDONLY)");
		if (drive(ctx, r, 0) != RADCLI_TIMEOUT)
			die("an unanswered request did not time out");
	} else if (strcmp(mode, "drop-sendonly") == 0) {
		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
			die("radcli_request_perform(RADCLI_REQUEST_SENDONLY)");
		rc = drive(ctx, r, 0);
		if (rc != RADCLI_OK || radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT)
			die("the request resent over a new connection did not succeed");
	} else if (strcmp(mode, "drop-nonblock") == 0) {
		r = new_request(ctx);
		perform_nonblock(r);
		rc = drive(ctx, r, 0);
		if (rc != RADCLI_OK || radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT)
			die("the request resent over a new connection did not succeed");
	} else if (stall) {
		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_NONE) != RADCLI_OK)
			die("the warm-up request failed");
		radcli_request_free(r);
		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
			die("radcli_request_perform(RADCLI_REQUEST_SENDONLY)");
		if (drive(ctx, r, MAX_DISPATCH_MS) == RADCLI_OK)
			die("a request whose server never answered succeeded");
	} else if (strcmp(mode, "nonblock-mute") == 0) {
		r = new_request(ctx);
		perform_nonblock(r);
		if (drive(ctx, r, MAX_DISPATCH_MS) != RADCLI_TIMEOUT)
			die("a request whose server never completed the handshake did not time out");
	} else if (strcmp(mode, "nonblock-burst") == 0) {
		int i;

		for (i = 0; i < BURST; i++) {
			burst[i] = new_request(ctx);
			perform_nonblock(burst[i]);
		}
		/* Spread over the queue, not only its tail. */
		for (i = 0; i < FREED; i++) {
			radcli_request_free(burst[i * (BURST / FREED)]);
			burst[i * (BURST / FREED)] = NULL;
		}
		for (i = 0; i < BURST; i++) {
			if (burst[i] == NULL)
				continue;
			rc = drive(ctx, burst[i], MAX_DISPATCH_MS);
			if (rc != RADCLI_OK || radcli_request_code(burst[i]) != RADCLI_CODE_ACCESS_ACCEPT)
				die("a queued request did not succeed");
			radcli_request_free(burst[i]);
		}
		r = NULL;
	} else if (strcmp(mode, "sendfail-once") == 0) {
		double start = now_ms();

		sends_to_fail = 1;
		r = new_request(ctx);
		if (radcli_request_perform(r, RADCLI_REQUEST_NONE) == RADCLI_OK)
			die("a request whose server never answered succeeded");
		if (sends_to_fail != 0)
			die("no send went through the replaced sendmsg()");
		if (first_send_ms == 0 || first_send_ms - start > MAX_RETRY_MS)
			die("the failed send was not retried promptly");
	} else {
		die("unknown mode");
	}

	radcli_request_free(r);
	radcli_ctx_free(ctx);
	if (silent_fd != -1)
		close(silent_fd);
	printf("session-timeout: %s passed\n", mode);
	return 0;
}
