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
 * Minimal TLS/DTLS-to-UDP proxy server for close_notify testing.
 *
 * Acts as a TLS (TCP) or DTLS (UDP) frontend that forwards raw RADIUS packets
 * to a plain-UDP backend (radius-server.py) and relays the response back.
 * After one request/response exchange it waits for the client to send a
 * TLS close_notify alert.
 *
 * Exit 0: close_notify received (correct behaviour after the fix).
 * Exit 1: connection closed without close_notify (bug: gnutls_bye() missing).
 * Exit 2: setup or handshake failure (not the bug under test).
 *
 * Usage:
 *   close-notify-server [--dtls] --port PORT --backend-port PORT
 *                       --ca CA_FILE --cert CERT_FILE --key KEY_FILE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>

#define BUF_SIZE 4096

/* ------------------------------------------------------------------ */
/* DTLS custom transport                                               */
/* ------------------------------------------------------------------ */

/*
 * For DTLS the listening socket is UDP (connectionless).  We call recvfrom()
 * once to learn the client's address and buffer that first datagram, then
 * connect() the socket so that subsequent send()/recv() work normally.
 * GnuTLS calls our pull function before the handshake to read that first
 * datagram, so we serve it from the buffer on the first call.
 */
typedef struct {
	int fd;
	uint8_t first_buf[BUF_SIZE];
	ssize_t first_len;	/* >= 0: unconsumed; -1: already consumed */
} udp_tr_t;

static ssize_t
udp_push(gnutls_transport_ptr_t ptr, const void *buf, size_t len)
{
	udp_tr_t *t = ptr;
	return send(t->fd, buf, len, 0);
}

static ssize_t
udp_pull(gnutls_transport_ptr_t ptr, void *buf, size_t len)
{
	udp_tr_t *t = ptr;
	if (t->first_len >= 0) {
		ssize_t n = t->first_len < (ssize_t)len
		            ? t->first_len : (ssize_t)len;
		memcpy(buf, t->first_buf, n);
		t->first_len = -1;
		return n;
	}
	return recv(t->fd, buf, len, 0);
}

static int
udp_pull_timeout(gnutls_transport_ptr_t ptr, unsigned ms)
{
	udp_tr_t *t = ptr;
	fd_set fds;
	struct timeval tv;

	if (t->first_len >= 0)
		return 1;	/* data buffered, immediately available */

	FD_ZERO(&fds);
	FD_SET(t->fd, &fds);

	if (ms == GNUTLS_INDEFINITE_TIMEOUT)
		return select(t->fd + 1, &fds, NULL, NULL, NULL);

	tv.tv_sec  = ms / 1000;
	tv.tv_usec = (ms % 1000) * 1000;
	return select(t->fd + 1, &fds, NULL, NULL, &tv);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

static struct option longopts[] = {
	{ "dtls",         no_argument,       NULL, 'd' },
	{ "port",         required_argument, NULL, 'p' },
	{ "backend-port", required_argument, NULL, 'b' },
	{ "ca",           required_argument, NULL, 'a' },
	{ "cert",         required_argument, NULL, 'c' },
	{ "key",          required_argument, NULL, 'k' },
	{ NULL, 0, NULL, 0 }
};

int main(int argc, char **argv)
{
	int dtls = 0, port = 0, backend_port = 0;
	const char *ca = NULL, *cert = NULL, *key = NULL;
	int opt, ret;

	while ((opt = getopt_long(argc, argv, "dp:b:a:c:k:", longopts,
				  NULL)) != -1) {
		switch (opt) {
		case 'd': dtls = 1; break;
		case 'p': port = atoi(optarg); break;
		case 'b': backend_port = atoi(optarg); break;
		case 'a': ca = optarg; break;
		case 'c': cert = optarg; break;
		case 'k': key = optarg; break;
		default:
			fprintf(stderr,
				"Usage: close-notify-server [--dtls] "
				"--port P --backend-port P "
				"--ca F --cert F --key F\n");
			return 2;
		}
	}

	if (!port || !backend_port || !ca || !cert || !key) {
		fprintf(stderr,
			"close-notify-server: missing required arguments\n");
		return 2;
	}

	gnutls_global_init();

	/* -- credentials (shared by TLS and DTLS) -- */
	gnutls_certificate_credentials_t cred;
	gnutls_certificate_allocate_credentials(&cred);

	ret = gnutls_certificate_set_x509_trust_file(cred, ca,
						     GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		fprintf(stderr, "close-notify-server: ca: %s\n",
			gnutls_strerror(ret));
		return 2;
	}

	ret = gnutls_certificate_set_x509_key_file(cred, cert, key,
						   GNUTLS_X509_FMT_PEM);
	if (ret < 0) {
		fprintf(stderr, "close-notify-server: cert/key: %s\n",
			gnutls_strerror(ret));
		return 2;
	}

	/* -- listening socket -- */
	int type = dtls ? SOCK_DGRAM : SOCK_STREAM;
	int fd = socket(AF_INET, type, 0);
	if (fd < 0) { perror("socket"); return 2; }

	int on = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	struct sockaddr_in saddr = {
		.sin_family      = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port        = htons(port),
	};
	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("bind"); return 2;
	}

	/* Print the actual port so the shell script can detect startup */
	socklen_t slen = sizeof(saddr);
	getsockname(fd, (struct sockaddr *)&saddr, &slen);
	printf("PORT %d\n", ntohs(saddr.sin_port));
	fflush(stdout);

	/* -- accept / connect -- */
	gnutls_session_t session;
	udp_tr_t tr;
	int conn_fd = -1;

	if (dtls) {
		/* Receive first datagram to learn client address */
		struct sockaddr_in caddr;
		socklen_t clen = sizeof(caddr);
		tr.fd = fd;
		tr.first_len = recvfrom(fd, tr.first_buf, sizeof(tr.first_buf),
					0, (struct sockaddr *)&caddr, &clen);
		if (tr.first_len < 0) { perror("recvfrom"); return 2; }

		/* Connect so send()/recv() are addressed to this client */
		if (connect(fd, (struct sockaddr *)&caddr, clen) < 0) {
			perror("connect"); return 2;
		}

		gnutls_init(&session, GNUTLS_SERVER | GNUTLS_DATAGRAM);
		gnutls_transport_set_ptr(session, &tr);
		gnutls_transport_set_push_function(session, udp_push);
		gnutls_transport_set_pull_function(session, udp_pull);
		gnutls_transport_set_pull_timeout_function(session,
							   udp_pull_timeout);
		gnutls_dtls_set_timeouts(session, 100, 10000);
	} else {
		if (listen(fd, 1) < 0) { perror("listen"); return 2; }

		conn_fd = accept(fd, NULL, NULL);
		if (conn_fd < 0) { perror("accept"); return 2; }

		gnutls_init(&session, GNUTLS_SERVER);
		gnutls_transport_set_int(session, conn_fd);
	}

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
	gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUIRE);
	gnutls_set_default_priority(session);

	/* -- handshake -- */
	do {
		ret = gnutls_handshake(session);
	} while (ret < 0 && !gnutls_error_is_fatal(ret));

	if (ret < 0) {
		fprintf(stderr, "close-notify-server: handshake: %s\n",
			gnutls_strerror(ret));
		gnutls_deinit(session);
		gnutls_certificate_free_credentials(cred);
		if (conn_fd >= 0) close(conn_fd);
		close(fd);
		return 2;
	}

	/* -- proxy: one RADIUS request/response round-trip -- */
	uint8_t req[BUF_SIZE], resp[BUF_SIZE];

	int n = gnutls_record_recv(session, req, sizeof(req));
	if (n <= 0) {
		fprintf(stderr, "close-notify-server: recv request: %s\n",
			n < 0 ? gnutls_strerror(n) : "empty");
		gnutls_deinit(session);
		gnutls_certificate_free_credentials(cred);
		if (conn_fd >= 0) close(conn_fd);
		close(fd);
		return 2;
	}

	/* Forward to radius-server.py over plain UDP */
	int udpfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (udpfd < 0) { perror("udp socket"); return 2; }

	struct sockaddr_in beaddr = {
		.sin_family      = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
		.sin_port        = htons(backend_port),
	};
	if (connect(udpfd, (struct sockaddr *)&beaddr, sizeof(beaddr)) < 0) {
		perror("connect backend"); return 2;
	}

	if (send(udpfd, req, n, 0) < 0) {
		perror("send to backend"); return 2;
	}

	/* Wait for response from radius-server.py (5 second timeout) */
	fd_set rfds;
	struct timeval tv = { 5, 0 };
	FD_ZERO(&rfds);
	FD_SET(udpfd, &rfds);
	if (select(udpfd + 1, &rfds, NULL, NULL, &tv) <= 0) {
		fprintf(stderr, "close-notify-server: backend timeout\n");
		return 2;
	}
	int m = recv(udpfd, resp, sizeof(resp), 0);
	if (m <= 0) {
		fprintf(stderr, "close-notify-server: backend recv failed\n");
		return 2;
	}
	close(udpfd);

	ret = gnutls_record_send(session, resp, m);
	if (ret < 0) {
		fprintf(stderr, "close-notify-server: send response: %s\n",
			gnutls_strerror(ret));
		gnutls_deinit(session);
		gnutls_certificate_free_credentials(cred);
		if (conn_fd >= 0) close(conn_fd);
		close(fd);
		return 2;
	}

	/*
	 * Wait for TLS close_notify from the client (2-second window).
	 *
	 * gnutls_record_recv() returns:
	 *   0                          — close_notify received (correct)
	 *   GNUTLS_E_PREMATURE_TERMINATION — TCP closed without close_notify
	 *   GNUTLS_E_TIMEDOUT          — DTLS: client vanished without close_notify
	 */
	gnutls_record_set_timeout(session, 2000);
	uint8_t dummy[1];
	ret = gnutls_record_recv(session, dummy, sizeof(dummy));

	int exit_code;
	if (ret == 0) {
		printf("PASS: close_notify received\n");
		exit_code = 0;
	} else {
		printf("FAIL: expected close_notify, got: %s\n",
		       gnutls_strerror(ret));
		exit_code = 1;
	}
	fflush(stdout);

	gnutls_deinit(session);
	gnutls_certificate_free_credentials(cred);
	gnutls_global_deinit();
	if (conn_fd >= 0) close(conn_fd);
	close(fd);
	return exit_code;
}
