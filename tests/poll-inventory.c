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

/* REQ-NET2-NET-001: radcli_ctx_get_poll() reports every socket radcli holds
 * open for a ctx, across serv-type x DAE mode x request state. Rather than
 * pinning each combination's expected descriptors, it compares the sockets
 * that appeared in /proc/self/fd since the ctx was built with what was
 * reported, so a descriptor added later to the library is caught too.
 *
 * With no arguments, every peer is a local socket that never answers, so
 * no root or server is needed. With <tls-port> <tls-ca-file> (from
 * tests/poll-inventory-tests.sh, peer: tests/radius-server.py --transport
 * tls), it also covers RadSec dae-accept=yes, whose radcli_dae_start()
 * needs a completed handshake.
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <poll.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <radcli/radcli2.h>

#define MAX_FD 1024

/* Marks every open IPv4/IPv6 socket descriptor below MAX_FD in map. Other
 * families are skipped: rc_log()'s first syslog() call leaves libc's
 * AF_UNIX /dev/log socket open, which is not radcli's to report. */
static void snapshot_sockets(char *map)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *e;

	assert(d != NULL);
	memset(map, 0, MAX_FD);
	while ((e = readdir(d)) != NULL) {
		struct sockaddr_storage addr;
		socklen_t addrlen = sizeof(addr);
		int fd = atoi(e->d_name);

		if (e->d_name[0] == '.' || fd == dirfd(d) || fd >= MAX_FD)
			continue;
		if (getsockname(fd, (struct sockaddr *)&addr, &addrlen) == 0 &&
		    (addr.ss_family == AF_INET || addr.ss_family == AF_INET6))
			map[fd] = 1;
	}
	closedir(d);
}

/* Opens a loopback peer that never answers: a listening TCP socket that is
 * never accept()ed (connect() completes, the TLS handshake stalls) or an
 * unread UDP one. Writes "127.0.0.1:<port>" to authserver. */
static int silent_peer(int stream, char *authserver, size_t len)
{
	struct sockaddr_in a;
	socklen_t alen = sizeof(a);
	int fd = socket(AF_INET, stream ? SOCK_STREAM : SOCK_DGRAM, 0);

	assert(fd != -1);
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	assert(bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
	if (stream)
		assert(listen(fd, 1) == 0);
	assert(getsockname(fd, (struct sockaddr *)&a, &alen) == 0);
	snprintf(authserver, len, "127.0.0.1:%u", ntohs(a.sin_port));
	return fd;
}

/* Runs one combination; returns 0 if every new socket was reported (and
 * nothing else was), 1 otherwise. dae_accept is NULL for no radcli_dae.
 * tls_ca is set only for a live RadSec peer at authserver. */
static int run_case(const char *serv_type, const char *dae_accept, int with_req,
		    const char *authserver, const char *tls_ca)
{
	int radsec = !strcmp(serv_type, "tls") || !strcmp(serv_type, "dtls");
	char before[MAX_FD], after[MAX_FD], server[96];
	struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
	radcli_ctx *ctx;
	radcli_dae *dae = NULL;
	radcli_request *req = NULL;
	size_t nfds, i;
	int timeout_ms, fd, failed = 0;

	/* RadSec uses its fixed secret; UDP/TCP take it from authserver. */
	snprintf(server, sizeof(server), "%s%s", authserver, radsec ? "" : ":testing123");
	snapshot_sockets(before);

	ctx = radcli_ctx_new(0);
	assert(ctx != NULL);
	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 3) == 0);
	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 3) == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_SERV_TYPE, serv_type) == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, server) == 0);
	if (tls_ca != NULL)
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_TLS_CA_FILE, tls_ca) == 0);
	if (dae_accept != NULL) {
		assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, dae_accept) == 0);
		if (!strcmp(dae_accept, "udp")) {
			assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, "192.0.2.9") == 0);
			assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
			assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_LISTEN, "127.0.0.1:0") == 0);
		}
	}
	assert(radcli_ctx_apply(ctx) == 0);

	if (dae_accept != NULL) {
		dae = radcli_dae_new(ctx, 0);
		assert(dae != NULL);
		assert(radcli_dae_start(dae) == 0);
	}
	if (with_req) {
		req = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, NULL);
		assert(req != NULL);
		assert(radcli_request_perform(req, RADCLI_REQUEST_SENDONLY_NONBLOCK) == RADCLI_OK);
		assert(radcli_ctx_dispatch(ctx) == 0);
	}

	assert(radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) == 0);
	snapshot_sockets(after);

	for (fd = 0; fd < MAX_FD; fd++) {
		int reported = 0;

		if (!after[fd] || before[fd])
			continue;
		for (i = 0; i < nfds; i++)
			if (pfds[i].fd == fd)
				reported = 1;
		if (!reported) {
			fprintf(stderr, "  socket %d is open but not reported\n", fd);
			failed = 1;
		}
	}
	for (i = 0; i < nfds; i++) {
		if (pfds[i].fd < 0 || pfds[i].fd >= MAX_FD ||
		    !after[pfds[i].fd] || before[pfds[i].fd]) {
			fprintf(stderr, "  reported descriptor %d is not a socket radcli opened\n",
				pfds[i].fd);
			failed = 1;
		}
	}
	if (with_req && timeout_ms < 0) {
		fprintf(stderr, "  no timeout reported with a request in flight\n");
		failed = 1;
	}
	/* A RadSec DAE has no socket of its own: only the session is reported. */
	if (dae_accept != NULL && !strcmp(dae_accept, "yes")) {
		int type;
		socklen_t typelen = sizeof(type);

		if (nfds != 1 ||
		    getsockopt(pfds[0].fd, SOL_SOCKET, SO_TYPE, &type, &typelen) != 0 ||
		    type != (!strcmp(serv_type, "tls") ? SOCK_STREAM : SOCK_DGRAM)) {
			fprintf(stderr, "  expected only the RadSec session to be reported\n");
			failed = 1;
		}
	}

	printf("%s serv-type=%s dae-accept=%s request=%s: nfds=%zu timeout_ms=%d\n",
	       failed ? "FAIL" : "ok  ", serv_type, dae_accept ? dae_accept : "unset",
	       with_req ? "in-flight" : "none", nfds, timeout_ms);

	radcli_request_free(req);
	radcli_dae_free(dae);
	radcli_ctx_free(ctx);
	return failed;
}

int main(int argc, char **argv)
{
	static const char *serv_types[] = { "udp", "tcp", "tls", "dtls" };
	char authserver[64];
	size_t s;
	int with_dae, with_req, failed = 0;

	if (argc != 1 && argc != 3) {
		fprintf(stderr, "usage: %s [<tls-port> <tls-ca-file>]\n", argv[0]);
		return 2;
	}
	if (access("/proc/self/fd", R_OK) != 0) {
		printf("/proc/self/fd is not available; skipping\n");
		return 77;
	}

	if (argc == 3) {
		snprintf(authserver, sizeof(authserver), "127.0.0.1:%s", argv[1]);
		for (with_req = 0; with_req < 2; with_req++)
			failed |= run_case("tls", "yes", with_req, authserver, argv[2]);
		return failed;
	}

	for (s = 0; s < sizeof(serv_types) / sizeof(serv_types[0]); s++) {
		int stream = !strcmp(serv_types[s], "tcp") || !strcmp(serv_types[s], "tls");

		for (with_dae = 0; with_dae < 2; with_dae++) {
			for (with_req = 0; with_req < 2; with_req++) {
				int peer = silent_peer(stream, authserver, sizeof(authserver));

				failed |= run_case(serv_types[s], with_dae ? "udp" : NULL,
						   with_req, authserver, NULL);
				close(peer);
			}
		}
	}
	return failed;
}
