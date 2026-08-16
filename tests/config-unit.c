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

/* Unit tests for lib/config.c fixes that have no other test coverage.
 * All of these exercise rc_read_config()/rc_test_config()/
 * rc_find_server_addr() directly: pure config parsing and lookup, no
 * network I/O (TLS/DTLS handshakes are deferred to first send, and
 * "127.0.0.x" addresses resolve locally without any DNS lookup), so this
 * needs neither root nor a running RADIUS server.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <syslog.h>

#include <radcli/radcli.h>

static char tmpl[] = "config-unit-XXXXXX";

/* Write a config file. If trailing_newline is 0, the buffer's last byte is
 * written as-is with no '\n' appended (fwrite()/fprintf() from a shell
 * heredoc always terminates the last line; we need direct control to
 * reproduce the exact byte layout the line-buffer fix cares about). */
static char *write_conf(const char *content, size_t len)
{
	static char path[64];
	int fd;

	strcpy(path, tmpl);
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		exit(1);
	}
	if (write(fd, content, len) != (ssize_t)len) {
		perror("write");
		exit(1);
	}
	close(fd);
	return path;
}

/* commit de940b1: off-by-one in server-list bound check (RC_SERVER_MAX=8) */
static void test_server_list_bound(void)
{
	rc_handle *rh;
	char *path;

	/* Exactly RC_SERVER_MAX (8) servers: must be accepted. */
	const char eight[] =
		"authserver 127.0.0.1:1,127.0.0.2:1,127.0.0.3:1,127.0.0.4:1,"
		"127.0.0.5:1,127.0.0.6:1,127.0.0.7:1,127.0.0.8:1\n"
		"acctserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n";
	path = write_conf(eight, sizeof(eight) - 1);
	rh = rc_read_config(path);
	unlink(path);
	if (rh == NULL) {
		fprintf(stderr, "error: 8 (== RC_SERVER_MAX) servers were rejected\n");
		exit(1);
	}
	rc_destroy(rh);

	/* One more than RC_SERVER_MAX: must be rejected cleanly, not
	 * overflow serv->name[]/port[]/secret[]. */
	const char nine[] =
		"authserver 127.0.0.1:1,127.0.0.2:1,127.0.0.3:1,127.0.0.4:1,"
		"127.0.0.5:1,127.0.0.6:1,127.0.0.7:1,127.0.0.8:1,127.0.0.9:1\n"
		"acctserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n";
	path = write_conf(nine, sizeof(nine) - 1);
	rh = rc_read_config(path);
	unlink(path);
	if (rh != NULL) {
		fprintf(stderr, "error: RC_SERVER_MAX+1 (9) servers were accepted\n");
		rc_destroy(rh);
		exit(1);
	}
}

/* commit 44ce586: rc_find_server_addr() prefix-match secret lookup.
 * "127.0.0.10" is listed first and is a textual prefix-superstring of the
 * query "127.0.0.1"; the old strncmp() bounded by the query's length
 * would match it and return the wrong secret. */
static void test_prefix_match_secret(void)
{
	rc_handle *rh;
	char *path;
	struct addrinfo *info = NULL;
	char secret[MAX_SECRET_LENGTH];

	const char conf[] =
		"authserver 127.0.0.10:1:secretB,127.0.0.1:1:secretA\n"
		"acctserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n";
	path = write_conf(conf, sizeof(conf) - 1);
	rh = rc_read_config(path);
	unlink(path);
	if (rh == NULL) {
		fprintf(stderr, "error: valid config with two authservers was rejected\n");
		exit(1);
	}

	if (rc_find_server_addr(rh, "127.0.0.1", &info, secret, AUTH) != 0) {
		fprintf(stderr, "error: rc_find_server_addr() failed for exact match\n");
		exit(1);
	}
	freeaddrinfo(info);

	if (strcmp(secret, "secretA") != 0) {
		fprintf(stderr, "error: rc_find_server_addr(\"127.0.0.1\") returned "
				"secret '%s', expected 'secretA' "
				"(prefix-matched the unrelated \"127.0.0.10\" entry)\n", secret);
		exit(1);
	}

	rc_destroy(rh);
}

int main(void)
{
	openlog(NULL, LOG_PERROR, LOG_USER);

	test_server_list_bound();
	test_prefix_match_secret();

	printf("config-unit: all tests passed\n");
	return 0;
}
