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

/* commit 25d4339: line-buffer handling in rc_read_config().
 * (a) last line without a trailing newline must not have its real last
 *     byte stripped as if it were a '\n'. */
static void test_last_line_no_newline(void)
{
	rc_handle *rh;
	char *path;
	const char *bindaddr;

	const char conf[] =
		"authserver 127.0.0.1:1\n"
		"acctserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n"
		"bindaddr *";  /* no trailing '\n' on purpose */
	path = write_conf(conf, sizeof(conf) - 1);
	rh = rc_read_config(path);
	unlink(path);
	if (rh == NULL) {
		fprintf(stderr, "error: config with no trailing newline on the "
				"last line was rejected\n");
		exit(1);
	}

	bindaddr = rc_conf_str(rh, "bindaddr");
	if (bindaddr == NULL || strcmp(bindaddr, "*") != 0) {
		fprintf(stderr, "error: bindaddr = '%s', expected '*' "
				"(last byte of the newline-less last line was stripped)\n",
				bindaddr ? bindaddr : "(null)");
		exit(1);
	}

	rc_destroy(rh);
}

/* (b) rc_read_config() now reads lines with getline(), which has no fixed
 *     buffer to overflow. A single physical line far longer than the old
 *     512-byte fgets() buffer must be read and parsed intact -- value not
 *     truncated, following line not corrupted -- instead of triggering the
 *     old "line too long, skip and resync" path (which no longer exists). */
static void test_long_line_no_truncation(void)
{
	rc_handle *rh;
	char *path;
	const char *nas_id, *bindaddr;
	char long_id[1000];
	char buf[4096];
	int n;

	memset(long_id, 'a', sizeof(long_id) - 1);
	long_id[sizeof(long_id) - 1] = '\0';

	n = snprintf(buf, sizeof(buf),
		     "authserver 127.0.0.1:1\n"
		     "acctserver 127.0.0.1:1\n"
		     "radius_timeout 5\n"
		     "radius_retries 1\n"
		     "nas-identifier %s\n"     /* far longer than the old 512-byte line buffer */
		     "bindaddr *\n", long_id);
	path = write_conf(buf, (size_t)n);
	rh = rc_read_config(path);
	unlink(path);
	if (rh == NULL) {
		fprintf(stderr, "error: config with a line longer than the old "
				"512-byte buffer was rejected\n");
		exit(1);
	}

	nas_id = rc_conf_str(rh, "nas-identifier");
	if (nas_id == NULL || strcmp(nas_id, long_id) != 0) {
		fprintf(stderr, "error: nas-identifier value was truncated or "
				"corrupted by a line longer than the old 512-byte buffer\n");
		exit(1);
	}

	bindaddr = rc_conf_str(rh, "bindaddr");
	if (bindaddr == NULL || strcmp(bindaddr, "*") != 0) {
		fprintf(stderr, "error: bindaddr = '%s', expected '*' "
				"(the line after the long one was misparsed)\n",
				bindaddr ? bindaddr : "(null)");
		exit(1);
	}

	rc_destroy(rh);
}

/* A keyword line whose value is only trailing whitespace (no actual value)
 * must not underflow the trailing-whitespace-trim index: after skipping the
 * separator whitespace, p points at the line's terminating '\0', so
 * strlen(p) - 1 wraps to SIZE_MAX. Caught by UBSan as a pointer-offset
 * overflow at the p[pos]/p[pos+1] accesses. */
static void test_keyword_trailing_whitespace_only(void)
{
	rc_handle *rh;
	char *path;
	const char *bindaddr;

	const char conf[] =
		"authserver 127.0.0.1:1\n"
		"acctserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n"
		"bindaddr   \n";  /* keyword followed only by whitespace */
	path = write_conf(conf, sizeof(conf) - 1);
	rh = rc_read_config(path);
	unlink(path);
	if (rh == NULL) {
		fprintf(stderr, "error: config with a whitespace-only option value "
				"was rejected\n");
		exit(1);
	}

	bindaddr = rc_conf_str(rh, "bindaddr");
	if (bindaddr == NULL || strcmp(bindaddr, "") != 0) {
		fprintf(stderr, "error: bindaddr = '%s', expected '' "
				"(empty value)\n", bindaddr ? bindaddr : "(null)");
		exit(1);
	}

	rc_destroy(rh);
}

/* commit 8c4e3ac: "no acctserver specified" must be suppressed for
 * serv-type tls/dtls, and still logged otherwise. rh->so_type is not set
 * until rc_apply_config() runs (called internally by rc_read_config() via
 * rc_test_config()), so the fix reads the "serv-type" string directly
 * instead. Captured via LOG_PERROR, since rc_log() is plain syslog(). */
static int run_capturing_stderr(const char *conf, size_t len, char *out, size_t outlen)
{
	rc_handle *rh;
	char *path;
	int saved_fd, tmp_fd;
	ssize_t n;

	path = write_conf(conf, len);

	fflush(stderr);
	saved_fd = dup(STDERR_FILENO);
	tmp_fd = open("config-unit-stderr.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (tmp_fd < 0) {
		perror("open");
		exit(1);
	}
	dup2(tmp_fd, STDERR_FILENO);

	rh = rc_read_config(path);

	fflush(stderr);
	dup2(saved_fd, STDERR_FILENO);
	close(saved_fd);
	unlink(path);

	lseek(tmp_fd, 0, SEEK_SET);
	n = read(tmp_fd, out, outlen - 1);
	out[n > 0 ? n : 0] = '\0';
	close(tmp_fd);
	unlink("config-unit-stderr.tmp");

	if (rh != NULL)
		rc_destroy(rh);

	return rh != NULL;
}

static void test_acctserver_log_suppression(void)
{
	char captured[4096];
	const char needle[] = "no acctserver specified";

	const char udp_conf[] =
		"authserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n";
	if (!run_capturing_stderr(udp_conf, sizeof(udp_conf) - 1, captured, sizeof(captured))) {
		fprintf(stderr, "error: valid udp config without acctserver was rejected\n");
		exit(1);
	}
	if (strstr(captured, needle) == NULL) {
		fprintf(stderr, "error: '%s' was NOT logged for serv-type udp "
				"(default) without an acctserver\n", needle);
		exit(1);
	}

	const char tls_conf[] =
		"serv-type tls\n"
		"authserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n";
	if (!run_capturing_stderr(tls_conf, sizeof(tls_conf) - 1, captured, sizeof(captured))) {
		fprintf(stderr, "error: valid tls config without acctserver was rejected\n");
		exit(1);
	}
	if (strstr(captured, needle) != NULL) {
		fprintf(stderr, "error: '%s' WAS logged for serv-type tls "
				"without an acctserver (should be suppressed)\n", needle);
		exit(1);
	}
}

int main(void)
{
	openlog(NULL, LOG_PERROR, LOG_USER);

	test_server_list_bound();
	test_prefix_match_secret();
	test_last_line_no_newline();
	test_long_line_no_truncation();
	test_keyword_trailing_whitespace_only();
	test_acctserver_log_suppression();

	printf("config-unit: all tests passed\n");
	return 0;
}
