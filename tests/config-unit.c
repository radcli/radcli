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
#include <radcli/radcli2.h>

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

/* issue #102 / REQ-CONFIG-CFG-010: radius_retries 0 (send once, no
 * retransmit) must be accepted by both the legacy and radcli2 config-file
 * entry points; radius_retries -1 must still be rejected by both.
 * radius_timeout 0 is deliberately left rejected -- see the discussion on
 * issue #102 -- so this also pins down that it stays that way. */
static void test_zero_retries_allowed(void)
{
	rc_handle *rh;
	radcli_ctx *ctx;
	char *path;

	const char zero_retries[] =
		"authserver 127.0.0.1:1\n"
		"acctserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 0\n";
	path = write_conf(zero_retries, sizeof(zero_retries) - 1);
	rh = rc_read_config(path);
	if (rh == NULL) {
		unlink(path);
		fprintf(stderr, "error: radius_retries 0 was rejected by rc_read_config()\n");
		exit(1);
	}
	if (rc_conf_int(rh, "radius_retries") != 0) {
		unlink(path);
		rc_destroy(rh);
		fprintf(stderr, "error: radius_retries 0 did not round-trip through rc_conf_int()\n");
		exit(1);
	}
	rc_destroy(rh);

	ctx = radcli_ctx_read_config(path, 0);
	unlink(path);
	if (ctx == NULL) {
		fprintf(stderr, "error: radius_retries 0 was rejected by radcli_ctx_read_config()\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	const char negative_retries[] =
		"authserver 127.0.0.1:1\n"
		"acctserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries -1\n";
	path = write_conf(negative_retries, sizeof(negative_retries) - 1);
	rh = rc_read_config(path);
	if (rh != NULL) {
		unlink(path);
		rc_destroy(rh);
		fprintf(stderr, "error: radius_retries -1 was accepted by rc_read_config()\n");
		exit(1);
	}

	ctx = radcli_ctx_read_config(path, 0);
	unlink(path);
	if (ctx != NULL) {
		radcli_ctx_free(ctx);
		fprintf(stderr, "error: radius_retries -1 was accepted by radcli_ctx_read_config()\n");
		exit(1);
	}

	const char zero_timeout[] =
		"authserver 127.0.0.1:1\n"
		"acctserver 127.0.0.1:1\n"
		"radius_timeout 0\n"
		"radius_retries 1\n";
	path = write_conf(zero_timeout, sizeof(zero_timeout) - 1);
	rh = rc_read_config(path);
	if (rh != NULL) {
		unlink(path);
		rc_destroy(rh);
		fprintf(stderr, "error: radius_timeout 0 was accepted (should still be rejected)\n");
		exit(1);
	}
	unlink(path);
}

/* REQ-CONFIG-CFG-019: under serv-type tls/dtls, radcli_transport_exchange()
 * (lib/sendserver.c) always overwrites whatever secret rc_find_server_addr()
 * returns with the RFC 6614/7360 fixed secret, so an authserver/acctserver
 * with no inline secret, no "secret" option, and no matching "servers" file
 * entry must still resolve successfully -- the client works without any
 * secret configured at all under TLS/DTLS. */
static void test_tls_no_secret_required(void)
{
	rc_handle *rh;
	char *path;
	struct addrinfo *info = NULL;
	char secret[MAX_SECRET_LENGTH];

	const char conf[] =
		"serv-type tls\n"
		"authserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n";
	path = write_conf(conf, sizeof(conf) - 1);
	rh = rc_read_config(path);
	unlink(path);
	if (rh == NULL) {
		fprintf(stderr, "error: valid tls config with no secret anywhere "
				"was rejected\n");
		exit(1);
	}

	memset(secret, 'x', sizeof(secret));
	if (rc_find_server_addr(rh, "127.0.0.1", &info, secret, AUTH) != 0) {
		fprintf(stderr, "error: rc_find_server_addr() failed under "
				"serv-type tls with no secret configured -- the client "
				"would be unable to send an ordinary Access-Request\n");
		exit(1);
	}
	freeaddrinfo(info);

	if (secret[0] != '\0') {
		fprintf(stderr, "error: rc_find_server_addr() returned a non-empty "
				"secret ('%s') under serv-type tls with none configured\n",
				secret);
		exit(1);
	}

	rc_destroy(rh);

	/* Same config, but serv-type udp (the default): must still fail, since
	 * a UDP/TCP server genuinely needs a secret and none was configured
	 * anywhere -- this is the pre-existing behavior, unchanged. */
	const char udp_conf[] =
		"authserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n";
	path = write_conf(udp_conf, sizeof(udp_conf) - 1);
	rh = rc_read_config(path);
	unlink(path);
	if (rh == NULL) {
		fprintf(stderr, "error: valid udp config with no secret was rejected\n");
		exit(1);
	}

	if (rc_find_server_addr(rh, "127.0.0.1", &info, secret, AUTH) == 0) {
		fprintf(stderr, "error: rc_find_server_addr() succeeded under "
				"serv-type udp with no secret configured anywhere\n");
		freeaddrinfo(info);
		exit(1);
	}

	rc_destroy(rh);
}

/* rc_find_server_addr()'s "servers" file parsing switched from a fixed
 * 128-byte fgets() buffer to getline(). A servers-file line longer than the
 * old buffer must be read intact (not silently truncated/misparsed as a
 * bogus extra line) and must not corrupt the valid entry that follows it.
 *
 * The padding that makes the line long is a third, unused whitespace-
 * separated token trailing the hostname/secret pair (rc_find_server_addr()
 * only ever reads the first two tokens off a line via strtok_r()), not a
 * long hostname: hostnm[] is fixed at AUTH_ID_LEN (64) regardless of line
 * length, so a too-long *hostname* would just get silently truncated to a
 * valid-length nonexistent name and trigger a real (sandboxed, slow) DNS
 * lookup attempt -- unrelated to the getline() behavior under test here.
 * The filler line's own hostname is a numeric address (192.0.2.1, TEST-NET-1)
 * so its rc_getaddrinfo() call resolves instantly, no DNS involved. */
static void test_servers_file_long_line(void)
{
	rc_handle *rh;
	char *path;
	char servers_path[64];
	char conf_path[64];
	char conf[512];
	struct addrinfo *info = NULL;
	char secret[MAX_SECRET_LENGTH];
	char padding[300];
	char servers_content[512];
	int n;

	memset(padding, 'x', sizeof(padding) - 1);
	padding[sizeof(padding) - 1] = '\0';

	n = snprintf(servers_content, sizeof(servers_content),
		     "192.0.2.1 secretA %s\n"   /* far longer than the old 128-byte buffer */
		     "127.0.0.1 secretB\n", padding);
	path = write_conf(servers_content, (size_t)n);
	strcpy(servers_path, path);

	n = snprintf(conf, sizeof(conf),
		     "authserver 127.0.0.1:1\n"
		     "acctserver 127.0.0.1:1\n"
		     "radius_timeout 5\n"
		     "radius_retries 1\n"
		     "servers %s\n", servers_path);
	path = write_conf(conf, (size_t)n);
	strcpy(conf_path, path);

	rh = rc_read_config(conf_path);
	unlink(conf_path);
	if (rh == NULL) {
		fprintf(stderr, "error: valid config referencing a servers file "
				"was rejected\n");
		exit(1);
	}

	if (rc_find_server_addr(rh, "127.0.0.1", &info, secret, ACCT) != 0) {
		unlink(servers_path);
		fprintf(stderr, "error: rc_find_server_addr() failed to find "
				"the entry after the too-long servers-file line\n");
		exit(1);
	}
	unlink(servers_path);
	freeaddrinfo(info);

	if (strcmp(secret, "secretB") != 0) {
		fprintf(stderr, "error: secret = '%s', expected 'secretB' "
				"(the entry after the long line was misparsed)\n", secret);
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
	if (saved_fd < 0) {
		perror("dup");
		exit(1);
	}
	tmp_fd = open("config-unit-stderr.tmp", O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (tmp_fd < 0) {
		perror("open");
		exit(1);
	}
	dup2(tmp_fd, STDERR_FILENO);

	rh = rc_read_config(path);

	fflush(stderr);
	assert(saved_fd >= 0);
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

/* radcli2_priv_check_config() (lib/config.c) requires either an authserver
 * or a configured DAE listener (dae-accept set), not an authserver
 * unconditionally -- an RFC 5176 DAE listener is a server-side role,
 * independent of ever sending an Access-/Accounting-Request as a client, so
 * a DAE-only config must not be forced to carry an authserver just to
 * satisfy this check (REQ-CONFIG2-CFG-004/REQ-CONFIG-CFG-010). This also
 * means the "no acctserver specified" debug log -- itself only meaningful
 * for a config that has a client role at all -- must not fire for a
 * DAE-only config that never configured an authserver either. */
static void test_dae_only_no_authserver_required(void)
{
	char captured[4096];
	const char no_acctserver_needle[] = "no acctserver specified";
	const char no_authserver_needle[] = "no authserver";

	const char dae_only_conf[] =
		"dae-accept yes\n"
		"dae-server 192.0.2.1\n"
		"dae-secret testing123\n"
		"radius_timeout 5\n"
		"radius_retries 1\n";
	if (!run_capturing_stderr(dae_only_conf, sizeof(dae_only_conf) - 1,
				   captured, sizeof(captured))) {
		fprintf(stderr, "error: a DAE-only config (dae-accept set, no "
				"authserver) was rejected: %s\n", captured);
		exit(1);
	}
	if (strstr(captured, no_acctserver_needle) != NULL) {
		fprintf(stderr, "error: '%s' WAS logged for a DAE-only config "
				"with no authserver at all (should be skipped, not just "
				"suppressed)\n", no_acctserver_needle);
		exit(1);
	}

	const char neither_conf[] =
		"radius_timeout 5\n"
		"radius_retries 1\n";
	if (run_capturing_stderr(neither_conf, sizeof(neither_conf) - 1,
				  captured, sizeof(captured))) {
		fprintf(stderr, "error: a config with neither authserver nor "
				"dae-accept was accepted\n");
		exit(1);
	}
	if (strstr(captured, no_authserver_needle) == NULL) {
		fprintf(stderr, "error: expected a 'no authserver' error for a "
				"config with neither authserver nor dae-accept, got: %s\n",
				captured);
		exit(1);
	}
}

/* The dae-* option names must be registered in lib/options.h -- a config
 * file that sets all six must be accepted (no "unrecognized option"), and
 * rc_conf_str()/rc_conf_int() must read back exactly what was set. Actual
 * validation (dae-accept gating, dae-server/dae-secret required together,
 * dae-server prefix rejection) is lib/dae.c's job, not the generic config
 * layer's, so it is not exercised here. */
static void test_dae_options_registered(void)
{
	rc_handle *rh;
	char *path, *v;
	const char conf[] =
		"authserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n"
		"dae-accept yes\n"
		"dae-listen 0.0.0.0:3799\n"
		"dae-secret testing123\n"
		"dae-server 192.0.2.1,192.0.2.2:othersecret\n"
		"dae-max-clock-skew 60\n"
		"dae-require-message-authenticator yes\n";

	path = write_conf(conf, sizeof(conf) - 1);
	rh = rc_read_config(path);
	unlink(path);
	if (rh == NULL) {
		fprintf(stderr, "error: a config file setting all dae-* options was rejected\n");
		exit(1);
	}

	v = rc_conf_str(rh, "dae-accept");
	if (v == NULL || strcmp(v, "yes") != 0) {
		fprintf(stderr, "error: dae-accept: expected \"yes\", got %s\n", v ? v : "(null)");
		exit(1);
	}
	v = rc_conf_str(rh, "dae-listen");
	if (v == NULL || strcmp(v, "0.0.0.0:3799") != 0) {
		fprintf(stderr, "error: dae-listen: expected \"0.0.0.0:3799\", got %s\n", v ? v : "(null)");
		exit(1);
	}
	v = rc_conf_str(rh, "dae-secret");
	if (v == NULL || strcmp(v, "testing123") != 0) {
		fprintf(stderr, "error: dae-secret: expected \"testing123\", got %s\n", v ? v : "(null)");
		exit(1);
	}
	v = rc_conf_str(rh, "dae-server");
	if (v == NULL || strcmp(v, "192.0.2.1,192.0.2.2:othersecret") != 0) {
		fprintf(stderr, "error: dae-server: expected \"192.0.2.1,192.0.2.2:othersecret\", got %s\n", v ? v : "(null)");
		exit(1);
	}
	if (rc_conf_int(rh, "dae-max-clock-skew") != 60) {
		fprintf(stderr, "error: dae-max-clock-skew: expected 60, got %d\n",
			rc_conf_int(rh, "dae-max-clock-skew"));
		exit(1);
	}
	v = rc_conf_str(rh, "dae-require-message-authenticator");
	if (v == NULL || strcmp(v, "yes") != 0) {
		fprintf(stderr, "error: dae-require-message-authenticator: expected \"yes\", got %s\n", v ? v : "(null)");
		exit(1);
	}

	rc_destroy(rh);
}

/* Options removed from RC_OPTION_TABLE (they were parsed but never read
 * back anywhere) must still load without error via RC_IGNORED_OPTION_TABLE,
 * for compatibility with existing config files -- but their value must not
 * be storable/retrievable under any name/type, unlike a real option. */
static void test_ignored_options_still_load(void)
{
	rc_handle *rh;
	char *path;
	const char conf[] =
		"authserver 127.0.0.1:1\n"
		"radius_timeout 5\n"
		"radius_retries 1\n"
		"auth_order radius,local\n"
		"login_tries 4\n"
		"login_timeout 60\n"
		"nologin /etc/nologin\n"
		"issue /etc/issue\n"
		"login_radius /usr/local/sbin/login.radius\n"
		"seqfile /var/run/seqfile\n"
		"mapfile ../etc/port-id-map\n"
		"radius_deadtime 0\n"
		"login_local /bin/login\n";

	path = write_conf(conf, sizeof(conf) - 1);
	rh = rc_read_config(path);
	unlink(path);
	if (rh == NULL) {
		fprintf(stderr, "error: a config file setting only ignored legacy "
				"options was rejected\n");
		exit(1);
	}

	if (rc_conf_str(rh, "mapfile") != NULL) {
		fprintf(stderr, "error: rc_conf_str(\"mapfile\") returned a value "
				"for an option that should not be stored\n");
		exit(1);
	}
	if (rc_conf_int(rh, "auth_order") != 0) {
		fprintf(stderr, "error: rc_conf_int(\"auth_order\") returned a "
				"nonzero value for an option that should not be stored\n");
		exit(1);
	}

	rc_destroy(rh);

	/* rc_add_config()'s programmatic path must accept the same names,
	 * silently discarding them, rather than erroring like a genuinely
	 * unknown option would. */
	rh = rc_new();
	if (rh == NULL || rc_config_init(rh) == NULL) {
		fprintf(stderr, "error: rc_config_init failed\n");
		exit(1);
	}
	if (rc_add_config(rh, "mapfile", "../etc/port-id-map", __FILE__, __LINE__) != 0) {
		fprintf(stderr, "error: rc_add_config(\"mapfile\", ...) was rejected\n");
		exit(1);
	}
	if (rc_add_config(rh, "not-a-real-option", "x", __FILE__, __LINE__) == 0) {
		fprintf(stderr, "error: rc_add_config() accepted a genuinely unknown option\n");
		exit(1);
	}
	rc_destroy(rh);
}

int main(void)
{
	openlog(NULL, LOG_PERROR, LOG_USER);

	test_server_list_bound();
	test_prefix_match_secret();
	test_zero_retries_allowed();
	test_tls_no_secret_required();
	test_servers_file_long_line();
	test_last_line_no_newline();
	test_long_line_no_truncation();
	test_keyword_trailing_whitespace_only();
	test_acctserver_log_suppression();
	test_dae_only_no_authserver_required();
	test_dae_options_registered();
	test_ignored_options_still_load();

	printf("config-unit: all tests passed\n");
	return 0;
}
