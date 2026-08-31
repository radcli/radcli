/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
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

/** @file compat.c
 * @brief One-line wrappers keeping every already-released, radcli.h-public
 * `rc_*` symbol whose real implementation moved into libradcli2
 * physically defined in libradcli itself, under its original name.
 *
 * Needed because of how symbol versioning resolves: a binary linked
 * against the pre-split libradcli.so has `rc_dict_free@RADCLI_10` (etc.)
 * baked into its relocation records. libradcli2.so transitively loading at
 * runtime does not satisfy that -- ld.so matches on the exact
 * name@version pair, and libradcli2.so exports these under its own,
 * differently-named private version node, not RADCLI_10. So libradcli.so
 * itself must still define the symbol; most of this file is that
 * definition, each one a single call into the renamed radcli2_priv_*
 * implementation (lib/includes.h) that actually does the work. A few
 * functions below are not wrappers at all, but moved here verbatim --
 * see the comment above rc_getport() for why.
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include "util.h"

/* Legacy-only debug-verbosity knob (freeradius-client/radiusclient-ng
 * source compatibility). Unlike a handle's own `debug` field
 * (lib/includes.h), rc_setdebug() has no rc_handle argument, so it can
 * only pre-seed handles constructed afterward -- see rc_new()/
 * rc_read_config() below. Deliberately confined to this legacy shim: see
 * REQ-GEN-SEC-005. */
static unsigned int radcli_legacy_debug = 0;

int rc_add_config(rc_handle *rh, char const *option_name, char const *option_val,
		  char const *source, int line)
{
	return radcli2_priv_add_config(rh, option_name, option_val, source, line);
}

rc_handle *rc_config_init(rc_handle *rh)
{
	return radcli2_priv_config_init(rh);
}

/** @brief Read the global config file
 *
 * This is the primary way to initialise radcli.  Loads the configuration
 * file, initialises the transport (including TLS/DTLS handshake when
 * applicable), and returns an opaque handle for use in subsequent calls.
 * The format is compatible with radiusclient-ng and freeradius-client.
 *
 * Standard RFC 2865/2866/2869 attributes are built into the library;
 * the @b dictionary option is only needed for vendor-specific attributes.
 *
 * Recognised configuration options:
 *
 * **Server address:**
 *  - @b authserver: authentication server; format is
 *    @c host[:port[:secret]] (may be repeated for failover, comma-separated).
 *  - @b acctserver: accounting server; same format as @b authserver.
 *  - @b secret: shared secret applied to @b authserver/@b acctserver when
 *    they don't already carry an inline @c :secret -- the config-file
 *    equivalent of radcli_ctx_set_secret() (radcli2.h). Ignored when
 *    @b serv-type is @c tls or @c dtls: that transport uses its own fixed
 *    RFC 6614/7360 secret instead, so this option is never consulted.
 *
 * **Transport:**
 *  - @b serv-type: one of @c udp (default), @c tcp, @c tls, @c dtls.
 *  - @b namespace: Linux network namespace name to use for socket operations.
 *
 * **TLS/DTLS credentials** (required when @b serv-type is @c tls or @c dtls):
 *  - @b tls-ca-file: PEM file of the CA certificate used to verify the server.
 *  - @b tls-cert-file: PEM file of the client certificate.
 *  - @b tls-key-file: PEM file of the client private key.
 *  - @b tls-verify-hostname: set to @c false to skip server hostname
 *    verification (not recommended).
 *  - @b tls-psk-identity / @b tls-psk-key: Pre-Shared Key identity (plain
 *    text) and key (hex text), used instead of X.509 credentials; both must
 *    be set together. The config-file equivalent of radcli_ctx_set_tls_psk()
 *    (radcli2.h), and preferred over a @c psk\@username\@hexkey embedded in
 *    @b authserver's value.
 *
 * **Security:**
 *  - @b require-message-authenticator: set to @c no to accept responses that
 *    lack the Message-Authenticator attribute.  Enabled by default per
 *    draft-ietf-radext-deprecating-radius-10 (CVE-2024-3596 / BLAST RADIUS);
 *    only disable for legacy servers that predate RFC 3579.  Has no effect
 *    over RADIUS/TLS or RADIUS/DTLS, where this mitigation is never
 *    enforced, per draft-ietf-radext-deprecating-radius-10 Section 4.
 *
 * **Tuning:**
 *  - @b radius_timeout: request timeout in seconds (integer, default 3).
 *  - @b radius_retries: number of retries per server (integer, default 3).
 *  - @b nas-ip: source IP address to bind to when sending requests.
 *  - @b nas-identifier: NAS-Identifier string sent in requests.
 *  - @b dictionary: path to an additional attribute dictionary file.
 *  - @b clientdebug: debug verbosity level (integer; 0 = off).
 *
 * @param filename path to the configuration file.
 * @return new rc_handle on success, NULL on failure.
 */
rc_handle *rc_read_config(char const *filename)
{
	rc_handle *rh = radcli2_priv_read_config(filename, 0);

	if (rh != NULL && radcli_legacy_debug)
		rh->debug = radcli_legacy_debug;

	return rh;
}

char *rc_conf_str(rc_handle const *rh, char const *optname)
{
	return radcli2_priv_conf_str(rh, optname);
}

int rc_conf_int(rc_handle const *rh, char const *optname)
{
	return radcli2_priv_conf_int(rh, optname);
}

SERVER *rc_conf_srv(rc_handle const *rh, char const *optname)
{
	return radcli2_priv_conf_srv(rh, optname);
}

int rc_test_config(rc_handle *rh, char const *filename)
{
	return radcli2_priv_test_config(rh, filename);
}

int rc_apply_config(rc_handle *rh)
{
	return radcli2_priv_apply_config(rh);
}

int rc_find_server_addr(rc_handle const *rh, char const *server_name,
			struct addrinfo **info, char *secret, rc_type type)
{
	return radcli2_priv_find_server_addr(rh, server_name, info, secret, type);
}

void rc_config_free(rc_handle *rh)
{
	radcli2_priv_config_free(rh);
}

rc_handle *rc_new(void)
{
	rc_handle *rh = radcli2_priv_new();

	if (rh != NULL && radcli_legacy_debug)
		rh->debug = radcli_legacy_debug;

	return rh;
}

void rc_destroy(rc_handle *rh)
{
	radcli2_priv_destroy(rh);
}

rc_socket_type rc_get_socket_type(rc_handle *rh)
{
	return rh->so_type;
}

int rc_read_dictionary(rc_handle *rh, char const *filename)
{
	return radcli2_priv_read_dictionary(rh, filename);
}

int rc_read_dictionary_from_buffer(rc_handle *rh, char const *buf, size_t size)
{
	return radcli2_priv_read_dictionary_from_buffer(rh, buf, size);
}

void rc_dict_free(rc_handle *rh)
{
	radcli2_priv_dict_free(rh);
}

int rc_tls_fd(rc_handle *rh)
{
	return radcli2_priv_tls_fd(rh);
}

int rc_check_tls(rc_handle *rh)
{
	return radcli2_priv_check_tls(rh);
}

/* rc_getport()/rc_own_hostname()/rc_mksid()/rc_setdebug()/rc_openlog(),
 * unlike the wrappers above, are the real implementations, moved here
 * verbatim rather than renamed-and-wrapped: nothing else in libradcli2
 * ever called them (confirmed by grepping every libradcli2-bound source
 * file for a real call site, not just each function's own definition),
 * so there was no reason for them to live there at all -- unlike
 * lib/tls.c's rc_tls_fd()/rc_check_tls() just above, which stay
 * genuinely private-wrapped because rc_check_tls() calls tls.c's static
 * restart_session() and touches its session-internal tls_st fields:
 * pulling it out would mean exporting more private surface (that static
 * helper plus tls_st's layout), not less. */

unsigned short rc_getport(int type)
{
	struct servent *svp;

	if ((svp = getservbyname((type == AUTH) ? "radius" : "radacct", "udp")) == NULL) {
		return (type == AUTH) ? PW_AUTH_UDP_PORT : PW_ACCT_UDP_PORT;
	} else {
		return ntohs((unsigned short)svp->s_port);
	}
}

int rc_own_hostname(char *hostname, int len)
{
#ifdef HAVE_UNAME
	struct utsname uts;
#endif

#if defined(HAVE_UNAME)
	if (uname(&uts) < 0) {
		rc_log(LOG_ERR, "rc_own_hostname: couldn't get own hostname");
		return -1;
	}
	strlcpy(hostname, uts.nodename, len);
#elif defined(HAVE_GETHOSTNAME)
	if (gethostname(hostname, len) < 0) {
		rc_log(LOG_ERR, "rc_own_hostname: couldn't get own hostname");
		return -1;
	}
#elif defined(HAVE_SYSINFO)
	if (sysinfo(SI_HOSTNAME, hostname, len) < 0) {
		rc_log(LOG_ERR, "rc_own_hostname: couldn't get own hostname");
		return -1;
	}
#else
	return -1;
#endif

	return 0;
}

int rc_get_srcaddr(struct sockaddr *lia, const struct sockaddr *ria)
{
	return radcli2_priv_get_srcaddr(lia, ria);
}

void rc_setdebug(int debug)
{
	radcli_legacy_debug = debug;
}

void rc_openlog(char const *ident)
{
#ifndef _MSC_VER /* TODO: Fix me */
	openlog(ident, LOG_PID, RC_LOG_FACILITY);
#endif
}

/** @brief Generate a session-ID-like string from the current time, pid,
 *  and a call counter.
 * @deprecated Returns a pointer to a static, non-reentrant buffer
 *  overwritten on each call -- see REQ-GEN-SEC-005 (general.md) for why
 *  this hazard is an accepted property of a deprecated function rather
 *  than something requiring a code change.
 * @return a NUL-terminated string in a static buffer, valid only until
 *  the next rc_mksid() call.
 */
char *rc_mksid(void)
{
	static char buf[15];
	static unsigned short int cnt = 0;

	snprintf(buf, sizeof(buf), "%08lX%04X%02hX",
		(unsigned long int)time(NULL),
		(unsigned int)getpid(),
		cnt & 0xFF);
	cnt++;
	return buf;
}
