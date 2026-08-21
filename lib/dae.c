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

/* radcli2.h's RFC 5176 dynamic-authorization listener (radcli_dae_new()/
 * _set_handler()/_start()/_free(), plus the ctx-level poll surface
 * radcli_ctx_get_poll()/radcli_ctx_dispatch(), doc/requirements/dae.md's
 * INIT/NET/SEC/DATA categories).
 *
 * radcli_dae_new() validates the dae-* configuration and resolves every
 * dae-server entry to concrete addresses, but opens no socket
 * (REQ-DAE-INIT-*); radcli_dae_start() does that, non-blocking and
 * close-on-exec (REQ-DAE-SEC-010/011). There is deliberately no
 * radcli_dae_fd(): the descriptor is exposed only via
 * radcli_ctx_get_poll(), which operates on ctx rather than on any one
 * radcli_dae, so a future dynamic-authorization transport that shares one
 * descriptor with the ordinary request path (rather than a separate
 * UDP/3799 listener) never leaves an application holding two accessors
 * that alias the same descriptor -- see radcli_ctx_get_poll()'s doc
 * comment in radcli2.h. radcli never calls poll()/select()/epoll_wait()
 * itself (REQ-DAE-NET-001, REQ-GEN-SEC-003).
 *
 * radcli_ctx_dispatch() runs the full validation pipeline (REQ-DAE-NET-002)
 * before ever invoking the registered radcli_dae_handler: source-address
 * authorization, Request Authenticator, Message-Authenticator, Event-
 * Timestamp freshness, then duplicate suppression against a fixed
 * 256-slot-per-DAC table (REQ-DAE-SEC-001..006). Session-selector
 * convenience accessors (radcli_dae_req_session_id()/_user_name()/
 * _framed_ip()/_nas_port()/_check_nas(), doc/requirements/dae.md's DATA
 * category) are not implemented yet: an application can still reach the
 * same data today via radcli_dae_req_attrs(). */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "util.h"
#include "avp.h"
#include "rc-md5.h"
#include "rc-hmac.h" /* MD5_DIGEST_SIZE: see lib/request.c's identical include
                      * for why (nettle vs. non-nettle builds) */
#include <poll.h>
#include <fcntl.h>
#include <time.h>

#define RADCLI_DAE_DEFAULT_PORT 3799
/* Sane bound on the number of addresses dae-server's entries resolve to --
 * not a protocol limit, just parse-loop hygiene against an operator config
 * mistake (e.g. a hostname with an unexpectedly large RRset). */
#define RADCLI_DAE_MAX_DACS 64

/* RFC 5176 SS2.3: duplicate suppression is keyed on (source address, source
 * port, Identifier); Identifier is one octet, so this is the whole space --
 * a fixed table, not a cache with an eviction policy (REQ-DAE-SEC-005). */
#define RADCLI_DAE_SLOTS 256

struct radcli_dae_slot {
	unsigned valid;
	time_t timestamp;
	uint16_t source_port;
	uint8_t request_authenticator[AUTH_VECTOR_LEN];
	unsigned pending; /* 1 = PENDING (awaiting an application decision) */
	uint8_t reply_code;
	uint32_t error_cause; /* 0 = no Error-Cause attribute (an ACK) */
};

struct radcli_dae_dac {
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char *secret; /* NULL => use radcli_dae_st.secret */
	struct radcli_dae_slot *slots; /* RADCLI_DAE_SLOTS entries */
};

struct radcli_dae_st {
	rc_handle *rh;
	char *secret;
	struct radcli_dae_dac *dacs;
	unsigned n_dacs;
	int max_clock_skew;
	int require_message_authenticator;
	char *listen_host; /* NULL => any address */
	int listen_port;
	int fd;
	radcli_dae_handler handler;
	void *handler_user;
};

struct radcli_dae_request_st {
	struct radcli_dae_st *dae;
	struct radcli_dae_dac *dac; /* the authorized sender this arrived from */
	uint8_t code;
	uint8_t id;
	uint8_t request_authenticator[AUTH_VECTOR_LEN];
	struct sockaddr_storage from;
	socklen_t fromlen;
	char secret[MAX_SECRET_LENGTH + 1]; /* dac->secret or dae->secret, copied in */
	radcli_avp_list *attrs;
	unsigned replied;
	char *session_id; /* Acct-Session-Id, NUL-terminated; NULL if absent */
	char *user_name;  /* User-Name, NUL-terminated; NULL if absent */

	/* Set when this request represents a retransmission radcli_dae_process()
	 * (L0) already matched to an ANSWERED duplicate-suppression slot: there
	 * is no new decision to make, so radcli_dae_reply()/_reply_error() are
	 * meaningless (and, for an L0-only dae with no socket, would fail
	 * outright), and radcli_dae_reply_to_buffer() reproduces the cached
	 * decision snapshotted here instead of the caller's ack/error_cause
	 * arguments -- a genuine retransmission always gets the same answer
	 * (RFC 5176 SS2.3), never a fresh one. */
	unsigned is_cached_duplicate;
	uint8_t cached_reply_code;
	uint32_t cached_error_cause;
};

static void free_dacs(struct radcli_dae_dac *dacs, unsigned n)
{
	unsigned i;

	if (dacs == NULL)
		return;
	for (i = 0; i < n; i++) {
		free(dacs[i].secret);
		free(dacs[i].slots);
	}
	free(dacs);
}

/* Parses one "address_or_hostname[:secret]" dae-server entry. IPv6
 * literals need bracket notation ("[addr]" or "[addr]:secret") to attach a
 * secret unambiguously, since a bare IPv6 address itself contains colons;
 * a bare token with zero or more than one colon is taken whole as the
 * address, with no secret override in that form. *name and *secret are
 * malloc()'d (*secret may come back NULL, meaning "no override"); caller
 * frees both. Returns 0 on success, -1 on a malformed token -- including
 * one that embeds a network prefix ('/'), which dae-server never accepts
 * (REQ-DAE-INIT-003), or a ":secret" override longer than
 * MAX_SECRET_LENGTH: rejected here at construction, the same as an
 * overlong dae-secret, rather than silently truncated the first time it is
 * used to verify a packet. */
static int parse_dae_server_token(const char *token, char **name, char **secret)
{
	const char *close, *colon;
	size_t namelen;

	*name = NULL;
	*secret = NULL;

	if (token[0] == '\0' || strchr(token, '/') != NULL)
		return -1;

	if (token[0] == '[') {
		close = strchr(token, ']');
		if (close == NULL || close == token + 1)
			return -1;
		namelen = (size_t)(close - (token + 1));
		*name = malloc(namelen + 1);
		if (*name == NULL)
			return -1;
		memcpy(*name, token + 1, namelen);
		(*name)[namelen] = '\0';

		if (close[1] == ':') {
			if (close[2] == '\0')
				goto fail;
			if (strlen(close + 2) > MAX_SECRET_LENGTH) {
				rc_log(LOG_ERR, "radcli_dae_new: dae-server: secret override for "
				       "\"%s\" is longer than %d bytes", *name, MAX_SECRET_LENGTH);
				goto fail;
			}
			*secret = strdup(close + 2);
			if (*secret == NULL)
				goto fail;
		} else if (close[1] != '\0') {
			goto fail;
		}
		return 0;
	}

	colon = strchr(token, ':');
	if (colon != NULL && strchr(colon + 1, ':') == NULL) {
		if (colon == token || colon[1] == '\0')
			return -1;
		namelen = (size_t)(colon - token);
		*name = malloc(namelen + 1);
		if (*name == NULL)
			return -1;
		memcpy(*name, token, namelen);
		(*name)[namelen] = '\0';
		if (strlen(colon + 1) > MAX_SECRET_LENGTH) {
			rc_log(LOG_ERR, "radcli_dae_new: dae-server: secret override for "
			       "\"%s\" is longer than %d bytes", *name, MAX_SECRET_LENGTH);
			goto fail;
		}
		*secret = strdup(colon + 1);
		if (*secret == NULL)
			goto fail;
		return 0;
	}

	*name = strdup(token);
	if (*name == NULL)
		return -1;
	return 0;

fail:
	free(*name);
	free(*secret);
	*name = NULL;
	*secret = NULL;
	return -1;
}

/* Resolves name (already stripped of any ":secret" suffix) and appends one
 * DAC entry per resulting address, each carrying secret_override (or
 * NULL, meaning "use dae->secret"). REQ-DAE-INIT-004: every address a
 * hostname resolves to is authorized. */
static int add_dac_addrs(struct radcli_dae_st *dae, const char *name,
			  const char *secret_override)
{
	struct addrinfo hints, *res, *rp;
	int err;
	struct radcli_dae_dac *tmp;
	unsigned added = 0;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	err = getaddrinfo(name, NULL, &hints, &res);
	if (err != 0) {
		rc_log(LOG_ERR, "radcli_dae_new: dae-server: cannot resolve %s: %s",
		       name, gai_strerror(err));
		return -1;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		if (dae->n_dacs >= RADCLI_DAE_MAX_DACS) {
			rc_log(LOG_ERR, "radcli_dae_new: dae-server: too many resolved "
			       "addresses (max %d)", RADCLI_DAE_MAX_DACS);
			freeaddrinfo(res);
			return -1;
		}
		tmp = realloc(dae->dacs, (dae->n_dacs + 1) * sizeof(*tmp));
		if (tmp == NULL) {
			freeaddrinfo(res);
			return -1;
		}
		dae->dacs = tmp;
		memset(&dae->dacs[dae->n_dacs], 0, sizeof(*tmp));
		memcpy(&dae->dacs[dae->n_dacs].addr, rp->ai_addr, rp->ai_addrlen);
		dae->dacs[dae->n_dacs].addrlen = rp->ai_addrlen;
		if (secret_override != NULL) {
			dae->dacs[dae->n_dacs].secret = strdup(secret_override);
			if (dae->dacs[dae->n_dacs].secret == NULL) {
				freeaddrinfo(res);
				return -1;
			}
		}
		/* REQ-DAE-INIT-005: allocated once, here, at construction --
		 * never grown, evicted, or resized at run time. */
		dae->dacs[dae->n_dacs].slots =
			calloc(RADCLI_DAE_SLOTS, sizeof(*dae->dacs[dae->n_dacs].slots));
		if (dae->dacs[dae->n_dacs].slots == NULL) {
			free(dae->dacs[dae->n_dacs].secret);
			freeaddrinfo(res);
			return -1;
		}
		dae->n_dacs++;
		added++;
	}
	freeaddrinfo(res);

	if (added == 0) {
		rc_log(LOG_ERR, "radcli_dae_new: dae-server: %s resolved to no addresses", name);
		return -1;
	}
	return 0;
}

/* Parses dae-listen ("[host]:port", "host:port", ":port", or an empty/NULL
 * spec for the default). *host comes back malloc()'d, or NULL for "any
 * address"; caller frees. Returns 0 on success, -1 on a malformed spec. */
static int parse_dae_listen(const char *spec, char **host, int *port)
{
	const char *close, *colon;
	long p;
	char *end;

	*host = NULL;
	*port = RADCLI_DAE_DEFAULT_PORT;

	if (spec == NULL || spec[0] == '\0')
		return 0;

	if (spec[0] == '[') {
		close = strchr(spec, ']');
		if (close == NULL || close == spec + 1)
			return -1;
		*host = malloc((size_t)(close - (spec + 1)) + 1);
		if (*host == NULL)
			return -1;
		memcpy(*host, spec + 1, (size_t)(close - (spec + 1)));
		(*host)[close - (spec + 1)] = '\0';

		if (close[1] == ':') {
			p = strtol(close + 2, &end, 10);
			if (*end != '\0' || p < 0 || p > 65535)
				goto fail;
			*port = (int)p;
		} else if (close[1] != '\0') {
			goto fail;
		}
		return 0;
	}

	colon = strrchr(spec, ':');
	if (colon == NULL) {
		*host = strdup(spec);
		if (*host == NULL)
			return -1;
		return 0;
	}

	if (colon != spec) {
		*host = malloc((size_t)(colon - spec) + 1);
		if (*host == NULL)
			return -1;
		memcpy(*host, spec, (size_t)(colon - spec));
		(*host)[colon - spec] = '\0';
	}
	if (colon[1] != '\0') {
		p = strtol(colon + 1, &end, 10);
		if (*end != '\0' || p < 0 || p > 65535)
			goto fail;
		*port = (int)p;
	}
	return 0;

fail:
	free(*host);
	*host = NULL;
	return -1;
}

/** @brief Create a dynamic-authorization listener. See the doc comment in
 *  radcli2.h. */
radcli_dae *radcli_dae_new(radcli_ctx *ctx)
{
	rc_handle *rh = (rc_handle *)ctx;
	struct radcli_dae_st *dae = NULL;
	const char *accept_str, *secret, *server_str, *require_ma_str, *listen_str;
	char *server_dup = NULL, *saveptr, *tok;
	int force_udp;

	if (rh == NULL)
		return NULL;

	accept_str = rc_conf_str(rh, "dae-accept");
	if (accept_str == NULL || strcasecmp(accept_str, "no") == 0) {
		/* Not a misconfiguration: dae-accept unset/"no" is the documented
		 * default, and returning NULL here is how a caller learns dynamic
		 * authorization is off (REQ-DAE-INIT-001) -- no error log. */
		return NULL;
	}
	if (strcasecmp(accept_str, "yes") == 0) {
		force_udp = 0;
	} else if (strcasecmp(accept_str, "udp") == 0) {
		force_udp = 1;
	} else {
		rc_log(LOG_ERR, "radcli_dae_new: dae-accept: invalid value \"%s\" "
		       "(must be no, yes, or udp)", accept_str);
		return NULL;
	}

	/* dae-accept=yes means "follow serv-type": under TLS/DTLS that means
	 * attaching to the already-open RadSec session instead of binding a
	 * separate RFC 5176/UDP listener -- not implemented yet, so fail
	 * clearly here rather than silently falling back to a UDP listener
	 * nothing authorized. dae-accept=udp always forces the RFC 5176/UDP
	 * listener, which this UDP-only implementation can honor regardless
	 * of serv-type. */
	if (!force_udp && (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS)) {
		rc_log(LOG_ERR, "radcli_dae_new: dae-accept=yes under serv-type "
		       "tls/dtls needs dynamic authorization over RadSec, which is "
		       "not implemented yet; set dae-accept=udp to force the RFC "
		       "5176/UDP listener instead");
		return NULL;
	}

	if (rh->active_dae != NULL) {
		rc_log(LOG_ERR, "radcli_dae_new: a radcli_dae is already active on this context");
		return NULL;
	}

	secret = rc_conf_str(rh, "dae-secret");
	server_str = rc_conf_str(rh, "dae-server");
	if (secret == NULL || secret[0] == '\0' || server_str == NULL || server_str[0] == '\0') {
		rc_log(LOG_ERR, "radcli_dae_new: dae-accept is enabled but dae-server "
		       "and/or dae-secret is not set");
		return NULL;
	}
	if (strlen(secret) > MAX_SECRET_LENGTH) {
		rc_log(LOG_ERR, "radcli_dae_new: dae-secret is longer than %d bytes",
		       MAX_SECRET_LENGTH);
		return NULL;
	}

	dae = calloc(1, sizeof(*dae));
	if (dae == NULL)
		return NULL;
	dae->rh = rh;
	dae->fd = -1;

	dae->secret = strdup(secret);
	if (dae->secret == NULL)
		goto fail;

	server_dup = strdup(server_str);
	if (server_dup == NULL)
		goto fail;

	for (tok = strtok_r(server_dup, ",", &saveptr); tok != NULL;
	     tok = strtok_r(NULL, ",", &saveptr)) {
		char *name = NULL, *secret_override = NULL;
		int ret;

		while (*tok == ' ' || *tok == '\t')
			tok++;

		if (parse_dae_server_token(tok, &name, &secret_override) != 0) {
			rc_log(LOG_ERR, "radcli_dae_new: dae-server: invalid entry \"%s\"", tok);
			goto fail;
		}

		ret = add_dac_addrs(dae, name, secret_override);
		free(name);
		free(secret_override);
		if (ret != 0)
			goto fail;
	}
	free(server_dup);
	server_dup = NULL;

	if (dae->n_dacs == 0) {
		rc_log(LOG_ERR, "radcli_dae_new: dae-server produced no authorized senders");
		goto fail;
	}

	dae->max_clock_skew = rc_conf_int_def(rh, "dae-max-clock-skew", 300);
	if (dae->max_clock_skew < 0) {
		rc_log(LOG_ERR, "radcli_dae_new: dae-max-clock-skew must not be negative");
		goto fail;
	}

	require_ma_str = rc_conf_str(rh, "dae-require-message-authenticator");
	dae->require_message_authenticator =
		(require_ma_str != NULL && strcasecmp(require_ma_str, "yes") == 0);

	listen_str = rc_conf_str(rh, "dae-listen");
	if (parse_dae_listen(listen_str, &dae->listen_host, &dae->listen_port) != 0) {
		rc_log(LOG_ERR, "radcli_dae_new: dae-listen: invalid value \"%s\"",
		       listen_str ? listen_str : "");
		goto fail;
	}

	rh->active_dae = dae;
	return (radcli_dae *)dae;

fail:
	free(server_dup);
	radcli_dae_free((radcli_dae *)dae);
	return NULL;
}

/** @brief Register the request handler. See the doc comment in radcli2.h. */
void radcli_dae_set_handler(radcli_dae *d, radcli_dae_handler cb, void *user)
{
	struct radcli_dae_st *dae = (struct radcli_dae_st *)d;

	if (dae == NULL)
		return;
	dae->handler = cb;
	dae->handler_user = user;
}

/* Sets O_NONBLOCK and FD_CLOEXEC on fd. A datagram discarded by the kernel
 * between the readiness report and the read -- or a second reader draining
 * it first -- must not block the application's entire event loop inside a
 * library that never owns it (REQ-GEN-SEC-003); FD_CLOEXEC keeps a
 * library-opened descriptor from leaking across exec() in an application
 * that spawns children (REQ-GEN-SEC-004's ambient-state family). Matches
 * lib/tls.c's fcntl()-based style rather than the SOCK_NONBLOCK/SOCK_CLOEXEC
 * socket() flags, for portability. */
static int set_nonblock_cloexec(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
		return -1;
	flags = fcntl(fd, F_GETFD, 0);
	if (flags == -1 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
		return -1;
	return 0;
}

/** @brief Bind the dae-listen socket. See the doc comment in radcli2.h. */
int radcli_dae_start(radcli_dae *d)
{
	struct radcli_dae_st *dae = (struct radcli_dae_st *)d;
	struct addrinfo hints, *res, *rp;
	int err, fd = -1;
	char portstr[8];

	if (dae == NULL)
		return -1;
	if (dae->fd != -1) {
		rc_log(LOG_ERR, "radcli_dae_start: already started");
		return -1;
	}

	snprintf(portstr, sizeof(portstr), "%d", dae->listen_port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	err = getaddrinfo(dae->listen_host, portstr, &hints, &res);
	if (err != 0) {
		rc_log(LOG_ERR, "radcli_dae_start: dae-listen: %s", gai_strerror(err));
		return -1;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (fd == -1)
			continue;
		if (set_nonblock_cloexec(fd) != 0) {
			close(fd);
			fd = -1;
			continue;
		}
		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
			break;
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);

	if (fd == -1) {
		rc_log(LOG_ERR, "radcli_dae_start: bind: %s", strerror(errno));
		return -1;
	}

	dae->fd = fd;
	return 0;
}

/** @brief Release a listener. See the doc comment in radcli2.h. */
void radcli_dae_free(radcli_dae *d)
{
	struct radcli_dae_st *dae = (struct radcli_dae_st *)d;

	if (dae == NULL)
		return;
	if (dae->rh != NULL && dae->rh->active_dae == dae)
		dae->rh->active_dae = NULL;
	if (dae->fd != -1)
		close(dae->fd);
	free_dacs(dae->dacs, dae->n_dacs);
	free(dae->secret);
	free(dae->listen_host);
	free(dae);
}

/** @brief Report ctx's poll surface. See the doc comment in radcli2.h. */
int radcli_ctx_get_poll(radcli_ctx *ctx, int *fd, unsigned *events, int *timeout_ms)
{
	rc_handle *rh = (rc_handle *)ctx;

	if (rh == NULL || fd == NULL || events == NULL || timeout_ms == NULL)
		return -1;

	if (rh->active_dae == NULL || rh->active_dae->fd == -1) {
		*fd = -1;
		*events = 0;
		*timeout_ms = -1;
		return 0;
	}

	*fd = rh->active_dae->fd;
	*events = POLLIN;
	/* No proactive timer needed: the duplicate-suppression table expires
	 * slots lazily, on next access, rather than on a schedule -- radcli
	 * owns no timer (REQ-GEN-SEC-003). */
	*timeout_ms = -1;
	return 0;
}

/* Finds the configured DAC matching from's address (port ignored: the
 * DAC's source port varies per request, only the address is part of its
 * identity -- REQ-DAE-SEC-001). Returns NULL if from is not authorized. */
static struct radcli_dae_dac *find_dac(struct radcli_dae_st *dae,
					const struct sockaddr *from)
{
	unsigned i;

	for (i = 0; i < dae->n_dacs; i++) {
		const struct sockaddr *caddr = (const struct sockaddr *)&dae->dacs[i].addr;

		if (caddr->sa_family != from->sa_family)
			continue;
		if (memcmp(SA_GET_INADDR(caddr), SA_GET_INADDR(from), SA_GET_INLEN(from)) == 0)
			return &dae->dacs[i];
	}
	return NULL;
}

static uint16_t get_port(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return ntohs(((const struct sockaddr_in *)sa)->sin_port);
	return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
}

/* Returns a malloc()'d, NUL-terminated copy of attrs' first name attribute's
 * value, or NULL if the dictionary lacks name, attrs carries none, or
 * allocation failed. Used to populate radcli_dae_request_st's
 * session_id/user_name fields once, at receive time, since
 * radcli_avp_get_bytes() returns unterminated wire bytes and
 * radcli_dae_req_session_id()/_user_name() must return a C string. */
static char *dup_avp_str(rc_handle *rh, const radcli_avp_list *attrs, const char *name)
{
	const radcli_attr_def *d = radcli_dict_lookup(rh, name);
	const radcli_avp *a;
	const void *val;
	size_t len;
	char *s;

	if (d == NULL)
		return NULL;
	a = radcli_avp_get(attrs, d, 0);
	if (a == NULL || radcli_avp_get_bytes(a, &val, &len) != 0)
		return NULL;
	s = malloc(len + 1);
	if (s == NULL)
		return NULL;
	memcpy(s, val, len);
	s[len] = '\0';
	return s;
}

/* Verifies buf[0..length)'s Request Authenticator (buf[4..20)) per RFC 5176
 * SS2.3 (as specified for Accounting-Request, RFC 2866 SS4.1):
 * MD5(Code+Identifier+Length+16 zero octets+Attributes+Secret) must equal
 * the received field. Constant-time comparison (REQ-DAE-SEC-002). buf must
 * be at least length + strlen(secret) bytes writable (the caller's receive
 * buffer, per the same convention lib/sendserver.c's request-building uses
 * to append the secret before hashing). */
static int verify_request_authenticator(uint8_t *buf, size_t length, const char *secret)
{
	uint8_t received[AUTH_VECTOR_LEN];
	uint8_t calc[AUTH_VECTOR_LEN];
	size_t secretlen = rc_secret_len(secret);

	if (length < AUTH_HDR_LEN)
		return -1;

	memcpy(received, buf + 4, AUTH_VECTOR_LEN);
	memset(buf + 4, 0, AUTH_VECTOR_LEN);
	memcpy(buf + length, secret, secretlen);
	rc_md5_calc(calc, buf, length + secretlen);
	memcpy(buf + 4, received, AUTH_VECTOR_LEN); /* restore: buf is the caller's receive buffer */

	return rc_memcmp(received, calc, AUTH_VECTOR_LEN) == 0 ? 0 : -1;
}

/* Builds and sends req's reply: reply_code (already the concrete 41/42/44/45
 * code) with error_cause encoded as attribute 101 when non-zero, mirroring
 * every Proxy-State from the request, Message-Authenticator, and a Response
 * Authenticator computed over req's own Request Authenticator (RFC 5176
 * SS2.3, REQ-DAE-SEC-008). Returns 0 on success, -1 on failure. */
/* Builds req's reply into out_buf (capacity out_cap), setting *out_len.
 * Shared by send_reply() (which then sends the bytes over req->dae->fd) and
 * radcli_dae_reply_to_buffer() (which hands them to the caller instead).
 * Returns 0 on success, -1 on failure (e.g. out_cap too small). */
static int build_reply(struct radcli_dae_request_st *req, uint8_t reply_code, uint32_t error_cause,
		       uint8_t *out_buf, int out_cap, int *out_len)
{
	rc_handle *rh = req->dae->rh;
	AUTH_HDR *auth = (AUTH_HDR *)out_buf;
	radcli_avp_list *reply_attrs;
	const radcli_avp *a;
	const radcli_attr_def *d_proxy_state;
	int encoded_len, total_length;
	size_t secretlen;
	uint8_t digest[AUTH_VECTOR_LEN];

	if (out_cap < AUTH_HDR_LEN)
		return -1;

	reply_attrs = radcli_avp_list_new();
	if (reply_attrs == NULL)
		return -1;

	if (error_cause != 0) {
		const radcli_attr_def *d_ec = radcli_dict_lookup(rh, "Error-Cause");

		if (d_ec != NULL)
			radcli_avp_add_uint32(reply_attrs, d_ec, error_cause);
	}

	d_proxy_state = radcli_dict_lookup(rh, "Proxy-State");
	if (d_proxy_state != NULL) {
		radcli_avp_iter it = radcli_avp_list_iter(req->attrs);

		while ((a = radcli_avp_iter_next(&it)) != NULL) {
			const void *val;
			size_t len;

			if (radcli_avp_def(a) != d_proxy_state)
				continue;
			if (radcli_avp_get_bytes(a, &val, &len) == 0)
				radcli_avp_add_bytes(reply_attrs, d_proxy_state, val, len);
		}
	}

	auth->code = reply_code;
	auth->id = req->id;
	memcpy(auth->vector, req->request_authenticator, AUTH_VECTOR_LEN);

	encoded_len = radcli_avp_encode_rfc2865(rh, reply_attrs, req->secret, req->request_authenticator,
					auth->data, out_cap - AUTH_HDR_LEN - (2 + MD5_DIGEST_SIZE), NULL);
	radcli_avp_list_free(reply_attrs);
	if (encoded_len < 0)
		return -1;

	total_length = AUTH_HDR_LEN + encoded_len;
	auth->length = htons((uint16_t)total_length);

	if (out_cap < total_length + (2 + MD5_DIGEST_SIZE))
		return -1;
	total_length = add_msg_auth_attr(rh, req->secret, auth, total_length);

	secretlen = rc_secret_len(req->secret);
	if ((size_t)(out_cap - total_length) < secretlen)
		return -1;
	memcpy(out_buf + total_length, req->secret, secretlen);
	rc_md5_calc(digest, out_buf, (size_t)total_length + secretlen);
	memcpy(auth->vector, digest, AUTH_VECTOR_LEN);

	*out_len = total_length;
	return 0;
}

static int send_reply(struct radcli_dae_request_st *req, uint8_t reply_code, uint32_t error_cause)
{
	uint8_t send_buffer[RC_BUFFER_LEN];
	int total_length;

	if (build_reply(req, reply_code, error_cause, send_buffer, sizeof(send_buffer),
			&total_length) != 0)
		return -1;

	if (sendto(req->dae->fd, send_buffer, (size_t)total_length, 0,
		  (struct sockaddr *)&req->from, req->fromlen) != total_length)
		return -1;

	return 0;
}

/** @brief Return the request's code. See the doc comment in radcli2.h. */
radcli_code radcli_dae_req_code(const radcli_dae_request *r)
{
	const struct radcli_dae_request_st *req = (const struct radcli_dae_request_st *)r;

	if (req == NULL)
		return 0;
	return (radcli_code)req->code;
}

/** @brief Return the request's attributes. See the doc comment in radcli2.h. */
const radcli_avp_list *radcli_dae_req_attrs(const radcli_dae_request *r)
{
	const struct radcli_dae_request_st *req = (const struct radcli_dae_request_st *)r;

	if (req == NULL)
		return NULL;
	return req->attrs;
}

/** @brief Return the request's Acct-Session-Id. See the doc comment in
 *  radcli2.h. */
const char *radcli_dae_req_session_id(const radcli_dae_request *r)
{
	const struct radcli_dae_request_st *req = (const struct radcli_dae_request_st *)r;

	if (req == NULL)
		return NULL;
	return req->session_id;
}

/** @brief Return the request's User-Name. See the doc comment in radcli2.h. */
const char *radcli_dae_req_user_name(const radcli_dae_request *r)
{
	const struct radcli_dae_request_st *req = (const struct radcli_dae_request_st *)r;

	if (req == NULL)
		return NULL;
	return req->user_name;
}

/** @brief Return the request's Framed-IP-Address/Framed-IPv6-Address. See
 *  the doc comment in radcli2.h. */
int radcli_dae_req_framed_ip(const radcli_dae_request *r, struct sockaddr_storage *out)
{
	const struct radcli_dae_request_st *req = (const struct radcli_dae_request_st *)r;
	rc_handle *rh;
	const radcli_attr_def *d;
	const radcli_avp *a;

	if (req == NULL || out == NULL)
		return -1;
	rh = req->dae->rh;

	d = radcli_dict_lookup(rh, "Framed-IP-Address");
	a = (d != NULL) ? radcli_avp_get(req->attrs, d, 0) : NULL;
	if (a != NULL) {
		uint32_t val;

		if (radcli_avp_get_uint32(a, &val) == 0) {
			struct sockaddr_in sin;

			memset(&sin, 0, sizeof(sin));
			sin.sin_family = AF_INET;
			sin.sin_addr.s_addr = htonl(val);
			memset(out, 0, sizeof(*out));
			memcpy(out, &sin, sizeof(sin));
			return 0;
		}
	}

	d = radcli_dict_lookup(rh, "Framed-IPv6-Address");
	a = (d != NULL) ? radcli_avp_get(req->attrs, d, 0) : NULL;
	if (a != NULL) {
		struct in6_addr addr;
		unsigned prefix;

		if (radcli_avp_get_in6(a, &addr, &prefix) == 0) {
			struct sockaddr_in6 sin6;

			memset(&sin6, 0, sizeof(sin6));
			sin6.sin6_family = AF_INET6;
			sin6.sin6_addr = addr;
			memset(out, 0, sizeof(*out));
			memcpy(out, &sin6, sizeof(sin6));
			return 0;
		}
	}

	return -1;
}

/** @brief Return the request's NAS-Port. See the doc comment in radcli2.h. */
int radcli_dae_req_nas_port(const radcli_dae_request *r, uint32_t *out)
{
	const struct radcli_dae_request_st *req = (const struct radcli_dae_request_st *)r;
	rc_handle *rh;
	const radcli_attr_def *d;
	const radcli_avp *a;

	if (req == NULL)
		return -1;
	rh = req->dae->rh;

	d = radcli_dict_lookup(rh, "NAS-Port");
	a = (d != NULL) ? radcli_avp_get(req->attrs, d, 0) : NULL;
	if (a == NULL)
		return -1;
	if (out == NULL)
		return 0;
	return radcli_avp_get_uint32(a, out);
}

/** @brief Check the request's NAS identity against this context's own. See
 *  the doc comment in radcli2.h. */
int radcli_dae_req_check_nas(const radcli_dae_request *r)
{
	const struct radcli_dae_request_st *req = (const struct radcli_dae_request_st *)r;
	rc_handle *rh;
	const radcli_attr_def *d;
	const radcli_avp *a;
	const char *cfg_id, *cfg_ip;

	if (req == NULL)
		return -1;
	rh = req->dae->rh;

	cfg_id = rc_conf_str(rh, "nas-identifier");
	d = radcli_dict_lookup(rh, "NAS-Identifier");
	a = (d != NULL) ? radcli_avp_get(req->attrs, d, 0) : NULL;
	if (a != NULL && cfg_id != NULL) {
		const void *val;
		size_t len;

		if (radcli_avp_get_bytes(a, &val, &len) == 0 &&
		    (len != strlen(cfg_id) || memcmp(val, cfg_id, len) != 0))
			return -1;
	}

	cfg_ip = rc_conf_str(rh, "nas-ip");

	d = radcli_dict_lookup(rh, "NAS-IP-Address");
	a = (d != NULL) ? radcli_avp_get(req->attrs, d, 0) : NULL;
	if (a != NULL && cfg_ip != NULL) {
		uint32_t reqval;
		struct in_addr cfgaddr;

		if (radcli_avp_get_uint32(a, &reqval) == 0 &&
		    inet_pton(AF_INET, cfg_ip, &cfgaddr) == 1 &&
		    ntohl(cfgaddr.s_addr) != reqval)
			return -1;
	}

	d = radcli_dict_lookup(rh, "NAS-IPv6-Address");
	a = (d != NULL) ? radcli_avp_get(req->attrs, d, 0) : NULL;
	if (a != NULL && cfg_ip != NULL) {
		struct in6_addr reqaddr, cfgaddr;
		unsigned prefix;

		if (radcli_avp_get_in6(a, &reqaddr, &prefix) == 0 &&
		    inet_pton(AF_INET6, cfg_ip, &cfgaddr) == 1 &&
		    memcmp(&reqaddr, &cfgaddr, sizeof(reqaddr)) != 0)
			return -1;
	}

	return 0;
}

/* Records reply_code/error_cause as the decision in req's duplicate-
 * suppression slot, if it still matches req exactly (source port and
 * Request Authenticator) and is still awaiting one -- i.e. transitions it
 * from PENDING to ANSWERED. Shared by reply_and_record() (after an actual
 * send) and radcli_dae_reply_to_buffer() (after producing bytes an L0
 * caller will send itself): either way, a later retransmission must be
 * answered from this same decision, not a fresh one (REQ-DAE-SEC-005), even
 * if the reply was deferred past the handler's own return. */
static void record_reply_decision(struct radcli_dae_request_st *req, uint8_t reply_code,
				  uint32_t error_cause)
{
	struct radcli_dae_slot *slot;

	if (req->dac == NULL)
		return;
	slot = &req->dac->slots[req->id];
	if (slot->valid && slot->pending &&
	    slot->source_port == get_port((struct sockaddr *)&req->from) &&
	    rc_memcmp(slot->request_authenticator, req->request_authenticator,
		     AUTH_VECTOR_LEN) == 0) {
		slot->pending = 0;
		slot->reply_code = reply_code;
		slot->error_cause = error_cause;
	}
}

static int reply_and_record(struct radcli_dae_request_st *req, uint8_t reply_code, uint32_t error_cause)
{
	int ret;

	if (req == NULL || req->replied)
		return -1;
	req->replied = 1;

	ret = send_reply(req, reply_code, error_cause);
	record_reply_decision(req, reply_code, error_cause);

	return ret;
}

/* Selects the concrete ACK/NAK code (41/42/44/45) for req's own code (40/43)
 * and the application's accept/reject decision (RFC 5176 SS2.1, SS3). Shared
 * by radcli_dae_reply() and radcli_dae_reply_to_buffer(). */
static uint8_t select_reply_code(const struct radcli_dae_request_st *req, int ack)
{
	return ack
		? (req->code == RADCLI_DISCONNECT_REQUEST ? RADCLI_DISCONNECT_ACK : RADCLI_COA_ACK)
		: (req->code == RADCLI_DISCONNECT_REQUEST ? RADCLI_DISCONNECT_NAK : RADCLI_COA_NAK);
}

/** @brief Answer with an ACK/NAK. See the doc comment in radcli2.h. */
int radcli_dae_reply(radcli_dae_request *r, int ack)
{
	struct radcli_dae_request_st *req = (struct radcli_dae_request_st *)r;

	if (req == NULL)
		return -1;
	return reply_and_record(req, select_reply_code(req, ack), 0);
}

/** @brief Answer with a NAK carrying an Error-Cause. See the doc comment in
 *  radcli2.h. */
int radcli_dae_reply_error(radcli_dae_request *r, uint32_t error_cause)
{
	struct radcli_dae_request_st *req = (struct radcli_dae_request_st *)r;
	uint8_t reply_code;

	if (req == NULL)
		return -1;
	reply_code = (req->code == RADCLI_DISCONNECT_REQUEST) ? RADCLI_DISCONNECT_NAK : RADCLI_COA_NAK;
	return reply_and_record(req, reply_code, error_cause);
}

/** @brief Produce a reply as bytes instead of sending it. See the doc
 *  comment in radcli2.h. */
int radcli_dae_reply_to_buffer(radcli_dae_request *r, int ack, uint32_t error_cause,
			       void *buf, size_t *len)
{
	struct radcli_dae_request_st *req = (struct radcli_dae_request_st *)r;
	uint8_t reply_code;
	int out_len;

	if (req == NULL || buf == NULL || len == NULL || *len > INT_MAX)
		return -1;

	if (req->is_cached_duplicate) {
		/* A genuine retransmission always gets the same answer
		 * (RFC 5176 SS2.3): the caller's ack/error_cause are not
		 * this decision's to make over again. */
		reply_code = req->cached_reply_code;
		error_cause = req->cached_error_cause;
	} else {
		if (req->replied)
			return -1;
		reply_code = select_reply_code(req, ack);
	}

	if (build_reply(req, reply_code, error_cause, (uint8_t *)buf, (int)*len, &out_len) != 0)
		return -1;
	*len = (size_t)out_len;

	if (!req->is_cached_duplicate) {
		req->replied = 1;
		record_reply_decision(req, reply_code, error_cause);
	}

	return 0;
}

/** @brief Release a request. See the doc comment in radcli2.h. */
void radcli_dae_request_free(radcli_dae_request *r)
{
	struct radcli_dae_request_st *req = (struct radcli_dae_request_st *)r;

	if (req == NULL)
		return;
	radcli_avp_list_free(req->attrs);
	free(req->session_id);
	free(req->user_name);
	free(req);
}

/* Rebuilds and resends a duplicate's reply from the retransmitted request
 * (its Proxy-State attributes, per RFC 5176 SS2.3) plus the cached decision
 * -- never from a stored copy of the original reply, which is why a slot
 * stays ~32 bytes rather than a full packet buffer. */
/* Outcomes of process_packet(), the validation pipeline shared by
 * radcli_ctx_dispatch() (socket path) and radcli_dae_process() (L0 buffer
 * path) -- REQ-DAE-NET-003 requires the two to be indistinguishable. */
enum process_result {
	PROCESS_DROP,         /* discarded at some check; *out_req left NULL */
	PROCESS_NEW,          /* a newly validated request; *out_req set, PENDING */
	PROCESS_DUP_ANSWERED, /* a retransmission of an ANSWERED request; *out_req
	                       * set, carrying the cached decision */
};

/* Runs the full RFC 5176 validation pipeline on one packet (REQ-DAE-NET-002):
 * source-address authorization (REQ-DAE-SEC-001), packet-code and length
 * sanity (REQ-DAE-ERR-001), Request Authenticator (REQ-DAE-SEC-002),
 * Message-Authenticator when present or required (REQ-DAE-SEC-003),
 * Event-Timestamp freshness (REQ-DAE-SEC-004), then duplicate suppression
 * (REQ-DAE-SEC-005/006). buf must have RC_MAX_PACKET_LEN + MAX_SECRET_LENGTH
 * bytes of headroom past len (verify_request_authenticator() writes there);
 * both callers below satisfy this from a stack buffer sized RC_BUFFER_LEN. */
static enum process_result process_packet(struct radcli_dae_st *dae, uint8_t *buf, size_t len,
					   const struct sockaddr *from, socklen_t fromlen,
					   struct radcli_dae_request_st **out_req)
{
	rc_handle *rh = dae->rh;
	size_t length = len;
	struct radcli_dae_dac *dac;
	struct radcli_dae_slot *slot;
	uint16_t src_port;
	time_t now;
	int retention;
	struct radcli_dae_request_st *req;
	radcli_avp_list *attrs = NULL;
	const radcli_attr_def *d;
	const radcli_avp *a;

	*out_req = NULL;

	/* REQ-DAE-SEC-001: discarded before parsing attributes or computing
	 * any MD5/HMAC, and without a reply -- a response would confirm to a
	 * scanner that a listener is present. */
	dac = find_dac(dae, from);
	if (dac == NULL)
		return PROCESS_DROP;

	/* Header sanity: enough bytes for a header, the wire Length field
	 * agrees with what was actually received (never trust it beyond
	 * that) and with RFC 2865's packet-size cap (also what leaves
	 * verify_request_authenticator() below enough headroom in buf to
	 * append the secret without overrunning it), and the code is one
	 * this pipeline handles at all (REQ-DAE-ERR-001). */
	if (length < AUTH_HDR_LEN)
		return PROCESS_DROP;
	{
		uint16_t wire_length;

		memcpy(&wire_length, buf + 2, sizeof(wire_length));
		wire_length = ntohs(wire_length);
		if (wire_length < AUTH_HDR_LEN || wire_length > length ||
		    wire_length > RC_MAX_PACKET_LEN)
			return PROCESS_DROP;
		length = wire_length; /* never read past the packet's own Length */
	}
	if (buf[0] != RADCLI_DISCONNECT_REQUEST && buf[0] != RADCLI_COA_REQUEST)
		return PROCESS_DROP;

	{
		const char *secret = (dac->secret != NULL) ? dac->secret : dae->secret;

		if (verify_request_authenticator(buf, length, secret) != 0)
			return PROCESS_DROP;

		if (radcli_avp_decode(rh, secret, buf + 4, buf + AUTH_HDR_LEN,
				      length - AUTH_HDR_LEN, 0, &attrs) != 0)
			return PROCESS_DROP;

		/* Message-Authenticator: verified when present (mismatch is a
		 * silent discard, same as any other authentication failure);
		 * required when dae-require-message-authenticator is set
		 * (RFC 5176 SS3 makes the attribute itself a MAY, so absence
		 * alone is not a failure otherwise). Disconnect-Request and
		 * CoA-Request derive their own Request Authenticator from a
		 * hash of the packet (RFC 5176 SS2.3, the Accounting-Request
		 * convention), so -- like Accounting-Request -- the sender
		 * computes this HMAC with the Authenticator field treated as
		 * sixteen zero octets (RFC 2869 SS5.14), not the packet's
		 * actual Request Authenticator: only that ordering is
		 * non-circular, since the real Request Authenticator is
		 * itself hashed over the attributes including this one. */
		d = radcli_dict_lookup(rh, "Message-Authenticator");
		a = (d != NULL) ? radcli_avp_get(attrs, d, 0) : NULL;
		if (a != NULL) {
			uint8_t zero_vector[AUTH_VECTOR_LEN];

			memset(zero_vector, 0, sizeof(zero_vector));
			if (validate_message_authenticator(buf, length - AUTH_HDR_LEN, secret,
							   zero_vector) != 0) {
				radcli_avp_list_free(attrs);
				return PROCESS_DROP;
			}
		} else if (dae->require_message_authenticator) {
			radcli_avp_list_free(attrs);
			return PROCESS_DROP;
		}
	}

	/* Event-Timestamp: two-sided freshness check when present and
	 * enabled; absence is accepted (RFC 5176 SS6.3 makes it a SHOULD). */
	if (dae->max_clock_skew > 0) {
		d = radcli_dict_lookup(rh, "Event-Timestamp");
		a = (d != NULL) ? radcli_avp_get(attrs, d, 0) : NULL;
		if (a != NULL) {
			uint32_t ts;
			long diff;

			if (radcli_avp_get_uint32(a, &ts) != 0) {
				radcli_avp_list_free(attrs);
				return PROCESS_DROP;
			}
			now = time(NULL);
			diff = (long)now - (long)ts;
			if (diff < 0)
				diff = -diff;
			if (diff > dae->max_clock_skew) {
				radcli_avp_list_free(attrs);
				return PROCESS_DROP;
			}
		}
	}

	/* Duplicate suppression (REQ-DAE-SEC-005/006): a fixed slot per
	 * Identifier, per authorized DAC. A match on source port and
	 * Request Authenticator is a genuine retransmission -- answered from
	 * the cached decision if one exists, or silently dropped if the
	 * original is still PENDING; anything else (including a first-ever
	 * arrival) claims the slot and produces a new request. */
	now = time(NULL);
	retention = (dae->max_clock_skew > 0) ? dae->max_clock_skew : 30;
	src_port = get_port(from);
	slot = &dac->slots[buf[1]];

	req = calloc(1, sizeof(*req));
	if (req == NULL) {
		radcli_avp_list_free(attrs);
		return PROCESS_DROP;
	}
	req->dae = dae;
	req->dac = dac;
	req->code = buf[0];
	req->id = buf[1];
	memcpy(req->request_authenticator, buf + 4, AUTH_VECTOR_LEN);
	memcpy(&req->from, from, fromlen);
	req->fromlen = fromlen;
	strlcpy(req->secret, (dac->secret != NULL) ? dac->secret : dae->secret,
	       sizeof(req->secret));
	req->attrs = attrs;
	attrs = NULL;
	req->session_id = dup_avp_str(rh, req->attrs, "Acct-Session-Id");
	req->user_name = dup_avp_str(rh, req->attrs, "User-Name");

	if (slot->valid && (now - slot->timestamp) <= retention &&
	    slot->source_port == src_port &&
	    rc_memcmp(slot->request_authenticator, req->request_authenticator,
		     AUTH_VECTOR_LEN) == 0) {
		if (!slot->pending) {
			req->is_cached_duplicate = 1;
			req->cached_reply_code = slot->reply_code;
			req->cached_error_cause = slot->error_cause;
			*out_req = req;
			return PROCESS_DUP_ANSWERED;
		}
		/* Original still PENDING an application decision -- discarded
		 * silently, exactly like any other failed check. */
		radcli_dae_request_free((radcli_dae_request *)req);
		return PROCESS_DROP;
	}

	slot->valid = 1;
	slot->timestamp = now;
	slot->source_port = src_port;
	memcpy(slot->request_authenticator, req->request_authenticator, AUTH_VECTOR_LEN);
	slot->pending = 1;

	*out_req = req;
	return PROCESS_NEW;
}

/** @brief Read and demultiplex what is ready on ctx's descriptor. See the
 *  doc comment in radcli2.h.
 *
 * Reads exactly one datagram per call (non-blocking), so a burst of
 * requests re-arms the caller's loop rather than starving it, and runs it
 * through process_packet()'s validation pipeline before ever invoking the
 * registered handler. Every rejection short of "authorized sender" is
 * silent: no reply, no Error-Cause, no log of the secret or either
 * authenticator (REQ-DAE-SEC-009). */
int radcli_ctx_dispatch(radcli_ctx *ctx)
{
	rc_handle *rh = (rc_handle *)ctx;
	struct radcli_dae_st *dae;
	uint8_t buf[RC_BUFFER_LEN];
	struct sockaddr_storage from;
	socklen_t fromlen;
	ssize_t n;
	struct radcli_dae_request_st *req = NULL;

	if (rh == NULL)
		return -1;

	if (rh->in_dispatch) {
		rc_log(LOG_ERR, "radcli_ctx_dispatch: reentrant call");
		return -1;
	}

	dae = rh->active_dae;
	if (dae == NULL || dae->fd == -1)
		return -1;

	rh->in_dispatch = 1;

	fromlen = sizeof(from);
	n = recvfrom(dae->fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fromlen);
	if (n < 0) {
		/* EAGAIN/EWOULDBLOCK ("nothing to read after all") and any other
		 * receive error both simply mean there is nothing to deliver
		 * this call; a socket-level error is not the caller's to act
		 * on here. */
		rh->in_dispatch = 0;
		return 0;
	}

	switch (process_packet(dae, buf, (size_t)n, (struct sockaddr *)&from, fromlen, &req)) {
	case PROCESS_NEW:
		if (dae->handler != NULL)
			dae->handler((radcli_dae_request *)req, dae->handler_user);
		else
			radcli_dae_request_free((radcli_dae_request *)req);
		break;
	case PROCESS_DUP_ANSWERED:
		req->replied = 1; /* answered from the cached decision, not a fresh one */
		send_reply(req, req->cached_reply_code, req->cached_error_cause);
		radcli_dae_request_free((radcli_dae_request *)req);
		break;
	case PROCESS_DROP:
		break;
	}

	rh->in_dispatch = 0;
	return 0;
}

/** @brief Validate a caller-supplied packet without a radcli-owned socket.
 *  See the doc comment in radcli2.h. */
int radcli_dae_process(radcli_dae *d, const void *buf, size_t len,
		       const struct sockaddr *from, socklen_t fromlen,
		       radcli_dae_request **req_out)
{
	struct radcli_dae_st *dae = (struct radcli_dae_st *)d;
	struct radcli_dae_request_st *req = NULL;
	uint8_t local_buf[RC_BUFFER_LEN];
	enum process_result result;

	if (dae == NULL || buf == NULL || from == NULL || req_out == NULL ||
	    len == 0 || len > sizeof(local_buf) - 1)
		return -1;
	*req_out = NULL;

	/* process_packet() mutates the buffer in place (verify_request_
	 * authenticator() zeroes and restores the Authenticator field) --
	 * copy so the caller's own buffer is never touched. */
	memcpy(local_buf, buf, len);

	result = process_packet(dae, local_buf, len, from, fromlen, &req);
	if (result == PROCESS_DROP)
		return -1;

	*req_out = (radcli_dae_request *)req;
	return (result == PROCESS_DUP_ANSWERED) ? RADCLI_DAE_DUPLICATE : RADCLI_DAE_NEW;
}
