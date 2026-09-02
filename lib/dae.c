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

/** @file dae.c
 * @brief RFC 5176 dynamic-authorization (CoA/Disconnect) listener and dispatch.
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
 * itself (REQ-NET2-NET-001, REQ-GEN-SEC-003).
 *
 * radcli_ctx_dispatch() runs the full validation pipeline (REQ-NET2-NET-002)
 * before ever invoking the registered radcli_dae_handler: source-address
 * authorization, Request Authenticator, Message-Authenticator, Event-
 * Timestamp freshness, then duplicate suppression against a fixed
 * 256-slot table shared by every configured dae-server entry
 * (REQ-DAE-SEC-001..006). Session-selector convenience accessors
 * (radcli_dae_req_session_id()/_user_name()/_framed_ip()/_nas_port()/
 * _check_nas(), doc/requirements/dae.md's DATA category) are implemented
 * below; an application can still reach the same data via
 * radcli_dae_req_attrs() directly instead. */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "util.h"
#include "avp.h"
#include "options.h"
#include "rc-crypto.h"
#include "rc-random.h"
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#define RADCLI_DAE_DEFAULT_PORT 3799
/* Sane bound on the number of addresses dae-server's entries resolve to --
 * not a protocol limit, just parse-loop hygiene against an operator config
 * mistake (e.g. a hostname with an unexpectedly large RRset). */
#define RADCLI_DAE_MAX_DACS 64

/* Duplicate suppression is keyed on (Identifier, Request Authenticator)
 * alone; Identifier is one octet, so this is the whole space -- a fixed
 * table, not a cache with an eviction policy (REQ-DAE-SEC-005). RFC 5176
 * SS2.3 names source address and source port as part of the tuple too, but
 * neither is part of what the Request/Message-Authenticator actually hash
 * (Code+Identifier+Length+Authenticator+Attributes+Secret): the source
 * address is not cryptographically bound to the packet at all, so it was
 * never real proof of anything -- only the Authenticator, keyed on the
 * shared secret, is. One shared table per listener (not one per configured
 * dae-server entry) follows from that: source port was dropped from the
 * match first (an off-path attacker replaying one captured packet controls
 * the port freely, so requiring it to match let the packet be replayed as
 * "new" from a fresh port indefinitely); partitioning the table per
 * configured sender address reopened the identical bypass one level up,
 * since dae-server entries commonly share one secret (no per-entry
 * :secret override) -- a captured packet replayed with the source address
 * spoofed to a DIFFERENT configured entry sharing that secret still
 * verified, but landed in that entry's own empty table and was delivered
 * as new. A single shared table closes both: whichever configured sender
 * the replay is spoofed as, the same dedup key lands in the same slot.
 * (A genuine collision between two different, unrelated packets would need
 * the 256-bit SHA-256 dedup key -- REQ-DAE-SEC-005, computed by
 * process_packet() itself over the verified packet, not the wire's 128-bit
 * MD5 Request Authenticator -- to coincide by chance: not a practical
 * concern.) */
#define RADCLI_DAE_SLOTS 256

struct radcli_dae_slot {
	unsigned valid;
	time_t timestamp;
	uint8_t dedup_key[RC_SHA256_DIGEST_SIZE]; /* REQ-DAE-SEC-005: an
	                                            * SHA-256 digest process_
	                                            * packet() computes itself
	                                            * over the verified packet
	                                            * -- not the wire's MD5
	                                            * Request Authenticator. */
	unsigned pending; /* 1 = PENDING (awaiting an application decision) */
	uint8_t reply_code;
	uint32_t error_cause; /* 0 = no Error-Cause attribute (an ACK) */
};

struct radcli_dae_dac {
	struct sockaddr_storage addr;
	socklen_t addrlen;
	char *secret; /* NULL => use radcli_dae_st.secret */
};

/* Fixed bound on radcli2_priv_dae_on_radsec_packet()'s queue of validated
 * RadSec requests awaiting delivery via radcli_ctx_dispatch() -- never
 * grown at run time, same "no unbounded packet-driven allocation"
 * principle as RADCLI_DAE_SLOTS/RADCLI_DAE_MAX_DACS above. In practice
 * this holds at most one entry almost always: radcli_transport_exchange()
 * serializes the whole RadSec session behind one lock for an entire
 * send-and-wait cycle (lib/sendserver.c), so only one thread is ever
 * reading the wire at a time. A small bound still exists for the case
 * where the application is slow to call radcli_ctx_dispatch() while
 * several requests arrive; overflow drops the oldest queued entry and
 * logs, rather than growing without limit. */
#define RADCLI_DAE_RADSEC_QUEUE_SIZE 8

/* REQ-DAE-SEC-013: bound on radcli_ctx_dispatch()'s queue of RadSec
 * replies (ACK/NAK) that could not be sent immediately without blocking
 * (radcli2_priv_tls_dae_send() returned "would block") -- send_reply()
 * defers to this queue instead of waiting, so a slow-reading DAC cannot
 * turn a dispatch() call into a multi-second stall of the caller's event
 * loop. A fixed byte size per slot, not RC_BUFFER_LEN: every DAE reply is
 * a header plus at most one Error-Cause (6 bytes) and Proxy-State
 * attributes mirrored from the request (RFC 5176 SS3, bounded by whatever
 * the request itself carried) plus a Message-Authenticator (18 bytes) --
 * 512 bytes is generous headroom over any of this without the ~8KB
 * per-slot cost RC_BUFFER_LEN would add for a queue that is expected to
 * hold at most a handful of entries at once. */
#define RADCLI_DAE_RADSEC_REPLY_QUEUE_SIZE 8
#define RADCLI_DAE_RADSEC_REPLY_MAX_LEN 512

struct radcli_dae_pending_reply {
	uint8_t buf[RADCLI_DAE_RADSEC_REPLY_MAX_LEN];
	size_t len;
};

struct radcli_dae_st {
	rc_handle *rh;
	char *secret;
	struct radcli_dae_dac *dacs;
	unsigned n_dacs;
	struct radcli_dae_slot *slots; /* RADCLI_DAE_SLOTS entries, shared by
	                                * every configured dae-server entry --
	                                * see RADCLI_DAE_SLOTS's comment. */
	int max_clock_skew;
	int require_message_authenticator;
	unsigned no_nas_check; /* RADCLI_DAE_NO_NAS_CHECK passed to radcli_dae_new() */
	char *listen_host; /* NULL => any address */
	int listen_port;
	int fd;
	radcli_dae_handler handler;
	void *handler_user;

	/* Set at construction when dae-accept=yes follows serv-type=tls/dtls
	 * (radcli_dae_new()): CoA/Disconnect flow over rh's own established
	 * TLS/DTLS session (lib/tls.c's tls_recvfrom() demux,
	 * radcli2_priv_dae_on_radsec_packet()) instead of a dae-owned UDP
	 * listener -- dacs/n_dacs/secret/listen_host/listen_port/fd above are
	 * all unused in this mode (dae->fd stays -1 throughout). */
	unsigned radsec;
	unsigned started; /* radcli_dae_start() already called -- radsec mode
	                    * has no fd to test "already started" against. */

	/* radcli2_priv_dae_on_radsec_packet()'s queue -- see
	 * RADCLI_DAE_RADSEC_QUEUE_SIZE's comment. FIFO: radsec_queue[0] is
	 * the oldest still-undelivered request. Protected by radsec_lock:
	 * radcli2_priv_dae_on_radsec_packet() can run on whatever thread is
	 * currently inside radcli_transport_exchange() (tls_recvfrom()'s
	 * inline demux, holding the *session's* lock, lib/tls.c) at the exact
	 * same time radcli_ctx_dispatch()'s poll thread (having already
	 * released the session lock -- radcli2_priv_tls_dae_poll() only holds
	 * it for the read itself) is draining the queue or processing a
	 * record of its own -- the session lock alone does not serialize
	 * these two call sites against each other. process_packet()'s own
	 * duplicate-suppression table (dae->slots[]) needs the same
	 * protection for the identical reason, so this lock is held around
	 * every radsec-mode call into process_packet() too, not just the
	 * queue operations. */
	struct radcli_dae_request_st *radsec_queue[RADCLI_DAE_RADSEC_QUEUE_SIZE];
	unsigned radsec_queue_len;

	/* REQ-DAE-SEC-013: outbound replies deferred by send_reply() when
	 * radcli2_priv_tls_dae_send() reports the send would block. FIFO,
	 * drained in order (a later reply must not overtake an earlier one
	 * still waiting) by radsec_flush_reply_queue(), called from
	 * radcli_ctx_dispatch()'s radsec branch. Also protected by
	 * radsec_lock, for the same reason radsec_queue[] above is. */
	struct radcli_dae_pending_reply radsec_reply_queue[RADCLI_DAE_RADSEC_REPLY_QUEUE_SIZE];
	unsigned radsec_reply_queue_len;

	pthread_mutex_t radsec_lock;
};

struct radcli_dae_request_st {
	struct radcli_dae_st *dae;
	struct radcli_dae_dac *dac; /* the authorized sender this arrived from */
	uint8_t code;
	uint8_t id;
	uint8_t request_authenticator[AUTH_VECTOR_LEN];
	uint8_t dedup_key[RC_SHA256_DIGEST_SIZE]; /* REQ-DAE-SEC-005: SHA-256
	                                            * over the verified packet,
	                                            * snapshotted so a later
	                                            * record_reply_decision()
	                                            * call can re-verify the
	                                            * slot it claimed is still
	                                            * this same request's. */
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

/*- Free a dacs array and each entry's secret.
 *
 * @param dacs the array to free; NULL is accepted and ignored.
 * @param n the number of entries in dacs.
 -*/
static void free_dacs(struct radcli_dae_dac *dacs, unsigned n)
{
	unsigned i;

	if (dacs == NULL)
		return;
	for (i = 0; i < n; i++)
		free(dacs[i].secret);
	free(dacs);
}

/*- Append req to dae's RadSec delivery queue (radcli2_priv_dae_on_radsec_
 * packet(), radcli_ctx_dispatch()'s RadSec branch). If the queue is
 * already at RADCLI_DAE_RADSEC_QUEUE_SIZE, the oldest entry is dropped
 * (freed) and logged first -- see that constant's comment.
 *
 * @param dae the listener whose queue to append to.
 * @param req the request to enqueue.
 -*/
static void radsec_queue_push(struct radcli_dae_st *dae, struct radcli_dae_request_st *req)
{
	unsigned i;

	if (dae->radsec_queue_len == RADCLI_DAE_RADSEC_QUEUE_SIZE) {
		rc_log(LOG_WARNING, "radcli_ctx_dispatch: RadSec dynamic-authorization "
		       "queue full (%u), dropping the oldest undelivered request",
		       (unsigned)RADCLI_DAE_RADSEC_QUEUE_SIZE);
		radcli_dae_request_free((radcli_dae_request *)dae->radsec_queue[0]);
		for (i = 1; i < dae->radsec_queue_len; i++)
			dae->radsec_queue[i - 1] = dae->radsec_queue[i];
		dae->radsec_queue_len--;
	}
	dae->radsec_queue[dae->radsec_queue_len++] = req;
}

/*- Pop and return the oldest queued RadSec request.
 *
 * @param dae the listener whose queue to pop from.
 * @return the oldest queued request, or NULL if the queue is empty.
 -*/
static struct radcli_dae_request_st *radsec_queue_pop(struct radcli_dae_st *dae)
{
	struct radcli_dae_request_st *req;
	unsigned i;

	if (dae->radsec_queue_len == 0)
		return NULL;
	req = dae->radsec_queue[0];
	for (i = 1; i < dae->radsec_queue_len; i++)
		dae->radsec_queue[i - 1] = dae->radsec_queue[i];
	dae->radsec_queue_len--;
	return req;
}

/* Appends one reply to dae->radsec_reply_queue -- REQ-DAE-SEC-013. Caller
 * must hold dae->radsec_lock. If the queue is already at
 * RADCLI_DAE_RADSEC_REPLY_QUEUE_SIZE, the OLDEST queued reply is dropped
 * (and logged) to make room, per that requirement's own text ("dropped
 * rather than buffered without limit"); a reply longer than
 * RADCLI_DAE_RADSEC_REPLY_MAX_LEN is dropped outright rather than queued
 * (RFC 5176 replies are small and fixed-shape -- see that constant's
 * comment -- so this should never actually happen in practice). */
/*- Append one reply to dae->radsec_reply_queue -- see the comment above
 * for the drop policy. Caller must hold dae->radsec_lock.
 *
 * @param dae the listener whose reply queue to append to.
 * @param buf the reply bytes to enqueue.
 * @param len buf's length in bytes.
 -*/
static void radsec_reply_queue_push_locked(struct radcli_dae_st *dae, const uint8_t *buf, size_t len)
{
	unsigned i;

	if (len > RADCLI_DAE_RADSEC_REPLY_MAX_LEN) {
		rc_log(LOG_ERR, "radcli_ctx_dispatch: RadSec reply of %zu bytes exceeds "
		       "the %d-byte queue slot size, dropping", len,
		       RADCLI_DAE_RADSEC_REPLY_MAX_LEN);
		return;
	}
	if (dae->radsec_reply_queue_len == RADCLI_DAE_RADSEC_REPLY_QUEUE_SIZE) {
		rc_log(LOG_WARNING, "radcli_ctx_dispatch: RadSec reply queue full (%u), "
		       "dropping the oldest unsent reply", (unsigned)RADCLI_DAE_RADSEC_REPLY_QUEUE_SIZE);
		for (i = 1; i < dae->radsec_reply_queue_len; i++)
			dae->radsec_reply_queue[i - 1] = dae->radsec_reply_queue[i];
		dae->radsec_reply_queue_len--;
	}
	memcpy(dae->radsec_reply_queue[dae->radsec_reply_queue_len].buf, buf, len);
	dae->radsec_reply_queue[dae->radsec_reply_queue_len].len = len;
	dae->radsec_reply_queue_len++;
}

/* Attempts to send every reply currently queued, in order, stopping at
 * the first one that would still block (a later reply must never
 * overtake an earlier one that has not gone out yet) -- one non-blocking
 * attempt per queued reply per call, never a wait. Caller must hold
 * dae->radsec_lock. A session error (radcli2_priv_tls_dae_send()
 * returning -1) drops the reply it was attempting: the session is being
 * marked for reconnection anyway, and there is nothing more sensible to
 * do with a reply for a connection that no longer exists. */
/*- Attempt one non-blocking send per queued reply, in order, stopping at
 * the first one that would still block -- see the comment above. Caller
 * must hold dae->radsec_lock.
 *
 * @param dae the listener whose reply queue to flush.
 -*/
static void radsec_flush_reply_queue_locked(struct radcli_dae_st *dae)
{
	while (dae->radsec_reply_queue_len > 0) {
		struct radcli_dae_pending_reply *p = &dae->radsec_reply_queue[0];
		int ret = radcli2_priv_tls_dae_send(dae->rh, p->buf, p->len);
		unsigned i;

		if (ret == 0)
			break; /* still would block -- try again on a later call */
		for (i = 1; i < dae->radsec_reply_queue_len; i++)
			dae->radsec_reply_queue[i - 1] = dae->radsec_reply_queue[i];
		dae->radsec_reply_queue_len--;
	}
}

/*- Lock, flush, and unlock dae's RadSec reply queue; see
 * radsec_flush_reply_queue_locked().
 *
 * @param dae the listener whose reply queue to flush.
 -*/
static void radsec_flush_reply_queue(struct radcli_dae_st *dae)
{
	pthread_mutex_lock(&dae->radsec_lock);
	radsec_flush_reply_queue_locked(dae);
	pthread_mutex_unlock(&dae->radsec_lock);
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
/*- Parse one "address_or_hostname[:secret]" dae-server entry -- see the
 * comment above for the bracket-notation/prefix-rejection details.
 *
 * @param token the dae-server entry text to parse.
 * @param name set to a malloc()'d copy of the address/hostname.
 * @param secret set to a malloc()'d copy of the secret override, or NULL
 * if token carries none.
 * @return 0 on success, -1 on a malformed token.
 -*/
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
/*- Resolve name (already stripped of any ":secret" suffix) and append one
 * DAC entry per resulting address -- see the comment above.
 *
 * @param dae the listener to append resolved DAC entries to.
 * @param name the hostname/address to resolve.
 * @param secret_override the per-entry secret to record, or NULL to fall
 * back to dae->secret.
 * @return 0 on success, -1 on failure (resolution error, allocation
 * failure, or too many resolved addresses).
 -*/
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

/*- Parse dae-listen ("[host]:port", "host:port", ":port", or an
 * empty/NULL spec for the default).
 *
 * @param spec the dae-listen text to parse.
 * @param host set to a malloc()'d host string, or NULL for "any address";
 * caller frees.
 * @param port set to the parsed port.
 * @return 0 on success, -1 on a malformed spec.
 -*/
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

/** @brief Validate dae-* configuration and build a dynamic-authorization
 *  listener. Opens no socket -- see radcli_dae_start().
 *
 * Fails (returns NULL) unless dae-accept is "yes" or "udp", so that a
 * library upgrade never silently exposes a session-terminating channel in
 * an application that did not opt in. When enabled, also fails unless both
 * dae-server and dae-secret are set, and unless every dae-server entry
 * resolves and carries no network prefix.
 *
 * At most one radcli_dae may be active on a given ctx at a time, since
 * radcli_ctx_get_poll()/radcli_ctx_dispatch() operate on ctx and need a
 * single descriptor to report.
 *
 * @param ctx a configured context (rc_read_config()/rc_apply_config()
 *  already called).
 * @param flags a bitwise OR of #radcli_dae_flags, or 0 for the common case.
 * @return a new listener, or NULL on invalid configuration or an unknown
 *  flags bit.
 */
radcli_dae *radcli_dae_new(radcli_ctx *ctx, unsigned flags)
{
	rc_handle *rh = (rc_handle *)ctx;
	struct radcli_dae_st *dae = NULL;
	const char *accept_str, *secret, *server_str, *require_ma_str, *listen_str;
	char *server_dup = NULL, *saveptr, *tok;
	int force_udp, radsec_mode;

	if (rh == NULL)
		return NULL;

	if (flags & ~(unsigned)RADCLI_DAE_NO_NAS_CHECK)
		return NULL;

	accept_str = rc_conf_str_id(rh, OPT_DAE_ACCEPT);
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

	/* dae-accept=yes means "follow serv-type": under TLS/DTLS, CoA/
	 * Disconnect flow over the already-established RadSec session
	 * (RFC 6614 SS2.1/SS2.5, RFC 7360 SS3.1: one port, one connection,
	 * every packet type) instead of a separate RFC 5176/UDP listener.
	 * dae-accept=udp always forces the RFC 5176/UDP listener regardless
	 * of serv-type -- kept as a fully supported, documented option (not
	 * a deprecated fallback): the shared-connection RadSec path above is
	 * new and, unlike the UDP listener, not yet validated against
	 * real-world DACs. */
	radsec_mode = (!force_udp && (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS));

	if (rh->active_dae != NULL) {
		rc_log(LOG_ERR, "radcli_dae_new: a radcli_dae is already active on this context");
		return NULL;
	}

	if (radsec_mode) {
		/* REQ-DAE-INIT-007: under RadSec there is no dae-server source
		 * ACL -- the TLS/DTLS peer's verified identity is the sole
		 * authorization for who may send a CoA/Disconnect-Request, so
		 * construction must refuse if that verification is disabled. */
		const char *verify_str = rc_conf_str_id(rh, OPT_TLS_VERIFY_HOSTNAME);

		if (verify_str != NULL &&
		    (strcasecmp(verify_str, "false") == 0 || strcasecmp(verify_str, "no") == 0)) {
			rc_log(LOG_ERR, "radcli_dae_new: dae-accept=yes under serv-type "
			       "tls/dtls needs tls-verify-hostname enabled: RadSec's "
			       "verified peer identity is what authorizes a "
			       "CoA/Disconnect-Request sender, replacing dae-server");
			return NULL;
		}

		/* REQ-DAE-INIT-008: inapplicable under RadSec (the secret is the
		 * RFC 6614/7360 fixed string, the authorized sender is the TLS
		 * peer, and there is no dae-owned listener to bind) -- warn, but
		 * do not fail, so switching serv-type to tls/dtls is a config
		 * change an operator can make incrementally. */
		{
			static const struct {
				rc_option_id id;
				const char *name;
			} inapplicable[] = {
				{ OPT_DAE_LISTEN, "dae-listen" },
				{ OPT_DAE_SERVER, "dae-server" },
				{ OPT_DAE_SECRET, "dae-secret" },
				{ OPT_DAE_REQUIRE_MESSAGE_AUTHENTICATOR, "dae-require-message-authenticator" }
			};
			unsigned i;

			for (i = 0; i < sizeof(inapplicable) / sizeof(inapplicable[0]); i++) {
				const char *v = rc_conf_str_id(rh, inapplicable[i].id);

				if (v != NULL && v[0] != '\0')
					rc_log(LOG_WARNING, "radcli_dae_new: %s is set but has no "
					       "effect under serv-type tls/dtls (RadSec replaces "
					       "it)", inapplicable[i].name);
			}
		}

		dae = calloc(1, sizeof(*dae));
		if (dae == NULL)
			return NULL;
		dae->rh = rh;
		dae->fd = -1;
		dae->radsec = 1;
		dae->no_nas_check = (flags & RADCLI_DAE_NO_NAS_CHECK) != 0;
		if (pthread_mutex_init(&dae->radsec_lock, NULL) != 0) {
			free(dae);
			return NULL;
		}

		/* REQ-DAE-INIT-005: still needed under RadSec -- Event-Timestamp
		 * freshness and duplicate suppression are replay protections
		 * independent of the transport's source-authorization model. */
		dae->slots = calloc(RADCLI_DAE_SLOTS, sizeof(*dae->slots));
		if (dae->slots == NULL)
			goto fail;

		dae->max_clock_skew = rc_conf_int_id(rh, OPT_DAE_MAX_CLOCK_SKEW);
		if (dae->max_clock_skew < 0) {
			rc_log(LOG_ERR, "radcli_dae_new: dae-max-clock-skew must not be negative");
			goto fail;
		}

		rh->active_dae = dae;
		return (radcli_dae *)dae;
	}

	secret = rc_conf_str_id(rh, OPT_DAE_SECRET);
	server_str = rc_conf_str_id(rh, OPT_DAE_SERVER);
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
	dae->no_nas_check = (flags & RADCLI_DAE_NO_NAS_CHECK) != 0;

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

	/* REQ-DAE-INIT-005: allocated once, here, at construction -- never
	 * grown, evicted, or resized at run time. Shared across every
	 * configured dae-server entry (RADCLI_DAE_SLOTS's comment explains
	 * why partitioning per entry is the wrong design). */
	dae->slots = calloc(RADCLI_DAE_SLOTS, sizeof(*dae->slots));
	if (dae->slots == NULL)
		goto fail;

	dae->max_clock_skew = rc_conf_int_id(rh, OPT_DAE_MAX_CLOCK_SKEW);
	if (dae->max_clock_skew < 0) {
		rc_log(LOG_ERR, "radcli_dae_new: dae-max-clock-skew must not be negative");
		goto fail;
	}

	require_ma_str = rc_conf_str_id(rh, OPT_DAE_REQUIRE_MESSAGE_AUTHENTICATOR);
	dae->require_message_authenticator =
		(require_ma_str != NULL && strcasecmp(require_ma_str, "yes") == 0);

	listen_str = rc_conf_str_id(rh, OPT_DAE_LISTEN);
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

/** @brief Register the callback radcli_ctx_dispatch() invokes for each
 *  validated request. May be called before or after radcli_dae_start().
 * @param dae a listener from radcli_dae_new().
 * @param cb the callback; NULL clears a previously registered one.
 * @param user passed back to cb unchanged.
 */
void radcli_dae_set_handler(radcli_dae *dae, radcli_dae_handler cb, void *user)
{

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
/*- Set O_NONBLOCK and FD_CLOEXEC on fd -- see the comment above for why.
 * Shared with lib/sendserver.c's persistent UDP request socket
 * (REQ-NET2-SEND-016), which needs the identical non-blocking-drain
 * property for the same reason (radcli2_priv_reqreg_drain() loops
 * recvfrom() until EAGAIN; a blocking socket would hang the caller's
 * whole event loop on the last, empty call instead).
 *
 * @param fd the descriptor to modify.
 * @return 0 on success, -1 on failure.
 -*/
int radcli2_priv_set_nonblock_cloexec(int fd)
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

/** @brief Start receiving: binds the socket described by dae-listen.
 * @param dae a listener from radcli_dae_new().
 * @return 0 on success, -1 on failure (e.g. the address is already in use).
 */
int radcli_dae_start(radcli_dae *dae)
{
	struct addrinfo hints, *res, *rp;
	int err, fd = -1;
	char portstr[8];
	char addr_txt[NI_MAXHOST] = "?";

	if (dae == NULL)
		return -1;
	if (dae->started) {
		rc_log(LOG_ERR, "radcli_dae_start: already started");
		return -1;
	}

	if (dae->radsec) {
		/* No dae-owned socket to bind: force rh's own TLS/DTLS handshake
		 * now rather than waiting for the first ordinary rc_auth()/
		 * rc_acct() call, so enabling DAE makes the NAS reachable
		 * immediately -- matching the UDP listener's own immediate
		 * bind() below. */
		if (radcli2_priv_tls_ensure_connected(dae->rh) != 0) {
			rc_log(LOG_ERR, "radcli_dae_start: could not establish the "
			       "RadSec (TLS/DTLS) session");
			return -1;
		}
		dae->started = 1;
		return 0;
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
		if (radcli2_priv_set_nonblock_cloexec(fd) != 0) {
			close(fd);
			fd = -1;
			continue;
		}
		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
			getnameinfo(rp->ai_addr, rp->ai_addrlen, addr_txt, sizeof(addr_txt),
				   NULL, 0, NI_NUMERICHOST);
			break;
		}
		close(fd);
		fd = -1;
	}
	freeaddrinfo(res);

	if (fd == -1) {
		rc_log(LOG_ERR, "radcli_dae_start: bind: %s", strerror(errno));
		return -1;
	}

	/* Diagnostic only: with dae-listen unset, getaddrinfo(AI_PASSIVE)'s
	 * candidate order decides which single address family gets bound
	 * (radcli_dae_start() binds exactly one socket, matching
	 * radcli_ctx_get_poll()'s one-descriptor contract), which is easy to
	 * mistake for "the listener isn't receiving anything" if left silent. */
	rc_log(LOG_INFO, "radcli_dae_start: listening on %s port %d", addr_txt, dae->listen_port);

	dae->fd = fd;
	dae->started = 1;
	return 0;
}

/** @brief Release a listener, closing its socket if radcli_dae_start()
 *  opened one.
 * @param dae a listener from radcli_dae_new(); NULL is accepted and ignored.
 */
void radcli_dae_free(radcli_dae *dae)
{
	unsigned i;

	if (dae == NULL)
		return;
	if (dae->rh != NULL && dae->rh->active_dae == dae)
		dae->rh->active_dae = NULL;
	/* Under RadSec, dae->fd is always -1: the TLS/DTLS session belongs to
	 * ordinary request handling (rc_init_tls()/lib/tls.c) and outlives
	 * this radcli_dae -- there is nothing dae-owned to close here. */
	if (dae->fd != -1)
		close(dae->fd);
	if (dae->radsec) {
		/* No other thread may still be calling radcli_ctx_dispatch()/
		 * relying on this dae once radcli_dae_free() is called (the
		 * caller's responsibility, same as freeing any other object
		 * concurrently in use) -- the lock here is just to pair cleanly
		 * with pthread_mutex_destroy(), not to defend against a
		 * concurrent user past this point. */
		pthread_mutex_lock(&dae->radsec_lock);
		for (i = 0; i < dae->radsec_queue_len; i++)
			radcli_dae_request_free((radcli_dae_request *)dae->radsec_queue[i]);
		dae->radsec_queue_len = 0;
		pthread_mutex_unlock(&dae->radsec_lock);
		pthread_mutex_destroy(&dae->radsec_lock);
	} else {
		for (i = 0; i < dae->radsec_queue_len; i++)
			radcli_dae_request_free((radcli_dae_request *)dae->radsec_queue[i]);
	}
	free_dacs(dae->dacs, dae->n_dacs);
	free(dae->slots);
	free(dae->secret);
	free(dae->listen_host);
	free(dae);
}

/* Milliseconds until watchdog-interval elapses for an established RadSec
 * ctx (REQ-WATCHDOG-NET-002), or -1 if disabled/not applicable. Shared by
 * radcli_ctx_get_poll() (below) and radcli_ctx_dispatch() (the actual due
 * check that triggers radcli2_priv_dae_send_watchdog()), so the two agree
 * on exactly the same deadline. */
static int watchdog_deadline_ms(rc_handle *rh, int fd)
{
	int interval;

	if (fd == -1)
		/* An unestablished session (radcli2_priv_tls_last_msg() reports
		 * 0) must not be reported as an overdue watchdog, which would
		 * otherwise busy-loop a caller not yet polling this fd. */
		return -1;

	interval = rc_conf_int_id(rh, OPT_WATCHDOG_INTERVAL);
	if (interval > 0) {
		time_t last = radcli2_priv_tls_last_msg(rh);
		long elapsed_ms = (long)(time(0) - last) * 1000L;
		long remaining_ms = (long)interval * 1000L - elapsed_ms;

		return (remaining_ms > 0) ? (int)remaining_ms : 0;
	}
	return -1;
}

/* Folds a new candidate deadline into *timeout_ms (the running minimum;
 * negative candidates -- "no timeout needed" -- are ignored). */
static void fold_timeout(int *timeout_ms, int candidate)
{
	if (candidate < 0)
		return;
	if (*timeout_ms < 0 || candidate < *timeout_ms)
		*timeout_ms = candidate;
}

/** @brief Report what to wait for on ctx's behalf, for the caller's own
 *  event loop -- radcli never calls poll()/select()/epoll_wait() itself.
 *
 * There is no per-object descriptor accessor (e.g. no radcli_dae_fd(), no
 * per-radcli_request one either -- net2.md's REQ-NET2-SEND-013): every
 * descriptor this reports belongs to ctx, not to any one radcli_dae or
 * radcli_request, so that a transport sharing one descriptor between
 * dynamic authorization and ordinary requests (already true for TLS/DTLS)
 * never leaves an application holding a watcher on a descriptor that has
 * quietly started meaning something else.
 *
 * For TLS/DTLS, or for a UDP ctx with no active radcli_dae, this is always
 * exactly one descriptor: the session fd (TLS/DTLS, also carrying any
 * in-flight RADCLI_REQUEST_SENDONLY traffic) or the request-registry socket
 * (UDP, REQ-NET2-SEND-016). A UDP ctx with an active radcli_dae reports a
 * second, independent descriptor for the DAE listener alongside it -- the
 * two are genuinely different local sockets/ports and cannot be merged into
 * one without changing the wire protocol; RADCLI_CTX_MAX_POLLFDS (2) is the
 * maximum this API ever needs. *timeout_ms folds together every deadline
 * source that applies (DAE queued-work, RadSec watchdog, and any in-flight
 * RADCLI_REQUEST_SENDONLY exchange's own retransmit/timeout) into one
 * caller-facing value, so the caller never computes a min() itself.
 *
 * A descriptor is closed or replaced only during a call the application
 * itself makes (radcli_ctx_dispatch(), radcli_dae_free(),
 * radcli_request_perform(), rc_destroy()), never asynchronously -- but
 * re-query after any of those regardless, since one may replace it.
 *
 * @param ctx a context, with or without an active radcli_dae.
 * @param[out] pfds filled with up to RADCLI_CTX_MAX_POLLFDS entries
 *  (fd/events; revents is left for the caller's poll() to fill in).
 * @param max_pfds pfds's capacity; MUST be at least RADCLI_CTX_MAX_POLLFDS.
 * @param[out] nfds set to how many of pfds were filled in (0 if there is
 *  nothing to watch yet).
 * @param[out] timeout_ms milliseconds after which to call
 *  radcli_ctx_dispatch() even without I/O readiness; -1 for "no timeout
 *  needed".
 * @return 0 on success, -1 if ctx or an out-parameter is NULL, or max_pfds
 *  is too small.
 */
int radcli_ctx_get_poll(radcli_ctx *ctx, struct pollfd *pfds, size_t max_pfds,
			size_t *nfds, int *timeout_ms)
{
	rc_handle *rh = (rc_handle *)ctx;
	size_t n = 0;

	if (rh == NULL || pfds == NULL || nfds == NULL || timeout_ms == NULL)
		return -1;
	if (max_pfds < RADCLI_CTX_MAX_POLLFDS)
		return -1;

	*timeout_ms = -1;

	if (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS) {
		/* Reported for any established RadSec radcli_ctx, whether or not
		 * dynamic authorization is active on it: the watchdog machinery
		 * below (REQ-WATCHDOG-NET-001/002) is a property of the TLS/DTLS
		 * session itself (keeping a NAT/firewall mapping alive, or just
		 * avoiding a rehandshake after an idle period), not of DAE -- an
		 * application using radcli purely as an ordinary rc_auth()/
		 * rc_acct() RadSec client, with no radcli_dae at all, is as
		 * entitled to it as one with dae-accept=yes. The DAE-specific
		 * reply-queue bits just below are the only part still gated on
		 * an active radcli_dae. */
		int dae_radsec = (rh->active_dae != NULL && rh->active_dae->radsec);
		int fd = radcli2_priv_tls_fd(rh);
		unsigned events = (fd != -1) ? POLLIN : 0;

		/* REQ-DAE-SEC-013: a reply send_reply() deferred (radsec_reply_
		 * queue non-empty) needs POLLOUT too, or a poll()-driven
		 * application waiting only on POLLIN (the common case) may
		 * never learn the socket became writable again and call
		 * dispatch() to flush it. DAE-only. */
		if (dae_radsec && fd != -1 && rh->active_dae->radsec_reply_queue_len > 0)
			events |= POLLOUT;

		if (fd != -1) {
			pfds[n].fd = fd;
			pfds[n].events = (short)events;
			pfds[n].revents = 0;
			n++;
		}

		/* A record already pulled off the wire by an in-flight ordinary
		 * request (tls_recvfrom()'s inline demux) may be sitting queued
		 * with no further fd activity to prompt a redispatch -- ask the
		 * caller back promptly rather than only on the next POLLIN. Read
		 * without dae->radsec_lock deliberately: this is an advisory
		 * hint only (worst case a stale read costs one extra dispatch()
		 * call that finds nothing, never a correctness issue), and
		 * radcli_ctx_get_poll() is documented to be callable from any
		 * thread cheaply and often. DAE-only, same reason as above. */
		if (dae_radsec && (rh->active_dae->radsec_queue_len > 0 ||
				   rh->active_dae->radsec_reply_queue_len > 0))
			*timeout_ms = 0;
		else
			fold_timeout(timeout_ms, watchdog_deadline_ms(rh, fd));

		fold_timeout(timeout_ms, radcli2_priv_reqreg_earliest_deadline_ms(rh));

		*nfds = n;
		return 0;
	}

	/* UDP: the DAE listener (if active) and the shared request-registry
	 * socket (if any RADCLI_REQUEST_SENDONLY exchange has ever used one)
	 * are genuinely different local sockets -- report both when present. */
	if (rh->active_dae != NULL && rh->active_dae->fd != -1) {
		pfds[n].fd = rh->active_dae->fd;
		pfds[n].events = POLLIN;
		pfds[n].revents = 0;
		n++;
	}
	if (rh->req_fd != -1) {
		pfds[n].fd = rh->req_fd;
		pfds[n].events = POLLIN;
		pfds[n].revents = 0;
		n++;
	}

	/* No DAE-proactive timer needed: the duplicate-suppression table
	 * expires slots lazily, on next access, rather than on a schedule --
	 * radcli owns no timer (REQ-GEN-SEC-003). Only an in-flight
	 * RADCLI_REQUEST_SENDONLY exchange contributes a deadline on UDP. */
	fold_timeout(timeout_ms, radcli2_priv_reqreg_earliest_deadline_ms(rh));

	*nfds = n;
	return 0;
}

/** @brief Send an RFC 5997 Status-Server watchdog on rh's established
 * RadSec session -- internal, no longer a public entry point.
 *
 * One non-blocking attempt to send a Status-Server (Code 12), built exactly
 * like any other outbound request (lib/request.c's radcli_encode_request():
 * CSPRNG-drawn Identifier and Request Authenticator, Message-Authenticator
 * per RFC 2869 SS5.14) but with no attributes, over rh's TLS/DTLS session,
 * using the RFC 6614 SS2.3/RFC 7360 SS3.2 fixed RadSec secret -- the same
 * one REQ-DAE-SEC-015's RadSec DAE path already trusts. Unlike a DAE reply
 * (REQ-DAE-SEC-013), a dropped watchdog is never queued or retried: it is
 * harmless (the next call once due, per watchdog-interval and
 * radcli_ctx_get_poll()'s advisory timeout_ms, covers it), so this makes
 * exactly one attempt and returns.
 *
 * Any reply the peer sends back is not correlated to this call -- radcli
 * owns no request/reply matching state for it. It is silently absorbed by
 * radcli_ctx_dispatch()'s own "unexpected packet code on the RadSec session
 * while idle" handling, the same path any other unsolicited packet on an
 * idle RadSec session already takes.
 *
 * Before building/sending, this also checks for a peer that has gone silent
 * while the connection itself is still technically open -- RFC 3539 SS3.4's
 * watchdog algorithm exists precisely to catch that, not just an outright
 * socket error (which the transport already reconnects from on its own,
 * need_restart). If watchdog-interval is enabled and no record has actually
 * been *received* (radcli2_priv_tls_last_recv(), never advanced by a send,
 * unlike the last-activity clock REQ-WATCHDOG-NET-002's deadline uses) for 2.5x
 * that interval, the session is presumed dead and forcibly reconnected
 * (REQ-WATCHDOG-NET-003) before the watchdog is sent on the fresh connection --
 * still radcli-owns-no-timer (REQ-GEN-SEC-003): this only runs lazily,
 * inside this call, which happens only inside a call the application itself
 * makes (below).
 *
 * draft-ietf-radext-reverse-coa (SS4.2) is what actually calls for this: a
 * client SHOULD keep sending watchdogs on an otherwise-idle RadSec
 * connection so a NAT/firewall does not reap its state, which would
 * otherwise leave a server unable to reach it to send a CoA/Disconnect-
 * Request back down (REQ-DAE-INIT-010's reverse-path model). radcli itself
 * still owns no timer (REQ-GEN-SEC-003): this has exactly two call sites,
 * both gated on the application's own schedule, never a radcli-owned
 * thread/signal -- radcli_ctx_dispatch() below, which calls this once
 * watchdog_deadline_ms() says it is due (REQ-WATCHDOG-NET-001), and
 * lib/tls.c's radcli2_priv_check_tls() (rc_check_tls()'s legacy-API
 * implementation), which calls it directly since a UDP/legacy-only caller
 * may never call radcli_ctx_dispatch() at all.
 *
 * Placed alongside radcli_ctx_get_poll()/radcli_ctx_dispatch() (ctx-level,
 * not dae-level) for the same reason REQ-NET2-NET-001 already gives for
 * those two: the RadSec session belongs to radcli_ctx, not to any one
 * radcli_dae, and this works on any established RadSec session regardless
 * of whether dynamic authorization is even enabled over it.
 *
 * @param ctx a context with an established TLS/DTLS session
 *  (radcli_dae_start() or an ordinary rc_auth()/rc_acct() call already
 *  connected it).
 * @return the number of bytes sent on success, 0 if the send would block
 *  (nothing sent -- call again later), -1 if ctx's transport is not
 *  TLS/DTLS, the session is not yet established (including a forced
 *  reconnect above that failed), or encoding/sending otherwise failed.
 */
int radcli2_priv_dae_send_watchdog(radcli_ctx *ctx)
{
	rc_handle *rh = (rc_handle *)ctx;
	uint8_t send_buffer[RC_BUFFER_LEN];
	unsigned char vector[AUTH_VECTOR_LEN];
	char secret[MAX_SECRET_LENGTH + 1];
	radcli_avp_list *empty;
	int total_length;
	int ret;

	if (rh == NULL)
		return -1;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return -1;

	if (radcli2_priv_tls_fd(rh) == -1)
		return -1; /* not established -- see radcli2_priv_tls_ensure_connected() */

	{
		int interval = rc_conf_int_id(rh, OPT_WATCHDOG_INTERVAL);

		if (interval > 0 &&
		    (double)(time(0) - radcli2_priv_tls_last_recv(rh)) >= interval * 2.5) {
			rc_log(LOG_WARNING, "radcli2_priv_dae_send_watchdog: no record received in "
					    "%.1fx watchdog-interval -- presuming the peer dead "
					    "and reconnecting", 2.5);
			if (radcli2_priv_tls_force_reconnect(rh) < 0)
				return -1;
		}
	}

	if (radcli2_priv_tls_fd(rh) == -1)
		return -1; /* the forced reconnect above left no usable session */

	if (rh->so.static_secret == NULL)
		return -1;
	strlcpy(secret, rh->so.static_secret, sizeof(secret));

	/* radcli_avp_encode() (via radcli_encode_request()) rejects a NULL
	 * list outright -- RFC 5997 Status-Server needs no attributes but
	 * Message-Authenticator, but "no attributes" still means an empty
	 * list, not a NULL one. */
	empty = radcli_avp_list_new();
	if (empty == NULL)
		return -1;

	/* Own established RadSec session, correlated to no other in-flight
	 * exchange (REQ-WATCHDOG-NET-001 never queues/retries this) -- a
	 * CSPRNG draw is sufficient (REQ-NET2-SEND-010). */
	ret = radcli_encode_request(rh, PW_STATUS_SERVER, empty, secret,
				    send_buffer, rc_get_random_byte(), vector, &total_length);
	radcli_avp_list_free(empty);
	if (ret < 0)
		return -1;

	return radcli2_priv_tls_dae_send(rh, send_buffer, (size_t)total_length);
}

/* If sa is an IPv4-mapped IPv6 address ("::ffff:a.b.c.d"), extracts the
 * mapped IPv4 address into *out and returns 1; otherwise returns 0. A
 * dual-stack AF_INET6 listening socket (the default unless the platform
 * sets IPV6_V6ONLY) delivers an IPv4 sender's packet this way, with
 * from->sa_family == AF_INET6 -- see find_dac()'s use of this. */
/*- Extract an IPv4-mapped IPv6 address's IPv4 part -- see the comment
 * above.
 *
 * @param sa the address to check.
 * @param out set to the mapped IPv4 address, if sa is one.
 * @return 1 if sa is an IPv4-mapped IPv6 address (out set), 0 otherwise.
 -*/
static int get_v4_mapped(const struct sockaddr *sa, struct in_addr *out)
{
	const struct sockaddr_in6 *sin6;

	if (sa->sa_family != AF_INET6)
		return 0;
	sin6 = (const struct sockaddr_in6 *)sa;
	if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
		return 0;
	memcpy(out, &sin6->sin6_addr.s6_addr[12], sizeof(*out));
	return 1;
}

/* Finds the configured DAC matching from's address (port ignored: the
 * DAC's source port varies per request, only the address is part of its
 * identity -- REQ-DAE-SEC-001). Returns NULL if from is not authorized. */
/*- Find the configured DAC matching from's address -- see the comment
 * above.
 *
 * @param dae the listener whose DAC list to search.
 * @param from the sender's address to match.
 * @return the matching DAC, or NULL if from is not authorized.
 -*/
static struct radcli_dae_dac *find_dac(struct radcli_dae_st *dae,
					const struct sockaddr *from)
{
	unsigned i;
	struct in_addr mapped;
	int have_mapped = get_v4_mapped(from, &mapped);

	for (i = 0; i < dae->n_dacs; i++) {
		const struct sockaddr *caddr = (const struct sockaddr *)&dae->dacs[i].addr;

		if (caddr->sa_family == from->sa_family) {
			if (memcmp(SA_GET_INADDR(caddr), SA_GET_INADDR(from), SA_GET_INLEN(from)) == 0)
				return &dae->dacs[i];
			continue;
		}
		/* from is AF_INET6 but mapped from an IPv4 sender: also try
		 * it against an AF_INET dae-server entry, or every packet
		 * from an authorized IPv4 DAC is silently unreachable on a
		 * dual-stack listener. */
		if (have_mapped && caddr->sa_family == AF_INET &&
		    memcmp(&((const struct sockaddr_in *)caddr)->sin_addr, &mapped,
			  sizeof(mapped)) == 0)
			return &dae->dacs[i];
	}
	return NULL;
}

/* Returns a malloc()'d, NUL-terminated copy of attrs' first name attribute's
 * value, or NULL if the dictionary lacks name, attrs carries none, or
 * allocation failed. Used to populate radcli_dae_request_st's
 * session_id/user_name fields once, at receive time, since
 * radcli_avp_get_bytes() returns unterminated wire bytes and
 * radcli_dae_req_session_id()/_user_name() must return a C string. */
/*- Return a malloc()'d, NUL-terminated copy of attrs' first attrid
 * attribute's value -- see the comment above for why this exists.
 *
 * @param rh a handle to parsed configuration.
 * @param attrs the attribute list to search.
 * @param attrid the attribute ID to look up and copy.
 * @return the copied string, or NULL if the dictionary lacks attrid,
 * attrs carries none, or allocation failed.
 -*/
static char *dup_avp_str(rc_handle *rh, const radcli_avp_list *attrs, uint32_t attrid)
{
	const radcli_attr_def *d = radcli_dict_lookup_num(rh, attrid, 0);
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
/*- Verify buf[0..length)'s Request Authenticator -- see the comment above.
 *
 * @param buf the received packet; temporarily modified and restored.
 * Must be at least length + strlen(secret) bytes writable.
 * @param length buf's length in bytes.
 * @param secret the shared secret.
 * @return 0 if the authenticator is valid, -1 otherwise.
 -*/
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

/* Encodes reply_code (already the concrete 41/42/44/45 code) with
 * error_cause as attribute 101 when non-zero, mirroring every Proxy-State
 * from the request, Message-Authenticator, and a Response Authenticator
 * computed over req's own Request Authenticator (RFC 5176 SS2.3,
 * REQ-DAE-SEC-008). Shared by send_reply() (which then sends the bytes
 * over req->dae->fd) and radcli_dae_reply_to_buffer() (which hands them
 * to the caller instead). */
/*- Build req's reply into out_buf.
 *
 * @param req the request to reply to.
 * @param reply_code the concrete RADIUS reply code to send.
 * @param error_cause a radcli_error_cause value to encode as attribute
 * 101, or 0 for none.
 * @param out_buf destination buffer for the encoded reply.
 * @param out_cap out_buf's capacity in bytes.
 * @param out_len set to the reply's encoded length on success.
 * @return 0 on success, -1 on failure (e.g. out_cap too small).
 -*/
static int build_reply(struct radcli_dae_request_st *req, uint8_t reply_code, uint32_t error_cause,
		       uint8_t *out_buf, size_t out_cap, int *out_len)
{
	rc_handle *rh = req->dae->rh;
	AUTH_HDR *auth = (AUTH_HDR *)out_buf;
	radcli_avp_list *reply_attrs;
	const radcli_avp *a;
	const radcli_attr_def *d_proxy_state;
	int encoded_len, total_length;
	size_t secretlen;
	uint8_t digest[AUTH_VECTOR_LEN];

	/* Header, plus room for the Message-Authenticator add_msg_auth_attr()
	 * always appends below, must fit before out_cap - AUTH_HDR_LEN -
	 * (2 + MD5_DIGEST_SIZE) is computed for radcli_avp_encode()'s
	 * buflen just below: with only the old `out_cap < AUTH_HDR_LEN`
	 * guard, an out_cap in [AUTH_HDR_LEN, AUTH_HDR_LEN + 2 +
	 * MD5_DIGEST_SIZE) made that subtraction wrap to a huge size_t
	 * instead of failing cleanly. */
	if (out_cap < (size_t)(AUTH_HDR_LEN + 2 + MD5_DIGEST_SIZE))
		return -1;

	reply_attrs = radcli_avp_list_new();
	if (reply_attrs == NULL)
		return -1;

	if (error_cause != 0) {
		const radcli_attr_def *d_ec = radcli_dict_lookup_num(rh, PW_ERROR_CAUSE, 0);

		if (d_ec != NULL)
			radcli_avp_add_uint32(reply_attrs, d_ec, error_cause);
	}

	d_proxy_state = radcli_dict_lookup_num(rh, PW_PROXY_STATE, 0);
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

	encoded_len = radcli_avp_encode(rh, reply_attrs, req->secret, req->request_authenticator,
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

/*- Build req's reply via build_reply() and send it over req->dae->fd.
 *
 * @param req the request to reply to.
 * @param reply_code the concrete RADIUS reply code to send.
 * @param error_cause a radcli_error_cause value to encode as attribute
 * 101, or 0 for none.
 * @return 0 on success, -1 on failure.
 -*/
static int send_reply(struct radcli_dae_request_st *req, uint8_t reply_code, uint32_t error_cause)
{
	uint8_t send_buffer[RC_BUFFER_LEN];
	int total_length;

	if (build_reply(req, reply_code, error_cause, send_buffer, sizeof(send_buffer),
			&total_length) != 0)
		return -1;

	if (req->dae->radsec) {
		/* No dae-owned socket/peer address under RadSec: the reply goes
		 * back over rh's own established TLS/DTLS session. Unlike an
		 * ordinary request (which may legitimately block up to
		 * radius_timeout waiting for POLLOUT via tls_sendto()), this can
		 * be called from radcli_ctx_dispatch() -- invoked only because
		 * the descriptor was reported readable -- which must never turn
		 * into a multi-second stall of the caller's event loop just
		 * because a reply happens to need one. One non-blocking attempt
		 * (radcli2_priv_tls_dae_send()); if it would block, defer to
		 * REQ-DAE-SEC-013's bounded queue instead of waiting, to be
		 * flushed by a later radcli_ctx_dispatch() call
		 * (radsec_flush_reply_queue()). Order matters: flush whatever is
		 * already queued first, and if anything remains queued after
		 * that, this reply queues behind it too rather than jumping the
		 * line by being attempted directly. */
		struct radcli_dae_st *dae = req->dae;
		int ret;

		pthread_mutex_lock(&dae->radsec_lock);
		radsec_flush_reply_queue_locked(dae);
		if (dae->radsec_reply_queue_len > 0) {
			radsec_reply_queue_push_locked(dae, send_buffer, (size_t)total_length);
			pthread_mutex_unlock(&dae->radsec_lock);
			return 0;
		}
		pthread_mutex_unlock(&dae->radsec_lock);

		ret = radcli2_priv_tls_dae_send(dae->rh, send_buffer, (size_t)total_length);
		if (ret == 0) {
			pthread_mutex_lock(&dae->radsec_lock);
			radsec_reply_queue_push_locked(dae, send_buffer, (size_t)total_length);
			pthread_mutex_unlock(&dae->radsec_lock);
			return 0;
		}
		return (ret > 0) ? 0 : -1;
	}

	if (sendto(req->dae->fd, send_buffer, (size_t)total_length, 0,
		  (struct sockaddr *)&req->from, req->fromlen) != total_length)
		return -1;

	return 0;
}

/** @brief Return the received packet's RADIUS code.
 * @param req a request passed to a radcli_dae_handler.
 * @return RADCLI_DISCONNECT_REQUEST or RADCLI_COA_REQUEST (no other code
 *  ever reaches a handler -- see radcli_ctx_dispatch()'s doc comment), or
 *  0 if req is NULL.
 */
radcli_code radcli_dae_req_code(const radcli_dae_request *req)
{

	if (req == NULL)
		return 0;
	return (radcli_code)req->code;
}

/** @brief Return the request's decoded attributes.
 * @param req a request passed to a radcli_dae_handler.
 * @return the attribute list, owned by req and valid until it is freed;
 *  NULL if req is NULL. Never NULL for a request the handler actually
 *  received: an attribute-free Disconnect-Request/CoA-Request still yields
 *  a valid, empty list.
 */
const radcli_avp_list *radcli_dae_req_attrs(const radcli_dae_request *req)
{

	if (req == NULL)
		return NULL;
	return req->attrs;
}

/** @brief Return the request's Acct-Session-Id, if it carried one.
 * @param req a request passed to a radcli_dae_handler.
 * @return a NUL-terminated string owned by req and valid until it is freed,
 *  or NULL if req is NULL or carried no Acct-Session-Id.
 */
const char *radcli_dae_req_session_id(const radcli_dae_request *req)
{

	if (req == NULL)
		return NULL;
	return req->session_id;
}

/** @brief Return the request's User-Name, if it carried one.
 * @param req a request passed to a radcli_dae_handler.
 * @return a NUL-terminated string owned by req and valid until it is freed,
 *  or NULL if req is NULL or carried no User-Name.
 */
const char *radcli_dae_req_user_name(const radcli_dae_request *req)
{

	if (req == NULL)
		return NULL;
	return req->user_name;
}

/** @brief Return the request's Framed-IP-Address or Framed-IPv6-Address.
 * @param req a request passed to a radcli_dae_handler.
 * @param[out] out filled with an AF_INET or AF_INET6 address on success;
 *  untouched on failure.
 * @return 0 on success, -1 if req or out is NULL, or the request carried
 *  neither attribute.
 */
int radcli_dae_req_framed_ip(const radcli_dae_request *req, struct sockaddr_storage *out)
{
	rc_handle *rh;
	const radcli_attr_def *d;
	const radcli_avp *a;

	if (req == NULL || out == NULL)
		return -1;
	rh = req->dae->rh;

	d = radcli_dict_lookup_num(rh, PW_FRAMED_IP_ADDRESS, 0);
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

	d = radcli_dict_lookup_num(rh, PW_FRAMED_IPV6_ADDRESS, 0);
	a = (d != NULL) ? radcli_avp_get(req->attrs, d, 0) : NULL;
	if (a != NULL) {
		struct in6_addr addr;
		unsigned prefix;

		if (radcli_avp_get_ip6(a, &addr, &prefix) == 0) {
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

/** @brief Return the request's NAS-Port.
 * @param req a request passed to a radcli_dae_handler.
 * @param[out] out filled with the value on success; may be NULL to just
 *  check presence.
 * @return 0 on success, -1 if req is NULL or the request carried no
 *  NAS-Port.
 */
int radcli_dae_req_nas_port(const radcli_dae_request *req, uint32_t *out)
{
	rc_handle *rh;
	const radcli_attr_def *d;
	const radcli_avp *a;

	if (req == NULL)
		return -1;
	rh = req->dae->rh;

	d = radcli_dict_lookup_num(rh, PW_NAS_PORT, 0);
	a = (d != NULL) ? radcli_avp_get(req->attrs, d, 0) : NULL;
	if (a == NULL)
		return -1;
	if (out == NULL)
		return 0;
	return radcli_avp_get_uint32(a, out);
}


/* Records reply_code/error_cause as the decision in req's duplicate-
 * suppression slot, if it still matches req exactly (dedup_key, REQ-DAE-
 * SEC-005) and is still awaiting one -- i.e. transitions it from PENDING to
 * ANSWERED.
 * Shared by reply_and_record() (after an actual send) and
 * radcli_dae_reply_to_buffer() (after producing bytes an L0 caller will send
 * itself): either way, a later retransmission must be answered from this
 * same decision, not a fresh one (REQ-DAE-SEC-005), even if the reply was
 * deferred past the handler's own return. */
/*- Record reply_code/error_cause in req's duplicate-suppression slot --
 * see the comment above.
 *
 * @param req the request whose slot to update.
 * @param reply_code the reply code that was sent.
 * @param error_cause the error cause that was sent, or 0 for none.
 -*/
static void record_reply_decision(struct radcli_dae_request_st *req, uint8_t reply_code,
				  uint32_t error_cause)
{
	struct radcli_dae_slot *slot;

	if (req->dae == NULL)
		return;
	slot = &req->dae->slots[req->id];
	if (slot->valid && slot->pending &&
	    rc_memcmp(slot->dedup_key, req->dedup_key,
		     RC_SHA256_DIGEST_SIZE) == 0) {
		slot->pending = 0;
		slot->reply_code = reply_code;
		slot->error_cause = error_cause;
	}
}

/*- Send req's reply and record the decision for duplicate suppression.
 *
 * @param req the request to reply to; must not already be replied to.
 * @param reply_code the concrete RADIUS reply code to send.
 * @param error_cause a radcli_error_cause value to encode as attribute
 * 101, or 0 for none.
 * @return 0 on success, -1 if req is NULL, already replied to, or the
 * send failed.
 -*/
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

/*- Select the concrete ACK/NAK code (41/42/44/45) for req's own code
 * (40/43) and the application's accept/reject decision (RFC 5176 SS2.1,
 * SS3). Shared by radcli_dae_reply() and radcli_dae_reply_to_buffer().
 *
 * @param req the request being replied to.
 * @param ack nonzero for an ACK, zero for a NAK.
 * @return the concrete reply code.
 -*/
static uint8_t select_reply_code(const struct radcli_dae_request_st *req, int ack)
{
	return ack
		? (req->code == RADCLI_DISCONNECT_REQUEST ? RADCLI_DISCONNECT_ACK : RADCLI_COA_ACK)
		: (req->code == RADCLI_DISCONNECT_REQUEST ? RADCLI_DISCONNECT_NAK : RADCLI_COA_NAK);
}

/** @brief Answer a request with an ACK or NAK, selecting 41/42 or 44/45
 *  from the request's own code, mirroring its Proxy-State attributes, and
 *  computing the Response Authenticator over the request's Authenticator.
 *
 * @param req a request passed to a radcli_dae_handler, not yet replied to.
 * @param ack non-zero for an ACK (Disconnect-ACK/CoA-ACK), zero for a bare
 *  NAK with no Error-Cause attribute -- most callers rejecting a request
 *  should use radcli_dae_reply_error() instead, which also states why.
 * @return 0 once the reply is handed to the network, -1 on failure (req is
 *  NULL, already replied to, or the reply could not be sent).
 */
int radcli_dae_reply(radcli_dae_request *req, int ack)
{

	if (req == NULL)
		return -1;
	return reply_and_record(req, select_reply_code(req, ack), 0);
}

/** @brief Answer a request with a NAK carrying the given Error-Cause.
 * @param req a request passed to a radcli_dae_handler, not yet replied to.
 * @param error_cause a #radcli_error_cause value (e.g.
 *  RADCLI_ERROR_SESSION_CONTEXT_NOT_FOUND), encoded as attribute 101.
 * @return 0 once the reply is handed to the network, -1 on failure (req is
 *  NULL, already replied to, or the reply could not be sent).
 */
int radcli_dae_reply_error(radcli_dae_request *req, uint32_t error_cause)
{
	uint8_t reply_code;

	if (req == NULL)
		return -1;
	reply_code = (req->code == RADCLI_DISCONNECT_REQUEST) ? RADCLI_DISCONNECT_NAK : RADCLI_COA_NAK;
	return reply_and_record(req, reply_code, error_cause);
}

/** @brief Produce a reply as bytes instead of sending it -- the L0
 *  counterpart of radcli_dae_reply()/radcli_dae_reply_error(), for a
 *  request that came from radcli_dae_process().
 *
 * For a request radcli_dae_process() returned #RADCLI_DAE_DUPLICATE for,
 * ack and error_cause are ignored: a genuine retransmission always gets the
 * same answer it originally got (RFC 5176 SS2.3), never a fresh one, so the
 * bytes produced are always that cached decision's.
 *
 * @param req a request from radcli_dae_process(), not yet replied to
 *  (unless #RADCLI_DAE_DUPLICATE, which may be called any number of times).
 * @param ack non-zero for an ACK, zero for a NAK -- ignored if req is a
 *  #RADCLI_DAE_DUPLICATE.
 * @param error_cause a #radcli_error_cause value for a NAK, or 0 for a bare
 *  one -- ignored if req is a #RADCLI_DAE_DUPLICATE.
 * @param[out] buf filled with the reply's bytes on success.
 * @param[in,out] len buf's capacity on entry; the reply's actual length on
 *  success.
 * @return 0 on success, -1 on failure (any argument NULL, req already
 *  replied to and not a #RADCLI_DAE_DUPLICATE, or buf too small).
 */
int radcli_dae_reply_to_buffer(radcli_dae_request *req, int ack, uint32_t error_cause,
			       void *buf, size_t *len)
{
	uint8_t reply_code;
	int out_len;

	if (req == NULL || buf == NULL || len == NULL)
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

	if (build_reply(req, reply_code, error_cause, (uint8_t *)buf, *len, &out_len) != 0)
		return -1;
	*len = (size_t)out_len;

	if (!req->is_cached_duplicate) {
		req->replied = 1;
		record_reply_decision(req, reply_code, error_cause);
	}

	return 0;
}

/** @brief Release a request.
 * @param req a request passed to a radcli_dae_handler, or from
 *  radcli_dae_process(); NULL is accepted and ignored. Replying is optional
 *  before freeing: an unanswered request simply gets no reply.
 */
void radcli_dae_request_free(radcli_dae_request *req)
{

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

/* Runs the full RFC 5176 validation pipeline on one packet (REQ-NET2-NET-002):
 * source-address authorization (REQ-DAE-SEC-001), packet-code and length
 * sanity (REQ-DAE-ERR-001), Request Authenticator (REQ-DAE-SEC-002),
 * Message-Authenticator when present or required (REQ-DAE-SEC-003),
 * Event-Timestamp freshness (REQ-DAE-SEC-004), then duplicate suppression
 * (REQ-DAE-SEC-005/006). buf must have RC_MAX_PACKET_LEN + MAX_SECRET_LENGTH
 * bytes of headroom past len (verify_request_authenticator() writes there);
 * both callers below satisfy this from a stack buffer sized RC_BUFFER_LEN. */
/*- Run the full RFC 5176 validation pipeline on one packet -- see the
 * comment above.
 *
 * @param dae the listener the packet was received on.
 * @param buf the received packet; must have RC_MAX_PACKET_LEN +
 * MAX_SECRET_LENGTH bytes of headroom past len.
 * @param len the received packet's length in bytes.
 * @param from the sender's address.
 * @param fromlen from's length in bytes.
 * @param out_req set on PROCESS_NEW/PROCESS_DUP_ANSWERED; left NULL on
 * PROCESS_DROP.
 * @return the validation outcome.
 -*/
static enum process_result process_packet(struct radcli_dae_st *dae, uint8_t *buf, size_t len,
					   const struct sockaddr *from, socklen_t fromlen,
					   struct radcli_dae_request_st **out_req)
{
	rc_handle *rh = dae->rh;
	size_t length = len;
	struct radcli_dae_dac *dac;
	struct radcli_dae_slot *slot;
	time_t now;
	int retention;
	struct radcli_dae_request_st *req;
	radcli_avp_list *attrs = NULL;
	const radcli_attr_def *d;
	const radcli_avp *a;
	const char *secret;

	*out_req = NULL;

	if (dae->radsec) {
		/* REQ-DAE-SEC-015: "the source is the session" by construction
		 * -- the record necessarily arrived on rh's own TLS/DTLS-
		 * verified connection, so there is no separate source-address
		 * ACL to check the way find_dac() checks one for UDP; the
		 * RFC 6614/7360 fixed secret (rh->so.static_secret, set by
		 * lib/tls.c's rc_init_tls()) replaces dae-secret/dac->secret. */
		dac = NULL;
		secret = rh->so.static_secret;
	} else {
		/* REQ-DAE-SEC-001: discarded before parsing attributes or computing
		 * any MD5/HMAC, and without a reply -- a response would confirm to a
		 * scanner that a listener is present. */
		dac = find_dac(dae, from);
		if (dac == NULL)
			return PROCESS_DROP;
		secret = (dac->secret != NULL) ? dac->secret : dae->secret;
	}

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
		d = radcli_dict_lookup_num(rh, PW_MESSAGE_AUTHENTICATOR, 0);
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
		d = radcli_dict_lookup_num(rh, PW_EVENT_TIMESTAMP, 0);
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
	 * Identifier, shared across every configured dae-server entry. The
	 * match key is an SHA-256 digest process_packet() computes itself
	 * over the verified packet (buf[0..length)), not the wire's 16-byte
	 * MD5 Request Authenticator -- REQ-GEN-SEC-008 is why: that field is
	 * a secret-suffix MD5 MAC, the construction class Blast-RADIUS
	 * (CVE-2024-3596) broke, so basing "same key implies same content" on
	 * it would only be as strong as MD5. The packet is already fully
	 * authenticated by this point (REQ-DAE-SEC-002/003/004 above), so
	 * hashing it again here with a collision-resistant function makes
	 * that assumption actually true, independent of MD5's weakness,
	 * rather than inherited from it -- at the cost of one extra SHA-256
	 * over an already-small packet. A match (see RADCLI_DAE_SLOTS's
	 * comment on why neither source address nor source port is part of
	 * this) is a genuine retransmission -- answered from the cached
	 * decision if one exists, or silently dropped if the original is
	 * still PENDING; anything else (including a first-ever arrival)
	 * claims the slot and produces a new request. */
	now = time(NULL);
	retention = (dae->max_clock_skew > 0) ? dae->max_clock_skew : 30;
	slot = &dae->slots[buf[1]];

	req = calloc(1, sizeof(*req));
	if (req == NULL) {
		radcli_avp_list_free(attrs);
		return PROCESS_DROP;
	}
	req->dae = dae;
	req->dac = dac; /* NULL under RadSec -- see above */
	req->code = buf[0];
	req->id = buf[1];
	memcpy(req->request_authenticator, buf + 4, AUTH_VECTOR_LEN);
	rc_sha256_calc(req->dedup_key, buf, length);
	/* from is NULL exactly when dae->radsec is set (radcli2_priv_dae_on_
	 * radsec_packet() is process_packet()'s only radsec-mode caller, and
	 * always passes NULL/0 -- see above); the explicit from != NULL check
	 * alongside dae->radsec is redundant at runtime but makes that
	 * invariant provable locally instead of relying on a correlation
	 * across call sites the compiler's static analyzer cannot see. */
	if (!dae->radsec && from != NULL) {
		memcpy(&req->from, from, fromlen);
		req->fromlen = fromlen;
	}
	strlcpy(req->secret, secret, sizeof(req->secret));
	req->attrs = attrs;
	attrs = NULL;
	req->session_id = dup_avp_str(rh, req->attrs, PW_ACCT_SESSION_ID);
	req->user_name = dup_avp_str(rh, req->attrs, PW_USER_NAME);

	if (slot->valid && (now - slot->timestamp) <= retention &&
	    rc_memcmp(slot->dedup_key, req->dedup_key,
		     RC_SHA256_DIGEST_SIZE) == 0) {
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

	/* REQ-DAE-SEC-018: NAS-Identifier, if both the request and the
	 * nas-identifier config option carry one, must agree -- RFC 5176 SS3.5
	 * "NAS Identification Mismatch" (Error-Cause 403). Absence of either
	 * is not a mismatch -- there is nothing to check it against.
	 * NAS-IP-Address/NAS-IPv6-Address are deliberately not compared here:
	 * unlike NAS-Identifier, a DAC-observed address for a NAS routinely
	 * differs from what the NAS is itself configured with (NAT, containers,
	 * a proxy/load balancer in front of the NAS), so it is not something
	 * radcli can check on the application's behalf. */
	if (!dae->no_nas_check) {
		const char *cfg_id = rc_conf_str_id(rh, OPT_NAS_IDENTIFIER);

		if (cfg_id != NULL) {
			d = radcli_dict_lookup_num(rh, PW_NAS_IDENTIFIER, 0);
			a = (d != NULL) ? radcli_avp_get(req->attrs, d, 0) : NULL;
			if (a != NULL) {
				const void *val;
				size_t vlen;

				if (radcli_avp_get_bytes(a, &val, &vlen) == 0 &&
				    (vlen != strlen(cfg_id) || memcmp(val, cfg_id, vlen) != 0)) {
					req->cached_reply_code = (req->code == RADCLI_DISCONNECT_REQUEST)
						? RADCLI_DISCONNECT_NAK : RADCLI_COA_NAK;
					req->cached_error_cause = RADCLI_ERROR_NAS_IDENTIFICATION_MISMATCH;
					slot->valid = 1;
					slot->timestamp = now;
					memcpy(slot->dedup_key, req->dedup_key, RC_SHA256_DIGEST_SIZE);
					slot->pending = 0;
					slot->reply_code = req->cached_reply_code;
					slot->error_cause = req->cached_error_cause;
					req->is_cached_duplicate = 1;
					*out_req = req;
					return PROCESS_DUP_ANSWERED;
				}
			}
		}
	}

	slot->valid = 1;
	slot->timestamp = now;
	memcpy(slot->dedup_key, req->dedup_key, RC_SHA256_DIGEST_SIZE);
	slot->pending = 1;

	*out_req = req;
	return PROCESS_NEW;
}

/* Builds and sends a Disconnect-NAK/CoA-NAK with Error-Cause 406
 * ("Unsupported Extension") for reqbuf/reqlen, a CoA-Request or
 * Disconnect-Request that arrived on rh's RadSec session while dynamic
 * authorization is not enabled over it -- REQ-DAE-SEC-016, RFC 6614 SS2.5.
 * There is no radcli_dae_st to build this through (dynamic authorization
 * is off, or in UDP mode): a standalone builder, using rh->so.static_secret
 * directly, matching build_reply()'s wire logic for just this one fixed
 * case (no Proxy-State mirroring -- there is no configured dae to have
 * asked for it). reqbuf need only be long enough to name a Code and
 * Identifier; nothing about it is otherwise trusted or verified before
 * replying, since the reply itself carries no secret worth protecting
 * (the RFC 6614/7360 secret is a fixed, public string). */
/*- Build and send a Disconnect-NAK/CoA-NAK with Error-Cause 406
 * ("Unsupported Extension") for reqbuf/reqlen -- see the comment above.
 *
 * @param rh the handle whose RadSec session the request arrived on.
 * @param reqbuf the request; only its Code and Identifier are read.
 * @param reqlen reqbuf's length in bytes.
 -*/
static void send_radsec_unsupported_nak(rc_handle *rh, const uint8_t *reqbuf, size_t reqlen)
{
	uint8_t out[AUTH_HDR_LEN + 6 + 2 + MD5_DIGEST_SIZE]; /* header + Error-Cause(6) + Message-Authenticator(2+16) */
	AUTH_HDR *auth = (AUTH_HDR *)out;
	radcli_avp_list *reply_attrs;
	const radcli_attr_def *d_ec;
	int encoded_len, total_length;
	size_t secretlen;
	uint8_t digest[AUTH_VECTOR_LEN];
	const char *secret = rh->so.static_secret;

	if (reqlen < AUTH_HDR_LEN || secret == NULL)
		return;

	reply_attrs = radcli_avp_list_new();
	if (reply_attrs == NULL)
		return;

	d_ec = radcli_dict_lookup_num(rh, PW_ERROR_CAUSE, 0);
	if (d_ec != NULL)
		radcli_avp_add_uint32(reply_attrs, d_ec, 406);

	auth->code = (reqbuf[0] == RADCLI_DISCONNECT_REQUEST) ? RADCLI_DISCONNECT_NAK : RADCLI_COA_NAK;
	auth->id = reqbuf[1];
	memcpy(auth->vector, reqbuf + 4, AUTH_VECTOR_LEN);

	encoded_len = radcli_avp_encode(rh, reply_attrs, secret, reqbuf + 4,
						auth->data, sizeof(out) - AUTH_HDR_LEN - (2 + MD5_DIGEST_SIZE), NULL);
	radcli_avp_list_free(reply_attrs);
	if (encoded_len < 0)
		return;

	total_length = AUTH_HDR_LEN + encoded_len;
	auth->length = htons((uint16_t)total_length);
	total_length = add_msg_auth_attr(rh, (char *)secret, auth, total_length);

	secretlen = rc_secret_len(secret);
	if ((size_t)(sizeof(out) - total_length) < secretlen)
		return;
	memcpy(out + total_length, secret, secretlen);
	rc_md5_calc(digest, out, (size_t)total_length + secretlen);
	memcpy(auth->vector, digest, AUTH_VECTOR_LEN);

	/* One non-blocking attempt, matching send_reply()'s own reasoning
	 * (this can run from radcli_ctx_dispatch(), which must never turn
	 * into a multi-second stall) -- but dropped rather than queued if it
	 * would block: there is no radcli_dae_st here to hold a queue on
	 * (dynamic authorization is off, or in UDP mode, which is exactly why
	 * this path was reached at all), and RFC 6614 SS2.5's 406 signal is
	 * best-effort, not a delivery this library owes a guarantee for. */
	radcli2_priv_tls_dae_send(rh, out, (size_t)total_length);
}

/*- Process one RADIUS/TLS or RADIUS/DTLS record already known to carry
 * Code 40 (Disconnect-Request) or 43 (CoA-Request) -- called from lib/
 * tls.c's tls_recvfrom() (inline, mid-exchange) and from this file's own
 * radcli_ctx_dispatch() (via radcli2_priv_tls_dae_poll()). Never invokes a
 * registered radcli_dae_handler directly (that would let it run on
 * whatever thread/call stack happens to be inside rc_auth()/rc_acct() at
 * the time): a validated request is queued for radcli_ctx_dispatch() to
 * deliver, exactly as REQ-DAE-SEC-012's reentrancy guard already assumes.
 * If dynamic authorization is not enabled over RadSec at all (no active
 * radcli_dae, or one in UDP mode), replies with the RFC 6614 SS2.5-
 * mandated CoA-NAK/Disconnect-NAK (Error-Cause 406) instead.
 *
 * @param rh a handle to parsed configuration.
 * @param buf the received packet, header included.
 * @param len buf's length in bytes.
 -*/
void radcli2_priv_dae_on_radsec_packet(rc_handle *rh, const uint8_t *buf, size_t len)
{
	struct radcli_dae_st *dae = rh->active_dae;
	uint8_t local_buf[RC_BUFFER_LEN];
	struct radcli_dae_request_st *req = NULL;

	if (dae == NULL || !dae->radsec) {
		send_radsec_unsupported_nak(rh, buf, len);
		return;
	}

	if (len == 0 || len > sizeof(local_buf) - 1)
		return;

	/* process_packet() mutates the buffer in place (verify_request_
	 * authenticator() zeroes and restores the Authenticator field) --
	 * copy so the caller's (lib/tls.c's) own receive buffer is untouched. */
	memcpy(local_buf, buf, len);

	/* Guards dae->slots[] (process_packet()'s duplicate-suppression
	 * table) and dae->radsec_queue[] against the concurrent caller this
	 * function can have: the thread currently inside an in-flight
	 * radcli_transport_exchange() (tls_recvfrom()'s inline demux, holding
	 * the *session* lock, not this one) and radcli_ctx_dispatch()'s poll
	 * thread (which has already released the session lock by the time it
	 * gets here -- radcli2_priv_tls_dae_poll() only holds it for the read
	 * itself) can otherwise both be inside this function at once. */
	pthread_mutex_lock(&dae->radsec_lock);
	switch (process_packet(dae, local_buf, len, NULL, 0, &req)) {
	case PROCESS_NEW:
		radsec_queue_push(dae, req);
		break;
	case PROCESS_DUP_ANSWERED:
		req->replied = 1; /* answered from the cached decision, not a fresh one */
		send_reply(req, req->cached_reply_code, req->cached_error_cause);
		radcli_dae_request_free((radcli_dae_request *)req);
		break;
	case PROCESS_DROP:
		break;
	}
	pthread_mutex_unlock(&dae->radsec_lock);
}

/** @brief Read what is ready on ctx's descriptor(s), validate it, and
 *  invoke the registered handler for anything that passes -- see
 *  radcli_dae_set_handler(). Also: drains any in-flight
 *  RADCLI_REQUEST_SENDONLY exchange's reply and services its retransmit/
 *  timeout deadline (net2.md's REQ-NET2-SEND-013/016), and, once due, sends
 *  the RFC 5997 watchdog on an established RadSec session
 *  (watchdog.md's REQ-WATCHDOG-NET-001) -- all unconditionally, every call,
 *  regardless of whether an active radcli_dae exists at all: this is now
 *  the single entry point radcli_ctx_get_poll() drives, for everything ctx
 *  owns, not a DAE-only call.
 *
 * On the DAE side specifically, reads exactly one datagram per call
 * (non-blocking), so a burst of requests re-arms the caller's loop rather
 * than starving it, and runs it through process_packet()'s validation
 * pipeline before ever invoking the registered handler. Every rejection
 * short of "authorized sender" is silent: no reply, no Error-Cause, no log
 * of the secret or either authenticator (REQ-DAE-SEC-009).
 *
 * Not reentrant: calling this, radcli_dae_start(), or radcli_dae_free()
 * from within a handler radcli_ctx_dispatch() itself invoked is undefined.
 *
 * @param ctx a context previously reported ready by radcli_ctx_get_poll().
 * @return 0 on success (including "nothing was ready"), -1 on failure
 *  (e.g. ctx is NULL, or called reentrantly).
 */
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

	rh->in_dispatch = 1;

	/* REQ-NET2-SEND-013: unconditional and non-blocking, regardless of
	 * transport or whether any RADCLI_REQUEST_SENDONLY exchange is
	 * actually in flight (both functions no-op on a NULL rh->reqreg). */
	radcli2_priv_reqreg_drain(rh);
	radcli2_priv_reqreg_service_timeouts(rh);

	if (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS) {
		/* REQ-WATCHDOG-NET-001: folded in here rather than left as a
		 * separate caller-invoked call -- still never radcli calling
		 * itself unprompted (REQ-GEN-SEC-003): this only ever runs
		 * inside a radcli_ctx_dispatch() call the application itself
		 * makes, on its own schedule, driven by radcli_ctx_get_poll()'s
		 * advisory timeout_ms (watchdog_deadline_ms(), above it in this
		 * file). */
		if (watchdog_deadline_ms(rh, radcli2_priv_tls_fd(rh)) == 0)
			radcli2_priv_dae_send_watchdog(ctx);
	}

	dae = rh->active_dae;
	if (dae == NULL) {
		rh->in_dispatch = 0;
		return 0;
	}

	if (dae->radsec) {
		/* REQ-DAE-SEC-013: retry any replies send_reply() deferred
		 * earlier before doing anything else -- this call may be here
		 * because radcli_ctx_get_poll() reported POLLOUT specifically
		 * for this, not because there is new data to read at all. One
		 * non-blocking attempt per queued reply; never a wait. */
		radsec_flush_reply_queue(dae);

		/* radcli2_priv_tls_dae_poll() leaves the session lock held on
		 * success (>0) -- radcli2_priv_dae_on_radsec_packet() needs it
		 * held for the whole call (it takes dae->radsec_lock underneath,
		 * and consistently nesting session-lock-outside-radsec_lock on
		 * every call path, including tls_recvfrom()'s own inline demux,
		 * is what avoids a lock-order inversion between the two -- see
		 * lib/tls.c's doc comment on radcli2_priv_tls_dae_poll()). */
		int ret = radcli2_priv_tls_dae_poll(rh, buf, sizeof(buf) - 1);

		if (ret > 0) {
			if (buf[0] == RADCLI_DISCONNECT_REQUEST || buf[0] == RADCLI_COA_REQUEST) {
				radcli2_priv_dae_on_radsec_packet(rh, buf, (size_t)ret);
			} else {
				rc_log(LOG_INFO, "radcli_ctx_dispatch: unexpected packet code "
				       "%u on the RadSec session while idle, ignored",
				       (unsigned)buf[0]);
			}
			radcli2_priv_tls_dae_poll_done(rh);
		}

		/* Drain whatever is queued -- from the poll above, or from an
		 * in-flight radcli_transport_exchange() on another thread that
		 * already demuxed a record via tls_recvfrom()'s inline path.
		 * radsec_lock (not the session lock, already released above)
		 * guards radsec_queue[] here, matching radsec_queue_push()'s own
		 * locking in radcli2_priv_dae_on_radsec_packet(). */
		for (;;) {
			pthread_mutex_lock(&dae->radsec_lock);
			req = radsec_queue_pop(dae);
			pthread_mutex_unlock(&dae->radsec_lock);
			if (req == NULL)
				break;
			if (dae->handler != NULL)
				dae->handler((radcli_dae_request *)req, dae->handler_user);
			else
				radcli_dae_request_free((radcli_dae_request *)req);
		}

		rh->in_dispatch = 0;
		return 0;
	}

	if (dae->fd == -1) {
		/* Constructed but never (successfully) started -- nothing DAE-
		 * specific to do, but the reqreg/watchdog work above may already
		 * have done something useful, so this is not itself a failure. */
		rh->in_dispatch = 0;
		return 0;
	}

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

/** @brief Validate a caller-supplied packet, without a radcli-owned socket
 *  -- the L0 counterpart of radcli_ctx_dispatch(), running the identical
 *  validation pipeline (REQ-DAE-NET-003) on a buffer and source address the
 *  caller supplies instead of reading them from radcli_dae_start()'s
 *  socket. A request this produces is otherwise indistinguishable from one
 *  radcli_ctx_dispatch() would have delivered to a handler.
 *
 * @param dae a listener from radcli_dae_new() (radcli_dae_start() need
 *  never have been called: this function reads no socket). Rejected
 *  outright (-1) if dae is following serv-type=tls/dtls (RadSec): that
 *  transport trusts the record's origin entirely to the already-verified
 *  TLS/DTLS session (REQ-DAE-SEC-015), which this buffer/address pair is
 *  not, and has no source-address check of its own to apply to it.
 * @param buf the received packet, header included.
 * @param len buf's length.
 * @param from the packet's source address, for the dae-server authorization
 *  check.
 * @param fromlen from's length. Must be at least sizeof(struct sockaddr_in)
 *  and at most sizeof(struct sockaddr_storage), and consistent with the
 *  family from->sa_family declares (AF_INET or AF_INET6 only, matching what
 *  dae-server can authorize) -- an application relaying from and fromlen
 *  from an untrusted producer (e.g. over IPC from a privileged listener)
 *  must not assume this function corrects a mismatch; it only rejects one.
 * @param[out] req set to the validated request on success (#RADCLI_DAE_NEW
 *  or #RADCLI_DAE_DUPLICATE), left NULL on failure.
 * @return #RADCLI_DAE_NEW or #RADCLI_DAE_DUPLICATE on success, -1 if the
 *  packet failed validation (discarded silently, exactly as
 *  radcli_ctx_dispatch() would), dae is a RadSec listener, or any argument
 *  is invalid.
 */
int radcli_dae_process(radcli_dae *dae, const void *buf, size_t len,
		       const struct sockaddr *from, socklen_t fromlen,
		       radcli_dae_request **req)
{
	struct radcli_dae_request_st *built_req = NULL;
	uint8_t local_buf[RC_BUFFER_LEN];
	enum process_result result;

	if (dae == NULL || buf == NULL || from == NULL || req == NULL ||
	    len == 0 || len > sizeof(local_buf) - 1)
		return -1;
	*req = NULL;

	/* This L0 entry point has no meaning under RadSec: process_packet()'s
	 * radsec branch trusts the record's origin entirely to rh's own
	 * TLS-verified session (REQ-DAE-SEC-015) and does not check a source
	 * address at all -- accepting an arbitrary caller-supplied buf/from
	 * pair here would let any caller feed it unauthenticated bytes as if
	 * they had arrived on that session, with only the RFC 6614/7360 fixed
	 * (not actually secret) string standing in for authentication. It
	 * would also bypass radsec_lock entirely, racing lib/tls.c's own
	 * calls into the same dae. Reject outright rather than accept a
	 * caller's buffer as a substitute for the real session. */
	if (dae->radsec)
		return -1;

	/* fromlen is caller-supplied, not kernel-supplied (unlike
	 * radcli_ctx_dispatch()'s recvfrom(), which sets it itself): a caller
	 * relaying an address from an untrusted producer -- e.g. over IPC
	 * from a privileged listener, the documented reason this L0 entry
	 * point exists at all -- could pass a fromlen that does not match
	 * from's actual family, or one large enough to overflow
	 * req->from (struct sockaddr_storage) once process_packet() below
	 * does memcpy(&req->from, from, fromlen). Bound it against both the
	 * declared family and struct sockaddr_storage before trusting it. */
	if (fromlen < sizeof(struct sockaddr_in) || fromlen > sizeof(struct sockaddr_storage))
		return -1;
	if (from->sa_family == AF_INET6 && fromlen < sizeof(struct sockaddr_in6))
		return -1;
	if (from->sa_family != AF_INET && from->sa_family != AF_INET6)
		return -1;

	/* process_packet() mutates the buffer in place (verify_request_
	 * authenticator() zeroes and restores the Authenticator field) --
	 * copy so the caller's own buffer is never touched. */
	memcpy(local_buf, buf, len);

	result = process_packet(dae, local_buf, len, from, fromlen, &built_req);
	if (result == PROCESS_DROP)
		return -1;

	*req = (radcli_dae_request *)built_req;
	return (result == PROCESS_DUP_ANSWERED) ? RADCLI_DAE_DUPLICATE : RADCLI_DAE_NEW;
}
