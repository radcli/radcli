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

/** @file request.c
 * @brief radcli2.h's single-server request/reply entry point.
 */

/* radcli2.h's request/reply entry point (radcli_request_new()/_perform()/
 * etc.): builds a wire packet with radcli_avp_encode(), sends it with the
 * same radcli_transport_exchange() rc_send_server_ctx() uses (so failover,
 * retries, Response Authenticator, and Message-Authenticator/Blast-RADIUS
 * verification are exactly the code already proven against rc_send_server_ctx(),
 * not a second copy), and decodes the reply with radcli_avp_decode().
 *
 * Uses only the first configured server for the request's type, by design:
 * the new API carries one
 * server per context, redundancy delegated to DNS/address-level fail-over
 * (already inside radcli_transport_exchange()) rather than a configured
 * list of distinct servers each with its own secret -- that remains
 * rc_auth()/rc_acct()'s job alone. radcli_request_new() logs a warning,
 * not an error, if more than one entry is configured. */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "avp.h"
#include "util.h"
#include "options.h"
#include "rc-crypto.h"
#include "rc-random.h"

struct radcli_request_st {
	rc_handle *rh;
	uint8_t code;
	radcli_avp_list *send;
	char server[AUTH_ID_LEN + 1];
	uint16_t svc_port;
	char secret[MAX_SECRET_LENGTH + 1];
	int timeout;
	int retries;
	rc_type type;

	int performed;
	uint8_t reply_code;
	radcli_avp_list *reply_attrs;

	/* Set by radcli_request_perform(r, RADCLI_REQUEST_SENDONLY); driven to
	 * completion by radcli_ctx_get_poll()/radcli_ctx_dispatch() (lib/dae.c),
	 * read back with radcli_request_done(). See lib/includes.h's struct
	 * radcli_async_send_st. */
	struct radcli_async_send_st async;
};

/** @brief Create a request to send.
 *
 * Reads the destination server, its shared secret, and the timeout/retry
 * counts from ctx's configuration -- the same "authserver"/"acctserver",
 * "radius_timeout", and "radius_retries" settings rc_auth()/rc_acct()
 * (radcli.h) use. Unlike rc_auth()/rc_acct(), which fail over across every
 * configured entry, this uses only the first: the new API carries one
 * server per context, with redundancy delegated to DNS (several A/AAAA
 * records for one name, tried in order within the request's timeout by
 * radcli_transport_exchange()) rather than a configured list of distinct
 * servers. A warning is logged, not an error, if more than one entry is
 * configured, so a caller migrating one entry point at a time from the
 * legacy API isn't broken by the leftover entries.
 *
 * @param ctx a context with configuration loaded.
 * @param code RADCLI_CODE_ACCESS_REQUEST or RADCLI_CODE_ACCOUNTING_REQUEST.
 * @param send the attributes to send; copied in -- send may be freed or
 *  reused by the caller immediately after this call returns.
 * @return the new request, or NULL on allocation failure, an invalid code,
 *  or if ctx has no server configured for that code's type.
 */
radcli_request *radcli_request_new(radcli_ctx *ctx, radcli_code code, const radcli_avp_list *send)
{
	rc_handle *rh = (rc_handle *)ctx;
	struct radcli_request_st *r;
	SERVER *servers;
	const char *optname;
	rc_type type;
	radcli_avp_list *send_copy;
	radcli_avp_iter it;
	const radcli_avp *a;

	if (rh == NULL)
		return NULL;

	if (code != RADCLI_CODE_ACCESS_REQUEST && code != RADCLI_CODE_ACCOUNTING_REQUEST) {
		rc_log(LOG_ERR, "radcli_request_new: code must be RADCLI_CODE_ACCESS_REQUEST "
		    "or RADCLI_CODE_ACCOUNTING_REQUEST");
		return NULL;
	}

	/* Matches rc_select_aaa_server()'s (lib/buildreq.c) rule: an
	 * Accounting-Request goes to authserver, not acctserver, over
	 * TLS/DTLS, which carry both request types over one connection. */
	if (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS ||
	    code == RADCLI_CODE_ACCESS_REQUEST) {
		optname = "authserver";
		type = AUTH;
	} else {
		optname = "acctserver";
		type = ACCT;
	}

	servers = radcli2_priv_conf_srv(rh, optname);
	if (servers == NULL || servers->max == 0) {
		rc_log(LOG_ERR, "radcli_request_new: no %s configured", optname);
		return NULL;
	}
	/* By design, the new API carries one server per handle, redundancy
	 * delegated to DNS/address-level
	 * fail-over (already inside radcli_transport_exchange()), not a
	 * second, per-server-list failover loop -- that job is rc_auth()/
	 * rc_acct()'s alone. Only the first configured entry is ever used;
	 * this only warns, rather than rejecting outright, so a caller
	 * migrating a legacy multi-server config one entry point at a time
	 * isn't broken by the leftover entries. */
	if (servers->max > 1)
		rc_log(LOG_WARNING, "radcli_request_new: %d %s entries configured; "
		    "the new API uses only the first (%s) -- redundancy is "
		    "address-level (DNS), not server-list-level",
		    servers->max, optname, servers->name[0]);

	/* Copied in -- radcli2.h documents that "send" may be freed or reused
	 * by the caller immediately after this call returns; only aliasing
	 * the caller's pointer here would make that a use-after-free the
	 * first time radcli_request_perform() later reads it. */
	send_copy = radcli_avp_list_new();
	if (send_copy == NULL)
		return NULL;
	it = radcli_avp_list_iter(send);
	while ((a = radcli_avp_iter_next(&it)) != NULL) {
		const void *data;
		size_t len;

		if (radcli_avp_get_bytes(a, &data, &len) != 0 ||
		    radcli_avp_add_bytes(send_copy, radcli_avp_def(a), data, len) != 0) {
			radcli_avp_list_free(send_copy);
			return NULL;
		}
	}

	r = calloc(1, sizeof(*r));
	if (r == NULL) {
		radcli_avp_list_free(send_copy);
		return NULL;
	}

	r->type = type;

	strlcpy(r->server, servers->name[0], sizeof(r->server));
	r->svc_port = servers->port[0];
	if (servers->secret[0] != NULL)
		strlcpy(r->secret, servers->secret[0], sizeof(r->secret));

	r->timeout = rc_conf_int_id(rh, OPT_RADIUS_TIMEOUT);
	r->retries = rc_conf_int_id(rh, OPT_RADIUS_RETRIES);

	r->rh = rh;
	r->code = (uint8_t)code;
	r->send = send_copy;

	return r;
}

/*- Builds a wire packet for (code, send) into send_buffer (capacity
 * RC_BUFFER_LEN): Request Authenticator (or the Accounting-Request
 * zero-vector/trailing-MD5 variant), and -- for any code other than
 * Accounting-Request -- a Message-Authenticator via add_msg_auth_attr().
 * Factored out of radcli_do_exchange() so radcli_request_perform()'s
 * RADCLI_REQUEST_SENDONLY path (which hands the packet to
 * radcli_transport_send_async() instead of radcli_transport_exchange())
 * builds the exact same Response Authenticator / Message-Authenticator wire
 * logic, not a second copy -- and shared, too, by lib/dae.c's
 * radcli2_priv_dae_send_watchdog() (RFC 5997 Status-Server over an
 * established RadSec session). send may be an empty list (Status-Server
 * needs no attributes but Message-Authenticator) but not NULL --
 * radcli_avp_encode() rejects that outright. For a TLS/DTLS rh, secret is
 * overridden with the RFC 6614/7360 fixed RadSec secret before it is used
 * for anything (REQ-NET2-SEND-015) -- the caller's resolved secret is
 * irrelevant for that transport regardless of what it is.
 *
 * @param rh a handle to parsed configuration.
 * @param code the RADIUS packet code to send.
 * @param send the attributes to encode; must not be NULL.
 * @param secret the shared secret (overridden for TLS/DTLS, see above).
 * @param send_buffer destination, capacity RC_BUFFER_LEN.
 * @param id the packet's Identifier, always supplied by the caller -- this
 *  function does not draw one itself, so every call site states explicitly
 *  where its id comes from: rc_get_random_byte() for every caller not
 *  sharing a socket with any other concurrently in-flight exchange (the
 *  blocking radcli_do_exchange()/radcli_transport_exchange() path,
 *  radcli_aaa(), radcli2_priv_dae_send_watchdog() -- REQ-NET2-SEND-010), or,
 *  for RADCLI_REQUEST_SENDONLY, the Identifier ctx's in-flight registry
 *  already reserved (REQ-NET2-SEND-016) -- reserved and passed in before
 *  this call, never patched into the wire packet afterward, since id is
 *  itself covered by the Message-Authenticator HMAC.
 * @param vector_out set to the request authenticator vector used.
 * @param out_len set to the total encoded length, including the appended
 *  Message-Authenticator attribute.
 * @return 0 on success, -1 on encoding failure.
 -*/
int radcli_encode_request(rc_handle *rh, uint8_t code, const radcli_avp_list *send,
			  char secret[MAX_SECRET_LENGTH + 1],
			  uint8_t send_buffer[RC_BUFFER_LEN], uint8_t id,
			  unsigned char vector_out[AUTH_VECTOR_LEN], int *out_len)
{
	AUTH_HDR *auth = (AUTH_HDR *)send_buffer;
	int encoded_len, total_length;

	/* RFC 6614 SS2.3/RFC 7360 SS3.2 fix the RadSec shared secret; whatever
	 * the caller resolved from authserver/acctserver's configured secret
	 * (empty, ordinarily -- REQ-CONFIG-CFG-019) is not it. Overriding here,
	 * before secret is used for anything below, is the same override
	 * lib/legacy/send.c's rc_send_server_ctx() and lib/sendserver.c's
	 * radcli_transport_exchange()/radcli_transport_send_async() already
	 * apply -- those three just apply it too late to affect an already-
	 * encoded packet, since encoding (this function) always runs first. */
	if (rh->so.static_secret)
		strlcpy(secret, rh->so.static_secret, MAX_SECRET_LENGTH + 1);

	auth->code = code;
	auth->id = id;

	if (code == RADCLI_CODE_ACCOUNTING_REQUEST) {
		size_t secretlen;
		uint16_t tlen;

		memset(vector_out, 0, AUTH_VECTOR_LEN);
		memcpy(auth->vector, vector_out, AUTH_VECTOR_LEN);

		encoded_len = radcli_avp_encode(rh, send, secret, vector_out,
						send_buffer + AUTH_HDR_LEN,
						RC_MAX_PACKET_LEN - AUTH_HDR_LEN, NULL);
		if (encoded_len < 0)
			return -1;
		total_length = AUTH_HDR_LEN + encoded_len;

		tlen = htons((uint16_t)total_length);
		memcpy(&auth->length, &tlen, sizeof(tlen));

		secretlen = rc_secret_len(secret);
		memcpy(send_buffer + total_length, secret, secretlen);
		rc_md5_calc(vector_out, send_buffer, (size_t)total_length + secretlen);
		memcpy(auth->vector, vector_out, AUTH_VECTOR_LEN);
	} else {
		rc_get_random_bytes(vector_out, AUTH_VECTOR_LEN);
		memcpy(auth->vector, vector_out, AUTH_VECTOR_LEN);

		/* Leave 2+MD5_DIGEST_SIZE bytes for Message-Authenticator (added below). */
		encoded_len = radcli_avp_encode(rh, send, secret, vector_out,
						send_buffer + AUTH_HDR_LEN,
						RC_MAX_PACKET_LEN - AUTH_HDR_LEN - (2 + MD5_DIGEST_SIZE), NULL);
		if (encoded_len < 0)
			return -1;
		total_length = AUTH_HDR_LEN + encoded_len;

		total_length = add_msg_auth_attr(rh, secret, auth, total_length);
		auth->length = htons((uint16_t)total_length);
	}

	*out_len = total_length;
	return 0;
}

/*- Builds a wire packet for (code, send) and hands it to
 * radcli_transport_exchange() against (server, svc_port, secret). Shared by
 * radcli_request_perform() and lib/aaa2.c's radcli_aaa(), so both build the
 * exact same Response Authenticator / Message-Authenticator wire logic
 * instead of two independently-written copies of security-sensitive code.
 *
 * @param rh a handle to parsed configuration.
 * @param code the RADIUS packet code to send.
 * @param send the attributes to encode.
 * @param server the server to resolve and contact.
 * @param svc_port overrides the resolved port when non-zero.
 * @param secret the shared secret.
 * @param timeout per-attempt reply wait, in seconds.
 * @param retries additional retransmit attempts after the first.
 * @param no_wait nonzero to send once and return without waiting for a
 *  reply.
 * @param type AUTH or ACCT.
 * @param recv_buffer filled with the reply's attributes on a terminal
 *  result.
 * @param recv_buffer_cap recv_buffer's capacity in bytes.
 * @param recv_len set to the number of attribute bytes written to
 *  recv_buffer.
 * @param vector_out set to the Request Authenticator vector used, for the
 *  caller to decode the reply against.
 * @param out_reply_code if non-NULL, set to the reply's RADIUS code on a
 *  terminal result.
 * @return whatever radcli_transport_exchange() itself returns.
 -*/
int radcli_do_exchange(rc_handle *rh, uint8_t code, const radcli_avp_list *send,
		       char *server, uint16_t svc_port, char secret[MAX_SECRET_LENGTH + 1],
		       int timeout, int retries, int no_wait, rc_type type,
		       uint8_t *recv_buffer, size_t recv_buffer_cap, size_t *recv_len,
		       unsigned char vector_out[AUTH_VECTOR_LEN], uint8_t *out_reply_code)
{
	uint8_t send_buffer[RC_BUFFER_LEN];
	int total_length;

	/* Own per-call socket via radcli_transport_exchange() below -- no other
	 * concurrently in-flight exchange to collide with, so a CSPRNG draw is
	 * sufficient (REQ-NET2-SEND-010). */
	if (radcli_encode_request(rh, code, send, secret, send_buffer, rc_get_random_byte(),
				  vector_out, &total_length) < 0)
		return ERROR_RC;

	return radcli_transport_exchange(rh, NULL, server, svc_port,
					 secret, 0, timeout, retries, no_wait, type,
					 send_buffer, total_length,
					 recv_buffer, recv_buffer_cap, recv_len, out_reply_code);
}

/** @brief Send a request, optionally waiting for the reply.
 *
 * By default (flags == RADCLI_REQUEST_NONE), sends r and waits for the
 * reply. With RADCLI_REQUEST_SENDONLY, transmits r a single time and
 * returns once the packet is handed to the network, without blocking for a
 * reply -- either as a pure fire-and-forget notification whose outcome the
 * caller does not act on (call radcli_request_free() without ever calling
 * radcli_ctx_dispatch(); radcli.h's rc_acct_async() is the equivalent call
 * in the legacy API), or to read the reply later via radcli_request_done(),
 * driven by the caller's own radcli_ctx_get_poll()/radcli_ctx_dispatch()
 * loop (lib/dae.c).
 *
 * May be called only once per request; construct a new radcli_request for
 * a retransmission with different content.
 *
 * @param r a request from radcli_request_new().
 * @param flags a bitwise OR of #radcli_request_flags.
 * @return with RADCLI_REQUEST_NONE: RADCLI_OK if a validated reply was
 *  received (see radcli_request_code() for which one), RADCLI_TIMEOUT if
 *  none of the server's addresses replied, or RADCLI_ERROR on failure.
 *  With RADCLI_REQUEST_SENDONLY: RADCLI_OK once the packet is handed to
 *  the network, RADCLI_ERROR on failure (e.g. name resolution or encoding
 *  failed); never RADCLI_TIMEOUT.
 */
int radcli_request_perform(radcli_request *r, unsigned flags)
{
	uint8_t recv_buffer[RC_BUFFER_LEN];
	unsigned char vector[AUTH_VECTOR_LEN];
	size_t recv_len = 0;
	int result;

	if (r == NULL || r->performed)
		return RADCLI_ERROR;
	r->performed = 1;

	if (flags & RADCLI_REQUEST_SENDONLY) {
		uint8_t send_buffer[RC_BUFFER_LEN];
		int send_len;
		uint8_t id;
		int slot;

		/* Reserve the Identifier before encoding: it is itself covered
		 * by the Message-Authenticator HMAC below, so it cannot be
		 * patched in afterward (REQ-NET2-SEND-016). */
		slot = radcli2_priv_reqreg_reserve(r->rh, &r->async, &id);
		if (slot < 0)
			return RADCLI_ERROR;

		if (radcli_encode_request(r->rh, r->code, r->send, r->secret,
					  send_buffer, id, vector, &send_len) < 0) {
			radcli2_priv_reqreg_release(r->rh, slot);
			return RADCLI_ERROR;
		}

		result = radcli_transport_send_async(r->rh, slot, r->server, r->svc_port, r->secret,
						     r->type, send_buffer, send_len,
						     r->timeout, r->retries, &r->async);
		if (result != OK_RC) {
			radcli2_priv_reqreg_release(r->rh, slot);
			return RADCLI_ERROR;
		}
		return RADCLI_OK;
	}

	result = radcli_do_exchange(r->rh, r->code, r->send, r->server, r->svc_port, r->secret,
				    r->timeout, r->retries, 0, r->type,
				    recv_buffer, sizeof(recv_buffer), &recv_len, vector, &r->reply_code);

	switch (result) {
	case OK_RC:
	case REJECT_RC:
	case CHALLENGE_RC:
		if (recv_len > 0) {
			if (radcli_avp_decode(r->rh, r->secret, vector, recv_buffer, recv_len, 0,
					      &r->reply_attrs) != 0)
				return RADCLI_ERROR;
		}
		return RADCLI_OK;
	case TIMEOUT_RC:
		return RADCLI_TIMEOUT;
	default:
		return RADCLI_ERROR;
	}
}

/** @brief Report r's outcome once radcli_ctx_dispatch() has resolved it --
 *  a pure state query, performing no I/O of its own.
 *
 * Since REQ-NET2-SEND-016/013, r shares ctx's request socket/session with
 * every other concurrently in-flight RADCLI_REQUEST_SENDONLY request, and
 * radcli_ctx_dispatch() is what actually drives it to completion (draining
 * replies, retransmitting, expiring on timeout) -- this call never performs
 * I/O itself, so calling it any number of times between
 * radcli_ctx_dispatch() calls is free.
 *
 * @param r a request radcli_request_perform(r, RADCLI_REQUEST_SENDONLY)
 *  returned RADCLI_OK for.
 * @return RADCLI_AGAIN if still waiting (call radcli_ctx_get_poll()/
 *  radcli_ctx_dispatch() and try again), RADCLI_OK if a validated reply was
 *  received (read it with radcli_request_code()/_attrs(), same as
 *  radcli_request_perform()), RADCLI_TIMEOUT if retries are exhausted, or
 *  RADCLI_ERROR on failure or if r was never sent with
 *  RADCLI_REQUEST_SENDONLY.
 */
int radcli_request_done(radcli_request *r)
{
	if (r == NULL || !r->async.active)
		return RADCLI_ERROR;
	if (!r->async.delivered)
		return RADCLI_AGAIN;

	r->reply_code = r->async.reply_code;
	r->reply_attrs = r->async.reply_attrs;
	r->async.reply_attrs = NULL; /* ownership moved to r */
	r->async.active = 0;

	switch (r->async.result) {
	case OK_RC:
	case REJECT_RC:
	case CHALLENGE_RC:
		return RADCLI_OK;
	case TIMEOUT_RC:
		return RADCLI_TIMEOUT;
	default:
		return RADCLI_ERROR;
	}
}

/** @brief Return the reply's RADIUS code.
 * @param r a request radcli_request_perform() returned RADCLI_OK for.
 * @return the code (e.g. RADCLI_CODE_ACCESS_ACCEPT), or 0 if r has not yet
 *  been successfully performed.
 */
radcli_code radcli_request_code(const radcli_request *r)
{
	if (r == NULL || !r->performed)
		return 0;
	return (radcli_code)r->reply_code;
}

/** @brief Return the reply's decoded attributes.
 * @param r a request radcli_request_perform() returned RADCLI_OK for.
 * @return the attribute list, owned by r and valid for its lifetime; NULL
 *  if r has not yet been successfully performed, or the reply carried no
 *  attributes.
 */
const radcli_avp_list *radcli_request_attrs(const radcli_request *r)
{
	if (r == NULL)
		return NULL;
	return r->reply_attrs;
}

/** @brief Return the name of the server a request was (or will be) sent to.
 * @param r a request from radcli_request_new().
 * @return the server name, valid for r's lifetime; never NULL.
 */
const char *radcli_request_server(const radcli_request *r)
{
	static const char empty[] = "";

	if (r == NULL)
		return empty;
	return r->server;
}

/** @brief Release a request.
 *
 * If r was sent with RADCLI_REQUEST_SENDONLY and radcli_request_done()
 * never reached a terminal result (the fire-and-forget case: nothing ever
 * drives it via radcli_ctx_dispatch() at all), releases r's still-reserved
 * registry slot first -- this is what makes fire-and-forget just
 * "perform() then free()", with no separate close step for the caller to
 * remember.
 *
 * @param r a request from radcli_request_new(); NULL is accepted and ignored.
 */
void radcli_request_free(radcli_request *r)
{
	if (r == NULL)
		return;
	radcli_transport_async_abort(&r->async);
	radcli_avp_list_free(r->send);
	radcli_avp_list_free(r->reply_attrs);
	memset(r->secret, 0, sizeof(r->secret));
	free(r);
}
