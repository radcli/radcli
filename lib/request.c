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

/* radcli2.h's request/reply entry point (radcli_request_new()/_perform()/
 * etc.): builds a wire packet with radcli_avp_encode(), sends it with the
 * same radcli_transport_exchange() rc_send_server_ctx() uses (so failover,
 * retries, Response Authenticator, and Message-Authenticator/Blast-RADIUS
 * verification are exactly the code already proven against rc_send_server_ctx(),
 * not a second copy), and decodes the reply with radcli_avp_decode().
 *
 * Uses only the first configured server for the request's type, by design
 * (doc/plan-api-modernization.md's decision G): the new API carries one
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
#include "rc-md5.h"
#include "rc-hmac.h" /* MD5_DIGEST_SIZE: only nettle/md5.h defines it directly;
                      * the non-nettle build gets it from this header's own
                      * fallback #define instead (see lib/rc-hmac.h). */
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
};

/** @brief Create a request to send. See the doc comment in radcli2.h. */
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

	servers = rc_conf_srv(rh, optname);
	if (servers == NULL || servers->max == 0) {
		rc_log(LOG_ERR, "radcli_request_new: no %s configured", optname);
		return NULL;
	}
	/* Decision G (doc/plan-api-modernization.md): the new API carries one
	 * server per handle, redundancy delegated to DNS/address-level
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

	r->timeout = rc_conf_int(rh, "radius_timeout");
	r->retries = rc_conf_int(rh, "radius_retries");

	r->rh = rh;
	r->code = (uint8_t)code;
	r->send = send_copy;

	return r;
}

/** @brief Send a request and wait for the reply. See the doc comment in radcli2.h. */
int radcli_request_perform(radcli_request *r)
{
	uint8_t send_buffer[RC_BUFFER_LEN];
	uint8_t recv_buffer[RC_BUFFER_LEN];
	AUTH_HDR *auth = (AUTH_HDR *)send_buffer;
	unsigned char vector[AUTH_VECTOR_LEN];
	int encoded_len, total_length;
	size_t recv_len = 0;
	int result;

	if (r == NULL || r->performed)
		return RADCLI_ERROR;
	r->performed = 1;

	auth->code = r->code;
	auth->id = rc_get_random_byte();

	if (r->code == RADCLI_CODE_ACCOUNTING_REQUEST) {
		size_t secretlen;
		uint16_t tlen;

		memset(vector, 0, AUTH_VECTOR_LEN);
		memcpy(auth->vector, vector, AUTH_VECTOR_LEN);

		encoded_len = radcli_avp_encode_rfc2865(r->rh, r->send, r->secret, vector,
						send_buffer + AUTH_HDR_LEN,
						RC_MAX_PACKET_LEN - AUTH_HDR_LEN, NULL);
		if (encoded_len < 0)
			return RADCLI_ERROR;
		total_length = AUTH_HDR_LEN + encoded_len;

		tlen = htons((uint16_t)total_length);
		memcpy(&auth->length, &tlen, sizeof(tlen));

		secretlen = strlen(r->secret);
		if (secretlen > MAX_SECRET_LENGTH)
			secretlen = MAX_SECRET_LENGTH;
		memcpy(send_buffer + total_length, r->secret, secretlen);
		rc_md5_calc(vector, send_buffer, (size_t)total_length + secretlen);
		memcpy(auth->vector, vector, AUTH_VECTOR_LEN);
	} else {
		rc_get_random_bytes(vector, AUTH_VECTOR_LEN);
		memcpy(auth->vector, vector, AUTH_VECTOR_LEN);

		/* Leave 2+MD5_DIGEST_SIZE bytes for Message-Authenticator (added below). */
		encoded_len = radcli_avp_encode_rfc2865(r->rh, r->send, r->secret, vector,
						send_buffer + AUTH_HDR_LEN,
						RC_MAX_PACKET_LEN - AUTH_HDR_LEN - (2 + MD5_DIGEST_SIZE), NULL);
		if (encoded_len < 0)
			return RADCLI_ERROR;
		total_length = AUTH_HDR_LEN + encoded_len;

		total_length = add_msg_auth_attr(r->rh, r->secret, auth, total_length);
		auth->length = htons((uint16_t)total_length);
	}

	result = radcli_transport_exchange(r->rh, NULL, r->server, r->svc_port,
					   r->secret, 0, r->timeout, r->retries, 0, r->type,
					   send_buffer, total_length,
					   recv_buffer, sizeof(recv_buffer), &recv_len, &r->reply_code);

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

/** @brief Return the reply's RADIUS code. See the doc comment in radcli2.h. */
radcli_code radcli_request_code(const radcli_request *r)
{
	if (r == NULL || !r->performed)
		return 0;
	return (radcli_code)r->reply_code;
}

/** @brief Return the reply's decoded attributes. See the doc comment in radcli2.h. */
const radcli_avp_list *radcli_request_attrs(const radcli_request *r)
{
	if (r == NULL)
		return NULL;
	return r->reply_attrs;
}

/** @brief Return the name of the server a request was (or will be) sent to.
 * See the doc comment in radcli2.h. */
const char *radcli_request_server(const radcli_request *r)
{
	static const char empty[] = "";

	if (r == NULL)
		return empty;
	return r->server;
}

/** @brief Release a request. See the doc comment in radcli2.h. */
void radcli_request_free(radcli_request *r)
{
	if (r == NULL)
		return;
	radcli_avp_list_free(r->send);
	radcli_avp_list_free(r->reply_attrs);
	memset(r->secret, 0, sizeof(r->secret));
	free(r);
}
