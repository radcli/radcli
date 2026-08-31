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

/* radcli2.h's radcli_aaa(): the new API's counterpart to radcli.h's
 * rc_aaa()/rc_aaa_ctx() (lib/buildreq.c) -- Acct-Delay-Time autofill plus
 * fail-over across every configured authserver/acctserver entry, layered on
 * top of radcli_request_*'s single-server building block the same way
 * lib/aaa_ctx.c layers over rc_auth() today. Added as a separate wrapper
 * rather than an extension of radcli_request_perform(), so that function's
 * single-server contract is untouched. Unlike the legacy rc_aaa(), this has
 * no NAS-Port autofill: that value is known to the caller before the call,
 * same as any other attribute, so it belongs in send via
 * radcli_avp_add_uint32_by_num() rather than as a special-cased parameter.
 *
 * Deliberately does not go through radcli_request_new()/_perform(): those
 * are pinned to the single-server-per-request rule (REQ-NET2-INIT-003)
 * and have no way to name a specific server. Instead
 * this calls lib/request.c's radcli_do_exchange() directly -- once per
 * server attempted -- so the wire-format/Response-Authenticator/
 * Message-Authenticator logic is the exact code radcli_request_perform()
 * itself uses, not a second copy of it. */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "avp.h"
#include "util.h"
#include "options.h"

/* Mirrors rc_fill_acct_pairs()'s (lib/buildreq.c) Acct-Delay-Time semantics,
 * but as a fresh radcli_avp_list per attempt rather than one VALUE_PAIR
 * mutated in place, since radcli_avp_list is add-only by design
 * (lib/avp.c). Any original Acct-Delay-Time in send is dropped from the
 * copy -- its value is already folded into start_time by the caller -- so
 * the freshly computed one is the only one that reaches the wire. */
/*- Build the per-attempt attribute list for one radcli_aaa() server attempt.
 *
 * @param send the caller-supplied attributes to copy into the attempt.
 * @param code the request code; Acct-Delay-Time is only added for
 * RADCLI_CODE_ACCOUNTING_REQUEST.
 * @param d_adt the Acct-Delay-Time attribute definition, or NULL if the
 * dictionary doesn't define it.
 * @param start_time the elapsed-time origin, in seconds, used to compute
 * Acct-Delay-Time.
 * @return a newly allocated radcli_avp_list, or NULL on allocation failure.
 -*/
static radcli_avp_list *build_attempt(const radcli_avp_list *send,
				      radcli_code code,
				      const radcli_attr_def *d_adt, double start_time)
{
	radcli_avp_list *attempt;
	radcli_avp_iter it;
	const radcli_avp *a;

	attempt = radcli_avp_list_new();
	if (attempt == NULL)
		return NULL;

	it = radcli_avp_list_iter(send);
	while ((a = radcli_avp_iter_next(&it)) != NULL) {
		const void *data;
		size_t len;

		if (radcli_avp_def(a) == d_adt)
			continue;

		if (radcli_avp_get_bytes(a, &data, &len) != 0 ||
		    radcli_avp_add_bytes(attempt, radcli_avp_def(a), data, len) != 0) {
			radcli_avp_list_free(attempt);
			return NULL;
		}
	}

	if (code == RADCLI_CODE_ACCOUNTING_REQUEST && d_adt != NULL) {
		uint32_t dtime = (uint32_t)(rc_getmtime() - start_time);

		if (radcli_avp_add_uint32(attempt, d_adt, dtime) != 0) {
			radcli_avp_list_free(attempt);
			return NULL;
		}
	}

	return attempt;
}

/**
 * @addtogroup radcli2-messaging
 *
 * @{
 */

/** @brief Perform an authentication or accounting exchange with
 *  Acct-Delay-Time autofill and fail-over across every configured server.
 *
 * The new API's counterpart to radcli.h's rc_aaa()/rc_auth()/rc_acct(),
 * layered on top of the single-server radcli_request_new()/_perform()
 * building block the same way lib/aaa_ctx.c layers over rc_auth() today --
 * added as a separate wrapper rather than as an extension of
 * radcli_request_perform(), so that function's single-server contract is
 * untouched. Unlike radcli_request_new(), which uses only the first
 * configured "authserver"/"acctserver" entry (REQ-NET2-INIT-003), this
 * tries every configured entry in order, moving to the next on a timeout
 * or unreachable-network result, exactly as rc_aaa()/rc_aaa_ctx() do.
 *
 * Unlike the legacy rc_aaa(), this has no NAS-Port autofill parameters:
 * NAS-Port is a value the caller already knows before calling, exactly like
 * any other attribute (NAS-IP-Address, Called-Station-Id, ...), so it
 * belongs in send via radcli_avp_add_uint32_by_num(), not as a special-cased
 * parameter here. Acct-Delay-Time remains the one attribute radcli_aaa()
 * computes itself, since only it can see the fail-over timing: if code is
 * #RADCLI_CODE_ACCOUNTING_REQUEST, an Acct-Delay-Time attribute is always
 * added (replacing any in send), measuring elapsed time from the first
 * attempt -- continuing to accumulate across a fail-over retry, not
 * resetting -- folding in any Acct-Delay-Time already in send as an
 * initial offset, matching rc_fill_acct_pairs()'s (lib/buildreq.c)
 * semantics.
 *
 * @param ctx a context with configuration loaded.
 * @param code RADCLI_CODE_ACCESS_REQUEST or RADCLI_CODE_ACCOUNTING_REQUEST.
 * @param send the attributes to send; copied in per attempt -- send may be
 *  freed or reused by the caller immediately after this call returns.
 * @param out_code if non-NULL, receives the final reply's RADIUS code on
 *  RADCLI_OK.
 * @param out_attrs if non-NULL, receives the final reply's decoded
 *  attributes on RADCLI_OK (owned by the caller, free with
 *  radcli_avp_list_free()); left unset otherwise. Pass NULL for an
 *  Accounting-Request caller uninterested in the (typically empty) reply.
 * @return RADCLI_OK if any configured server produced a validated reply
 *  (check out_code for Access-Accept/Access-Reject/Access-Challenge),
 *  RADCLI_TIMEOUT if every configured server timed out or was unreachable,
 *  RADCLI_ERROR on failure (NULL ctx/send, an invalid code, no server
 *  configured for that code's type, or an allocation/encoding failure).
 */
int radcli_aaa(radcli_ctx *ctx, radcli_code code, const radcli_avp_list *send,
	       radcli_code *out_code, radcli_avp_list **out_attrs)
{
	rc_handle *rh = (rc_handle *)ctx;
	const char *optname;
	rc_type type;
	SERVER *servers;
	const radcli_attr_def *d_adt;
	double start_time;
	int timeout, retries;
	int servernum, result = ERROR_RC;

	if (rh == NULL || send == NULL)
		return RADCLI_ERROR;

	if (code != RADCLI_CODE_ACCESS_REQUEST && code != RADCLI_CODE_ACCOUNTING_REQUEST) {
		rc_log(LOG_ERR, "radcli_aaa: code must be RADCLI_CODE_ACCESS_REQUEST "
		    "or RADCLI_CODE_ACCOUNTING_REQUEST");
		return RADCLI_ERROR;
	}

	/* Same TLS/DTLS + request-type rule as radcli_request_new()
	 * (REQ-NET2-INIT-002) / rc_select_aaa_server() (lib/buildreq.c). */
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
		rc_log(LOG_ERR, "radcli_aaa: no %s configured", optname);
		return RADCLI_ERROR;
	}

	timeout = rc_conf_int_id(rh, OPT_RADIUS_TIMEOUT);
	retries = rc_conf_int_id(rh, OPT_RADIUS_RETRIES);

	d_adt = radcli_dict_lookup_num(ctx, PW_ACCT_DELAY_TIME, 0);

	/* start_time is measured once, before the first attempt -- not reset
	 * on fail-over -- so Acct-Delay-Time keeps accumulating real elapsed
	 * time across every server tried, exactly as rc_aaa_ctx_server()'s
	 * single, retry-spanning start_time does. A pre-existing
	 * Acct-Delay-Time in send is folded in the same way
	 * rc_fill_acct_pairs() folds one found already on the VALUE_PAIR
	 * list: as an initial offset, not a value copied onto the wire as-is. */
	start_time = rc_getmtime();
	if (code == RADCLI_CODE_ACCOUNTING_REQUEST && d_adt != NULL) {
		const radcli_avp *existing = radcli_avp_get(send, d_adt, 0);

		if (existing != NULL) {
			uint32_t v;

			if (radcli_avp_get_uint32(existing, &v) == 0)
				start_time -= v;
		}
	}

	servernum = 0;
	do {
		radcli_avp_list *attempt;
		uint8_t recv_buffer[RC_BUFFER_LEN];
		unsigned char vector[AUTH_VECTOR_LEN];
		size_t recv_len = 0;
		uint8_t reply_code = 0;
		char server[AUTH_ID_LEN + 1] = "";
		char secret[MAX_SECRET_LENGTH + 1] = "";

		attempt = build_attempt(send, code, d_adt, start_time);
		if (attempt == NULL)
			return RADCLI_ERROR;

		strlcpy(server, servers->name[servernum], sizeof(server));
		if (servers->secret[servernum] != NULL)
			strlcpy(secret, servers->secret[servernum], sizeof(secret));

		result = radcli_do_exchange(rh, (uint8_t)code, attempt, server,
					    servers->port[servernum], secret,
					    timeout, retries, 0, type,
					    recv_buffer, sizeof(recv_buffer), &recv_len,
					    vector, &reply_code);

		radcli_avp_list_free(attempt);
		memset(secret, 0, sizeof(secret));

		if (result == OK_RC || result == REJECT_RC || result == CHALLENGE_RC) {
			radcli_avp_list *decoded = NULL;

			if (recv_len > 0) {
				if (radcli_avp_decode(rh, servers->secret[servernum] ? servers->secret[servernum] : "",
						      vector, recv_buffer, recv_len, 0, &decoded) != 0)
					return RADCLI_ERROR;
			}

			if (out_code != NULL)
				*out_code = (radcli_code)reply_code;
			if (out_attrs != NULL)
				*out_attrs = decoded;
			else
				radcli_avp_list_free(decoded);

			DEBUG(rh, LOG_INFO, "radcli_aaa: succeeded against server %u (%s)",
			      servernum, server);
			return RADCLI_OK;
		}

		DEBUG(rh, LOG_INFO, "radcli_aaa: attempt against server %u (%s) failed "
		      "(%d); remaining: %d", servernum, server, result,
		      servers->max - servernum - 1);
		servernum++;
	} while (servernum < servers->max && (result == TIMEOUT_RC || result == NETUNREACH_RC));

	return result == TIMEOUT_RC ? RADCLI_TIMEOUT : RADCLI_ERROR;
}

/** @} */
