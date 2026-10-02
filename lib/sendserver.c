/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 * Copyright (C) 2015,2016 Nikos Mavrogiannopoulos
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 *
 */

#include <includes.h>
#include <radcli/radcli.h>
#include <poll.h>
#include "dict2.h"
#include "options.h"
#include "util.h"
#include "avp.h"
#include "rc-crypto.h"
#include "rc-random.h"

#if defined(HAVE_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
#endif

#if defined(__linux__)
#include <linux/in6.h>
#endif


/* Resets fd to -1 after closing so a later unconditional cleanup (e.g. the
 * shared `cleanup:` label's `if (sockfd >= 0) SCLOSE(sockfd)`) cannot close
 * the same descriptor a second time. */
#define SCLOSE(fd) do { if (sfuncs->close_fd) sfuncs->close_fd(fd); (fd) = -1; } while (0)

/* rc_check_reply(), populate_ctx(), add_msg_auth_attr(),
 * validate_message_authenticator() are declared in include/includes.h (no
 * longer static): they operate purely on raw bytes/AUTH_HDR/secret/vector,
 * never on VALUE_PAIR, so radcli_transport_exchange() below reuses them
 * directly instead of reimplementing the same RFC 2865 SS3 Response
 * Authenticator and Message-Authenticator/Blast-RADIUS logic a second
 * time. */

/*- Allocate and fill an RC_AAA_CTX capturing the secret/vector used for a
 * sent request, if the caller asked for one.
 *
 * @param ctx if non-NULL and *ctx is NULL, allocated and filled; a no-op
 * if ctx is NULL.
 * @param secret the shared secret used for the request.
 * @param vector the request authenticator vector used for the request.
 * @return OK_RC on success (including the ctx == NULL no-op case),
 * ERROR_RC if *ctx is already non-NULL or allocation failed.
 -*/
int populate_ctx(RC_AAA_CTX ** ctx, char secret[MAX_SECRET_LENGTH + 1],
		 uint8_t vector[AUTH_VECTOR_LEN])
{
	if (ctx) {
		if (*ctx != NULL)
			return ERROR_RC;

		*ctx = malloc(sizeof(RC_AAA_CTX));
		if (*ctx) {
			memcpy((*ctx)->secret, secret, sizeof((*ctx)->secret));
			memcpy((*ctx)->request_vector, vector,
			       sizeof((*ctx)->request_vector));
		} else {
			return ERROR_RC;
		}
	}
	return OK_RC;
}
/*- Verify a reply packet's length, sequence number, and Response
 * Authenticator digest.
 *
 * @param auth a pointer to AUTH_HDR.
 * @param bufferlen the available buffer length.
 * @param secret the secret used by the server.
 * @param vector a random vector of AUTH_VECTOR_LEN.
 * @param seq_nbr a unique sequence number.
 * @return OK_RC upon success, BADRESP_RC if anything looks funny.
 -*/
int rc_check_reply(AUTH_HDR * auth, int bufferlen, char const *secret,
		   unsigned char const *vector, uint8_t seq_nbr)
{
	int secretlen;
	int totallen;
	unsigned char calc_digest[AUTH_VECTOR_LEN];
	unsigned char reply_digest[AUTH_VECTOR_LEN];

	totallen = ntohs(auth->length);
	secretlen = (int)strlen(secret);

	/* Do sanity checks on packet length */
	if ((totallen < 20) || (totallen > 4096)) {
		rc_log(LOG_ERR,
		       "rc_check_reply: received RADIUS server response with invalid length");
		return BADRESP_RC;
	}

	/* Verify buffer space, should never trigger with current buffer size and check above */
	if ((totallen + secretlen) > bufferlen) {
		rc_log(LOG_ERR,
		       "rc_check_reply: not enough buffer space to verify RADIUS server response");
		return BADRESP_RC;
	}

	/* Verify that id (seq. number) matches what we sent */
	if (auth->id != seq_nbr) {
		rc_log(LOG_ERR,
		       "rc_check_reply: received non-matching id in RADIUS server response");
		return BADRESPID_RC;
	}
	/* Verify the reply digest */
	memcpy((char *)reply_digest, (char *)auth->vector, AUTH_VECTOR_LEN);
	memcpy((char *)auth->vector, (char *)vector, AUTH_VECTOR_LEN);
	memcpy((char *)auth + totallen, secret, secretlen);
	rc_md5_calc(calc_digest, (unsigned char *)auth, totallen + secretlen);

	if (rc_memcmp((char *)reply_digest, (char *)calc_digest,
		      AUTH_VECTOR_LEN) != 0) {
		rc_log(LOG_ERR,
		       "rc_check_reply: received invalid reply digest from RADIUS server");
		return BADRESP_RC;
	}

	return OK_RC;

}

/*- Add a Message-Authenticator attribute to a message. Mandatory, for
 * example, when sending a message containing an EAP-Message attribute.
 *
 * @param rh a handle to parsed configuration.
 * @param secret the server's secret string.
 * @param auth pointer to the AUTH_HDR structure.
 * @param total_length total packet length before Message-Authenticator is
 * added.
 * @return total packet length after Message-Authenticator is added.
 -*/
int add_msg_auth_attr(rc_handle * rh, char * secret,
		      AUTH_HDR *auth, int total_length)
{
	size_t secretlen = rc_secret_len(secret);
	uint8_t *msg_auth = (uint8_t *)auth + total_length;
	msg_auth[0] = PW_MESSAGE_AUTHENTICATOR;
	msg_auth[1] = 18;
	memset(&msg_auth[2], 0, MD5_DIGEST_SIZE);
	total_length += 18;
	auth->length = htons((unsigned short)total_length);

	/* Calculate HMAC-MD5 [RFC2104] hash */
	uint8_t digest[MD5_DIGEST_SIZE];
	rc_hmac_md5((uint8_t *)auth, (size_t)total_length, (uint8_t *)secret, secretlen, digest);
	memcpy(&msg_auth[2], digest, MD5_DIGEST_SIZE);

	return total_length;
}

/*- Validate a reply's Message-Authenticator attribute (RFC 2869 §5.14,
 * RFC 3579 §3.2).
 *
 * @param recv_buffer the original packet.
 * @param length the length of the attribute data (packet length minus
 * AUTH_HDR_LEN).
 * @param secret the RADIUS secret.
 * @param req_auth the request authenticator from the Access-Request (RFC
 * 3579 §3.2 requires MA in responses to be computed over the packet with
 * the Request Authenticator in the Authenticator field, not the Response
 * Authenticator).
 * @return zero on success, other values for failure.
 -*/
int validate_message_authenticator(const uint8_t *recv_buffer,
				   size_t length, const char *secret,
				   const unsigned char *req_auth)
{
	uint8_t verify_buffer[RC_BUFFER_LEN];
	pkt_buf vb;
	uint8_t ma_copy[MD5_DIGEST_SIZE];
	uint8_t digest[MD5_DIGEST_SIZE];
	uint8_t attr_type, attr_len;
	int ma_found = 0;

	if (AUTH_HDR_LEN + length > sizeof(verify_buffer)) {
		rc_log(LOG_ERR, "%s: packet too large for verification buffer", __func__);
		return -1;
	}

	/* Copy the packet, substitute the Request Authenticator per RFC 3579 §3.2,
	 * and zero the Message-Authenticator value before computing HMAC-MD5. */
	memcpy(verify_buffer, recv_buffer, AUTH_HDR_LEN + length);
	memcpy(verify_buffer + 4, req_auth, AUTH_VECTOR_LEN);
	pb_init_read(&vb, verify_buffer + AUTH_HDR_LEN, length, length);

	while (pb_len(&vb) >= 2) {
		attr_type = vb.data[0];
		attr_len  = vb.data[1];
		if (attr_len < 2 || (size_t)attr_len > pb_len(&vb))
			break;  /* malformed; already rejected by upstream attr-loop */

		if (attr_type == PW_MESSAGE_AUTHENTICATOR) {
			if (attr_len != 2 + MD5_DIGEST_SIZE) {
				rc_log(LOG_ERR, "%s: Message-Authenticator has wrong length %u",
				       __func__, (unsigned)(attr_len - 2));
				return -1;
			}
			/* Save original value before zeroing in the verification copy */
			memcpy(ma_copy, vb.data + 2, MD5_DIGEST_SIZE);
			memset(vb.data + 2, '\0', MD5_DIGEST_SIZE);
			ma_found = 1;
			break;
		}
		assert(pb_pull(&vb, attr_len) == 0);
	}

	if (!ma_found)
		return -1;

	rc_hmac_md5(verify_buffer, AUTH_HDR_LEN + length, (uint8_t *)secret, rc_secret_len(secret), digest);
	return rc_memcmp(ma_copy, digest, MD5_DIGEST_SIZE);
}

/*- Representation-agnostic RADIUS request/reply exchange.
 *
 * Resolves server_name to every A/AAAA address it has and tries each in
 * turn -- a fresh socket and re-derived source address per attempt, since
 * a name can resolve to a mix of address families -- retrying up to
 * `retries` times before moving to the next address. send_buf is a
 * complete, pre-encoded packet (header included); code, Identifier, and
 * Request Authenticator are read straight from its header rather than
 * passed separately. mgmt_secret picks the resolution path: non-zero
 * resolves server_name to an address only (rc_getaddrinfo()) and uses
 * secret as given (the "management poll" case); zero resolves both
 * address and secret via radcli2_priv_find_server_addr(), which overwrites secret
 * if server_name matches a configured authserver/acctserver entry.
 * no_wait is fire-and-forget (REQ-NET-NET-017): send once to the first
 * resolved address and return without waiting for a reply.
 *
 * On a reply, validates framing, the Response Authenticator
 * (rc_check_reply()), and -- for AUTH over UDP/TCP -- the
 * Message-Authenticator and its Blast-RADIUS first-attribute position
 * (validate_message_authenticator()). On success the reply's attribute
 * region (header stripped) is left in recv_buf[0 .. *recv_len); this
 * function does not encode or decode individual attributes.
 *
 * Deliberately does NOT scrub secret before returning: secret is caller
 * memory (radcli_do_exchange() passes radcli2's own persistent r->secret
 * through here by reference, not a copy), and this function has no way to
 * know whether the caller is done with it -- radcli_do_exchange()'s own
 * caller (radcli_request_perform()) still needs it one call later, to
 * decode the very reply this function just validated. Wiping it here (as
 * an earlier version of this function did) zeroed r->secret before that
 * decode ran, silently corrupting any salt-encrypted reply attribute
 * (Tunnel-Password, MS-MPPE-*-Key -- RFC 2868 SS3.5). Each caller that
 * owns a secret buffer is responsible for clearing it once IT is actually
 * done: rc_send_server_ctx() (lib/legacy/send.c) at its own end of
 * function, radcli_request_free() (lib/request.c) at r's end of life.
 *
 * @param rh a handle to parsed configuration.
 * @param ctx if non-NULL, receives the context of the sent request; release with rc_aaa_ctx_free().
 * @param server_name the server to resolve and contact.
 * @param svc_port overrides the resolved port when non-zero.
 * @param secret the shared secret; see mgmt_secret for how it is used/resolved.
 * @param mgmt_secret non-zero for the "management poll" resolution path (see above).
 * @param timeout per-address, per-attempt reply wait, in seconds.
 * @param retries additional attempts per address after the first (0 = one attempt per address, no retry).
 * @param no_wait fire-and-forget; see above.
 * @param type AUTH or ACCT; selects the Message-Authenticator/Blast-RADIUS check.
 * @param send_buf the complete, pre-built, pre-encoded packet to send.
 * @param send_len send_buf's length in bytes.
 * @param recv_buf destination for the reply's attribute region.
 * @param recv_buf_cap recv_buf's capacity in bytes.
 * @param recv_len set to the reply's attribute region length on success.
 * @param out_code if non-NULL, set to the reply's raw wire Code octet
 *  (e.g. PW_ACCESS_ACCEPT) whenever recv_len is also set, i.e. on
 *  OK_RC/REJECT_RC/CHALLENGE_RC/BADRESP_RC; left untouched otherwise.
 * @return OK_RC (0) on success, CHALLENGE_RC on Access-Challenge, TIMEOUT_RC
 *  if every address's retries are exhausted, REJECT_RC on reject, or
 *  negative on failure.
 -*/
/*- Validate and decode a reply already known to have the right Identifier
 * and Response Authenticator (rc_check_reply() returned OK_RC) into
 * recv_buf's attribute region, exactly as radcli_transport_exchange()'s own
 * `got_reply:` block used to do inline. Factored out so
 * radcli2_priv_reqreg_drain() below can reuse the identical RFC
 * 2865/2869/Blast-RADIUS validation instead of a second copy.
 * secret/vector/type/server_name/svc_port are as radcli_transport_exchange()
 * received them; recv_buf/recv_buf_cap/recv_len/out_code are as documented
 * on radcli_transport_exchange() itself.
 *
 * Despite the above, this function does not simply trust its callers for the
 * one property that would otherwise abort() the process if violated: whether
 * recv_auth->length is at least AUTH_HDR_LEN. Both call sites only bound
 * recv_auth->length against the bytes actually received, not against
 * AUTH_HDR_LEN itself, and rc_check_reply()'s OK_RC does establish it -- but
 * this function is static with exactly two callers, and REQ-GEN-STYLE-009
 * treats a cross-function invariant on wire-controlled data as one reorg
 * away from silently breaking, not as a fact to assert. Checked explicitly
 * below instead.
 *
 * @return OK_RC/REJECT_RC/CHALLENGE_RC/BADRESP_RC/ERROR_RC -- never
 *  TIMEOUT_RC or BADRESPID_RC, which are decided by the caller before this
 *  is reached. A BADRESP_RC return here is this function's own verdict (an
 *  unrecognized reply code), unrelated to rc_check_reply()'s BADRESP_RC,
 *  which the caller must have already turned away before calling in.
 -*/
static int decode_reply(rc_handle *rh, RC_AAA_CTX **ctx, const char *server_name,
			unsigned short svc_port, rc_type type,
			char secret[MAX_SECRET_LENGTH + 1], const unsigned char *vector,
			uint8_t *recv_buf, size_t recv_buf_cap,
			size_t *recv_len, uint8_t *out_code)
{
	AUTH_HDR *recv_auth = (AUTH_HDR *)recv_buf;
	int length = ntohs(recv_auth->length);
	pkt_buf rb;
	uint8_t attr_type, attr_len;
	int result;

	if ((size_t)length > recv_buf_cap)
		length = (int)recv_buf_cap;

	/* Verify it's a well-formed RADIUS packet before doing ANYTHING with it. */
	pb_init_read(&rb, recv_buf, length, recv_buf_cap);
	if (pb_pull(&rb, AUTH_HDR_LEN) != 0) {
		rc_log(LOG_ERR, "%s: %s:%d: reply shorter than the RADIUS header",
		       __func__, server_name, svc_port);
		return ERROR_RC;
	}
	while (pb_len(&rb) > 0) {
		if (pb_peek_byte(&rb, 0, &attr_type) < 0 || pb_peek_byte(&rb, 1, &attr_len) < 0) {
			rc_log(LOG_ERR, "%s: %s:%d: truncated attribute", __func__, server_name, svc_port);
			return ERROR_RC;
		}
		if (attr_type == 0) {
			rc_log(LOG_ERR, "%s: %s:%d: attribute zero is invalid", __func__, server_name, svc_port);
			return ERROR_RC;
		}
		if (attr_len < 2) {
			rc_log(LOG_ERR, "%s: %s:%d: attribute length is too small", __func__, server_name, svc_port);
			return ERROR_RC;
		}
		if (attr_len > pb_len(&rb)) {
			rc_log(LOG_ERR, "%s: %s:%d: attribute overflows the packet", __func__, server_name, svc_port);
			return ERROR_RC;
		}
		assert(pb_pull(&rb, attr_len) == 0);
	}

	length = ntohs(recv_auth->length) - AUTH_HDR_LEN;
	if (length < 0)
		length = 0;

	result = populate_ctx(ctx, secret, (unsigned char *)vector);
	if (result != OK_RC)
		return result;

	/* Per draft-ietf-radext-deprecating-radius, Message-Authenticator MUST
	 * be the first attribute in Access-Request responses (BLAST RADIUS).
	 * Not required for Accounting-Response. Unchanged from
	 * rc_send_server_ctx()'s own, identical check (f6f2487). */
	if (type == AUTH) {
		pkt_buf mb;
		uint8_t mtype, mlen;
		int has_ma = 0;

		pb_init_read(&mb, recv_buf + AUTH_HDR_LEN, (size_t)length, (size_t)length);
		while (pb_len(&mb) > 0) {
			assert(pb_peek_byte(&mb, 0, &mtype) == 0);
			assert(pb_peek_byte(&mb, 1, &mlen) == 0);
			if (mtype == PW_MESSAGE_AUTHENTICATOR) {
				has_ma = 1;
				break;
			}
			assert(pb_pull(&mb, mlen) == 0);
		}

		if (has_ma) {
			if (validate_message_authenticator(recv_buf, (size_t)length, secret, vector)) {
				rc_log(LOG_ERR, "%s: %s:%d: received attribute Message-Authenticator is incorrect",
				       __func__, server_name, svc_port);
				return ERROR_RC;
			}
		}

		if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS) {
			if (length == 0 || recv_buf[AUTH_HDR_LEN] != PW_MESSAGE_AUTHENTICATOR) {
				char *p = rc_conf_str_id(rh, OPT_REQUIRE_MESSAGE_AUTHENTICATOR);
				if (p == NULL || (strcasecmp(p, "false") != 0 &&
						  strcasecmp(p, "no") != 0)) {
					rc_log(LOG_ERR, "%s: %s:%d: required attribute Message-Authenticator "
					       "is missing or not first", __func__, server_name, svc_port);
					return ERROR_RC;
				}
			}
		}
	}

	{
		uint8_t code = recv_auth->code; /* memmove() below invalidates recv_auth */

		*recv_len = (size_t)length;
		if (out_code)
			*out_code = code;
		if (recv_buf_cap > (size_t)AUTH_HDR_LEN)
			memmove(recv_buf, recv_buf + AUTH_HDR_LEN, (size_t)length);

		switch (code) {
		case PW_ACCESS_ACCEPT:
		case PW_PASSWORD_ACK:
		case PW_ACCOUNTING_RESPONSE:
			return OK_RC;
		case PW_ACCESS_REJECT:
		case PW_PASSWORD_REJECT:
			return REJECT_RC;
		case PW_ACCESS_CHALLENGE:
			return CHALLENGE_RC;
		default:
			rc_log(LOG_ERR, "%s: received RADIUS server response neither ACCEPT nor "
			       "REJECT, code=%d is invalid", __func__, code);
			return BADRESP_RC;
		}
	}
}

/*- Representation-agnostic send/retry/receive core, shared by
 * rc_send_server_ctx() (legacy VALUE_PAIR API) and lib/request.c's
 * radcli_request_perform() (radcli2 API): resolves server_name (or takes
 * mgmt_secret's pre-resolved addr_info-only path for a management/CoA
 * response), holds the configured network namespace switched for the
 * whole call, sends send_buf once per address/retry, and, for each address
 * in resolution order, retries up to retries times waiting timeout seconds
 * per attempt -- moving to the next address only once the current one is
 * exhausted. On a datagram, validates it via rc_check_reply() (RFC 2865
 * SS3 Response Authenticator + Identifier match) and, unless rh's
 * transport is TLS/DTLS, validate_message_authenticator() (RFC 2869
 * SS5.14), discarding anything that fails either and continuing to wait.
 *
 * @param rh a handle to parsed configuration.
 * @param ctx if non-NULL and *ctx is NULL, filled via populate_ctx() with
 *  the secret/vector actually used.
 * @param server_name the server to resolve and contact.
 * @param svc_port overrides the resolved port when non-zero.
 * @param secret the shared secret; radcli2_priv_find_server_addr() may
 *  overwrite it when mgmt_secret is 0.
 * @param mgmt_secret nonzero to skip server-name lookup in rh's configured
 *  server list and resolve server_name directly (the CoA/Disconnect reply
 *  path, whose peer is the DAC that sent the request, not a configured
 *  RADIUS server).
 * @param timeout per-attempt reply wait, in seconds.
 * @param retries additional retransmit attempts after the first, per
 *  address.
 * @param no_wait nonzero to send once and return without waiting for a
 *  reply (accounting fire-and-forget).
 * @param type AUTH or ACCT.
 * @param send_buf the complete, pre-built, pre-encoded packet to send;
 *  its Identifier (send_buf[1]) and Request Authenticator (send_buf+4)
 *  are reused to validate the reply.
 * @param send_len send_buf's length in bytes.
 * @param recv_buf filled with the reply's attributes (header stripped) on
 *  a terminal OK_RC/REJECT_RC/CHALLENGE_RC.
 * @param recv_buf_cap recv_buf's capacity in bytes.
 * @param recv_len set to the number of attribute bytes written to recv_buf.
 * @param out_code if non-NULL, set to the reply's RADIUS code on a
 *  terminal result.
 * @return OK_RC/REJECT_RC/CHALLENGE_RC on a validated reply, TIMEOUT_RC if
 *  every address's retries were exhausted, ERROR_RC on failure.
 -*/
int radcli_transport_exchange(rc_handle *rh, RC_AAA_CTX **ctx,
			      char *server_name, unsigned short svc_port,
			      char secret[MAX_SECRET_LENGTH + 1], int mgmt_secret,
			      int timeout, int retries, int no_wait, rc_type type,
			      const uint8_t *send_buf, int send_len,
			      uint8_t *recv_buf, size_t recv_buf_cap, size_t *recv_len,
			      uint8_t *out_code)
{
	struct addrinfo *auth_addr = NULL, *cur_addr;
	const rc_sockets_override *sfuncs;
	int sockfd = -1;
	int result = 0;
	char *ns = NULL;
	int ns_def_hdl = 0;
	char *server_type = (type == ACCT) ? "acct" : "auth";
	const unsigned char *vector = send_buf + 4; /* AUTH_HDR: code(1) id(1) length(2) vector(16) */
	uint8_t seq_nbr = send_buf[1];
	int is_radsec = (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS);

	if (server_name == NULL || server_name[0] == '\0')
		return ERROR_RC;
	if (send_len < AUTH_HDR_LEN)
		return ERROR_RC;

	ns = rc_conf_str_id(rh, OPT_NAMESPACE);
	if (ns != NULL) {
		if (-1 == rc_set_netns(ns, &ns_def_hdl)) {
			rc_log(LOG_ERR, "radcli_transport_exchange: namespace %s set failed", ns);
			return ERROR_RC;
		}
	}

	if (mgmt_secret) {
		auth_addr = rc_getaddrinfo(server_name, type == AUTH ? PW_AI_AUTH : PW_AI_ACCT);
		if (auth_addr == NULL) {
			result = ERROR_RC;
			goto exit_error;
		}
	} else {
		if (radcli2_priv_find_server_addr(rh, server_name, &auth_addr, secret, type) != 0) {
			rc_log(LOG_ERR, "radcli_transport_exchange: unable to find server: %s",
			       server_name);
			result = ERROR_RC;
			goto exit_error;
		}
	}

	sfuncs = &rh->so;

	if (sfuncs->static_secret) {
		/* any static secret set in sfuncs overrides the configured/resolved one */
		strlcpy(secret, sfuncs->static_secret, MAX_SECRET_LENGTH + 1);
	}

	if (sfuncs->lock) {
		if (sfuncs->lock(sfuncs->ptr) != 0) {
			rc_log(LOG_ERR, "%s: lock error", __func__);
			result = ERROR_RC;
			goto exit_error;
		}
	}

	result = TIMEOUT_RC; /* if every address is unreachable/times out */

	for (cur_addr = auth_addr; cur_addr != NULL; cur_addr = cur_addr->ai_next) {
		struct sockaddr_storage our_sockaddr;
		unsigned discover_local_ip;
		int retry_max = retries;
		int this_retries = 0;

		if (svc_port) {
			if (cur_addr->ai_family == AF_INET)
				((struct sockaddr_in *)cur_addr->ai_addr)->sin_port = htons(svc_port);
			else
				((struct sockaddr_in6 *)cur_addr->ai_addr)->sin6_port = htons(svc_port);
		}

		rc_own_bind_addr(rh, &our_sockaddr);
		discover_local_ip = 0;
		if (our_sockaddr.ss_family == AF_INET &&
		    ((struct sockaddr_in *)(&our_sockaddr))->sin_addr.s_addr == INADDR_ANY)
			discover_local_ip = 1;

		if (discover_local_ip) {
			result = radcli2_priv_get_srcaddr(SA(&our_sockaddr), cur_addr->ai_addr);
			if (result != OK_RC) {
				rc_log(LOG_ERR, "radcli_transport_exchange: cannot figure our own address");
				continue; /* try the next resolved address, if any */
			}
		}

		if (sfuncs->get_fd) {
			sockfd = sfuncs->get_fd(sfuncs->ptr, SA(&our_sockaddr));
			if (sockfd < 0) {
				rc_log(LOG_ERR, "radcli_transport_exchange: socket: %s", strerror(errno));
				result = ERROR_RC;
				continue;
			}
		}

		if (our_sockaddr.ss_family == AF_INET6) {
			char *non_temp_addr = rc_conf_str_id(rh, OPT_USE_PUBLIC_ADDR);
			if (non_temp_addr && strcasecmp(non_temp_addr, "true") == 0) {
#if defined(__linux__)
				int sock_opt = IPV6_PREFER_SRC_PUBLIC;
				if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES,
					       &sock_opt, sizeof(sock_opt)) != 0) {
					rc_log(LOG_ERR, "radcli_transport_exchange: setsockopt: %s",
					       strerror(errno));
					result = ERROR_RC;
					SCLOSE(sockfd);
					continue;
				}
#elif defined(BSD) || defined(__APPLE__)
				int sock_opt = 0;
				if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR,
					       &sock_opt, sizeof(sock_opt)) != 0) {
					rc_log(LOG_ERR, "radcli_transport_exchange: setsockopt: %s",
					       strerror(errno));
					result = ERROR_RC;
					SCLOSE(sockfd);
					continue;
				}
#else
				rc_log(LOG_INFO, "radcli_transport_exchange: Usage of non-temporary "
				       "IPv6 address is not supported in this system");
#endif
			}
		}

		if (rh->debug) {
			char our_addr_txt[50] = "", addr_txt[50] = "";

			getnameinfo(SA(&our_sockaddr), SS_LEN(&our_sockaddr), NULL, 0,
				    our_addr_txt, sizeof(our_addr_txt), NI_NUMERICHOST);
			getnameinfo(cur_addr->ai_addr, cur_addr->ai_addrlen, NULL, 0,
				    addr_txt, sizeof(addr_txt), NI_NUMERICHOST);
			DEBUG(rh, LOG_ERR,
			      "DEBUG: radcli_transport_exchange: timeout=%d retries=%d local %s : 0, "
			      "remote %s : %u\n", timeout, retry_max, our_addr_txt, addr_txt, svc_port);
		}

		for (;;) {
			socklen_t salen;
			int recv_length;
			struct pollfd pfd;
			double deadline;

			do {
				result = sfuncs->sendto(sfuncs->ptr, sockfd, (const char *)send_buf,
							(unsigned int)send_len, 0,
							SA(cur_addr->ai_addr), cur_addr->ai_addrlen);
			} while (result == -1 && errno == EINTR);
			if (result == -1) {
				result = errno == ENETUNREACH ? NETUNREACH_RC : ERROR_RC;
				rc_log(LOG_ERR, "%s: socket: %s", __FUNCTION__, strerror(errno));
				break; /* try the next address */
			}

			if (no_wait) {
				SCLOSE(sockfd);
				result = populate_ctx(ctx, secret, (unsigned char *)vector);
				goto cleanup; /* first address only -- no reply to judge a retry by */
			}

			if (sfuncs->get_active_fd) {
				int new_fd = sfuncs->get_active_fd(sfuncs->ptr);
				if (new_fd >= 0)
					sockfd = new_fd;
			}

			/* Wait out this attempt's whole timeout for our own reply:
			 * a reply that is not ours only continues the wait, it does
			 * not end the attempt (REQ-NET-NET-010). */
			deadline = rc_getmtime() + timeout;
			for (;;) {
				double remaining = deadline - rc_getmtime();

				if (remaining <= 0)
					break;
				/* A record GnuTLS already holds raises no POLLIN. */
				if (!(is_radsec && radcli2_priv_tls_pending(rh))) {
					pfd.fd = sockfd;
					pfd.events = POLLIN;
					pfd.revents = 0;
					do {
						result = poll(&pfd, 1, (int)(remaining * 1000) + 1);
					} while (result == -1 && errno == EINTR);

					if (result == -1) {
						rc_log(LOG_ERR, "radcli_transport_exchange: poll: %s",
						       strerror(errno));
						SCLOSE(sockfd);
						result = ERROR_RC;
						goto cleanup;
					}
					if (result == 0 || (pfd.revents & POLLIN) == 0)
						break;
				}

				salen = cur_addr->ai_addrlen;
				do {
					recv_length = sfuncs->recvfrom(sfuncs->ptr, sockfd,
									(char *)recv_buf,
									(int)recv_buf_cap, 0,
									SA(cur_addr->ai_addr), &salen);
				} while (recv_length == -1 && errno == EINTR);

				if (recv_length <= 0) {
					int e = errno;
					rc_log(LOG_ERR, "radcli_transport_exchange: recvfrom: %s:%d: %s",
					       server_name, svc_port, strerror(e));
					if (recv_length == -1 && e == EAGAIN)
						continue;
					SCLOSE(sockfd);
					result = ERROR_RC;
					goto cleanup;
				}

				{
					AUTH_HDR *recv_auth = (AUTH_HDR *)recv_buf;

					/* RFC 6614 SS2.1/SS2.5, RFC 7360 SS2.2: the session
					 * carries every packet type; what is not this
					 * exchange's reply goes where it belongs
					 * (REQ-NET2-NET-004). */
					if (is_radsec && (recv_buf[0] == RADCLI_DISCONNECT_REQUEST ||
							  recv_buf[0] == RADCLI_COA_REQUEST)) {
						radcli2_priv_radsec_route(rh, recv_buf, recv_buf_cap,
									  recv_length);
						continue;
					}

					if (recv_length < AUTH_HDR_LEN ||
					    recv_length < ntohs(recv_auth->length)) {
						rc_log(LOG_ERR, "radcli_transport_exchange: recvfrom: "
						       "%s:%d: reply is too short", server_name, svc_port);
						SCLOSE(sockfd);
						result = ERROR_RC;
						goto cleanup;
					}

					if (is_radsec && recv_auth->id != seq_nbr) {
						radcli2_priv_radsec_route(rh, recv_buf, recv_buf_cap,
									  recv_length);
						continue;
					}

					result = rc_check_reply(recv_auth, (int)recv_buf_cap, secret,
								vector, seq_nbr);
					if (result == OK_RC)
						goto got_reply; /* out of every loop */
					/* BADRESPID_RC (some other packet arrived, e.g. a stale
					 * retransmit's answer) and BADRESP_RC (bad length or
					 * Response Authenticator -- possibly spoofed) are both
					 * treated as "not our reply yet": keep waiting rather
					 * than handing an unverified packet to decode_reply(),
					 * which trusts its caller to have already validated it
					 * (REQ-GEN-STYLE-009). */
				}
			}

			if (this_retries++ >= retry_max) {
				char server_ip[128];
				struct sockaddr_in *si = (struct sockaddr_in *)cur_addr->ai_addr;

				inet_ntop(cur_addr->ai_family, &si->sin_addr, server_ip, sizeof(server_ip));
				rc_log(LOG_ERR, "radcli_transport_exchange: no reply from RADIUS "
				       "%s server %s:%u", server_type, server_ip, svc_port);
				result = TIMEOUT_RC;
				break; /* try the next address */
			}
		}

		SCLOSE(sockfd);
	}

	/* Every resolved address was tried without a valid reply. */
	goto cleanup_nosock;

 got_reply:
	result = decode_reply(rh, ctx, server_name, svc_port, type, secret, vector,
			      recv_buf, recv_buf_cap, recv_len, out_code);

 cleanup:
	if (sockfd >= 0)
		SCLOSE(sockfd);
 cleanup_nosock:
	if (auth_addr)
		freeaddrinfo(auth_addr);
	if (sfuncs->unlock) {
		if (sfuncs->unlock(sfuncs->ptr) != 0)
			rc_log(LOG_ERR, "%s: unlock error", __func__);
	}
 exit_error:
	if (ns != NULL) {
		if (-1 == rc_reset_netns(&ns_def_hdl)) {
			rc_log(LOG_ERR, "radcli_transport_exchange: namespace %s reset failed", ns);
			result = ERROR_RC;
		}
	}

	return result;
}

/* Compares two sockaddrs' family+address+port -- REQ-NET2-SEND-016's
 * explicit reply-source check on the shared, unconnected UDP request
 * socket (replacing the kernel-level filtering a connect()ed per-request
 * socket used to give for free). */
static int reqreg_peer_matches(const struct sockaddr *from, const struct sockaddr *expected)
{
	if (from->sa_family != expected->sa_family)
		return 0;
	if (from->sa_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)from;
		const struct sockaddr_in *b = (const struct sockaddr_in *)expected;
		return a->sin_port == b->sin_port &&
		       memcmp(&a->sin_addr, &b->sin_addr, sizeof(a->sin_addr)) == 0;
	}
	{
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)from;
		const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)expected;
		return a->sin6_port == b->sin6_port &&
		       memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0;
	}
}

/* Lazily allocates rh->reqreg (REQ-NET2-SEND-016). */
static int reqreg_ensure(rc_handle *rh)
{
	if (rh->reqreg != NULL)
		return 0;

	rh->reqreg = calloc(1, sizeof(*rh->reqreg));
	return rh->reqreg != NULL ? 0 : -1;
}

/*- Mark reg's least-recently-used free slot in use (RFC 5080 SS2.1.1),
 * not yet armed, and return its index -- the Identifier.
 *
 * @param reg the registry to take a slot from.
 * @param owner stored on the slot; NULL for a blocking request or watchdog,
 *  whose reply is never delivered through the registry.
 * @return the slot index, or -1 (logged) if every slot is in use.
 -*/
static int reqreg_take_lru(struct radcli_reqreg *reg, struct radcli_async_send_st *owner)
{
	int best = -1;
	uint64_t best_seq = 0;
	int i;

	for (i = 0; i < RADCLI_CTX_MAX_INFLIGHT; i++) {
		if (reg->slots[i].valid)
			continue;
		/* LRU: the slot free the longest wins; free_seq == 0 (never
		 * used yet) sorts first automatically. */
		if (best == -1 || reg->slots[i].free_seq < best_seq) {
			best = i;
			best_seq = reg->slots[i].free_seq;
		}
	}
	if (best == -1) {
		rc_log(LOG_ERR, "%s: no free Identifier (%d requests already in flight)",
		       __func__, RADCLI_CTX_MAX_INFLIGHT);
		return -1;
	}
	reg->slots[best].valid = 1;
	reg->slots[best].armed = 0;
	reg->slots[best].owner = owner;
	return best;
}

/*- Reserve a slot in rh's in-flight registry (REQ-NET2-SEND-016),
 * allocating the registry itself on first use. The Identifier is chosen by
 * least-recently-used selection among currently-free slots (RFC 5080
 * SS2.1.1), never randomly and never a fixed counter -- see
 * REQ-NET2-SEND-010/016. The slot is marked valid (excluded from future
 * reservation) but not yet armed: radcli_transport_send_async() arms it
 * once the packet -- built using the returned id, per
 * radcli_encode_request()'s forced_id parameter -- has actually been sent.
 *
 * @param rh a handle to parsed configuration.
 * @param owner stored on the slot; written to directly by drain()/
 *  service_timeouts() on delivery.
 * @param out_id set to the reserved Identifier (== the slot index) on success.
 * @return the reserved slot index (0..RADCLI_CTX_MAX_INFLIGHT-1) on success,
 *  -1 if the registry is full or allocation failed.
 -*/
int radcli2_priv_reqreg_reserve(rc_handle *rh, struct radcli_async_send_st *owner, uint8_t *out_id)
{
	int best;

	if (rh == NULL || owner == NULL || out_id == NULL)
		return -1;
	if (reqreg_ensure(rh) != 0)
		return -1;

	best = reqreg_take_lru(rh->reqreg, owner);
	if (best == -1)
		return -1;

	*out_id = (uint8_t)best;
	return best;
}

/*- Choose the Identifier for a blocking request or watchdog
 * (REQ-NET2-SEND-010): reserved from the in-flight registry when one exists
 * on a TLS/DTLS session, shared with RADCLI_REQUEST_SENDONLY requests;
 * drawn at random otherwise.
 *
 * @param rh a handle to parsed configuration.
 * @param out_id set to the Identifier to use.
 * @param out_slot set to the reserved slot, to release once the exchange
 *  ends, or to -1 when nothing was reserved.
 * @return 0 on success, -1 if every Identifier is in flight.
 -*/
int radcli2_priv_reqreg_pick_id(rc_handle *rh, uint8_t *out_id, int *out_slot)
{
	*out_slot = -1;
	if ((rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS) &&
	    rh->reqreg != NULL) {
		int slot = reqreg_take_lru(rh->reqreg, NULL);

		if (slot == -1)
			return -1;
		*out_id = (uint8_t)slot;
		*out_slot = slot;
		return 0;
	}
	*out_id = rc_get_random_byte();
	return 0;
}

/*- Unconditionally vacate slot (valid=0, armed=0, owner=NULL, secret
 * scrubbed, LRU-stamped free per REQ-NET2-SEND-016), making its Identifier
 * available for reuse. Used both to undo a reservation
 * radcli_transport_send_async() failed to arm, and by
 * radcli_transport_async_abort() for a still-active, undelivered exchange. -*/
void radcli2_priv_reqreg_release(rc_handle *rh, int slot)
{
	struct radcli_reqreg *reg;

	if (rh == NULL || rh->reqreg == NULL || slot < 0 || slot >= RADCLI_CTX_MAX_INFLIGHT)
		return;
	reg = rh->reqreg;

	reg->slots[slot].valid = 0;
	reg->slots[slot].armed = 0;
	reg->slots[slot].owner = NULL;
	memset(reg->slots[slot].secret, 0, sizeof(reg->slots[slot].secret));
	reg->slots[slot].free_seq = ++reg->free_seq_ctr;
}

/*- Milliseconds remaining until the *earliest* deadline among every
 * currently armed slot on rh (0 if one is already due), or -1 if rh has no
 * registry yet or nothing is in flight. Used by lib/dae.c's
 * radcli_ctx_get_poll() to fold RADCLI_REQUEST_SENDONLY's retransmit/
 * timeout deadlines into its own timeout_ms, alongside DAE/watchdog
 * deadlines (REQ-NET2-NET-001). -*/
int radcli2_priv_reqreg_earliest_deadline_ms(rc_handle *rh)
{
	struct radcli_reqreg *reg;
	double earliest = 0;
	int have_one = 0;
	int i;

	if (rh == NULL || rh->reqreg == NULL)
		return -1;
	reg = rh->reqreg;

	for (i = 0; i < RADCLI_CTX_MAX_INFLIGHT; i++) {
		if (!reg->slots[i].valid || !reg->slots[i].armed)
			continue;
		if (!have_one || reg->slots[i].deadline < earliest) {
			earliest = reg->slots[i].deadline;
			have_one = 1;
		}
	}

	if (!have_one)
		return -1;

	{
		double remaining = earliest - rc_getmtime();

		if (remaining <= 0)
			return 0;
		return (int)(remaining * 1000) + 1;
	}
}

/*- Hand one received reply to the in-flight registry slot it answers,
 * validating it (REQ-NET2-SEND-016/017) and writing the outcome onto the
 * slot's owner (struct radcli_async_send_st).
 *
 * @param rh a handle to parsed configuration.
 * @param recv_buf the reply; modified in place (rc_check_reply()/
 *  decode_reply()).
 * @param recv_buf_cap recv_buf's capacity in bytes.
 * @param recv_length the number of bytes received into recv_buf.
 * @param from the datagram's source for the UDP source check, or NULL on a
 *  RadSec session, whose peer is already authenticated.
 * @return 1 if the reply resolved a slot, 0 if it was discarded.
 -*/
static int reqreg_deliver(rc_handle *rh, uint8_t *recv_buf, size_t recv_buf_cap,
			  int recv_length, const struct sockaddr *from)
{
	struct radcli_reqreg *reg = rh->reqreg;
	AUTH_HDR *recv_auth = (AUTH_HDR *)recv_buf;
	struct radcli_reqreg_slot *rslot;
	uint8_t id;

	if (reg == NULL)
		return 0;
	/* The caller's buffer is reused across reads: bytes past a short
	 * read belong to an earlier datagram (REQ-NET2-SEND-017). */
	if ((size_t)recv_length < AUTH_HDR_LEN || recv_length < ntohs(recv_auth->length))
		return 0;
	id = recv_auth->id;

	rslot = &reg->slots[id];
	if (rslot->valid && !rslot->armed && id == rh->watchdog_slot) {
		/* The watchdog's reply only frees its Identifier (REQ-NET2-SEND-010). */
		radcli2_priv_reqreg_release(rh, id);
		rh->watchdog_slot = -1;
		return 1;
	}
	if (!rslot->valid || !rslot->armed)
		return 0; /* no in-flight exchange for this Identifier */
	if (from != NULL && !reqreg_peer_matches(from, SA(&rslot->peer)))
		return 0;

	if (rc_check_reply(recv_auth, (int)recv_buf_cap, rslot->secret,
			   rslot->vector, id) != OK_RC) {
		/* BADRESPID_RC (unreachable: id already matched above)
		 * or BADRESP_RC (bad length or Response Authenticator --
		 * possibly spoofed) -- keep the slot waiting rather than
		 * handing an unverified packet to decode_reply(),
		 * matching the pre-registry single-exchange semantics
		 * (REQ-GEN-STYLE-009). */
		return 0;
	}

	{
		struct radcli_async_send_st *owner = rslot->owner;
		char secret_copy[MAX_SECRET_LENGTH + 1];
		unsigned char vector_copy[AUTH_VECTOR_LEN];
		char server_name_copy[128];
		unsigned short svc_port_copy;
		rc_type type_copy;
		size_t recv_len = 0;
		uint8_t reply_code = 0;
		int decode_result;
		radcli_avp_list *attrs = NULL;

		memcpy(secret_copy, rslot->secret, sizeof(secret_copy));
		memcpy(vector_copy, rslot->vector, sizeof(vector_copy));
		memcpy(server_name_copy, rslot->server_name, sizeof(server_name_copy));
		svc_port_copy = rslot->svc_port;
		type_copy = rslot->type;

		/* Vacate now, before decode_reply()/radcli_avp_decode()
		 * run: RFC 5080 SS2.1.1 permits reuse as soon as a valid
		 * response is received, not once the application
		 * collects it (REQ-NET2-SEND-016). */
		rslot->valid = 0;
		rslot->armed = 0;
		rslot->owner = NULL;
		memset(rslot->secret, 0, sizeof(rslot->secret));
		rslot->free_seq = ++reg->free_seq_ctr;

		decode_result = decode_reply(rh, NULL, server_name_copy, svc_port_copy,
					     type_copy, secret_copy, vector_copy,
					     recv_buf, recv_buf_cap, &recv_len, &reply_code);
		if (decode_result == OK_RC || decode_result == REJECT_RC ||
		    decode_result == CHALLENGE_RC) {
			if (recv_len > 0 &&
			    radcli_avp_decode(rh, secret_copy, vector_copy, recv_buf, recv_len, 0,
					      &attrs) != 0)
				decode_result = ERROR_RC;
		}
		memset(secret_copy, 0, sizeof(secret_copy));

		owner->result = decode_result;
		owner->reply_code = reply_code;
		owner->reply_attrs = attrs;
		owner->delivered = 1;
	}
	return 1;
}

/*- Route one record read from rh's RadSec session to what it belongs to
 * -- the single routing point for every reader of the session
 * (REQ-NET2-NET-004): a Disconnect-/CoA-Request to the DAE pipeline, a
 * reply to the in-flight registry slot it answers; anything else is
 * dropped.
 *
 * @param rh a handle to parsed configuration.
 * @param buf the record; modified in place.
 * @param cap buf's capacity in bytes.
 * @param len the record's length in bytes.
 * @return RADSEC_ROUTE_DAE, RADSEC_ROUTE_REPLY, or RADSEC_ROUTE_DROPPED.
 -*/
int radcli2_priv_radsec_route(rc_handle *rh, uint8_t *buf, size_t cap, int len)
{
	if (len >= 1 && (buf[0] == RADCLI_DISCONNECT_REQUEST || buf[0] == RADCLI_COA_REQUEST)) {
		radcli2_priv_dae_on_radsec_packet(rh, buf, (size_t)len);
		return RADSEC_ROUTE_DAE;
	}
	if (reqreg_deliver(rh, buf, cap, len, NULL))
		return RADSEC_ROUTE_REPLY;
	rc_log(LOG_INFO, "%s: record with code %u matches nothing in flight on the "
	       "RadSec session, ignored", __func__, len >= 1 ? (unsigned)buf[0] : 0U);
	return RADSEC_ROUTE_DROPPED;
}

/*- Drain every ready datagram on ctx's shared UDP request socket
 * (rh->req_fd) into the in-flight registry, with explicit source-address
 * validation since the socket is shared and unconnected
 * (REQ-NET2-SEND-016). A no-op if no RADCLI_REQUEST_SENDONLY exchange
 * ever opened the socket. Never blocks. -*/
void radcli2_priv_reqreg_drain(rc_handle *rh)
{
	const rc_sockets_override *sfuncs;
	char *ns;

	if (rh == NULL || rh->reqreg == NULL || rh->req_fd == -1)
		return;
	sfuncs = &rh->so;
	ns = rc_conf_str_id(rh, OPT_NAMESPACE);

	for (;;) {
		uint8_t recv_buf[RC_BUFFER_LEN];
		struct sockaddr_storage from;
		socklen_t fromlen = sizeof(from);
		int recv_length;
		int ns_def_hdl = 0;

		if (ns != NULL && -1 == rc_set_netns(ns, &ns_def_hdl)) {
			rc_log(LOG_ERR, "%s: namespace %s set failed", __func__, ns);
			return;
		}
		do {
			recv_length = sfuncs->recvfrom(sfuncs->ptr, rh->req_fd, (char *)recv_buf,
							sizeof(recv_buf), 0, SA(&from), &fromlen);
		} while (recv_length == -1 && errno == EINTR);
		if (ns != NULL)
			rc_reset_netns(&ns_def_hdl);

		if (recv_length <= 0)
			return; /* nothing more ready, or a socket error no slot can act on */

		reqreg_deliver(rh, recv_buf, sizeof(recv_buf), recv_length, SA(&from));
	}
}

/*- Read every record already available on rh's RadSec session and route
 * each (radcli2_priv_radsec_route()), stopping after a DAE request so that
 * a burst of them re-arms the caller's loop one per call. Never blocks. -*/
void radcli2_priv_radsec_drain(rc_handle *rh)
{
	for (;;) {
		uint8_t recv_buf[RC_BUFFER_LEN];
		int recv_length;

		recv_length = radcli2_priv_tls_try_recv(rh, recv_buf, sizeof(recv_buf));
		if (recv_length <= 0)
			return;
		if (radcli2_priv_radsec_route(rh, recv_buf, sizeof(recv_buf), recv_length) ==
		    RADSEC_ROUTE_DAE)
			return;
	}
}

/*- Service every registry slot whose retransmit/timeout deadline has
 * passed: retransmit (if retries remain) or resolve as TIMEOUT_RC
 * (vacating the slot), writing the outcome directly onto the owning struct
 * radcli_async_send_st. A no-op if rh->reqreg is NULL. Never blocks. -*/
void radcli2_priv_reqreg_service_timeouts(rc_handle *rh)
{
	struct radcli_reqreg *reg;
	const rc_sockets_override *sfuncs;
	int is_radsec;
	char *ns;
	int i;

	if (rh == NULL || rh->reqreg == NULL)
		return;
	reg = rh->reqreg;
	sfuncs = &rh->so;
	is_radsec = (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS);
	ns = rc_conf_str_id(rh, OPT_NAMESPACE);

	for (i = 0; i < RADCLI_CTX_MAX_INFLIGHT; i++) {
		struct radcli_reqreg_slot *rslot = &reg->slots[i];

		if (!rslot->valid || !rslot->armed || rc_getmtime() < rslot->deadline)
			continue;

		if (rslot->retries_left-- <= 0) {
			struct radcli_async_send_st *owner = rslot->owner;
			char server_name_copy[128];
			unsigned short svc_port_copy = rslot->svc_port;

			memcpy(server_name_copy, rslot->server_name, sizeof(server_name_copy));
			rslot->valid = 0;
			rslot->armed = 0;
			rslot->owner = NULL;
			memset(rslot->secret, 0, sizeof(rslot->secret));
			rslot->free_seq = ++reg->free_seq_ctr;

			rc_log(LOG_ERR, "%s: no reply from RADIUS server %s:%u",
			       __func__, server_name_copy, svc_port_copy);
			owner->result = TIMEOUT_RC;
			owner->reply_code = 0;
			owner->reply_attrs = NULL;
			owner->delivered = 1;
			continue;
		}

		if (is_radsec) {
			/* Never waits for write room: a retransmit the session
			 * cannot take now is queued, or skipped like a lost packet
			 * when the queue is full (REQ-NET2-NET-005); either way its
			 * timeout runs on. */
			radcli2_priv_tls_send_queued(rh, rslot->send_buf, (size_t)rslot->send_len,
						     RADSEC_SEND_RETRANSMIT);
			rslot->deadline = rc_getmtime() + rslot->timeout;
			continue;
		}

		{
			int ns_def_hdl = 0;
			int sresult;

			if (rh->req_fd == -1)
				continue;

			if (ns != NULL && -1 == rc_set_netns(ns, &ns_def_hdl)) {
				rc_log(LOG_ERR, "%s: namespace %s set failed", __func__, ns);
				continue;
			}

			do {
				sresult = sfuncs->sendto(sfuncs->ptr, rh->req_fd, (const char *)rslot->send_buf,
							 (unsigned int)rslot->send_len, 0,
							 SA(&rslot->peer), rslot->peer_len);
			} while (sresult == -1 && errno == EINTR);

			if (ns != NULL)
				rc_reset_netns(&ns_def_hdl);

			if (sresult == -1) {
				rc_log(LOG_ERR, "%s: sendto: %s", __func__, strerror(errno));
				continue; /* leave deadline as-is; retried again next call */
			}

			rslot->deadline = rc_getmtime() + rslot->timeout;
		}
	}
}

/*- Begin an async (poll-driven) send: reserve slot in rh's in-flight
 * registry, resolve server_name to its first address only (no DNS
 * fail-over, matching radcli_transport_exchange()'s own no_wait
 * simplification), send send_buf once over ctx's shared, persistent
 * request socket (UDP, opened lazily here if not already; TLS/DTLS reuses
 * the session, establishing it if needed), and arm the slot for
 * radcli_ctx_dispatch() to drive to completion -- REQ-NET2-SEND-016.
 *
 * Unlike radcli_transport_exchange(), does not itself hold the configured
 * network namespace (lib/util.c's rc_set_netns()) switched for its whole
 * duration: namespace membership is per-thread, and this call, unlike a
 * blocking exchange, returns to a caller's event loop that may run other
 * socket I/O on the same thread before radcli_ctx_dispatch() is next
 * called -- switching once and resetting only at the very end would leak
 * the RADIUS server's namespace into that other I/O. Instead, each of this
 * function and the registry's drain/retransmit helpers brackets only its
 * own, brief syscall(s) with a set/reset pair.
 *
 * @param rh a handle to parsed configuration.
 * @param slot the registry slot radcli2_priv_reqreg_reserve() already
 *  reserved for this exchange -- its Identifier MUST already be baked into
 *  send_buf (radcli_encode_request()'s forced_id), not patched in here.
 * @param server_name the server to resolve and contact.
 * @param svc_port overrides the resolved port when non-zero.
 * @param secret the shared secret; radcli2_priv_find_server_addr() may
 *  overwrite it, exactly as radcli_transport_exchange() does.
 * @param type AUTH or ACCT.
 * @param send_buf the complete, pre-built, pre-encoded packet to send.
 * @param send_len send_buf's length in bytes; must fit RC_BUFFER_LEN.
 * @param timeout per-attempt reply wait, in seconds.
 * @param retries additional retransmit attempts after the first.
 * @param out zeroed, then filled in on success; left inactive (out->active
 *  == 0) on failure -- the caller MUST then release slot itself
 *  (radcli2_priv_reqreg_release()), since this function does not on failure
 *  (the reservation is the caller's, made before encoding).
 * @return OK_RC once the first packet is on the wire, ERROR_RC on failure.
 -*/
int radcli_transport_send_async(rc_handle *rh, int slot, char *server_name, unsigned short svc_port,
				char secret[MAX_SECRET_LENGTH + 1], rc_type type,
				const uint8_t *send_buf, int send_len,
				int timeout, int retries,
				struct radcli_async_send_st *out)
{
	struct addrinfo *auth_addr = NULL;
	const rc_sockets_override *sfuncs;
	struct sockaddr_storage our_sockaddr;
	unsigned discover_local_ip;
	struct radcli_reqreg *reg;
	struct radcli_reqreg_slot *rslot;
	char *ns = NULL;
	int ns_def_hdl = 0;
	int sockfd = -1;
	int is_radsec;
	int result;

	memset(out, 0, sizeof(*out));

	if (rh == NULL || rh->reqreg == NULL || slot < 0 || slot >= RADCLI_CTX_MAX_INFLIGHT)
		return ERROR_RC;
	reg = rh->reqreg;
	rslot = &reg->slots[slot];
	is_radsec = (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS);

	if (server_name == NULL || server_name[0] == '\0')
		return ERROR_RC;
	if (send_len < AUTH_HDR_LEN || (size_t)send_len > sizeof(rslot->send_buf))
		return ERROR_RC;

	ns = rc_conf_str_id(rh, OPT_NAMESPACE);
	if (ns != NULL) {
		if (-1 == rc_set_netns(ns, &ns_def_hdl)) {
			rc_log(LOG_ERR, "%s: namespace %s set failed", __func__, ns);
			return ERROR_RC;
		}
	}

	if (radcli2_priv_find_server_addr(rh, server_name, &auth_addr, secret, type) != 0) {
		rc_log(LOG_ERR, "%s: unable to find server: %s", __func__, server_name);
		result = ERROR_RC;
		goto exit_error;
	}

	sfuncs = &rh->so;

	if (sfuncs->static_secret)
		strlcpy(secret, sfuncs->static_secret, MAX_SECRET_LENGTH + 1);

	if (svc_port) {
		if (auth_addr->ai_family == AF_INET)
			((struct sockaddr_in *)auth_addr->ai_addr)->sin_port = htons(svc_port);
		else
			((struct sockaddr_in6 *)auth_addr->ai_addr)->sin6_port = htons(svc_port);
	}

	if (is_radsec) {
		/* get_fd(), not get_active_fd(): establishes the session if it
		 * is not up yet (REQ-NET2-SEND-012, REQ-NET-NET-019). */
		sockfd = sfuncs->get_fd(sfuncs->ptr, NULL);
		if (sockfd < 0) {
			rc_log(LOG_ERR, "%s: cannot establish the RadSec session", __func__);
			result = ERROR_RC;
			goto fail;
		}
	} else if (rh->req_fd != -1) {
		sockfd = rh->req_fd;
	} else {
		rc_own_bind_addr(rh, &our_sockaddr);
		discover_local_ip = 0;
		if (our_sockaddr.ss_family == AF_INET &&
		    ((struct sockaddr_in *)(&our_sockaddr))->sin_addr.s_addr == INADDR_ANY)
			discover_local_ip = 1;

		if (discover_local_ip) {
			/* REQ-NET2-SEND-016: this fixes the source address at
			 * first use (from whichever destination happens to
			 * trigger it), unlike the old per-request socket,
			 * which rediscovered it per destination -- acceptable
			 * on a single-homed host; a multi-homed one with no
			 * explicit bindaddr may get a suboptimal source
			 * address for a later request to a different
			 * destination (e.g. acctserver after authserver).
			 * Configure bindaddr explicitly to avoid this. */
			result = radcli2_priv_get_srcaddr(SA(&our_sockaddr), auth_addr->ai_addr);
			if (result != OK_RC) {
				rc_log(LOG_ERR, "%s: cannot figure our own address", __func__);
				result = ERROR_RC;
				goto fail;
			}
		}

		if (sfuncs->get_fd) {
			sockfd = sfuncs->get_fd(sfuncs->ptr, SA(&our_sockaddr));
			if (sockfd < 0) {
				rc_log(LOG_ERR, "%s: socket: %s", __func__, strerror(errno));
				result = ERROR_RC;
				goto fail;
			}
			/* REQ-NET2-SEND-016: radcli2_priv_reqreg_drain() loops
			 * recvfrom() on this socket until EAGAIN -- a blocking
			 * socket would hang the caller's entire event loop on
			 * the last, empty call instead of returning promptly. */
			if (radcli2_priv_set_nonblock_cloexec(sockfd) != 0) {
				rc_log(LOG_ERR, "%s: fcntl: %s", __func__, strerror(errno));
				result = ERROR_RC;
				if (sfuncs->close_fd)
					sfuncs->close_fd(sockfd);
				goto fail;
			}
			/* Commit immediately, not at the end of this branch: any
			 * later step failing (the IPv6 setsockopt below) must
			 * still leave a good, already-nonblocking socket in
			 * rh->req_fd for the next call to reuse, rather than
			 * leaking a freshly opened one that fail: below
			 * deliberately never closes (it may be an *already*
			 * persistent rh->req_fd from a previous call, which
			 * must never be closed just because this one send
			 * failed). */
			rh->req_fd = sockfd;
		}

		if (sockfd >= 0 && our_sockaddr.ss_family == AF_INET6) {
			char *non_temp_addr = rc_conf_str_id(rh, OPT_USE_PUBLIC_ADDR);
			if (non_temp_addr && strcasecmp(non_temp_addr, "true") == 0) {
#if defined(__linux__)
				int sock_opt = IPV6_PREFER_SRC_PUBLIC;
				if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES,
					       &sock_opt, sizeof(sock_opt)) != 0) {
					rc_log(LOG_ERR, "%s: setsockopt: %s", __func__, strerror(errno));
					result = ERROR_RC;
					goto fail;
				}
#elif defined(BSD) || defined(__APPLE__)
				int sock_opt = 0;
				if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR,
					       &sock_opt, sizeof(sock_opt)) != 0) {
					rc_log(LOG_ERR, "%s: setsockopt: %s", __func__, strerror(errno));
					result = ERROR_RC;
					goto fail;
				}
#else
				rc_log(LOG_INFO, "%s: Usage of non-temporary IPv6 address is not "
				       "supported in this system", __func__);
#endif
			}
		}
	}

	do {
		result = sfuncs->sendto(sfuncs->ptr, sockfd, (const char *)send_buf,
					(unsigned int)send_len, 0,
					SA(auth_addr->ai_addr), auth_addr->ai_addrlen);
	} while (result == -1 && errno == EINTR);
	if (result == -1) {
		rc_log(LOG_ERR, "%s: sendto: %s", __func__, strerror(errno));
		result = ERROR_RC;
		goto fail;
	}

	memcpy(&rslot->peer, auth_addr->ai_addr, auth_addr->ai_addrlen);
	rslot->peer_len = auth_addr->ai_addrlen;
	memcpy(rslot->send_buf, send_buf, (size_t)send_len);
	rslot->send_len = send_len;
	memcpy(rslot->vector, send_buf + 4, AUTH_VECTOR_LEN); /* AUTH_HDR: code(1) id(1) length(2) vector(16) */
	strlcpy(rslot->secret, secret, sizeof(rslot->secret));
	strlcpy(rslot->server_name, server_name, sizeof(rslot->server_name));
	rslot->svc_port = svc_port;
	rslot->type = type;
	rslot->timeout = timeout > 0 ? timeout : 1;
	rslot->retries_left = retries;
	rslot->deadline = rc_getmtime() + rslot->timeout;
	rslot->armed = 1;

	out->rh = rh;
	out->active = 1;
	out->slot = slot;
	out->delivered = 0;

	result = OK_RC;
	goto exit_ok;

 fail:
	memset(secret, '\0', MAX_SECRET_LENGTH + 1);
 exit_ok:
	if (auth_addr)
		freeaddrinfo(auth_addr);
 exit_error:
	if (ns != NULL) {
		if (-1 == rc_reset_netns(&ns_def_hdl))
			rc_log(LOG_ERR, "%s: namespace %s reset failed", __func__, ns);
	}
	return result;
}

/*- Release st's registry slot without waiting for a terminal result. A
 * no-op if st is not active (never sent, or already terminal/delivered).
 * Used by lib/request.c's radcli_request_free() for the fire-and-forget
 * case: a RADCLI_REQUEST_SENDONLY request whose caller never drove it to a
 * terminal result via radcli_ctx_dispatch()/radcli_request_done(). If st
 * was already delivered but never read via radcli_request_done(), frees
 * st->reply_attrs instead (the slot is already vacated by then --
 * REQ-NET2-SEND-016 vacates on delivery, not on collection). -*/
void radcli_transport_async_abort(struct radcli_async_send_st *st)
{
	if (st == NULL || !st->active)
		return;

	if (!st->delivered)
		radcli2_priv_reqreg_release(st->rh, st->slot);
	else
		radcli_avp_list_free(st->reply_attrs);
	st->active = 0;
}

