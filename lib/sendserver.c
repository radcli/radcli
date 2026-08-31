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
 * radcli_transport_service_async() below can reuse the identical RFC
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
			double start_time, poll_timeout;

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
			pfd.fd = sockfd;
			pfd.events = POLLIN;
			pfd.revents = 0;
			start_time = rc_getmtime();
			for (poll_timeout = timeout; poll_timeout > 0;
			     poll_timeout -= rc_getmtime() - start_time) {
				result = poll(&pfd, 1, poll_timeout * 1000);
				if (result != -1 || errno != EINTR)
					break;
			}

			if (result == -1) {
				rc_log(LOG_ERR, "radcli_transport_exchange: poll: %s", strerror(errno));
				SCLOSE(sockfd);
				result = ERROR_RC;
				goto cleanup;
			}

			if (result == 1 && (pfd.revents & POLLIN) != 0) {
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
					if (recv_length == -1 && (e == EAGAIN || e == EINTR))
						continue;
					SCLOSE(sockfd);
					result = ERROR_RC;
					goto cleanup;
				}

				{
					AUTH_HDR *recv_auth = (AUTH_HDR *)recv_buf;

					if (recv_length < AUTH_HDR_LEN ||
					    recv_length < ntohs(recv_auth->length)) {
						rc_log(LOG_ERR, "radcli_transport_exchange: recvfrom: "
						       "%s:%d: reply is too short", server_name, svc_port);
						SCLOSE(sockfd);
						result = ERROR_RC;
						goto cleanup;
					}

					result = rc_check_reply(recv_auth, (int)recv_buf_cap, secret,
								vector, seq_nbr);
					if (result == OK_RC)
						goto got_reply; /* out of both loops */
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

/* See lib/includes.h's doc comment. */
int radcli_transport_send_async(rc_handle *rh, char *server_name, unsigned short svc_port,
				char secret[MAX_SECRET_LENGTH + 1], rc_type type,
				const uint8_t *send_buf, int send_len,
				int timeout, int retries,
				struct radcli_async_send_st *out)
{
	struct addrinfo *auth_addr = NULL;
	const rc_sockets_override *sfuncs;
	struct sockaddr_storage our_sockaddr;
	unsigned discover_local_ip;
	char *ns = NULL;
	int ns_def_hdl = 0;
	int sockfd = -1;
	int result;

	memset(out, 0, sizeof(*out));

	if (server_name == NULL || server_name[0] == '\0')
		return ERROR_RC;
	if (send_len < AUTH_HDR_LEN || (size_t)send_len > sizeof(out->send_buf))
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

	if (sfuncs->lock) {
		if (sfuncs->lock(sfuncs->ptr) != 0) {
			rc_log(LOG_ERR, "%s: lock error", __func__);
			result = ERROR_RC;
			goto fail_unlocked;
		}
	}

	if (svc_port) {
		if (auth_addr->ai_family == AF_INET)
			((struct sockaddr_in *)auth_addr->ai_addr)->sin_port = htons(svc_port);
		else
			((struct sockaddr_in6 *)auth_addr->ai_addr)->sin6_port = htons(svc_port);
	}

	rc_own_bind_addr(rh, &our_sockaddr);
	discover_local_ip = 0;
	if (our_sockaddr.ss_family == AF_INET &&
	    ((struct sockaddr_in *)(&our_sockaddr))->sin_addr.s_addr == INADDR_ANY)
		discover_local_ip = 1;

	if (discover_local_ip) {
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
	}

	if (our_sockaddr.ss_family == AF_INET6) {
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

	out->rh = rh;
	out->sfuncs = sfuncs;
	out->active = 1;
	out->sockfd = sockfd;
	memcpy(&out->peer, auth_addr->ai_addr, auth_addr->ai_addrlen);
	out->peer_len = auth_addr->ai_addrlen;
	memcpy(out->send_buf, send_buf, (size_t)send_len);
	out->send_len = send_len;
	memcpy(out->vector, send_buf + 4, AUTH_VECTOR_LEN); /* AUTH_HDR: code(1) id(1) length(2) vector(16) */
	out->seq_nbr = send_buf[1];
	strlcpy(out->secret, secret, sizeof(out->secret));
	strlcpy(out->server_name, server_name, sizeof(out->server_name));
	out->svc_port = svc_port;
	out->type = type;
	out->timeout = timeout > 0 ? timeout : 1;
	out->retries_left = retries;
	out->deadline = rc_getmtime() + out->timeout;

	result = OK_RC;
	goto exit_ok;

 fail:
	if (sockfd >= 0 && sfuncs->close_fd)
		sfuncs->close_fd(sockfd);
	if (sfuncs->unlock)
		sfuncs->unlock(sfuncs->ptr);
 fail_unlocked:
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

/* See lib/includes.h's doc comment. */
int radcli_transport_service_async(struct radcli_async_send_st *st, int fd_ready,
				   uint8_t *recv_buf, size_t recv_buf_cap, size_t *recv_len,
				   uint8_t *out_code)
{
	char *ns;
	int ns_def_hdl = 0;
	int result;

	if (st == NULL || !st->active)
		return ERROR_RC;

	ns = rc_conf_str_id(st->rh, OPT_NAMESPACE);

	if (fd_ready) {
		int sockfd = st->sockfd;
		int recv_length;
		socklen_t salen = st->peer_len;

		if (st->sfuncs->get_active_fd) {
			int new_fd = st->sfuncs->get_active_fd(st->sfuncs->ptr);
			if (new_fd >= 0)
				sockfd = st->sockfd = new_fd;
		}

		if (ns != NULL && -1 == rc_set_netns(ns, &ns_def_hdl)) {
			rc_log(LOG_ERR, "%s: namespace %s set failed", __func__, ns);
			result = ERROR_RC;
			goto terminal;
		}

		if (st->rh->so_type == RC_SOCKET_TLS || st->rh->so_type == RC_SOCKET_DTLS) {
			recv_length = radcli2_priv_tls_try_recv(st->rh, recv_buf, (size_t)recv_buf_cap);
		} else {
			do {
				recv_length = st->sfuncs->recvfrom(st->sfuncs->ptr, sockfd, (char *)recv_buf,
								   (int)recv_buf_cap, 0,
								   SA(&st->peer), &salen);
			} while (recv_length == -1 && errno == EINTR);
			if (recv_length == -1 && errno == EAGAIN)
				recv_length = 0; /* not ready yet -- same "0 = not ready" contract
						  * radcli2_priv_tls_try_recv() uses */
		}

		if (ns != NULL)
			rc_reset_netns(&ns_def_hdl);

		if (recv_length < 0) {
			rc_log(LOG_ERR, "%s: recvfrom: %s:%d: %s", __func__,
			       st->server_name, st->svc_port, strerror(errno));
			result = ERROR_RC;
			goto terminal;
		}

		if (recv_length > 0) {
			AUTH_HDR *recv_auth = (AUTH_HDR *)recv_buf;

			if (recv_length < AUTH_HDR_LEN || recv_length < ntohs(recv_auth->length)) {
				rc_log(LOG_ERR, "%s: %s:%d: reply is too short", __func__,
				       st->server_name, st->svc_port);
				result = ERROR_RC;
				goto terminal;
			}

			result = rc_check_reply(recv_auth, (int)recv_buf_cap, st->secret,
						st->vector, st->seq_nbr);
			if (result == OK_RC) {
				result = decode_reply(st->rh, NULL, st->server_name, st->svc_port,
						      st->type, st->secret, st->vector,
						      recv_buf, recv_buf_cap, recv_len, out_code);
				goto terminal;
			}
			/* BADRESPID_RC (some other packet arrived, e.g. a stale
			 * retransmit's answer) and BADRESP_RC (bad length or Response
			 * Authenticator -- possibly spoofed) both keep waiting rather
			 * than handing an unverified packet to decode_reply(), matching
			 * the blocking loop's own "if (result == OK_RC) goto got_reply;"
			 * (REQ-GEN-STYLE-009). */
		}
	}

	if (rc_getmtime() < st->deadline)
		return RADCLI_ASYNC_AGAIN;

	if (st->retries_left-- <= 0) {
		rc_log(LOG_ERR, "%s: no reply from RADIUS server %s:%u", __func__,
		       st->server_name, st->svc_port);
		result = TIMEOUT_RC;
		goto terminal;
	}

	if (ns != NULL && -1 == rc_set_netns(ns, &ns_def_hdl)) {
		rc_log(LOG_ERR, "%s: namespace %s set failed", __func__, ns);
		result = ERROR_RC;
		goto terminal;
	}
	{
		int sresult;

		do {
			sresult = st->sfuncs->sendto(st->sfuncs->ptr, st->sockfd,
						     (const char *)st->send_buf, (unsigned int)st->send_len,
						     0, SA(&st->peer), st->peer_len);
		} while (sresult == -1 && errno == EINTR);
		if (ns != NULL)
			rc_reset_netns(&ns_def_hdl);
		if (sresult == -1) {
			rc_log(LOG_ERR, "%s: sendto: %s", __func__, strerror(errno));
			result = ERROR_RC;
			goto terminal;
		}
	}
	st->deadline = rc_getmtime() + st->timeout;
	return RADCLI_ASYNC_AGAIN;

 terminal:
	if (st->sfuncs->close_fd)
		st->sfuncs->close_fd(st->sockfd);
	st->sockfd = -1;
	if (st->sfuncs->unlock)
		st->sfuncs->unlock(st->sfuncs->ptr);
	memset(st->secret, '\0', sizeof(st->secret));
	st->active = 0;
	return result;
}

/* See lib/includes.h's doc comment. */
void radcli_transport_async_abort(struct radcli_async_send_st *st)
{
	if (st == NULL || !st->active)
		return;

	if (st->sfuncs->close_fd)
		st->sfuncs->close_fd(st->sockfd);
	st->sockfd = -1;
	if (st->sfuncs->unlock)
		st->sfuncs->unlock(st->sfuncs->ptr);
	memset(st->secret, '\0', sizeof(st->secret));
	st->active = 0;
}

