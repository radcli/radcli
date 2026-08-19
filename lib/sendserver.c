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
#include <pathnames.h>
#include <poll.h>
#include "util.h"
#include "avp.h"
#include "rc-md5.h"
#include "rc-hmac.h"
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

/**
 * @defgroup radcli-api Main API
 * @brief Main API Functions
 *
 * @{
 */

/* Packs an attribute value pair list into a buffer.
 *
 * No longer called by rc_send_server_ctx(), which builds its packet via
 * radcli_value_pairs_to_avp_list() + radcli_avp_encode_rfc2865() (lib/avp.c)
 * instead -- one encoder implementing the encrypt=N whitelist and the
 * wire format, not two. Kept, and still tested directly (tests/pack.c),
 * as the documented behaviour of an already-shipped internal symbol.
 *
 * @param rh a handle to parsed configuration (used for the dictionary
 *        encrypt=N lookup that refuses an attribute this function cannot
 *        encrypt -- see the check at the top of the loop below).
 * @param vp a pointer to a VALUE_PAIR.
 * @param secret the secret used by the server.
 * @param auth a pointer to AUTH_HDR.
 * @param max_len maximum total packet length in bytes (header + attributes);
 *        callers must subtract any bytes appended after this call (e.g. 18
 *        bytes for Message-Authenticator on auth requests).
 * @return The number of octets packed, or -1 if any attribute value exceeds
 *         253 bytes, the packet would exceed max_len, or an attribute
 *         requires encryption this function does not implement (any
 *         dictionary encrypt=N flag other than User-Password's own
 *         RFC 2865 SS5.2 handling below).
 */
/// @cond INTERNAL
int rc_pack_list(rc_handle *rh, VALUE_PAIR * vp, char *secret, AUTH_HDR * auth, int max_len)
{
	int length, i, pc, padded_length;
	size_t secretlen;
	uint32_t lvalue, vendor;
	unsigned char passbuf[RC_MAX(AUTH_PASS_LEN, CHAP_VALUE_LENGTH)];
	unsigned char md5buf[MAX_SECRET_LENGTH + AUTH_VECTOR_LEN];
	unsigned char *vector;
	pkt_buf pb;
	uint8_t *attr_start, *attr_len_ptr, *vsa_len_ptr;

	/* head = start of RADIUS packet; tail starts after the fixed header;
	 * pb_written() will return the total packet length (header + attrs). */
	pb.head = (uint8_t *)auth;
	pb.data = (uint8_t *)auth;
	pb.tail = auth->data;
	pb.end  = (uint8_t *)auth + max_len;

	while (vp != NULL) {
		vsa_len_ptr = NULL;
		unsigned max_vlen = AUTH_STRING_LEN;        /* 253: RFC 2865 per-attribute value limit */

		/* PW_USER_PASSWORD has its own encryption below (RFC 2865 SS5.2);
		 * every other attribute the dictionary flags "encrypt=N" -- today
		 * that means Tunnel-Password and the two MS-MPPE-*-Key VSAs,
		 * encrypt=2, RFC 2868 SS3.5 salt-encryption -- has no
		 * implementation in this function, and MUST NOT fall through to
		 * the plain string/integer encoding below: doing so would send
		 * the attribute's real value on the wire completely unencrypted.
		 * A whitelist, not a blocklist: refusal is the default for any
		 * flagged attribute this function does not specifically know how
		 * to encrypt, including one a future dictionary change adds. */
		if (vp->attribute != PW_USER_PASSWORD) {
			DICT_ATTR *def = rc_dict_getattr(rh, vp->attribute);

			if (def != NULL && rc_dict_attr_encrypt_type(rh, def) != 0) {
				rc_log(LOG_ERR, "rc_pack_list: %s requires encryption this "
				    "function does not implement; refusing to send it "
				    "unencrypted", def->name);
				return -1;
			}
		}

		if (VENDOR(vp->attribute) != 0) {
			max_vlen = AUTH_STRING_LEN - VSA_HDR_LEN; /* 247: VSA envelope consumes 6 bytes */
			if (pb_put_byte(&pb, PW_VENDOR_SPECIFIC) < 0) goto too_large;
			vsa_len_ptr = pb.tail;
			if (pb_put_byte(&pb, 6) < 0) goto too_large;
			vendor = htonl(VENDOR(vp->attribute));
			if (pb_put_bytes(&pb, &vendor, sizeof(uint32_t)) < 0) goto too_large;
		}

		attr_start = pb.tail;
		if (pb_put_byte(&pb, vp->attribute & 0xff) < 0) goto too_large;
		attr_len_ptr = pb.tail;
		if (pb_put_byte(&pb, 2) < 0) goto too_large;  /* placeholder; patched below */

		switch (vp->attribute) {
		case PW_USER_PASSWORD:
			length = vp->lvalue;
			if (length > AUTH_PASS_LEN)
				length = AUTH_PASS_LEN;
			padded_length =
			    (length + (AUTH_VECTOR_LEN - 1)) & ~(AUTH_VECTOR_LEN - 1);

			if (pb.tail + padded_length > pb.end) goto too_large;

			/* Pad the password with zeros */
			memset((char *)passbuf, '\0', AUTH_PASS_LEN);
			memcpy((char *)passbuf, vp->strvalue, (size_t) length);

			secretlen = strlen(secret);
			if (secretlen > MAX_SECRET_LENGTH)
				secretlen = MAX_SECRET_LENGTH;
			vector = (unsigned char *)auth->vector;
			for (i = 0; i < padded_length; i += AUTH_VECTOR_LEN) {
				/* Build hash input: secret || vector */
				memcpy(md5buf, secret, secretlen);
				memcpy(md5buf + secretlen, vector, AUTH_VECTOR_LEN);
				rc_md5_calc(pb.tail, md5buf, secretlen + AUTH_VECTOR_LEN);

				/* Remember the start of the digest */
				vector = pb.tail;

				/* Xor the password into the MD5 digest */
				for (pc = i; pc < (i + AUTH_VECTOR_LEN); pc++)
					*pb.tail++ ^= passbuf[pc];
			}
			break;

		default:
			switch (vp->type) {
			case PW_TYPE_STRING:
			case PW_TYPE_IPV6PREFIX:
				if (vp->lvalue > max_vlen) goto too_large;
				if (pb_put_bytes(&pb, vp->strvalue, (int)vp->lvalue) < 0)
					goto too_large;
				break;

			case PW_TYPE_IPV6ADDR:
				if (pb_put_bytes(&pb, vp->strvalue, 16) < 0)
					goto too_large;
				break;

			case PW_TYPE_INTEGER:
			case PW_TYPE_IPADDR:
			case PW_TYPE_DATE:
				lvalue = htonl(vp->lvalue);
				if (pb_put_bytes(&pb, &lvalue, sizeof(uint32_t)) < 0)
					goto too_large;
				break;

			default:
				break;
			}
			break;
		}

		/* Patch back lengths: attr_len = type(1) + len(1) + value */
		*attr_len_ptr = (uint8_t)(pb.tail - attr_start);
		if (vsa_len_ptr != NULL)
			*vsa_len_ptr += *attr_len_ptr;

		vp = vp->next;
	}
	return (int)pb_written(&pb);  /* total packet bytes: AUTH_HDR_LEN + attrs */

too_large:
	rc_log(LOG_ERR, "rc_pack_list: attribute value too large or packet would exceed %d bytes", max_len);
	return -1;
}
/// @endcond

/* Appends a string to the provided buffer
 *
 * @param dest the destination buffer.
 * @param max_size the maximum size available in the destination buffer.
 * @param pos the current position in the dest buffer; initially must be zero.
 * @param src the source buffer to append.
 */
/// @cond INTERNAL
static void strappend(char *dest, unsigned max_size, int *pos, const char *src)
{
	unsigned len = strlen(src) + 1;

	if (*pos == -1)
		return;

	if (len + *pos > max_size) {
		*pos = -1;
		return;
	}

	memcpy(&dest[*pos], src, len);
	*pos += len - 1;
	return;
}
/// @endcond


/// @cond INTERNAL
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
/// @endcond

/** @brief Sends a request to a RADIUS server and waits for the reply
 *
 * @param rh a handle to parsed configuration
 * @param data a pointer to a SEND_DATA structure
 * @param msg must be an array of %PW_MAX_MSG_SIZE or NULL; will contain the concatenation of
 *	any %PW_REPLY_MESSAGE received.
 * @param type must be %AUTH or %ACCT
 * @return OK_RC (0) on success, TIMEOUT_RC on timeout REJECT_RC on access reject, or negative
 *	on failure as return value.
 */
int rc_send_server(rc_handle * rh, SEND_DATA * data, char *msg, rc_type type)
{
	return rc_send_server_ctx(rh, NULL, data, msg, type, 0);
}

/* Verify items in returned packet
 *
 * @param auth a pointer to AUTH_HDR.
 * @param bufferlen the available buffer length.
 * @param secret the secret used by the server.
 * @param vector a random vector of %AUTH_VECTOR_LEN.
 * @param seq_nbr a unique sequence number.
 * @return OK_RC upon success, BADRESP_RC if anything looks funny.
 */
/// @cond INTERNAL
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
/// @endcond

/** @} */


/** Add a Message-Authenticator attribute to a message. This is mandatory,
 *  for example, when sending a message containing an EAP-Message
 *  attribute.
 *
 * @param rh - A handle to parsed configuration
 * @param secret - The server's secret string
 * @param auth - Pointer to the AUTH_HDR structure
 * @param total_length - Total packet length before Message Authenticator
 *                is added.
 *
 * @return Total packet length after Message Authenticator is added.
 */
int add_msg_auth_attr(rc_handle * rh, char * secret,
		      AUTH_HDR *auth, int total_length)
{
	size_t secretlen = strlen(secret);
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

/** Validate the Message-Authenticator attribute
 *
 * @param recv_buffer The original packet
 * @param length The length of the attribute data (packet length minus AUTH_HDR_LEN)
 * @param secret The RADIUS secret
 * @param req_auth The request authenticator from the Access-Request (RFC 3579 §3.2
 *   requires MA in responses to be computed over the packet with the Request
 *   Authenticator in the Authenticator field, not the Response Authenticator)
 * @return zero on success, other values for failure
 */
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

	rc_hmac_md5(verify_buffer, AUTH_HDR_LEN + length, (uint8_t *)secret, strlen(secret), digest);
	return rc_memcmp(ma_copy, digest, MD5_DIGEST_SIZE);
}

/** Representation-agnostic RADIUS request/reply exchange.
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
 * address and secret via rc_find_server_addr(), which overwrites secret
 * if server_name matches a configured authserver/acctserver entry.
 * no_wait is fire-and-forget (REQ-NET-NET-017): send once to the first
 * resolved address and return without waiting for a reply.
 *
 * On a reply, validates framing, the Response Authenticator
 * (rc_check_reply()), and -- for AUTH over UDP/TCP -- the
 * Message-Authenticator and its Blast-RADIUS first-attribute position
 * (validate_message_authenticator()). On success the reply's attribute
 * region (header stripped) is left in recv_buf[0 .. *recv_len); this
 * function does not encode or decode individual attributes. secret is
 * memset to zero before every return.
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
 */
/// @cond INTERNAL
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

	ns = rc_conf_str(rh, "namespace");
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
		if (rc_find_server_addr(rh, server_name, &auth_addr, secret, type) != 0) {
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
			result = rc_get_srcaddr(SA(&our_sockaddr), cur_addr->ai_addr);
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
			char *non_temp_addr = rc_conf_str(rh, "use-public-addr");
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

		if (radcli_debug) {
			char our_addr_txt[50] = "", addr_txt[50] = "";

			getnameinfo(SA(&our_sockaddr), SS_LEN(&our_sockaddr), NULL, 0,
				    our_addr_txt, sizeof(our_addr_txt), NI_NUMERICHOST);
			getnameinfo(cur_addr->ai_addr, cur_addr->ai_addrlen, NULL, 0,
				    addr_txt, sizeof(addr_txt), NI_NUMERICHOST);
			DEBUG(LOG_ERR,
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
				memset(secret, '\0', MAX_SECRET_LENGTH + 1);
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
					if (result != BADRESPID_RC)
						goto got_reply; /* out of both loops */
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
	memset(secret, '\0', MAX_SECRET_LENGTH + 1);
	goto cleanup_nosock;

 got_reply:
	{
		AUTH_HDR *recv_auth = (AUTH_HDR *)recv_buf;
		int length = ntohs(recv_auth->length);
		pkt_buf rb;
		uint8_t attr_type, attr_len;

		if ((size_t)length > recv_buf_cap)
			length = (int)recv_buf_cap;

		/* Verify it's a well-formed RADIUS packet before doing ANYTHING with it. */
		pb_init_read(&rb, recv_buf, length, recv_buf_cap);
		assert(pb_pull(&rb, AUTH_HDR_LEN) == 0);
		while (pb_len(&rb) > 0) {
			if (pb_peek_byte(&rb, 0, &attr_type) < 0 || pb_peek_byte(&rb, 1, &attr_len) < 0) {
				rc_log(LOG_ERR, "radcli_transport_exchange: recvfrom: %s:%d: "
				       "truncated attribute", server_name, svc_port);
				result = ERROR_RC;
				goto cleanup;
			}
			if (attr_type == 0) {
				rc_log(LOG_ERR, "radcli_transport_exchange: recvfrom: %s:%d: "
				       "attribute zero is invalid", server_name, svc_port);
				result = ERROR_RC;
				goto cleanup;
			}
			if (attr_len < 2) {
				rc_log(LOG_ERR, "radcli_transport_exchange: recvfrom: %s:%d: "
				       "attribute length is too small", server_name, svc_port);
				result = ERROR_RC;
				goto cleanup;
			}
			if (attr_len > pb_len(&rb)) {
				rc_log(LOG_ERR, "radcli_transport_exchange: recvfrom: %s:%d: "
				       "attribute overflows the packet", server_name, svc_port);
				result = ERROR_RC;
				goto cleanup;
			}
			assert(pb_pull(&rb, attr_len) == 0);
		}

		length = ntohs(recv_auth->length) - AUTH_HDR_LEN;
		if (length < 0)
			length = 0;

		{
			int ctxresult = populate_ctx(ctx, secret, (unsigned char *)vector);
			if (ctxresult != OK_RC) {
				result = ctxresult;
				goto cleanup;
			}
		}

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
				if (validate_message_authenticator(recv_buf, (size_t)length, secret,
								    vector)) {
					rc_log(LOG_ERR, "radcli_transport_exchange: recvfrom: %s:%d: "
					       "received attribute Message-Authenticator is incorrect",
					       server_name, svc_port);
					result = ERROR_RC;
					goto cleanup;
				}
			}

			if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS) {
				if (length == 0 || recv_buf[AUTH_HDR_LEN] != PW_MESSAGE_AUTHENTICATOR) {
					char *p = rc_conf_str(rh, "require-message-authenticator");
					if (p == NULL || (strcasecmp(p, "false") != 0 &&
							  strcasecmp(p, "no") != 0)) {
						rc_log(LOG_ERR, "radcli_transport_exchange: recvfrom: "
						       "%s:%d: required attribute Message-Authenticator "
						       "is missing or not first", server_name, svc_port);
						result = ERROR_RC;
						goto cleanup;
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
				result = OK_RC;
				break;
			case PW_ACCESS_REJECT:
			case PW_PASSWORD_REJECT:
				result = REJECT_RC;
				break;
			case PW_ACCESS_CHALLENGE:
				result = CHALLENGE_RC;
				break;
			default:
				rc_log(LOG_ERR, "radcli_transport_exchange: received RADIUS server response "
				       "neither ACCEPT nor REJECT, code=%d is invalid", code);
				result = BADRESP_RC;
			}
		}
	}

 cleanup:
	memset(secret, '\0', MAX_SECRET_LENGTH + 1);
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
/// @endcond

/** Sends a request to a RADIUS server and waits for the reply
 *
 * The send/retry/receive step, including DNS-resolved address-level
 * failover, is delegated to radcli_transport_exchange(); this function
 * keeps only the VALUE_PAIR-specific work: management-secret detection,
 * NAS-IP-Address/NAS-Identifier auto-injection, encoding send_pairs into
 * the packet (rc_pack_list()), and decoding the reply back into
 * receive_pairs/msg (rc_avpair_gen()).
 *
 * @param rh a handle to parsed configuration
 * @param ctx if non-NULL it will contain the context of sent request; It must be released using rc_aaa_ctx_free().
 * @param data a pointer to a SEND_DATA structure.
 * @param msg must be an array of %PW_MAX_MSG_SIZE or NULL; will contain the concatenation of
 *	any %PW_REPLY_MESSAGE received.
 * @param type must be %AUTH or %ACCT
 * @param no_wait if non-zero, the request is transmitted once and this
 *  function returns OK_RC immediately without waiting for or expecting a
 *  reply; @c data->timeout and @c data->retries are not consulted in that
 *  case. Used by rc_acct_async() for best-effort, non-blocking
 *  notifications. TIMEOUT_RC is never returned when @p no_wait is set.
 * @return OK_RC (0) on success, CHALLENGE_RC when an Access-Challenge
 *  response is received, TIMEOUT_RC on timeout, REJECT_RC on access reject,
 *  or negative on failure as return value.
 */
int rc_send_server_ctx(rc_handle * rh, RC_AAA_CTX ** ctx, SEND_DATA * data,
		       char *msg, rc_type type, int no_wait)
{
	AUTH_HDR *auth;
	char *server_name, *p;
	struct sockaddr_storage our_sockaddr;
	struct addrinfo *auth_addr = NULL;
	int result = 0;
	int total_length;
	int length, pos;
	const rc_sockets_override *sfuncs;
	unsigned discover_local_ip;
	size_t secretlen;
	char secret[MAX_SECRET_LENGTH + 1];
	unsigned char vector[AUTH_VECTOR_LEN];
	uint8_t recv_buffer[RC_BUFFER_LEN];
	uint8_t send_buffer[RC_BUFFER_LEN];
	uint16_t tlen;
	size_t recv_len = 0;
	VALUE_PAIR *vp;
	struct sockaddr_storage *ss_set = NULL;
	int mgmt_secret = 0;
	radcli_avp_list *avp_list;
	int encoded_len;

	server_name = data->server;
	if (server_name == NULL || server_name[0] == '\0')
		return ERROR_RC;

	if ((vp = rc_avpair_get(data->send_pairs, PW_SERVICE_TYPE, 0)) &&
	    (vp->lvalue == PW_ADMINISTRATIVE)) {
		mgmt_secret = 1;
		strlcpy(secret, MGMT_POLL_SECRET, sizeof(secret));
		auth_addr =
		    rc_getaddrinfo(server_name,
				   type == AUTH ? PW_AI_AUTH : PW_AI_ACCT);
		if (auth_addr == NULL)
			return ERROR_RC;
	} else {
		if (data->secret != NULL) {
			strlcpy(secret, data->secret, sizeof(secret));
		}
		if (rc_find_server_addr
		    (rh, server_name, &auth_addr, secret, type) != 0) {
			rc_log(LOG_ERR,
			       "rc_send_server: unable to find server: %s",
			       server_name);
			return ERROR_RC;
		}
	}

	sfuncs = &rh->so;

	if (sfuncs->static_secret) {
		/* any static secret set in sfuncs overrides the configured */
		strlcpy(secret, sfuncs->static_secret, sizeof(secret));
	}

	/* Discover our own source address, used below to fill in
	 * NAS-IP-Address/NAS-IPv6-Address when the caller didn't set one;
	 * radcli_transport_exchange() re-does this per address it actually
	 * sends from, so this is only for the auto-injected attribute's
	 * value, not for building a socket. */
	rc_own_bind_addr(rh, &our_sockaddr);
	discover_local_ip = 0;
	if (our_sockaddr.ss_family == AF_INET) {
		if (((struct sockaddr_in *)(&our_sockaddr))->sin_addr.s_addr ==
		    INADDR_ANY) {
			discover_local_ip = 1;
		}
	}

	if (discover_local_ip) {
		result = rc_get_srcaddr(SA(&our_sockaddr), auth_addr->ai_addr);
		if (result != OK_RC) {
			memset(secret, '\0', sizeof(secret));
			rc_log(LOG_ERR,
			       "rc_send_server: cannot figure our own address");
			freeaddrinfo(auth_addr);
			return result;
		}
	}

	freeaddrinfo(auth_addr);
	auth_addr = NULL;

	/*
	 * Fill in NAS-IP-Address (if needed)
	 */
	if (rh->nas_addr_set) {
		rc_avpair_remove(&(data->send_pairs), PW_NAS_IP_ADDRESS, 0);
		rc_avpair_remove(&(data->send_pairs), PW_NAS_IPV6_ADDRESS, 0);

		ss_set = &rh->nas_addr;
	} else if (rc_avpair_get(data->send_pairs, PW_NAS_IP_ADDRESS, 0) == NULL &&
	    	   rc_avpair_get(data->send_pairs, PW_NAS_IPV6_ADDRESS, 0) == NULL) {

	    	ss_set = &our_sockaddr;
	}

	if (ss_set) {
		if (ss_set->ss_family == AF_INET) {
			uint32_t ip;
			ip = *((uint32_t
				*) (&((struct sockaddr_in *)ss_set)->
				    sin_addr));
			ip = ntohl(ip);

			rc_avpair_add(rh, &(data->send_pairs),
				      PW_NAS_IP_ADDRESS, &ip, 0, 0);
		} else {
			void *p2;
			p2 = &((struct sockaddr_in6 *)ss_set)->sin6_addr;

			rc_avpair_add(rh, &(data->send_pairs),
				      PW_NAS_IPV6_ADDRESS, p2, 16, 0);
		}
	}

	/*
	 * Fill in NAS-Identifier (if needed)
	 */
	p = rc_conf_str(rh, "nas-identifier");
	if (p != NULL) {
		rc_avpair_remove(&(data->send_pairs), PW_NAS_IDENTIFIER, 0);
		rc_avpair_add(rh, &(data->send_pairs),
			      PW_NAS_IDENTIFIER, p, -1, 0);
	}

	/* Build a request. Encodes via the same radcli_avp_encode_rfc2865()
	 * the new API uses -- converting data->send_pairs to a
	 * radcli_avp_list first -- rather than rc_pack_list(), so there is
	 * one encoder implementing the encrypt=N whitelist and the wire
	 * format, not two. The one caller-visible difference from
	 * rc_pack_list(): per RFC 2865 SS5.2, an over-length User-Password
	 * (> AUTH_PASS_LEN, 128 octets) is now rejected rather than silently
	 * truncated to a different, shorter password the caller did not ask
	 * to send -- a deliberate divergence, not an oversight (see
	 * radcli_avp_encode_rfc2865()'s own comment, lib/avp.c). */
	if (radcli_value_pairs_to_avp_list(rh, data->send_pairs, &avp_list) != 0) {
		memset(secret, '\0', sizeof(secret));
		return ERROR_RC;
	}

	auth = (AUTH_HDR *) send_buffer;
	auth->code = data->code;
	auth->id = data->seq_nbr;

	if (data->code == PW_ACCOUNTING_REQUEST) {
		encoded_len = radcli_avp_encode_rfc2865(rh, avp_list, secret, auth->vector,
						auth->data, RC_MAX_PACKET_LEN - AUTH_HDR_LEN, NULL);
		radcli_avp_list_free(avp_list);
		if (encoded_len < 0) {
			memset(secret, '\0', sizeof(secret));
			return ERROR_RC;
		}
		total_length = AUTH_HDR_LEN + encoded_len;

		tlen = htons((unsigned short)total_length);
		memcpy(&auth->length, &tlen, sizeof(uint16_t));

		memset((char *)auth->vector, 0, AUTH_VECTOR_LEN);
		secretlen = strlen(secret);
		memcpy((char *)auth + total_length, secret, secretlen);
		rc_md5_calc(vector, (unsigned char *)auth,
			    total_length + secretlen);
		memcpy((char *)auth->vector, (char *)vector, AUTH_VECTOR_LEN);
	} else {
		rc_get_random_bytes(vector, AUTH_VECTOR_LEN);
		memcpy((char *)auth->vector, (char *)vector, AUTH_VECTOR_LEN);

		/* Leave 2+MD5_DIGEST_SIZE bytes for Message-Authenticator (added below) */
		encoded_len = radcli_avp_encode_rfc2865(rh, avp_list, secret, vector, auth->data,
						RC_MAX_PACKET_LEN - AUTH_HDR_LEN - (2 + MD5_DIGEST_SIZE), NULL);
		radcli_avp_list_free(avp_list);
		if (encoded_len < 0) {
			memset(secret, '\0', sizeof(secret));
			return ERROR_RC;
		}
		total_length = AUTH_HDR_LEN + encoded_len;

		total_length = add_msg_auth_attr(rh, secret, auth, total_length);

		auth->length = htons((unsigned short)total_length);
	}

	result = radcli_transport_exchange(rh, ctx, server_name,
					   (unsigned short)data->svc_port,
					   secret, mgmt_secret,
					   data->timeout, data->retries, no_wait, type,
					   send_buffer, total_length,
					   recv_buffer, sizeof(recv_buffer), &recv_len, NULL);

	if (no_wait ||
	    (result != OK_RC && result != CHALLENGE_RC &&
	     result != REJECT_RC && result != BADRESP_RC)) {
		return result;
	}

	length = (int)recv_len;
	if (length > 0) {
		data->receive_pairs = rc_avpair_gen(rh, NULL, recv_buffer,
						    length, 0);
	} else {
		data->receive_pairs = NULL;
	}

	if (msg) {
		*msg = '\0';
		pos = 0;
		vp = data->receive_pairs;
		while (vp) {
			if ((vp = rc_avpair_get(vp, PW_REPLY_MESSAGE, 0))) {
				strappend(msg, PW_MAX_MSG_SIZE, &pos,
					  vp->strvalue);
				strappend(msg, PW_MAX_MSG_SIZE, &pos, "\n");
				vp = vp->next;
			}
		}
	}

	return result;
}
