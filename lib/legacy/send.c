/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 * Copyright (C) 2015,2016,2026 Nikos Mavrogiannopoulos
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 *
 */

/* rc_pack_list()/rc_send_server()/rc_send_server_ctx() (legacy,
 * VALUE_PAIR-based): split out of lib/sendserver.c because they call
 * lib/legacy/avpair.c's rc_avpair_*() directly, unlike
 * radcli_transport_exchange() and its helpers (still in lib/sendserver.c),
 * which are VALUE_PAIR-free and shared with lib/request.c's new-API path.
 */

#include <includes.h>
#include <radcli/radcli.h>
#include <poll.h>
#include "dict2.h"
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

/**
 * @defgroup radcli-api Main API
 * @brief Main API Functions
 *
 * @{
 */

/* No longer called by rc_send_server_ctx(), which builds its packet via
 * radcli_value_pairs_to_avp_list() + radcli_avp_encode() (lib/avp.c)
 * instead -- one encoder implementing the encrypt=N whitelist and the
 * wire format, not two. Kept, and still tested directly (tests/pack.c),
 * as the documented behaviour of an already-shipped internal symbol. */
/*- Pack an attribute value pair list into a buffer.
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
 -*/
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
			struct radcli_dict_attr *def = radcli_dict_attr_by_id(rh, vp->attribute);
			struct radcli_dict_flags *fl = def != NULL ? radcli_dict_flags_by_id(rh, def->value) : NULL;

			if (fl != NULL && fl->encrypt_type != 0) {
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

			secretlen = rc_secret_len(secret);
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

/*- Append a string to the provided buffer.
 *
 * @param dest the destination buffer.
 * @param max_size the maximum size available in the destination buffer.
 * @param pos the current position in the dest buffer; initially must be zero.
 * @param src the source buffer to append.
 -*/
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

/*- Send a request to a RADIUS server and wait for the reply.
 *
 * The send/retry/receive step, including DNS-resolved address-level
 * failover, is delegated to radcli_transport_exchange(); this function
 * keeps only the VALUE_PAIR-specific work: management-secret detection,
 * NAS-IP-Address/NAS-Identifier auto-injection, encoding send_pairs into
 * the packet (rc_pack_list()), and decoding the reply back into
 * receive_pairs/msg (rc_avpair_gen()).
 *
 * @param rh a handle to parsed configuration.
 * @param ctx if non-NULL, receives the context of the sent request; release with rc_aaa_ctx_free().
 * @param data a pointer to a SEND_DATA structure.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of
 *	any PW_REPLY_MESSAGE received.
 * @param type must be AUTH or ACCT.
 * @param no_wait if non-zero, the request is transmitted once and this
 *  function returns OK_RC immediately without waiting for or expecting a
 *  reply; data->timeout and data->retries are not consulted in that
 *  case. Used by rc_acct_async() for best-effort, non-blocking
 *  notifications. TIMEOUT_RC is never returned when no_wait is set.
 * @return OK_RC (0) on success, CHALLENGE_RC when an Access-Challenge
 *  response is received, TIMEOUT_RC on timeout, REJECT_RC on access reject,
 *  or negative on failure as return value.
 -*/
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
		if (radcli2_priv_find_server_addr
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

	/* Build a request. Encodes via the same radcli_avp_encode()
	 * the new API uses -- converting data->send_pairs to a
	 * radcli_avp_list first -- rather than rc_pack_list(), so there is
	 * one encoder implementing the encrypt=N whitelist and the wire
	 * format, not two. The one caller-visible difference from
	 * rc_pack_list(): per RFC 2865 SS5.2, an over-length User-Password
	 * (> AUTH_PASS_LEN, 128 octets) is now rejected rather than silently
	 * truncated to a different, shorter password the caller did not ask
	 * to send -- a deliberate divergence, not an oversight (see
	 * radcli_avp_encode()'s own comment, lib/avp.c). */
	if (radcli_value_pairs_to_avp_list(rh, data->send_pairs, &avp_list) != 0) {
		memset(secret, '\0', sizeof(secret));
		return ERROR_RC;
	}

	auth = (AUTH_HDR *) send_buffer;
	auth->code = data->code;
	auth->id = data->seq_nbr;

	if (data->code == PW_ACCOUNTING_REQUEST) {
		encoded_len = radcli_avp_encode(rh, avp_list, secret, auth->vector,
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
		secretlen = rc_secret_len(secret);
		memcpy((char *)auth + total_length, secret, secretlen);
		rc_md5_calc(vector, (unsigned char *)auth,
			    total_length + secretlen);
		memcpy((char *)auth->vector, (char *)vector, AUTH_VECTOR_LEN);
	} else {
		rc_get_random_bytes(vector, AUTH_VECTOR_LEN);
		memcpy((char *)auth->vector, (char *)vector, AUTH_VECTOR_LEN);

		/* Leave 2+MD5_DIGEST_SIZE bytes for Message-Authenticator (added below) */
		encoded_len = radcli_avp_encode(rh, avp_list, secret, vector, auth->data,
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

	/* radcli_transport_exchange() no longer scrubs secret itself (it
	 * cannot know when a caller is truly done with it -- see its own doc
	 * comment); nothing below this point uses secret again (rc_avpair_gen()
	 * takes no secret parameter), so this is the correct, single place to
	 * clear it for every return path from here on. */
	memset(secret, '\0', sizeof(secret));

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

/** @} */
