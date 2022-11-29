/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */
#include <includes.h>
#include "rc-md5.h"
#include "rc-hmac.h"

#if defined(HAVE_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
#endif


/**
 * @defgroup radcli-api Main API
 * @brief Main API Functions
 *
 * @{
 */

/** Packs an attribute value pair list into a buffer
 *
 * @param vp a pointer to a VALUE_PAIR.
 * @param secret the secret used by the server.
 * @param auth a pointer to AUTH_HDR.
 * @return The number of octets packed.
 */
int
rc_pack_list(VALUE_PAIR * vp, char *secret, AUTH_HDR * auth)
{
	int length, i, pc, padded_length;
	int total_length = 0;
	size_t secretlen;
	uint32_t lvalue, vendor;
	unsigned char passbuf[RC_MAX(AUTH_PASS_LEN, CHAP_VALUE_LENGTH)];
	unsigned char md5buf[256];
	unsigned char *buf, *vector, *vsa_length_ptr;

	buf = auth->data;

	while (vp != NULL) {
		vsa_length_ptr = NULL;
		if (VENDOR(vp->attribute) != 0) {
			*buf++ = PW_VENDOR_SPECIFIC;
			vsa_length_ptr = buf;
			*buf++ = 6;
			vendor = htonl(VENDOR(vp->attribute));
			memcpy(buf, &vendor, sizeof(uint32_t));
			buf += 4;
			total_length += 6;
		}
		*buf++ = (vp->attribute & 0xff);

		switch (vp->attribute) {
		case PW_USER_PASSWORD:

			/* Encrypt the password */

			/* Chop off password at AUTH_PASS_LEN */
			length = vp->lvalue;
			if (length > AUTH_PASS_LEN)
				length = AUTH_PASS_LEN;

			/* Calculate the padded length */
			padded_length =
			    (length +
			     (AUTH_VECTOR_LEN - 1)) & ~(AUTH_VECTOR_LEN - 1);

			/* Record the attribute length */
			*buf++ = padded_length + 2;
			if (vsa_length_ptr != NULL)
				*vsa_length_ptr += padded_length + 2;

			/* Pad the password with zeros */
			memset((char *)passbuf, '\0', AUTH_PASS_LEN);
			memcpy((char *)passbuf, vp->strvalue, (size_t) length);

			secretlen = strlen(secret);
			vector = (unsigned char *)auth->vector;
			for (i = 0; i < padded_length; i += AUTH_VECTOR_LEN) {
				/* Calculate the MD5 digest */
				strcpy((char *)md5buf, secret);
				memcpy((char *)md5buf + secretlen, vector,
				       AUTH_VECTOR_LEN);
				rc_md5_calc(buf, md5buf,
					    secretlen + AUTH_VECTOR_LEN);

				/* Remeber the start of the digest */
				vector = buf;

				/* Xor the password into the MD5 digest */
				for (pc = i; pc < (i + AUTH_VECTOR_LEN); pc++) {
					*buf++ ^= passbuf[pc];
				}
			}

			total_length += padded_length + 2;

			break;
		default:
			switch (vp->type) {
			case PW_TYPE_STRING:
				length = vp->lvalue;
				*buf++ = length + 2;
				if (vsa_length_ptr != NULL)
					*vsa_length_ptr += length + 2;
				memcpy(buf, vp->strvalue, (size_t) length);
				buf += length;
				total_length += length + 2;
				break;

			case PW_TYPE_IPV6ADDR:
				length = 16;
				*buf++ = length + 2;
				if (vsa_length_ptr != NULL)
					*vsa_length_ptr += length + 2;
				memcpy(buf, vp->strvalue, (size_t) length);
				buf += length;
				total_length += length + 2;
				break;

			case PW_TYPE_IPV6PREFIX:
				length = vp->lvalue;
				*buf++ = length + 2;
				if (vsa_length_ptr != NULL)
					*vsa_length_ptr += length + 2;
				memcpy(buf, vp->strvalue, (size_t) length);
				buf += length;
				total_length += length + 2;
				break;

			case PW_TYPE_INTEGER:
			case PW_TYPE_IPADDR:
			case PW_TYPE_DATE:
				*buf++ = sizeof(uint32_t) + 2;
				if (vsa_length_ptr != NULL)
					*vsa_length_ptr += sizeof(uint32_t) + 2;
				lvalue = htonl(vp->lvalue);
				memcpy(buf, (char *)&lvalue, sizeof(uint32_t));
				buf += sizeof(uint32_t);
				total_length += sizeof(uint32_t) + 2;
				break;

			default:
				break;
			}
			break;
		}
		vp = vp->next;
	}
	return total_length;
}
/** Appends a string to the provided buffer
 *
 * @param dest the destination buffer.
 * @param max_size the maximum size available in the destination buffer.
 * @param pos the current position in the dest buffer; initially must be zero.
 * @param src the source buffer to append.
 */
void
strappend(char *dest, unsigned max_size, int *pos, const char *src)
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


int
populate_ctx(RC_AAA_CTX ** ctx, char secret[MAX_SECRET_LENGTH + 1],
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


/** Verify items in returned packet
 *
 * @param auth a pointer to AUTH_HDR.
 * @param bufferlen the available buffer length.
 * @param secret the secret used by the server.
 * @param vector a random vector of %AUTH_VECTOR_LEN.
 * @param seq_nbr a unique sequence number.
 * @return OK_RC upon success, BADRESP_RC if anything looks funny.
 */
int
rc_check_reply(AUTH_HDR * auth, int bufferlen, char const *secret,
		unsigned char const *vector, uint8_t seq_nbr)
{
	int secretlen;
	int totallen;
	unsigned char calc_digest[AUTH_VECTOR_LEN];
	unsigned char reply_digest[AUTH_VECTOR_LEN];
#ifdef DIGEST_DEBUG
	uint8_t *ptr;
#endif

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
#ifdef DIGEST_DEBUG
	rc_log(LOG_ERR, "Calculating digest on:");
	for (ptr = (u_char *) auth;
	     ptr < ((u_char *) auth) + totallen + secretlen; ptr += 32) {
		char buf[65];
		int i;

		buf[0] = '\0';
		for (i = 0; i < 32; i++) {
			if (ptr + i >= ((u_char *) auth) + totallen + secretlen)
				break;
			sprintf(buf + i * 2, "%.2X", ptr[i]);
		}
		rc_log(LOG_ERR, "  %s", buf);
	}
#endif
	rc_md5_calc(calc_digest, (unsigned char *)auth, totallen + secretlen);
#ifdef DIGEST_DEBUG
	rc_log(LOG_ERR, "Calculated digest is:");
	for (ptr = (u_char *) calc_digest; ptr < ((u_char *) calc_digest) + 16;
	     ptr += 32) {
		char buf[65];
		int i;

		buf[0] = '\0';
		for (i = 0; i < 32; i++) {
			if (ptr + i >= ((u_char *) calc_digest) + 16)
				break;
			sprintf(buf + i * 2, "%.2X", ptr[i]);
		}
		rc_log(LOG_ERR, "  %s", buf);
	}
	rc_log(LOG_ERR, "Reply digest is:");
	for (ptr = (u_char *) reply_digest;
	     ptr < ((u_char *) reply_digest) + 16; ptr += 32) {
		char buf[65];
		int i;

		buf[0] = '\0';
		for (i = 0; i < 32; i++) {
			if (ptr + i >= ((u_char *) reply_digest) + 16)
				break;
			sprintf(buf + i * 2, "%.2X", ptr[i]);
		}
		rc_log(LOG_ERR, "  %s", buf);
	}
#endif

	if (memcmp((char *)reply_digest, (char *)calc_digest,
		   AUTH_VECTOR_LEN) != 0) {
		rc_log(LOG_ERR,
		       "rc_check_reply: received invalid reply digest from RADIUS server");
		return BADRESP_RC;
	}

	return OK_RC;

}

/** Generates a random vector of AUTH_VECTOR_LEN octets
 *
 * @param vector a buffer with at least %AUTH_VECTOR_LEN bytes.
 */
void
rc_random_vector(unsigned char *vector)
{
	int randno;
	int i;
#if defined(HAVE_GNUTLS)
	if (gnutls_rnd(GNUTLS_RND_NONCE, vector, AUTH_VECTOR_LEN) >= 0) {
		return;
	}
#elif defined(HAVE_GETENTROPY)
	if (getentropy(vector, AUTH_VECTOR_LEN) >= 0) {
		return;
	}			/* else fall through */
#elif defined(HAVE_DEV_URANDOM)
	int fd;

/* well, I added this to increase the security for user passwords.
   we use /dev/urandom here, as /dev/random might block and we don't
   need that much randomness. BTW, great idea, Ted!     -lf, 03/18/95	*/

	if ((fd = open(_PATH_DEV_URANDOM, O_RDONLY)) >= 0) {
		unsigned char *pos;
		int readcount;

		i = AUTH_VECTOR_LEN;
		pos = vector;
		while (i > 0) {
			readcount = read(fd, (char *)pos, i);
			if (readcount >= 0) {
				pos += readcount;
				i -= readcount;
			} else {
				if (errno != EINTR && errno != EAGAIN)
					goto fallback;
			}
		}

		close(fd);
		return;
	}			/* else fall through */
 fallback:
#endif
	for (i = 0; i < AUTH_VECTOR_LEN;) {
		randno = random();
		memcpy((char *)vector, (char *)&randno, sizeof(int));
		vector += sizeof(int);
		i += sizeof(int);
	}

	return;
}

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
int
add_msg_auth_attr(rc_handle * rh, char * secret,
		AUTH_HDR *auth, int total_length)
{
	size_t secretlen = strlen(secret);
	uint8_t *msg_auth = (uint8_t *)auth + total_length;
	msg_auth[0] = PW_MESSAGE_AUTHENTICATOR;
	msg_auth[1] = 18;
	memset(&msg_auth[2], 0, MD5_DIGEST_SIZE);
	total_length += 18;
	auth->length = htons((unsigned short)total_length);

	/* Calulate HMAC-MD5 [RFC2104] hash */
	uint8_t digest[MD5_DIGEST_SIZE];
	rc_hmac_md5((uint8_t *)auth, (size_t)total_length, (uint8_t *)secret, secretlen, digest);
	memcpy(&msg_auth[2], digest, MD5_DIGEST_SIZE);

	return total_length;
}
