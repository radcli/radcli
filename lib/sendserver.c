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
#include <radcli/radcli.h>
#include <pathnames.h>
#include <poll.h>

#include "sendserver_util.h"

#include "util.h"
#include "rc-md5.h"
#include "rc-hmac.h"

#if defined(HAVE_GNUTLS)
# include <gnutls/gnutls.h>
# include <gnutls/crypto.h>
#endif

#if defined(__linux__)
#include <linux/in6.h>
#endif


#define SCLOSE(fd) if (sfuncs->close_fd) sfuncs->close_fd(fd)


/** Sends a request to a RADIUS server and waits for the reply
 *
 * @param rh a handle to parsed configuration
 * @param ctx if non-NULL it will contain the context of sent request; It must be released using rc_aaa_ctx_free().
 * @param data a pointer to a SEND_DATA structure
 * @param msg must be an array of %PW_MAX_MSG_SIZE or NULL; will contain the concatenation of
 *	any %PW_REPLY_MESSAGE received.
 * @param type must be %AUTH or %ACCT
 * @return OK_RC (0) on success, CHALLENGE_RC when an Access-Challenge
 *  response is received, TIMEOUT_RC on timeout REJECT_RC on access reject,
 *  or negative on failure as return value.
 */
int rc_send_server_ctx(rc_handle * rh, RC_AAA_CTX ** ctx, SEND_DATA * data,
		       char *msg, rc_type type)
{
	int sockfd = -1;
	AUTH_HDR *auth, *recv_auth;
	char *server_name, *p;	/* Name of server to query */
	struct sockaddr_storage our_sockaddr;
	struct addrinfo *auth_addr = NULL;
	socklen_t salen;
	int result = 0;
	int total_length;
	int length, pos;
	int retry_max;
	const rc_sockets_override *sfuncs;
	unsigned discover_local_ip;
	size_t secretlen;
	char secret[MAX_SECRET_LENGTH + 1];
	unsigned char vector[AUTH_VECTOR_LEN];
	uint8_t recv_buffer[RC_BUFFER_LEN];
	uint8_t send_buffer[RC_BUFFER_LEN];
	uint8_t *attr;
	uint16_t tlen;
	int retries;
	VALUE_PAIR *vp;
	struct pollfd pfd;
	double start_time, timeout;
	struct sockaddr_storage *ss_set = NULL;
	char *server_type = "auth";
	char *ns = NULL;
	int ns_def_hdl = 0;

	server_name = data->server;
	if (server_name == NULL || server_name[0] == '\0')
		return ERROR_RC;

	ns = rc_conf_str(rh, "namespace"); /* Check for namespace config */
	if (ns != NULL) {
		if(-1 == rc_set_netns(ns, &ns_def_hdl)) {
			rc_log(LOG_ERR, "rc_send_server: namespace %s set failed", ns);
			return ERROR_RC;
		}
	}
	if ((vp = rc_avpair_get(data->send_pairs, PW_SERVICE_TYPE, 0)) &&
	    (vp->lvalue == PW_ADMINISTRATIVE)) {
		strcpy(secret, MGMT_POLL_SECRET);
		auth_addr =
		    rc_getaddrinfo(server_name,
				   type == AUTH ? PW_AI_AUTH : PW_AI_ACCT);
		if (auth_addr == NULL) {
			result = ERROR_RC;
			goto exit_error;
		}    
	} else {
		if (data->secret != NULL) {
			strlcpy(secret, data->secret, MAX_SECRET_LENGTH);
		}
		/*
		   else
		   {
		 */
		if (rc_find_server_addr
		    (rh, server_name, &auth_addr, secret, type) != 0) {
			rc_log(LOG_ERR,
			       "rc_send_server: unable to find server: %s",
			       server_name);
			result = ERROR_RC;
			goto exit_error;
		}
		/*} */
	}

	sfuncs = &rh->so;

	if (sfuncs->static_secret) {
		/* any static secret set in sfuncs overrides the configured */
		strlcpy(secret, sfuncs->static_secret,
			MAX_SECRET_LENGTH);
	}

	if (sfuncs->lock) {
		if (sfuncs->lock(sfuncs->ptr) != 0) {
			rc_log(LOG_ERR, "%s: lock error", __func__);
			result = ERROR_RC;
			goto exit_error;
		}
	}

	rc_own_bind_addr(rh, &our_sockaddr);
	discover_local_ip = 0;
	if (our_sockaddr.ss_family == AF_INET) {
		if (((struct sockaddr_in *)(&our_sockaddr))->sin_addr.s_addr ==
		    INADDR_ANY) {
			discover_local_ip = 1;
		}
	}

	DEBUG(LOG_ERR, "DEBUG: rc_send_server: creating socket to: %s",
	      server_name);
	if (discover_local_ip) {
		result = rc_get_srcaddr(SA(&our_sockaddr), auth_addr->ai_addr);
		if (result != OK_RC) {
			memset(secret, '\0', sizeof(secret));
			rc_log(LOG_ERR,
			       "rc_send_server: cannot figure our own address");
			goto cleanup;
		}
	}

	if (sfuncs->get_fd) {
		sockfd = sfuncs->get_fd(sfuncs->ptr, SA(&our_sockaddr));
		if (sockfd < 0) {
			memset(secret, '\0', sizeof(secret));
			rc_log(LOG_ERR, "rc_send_server: socket: %s",
			       strerror(errno));
			result = ERROR_RC;
			goto cleanup;
		}
	}

	if(our_sockaddr.ss_family  == AF_INET6) {
		/* Check for IPv6 non-temporary address support */
		char *non_temp_addr = rc_conf_str(rh, "use-public-addr");
		if (non_temp_addr && (strcasecmp(non_temp_addr, "true") == 0)) {
#if defined(__linux__)
			int sock_opt = IPV6_PREFER_SRC_PUBLIC;
			if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES, 
					&sock_opt, sizeof(sock_opt)) != 0) {
				rc_log(LOG_ERR, "rc_send_server: setsockopt: %s", 
					strerror(errno));
				result = ERROR_RC;
				goto cleanup;
			}
#elif defined(BSD) || defined(__APPLE__)
			int sock_opt = 0;
			if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR,
				&sock_opt, sizeof(sock_opt)) != 0) {
				rc_log(LOG_ERR, "rc_send_server: setsockopt: %s", 
					strerror(errno));
				result = ERROR_RC;
				goto cleanup;
			}
#else
			rc_log(LOG_INFO, "rc_send_server: Usage of non-temporary IPv6"
					" address is not supported in this system");
#endif       
		}
	}

	retry_max = data->retries;	/* Max. numbers to try for reply */
	retries = 0;		/* Init retry cnt for blocking call */

	if (data->svc_port) {
		if (our_sockaddr.ss_family == AF_INET)
			((struct sockaddr_in *)auth_addr->ai_addr)->sin_port =
			    htons((unsigned short)data->svc_port);
		else
			((struct sockaddr_in6 *)auth_addr->ai_addr)->sin6_port =
			    htons((unsigned short)data->svc_port);
	}

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
			void *p;
			p = &((struct sockaddr_in6 *)ss_set)->sin6_addr;

			rc_avpair_add(rh, &(data->send_pairs),
				      PW_NAS_IPV6_ADDRESS, p, 16, 0);
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

	/* Build a request */
	auth = (AUTH_HDR *) send_buffer;
	auth->code = data->code;
	auth->id = data->seq_nbr;

	if (data->code == PW_ACCOUNTING_REQUEST) {
		server_type = "acct";
		total_length =
		    rc_pack_list(data->send_pairs, secret, auth) + AUTH_HDR_LEN;

		tlen = htons((unsigned short)total_length);
		memcpy(&auth->length, &tlen, sizeof(uint16_t));

		memset((char *)auth->vector, 0, AUTH_VECTOR_LEN);
		secretlen = strlen(secret);
		memcpy((char *)auth + total_length, secret, secretlen);
		rc_md5_calc(vector, (unsigned char *)auth,
			    total_length + secretlen);
		memcpy((char *)auth->vector, (char *)vector, AUTH_VECTOR_LEN);
	} else {
		rc_random_vector(vector);
		memcpy((char *)auth->vector, (char *)vector, AUTH_VECTOR_LEN);

		total_length =
		    rc_pack_list(data->send_pairs, secret, auth) + AUTH_HDR_LEN;

		auth->length = htons((unsigned short)total_length);

		/* If EAP message we MUST add a Message-Authenticator attribute */
		if (rc_avpair_get(data->send_pairs, PW_EAP_MESSAGE, 0) != NULL)
		    total_length = add_msg_auth_attr(rh, secret, auth, total_length);
	}

	if (radcli_debug) {
		char our_addr_txt[50] = "";	/* hold a text IP */
		char auth_addr_txt[50] = "";	/* hold a text IP */

		getnameinfo(SA(&our_sockaddr), SS_LEN(&our_sockaddr), NULL, 0,
			    our_addr_txt, sizeof(our_addr_txt), NI_NUMERICHOST);
		getnameinfo(auth_addr->ai_addr, auth_addr->ai_addrlen, NULL, 0,
			    auth_addr_txt, sizeof(auth_addr_txt),
			    NI_NUMERICHOST);

		DEBUG(LOG_ERR,
		      "DEBUG: timeout=%d retries=%d local %s : 0, remote %s : %u\n",
		      data->timeout, retry_max, our_addr_txt, auth_addr_txt,
		      data->svc_port);
	}

	if (sfuncs->connect) {
		do {
			result =
			    sfuncs->connect(sfuncs->ptr, sockfd,
					    SA(auth_addr->ai_addr),
					    auth_addr->ai_addrlen);
		} while (result == -1 && errno == EINTR);
		if (result == -1) {
			result = errno == ENETUNREACH ? NETUNREACH_RC : ERROR_RC;
			rc_log(LOG_ERR, "%s: connect: %s", __FUNCTION__,
			       strerror(errno));
			goto cleanup;
		}
	}

	for (;;) {
		do {
			result =
			    sfuncs->sendto(sfuncs->ptr, sockfd, (char *)auth,
					   (unsigned int)total_length, (int)0,
					   SA(auth_addr->ai_addr),
					   auth_addr->ai_addrlen);
		} while (result == -1 && errno == EINTR);
		if (result == -1) {
			result = errno == ENETUNREACH ? NETUNREACH_RC : ERROR_RC;
			rc_log(LOG_ERR, "%s: sendto: %s", __FUNCTION__,
			       strerror(errno));
			goto cleanup;
		}

		pfd.fd = sockfd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		start_time = rc_getmtime();
		for (timeout = data->timeout; timeout > 0;
		     timeout -= rc_getmtime() - start_time) {
			result = poll(&pfd, 1, timeout * 1000);
			if (result != -1 || errno != EINTR)
				break;
		}

		if (result == -1) {
			rc_log(LOG_ERR, "rc_send_server: poll: %s",
			       strerror(errno));
			memset(secret, '\0', sizeof(secret));
			SCLOSE(sockfd);
			result = ERROR_RC;
			goto cleanup;
		}

		if (result == 1 && (pfd.revents & POLLIN) != 0) {
			salen = auth_addr->ai_addrlen;
			do {
				length = sfuncs->recvfrom(sfuncs->ptr, sockfd,
							  (char *)recv_buffer,
							  (int)
							  sizeof(recv_buffer),
							  (int)0,
							  SA(auth_addr->
							     ai_addr), &salen);
			} while (length == -1 && errno == EINTR);

			if (length <= 0) {
				int e = errno;
				rc_log(LOG_ERR,
				       "rc_send_server: recvfrom: %s:%d: %s",
				       server_name, data->svc_port,
				       strerror(e));
				if (length == -1 && (e == EAGAIN || e == EINTR))
					continue;
				SCLOSE(sockfd);
				memset(secret, '\0', sizeof(secret));
				result = ERROR_RC;
				goto cleanup;
			}

			recv_auth = (AUTH_HDR *) recv_buffer;

			if (length < AUTH_HDR_LEN
			    || length < ntohs(recv_auth->length)) {
				rc_log(LOG_ERR,
				       "rc_send_server: recvfrom: %s:%d: reply is too short",
				       server_name, data->svc_port);
				SCLOSE(sockfd);
				memset(secret, '\0', sizeof(secret));
				result = ERROR_RC;
				goto cleanup;
			}

			result =
			    rc_check_reply(recv_auth, RC_BUFFER_LEN, secret,
					   vector, data->seq_nbr);
			if (result != BADRESPID_RC) {
				/* if a message that doesn't match our ID was received, then ignore
				 * it, and try to receive more, until timeout. That is because in
				 * DTLS the channel is shared, and we may receive duplicates or
				 * out-of-order packets. */
				break;
			}
		}

		/*
		 * Timed out waiting for response.  Retry "retry_max" times
		 * before giving up.  If retry_max = 0, don't retry at all.
		 */
		if (retries++ >= retry_max) {
			char radius_server_ip[128];
			struct sockaddr_in *si =
			    (struct sockaddr_in *)auth_addr->ai_addr;
			inet_ntop(auth_addr->ai_family, &si->sin_addr,
				  radius_server_ip, sizeof(radius_server_ip));
			rc_log(LOG_ERR,
			       "rc_send_server: no reply from RADIUS %s server %s:%u",
			       server_type, radius_server_ip, data->svc_port);
			SCLOSE(sockfd);
			memset(secret, '\0', sizeof(secret));
			result = TIMEOUT_RC;
			goto cleanup;
		}
	}

	/*
	 *      If UDP is larger than RADIUS, shorten it to RADIUS.
	 */
	if (length > ntohs(recv_auth->length))
		length = ntohs(recv_auth->length);

	/*
	 *      Verify that it's a valid RADIUS packet before doing ANYTHING with it.
	 */
	attr = recv_buffer + AUTH_HDR_LEN;
	while (attr < (recv_buffer + length)) {
		if (attr[0] == 0) {
			rc_log(LOG_ERR,
			       "rc_send_server: recvfrom: %s:%d: attribute zero is invalid",
			       server_name, data->svc_port);
			SCLOSE(sockfd);
			memset(secret, '\0', sizeof(secret));
			result = ERROR_RC;
			goto cleanup;
		}

		if (attr[1] < 2) {
			rc_log(LOG_ERR,
			       "rc_send_server: recvfrom: %s:%d: attribute length is too small",
			       server_name, data->svc_port);
			SCLOSE(sockfd);
			memset(secret, '\0', sizeof(secret));
			result = ERROR_RC;
			goto cleanup;
		}

		if ((attr + attr[1]) > (recv_buffer + length)) {
			rc_log(LOG_ERR,
			       "rc_send_server: recvfrom: %s:%d: attribute overflows the packet",
			       server_name, data->svc_port);
			SCLOSE(sockfd);
			memset(secret, '\0', sizeof(secret));
			result = ERROR_RC;
			goto cleanup;
		}

		attr += attr[1];
	}

	length = ntohs(recv_auth->length) - AUTH_HDR_LEN;
	if (length > 0) {
		data->receive_pairs = rc_avpair_gen(rh, NULL, recv_auth->data,
						    length, 0);
	} else {
		data->receive_pairs = NULL;
	}

	SCLOSE(sockfd);
	result = populate_ctx(ctx, secret, vector);
	if (result != OK_RC) {
		memset(secret, '\0', sizeof(secret));
		goto cleanup;
	}

	memset(secret, '\0', sizeof(secret));

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

	switch (recv_auth->code) {
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
		rc_log(LOG_ERR, "rc_send_server: received RADIUS server response neither ACCEPT nor REJECT, code=%d is invalid",
		       recv_auth->code);
		result = BADRESP_RC;
	}

 cleanup:
	if (auth_addr)
		freeaddrinfo(auth_addr);

	if (sfuncs->unlock) {
		if (sfuncs->unlock(sfuncs->ptr) != 0) {
			rc_log(LOG_ERR, "%s: unlock error", __func__);
		}
	}
 exit_error:
	if (ns != NULL) {
		if(-1 == rc_reset_netns(&ns_def_hdl)) {
			rc_log(LOG_ERR, "rc_send_server: namespace %s reset failed", ns);
			result = ERROR_RC;
		}
	}

	return result;
}


/** Sends a request to a RADIUS server and waits for the reply
 *
 * @param rh a handle to parsed configuration
 * @param data a pointer to a SEND_DATA structure
 * @param msg must be an array of %PW_MAX_MSG_SIZE or NULL; will contain the concatenation of
 *	any %PW_REPLY_MESSAGE received.
 * @param type must be %AUTH or %ACCT
 * @return OK_RC (0) on success, TIMEOUT_RC on timeout REJECT_RC on acess reject, or negative
 *	on failure as return value.
 */
int rc_send_server(rc_handle * rh, SEND_DATA * data, char *msg, rc_type type)
{
	return rc_send_server_ctx(rh, NULL, data, msg, type);
}
