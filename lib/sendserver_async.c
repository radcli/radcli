/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * Copyright (C) 2022 Cadami GmbH, info@cadami.net
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 */

#include <includes.h>
#include <radcli/radcli.h>
#include <pathnames.h>
#include <poll.h>

#include "sendserver_util.h"
#include "util.h"
#include "rc-md5.h"
#include "rc-hmac.h"

#if defined(__linux__)
#include <linux/in6.h>
#endif


enum rc_async_handle_state {
	RC_ASYNC_CREATED,
	RC_ASYNC_PREPARED,
	RC_ASYNC_CONNECTING,
	RC_ASYNC_SENDING,
	RC_ASYNC_RECEIVING,
	RC_ASYNC_DONE,
};


struct rc_async_handle {
	char *msg;
	SEND_DATA data;
	rc_type type;
	RC_AAA_CTX **ctx;
	rc_handle *rh;
	int sockfd;
	int result;

	enum rc_async_handle_state state;
	struct addrinfo *auth_addr;
	const rc_sockets_override *sfuncs;
	rc_socket_type so_type;
	size_t secretlen;
	char secret[MAX_SECRET_LENGTH + 1];
	unsigned char vector[AUTH_VECTOR_LEN];
	uint8_t recv_buffer[RC_BUFFER_LEN];
	uint8_t send_buffer[RC_BUFFER_LEN];
	int send_length;
	int transferred;
	int retry_max;
	int retries;
	double start_time;
	double timeout;
};


static struct rc_async_handle *
rc_async_alloc_handle(void)
{
	struct rc_async_handle *hdl = calloc(1, sizeof(struct rc_async_handle));
	if (!hdl)
		return NULL;

	hdl->msg = calloc(PW_MAX_MSG_SIZE, sizeof(char));
	if (!hdl->msg) {
		free(hdl);
		return NULL;
	}

	hdl->msg[0] = '\0';

	hdl->sockfd = -1;

	hdl->data.send_pairs = NULL;
	hdl->data.receive_pairs = NULL;

	return hdl;
}


/** Destroy and deallocate an rc_async_handle.
 *
 * The function does nothing if the passed handle is NULL.
 *
 * @param hdl the rc_async_handle to destroy.
 */
void
rc_async_destroy_handle(struct rc_async_handle *hdl)
{
	if (!hdl)
		return;

	if (hdl->sockfd >= 0)
		if (hdl->sfuncs->close_fd)
			hdl->sfuncs->close_fd(hdl->sockfd);

	if (hdl->auth_addr)
		freeaddrinfo(hdl->auth_addr);

	if (hdl->msg)
		free(hdl->msg);

	if (hdl->data.send_pairs)
		rc_avpair_free(hdl->data.send_pairs);

	if (hdl->data.receive_pairs)
		rc_avpair_free(hdl->data.receive_pairs);

	/* Note: memset is no good for clearing secrets.  But it's what radcli
	 * does in other places as well.  :shrug: */
	memset(hdl->secret, '\0', sizeof(hdl->secret));

	free(hdl);
}


/** Check whether the rc_async_handle is done and has a result.
 *
 * @param hdl the rc_async_handle.
 * @return true (1) if the handle is done.
 */
int
rc_async_is_done(struct rc_async_handle *hdl)
{
	return hdl->state == RC_ASYNC_DONE;
}


/** Query the result of the request.
 *
 * Must only be called if the handle is done.
 *
 * @param hdl the rc_async_handle.
 * @return OK_RC (0) on success, CHALLENGE_RC (3) on Access-Challenge
 *  received, negative on failure as return value.
 */
int
rc_async_get_result(struct rc_async_handle *hdl)
{
	return hdl->result;
}


/** Get the concatenated PW_REPLY messages if any where received.
 *
 * Must only be called if the handle is done.
 *
 * @param hdl the rc_async_handle.
 * @return messages from the server or NULL
 */
char *
rc_async_get_reply_message(struct rc_async_handle *hdl)
{
	return hdl->msg;
}


/** Get the values received from the server.
 *
 * Must only be called if the handle is done.
 *
 * @param hdl the rc_async_handle.
 * @return array of values received from the server.
 */
VALUE_PAIR *
rc_async_get_receive_pairs(struct rc_async_handle *hdl)
{
	return hdl->data.receive_pairs;
}


/** Get the sent values to the server.
 *
 * Must only be called if the handle is done.
 *
 * @param hdl the rc_async_handle.
 * @return array of values sent to the server.
 */
VALUE_PAIR *
rc_async_get_send_pairs(struct rc_async_handle *hdl)
{
	return hdl->data.send_pairs;
}


/** Get the rc_socket_type of the socket.
 *
 * @param hdl the rc_async_handle.
 * @return the rc_socket_type
 */
rc_socket_type
rc_async_get_socket_type(struct rc_async_handle *hdl)
{
	return hdl->so_type;
}


/** Get the open socket file descriptor.
 *
 * @param hdl the rc_async_handle.
 * @return the open file descriptor or -1 if there is none.
 */
int
rc_async_get_fd(struct rc_async_handle *hdl)
{
	return hdl->sockfd;
}


/** Get the poll events that the handle is waiting for.
 *
 * @param hdl the rc_async_handle.
 * @return bitwise or of the expected poll events or 0 if none are expected.
 */
short
rc_async_get_events(struct rc_async_handle *hdl)
{
	switch (hdl->state) {
	case RC_ASYNC_CONNECTING:
	case RC_ASYNC_SENDING:
		return POLLOUT;
	case RC_ASYNC_RECEIVING:
		return POLLIN;
	default:
		return 0;
	}
}


static int
set_sock_to_nonblock(int sock)
{
	int flags = 0;

	flags = fcntl(sock, F_GETFL);
	if (flags == -1) {
		rc_log(LOG_WARNING, "%s: Could not obtain old socket flags. "
			"Overwriting old ones with O_NONBLOCK only.", __func__);
		flags = O_NONBLOCK;
	} else {
		flags |= O_NONBLOCK;
	}

	return fcntl(sock, F_SETFL, flags);
}


static int
check_configure_ipv6(int sockfd, rc_handle *rh)
{
	int sock_opt = 0;
	char *non_temp_addr = NULL;

	/* Check for IPv6 non-temporary address support */
	non_temp_addr = rc_conf_str(rh, "use-public-addr");
	if (non_temp_addr && (strcasecmp(non_temp_addr, "true") != 0))
		return 0;

#if defined(__linux__)
	sock_opt = IPV6_PREFER_SRC_PUBLIC;
	if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES,
			&sock_opt, sizeof(sock_opt)) != 0) {
		rc_log(LOG_ERR, "%s: setsockopt: %s", __func__,
			strerror(errno));
		return ERROR_RC;
	}

#elif defined(BSD) || defined(__APPLE__)
	sock_opt = 0;
	if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR,
			&sock_opt, sizeof(sock_opt)) != 0) {
		rc_log(LOG_ERR, "%s: setsockopt: %s", __func__,
			strerror(errno));
		return ERROR_RC;
	}
#else
	rc_log(LOG_INFO, "%s: Usage of non-temporary IPv6"
		" address is not supported in this system", __func__);
#endif

	return 0;
}


static void
prepare_request(struct rc_async_handle *hdl)
{
	struct sockaddr_storage *ss_set = NULL;
	struct sockaddr_storage our_sockaddr;
	SEND_DATA *data = &hdl->data;
	unsigned discover_local_ip;
	int result = ERROR_RC;
	AUTH_HDR *auth;
	uint16_t tlen;
	char *p;

	if (hdl->sfuncs->static_secret) {
		/* any static secret set in sfuncs overrides the configured */
		strlcpy(hdl->secret, hdl->sfuncs->static_secret,
			MAX_SECRET_LENGTH);
	}

	rc_own_bind_addr(hdl->rh, &our_sockaddr);
	discover_local_ip = 0;
	if (our_sockaddr.ss_family == AF_INET) {
		if (((struct sockaddr_in *)(&our_sockaddr))->sin_addr.s_addr ==
				INADDR_ANY) {
			discover_local_ip = 1;
		}
	}

	DEBUG(LOG_ERR, "DEBUG: rc_send_server: creating socket to: %s",
		hdl->data.server);
	if (discover_local_ip) {
		result = rc_get_srcaddr(SA(&our_sockaddr), hdl->auth_addr->ai_addr);
		if (result != OK_RC) {
			rc_log(LOG_ERR, "%s: cannot figure our own address",
				__func__);
			goto error;
		}
	}

	if (hdl->sfuncs->get_fd) {
		hdl->sockfd = hdl->sfuncs->get_fd(hdl->sfuncs->ptr, SA(&our_sockaddr));
		if (hdl->sockfd < 0) {
			rc_log(LOG_ERR, "%s: socket: %s", __func__,
				strerror(errno));
			goto error;
		}
	}

	if (our_sockaddr.ss_family == AF_INET6) {
		result = check_configure_ipv6(hdl->sockfd, hdl->rh);
		if (result == ERROR_RC)
			goto error;
	}

	if (data->svc_port) {
		if (our_sockaddr.ss_family == AF_INET) {
			((struct sockaddr_in *)hdl->auth_addr->ai_addr)->sin_port =
				htons((unsigned short)data->svc_port);
		} else {
			((struct sockaddr_in6 *)hdl->auth_addr->ai_addr)->sin6_port =
				htons((unsigned short)data->svc_port);
		}
	}

	/*
	 * Fill in NAS-IP-Address (if needed)
	 */
	if (hdl->rh->nas_addr_set) {
		rc_avpair_remove(&(data->send_pairs), PW_NAS_IP_ADDRESS, 0);
		rc_avpair_remove(&(data->send_pairs), PW_NAS_IPV6_ADDRESS, 0);

		ss_set = &hdl->rh->nas_addr;
	} else if (rc_avpair_get(data->send_pairs, PW_NAS_IP_ADDRESS, 0) == NULL &&
			rc_avpair_get(data->send_pairs, PW_NAS_IPV6_ADDRESS, 0) == NULL) {
		ss_set = &our_sockaddr;
	}

	if (ss_set) {
		if (ss_set->ss_family == AF_INET) {
			uint32_t ip;
			ip = *((uint32_t*) (&((struct sockaddr_in *)ss_set)->sin_addr));
			ip = ntohl(ip);

			rc_avpair_add(hdl->rh, &(data->send_pairs),
					PW_NAS_IP_ADDRESS, &ip, 0, 0);
		} else {
			void *tmp_pt;
			tmp_pt = &((struct sockaddr_in6 *)ss_set)->sin6_addr;
			rc_avpair_add(hdl->rh, &(data->send_pairs),
					PW_NAS_IPV6_ADDRESS, tmp_pt, 16, 0);
		}
	}

	/*
	 * Fill in NAS-Identifier (if needed)
	 */
	p = rc_conf_str(hdl->rh, "nas-identifier");
	if (p != NULL) {
		rc_avpair_remove(&(data->send_pairs), PW_NAS_IDENTIFIER, 0);
		rc_avpair_add(hdl->rh, &(data->send_pairs),
			      PW_NAS_IDENTIFIER, p, -1, 0);
	}

	/*
	 * Build a request
	 */
	auth = (AUTH_HDR *) hdl->send_buffer;
	auth->code = data->code;
	auth->id = data->seq_nbr;

	if (data->code == PW_ACCOUNTING_REQUEST) {
		hdl->send_length = rc_pack_list(data->send_pairs,
				hdl->secret, auth) + AUTH_HDR_LEN;

		tlen = htons((unsigned short)hdl->send_length);
		memcpy(&(auth->length), &tlen, sizeof(uint16_t));

		memset((char *)auth->vector, 0, AUTH_VECTOR_LEN);
		hdl->secretlen = strlen(hdl->secret);
		memcpy((char *)auth + hdl->send_length, hdl->secret, hdl->secretlen);
		rc_md5_calc(hdl->vector, (unsigned char *)auth,
			    hdl->send_length + hdl->secretlen);
		memcpy((char *)auth->vector, (char *)hdl->vector, AUTH_VECTOR_LEN);
	} else {
		rc_random_vector(hdl->vector);
		memcpy((char *)auth->vector, (char *)hdl->vector, AUTH_VECTOR_LEN);

		hdl->send_length = rc_pack_list(data->send_pairs, hdl->secret,
			auth) + AUTH_HDR_LEN;

		auth->length = htons((unsigned short)hdl->send_length);

		/* If EAP message we MUST add a Message-Authenticator attribute */
		if (rc_avpair_get(data->send_pairs, PW_EAP_MESSAGE, 0) != NULL) {
			hdl->send_length = add_msg_auth_attr(hdl->rh, hdl->secret,
				auth, hdl->send_length);
		}
	}

	if (radcli_debug) {
		char our_addr_txt[50] = "";	/* hold a text IP */
		char auth_addr_txt[50] = "";	/* hold a text IP */

		getnameinfo(SA(&our_sockaddr), SS_LEN(&our_sockaddr),
			NULL, 0, our_addr_txt, sizeof(our_addr_txt),
			NI_NUMERICHOST);
		getnameinfo(hdl->auth_addr->ai_addr, hdl->auth_addr->ai_addrlen,
			NULL, 0, auth_addr_txt, sizeof(auth_addr_txt),
			NI_NUMERICHOST);

		DEBUG(LOG_ERR,
			"DEBUG: timeout=%d retries=%d local %s : 0, remote %s : %u\n",
			data->timeout, hdl->retry_max, our_addr_txt,
			auth_addr_txt, data->svc_port);
	}

	result = set_sock_to_nonblock(hdl->sockfd);
	if (result == -1) {
		rc_log(LOG_ERR, "%s: set socket nonblocking: %s", __func__,
			strerror(errno));
		goto error;
	}

	/*
	 * Store when this request has been submitted, so we can later
	 * check if the request has timed out.
	 */
	hdl->start_time = rc_getmtime();

	hdl->state = RC_ASYNC_PREPARED;
	hdl->result = OK_RC;

	return;

error:
	hdl->state = RC_ASYNC_DONE;
	hdl->result = ERROR_RC;

	return;
}


static void
connect_to_server(struct rc_async_handle *hdl)
{
	int result = 0;

	if (hdl->sfuncs->connect) {
		do {
			result = hdl->sfuncs->connect(hdl->sfuncs->ptr, hdl->sockfd,
				SA(hdl->auth_addr->ai_addr), hdl->auth_addr->ai_addrlen);
		} while (result == -1 && errno == EINTR);

		if (result == -1 &&
		    (errno == EINPROGRESS || errno == EALREADY ||
		     errno == EAGAIN || errno == EWOULDBLOCK))
		{
			hdl->state = RC_ASYNC_CONNECTING;
			hdl->result = OK_RC;
			return;
		}

		if (result == -1) {
			rc_log(LOG_ERR, "%s: connect: %s", __func__, strerror(errno));
			hdl->state = RC_ASYNC_DONE;
			hdl->result = errno == ENETUNREACH ? NETUNREACH_RC : ERROR_RC;
			return;
		}
	}

	hdl->state = RC_ASYNC_SENDING;
	hdl->result = OK_RC;
	hdl->transferred = 0;

	return;
}


static void
check_connected(struct rc_async_handle *hdl)
{
	socklen_t optlen = sizeof(int);
	int result = ERROR_RC;
	int err = 0;

	result = getsockopt(hdl->sockfd, SOL_SOCKET, SO_ERROR, &err, &optlen);
	if (result == -1) {
		rc_log(LOG_ERR, "%s: getsockopt: %s", __func__, strerror(errno));
		hdl->state = RC_ASYNC_DONE;
		hdl->result = ERROR_RC;
		return;
	}

	if (err == EAGAIN || err == EWOULDBLOCK || err == EINPROGRESS || err == EALREADY)
		return;

	if (err != 0) {
		rc_log(LOG_ERR, "%s: connect: %s", __func__, strerror(err));
		hdl->state = RC_ASYNC_DONE;
		hdl->result = ERROR_RC;
		return;
	}

	hdl->state = RC_ASYNC_SENDING;
	hdl->result = OK_RC;
	hdl->transferred = 0;
}

static void
send_request(struct rc_async_handle *hdl)
{
	int result = ERROR_RC;

	do {
		result = hdl->sfuncs->sendto(hdl->sfuncs->ptr, hdl->sockfd,
			hdl->send_buffer + hdl->transferred,
			(unsigned)(hdl->send_length - hdl->transferred), 0,
			SA(hdl->auth_addr->ai_addr), hdl->auth_addr->ai_addrlen);
	} while (result == -1 && errno == EINTR);

	if (result == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return;

	if (result == -1) {
		rc_log(LOG_ERR, "%s: sendto: %s", __func__, strerror(errno));
		hdl->state = RC_ASYNC_DONE;
		hdl->result = errno == ENETUNREACH ? NETUNREACH_RC : ERROR_RC;
		return;
	}

	if (hdl->so_type == RC_SOCKET_TCP) {
		hdl->transferred += result;
		result = hdl->transferred;
		if (result < hdl->send_length)
			return;
	} else {
		if (result < hdl->send_length) {
			rc_log(LOG_ERR, "%s: sendto: send to short", __func__);
			hdl->state = RC_ASYNC_DONE;
			hdl->result = ERROR_RC;
			return;
		}
	}

	hdl->result = OK_RC;
	hdl->state = RC_ASYNC_RECEIVING;
	hdl->transferred = 0;

	return;
}


static int
check_server_response_code(uint8_t code)
{
	int result = BADRESP_RC;

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
		rc_log(LOG_ERR, "%s: received RADIUS server "
			"response neither ACCEPT nor REJECT, code=%d is invalid",
			__func__, code);
		result = BADRESP_RC;
		break;
	}

	return result;
}


static void
receive_response(struct rc_async_handle *hdl)
{
	int result = ERROR_RC;
	AUTH_HDR *recv_auth;
	socklen_t salen;
	VALUE_PAIR *vp;
	uint8_t *attr;
	int length;
	int pos;

	do {
		salen = hdl->auth_addr->ai_addrlen;
		result = hdl->sfuncs->recvfrom(hdl->sfuncs->ptr, hdl->sockfd,
				hdl->recv_buffer + hdl->transferred,
				sizeof(hdl->recv_buffer) - hdl->transferred, 0,
				SA(hdl->auth_addr->ai_addr), &salen);
	} while (result == -1 && errno == EINTR);

	if (result == -1 && (errno == EWOULDBLOCK || errno == EAGAIN))
		return;

	if (result == -1) {
		rc_log(LOG_ERR, "%s: recvfrom: %s:%d: %s",
			__func__, hdl->data.server, hdl->data.svc_port,
			strerror(errno));
		result = ERROR_RC;
		goto done;
	}

	recv_auth = (AUTH_HDR *)(hdl->recv_buffer);
	length = result;

	if (hdl->so_type == RC_SOCKET_TCP) {
		hdl->transferred += length;
		length = hdl->transferred;
		if (length < AUTH_HDR_LEN || length < ntohs(recv_auth->length))
			return;
	} else {
		if (length < AUTH_HDR_LEN || length < ntohs(recv_auth->length)) {
			rc_log(LOG_ERR, "%s: recvfrom: %s:%d: reply is too short",
				__func__, hdl->data.server, hdl->data.svc_port);
			result = ERROR_RC;
			goto done;
		}
	}

	result = rc_check_reply(recv_auth, RC_BUFFER_LEN, hdl->secret,
		hdl->vector, hdl->data.seq_nbr);
	if (result != OK_RC) {
		goto done;
	}

	/*
	 *      If UDP is larger than RADIUS, shorten it to RADIUS.
	 */
	if (length > ntohs(recv_auth->length))
		length = ntohs(recv_auth->length);

	/*
	 *      Verify that it's a valid RADIUS packet before doing ANYTHING with it.
	 */
	attr = hdl->recv_buffer + AUTH_HDR_LEN;
	result = ERROR_RC;

	while (attr < (hdl->recv_buffer + length)) {
		if (attr[0] == 0) {
			rc_log(LOG_ERR,
				"%s: recvfrom: %s:%d: attribute zero is invalid",
				__func__, hdl->data.server, hdl->data.svc_port);
			goto done;
		}

		if (attr[1] < 2) {
			rc_log(LOG_ERR,
				"%s: recvfrom: %s:%d: attribute length is too small",
				__func__, hdl->data.server, hdl->data.svc_port);
			goto done;
		}

		if ((attr + attr[1]) > (hdl->recv_buffer + length)) {
			rc_log(LOG_ERR,
				"%s: recvfrom: %s:%d: attribute overflows the packet",
				__func__, hdl->data.server, hdl->data.svc_port);
			goto done;
		}

		attr += attr[1];
	}

	length = ntohs(recv_auth->length) - AUTH_HDR_LEN;
	if (length > 0) {
		hdl->data.receive_pairs = rc_avpair_gen(hdl->rh, NULL,
			recv_auth->data, length, 0);
	} else {
		hdl->data.receive_pairs = NULL;
	}

	result = populate_ctx(hdl->ctx, hdl->secret, hdl->vector);
	if (result != OK_RC) {
		result = ERROR_RC;
		goto done;
	}

	/* In this async implementation, there is always a message allocated. */
	hdl->msg[0] = '\0';
	vp = hdl->data.receive_pairs;
	pos = 0;
	while (vp) {
		if ((vp = rc_avpair_get(vp, PW_REPLY_MESSAGE, 0))) {
			strappend(hdl->msg, PW_MAX_MSG_SIZE, &pos,
				vp->strvalue);
			strappend(hdl->msg, PW_MAX_MSG_SIZE, &pos, "\n");
			vp = vp->next;
		}
	}

	result = check_server_response_code(recv_auth->code);

done:
	hdl->state = RC_ASYNC_DONE;
	hdl->result = result;

	return;
}


/*
 * Checks whether the request has been pending for too long by now. The start
 * time has been set in rc_async_send_server_ctx().
 */
static void
check_for_timeout(struct rc_async_handle *hdl)
{
	double start_time = hdl->start_time;
	int timeout = hdl->timeout;
	double current_time;

	current_time = rc_getmtime();
	if (current_time < 0) {
		rc_log(LOG_ERR, "%s: Can not deliver current time."
			" Can not time out requests. Dead requests will remain enqueued.",
			__func__);
		return;
	}

	if (timeout < 0) {
		rc_log(LOG_ERR, "%s: Invalid timeout specified. "
			" Can not time out requests. Dead requests will remain enqueued.",
			__func__);
		return;
	}

	if (current_time - start_time < timeout) {
		/* No timeout has occurred yet. */
		return;
	}

	if (hdl->retries >= hdl->retry_max) {
		hdl->result = TIMEOUT_RC;
		hdl->state = RC_ASYNC_DONE;
	} else {
		hdl->retries++;
	}
}


/** Processes the handle according to the pass bit mask of observed poll events
 * on the associated file descriptor and check for timeouts.  Return whether
 * the handle is done. Pass revents = POLLIN | POLLOUT for full processing.
 *
 * @param hdl the rc_async_handle to process.
 * @param revents the observed events that should be processed.
 * @return 1 (true) if the handle is done, otherwise 0 (false).
 */
int
rc_async_process_handle(struct rc_async_handle *hdl, short revents)
{
	rc_log(LOG_INFO, "%s: ENTER hdl %016lx   fd %4d   state %2d   result %3d\n",
			__func__, (unsigned long)hdl, hdl->sockfd, hdl->state,
			hdl->result);

	if (hdl->state == RC_ASYNC_CREATED)
		prepare_request(hdl);

	if (hdl->state == RC_ASYNC_PREPARED)
		connect_to_server(hdl);

	if (hdl->state == RC_ASYNC_CONNECTING)
		if (revents & POLLOUT)
			check_connected(hdl);

	if (hdl->state == RC_ASYNC_SENDING)
		if (revents & POLLOUT)
			send_request(hdl);

	if (hdl->state == RC_ASYNC_RECEIVING)
		if (revents & POLLIN)
			receive_response(hdl);

	if (hdl->state != RC_ASYNC_CREATED && hdl->state != RC_ASYNC_DONE)
		check_for_timeout(hdl);

	rc_log(LOG_INFO, "%s: EXIT  hdl %016lx   fd %4d   state %2d   result %3d\n",
			__func__, (unsigned long)hdl, hdl->sockfd, hdl->state,
			hdl->result);

	return rc_async_is_done(hdl);
}


/*
 * In the function below, rc_type type is not documented in the original
 * rc_aaa_ctx_server() in buildreq.c. Find out what it does and document it
 * there and here.
 */

/** Builds an asynchronous authentication/accounting request for port id
 * nas_port with the value_pairs send for sending it to the first server in
 * aaaserver.  The request can be added to a rc_async_multihandle for
 * asynchronous processing.
 *
 * @note This function currently only supports sending to ONE server. Only the
 * first server in aaaserver is used.
 *
 * @note The returned rc_async_handle must be freed by the caller using
 * rc_async_destroy_handle.
 *
 * @param rh a handle to parsed configuration. This configuration should always
 * contain a timeout > 0 - otherwise zombie requests might occur.
 * @param ctx if non-NULL it will contain the context of the request;
 * Its initial value should be NULL and it must be released using rc_aaa_ctx_free().
 * @param aaaserver a non-NULL SERVER to send the message to.
 * @param nas_port the physical NAS port number to use (may be zero).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param add_nas_port this should be zero; if non-zero it will include PW_NAS_PORT in sent pairs.
 * @param request_type one of standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @return pointer to allocated rc_async_handle or NULL on error.
 */
struct rc_async_handle *
rc_async_create_handle(rc_handle *rh, RC_AAA_CTX **ctx, SERVER *aaaserver,
		rc_type type, uint32_t nas_port, VALUE_PAIR *send,
		int add_nas_port, rc_standard_codes request_type)
{
	struct rc_async_handle *hdl = NULL;
	SEND_DATA *data;
	VALUE_PAIR *adt_vp = NULL;
	VALUE_PAIR *vp = NULL;
	int timeout = rc_conf_int(rh, "radius_timeout");
	int retries = rc_conf_int(rh, "radius_retries");
	double start_time = 0;
	double now = 0;
	time_t dtime;
	int servernum;

	/* Check the namespace configuration */
	if (rh->so_type != RC_SOCKET_UDP && rh->so_type != RC_SOCKET_TCP) {
		rc_log(LOG_ERR, "%s: Async should only be "
			"used with plain UDP or TCP sockets.",
			__func__);
		return NULL;
	}

	if (rh->so.lock) {
		rc_log(LOG_ERR,
			"%s: Socket locking not supported for async operations.",
			__func__);
		return NULL;
	}

	if (rc_conf_str(rh, "namespace")) {
		rc_log(LOG_ERR,
			"%s: namespace setting not supported for async operations.",
			__func__);
		return NULL;
	}

	hdl = rc_async_alloc_handle();
	if (!hdl)
		return NULL;

	data = &hdl->data;

	data->send_pairs = rc_avpair_copy(send);
	if (!data->send_pairs)
		goto error;

	if (add_nas_port != 0 && !rc_avpair_get(data->send_pairs, PW_NAS_PORT, 0)) {
		/*
		 * Fill in NAS-Port
		 */
		if (rc_avpair_add(rh, &(data->send_pairs), PW_NAS_PORT,
				&nas_port, 0, 0) == NULL) {
			goto error;
		}
	}

	if (request_type == PW_ACCOUNTING_REQUEST) {
		/*
		 * Fill in Acct-Delay-Time
		 */
		dtime = 0;
		now = rc_getmtime();
		adt_vp = rc_avpair_get(data->send_pairs, PW_ACCT_DELAY_TIME, 0);
		if (adt_vp == NULL) {
			adt_vp = rc_avpair_add(rh, &(data->send_pairs),
				PW_ACCT_DELAY_TIME, &dtime, 0, 0);

			if (adt_vp == NULL)
				goto error;

			start_time = now;
		} else {
			start_time = now - adt_vp->lvalue;
		}
	}

	if (aaaserver->max > 1) {
		rc_log(LOG_WARNING, "%s: More than one target RADIUS server. "
			"async-radcli currently supports only requests to 1 server "
			"per request. Ignoring the other ones.", __func__);
	}

	servernum = 0;
	rc_buildreq(rh, data, request_type, aaaserver->name[servernum],
		    aaaserver->port[servernum],
		    aaaserver->secret[servernum], timeout, retries);

	if (request_type == PW_ACCOUNTING_REQUEST) {
		dtime = rc_getmtime() - start_time;
		rc_avpair_assign(adt_vp, &dtime, 0);
	}

	if (!data->server || data->server[0] == '\0')
		goto error;

	if ((vp = rc_avpair_get(data->send_pairs, PW_SERVICE_TYPE, 0)) &&
			(vp->lvalue == PW_ADMINISTRATIVE)) {
		strcpy(hdl->secret, MGMT_POLL_SECRET);
		hdl->auth_addr = rc_getaddrinfo(data->server,
			type == AUTH ? PW_AI_AUTH : PW_AI_ACCT);
		if (hdl->auth_addr == NULL) {
			goto error;
		}
	} else {
		if (data->secret != NULL) {
			strlcpy(hdl->secret, data->secret, MAX_SECRET_LENGTH);
		}

		if (rc_find_server_addr(rh, data->server, &(hdl->auth_addr),
				hdl->secret, type) != 0) {
			rc_log(LOG_ERR, "%s: unable to find server: %s",
				__func__, data->server);
			goto error;
		}
	}

	hdl->type = type;
	hdl->ctx = ctx;
	hdl->rh = rh;
	hdl->sfuncs = &rh->so;
	hdl->so_type = rh->so_type;
	hdl->retry_max = data->retries;	/* Max. numbers to try for reply */
	hdl->retries = 0;		/* Init retry cnt for blocking call */
	hdl->timeout = data->timeout;

	hdl->state = RC_ASYNC_CREATED;
	hdl->result = OK_RC;

	return hdl;

error:
	rc_async_destroy_handle(hdl);

	return NULL;
}


/** Builds an asynchronous accounting request for port id nas_port with the
 * value_pairs at send.  The request can be added to a rc_async_multihandle for
 * asynchronous processing.
 *
 * @note The returned rc_async_handle must be freed by the caller using
 * rc_async_destroy_handle.
 *
 * @param rh a handle to parsed configuration. This configuration should always
 * contain a timeout > 0 - otherwise zombie requests might occur.
 * @param nas_port the physical NAS port number to use (may be zero).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @return pointer to allocated rc_async_handle or NULL on error.
 */
struct rc_async_handle *
rc_async_create_handle_auth(rc_handle *rh, uint32_t nas_port,
		VALUE_PAIR *send)
{
	SERVER *aaaserver = rc_conf_srv(rh, "authserver");
	if (!aaaserver)
		return NULL;

	return rc_async_create_handle(rh, NULL, aaaserver, AUTH, nas_port,
			send, 1, PW_ACCESS_REQUEST);
}


/** Builds an asynchronous accounting request for port id nas_port with the
 * value_pairs at send.  The request can be added to a rc_async_multihandle for
 * asynchronous processing.
 *
 * @note The returned rc_async_handle must be freed by the caller using
 * rc_async_destroy_handle.
 *
 * @note NAS-IP-Address, NAS-Port and Acct-Delay-Time get filled in by this
 * function, the rest has to be supplied.
 *
 * @param rh a handle to parsed configuration. This configuration should always
 * contain a timeout > 0 - otherwise zombie requests might occur.
 * @param nas_port the physical NAS port number to use (may be zero).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @return pointer to allocated rc_async_handle or NULL on error.
 */
struct rc_async_handle *
rc_async_create_handle_acct(rc_handle *rh, uint32_t nas_port,
		VALUE_PAIR *send)
{
	SERVER *aaaserver = rc_conf_srv(rh, "acctserver");
	if (!aaaserver)
		return NULL;

	return rc_async_create_handle(rh, NULL, aaaserver, ACCT, nas_port,
			send, 1, PW_ACCOUNTING_REQUEST);
}
