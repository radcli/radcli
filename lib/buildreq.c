/*
 * Copyright (C) 1995,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */
#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include "util.h"
#include "rc-random.h"

/**
 * @defgroup radcli-api Main API
 * @brief Main API Functions
 *
 * @{
 */

/** @brief Build a skeleton RADIUS request using information from the config file
 *
 * @note This is a low-level helper used internally by rc_aaa_ctx_server().
 * Normal applications should call rc_auth() or rc_acct() instead of
 * constructing SEND_DATA directly.
 *
 * @param rh a handle to parsed configuration.
 * @param data a pointer to a SEND_DATA structure.
 * @param code one of standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @param server the name of the server.
 * @param port the server's port number.
 * @param secret the secret used by the server.
 * @param timeout the timeout in seconds of a message.
 * @param retries the number of retries.
 */
void rc_buildreq(rc_handle const *rh, SEND_DATA * data, int code, char *server,
		 unsigned short port, char *secret, int timeout, int retries)
{
	data->server = server;
	data->secret = secret;
	data->svc_port = port;
	data->seq_nbr = rc_get_random_byte();
	data->timeout = timeout;
	data->retries = retries;
	data->code = code;
}

/** @brief Selects the server list and rc_type for a request based on transport and request type
 *
 * @note Internal helper shared by rc_aaa_ctx() and rc_acct_async().
 *
 * @param rh a handle to parsed configuration.
 * @param aaaserver receives the selected SERVER list from configuration.
 * @param type receives AUTH or ACCT, matching the selected server list.
 * @param request_type one of the standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @return OK_RC (0) on success, ERROR_RC if no matching servers are configured.
 */
static int rc_select_aaa_server(rc_handle *rh, SERVER **aaaserver,
				rc_type *type, rc_standard_codes request_type)
{
	if (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS ||
	    request_type != PW_ACCOUNTING_REQUEST) {
		*aaaserver = rc_conf_srv(rh, "authserver");
		*type = AUTH;
	} else {
		*aaaserver = rc_conf_srv(rh, "acctserver");
		*type = ACCT;
	}

	if (*aaaserver == NULL)
		return ERROR_RC;

	return OK_RC;
}

/** @brief Fills in NAS-Port and Acct-Delay-Time on a request being built
 *
 * @note Internal helper shared by rc_aaa_ctx_server() and
 * rc_aaa_ctx_server_async().
 *
 * @param rh a handle to parsed configuration.
 * @param data the request being built; @c send_pairs is extended in place.
 * @param nas_port the physical NAS port number to include (may be zero).
 * @param add_nas_port if non-zero, PW_NAS_PORT is added to the sent pairs.
 * @param request_type one of the standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @param adt_vp receives the Acct-Delay-Time pair when @p request_type is
 *  PW_ACCOUNTING_REQUEST, so the caller can update it on each retransmission.
 * @param start_time receives the time the delay is measured from.
 * @return OK_RC (0) on success, ERROR_RC on failure.
 */
static int rc_fill_acct_pairs(rc_handle const *rh, SEND_DATA *data,
			      uint32_t nas_port, int add_nas_port,
			      rc_standard_codes request_type,
			      VALUE_PAIR **adt_vp, double *start_time)
{
	time_t dtime;
	double now;

	if (add_nas_port != 0
	    && rc_avpair_get(data->send_pairs, PW_NAS_PORT, 0) == NULL) {
		/*
		 * Fill in NAS-Port
		 */
		if (rc_avpair_add(rh, &(data->send_pairs), PW_NAS_PORT,
				  &nas_port, 0, 0) == NULL)
			return ERROR_RC;
	}

	if (request_type == PW_ACCOUNTING_REQUEST) {
		/*
		 * Fill in Acct-Delay-Time
		 */
		dtime = 0;
		now = rc_getmtime();
		*adt_vp = rc_avpair_get(data->send_pairs, PW_ACCT_DELAY_TIME, 0);
		if (*adt_vp == NULL) {
			*adt_vp = rc_avpair_add(rh, &(data->send_pairs),
					       PW_ACCT_DELAY_TIME, &dtime, 0,
					       0);
			if (*adt_vp == NULL)
				return ERROR_RC;
			*start_time = now;
		} else {
			*start_time = now - (*adt_vp)->lvalue;
		}
	}

	return OK_RC;
}

/** @brief Builds an authentication/accounting request and submits it to a server, optionally returning context
 *
 * Selects the server list from configuration (authserver or acctserver
 * depending on @p request_type and transport), sends the request with
 * automatic retry and server failover, and returns the server's response.
 *
 * @note Use rc_auth() or rc_acct() when no context is needed (they call this
 * with @p ctx set to NULL).  Pass a non-NULL @p ctx only when you need to
 * inspect the secret and vector used in the request afterwards.
 *
 * @param rh a handle to parsed configuration.
 * @param ctx if non-NULL, receives an allocated RC_AAA_CTX on success; the
 *   caller must free it with rc_aaa_ctx_free().  Pass NULL if not needed.
 * @param nas_port the physical NAS port number to include (may be zero).
 * @param send VALUE_PAIR list of attributes to send (e.g., PW_USER_NAME).
 * @param received on success, receives the server's reply VALUE_PAIR list;
 *   the caller must free it with rc_avpair_free().
 * @param msg if non-NULL, must point to a buffer of PW_MAX_MSG_SIZE bytes;
 *   will contain the concatenation of any PW_REPLY_MESSAGE attributes received.
 * @param add_nas_port if non-zero, PW_NAS_PORT is added to the sent pairs.
 * @param request_type one of the standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @return OK_RC (0) on success, CHALLENGE_RC (3) on Access-Challenge,
 *   REJECT_RC (2) on Access-Reject, or a negative error code on failure.
 */
int rc_aaa_ctx(rc_handle * rh, RC_AAA_CTX ** ctx, uint32_t nas_port,
	       VALUE_PAIR * send, VALUE_PAIR ** received, char *msg,
	       int add_nas_port, rc_standard_codes request_type)
{
	SERVER *aaaserver;
	rc_type type;

	if (rc_select_aaa_server(rh, &aaaserver, &type, request_type) != OK_RC)
		return ERROR_RC;

	return rc_aaa_ctx_server(rh, ctx, aaaserver, type,
				 nas_port, send, received, msg,
				 add_nas_port, request_type);
}

/** @brief Builds an authentication/accounting request and submits it to a specific server
 *
 * Like rc_aaa_ctx() but sends to @p aaaserver instead of the server list from
 * the configuration.  Use this when the caller has already selected the server
 * (e.g., in proxy scenarios).
 *
 * @param rh a handle to parsed configuration.
 * @param ctx if non-NULL, receives an allocated RC_AAA_CTX on success; the
 *   caller must free it with rc_aaa_ctx_free().  Pass NULL if not needed.
 * @param aaaserver a non-NULL SERVER describing the target server(s).
 * @param type AUTH to use the authentication port, ACCT for the accounting
 *   port.  Under TLS/DTLS only AUTH is valid (both auth and acct share the
 *   same TLS connection to the authserver).
 * @param nas_port the physical NAS port number to include (may be zero).
 * @param send VALUE_PAIR list of attributes to send (e.g., PW_USER_NAME).
 * @param received on success, receives the server's reply VALUE_PAIR list;
 *   the caller must free it with rc_avpair_free().
 * @param msg if non-NULL, must point to a buffer of PW_MAX_MSG_SIZE bytes;
 *   will contain the concatenation of any PW_REPLY_MESSAGE attributes received.
 * @param add_nas_port if non-zero, PW_NAS_PORT is added to the sent pairs.
 * @param request_type one of the standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @return OK_RC (0) on success, CHALLENGE_RC (3) on Access-Challenge,
 *   REJECT_RC (2) on Access-Reject, or a negative error code on failure.
 */
int rc_aaa_ctx_server(rc_handle * rh, RC_AAA_CTX ** ctx, SERVER * aaaserver,
		      rc_type type,
		      uint32_t nas_port,
		      VALUE_PAIR * send, VALUE_PAIR ** received,
		      char *msg, int add_nas_port,
		      rc_standard_codes request_type)
{
	SEND_DATA data;
	VALUE_PAIR *adt_vp = NULL;
	int result;
	int timeout = rc_conf_int(rh, "radius_timeout");
	int retries = rc_conf_int(rh, "radius_retries");
	double start_time = 0;
	time_t dtime;
	int servernum;

	data.send_pairs = send;
	data.receive_pairs = NULL;

	if (rc_fill_acct_pairs(rh, &data, nas_port, add_nas_port, request_type,
			       &adt_vp, &start_time) != OK_RC)
		return ERROR_RC;

	if (data.receive_pairs != NULL) {
		rc_avpair_free(data.receive_pairs);
		data.receive_pairs = NULL;
	}

	servernum = 0;
	do {
		rc_buildreq(rh, &data, request_type, aaaserver->name[servernum],
			    aaaserver->port[servernum],
			    aaaserver->secret[servernum], timeout, retries);

		if (request_type == PW_ACCOUNTING_REQUEST) {
			dtime = rc_getmtime() - start_time;
			rc_avpair_assign(adt_vp, &dtime, 0);
		}

		result = rc_send_server_ctx(rh, ctx, &data, msg, type, 0);

		if ((result == OK_RC) || (result == CHALLENGE_RC) || (result == REJECT_RC)) {
			if (request_type != PW_ACCOUNTING_REQUEST) {
				*received = data.receive_pairs;
			} else {
				rc_avpair_free(data.receive_pairs);
			}

			DEBUG(LOG_INFO,
			      "rc_send_server_ctx returned success for server %u", servernum);
			return result;
		}

		rc_avpair_free(data.receive_pairs);
		data.receive_pairs = NULL;

		DEBUG(LOG_INFO, "rc_send_server_ctx returned error (%d) for server %u: (remaining: %d)",
              result, servernum, aaaserver->max-servernum);
		servernum++;
	} while (servernum < aaaserver->max && ((result == TIMEOUT_RC) || (result == NETUNREACH_RC)));

	return result;
}

/** @brief Builds an authentication/accounting request for port id nas_port with the value_pairs send and submits it to a server
 *
 * @param rh a handle to parsed configuration.
 * @param nas_port the physical NAS port number to use (may be zero).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of any
 *	PW_REPLY_MESSAGE received.
 * @param add_nas_port this should be zero; if non-zero it will include PW_NAS_PORT in sent pairs.
 * @param request_type one of standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @return received value_pairs in received, messages from the server in
 *  msg and OK_RC (0) on success, CHALLENGE_RC (3) on Access-Challenge
 *  received, negative on failure as return value.
 */
int rc_aaa(rc_handle * rh, uint32_t nas_port, VALUE_PAIR * send,
	   VALUE_PAIR ** received, char *msg, int add_nas_port,
	   rc_standard_codes request_type)
{
	return rc_aaa_ctx(rh, NULL, nas_port, send, received, msg,
			  add_nas_port, request_type);
}

/** @brief Builds an authentication request for port id nas_port with the value_pairs send and submits it to a server
 *
 * @param rh a handle to parsed configuration.
 * @param nas_port the physical NAS port number to use (may be zero).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of any
 *	PW_REPLY_MESSAGE received.
 * @return received value_pairs in received, messages from the server in
 *  msg (if non-NULL), and OK_RC (0) on success,CHALLENGE_RC (3) on
 *  Access-Challenge received, negative on failure as return value.
 */
int rc_auth(rc_handle * rh, uint32_t nas_port, VALUE_PAIR * send,
	    VALUE_PAIR ** received, char *msg)
{

	return rc_aaa(rh, nas_port, send, received, msg, 1,
		      PW_ACCESS_REQUEST);
}

/** @brief Builds an authentication request for proxying
 *
 * Builds an authentication request with the value_pairs send and submits it to a server.
 * Works for a proxy; does not add IP address, and does does not rely on config file.
 *
 * @param rh a handle to parsed configuration.
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of
 *	any PW_REPLY_MESSAGE received.
 * @return received value_pairs in received, messages from the server in
 *  msg (if non-NULL) and OK_RC (0) on success, CHALLENGE_RC (3) on
 *  Access-Challenge received, negative on failure as return value.
 */
int rc_auth_proxy(rc_handle * rh, VALUE_PAIR * send, VALUE_PAIR ** received,
		  char *msg)
{
	return rc_aaa(rh, 0, send, received, msg, 0, PW_ACCESS_REQUEST);
}

/** @brief Builds an accounting request for port id nas_port with the value_pairs at send
 *
 * @note NAS-IP-Address, NAS-Port and Acct-Delay-Time get filled in by this function, the rest has to be supplied.
 *
 * @param rh a handle to parsed configuration.
 * @param nas_port the physical NAS port number to use (may be zero).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @return received value_pairs in received, and OK_RC (0) on success,
 *  CHALLENGE_RC (3) on Access-Challenge received, negative on failure as
 *  return value.
 */
int rc_acct(rc_handle * rh, uint32_t nas_port, VALUE_PAIR * send)
{
	return rc_aaa(rh, nas_port, send, NULL, NULL, 1,
		      PW_ACCOUNTING_REQUEST);
}

/** @brief Builds an accounting request with the value_pairs at send
 *
 * @param rh a handle to parsed configuration.
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @return OK_RC (0) on success, CHALLENGE_RC (3) on Access-Challenge
 *  received, negative on failure as return value.
 */
int rc_acct_proxy(rc_handle * rh, VALUE_PAIR * send)
{

	return rc_aaa(rh, 0, send, NULL, NULL, 0, PW_ACCOUNTING_REQUEST);
}

/** @brief Sends an accounting request to every server in @p aaaserver without waiting for a reply
 *
 * @note Internal helper behind rc_acct_async().
 *
 * @param rh a handle to parsed configuration.
 * @param aaaserver a non-NULL SERVER describing the target server(s).
 * @param type AUTH or ACCT, selects the destination port.
 * @param nas_port the physical NAS port number to include (may be zero).
 * @param send VALUE_PAIR list of attributes to send.
 * @return OK_RC (0) if the packet was handed to the socket layer for at
 *  least one server, ERROR_RC on failure.
 */
static int rc_aaa_ctx_server_async(rc_handle * rh, SERVER * aaaserver,
				   rc_type type, uint32_t nas_port,
				   VALUE_PAIR * send)
{
	SEND_DATA data;
	VALUE_PAIR *adt_vp = NULL;
	double start_time = 0;
	time_t dtime;
	int timeout = rc_conf_int(rh, "radius_timeout");
	int retries = rc_conf_int(rh, "radius_retries");
	int servernum;
	int result;
	int sent = 0;

	data.send_pairs = send;
	data.receive_pairs = NULL;

	if (rc_fill_acct_pairs(rh, &data, nas_port, 1, PW_ACCOUNTING_REQUEST,
			       &adt_vp, &start_time) != OK_RC)
		return ERROR_RC;

	for (servernum = 0; servernum < aaaserver->max; servernum++) {
		dtime = rc_getmtime() - start_time;
		rc_avpair_assign(adt_vp, &dtime, 0);

		/* timeout/retries are not consulted by rc_send_server_ctx()
		 * when no_wait is set below; passed through unchanged only
		 * so SEND_DATA/DEBUG output reflect the real configuration. */
		rc_buildreq(rh, &data, PW_ACCOUNTING_REQUEST,
			    aaaserver->name[servernum],
			    aaaserver->port[servernum],
			    aaaserver->secret[servernum], timeout, retries);

		result = rc_send_server_ctx(rh, NULL, &data, NULL, type, 1);

		if (data.receive_pairs != NULL) {
			rc_avpair_free(data.receive_pairs);
			data.receive_pairs = NULL;
		}

		if (result == OK_RC) {
			sent++;
		} else {
			DEBUG(LOG_INFO,
			      "rc_send_server_ctx returned error (%d) for server %u",
			      result, servernum);
		}
	}

	return sent > 0 ? OK_RC : ERROR_RC;
}

/** @brief Sends an accounting request to every configured accounting server without waiting for a reply
 *
 * Selects the server list the same way rc_acct() does (acctserver, or
 * authserver under TLS/DTLS). Unlike rc_acct()/rc_aaa(), which stop at the
 * first server that replies and fail over to the next only after a
 * timeout, this sends to *every* configured server unconditionally, since
 * there is no reply to judge success or failure by. Intended for
 * best-effort notifications such as an Accounting-Stop sent while an
 * application is shutting down and cannot afford to block.
 *
 * @param rh a handle to parsed configuration.
 * @param nas_port the physical NAS port number to include (may be zero).
 * @param send VALUE_PAIR list of attributes to send; NAS-Port and
 *  Acct-Delay-Time are filled in as with rc_acct().
 * @return OK_RC (0) if the packet was handed to the socket layer for at
 *  least one server, ERROR_RC if no accounting servers are configured or
 *  the send failed for all of them.
 */
int rc_acct_async(rc_handle * rh, uint32_t nas_port, VALUE_PAIR * send)
{
	SERVER *aaaserver;
	rc_type type;

	if (rc_select_aaa_server(rh, &aaaserver, &type, PW_ACCOUNTING_REQUEST) != OK_RC)
		return ERROR_RC;

	return rc_aaa_ctx_server_async(rh, aaaserver, type, nas_port, send);
}

/** @brief Asks the server hostname on the specified port for a status message
 *
 * @param rh a handle to parsed configuration.
 * @param host the name of the server.
 * @param secret the secret used by the server.
 * @param port the server's port number.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of any
 *	PW_REPLY_MESSAGE received.
 * @return OK_RC (0) on success, negative on failure as return value.
 */
int rc_check(rc_handle * rh, char *host, char *secret, unsigned short port,
	     char *msg)
{
	SEND_DATA data;
	int result;
	uint32_t service_type;
	int timeout = rc_conf_int(rh, "radius_timeout");
	int retries = rc_conf_int(rh, "radius_retries");
	rc_type type;

	data.send_pairs = data.receive_pairs = NULL;

	if (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS)
		type = AUTH;
	else
		type = ACCT;

	/*
	 * Fill in Service-Type
	 */

	service_type = PW_ADMINISTRATIVE;
	rc_avpair_add(rh, &(data.send_pairs), PW_SERVICE_TYPE, &service_type, 0,
		      0);

	rc_buildreq(rh, &data, PW_STATUS_SERVER, host, port, secret, timeout,
		    retries);
	result = rc_send_server(rh, &data, msg, type);

	rc_avpair_free(data.receive_pairs);

	return result;
}

/** @} */
