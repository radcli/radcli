/*
 * Copyright (c) 2014-2026, Nikos Mavrogiannopoulos.  All rights reserved.
 * Copyright (c) 2015, Red Hat, Inc. All rights reserved.
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

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h> /* RADCLI_DISCONNECT_REQUEST/RADCLI_COA_REQUEST,
                             * for tls_recvfrom()'s DAE-over-RadSec demux */
#include "util.h"
#include "options.h"
#include "tls.h"

#ifdef HAVE_GNUTLS

/**
 * @defgroup tls-api TLS/DTLS API
 * @brief TLS and DTLS related functions
 *
 * Note that, that API is for improving TLS and DTLS support
 * in an application. Applications are not required to use this
 * API to support them. TLS and DTLS support can be enabled by
 * the administrator transparently from the radiusclient configuration
 * file.
 *
 * @{
 */

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <pthread.h>
#include <time.h>
#include <poll.h>

#define DEFAULT_DTLS_SECRET "radius/dtls"
#define DEFAULT_TLS_SECRET "radsec"

typedef struct tls_int_st {
	char hostname[256];	/* server's hostname */
	unsigned port;		/* server's port */
	struct sockaddr_storage our_sockaddr;
	gnutls_session_t session;
	int sockfd;
	unsigned init;
	unsigned handshake_done; /* set only once gnutls_handshake() succeeds;
				  * guards deinit_session()'s gnutls_bye(),
				  * which is invalid on a session that never
				  * finished (or started) its handshake. */
	unsigned need_restart;
	unsigned skip_hostname_check; /* whether to verify hostname */
	pthread_mutex_t lock;
	time_t last_msg;	/* last send OR receive -- when the next watchdog is due */
	time_t last_recv;	/* last receive only -- REQ-WATCHDOG-NET-003's dead-peer clock */
} tls_int_st;

typedef struct tls_st {
	gnutls_psk_client_credentials_t psk_cred;
	gnutls_certificate_credentials_t x509_cred;
	struct tls_int_st ctx;	/* one for ACCT and another for AUTH */
	unsigned flags; /* the flags set on init */
	rc_handle *rh; /* a pointer to our owner */
} tls_st;

/** @} */

static int restart_session(rc_handle *rh, tls_st *st);

/*- rc_sockets_override.get_fd: return st's session socket, restarting the
 * session first if it was marked for restart.
 *
 * @param ptr the tls_st for this session.
 * @param our_sockaddr unused; part of the get_fd calling convention.
 * @return the session socket, or -1 if a needed restart failed.
 -*/
static int tls_get_fd(void *ptr, struct sockaddr *our_sockaddr)
{
	tls_st *st = ptr;
	if (st->ctx.need_restart != 0) {
		if (restart_session(st->rh, st) < 0)
			return -1;
	}
	return st->ctx.sockfd;
}

/*- rc_sockets_override.get_active_fd: return st's current session socket
 * without attempting a restart.
 *
 * @param ptr the tls_st for this session.
 * @return the session socket.
 -*/
static int tls_get_active_fd(void *ptr)
{
	tls_st *st = ptr;
	return st->ctx.sockfd;
}

/* Used from the GNUTLS_E_AGAIN/GNUTLS_E_INTERRUPTED retry branches of
 * tls_sendto()/tls_recvfrom(): GnuTLS requires retrying the record call
 * with the same arguments once events is ready on the session fd. Waits
 * up to the configured radius_timeout, safe against poll() itself being
 * interrupted by a signal (retried against the same, non-extending
 * deadline, so neither a signal nor a run of spurious EAGAINs can make
 * the wait unbounded). */
/*- Wait for a session socket to become ready for a retried GnuTLS record
 * call, or mark the session for restart on timeout/error.
 *
 * @param st the session to wait on.
 * @param events POLLIN or POLLOUT, matching the record call being retried.
 * @param what a short verb ("send"/"receive") for the timeout log message.
 * @return 1 if the caller should retry the gnutls_record_*() call, or -1
 * if it should give up (errno set to EIO, session marked for restart).
 -*/
static int tls_wait_or_give_up(tls_st *st, short events, const char *what)
{
	double start_time = rc_getmtime();
	int timeout = rc_conf_int_id(st->rh, OPT_RADIUS_TIMEOUT);

	if (timeout <= 0)
		timeout = 1;

	for (; timeout > 0; timeout -= (int)(rc_getmtime() - start_time)) {
		struct pollfd pfd = { st->ctx.sockfd, events, 0 };
		int ret = poll(&pfd, 1, timeout * 1000);

		if (ret > 0)
			return 1;
		if (ret == 0)
			break;
		if (errno != EINTR) {
			rc_log(LOG_ERR, "%s: poll: %s", __func__, strerror(errno));
			goto give_up;
		}
		/* poll() itself was interrupted; retry against the same
		 * deadline rather than treating it as a timeout. */
	}
	rc_log(LOG_ERR, "%s: timeout waiting to %s TLS data", __func__, what);
give_up:
	errno = EIO;
	st->ctx.need_restart = 1;
	return -1;
}

/*- rc_sockets_override.sendto: send buf over st's GnuTLS session,
 * retrying on GNUTLS_E_AGAIN/GNUTLS_E_INTERRUPTED via
 * tls_wait_or_give_up(), restarting the session first if needed.
 *
 * @param ptr the tls_st for this session.
 * @param sockfd unused; part of the sendto calling convention.
 * @param buf the data to send.
 * @param len buf's length in bytes.
 * @param flags unused; part of the sendto calling convention.
 * @param dest_addr unused; part of the sendto calling convention.
 * @param addrlen unused; part of the sendto calling convention.
 * @return the number of bytes sent, or -1 on failure (errno set to EIO).
 -*/
static ssize_t tls_sendto(void *ptr, int sockfd,
			   const void *buf, size_t len,
			   int flags, const struct sockaddr *dest_addr,
			   socklen_t addrlen)
{
	tls_st *st = ptr;
	int ret;

	if (st->ctx.need_restart != 0) {
		if (restart_session(st->rh, st) < 0) {
			errno = EIO;
			return -1;
		}
	}

	for (;;) {
		ret = gnutls_record_send(st->ctx.session, buf, len);
		if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
			if (tls_wait_or_give_up(st, POLLOUT, "send") < 0)
				return -1;
			continue;
		}

		if (ret < 0) {
			rc_log(LOG_ERR, "%s: error in sending: %s", __func__,
			       gnutls_strerror(ret));
			errno = EIO;
			st->ctx.need_restart = 1;
			return -1;
		}

		break;
	}

	st->ctx.last_msg = time(0);
	return ret;
}

/*- rc_sockets_override.lock: acquire st's session lock.
 *
 * @param ptr the tls_st for this session.
 * @return pthread_mutex_lock()'s return value.
 -*/
static int tls_lock(void *ptr)
{
	tls_st *st = ptr;

	return pthread_mutex_lock(&st->ctx.lock);
}

/*- rc_sockets_override.unlock: release st's session lock.
 *
 * @param ptr the tls_st for this session.
 * @return pthread_mutex_unlock()'s return value.
 -*/
static int tls_unlock(void *ptr)
{
	tls_st *st = ptr;

	return pthread_mutex_unlock(&st->ctx.lock);
}

/*- rc_sockets_override.recvfrom: read one reply from st's GnuTLS session,
 * retrying on GNUTLS_E_AGAIN/GNUTLS_E_INTERRUPTED via tls_wait_or_give_up(),
 * and diverting a DAE-over-RadSec CoA/Disconnect
 * packet straight to lib/dae.c's pipeline instead of returning it here
 * (RFC 6614 §2.1/§2.5, RFC 7360 §2.2: one connection carries every packet
 * type).
 *
 * @param ptr the tls_st for this session.
 * @param sockfd unused; part of the recvfrom calling convention.
 * @param buf destination buffer for the received record.
 * @param len buf's capacity in bytes.
 * @param flags unused; part of the recvfrom calling convention.
 * @param src_addr unused; part of the recvfrom calling convention.
 * @param addrlen unused; part of the recvfrom calling convention.
 * @return the number of bytes received, or -1 on failure (errno set to
 * EINTR on a received alert, EIO otherwise).
 -*/
static ssize_t tls_recvfrom(void *ptr, int sockfd,
			     void *buf, size_t len,
			     int flags, struct sockaddr *src_addr,
			     socklen_t * addrlen)
{
	tls_st *st = ptr;
	int ret;

	for (;;) {
		ret = gnutls_record_recv(st->ctx.session, buf, len);
		if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
			if (tls_wait_or_give_up(st, POLLIN, "receive") < 0)
				return -1;
			continue;
		}

		/* RFC 6614 SS2.1/SS2.5, RFC 7360 SS2.2: one port, one connection
		 * carries every packet type. A Disconnect-Request/CoA-Request
		 * arriving here is never the reply this caller (radcli_transport_
		 * exchange(), waiting for an Access-Accept/Accounting-Response) is
		 * waiting for -- hand it to lib/dae.c's RadSec pipeline right here
		 * (the thread already holding this session's lock, mid-exchange,
		 * is exactly the thread that must not miss it) and keep waiting
		 * for the actual reply. */
		if (ret >= 1 &&
		    (((const uint8_t *)buf)[0] == RADCLI_DISCONNECT_REQUEST ||
		     ((const uint8_t *)buf)[0] == RADCLI_COA_REQUEST)) {
			radcli2_priv_dae_on_radsec_packet(st->rh, buf, (size_t)ret);
			continue;
		}
		break;
	}

	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED) {
		rc_log(LOG_ERR, "%s: received alert: %s", __func__,
		       gnutls_alert_get_name(gnutls_alert_get(st->ctx.session)));
		errno = EINTR;
		return -1;
	}

	/* RFC6614 says: "After the TLS session is established, RADIUS packet payloads are
	 * exchanged over the encrypted TLS tunnel.  In RADIUS/UDP, the
	 * packet size can be determined by evaluating the size of the
	 * datagram that arrived.  Due to the stream nature of TCP and TLS,
	 * this does not hold true for RADIUS/TLS packet exchange.",
	 *
	 * That is correct in principle but it fails to associate the length with
	 * the TLS record boundaries. Here, when in TLS, we assume that a single TLS
	 * record holds a single radius packet. It wouldn't make sense anyway to send
	 * multiple TLS records for a single packet.
	 */

	if (ret <= 0) {
		rc_log(LOG_ERR, "%s: error in receiving: %s", __func__,
		       gnutls_strerror(ret));
		errno = EIO;
		st->ctx.need_restart = 1;
		return -1;
	}

	st->ctx.last_msg = time(0);
	st->ctx.last_recv = st->ctx.last_msg;
	return ret;
}

/*- GnuTLS certificate-verification callback: verify the peer's
 * certificate chain and, unless skip_hostname_check is set, that its
 * hostname matches.
 *
 * @param session the GnuTLS session being handshaked; its tls_int_st is
 * read back via gnutls_session_get_ptr().
 * @return 0 if the certificate is acceptable, GNUTLS_E_CERTIFICATE_ERROR
 * otherwise.
 -*/
static int cert_verify_callback(gnutls_session_t session)
{
	unsigned int status;
	int ret;
	struct tls_int_st *ctx;
	gnutls_datum_t out;

	/* read hostname */
	ctx = gnutls_session_get_ptr(session);
	if (ctx == NULL)
		return GNUTLS_E_CERTIFICATE_ERROR;

	if (ctx->skip_hostname_check)
		ret = gnutls_certificate_verify_peers2(session, &status);
	else
		ret = gnutls_certificate_verify_peers3(session, ctx->hostname, &status);
	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in certificate verification: %s",
		       __func__, gnutls_strerror(ret));
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (status != 0) {
		ret =
		    gnutls_certificate_verification_status_print(status,
								 gnutls_certificate_type_get
								 (session),
								 &out, 0);
		if (ret < 0) {
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
		rc_log(LOG_INFO, "%s: certificate: %s", __func__, out.data);
		gnutls_free(out.data);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	return 0;
}

/*- Tear down a GnuTLS session: send close_notify (if the handshake
 * completed), deinit the GnuTLS session, destroy the lock, and close the
 * socket.
 *
 * @param ses the session to tear down; ses->init is left 0.
 -*/
static void deinit_session(tls_int_st *ses)
{
	if (ses->init != 0) {
		int ret;
		ses->init = 0;
		if (ses->session) {
			/* Send close_notify before closing the socket so the peer
			 * receives a proper TLS/DTLS shutdown alert. Only valid
			 * once the handshake actually completed -- e.g. a
			 * connect() failure leaves an initialized session with
			 * no negotiated cipher state, and gnutls_bye() on that
			 * is not meaningful. */
			if (ses->sockfd != -1 && ses->handshake_done) {
				do {
					ret = gnutls_bye(ses->session, GNUTLS_SHUT_WR);
				} while (ret == GNUTLS_E_INTERRUPTED);
			}
			gnutls_deinit(ses->session);
		}
		pthread_mutex_destroy(&ses->lock);
		if (ses->sockfd != -1)
			close(ses->sockfd);
	}
}

/*- Resolve hostname, open a socket, and complete the GnuTLS (D)TLS
 * handshake, filling in ses on success.
 *
 * @param rh a handle to parsed configuration.
 * @param ses the session struct to initialize.
 * @param hostname the server to resolve and connect to.
 * @param port the server's TLS/DTLS port.
 * @param our_sockaddr set to the local address the socket bound/connected
 * from.
 * @param timeout the handshake timeout in seconds.
 * @param secflags PSK/certificate security flags controlling credential
 * setup (see callers for the accepted bits).
 * @return 0 on success, negative on failure (ses is left safe to pass to
 * deinit_session()).
 -*/
static int init_session(rc_handle *rh, tls_int_st *ses,
			const char *hostname, unsigned port,
			struct sockaddr_storage *our_sockaddr,
			int timeout,
			unsigned secflags)
{
	int sockfd, ret, e, sock_flags;
	struct addrinfo *info;
	char *p;
	unsigned flags = 0;
	unsigned cred_set = 0;
	tls_st *st = rh->so.ptr;

	ses->sockfd = -1;
	ses->init = 1;
	ses->handshake_done = 0;

	{
		/* Recursive, not the default (non-recursive) type: DAE-over-
		 * RadSec's demux (lib/dae.c's radcli2_priv_dae_on_radsec_packet(),
		 * called inline from tls_recvfrom() below) can itself need to
		 * send an immediate reply -- a retransmission's cached ACK/NAK
		 * (PROCESS_DUP_ANSWERED), or an RFC 6614 SS2.5 406 NAK when
		 * dynamic authorization isn't enabled -- via this same rh's
		 * so.sendto()/so.lock(), while tls_recvfrom() itself is being
		 * called from inside radcli_transport_exchange() (lib/sendserver.c),
		 * which already holds this exact lock for its entire send-and-
		 * wait cycle, on this same thread. A plain mutex would deadlock
		 * (or be undefined behavior) the moment that reply path is taken
		 * from that call chain; a recursive one simply nests. */
		pthread_mutexattr_t attr;

		pthread_mutexattr_init(&attr);
		pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
		pthread_mutex_init(&ses->lock, &attr);
		pthread_mutexattr_destroy(&attr);
	}
	sockfd = socket(our_sockaddr->ss_family, (secflags&SEC_FLAG_DTLS)?SOCK_DGRAM:SOCK_STREAM, 0);
	if (sockfd < 0) {
		rc_log(LOG_ERR,
		       "%s: cannot open socket", __func__);
		ret = -1;
		goto cleanup;
	}

	if (our_sockaddr->ss_family == AF_INET)
		((struct sockaddr_in *)our_sockaddr)->sin_port = 0;
	else
		((struct sockaddr_in6 *)our_sockaddr)->sin6_port = 0;

	ses->sockfd = sockfd;

	/* Initialize DTLS */

	flags = GNUTLS_CLIENT;
	if (secflags&SEC_FLAG_DTLS)
		flags |= GNUTLS_DATAGRAM;
	ret = gnutls_init(&ses->session, flags);
	if (ret < 0) {
		rc_log(LOG_ERR,
		       "%s: error in gnutls_init(): %s", __func__, gnutls_strerror(ret));
		ret = -1;
		goto cleanup;
	}

	memcpy(&ses->our_sockaddr, our_sockaddr, sizeof(*our_sockaddr));
	if (!(secflags&SEC_FLAG_DTLS)) {
		if (timeout > 0) {
			gnutls_handshake_set_timeout(ses->session, timeout*1000);
		} else {
			gnutls_handshake_set_timeout(ses->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
		}
	} else { /* DTLS */
		if (timeout > 0)
			gnutls_dtls_set_timeouts(ses->session, 1000, timeout*1000);
	}

	gnutls_transport_set_int(ses->session, sockfd);
	gnutls_session_set_ptr(ses->session, ses);

	p = rc_conf_str_id(rh, OPT_TLS_VERIFY_HOSTNAME);
	if (p && (strcasecmp(p, "false") == 0 || strcasecmp(p, "no") == 0)) {
		ses->skip_hostname_check = 1;
	}

	if (st && st->psk_cred) {
		cred_set = 1;
		gnutls_credentials_set(ses->session,
				       GNUTLS_CRD_PSK, st->psk_cred);

		ret = gnutls_priority_set_direct(ses->session, "NORMAL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:-VERS-TLS1.0", NULL);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK priorities: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}
	} else if (st) {
		cred_set = 1;
		if (st->x509_cred) {
			gnutls_credentials_set(ses->session,
					       GNUTLS_CRD_CERTIFICATE,
					       st->x509_cred);
		}

		gnutls_set_default_priority(ses->session);
	}

	gnutls_server_name_set(ses->session, GNUTLS_NAME_DNS,
			       hostname, strlen(hostname));

	info =
	    rc_getaddrinfo(hostname, PW_AI_AUTH);
	if (info == NULL) {
		ret = -1;
		rc_log(LOG_ERR, "%s: cannot resolve %s", __func__,
		       hostname);
		goto cleanup;
	}

	if (port != 0) {
		if (info->ai_addr->sa_family == AF_INET)
			((struct sockaddr_in *)info->ai_addr)->sin_port =
			    htons(port);
		else
			((struct sockaddr_in6 *)info->ai_addr)->sin6_port =
			    htons(port);
	} else {
		rc_log(LOG_ERR, "%s: no port specified for server %s",
		       __func__, hostname);
		ret = -1;
		goto cleanup;
	}

	strlcpy(ses->hostname, hostname, sizeof(ses->hostname));
	ses->port = port;

	if (cred_set == 0) {
		rc_log(LOG_CRIT,
		       "%s: neither tls-ca-file or a PSK key are configured",
		       __func__);
		ret = -1;
		goto cleanup;
	}

	/* we connect since we are talking to a single server */
	ret = connect(sockfd, info->ai_addr, info->ai_addrlen);
	freeaddrinfo(info);
	if (ret == -1) {
		e = errno;
		ret = -1;
		rc_log(LOG_CRIT, "%s: cannot connect to %s: %s",
		       __func__, hostname, strerror(e));
		goto cleanup;
	}

	/* Switch to non-blocking mode before the handshake, so that both
	 * gnutls_handshake() (bounded above via gnutls_handshake_set_timeout()/
	 * gnutls_dtls_set_timeouts()) and the post-handshake record I/O in
	 * tls_sendto()/tls_recvfrom() can actually observe GNUTLS_E_AGAIN and
	 * take the bounded poll()-and-retry path in tls_wait_or_give_up(),
	 * instead of blocking in the kernel with no timeout at all. */
	sock_flags = fcntl(sockfd, F_GETFL, 0);
	if (sock_flags == -1 ||
	    fcntl(sockfd, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
		e = errno;
		ret = -1;
		rc_log(LOG_CRIT, "%s: cannot set socket non-blocking: %s",
		       __func__, strerror(e));
		goto cleanup;
	}

	rc_log(LOG_DEBUG,
	       "%s: performing TLS/DTLS handshake with [%s]:%d",
	       __func__, hostname, port);
	do {
		ret = gnutls_handshake(ses->session);
		if (ret == GNUTLS_E_LARGE_PACKET)
			break;
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in handshake: %s",
		       __func__, gnutls_strerror(ret));
		ret = -1;
		goto cleanup;
	}

	ses->handshake_done = 1;
	/* A freshly completed handshake counts as session activity: without
	 * this, last_msg stays at its zeroed-struct initial value until the
	 * first actual send/receive, which radcli_ctx_get_poll()'s watchdog-
	 * deadline math (lib/dae.c) would otherwise read as "session has been
	 * idle since the epoch" and report an already-overdue deadline right
	 * after radcli_dae_start()'s eager connect (REQ-DAE-INIT-010). */
	ses->last_msg = time(0);
	ses->last_recv = ses->last_msg;
	return 0;
 cleanup:
	deinit_session(ses);
	return ret;

}

/*- Reconnect st's session in place, replacing its tls_int_st with a freshly
 * established one. Every call site only ever calls this when the session is
 * already known to need it (a send/recv failure already set need_restart,
 * or rc_init_tls() preset it before the first connection), so this always
 * reinitializes unconditionally -- no rate-limiting, nothing to bypass.
 *
 * @param rh a handle to parsed configuration.
 * @param st the session to restart.
 * @return 0 on success, -1 if reinitialization failed (st is left unchanged
 * on failure).
 -*/
static int restart_session(rc_handle *rh, tls_st *st)
{
	/* init_session() assumes a zeroed struct: REQ-NET-NET-016 */
	struct tls_int_st tmps = { 0 };
	int ret;
	int timeout;

	timeout = rc_conf_int_id(rh, OPT_RADIUS_TIMEOUT);

	/* reinitialize this session */
	ret = init_session(rh, &tmps, st->ctx.hostname, st->ctx.port, &st->ctx.our_sockaddr, timeout, st->flags);
	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in re-initializing TLS session", __func__);
		return -1;
	}

	if (tmps.sockfd == st->ctx.sockfd)
		st->ctx.sockfd = -1;
	deinit_session(&st->ctx);
	memcpy(&st->ctx, &tmps, sizeof(tmps));
	st->ctx.need_restart = 0;

	return 0;
}

/*- Return the file descriptor of the TLS/DTLS session -- also usable as
 * a test for whether TLS or DTLS are in use.
 *
 * @param rh a handle to parsed configuration.
 * @return the file descriptor used by the TLS session, or -1 on error.
 -*/
int radcli2_priv_tls_fd(rc_handle * rh)
{
	tls_st *st;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return -1;

	st = rh->so.ptr;

	if (st->ctx.init != 0) {
		return st->ctx.sockfd;
	}
	return -1;
}

/*- Return the time of the last message sent or received on rh's TLS/DTLS
 * session (tls_int_st.last_msg, updated by every successful send/receive
 * on this session, including radcli2_priv_tls_dae_send()). Used by lib/
 * dae.c's radcli_ctx_get_poll() to compute a watchdog deadline
 * (watchdog-interval) without lib/dae.c needing to see the private
 * tls_int_st layout.
 *
 * @param rh a handle to parsed configuration.
 * @return the last-activity timestamp, or 0 if rh's transport is not
 * TLS/DTLS or the session is not yet initialized.
 -*/
time_t radcli2_priv_tls_last_msg(rc_handle * rh)
{
	tls_st *st;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return 0;

	st = rh->so.ptr;

	if (st->ctx.init != 0) {
		return st->ctx.last_msg;
	}
	return 0;
}

/*- Return the time of the last record actually *received* on rh's TLS/DTLS
 * session (tls_int_st.last_recv) -- unlike radcli2_priv_tls_last_msg(),
 * never advanced by a send. Used by lib/dae.c's radcli_ctx_send_watchdog()
 * (REQ-WATCHDOG-NET-003) to detect a peer that has gone silent while the
 * connection itself is still technically open: sending watchdogs into that
 * silence would keep radcli2_priv_tls_last_msg() looking fresh forever,
 * masking exactly the condition this is meant to catch.
 *
 * @param rh a handle to parsed configuration.
 * @return the last-receive timestamp, or 0 if rh's transport is not
 * TLS/DTLS or the session is not yet initialized.
 -*/
time_t radcli2_priv_tls_last_recv(rc_handle * rh)
{
	tls_st *st;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return 0;

	st = rh->so.ptr;

	if (st->ctx.init != 0) {
		return st->ctx.last_recv;
	}
	return 0;
}

/*- Force rh's TLS/DTLS session to reconnect now, the same way an actual
 * send/recv error already does (need_restart) -- used by lib/dae.c's
 * radcli_ctx_send_watchdog() (REQ-WATCHDOG-NET-003) when the peer is presumed
 * dead from elapsed time alone, with no socket-level error to set
 * need_restart on its own.
 *
 * @param rh a handle to parsed configuration.
 * @return 0 on success, -1 if rh's transport is not TLS/DTLS or
 * reconnection failed.
 -*/
int radcli2_priv_tls_force_reconnect(rc_handle * rh)
{
	tls_st *st;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return -1;

	st = rh->so.ptr;
	st->ctx.need_restart = 1;
	return restart_session(rh, st);
}

/*- Probe an established TLS/DTLS session's liveness and reconnect if it is
 * dead. Once watchdog-interval has elapsed since the session's last
 * activity, sends an RFC 5997 Status-Server watchdog
 * (radcli_ctx_send_watchdog(), REQ-WATCHDOG-NET-001) -- which itself already
 * detects and reconnects from a peer gone silent for 2.5x that interval
 * (REQ-WATCHDOG-NET-003), so this one call covers both probing and recovering. A
 * dead session is normally detected and reconnected transparently on the
 * next request anyway; this exists for a caller that wants that detected
 * proactively instead (e.g. from a dedicated watchdog thread), same as
 * before this used a TLS heartbeat for it.
 *
 * @param rh a handle to parsed configuration.
 * @return 0 on success or when TLS/DTLS is not in use, -1 if a
 * known-broken session could not be re-established.
 -*/
int radcli2_priv_check_tls(rc_handle * rh)
{
	tls_st *st;
	int interval;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return 0;

	st = rh->so.ptr;

	if (st->ctx.init == 0)
		return 0;

	if (st->ctx.need_restart != 0)
		return restart_session(rh, st) < 0 ? -1 : 0;

	interval = rc_conf_int_id(rh, OPT_WATCHDOG_INTERVAL);
	if (interval > 0 && time(0) - st->ctx.last_msg >= interval)
		radcli_ctx_send_watchdog((radcli_ctx *)rh);

	return 0;
}

/*- Force the TLS/DTLS handshake now, if it has not happened yet or the
 * session needs reconnecting. See lib/includes.h's doc comment. */
int radcli2_priv_tls_ensure_connected(rc_handle *rh)
{
	tls_st *st;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return -1;

	st = rh->so.ptr;

	if (st->ctx.init != 0 && st->ctx.need_restart == 0)
		return 0; /* already connected and healthy */

	return restart_session(rh, st);
}

/*- Make one non-blocking attempt to read a DAE-over-RadSec record.
 * See lib/includes.h's doc comment. */
int radcli2_priv_tls_dae_poll(rc_handle *rh, uint8_t *buf, size_t cap)
{
	tls_st *st;
	int ret;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return 0;

	st = rh->so.ptr;
	if (st->ctx.init == 0 || st->ctx.need_restart != 0)
		return 0; /* not connected -- nothing to poll; reconnecting is
			   * radcli_dae_start()'s/an ordinary request's job, not
			   * this opportunistic idle-time check's. */

	/* A trylock, not a blocking lock: if radcli_transport_exchange() is
	 * mid-exchange on another thread, it already owns this session's
	 * only read path and will itself see and demux any DAE record that
	 * arrives while it holds the lock (tls_recvfrom()'s own inline
	 * demux, above) -- so contention here simply means "nothing new to
	 * report this call", never a stall of the caller's event loop. */
	if (pthread_mutex_trylock(&st->ctx.lock) != 0)
		return 0;

	ret = gnutls_record_recv(st->ctx.session, buf, cap);

	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
		pthread_mutex_unlock(&st->ctx.lock);
		return 0; /* nothing ready this call -- no retry, unlike tls_recvfrom() */
	}

	if (ret <= 0) {
		rc_log(LOG_ERR, "%s: error in receiving: %s", __func__,
		       gnutls_strerror(ret));
		st->ctx.need_restart = 1;
		pthread_mutex_unlock(&st->ctx.lock);
		return -1;
	}

	st->ctx.last_msg = time(0);
	st->ctx.last_recv = st->ctx.last_msg;
	/* Lock deliberately left held -- see lib/includes.h's doc comment on
	 * this function and radcli2_priv_tls_dae_poll_done(). */
	return ret;
}

/*- Release the lock radcli2_priv_tls_dae_poll() left held on success.
 * See lib/includes.h's doc comment. */
void radcli2_priv_tls_dae_poll_done(rc_handle *rh)
{
	tls_st *st;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return;
	st = rh->so.ptr;
	pthread_mutex_unlock(&st->ctx.lock);
}

/*- Make one non-blocking attempt to send a DAE-over-RadSec reply.
 *
 * Unlike tls_sendto() (used for ordinary requests, where blocking until
 * radius_timeout elapses waiting for POLLOUT is the caller's own,
 * accepted contract), this never waits: a poll()-driven application's
 * dispatch action (lib/dae.c's radcli_ctx_dispatch(), invoked only
 * because the descriptor was reported readable) must not turn into a
 * multi-second stall just because sending a reply as a side effect would
 * otherwise block. On GNUTLS_E_AGAIN/_INTERRUPTED, the caller is expected
 * to queue buf and retry this same call later (lib/dae.c's bounded
 * radsec_reply_queue) rather than wait here.
 *
 * The session lock is a plain (recursive) lock, not a trylock: every
 * caller of this function already holds it via the recursive session
 * lock nesting radcli2_priv_tls_dae_poll()'s doc comment describes (this
 * thread either came from tls_recvfrom()'s inline demux, which holds it
 * for the whole enclosing radcli_transport_exchange() call, or from
 * radcli_ctx_dispatch(), which holds it across radcli2_priv_dae_on_radsec_
 * packet() precisely so this nests rather than deadlocking) -- so this
 * never actually blocks waiting for another thread.
 *
 * @return the number of bytes GnuTLS accepted as one complete record
 *  (matching gnutls_record_send()'s own return convention) on success, 0
 *  if the send would block (nothing was sent; retry the identical buf/len
 *  later), -1 on a session error (also marks the session for
 *  reconnection, same as tls_sendto()'s own error handling).
 -*/
int radcli2_priv_tls_dae_send(rc_handle *rh, const void *buf, size_t len)
{
	tls_st *st;
	int ret;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return -1;

	st = rh->so.ptr;
	if (st->ctx.init == 0 || st->ctx.need_restart != 0)
		return -1;

	pthread_mutex_lock(&st->ctx.lock);
	ret = gnutls_record_send(st->ctx.session, buf, len);

	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
		pthread_mutex_unlock(&st->ctx.lock);
		return 0;
	}
	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in sending: %s", __func__, gnutls_strerror(ret));
		st->ctx.need_restart = 1;
		pthread_mutex_unlock(&st->ctx.lock);
		return -1;
	}

	st->ctx.last_msg = time(0);
	pthread_mutex_unlock(&st->ctx.lock);
	return ret;
}

/*- One non-blocking attempt to read the reply an in-flight async
 * request/reply exchange (lib/sendserver.c's radcli_transport_service_
 * async()) is waiting for. See lib/includes.h's doc comment for why this,
 * unlike radcli2_priv_tls_dae_poll(), does not take the session lock
 * itself. -*/
int radcli2_priv_tls_try_recv(rc_handle *rh, uint8_t *buf, size_t cap)
{
	tls_st *st;
	int ret;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return -1;

	st = rh->so.ptr;

	ret = gnutls_record_recv(st->ctx.session, buf, cap);

	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
		return 0; /* nothing ready this call -- no retry, unlike tls_recvfrom() */

	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED) {
		rc_log(LOG_ERR, "%s: received alert: %s", __func__,
		       gnutls_alert_get_name(gnutls_alert_get(st->ctx.session)));
		return 0; /* transient, same as tls_recvfrom()'s own handling of this
			   * alert -- not a reason to tear down the session */
	}

	/* RFC 6614 SS2.1/SS2.5, RFC 7360 SS2.2: one connection carries every
	 * packet type. A Disconnect-Request/CoA-Request arriving here is
	 * never the reply this exchange is waiting for -- hand it to lib/
	 * dae.c's RadSec pipeline right here, exactly as tls_recvfrom()'s own
	 * inline demux does, and report "not ready yet"; a genuine reply
	 * queued right behind it is picked up on the next call. */
	if (ret >= 1 &&
	    (((const uint8_t *)buf)[0] == RADCLI_DISCONNECT_REQUEST ||
	     ((const uint8_t *)buf)[0] == RADCLI_COA_REQUEST)) {
		radcli2_priv_dae_on_radsec_packet(st->rh, buf, (size_t)ret);
		return 0;
	}

	if (ret <= 0) {
		rc_log(LOG_ERR, "%s: error in receiving: %s", __func__, gnutls_strerror(ret));
		st->ctx.need_restart = 1;
		return -1;
	}

	st->ctx.last_msg = time(0);
	return ret;
}

/*- This function will deinitialize a previously initialed DTLS or TLS session.
 *
 * @param rh the configuration handle.
 -*/
void rc_deinit_tls(rc_handle * rh)
{
	tls_st *st = rh->so.ptr;
	char *ns = NULL;
	int ns_def_hdl = 0;

	if (st) {
		ns = rc_conf_str_id(rh, OPT_NAMESPACE); /* Check for namespace config */
		if (ns != NULL) {
			if(-1 == rc_set_netns(ns, &ns_def_hdl)) {
				rc_log(LOG_ERR, "rc_send_server: namespace %s set failed", ns);
				return;
			}
		}
		if (st->ctx.init != 0)
			deinit_session(&st->ctx);
		if (st->x509_cred)
			gnutls_certificate_free_credentials(st->x509_cred);
		if (st->psk_cred)
			gnutls_psk_free_client_credentials(st->psk_cred);
		if (ns != NULL) {
			if(-1 == rc_reset_netns(&ns_def_hdl))
			rc_log(LOG_ERR, "rc_send_server: namespace %s reset failed", ns);
		}
	}
	free(st);
}

/*- Initialize a configuration for TLS or DTLS
 *
 * This function will initialize the handle for TLS or DTLS.
 *
 * @param rh a handle to parsed configuration
 * @param flags must be zero or SEC_FLAG_DTLS
 * @return 0 on success, -1 on failure.
 -*/
int rc_init_tls(rc_handle * rh, unsigned flags)
{
	int ret;
	tls_st *st = NULL;
	struct sockaddr_storage our_sockaddr;
	const char *ca_file = rc_conf_str_id(rh, OPT_TLS_CA_FILE);
	const char *cert_file = rc_conf_str_id(rh, OPT_TLS_CERT_FILE);
	const char *key_file = rc_conf_str_id(rh, OPT_TLS_KEY_FILE);
	const char *pskkey = NULL;
	SERVER *authservers;
	char hostname[256];	/* server's hostname */
	unsigned port;		/* server's port */
	char *ns = NULL;
	int ns_def_hdl = 0;

	memset(&rh->so, 0, sizeof(rh->so));

	ns = rc_conf_str_id(rh, OPT_NAMESPACE); /* Check for namespace config */
	if (ns != NULL) {
		if(-1 == rc_set_netns(ns, &ns_def_hdl)) {
			rc_log(LOG_ERR, "rc_send_server: namespace %s set failed", ns);
			return -1;
		}
	}

	if (flags & SEC_FLAG_DTLS) {
		rh->so_type = RC_SOCKET_DTLS;
		rh->so.static_secret = DEFAULT_DTLS_SECRET;
	} else {
		rh->so_type = RC_SOCKET_TLS;
		rh->so.static_secret = DEFAULT_TLS_SECRET;
	}

	rc_own_bind_addr(rh, &our_sockaddr);

	st = calloc(1, sizeof(tls_st));
	if (st == NULL) {
		ret = -1;
		goto cleanup;
	}

	st->rh = rh;
	st->flags = flags;

	rh->so.ptr = st;

	if (ca_file || (key_file && cert_file)) {
		ret = gnutls_certificate_allocate_credentials(&st->x509_cred);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting X.509 credentials: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}

		if (ca_file) {
			ret =
			    gnutls_certificate_set_x509_trust_file(st->x509_cred,
							   ca_file,
							   GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				ret = -1;
				rc_log(LOG_ERR,
				       "%s: error in setting X.509 trust file: %s: %s",
				       __func__, gnutls_strerror(ret), ca_file);
				goto cleanup;
			}
		}

		if (cert_file && key_file) {
			ret =
			    gnutls_certificate_set_x509_key_file(st->x509_cred,
								 cert_file,
								 key_file,
								 GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				ret = -1;
				rc_log(LOG_ERR,
				       "%s: error in setting X.509 cert and key files: %s: %s - %s",
				       __func__, gnutls_strerror(ret), cert_file, key_file);
				goto cleanup;
			}
		}

		gnutls_certificate_set_verify_function(st->x509_cred,
						       cert_verify_callback);
	}

	/* Read the PSK key if any */
	authservers = radcli2_priv_conf_srv(rh, "authserver");
	if (authservers == NULL) {
		rc_log(LOG_ERR,
		       "%s: cannot find authserver", __func__);
		ret = -1;
		goto cleanup;
	}
	if (authservers->max > 1) {
		ret = -1;
		rc_log(LOG_ERR,
		       "%s: too many auth servers for TLS/DTLS; only one is allowed",
		       __func__);
		goto cleanup;
	}
	strlcpy(hostname, authservers->name[0], sizeof(hostname));
	port = authservers->port[0];

	if (rh->tls_psk_key != NULL) {
		/* radcli2.h's radcli_ctx_set_tls_psk(): identity/key set directly
		 * as bytes, not parsed out of a "psk@user@hexkey" secret string --
		 * takes priority over authservers->secret[0] below if both are
		 * somehow set. */
		gnutls_datum_t rawkey;

		ret = gnutls_psk_allocate_client_credentials(&st->psk_cred);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK credentials: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}

		rawkey.data = rh->tls_psk_key;
		rawkey.size = rh->tls_psk_key_len;

		ret = gnutls_psk_set_client_credentials(st->psk_cred,
							 rh->tls_psk_identity ? rh->tls_psk_identity : "",
							 &rawkey, GNUTLS_PSK_KEY_RAW);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK key: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}

		goto psk_done;
	}

	{
		/* Config-file equivalent of radcli_ctx_set_tls_psk(): identity as
		 * plain text, key as hex text (RC_OPTION_TABLE's tls-psk-identity/
		 * tls-psk-key, radcli-defs.h) -- takes priority over authservers->
		 * secret[0]'s embedded "psk@username@hexkey" form below, but not
		 * over rh->tls_psk_key set via the API call above. GNUTLS_PSK_KEY_HEX
		 * lets gnutls parse the hex text directly, so no manual decoding
		 * is needed here. */
		const char *psk_identity = rc_conf_str_id(rh, OPT_TLS_PSK_IDENTITY);
		const char *psk_key = rc_conf_str_id(rh, OPT_TLS_PSK_KEY);

		if ((psk_identity != NULL) != (psk_key != NULL)) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: tls-psk-identity and tls-psk-key must both be set",
			       __func__);
			goto cleanup;
		}

		if (psk_identity != NULL && psk_key != NULL) {
			gnutls_datum_t hexkey;

			hexkey.data = (uint8_t *)psk_key;
			hexkey.size = strlen(psk_key);

			ret = gnutls_psk_allocate_client_credentials(&st->psk_cred);
			if (ret < 0) {
				ret = -1;
				rc_log(LOG_ERR,
				       "%s: error in setting PSK credentials: %s",
				       __func__, gnutls_strerror(ret));
				goto cleanup;
			}

			ret = gnutls_psk_set_client_credentials(st->psk_cred,
								 psk_identity, &hexkey,
								 GNUTLS_PSK_KEY_HEX);
			if (ret < 0) {
				ret = -1;
				rc_log(LOG_ERR,
				       "%s: error in setting PSK key: %s",
				       __func__, gnutls_strerror(ret));
				goto cleanup;
			}

			goto psk_done;
		}
	}

	if (authservers->secret[0])
		pskkey = authservers->secret[0];

	if (pskkey && pskkey[0] != 0) {
		char *p;
		char username[64];
		gnutls_datum_t hexkey;
		int username_len;

		if (strncmp(pskkey, "psk@", 4) != 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: server secret is set but does not start with 'psk@'",
			       __func__);
			goto cleanup;
		}
		pskkey+=4;

		if ((p = strchr(pskkey, '@')) == NULL) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: PSK key is not in 'username@hexkey' format",
			       __func__);
			goto cleanup;
		}

		username_len = p - pskkey;
		if (username_len + 1 > sizeof(username)) {
			rc_log(LOG_ERR,
			       "%s: PSK username too big", __func__);
			ret = -1;
			goto cleanup;
		}

		strlcpy(username, pskkey, username_len + 1);

		p++;
		hexkey.data = (uint8_t*)p;
		hexkey.size = strlen(p);

		ret = gnutls_psk_allocate_client_credentials(&st->psk_cred);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK credentials: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}

		ret =
		    gnutls_psk_set_client_credentials(st->psk_cred,
						      username, &hexkey,
						      GNUTLS_PSK_KEY_HEX);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK key: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}
	}

 psk_done:
	/* Defer TCP connect + TLS handshake to first use.
	 * tls_sendto() checks need_restart != 0 and calls restart_session(),
	 * which calls init_session() with these stored parameters. */
	strlcpy(st->ctx.hostname, hostname, sizeof(st->ctx.hostname));
	st->ctx.port = port;
	memcpy(&st->ctx.our_sockaddr, &our_sockaddr, sizeof(our_sockaddr));
	st->ctx.need_restart = 1;

	rh->so.get_fd = tls_get_fd;
	rh->so.get_active_fd = tls_get_active_fd;
	rh->so.sendto = tls_sendto;
	rh->so.recvfrom = tls_recvfrom;
	rh->so.lock = tls_lock;
	rh->so.unlock = tls_unlock;
	if (ns != NULL) {
		if(-1 == rc_reset_netns(&ns_def_hdl)) {
			rc_log(LOG_ERR, "rc_send_server: namespace %s reset failed", ns);
			ret = -1;
			goto cleanup;
		}
	}
	return 0;
 cleanup:
	if (st) {
		if (st->ctx.init != 0)
			deinit_session(&st->ctx);
		if (st->x509_cred)
			gnutls_certificate_free_credentials(st->x509_cred);
		if (st->psk_cred)
			gnutls_psk_free_client_credentials(st->psk_cred);
	}
	free(st);
	rh->so.ptr = NULL;
	if (ns != NULL) {
		if(-1 == rc_reset_netns(&ns_def_hdl))
		rc_log(LOG_ERR, "rc_send_server: namespace %s reset failed", ns);
	}
	return ret;
}

#else /* !HAVE_GNUTLS */

/* No-GnuTLS-build stubs: TLS/DTLS is never in use, so these report that
 * unconditionally rather than implementing the HAVE_GNUTLS versions'
 * behavior above. */

int radcli2_priv_tls_fd(rc_handle * rh)
{
	return -1;
}

time_t radcli2_priv_tls_last_msg(rc_handle * rh)
{
	(void)rh;
	return 0;
}

time_t radcli2_priv_tls_last_recv(rc_handle * rh)
{
	(void)rh;
	return 0;
}

int radcli2_priv_tls_force_reconnect(rc_handle * rh)
{
	(void)rh;
	return -1;
}

int radcli2_priv_check_tls(rc_handle * rh)
{
	return 0;
}

int radcli2_priv_tls_ensure_connected(rc_handle *rh)
{
	(void)rh;
	return -1;
}

int radcli2_priv_tls_dae_poll(rc_handle *rh, uint8_t *buf, size_t cap)
{
	(void)rh;
	(void)buf;
	(void)cap;
	return 0;
}

void radcli2_priv_tls_dae_poll_done(rc_handle *rh)
{
	(void)rh;
}

int radcli2_priv_tls_dae_send(rc_handle *rh, const void *buf, size_t len)
{
	(void)rh;
	(void)buf;
	(void)len;
	return -1;
}

int radcli2_priv_tls_try_recv(rc_handle *rh, uint8_t *buf, size_t cap)
{
	(void)rh;
	(void)buf;
	(void)cap;
	return -1;
}

#endif

