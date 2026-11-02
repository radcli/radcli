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
#include "util.h"
#include "options.h"
#include "tls.h"
#include "session.h"

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
#include <poll.h>

#define DEFAULT_DTLS_SECRET "radius/dtls"
#define DEFAULT_TLS_SECRET "radsec"

/* The credentials rc_init_tls() loaded; the session's rc_session.backend. */
struct tls_creds {
	gnutls_psk_client_credentials_t psk_cred;
	gnutls_certificate_credentials_t x509_cred;
};

/** @} */

/*- GnuTLS certificate-verification callback: verify the peer's
 * certificate chain and, unless skip_hostname_check is set, that its
 * hostname matches.
 *
 * @param session the GnuTLS session being handshaked; its rc_session is
 * read back via gnutls_session_get_ptr().
 * @return 0 if the certificate is acceptable, GNUTLS_E_CERTIFICATE_ERROR
 * otherwise.
 -*/
static int cert_verify_callback(gnutls_session_t session)
{
	unsigned int status;
	int ret;
	rc_session *ctx;
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

/*- rc_sess_ops.start: set up a GnuTLS session on c's connected socket,
 * for tls_handshake() to drive.
 *
 * @param s the session; s->backend holds the credentials.
 * @param c the connection being opened.
 * @param timeout the handshake timeout in seconds.
 * @return 0 on success, -1 on failure.
 -*/
static int tls_start(rc_session *s, rc_sess_conn *c, int timeout)
{
	struct tls_creds *cr = s->backend;
	/* GNUTLS_NONBLOCK: without it the handshake waits inside GnuTLS for
	 * its own timeouts, socket blocking or not. */
	unsigned flags = GNUTLS_CLIENT | GNUTLS_NONBLOCK;
	char *p;
	int ret;

	if (s->ops->datagram)
		flags |= GNUTLS_DATAGRAM;
	ret = gnutls_init(&c->session, flags);
	if (ret < 0) {
		rc_log(LOG_ERR,
		       "%s: error in gnutls_init(): %s", __func__, gnutls_strerror(ret));
		return -1;
	}

	if (!s->ops->datagram) {
		if (timeout > 0) {
			gnutls_handshake_set_timeout(c->session, timeout*1000);
		} else {
			gnutls_handshake_set_timeout(c->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
		}
	} else { /* DTLS */
		if (timeout > 0)
			gnutls_dtls_set_timeouts(c->session, 1000, timeout*1000);
	}

	gnutls_transport_set_int(c->session, c->sockfd);
	gnutls_session_set_ptr(c->session, s);

	p = rc_conf_str_id(s->rh, OPT_TLS_VERIFY_HOSTNAME);
	if (p && (strcasecmp(p, "false") == 0 || strcasecmp(p, "no") == 0)) {
		s->skip_hostname_check = 1;
	}

	if (cr->psk_cred) {
		gnutls_credentials_set(c->session,
				       GNUTLS_CRD_PSK, cr->psk_cred);

		ret = gnutls_priority_set_direct(c->session, "NORMAL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:-VERS-TLS1.0", NULL);
		if (ret < 0) {
			rc_log(LOG_ERR,
			       "%s: error in setting PSK priorities: %s",
			       __func__, gnutls_strerror(ret));
			return -1;
		}
	} else {
		if (cr->x509_cred) {
			gnutls_credentials_set(c->session,
					       GNUTLS_CRD_CERTIFICATE,
					       cr->x509_cred);
		}

		gnutls_set_default_priority(c->session);
	}

	gnutls_server_name_set(c->session, GNUTLS_NAME_DNS,
			       s->hostname, strlen(s->hostname));

	rc_log(LOG_DEBUG,
	       "%s: performing TLS/DTLS handshake with [%s]:%d",
	       __func__, s->hostname, s->port);
	return 0;
}

/*- rc_sess_ops.handshake: advance the (D)TLS handshake without waiting. -*/
static int tls_handshake(rc_sess_conn *c)
{
	int ret;

	do {
		ret = gnutls_handshake(c->session);
	} while (ret < 0 && ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED &&
		 ret != GNUTLS_E_LARGE_PACKET && gnutls_error_is_fatal(ret) == 0);

	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
		return SESS_AGAIN;
	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in handshake: %s",
		       __func__, gnutls_strerror(ret));
		return -1;
	}

	c->handshake_done = 1;
	return 0;
}

/*- rc_sess_ops.handshake_wait for TLS: the direction GnuTLS last blocked
 * in. -*/
static int tls_handshake_wait(rc_sess_conn *c, short *events)
{
	*events = gnutls_record_get_direction(c->session) ? POLLOUT : POLLIN;
	return -1;
}

/*- rc_sess_ops.handshake_wait for DTLS: also when the retransmission timer
 * next fires, for tls_handshake() to resend a lost flight. -*/
static int dtls_handshake_wait(rc_sess_conn *c, short *events)
{
	/* GnuTLS can still report "write" after a flight went out and it is
	 * waiting for the reply (gnutls#1992), and polling a writable socket
	 * for POLLOUT would spin, so trust it only if the socket is full. */
	struct pollfd pfd = { c->sockfd, POLLOUT, 0 };

	if (gnutls_record_get_direction(c->session) && poll(&pfd, 1, 0) == 0) {
		*events = POLLOUT;
		/* The timer reads 0 once expired, yet no retransmission can
		 * reset it until this send clears. */
		return -1;
	}
	*events = POLLIN;
	return (int)gnutls_dtls_get_timeout(c->session);
}

/*- rc_sess_ops.handshake for DTLS: dtls_handshake_wait() cannot tell a send
 * that failed on a writable socket from a stale direction, and would leave it
 * unsent until the retransmission timer, possibly past the attempt's deadline.
 * Retrying sends nothing if the direction was stale. -*/
static int dtls_handshake(rc_sess_conn *c)
{
	struct pollfd pfd = { c->sockfd, POLLOUT, 0 };
	int ret = tls_handshake(c);

	if (ret == SESS_AGAIN && gnutls_record_get_direction(c->session) &&
	    poll(&pfd, 1, 0) > 0)
		ret = tls_handshake(c);
	return ret;
}

/*- rc_sess_ops.send: one gnutls_record_send() call. -*/
static int tls_send(rc_sess_conn *c, const void *buf, size_t len)
{
	int ret = gnutls_record_send(c->session, buf, len);

	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
		return SESS_AGAIN;
	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in sending: %s", __func__, gnutls_strerror(ret));
		return -1;
	}
	return ret;
}

/*- rc_sess_ops.recv: one gnutls_record_recv() call. -*/
static int tls_recv(rc_sess_conn *c, void *buf, size_t len)
{
	int ret = gnutls_record_recv(c->session, buf, len);

	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
		return SESS_AGAIN;
	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED) {
		rc_log(LOG_ERR, "%s: received alert: %s", __func__,
		       gnutls_alert_get_name(gnutls_alert_get(c->session)));
		return SESS_ALERT;
	}
	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in receiving: %s", __func__, gnutls_strerror(ret));
		return -1;
	}
	return ret;
}

/*- rc_sess_ops.pending: whether GnuTLS holds decrypted data. -*/
static int tls_pending(rc_sess_conn *c)
{
	return gnutls_record_check_pending(c->session) > 0;
}

/*- rc_sess_ops.stop: send close_notify if the handshake completed, then
 * deinit the GnuTLS session. -*/
static void tls_stop(rc_sess_conn *c)
{
	int ret;

	if (c->session == NULL)
		return;
	/* Send close_notify before the socket closes so the peer receives a
	 * proper TLS/DTLS shutdown alert. Only valid once the handshake
	 * actually completed -- e.g. a failed connect() leaves an initialized
	 * session with no negotiated cipher state. */
	if (c->sockfd != -1 && c->handshake_done) {
		do {
			ret = gnutls_bye(c->session, GNUTLS_SHUT_WR);
		} while (ret == GNUTLS_E_INTERRUPTED);
	}
	gnutls_deinit(c->session);
	c->session = NULL;
}

/*- Free cr and the credentials it holds. -*/
static void free_creds(struct tls_creds *cr)
{
	if (cr == NULL)
		return;
	if (cr->x509_cred)
		gnutls_certificate_free_credentials(cr->x509_cred);
	if (cr->psk_cred)
		gnutls_psk_free_client_credentials(cr->psk_cred);
	free(cr);
}

/*- rc_sess_ops.free: release the session's credentials. -*/
static void tls_free(rc_session *s)
{
	free_creds(s->backend);
	s->backend = NULL;
}

static const rc_sess_ops tls_ops = {
	.start = tls_start,
	.handshake = tls_handshake,
	.handshake_wait = tls_handshake_wait,
	.send = tls_send,
	.recv = tls_recv,
	.pending = tls_pending,
	.stop = tls_stop,
	.free = tls_free,
};

static const rc_sess_ops dtls_ops = {
	.datagram = 1,
	.start = tls_start,
	.handshake = dtls_handshake,
	.handshake_wait = dtls_handshake_wait,
	.send = tls_send,
	.recv = tls_recv,
	.pending = tls_pending,
	.stop = tls_stop,
	.free = tls_free,
};

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
	struct tls_creds *cr = NULL;
	const char *ca_file = rc_conf_str_id(rh, OPT_TLS_CA_FILE);
	const char *cert_file = rc_conf_str_id(rh, OPT_TLS_CERT_FILE);
	const char *key_file = rc_conf_str_id(rh, OPT_TLS_KEY_FILE);
	const char *pskkey = NULL;
	SERVER *authservers;
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

	cr = calloc(1, sizeof(*cr));
	if (cr == NULL) {
		ret = -1;
		goto cleanup;
	}

	if (ca_file || (key_file && cert_file)) {
		ret = gnutls_certificate_allocate_credentials(&cr->x509_cred);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting X.509 credentials: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}

		if (ca_file) {
			ret =
			    gnutls_certificate_set_x509_trust_file(cr->x509_cred,
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
			    gnutls_certificate_set_x509_key_file(cr->x509_cred,
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

		gnutls_certificate_set_verify_function(cr->x509_cred,
						       cert_verify_callback);
	}

	/* Read the PSK key if any */
	authservers = rc_conf_srv_id(rh, OPT_AUTHSERVER);
	if (authservers == NULL) {
		rc_log(LOG_ERR,
		       "%s: cannot find authserver", __func__);
		ret = -1;
		goto cleanup;
	}

	if (rh->tls_psk_key != NULL) {
		/* radcli2.h's radcli_ctx_set_tls_psk(): identity/key set directly
		 * as bytes, not parsed out of a "psk@user@hexkey" secret string --
		 * takes priority over authservers->secret[0] below if both are
		 * somehow set. */
		gnutls_datum_t rawkey;

		ret = gnutls_psk_allocate_client_credentials(&cr->psk_cred);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK credentials: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}

		rawkey.data = rh->tls_psk_key;
		rawkey.size = rh->tls_psk_key_len;

		ret = gnutls_psk_set_client_credentials(cr->psk_cred,
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

			ret = gnutls_psk_allocate_client_credentials(&cr->psk_cred);
			if (ret < 0) {
				ret = -1;
				rc_log(LOG_ERR,
				       "%s: error in setting PSK credentials: %s",
				       __func__, gnutls_strerror(ret));
				goto cleanup;
			}

			ret = gnutls_psk_set_client_credentials(cr->psk_cred,
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

		ret = gnutls_psk_allocate_client_credentials(&cr->psk_cred);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK credentials: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}

		ret =
		    gnutls_psk_set_client_credentials(cr->psk_cred,
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
	/* The connection and handshake happen on first use. */
	ret = radcli2_priv_sess_init(rh, (flags & SEC_FLAG_DTLS) ? &dtls_ops : &tls_ops, cr);
	if (ret < 0)
		goto cleanup;
	if (ns != NULL) {
		if(-1 == rc_reset_netns(&ns_def_hdl)) {
			rc_log(LOG_ERR, "rc_send_server: namespace %s reset failed", ns);
			return -1; /* the session, now owning cr, goes with rh */
		}
	}
	return 0;
 cleanup:
	free_creds(cr);
	if (ns != NULL) {
		if(-1 == rc_reset_netns(&ns_def_hdl))
		rc_log(LOG_ERR, "rc_send_server: namespace %s reset failed", ns);
	}
	return ret;
}

#endif /* HAVE_GNUTLS */
