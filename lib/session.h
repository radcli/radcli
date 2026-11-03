/*
 * Copyright (c) 2014-2026, Nikos Mavrogiannopoulos.  All rights reserved.
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

/* The persistent connection a TCP, TLS or DTLS ctx carries every request
 * over (lib/session.c), and the backend interface lib/tls.c implements
 * for TLS/DTLS. */

#ifndef RADCLI_SESSION_H
#define RADCLI_SESSION_H

#include <config.h>
#include <includes.h>
#include <pthread.h>

#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
#endif

/* Backend results besides a byte count. */
#define SESS_AGAIN (-2) /* would block: repeat the same call once ready */
#define SESS_ALERT (-3) /* a TLS warning alert arrived instead of data */

/* REQ-NET2-NET-005: how many records a session's send queue copies. */
#define SESS_SENDQ_SIZE 8

typedef struct rc_sess_conn {
	int sockfd;
	unsigned init;
	unsigned need_restart;
	time_t last_msg;	/* last send OR receive -- when the next watchdog is due */
	time_t last_recv;	/* last receive only -- REQ-WATCHDOG-NET-003's dead-peer clock */
	uint8_t rbuf[RC_MAX_PACKET_LEN]; /* stream transports: the packet being reassembled */
	size_t rlen;
	size_t wpos; /* plain TCP: bytes of the record being sent already written */
	unsigned gen; /* the session's attempt that opened this connection */
#ifdef HAVE_GNUTLS
	gnutls_session_t session;
	/* Heap-owned DTLS send state moves with the connection at promotion;
	 * callbacks must not point into the copied rc_sess_conn itself. */
	struct dtls_push_state *dtls_io;
	unsigned handshake_done; /* guards gnutls_bye(), invalid before a handshake */
#endif
} rc_sess_conn;

struct rc_session;

typedef struct rc_sess_ops {
	unsigned datagram; /* one packet per record (DTLS), no reassembly */
	/*- Set up the protocol on c's connected, non-blocking socket.
	 * @return 0 on success, -1 on failure. -*/
	int (*start)(struct rc_session *s, rc_sess_conn *c, int timeout);
	/*- Advance the handshake start() set up, without waiting.
	 * @return 0 once complete, SESS_AGAIN while in progress, or -1. -*/
	int (*handshake)(rc_sess_conn *c);
	/*- What an unfinished handshake waits for.
	 * @param events set to POLLIN or POLLOUT.
	 * @return milliseconds after which to advance it regardless, or -1. -*/
	int (*handshake_wait)(rc_sess_conn *c, short *events);
	/*- Send a whole record; after SESS_AGAIN, repeat with the same record.
	 * @return len, SESS_AGAIN, or -1 on error. -*/
	int (*send)(rc_sess_conn *c, const void *buf, size_t len);
	/*- Read up to len bytes.
	 * @return bytes read, 0 at end of stream, SESS_AGAIN, SESS_ALERT, or -1. -*/
	int (*recv)(rc_sess_conn *c, void *buf, size_t len);
	/*- @return nonzero if data no poll() will report is already buffered. -*/
	int (*pending)(rc_sess_conn *c);
	/*- Release what start() set up, before the socket is closed. -*/
	void (*stop)(rc_sess_conn *c);
	/*- Release the backend's per-ctx state (s->backend). -*/
	void (*free)(struct rc_session *s);
} rc_sess_ops;

struct sess_pending_send {
	const uint8_t *data; /* a copy, a registry slot's packet, or head_buf */
	size_t len;
	int kind; /* RADSEC_SEND_* */
	int slot; /* the in-flight registry slot data belongs to, or -1 */
	int copy; /* the rc_session.copies entry data is, or -1 */
};

/* Phases of a connection attempt (rc_session.phase). */
#define SESS_IDLE	0 /* none in progress */
#define SESS_CONNECTING	1 /* waiting for connect() to complete */
#define SESS_HANDSHAKING	2 /* waiting for the backend's handshake */

typedef struct rc_session {
	const rc_sess_ops *ops;
	void *backend;
	rc_handle *rh;
	char hostname[256];
	unsigned port;
	struct sockaddr_storage our_sockaddr;
	unsigned skip_hostname_check;
	unsigned bind_local; /* bind to bindaddr before connecting (plain TCP) */
	/* Here, not in conn: restart_session() replaces conn wholesale, possibly
	 * while this lock is held (REQ-NET-TEARDOWN-006). */
	pthread_mutex_t lock;
	rc_sess_conn conn;
	/* The connection attempt replacing conn, which stays in place, marked
	 * for restart, until the attempt succeeds (REQ-NET-TEARDOWN-004). */
	rc_sess_conn next;
	unsigned phase;
	double deadline; /* rc_getmtime() by which the attempt must complete */
	unsigned gen; /* counts attempts; 0 is never an attempt's */
	/* Records radcli_ctx_dispatch() could not send at once, oldest first
	 * (REQ-NET2-NET-005): at most SESS_SENDQ_SIZE copies, plus one
	 * request's packet per registry slot, which stays in the slot.
	 * Discarded by every restart: the records belong to the failed
	 * connection. */
	struct sess_pending_send sendq[SESS_SENDQ_SIZE + RADCLI_CTX_MAX_INFLIGHT];
	unsigned sendq_len;
	unsigned head_started; /* the backend has seen sendq[0]: pass it again unchanged */
	uint8_t copies[SESS_SENDQ_SIZE][RC_MAX_PACKET_LEN];
	unsigned copies_used; /* bit i: copies[i] holds a queued record */
	/* A started head whose registry slot was vacated: it must still be
	 * finished, from data the slot no longer guarantees. */
	uint8_t head_buf[RC_MAX_PACKET_LEN];
} rc_session;

int radcli2_priv_sess_init(rc_handle *rh, const rc_sess_ops *ops, void *backend);
int radcli2_priv_sess_init_tcp(rc_handle *rh);

#endif
