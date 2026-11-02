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

/* The persistent connection that carries every request of a TCP, TLS or
 * DTLS ctx: establishment and restart, packet framing, the send queue and
 * the rc_sockets_override vtable. Plain TCP is implemented here; lib/tls.c
 * supplies the TLS/DTLS backend (rc_sess_ops). */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include "util.h"
#include "options.h"
#include "session.h"

#include <poll.h>
#include <time.h>

#if defined(__linux__)
#include <linux/in6.h>
#endif

static int restart_session(rc_session *s);

/*- Return rh's session, or NULL if its transport does not use one. -*/
static rc_session *sess_of(rc_handle *rh)
{
	if (rh->so_type != RC_SOCKET_TCP && rh->so_type != RC_SOCKET_TLS &&
	    rh->so_type != RC_SOCKET_DTLS)
		return NULL;
	return rh->so.ptr;
}

/*- rc_sockets_override.get_fd: return s's socket, restarting the
 * connection first if it was marked for restart.
 *
 * @param ptr the rc_session.
 * @param our_sockaddr unused; part of the get_fd calling convention.
 * @return the socket, or -1 if a needed restart failed.
 -*/
static int sess_get_fd(void *ptr, struct sockaddr *our_sockaddr)
{
	rc_session *s = ptr;

	if (s->conn.need_restart != 0) {
		if (restart_session(s) < 0)
			return -1;
	}
	return s->conn.sockfd;
}

/*- rc_sockets_override.get_active_fd: return s's current socket without
 * attempting a restart.
 *
 * @param ptr the rc_session.
 * @return the socket, or -1 if none is open.
 -*/
static int sess_get_active_fd(void *ptr)
{
	rc_session *s = ptr;

	return s->conn.sockfd;
}

/*- Wait, up to radius_timeout, for s's socket to be ready to repeat a
 * backend call that returned SESS_AGAIN, or mark s for restart.
 *
 * @param s the session to wait on.
 * @param events POLLIN or POLLOUT, matching the call being repeated.
 * @param what a short verb ("send"/"receive") for the timeout log message.
 * @return 1 if the caller should repeat the call, or -1 if it should give
 *  up (errno set to EIO, session marked for restart).
 -*/
static int sess_wait_or_give_up(rc_session *s, short events, const char *what)
{
	double start_time = rc_getmtime();
	int timeout = rc_conf_int_id(s->rh, OPT_RADIUS_TIMEOUT);

	if (timeout <= 0)
		timeout = 1;

	for (; timeout > 0; timeout -= (int)(rc_getmtime() - start_time)) {
		struct pollfd pfd = { s->conn.sockfd, events, 0 };
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
	rc_log(LOG_ERR, "%s: timeout waiting to %s data", __func__, what);
give_up:
	errno = EIO;
	s->conn.need_restart = 1;
	return -1;
}

/*- Read towards one RADIUS packet on s without waiting, on a stream
 * reassembling it by its Length field (RFC 6614 SS3.4 (1), RFC 6613 SS2.6.4).
 * Reads no further than the packet's end, so what follows stays unread.
 *
 * @param s the session to read from.
 * @param buf destination for the packet.
 * @param cap buf's capacity in bytes.
 * @return the packet's length, else an rc_sess_ops.recv result <= 0, or
 *  -1 on a framing error.
 -*/
static int sess_recv_packet(rc_session *s, void *buf, size_t cap)
{
	rc_sess_conn *c = &s->conn;
	size_t want = AUTH_HDR_LENGTH_END;
	int ret;

	if (s->ops->datagram)
		return s->ops->recv(c, buf, cap);

	for (;;) {
		if (c->rlen >= AUTH_HDR_LENGTH_END) {
			want = ntohs(((AUTH_HDR *)c->rbuf)->length);
			/* RFC 6613 SS2.6.4: a bad Length leaves the stream unframed. */
			if (want < AUTH_HDR_LEN || want > RC_MAX_PACKET_LEN || want > cap) {
				rc_log(LOG_ERR, "%s: invalid RADIUS packet length %u on the connection",
				       __func__, (unsigned)want);
				return -1;
			}
			if (c->rlen == want) {
				memcpy(buf, c->rbuf, want);
				c->rlen = 0;
				return (int)want;
			}
		}

		ret = s->ops->recv(c, c->rbuf + c->rlen, want - c->rlen);
		if (ret <= 0)
			return ret;
		c->rlen += ret;
	}
}

/*- Discard everything s has queued.
 *
 * @param s the session whose queue to empty.
 -*/
static void sendq_clear(rc_session *s)
{
	s->sendq_len = 0;
	s->head_started = 0;
	s->copies_used = 0;
}

/*- Remove entry i from s's queue, releasing its copy.
 *
 * @param s the session whose queue to shorten.
 * @param i the entry's index; 0 only if the backend has not started on it
 *  or is done with it.
 -*/
static void sendq_remove(rc_session *s, unsigned i)
{
	if (s->sendq[i].copy >= 0)
		s->copies_used &= ~(1u << s->sendq[i].copy);
	if (i == 0)
		s->head_started = 0;
	s->sendq_len--;
	memmove(&s->sendq[i], &s->sendq[i + 1], (s->sendq_len - i) * sizeof(s->sendq[0]));
}

/*- Report whether s's queue has a free copy for one more record. -*/
static int sendq_has_copy(rc_session *s)
{
	return s->copies_used != (1u << SESS_SENDQ_SIZE) - 1;
}

/*- Append a record to s's queue: by reference if it is a registry slot's
 * packet, otherwise into a free copy, which the caller ensured exists.
 *
 * @param s the session whose queue to append to.
 * @param buf the record; a slot's packet must outlive the entry.
 * @param len buf's length in bytes, at most RC_MAX_PACKET_LEN.
 * @param kind the record's RADSEC_SEND_* kind.
 * @param slot the registry slot buf belongs to, or -1.
 -*/
static void sendq_append(rc_session *s, const void *buf, size_t len, int kind, int slot)
{
	struct sess_pending_send *p = &s->sendq[s->sendq_len++];

	p->len = len;
	p->kind = kind;
	p->slot = slot;
	p->copy = -1;
	if (slot >= 0) {
		p->data = buf;
		return;
	}
	while (s->copies_used & (1u << ++p->copy))
		;
	s->copies_used |= 1u << p->copy;
	memcpy(s->copies[p->copy], buf, len);
	p->data = s->copies[p->copy];
}

/*- Make one non-blocking attempt to send s's oldest queued record.
 *
 * @param s the session whose queue to advance.
 * @return 1 if the record went out, 0 if it would block, -1 on a
 *  connection error (the session is marked for restart and the queue
 *  discarded).
 -*/
static int sendq_try_head(rc_session *s)
{
	int ret = s->ops->send(&s->conn, s->sendq[0].data, s->sendq[0].len);

	if (ret == SESS_AGAIN) {
		s->head_started = 1;
		return 0;
	}
	if (ret < 0) {
		s->conn.need_restart = 1;
		sendq_clear(s);
		return -1;
	}

	s->conn.last_msg = time(0);
	sendq_remove(s, 0);
	return 1;
}

/*- rc_sockets_override.sendto: send buf over s, waiting via
 * sess_wait_or_give_up() while the backend cannot take it, restarting the
 * connection first if needed.
 *
 * @param ptr the rc_session.
 * @param sockfd unused; part of the sendto calling convention.
 * @param buf the data to send.
 * @param len buf's length in bytes.
 * @param flags unused; part of the sendto calling convention.
 * @param dest_addr unused; part of the sendto calling convention.
 * @param addrlen unused; part of the sendto calling convention.
 * @return the number of bytes sent, or -1 on failure (errno set to EIO).
 -*/
static ssize_t sess_sendto(void *ptr, int sockfd,
			   const void *buf, size_t len,
			   int flags, const struct sockaddr *dest_addr,
			   socklen_t addrlen)
{
	rc_session *s = ptr;
	int ret;

	if (s->conn.need_restart != 0) {
		if (restart_session(s) < 0) {
			errno = EIO;
			return -1;
		}
	}

	/* What radcli_ctx_dispatch() queued goes first, in order
	 * (REQ-NET2-NET-005); a blocking exchange may wait for it. */
	while (s->sendq_len > 0) {
		int r = sendq_try_head(s);

		if (r < 0) {
			errno = EIO;
			return -1;
		}
		if (r == 0 && sess_wait_or_give_up(s, POLLOUT, "send") < 0)
			return -1;
	}

	for (;;) {
		ret = s->ops->send(&s->conn, buf, len);
		if (ret == SESS_AGAIN) {
			if (sess_wait_or_give_up(s, POLLOUT, "send") < 0)
				return -1;
			continue;
		}

		if (ret < 0) {
			errno = EIO;
			s->conn.need_restart = 1;
			return -1;
		}

		break;
	}

	s->conn.last_msg = time(0);
	return ret;
}

/*- rc_sockets_override.lock: acquire s's lock.
 *
 * @param ptr the rc_session.
 * @return pthread_mutex_lock()'s return value.
 -*/
static int sess_lock(void *ptr)
{
	rc_session *s = ptr;

	return pthread_mutex_lock(&s->lock);
}

/*- rc_sockets_override.unlock: release s's lock.
 *
 * @param ptr the rc_session.
 * @return pthread_mutex_unlock()'s return value.
 -*/
static int sess_unlock(void *ptr)
{
	rc_session *s = ptr;

	return pthread_mutex_unlock(&s->lock);
}

/*- rc_sockets_override.recvfrom: read one RADIUS packet from s without
 * waiting; a TLS record carrying no RADIUS data (e.g. a TLS 1.3 session
 * ticket) or part of a packet leaves the caller to poll() again. The packet
 * may be any type (RFC 6614 §2.1/§2.5, RFC 7360 §2.2); the caller routes
 * what is not its own reply.
 *
 * @param ptr the rc_session.
 * @param sockfd unused; part of the recvfrom calling convention.
 * @param buf destination buffer for the received packet.
 * @param len buf's capacity in bytes.
 * @param flags unused; part of the recvfrom calling convention.
 * @param src_addr unused; part of the recvfrom calling convention.
 * @param addrlen unused; part of the recvfrom calling convention.
 * @return the number of bytes received, or -1 on failure (errno set to
 * EAGAIN if no whole packet is ready yet, EINTR on a received alert, EIO
 * otherwise).
 -*/
static ssize_t sess_recvfrom(void *ptr, int sockfd,
			     void *buf, size_t len,
			     int flags, struct sockaddr *src_addr,
			     socklen_t * addrlen)
{
	rc_session *s = ptr;
	int ret;

	ret = sess_recv_packet(s, buf, len);
	if (ret == SESS_AGAIN) {
		errno = EAGAIN;
		return -1;
	}

	if (ret == SESS_ALERT) {
		errno = EINTR;
		return -1;
	}

	if (ret <= 0) {
		if (ret == 0)
			rc_log(LOG_ERR, "%s: connection closed by the server", __func__);
		errno = EIO;
		s->conn.need_restart = 1;
		return -1;
	}

	s->conn.last_msg = time(0);
	s->conn.last_recv = s->conn.last_msg;
	return ret;
}

/*- Close c: release the backend's state, then the socket.
 *
 * @param s the session c belongs to.
 * @param c the connection; c->init is left 0.
 -*/
static void conn_close(rc_session *s, rc_sess_conn *c)
{
	if (c->init == 0)
		return;
	c->init = 0;
	if (s->ops->stop)
		s->ops->stop(c);
	if (c->sockfd != -1)
		close(c->sockfd);
}

/*- Prefer a public over a temporary IPv6 source address when
 * use-public-addr asks for it.
 *
 * @param rh a handle to parsed configuration.
 * @param fd the socket, not yet connected.
 * @return 0 on success, -1 on failure.
 -*/
static int prefer_public_addr(rc_handle *rh, int fd)
{
	char *non_temp_addr = rc_conf_str_id(rh, OPT_USE_PUBLIC_ADDR);

	if (non_temp_addr == NULL || strcasecmp(non_temp_addr, "true") != 0)
		return 0;
#if defined(__linux__)
	{
		int sock_opt = IPV6_PREFER_SRC_PUBLIC;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_ADDR_PREFERENCES,
			       &sock_opt, sizeof(sock_opt)) != 0) {
			rc_log(LOG_ERR, "%s: setsockopt: %s", __func__, strerror(errno));
			return -1;
		}
	}
#elif defined(BSD) || defined(__APPLE__)
	{
		int sock_opt = 0;
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_PREFER_TEMPADDR,
			       &sock_opt, sizeof(sock_opt)) != 0) {
			rc_log(LOG_ERR, "%s: setsockopt: %s", __func__, strerror(errno));
			return -1;
		}
	}
#else
	rc_log(LOG_INFO, "%s: Usage of non-temporary IPv6 address is not "
	       "supported in this system", __func__);
#endif
	return 0;
}

/*- Begin a connection attempt to s's server, unless one is in progress:
 * open a non-blocking socket and start connecting it, discarding what was
 * queued for the failed connection. Name resolution may block
 * (REQ-NET2-NET-001).
 *
 * @param s the session to connect.
 * @return 0 if an attempt is in progress, -1 if it could not start.
 -*/
static int attempt_begin(rc_session *s)
{
	rc_sess_conn *c = &s->next;
	struct sockaddr_storage our_sockaddr;
	struct addrinfo *info;
	int sockfd, ret, e, sock_flags, timeout;

	if (s->phase != SESS_IDLE)
		return 0;

	/* The backend relies on fields it does not write being zero:
	 * REQ-NET-NET-016 */
	memset(c, 0, sizeof(*c));
	c->sockfd = -1;
	c->init = 1;
	sendq_clear(s);

	memcpy(&our_sockaddr, &s->our_sockaddr, sizeof(our_sockaddr));
	if (our_sockaddr.ss_family == AF_INET)
		((struct sockaddr_in *)&our_sockaddr)->sin_port = 0;
	else
		((struct sockaddr_in6 *)&our_sockaddr)->sin6_port = 0;

	sockfd = socket(our_sockaddr.ss_family, s->ops->datagram ? SOCK_DGRAM : SOCK_STREAM, 0);
	if (sockfd < 0) {
		rc_log(LOG_ERR, "%s: cannot open socket", __func__);
		goto fail;
	}
	c->sockfd = sockfd;

	if (s->bind_local) {
		if (bind(sockfd, SA(&our_sockaddr), SS_LEN(&our_sockaddr)) < 0) {
			rc_log(LOG_ERR, "%s: bind: %s", __func__, strerror(errno));
			goto fail;
		}
		if (our_sockaddr.ss_family == AF_INET6 && prefer_public_addr(s->rh, sockfd) < 0)
			goto fail;
	}

	/* Every operation on the socket must see SESS_AGAIN rather than block
	 * in the kernel with no timeout at all. */
	sock_flags = fcntl(sockfd, F_GETFL, 0);
	if (sock_flags == -1 ||
	    fcntl(sockfd, F_SETFL, sock_flags | O_NONBLOCK) == -1) {
		e = errno;
		rc_log(LOG_CRIT, "%s: cannot set socket non-blocking: %s",
		       __func__, strerror(e));
		goto fail;
	}

	info = rc_getaddrinfo(s->hostname, PW_AI_AUTH);
	if (info == NULL) {
		rc_log(LOG_ERR, "%s: cannot resolve %s", __func__, s->hostname);
		goto fail;
	}

	if (s->port == 0) {
		rc_log(LOG_ERR, "%s: no port specified for server %s", __func__, s->hostname);
		freeaddrinfo(info);
		goto fail;
	}
	if (info->ai_addr->sa_family == AF_INET)
		((struct sockaddr_in *)info->ai_addr)->sin_port = htons(s->port);
	else
		((struct sockaddr_in6 *)info->ai_addr)->sin6_port = htons(s->port);

	/* we connect since we are talking to a single server */
	ret = connect(sockfd, info->ai_addr, info->ai_addrlen);
	e = errno;
	freeaddrinfo(info);
	if (ret == -1 && e != EINPROGRESS) {
		rc_log(LOG_CRIT, "%s: cannot connect to %s: %s",
		       __func__, s->hostname, strerror(e));
		goto fail;
	}

	timeout = rc_conf_int_id(s->rh, OPT_RADIUS_TIMEOUT);
	s->deadline = rc_getmtime() + (timeout > 0 ? timeout : 1);
	if (++s->gen == 0)
		s->gen = 1;
	c->gen = s->gen;
	s->phase = SESS_CONNECTING;
	return 0;
 fail:
	conn_close(s, c);
	return -1;
}

/*- Check, without waiting, whether s's attempt has finished connecting.
 *
 * @param s the session whose attempt to check.
 * @return 1 once connected, 0 while pending, -1 if connecting failed.
 -*/
static int attempt_connected(rc_session *s)
{
	struct pollfd pfd = { s->next.sockfd, POLLOUT, 0 };
	socklen_t len = sizeof(int);
	int err = 0;

	if (poll(&pfd, 1, 0) <= 0)
		return 0;
	if (getsockopt(s->next.sockfd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
		err = errno;
	if (err != 0) {
		rc_log(LOG_CRIT, "%s: cannot connect to %s: %s",
		       __func__, s->hostname, strerror(err));
		return -1;
	}
	return 1;
}

/*- Advance s's connection attempt as far as it goes without waiting;
 * once established, it replaces s->conn.
 *
 * @param s the session whose attempt to advance.
 * @return 1 once established, 0 while in progress, -1 if the attempt
 *  failed (s->conn is left unchanged) or none is in progress.
 -*/
static int attempt_step(rc_session *s)
{
	rc_sess_conn *c = &s->next;
	int ret;

	if (s->phase == SESS_IDLE)
		return -1;
	if (rc_getmtime() >= s->deadline) {
		rc_log(LOG_ERR, "%s: timeout connecting to %s", __func__, s->hostname);
		goto fail;
	}

	if (s->phase == SESS_CONNECTING) {
		ret = attempt_connected(s);
		if (ret < 0)
			goto fail;
		if (ret == 0)
			return 0;
		if (s->ops->start &&
		    s->ops->start(s, c, rc_conf_int_id(s->rh, OPT_RADIUS_TIMEOUT)) < 0)
			goto fail;
		s->phase = SESS_HANDSHAKING;
	}

	if (s->ops->handshake) {
		ret = s->ops->handshake(c);
		if (ret == SESS_AGAIN)
			return 0;
		if (ret < 0)
			goto fail;
	}

	/* A fresh connection counts as activity: without this, last_msg stays
	 * at zero until the first send/receive, which radcli_ctx_get_poll()'s
	 * watchdog-deadline math (lib/dae.c) would read as "idle since the
	 * epoch" right after radcli_dae_start()'s eager connect
	 * (REQ-DAE-INIT-010). */
	c->last_msg = time(0);
	c->last_recv = c->last_msg;

	if (c->sockfd == s->conn.sockfd)
		s->conn.sockfd = -1;
	conn_close(s, &s->conn);
	memcpy(&s->conn, c, sizeof(*c));
	c->init = 0;
	s->conn.need_restart = 0;
	s->phase = SESS_IDLE;
	return 1;
 fail:
	rc_log(LOG_ERR, "%s: error in re-initializing the connection", __func__);
	conn_close(s, c);
	s->phase = SESS_IDLE;
	sendq_clear(s);
	return -1;
}

/*- Report what s's connection attempt is waiting for.
 *
 * @param s a session with an attempt in progress.
 * @param events set to POLLIN or POLLOUT.
 * @return milliseconds after which to advance the attempt regardless.
 -*/
static int attempt_wait(rc_session *s, short *events)
{
	int ms = (int)((s->deadline - rc_getmtime()) * 1000) + 1;
	int hs_ms;

	if (ms < 0)
		ms = 0;
	*events = POLLOUT;
	if (s->phase == SESS_HANDSHAKING && s->ops->handshake_wait) {
		hs_ms = s->ops->handshake_wait(&s->next, events);
		if (hs_ms >= 0 && hs_ms < ms)
			ms = hs_ms;
	}
	return ms;
}

/*- Reconnect s, waiting for the attempt (continuing one already in
 * progress) to finish. Every call site only ever calls this when the
 * connection is already known to need it (a send/recv failure already set
 * need_restart, or session init preset it before the first connection),
 * so this always reconnects unconditionally -- no rate-limiting.
 *
 * @param s the session to restart.
 * @return 0 on success, -1 if reconnecting failed (s->conn is left
 *  unchanged).
 -*/
static int restart_session(rc_session *s)
{
	int ret;

	if (attempt_begin(s) < 0)
		return -1;

	while ((ret = attempt_step(s)) == 0) {
		struct pollfd pfd = { s->next.sockfd, 0, 0 };
		int ms = attempt_wait(s, &pfd.events);

		/* A timeout or EINTR only means stepping again. */
		poll(&pfd, 1, ms);
	}
	return ret > 0 ? 0 : -1;
}

/*- Return the socket of rh's connection, if one is established and not
 * known to have failed.
 *
 * @param rh a handle to parsed configuration.
 * @return the socket, or -1 if rh uses no session or none is usable.
 -*/
int radcli2_priv_sess_fd(rc_handle *rh)
{
	rc_session *s = sess_of(rh);

	if (s != NULL && s->conn.init != 0 && s->conn.need_restart == 0)
		return s->conn.sockfd;
	return -1;
}

/*- Report what rh's session needs watched: its connection attempt, or its
 * established connection.
 *
 * @param rh a handle to parsed configuration.
 * @param events set to the poll() events to wait for.
 * @param timeout_ms set to the milliseconds after which to call
 *  radcli_ctx_dispatch() regardless, or -1 for none.
 * @return the socket to watch, or -1 if there is nothing to watch.
 -*/
int radcli2_priv_sess_poll(rc_handle *rh, short *events, int *timeout_ms)
{
	rc_session *s = sess_of(rh);

	*events = 0;
	*timeout_ms = -1;
	if (s == NULL)
		return -1;
	if (s->phase != SESS_IDLE) {
		*timeout_ms = attempt_wait(s, events);
		return s->next.sockfd;
	}
	if (s->conn.init == 0 || s->conn.need_restart != 0)
		return -1;

	*events = POLLIN;
	/* Queued records go out once the socket is writable again
	 * (REQ-NET2-NET-005). */
	if (s->sendq_len > 0)
		*events |= POLLOUT;
	/* Data the backend already holds raises no POLLIN. */
	if (s->ops->pending && s->ops->pending(&s->conn))
		*timeout_ms = 0;
	return s->conn.sockfd;
}

/*- Advance rh's connection attempt, if any, without waiting
 * (REQ-NET2-NET-001).
 *
 * @param rh a handle to parsed configuration.
 -*/
void radcli2_priv_sess_progress(rc_handle *rh)
{
	rc_session *s = sess_of(rh);

	if (s != NULL && s->phase != SESS_IDLE)
		attempt_step(s);
}

/*- Return the generation of rh's newest stream connection or connection
 * attempt, to record what a request was sent on for
 * radcli2_priv_sess_holds().
 *
 * @param rh a handle to parsed configuration.
 * @return the generation, or 0 if rh's transport has no stream connection
 *  (UDP, DTLS).
 -*/
unsigned radcli2_priv_sess_gen(rc_handle *rh)
{
	rc_session *s = sess_of(rh);

	if (s == NULL || s->ops->datagram)
		return 0;
	return s->gen;
}

/*- Report whether a request sent on generation gen is still in flight on
 * the same healthy stream connection, over which RFC 6613 SS2.6.1 forbids
 * sending it again (REQ-NET-NET-022).
 *
 * @param rh a handle to parsed configuration.
 * @param gen the radcli2_priv_sess_gen() value recorded when it was sent.
 * @return nonzero if it must not be sent again.
 -*/
int radcli2_priv_sess_holds(rc_handle *rh, unsigned gen)
{
	rc_session *s = sess_of(rh);

	return s != NULL && gen != 0 && s->phase == SESS_IDLE && s->conn.init != 0 &&
	       s->conn.need_restart == 0 && s->conn.gen == gen;
}

/*- Return the socket of rh's TLS/DTLS session, if one is established --
 * rc_tls_fd()'s implementation, also usable as a test for whether TLS or
 * DTLS is in use.
 *
 * @param rh a handle to parsed configuration.
 * @return the socket, or -1 if TLS/DTLS is not in use or no session is
 *  established.
 -*/
int radcli2_priv_tls_fd(rc_handle *rh)
{
	rc_session *s;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return -1;
	s = rh->so.ptr;
	if (s != NULL && s->conn.init != 0)
		return s->conn.sockfd;
	return -1;
}

/*- Return the time of the last packet sent or received on rh's connection
 * (rc_sess_conn.last_msg). Used by lib/dae.c's radcli_ctx_get_poll() to
 * compute a watchdog deadline (watchdog-interval).
 *
 * @param rh a handle to parsed configuration.
 * @return the last-activity timestamp, or 0 if rh uses no session or none
 *  is established.
 -*/
time_t radcli2_priv_sess_last_msg(rc_handle *rh)
{
	rc_session *s = sess_of(rh);

	if (s != NULL && s->conn.init != 0)
		return s->conn.last_msg;
	return 0;
}

/*- Return the time of the last packet actually *received* on rh's
 * connection (rc_sess_conn.last_recv) -- unlike
 * radcli2_priv_sess_last_msg(), never advanced by a send. Used by lib/
 * dae.c's radcli2_priv_dae_send_watchdog() (REQ-WATCHDOG-NET-003) to
 * detect a peer that has gone silent while the connection is still open.
 *
 * @param rh a handle to parsed configuration.
 * @return the last-receive timestamp, or 0 if rh uses no session or none
 *  is established.
 -*/
time_t radcli2_priv_sess_last_recv(rc_handle *rh)
{
	rc_session *s = sess_of(rh);

	if (s != NULL && s->conn.init != 0)
		return s->conn.last_recv;
	return 0;
}

/*- Treat rh's connection as failed, the same way an actual send/recv
 * error does (need_restart), and begin reconnecting without waiting --
 * used by lib/dae.c's radcli2_priv_dae_send_watchdog()
 * (REQ-WATCHDOG-NET-003) when the peer is presumed dead from elapsed time
 * alone.
 *
 * @param rh a handle to parsed configuration.
 * @return 0 if a connection attempt is in progress, -1 if rh uses no
 *  session or the attempt could not start.
 -*/
int radcli2_priv_sess_force_reconnect(rc_handle *rh)
{
	rc_session *s = sess_of(rh);

	if (s == NULL)
		return -1;
	s->conn.need_restart = 1;
	return attempt_begin(s);
}

/*- Probe an established TLS/DTLS session's liveness and reconnect if it is
 * dead. Once watchdog-interval has elapsed since the session's last
 * activity, sends an RFC 5997 Status-Server watchdog
 * (radcli2_priv_dae_send_watchdog(), REQ-WATCHDOG-NET-001) -- which itself
 * already detects and reconnects from a peer gone silent for 2.5x that
 * interval (REQ-WATCHDOG-NET-003), so this one call covers both probing and
 * recovering. For a caller that wants a dead session detected proactively
 * (e.g. from a periodic timer) rather than on the next request.
 *
 * @param rh a handle to parsed configuration.
 * @return 0 on success or when TLS/DTLS is not in use, -1 if a
 * known-broken session could not be re-established.
 -*/
int radcli2_priv_check_tls(rc_handle *rh)
{
	rc_session *s;
	int interval;

	if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
		return 0;

	s = rh->so.ptr;

	if (s->conn.init == 0)
		return 0;

	if (s->conn.need_restart != 0)
		return restart_session(s) < 0 ? -1 : 0;

	interval = rc_conf_int_id(rh, OPT_WATCHDOG_INTERVAL);
	if (interval > 0 && time(0) - s->conn.last_msg >= interval)
		radcli2_priv_dae_send_watchdog((radcli_ctx *)rh);

	return 0;
}

/*- Establish rh's connection now, rather than waiting for the first
 * request to do so -- used by radcli_dae_start() so enabling DAE makes
 * the NAS reachable immediately, matching the UDP listener's own
 * immediate bind().
 *
 * @param rh a handle to parsed configuration.
 * @return 0 on success or if already connected and healthy, -1 if rh uses
 *  no session or connecting failed.
 -*/
int radcli2_priv_sess_ensure_connected(rc_handle *rh)
{
	rc_session *s = sess_of(rh);

	if (s == NULL)
		return -1;

	if (s->conn.init != 0 && s->conn.need_restart == 0)
		return 0; /* already connected and healthy */

	return restart_session(s);
}

/*- Send whatever rh's connection has queued that can go out without
 * waiting (REQ-NET2-NET-005).
 *
 * @param rh a handle to parsed configuration.
 -*/
void radcli2_priv_sess_flush(rc_handle *rh)
{
	rc_session *s = sess_of(rh);

	if (s == NULL || s->conn.init == 0 || s->conn.need_restart != 0)
		return;
	while (s->sendq_len > 0 && sendq_try_head(s) == 1)
		;
}

/*- Send a record on rh's connection without ever waiting (REQ-NET2-NET-001,
 * REQ-NET2-NET-005): sent at once when nothing is queued ahead of it,
 * queued otherwise. A request's packet is queued by reference to its
 * registry slot; with no copy free for anything else, a DAE reply
 * displaces the oldest unstarted DAE reply (REQ-DAE-SEC-013) and a
 * watchdog is skipped. Anything but a DAE reply on a failed connection
 * begins reconnecting and is queued for the new connection; a DAE reply,
 * which belongs to the failed connection, fails instead.
 *
 * @param rh a handle to parsed configuration.
 * @param buf the record; a slot's packet must stay valid until sent or
 *  radcli2_priv_sess_unqueue().
 * @param len buf's length in bytes.
 * @param kind RADSEC_SEND_DAE_REPLY, RADSEC_SEND_REQUEST,
 *  RADSEC_SEND_RETRANSMIT or RADSEC_SEND_WATCHDOG.
 * @param slot the registry slot whose packet buf is, or -1.
 * @return the number of bytes sent if it went out at once, 0 if queued,
 *  -1 on a connection error or with no connection, -2 if skipped or
 *  dropped because no copy is free.
 -*/
int radcli2_priv_sess_send_queued(rc_handle *rh, const void *buf, size_t len, int kind, int slot)
{
	rc_session *s = sess_of(rh);
	unsigned i;
	int ret;

	if (s == NULL || len > RC_MAX_PACKET_LEN)
		return -1;

	if (s->conn.init == 0 || s->conn.need_restart != 0) {
		if (kind == RADSEC_SEND_DAE_REPLY || attempt_begin(s) < 0)
			return -1;
	} else {
		radcli2_priv_sess_flush(rh);
		if (s->conn.need_restart != 0)
			return -1;
	}

	if (s->phase == SESS_IDLE && s->sendq_len == 0) {
		ret = s->ops->send(&s->conn, buf, len);
		if (ret == SESS_AGAIN) {
			sendq_append(s, buf, len, kind, slot);
			s->head_started = 1;
			return 0;
		}
		if (ret < 0) {
			s->conn.need_restart = 1;
			return -1;
		}
		s->conn.last_msg = time(0);
		return ret;
	}

	if (slot >= 0 || sendq_has_copy(s)) {
		sendq_append(s, buf, len, kind, slot);
		return 0;
	}

	if (kind == RADSEC_SEND_DAE_REPLY) {
		for (i = s->head_started; i < s->sendq_len; i++) {
			if (s->sendq[i].kind == RADSEC_SEND_DAE_REPLY)
				break;
		}
		if (i < s->sendq_len) {
			rc_log(LOG_WARNING, "%s: send queue full (%u), dropping the "
			       "oldest unsent dynamic-authorization reply", __func__,
			       (unsigned)SESS_SENDQ_SIZE);
			sendq_remove(s, i);
			sendq_append(s, buf, len, kind, slot);
			return 0;
		}
	}

	rc_log(LOG_WARNING, "%s: send queue full (%u), skipping this %s", __func__,
	       (unsigned)SESS_SENDQ_SIZE,
	       kind == RADSEC_SEND_WATCHDOG ? "watchdog" : "dynamic-authorization reply");
	return -2;
}

/*- Report whether the packet of registry slot slot is queued on rh's
 * connection, not yet sent.
 *
 * @param rh a handle to parsed configuration.
 * @param slot the in-flight registry slot.
 * @return nonzero if it is queued.
 -*/
int radcli2_priv_sess_queued(rc_handle *rh, int slot)
{
	rc_session *s = sess_of(rh);
	unsigned i;

	if (s == NULL)
		return 0;
	for (i = 0; i < s->sendq_len; i++) {
		if (s->sendq[i].slot == slot)
			return 1;
	}
	return 0;
}

/*- Stop rh's queue from referencing registry slot slot, which is being
 * vacated: its packet leaves the queue, unless the backend has started on
 * it, which must then be finished from the session's own copy
 * (REQ-NET2-NET-005).
 *
 * @param rh a handle to parsed configuration.
 * @param slot the in-flight registry slot.
 -*/
void radcli2_priv_sess_unqueue(rc_handle *rh, int slot)
{
	rc_session *s = sess_of(rh);
	unsigned i;

	if (s == NULL)
		return;
	for (i = 0; i < s->sendq_len; i++) {
		if (s->sendq[i].slot != slot)
			continue;
		if (i == 0 && s->head_started) {
			memcpy(s->head_buf, s->sendq[0].data, s->sendq[0].len);
			s->sendq[0].data = s->head_buf;
			s->sendq[0].slot = -1;
		} else {
			sendq_remove(s, i);
		}
		return;
	}
}

/*- Make one non-blocking attempt (never waits, unlike sess_recvfrom()) to
 * read one already-available RADIUS packet from rh's connection, for
 * lib/sendserver.c's radcli2_priv_sess_drain() to route. A partly received
 * packet is kept for the next call.
 *
 * @param rh a handle to parsed configuration.
 * @param buf destination for the packet.
 * @param cap buf's capacity in bytes.
 * @return the packet length (>0) on success, 0 if no whole packet is ready
 *  or no connection is established, -1 on a connection error (also marks
 *  the session for reconnection, same as sess_recvfrom()).
 -*/
int radcli2_priv_sess_try_recv(rc_handle *rh, uint8_t *buf, size_t cap)
{
	rc_session *s = sess_of(rh);
	int ret;

	if (s == NULL)
		return -1;
	if (s->conn.init == 0 || s->conn.need_restart != 0)
		return 0; /* reconnecting is an ordinary send's job, not a read's */

	ret = sess_recv_packet(s, buf, cap);

	/* A warning alert is transient, not a reason to reconnect. */
	if (ret == SESS_AGAIN || ret == SESS_ALERT)
		return 0;

	if (ret <= 0) {
		if (ret == 0)
			rc_log(LOG_ERR, "%s: connection closed by the server", __func__);
		s->conn.need_restart = 1;
		return -1;
	}

	s->conn.last_msg = time(0);
	s->conn.last_recv = s->conn.last_msg;
	return ret;
}

/*- Report whether rh's connection holds already-received data that no read
 * has returned yet -- data no poll() on the socket will signal.
 *
 * @param rh a handle to parsed configuration.
 * @return nonzero if a read would return data without waiting.
 -*/
int radcli2_priv_sess_pending(rc_handle *rh)
{
	rc_session *s = sess_of(rh);

	if (s == NULL || s->conn.init == 0 || s->conn.need_restart != 0 ||
	    s->ops->pending == NULL)
		return 0;
	return s->ops->pending(&s->conn);
}

/*- Close rh's connection, if any, and free its session.
 *
 * @param rh the configuration handle.
 -*/
void radcli2_priv_sess_deinit(rc_handle *rh)
{
	rc_session *s = sess_of(rh);
	char *ns = NULL;
	int ns_def_hdl = 0;

	if (s == NULL)
		return;

	ns = rc_conf_str_id(rh, OPT_NAMESPACE);
	if (ns != NULL && rc_set_netns(ns, &ns_def_hdl) == -1) {
		rc_log(LOG_ERR, "%s: namespace %s set failed", __func__, ns);
		return;
	}
	if (s->phase != SESS_IDLE)
		conn_close(s, &s->next);
	conn_close(s, &s->conn);
	if (ns != NULL && rc_reset_netns(&ns_def_hdl) == -1)
		rc_log(LOG_ERR, "%s: namespace %s reset failed", __func__, ns);

	if (s->ops->free)
		s->ops->free(s);
	pthread_mutex_destroy(&s->lock);
	free(s);
	rh->so.ptr = NULL;
}

/*- Give rh a session to its single authserver over the backend ops,
 * connected on first use. rh->so_type must already be set; on success
 * the session owns backend.
 *
 * @param rh a handle to parsed configuration.
 * @param ops the transport backend.
 * @param backend the backend's per-ctx state, released by ops->free.
 * @return 0 on success, -1 on failure.
 -*/
int radcli2_priv_sess_init(rc_handle *rh, const rc_sess_ops *ops, void *backend)
{
	SERVER *authservers;
	rc_session *s;

	authservers = rc_conf_srv_id(rh, OPT_AUTHSERVER);
	if (authservers == NULL || authservers->max == 0) {
		rc_log(LOG_ERR, "%s: cannot find authserver", __func__);
		return -1;
	}
	if (authservers->max > 1) {
		rc_log(LOG_ERR, "%s: too many auth servers for TCP/TLS/DTLS; only one is allowed",
		       __func__);
		return -1;
	}

	s = calloc(1, sizeof(*s));
	if (s == NULL)
		return -1;

	s->ops = ops;
	s->backend = backend;
	s->rh = rh;
	strlcpy(s->hostname, authservers->name[0], sizeof(s->hostname));
	s->port = authservers->port[0];
	rc_own_bind_addr(rh, &s->our_sockaddr);
	pthread_mutex_init(&s->lock, NULL);
	/* calloc() left 0, a valid descriptor: no connection exists yet
	 * (REQ-NET-NET-019). */
	s->conn.sockfd = -1;
	/* Connect on first use (REQ-NET-NET-005). */
	s->conn.need_restart = 1;

	rh->so.ptr = s;
	rh->so.get_fd = sess_get_fd;
	rh->so.get_active_fd = sess_get_active_fd;
	rh->so.sendto = sess_sendto;
	rh->so.recvfrom = sess_recvfrom;
	rh->so.lock = sess_lock;
	rh->so.unlock = sess_unlock;
	return 0;
}

/*- rc_sess_ops.send for plain TCP: write all of buf, resuming after a
 * short write from where the previous call stopped.
 -*/
static int tcp_send(rc_sess_conn *c, const void *buf, size_t len)
{
	while (c->wpos < len) {
		ssize_t n = send(c->sockfd, (const uint8_t *)buf + c->wpos, len - c->wpos, 0);

		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
				return SESS_AGAIN;
			rc_log(LOG_ERR, "%s: send: %s", __func__, strerror(errno));
			return -1;
		}
		c->wpos += (size_t)n;
	}
	c->wpos = 0;
	return (int)len;
}

/*- rc_sess_ops.recv for plain TCP: a thin recv(2) wrapper. -*/
static int tcp_recv(rc_sess_conn *c, void *buf, size_t len)
{
	ssize_t n = recv(c->sockfd, buf, len, 0);

	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return SESS_AGAIN;
		rc_log(LOG_ERR, "%s: recv: %s", __func__, strerror(errno));
		return -1;
	}
	return (int)n;
}

static const rc_sess_ops tcp_ops = {
	.send = tcp_send,
	.recv = tcp_recv,
};

/*- Select the plain TCP transport: one persistent connection to the
 * single authserver, carrying every request (RFC 6613).
 *
 * @param rh a handle to parsed configuration.
 * @return 0 on success, -1 on failure.
 -*/
int radcli2_priv_sess_init_tcp(rc_handle *rh)
{
	memset(&rh->so, 0, sizeof(rh->so));
	rh->so_type = RC_SOCKET_TCP;
	if (radcli2_priv_sess_init(rh, &tcp_ops, NULL) < 0)
		return -1;
	((rc_session *)rh->so.ptr)->bind_local = 1;
	return 0;
}
