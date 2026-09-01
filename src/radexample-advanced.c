/*
 * Copyright (C) 2015,2026 Nikos Mavrogiannopoulos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file radexample-advanced.c
 * @brief radexample.c's This is a client the maintains a long-lived TLS/DTLS session
 *  with the radius server, sending Access-Request, and sending a watchdog message,
 *  plus a Disconnect-Request (Dynamic Authorization) listener.
 */

#include	<config.h>
#include	<stdio.h>
#include	<syslog.h>
#include	<poll.h>
#include	<errno.h>
#include	<arpa/inet.h>
#include	<radcli/radcli2.h>

static void
print_reply(radcli_ctx *ctx, const radcli_avp_list *recvd)
{
	uint32_t timeout, service_type;
	struct in6_addr framed_ipv6;
	char buf[INET6_ADDRSTRLEN];

	if (radcli_avp_get_uint32_by_num(recvd, ctx, PW_SESSION_TIMEOUT, 0, &timeout) == 0)
		fprintf(stderr, "Session-Timeout: %u seconds\n", (unsigned)timeout);

	if (radcli_avp_get_ip6_by_num(recvd, ctx, PW_FRAMED_IPV6_ADDRESS, 0, &framed_ipv6, NULL) == 0 &&
	    inet_ntop(AF_INET6, &framed_ipv6, buf, sizeof(buf)) != NULL)
		fprintf(stderr, "Framed-IPv6-Address: %s\n", buf);

	if (radcli_avp_get_uint32_by_num(recvd, ctx, PW_SERVICE_TYPE, 0, &service_type) == 0)
		fprintf(stderr, "Service-Type: %u\n", (unsigned)service_type);
}

static void
handle_dae_request(radcli_dae_request *req, void *user)
{
	const char *session_id = radcli_dae_req_session_id(req);
	const char *user_name = radcli_dae_req_user_name(req);

	(void)user;

	/* This example only implements Disconnect-Request; CoA-Request
	 * (session attribute changes) is not applied, so it must be NAKed
	 * rather than ACKed -- a CoA-ACK asserts the change was applied. */
	if (radcli_dae_req_code(req) != RADCLI_DISCONNECT_REQUEST) {
		radcli_dae_reply_error(req, RADCLI_ERROR_UNSUPPORTED_SERVICE);
		radcli_dae_request_free(req);
		return;
	}

	printf("Disconnect-Request for user '%s', session '%s'\n",
	       user_name ? user_name : "?", session_id ? session_id : "?");

	radcli_dae_reply(req, 1);
	radcli_dae_request_free(req);
}

int
main (int argc, char **argv)
{
	radcli_ctx	*ctx;
	radcli_dae	*dae = NULL;
	radcli_avp_list *send = NULL;
	radcli_request  *r;
	int		result = 1;

	openlog("my-prog-name", LOG_PID, LOG_DAEMON);

	ctx = radcli_ctx_read_config(RC_CONFIG_FILE, 0);
	if (ctx == NULL)
		return 1;

	dae = radcli_dae_new(ctx, 0);
	if (dae == NULL) {
		fprintf(stderr, "dynamic authorization is not enabled or is "
				"misconfigured (check dae-accept/dae-server/dae-secret)\n");
		radcli_ctx_free(ctx);
		return 1;
	}
	radcli_dae_set_handler(dae, handle_dae_request, NULL);
	if (radcli_dae_start(dae) != 0) {
		fprintf(stderr, "cannot start the DAE listener\n");
		radcli_dae_free(dae);
		radcli_ctx_free(ctx);
		return 1;
	}

	send = radcli_avp_list_new();
	radcli_avp_add_str_by_num(send, ctx, PW_USER_NAME, 0, "my-username");
	radcli_avp_add_str_by_num(send, ctx, PW_USER_PASSWORD, 0, "my-password");
	radcli_avp_add_uint32_by_num(send, ctx, PW_SERVICE_TYPE, 0, PW_AUTHENTICATE_ONLY);

	if (radcli_avp_list_error(send)) {
		fprintf(stderr, "error constructing the Access-Request\n");
		radcli_avp_list_free(send);
		radcli_ctx_free(ctx);
		return 1;
	}

	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send);
	radcli_avp_list_free(send);
	if (r == NULL) {
		radcli_ctx_free(ctx);
		return 1;
	}

	if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK) {
		fprintf(stderr, "cannot send the Access-Request\n");
		radcli_request_free(r);
		radcli_ctx_free(ctx);
		return 1;
	}

	/* Single main loop, from the very first iteration: services the
	 * pending Access-Request (r) alongside the already-running watchdog
	 * and DAE listener (dae) */
	for (;;) {
		struct pollfd pfds[2];
		int nfds = 0;
		int ctx_fd, ctx_idx = -1, req_idx = -1;
		unsigned ctx_events;
		int ctx_timeout_ms, req_timeout_ms = -1, timeout_ms;
		int ret;

		if (radcli_ctx_get_poll(ctx, &ctx_fd, &ctx_events, &ctx_timeout_ms) != 0)
			break;

		if (ctx_fd != -1) {
			pfds[nfds].fd = ctx_fd;
			pfds[nfds].events = (short)ctx_events;
			pfds[nfds].revents = 0;
			ctx_idx = nfds++;
		}

		if (r != NULL) {
			int rfd = radcli_request_fd(r);

			req_timeout_ms = radcli_request_timeout_ms(r);

			if (rfd != -1 && rfd == ctx_fd) {
				req_idx = ctx_idx; /* same fd -- see comment above */
			} else if (rfd != -1) {
				pfds[nfds].fd = rfd;
				pfds[nfds].events = radcli_request_poll_events(r);
				pfds[nfds].revents = 0;
				req_idx = nfds++;
			}
		}

		if (nfds == 0)
			break; /* nothing left to wait on */

		timeout_ms = ctx_timeout_ms;
		if (r != NULL &&
		    (timeout_ms < 0 || (req_timeout_ms >= 0 && req_timeout_ms < timeout_ms)))
			timeout_ms = req_timeout_ms;

		ret = poll(pfds, (nfds_t)nfds, timeout_ms);
		if (ret < 0) {
			/* EINTR (e.g. a signal the embedding application handles)
			 * is not a timeout: retry rather than misfiring the
			 * watchdog or the request's retransmit. Any other errno
			 * is a genuine poll() failure. */
			if (errno == EINTR)
				continue;
			break;
		}

		if (r != NULL) {
			int fd_ready = req_idx >= 0 && ret > 0 &&
				       (pfds[req_idx].revents & radcli_request_poll_events(r)) != 0;
			int rc = radcli_request_wait(r, fd_ready);

			if (rc != RADCLI_AGAIN) {
				if (rc == RADCLI_OK && radcli_request_code(r) == RADCLI_CODE_ACCESS_ACCEPT) {
					fprintf(stderr, "\"my-username\" RADIUS Authentication OK\n");
					print_reply(ctx, radcli_request_attrs(r));
					result = 0;
				} else {
					fprintf(stderr, "\"my-username\" RADIUS Authentication failure\n");
				}
				radcli_request_free(r);
				r = NULL;
			}
		}

		if (ctx_idx >= 0) {
			int ctx_fd_ready = ret > 0 &&
					   (pfds[ctx_idx].revents & pfds[ctx_idx].events) != 0;

			if (ctx_fd_ready)
				radcli_ctx_dispatch(ctx);
			else if (ret == 0 && timeout_ms == ctx_timeout_ms)
				/* The overall poll() timeout used this round was
				 * ctx's own deadline (not r's shorter one, if any),
				 * so it is ctx's watchdog that is actually due. */
				radcli_ctx_send_watchdog(ctx);
		}
	}

	if (dae != NULL)
		radcli_dae_free(dae);
	if (r != NULL)
		radcli_request_free(r);
	radcli_ctx_free(ctx);

	return result;
}
