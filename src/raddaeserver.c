/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
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

/** @file raddaeserver.c
 * @brief A runnable RFC 5176 dynamic-authorization (CoA/Disconnect) server,
 *  built entirely on radcli2.h's public API: radcli_dae_new()/_set_handler()/
 *  _start(), a plain poll() loop driven by radcli_ctx_get_poll(), and
 *  radcli_ctx_dispatch() to validate and deliver each request to the handler
 *  below, which prints it and answers.
 */

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <poll.h>
#include <arpa/inet.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>

static int opt_nak = 0;
static uint32_t opt_error_cause = 0;
static int opt_no_reply = 0;
static int opt_verbose = 0;

static void print_attrs(const radcli_avp_list *attrs)
{
	const radcli_avp *a;
	radcli_avp_iter it = radcli_avp_list_iter(attrs);

	while ((a = radcli_avp_iter_next(&it)) != NULL) {
		const radcli_attr_def *def = radcli_avp_def(a);
		const char *name = radcli_attr_def_name(def);

		switch (radcli_attr_def_type(def)) {
		case RADCLI_TYPE_INTEGER:
		case RADCLI_TYPE_DATE: {
			uint32_t v;
			if (radcli_avp_get_uint32(a, &v) == 0)
				printf("\t%s = %u\n", name, (unsigned)v);
			break;
		}
		case RADCLI_TYPE_IPADDR: {
			uint32_t v;
			if (radcli_avp_get_uint32(a, &v) == 0) {
				struct in_addr ia;
				ia.s_addr = htonl(v);
				printf("\t%s = %s\n", name, inet_ntoa(ia));
			}
			break;
		}
		case RADCLI_TYPE_IPV6ADDR:
		case RADCLI_TYPE_IPV6PREFIX: {
			struct in6_addr v6;
			unsigned prefix;
			char buf[INET6_ADDRSTRLEN];
			if (radcli_avp_get_ip6(a, &v6, &prefix) == 0 &&
			    inet_ntop(AF_INET6, &v6, buf, sizeof(buf)) != NULL)
				printf("\t%s = %s\n", name, buf);
			break;
		}
		case RADCLI_TYPE_INTEGER64: {
			uint64_t v;
			if (radcli_avp_get_uint64(a, &v) == 0)
				printf("\t%s = %llu\n", name, (unsigned long long)v);
			break;
		}
		case RADCLI_TYPE_STRING:
		default: {
			const void *val;
			size_t len;
			if (radcli_avp_get_bytes(a, &val, &len) == 0)
				printf("\t%s = %.*s\n", name, (int)len, (const char *)val);
			break;
		}
		}
	}
}

static void handle_request(radcli_dae_request *req, void *user)
{
	radcli_code code = radcli_dae_req_code(req);
	const char *sid, *user_name;

	(void)user;

	printf("%s request:\n", code == RADCLI_DISCONNECT_REQUEST ? "Disconnect" : "CoA");
	print_attrs(radcli_dae_req_attrs(req));

	if (opt_verbose) {
		sid = radcli_dae_req_session_id(req);
		user_name = radcli_dae_req_user_name(req);
		if (sid != NULL)
			printf("  (session-id: %s)\n", sid);
		if (user_name != NULL)
			printf("  (user-name: %s)\n", user_name);
	}

	if (opt_no_reply) {
		printf("(not replying)\n");
	} else if (opt_nak) {
		printf("(sending NAK, Error-Cause %u)\n", (unsigned)opt_error_cause);
		radcli_dae_reply_error(req, opt_error_cause);
	} else {
		printf("(sending ACK)\n");
		radcli_dae_reply(req, 1);
	}

	radcli_dae_request_free(req);
}

static void usage(void)
{
	fprintf(stderr,
		"usage: raddaeserver [-f config_file] [--nak[=error-cause]] [--no-reply] [-v]\n");
	exit(1);
}

int main(int argc, char **argv)
{
	const char *config_file = RC_CONFIG_FILE;
	rc_handle *rh;
	radcli_dae *dae;
	int i;

	setvbuf(stdout, NULL, _IOLBF, 0); /* so a log-tailing reader sees each request promptly */
	openlog("raddaeserver", LOG_PID, LOG_DAEMON);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
			config_file = argv[++i];
		} else if (strcmp(argv[i], "--no-reply") == 0) {
			opt_no_reply = 1;
		} else if (strncmp(argv[i], "--nak", 5) == 0) {
			opt_nak = 1;
			if (argv[i][5] == '=')
				opt_error_cause = (uint32_t)strtoul(argv[i] + 6, NULL, 10);
		} else if (strcmp(argv[i], "-v") == 0) {
			opt_verbose = 1;
		} else {
			usage();
		}
	}

	rh = rc_read_config(config_file);
	if (rh == NULL) {
		fprintf(stderr, "raddaeserver: cannot read config %s\n", config_file);
		return 1;
	}

	dae = radcli_dae_new(rh, 0);
	if (dae == NULL) {
		fprintf(stderr, "raddaeserver: dynamic authorization is not enabled or is "
				"misconfigured (check dae-accept/dae-server/dae-secret)\n");
		rc_destroy(rh);
		return 1;
	}
	radcli_dae_set_handler(dae, handle_request, NULL);
	if (radcli_dae_start(dae) != 0) {
		fprintf(stderr, "raddaeserver: cannot start the listener\n");
		radcli_dae_free(dae);
		rc_destroy(rh);
		return 1;
	}

	printf("raddaeserver: listening\n");

	for (;;) {
		struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
		size_t nfds;
		int timeout_ms;

		if (radcli_ctx_get_poll(rh, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) != 0)
			break;
		if (nfds == 0)
			break;

		if (poll(pfds, (nfds_t)nfds, timeout_ms) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		radcli_ctx_dispatch(rh);
	}

	radcli_dae_free(dae);
	rc_destroy(rh);
	return 0;
}
