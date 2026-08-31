/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 * Copyright (C) 2015,2026 Nikos Mavrogiannopoulos
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 *
 */

/** @file radexample.c
 * @brief Minimal example of using the radcli2.h library for authentication.
 */

#include	<config.h>
#include	<stdio.h>
#include	<syslog.h>
#include	<arpa/inet.h>
#include	<radcli/radcli2.h>

/* As in a real client (e.g. ocserv's src/auth/radius.c), the attributes a
 * reply may usefully carry are known ahead of time -- each looked up
 * directly by its PW_* ID and read back with the typed accessor matching
 * its radcli_attr_def_type(), rather than dumping the whole reply generically. */
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

int
main (int argc, char **argv)
{
	int             result = 1;
	radcli_ctx	*ctx;
	radcli_avp_list *send = NULL;
	radcli_request  *r;

	/* openlog() sets the syslog identity used by radcli's internal messages */
	openlog("my-prog-name", LOG_PID, LOG_DAEMON);

	if ((ctx = radcli_ctx_read_config(RC_CONFIG_FILE, 0)) == NULL)
		return 1;

	send = radcli_avp_list_new();
	if (send == NULL) {
		radcli_ctx_free(ctx);
		return 1;
	}

	/*
	 * Fill in User-Name, User-Password, Service-Type. Each add is
	 * independent -- radcli_avp_list_error() below is one aggregate
	 * check for all of them, instead of chaining "!= 0 || ... != 0"
	 * across every call or repeating a check-and-bail block after each.
	 */
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

	if (radcli_request_perform(r, 0) == RADCLI_OK &&
	    radcli_request_code(r) == RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "\"my-username\" RADIUS Authentication OK\n");
		print_reply(ctx, radcli_request_attrs(r));
		result = 0;
	} else {
		fprintf(stderr, "\"my-username\" RADIUS Authentication failure\n");
	}

	radcli_request_free(r);
	radcli_ctx_free(ctx);

	return result;
}
