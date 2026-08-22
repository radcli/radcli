/*
 * Copyright (c) 2026, Nikos Mavrogiannopoulos.  All rights reserved.
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
 *
 * Interoperability check for radcli2.h's request/reply entry point
 * (radcli_request_new()/_perform()/etc., lib/request.c) against a real
 * FreeRADIUS server (driven by tests/request-freeradius-tests.sh, which
 * needs root and a real radiusd/freeradius binary -- see tests/ns.sh).
 *
 * Unlike tests/avp-codec-freeradius.c, which builds/parses packets by hand
 * to judge the codec independently of radcli's transport, this goes
 * through the full stack an application would actually call: config ->
 * radcli_request_new() -> radcli_request_perform() -> radcli_transport_exchange()
 * -> a real UDP exchange -> radcli_request_code()/_attrs(). Two requests:
 *
 *   1. An Access-Request for the "test" user (tests/raddb/users), checking
 *      radcli_request_perform() returns RADCLI_OK, radcli_request_code()
 *      reports RADCLI_CODE_ACCESS_ACCEPT, and the reply attributes decode
 *      correctly -- exercising the random-vector + Message-Authenticator
 *      request path.
 *   2. An Accounting-Request (Acct-Status-Type = Start), checking
 *      radcli_request_code() reports RADCLI_CODE_ACCOUNTING_RESPONSE --
 *      exercising the zero-vector-then-computed-from-the-packet request
 *      path, which the Access-Request above does not.
 *   3. A no_wait Accounting-Request via radcli_request_send_noreply(), for
 *      a User-Name unique to this check (NOREPLY_USER below). This process
 *      itself never reads a reply -- that is the point of send_noreply()
 *      -- so it cannot confirm server-side receipt on its own; instead,
 *      tests/request-freeradius-tests.sh runs radiusd with its own debug
 *      trace captured to a file (tests/ns.sh's RADIUSD_LOGFILE), and greps
 *      that file for NOREPLY_USER followed by a genuine "Sent
 *      Accounting-Response", after this program exits. That is what
 *      actually proves the fire-and-forget send was received and
 *      processed by a real server, not merely handed to the local kernel.
 *   4. An Accounting-Request carrying an Acct-Input-Octets/-Gigawords pair
 *      built by radcli_avp_add_gigawords64() for a value over 2^32, checking
 *      a real server accepts it -- Phase 2's Gigawords helper is "the part
 *      that actually interoperates" precisely because no standard
 *      attribute counts octets as a genuine 64-bit integer.
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Grepped for in tests/request-freeradius-tests.sh's captured radiusd
 * debug trace -- see the check 3 note in the file comment above. Not a
 * user tests/raddb/users has an entry for: this Accounting-Request
 * carries no Cleartext-Password, so it is not an authentication attempt
 * and the username matching no "users" entry is irrelevant to it. */
#define NOREPLY_USER "radcli-noreply-interop-check"

static void die(const char *msg) __attribute__((noreturn));

static void die(const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(1);
}

int main(int argc, char **argv)
{
	rc_handle *rh;
	radcli_ctx *ctx;
	const char *server_ip = "127.0.0.1";
	char authserver[128], acctserver[128];
	const radcli_attr_def *d_user, *d_pass, *d_ip, *d_acct_status;
	radcli_avp_list *send_list;
	radcli_request *r;

	if (argc > 1)
		server_ip = argv[1];

	openlog("request-freeradius", LOG_PID | LOG_PERROR, LOG_USER);

	rh = rc_new();
	if (rh == NULL)
		die("rc_new");
	rc_config_init(rh);

	if (rc_add_config(rh, "radius_timeout", "5", "config", 0) != 0)
		die("rc_add_config(radius_timeout)");
	if (rc_add_config(rh, "radius_retries", "2", "config", 0) != 0)
		die("rc_add_config(radius_retries)");

	snprintf(authserver, sizeof(authserver), "%s:1812:testing123", server_ip);
	if (rc_add_config(rh, "authserver", authserver, "config", 0) != 0)
		die("rc_add_config(authserver)");
	snprintf(acctserver, sizeof(acctserver), "%s:1813:testing123", server_ip);
	if (rc_add_config(rh, "acctserver", acctserver, "config", 0) != 0)
		die("rc_add_config(acctserver)");

	if (rc_apply_config(rh) != 0)
		die("rc_apply_config");
	if (rc_read_dictionary(rh, "../etc/dictionary") != 0)
		die("rc_read_dictionary(../etc/dictionary)");
	ctx = rh;

	d_user = radcli_dict_lookup(ctx, "User-Name");
	d_pass = radcli_dict_lookup(ctx, "User-Password");
	d_ip = radcli_dict_lookup(ctx, "Framed-IP-Address");
	d_acct_status = radcli_dict_lookup(ctx, "Acct-Status-Type");
	if (d_user == NULL || d_pass == NULL || d_ip == NULL || d_acct_status == NULL)
		die("attribute not in the loaded dictionary");

	/* --- 1: Access-Request/Access-Accept through the full request object --- */

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str(send_list, d_user, "test") != 0)
		die("radcli_avp_add_str(User-Name)");
	if (radcli_avp_add_str(send_list, d_pass, "test") != 0)
		die("radcli_avp_add_str(User-Password)");

	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new(RADCLI_CODE_ACCESS_REQUEST)");

	if (radcli_request_perform(r) != RADCLI_OK)
		die("radcli_request_perform did not return RADCLI_OK for user \"test\"");
	if (radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "error: expected RADCLI_CODE_ACCESS_ACCEPT, got %d\n",
			(int)radcli_request_code(r));
		exit(1);
	}
	if (strcmp(radcli_request_server(r), server_ip) != 0) {
		fprintf(stderr, "error: radcli_request_server() returned \"%s\", expected \"%s\"\n",
			radcli_request_server(r), server_ip);
		exit(1);
	}
	{
		const radcli_avp_list *reply = radcli_request_attrs(r);
		const radcli_avp *a = radcli_avp_get(reply, d_ip, 0);
		uint32_t ip;

		if (a == NULL || radcli_avp_get_uint32(a, &ip) != 0)
			die("Framed-IP-Address missing from a real Access-Accept");
		/* tests/raddb/users: Framed-IP-Address = 192.168.1.190 */
		if (ip != ((192u << 24) | (168u << 16) | (1u << 8) | 190u)) {
			fprintf(stderr, "error: Framed-IP-Address decoded as 0x%08x, "
					"expected 192.168.1.190\n", ip);
			exit(1);
		}
	}
	radcli_request_free(r);
	printf("OK: Access-Request/Access-Accept through radcli_request_perform()\n");

	/* --- 2: Accounting-Request/Accounting-Response, exercising the
	 * zero-vector-then-computed-from-the-packet request path --- */

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str(send_list, d_user, "test") != 0)
		die("radcli_avp_add_str(User-Name)");
	if (radcli_avp_add_uint32(send_list, d_acct_status, 1 /* Start */) != 0)
		die("radcli_avp_add_uint32(Acct-Status-Type)");

	r = radcli_request_new(ctx, RADCLI_CODE_ACCOUNTING_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new(RADCLI_CODE_ACCOUNTING_REQUEST)");

	if (radcli_request_perform(r) != RADCLI_OK)
		die("radcli_request_perform did not return RADCLI_OK for the Accounting-Request");
	if (radcli_request_code(r) != RADCLI_CODE_ACCOUNTING_RESPONSE) {
		fprintf(stderr, "error: expected RADCLI_CODE_ACCOUNTING_RESPONSE, got %d\n",
			(int)radcli_request_code(r));
		exit(1);
	}
	radcli_request_free(r);
	printf("OK: Accounting-Request/Accounting-Response through radcli_request_perform()\n");

	/* --- 3: a no_wait Accounting-Request; see the check 3 note in the
	 * file comment above for how this is actually verified --- */

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str(send_list, d_user, NOREPLY_USER) != 0)
		die("radcli_avp_add_str(User-Name)");
	if (radcli_avp_add_uint32(send_list, d_acct_status, 1 /* Start */) != 0)
		die("radcli_avp_add_uint32(Acct-Status-Type)");

	r = radcli_request_new(ctx, RADCLI_CODE_ACCOUNTING_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new(RADCLI_CODE_ACCOUNTING_REQUEST) for the no_wait check");

	if (radcli_request_send_noreply(r) != RADCLI_OK)
		die("radcli_request_send_noreply did not return RADCLI_OK");
	radcli_request_free(r);
	printf("OK: radcli_request_send_noreply() transmitted the no_wait Accounting-Request\n");

	/* --- 4: the Gigawords helper -- an Acct-Input-Octets/-Gigawords pair
	 * built by radcli_avp_add_gigawords64() for a value over 2^32 is
	 * accepted by a real server, not just self-consistent with this
	 * implementation's own decoder ("the part that actually
	 * interoperates", per doc/plan-api-modernization.md's own framing) --- */

	{
		const radcli_attr_def *d_octets = radcli_dict_lookup(ctx, "Acct-Input-Octets");

		if (d_octets == NULL)
			die("Acct-Input-Octets not in the loaded dictionary");

		send_list = radcli_avp_list_new();
		if (send_list == NULL)
			die("radcli_avp_list_new");
		if (radcli_avp_add_str(send_list, d_user, "test") != 0)
			die("radcli_avp_add_str(User-Name)");
		if (radcli_avp_add_uint32(send_list, d_acct_status, 1 /* Start */) != 0)
			die("radcli_avp_add_uint32(Acct-Status-Type)");
		if (radcli_avp_add_gigawords64(ctx, send_list, d_octets, UINT64_C(5000000000)) != 0)
			die("radcli_avp_add_gigawords64(Acct-Input-Octets)");

		r = radcli_request_new(ctx, RADCLI_CODE_ACCOUNTING_REQUEST, send_list);
		radcli_avp_list_free(send_list);
		if (r == NULL)
			die("radcli_request_new(RADCLI_CODE_ACCOUNTING_REQUEST) for the Gigawords check");

		if (radcli_request_perform(r) != RADCLI_OK)
			die("radcli_request_perform did not return RADCLI_OK for the "
			    "Acct-Input-Octets/-Gigawords Accounting-Request");
		if (radcli_request_code(r) != RADCLI_CODE_ACCOUNTING_RESPONSE) {
			fprintf(stderr, "error: expected RADCLI_CODE_ACCOUNTING_RESPONSE, got %d\n",
				(int)radcli_request_code(r));
			exit(1);
		}
		radcli_request_free(r);
	}
	printf("OK: Acct-Input-Octets/-Gigawords (radcli_avp_add_gigawords64()) accepted by a real server\n");

	rc_dict_free(rh);
	rc_destroy(rh);

	printf("radcli2 request/reply / FreeRADIUS interoperability: all checks passed\n");
	return 0;
}
