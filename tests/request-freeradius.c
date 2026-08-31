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
 *   3. A fire-and-forget Accounting-Request via radcli_request_perform()
 *      with RADCLI_REQUEST_SENDONLY, freed without ever calling
 *      radcli_request_wait(), for a User-Name unique to this check
 *      (NOREPLY_USER below). This process itself never reads a reply --
 *      that is the point of using SENDONLY this way -- so it cannot
 *      confirm server-side receipt on its own; instead,
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
 *   5. The same Access-Request as check 1, but sent with
 *      RADCLI_REQUEST_SENDONLY and its reply read back via
 *      radcli_request_fd()/_poll_events()/_timeout_ms()/_wait(), driven by
 *      a real poll() loop -- proving the poll-driven async path decodes a
 *      real server's Access-Accept identically to the blocking path in
 *      check 1, not merely that it doesn't crash against a synthetic or
 *      unreachable server (tests/request.c's own async coverage, which
 *      needs no server, only exercises the timeout path).
 *   6. An Access-Request for "test-crypto" (tests/raddb/users), whose
 *      Access-Accept carries Tunnel-Password/MS-MPPE-Send-Key/-Recv-Key --
 *      salt-encrypted attributes (RFC 2868 SS3.5) that need the shared
 *      secret to decrypt. tests/avp-codec-freeradius.c already proves
 *      radcli_avp_decode() itself reverses this correctly when called
 *      directly with the real secret; this check instead goes through
 *      radcli_request_perform(r, 0) -- the actual public entry point an
 *      application uses -- and is a regression test for a bug found while
 *      building the async path above: radcli_request_perform() passes
 *      r->secret *by reference* through radcli_do_exchange() into
 *      radcli_transport_exchange(), which zeroes it (the same memory,
 *      since C passes arrays by pointer) at its `cleanup:` label before
 *      returning -- on every outcome, including a successful one -- so by
 *      the time radcli_request_perform() reaches its own
 *      radcli_avp_decode(r->rh, r->secret, ...) call a few lines later,
 *      r->secret is already all-zero. Attributes needing no secret decode
 *      fine regardless (checks 1/2/4/5 above never caught this); a
 *      salt-encrypted one decodes to garbage instead of the real
 *      plaintext. This check is expected to FAIL until that is fixed.
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli2.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>

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
	radcli_ctx *ctx;
	const char *server_ip = "127.0.0.1";
	char authserver[128], acctserver[128];
	const radcli_attr_def *d_user, *d_pass, *d_ip, *d_acct_status;
	radcli_avp_list *send_list;
	radcli_request *r;

	if (argc > 1)
		server_ip = argv[1];

	openlog("request-freeradius", LOG_PID | LOG_PERROR, LOG_USER);

	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	if (ctx == NULL)
		die("radcli_ctx_new");

	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_TIMEOUT, 5) != 0)
		die("radcli_ctx_set_opt_int(radius_timeout)");
	if (radcli_ctx_set_opt_int(ctx, RADCLI_OPT_RADIUS_RETRIES, 2) != 0)
		die("radcli_ctx_set_opt_int(radius_retries)");

	snprintf(authserver, sizeof(authserver), "%s:1812:testing123", server_ip);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_AUTHSERVER, authserver) != 0)
		die("radcli_ctx_set_opt_str(authserver)");
	snprintf(acctserver, sizeof(acctserver), "%s:1813:testing123", server_ip);
	if (radcli_ctx_set_opt_str(ctx, RADCLI_OPT_ACCTSERVER, acctserver) != 0)
		die("radcli_ctx_set_opt_str(acctserver)");

	if (radcli_ctx_apply(ctx) != 0)
		die("radcli_ctx_apply");
	if (radcli_ctx_read_dictionary(ctx, "../etc/dictionary") != 0)
		die("radcli_ctx_read_dictionary(../etc/dictionary)");

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

	if (radcli_request_perform(r, 0) != RADCLI_OK)
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

	if (radcli_request_perform(r, 0) != RADCLI_OK)
		die("radcli_request_perform did not return RADCLI_OK for the Accounting-Request");
	if (radcli_request_code(r) != RADCLI_CODE_ACCOUNTING_RESPONSE) {
		fprintf(stderr, "error: expected RADCLI_CODE_ACCOUNTING_RESPONSE, got %d\n",
			(int)radcli_request_code(r));
		exit(1);
	}
	radcli_request_free(r);
	printf("OK: Accounting-Request/Accounting-Response through radcli_request_perform()\n");

	/* --- 3: a fire-and-forget Accounting-Request; see the check 3 note in
	 * the file comment above for how this is actually verified --- */

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
		die("radcli_request_new(RADCLI_CODE_ACCOUNTING_REQUEST) for the fire-and-forget check");

	if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
		die("radcli_request_perform(RADCLI_REQUEST_SENDONLY) did not return RADCLI_OK");
	radcli_request_free(r); /* fire-and-forget: radcli_request_wait() never called */
	printf("OK: radcli_request_perform(RADCLI_REQUEST_SENDONLY) transmitted the fire-and-forget Accounting-Request\n");

	/* --- 4: the Gigawords helper -- an Acct-Input-Octets/-Gigawords pair
	 * built by radcli_avp_add_gigawords64() for a value over 2^32 is
	 * accepted by a real server, not just self-consistent with this
	 * implementation's own decoder --- */

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

		if (radcli_request_perform(r, 0) != RADCLI_OK)
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

	/* --- 5: the poll-driven async path against a real server -- see the
	 * check 5 note in the file comment above --- */

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
		die("radcli_request_new(RADCLI_CODE_ACCESS_REQUEST) for the async check");

	if (radcli_request_perform(r, RADCLI_REQUEST_SENDONLY) != RADCLI_OK)
		die("radcli_request_perform(RADCLI_REQUEST_SENDONLY) did not return RADCLI_OK "
		    "for the async round trip");

	{
		int rc;

		for (;;) {
			struct pollfd pfd;

			pfd.fd = radcli_request_fd(r);
			pfd.events = radcli_request_poll_events(r);
			pfd.revents = 0;
			if (pfd.fd < 0)
				die("radcli_request_fd() returned -1 while the async "
				    "exchange was still in progress");

			poll(&pfd, 1, radcli_request_timeout_ms(r));

			rc = radcli_request_wait(r, (pfd.revents & pfd.events) != 0);
			if (rc != RADCLI_AGAIN)
				break;
		}

		if (rc != RADCLI_OK)
			die("radcli_request_wait() did not return RADCLI_OK for the async "
			    "Access-Request/Access-Accept round trip");
	}

	if (radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "error: async path: expected RADCLI_CODE_ACCESS_ACCEPT, got %d\n",
			(int)radcli_request_code(r));
		exit(1);
	}
	{
		const radcli_avp_list *reply = radcli_request_attrs(r);
		const radcli_avp *a = radcli_avp_get(reply, d_ip, 0);
		uint32_t ip;

		if (a == NULL || radcli_avp_get_uint32(a, &ip) != 0)
			die("async path: Framed-IP-Address missing from a real Access-Accept");
		if (ip != ((192u << 24) | (168u << 16) | (1u << 8) | 190u)) {
			fprintf(stderr, "error: async path: Framed-IP-Address decoded as 0x%08x, "
					"expected 192.168.1.190\n", ip);
			exit(1);
		}
	}
	radcli_request_free(r);
	printf("OK: async Access-Request/Access-Accept via radcli_request_fd()/_wait()\n");

	/* --- 6: r->secret-zeroed-before-decode regression check -- see the
	 * check 6 note in the file comment above --- */

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str(send_list, d_user, "test-crypto") != 0)
		die("radcli_avp_add_str(User-Name)");
	if (radcli_avp_add_str(send_list, d_pass, "test") != 0)
		die("radcli_avp_add_str(User-Password)");

	r = radcli_request_new(ctx, RADCLI_CODE_ACCESS_REQUEST, send_list);
	radcli_avp_list_free(send_list);
	if (r == NULL)
		die("radcli_request_new(RADCLI_CODE_ACCESS_REQUEST) for the secret-zeroing check");

	if (radcli_request_perform(r, 0) != RADCLI_OK)
		die("radcli_request_perform did not return RADCLI_OK for user \"test-crypto\"");
	if (radcli_request_code(r) != RADCLI_CODE_ACCESS_ACCEPT) {
		fprintf(stderr, "error: expected RADCLI_CODE_ACCESS_ACCEPT for \"test-crypto\", got %d\n",
			(int)radcli_request_code(r));
		exit(1);
	}
	{
		static const struct { const char *name; const char *want; } checks[] = {
			{ "Tunnel-Password",  "tunnel-secret" },
			{ "MS-MPPE-Send-Key", "0123456789abcdef0123456789abcdef" },
			{ "MS-MPPE-Recv-Key", "fedcba9876543210fedcba9876543210" },
		};
		const radcli_avp_list *reply = radcli_request_attrs(r);
		size_t i;

		for (i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
			const radcli_attr_def *d = radcli_dict_lookup(ctx, checks[i].name);
			const radcli_avp *a = radcli_avp_get(reply, d, 0);
			const void *raw;
			size_t rawlen;
			size_t wantlen = strlen(checks[i].want);

			if (d == NULL) {
				fprintf(stderr, "error: %s not in the loaded dictionary\n",
					checks[i].name);
				exit(1);
			}
			if (a == NULL || radcli_avp_get_bytes(a, &raw, &rawlen) != 0) {
				fprintf(stderr, "error: %s missing from the Access-Accept\n",
					checks[i].name);
				exit(1);
			}
			if (rawlen != wantlen || memcmp(raw, checks[i].want, wantlen) != 0) {
				fprintf(stderr, "error: %s decrypted to the wrong plaintext via "
						"radcli_request_perform() (%zu bytes, expected %zu) "
						"-- r->secret was zeroed before radcli_avp_decode() "
						"was called; see this file's header comment, check 6\n",
					checks[i].name, rawlen, wantlen);
				exit(1);
			}
			printf("OK: %s decrypted correctly through radcli_request_perform()\n",
			       checks[i].name);
		}
	}
	radcli_request_free(r);

	radcli_ctx_free(ctx);

	printf("radcli2 request/reply / FreeRADIUS interoperability: all checks passed\n");
	return 0;
}
