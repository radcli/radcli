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
 */

/* Interoperability check for the radcli2.h wire codec against a real
 * FreeRADIUS server (driven by tests/avp-codec-freeradius-tests.sh, which
 * needs root and a real radiusd/freeradius binary -- see tests/ns.sh).
 *
 * This does not go through any of radcli's own transport code: it builds
 * and parses RADIUS packets by hand with radcli_avp_encode_rfc2865()/_decode()
 * (internal, reached via libradcli_static, as tests/avp-codec.c already
 * does) over a plain UDP socket, so that the codec's output is judged by
 * an independent RADIUS implementation rather than only by radcli itself.
 *
 * Two requests are sent:
 *   1. User-Name/User-Password for the "test" user already used by the
 *      other tests in this directory (tests/raddb/users), checking that
 *      RFC 2865 5.2 User-Password encryption produces ciphertext a real
 *      server accepts, and that the Access-Accept's other reply
 *      attributes decode correctly.
 *   2. User-Name/User-Password for "test-crypto" (tests/raddb/users),
 *      whose Access-Accept carries Tunnel-Password and MS-MPPE-Send-Key/
 *      Recv-Key reply attributes, checking that radcli_avp_decode()
 *      correctly reverses FreeRADIUS's own RFC 2868/2548 salt-encryption
 *      -- ciphertext this implementation did not produce itself. */

#include <config.h>
#include <avp.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "rc-md5.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define SERVER_PORT 1812
#define SECRET "testing123"
#define RECV_TIMEOUT_SEC 5

static void die(const char *msg)
{
	fprintf(stderr, "error: %s\n", msg);
	exit(1);
}

static void die_errno(const char *msg)
{
	fprintf(stderr, "error: %s: %s\n", msg, strerror(errno));
	exit(1);
}

/* Sends a PAP Access-Request for username/password and returns the
 * decoded reply attributes in *reply (caller frees). request_authenticator
 * (16 bytes) is filled in with the value actually sent, needed by the
 * caller to decode any reply attribute that is itself salt-encrypted. */
static int do_auth(int sock, struct sockaddr_in *server, radcli_ctx *ctx,
		   const char *username, const char *password,
		   unsigned char request_authenticator[AUTH_VECTOR_LEN],
		   radcli_avp_list **reply)
{
	const radcli_attr_def *d_user, *d_pass;
	radcli_avp_list *send_list;
	uint8_t packet[RC_MAX_PACKET_LEN];
	uint8_t response[RC_MAX_PACKET_LEN];
	int attrlen, packet_len;
	uint16_t total_len;
	ssize_t n;
	socklen_t fromlen;
	struct sockaddr_in from;
	uint8_t computed_resp_auth[AUTH_VECTOR_LEN];
	unsigned char md5in[RC_MAX_PACKET_LEN + MAX_SECRET_LENGTH];
	size_t md5in_len;
	uint16_t resp_len;

	d_user = radcli_dict_lookup(ctx, "User-Name");
	d_pass = radcli_dict_lookup(ctx, "User-Password");
	if (d_user == NULL || d_pass == NULL)
		die("User-Name/User-Password not in the loaded dictionary");

	send_list = radcli_avp_list_new();
	if (send_list == NULL)
		die("radcli_avp_list_new");
	if (radcli_avp_add_str(send_list, d_user, username) != 0)
		die("radcli_avp_add_str(User-Name)");

	if (getentropy(request_authenticator, AUTH_VECTOR_LEN) != 0)
		die_errno("getentropy");

	if (radcli_avp_add_str(send_list, d_pass, password) != 0)
		die("radcli_avp_add_str(User-Password)");

	{
		size_t n_enc = 0;

		attrlen = radcli_avp_encode_rfc2865(ctx, send_list, SECRET, request_authenticator,
					    packet + AUTH_HDR_LEN, sizeof(packet) - AUTH_HDR_LEN, &n_enc);
		if (attrlen < 0)
			die("radcli_avp_encode_rfc2865");
		if (n_enc != 1)
			die("radcli_avp_encode_rfc2865: expected exactly one RFC 2865 SS5.2 "
			    "encrypted attribute (User-Password) -- etc/dictionary may be "
			    "missing its encrypt=User-Password flag");
	}
	radcli_avp_list_free(send_list);

	packet[0] = 1; /* Access-Request */
	packet[1] = 42; /* Identifier */
	total_len = (uint16_t)(AUTH_HDR_LEN + attrlen);
	packet[2] = (uint8_t)(total_len >> 8);
	packet[3] = (uint8_t)(total_len & 0xff);
	memcpy(packet + 4, request_authenticator, AUTH_VECTOR_LEN);
	packet_len = total_len;

	if (sendto(sock, packet, (size_t)packet_len, 0,
		  (struct sockaddr *)server, sizeof(*server)) != packet_len)
		die_errno("sendto");

	fromlen = sizeof(from);
	n = recvfrom(sock, response, sizeof(response), 0, (struct sockaddr *)&from, &fromlen);
	if (n < 0)
		die_errno("recvfrom (is radiusd running and reachable?)");
	if (n < AUTH_HDR_LEN)
		die("reply shorter than a RADIUS header");

	resp_len = (uint16_t)((response[2] << 8) | response[3]);
	if (resp_len < AUTH_HDR_LEN || resp_len > n)
		die("reply declares an invalid length");
	if (response[1] != packet[1])
		die("reply Identifier does not match the request");

	/* Response Authenticator = MD5(code + id + length + request
	 * authenticator + reply attributes + secret), RFC 2865 SS3. */
	md5in_len = 0;
	memcpy(md5in, response, 4);
	md5in_len += 4;
	memcpy(md5in + md5in_len, request_authenticator, AUTH_VECTOR_LEN);
	md5in_len += AUTH_VECTOR_LEN;
	memcpy(md5in + md5in_len, response + AUTH_HDR_LEN, (size_t)resp_len - AUTH_HDR_LEN);
	md5in_len += (size_t)resp_len - AUTH_HDR_LEN;
	memcpy(md5in + md5in_len, SECRET, strlen(SECRET));
	md5in_len += strlen(SECRET);
	rc_md5_calc(computed_resp_auth, md5in, md5in_len);
	if (memcmp(computed_resp_auth, response + 4, AUTH_VECTOR_LEN) != 0)
		die("reply Response Authenticator does not verify -- reply is "
		    "not genuine, or the shared secret does not match tests/raddb");

	if (radcli_avp_decode(ctx, SECRET, request_authenticator,
			      response + AUTH_HDR_LEN, (size_t)resp_len - AUTH_HDR_LEN,
			      0, reply) != 0)
		die("radcli_avp_decode of the reply failed");

	return response[0]; /* reply code: 2 Access-Accept, 3 Access-Reject */
}

int main(int argc, char **argv)
{
	rc_handle *rh;
	radcli_ctx *ctx;
	int sock;
	struct sockaddr_in server;
	struct timeval tv;
	const char *server_ip = "127.0.0.1";
	unsigned char req_auth[AUTH_VECTOR_LEN];
	radcli_avp_list *reply;
	int code;

	if (argc > 1)
		server_ip = argv[1];

	/* rc_log() is just syslog(): without LOG_PERROR, any error radcli
	 * logs internally (a dictionary parse failure, in particular) goes
	 * to the system journal and never appears in this program's own
	 * output or in "meson test"'s captured log. */
	openlog("avp-codec-freeradius", LOG_PID | LOG_PERROR, LOG_USER);

	rh = rc_new();
	if (rh == NULL)
		die("rc_new");
	rc_config_init(rh);
	if (rc_read_dictionary(rh, "../etc/dictionary") != 0)
		die("rc_read_dictionary(../etc/dictionary)");
	ctx = rh;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
		die_errno("socket");
	tv.tv_sec = RECV_TIMEOUT_SEC;
	tv.tv_usec = 0;
	if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0)
		die_errno("setsockopt(SO_RCVTIMEO)");

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_port = htons(SERVER_PORT);
	if (inet_pton(AF_INET, server_ip, &server.sin_addr) != 1)
		die("invalid server address");

	/* --- 1: plain PAP auth, verifies User-Password encryption is
	 * accepted by a real server and the reply decodes correctly --- */
	code = do_auth(sock, &server, ctx, "test", "test", req_auth, &reply);
	if (code != 2) {
		fprintf(stderr, "error: expected Access-Accept (2) for user "
				"\"test\", got code %d\n", code);
		exit(1);
	}
	{
		const radcli_attr_def *d_ip = radcli_dict_lookup(ctx, "Framed-IP-Address");
		const radcli_avp *a = radcli_avp_get(reply, d_ip, 0);
		uint32_t ip;

		if (a == NULL || radcli_avp_get_uint32(a, &ip) != 0) {
			fprintf(stderr, "error: Framed-IP-Address missing from a "
					"real Access-Accept\n");
			exit(1);
		}
		/* tests/raddb/users: Framed-IP-Address = 192.168.1.190 */
		if (ip != ((192u << 24) | (168u << 16) | (1u << 8) | 190u)) {
			fprintf(stderr, "error: Framed-IP-Address decoded as "
					"0x%08x, expected 192.168.1.190\n", ip);
			exit(1);
		}
	}
	radcli_avp_list_free(reply);
	printf("OK: User-Password encryption accepted, plain reply decoded correctly\n");

	/* --- 2: a server-generated Tunnel-Password/MS-MPPE-*-Key reply,
	 * verifies radcli_avp_decode() reverses FreeRADIUS's own ciphertext,
	 * not just ciphertext this implementation produced itself --- */
	code = do_auth(sock, &server, ctx, "test-crypto", "test", req_auth, &reply);
	if (code != 2) {
		fprintf(stderr, "error: expected Access-Accept (2) for user "
				"\"test-crypto\", got code %d\n", code);
		exit(1);
	}
	{
		static const struct { const char *name; const char *want; } checks[] = {
			{ "Tunnel-Password",  "tunnel-secret" },
			{ "MS-MPPE-Send-Key", "0123456789abcdef0123456789abcdef" },
			{ "MS-MPPE-Recv-Key", "fedcba9876543210fedcba9876543210" },
		};
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
				fprintf(stderr, "error: %s decrypted to the wrong plaintext "
						"(%zu bytes, expected %zu) -- radcli's "
						"salt-decryption does not agree with a real "
						"FreeRADIUS server's salt-encryption\n",
					checks[i].name, rawlen, wantlen);
				exit(1);
			}
			printf("OK: %s decrypted correctly against a real "
			       "FreeRADIUS-generated ciphertext\n", checks[i].name);
		}
	}
	radcli_avp_list_free(reply);

	close(sock);
	rc_dict_free(rh);
	rc_destroy(rh);

	printf("radcli2 avp codec / FreeRADIUS interoperability: all checks passed\n");
	return 0;
}
