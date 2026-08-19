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

/* rc_auth()/rc_send_server_ctx() now build the wire packet via
 * radcli_avp_encode_rfc2865() (lib/avp.c) instead of rc_pack_list()
 * (lib/sendserver.c). Per RFC 2865 SS5.2, User-Password is encrypted in
 * AUTH_VECTOR_LEN (16)-octet blocks up to AUTH_PASS_LEN (128) octets; that
 * encoder rejects a value longer than AUTH_PASS_LEN outright instead of
 * silently truncating it to a different, shorter password the caller never
 * asked to send. This is checked here without any real network I/O: packet
 * encoding -- where the rejection happens -- runs before rc_send_server_ctx()
 * ever touches a socket, so an unreachable server address is enough; the
 * call must fail immediately rather than waiting out radius_timeout. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/time.h>

#include <radcli/radcli.h>

static double test_mtime(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0;
}

static char test_dict[] =
"ATTRIBUTE	User-Name		1	string\n"
"ATTRIBUTE	User-Password		2	string\n";

int main(int argc, char **argv)
{
	rc_handle *rh;
	VALUE_PAIR *send = NULL, *received = NULL;
	char msg[PW_MAX_MSG_SIZE];
	char toolong[AUTH_PASS_LEN + 1];
	double start, elapsed;
	int ret;

	rh = rc_new();
	assert(rh != NULL);
	rc_config_init(rh);
	assert(rc_read_dictionary_from_buffer(rh, test_dict, sizeof(test_dict)) == 0);

	assert(rc_add_config(rh, "radius_timeout", "5", "config", 0) == 0);
	assert(rc_add_config(rh, "radius_retries", "0", "config", 0) == 0);
	/* 192.0.2.1 is TEST-NET-1 (RFC 5737): reserved, never routed. If the
	 * over-length password were not caught before the socket is used,
	 * this test would hang for radius_timeout seconds instead of failing
	 * immediately. */
	assert(rc_add_config(rh, "authserver", "192.0.2.1:1812:testing123", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);

	assert(rc_avpair_add(rh, &send, 1, "alice", -1, 0) != NULL);

	memset(toolong, 'A', sizeof(toolong));
	toolong[sizeof(toolong) - 1] = '\0';
	assert(rc_avpair_add(rh, &send, 2, toolong, -1, 0) != NULL);

	start = test_mtime();
	ret = rc_auth(rh, 0, send, &received, msg);
	elapsed = test_mtime() - start;

	if (ret != ERROR_RC) {
		fprintf(stderr, "error: rc_auth() with an over-length User-Password "
				"returned %d, expected ERROR_RC (%d)\n", ret, ERROR_RC);
		exit(1);
	}
	if (elapsed >= 1.0) {
		fprintf(stderr, "error: rc_auth() took %.2fs to reject the over-length "
				"User-Password -- expected an immediate, pre-network failure\n",
			elapsed);
		exit(1);
	}
	if (received != NULL) {
		fprintf(stderr, "error: rc_auth() set *received on failure\n");
		exit(1);
	}

	rc_avpair_free(send);
	rc_dict_free(rh);
	rc_destroy(rh);

	return 0;
}
