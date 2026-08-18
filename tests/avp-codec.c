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

/* Unit test for radcli_avp_decode()/radcli_avp_encode() (lib/avp.c): the
 * radcli2.h wire codec. Both are internal-only (declared in lib/avp.h, not
 * exported), so this links against libradcli_static directly, the same
 * pattern tests/pack.c uses for rc_pack_list(). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include <includes.h>
#include "avp.h" /* radcli_avp_decode(), radcli_avp_encode() */

static char test_dict[] =
"ATTRIBUTE	User-Name		1	string\n"
"ATTRIBUTE	User-Password		2	string\n"
"ATTRIBUTE	NAS-IP-Address		4	ipaddr\n"
"ATTRIBUTE	Session-Timeout		27	integer\n"
"ATTRIBUTE	Framed-IPv6-Address	168	ipv6addr\n"
"VENDOR          DSL-Forum       3561     Large\n"
"ATTRIBUTE	Agent-Circuit-Id		1	string DSL-Forum\n";

static int avp_list_empty(const radcli_avp_list *l)
{
	radcli_avp_iter it = radcli_avp_list_iter(l);
	return radcli_avp_iter_next(&it) == NULL;
}

int main(int argc, char **argv)
{
	rc_handle *rh;
	radcli_avp_list *l, *decoded;
	const radcli_attr_def *d_user, *d_pass, *d_nasip, *d_timeout, *d_v6, *d_agent;
	uint8_t buf[512];
	int n;
	struct in_addr ia;
	struct in6_addr i6, i6out;
	unsigned prefix;
	const radcli_avp *a;
	const void *raw;
	size_t rawlen;
	uint32_t u = 0;

	rh = rc_new();
	assert(rh != NULL);
	rc_config_init(rh);
	assert(rc_read_dictionary_from_buffer(rh, test_dict, sizeof(test_dict)) == 0);

	d_user = radcli_dict_lookup(rh, "User-Name");
	d_pass = radcli_dict_lookup(rh, "User-Password");
	d_nasip = radcli_dict_lookup(rh, "NAS-IP-Address");
	d_timeout = radcli_dict_lookup(rh, "Session-Timeout");
	d_v6 = radcli_dict_lookup(rh, "Framed-IPv6-Address");
	d_agent = radcli_dict_lookup(rh, "Agent-Circuit-Id");
	assert(d_user && d_pass && d_nasip && d_timeout && d_v6 && d_agent);

	/* --- round trip: encode(list) then decode(bytes) reproduces every
	 * attribute, including a VSA, across every non-encrypted type --- */

	l = radcli_avp_list_new();
	assert(l != NULL);
	assert(radcli_avp_add_str(l, d_user, "alice") == 0);
	inet_pton(AF_INET, "192.0.2.7", &ia);
	assert(radcli_avp_add_ipaddr(l, d_nasip, ia) == 0);
	assert(radcli_avp_add_uint32(l, d_timeout, 3600) == 0);
	inet_pton(AF_INET6, "2001:db8::1", &i6);
	assert(radcli_avp_add_in6(l, d_v6, &i6, 0) == 0);
	assert(radcli_avp_add_str(l, d_agent, "circuit-42") == 0); /* VSA */

	n = radcli_avp_encode(l, buf, sizeof(buf));
	if (n <= 0) {
		fprintf(stderr, "error: radcli_avp_encode() failed (%d)\n", n);
		exit(1);
	}

	if (radcli_avp_decode(rh, buf, (size_t)n, 0, &decoded) != 0) {
		fprintf(stderr, "error: radcli_avp_decode() failed on radcli_avp_encode()'s own output\n");
		exit(1);
	}

	a = radcli_avp_get(decoded, d_user, 0);
	if (a == NULL || radcli_avp_get_bytes(a, &raw, &rawlen) != 0 ||
	    rawlen != 5 || memcmp(raw, "alice", 5) != 0) {
		fprintf(stderr, "error: User-Name did not round-trip\n");
		exit(1);
	}

	/* This is the case that caught a real bug during development: the
	 * encoder converts host->network order on write (RFC 2865), so the
	 * decoder must convert network->host on read, or an IPADDR/INTEGER/
	 * DATE attribute round-trips byte-swapped on big-endian-different
	 * pairs of calls. */
	a = radcli_avp_get(decoded, d_nasip, 0);
	if (a == NULL || radcli_avp_get_uint32(a, &u) != 0 || u != ntohl(ia.s_addr)) {
		fprintf(stderr, "error: NAS-IP-Address did not round-trip "
				"(got 0x%x, want 0x%x) -- byte-order bug\n", u, ntohl(ia.s_addr));
		exit(1);
	}

	a = radcli_avp_get(decoded, d_timeout, 0);
	if (a == NULL || radcli_avp_get_uint32(a, &u) != 0 || u != 3600) {
		fprintf(stderr, "error: Session-Timeout did not round-trip\n");
		exit(1);
	}

	a = radcli_avp_get(decoded, d_v6, 0);
	if (a == NULL || radcli_avp_get_in6(a, &i6out, &prefix) != 0 ||
	    memcmp(&i6out, &i6, 16) != 0 || prefix != 128) {
		fprintf(stderr, "error: Framed-IPv6-Address did not round-trip\n");
		exit(1);
	}

	a = radcli_avp_get(decoded, d_agent, 0);
	if (a == NULL || radcli_avp_get_bytes(a, &raw, &rawlen) != 0 ||
	    rawlen != 10 || memcmp(raw, "circuit-42", 10) != 0) {
		fprintf(stderr, "error: Agent-Circuit-Id (VSA) did not round-trip\n");
		exit(1);
	}

	radcli_avp_list_free(l);
	radcli_avp_list_free(decoded);

	/* --- decode: hard framing errors abort the whole decode --- */

	{
		radcli_avp_list *bad;
		uint8_t too_short[] = { 1 };               /* pb_len() < 2 */
		uint8_t len_lt_2[]  = { 1, 1 };             /* attrlen field < 2 */
		uint8_t overflow[]  = { 1, 10, 'a' };       /* attrlen > remaining bytes */

		if (radcli_avp_decode(rh, too_short, sizeof(too_short), 0, &bad) == 0) {
			fprintf(stderr, "error: a 1-byte attribute region was accepted\n");
			exit(1);
		}
		if (radcli_avp_decode(rh, len_lt_2, sizeof(len_lt_2), 0, &bad) == 0) {
			fprintf(stderr, "error: an attribute with length field < 2 was accepted\n");
			exit(1);
		}
		if (radcli_avp_decode(rh, overflow, sizeof(overflow), 0, &bad) == 0) {
			fprintf(stderr, "error: an attribute whose length exceeds the buffer was accepted\n");
			exit(1);
		}
	}

	/* --- decode: an unrecognised attribute/VSA is skipped, not a hard
	 * error (matches lib/avpair.c's rc_avpair_gen2() robustness) --- */

	{
		radcli_avp_list *skipped;
		/* attribute 250 is not in test_dict */
		uint8_t unknown_attr[] = { 250, 3, 'x' };
		/* VSA envelope with a 3-byte body: too short for a 4-byte Vendor-Id */
		uint8_t short_vsa[] = { 26, 5, 0, 0, 0 };

		if (radcli_avp_decode(rh, unknown_attr, sizeof(unknown_attr), 0, &skipped) != 0) {
			fprintf(stderr, "error: an unrecognised attribute was a hard decode error\n");
			exit(1);
		}
		if (!avp_list_empty(skipped)) {
			fprintf(stderr, "error: an unrecognised attribute was not skipped\n");
			exit(1);
		}
		radcli_avp_list_free(skipped);

		if (radcli_avp_decode(rh, short_vsa, sizeof(short_vsa), 0, &skipped) != 0) {
			fprintf(stderr, "error: an undersized VSA envelope was a hard decode error\n");
			exit(1);
		}
		if (!avp_list_empty(skipped)) {
			fprintf(stderr, "error: an undersized VSA envelope was not skipped\n");
			exit(1);
		}
		radcli_avp_list_free(skipped);
	}

	/* --- decode: an unrecognised vendor's VSA is skipped whole --- */

	{
		radcli_avp_list *skipped;
		/* VSA, vendor 100000 (0x000186A0, not DSL-Forum/3561), one sub-attribute */
		uint8_t unknown_vendor_vsa[] = { 26, 9, 0, 1, 0x86, 0xa0, 1, 3, 'x' };

		if (radcli_avp_decode(rh, unknown_vendor_vsa, sizeof(unknown_vendor_vsa), 0, &skipped) != 0) {
			fprintf(stderr, "error: an unrecognised vendor was a hard decode error\n");
			exit(1);
		}
		if (!avp_list_empty(skipped)) {
			fprintf(stderr, "error: an unrecognised vendor's VSA was not skipped\n");
			exit(1);
		}
		radcli_avp_list_free(skipped);
	}

	/* --- encode: attributes needing per-request encryption are refused,
	 * never sent as accidental plaintext --- */

	{
		radcli_avp_list *l2 = radcli_avp_list_new();

		assert(radcli_avp_add_str(l2, d_pass, "hunter2") == 0);
		if (radcli_avp_encode(l2, buf, sizeof(buf)) >= 0) {
			fprintf(stderr, "error: radcli_avp_encode() sent User-Password in "
					"plaintext instead of refusing it\n");
			exit(1);
		}
		radcli_avp_list_free(l2);
	}

	rc_dict_free(rh);
	rc_destroy(rh);

	printf("radcli2 avp codec: all tests passed\n");
	return 0;
}
