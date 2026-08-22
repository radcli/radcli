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

/* Unit test for radcli2.h's radcli_avp_list / radcli_avp: construction,
 * typed setters/getters, and the dictionary-type validation each performs.
 * Purely in-memory -- no wire encoding/decoding exists yet (a later commit
 * of doc/plan-api-modernization.md's Phase 1). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

static char test_dict[] =
"ATTRIBUTE	User-Name		1	string\n"
"ATTRIBUTE	NAS-IP-Address		4	ipaddr\n"
"ATTRIBUTE	Framed-IPv6-Address	168	ipv6addr\n"
"ATTRIBUTE	Framed-IPv6-Prefix	97	ipv6prefix\n"
"ATTRIBUTE	Session-Timeout		27	integer\n"
"ATTRIBUTE	Test-Int64		251	integer64\n"
"ATTRIBUTE	Test-Octets		252	integer gigawords=253\n"
"ATTRIBUTE	Test-Gigawords		253	integer\n"
"ATTRIBUTE	Test-Octets-Unpaired	254	integer\n";

int main(int argc, char **argv)
{
	rc_handle *rh;
	radcli_ctx *ctx;
	radcli_avp_list *l;
	const radcli_avp *a;
	radcli_avp_iter it;
	const radcli_attr_def *d_user, *d_nasip, *d_v6addr, *d_v6prefix, *d_timeout;
	uint32_t u;
	struct in_addr ia;
	struct in6_addr i6, i6out;
	unsigned prefix;
	const void *raw;
	size_t rawlen;

	rh = rc_new();
	assert(rh != NULL);
	rc_config_init(rh);
	assert(rc_read_dictionary_from_buffer(rh, test_dict, sizeof(test_dict)) == 0);

	/* radcli_ctx and rc_handle name the same object (decision A2): no cast
	 * needed to pass rh where radcli2.h expects a radcli_ctx. */
	ctx = rh;

	d_user = radcli_dict_lookup(ctx, "User-Name");
	d_nasip = radcli_dict_lookup(ctx, "NAS-IP-Address");
	d_v6addr = radcli_dict_lookup(ctx, "Framed-IPv6-Address");
	d_v6prefix = radcli_dict_lookup(ctx, "Framed-IPv6-Prefix");
	d_timeout = radcli_dict_lookup(ctx, "Session-Timeout");
	assert(d_user && d_nasip && d_v6addr && d_v6prefix && d_timeout);

	l = radcli_avp_list_new();
	assert(l != NULL);

	/* Empty list: no first element, no NULL-def match. */
	it = radcli_avp_list_iter(l);
	assert(radcli_avp_iter_next(&it) == NULL);
	assert(radcli_avp_get(l, d_user, 0) == NULL);

	/* --- construction, one call per accepted type --- */

	if (radcli_avp_add_str(l, d_user, "alice") != 0) {
		fprintf(stderr, "error: radcli_avp_add_str() failed\n");
		exit(1);
	}

	inet_pton(AF_INET, "192.0.2.7", &ia);
	if (radcli_avp_add_ipaddr(l, d_nasip, ia) != 0) {
		fprintf(stderr, "error: radcli_avp_add_ipaddr() failed\n");
		exit(1);
	}

	if (radcli_avp_add_uint32(l, d_timeout, 3600) != 0) {
		fprintf(stderr, "error: radcli_avp_add_uint32() failed\n");
		exit(1);
	}

	inet_pton(AF_INET6, "2001:db8::1", &i6);
	if (radcli_avp_add_in6(l, d_v6addr, &i6, 0) != 0) {
		fprintf(stderr, "error: radcli_avp_add_in6() (address) failed\n");
		exit(1);
	}
	if (radcli_avp_add_in6(l, d_v6prefix, &i6, 64) != 0) {
		fprintf(stderr, "error: radcli_avp_add_in6() (prefix) failed\n");
		exit(1);
	}

	/* --- setters MUST reject a definition of the wrong type --- */

	if (radcli_avp_add_uint32(l, d_user, 5) == 0) {
		fprintf(stderr, "error: radcli_avp_add_uint32() accepted a STRING attribute\n");
		exit(1);
	}
	if (radcli_avp_add_str(l, d_nasip, "not-an-address") == 0) {
		fprintf(stderr, "error: radcli_avp_add_str() accepted an IPADDR attribute\n");
		exit(1);
	}
	if (radcli_avp_add_in6(l, d_v6addr, &i6, 64) == 0) {
		fprintf(stderr, "error: radcli_avp_add_in6() accepted prefix != 0 for IPV6ADDR\n");
		exit(1);
	}
	if (radcli_avp_add_in6(l, d_v6prefix, &i6, 200) == 0) {
		fprintf(stderr, "error: radcli_avp_add_in6() accepted prefix > 128\n");
		exit(1);
	}
	if (radcli_avp_add_bytes(l, NULL, "x", 1) == 0) {
		fprintf(stderr, "error: radcli_avp_add_bytes() accepted a NULL def\n");
		exit(1);
	}

	/* --- wire order is preserved; radcli_avp_iter_next() walks it --- */

	it = radcli_avp_list_iter(l);
	a = radcli_avp_iter_next(&it);
	if (a == NULL || radcli_avp_def(a) != d_user) {
		fprintf(stderr, "error: first attribute is not User-Name\n");
		exit(1);
	}
	a = radcli_avp_iter_next(&it);
	if (a == NULL || radcli_avp_def(a) != d_nasip) {
		fprintf(stderr, "error: second attribute is not NAS-IP-Address\n");
		exit(1);
	}

	/* --- exhaustion is sticky: NULL never restarts the same iterator --- */

	{
		radcli_avp_iter it2 = radcli_avp_list_iter(l);
		unsigned count = 0;

		while (radcli_avp_iter_next(&it2) != NULL)
			count++;
		if (count != 5) {
			fprintf(stderr, "error: expected 5 attributes, walked %u\n", count);
			exit(1);
		}
		if (radcli_avp_iter_next(&it2) != NULL || radcli_avp_iter_next(&it2) != NULL) {
			fprintf(stderr, "error: iterator restarted after exhaustion\n");
			exit(1);
		}
	}

	/* --- two independent iterators over the same list do not interfere --- */

	{
		radcli_avp_iter ita = radcli_avp_list_iter(l);
		radcli_avp_iter itb;
		const radcli_avp *x;

		while (radcli_avp_iter_next(&ita) != NULL)
			; /* drain ita fully */
		itb = radcli_avp_list_iter(l);
		x = radcli_avp_iter_next(&itb);
		if (x == NULL || radcli_avp_def(x) != d_user) {
			fprintf(stderr, "error: a fresh iterator did not start at the first attribute\n");
			exit(1);
		}
	}

	/* --- NULL list is a no-op iterator, not a crash --- */

	{
		radcli_avp_iter itn = radcli_avp_list_iter(NULL);

		if (radcli_avp_iter_next(&itn) != NULL) {
			fprintf(stderr, "error: iterating a NULL list returned an attribute\n");
			exit(1);
		}
	}

	/* --- typed getters round-trip what was set, and reject the wrong type --- */

	a = radcli_avp_get(l, d_user, 0);
	assert(a != NULL);
	if (radcli_avp_get_bytes(a, &raw, &rawlen) != 0 || rawlen != 5 ||
	    memcmp(raw, "alice", 5) != 0) {
		fprintf(stderr, "error: User-Name did not round-trip via radcli_avp_get_bytes()\n");
		exit(1);
	}
	if (radcli_avp_get_uint32(a, &u) == 0) {
		fprintf(stderr, "error: radcli_avp_get_uint32() accepted a STRING attribute\n");
		exit(1);
	}

	a = radcli_avp_get(l, d_nasip, 0);
	assert(a != NULL);
	if (radcli_avp_get_uint32(a, &u) != 0 || u != ntohl(ia.s_addr)) {
		fprintf(stderr, "error: NAS-IP-Address did not round-trip via radcli_avp_get_uint32()\n");
		exit(1);
	}

	a = radcli_avp_get(l, d_timeout, 0);
	assert(a != NULL);
	if (radcli_avp_get_uint32(a, &u) != 0 || u != 3600) {
		fprintf(stderr, "error: Session-Timeout did not round-trip\n");
		exit(1);
	}

	a = radcli_avp_get(l, d_v6addr, 0);
	assert(a != NULL);
	memset(&i6out, 0xff, sizeof(i6out));
	if (radcli_avp_get_in6(a, &i6out, &prefix) != 0 ||
	    memcmp(&i6out, &i6, 16) != 0 || prefix != 128) {
		fprintf(stderr, "error: Framed-IPv6-Address did not round-trip\n");
		exit(1);
	}

	a = radcli_avp_get(l, d_v6prefix, 0);
	assert(a != NULL);
	memset(&i6out, 0xff, sizeof(i6out));
	if (radcli_avp_get_in6(a, &i6out, &prefix) != 0 ||
	    memcmp(&i6out, &i6, 16) != 0 || prefix != 64) {
		fprintf(stderr, "error: Framed-IPv6-Prefix did not round-trip\n");
		exit(1);
	}

	/* --- repeated attributes are addressed by occurrence index --- */

	if (radcli_avp_get(l, d_user, 1) != NULL) {
		fprintf(stderr, "error: a second User-Name was found before one was added\n");
		exit(1);
	}
	if (radcli_avp_add_str(l, d_user, "bob") != 0) {
		fprintf(stderr, "error: radcli_avp_add_str() (second User-Name) failed\n");
		exit(1);
	}
	a = radcli_avp_get(l, d_user, 0);
	assert(a != NULL && radcli_avp_get_bytes(a, &raw, &rawlen) == 0);
	if (rawlen != 5 || memcmp(raw, "alice", 5) != 0) {
		fprintf(stderr, "error: idx=0 User-Name is not the first one added\n");
		exit(1);
	}
	a = radcli_avp_get(l, d_user, 1);
	assert(a != NULL && radcli_avp_get_bytes(a, &raw, &rawlen) == 0);
	if (rawlen != 3 || memcmp(raw, "bob", 3) != 0) {
		fprintf(stderr, "error: idx=1 User-Name is not the second one added\n");
		exit(1);
	}

	/* --- Phase 2: RADCLI_TYPE_INTEGER64, radcli_avp_add_uint64()/_get_uint64() --- */

	{
		const radcli_attr_def *d_int64 = radcli_dict_lookup(ctx, "Test-Int64");
		uint64_t v64;

		assert(d_int64 != NULL);
		if (radcli_attr_def_type(d_int64) != RADCLI_TYPE_INTEGER64) {
			fprintf(stderr, "error: Test-Int64 did not parse to RADCLI_TYPE_INTEGER64\n");
			exit(1);
		}
		/* Exercises both halves independently: a value with the high 32
		 * bits set (0x0123456789abcdef) is not representable as, and would
		 * be silently truncated by, any of the 32-bit setters. */
		if (radcli_avp_add_uint64(l, d_int64, UINT64_C(0x0123456789abcdef)) != 0) {
			fprintf(stderr, "error: radcli_avp_add_uint64() failed\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_int64, 0);
		if (a == NULL || radcli_avp_get_uint64(a, &v64) != 0 ||
		    v64 != UINT64_C(0x0123456789abcdef)) {
			fprintf(stderr, "error: Test-Int64 did not round-trip\n");
			exit(1);
		}
		/* Wrong-type rejection, both directions. */
		if (radcli_avp_add_uint64(l, d_user, 1) == 0) {
			fprintf(stderr, "error: radcli_avp_add_uint64() accepted a "
					"non-integer64 attribute\n");
			exit(1);
		}
		if (radcli_avp_get_uint32(a, &u) == 0) {
			fprintf(stderr, "error: radcli_avp_get_uint32() accepted an "
					"integer64 attribute\n");
			exit(1);
		}
	}

	/* --- Phase 2: the Gigawords helper --- */

	{
		const radcli_attr_def *d_octets = radcli_dict_lookup(ctx, "Test-Octets");
		const radcli_attr_def *d_gigawords = radcli_dict_lookup(ctx, "Test-Gigawords");
		const radcli_attr_def *d_unpaired = radcli_dict_lookup(ctx, "Test-Octets-Unpaired");
		radcli_avp_list *cl;
		uint64_t v64;

		assert(d_octets != NULL && d_gigawords != NULL && d_unpaired != NULL);

		/* A count over 2^32: both halves must be present and correct. */
		cl = radcli_avp_list_new();
		assert(cl != NULL);
		if (radcli_avp_add_gigawords64(ctx, cl, d_octets, UINT64_C(5000000000)) != 0) {
			fprintf(stderr, "error: radcli_avp_add_gigawords64() failed\n");
			exit(1);
		}
		if (radcli_avp_get(cl, d_gigawords, 0) == NULL) {
			fprintf(stderr, "error: radcli_avp_add_gigawords64() did not add the "
					"Gigawords attribute for a value over 2^32\n");
			exit(1);
		}
		if (radcli_avp_get_gigawords64(ctx, cl, d_octets, &v64) != 0 ||
		    v64 != UINT64_C(5000000000)) {
			fprintf(stderr, "error: radcli_avp_get_gigawords64() did not "
					"reassemble a value over 2^32\n");
			exit(1);
		}
		radcli_avp_list_free(cl);

		/* A count under 2^32: the Gigawords attribute must be omitted --
		 * matching how a real NAS sends it -- not added as zero. */
		cl = radcli_avp_list_new();
		assert(cl != NULL);
		if (radcli_avp_add_gigawords64(ctx, cl, d_octets, 42) != 0) {
			fprintf(stderr, "error: radcli_avp_add_gigawords64() failed (small value)\n");
			exit(1);
		}
		if (radcli_avp_get(cl, d_gigawords, 0) != NULL) {
			fprintf(stderr, "error: radcli_avp_add_gigawords64() added a zero "
					"Gigawords attribute\n");
			exit(1);
		}
		/* Reassembly must still work with the Gigawords half absent. */
		if (radcli_avp_get_gigawords64(ctx, cl, d_octets, &v64) != 0 || v64 != 42) {
			fprintf(stderr, "error: radcli_avp_get_gigawords64() failed with no "
					"Gigawords attribute present\n");
			exit(1);
		}
		radcli_avp_list_free(cl);

		/* No gigawords= counterpart configured: an error, not a silent
		 * truncation to 32 bits. */
		cl = radcli_avp_list_new();
		assert(cl != NULL);
		if (radcli_avp_add_gigawords64(ctx, cl, d_unpaired, 42) == 0) {
			fprintf(stderr, "error: radcli_avp_add_gigawords64() accepted an "
					"attribute with no gigawords= counterpart\n");
			exit(1);
		}
		if (radcli_avp_get_gigawords64(ctx, cl, d_unpaired, &v64) == 0) {
			fprintf(stderr, "error: radcli_avp_get_gigawords64() accepted an "
					"attribute with no gigawords= counterpart\n");
			exit(1);
		}
		radcli_avp_list_free(cl);
	}

	/* --- teardown: a NULL list must be a no-op, not a crash --- */

	radcli_avp_list_free(l);
	radcli_avp_list_free(NULL);

	rc_dict_free(rh);
	rc_destroy(rh);

	printf("radcli2 avp: all tests passed\n");
	return 0;
}
