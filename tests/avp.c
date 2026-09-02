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
 * Purely in-memory; wire encoding/decoding is covered separately (see
 * tests/avp-codec.c). */

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
"ATTRIBUTE	Framed-Route		22	string\n"
"ATTRIBUTE	Framed-IPv6-Address	168	ipv6addr\n"
"ATTRIBUTE	Framed-IPv6-Prefix	97	ipv6prefix\n"
"ATTRIBUTE	Session-Timeout		27	integer\n"
"ATTRIBUTE	Test-Int64		251	integer64\n"
"ATTRIBUTE	Test-Ipv4prefix		255	ipv4prefix\n"
"ATTRIBUTE	Test-Text		256	text\n"
"ATTRIBUTE	Test-Ifid		257	ifid\n"
"ATTRIBUTE	Test-Octets		252	integer gigawords=253\n"
"ATTRIBUTE	Test-Gigawords		253	integer\n"
"ATTRIBUTE	Test-Octets-Unpaired	254	integer\n";

int main(int argc, char **argv)
{
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

	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	assert(radcli_ctx_read_dictionary_from_buffer(ctx, test_dict, sizeof(test_dict)) == 0);

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
	if (radcli_avp_add_ip4(l, d_nasip, ia) != 0) {
		fprintf(stderr, "error: radcli_avp_add_ip4() failed\n");
		exit(1);
	}

	if (radcli_avp_add_uint32(l, d_timeout, 3600) != 0) {
		fprintf(stderr, "error: radcli_avp_add_uint32() failed\n");
		exit(1);
	}

	inet_pton(AF_INET6, "2001:db8::1", &i6);
	if (radcli_avp_add_ip6(l, d_v6addr, &i6, 0) != 0) {
		fprintf(stderr, "error: radcli_avp_add_ip6() (address) failed\n");
		exit(1);
	}
	if (radcli_avp_add_ip6(l, d_v6prefix, &i6, 64) != 0) {
		fprintf(stderr, "error: radcli_avp_add_ip6() (prefix) failed\n");
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
	if (radcli_avp_add_ip6(l, d_v6addr, &i6, 64) == 0) {
		fprintf(stderr, "error: radcli_avp_add_ip6() accepted prefix != 0 for IPV6ADDR\n");
		exit(1);
	}
	if (radcli_avp_add_ip6(l, d_v6prefix, &i6, 200) == 0) {
		fprintf(stderr, "error: radcli_avp_add_ip6() accepted prefix > 128\n");
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
	if (strcmp(radcli_avp_get_cstr(a), "alice") != 0) {
		fprintf(stderr, "error: radcli_avp_get_cstr() did not round-trip \"alice\"\n");
		exit(1);
	}
	if (radcli_avp_get_cstr(NULL) != NULL) {
		fprintf(stderr, "error: radcli_avp_get_cstr(NULL) did not return NULL\n");
		exit(1);
	}

	/* --- radcli_avp_get_cstr() must refuse a value with an embedded NUL,
	 * not hand back a pointer that looks like a shorter, complete string
	 * (e.g. a server-supplied "admin\0attacker" read back as "admin") --- */
	{
		radcli_avp_list *l2 = radcli_avp_list_new();
		const radcli_avp *a2;

		assert(l2 != NULL);
		assert(radcli_avp_add_bytes(l2, d_user, "admin\0attacker", 14) == 0);
		a2 = radcli_avp_get(l2, d_user, 0);
		assert(a2 != NULL);
		if (radcli_avp_get_cstr(a2) != NULL) {
			fprintf(stderr, "error: radcli_avp_get_cstr() returned non-NULL "
					"for a value with an embedded NUL byte\n");
			exit(1);
		}
		/* the raw bytes are still fully accessible via radcli_avp_get_bytes() */
		if (radcli_avp_get_bytes(a2, &raw, &rawlen) != 0 || rawlen != 14 ||
		    memcmp(raw, "admin\0attacker", 14) != 0) {
			fprintf(stderr, "error: radcli_avp_get_bytes() did not return the "
					"full value with an embedded NUL byte\n");
			exit(1);
		}
		radcli_avp_list_free(l2);
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
	if (radcli_avp_get_ip6(a, &i6out, &prefix) != 0 ||
	    memcmp(&i6out, &i6, 16) != 0 || prefix != 128) {
		fprintf(stderr, "error: Framed-IPv6-Address did not round-trip\n");
		exit(1);
	}

	a = radcli_avp_get(l, d_v6prefix, 0);
	assert(a != NULL);
	memset(&i6out, 0xff, sizeof(i6out));
	if (radcli_avp_get_ip6(a, &i6out, &prefix) != 0 ||
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

	/* --- Phase 2b: RADCLI_TYPE_IFID, sharing radcli_avp_add_uint64()/
	 * _get_uint64() with RADCLI_TYPE_INTEGER64 above (identical 8-octet
	 * wire shape) --- */

	{
		const radcli_attr_def *d_ifid = radcli_dict_lookup(ctx, "Test-Ifid");
		uint64_t v64;

		assert(d_ifid != NULL);
		if (radcli_attr_def_type(d_ifid) != RADCLI_TYPE_IFID) {
			fprintf(stderr, "error: Test-Ifid did not parse to RADCLI_TYPE_IFID\n");
			exit(1);
		}
		if (radcli_avp_add_uint64(l, d_ifid, UINT64_C(0xfe80000000000001)) != 0) {
			fprintf(stderr, "error: radcli_avp_add_uint64() failed on an ifid attribute\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_ifid, 0);
		if (a == NULL || radcli_avp_get_uint64(a, &v64) != 0 ||
		    v64 != UINT64_C(0xfe80000000000001)) {
			fprintf(stderr, "error: Test-Ifid did not round-trip\n");
			exit(1);
		}
	}

	/* --- Phase 3: RADCLI_TYPE_IPV4PREFIX, radcli_avp_add_ip4prefix()/_get_ip4prefix() --- */

	{
		const radcli_attr_def *d_v4prefix = radcli_dict_lookup(ctx, "Test-Ipv4prefix");
		struct in_addr ia4, ia4out;
		unsigned pfx;

		assert(d_v4prefix != NULL);
		if (radcli_attr_def_type(d_v4prefix) != RADCLI_TYPE_IPV4PREFIX) {
			fprintf(stderr, "error: Test-Ipv4prefix did not parse to RADCLI_TYPE_IPV4PREFIX\n");
			exit(1);
		}

		inet_pton(AF_INET, "198.51.100.0", &ia4);
		if (radcli_avp_add_ip4prefix(l, d_v4prefix, ia4, 24) != 0) {
			fprintf(stderr, "error: radcli_avp_add_ip4prefix() failed\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_v4prefix, 0);
		if (a == NULL || radcli_avp_get_ip4prefix(a, &ia4out, &pfx) != 0 ||
		    pfx != 24 || memcmp(&ia4, &ia4out, sizeof(ia4)) != 0) {
			fprintf(stderr, "error: Test-Ipv4prefix did not round-trip\n");
			exit(1);
		}

		/* Wrong-type rejection, both directions. */
		if (radcli_avp_add_ip4prefix(l, d_nasip, ia4, 24) == 0) {
			fprintf(stderr, "error: radcli_avp_add_ip4prefix() accepted an "
					"IPADDR attribute\n");
			exit(1);
		}
		if (radcli_avp_add_ip4(l, d_v4prefix, ia4) == 0) {
			fprintf(stderr, "error: radcli_avp_add_ip4() accepted an "
					"IPV4PREFIX attribute\n");
			exit(1);
		}
		if (radcli_avp_get_ip6(a, &i6out, &prefix) == 0) {
			fprintf(stderr, "error: radcli_avp_get_ip6() accepted an "
					"IPV4PREFIX attribute\n");
			exit(1);
		}

		/* Prefix out of range. */
		if (radcli_avp_add_ip4prefix(l, d_v4prefix, ia4, 33) == 0) {
			fprintf(stderr, "error: radcli_avp_add_ip4prefix() accepted prefix > 32\n");
			exit(1);
		}
	}

	/* --- Phase 4: RADCLI_TYPE_TEXT, dual-use radcli_avp_add_str() and
	 * UTF-8-validating radcli_avp_get_cstr() --- */

	{
		const radcli_attr_def *d_text = radcli_dict_lookup(ctx, "Test-Text");
		const char *s;

		assert(d_text != NULL);
		if (radcli_attr_def_type(d_text) != RADCLI_TYPE_TEXT) {
			fprintf(stderr, "error: Test-Text did not parse to RADCLI_TYPE_TEXT\n");
			exit(1);
		}

		/* Valid UTF-8 (includes a multi-byte character) round-trips through
		 * add_str()/get_cstr(). */
		if (radcli_avp_add_str(l, d_text, "caf\xc3\xa9") != 0) {
			fprintf(stderr, "error: radcli_avp_add_str() rejected valid UTF-8 "
					"for a RADCLI_TYPE_TEXT attribute\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_text, 0);
		s = a ? radcli_avp_get_cstr(a) : NULL;
		if (s == NULL || strcmp(s, "caf\xc3\xa9") != 0) {
			fprintf(stderr, "error: Test-Text did not round-trip through "
					"add_str()/get_cstr()\n");
			exit(1);
		}

		/* Invalid UTF-8 (a lone continuation byte) is rejected on add. */
		if (radcli_avp_add_str(l, d_text, "bad\x80value") == 0) {
			fprintf(stderr, "error: radcli_avp_add_str() accepted invalid "
					"UTF-8 for a RADCLI_TYPE_TEXT attribute\n");
			exit(1);
		}

		/* radcli_avp_add_str() against a RADCLI_TYPE_STRING attribute is
		 * unchanged by the RADCLI_TYPE_TEXT widening -- regression guard for
		 * the compatibility concern that motivated making add_str() dual-use
		 * rather than adding a separate add_text(). */
		if (radcli_avp_add_str(l, d_user, "carol") != 0) {
			fprintf(stderr, "error: radcli_avp_add_str() regressed for a "
					"RADCLI_TYPE_STRING attribute\n");
			exit(1);
		}
		/* Third User-Name occurrence: idx=0 "alice", idx=1 "bob" (added
		 * earlier in this test), idx=2 the "carol" just added above. */
		a = radcli_avp_get(l, d_user, 2);
		s = a ? radcli_avp_get_cstr(a) : NULL;
		if (s == NULL || strcmp(s, "carol") != 0) {
			fprintf(stderr, "error: User-Name (STRING) did not round-trip "
					"through add_str()/get_cstr()\n");
			exit(1);
		}

		/* get_cstr()'s export-side checks apply even to a RADCLI_TYPE_TEXT
		 * value that bypassed add_str()'s validation entirely -- simulating
		 * an attribute populated by radcli_avp_decode() from a received
		 * packet, whose bytes never went through add-side validation. */
		if (radcli_avp_add_bytes(l, d_text, "admin\0attacker", 14) != 0) {
			fprintf(stderr, "error: radcli_avp_add_bytes() failed\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_text, 1);
		if (a == NULL || radcli_avp_get_cstr(a) != NULL) {
			fprintf(stderr, "error: radcli_avp_get_cstr() returned a string "
					"for a RADCLI_TYPE_TEXT value with an embedded NUL\n");
			exit(1);
		}

		if (radcli_avp_add_bytes(l, d_text, "bad\x80value", strlen("bad\x80value")) != 0) {
			fprintf(stderr, "error: radcli_avp_add_bytes() failed\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_text, 2);
		if (a == NULL || radcli_avp_get_cstr(a) != NULL) {
			fprintf(stderr, "error: radcli_avp_get_cstr() returned a string "
					"for a RADCLI_TYPE_TEXT value with invalid UTF-8\n");
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

		/* _by_num() wrappers: same behaviour, looked up by (attrid, vendor)
		 * instead of a pre-resolved radcli_attr_def -- only the octets
		 * attribute's ID is needed, unlike the other _by_num() wrappers,
		 * since the Gigawords counterpart is resolved from octets' own
		 * dictionary entry either way. */
		cl = radcli_avp_list_new();
		assert(cl != NULL);
		if (radcli_avp_add_gigawords64_by_num(ctx, cl, 252, 0, UINT64_C(5000000000)) != 0) {
			fprintf(stderr, "error: radcli_avp_add_gigawords64_by_num() failed\n");
			exit(1);
		}
		if (radcli_avp_get(cl, d_gigawords, 0) == NULL) {
			fprintf(stderr, "error: radcli_avp_add_gigawords64_by_num() did not add "
					"the Gigawords attribute for a value over 2^32\n");
			exit(1);
		}
		if (radcli_avp_get_gigawords64_by_num(ctx, cl, 252, 0, &v64) != 0 ||
		    v64 != UINT64_C(5000000000)) {
			fprintf(stderr, "error: radcli_avp_get_gigawords64_by_num() did not "
					"reassemble a value over 2^32\n");
			exit(1);
		}
		radcli_avp_list_free(cl);

		/* No gigawords= counterpart configured: an error, same as the
		 * radcli_attr_def-taking form. */
		cl = radcli_avp_list_new();
		assert(cl != NULL);
		if (radcli_avp_add_gigawords64_by_num(ctx, cl, 254, 0, 42) == 0) {
			fprintf(stderr, "error: radcli_avp_add_gigawords64_by_num() accepted an "
					"attribute with no gigawords= counterpart\n");
			exit(1);
		}
		if (radcli_avp_get_gigawords64_by_num(ctx, cl, 254, 0, &v64) == 0) {
			fprintf(stderr, "error: radcli_avp_get_gigawords64_by_num() accepted an "
					"attribute with no gigawords= counterpart\n");
			exit(1);
		}
		radcli_avp_list_free(cl);

		/* Unresolvable attribute ID: an error, not a crash. */
		cl = radcli_avp_list_new();
		assert(cl != NULL);
		if (radcli_avp_add_gigawords64_by_num(ctx, cl, 9999, 0, 42) == 0) {
			fprintf(stderr, "error: radcli_avp_add_gigawords64_by_num() accepted an "
					"unresolvable attribute ID\n");
			exit(1);
		}
		if (radcli_avp_get_gigawords64_by_num(ctx, cl, 9999, 0, &v64) == 0) {
			fprintf(stderr, "error: radcli_avp_get_gigawords64_by_num() accepted an "
					"unresolvable attribute ID\n");
			exit(1);
		}
		radcli_avp_list_free(cl);
	}

	/* --- Phase 6a: radcli_avp_get_*_by_num(), the receive-side mirror of
	 * radcli_avp_add_*_by_num() --- */

	{
		radcli_avp_list *gl = radcli_avp_list_new();
		uint32_t v32;
		struct in6_addr v6;
		const void *vraw;
		size_t vlen;
		const char *vstr;

		assert(gl != NULL);
		inet_pton(AF_INET, "192.0.2.9", &ia);
		assert(radcli_avp_add_ip4_by_num(gl, ctx, PW_NAS_IP_ADDRESS, 0, ia) == 0);
		memset(&i6, 0x42, sizeof(i6));
		assert(radcli_avp_add_ip6_by_num(gl, ctx, PW_FRAMED_IPV6_ADDRESS, 0, &i6, 0) == 0);
		assert(radcli_avp_add_str_by_num(gl, ctx, PW_USER_NAME, 0, "carol") == 0);

		if (radcli_avp_get_uint32_by_num(gl, ctx, PW_NAS_IP_ADDRESS, 0, &v32) != 0 ||
		    v32 != ntohl(ia.s_addr)) {
			fprintf(stderr, "error: radcli_avp_get_uint32_by_num() did not round-trip NAS-IP-Address\n");
			exit(1);
		}
		if (radcli_avp_get_ip6_by_num(gl, ctx, PW_FRAMED_IPV6_ADDRESS, 0, &v6, NULL) != 0 ||
		    memcmp(&v6, &i6, 16) != 0) {
			fprintf(stderr, "error: radcli_avp_get_ip6_by_num() did not round-trip\n");
			exit(1);
		}
		if (radcli_avp_get_bytes_by_num(gl, ctx, PW_USER_NAME, 0, &vraw, &vlen) != 0 ||
		    vlen != 5 || memcmp(vraw, "carol", 5) != 0) {
			fprintf(stderr, "error: radcli_avp_get_bytes_by_num() did not round-trip\n");
			exit(1);
		}
		vstr = radcli_avp_get_cstr_by_num(gl, ctx, PW_USER_NAME, 0);
		if (vstr == NULL || strcmp(vstr, "carol") != 0) {
			fprintf(stderr, "error: radcli_avp_get_cstr_by_num() did not round-trip\n");
			exit(1);
		}

		/* An attribute number the loaded dictionary has no entry for at
		 * all (not merely "no occurrence in this list") must fail, not
		 * crash or silently return a zeroed value. */
		if (radcli_avp_get_uint32_by_num(gl, ctx, 9999, 0, &v32) == 0) {
			fprintf(stderr, "error: radcli_avp_get_uint32_by_num() accepted an "
					"attribute ID with no dictionary entry\n");
			exit(1);
		}
		if (radcli_avp_get_cstr_by_num(gl, ctx, 9999, 0) != NULL) {
			fprintf(stderr, "error: radcli_avp_get_cstr_by_num() accepted an "
					"attribute ID with no dictionary entry\n");
			exit(1);
		}

		/* A well-known attribute ID the dictionary does have, but that
		 * was never added to this particular list, is "no occurrence" --
		 * same failure shape (NULL/-1), different cause. */
		if (radcli_avp_get_uint32_by_num(gl, ctx, PW_SESSION_TIMEOUT, 0, &v32) == 0) {
			fprintf(stderr, "error: radcli_avp_get_uint32_by_num() found an "
					"attribute never added to this list\n");
			exit(1);
		}

		/* radcli_avp_get_by_num()'s idx parameter: the plain finder is
		 * how a multi-occurrence attribute (unlike the above,
		 * single-occurrence ones) is walked -- see the
		 * radcli_avp_concat_str_by_num() block below for the common
		 * "join every occurrence as text" case built on top of it. */
		assert(radcli_avp_add_str_by_num(gl, ctx, PW_USER_NAME, 0, "dave") == 0);
		if (radcli_avp_get_by_num(gl, ctx, PW_USER_NAME, 0, 0) == NULL ||
		    radcli_avp_get_by_num(gl, ctx, PW_USER_NAME, 0, 1) == NULL ||
		    radcli_avp_get_by_num(gl, ctx, PW_USER_NAME, 0, 2) != NULL) {
			fprintf(stderr, "error: radcli_avp_get_by_num() idx did not address "
					"occurrences correctly\n");
			exit(1);
		}

		radcli_avp_list_free(gl);
	}

	/* --- Phase 6b: radcli_avp_concat_str()/_by_num() --- */

	{
		radcli_avp_list *rl = radcli_avp_list_new();
		const radcli_attr_def *d_framed_route = radcli_dict_lookup(ctx, "Framed-Route");
		char buf[64], buf2[64];
		int n;
		const char *expected = "192.0.2.0/24 192.0.2.1\n198.51.100.0/24 198.51.100.1";
		int expected_len = (int)strlen(expected);

		assert(rl != NULL && d_framed_route != NULL);

		/* No Framed-Route added yet: empty result, not a failure --
		 * matches legacy rc_aaa()'s msg starting as '\0' and simply
		 * staying that way when nothing matched. Both forms agree. */
		n = radcli_avp_concat_str_by_num(buf, sizeof(buf), rl, ctx, PW_FRAMED_ROUTE, 0, "\n");
		if (n != 0 || buf[0] != 0) {
			fprintf(stderr, "error: radcli_avp_concat_str_by_num() was not empty "
					"with no occurrences present\n");
			exit(1);
		}
		n = radcli_avp_concat_str(buf, sizeof(buf), rl, d_framed_route, "\n");
		if (n != 0 || buf[0] != 0) {
			fprintf(stderr, "error: radcli_avp_concat_str() was not empty "
					"with no occurrences present\n");
			exit(1);
		}

		assert(radcli_avp_add_str_by_num(rl, ctx, PW_FRAMED_ROUTE, 0, "192.0.2.0/24 192.0.2.1") == 0);
		assert(radcli_avp_add_str_by_num(rl, ctx, PW_FRAMED_ROUTE, 0, "198.51.100.0/24 198.51.100.1") == 0);

		n = radcli_avp_concat_str_by_num(buf, sizeof(buf), rl, ctx, PW_FRAMED_ROUTE, 0, "\n");
		if (n != expected_len || strcmp(buf, expected) != 0) {
			fprintf(stderr, "error: radcli_avp_concat_str_by_num() did not join "
					"every occurrence with the separator: got \"%s\"\n", buf);
			exit(1);
		}

		/* radcli_avp_concat_str() (the def-taking primitive) must agree
		 * exactly with the _by_num() wrapper built on top of it. */
		n = radcli_avp_concat_str(buf2, sizeof(buf2), rl, d_framed_route, "\n");
		if (n != expected_len || strcmp(buf2, buf) != 0) {
			fprintf(stderr, "error: radcli_avp_concat_str() disagrees with "
					"radcli_avp_concat_str_by_num(): got \"%s\"\n", buf2);
			exit(1);
		}

		/* Truncation: snprintf()-style -- returns the full would-be
		 * length (not -1), and buf is left as a valid, NUL-terminated
		 * prefix of what fits -- never garbage, never unterminated. */
		{
			char small[10];

			n = radcli_avp_concat_str_by_num(small, sizeof(small), rl, ctx,
							 PW_FRAMED_ROUTE, 0, "\n");
			if (n != expected_len) {
				fprintf(stderr, "error: radcli_avp_concat_str_by_num() did not "
						"report the full needed length on truncation\n");
				exit(1);
			}
			if (strlen(small) >= sizeof(small)) {
				fprintf(stderr, "error: radcli_avp_concat_str_by_num() left an "
						"unterminated buffer on truncation\n");
				exit(1);
			}

			n = radcli_avp_concat_str(small, sizeof(small), rl, d_framed_route, "\n");
			if (n != expected_len) {
				fprintf(stderr, "error: radcli_avp_concat_str() did not "
						"report the full needed length on truncation\n");
				exit(1);
			}
			if (strlen(small) >= sizeof(small)) {
				fprintf(stderr, "error: radcli_avp_concat_str() left an "
						"unterminated buffer on truncation\n");
				exit(1);
			}
		}

		/* Size query: buf == NULL and buflen == 0 are valid inputs, the
		 * same way snprintf(NULL, 0, ...) is -- both return the same
		 * full length as the truncation case above, without writing
		 * anything. */
		if (radcli_avp_concat_str_by_num(NULL, sizeof(buf), rl, ctx, PW_FRAMED_ROUTE, 0, "\n") != expected_len ||
		    radcli_avp_concat_str_by_num(buf, 0, rl, ctx, PW_FRAMED_ROUTE, 0, "\n") != expected_len) {
			fprintf(stderr, "error: radcli_avp_concat_str_by_num() did not treat a "
					"NULL buf/zero buflen as a size query\n");
			exit(1);
		}
		if (radcli_avp_concat_str(NULL, sizeof(buf), rl, d_framed_route, "\n") != expected_len ||
		    radcli_avp_concat_str(buf, 0, rl, d_framed_route, "\n") != expected_len) {
			fprintf(stderr, "error: radcli_avp_concat_str() did not treat a "
					"NULL buf/zero buflen as a size query\n");
			exit(1);
		}

		/* No dictionary entry at all: same "empty, not a failure" shape
		 * as "no occurrences" -- only meaningful for the _by_num()
		 * wrapper, which is the one that does the numeric lookup. */
		n = radcli_avp_concat_str_by_num(buf, sizeof(buf), rl, ctx, 9999, 0, "\n");
		if (n != 0 || buf[0] != 0) {
			fprintf(stderr, "error: radcli_avp_concat_str_by_num() was not empty "
					"for an attribute ID with no dictionary entry\n");
			exit(1);
		}

		/* radcli_avp_concat_str()'s one remaining failure case: a NULL
		 * def is a genuine invalid argument (unlike _by_num()'s "unknown
		 * attribute ID", which is not a failure). */
		if (radcli_avp_concat_str(buf, sizeof(buf), rl, NULL, "\n") != -1) {
			fprintf(stderr, "error: radcli_avp_concat_str() accepted a NULL def\n");
			exit(1);
		}

		radcli_avp_list_free(rl);
	}

	/* --- Phase 6c: radcli_avp_list_error() --- */

	{
		radcli_avp_list *el = radcli_avp_list_new();

		assert(el != NULL);
		if (radcli_avp_list_error(el) != 0) {
			fprintf(stderr, "error: radcli_avp_list_error() was set on a fresh list\n");
			exit(1);
		}

		/* A rejected add (wrong type) sets the sticky flag ... */
		if (radcli_avp_add_uint32(el, d_user, 1) == 0) {
			fprintf(stderr, "error: radcli_avp_add_uint32() accepted a "
					"non-integer attribute (test precondition)\n");
			exit(1);
		}
		if (radcli_avp_list_error(el) == 0) {
			fprintf(stderr, "error: radcli_avp_list_error() was not set after a "
					"failed add\n");
			exit(1);
		}

		/* ... but does NOT block or poison subsequent, unrelated adds --
		 * purely observational, see radcli_avp_list_error()'s own doc
		 * comment (lib/avp.c). A caller
		 * deliberately testing rejection (as this file does throughout)
		 * must see no behavior change from this flag's mere existence. */
		if (radcli_avp_add_str(el, d_user, "eve") != 0) {
			fprintf(stderr, "error: radcli_avp_list_error() being set caused an "
					"otherwise-valid, unrelated add to fail\n");
			exit(1);
		}
		/* The flag itself stays set (first failure, not just the most
		 * recent) even though a later add on the same list succeeded. */
		if (radcli_avp_list_error(el) == 0) {
			fprintf(stderr, "error: radcli_avp_list_error() cleared itself after "
					"a later add succeeded\n");
			exit(1);
		}

		radcli_avp_list_free(el);

		/* NULL counts as an error too -- a caller does not need a
		 * separate NULL check right after radcli_avp_list_new(). */
		if (radcli_avp_list_error(NULL) == 0) {
			fprintf(stderr, "error: radcli_avp_list_error(NULL) was not an error\n");
			exit(1);
		}
	}

	/* --- teardown: a NULL list must be a no-op, not a crash --- */

	radcli_avp_list_free(l);
	radcli_avp_list_free(NULL);

	radcli_ctx_free(ctx);

	printf("radcli2 avp: all tests passed\n");
	return 0;
}
