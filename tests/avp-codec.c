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

/* Unit test for radcli_avp_decode()/radcli_avp_encode() (lib/avp.c):
 * the radcli2.h wire codec. Both are internal-only (declared in lib/avp.h,
 * not exported), so this links against libradcli_static directly, the same
 * pattern tests/pack.c uses for rc_pack_list(). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <limits.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include <includes.h>
#include "avp.h" /* radcli_avp_decode(), radcli_avp_encode() */
#include "dict2.h" /* radcli_dict_flags_by_id(): radcli_dict_lookup() returns a
                     * struct radcli_dict_attr*, not a DICT_ATTR*, and there is
                     * no rc_dict_attr_encrypt_type()/_has_tag() equivalent
                     * that takes one -- those legacy shim functions were
                     * removed once lib/avp.c/lib/sendserver.c stopped
                     * calling them, so this reads the flags_by_attr_id side
                     * table directly instead. */

static int def_encrypt_type(radcli_ctx const *ctx, const radcli_attr_def *def)
{
	struct radcli_dict_flags *fl =
		radcli_dict_flags_by_id(ctx, ((const struct radcli_dict_attr *)def)->value);
	return fl ? fl->encrypt_type : 0;
}

static int def_has_tag(radcli_ctx const *ctx, const radcli_attr_def *def)
{
	struct radcli_dict_flags *fl =
		radcli_dict_flags_by_id(ctx, ((const struct radcli_dict_attr *)def)->value);
	return fl ? fl->has_tag : 0;
}

static char test_dict[] =
"ATTRIBUTE	User-Name		1	string\n"
"ATTRIBUTE	User-Password		2	string encrypt=User-Password\n"
"ATTRIBUTE	NAS-IP-Address		4	ipaddr\n"
"ATTRIBUTE	Session-Timeout		27	integer\n"
"ATTRIBUTE	Framed-IPv6-Address	168	ipv6addr\n"
"ATTRIBUTE	Tunnel-Password		69	string encrypt=Tunnel-Password,has_tag\n"
"VENDOR          DSL-Forum       3561     Large\n"
"ATTRIBUTE	Agent-Circuit-Id		1	string DSL-Forum\n"
"VENDOR          Microsoft       311      Large\n"
"ATTRIBUTE	MS-MPPE-Send-Key		16	string Microsoft,encrypt=Tunnel-Password\n"
"ATTRIBUTE	Test-Int64		251	integer64\n"
"ATTRIBUTE	Test-Ifid		252	ifid\n";

static int avp_list_empty(const radcli_avp_list *l)
{
	radcli_avp_iter it = radcli_avp_list_iter(l);
	return radcli_avp_iter_next(&it) == NULL;
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_avp_list *l, *decoded;
	const radcli_attr_def *d_user, *d_pass, *d_nasip, *d_timeout, *d_v6, *d_agent;
	const radcli_attr_def *d_tunnelpw, *d_mppe;
	uint8_t buf[512];
	int n;
	struct in_addr ia;
	struct in6_addr i6, i6out;
	unsigned prefix;
	const radcli_avp *a;
	const void *raw;
	size_t rawlen;
	uint32_t u = 0;

	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	assert(radcli_ctx_read_dictionary_from_buffer(ctx, test_dict, sizeof(test_dict)) == 0);

	d_user = radcli_dict_lookup(ctx, "User-Name");
	d_pass = radcli_dict_lookup(ctx, "User-Password");
	d_nasip = radcli_dict_lookup(ctx, "NAS-IP-Address");
	d_timeout = radcli_dict_lookup(ctx, "Session-Timeout");
	d_v6 = radcli_dict_lookup(ctx, "Framed-IPv6-Address");
	d_agent = radcli_dict_lookup(ctx, "Agent-Circuit-Id");
	d_tunnelpw = radcli_dict_lookup(ctx, "Tunnel-Password");
	d_mppe = radcli_dict_lookup(ctx, "MS-MPPE-Send-Key");
	assert(d_user && d_pass && d_nasip && d_timeout && d_v6 && d_agent && d_tunnelpw && d_mppe);

	/* --- round trip: encode(list) then decode(bytes) reproduces every
	 * attribute, including a VSA, across every non-encrypted type --- */

	l = radcli_avp_list_new();
	assert(l != NULL);
	assert(radcli_avp_add_str(l, d_user, "alice") == 0);
	inet_pton(AF_INET, "192.0.2.7", &ia);
	assert(radcli_avp_add_ip4(l, d_nasip, ia) == 0);
	assert(radcli_avp_add_uint32(l, d_timeout, 3600) == 0);
	inet_pton(AF_INET6, "2001:db8::1", &i6);
	assert(radcli_avp_add_ip6(l, d_v6, &i6, 0) == 0);
	assert(radcli_avp_add_str(l, d_agent, "circuit-42") == 0); /* VSA */

	{
		size_t n_enc = 1; /* poisoned; radcli_avp_encode() must zero it */

		n = radcli_avp_encode(ctx, l, NULL, NULL, buf, sizeof(buf), &n_enc);
		if (n <= 0) {
			fprintf(stderr, "error: radcli_avp_encode() failed (%d)\n", n);
			exit(1);
		}
		if (n_enc != 0) {
			fprintf(stderr, "error: n_encrypted was %zu for a list with no "
					"RFC 2865 SS5.2-flagged attribute\n", n_enc);
			exit(1);
		}
	}

	if (radcli_avp_decode(ctx, NULL, NULL, buf, (size_t)n, 0, &decoded) != 0) {
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
	if (a == NULL || radcli_avp_get_ip6(a, &i6out, &prefix) != 0 ||
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

	/* --- round trip: RADCLI_TYPE_INTEGER64, 8-octet network byte order.
	 * A value with both halves non-zero (0x0123456789abcdef) exercises the
	 * full width -- either half being byte-swapped or dropped would
	 * corrupt the other half's bit pattern too, given how the halves are
	 * combined, unlike an all-zero-high-word value that could hide a
	 * dropped-high-word bug. --- */

	{
		const radcli_attr_def *d_int64 = radcli_dict_lookup(ctx, "Test-Int64");
		radcli_avp_list *l4 = radcli_avp_list_new();
		uint64_t v64;

		assert(d_int64 != NULL && l4 != NULL);
		assert(radcli_avp_add_uint64(l4, d_int64, UINT64_C(0x0123456789abcdef)) == 0);

		n = radcli_avp_encode(ctx, l4, NULL, NULL, buf, sizeof(buf), NULL);
		if (n != 10 /* type(1) + len(1) + 8 octets */) {
			fprintf(stderr, "error: Test-Int64 encoded to %d bytes, expected 10\n", n);
			exit(1);
		}
		/* Network byte order, high word first: 01 23 45 67 89 ab cd ef. */
		{
			static const uint8_t want[] = {
				0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			};
			if (memcmp(buf + 2, want, sizeof(want)) != 0) {
				fprintf(stderr, "error: Test-Int64 wire encoding is not "
						"big-endian, or halves are swapped\n");
				exit(1);
			}
		}

		if (radcli_avp_decode(ctx, NULL, NULL, buf, (size_t)n, 0, &decoded) != 0) {
			fprintf(stderr, "error: radcli_avp_decode() failed on Test-Int64\n");
			exit(1);
		}
		a = radcli_avp_get(decoded, d_int64, 0);
		if (a == NULL || radcli_avp_get_uint64(a, &v64) != 0 ||
		    v64 != UINT64_C(0x0123456789abcdef)) {
			fprintf(stderr, "error: Test-Int64 did not round-trip through the wire codec\n");
			exit(1);
		}
		radcli_avp_list_free(l4);
		radcli_avp_list_free(decoded);
	}

	/* --- round trip: RADCLI_TYPE_IFID, 8-octet network byte order --
	 * identical assertion shape to the RADCLI_TYPE_INTEGER64 case above,
	 * confirming ifid shares the same wire codec branch. --- */

	{
		const radcli_attr_def *d_ifid = radcli_dict_lookup(ctx, "Test-Ifid");
		radcli_avp_list *l5 = radcli_avp_list_new();
		uint64_t v64;

		assert(d_ifid != NULL && l5 != NULL);
		assert(radcli_avp_add_uint64(l5, d_ifid, UINT64_C(0xfe80000000000001)) == 0);

		n = radcli_avp_encode(ctx, l5, NULL, NULL, buf, sizeof(buf), NULL);
		if (n != 10 /* type(1) + len(1) + 8 octets */) {
			fprintf(stderr, "error: Test-Ifid encoded to %d bytes, expected 10\n", n);
			exit(1);
		}
		{
			static const uint8_t want[] = {
				0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			};
			if (memcmp(buf + 2, want, sizeof(want)) != 0) {
				fprintf(stderr, "error: Test-Ifid wire encoding is not "
						"big-endian, or halves are swapped\n");
				exit(1);
			}
		}

		if (radcli_avp_decode(ctx, NULL, NULL, buf, (size_t)n, 0, &decoded) != 0) {
			fprintf(stderr, "error: radcli_avp_decode() failed on Test-Ifid\n");
			exit(1);
		}
		a = radcli_avp_get(decoded, d_ifid, 0);
		if (a == NULL || radcli_avp_get_uint64(a, &v64) != 0 ||
		    v64 != UINT64_C(0xfe80000000000001)) {
			fprintf(stderr, "error: Test-Ifid did not round-trip through the wire codec\n");
			exit(1);
		}
		radcli_avp_list_free(l5);
		radcli_avp_list_free(decoded);
	}

	/* --- decode: an integer64/ifid attribute with the wrong wire length is
	 * skipped outright, not stored raw for a getter to reject later; the
	 * four-octet numeric types (integer/ipaddr/date) follow the same
	 * strict-length policy --- */

	{
		radcli_avp_list *skipped;
		/* Test-Int64 (251) with a 7-byte value: one short of the required 8. */
		uint8_t short_int64[] = { 251, 9, 1, 2, 3, 4, 5, 6, 7 };
		/* Test-Ifid (252), same wrong-length shape. */
		uint8_t short_ifid[] = { 252, 9, 1, 2, 3, 4, 5, 6, 7 };
		/* Session-Timeout (27, integer) with a 3-byte value: one short of
		 * the required 4. */
		uint8_t short_int[] = { 27, 5, 1, 2, 3 };

		if (radcli_avp_decode(ctx, NULL, NULL, short_int64, sizeof(short_int64), 0, &skipped) != 0) {
			fprintf(stderr, "error: a wrong-length integer64 attribute was a "
					"hard decode error\n");
			exit(1);
		}
		if (!avp_list_empty(skipped)) {
			fprintf(stderr, "error: a wrong-length integer64 attribute was not skipped\n");
			exit(1);
		}
		radcli_avp_list_free(skipped);

		if (radcli_avp_decode(ctx, NULL, NULL, short_ifid, sizeof(short_ifid), 0, &skipped) != 0) {
			fprintf(stderr, "error: a wrong-length ifid attribute was a "
					"hard decode error\n");
			exit(1);
		}
		if (!avp_list_empty(skipped)) {
			fprintf(stderr, "error: a wrong-length ifid attribute was not skipped\n");
			exit(1);
		}
		radcli_avp_list_free(skipped);

		if (radcli_avp_decode(ctx, NULL, NULL, short_int, sizeof(short_int), 0, &skipped) != 0) {
			fprintf(stderr, "error: a wrong-length integer attribute was a "
					"hard decode error\n");
			exit(1);
		}
		if (!avp_list_empty(skipped)) {
			fprintf(stderr, "error: a wrong-length integer attribute was not skipped\n");
			exit(1);
		}
		radcli_avp_list_free(skipped);
	}

	/* --- decode: hard framing errors abort the whole decode --- */

	{
		radcli_avp_list *bad;
		uint8_t too_short[] = { 1 };               /* pb_len() < 2 */
		uint8_t len_lt_2[]  = { 1, 1 };             /* attrlen field < 2 */
		uint8_t overflow[]  = { 1, 10, 'a' };       /* attrlen > remaining bytes */

		if (radcli_avp_decode(ctx, NULL, NULL, too_short, sizeof(too_short), 0, &bad) == 0) {
			fprintf(stderr, "error: a 1-byte attribute region was accepted\n");
			exit(1);
		}
		if (radcli_avp_decode(ctx, NULL, NULL, len_lt_2, sizeof(len_lt_2), 0, &bad) == 0) {
			fprintf(stderr, "error: an attribute with length field < 2 was accepted\n");
			exit(1);
		}
		if (radcli_avp_decode(ctx, NULL, NULL, overflow, sizeof(overflow), 0, &bad) == 0) {
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

		if (radcli_avp_decode(ctx, NULL, NULL, unknown_attr, sizeof(unknown_attr), 0, &skipped) != 0) {
			fprintf(stderr, "error: an unrecognised attribute was a hard decode error\n");
			exit(1);
		}
		if (!avp_list_empty(skipped)) {
			fprintf(stderr, "error: an unrecognised attribute was not skipped\n");
			exit(1);
		}
		radcli_avp_list_free(skipped);

		if (radcli_avp_decode(ctx, NULL, NULL, short_vsa, sizeof(short_vsa), 0, &skipped) != 0) {
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

		if (radcli_avp_decode(ctx, NULL, NULL, unknown_vendor_vsa, sizeof(unknown_vendor_vsa), 0, &skipped) != 0) {
			fprintf(stderr, "error: an unrecognised vendor was a hard decode error\n");
			exit(1);
		}
		if (!avp_list_empty(skipped)) {
			fprintf(stderr, "error: an unrecognised vendor's VSA was not skipped\n");
			exit(1);
		}
		radcli_avp_list_free(skipped);
	}

	/* --- decode: RFC 2868 SS3.5 / RFC 2548 SS2.4.2 salt-encryption is
	 * transparently reversed for an "encrypt=Tunnel-Password" attribute.
	 * Vectors below
	 * were computed independently in Python (hashlib.md5), not derived
	 * from this implementation, so this checks the algorithm is actually
	 * RFC-correct rather than merely self-consistent. secret="testing123",
	 * request_authenticator = bytes 0x00..0x0f, salt = 0x8a7c. --- */

	{
		static const char secret[] = "testing123";
		static const uint8_t req_auth[AUTH_VECTOR_LEN] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		};
		radcli_avp_list *dec;
		const radcli_avp *a2;
		const void *raw2;
		size_t rawlen2;

		/* Tunnel-Password: Tag(0x11) + Salt(0x8a7c) + one 16-byte block
		 * decrypting to Data-Length(5) + "hello" + 10 zero pad bytes. */
		{
			uint8_t attrval[] = {
				0x11, 0x8a, 0x7c,
				0x63, 0x53, 0xe3, 0x9c, 0x38, 0x78, 0x97, 0xb1,
				0xc9, 0x15, 0xcb, 0xa4, 0xa3, 0xe3, 0xda, 0x9f,
			};
			uint8_t pkt[2 + sizeof(attrval)];

			pkt[0] = 69; /* Tunnel-Password */
			pkt[1] = (uint8_t)sizeof(pkt);
			memcpy(pkt + 2, attrval, sizeof(attrval));

			if (radcli_avp_decode(ctx, secret, req_auth, pkt, sizeof(pkt), 0, &dec) != 0) {
				fprintf(stderr, "error: Tunnel-Password salt-decrypt decode failed\n");
				exit(1);
			}
			a2 = radcli_avp_get(dec, d_tunnelpw, 0);
			if (a2 == NULL || radcli_avp_get_bytes(a2, &raw2, &rawlen2) != 0 ||
			    rawlen2 != 5 || memcmp(raw2, "hello", 5) != 0) {
				fprintf(stderr, "error: Tunnel-Password did not decrypt to "
						"the expected plaintext\n");
				exit(1);
			}
			radcli_avp_list_free(dec);
		}

		/* MS-MPPE-Send-Key (VSA, no Tag): Salt(0x8a7c) + two 16-byte
		 * blocks decrypting to Key-Length(20) + bytes 0x00..0x13 + 11
		 * zero pad bytes. Wrapped in a Vendor-Specific(26) envelope. */
		{
			uint8_t cipher[] = {
				0x8a, 0x7c,
				0x72, 0x3b, 0x87, 0xf2, 0x57, 0x13, 0x92, 0xb7,
				0xce, 0x1d, 0xc2, 0xae, 0xa8, 0xef, 0xd7, 0x91,
				0x94, 0xff, 0xec, 0x80, 0x16, 0x7c, 0xb5, 0xc9,
				0xb2, 0xca, 0xed, 0x00, 0x49, 0x59, 0x3d, 0x88,
			};
			uint8_t vsa[4 + 2 + sizeof(cipher)];
			uint8_t pkt[2 + sizeof(vsa)];
			uint32_t vendor_be = htonl(311);
			int i;

			memcpy(vsa, &vendor_be, 4);
			vsa[4] = 16; /* MS-MPPE-Send-Key */
			vsa[5] = (uint8_t)(2 + sizeof(cipher));
			memcpy(vsa + 6, cipher, sizeof(cipher));

			pkt[0] = 26; /* Vendor-Specific */
			pkt[1] = (uint8_t)sizeof(pkt);
			memcpy(pkt + 2, vsa, sizeof(vsa));

			if (radcli_avp_decode(ctx, secret, req_auth, pkt, sizeof(pkt), 0, &dec) != 0) {
				fprintf(stderr, "error: MS-MPPE-Send-Key salt-decrypt decode failed\n");
				exit(1);
			}
			a2 = radcli_avp_get(dec, d_mppe, 0);
			if (a2 == NULL || radcli_avp_get_bytes(a2, &raw2, &rawlen2) != 0 || rawlen2 != 20) {
				fprintf(stderr, "error: MS-MPPE-Send-Key did not decrypt to a "
						"20-byte key\n");
				exit(1);
			}
			for (i = 0; i < 20; i++) {
				if (((const unsigned char *)raw2)[i] != (unsigned char)i) {
					fprintf(stderr, "error: MS-MPPE-Send-Key decrypted key "
							"content mismatch at byte %d\n", i);
					exit(1);
				}
			}
			radcli_avp_list_free(dec);
		}

		/* Wrong secret: same ciphertext, must not decrypt to the same
		 * plaintext (and must not crash or misparse). */
		{
			uint8_t attrval[] = {
				0x11, 0x8a, 0x7c,
				0x63, 0x53, 0xe3, 0x9c, 0x38, 0x78, 0x97, 0xb1,
				0xc9, 0x15, 0xcb, 0xa4, 0xa3, 0xe3, 0xda, 0x9f,
			};
			uint8_t pkt[2 + sizeof(attrval)];

			pkt[0] = 69;
			pkt[1] = (uint8_t)sizeof(pkt);
			memcpy(pkt + 2, attrval, sizeof(attrval));

			assert(radcli_avp_decode(ctx, "wrong-secret", req_auth, pkt, sizeof(pkt), 0, &dec) == 0);
			a2 = radcli_avp_get(dec, d_tunnelpw, 0);
			if (a2 != NULL && radcli_avp_get_bytes(a2, &raw2, &rawlen2) == 0 &&
			    rawlen2 == 5 && memcmp(raw2, "hello", 5) == 0) {
				fprintf(stderr, "error: decrypt with the wrong secret produced "
						"the correct plaintext\n");
				exit(1);
			}
			radcli_avp_list_free(dec);
		}

		/* No secret supplied: the attribute is skipped, not garbled. */
		{
			uint8_t attrval[] = {
				0x11, 0x8a, 0x7c,
				0x63, 0x53, 0xe3, 0x9c, 0x38, 0x78, 0x97, 0xb1,
				0xc9, 0x15, 0xcb, 0xa4, 0xa3, 0xe3, 0xda, 0x9f,
			};
			uint8_t pkt[2 + sizeof(attrval)];

			pkt[0] = 69;
			pkt[1] = (uint8_t)sizeof(pkt);
			memcpy(pkt + 2, attrval, sizeof(attrval));

			if (radcli_avp_decode(ctx, NULL, NULL, pkt, sizeof(pkt), 0, &dec) != 0) {
				fprintf(stderr, "error: missing secret was a hard decode error\n");
				exit(1);
			}
			if (!avp_list_empty(dec)) {
				fprintf(stderr, "error: a salt-encrypted attribute was decoded "
						"without a secret\n");
				exit(1);
			}
			radcli_avp_list_free(dec);
		}
	}

	/* --- lib/dict.c's encrypt= parser, exercised against the real,
	 * shipped etc/dictionary rather than a hand-written fixture --- */

	{
		radcli_ctx *ctx2 = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		const radcli_attr_def *dd;
		char dict_path[PATH_MAX];
		const char *sd = getenv("srcdir");

		/* "../etc/dictionary" is only valid relative to tests/ (srcdir),
		 * not to whatever directory the test happens to be run from --
		 * e.g. under "meson dist"/distcheck, the build directory is not
		 * a child of the unpacked source tree, so a plain relative path
		 * resolved against the process's cwd does not find it. */
		snprintf(dict_path, sizeof(dict_path), "%s/../etc/dictionary", sd ? sd : ".");

		assert(ctx2 != NULL);
		if (radcli_ctx_read_dictionary(ctx2, dict_path) != 0) {
			fprintf(stderr, "error: %s failed to load "
					"(syntax error introduced by an encrypt= edit?)\n", dict_path);
			exit(1);
		}

		dd = radcli_dict_lookup(ctx2, "Tunnel-Password");
		if (dd == NULL || def_encrypt_type(ctx2, dd) != 2) {
			fprintf(stderr, "error: etc/dictionary's Tunnel-Password is not "
					"marked encrypt=Tunnel-Password\n");
			exit(1);
		}

		dd = radcli_dict_lookup(ctx2, "MS-MPPE-Send-Key");
		if (dd == NULL || def_encrypt_type(ctx2, dd) != 2) {
			fprintf(stderr, "error: etc/dictionary's MS-MPPE-Send-Key is not "
					"marked encrypt=Tunnel-Password\n");
			exit(1);
		}

		dd = radcli_dict_lookup(ctx2, "MS-MPPE-Recv-Key");
		if (dd == NULL || def_encrypt_type(ctx2, dd) != 2) {
			fprintf(stderr, "error: etc/dictionary's MS-MPPE-Recv-Key is not "
					"marked encrypt=Tunnel-Password\n");
			exit(1);
		}

		/* An ordinary attribute must not come back flagged. */
		dd = radcli_dict_lookup(ctx2, "User-Name");
		if (dd == NULL || def_encrypt_type(ctx2, dd) != 0) {
			fprintf(stderr, "error: User-Name was unexpectedly reported "
					"as encrypt-flagged\n");
			exit(1);
		}

		radcli_ctx_free(ctx2);
	}

	/* --- radcli_dict_flags_by_id() (def_encrypt_type()/def_has_tag() above)
	 * match by attribute id (attribute id + vendor), not node identity:
	 * two attribute definitions for the same wire attribute -- whether the
	 * built-in "Password"/"User-Password" id-2 alias pair (etc/dictionary),
	 * or a later-loaded dictionary redefining an already-flagged id -- must
	 * both see the flag, not just whichever DICT_ATTR happened to register
	 * it. See the discussion in the commit introducing this. --- */

	{
		radcli_ctx *ctx4 = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		const radcli_attr_def *pw;
		char dict_path[PATH_MAX];
		const char *sd = getenv("srcdir");

		snprintf(dict_path, sizeof(dict_path), "%s/../etc/dictionary", sd ? sd : ".");

		assert(ctx4 != NULL);
		if (radcli_ctx_read_dictionary(ctx4, dict_path) != 0) {
			fprintf(stderr, "error: %s failed to load\n", dict_path);
			exit(1);
		}

		/* "Password" (etc/dictionary's legacy Cistron-era alias for id 2)
		 * carries no encrypt= of its own -- only "User-Password" does. A
		 * pointer-identity match would report it unencrypted. */
		pw = radcli_dict_lookup(ctx4, "Password");
		if (pw == NULL || def_encrypt_type(ctx4, pw) != 1) {
			fprintf(stderr, "error: the \"Password\" id-2 alias was not "
					"reported as encrypt=User-Password\n");
			exit(1);
		}

		/* A dictionary loaded afterwards that redefines Tunnel-Password (69)
		 * without repeating encrypt=/has_tag must not turn off encryption
		 * for it: radcli_dict_lookup() now resolves "Tunnel-Password" to
		 * this new, unflagged attribute definition (most-recently-loaded
		 * wins), but the built-in definition's dictionary_encrypt entry for
		 * id 69 must still be found by value. */
		{
			static const char shadow_dict[] =
"ATTRIBUTE	Tunnel-Password		69	string\n";
			const radcli_attr_def *tp;

			if (radcli_ctx_read_dictionary_from_buffer(ctx4, shadow_dict, sizeof(shadow_dict) - 1) != 0) {
				fprintf(stderr, "error: failed to load the shadowing dictionary\n");
				exit(1);
			}

			tp = radcli_dict_lookup(ctx4, "Tunnel-Password");
			if (tp == NULL || def_encrypt_type(ctx4, tp) != 2) {
				fprintf(stderr, "error: a Tunnel-Password redefinition without "
						"encrypt= silently disabled encryption for id 69\n");
				exit(1);
			}
		}

		radcli_ctx_free(ctx4);
	}

	/* --- lib/dict.c's uint32/has_tag/encrypt=<name> grammar, exercised
	 * against a verbatim excerpt of FreeRADIUS's own
	 * share/dictionary/radius/dictionary.rfc2868 (fetched from the
	 * FreeRADIUS-server master branch on GitHub), not a paraphrase of it --
	 * proves radcli can load the real file, not just a fixture shaped like
	 * it. Tabs and spelling match the upstream file exactly. --- */

	{
		static const char rfc2868_dict[] =
"ATTRIBUTE	Tunnel-Type				64	uint32	has_tag\n"
"ATTRIBUTE	Tunnel-Medium-Type			65	uint32	has_tag\n"
"ATTRIBUTE	Tunnel-Client-Endpoint			66	string	has_tag\n"
"ATTRIBUTE	Tunnel-Server-Endpoint			67	string	has_tag\n"
"ATTRIBUTE	Tunnel-Password				69	string	has_tag,encrypt=Tunnel-Password\n"
"ATTRIBUTE	Tunnel-Private-Group-Id			81	string	has_tag\n"
"ATTRIBUTE	Tunnel-Assignment-Id			82	string	has_tag\n"
"ATTRIBUTE	Tunnel-Preference			83	uint32	has_tag\n"
"ATTRIBUTE	Tunnel-Client-Auth-Id			90	string	has_tag\n"
"ATTRIBUTE	Tunnel-Server-Auth-Id			91	string	has_tag\n";
		radcli_ctx *ctx3 = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		const radcli_attr_def *dt, *dp, *dc;
		radcli_avp_list *dec3;
		const radcli_avp *a3;

		assert(ctx3 != NULL);
		if (radcli_ctx_read_dictionary_from_buffer(ctx3, rfc2868_dict, sizeof(rfc2868_dict)) != 0) {
			fprintf(stderr, "error: real dictionary.rfc2868 excerpt failed to load\n");
			exit(1);
		}

		/* uint32 is a PW_TYPE_INTEGER synonym, same as ipaddr/ipv4addr. */
		dt = radcli_dict_lookup(ctx3, "Tunnel-Type");
		if (dt == NULL || radcli_attr_def_type(dt) != RADCLI_TYPE_INTEGER) {
			fprintf(stderr, "error: Tunnel-Type (uint32) did not resolve to "
					"RADCLI_TYPE_INTEGER\n");
			exit(1);
		}
		if (def_has_tag(ctx3, dt) != 1 ||
		    def_encrypt_type(ctx3, dt) != 0) {
			fprintf(stderr, "error: Tunnel-Type should be has_tag only, "
					"not encrypt-flagged\n");
			exit(1);
		}

		/* has_tag alone, no encrypt=, on a plain string attribute. */
		dc = radcli_dict_lookup(ctx3, "Tunnel-Client-Endpoint");
		if (dc == NULL || def_has_tag(ctx3, dc) != 1 ||
		    def_encrypt_type(ctx3, dc) != 0) {
			fprintf(stderr, "error: Tunnel-Client-Endpoint should be has_tag "
					"only\n");
			exit(1);
		}

		/* "has_tag,encrypt=Tunnel-Password" (the real file's own token
		 * order -- flags first, encrypt= second, the reverse of this test's
		 * other fixtures) must parse identically regardless of order. */
		dp = radcli_dict_lookup(ctx3, "Tunnel-Password");
		if (dp == NULL || def_encrypt_type(ctx3, dp) != 2 ||
		    def_has_tag(ctx3, dp) != 1) {
			fprintf(stderr, "error: Tunnel-Password (encrypt=Tunnel-Password) "
					"did not resolve to encrypt_type 2 with has_tag\n");
			exit(1);
		}

		/* Decrypt round-trip using a Tunnel-Password definition loaded from
		 * this real upstream excerpt, not radcli's own fixture: same wire
		 * bytes and vectors as the earlier test, must decode to the same
		 * plaintext -- the real file's grammar is functionally equivalent,
		 * not just independently parseable. */
		{
			static const char secret[] = "testing123";
			static const uint8_t req_auth[AUTH_VECTOR_LEN] = {
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			};
			uint8_t attrval[] = {
				0x11, 0x8a, 0x7c,
				0x63, 0x53, 0xe3, 0x9c, 0x38, 0x78, 0x97, 0xb1,
				0xc9, 0x15, 0xcb, 0xa4, 0xa3, 0xe3, 0xda, 0x9f,
			};
			uint8_t pkt[2 + sizeof(attrval)];
			const void *raw3;
			size_t rawlen3;

			pkt[0] = 69; /* Tunnel-Password */
			pkt[1] = (uint8_t)sizeof(pkt);
			memcpy(pkt + 2, attrval, sizeof(attrval));

			if (radcli_avp_decode(ctx3, secret, req_auth, pkt, sizeof(pkt), 0, &dec3) != 0) {
				fprintf(stderr, "error: Tunnel-Password decode failed against "
						"the dictionary.rfc2868 excerpt\n");
				exit(1);
			}
			a3 = radcli_avp_get(dec3, dp, 0);
			if (a3 == NULL || radcli_avp_get_bytes(a3, &raw3, &rawlen3) != 0 ||
			    rawlen3 != 5 || memcmp(raw3, "hello", 5) != 0) {
				fprintf(stderr, "error: Tunnel-Password loaded via "
						"encrypt=Tunnel-Password did not decrypt correctly\n");
				exit(1);
			}
			radcli_avp_list_free(dec3);
		}

		radcli_ctx_free(ctx3);
	}

	/* --- lib/dict.c: an unrecognised encrypt=<name> is still rejected, and
	 * so is the old numeric spelling -- there is exactly one accepted
	 * spelling of this scheme, matching FreeRADIUS's own dictionaries, not
	 * two ways to write the same thing. --- */

	{
		static const char bogus_dict[] =
			"ATTRIBUTE	Foo	1	string	encrypt=Bogus-Name\n";
		static const char numeric_dict[] =
			"ATTRIBUTE	Foo	1	string	encrypt=2\n";
		radcli_ctx *ctx4 = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		radcli_ctx *ctx5 = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);

		assert(ctx4 != NULL && ctx5 != NULL);
		if (radcli_ctx_read_dictionary_from_buffer(ctx4, bogus_dict, sizeof(bogus_dict)) == 0) {
			fprintf(stderr, "error: encrypt=Bogus-Name was accepted\n");
			exit(1);
		}
		if (radcli_ctx_read_dictionary_from_buffer(ctx5, numeric_dict, sizeof(numeric_dict)) == 0) {
			fprintf(stderr, "error: the old numeric encrypt=2 spelling was "
					"accepted (only encrypt=Tunnel-Password is)\n");
			exit(1);
		}
		radcli_ctx_free(ctx4);
		radcli_ctx_free(ctx5);
	}

	/* --- encode: RFC 2865 SS5.2 User-Password encryption, against vectors
	 * computed independently in Python (hashlib.md5), covering one cipher
	 * block (7-byte password, padded to 16) and two (20-byte password,
	 * padded to 32). secret/authenticator match the salt-decrypt vectors
	 * above. --- */

	{
		static const char secret[] = "testing123";
		static const uint8_t req_auth[AUTH_VECTOR_LEN] = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		};

		{
			static const uint8_t want_cipher[] = {
				0xe5, 0xdd, 0x6a, 0xb8, 0x47, 0x89, 0x5b, 0x1a,
				0x10, 0x46, 0x07, 0x24, 0x00, 0x14, 0x82, 0x8b,
			};
			radcli_avp_list *l3 = radcli_avp_list_new();
			int len;
			size_t n_enc = 0;

			assert(radcli_avp_add_str(l3, d_pass, "s3cr3t!") == 0);
			len = radcli_avp_encode(ctx, l3, secret, req_auth, buf, sizeof(buf), &n_enc);
			if (len != 2 + (int)sizeof(want_cipher) ||
			    buf[0] != 2 /* User-Password */ ||
			    buf[1] != (uint8_t)len ||
			    memcmp(buf + 2, want_cipher, sizeof(want_cipher)) != 0) {
				fprintf(stderr, "error: User-Password (1 block) did not "
						"encrypt to the expected ciphertext\n");

				exit(1);
			}
			if (n_enc != 1) {
				fprintf(stderr, "error: n_encrypted was %zu, want 1\n", n_enc);
				exit(1);
			}
			radcli_avp_list_free(l3);
		}

		{
			static const uint8_t want_cipher[] = {
				0xf7, 0x8c, 0x6a, 0xae, 0x11, 0x9b, 0x1d, 0x72,
				0x79, 0x2c, 0x6c, 0x48, 0x6d, 0x7a, 0xed, 0xfb,
				0xa7, 0x74, 0xce, 0xa9, 0xec, 0x04, 0xf9, 0x9a,
				0xf4, 0x66, 0x2f, 0x74, 0xd7, 0x8f, 0xd5, 0x3d,
			};
			radcli_avp_list *l3 = radcli_avp_list_new();
			int len;
			size_t n_enc = 0;

			assert(radcli_avp_add_str(l3, d_pass, "abcdefghijklmnopqrst") == 0);
			len = radcli_avp_encode(ctx, l3, secret, req_auth, buf, sizeof(buf), &n_enc);
			if (len != 2 + (int)sizeof(want_cipher) ||
			    memcmp(buf + 2, want_cipher, sizeof(want_cipher)) != 0) {
				fprintf(stderr, "error: User-Password (2 blocks) did not "
						"encrypt to the expected ciphertext\n");

				exit(1);
			}
			if (n_enc != 1) {
				fprintf(stderr, "error: n_encrypted was %zu, want 1\n", n_enc);
				exit(1);
			}
			radcli_avp_list_free(l3);
		}

		/* Longer than AUTH_PASS_LEN (128) is rejected, not truncated. */
		{
			radcli_avp_list *l3 = radcli_avp_list_new();
			char toolong[AUTH_PASS_LEN + 2]; /* AUTH_PASS_LEN+1 'x's, one over the limit */

			memset(toolong, 'x', sizeof(toolong) - 1);
			toolong[sizeof(toolong) - 1] = '\0';
			assert(strlen(toolong) == AUTH_PASS_LEN + 1);
			assert(radcli_avp_add_str(l3, d_pass, toolong) == 0);
			if (radcli_avp_encode(ctx, l3, secret, req_auth, buf, sizeof(buf), NULL) >= 0) {
				fprintf(stderr, "error: an over-length User-Password was "
						"accepted instead of rejected\n");

				exit(1);
			}
			radcli_avp_list_free(l3);
		}
	}

	/* --- encode: User-Password without a secret is refused, never sent as
	 * accidental plaintext --- */

	{
		radcli_avp_list *l2 = radcli_avp_list_new();

		assert(radcli_avp_add_str(l2, d_pass, "hunter2") == 0);
		if (radcli_avp_encode(ctx, l2, NULL, NULL, buf, sizeof(buf), NULL) >= 0) {
			fprintf(stderr, "error: radcli_avp_encode() sent User-Password in "
					"plaintext instead of refusing it\n");
			exit(1);
		}
		radcli_avp_list_free(l2);
	}

	radcli_ctx_free(ctx);

	printf("radcli2 avp codec: all tests passed\n");
	return 0;
}
