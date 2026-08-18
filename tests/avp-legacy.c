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

/* Unit test for radcli_avp_list_to_value_pairs()/radcli_value_pairs_to_avp_list()
 * (lib/avp.c): the projection between VALUE_PAIR and radcli_avp_list. Both
 * are internal-only (declared in lib/avp.h, not exported -- see
 * that file's comment), so this links against libradcli_static, the same
 * pattern tests/pack.c and tests/avp-codec.c already use. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include <avp.h> /* radcli_avp_list_to_value_pairs(), radcli_value_pairs_to_avp_list() */

static char test_dict[] =
"ATTRIBUTE	User-Name		1	string\n"
"ATTRIBUTE	NAS-IP-Address		4	ipaddr\n"
"ATTRIBUTE	Session-Timeout		27	integer\n"
"ATTRIBUTE	Framed-IPv6-Address	168	ipv6addr\n"
"ATTRIBUTE	Tunnel-Password		69	string encrypt=Tunnel-Password\n"
"VENDOR          DSL-Forum       3561     Large\n"
"ATTRIBUTE	Agent-Circuit-Id		1	string DSL-Forum\n";

int main(int argc, char **argv)
{
	rc_handle *rh;
	VALUE_PAIR *vp, *round;
	radcli_avp_list *l;
	const radcli_attr_def *d_user, *d_nasip, *d_timeout, *d_v6, *d_tunnelpw, *d_agent;
	struct in_addr ia;
	struct in6_addr i6;

	rh = rc_new();
	assert(rh != NULL);
	rc_config_init(rh);
	assert(rc_read_dictionary_from_buffer(rh, test_dict, sizeof(test_dict)) == 0);

	d_user = radcli_dict_lookup(rh, "User-Name");
	d_nasip = radcli_dict_lookup(rh, "NAS-IP-Address");
	d_timeout = radcli_dict_lookup(rh, "Session-Timeout");
	d_v6 = radcli_dict_lookup(rh, "Framed-IPv6-Address");
	d_tunnelpw = radcli_dict_lookup(rh, "Tunnel-Password");
	d_agent = radcli_dict_lookup(rh, "Agent-Circuit-Id");
	assert(d_user && d_nasip && d_timeout && d_v6 && d_tunnelpw && d_agent);

	/* --- VALUE_PAIR -> radcli_avp_list -> VALUE_PAIR round-trips
	 * byte-identically for everything VALUE_PAIR can hold --- */

	vp = NULL;
	assert(rc_avpair_add(rh, &vp, PW_USER_NAME, "alice", -1, 0) != NULL);
	inet_pton(AF_INET, "192.0.2.7", &ia);
	{
		uint32_t hostval = ntohl(ia.s_addr);
		assert(rc_avpair_add(rh, &vp, PW_NAS_IP_ADDRESS, &hostval, 0, 0) != NULL);
	}
	{
		uint32_t timeout = 3600;
		assert(rc_avpair_add(rh, &vp, PW_SESSION_TIMEOUT, &timeout, 0, 0) != NULL);
	}
	inet_pton(AF_INET6, "2001:db8::1", &i6);
	assert(rc_avpair_add(rh, &vp, PW_FRAMED_IPV6_ADDRESS, &i6, 16, 0) != NULL);
	assert(rc_avpair_add(rh, &vp, 1, "circuit-42", -1, 3561) != NULL); /* Agent-Circuit-Id, VSA */

	if (radcli_value_pairs_to_avp_list(rh, vp, &l) != 0) {
		fprintf(stderr, "error: radcli_value_pairs_to_avp_list() failed\n");
		exit(1);
	}

	{
		const radcli_avp *a;
		const void *raw;
		size_t rawlen;
		uint32_t u;
		struct in6_addr i6out;
		unsigned prefix;

		a = radcli_avp_get(l, d_user, 0);
		if (a == NULL || radcli_avp_get_bytes(a, &raw, &rawlen) != 0 ||
		    rawlen != 5 || memcmp(raw, "alice", 5) != 0) {
			fprintf(stderr, "error: User-Name did not project to radcli_avp_list\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_nasip, 0);
		if (a == NULL || radcli_avp_get_uint32(a, &u) != 0 || u != ntohl(ia.s_addr)) {
			fprintf(stderr, "error: NAS-IP-Address did not project to radcli_avp_list\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_timeout, 0);
		if (a == NULL || radcli_avp_get_uint32(a, &u) != 0 || u != 3600) {
			fprintf(stderr, "error: Session-Timeout did not project to radcli_avp_list\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_v6, 0);
		if (a == NULL || radcli_avp_get_in6(a, &i6out, &prefix) != 0 ||
		    memcmp(&i6out, &i6, 16) != 0 || prefix != 128) {
			fprintf(stderr, "error: Framed-IPv6-Address did not project to radcli_avp_list\n");
			exit(1);
		}
		a = radcli_avp_get(l, d_agent, 0);
		if (a == NULL || radcli_avp_get_bytes(a, &raw, &rawlen) != 0 ||
		    rawlen != 10 || memcmp(raw, "circuit-42", 10) != 0) {
			fprintf(stderr, "error: Agent-Circuit-Id (VSA) did not project to radcli_avp_list\n");
			exit(1);
		}
	}

	if (radcli_avp_list_to_value_pairs(rh, l, &round) != 0) {
		fprintf(stderr, "error: radcli_avp_list_to_value_pairs() failed\n");
		exit(1);
	}

	{
		VALUE_PAIR *a, *b;

		for (a = vp, b = round; a != NULL && b != NULL; a = a->next, b = b->next) {
			/* Only lvalue bytes of strvalue are meaningful for a
			 * string-like type; the trailing, unused portion of the
			 * 254-byte buffer is uninitialised in a rc_avpair_new()-built
			 * VALUE_PAIR (malloc(), not calloc()) and must not be
			 * compared. For an INTEGER/IPADDR/DATE-typed pair strvalue
			 * is not used at all -- lvalue alone carries the value. */
			int string_like = (a->type == PW_TYPE_STRING || a->type == PW_TYPE_IPV6ADDR ||
					   a->type == PW_TYPE_IPV6PREFIX);

			if (a->attribute != b->attribute || a->type != b->type ||
			    a->lvalue != b->lvalue ||
			    (string_like && memcmp(a->strvalue, b->strvalue, a->lvalue) != 0)) {
				fprintf(stderr, "error: round-tripped VALUE_PAIR list differs "
						"from the original at %s\n", a->name);
				exit(1);
			}
		}
		if (a != NULL || b != NULL) {
			fprintf(stderr, "error: round-tripped VALUE_PAIR list has a "
					"different length than the original\n");
			exit(1);
		}
	}

	rc_avpair_free(vp);
	rc_avpair_free(round);
	radcli_avp_list_free(l);

	/* --- radcli_avp_list -> VALUE_PAIR omits what does not fit, rather
	 * than truncating it or failing the whole projection --- */

	{
		radcli_avp_list *l2 = radcli_avp_list_new();
		char toolong[AUTH_STRING_LEN + 2];
		VALUE_PAIR *out;

		memset(toolong, 'x', sizeof(toolong) - 1);
		toolong[sizeof(toolong) - 1] = '\0';
		assert(strlen(toolong) == AUTH_STRING_LEN + 1);

		assert(radcli_avp_add_str(l2, d_user, "bob") == 0);
		assert(radcli_avp_add_bytes(l2, d_agent, toolong, strlen(toolong)) == 0);

		if (radcli_avp_list_to_value_pairs(rh, l2, &out) != 0) {
			fprintf(stderr, "error: projection with an over-long attribute failed "
					"entirely instead of omitting it\n");
			exit(1);
		}
		if (out == NULL || out->next != NULL) {
			fprintf(stderr, "error: expected exactly one VALUE_PAIR (User-Name); "
					"the over-long Agent-Circuit-Id should have been omitted\n");
			exit(1);
		}
		if (strcmp(out->name, "User-Name") != 0) {
			fprintf(stderr, "error: the surviving VALUE_PAIR is not User-Name\n");
			exit(1);
		}

		rc_avpair_free(out);
		radcli_avp_list_free(l2);
	}

	/* --- a decrypted attribute (already plaintext by the time it is a
	 * radcli_avp -- decrypt itself is tested in tests/avp-codec.c) projects
	 * to VALUE_PAIR as an ordinary string, with no re-encryption --- */

	{
		radcli_avp_list *l3 = radcli_avp_list_new();
		VALUE_PAIR *out;

		assert(radcli_avp_add_str(l3, d_tunnelpw, "already-plaintext") == 0);
		if (radcli_avp_list_to_value_pairs(rh, l3, &out) != 0 || out == NULL) {
			fprintf(stderr, "error: Tunnel-Password did not project to VALUE_PAIR\n");
			exit(1);
		}
		if (out->lvalue != strlen("already-plaintext") ||
		    memcmp(out->strvalue, "already-plaintext", out->lvalue) != 0) {
			fprintf(stderr, "error: Tunnel-Password's plaintext value was altered "
					"by the projection\n");
			exit(1);
		}

		rc_avpair_free(out);
		radcli_avp_list_free(l3);
	}

	rc_dict_free(rh);
	rc_destroy(rh);

	printf("radcli2 avp legacy projection: all tests passed\n");
	return 0;
}
