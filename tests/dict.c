/*
 * Copyright (c) 2020, Nikos Mavrogiannopoulos.  All rights reserved.
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

/* Unit test for radcli2.h's dictionary lookup API (radcli_dict_lookup()/
 * _lookup_oid()/_lookup_num()/_lookup_value(), radcli_attr_def_*(),
 * lib/dict2.c/lib/dict2-parse.c -- the canonical parser). radcli.h-only
 * coverage of the same parser through the legacy accessors
 * (rc_dict_findattr()/_findval()/_findvend()/_getval()/_getvend()/
 * _addattr()) lives in tests/dict-legacy.c instead -- split along the API
 * boundary (REQ-GEN-TEST-006, doc/requirements/general.md) rather than one
 * file mixing both. The parser-behavior fixtures shared with
 * tests/dict-legacy.c (malformed input rejection, long name/line handling,
 * dedup/conflict resolution) are duplicated here and verified through
 * radcli_dict_lookup()/radcli_ctx_read_dictionary_from_buffer() instead,
 * proving the same guarantees hold through both public entry points.
 *
 * Each fixture uses its own radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT)/
 * radcli_ctx_free() pair rather than reusing one context across reloads:
 * unlike rc_dict_free(rh), which clears a handle's dictionary for reuse,
 * radcli2.h has no equivalent "clear the dictionary, keep the context"
 * operation, so a fresh context per fixture is the radcli2-only way to get
 * an empty dictionary to reload into. RADCLI_CTX_NO_BUILTIN_DICT avoids any
 * collision between these fixtures' low attribute numbers and the built-in
 * RFC 2865/2866/2869 dictionary radcli_ctx_new(0) would otherwise load. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <radcli/radcli2.h>

char large_value_dict[] =
"ATTRIBUTE	Sip-Method		101	integer\n"
"ATTRIBUTE	Digest-Method		1065	string\n"
"ATTRIBUTE	LargeOne		17000	string\n";

/* Names longer than the old RC_NAME_LENGTH (32) limit: issue #112 */
char long_name_dict[] =
"ATTRIBUTE	WISPr-Session-Terminate-End-Of-Day              10	string\n"
"ATTRIBUTE	Airespace-Real-Time-Bandwidth-Average-Contract-Upstream	56	string\n";

char large_vendor_dict[] =
"\nVENDOR          Largeone       18311     Large\n"
"\n"
"ATTRIBUTE	Digest-Method		1065	string Largeone\n"
"ATTRIBUTE	LargeOne		17001	string Largeone\n";

/* Case-insensitive attrname match: commit 1e56a2c */
char case_insensitive_dict[] =
"ATTRIBUTE	Framed-Protocol		7	integer\n"
"VALUE	Framed-Protocol		PPP	1\n";

/* Malformed numeric fields ("101abc" instead of a pure digit string):
 * commit 790407f. Each must be rejected, not silently atoi()-truncated. */
char bad_attr_value_dict[] =
"ATTRIBUTE	Bad-Attr		101abc	integer\n";
char bad_value_value_dict[] =
"ATTRIBUTE	Framed-Protocol		7	integer\n"
"VALUE	Framed-Protocol		PPP	1x\n";
char bad_vendor_pec_dict[] =
"VENDOR          Bogus       18311x     Large\n";

/* radcli2.h dictionary lookup (radcli_dict_lookup*, radcli_attr_def_*) */
char radcli2_dict[] =
"ATTRIBUTE	Test-Std-Attr		250	integer\n"
"VENDOR          Testvendor       19999     Large\n"
"ATTRIBUTE	Test-Vendor-Attr		5	string Testvendor\n"
/* radcli_dict_lookup_value(): a second attribute reusing the VALUE name
 * "One" for a different number, proving the lookup is scoped by attribute
 * rather than matching the first "One" anywhere in the dictionary. */
"ATTRIBUTE	Test-Std-Attr2		251	integer\n"
"VALUE	Test-Std-Attr		One	1\n"
"VALUE	Test-Std-Attr		Two	2\n"
"VALUE	Test-Std-Attr2		One	100\n";

/* Phase 2: the "integer64" keyword. Deliberately declares Test-Int64-Attr
 * before Test-Int64-Gigawords (attr 253), the same order etc/dictionary's
 * real Acct-Input-Octets/-Gigawords pair uses -- the paired attribute is
 * looked up by id, not by pointer, precisely so this ordering is fine. */
char counter64_dict[] =
"ATTRIBUTE	Test-Int64-Attr		251	integer64\n"
"ATTRIBUTE	Test-Counter-Octets	252	integer gigawords=253\n"
"ATTRIBUTE	Test-Counter-Gigawords	253	integer\n"
"ATTRIBUTE	Test-Counter-Unpaired	254	integer\n";
char bad_integer64_dict[] =
"ATTRIBUTE	Bad-Int64-Attr		251	integer65\n";
char bad_gigawords_dict[] =
"ATTRIBUTE	Bad-Gigawords-Attr	251	integer gigawords=notanumber\n";

/* RFC 8044 SS3.5 "time" keyword: a synonym for "date"/PW_TYPE_DATE/
 * RADCLI_TYPE_DATE. */
char time_dict[] =
"ATTRIBUTE	Test-Time-Attr		251	time\n";

/* RFC 8044 SS3.9 "ipv4prefix" keyword. */
char ipv4prefix_dict[] =
"ATTRIBUTE	Test-Ipv4prefix-Attr	251	ipv4prefix\n";

/* RFC 8044 SS3.1 "text" keyword. */
char text_dict[] =
"ATTRIBUTE	Test-Text-Attr		251	text\n";

/* RFC 8044 SS3.7 "ifid" keyword. */
char ifid_dict[] =
"ATTRIBUTE	Test-Ifid-Attr		251	ifid\n";
char bad_ifid_dict[] =
"ATTRIBUTE	Bad-Ifid-Attr		251	ifidx\n";

/* "enum" keyword: a synonym for "integer"/"uint32" (IANA's Data Type name
 * for an enumerated 4-octet integer). */
char enum_dict[] =
"ATTRIBUTE	Test-Enum-Attr		251	enum\n";

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	int ret;
	const radcli_attr_def *d;
	char buf[64];

	/* --- large_value_dict: standard-space attributes with values up to
	 * 17000, verified by round-tripping name -> id -> name. --- */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);

	ret = radcli_ctx_read_dictionary_from_buffer(ctx, large_value_dict, sizeof(large_value_dict));
	if (ret != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	d = radcli_dict_lookup(ctx, "Digest-Method");
	if (d == NULL || radcli_dict_lookup_num(ctx, 1065, 0) != d) {
		fprintf(stderr, "error: Digest-Method round-trip failed\n");
		exit(1);
	}

	d = radcli_dict_lookup(ctx, "LargeOne");
	if (d == NULL || radcli_dict_lookup_num(ctx, 17000, 0) != d) {
		fprintf(stderr, "error: LargeOne round-trip failed\n");
		exit(1);
	}

	radcli_ctx_free(ctx);

	/* --- large_vendor_dict: same attributes under a vendor (PEC 18311). --- */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);

	ret = radcli_ctx_read_dictionary_from_buffer(ctx, large_vendor_dict, sizeof(large_vendor_dict));
	if (ret != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	d = radcli_dict_lookup(ctx, "Digest-Method");
	if (d == NULL || radcli_dict_lookup_oid(ctx, "26.18311.1065") != d) {
		fprintf(stderr, "error: vendor Digest-Method round-trip failed\n");
		exit(1);
	}

	d = radcli_dict_lookup(ctx, "LargeOne");
	if (d == NULL || radcli_dict_lookup_oid(ctx, "26.18311.17001") != d) {
		fprintf(stderr, "error: vendor LargeOne round-trip failed\n");
		exit(1);
	}

	radcli_ctx_free(ctx);

	/* --- long_name_dict: attribute names past the old 32-char limit. --- */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);

	ret = radcli_ctx_read_dictionary_from_buffer(ctx, long_name_dict, sizeof(long_name_dict));
	if (ret != 0) {
		fprintf(stderr, "error: long attribute names rejected (line %d)\n", __LINE__);
		exit(1);
	}

	d = radcli_dict_lookup(ctx, "WISPr-Session-Terminate-End-Of-Day");
	if (d == NULL || radcli_dict_lookup_num(ctx, 10, 0) != d) {
		fprintf(stderr, "error: WISPr-Session-Terminate-End-Of-Day round-trip failed\n");
		exit(1);
	}

	d = radcli_dict_lookup(ctx, "Airespace-Real-Time-Bandwidth-Average-Contract-Upstream");
	if (d == NULL || radcli_dict_lookup_num(ctx, 56, 0) != d) {
		fprintf(stderr, "error: Airespace-Real-Time-Bandwidth-Average-Contract-Upstream round-trip failed\n");
		exit(1);
	}

	radcli_ctx_free(ctx);

	/* --- case_insensitive_dict: attrname match is case-insensitive. --- */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);

	ret = radcli_ctx_read_dictionary_from_buffer(ctx, case_insensitive_dict, sizeof(case_insensitive_dict));
	if (ret != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	if (radcli_dict_lookup(ctx, "framed-protocol") == NULL) {
		fprintf(stderr, "error: radcli_dict_lookup() did not match attrname case-insensitively\n");
		exit(1);
	}
	if (radcli_dict_lookup(ctx, "FRAMED-PROTOCOL") == NULL) {
		fprintf(stderr, "error: radcli_dict_lookup() did not match attrname case-insensitively (upper)\n");
		exit(1);
	}

	radcli_ctx_free(ctx);

	/* --- Over-long name tokens (> radcli.h's RC_NAME_LENGTH, 64 -- not
	 * referenced directly here to keep this file radcli2.h-only) must be
	 * rejected. --- */
	{
		char long_token[64 + 16];
		char dictbuf[256];

		memset(long_token, 'A', sizeof(long_token) - 1);
		long_token[sizeof(long_token) - 1] = '\0';

		ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		assert(ctx != NULL);

		snprintf(dictbuf, sizeof(dictbuf), "ATTRIBUTE\t%s\t\t200\tinteger\n", long_token);
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, dictbuf, strlen(dictbuf) + 1);
		if (ret == 0) {
			fprintf(stderr, "error: over-long ATTRIBUTE name was accepted\n");
			exit(1);
		}

		snprintf(dictbuf, sizeof(dictbuf),
			 "ATTRIBUTE\tSome-Attr\t\t201\tinteger\n"
			 "VALUE\tSome-Attr\t\t%s\t1\n", long_token);
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, dictbuf, strlen(dictbuf) + 1);
		if (ret == 0) {
			fprintf(stderr, "error: over-long VALUE name was accepted\n");
			exit(1);
		}

		snprintf(dictbuf, sizeof(dictbuf), "VENDOR\t%s\t\t18312\n", long_token);
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, dictbuf, strlen(dictbuf) + 1);
		if (ret == 0) {
			fprintf(stderr, "error: over-long VENDOR name was accepted\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- A physical line far longer than the old fixed 1024-byte fgets()
	 * buffer must be read intact by getline() and must not corrupt the
	 * line that follows it. --- */
	{
		char long_comment[2000];
		char dictbuf[2200];
		uint32_t out;

		memset(long_comment, 'x', sizeof(long_comment) - 1);
		long_comment[sizeof(long_comment) - 1] = '\0';

		ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		assert(ctx != NULL);

		snprintf(dictbuf, sizeof(dictbuf),
			 "ATTRIBUTE\tTest-Attr\t\t202\tinteger\n"
			 "# %s\n"
			 "VALUE\tTest-Attr\tTest-Val\t1\n", long_comment);
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, dictbuf, strlen(dictbuf) + 1);
		if (ret != 0) {
			fprintf(stderr, "error: dictionary with a line longer than the "
					"old 1024-byte buffer was rejected\n");
			exit(1);
		}

		d = radcli_dict_lookup(ctx, "Test-Attr");
		if (d == NULL) {
			fprintf(stderr, "error: Test-Attr not found\n");
			exit(1);
		}
		if (radcli_dict_lookup_value(ctx, d, "Test-Val", &out) != 0 || out != 1) {
			fprintf(stderr, "error: Test-Val not found "
					"(line after the long comment was misparsed)\n");
			exit(1);
		}

		radcli_ctx_free(ctx);
	}

	/* --- Malformed numeric fields must be fully validated. --- */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);

	ret = radcli_ctx_read_dictionary_from_buffer(ctx, bad_attr_value_dict, sizeof(bad_attr_value_dict));
	if (ret == 0) {
		fprintf(stderr, "error: ATTRIBUTE with malformed numeric value was accepted\n");
		exit(1);
	}

	ret = radcli_ctx_read_dictionary_from_buffer(ctx, bad_value_value_dict, sizeof(bad_value_value_dict));
	if (ret == 0) {
		fprintf(stderr, "error: VALUE with malformed numeric value was accepted\n");
		exit(1);
	}

	ret = radcli_ctx_read_dictionary_from_buffer(ctx, bad_vendor_pec_dict, sizeof(bad_vendor_pec_dict));
	if (ret == 0) {
		fprintf(stderr, "error: VENDOR with malformed numeric PEC was accepted\n");
		exit(1);
	}

	radcli_ctx_free(ctx);

	/* --- radcli2.h: radcli_dict_lookup()/_oid()/_num() and radcli_attr_def_*() --- */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);

	ret = radcli_ctx_read_dictionary_from_buffer(ctx, radcli2_dict, sizeof(radcli2_dict));
	if (ret != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	{
		/* by name */
		d = radcli_dict_lookup(ctx, "Test-Std-Attr");
		if (d == NULL || strcmp(radcli_attr_def_name(d), "Test-Std-Attr") != 0) {
			fprintf(stderr, "error: radcli_dict_lookup() by name failed\n");
			exit(1);
		}
		if (radcli_attr_def_type(d) != RADCLI_TYPE_INTEGER) {
			fprintf(stderr, "error: radcli_attr_def_type() wrong for Test-Std-Attr\n");
			exit(1);
		}

		/* by legacy numeric id/vendor */
		d = radcli_dict_lookup_num(ctx, 250, 0);
		if (d == NULL || strcmp(radcli_attr_def_name(d), "Test-Std-Attr") != 0) {
			fprintf(stderr, "error: radcli_dict_lookup_num() failed\n");
			exit(1);
		}

		/* by OID: standard attribute, with round-trip text */
		d = radcli_dict_lookup_oid(ctx, "250");
		if (d == NULL || strcmp(radcli_attr_def_name(d), "Test-Std-Attr") != 0) {
			fprintf(stderr, "error: radcli_dict_lookup_oid() standard failed\n");
			exit(1);
		}
		ret = radcli_attr_def_oid(d, buf, sizeof(buf));
		if (ret <= 0 || strcmp(buf, "250") != 0) {
			fprintf(stderr, "error: radcli_attr_def_oid() standard round-trip got '%s'\n", buf);
			exit(1);
		}

		/* by OID: vendor attribute ("26.<vendor>.<type>"), with round-trip text */
		d = radcli_dict_lookup_oid(ctx, "26.19999.5");
		if (d == NULL || strcmp(radcli_attr_def_name(d), "Test-Vendor-Attr") != 0) {
			fprintf(stderr, "error: radcli_dict_lookup_oid() vendor failed\n");
			exit(1);
		}
		if (radcli_attr_def_type(d) != RADCLI_TYPE_STRING) {
			fprintf(stderr, "error: radcli_attr_def_type() wrong for Test-Vendor-Attr\n");
			exit(1);
		}
		ret = radcli_attr_def_oid(d, buf, sizeof(buf));
		if (ret <= 0 || strcmp(buf, "26.19999.5") != 0) {
			fprintf(stderr, "error: radcli_attr_def_oid() vendor round-trip got '%s'\n", buf);
			exit(1);
		}

		/* malformed OIDs and absent names must all miss, not crash */
		if (radcli_dict_lookup_oid(ctx, "") != NULL) {
			fprintf(stderr, "error: empty OID unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup_oid(ctx, "1.2.3.4.5.6") != NULL) {
			fprintf(stderr, "error: over-long OID unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup_oid(ctx, "250x") != NULL) {
			fprintf(stderr, "error: non-numeric OID unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup_oid(ctx, "241.1") != NULL) {
			fprintf(stderr, "error: well-formed but unloaded extended-attribute OID unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup_oid(ctx, "26.19999") != NULL) {
			fprintf(stderr, "error: vendor-only OID (naming the vendor, not an attribute) unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup(ctx, "Not-A-Real-Attribute") != NULL) {
			fprintf(stderr, "error: unknown attribute name unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup(NULL, "Test-Std-Attr") != NULL ||
		    radcli_dict_lookup(ctx, NULL) != NULL ||
		    radcli_dict_lookup_num(NULL, 250, 0) != NULL ||
		    radcli_dict_lookup_oid(NULL, "250") != NULL) {
			fprintf(stderr, "error: a NULL ctx/name argument unexpectedly matched\n");
			exit(1);
		}

		/* radcli_dict_lookup_value(): resolves a VALUE name scoped to one
		 * attribute -- Test-Std-Attr's "One" and Test-Std-Attr2's "One"
		 * must resolve to their own, different numbers, not collide. */
		{
			const radcli_attr_def *d1, *d2;
			uint32_t out;

			d1 = radcli_dict_lookup(ctx, "Test-Std-Attr");
			d2 = radcli_dict_lookup(ctx, "Test-Std-Attr2");
			if (d1 == NULL || d2 == NULL) {
				fprintf(stderr, "error: setup failed resolving Test-Std-Attr(2)\n");
				exit(1);
			}

			if (radcli_dict_lookup_value(ctx, d1, "One", &out) != 0 || out != 1) {
				fprintf(stderr, "error: radcli_dict_lookup_value() Test-Std-Attr/One failed\n");
				exit(1);
			}
			if (radcli_dict_lookup_value(ctx, d1, "Two", &out) != 0 || out != 2) {
				fprintf(stderr, "error: radcli_dict_lookup_value() Test-Std-Attr/Two failed\n");
				exit(1);
			}
			/* case-insensitive, matching every other dict2 name lookup */
			if (radcli_dict_lookup_value(ctx, d1, "oNe", &out) != 0 || out != 1) {
				fprintf(stderr, "error: radcli_dict_lookup_value() is not case-insensitive\n");
				exit(1);
			}
			/* scoping proof: same name, different attribute, different number */
			if (radcli_dict_lookup_value(ctx, d2, "One", &out) != 0 || out != 100) {
				fprintf(stderr, "error: radcli_dict_lookup_value() Test-Std-Attr2/One failed "
						"(scoping by attribute is broken)\n");
				exit(1);
			}
			/* Test-Std-Attr2 never defines "Two" */
			if (radcli_dict_lookup_value(ctx, d2, "Two", &out) == 0) {
				fprintf(stderr, "error: radcli_dict_lookup_value() matched a VALUE not "
						"defined for this attribute\n");
				exit(1);
			}
			if (radcli_dict_lookup_value(ctx, d1, "Not-A-Real-Value", &out) == 0) {
				fprintf(stderr, "error: radcli_dict_lookup_value() matched an unknown name\n");
				exit(1);
			}
			if (radcli_dict_lookup_value(NULL, d1, "One", &out) == 0 ||
			    radcli_dict_lookup_value(ctx, NULL, "One", &out) == 0 ||
			    radcli_dict_lookup_value(ctx, d1, NULL, &out) == 0 ||
			    radcli_dict_lookup_value(ctx, d1, "One", NULL) == 0) {
				fprintf(stderr, "error: radcli_dict_lookup_value() a NULL argument unexpectedly matched\n");
				exit(1);
			}
		}
	}

	radcli_ctx_free(ctx);

	/* Phase 2: the "integer64" keyword and "gigawords=" pairing. */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	{
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, counter64_dict, sizeof(counter64_dict));
		if (ret != 0) {
			fprintf(stderr, "error: dictionary with a valid \"integer64\" line "
					"and \"gigawords=\" pairing was rejected\n");
			exit(1);
		}

		d = radcli_dict_lookup(ctx, "Test-Int64-Attr");
		if (d == NULL || radcli_attr_def_type(d) != RADCLI_TYPE_INTEGER64) {
			fprintf(stderr, "error: \"integer64\" did not parse to RADCLI_TYPE_INTEGER64\n");
			exit(1);
		}

		/* Test-Counter-Octets/-Unpaired exercise radcli_avp_add_gigawords64()/
		 * _get_counter64() (the only public way to reach the internal
		 * gigawords= pairing) -- see tests/avp.c. */
	}
	radcli_ctx_free(ctx);

	/* Phase 3: the "time" keyword (RFC 8044 SS3.5), a synonym for "date". */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	{
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, time_dict, sizeof(time_dict));
		if (ret != 0) {
			fprintf(stderr, "error: dictionary with a valid \"time\" line "
					"was rejected\n");
			exit(1);
		}

		d = radcli_dict_lookup(ctx, "Test-Time-Attr");
		if (d == NULL || radcli_attr_def_type(d) != RADCLI_TYPE_DATE) {
			fprintf(stderr, "error: \"time\" did not parse to RADCLI_TYPE_DATE\n");
			exit(1);
		}
	}
	radcli_ctx_free(ctx);

	/* Phase 4: the "ipv4prefix" keyword (RFC 8044 SS3.9). */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	{
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, ipv4prefix_dict, sizeof(ipv4prefix_dict));
		if (ret != 0) {
			fprintf(stderr, "error: dictionary with a valid \"ipv4prefix\" line "
					"was rejected\n");
			exit(1);
		}

		d = radcli_dict_lookup(ctx, "Test-Ipv4prefix-Attr");
		if (d == NULL || radcli_attr_def_type(d) != RADCLI_TYPE_IPV4PREFIX) {
			fprintf(stderr, "error: \"ipv4prefix\" did not parse to RADCLI_TYPE_IPV4PREFIX\n");
			exit(1);
		}
	}
	radcli_ctx_free(ctx);

	/* Phase 5: the "text" keyword (RFC 8044 SS3.1). */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	{
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, text_dict, sizeof(text_dict));
		if (ret != 0) {
			fprintf(stderr, "error: dictionary with a valid \"text\" line "
					"was rejected\n");
			exit(1);
		}

		d = radcli_dict_lookup(ctx, "Test-Text-Attr");
		if (d == NULL || radcli_attr_def_type(d) != RADCLI_TYPE_TEXT) {
			fprintf(stderr, "error: \"text\" did not parse to RADCLI_TYPE_TEXT\n");
			exit(1);
		}
	}
	radcli_ctx_free(ctx);

	/* Phase 6: the "ifid" keyword (RFC 8044 SS3.7). */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	{
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, ifid_dict, sizeof(ifid_dict));
		if (ret != 0) {
			fprintf(stderr, "error: dictionary with a valid \"ifid\" line "
					"was rejected\n");
			exit(1);
		}

		d = radcli_dict_lookup(ctx, "Test-Ifid-Attr");
		if (d == NULL || radcli_attr_def_type(d) != RADCLI_TYPE_IFID) {
			fprintf(stderr, "error: \"ifid\" did not parse to RADCLI_TYPE_IFID\n");
			exit(1);
		}
	}
	radcli_ctx_free(ctx);

	/* Phase 7: the "enum" keyword, a synonym for "integer"/"uint32". */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	{
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, enum_dict, sizeof(enum_dict));
		if (ret != 0) {
			fprintf(stderr, "error: dictionary with a valid \"enum\" line "
					"was rejected\n");
			exit(1);
		}

		d = radcli_dict_lookup(ctx, "Test-Enum-Attr");
		if (d == NULL || radcli_attr_def_type(d) != RADCLI_TYPE_INTEGER) {
			fprintf(stderr, "error: \"enum\" did not parse to RADCLI_TYPE_INTEGER\n");
			exit(1);
		}
	}
	radcli_ctx_free(ctx);

	/* An unrecognised type string ("integer65") is rejected, not silently
	 * treated as some other type. */
	ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	assert(ctx != NULL);
	ret = radcli_ctx_read_dictionary_from_buffer(ctx, bad_integer64_dict, sizeof(bad_integer64_dict));
	if (ret == 0) {
		fprintf(stderr, "error: dictionary with an unrecognised type "
				"(\"integer65\") was accepted\n");
		exit(1);
	}

	/* Same, for "ifidx" -- confirms the "ifid" match is exact, not a
	 * prefix match. */
	ret = radcli_ctx_read_dictionary_from_buffer(ctx, bad_ifid_dict, sizeof(bad_ifid_dict));
	if (ret == 0) {
		fprintf(stderr, "error: dictionary with an unrecognised type "
				"(\"ifidx\") was accepted\n");
		exit(1);
	}

	/* A non-numeric gigawords= value is rejected, not silently ignored --
	 * matches encrypt='s own validation, not a new convention. */
	ret = radcli_ctx_read_dictionary_from_buffer(ctx, bad_gigawords_dict, sizeof(bad_gigawords_dict));
	if (ret == 0) {
		fprintf(stderr, "error: dictionary with a non-numeric \"gigawords=\" "
				"value was accepted\n");
		exit(1);
	}
	radcli_ctx_free(ctx);

	/* --- Loading identical ATTRIBUTE/VALUE/VENDOR definitions twice must be
	 * a no-op the second time (same lookup results, no error). A conflicting
	 * redefinition (same name, or same attribute+numeric-value for VALUE,
	 * but a different definition) must instead fail the whole load. --- */
	{
		const char dup_dict[] =
			"VENDOR Dup-Vendor 99998\n"
			"ATTRIBUTE Dup-Attr 210 integer Dup-Vendor\n"
			"VALUE Dup-Attr One 1\n";
		const char conflicting_attr_dict[] =
			"VENDOR Dup-Vendor 99998\n"
			"ATTRIBUTE Dup-Attr 210 integer Dup-Vendor\n"
			"VALUE Dup-Attr One 1\n"
			"ATTRIBUTE Dup-Attr 211 integer Dup-Vendor\n"; /* same name, different id */
		const char conflicting_value_dict[] =
			"VENDOR Dup-Vendor 99998\n"
			"ATTRIBUTE Dup-Attr 210 integer Dup-Vendor\n"
			"VALUE Dup-Attr One 1\n"
			"VALUE Dup-Attr Uno 1\n"; /* same attr+value 1, different name */
		const char conflicting_vendor_dict[] =
			"VENDOR Dup-Vendor 99998\n"
			"VENDOR Dup-Vendor 99999\n"; /* same name, different PEC */

		ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		assert(ctx != NULL);

		ret = radcli_ctx_read_dictionary_from_buffer(ctx, dup_dict, sizeof(dup_dict));
		if (ret != 0) {
			fprintf(stderr, "error: initial load of dup_dict was rejected\n");
			exit(1);
		}

		d = radcli_dict_lookup(ctx, "Dup-Attr");
		if (d == NULL || radcli_dict_lookup_oid(ctx, "26.99998.210") != d) {
			fprintf(stderr, "error: Dup-Attr not resolved as expected after initial load\n");
			exit(1);
		}

		/* Re-loading byte-identical definitions must succeed and must not
		 * add a second, shadowing entry: the same attribute object is
		 * found afterwards. */
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, dup_dict, sizeof(dup_dict));
		if (ret != 0) {
			fprintf(stderr, "error: re-loading an identical dictionary was rejected\n");
			exit(1);
		}
		if (radcli_dict_lookup(ctx, "Dup-Attr") != d) {
			fprintf(stderr, "error: re-loading an identical dictionary shadowed the "
					"existing Dup-Attr entry\n");
			exit(1);
		}

		radcli_ctx_free(ctx);

		ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		assert(ctx != NULL);
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, conflicting_attr_dict, sizeof(conflicting_attr_dict));
		if (ret == 0) {
			fprintf(stderr, "error: ATTRIBUTE redefined under the same name "
					"with a different id was accepted\n");
			exit(1);
		}
		radcli_ctx_free(ctx);

		ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		assert(ctx != NULL);
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, conflicting_value_dict, sizeof(conflicting_value_dict));
		if (ret == 0) {
			fprintf(stderr, "error: VALUE redefined for the same attribute+number "
					"with a different name was accepted\n");
			exit(1);
		}
		radcli_ctx_free(ctx);

		ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		assert(ctx != NULL);
		ret = radcli_ctx_read_dictionary_from_buffer(ctx, conflicting_vendor_dict, sizeof(conflicting_vendor_dict));
		if (ret == 0) {
			fprintf(stderr, "error: VENDOR redefined under the same name "
					"with a different Vendor-Id was accepted\n");
			exit(1);
		}
		radcli_ctx_free(ctx);
	}

	printf("radcli2 dict: all tests passed\n");

	return 0;
}
