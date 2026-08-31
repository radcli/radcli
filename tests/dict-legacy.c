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

/* Unit test for radcli.h's legacy dictionary API (rc_dict_findattr()/
 * _findval()/_findvend()/_getval()/_getvend()/_addattr(), lib/dict.c's shim
 * over lib/dict2-parse.c, the canonical parser). radcli2.h-only coverage of
 * the same parser (radcli_dict_lookup*(), radcli_attr_def_*(), and the
 * integer64/time/ipv4prefix/text dictionary-keyword phases) lives in
 * tests/dict.c instead -- split along the API boundary (REQ-GEN-TEST-006,
 * doc/requirements/general.md) rather than one file mixing both, since the
 * parser guarantees this file checks (dedup/conflict resolution, malformed
 * input rejection, long name/line handling) hold independently through
 * either public entry point and are worth proving through both. */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <radcli/radcli.h>

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

/* Case-insensitive attrname match in rc_dict_getval(): commit 1e56a2c */
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

/* An unrecognised type string must be rejected, not silently treated as
 * some other type. */
char bad_integer64_dict[] =
"ATTRIBUTE	Bad-Int64-Attr		251	integer65\n";
char bad_gigawords_dict[] =
"ATTRIBUTE	Bad-Gigawords-Attr	251	integer gigawords=notanumber\n";

int main(int argc, char **argv)
{
	rc_handle 	*rh = NULL;
	int ret;
	DICT_ATTR *attr;
	DICT_VENDOR *v;
	DICT_VALUE *dv;

	rh = rc_new();
	if (rh == NULL) {
		printf("ERROR: Failed to allocate initial structure\n");
		exit(1);
	}

	rh = rc_config_init(rh);
	if (rh == NULL) {
		printf("ERROR: Failed to initialize configuration\n");
		exit(1);
	}

	ret = rc_read_dictionary_from_buffer(rh, large_value_dict, sizeof(large_value_dict));
	if (ret != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	attr = rc_dict_findattr(rh, "Digest-Method");
	assert(attr != NULL);

	assert(VENDOR(attr->value)==0);
	assert(ATTRID(attr->value)==1065);

	attr = rc_dict_findattr(rh, "LargeOne");
	assert(attr != NULL);

	assert(VENDOR(attr->value)==0);
	assert(ATTRID(attr->value)==17000);

	rc_dict_free(rh);

	/* Vendor */
	ret = rc_read_dictionary_from_buffer(rh, large_vendor_dict, sizeof(large_vendor_dict));
	if (ret != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	attr = rc_dict_findattr(rh, "Digest-Method");
	assert(attr != NULL);

	assert(VENDOR(attr->value)==18311);
	assert(ATTRID(attr->value)==1065);

	attr = rc_dict_findattr(rh, "LargeOne");
	assert(attr != NULL);

	assert(VENDOR(attr->value)==18311);
	assert(ATTRID(attr->value)==17001);

	v = rc_dict_findvend(rh, "Unknown");
	assert(v==NULL);

	v = rc_dict_findvend(rh, "Largeone");
	assert(v!=NULL);
	assert(v->vendorpec == 18311);

	assert(rc_dict_getvend(rh, 18311) != NULL);

	dv = rc_dict_findval(rh, "UnknownOne");
	assert(dv == NULL);

	rc_dict_free(rh);

	/* Long attribute names (> old 32-char limit) */
	ret = rc_read_dictionary_from_buffer(rh, long_name_dict, sizeof(long_name_dict));
	if (ret != 0) {
		fprintf(stderr, "error: long attribute names rejected (line %d)\n", __LINE__);
		exit(1);
	}

	attr = rc_dict_findattr(rh, "WISPr-Session-Terminate-End-Of-Day");
	if (attr == NULL) {
		fprintf(stderr, "error: WISPr-Session-Terminate-End-Of-Day not found\n");
		exit(1);
	}
	assert(ATTRID(attr->value) == 10);

	attr = rc_dict_findattr(rh, "Airespace-Real-Time-Bandwidth-Average-Contract-Upstream");
	if (attr == NULL) {
		fprintf(stderr, "error: Airespace-Real-Time-Bandwidth-Average-Contract-Upstream not found\n");
		exit(1);
	}
	assert(ATTRID(attr->value) == 56);

	rc_dict_free(rh);

	/* rc_dict_getval() attrname match must be case-insensitive: commit 1e56a2c */
	ret = rc_read_dictionary_from_buffer(rh, case_insensitive_dict, sizeof(case_insensitive_dict));
	if (ret != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	dv = rc_dict_getval(rh, 1, "framed-protocol");
	if (dv == NULL) {
		fprintf(stderr, "error: rc_dict_getval() did not match attrname case-insensitively\n");
		exit(1);
	}

	dv = rc_dict_getval(rh, 1, "FRAMED-PROTOCOL");
	if (dv == NULL) {
		fprintf(stderr, "error: rc_dict_getval() did not match attrname case-insensitively (upper)\n");
		exit(1);
	}

	rc_dict_free(rh);

	/* Over-long name/attrname tokens (> RC_NAME_LENGTH) must be rejected,
	 * not silently truncated by strlcpy() before the length check runs:
	 * commit 17a3521. One case per ATTRIBUTE/VALUE/VENDOR line type. */
	{
		char long_token[RC_NAME_LENGTH + 16];
		char dictbuf[256];

		memset(long_token, 'A', sizeof(long_token) - 1);
		long_token[sizeof(long_token) - 1] = '\0';

		snprintf(dictbuf, sizeof(dictbuf), "ATTRIBUTE\t%s\t\t200\tinteger\n", long_token);
		ret = rc_read_dictionary_from_buffer(rh, dictbuf, strlen(dictbuf) + 1);
		if (ret == 0) {
			fprintf(stderr, "error: over-long ATTRIBUTE name was accepted\n");
			exit(1);
		}

		snprintf(dictbuf, sizeof(dictbuf),
			 "ATTRIBUTE\tSome-Attr\t\t201\tinteger\n"
			 "VALUE\tSome-Attr\t\t%s\t1\n", long_token);
		ret = rc_read_dictionary_from_buffer(rh, dictbuf, strlen(dictbuf) + 1);
		if (ret == 0) {
			fprintf(stderr, "error: over-long VALUE name was accepted\n");
			exit(1);
		}

		snprintf(dictbuf, sizeof(dictbuf), "VENDOR\t%s\t\t18312\n", long_token);
		ret = rc_read_dictionary_from_buffer(rh, dictbuf, strlen(dictbuf) + 1);
		if (ret == 0) {
			fprintf(stderr, "error: over-long VENDOR name was accepted\n");
			exit(1);
		}
	}

	rc_dict_free(rh);

	/* A physical line far longer than the old fixed 1024-byte fgets()
	 * buffer must be read intact by getline() and must not corrupt the
	 * line that follows it. */
	{
		char long_comment[2000];
		char dictbuf[2200];

		memset(long_comment, 'x', sizeof(long_comment) - 1);
		long_comment[sizeof(long_comment) - 1] = '\0';

		snprintf(dictbuf, sizeof(dictbuf),
			 "ATTRIBUTE\tTest-Attr\t\t202\tinteger\n"
			 "# %s\n"
			 "VALUE\tTest-Attr\tTest-Val\t1\n", long_comment);
		ret = rc_read_dictionary_from_buffer(rh, dictbuf, strlen(dictbuf) + 1);
		if (ret != 0) {
			fprintf(stderr, "error: dictionary with a line longer than the "
					"old 1024-byte buffer was rejected\n");
			exit(1);
		}

		attr = rc_dict_findattr(rh, "Test-Attr");
		if (attr == NULL) {
			fprintf(stderr, "error: Test-Attr not found\n");
			exit(1);
		}
		assert(ATTRID(attr->value) == 202);

		dv = rc_dict_findval(rh, "Test-Val");
		if (dv == NULL) {
			fprintf(stderr, "error: Test-Val not found "
					"(line after the long comment was misparsed)\n");
			exit(1);
		}
	}

	rc_dict_free(rh);

	/* Malformed numeric fields must be fully validated, not just their
	 * first character (isdigit(*valstr) let "101abc" through): commit
	 * 790407f. One case per ATTRIBUTE value / VALUE value / VENDOR PEC. */
	ret = rc_read_dictionary_from_buffer(rh, bad_attr_value_dict, sizeof(bad_attr_value_dict));
	if (ret == 0) {
		fprintf(stderr, "error: ATTRIBUTE with malformed numeric value was accepted\n");
		exit(1);
	}

	ret = rc_read_dictionary_from_buffer(rh, bad_value_value_dict, sizeof(bad_value_value_dict));
	if (ret == 0) {
		fprintf(stderr, "error: VALUE with malformed numeric value was accepted\n");
		exit(1);
	}

	ret = rc_read_dictionary_from_buffer(rh, bad_vendor_pec_dict, sizeof(bad_vendor_pec_dict));
	if (ret == 0) {
		fprintf(stderr, "error: VENDOR with malformed numeric PEC was accepted\n");
		exit(1);
	}

	rc_dict_free(rh);

	/* An unrecognised type string ("integer65") is rejected, not silently
	 * treated as some other type. */
	ret = rc_read_dictionary_from_buffer(rh, bad_integer64_dict, sizeof(bad_integer64_dict));
	if (ret == 0) {
		fprintf(stderr, "error: dictionary with an unrecognised type "
				"(\"integer65\") was accepted\n");
		exit(1);
	}
	rc_dict_free(rh);

	/* A non-numeric gigawords= value is rejected, not silently ignored --
	 * matches encrypt='s own validation, not a new convention. */
	ret = rc_read_dictionary_from_buffer(rh, bad_gigawords_dict, sizeof(bad_gigawords_dict));
	if (ret == 0) {
		fprintf(stderr, "error: dictionary with a non-numeric \"gigawords=\" "
				"value was accepted\n");
		exit(1);
	}
	rc_dict_free(rh);

	/* Loading identical ATTRIBUTE/VALUE/VENDOR definitions twice must be a
	 * no-op the second time (same lookup results, no error) -- this is what
	 * lets rc_read_config() load the built-in RFC dictionary and then a
	 * dictionary= file that repeats some of the same standard attributes
	 * without wasting memory. A conflicting redefinition (same name, or
	 * same attribute+numeric-value for VALUE, but a different definition)
	 * must instead fail the whole load. */
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

		ret = rc_read_dictionary_from_buffer(rh, dup_dict, sizeof(dup_dict));
		if (ret != 0) {
			fprintf(stderr, "error: initial load of dup_dict was rejected\n");
			exit(1);
		}

		attr = rc_dict_findattr(rh, "Dup-Attr");
		assert(attr != NULL);
		assert(ATTRID(attr->value) == 210);
		assert(VENDOR(attr->value) == 99998);

		/* Re-loading byte-identical definitions must succeed and must not
		 * add a second, shadowing entry: the attribute/value/vendor found
		 * afterwards is still exactly the one already loaded. */
		ret = rc_read_dictionary_from_buffer(rh, dup_dict, sizeof(dup_dict));
		if (ret != 0) {
			fprintf(stderr, "error: re-loading an identical dictionary was rejected\n");
			exit(1);
		}
		attr = rc_dict_findattr(rh, "Dup-Attr");
		assert(attr != NULL);
		assert(ATTRID(attr->value) == 210);
		assert(VENDOR(attr->value) == 99998);

		rc_dict_free(rh);

		ret = rc_read_dictionary_from_buffer(rh, conflicting_attr_dict, sizeof(conflicting_attr_dict));
		if (ret == 0) {
			fprintf(stderr, "error: ATTRIBUTE redefined under the same name "
					"with a different id was accepted\n");
			exit(1);
		}
		rc_dict_free(rh);

		ret = rc_read_dictionary_from_buffer(rh, conflicting_value_dict, sizeof(conflicting_value_dict));
		if (ret == 0) {
			fprintf(stderr, "error: VALUE redefined for the same attribute+number "
					"with a different name was accepted\n");
			exit(1);
		}
		rc_dict_free(rh);

		ret = rc_read_dictionary_from_buffer(rh, conflicting_vendor_dict, sizeof(conflicting_vendor_dict));
		if (ret == 0) {
			fprintf(stderr, "error: VENDOR redefined under the same name "
					"with a different Vendor-Id was accepted\n");
			exit(1);
		}
		rc_dict_free(rh);
	}

	/* The same dedup/conflict rules apply to the programmatic
	 * rc_dict_addattr() path (lib/dict.c's shim over
	 * radcli_dict_attr_add(), RADCLI2_PRIVATE/internal-only -- no public
	 * radcli2.h equivalent to duplicate this coverage against): an
	 * identical re-add returns the existing entry's DICT_ATTR (not a
	 * second one), a conflicting re-add fails. */
	{
		DICT_ATTR *a1, *a2;

		a1 = rc_dict_addattr(rh, "Prog-Attr", 220, PW_TYPE_INTEGER, 0);
		if (a1 == NULL) {
			fprintf(stderr, "error: rc_dict_addattr() initial add failed\n");
			exit(1);
		}

		a2 = rc_dict_addattr(rh, "Prog-Attr", 220, PW_TYPE_INTEGER, 0);
		if (a2 != a1) {
			fprintf(stderr, "error: rc_dict_addattr() identical re-add did "
					"not return the existing entry\n");
			exit(1);
		}

		if (rc_dict_addattr(rh, "Prog-Attr", 221, PW_TYPE_INTEGER, 0) != NULL) {
			fprintf(stderr, "error: rc_dict_addattr() conflicting re-add "
					"(same name, different id) was accepted\n");
			exit(1);
		}

		rc_dict_free(rh);
	}

	rc_destroy(rh);

	printf("radcli legacy dict: all tests passed\n");

	return 0;
}
