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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <radcli/radcli.h>
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

/* radcli2.h dictionary lookup (radcli_dict_lookup*, radcli_attr_def_*) */
char radcli2_dict[] =
"ATTRIBUTE	Test-Std-Attr		250	integer\n"
"VENDOR          Testvendor       19999     Large\n"
"ATTRIBUTE	Test-Vendor-Attr		5	string Testvendor\n";

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

	/* radcli2.h: radcli_dict_lookup()/_oid()/_num() and radcli_attr_def_*() */
	ret = rc_read_dictionary_from_buffer(rh, radcli2_dict, sizeof(radcli2_dict));
	if (ret != 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	{
		const radcli_attr_def *d;
		char buf[64];

		/* by name */
		d = radcli_dict_lookup(rh, "Test-Std-Attr");
		if (d == NULL || strcmp(radcli_attr_def_name(d), "Test-Std-Attr") != 0) {
			fprintf(stderr, "error: radcli_dict_lookup() by name failed\n");
			exit(1);
		}
		if (radcli_attr_def_type(d) != RADCLI_TYPE_INTEGER) {
			fprintf(stderr, "error: radcli_attr_def_type() wrong for Test-Std-Attr\n");
			exit(1);
		}

		/* by legacy numeric id/vendor */
		d = radcli_dict_lookup_num(rh, 250, 0);
		if (d == NULL || strcmp(radcli_attr_def_name(d), "Test-Std-Attr") != 0) {
			fprintf(stderr, "error: radcli_dict_lookup_num() failed\n");
			exit(1);
		}

		/* by OID: standard attribute, with round-trip text */
		d = radcli_dict_lookup_oid(rh, "250");
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
		d = radcli_dict_lookup_oid(rh, "26.19999.5");
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
		if (radcli_dict_lookup_oid(rh, "") != NULL) {
			fprintf(stderr, "error: empty OID unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup_oid(rh, "1.2.3.4.5.6") != NULL) {
			fprintf(stderr, "error: over-long OID unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup_oid(rh, "250x") != NULL) {
			fprintf(stderr, "error: non-numeric OID unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup_oid(rh, "241.1") != NULL) {
			fprintf(stderr, "error: well-formed but unloaded extended-attribute OID unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup_oid(rh, "26.19999") != NULL) {
			fprintf(stderr, "error: vendor-only OID (naming the vendor, not an attribute) unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup(rh, "Not-A-Real-Attribute") != NULL) {
			fprintf(stderr, "error: unknown attribute name unexpectedly matched\n");
			exit(1);
		}
		if (radcli_dict_lookup(NULL, "Test-Std-Attr") != NULL ||
		    radcli_dict_lookup(rh, NULL) != NULL ||
		    radcli_dict_lookup_num(NULL, 250, 0) != NULL ||
		    radcli_dict_lookup_oid(NULL, "250") != NULL) {
			fprintf(stderr, "error: a NULL ctx/name argument unexpectedly matched\n");
			exit(1);
		}
	}

	rc_dict_free(rh);

	rc_destroy(rh);

	return 0;

}
