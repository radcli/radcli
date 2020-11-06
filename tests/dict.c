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

char large_value_dict[] = 
"ATTRIBUTE	Sip-Method		101	integer\n"
"ATTRIBUTE	Digest-Method		1065	string\n"
"ATTRIBUTE	LargeOne		17000	string\n";

char large_vendor_dict[] = 
"\nVENDOR          Largeone       18311     Large\n"
"\n"
"ATTRIBUTE	Digest-Method		1065	string Largeone\n"
"ATTRIBUTE	LargeOne		17001	string Largeone\n";

int main(int argc, char **argv)
{
	rc_handle 	*rh = NULL;
	int checks;
	int ret, prev;
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
		printf("ERROR: Failed to initialze configuration\n");
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

	rc_destroy(rh);

	return 0;

}
