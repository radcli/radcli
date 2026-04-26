/*
 * Copyright (c) 2026, Nikos Mavrogiannopoulos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <radcli/radcli.h>
#include <includes.h>  /* AUTH_HDR */

/* Internal function exposed for unit testing (not in public API) */
int rc_pack_list(VALUE_PAIR *vp, char *secret, AUTH_HDR *auth, int max_len);

#define MSG_AUTH_ATTR_LEN  (2 + 16)  /* type(1) + len(1) + HMAC-MD5(16) */

int main(int argc, char **argv)
{
	rc_handle *rh;
	VALUE_PAIR *vp;
	uint8_t buf[RC_BUFFER_LEN];
	AUTH_HDR *auth = (AUTH_HDR *)buf;
	char secret[] = "testing123";
	char val200[200];
	int n, i;

	{
		const char *sd = getenv("srcdir");
		if (sd && chdir(sd) != 0) {
			fprintf(stderr, "%s: cannot chdir to srcdir: %s\n", argv[0], sd);
			exit(1);
		}
		rh = rc_read_config("radiusclient.conf");
	}
	if (rh == NULL) {
		fprintf(stderr, "%s: error opening radius configuration file\n", argv[0]);
		exit(1);
	}

	/* Test 1: positive — small list packs correctly */
	vp = NULL;
	rc_avpair_add(rh, &vp, PW_SESSION_TIMEOUT, &(uint32_t){55}, 0, 0);
	rc_avpair_add(rh, &vp, PW_IDLE_TIMEOUT,    &(uint32_t){120}, 0, 0);
	rc_avpair_add(rh, &vp, PW_ACCT_DELAY_TIME, &(uint32_t){0}, 0, 0);

	memset(buf, 0, sizeof(buf));
	n = rc_pack_list(vp, secret, auth, RC_MAX_PACKET_LEN);
	if (n <= 0) {
		fprintf(stderr, "%d: small list should pack; got %d\n", __LINE__, n);
		exit(1);
	}
	/* 3 integer attrs × (type(1)+len(1)+val(4)) = 18 bytes */
	if (n != 18) {
		fprintf(stderr, "%d: expected 18 bytes, got %d\n", __LINE__, n);
		exit(1);
	}
	rc_avpair_free(vp);

	/* Test 2: negative — list too large for one packet */
	vp = NULL;
	memset(val200, 'A', sizeof(val200));
	/* Each NAS-Identifier attr consumes 2 + 200 = 202 bytes.
	 * 21 of them = 4242 bytes > RC_MAX_PACKET_LEN - AUTH_HDR_LEN (4076). */
	for (i = 0; i < 21; i++)
		rc_avpair_add(rh, &vp, PW_NAS_IDENTIFIER, val200, sizeof(val200), 0);

	memset(buf, 0, sizeof(buf));
	n = rc_pack_list(vp, secret, auth, RC_MAX_PACKET_LEN);
	if (n != -1) {
		fprintf(stderr, "%d: oversized list should return -1; got %d\n", __LINE__, n);
		exit(1);
	}
	rc_avpair_free(vp);

	/* Test 3: negative — attribute with lvalue > 253 is rejected.
	 * rc_avpair_assign() caps at 253 via the public API, but internal callers
	 * or future extensions could set lvalue directly.  rc_pack_list() must
	 * catch this defensively to avoid a corrupt 8-bit length field. */
	{
		char val253[253];
		VALUE_PAIR *p;
		memset(val253, 'B', sizeof(val253));
		vp = NULL;
		p = rc_avpair_add(rh, &vp, PW_NAS_IDENTIFIER, val253, sizeof(val253), 0);
		if (!p) {
			fprintf(stderr, "%d: setup failed for test 3\n", __LINE__);
			exit(1);
		}
		p->lvalue = 254;  /* override: simulate direct struct access bypassing API */

		memset(buf, 0, sizeof(buf));
		n = rc_pack_list(vp, secret, auth, RC_MAX_PACKET_LEN);
		if (n != -1) {
			fprintf(stderr, "%d: lvalue > 253 should return -1; got %d\n",
				__LINE__, n);
			exit(1);
		}
		rc_avpair_free(vp);
	}

	/* Test 4: auth vs accounting limit.
	 * Build a list that fills exactly the auth headroom so it succeeds with
	 * the accounting budget (RC_MAX_PACKET_LEN) but fails with the auth budget
	 * (RC_MAX_PACKET_LEN - MSG_AUTH_ATTR_LEN).
	 *
	 * AUTH_HDR_LEN = 20; attr overhead per NAS-Identifier = 2.
	 * Auth attribute budget = RC_MAX_PACKET_LEN - MSG_AUTH_ATTR_LEN - AUTH_HDR_LEN
	 *                       = 4096 - 18 - 20 = 4058 bytes.
	 * We'll build a list of exactly 4060 attribute bytes (20 attrs × 203 bytes each:
	 * 2 overhead + 201 value), which exceeds the auth budget by 2 but fits the
	 * accounting budget.
	 */
	{
		char val201[201];
		memset(val201, 'C', sizeof(val201));
		vp = NULL;
		for (i = 0; i < 20; i++)
			rc_avpair_add(rh, &vp, PW_NAS_IDENTIFIER, val201, sizeof(val201), 0);
		/* 20 × (2 + 201) = 20 × 203 = 4060 attribute bytes */

		memset(buf, 0, sizeof(buf));
		n = rc_pack_list(vp, secret, auth, RC_MAX_PACKET_LEN);
		if (n != 4060) {
			fprintf(stderr, "%d: accounting limit: expected 4060, got %d\n",
				__LINE__, n);
			exit(1);
		}

		memset(buf, 0, sizeof(buf));
		n = rc_pack_list(vp, secret, auth, RC_MAX_PACKET_LEN - MSG_AUTH_ATTR_LEN);
		if (n != -1) {
			fprintf(stderr, "%d: auth limit: expected -1, got %d\n", __LINE__, n);
			exit(1);
		}
		rc_avpair_free(vp);
	}

	rc_destroy(rh);
	return 0;
}
