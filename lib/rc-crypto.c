/*
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
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
 *
 */

/** @file rc-crypto.c
 * @brief MD5 / HMAC-MD5 / SHA-256 wrappers, backed by nettle (REQ-GEN-TECH-006).
 */

#include <string.h>   /* memset() */
#include "config.h"   /* HAVE_DIGEST_LENGTH_ARG */
#include "rc-crypto.h"

void rc_md5_calc(unsigned char *output, unsigned char const *input,
		 size_t inlen)
{
	struct md5_ctx context;

	md5_init(&context);
	md5_update(&context, inlen, input);
#ifdef HAVE_DIGEST_LENGTH_ARG
	md5_digest(&context, MD5_DIGEST_SIZE, output);
#else
	md5_digest(&context, output);
#endif
}

void rc_hmac_md5(uint8_t *data, size_t data_len,
		 uint8_t *key, size_t key_len,
		 uint8_t digest[MD5_DIGEST_SIZE])
{
	struct hmac_md5_ctx md5;

	memset(digest, 0, MD5_DIGEST_SIZE);
	hmac_md5_set_key(&md5, key_len, key);
	hmac_md5_update(&md5, data_len, data);
#ifdef HAVE_DIGEST_LENGTH_ARG
	hmac_md5_digest(&md5, MD5_DIGEST_SIZE, digest);
#else
	hmac_md5_digest(&md5, digest);
#endif
}

void rc_sha256_calc(uint8_t output[RC_SHA256_DIGEST_SIZE],
		    unsigned char const *input, size_t inlen)
{
	struct sha256_ctx context;

	sha256_init(&context);
	sha256_update(&context, inlen, input);
#ifdef HAVE_DIGEST_LENGTH_ARG
	sha256_digest(&context, RC_SHA256_DIGEST_SIZE, output);
#else
	sha256_digest(&context, output);
#endif
}
