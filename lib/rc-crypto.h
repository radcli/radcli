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
 */

/** @file rc-crypto.h
 * @brief MD5 / HMAC-MD5 / SHA-256 wrappers, backed by nettle (REQ-GEN-TECH-006).
 */

#ifndef _RC_CRYPTO_H
#define _RC_CRYPTO_H

#include <includes.h>
#include <stdint.h>
#include <stdlib.h>
#include <nettle/md5.h>
#include <nettle/hmac.h>
#include <nettle/sha2.h>

#define RC_SHA256_DIGEST_SIZE SHA256_DIGEST_SIZE

/*- Hash the provided data using MD5
 *
 * @param[out] output will hold a 16-byte checksum.
 * @param[in] input pointer to data to hash.
 * @param[in] inlen the length of input.
 -*/
void rc_md5_calc(unsigned char *output, unsigned char const *input,
		 size_t inlen);

/*- Compute the RFC 2104 HMAC-MD5 of data under key.
 *
 * @param data pointer to the data to authenticate.
 * @param data_len data's length in bytes.
 * @param key the HMAC key.
 * @param key_len key's length in bytes.
 * @param digest set to the 16-byte HMAC-MD5 output.
 -*/
void rc_hmac_md5(uint8_t *data, size_t data_len,
		 uint8_t *key, size_t key_len,
		 uint8_t digest[MD5_DIGEST_SIZE]);

/*- Hash the provided data using SHA-256.
 *
 * @param[out] output will hold a 32-byte digest.
 * @param[in] input pointer to data to hash.
 * @param[in] inlen the length of input.
 -*/
void rc_sha256_calc(uint8_t output[RC_SHA256_DIGEST_SIZE],
		    unsigned char const *input, size_t inlen);

#endif /* _RC_CRYPTO_H */
