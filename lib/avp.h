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

/* radcli2.h wire codec (lib/avp.c) -- internal only, not part of the public
 * API or radcli.map. See the function definitions in lib/avp.c for what
 * each one does. */

#ifndef AVP_H
#define AVP_H

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

int radcli_avp_decode(rc_handle const *rh, const char *secret,
                      const uint8_t request_authenticator[AUTH_VECTOR_LEN],
                      const uint8_t *ptr, size_t length,
                      uint32_t vendorspec, radcli_avp_list **out);
int radcli_avp_encode_rfc2865(rc_handle const *rh, const radcli_avp_list *list, const char *secret,
                      const uint8_t request_authenticator[AUTH_VECTOR_LEN],
                      uint8_t *buf, size_t buflen, size_t *n_encrypted);

#endif /* AVP_H */
