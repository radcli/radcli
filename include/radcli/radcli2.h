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

/** @file radcli2.h
 * @brief New, opaque-by-default public API of the radcli library.
 *
 * This header is deliberately independent of radcli.h: it does not include
 * it and does not expose any of its structures (VALUE_PAIR, SEND_DATA,
 * SERVER, DICT_ATTR, DICT_VALUE, DICT_VENDOR). All identifiers here use the
 * radcli_ / RADCLI_ prefix; radcli.h's rc_ / RC_ surface is frozen and
 * receives bug fixes only.
 *
 * Both headers may be included together in the same translation unit.
 * radcli_ctx and rc_handle name the same underlying object, so a handle
 * obtained through either header's constructors may be passed to functions
 * declared in the other -- this is what lets a caller migrate one call site
 * at a time. See doc/plan-api-modernization.md for the design rationale.
 */

#ifndef RADCLI2_H
#define RADCLI2_H

#include <stdint.h>
#include <stddef.h>

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

/**
 * @defgroup radcli2-api New API
 * @brief New, opaque-by-default API functions
 *
 * @{
 */

/** A handle to parsed configuration, a loaded dictionary, and (once
 * established) a transport session.
 *
 * radcli_ctx and rc_handle (radcli.h) are typedefs of the same incomplete
 * struct type; the two headers may be used together and a context created
 * through one API's constructors is valid input to the other's functions.
 */
struct rc_conf;
typedef struct rc_conf radcli_ctx;

/** \enum radcli_attr_type Attribute types recognised by the new API.
 *
 * Independent of radcli.h's rc_attr_type: it grows on its own schedule (see
 * doc/plan-api-modernization.md Phase 2 for RADCLI_TYPE_INTEGER64) rather
 * than forcing the legacy enum, and therefore the legacy PW_TYPE_MAX, to
 * change.
 */
typedef enum radcli_attr_type {
	RADCLI_TYPE_STRING = 0,     //!< A printable string.
	RADCLI_TYPE_INTEGER = 1,    //!< A 32-bit integer.
	RADCLI_TYPE_IPADDR = 2,     //!< An IPv4 address in host byte order.
	RADCLI_TYPE_DATE = 3,       //!< Seconds since epoch, as a 32-bit integer.
	RADCLI_TYPE_IPV6ADDR = 4,   //!< A 128-bit IPv6 address.
	RADCLI_TYPE_IPV6PREFIX = 5  //!< An IPv6 prefix (RFC 3162 wire format).
} radcli_attr_type;

/** Opaque dictionary attribute definition.
 *
 * Obtained from radcli_dict_lookup(), radcli_dict_lookup_oid(), or
 * radcli_dict_lookup_num(). Owned by the dictionary loaded into the
 * radcli_ctx that produced it; valid for as long as that context is not
 * destroyed and its dictionary is not reloaded. Never freed by the caller.
 */
struct radcli_attr_def_st;
typedef struct radcli_attr_def_st radcli_attr_def;

/** @brief Look up a dictionary attribute by its canonical name.
 *
 * Case-insensitive, matching the legacy dictionary's own lookup rules.
 *
 * @param ctx a context with a dictionary loaded.
 * @param name the attribute name, e.g. "Framed-IP-Address".
 * @return the attribute definition, or NULL if no such attribute is loaded.
 */
const radcli_attr_def *radcli_dict_lookup(const radcli_ctx *ctx, const char *name);

/** @brief Look up a dictionary attribute by RFC 6929 §2.7 OID notation.
 *
 * Accepts a standard attribute as a single component ("1" for User-Name) or
 * a vendor-specific attribute as "26.<vendor-id>.<vendor-type>" (e.g.
 * "26.311.11"). Longer forms naming an RFC 6929 extended, long-extended, or
 * TLV-nested attribute parse without error but currently match nothing: the
 * bundled dictionary carries no such attributes yet (see
 * doc/plan-api-modernization.md's Phase 1 scope note on RFC 6929).
 *
 * @param ctx a context with a dictionary loaded.
 * @param oid the dot-separated OID text.
 * @return the attribute definition, or NULL if the OID is malformed or
 *  matches no loaded attribute.
 */
const radcli_attr_def *radcli_dict_lookup_oid(const radcli_ctx *ctx, const char *oid);

/** @brief Look up a dictionary attribute by its legacy numeric ID and vendor.
 *
 * Bridges callers that still hold a radcli.h PW_* constant; equivalent to
 * radcli_dict_lookup_oid() with the same attribute expressed as an OID.
 *
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID
 *  when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @return the attribute definition, or NULL if no such attribute is loaded.
 */
const radcli_attr_def *radcli_dict_lookup_num(const radcli_ctx *ctx, uint32_t attrid, uint32_t vendor);

/** @brief Return an attribute definition's canonical name.
 * @param def an attribute definition from radcli_dict_lookup() or a sibling.
 * @return the name; never NULL for a non-NULL def.
 */
const char *radcli_attr_def_name(const radcli_attr_def *def);

/** @brief Return an attribute definition's wire type.
 * @param def an attribute definition from radcli_dict_lookup() or a sibling.
 */
radcli_attr_type radcli_attr_def_type(const radcli_attr_def *def);

/** @brief Render an attribute definition's RFC 6929 §2.7 OID notation.
 *
 * @param def an attribute definition from radcli_dict_lookup() or a sibling.
 * @param buf destination buffer; may be NULL if buflen is 0.
 * @param buflen size of buf in bytes.
 * @return the number of characters the OID text would occupy, excluding
 *  the terminating null, as with snprintf(); negative if def is NULL.
 */
int radcli_attr_def_oid(const radcli_attr_def *def, char *buf, size_t buflen);

/** @} */

/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif /* RADCLI2_H */
