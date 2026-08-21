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
#include <netinet/in.h>

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

/** Opaque attribute-value pair.
 *
 * Owned by the radcli_avp_list it was added to; never freed individually by
 * the caller. Its value is heap-allocated and length-carrying -- unlike
 * radcli.h's VALUE_PAIR, it has no 253-octet ceiling.
 */
struct radcli_avp_st;
typedef struct radcli_avp_st radcli_avp;

/** Opaque, ordered list of attribute-value pairs.
 *
 * Construct with radcli_avp_list_new(), add attributes with the
 * radcli_avp_add_*() family, and release with radcli_avp_list_free().
 */
struct radcli_avp_list_st;
typedef struct radcli_avp_list_st radcli_avp_list;

/** @brief Create an empty attribute-value pair list.
 * @return the new list, or NULL on allocation failure.
 */
radcli_avp_list *radcli_avp_list_new(void);

/** @brief Free a list and every attribute it holds.
 * @param list a list from radcli_avp_list_new(); NULL is accepted and ignored.
 */
void radcli_avp_list_free(radcli_avp_list *list);

/** @brief Append an attribute holding an arbitrary byte string.
 *
 * The primitive every other radcli_avp_add_*() function is defined in terms
 * of; valid for any attribute type, since the underlying representation is
 * always length-carrying bytes.
 *
 * @param list destination list.
 * @param def the attribute, from radcli_dict_lookup() or a sibling.
 * @param value the bytes to copy in; may be NULL only if len is 0.
 * @param len number of bytes at value.
 * @return 0 on success, -1 on failure (allocation failure, or NULL list/def).
 */
int radcli_avp_add_bytes(radcli_avp_list *list, const radcli_attr_def *def, const void *value, size_t len);

/** @brief Append a string-typed attribute.
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_STRING.
 * @param value a null-terminated string.
 * @return 0 on success, -1 on failure (def is not RADCLI_TYPE_STRING, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_str(radcli_avp_list *list, const radcli_attr_def *def, const char *value);

/** @brief Append an integer/IPv4-address/date-typed attribute.
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_INTEGER, RADCLI_TYPE_IPADDR, or RADCLI_TYPE_DATE.
 * @param value the value; an IPv4 address is given in host byte order.
 * @return 0 on success, -1 on failure (def has none of the accepted types, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_uint32(radcli_avp_list *list, const radcli_attr_def *def, uint32_t value);

/** @brief Append an IPv4-address-typed attribute from a struct in_addr.
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_IPADDR.
 * @param value the address, in the usual network byte order struct in_addr carries.
 * @return 0 on success, -1 on failure (def is not RADCLI_TYPE_IPADDR, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_ipaddr(radcli_avp_list *list, const radcli_attr_def *def, struct in_addr value);

/** @brief Append an IPv6-address or IPv6-prefix-typed attribute.
 *
 * For RADCLI_TYPE_IPV6ADDR, prefix MUST be 0 (a plain address has no
 * prefix). For RADCLI_TYPE_IPV6PREFIX, the RFC 3162 wire format is built
 * internally: a reserved zero octet, the prefix length, and the full
 * 16-octet address.
 *
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_IPV6ADDR or RADCLI_TYPE_IPV6PREFIX.
 * @param value the address.
 * @param prefix the prefix length (0-128); ignored/must be 0 for RADCLI_TYPE_IPV6ADDR.
 * @return 0 on success, -1 on failure (wrong type, prefix out of range, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_in6(radcli_avp_list *list, const radcli_attr_def *def,
			const struct in6_addr *value, unsigned prefix);

/** @brief Find the idx-th occurrence of an attribute in a list.
 * @param list the list to search.
 * @param def the attribute to look for.
 * @param idx 0 for the first occurrence, 1 for the second, and so on.
 * @return the matching attribute, or NULL if fewer than idx+1 occurrences exist.
 */
const radcli_avp *radcli_avp_get(const radcli_avp_list *list, const radcli_attr_def *def, unsigned idx);

/** Iterator over a radcli_avp_list.
 *
 * A plain value: construct with radcli_avp_list_iter(), advance with
 * radcli_avp_iter_next(). No allocation, safe to copy, safe to run several
 * independent iterators over the same list concurrently (as long as nothing
 * mutates the list while any of them are in use -- see radcli_avp_list_st's
 * locking note in lib/avp.c). Fields are an implementation detail; do not
 * access them directly. Deliberately not opaque via an incomplete type: a
 * two-pointer cursor belongs on the caller's stack at zero cost, the way any
 * ccan/list or kernel list cursor does, not behind a heap allocation.
 *
 * Usage:
 * @code
 * radcli_avp_iter it = radcli_avp_list_iter(list);
 * const radcli_avp *a;
 * while ((a = radcli_avp_iter_next(&it)) != NULL) {
 *     ...
 * }
 * @endcode
 */
typedef struct {
	const radcli_avp_list *list;
	const radcli_avp *cur;
} radcli_avp_iter;

/** @brief Begin iterating list.
 * @param list the list to iterate; NULL is accepted (the iterator yields nothing).
 * @return an iterator positioned at list's first attribute.
 */
radcli_avp_iter radcli_avp_list_iter(const radcli_avp_list *list);

/** @brief Return the current attribute and advance.
 * @param it an iterator from radcli_avp_list_iter().
 * @return the current attribute, or NULL once the list is exhausted -- every
 *  subsequent call on the same it also returns NULL; it does not restart.
 */
const radcli_avp *radcli_avp_iter_next(radcli_avp_iter *it);

/** @brief Return the attribute definition of a. */
const radcli_attr_def *radcli_avp_def(const radcli_avp *a);

/** @brief Read an attribute's value as an integer/IPv4-address/date.
 * @param a the attribute; radcli_avp_def(a) must be RADCLI_TYPE_INTEGER,
 *  RADCLI_TYPE_IPADDR, or RADCLI_TYPE_DATE. An IPv4 address is returned in
 *  host byte order.
 * @param out where to write the value; may be NULL to just check validity.
 * @return 0 on success, -1 if a's type does not match.
 */
int radcli_avp_get_uint32(const radcli_avp *a, uint32_t *out);

/** @brief Read an attribute's value as an IPv6 address or prefix.
 * @param a the attribute; radcli_avp_def(a) must be RADCLI_TYPE_IPV6ADDR or
 *  RADCLI_TYPE_IPV6PREFIX.
 * @param out where to write the address (zero-padded beyond the prefix
 *  length for RADCLI_TYPE_IPV6PREFIX); may be NULL.
 * @param prefix where to write the prefix length (128 for
 *  RADCLI_TYPE_IPV6ADDR); may be NULL.
 * @return 0 on success, -1 if a's type does not match.
 */
int radcli_avp_get_in6(const radcli_avp *a, struct in6_addr *out, unsigned *prefix);

/** @brief Read an attribute's value as raw bytes.
 *
 * Valid for every attribute type, since the underlying representation is
 * always length-carrying bytes; the interpretation of those bytes for
 * integer/IPv4/date-typed attributes matches radcli_avp_get_uint32()'s.
 *
 * @param a the attribute.
 * @param out where to write a pointer to the value; valid for a's lifetime.
 *  May be NULL.
 * @param len where to write the value's length in bytes. May be NULL.
 * @return 0 on success, -1 if a is NULL.
 */
int radcli_avp_get_bytes(const radcli_avp *a, const void **out, size_t *len);

/** \enum radcli_code RADIUS packet codes (RFC 2865 SS3).
 *
 * Used both to construct a #radcli_request (RADCLI_CODE_ACCESS_REQUEST or
 * RADCLI_CODE_ACCOUNTING_REQUEST) and to read back the code of the reply a
 * successful radcli_request_perform() received, via radcli_request_code().
 * These are fixed protocol constants and match radcli.h's PW_* constants of
 * the same name; radcli2.h does not include radcli.h (see this header's top
 * comment), so they are restated here rather than shared.
 */
typedef enum radcli_code {
	RADCLI_CODE_ACCESS_REQUEST = 1,
	RADCLI_CODE_ACCESS_ACCEPT = 2,
	RADCLI_CODE_ACCESS_REJECT = 3,
	RADCLI_CODE_ACCOUNTING_REQUEST = 4,
	RADCLI_CODE_ACCOUNTING_RESPONSE = 5,
	RADCLI_CODE_ACCESS_CHALLENGE = 11
} radcli_code;

/** \enum radcli_result Outcome of radcli_request_perform(). */
typedef enum radcli_result {
	RADCLI_OK = 0,       //!< A validated reply was received; see radcli_request_code() for which one.
	RADCLI_TIMEOUT = 1,  //!< No reply from any address the server name resolved to.
	RADCLI_ERROR = -1    //!< Malformed input, a verification failure, or no server configured.
} radcli_result;

/** Opaque RADIUS request/reply exchange.
 *
 * Construct with radcli_request_new(), send it and await the reply with
 * radcli_request_perform(), read the outcome with the accessors below, and
 * release with radcli_request_free().
 */
struct radcli_request_st;
typedef struct radcli_request_st radcli_request;

/** @brief Create a request to send.
 *
 * Reads the destination server, its shared secret, and the timeout/retry
 * counts from ctx's configuration -- the same "authserver"/"acctserver",
 * "radius_timeout", and "radius_retries" settings rc_auth()/rc_acct()
 * (radcli.h) use. Unlike rc_auth()/rc_acct(), which fail over across every
 * configured entry, this uses only the first: the new API carries one
 * server per context, with redundancy delegated to DNS (several A/AAAA
 * records for one name, tried in order within the request's timeout by
 * radcli_transport_exchange()) rather than a configured list of distinct
 * servers. A warning is logged, not an error, if more than one entry is
 * configured, so a caller migrating one entry point at a time from the
 * legacy API isn't broken by the leftover entries.
 *
 * @param ctx a context with configuration loaded.
 * @param code RADCLI_CODE_ACCESS_REQUEST or RADCLI_CODE_ACCOUNTING_REQUEST.
 * @param send the attributes to send; copied in -- send may be freed or
 *  reused by the caller immediately after this call returns.
 * @return the new request, or NULL on allocation failure, an invalid code,
 *  or if ctx has no server configured for that code's type.
 */
radcli_request *radcli_request_new(radcli_ctx *ctx, radcli_code code, const radcli_avp_list *send);

/** @brief Send a request and wait for the reply.
 *
 * May be called only once per request; construct a new radcli_request for
 * a retransmission with different content.
 *
 * @param r a request from radcli_request_new().
 * @return RADCLI_OK if a validated reply was received (see
 *  radcli_request_code() for which one), RADCLI_TIMEOUT if none of the
 *  server's addresses replied, or RADCLI_ERROR on failure.
 */
int radcli_request_perform(radcli_request *r);

/** @brief Send a request once, without waiting for or expecting a reply.
 *
 * The fire-and-forget counterpart to radcli_request_perform(): transmits r
 * a single time (no retries -- there is no reply to judge one by) and
 * returns immediately. Intended for a best-effort notification whose
 * outcome the caller does not act on, e.g. an accounting stop sent during
 * shutdown; radcli.h's rc_acct_async() is the equivalent call in the
 * legacy API.
 *
 * May be called only once per request; construct a new radcli_request to
 * send again.
 *
 * @param r a request from radcli_request_new().
 * @return RADCLI_OK once the packet is handed to the network, RADCLI_ERROR
 *  on failure (e.g. name resolution or encoding failed). Never RADCLI_TIMEOUT.
 */
int radcli_request_send_noreply(radcli_request *r);

/** @brief Return the reply's RADIUS code.
 * @param r a request radcli_request_perform() returned RADCLI_OK for.
 * @return the code (e.g. RADCLI_CODE_ACCESS_ACCEPT), or 0 if r has not yet
 *  been successfully performed.
 */
radcli_code radcli_request_code(const radcli_request *r);

/** @brief Return the reply's decoded attributes.
 * @param r a request radcli_request_perform() returned RADCLI_OK for.
 * @return the attribute list, owned by r and valid for its lifetime; NULL
 *  if r has not yet been successfully performed, or the reply carried no
 *  attributes.
 */
const radcli_avp_list *radcli_request_attrs(const radcli_request *r);

/** @brief Return the name of the server a request was (or will be) sent to.
 * @param r a request from radcli_request_new().
 * @return the server name, valid for r's lifetime; never NULL.
 */
const char *radcli_request_server(const radcli_request *r);

/** @brief Release a request.
 * @param r a request from radcli_request_new(); NULL is accepted and ignored.
 */
void radcli_request_free(radcli_request *r);

/** @} */

/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif /* RADCLI2_H */
