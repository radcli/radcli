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
 * Independent of radcli.h's rc_attr_type: it grows on its own schedule
 * rather than forcing the legacy enum, and therefore the legacy
 * PW_TYPE_MAX, to change -- RADCLI_TYPE_INTEGER64 is the first payoff of
 * that split: the dictionary can carry an attribute no VALUE_PAIR-based
 * caller could ever have been compiled against.
 *
 * RADCLI_TYPE_INTEGER64 implements the "integer64" data type of RFC 8044
 * (Data Types for RADIUS, SS3.3): an 8-octet unsigned integer in network
 * byte order. MIP6-Feature-Vector (etc/dictionary attribute 124, RFC 5447
 * SS4.2.5) is, per IANA, the only standard attribute of this type.
 */
typedef enum radcli_attr_type {
	RADCLI_TYPE_STRING = 0,     //!< A printable string.
	RADCLI_TYPE_INTEGER = 1,    //!< A 32-bit integer.
	RADCLI_TYPE_IPADDR = 2,     //!< An IPv4 address in host byte order.
	RADCLI_TYPE_DATE = 3,       //!< Seconds since epoch, as a 32-bit integer.
	RADCLI_TYPE_IPV6ADDR = 4,   //!< A 128-bit IPv6 address.
	RADCLI_TYPE_IPV6PREFIX = 5, //!< An IPv6 prefix (RFC 3162 wire format).
	RADCLI_TYPE_INTEGER64 = 6   //!< A 64-bit integer.
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

/** @brief Append a 64-bit integer-typed attribute.
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_INTEGER64.
 * @return 0 on success, -1 on failure (def is not RADCLI_TYPE_INTEGER64, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_uint64(radcli_avp_list *list, const radcli_attr_def *def, uint64_t value);

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

/** @brief Read an attribute's value as a 64-bit integer.
 * @param a the attribute; radcli_avp_def(a) must be RADCLI_TYPE_INTEGER64.
 * @param out where to write the value; may be NULL to just check validity.
 * @return 0 on success, -1 if a's type does not match.
 */
int radcli_avp_get_uint64(const radcli_avp *a, uint64_t *out);

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

/** @brief Append a 64-bit counter as an Octets/Gigawords attribute pair.
 *
 * No standard RADIUS attribute counts octets as a 64-bit integer; real
 * 64-bit accounting is done with a pair of 32-bit attributes -- e.g.
 * Acct-Input-Octets (the low 32 bits) and Acct-Input-Gigawords (the high
 * 32 bits) -- which is what every deployed server actually implements.
 * This is the one call an accounting caller needs instead of computing and
 * adding both halves by hand.
 *
 * Implements the Acct-Input/Output-Octets (RFC 2866 SS5.3/5.4) plus
 * Acct-Input/Output-Gigawords (RFC 2869 SS5.1/5.2) pairing: Gigawords holds
 * the number of times its Octets counterpart has wrapped past 2^32, so the
 * pair together give a 64-bit octet count. Not RADCLI_TYPE_INTEGER64/RFC
 * 8044 -- no standard accounting attribute uses that type.
 *
 * octets' Gigawords counterpart is looked up from the dictionary (an
 * ATTRIBUTE line's "gigawords=" option, etc/dictionary), not derived from
 * its name, so passing an attribute with no such counterpart configured is
 * an error rather than a silent truncation to 32 bits. The gigawords
 * attribute is omitted from list when it would be zero (value fits in 32
 * bits), matching how a real NAS sends it.
 *
 * @param ctx the context octets was looked up from -- the gigawords=
 *  pairing is recorded per dictionary, not on radcli_attr_def itself (that
 *  would need a public struct field, and the struct is frozen ABI), so
 *  finding it means searching ctx's loaded dictionary.
 * @param list destination list.
 * @param octets the octets attribute (e.g. Acct-Input-Octets); its
 *  dictionary entry must declare a gigawords= counterpart.
 * @param value the full 64-bit count.
 * @return 0 on success, -1 on failure (octets has no configured gigawords
 *  counterpart, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_gigawords64(radcli_ctx *ctx, radcli_avp_list *list,
			     const radcli_attr_def *octets, uint64_t value);

/** @brief Reassemble a 64-bit counter from an Octets/Gigawords attribute pair.
 *
 * @param ctx the context octets was looked up from; see radcli_avp_add_gigawords64().
 * @param list the list to search (via radcli_avp_get()).
 * @param octets the octets attribute; its dictionary entry must declare a
 *  gigawords= counterpart, as for radcli_avp_add_gigawords64().
 * @param out where to write the reassembled value; may be NULL to just
 *  check validity.
 * @return 0 on success, -1 if octets has no configured gigawords
 *  counterpart, list has no octets attribute, or the gigawords attribute
 *  is present but has the wrong type.
 */
int radcli_avp_get_gigawords64(const radcli_ctx *ctx, const radcli_avp_list *list,
			     const radcli_attr_def *octets, uint64_t *out);

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
	RADCLI_CODE_ACCESS_CHALLENGE = 11,
	/* RFC 5176 SS3: Dynamic Authorization. The legacy rc_standard_codes
	 * enum (radcli.h) is not extended -- these belong to the new API
	 * only, since radcli.h's request/reply path never handles them. */
	RADCLI_DISCONNECT_REQUEST = 40,
	RADCLI_DISCONNECT_ACK = 41,
	RADCLI_DISCONNECT_NAK = 42,
	RADCLI_COA_REQUEST = 43,
	RADCLI_COA_ACK = 44,
	RADCLI_COA_NAK = 45
} radcli_code;

/** \enum radcli_error_cause RFC 5176 SS3.5 Error-Cause values.
 *
 * Passed to radcli_dae_reply_error() to build a Disconnect-NAK/CoA-NAK.
 * Matches etc/dictionary's Error-Cause VALUEs; restated here as typed
 * constants for callers that build a NAK without touching the dictionary.
 */
typedef enum radcli_error_cause {
	RADCLI_ERROR_RESIDUAL_SESSION_CONTEXT_REMOVED = 201,
	RADCLI_ERROR_INVALID_EAP_PACKET = 202,
	RADCLI_ERROR_UNSUPPORTED_ATTRIBUTE = 401,
	RADCLI_ERROR_MISSING_ATTRIBUTE = 402,
	RADCLI_ERROR_NAS_IDENTIFICATION_MISMATCH = 403,
	RADCLI_ERROR_INVALID_REQUEST = 404,
	RADCLI_ERROR_UNSUPPORTED_SERVICE = 405,
	RADCLI_ERROR_UNSUPPORTED_EXTENSION = 406,
	RADCLI_ERROR_ADMINISTRATIVELY_PROHIBITED = 501,
	RADCLI_ERROR_REQUEST_NOT_ROUTABLE = 502,
	RADCLI_ERROR_SESSION_CONTEXT_NOT_FOUND = 503,
	RADCLI_ERROR_SESSION_CONTEXT_NOT_REMOVABLE = 504,
	RADCLI_ERROR_OTHER_PROXY_PROCESSING_ERROR = 505,
	RADCLI_ERROR_RESOURCES_UNAVAILABLE = 506,
	RADCLI_ERROR_REQUEST_INITIATED = 507,
	RADCLI_ERROR_MULTIPLE_SESSION_SELECTION_UNSUPPORTED = 508
} radcli_error_cause;

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

/** \defgroup radcli-dae RFC 5176 dynamic authorization (CoA/Disconnect)
 *
 * Receive-only support for RFC 5176: radcli answers CoA-Request and
 * Disconnect-Request packets from a Dynamic Authorization Client (DAC);
 * there is no exported function to send them (radcli implements the
 * server/receiving role only -- see doc/requirements/dae.md).
 *
 * radcli never exposes the listener's own descriptor and never offers a
 * blocking read call: instead, the application registers a handler with
 * radcli_dae_set_handler() and polls radcli_ctx_get_poll()/dispatches with
 * radcli_ctx_dispatch(), both at the radcli_ctx level rather than the
 * radcli_dae level. That is deliberate, not incidental: a future dynamic
 * authorization transport carried over the same session as ordinary
 * requests (rather than a separate UDP/3799 listener) shares one
 * descriptor between the two, and an accessor on radcli_dae alone would
 * let an application watch a descriptor that silently stops meaning what
 * it thinks -- see radcli_ctx_dispatch()'s doc comment.
 *
 * radcli_dae_process()/radcli_dae_reply_to_buffer() are the L0 entry point:
 * the same validation and reply machinery, without a radcli-owned socket,
 * for an application that owns its own transport -- e.g. a privileged
 * listener process handing validated requests to workers over IPC.
 *
 * radcli itself never forks and never installs an atfork handler, so it
 * cannot protect an application that binds the listener and then forks
 * (e.g. a worker/main/privilege-separated process shape): every child
 * inherits a working copy of the same UDP socket, races the others for
 * datagrams, and -- since the duplicate-suppression table is per-process --
 * can end up acting on the same Disconnect-Request more than once. A
 * process that forks after radcli_dae_start() must call radcli_dae_free()
 * in every child that does not itself own the listener before running its
 * own event loop.
 *
 * @{
 */

/** Opaque RFC 5176 dynamic-authorization listener. */
typedef struct radcli_dae_st radcli_dae;

/** Opaque validated CoA-Request or Disconnect-Request, passed to a
 * radcli_dae_handler. By the time an application sees one, it has already
 * passed source-address authorization, Request Authenticator verification,
 * Message-Authenticator verification (when present, or unconditionally
 * under dae-require-message-authenticator), Event-Timestamp freshness, and
 * duplicate suppression -- see radcli_ctx_dispatch()'s doc comment. */
typedef struct radcli_dae_request_st radcli_dae_request;

/** @brief Application callback invoked by radcli_ctx_dispatch() for a
 *  validated request.
 *
 * Called synchronously, from inside radcli_ctx_dispatch(): only
 * radcli_dae_req_*(), radcli_dae_reply(), radcli_dae_reply_error(), and
 * radcli_dae_request_free() may be called from within it. Calling
 * radcli_ctx_dispatch(), radcli_dae_start(), or radcli_dae_free() from a
 * handler is undefined.
 *
 * @param req the validated request; owned by radcli until freed with
 *  radcli_dae_request_free(), or may be freed here if not needed after.
 * @param user the pointer passed to radcli_dae_set_handler().
 */
typedef void (*radcli_dae_handler)(radcli_dae_request *req, void *user);

/** @brief Return the received packet's RADIUS code.
 * @param req a request passed to a radcli_dae_handler.
 * @return RADCLI_DISCONNECT_REQUEST or RADCLI_COA_REQUEST (no other code
 *  ever reaches a handler -- see radcli_ctx_dispatch()'s doc comment), or
 *  0 if req is NULL.
 */
radcli_code radcli_dae_req_code(const radcli_dae_request *req);

/** @brief Return the request's decoded attributes.
 * @param req a request passed to a radcli_dae_handler.
 * @return the attribute list, owned by req and valid until it is freed;
 *  NULL if req is NULL. Never NULL for a request the handler actually
 *  received: an attribute-free Disconnect-Request/CoA-Request still yields
 *  a valid, empty list.
 */
const radcli_avp_list *radcli_dae_req_attrs(const radcli_dae_request *req);

/** @brief Return the request's Acct-Session-Id, if it carried one.
 * @param req a request passed to a radcli_dae_handler.
 * @return a NUL-terminated string owned by req and valid until it is freed,
 *  or NULL if req is NULL or carried no Acct-Session-Id.
 */
const char *radcli_dae_req_session_id(const radcli_dae_request *req);

/** @brief Return the request's User-Name, if it carried one.
 * @param req a request passed to a radcli_dae_handler.
 * @return a NUL-terminated string owned by req and valid until it is freed,
 *  or NULL if req is NULL or carried no User-Name.
 */
const char *radcli_dae_req_user_name(const radcli_dae_request *req);

/** @brief Return the request's Framed-IP-Address or Framed-IPv6-Address.
 * @param req a request passed to a radcli_dae_handler.
 * @param[out] out filled with an AF_INET or AF_INET6 address on success;
 *  untouched on failure.
 * @return 0 on success, -1 if req or out is NULL, or the request carried
 *  neither attribute.
 */
int radcli_dae_req_framed_ip(const radcli_dae_request *req, struct sockaddr_storage *out);

/** @brief Return the request's NAS-Port.
 * @param req a request passed to a radcli_dae_handler.
 * @param[out] out filled with the value on success; may be NULL to just
 *  check presence.
 * @return 0 on success, -1 if req is NULL or the request carried no
 *  NAS-Port.
 */
int radcli_dae_req_nas_port(const radcli_dae_request *req, uint32_t *out);

/** @brief Check the request's NAS-IP-Address/NAS-IPv6-Address/NAS-Identifier,
 *  if any, against this context's own identity (the nas-ip/nas-identifier
 *  config options), so the application never has to know that the RFC 5176
 *  SS3.5 term for a disagreement is "NAS Identification Mismatch" or that
 *  its Error-Cause is 403.
 *
 * An attribute the request did not carry, or a configured identity option
 * that is unset, is not a mismatch by itself -- there is nothing to check
 * it against. A request naming a different NAS-IP-Address, NAS-IPv6-Address,
 * or NAS-Identifier than the one configured here is.
 *
 * @param req a request passed to a radcli_dae_handler.
 * @return 0 if consistent (including "nothing to check"), -1 if req is
 *  NULL or any attribute present disagrees with the configured identity.
 */
int radcli_dae_req_check_nas(const radcli_dae_request *req);

/** @brief Answer a request with an ACK or NAK, selecting 41/42 or 44/45
 *  from the request's own code, mirroring its Proxy-State attributes, and
 *  computing the Response Authenticator over the request's Authenticator.
 *
 * @param req a request passed to a radcli_dae_handler, not yet replied to.
 * @param ack non-zero for an ACK (Disconnect-ACK/CoA-ACK), zero for a bare
 *  NAK with no Error-Cause attribute -- most callers rejecting a request
 *  should use radcli_dae_reply_error() instead, which also states why.
 * @return 0 once the reply is handed to the network, -1 on failure (req is
 *  NULL, already replied to, or the reply could not be sent).
 */
int radcli_dae_reply(radcli_dae_request *req, int ack);

/** @brief Answer a request with a NAK carrying the given Error-Cause.
 * @param req a request passed to a radcli_dae_handler, not yet replied to.
 * @param error_cause a #radcli_error_cause value (e.g.
 *  RADCLI_ERROR_SESSION_CONTEXT_NOT_FOUND), encoded as attribute 101.
 * @return 0 once the reply is handed to the network, -1 on failure (req is
 *  NULL, already replied to, or the reply could not be sent).
 */
int radcli_dae_reply_error(radcli_dae_request *req, uint32_t error_cause);

/** @brief Produce a reply as bytes instead of sending it -- the L0
 *  counterpart of radcli_dae_reply()/radcli_dae_reply_error(), for a
 *  request that came from radcli_dae_process().
 *
 * For a request radcli_dae_process() returned #RADCLI_DAE_DUPLICATE for,
 * ack and error_cause are ignored: a genuine retransmission always gets the
 * same answer it originally got (RFC 5176 SS2.3), never a fresh one, so the
 * bytes produced are always that cached decision's.
 *
 * @param req a request from radcli_dae_process(), not yet replied to
 *  (unless #RADCLI_DAE_DUPLICATE, which may be called any number of times).
 * @param ack non-zero for an ACK, zero for a NAK -- ignored if req is a
 *  #RADCLI_DAE_DUPLICATE.
 * @param error_cause a #radcli_error_cause value for a NAK, or 0 for a bare
 *  one -- ignored if req is a #RADCLI_DAE_DUPLICATE.
 * @param[out] buf filled with the reply's bytes on success.
 * @param[in,out] buf's capacity on entry; the reply's actual length on
 *  success.
 * @return 0 on success, -1 on failure (any argument NULL, req already
 *  replied to and not a #RADCLI_DAE_DUPLICATE, or buf too small).
 */
int radcli_dae_reply_to_buffer(radcli_dae_request *req, int ack, uint32_t error_cause,
			       void *buf, size_t *len);

/** @brief Release a request.
 * @param req a request passed to a radcli_dae_handler, or from
 *  radcli_dae_process(); NULL is accepted and ignored. Replying is optional
 *  before freeing: an unanswered request simply gets no reply.
 */
void radcli_dae_request_free(radcli_dae_request *req);

/** radcli_dae_process() succeeded, producing a newly validated request that
 * needs an application decision. */
#define RADCLI_DAE_NEW 0
/** radcli_dae_process() succeeded, producing a request that is a
 * retransmission of one already answered: no new decision to make, and
 * radcli_dae_reply_to_buffer() on it reproduces that cached answer
 * regardless of the ack/error_cause passed to it. */
#define RADCLI_DAE_DUPLICATE 1

/** @brief Validate a caller-supplied packet, without a radcli-owned socket
 *  -- the L0 counterpart of radcli_ctx_dispatch(), running the identical
 *  validation pipeline (REQ-DAE-NET-003) on a buffer and source address the
 *  caller supplies instead of reading them from radcli_dae_start()'s
 *  socket. A request this produces is otherwise indistinguishable from one
 *  radcli_ctx_dispatch() would have delivered to a handler.
 *
 * @param dae a listener from radcli_dae_new() (radcli_dae_start() need
 *  never have been called: this function reads no socket).
 * @param buf the received packet, header included.
 * @param len buf's length.
 * @param from the packet's source address, for the dae-server authorization
 *  check and for the source-port match duplicate suppression uses.
 * @param fromlen from's length.
 * @param[out] req set to the validated request on success (#RADCLI_DAE_NEW
 *  or #RADCLI_DAE_DUPLICATE), left NULL on failure.
 * @return #RADCLI_DAE_NEW or #RADCLI_DAE_DUPLICATE on success, -1 if the
 *  packet failed validation (discarded silently, exactly as
 *  radcli_ctx_dispatch() would) or any argument is invalid.
 */
int radcli_dae_process(radcli_dae *dae, const void *buf, size_t len,
		       const struct sockaddr *from, socklen_t fromlen,
		       radcli_dae_request **req);

/** @brief Validate dae-* configuration and build a dynamic-authorization
 *  listener. Opens no socket -- see radcli_dae_start().
 *
 * Fails (returns NULL) unless dae-accept is "yes" or "udp", so that a
 * library upgrade never silently exposes a session-terminating channel in
 * an application that did not opt in. When enabled, also fails unless both
 * dae-server and dae-secret are set, and unless every dae-server entry
 * resolves and carries no network prefix.
 *
 * At most one radcli_dae may be active on a given ctx at a time, since
 * radcli_ctx_get_poll()/radcli_ctx_dispatch() operate on ctx and need a
 * single descriptor to report.
 *
 * @param ctx a configured context (rc_read_config()/rc_apply_config()
 *  already called).
 * @return a new listener, or NULL on invalid configuration.
 */
radcli_dae *radcli_dae_new(radcli_ctx *ctx);

/** @brief Register the callback radcli_ctx_dispatch() invokes for each
 *  validated request. May be called before or after radcli_dae_start().
 * @param dae a listener from radcli_dae_new().
 * @param cb the callback; NULL clears a previously registered one.
 * @param user passed back to cb unchanged.
 */
void radcli_dae_set_handler(radcli_dae *dae, radcli_dae_handler cb, void *user);

/** @brief Start receiving: binds the socket described by dae-listen.
 * @param dae a listener from radcli_dae_new().
 * @return 0 on success, -1 on failure (e.g. the address is already in use).
 */
int radcli_dae_start(radcli_dae *dae);

/** @brief Release a listener, closing its socket if radcli_dae_start()
 *  opened one.
 * @param dae a listener from radcli_dae_new(); NULL is accepted and ignored.
 */
void radcli_dae_free(radcli_dae *dae);

/** @brief Report what to wait for on ctx's behalf, for the caller's own
 *  event loop -- radcli never calls poll()/select()/epoll_wait() itself.
 *
 * There is no per-object descriptor accessor (e.g. no radcli_dae_fd()):
 * the descriptor radcli_ctx_get_poll() reports belongs to ctx, not to any
 * one radcli_dae, so that a future transport sharing one descriptor between
 * dynamic authorization and ordinary requests never leaves an application
 * holding a watcher on a descriptor that has quietly started meaning
 * something else. A descriptor is closed or replaced only during a call
 * the application itself makes (radcli_ctx_dispatch(), radcli_dae_free(),
 * rc_destroy()), never asynchronously -- but re-query after every
 * radcli_ctx_dispatch() call regardless, since one may replace it.
 *
 * @param ctx a context, with or without an active radcli_dae.
 * @param[out] fd the descriptor to watch, or -1 if there is nothing to
 *  watch (e.g. no radcli_dae yet, or radcli_dae_start() not yet called).
 * @param[out] events a poll(2)-compatible bitmask (POLLIN and/or POLLOUT)
 *  of the directions to watch fd for.
 * @param[out] timeout_ms milliseconds after which to call
 *  radcli_ctx_dispatch() even without I/O readiness, or -1 for "no timeout
 *  needed".
 * @return 0 on success, -1 if ctx or an out-parameter is NULL.
 */
int radcli_ctx_get_poll(radcli_ctx *ctx, int *fd, unsigned *events, int *timeout_ms);

/** @brief Read what is ready on ctx's descriptor, validate it, and invoke
 *  the registered handler for anything that passes -- see
 *  radcli_dae_set_handler().
 *
 * Not reentrant: calling this, radcli_dae_start(), or radcli_dae_free()
 * from within a handler radcli_ctx_dispatch() itself invoked is undefined.
 *
 * @param ctx a context previously reported ready by radcli_ctx_get_poll().
 * @return 0 on success (including "nothing was ready"), -1 on failure
 *  (e.g. ctx is NULL, or called reentrantly).
 */
int radcli_ctx_dispatch(radcli_ctx *ctx);

/** @} */

/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif /* RADCLI2_H */
