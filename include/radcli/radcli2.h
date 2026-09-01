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
 * receives bug fixes only. The deliberate exception is radcli-defs.h (the
 * numeric PW_* attribute IDs, the numeric PW_* VALUEs of well-known
 * attributes -- Service-Type, Framed-Protocol, NAS-Port-Type,
 * Acct-Status-Type, Acct-Terminate-Cause, etc. -- and the RC_OPTION_TABLE
 * config-option list): with 100+ attribute IDs and dozens of values,
 * hand-duplicating them under a second, RADCLI_-prefixed name (as is done
 * for the small radcli_code/rc_standard_codes pair below) would be a real
 * drift risk, so both headers include that one plain-enum file instead as
 * a shared source of truth. It declares nothing beyond those enums/macros
 * -- no rc_/RC_ types leak in through it.
 *
 * Both headers may be included together in the same translation unit.
 * radcli_ctx and rc_handle name the same underlying object, so a handle
 * obtained through either header's constructors may be passed to functions
 * declared in the other -- this is what lets a caller migrate one call site
 * at a time.
 */

#ifndef RADCLI2_H
#define RADCLI2_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>
#include <poll.h> /* struct pollfd, radcli_ctx_get_poll() */
#include <radcli/radcli-defs.h>

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

/** \defgroup radcli2-ctx Context & Configuration
 * @brief Building a radcli_ctx from a config file, or entirely
 *  programmatically, without ever including radcli.h.
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

/** \enum radcli_opt_id Recognised configuration option identifiers.
 *
 * Generated from the same X()-macro list (RC_OPTION_TABLE, radcli-defs.h)
 * that drives radcli.h's string-based rc_add_config()/rc_read_config()
 * grammar, so the two APIs can never recognise a different set of option
 * names by accident. Each value here shares its ordinal position with the
 * corresponding legacy rc_option_id, which is how
 * radcli_ctx_set_opt_str()/_set_opt_int() reach the same underlying storage
 * rc_add_config() does.
 */
typedef enum radcli_opt_id {
#define RADCLI_OPT_ENTRY(id, name, type) RADCLI_##id,
	RC_OPTION_TABLE
#undef RADCLI_OPT_ENTRY
	RADCLI_OPT_COUNT
} radcli_opt_id;

/** \enum radcli_ctx_flags Flags for radcli_ctx_new() and radcli_ctx_read_config().
 *
 * A bitwise OR of these is passed as the flags parameter; 0 is the common
 * case.
 */
typedef enum radcli_ctx_flags {
	RADCLI_CTX_NO_BUILTIN_DICT = 1 << 0 //!< Skip loading the built-in RFC 2865/2866/2869 dictionary.
} radcli_ctx_flags;

radcli_ctx *radcli_ctx_new(unsigned flags);

radcli_ctx *radcli_ctx_read_config(const char *filename, unsigned flags);

int radcli_ctx_set_opt_str(radcli_ctx *ctx, radcli_opt_id opt, const char *val);

int radcli_ctx_set_opt_int(radcli_ctx *ctx, radcli_opt_id opt, long val);

const char *radcli_ctx_get_opt_str(const radcli_ctx *ctx, radcli_opt_id opt);

int radcli_ctx_get_opt_int(const radcli_ctx *ctx, radcli_opt_id opt, long *out);

int radcli_ctx_apply(radcli_ctx *ctx);

int radcli_ctx_read_dictionary(radcli_ctx *ctx, const char *path);

int radcli_ctx_read_dictionary_from_buffer(radcli_ctx *ctx, const char *buf, size_t size);

/** \enum radcli_secret_target Which server(s) a radcli_ctx_set_secret() call
 *  applies to.
 *
 * A bitwise OR of these is passed as radcli_ctx_set_secret()'s target_mask,
 * so a deployment where the authserver and acctserver share one secret --
 * the common case -- can set it in a single call rather than being forced
 * to call radcli_ctx_set_secret() twice with the same value.
 */
typedef enum radcli_secret_target {
	RADCLI_SECRET_AUTH = 1 << 0, //!< Applies to the configured authserver (Access-Request).
	RADCLI_SECRET_ACCT = 1 << 1  //!< Applies to the configured acctserver (Accounting-Request).
} radcli_secret_target;

int radcli_ctx_set_secret(radcli_ctx *ctx, unsigned target_mask, const char *secret);

int radcli_ctx_set_tls_psk(radcli_ctx *ctx,
			    const void *identity, size_t identity_len,
			    const uint8_t *key, size_t keylen);

void radcli_ctx_free(radcli_ctx *ctx);

/** @} */

/** \defgroup radcli2-dict Dictionary
 * @brief Looking up an attribute's definition -- name, wire type, OID, and
 *  named VALUEs -- from the dictionary a radcli_ctx has loaded.
 *
 * @{
 */

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
 *
 * Every enumerator below documents the radcli_avp_add_*()/radcli_avp_get_*()
 * pair that reads and writes it, so a caller never has to read lib/avp.c to
 * find the right function for a given radcli_attr_def's type.
 */
typedef enum radcli_attr_type {
	RADCLI_TYPE_STRING = 0,     //!< A printable string of opaque octets.
	                            //!< Read/written with radcli_avp_add_str()/
	                            //!< radcli_avp_get_cstr() (NUL-terminated
	                            //!< text access) or, for the raw bytes with
	                            //!< no NUL/UTF-8 checks, radcli_avp_add_bytes()/
	                            //!< radcli_avp_get_bytes().
	RADCLI_TYPE_INTEGER = 1,    //!< A 32-bit integer, host byte order.
	                            //!< Read/written with radcli_avp_add_uint32()/
	                            //!< radcli_avp_get_uint32().
	RADCLI_TYPE_IPADDR = 2,     //!< An IPv4 address in host byte order.
	                            //!< Written with radcli_avp_add_ip4()
	                            //!< (takes a struct in_addr) or
	                            //!< radcli_avp_add_uint32() (takes the
	                            //!< address as a host-byte-order uint32_t);
	                            //!< read back with radcli_avp_get_uint32()
	                            //!< -- there is no separate ip4 getter.
	RADCLI_TYPE_DATE = 3,       //!< Seconds since epoch, as a 32-bit integer.
	                            //!< Implements RFC 8044 SS3.5's "time" data
	                            //!< type; the dictionary may spell an
	                            //!< attribute of this type "date" or "time".
	                            //!< Read/written with radcli_avp_add_uint32()/
	                            //!< radcli_avp_get_uint32(), same as
	                            //!< RADCLI_TYPE_INTEGER.
	RADCLI_TYPE_IPV6ADDR = 4,   //!< A 128-bit IPv6 address. Read/written
	                            //!< with radcli_avp_add_ip6()/
	                            //!< radcli_avp_get_ip6(), passing prefix 0.
	RADCLI_TYPE_IPV6PREFIX = 5, //!< An IPv6 prefix (RFC 3162 wire format).
	                            //!< Read/written with radcli_avp_add_ip6()/
	                            //!< radcli_avp_get_ip6(), same pair as
	                            //!< RADCLI_TYPE_IPV6ADDR but with a
	                            //!< meaningful prefix length.
	RADCLI_TYPE_INTEGER64 = 6,  //!< A 64-bit integer, network byte order on
	                            //!< the wire. Read/written with
	                            //!< radcli_avp_add_uint64()/
	                            //!< radcli_avp_get_uint64() -- the same pair
	                            //!< RADCLI_TYPE_IFID uses below, since both
	                            //!< are 8 raw octets.
	RADCLI_TYPE_IPV4PREFIX = 7, //!< An IPv4 prefix (RFC 8044 SS3.9 wire format).
	                            //!< Read/written with
	                            //!< radcli_avp_add_ip4prefix()/
	                            //!< radcli_avp_get_ip4prefix().
	RADCLI_TYPE_TEXT = 8,       //!< UTF-8 human-readable text (RFC 8044 SS3.1),
	                            //!< distinct from RADCLI_TYPE_STRING's opaque
	                            //!< octets. radcli_avp_add_str() accepts both
	                            //!< RADCLI_TYPE_STRING and RADCLI_TYPE_TEXT
	                            //!< attributes, validating UTF-8 only for the
	                            //!< latter; radcli_avp_get_cstr() likewise
	                            //!< validates UTF-8 only for RADCLI_TYPE_TEXT,
	                            //!< in addition to its embedded-NUL check for
	                            //!< every type.
	RADCLI_TYPE_IFID = 9        //!< An 8-octet IPv6 interface identifier in
	                            //!< network byte order (RFC 8044 SS3.7's
	                            //!< "ifid" data type; the dictionary spells
	                            //!< it "ifid" -- e.g. Framed-Interface-Id,
	                            //!< etc/dictionary attribute 96, RFC 3162
	                            //!< SS2.3). Not a numeric quantity, but
	                            //!< identical in wire shape to
	                            //!< RADCLI_TYPE_INTEGER64 (8 raw octets), so
	                            //!< it is read/written with the very same
	                            //!< radcli_avp_add_uint64()/
	                            //!< radcli_avp_get_uint64() pair rather than
	                            //!< a dedicated ifid-specific function.
} radcli_attr_type;

/** Opaque dictionary attribute definition.
 *
 * Obtained from radcli_dict_lookup(), radcli_dict_lookup_oid(), or
 * radcli_dict_lookup_num(). Owned by the dictionary loaded into the
 * radcli_ctx that produced it; valid for as long as that context is not
 * destroyed and its dictionary is not reloaded. Never freed by the caller.
 *
 * A caller that already has a `PW_*` constant (radcli-defs.h, e.g.
 * PW_USER_NAME) for a well-known attribute does not need to obtain one of
 * these at all: \ref radcli2-avp-by-num (radcli_avp_add_str_by_num() etc.)
 * and \ref radcli2-avp-get-by-num take the `PW_*` ID directly and resolve
 * it against the radcli_ctx's dictionary internally, the same one-call
 * shape src/radexample.c uses throughout.
 */
struct radcli_attr_def_st;
typedef struct radcli_attr_def_st radcli_attr_def;

const radcli_attr_def *radcli_dict_lookup(const radcli_ctx *ctx, const char *name);

const radcli_attr_def *radcli_dict_lookup_oid(const radcli_ctx *ctx, const char *oid);

const radcli_attr_def *radcli_dict_lookup_num(const radcli_ctx *ctx, uint32_t attrid, uint32_t vendor);

const char *radcli_attr_def_name(const radcli_attr_def *def);

radcli_attr_type radcli_attr_def_type(const radcli_attr_def *def);

int radcli_attr_def_oid(const radcli_attr_def *def, char *buf, size_t buflen);

int radcli_dict_lookup_value(const radcli_ctx *ctx, const radcli_attr_def *def,
			      const char *name, uint32_t *out);

/** @} */

/** \defgroup radcli2-avp Attribute-Value Pair Handling
 * @brief Building a request's attributes and reading back a reply's,
 *  through the radcli_avp_list/radcli_avp opaque types rather than
 *  radcli.h's VALUE_PAIR linked list.
 *
 * @{
 */

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

radcli_avp_list *radcli_avp_list_new(void);

void radcli_avp_list_free(radcli_avp_list *list);

int radcli_avp_add_bytes(radcli_avp_list *list, const radcli_attr_def *def, const void *value, size_t len);

int radcli_avp_add_str(radcli_avp_list *list, const radcli_attr_def *def, const char *value);

int radcli_avp_add_uint32(radcli_avp_list *list, const radcli_attr_def *def, uint32_t value);

int radcli_avp_add_uint64(radcli_avp_list *list, const radcli_attr_def *def, uint64_t value);

int radcli_avp_add_ip4(radcli_avp_list *list, const radcli_attr_def *def, struct in_addr value);

int radcli_avp_add_ip6(radcli_avp_list *list, const radcli_attr_def *def,
			const struct in6_addr *value, unsigned prefix);

int radcli_avp_add_ip4prefix(radcli_avp_list *list, const radcli_attr_def *def,
			      struct in_addr value, unsigned prefix);

/** \defgroup radcli2-avp-by-num radcli_avp_add_*_by_num() -- lookup-and-add in one call
 * @brief Convenience wrappers over radcli_dict_lookup_num() + the matching
 *  radcli_avp_add_*(), for the common case of a well-known attribute a
 *  caller already has a legacy `PW_*` constant for.
 *
 * Each folds a radcli_dict_lookup_num() call into the add itself, so
 * appending a well-known attribute (e.g. one of the RFC 2865/2866/2869
 * attributes the built-in dictionary radcli_ctx_read_config() loads always
 * carries) is back to a single call with a single failure path, instead of
 * a separate lookup, a NULL check on its result, and then the add --
 * exactly the rc_avpair_add() shape radcli.h callers are used to. The
 * un-suffixed radcli_avp_add_*() functions remain the right choice when a
 * radcli_attr_def is already in hand (e.g. reused across a loop, or
 * obtained via radcli_dict_lookup()/radcli_dict_lookup_oid() for a name or
 * OID rather than a numeric ID), or when a NULL from the lookup is a
 * meaningful, distinct outcome the caller wants to detect on its own (e.g.
 * an attribute that depends on an optional, caller-supplied dictionary).
 *
 * @{
 */

int radcli_avp_add_bytes_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				 uint32_t attrid, uint32_t vendor,
				 const void *value, size_t len);

int radcli_avp_add_str_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
			       uint32_t attrid, uint32_t vendor, const char *value);

int radcli_avp_add_uint32_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, uint32_t value);

int radcli_avp_add_uint64_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, uint64_t value);

int radcli_avp_add_ip4_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, struct in_addr value);

int radcli_avp_add_ip6_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
			       uint32_t attrid, uint32_t vendor,
			       const struct in6_addr *value, unsigned prefix);

int radcli_avp_add_ip4prefix_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				     uint32_t attrid, uint32_t vendor,
				     struct in_addr value, unsigned prefix);

/** @} */

int radcli_avp_add_username(radcli_avp_list *list, const radcli_ctx *ctx,
			     const char *username, const char *realm);

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

radcli_avp_iter radcli_avp_list_iter(const radcli_avp_list *list);

const radcli_avp *radcli_avp_iter_next(radcli_avp_iter *it);

const radcli_attr_def *radcli_avp_def(const radcli_avp *a);

int radcli_avp_get_uint32(const radcli_avp *a, uint32_t *out);

int radcli_avp_get_uint64(const radcli_avp *a, uint64_t *out);

int radcli_avp_get_ip6(const radcli_avp *a, struct in6_addr *out, unsigned *prefix);

int radcli_avp_get_ip4prefix(const radcli_avp *a, struct in_addr *out, unsigned *prefix);

int radcli_avp_get_bytes(const radcli_avp *a, const void **out, size_t *len);

const char *radcli_avp_get_cstr(const radcli_avp *a);

/** \defgroup radcli2-avp-get-by-num radcli_avp_get_*_by_num() -- lookup-and-get in one call
 * @brief Receive-side mirror of \ref radcli2-avp-by-num: fold
 *  radcli_dict_lookup_num() + radcli_avp_get() + the matching typed getter
 *  into one call, for the common case of a well-known, single-occurrence
 *  attribute a caller already has a legacy `PW_*` constant for.
 *
 * Each returns the *first* occurrence only (idx 0) -- the common case for
 * every attribute that is not documented to legitimately repeat. An
 * attribute that can carry more than one meaningful occurrence in a single
 * reply (e.g. Reply-Message, Framed-Route) needs radcli_avp_get_by_num()
 * (this group's plain finder, which does take idx) in a small loop instead
 * -- see radcli_avp_concat_str_by_num() for the specific, very common case
 * of concatenating every occurrence of a text attribute.
 *
 * @{
 */

const radcli_avp *radcli_avp_get_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
					 uint32_t attrid, uint32_t vendor, unsigned idx);

int radcli_avp_get_uint32_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, uint32_t *out);

int radcli_avp_get_uint64_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, uint64_t *out);

int radcli_avp_get_ip6_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
			       uint32_t attrid, uint32_t vendor,
			       struct in6_addr *out, unsigned *prefix);

int radcli_avp_get_ip4prefix_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
				     uint32_t attrid, uint32_t vendor,
				     struct in_addr *out, unsigned *prefix);

int radcli_avp_get_bytes_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
				 uint32_t attrid, uint32_t vendor,
				 const void **out, size_t *len);

const char *radcli_avp_get_cstr_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
					uint32_t attrid, uint32_t vendor);

/** @} */

/** \defgroup radcli2-avp-concat radcli_avp_concat_str()/_by_num() -- join every occurrence of a text attribute
 * @brief Concatenate every occurrence of an attribute into a bounded buffer,
 *  following snprintf()'s buffer-sizing contract (buf may be NULL/buflen may
 *  be 0 to size a buffer first; the return value is always the number of
 *  bytes the joined result would occupy, whether or not it fit).
 * @{
 */

int radcli_avp_concat_str(char *buf, size_t buflen, const radcli_avp_list *list,
			   const radcli_attr_def *def, const char *sep);

int radcli_avp_concat_str_by_num(char *buf, size_t buflen, const radcli_avp_list *list,
				  const radcli_ctx *ctx, uint32_t attrid, uint32_t vendor,
				  const char *sep);

/** @} */

int radcli_avp_list_error(const radcli_avp_list *list);

int radcli_avp_add_gigawords64(radcli_ctx *ctx, radcli_avp_list *list,
			     const radcli_attr_def *octets, uint64_t value);

int radcli_avp_get_gigawords64(const radcli_ctx *ctx, const radcli_avp_list *list,
			     const radcli_attr_def *octets, uint64_t *out);

int radcli_avp_add_gigawords64_by_num(radcli_ctx *ctx, radcli_avp_list *list,
				       uint32_t attrid, uint32_t vendor, uint64_t value);

int radcli_avp_get_gigawords64_by_num(const radcli_ctx *ctx, const radcli_avp_list *list,
				       uint32_t attrid, uint32_t vendor, uint64_t *out);

/** @} */


/** \defgroup radcli2-messaging RADIUS messaging
 * @brief Building a radcli_request, exchanging it with the server, and
 *  reading back the reply's code and attributes -- or radcli_aaa() for the
 *  send-and-wait-for-reply case in one call.
 *
 * @{
 */

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

/** \enum radcli_error_cause RADIUS Error-Cause (attribute 101) values, per
 * the IANA registry (RFC 5176 SS3.5, RFC 5580 SS3.3, RFC 7930 SS4).
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
	RADCLI_ERROR_INVALID_ATTRIBUTE_VALUE = 407,
	RADCLI_ERROR_ADMINISTRATIVELY_PROHIBITED = 501,
	RADCLI_ERROR_REQUEST_NOT_ROUTABLE = 502,
	RADCLI_ERROR_SESSION_CONTEXT_NOT_FOUND = 503,
	RADCLI_ERROR_SESSION_CONTEXT_NOT_REMOVABLE = 504,
	RADCLI_ERROR_OTHER_PROXY_PROCESSING_ERROR = 505,
	RADCLI_ERROR_RESOURCES_UNAVAILABLE = 506,
	RADCLI_ERROR_REQUEST_INITIATED = 507,
	RADCLI_ERROR_MULTIPLE_SESSION_SELECTION_UNSUPPORTED = 508,
	RADCLI_ERROR_LOCATION_INFO_REQUIRED = 509,
	RADCLI_ERROR_RESPONSE_TOO_BIG = 601
} radcli_error_cause;

/** \enum radcli_result Outcome of radcli_request_perform().
 *
 * RADCLI_OK is always 0 and every failure outcome is a distinct negative
 * value. Test for success with `result == RADCLI_OK`; treat every other
 * value -- including ones not listed here yet -- as failure. Do not test
 * for a specific non-OK value (e.g. `!= RADCLI_ERROR`) and assume anything
 * else means success: that pattern silently treats an unhandled outcome
 * (such as RADCLI_TIMEOUT) as a validated reply.
 */
typedef enum radcli_result {
	RADCLI_OK = 0,        //!< A validated reply was received; see radcli_request_code() for which one.
	RADCLI_ERROR = -1,    //!< Malformed input, a verification failure, or no server configured.
	RADCLI_TIMEOUT = -2,  //!< No reply from any address the server name resolved to.
	/** Only ever returned by radcli_request_wait(): still waiting for a
	 * reply. Poll radcli_request_fd(r) (or wait for radcli_request_timeout_ms(r)
	 * to elapse) and call radcli_request_wait() again. Never returned by
	 * radcli_request_perform() itself. */
	RADCLI_AGAIN = -3
} radcli_result;

/** Opaque RADIUS request/reply exchange.
 *
 * Construct with radcli_request_new(), send it and await the reply with
 * radcli_request_perform(), read the outcome with the accessors below, and
 * release with radcli_request_free().
 */
struct radcli_request_st;
typedef struct radcli_request_st radcli_request;

/** \enum radcli_request_flags Flags for radcli_request_perform(). */
typedef enum radcli_request_flags {
	RADCLI_REQUEST_NONE = 0,
	/** Transmit r once and return once the packet is handed to the
	 * network, without blocking for a reply. Two uses:
	 *
	 * - Fire-and-forget: call radcli_request_free() without ever calling
	 *   radcli_request_wait(). A best-effort notification whose outcome
	 *   the caller does not act on, e.g. an accounting stop sent during
	 *   shutdown; radcli.h's rc_acct_async() is the equivalent call in
	 *   the legacy API.
	 * - Poll-driven async request/reply: read the reply later with
	 *   radcli_request_fd()/_poll_events()/_timeout_ms()/_wait(), driven
	 *   by the caller's own poll()/select() loop, e.g. from an
	 *   application built around an event loop that cannot afford to
	 *   block a thread on radcli_request_perform(r, RADCLI_REQUEST_NONE).
	 *
	 * Either way, only the first address the server name resolves to is
	 * tried -- no DNS-level fail-over, unlike RADCLI_REQUEST_NONE -- but
	 * retransmission to that one address, up to the configured retry
	 * count, still happens for the poll-driven case. */
	RADCLI_REQUEST_SENDONLY = 1 << 0
} radcli_request_flags;

radcli_request *radcli_request_new(radcli_ctx *ctx, radcli_code code, const radcli_avp_list *send);

int radcli_request_perform(radcli_request *r, unsigned flags);

/* Poll-driven async progress for a request sent with RADCLI_REQUEST_SENDONLY;
 * see lib/request.c's doc comments on each of these for the full contract
 * and a usage example. */
int radcli_request_fd(const radcli_request *r);
short radcli_request_poll_events(const radcli_request *r);
int radcli_request_timeout_ms(const radcli_request *r);
int radcli_request_wait(radcli_request *r, int fd_ready);

radcli_code radcli_request_code(const radcli_request *r);

const radcli_avp_list *radcli_request_attrs(const radcli_request *r);

const char *radcli_request_server(const radcli_request *r);

void radcli_request_free(radcli_request *r);

int radcli_aaa(radcli_ctx *ctx, radcli_code code, const radcli_avp_list *send,
	       radcli_code *out_code, radcli_avp_list **out_attrs);

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
 * When the nas-identifier config option is set, every request's own
 * NAS-Identifier (if it carries one) is checked against it automatically,
 * before radcli_dae_handler ever sees the request: a mismatch is NAKed with
 * RADCLI_ERROR_NAS_IDENTIFICATION_MISMATCH and the handler is not invoked.
 * Pass RADCLI_DAE_NO_NAS_CHECK to radcli_dae_new() to disable this check.
 * NAS-IP-Address/NAS-IPv6-Address are never compared: a value a DAC observed
 * for a NAS routinely differs from what the NAS itself is configured with
 * (NAT, containers, a proxy/load balancer in front of the NAS), unlike
 * NAS-Identifier, which both sides are explicitly, statically configured
 * with.
 *
 * @{
 */

/** Opaque RFC 5176 dynamic-authorization listener. */
typedef struct radcli_dae_st radcli_dae;

/** Opaque validated CoA-Request or Disconnect-Request, passed to a
 * radcli_dae_handler. By the time an application sees one, it has already
 * passed source-address authorization, Request Authenticator verification,
 * Message-Authenticator verification (when present, or unconditionally
 * under dae-require-message-authenticator), Event-Timestamp freshness,
 * duplicate suppression, and (unless RADCLI_DAE_NO_NAS_CHECK was passed to
 * radcli_dae_new()) the NAS-Identifier check -- see radcli_ctx_dispatch()'s
 * doc comment. */
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

radcli_code radcli_dae_req_code(const radcli_dae_request *req);

const radcli_avp_list *radcli_dae_req_attrs(const radcli_dae_request *req);

const char *radcli_dae_req_session_id(const radcli_dae_request *req);

const char *radcli_dae_req_user_name(const radcli_dae_request *req);

int radcli_dae_req_framed_ip(const radcli_dae_request *req, struct sockaddr_storage *out);

int radcli_dae_req_nas_port(const radcli_dae_request *req, uint32_t *out);

int radcli_dae_reply(radcli_dae_request *req, int ack);

int radcli_dae_reply_error(radcli_dae_request *req, uint32_t error_cause);

int radcli_dae_reply_to_buffer(radcli_dae_request *req, int ack, uint32_t error_cause,
			       void *buf, size_t *len);

void radcli_dae_request_free(radcli_dae_request *req);

/** radcli_dae_process() succeeded, producing a newly validated request that
 * needs an application decision. */
#define RADCLI_DAE_NEW 0
/** radcli_dae_process() succeeded, producing a request that is a
 * retransmission of one already answered: no new decision to make, and
 * radcli_dae_reply_to_buffer() on it reproduces that cached answer
 * regardless of the ack/error_cause passed to it. */
#define RADCLI_DAE_DUPLICATE 1

int radcli_dae_process(radcli_dae *dae, const void *buf, size_t len,
		       const struct sockaddr *from, socklen_t fromlen,
		       radcli_dae_request **req);

/** \enum radcli_dae_flags Flags for radcli_dae_new().
 *
 * A bitwise OR of these is passed as radcli_dae_new()'s flags parameter; 0
 * is the common case.
 */
typedef enum radcli_dae_flags {
	RADCLI_DAE_NO_NAS_CHECK = 1 << 0 //!< Skip the automatic check of a
	                                 //!< request's NAS-Identifier against
	                                 //!< the nas-identifier config option.
} radcli_dae_flags;

radcli_dae *radcli_dae_new(radcli_ctx *ctx, unsigned flags);

void radcli_dae_set_handler(radcli_dae *dae, radcli_dae_handler cb, void *user);

int radcli_dae_start(radcli_dae *dae);

void radcli_dae_free(radcli_dae *dae);

/** The maximum number of descriptors radcli_ctx_get_poll() ever reports in
 * one call: the request-registry socket/session (REQ-NET2-SEND-016) and,
 * for UDP with an active radcli_dae, the separate DAE listener socket --
 * genuinely different local sockets that cannot be merged into one without
 * changing the wire protocol. Every other case (TLS/DTLS regardless of
 * radcli_dae; UDP with no radcli_dae) reports at most 1. */
#define RADCLI_CTX_MAX_POLLFDS 2

int radcli_ctx_get_poll(radcli_ctx *ctx, struct pollfd *pfds, size_t max_pfds,
			size_t *nfds, int *timeout_ms);

int radcli_ctx_dispatch(radcli_ctx *ctx);

/** @} */


/** \example radexample.c
 * This is an example of how to use the radcli2.h API.
 */

/** \example radexample-advanced.c
 * radexample.c's Access-Request, plus a working RFC 5176 Disconnect
 * server and an RFC 5997 watchdog to keep a TLS/DTLS session alive --
 * built entirely on radcli2.h.
 */

/** \example radiusclient-tls.conf
 * This is an configuration file with TLS.
 */

/** \example radiusclient.conf
 * This is an example configuration file listing the available options.
 */

/** \example servers
 * This is an example servers configuration file.
 */

/** \example servers-tls
 * This is an example servers configuration file with TLS PSK.
 */

/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif /* RADCLI2_H */
