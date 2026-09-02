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

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include <ccan/list/list.h>
#include <utf8decode/utf8decode.h>
#include "dict2.h"
#include "util.h"
#include "rc-crypto.h"
#include "avp.h"
#include "options.h"

/** @file avp.c
 * @brief radcli2.h's radcli_avp/radcli_avp_list construction, access, and encoding.
 */

/**
 * @addtogroup radcli2-avp
 *
 * @{
 */

/* radcli_avp/radcli_avp_list construction and access. Values are always
 * stored as heap-allocated, length-carrying bytes -- there is no
 * 253-octet ceiling as in VALUE_PAIR. Typed setters/getters interpret
 * those bytes according to the attribute's radcli_attr_type, validated
 * against radcli_attr_def_type(); wire encoding/decoding is
 * radcli_avp_encode()/radcli_avp_decode(), further down this file.
 *
 * radcli_avp_add_uint64()/radcli_avp_get_uint64() are meaningful only for
 * RADCLI_TYPE_INTEGER64 (RFC 8044 SS3.3's "integer64" data type; see
 * radcli2.h), the dictionary attribute type introduced alongside them for
 * MIP6-Feature-Vector (RFC 5447 SS4.2.5), the one standard attribute of
 * this type, and RADCLI_TYPE_IFID (RFC 8044 SS3.7's "ifid" data type,
 * e.g. Framed-Interface-Id, RFC 3162 SS2.3) -- the two share this pair
 * because both are 8 raw octets, network byte order, on the wire.
 */

/* Doubly-linked via ccan/list rather than a hand-rolled next-only chain, to
 * match the rest of the codebase's convention for its (few) other linked
 * structures -- see lib/dict.c's dict_encrypt_flag / dict_counter64_pair for
 * the singly-linked style used for prepend-only, walk-to-free dictionary
 * side tables.
 *
 * No owner back-pointer: radcli_avp_iter (radcli2.h) carries the list
 * alongside the current position, the same two things any ccan/list or
 * kernel-list iterator needs (a head to detect end-of-list, a node for
 * position) -- so unlike an earlier version of this API, no per-node state
 * is needed just to answer "am I at the end".
 *
 * Locking: none, by design -- same contract as ccan/list itself and as
 * kernel intrusive lists generally. A radcli_avp_list is built by exactly
 * one thread (radcli_avp_list_new() plus radcli_avp_add_*()/
 * radcli_avp_decode()) and is expected to have a single owner at a time
 * thereafter; concurrent readers are fine, a concurrent mutator is not.
 * Nothing here takes a lock, so callers sharing one list across threads
 * (e.g. handing decoded request avps to a worker while another thread still
 * walks them) must serialise that themselves. radcli_avp_iter is a plain
 * value (no allocation, safe to copy, safe to run several independent
 * iterators over one list concurrently, as long as nothing is mutating it),
 * but it is only valid as long as the radcli_avp_list it was constructed
 * from is; nothing detects use of an iterator, or an avp it returned, past
 * that list's radcli_avp_list_free(), same as walking a kernel list past
 * its lifetime. */
struct radcli_avp_st {
	const radcli_attr_def *def;
	struct list_node node;
	size_t len;      /* data holds len bytes, possibly 0 */
	unsigned char data[];
};

struct radcli_avp_list_st {
	struct list_head head;
	int error; /* sticky: set by the first failed add call, see radcli_avp_list_error() */
};

/* linux/list.h has list_is_last(pos, head): true if pos is the last entry,
 * for callers that only have a node, not the list_head, and need to detect
 * end-of-list without walking off it. ccan/list has no equivalent -- every
 * built-in helper takes the head and iterates from there -- so this is that
 * primitive, backing radcli_avp_iter_next() below, rather than a one-off
 * inline pointer compare. */
/*- Report whether n is the last node in list h.
 *
 * @param n the node to check.
 * @param h the list n belongs to.
 * @return true if n has no successor in h, false otherwise.
 -*/
static inline bool avp_list_node_is_last(const struct list_node *n, const struct list_head *h)
{
	return n->next == &h->n;
}

/* Every radcli_avp_add_*()/_by_num() failure routes through here (including
 * radcli_avp_add_bytes()'s own -- the primitive every other add is defined
 * in terms of, but not every add's own validation happens inside it, e.g.
 * radcli_avp_add_str()'s RADCLI_TYPE_STRING check runs before it would ever
 * call radcli_avp_add_bytes()), so radcli_avp_list_error() sees every
 * failure regardless of which layer detected it. NULL-safe: a caller
 * chaining adds onto a list that never allocated (radcli_avp_list_new()
 * returned NULL) still gets a well-defined -1/NULL from every call in this
 * file, not a crash. */
/*- Mark l as having failed and return -1, the common tail of every
 * radcli_avp_add_*() failure path.
 *
 * @param l the list to mark; NULL-safe (a no-op then).
 * @return always -1.
 -*/
static int avp_list_fail(radcli_avp_list *l)
{
	struct radcli_avp_list_st *list = (struct radcli_avp_list_st *)l;

	if (list != NULL)
		list->error = 1;
	return -1;
}

/** @brief Create an empty attribute-value pair list.
 * @return the new list, or NULL on allocation failure.
 */
radcli_avp_list *radcli_avp_list_new(void)
{
	struct radcli_avp_list_st *list = calloc(1, sizeof(*list));
	if (list == NULL) {
		rc_log(LOG_CRIT, "radcli_avp_list_new: out of memory");
		return NULL;
	}
	list_head_init(&list->head);
	return (radcli_avp_list *)list;
}

/** @brief Free a list and every attribute it holds.
 * @param list a list from radcli_avp_list_new(); NULL is accepted and ignored.
 */
void radcli_avp_list_free(radcli_avp_list *list)
{
	struct list_node *n, *next;

	if (list == NULL)
		return;

	/* list_check(), for parity with every other entry point in this file
	 * (list_add_tail()/list_for_each() all run it via list_debug()): a
	 * no-op build (CCAN_LIST_DEBUG unset, as this tree always builds) costs
	 * nothing, but it means turning that debug knob on to chase a real
	 * corruption gets coverage here too, not just on insert/lookup. */
	(void)list_debug(&list->head);

	/* Walk list->head's chain directly and capture next before freeing the
	 * current node, rather than re-deriving the first node with list_top()
	 * once per iteration (as an earlier version of this loop did, replacing
	 * an even earlier list_for_each_safe() that a static analyzer read as a
	 * double-free -- see git history). Once the list is non-empty and
	 * populated from real decoded data (radcli_avp_decode()'s error path,
	 * rather than a small hand-built test list), re-entering list_top()
	 * after each free() gave the same analyzer a *use-after-free* reading
	 * of the identical list_top_() pointer arithmetic instead.
	 *
	 * The actual fix is this loop never converting the sentinel node
	 * (list->head.n) into a (fictitious, one-before-the-allocation)
	 * struct radcli_avp_st * at all: list_entry()/container_of() is only
	 * ever applied to "n" after the loop condition has confirmed it is a
	 * real entry, unlike list_for_each_off()/list_for_each_safe_off(),
	 * which unconditionally form that phantom pointer every iteration
	 * (including the terminating one) purely to compare it against the
	 * head. That phantom pointer is never dereferenced and is exactly the
	 * trick struct list_head-based kernel lists rely on too, but it is
	 * what a static analyzer sees and objects to; not forming it avoids
	 * relying on that "never dereferenced" caveat in the first place.
	 *
	 * list_del() still runs on each node before free(), the standard
	 * "list_del(&pos->list); kfree(pos);" kernel teardown idiom applied
	 * one node at a time: it keeps list->head's links correct at every
	 * step rather than only at the end, and under CCAN_LIST_DEBUG it
	 * poisons the freed node's next/prev, turning any stray second use of
	 * a dangling avp into a NULL-pointer deref instead of walking into
	 * whatever the allocator put in that freed slot next. */
	for (n = list->head.n.next; n != &list->head.n; n = next) {
		struct radcli_avp_st *a = list_entry(n, struct radcli_avp_st, node);

		next = n->next;
		list_del(n);
		free(a);
	}
	free(list);
}

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
int radcli_avp_add_bytes(radcli_avp_list *list, const radcli_attr_def *def, const void *value, size_t len)
{
	struct radcli_avp_st *a;

	if (list == NULL || def == NULL)
		return avp_list_fail(list);
	if (len > 0 && value == NULL)
		return avp_list_fail(list);

	/* Single allocation for the header and its data: data is never
	 * resized after creation, so there is no reason to keep them apart.
	 * One byte larger than len -- calloc() already zero-fills it, so
	 * data[len] is always a free NUL terminator, letting
	 * radcli_avp_get_cstr() hand back a C-string view with no separate
	 * allocation or copy at read time. */
	a = calloc(1, sizeof(*a) + len + 1);
	if (a == NULL) {
		rc_log(LOG_CRIT, "radcli_avp_add_bytes: out of memory");
		return avp_list_fail(list);
	}

	if (len > 0)
		memcpy(a->data, value, len);
	a->len = len;
	a->def = def;

	list_add_tail(&list->head, &a->node);

	return 0;
}

/* RFC 8044 SS3.1 requires RADCLI_TYPE_TEXT values to be valid UTF-8.
 * lib/utf8decode/utf8decode.h's decode() alone does not reject an
 * embedded NUL -- U+0000 is a legal Unicode code point, encoded as a
 * single 0x00 byte -- so that is checked explicitly here too. */
/*- Validate that buf holds RFC 8044 §3.1-conformant UTF-8, rejecting an
 * embedded NUL as well as malformed encoding.
 *
 * @param buf the bytes to validate.
 * @param len buf's length in bytes.
 * @return nonzero if buf is valid UTF-8 with no embedded NUL, zero otherwise.
 -*/
static int is_valid_utf8(const void *buf, size_t len)
{
	const unsigned char *p = buf;
	uint32_t state = UTF8_ACCEPT, codep = 0;
	size_t i;

	for (i = 0; i < len; i++) {
		if (p[i] == 0)
			return 0;
		if (decode(&state, &codep, p[i]) == UTF8_REJECT)
			return 0;
	}
	return state == UTF8_ACCEPT;
}

/** @brief Append a string- or text-typed attribute.
 *
 * Accepts both RADCLI_TYPE_STRING and RADCLI_TYPE_TEXT attributes. For
 * RADCLI_TYPE_STRING, value's bytes are copied verbatim (opaque octets,
 * no validation) -- unchanged from this function's original behavior,
 * so that a caller already using it against an attribute later retagged
 * from "string" to "text" (RFC 8044 SS3.1) in the dictionary keeps
 * working rather than starting to fail with the retag. For
 * RADCLI_TYPE_TEXT, value must additionally be valid UTF-8; invalid
 * UTF-8 is rejected rather than stored.
 *
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_STRING or RADCLI_TYPE_TEXT.
 * @param value a null-terminated string.
 * @return 0 on success, -1 on failure (def is neither RADCLI_TYPE_STRING nor
 *  RADCLI_TYPE_TEXT, value is invalid UTF-8 for a RADCLI_TYPE_TEXT def, or
 *  as radcli_avp_add_bytes()).
 */
int radcli_avp_add_str(radcli_avp_list *list, const radcli_attr_def *def, const char *value)
{
	radcli_attr_type t;

	if (def == NULL || value == NULL)
		return avp_list_fail(list);
	t = radcli_attr_def_type(def);
	if (t != RADCLI_TYPE_STRING && t != RADCLI_TYPE_TEXT)
		return avp_list_fail(list);
	/* A NUL-terminated C string can never itself contain the embedded
	 * NUL is_valid_utf8() also checks for -- strlen() below stops at the
	 * first one -- so that check is redundant here, but harmless and
	 * kept for a single shared implementation with radcli_avp_get_cstr(). */
	if (t == RADCLI_TYPE_TEXT && !is_valid_utf8(value, strlen(value)))
		return avp_list_fail(list);
	return radcli_avp_add_bytes(list, def, value, strlen(value));
}

/** @brief Append an integer/IPv4-address/date-typed attribute.
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_INTEGER, RADCLI_TYPE_IPADDR, or RADCLI_TYPE_DATE.
 * @param value the value; an IPv4 address is given in host byte order.
 * @return 0 on success, -1 on failure (def has none of the accepted types, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_uint32(radcli_avp_list *list, const radcli_attr_def *def, uint32_t value)
{
	radcli_attr_type t;

	if (def == NULL)
		return avp_list_fail(list);
	t = radcli_attr_def_type(def);
	if (t != RADCLI_TYPE_INTEGER && t != RADCLI_TYPE_IPADDR && t != RADCLI_TYPE_DATE)
		return avp_list_fail(list);
	return radcli_avp_add_bytes(list, def, &value, sizeof(value));
}

/** @brief Append a 64-bit integer- or ifid-typed attribute.
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_INTEGER64 or RADCLI_TYPE_IFID
 *  (RFC 8044 SS3.7's "ifid" data type -- an opaque 8-octet value, but
 *  identical in wire shape to RADCLI_TYPE_INTEGER64, so it shares this
 *  setter rather than getting its own).
 * @param value the value; for RADCLI_TYPE_IFID, the raw 8 octets read as a
 *  big-endian uint64_t.
 * @return 0 on success, -1 on failure (def has neither accepted type, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_uint64(radcli_avp_list *list, const radcli_attr_def *def, uint64_t value)
{
	radcli_attr_type t;

	if (def == NULL)
		return avp_list_fail(list);
	t = radcli_attr_def_type(def);
	if (t != RADCLI_TYPE_INTEGER64 && t != RADCLI_TYPE_IFID)
		return avp_list_fail(list);
	return radcli_avp_add_bytes(list, def, &value, sizeof(value));
}

/** @brief Append an IPv4-address-typed attribute from a struct in_addr.
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_IPADDR.
 * @param value the address, in the usual network byte order struct in_addr carries.
 * @return 0 on success, -1 on failure (def is not RADCLI_TYPE_IPADDR, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_ip4(radcli_avp_list *list, const radcli_attr_def *def, struct in_addr value)
{
	uint32_t hostval;

	if (def == NULL || radcli_attr_def_type(def) != RADCLI_TYPE_IPADDR)
		return avp_list_fail(list);
	hostval = ntohl(value.s_addr);
	return radcli_avp_add_bytes(list, def, &hostval, sizeof(hostval));
}

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
int radcli_avp_add_ip6(radcli_avp_list *list, const radcli_attr_def *def,
			const struct in6_addr *value, unsigned prefix)
{
	radcli_attr_type t;
	unsigned char buf[18]; /* RFC 3162: reserved(1) + prefix-len(1) + address(16) */

	if (def == NULL || value == NULL)
		return avp_list_fail(list);
	t = radcli_attr_def_type(def);

	if (t == RADCLI_TYPE_IPV6ADDR) {
		if (prefix != 0)
			return avp_list_fail(list);
		return radcli_avp_add_bytes(list, def, value, 16);
	}
	if (t == RADCLI_TYPE_IPV6PREFIX) {
		if (prefix > 128)
			return avp_list_fail(list);
		buf[0] = 0;
		buf[1] = (unsigned char)prefix;
		memcpy(buf + 2, value, 16);
		return radcli_avp_add_bytes(list, def, buf, sizeof(buf));
	}
	return avp_list_fail(list);
}

/** @brief Append an IPv4-prefix-typed attribute.
 *
 * The RFC 8044 SS3.9 wire format is built internally: a reserved zero
 * octet, the prefix length, and the 4-octet address.
 *
 * A dedicated function rather than a prefix parameter on
 * radcli_avp_add_ip4(): unlike radcli_avp_add_ip6() (which took a prefix
 * parameter from its introduction), radcli_avp_add_ip4() already shipped
 * without one, with real callers; adding one now would force every
 * existing caller to update for a type most of them don't use.
 *
 * @param list destination list.
 * @param def the attribute; must be RADCLI_TYPE_IPV4PREFIX.
 * @param value the address.
 * @param prefix the prefix length (0-32).
 * @return 0 on success, -1 on failure (wrong type, prefix out of range, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_ip4prefix(radcli_avp_list *list, const radcli_attr_def *def,
			      struct in_addr value, unsigned prefix)
{
	unsigned char buf[6]; /* RFC 8044 SS3.9: reserved(1) + prefix-len(1) + address(4) */

	if (def == NULL || radcli_attr_def_type(def) != RADCLI_TYPE_IPV4PREFIX)
		return avp_list_fail(list);
	if (prefix > 32)
		return avp_list_fail(list);
	buf[0] = 0;
	buf[1] = (unsigned char)prefix;
	/* struct in_addr's s_addr is already network byte order, same as the
	 * wire format's address octets -- no ntohl()/htonl() round trip
	 * needed, unlike radcli_avp_add_ip4()'s RADCLI_TYPE_IPADDR case whose
	 * *internal* representation is host byte order. */
	memcpy(buf + 2, &value.s_addr, 4);
	return radcli_avp_add_bytes(list, def, buf, sizeof(buf));
}

/* _by_num() wrappers: fold the radcli_dict_lookup_num() a caller would
 * otherwise write inline into the add call itself, so a well-known
 * attribute goes back to being a single call with a single failure path --
 * the rc_avpair_add() ergonomics of radcli.h -- instead of a separate
 * lookup, a NULL check, and then the add. See radexample.c and
 * REQ-GEN-STYLE-002 (doc/requirements/general.md) for the caller-burden
 * reasoning.
 */

/** @brief Look up an attribute by legacy numeric ID and append its bytes.
 * @param list destination list.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param value the bytes to copy in; may be NULL only if len is 0.
 * @param len number of bytes at value.
 * @return 0 on success, -1 on failure (no such attribute, or as radcli_avp_add_bytes()).
 */
int radcli_avp_add_bytes_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				 uint32_t attrid, uint32_t vendor,
				 const void *value, size_t len)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (def == NULL)
		return avp_list_fail(list);
	return radcli_avp_add_bytes(list, def, value, len);
}

/** @brief Look up a string-typed attribute by legacy numeric ID and append it.
 * @param list destination list.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param value a null-terminated string.
 * @return 0 on success, -1 on failure (no such attribute, or as radcli_avp_add_str()).
 */
int radcli_avp_add_str_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
			       uint32_t attrid, uint32_t vendor, const char *value)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (def == NULL)
		return avp_list_fail(list);
	return radcli_avp_add_str(list, def, value);
}

/** @brief Look up an integer/IPv4-address/date-typed attribute by legacy numeric ID and append it.
 * @param list destination list.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param value the value; an IPv4 address is given in host byte order.
 * @return 0 on success, -1 on failure (no such attribute, or as radcli_avp_add_uint32()).
 */
int radcli_avp_add_uint32_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, uint32_t value)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (def == NULL)
		return avp_list_fail(list);
	return radcli_avp_add_uint32(list, def, value);
}

/** @brief Look up a 64-bit integer-typed attribute by legacy numeric ID and append it.
 * @param list destination list.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param value the value.
 * @return 0 on success, -1 on failure (no such attribute, or as radcli_avp_add_uint64()).
 */
int radcli_avp_add_uint64_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, uint64_t value)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (def == NULL)
		return avp_list_fail(list);
	return radcli_avp_add_uint64(list, def, value);
}

/** @brief Look up an IPv4-address-typed attribute by legacy numeric ID and append it.
 * @param list destination list.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param value the address, in the usual network byte order struct in_addr carries.
 * @return 0 on success, -1 on failure (no such attribute, or as radcli_avp_add_ip4()).
 */
int radcli_avp_add_ip4_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, struct in_addr value)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (def == NULL)
		return avp_list_fail(list);
	return radcli_avp_add_ip4(list, def, value);
}

/** @brief Look up an IPv6-address or IPv6-prefix-typed attribute by legacy numeric ID and append it.
 * @param list destination list.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param value the address.
 * @param prefix the prefix length (0-128); ignored/must be 0 for RADCLI_TYPE_IPV6ADDR.
 * @return 0 on success, -1 on failure (no such attribute, or as radcli_avp_add_ip6()).
 */
int radcli_avp_add_ip6_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
			       uint32_t attrid, uint32_t vendor,
			       const struct in6_addr *value, unsigned prefix)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (def == NULL)
		return avp_list_fail(list);
	return radcli_avp_add_ip6(list, def, value, prefix);
}

/** @brief Look up an IPv4-prefix-typed attribute by legacy numeric ID and append it.
 * @param list destination list.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param value the address.
 * @param prefix the prefix length (0-32).
 * @return 0 on success, -1 on failure (no such attribute, or as radcli_avp_add_ip4prefix()).
 */
int radcli_avp_add_ip4prefix_by_num(radcli_avp_list *list, const radcli_ctx *ctx,
				     uint32_t attrid, uint32_t vendor,
				     struct in_addr value, unsigned prefix)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (def == NULL)
		return avp_list_fail(list);
	return radcli_avp_add_ip4prefix(list, def, value, prefix);
}

/** @brief Append a User-Name AVP, appending a realm as "username@realm"
 *  unless username already contains one.
 *
 * Written for callers (e.g. an application reading its own "default_realm"
 * config knob) that need to send "username@realm" only when the caller-
 * supplied username didn't already come with a realm attached. Passing
 * realm as NULL reaches for ctx's own "default_realm" configuration
 * option, so an application whose realm policy is just "whatever this
 * ctx's config file says" never needs to read that option out itself.
 *
 * @param list destination list.
 * @param ctx a context with a dictionary defining User-Name (any
 *  radcli_ctx_new()/radcli_ctx_read_config() context qualifies).
 * @param username the username; used as-is if it already contains '@'.
 * @param realm realm to append if username has no '@': NULL uses ctx's own
 *  "default_realm" configuration option (no realm appended if that option
 *  is unset or empty); "" explicitly suppresses appending a realm even if
 *  "default_realm" is configured; any other string is used verbatim.
 * @return 0 on success, -1 on failure (no User-Name attribute in ctx's
 *  dictionary, allocation failure, or as radcli_avp_add_str()).
 */
int radcli_avp_add_username(radcli_avp_list *list, const radcli_ctx *ctx,
			     const char *username, const char *realm)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, PW_USER_NAME, 0);
	char *composed;
	size_t len;
	int ret;

	if (def == NULL || username == NULL)
		return avp_list_fail(list);

	if (realm == NULL)
		realm = rc_conf_str_id((rc_handle const *)ctx, OPT_DEFAULT_REALM);

	if (strchr(username, '@') != NULL || realm == NULL || realm[0] == 0)
		return radcli_avp_add_str(list, def, username);

	len = strlen(username) + 1 + strlen(realm) + 1;
	composed = malloc(len);
	if (composed == NULL)
		return avp_list_fail(list);
	snprintf(composed, len, "%s@%s", username, realm);

	ret = radcli_avp_add_str(list, def, composed);
	free(composed);
	return ret;
}

/** @brief Find the idx-th occurrence of an attribute in a list.
 * @param list the list to search.
 * @param def the attribute to look for.
 * @param idx 0 for the first occurrence, 1 for the second, and so on.
 * @return the matching attribute, or NULL if fewer than idx+1 occurrences exist.
 */
const radcli_avp *radcli_avp_get(const radcli_avp_list *list, const radcli_attr_def *def, unsigned idx)
{
	const struct radcli_avp_st *a = NULL;
	unsigned n = 0;

	if (list == NULL || def == NULL)
		return NULL;

	list_for_each(&list->head, a, node) {
		if (a->def == def) {
			if (n == idx)
				return (const radcli_avp *)a;
			n++;
		}
	}
	return NULL;
}

/** @brief Begin iterating list.
 * @param list the list to iterate; NULL is accepted (the iterator yields nothing).
 * @return an iterator positioned at list's first attribute.
 */
radcli_avp_iter radcli_avp_list_iter(const radcli_avp_list *list)
{
	radcli_avp_iter it;

	it.list = list;
	it.cur = list ? (const radcli_avp *)list_top(&list->head, struct radcli_avp_st, node) : NULL;
	return it;
}

/** @brief Return the current attribute and advance.
 * @param it an iterator from radcli_avp_list_iter().
 * @return the current attribute, or NULL once the list is exhausted -- every
 *  subsequent call on the same it also returns NULL; it does not restart.
 */
const radcli_avp *radcli_avp_iter_next(radcli_avp_iter *it)
{
	const struct radcli_avp_st *avp = (const struct radcli_avp_st *)it->cur;
	const radcli_avp *ret = it->cur;

	/* it->cur is resolved once, at radcli_avp_list_iter() construction (the
	 * first element, or NULL for an empty/NULL list) or right here on each
	 * advance -- never re-derived from it->list once it goes NULL. That is
	 * what makes NULL mean "exhausted" unconditionally: a caller that calls
	 * this again after already seeing NULL keeps getting NULL, rather than
	 * silently restarting from the top. */
	if (avp != NULL) {
		const struct radcli_avp_list_st *list = (const struct radcli_avp_list_st *)it->list;

		if (avp_list_node_is_last(&avp->node, &list->head))
			it->cur = NULL;
		else
			it->cur = (const radcli_avp *)list_entry(avp->node.next, struct radcli_avp_st, node);
	}
	return ret;
}

/** @brief Return the attribute definition of a. */
const radcli_attr_def *radcli_avp_def(const radcli_avp *a)
{
	const struct radcli_avp_st *avp = (const struct radcli_avp_st *)a;
	return avp ? avp->def : NULL;
}

/** @brief Read an attribute's value as an integer/IPv4-address/date.
 * @param a the attribute; radcli_avp_def(a) must be RADCLI_TYPE_INTEGER,
 *  RADCLI_TYPE_IPADDR, or RADCLI_TYPE_DATE. An IPv4 address is returned in
 *  host byte order.
 * @param out where to write the value; may be NULL to just check validity.
 * @return 0 on success, -1 if a's type does not match.
 */
int radcli_avp_get_uint32(const radcli_avp *a, uint32_t *out)
{
	const struct radcli_avp_st *avp = (const struct radcli_avp_st *)a;
	radcli_attr_type t;

	if (avp == NULL || avp->def == NULL)
		return -1;
	t = radcli_attr_def_type(avp->def);
	if (t != RADCLI_TYPE_INTEGER && t != RADCLI_TYPE_IPADDR && t != RADCLI_TYPE_DATE)
		return -1;
	if (avp->len != sizeof(uint32_t))
		return -1;

	if (out)
		memcpy(out, avp->data, sizeof(uint32_t));
	return 0;
}

/** @brief Read an attribute's value as a 64-bit integer or ifid.
 * @param a the attribute; radcli_avp_def(a) must be RADCLI_TYPE_INTEGER64
 *  or RADCLI_TYPE_IFID -- see radcli_avp_add_uint64() for why the two
 *  types share this getter.
 * @param out where to write the value (a big-endian uint64_t for
 *  RADCLI_TYPE_IFID); may be NULL to just check validity.
 * @return 0 on success, -1 if a's type is neither.
 */
int radcli_avp_get_uint64(const radcli_avp *a, uint64_t *out)
{
	const struct radcli_avp_st *avp = (const struct radcli_avp_st *)a;
	radcli_attr_type t;

	if (avp == NULL || avp->def == NULL)
		return -1;
	t = radcli_attr_def_type(avp->def);
	if (t != RADCLI_TYPE_INTEGER64 && t != RADCLI_TYPE_IFID)
		return -1;
	if (avp->len != sizeof(uint64_t))
		return -1;

	if (out)
		memcpy(out, avp->data, sizeof(uint64_t));
	return 0;
}

/** @brief Read an attribute's value as an IPv6 address or prefix.
 * @param a the attribute; radcli_avp_def(a) must be RADCLI_TYPE_IPV6ADDR or
 *  RADCLI_TYPE_IPV6PREFIX.
 * @param out where to write the address (zero-padded beyond the prefix
 *  length for RADCLI_TYPE_IPV6PREFIX); may be NULL.
 * @param prefix where to write the prefix length (128 for
 *  RADCLI_TYPE_IPV6ADDR); may be NULL.
 * @return 0 on success, -1 if a's type does not match.
 */
int radcli_avp_get_ip6(const radcli_avp *a, struct in6_addr *out, unsigned *prefix)
{
	const struct radcli_avp_st *avp = (const struct radcli_avp_st *)a;
	radcli_attr_type t;

	if (avp == NULL || avp->def == NULL)
		return -1;
	t = radcli_attr_def_type(avp->def);

	if (t == RADCLI_TYPE_IPV6ADDR) {
		if (avp->len != 16)
			return -1;
		if (out)
			memcpy(out, avp->data, 16);
		if (prefix)
			*prefix = 128;
		return 0;
	}
	if (t == RADCLI_TYPE_IPV6PREFIX) {
		const unsigned char *p = avp->data;
		size_t addrbytes;

		if (avp->len < 2 || avp->len > 18)
			return -1;
		addrbytes = avp->len - 2;

		if (out) {
			memset(out, 0, 16);
			memcpy(out, p + 2, addrbytes);
		}
		if (prefix)
			*prefix = p[1];
		return 0;
	}
	return -1;
}

/** @brief Read an attribute's value as an IPv4 prefix.
 * @param a the attribute; radcli_avp_def(a) must be RADCLI_TYPE_IPV4PREFIX.
 * @param out where to write the address (zero-padded beyond the prefix
 *  length); may be NULL.
 * @param prefix where to write the prefix length; may be NULL.
 * @return 0 on success, -1 if a's type does not match.
 */
int radcli_avp_get_ip4prefix(const radcli_avp *a, struct in_addr *out, unsigned *prefix)
{
	const struct radcli_avp_st *avp = (const struct radcli_avp_st *)a;
	const unsigned char *p;
	size_t addrbytes;

	if (avp == NULL || avp->def == NULL)
		return -1;
	if (radcli_attr_def_type(avp->def) != RADCLI_TYPE_IPV4PREFIX)
		return -1;
	/* Mirrors radcli_avp_get_ip6()'s RADCLI_TYPE_IPV6PREFIX case: tolerate
	 * a wire value shorter than the full address (only reserved(1) +
	 * prefix-len(1) mandatory), zero-padding the rest, rather than
	 * requiring exactly 6 bytes. */
	if (avp->len < 2 || avp->len > 6)
		return -1;
	p = avp->data;
	addrbytes = avp->len - 2;

	if (out) {
		memset(out, 0, sizeof(*out));
		memcpy(out, p + 2, addrbytes);
	}
	if (prefix)
		*prefix = p[1];
	return 0;
}

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
int radcli_avp_get_bytes(const radcli_avp *a, const void **out, size_t *len)
{
	const struct radcli_avp_st *avp = (const struct radcli_avp_st *)a;

	if (avp == NULL)
		return -1;

	if (out)
		*out = avp->data;
	if (len)
		*len = avp->len;
	return 0;
}

/** @brief Read an attribute's value as a NUL-terminated string, with no
 *  allocation or copy.
 *
 * Meaningful for RADCLI_TYPE_STRING and RADCLI_TYPE_TEXT attributes, but
 * callable on any type, like radcli_avp_get_bytes() -- every attribute is
 * stored with a trailing NUL one byte past its real length, so this never
 * allocates. Returns NULL, rather than a silently short string, if the
 * value contains an embedded NUL byte before its real end (logged at
 * LOG_WARNING): a server-supplied value of e.g. "admin\0attacker" must not
 * be readable back as the trusted string "admin" by any caller that treats
 * this return value as the whole attribute. Use radcli_avp_get_bytes()
 * instead for an attribute where an embedded NUL is expected and meaningful
 * (e.g. one whose dictionary type is not RADCLI_TYPE_STRING or
 * RADCLI_TYPE_TEXT).
 *
 * For a RADCLI_TYPE_TEXT attribute specifically, this also returns NULL
 * (logged at LOG_WARNING) if the value is not valid UTF-8 (RFC 8044
 * SS3.1) -- checked here as well as in radcli_avp_add_str(), since an
 * attribute can also be populated by radcli_avp_decode() from a received
 * packet, whose bytes never went through add-side validation.
 * RADCLI_TYPE_STRING attributes have no such requirement: NUL-checked
 * only, like every other type.
 *
 * @param a the attribute.
 * @return a pointer valid for a's lifetime (owned by the list a came from --
 *  never freed by the caller), or NULL if a is NULL, its value contains an
 *  embedded NUL byte, or (for RADCLI_TYPE_TEXT) its value is not valid
 *  UTF-8.
 */
const char *radcli_avp_get_cstr(const radcli_avp *a)
{
	const struct radcli_avp_st *avp = (const struct radcli_avp_st *)a;

	if (avp == NULL)
		return NULL;

	/* An embedded NUL before the real end would make any C-string
	 * function (strlen()/strcmp()/printf("%s")) stop early and silently
	 * see a shorter value than what was actually received -- e.g. a
	 * server-supplied Class value of "admin\0attacker" read back as the
	 * trusted string "admin". Reject rather than hand back a pointer
	 * that looks like a complete string but isn't. */
	if (avp->len > 0 && memchr(avp->data, 0, avp->len) != NULL) {
		rc_log(LOG_WARNING, "radcli_avp_get_cstr: %s contains an embedded "
				    "NUL byte, refusing to return a C string",
		       radcli_attr_def_name(avp->def));
		return NULL;
	}

	/* RADCLI_TYPE_TEXT (RFC 8044 SS3.1) additionally requires valid UTF-8.
	 * radcli_avp_add_str() already enforces this for values added through
	 * this API, but an attribute can also be populated by
	 * radcli_avp_decode() from a received packet, whose bytes never went
	 * through add-side validation -- check again here so a malicious or
	 * buggy peer cannot smuggle invalid UTF-8 into what this function
	 * hands back as "text". RADCLI_TYPE_STRING attributes are unaffected:
	 * their opaque octets were never required to be UTF-8. */
	if (radcli_attr_def_type(avp->def) == RADCLI_TYPE_TEXT &&
	    !is_valid_utf8(avp->data, avp->len)) {
		rc_log(LOG_WARNING, "radcli_avp_get_cstr: %s contains invalid "
				    "UTF-8, refusing to return a C string",
		       radcli_attr_def_name(avp->def));
		return NULL;
	}

	/* data[len] is always a valid, zeroed byte: radcli_avp_add_bytes()
	 * over-allocates by one for exactly this. */
	return (const char *)avp->data;
}

/* radcli_avp_get_*_by_num(): the receive-side mirror of
 * radcli_avp_add_*_by_num() -- fold radcli_dict_lookup_num() +
 * radcli_avp_get() + the matching typed getter into one call for the
 * common, single-occurrence case. See radcli2.h for the full rationale.
 */

/** @brief Look up the idx-th occurrence of an attribute by legacy numeric ID.
 * @param list the list to search.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param idx 0 for the first occurrence, 1 for the second, and so on.
 * @return the matching attribute, or NULL if no such attribute is defined,
 *  or fewer than idx+1 occurrences exist in list.
 */
const radcli_avp *radcli_avp_get_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
					 uint32_t attrid, uint32_t vendor, unsigned idx)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (def == NULL)
		return NULL;
	return radcli_avp_get(list, def, idx);
}

/** @brief Look up an integer/IPv4-address/date-typed attribute by legacy numeric ID and read its first occurrence.
 * @param list the list to search.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param out where to write the value; an IPv4 address is returned in host byte order. May be NULL.
 * @return 0 on success, -1 on failure (no such attribute, no occurrence, or as radcli_avp_get_uint32()).
 */
int radcli_avp_get_uint32_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, uint32_t *out)
{
	const radcli_avp *a = radcli_avp_get_by_num(list, ctx, attrid, vendor, 0);

	if (a == NULL)
		return -1;
	return radcli_avp_get_uint32(a, out);
}

/** @brief Look up a 64-bit integer-typed attribute by legacy numeric ID and read its first occurrence.
 * @param list the list to search.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param out where to write the value. May be NULL.
 * @return 0 on success, -1 on failure (no such attribute, no occurrence, or as radcli_avp_get_uint64()).
 */
int radcli_avp_get_uint64_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
				  uint32_t attrid, uint32_t vendor, uint64_t *out)
{
	const radcli_avp *a = radcli_avp_get_by_num(list, ctx, attrid, vendor, 0);

	if (a == NULL)
		return -1;
	return radcli_avp_get_uint64(a, out);
}

/** @brief Look up an IPv6-address or IPv6-prefix-typed attribute by legacy numeric ID and read its first occurrence.
 * @param list the list to search.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param out where to write the address. May be NULL.
 * @param prefix where to write the prefix length. May be NULL.
 * @return 0 on success, -1 on failure (no such attribute, no occurrence, or as radcli_avp_get_ip6()).
 */
int radcli_avp_get_ip6_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
			       uint32_t attrid, uint32_t vendor,
			       struct in6_addr *out, unsigned *prefix)
{
	const radcli_avp *a = radcli_avp_get_by_num(list, ctx, attrid, vendor, 0);

	if (a == NULL)
		return -1;
	return radcli_avp_get_ip6(a, out, prefix);
}

/** @brief Look up an IPv4-prefix-typed attribute by legacy numeric ID and read its first occurrence.
 * @param list the list to search.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param out where to write the address. May be NULL.
 * @param prefix where to write the prefix length. May be NULL.
 * @return 0 on success, -1 on failure (no such attribute, no occurrence, or as radcli_avp_get_ip4prefix()).
 */
int radcli_avp_get_ip4prefix_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
				     uint32_t attrid, uint32_t vendor,
				     struct in_addr *out, unsigned *prefix)
{
	const radcli_avp *a = radcli_avp_get_by_num(list, ctx, attrid, vendor, 0);

	if (a == NULL)
		return -1;
	return radcli_avp_get_ip4prefix(a, out, prefix);
}

/** @brief Look up an attribute by legacy numeric ID and read its first occurrence's raw bytes.
 * @param list the list to search.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param out where to write a pointer to the value; valid for list's lifetime. May be NULL.
 * @param len where to write the value's length in bytes. May be NULL.
 * @return 0 on success, -1 on failure (no such attribute, or no occurrence).
 */
int radcli_avp_get_bytes_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
				 uint32_t attrid, uint32_t vendor,
				 const void **out, size_t *len)
{
	const radcli_avp *a = radcli_avp_get_by_num(list, ctx, attrid, vendor, 0);

	if (a == NULL)
		return -1;
	return radcli_avp_get_bytes(a, out, len);
}

/** @brief Look up an attribute by legacy numeric ID and read its first occurrence as a NUL-terminated string.
 * @param list the list to search.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @return a pointer valid for list's lifetime (owned by list -- never freed
 *  by the caller), or NULL if no such attribute is defined, no occurrence
 *  exists, or as radcli_avp_get_cstr() (embedded NUL byte, or invalid UTF-8
 *  for a RADCLI_TYPE_TEXT attribute).
 */
const char *radcli_avp_get_cstr_by_num(const radcli_avp_list *list, const radcli_ctx *ctx,
					uint32_t attrid, uint32_t vendor)
{
	const radcli_avp *a = radcli_avp_get_by_num(list, ctx, attrid, vendor, 0);

	if (a == NULL)
		return NULL;
	return radcli_avp_get_cstr(a);
}

/* radcli_avp_concat_str()/_by_num(): the generic form of the one convenience
 * legacy rc_aaa() folded into its own signature (its "msg" parameter,
 * lib/legacy/buildreq.c), for any attribute that can legitimately repeat,
 * not just Reply-Message. */
/** @brief Concatenate every occurrence of an attribute into a bounded buffer.
 *
 * Generalizes the one convenience legacy radcli.h's rc_aaa() folded into
 * its own call signature (its `msg` parameter: "will contain the
 * concatenation of any PW_REPLY_MESSAGE received", lib/buildreq.c) to any
 * attribute, since the pattern -- walk every occurrence of one attribute in
 * a reply, join as text -- is not specific to Reply-Message. A caller
 * wanting rc_aaa()'s old convenience no longer needs to hand-roll the
 * radcli_avp_get()-in-a-loop this replaces.
 *
 * If no occurrence of def is present in list, buf is set to an empty string
 * and 0 is returned -- this is not a failure, the same way rc_aaa()'s msg
 * started as `'\0'` and simply stayed that way when no Reply-Message
 * arrived. An attribute whose value contains an embedded NUL byte, or (for
 * a RADCLI_TYPE_TEXT attribute) invalid UTF-8, is skipped (radcli_avp_get_cstr()'s
 * policy), not treated as a failure either.
 *
 * Follows snprintf()'s buffer-sizing contract exactly: buf may be NULL and/or
 * buflen may be 0 to size a buffer before allocating one (nothing is written
 * in that case), and the return value is always the number of bytes the
 * joined result would occupy, whether or not it fit -- a return `>= buflen`
 * means the result was truncated, and buf (if non-NULL and buflen > 0) then
 * holds only a valid NUL-terminated prefix of what fits, never garbage and
 * never unterminated.
 *
 * @param buf destination buffer, or NULL to only compute the needed size;
 *  always left NUL-terminated on return (including on truncation, containing
 *  whatever fit), whenever buf is non-NULL and buflen > 0.
 * @param buflen size of buf, in bytes; may be 0.
 * @param list the list to search.
 * @param def the attribute to concatenate occurrences of.
 * @param sep separator inserted between occurrences; NULL or "" for none.
 * @return the number of bytes the joined result occupies (excluding the NUL
 *  terminator), whether or not it fit in buf -- or -1 if def is NULL.
 */
int radcli_avp_concat_str(char *buf, size_t buflen, const radcli_avp_list *list,
			   const radcli_attr_def *def, const char *sep)
{
	const radcli_avp *a;
	unsigned idx;
	size_t used = 0, total = 0;
	size_t seplen = sep ? strlen(sep) : 0;
	int truncated = (buf == NULL || buflen == 0);

	if (def == NULL)
		return -1;

	if (buf != NULL && buflen > 0)
		buf[0] = 0;

	for (idx = 0; (a = radcli_avp_get(list, def, idx)) != NULL; idx++) {
		const char *s = radcli_avp_get_cstr(a);
		size_t slen;

		if (s == NULL)
			continue; /* embedded NUL: radcli_avp_get_cstr()'s own skip policy */
		slen = strlen(s);

		if (total > 0 && seplen > 0) {
			total += seplen;
			if (!truncated) {
				if (used + seplen >= buflen) {
					truncated = 1;
				} else {
					memcpy(buf + used, sep, seplen);
					used += seplen;
					buf[used] = 0;
				}
			}
		}
		total += slen;
		if (!truncated) {
			if (used + slen >= buflen) {
				truncated = 1;
			} else {
				memcpy(buf + used, s, slen);
				used += slen;
				buf[used] = 0;
			}
		}
	}
	return (int)total;
}

/** @brief Look up an attribute by legacy numeric ID and concatenate every occurrence into a bounded buffer.
 *
 * The `_by_num()` wrapper for radcli_avp_concat_str(): equivalent to
 * `radcli_avp_concat_str(buf, buflen, l, radcli_dict_lookup_num(ctx, attrid,
 * vendor), sep)`, except that an unresolvable attribute ID is not itself a
 * failure here -- it is treated the same as "no occurrence present" (buf set
 * to an empty string, 0 returned), matching this function's legacy-ID
 * convenience role: a caller passing a well-known `PW_*` constant should not
 * have to separately handle "not in this dictionary" as an error case, the
 * same way rc_aaa()'s `msg` never failed just because a reply had no
 * Reply-Message.
 *
 * @param buf destination buffer, or NULL to only compute the needed size; see radcli_avp_concat_str().
 * @param buflen size of buf, in bytes; may be 0.
 * @param list the list to search.
 * @param ctx a context with a dictionary loaded.
 * @param attrid the attribute ID (a PW_* constant, or a vendor type ID when vendor is non-zero).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param sep separator inserted between occurrences; NULL or "" for none.
 * @return the number of bytes the joined result occupies (excluding the NUL
 *  terminator), whether or not it fit in buf; 0 if attrid/vendor resolves to
 *  no attribute.
 */
int radcli_avp_concat_str_by_num(char *buf, size_t buflen, const radcli_avp_list *list,
				  const radcli_ctx *ctx, uint32_t attrid, uint32_t vendor,
				  const char *sep)
{
	const radcli_attr_def *def = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (def == NULL) {
		if (buf != NULL && buflen > 0)
			buf[0] = 0;
		return 0;
	}
	return radcli_avp_concat_str(buf, buflen, list, def, sep);
}

/** @brief Check whether any radcli_avp_add_*()/_by_num() call on list has ever failed.
 *
 * Once any add call on a given list fails, the list remembers it (sticky --
 * the first failure, not just the most recent). This lets a caller build a
 * whole request as a flat sequence of add calls with no per-call check,
 * then check once, here, before sending -- instead of the ~6-line
 * "if (radcli_avp_add_...(...) != 0) { log; abort; }" block repeated at
 * every call site, which has only one realistic recovery action (abort the
 * whole request) regardless of which attribute failed to add.
 *
 * Purely observational: it does not change any radcli_avp_add_*()'s own
 * behavior. Every add call is attempted and returns its own 0/-1 exactly
 * as it would without this function existing, even after an earlier add on
 * the same list has already failed -- a caller checking each call
 * individually (or deliberately testing that one bad attribute is rejected
 * before adding others, as tests/avp.c does) sees no difference. This
 * function only adds a second, aggregate way to notice a failure that
 * already happened, for a caller that would rather check once than at
 * every call site.
 *
 * @param list the list to check; NULL counts as an error (nothing to
 *  build onto), matching how every radcli_avp_add_*() already treats a
 *  NULL list as failure -- so a caller does not need a separate
 *  `if (list == NULL)` check right after radcli_avp_list_new() before
 *  relying on this.
 * @return non-zero if list is NULL or any add call on it has ever failed, 0 otherwise.
 */
int radcli_avp_list_error(const radcli_avp_list *list)
{

	if (list == NULL)
		return 1;
	return list->error ? 1 : 0;
}

/* RFC 2866 SS5.3/5.4 Acct-Input/Output-Octets + RFC 2869 SS5.1/5.2
 * Acct-Input/Output-Gigawords: see radcli2.h's doc comment. */
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
			     const radcli_attr_def *octets, uint64_t value)
{
	rc_handle *rh = (rc_handle *)ctx;
	const radcli_attr_def *gigawords;

	if (rh == NULL || octets == NULL || radcli_attr_def_type(octets) != RADCLI_TYPE_INTEGER)
		return avp_list_fail(list);

	gigawords = (const radcli_attr_def *)radcli_dict_attr_gigawords(rh, (const struct radcli_dict_attr *)octets);
	if (gigawords == NULL) {
		rc_log(LOG_ERR, "radcli_avp_add_gigawords64: %s has no gigawords= "
		    "counterpart configured", radcli_attr_def_name(octets));
		return avp_list_fail(list);
	}

	if (radcli_avp_add_uint32(list, octets, (uint32_t)value) != 0)
		return -1;
	if (value > UINT32_MAX) {
		/* Omitted when it would be zero, matching how a real NAS sends
		 * it -- the previous call already added the octets attribute
		 * either way, so a receiver with no Gigawords support still
		 * gets the low 32 bits it always got. */
		if (radcli_avp_add_uint32(list, gigawords, (uint32_t)(value >> 32)) != 0)
			return -1;
	}
	return 0;
}

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
			     const radcli_attr_def *octets, uint64_t *out)
{
	const rc_handle *rh = (const rc_handle *)ctx;
	const radcli_attr_def *gigawords;
	const radcli_avp *a;
	uint32_t lo, hi = 0;

	if (rh == NULL || octets == NULL)
		return -1;

	gigawords = (const radcli_attr_def *)radcli_dict_attr_gigawords(rh, (const struct radcli_dict_attr *)octets);
	if (gigawords == NULL)
		return -1;

	a = radcli_avp_get(list, octets, 0);
	if (a == NULL || radcli_avp_get_uint32(a, &lo) != 0)
		return -1;

	a = radcli_avp_get(list, gigawords, 0);
	if (a != NULL && radcli_avp_get_uint32(a, &hi) != 0)
		return -1; /* present but not a 32-bit integer: malformed, not "absent" */

	if (out)
		*out = ((uint64_t)hi << 32) | lo;
	return 0;
}

/** @brief Look up the octets attribute by legacy numeric ID and append a 64-bit counter as an Octets/Gigawords pair.
 *
 * The `_by_num()` wrapper for radcli_avp_add_gigawords64(): unlike the
 * other `_by_num()` wrappers, only one attribute ID is needed here, not
 * two -- the Gigawords counterpart is resolved from octets' own
 * dictionary entry (its `gigawords=` option), the same way
 * radcli_avp_add_gigawords64() resolves it from a `radcli_attr_def *`.
 *
 * @param ctx a context with a dictionary loaded.
 * @param list destination list.
 * @param attrid the octets attribute's ID (e.g. PW_ACCT_INPUT_OCTETS).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param value the full 64-bit count.
 * @return 0 on success, -1 on failure (no such attribute, or as radcli_avp_add_gigawords64()).
 */
int radcli_avp_add_gigawords64_by_num(radcli_ctx *ctx, radcli_avp_list *list,
				       uint32_t attrid, uint32_t vendor, uint64_t value)
{
	const radcli_attr_def *octets = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (octets == NULL)
		return avp_list_fail(list);
	return radcli_avp_add_gigawords64(ctx, list, octets, value);
}

/** @brief Look up the octets attribute by legacy numeric ID and reassemble a 64-bit counter from an Octets/Gigawords pair.
 * @param ctx a context with a dictionary loaded.
 * @param list the list to search.
 * @param attrid the octets attribute's ID (e.g. PW_ACCT_INPUT_OCTETS).
 * @param vendor the vendor PEN, or 0 for a standard attribute.
 * @param out where to write the reassembled value; may be NULL to just check validity.
 * @return 0 on success, -1 on failure (no such attribute, or as radcli_avp_get_gigawords64()).
 */
int radcli_avp_get_gigawords64_by_num(const radcli_ctx *ctx, const radcli_avp_list *list,
				       uint32_t attrid, uint32_t vendor, uint64_t *out)
{
	const radcli_attr_def *octets = radcli_dict_lookup_num(ctx, attrid, vendor);

	if (octets == NULL)
		return -1;
	return radcli_avp_get_gigawords64(ctx, list, octets, out);
}

/** @} */

/* --- radcli_avp_decode()/radcli_avp_encode(): wire codec (internal
 * only) --
 *
 * Not part of the public radcli2 API -- declared in lib/avp.h, not in
 * radcli2.h or radcli.map. Mirrors lib/avpair.c's rc_avpair_gen2()/
 * lib/sendserver.c's rc_pack_list() framing rules exactly (RFC 2865 TLV
 * attributes, RFC 2865 SS5.26 VSA envelope with a 4-octet Vendor-Id).
 *
 * The decode side needs almost no per-type switch: since every radcli_avp
 * stores its value as length-carrying bytes, decoding most attributes is
 * "look it up in the dictionary, copy its value in" regardless of type --
 * the interpretation is deferred to the typed getters. The one exception is
 * the three 4-octet numeric types (INTEGER/IPADDR/DATE), which the wire
 * carries in network byte order but radcli_avp_add_uint32()/
 * radcli_avp_get_uint32() store/read in host byte order (matching legacy
 * VALUE_PAIR->lvalue's convention); decode converts with ntohl() so both
 * construction paths agree on what is in memory. A wrong-length instance of
 * one of these (e.g. a 3-octet INTEGER) is skipped outright, logged and
 * never stored -- the same strict-length policy as RADCLI_TYPE_INTEGER64/
 * _IFID below, rather than storing it un-byte-swapped for
 * radcli_avp_get_uint32() to reject later: ntohl() would read past a
 * too-short value, and there is no use in keeping a too-long one around
 * either, since these are fixed-width types with only one valid length.
 *
 * The other exception is an attribute the dictionary marks
 * "encrypt=Tunnel-Password" (Tunnel-Password, MS-MPPE-Send-Key,
 * MS-MPPE-Recv-Key -- see
 * etc/dictionary and lib/dict2.h's radcli_dict_flags_by_id()): decode
 * transparently reverses the RFC 2868 SS3.5 / RFC 2548 salt-encryption
 * scheme using the caller-supplied secret and request authenticator, and
 * radcli_avp_get_bytes() then returns the plaintext. Only decryption is
 * implemented; radcli_avp_encode() still refuses to originate any
 * encrypt=Tunnel-Password-flagged attribute (Tunnel-Password,
 * MS-MPPE-Send-Key, MS-MPPE-Recv-Key) -- a RADIUS client has not needed to
 * send one. radcli_avp_encode() dispatches on
 * radcli_dict_flags_by_id() too, the same lookup this decode path uses:
 * this is a whitelist, not a blocklist -- an attribute is encoded
 * unencrypted only because the dictionary says it needs no encryption,
 * never because radcli_avp_encode() simply did not recognise that
 * it does. Note that this whitelist only guards against attributes this
 * function *refuses*; it does not by itself guarantee the dictionary is
 * *correct* -- a dictionary missing "encrypt=User-Password" on
 * User-Password would send it as plaintext, no differently than any other
 * unflagged attribute, and this function has no way to tell that apart
 * from a legitimately unflagged one. The n_encrypted out-parameter below
 * exists for exactly that: a caller who knows how many attributes in
 * their own list *should* be RFC 2865 SS5.2-encrypted can compare against
 * it and refuse to send on a mismatch, catching a misloaded or
 * mis-edited dictionary that this function's own whitelist logic cannot
 * detect from the inside.
 */

/* RFC 2868 SS3.5 / RFC 2548 SS2.4.2-2.4.3 "salt-encryption" keystream:
 *   b(1) = MD5(secret || request_authenticator || salt)
 *   b(i) = MD5(secret || c(i-1))                      for i > 1
 *   p(i) = c(i) XOR b(i)
 * ciphertext/plaintext are len bytes, a non-zero multiple of 16; plaintext
 * must have room for len bytes. Used only to decrypt (encrypting these
 * attributes -- e.g. to originate a CoA/Access-Accept -- is not implemented;
 * radcli is a client and has not needed to originate them so far). */
/*- Decrypt an RFC 2868 §3.5 / RFC 2548 §2.4.2-2.4.3 salt-encrypted value.
 *
 * @param plaintext set to the decrypted value; must have room for len bytes.
 * @param ciphertext the encrypted value, len bytes (a non-zero multiple of 16).
 * @param len ciphertext/plaintext's length in bytes.
 * @param secret the shared secret.
 * @param request_authenticator the packet's request authenticator.
 * @param salt the attribute's 2-byte salt.
 -*/
static void salt_decrypt(unsigned char *plaintext, const unsigned char *ciphertext, size_t len,
			 const char *secret, const unsigned char request_authenticator[AUTH_VECTOR_LEN],
			 const unsigned char salt[2])
{
	unsigned char keybuf[MAX_SECRET_LENGTH + AUTH_VECTOR_LEN + 2];
	unsigned char b[16];
	size_t secretlen = rc_secret_len(secret);
	size_t i;

	memcpy(keybuf, secret, secretlen);
	memcpy(keybuf + secretlen, request_authenticator, AUTH_VECTOR_LEN);
	memcpy(keybuf + secretlen + AUTH_VECTOR_LEN, salt, 2);
	rc_md5_calc(b, keybuf, secretlen + AUTH_VECTOR_LEN + 2);

	for (i = 0; i < len; i += 16) {
		size_t j;

		if (i > 0) {
			memcpy(keybuf, secret, secretlen);
			memcpy(keybuf + secretlen, ciphertext + i - 16, 16);
			rc_md5_calc(b, keybuf, secretlen + 16);
		}
		for (j = 0; j < 16; j++)
			plaintext[i + j] = ciphertext[i + j] ^ b[j];
	}
}

/* RFC 2865 SS5.2 User-Password encryption. Same construction as
 * salt_decrypt() with no salt component, but deliberately NOT implemented
 * by generalizing that function to share code: the two run in opposite
 * directions, and b(i) for i>1 must chain from the *ciphertext* of block
 * i-1 either way -- which for encryption is `ciphertext[i-16..i)`, already
 * written by the previous loop iteration, not `plaintext[i-16..i)`. A
 * shared "in/out" primitive would have to read from `out` here and from
 * `in` in the decrypt case, an easy place to introduce a directional bug
 * silently; two small, direction-specific functions are safer than one
 * clever one. len must be a non-zero multiple of 16; ciphertext must have
 * room for len bytes and must not alias plaintext. */
/*- Encrypt a value per RFC 2865 §5.2 User-Password encryption.
 *
 * @param ciphertext set to the encrypted value; must have room for len
 * bytes and must not alias plaintext.
 * @param plaintext the value to encrypt, len bytes (a non-zero multiple of 16).
 * @param len ciphertext/plaintext's length in bytes.
 * @param secret the shared secret.
 * @param request_authenticator the packet's request authenticator.
 -*/
static void user_password_encrypt(unsigned char *ciphertext, const unsigned char *plaintext, size_t len,
				  const char *secret,
				  const unsigned char request_authenticator[AUTH_VECTOR_LEN])
{
	unsigned char keybuf[MAX_SECRET_LENGTH + AUTH_VECTOR_LEN];
	unsigned char b[16];
	size_t secretlen = rc_secret_len(secret);
	size_t i;

	memcpy(keybuf, secret, secretlen);
	memcpy(keybuf + secretlen, request_authenticator, AUTH_VECTOR_LEN);
	rc_md5_calc(b, keybuf, secretlen + AUTH_VECTOR_LEN);

	for (i = 0; i < len; i += 16) {
		size_t j;

		if (i > 0) {
			memcpy(keybuf, secret, secretlen);
			memcpy(keybuf + secretlen, ciphertext + i - 16, 16); /* previously-written block */
			rc_md5_calc(b, keybuf, secretlen + 16);
		}
		for (j = 0; j < 16; j++)
			ciphertext[i + j] = plaintext[i + j] ^ b[j];
	}
}

/*- Decode a run of RADIUS attribute TLVs from ptr_in into list, recursing
 * into VSA sub-attributes.
 *
 * @param rh a handle to parsed configuration.
 * @param secret the shared secret, needed to decrypt an encrypt= attribute.
 * @param request_authenticator the packet's request authenticator.
 * @param list destination list; attributes are appended to it.
 * @param ptr_in the attribute region to decode.
 * @param length ptr_in's length in bytes.
 * @param vendorspec 0 when decoding the packet's top-level attributes,
 * or the enclosing vendor's PEN when recursing into a VSA's sub-attributes.
 * @return 0 on success, -1 on a malformed attribute.
 -*/
static int avp_decode_into(rc_handle const *rh, const char *secret,
			   const uint8_t request_authenticator[AUTH_VECTOR_LEN],
			   struct radcli_avp_list_st *list,
			   const uint8_t *ptr_in, size_t length, uint32_t vendorspec)
{
	pkt_buf pb;
	const uint8_t *attr_data, *ptr;
	int attrlen;
	uint32_t lvalue;
	const radcli_attr_def *def;

	pb_init_read(&pb, (void *)(uintptr_t)ptr_in, length, length);

	while (pb_len(&pb) > 0) {
		if (pb_len(&pb) < 2) {
			rc_log(LOG_ERR, "radcli_avp_decode: received attribute with invalid length");
			return -1;
		}
		attrlen = pb.data[1];
		if (attrlen < 2 || (size_t)attrlen > pb_len(&pb)) {
			rc_log(LOG_ERR, "radcli_avp_decode: received attribute with invalid length");
			return -1;
		}

		attr_data = pb.data;
		if (pb_pull(&pb, attrlen) != 0) {
			rc_log(LOG_ERR, "radcli_avp_decode: internal pb_pull failure");
			return -1;
		}

		ptr = attr_data + 2;
		attrlen -= 2;

		if (vendorspec == 0 && attr_data[0] == PW_VENDOR_SPECIFIC) {
			if (attrlen < 4) {
				rc_log(LOG_WARNING, "radcli_avp_decode: received VSA attribute with invalid length");
				continue;
			}
			memcpy(&lvalue, ptr, 4);
			lvalue = ntohl(lvalue);
			if (radcli_dict_vendor_by_pec(rh, lvalue) == NULL) {
				rc_log(LOG_WARNING, "radcli_avp_decode: received VSA attribute "
				    "with unknown Vendor-Id %u", lvalue);
				continue;
			}
			if (avp_decode_into(rh, secret, request_authenticator, list,
					    ptr + 4, (size_t)(attrlen - 4), lvalue) < 0)
				return -1;
			continue;
		}

		def = radcli_dict_lookup_num(rh, attr_data[0], vendorspec);
		if (def == NULL) {
			if (vendorspec == 0)
				rc_log(LOG_WARNING, "radcli_avp_decode: received unknown "
				    "attribute %u of length %d", (unsigned)attr_data[0], attrlen + 2);
			else
				rc_log(LOG_WARNING, "radcli_avp_decode: received unknown VSA "
				    "attribute %u, vendor %u of length %d",
				    (unsigned)attr_data[0], vendorspec, attrlen + 2);
			continue;
		}

		{
		struct radcli_dict_flags *fl = radcli_dict_flags_by_id(rh, ((const struct radcli_dict_attr *)def)->value);

		if (fl != NULL && fl->encrypt_type == 2) {
			/* RFC 2868 SS3.5 / RFC 2548 SS2.4.2-2.4.3 salt-encryption.
			 * Whether a one-octet Tag precedes the Salt is dictionary data
			 * (the "has_tag" ATTRIBUTE option -- RFC 2868 SS3.1), not an
			 * identity check on Tunnel-Password: Tunnel-Password carries
			 * both encrypt=Tunnel-Password and has_tag; the MS-MPPE-*-Key
			 * VSAs carry encrypt=Tunnel-Password alone. Any framing problem
			 * here is treated the same
			 * as an unrecognised attribute -- logged and skipped, not a
			 * hard decode error, since it is a property of this one
			 * attribute, not of the packet. */
			size_t off = fl->has_tag ? 1 : 0;

			if (secret == NULL || request_authenticator == NULL) {
				rc_log(LOG_WARNING, "radcli_avp_decode: %s is salt-encrypted "
				    "but no secret/request authenticator was supplied; skipping",
				    radcli_attr_def_name(def));
			} else if ((size_t)attrlen < off + 2 + 16 ||
				   ((size_t)attrlen - off - 2) % 16 != 0) {
				rc_log(LOG_WARNING, "radcli_avp_decode: %s has an invalid "
				    "salt-encrypted length", radcli_attr_def_name(def));
			} else {
				size_t ctlen = (size_t)attrlen - off - 2;
				unsigned char plain[AUTH_STRING_LEN];
				unsigned char salt[2];
				unsigned char lenoct;

				memcpy(salt, ptr + off, 2);
				salt_decrypt(plain, ptr + off + 2, ctlen, secret,
					    request_authenticator, salt);
				lenoct = plain[0];
				if (lenoct > ctlen - 1) {
					rc_log(LOG_WARNING, "radcli_avp_decode: %s decrypted to "
					    "an out-of-range length prefix", radcli_attr_def_name(def));
				} else if (radcli_avp_add_bytes((radcli_avp_list *)list, def,
								plain + 1, lenoct) != 0) {
					return -1; /* allocation failure; already logged */
				}
			}
			continue;
		}
		}

		{
			radcli_attr_type t = radcli_attr_def_type(def);

			if (t == RADCLI_TYPE_INTEGER64 || t == RADCLI_TYPE_IFID) {
				/* RFC 8044 SS3.3/SS3.7: integer64 and ifid are both 8
				 * octets, network byte order (high 32 bits first), twice
				 * the width of the four-octet numeric types below -- ifid
				 * shares this branch because its wire shape is
				 * identical, even though it is not itself a numeric
				 * quantity. Same strict length check as that branch: skip
				 * a malformed instance here, like an unrecognised
				 * attribute, rather than storing it for a getter to
				 * reject later. */
				uint32_t hi, lo;
				uint64_t hostval;

				if (attrlen != (int)sizeof(uint64_t)) {
					rc_log(LOG_WARNING, "radcli_avp_decode: %s has an invalid "
					    "integer64/ifid length (%d, expected 8)",
					    radcli_attr_def_name(def), attrlen);
					continue;
				}
				memcpy(&hi, ptr, sizeof(hi));
				memcpy(&lo, ptr + sizeof(hi), sizeof(lo));
				hostval = ((uint64_t)ntohl(hi) << 32) | ntohl(lo);
				if (radcli_avp_add_bytes((radcli_avp_list *)list, def,
							 &hostval, sizeof(hostval)) != 0)
					return -1; /* allocation failure; already logged */
			} else if (t == RADCLI_TYPE_INTEGER || t == RADCLI_TYPE_IPADDR || t == RADCLI_TYPE_DATE) {
				/* Same strict-length policy as RADCLI_TYPE_INTEGER64/_IFID
				 * above: skip a malformed instance rather than storing it
				 * un-byte-swapped for radcli_avp_get_uint32() to reject
				 * later. */
				uint32_t netval, hostval;

				if (attrlen != (int)sizeof(uint32_t)) {
					rc_log(LOG_WARNING, "radcli_avp_decode: %s has an invalid "
					    "integer/ipaddr/date length (%d, expected 4)",
					    radcli_attr_def_name(def), attrlen);
					continue;
				}
				memcpy(&netval, ptr, sizeof(netval));
				hostval = ntohl(netval);
				if (radcli_avp_add_bytes((radcli_avp_list *)list, def,
							 &hostval, sizeof(hostval)) != 0)
					return -1; /* allocation failure; already logged */
			} else {
				if (radcli_avp_add_bytes((radcli_avp_list *)list, def, ptr, (size_t)attrlen) != 0)
					return -1; /* allocation failure; already logged */
			}
		}
	}
	return 0;
}

/* Parses the attribute-value region [ptr, ptr+length) of a received RADIUS
 * packet into a newly allocated radcli_avp_list; vendorspec is 0 for a
 * top-level packet region, or the enclosing vendor's PEN when decoding a
 * VSA's sub-attributes. secret/request_authenticator are used only to
 * decrypt an attribute the dictionary marks "encrypt=Tunnel-Password"
 * (Tunnel-Password, MS-MPPE-Send-Key, MS-MPPE-Recv-Key -- RFC 2868 SS3.5 /
 * RFC 2548); pass
 * secret == NULL if none of those can occur. */
/*- Decode a received RADIUS packet's attribute region into a newly
 * allocated radcli_avp_list.
 *
 * @param rh a handle to parsed configuration.
 * @param secret the shared secret, needed to decrypt an encrypt= attribute;
 * NULL if none can occur.
 * @param request_authenticator the packet's request authenticator.
 * @param ptr the attribute region to decode.
 * @param length ptr's length in bytes.
 * @param vendorspec 0 for a top-level packet region.
 * @param out set to the newly allocated list on success (possibly empty,
 * if every attribute present was unrecognised/undecryptable and skipped).
 * @return 0 on success, -1 on a hard framing error (out left unset) or if
 * rh/out is NULL.
 -*/
int radcli_avp_decode(rc_handle const *rh, const char *secret,
		      const uint8_t request_authenticator[AUTH_VECTOR_LEN],
		      const uint8_t *ptr, size_t length,
		      uint32_t vendorspec, radcli_avp_list **out)
{
	struct radcli_avp_list_st *list;

	if (rh == NULL || out == NULL)
		return -1;

	list = (struct radcli_avp_list_st *)radcli_avp_list_new();
	if (list == NULL)
		return -1;

	if (avp_decode_into(rh, secret, request_authenticator, list, ptr, length, vendorspec) != 0) {
		radcli_avp_list_free((radcli_avp_list *)list);
		return -1;
	}

	*out = (radcli_avp_list *)list;
	return 0;
}

/* Writes list's wire encoding into buf (capacity buflen) -- attribute bytes
 * only, no packet header. rh's dictionary decides which attributes need
 * special handling, via radcli_dict_flags_by_id(): an unflagged attribute
 * is encoded as-is; an "encrypt=User-Password" attribute (RFC 2865 SS5.2 --
 * the one obfuscation scheme this function implements, hence the _rfc2865
 * suffix) is encrypted using secret/request_authenticator (pass secret ==
 * NULL if the list carries none of those -- encoding then fails if it
 * does, rather than sending it unencrypted); any other flagged value,
 * including "encrypt=Tunnel-Password" (Tunnel-Password, MS-MPPE-Send-Key,
 * MS-MPPE-Recv-Key -- RFC 2868 SS3.5 / RFC 2548 salt-encryption, which
 * radcli_avp_decode() reverses but this function does not originate), is
 * refused outright. This is a whitelist: an attribute is only ever encoded
 * unencrypted because the dictionary says it needs no encryption, never
 * because this function failed to recognise that it does -- but the
 * whitelist can only catch attributes it knows to refuse, not a dictionary
 * that is simply missing "encrypt=User-Password" on an attribute that
 * should have it (see the wire-codec comment above for why). If
 * n_encrypted is non-NULL, it is set to the number of attributes this call
 * routed through the RFC 2865 SS5.2 path -- a caller who knows how many
 * User-Password-like attributes their own list should contain can compare
 * against it and refuse to send on a mismatch, rather than trusting the
 * dictionary blindly. Returns the number of bytes written, or -1 on
 * overflow, on User-Password without a secret supplied or longer than
 * AUTH_PASS_LEN (128) bytes, or on any other encrypt-flagged attribute. */
/*- Encode l's wire representation (attribute bytes only, no packet header)
 * into buf.
 *
 * @param rh a handle to parsed configuration.
 * @param l the list to encode.
 * @param secret the shared secret, needed to encrypt an encrypt=
 * User-Password attribute; NULL if the list carries none.
 * @param request_authenticator the packet's request authenticator.
 * @param buf destination buffer for the encoded attributes.
 * @param buflen buf's capacity in bytes.
 * @param n_encrypted if non-NULL, set to the number of attributes encoded
 * via the RFC 2865 §5.2 User-Password path.
 * @return the number of bytes written, or -1 on failure (see the comment
 * above for the specific failure cases).
 -*/
int radcli_avp_encode(rc_handle const *rh, const radcli_avp_list *l, const char *secret,
		      const uint8_t request_authenticator[AUTH_VECTOR_LEN],
		      uint8_t *buf, size_t buflen, size_t *n_encrypted)
{
	const struct radcli_avp_list_st *list = (const struct radcli_avp_list_st *)l;
	const struct radcli_avp_st *a = NULL;
	pkt_buf pb;
	uint8_t *attr_start, *attr_len_ptr, *vsa_len_ptr;
	uint32_t vendor, attrid, netval;
	radcli_attr_type t;

	if (rh == NULL || list == NULL)
		return -1;

	if (n_encrypted != NULL)
		*n_encrypted = 0;

	pb_init(&pb, buf, buflen);

	list_for_each(&list->head, a, node) {
		const struct radcli_dict_attr *def = (const struct radcli_dict_attr *)a->def;
		struct radcli_dict_flags *fl = radcli_dict_flags_by_id(rh, def->value);

		vendor = VENDOR(def->value);
		attrid = ATTRID(def->value);

		/* Whitelist, not a blocklist: only an attribute the dictionary does
		 * NOT flag for encryption, or flags encrypt=User-Password
		 * specifically (which this function implements), is safe to send.
		 * Anything else -- encrypt=Tunnel-Password (Tunnel-Password,
		 * MS-MPPE-Send-Key, MS-MPPE-Recv-Key today; RFC 2868 SS3.5
		 * salt-encryption, which this function does not originate), or any
		 * future encrypt=N this function has no code for -- is refused.
		 * Driving this off the flags_by_attr_id side table rather than an
		 * enumerated attribute list means a dictionary addition can never
		 * silently start sending something in the clear that was supposed
		 * to be encrypted. */
		switch (fl ? fl->encrypt_type : 0) {
		case 0:
			break;
		case 1: {
			unsigned char passbuf[AUTH_PASS_LEN];
			unsigned char cipher[AUTH_PASS_LEN];
			size_t padded_len;

			if (secret == NULL || request_authenticator == NULL) {
				rc_log(LOG_ERR, "radcli_avp_encode: %s requires the shared "
				    "secret and request authenticator, which were not supplied",
				    def->name);
				return -1;
			}
			if (a->len > AUTH_PASS_LEN) {
				/* Legacy rc_pack_list() silently truncates an over-length
				 * password to AUTH_PASS_LEN; that is a footgun (the server
				 * authenticates a different, shorter password than the
				 * caller believes it sent), not behaviour worth repeating
				 * here. Reject instead. */
				rc_log(LOG_ERR, "radcli_avp_encode: %s is %zu bytes, longer "
				    "than the %d-byte RFC 2865 SS5.2 maximum",
				    def->name, a->len, AUTH_PASS_LEN);
				return -1;
			}

			padded_len = ((a->len + (AUTH_VECTOR_LEN - 1)) / AUTH_VECTOR_LEN) * AUTH_VECTOR_LEN;
			if (padded_len == 0)
				padded_len = AUTH_VECTOR_LEN; /* RFC 2865 SS5.2: pad to a
				                                * multiple of 16; an empty
				                                * password still sends one
				                                * (all-zero) block. */

			memset(passbuf, 0, sizeof(passbuf));
			if (a->len > 0)
				memcpy(passbuf, a->data, a->len);
			user_password_encrypt(cipher, passbuf, padded_len, secret, request_authenticator);

			attr_start = pb.tail;
			if (pb_put_byte(&pb, (uint8_t)(attrid & 0xff)) < 0) goto too_large;
			attr_len_ptr = pb.tail;
			if (pb_put_byte(&pb, 2) < 0) goto too_large; /* placeholder; patched below */
			if (pb_put_bytes(&pb, cipher, (int)padded_len) < 0) goto too_large;
			*attr_len_ptr = (uint8_t)(pb.tail - attr_start);
			if (n_encrypted != NULL)
				(*n_encrypted)++;
			continue;
		}
		default:
			rc_log(LOG_ERR, "radcli_avp_encode: %s requires per-request "
			    "encryption, which this function does not perform", def->name);
			return -1;
		}

		if (vendor == 0 && attrid > 0xff) {
			/* An RFC 6929 extended attribute number: not encodable in the
			 * classic RFC 2865 TLV this function writes. The bundled
			 * dictionary carries none today (Phase 1 scope note), so this
			 * is unreachable in practice; kept as a defensive guard rather
			 * than an assumption. */
			rc_log(LOG_ERR, "radcli_avp_encode: %s has an attribute number "
			    "outside the classic RADIUS TLV range", def->name);
			return -1;
		}

		vsa_len_ptr = NULL;
		if (vendor != 0) {
			if (pb_put_byte(&pb, PW_VENDOR_SPECIFIC) < 0) goto too_large;
			vsa_len_ptr = pb.tail;
			if (pb_put_byte(&pb, 6) < 0) goto too_large;
			netval = htonl(vendor);
			if (pb_put_bytes(&pb, &netval, sizeof(netval)) < 0) goto too_large;
		}

		attr_start = pb.tail;
		if (pb_put_byte(&pb, (uint8_t)(attrid & 0xff)) < 0) goto too_large;
		attr_len_ptr = pb.tail;
		if (pb_put_byte(&pb, 2) < 0) goto too_large; /* placeholder; patched below */

		t = radcli_attr_def_type(a->def);
		if (t == RADCLI_TYPE_INTEGER64 || t == RADCLI_TYPE_IFID) {
			/* RFC 8044 SS3.3/SS3.7: 8 octets, network byte order, high 32
			 * bits first -- mirrors the decode side above. */
			uint64_t hostval;
			uint32_t hi, lo;

			if (a->len != sizeof(uint64_t)) {
				rc_log(LOG_ERR, "radcli_avp_encode: %s has the wrong stored "
				    "length for its type", def->name);
				return -1;
			}
			memcpy(&hostval, a->data, sizeof(hostval));
			hi = htonl((uint32_t)(hostval >> 32));
			lo = htonl((uint32_t)hostval);
			if (pb_put_bytes(&pb, &hi, sizeof(hi)) < 0) goto too_large;
			if (pb_put_bytes(&pb, &lo, sizeof(lo)) < 0) goto too_large;
		} else if (t == RADCLI_TYPE_INTEGER || t == RADCLI_TYPE_IPADDR || t == RADCLI_TYPE_DATE) {
			uint32_t hostval;

			if (a->len != sizeof(uint32_t)) {
				rc_log(LOG_ERR, "radcli_avp_encode: %s has the wrong stored "
				    "length for its type", def->name);
				return -1;
			}
			memcpy(&hostval, a->data, sizeof(hostval));
			netval = htonl(hostval);
			if (pb_put_bytes(&pb, &netval, sizeof(netval)) < 0) goto too_large;
		} else {
			if (a->len > AUTH_STRING_LEN - (vendor != 0 ? VSA_HDR_LEN : 0)) {
				rc_log(LOG_ERR, "radcli_avp_encode: %s value too long (%zu bytes)",
				    def->name, a->len);
				return -1;
			}
			if (pb_put_bytes(&pb, a->data, (int)a->len) < 0) goto too_large;
		}

		*attr_len_ptr = (uint8_t)(pb.tail - attr_start);
		if (vsa_len_ptr != NULL)
			*vsa_len_ptr += *attr_len_ptr;
	}

	return (int)pb_written(&pb);

too_large:
	rc_log(LOG_ERR, "radcli_avp_encode: attribute value too large or buffer "
	    "would exceed %zu bytes", buflen);
	return -1;
}

