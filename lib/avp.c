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
#include "util.h"
#include "rc-md5.h"
#include "avp.h"

/**
 * @defgroup radcli2-api New API
 * @brief New, opaque-by-default API functions
 *
 * @{
 */

/* radcli_avp/radcli_avp_list construction and access (decision A, Phase 1 of
 * doc/plan-api-modernization.md). Values are always stored as heap-allocated,
 * length-carrying bytes -- there is no 253-octet ceiling as in VALUE_PAIR,
 * and no attempt here to encode or decode wire format; that is a later
 * commit. Typed setters/getters interpret those bytes according to the
 * attribute's radcli_attr_type, validated against radcli_attr_def_type().
 *
 * radcli_avp_add_uint64()/radcli_avp_get_uint64() are deliberately not
 * implemented yet: they would only be meaningful for RADCLI_TYPE_INTEGER64,
 * which Phase 2 introduces alongside the dictionary attribute that needs it
 * (MIP6-Feature-Vector). Adding them now would be dead API surface with no
 * type that could use it.
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
};

/* linux/list.h has list_is_last(pos, head): true if pos is the last entry,
 * for callers that only have a node, not the list_head, and need to detect
 * end-of-list without walking off it. ccan/list has no equivalent -- every
 * built-in helper takes the head and iterates from there -- so this is that
 * primitive, backing radcli_avp_iter_next() below, rather than a one-off
 * inline pointer compare. */
static inline bool avp_list_node_is_last(const struct list_node *n, const struct list_head *h)
{
	return n->next == &h->n;
}

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

void radcli_avp_list_free(radcli_avp_list *l)
{
	struct radcli_avp_list_st *list = (struct radcli_avp_list_st *)l;
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

int radcli_avp_add_bytes(radcli_avp_list *l, const radcli_attr_def *def, const void *value, size_t len)
{
	struct radcli_avp_list_st *list = (struct radcli_avp_list_st *)l;
	struct radcli_avp_st *a;

	if (list == NULL || def == NULL)
		return -1;
	if (len > 0 && value == NULL)
		return -1;

	/* Single allocation for the header and its data: data is never
	 * resized after creation, so there is no reason to keep them apart. */
	a = calloc(1, sizeof(*a) + len);
	if (a == NULL) {
		rc_log(LOG_CRIT, "radcli_avp_add_bytes: out of memory");
		return -1;
	}

	if (len > 0)
		memcpy(a->data, value, len);
	a->len = len;
	a->def = def;

	list_add_tail(&list->head, &a->node);

	return 0;
}

int radcli_avp_add_str(radcli_avp_list *l, const radcli_attr_def *def, const char *value)
{
	if (def == NULL || value == NULL || radcli_attr_def_type(def) != RADCLI_TYPE_STRING)
		return -1;
	return radcli_avp_add_bytes(l, def, value, strlen(value));
}

int radcli_avp_add_uint32(radcli_avp_list *l, const radcli_attr_def *def, uint32_t value)
{
	radcli_attr_type t;

	if (def == NULL)
		return -1;
	t = radcli_attr_def_type(def);
	if (t != RADCLI_TYPE_INTEGER && t != RADCLI_TYPE_IPADDR && t != RADCLI_TYPE_DATE)
		return -1;
	return radcli_avp_add_bytes(l, def, &value, sizeof(value));
}

int radcli_avp_add_ipaddr(radcli_avp_list *l, const radcli_attr_def *def, struct in_addr value)
{
	uint32_t hostval;

	if (def == NULL || radcli_attr_def_type(def) != RADCLI_TYPE_IPADDR)
		return -1;
	hostval = ntohl(value.s_addr);
	return radcli_avp_add_bytes(l, def, &hostval, sizeof(hostval));
}

int radcli_avp_add_in6(radcli_avp_list *l, const radcli_attr_def *def,
			const struct in6_addr *value, unsigned prefix)
{
	radcli_attr_type t;
	unsigned char buf[18]; /* RFC 3162: reserved(1) + prefix-len(1) + address(16) */

	if (def == NULL || value == NULL)
		return -1;
	t = radcli_attr_def_type(def);

	if (t == RADCLI_TYPE_IPV6ADDR) {
		if (prefix != 0)
			return -1;
		return radcli_avp_add_bytes(l, def, value, 16);
	}
	if (t == RADCLI_TYPE_IPV6PREFIX) {
		if (prefix > 128)
			return -1;
		buf[0] = 0;
		buf[1] = (unsigned char)prefix;
		memcpy(buf + 2, value, 16);
		return radcli_avp_add_bytes(l, def, buf, sizeof(buf));
	}
	return -1;
}

const radcli_avp *radcli_avp_get(const radcli_avp_list *l, const radcli_attr_def *def, unsigned idx)
{
	const struct radcli_avp_list_st *list = (const struct radcli_avp_list_st *)l;
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

radcli_avp_iter radcli_avp_list_iter(const radcli_avp_list *l)
{
	const struct radcli_avp_list_st *list = (const struct radcli_avp_list_st *)l;
	radcli_avp_iter it;

	it.list = l;
	it.cur = list ? (const radcli_avp *)list_top(&list->head, struct radcli_avp_st, node) : NULL;
	return it;
}

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

const radcli_attr_def *radcli_avp_def(const radcli_avp *a)
{
	const struct radcli_avp_st *avp = (const struct radcli_avp_st *)a;
	return avp ? avp->def : NULL;
}

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

int radcli_avp_get_in6(const radcli_avp *a, struct in6_addr *out, unsigned *prefix)
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

/** @} */

/* --- radcli_avp_decode()/radcli_avp_encode_rfc2865(): wire codec (internal
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
 * construction paths agree on what is in memory. Decode does not itself
 * reject a fixed-length type whose wire length is wrong (e.g. a 3-octet
 * INTEGER, left un-byte-swapped since ntohl() would read past it);
 * radcli_avp_get_uint32() already rejects that at read time, and
 * radcli_avp_get_bytes() still lets a caller see the raw (malformed) value,
 * which is strictly more information than rc_avpair_gen2() offers today by
 * silently dropping the attribute.
 *
 * The other exception is an attribute the dictionary marks
 * "encrypt=Tunnel-Password" (Tunnel-Password, MS-MPPE-Send-Key,
 * MS-MPPE-Recv-Key -- see
 * etc/dictionary and lib/dict.c's rc_dict_attr_encrypt_type()): decode
 * transparently reverses the RFC 2868 SS3.5 / RFC 2548 salt-encryption
 * scheme using the caller-supplied secret and request authenticator, and
 * radcli_avp_get_bytes() then returns the plaintext. Only decryption is
 * implemented; radcli_avp_encode_rfc2865() still refuses to originate any
 * encrypt=Tunnel-Password-flagged attribute (Tunnel-Password,
 * MS-MPPE-Send-Key, MS-MPPE-Recv-Key) -- a RADIUS client has not needed to
 * send one. radcli_avp_encode_rfc2865() dispatches on
 * rc_dict_attr_encrypt_type() too, the same lookup this decode path uses:
 * this is a whitelist, not a blocklist -- an attribute is encoded
 * unencrypted only because the dictionary says it needs no encryption,
 * never because radcli_avp_encode_rfc2865() simply did not recognise that
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
/// @cond INTERNAL
static void salt_decrypt(unsigned char *plaintext, const unsigned char *ciphertext, size_t len,
			 const char *secret, const unsigned char request_authenticator[AUTH_VECTOR_LEN],
			 const unsigned char salt[2])
{
	unsigned char keybuf[MAX_SECRET_LENGTH + AUTH_VECTOR_LEN + 2];
	unsigned char b[16];
	size_t secretlen = strlen(secret);
	size_t i;

	if (secretlen > MAX_SECRET_LENGTH)
		secretlen = MAX_SECRET_LENGTH;

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
/// @cond INTERNAL
static void user_password_encrypt(unsigned char *ciphertext, const unsigned char *plaintext, size_t len,
				  const char *secret,
				  const unsigned char request_authenticator[AUTH_VECTOR_LEN])
{
	unsigned char keybuf[MAX_SECRET_LENGTH + AUTH_VECTOR_LEN];
	unsigned char b[16];
	size_t secretlen = strlen(secret);
	size_t i;

	if (secretlen > MAX_SECRET_LENGTH)
		secretlen = MAX_SECRET_LENGTH;

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
/// @endcond

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
			if (rc_dict_getvend(rh, lvalue) == NULL) {
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

		if (rc_dict_attr_encrypt_type(rh, (const DICT_ATTR *)def) == 2) {
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
			int has_tag = rc_dict_attr_has_tag(rh, (const DICT_ATTR *)def);
			size_t off = has_tag ? 1 : 0;

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

		{
			radcli_attr_type t = radcli_attr_def_type(def);

			if ((t == RADCLI_TYPE_INTEGER || t == RADCLI_TYPE_IPADDR || t == RADCLI_TYPE_DATE)
			    && attrlen == (int)sizeof(uint32_t)) {
				uint32_t netval, hostval;

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
/// @endcond

/* Parses the attribute-value region [ptr, ptr+length) of a received RADIUS
 * packet into a newly allocated radcli_avp_list; vendorspec is 0 for a
 * top-level packet region, or the enclosing vendor's PEN when decoding a
 * VSA's sub-attributes. secret/request_authenticator are used only to
 * decrypt an attribute the dictionary marks "encrypt=Tunnel-Password"
 * (Tunnel-Password, MS-MPPE-Send-Key, MS-MPPE-Recv-Key -- RFC 2868 SS3.5 /
 * RFC 2548); pass
 * secret == NULL if none of those can occur. Returns 0 on success (*out set,
 * possibly to an empty list if every attribute present was
 * unrecognised/undecryptable and skipped), -1 on a hard framing error (*out
 * left unset). */
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
 * special handling, via rc_dict_attr_encrypt_type(): an unflagged attribute
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
int radcli_avp_encode_rfc2865(rc_handle const *rh, const radcli_avp_list *l, const char *secret,
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
		const DICT_ATTR *def = (const DICT_ATTR *)a->def;

		vendor = VENDOR(def->value);
		attrid = ATTRID(def->value);

		/* Whitelist, not a blocklist: only an attribute the dictionary does
		 * NOT flag for encryption, or flags encrypt=User-Password
		 * specifically (which this function implements), is safe to send.
		 * Anything else -- encrypt=Tunnel-Password (Tunnel-Password,
		 * MS-MPPE-Send-Key, MS-MPPE-Recv-Key today; RFC 2868 SS3.5
		 * salt-encryption, which this function does not originate), or any
		 * future encrypt=N this function has no code for -- is refused.
		 * Driving this off rc_dict_attr_encrypt_type() rather than an
		 * enumerated attribute list means a dictionary addition can never
		 * silently start sending something in the clear that was supposed
		 * to be encrypted. */
		switch (rc_dict_attr_encrypt_type(rh, def)) {
		case 0:
			break;
		case 1: {
			unsigned char passbuf[AUTH_PASS_LEN];
			unsigned char cipher[AUTH_PASS_LEN];
			size_t padded_len;

			if (secret == NULL || request_authenticator == NULL) {
				rc_log(LOG_ERR, "radcli_avp_encode_rfc2865: %s requires the shared "
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
				rc_log(LOG_ERR, "radcli_avp_encode_rfc2865: %s is %zu bytes, longer "
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
			rc_log(LOG_ERR, "radcli_avp_encode_rfc2865: %s requires per-request "
			    "encryption, which this function does not perform", def->name);
			return -1;
		}

		if (vendor == 0 && attrid > 0xff) {
			/* An RFC 6929 extended attribute number: not encodable in the
			 * classic RFC 2865 TLV this function writes. The bundled
			 * dictionary carries none today (Phase 1 scope note), so this
			 * is unreachable in practice; kept as a defensive guard rather
			 * than an assumption. */
			rc_log(LOG_ERR, "radcli_avp_encode_rfc2865: %s has an attribute number "
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
		if (t == RADCLI_TYPE_INTEGER || t == RADCLI_TYPE_IPADDR || t == RADCLI_TYPE_DATE) {
			uint32_t hostval;

			if (a->len != sizeof(uint32_t)) {
				rc_log(LOG_ERR, "radcli_avp_encode_rfc2865: %s has the wrong stored "
				    "length for its type", def->name);
				return -1;
			}
			memcpy(&hostval, a->data, sizeof(hostval));
			netval = htonl(hostval);
			if (pb_put_bytes(&pb, &netval, sizeof(netval)) < 0) goto too_large;
		} else {
			if (a->len > AUTH_STRING_LEN - (vendor != 0 ? VSA_HDR_LEN : 0)) {
				rc_log(LOG_ERR, "radcli_avp_encode_rfc2865: %s value too long (%zu bytes)",
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
	rc_log(LOG_ERR, "radcli_avp_encode_rfc2865: attribute value too large or buffer "
	    "would exceed %zu bytes", buflen);
	return -1;
}
