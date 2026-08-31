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

/** @file dict2.h
 * @brief Internal, hash-indexed dictionary storage.
 *
 * This is the canonical implementation of the RADIUS dictionary: parsing,
 * loading, and O(1) lookup by name/id/vendor, backed by uthash
 * (lib/uthash/uthash.h). It is internal only -- never included from any
 * public header under include/radcli/, and never linked against by
 * anything outside lib/.
 *
 * rc_read_dictionary()/rc_read_dictionary_from_buffer()/rc_dict_free()
 * (the three entry points every known caller -- radcli's own tools and
 * ocserv -- actually uses) are implemented here, under their existing
 * public names/signatures, and keep rc_handle's exact documented contract
 * (REQ-DICT-INIT-001/002, REQ-DICT-DATA-008). lib/dict.c's remaining
 * rc_dict_*() lookup/construction functions are a thin compatibility shim
 * over the functions declared below, kept only so the frozen public ABI
 * (DICT_ATTR/DICT_VALUE/DICT_VENDOR returned by pointer) keeps working;
 * new internal code should call the functions here directly instead of
 * going through that shim. See doc/requirements/dict.md.
 */

#ifndef RC_DICT2_H
#define RC_DICT2_H

#include <stdint.h>
#include <stddef.h>
#include <radcli/radcli.h>
#include "uthash/uthash.h"

/* RC_NAME_LENGTH (radcli.h) is the hard bound already enforced on every
 * attribute/value/vendor name at load time (REQ-DICT-ERR-001), so a fixed
 * RC_NAME_LENGTH+1 array is sized correctly for both the display copy and
 * the lowercased hash key -- no heap allocation needed for names. */
#define RC_DICT2_KEY_LEN (RC_NAME_LENGTH + 1)

/* Lowercases src into dst (case-insensitive hash key), truncating at
 * dstsize - 1 like strlcpy -- callers always pass a name already validated
 * against RC_NAME_LENGTH, so truncation never actually triggers. Shared
 * (static inline, header-only) between lib/dict2.c and lib/dict2-parse.c,
 * both of which hash names into the same tables. */
static inline void dict2_lc(char *dst, size_t dstsize, const char *src)
{
	size_t i;

	for (i = 0; i + 1 < dstsize && src[i] != '\0'; i++)
		dst[i] = (char)tolower((unsigned char)src[i]);
	dst[i] = '\0';
}

/* Narrows a struct radcli_dict_attr's type for use as a legacy VALUE_PAIR/
 * DICT_ATTR's rc_attr_type. dict2-parse.c encodes RFC 8044 types radcli2.h
 * added typed accessors for but the legacy API never had (integer64,
 * ipv4prefix, text, ifid) as sentinels >= PW_TYPE_MAX -- never a legal
 * rc_attr_type, and rc_dict_addattr() itself rejects them for legacy
 * callers constructing their own attributes. But a DICT_ATTR/VALUE_PAIR for
 * one of the *bundled* dictionary's own attributes (e.g. User-Name as
 * "text") can still reach a legacy rc_new()/rc_read_config() context, so
 * every place legacy code copies a struct radcli_dict_attr's type into a
 * legacy field, or switches on one to decide how to handle a value, must
 * go through this first -- PW_TYPE_STRING is the same opaque-bytes
 * handling every legacy caller already gets for an actual "string"
 * attribute, and is wire-compatible with all four sentinel types' encoding
 * (fixed-size or length-prefixed octets either way). Shared (static
 * inline, header-only) so lib/dict2.c's radcli_dict_attr_to_legacy() and
 * lib/legacy/avpair.c's direct struct radcli_dict_attr access can't drift
 * out of sync on which types need narrowing. */
static inline rc_attr_type radcli_dict_type_to_legacy(rc_attr_type type)
{
	return type < PW_TYPE_MAX ? type : PW_TYPE_STRING;
}

struct radcli_dict_attr {
	char name[RC_DICT2_KEY_LEN];     /* as loaded, original case */
	char name_key[RC_DICT2_KEY_LEN]; /* lowercased; hh_name's key */
	uint64_t value;                  /* RADCLI_VENDOR_ATTR_SET(id, vendor) */
	rc_attr_type type;
	DICT_ATTR *legacy;               /* lazily materialized shadow for the
					   * lib/dict.c shim; NULL until first touch */
	UT_hash_handle hh_name;          /* indexed by name_key */
	UT_hash_handle hh_id;            /* indexed by value */
};

/* encrypt_type/has_tag (RFC 2868 SS3.1/SS3.5, RFC 2548 SS2.4.2-2.4.3) and
 * the Octets/Gigawords pairing (RFC 2866/2869) are kept as side tables
 * keyed by attribute id, deliberately NOT fields on radcli_dict_attr
 * itself: rc_dict_addattr()/a dictionary redefinition never dedup the same
 * (id, vendor) under a new name or from a later-loaded dictionary (e.g.
 * the built-in "Password"/"User-Password" id-2 alias pair, or a caller's
 * supplemental dictionary shadowing the built-in one -- see
 * etc/dictionary), so two distinct radcli_dict_attr nodes can legitimately
 * mean the same wire attribute. A side table entry is inserted only when
 * an ATTRIBUTE line actually sets the flag/pairing it carries, so a later
 * redefinition that omits encrypt=/has_tag/gigawords= cannot shadow-out an
 * earlier definition's entry the way a plain radcli_dict_attr redefinition
 * shadows the lookup tables above -- the flag stays "sticky" for that id
 * for as long as any loaded definition set it. This exactly replicates the
 * pre-dict2 dict_encrypt_flag/dict_counter64_pair side lists' behavior,
 * just hash-indexed instead of linearly scanned. */
struct radcli_dict_flags {
	uint64_t attr_id; /* RADCLI_VENDOR_ATTR_SET(id, vendor), as radcli_dict_attr.value */
	int encrypt_type; /* 0, 1 (User-Password), 2 (Tunnel-Password) */
	int has_tag;       /* RFC 2868 SS3.1 tunnel-attribute tag flag */
	UT_hash_handle hh;
};

struct radcli_dict_gigawords {
	uint64_t attr_id; /* RADCLI_VENDOR_ATTR_SET(id, vendor), as radcli_dict_attr.value */
	uint64_t gigawords_attrid; /* vendor-combined id of the Gigawords
				     * counterpart */
	UT_hash_handle hh;
};

/* Compound key for radcli_dict_value's hh_attr index: rc_dict_getval()
 * resolves a VALUE by (attribute name, integer value) together, so both
 * must be part of the same hashed key. A fixed-size struct (rather than a
 * concatenated string) keeps the key a single contiguous, directly
 * comparable byte range, as uthash's HASH_ADD/HASH_FIND require. */
struct radcli_dict_value_key {
	char attrname_key[RC_DICT2_KEY_LEN]; /* lowercased */
	uint32_t value;
};

/* Compound key for radcli_dict_value's hh_attr_name index:
 * radcli_dict_value_by_attr_name() (radcli2.h's radcli_dict_lookup_value())
 * resolves a VALUE by name scoped to one attribute -- a VALUE name is only
 * unique within the ATTRIBUTE that defines it (dict2_check_value() only
 * guards attrname+value pairs against a conflicting name, not the reverse),
 * so two different attributes may each legitimately define a VALUE named
 * e.g. "Yes", and a name-only lookup like values_by_name/hh_name below
 * would not know which one a caller meant. */
struct radcli_dict_value_name_key {
	char attrname_key[RC_DICT2_KEY_LEN]; /* lowercased */
	char name_key[RC_DICT2_KEY_LEN];     /* lowercased */
};

struct radcli_dict_value {
	char attrname[RC_DICT2_KEY_LEN];
	char name[RC_DICT2_KEY_LEN];
	char name_key[RC_DICT2_KEY_LEN]; /* lowercased; hh_name's key */
	struct radcli_dict_value_key attr_key; /* hh_attr's key */
	struct radcli_dict_value_name_key attr_name_key; /* hh_attr_name's key */
	uint32_t value;
	DICT_VALUE *legacy;
	UT_hash_handle hh_name;
	UT_hash_handle hh_attr;
	UT_hash_handle hh_attr_name;
};

struct radcli_dict_vendor {
	char name[RC_DICT2_KEY_LEN];
	char name_key[RC_DICT2_KEY_LEN]; /* lowercased; hh_name's key */
	uint32_t pec; /* IANA Private Enterprise Number (RFC 2865 SS5.26
			* Vendor-Specific); "PEC"/"PEN" is this attribute's own
			* traditional RADIUS name, kept for consistency with the
			* legacy DICT_VENDOR.vendorpec field it mirrors. */
	DICT_VENDOR *legacy;
	UT_hash_handle hh_name;
	UT_hash_handle hh_pec;
};

/* One dictionary: six uthash tables (two indexes each for attrs/values/
 * vendors). Reachable only via rc_handle's own rh->dict (include/includes.h)
 * -- there is no free-standing constructor in the public shape of this API,
 * since every known caller reaches the dictionary through an rc_handle. */
struct radcli_dict {
	struct radcli_dict_attr *attrs_by_name;
	struct radcli_dict_attr *attrs_by_id;
	struct radcli_dict_value *values_by_name;
	struct radcli_dict_value *values_by_attr;
	struct radcli_dict_value *values_by_attr_name;
	struct radcli_dict_vendor *vendors_by_name;
	struct radcli_dict_vendor *vendors_by_pec;
	struct radcli_dict_flags *flags_by_attr_id;
	struct radcli_dict_gigawords *gigawords_by_attr_id;
};

/* Lazily allocates rh->dict on first use -- every entry point (the loader
 * and the three radcli_dict_*_add() backers) needs one, and none of
 * radcli's own callers require a dictionary to have been loaded first
 * (tests/dict-add.c calls rc_dict_addattr() straight after rc_new()). */
static inline int dict2_ensure(rc_handle *rh)
{
	if (rh->dict != NULL)
		return 0;

	rh->dict = calloc(1, sizeof(*rh->dict));
	if (rh->dict == NULL) {
		rc_log(LOG_CRIT, "radcli: dictionary: out of memory");
		return -1;
	}
	return 0;
}

/* Real implementation of the three legacy entry points every known caller
 * uses (radcli's own lib/src, and every external caller checked -- e.g.
 * ocserv's src/acct/radius.c, src/auth/radius.c -- calls only these three).
 * Same contract as before: rc_read_dictionary() guards against re-reading
 * rh->first_dict_read (REQ-DICT-INIT-001), rc_read_dictionary_from_buffer()
 * parses buf with $INCLUDE disabled (REQ-DICT-INIT-002), rc_dict_free()
 * clears rh->dict but MUST NOT touch rh->first_dict_read (REQ-DICT-DATA-008,
 * owned/released by rc_config_free() instead). Declared in radcli.h; defined
 * in lib/dict2.c. */

/* Programmatic construction, backing rc_dict_addattr()/addval()/addvend()
 * in the lib/dict.c shim. Same name-length/type-range validation as the
 * file/buffer parser. Creates rh->dict on first use if not already loaded. */
struct radcli_dict_attr *radcli_dict_attr_add(rc_handle *rh, const char *name,
					       uint32_t value, int type, uint32_t vendorspec);
struct radcli_dict_value *radcli_dict_value_add(rc_handle *rh, const char *attrname,
						 const char *name, uint32_t value);
struct radcli_dict_vendor *radcli_dict_vendor_add(rc_handle *rh, const char *name,
						   uint32_t vendorspec);

/* O(1) lookups (all case-insensitive on name, per REQ-DICT-DATA-006). */
struct radcli_dict_attr *radcli_dict_attr_by_name(rc_handle const *rh, const char *name);
struct radcli_dict_attr *radcli_dict_attr_by_id(rc_handle const *rh, uint64_t value);
struct radcli_dict_value *radcli_dict_value_by_name(rc_handle const *rh, const char *name);
struct radcli_dict_value *radcli_dict_value_by_attr(rc_handle const *rh, const char *attrname, uint32_t value);
struct radcli_dict_value *radcli_dict_value_by_attr_name(rc_handle const *rh, const char *attrname, const char *name);
struct radcli_dict_vendor *radcli_dict_vendor_by_name(rc_handle const *rh, const char *name);
struct radcli_dict_vendor *radcli_dict_vendor_by_pec(rc_handle const *rh, uint32_t pec);

/* encrypt_type/has_tag/gigawords side-table lookups, by attribute id
 * (RADCLI_VENDOR_ATTR_SET()-combined) -- see struct radcli_dict_flags's
 * comment above for why these are not radcli_dict_attr fields. Return NULL
 * if no ATTRIBUTE line ever set the corresponding flag/pairing for that id. */
struct radcli_dict_flags *radcli_dict_flags_by_id(rc_handle const *rh, uint64_t attr_id);
struct radcli_dict_gigawords *radcli_dict_gigawords_by_id(rc_handle const *rh, uint64_t attr_id);

/* Resolves octets's gigawords pairing, if any, to the paired attribute --
 * used directly by radcli_avp_add_gigawords64()/_get_gigawords64()
 * (lib/avp.c). */
struct radcli_dict_attr *radcli_dict_attr_gigawords(rc_handle const *rh, const struct radcli_dict_attr *octets);

/* Legacy-shim support: lazily materializes (and caches on ->legacy) a
 * DICT_ATTR/DICT_VALUE/DICT_VENDOR equivalent to the given entry, for the
 * lib/dict.c rc_dict_*() calls that must keep returning the frozen public
 * struct by pointer. The returned pointer is owned by the dict2 entry and
 * freed along with it by rc_dict_free() -- never freed by the caller. */
DICT_ATTR *radcli_dict_attr_to_legacy(struct radcli_dict_attr *a);
DICT_VALUE *radcli_dict_value_to_legacy(struct radcli_dict_value *v);
DICT_VENDOR *radcli_dict_vendor_to_legacy(struct radcli_dict_vendor *v);

#endif /* RC_DICT2_H */
