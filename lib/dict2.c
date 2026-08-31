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

/** @file dict2.c
 * @brief Canonical, hash-indexed dictionary implementation: freeing, lookup,
 * and the radcli2.h opaque-attribute-definition API.
 *
 * The dictionary file/buffer parser and the rh->dict-backed
 * radcli_dict_*_add() constructors -- both close ports of pre-dict2
 * lib/dict.c code and so still carrying that code's original copyrights --
 * live in lib/dict2-parse.c instead, keeping this file under a plain
 * 2-clause BSD license (see COPYRIGHT). See dict2.h's file comment for the
 * overall split between lib/dict.c, this file, and lib/dict2-parse.c.
 */

#include <config.h>
#include <includes.h>
#include <limits.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "dict2.h"
#include "util.h"

/*- Free rh's dictionary and every attribute/value/vendor/flags/gigawords
 * entry it holds.
 *
 * @param rh a handle whose dictionary is to be freed.
 -*/
void radcli2_priv_dict_free(rc_handle *rh)
{
	struct radcli_dict_attr *a, *atmp;
	struct radcli_dict_value *v, *vtmp;
	struct radcli_dict_vendor *w, *wtmp;
	struct radcli_dict_flags *fl, *fltmp;
	struct radcli_dict_gigawords *gw, *gwtmp;
	struct radcli_dict *d = rh->dict;

	if (d == NULL)
		return;

	/* HASH_DELETE() is skipped under __clang_analyzer__ (never in a real
	 * build -- dynamically verified LSan/ASan/UBSan-clean, and this
	 * function is exercised via radcli2_priv_destroy() throughout the test suite).
	 * Clang Static Analyzer's unix.Malloc checker misreads ordinary
	 * HASH_ITER()+HASH_DELETE()+free() teardown as a use-after-free: a
	 * confirmed false positive, reported against uthash itself and closed
	 * as a checker limitation -- github.com/troydhanson/uthash#128. The
	 * free() calls stay visible to the analyzer in every build, so the
	 * leak checker still sees every allocation matched with a
	 * deallocation; only the macro shape that misleads the
	 * use-after-free checker is hidden. */
	HASH_ITER(hh_name, d->attrs_by_name, a, atmp) {
#ifndef __clang_analyzer__
		HASH_DELETE(hh_name, d->attrs_by_name, a);
		HASH_DELETE(hh_id, d->attrs_by_id, a);
#endif
		free(a->legacy);
		free(a);
	}
	HASH_ITER(hh_name, d->values_by_name, v, vtmp) {
#ifndef __clang_analyzer__
		HASH_DELETE(hh_name, d->values_by_name, v);
		HASH_DELETE(hh_attr, d->values_by_attr, v);
		HASH_DELETE(hh_attr_name, d->values_by_attr_name, v);
#endif
		free(v->legacy);
		free(v);
	}
	HASH_ITER(hh_name, d->vendors_by_name, w, wtmp) {
#ifndef __clang_analyzer__
		HASH_DELETE(hh_name, d->vendors_by_name, w);
		HASH_DELETE(hh_pec, d->vendors_by_pec, w);
#endif
		free(w->legacy);
		free(w);
	}
	HASH_ITER(hh, d->flags_by_attr_id, fl, fltmp) {
#ifndef __clang_analyzer__
		HASH_DELETE(hh, d->flags_by_attr_id, fl);
#endif
		free(fl);
	}
	HASH_ITER(hh, d->gigawords_by_attr_id, gw, gwtmp) {
#ifndef __clang_analyzer__
		HASH_DELETE(hh, d->gigawords_by_attr_id, gw);
#endif
		free(gw);
	}

	free(d);
	rh->dict = NULL;
	/* rh->first_dict_read is intentionally left untouched -- see
	 * REQ-DICT-DATA-008; owned/released by radcli2_priv_config_free() instead. */
}

/*- Look up a dictionary attribute by its case-insensitive name.
 *
 * @param rh a handle to parsed configuration.
 * @param name the attribute name.
 * @return the attribute, or NULL if rh/name is NULL, rh has no dictionary,
 * or no such attribute is loaded.
 -*/
struct radcli_dict_attr *radcli_dict_attr_by_name(rc_handle const *rh, const char *name)
{
	/* dict2_lc() only fills up to its NUL terminator; zero the tail so
	 * the whole buffer is initialized before HASH_FIND() hashes it
	 * (bounded to strlen(key) either way, but not provably so to Clang
	 * Static Analyzer -- MemorySanitizer confirms it's a false concern). */
	char key[RC_DICT2_KEY_LEN] = {0};
	struct radcli_dict_attr *out;

	if (rh == NULL || rh->dict == NULL || name == NULL)
		return NULL;

	dict2_lc(key, sizeof(key), name);
	HASH_FIND(hh_name, rh->dict->attrs_by_name, key, strlen(key), out);
	return out;
}

/*- Look up a dictionary attribute by its RADCLI_VENDOR_ATTR_SET-combined
 * attribute/vendor ID.
 *
 * @param rh a handle to parsed configuration.
 * @param value the combined attribute/vendor ID.
 * @return the attribute, or NULL if rh is NULL, rh has no dictionary, or
 * no such attribute is loaded.
 -*/
struct radcli_dict_attr *radcli_dict_attr_by_id(rc_handle const *rh, uint64_t value)
{
	struct radcli_dict_attr *out;

	if (rh == NULL || rh->dict == NULL)
		return NULL;

	HASH_FIND(hh_id, rh->dict->attrs_by_id, &value, sizeof(value), out);
	return out;
}

/*- Look up a dictionary VALUE by its case-insensitive name, across every
 * attribute.
 *
 * @param rh a handle to parsed configuration.
 * @param name the VALUE's name.
 * @return the VALUE, or NULL if rh/name is NULL, rh has no dictionary, or
 * no such VALUE is loaded.
 -*/
struct radcli_dict_value *radcli_dict_value_by_name(rc_handle const *rh, const char *name)
{
	/* dict2_lc() only fills up to its NUL terminator; zero the tail so
	 * the whole buffer is initialized before HASH_FIND() hashes it
	 * (bounded to strlen(key) either way, but not provably so to Clang
	 * Static Analyzer -- MemorySanitizer confirms it's a false concern). */
	char key[RC_DICT2_KEY_LEN] = {0};
	struct radcli_dict_value *out;

	if (rh == NULL || rh->dict == NULL || name == NULL)
		return NULL;

	dict2_lc(key, sizeof(key), name);
	HASH_FIND(hh_name, rh->dict->values_by_name, key, strlen(key), out);
	return out;
}

/*- Look up a dictionary VALUE by its attribute name and numeric value.
 *
 * @param rh a handle to parsed configuration.
 * @param attrname the attribute the VALUE belongs to.
 * @param value the VALUE's numeric value.
 * @return the VALUE, or NULL if rh/attrname is NULL, rh has no dictionary,
 * or no such VALUE is loaded.
 -*/
struct radcli_dict_value *radcli_dict_value_by_attr(rc_handle const *rh, const char *attrname, uint32_t value)
{
	struct radcli_dict_value_key key;
	struct radcli_dict_value *out;

	if (rh == NULL || rh->dict == NULL || attrname == NULL)
		return NULL;

	memset(&key, 0, sizeof(key));
	dict2_lc(key.attrname_key, sizeof(key.attrname_key), attrname);
	key.value = value;

	HASH_FIND(hh_attr, rh->dict->values_by_attr, &key, sizeof(key), out);
	return out;
}

/*- Look up a dictionary VALUE by its attribute name and its own name.
 *
 * @param rh a handle to parsed configuration.
 * @param attrname the attribute the VALUE belongs to.
 * @param name the VALUE's name.
 * @return the VALUE, or NULL if rh/attrname/name is NULL, rh has no
 * dictionary, or no such VALUE is loaded.
 -*/
struct radcli_dict_value *radcli_dict_value_by_attr_name(rc_handle const *rh, const char *attrname, const char *name)
{
	struct radcli_dict_value_name_key key;
	struct radcli_dict_value *out;

	if (rh == NULL || rh->dict == NULL || attrname == NULL || name == NULL)
		return NULL;

	memset(&key, 0, sizeof(key));
	dict2_lc(key.attrname_key, sizeof(key.attrname_key), attrname);
	dict2_lc(key.name_key, sizeof(key.name_key), name);

	HASH_FIND(hh_attr_name, rh->dict->values_by_attr_name, &key, sizeof(key), out);
	return out;
}

/*- Look up a dictionary vendor by its case-insensitive name.
 *
 * @param rh a handle to parsed configuration.
 * @param name the vendor name.
 * @return the vendor, or NULL if rh/name is NULL, rh has no dictionary, or
 * no such vendor is loaded.
 -*/
struct radcli_dict_vendor *radcli_dict_vendor_by_name(rc_handle const *rh, const char *name)
{
	/* dict2_lc() only fills up to its NUL terminator; zero the tail so
	 * the whole buffer is initialized before HASH_FIND() hashes it
	 * (bounded to strlen(key) either way, but not provably so to Clang
	 * Static Analyzer -- MemorySanitizer confirms it's a false concern). */
	char key[RC_DICT2_KEY_LEN] = {0};
	struct radcli_dict_vendor *out;

	if (rh == NULL || rh->dict == NULL || name == NULL)
		return NULL;

	dict2_lc(key, sizeof(key), name);
	HASH_FIND(hh_name, rh->dict->vendors_by_name, key, strlen(key), out);
	return out;
}

/*- Look up a dictionary vendor by its IANA Private Enterprise Number.
 *
 * @param rh a handle to parsed configuration.
 * @param pec the vendor's PEN.
 * @return the vendor, or NULL if rh is NULL, rh has no dictionary, or no
 * such vendor is loaded.
 -*/
struct radcli_dict_vendor *radcli_dict_vendor_by_pec(rc_handle const *rh, uint32_t pec)
{
	struct radcli_dict_vendor *out;

	if (rh == NULL || rh->dict == NULL)
		return NULL;

	HASH_FIND(hh_pec, rh->dict->vendors_by_pec, &pec, sizeof(pec), out);
	return out;
}

/*- Look up an attribute's dictionary flags (e.g. encrypt=) by its combined
 * attribute/vendor ID.
 *
 * @param rh a handle to parsed configuration.
 * @param attr_id the combined attribute/vendor ID.
 * @return the flags entry, or NULL if rh is NULL, rh has no dictionary, or
 * the attribute has no flags entry.
 -*/
struct radcli_dict_flags *radcli_dict_flags_by_id(rc_handle const *rh, uint64_t attr_id)
{
	struct radcli_dict_flags *out;

	if (rh == NULL || rh->dict == NULL)
		return NULL;

	HASH_FIND(hh, rh->dict->flags_by_attr_id, &attr_id, sizeof(attr_id), out);
	return out;
}

/*- Look up an Input/Output-Octets-style attribute's paired Gigawords
 * attribute, by the octets attribute's combined attribute/vendor ID.
 *
 * @param rh a handle to parsed configuration.
 * @param attr_id the octets attribute's combined attribute/vendor ID.
 * @return the gigawords entry, or NULL if rh is NULL, rh has no
 * dictionary, or the attribute has no paired gigawords entry.
 -*/
struct radcli_dict_gigawords *radcli_dict_gigawords_by_id(rc_handle const *rh, uint64_t attr_id)
{
	struct radcli_dict_gigawords *out;

	if (rh == NULL || rh->dict == NULL)
		return NULL;

	HASH_FIND(hh, rh->dict->gigawords_by_attr_id, &attr_id, sizeof(attr_id), out);
	return out;
}

/*- Look up an Input/Output-Octets-style attribute's paired Gigawords
 * attribute definition.
 *
 * @param rh a handle to parsed configuration.
 * @param octets the octets attribute definition.
 * @return the gigawords attribute, or NULL if rh/octets is NULL or the
 * attribute has no paired gigawords entry.
 -*/
struct radcli_dict_attr *radcli_dict_attr_gigawords(rc_handle const *rh, const struct radcli_dict_attr *octets)
{
	struct radcli_dict_gigawords *gw;

	if (rh == NULL || octets == NULL)
		return NULL;

	gw = radcli_dict_gigawords_by_id(rh, octets->value);
	if (gw == NULL)
		return NULL;

	return radcli_dict_attr_by_id(rh, gw->gigawords_attrid);
}

/*- Return a's legacy DICT_ATTR shadow struct, lazily materializing and
 * caching it on first call.
 *
 * @param a the dictionary attribute to project.
 * @return the cached legacy struct, or NULL if a is NULL or allocation
 * failed.
 -*/
DICT_ATTR *radcli_dict_attr_to_legacy(struct radcli_dict_attr *a)
{
	if (a == NULL)
		return NULL;

	if (a->legacy == NULL) {
		a->legacy = malloc(sizeof(*a->legacy));
		if (a->legacy == NULL) {
			rc_log(LOG_CRIT, "radcli_dict_attr_to_legacy: out of memory");
			return NULL;
		}
		strlcpy(a->legacy->name, a->name, sizeof(a->legacy->name));
		a->legacy->value = a->value;
		a->legacy->type = radcli_dict_type_to_legacy(a->type);
		a->legacy->next = NULL;
	}
	return a->legacy;
}

/*- Return v's legacy DICT_VALUE shadow struct, lazily materializing and
 * caching it on first call.
 *
 * @param v the dictionary VALUE to project.
 * @return the cached legacy struct, or NULL if v is NULL or allocation
 * failed.
 -*/
DICT_VALUE *radcli_dict_value_to_legacy(struct radcli_dict_value *v)
{
	if (v == NULL)
		return NULL;

	if (v->legacy == NULL) {
		v->legacy = malloc(sizeof(*v->legacy));
		if (v->legacy == NULL) {
			rc_log(LOG_CRIT, "radcli_dict_value_to_legacy: out of memory");
			return NULL;
		}
		strlcpy(v->legacy->attrname, v->attrname, sizeof(v->legacy->attrname));
		strlcpy(v->legacy->name, v->name, sizeof(v->legacy->name));
		v->legacy->value = v->value;
		v->legacy->next = NULL;
	}
	return v->legacy;
}

/*- Return v's legacy DICT_VENDOR shadow struct, lazily materializing and
 * caching it on first call.
 *
 * @param v the dictionary vendor to project.
 * @return the cached legacy struct, or NULL if v is NULL or allocation
 * failed.
 -*/
DICT_VENDOR *radcli_dict_vendor_to_legacy(struct radcli_dict_vendor *v)
{
	if (v == NULL)
		return NULL;

	if (v->legacy == NULL) {
		v->legacy = malloc(sizeof(*v->legacy));
		if (v->legacy == NULL) {
			rc_log(LOG_CRIT, "radcli_dict_vendor_to_legacy: out of memory");
			return NULL;
		}
		strlcpy(v->legacy->vendorname, v->name, sizeof(v->legacy->vendorname));
		v->legacy->vendorpec = v->pec;
		v->legacy->next = NULL;
	}
	return v->legacy;
}

/**
 * @addtogroup radcli2-dict
 *
 * @{
 */

/* radcli_attr_def is never given its own storage: a dictionary attribute
 * definition is a struct radcli_dict_attr, and the "opaque handle" is that
 * same pointer under a name radcli2.h does not define. This keeps the new
 * lookup API from duplicating the dictionary
 * (contrib/ai/personas/radcli-core-dev.md, Design Review / Dependency
 * growth). Unlike lib/dict.c's rc_dict_findattr()/rc_dict_getattr(), these
 * go straight to the lookup functions above -- no legacy DICT_ATTR shadow
 * is ever materialized for a radcli2.h caller. lib/avp.c casts a
 * radcli_attr_def straight to struct radcli_dict_attr (not DICT_ATTR) to
 * match. */

/*- Map a dictionary's internal rc_attr_type wire type to the public
 * radcli_attr_type enum.
 *
 * @param t the internal wire type, including dict2-parse.c's
 * internal-only RFC 8044 sentinel types.
 * @return the corresponding radcli_attr_type.
 -*/
static radcli_attr_type dict_type_to_radcli(rc_attr_type t)
{
	/* switch on the underlying int, not the rc_attr_type enum directly:
	 * the "integer64"/"ipv4prefix" sentinels below are deliberately not
	 * legal rc_attr_type enumerators (see their case comments), and
	 * -Wswitch flags any case value outside the switched-on enum's own
	 * value set when switching on an enum-typed expression. */
	switch ((int)t) {
	case PW_TYPE_STRING:
		return RADCLI_TYPE_STRING;
	case PW_TYPE_INTEGER:
		return RADCLI_TYPE_INTEGER;
	case PW_TYPE_IPADDR:
		return RADCLI_TYPE_IPADDR;
	case PW_TYPE_DATE:
		return RADCLI_TYPE_DATE;
	case PW_TYPE_IPV6ADDR:
		return RADCLI_TYPE_IPV6ADDR;
	case PW_TYPE_IPV6PREFIX:
		return RADCLI_TYPE_IPV6PREFIX;
	case PW_TYPE_MAX:
		/* The internal-only "integer64" sentinel -- see the "integer64"
		 * keyword's comment above. rc_dict_addattr() (the public,
		 * programmatic attribute API) still rejects type >= PW_TYPE_MAX,
		 * so this value can only ever come from the bundled dictionary
		 * file. */
		return RADCLI_TYPE_INTEGER64;
	case PW_TYPE_MAX + 1:
		/* The internal-only "ipv4prefix" sentinel -- see lib/dict2-parse.c's
		 * "ipv4prefix" keyword comment. Same rc_dict_addattr() rejection as
		 * PW_TYPE_MAX above. */
		return RADCLI_TYPE_IPV4PREFIX;
	case PW_TYPE_MAX + 2:
		/* The internal-only "text" sentinel -- see lib/dict2-parse.c's
		 * "text" keyword comment. Same rc_dict_addattr() rejection as
		 * PW_TYPE_MAX above. */
		return RADCLI_TYPE_TEXT;
	case PW_TYPE_MAX + 3:
		/* The internal-only "ifid" sentinel -- see lib/dict2-parse.c's
		 * "ifid" keyword comment. Same rc_dict_addattr() rejection as
		 * PW_TYPE_MAX above. */
		return RADCLI_TYPE_IFID;
	default:
		/* unreachable: every legal DICT_ATTR.type value (0..PW_TYPE_MAX + 3
		 * inclusive) is handled above. */
		return RADCLI_TYPE_STRING;
	}
}

/* 5 = the deepest RFC 6929 form this parser accepts, even though the
 * bundled dictionary can only resolve the 1- and 3-component ones today:
 * vendor(26) . vendor-id . extended-type(241) . ext-attr . tlv-type. */
#define RADCLI_OID_MAX_COMPONENTS 5

/*- Parse a dot-separated OID ("1", "26.311.11") into uint32_t components.
 *
 * @param oid the OID text to parse.
 * @param comp set to the parsed components, up to
 * RADCLI_OID_MAX_COMPONENTS of them.
 * @return the component count, or -1 if oid is NULL/empty, a component is
 * not a plain unsigned integer, a component overflows uint32_t, or more
 * components than fit in comp are present.
 -*/
static int parse_oid(const char *oid, uint32_t comp[RADCLI_OID_MAX_COMPONENTS])
{
	const char *p = oid;
	int n = 0;

	if (oid == NULL || *oid == '\0')
		return -1;

	while (1) {
		char *end;
		unsigned long v;

		if (n >= RADCLI_OID_MAX_COMPONENTS)
			return -1;

		errno = 0;
		v = strtoul(p, &end, 10);
		if (end == p || (v == ULONG_MAX && errno == ERANGE))
			return -1;
#if ULONG_MAX > UINT32_MAX
		if (v > UINT32_MAX)
			return -1;
#endif

		comp[n++] = (uint32_t)v;

		if (*end == '\0')
			break;
		if (*end != '.')
			return -1;
		p = end + 1;
	}
	return n;
}

/** @brief Look up a dictionary attribute by its canonical name.
 *
 * Case-insensitive, matching the legacy dictionary's own lookup rules.
 *
 * @param ctx a context with a dictionary loaded.
 * @param name the attribute name, e.g. "Framed-IP-Address".
 * @return the attribute definition, or NULL if no such attribute is loaded.
 */
const radcli_attr_def *radcli_dict_lookup(const radcli_ctx *ctx, const char *name)
{
	if (ctx == NULL || name == NULL)
		return NULL;
	return (const radcli_attr_def *)radcli_dict_attr_by_name((rc_handle const *)ctx, name);
}

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
 *  Non-NULL for any RFC 2865/2866/2869 attribute ID on a context that has
 *  the built-in dictionary loaded -- every radcli_ctx_read_config() context,
 *  and every radcli_ctx_new() context unless created with
 *  #RADCLI_CTX_NO_BUILTIN_DICT.
 */
const radcli_attr_def *radcli_dict_lookup_num(const radcli_ctx *ctx, uint32_t attrid, uint32_t vendor)
{
	if (ctx == NULL)
		return NULL;
	return (const radcli_attr_def *)radcli_dict_attr_by_id((rc_handle const *)ctx,
								RADCLI_VENDOR_ATTR_SET(attrid, vendor));
}

/** @brief Look up a dictionary attribute by RFC 6929 §2.7 OID notation.
 *
 * Accepts a standard attribute as a single component ("1" for User-Name) or
 * a vendor-specific attribute as "26.<vendor-id>.<vendor-type>" (e.g.
 * "26.311.11"). Longer forms naming an RFC 6929 extended, long-extended, or
 * TLV-nested attribute parse without error but currently match nothing: the
 * bundled dictionary carries no RFC 6929 extended/long-extended/TLV-nested
 * attributes yet.
 *
 * @param ctx a context with a dictionary loaded.
 * @param oid the dot-separated OID text.
 * @return the attribute definition, or NULL if the OID is malformed or
 *  matches no loaded attribute.
 */
const radcli_attr_def *radcli_dict_lookup_oid(const radcli_ctx *ctx, const char *oid)
{
	uint32_t comp[RADCLI_OID_MAX_COMPONENTS];
	int n;

	if (ctx == NULL)
		return NULL;

	n = parse_oid(oid, comp);
	if (n <= 0)
		return NULL;

	if (n == 1)
		return radcli_dict_lookup_num(ctx, comp[0], 0);

	if (n == 3 && comp[0] == PW_VENDOR_SPECIFIC)
		return radcli_dict_lookup_num(ctx, comp[2], comp[1]);

	/* "26.<vendor>" alone names a vendor, not an attribute; longer forms
	 * name an RFC 6929 extended/TLV attribute the bundled dictionary does
	 * not yet carry. Both are well-formed OIDs that simply match nothing
	 * today. */
	return NULL;
}

/** @brief Return an attribute definition's canonical name.
 * @param def an attribute definition from radcli_dict_lookup() or a sibling.
 * @return the name; never NULL for a non-NULL def.
 */
const char *radcli_attr_def_name(const radcli_attr_def *def)
{
	const struct radcli_dict_attr *a = (const struct radcli_dict_attr *)def;
	return a ? a->name : NULL;
}

/** @brief Return an attribute definition's wire type.
 * @param def an attribute definition from radcli_dict_lookup() or a sibling.
 */
radcli_attr_type radcli_attr_def_type(const radcli_attr_def *def)
{
	const struct radcli_dict_attr *a = (const struct radcli_dict_attr *)def;
	return dict_type_to_radcli(a ? a->type : PW_TYPE_STRING);
}

/** @brief Render an attribute definition's RFC 6929 §2.7 OID notation.
 *
 * @param def an attribute definition from radcli_dict_lookup() or a sibling.
 * @param buf destination buffer; may be NULL if buflen is 0.
 * @param buflen size of buf in bytes.
 * @return the number of characters the OID text would occupy, excluding
 *  the terminating null, as with snprintf(); negative if def is NULL.
 */
int radcli_attr_def_oid(const radcli_attr_def *def, char *buf, size_t buflen)
{
	const struct radcli_dict_attr *a = (const struct radcli_dict_attr *)def;
	uint32_t vendor, attrid;

	if (a == NULL)
		return -1;

	vendor = VENDOR(a->value);
	attrid = ATTRID(a->value);

	if (vendor == 0)
		return snprintf(buf, buflen, "%u", attrid);
	return snprintf(buf, buflen, "26.%u.%u", vendor, attrid);
}

/** @brief Resolve a dictionary VALUE by name, scoped to one attribute.
 *
 * The runtime, VALUE-name counterpart to radcli_dict_lookup(): covers a
 * vendor-specific or supplemental-dictionary VALUE with no compiled-in
 * constant in radcli-defs.h (which only covers RFC 2865/2866/2869
 * standard VALUEs). A VALUE name is only meaningful together with the
 * attribute it was defined under -- two different attributes may each
 * define a VALUE named e.g. "Yes" -- so def fixes that scope, the same way
 * radcli_dict_value_by_attr()/rc_dict_getval() already scope a numeric
 * VALUE lookup by attribute rather than matching across the whole
 * dictionary.
 *
 * @param ctx a context with a dictionary loaded.
 * @param def the attribute the VALUE belongs to, from radcli_dict_lookup()
 *  or a sibling.
 * @param name the VALUE's name, as it appears in a VALUE dictionary line.
 * @param[out] out the VALUE's numeric value, set only on success.
 * @return 0 on success, -1 if ctx/def/name/out is NULL or no such VALUE is
 *  defined for def.
 */
int radcli_dict_lookup_value(const radcli_ctx *ctx, const radcli_attr_def *def,
			      const char *name, uint32_t *out)
{
	const struct radcli_dict_attr *a = (const struct radcli_dict_attr *)def;
	const struct radcli_dict_value *v;

	if (ctx == NULL || a == NULL || name == NULL || out == NULL)
		return -1;

	v = radcli_dict_value_by_attr_name((rc_handle const *)ctx, a->name, name);
	if (v == NULL)
		return -1;

	*out = v->value;
	return 0;
}

/** @} */
