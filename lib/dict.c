/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

/**
 * @defgroup radcli-api Main API
 * @brief Main API Functions
 *
 * @{
 */

/* This file is a compatibility shim over lib/dict2.c, the canonical,
 * hash-indexed dictionary implementation. It exists only because
 * DICT_ATTR/DICT_VALUE/DICT_VENDOR are frozen public ABI returned by
 * pointer: every rc_dict_*() lookup/construction function below resolves
 * through dict2.h and then hands back a lazily-materialized, cached shadow
 * struct (radcli_dict_*_to_legacy()) matching what a linear-scanned
 * next-chain used to return directly. rc_read_dictionary()/
 * rc_read_dictionary_from_buffer()/rc_dict_free() -- the only three
 * functions any external caller checked (including ocserv) actually uses --
 * are real code in lib/dict2.c, not shimmed here. New internal code should
 * call lib/dict2.h's functions directly instead of the shim below. See
 * doc/requirements/dict.md.
 */

#include <config.h>
#include <includes.h>
#include <limits.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "dict2.h"

DICT_ATTR *rc_dict_addattr(rc_handle *rh, char const * namestr, uint32_t value, int type, uint32_t vendorspec)
{
	return radcli_dict_attr_to_legacy(radcli_dict_attr_add(rh, namestr, value, type, vendorspec));
}

DICT_VALUE *rc_dict_addval(rc_handle *rh, char const * attrstr, char const * namestr, uint32_t value)
{
	return radcli_dict_value_to_legacy(radcli_dict_value_add(rh, attrstr, namestr, value));
}

DICT_VENDOR *rc_dict_addvend(rc_handle *rh, char const * namestr, uint32_t vendorspec)
{
	return radcli_dict_vendor_to_legacy(radcli_dict_vendor_add(rh, namestr, vendorspec));
}

DICT_ATTR *rc_dict_getattr(rc_handle const *rh, uint64_t attribute)
{
	return radcli_dict_attr_to_legacy(radcli_dict_attr_by_id(rh, attribute));
}

DICT_ATTR *rc_dict_findattr(rc_handle const *rh, char const *attrname)
{
	return radcli_dict_attr_to_legacy(radcli_dict_attr_by_name(rh, attrname));
}

DICT_VALUE *rc_dict_findval(rc_handle const *rh, char const *valname)
{
	return radcli_dict_value_to_legacy(radcli_dict_value_by_name(rh, valname));
}

DICT_VENDOR *rc_dict_findvend(rc_handle const *rh, char const *vendorname)
{
	return radcli_dict_vendor_to_legacy(radcli_dict_vendor_by_name(rh, vendorname));
}

DICT_VENDOR *rc_dict_getvend (rc_handle const *rh, uint32_t vendorspec)
{
	return radcli_dict_vendor_to_legacy(radcli_dict_vendor_by_pec(rh, vendorspec));
}

DICT_VALUE *rc_dict_getval(rc_handle const *rh, uint32_t value, char const *attrname)
{
	return radcli_dict_value_to_legacy(radcli_dict_value_by_attr(rh, attrname, value));
}

/** @} */

/**
 * @defgroup radcli2-api New API
 * @brief New, opaque-by-default API functions
 *
 * @{
 */

/* radcli_attr_def is never given its own storage: a dictionary attribute
 * definition is a DICT_ATTR, and the "opaque handle" is that same pointer
 * under a name radcli2.h does not define. This keeps the new lookup API
 * from duplicating the dictionary (contrib/ai/personas/radcli-core-dev.md,
 * Design Review / Dependency growth). Unlike rc_dict_findattr()/
 * rc_dict_getattr(), these go straight to dict2.h -- no legacy DICT_ATTR
 * shadow is ever materialized for a radcli2.h caller. lib/avp.c casts a
 * radcli_attr_def straight to struct radcli_dict_attr (not DICT_ATTR) to
 * match. */

/// @cond INTERNAL
static radcli_attr_type dict_type_to_radcli(rc_attr_type t)
{
	switch (t) {
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
		 * keyword's comment in lib/dict2.c. rc_dict_addattr() (the
		 * public, programmatic attribute API) still rejects
		 * type >= PW_TYPE_MAX, so this value can only ever come from
		 * the bundled dictionary file. */
		return RADCLI_TYPE_INTEGER64;
	default:
		/* unreachable: every legal DICT_ATTR.type value (0..PW_TYPE_MAX
		 * inclusive) is handled above. */
		return RADCLI_TYPE_STRING;
	}
}

/* 5 = the deepest RFC 6929 form this parser accepts, even though the
 * bundled dictionary can only resolve the 1- and 3-component ones today:
 * vendor(26) . vendor-id . extended-type(241) . ext-attr . tlv-type. */
#define RADCLI_OID_MAX_COMPONENTS 5

/* Parses a dot-separated OID ("1", "26.311.11") into up to
 * RADCLI_OID_MAX_COMPONENTS uint32_t components. Returns the component
 * count, or -1 if oid is NULL/empty, a component is not a plain unsigned
 * integer, a component overflows uint32_t, or more components than fit in
 * comp are present. */
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
/// @endcond

const radcli_attr_def *radcli_dict_lookup(const radcli_ctx *ctx, const char *name)
{
	if (ctx == NULL || name == NULL)
		return NULL;
	return (const radcli_attr_def *)radcli_dict_attr_by_name((rc_handle const *)ctx, name);
}

const radcli_attr_def *radcli_dict_lookup_num(const radcli_ctx *ctx, uint32_t attrid, uint32_t vendor)
{
	if (ctx == NULL)
		return NULL;
	return (const radcli_attr_def *)radcli_dict_attr_by_id((rc_handle const *)ctx,
								RADCLI_VENDOR_ATTR_SET(attrid, vendor));
}

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
	 * not yet carry (doc/plan-api-modernization.md Phase 1 scope note).
	 * Both are well-formed OIDs that simply match nothing today. */
	return NULL;
}

const char *radcli_attr_def_name(const radcli_attr_def *def)
{
	const struct radcli_dict_attr *a = (const struct radcli_dict_attr *)def;
	return a ? a->name : NULL;
}

radcli_attr_type radcli_attr_def_type(const radcli_attr_def *def)
{
	const struct radcli_dict_attr *a = (const struct radcli_dict_attr *)def;
	return dict_type_to_radcli(a ? a->type : PW_TYPE_STRING);
}

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

/** @} */
