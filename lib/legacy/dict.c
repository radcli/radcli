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
 * are real code in lib/dict2.c, not shimmed here. Every symbol below is
 * declared in include/radcli/radcli.h; radcli2.h's dictionary-lookup API
 * (radcli_dict_lookup() and friends) has no such ABI constraint and lives
 * in lib/dict2.c entirely, alongside its real implementation. New internal
 * code should call lib/dict2.h's functions directly instead of the shim
 * below. See doc/requirements/dict.md.
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include "dict2.h"

/** @brief Add attribute to dictionary
 *
 * A re-add identical to an already-loaded attribute of the same name
 * returns that existing attribute rather than adding a duplicate; a re-add
 * of the same name with a conflicting definition (different id/vendor/type)
 * fails, after a warning naming both definitions.
 *
 * @param rh              a handle to configuration.
 * @param namestr         attribute name
 * @param type            attribute type
 * @param value           attribute value
 * @param vendorspec      vendorspec
 * @return                added (or already-existing, identical) attr on
 *                        success, NULL on failure or conflict
 */
DICT_ATTR *rc_dict_addattr(rc_handle *rh, char const * namestr, uint32_t value, int type, uint32_t vendorspec)
{
	return radcli_dict_attr_to_legacy(radcli_dict_attr_add(rh, namestr, value, type, vendorspec));
}

/** @brief Add value to dictionary
 *
 * A re-add identical to an already-loaded value of the same attribute+number
 * returns that existing value rather than adding a duplicate; a re-add of
 * the same attribute+number with a conflicting name fails, after a warning
 * naming both definitions.
 *
 * @param rh              a handle to configuration.
 * @param attrstr         attribute name
 * @param namestr         name
 * @param value           attribute value
 * @return                added (or already-existing, identical) value on
 *                        success, NULL on failure or conflict
 */
DICT_VALUE *rc_dict_addval(rc_handle *rh, char const * attrstr, char const * namestr, uint32_t value)
{
	return radcli_dict_value_to_legacy(radcli_dict_value_add(rh, attrstr, namestr, value));
}

/** @brief Add vendor to dictionary
 *
 * A re-add identical to an already-loaded vendor of the same name returns
 * that existing vendor rather than adding a duplicate; a re-add of the same
 * name with a conflicting Vendor-Id fails, after a warning naming both
 * definitions.
 *
 * @param rh              a handle to configuration.
 * @param namestr         vendor name
 * @param vendorspec      vendorspec
 * @return                added (or already-existing, identical) vendor on
 *                        success, NULL on failure or conflict
 */
DICT_VENDOR *rc_dict_addvend(rc_handle *rh, char const * namestr, uint32_t vendorspec)
{
	return radcli_dict_vendor_to_legacy(radcli_dict_vendor_add(rh, namestr, vendorspec));
}

/** @brief Lookup a DICT_ATTR by attribute number
 *
 * @param rh a handle to parsed configuration.
 * @param attribute the attribute ID.
 * @return the full attribute structure based on the attribute id number.
 */
DICT_ATTR *rc_dict_getattr(rc_handle const *rh, uint64_t attribute)
{
	return radcli_dict_attr_to_legacy(radcli_dict_attr_by_id(rh, attribute));
}

/** @brief Lookup a DICT_ATTR by its name
 *
 * @param rh a handle to parsed configuration.
 * @param attrname the attribute name.
 *
 * @return the full attribute structure based on the attribute name.
 */
DICT_ATTR *rc_dict_findattr(rc_handle const *rh, char const *attrname)
{
	return radcli_dict_attr_to_legacy(radcli_dict_attr_by_name(rh, attrname));
}

/** @brief Lookup a DICT_VALUE by its name
 *
 * @param rh a handle to parsed configuration.
 * @param valname the value name.
 * @return the full value structure based on the value name.
 */
DICT_VALUE *rc_dict_findval(rc_handle const *rh, char const *valname)
{
	return radcli_dict_value_to_legacy(radcli_dict_value_by_name(rh, valname));
}

/** @brief Lookup a DICT_VENDOR by its name
 *
 * @param rh a handle to parsed configuration.
 * @param vendorname the vendor name.
 * @return the full vendor structure based on the vendor name.
 */
DICT_VENDOR *rc_dict_findvend(rc_handle const *rh, char const *vendorname)
{
	return radcli_dict_vendor_to_legacy(radcli_dict_vendor_by_name(rh, vendorname));
}

/** @brief Lookup a DICT_VENDOR by its IANA number
 *
 * @param rh a handle to parsed configuration.
 * @param vendorspec the vendor ID.
 * @return the full vendor structure based on the vendor id number.
 */
DICT_VENDOR *rc_dict_getvend (rc_handle const *rh, uint32_t vendorspec)
{
	return radcli_dict_vendor_to_legacy(radcli_dict_vendor_by_pec(rh, vendorspec));
}

/** @brief Get DICT_VALUE based on attribute name and integer value number
 *
 * @param rh a handle to parsed configuration.
 * @param value the attribute value.
 * @param attrname the attribute name.
 * @return the full value structure based on the actual value and the associated attribute name.
 */
DICT_VALUE *rc_dict_getval(rc_handle const *rh, uint32_t value, char const *attrname)
{
	return radcli_dict_value_to_legacy(radcli_dict_value_by_attr(rh, attrname, value));
}

/** @} */
