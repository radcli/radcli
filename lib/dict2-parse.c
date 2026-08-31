/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * Copyright (C) 2026 Nikos Mavrogiannopoulos
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 *
 */

/** @file dict2-parse.c
 * @brief Dictionary file/buffer parser and rh->dict-backed rc_dict_add*() helpers.
 *
 * Split out of lib/dict.c as its functionality remains active part of the API/ABI.
 */

#include <config.h>
#include <includes.h>
#include <limits.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "dict2.h"
#include "util.h"

/*- Report whether s is a non-empty string of decimal digits.
 *
 * @param s the string to check.
 * @return 1 if s is non-empty and every character is a digit, 0 otherwise.
 -*/
static int is_unsigned_decimal(char const *s)
{
	if (*s == '\0')
		return 0;
	for (; *s != '\0'; s++) {
		if (!isdigit((unsigned char) *s))
			return 0;
	}
	return 1;
}

/* dict2_check_*(): looks up an already-loaded entry with the same primary
 * key (attribute/vendor name, or attribute+numeric-value for a VALUE) as a
 * freshly-parsed, not-yet-inserted candidate. Returns 1 if the existing
 * entry's definition is identical to the candidate's (the caller must
 * discard the candidate instead of inserting it -- this is what makes
 * loading the same dictionary content twice cost no extra memory), -1 if it
 * conflicts (the caller must discard the candidate and fail the whole
 * parse/add call; a warning naming both definitions has already been
 * logged), or 0 if the key is new (the caller inserts the candidate
 * normally). *existing_out is set whenever an entry with the same key was
 * found (both the 1 and -1 cases), NULL otherwise.
 *
 * Shared between the file/buffer parser (dict2_parse()) and the
 * programmatic radcli_dict_*_add() family below, so the two can never
 * diverge (REQ-DICT-DATA-005). pfilename/line_no are for the warning
 * message only; line_no <= 0 means "no line to report" (the programmatic
 * add path).
 *
 * Deliberately keyed on name (attrs_by_name/vendors_by_name) or
 * attribute+value (values_by_attr), never on attrs_by_id/vendors_by_pec:
 * several distinct *names* may legitimately share one numeric id -- e.g.
 * the built-in "Password"/"User-Password" alias pair for attribute 2 (see
 * lib/dict2.h's radcli_dict_flags comment) -- so that is not treated as a
 * conflict, only a same-name (or same-attribute-same-value, for VALUE)
 * redefinition is. */
/*- Check a candidate attribute against any already-loaded entry of the
 * same name -- see the comment above for the shared dict2_check_*()
 * contract.
 *
 * @param rh a handle to parsed configuration.
 * @param cand the not-yet-inserted candidate attribute.
 * @param pfilename the dictionary file name, for the warning message; NULL
 * for the programmatic add path.
 * @param line_no the dictionary line number, for the warning message;
 * <= 0 means "no line to report" (the programmatic add path).
 * @param existing_out set to the existing entry with the same key, or
 * NULL if the key is new.
 * @return 1 if identical to the existing entry (discard cand), -1 if
 * conflicting (discard cand and fail), 0 if the key is new (insert cand).
 -*/
static int dict2_check_attr(rc_handle *rh, const struct radcli_dict_attr *cand,
			     char const *pfilename, int line_no,
			     struct radcli_dict_attr **existing_out)
{
	struct radcli_dict_attr *existing = radcli_dict_attr_by_name(rh, cand->name);

	*existing_out = existing;
	if (existing == NULL)
		return 0;

	if (existing->value == cand->value && existing->type == cand->type)
		return 1;

	if (line_no > 0)
		rc_log(LOG_WARNING,
		       "%s: line %d: attribute %s redefined with a conflicting "
		       "definition (id %u vendor %u type %d -> id %u vendor %u type %d)",
		       pfilename, line_no, cand->name,
		       (unsigned)ATTRID(existing->value), (unsigned)VENDOR(existing->value), existing->type,
		       (unsigned)ATTRID(cand->value), (unsigned)VENDOR(cand->value), cand->type);
	else
		rc_log(LOG_WARNING,
		       "attribute %s redefined with a conflicting definition "
		       "(id %u vendor %u type %d -> id %u vendor %u type %d)",
		       cand->name,
		       (unsigned)ATTRID(existing->value), (unsigned)VENDOR(existing->value), existing->type,
		       (unsigned)ATTRID(cand->value), (unsigned)VENDOR(cand->value), cand->type);
	return -1;
}

/*- Check a candidate VALUE against any already-loaded entry for the same
 * attribute+numeric-value -- see dict2_check_attr()'s comment for the
 * shared dict2_check_*() contract.
 *
 * @param rh a handle to parsed configuration.
 * @param cand the not-yet-inserted candidate VALUE.
 * @param pfilename the dictionary file name, for the warning message; NULL
 * for the programmatic add path.
 * @param line_no the dictionary line number, for the warning message;
 * <= 0 means "no line to report" (the programmatic add path).
 * @param existing_out set to the existing entry with the same key, or
 * NULL if the key is new.
 * @return 1 if identical to the existing entry (discard cand), -1 if
 * conflicting (discard cand and fail), 0 if the key is new (insert cand).
 -*/
static int dict2_check_value(rc_handle *rh, const struct radcli_dict_value *cand,
			      char const *pfilename, int line_no,
			      struct radcli_dict_value **existing_out)
{
	struct radcli_dict_value *existing =
		radcli_dict_value_by_attr(rh, cand->attrname, cand->value);

	*existing_out = existing;
	if (existing == NULL)
		return 0;

	if (strcasecmp(existing->name, cand->name) == 0)
		return 1;

	if (line_no > 0)
		rc_log(LOG_WARNING,
		       "%s: line %d: VALUE %u for attribute %s redefined with a "
		       "conflicting name (%s -> %s)",
		       pfilename, line_no, cand->value, cand->attrname,
		       existing->name, cand->name);
	else
		rc_log(LOG_WARNING,
		       "VALUE for attribute %s redefined with a conflicting name "
		       "(%s -> %s)", cand->attrname, existing->name, cand->name);
	return -1;
}

/*- Check a candidate vendor against any already-loaded entry of the same
 * name -- see dict2_check_attr()'s comment for the shared
 * dict2_check_*() contract.
 *
 * @param rh a handle to parsed configuration.
 * @param cand the not-yet-inserted candidate vendor.
 * @param pfilename the dictionary file name, for the warning message; NULL
 * for the programmatic add path.
 * @param line_no the dictionary line number, for the warning message;
 * <= 0 means "no line to report" (the programmatic add path).
 * @param existing_out set to the existing entry with the same key, or
 * NULL if the key is new.
 * @return 1 if identical to the existing entry (discard cand), -1 if
 * conflicting (discard cand and fail), 0 if the key is new (insert cand).
 -*/
static int dict2_check_vendor(rc_handle *rh, const struct radcli_dict_vendor *cand,
			       char const *pfilename, int line_no,
			       struct radcli_dict_vendor **existing_out)
{
	struct radcli_dict_vendor *existing = radcli_dict_vendor_by_name(rh, cand->name);

	*existing_out = existing;
	if (existing == NULL)
		return 0;

	if (existing->pec == cand->pec)
		return 1;

	if (line_no > 0)
		rc_log(LOG_WARNING,
		       "%s: line %d: VENDOR %s redefined with a conflicting Vendor-Id "
		       "(%u -> %u)", pfilename, line_no, cand->name, existing->pec, cand->pec);
	else
		rc_log(LOG_WARNING,
		       "VENDOR %s redefined with a conflicting Vendor-Id (%u -> %u)",
		       cand->name, existing->pec, cand->pec);
	return -1;
}

/* Parses the ATTRIBUTE/VALUE/VENDOR/$INCLUDE/BEGIN-VENDOR/END-VENDOR
 * dictionary grammar into rh->dict. An entry identical to an already-loaded
 * one is silently deduplicated (no extra memory); an entry that reuses the
 * same name (or, for VALUE, the same attribute+numeric-value) with a
 * conflicting definition fails the load, after a warning naming both
 * definitions (REQ-DICT-DATA-005; see dict2_check_attr()'s comment above for
 * exactly what counts as a conflict). */
/*- Parse a dictionary file/buffer into rh->dict.
 *
 * @param rh a handle to parsed configuration.
 * @param dictfd the open dictionary stream to parse.
 * @param filename the dictionary's file name, for $INCLUDE resolution and
 * warning messages; NULL for a buffer-sourced load, which per
 * REQ-DICT-INIT-002 disables $INCLUDE.
 * @return 0 on success, -1 on a parse error or conflicting redefinition.
 -*/
static int dict2_parse(rc_handle *rh, FILE *dictfd, char const *filename)
{
	char            namestr[AUTH_ID_LEN];
	char            valstr[AUTH_ID_LEN];
	char            attrstr[AUTH_ID_LEN];
	char            typestr[AUTH_ID_LEN];
	char            optstr[AUTH_ID_LEN];
	char            ifilename[RC_MAX(1024, PATH_MAX)] = {0};
	char            *cp;
	char            *saveptr;
	char            *tok;
	int             line_no = 0;
	struct radcli_dict_attr   *attr;
	struct radcli_dict_value  *dval;
	struct radcli_dict_vendor *dvend;
	char            *buffer = NULL;
	size_t          bufsize = 0;
	uint32_t        value;
	int             type;
	int             encrypt_type;
	int             has_tag_flag;
	uint32_t        gigawords_attrid;
	unsigned attr_vendorspec = 0;
	const char *pfilename = filename;

	if (pfilename == NULL)
	{
		pfilename = "memory";
	}

	while (getline (&buffer, &bufsize, dictfd) != -1)
	{
		line_no++;

		/* Skip empty space */
		if (*buffer == '#' || *buffer == '\0' || *buffer == '\n' || \
		    *buffer == '\r')
		{
			continue;
		}

		/* Strip out comments */
		cp = strchr(buffer, '#');
		if (cp != NULL)
		{
			*cp = '\0';
		}

		tok = strtok_r(buffer, " \t\r\n", &saveptr);
		if (tok == NULL)
		{
			continue;
		}

		if (strcmp (tok, "ATTRIBUTE") == 0)
		{
			char *name_t, *val_t, *type_t, *opt_t;

			/* Read the ATTRIBUTE line */
			name_t = strtok_r(NULL, " \t\r\n", &saveptr);
			val_t = strtok_r(NULL, " \t\r\n", &saveptr);
			type_t = strtok_r(NULL, " \t\r\n", &saveptr);
			opt_t = strtok_r(NULL, " \t\r\n", &saveptr);
			if (name_t == NULL || val_t == NULL || type_t == NULL)
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid attribute on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}
			/*
			 * Validate all entries. Length checks must run against the
			 * original tokens, before strlcpy() truncates them into the
			 * fixed-size buffers below -- otherwise an over-long name can
			 * never trip the check, since the truncated copy is always
			 * within bounds.
			 */
			if (strlen (name_t) > RC_NAME_LENGTH)
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid name length on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}

			strlcpy(namestr, name_t, sizeof(namestr));
			strlcpy(valstr, val_t, sizeof(valstr));
			strlcpy(typestr, type_t, sizeof(typestr));
			if (opt_t != NULL)
			{
				strlcpy(optstr, opt_t, sizeof(optstr));
			}
			else
			{
				optstr[0] = '\0';
			}

			if (!is_unsigned_decimal (valstr))
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid value on line %d of dictionary %s",
					line_no, pfilename);
				goto error;
			}
			value = atoi (valstr);

			if (strcmp (typestr, "string") == 0)
			{
				type = PW_TYPE_STRING;
			}
			else if (strcmp (typestr, "integer") == 0)
			{
				type = PW_TYPE_INTEGER;
			}
			else if (strcmp (typestr, "uint32") == 0)
			{
				/* FreeRADIUS's newer dictionaries (e.g. dictionary.rfc2868)
				 * spell PW_TYPE_INTEGER "uint32"; same synonym relationship
				 * as ipaddr/ipv4addr above. */
				type = PW_TYPE_INTEGER;
			}
			else if (strcmp (typestr, "enum") == 0)
			{
				/* IANA's RADIUS Attribute Types registry uses "enum" as the
				 * Data Type for attributes whose 4-octet integer value is
				 * drawn from a fixed set of named constants (e.g.
				 * Service-Type, NAS-Port-Type) -- it is not one of RFC 8044's
				 * wire data types, just IANA's name for this semantic
				 * category of PW_TYPE_INTEGER. Same synonym relationship as
				 * "uint32" above: resolves to the same RADCLI_TYPE_INTEGER,
				 * with no dedicated radcli_attr_type value of its own. */
				type = PW_TYPE_INTEGER;
			}
			else if (strcmp (typestr, "ipaddr") == 0)
			{
				type = PW_TYPE_IPADDR;
			}
			else if (strcmp (typestr, "ipv4addr") == 0)
			{
				type = PW_TYPE_IPADDR;
			}
			else if (strcmp (typestr, "ipv6addr") == 0)
			{
				type = PW_TYPE_IPV6ADDR;
			}
			else if (strcmp (typestr, "ipv6prefix") == 0)
			{
				type = PW_TYPE_IPV6PREFIX;
			}
			else if (strcmp (typestr, "date") == 0)
			{
				type = PW_TYPE_DATE;
			}
			else if (strcmp (typestr, "time") == 0)
			{
				/* RFC 8044 SS3.5 names this "time"; it is the same 32-bit
				 * seconds-since-epoch representation as the legacy "date"
				 * keyword/PW_TYPE_DATE/RADCLI_TYPE_DATE, just newer
				 * terminology -- same synonym relationship as ipaddr/
				 * ipv4addr above. */
				type = PW_TYPE_DATE;
			}
			else if (strcmp (typestr, "integer64") == 0)
			{
				/* RFC 8044 SS3.3 "integer64" data type (8 octets, network
				 * byte order) -- see radcli2.h's RADCLI_TYPE_INTEGER64.
				 * Internal-only sentinel: PW_TYPE_MAX (6) is not a legal
				 * rc_attr_type value -- rc_dict_addattr() (the public,
				 * programmatic attribute API) rejects any type >= PW_TYPE_MAX,
				 * so no VALUE_PAIR-based caller can ever construct a
				 * DICT_ATTR with this type, only the bundled dictionary file
				 * parsed here can. radcli2.h's RADCLI_TYPE_INTEGER64 is the
				 * only way to see one; see dict_type_to_radcli() in dict.c. */
				type = PW_TYPE_MAX;
			}
			else if (strcmp (typestr, "ipv4prefix") == 0)
			{
				/* RFC 8044 SS3.9 "ipv4prefix" data type: reserved(1) +
				 * prefix-len(1) + address(4) -- see radcli2.h's
				 * RADCLI_TYPE_IPV4PREFIX. Internal-only sentinel, same
				 * technique as "integer64" above but a distinct value
				 * (PW_TYPE_MAX itself is already claimed by "integer64"):
				 * still >= PW_TYPE_MAX, so rc_dict_addattr() still rejects
				 * it for legacy/programmatic callers; only the bundled
				 * dictionary file parsed here can produce it. */
				type = PW_TYPE_MAX + 1;
			}
			else if (strcmp (typestr, "text") == 0)
			{
				/* RFC 8044 SS3.1 "text" data type: UTF-8 human-readable text,
				 * distinct from "string"'s opaque octets -- see radcli2.h's
				 * RADCLI_TYPE_TEXT. Internal-only sentinel, same technique as
				 * "integer64"/"ipv4prefix" above but a distinct value again;
				 * still >= PW_TYPE_MAX, so rc_dict_addattr() still rejects it
				 * for legacy/programmatic callers; only the bundled
				 * dictionary file parsed here can produce it. */
				type = PW_TYPE_MAX + 2;
			}
			else if (strcmp (typestr, "ifid") == 0)
			{
				/* RFC 8044 SS3.7 "ifid" data type: an 8-octet IPv6 interface
				 * identifier in network byte order -- see radcli2.h's
				 * RADCLI_TYPE_IFID. Internal-only sentinel, same technique as
				 * "integer64"/"ipv4prefix"/"text" above but a distinct value
				 * again; still >= PW_TYPE_MAX, so rc_dict_addattr() still
				 * rejects it for legacy/programmatic callers; only the
				 * bundled dictionary file parsed here can produce it. */
				type = PW_TYPE_MAX + 3;
			}
			else
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid type on line %d of dictionary %s",
					line_no, pfilename);
				goto error;
			}

			dvend = NULL;
			encrypt_type = 0;
			has_tag_flag = 0;
			gigawords_attrid = 0;
			if (optstr[0] != '\0') {
				char *cp1;
				for (cp1 = optstr; cp1 != NULL; cp1 = cp) {
					cp = strchr(cp1, ',');
					if (cp != NULL) {
						*cp = '\0';
						cp++;
					}

					if (strcmp(cp1, "has_tag") == 0) {
						/* RFC 2868 SS3.1 tunnel-attribute tagging. */
						has_tag_flag = 1;
						continue;
					}

					if (strncmp(cp1, "encrypt=", 8) == 0) {
						/* FreeRADIUS's dictionaries name an encryption scheme
						 * by the attribute that first defines it, e.g.
						 * "encrypt=Tunnel-Password" for the RFC 2868 SS3.5 /
						 * RFC 2548 SS2.4.2-2.4.3 salt-encryption scheme, and
						 * "encrypt=User-Password" for the RFC 2865 SS5.2
						 * scheme (see share/dictionary/radius/dictionary.rfc2865
						 * and dictionary.rfc2868 upstream) -- matched here so a
						 * real FreeRADIUS dictionary loads unmodified. No
						 * other scheme name has a matching implementation
						 * yet (see radcli_avp_decode()/radcli_avp_encode()
						 * in lib/avp.c). */
						if (strcmp(cp1 + 8, "User-Password") == 0) {
							encrypt_type = 1;
							continue;
						}
						if (strcmp(cp1 + 8, "Tunnel-Password") == 0) {
							encrypt_type = 2;
							continue;
						}
						rc_log(LOG_ERR,
							"rc_dict_init: unsupported encrypt=%s on line %d "
							"of dictionary %s (only encrypt=User-Password and "
							"encrypt=Tunnel-Password are implemented)",
							cp1 + 8, line_no, pfilename);
						goto error;
					}

					if (strncmp(cp1, "gigawords=", 10) == 0) {
						char *endp;
						long v = strtol(cp1 + 10, &endp, 10);

						/* RFC 2866 SS5.3/5.4 Octets + RFC 2869 SS5.1/5.2
						 * Gigawords pairing. The attribute id (within
						 * this line's own vendor scope, if any) of this
						 * attribute's Gigawords counterpart -- e.g.
						 * "gigawords=52" on the Acct-Input-Octets (42)
						 * line, naming Acct-Input-Gigawords (52). Not
						 * resolved to a struct radcli_dict_attr* here: the
						 * named counterpart's own ATTRIBUTE line may not
						 * have been parsed yet (e.g. it precedes this one
						 * in etc/dictionary) -- resolution happens lazily,
						 * by radcli_dict_attr_gigawords(), once the whole
						 * dictionary is loaded. */
						if (*endp != '\0' || v <= 0 || v > 0xff) {
							rc_log(LOG_ERR,
								"rc_dict_init: invalid gigawords=%s on line %d "
								"of dictionary %s", cp1 + 10, line_no, pfilename);
							goto error;
						}
						gigawords_attrid = (uint32_t)v;
						continue;
					}

					if (strncmp(cp1, "vendor=", 7) == 0)
						cp1 += 7;
					dvend = radcli_dict_vendor_by_name(rh, cp1);
					if (dvend == NULL) {
						rc_log(LOG_ERR,
							"rc_dict_init: unknown Vendor-Id %s on line %d of "
							"dictionary %s", cp1, line_no, pfilename);
						goto error;
					}
				}
			}

			/* Create a new attribute */
			if ((attr = calloc (1, sizeof (*attr))) == NULL)
			{
				rc_log(LOG_CRIT, "rc_dict_init: out of memory");
				goto error;
			}
			strlcpy (attr->name, namestr, sizeof(attr->name));
			dict2_lc(attr->name_key, sizeof(attr->name_key), attr->name);
			attr->type = type;

			if (dvend != NULL) {
				attr->value = RADCLI_VENDOR_ATTR_SET(value, dvend->pec);
			} else {
				attr->value = RADCLI_VENDOR_ATTR_SET(value, attr_vendorspec);
			}

			{
				struct radcli_dict_attr *existing;
				int cmp = dict2_check_attr(rh, attr, pfilename, line_no, &existing);

				if (cmp < 0) {
					free(attr);
					goto error;
				} else if (cmp > 0) {
					/* Identical redefinition: keep the already-loaded
					 * entry, whose ->value the side tables below need,
					 * and drop the freshly-parsed duplicate. */
					free(attr);
					attr = existing;
				} else {
					HASH_ADD(hh_name, rh->dict->attrs_by_name, name_key, strlen(attr->name_key), attr);
					HASH_ADD(hh_id, rh->dict->attrs_by_id, value, sizeof(attr->value), attr);
				}
			}

			if (encrypt_type != 0 || has_tag_flag != 0) {
				struct radcli_dict_flags *fl = calloc(1, sizeof(*fl));

				if (fl == NULL) {
					rc_log(LOG_CRIT, "rc_dict_init: out of memory");
					goto error;
				}
				fl->attr_id = attr->value;
				fl->encrypt_type = encrypt_type;
				fl->has_tag = has_tag_flag;
				HASH_ADD(hh, rh->dict->flags_by_attr_id, attr_id, sizeof(fl->attr_id), fl);
			}

			if (gigawords_attrid != 0) {
				struct radcli_dict_gigawords *gw = calloc(1, sizeof(*gw));

				if (gw == NULL) {
					rc_log(LOG_CRIT, "rc_dict_init: out of memory");
					goto error;
				}
				gw->attr_id = attr->value;
				/* Same vendor scope as this ATTRIBUTE line itself -- a
				 * VSA's gigawords= counterpart is another sub-attribute of
				 * the same vendor, not a standard attribute. */
				gw->gigawords_attrid = RADCLI_VENDOR_ATTR_SET(gigawords_attrid,
									      VENDOR(attr->value));
				HASH_ADD(hh, rh->dict->gigawords_by_attr_id, attr_id, sizeof(gw->attr_id), gw);
			}
		}
		else if (strcmp (tok, "VALUE") == 0)
		{
			char *attr_t, *name_t, *val_t;

			/* Read the VALUE line */
			attr_t = strtok_r(NULL, " \t\r\n", &saveptr);
			name_t = strtok_r(NULL, " \t\r\n", &saveptr);
			val_t = strtok_r(NULL, " \t\r\n", &saveptr);
			if (attr_t == NULL || name_t == NULL || val_t == NULL)
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid value entry on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}
			/*
			 * Validate all entries. Length checks must run against the
			 * original tokens, before strlcpy() truncates them below.
			 */
			if (strlen (attr_t) > RC_NAME_LENGTH)
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid attribute length on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}

			if (strlen (name_t) > RC_NAME_LENGTH)
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid name length on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}

			strlcpy(attrstr, attr_t, sizeof(attrstr));
			strlcpy(namestr, name_t, sizeof(namestr));
			strlcpy(valstr, val_t, sizeof(valstr));

			if (!is_unsigned_decimal (valstr))
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid value on line %d of dictionary %s",
					line_no, pfilename);
				goto error;
			}
			value = atoi (valstr);

			/* Create a new VALUE entry */
			if ((dval = calloc (1, sizeof (*dval))) == NULL)
			{
				rc_log(LOG_CRIT, "rc_dict_init: out of memory");
				goto error;
			}
			strlcpy (dval->attrname, attrstr, sizeof(dval->attrname));
			strlcpy (dval->name, namestr, sizeof(dval->name));
			dict2_lc(dval->name_key, sizeof(dval->name_key), dval->name);
			dict2_lc(dval->attr_key.attrname_key, sizeof(dval->attr_key.attrname_key), dval->attrname);
			dict2_lc(dval->attr_name_key.attrname_key, sizeof(dval->attr_name_key.attrname_key), dval->attrname);
			dict2_lc(dval->attr_name_key.name_key, sizeof(dval->attr_name_key.name_key), dval->name);
			dval->value = value;
			dval->attr_key.value = value;

			{
				struct radcli_dict_value *existing;
				int cmp = dict2_check_value(rh, dval, pfilename, line_no, &existing);

				if (cmp < 0) {
					free(dval);
					goto error;
				} else if (cmp > 0) {
					free(dval);
				} else {
					HASH_ADD(hh_name, rh->dict->values_by_name, name_key, strlen(dval->name_key), dval);
					HASH_ADD(hh_attr, rh->dict->values_by_attr, attr_key, sizeof(dval->attr_key), dval);
					HASH_ADD(hh_attr_name, rh->dict->values_by_attr_name, attr_name_key, sizeof(dval->attr_name_key), dval);
				}
			}
		}
		else if ((filename != NULL) &&
				(strcmp (tok, "$INCLUDE") == 0))
		{
			char *path_t;

			/* Read the $INCLUDE line. The path token is used directly
			 * (strtok_r null-terminates it in place in buffer, which is
			 * large enough for the longest path this parser can see),
			 * copied into ifilename (RC_MAX(1024, PATH_MAX)-sized) since
			 * $INCLUDE paths can legitimately be longer than 63 chars. */
			path_t = strtok_r(NULL, " \t\r\n", &saveptr);
			if (path_t == NULL)
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid include entry on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}
			strlcpy(ifilename, path_t, sizeof(ifilename));
			/* Append directory if necessary */
			if (path_t[0] != '/') {
				cp = strrchr(filename, '/');
				if (cp != NULL) {
					*cp = '\0';
					strlcpy(ifilename, filename, sizeof(ifilename));
					strlcat(ifilename, "/", sizeof(ifilename));
					strlcat(ifilename, path_t, sizeof(ifilename));
					*cp = '/';
				}
			}
			if (radcli2_priv_read_dictionary(rh, ifilename) < 0)
			{
				goto error;
			}
		}
		else if (strcmp (tok, "END-VENDOR") == 0)
		{
			attr_vendorspec = 0;
		}
		else if (strcmp (tok, "BEGIN-VENDOR") == 0)
		{
			struct radcli_dict_vendor *v;
			char *name_t;

			/* Read the vendor name */
			name_t = strtok_r(NULL, " \t\r\n", &saveptr);
			if (name_t == NULL)
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid Vendor-Id on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}

			v = radcli_dict_vendor_by_name(rh, name_t);
			if (v == NULL) {
				rc_log(LOG_ERR,
					"rc_dict_init: unknown Vendor %s on line %d of "
					"dictionary %s", name_t, line_no, pfilename);
				goto error;
			}

			attr_vendorspec = v->pec;
		}
		else if (strcmp (tok, "VENDOR") == 0)
		{
			char *name_t, *val_t;

			/* Read the VENDOR line */
			name_t = strtok_r(NULL, " \t\r\n", &saveptr);
			val_t = strtok_r(NULL, " \t\r\n", &saveptr);
			if (name_t == NULL || val_t == NULL)
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid Vendor-Id on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}
			/* Validate all entries against the original tokens, before
			 * strlcpy() truncates them below. */
			if (strlen (name_t) > RC_NAME_LENGTH)
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid attribute length on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}

			strlcpy(attrstr, name_t, sizeof(attrstr));
			strlcpy(valstr, val_t, sizeof(valstr));

			if (!is_unsigned_decimal (valstr))
			{
				rc_log(LOG_ERR,
					"rc_dict_init: invalid Vendor-Id on line %d of "
					"dictionary %s", line_no, pfilename);
				goto error;
			}
			value = atoi (valstr);

			/* Create a new VENDOR entry */
			dvend = calloc(1, sizeof(*dvend));
			if (dvend == NULL)
			{
				rc_log(LOG_CRIT, "rc_dict_init: out of memory");
				goto error;
			}
			strlcpy (dvend->name, attrstr, sizeof(dvend->name));
			dict2_lc(dvend->name_key, sizeof(dvend->name_key), dvend->name);
			dvend->pec = value;

			{
				struct radcli_dict_vendor *existing;
				int cmp = dict2_check_vendor(rh, dvend, pfilename, line_no, &existing);

				if (cmp < 0) {
					free(dvend);
					goto error;
				} else if (cmp > 0) {
					free(dvend);
				} else {
					HASH_ADD(hh_name, rh->dict->vendors_by_name, name_key, strlen(dvend->name_key), dvend);
					HASH_ADD(hh_pec, rh->dict->vendors_by_pec, pec, sizeof(dvend->pec), dvend);
				}
			}
		}
	}
	free(buffer);
	return 0;

error:
	free(buffer);
	return -1;
}

/*- Initialize the dictionary from a file.
 *
 * @param rh a handle to parsed configuration.
 * @param filename the name of the dictionary file.
 * @return 0 on success, -1 on failure.
 -*/
int radcli2_priv_read_dictionary (rc_handle *rh, char const *filename)
{
	FILE    *dictfd;
	int     ret_val = 0;

	if (rh->first_dict_read != NULL && strcmp(filename, rh->first_dict_read) == 0)
		return 0;

	if (dict2_ensure(rh) < 0)
		return -1;

	if ((dictfd = fopen (filename, "r")) == NULL)
	{
		rc_log(LOG_ERR, "radcli2_priv_read_dictionary couldn't open dictionary %s: %s",
				filename, strerror(errno));
		return -1;
	}

	ret_val = dict2_parse(rh, dictfd, filename);

	fclose (dictfd);

	if (rh->first_dict_read == NULL)
		rh->first_dict_read = strdup(filename);

	return ret_val;
}

/*- Initialize the dictionary from an in-memory buffer.
 *
 * @param rh a handle to parsed configuration.
 * @param buf buffer holding dictionary text.
 * @param size buf's length in bytes.
 * @return 0 on success, -1 on failure.
 -*/
int radcli2_priv_read_dictionary_from_buffer (rc_handle *rh, char const *buf, size_t size)
{
	FILE      *dictfd;
	int       ret_val = 0;

	if (dict2_ensure(rh) < 0)
		return -1;

	if ((dictfd = fmemopen ((void *)buf, size, "r")) == NULL)
	{
		rc_log(LOG_ERR, "radcli2_priv_read_dictionary_from_buffer failed to read "
				"input buffer %s", strerror(errno));
		return -1;
	}

	ret_val = dict2_parse(rh, dictfd, NULL);

	fclose (dictfd);

	return ret_val;
}

/*- Add an attribute to rh's dictionary programmatically. A re-add
 * identical to an already-loaded attribute of the same name returns that
 * existing attribute rather than adding a duplicate; a re-add of the same
 * name with a conflicting definition fails, after a warning naming both
 * definitions.
 *
 * @param rh a handle to parsed configuration.
 * @param name the attribute name.
 * @param value the attribute's numeric ID.
 * @param type the attribute's wire type (a PW_TYPE_* value).
 * @param vendorspec the vendor PEN, or 0 for a standard attribute.
 * @return the added (or already-existing, identical) attribute, or NULL
 * on failure or conflict.
 -*/
struct radcli_dict_attr *radcli_dict_attr_add(rc_handle *rh, const char *name,
					       uint32_t value, int type, uint32_t vendorspec)
{
	struct radcli_dict_attr *attr;

	if (strlen(name) > RC_NAME_LENGTH)
	{
		rc_log(LOG_ERR, "rc_dict_addattr: invalid attribute length");
		return NULL;
	}

	if (type < 0 || type >= PW_TYPE_MAX)
	{
		rc_log(LOG_ERR, "rc_dict_addattr: invalid attribute type");
		return NULL;
	}

	if (dict2_ensure(rh) < 0)
		return NULL;

	if ((attr = calloc(1, sizeof(*attr))) == NULL)
	{
		rc_log(LOG_CRIT, "rc_dict_addattr: out of memory");
		return NULL;
	}

	strlcpy(attr->name, name, sizeof(attr->name));
	dict2_lc(attr->name_key, sizeof(attr->name_key), attr->name);
	attr->value = RADCLI_VENDOR_ATTR_SET(value, vendorspec);
	attr->type = type;

	{
		struct radcli_dict_attr *existing;
		int cmp = dict2_check_attr(rh, attr, NULL, 0, &existing);

		if (cmp < 0) {
			free(attr);
			return NULL;
		} else if (cmp > 0) {
			free(attr);
			return existing;
		}
	}

	HASH_ADD(hh_name, rh->dict->attrs_by_name, name_key, strlen(attr->name_key), attr);
	HASH_ADD(hh_id, rh->dict->attrs_by_id, value, sizeof(attr->value), attr);
	return attr;
}

/*- Add a VALUE to rh's dictionary programmatically. A re-add identical to
 * an already-loaded value of the same attribute+number returns that
 * existing value rather than adding a duplicate; a re-add of the same
 * attribute+number with a conflicting name fails, after a warning naming
 * both definitions.
 *
 * @param rh a handle to parsed configuration.
 * @param attrname the attribute name the VALUE belongs to.
 * @param name the VALUE's name.
 * @param value the VALUE's numeric value.
 * @return the added (or already-existing, identical) VALUE, or NULL on
 * failure or conflict.
 -*/
struct radcli_dict_value *radcli_dict_value_add(rc_handle *rh, const char *attrname,
						 const char *name, uint32_t value)
{
	struct radcli_dict_value *dval;

	if (strlen(attrname) > RC_NAME_LENGTH)
	{
		rc_log(LOG_ERR, "rc_dict_addval: invalid attribute length");
		return NULL;
	}

	if (strlen(name) > RC_NAME_LENGTH)
	{
		rc_log(LOG_ERR, "rc_dict_addval: invalid name length");
		return NULL;
	}

	if (dict2_ensure(rh) < 0)
		return NULL;

	if ((dval = calloc(1, sizeof(*dval))) == NULL)
	{
		rc_log(LOG_CRIT, "rc_dict_addval: out of memory");
		return NULL;
	}
	strlcpy(dval->attrname, attrname, sizeof(dval->attrname));
	strlcpy(dval->name, name, sizeof(dval->name));
	dict2_lc(dval->name_key, sizeof(dval->name_key), dval->name);
	dict2_lc(dval->attr_key.attrname_key, sizeof(dval->attr_key.attrname_key), dval->attrname);
	dict2_lc(dval->attr_name_key.attrname_key, sizeof(dval->attr_name_key.attrname_key), dval->attrname);
	dict2_lc(dval->attr_name_key.name_key, sizeof(dval->attr_name_key.name_key), dval->name);
	dval->value = value;
	dval->attr_key.value = value;

	{
		struct radcli_dict_value *existing;
		int cmp = dict2_check_value(rh, dval, NULL, 0, &existing);

		if (cmp < 0) {
			free(dval);
			return NULL;
		} else if (cmp > 0) {
			free(dval);
			return existing;
		}
	}

	HASH_ADD(hh_name, rh->dict->values_by_name, name_key, strlen(dval->name_key), dval);
	HASH_ADD(hh_attr, rh->dict->values_by_attr, attr_key, sizeof(dval->attr_key), dval);
	HASH_ADD(hh_attr_name, rh->dict->values_by_attr_name, attr_name_key, sizeof(dval->attr_name_key), dval);
	return dval;
}

/*- Add a vendor to rh's dictionary programmatically. A re-add identical
 * to an already-loaded vendor of the same name returns that existing
 * vendor rather than adding a duplicate; a re-add of the same name with a
 * conflicting Vendor-Id fails, after a warning naming both definitions.
 *
 * @param rh a handle to parsed configuration.
 * @param name the vendor name.
 * @param vendorspec the vendor's PEN.
 * @return the added (or already-existing, identical) vendor, or NULL on
 * failure or conflict.
 -*/
struct radcli_dict_vendor *radcli_dict_vendor_add(rc_handle *rh, const char *name,
						   uint32_t vendorspec)
{
	struct radcli_dict_vendor *dvend;

	if (strlen(name) > RC_NAME_LENGTH)
	{
		rc_log(LOG_ERR, "rc_dict_addvend: invalid vendor name length");
		return NULL;
	}

	if (dict2_ensure(rh) < 0)
		return NULL;

	if ((dvend = calloc(1, sizeof(*dvend))) == NULL)
	{
		rc_log(LOG_CRIT, "rc_dict_addvend: out of memory");
		return NULL;
	}
	strlcpy(dvend->name, name, sizeof(dvend->name));
	dict2_lc(dvend->name_key, sizeof(dvend->name_key), dvend->name);
	dvend->pec = vendorspec;

	{
		struct radcli_dict_vendor *existing;
		int cmp = dict2_check_vendor(rh, dvend, NULL, 0, &existing);

		if (cmp < 0) {
			free(dvend);
			return NULL;
		} else if (cmp > 0) {
			free(dvend);
			return existing;
		}
	}

	HASH_ADD(hh_name, rh->dict->vendors_by_name, name_key, strlen(dvend->name_key), dvend);
	HASH_ADD(hh_pec, rh->dict->vendors_by_pec, pec, sizeof(dvend->pec), dvend);
	return dvend;
}
