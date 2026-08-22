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
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

/** @file dict2.c
 * @brief Canonical, hash-indexed dictionary implementation.
 *
 * See dict2.h's file comment for the split between this file and
 * lib/dict.c's compatibility shim.
 */

#include <config.h>
#include <includes.h>
#include <limits.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "dict2.h"
#include "util.h"

/// @cond INTERNAL

/* Lowercases src into dst (case-insensitive hash key), truncating at
 * dstsize - 1 like strlcpy -- callers always pass a name already validated
 * against RC_NAME_LENGTH, so truncation never actually triggers. */
static void dict2_lc(char *dst, size_t dstsize, const char *src)
{
	size_t i;

	for (i = 0; i + 1 < dstsize && src[i] != '\0'; i++)
		dst[i] = (char)tolower((unsigned char)src[i]);
	dst[i] = '\0';
}

/* Lazily allocates rh->dict on first use -- every entry point (the loader
 * and the three rc_dict_add*() backers) needs one, and none of radcli's own
 * callers require a dictionary to have been loaded first (tests/dict-add.c
 * calls rc_dict_addattr() straight after rc_new()). */
static int dict2_ensure(rc_handle *rh)
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

/* The ATTRIBUTE/VALUE/VENDOR/$INCLUDE/BEGIN-VENDOR/END-VENDOR grammar --
 * ported from the pre-dict2 rc_dict_init(), unchanged apart from inserting
 * into rh->dict's uthash tables instead of prepending to hand-rolled
 * next-chains (the same "most recently loaded wins" lookup semantics falls
 * out of uthash's own bucket order -- HASH_ADD_TO_BKT prepends, so
 * HASH_FIND always sees the newest match first, matching
 * REQ-DICT-DATA-005 without any extra bookkeeping here). filename is NULL
 * for a buffer-sourced load, which -- per REQ-DICT-INIT-002 -- disables
 * $INCLUDE. */
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
						 * yet (see radcli_avp_decode()/radcli_avp_encode_rfc2865()
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

			HASH_ADD(hh_name, rh->dict->attrs_by_name, name_key, strlen(attr->name_key), attr);
			HASH_ADD(hh_id, rh->dict->attrs_by_id, value, sizeof(attr->value), attr);

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
			dval->value = value;
			dval->attr_key.value = value;

			HASH_ADD(hh_name, rh->dict->values_by_name, name_key, strlen(dval->name_key), dval);
			HASH_ADD(hh_attr, rh->dict->values_by_attr, attr_key, sizeof(dval->attr_key), dval);
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
			if (rc_read_dictionary(rh, ifilename) < 0)
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

			HASH_ADD(hh_name, rh->dict->vendors_by_name, name_key, strlen(dvend->name_key), dvend);
			HASH_ADD(hh_pec, rh->dict->vendors_by_pec, pec, sizeof(dvend->pec), dvend);
		}
	}
	free(buffer);
	return 0;

error:
	free(buffer);
	return -1;
}
/// @endcond

int rc_read_dictionary (rc_handle *rh, char const *filename)
{
	FILE    *dictfd;
	int     ret_val = 0;

	if (rh->first_dict_read != NULL && strcmp(filename, rh->first_dict_read) == 0)
		return 0;

	if (dict2_ensure(rh) < 0)
		return -1;

	if ((dictfd = fopen (filename, "r")) == NULL)
	{
		rc_log(LOG_ERR, "rc_read_dictionary couldn't open dictionary %s: %s",
				filename, strerror(errno));
		return -1;
	}

	ret_val = dict2_parse(rh, dictfd, filename);

	fclose (dictfd);

	if (rh->first_dict_read == NULL)
		rh->first_dict_read = strdup(filename);

	return ret_val;
}

int rc_read_dictionary_from_buffer (rc_handle *rh, char const *buf, size_t size)
{
	FILE      *dictfd;
	int       ret_val = 0;

	if (dict2_ensure(rh) < 0)
		return -1;

	if ((dictfd = fmemopen ((void *)buf, size, "r")) == NULL)
	{
		rc_log(LOG_ERR, "rc_read_dictionary_from_buffer failed to read "
				"input buffer %s", strerror(errno));
		return -1;
	}

	ret_val = dict2_parse(rh, dictfd, NULL);

	fclose (dictfd);

	return ret_val;
}

void rc_dict_free(rc_handle *rh)
{
	struct radcli_dict_attr *a, *atmp;
	struct radcli_dict_value *v, *vtmp;
	struct radcli_dict_vendor *w, *wtmp;
	struct radcli_dict_flags *fl, *fltmp;
	struct radcli_dict_gigawords *gw, *gwtmp;
	struct radcli_dict *d = rh->dict;

	if (d == NULL)
		return;

	HASH_ITER(hh_name, d->attrs_by_name, a, atmp) {
		HASH_DELETE(hh_name, d->attrs_by_name, a);
		HASH_DELETE(hh_id, d->attrs_by_id, a);
		free(a->legacy);
		free(a);
	}
	HASH_ITER(hh_name, d->values_by_name, v, vtmp) {
		HASH_DELETE(hh_name, d->values_by_name, v);
		HASH_DELETE(hh_attr, d->values_by_attr, v);
		free(v->legacy);
		free(v);
	}
	HASH_ITER(hh_name, d->vendors_by_name, w, wtmp) {
		HASH_DELETE(hh_name, d->vendors_by_name, w);
		HASH_DELETE(hh_pec, d->vendors_by_pec, w);
		free(w->legacy);
		free(w);
	}
	HASH_ITER(hh, d->flags_by_attr_id, fl, fltmp) {
		HASH_DELETE(hh, d->flags_by_attr_id, fl);
		free(fl);
	}
	HASH_ITER(hh, d->gigawords_by_attr_id, gw, gwtmp) {
		HASH_DELETE(hh, d->gigawords_by_attr_id, gw);
		free(gw);
	}

	free(d);
	rh->dict = NULL;
	/* rh->first_dict_read is intentionally left untouched -- see
	 * REQ-DICT-DATA-008; owned/released by rc_config_free() instead. */
}

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

	HASH_ADD(hh_name, rh->dict->attrs_by_name, name_key, strlen(attr->name_key), attr);
	HASH_ADD(hh_id, rh->dict->attrs_by_id, value, sizeof(attr->value), attr);
	return attr;
}

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
	dval->value = value;
	dval->attr_key.value = value;

	HASH_ADD(hh_name, rh->dict->values_by_name, name_key, strlen(dval->name_key), dval);
	HASH_ADD(hh_attr, rh->dict->values_by_attr, attr_key, sizeof(dval->attr_key), dval);
	return dval;
}

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

	HASH_ADD(hh_name, rh->dict->vendors_by_name, name_key, strlen(dvend->name_key), dvend);
	HASH_ADD(hh_pec, rh->dict->vendors_by_pec, pec, sizeof(dvend->pec), dvend);
	return dvend;
}

struct radcli_dict_attr *radcli_dict_attr_by_name(rc_handle const *rh, const char *name)
{
	char key[RC_DICT2_KEY_LEN];
	struct radcli_dict_attr *out;

	if (rh == NULL || rh->dict == NULL || name == NULL)
		return NULL;

	dict2_lc(key, sizeof(key), name);
	HASH_FIND(hh_name, rh->dict->attrs_by_name, key, strlen(key), out);
	return out;
}

struct radcli_dict_attr *radcli_dict_attr_by_id(rc_handle const *rh, uint64_t value)
{
	struct radcli_dict_attr *out;

	if (rh == NULL || rh->dict == NULL)
		return NULL;

	HASH_FIND(hh_id, rh->dict->attrs_by_id, &value, sizeof(value), out);
	return out;
}

struct radcli_dict_value *radcli_dict_value_by_name(rc_handle const *rh, const char *name)
{
	char key[RC_DICT2_KEY_LEN];
	struct radcli_dict_value *out;

	if (rh == NULL || rh->dict == NULL || name == NULL)
		return NULL;

	dict2_lc(key, sizeof(key), name);
	HASH_FIND(hh_name, rh->dict->values_by_name, key, strlen(key), out);
	return out;
}

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

struct radcli_dict_vendor *radcli_dict_vendor_by_name(rc_handle const *rh, const char *name)
{
	char key[RC_DICT2_KEY_LEN];
	struct radcli_dict_vendor *out;

	if (rh == NULL || rh->dict == NULL || name == NULL)
		return NULL;

	dict2_lc(key, sizeof(key), name);
	HASH_FIND(hh_name, rh->dict->vendors_by_name, key, strlen(key), out);
	return out;
}

struct radcli_dict_vendor *radcli_dict_vendor_by_pec(rc_handle const *rh, uint32_t pec)
{
	struct radcli_dict_vendor *out;

	if (rh == NULL || rh->dict == NULL)
		return NULL;

	HASH_FIND(hh_pec, rh->dict->vendors_by_pec, &pec, sizeof(pec), out);
	return out;
}

struct radcli_dict_flags *radcli_dict_flags_by_id(rc_handle const *rh, uint64_t attr_id)
{
	struct radcli_dict_flags *out;

	if (rh == NULL || rh->dict == NULL)
		return NULL;

	HASH_FIND(hh, rh->dict->flags_by_attr_id, &attr_id, sizeof(attr_id), out);
	return out;
}

struct radcli_dict_gigawords *radcli_dict_gigawords_by_id(rc_handle const *rh, uint64_t attr_id)
{
	struct radcli_dict_gigawords *out;

	if (rh == NULL || rh->dict == NULL)
		return NULL;

	HASH_FIND(hh, rh->dict->gigawords_by_attr_id, &attr_id, sizeof(attr_id), out);
	return out;
}

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
		a->legacy->type = a->type;
		a->legacy->next = NULL;
	}
	return a->legacy;
}

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
