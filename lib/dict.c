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

#include <config.h>
#include <includes.h>
#include <limits.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "util.h"

/** @brief Add attribute to dictionary
 *
 * Does not check if such attribute already exists
 *
 * @param rh              a handle to configuration.
 * @param namestr         attribute name
 * @param type            attribute type
 * @param value           attribute value
 * @param vendorspec      vendorspec
 * @return                added attr on success, NULL on failure
 */
DICT_ATTR *rc_dict_addattr(rc_handle *rh, char const * namestr, uint32_t value, int type, uint32_t vendorspec)
{
	DICT_ATTR *attr;

	if (strlen (namestr) > RC_NAME_LENGTH)
	{
		rc_log(LOG_ERR, "rc_dict_addattr: invalid attribute length");
		return NULL;
	}

	if (type < 0 || type >= PW_TYPE_MAX)
	{
		rc_log(LOG_ERR, "rc_dict_addattr: invalid attribute type");
		return NULL;
	}

	/* Create a new attribute for the list */
	if ((attr = malloc(sizeof (DICT_ATTR))) == NULL)
	{
		rc_log(LOG_CRIT, "rc_dict_addattr: out of memory");
		return NULL;
	}

	strlcpy(attr->name, namestr, sizeof(attr->name));
	attr->value = RADCLI_VENDOR_ATTR_SET(value, vendorspec);
	attr->type = type;

	/* Insert it into the list */
	attr->next = rh->dictionary_attributes;
	rh->dictionary_attributes = attr;
	return attr;
}

/** @brief Add value to dictionary
 *
 * Does not check if such value already exists
 *
 * @param rh              a handle to configuration.
 * @param attrstr         attribute name
 * @param namestr         name
 * @param value           attribute value
 * @return                added value on success, NULL on failure
 */
DICT_VALUE *rc_dict_addval(rc_handle *rh, char const * attrstr, char const * namestr, uint32_t value)
{
	DICT_VALUE *dval;

	if (strlen(attrstr) > RC_NAME_LENGTH)
	{
		rc_log(LOG_ERR, "rc_dict_addval: invalid attribute length");
		return NULL;
	}

	if (strlen(namestr) > RC_NAME_LENGTH)
	{
		rc_log(LOG_ERR, "rc_dict_addval: invalid name length");
		return NULL;
	}

	/* Create a new VALUE entry for the list */
	if ((dval = malloc(sizeof (DICT_VALUE))) == NULL)
	{
		rc_log(LOG_CRIT, "rc_dict_addval: out of memory");
		return NULL;
	}
	strlcpy(dval->attrname, attrstr, sizeof(dval->attrname));
	strlcpy(dval->name, namestr, sizeof(dval->name));
	dval->value = value;

	/* Insert it into the list */
	dval->next = rh->dictionary_values;
	rh->dictionary_values = dval;
	return dval;
}

/** @brief Add vendor to dictionary
 *
 * Does not check if such vendor already exists
 *
 * @param rh              a handle to configuration.
 * @param namestr         vendor name
 * @param vendorspec      vendorspec
 * @return                added value on success, NULL on failure
 */
DICT_VENDOR *rc_dict_addvend(rc_handle *rh, char const * namestr, uint32_t vendorspec)
{
	DICT_VENDOR *dvend;

	if (strlen(namestr) > RC_NAME_LENGTH)
	{
		rc_log(LOG_ERR, "rc_dict_addvend: invalid vendor name length");
		return NULL;
	}

	/* Create a new VENDOR entry for the list */
	dvend = malloc(sizeof(DICT_VENDOR));
	if (dvend == NULL)
	{
		rc_log(LOG_CRIT, "rc_dict_init: out of memory");
		return NULL;
	}
	strlcpy(dvend->vendorname, namestr, sizeof(dvend->vendorname));
	dvend->vendorpec = vendorspec;

	/* Insert it into the list */
	dvend->next = rh->dictionary_vendors;
	rh->dictionary_vendors = dvend;
	return dvend;
}

/* Parse the input dictionary-config and initialize the dictionary.
 *
 * Read all ATTRIBUTES into the dictionary_attributes list.
 * Read all VALUES into the dictionary_values list.
 *
 * @param rh       a handle to parsed configuration.
 * @param dictfd   a handle to the dictionary config.
 * @param filename the name of the dictionary file.
 * @return 0 on success, -1 on failure.
 */
/// @cond INTERNAL
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

static int rc_dict_init(rc_handle *rh, FILE *dictfd, char const *filename)
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
	DICT_ATTR      *attr;
	DICT_VALUE     *dval;
	DICT_VENDOR    *dvend;
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
				 * only way to see one; see dict_type_to_radcli() below. */
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
						/* RFC 2868 SS3.1 tunnel-attribute tagging; see
						 * rc_dict_attr_has_tag() below. */
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
						 * "gigawords=52" on the
						 * Acct-Input-Octets (42) line, naming
						 * Acct-Input-Gigawords (52). Not resolved to a
						 * DICT_ATTR* here: see struct dict_counter64_pair's
						 * comment (include/includes.h) for why. */
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
					dvend = rc_dict_findvend(rh, cp1);
					if (dvend == NULL) {
						rc_log(LOG_ERR,
							"rc_dict_init: unknown Vendor-Id %s on line %d of "
							"dictionary %s", cp1, line_no, pfilename);
						goto error;
					}
				}
			}

			/* Create a new attribute for the list */
			if ((attr = malloc (sizeof (DICT_ATTR))) == NULL)
			{
				rc_log(LOG_CRIT, "rc_dict_init: out of memory");
				goto error;
			}
			strlcpy (attr->name, namestr, sizeof(attr->name));
			attr->type = type;

			if (dvend != NULL) {
				attr->value = RADCLI_VENDOR_ATTR_SET(value, dvend->vendorpec);
			} else {
				attr->value = RADCLI_VENDOR_ATTR_SET(value, attr_vendorspec);
			}

			/* Insert it into the list */
			attr->next = rh->dictionary_attributes;
			rh->dictionary_attributes = attr;

			if (encrypt_type != 0 || has_tag_flag != 0) {
				struct dict_encrypt_flag *ef = malloc(sizeof(*ef));

				if (ef == NULL) {
					rc_log(LOG_CRIT, "rc_dict_init: out of memory");
					goto error;
				}
				ef->attr = attr;
				ef->encrypt_type = encrypt_type;
				ef->has_tag = has_tag_flag;
				ef->next = rh->dictionary_encrypt;
				rh->dictionary_encrypt = ef;
			}

			if (gigawords_attrid != 0) {
				struct dict_counter64_pair *gp = malloc(sizeof(*gp));

				if (gp == NULL) {
					rc_log(LOG_CRIT, "rc_dict_init: out of memory");
					goto error;
				}
				gp->octets = attr;
				/* Same vendor scope as this ATTRIBUTE line itself -- a VSA's
				 * gigawords= counterpart is another sub-attribute of the
				 * same vendor, not a standard attribute. */
				gp->gigawords_attrid = RADCLI_VENDOR_ATTR_SET(gigawords_attrid,
									      VENDOR(attr->value));
				gp->next = rh->dictionary_gigawords;
				rh->dictionary_gigawords = gp;
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

			/* Create a new VALUE entry for the list */
			if ((dval = malloc (sizeof (DICT_VALUE))) == NULL)
			{
				rc_log(LOG_CRIT, "rc_dict_init: out of memory");
				goto error;
			}
			strlcpy (dval->attrname, attrstr, sizeof(dval->attrname));
			strlcpy (dval->name, namestr, sizeof(dval->name));
			dval->value = value;

			/* Insert it into the list */
			dval->next = rh->dictionary_values;
			rh->dictionary_values = dval;
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
			DICT_VENDOR *v;
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

			v = rc_dict_findvend(rh, name_t);
			if (v == NULL) {
				rc_log(LOG_ERR,
					"rc_dict_init: unknown Vendor %s on line %d of "
					"dictionary %s", name_t, line_no, pfilename);
				goto error;
			}

			attr_vendorspec = v->vendorpec;
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

			/* Create a new VENDOR entry for the list */
			dvend = malloc(sizeof(DICT_VENDOR));
			if (dvend == NULL)
			{
				rc_log(LOG_CRIT, "rc_dict_init: out of memory");
				goto error;
			}
			strlcpy (dvend->vendorname, attrstr, sizeof(dvend->vendorname));
			dvend->vendorpec = value;

			/* Insert it into the list */
			dvend->next = rh->dictionary_vendors;
			rh->dictionary_vendors = dvend;
		}
	}
	free(buffer);
	return 0;

error:
	free(buffer);
	return -1;
}
/// @endcond

/** @brief Initialize the dictionary
 *
 * Read all ATTRIBUTES into the dictionary_attributes list.
 * Read all VALUES into the dictionary_values list.
 *
 * @param rh a handle to parsed configuration.
 * @param filename the name of the dictionary file.
 * @return 0 on success, -1 on failure.
 */
int rc_read_dictionary (rc_handle *rh, char const *filename)
{
	FILE    *dictfd;
	int     ret_val = 0;

	if (rh->first_dict_read != NULL && strcmp(filename, rh->first_dict_read) == 0)
		return 0;

	if ((dictfd = fopen (filename, "r")) == NULL)
	{
		rc_log(LOG_ERR, "rc_read_dictionary couldn't open dictionary %s: %s",
				filename, strerror(errno));
		return -1;
	}

	ret_val = rc_dict_init(rh, dictfd, filename);

	fclose (dictfd);

	if (rh->first_dict_read == NULL)
		rh->first_dict_read = strdup(filename);

	return ret_val;
}

/** @brief Initialize the dictionary from Buffer
 *
 * Read all ATTRIBUTES into the dictionary_attributes list.
 * Read all VALUES into the dictionary_values list.
 *
 * @param rh   a handle to parsed configuration.
 * @param buf  buffer holding Dictionary info
 * @param size size of buffer
 * @return 0 on success, -1 on failure.
 */
int rc_read_dictionary_from_buffer (rc_handle *rh, char const *buf, size_t size)
{
	FILE      *dictfd;
	int       ret_val = 0;

	if ((dictfd = fmemopen ((void *)buf, size, "r")) == NULL)
	{
		rc_log(LOG_ERR, "rc_read_dictionary_from_buffer failed to read "
				"input buffer %s", strerror(errno));
		return -1;
	}

	ret_val = rc_dict_init(rh, dictfd, NULL);

	fclose (dictfd);

	return ret_val;
}

/** @brief Lookup a DICT_ATTR by attribute number
 *
 * @param rh a handle to parsed configuration.
 * @param attribute the attribute ID.
 * @return the full attribute structure based on the attribute id number.
 */
DICT_ATTR *rc_dict_getattr(rc_handle const *rh, uint64_t attribute)
{
	DICT_ATTR      *attr;

	attr = rh->dictionary_attributes;
	while (attr != NULL)
	{
		if (attr->value == attribute)
		{
			return attr;
		}
		attr = attr->next;
	}
	return NULL;
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
	DICT_ATTR      *attr;

	attr = rh->dictionary_attributes;
	while (attr != NULL)
	{
		if (strcasecmp (attr->name, attrname) == 0)
		{
			return attr;
		}
		attr = attr->next;
	}
	return NULL;
}


/** @brief Lookup a DICT_VALUE by its name
 *
 * @param rh a handle to parsed configuration.
 * @param valname the value name.
 * @return the full value structure based on the value name.
 */
DICT_VALUE *rc_dict_findval(rc_handle const *rh, char const *valname)
{
	DICT_VALUE     *val;
	val = rh->dictionary_values;
	while (val != NULL)
	{
		if (strcasecmp (val->name, valname) == 0)
		{
			return val;
		}
		val = val->next;
	}
	return NULL;
}

/** @brief Lookup a DICT_VENDOR by its name
 *
 * @param rh a handle to parsed configuration.
 * @param vendorname the vendor name.
 * @return the full vendor structure based on the vendor name.
 */
DICT_VENDOR *rc_dict_findvend(rc_handle const *rh, char const *vendorname)
{
	DICT_VENDOR	*vend;

	for (vend = rh->dictionary_vendors; vend != NULL; vend = vend->next)
		if (strcasecmp(vend->vendorname, vendorname) == 0)
			return vend;
	return NULL;
}

/** @brief Lookup a DICT_VENDOR by its IANA number
 *
 * @param rh a handle to parsed configuration.
 * @param vendorspec the vendor ID.
 * @return the full vendor structure based on the vendor id number.
 */
DICT_VENDOR *rc_dict_getvend (rc_handle const *rh, uint32_t vendorspec)
{
        DICT_VENDOR      *vend;

	for (vend = rh->dictionary_vendors; vend != NULL; vend = vend->next)
		if (vend->vendorpec == vendorspec)
			return vend;
	return NULL;
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
	DICT_VALUE     *val;

	val = rh->dictionary_values;
	while (val != NULL)
	{
		if (strcasecmp (val->attrname, attrname) == 0 &&
				val->value == value)
		{
			return val;
		}
		val = val->next;
	}
	return NULL;
}

/** @brief Frees the allocated dictionary
 *
 * @param rh a handle to parsed configuration.
 */
void rc_dict_free(rc_handle *rh)
{
	DICT_ATTR	*attr, *nattr;
	DICT_VALUE	*val, *nval;
	DICT_VENDOR	*vend, *nvend;
	struct dict_encrypt_flag *ef, *nef;
	struct dict_counter64_pair *gp, *ngp;

	for (attr = rh->dictionary_attributes; attr != NULL; attr = nattr) {
		nattr = attr->next;
		free(attr);
	}
	for (val = rh->dictionary_values; val != NULL; val = nval) {
		nval = val->next;
		free(val);
	}
	for (vend = rh->dictionary_vendors; vend != NULL; vend = nvend) {
		nvend = vend->next;
		free(vend);
	}
	for (ef = rh->dictionary_encrypt; ef != NULL; ef = nef) {
		nef = ef->next;
		free(ef);
	}
	for (gp = rh->dictionary_gigawords; gp != NULL; gp = ngp) {
		ngp = gp->next;
		free(gp);
	}
	rh->dictionary_attributes = NULL;
	rh->dictionary_values = NULL;
	rh->dictionary_vendors = NULL;
	rh->dictionary_encrypt = NULL;
	rh->dictionary_gigawords = NULL;
}

/* Internal only -- see the declaration in include/includes.h, shared with
 * lib/avp.c the way rc_send_server_ctx is.
 *
 * Matches by attr->value (attribute id + vendor, RADCLI_VENDOR_ATTR_SET()-
 * combined), not by DICT_ATTR pointer identity: rc_dict_addattr()/
 * rc_dict_init() never dedup redefinitions of the same (id, vendor) under a
 * new name or from a later-loaded dictionary (e.g. a caller's supplemental
 * dictionary loaded after the built-in one, or the built-in "Password"/
 * "User-Password" id-2 alias pair -- see etc/dictionary), so two distinct
 * DICT_ATTR objects can legitimately mean the same wire attribute. Matching
 * by value means any dictionary_encrypt entry ever registered for that id
 * still applies, regardless of which same-id DICT_ATTR a caller resolved
 * through -- fail-safe: a redefinition that omits encrypt=/has_tag cannot
 * silently turn off encryption for an id another loaded definition already
 * flagged. */
int rc_dict_attr_encrypt_type(rc_handle const *rh, const DICT_ATTR *attr)
{
	struct dict_encrypt_flag *ef;

	if (rh == NULL || attr == NULL)
		return 0;

	for (ef = rh->dictionary_encrypt; ef != NULL; ef = ef->next) {
		if (ef->attr->value == attr->value)
			return ef->encrypt_type;
	}
	return 0;
}

/* Internal only -- see the declaration in include/includes.h, shared with
 * lib/avp.c the way rc_send_server_ctx is. Matches by attr->value, not
 * pointer identity -- see rc_dict_attr_encrypt_type() above for why. */
int rc_dict_attr_has_tag(rc_handle const *rh, const DICT_ATTR *attr)
{
	struct dict_encrypt_flag *ef;

	if (rh == NULL || attr == NULL)
		return 0;

	for (ef = rh->dictionary_encrypt; ef != NULL; ef = ef->next) {
		if (ef->attr->value == attr->value)
			return ef->has_tag;
	}
	return 0;
}

/* Internal only -- see the declaration in include/includes.h. */
const DICT_ATTR *rc_dict_attr_gigawords(rc_handle const *rh, const DICT_ATTR *octets)
{
	struct dict_counter64_pair *gp;

	if (rh == NULL || octets == NULL)
		return NULL;

	for (gp = rh->dictionary_gigawords; gp != NULL; gp = gp->next) {
		if (gp->octets == octets)
			return rc_dict_getattr(rh, gp->gigawords_attrid);
	}
	return NULL;
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
 * Design Review / Dependency growth). */

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
		 * keyword's comment above (rc_dict_init()). rc_dict_addattr()
		 * (the public, programmatic attribute API) still rejects
		 * type >= PW_TYPE_MAX, so this value can only ever come from the
		 * bundled dictionary file. */
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
	return (const radcli_attr_def *)rc_dict_findattr((rc_handle const *)ctx, name);
}

const radcli_attr_def *radcli_dict_lookup_num(const radcli_ctx *ctx, uint32_t attrid, uint32_t vendor)
{
	if (ctx == NULL)
		return NULL;
	return (const radcli_attr_def *)rc_dict_getattr((rc_handle const *)ctx,
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
	const DICT_ATTR *a = (const DICT_ATTR *)def;
	return a ? a->name : NULL;
}

radcli_attr_type radcli_attr_def_type(const radcli_attr_def *def)
{
	const DICT_ATTR *a = (const DICT_ATTR *)def;
	return dict_type_to_radcli(a ? a->type : PW_TYPE_STRING);
}

int radcli_attr_def_oid(const radcli_attr_def *def, char *buf, size_t buflen)
{
	const DICT_ATTR *a = (const DICT_ATTR *)def;
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
