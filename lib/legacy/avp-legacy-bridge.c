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

/** @file avp-legacy-bridge.c
 * @brief Projection between radcli_avp_list (radcli2.h) and VALUE_PAIR
 * (radcli.h), split out of lib/avp.c because both directions need legacy
 * VALUE_PAIR construction -- radcli_value_pairs_to_avp_list() is called
 * by lib/legacy/send.c's rc_send_server_ctx(); the reverse direction,
 * radcli_avp_list_to_value_pairs(), is exercised directly by
 * tests/avp-legacy.c. Both are internal only (declared in
 * lib/includes.h), built entirely on radcli2.h's own public
 * radcli_avp_list_new()/radcli_avp_add_bytes()/radcli_avp_list_free()/
 * iteration API plus legacy VALUE_PAIR construction -- no private
 * cross-library export needed for either.
 */

#include <includes.h>
#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include "dict2.h"
#include "util.h"

/* --- projection between radcli_avp_list and VALUE_PAIR (internal only) ---
 *
 * Not part of the public radcli2 API -- declared in lib/avp.h.
 * Lets a VALUE_PAIR-based caller and a radcli_avp_list-based caller
 * exchange attribute lists without either side needing to know the other's
 * representation. Both directions are pure re-copies through the public
 * accessors/constructors of whichever side they are producing -- no shared
 * storage, no aliasing, one direction does not undo what the other did.
 *
 * radcli_avp_list_to_value_pairs() omits an attribute VALUE_PAIR's fixed-
 * size fields cannot hold (a string/IPv6-prefix value over the wire length
 * VALUE_PAIR's 253-octet strvalue allows, or a value whose stored length
 * does not match its type's fixed size), logging why exactly as
 * rc_avpair_gen() itself does (lib/avpair.c) for an attribute it does not
 * recognise. This means a VALUE_PAIR list produced this way is
 * never longer, and is byte-identical for every attribute it does carry, to
 * what the legacy decoder would have produced from the same wire data
 * directly -- including a decrypted Tunnel-Password or MS-MPPE-*-Key
 * attribute, which arrives here as an ordinary plaintext string, already
 * decrypted by whichever radcli_avp_decode() call produced the source list.
 *
 * radcli_value_pairs_to_avp_list() is the reverse: encryption is not a
 * concern in this direction, since it happens later, in
 * radcli_avp_encode() itself, driven by the same dictionary encrypt=N flag
 * regardless of which representation the caller started from.
 */

/*- Convert a radcli_avp_list into a VALUE_PAIR list, byte-identical to what
 * the legacy decoder would have produced from the same wire data.
 *
 * @param rh a handle to parsed configuration.
 * @param l the attribute list to convert.
 * @param out set to the newly allocated VALUE_PAIR list (possibly NULL/
 * empty) on success.
 * @return 0 on success, -1 if rh or out is NULL, or on allocation failure.
 -*/
int radcli_avp_list_to_value_pairs(rc_handle const *rh, const radcli_avp_list *l, VALUE_PAIR **out)
{
	radcli_avp_iter it;
	const radcli_avp *a;
	VALUE_PAIR *head = NULL, **tail = &head;

	if (rh == NULL || out == NULL)
		return -1;

	/* Walked via the same public radcli_avp_list_iter()/radcli_avp_iter_next()/
	 * radcli_avp_def()/radcli_avp_get_bytes() API any other libradcli2
	 * caller uses -- l is a NULL-safe, empty iterator per
	 * radcli_avp_list_iter()'s own contract, so no separate NULL check is
	 * needed here. def is cast to lib/dict2.h's concrete struct
	 * radcli_dict_attr the same way lib/avp.c itself already does
	 * (radcli_dict_attr_gigawords()/radcli_dict_flags_by_id() call sites)
	 * -- radcli_attr_def is that struct's public, opaque name. */
	it = radcli_avp_list_iter(l);
	while ((a = radcli_avp_iter_next(&it)) != NULL) {
		const struct radcli_dict_attr *def = (const struct radcli_dict_attr *)radcli_avp_def(a);
		/* def->type may be one of dict2-parse.c's RFC 8044 sentinel types
		 * (integer64/ipv4prefix/text/ifid) for a bundled-dictionary
		 * attribute (e.g. User-Name as "text") -- narrow to the legacy
		 * rc_attr_type these switch()es and vp->type actually handle;
		 * see radcli_dict_type_to_legacy()'s comment (lib/dict2.h). */
		rc_attr_type type = radcli_dict_type_to_legacy(def->type);
		unsigned max_vlen = (VENDOR(def->value) != 0) ? (AUTH_STRING_LEN - VSA_HDR_LEN) : AUTH_STRING_LEN;
		const void *data;
		size_t len;
		VALUE_PAIR *vp;

		radcli_avp_get_bytes(a, &data, &len);

		switch (type) {
		case PW_TYPE_STRING:
		case PW_TYPE_IPV6PREFIX:
			if (len > max_vlen) {
				rc_log(LOG_WARNING, "radcli_avp_list_to_value_pairs: %s: "
				    "%zu bytes exceeds VALUE_PAIR's %u-byte limit, omitting",
				    def->name, len, max_vlen);
				continue; /* omitted: does not fit VALUE_PAIR's wire limit */
			}
			break;
		case PW_TYPE_IPV6ADDR:
			if (len != 16) {
				rc_log(LOG_WARNING, "radcli_avp_list_to_value_pairs: %s: "
				    "%zu bytes, expected 16, omitting", def->name, len);
				continue;
			}
			break;
		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
		case PW_TYPE_DATE:
			if (len != sizeof(uint32_t)) {
				rc_log(LOG_WARNING, "radcli_avp_list_to_value_pairs: %s: "
				    "%zu bytes, expected 4, omitting", def->name, len);
				continue;
			}
			break;
		default:
			continue; /* unreachable: radcli_attr_type has no other value */
		}

		vp = calloc(1, sizeof(*vp));
		if (vp == NULL) {
			rc_log(LOG_CRIT, "radcli_avp_list_to_value_pairs: out of memory");
			rc_avpair_free(head);
			return -1;
		}
		strlcpy(vp->name, def->name, sizeof(vp->name));
		vp->attribute = def->value;
		vp->type = type;

		switch (type) {
		case PW_TYPE_STRING:
		case PW_TYPE_IPV6PREFIX:
			memcpy(vp->strvalue, data, len);
			vp->lvalue = (uint32_t)len;
			break;
		case PW_TYPE_IPV6ADDR:
			memcpy(vp->strvalue, data, 16);
			vp->lvalue = 16;
			break;
		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
		case PW_TYPE_DATE:
			memcpy(&vp->lvalue, data, sizeof(uint32_t));
			break;
		default:
			break;
		}

		*tail = vp;
		tail = &vp->next;
	}

	*out = head;
	return 0;
}

/*- Convert a VALUE_PAIR list into a radcli_avp_list.
 *
 * @param rh a handle to parsed configuration.
 * @param vp the VALUE_PAIR list to convert.
 * @param out set to the newly allocated radcli_avp_list on success.
 * @return 0 on success, -1 if rh or out is NULL, or on allocation failure.
 -*/
int radcli_value_pairs_to_avp_list(rc_handle const *rh, VALUE_PAIR *vp, radcli_avp_list **out)
{
	radcli_avp_list *list;

	if (rh == NULL || out == NULL)
		return -1;

	list = radcli_avp_list_new();
	if (list == NULL)
		return -1;

	for (; vp != NULL; vp = vp->next) {
		const radcli_attr_def *def = radcli_dict_lookup_num(rh, (uint32_t)ATTRID(vp->attribute),
								     (uint32_t)VENDOR(vp->attribute));

		if (def == NULL) {
			/* Defensive only: a VALUE_PAIR built via rc_avpair_add()/
			 * rc_avpair_gen() against this same rh always has one. */
			continue;
		}

		switch (vp->type) {
		case PW_TYPE_STRING:
		case PW_TYPE_IPV6ADDR:
		case PW_TYPE_IPV6PREFIX:
			if (radcli_avp_add_bytes(list, def, vp->strvalue, vp->lvalue) != 0) {
				radcli_avp_list_free(list);
				return -1;
			}
			break;
		case PW_TYPE_INTEGER:
		case PW_TYPE_IPADDR:
		case PW_TYPE_DATE:
			if (radcli_avp_add_bytes(list, def, &vp->lvalue, sizeof(vp->lvalue)) != 0) {
				radcli_avp_list_free(list);
				return -1;
			}
			break;
		default:
			break;
		}
	}

	*out = list;
	return 0;
}
