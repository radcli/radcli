/*
 * Copyright (C) 1996 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <radcli/radcli-defs.h>

#define OPTION_LEN	64

#define OT_ANY		((unsigned int)~0)	//!< Used internally.

/* status types */
#define ST_UNDEF	(1<<0)			//!< option is undefined.

typedef struct _option {
	char name[OPTION_LEN];			//!< name of the option.
	int type, status;			//!< type and status.
	void *val;				//!< pointer to option value.
} OPTION;

/* RC_OPTION_TABLE itself (the X-macro list generating config_options_default[]
 * below and the rc_option_id enum) now lives in the public, installed
 * radcli/radcli-defs.h, included above: it is also the source radcli2.h's
 * radcli_opt_id enum is generated from, so the legacy and new APIs can never
 * recognise a different set of option names by accident. */

/* Legacy radiusclient-ng/freeradius-client option names that radcli parses
 * but never acted on (no code anywhere reads their stored value back) --
 * login_radius/seqfile/mapfile/nologin/issue/login_local supported an
 * external radlogin(1)-style local-login daemon radcli never implemented;
 * auth_order/login_tries/login_timeout supported choosing between local and
 * RADIUS authentication, likewise never implemented here. Kept as a
 * name-only ignore list (lib/config.c's rc_ignored_option()) purely so
 * existing config files carrying these lines keep loading unchanged --
 * they carry no rc_option_id, no storage, and rc_conf_str()/rc_conf_int()
 * can never return a value for them. */
#define RC_IGNORED_OPTION_TABLE \
X("login_radius") \
X("seqfile") \
X("mapfile") \
X("auth_order") \
X("login_tries") \
X("login_timeout") \
X("nologin") \
X("issue") \
X("login_local") \
X("radius_deadtime")

/* Index into config_options_default[]/rh->config_options[] for internal,
 * compile-time-known lookups (lib/config.c's rc_option_by_id() and
 * friends) that bypass find_option()'s string search. OPT_COUNT is
 * generated from the same RC_OPTION_TABLE list as the array below, so it
 * always matches NUM_OPTIONS. */
typedef enum {
#define RADCLI_OPT_ENTRY(id, name, type) id,
	RC_OPTION_TABLE
#undef RADCLI_OPT_ENTRY
	OPT_COUNT
} rc_option_id;

/* config_options_default[]/NUM_OPTIONS are only ever used in lib/config.c
 * (the array is memcpy()'d into each rc_handle's own config_options[]
 * there); defined there rather than here so headers that only need the
 * OPT_* ids/rc_conf_*_id() prototypes don't each get their own unused
 * static copy of the array. */

/* Internal (non-exported, see lib/radcli.map) id-based accessors --
 * defined in lib/config.c, used by hot per-request callers (buildreq.c,
 * request.c, tls.c) that already know which option they want at compile
 * time and can skip find_option()'s string search. Behave exactly like
 * rc_conf_int()/rc_conf_str() otherwise. */
int rc_conf_int_id(rc_handle const *rh, rc_option_id id);
char *rc_conf_str_id(rc_handle const *rh, rc_option_id id);
