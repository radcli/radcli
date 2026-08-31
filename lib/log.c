/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>

/* Debug verbosity is a per-rc_handle field (struct rc_conf's `debug`,
 * lib/includes.h) read by util.h's DEBUG() macro. The legacy
 * rc_setdebug()/radcli_legacy_debug global lives entirely in
 * lib/legacy/compat.c now -- see REQ-GEN-SEC-005. */
