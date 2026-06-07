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

unsigned int radcli_debug = 0;

/**
 * @defgroup misc-api Miscellaneous API
 * @brief Miscellaneous functions
 *
 * All radcli error and informational messages are emitted via syslog(3)
 * (facility @c LOG_DAEMON by default).  An application controls where those
 * messages go by calling openlog(3) with its own ident and facility before
 * making any radcli calls.  The rc_openlog() and rc_setdebug() functions
 * below are kept for source compatibility with older code; new code should
 * use openlog(3) and the @c clientdebug config option directly.
 *
 * @{
 */

/** Set debug logging level
 *
 * @deprecated Prefer setting @c clientdebug in the configuration file
 * (rc_read_config()) or rc_add_config().  Using this function bypasses the
 * config file and is retained only for source compatibility with
 * freeradius-client and radiusclient-ng.
 *
 * @param debug debug level; 0 disables debug output, positive values enable it.
 */
void rc_setdebug(int debug)
{
  radcli_debug = debug;
}

/** Open the system log for radcli messages
 *
 * @deprecated New code should call openlog(3) directly.  radcli emits all
 * messages via syslog(3); opening the log with your application's own ident
 * and facility before the first radcli call is sufficient.  This function is
 * a thin wrapper around openlog() retained for source compatibility with
 * freeradius-client and radiusclient-ng.
 *
 * @param ident program name passed to openlog(3).
 */
void rc_openlog(char const *ident)
{
#ifndef _MSC_VER /* TODO: Fix me */
	openlog(ident, LOG_PID, RC_LOG_FACILITY);
#endif
}

/** @} */
