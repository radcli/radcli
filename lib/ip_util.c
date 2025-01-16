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

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include "util.h"

#define HOSTBUF_SIZE 1024

/*- Returns a struct addrinfo from a host name or address in textual notation.
 *
 * @param host the name of the host
 * @param flags should be a combinations of PW_AI flags
 * @return address which should be deallocated using freeaddrinfo() or NULL on failure
 -*/
struct addrinfo *rc_getaddrinfo (char const *host, unsigned flags)
{
	struct addrinfo hints, *res;
	int err;
	const char *service = NULL;
 
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	if (flags & PW_AI_PASSIVE)
		hints.ai_flags = AI_PASSIVE;

	if (flags & PW_AI_AUTH)
		service = "radius";
	else if (flags & PW_AI_ACCT)
		service = "radius-acct";
 
	err = getaddrinfo(host, service, &hints, &res);
	if (err != 0) {
 		return NULL;
 	}

	return res;
}

/**
 * @defgroup misc-api Miscellaneous API
 *
 * @{
 */

/** Get the port number for the supplied request type
 *
 * @param type %AUTH or %ACCT.
 * @return the port number.
 */
unsigned short rc_getport(int type)
{
	struct servent *svp;

	if ((svp = getservbyname ((type==AUTH)?"radius" : "radacct", "udp")) == NULL)
	{
		return (type==AUTH) ? PW_AUTH_UDP_PORT : PW_ACCT_UDP_PORT;
	} else {
		return ntohs ((unsigned short) svp->s_port);
	}
}

/** Get the hostname of this machine
 *
 * @param hostname will hold the name of the host.
 * @param len the size of hostname.
 * @return -1 on failure, 0 on success.
 */
int rc_own_hostname(char *hostname, int len)
{
#ifdef HAVE_UNAME
	struct	utsname uts;
#endif

#if defined(HAVE_UNAME)
	if (uname(&uts) < 0)
	{
		rc_log(LOG_ERR,"rc_own_hostname: couldn't get own hostname");
		return -1;
	}
	strlcpy(hostname, uts.nodename, len);
#elif defined(HAVE_GETHOSTNAME)
	if (gethostname(hostname, len) < 0)
	{
		rc_log(LOG_ERR,"rc_own_hostname: couldn't get own hostname");
		return -1;
	}
#elif defined(HAVE_SYSINFO)
	if (sysinfo(SI_HOSTNAME, hostname, len) < 0)
	{
		rc_log(LOG_ERR,"rc_own_hostname: couldn't get own hostname");
		return -1;
	}
#else
	return -1;
#endif

	return 0;
}

/** Find outbound interface address for a given destination
 *
 * Given remote address find local address which the system will use as a source address for sending
 * datagrams to that remote address.
 *
 * @param[out] lia local address.
 * @param[in]  ria the remote address.
 * @return OK_RC on success. NETUNREACH_RC if network is unreachable (i.e.
 *         no route to destination). ERROR_RC for all other failures.
 *         Address is filled into the first argument.
 */
int rc_get_srcaddr(struct sockaddr *lia, const struct sockaddr *ria)
{
	int temp_sock;
	socklen_t namelen;

	temp_sock = socket(ria->sa_family, SOCK_DGRAM, 0);
	if (temp_sock == -1) {
		rc_log(LOG_ERR, "rc_get_srcaddr: socket: %s", strerror(errno));
		return ERROR_RC;
	}

	if (connect(temp_sock, ria, SA_LEN(ria)) != 0) {
		int rc = errno == ENETUNREACH ? NETUNREACH_RC : ERROR_RC;
		rc_log(LOG_ERR, "rc_get_srcaddr: connect: %s",
		    strerror(errno));
		close(temp_sock);
		return rc;
	}

	namelen = SA_LEN(ria);
	if (getsockname(temp_sock, lia, &namelen) != 0) {
		rc_log(LOG_ERR, "rc_get_srcaddr: getsockname: %s",
		    strerror(errno));
		close(temp_sock);
		return ERROR_RC;
	}

	close(temp_sock);
	return OK_RC;
}

/** Find our source address
 *
 * Get the IP address to be used as a source address
 * for sending requests in host order.
 *
 * @param rh a handle to parsed configuration
 * @param lia the local address to listen to
 *
 **/
void rc_own_bind_addr(rc_handle *rh, struct sockaddr_storage *lia)
{
	char *txtaddr = rc_conf_str(rh, "bindaddr");
	struct addrinfo *info;

	if (rh->own_bind_addr_set) {
		memcpy(lia, &rh->own_bind_addr, SS_LEN(&rh->own_bind_addr));
		return;
	}

	memset(lia, 0, sizeof(*lia));
	if (txtaddr == NULL || txtaddr[0] == '*') {
		((struct sockaddr_in*)lia)->sin_family = AF_INET;
		((struct sockaddr_in*)lia)->sin_addr.s_addr = INADDR_ANY;
	} else {
		info = rc_getaddrinfo (txtaddr, PW_AI_PASSIVE);
		if (info == NULL) {
			rc_log(LOG_ERR, "rc_own_ipaddress: couldn't get IP address from bindaddr");
			((struct sockaddr_in*)lia)->sin_family = AF_INET;
			((struct sockaddr_in*)lia)->sin_addr.s_addr = INADDR_ANY;
			return;
		}

		memcpy(lia, info->ai_addr, info->ai_addrlen);
       }

       return;
}
/** @} */
