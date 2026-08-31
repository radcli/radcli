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
/** @} */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include <options.h>
#include "util.h"
#include "tls.h"
#include "dict_rfc_gen.h"

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

static int rc_conf_int_2(rc_handle const *rh, char const *optname, int complain);

/* The template every rc_handle's config_options[] is memcpy()'d from
 * (lib/config.c's radcli2_priv_new()/radcli2_priv_read_config()); the per-id enum in
 * lib/options.h's RC_OPTION_TABLE indexes straight into it/its copies. */
static OPTION config_options_default[] = {
#define RADCLI_OPT_ENTRY(id, name, type) {name, type, ST_UNDEF, NULL},
	RC_OPTION_TABLE
#undef RADCLI_OPT_ENTRY
};

#define	NUM_OPTIONS	((sizeof(config_options_default))/(sizeof(config_options_default[0])))

/* Find an option in the option list
 *
 * @param rh a handle to parsed configuration.
 * @param optname the name of the option.
 * @param type the option type.
 * @return pointer to option on success, NULL otherwise.
 */
/*- Look up optname's OPTION entry, scanning linearly (few enough options
 * that a binary search isn't worthwhile).
 *
 * @param rh a handle to parsed configuration.
 * @param optname the option name to look up.
 * @param type a bitmask of acceptable RADCLI_OPT_TYPE_* types for the match.
 * @return the option's entry, or NULL if optname is unknown or its type
 * doesn't match type.
 -*/
static OPTION *find_option(rc_handle const *rh, char const *optname, unsigned int type)
{
	int 	i;

	/* there're so few options that a binary search seems not necessary */
	for (i = 0; i < NUM_OPTIONS; i++) {
		if (!strcmp(rh->config_options[i].name, optname) &&
		    (rh->config_options[i].type & type))
		{
		    	return &rh->config_options[i];
		}
	}

	return NULL;
}

/*- Report whether name is one of RC_IGNORED_OPTION_TABLE's legacy option
 * names -- accepted for backward compatibility with existing config
 * files, but never stored (see lib/options.h's RC_IGNORED_OPTION_TABLE
 * comment).
 *
 * @param name the option name to check.
 * @return nonzero if name is an ignored legacy option, zero otherwise.
 -*/
static int rc_ignored_option(char const *name)
{
#define X(n) if (!strcmp(name, n)) return 1;
	RC_IGNORED_OPTION_TABLE
#undef X
	return 0;
}

/* Index-based option lookup for internal callers that already know which
 * option they want at compile time (an OPT_* from lib/options.h's
 * RC_OPTION_TABLE) -- skips find_option()'s string scan entirely. Only
 * ever called with a literal OPT_* id, so id/type pairing is fixed at
 * compile time; the assert()s below catch a future miswired call site. */
/*- Look up id's OPTION entry directly by index.
 *
 * @param rh a handle to parsed configuration.
 * @param id the option's compile-time index.
 * @return the option's entry; never NULL (asserts rh/id are valid).
 -*/
static inline OPTION *rc_option_by_id(rc_handle const *rh, rc_option_id id)
{
	assert(rh != NULL && rh->config_options != NULL);
	assert((unsigned)id < NUM_OPTIONS);
	return &rh->config_options[id];
}

/*- Get the value of an integer-typed config option by compile-time index.
 *
 * @param rh a handle to parsed configuration.
 * @param id the option's compile-time index; must be RADCLI_OPT_TYPE_INT.
 * @return config option value, or 0 if unset.
 -*/
int rc_conf_int_id(rc_handle const *rh, rc_option_id id)
{
	OPTION *option = rc_option_by_id(rh, id);

	assert(option->type & RADCLI_OPT_TYPE_INT);

	if (option->val)
		return *((int *)option->val);

	rc_log(LOG_INFO, "radcli2_priv_conf_int: config option %s was not set", option->name);
	return 0;
}

/*- Get the value of a string-typed config option by compile-time index.
 *
 * @param rh a handle to parsed configuration.
 * @param id the option's compile-time index; must be RADCLI_OPT_TYPE_STR.
 * @return config option value.
 -*/
char *rc_conf_str_id(rc_handle const *rh, rc_option_id id)
{
	OPTION *option = rc_option_by_id(rh, id);

	assert(option->type & RADCLI_OPT_TYPE_STR);

	return (char *)option->val;
}

/*- Set a string-typed option's value, duplicating p.
 *
 * @param filename the name of the config file (for logging purposes).
 * @param line the line number in the file (for logging purposes).
 * @param option the option to set.
 * @param p the value, or NULL to clear it.
 * @return 0 on success, -1 on allocation failure.
 -*/
static int set_option_str(char const *filename, int line, OPTION *option, char const *p)
{
	if (p) {
		option->val = (void *) strdup(p);
		if (option->val == NULL) {
			rc_log(LOG_CRIT, "read_config: out of memory");
			return -1;
		}
	} else {
		option->val = NULL;
	}

	return 0;
}

/*- Set an integer-typed option's value, parsing p.
 *
 * watchdog-interval carries a floor below which it is refused outright (0
 * still disables it, unchanged): 1-5 would just mean radcli spends nearly
 * all its time reconnecting/sending Status-Server packets when
 * REQ-WATCHDOG-NET-003's 2.5x-interval dead-peer threshold is this close to the
 * interval itself, RFC 3539 SS3.4's watchdog algorithm assumes Tw is chosen
 * with meaningful headroom, and TCP-level connection churn that fast is not
 * useful "liveness" checking. Enforced here, the single choke point both
 * the config-file reader and radcli_ctx_set_opt_int() (lib/config2.c)
 * funnel through, so both paths agree.
 *
 * @param filename the name of the config file (for logging purposes).
 * @param line the line number in the file (for logging purposes).
 * @param option the option to set.
 * @param p the value text to parse; must be non-NULL.
 * @return 0 on success, -1 if p is NULL, out of range for option, or on
 * allocation failure.
 -*/
static int set_option_int(char const *filename, int line, OPTION *option, char const *p)
{
	int *iptr;
	int val;

	if (p == NULL) {
		rc_log(LOG_ERR, "%s: line %d: bogus option value", filename, line);
		return -1;
	}

	val = atoi(p);

	if (strcmp(option->name, "watchdog-interval") == 0 && val >= 1 && val <= 5) {
		rc_log(LOG_ERR, "%s: line %d: watchdog-interval must be 0 (disabled) "
				"or at least 6 seconds, not %d", filename, line, val);
		return -1;
	}

	if ((iptr = malloc(sizeof(*iptr))) == NULL) {
		rc_log(LOG_CRIT, "read_config: out of memory");
		return -1;
	}

	*iptr = val;
	option->val = (void *) iptr;

	return 0;
}

/* Shared by set_option_srv()'s parse-failure cleanup and
 * radcli2_priv_config_free(), which both need to release the same
 * per-entry allocations. */
/*- Free serv->name[i]/secret[i] for i in [from, to), nulling each
 * pointer afterwards.
 *
 * @param serv the server list to free entries from.
 * @param from the first index to free.
 * @param to one past the last index to free.
 -*/
static void server_free_entries(SERVER *serv, unsigned from, unsigned to)
{
	unsigned i;

	for (i = from; i < to; i++) {
		free(serv->name[i]);
		free(serv->secret[i]);
		serv->name[i] = NULL;
		serv->secret[i] = NULL;
	}
}

/*- Parse and append server-list entries onto a server-typed option,
 * accepting a comma-separated "host[:port[:secret]]" list.
 *
 * @param rh a handle to parsed configuration.
 * @param filename the name of the config file (for logging purposes).
 * @param line the line number in the file (for logging purposes).
 * @param option the RADCLI_OPT_TYPE_SRV option to append entries to.
 * @param p the comma-separated server list text.
 * @return 0 on success, -1 on a parse error or allocation failure.
 -*/
static int set_option_srv(rc_handle *rh, char const *filename, int line, OPTION *option, char const *p)
{
	SERVER *serv;
	char *p_pointer;
	char *p_dupe;
	char *p_save;
	char *q;
	char *s;
	struct servent *svp;
	unsigned start_max;

	p_dupe = strdup(p);

	if (p_dupe == NULL) {
		rc_log(LOG_ERR, "%s: line %d: Invalid option or memory failure", filename, line);
		return -1;
	}

	serv = (SERVER *) option->val;
	if (serv == NULL) {
		serv = calloc(1, sizeof(*serv));
		if (serv == NULL) {
			rc_log(LOG_CRIT, "read_config: out of memory");
			free(p_dupe);
			return -1;
		}
		serv->max = 0;
	}
	start_max = serv->max;

	p_pointer = strtok_r(p_dupe, ", \t", &p_save);

        while(p_pointer != NULL) {
                if (serv->max >= RC_SERVER_MAX) {
                        DEBUG(rh, LOG_ERR, "cannot set more than %d servers", RC_SERVER_MAX);
                        goto fail;
                }

		DEBUG(rh, LOG_ERR, "processing server: %s", p_pointer);
                /* check to see for '[IPv6]:port' syntax */
                if ((q = strchr(p_pointer,'[')) != NULL) {
                        *q = '\0';
                        q++;
                        p_pointer = q;

                        q = strchr(p_pointer, ']');
                        if (q == NULL) {
                                rc_log(LOG_CRIT, "read_config: IPv6 parse error");
                                goto fail;
                        }
                        *q = '\0';
                        q++;

                        if (q[0] == ':') {
                                q++;
                        }

                        /* Check to see if we have '[IPv6]:port:secret' syntax */
                        if((s=strchr(q, ':')) != NULL) {
                                *s = '\0';
                                s++;
                                serv->secret[serv->max] = strdup(s);
                                if (serv->secret[serv->max] == NULL) {
                                        rc_log(LOG_CRIT, "read_config: out of memory");
                                        goto fail;
                                }
                        }

                } else /* Check to see if we have 'servername:port' syntax */
                        if ((q = strchr(p_pointer,':')) != NULL) {
                                *q = '\0';
                                q++;

                                /* Check to see if we have 'servername:port:secret' syntax */
                                if((s = strchr(q,':')) != NULL) {
                                        *s = '\0';
                                        s++;
                                        serv->secret[serv->max] = strdup(s);
                                        if (serv->secret[serv->max] == NULL) {
                                                rc_log(LOG_CRIT, "read_config: out of memory");
                                                goto fail;
                                        }
                                }
                        }

                if(q && strlen(q) > 0) {
                        serv->port[serv->max] = atoi(q);
                } else {
                        if (!strcmp(option->name,"authserver"))
                                if ((svp = getservbyname ("radius", "udp")) == NULL)
                                        serv->port[serv->max] = PW_AUTH_UDP_PORT;
                                else
                                        serv->port[serv->max] = ntohs ((unsigned int) svp->s_port);
                        else if (!strcmp(option->name, "acctserver"))
                                if ((svp = getservbyname ("radacct", "udp")) == NULL)
                                        serv->port[serv->max] = PW_ACCT_UDP_PORT;
                                else
                                        serv->port[serv->max] = ntohs ((unsigned int) svp->s_port);
                        else {
                                rc_log(LOG_ERR, "%s: line %d: no default port for %s", filename, line, option->name);
                                goto fail;
                        }
                }

                serv->name[serv->max] = strdup(p_pointer);
                if (serv->name[serv->max] == NULL) {
                        rc_log(LOG_CRIT, "read_config: out of memory");
                        goto fail;
                }

                serv->max++;
                p_pointer = strtok_r(NULL, ", \t", &p_save);
        }

        free(p_dupe);
	if (option->val == NULL)
		option->val = (void *)serv;

	return 0;
 fail:
        free(p_dupe);
        /* Release whatever this call already committed (start_max..max),
         * plus the in-progress entry's secret if it was parsed before the
         * failure (name[] is only ever set last, right before max++, so
         * it never needs freeing here). Without this, a config line that
         * fails partway through (e.g. more than RC_SERVER_MAX servers)
         * leaks every entry already parsed. */
        server_free_entries(serv, start_max, serv->max);
        serv->max = start_max;
        if (serv->max < RC_SERVER_MAX) {
                free(serv->secret[serv->max]);
                serv->secret[serv->max] = NULL;
        }
        if (option->val == NULL)
	        free(serv);
        return -1;

}

/*- Add a config option to rc_handle from inside a program, letting a
 * program set up a handle without loading a configuration file.
 *
 * @param rh a handle to parsed configuration.
 * @param option_name the name of the option.
 * @param option_val the value to be added.
 * @param source typically should be __FILE__ or __func__ for logging purposes.
 * @param line __LINE__ for logging purposes.
 * @return 0 on success, -1 on failure.
 -*/
int radcli2_priv_add_config(rc_handle *rh, char const *option_name, char const *option_val, char const *source, int line)
{
	OPTION *option;

	if ((option = find_option(rh, option_name, OT_ANY)) == NULL)
	{
		if (rc_ignored_option(option_name))
			return 0;
		rc_log(LOG_ERR, "ERROR: unrecognized option: %s", option_name);
		return -1;
	}

	if (option->status != ST_UNDEF)
	{
		rc_log(LOG_ERR, "ERROR: duplicate option: %s", option_name);
		return -1;
	}

	switch (option->type) {
		case RADCLI_OPT_TYPE_STR:
			if (set_option_str(source, line, option, option_val) < 0) {
				return -1;
			}
			break;
		case RADCLI_OPT_TYPE_INT:
			if (set_option_int(source, line, option, option_val) < 0) {
				return -1;
			}
			break;
		case RADCLI_OPT_TYPE_SRV:
			if (set_option_srv(rh, source, line, option, option_val) < 0) {
				return -1;
			}
			break;
		default:
			rc_log(LOG_CRIT, "radcli2_priv_add_config: impossible case branch!");
			abort();
	}

	return 0;
}

/*- Initialise a configuration structure for programmatic configuration.
 *
 * Use this when configuring radcli from code rather than from a file. The
 * full call sequence: radcli2_priv_new(), this function,
 * radcli2_priv_add_config() per option, then radcli2_priv_apply_config()
 * to activate.
 *
 * @param rh a handle allocated by radcli2_priv_new().
 * @return rh on success, NULL on failure (rh is freed on failure).
 -*/
rc_handle *radcli2_priv_config_init(rc_handle *rh)
{
	SERVER *authservers = NULL;
	SERVER *acctservers;
	OPTION *acct;
	OPTION *auth;

        rh->config_options = malloc(sizeof(config_options_default));
        if (rh->config_options == NULL)
	{
                rc_log(LOG_CRIT, "radcli2_priv_config_init: out of memory");
		radcli2_priv_destroy(rh);
                return NULL;
        }
        memcpy(rh->config_options, &config_options_default, sizeof(config_options_default));

	auth = find_option(rh, "authserver", OT_ANY);
	if (auth) {
		authservers = calloc(1, sizeof(SERVER));
		if(authservers == NULL) {
	                rc_log(LOG_CRIT, "radcli2_priv_config_init: error initializing server structs");
			radcli2_priv_destroy(rh);
	                return NULL;
		}
		auth->val = authservers;
	}

	acct = find_option(rh, "acctserver", OT_ANY);
	if (acct) {
		acctservers = calloc(1, sizeof(SERVER));
		if(acctservers == NULL) {
	                rc_log(LOG_CRIT, "radcli2_priv_config_init: error initializing server structs");
			radcli2_priv_destroy(rh);
			if(authservers) free(authservers);
	                return NULL;
		}
		acct->val = acctservers;
	}

	return rh;
}

/*- rc_sockets_override.sendto for the plain UDP transport: a thin
 * sendto(2) wrapper.
 -*/
static ssize_t plain_sendto(void *ptr, int sockfd,
			    const void *buf, size_t len, int flags,
			    const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

/*- rc_sockets_override.sendto for the plain TCP transport: connect(2)
 * then sendto(2).
 -*/
static ssize_t plain_tcp_sendto(void *ptr, int sockfd,
			    const void *buf, size_t len, int flags,
			    const struct sockaddr *dest_addr, socklen_t addrlen)
{
	if((connect(sockfd, dest_addr, addrlen)) != 0){
		rc_log(LOG_ERR, "%s: Connect Call Failed : %s", __FUNCTION__, strerror(errno));
		return -1;
	}
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

/*- rc_sockets_override.recvfrom for the plain UDP/TCP transports: a thin
 * recvfrom(2) wrapper.
 -*/
static ssize_t plain_recvfrom(void *ptr, int sockfd,
			      void *buf, size_t len, int flags,
			      struct sockaddr *src_addr, socklen_t * addrlen)
{
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

/*- rc_sockets_override.close_fd for the plain UDP/TCP transports: a thin
 * close(2) wrapper.
 -*/
static void plain_close_fd(int fd)
{
	close(fd);
}

/*- rc_sockets_override.get_fd for the plain UDP transport: open and bind
 * a UDP socket at an ephemeral port on our_sockaddr's address/family.
 *
 * @param ptr unused; part of the get_fd calling convention.
 * @param our_sockaddr the local address to bind to (port overwritten with 0).
 * @return the new socket, or -1 on failure.
 -*/
static int plain_get_fd(void *ptr, struct sockaddr *our_sockaddr)
{
	int sockfd;

	sockfd = socket(our_sockaddr->sa_family, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		return -1;
	}

	if (our_sockaddr->sa_family == AF_INET)
		((struct sockaddr_in *)our_sockaddr)->sin_port = 0;
	else
		((struct sockaddr_in6 *)our_sockaddr)->sin6_port = 0;

	if (bind(sockfd, SA(our_sockaddr), SA_LEN(our_sockaddr)) < 0) {
		close(sockfd);
		return -1;
	}
	return sockfd;
}

/*- rc_sockets_override.get_fd for the plain TCP transport: open and bind
 * a TCP socket at an ephemeral port on our_sockaddr's address/family.
 *
 * @param ptr unused; part of the get_fd calling convention.
 * @param our_sockaddr the local address to bind to (port overwritten with 0).
 * @return the new socket, or -1 on failure.
 -*/
static int plain_tcp_get_fd(void *ptr, struct sockaddr *our_sockaddr)
{
	int sockfd;

	sockfd = socket(our_sockaddr->sa_family, SOCK_STREAM, 0);
	if (sockfd < 0) {
		return -1;
	}

	if (our_sockaddr->sa_family == AF_INET)
		((struct sockaddr_in *)our_sockaddr)->sin_port = 0;
	else
		((struct sockaddr_in6 *)our_sockaddr)->sin6_port = 0;

	if (bind(sockfd, SA(our_sockaddr), SA_LEN(our_sockaddr)) < 0) {
		close(sockfd);
		return -1;
	}
	return sockfd;
}

static const rc_sockets_override default_socket_funcs = {
	.get_fd = plain_get_fd,
	.close_fd = plain_close_fd,
	.sendto = plain_sendto,
	.recvfrom = plain_recvfrom
};

static const rc_sockets_override default_tcp_socket_funcs = {
	.get_fd = plain_tcp_get_fd,
	.close_fd = plain_close_fd,
	.sendto = plain_tcp_sendto,
	.recvfrom = plain_recvfrom
};

/*- Parse ip (IPv4 or IPv6 text) into ss.
 *
 * @param ss set to the parsed address on success.
 * @param ip the address text to parse.
 * @return 0 on success, -1 if ip is neither a valid IPv4 nor IPv6 address.
 -*/
static int set_addr(struct sockaddr_storage *ss, const char *ip)
{
	memset(ss, 0, sizeof(*ss));
	if (inet_pton(AF_INET, ip, &((struct sockaddr_in *)ss)->sin_addr) == 1) {
		ss->ss_family = AF_INET;
	} else if (inet_pton(AF_INET6, ip, &((struct sockaddr_in6 *)ss)->sin6_addr) == 1) {
		ss->ss_family = AF_INET6;
	} else {
		rc_log(LOG_CRIT, "invalid IP address for nas-ip: %s", ip);
		return -1;
	}
	return 0;
}

/* Fills in an authserver/acctserver SERVER's secret[0] from the "secret"
 * option, but only when that entry has no secret of its own yet -- an
 * inline host:port:secret (or a legacy "servers" file entry, resolved
 * later at send time) always takes priority. This is the config-file
 * counterpart of radcli2.h's radcli_ctx_set_secret(), which instead
 * overwrites secret[0] unconditionally on an explicit call.
 *
 * Harmless but pointless under TLS/DTLS: radcli2_priv_find_server_addr()
 * doesn't need secret[0] there in the first place (rh->so_type ==
 * RC_SOCKET_TLS/_DTLS branch), and radcli_transport_exchange()
 * (lib/sendserver.c) overwrites it with the RFC 6614/7360 fixed secret
 * before it would ever be used regardless. */
/*- Fill in optname's first server entry's secret from the "secret"
 * option, but only when that entry has no secret of its own yet.
 *
 * @param rh a handle to parsed configuration.
 * @param optname "authserver" or "acctserver".
 * @param secret the fallback secret to apply.
 -*/
static void apply_secret_fallback_one(rc_handle *rh, const char *optname, const char *secret)
{
	SERVER *serv = radcli2_priv_conf_srv(rh, optname);
	char *dup;

	if (serv == NULL || serv->max == 0)
		return;
	if (serv->secret[0] != NULL && serv->secret[0][0] != '\0')
		return;

	dup = strdup(secret);
	if (dup == NULL)
		return;

	free(serv->secret[0]);
	serv->secret[0] = dup;
}

/*- Apply the "secret" option as a fallback to authserver/acctserver's
 * first entry, when they don't already carry their own secret.
 *
 * @param rh a handle to parsed configuration.
 -*/
static void apply_secret_fallback(rc_handle *rh)
{
	const char *secret = rc_conf_str_id(rh, OPT_SECRET);

	if (secret == NULL || secret[0] == '\0')
		return;

	apply_secret_fallback_one(rh, "authserver", secret);
	apply_secret_fallback_one(rh, "acctserver", secret);
}

/*- Materialize optname's default into rh's config table if it was never
 * explicitly set, so every internal reader can use the default-free,
 * compile-time-indexed rc_conf_int_id() uniformly afterward (REQ-GEN-STYLE-011)
 * instead of a runtime string-keyed lookup with an inline default.
 *
 * @param rh a handle to parsed configuration.
 * @param optname the option's name.
 * @param def the default to materialize if unset.
 -*/
static void apply_int_default(rc_handle *rh, char const *optname, int def)
{
	OPTION *option = find_option(rh, optname, RADCLI_OPT_TYPE_INT);
	int *val;

	if (option == NULL || option->val != NULL)
		return;

	val = malloc(sizeof(*val));
	if (val == NULL)
		return;

	*val = def;
	option->val = val;
}

/*- Apply configuration and initialise the transport.
 *
 * Must be called after all radcli2_priv_add_config() calls when using
 * programmatic configuration (i.e., without a config file). Initialises
 * the transport selected by the serv-type option, including the TLS/DTLS
 * handshake for TLS and DTLS transports. radcli2_priv_read_config() calls
 * this internally; do not call it again after radcli2_priv_read_config().
 *
 * @param rh a handle to parsed configuration.
 * @return 0 on success, -1 on failure.
 -*/
int radcli2_priv_apply_config(rc_handle *rh)
{
	const char *txt;
	int ret;

	apply_secret_fallback(rh);
	apply_int_default(rh, "watchdog-interval", 15);
	apply_int_default(rh, "dae-max-clock-skew", 300);

	memset(&rh->own_bind_addr, 0, sizeof(rh->own_bind_addr));
	rh->own_bind_addr_set = 0;
	rc_own_bind_addr(rh, &rh->own_bind_addr);
	rh->own_bind_addr_set = 1;

	txt = rc_conf_str_id(rh, OPT_NAS_IP);
	if (txt != NULL) {
		if (set_addr(&rh->nas_addr, txt) < 0)
			return -1;
		rh->nas_addr_set = 1;
	}

	txt = rc_conf_str_id(rh, OPT_SERV_TYPE);
	if (txt == NULL)
		txt = rc_conf_str_id(rh, OPT_SERV_AUTH_TYPE);

	if (txt == NULL)
		txt = "udp";

	if (strcasecmp(txt, "udp") == 0) {
		memset(&rh->so, 0, sizeof(rh->so));
		rh->so_type = RC_SOCKET_UDP;
		memcpy(&rh->so, &default_socket_funcs, sizeof(rh->so));
		ret = 0;
	} else if (strcasecmp(txt, "tcp") == 0) {
		memset(&rh->so, 0, sizeof(rh->so));
		rh->so_type = RC_SOCKET_TCP;
		memcpy(&rh->so, &default_tcp_socket_funcs, sizeof(rh->so));
		ret = 0;
#ifdef HAVE_GNUTLS
	} else if (strcasecmp(txt, "dtls") == 0) {
		ret = rc_init_tls(rh, SEC_FLAG_DTLS);
	} else if (strcasecmp(txt, "tls") == 0) {
		ret = rc_init_tls(rh, 0);
#endif
	} else {
		rc_log(LOG_CRIT, "unknown server type: %s", txt);
		return -1;
	}

	if (ret < 0) {
		rc_log(LOG_CRIT, "error initializing %s", txt);
		return -1;
	}

	return 0;

}

/*- Load the built-in RFC 2865/2866/2869 dictionary into rh. Shared by
 * radcli2_priv_read_config() and radcli_ctx_new() (lib/config2.c) so both
 * entry points agree on what "the built-in dictionary" is.
 *
 * @param rh a handle allocated by radcli2_priv_new().
 * @return 0 on success, -1 on failure (rh is left as-is; the caller is
 *  responsible for destroying it).
 -*/
int radcli2_priv_load_builtin_dict(rc_handle *rh)
{
	if (radcli2_priv_read_dictionary_from_buffer(rh, rc_rfc_dictionary,
	                                   sizeof(rc_rfc_dictionary) - 1) != 0) {
		rc_log(LOG_CRIT, "radcli2_priv_load_builtin_dict: failed to load built-in RFC dictionary");
		return -1;
	}
	return 0;
}

/*- Read the global config file. The full recognised-option reference lives
 * on the public rc_read_config()'s doc comment (lib/legacy/compat.c),
 * which this implements.
 *
 * @param filename path to the configuration file.
 * @param skip_builtin_dict nonzero to skip loading the built-in RFC
 *  2865/2866/2869 dictionary (radcli_ctx_read_config()'s
 *  #RADCLI_CTX_NO_BUILTIN_DICT, translated by lib/config2.c so this
 *  legacy-shared function need not know about radcli2.h's flags enum).
 * @return new rc_handle on success, NULL on failure.
 -*/
rc_handle *radcli2_priv_read_config(char const *filename, int skip_builtin_dict)
{
	FILE *configfd;
	char *buffer = NULL, *p;
	size_t bufsize = 0;
	ssize_t nread;
	OPTION *option;
	int line;
	size_t pos;
	rc_handle *rh;


	rh = radcli2_priv_new();
	if (rh == NULL)
		return NULL;

        rh->config_options = malloc(sizeof(config_options_default));
        if (rh->config_options == NULL) {
                rc_log(LOG_CRIT, "radcli2_priv_read_config: out of memory");
		radcli2_priv_destroy(rh);
                return NULL;
        }
        memcpy(rh->config_options, &config_options_default, sizeof(config_options_default));

	if ((configfd = fopen(filename,"r")) == NULL)
	{
		rc_log(LOG_ERR,"radcli2_priv_read_config: can't open %s: %s", filename, strerror(errno));
		radcli2_priv_destroy(rh);
		return NULL;
	}

	line = 0;
	while ((nread = getline(&buffer, &bufsize, configfd)) != -1)
	{
		line++;

		if (nread > 0 && buffer[nread-1] == '\n')
			buffer[--nread] = '\0';

		p = buffer;

		if ((*p == '#') || (*p == '\0'))
			continue;

		if ((pos = strcspn(p, "\t ")) == 0) {
			rc_log(LOG_ERR, "%s: line %d: bogus format: %s", filename, line, p);
			goto error;
		}

		p[pos] = '\0';

		if ((option = find_option(rh, p, OT_ANY)) == NULL) {
			if (rc_ignored_option(p)) {
				rc_log(LOG_INFO, "%s: line %d: option '%s' is no longer used, ignoring", filename, line, p);
				continue;
			}
			rc_log(LOG_ERR, "%s: line %d: unrecognized keyword: %s", filename, line, p);
			goto error;
		}

		if (option->status != ST_UNDEF) {
			rc_log(LOG_ERR, "%s: line %d: duplicate option line: %s", filename, line, p);
			goto error;
		}

		p += pos+1;
		while (isspace(*p))
			p++;
		if (*p != '\0') {
			pos = strlen(p) - 1;
			while (pos != 0 && isspace(p[pos]))
				pos--;
			p[pos + 1] = '\0';
		}

		switch (option->type) {
			case RADCLI_OPT_TYPE_STR:
				if (set_option_str(filename, line, option, p) < 0)
					goto error;
				break;
			case RADCLI_OPT_TYPE_INT:
				if (set_option_int(filename, line, option, p) < 0)
					goto error;
				break;
			case RADCLI_OPT_TYPE_SRV:
				if (set_option_srv(rh, filename, line, option, p) < 0)
					goto error;
				break;
			default:
				rc_log(LOG_CRIT, "radcli2_priv_read_config: impossible case branch!");
				abort();
		}
	}
	free(buffer);
	fclose(configfd);

	if (radcli2_priv_test_config(rh, filename) == -1) {
		radcli2_priv_destroy(rh);
		return NULL;
	}

        {
                int clientdebug = rc_conf_int_2(rh, "clientdebug", FALSE);
                if(clientdebug > 0) {
                        rh->debug = clientdebug;
                }
        }

	/* Load the built-in RFC 2865/2866/2869 dictionary first so that
	 * applications need not ship a dictionary file for standard attributes,
	 * unless the caller asked to skip it. */
	if (!skip_builtin_dict && radcli2_priv_load_builtin_dict(rh) != 0) {
		radcli2_priv_destroy(rh);
		return NULL;
	}

	p = rc_conf_str_id(rh, OPT_DICTIONARY);
	if (p != NULL) {
		if (radcli2_priv_read_dictionary(rh, p) != 0) {
			rc_log(LOG_CRIT, "could not load dictionary");
			radcli2_priv_destroy(rh);
			return NULL;
		}
	}

	return rh;

error:
	free(buffer);
	fclose(configfd);
	radcli2_priv_destroy(rh);
	return NULL;
}

/*- Get the value of a string-typed config option.
 *
 * @param rh a handle to parsed configuration.
 * @param optname the name of an option.
 * @return config option value.
 -*/
char *radcli2_priv_conf_str(rc_handle const *rh, char const *optname)
{
	OPTION *option;

	option = find_option(rh, optname, RADCLI_OPT_TYPE_STR);

	if (option != NULL) {
		return (char *)option->val;
	} else {
		rc_log(LOG_CRIT, "radcli2_priv_conf_str: unknown config option requested: %s", optname);
		return NULL;
	}
}

/*- Get the value of an integer-typed config option, optionally logging
 * when it was never set.
 *
 * @param rh a handle to parsed configuration.
 * @param optname the name of an option.
 * @param complain nonzero to log an error when optname was not set.
 * @return config option value, or 0 if not found, not an integer, or unset.
 -*/
static int rc_conf_int_2(rc_handle const *rh, char const *optname, int complain)
{
	OPTION *option;

	option = find_option(rh, optname, RADCLI_OPT_TYPE_INT);

	if (option != NULL) {
		if (option->val) {
			return *((int *)option->val);
		} else if(complain) {
			rc_log(LOG_ERR, "radcli2_priv_conf_int: config option %s was not set", optname);
		}
                return 0;
	} else {
		rc_log(LOG_CRIT, "radcli2_priv_conf_int: unknown config option requested: %s", optname);
		return 0;
	}
}

/*- Get the value of an integer-typed config option.
 *
 * @param rh a handle to parsed configuration.
 * @param optname the name of an option.
 * @return config option value, or 0 if not found or not an integer.
 -*/
int radcli2_priv_conf_int(rc_handle const *rh, char const *optname)
{
        return rc_conf_int_2(rh, optname, TRUE);
}

/*- Get the value of a server-list-typed config option.
 *
 * @param rh a handle to parsed configuration.
 * @param optname the name of an option.
 * @return config option value.
 -*/
SERVER *radcli2_priv_conf_srv(rc_handle const *rh, char const *optname)
{
	OPTION *option;

	option = find_option(rh, optname, RADCLI_OPT_TYPE_SRV);

	if (option != NULL) {
		return (SERVER *)option->val;
	} else {
		rc_log(LOG_CRIT, "radcli2_priv_conf_srv: unknown config option requested: %s", optname);
		return NULL;
	}
}

/*- Test the configuration the user supplied.
 *
 * @param rh a handle to parsed configuration.
 * @param filename a name of a configuration file.
 * @return 0 on success, -1 when failure.
 -*/
int radcli2_priv_test_config(rc_handle *rh, char const *filename)
{
	SERVER *srv;

	srv = radcli2_priv_conf_srv(rh, "authserver");
	if (!srv || !srv->max)
	{
		rc_log(LOG_ERR,"%s: no authserver specified", filename);
		return -1;
	}

	srv = radcli2_priv_conf_srv(rh, "acctserver");
	if (!srv || !srv->max)
	{
		/* it is allowed not to have acct servers under TLS/DTLS. rh->so_type
		 * isn't set until radcli2_priv_apply_config() below, so check the configured
		 * serv-type string directly rather than the not-yet-initialized
		 * transport state. */
		const char *stype = rc_conf_str_id(rh, OPT_SERV_TYPE);
		if (stype == NULL)
			stype = rc_conf_str_id(rh, OPT_SERV_AUTH_TYPE);
		if (stype == NULL ||
		    (strcasecmp(stype, "tls") != 0 && strcasecmp(stype, "dtls") != 0))
			rc_log(LOG_DEBUG,"%s: no acctserver specified", filename);
	}

	if (rc_conf_int_id(rh, OPT_RADIUS_TIMEOUT) <= 0)
	{
		rc_log(LOG_ERR,"%s: radius_timeout <= 0 is illegal", filename);
		return -1;
	}
	if (rc_conf_int_id(rh, OPT_RADIUS_RETRIES) <= 0)
	{
		rc_log(LOG_ERR,"%s: radius_retries <= 0 is illegal", filename);
		return -1;
	}

	if (radcli2_priv_apply_config(rh) == -1) {
		return -1;
	}

	return 0;
}

/*- Report whether any address in addr matches any address in hostname.
 *
 * @param addr a struct addrinfo chain.
 * @param hostname a struct addrinfo chain to compare against.
 * @return 0 if a match is found, -1 otherwise.
 -*/
static int find_match (const struct addrinfo* addr, const struct addrinfo *hostname)
{
	const struct addrinfo *ptr, *ptr2;
	unsigned len1, len2;

	ptr = addr;
	while(ptr) {
		ptr2 = hostname;
		while(ptr2) {
			len1 = SA_GET_INLEN(ptr->ai_addr);
			len2 = SA_GET_INLEN(ptr2->ai_addr);

			if (len1 > 0 &&
			    len1 == len2 &&
			    memcmp(SA_GET_INADDR(ptr->ai_addr), SA_GET_INADDR(ptr2->ai_addr), len1) == 0) {
				return 0;
			}
			ptr2 = ptr2->ai_next;
 		}
		ptr = ptr->ai_next;
 	}
 	return -1;
}

/*- Report whether addr is a local address, by attempting to bind it.
 *
 * @param addr an AF_INET or AF_INET6 address.
 * @return 0 if local, 1 if not local, -1 on failure.
 -*/
static int rc_ipaddr_local(const struct sockaddr *addr)
{
	int temp_sock, res, serrno;
	struct sockaddr_storage tmpaddr;

	memcpy(&tmpaddr, addr, SA_LEN(addr));

	temp_sock = socket(addr->sa_family, SOCK_DGRAM, 0);
	if (temp_sock == -1)
		return -1;

	if (addr->sa_family == AF_INET) {
		((struct sockaddr_in*)&tmpaddr)->sin_port = 0;
	} else {
		((struct sockaddr_in6*)&tmpaddr)->sin6_port = 0;
	}
	res = bind(temp_sock, SA(&tmpaddr), SS_LEN(&tmpaddr));
	serrno = errno;
	close(temp_sock);
	if (res == 0)
		return 0;
	if (serrno == EADDRNOTAVAIL)
		return 1;
	return -1;
}

/*- Report whether info refers to one of our own local addresses.
 *
 * @param info a struct addrinfo chain of the host to check.
 * @return 0 if yes, 1 if no, -1 on failure.
 -*/
static int rc_is_myname(const struct addrinfo *info)
{
	const struct addrinfo *p;
	int	res;

	p = info;
	while(p != NULL) {
		res = rc_ipaddr_local(p->ai_addr);
		if (res == 0 || res == -1) {
 			return res;
		}
		p = p->ai_next;
 	}
 	return 1;
}

/*- Locate a server in the rh config or, if not found, check for a
 * servers file.
 *
 * @param rh a handle to parsed configuration.
 * @param server_name the name of the server.
 * @param info set to a pointer to the resolved addrinfo.
 * @param secret set to the server's secret (buffer of MAX_SECRET_LENGTH).
 * @param type AUTH or ACCT.
 * @return 0 on success, -1 on failure.
 -*/
int radcli2_priv_find_server_addr (rc_handle const *rh, char const *server_name,
                         struct addrinfo** info, char *secret, rc_type type)
{
	int             result = 0;
	FILE           *clientfd;
	char           *h;
	char           *s;
	char           *buffer = NULL;
	size_t          bufsize = 0;
	char            hostnm[AUTH_ID_LEN + 1];
	char	       *buffer_save;
	char	       *hostnm_save;
	SERVER	       *servers;
	struct addrinfo *tmpinfo = NULL;
	const char      *fservers;
	char const      *optname;

	/* Lookup the IP address of the radius server */
	if ((*info = rc_getaddrinfo (server_name, type==AUTH?PW_AI_AUTH:PW_AI_ACCT)) == NULL)
		return -1;

	switch (type)
	{
	case AUTH: optname = "authserver"; break;
	case ACCT: optname = "acctserver"; break;
	default:   optname = NULL;
	}

	if ( (optname != NULL) &&
	     ((servers = radcli2_priv_conf_srv(rh, optname)) != NULL) )
	{
		/* Check to see if the server secret is defined in the rh config */
		unsigned  servernum;
		for (servernum = 0; servernum < servers->max; servernum++)
		{
			if( (strcmp(server_name, servers->name[servernum]) == 0) &&
				(servers->secret[servernum] != NULL) )
			{
				memset(secret, '\0', MAX_SECRET_LENGTH);
				strlcpy(secret, servers->secret[servernum], MAX_SECRET_LENGTH);
				return 0;
			}
		}
	}

	/* We didn't find it in the rh_config or the servername is too long so look for a
	 * servers file to define the secret(s)
	 */

	fservers = rc_conf_str_id(rh, OPT_SERVERS);
	if (fservers != NULL) {
		if ((clientfd = fopen (fservers, "r")) == NULL)
		{
			rc_log(LOG_ERR, "rc_find_server: couldn't open file: %s: %s", strerror(errno), fservers);
			goto fail;
		}

		while (getline (&buffer, &bufsize, clientfd) != -1)
		{
			if (*buffer == '#')
				continue;

			if ((h = strtok_r(buffer, " \t\n", &buffer_save)) == NULL) /* first hostname */
				continue;

			strlcpy (hostnm, h, AUTH_ID_LEN);

			if ((s = strtok_r (NULL, " \t\n", &buffer_save)) == NULL) /* and secret field */
				continue;

			strlcpy (secret, s, MAX_SECRET_LENGTH);

			if (!strchr (hostnm, '/')) /* If single name form */
			{
				tmpinfo = rc_getaddrinfo(hostnm, 0);
				if (tmpinfo)
				{
					result = find_match (*info, tmpinfo);
					if (result == 0)
					{
						result++;
						break;
					}

					freeaddrinfo(tmpinfo);
					tmpinfo = NULL;
				}
			}
			else /* <name1>/<name2> "paired" form */
			{
				strtok_r(hostnm, "/", &hostnm_save);
				tmpinfo = rc_getaddrinfo(hostnm, 0);
				if (tmpinfo)
 				{
					if (rc_is_myname(tmpinfo) == 0)
					{	     /* If we're the 1st name, target is 2nd */
						if (find_match (*info, tmpinfo) == 0)
						{
							result++;
							break;
						}
					}
					else	/* If we were 2nd name, target is 1st name */
 					{
						if (find_match (*info, tmpinfo) == 0)
						{
							result++;
							break;
						}
 					}
					freeaddrinfo(tmpinfo);
					tmpinfo = NULL;
 				}
			}
		}
		fclose (clientfd);
	}
	if (result == 0)
	{
		/* Under TLS/DTLS, this function's whole secret-lookup half (the
		 * server's :secret suffix, or a legacy "servers" file) is moot:
		 * radcli_transport_exchange() (lib/sendserver.c) unconditionally
		 * overwrites whatever secret is returned here with the RFC 6614/
		 * 7360 fixed string (rh->so.static_secret) immediately after
		 * calling this function, since the shared secret for that
		 * transport is a protocol constant, not something an operator
		 * configures per server. Requiring a real secret to be found
		 * here anyway made every ordinary request over a TLS/DTLS
		 * authserver configured the normal way (no inline :secret, since
		 * none is needed) fail outright before ever reaching that
		 * override -- the address above was already resolved
		 * successfully, which is all this transport actually needs from
		 * this function. */
		if (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS) {
			memset(secret, '\0', MAX_SECRET_LENGTH);
			result = 0;
			goto cleanup;
		}
		memset (secret, '\0', MAX_SECRET_LENGTH);
		rc_log(LOG_ERR, "rc_find_server: couldn't find RADIUS server %s in %s",
			 server_name, rc_conf_str_id(rh, OPT_SERVERS));
		goto fail;
	}

	result = 0;
	goto cleanup;

 fail:
 	freeaddrinfo(*info);
 	result = -1;

 cleanup:
 	if (tmpinfo)
 		freeaddrinfo(tmpinfo);
	free(buffer);

	return result;
}

/*- Free allocated config values. For legacy compatibility reasons this
 * will not release any dictionary entries -- use radcli2_priv_destroy()
 * to release all memory from the handle.
 *
 * @param rh a handle to parsed configuration.
 -*/
void radcli2_priv_config_free(rc_handle *rh)
{
	int i;
	SERVER *serv;

	if (rh->config_options == NULL)
		return;

	for (i = 0; i < NUM_OPTIONS; i++) {
		if (rh->config_options[i].val == NULL)
			continue;
		if (rh->config_options[i].type == RADCLI_OPT_TYPE_SRV) {
			serv = (SERVER *)rh->config_options[i].val;
			server_free_entries(serv, 0, serv->max);
			free(serv);
		} else {
			free(rh->config_options[i].val);
		}
	}
	free(rh->config_options);
	free(rh->first_dict_read);
	rh->config_options = NULL;
	rh->first_dict_read = NULL;
}

static int _initialized = 0;

/*- Initialise a new Radius client handle.
 *
 * @return a new rc_handle (free with radcli2_priv_destroy()), or NULL on
 * allocation failure.
 -*/
rc_handle *radcli2_priv_new(void)
{
	rc_handle *rh;

	if (_initialized == 0) {
#if defined(HAVE_GNUTLS) && GNUTLS_VERSION_NUMBER < 0x030300
		int ret;
		ret = gnutls_global_init();
		if (ret < 0) {
			rc_log(LOG_ERR,
			       "%s: error initializing gnutls: %s",
			       __func__, gnutls_strerror(ret));
			return NULL;
		}
#endif
	}
	_initialized++;

	rh = calloc(1, sizeof(*rh));
	if (rh == NULL) {
                rc_log(LOG_CRIT, "radcli2_priv_new: out of memory");
                return NULL;
        }
	return rh;
}

/*- Destroy a Radius client handle, reclaiming all memory.
 *
 * @param rh the handle to free.
 -*/
void radcli2_priv_destroy(rc_handle *rh)
{
	radcli2_priv_dict_free(rh);
#ifdef HAVE_GNUTLS
	rc_deinit_tls(rh);
#endif
	radcli2_priv_config_free(rh);
	free(rh->tls_psk_identity);
	free(rh->tls_psk_key);
	free(rh);

#if defined(HAVE_GNUTLS) && GNUTLS_VERSION_NUMBER < 0x030300
	_initialized--;
	if (_initialized == 0) {
		gnutls_global_deinit();
	}
#endif
}

 /*
 * Local Variables:
 * c-basic-offset:8
 * c-style: whitesmith
 * End:
 */
