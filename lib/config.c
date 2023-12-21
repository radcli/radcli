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
#include <radcli/radcli.h>
#include <options.h>
#include "util.h"
#include "tls.h"

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

static int rc_conf_int_2(rc_handle const *rh, char const *optname, int complain);

/** Find an option in the option list
 *
 * @param rh a handle to parsed configuration.
 * @param optname the name of the option.
 * @param type the option type.
 * @return pointer to option on success, NULL otherwise.
 */
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

/** Set a specific option doing type conversions
 *
 * @param filename the name of the config file (for logging purposes).
 * @param line the line number in the file.
 * @param option option to set.
 * @param p Value.
 * @return 0 on success, -1 on failure.
 */
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

static int set_option_int(char const *filename, int line, OPTION *option, char const *p)
{
	int *iptr;

	if (p == NULL) {
		rc_log(LOG_ERR, "%s: line %d: bogus option value", filename, line);
		return -1;
	}

	if ((iptr = malloc(sizeof(*iptr))) == NULL) {
		rc_log(LOG_CRIT, "read_config: out of memory");
		return -1;
	}

	*iptr = atoi(p);
	option->val = (void *) iptr;

	return 0;
}

static int set_option_srv(char const *filename, int line, OPTION *option, char const *p)
{
	SERVER *serv;
	char *p_pointer;
	char *p_dupe;
	char *p_save;
	char *q;
	char *s;
	struct servent *svp;

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

	p_pointer = strtok_r(p_dupe, ", \t", &p_save);

        while(p_pointer != NULL) {
                if (serv->max > RC_SERVER_MAX) {
                        DEBUG(LOG_ERR, "cannot set more than %d servers", RC_SERVER_MAX);
                        goto fail;
                }

		DEBUG(LOG_ERR, "processing server: %s", p_pointer);
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
        if (option->val == NULL)
	        free(serv);
        return -1;

}

static int set_option_auo(char const *filename, int line, OPTION *option, char const *p)
{
	int *iptr;
	char *p_dupe = NULL;
	char *p_pointer = NULL;
	char *p_save = NULL;

	p_dupe = strdup(p);

	if (p_dupe == NULL) {
		rc_log(LOG_WARNING, "%s: line %d: bogus option value", filename, line);
		return -1;
	}

	if ((iptr = malloc(sizeof(*iptr))) == NULL) {
			rc_log(LOG_CRIT, "read_config: out of memory");
			free(p_dupe);
			return -1;
	}

	*iptr = 0;
	p_pointer = strtok_r(p_dupe, ", \t", &p_save);

	if (!strncmp(p_pointer, "local", 5))
			*iptr = AUTH_LOCAL_FST;
	else if (!strncmp(p_pointer, "radius", 6))
			*iptr = AUTH_RADIUS_FST;
	else {
		rc_log(LOG_ERR,"%s: auth_order: unknown keyword: %s", filename, p);
		free(iptr);
		free(p_dupe);
		return -1;
	}

	p_pointer = strtok_r(NULL, ", \t", &p_save);

	if (p_pointer && (*p_pointer != '\0')) {
		if ((*iptr & AUTH_RADIUS_FST) && !strcmp(p_pointer, "local"))
			*iptr = (*iptr) | AUTH_LOCAL_SND;
		else if ((*iptr & AUTH_LOCAL_FST) && !strcmp(p_pointer, "radius"))
			*iptr = (*iptr) | AUTH_RADIUS_SND;
		else {
			rc_log(LOG_ERR,"%s: auth_order: unknown or unexpected keyword: %s", filename, p);
			free(iptr);
			free(p_dupe);
			return -1;
		}
	}

	option->val = (void *) iptr;

	free(p_dupe);
	return 0;
}

/** Allow a config option to be added to rc_handle from inside a program.
 *
 * That allows programs to setup a handle without loading a configuration
 * file.
 *
 * @param rh a handle to parsed configuration.
 * @param option_name the name of the option.
 * @param option_val the value to be added.
 * @param source typically should be __FILE__ or __func__ for logging purposes.
 * @param line __LINE__ for logging purposes.
 * @return 0 on success, -1 on failure.
 */
int rc_add_config(rc_handle *rh, char const *option_name, char const *option_val, char const *source, int line)
{
	OPTION *option;

	if ((option = find_option(rh, option_name, OT_ANY)) == NULL)
	{
		rc_log(LOG_ERR, "ERROR: unrecognized option: %s", option_name);
		return -1;
	}

	if (option->status != ST_UNDEF)
	{
		rc_log(LOG_ERR, "ERROR: duplicate option: %s", option_name);
		return -1;
	}

	switch (option->type) {
		case OT_STR:
			if (set_option_str(source, line, option, option_val) < 0) {
				return -1;
			}
			break;
		case OT_INT:
			if (set_option_int(source, line, option, option_val) < 0) {
				return -1;
			}
			break;
		case OT_SRV:
			if (set_option_srv(source, line, option, option_val) < 0) {
				return -1;
			}
			break;
		case OT_AUO:
			if (set_option_auo(source, line, option, option_val) < 0) {
				return -1;
			}
			break;
		default:
			rc_log(LOG_CRIT, "rc_add_config: impossible case branch!");
			abort();
	}

	return 0;
}

/** Initialise a configuration structure
 *
 * Initialize the configuration structure from an external program.  For use when not
 * running a standalone client that reads from a config file.
 *
 * The provided handled must have been allocated using rc_new().
 *
 * @param rh a handle to parsed configuration.
 * @return rc_handle on success, NULL on failure.
 */
rc_handle *rc_config_init(rc_handle *rh)
{
	SERVER *authservers = NULL;
	SERVER *acctservers;
	OPTION *acct;
	OPTION *auth;

        rh->config_options = malloc(sizeof(config_options_default));
        if (rh->config_options == NULL)
	{
                rc_log(LOG_CRIT, "rc_config_init: out of memory");
		rc_destroy(rh);
                return NULL;
        }
        memcpy(rh->config_options, &config_options_default, sizeof(config_options_default));

	auth = find_option(rh, "authserver", OT_ANY);
	if (auth) {
		authservers = calloc(1, sizeof(SERVER));
		if(authservers == NULL) {
	                rc_log(LOG_CRIT, "rc_config_init: error initializing server structs");
			rc_destroy(rh);
	                return NULL;
		}
		auth->val = authservers;
	}

	acct = find_option(rh, "acctserver", OT_ANY);
	if (acct) {
		acctservers = calloc(1, sizeof(SERVER));
		if(acctservers == NULL) {
	                rc_log(LOG_CRIT, "rc_config_init: error initializing server structs");
			rc_destroy(rh);
			if(authservers) free(authservers);
	                return NULL;
		}
		acct->val = acctservers;
	}

	return rh;
}

static ssize_t plain_sendto(void *ptr, int sockfd,
			    const void *buf, size_t len, int flags,
			    const struct sockaddr *dest_addr, socklen_t addrlen)
{
	return sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

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

static ssize_t plain_recvfrom(void *ptr, int sockfd,
			      void *buf, size_t len, int flags,
			      struct sockaddr *src_addr, socklen_t * addrlen)
{
	return recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

static void plain_close_fd(int fd)
{
	close(fd);
}

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

/** Applies and initializes any parameters from the radcli configuration
 *
 * When no configuration file is provided and the configuration
 * is provided via rc_add_config(), radcli requires the call of this function
 * in order to initialize items for the connection.
 *
 * @param rh a handle to parsed configuration.
 * @return 0 on success, -1 when failure.
 */
int rc_apply_config(rc_handle *rh)
{
	const char *txt;
	int ret;

	memset(&rh->own_bind_addr, 0, sizeof(rh->own_bind_addr));
	rh->own_bind_addr_set = 0;
	rc_own_bind_addr(rh, &rh->own_bind_addr);
	rh->own_bind_addr_set = 1;

	txt = rc_conf_str(rh, "nas-ip");
	if (txt != NULL) {
		if (set_addr(&rh->nas_addr, txt) < 0)
			return -1;
		rh->nas_addr_set = 1;
	}

	txt = rc_conf_str(rh, "serv-type");
	if (txt == NULL)
		txt = rc_conf_str(rh, "serv-auth-type");

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

/** Read the global config file
 *
 * This function will load the provided configuration file, and
 * any other files such as the dictionary. This is the most common
 * mode of use of this library. The configuration format is compatible
 * with the radiusclient-ng and freeradius-client formats.
 *
 * Note: To preserve compatibility with libraries of the same API
 * which don't load the dictionary care is taken not to reload the
 * same filename twice even if instructed to.
 *
 * @param filename a name of a file.
 * @return new rc_handle on success, NULL when failure.
 */
rc_handle *rc_read_config(char const *filename)
{
	FILE *configfd;
	char buffer[512], *p;
	OPTION *option;
	int line;
	size_t pos;
	rc_handle *rh;


	rh = rc_new();
	if (rh == NULL)
		return NULL;

        rh->config_options = malloc(sizeof(config_options_default));
        if (rh->config_options == NULL) {
                rc_log(LOG_CRIT, "rc_read_config: out of memory");
		rc_destroy(rh);
                return NULL;
        }
        memcpy(rh->config_options, &config_options_default, sizeof(config_options_default));

	if ((configfd = fopen(filename,"r")) == NULL)
	{
		rc_log(LOG_ERR,"rc_read_config: can't open %s: %s", filename, strerror(errno));
		rc_destroy(rh);
		return NULL;
	}

	line = 0;
	while ((fgets(buffer, sizeof(buffer), configfd) != NULL))
	{
		line++;
		p = buffer;

		if ((*p == '\n') || (*p == '#') || (*p == '\0'))
			continue;

		p[strlen(p)-1] = '\0';


		if ((pos = strcspn(p, "\t ")) == 0) {
			rc_log(LOG_ERR, "%s: line %d: bogus format: %s", filename, line, p);
			fclose(configfd);
			rc_destroy(rh);
			return NULL;
		}

		p[pos] = '\0';

		if ((option = find_option(rh, p, OT_ANY)) == NULL) {
			rc_log(LOG_ERR, "%s: line %d: unrecognized keyword: %s", filename, line, p);
			fclose(configfd);
			rc_destroy(rh);
			return NULL;
		}

		if (option->status != ST_UNDEF) {
			rc_log(LOG_ERR, "%s: line %d: duplicate option line: %s", filename, line, p);
			fclose(configfd);
			rc_destroy(rh);
			return NULL;
		}

		p += pos+1;
		while (isspace(*p))
			p++;
		pos = strlen(p) - 1;
		while(pos != 0 && isspace(p[pos]))
			pos--;
		p[pos + 1] = '\0';

		switch (option->type) {
			case OT_STR:
				if (set_option_str(filename, line, option, p) < 0) {
					fclose(configfd);
					rc_destroy(rh);
				 	return NULL;
				}
				break;
			case OT_INT:
				if (set_option_int(filename, line, option, p) < 0) {
					fclose(configfd);
					rc_destroy(rh);
				 	return NULL;
				}
				break;
			case OT_SRV:
				if (set_option_srv(filename, line, option, p) < 0) {
					fclose(configfd);
					rc_destroy(rh);
				 	return NULL;
				}
				break;
			case OT_AUO:
				if (set_option_auo(filename, line, option, p) < 0) {
					fclose(configfd);
					rc_destroy(rh);
				 	return NULL;
				}
				break;
			default:
				rc_log(LOG_CRIT, "rc_read_config: impossible case branch!");
				abort();
		}
	}
	fclose(configfd);

	if (rc_test_config(rh, filename) == -1) {
		rc_destroy(rh);
		return NULL;
	}

        {
                int clientdebug = rc_conf_int_2(rh, "clientdebug", FALSE);
                if(clientdebug > 0) {
                        radcli_debug = clientdebug;
                }
        }

	p = rc_conf_str(rh, "dictionary");
	if (p != NULL) {
		if (rc_read_dictionary(rh, p) != 0) {
			rc_log(LOG_CRIT, "could not load dictionary");
			rc_destroy(rh);
			return NULL;
		}
	} else {
		rc_log(LOG_INFO, "rc_read_config: no dictionary was specified");
	}

	return rh;
}

/** Get the value of a config option
 *
 * @param rh a handle to parsed configuration.
 * @param optname the name of an option.
 * @return config option value.
 */
char *rc_conf_str(rc_handle const *rh, char const *optname)
{
	OPTION *option;

	option = find_option(rh, optname, OT_STR);

	if (option != NULL) {
		return (char *)option->val;
	} else {
		rc_log(LOG_CRIT, "rc_conf_str: unknown config option requested: %s", optname);
		return NULL;
	}
}

/*- Get the value of a config option
 *
 * @param rh a handle to parsed configuration.
 * @param optname the name of an option.
 * @return config option value.
 */
static int rc_conf_int_2(rc_handle const *rh, char const *optname, int complain)
{
	OPTION *option;

	option = find_option(rh, optname, OT_INT|OT_AUO);

	if (option != NULL) {
		if (option->val) {
			return *((int *)option->val);
		} else if(complain) {
			rc_log(LOG_ERR, "rc_conf_int: config option %s was not set", optname);
		}
                return 0;
	} else {
		rc_log(LOG_CRIT, "rc_conf_int: unknown config option requested: %s", optname);
		return 0;
	}
}

int rc_conf_int(rc_handle const *rh, char const *optname)
{
        return rc_conf_int_2(rh, optname, TRUE);
}

/** Get the value of a config option
 *
 * @param rh a handle to parsed configuration.
 * @param optname the name of an option.
 * @return config option value.
 */
SERVER *rc_conf_srv(rc_handle const *rh, char const *optname)
{
	OPTION *option;

	option = find_option(rh, optname, OT_SRV);

	if (option != NULL) {
		return (SERVER *)option->val;
	} else {
		rc_log(LOG_CRIT, "rc_conf_srv: unknown config option requested: %s", optname);
		return NULL;
	}
}

/** Tests the configuration the user supplied
 *
 * @param rh a handle to parsed configuration.
 * @param filename a name of a configuration file.
 * @return 0 on success, -1 when failure.
 */
int rc_test_config(rc_handle *rh, char const *filename)
{
	SERVER *srv;

	srv = rc_conf_srv(rh, "authserver");
	if (!srv || !srv->max)
	{
		rc_log(LOG_ERR,"%s: no authserver specified", filename);
		return -1;
	}

	srv = rc_conf_srv(rh, "acctserver");
	if (!srv || !srv->max)
	{
		/* it is allowed not to have acct servers */
		if (rh->so_type != RC_SOCKET_TLS && rh->so_type != RC_SOCKET_DTLS)
			rc_log(LOG_DEBUG,"%s: no acctserver specified", filename);
	}
	if (!rc_conf_str(rh, "dictionary"))
	{
		rc_log(LOG_ERR,"%s: no dictionary specified", filename);
		return -1;
	}

	if (rc_conf_int(rh, "radius_timeout") <= 0)
	{
		rc_log(LOG_ERR,"%s: radius_timeout <= 0 is illegal", filename);
		return -1;
	}
	if (rc_conf_int(rh, "radius_retries") <= 0)
	{
		rc_log(LOG_ERR,"%s: radius_retries <= 0 is illegal", filename);
		return -1;
	}

	if (rc_apply_config(rh) == -1) {
		return -1;
	}

	return 0;
}

/** See if info matches hostname
 *
 * @param addr a struct addrinfo
 * @param hostname the name of the host.
 * @return 0 on success, -1 when failure.
 */
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

/** Checks if provided address is local address
 *
 * @param addr an %AF_INET or %AF_INET6 address
 * @return 0 if local, 1 if not local, -1 on failure.
 */
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

/** Checks if provided name refers to ourselves
 *
 * @param info an addrinfo of the host to check
 * @return 0 if yes, 1 if no and -1 on failure.
 */
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

/** Locate a server in the rh config or if not found, check for a servers file
 *
 * @param rh a handle to parsed configuration.
 * @param server_name the name of the server.
 * @param info: will hold a pointer to addrinfo
 * @param secret will hold the server's secret (of %MAX_SECRET_LENGTH).
 * @param type %AUTH or %ACCT

 * @return 0 on success, -1 on failure.
 */
int rc_find_server_addr (rc_handle const *rh, char const *server_name,
                         struct addrinfo** info, char *secret, rc_type type)
{
	int             result = 0;
	FILE           *clientfd;
	char           *h;
	char           *s;
	char            buffer[128];
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
	     ((servers = rc_conf_srv(rh, optname)) != NULL) )
	{
		/* Check to see if the server secret is defined in the rh config */
		unsigned  servernum;
		size_t    server_name_len = strlen(server_name);
		for (servernum = 0; servernum < servers->max; servernum++)
		{
			if( (strncmp(server_name, servers->name[servernum], server_name_len) == 0) &&
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

	fservers = rc_conf_str(rh, "servers");
	if (fservers != NULL) {
		if ((clientfd = fopen (fservers, "r")) == NULL)
		{
			rc_log(LOG_ERR, "rc_find_server: couldn't open file: %s: %s", strerror(errno), rc_conf_str(rh, "servers"));
			goto fail;
		}

		while (fgets (buffer, sizeof (buffer), clientfd) != NULL)
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
		memset (buffer, '\0', sizeof (buffer));
		memset (secret, '\0', MAX_SECRET_LENGTH);
		rc_log(LOG_ERR, "rc_find_server: couldn't find RADIUS server %s in %s",
			 server_name, rc_conf_str(rh, "servers"));
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

	return result;
}

/**
 * rc_config_free:
 * @param rh a handle to parsed configuration
 *
 * Free allocated config values. For legacy compatibility
 * reasons this will not release any dictionary entries.
 * To release all memory from the handle use rc_destroy()
 * instead.
 *
 */
void rc_config_free(rc_handle *rh)
{
	int i, j;
	SERVER *serv;

	if (rh->config_options == NULL)
		return;

	for (i = 0; i < NUM_OPTIONS; i++) {
		if (rh->config_options[i].val == NULL)
			continue;
		if (rh->config_options[i].type == OT_SRV) {
			serv = (SERVER *)rh->config_options[i].val;
			for (j = 0; j < serv->max; j++) {
				free(serv->name[j]);
				if(serv->secret[j]) free(serv->secret[j]);
			}
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

/** Initialises new Radius Client handle
 *
 * @return a new rc_handle (free with rc_destroy).
 */
rc_handle *rc_new(void)
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
		srandom((unsigned int)(time(NULL)+getpid()));
	}
	_initialized++;

	rh = calloc(1, sizeof(*rh));
	if (rh == NULL) {
                rc_log(LOG_CRIT, "rc_new: out of memory");
                return NULL;
        }
	return rh;
}

/** Destroys Radius Client handle reclaiming all memory
 *
 * @param rh The Radius client handle to free.
 */
void rc_destroy(rc_handle *rh)
{
	rc_dict_free(rh);
	rc_config_free(rh);
	free(rh);

#if defined(HAVE_GNUTLS) && GNUTLS_VERSION_NUMBER < 0x030300
	_initialized--;
	if (_initialized == 0) {
		gnutls_global_deinit();
	}
#endif
}

/** Returns the type of the socket used
 *
 * That indicates the type of connection used with the radius
 * server, and can be UDP, TLS or DTLS.
 *
 * @return the type of the socket
 */
rc_socket_type rc_get_socket_type(rc_handle *rh)
{
	return rh->so_type;
}

/** @} */
 /*
 * Local Variables:
 * c-basic-offset:8
 * c-style: whitesmith
 * End:
 */
