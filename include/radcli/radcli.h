/*
 * Copyright (C) 1995,1996,1997,1998 Lars Fenneberg
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

/** @file radcli.h
 * @brief Public API of the radcli library.
 */

#ifndef RADCLI_H
#define RADCLI_H

#ifndef RADCLI_SUPPRESS_LEGACY_WARNING
#warning "radcli.h/-lradcli is the legacy, frozen API. New code should use \
<radcli/radcli2.h> (-lradcli2). See https://radcli.github.io/radcli/ for \
the new API's documentation, or define RADCLI_SUPPRESS_LEGACY_WARNING to \
silence this warning."
#endif

#include	<sys/types.h>
/*
 * Include for C99 uintX_t defines is stdint.h on most systems.  Solaris uses
 * inttypes.h instead.  Comment out the stdint include if you get an error,
 * and uncomment the inttypes.h include.
 */
#include	<stdint.h>
/* #include	<inttypes.h> */
#include	<stdio.h>
#include	<time.h>

/* for struct in6_addr */
#include	<netinet/in.h>

/* for struct addrinfo and sockaddr_storage */
#include <sys/socket.h>
#include <netdb.h>

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

/**
 * @defgroup radcli-api Main API
 * @brief Main API Functions
 *
 * @{
 */

#define AUTH_PASS_LEN		(8 * 16) /* multiple of 16 */
#define AUTH_ID_LEN		64

#define RC_BUFFER_LEN		8192
#define RC_MAX_PACKET_LEN	4096 /* RFC 2865: maximum RADIUS packet size */

#define RC_NAME_LENGTH		64

#define MAX_SECRET_LENGTH	(16 * 16) /* MUST be multiple of 16 */

#define RADCLI_VENDOR_MASK 0xffffffff
#define VENDOR_BIT_SIZE		32
#define RADCLI_VENDOR_ATTR_SET(attr, vendor) ((attr)|((uint64_t)((vendor)&RADCLI_VENDOR_MASK)) << VENDOR_BIT_SIZE)

#define VENDOR(x)		(((x) >> VENDOR_BIT_SIZE) & 0xffffffff)
#define ATTRID(x)		((x) & 0xffffffff)

#define PW_MAX_MSG_SIZE		4096

/** \enum rc_type Codes to indicate the type of server
 */
typedef enum rc_type {
	AUTH = 0, //!< Request for authentication server
	ACCT = 1  //!< Request for accounting server
} rc_type;

/* defines for config.c */

#define RC_SERVER_MAX 8

#define AUTH_LOCAL_FST	(1<<0)
#define AUTH_RADIUS_FST	(1<<1)
#define AUTH_LOCAL_SND	(1<<2)
#define AUTH_RADIUS_SND	(1<<3)

struct rc_conf;
typedef struct rc_conf rc_handle;

/** \struct server
 * Avoid using this structure directly, it is included for backwards compatibility only.
 * Several of its fields have been deprecated.
 */
typedef struct server {
	int   max;
	char *name[RC_SERVER_MAX];
	uint16_t port[RC_SERVER_MAX];
	char *secret[RC_SERVER_MAX];
	double deadtime_ends[RC_SERVER_MAX]; //!< unused
} SERVER;

/** \enum rc_socket_type Indicate the type of the socket
 */
typedef enum rc_socket_type {
	RC_SOCKET_UDP = 0,	//!< Plain UDP socket
	RC_SOCKET_TLS = 1,	//!< TLS socket
	RC_SOCKET_DTLS = 2,	//!< DTLS socket
	RC_SOCKET_TCP = 3	//!< Plain TCP socket
} rc_socket_type;

#define AUTH_HDR_LEN			20
#define CHAP_VALUE_LENGTH		16

#define PW_AUTH_UDP_PORT		1812
#define PW_ACCT_UDP_PORT		1813

/** \enum rc_attr_type Attribute types
 */
typedef enum rc_attr_type {
	PW_TYPE_STRING=0,	//!< The attribute is a printable string.
	PW_TYPE_INTEGER=1,	//!< The attribute is a 32-bit integer.
	PW_TYPE_IPADDR=2,	//!< The attribute is an IPv4 address in host-byte order.
	PW_TYPE_DATE=3,		//!< The attribute contains a 32-bit number indicating the seconds since epoch.
	PW_TYPE_IPV6ADDR=4,	//!< The attribute is an 128-bit IPv6 address.
	PW_TYPE_IPV6PREFIX=5,   //!< The attribute is an IPv6 prefix; the lvalue will indicate its size.
	PW_TYPE_MAX=6   	//!< Maximum number of types (last+1)
} rc_attr_type;

/** \enum rc_standard_codes Standard RADIUS request codes
 */
typedef enum rc_standard_codes {
	PW_ACCESS_REQUEST=1,
	PW_ACCESS_ACCEPT=2,
	PW_ACCESS_REJECT=3,
	PW_ACCOUNTING_REQUEST=4,
	PW_ACCOUNTING_RESPONSE=5,
	PW_ACCOUNTING_STATUS=6,
	PW_PASSWORD_REQUEST=7,
	PW_PASSWORD_ACK=8,
	PW_PASSWORD_REJECT=9,
	PW_ACCOUNTING_MESSAGE=10,
	PW_ACCESS_CHALLENGE=11,
	PW_STATUS_SERVER=12,
	PW_STATUS_CLIENT=13
} rc_standard_codes;

/* rc_attr_id (the numeric PW_* attribute IDs), rc_service_type,
 * rc_framed_protocol, rc_framed_routing_type, rc_framed_comp,
 * rc_login_service_type, rc_termination_action, rc_acct_status_type,
 * rc_acct_terminate_cause, rc_nas_port_type, rc_acct_auth_type, and
 * rc_vendor_pec/rc_vendor_type live in radcli-defs.h, shared with
 * radcli2.h so both headers use the same numeric IDs/VALUEs. */
#include <radcli/radcli-defs.h>

/* Integer Translations */

/* Vendor RADIUS attribute-value pairs for MICROSOFT */
enum rc_vendor_attr_microsoft {
  PW_MS_CHAP_CHALLENGE	=	11,	/* string */
  PW_MS_CHAP_RESPONSE	=	1,	/* string */
  PW_MS_CHAP2_RESPONSE	=	25,	/* string */
  PW_MS_CHAP2_SUCCESS	=	26,	/* string */
  PW_MS_MPPE_ENCRYPTION_POLICY=	7,	/* string */
  PW_MS_MPPE_ENCRYPTION_TYPE=	8,	/* string */
  PW_MS_MPPE_ENCRYPTION_TYPES=PW_MS_MPPE_ENCRYPTION_TYPE,
  PW_MS_CHAP_MPPE_KEYS	=	12,	/* string */
  PW_MS_MPPE_SEND_KEY	=	16,	/* string */
  PW_MS_MPPE_RECV_KEY	=	17,	/* string */
  PW_MS_PRIMARY_DNS_SERVER=	28,	/* ipaddr */
  PW_MS_SECONDARY_DNS_SERVER=	29,	/* ipaddr */
  PW_MS_PRIMARY_NBNS_SERVER=	30,	/* ipaddr */
  PW_MS_SECONDARY_NBNS_SERVER=	31,	/* ipaddr */
};

/* Vendor RADIUS attribute-value pairs for Roaring Penguin: Bandwidth bit rate limits */
enum rc_vendor_attr_roaringpenguin {
  PW_RP_UPSTREAM_LIMIT        =1,  /* integer */
  PW_RP_DOWNSTREAM_LIMIT      =2,  /* integer */
};

/* PROHIBIT PROTOCOL */
#define PW_DUMB			0	//!< 1 and 2 are defined in FRAMED PROTOCOLS.
#define PW_AUTH_ONLY		3
#define PW_ALL			255

/* Server data structures */

/** \struct dict_attr
 * A dictionary attribute definition (name, numeric ID, type).
 */
typedef struct dict_attr
{
	char              name[RC_NAME_LENGTH + 1];	//!< attribute name.
	uint64_t          value;			//!< attribute index and vendor number; use VENDOR() and ATTRID() to separate.
	rc_attr_type      type;				//!< string, int, etc..
	struct dict_attr *next;
} DICT_ATTR;

/** \struct dict_value
 * A named value for a dictionary attribute (e.g. an enumerated integer value).
 */
typedef struct dict_value
{
	char               attrname[RC_NAME_LENGTH +1];
	char               name[RC_NAME_LENGTH + 1];
	uint32_t           value;
	struct dict_value *next;
} DICT_VALUE;

/** \struct dict_vendor
 * A dictionary vendor definition (name and PEN/vendor ID).
 */
typedef struct dict_vendor
{
	char               vendorname[RC_NAME_LENGTH +1];
	uint32_t           vendorpec;
	struct dict_vendor *next;
} DICT_VENDOR;

/* don't change this, as it has to be the same as in the Merit radiusd code */
#define MGMT_POLL_SECRET	"Hardlyasecret" //!< Default for Merit radiusd

/** \enum rc_send_status Return codes for rc_send_server()
 */
typedef enum rc_send_status {
	NETUNREACH_RC=-4,
	BADRESPID_RC=-3,
	BADRESP_RC=-2,
	ERROR_RC=-1,
	OK_RC=0,
	TIMEOUT_RC=1,
	REJECT_RC=2,
	CHALLENGE_RC=3
} rc_send_status;


# define AUTH_STRING_LEN		253	 /* maximum of 253 */

/** \struct rc_value_pair
 * Avoid using this structure directly. Use rc_avpair_get_uint32() for
 * integer/IPv4/date values, rc_avpair_get_in6() for IPv6 addresses and
 * prefixes, rc_avpair_get_raw() for string/binary values, and
 * rc_avpair_get_attr() to read the attribute type and ID.  To iterate the
 * list use rc_avpair_next().  Free the entire list with rc_avpair_free().
 */
typedef struct rc_value_pair
{
	char               name[RC_NAME_LENGTH + 1];	//!< attribute name if known.
	uint64_t           attribute;			//!< attribute numeric value of type rc_attr_id including vendor; use VENDOR() and ATTRID() to separate.
	rc_attr_type	   type;			//!< attribute type.
	uint32_t           lvalue;			//!< attribute value if type is PW_TYPE_INTEGER, PW_TYPE_DATE or PW_TYPE_IPADDR.
	char               strvalue[AUTH_STRING_LEN + 1]; //!< contains attribute value in other cases.
	struct rc_value_pair *next;
	char		   pad[32];			//!< unused pad
} VALUE_PAIR;

/** \struct send_data
 * Avoid using this structure directly; it is included for backwards
 * compatibility only.  Use rc_auth() or rc_acct() for authentication and
 * accounting requests.  Several of its fields have been deprecated.
 */
typedef struct send_data
{
	uint8_t        code;		//!< RADIUS packet code.
	uint8_t        seq_nbr;		//!< Packet sequence number.
	char           *server;		//!< Name/address of RADIUS server.
	int            svc_port;	//!< RADIUS protocol destination port.
	char           *secret;		//!< Shared secret of RADIUS server.
	int            timeout;		//!< Session timeout in seconds.
	int            retries;
	VALUE_PAIR     *send_pairs;     //!< More a/v pairs to send.
	VALUE_PAIR     *receive_pairs;  //!< Where to place received a/v pairs.
} SEND_DATA;

#define AUTH_VECTOR_LEN		16

struct rc_aaa_ctx_st;
/** Opaque context returned by rc_aaa_ctx() after a successful request.
 *
 * Captures the shared secret and the request authenticator vector
 * (AUTH_VECTOR_LEN bytes) that were used in the last request.  These can be
 * retrieved with rc_aaa_ctx_get_secret() and rc_aaa_ctx_get_vector().
 *
 * Pass NULL for the @p ctx argument to rc_aaa_ctx() if this information is not
 * needed.  When a context is no longer needed, free it with rc_aaa_ctx_free().
 */
typedef struct rc_aaa_ctx_st RC_AAA_CTX;

#ifndef RC_MIN
#define RC_MIN(a, b)     ((a) < (b) ? (a) : (b))
#endif
#ifndef RC_MAX
#define RC_MAX(a, b)     ((a) > (b) ? (a) : (b))
#endif

#ifndef PATH_MAX
#define PATH_MAX	1024
#endif

#define ENV_SIZE	128

/** @} */

/* See doc/mainpage-legacy.md for the introduction/quick-start content that
 * used to live here as \mainpage -- USE_MDFILE_AS_MAINPAGE now supplies the
 * legacy Doxygen pass's main page, and an explicit \mainpage in this header
 * would take precedence over it. */

/** \example radiusclient-tls.conf
 * This is an configuration file with TLS.
 */

/** \example radiusclient.conf
 * This is an example configuration file listing the available options.
 */

/** \example servers
 * This is an example servers configuration file.
 */

/** \example servers-tls
 * This is an example servers configuration file with TLS PSK.
 */

/* avpair.c */

VALUE_PAIR *rc_avpair_add (rc_handle const *rh, VALUE_PAIR **list, uint32_t attrid, void const *pval, int len, uint32_t vendorspec);
int rc_avpair_assign (VALUE_PAIR *vp, void const *pval, int len);
VALUE_PAIR *rc_avpair_new (rc_handle const *rh, uint32_t attrid, void const *pval, int len, uint32_t vendorspec);
VALUE_PAIR *rc_avpair_gen(rc_handle const *rh, VALUE_PAIR *pair, unsigned char const *ptr,
			  int length, uint32_t vendorspec);
void rc_avpair_remove (VALUE_PAIR **list, uint32_t attrid, uint32_t vendorspec);
VALUE_PAIR *rc_avpair_get (VALUE_PAIR *vp, uint32_t attrid, uint32_t vendorspec);
VALUE_PAIR *rc_avpair_copy(VALUE_PAIR *p);
void rc_avpair_insert(VALUE_PAIR **a, VALUE_PAIR *p, VALUE_PAIR *b);
void rc_avpair_free (VALUE_PAIR *pair);
int rc_avpair_parse (rc_handle const *rh, char const *buffer, VALUE_PAIR **first_pair);
int rc_avpair_tostr (rc_handle const *rh, VALUE_PAIR *pair, char *name, int ln, char *value, int lv);
char *rc_avpair_log(rc_handle const *rh, VALUE_PAIR *pair, char *buf, size_t buf_len);
VALUE_PAIR *rc_avpair_next(VALUE_PAIR *t);

int rc_avpair_get_uint32 (VALUE_PAIR *vp, uint32_t *res);
int rc_avpair_get_in6 (VALUE_PAIR *vp, struct in6_addr *res, unsigned *prefix);
int rc_avpair_get_raw (VALUE_PAIR *vp, char **res, unsigned *res_size);
void rc_avpair_get_attr (VALUE_PAIR *vp, unsigned *type, unsigned *id);

/* buildreq.c */

void rc_buildreq(rc_handle const *rh, SEND_DATA *data, int code, char *server, unsigned short port,
		 char *secret, int timeout, int retries);
int rc_auth(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send,
            VALUE_PAIR **received, char *msg);
int rc_auth_proxy(rc_handle *rh, VALUE_PAIR *send, VALUE_PAIR **received, char *msg);
int rc_acct(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send);
int rc_acct_proxy(rc_handle *rh, VALUE_PAIR *send);

int rc_acct_async(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send);

int rc_check(rc_handle *rh, char *host, char *secret, unsigned short port, char *msg);

int rc_aaa(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
	   char *msg, int add_nas_port, rc_standard_codes request_type);
int rc_aaa_ctx(rc_handle *rh, RC_AAA_CTX **ctx, uint32_t client_port, VALUE_PAIR *send,
               VALUE_PAIR **received,
               char *msg, int add_nas_port, rc_standard_codes request_type);
int rc_aaa_ctx_server(rc_handle *rh, RC_AAA_CTX **ctx, SERVER *aaaserver,
                      rc_type type, uint32_t client_port,
                      VALUE_PAIR *send, VALUE_PAIR **received,
                      char *msg, int add_nas_port, rc_standard_codes request_type);

/* config.c */

int rc_add_config(rc_handle *rh, char const *option_name, char const *option_val, char const *source, int line);
rc_handle *rc_config_init(rc_handle *rh);
rc_handle *rc_read_config(char const *filename);
char *rc_conf_str(rc_handle const *rh, char const *optname);
int rc_conf_int(rc_handle const *rh, char const *optname);
SERVER *rc_conf_srv(rc_handle const *rh, char const *optname);
int rc_test_config(rc_handle *rh, char const *filename);
int rc_apply_config(rc_handle *rh);
int rc_find_server_addr (rc_handle const *rh, char const *server_name,
                         struct addrinfo** info, char *secret, rc_type type);
void rc_config_free(rc_handle *rh);
rc_handle *rc_new(void);
void rc_destroy(rc_handle *rh);
rc_socket_type rc_get_socket_type(rc_handle * rh);

#define test_config rc_test_config

/* dict.c */

int rc_read_dictionary (rc_handle *rh, char const *filename);
int rc_read_dictionary_from_buffer (rc_handle *rh, char const *buf, size_t size);

DICT_ATTR *rc_dict_addattr(rc_handle *rh, char const * namestr, uint32_t value, int type, uint32_t vendorspec);
DICT_VALUE *rc_dict_addval(rc_handle *rh, char const * attrstr, char const * namestr, uint32_t value);
DICT_VENDOR *rc_dict_addvend(rc_handle *rh, char const * vendorname, uint32_t value);

DICT_ATTR *rc_dict_getattr(rc_handle const *rh, uint64_t attribute);
DICT_ATTR *rc_dict_findattr(rc_handle const *rh, char const *attrname);
DICT_VALUE *rc_dict_findval(rc_handle const *rh, char const *valname);
DICT_VENDOR *rc_dict_findvend(rc_handle const *rh, char const *vendorname);
DICT_VENDOR *rc_dict_getvend (rc_handle const *rh, uint32_t vendorspec);
DICT_VALUE *rc_dict_getval(rc_handle const *rh, uint32_t value, char const *attrname);
void rc_dict_free(rc_handle *rh);

/*	tls.c			*/

int rc_tls_fd(rc_handle * rh);
int rc_check_tls(rc_handle * rh);

/* ip_util.c */

unsigned short rc_getport(int type);
int rc_own_hostname(char *hostname, int len);
struct sockaddr;
int rc_get_srcaddr(struct sockaddr *lia, const struct sockaddr *ria);

/* log.c */

void rc_setdebug(int debug);
void rc_openlog(char const *ident);
/* to provide compatibility with any old applications that may have
 * been using rc_log() */
#define rc_log syslog

/* sendserver.c */

int rc_send_server (rc_handle *rh, SEND_DATA *data, char *msg,
                    rc_type type);

/* aaa_ctx.c */
void rc_aaa_ctx_free(RC_AAA_CTX *ctx);
const char *rc_aaa_ctx_get_secret(RC_AAA_CTX *ctx);
const void *rc_aaa_ctx_get_vector(RC_AAA_CTX *ctx);

/* obsolete functions */
#define _RADCLI_GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if !defined RADCLI_INTERNAL_BUILD
# if _RADCLI_GCC_VERSION >= 30100
#  define _RADCLI_GCC_ATTR_DEPRECATED __attribute__ ((__deprecated__))
# endif
#endif
char *rc_mksid(void) _RADCLI_GCC_ATTR_DEPRECATED;


/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif /* RADCLI_H */
