/*
 * Copyright (C) 1997 Lars Fenneberg
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

#ifndef RC_INCLUDES_H
# define RC_INCLUDES_H

#include "config.h"

#include <sys/types.h>

#include <ctype.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef STDC_HEADERS
# include <stdlib.h>
# include <string.h>
# include <stdarg.h>
#else
# include <stdarg.h>
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
#endif

/* I realize that this is ugly and unsafe.. :( */
#ifndef HAVE_SNPRINTF
# define snprintf(buf, len, format, ...) sprintf(buf, format, __VA_ARGS__)
#endif
#ifndef HAVE_VSNPRINTF
# define vsnprintf(buf, len, format, ap) vsprintf(buf, format, ap)
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_SYS_FCNTL_H
# include <sys/fcntl.h>
#endif

#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif

#ifdef HAVE_TERMIOS_H
# include <termios.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX        1024
#endif

#ifndef UCHAR_MAX
# ifdef  __STDC__
#  define UCHAR_MAX       255U
# else
#  define UCHAR_MAX       255
# endif
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_GETOPT_H
# include <getopt.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/*
 * prefer srandom/random over srand/rand as there generator has a
 * better distribution of the numbers on certain systems.
 * on Linux both generators are identical.
 */
#ifndef HAVE_RANDOM
# ifdef HAVE_RAND
# define srandom        srand
# define random         rand
# endif
#endif

#include <radcli/radcli.h>
#include <radcli/radcli2.h>

#define GETSTR_LENGTH		128	//!< must be bigger than AUTH_PASS_LEN.

/* Overhead consumed by the VSA envelope inside a RADIUS attribute:
 * vendor-id(4) + sub-attr-type(1) + sub-attr-length(1) = 6 bytes.
 * A VSA value may be at most AUTH_STRING_LEN - VSA_HDR_LEN bytes long. */
#define VSA_HDR_LEN		6

typedef struct pw_auth_hdr
{
	uint8_t		code;
	uint8_t		id;
	uint16_t	length;
	uint8_t		vector[AUTH_VECTOR_LEN];
	uint8_t		data[2];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
AUTH_HDR;

typedef struct rc_sockets_override {
	void *ptr;
	const char *static_secret;
	int (*get_fd)(void *ptr, struct sockaddr* our_sockaddr);
	/* get_active_fd: return the fd of an already-established connection
	 * without allocating a new socket. Only set by transports that
	 * maintain a persistent connection (TLS/DTLS). */
	int (*get_active_fd)(void *ptr);
	void (*close_fd)(int fd);
	ssize_t (*sendto)(void *ptr, int sockfd, const void *buf, size_t len, int flags,
	                  const struct sockaddr *dest_addr, socklen_t addrlen);
	ssize_t (*recvfrom)(void *ptr, int sockfd, void *buf, size_t len, int flags,
	                    struct sockaddr *src_addr, socklen_t *addrlen);
	int (*lock)(void *ptr);
	int (*unlock)(void *ptr);
} rc_sockets_override;

/* Per-attribute wire-encryption scheme and RFC 2868 SS3.1 tag flag, keyed by
 * DICT_ATTR identity, set by "encrypt=N"/"encrypt=<name>" and "has_tag"
 * tokens on a dictionary ATTRIBUTE line (lib/dict.c). Kept as a side list
 * rather than DICT_ATTR fields so the public DICT_ATTR struct
 * (include/radcli/radcli.h) never changes layout -- this list is reachable
 * only through the internal rc_conf a caller never sees the definition of.
 * encrypt_type's only value is 2 (RFC 2868 SS3.5 / RFC 2548 SS2.4.2-2.4.3
 * salt-encryption); see radcli_avp_decode() in lib/avp.c. An attribute may
 * set either flag alone or both together (Tunnel-Password sets both). */
struct dict_encrypt_flag {
	const struct dict_attr *attr;
	int encrypt_type;
	int has_tag;
	struct dict_encrypt_flag *next;
};

/* Octets-attribute -> Gigawords-attribute pairing for 64-bit accounting
 * counters (RFC 2866 SS5.3/5.4 Acct-Input/Output-Octets + RFC 2869 SS5.1/5.2
 * Acct-Input/Output-Gigawords), set by a "gigawords=<attrid>" token on a
 * dictionary ATTRIBUTE line (lib/dict.c) -- e.g. Acct-Input-Octets (42)
 * paired with Acct-Input-Gigawords (52). Kept as a side list, like dict_encrypt_flag
 * above and for the same reason (the public DICT_ATTR struct never changes
 * layout). gigawords_attrid is stored raw, not resolved to a DICT_ATTR* at
 * parse time, because the paired attribute's own ATTRIBUTE line has often
 * not been parsed yet (e.g. Acct-Input-Octets precedes Acct-Input-Gigawords
 * in etc/dictionary); resolution happens lazily, by rc_dict_getattr(), once
 * the whole dictionary is loaded -- see rc_dict_attr_gigawords() below,
 * used from lib/avp.c. Stored as the same vendor-combined uint64_t
 * DICT_ATTR.value/rc_dict_getattr() use (RADCLI_VENDOR_ATTR_SET()), not a
 * bare attribute number, so a VSA's gigawords= counterpart -- another
 * sub-attribute of the same vendor -- resolves correctly too. */
struct dict_counter64_pair {
	const struct dict_attr *octets;
	uint64_t gigawords_attrid;
	struct dict_counter64_pair *next;
};

struct radcli_dae_st; /* lib/dae.c; opaque here, ctx just tracks the pointer */

struct rc_conf
{
	struct _option		*config_options;
	struct sockaddr_storage	nas_addr;
	unsigned		nas_addr_set;

	struct sockaddr_storage	own_bind_addr;
	unsigned		own_bind_addr_set;

	 /* we keep a copy of the filename to avoid re-reading a dictionary,
	  * for applications relying on the old API which required explicit
	  * load of it. */
	char			*first_dict_read;
	struct dict_attr	*dictionary_attributes;
	struct dict_value	*dictionary_values;
	struct dict_vendor	*dictionary_vendors;
	struct dict_encrypt_flag *dictionary_encrypt;
	struct dict_counter64_pair *dictionary_gigawords;

	rc_sockets_override	so;
	unsigned		so_type; /* rc_socket_type */

	/* radcli2.h's radcli_ctx_get_poll()/radcli_ctx_dispatch() (lib/dae.c)
	 * operate on ctx, not on a radcli_dae, so that a future dynamic-
	 * authorization transport sharing one descriptor with the request
	 * path never has two independent accessors aliasing it -- see
	 * radcli_ctx_get_poll()'s doc comment. At most one radcli_dae may be
	 * active per ctx at a time, since these two calls need a single
	 * descriptor to report. */
	struct radcli_dae_st	*active_dae;
	unsigned		in_dispatch; /* radcli_ctx_dispatch() reentrancy guard */
};

/* older compilers don't like seeing this typedef along with the one in radcli.h */
struct rc_aaa_ctx_st
{
	char	secret[MAX_SECRET_LENGTH + 1]; //!< The secret used for this request
	uint8_t	request_vector[AUTH_VECTOR_LEN]; //< The auth vector used in this request
};

int rc_send_server_ctx (rc_handle *rh, RC_AAA_CTX **ctx, SEND_DATA *data,
                        char *msg, rc_type type, int no_wait);

/* Looks up attr's "encrypt=N" flag (lib/dict.c); used by radcli_avp_decode()
 * (lib/avp.c). See the definition in lib/dict.c. */
int rc_dict_attr_encrypt_type(rc_handle const *rh, const struct dict_attr *attr);

/* Looks up attr's "has_tag" flag (RFC 2868 SS3.1 tunnel-attribute tagging;
 * lib/dict.c); used by radcli_avp_decode() (lib/avp.c). See the definition
 * in lib/dict.c. */
int rc_dict_attr_has_tag(rc_handle const *rh, const struct dict_attr *attr);

/* Looks up the "gigawords=" pairing (lib/dict.c) recorded for octets, and
 * resolves it, via rc_dict_getattr(), to the paired attribute's DICT_ATTR
 * in rh's now-fully-loaded dictionary. Returns NULL if octets has no
 * gigawords= pairing configured, or if the configured attribute id does
 * not (or no longer) exist in the dictionary. Internal only -- used by
 * radcli_avp_add_gigawords64()/_get_counter64() (lib/avp.c). */
const struct dict_attr *rc_dict_attr_gigawords(rc_handle const *rh, const struct dict_attr *octets);

/* Projection between radcli_avp_list and VALUE_PAIR (lib/avp.c), internal
 * only. Neither aliases the other's storage; each call produces a fresh,
 * independently-owned list.
 *
 * radcli_avp_list_to_value_pairs() copies list into a newly allocated
 * VALUE_PAIR chain in *out (NULL if list is empty or every attribute was
 * omitted). An attribute VALUE_PAIR's fixed-size fields cannot hold -- a
 * string/IPv6-prefix value longer than VALUE_PAIR's 253-octet strvalue
 * allows for that attribute's wire framing, or a value whose stored length
 * does not match its type's fixed size -- is omitted, exactly as an
 * attribute the legacy decoder does not recognise is already omitted
 * today. Returns 0 on success, -1 on allocation failure (*out then freed
 * and left unset) or a NULL rh/out.
 *
 * radcli_value_pairs_to_avp_list() is the reverse: copies vp into a newly
 * allocated radcli_avp_list in *out, re-deriving each attribute's
 * radcli_attr_def from rh's dictionary by (attribute, vendor) identity.
 * Returns 0 on success, -1 on allocation failure or a NULL rh/out. */
int radcli_avp_list_to_value_pairs(rc_handle const *rh, const radcli_avp_list *list, VALUE_PAIR **out);
int radcli_value_pairs_to_avp_list(rc_handle const *rh, VALUE_PAIR *vp, radcli_avp_list **out);

/* lib/sendserver.c internals, exposed (no longer static) so
 * radcli_transport_exchange() can reuse the exact RFC 2865 SS3 Response
 * Authenticator and Message-Authenticator/Blast-RADIUS logic
 * rc_send_server_ctx() uses, rather than a second, independently-written
 * copy of security-sensitive code. None of the five takes or returns a
 * VALUE_PAIR; all operate on raw bytes, AUTH_HDR, secret, and vector. */

/* Fills a freshly allocated *ctx (if ctx != NULL and *ctx == NULL) with a
 * copy of secret/vector; a no-op returning OK_RC if ctx == NULL. ERROR_RC
 * if *ctx is already non-NULL or on allocation failure. */
int populate_ctx(RC_AAA_CTX **ctx, char secret[MAX_SECRET_LENGTH + 1],
		 uint8_t vector[AUTH_VECTOR_LEN]);

/* Verifies a reply's Response Authenticator (RFC 2865 SS3: MD5 over Code,
 * Identifier, Length, the Request Authenticator (vector) the request was
 * sent with, the reply attributes, and secret) and that its Identifier
 * matches seq_nbr. Returns OK_RC if both check out, BADRESPID_RC if the
 * Identifier does not match, BADRESP_RC if the Response Authenticator does
 * not verify. */
int rc_check_reply(AUTH_HDR *auth, int bufferlen, char const *secret,
		   unsigned char const *vector, uint8_t seq_nbr);

/* Appends a Message-Authenticator attribute (RFC 2869 SS5.14: type 80,
 * length 18, an HMAC-MD5 over the packet with the attribute's own value
 * field zeroed during computation) to the packet at auth, whose first
 * total_length bytes (header + attributes already encoded) must already be
 * written. Returns the new total length, including the appended attribute. */
int add_msg_auth_attr(rc_handle *rh, char *secret, AUTH_HDR *auth, int total_length);

/* Verifies a received Message-Authenticator attribute against recv_buffer
 * (length bytes, header included), given secret and the request's own
 * Request Authenticator (req_auth) -- required for a reply to an
 * Access-Request, RFC 2869 SS5.14. Returns 0 if it verifies (or is absent:
 * the caller decides whether that is acceptable), non-zero if present and
 * wrong. */
int validate_message_authenticator(const uint8_t *recv_buffer, size_t length,
				   const char *secret, const unsigned char *req_auth);

/* Representation-agnostic send/retry/receive core (lib/sendserver.c),
 * shared by rc_send_server_ctx() and lib/request.c's radcli_request_perform();
 * see its own doc comment for the full contract. */
int radcli_transport_exchange(rc_handle *rh, RC_AAA_CTX **ctx,
			      char *server_name, unsigned short svc_port,
			      char secret[MAX_SECRET_LENGTH + 1], int mgmt_secret,
			      int timeout, int retries, int no_wait, rc_type type,
			      const uint8_t *send_buf, int send_len,
			      uint8_t *recv_buf, size_t recv_buf_cap, size_t *recv_len,
			      uint8_t *out_code);

/* Like rc_conf_int() (radcli.h), but returns def instead of logging an
 * error when optname was never set (lib/config.c). */
int rc_conf_int_def(rc_handle const *rh, char const *optname, int def);

#endif
