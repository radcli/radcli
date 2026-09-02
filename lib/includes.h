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
#include <time.h>

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

#include <pthread.h> /* struct radcli_reqreg's lock (REQ-NET2-SEND-016);
                       * radcli threads are still never spawned by radcli
                       * itself (REQ-GEN-SEC-002) -- this only guards
                       * instance state a caller's own threads may share. */

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

struct radcli_dae_st; /* lib/dae.c; opaque here, ctx just tracks the pointer */
struct radcli_dict; /* lib/dict2.h; opaque here, ctx just tracks the pointer.
		      * Per-attribute encrypt_type/has_tag/gigawords_attrid --
		      * formerly side lists (dict_encrypt_flag/
		      * dict_counter64_pair) keyed by DICT_ATTR identity, kept
		      * separate only because the public DICT_ATTR struct
		      * (include/radcli/radcli.h) could never change layout --
		      * are now plain fields on dict2.h's own
		      * struct radcli_dict_attr, which carries no such
		      * constraint. */

/* One octet (RFC 2865 SS3) -- a hard protocol ceiling on how many
 * RADCLI_REQUEST_SENDONLY exchanges can share one socket/session
 * concurrently, not a tunable. REQ-NET2-SEND-016. */
#define RADCLI_CTX_MAX_INFLIGHT 256

struct radcli_async_send_st; /* defined below; forward-declared for the
                               * owner pointer in struct radcli_reqreg_slot */

/* One in-flight RADCLI_REQUEST_SENDONLY exchange, sharing ctx's persistent
 * request socket (UDP, rh->req_fd) or session fd (TLS/DTLS,
 * sfuncs->get_active_fd()) with every other concurrently in-flight
 * RADCLI_REQUEST_SENDONLY exchange on the same ctx -- REQ-NET2-SEND-016.
 * The slot index *is* the RADIUS Identifier this exchange was assigned
 * (both are the same 256-entry space, deliberately, so no separate mapping
 * is needed). owner is written to directly by
 * radcli2_priv_reqreg_drain()/_service_timeouts() (lib/sendserver.c) on
 * delivery, rather than through a callback, since struct
 * radcli_async_send_st is fully defined in this same header. */
struct radcli_reqreg_slot {
	unsigned valid; /* 1 once reserved (radcli2_priv_reqreg_reserve()),
	                 * until vacated */
	unsigned armed; /* 1 once radcli_transport_send_async() has filled
	                 * peer/secret/vector/send_buf below and sent the first
	                 * copy -- a reserved-but-not-yet-armed slot (the brief
	                 * window between reserving an Identifier, for
	                 * radcli_encode_request()'s Message-Authenticator to
	                 * cover, and the first successful send) is excluded
	                 * from drain()/service_timeouts() */
	uint64_t free_seq; /* LRU stamp, bumped on vacate; 0 = never used yet,
	                    * which sorts first -- RFC 5080 SS2.1.1 LRU
	                    * allocation, REQ-NET2-SEND-016 */
	struct radcli_async_send_st *owner;
	struct sockaddr_storage peer;
	socklen_t peer_len;
	uint8_t send_buf[RC_BUFFER_LEN]; /* retained for identical retransmits */
	int send_len;
	unsigned char vector[AUTH_VECTOR_LEN];
	char secret[MAX_SECRET_LENGTH + 1];
	char server_name[128]; /* for log messages only */
	unsigned short svc_port;
	rc_type type;
	int timeout; /* per-attempt, seconds */
	int retries_left;
	double deadline; /* rc_getmtime() value of the next retransmit/timeout */
};

/* ctx-owned registry backing every RADCLI_REQUEST_SENDONLY exchange on this
 * ctx (REQ-NET2-SEND-016); allocated lazily on the first such call
 * (lib/sendserver.c's reqreg_ensure()), freed only by
 * radcli2_priv_destroy(). Instance state on rh, never library-global
 * (REQ-GEN-SEC-005). */
struct radcli_reqreg {
	struct radcli_reqreg_slot slots[RADCLI_CTX_MAX_INFLIGHT];
	uint64_t free_seq_ctr;
	pthread_mutex_t lock;
};

struct rc_conf
{
	struct _option		*config_options;
	struct sockaddr_storage	nas_addr;
	unsigned		nas_addr_set;

	struct sockaddr_storage	own_bind_addr;
	unsigned		own_bind_addr_set;

	 /* we keep a copy of the filename to avoid re-reading a dictionary,
	  * for applications relying on the old API which required explicit
	  * load of it. Independent of dict's own lifetime: rc_dict_free()
	  * (lib/dict2.c) MUST NOT clear this (REQ-DICT-DATA-008) -- only
	  * rc_config_free() does, via rc_destroy(). */
	char			*first_dict_read;
	struct radcli_dict	*dict; /* lib/dict2.h; NULL until first load */

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

	/* radcli2.h's RADCLI_REQUEST_SENDONLY request registry (REQ-NET2-SEND-016):
	 * req_fd is ctx's persistent, unconnected UDP request socket, shared by
	 * every concurrently in-flight RADCLI_REQUEST_SENDONLY request on this
	 * ctx -- opened lazily on the first such call that needs one (-1 until
	 * then), never used for TLS/DTLS (which reuses its own session fd,
	 * sfuncs->get_active_fd(), instead), kept open for ctx's own lifetime
	 * and closed only by radcli2_priv_destroy(). reqreg is the in-flight
	 * registry backing it (also used, for the slot/Identifier bookkeeping
	 * only, by TLS/DTLS), allocated lazily alongside via
	 * reqreg_ensure()/reqreg_init_lock (lib/sendserver.c) -- guarding the
	 * lazy allocation itself, since reqreg_init_lock is always initialized
	 * (radcli2_priv_new()) even before reqreg exists. */
	int			req_fd;
	struct radcli_reqreg	*reqreg;
	pthread_mutex_t		reqreg_init_lock;

	/* radcli2.h's radcli_ctx_set_tls_psk(): TLS PSK identity/key for the
	 * new API's single-server context, set directly as bytes -- distinct
	 * from SERVER->secret[]'s "psk@user@hexkey" string convention
	 * (lib/tls.c's rc_init_tls(), still used by the legacy authserver-line
	 * path). tls_psk_identity is heap-allocated and NUL-terminated (GnuTLS'
	 * own PSK identity parameter is a plain C string); tls_psk_key is raw
	 * key bytes, tls_psk_key_len its length. Both NULL/0 until set;
	 * rc_init_tls() prefers this pair over authservers->secret[0] when set. */
	char			*tls_psk_identity;
	void			*tls_psk_key;
	size_t			tls_psk_key_len;

	/* debug verbosity for this handle's DEBUG()/rc_log() output (lib/util.h);
	 * 0 disables it. Set via the "clientdebug" config key (lib/config.c) or,
	 * for legacy callers, pre-seeded from rc_setdebug() at handle-construction
	 * time (lib/legacy/compat.c) -- see REQ-GEN-SEC-005. */
	unsigned		debug;
};

/* older compilers don't like seeing this typedef along with the one in radcli.h */
struct rc_aaa_ctx_st
{
	char	secret[MAX_SECRET_LENGTH + 1]; //!< The secret used for this request
	uint8_t	request_vector[AUTH_VECTOR_LEN]; //< The auth vector used in this request
};

int rc_send_server_ctx (rc_handle *rh, RC_AAA_CTX **ctx, SEND_DATA *data,
                        char *msg, rc_type type, int no_wait);

/* Projection between radcli_avp_list and VALUE_PAIR, internal only. */
int radcli_avp_list_to_value_pairs(rc_handle const *rh, const radcli_avp_list *list, VALUE_PAIR **out);
int radcli_value_pairs_to_avp_list(rc_handle const *rh, VALUE_PAIR *vp, radcli_avp_list **out);

/* Exposed (no longer static) so radcli_transport_exchange() can reuse the
 * exact RFC 2865 SS3 Response Authenticator and Message-Authenticator/
 * Blast-RADIUS logic rc_send_server_ctx() uses, rather than a second,
 * independently-written copy of security-sensitive code. None of the five
 * takes or returns a VALUE_PAIR; all operate on raw bytes, AUTH_HDR,
 * secret, and vector. */
int populate_ctx(RC_AAA_CTX **ctx, char secret[MAX_SECRET_LENGTH + 1],
		 uint8_t vector[AUTH_VECTOR_LEN]);

int rc_check_reply(AUTH_HDR *auth, int bufferlen, char const *secret,
		   unsigned char const *vector, uint8_t seq_nbr);

int add_msg_auth_attr(rc_handle *rh, char *secret, AUTH_HDR *auth, int total_length);

int radcli_encode_request(rc_handle *rh, uint8_t code, const radcli_avp_list *send,
			  char secret[MAX_SECRET_LENGTH + 1],
			  uint8_t send_buffer[RC_BUFFER_LEN], uint8_t id,
			  unsigned char vector_out[AUTH_VECTOR_LEN], int *out_len);

int validate_message_authenticator(const uint8_t *recv_buffer, size_t length,
				   const char *secret, const unsigned char *req_auth);

int radcli_transport_exchange(rc_handle *rh, RC_AAA_CTX **ctx,
			      char *server_name, unsigned short svc_port,
			      char secret[MAX_SECRET_LENGTH + 1], int mgmt_secret,
			      int timeout, int retries, int no_wait, rc_type type,
			      const uint8_t *send_buf, int send_len,
			      uint8_t *recv_buf, size_t recv_buf_cap, size_t *recv_len,
			      uint8_t *out_code);

/* Handle for one poll()-driven send-then-wait-for-reply cycle, started by
 * radcli_transport_send_async() and driven to completion by repeated calls
 * to radcli_transport_service_async(). lib/request.c embeds one of these by
 * value in struct radcli_request_st; internal only, never exposed through
 * radcli2.h.
 *
 * Unlike before REQ-NET2-SEND-016, this is now a thin handle into ctx's
 * shared in-flight registry (struct radcli_reqreg_slot, above), not an
 * independent, fully self-contained exchange with its own socket: the
 * slot -- keyed by the RADIUS Identifier this exchange was assigned --
 * holds the peer/secret/vector/send_buf/timeout/retry state and does the
 * actual retransmit/receive work, shared across every other concurrently
 * in-flight RADCLI_REQUEST_SENDONLY exchange on the same ctx.
 * result/reply_code/reply_attrs below are written to directly by
 * radcli2_priv_reqreg_drain()/_service_timeouts() (lib/sendserver.c) the
 * moment the slot resolves -- which may happen inside a *different*
 * radcli_request*'s own radcli_transport_service_async() call, since one
 * call drains every ready datagram on the shared socket/session, not just
 * this exchange's own. */
struct radcli_async_send_st {
	rc_handle *rh;
	int active; /* 1 from a successful radcli_transport_send_async() until
		     * radcli_transport_service_async() itself consumes a
		     * delivered result (below) and returns it -- deliberately
		     * NOT cleared at the moment delivered flips to 1, which can
		     * happen asynchronously inside a *different* exchange's own
		     * drain call; staying active in the meantime is what lets
		     * radcli_transport_async_abort() still find and free a
		     * delivered-but-never-read reply_attrs instead of leaking
		     * it. Also cleared by radcli_transport_async_abort(). */
	int slot;   /* index into rh->reqreg->slots[] == this exchange's
		     * RADIUS Identifier; meaningful only while active */
	int delivered; /* 1 once the registry has resolved this exchange's
	                * slot and written result/reply_code/reply_attrs below --
	                * independent of active, see above */
	int result;     /* OK_RC/REJECT_RC/CHALLENGE_RC/TIMEOUT_RC/ERROR_RC,
	                 * valid iff delivered */
	uint8_t reply_code;
	radcli_avp_list *reply_attrs; /* owned; valid iff delivered and result
	                               * is OK_RC/REJECT_RC/CHALLENGE_RC */
};

/* Sentinel returned only by radcli_transport_service_async(), meaning
 * "still waiting, call again after the caller's poll()/select() reports
 * ctx's fd ready or its deadline elapses". Deliberately not added to
 * radcli.h's public rc_send_status enum (NETUNREACH_RC..CHALLENGE_RC):
 * that enum documents rc_send_server()'s return values, and no public
 * function -- rc_send_server()/rc_auth()/rc_acct() included -- ever
 * returns this one. */
#define RADCLI_ASYNC_AGAIN 100

/* radcli_transport_send_async()/_service_async()/_async_abort() and the
 * radcli2_priv_reqreg_*() registry helpers below implement REQ-NET2-SEND-016. */
int radcli_transport_send_async(rc_handle *rh, int slot, char *server_name, unsigned short svc_port,
				char secret[MAX_SECRET_LENGTH + 1], rc_type type,
				const uint8_t *send_buf, int send_len,
				int timeout, int retries,
				struct radcli_async_send_st *out);

int radcli_transport_service_async(struct radcli_async_send_st *st, int fd_ready);

void radcli_transport_async_abort(struct radcli_async_send_st *st);

int radcli2_priv_reqreg_reserve(rc_handle *rh, struct radcli_async_send_st *owner, uint8_t *out_id);

void radcli2_priv_reqreg_release(rc_handle *rh, int slot);

int radcli2_priv_reqreg_earliest_deadline_ms(rc_handle *rh);

void radcli2_priv_reqreg_drain(rc_handle *rh);

void radcli2_priv_reqreg_service_timeouts(rc_handle *rh);

/* No longer public (radcli2.h). */
int radcli2_priv_dae_send_watchdog(radcli_ctx *ctx);

int radcli_do_exchange(rc_handle *rh, uint8_t code, const radcli_avp_list *send,
		       char *server, uint16_t svc_port, char secret[MAX_SECRET_LENGTH + 1],
		       int timeout, int retries, int no_wait, rc_type type,
		       uint8_t *recv_buffer, size_t recv_buffer_cap, size_t *recv_len,
		       unsigned char vector_out[AUTH_VECTOR_LEN], uint8_t *out_reply_code);

/* radcli.h public legacy symbols whose real implementation lives in a
 * libradcli2-bound file (lib/config.c, lib/dict2.c, lib/dict2-parse.c,
 * lib/tls.c): renamed to these radcli2_priv_* names so libradcli2-internal
 * callers (lib/config2.c, lib/dict2.c, lib/request.c, lib/dae.c,
 * lib/sendserver.c, lib/tls.c, lib/aaa2.c, lib/ip_util.c, ...) never call
 * the public rc_* name -- doing so would call across the library split in
 * the wrong direction once lib/legacy/compat.c's one-line wrappers (under
 * the original rc_* names, declared in radcli.h as before) are the only
 * thing defining those names for real. */
rc_handle *radcli2_priv_config_init(rc_handle *rh);
rc_handle *radcli2_priv_new(void);
void radcli2_priv_destroy(rc_handle *rh);
int radcli2_priv_add_config(rc_handle *rh, char const *option_name, char const *option_val,
			    char const *source, int line);
int radcli2_priv_apply_config(rc_handle *rh);
rc_handle *radcli2_priv_read_config(char const *filename, int skip_builtin_dict);
char *radcli2_priv_conf_str(rc_handle const *rh, char const *optname);
int radcli2_priv_conf_int(rc_handle const *rh, char const *optname);
SERVER *radcli2_priv_conf_srv(rc_handle const *rh, char const *optname);
int radcli2_priv_test_config(rc_handle *rh, char const *filename);
int radcli2_priv_find_server_addr(rc_handle const *rh, char const *server_name,
				  struct addrinfo **info, char *secret, rc_type type);
void radcli2_priv_config_free(rc_handle *rh);

int radcli2_priv_set_nonblock_cloexec(int fd);

void radcli2_priv_dict_free(rc_handle *rh);
int radcli2_priv_read_dictionary(rc_handle *rh, char const *filename);
int radcli2_priv_read_dictionary_from_buffer(rc_handle *rh, char const *buf, size_t size);
int radcli2_priv_load_builtin_dict(rc_handle *rh);

int radcli2_priv_tls_fd(rc_handle *rh);
int radcli2_priv_check_tls(rc_handle *rh);

time_t radcli2_priv_tls_last_msg(rc_handle *rh);
time_t radcli2_priv_tls_last_recv(rc_handle *rh);
int radcli2_priv_tls_force_reconnect(rc_handle *rh);
int radcli2_priv_tls_ensure_connected(rc_handle *rh);
int radcli2_priv_tls_dae_poll(rc_handle *rh, uint8_t *buf, size_t cap);
void radcli2_priv_tls_dae_poll_done(rc_handle *rh);
int radcli2_priv_tls_dae_send(rc_handle *rh, const void *buf, size_t len);
void radcli2_priv_dae_on_radsec_packet(rc_handle *rh, const uint8_t *buf, size_t len);
int radcli2_priv_tls_try_recv(rc_handle *rh, uint8_t *buf, size_t cap);

int radcli2_priv_get_srcaddr(struct sockaddr *lia, const struct sockaddr *ria);

#endif
