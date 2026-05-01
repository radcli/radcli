/*
 * util.h        Utility structures and prototypes.
 *
 * License:	BSD
 *
 */

#ifndef UTIL_H
# define UTIL_H

#include <string.h>

/* Asserts must never be compiled out in security-sensitive parsing code. */
#undef NDEBUG
#include <assert.h>

#ifdef HAVE_GNUTLS
# include <gnutls/gnutls.h>
#endif

/* __has_feature is a Clang built-in; provide a no-op fallback for GCC. */
#ifndef __has_feature
# define __has_feature(x) 0
#endif

/* Constant-time memory comparison for security-sensitive data.
 * Uses gnutls_memcmp() when GnuTLS is available, falls back to memcmp(). */
static inline int rc_memcmp(const void *s1, const void *s2, size_t n)
{
#ifdef HAVE_GNUTLS
	return gnutls_memcmp(s1, s2, n);
#else
	return memcmp(s1, s2, n);
#endif
}

/* Use rc_strlcpy when there is no system strlcpy, or when compiling under MSan:
 * glibc's strlcpy has no MSan interceptor so it leaves shadow bits unset. */
#if !defined(HAVE_STRLCPY) || __has_feature(memory_sanitizer)
# define RC_NEED_STRLCPY 1
size_t rc_strlcpy(char *dst, char const *src, size_t siz);
# define strlcpy rc_strlcpy
#endif

#include <includes.h>

#define	SA(p)	((struct sockaddr *)(p))

#if !defined(SA_LEN)
#define SA_LEN(sa) \
  (((sa)->sa_family == AF_INET) ? \
    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#define SS_LEN(sa) \
  (((sa)->ss_family == AF_INET) ? \
    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif

#define SA_GET_INADDR(sa) \
  (((sa)->sa_family == AF_INET) ? \
    ((void*)&(((struct sockaddr_in*)(sa))->sin_addr)) : ((void*)&(((struct sockaddr_in6*)(sa))->sin6_addr)))

#define SA_GET_INLEN(sa) \
  ((sa)->sa_family == AF_INET) ? \
    sizeof(struct in_addr) : sizeof(struct in6_addr)

/* flags to rc_getaddrinfo() */
#define PW_AI_PASSIVE		1
#define PW_AI_AUTH		(1<<1)
#define PW_AI_ACCT		(1<<2)

struct addrinfo *rc_getaddrinfo (char const *host, unsigned flags);
void rc_own_bind_addr(rc_handle *rh, struct sockaddr_storage *lia);
double rc_getmtime(void);
void rc_str2tm (char const *valstr, struct tm *tm);
int rc_set_netns(const char *net_namespace, int *prev_ns_handle);
int rc_reset_netns(int *prev_ns_handle);

#undef rc_log

#ifdef _MSC_VER /* TODO: Fix me */
# define rc_log(...)
#else

# ifdef __GNUC__
#  define rc_log(prio, fmt, ...) \
	syslog(prio, "radcli: %s: "fmt, __func__, ##__VA_ARGS__)
# else
#  define rc_log syslog
# endif
#endif

extern unsigned int radcli_debug;

#define		DEBUG(args...)	if(radcli_debug) rc_log(args)

/* sk_buff-style packet buffer.
 *
 *  head ──► +──────────────────+
 *           │  RADIUS header   │  (pre-filled by caller for outgoing packets)
 *  data ──► +──────────────────+  read/parse cursor
 *           │  attribute data  │
 *  tail ──► +──────────────────+  write cursor
 *           │   tailroom       │
 *   end ──► +──────────────────+  hard capacity limit (never moves)
 *
 * head and end are set once at initialisation and never modified.
 * tail advances on writes; data advances on reads/parses.
 *   pb_written() == tail - head  (total bytes built, incl. header)
 *   pb_len()     == tail - data  (unread/unconsumed bytes)
 *   pb_tailroom()== end  - tail  (free write space)
 */
typedef struct {
	uint8_t *head;  /* immutable: start of raw buffer                    */
	uint8_t *data;  /* read/parse cursor: start of unconsumed data        */
	uint8_t *tail;  /* write cursor: end of written data                  */
	uint8_t *end;   /* immutable: hard capacity limit                     */
} pkt_buf;

/* --- init ---------------------------------------------------------------- */

/* Write mode: head/data/tail all start at buf; end = buf + cap. */
static inline void pb_init(pkt_buf *pb, void *buf, size_t cap)
{
	pb->head = pb->data = pb->tail = (uint8_t *)buf;
	pb->end  = pb->head + cap;
}

/* Read mode: head/data = buf; tail = buf + len (data already received);
 * end = buf + cap. */
static inline void pb_init_read(pkt_buf *pb, void *buf, size_t len, size_t cap)
{
	pb->head = pb->data = (uint8_t *)buf;
	pb->tail = pb->head + len;
	pb->end  = pb->head + cap;
}

/* --- measurement --------------------------------------------------------- */

static inline size_t pb_written(const pkt_buf *pb)  /* total bytes head..tail */
	{ return (size_t)(pb->tail - pb->head); }

static inline size_t pb_len(const pkt_buf *pb)      /* unread bytes data..tail */
	{ return (size_t)(pb->tail - pb->data); }

static inline size_t pb_tailroom(const pkt_buf *pb) /* free bytes tail..end */
	{ return (size_t)(pb->end - pb->tail); }

/* --- write helpers (advance tail) ---------------------------------------- */

static inline int pb_put_byte(pkt_buf *pb, uint8_t v)
{
	if (pb->tail >= pb->end) return -1;
	*pb->tail++ = v;
	return 0;
}

static inline int pb_put_bytes(pkt_buf *pb, const void *src, int n)
{
	if (n < 0 || pb->tail + n > pb->end) return -1;
	memcpy(pb->tail, src, n);
	pb->tail += n;
	return 0;
}

/* Reserve n bytes at tail; return pointer to the reserved region, or NULL on
 * overflow.  The caller patches the content after writing surrounding data. */
static inline uint8_t *pb_put_reserve(pkt_buf *pb, int n)
{
	if (n <= 0 || pb->tail + n > pb->end) return NULL;
	uint8_t *p = pb->tail;
	pb->tail += n;
	return p;
}

/* --- read/parse helpers (advance data) ----------------------------------- */

/* Consume n bytes from the front.  Returns -1 if fewer than n bytes remain. */
static inline int pb_pull(pkt_buf *pb, int n)
{
	if (n < 0 || pb->data + n > pb->tail) return -1;
	pb->data += n;
	return 0;
}

/* Peek at one byte at data[offset] without advancing.  Returns -1 on OOB. */
static inline int pb_peek_byte(const pkt_buf *pb, int offset, uint8_t *out)
{
	if (offset < 0 || pb->data + offset >= pb->tail) return -1;
	*out = pb->data[offset];
	return 0;
}

/* Encode 'len' bytes from 'src' as uppercase hex into 'dst' (size 'dst_size').
 * dst_size must be at least 2*len+1. Returns a pointer to the terminating NUL. */
static inline char *rc_bin2hex(char *dst, size_t dst_size, const uint8_t *src, size_t len)
{
	static const char hx[] = "0123456789ABCDEF";
	assert(dst_size >= 2 * len + 1);
	while (len--) {
		*dst++ = hx[(*src >> 4) & 0xf];
		*dst++ = hx[ *src       & 0xf];
		src++;
	}
	*dst = '\0';
	return dst;
}

#endif /* UTIL_H */

