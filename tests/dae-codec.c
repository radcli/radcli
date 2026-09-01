/*
 * Copyright (c) 2026, Nikos Mavrogiannopoulos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Unit test for radcli_ctx_dispatch()'s RFC 5176 validation pipeline
 * (lib/dae.c): REQ-DAE-NET-002, REQ-DAE-SEC-001..006, REQ-DAE-SEC-008.
 * Plays a hostile DAC over a real loopback UDP socket (127.0.0.1, an
 * OS-assigned ephemeral port learned via radcli_ctx_get_poll()'s fd and
 * getsockname() -- both public API, no radcli_dae_fd() needed), so this
 * exercises the exact wire path a real FreeRADIUS-driven DAC would use.
 * Needs no root and no external server.
 *
 * Links against libradcli_static: add_msg_auth_attr()/radcli_avp_encode()
 * are internal-only (include/includes.h, lib/avp.h), the same reason
 * tests/avp-codec.c and tests/pack.c do.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>

#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include <includes.h> /* add_msg_auth_attr() */
#include "avp.h" /* radcli_avp_encode() */
#include "rc-crypto.h"

static char test_dict[] =
"ATTRIBUTE	User-Name		1	string\n"
"ATTRIBUTE	NAS-IP-Address		4	ipaddr\n"
"ATTRIBUTE	NAS-Port		5	integer\n"
"ATTRIBUTE	Framed-IP-Address	8	ipaddr\n"
"ATTRIBUTE	NAS-Identifier		32	string\n"
"ATTRIBUTE	Proxy-State		33	string\n"
"ATTRIBUTE	Acct-Session-Id		44	string\n"
"ATTRIBUTE	Event-Timestamp		55	date\n"
"ATTRIBUTE	Message-Authenticator	80	string\n"
"ATTRIBUTE	Error-Cause		101	integer\n";

struct handler_state {
	int calls;
	radcli_code last_code;
	int defer; /* if set, do not reply from the handler */
	radcli_dae_request *deferred; /* saved when defer is set */
	radcli_ctx *reentrant_ctx; /* if set, call radcli_ctx_dispatch(reentrant_ctx) from the handler */
	int reentrant_ret; /* that call's return value */

	/* captured on every call, for the session-selector accessor tests */
	char session_id[64];
	int has_session_id;
	char user_name[64];
	int has_user_name;
	struct sockaddr_storage framed_ip;
	int has_framed_ip;
	uint32_t nas_port;
	int has_nas_port;
};

static void counting_handler(radcli_dae_request *req, void *user)
{
	struct handler_state *st = (struct handler_state *)user;
	const char *s;

	st->calls++;
	st->last_code = radcli_dae_req_code(req);
	if (st->reentrant_ctx != NULL)
		st->reentrant_ret = radcli_ctx_dispatch(st->reentrant_ctx);

	s = radcli_dae_req_session_id(req);
	st->has_session_id = (s != NULL);
	if (s != NULL)
		snprintf(st->session_id, sizeof(st->session_id), "%s", s);
	s = radcli_dae_req_user_name(req);
	st->has_user_name = (s != NULL);
	if (s != NULL)
		snprintf(st->user_name, sizeof(st->user_name), "%s", s);
	st->has_framed_ip = (radcli_dae_req_framed_ip(req, &st->framed_ip) == 0);
	st->has_nas_port = (radcli_dae_req_nas_port(req, &st->nas_port) == 0);

	if (st->defer) {
		st->deferred = req; /* caller frees/replies later */
		return;
	}
	radcli_dae_reply(req, 1); /* ACK */
	radcli_dae_request_free(req);
}

/* Builds a Disconnect-Request/CoA-Request packet the way a real DAC would:
 * Message-Authenticator (if requested) computed with the Authenticator
 * field treated as sixteen zero octets, then the real Request Authenticator
 * hashed over the finished packet (RFC 5176 SS2.3, RFC 2869 SS5.14 -- the
 * Accounting-Request convention). */
static size_t build_packet(radcli_ctx *ctx, uint8_t code, uint8_t id, const char *secret,
			   radcli_avp_list *attrs, int with_ma, uint8_t *buf, size_t cap)
{
	AUTH_HDR *auth = (AUTH_HDR *)buf;
	int encoded_len, total_length;
	size_t secretlen = strlen(secret);
	uint8_t digest[AUTH_VECTOR_LEN];
	size_t reserve = with_ma ? (2 + 16) : 0;

	auth->code = code;
	auth->id = id;
	memset(auth->vector, 0, AUTH_VECTOR_LEN);

	encoded_len = radcli_avp_encode(ctx, attrs, secret, auth->vector, auth->data,
					cap - AUTH_HDR_LEN - reserve, NULL);
	assert(encoded_len >= 0);
	total_length = AUTH_HDR_LEN + encoded_len;
	auth->length = htons((uint16_t)total_length);

	if (with_ma)
		total_length = add_msg_auth_attr(ctx, (char *)secret, auth, total_length);

	memcpy(buf + total_length, secret, secretlen);
	rc_md5_calc(digest, buf, (size_t)total_length + secretlen);
	memcpy(auth->vector, digest, AUTH_VECTOR_LEN);

	assert(total_length > 0);
	return (size_t)total_length;
}

/* Independently recomputes and checks a reply's Response Authenticator
 * (RFC 5176 SS2.3, REQ-DAE-SEC-008): MD5(header-with-request-vector +
 * attrs + secret) must equal the Authenticator field actually sent. */
static int response_authenticator_ok(const uint8_t *reply, size_t len,
				     const uint8_t request_authenticator[AUTH_VECTOR_LEN],
				     const char *secret)
{
	uint8_t copy[RC_BUFFER_LEN];
	uint8_t received[AUTH_VECTOR_LEN], calc[AUTH_VECTOR_LEN];
	size_t secretlen = strlen(secret);

	if (len + secretlen > sizeof(copy))
		return 0;
	memcpy(copy, reply, len);
	memcpy(received, copy + 4, AUTH_VECTOR_LEN);
	memcpy(copy + 4, request_authenticator, AUTH_VECTOR_LEN);
	memcpy(copy + len, secret, secretlen);
	rc_md5_calc(calc, copy, len + secretlen);
	return memcmp(received, calc, AUTH_VECTOR_LEN) == 0;
}

static int poll_recv(int fd, void *buf, size_t cap, int timeout_ms)
{
	struct pollfd pfd;
	int ret;

	pfd.fd = fd;
	pfd.events = POLLIN;
	ret = poll(&pfd, 1, timeout_ms);
	if (ret <= 0)
		return -1;
	return (int)recv(fd, buf, cap, 0);
}

static radcli_ctx *setup_dae(const char *dae_server, int max_clock_skew,
			    radcli_dae **dae_out, int *fd_out, struct sockaddr_in *dest)
{
	radcli_ctx *ctx = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
	radcli_dae *dae;
	struct pollfd pfds[RADCLI_CTX_MAX_POLLFDS];
	size_t nfds;
	int fd;
	int timeout_ms;
	socklen_t slen;

	assert(ctx != NULL);
	assert(radcli_ctx_read_dictionary_from_buffer(ctx, test_dict, sizeof(test_dict)) == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_ACCEPT, "udp") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SERVER, dae_server) == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_DAE_LISTEN, "127.0.0.1:0") == 0);
	assert(radcli_ctx_set_opt_int(ctx, RADCLI_OPT_DAE_MAX_CLOCK_SKEW, max_clock_skew) == 0);
	assert(radcli_ctx_apply(ctx) == 0);

	dae = radcli_dae_new(ctx, 0);
	assert(dae != NULL);
	assert(radcli_dae_start(dae) == 0);
	assert(radcli_ctx_get_poll(ctx, pfds, RADCLI_CTX_MAX_POLLFDS, &nfds, &timeout_ms) == 0);
	assert(nfds == 1);
	fd = pfds[0].fd;
	assert(fd >= 0);

	memset(dest, 0, sizeof(*dest));
	slen = sizeof(*dest);
	assert(getsockname(fd, (struct sockaddr *)dest, &slen) == 0);
	dest->sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &dest->sin_addr);

	*dae_out = dae;
	*fd_out = fd;
	return ctx;
}

int main(int argc, char **argv)
{
	radcli_ctx *ctx;
	radcli_dae *dae;
	int dae_fd, client_fd;
	struct sockaddr_in dest;
	struct handler_state st;
	const radcli_attr_def *d_user, *d_proxy, *d_ts, *d_ec;
	const radcli_attr_def *d_sessid, *d_framedip, *d_nasport, *d_nasid;
	radcli_avp_list *attrs;
	uint8_t pkt[RC_BUFFER_LEN], reply[RC_BUFFER_LEN];
	size_t pktlen;
	int n;

	ctx = setup_dae("127.0.0.1", 60, &dae, &dae_fd, &dest);
	memset(&st, 0, sizeof(st));
	radcli_dae_set_handler(dae, counting_handler, &st);

	client_fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(client_fd >= 0);
	{
		struct sockaddr_in any;
		memset(&any, 0, sizeof(any));
		any.sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &any.sin_addr);
		assert(bind(client_fd, (struct sockaddr *)&any, sizeof(any)) == 0);
	}

	d_user = radcli_dict_lookup(ctx, "User-Name");
	d_proxy = radcli_dict_lookup(ctx, "Proxy-State");
	d_ts = radcli_dict_lookup(ctx, "Event-Timestamp");
	d_ec = radcli_dict_lookup(ctx, "Error-Cause");
	d_sessid = radcli_dict_lookup(ctx, "Acct-Session-Id");
	d_framedip = radcli_dict_lookup(ctx, "Framed-IP-Address");
	d_nasport = radcli_dict_lookup(ctx, "NAS-Port");
	d_nasid = radcli_dict_lookup(ctx, "NAS-Identifier");
	assert(d_user && d_proxy && d_ts && d_ec);
	assert(d_sessid && d_framedip && d_nasport && d_nasid);

	/* --- 1: a well-formed Disconnect-Request is ACKed, with mirrored
	 * Proxy-State and a correct Response Authenticator --- */
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "alice") == 0);
	assert(radcli_avp_add_bytes(attrs, d_proxy, "state-42", 8) == 0);
	pktlen = build_packet(ctx, RADCLI_DISCONNECT_REQUEST, 10, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);

	if (st.calls != 1 || st.last_code != RADCLI_DISCONNECT_REQUEST) {
		fprintf(stderr, "error: handler was not invoked exactly once for a valid request\n");
		exit(1);
	}
	n = poll_recv(client_fd, reply, sizeof(reply), 500);
	if (n < AUTH_HDR_LEN) {
		fprintf(stderr, "error: no ACK reply received for a valid Disconnect-Request\n");
		exit(1);
	}
	if (reply[0] != RADCLI_DISCONNECT_ACK || reply[1] != 10) {
		fprintf(stderr, "error: reply code/id mismatch (code=%d id=%d)\n", reply[0], reply[1]);
		exit(1);
	}
	if (memmem(reply, (size_t)n, "state-42", 8) == NULL) {
		fprintf(stderr, "error: reply did not mirror the request's Proxy-State\n");
		exit(1);
	}
	{
		uint8_t zero[AUTH_VECTOR_LEN];
		memset(zero, 0, sizeof(zero));
		/* pkt's own Authenticator field (offset 4) is the real Request
		 * Authenticator the DAC sent -- what the Response Authenticator
		 * must be computed over. */
		if (!response_authenticator_ok(reply, (size_t)n, pkt + 4, "testing123")) {
			fprintf(stderr, "error: reply's Response Authenticator does not verify\n");
			exit(1);
		}
	}

	/* --- 2: a bad Request Authenticator is a silent discard --- */
	st.calls = 0;
	pkt[4] ^= 0xff; /* corrupt after the fact: build_packet() already finalized it */
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: a bad Request Authenticator was not silently discarded\n");
		exit(1);
	}

	/* --- 3: a bad Message-Authenticator is a silent discard --- */
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "bob") == 0);
	pktlen = build_packet(ctx, RADCLI_DISCONNECT_REQUEST, 11, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	pkt[pktlen - 1] ^= 0xff; /* last byte of the Message-Authenticator's HMAC */
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: a bad Message-Authenticator was not silently discarded\n");
		exit(1);
	}

	/* --- 4: a valid packet from an unauthorized source is discarded
	 * before any crypto -- simulated with a dae-server ACL that does not
	 * include 127.0.0.1, the only source address this test can send
	 * from --- */
	{
		radcli_ctx *ctx2;
		radcli_dae *dae2;
		int fd2;
		struct sockaddr_in dest2;
		struct handler_state st2;

		ctx2 = setup_dae("192.0.2.1", 60, &dae2, &fd2, &dest2);
		memset(&st2, 0, sizeof(st2));
		radcli_dae_set_handler(dae2, counting_handler, &st2);

		attrs = radcli_avp_list_new();
		assert(radcli_avp_add_str(attrs, d_user, "eve") == 0);
		pktlen = build_packet(ctx2, RADCLI_DISCONNECT_REQUEST, 1, "testing123", attrs, 1, pkt, sizeof(pkt));
		radcli_avp_list_free(attrs);

		assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest2, sizeof(dest2)) == (ssize_t)pktlen);
		assert(radcli_ctx_dispatch(ctx2) == 0);
		if (st2.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
			fprintf(stderr, "error: a request from an unauthorized source was not discarded\n");
			exit(1);
		}

		radcli_dae_free(dae2);
		radcli_ctx_free(ctx2);
	}

	/* --- 5: a retransmission (identical Identifier, source port, and
	 * Request Authenticator) is answered from the cached decision
	 * without invoking the handler again --- */
	st.calls = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "carol") == 0);
	pktlen = build_packet(ctx, RADCLI_DISCONNECT_REQUEST, 20, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 1 || poll_recv(client_fd, reply, sizeof(reply), 500) < AUTH_HDR_LEN) {
		fprintf(stderr, "error: the original request in the retransmission test was not answered\n");
		exit(1);
	}

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	n = poll_recv(client_fd, reply, sizeof(reply), 500);
	if (st.calls != 1) {
		fprintf(stderr, "error: a retransmission invoked the handler a second time\n");
		exit(1);
	}
	if (n < AUTH_HDR_LEN || reply[0] != RADCLI_DISCONNECT_ACK || reply[1] != 20) {
		fprintf(stderr, "error: the retransmission was not answered identically\n");
		exit(1);
	}

	/* --- 5b: the SAME retransmission (identical Identifier, Request
	 * Authenticator, and Message-Authenticator -- byte-for-byte the same
	 * packet), but sent from a different, spoofable UDP source port,
	 * must still be recognised as a duplicate of the already-ANSWERED
	 * request above and answered from the cached decision, not
	 * delivered to the handler again: RFC 5176 SS2.3's match tuple is
	 * (source address, source port, Identifier, Request Authenticator),
	 * but the Request Authenticator is itself a keyed hash over the
	 * whole packet, so the address+Identifier+Authenticator alone is
	 * already unforgeable without the shared secret -- adding the
	 * source port narrows the match instead of strengthening it, since
	 * an off-path attacker replaying a captured packet controls it
	 * freely. --- */
	{
		int client_fd2;
		struct sockaddr_in any2;

		client_fd2 = socket(AF_INET, SOCK_DGRAM, 0);
		assert(client_fd2 >= 0);
		memset(&any2, 0, sizeof(any2));
		any2.sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &any2.sin_addr);
		assert(bind(client_fd2, (struct sockaddr *)&any2, sizeof(any2)) == 0);

		assert(sendto(client_fd2, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) ==
		      (ssize_t)pktlen);
		assert(radcli_ctx_dispatch(ctx) == 0);
		n = poll_recv(client_fd2, reply, sizeof(reply), 500);
		if (st.calls != 1) {
			fprintf(stderr, "error: a retransmission from a different source port "
					"invoked the handler a second time (SEC-005 match must not "
					"depend on the source port)\n");
			exit(1);
		}
		if (n < AUTH_HDR_LEN || reply[0] != RADCLI_DISCONNECT_ACK || reply[1] != 20) {
			fprintf(stderr, "error: the cross-port retransmission was not answered "
					"from the cached decision\n");
			exit(1);
		}
		close(client_fd2);
	}

	/* --- 5c: the SAME retransmission again, this time spoofed as
	 * arriving from a DIFFERENT configured dae-server entry that shares
	 * the same secret (the common, no-:secret-override case) rather than
	 * a different port on the same entry -- must still be recognised as
	 * a duplicate. Request/Message-Authenticator never include the
	 * source address in their hash input, so the address was never part
	 * of the cryptographic proof; if duplicate-suppression state were
	 * still partitioned per configured sender, this would land in a
	 * different, empty slot table and bypass suppression exactly like
	 * 5b did before source port was dropped from the match. Uses
	 * radcli_dae_process() (L0) rather than a real socket, since sending
	 * from two distinct source addresses needs more than one local
	 * interface. --- */
	{
		radcli_ctx *ctx3;
		radcli_dae *dae3;
		struct sockaddr_in fromA, fromB;
		radcli_dae_request *req3;
		uint8_t pkt3[RC_BUFFER_LEN];
		size_t pkt3len;
		int ret3;

		ctx3 = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		assert(ctx3 != NULL);
		assert(radcli_ctx_read_dictionary_from_buffer(ctx3, test_dict, sizeof(test_dict)) == 0);
		assert(radcli_ctx_set_opt_str(ctx3, RADCLI_OPT_DAE_ACCEPT, "udp") == 0);
		/* Two authorized senders, no per-entry :secret override. */
		assert(radcli_ctx_set_opt_str(ctx3, RADCLI_OPT_DAE_SERVER, "192.0.2.1,192.0.2.2") == 0);
		assert(radcli_ctx_set_opt_str(ctx3, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
		assert(radcli_ctx_apply(ctx3) == 0);
		dae3 = radcli_dae_new(ctx3, 0);
		assert(dae3 != NULL);
		/* radcli_dae_process() (L0) never invokes a registered handler --
		 * only radcli_ctx_dispatch() does -- so correctness here is
		 * entirely in ret3, not in any handler call count. */

		attrs = radcli_avp_list_new();
		assert(radcli_avp_add_str(attrs, d_user, "frank") == 0);
		pkt3len = build_packet(ctx3, RADCLI_DISCONNECT_REQUEST, 25, "testing123", attrs, 1,
				       pkt3, sizeof(pkt3));
		radcli_avp_list_free(attrs);

		memset(&fromA, 0, sizeof(fromA));
		fromA.sin_family = AF_INET;
		fromA.sin_port = htons(1234);
		inet_pton(AF_INET, "192.0.2.1", &fromA.sin_addr);

		req3 = NULL;
		ret3 = radcli_dae_process(dae3, pkt3, pkt3len, (struct sockaddr *)&fromA,
					  sizeof(fromA), &req3);
		if (ret3 != RADCLI_DAE_NEW || req3 == NULL) {
			fprintf(stderr, "error: radcli_dae_process() did not accept the original "
					"request in the cross-DAC replay test\n");
			exit(1);
		}
		radcli_dae_reply(req3, 1);
		radcli_dae_request_free(req3);

		memset(&fromB, 0, sizeof(fromB));
		fromB.sin_family = AF_INET;
		fromB.sin_port = htons(1234);
		inet_pton(AF_INET, "192.0.2.2", &fromB.sin_addr);

		req3 = NULL;
		ret3 = radcli_dae_process(dae3, pkt3, pkt3len, (struct sockaddr *)&fromB,
					  sizeof(fromB), &req3);
		if (ret3 != RADCLI_DAE_DUPLICATE) {
			fprintf(stderr, "error: replaying a captured packet spoofed as arriving "
					"from a different dae-server entry sharing the same secret "
					"was not recognised as a duplicate (ret=%d)\n", ret3);
			exit(1);
		}
		if (req3 != NULL)
			radcli_dae_request_free(req3);

		radcli_dae_free(dae3);
		radcli_ctx_free(ctx3);
	}

	/* --- 6: a duplicate arriving while the original is still PENDING an
	 * application decision is discarded silently; the deferred reply,
	 * issued later, is still delivered and recorded --- */
	st.calls = 0;
	st.defer = 1;
	st.deferred = NULL;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "dave") == 0);
	pktlen = build_packet(ctx, RADCLI_COA_REQUEST, 30, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 1 || st.deferred == NULL) {
		fprintf(stderr, "error: the handler was not invoked (or did not defer) for the PENDING test\n");
		exit(1);
	}
	if (poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: a reply was sent before the deferred handler answered\n");
		exit(1);
	}

	/* same Identifier/port/Request Authenticator: a genuine retransmission,
	 * arriving while PENDING. */
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 1 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: a duplicate arriving during PENDING was not silently discarded\n");
		exit(1);
	}

	if (radcli_dae_reply_error(st.deferred, RADCLI_ERROR_SESSION_CONTEXT_NOT_FOUND) != 0) {
		fprintf(stderr, "error: the deferred radcli_dae_reply_error() call failed\n");
		exit(1);
	}
	radcli_dae_request_free(st.deferred);
	st.deferred = NULL;
	n = poll_recv(client_fd, reply, sizeof(reply), 500);
	if (n < AUTH_HDR_LEN || reply[0] != RADCLI_COA_NAK || reply[1] != 30) {
		fprintf(stderr, "error: the deferred reply was not delivered correctly\n");
		exit(1);
	}
	st.defer = 0;

	/* --- 7: a stale Event-Timestamp is a silent discard; a fresh one is
	 * accepted (dae-max-clock-skew=60 for this handle, set in setup_dae()) --- */
	st.calls = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "erin") == 0);
	assert(radcli_avp_add_uint32(attrs, d_ts, (uint32_t)(time(NULL) - 120)) == 0);
	pktlen = build_packet(ctx, RADCLI_DISCONNECT_REQUEST, 40, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: a stale Event-Timestamp was not silently discarded\n");
		exit(1);
	}

	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "frank") == 0);
	assert(radcli_avp_add_uint32(attrs, d_ts, (uint32_t)time(NULL)) == 0);
	pktlen = build_packet(ctx, RADCLI_DISCONNECT_REQUEST, 41, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 1 || poll_recv(client_fd, reply, sizeof(reply), 500) < AUTH_HDR_LEN) {
		fprintf(stderr, "error: a fresh Event-Timestamp was rejected\n");
		exit(1);
	}

	/* --- 8: an unhandled packet code (e.g. Accounting-Request) is a
	 * silent discard (REQ-DAE-ERR-001) --- */
	st.calls = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "gina") == 0);
	pktlen = build_packet(ctx, 4 /* Accounting-Request */, 50, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: an unhandled packet code was not silently discarded\n");
		exit(1);
	}

	/* --- 9: radcli_ctx_dispatch() rejects a reentrant call from within
	 * a handler it invoked (REQ-DAE-SEC-012), and still answers the
	 * outer request normally afterwards --- */
	st.calls = 0;
	st.reentrant_ctx = ctx;
	st.reentrant_ret = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "henry") == 0);
	pktlen = build_packet(ctx, RADCLI_DISCONNECT_REQUEST, 60, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 1 || st.reentrant_ret == 0) {
		fprintf(stderr, "error: a reentrant radcli_ctx_dispatch() call from within a "
				"handler was not rejected\n");
		exit(1);
	}
	if (poll_recv(client_fd, reply, sizeof(reply), 500) < AUTH_HDR_LEN) {
		fprintf(stderr, "error: the outer request was not still answered after the "
				"rejected reentrant call\n");
		exit(1);
	}
	st.reentrant_ctx = NULL;

	/* --- 10: session-selector accessors read back what the request
	 * carried --- */
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_NAS_IDENTIFIER, "nas1.example.org") == 0);
	assert(radcli_ctx_set_opt_str(ctx, RADCLI_OPT_NAS_IP, "10.0.0.5") == 0);
	assert(radcli_ctx_apply(ctx) == 0);

	st.calls = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "capture-test") == 0);
	assert(radcli_avp_add_str(attrs, d_sessid, "sess-123") == 0);
	{
		struct in_addr ia;
		inet_pton(AF_INET, "192.0.2.42", &ia);
		assert(radcli_avp_add_ip4(attrs, d_framedip, ia) == 0);
	}
	assert(radcli_avp_add_uint32(attrs, d_nasport, 7) == 0);
	assert(radcli_avp_add_str(attrs, d_nasid, "nas1.example.org") == 0);
	pktlen = build_packet(ctx, RADCLI_DISCONNECT_REQUEST, 70, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 1) {
		fprintf(stderr, "error: session-selector test: handler was not invoked\n");
		exit(1);
	}
	if (!st.has_session_id || strcmp(st.session_id, "sess-123") != 0) {
		fprintf(stderr, "error: radcli_dae_req_session_id() did not return \"sess-123\"\n");
		exit(1);
	}
	if (!st.has_user_name || strcmp(st.user_name, "capture-test") != 0) {
		fprintf(stderr, "error: radcli_dae_req_user_name() did not return \"capture-test\"\n");
		exit(1);
	}
	if (!st.has_framed_ip || st.framed_ip.ss_family != AF_INET) {
		fprintf(stderr, "error: radcli_dae_req_framed_ip() did not report an AF_INET address\n");
		exit(1);
	}
	{
		struct sockaddr_in *sin = (struct sockaddr_in *)&st.framed_ip;
		struct in_addr expect;
		inet_pton(AF_INET, "192.0.2.42", &expect);
		if (sin->sin_addr.s_addr != expect.s_addr) {
			fprintf(stderr, "error: radcli_dae_req_framed_ip() returned the wrong address\n");
			exit(1);
		}
	}
	if (!st.has_nas_port || st.nas_port != 7) {
		fprintf(stderr, "error: radcli_dae_req_nas_port() did not return 7\n");
		exit(1);
	}
	poll_recv(client_fd, reply, sizeof(reply), 500); /* drain the ACK */

	/* --- 11: a request naming a different NAS-Identifier than
	 * nas-identifier is NAKed automatically (REQ-DAE-SEC-018) with
	 * Error-Cause 403, and the handler is never invoked for it --- */
	st.calls = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "ivy") == 0);
	assert(radcli_avp_add_str(attrs, d_nasid, "some-other-nas") == 0);
	pktlen = build_packet(ctx, RADCLI_DISCONNECT_REQUEST, 71, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(ctx) == 0);
	if (st.calls != 0) {
		fprintf(stderr, "error: the handler was invoked for a mismatched NAS-Identifier\n");
		exit(1);
	}
	n = poll_recv(client_fd, reply, sizeof(reply), 500);
	if (n < AUTH_HDR_LEN || reply[0] != RADCLI_DISCONNECT_NAK || reply[1] != 71) {
		fprintf(stderr, "error: no NAK reply received for a mismatched NAS-Identifier\n");
		exit(1);
	}
	{
		const radcli_avp *a;
		uint32_t ec;
		radcli_avp_list *reply_attrs = NULL;

		assert(radcli_avp_decode(ctx, "testing123", reply + 4, reply + AUTH_HDR_LEN,
					 (size_t)n - AUTH_HDR_LEN, 0, &reply_attrs) == 0);
		a = radcli_avp_get(reply_attrs, d_ec, 0);
		if (a == NULL || radcli_avp_get_uint32(a, &ec) != 0 || ec != 403) {
			fprintf(stderr, "error: NAK for a mismatched NAS-Identifier did not carry "
					"Error-Cause 403\n");
			radcli_avp_list_free(reply_attrs);
			exit(1);
		}
		radcli_avp_list_free(reply_attrs);
	}

	/* --- 11b: the same mismatch, this time with RADCLI_DAE_NO_NAS_CHECK
	 * passed to radcli_dae_new(), confirms the flag actually disables the
	 * check: process_packet() must treat the request as an ordinary new
	 * request (RADCLI_DAE_NEW), not NAK it. Uses radcli_dae_process() (L0)
	 * like the 12/13/14 block below -- it never invokes a registered
	 * handler, so correctness here is entirely in the returned outcome,
	 * not any handler call count. --- */
	{
		radcli_ctx *ctx11b = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		radcli_dae *dae11b;
		const radcli_attr_def *d_user11b, *d_nasid11b;
		uint8_t pkt11b[RC_BUFFER_LEN];
		size_t pkt11blen;
		radcli_avp_list *attrs11b;
		struct sockaddr_in fake_from;
		radcli_dae_request *req11b = NULL;
		int ret11b;

		assert(ctx11b != NULL);
		assert(radcli_ctx_read_dictionary_from_buffer(ctx11b, test_dict, sizeof(test_dict)) == 0);
		assert(radcli_ctx_set_opt_str(ctx11b, RADCLI_OPT_DAE_ACCEPT, "udp") == 0);
		assert(radcli_ctx_set_opt_str(ctx11b, RADCLI_OPT_DAE_SERVER, "127.0.0.1") == 0);
		assert(radcli_ctx_set_opt_str(ctx11b, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
		assert(radcli_ctx_set_opt_str(ctx11b, RADCLI_OPT_NAS_IDENTIFIER, "nas1.example.org") == 0);
		assert(radcli_ctx_apply(ctx11b) == 0);
		dae11b = radcli_dae_new(ctx11b, RADCLI_DAE_NO_NAS_CHECK);
		assert(dae11b != NULL);

		d_user11b = radcli_dict_lookup(ctx11b, "User-Name");
		d_nasid11b = radcli_dict_lookup(ctx11b, "NAS-Identifier");
		assert(d_user11b && d_nasid11b);

		attrs11b = radcli_avp_list_new();
		assert(radcli_avp_add_str(attrs11b, d_user11b, "jack") == 0);
		assert(radcli_avp_add_str(attrs11b, d_nasid11b, "some-other-nas") == 0);
		pkt11blen = build_packet(ctx11b, RADCLI_DISCONNECT_REQUEST, 72, "testing123", attrs11b, 1,
					 pkt11b, sizeof(pkt11b));
		radcli_avp_list_free(attrs11b);

		memset(&fake_from, 0, sizeof(fake_from));
		fake_from.sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &fake_from.sin_addr);
		fake_from.sin_port = htons(11111);

		ret11b = radcli_dae_process(dae11b, pkt11b, pkt11blen, (struct sockaddr *)&fake_from,
					    sizeof(fake_from), &req11b);
		if (ret11b != RADCLI_DAE_NEW || req11b == NULL) {
			fprintf(stderr, "error: RADCLI_DAE_NO_NAS_CHECK did not disable the "
					"NAS-Identifier check\n");
			exit(1);
		}
		radcli_dae_request_free(req11b);

		radcli_dae_free(dae11b);
		radcli_ctx_free(ctx11b);
	}

	/* --- 12/13/14: the L0 buffer entry point (radcli_dae_process()/
	 * radcli_dae_reply_to_buffer()) -- a separate handle, since it needs
	 * no radcli_dae_start() (no socket at all). --- */
	{
		radcli_ctx *ctx_l0 = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		radcli_dae *dae_l0;
		struct sockaddr_in fake_from;
		radcli_dae_request *req;
		uint8_t reply1[RC_BUFFER_LEN], reply2[RC_BUFFER_LEN];
		size_t reply1_len, reply2_len;
		int ret;

		assert(ctx_l0 != NULL);
		assert(radcli_ctx_read_dictionary_from_buffer(ctx_l0, test_dict, sizeof(test_dict)) == 0);
		assert(radcli_ctx_set_opt_str(ctx_l0, RADCLI_OPT_DAE_ACCEPT, "udp") == 0);
		assert(radcli_ctx_set_opt_str(ctx_l0, RADCLI_OPT_DAE_SERVER, "127.0.0.1") == 0);
		assert(radcli_ctx_set_opt_str(ctx_l0, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
		assert(radcli_ctx_apply(ctx_l0) == 0);
		dae_l0 = radcli_dae_new(ctx_l0, 0);
		assert(dae_l0 != NULL);
		/* Deliberately no radcli_dae_start(): L0 needs no socket. */

		memset(&fake_from, 0, sizeof(fake_from));
		fake_from.sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &fake_from.sin_addr);
		fake_from.sin_port = htons(54321);

		/* --- 12: a new, valid request --- */
		attrs = radcli_avp_list_new();
		assert(radcli_avp_add_str(attrs, d_user, "l0-user") == 0);
		pktlen = build_packet(ctx_l0, RADCLI_DISCONNECT_REQUEST, 80, "testing123", attrs, 1,
				      pkt, sizeof(pkt));
		radcli_avp_list_free(attrs);

		req = NULL;
		ret = radcli_dae_process(dae_l0, pkt, pktlen, (struct sockaddr *)&fake_from,
					 sizeof(fake_from), &req);
		if (ret != RADCLI_DAE_NEW || req == NULL) {
			fprintf(stderr, "error: radcli_dae_process() did not return "
					"RADCLI_DAE_NEW for a valid new request\n");
			exit(1);
		}
		if (radcli_dae_req_code(req) != RADCLI_DISCONNECT_REQUEST) {
			fprintf(stderr, "error: radcli_dae_process()'s request has the wrong code\n");
			exit(1);
		}

		reply1_len = sizeof(reply1);
		if (radcli_dae_reply_to_buffer(req, 1, 0, reply1, &reply1_len) != 0) {
			fprintf(stderr, "error: radcli_dae_reply_to_buffer() failed for a new request\n");
			exit(1);
		}
		if (reply1[0] != RADCLI_DISCONNECT_ACK || reply1[1] != 80) {
			fprintf(stderr, "error: radcli_dae_reply_to_buffer()'s code/id is wrong\n");
			exit(1);
		}
		if (!response_authenticator_ok(reply1, reply1_len, pkt + 4, "testing123")) {
			fprintf(stderr, "error: radcli_dae_reply_to_buffer()'s Response "
					"Authenticator does not verify\n");
			exit(1);
		}
		radcli_dae_request_free(req);

		/* --- 12b: radcli_dae_reply_to_buffer()'s capacity check must
		 * reject every buffer too small to hold AUTH_HDR_LEN plus the
		 * Message-Authenticator attribute it always appends (2 +
		 * MD5_DIGEST_SIZE = 18 bytes), not just one shorter than the
		 * bare header -- an out_cap in [AUTH_HDR_LEN, AUTH_HDR_LEN +
		 * 18) used to reach an unguarded subtraction in build_reply()
		 * that underflowed to a huge size_t instead of failing. --- */
		{
			radcli_avp_list *attrs12b;
			uint8_t pkt12b[RC_BUFFER_LEN];
			size_t pkt12blen;
			uint8_t small_buf[64];
			size_t small_len;
			size_t cap;

			attrs12b = radcli_avp_list_new();
			assert(radcli_avp_add_str(attrs12b, d_user, "l0-user-cap") == 0);
			pkt12blen = build_packet(ctx_l0, RADCLI_DISCONNECT_REQUEST, 83, "testing123",
						 attrs12b, 1, pkt12b, sizeof(pkt12b));
			radcli_avp_list_free(attrs12b);

			req = NULL;
			ret = radcli_dae_process(dae_l0, pkt12b, pkt12blen,
						 (struct sockaddr *)&fake_from, sizeof(fake_from), &req);
			if (ret != RADCLI_DAE_NEW || req == NULL) {
				fprintf(stderr, "error: radcli_dae_process() did not return "
						"RADCLI_DAE_NEW for the capacity test's request\n");
				exit(1);
			}

			for (cap = 0; cap < AUTH_HDR_LEN + 2 + 16 /* MD5_DIGEST_SIZE */; cap++) {
				small_len = cap;
				if (radcli_dae_reply_to_buffer(req, 1, 0, small_buf, &small_len) != -1) {
					fprintf(stderr, "error: radcli_dae_reply_to_buffer() accepted "
							"an undersized buffer (cap=%zu)\n", cap);
					exit(1);
				}
			}

			small_len = sizeof(small_buf);
			if (radcli_dae_reply_to_buffer(req, 1, 0, small_buf, &small_len) != 0) {
				fprintf(stderr, "error: radcli_dae_reply_to_buffer() rejected a "
						"correctly sized buffer\n");
				exit(1);
			}
			radcli_dae_request_free(req);
		}

		/* --- 13: a retransmission is reported as RADCLI_DAE_DUPLICATE, and
		 * radcli_dae_reply_to_buffer() reproduces the cached ACK byte for
		 * byte regardless of the (wrong) ack/error_cause passed in --- */
		req = NULL;
		ret = radcli_dae_process(dae_l0, pkt, pktlen, (struct sockaddr *)&fake_from,
					 sizeof(fake_from), &req);
		if (ret != RADCLI_DAE_DUPLICATE || req == NULL) {
			fprintf(stderr, "error: radcli_dae_process() did not return "
					"RADCLI_DAE_DUPLICATE for a retransmission\n");
			exit(1);
		}
		reply2_len = sizeof(reply2);
		if (radcli_dae_reply_to_buffer(req, 0, 999, reply2, &reply2_len) != 0) {
			fprintf(stderr, "error: radcli_dae_reply_to_buffer() failed for a "
					"duplicate\n");
			exit(1);
		}
		if (reply2_len != reply1_len || memcmp(reply1, reply2, reply1_len) != 0) {
			fprintf(stderr, "error: radcli_dae_reply_to_buffer() did not reproduce "
					"the cached decision byte-for-byte for a duplicate\n");
			exit(1);
		}
		radcli_dae_request_free(req);

		/* --- 14: an invalid packet (bad Request Authenticator) is
		 * rejected, *req left NULL, exactly as radcli_ctx_dispatch()
		 * would silently discard it --- */
		pkt[4] ^= 0xff;
		req = (radcli_dae_request *)0x1; /* sentinel: must be reset to NULL */
		ret = radcli_dae_process(dae_l0, pkt, pktlen, (struct sockaddr *)&fake_from,
					 sizeof(fake_from), &req);
		if (ret != -1 || req != NULL) {
			fprintf(stderr, "error: radcli_dae_process() accepted a packet with a "
					"bad Request Authenticator\n");
			exit(1);
		}

		/* --- 15: an IPv4-mapped IPv6 source address (::ffff:127.0.0.1,
		 * as a dual-stack AF_INET6 listener delivers an IPv4 sender's
		 * packet) still matches a dae-server entry given as a plain
		 * IPv4 address -- otherwise every packet from an authorized
		 * IPv4 DAC would be silently unreachable whenever
		 * radcli_dae_start() happens to bind the AF_INET6 candidate
		 * (dae-listen unset, platform IPV6_V6ONLY default off). --- */
		{
			struct sockaddr_in6 mapped_from;
			radcli_avp_list *attrs15;
			uint8_t pkt15[RC_BUFFER_LEN];
			size_t pkt15len;

			memset(&mapped_from, 0, sizeof(mapped_from));
			mapped_from.sin6_family = AF_INET6;
			mapped_from.sin6_port = htons(54322);
			assert(inet_pton(AF_INET6, "::ffff:127.0.0.1", &mapped_from.sin6_addr) == 1);

			attrs15 = radcli_avp_list_new();
			assert(radcli_avp_add_str(attrs15, d_user, "l0-user-v4mapped") == 0);
			pkt15len = build_packet(ctx_l0, RADCLI_DISCONNECT_REQUEST, 81, "testing123",
						attrs15, 1, pkt15, sizeof(pkt15));
			radcli_avp_list_free(attrs15);

			req = NULL;
			ret = radcli_dae_process(dae_l0, pkt15, pkt15len,
						 (struct sockaddr *)&mapped_from,
						 sizeof(mapped_from), &req);
			if (ret != RADCLI_DAE_NEW || req == NULL) {
				fprintf(stderr, "error: radcli_dae_process() rejected a request "
						"from an IPv4-mapped IPv6 source address matching "
						"an IPv4 dae-server entry\n");
				exit(1);
			}
			radcli_dae_request_free(req);
		}

		/* --- 16: fromlen is caller-supplied here (unlike
		 * radcli_ctx_dispatch(), where recvfrom() sets it), and must be
		 * bounded before process_packet() trusts it enough to
		 * memcpy(&req->from, from, fromlen) into a fixed-size struct
		 * sockaddr_storage field: too large, too small for the declared
		 * family, or an unsupported family must all be rejected. The
		 * "from" backing buffer here is deliberately larger than any
		 * fromlen tested, so only radcli_dae_process()'s own bound is
		 * under test, not an out-of-bounds read on our side. --- */
		{
			uint8_t from_buf[2048];
			radcli_avp_list *attrs16;
			uint8_t pkt16[RC_BUFFER_LEN];
			size_t pkt16len;
			struct sockaddr_in *sin = (struct sockaddr_in *)from_buf;

			memset(from_buf, 0, sizeof(from_buf));
			sin->sin_family = AF_INET;
			sin->sin_port = htons(54323);
			inet_pton(AF_INET, "127.0.0.1", &sin->sin_addr);

			attrs16 = radcli_avp_list_new();
			assert(radcli_avp_add_str(attrs16, d_user, "l0-user-fromlen") == 0);
			pkt16len = build_packet(ctx_l0, RADCLI_DISCONNECT_REQUEST, 82, "testing123",
						attrs16, 1, pkt16, sizeof(pkt16));
			radcli_avp_list_free(attrs16);

			/* fromlen far larger than sizeof(struct sockaddr_storage) */
			req = (radcli_dae_request *)0x1;
			ret = radcli_dae_process(dae_l0, pkt16, pkt16len, (struct sockaddr *)from_buf,
						 sizeof(from_buf), &req);
			if (ret != -1 || req != NULL) {
				fprintf(stderr, "error: radcli_dae_process() accepted an oversized "
						"fromlen\n");
				exit(1);
			}

			/* fromlen too small to hold even a struct sockaddr_in */
			req = (radcli_dae_request *)0x1;
			ret = radcli_dae_process(dae_l0, pkt16, pkt16len, (struct sockaddr *)from_buf,
						 4, &req);
			if (ret != -1 || req != NULL) {
				fprintf(stderr, "error: radcli_dae_process() accepted an undersized "
						"fromlen\n");
				exit(1);
			}

			/* sa_family claims AF_INET6 but fromlen only covers a
			 * struct sockaddr_in -- reading/copying sockaddr_in6's
			 * full extent would run past the declared length. */
			sin->sin_family = AF_INET6;
			req = (radcli_dae_request *)0x1;
			ret = radcli_dae_process(dae_l0, pkt16, pkt16len, (struct sockaddr *)from_buf,
						 sizeof(struct sockaddr_in), &req);
			if (ret != -1 || req != NULL) {
				fprintf(stderr, "error: radcli_dae_process() accepted an "
						"AF_INET6 fromlen too short for struct "
						"sockaddr_in6\n");
				exit(1);
			}
			sin->sin_family = AF_INET;

			/* an unsupported address family, correctly sized */
			sin->sin_family = AF_UNIX;
			req = (radcli_dae_request *)0x1;
			ret = radcli_dae_process(dae_l0, pkt16, pkt16len, (struct sockaddr *)from_buf,
						 sizeof(struct sockaddr_in), &req);
			if (ret != -1 || req != NULL) {
				fprintf(stderr, "error: radcli_dae_process() accepted an "
						"unsupported address family\n");
				exit(1);
			}
			sin->sin_family = AF_INET;

			/* the same request, with a correctly bounded fromlen, is
			 * still accepted -- the guard rejects only what it should. */
			req = NULL;
			ret = radcli_dae_process(dae_l0, pkt16, pkt16len, (struct sockaddr *)from_buf,
						 sizeof(struct sockaddr_in), &req);
			if (ret != RADCLI_DAE_NEW || req == NULL) {
				fprintf(stderr, "error: radcli_dae_process() rejected a "
						"correctly bounded fromlen\n");
				exit(1);
			}
			radcli_dae_request_free(req);
		}

		radcli_dae_free(dae_l0);
		radcli_ctx_free(ctx_l0);
	}

	/* --- 17: REQ-DAE-INIT-004 -- a dae-server hostname is resolved once
	 * at radcli_dae_new() time, and every resulting address is
	 * authorized. "localhost" is used instead of a real network hostname
	 * so this needs no DNS access, only the system's own
	 * /etc/hosts-or-equivalent NSS "files" source; on a host where it
	 * resolves to only one family, the other half of this test is
	 * skipped rather than failed, since that is an environment property,
	 * not a radcli one. --- */
	{
		radcli_ctx *ctx17 = radcli_ctx_new(RADCLI_CTX_NO_BUILTIN_DICT);
		radcli_dae *dae17;
		radcli_dae_request *req;
		radcli_avp_list *attrs17;
		uint8_t pkt17[RC_BUFFER_LEN], pkt17b[RC_BUFFER_LEN];
		size_t pkt17len, pkt17blen;
		int ret;
		int saw_v4 = 0, saw_v6 = 0;
		struct addrinfo hints, *res, *rp;

		assert(ctx17 != NULL);
		assert(radcli_ctx_read_dictionary_from_buffer(ctx17, test_dict, sizeof(test_dict)) == 0);
		assert(radcli_ctx_set_opt_str(ctx17, RADCLI_OPT_DAE_ACCEPT, "udp") == 0);
		assert(radcli_ctx_set_opt_str(ctx17, RADCLI_OPT_DAE_SERVER, "localhost") == 0);
		assert(radcli_ctx_set_opt_str(ctx17, RADCLI_OPT_DAE_SECRET, "testing123") == 0);
		assert(radcli_ctx_apply(ctx17) == 0);
		dae17 = radcli_dae_new(ctx17, 0);
		assert(dae17 != NULL);

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		if (getaddrinfo("localhost", NULL, &hints, &res) == 0) {
			for (rp = res; rp != NULL; rp = rp->ai_next) {
				if (rp->ai_family == AF_INET)
					saw_v4 = 1;
				else if (rp->ai_family == AF_INET6)
					saw_v6 = 1;
			}
			freeaddrinfo(res);
		}

		attrs17 = radcli_avp_list_new();
		assert(radcli_avp_add_str(attrs17, d_user, "l0-user-localhost") == 0);
		pkt17len = build_packet(ctx17, RADCLI_DISCONNECT_REQUEST, 90, "testing123",
					attrs17, 1, pkt17, sizeof(pkt17));
		radcli_avp_list_free(attrs17);

		/* A distinct Identifier for the second (::1) send: duplicate
		 * suppression matches on Identifier+Authenticator alone,
		 * deliberately ignoring source address (REQ-DAE-SEC-005) --
		 * reusing pkt17 here would make the second call a duplicate of
		 * the first rather than a second, independently authorized
		 * new request. */
		attrs17 = radcli_avp_list_new();
		assert(radcli_avp_add_str(attrs17, d_user, "l0-user-localhost-v6") == 0);
		pkt17blen = build_packet(ctx17, RADCLI_DISCONNECT_REQUEST, 91, "testing123",
					 attrs17, 1, pkt17b, sizeof(pkt17b));
		radcli_avp_list_free(attrs17);

		if (saw_v4) {
			struct sockaddr_in from4;

			memset(&from4, 0, sizeof(from4));
			from4.sin_family = AF_INET;
			from4.sin_port = htons(54324);
			inet_pton(AF_INET, "127.0.0.1", &from4.sin_addr);

			req = NULL;
			ret = radcli_dae_process(dae17, pkt17, pkt17len, (struct sockaddr *)&from4,
						 sizeof(from4), &req);
			if (ret != RADCLI_DAE_NEW || req == NULL) {
				fprintf(stderr, "error: radcli_dae_process() rejected a request "
						"from 127.0.0.1 with dae-server=localhost\n");
				exit(1);
			}
			radcli_dae_request_free(req);
		}

		if (saw_v6) {
			struct sockaddr_in6 from6;

			memset(&from6, 0, sizeof(from6));
			from6.sin6_family = AF_INET6;
			from6.sin6_port = htons(54325);
			inet_pton(AF_INET6, "::1", &from6.sin6_addr);

			req = NULL;
			ret = radcli_dae_process(dae17, pkt17b, pkt17blen, (struct sockaddr *)&from6,
						 sizeof(from6), &req);
			if (ret != RADCLI_DAE_NEW || req == NULL) {
				fprintf(stderr, "error: radcli_dae_process() rejected a request "
						"from ::1 with dae-server=localhost\n");
				exit(1);
			}
			radcli_dae_request_free(req);
		}

		if (!saw_v4 && !saw_v6) {
			fprintf(stderr, "warning: \"localhost\" resolved to neither an IPv4 "
					"nor an IPv6 address on this system; REQ-DAE-INIT-004 "
					"test skipped\n");
		}

		radcli_dae_free(dae17);
		radcli_ctx_free(ctx17);
	}

	/* --- 18: REQ-DAE-ERR-003 -- radcli_dae_reply()/_reply_error() return a
	 * distinguishable error (-1) when the reply cannot be transmitted,
	 * rather than reporting success for a reply that was silently
	 * dropped. Forced here by closing the dae's own socket out from
	 * under a still-PENDING (deferred) request before answering it: the
	 * fd radcli_ctx_get_poll() reports is the same one build_reply()'s
	 * sendto() would use, so closing it makes that sendto() fail with
	 * EBADF. A fresh ctx/dae/socket is used so this doesn't disturb the
	 * fd the rest of this file's tests still depend on. --- */
	{
		radcli_ctx *ctx18;
		radcli_dae *dae18;
		int dae_fd18, client_fd18;
		struct sockaddr_in dest18;
		struct handler_state st18;
		radcli_avp_list *attrs18;
		uint8_t pkt18[RC_BUFFER_LEN];
		size_t pkt18len;

		ctx18 = setup_dae("127.0.0.1", 60, &dae18, &dae_fd18, &dest18);
		memset(&st18, 0, sizeof(st18));
		st18.defer = 1;
		radcli_dae_set_handler(dae18, counting_handler, &st18);

		client_fd18 = socket(AF_INET, SOCK_DGRAM, 0);
		assert(client_fd18 >= 0);

		attrs18 = radcli_avp_list_new();
		assert(radcli_avp_add_str(attrs18, d_user, "err003-user") == 0);
		pkt18len = build_packet(ctx18, RADCLI_DISCONNECT_REQUEST, 95, "testing123",
					attrs18, 1, pkt18, sizeof(pkt18));
		radcli_avp_list_free(attrs18);

		assert(sendto(client_fd18, pkt18, pkt18len, 0, (struct sockaddr *)&dest18,
			     sizeof(dest18)) == (ssize_t)pkt18len);
		if (radcli_ctx_dispatch(ctx18) != 0) {
			fprintf(stderr, "error: radcli_ctx_dispatch() failed for the "
					"REQ-DAE-ERR-003 request\n");
			exit(1);
		}
		if (st18.calls != 1 || st18.deferred == NULL) {
			fprintf(stderr, "error: the handler was not invoked (or did not "
					"defer) for the REQ-DAE-ERR-003 test\n");
			exit(1);
		}

		assert(close(dae_fd18) == 0);

		if (radcli_dae_reply(st18.deferred, 1) != -1) {
			fprintf(stderr, "error: radcli_dae_reply() did not report an error "
					"after its socket was closed\n");
			exit(1);
		}
		radcli_dae_request_free(st18.deferred);

		/* radcli_dae_free() below still closes dae18's own idea of its fd
		 * (dae_fd18's number) -- reopen that number onto /dev/null first so
		 * that close() lands on a descriptor this process legitimately
		 * owns, rather than risking a double-close of whatever unrelated
		 * fd the kernel may have already reissued that number to. */
		{
			int devnull = open("/dev/null", O_RDONLY);
			assert(devnull >= 0);
			if (devnull != dae_fd18) {
				assert(dup2(devnull, dae_fd18) == dae_fd18);
				close(devnull);
			}
		}

		close(client_fd18);
		radcli_dae_free(dae18);
		radcli_ctx_free(ctx18);
	}

	(void)d_ec;
	close(client_fd);
	radcli_dae_free(dae);
	radcli_ctx_free(ctx);

	printf("dae-codec: all tests passed\n");
	return 0;
}
