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
 * Links against libradcli_static: add_msg_auth_attr()/radcli_avp_encode_rfc2865()
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

#include <radcli/radcli.h>
#include <radcli/radcli2.h>
#include <includes.h> /* add_msg_auth_attr() */
#include "avp.h" /* radcli_avp_encode_rfc2865() */
#include "rc-md5.h"

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
	rc_handle *reentrant_rh; /* if set, call radcli_ctx_dispatch(reentrant_rh) from the handler */
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
	int check_nas_result;
};

static void counting_handler(radcli_dae_request *req, void *user)
{
	struct handler_state *st = (struct handler_state *)user;
	const char *s;

	st->calls++;
	st->last_code = radcli_dae_req_code(req);
	if (st->reentrant_rh != NULL)
		st->reentrant_ret = radcli_ctx_dispatch(st->reentrant_rh);

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
	st->check_nas_result = radcli_dae_req_check_nas(req);

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
static size_t build_packet(rc_handle *rh, uint8_t code, uint8_t id, const char *secret,
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

	encoded_len = radcli_avp_encode_rfc2865(rh, attrs, secret, auth->vector, auth->data,
					cap - AUTH_HDR_LEN - reserve, NULL);
	assert(encoded_len >= 0);
	total_length = AUTH_HDR_LEN + encoded_len;
	auth->length = htons((uint16_t)total_length);

	if (with_ma)
		total_length = add_msg_auth_attr(rh, (char *)secret, auth, total_length);

	memcpy(buf + total_length, secret, secretlen);
	rc_md5_calc(digest, buf, (size_t)total_length + secretlen);
	memcpy(auth->vector, digest, AUTH_VECTOR_LEN);

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

static rc_handle *setup_dae(const char *dae_server, int max_clock_skew,
			    radcli_dae **dae_out, int *fd_out, struct sockaddr_in *dest)
{
	rc_handle *rh = rc_new();
	radcli_dae *dae;
	int fd;
	unsigned events;
	int timeout_ms;
	socklen_t slen;
	char skew[16];

	assert(rh != NULL);
	rc_config_init(rh);
	assert(rc_read_dictionary_from_buffer(rh, test_dict, sizeof(test_dict)) == 0);
	assert(rc_add_config(rh, "dae-accept", "udp", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-server", dae_server, "config", 0) == 0);
	assert(rc_add_config(rh, "dae-secret", "testing123", "config", 0) == 0);
	assert(rc_add_config(rh, "dae-listen", "127.0.0.1:0", "config", 0) == 0);
	snprintf(skew, sizeof(skew), "%d", max_clock_skew);
	assert(rc_add_config(rh, "dae-max-clock-skew", skew, "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);

	dae = radcli_dae_new(rh);
	assert(dae != NULL);
	assert(radcli_dae_start(dae) == 0);
	assert(radcli_ctx_get_poll(rh, &fd, &events, &timeout_ms) == 0);
	assert(fd >= 0);

	memset(dest, 0, sizeof(*dest));
	slen = sizeof(*dest);
	assert(getsockname(fd, (struct sockaddr *)dest, &slen) == 0);
	dest->sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &dest->sin_addr);

	*dae_out = dae;
	*fd_out = fd;
	return rh;
}

int main(int argc, char **argv)
{
	rc_handle *rh;
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

	rh = setup_dae("127.0.0.1", 60, &dae, &dae_fd, &dest);
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

	d_user = radcli_dict_lookup(rh, "User-Name");
	d_proxy = radcli_dict_lookup(rh, "Proxy-State");
	d_ts = radcli_dict_lookup(rh, "Event-Timestamp");
	d_ec = radcli_dict_lookup(rh, "Error-Cause");
	d_sessid = radcli_dict_lookup(rh, "Acct-Session-Id");
	d_framedip = radcli_dict_lookup(rh, "Framed-IP-Address");
	d_nasport = radcli_dict_lookup(rh, "NAS-Port");
	d_nasid = radcli_dict_lookup(rh, "NAS-Identifier");
	assert(d_user && d_proxy && d_ts && d_ec);
	assert(d_sessid && d_framedip && d_nasport && d_nasid);

	/* --- 1: a well-formed Disconnect-Request is ACKed, with mirrored
	 * Proxy-State and a correct Response Authenticator --- */
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "alice") == 0);
	assert(radcli_avp_add_bytes(attrs, d_proxy, "state-42", 8) == 0);
	pktlen = build_packet(rh, RADCLI_DISCONNECT_REQUEST, 10, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);

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
	assert(radcli_ctx_dispatch(rh) == 0);
	if (st.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: a bad Request Authenticator was not silently discarded\n");
		exit(1);
	}

	/* --- 3: a bad Message-Authenticator is a silent discard --- */
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "bob") == 0);
	pktlen = build_packet(rh, RADCLI_DISCONNECT_REQUEST, 11, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	pkt[pktlen - 1] ^= 0xff; /* last byte of the Message-Authenticator's HMAC */
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
	if (st.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: a bad Message-Authenticator was not silently discarded\n");
		exit(1);
	}

	/* --- 4: a valid packet from an unauthorized source is discarded
	 * before any crypto -- simulated with a dae-server ACL that does not
	 * include 127.0.0.1, the only source address this test can send
	 * from --- */
	{
		rc_handle *rh2;
		radcli_dae *dae2;
		int fd2;
		struct sockaddr_in dest2;
		struct handler_state st2;

		rh2 = setup_dae("192.0.2.1", 60, &dae2, &fd2, &dest2);
		memset(&st2, 0, sizeof(st2));
		radcli_dae_set_handler(dae2, counting_handler, &st2);

		attrs = radcli_avp_list_new();
		assert(radcli_avp_add_str(attrs, d_user, "eve") == 0);
		pktlen = build_packet(rh2, RADCLI_DISCONNECT_REQUEST, 1, "testing123", attrs, 1, pkt, sizeof(pkt));
		radcli_avp_list_free(attrs);

		assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest2, sizeof(dest2)) == (ssize_t)pktlen);
		assert(radcli_ctx_dispatch(rh2) == 0);
		if (st2.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
			fprintf(stderr, "error: a request from an unauthorized source was not discarded\n");
			exit(1);
		}

		radcli_dae_free(dae2);
		rc_dict_free(rh2);
		rc_destroy(rh2);
	}

	/* --- 5: a retransmission (identical Identifier, source port, and
	 * Request Authenticator) is answered from the cached decision
	 * without invoking the handler again --- */
	st.calls = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "carol") == 0);
	pktlen = build_packet(rh, RADCLI_DISCONNECT_REQUEST, 20, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
	if (st.calls != 1 || poll_recv(client_fd, reply, sizeof(reply), 500) < AUTH_HDR_LEN) {
		fprintf(stderr, "error: the original request in the retransmission test was not answered\n");
		exit(1);
	}

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
	n = poll_recv(client_fd, reply, sizeof(reply), 500);
	if (st.calls != 1) {
		fprintf(stderr, "error: a retransmission invoked the handler a second time\n");
		exit(1);
	}
	if (n < AUTH_HDR_LEN || reply[0] != RADCLI_DISCONNECT_ACK || reply[1] != 20) {
		fprintf(stderr, "error: the retransmission was not answered identically\n");
		exit(1);
	}

	/* --- 6: a duplicate arriving while the original is still PENDING an
	 * application decision is discarded silently; the deferred reply,
	 * issued later, is still delivered and recorded --- */
	st.calls = 0;
	st.defer = 1;
	st.deferred = NULL;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "dave") == 0);
	pktlen = build_packet(rh, RADCLI_COA_REQUEST, 30, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
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
	assert(radcli_ctx_dispatch(rh) == 0);
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
	pktlen = build_packet(rh, RADCLI_DISCONNECT_REQUEST, 40, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
	if (st.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: a stale Event-Timestamp was not silently discarded\n");
		exit(1);
	}

	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "frank") == 0);
	assert(radcli_avp_add_uint32(attrs, d_ts, (uint32_t)time(NULL)) == 0);
	pktlen = build_packet(rh, RADCLI_DISCONNECT_REQUEST, 41, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
	if (st.calls != 1 || poll_recv(client_fd, reply, sizeof(reply), 500) < AUTH_HDR_LEN) {
		fprintf(stderr, "error: a fresh Event-Timestamp was rejected\n");
		exit(1);
	}

	/* --- 8: an unhandled packet code (e.g. Accounting-Request) is a
	 * silent discard (REQ-DAE-ERR-001) --- */
	st.calls = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "gina") == 0);
	pktlen = build_packet(rh, 4 /* Accounting-Request */, 50, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
	if (st.calls != 0 || poll_recv(client_fd, reply, sizeof(reply), 200) >= 0) {
		fprintf(stderr, "error: an unhandled packet code was not silently discarded\n");
		exit(1);
	}

	/* --- 9: radcli_ctx_dispatch() rejects a reentrant call from within
	 * a handler it invoked (REQ-DAE-SEC-012), and still answers the
	 * outer request normally afterwards --- */
	st.calls = 0;
	st.reentrant_rh = rh;
	st.reentrant_ret = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "henry") == 0);
	pktlen = build_packet(rh, RADCLI_DISCONNECT_REQUEST, 60, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);
	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
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
	st.reentrant_rh = NULL;

	/* --- 10: session-selector accessors read back what the request
	 * carried --- */
	assert(rc_add_config(rh, "nas-identifier", "nas1.example.org", "config", 0) == 0);
	assert(rc_add_config(rh, "nas-ip", "10.0.0.5", "config", 0) == 0);
	assert(rc_apply_config(rh) == 0);

	st.calls = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "capture-test") == 0);
	assert(radcli_avp_add_str(attrs, d_sessid, "sess-123") == 0);
	{
		struct in_addr ia;
		inet_pton(AF_INET, "192.0.2.42", &ia);
		assert(radcli_avp_add_ipaddr(attrs, d_framedip, ia) == 0);
	}
	assert(radcli_avp_add_uint32(attrs, d_nasport, 7) == 0);
	assert(radcli_avp_add_str(attrs, d_nasid, "nas1.example.org") == 0);
	pktlen = build_packet(rh, RADCLI_DISCONNECT_REQUEST, 70, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
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
	if (st.check_nas_result != 0) {
		fprintf(stderr, "error: radcli_dae_req_check_nas() reported a mismatch for the "
				"correctly-named NAS\n");
		exit(1);
	}
	poll_recv(client_fd, reply, sizeof(reply), 500); /* drain the ACK */

	/* --- 11: radcli_dae_req_check_nas() reports a mismatch when
	 * NAS-Identifier names a different NAS --- */
	st.calls = 0;
	attrs = radcli_avp_list_new();
	assert(radcli_avp_add_str(attrs, d_user, "ivy") == 0);
	assert(radcli_avp_add_str(attrs, d_nasid, "some-other-nas") == 0);
	pktlen = build_packet(rh, RADCLI_DISCONNECT_REQUEST, 71, "testing123", attrs, 1, pkt, sizeof(pkt));
	radcli_avp_list_free(attrs);

	assert(sendto(client_fd, pkt, pktlen, 0, (struct sockaddr *)&dest, sizeof(dest)) == (ssize_t)pktlen);
	assert(radcli_ctx_dispatch(rh) == 0);
	if (st.calls != 1 || st.check_nas_result == 0) {
		fprintf(stderr, "error: radcli_dae_req_check_nas() did not report a mismatch for "
				"a different NAS-Identifier\n");
		exit(1);
	}
	/* radcli_dae_req_nas_port()/_framed_ip() correctly report absence:
	 * this request carried neither. */
	if (st.has_framed_ip || st.has_nas_port) {
		fprintf(stderr, "error: radcli_dae_req_framed_ip()/_nas_port() reported presence "
				"for attributes this request did not carry\n");
		exit(1);
	}
	poll_recv(client_fd, reply, sizeof(reply), 500); /* drain the ACK */

	/* --- 12/13/14: the L0 buffer entry point (radcli_dae_process()/
	 * radcli_dae_reply_to_buffer()) -- a separate handle, since it needs
	 * no radcli_dae_start() (no socket at all). --- */
	{
		rc_handle *rh_l0 = rc_new();
		radcli_dae *dae_l0;
		struct sockaddr_in fake_from;
		radcli_dae_request *req;
		uint8_t reply1[RC_BUFFER_LEN], reply2[RC_BUFFER_LEN];
		size_t reply1_len, reply2_len;
		int ret;

		assert(rh_l0 != NULL);
		rc_config_init(rh_l0);
		assert(rc_read_dictionary_from_buffer(rh_l0, test_dict, sizeof(test_dict)) == 0);
		assert(rc_add_config(rh_l0, "dae-accept", "udp", "config", 0) == 0);
		assert(rc_add_config(rh_l0, "dae-server", "127.0.0.1", "config", 0) == 0);
		assert(rc_add_config(rh_l0, "dae-secret", "testing123", "config", 0) == 0);
		assert(rc_apply_config(rh_l0) == 0);
		dae_l0 = radcli_dae_new(rh_l0);
		assert(dae_l0 != NULL);
		/* Deliberately no radcli_dae_start(): L0 needs no socket. */

		memset(&fake_from, 0, sizeof(fake_from));
		fake_from.sin_family = AF_INET;
		inet_pton(AF_INET, "127.0.0.1", &fake_from.sin_addr);
		fake_from.sin_port = htons(54321);

		/* --- 12: a new, valid request --- */
		attrs = radcli_avp_list_new();
		assert(radcli_avp_add_str(attrs, d_user, "l0-user") == 0);
		pktlen = build_packet(rh_l0, RADCLI_DISCONNECT_REQUEST, 80, "testing123", attrs, 1,
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

		radcli_dae_free(dae_l0);
		rc_dict_free(rh_l0);
		rc_destroy(rh_l0);
	}

	(void)d_ec;
	close(client_fd);
	radcli_dae_free(dae);
	rc_dict_free(rh);
	rc_destroy(rh);

	printf("dae-codec: all tests passed\n");
	return 0;
}
