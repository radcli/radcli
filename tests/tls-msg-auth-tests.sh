#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# draft-ietf-radext-deprecating-radius-10 Section 4 requires that the BLAST
# RADIUS Message-Authenticator mitigations "MUST be applied to RADIUS/UDP
# and RADIUS/TCP, and MUST NOT be applied to RADIUS/TLS or RADIUS/DTLS"
# (those transports are already integrity-protected, so the MD5-prefix
# attack the mitigation defends against isn't reachable). This mirrors
# msg-auth-tests.sh, but over RADIUS/TLS, to confirm radcli does not
# require or position-check Message-Authenticator there, while it still
# opportunistically validates one if the server sends it (REQ-NET-SEC-006,
# unaffected by the transport scoping of REQ-NET-SEC-007).
#
# DTLS is not separately covered here: rc_send_server_ctx() branches on
# rh->so_type with a single `RC_SOCKET_TLS || RC_SOCKET_DTLS` check
# (lib/sendserver.c), and DTLS shares that whole function with TLS -- only
# rc_init_tls()'s flags argument differs between them. tests/radius-server.py
# only implements a UDP and a TLS listener, so DTLS is exercised structurally
# rather than with its own test server here.

srcdir="${srcdir:-.}"

echo "===== Message-Authenticator over RADIUS/TLS tests ====="
echo " 1. Client accepts response missing the attr (not required over TLS)"
echo " 2. Client accepts MA present but not first (not enforced over TLS)"
echo " 3. Client rejects a present-but-wrong MA (opportunistic check still applies)"
echo " 4. require-message-authenticator=no is a no-op over TLS (still accepts)"
echo "========================================================="

if ! python3 -c 'import ssl' 2>/dev/null; then
	echo "This test requires python3 with the ssl module"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
RADIUSPID=""

function finish {
	test -n "${RADIUSPID}" && kill ${RADIUSPID} >/dev/null 2>&1
	rm -f $TMPFILE
	rm -f radiusclient-temp$PID.conf
	rm -f radiusclient-no-req$PID.conf
	rm -f servers-temp$PID
}
trap finish EXIT

wait_for_server() {
	local i
	for i in 1 2 3 4 5 6 7 8; do
		check_if_port_in_use ${PORT} && return 0
		sleep 0.5
	done
	return 1
}

# Build a radiusclient.conf pointing to localhost:PORT over TLS. The
# configured secret is irrelevant -- RFC 6614 Section 3.4 fixes the
# RADIUS/TLS shared secret to "radsec", which radcli enforces regardless of
# what's in servers-temp$PID.
make_conf() {
	cat >radiusclient-temp$PID.conf <<EOF
serv-type tls
tls-ca-file ${srcdir}/dtls/ca.pem
tls-verify-hostname false
nas-identifier my-nas-id
authserver  127.0.0.1:${PORT}
acctserver  127.0.0.1:${PORT}
servers     ./servers-temp$PID
dictionary  ${srcdir}/../etc/dictionary
default_realm
radius_timeout  5
radius_retries  1
bindaddr    *
EOF
}

# Each call picks a fresh port: a killed TLS/TCP server can leave its old
# socket in TIME_WAIT, which would make check_if_port_in_use (netstat -an,
# which matches any socket state, not just LISTEN) report the port as
# already "in use" before the new server has actually bound it -- a race
# that doesn't affect the UDP server in msg-auth-tests.sh, which has no
# connection state to linger.
start_server() {
	eval "$GETPORT"
	make_conf
	python3 ${srcdir}/radius-server.py \
		--transport tls --port ${PORT} --secret radsec --msg-auth "$1" \
		--tls-cert ${srcdir}/raddb/cert-rsa.pem --tls-key ${srcdir}/raddb/key-rsa.pem \
		2>/dev/null &
	RADIUSPID=$!
	wait_for_server
}

stop_server() {
	if test -n "${RADIUSPID}"; then
		kill ${RADIUSPID} >/dev/null 2>&1
		wait ${RADIUSPID} 2>/dev/null
		RADIUSPID=""
	fi
}

echo "127.0.0.1	testing123" >servers-temp$PID

# Test 1: server sends no Message-Authenticator; over UDP this would fail by
# default (msg-auth-tests.sh test 1) -- over TLS it MUST succeed.
start_server absent
run_test "Accept response with absent MA over TLS" \
	"${top_builddir}/src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	|| exit 1

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0; then
	echo "[ FAIL ] Expected Framed-Protocol = 'PPP' in response"
	exit 1
fi

# Test 2: server sends a correct MA but not as the first attribute; over
# UDP this would fail by default (msg-auth-tests.sh test 4) -- over TLS the
# position requirement MUST NOT be enforced.
stop_server
start_server not-first
run_test "Accept response with correct MA not first, over TLS" \
	"${top_builddir}/src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	|| exit 1

# Test 3: server sends a Message-Authenticator with the wrong value. This is
# not the BLAST presence/position mitigation -- it's plain opportunistic
# validation (REQ-NET-SEC-006), which applies on every transport and MUST
# still reject.
stop_server
start_server wrong
run_test "Reject response with incorrect MA value over TLS" \
	"${top_builddir}/src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1

# Test 4: require-message-authenticator=no explicitly set over TLS changes
# nothing -- the presence/position check it would otherwise disable is
# already not enforced over TLS.
stop_server
start_server absent
cp radiusclient-temp$PID.conf radiusclient-no-req$PID.conf
echo "require-message-authenticator	no" >> radiusclient-no-req$PID.conf

run_test "Accept response with absent MA over TLS (require-message-authenticator=no)" \
	"${top_builddir}/src/radiusclient -D -i -f radiusclient-no-req$PID.conf User-Name=test Password=test" \
	|| exit 1
stop_server

echo ""
exit 0
