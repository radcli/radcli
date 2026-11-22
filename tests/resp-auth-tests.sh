#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== Response Authenticator verification (legacy API) ====="
echo " REQ-NET-SEC-004: rc_auth()/rc_acct() never act on a reply whose"
echo " Response Authenticator does not verify, and keep waiting for the"
echo " real reply instead (GHSA-v2f7-mw6g-gf89)."
echo " 1. Reject a bad Access-Accept with no Message-Authenticator required"
echo " 2. Reject a bad Access-Accept whose Message-Authenticator is valid"
echo " 3. Reject an Access-Accept signed with another shared secret"
echo " 4. Reject a bad Accounting-Response"
echo " 5. Accept the real Access-Accept after a forged Access-Reject"
echo " 6. Accept the real Accounting-Response after a forged Access-Reject"
echo "======================================================================"

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
LOG=radius-server-respauth-$PID.log
CONF=radiusclient-respauth$PID.conf
CONF_NO_MA=radiusclient-respauth-no-ma$PID.conf
SERVERS=servers-respauth$PID
RADIUSPID=""

eval "$GETPORT"

function finish {
	test -n "${RADIUSPID}" && kill ${RADIUSPID} >/dev/null 2>&1
	rm -f $TMPFILE $LOG $CONF $CONF_NO_MA $SERVERS
}
trap finish EXIT

# $1: the server's shared secret, remaining arguments: extra
# tests/radius-server.py options.
start_server() {
	local secret="$1" i
	shift
	python3 ${srcdir}/radius-server.py --port ${PORT} --secret "$secret" "$@" >$LOG 2>&1 &
	RADIUSPID=$!
	for i in 1 2 3 4 5 6 7 8; do
		check_if_port_in_use ${PORT} && return 0
		sleep 0.5
	done
	return 1
}

stop_server() {
	if test -n "${RADIUSPID}"; then
		kill ${RADIUSPID} >/dev/null 2>&1
		wait ${RADIUSPID} 2>/dev/null
		RADIUSPID=""
	fi
}

# A failure must be the request timing out, not an error or a reject
# decoded from the bad reply.
expect_timeout() {
	if ! grep -q "no reply from RADIUS" $TMPFILE; then
		echo "[ FAIL ] $1: the request did not end in a timeout"
		exit 1
	fi
}

cat >$CONF <<EOF
authserver  127.0.0.1:${PORT}
acctserver  127.0.0.1:${PORT}
servers     ./$SERVERS
dictionary  ${srcdir}/../etc/dictionary
radius_timeout  2
radius_retries  0
bindaddr    *
EOF
cp $CONF $CONF_NO_MA
echo "require-message-authenticator	no" >>$CONF_NO_MA
echo "127.0.0.1/127.0.0.1	testing123" >$SERVERS

AUTH="${top_builddir}/src/radiusclient -D -i -f"
ACCT="${top_builddir}/src/radiusclient -D -a -f"

# Test 1: the shape of GHSA-v2f7-mw6g-gf89 -- with no Message-Authenticator
# required, only the Response Authenticator stands between a forged
# Access-Accept and a successful login.
start_server testing123 --bad-resp-auth --msg-auth absent
run_test "Reject an Access-Accept with a bad Response Authenticator (MA not required)" \
	"$AUTH $CONF_NO_MA User-Name=test Password=test" expect_fail || exit 1
expect_timeout "Test 1"
stop_server

# Test 2: the Message-Authenticator verifies, so only the Response
# Authenticator check can reject the reply.
start_server testing123 --bad-resp-auth
run_test "Reject an Access-Accept with a bad Response Authenticator (valid MA)" \
	"$AUTH $CONF User-Name=test Password=test" expect_fail || exit 1
expect_timeout "Test 2"
stop_server

# Test 3: the advisory's reproducer -- client and server disagree on the
# shared secret.
start_server other-secret --msg-auth absent
run_test "Reject an Access-Accept signed with another shared secret" \
	"$AUTH $CONF_NO_MA User-Name=test Password=test" expect_fail || exit 1
expect_timeout "Test 3"
stop_server

# Test 4: an Accounting-Response carries no Message-Authenticator
# (REQ-NET-SEC-008), so this holds whatever the configuration.
start_server testing123 --bad-resp-auth
run_test "Reject an Accounting-Response with a bad Response Authenticator" \
	"$ACCT $CONF User-Name=test Acct-Status-Type=Start Acct-Session-Id=1" expect_fail || exit 1
expect_timeout "Test 4"
stop_server

# Test 5: the forged Access-Reject must neither be acted on nor end the
# wait (REQ-NET-NET-009).
start_server testing123 --forged-first --msg-auth absent
run_test "Accept the real Access-Accept after a forged Access-Reject" \
	"$AUTH $CONF_NO_MA User-Name=test Password=test" || exit 1
if ! grep -q "^Framed-Protocol *= 'PPP'$" $TMPFILE; then
	echo "[ FAIL ] Test 5: expected the Access-Accept's Framed-Protocol = 'PPP'"
	exit 1
fi
stop_server

# Test 6: the same for accounting.
start_server testing123 --forged-first
run_test "Accept the real Accounting-Response after a forged Access-Reject" \
	"$ACCT $CONF User-Name=test Acct-Status-Type=Start Acct-Session-Id=1" || exit 1
stop_server

echo ""
exit 0
