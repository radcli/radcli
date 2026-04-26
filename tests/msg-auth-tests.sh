#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== Message-Authenticator validation tests ====="
echo " 1. Client rejects response missing the attr"
echo " 2. Client accepts if require-msg-auth = no"
echo " 3. Client rejects response with wrong MA"
echo " 4. Client rejects MA that is correct but not first"
echo " 5. Client accepts response with correct MA"
echo " 6. Client rejects wrong MA even when not first (require-MA disabled)"
echo "==================================================="

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
RADIUSPID=""

eval "$GETPORT"

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

start_server() {
	python3 ${srcdir}/radius-server.py \
		--port ${PORT} --secret testing123 --msg-auth "$1" 2>/dev/null &
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

# Build a radiusclient.conf pointing to localhost:PORT
cat >radiusclient-temp$PID.conf <<EOF
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
echo "127.0.0.1/127.0.0.1	testing123" >servers-temp$PID

# Test 1: server sends no Message-Authenticator; default config requires it → must fail
start_server absent
run_test "Reject response with absent MA (require on by default)" \
	"../src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1

# Test 2: same server (no MA), but require-message-authenticator = no → must succeed
cp radiusclient-temp$PID.conf radiusclient-no-req$PID.conf
echo "require-message-authenticator	no" >> radiusclient-no-req$PID.conf

run_test "Accept response with absent MA when require-message-authenticator = no" \
	"../src/radiusclient -D -i -f radiusclient-no-req$PID.conf User-Name=test Password=test" \
	|| exit 1

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0; then
	echo "[ FAIL ] Expected Framed-Protocol = 'PPP' in response"
	exit 1
fi

# Test 3: server sends a Message-Authenticator with wrong value → must fail
stop_server
start_server wrong
run_test "Reject response with incorrect MA value" \
	"../src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1

# Test 4: server sends a correct MA but not as the first attribute → must fail
stop_server
start_server not-first
run_test "Reject response where MA is correct but not the first attribute" \
	"../src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1

# Test 5: server sends a correct MA (first attribute, valid HMAC) → must succeed
stop_server
start_server correct
run_test "Accept response with correct MA (valid HMAC-MD5, first attribute)" \
	"../src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	|| exit 1

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0; then
	echo "[ FAIL ] Expected Framed-Protocol = 'PPP' in response"
	exit 1
fi

# Test 6: MA present with wrong value, placed after other attrs (not first).
# validate_message_authenticator must be called even when MA is not first.
# require-message-authenticator=no so the position check doesn't fire first.
stop_server
start_server wrong-not-first
run_test "Reject response with wrong MA even when not first (require-MA disabled)" \
	"../src/radiusclient -D -i -f radiusclient-no-req$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1
stop_server

echo ""
exit 0
