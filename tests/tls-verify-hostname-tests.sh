#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# Regression test for the fix in commit 5dc5e25c ("lib/tls.c: fix
# tls-verify-hostname=no comparison missing == 0"). The bug was:
#
#   if (p && (strcasecmp(p, "false") == 0 || strcasecmp(p, "no"))) {
#
# strcasecmp(p, "no") returns nonzero (C-truthy) for any value other than
# the literal string "no", so hostname verification was disabled for
# *any* configured tls-verify-hostname value, including "true" -- the
# opposite of what the operator asked for.
#
# This test connects to radius-server.py's TLS transport (its certificate,
# tests/raddb/cert-rsa.pem, has SAN DNS:localhost only) using the numeric
# address 127.0.0.1 as the configured server name, so the certificate's
# hostname never matches the connection target. That mismatch must be
# rejected whenever tls-verify-hostname is anything other than "no"/
# "false", and must be accepted only when it is explicitly disabled.
# Using the Python test server instead of a real TLS-capable RADIUS
# server keeps this test free of the root/network-namespace requirement
# that tls-tests.sh has (see doc/radius-test-server.md).

srcdir="${srcdir:-.}"

echo "==========================================================="
echo "tls-verify-hostname tests"
echo " 1. Client rejects server cert/hostname mismatch by default"
echo " 2. Client rejects the mismatch with tls-verify-hostname true"
echo " 3. Client accepts the mismatch with tls-verify-hostname no"
echo "==========================================================="

if ! python3 -c 'import ssl' 2>/dev/null; then
	echo "This test requires python3 with the ssl module"
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
		--transport tls --port ${PORT} --secret radsec --msg-auth correct \
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

# Build a client config pointing at 127.0.0.1:PORT -- a numeric address, so
# it can never match the certificate's DNS:localhost SAN. $1, if given, is
# a "tls-verify-hostname <value>" line to append (omitted entirely to test
# the default).
make_conf() {
	cat >radiusclient-temp$PID.conf <<EOF
serv-type tls
tls-ca-file ${srcdir}/dtls/ca.pem
authserver  127.0.0.1:${PORT}
acctserver  127.0.0.1:${PORT}
servers     ./servers-temp$PID
dictionary  ${srcdir}/../etc/dictionary
default_realm
radius_timeout  5
radius_retries  1
bindaddr    *
EOF
	if test -n "$1"; then
		echo "$1" >>radiusclient-temp$PID.conf
	fi
}
echo "127.0.0.1	testing123" >servers-temp$PID

start_server

# Test 1: tls-verify-hostname not set (default is to verify) -> must fail
make_conf ""
run_test "Reject cert/hostname mismatch with tls-verify-hostname unset (default)" \
	"${top_builddir}/src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1

# Test 2: tls-verify-hostname true (this is exactly the case commit 5dc5e25c
# fixed: the buggy comparison treated this the same as "no") -> must fail
make_conf "tls-verify-hostname true"
run_test "Reject cert/hostname mismatch with tls-verify-hostname true" \
	"${top_builddir}/src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1

# Test 3: tls-verify-hostname no -> must succeed despite the mismatch
make_conf "tls-verify-hostname no"
run_test "Accept cert/hostname mismatch with tls-verify-hostname no" \
	"${top_builddir}/src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	|| exit 1

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0; then
	echo "[ FAIL ] Expected Framed-Protocol = 'PPP' in response"
	exit 1
fi

stop_server

echo ""
exit 0
