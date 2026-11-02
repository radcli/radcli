#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# REQ-NET-NET-020: RADIUS packets on a TLS session are delimited by their
# Length field, not by TLS record boundaries. See tests/radsec-framing.c.

srcdir="${srcdir:-.}"

echo "===== RadSec stream framing test ====="

if ! python3 -c 'import ssl' 2>/dev/null; then
	echo "This test requires python3 with TLS (ssl module) support"
	exit 77
fi
OPENSSL=$(which openssl)
if test -z "${OPENSSL}"; then
	echo "This test requires openssl (to generate a throwaway test certificate)"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
CERT=radsec-framing-cert$PID.pem
KEY=radsec-framing-key$PID.pem
SERVEROUT=radsec-framing-server-out$PID.txt

function finish {
	rm -f $CERT $KEY $SERVEROUT
}
trap finish EXIT

${OPENSSL} req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout $KEY -out $CERT -subj "/CN=127.0.0.1" \
	-addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
if test ! -s "$CERT" || test ! -s "$KEY"; then
	echo "Could not generate a throwaway test certificate with openssl"
	exit 1
fi

# $1: server mode, $2: client mode, $3: line the peer must print,
# remaining arguments: extra server options.
function run_case {
	local smode="$1" cmode="$2" expect="$3"
	shift 3

	eval "$GETPORT"
	# The server's own redirection runs in its child, possibly after the
	# wait below has looked: it must not find the previous case's READY.
	: >$SERVEROUT
	python3 ${srcdir}/radsec-framing-server.py --port ${PORT} \
		--cert $CERT --key $KEY --mode $smode "$@" >$SERVEROUT 2>&1 &
	SERVERPID=$!
	sleep 0.5

	${top_builddir}/tests/radsec-framing ${PORT} $CERT $cmode
	RET=$?

	wait ${SERVERPID}

	echo "--- peer output ($smode/$cmode) ---"
	cat $SERVEROUT

	if test ${RET} -ne 0; then
		echo "[ FAIL ] $smode/$cmode: client reported a failure"
		exit 1
	fi
	if ! grep -q "^$expect" $SERVEROUT; then
		echo "[ FAIL ] $smode/$cmode: peer did not report $expect"
		exit 1
	fi
}

run_case split blocking "DONE replied=2"
run_case split sendonly "DONE replied=2"
run_case coalesce blocking "DONE replied=2" --batch 1
run_case coalesce sendonly "DONE replied=2" --batch 2
run_case badlen badlen "SECOND-CONNECTION"

echo "[  OK  ] RadSec replies are framed by their Length field"
exit 0
