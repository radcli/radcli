#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# REQ-NET-NET-021/022, REQ-NET2-NET-001: requests left unanswered on a TCP
# or TLS session time out, are resent only over a new connection, and never
# make radcli_ctx_dispatch() wait. See tests/session-timeout.c. TLS cases
# run only when the build has TLS support and openssl is available; DTLS cases only need TLS support.

srcdir="${srcdir:-.}"

echo "===== TCP/TLS session timeout test ====="

if ! command -v python3 >/dev/null 2>&1; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
SECRET=testing123
CERT=session-timeout-cert$PID.pem
KEY=session-timeout-key$PID.pem
SERVEROUT=session-timeout-server-out$PID.txt

function finish {
	rm -f $CERT $KEY $SERVEROUT
}
trap finish EXIT

# $1: tcp or tls, $2: server mode, $3: client mode, $4: line the peer must
# print, $5: seconds the peer waits.
function run_case {
	local transport="$1" smode="$2" cmode="$3" expect="$4" ptimeout="$5"
	local sargs cred

	if test "$transport" = tls; then
		sargs="--cert $CERT --key $KEY"
		cred=$CERT
	else
		sargs="--plain --secret $SECRET"
		cred=$SECRET
	fi

	eval "$GETPORT"
	# The server's own redirection runs in its child, possibly after the
	# wait below has looked: it must not find the previous case's READY.
	: >$SERVEROUT
	python3 ${srcdir}/session-timeout-server.py --port ${PORT} $sargs \
		--mode $smode --timeout $ptimeout >$SERVEROUT 2>&1 &
	SERVERPID=$!
	for i in $(seq 50); do
		grep -q '^READY' $SERVEROUT && break
		sleep 0.1
	done

	${top_builddir}/tests/session-timeout $transport ${PORT} $cred $cmode
	RET=$?

	wait ${SERVERPID}

	echo "--- peer output ($transport $smode/$cmode) ---"
	cat $SERVEROUT

	if test ${RET} -ne 0; then
		echo "[ FAIL ] $transport $smode/$cmode: client reported a failure"
		exit 1
	fi
	if ! grep -q "^$expect" $SERVEROUT; then
		echo "[ FAIL ] $transport $smode/$cmode: peer did not report $expect"
		exit 1
	fi
}

run_case tcp once once-blocking "COPIES=1 CONNECTIONS=1" 4
run_case tcp once once-sendonly "COPIES=1 CONNECTIONS=1" 4
run_case tcp drop drop-sendonly "RESENT-ON-NEW" 10

if test "${HAVE_TLS:-yes}" = yes; then
	for cmode in blocking-mute sendfail-once; do
		if ! ${top_builddir}/tests/session-timeout dtls - - $cmode; then
			echo "[ FAIL ] dtls $cmode: client reported a failure"
			exit 1
		fi
	done
fi

if test "${HAVE_TLS:-yes}" = yes && command -v openssl >/dev/null 2>&1; then
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
		-keyout $KEY -out $CERT -subj "/CN=127.0.0.1" \
		-addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
	if test ! -s "$CERT" || test ! -s "$KEY"; then
		echo "Could not generate a throwaway test certificate with openssl"
		exit 1
	fi
	run_case tls once once-blocking "COPIES=1 CONNECTIONS=1" 4
	run_case tls once once-sendonly "COPIES=1 CONNECTIONS=1" 4
	run_case tls stall stall "STALLED" 10
fi

echo "[  OK  ] TCP/TLS requests are resent only over a new connection, without blocking dispatch"
exit 0
