#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# REQ-NET2-SEND-018, REQ-NET2-NET-005: RADCLI_REQUEST_SENDONLY_NONBLOCK
# requests queue behind a full send window without waiting, and freeing them there
# sends nothing unstarted and never cuts a started packet short. See
# tests/nonblock-backpressure.c. TLS cases run only when the build has TLS
# support and openssl is available.

srcdir="${srcdir:-.}"

echo "===== RADCLI_REQUEST_SENDONLY_NONBLOCK backpressure test ====="

if ! command -v python3 >/dev/null 2>&1; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
SECRET=testing123
CERT=nonblock-backpressure-cert$PID.pem
KEY=nonblock-backpressure-key$PID.pem
SERVEROUT=nonblock-backpressure-server-out$PID.txt
OLD=20
NEW=256

function finish {
	rm -f $CERT $KEY $SERVEROUT
}
trap finish EXIT

# $1: tcp or tls, $2: hold or cancel.
function run_case {
	local transport="$1" mode="$2" sargs cred verdict sent

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
	python3 ${srcdir}/nonblock-backpressure-server.py --port ${PORT} $sargs \
		--hold 2 >$SERVEROUT 2>&1 &
	SERVERPID=$!
	for i in $(seq 50); do
		grep -q '^READY' $SERVEROUT && break
		sleep 0.1
	done

	${top_builddir}/tests/nonblock-backpressure $transport ${PORT} $cred $mode
	RET=$?

	wait ${SERVERPID}

	echo "--- peer output ($transport $mode) ---"
	cat $SERVEROUT

	if test ${RET} -ne 0; then
		echo "[ FAIL ] $transport $mode: client reported a failure"
		exit 1
	fi

	verdict=$(sed -n 's/^VERDICT //p' $SERVEROUT)
	if test "$mode" = hold; then
		if test "$verdict" != "ok old=$OLD new=0"; then
			echo "[ FAIL ] $transport hold: peer did not receive all $OLD requests intact and in order"
			exit 1
		fi
		return
	fi

	# A started packet is finished (at least old-0 was), an unstarted one
	# is never sent (some must be missing).
	sent=$(echo "$verdict" | sed -n "s/^ok old=\([0-9]*\) new=$NEW\$/\1/p")
	if test -z "$sent" || test "$sent" -lt 1 || test "$sent" -ge $OLD; then
		echo "[ FAIL ] $transport cancel: expected an intact prefix of the $OLD freed requests, then all $NEW new ones"
		exit 1
	fi
}

run_case tcp hold
run_case tcp cancel

if test "${HAVE_TLS:-yes}" = yes && command -v openssl >/dev/null 2>&1; then
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
		-keyout $KEY -out $CERT -subj "/CN=127.0.0.1" \
		-addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
	if test ! -s "$CERT" || test ! -s "$KEY"; then
		echo "Could not generate a throwaway test certificate with openssl"
		exit 1
	fi
	run_case tls hold
	run_case tls cancel
fi

echo "[  OK  ] RADCLI_REQUEST_SENDONLY_NONBLOCK requests queue and cancel cleanly behind a full send window"
exit 0
