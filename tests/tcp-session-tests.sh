#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# REQ-NET-NET-004/020: serv-type tcp carries every request over one
# connection to the authserver, framing replies by their Length field,
# for both blocking and RADCLI_REQUEST_SENDONLY requests. See
# tests/session-framing.c.

srcdir="${srcdir:-.}"

echo "===== RADIUS/TCP session test ====="

if ! command -v python3 >/dev/null 2>&1; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
SECRET=testing123
SERVEROUT=tcp-session-server-out$PID.txt

function finish {
	rm -f $SERVEROUT
}
trap finish EXIT

# $1: server mode, $2: client mode, $3: line the peer must print,
# remaining arguments: extra server options.
function run_case {
	local smode="$1" cmode="$2" expect="$3"
	shift 3

	eval "$GETPORT"
	# The server's own redirection runs in its child, possibly after the
	# wait below has looked: it must not find the previous case's READY.
	: >$SERVEROUT
	python3 ${srcdir}/session-framing-server.py --plain --port ${PORT} \
		--secret $SECRET --mode $smode "$@" >$SERVEROUT 2>&1 &
	SERVERPID=$!
	for i in $(seq 50); do
		grep -q '^READY' $SERVEROUT && break
		sleep 0.1
	done

	${top_builddir}/tests/session-framing tcp ${PORT} $SECRET $cmode
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
run_case split acct "DONE replied=2"
run_case coalesce blocking "DONE replied=2" --batch 1
run_case coalesce sendonly "DONE replied=2" --batch 2
run_case badlen badlen "SECOND-CONNECTION"

echo "[  OK  ] RADIUS/TCP requests share one connection, framed by their Length field"
exit 0
