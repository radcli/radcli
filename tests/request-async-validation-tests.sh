#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== radcli2 RADCLI_REQUEST_SENDONLY reply validation ====="
echo " Replies the poll-driven path must discard: one shorter than its own"
echo " Length field (even when the client's receive buffer still holds the"
echo " rest of a valid reply), and a valid one from an unexpected source"
echo " (see tests/request-async-validation.c)."
echo "============================================================"

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
LOG=radius-server-asyncval-$PID.log
SRVPID=""

function finish {
	test -n "${SRVPID}" && kill ${SRVPID} >/dev/null 2>&1
	rm -f $TMPFILE $LOG
}
trap finish EXIT

# $1: the tests/radius-server.py option selecting the reply to discard.
function run_mode {
	local mode="$1"

	eval "$GETPORT"
	python3 ${srcdir}/radius-server.py --port ${PORT} --secret testing123 \
		${mode} >$LOG 2>&1 &
	SRVPID=$!
	for i in 1 2 3 4 5 6 7 8; do
		check_if_port_in_use ${PORT} && break
		sleep 0.5
	done

	${top_builddir}/tests/request-async-validation ${PORT} testing123 >$TMPFILE 2>&1
	RET=$?
	sed 's/^/         | /' $TMPFILE
	kill ${SRVPID} >/dev/null 2>&1
	wait ${SRVPID} 2>/dev/null
	SRVPID=""

	if ! grep -q "received Access-Request" $LOG; then
		echo "[ FAIL ] ${mode}: the server never received the Access-Request"
		cat $LOG
		exit 1
	fi

	if test $RET != 0; then
		echo "[ FAIL ] ${mode}: request-async-validation exited with code $RET"
		exit 1
	fi
}

run_mode --stale-truncated
run_mode --spoof-source

echo "[  OK  ] truncated and wrong-source replies discarded on the RADCLI_REQUEST_SENDONLY path"
exit 0
