#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== radcli2 multiplexed poll-driven request/reply ====="
echo " NAS sends several Access-Requests with RADCLI_REQUEST_SENDONLY"
echo " before waiting on any of them, then services all of them out of"
echo " a single shared poll() loop, exactly as an application built"
echo " around an event loop would (see doc/radius-test-server.md and"
echo " tests/request-poll-multi.c)."
echo "==========================================================="

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
LOG=radius-server-pollmulti-$PID.log
SRVPID=""

eval "$GETPORT"; PORT=$PORT

function finish {
	test -n "${SRVPID}" && kill ${SRVPID} >/dev/null 2>&1
	rm -f $TMPFILE $LOG
}
trap finish EXIT

wait_for_server() {
	local port="$1"
	local i
	for i in 1 2 3 4 5 6 7 8; do
		check_if_port_in_use ${port} && return 0
		sleep 0.5
	done
	return 1
}

python3 ${srcdir}/radius-server.py --port ${PORT} --secret testing123 >$LOG 2>&1 &
SRVPID=$!
wait_for_server ${PORT} || { echo "[ FAIL ] server did not start"; exit 1; }

${top_builddir}/tests/request-poll-multi 127.0.0.1 ${PORT} testing123 >$TMPFILE 2>&1
RET=$?
sed 's/^/         | /' $TMPFILE

if test $RET != 0; then
	echo "[ FAIL ] request-poll-multi exited with code $RET"
	exit 1
fi

# Every one of the NREQ requests (tests/request-poll-multi.c) must actually
# have reached the server as a distinct wire packet, not merely have been
# satisfied in-process -- same evidentiary standard as acct-async-tests.sh.
NREQ=5
COUNT=$(grep -c "received Access-Request" $LOG)
if test "$COUNT" -lt "$NREQ"; then
	echo "[ FAIL ] server log shows only $COUNT Access-Request(s), expected at least $NREQ"
	cat $LOG
	exit 1
fi

echo "[  OK  ] $COUNT concurrent Access-Requests serviced through a single shared poll() loop"

exit 0
