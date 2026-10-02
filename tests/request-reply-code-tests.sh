#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== radcli2 radcli_request_code() after a failed request ====="
echo " A correctly authenticated reply with a code radcli does not accept"
echo " fails the request; radcli_request_code() must then report 0, not"
echo " that code (see tests/request-reply-code.c)."
echo "================================================================"

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
LOG=radius-server-replycode-$PID.log
SRVPID=""

eval "$GETPORT"

function finish {
	test -n "${SRVPID}" && kill ${SRVPID} >/dev/null 2>&1
	rm -f $TMPFILE $LOG
}
trap finish EXIT

python3 ${srcdir}/radius-server.py --port ${PORT} --secret testing123 \
	--reply-code 42 >$LOG 2>&1 &
SRVPID=$!
for i in 1 2 3 4 5 6 7 8; do
	check_if_port_in_use ${PORT} && break
	sleep 0.5
done

${top_builddir}/tests/request-reply-code ${PORT} testing123 >$TMPFILE 2>&1
RET=$?
sed 's/^/         | /' $TMPFILE

if test $(grep -c "received Access-Request" $LOG) -lt 2; then
	echo "[ FAIL ] the server did not receive both Access-Requests"
	cat $LOG
	exit 1
fi

if test $RET != 0; then
	echo "[ FAIL ] request-reply-code exited with code $RET"
	exit 1
fi

echo "[  OK  ] radcli_request_code() reports 0 after a failed request"
exit 0
