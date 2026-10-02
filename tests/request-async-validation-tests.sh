#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== radcli2 RADCLI_REQUEST_SENDONLY reply validation ====="
echo " A reply shorter than its own Length field must be discarded on the"
echo " poll-driven path, even when the client's receive buffer still holds"
echo " the rest of a valid reply (see tests/request-async-validation.c)."
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

eval "$GETPORT"

function finish {
	test -n "${SRVPID}" && kill ${SRVPID} >/dev/null 2>&1
	rm -f $TMPFILE $LOG
}
trap finish EXIT

python3 ${srcdir}/radius-server.py --port ${PORT} --secret testing123 \
	--stale-truncated >$LOG 2>&1 &
SRVPID=$!
for i in 1 2 3 4 5 6 7 8; do
	check_if_port_in_use ${PORT} && break
	sleep 0.5
done

${top_builddir}/tests/request-async-validation ${PORT} testing123 >$TMPFILE 2>&1
RET=$?
sed 's/^/         | /' $TMPFILE

if ! grep -q "received Access-Request" $LOG; then
	echo "[ FAIL ] the server never received the Access-Request"
	cat $LOG
	exit 1
fi

if test $RET != 0; then
	echo "[ FAIL ] request-async-validation exited with code $RET"
	exit 1
fi

echo "[  OK  ] truncated reply discarded on the RADCLI_REQUEST_SENDONLY path"
exit 0
