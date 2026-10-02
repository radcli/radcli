#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== blocking request after a reply with another Identifier ====="
echo " A reply carrying another Identifier must not end a blocking"
echo " request's wait for its own (see tests/request-stray-reply.c)."
echo "=================================================================="

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
LOG=radius-server-strayreply-$PID.log
SRVPID=""

eval "$GETPORT"

function finish {
	test -n "${SRVPID}" && kill ${SRVPID} >/dev/null 2>&1
	rm -f $TMPFILE $LOG
}
trap finish EXIT

python3 ${srcdir}/radius-server.py --port ${PORT} --secret testing123 \
	--stray-first >$LOG 2>&1 &
SRVPID=$!
for i in 1 2 3 4 5 6 7 8; do
	check_if_port_in_use ${PORT} && break
	sleep 0.5
done

${top_builddir}/tests/request-stray-reply ${PORT} testing123 >$TMPFILE 2>&1
RET=$?
sed 's/^/         | /' $TMPFILE

if test $(grep -c "received Access-Request" $LOG) -ne 1; then
	echo "[ FAIL ] expected exactly one Access-Request (no retransmission)"
	cat $LOG
	exit 1
fi

if test $RET != 0; then
	echo "[ FAIL ] request-stray-reply exited with code $RET"
	exit 1
fi

echo "[  OK  ] the wait continued past a reply with another Identifier"
exit 0
