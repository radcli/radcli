#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# REQ-NET-NET-015: a request resent from radcli_ctx_dispatch() over a new TCP
# connection must connect in the configured namespace. The server is
# reachable only from that namespace, and drops the first connection. See
# tests/session-timeout.c.

srcdir="${srcdir:-.}"

CLI_ADDRESS=10.203.9.1
ADDRESS=10.203.10.1
NO_RADIUSD=1
PID=$$
SECRET=testing123
SERVEROUT=namespace-reconnect-server-out$PID.txt

function finish {
	rm -f $SERVEROUT
}

if ! command -v python3 >/dev/null 2>&1; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/ns.sh

echo "===== namespace reconnect test ====="

for cmode in drop-sendonly drop-nonblock; do
	eval "$GETPORT"
	: >$SERVEROUT
	${CMDNS2} python3 ${srcdir}/session-timeout-server.py --host $ADDRESS --port ${PORT} \
		--plain --secret $SECRET --mode drop --timeout 10 >$SERVEROUT 2>&1 &
	SERVERPID=$!
	for i in $(seq 50); do
		grep -q '^READY' $SERVEROUT && break
		sleep 0.1
	done

	SESSION_TIMEOUT_ADDRESS=$ADDRESS SESSION_TIMEOUT_NAMESPACE=$NSNAME1 \
		${top_builddir}/tests/session-timeout tcp ${PORT} $SECRET $cmode
	RET=$?

	wait ${SERVERPID}

	echo "--- peer output ($cmode) ---"
	cat $SERVEROUT

	if test ${RET} -ne 0; then
		echo "[ FAIL ] $cmode: client reported a failure"
		exit 1
	fi
	if ! grep -q "^RESENT-ON-NEW" $SERVEROUT; then
		echo "[ FAIL ] $cmode: peer did not report RESENT-ON-NEW"
		exit 1
	fi
done

echo "[  OK  ] a request resent over a new connection stays in the configured namespace"
exit 0
