#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== rc_acct_async() non-blocking accounting tests ====="
echo " 1. Returns promptly, without waiting for any server to reply"
echo " 2. Every configured accounting server is contacted (no early exit)"
echo " 3. Fails with no server contacted when no acctserver is configured"
echo "==========================================================="

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
LOG1=radius-server1-$PID.log
LOG2=radius-server2-$PID.log
SRVPID1=""
SRVPID2=""

eval "$GETPORT"; PORT1=$PORT
eval "$GETPORT"; PORT2=$PORT

function finish {
	test -n "${SRVPID1}" && kill ${SRVPID1} >/dev/null 2>&1
	test -n "${SRVPID2}" && kill ${SRVPID2} >/dev/null 2>&1
	rm -f $TMPFILE $LOG1 $LOG2
	rm -f radiusclient-temp$PID.conf
	rm -f radiusclient-noacct$PID.conf
	rm -f servers-temp$PID
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

# Two accounting servers that receive and log every packet but never reply --
# models a server that is slow, unresponsive, or simply doesn't answer
# Accounting-Requests. rc_acct_async() (REQ-NET-NET-017's no_wait contract,
# REQ-ATTR-NET-030) must still return promptly and must still contact both,
# rather than stopping after the first send like rc_acct()'s blocking
# failover would (REQ-ATTR-NET-025).
python3 ${srcdir}/radius-server.py --port ${PORT1} --secret testing123 --no-reply >$LOG1 2>&1 &
SRVPID1=$!
python3 ${srcdir}/radius-server.py --port ${PORT2} --secret testing123 --no-reply >$LOG2 2>&1 &
SRVPID2=$!
wait_for_server ${PORT1} || { echo "[ FAIL ] server 1 did not start"; exit 1; }
wait_for_server ${PORT2} || { echo "[ FAIL ] server 2 did not start"; exit 1; }

cat >radiusclient-temp$PID.conf <<EOF
nas-identifier my-nas-id
authserver  127.0.0.1:${PORT1}
acctserver  127.0.0.1:${PORT1},127.0.0.1:${PORT2}
servers     ./servers-temp$PID
dictionary  ${srcdir}/../etc/dictionary
default_realm
radius_timeout  10
radius_retries  3
bindaddr    *
EOF
echo "127.0.0.1/127.0.0.1	testing123" >servers-temp$PID

START=$(date +%s)
${top_builddir}/src/radiusclient -D -f radiusclient-temp$PID.conf -A User-Name=test Acct-Status-Type=Start >$TMPFILE 2>&1
RET=$?
END=$(date +%s)
ELAPSED=$((END - START))
sed 's/^/         | /' $TMPFILE

if test $RET != 0; then
	echo "[ FAIL ] async accounting request returned exit code $RET (expected 0/OK_RC)"
	exit 1
fi

# radius_timeout is 10s with 3 retries; a blocking failover call would take at
# least that long against even one non-replying server. The async call must
# return almost immediately regardless of how many servers are configured or
# whether any of them reply.
if test $ELAPSED -ge 5; then
	echo "[ FAIL ] async accounting request took ${ELAPSED}s; expected well under radius_timeout"
	exit 1
fi

# Every configured server must have been contacted (REQ-ATTR-NET-030: no
# early exit on a per-server result, unlike rc_acct()'s failover).
for log in $LOG1 $LOG2; do
	if ! grep -q "received Accounting-Request" $log; then
		echo "[ FAIL ] $log: accounting server never received the packet"
		cat $log
		exit 1
	fi
done

echo "[  OK  ] async accounting request reached both configured servers in ${ELAPSED}s"

# Negative case: no acctserver configured -> ERROR_RC, no server contacted
# (REQ-ATTR-NET-030).
cat >radiusclient-noacct$PID.conf <<EOF
nas-identifier my-nas-id
authserver  127.0.0.1:${PORT1}
servers     ./servers-temp$PID
dictionary  ${srcdir}/../etc/dictionary
default_realm
radius_timeout  10
radius_retries  3
bindaddr    *
EOF

${top_builddir}/src/radiusclient -D -f radiusclient-noacct$PID.conf -A User-Name=test Acct-Status-Type=Start >$TMPFILE 2>&1
RET=$?
sed 's/^/         | /' $TMPFILE

if test $RET == 0; then
	echo "[ FAIL ] async accounting request with no acctserver configured unexpectedly succeeded"
	exit 1
fi

echo "[  OK  ] async accounting request with no acctserver configured correctly failed"

exit 0
