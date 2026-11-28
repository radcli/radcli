#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== radcli2 RADCLI_REQUEST_SENDONLY reply validation ====="
echo " Datagrams the poll-driven path must discard: ones shorter than the"
echo " header or than their own Length field (even when the client's receive"
echo " buffer still holds the rest of a valid reply), and any from an"
echo " unexpected source, which must not redirect the retransmission either"
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

# $1: the tests/radius-server.py option selecting the peer's behaviour,
# $2: radius_retries, $3: accept|timeout|error (the outcome the request must
# end in), $4: how many Access-Requests the peer must receive.
function run_mode {
	local mode="$1" retries="$2" expect="$3" requests="$4"

	eval "$GETPORT"
	python3 ${srcdir}/radius-server.py --port ${PORT} --secret testing123 \
		${mode} >$LOG 2>&1 &
	SRVPID=$!
	for i in 1 2 3 4 5 6 7 8; do
		check_if_port_in_use ${PORT} && break
		sleep 0.5
	done

	${top_builddir}/tests/request-async-validation ${PORT} testing123 ${retries} ${expect} \
		>$TMPFILE 2>&1
	RET=$?
	sed 's/^/         | /' $TMPFILE
	kill ${SRVPID} >/dev/null 2>&1
	wait ${SRVPID} 2>/dev/null
	SRVPID=""

	if test $(grep -c "received Access-Request" $LOG) -ne ${requests}; then
		echo "[ FAIL ] ${mode}: expected the server to receive ${requests} Access-Request(s)"
		cat $LOG
		exit 1
	fi

	if test $RET != 0; then
		echo "[ FAIL ] ${mode}: request-async-validation exited with code $RET"
		exit 1
	fi
}

# REQ-NET-ERR-005: datagrams shorter than the header or than their Length
run_mode --stale-truncated 0 timeout 1
run_mode --short-datagrams-first 0 accept 1
# REQ-NET-NET-024: a valid reply from another port or address is not
# accepted ...
run_mode --spoof-source 0 timeout 1
run_mode --spoof-address 0 timeout 1
# ... and a datagram from another port does not redirect the retransmission
run_mode --other-port-first 1 accept 2

# REQ-NET-SEC-004: a reply whose Response Authenticator does not verify is
# never accepted, whatever its code ...
run_mode --bad-resp-auth 0 timeout 1
run_mode "--bad-resp-auth --reply-code 3" 0 timeout 1
run_mode "--bad-resp-auth --reply-code 11" 0 timeout 1
# ... and a forged Access-Reject does not end the wait for the real reply
run_mode --forged-first 0 accept 1

# REQ-NET-SEC-005..007: a reply that passed rc_check_reply() but fails a
# Message-Authenticator check ends the request with an error at once,
# without a retransmission, whatever its code
run_mode "--msg-auth absent" 1 error 1
run_mode "--msg-auth not-first" 1 error 1
run_mode "--msg-auth wrong" 1 error 1
run_mode "--msg-auth wrong --reply-code 3" 1 error 1
run_mode "--msg-auth wrong --reply-code 11" 1 error 1
run_mode "--msg-auth resp-auth-vector" 1 error 1
run_mode "--msg-auth bad-length" 1 error 1

echo "[  OK  ] short, wrong-source and unauthenticated datagrams discarded, and replies failing Message-Authenticator checks rejected, on the RADCLI_REQUEST_SENDONLY path"
exit 0
