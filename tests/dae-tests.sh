#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# End-to-end RFC 5176 dynamic-authorization tests: raddaeserver (built on
# radcli_dae_new()/_set_handler()/_start(), radcli_ctx_get_poll()/
# radcli_ctx_dispatch()) as the application under test, tests/dae-client.py
# as a hostile DAC. Both sides are radcli's own code/tooling driven over
# real loopback UDP sockets -- no root, no network namespace, and no real
# FreeRADIUS/strongSwan DAC needed, unlike the ns.sh-based interop tests.

srcdir="${srcdir:-.}"

echo "===== RFC 5176 dynamic-authorization tests (raddaeserver / dae-client.py) ====="
echo " 1. Valid Disconnect-Request is ACKed with a correct Response Authenticator"
echo " 2. Bad Request Authenticator is silently discarded"
echo " 3. Bad Message-Authenticator is silently discarded"
echo " 4. Absent Message-Authenticator is accepted by default"
echo " 5. Absent Message-Authenticator is rejected under dae-require-message-authenticator"
echo " 6. Stale Event-Timestamp is silently discarded"
echo " 7. Fresh Event-Timestamp is accepted"
echo " 8. A truncated packet is silently discarded"
echo " 9. A packet whose wire Length field overstates its content is discarded"
echo "10. A retransmission is answered identically without reprocessing"
echo "11. --nak answers with a NAK carrying the requested Error-Cause"
echo "12. --no-reply leaves both an original request and its retransmission unanswered"
echo "==============================================================================="

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
DAEPID=""
CONF=raddaeserver-temp$PID.conf
LOG=raddaeserver-log$PID.out

eval "$GETPORT"

function finish {
	test -n "${DAEPID}" && kill ${DAEPID} >/dev/null 2>&1
	rm -f $TMPFILE $CONF $LOG
}
trap finish EXIT

wait_for_server() {
	local i
	for i in 1 2 3 4 5 6 7 8; do
		check_if_port_in_use ${PORT} && return 0
		sleep 0.5
	done
	return 1
}

start_server() {
	cat >$CONF <<EOF
authserver	192.0.2.1
radius_timeout	5
radius_retries	1
dictionary	${srcdir}/../etc/dictionary
dae-accept	udp
dae-server	127.0.0.1
dae-secret	testing123
dae-listen	127.0.0.1:${PORT}
dae-max-clock-skew	60
$1
EOF
	: >$LOG
	${top_builddir}/src/raddaeserver -f $CONF -v $2 >>$LOG 2>&1 &
	DAEPID=$!
	wait_for_server
}

stop_server() {
	if test -n "${DAEPID}"; then
		kill ${DAEPID} >/dev/null 2>&1
		wait ${DAEPID} 2>/dev/null
		DAEPID=""
	fi
}

client() {
	python3 ${srcdir}/dae-client.py --port ${PORT} --secret testing123 --timeout 1 "$@"
}

start_server "" ""

# Test 1: a well-formed request is ACKed, with a Response Authenticator the
# client independently verifies (REQ-DAE-SEC-008).
run_test "Valid Disconnect-Request is ACKed" \
	"client --id 1 --attr User-Name=alice | grep -q '^REPLY code=41 id=1 auth=ok'" \
	|| exit 1

# Test 2: bad Request Authenticator (REQ-DAE-SEC-002) -- silent discard, and
# never reaches the handler (no line logged for it).
run_test "Bad Request Authenticator is silently discarded" \
	"client --id 2 --authenticator wrong | grep -q '^NO-REPLY'" \
	|| exit 1
grep -q "id=2" $LOG 2>/dev/null && { echo "[ FAIL ] id=2 was logged despite a bad Request Authenticator"; exit 1; }

# Test 3: bad Message-Authenticator (REQ-DAE-SEC-003).
run_test "Bad Message-Authenticator is silently discarded" \
	"client --id 3 --msg-auth wrong | grep -q '^NO-REPLY'" \
	|| exit 1

# Test 4: absent Message-Authenticator is accepted (RFC 5176 SS3 MAY,
# dae-require-message-authenticator defaults to no).
run_test "Absent Message-Authenticator is accepted by default" \
	"client --id 4 --msg-auth absent | grep -q '^REPLY code=41 id=4 auth=ok'" \
	|| exit 1

# Test 5: with dae-require-message-authenticator = yes, absence is now a
# silent discard too.
stop_server
start_server "dae-require-message-authenticator	yes" ""
run_test "Absent Message-Authenticator is rejected under dae-require-message-authenticator" \
	"client --id 5 --msg-auth absent | grep -q '^NO-REPLY'" \
	|| exit 1
stop_server
start_server "" ""

# Test 6/7: Event-Timestamp freshness (REQ-DAE-SEC-004; dae-max-clock-skew=60
# above).
run_test "Stale Event-Timestamp is silently discarded" \
	"client --id 6 --event-timestamp stale | grep -q '^NO-REPLY'" \
	|| exit 1
run_test "Fresh Event-Timestamp is accepted" \
	"client --id 7 --event-timestamp now | grep -q '^REPLY code=41 id=7 auth=ok'" \
	|| exit 1

# Test 8/9: bounds/length handling (REQ-DAE-SEC-007-adjacent).
run_test "A truncated packet is silently discarded" \
	"client --id 8 --truncate 10 | grep -q '^NO-REPLY'" \
	|| exit 1
run_test "A packet whose wire Length field overstates its content is discarded" \
	"client --id 9 --bad-length | grep -q '^NO-REPLY'" \
	|| exit 1

# Test 10: duplicate suppression (REQ-DAE-SEC-005/006) -- three identical
# retransmissions each get the same ACK, but the handler (and therefore the
# server's own log line for it) fires only once. $LOG already carries test
# 7's one processed request, so compare a before/after count rather than an
# absolute one.
before=$(grep -c '^Disconnect request:$' $LOG)
run_test "A retransmission is answered identically without reprocessing" \
	"client --id 10 --repeat 3 | sort -u | wc -l | grep -qx 1" \
	|| exit 1
after=$(grep -c '^Disconnect request:$' $LOG)
n=$((after - before))
if test "$n" != "1"; then
	echo "[ FAIL ] expected exactly one newly processed request for the retransmission test, got $n"
	cat $LOG
	exit 1
fi

# Test 11: --nak answers with the requested Error-Cause (attribute 101,
# 4-byte integer, big-endian) instead of a bare ACK.
stop_server
start_server "" "--nak=503"
# attrs= is Error-Cause (type 101, length 6, value 503 = 0x000001f7) followed
# by Message-Authenticator, whose HMAC bytes are not predictable -- match
# only the Error-Cause prefix.
run_test "--nak answers with a NAK carrying the requested Error-Cause" \
	"client --id 11 | grep -q '^REPLY code=42 id=11 auth=ok attrs=6506000001f7'" \
	|| exit 1
stop_server

# Test 12: --no-reply leaves the original request unanswered, and a later
# retransmission (still PENDING, per REQ-DAE-SEC-005) unanswered too --
# proving the "don't invoke the handler twice" guarantee holds even when the
# first copy was never replied to at all. Duplicate detection is keyed on
# (source port, Identifier, Request Authenticator) per RFC 5176 SS2.3, and
# each `client` invocation is a separate dae-client.py process that binds
# its own kernel-assigned ephemeral source port by default -- two separate
# invocations are therefore two distinct senders, not a retransmission,
# unless pinned to the same --source-port explicitly, as here.
start_server "" "--no-reply"
run_test "--no-reply leaves the original request unanswered" \
	"client --id 12 --source-port 45012 | grep -q '^NO-REPLY'" \
	|| exit 1
run_test "--no-reply leaves a PENDING retransmission unanswered too" \
	"client --id 12 --source-port 45012 | grep -q '^NO-REPLY'" \
	|| exit 1
n=$(grep -c '^Disconnect request:$' $LOG)
if test "$n" != "1"; then
	echo "[ FAIL ] expected exactly one processed request for the --no-reply test, got $n"
	cat $LOG
	exit 1
fi
stop_server

echo ""
exit 0
