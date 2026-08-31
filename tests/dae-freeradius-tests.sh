#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# RFC 5176 dynamic-authorization interoperability test against a real
# FreeRADIUS DAC: raddaeserver (built on radcli_dae_new()/_set_handler()/
# _start(), radcli_ctx_get_poll()/radcli_ctx_dispatch()) as the application
# under test, FreeRADIUS's own `radclient` sending a real Disconnect-Request
# it encodes itself -- not radcli's own tooling on both ends, unlike
# dae-tests.sh's dae-client.py-based checks. Plain loopback UDP, so unlike
# the ns.sh-based request-freeradius/avp-codec-freeradius interop tests,
# this needs no root and no network namespace: a Disconnect-Request's
# sender does not need a distinct source address for raddaeserver's
# dae-server ACL to be meaningful the way an inbound Access-Request's does.

srcdir="${srcdir:-.}"

echo "===== RFC 5176 dynamic-authorization / FreeRADIUS interoperability ====="
echo " 1. A Disconnect-Request built and sent by FreeRADIUS's radclient,"
echo "    carrying User-Name and Acct-Session-Id, is ACKed by raddaeserver"
echo " 2. raddaeserver's own request dump shows the exact User-Name and"
echo "    Acct-Session-Id values radclient sent, decoded correctly -- not"
echo "    just that some reply came back"
echo "=========================================================================="

RADCLIENT=$(which radclient)
if test -z "${RADCLIENT}"; then
	echo "This test requires FreeRADIUS's radclient"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
DAEPID=""
CONF=raddaeserver-freeradius-temp$PID.conf
LOG=raddaeserver-freeradius-log$PID.out

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
EOF

: >$LOG
${top_builddir}/src/raddaeserver -f $CONF -v >>$LOG 2>&1 &
DAEPID=$!
if ! wait_for_server; then
	echo "raddaeserver did not start"
	cat $LOG
	exit 1
fi

USER=radcli-dae-interop-user
SESSIONID=radcli-dae-interop-session-00001

# radclient reads one or more attribute lists from stdin, one request per
# invocation here; -x adds verbose/debug output to stderr, which run_test's
# capture also picks up, so the [ RUN ] block below is useful on failure
# without needing a second run.
run_test "FreeRADIUS radclient's Disconnect-Request is ACKed" \
	"echo 'User-Name = \"${USER}\", Acct-Session-Id = \"${SESSIONID}\"' | \
	 ${RADCLIENT} -x 127.0.0.1:${PORT} disconnect testing123 | grep -qi '^Received Disconnect-ACK'" \
	|| exit 1

# raddaeserver -v logs the decoded session selectors themselves
# (radcli_dae_req_user_name()/_req_session_id()), not merely the raw
# attribute dump -- confirming radcli's own decode of a packet it did not
# construct, sent by an independent, real implementation of RFC 5176's
# client side.
if ! grep -q "(user-name: ${USER})" $LOG; then
	echo "[ FAIL ] raddaeserver did not report the expected User-Name"
	cat $LOG
	exit 1
fi
if ! grep -q "(session-id: ${SESSIONID})" $LOG; then
	echo "[ FAIL ] raddaeserver did not report the expected Acct-Session-Id"
	cat $LOG
	exit 1
fi
echo "[  OK  ] raddaeserver decoded User-Name and Acct-Session-Id correctly"

kill ${DAEPID} >/dev/null 2>&1
wait ${DAEPID} 2>/dev/null
DAEPID=""

echo ""
exit 0
