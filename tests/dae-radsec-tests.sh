#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# RFC 5176 dynamic-authorization over RadSec (RFC 6614 SS2.1/SS2.5): unlike
# dae-tests.sh/dae-freeradius-tests.sh (dae-accept=udp, a separate RFC 5176/
# UDP listener), this exercises dae-accept=yes under serv-type=tls, where
# CoA/Disconnect flow over the same TLS connection raddaeserver itself
# dials out on its ordinary authserver connection -- forced eagerly by
# radcli_dae_start() (REQ-DAE-INIT-010), since raddaeserver never sends an
# Access-Request of its own. tests/dae-tls-client.py plays the accepting
# AAA-server role and sends the Disconnect-Request back down that same
# accepted socket, matching RFC 6614 SS2.5's model.
#
# No real DAC was found to validate this against (see doc/requirements/
# dae.md's header: FreeRADIUS's own equivalent, WITH_COA_TUNNEL, is
# compiled out in every stock build and removed entirely upstream) -- this
# is dae-tls-client.py, a spec-conformant test double, reusing dae-client.py's
# wire-format helpers, not radcli's own encoder on both ends. TLS only (no
# DTLS: Python's ssl module has no DTLS support); no root, no network
# namespace (plain loopback TCP/TLS).

srcdir="${srcdir:-.}"

echo "===== RFC 5176 dynamic-authorization over RadSec (TLS) ====="
echo " 1. raddaeserver dials out under serv-type=tls; radcli_dae_start()"
echo "    completes the handshake eagerly with no Access-Request ever sent"
echo " 2. A Disconnect-Request sent back down that same accepted TLS"
echo "    connection, carrying User-Name and Acct-Session-Id, is ACKed"
echo " 3. raddaeserver's own request dump shows those exact values,"
echo "    decoded correctly over the shared RadSec session"
echo "============================================================="

if ! python3 -c 'import ssl' 2>/dev/null; then
	echo "This test requires python3 with TLS (ssl module) support"
	exit 77
fi
OPENSSL=$(which openssl)
if test -z "${OPENSSL}"; then
	echo "This test requires openssl (to generate a throwaway test certificate)"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
DAEPID=""
CONF=raddaeserver-radsec-temp$PID.conf
LOG=raddaeserver-radsec-log$PID.out
CERT=raddaeserver-radsec-cert$PID.pem
KEY=raddaeserver-radsec-key$PID.pem
CLIENTOUT=dae-tls-client-out$PID.txt

eval "$GETPORT"

function finish {
	test -n "${DAEPID}" && kill ${DAEPID} >/dev/null 2>&1
	rm -f $TMPFILE $CONF $LOG $CERT $KEY $CLIENTOUT
}
trap finish EXIT

${OPENSSL} req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout $KEY -out $CERT -subj "/CN=127.0.0.1" \
	-addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
if test ! -s "$CERT" || test ! -s "$KEY"; then
	echo "Could not generate a throwaway test certificate with openssl"
	exit 1
fi

USER=radcli-dae-radsec-user
SESSIONID=radcli-dae-radsec-session-00001

# Start the DAC test double first: it must already be listening (accepting
# the TLS connection) before raddaeserver's own radcli_dae_start() dials
# out, or the handshake below fails outright.
python3 ${srcdir}/dae-tls-client.py --host 127.0.0.1 --port ${PORT} \
	--cert $CERT --key $KEY --id 1 \
	--attr "User-Name=${USER}" --attr "Acct-Session-Id=${SESSIONID}" \
	--timeout 8 >$CLIENTOUT 2>&1 &
CLIENTPID=$!
sleep 0.5

cat >$CONF <<EOF
serv-type	tls
authserver	127.0.0.1:${PORT}
tls-ca-file	${CERT}
radius_timeout	5
radius_retries	1
dictionary	${srcdir}/../etc/dictionary
dae-accept	yes
dae-max-clock-skew	60
EOF

: >$LOG
${top_builddir}/src/raddaeserver -f $CONF -v >>$LOG 2>&1 &
DAEPID=$!

# raddaeserver is long-running; the only observable proof that
# radcli_dae_start() actually completed the eager RadSec handshake (REQ-DAE-
# INIT-010) is dae-tls-client.py's own accept()+handshake succeeding, which
# its REPLY/NO-REPLY line (checked below) already reflects.
wait ${CLIENTPID}

run_test "Disconnect-Request over the shared RadSec connection is ACKed" \
	"grep -q '^REPLY code=41 id=1 auth=ok' $CLIENTOUT" \
	|| { cat $CLIENTOUT; cat $LOG; exit 1; }

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
echo "[  OK  ] raddaeserver decoded User-Name and Acct-Session-Id correctly over RadSec"

kill ${DAEPID} >/dev/null 2>&1
wait ${DAEPID} 2>/dev/null
DAEPID=""

echo ""
exit 0
