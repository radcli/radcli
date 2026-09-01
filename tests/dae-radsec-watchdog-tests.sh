#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# DAE-over-RadSec connection-liveness test: radcli_ctx_dispatch()'s internal watchdog send sends
# an RFC 5997 Status-Server the peer (dae-watchdog-server.py) verifies the
# Message-Authenticator of, unprompted -- the peer never asks for it, unlike
# dae-radsec-tests.sh's single round-trip. See dae-radsec-watchdog.c's header
# comment for the deadline-math assertions this also covers
# (radcli_ctx_get_poll()'s dae-watchdog-interval-derived timeout_ms).

srcdir="${srcdir:-.}"

echo "===== DAE-over-RadSec connection-liveness (watchdog) test ====="
echo " 1. radcli_ctx_dispatch()'s internal watchdog send sends an unprompted RFC 5997"
echo "    Status-Server over the established RadSec session; the peer"
echo "    verifies its Message-Authenticator"
echo " 2. radcli_ctx_get_poll()'s timeout_ms reflects dae-watchdog-interval:"
echo "    close to the full interval right after activity, 0 once it has"
echo "    elapsed with nothing else pending"
echo "================================================================="

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
CERT=dae-radsec-watchdog-cert$PID.pem
KEY=dae-radsec-watchdog-key$PID.pem
SERVEROUT=dae-radsec-watchdog-server-out$PID.txt

eval "$GETPORT"

function finish {
	rm -f $CERT $KEY $SERVEROUT
}
trap finish EXIT

${OPENSSL} req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout $KEY -out $CERT -subj "/CN=127.0.0.1" \
	-addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
if test ! -s "$CERT" || test ! -s "$KEY"; then
	echo "Could not generate a throwaway test certificate with openssl"
	exit 1
fi

python3 ${srcdir}/dae-watchdog-server.py --host 127.0.0.1 --port ${PORT} \
	--cert $CERT --key $KEY --timeout 15 --reply >$SERVEROUT 2>&1 &
SERVERPID=$!
sleep 0.5

${top_builddir}/tests/dae-radsec-watchdog ${PORT} $CERT
RET=$?

wait ${SERVERPID}

echo "--- peer output ---"
cat $SERVEROUT

if test ${RET} -ne 0; then
	echo "[ FAIL ] dae-radsec-watchdog reported a failure -- see its stderr above"
	exit 1
fi

if ! grep -q '^WATCHDOG code=12 .*msgauth=ok' $SERVEROUT; then
	echo "[ FAIL ] the peer did not see a valid, unprompted Status-Server"
	exit 1
fi

echo "[  OK  ] radcli_ctx_dispatch()'s internal watchdog send sent a valid Status-Server; timeout_ms tracked dae-watchdog-interval"
exit 0
