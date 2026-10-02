#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== one Identifier space per RadSec session ====="
echo " Blocking requests and watchdogs take their Identifier from the same"
echo " registry as async requests (see tests/radsec-shared-ids.c)."
echo "===================================================="

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
CERT=radsec-shared-ids-cert$PID.pem
KEY=radsec-shared-ids-key$PID.pem
SERVEROUT=radsec-shared-ids-server-out$PID.txt
CLIENTOUT=radsec-shared-ids-client-out$PID.txt

eval "$GETPORT"

function finish {
	rm -f $CERT $KEY $SERVEROUT $CLIENTOUT
}
trap finish EXIT

${OPENSSL} req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout $KEY -out $CERT -subj "/CN=127.0.0.1" \
	-addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
if test ! -s "$CERT" || test ! -s "$KEY"; then
	echo "Could not generate a throwaway test certificate with openssl"
	exit 1
fi

python3 ${srcdir}/watchdog-aaa-server.py --host 127.0.0.1 --port ${PORT} \
	--cert $CERT --key $KEY --timeout 30 --accept-timeout 5 \
	--accepts 1 >$SERVEROUT 2>&1 &
SERVERPID=$!
sleep 0.5

${top_builddir}/tests/radsec-shared-ids ${PORT} $CERT >$CLIENTOUT
RET=$?
cat $CLIENTOUT

wait ${SERVERPID}
echo "--- peer output ---"
cat $SERVEROUT

if test ${RET} -ne 0; then
	echo "[ FAIL ] radsec-shared-ids reported a failure -- see its stderr above"
	exit 1
fi

# The peer's log must hold exactly the expected Access-Request and
# watchdog: none sent while every Identifier was in flight.
if test "$(grep -E '^(AUTH|WATCHDOG) ' $SERVEROUT | sed 's/ msgauth=.*//')" != \
	"$(sed -n 's/^EXPECT //p' $CLIENTOUT)"; then
	echo "[ FAIL ] the Identifiers on the wire differ from the free ones"
	exit 1
fi

echo "[  OK  ] blocking requests and watchdogs used only free Identifiers"
exit 0
