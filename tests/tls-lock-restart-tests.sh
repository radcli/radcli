#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== TLS session lock across a session restart ====="
echo " The lock held around a TLS exchange must still be releasable after"
echo " the session underneath it is restarted (see tests/tls-lock-restart.c)."
echo "======================================================"

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
CERT=tls-lock-restart-cert$PID.pem
KEY=tls-lock-restart-key$PID.pem
SERVEROUT=tls-lock-restart-server-out$PID.txt

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

python3 ${srcdir}/watchdog-aaa-server.py --host 127.0.0.1 --port ${PORT} \
	--cert $CERT --key $KEY --timeout 2 --accept-timeout 5 \
	--accepts 2 >$SERVEROUT 2>&1 &
SERVERPID=$!
sleep 0.5

${top_builddir}/tests/tls-lock-restart ${PORT} $CERT
RET=$?

wait ${SERVERPID}
echo "--- peer output ---"
cat $SERVEROUT

if test ${RET} -ne 0; then
	echo "[ FAIL ] tls-lock-restart reported a failure -- see its stderr above"
	exit 1
fi

if test $(grep -c '^ACCEPT ' $SERVEROUT) -ne 2; then
	echo "[ FAIL ] expected the restart to open a second TLS connection"
	exit 1
fi

echo "[  OK  ] the session lock survived a session restart"
exit 0
