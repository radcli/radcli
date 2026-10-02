#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== async and blocking requests on one TLS session ====="
echo " A blocking request that reads the reply to an in-flight async"
echo " request must deliver it, not discard it"
echo " (see tests/request-tls-interleave.c)."
echo "=========================================================="

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
CERT=request-tls-interleave-cert$PID.pem
KEY=request-tls-interleave-key$PID.pem
SERVEROUT=request-tls-interleave-server-out$PID.txt

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
	--cert $CERT --key $KEY --timeout 5 --accept-timeout 5 \
	--accepts 1 >$SERVEROUT 2>&1 &
SERVERPID=$!
sleep 0.5

${top_builddir}/tests/request-tls-interleave ${PORT} $CERT
RET=$?

wait ${SERVERPID}
echo "--- peer output ---"
cat $SERVEROUT

if test ${RET} -ne 0; then
	echo "[ FAIL ] request-tls-interleave reported a failure -- see its stderr above"
	exit 1
fi

if test $(grep -c '^AUTH ' $SERVEROUT) -ne 2; then
	echo "[ FAIL ] expected exactly two Access-Requests (no retransmission)"
	exit 1
fi

echo "[  OK  ] the async reply read by a blocking request reached its request"
exit 0
