#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# Dedicated reproducer for a radcli_encode_request() bug (lib/request.c):
# an Access-Request built by radcli_request_new()/_perform() over a TLS
# authserver with no inline secret (the normal, documented configuration)
# must have its Message-Authenticator and User-Password keyed with the RFC
# 6614 SS2.3/RFC 7360 SS3.2 fixed RadSec secret, not an empty one. See
# tests/request-tls-secret.c's header comment.

srcdir="${srcdir:-.}"

echo "===== radcli_encode_request() TLS secret test ====="
echo " Access-Request's Message-Authenticator and User-Password must both"
echo " be keyed with the RFC 6614/7360 fixed RadSec secret, not whatever"
echo " (empty) secret the authserver config resolves to"
echo "====================================================="

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
CERT=request-tls-secret-cert$PID.pem
KEY=request-tls-secret-key$PID.pem
SERVEROUT=request-tls-secret-server-out$PID.txt

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

python3 ${srcdir}/request-tls-secret-server.py --host 127.0.0.1 --port ${PORT} \
	--cert $CERT --key $KEY --expect-password test >$SERVEROUT 2>&1 &
SERVERPID=$!
sleep 0.5

${top_builddir}/tests/request-tls-secret ${PORT} $CERT
RET=$?

wait ${SERVERPID}

echo "--- peer output ---"
cat $SERVEROUT

if test ${RET} -ne 0; then
	echo "[ FAIL ] request-tls-secret reported a failure -- see its stderr above"
	exit 1
fi

if ! grep -q '^AUTH .*msgauth=ok' $SERVEROUT; then
	echo "[ FAIL ] Message-Authenticator did not verify against the RFC 6614/7360 fixed secret"
	exit 1
fi

if ! grep -q '^AUTH .*password=ok' $SERVEROUT; then
	echo "[ FAIL ] User-Password did not decrypt correctly against the RFC 6614/7360 fixed secret"
	exit 1
fi

echo "[  OK  ] Message-Authenticator and User-Password both keyed with the RFC 6614/7360 fixed secret"
exit 0
