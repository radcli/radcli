#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# RadSec dispatch-must-not-wait-to-send test: see radsec-send-backpressure.c.
# The peer floods Disconnect-Requests and then stops reading for a while,
# so DAE replies fill the session's send window while an async request
# keeps retransmitting into it; every radcli_ctx_dispatch() call is timed.

srcdir="${srcdir:-.}"

echo "===== RadSec dispatch-must-not-wait-to-send test ====="

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
CERT=radsec-send-backpressure-cert$PID.pem
KEY=radsec-send-backpressure-key$PID.pem
SERVEROUT=radsec-send-backpressure-server-out$PID.txt

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

python3 ${srcdir}/radsec-backpressure-server.py --host 127.0.0.1 --port ${PORT} \
	--cert $CERT --key $KEY --count 2000 --timeout 15 --hold 10 >$SERVEROUT 2>&1 &
SERVERPID=$!
sleep 0.5

${top_builddir}/tests/radsec-send-backpressure ${PORT} $CERT
RET=$?

wait ${SERVERPID}

echo "--- peer output ---"
cat $SERVEROUT

if test ${RET} -ne 0; then
	echo "[ FAIL ] radsec-send-backpressure reported a dispatch() call that waited to send"
	exit 1
fi

echo "[  OK  ] radcli_ctx_dispatch() never waited to send under backpressure"
exit 0
