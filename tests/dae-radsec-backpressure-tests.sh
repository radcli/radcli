#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# DAE-over-RadSec dispatch-must-not-block test: see dae-radsec-backpressure.c's
# header comment for the full invariant and mechanism. In short: a poll()-
# driven application's contract is that radcli_ctx_dispatch(), called
# because the descriptor was reported readable, never performs a blocking
# wait of its own -- including one hidden inside sending a reply as a side
# effect of what it just read. This provokes exactly that by having the
# peer (radsec-backpressure-server.py) shrink its own receive buffer and
# flood a burst of Disconnect-Request messages without ever reading
# anything back, then timing every radcli_ctx_dispatch() call on the
# client side.

srcdir="${srcdir:-.}"

echo "===== DAE-over-RadSec dispatch-must-not-block test ====="
echo " The peer shrinks its own TCP receive buffer and sends 200"
echo " Disconnect-Request messages back-to-back without ever reading"
echo " radcli's ACKs, forcing radcli's reply sends to hit a full TCP"
echo " send window. Asserts every radcli_ctx_dispatch() call -- invoked"
echo " only because poll() reported the descriptor readable -- returns"
echo " within a short bound regardless, never blocking for radius_timeout"
echo " waiting to push a reply it could instead defer."
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
CERT=dae-radsec-backpressure-cert$PID.pem
KEY=dae-radsec-backpressure-key$PID.pem
SERVEROUT=dae-radsec-backpressure-server-out$PID.txt

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

# 200 burst messages, matching EXPECTED_BURST in dae-radsec-backpressure.c.
python3 ${srcdir}/radsec-backpressure-server.py --host 127.0.0.1 --port ${PORT} \
	--cert $CERT --key $KEY --count 200 --timeout 15 >$SERVEROUT 2>&1 &
SERVERPID=$!
sleep 0.5

${top_builddir}/tests/dae-radsec-backpressure ${PORT} $CERT
RET=$?

wait ${SERVERPID}

echo "--- peer output ---"
cat $SERVEROUT

if test ${RET} -ne 0; then
	echo "[ FAIL ] dae-radsec-backpressure reported a blocking dispatch() call -- see its stderr above"
	exit 1
fi

echo "[  OK  ] radcli_ctx_dispatch() never blocked under send-side backpressure"
exit 0
