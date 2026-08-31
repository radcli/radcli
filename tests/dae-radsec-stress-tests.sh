#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# DAE-over-RadSec concurrency stress test: tests/dae-radsec-stress.c (two
# sender threads driving radcli_aaa() Access-Request/Accounting-Request
# exchanges over one TLS connection, plus a dedicated poll()-driven
# dispatch loop) against tests/radsec-stress-server.py (a single-threaded,
# purely blocking peer that answers the ordinary traffic while also
# interleaving unsolicited Disconnect-Request/CoA-Request messages on the
# exact same connection). See dae-radsec-stress.c's own header comment for
# the full rationale and the REQ-DAE-* traceability this test covers, and
# for two explicitly flagged coverage gaps (RadSec queue overflow, DTLS)
# not attempted here.
#
# Plain loopback TCP/TLS, no root, no network namespace -- same shape as
# dae-radsec-tests.sh, whose "authserver as a literal IP, cert with an IP
# SAN, never a hostname" lesson (avoiding "localhost" resolving to ::1
# first with nothing listening there) this script follows from the start.

srcdir="${srcdir:-.}"

echo "===== DAE-over-RadSec concurrency stress test ====="
echo " Two sender threads perform 25 Access-Request/Accounting-Request"
echo " exchanges each (radcli_aaa()) on one shared TLS connection, while"
echo " the peer interleaves 10 unsolicited Disconnect-Request/CoA-Request"
echo " messages on that same connection, delivered via a dedicated"
echo " poll()-driven dispatch loop. Asserts: every ordinary reply has the"
echo " correct code (never a timeout, error, or DAE code); every DAE"
echo " message is delivered exactly once with the correct User-Name/"
echo " Acct-Session-Id; radcli_dae_handler is invoked ONLY from the poll"
echo " thread, never from inside a sender thread's radcli_aaa() call."
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
CERT=dae-radsec-stress-cert$PID.pem
KEY=dae-radsec-stress-key$PID.pem
SERVEROUT=dae-radsec-stress-server-out$PID.txt

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

# 50 ordinary requests total (2 sender threads x 25 each, matching
# dae-radsec-stress.c's N_SENDERS/N_PER_THREAD), one DAE message every 5th
# one answered (matching DAE_EVERY) = 10 DAE messages -- keep these three
# numbers in sync with the constants in dae-radsec-stress.c.
python3 ${srcdir}/radsec-stress-server.py --host 127.0.0.1 --port ${PORT} \
	--cert $CERT --key $KEY --ordinary 50 --dae-every 5 \
	--timeout 25 >$SERVEROUT 2>&1 &
SERVERPID=$!
sleep 0.5

${top_builddir}/tests/dae-radsec-stress ${PORT} $CERT
RET=$?

wait ${SERVERPID}
SERVER_RET=$?

echo "--- peer output ---"
cat $SERVEROUT

if test ${RET} -ne 0; then
	echo "[ FAIL ] dae-radsec-stress reported failure (exit ${RET}) -- see its stderr above"
	exit 1
fi
if test ${SERVER_RET} -ne 0; then
	echo "[ FAIL ] radsec-stress-server.py reported failure (exit ${SERVER_RET})"
	exit 1
fi

echo "[  OK  ] DAE-over-RadSec concurrency stress test passed"
exit 0
