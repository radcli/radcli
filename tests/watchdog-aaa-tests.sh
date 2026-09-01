#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# RFC 3539 SS3.4 watchdog behavior for radcli_ctx_dispatch()'s internal watchdog send/
# radcli_ctx_get_poll(), driven entirely through ordinary AAA traffic (no
# radcli_dae_*() call anywhere in tests/watchdog-aaa.c -- see its header
# comment). Peer: tests/watchdog-aaa-server.py.

srcdir="${srcdir:-.}"

echo "===== watchdog + ordinary AAA (non-DAE) test ====="
echo " 1. the watchdog deadline resets on ANY message received from the"
echo "    peer, not only a watchdog round trip"
echo " 2. watchdog-interval cannot be set below 6 seconds"
echo " 3. an unsolicited reply to a watchdog is read and silently dropped"
echo " 4. a peer silent for 2.5x the interval -- connection still open,"
echo "    just unanswered -- is presumed dead and the connection"
echo "    reestablished"
echo "==================================================="

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
CERT=watchdog-aaa-cert$PID.pem
KEY=watchdog-aaa-key$PID.pem
SERVEROUT=watchdog-aaa-server-out$PID.txt

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

# --timeout (per-connection read) is kept short relative to --accept-timeout
# so the peer gives up on the now-idle first connection and returns to
# accept() well before watchdog-aaa's phase 4 (which sends nothing for well
# over 2.5x watchdog-interval) forces a reconnect -- see
# watchdog-aaa-server.py's --timeout help text.
python3 ${srcdir}/watchdog-aaa-server.py --host 127.0.0.1 --port ${PORT} \
	--cert $CERT --key $KEY --timeout 8 --accept-timeout 40 \
	--accepts 2 >$SERVEROUT 2>&1 &
SERVERPID=$!
sleep 0.5

${top_builddir}/tests/watchdog-aaa ${PORT} $CERT
RET=$?

wait ${SERVERPID}

echo "--- peer output ---"
cat $SERVEROUT

if test ${RET} -ne 0; then
	echo "[ FAIL ] watchdog-aaa reported a failure -- see its stderr above"
	exit 1
fi

if test $(grep -c '^AUTH .*msgauth=ok' $SERVEROUT) -lt 4; then
	echo "[ FAIL ] expected 4 verified ordinary Access-Requests in the peer log"
	exit 1
fi

if ! grep -q '^WATCHDOG id=.*msgauth=ok' $SERVEROUT; then
	echo "[ FAIL ] the peer did not see a valid, verified Status-Server"
	exit 1
fi

if test $(grep -c '^ACCEPT ' $SERVEROUT) -lt 2; then
	echo "[ FAIL ] expected a second TLS connection accepted -- the peer going "
	echo "         silent should have made radcli reconnect (REQ-WATCHDOG-NET-003)"
	exit 1
fi

echo "[  OK  ] watchdog deadline resets on any peer message; watchdog-interval floor enforced;"
echo "         an unsolicited watchdog reply was silently absorbed; a silent peer triggered reconnection"
exit 0
