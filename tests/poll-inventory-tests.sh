#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# REQ-NET2-NET-001: radcli_ctx_get_poll() reports every socket radcli holds
# for a RadSec dae-accept=yes ctx. tests/poll-inventory.c covers every other
# serv-type x DAE combination standalone; this case needs a live TLS peer
# because radcli_dae_start() completes the handshake. The peer is
# tests/radius-server.py (REQ-GEN-TEST-004); the client is a C program
# rather than src/radiusclient, which never calls radcli_ctx_get_poll().

srcdir="${srcdir:-.}"

echo "===== radcli_ctx_get_poll() socket inventory, RadSec dae-accept=yes ====="

if ! python3 -c 'import ssl' 2>/dev/null; then
	echo "This test requires python3 with the ssl module"
	exit 77
fi
OPENSSL=$(which openssl)
if test -z "${OPENSSL}"; then
	echo "This test requires openssl (to generate a throwaway test certificate)"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$PID.out
CERT=poll-inventory-cert$PID.pem
KEY=poll-inventory-key$PID.pem
RADIUSPID=""

eval "$GETPORT"

function finish {
	test -n "${RADIUSPID}" && kill ${RADIUSPID} >/dev/null 2>&1
	rm -f $TMPFILE $CERT $KEY
}
trap finish EXIT

# RadSec DAE refuses to run without hostname verification (REQ-DAE-INIT-007),
# and no checked-in certificate names 127.0.0.1 as an IP address.
${OPENSSL} req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout $KEY -out $CERT -subj "/CN=127.0.0.1" \
	-addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
if test ! -s "$CERT" || test ! -s "$KEY"; then
	echo "Could not generate a throwaway test certificate with openssl"
	exit 1
fi

python3 ${srcdir}/radius-server.py \
	--transport tls --port ${PORT} --secret radsec --msg-auth correct \
	--tls-cert $CERT --tls-key $KEY >/dev/null 2>&1 &
RADIUSPID=$!

for i in 1 2 3 4 5 6 7 8; do
	check_if_port_in_use ${PORT} && break
	sleep 0.5
done
if ! check_if_port_in_use ${PORT}; then
	echo "radius-server.py did not start"
	exit 1
fi

run_test "Every socket of a RadSec dae-accept=yes ctx is reported" \
	"${top_builddir}/tests/poll-inventory ${PORT} $CERT" || exit 1

exit 0
