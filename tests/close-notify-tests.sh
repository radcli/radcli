#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#   1. Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#   2. Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#
#   THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
#   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#   ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
#   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#   SUCH DAMAGE.

# Test that rc_destroy() sends TLS and DTLS close_notify alerts.
#
# Architecture:
#   radcli client <--TLS/DTLS--> close-notify-server <--UDP--> radius-server.py
#
# close-notify-server exits 0 if close_notify was received after the
# exchange, 1 if not (bug: deinit_session() missing gnutls_bye()).
# Does not require root; uses loopback addresses only.

srcdir="${srcdir:-.}"

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

echo "===== TLS/DTLS close_notify tests ====="

PID=$$
TMPFILE="tmp-cn-$PID.out"
BEPID_TLS=""
BEPID_DTLS=""
SRVPID=""
SERVERS_FILE="servers-cn-$PID"
TLS_CONF="conf-tls-cn-$PID"
DTLS_CONF="conf-dtls-cn-$PID"

function finish {
	test -n "${SRVPID}"     && kill ${SRVPID}     >/dev/null 2>&1
	test -n "${BEPID_TLS}"  && kill ${BEPID_TLS}  >/dev/null 2>&1
	test -n "${BEPID_DTLS}" && kill ${BEPID_DTLS} >/dev/null 2>&1
	rm -f "$TMPFILE" "$SERVERS_FILE" "$TLS_CONF" "$DTLS_CONF"
}
trap finish EXIT

wait_for_server() {
	local port="${1:-${PORT}}"
	local i
	for i in 1 2 3 4 5 6 7 8; do
		check_if_port_in_use ${port} && return 0
		sleep 0.5
	done
	return 1
}

# Two plain-UDP backends, one per mode: radcli fixes the RADIUS/TLS shared
# secret to "radsec" (RFC 6614 SS3.4) and the RADIUS/DTLS one to "radius/dtls"
# (RFC 7360 SS2.3) regardless of what's in SERVERS_FILE (see
# tls-msg-auth-tests.sh), and verifies the Response Authenticator digest
# against whichever one applies -- a mismatched backend secret makes every
# reply fail digest validation.
eval "$GETPORT"
BEPORT_TLS=${PORT}
python3 "${srcdir}/radius-server.py" \
	--port "${BEPORT_TLS}" --secret radsec --msg-auth correct \
	>/dev/null 2>&1 &
BEPID_TLS=$!
wait_for_server "${BEPORT_TLS}" || { echo "FAIL: radius-server.py (TLS backend) did not start"; exit 1; }

eval "$GETPORT"
BEPORT_DTLS=${PORT}
python3 "${srcdir}/radius-server.py" \
	--port "${BEPORT_DTLS}" --secret "radius/dtls" --msg-auth correct \
	>/dev/null 2>&1 &
BEPID_DTLS=$!
wait_for_server "${BEPORT_DTLS}" || { echo "FAIL: radius-server.py (DTLS backend) did not start"; exit 1; }

# Common servers file (address must match authserver; secret ignored for TLS/DTLS).
echo "127.0.0.1/127.0.0.1	testing123" >"${SERVERS_FILE}"

# write_conf MODE PORT — writes conf-{MODE}-cn-$PID
write_conf() {
	local mode="$1"
	local frontend_port="$2"
	cat >"conf-${mode}-cn-${PID}" <<EOF
serv-type         ${mode}
tls-ca-file       ${srcdir}/dtls/ca.pem
tls-cert-file     ${srcdir}/dtls/clicert.pem
tls-key-file      ${srcdir}/dtls/clikey.pem
tls-verify-hostname false
authserver        127.0.0.1:${frontend_port}
acctserver        127.0.0.1:${frontend_port}
servers           ${SERVERS_FILE}
dictionary        ${srcdir}/../etc/dictionary
radius_timeout    5
radius_retries    1
bindaddr          *
EOF
}

# run_test MODE — returns 0 on pass, 1 on fail
run_close_notify_test() {
	local mode="$1"
	local dtls_flag=""
	local backend_port="${BEPORT_TLS}"
	test "${mode}" = "dtls" && { dtls_flag="--dtls"; backend_port="${BEPORT_DTLS}"; }

	eval "$GETPORT"
	local frontend_port=${PORT}
	write_conf "${mode}" "${frontend_port}"

	${top_builddir}/tests/close-notify-server ${dtls_flag} \
		--port "${frontend_port}" \
		--backend-port "${backend_port}" \
		--ca  "${srcdir}/dtls/ca.pem" \
		--cert "${srcdir}/raddb/cert-rsa.pem" \
		--key  "${srcdir}/raddb/key-rsa.pem" \
		>"${TMPFILE}" 2>&1 &
	SRVPID=$!

	wait_for_server || {
		echo "FAIL: ${mode} close-notify-server did not start"
		kill ${SRVPID} 2>/dev/null; SRVPID=""
		return 1
	}

	${top_builddir}/src/radiusclient -D -i \
		-f "conf-${mode}-cn-${PID}" \
		User-Name=test Password=test >/dev/null

	wait ${SRVPID}
	local srv_ret=$?
	SRVPID=""

	if test ${srv_ret} -ne 0; then
		cat "${TMPFILE}"
		return 1
	fi
	return 0
}

run_close_notify_test tls
if test $? -ne 0; then
	echo "FAIL: TLS close_notify not sent (deinit_session() missing gnutls_bye())"
	exit 1
fi
echo "[  OK  ] TLS: close_notify sent correctly"

run_close_notify_test dtls
if test $? -ne 0; then
	echo "FAIL: DTLS close_notify not sent (deinit_session() missing gnutls_bye())"
	exit 1
fi
echo "[  OK  ] DTLS: close_notify sent correctly"

echo ""
exit 0
