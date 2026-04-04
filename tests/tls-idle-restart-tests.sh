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

# Test for TLS reconnection after server-side idle close (issue #89).
#
# This test verifies that after the RADIUS/TLS server closes an idle
# connection, radcli can reconnect and serve subsequent requests within
# the TIME_ALIVE (120s) window.
#
# The test kills radiusd after the first request and restarts it after
# two failed reconnection attempts by the client.  The third attempt
# (request 4 in the client) must succeed; with the bug it fails because
# the TIME_ALIVE time guard in restart_session() blocks reconnection.

srcdir="${srcdir:-.}"
STATEDIR=$(mktemp -d /tmp/tls-idle-restart-XXXXXX)
CONFFILE="conf-idle-restart.$$.tmp"
SERVERSFILE="servers-idle-restart.$$.tmp"
PID=$$
CLI_ADDRESS=10.203.23.1
ADDRESS=10.203.24.1

function finish {
	rm -f "$CONFFILE" "$SERVERSFILE"
	rm -rf "$STATEDIR"
}

. ${srcdir}/ns.sh

echo "***********************************************"
echo "Test: TLS reconnect after server idle close (issue #89)"
echo "***********************************************"

sed -e 's|dtls/|'"${srcdir}"'/dtls/|g' \
    -e 's/localhost/'"$ADDRESS"'/g' \
    -e 's/servers-tls-temp/'"$SERVERSFILE"'/g' \
    <"$srcdir"/dtls/radiusclient-tls.conf >"$CONFFILE"
sed 's/localhost/'"$ADDRESS"'/g' <"$srcdir"/servers >"$SERVERSFILE"

# ns.sh waits for port 1812 (UDP/TCP RADIUS), but TLS uses port 2083.
# Wait for that port too before starting the client.
wait_for_port 2083

# Verify TLS connectivity before starting the background client.
# This ensures rc_init_tls() (called inside rc_read_config) will succeed.
${CMDNS1} ../src/radiusclient -D -f "$CONFFILE" User-Name=test Password=test \
    >/dev/null 2>&1
if test $? != 0; then
	echo "Error: initial TLS connectivity check failed"
	exit 1
fi

# Start the test client in the background; it coordinates with us via
# flag files in $STATEDIR.
${CMDNS1} ./tls-idle-restart -f "$CONFFILE" -S "$STATEDIR" \
    User-Name=test Password=test &
TESTPID=$!

# Helper: poll for a flag file with a timeout.
wait_for_state() {
	local flag="$1"
	local desc="$2"
	local i
	for i in $(seq 1 30); do
		if test -f "$STATEDIR/$flag"; then
			return 0
		fi
		sleep 1
	done
	echo "Error: timed out waiting for '$desc'"
	kill "$TESTPID" 2>/dev/null
	exit 1
}

# Step 1: wait for the client to complete its first (successful) request.
wait_for_state "ready_to_kill" "client initial request"

# Step 2: kill radiusd to simulate an idle-timeout close.
# The kernel will send FIN to the client's open TLS connection.
echo " * Killing radiusd (simulating idle timeout)..."
kill "$RADIUSPID"
wait "$RADIUSPID" 2>/dev/null
RADIUSPID=""

# Notify the client that the server is gone.
touch "$STATEDIR/server_killed"

# Step 3: wait for the client to finish its two failing requests
# (request 2 detects the FIN; request 3 tries restart_session which
# fails because the server is still down, setting last_restart=now).
wait_for_state "restart_server" "client restart signal"

# Step 4: bring radiusd back.  The client will now attempt request 4
# within the TIME_ALIVE window (last_restart was set moments ago).
echo " * Restarting radiusd..."
${CMDNS2} ${RADIUSD} -d "${srcdir}"/raddb/ -fxx -l stdout 2>&1 &
RADIUSPID=$!
wait_for_port 1812
wait_for_port 2083

# Notify the client that the server is up again.
touch "$STATEDIR/server_up"

# Step 5: wait for the test to finish and collect its exit code.
wait "$TESTPID"
RET=$?

if test "$RET" != 0; then
	echo "FAIL: TLS did not reconnect after server restart within TIME_ALIVE window (issue #89)"
	exit 1
fi

echo "PASS"
exit 0
