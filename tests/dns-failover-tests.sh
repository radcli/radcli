#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== radcli_transport_exchange() DNS address failover tests ====="
echo " 1. A server name resolving to multiple addresses falls back to the"
echo "    next address when the first one never replies"
echo "===================================================================="

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
LOG=radius-server-$PID.log
RADIUSPID=""

eval "$GETPORT"

function finish {
	test -n "${RADIUSPID}" && kill ${RADIUSPID} >/dev/null 2>&1
	rm -f $TMPFILE $LOG
	rm -f radiusclient-temp$PID.conf
	rm -f servers-temp$PID
}
trap finish EXIT

# "localhost" normally resolves to both ::1 and 127.0.0.1 (no /etc/hosts
# changes needed). Which comes first from getaddrinfo() is system-dependent,
# so instead of guessing, ask Python -- using the same hints radcli's
# rc_getaddrinfo() uses (AF_UNSPEC, SOCK_DGRAM) -- and bind the mock server
# to whichever loopback address getaddrinfo() returns *second*. That
# guarantees the *first* resolved address always has nothing listening on
# it (a real, silent timeout: an unconnected UDP socket, which is what
# radcli uses, gets no ICMP-driven error back), so a successful run can only
# mean radcli_transport_exchange() moved on to the second address.
ORDER=$(python3 - <<'PYEOF'
import socket
res = socket.getaddrinfo('localhost', 1, socket.AF_UNSPEC, socket.SOCK_DGRAM)
families = []
for family, _, _, _, _ in res:
	name = 'inet6' if family == socket.AF_INET6 else 'inet'
	if name not in families:
		families.append(name)
print(' '.join(families))
PYEOF
)
set -- $ORDER
if test "$#" -lt 2; then
	echo "localhost does not resolve to both an IPv4 and an IPv6 address on this system"
	exit 77
fi
FIRST="$1"
SECOND="$2"

if test "$SECOND" = "inet6"; then
	BIND_ADDR="::1"
else
	BIND_ADDR="127.0.0.1"
fi

echo "getaddrinfo(\"localhost\") order: $FIRST, $SECOND -- binding mock server to $BIND_ADDR"

wait_for_server() {
	local i
	for i in 1 2 3 4 5 6 7 8; do
		check_if_port_in_use ${PORT} && return 0
		sleep 0.5
	done
	return 1
}

python3 ${srcdir}/radius-server.py \
	--port ${PORT} --secret testing123 --bind "${BIND_ADDR}" >$LOG 2>&1 &
RADIUSPID=$!
wait_for_server || { echo "[ FAIL ] mock server did not start"; cat $LOG; exit 1; }

cat >radiusclient-temp$PID.conf <<EOF
nas-identifier my-nas-id
authserver  localhost:${PORT}
servers     ./servers-temp$PID
dictionary  ${srcdir}/../etc/dictionary
default_realm
radius_timeout  1
radius_retries  1
bindaddr    *
EOF
echo "localhost/localhost	testing123" >servers-temp$PID

START=$(date +%s)
run_test "Auth succeeds via the second resolved address after the first times out" \
	"${top_builddir}/src/radiusclient -D -i -f radiusclient-temp$PID.conf User-Name=test Password=test" \
	|| exit 1
END=$(date +%s)
ELAPSED=$((END - START))

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0; then
	echo "[ FAIL ] Expected Framed-Protocol = 'PPP' in response"
	exit 1
fi

# The first (unreachable) address must have burned its full retry budget
# (radius_timeout=1s * (radius_retries=1 + 1) = 2s) before the second
# address got a chance to answer -- otherwise this run proves nothing about
# failover (e.g. a config mistake sending straight to the working address).
# Generous upper bound to stay robust under load.
if test $ELAPSED -lt 2; then
	echo "[ FAIL ] request completed in ${ELAPSED}s -- too fast to have timed out on the first address (radius_timeout=1s, radius_retries=1); failover was not exercised"
	exit 1
fi
if test $ELAPSED -ge 15; then
	echo "[ FAIL ] request took ${ELAPSED}s -- expected close to 2s (one exhausted retry budget), not a hang on both addresses"
	exit 1
fi

echo "[  OK  ] failover took ${ELAPSED}s, consistent with exactly one address timing out first"

grep "received Access-Request" $LOG >/dev/null 2>&1
if test $? != 0; then
	echo "[ FAIL ] mock server on the second address never received the request"
	cat $LOG
	exit 1
fi

exit 0
