#!/bin/bash

# Copyright (C) 2026 Italo Francis
#
# License: BSD
#
# REQ-NET-NET-020: a TLS session to a server that silently drops the SYN
# must fail within radius_timeout, not after the kernel's SYN retries.

srcdir="${srcdir:-.}"
TMPFILE=tmp$$.tmp
CONFFILE="conf.$$.tmp"
SERVERSFILE="servers.tmp$$.tmp"
PID=$$
CLI_ADDRESS=10.203.31.1
ADDRESS=10.203.32.1
# Routed to the server namespace, but assigned to no interface there and
# not forwarded: the SYN is dropped silently, with no RST or ICMP.
BLACKHOLE=10.203.33.1
NO_RADIUSD=1

function finish {
	rm -f $TMPFILE $SERVERSFILE $CONFFILE
}

. ${srcdir}/ns.sh

sed -e 's|dtls/|'${srcdir}'/dtls/|g' -e 's/localhost/'$BLACKHOLE'/g' \
    -e 's/servers-tls-temp/'$SERVERSFILE'/g' \
    -e 's/^radius_timeout.*/radius_timeout 2/' -e 's/^radius_retries.*/radius_retries 0/' \
    <$srcdir/dtls/radiusclient-tls.conf >$CONFFILE
sed 's/localhost/'$BLACKHOLE'/g' <$srcdir/servers >$SERVERSFILE

START=$(date +%s)
${CMDNS1} timeout 200 ${top_builddir}/src/radiusclient -f $CONFFILE User-Name=test Password=test >$TMPFILE 2>&1
RET=$?
ELAPSED=$(( $(date +%s) - START ))

if test $RET = 0; then
	echo "Error: request to an unreachable server succeeded"
	cat $TMPFILE
	exit 1
fi

if test $ELAPSED -gt 10; then
	echo "Error: request to an unreachable server took ${ELAPSED}s (radius_timeout 2)"
	exit 1
fi

echo "Request to an unreachable server failed after ${ELAPSED}s"
exit 0
