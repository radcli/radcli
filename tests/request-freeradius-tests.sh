#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== radcli2 request/reply / FreeRADIUS interoperability ====="
echo " 1. radcli_request_new()/_perform() end-to-end for an Access-Request,"
echo "    through the real transport (radcli_transport_exchange())"
echo " 2. Same, for an Accounting-Request -- the zero-vector request path"
echo "    the Access-Request check above does not exercise"
echo " 3. radcli_request_send_noreply() -- verified by grepping radiusd's"
echo "    own debug trace for evidence it actually received and answered"
echo "    the fire-and-forget request, since this process never reads a"
echo "    reply to check itself"
echo " 4. radcli_avp_add_counter64()'s Acct-Input-Octets/-Gigawords pair"
echo "    is accepted by a real server"
echo "================================================================="
echo "This test will use a radius server on localhost"
echo "and which can be executed with ns.sh"
echo "================================================================="

PID=$$
CLI_ADDRESS=10.203.1.1
ADDRESS=10.203.2.1

# Matches tests/request-freeradius.c's NOREPLY_USER.
NOREPLY_USER="radcli-noreply-interop-check"
export RADIUSD_LOGFILE=$(mktemp)

function finish {
	rm -f "${RADIUSD_LOGFILE}"
}
# ns.sh only registers its own EXIT trap (which calls finish) after its
# root/radiusd/ip-netns checks; without this, an early "exit 77" from one
# of those checks would skip finish() and leak RADIUSD_LOGFILE.
trap finish EXIT

. ${srcdir}/ns.sh

${CMDNS1} ${top_builddir}/tests/request-freeradius ${ADDRESS}
if test $? != 0;then
	echo "Error in radcli2 request/reply / FreeRADIUS interoperability check"
	exit 1
fi

# radiusd processes the no_wait Accounting-Request asynchronously with
# respect to the client program above returning, so poll its captured
# debug trace briefly rather than checking it exactly once. Each request
# radiusd's -x trace logs is prefixed "(N) ...", the same N on every line
# belonging to it (see tests/raddb's debug format, e.g. "(0) Received
# Accounting-Request ..." / "(0)   User-Name = ..." / "(0) Sent
# Accounting-Response ..."), so requiring the SAME N on both the
# NOREPLY_USER line and a "Sent Accounting-Response" line -- not just both
# strings appearing anywhere in the file -- ties the response to this
# specific request, not to one of the other Accounting-Requests check 2
# above already sent in the same run.
found=0
for i in $(seq 1 20); do
	reqnum=$(awk -F'[()]' -v u="${NOREPLY_USER}" \
		'$0 ~ "User-Name = \"" u "\"" { print $2; exit }' "${RADIUSD_LOGFILE}" 2>/dev/null)
	if test -n "${reqnum}" && \
	   grep -q "^(${reqnum}) Sent Accounting-Response" "${RADIUSD_LOGFILE}" 2>/dev/null; then
		found=1
		break
	fi
	sleep 0.2
done

if test "${found}" != 1; then
	echo "Error: radiusd's debug trace shows no sign of the no_wait Accounting-Request"
	echo "(User-Name ${NOREPLY_USER}) -- radcli_request_send_noreply() may not have"
	echo "actually reached the server. Captured trace:"
	cat "${RADIUSD_LOGFILE}"
	exit 1
fi
echo "OK: radiusd's own debug trace confirms the no_wait Accounting-Request was received and answered"

exit 0
