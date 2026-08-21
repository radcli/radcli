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
echo "================================================================="
echo "This test will use a radius server on localhost"
echo "and which can be executed with ns.sh"
echo "================================================================="

PID=$$
CLI_ADDRESS=10.203.1.1
ADDRESS=10.203.2.1

function finish {
	:
}

. ${srcdir}/ns.sh

${CMDNS1} ${top_builddir}/tests/request-freeradius ${ADDRESS}
if test $? != 0;then
	echo "Error in radcli2 request/reply / FreeRADIUS interoperability check"
	exit 1
fi

exit 0
