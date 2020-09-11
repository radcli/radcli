#!/bin/bash

# License: 2-clause BSD
#
# Copyright (c) 2017, Martin Belanger <nitram_67@hotmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

srcdir="${srcdir:-.}"

CLI_ADDRESS=10.203.33.1
ADDRESS=10.203.34.1
DICT_FILE=skip-unknown-vsa.sh.dictionary
CONF_FILE=skip-unknown-vsa.sh.conf
OUTP_FILE=skip-unknown-vsa.sh.out

function finish {
	rm -f ${OUTP_FILE} ${CONF_FILE} ${DICT_FILE}
}

. ${srcdir}/ns.sh

echo "********************************************************************************"
echo "This test will use a radius server on localhost previously launched with"
echo "ns.sh. The test sends an authentication message to the server and"
echo "expects an Access-Accept response containing VSAs for two vendors:"
echo "   1) Microsoft"
echo "   2) Roaring Penguin"
echo ""
echo "The idea is to show that if a dictionary has not been provided for one of those"
echo "vendors, then VSAs for that missing vendor will be skipped, but VSAs for the"
echo "other vendor (i.e. the one with a provided dictionary) will be processed."
echo ""
echo "Four tests are performed:"
echo "   1) Only the Microsoft dictionary is provided"
echo "       1a) Authenticate a user for which the Roaring Penguin VSA is sent as the"
echo "           last attribute"
echo "       1b) Authenticate a user for which the Microsoft VSA is sent as the"
echo "           last attribute"
echo ""
echo "   2) Both the Microsoft and Roaring Penguin dictionaries are provided"
echo "       2a) Same as 1a)"
echo "       1b) Same as 1b)"
echo ""
echo "Expected results:"
echo "   When the Roaring Penguin dictionary is not provided, the VSAs from that"
echo "   vendor should be skipped, but the Microsoft VSAs should be processed."
echo ""
echo "   When both dictionaries are provided, the VSAs from both vendors"
echo "   should be processed."


# Create a dictionary with support for microsoft VSAs only
cp ../etc/dictionary ${DICT_FILE}
echo '$'INCLUDE ../etc/dictionary.microsoft >> ${DICT_FILE}

# Create a radius-client configuration file
cat <<-EOF >> ${CONF_FILE}
nas-identifier my-nas-id
authserver  $ADDRESS::testing123
acctserver  $ADDRESS::testing123
dictionary  ${DICT_FILE}
default_realm
radius_timeout	6
radius_retries	1
bindaddr *
EOF

check_ms_present() {
	grep "^MS-CHAP-Response                 = 'Hi-There'\$" ${OUTP_FILE} >/dev/null 2>&1
	if test $? != 0;then
		printf "\nERROR! Missing \"MS-CHAP-Response\" in response for user: \"${user}\"\n\n"
		exit 1
	fi
}

check_rp_present() {
	grep "^RP-Upstream-Speed-Limit          = '3'\$" ${OUTP_FILE} >/dev/null 2>&1
	if test $? != 0;then
		printf "\nERROR! Missing \"RP-Upstream-Speed-Limit\" in response for user: \"${user}\"\n\n"
		exit 1
	fi
}

auth() {
	vendors=$1
	user=$2
	shift
	shift
	tests=$*
	echo ""
	echo "********************************************************************************"
	printf "Testing user: \"${user}\" with support for vendors: \"${vendors}\"\n"

	${CMDNS1} ../src/radiusclient -D -i -f ${CONF_FILE}  User-Name=${user} Password=test | tee ${OUTP_FILE}
	if test $? != 0;then
		printf "Error in auth for user: \"${user}\"\n\n"
		exit 1
	fi

	for test in $tests; do
		$test
	done
}

auth "microsoft only" user-known-vsa-last check_ms_present
auth "microsoft only" user-unknown-vsa-last check_ms_present

# Add support for Roaring Penguin VSAs
echo '$'INCLUDE ../etc/dictionary.roaringpenguin >> ${DICT_FILE}

auth "microsoft+roaring-penguin" user-known-vsa-last check_ms_present check_rp_present
auth "microsoft+roaring-penguin" user-unknown-vsa-last check_ms_present check_rp_present

exit 0
