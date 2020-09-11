#!/bin/bash

# Copyright (C) 2018 Aravind Prasad S
#
# License: BSD

srcdir="${srcdir:-.}"

echo "***********************************************"
echo "This test will use a radius server on localhost"
echo "and which can be executed with ns.sh   "
echo "***********************************************"

CLI_ADDRESS=10.203.11.1
ADDRESS=10.203.12.1

function finish {
	/bin/true
}

. ${srcdir}/ns.sh

${CMDNS1} ../src/radembedded ${ADDRESS}
if test $? != 0;then
	echo "Error in Radembedded handling"
	exit 1
fi

exit 0
