#!/bin/bash

# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "***********************************************"
echo "This test will use a radius server on localhost"
echo "and which can be executed with ns.sh   "
echo "***********************************************"

PID=$$
TMPFILE=tmp$$.out
CLI_ADDRESS="fc6b:1bf6:2675:77ad:6755:57ee::"
ADDRESS="fd45:f830:991d:6fc7:c49b:4205::"
PREFIX=96

function finish {
	rm -f servers-temp$PID
	rm -f $TMPFILE
	rm -f radiusclient-temp$PID.conf
}

. ${srcdir}/ns.sh

sed -e 's/::1/'$ADDRESS'/g' -e 's/servers-ipv6-temp/servers-ipv6-temp'$PID'/g' <$srcdir/radiusclient-ipv6.conf >radiusclient-temp$PID.conf
sed 's/::1/'$ADDRESS'/g' <$srcdir/servers-ipv6 >servers-ipv6-temp$PID

${CMDNS1} ../src/radiusclient -D -f radiusclient-temp$PID.conf  User-Name=test6 Password=test >$TMPFILE 
if test $? != 0;then
	cat $TMPFILE
	echo "Error in PAP IPv6 auth"
	exit 1
fi

grep "^Framed-IPv6-Prefix               = '2000:0:0:106::/64'$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (Framed-IPv6-Prefix)"
	cat $TMPFILE
	exit 1
fi

exit 0
