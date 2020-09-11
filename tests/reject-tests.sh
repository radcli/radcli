#!/bin/bash

# Copyright (C) 2017 Aravind Prasad <raja.avi@gmail.com>
#
# License: BSD

srcdir="${srcdir:-.}"

echo "***********************************************"
echo "This test will use a radius server on localhost"
echo "and which can be executed with ns.sh.  "
echo "Test passes invalid client credentials and     "
echo "expects it to be rejected by Server.           "
echo "***********************************************"

TMPFILE=tmp$$.out
PID=$$

CLI_ADDRESS=10.203.13.1
ADDRESS=10.203.14.1

function finish {
	rm -f servers-temp$PID 
	rm -f $TMPFILE
	rm -f radiusclient-temp$PID.conf
}

. ${srcdir}/ns.sh

sed -e 's/localhost/'$ADDRESS'/g' -e 's/servers-temp/servers-temp'$PID'/g' <$srcdir/radiusclient.conf >radiusclient-temp$PID.conf
sed 's/localhost/'$ADDRESS'/g' <$srcdir/servers >servers-temp$PID

echo ../src/radiusclient -D -i -f radiusclient-temp$PID.conf  User-Name=admin Password=admin | tee $TMPFILE
${CMDNS1} ../src/radiusclient -D -i -f radiusclient-temp$PID.conf  User-Name=admin Password=admin | tee $TMPFILE

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? = 0;then
    echo "Credentials passed here. Credentials should have failed. Error."
    cat $TMPFILE
    exit 1
fi

grep "^Framed-IP-Address                = '192.168.1.190'$" $TMPFILE >/dev/null 2>&1
if test $? = 0;then
    echo "Credentials passed here. Credentials should have failed. Error."
    cat $TMPFILE
    exit 1
fi

grep "^Framed-Route                     = '192.168.100.5/24'$" $TMPFILE >/dev/null 2>&1
if test $? = 0;then
    echo "Credentials passed here. Credentials should have failed. Error."
    cat $TMPFILE
    exit 1
fi

grep "^Request-Info-Secret = testing123$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
    echo "Info not copied back from Server's Reply. Error"
    cat $TMPFILE
    exit 1
fi

grep "^Request-Info-Vector = " $TMPFILE >/dev/null 2>&1
if test $? != 0;then
    echo "Info not copied back from Server's Reply. Error"
    cat $TMPFILE
    exit 1
fi

exit 0
