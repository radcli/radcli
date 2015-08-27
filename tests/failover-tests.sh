#!/bin/sh

# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "***********************************************"
echo "This test will use a radius server on localhost"
echo "and which can be executed with run-server.sh   "
echo "***********************************************"

TMPFILE=tmp-failover.out

if test -z "$SERVER_IP";then
	echo "the variable SERVER_IP is not defined"
	exit 77
fi

#socat UDP4-RECVFROM:9999 UDP4-SENDTO:$SERVER_IP:1812 &
#SOPID=$!

PID=$$
sed -e 's/localhost/127.1.1.1:9999,'$SERVER_IP'/g' -e 's/servers-temp/servers-temp'$PID'/g' <$srcdir/radiusclient.conf >radiusclient-temp$PID.conf
sed 's/localhost/'$SERVER_IP'/g' <$srcdir/servers >servers-temp$PID

../src/radiusclient -D -i -f radiusclient-temp$PID.conf  User-Name=test Password=test | tee $TMPFILE
if test $? != 0;then
	echo "Error in PAP auth"
	exit 1
fi

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (Framed-Protocol)"
	cat $TMPFILE
	exit 1
fi

grep "^Framed-IP-Address                = '192.168.1.190'$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (Framed-IP-Address)"
	cat $TMPFILE
	exit 1
fi

grep "^Framed-Route                     = '192.168.100.5/24'$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in data received by server (Framed-Route)"
	cat $TMPFILE
	exit 1
fi

grep "^Request-Info-Secret = testing123$" $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in request info data (secret)"
	cat $TMPFILE
	exit 1
fi

grep "^Request-Info-Vector = " $TMPFILE >/dev/null 2>&1
if test $? != 0;then
	echo "Error in request info data (vector)"
	cat $TMPFILE
	exit 1
fi

rm -f servers-temp$PID
#cat $TMPFILE
rm -f $TMPFILE
rm -f radiusclient-temp$PID.conf

exit 0
