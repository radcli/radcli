#!/bin/sh

# Copyright (C) 2014 Nikos Mavrogiannopoulos
# Copyright (C) 2015 Red Hat, Inc
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

srcdir="${srcdir:-.}"
TMPFILE=tmp$$.out
CONFFILE=conf.tmp$$.out
SERVERSFILE=servers.tmp$$.out

echo "***********************************************"
echo "This test will use a radius-tls server on localhost"
echo "and which can be executed with run-server.sh   "
echo "***********************************************"


if test -z "$SERVER_IP";then
	echo "the variable SERVER_IP is not defined"
	exit 77
fi

PID=$$
sed -e 's/localhost/'$SERVER_IP'/g' -e 's/servers-tls-temp/servers-tls-temp'$PID'/g' <$srcdir/dtls/radiusclient-tls.conf >$CONFFILE
sed 's/localhost/'$SERVER_IP'/g' <$srcdir/servers >$SERVERSFILE

# Test whether a TLS session will succeed
../src/radiusclient -D -f $CONFFILE  User-Name=test Password=test >$TMPFILE
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

# Test whether a TLS invalidated session for some reason will reconnect
./tls-restart -f $CONFFILE  User-Name=test Password=test >$TMPFILE
if test $? != 0;then
	echo "Error in session restart"
	exit 1
fi

rm -f $TMPFILE
rm -f $SERVERSFILE $CONFFILE
exit 0
