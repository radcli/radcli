#!/bin/sh

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

echo "**************************************************"
echo "Test that we can specify servers as a comma-"
echo "separated list of \"IP:port:secrets\" using"
echo "authserver and acctserver. More precisely, this"
echo "test does not use a separate \"servers\" file to"
echo "specify server's IP, port, and secret information."
echo "**************************************************"

TMPFILE=tmp$$.out

if test -z "$SERVER_IP";then
	echo "the variable SERVER_IP is not defined"
	exit 77
fi

# Specify a list of 2 servers as follows:
#   1) 127.1.1.1:9999:hardly-a-secret
#   2) $SERVER_IP::testing123
#
# The first server is specified with and invalid port to force it to fail.
# The second one contains the valid info so it should pass.

PID=$$
cat <<-EOF >> radiusclient-temp$PID.conf
nas-identifier my-nas-id
authserver 	127.1.1.1:9999:hardly-a-secret,$SERVER_IP::testing123
acctserver 	127.1.1.1:9999:hardly-a-secret,$SERVER_IP::testing123
dictionary 	../etc/dictionary
default_realm
radius_timeout	6
radius_retries	1
bindaddr *
EOF

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
