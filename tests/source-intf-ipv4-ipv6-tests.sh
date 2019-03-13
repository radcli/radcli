#!/bin/sh

# License: 2-clause BSD
#
# Copyright (c) 2019, Geetha Sekar
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

echo "********************************************************************************"
echo "This test will use a radius server on localhost previously launched with"
echo "run-server.sh. The test sends an authentication message to the server and"
echo "expects an Access-Accept response"
echo ""
echo "Test performed:"
echo "	1. set bindaddr to SERVER_IP with last octet set to lastoctet -1."
echo " 		i.e SERVER_IP = 172.17.0.2 then bindaddr set to 172.17.0.1"
echo "	2. Set bindaddr_v6 to a IPv6 address"
echo "	3. Initiate radius server authentication."
echo ""
echo "Expected results:"
echo "  The authentication should go through sucessfully"
echo ""

CONF_FILE=source-intf-ipv4-ipv6.sh.conf
TMPFILE=source-intf-ipv4-ipv4.out

if test -z "$SERVER_IP";then
	echo "the variable SERVER_IP is not defined"
	exit 77
fi

BIND_ADDR=`echo $SERVER_IP | awk -F. '{$4--}{gsub(OFS,".")}1'`
echo $BIND_ADDR

# Create a radius-client configuration file
cat <<-EOF >> ${CONF_FILE}
nas-identifier my-nas-id
authserver  $SERVER_IP::testing123
acctserver  $SERVER_IP::testing123
dictionary ../etc/dictionary
default_realm
radius_timeout  6
radius_retries  1
bindaddr $BIND_ADDR
bindaddr_v6 2001:db8:1::1
EOF

echo ../src/radiusclient -D -i -f $CONF_FILE User-Name=test Password=test | tee $TMPFILE

../src/radiusclient -D -i -f $CONF_FILE  User-Name=test Password=test | tee $TMPFILE

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

rm -f ${CONF_FILE} ${TMPFILE}

exit 0
