#!/bin/sh

# Copyright (C) 2018 Aravind Prasad S
#
# License: BSD

srcdir="${srcdir:-.}"

echo "***********************************************"
echo "This test will use a radius server on localhost"
echo "and which can be executed with run-server.sh   "
echo "***********************************************"

TMPFILE=tmp$$.out

if test "$(id -u)" != "0";then
	echo "This test must be run as root"
	exit 77
fi

#Identify the platform
OS="`uname`"
case $OS in
  'Linux')
    OS='Linux'
    ;;
  'FreeBSD')
    OS='FreeBSD'
    ;;
  'Darwin') 
    OS='Mac'
    ;;
  *) 
    OS='None'
    ;;
esac

#Check if the platform is supported
if test $OS = "None"; then
	echo "Platform not supported. Tests cannot be done"
	exit 77
fi

if test -z "$SERVER_IP6"; then
	echo "the variable SERVER_IP6 is not defined"
	exit 77
fi

PID=$$
sed -e 's/::1/'$SERVER_IP6'/g' -e 's/servers-ipv6-temp/servers-ipv6-temp'$PID'/g' <$srcdir/radiusclient-ipv6.conf >radiusclient-temp$PID.conf
sed 's/::1/'$SERVER_IP6'/g' <$srcdir/servers-ipv6 >servers-ipv6-temp$PID                            
echo "use-public-addr	true" >> radiusclient-temp$PID.conf

#enable ipv6 privay settings
sysctl -w net.ipv6.conf.all.use_tempaddr=2
#set interval=1 for generation of new temporary ipv6 addresses
sysctl -w net.ipv6.conf.all.temp_prefered_lft=1
#restart interfaces in Debian based system 
systemctl restart networking
if test $? != 0; then
	#restart interfaces in Fedora based system 
	systemctl restart network
fi    

#wait for 2 seconds for generation of new temporary ipv6 address
sleep 2

#radius-client is expected to use the global ipv6 address and not temporary address now
echo ../src/radiusclient -D -i -f radiusclient-temp$PID.conf  User-Name=test Password=test6 | tee $TMPFILE
../src/radiusclient -D -i -f radiusclient-temp$PID.conf  User-Name=test6 Password=test | tee $TMPFILE
if test $? != 0;then
	echo "Error in PAP auth"
	sysctl -w net.ipv6.conf.all.use_tempaddr=0
	sysctl -w net.ipv6.conf.all.temp_prefered_lft=86400
	exit 1
fi

grep "^Framed-IPv6-Prefix               = '2000:0:0:106::/64'$" $TMPFILE >/dev/null 2>&1            
if test $? != 0;then                                                                                
	echo "Error in data received by server (Framed-IPv6-Prefix)"                                    
	cat $TMPFILE                                                                                    
	sysctl -w net.ipv6.conf.all.use_tempaddr=0
	sysctl -w net.ipv6.conf.all.temp_prefered_lft=86400
	exit 1                                                                                          
fi                                                                                                  

rm -f servers-temp$PID 
cat $TMPFILE
rm -f $TMPFILE
rm -f radiusclient-temp$PID.conf
sysctl -w net.ipv6.conf.all.use_tempaddr=0
sysctl -w net.ipv6.conf.all.temp_prefered_lft=86400

exit 0
