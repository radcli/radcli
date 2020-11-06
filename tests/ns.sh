#!/bin/bash
#
# Copyright (C) 2018 Nikos Mavrogiannopoulos
#
# This file is part of ocserv.
#
# ocserv is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# ocserv is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

srcdir=${srcdir:-.}

PATH=${PATH}:/usr/sbin
IP=$(which ip)
RADIUSD=$(which radiusd)

if test -z "${RADIUSD}";then
	RADIUSD=$(which freeradius)
fi 

if test "$(id -u)" != "0";then
	echo "This test must be run as root"
	exit 77
fi

ip netns list >/dev/null 2>&1
if test $? != 0;then
	echo "This test requires ip netns command"
	exit 77
fi

if test "$(uname -s)" != Linux;then
	echo "This test must be run on Linux"
	exit 77
fi

have_port_finder() {
	for file in $(which ss 2> /dev/null) /*bin/ss /usr/*bin/ss /usr/local/*bin/ss;do
		if test -x "$file";then
			PFCMD="$file";return 0
		fi
	done

	if test -z "$PFCMD";then
	for file in $(which netstat 2> /dev/null) /bin/netstat /usr/bin/netstat /usr/local/bin/netstat;do
		if test -x "$file";then
			PFCMD="$file";return 0
		fi
	done
	fi

	if test -z "$PFCMD";then
		echo "neither ss nor netstat found"
		exit 1
	fi
}

check_if_port_listening() {
	local PORT="$1"
	local PFCMD; have_port_finder
	${CMDNS2} $PFCMD -anl|grep "[\:\.]$PORT"|grep LISTEN >/dev/null 2>&1
}

wait_for_port()
{
	local ret
	local PORT="$1"
	sleep 1

	for i in 1 2 3 4 5 6;do
		check_if_port_listening ${PORT}
		ret=$?
		if test $ret != 0;then
			sleep 2
		else
			break
		fi
	done
	return $ret
}

function nsfinish {
  set +e
  test -n "${ETHNAME1}" && ${IP} link delete ${ETHNAME1} >/dev/null 2>&1
  test -n "${ETHNAME2}" && ${IP} link delete ${ETHNAME2} >/dev/null 2>&1
  test -n "${NSNAME1}" && ${IP} netns delete ${NSNAME1} >/dev/null 2>&1
  test -n "${NSNAME2}" && ${IP} netns delete ${NSNAME2} >/dev/null 2>&1
  test -n "${RADIUSPID}" && kill ${RADIUSPID} >/dev/null 2>&1
  
  finish
}
trap nsfinish EXIT

if test "$ADDRESS" = "";then
	echo ADDRESS is not set.
	exit 1
fi

IPEXTRA=""
if [[ $ADDRESS == *':'* ]]; then
	IPEXTRA="-family inet6"
fi

echo " * Setting up namespaces..."
set -e
NSNAME1="ns-c-tmp-$$"
NSNAME2="ns-s-tmp-$$"
ETHNAME1="radeth-c$$"
ETHNAME2="radeth-s$$"
${IP} netns add ${NSNAME1}
${IP} netns add ${NSNAME2}

${IP} link add ${ETHNAME1} type veth peer name ${ETHNAME2}
${IP} ${IPEXTRA} link set dev ${ETHNAME1} netns ${NSNAME1}
${IP} ${IPEXTRA} link set dev ${ETHNAME2} netns ${NSNAME2}

CMDNS1="${IP} netns exec ${NSNAME1}"
CMDNS2="${IP} netns exec ${NSNAME2}"

if [[ $ADDRESS == *':'* ]]; then
${IP} -n ${NSNAME1} ${IPEXTRA} addr add ${CLI_ADDRESS}/${PREFIX} dev ${ETHNAME1} nodad
${IP} -n ${NSNAME2} ${IPEXTRA} addr add ${ADDRESS}/${PREFIX} dev ${ETHNAME2} nodad
else
${IP} -n ${NSNAME1} ${IPEXTRA} addr add ${CLI_ADDRESS} dev ${ETHNAME1}
${IP} -n ${NSNAME2} ${IPEXTRA} addr add ${ADDRESS} dev ${ETHNAME2}
fi

${IP} -n ${NSNAME1} ${IPEXTRA} link set ${ETHNAME1} up
${IP} -n ${NSNAME2} ${IPEXTRA} link set ${ETHNAME2} up

if [[ $ADDRESS == *':'* ]]; then
${IP} -n ${NSNAME1} ${IPEXTRA} route add "${CLI_ADDRESS}/128" dev ${ETHNAME1}
${IP} -n ${NSNAME1} ${IPEXTRA} route add default dev ${ETHNAME1} # via "${CLI_ADDRESS}"

${IP} -n ${NSNAME2} ${IPEXTRA} route add "${ADDRESS}/128" dev ${ETHNAME2}
${IP} -n ${NSNAME2} ${IPEXTRA} route add default dev ${ETHNAME2} #via "${ADDRESS}"
else
${IP} -n ${NSNAME1} ${IPEXTRA} route add default via "${CLI_ADDRESS}" dev ${ETHNAME1}
${IP} -n ${NSNAME2} ${IPEXTRA} route add default via "${ADDRESS}" dev ${ETHNAME2}
fi

${IP} -n ${NSNAME2} ${IPEXTRA} link set lo up

echo ""
echo "${NSNAME1}:"
${IP} -n ${NSNAME1} ${IPEXTRA} addr
${IP} -n ${NSNAME1} ${IPEXTRA} route

echo ""
echo "${NSNAME2}:"
${IP} -n ${NSNAME2} ${IPEXTRA} addr
${IP} -n ${NSNAME2} ${IPEXTRA} route


echo ""

echo pinging
${CMDNS1} ping -c 1 ${ADDRESS} #>/dev/null
${CMDNS2} ping -c 1 ${ADDRESS} #>/dev/null
${CMDNS2} ping -c 1 ${CLI_ADDRESS} >/dev/null
set +e


${CMDNS2} ${IP} link set dev lo up

if test -z "${RADDB_DIR}";then
	RADDB_DIR="raddb"
fi

set -e
echo ${CMDNS2} ${RADIUSD} -d ${srcdir}/${RADDB_DIR}/ -fxx -l stdout
${CMDNS2} ${RADIUSD} -d ${srcdir}/${RADDB_DIR}/ -fxx -l stdout 2>&1 &
RADIUSPID=$!
set +e

wait_for_port 1812

echo "Started radius (${RADDB_DIR})"
