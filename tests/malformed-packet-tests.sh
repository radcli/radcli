#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== Malformed/unusual attribute parsing tests ====="
echo " 1. Client rejects response with a type-0 attribute"
echo " 2. Client rejects response with an attribute length < 2"
echo " 3. Client rejects response with attribute overflow (len > remaining)"
echo " 4. Client accepts and decodes response containing unknown attribute types"
echo " 5. Client accepts response where an INTEGER attribute has wrong length"
echo " 6. Client accepts response with VSA containing only unknown sub-attributes"
echo "====================================================="

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

. ${srcdir}/common.sh

PID=$$
TMPFILE=tmp$$.out
RADIUSPID=""

eval "$GETPORT"

function finish {
	test -n "${RADIUSPID}" && kill ${RADIUSPID} >/dev/null 2>&1
	rm -f $TMPFILE
	rm -f radiusclient-malformed$PID.conf
	rm -f radiusclient-noauth$PID.conf
	rm -f servers-malformed$PID
}
trap finish EXIT

wait_for_server() {
	local i
	for i in 1 2 3 4 5 6 7 8; do
		check_if_port_in_use ${PORT} && return 0
		sleep 0.5
	done
	return 1
}

start_server() {
	python3 ${srcdir}/radius-server.py \
		--port ${PORT} --secret testing123 \
		--msg-auth "$1" --attrs "$2" 2>/dev/null &
	RADIUSPID=$!
	wait_for_server
}

stop_server() {
	if test -n "${RADIUSPID}"; then
		kill ${RADIUSPID} >/dev/null 2>&1
		wait ${RADIUSPID} 2>/dev/null
		RADIUSPID=""
	fi
}

# Config for tests 1-3: MA absent, require-msg-auth default (on)
# The packet is rejected at the attr-validation loop before the MA check fires.
cat >radiusclient-malformed$PID.conf <<EOF
nas-identifier my-nas-id
authserver  127.0.0.1:${PORT}
acctserver  127.0.0.1:${PORT}
servers     ./servers-malformed$PID
dictionary  ${srcdir}/../etc/dictionary
default_realm
radius_timeout  5
radius_retries  1
bindaddr    *
EOF
echo "127.0.0.1/127.0.0.1	testing123" >servers-malformed$PID

# Config for tests 4-5: MA correct, require-msg-auth disabled.
# We are testing attribute parsing here; MA correctness is covered by
# msg-auth-tests.sh.
cp radiusclient-malformed$PID.conf radiusclient-noauth$PID.conf
echo "require-message-authenticator	no" >> radiusclient-noauth$PID.conf

# --- Tests 1-3: malformed wire structure, caught by attr validation loop ---

# Test 1: response contains an attribute with type=0 (forbidden by RFC 2865 §5)
start_server absent malformed-type-zero
run_test "Reject response containing a type-0 attribute" \
	"../src/radiusclient -D -i -f radiusclient-malformed$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1
stop_server

# Test 2: response contains an attribute whose length byte is 1 (minimum is 2)
start_server absent malformed-len-one
run_test "Reject response with attribute length < 2" \
	"../src/radiusclient -D -i -f radiusclient-malformed$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1
stop_server

# Test 3: response contains an attribute that declares len=255 but the packet
# only carries 7 bytes for it — attr_len > pb_len check fires
start_server absent malformed-overflow
run_test "Reject response where attribute length overflows the packet" \
	"../src/radiusclient -D -i -f radiusclient-malformed$PID.conf User-Name=test Password=test" \
	expect_fail || exit 1
stop_server

# --- Tests 4-5: unusual but valid-format attrs, caught/handled in rc_avpair_gen2 ---

# Test 4: response includes two unknown attribute types (250, 251).
# rc_avpair_gen2 must skip them and still decode Framed-Protocol.
# MA is absent + require-msg-auth disabled to decouple from MA validation
# (validate_message_authenticator walks the VP list and would desync on
# unknown attrs that rc_avpair_gen2 omits from the list).
start_server absent unknown-attrs
run_test "Accept response with unknown attribute types (skipped, rest decoded)" \
	"../src/radiusclient -D -i -f radiusclient-noauth$PID.conf User-Name=test Password=test" \
	|| exit 1

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0; then
	echo "[ FAIL ] Expected Framed-Protocol = 'PPP' in response"
	exit 1
fi
stop_server

# Test 5: Service-Type INTEGER attribute sent with length=5 (should be 6).
# rc_avpair_gen2 must free the bad rpair and continue; Framed-Protocol still decoded.
# MA absent for the same reason as test 4.
start_server absent int-badlen
run_test "Accept response where an INTEGER attr has wrong length (skipped, rest decoded)" \
	"../src/radiusclient -D -i -f radiusclient-noauth$PID.conf User-Name=test Password=test" \
	|| exit 1

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0; then
	echo "[ FAIL ] Expected Framed-Protocol = 'PPP' in response"
	exit 1
fi
stop_server

# Test 6: VSA envelope for a known vendor (DSL-Forum, ID 3561) whose sub-attribute
# types are absent from the dictionary.  rc_avpair_gen2 recurses into the VSA body,
# skips every sub-attr (all unknown), and returns *out=NULL with rc=0 — valid empty
# result.  The outer loop must treat that as success and continue; Framed-Protocol
# must still be decoded.
start_server absent vsa-unknown-subattrs
run_test "Accept response with VSA containing only unknown sub-attrs (skipped, rest decoded)" \
	"../src/radiusclient -D -i -f radiusclient-noauth$PID.conf User-Name=test Password=test" \
	|| exit 1

grep "^Framed-Protocol                  = 'PPP'$" $TMPFILE >/dev/null 2>&1
if test $? != 0; then
	echo "[ FAIL ] Expected Framed-Protocol = 'PPP' in response"
	exit 1
fi
stop_server

echo ""
exit 0
