#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== shipped example config documentation (REQ-CONFIG2-SECRET-005) ====="
echo " etc/radiusclient.conf.in / etc/radiusclient-tls.conf.in must document"
echo " a secret or PSK only via the 'secret'/'tls-psk-identity'/"
echo " 'tls-psk-key' options -- never via the legacy inline"
echo " host:port:secret / host:port:psk@user@hexkey suffix, and never via an"
echo " active or documented 'servers'/'servers-tls' credentials file -- so"
echo " those legacy forms stay parseable but stop being what a new config"
echo " file is written to look like."
echo "=========================================================================="

fail=0

check_file() {
	file="$1"

	if [ ! -f "$file" ]; then
		echo "cannot find $file"
		fail=1
		return
	fi

	# A real authserver/acctserver directive's value is a single
	# whitespace-free token (comma-separated hosts have no internal
	# spaces either); this deliberately does not match prose describing
	# the legacy syntax in a sentence (which has spaces/words after the
	# option name, not a bare value).
	if grep -nE '^[[:space:]]*#?[[:space:]]*(auth|acct)server[[:space:]]+[^[:space:]]*:[^[:space:]]*:[^[:space:]]*[[:space:]]*$' "$file"; then
		echo "FAIL: $file documents authserver/acctserver with an inline :secret (or :psk@...) suffix"
		fail=1
	fi

	if grep -n 'psk@' "$file"; then
		echo "FAIL: $file documents the legacy inline psk@username@hexkey form"
		fail=1
	fi

	if grep -nE '^[[:space:]]*servers(-tls)?[[:space:]]' "$file"; then
		echo "FAIL: $file sets 'servers'/'servers-tls' as an active option"
		fail=1
	fi
}

check_file "${srcdir}/../etc/radiusclient.conf.in"
check_file "${srcdir}/../etc/radiusclient-tls.conf.in"

if [ "$fail" -ne 0 ]; then
	echo "FAIL: shipped example config(s) promote a legacy secret/PSK form"
	exit 1
fi

echo "OK: shipped example configs document only secret/tls-psk-identity/tls-psk-key"
