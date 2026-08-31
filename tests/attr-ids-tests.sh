#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD

srcdir="${srcdir:-.}"

echo "===== etc/dictionary vs. include/radcli/radcli-defs.h consistency ====="
echo " Every numeric ATTRIBUTE id in the bundled dictionary must have a"
echo " matching PW_* enumerator in radcli-defs.h, so the two can't silently"
echo " drift apart again."
echo "=========================================================================="

DICT="${srcdir}/../etc/dictionary"
HDR="${srcdir}/../include/radcli/radcli-defs.h"

if [ ! -f "$DICT" ] || [ ! -f "$HDR" ]; then
	echo "cannot find $DICT or $HDR"
	exit 1
fi

fail=0

# Numeric IDs actually declared in the enum (rc_attr_id), one per "=<number>".
hdr_ids=$(grep -oE '=[[:space:]]*[0-9]+' "$HDR" | grep -oE '[0-9]+' | sort -nu)

while read -r name num; do
	if ! echo "$hdr_ids" | grep -qx "$num"; then
		echo "MISSING: $name ($num) has no PW_* entry in radcli-defs.h"
		fail=1
	fi
done < <(grep -E '^ATTRIBUTE[[:space:]]' "$DICT" | awk '{print $2, $3}')

if [ "$fail" -ne 0 ]; then
	echo "FAIL: radcli-defs.h is missing entries present in etc/dictionary"
	exit 1
fi

echo "OK: every etc/dictionary attribute has a radcli-defs.h entry"
exit 0
