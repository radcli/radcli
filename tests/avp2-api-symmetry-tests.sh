#!/bin/bash

# Copyright (C) 2026 Nikos Mavrogiannopoulos
#
# License: BSD
#
# REQ-AVP2-DATA-033 (doc/requirements/avp2.md) conformance check: every
# radcli_avp_add_*/_get_*/_concat_* function parameterised by a single
# target attribute must exist in both a radcli_attr_def-taking form and a
# _by_num() form, 1:1 in both directions. This is a structural, header-only
# check (no build/link needed) so a future addition that forgets the
# sibling function fails immediately instead of waiting for a manual audit
# -- which is how the original gap (radcli_avp_concat_str_by_num() with no
# radcli_avp_concat_str()) was found.

srcdir="${srcdir:-.}"
HDR="${srcdir}/../include/radcli/radcli2.h"

echo "===== REQ-AVP2-DATA-033: radcli_avp_*() def/_by_num() pairing ====="
echo " Every radcli_avp_add_*/_get_*/_concat_* function taking a"
echo " radcli_attr_def* must have a _by_num() sibling, and vice versa."
echo "===================================================================="

if ! python3 -c '' 2>/dev/null; then
	echo "This test requires python3"
	exit 77
fi

if [ ! -f "$HDR" ]; then
	echo "cannot find $HDR"
	exit 1
fi

python3 - "$HDR" <<'PYEOF'
import re
import sys

hdr = sys.argv[1]
text = open(hdr).read()

# Strip comments first -- doxygen prose can contain literal ';'/'()' that
# would otherwise confuse the prototype scan below.
text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.DOTALL)
text = re.sub(r'//.*', '', text)

# name -> parameter-list text, for every radcli_avp_add_*/_get_*/_concat_*
# prototype (these are all flat parameter lists with no nested parens, so
# "up to the next ');'" is exactly the parameter list).
protos = {}
for m in re.finditer(r'\b(radcli_avp_(?:add|get|concat)\w*)\s*\(([^;]*)\)\s*;', text):
	protos[m.group(1)] = m.group(2)

names = set(protos)
by_num = {n for n in names if n.endswith('_by_num')}
base = names - by_num

fail = []

# Rule 1: every _by_num() name must have a base sibling.
for n in sorted(by_num):
	b = n[:-len('_by_num')]
	if b not in names:
		fail.append(f"{n}() has no radcli_attr_def-taking sibling {b}()")

# Rule 2: every base name whose signature takes a radcli_attr_def* (i.e. is
# parameterised by a single target attribute -- REQ-AVP2-DATA-033's scope)
# must have a _by_num() sibling. This signature check is what excludes
# functions outside that scope without a hardcoded list: the typed readers
# (radcli_avp_get_uint32() etc.) take an already-resolved radcli_avp*, not a
# def, and radcli_avp_add_username() takes no single target attribute at
# all -- neither mentions radcli_attr_def, so neither is flagged here.
for n in sorted(base):
	if 'radcli_attr_def' not in protos[n]:
		continue
	bn = n + '_by_num'
	if bn not in names:
		fail.append(f"{n}() has no _by_num() sibling {bn}()")

if fail:
	print("FAIL: REQ-AVP2-DATA-033 pairing violations:")
	for f in fail:
		print(f"  {f}")
	sys.exit(1)

print(f"OK: {len(names)} radcli_avp_*() declarations, all def/_by_num() pairs complete")
PYEOF
