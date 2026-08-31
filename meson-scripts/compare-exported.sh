#!/bin/sh
# Verifies that the public headers and the linker version script export the
# same set of symbols. Equivalent of the autotools "compare-exported" target.
#
# Usage: compare-exported.sh <map> <scripts_dir> <header>...
# One or more headers may be given; their exported functions are pooled
# before comparing against the map (radcli.h and radcli2.h together export
# exactly what lib/radcli.map lists).
set -e

map="$1"
scripts_dir="$2"
shift 2

tmp_head="$(mktemp)"
tmp_exp="$(mktemp)"
trap 'rm -f "$tmp_head" "$tmp_exp"' EXIT

cat -- "$@" | "$scripts_dir/getfuncs.pl" | sort -u >"$tmp_head"
"$scripts_dir/getfuncs-map.pl" <"$map" | sort -u >"$tmp_exp"

echo "******************************************************************************"
echo "If the following step fails there is a symbol in headers that is not exported or vice-versa"
echo "******************************************************************************"
diff -u "$tmp_exp" "$tmp_head"
