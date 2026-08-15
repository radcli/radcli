#!/bin/sh
# Verifies that the public header and the linker version script export the
# same set of symbols. Equivalent of the autotools "compare-exported" target.
set -e

header="$1"
map="$2"
scripts_dir="$3"

tmp_head="$(mktemp)"
tmp_exp="$(mktemp)"
trap 'rm -f "$tmp_head" "$tmp_exp"' EXIT

"$scripts_dir/getfuncs.pl" <"$header" | sort -u >"$tmp_head"
"$scripts_dir/getfuncs-map.pl" <"$map" | sort -u >"$tmp_exp"

echo "******************************************************************************"
echo "If the following step fails there is a symbol in headers that is not exported or vice-versa"
echo "******************************************************************************"
diff -u "$tmp_exp" "$tmp_head"
