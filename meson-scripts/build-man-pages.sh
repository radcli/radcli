#!/bin/sh
# Generates the radcli API man pages (Doxygen + doxy2man), mirroring the
# doc/Makefile.am "stamp_mans" target from the autotools build.
set -e

doc_srcdir="$1"
doc_builddir="$2"
doxygen="$3"
doxy2man="$4"
perl="$5"

top_srcdir="$doc_srcdir/.."

mkdir -p "$doc_builddir"
cd "$doc_builddir"

"$doxygen" Doxyfile

rm -rf man
mkdir -p man

"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/group__radcli-api.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/group__tls-api.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/group__misc-api.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/radcli_8h.xml

PUBFUNCS="$("$doc_srcdir/scripts/getfuncs.pl" <"$top_srcdir/include/radcli/radcli.h" | sort -u)"
for f in man/*.3; do
	base="$(basename "$f" .3)"
	[ "$base" = "radcli.h" ] && continue
	echo "$PUBFUNCS" | grep -qx "$base" || rm -f "$f"
done

"$perl" "$doc_srcdir/scripts/gen-radcli-h-man.pl" \
	"$top_srcdir/include/radcli/radcli.h" \
	"$top_srcdir/lib/radcli.map.in" \
	xml/radcli_8h.xml \
	xml/group__radcli-api.xml \
	xml/group__tls-api.xml \
	xml/group__misc-api.xml > man/radcli.h.3

"$perl" "$doc_srcdir/scripts/fix-seealso.pl" \
	"$top_srcdir/include/radcli/radcli.h" \
	"$top_srcdir/lib/radcli.map.in" \
	man/

echo generated > stamp_mans
