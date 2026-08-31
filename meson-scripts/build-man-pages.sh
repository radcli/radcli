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

"$doxygen" Doxyfile-legacy

rm -rf man
mkdir -p man

"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/group__radcli-api.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/group__tls-api.xml
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
	xml/group__tls-api.xml > man/radcli.h.3

"$perl" "$doc_srcdir/scripts/fix-seealso.pl" \
	"$top_srcdir/include/radcli/radcli.h" \
	"$top_srcdir/lib/radcli.map.in" \
	man/

# New-API pass. Runs after the legacy pass above has already harvested
# man/ from xml/ -- both Doxyfiles write to the same XML_OUTPUT ("xml",
# see Doxyfile.in), so this overwrites it; nothing below depends on the
# legacy XML tree any more. Output goes to a scratch dir first (rather than
# straight into man/) so the PUBFUNCS2 filtering below -- which, like the
# legacy pass, must delete *any* non-public stray page doxy2man emits from
# scanning lib/*.c (e.g. avp_list_fail, is_valid_utf8) -- can safely loop
# over "every .3 file this pass produced" without risking a name collision
# against the legacy pass's already-filtered rc_*.3/radcli.h.3 output
# sitting in the same man/ dir. Update the group__*.xml list here if
# radcli2.h gains/renames \defgroup blocks.
rm -rf man-new
mkdir -p man-new

"$doxygen" Doxyfile-radcli2

"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man-new --novalidate --nosummary xml/group__radcli2-ctx.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man-new --novalidate --nosummary xml/group__radcli2-dict.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man-new --novalidate --nosummary xml/group__radcli2-avp.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man-new --novalidate --nosummary xml/group__radcli2-avp-by-num.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man-new --novalidate --nosummary xml/group__radcli2-avp-get-by-num.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man-new --novalidate --nosummary xml/group__radcli2-messaging.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man-new --novalidate --nosummary xml/group__radcli-dae.xml
"$doxy2man" -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man-new --novalidate --nosummary xml/radcli2_8h.xml

PUBFUNCS2="$("$doc_srcdir/scripts/getfuncs.pl" <"$top_srcdir/include/radcli/radcli2.h" | sort -u)"
for f in man-new/*.3; do
	base="$(basename "$f" .3)"
	[ "$base" = "radcli2.h" ] && continue
	echo "$PUBFUNCS2" | grep -qx "$base" || rm -f "$f"
done

"$perl" "$doc_srcdir/scripts/gen-radcli-h-man.pl" \
	"$top_srcdir/include/radcli/radcli2.h" \
	"$top_srcdir/lib/radcli2.map.in" \
	xml/radcli2_8h.xml \
	xml/group__radcli2-ctx.xml \
	xml/group__radcli2-dict.xml \
	xml/group__radcli2-avp.xml \
	xml/group__radcli2-avp-by-num.xml \
	xml/group__radcli2-avp-get-by-num.xml \
	xml/group__radcli2-messaging.xml \
	xml/group__radcli-dae.xml > man-new/radcli2.h.3

"$perl" "$doc_srcdir/scripts/fix-seealso.pl" \
	"$top_srcdir/include/radcli/radcli2.h" \
	"$top_srcdir/lib/radcli2.map.in" \
	man-new/

mv man-new/*.3 man/
rmdir man-new

echo generated > stamp_mans
