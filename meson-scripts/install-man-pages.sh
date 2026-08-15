#!/bin/sh
# Installs the API man pages (doc/meson.build). Two candidate source
# directories are given, in preference order:
#   1. the build dir's freshly (re)generated pages -- only present if this
#      build was configured with -Ddocs=enabled and doxygen/doxy2man/perl
#      were found;
#   2. the source tree's doc/man -- populated inside release tarballs by
#      `meson dist` (see meson-scripts/dist-man-pages.sh), absent in a plain
#      git checkout.
# Skips quietly if neither is present (e.g. a docs-disabled dev build from
# a git checkout).
set -e

man_builddir="$1"
man_srcdir="$2"
man3_reldir="$3"

src=""
for candidate in "$man_builddir" "$man_srcdir"; do
	if [ -d "$candidate" ] && [ -n "$(ls -A "$candidate"/*.3 2>/dev/null)" ]; then
		src="$candidate"
		break
	fi
done
[ -n "$src" ] || exit 0

destdir="${MESON_INSTALL_DESTDIR_PREFIX:-${MESON_INSTALL_PREFIX}}"
target="$destdir/$man3_reldir"

mkdir -p "$target"
for f in "$src"/*.3; do
	[ -e "$f" ] || continue
	install -m 644 "$f" "$target/"
done
