#!/bin/sh
# Embeds fresh API man pages in the `meson dist` tarball (doc/meson.build).
#
# doc/man/*.3 is not tracked in git (see .gitignore) -- the release tarball
# is the only place they're shipped pre-generated, so downstream packagers
# (e.g. fedora/radcli.spec) never need doxygen/doxy2man/perl. That means
# `meson dist` is the one point where staleness or absence would silently
# ship a broken release, so it's refused outright unless the build
# directory being dist'ed was configured with -Ddocs=enabled.
set -e

docs_enabled="$1"

if [ "$docs_enabled" != "1" ]; then
	echo "error: 'meson dist' requires the build directory to be configured" >&2
	echo "       with -Ddocs=enabled, so the API man pages are regenerated" >&2
	echo "       fresh before being embedded in the release tarball." >&2
	echo "       Reconfigure: meson setup --reconfigure -Ddocs=enabled <builddir>" >&2
	exit 1
fi

# Rebuild so the embedded pages reflect any source changes since the last
# build; a cheap no-op if already up to date.
meson compile -C "$MESON_BUILD_ROOT"

man_builddir="$MESON_BUILD_ROOT/doc/man"
if [ ! -d "$man_builddir" ] || [ -z "$(ls -A "$man_builddir"/*.3 2>/dev/null)" ]; then
	echo "error: -Ddocs=enabled but $man_builddir has no generated .3 files" >&2
	exit 1
fi

dest="$MESON_DIST_ROOT/doc/man"
rm -rf "$dest"
mkdir -p "$dest"
cp "$man_builddir"/*.3 "$dest/"
