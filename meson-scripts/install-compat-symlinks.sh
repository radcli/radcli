#!/bin/sh
# Creates the libfreeradius-client.so / libradiusclient-ng.so compatibility
# symlinks (-Dlegacy-compat=true), mirroring the autotools install-exec-hook.
set -e

libdir_rel="$1"

destdir="${MESON_INSTALL_DESTDIR_PREFIX:-${MESON_INSTALL_PREFIX}}"
target="$destdir/$libdir_rel"

ln -sf libradcli.so "$target/libfreeradius-client.so"
ln -sf libradcli.so "$target/libradiusclient-ng.so"
