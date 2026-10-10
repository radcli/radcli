#!/bin/bash
set -e

if test -z "$1"; then
	echo "usage: $0 VERSION"
	exit 1
fi

version=$1
builddir="build"
tarball="radcli-${version}.tar.xz"

# Ensure we are on the master branch
current_branch=$(git rev-parse --abbrev-ref HEAD)
if test "$current_branch" != "master"; then
	echo "ERROR: releases must be made from master (current branch: $current_branch)"
	exit 1
fi

# Validate meson.build
meson_version=$(grep "^  version:" meson.build | sed "s/.*'\([0-9.]*\)'.*/\1/")
if test "$meson_version" != "$version"; then
	echo "ERROR: meson.build has version $meson_version, expected $version"
	exit 1
fi

# Validate NEWS entry exists and is not marked unreleased
news_line=$(grep -n "^\* Version ${version}" NEWS | cut -d: -f1)
if test -z "$news_line"; then
	echo "ERROR: No '* Version ${version}' entry found in NEWS"
	exit 1
fi
if grep -q "^\* Version ${version}.*unreleased" NEWS; then
	echo "ERROR: Version ${version} is still marked as unreleased in NEWS"
	exit 1
fi

echo "Version checks passed: meson.build and NEWS both have ${version}"

# Ask up front so the rest of the release can run unattended. The token is
# passed to gh via GH_TOKEN for the release command only, which takes
# precedence over gh's stored credentials without modifying them.
echo ""
read -rsp "GitHub release token: " release_token
echo ""
if test -z "$release_token"; then
	echo "ERROR: no release token given"
	exit 1
fi

# Build and check the tarball
echo ""
if ! test -d "${builddir}"; then
	echo "Setting up ${builddir}..."
	meson setup "${builddir}"
fi
echo "Running meson dist..."
meson dist -C "${builddir}"

distdir="${builddir}/meson-dist"
cp "${distdir}/${tarball}" "${tarball}"

# Verify the sha256sum meson generated
echo ""
echo "Verifying checksum..."
(cd "${distdir}" && sha256sum -c "${tarball}.sha256sum")

# Sign
echo ""
echo "Signing ${tarball}..."
gpg --sign --detach "${tarball}"

# Extract NEWS entry for this release (lines between this version header and the next)
next_line=$(awk "NR>${news_line} && /^\* Version /{print NR; exit}" NEWS)
if test -z "$next_line"; then
	release_notes=$(tail -n +"$((news_line + 1))" NEWS | sed '/^[[:space:]]*$/{ /./!d }')
else
	release_notes=$(sed -n "$((news_line + 1)),$((next_line - 1))p" NEWS | sed '/^[[:space:]]*$/{ /./!d }')
fi

# Create signed git tag
echo ""
echo "Creating signed git tag ${version}..."
git tag -fs "${version}" -m "Released ${version}"

echo ""
echo "Pushing tag..."
git push -f origin "${version}"

# Create GitHub release with notes and artifacts
echo ""
echo "Creating GitHub release ${version}..."
GH_TOKEN="${release_token}" gh release create "${version}" \
	--title "${version}" \
	--notes "${release_notes}" \
	"${tarball}" \
	"${tarball}.sig" \
	"${distdir}/${tarball}.sha256sum"
unset release_token

echo ""
echo "Release ${version} is ready."
