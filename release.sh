#!/bin/bash
set -e

if test -z "$1"; then
	echo "usage: $0 VERSION"
	exit 1
fi

version=$1
tarball="radcli-${version}.tar.gz"

# Validate configure.ac
ac_version=$(grep '^AC_INIT' configure.ac | sed 's/.*\[\([0-9.]*\)\].*/\1/')
if test "$ac_version" != "$version"; then
	echo "ERROR: configure.ac has version $ac_version, expected $version"
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

echo "Version checks passed: configure.ac and NEWS both have ${version}"

# Build and check the tarball
echo ""
echo "Running make distcheck..."
make distcheck

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
git tag -s "${version}" -m "Released ${version}"

echo ""
echo "Pushing tag..."
git push origin "${version}"

# Create GitHub release with notes and artifacts
echo ""
echo "Creating GitHub release ${version}..."
gh release create "${version}" \
	--title "${version}" \
	--notes "${release_notes}" \
	"${tarball}" \
	"${tarball}.sig"

echo ""
echo "Release ${version} is ready."
