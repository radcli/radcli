#!/bin/sh
# Regenerates the Doxygen HTML docs and publishes doc/web/ + the HTML manual
# to the gh-pages branch. Equivalent of the old autotools "make web" target.
#
# This force-pushes to origin/gh-pages -- run it deliberately, not from CI.
set -e

top_srcdir="$1"
doc_builddir="$2"
doxygen="$3"

cd "$doc_builddir"
"$doxygen" Doxyfile

cd "$top_srcdir"

if [ -n "$(git status --porcelain)" ]; then
	echo "error: working tree is not clean; commit or stash changes before publishing" >&2
	exit 1
fi

current_branch="$(git rev-parse --abbrev-ref HEAD)"

rm -rf html
mkdir -p html
rsync -Hvax "$top_srcdir/doc/web/" html/
rsync -Hvax "$doc_builddir/html/" html/manual/

git branch -D tmp-web-pages >/dev/null 2>&1 || true
git checkout -b tmp-web-pages
git add -f html
git commit -n -sm "auto-generated web-pages"
gh_pages_commit="$(git subtree split --prefix html tmp-web-pages)"
git checkout "$current_branch"
git branch -D tmp-web-pages
rm -rf html

echo "Built gh-pages content as commit $gh_pages_commit"
echo "Review it, then publish with:"
echo "  git push origin $gh_pages_commit:refs/heads/gh-pages --force"
