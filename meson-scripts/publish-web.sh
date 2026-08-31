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
"$doxygen" Doxyfile-legacy
"$doxygen" Doxyfile-radcli2

cd "$top_srcdir"

# Only tracked modifications matter here: the gh-pages commit is built from an
# explicit "git add -f html", so untracked files in the tree cannot leak into it.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
	echo "error: tracked files have uncommitted changes; commit or stash them before publishing" >&2
	exit 1
fi

current_branch="$(git rev-parse --abbrev-ref HEAD)"

rm -rf html
mkdir -p html
rsync -Hvax "$top_srcdir/doc/web/" html/
rsync -Hvax "$doc_builddir/html/" html/manual/
rsync -Hvax "$doc_builddir/html-legacy/" html/manual-legacy/

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
