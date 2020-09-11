# 
#  $Id: Makefile.am,v 1.3 2006/03/14 17:14:27 janakj Exp $
# 
#  Copyright (C) 1997 Lars Fenneberg
# 
#  See the file COPYRIGHT for the respective terms and conditions. 
#  If the file is missing contact me at lf@elemental.net 
#  and I'll send you a copy.
# 
#

AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -D_GNU_SOURCE

ACLOCAL = @ACLOCAL@
LTLIBOBJS = @LTLIBOBJS@

SUBDIRS = include lib src etc man doc tests
EXTRA_DIST = NEWS COPYRIGHT README.rst

compare-exported: include/radcli/radcli.h
	doc/scripts/getfuncs.pl <$^|sort -u >tmp-head-$@
	doc/scripts/getfuncs-map.pl <lib/radcli.map|sort -u >tmp-exp-$@
	@echo "******************************************************************************"
	@echo "If the following step fails there is a symbol in headers that is not exported or vice-versa"
	@echo "******************************************************************************"
	diff -u tmp-exp-$@ tmp-head-$@
	rm -f tmp-exp-$@ tmp-head-$@

abi-check:
	@echo "Checking radcli ABI"
	if test -f "$(srcdir)/devel/ABI-$$(uname -m).dump" && test "$(ABI_SKIP)" != 1; then \
		abidiff --no-added-syms --hd2 $(srcdir)/include/radcli/ $(builddir)/lib/.libs/libradcli.so devel/ABI-x86_64.dump; \
	fi

abi-dump:
	@echo "Saving radcli ABI"
	abidw $(builddir)/lib/.libs/libradcli.so --out-file "$(srcdir)/devel/ABI-$$(uname -m).dump"

web: html.upload

clean-local:
	rm -f .html.stamp

.html.stamp:
	rm -rf html/* doc/html/* doc/stamp_html
	make -C doc stamp_html
	rsync -Hvax doc/web/ html/
	rsync -Hvax doc/html/ html/manual/
	touch $@

html.upload: .html.stamp
	-git branch -D tmp-web-pages
	-git branch -D tmp-web-pages
	git checkout -b tmp-web-pages
	git add -f html
	git commit -n -sm "auto-generated web-pages" html
	git push origin $$(git subtree split --prefix html tmp-web-pages):refs/heads/gh-pages --force
	git checkout master
	git branch -D tmp-web-pages

dist-hook: compare-exported abi-check

CLEANFILES = *~

.PHONY: web html.upload .html.stamp
