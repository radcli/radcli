#
# Copyright (C) 2015 Red Hat, Inc.
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

include $(top_srcdir)/doc/doc.mk

APIMANS += man/radcli.h.3

CLEANFILES = *~
DISTCLEANFILES = stamp_mans stamp_html

EXTRA_DIST = Doxyfile.in scripts/getfuncs.pl scripts/getfuncs-map.pl scripts/gen-radcli-h-man.pl scripts/fix-seealso.pl doc.mk

dist_man_MANS = $(APIMANS)

$(APIMANS):

stamp_mans: ../include/radcli/radcli.h
	doxygen Doxyfile
	doxy2man -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/group__radcli-api.xml
	doxy2man -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/group__tls-api.xml
	doxy2man -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/group__misc-api.xml
	doxy2man -i radcli/ --short-pkg radcli --pkg 'Radius client library' --out man --novalidate --nosummary xml/radcli_8h.xml
	PUBFUNCS="$$(cat $(top_srcdir)/include/radcli/radcli.h | \
		$(top_srcdir)/doc/scripts/getfuncs.pl | sort -u)"; \
	for f in man/*.3; do \
		base="$$(basename $$f .3)"; \
		[ "$$base" = "radcli.h" ] && continue; \
		echo "$$PUBFUNCS" | grep -qx "$$base" || rm -f "$$f"; \
	done
	perl $(top_srcdir)/doc/scripts/gen-radcli-h-man.pl \
	    $(top_srcdir)/include/radcli/radcli.h \
	    $(top_srcdir)/lib/radcli.map \
	    xml/radcli_8h.xml \
	    xml/group__radcli-api.xml \
	    xml/group__tls-api.xml \
	    xml/group__misc-api.xml > man/radcli.h.3
	perl $(top_srcdir)/doc/scripts/fix-seealso.pl \
	    $(top_srcdir)/include/radcli/radcli.h \
	    $(top_srcdir)/lib/radcli.map \
	    man/
	echo > $@

stamp_html: ../include/radcli/radcli.h
	doxygen Doxyfile
	echo > $@

update-doc: stamp_mans
	FUNCS=`cat $(top_srcdir)/include/radcli/radcli.h | $(top_srcdir)/doc/scripts/getfuncs.pl|sort -d|uniq`; \
	MANS=""; \
	for i in $$FUNCS; do \
		MANS="$$MANS\nAPIMANS += man\/$$i.3"; \
	done; \
	grep -v -e '^APIMANS += ' doc.mk | \
		perl -p -e "s/^APIMANS =/APIMANS =$$MANS/" > tmp-$@; \
	diff -u $(srcdir)/doc.mk tmp-$@ || mv tmp-$@ doc.mk
	rm -f tmp-$@

dist-hook:
	@if test "$(srcdir)" = "."; then $(MAKE) $(AM_MAKEFLAGS) update-doc; fi
