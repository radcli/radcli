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

EXTRA_DIST = Doxyfile.in scripts/getfuncs.pl scripts/getfuncs-map.pl doc.mk

dist_man_MANS = $(APIMANS)

$(APIMANS):

stamp_mans: ../include/radcli/radcli.h
	doxygen Doxyfile
	doxy2man -i radcli/ --short-pkg radcli --pkg 'Radius client library'  --out man --novalidate xml/radcli_8h.xml
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

dist-hook: update-doc
