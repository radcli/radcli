# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# License: BSD

EXTRA_DIST = radiusclient-ipv6.conf servers-ipv6 \
	radiusclient.conf servers README \
	dtls/ca.pem dtls/clicert.pem \
	dtls/clikey.pem dtls/radiusclient-tls.conf \
	dtls/radsecproxy.conf \
	raddb/access_challenge raddb/access_reject raddb/accounting_response \
	raddb/acct_users raddb/ca.pem raddb/cert-rsa.pem raddb/clients.conf \
	raddb/key-rsa.pem raddb/mods-enabled raddb/radiusd.conf \
	raddb/sites-enabled raddb/users raddb/mods-enabled/eap \
	raddb/sites-enabled/tls \
	raddb-tcp/access_challenge raddb-tcp/access_reject \
	raddb-tcp/accounting_response raddb-tcp/acct_users raddb-tcp/ca.pem \
	raddb-tcp/cert-rsa.pem raddb-tcp/clients.conf raddb-tcp/key-rsa.pem \
	raddb-tcp/radiusd.conf raddb-tcp/users \
	radius-server.py \
	common.sh \
	ns.sh \
	dictionaries/dictionary.microsoft \
	dictionaries/dictionary.roaringpenguin

AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include -I$(top_srcdir)/src -I$(top_builddir)
LDADD = ../lib/libradcli.la

dist_check_SCRIPTS = basic-tests.sh ipv6-tests.sh tls-tests.sh tls-idle-restart-tests.sh failover-tests.sh tcp-tests.sh eap-tests.sh no-server-file-tests.sh reject-tests.sh skip-unknown-vsa.sh namespace-tests.sh radembedded-tests.sh radembedded-dict-tests.sh ipv6-non-temp-addr-tests.sh msg-auth-tests.sh close-notify-tests.sh malformed-packet-tests.sh
TESTS = basic-tests.sh ipv6-tests.sh failover-tests.sh tcp-tests.sh eap-tests.sh no-server-file-tests.sh reject-tests.sh skip-unknown-vsa.sh namespace-tests.sh radembedded-tests.sh radembedded-dict-tests.sh ipv6-non-temp-addr-tests.sh msg-auth-tests.sh malformed-packet-tests.sh
check_PROGRAMS =

if ENABLE_GNUTLS
ctests = avpair dict dict-add pack

TESTS += tls-tests.sh tls-idle-restart-tests.sh close-notify-tests.sh $(ctests)

check_PROGRAMS += tls-restart tls-idle-restart close-notify-server $(ctests)

tls_restart_SOURCES = tls-restart.c
tls_restart_LDADD = ../lib/libradcli.la

tls_idle_restart_SOURCES = tls-idle-restart.c
tls_idle_restart_LDADD = ../lib/libradcli.la

close_notify_server_SOURCES = close-notify-server.c
close_notify_server_LDADD = $(LIBGNUTLS_LIBS)
close_notify_server_CFLAGS = $(LIBGNUTLS_CFLAGS)

# Link pack directly against the static archive so the non-exported
# rc_pack_list symbol (not in radcli.map) is accessible for unit testing.
pack_SOURCES = pack.c
pack_LDADD = ../lib/.libs/libradcli.a $(LIBGNUTLS_LIBS) -lnettle
endif


TESTS_ENVIRONMENT = \
	top_builddir="$(top_builddir)"                          \
	srcdir="$(srcdir)"

