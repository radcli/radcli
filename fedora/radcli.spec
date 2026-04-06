Summary: RADIUS protocol client library
Name: radcli
Version: 1.5.0
Release: %autorelease

#Breakdown of licenses. Under MIT license:
# lib/avpair.c, lib/buildreq.c, lib/clientid.c, lib/config.c, lib/dict.c,
# lib/env.c, lib/ip_util.c, lib/log.c, lib/sendserver.c, lib/util.c,
# src/local.c, src/radacct.c, src/radexample.c, src/radius.c, src/radlogin.c,
# src/radstatus.c, include/messages.h, include/pathnames.h, lib/options.h
# Under BSD license: lib/util.c, src/radiusclient.c, lib/rc-md5.c, lib/tls.c,
# lib/tls.h

License: BSD-2-Clause AND UMich-Merit AND HPND-Fenneberg-Livingston
URL: http://radcli.github.io/radcli/

Source0: https://github.com/radcli/radcli/releases/download/%{version}/%{name}-%{version}.tar.gz
Source1: https://github.com/radcli/radcli/releases/download/%{version}/%{name}-%{version}.tar.gz.sig

BuildRequires: libtool, automake, autoconf
#BuildRequires: gettext-devel
BuildRequires: make
BuildRequires: gcc, iproute
BuildRequires: nettle-devel >= 2.7.1
BuildRequires: gnutls-devel

%description
The radcli library is a library for writing RADIUS Clients. The library's
approach is to allow writing RADIUS-aware application in less than 50 lines
of C code. It was based originally on freeradius-client and is source compatible
with it.

%package devel
Summary: Development files for radcli
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
This package contains libraries and header files for developing applications
that use %{name}.

%package compat-devel
Summary: Development files for compatibility with radiusclient-ng and freeradius-client
Requires: %{name}-devel = %{version}-%{release}
# We provide compatible headers with it
Conflicts: freeradius-client-devel, radiusclient-ng-devel

%description compat-devel
This package contains the compatibility headers and libraries for freeradius-client
and radiusclient-ng.

%prep
%autosetup -p1
rm -f lib/md5.c
sed -i -e 's|sys_lib_dlsearch_path_spec="[^"]\+|& %{_libdir}|g' configure

%build
autoreconf -fvi
%configure --disable-static --disable-rpath --with-nettle --with-tls --enable-legacy-compat
make %{?_smp_mflags}

%check
make %{?_smp_mflags} check

%install
make DESTDIR=%{buildroot} install
rm -f %{buildroot}%{_libdir}/*.la

# these should be removed once the utils subpackage is on

mkdir -p %{buildroot}%{_datadir}/%{name}
cp -p %{buildroot}%{_datadir}/%{name}/dictionary %{buildroot}%{_sysconfdir}/%{name}/dictionary

%ldconfig_scriptlets

%files
%doc README.md NEWS
%license COPYRIGHT

%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/radiusclient.conf
%config(noreplace) %{_sysconfdir}/%{name}/radiusclient-tls.conf
%config(noreplace) %{_sysconfdir}/%{name}/servers
%config(noreplace) %{_sysconfdir}/%{name}/servers-tls
%config(noreplace) %{_sysconfdir}/%{name}/dictionary

%{_libdir}/libradcli.so.*

%dir %{_datadir}/%{name}
%{_datadir}/%{name}/dictionary
%{_datadir}/%{name}/dictionary.roaringpenguin
%{_datadir}/%{name}/dictionary.microsoft
%{_datadir}/%{name}/dictionary.ascend
%{_datadir}/%{name}/dictionary.compat
%{_datadir}/%{name}/dictionary.merit
%{_datadir}/%{name}/dictionary.sip

%files devel

%{_includedir}/%{name}
%{_libdir}/libradcli.so
%{_mandir}/man3/*
%{_libdir}/pkgconfig/*.pc

%files compat-devel

%{_includedir}/freeradius-client.h
%{_includedir}/radiusclient-ng.h
%{_libdir}/libfreeradius-client.so
%{_libdir}/libradiusclient-ng.so

%changelog
%autochangelog
