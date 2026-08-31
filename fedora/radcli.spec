Summary: RADIUS protocol client library
Name: radcli
Version: 1.5.2
Release: %autorelease

#Breakdown of licenses. Under MIT license:
# lib/avpair.c, lib/buildreq.c, lib/clientid.c, lib/config.c, lib/dict.c,
# lib/env.c, lib/ip_util.c, lib/log.c, lib/sendserver.c, lib/util.c,
# src/local.c, src/radacct.c, src/radexample.c, src/radius.c, src/radlogin.c,
# src/radstatus.c, include/messages.h, include/pathnames.h, lib/options.h
# Under BSD license: lib/util.c, src/radiusclient.c, lib/rc-crypto.c, lib/tls.c,
# lib/tls.h

License: BSD-2-Clause AND UMich-Merit AND HPND-Fenneberg-Livingston
URL: http://radcli.github.io/radcli/

Source0: https://github.com/radcli/radcli/releases/download/%{version}/%{name}-%{version}.tar.xz
Source1: https://github.com/radcli/radcli/releases/download/%{version}/%{name}-%{version}.tar.xz.sig

BuildRequires: meson, ninja-build
BuildRequires: gcc, iproute
BuildRequires: nettle-devel >= 2.7.1
BuildRequires: gnutls-devel

%description
The radcli library is a library for writing RADIUS Clients. The library's
approach is to allow writing RADIUS-aware application in less than 50 lines
of C code. It provides radcli2.h, a new, self-sufficient API, and radcli.h,
a legacy API kept source compatible with freeradius-client (see the
%{name}-compat subpackage).

%package devel
Summary: Development files for radcli
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
This package contains libraries and header files for developing applications
against radcli2.h, %{name}'s new, self-sufficient API.

%package compat
Summary: Legacy radcli client library, source compatible with freeradius-client
Requires: %{name}%{?_isa} = %{version}-%{release}

%description compat
This package contains the legacy radcli client library (radcli.h, the
rc_*/RC_* API), kept for applications not yet migrated to radcli2.h. New
applications should use %{name}-devel/radcli2.h instead -- see
https://radcli.github.io/radcli/ for the new API's documentation.

%package compat-devel
Summary: Development files for the legacy radcli API, and compatibility with radiusclient-ng and freeradius-client
Requires: %{name}-compat%{?_isa} = %{version}-%{release}
Requires: %{name}-devel = %{version}-%{release}
# We provide compatible headers with it
Conflicts: freeradius-client-devel, radiusclient-ng-devel

%description compat-devel
This package contains the headers and libraries for developing applications
against the legacy radcli.h API, and the compatibility headers and library
symlinks for freeradius-client and radiusclient-ng.

%prep
%autosetup -p1

%build
%meson -Dtls=enabled -Dlegacy-compat=true -Ddocs=disabled
%meson_build

%check
%meson_test

%install
%meson_install

# these should be removed once the utils subpackage is on

mkdir -p %{buildroot}%{_datadir}/%{name}
cp -p %{buildroot}%{_datadir}/%{name}/dictionary %{buildroot}%{_sysconfdir}/%{name}/dictionary

%ldconfig_scriptlets
%ldconfig_scriptlets compat

%files
%doc README.md NEWS
%license COPYRIGHT

%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/radiusclient.conf
%config(noreplace) %{_sysconfdir}/%{name}/radiusclient-tls.conf
%config(noreplace) %{_sysconfdir}/%{name}/servers
%config(noreplace) %{_sysconfdir}/%{name}/servers-tls
%config(noreplace) %{_sysconfdir}/%{name}/dictionary

%{_libdir}/libradcli2.so.*

%dir %{_datadir}/%{name}
%{_datadir}/%{name}/dictionary

# radcli2.h man pages -- the new API ships with the base package, alongside
# libradcli2.so.*
%exclude %{_mandir}/man3/rc_*.3*
%exclude %{_mandir}/man3/radcli.h.3*
%{_mandir}/man3/*

%files devel

%dir %{_includedir}/%{name}
%{_includedir}/%{name}/radcli2.h
%{_includedir}/%{name}/radcli-defs.h
%{_includedir}/%{name}/version.h
%{_libdir}/libradcli2.so
%{_libdir}/pkgconfig/radcli2.pc

%files compat

%{_libdir}/libradcli.so.*

%files compat-devel

%{_includedir}/%{name}/radcli.h
%{_includedir}/freeradius-client.h
%{_includedir}/radiusclient-ng.h
%{_libdir}/libradcli.so
%{_libdir}/libfreeradius-client.so
%{_libdir}/libradiusclient-ng.so
%{_libdir}/pkgconfig/radcli.pc
%{_mandir}/man3/rc_*.3*
%{_mandir}/man3/radcli.h.3*

%changelog
%autochangelog
