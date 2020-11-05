![Tests](https://github.com/radcli/radcli/workflows/Tests/badge.svg?branch=master)

# The radcli library

## Introduction

The radcli library is a library for writing RADIUS Clients. The library's
approach is to allow writing RADIUS-aware application in less than 50 lines
of C code. It was based originally on freeradius-client and radiusclient-ng
and is source compatible with them.


## Background

For the development of the openconnect VPN server, I needed a simple library to
allow using radius for authentication and accounting without having to understand
the internals of radius. Such library was the freeradius-client library, but
was undocumented, had too much legacy code centered around radlogin, a tool 
which is of no significance today, was IPv4-only and had no releases for
several years.

This library addresses these shortcomings, adds package management via
pkg-config, adds support for TCP, TLS and DTLS, provides documentation of the API,
and will include any new features for the task. It is provided as a shared
library in case it is useful to other projects as well, and is also made source
compatible with radiusclient-ng and freeradius-client.


## Documentation

Documentation and examples are available at:
http://radcli.github.io/radcli/

## Compilation

Run autogen.sh to generate the configure script and makefiles.

Required dependencies (Fedora/RHEL pkg):

```
yum install -y autoconf libtool automake nettle-devel gnutls-devel abi-compliance-checker
```


Required dependencies (Fedora 23+):
```
dnf install -y autoconf libtool automake nettle-devel gnutls-devel gettext-devel abi-compliance-checker
```


Required dependencies (Debian pkg):
```
apt-get install -y autoconf libtool automake nettle-dev libgnutls28-dev abi-compliance-checker
```

## Contributing/Submitting pull requests

For adding new features or extending functionality in addition to the code,
please also submit a test program which verifies the correctness of operation.
See `tests/` and `.travis.yml` for the existing test suite.


## Bug reporting

Please use the issue tracker at:
https://github.com/radcli/radcli/issues


## Web Site

The web site http://radcli.github.io/radcli is the primary web-site for
radcli and is auto-generated via the 'make web' rule.
