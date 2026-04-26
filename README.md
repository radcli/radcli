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
several years, and zero tests.

This library addresses these shortcomings, adds a test suite and test driven
development, adds package management via pkg-config, adds support for TCP,
TLS and DTLS, provides documentation of the API, and will include any new
features for the task. It is provided as a shared library in case it is
useful to other projects as well, and is also made source compatible with
radiusclient-ng and freeradius-client.


## Documentation

Documentation and examples are available at:
https://radcli.github.io/radcli/

## Compilation

Run autogen.sh to generate the configure script and makefiles.

Required dependencies (Fedora/RHEL pkg):
```
dnf install -y autoconf libtool automake nettle-devel gnutls-devel gettext-devel libabigail doxygen doxy2man
```

## Contributing/Submitting pull requests

For adding new features or extending functionality in addition to the code,
please also submit a test program which verifies the correctness of operation.
See `tests/` and `.travis.yml` for the existing test suite.

## AI Assistance Policy

AI tool use is assumed and does not require disclosure. What matters is human
accountability: every line you submit is your responsibility, regardless of how
it was generated. Reviewers will hold you accountable as the author.

**If you use AI assistance:**

- Follow the guidance in [`AGENTS.md`](AGENTS.md) for all AI-assisted work.
- External contributors should load the `radcli-contributor` persona
  (`contrib/ai/personas/radcli-contributor.md`) before starting.
- Maintainers doing AI-assisted review or development should load the
  `radcli-core-dev` persona (`contrib/ai/personas/radcli-core-dev.md`).

**Review calibration:** Reviewers may ask how a contribution was developed if it
raises quality questions. Be prepared to explain your approach. Submissions that
show signs of unchecked generation — hallucinated API calls, missing tests, style
inconsistencies — may be returned with a request for additional work rather than
an inline review.

**Not acceptable:** Submitting code you cannot explain or defend. Own your patch.



## Bug reporting

Please use the issue tracker at:
https://github.com/radcli/radcli/issues


## Web Site

The web site https://radcli.github.io/radcli is the primary web-site for
radcli and is auto-generated via the 'make web' rule.
