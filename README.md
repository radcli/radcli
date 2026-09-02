![Tests](https://github.com/radcli/radcli/actions/workflows/tests.yaml/badge.svg?branch=master)

# The radcli library

## Introduction

The radcli library is a library for writing RADIUS Clients. The library's
approach is to allow writing RADIUS-aware application in less than 50 lines
of C code. It was based originally on freeradius-client and radiusclient-ng
and is source compatible with them.


## Background

A modern RADIUS client library was missing: one with asynchronous request
handling for event-driven applications, RFC 5176 Dynamic Authorization
(CoA/Disconnect) support, and native handling of modern RADIUS attributes
(RFC 8044 types, 64-bit counters). radcli2 fills that gap, alongside a
documented API, a test suite, and support for TCP, TLS and DTLS transport.


## Which API should I use?

- **New code:** use `libradcli2` (`#include <radcli/radcli2.h>`). It's built
  around opaque, forward-compatible structures, supports RFC 5176 (CoA/
  Disconnect), RFC 8044 attribute types, and asynchronous request handling.
  See `src/radexample.c` and `src/radexample-async-dae.c` (async).
- **Existing radiusclient-ng/freeradius-client code:** `libradcli`'s
  `rc_*()` API is unchanged and still supported; no action needed.
- Porting `rc_*()` code to the new API? See `doc/migration-guide.md`.


## Documentation

Documentation and examples are available at:
https://radcli.github.io/radcli/

## Compilation

radcli uses [Meson](https://mesonbuild.com/) as its build system.

```
meson setup build
ninja -C build
sudo ninja -C build install
```

Required dependencies (Fedora/RHEL pkg):
```
dnf install -y meson ninja-build nettle-devel gnutls-devel libabigail doxygen doxy2man
```

Useful `meson setup` options (`-Doption=value`):
- `-Dtls=disabled` — disable TLS/DTLS (GnuTLS dependency)
- `-Dlegacy-compat=true` — install freeradius-client/radiusclient-ng compat headers and `.so` symlinks
- `-Ddocs=disabled` — skip Doxygen/doxy2man man page generation

See [`AGENTS.md`](AGENTS.md) for testing, ABI-check, and other maintainer commands.

## Contributing/Submitting pull requests

For adding new features or extending functionality in addition to the code,
please also submit a test program which verifies the correctness of operation.
See `tests/` and `.github/workflows` for the existing test suite.

## AI Assistance Policy

AI tool use is assumed and does not require disclosure, but every line you
submit is your responsibility regardless of how it was generated. Follow the
guidance in [`AGENTS.md`](AGENTS.md) and load the matching persona from
`contrib/ai/personas/` (`radcli-contributor` for external contributors,
`radcli-core-dev` for maintainers) before starting AI-assisted work.



## Bug reporting

Please use the issue tracker at:
https://github.com/radcli/radcli/issues


## Web Site

The web site https://radcli.github.io/radcli is the primary web-site for
radcli and is generated from the `doc/` Doxygen output and `doc/web/`.

Rebuild and stage the site content with:
```
ninja -C build web
```
This regenerates the Doxygen HTML and stages `doc/web/` plus the HTML manual
as a commit ready to publish to the `gh-pages` branch. It does not push;
review the resulting commit and publish it yourself with the `git push`
command it prints.
