Migrating from the legacy API {#radcli2-migration}
==============================

radcli ships two public APIs side by side: the legacy API in `radcli.h`,
frozen -- bug fixes only, and the new API `radcli2.h`, where new functionality
lands).

This guide maps the legacy functions to their new-API replacements, and
shows a few real before/after simplifications the new API makes possible.
The examples are drawn from a real, partially-migrated call site (ocserv's
RADIUS auth/accounting module) rather than invented snippets.

- @subpage radcli2-migration-map "API mapping" -- the concept map and a
  function-by-function table of legacy calls to their new-API replacements.
- @subpage radcli2-migration-examples "Simplification examples" -- real
  before/after code showing what moving over simplifies.

## Silencing the legacy-header warning

Including `radcli.h` emits a build-time `#warning` (portable to GCC and
Clang) pointing here. If you've deliberately decided to stay on the legacy
API for now and don't want `-Werror` builds tripping over it, define
`RADCLI_SUPPRESS_LEGACY_WARNING` before including `radcli.h` -- or pass
`-DRADCLI_SUPPRESS_LEGACY_WARNING` on the compiler command line -- rather
than disabling `-Werror` wholesale or blanket-suppressing `-Wcpp`/`-W#warnings`.
