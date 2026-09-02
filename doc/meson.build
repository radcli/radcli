doxygen = find_program('doxygen', required: get_option('docs'))
doxy2man = find_program('doxy2man', required: get_option('docs'))
perl = find_program('perl', required: get_option('docs'))

if doxygen.found() and doxy2man.found() and perl.found()
  doxy_migration_guide = meson.current_source_dir() / 'migration-guide.md'
  doxy_migration_guide_map = meson.current_source_dir() / 'migration-guide-map.md'
  doxy_migration_guide_examples = meson.current_source_dir() / 'migration-guide-examples.md'
  doxy_mainpage_new = meson.current_source_dir() / 'mainpage-new.md'
  doxy_mainpage_legacy = meson.current_source_dir() / 'mainpage-legacy.md'

  # Legacy-API-only pass. Also one of the two passes used for man-page XML
  # generation below (build-man-pages.sh extracts the legacy radcli-api/
  # tls-api/radcli_8h XML groups from this one, and the radcli2-*/radcli-dae/
  # radcli2_8h XML groups from the new-API pass below), so scoping INPUT down
  # to the legacy surface here doesn't change what this pass's man pages
  # contain.
  doxyfile_conf = configuration_data()
  doxyfile_conf.set('VERSION', meson.project_version())
  doxyfile_conf.set('TOP_SRCDIR', meson.project_source_root())
  doxyfile_conf.set('DOXY_BRIEF', 'A simple radius library -- legacy API reference')
  doxyfile_conf.set('DOXY_INPUT', ' '.join([
    meson.project_source_root() / 'lib',
    meson.project_source_root() / 'lib/legacy',
    meson.project_source_root() / 'include/radcli',
    doxy_migration_guide,
    doxy_migration_guide_map,
    doxy_migration_guide_examples,
    doxy_mainpage_legacy,
  ]))
  doxyfile_conf.set('DOXY_EXCLUDE', ' '.join([
    meson.project_source_root() / 'lib/avp.c',
    meson.project_source_root() / 'lib/config2.c',
    meson.project_source_root() / 'lib/aaa2.c',
    meson.project_source_root() / 'lib/dict2.c',
    meson.project_source_root() / 'lib/dict2-parse.c',
    meson.project_source_root() / 'lib/request.c',
    meson.project_source_root() / 'lib/dae.c',
    meson.project_source_root() / 'include/radcli/radcli2.h',
  ]))
  doxyfile_conf.set('DOXY_HTML_OUTPUT', 'html-legacy')
  doxyfile_conf.set('DOXY_MAINPAGE', doxy_mainpage_legacy)
  doxyfile_conf.set('DOXY_GENERATE_XML', 'YES')
  # Stock layout (default "Related Pages" tab): the "Migration" tab is a
  # come-here-to-migrate call to action for legacy-API readers landing in
  # the *new* tree, and doesn't belong on the legacy tree's own tab bar.
  doxyfile_conf.set('DOXY_LAYOUT', '')
  doxyfile_legacy = configure_file(
    input: 'Doxyfile.in', output: 'Doxyfile-legacy', configuration: doxyfile_conf,
  )

  # New-API-only pass. Also generates XML (consumed by build-man-pages.sh
  # for the radcli2.h man pages, same as the legacy pass above).
  doxyfile_new_conf = configuration_data()
  doxyfile_new_conf.set('VERSION', meson.project_version())
  doxyfile_new_conf.set('TOP_SRCDIR', meson.project_source_root())
  doxyfile_new_conf.set('DOXY_BRIEF', 'A simple radius library -- new API reference')
  doxyfile_new_conf.set('DOXY_INPUT', ' '.join([
    meson.project_source_root() / 'lib',
    meson.project_source_root() / 'include/radcli',
    meson.project_source_root() / 'src/radexample.c',
    meson.project_source_root() / 'src/radexample-async-dae.c',
    meson.project_source_root() / 'src/raddaeserver.c',
    doxy_migration_guide,
    doxy_migration_guide_map,
    doxy_migration_guide_examples,
    doxy_mainpage_new,
  ]))
  doxyfile_new_conf.set('DOXY_EXCLUDE', ' '.join([
    meson.project_source_root() / 'lib/legacy',
    # These lib/*.c implement the legacy rc_/RC_ surface only (no radcli2.h
    # include) -- excluded here so the new-API tree doesn't pick up their
    # @defgroup radcli-api/tls-api content or bare legacy symbols.
    meson.project_source_root() / 'lib/config.c',
    meson.project_source_root() / 'lib/ip_util.c',
    meson.project_source_root() / 'lib/log.c',
    meson.project_source_root() / 'lib/sendserver.c',
    meson.project_source_root() / 'lib/tls.c',
    meson.project_source_root() / 'lib/util.c',
    meson.project_source_root() / 'include/radcli/radcli.h',
  ]))
  doxyfile_new_conf.set('DOXY_HTML_OUTPUT', 'html')
  doxyfile_new_conf.set('DOXY_MAINPAGE', doxy_mainpage_new)
  doxyfile_new_conf.set('DOXY_GENERATE_XML', 'YES')
  doxyfile_new_conf.set('DOXY_LAYOUT', meson.current_source_dir() / 'DoxygenLayout.xml')
  doxyfile_radcli2 = configure_file(
    input: 'Doxyfile.in', output: 'Doxyfile-radcli2', configuration: doxyfile_new_conf,
  )

  man3_stamp = custom_target('api-man-pages',
    input: [
      doxyfile_legacy, '../include/radcli/radcli.h', '../lib/radcli.map.in',
      doxyfile_radcli2, '../include/radcli/radcli2.h', '../lib/radcli2.map.in',
    ],
    output: 'stamp_mans',
    command: [
      find_program(meson.project_source_root() / 'meson-scripts/build-man-pages.sh'),
      meson.current_source_dir(), meson.project_build_root() / 'doc',
      doxygen.full_path(), doxy2man.full_path(), perl.full_path(),
    ],
    build_by_default: true,
    install: false,
  )

  # Equivalent of the old autotools "make web" target: rebuilds the Doxygen
  # HTML (new API and legacy API, as two cross-linked trees) and stages it +
  # doc/web/ as a gh-pages-ready commit. Does not push; run `ninja -C build
  # web` then follow the printed push instructions.
  run_target('web',
    command: [
      find_program(meson.project_source_root() / 'meson-scripts/publish-web.sh'),
      meson.project_source_root(), meson.project_build_root() / 'doc',
      doxygen.full_path(),
    ],
  )
else
  message('doxygen/doxy2man/perl not found: man pages will not be (re)generated locally (use -Ddocs=enabled to require)')
endif

# Always registered, regardless of whether the tools above were found:
# a release tarball (produced by `meson dist`, see dist-man-pages.sh) embeds
# pre-generated pages in the source tree itself, so downstream packagers
# never need doxygen/doxy2man/perl. install-man-pages.sh installs whichever
# of {freshly-regenerated build dir output, tarball-embedded source dir
# copies} exists, preferring the fresher build dir one.
meson.add_install_script(
  meson.project_source_root() / 'meson-scripts/install-man-pages.sh',
  meson.project_build_root() / 'doc/man',
  meson.current_source_dir() / 'man',
  get_option('mandir') / 'man3',
)

# Enforce fresh docs at release time: meson dist must fail unless this build
# was configured with -Ddocs=enabled, so a release tarball can never embed
# stale or missing man pages. See meson-scripts/dist-man-pages.sh.
meson.add_dist_script(
  meson.project_source_root() / 'meson-scripts/dist-man-pages.sh',
  get_option('docs').enabled() ? '1' : '0',
)
