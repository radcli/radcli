doxygen = find_program('doxygen', required: get_option('docs'))
doxy2man = find_program('doxy2man', required: get_option('docs'))
perl = find_program('perl', required: get_option('docs'))

if doxygen.found() and doxy2man.found() and perl.found()
  doxyfile_conf = configuration_data()
  doxyfile_conf.set('VERSION', meson.project_version())
  doxyfile_conf.set('TOP_SRCDIR', meson.project_source_root())
  doxyfile = configure_file(
    input: 'Doxyfile.in', output: 'Doxyfile', configuration: doxyfile_conf,
  )

  man3_stamp = custom_target('api-man-pages',
    input: [doxyfile, '../include/radcli/radcli.h', '../lib/radcli.map.in'],
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
  # HTML and stages it + doc/web/ as a gh-pages-ready commit. Does not push;
  # run `ninja -C build web` then follow the printed push instructions.
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
