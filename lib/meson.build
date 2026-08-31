# libradcli2 (new, self-sufficient radcli2.h API) library code modified:
#                                                       REVISION2++
# Interfaces changed/added/removed:   CURRENT2++       REVISION2=0
# Interfaces added:                             AGE2++
# Interfaces removed:                           AGE2=0
v2_current = 1
v2_revision = 0
v2_age = 0
lib2_soversion = (v2_current - v2_age).to_string()
lib2_fullversion = '@0@.@1@.@2@'.format(v2_current - v2_age, v2_age, v2_revision)

# libradcli (legacy radcli.h API) library code modified:  REVISION++
# Interfaces changed/added/removed:   CURRENT++       REVISION=0
# Interfaces added:                             AGE++
# Interfaces removed:                           AGE=0
v_current = 12
v_revision = 0
v_age = 2
lib_soversion = (v_current - v_age).to_string()
lib_fullversion = '@0@.@1@.@2@'.format(v_current - v_age, v_age, v_revision)

map_conf = configuration_data()
map_conf.set('LIBMAJOR', lib_soversion)
radcli_map = configure_file(
  input: 'radcli.map.in', output: 'radcli.map', configuration: map_conf,
)

map2_conf = configuration_data()
map2_conf.set('LIBMAJOR2', lib2_soversion)
radcli2_map = configure_file(
  input: 'radcli2.map.in', output: 'radcli2.map', configuration: map2_conf,
)

dict_rfc_gen_h = custom_target('dict_rfc_gen_h',
  input: ['gen-dict.awk', '../etc/dictionary'],
  output: 'dict_rfc_gen.h',
  command: [find_program('awk'), '-f', '@INPUT0@', '@INPUT1@'],
  capture: true,
)

# libradcli2: self-sufficient, radcli2.h's own radcli_* API -- depends on
# nothing else in this project. lib/legacy/*.c (below) depends on this,
# not the other way around.
lib2_sources = [
  'sendserver.c', 'avp.c', 'request.c', 'aaa2.c', 'config.c', 'config2.c', 'dict2.c', 'dict2-parse.c',
  'ip_util.c', 'log.c', 'util.c', 'rc-crypto.c', 'rc-random.c', 'tls.c',
  'ccan/list/list.c', 'dae.c',
  dict_rfc_gen_h,
]

# libradcli: legacy, source-compatible-with-freeradius-client radcli.h API
# (VALUE_PAIR-based). Links against libradcli2 below for everything it
# does not implement itself.
lib_sources = [
  'legacy/buildreq.c', 'legacy/avpair.c', 'legacy/dict.c', 'legacy/aaa_ctx.c',
  'legacy/compat.c', 'legacy/send.c', 'legacy/avp-legacy-bridge.c',
]

lib_incdirs = [config_inc, include_dirs, include_directories('.')]
lib_cargs = ['-DRC_LOG_FACILITY=' + get_option('facility')]

# File.full_path() needs meson >=1.4.0; construct the path manually instead,
# since we know exactly where configure_file() put it. Also reused by the
# top-level compare-exported target.
radcli_map_path = meson.current_build_dir() / 'radcli.map'
radcli2_map_path = meson.current_build_dir() / 'radcli2.map'

# GNU-ld-compatible linkers understand --version-script regardless of OS.
version_script_supported = cc.get_linker_id() in ['ld.bfd', 'ld.gold', 'ld.lld', 'ld.mold']
lib_link_args = []
lib2_link_args = []
if version_script_supported
  lib_link_args += ['-Wl,--version-script=' + radcli_map_path]
  lib2_link_args += ['-Wl,--version-script=' + radcli2_map_path]
endif

libradcli2_shared = shared_library('radcli2', lib2_sources,
  include_directories: lib_incdirs,
  dependencies: link_libs,
  c_args: lib_cargs,
  link_args: lib2_link_args,
  link_depends: version_script_supported ? [radcli2_map] : [],
  version: lib2_fullversion,
  soversion: lib2_soversion,
  install: true,
)

libradcli2_dep = declare_dependency(
  link_with: libradcli2_shared,
  include_directories: [include_dirs, config_inc],
)

# The static archive is always built -- combining both libraries' sources,
# unlike the two shared libraries -- so tests can link against internal
# symbols not exported via either map (see tests/meson.build). It isn't
# part of the package's public API/ABI, so it's only installed when
# explicitly requested via -Dstatic=true (equivalent to the old
# autotools/libtool --enable-static; Fedora and other distros normally
# want --disable-static's behavior, which is the default here).
libradcli_static = static_library('radcli', lib_sources + lib2_sources,
  include_directories: lib_incdirs,
  dependencies: link_libs,
  c_args: lib_cargs,
  install: get_option('static'),
)

libradcli_shared = shared_library('radcli', lib_sources,
  include_directories: lib_incdirs,
  dependencies: link_libs,
  link_with: libradcli2_shared,
  c_args: lib_cargs,
  link_args: lib_link_args,
  link_depends: version_script_supported ? [radcli_map] : [],
  version: lib_fullversion,
  soversion: lib_soversion,
  install: true,
)

libradcli_dep = declare_dependency(
  link_with: libradcli_shared,
  include_directories: [include_dirs, config_inc],
)

pkg = import('pkgconfig')
pkg.generate(libradcli2_shared,
  name: 'radcli2',
  description: 'radcli2.h: the new, self-sufficient radcli client API',
  url: 'http://radcli.github.io/radcli/',
  version: meson.project_version(),
  requires_private: requires_private,
)
pkg.generate(libradcli_shared,
  name: 'radcli',
  description: 'A small radius client library',
  url: 'http://radcli.github.io/radcli/',
  version: meson.project_version(),
  requires_private: requires_private + ['radcli2'],
)

if get_option('legacy-compat')
  meson.add_install_script(
    meson.project_source_root() / 'meson-scripts/install-compat-symlinks.sh',
    get_option('libdir'))
endif
