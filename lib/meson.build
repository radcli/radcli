# Library code modified:                              REVISION++
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

dict_rfc_gen_h = custom_target('dict_rfc_gen_h',
  input: ['gen-dict.awk', '../etc/dictionary'],
  output: 'dict_rfc_gen.h',
  command: [find_program('awk'), '-f', '@INPUT0@', '@INPUT1@'],
  capture: true,
)

lib_sources = [
  'buildreq.c', 'sendserver.c', 'avpair.c', 'avp.c', 'request.c', 'config.c', 'dict.c',
  'ip_util.c', 'log.c', 'util.c', 'rc-md5.c', 'tls.c', 'aaa_ctx.c',
  'ccan/list/list.c',
  dict_rfc_gen_h,
]

if have_nettle
  lib_sources += ['nettle-hmac.c']
else
  lib_sources += ['md5.c', 'hmac.c']
endif

lib_incdirs = [config_inc, include_dirs, include_directories('.')]
lib_cargs = ['-DRC_LOG_FACILITY=' + get_option('facility')]

# File.full_path() needs meson >=1.4.0; construct the path manually instead,
# since we know exactly where configure_file() put it. Also reused by the
# top-level compare-exported target.
radcli_map_path = meson.current_build_dir() / 'radcli.map'

# GNU-ld-compatible linkers understand --version-script regardless of OS.
version_script_supported = cc.get_linker_id() in ['ld.bfd', 'ld.gold', 'ld.lld', 'ld.mold']
lib_link_args = []
if version_script_supported
  lib_link_args += ['-Wl,--version-script=' + radcli_map_path]
endif

# The static archive is always built so tests can link against internal
# symbols not exported via radcli.map (see tests/meson.build). It isn't
# part of the package's public API/ABI, so it's only installed when
# explicitly requested via -Dstatic=true (equivalent to the old
# autotools/libtool --enable-static; Fedora and other distros normally
# want --disable-static's behavior, which is the default here).
libradcli_static = static_library('radcli', lib_sources,
  include_directories: lib_incdirs,
  dependencies: link_libs,
  c_args: lib_cargs,
  install: get_option('static'),
)

libradcli_shared = shared_library('radcli', lib_sources,
  include_directories: lib_incdirs,
  dependencies: link_libs,
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
pkg.generate(libradcli_shared,
  name: 'radcli',
  description: 'A small radius client library',
  url: 'http://radcli.github.io/radcli/',
  version: meson.project_version(),
  requires_private: requires_private,
)

if get_option('legacy-compat')
  meson.add_install_script(
    meson.project_source_root() / 'meson-scripts/install-compat-symlinks.sh',
    get_option('libdir'))
endif
