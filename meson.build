project('radcli', 'c',
  version: '1.5.3',
  license: 'BSD-2-Clause AND UMich-Merit AND HPND-Fenneberg-Livingston AND BSD-MIT AND CC0-1.0 AND BSD-1-Clause',
  default_options: ['c_std=gnu99', 'warning_level=1'],
  meson_version: '>=1.1.0',
)

cc = meson.get_compiler('c')

# ---------------------------------------------------------------------------
# config.h -- trimmed to the HAVE_* symbols actually referenced in the code
# ---------------------------------------------------------------------------

conf = configuration_data()

headers_to_check = [
  'arpa/inet.h', 'fcntl.h', 'getopt.h', 'inttypes.h', 'limits.h',
  'netdb.h', 'netinet/in.h', 'pwd.h', 'stdint.h', 'sys/fcntl.h',
  'sys/file.h', 'sys/ioctl.h', 'syslog.h', 'sys/socket.h', 'sys/stat.h',
  'sys/time.h', 'sys/types.h', 'sys/utsname.h', 'termios.h', 'unistd.h',
]
foreach h : headers_to_check
  conf.set('HAVE_' + h.underscorify().to_upper(), cc.has_header(h) ? 1 : false)
endforeach

funcs_to_check = [
  'gethostname', 'random', 'rand', 'snprintf', 'vsnprintf',
  'strlcpy', 'strchr', 'sysinfo', 'uname', 'clock_gettime',
]
have_clock_gettime = false
foreach f : funcs_to_check
  have_f = cc.has_function(f)
  conf.set('HAVE_' + f.to_upper(), have_f ? 1 : false)
  if f == 'clock_gettime'
    have_clock_gettime = have_f
  endif
endforeach

# Obsolete autoconf macros (AC_HEADER_STDC / historic sys/time.h+time.h
# check); true on every system radcli still supports, so set unconditionally
# rather than probing for them.
conf.set('STDC_HEADERS', 1)
conf.set('TIME_WITH_SYS_TIME', 1)

if cc.has_header('syslog.h')
  conf.set('HAVE_DECL_LOG_PERROR',
    cc.has_header_symbol('syslog.h', 'LOG_PERROR') ? 1 : 0)
else
  conf.set('HAVE_DECL_LOG_PERROR', 0)
endif

# threads / rt for pthread_mutex_lock / clock_gettime fallback
threads_dep = dependency('threads')
rt_dep = []
if not have_clock_gettime
  rt_dep = [cc.find_library('rt', required: false)]
endif

# Solaris -lsocket
socket_dep = cc.find_library('socket', required: false)

# TLS / crypto
gnutls_dep = dependency('gnutls', version: '>=3.1.0', required: get_option('tls'))
have_gnutls = gnutls_dep.found()
conf.set('HAVE_GNUTLS', have_gnutls ? 1 : false)

nettle_dep = dependency('nettle', version: '>=2.4', required: get_option('nettle'))
have_nettle = nettle_dep.found()
conf.set('HAVE_NETTLE', have_nettle ? 1 : false)

# nettle >=3.10 dropped the length argument from fixed-size digest
# functions (md5_digest(), hmac_md5_digest(), and friends), since
# truncating a fixed-size digest isn't meaningfully supported. Older
# nettle still requires it. Both functions changed together as part of
# the same upstream API revision, so one probe covers both.
have_digest_length_arg = false
if have_nettle
  have_digest_length_arg = cc.compiles('''
    #include <nettle/md5.h>
    void f(struct md5_ctx *ctx, uint8_t *out) {
      md5_digest(ctx, MD5_DIGEST_SIZE, out);
    }
    ''',
    name: 'nettle fixed-digest functions take a length argument',
    dependencies: nettle_dep)
endif
conf.set('HAVE_DIGEST_LENGTH_ARG', have_digest_length_arg ? 1 : false)

requires_private = []
if have_gnutls
  requires_private += 'gnutls'
endif
if have_nettle
  requires_private += 'nettle'
endif

link_libs = [threads_dep, rt_dep, socket_dep, gnutls_dep, nettle_dep]

config_h = configure_file(output: 'config.h', configuration: conf)
config_inc = include_directories('.')

# pkgsysconfdir: /etc/radcli -- shared between etc/ (install location) and
# src/ (RC_CONFIG_FILE define), computed once here to avoid drift.
pkgsysconfdir = get_option('sysconfdir') / meson.project_name()
if get_option('sysconfdir').startswith('/')
  pkgsysconfdir_abs = pkgsysconfdir
else
  pkgsysconfdir_abs = get_option('prefix') / pkgsysconfdir
endif

subdir('include')
subdir('lib')
subdir('src')
subdir('etc')
subdir('doc')
subdir('tests')

# ---------------------------------------------------------------------------
# Maintainer targets: ABI check / compare-exported (not part of `meson test`)
# ---------------------------------------------------------------------------

abidiff = find_program('abidiff', required: false)
abidw = find_program('abidw', required: false)
abi_dump = meson.current_source_dir() / 'devel/ABI-x86_64.dump'

if abidiff.found()
  run_target('abi-check',
    command: [abidiff, '--no-added-syms', '--hd2',
              meson.current_source_dir() / 'include/radcli',
              libradcli_shared.full_path(), abi_dump],
    depends: libradcli_shared)
endif

if abidw.found()
  run_target('abi-dump',
    command: [abidw, libradcli_shared.full_path(), '--out-file', abi_dump],
    depends: libradcli_shared)
endif

run_target('compare-exported',
  command: [find_program('meson-scripts/compare-exported.sh'),
            radcli_map_path,
            meson.current_source_dir() / 'doc/scripts',
            meson.current_source_dir() / 'include/radcli/radcli.h',
            meson.current_source_dir() / 'include/radcli/radcli2.h'])

summary({
  'TLS (gnutls)': have_gnutls,
  'nettle': have_nettle,
  'legacy-compat': get_option('legacy-compat'),
  'docs': get_option('docs'),
  'prefix': get_option('prefix'),
}, section: 'radcli configuration')
