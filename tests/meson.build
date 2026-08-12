tests_incdirs = [config_inc, include_dirs, include_directories('../src')]

test_env = environment()
test_env.set('top_builddir', meson.project_build_root())
test_env.set('srcdir', meson.current_source_dir())

shell_tests = [
  'basic-tests.sh', 'ipv6-tests.sh', 'failover-tests.sh', 'acct-async-tests.sh',
  'tcp-tests.sh', 'eap-tests.sh', 'no-server-file-tests.sh', 'reject-tests.sh',
  'skip-unknown-vsa.sh', 'namespace-tests.sh', 'radembedded-tests.sh',
  'radembedded-dict-tests.sh', 'ipv6-non-temp-addr-tests.sh',
  'msg-auth-tests.sh', 'malformed-packet-tests.sh',
]

if have_gnutls
  shell_tests += ['tls-tests.sh', 'tls-verify-hostname-tests.sh', 'tls-msg-auth-tests.sh', 'tls-idle-restart-tests.sh', 'close-notify-tests.sh']

  tls_restart = executable('tls-restart', 'tls-restart.c',
    include_directories: tests_incdirs, link_with: libradcli_shared,
    dependencies: link_libs, install: false)
  tls_idle_restart = executable('tls-idle-restart', 'tls-idle-restart.c',
    include_directories: tests_incdirs, link_with: libradcli_shared,
    dependencies: link_libs, install: false)
  close_notify_server = executable('close-notify-server', 'close-notify-server.c',
    include_directories: tests_incdirs, dependencies: [gnutls_dep], install: false)

  avpair = executable('avpair', 'avpair.c',
    include_directories: tests_incdirs, link_with: libradcli_shared,
    dependencies: link_libs, install: false)
  dict = executable('dict', 'dict.c',
    include_directories: tests_incdirs, link_with: libradcli_shared,
    dependencies: link_libs, install: false)
  dict_add = executable('dict-add', 'dict-add.c',
    include_directories: tests_incdirs, link_with: libradcli_shared,
    dependencies: link_libs, install: false)
  # Links against the static archive directly so the non-exported
  # rc_pack_list symbol (not in radcli.map) is accessible for unit testing.
  pack = executable('pack', 'pack.c',
    include_directories: tests_incdirs, link_with: libradcli_static,
    dependencies: [gnutls_dep, nettle_dep], install: false)
  config_unit = executable('config-unit', 'config-unit.c',
    include_directories: tests_incdirs, link_with: libradcli_shared,
    dependencies: link_libs, install: false)

  foreach t : [avpair, dict, dict_add, pack, config_unit]
    test(t.name(), t, env: test_env)
  endforeach
endif

foreach t : shell_tests
  test(t, find_program(t), env: test_env, timeout: 300,
       workdir: meson.current_source_dir())
endforeach
