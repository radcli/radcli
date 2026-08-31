tests_incdirs = [config_inc, include_dirs, include_directories('../src', '../lib')]

test_env = environment()
test_env.set('top_builddir', meson.project_build_root())
test_env.set('srcdir', meson.current_source_dir())

shell_tests = [
  'basic-tests.sh', 'ipv6-tests.sh', 'failover-tests.sh', 'acct-async-tests.sh',
  'tcp-tests.sh', 'eap-tests.sh', 'no-server-file-tests.sh', 'reject-tests.sh',
  'skip-unknown-vsa.sh', 'namespace-tests.sh', 'radembedded-tests.sh',
  'radembedded-dict-tests.sh', 'ipv6-non-temp-addr-tests.sh',
  'msg-auth-tests.sh', 'malformed-packet-tests.sh', 'dns-failover-tests.sh',
  'dae-tests.sh', 'dae-freeradius-tests.sh', 'attr-ids-tests.sh',
  'example-config-tests.sh', 'avp2-api-symmetry-tests.sh',
]

if have_gnutls
  shell_tests += ['tls-tests.sh', 'tls-verify-hostname-tests.sh', 'tls-msg-auth-tests.sh', 'tls-idle-restart-tests.sh', 'close-notify-tests.sh']
  shell_tests += ['avp-codec-freeradius-tests.sh', 'request-freeradius-tests.sh']
  shell_tests += ['request-poll-multi-tests.sh']
  shell_tests += ['dae-radsec-tests.sh', 'dae-radsec-stress-tests.sh', 'dae-radsec-backpressure-tests.sh', 'dae-radsec-watchdog-tests.sh']
  shell_tests += ['watchdog-aaa-tests.sh']
  shell_tests += ['request-tls-secret-tests.sh']

  tls_restart = executable('tls-restart', 'tls-restart.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  tls_idle_restart = executable('tls-idle-restart', 'tls-idle-restart.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  close_notify_server = executable('close-notify-server', 'close-notify-server.c',
    include_directories: tests_incdirs, dependencies: [gnutls_dep], install: false)

  avpair = executable('avpair', 'avpair.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  dict = executable('dict', 'dict.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  dict_legacy = executable('dict-legacy', 'dict-legacy.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  avp = executable('avp', 'avp.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  request = executable('request', 'request.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  aaa2_unit = executable('aaa2', 'aaa2.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  dict_add = executable('dict-add', 'dict-add.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  auth_userpass_len = executable('auth-userpass-len', 'auth-userpass-len.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  dae = executable('dae', 'dae.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  # Links against the static archive directly so the non-exported
  # rc_pack_list symbol (not in radcli.map) is accessible for unit testing.
  pack = executable('pack', 'pack.c',
    include_directories: tests_incdirs, link_with: libradcli_static,
    dependencies: [gnutls_dep, nettle_dep], install: false)
  # Same reason: radcli_avp_decode()/radcli_avp_encode() are internal-only
  # (lib/avp.h), not in radcli.map.
  avp_codec = executable('avp-codec', 'avp-codec.c',
    include_directories: tests_incdirs, link_with: libradcli_static,
    dependencies: [gnutls_dep, nettle_dep], install: false)
  # Same reason: radcli_avp_list_to_value_pairs()/radcli_value_pairs_to_avp_list()
  # are internal-only (lib/includes.h), not in radcli.map.
  avp_legacy = executable('avp-legacy', 'avp-legacy.c',
    include_directories: tests_incdirs, link_with: libradcli_static,
    dependencies: [gnutls_dep, nettle_dep], install: false)
  # FreeRADIUS interoperability check (tests/avp-codec-freeradius-tests.sh,
  # needs root + a real radiusd/freeradius binary; not run by "meson test"
  # directly). Needs ../lib for rc-crypto.h (rc_md5_calc, to verify the reply's
  # Response Authenticator); links libradcli_static for the same
  # non-exported radcli_avp_decode()/_encode() reason as avp_codec above.
  avp_codec_freeradius = executable('avp-codec-freeradius', 'avp-codec-freeradius.c',
    include_directories: tests_incdirs + [include_directories('../lib')],
    link_with: libradcli_static,
    dependencies: [gnutls_dep, nettle_dep], install: false)
  # FreeRADIUS interoperability check for radcli2.h's request/reply entry
  # point (tests/request-freeradius-tests.sh), same needs as avp_codec_freeradius
  # above. Links libradcli_shared: radcli_request_*() are public, exported API.
  request_freeradius = executable('request-freeradius', 'request-freeradius.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  # Multiplexed poll-driven request/reply check (tests/request-poll-multi-tests.sh)
  # against tests/radius-server.py -- unlike request_freeradius above, needs
  # no root/FreeRADIUS, so it takes server_ip/port/secret from argv instead
  # of ns.sh. Public radcli2.h API only.
  request_poll_multi = executable('request-poll-multi', 'request-poll-multi.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  # DAE-over-RadSec concurrency stress test (tests/dae-radsec-stress-tests.sh),
  # takes argv (port, tls-ca-file) from that script rather than running
  # standalone, so it is not added to the no-argument foreach loop below.
  # Public radcli2.h API only (radcli_aaa()/radcli_dae_*()), same as `dae`.
  dae_radsec_stress = executable('dae-radsec-stress', 'dae-radsec-stress.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  # DAE-over-RadSec dispatch-must-not-block test
  # (tests/dae-radsec-backpressure-tests.sh), same argv/build shape as
  # dae_radsec_stress above.
  dae_radsec_backpressure = executable('dae-radsec-backpressure', 'dae-radsec-backpressure.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  # DAE-over-RadSec connection-liveness test (tests/dae-radsec-watchdog-
  # tests.sh, peer: tests/dae-watchdog-server.py), same argv/build shape as
  # dae_radsec_stress/dae_radsec_backpressure above.
  dae_radsec_watchdog = executable('dae-radsec-watchdog', 'dae-radsec-watchdog.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  # RFC 3539 SS3.4 watchdog behavior driven purely by ordinary AAA traffic
  # (tests/watchdog-aaa-tests.sh, peer: tests/watchdog-aaa-server.py) -- no
  # radcli_dae_*() call anywhere in tests/watchdog-aaa.c, same argv/build
  # shape as dae_radsec_watchdog above.
  watchdog_aaa = executable('watchdog-aaa', 'watchdog-aaa.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  # Dedicated reproducer for radcli_encode_request()'s TLS-secret bug
  # (tests/request-tls-secret-tests.sh, peer: tests/request-tls-secret-
  # server.py), same argv/build shape as dae_radsec_watchdog above.
  request_tls_secret = executable('request-tls-secret', 'request-tls-secret.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  config_unit = executable('config-unit', 'config-unit.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  ctx_unit = executable('ctx', 'ctx.c',
    include_directories: tests_incdirs, link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs, install: false)
  # radcli_ctx_dispatch()'s validation pipeline over a real loopback UDP
  # socket. Needs ../lib for rc-crypto.h (rc_md5_calc(), to build/verify wire
  # authenticators) and libradcli_static for the same internal-only
  # add_msg_auth_attr()/radcli_avp_encode() reason as avp_codec_freeradius.
  dae_codec = executable('dae-codec', 'dae-codec.c',
    include_directories: tests_incdirs + [include_directories('../lib')],
    link_with: libradcli_static,
    dependencies: [gnutls_dep, nettle_dep], install: false)

  foreach t : [avpair, dict, dict_legacy, avp, request, aaa2_unit, dict_add, auth_userpass_len, dae, dae_codec, pack, avp_codec, avp_legacy, config_unit, ctx_unit]
    test(t.name(), t, env: test_env)
  endforeach
endif

foreach t : shell_tests
  test(t, find_program(t), env: test_env, timeout: 300,
       workdir: meson.current_source_dir())
endforeach
