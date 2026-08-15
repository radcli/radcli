etc_conf = configuration_data()
etc_conf.set('sbindir', get_option('prefix') / get_option('sbindir'))
etc_conf.set('pkgsysconfdir', pkgsysconfdir_abs)
etc_conf.set('sharedir', get_option('prefix') / get_option('datadir') / meson.project_name())

foreach f : ['radiusclient.conf', 'radiusclient-tls.conf']
  configure_file(
    input: f + '.in', output: f, configuration: etc_conf,
    install: true, install_dir: pkgsysconfdir,
  )
endforeach

install_data('dictionary', install_dir: get_option('datadir') / meson.project_name())

install_data('servers', 'servers-tls',
  install_dir: pkgsysconfdir, install_mode: 'rw-------')
