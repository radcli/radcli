version_parts = meson.project_version().split('.')

number_version = run_command(
  'printf', '0x%02x%02x%02x', version_parts[0], version_parts[1], version_parts[2],
  check: true,
).stdout().strip()

version_conf = configuration_data()
version_conf.set('VERSION', meson.project_version())
version_conf.set('MAJOR_VERSION', version_parts[0])
version_conf.set('MINOR_VERSION', version_parts[1])
version_conf.set('PATCH_VERSION', version_parts[2])
version_conf.set('NUMBER_VERSION', number_version)

version_h = configure_file(
  input: 'version.h.in',
  output: 'version.h',
  configuration: version_conf,
  install: true,
  install_dir: get_option('includedir') / 'radcli',
)
