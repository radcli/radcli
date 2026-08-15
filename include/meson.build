install_headers('radcli/radcli.h', subdir: 'radcli')

if get_option('legacy-compat')
  install_headers('freeradius-client.h', 'radiusclient-ng.h')
endif

include_dirs = include_directories('.')

subdir('radcli')
