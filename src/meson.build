src_cargs = [
  '-DRC_CONFIG_FILE="' + pkgsysconfdir_abs + '/radcli.conf"',
  '-DRC_SECURE_PATH="' + get_option('secure-path') + '"',
]
src_incdirs = [config_inc, include_dirs]

foreach prog : ['radstatus', 'radacct', 'radexample', 'radiusclient', 'radembedded', 'radembedded_dict']
  executable(prog, prog + '.c',
    include_directories: src_incdirs,
    c_args: src_cargs,
    link_with: libradcli_shared,
    dependencies: link_libs,
    install: false,
  )
endforeach
