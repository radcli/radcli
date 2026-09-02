src_cargs = [
  '-DRC_CONFIG_FILE="' + pkgsysconfdir_abs + '/radcli.conf"',
  '-DRC_SECURE_PATH="' + get_option('secure-path') + '"',
]
src_incdirs = [config_inc, include_dirs, include_directories('../lib')]

# radexample.c and radexample-async-dae.c use radcli2.h only, so they link
# libradcli2 alone -- everything else here still uses radcli.h and links
# libradcli, which itself depends on libradcli2 transitively.
foreach prog2 : ['radexample', 'radexample-async-dae']
  executable(prog2, prog2 + '.c',
    include_directories: src_incdirs,
    c_args: src_cargs,
    link_with: libradcli2_shared,
    dependencies: link_libs,
    install: false,
  )
endforeach

foreach prog : ['radiusclient', 'radembedded', 'radembedded_dict', 'raddaeserver']
  executable(prog, prog + '.c',
    include_directories: src_incdirs,
    c_args: src_cargs,
    # Both, not libradcli_shared alone: libradcli.so.10 only re-exports
    # radcli.h's own rc_* names as its own symbols, so a program (like
    # raddaeserver.c) that also calls a radcli2.h function directly needs
    # libradcli2 on its own link line too -- linking only libradcli.so
    # and relying on it transitively pulling in libradcli2.so does not
    # make libradcli2's symbols resolvable to *this* executable's own
    # undefined references under -Wl,--no-undefined/--as-needed.
    link_with: [libradcli_shared, libradcli2_shared],
    dependencies: link_libs,
    install: false,
  )
endforeach
