#!/usr/bin/awk -f
# gen-dict.awk: generates a C string literal from a RADIUS dictionary file.
# Usage: awk -f gen-dict.awk etc/dictionary > lib/dict_rfc_gen.h
#
# $INCLUDE directives are stripped — the embedded dictionary is self-contained.

BEGIN {
    print "/* Generated from etc/dictionary by gen-dict.awk — do not edit */"
    print "static const char rc_rfc_dictionary[] ="
}

/^\$INCLUDE/ { next }

{
    gsub(/\\/, "\\\\")
    gsub(/"/, "\\\"")
    printf "    \"%s\\n\"\n", $0
}

END {
    print "    ;"
}
