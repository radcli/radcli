#!/usr/bin/perl -w
# Generates radcli.h.3 from the public header and doxygen XML files.
# Replaces the doxygen 1.14.0-incompatible approach of running doxy2man on
# radcli_8h.xml, where grouped members no longer appear as memberdef entries.
#
# Usage: gen-radcli-h-man.pl PUBLIC_HEADER RADCLI_MAP FILE_XML GROUP_XML [GROUP_XML ...]
#
# Only functions present in both PUBLIC_HEADER and RADCLI_MAP are included.
# rc_mksid and rc_setdebug are excluded from the overview (they get their own
# pages via the radcli_8h.xml doxy2man pass).
# Struct definitions are extracted from FILE_XML's <innerclass> refs, filtered
# to structs declared in PUBLIC_HEADER.
#
# Copyright (C) 2026 Nikos Mavrogiannopoulos
# BSD 2-Clause License

use strict;
use POSIX qw(strftime);
use File::Basename qw(dirname);

my $header    = shift @ARGV or die "Usage: $0 PUBLIC_HEADER RADCLI_MAP FILE_XML GROUP_XML...\n";
my $map_file  = shift @ARGV or die "Usage: $0 PUBLIC_HEADER RADCLI_MAP FILE_XML GROUP_XML...\n";
my $file_xml  = shift @ARGV or die "Usage: $0 PUBLIC_HEADER RADCLI_MAP FILE_XML GROUP_XML...\n";
my @group_xmls = @ARGV      or die "Usage: $0 PUBLIC_HEADER RADCLI_MAP FILE_XML GROUP_XML...\n";

my $xml_dir = dirname($file_xml);

# Functions intentionally omitted from the radcli.h summary page.
my %exclude = map { $_ => 1 } qw(rc_mksid rc_setdebug);

# --- Build export allowlist: intersection of radcli.h and radcli.map ---

open my $hfh, '<', $header or die "Cannot open $header: $!\n";
my $header_text = do { local $/; <$hfh> };
close $hfh;

my %in_header;
while ($header_text =~ /\b(rc_[a-z_0-9]+)\s*\(/g) {
    $in_header{$1} = 1;
}

my %in_map;
open my $mfh, '<', $map_file or die "Cannot open $map_file: $!\n";
while (<$mfh>) {
    $in_map{$1} = 1 if /^\s+(rc_[a-z_0-9]+);/;
}
close $mfh;

my %public;
for my $name (keys %in_header) {
    $public{$name} = 1 if $in_map{$name} && !$exclude{$name};
}

# --- Helpers ---

sub strip_tags {
    my $s = shift;
    $s =~ s/<[^>]+>//g;
    $s =~ s/\s+/ /g;
    $s =~ s/^\s+|\s+$//g;
    return $s;
}

sub strip_para {
    my $s = shift;
    $s =~ s{<para>(.*?)</para>}{$1}gs;
    return strip_tags($s);
}

# --- Extract function prototypes from group XML files ---

my %functions;
for my $xml_file (@group_xmls) {
    open my $fh, '<', $xml_file or die "Cannot open $xml_file: $!\n";
    my $xml = do { local $/; <$fh> };
    close $fh;

    while ($xml =~ m{<memberdef\s+kind="function"[^>]*>(.*?)</memberdef>}gs) {
        my $block = $1;
        my ($ret_raw) = $block =~ m{<type>(.*?)</type>}s or next;
        my $ret = strip_tags($ret_raw);
        my ($name) = $block =~ m{<name>([^<]+)</name>} or next;
        $name =~ s/\s//g;
        next unless $public{$name};
        next if $functions{$name};    # first XML wins on duplicates
        my @params;
        while ($block =~ m{<param>(.*?)</param>}gs) {
            my ($t) = $1 =~ m{<type>(.*?)</type>}s or next;
            push @params, strip_tags($t);
        }
        $functions{$name} = { ret => $ret, params => \@params };
    }
}

my @sorted_funcs = sort keys %functions;

# Format a function synopsis line with 15-char type column.
# Pointer returns attach * directly before the name.
sub proto {
    my ($ret, $name, $params_ref) = @_;
    my $args = @$params_ref ? join(', ', @$params_ref) : 'void';
    if ($ret =~ s/\s*(\*+)\s*$//) {
        my $stars = $1;
        return sprintf("%-14s%s%s(%s);", $ret, $stars, $name, $args);
    }
    return sprintf("%-14s %s(%s);", $ret, $name, $args);
}

# --- Extract struct definitions from FILE_XML <innerclass> refs ---

open my $ffh, '<', $file_xml or die "Cannot open $file_xml: $!\n";
my $file_xml_text = do { local $/; <$ffh> };
close $ffh;

my @struct_sections;

while ($file_xml_text =~ m{<innerclass\s+refid="(struct[^"]+)"[^>]*>([^<]+)</innerclass>}g) {
    my ($refid, $sname) = ($1, $2);
    $sname =~ s/\s//g;

    # Only include structs explicitly tagged with /** \struct NAME */ in the
    # public header. This excludes opaque internal types (dict_attr etc.)
    # while including the publicly documented ones (server, send_data,
    # rc_value_pair).
    next unless $header_text =~ /\\struct\s+\Q$sname\E\b/;

    my $struct_xml_file = "$xml_dir/$refid.xml";
    next unless -f $struct_xml_file;

    open my $sfh, '<', $struct_xml_file or next;
    my $sxml = do { local $/; <$sfh> };
    close $sfh;

    # Extract detailed description (used as a lead-in paragraph).
    my $detail = '';
    if ($sxml =~ m{<detaileddescription>\s*(.*?)\s*</detaileddescription>}s) {
        $detail = strip_para($1);
    }

    # Extract public-attrib fields in document order.
    my @fields;
    while ($sxml =~ m{<memberdef\s+kind="variable"[^>]*>(.*?)</memberdef>}gs) {
        my $blk = $1;
        my ($ftype_raw) = $blk =~ m{<type>(.*?)</type>}s or next;
        my $ftype = strip_tags($ftype_raw);
        my ($fname) = $blk =~ m{<name>([^<]+)</name>} or next;
        $fname =~ s/\s//g;
        my ($fdims) = $blk =~ m{<argsstring>([^<]*)</argsstring>};
        $fdims //= '';
        my $fbrief = '';
        if ($blk =~ m{<briefdescription>\s*(.*?)\s*</briefdescription>}s) {
            $fbrief = strip_para($1);
        }
        push @fields, { type => $ftype, name => $fname, dims => $fdims, brief => $fbrief };
    }

    push @struct_sections, { name => $sname, detail => $detail, fields => \@fields };
}

# Format struct body with dynamic column widths matching the old doxy2man style.
# Type column width = max(full type length) + 1; pointer * is part of that column.
# Comment column = max(name + dims + ";") + 1 space, then "// brief".
sub format_struct_lines {
    my ($sname, $fields_ref) = @_;
    my @fields = @$fields_ref;

    my $max_type  = 1;
    my $max_named = 1;
    for my $f (@fields) {
        $max_type  = length($f->{type}) if length($f->{type}) > $max_type;
        my $nd = length($f->{name}) + length($f->{dims}) + 1;  # +1 for ;
        $max_named = $nd if $nd > $max_named;
    }
    my $col = $max_type + 1;

    my @lines = ("struct $sname \{");
    for my $f (@fields) {
        my ($t, $n, $d, $b) = @{$f}{qw(type name dims brief)};
        my $line;
        if ($t =~ s/\s*(\*+)\s*$//) {
            my $stars = $1;
            $line = sprintf("  %-*s%s\\fI%s\\fP%s;", $col - 1, $t, $stars, $n, $d);
        } else {
            $line = sprintf("  %-*s\\fI%s\\fP%s;", $col, $t, $n, $d);
        }
        if ($b) {
            my $nd  = length($n) + length($d) + 1;
            my $pad = $max_named - $nd + 1;
            $pad = 1 if $pad < 1;
            $line .= ' ' x $pad . "// $b ";
        }
        push @lines, $line;
    }
    push @lines, "};";
    return @lines;
}

# --- Emit the man page ---

my $date  = strftime("%Y-%m-%d", localtime);
my $dlong = strftime("%a %b %e %Y", localtime);
$dlong =~ s/  / /g;

print ".\\\" File automatically generated by gen-radcli-h-man.pl\n";
print ".\\\" Generation date: $dlong\n";
print ".TH radcli.h 3 $date \"radcli\" \"Radius client library\"\n";
print ".SH \"NAME\"\n";
print "radcli.h \\- \n";
print ".SH SYNOPSIS\n";
print ".nf\n";
print ".B #include <radcli/radcli.h>\n";
print ".fi\n";
print ".SH DESCRIPTION\n";
print ".PP\n";
print ".sp\n";
print ".RS\n";
print ".nf\n";
print "\\fB\n";

for my $name (@sorted_funcs) {
    my $f = $functions{$name};
    print proto($f->{ret}, $name, $f->{params}) . "\n";
}

print "\\fP\n";
print ".fi\n";
print ".RE\n";

for my $s (@struct_sections) {
    my @body = format_struct_lines($s->{name}, $s->{fields});
    print ".SS \"\"\n";
    print ".PP\n";
    print ".sp\n";
    if ($s->{detail}) {
        print ".PP \n$s->{detail} \n";
    }
    print ".sp\n";
    print ".RS\n";
    print ".nf\n";
    print "\\fB\n";
    print "$_\n" for @body;
    print "\\fP\n";
    print ".fi\n";
    print ".RE\n";
}

print ".SH SEE ALSO\n";
print ".PP\n";
print ".nh\n";
print ".ad l\n";
print join(', ', map { "\\fI$_\\fP(3)" } @sorted_funcs) . "\n";
print ".ad\n";
print ".hy\n";
