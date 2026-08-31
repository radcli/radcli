#!/usr/bin/perl -w
# Post-processes doxy2man-generated man pages to clean up SEE ALSO sections:
#   - removes empty \fI\fP(3) entries (doxy2man bug with unnamed memberdefs)
#   - removes entries for non-exported symbols (not in PUBLIC_HEADER AND MAP_FILE)
#   - removes the page's own function from its own SEE ALSO list
#   - falls back to "HEADER.h(3)" when the filtered list is empty
#
# Used for both radcli.h (rc_* symbols) and radcli2.h (radcli_* symbols).
#
# Usage: fix-seealso.pl PUBLIC_HEADER MAP_FILE MAN_DIR/
#
# Copyright (C) 2026 Nikos Mavrogiannopoulos
# BSD 2-Clause License

use strict;
use File::Basename qw(basename);

my $header   = shift @ARGV or die "Usage: $0 PUBLIC_HEADER MAP_FILE MAN_DIR\n";
my $map_file = shift @ARGV or die "Usage: $0 PUBLIC_HEADER MAP_FILE MAN_DIR\n";
my $man_dir  = shift @ARGV or die "Usage: $0 PUBLIC_HEADER MAP_FILE MAN_DIR\n";

my $header_base = basename($header);

# --- Build export allowlist (PUBLIC_HEADER ∩ MAP_FILE) ---
# rc_mksid and rc_setdebug are valid SEE ALSO targets even though they are
# excluded from the radcli.h.3 overview synopsis.

my %in_header;
open my $hfh, '<', $header or die "Cannot open $header: $!\n";
while (<$hfh>) {
    next if /^\s*[#\/\*]/;
    while (/\b((?:rc_|radcli_)[a-z_0-9]+)\s*\(/g) { $in_header{$1} = 1 }
}
close $hfh;

my %in_map;
open my $mfh, '<', $map_file or die "Cannot open $map_file: $!\n";
while (<$mfh>) {
    $in_map{$1} = 1 if /^\s+((?:rc_|radcli_)[a-z_0-9]+);/;
}
close $mfh;

my %exported = map { $_ => 1 } grep { $in_map{$_} } keys %in_header;

# --- Process each man page ---

opendir my $dh, $man_dir or die "Cannot open $man_dir: $!\n";
my @pages = sort map { "$man_dir/$_" } grep { /\.3$/ } readdir $dh;
closedir $dh;

for my $page (@pages) {
    open my $fh, '<', $page or next;
    my @lines = <$fh>;
    close $fh;

    # Determine page's own name from the .TH line.
    my $own = '';
    for my $l (@lines) {
        if ($l =~ /^\.TH\s+(\S+)/) { $own = $1; last }
    }

    my $changed = 0;
    for my $i (0 .. $#lines) {
        next unless $lines[$i] =~ /^\.SH SEE ALSO/;

        # Find the data line containing \fI entries (within 5 lines).
        my $data_idx;
        for my $j ($i + 1 .. $i + 5) {
            last if $j > $#lines;
            if ($lines[$j] =~ /\\fI/) { $data_idx = $j; last }
        }
        next unless defined $data_idx;

        my $data = $lines[$data_idx];
        chomp $data;

        # Parse and filter entries.
        my @kept;
        for my $entry (split /,\s*/, $data) {
            next unless $entry =~ /\\fI([^\\]*)\\fP\(3\)/;
            my $name = $1;
            next if $name eq '';          # empty \fI\fP(3)
            next if $name eq $own;        # self-reference
            # Keep only names in the export allowlist; all others (internal
            # functions, TLS internals, strappend, set_option_*, etc.) are dropped.
            next unless $exported{$name};
            push @kept, "\\fI${name}\\fP(3)";
        }

        my $new_data = @kept ? join(', ', @kept) . "\n" : "$header_base(3)\n";

        if ($new_data ne $lines[$data_idx]) {
            $lines[$data_idx] = $new_data;
            $changed = 1;
        }
        last;
    }

    if ($changed) {
        open my $out, '>', $page or die "Cannot write $page: $!\n";
        print $out @lines;
        close $out;
    }
}
