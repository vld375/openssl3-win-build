#!/usr/bin/perl
use strict;
use warnings;

my $objects_txt = $ARGV[0] // "crypto/objects/objects.txt";
my $start_nid = $ARGV[1] // 1500;

my @entries;
my %aliases;
my $nid = $start_nid;

open(my $fh, "<", $objects_txt) or die "Cannot open $objects_txt: $!";
while (<$fh>) {
    chomp;
    next if /^\s*#/ || /^\s*$/;
    if (/^!Alias\s+(\S+)\s+(.+)$/) {
        $aliases{$1} = $2;
        next;
    }
    if (/^(\S+)\s+(.+?)\s*:\s*(\S+)\s*:\s*(.+)$/) {
        my ($a, $suf, $sn, $ln) = ($1, $2, $3, $4);
        my $oid = $aliases{$a} . " " . $suf;
        $oid =~ s/\s+/./g;
        push @entries, { sn => $sn, ln => $ln, nid => $nid++, oid => $oid };
    }
}
close $fh;

# Create directories if needed
mkdir "crypto/objects" unless -d "crypto/objects";
mkdir "include/openssl" unless -d "include/openssl";

# obj_mac.num
open(my $num, ">", "crypto/objects/obj_mac.num") or die;
print $num "# Generated\n";
print $num "$_->{sn} $_->{nid}\n" for @entries;
close $num;

# obj_mac.h
open(my $h, ">", "include/openssl/obj_mac.h") or die;
print $h "/* Generated */\n\n";
for (@entries) {
    (my $m = $_->{sn}) =~ s/-/_/g;
    print $h "#define NID_$m $_->{nid}\n";
}
close $h;

# OID encoder
sub encode_oid {
    my @p = split /\./, $_[0];
    die "OID must have at least 2 arcs" unless @p >= 2;
    my @b = ($p[0] * 40 + $p[1]);
    for my $i (2 .. $#p) {
        my $v = $p[$i];
        my @e;
        do {
            push @e, ($v & 0x7f) | 0x80;
            $v >>= 7;
        } while ($v >= 128);
        push @e, $v;
        $e[0] &= 0x7f if @e;
        push @b, @e;
    }
    return \@b;
}

my %oid_data;
for my $e (@entries) {
    my $oid = $e->{oid};
    $oid_data{$oid} //= encode_oid($oid);
}

my @oid_keys = keys %oid_data;

# obj_dat.h
open(my $d, ">", "crypto/objects/obj_dat.h") or die;
print $d "/* Auto-generated */\n";
print $d "#include <openssl/objects.h>\n\n";

print $d "static const unsigned char lvalues[][9] = {\n";
for my $oid (@oid_keys) {
    my $bytes = $oid_data{$oid};
    my $hex = join(", ", map { sprintf "0x%02x", $_ } @$bytes);
    print $d "    { $hex },\n";
}
print $d "};\n\n";

print $d "static const ASN1_OBJECT nid_objs[" . @entries . "] = {\n";
for my $e (@entries) {
    my ($idx) = grep { $oid_keys[$_] eq $e->{oid} } 0..$#oid_keys;
    (my $m = $e->{sn}) =~ s/-/_/g;
    printf $d "    {\"%s\", \"%s\", NID_%s, %d, lvalues[%d]},\n",
        $e->{sn}, $e->{ln}, $m, scalar(@{$oid_data{$e->{oid}}}), $idx;
}
print $d "};\n\n";

print $d "static const int sn_objs[1] = {0};\n";
print $d "static const int ln_objs[1] = {0};\n";
print $d "static const int obj_objs[1] = {0};\n";
print $d "\n#define NUM_NID " . @entries . "\n";
print $d "#define NUM_SN 0\n";
print $d "#define NUM_LN 0\n";
print $d "#define NUM_OBJ 0\n";

close $d;

print "✅ Generated obj_mac.num, obj_mac.h, obj_dat.h\n";