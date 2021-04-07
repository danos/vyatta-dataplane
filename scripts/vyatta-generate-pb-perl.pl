#! /usr/bin/perl

use warnings;
use strict;

use Carp;

use MIME::Base64;
use Google::ProtocolBuffers;

my @arg0 = split(/\//, $ARGV[0]);
my $proto_dir = $arg0[$#arg0 - 1];
my $proto_file = $arg0[$#arg0];

my $target_dir = $ARGV[1];

if (substr($proto_file, -6) eq ".proto") {

    my %options;
    $options{include_dir} = "../$proto_dir";

    my $pb_pm = substr($proto_file, 0, length($proto_file) - 6) . ".pm";
    $options{generate_code} = $target_dir . "/$pb_pm";

    printf("writing out to: " . $target_dir . "/$pb_pm" . "\n");

    $options{create_accessors} = 1;
    $options{follow_best_practice} = 1;
    Google::ProtocolBuffers->parsefile($ARGV[0], \%options);
}

exit 0;
