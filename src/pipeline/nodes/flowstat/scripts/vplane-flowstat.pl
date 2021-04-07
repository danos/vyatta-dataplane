#!/usr/bin/perl
# Module: vplane-flowstat.pl
#
# **** License ****
#
# Copyright (c) 2021, SafePoint.
# Copyright (c) 2019, AT&T Intellectual Property.
# Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-only
#
# **** End License ****


use strict;
use warnings;
use lib '/opt/vyatta/share/perl5';
use Getopt::Long;
use Vyatta::Config;
use Vyatta::VPlaned;

use vyatta::proto::FlowStatFeatConfig;

#
# main
#
my ( $cmd, $intf, $enable ) = ("", "", "");

GetOptions(
    "cmd=s" => \$cmd,
    "intf=s"  => \$intf,
    "enable=s"  => \$enable,
);

sub config_dataplane_flowstat {
    my $cstore = new Vyatta::VPlaned;

    my $is_active = $enable eq 'true' ? 1 : 0;

    my $config = FlowStatFeatConfig->new({
        is_active  => $is_active,
        if_name => $intf
    });

    $cstore->store_pb(
        "interface dataplane flowstat $intf enable",
        $config,
        "fstat:fstat-feat");
}

sub config_global_flowstat {
    my $cstore = new Vyatta::VPlaned;

    my $is_active = $enable eq 'true' ? 1 : 0;

    my $config = FlowStatFeatConfig->new({
        is_active  => $is_active,
        if_name => ""
    });

    $cstore->store_pb(
        "service flowstat disable",
        $config,
        "fstat:fstat-feat");
}

if ($cmd eq "cfg_global") {
    config_global_flowstat();
} else {
    config_dataplane_flowstat();
}
