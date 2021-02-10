# Module Vplane.pm

# Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
# Copyright (c) 2015-2016, Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only
#
# This modules provides routines to identify supported adpaters.

package Vyatta::Vplane;

use strict;
use warnings;
require Exporter;

our @ISA    = qw(Exporter);
our @EXPORT = qw(is_supported_device is_supported_ib_device is_supported_pci_device);

# List of supported PCI device Id's generated from rte_pci_dev_ids.h in DPDK
my @pci_devices = (

    # Intel E1000
    { vendor => 0x8086, device => 0x100e },
    { vendor => 0x8086, device => 0x100f },
    { vendor => 0x8086, device => 0x1011 },
    { vendor => 0x8086, device => 0x1010 },
    { vendor => 0x8086, device => 0x1012 },
    { vendor => 0x8086, device => 0x101d },
    { vendor => 0x8086, device => 0x105e },
    { vendor => 0x8086, device => 0x105f },
    { vendor => 0x8086, device => 0x1060 },
    { vendor => 0x8086, device => 0x10d9 },
    { vendor => 0x8086, device => 0x10da },
    { vendor => 0x8086, device => 0x10a4 },
    { vendor => 0x8086, device => 0x10d5 },
    { vendor => 0x8086, device => 0x10a5 },
    { vendor => 0x8086, device => 0x10bc },
    { vendor => 0x8086, device => 0x107d },
    { vendor => 0x8086, device => 0x107e },
    { vendor => 0x8086, device => 0x107f },
    { vendor => 0x8086, device => 0x10b9 },
    { vendor => 0x8086, device => 0x109a },
    { vendor => 0x8086, device => 0x10d3 },
    { vendor => 0x8086, device => 0x10f6 },
    { vendor => 0x8086, device => 0x150c },
    { vendor => 0x8086, device => 0x153a },
    { vendor => 0x8086, device => 0x153b },
    { vendor => 0x8086, device => 0x155a },
    { vendor => 0x8086, device => 0x1559 },
    { vendor => 0x8086, device => 0x15a0 },
    { vendor => 0x8086, device => 0x15a1 },
    { vendor => 0x8086, device => 0x15a2 },
    { vendor => 0x8086, device => 0x15a3 },

    # Intel IGB
    { vendor => 0x8086, device => 0x10c9 },
    { vendor => 0x8086, device => 0x10e6 },
    { vendor => 0x8086, device => 0x10e7 },
    { vendor => 0x8086, device => 0x10e8 },
    { vendor => 0x8086, device => 0x1526 },
    { vendor => 0x8086, device => 0x150a },
    { vendor => 0x8086, device => 0x1518 },
    { vendor => 0x8086, device => 0x150d },
    { vendor => 0x8086, device => 0x10a7 },
    { vendor => 0x8086, device => 0x10a9 },
    { vendor => 0x8086, device => 0x10d6 },
    { vendor => 0x8086, device => 0x150e },
    { vendor => 0x8086, device => 0x150f },
    { vendor => 0x8086, device => 0x1510 },
    { vendor => 0x8086, device => 0x1511 },
    { vendor => 0x8086, device => 0x1516 },
    { vendor => 0x8086, device => 0x1527 },
    { vendor => 0x8086, device => 0x1521 },
    { vendor => 0x8086, device => 0x1522 },
    { vendor => 0x8086, device => 0x1523 },
    { vendor => 0x8086, device => 0x1524 },
    { vendor => 0x8086, device => 0x1546 },
    { vendor => 0x8086, device => 0x1533 },
    { vendor => 0x8086, device => 0x1534 },
    { vendor => 0x8086, device => 0x1535 },
    { vendor => 0x8086, device => 0x1536 },
    { vendor => 0x8086, device => 0x1537 },
    { vendor => 0x8086, device => 0x1538 },
    { vendor => 0x8086, device => 0x1539 },
    { vendor => 0x8086, device => 0x1f40 },
    { vendor => 0x8086, device => 0x1f41 },
    { vendor => 0x8086, device => 0x1f45 },
    { vendor => 0x8086, device => 0x0438 },
    { vendor => 0x8086, device => 0x043a },
    { vendor => 0x8086, device => 0x043c },
    { vendor => 0x8086, device => 0x0440 },

    # Intel IXGBE
    { vendor => 0x8086, device => 0x10b6 },
    { vendor => 0x8086, device => 0x1508 },
    { vendor => 0x8086, device => 0x10c6 },
    { vendor => 0x8086, device => 0x10c7 },
    { vendor => 0x8086, device => 0x10c8 },
    { vendor => 0x8086, device => 0x150b },
    { vendor => 0x8086, device => 0x10db },
    { vendor => 0x8086, device => 0x10dd },
    { vendor => 0x8086, device => 0x10ec },
    { vendor => 0x8086, device => 0x10f1 },
    { vendor => 0x8086, device => 0x10e1 },
    { vendor => 0x8086, device => 0x10f4 },
    { vendor => 0x8086, device => 0x10f7 },
    { vendor => 0x8086, device => 0x1514 },
    { vendor => 0x8086, device => 0x1517 },
    { vendor => 0x8086, device => 0x10f8 },
    { vendor => 0x8086, device => 0x000c },
    { vendor => 0x8086, device => 0x10f9 },
    { vendor => 0x8086, device => 0x10fb },
    { vendor => 0x8086, device => 0x11a9 },
    { vendor => 0x8086, device => 0x1f72 },
    { vendor => 0x8086, device => 0x17d0 },
    { vendor => 0x8086, device => 0x0470 },
    { vendor => 0x8086, device => 0x152a },
    { vendor => 0x8086, device => 0x1529 },
    { vendor => 0x8086, device => 0x1507 },
    { vendor => 0x8086, device => 0x154d },
    { vendor => 0x8086, device => 0x154a },
    { vendor => 0x8086, device => 0x1558 },
    { vendor => 0x8086, device => 0x1557 },
    { vendor => 0x8086, device => 0x10fc },
    { vendor => 0x8086, device => 0x151c },
    { vendor => 0x8086, device => 0x154f },
    { vendor => 0x8086, device => 0x1528 },
    { vendor => 0x8086, device => 0x1560 },
    { vendor => 0x8086, device => 0x15ac },
    { vendor => 0x8086, device => 0x15ad },
    { vendor => 0x8086, device => 0x15ae },
    { vendor => 0x8086, device => 0x1563 },
    { vendor => 0x8086, device => 0x15aa },
    { vendor => 0x8086, device => 0x15ab },
    { vendor => 0x8086, device => 0x15b4 },
    { vendor => 0x8086, device => 0x15c2 },
    { vendor => 0x8086, device => 0x15c3 },
    { vendor => 0x8086, device => 0x15c4 },
    { vendor => 0x8086, device => 0x15c5 },
    { vendor => 0x8086, device => 0x15c6 },
    { vendor => 0x8086, device => 0x15c7 },
    { vendor => 0x8086, device => 0x15c8 },
    { vendor => 0x8086, device => 0x15ca },
    { vendor => 0x8086, device => 0x15cc },
    { vendor => 0x8086, device => 0x15ce },
    { vendor => 0x8086, device => 0x15e4 },
    { vendor => 0x8086, device => 0x15e5 },

    # Intel I40E (Fortville)
    { vendor => 0x8086, device => 0x1572 },
    { vendor => 0x8086, device => 0x1574 },
    { vendor => 0x8086, device => 0x157f },
    { vendor => 0x8086, device => 0x1580 },
    { vendor => 0x8086, device => 0x1581 },
    { vendor => 0x8086, device => 0x1583 },
    { vendor => 0x8086, device => 0x1584 },
    { vendor => 0x8086, device => 0x1585 },
    { vendor => 0x8086, device => 0x1586 },
    { vendor => 0x8086, device => 0x1587 },
    { vendor => 0x8086, device => 0x1588 },
    { vendor => 0x8086, device => 0x1589 },
    { vendor => 0x8086, device => 0x158a },
    { vendor => 0x8086, device => 0x158b },
    { vendor => 0x8086, device => 0x374c },
    { vendor => 0x8086, device => 0x37ce },
    { vendor => 0x8086, device => 0x37d0 },
    { vendor => 0x8086, device => 0x37d1 },
    { vendor => 0x8086, device => 0x37d2 },
    { vendor => 0x8086, device => 0x37d3 },

    # Intel FM10K (Red Rock Canyon)
    { vendor => 0x8086, device => 0x15a4 },
    { vendor => 0x8086, device => 0x15d0 },

    # Intel IGB VF
    { vendor => 0x8086, device => 0x10ca },
    { vendor => 0x8086, device => 0x152d },
    { vendor => 0x8086, device => 0x1520 },
    { vendor => 0x8086, device => 0x152f },

    # Intel IXGBE VF
    { vendor => 0x8086, device => 0x10ed },
    { vendor => 0x8086, device => 0x152e },
    { vendor => 0x8086, device => 0x1515 },
    { vendor => 0x8086, device => 0x1530 },
    { vendor => 0x8086, device => 0x1564 },
    { vendor => 0x8086, device => 0x1565 },
    { vendor => 0x8086, device => 0x15a8 },
    { vendor => 0x8086, device => 0x15a9 },

    # Intel I40E VF
    { vendor => 0x8086, device => 0x154c },
    { vendor => 0x8086, device => 0x1571 },
    { vendor => 0x8086, device => 0x37cd },
    { vendor => 0x8086, device => 0x37d9 },

    # Intel FM10K VF
    { vendor => 0x8086, device => 0x15a5 },

    # Broadcom/Qlogic BNX2X
    { vendor => 0x14e4, device => 0x168a },
    { vendor => 0x14e4, device => 0x16a9 },
    { vendor => 0x14e4, device => 0x164f },
    { vendor => 0x14e4, device => 0x168e },
    { vendor => 0x14e4, device => 0x16af },
    { vendor => 0x14e4, device => 0x163d },
    { vendor => 0x14e4, device => 0x163f },
    { vendor => 0x14e4, device => 0x168d },
    { vendor => 0x14e4, device => 0x16a1 },
    { vendor => 0x14e4, device => 0x16a2 },
    { vendor => 0x14e4, device => 0x16ad },

    # Broadcom BNXT
    { vendor => 0x14e4, device => 0x1614 },
    { vendor => 0x14e4, device => 0x16c1 },
    { vendor => 0x14e4, device => 0x16c8 },
    { vendor => 0x14e4, device => 0x16c9 },
    { vendor => 0x14e4, device => 0x16ca },
    { vendor => 0x14e4, device => 0x16cb },
    { vendor => 0x14e4, device => 0x16cc },
    { vendor => 0x14e4, device => 0x16cd },
    { vendor => 0x14e4, device => 0x16ce },
    { vendor => 0x14e4, device => 0x16cf },
    { vendor => 0x14e4, device => 0x16d0 },
    { vendor => 0x14e4, device => 0x16d1 },
    { vendor => 0x14e4, device => 0x16d2 },
    { vendor => 0x14e4, device => 0x16d3 },
    { vendor => 0x14e4, device => 0x16d4 },
    { vendor => 0x14e4, device => 0x16d5 },
    { vendor => 0x14e4, device => 0x16d6 },
    { vendor => 0x14e4, device => 0x16d7 },
    { vendor => 0x14e4, device => 0x16d8 },
    { vendor => 0x14e4, device => 0x16d9 },
    { vendor => 0x14e4, device => 0x16dc },
    { vendor => 0x14e4, device => 0x16de },
    { vendor => 0x14e4, device => 0x16df },
    { vendor => 0x14e4, device => 0x16e0 },
    { vendor => 0x14e4, device => 0x16e1 },
    { vendor => 0x14e4, device => 0x16e2 },
    { vendor => 0x14e4, device => 0x16e3 },
    { vendor => 0x14e4, device => 0x16e4 },
    { vendor => 0x14e4, device => 0x16e7 },
    { vendor => 0x14e4, device => 0x16e8 },
    { vendor => 0x14e4, device => 0x16e9 },
    { vendor => 0x14e4, device => 0x16ea },
    { vendor => 0x14e4, device => 0x16ec },
    { vendor => 0x14e4, device => 0x16ee },

    # Virtio
    { vendor => 0x1af4, device => 0x1000 },
    { vendor => 0x1af4, device => 0x1041 },

    # Windriver Accelerated Virtual Port
    { vendor => 0x1af4, device => 0x1110 },

    # VMXNET3
    { vendor => 0x15ad, device => 0x07b0 },

    # Cavium ThunderNic
    { vendor => 0x177d, device => 0xa034 },
    { vendor => 0x177d, device => 0x0011 },

    # Chelsio T5 adapters
    { vendor => 0x1425, device => 0x5000 },
    { vendor => 0x1425, device => 0x5001 },
    { vendor => 0x1425, device => 0x5002 },
    { vendor => 0x1425, device => 0x5003 },
    { vendor => 0x1425, device => 0x5004 },
    { vendor => 0x1425, device => 0x5005 },
    { vendor => 0x1425, device => 0x5006 },
    { vendor => 0x1425, device => 0x5007 },
    { vendor => 0x1425, device => 0x5008 },
    { vendor => 0x1425, device => 0x5009 },
    { vendor => 0x1425, device => 0x500a },
    { vendor => 0x1425, device => 0x500d },
    { vendor => 0x1425, device => 0x500e },
    { vendor => 0x1425, device => 0x5010 },
    { vendor => 0x1425, device => 0x5011 },
    { vendor => 0x1425, device => 0x5012 },
    { vendor => 0x1425, device => 0x5013 },
    { vendor => 0x1425, device => 0x5014 },
    { vendor => 0x1425, device => 0x5015 },
    { vendor => 0x1425, device => 0x5016 },
    { vendor => 0x1425, device => 0x5017 },
    { vendor => 0x1425, device => 0x5018 },
    { vendor => 0x1425, device => 0x5019 },
    { vendor => 0x1425, device => 0x501a },
    { vendor => 0x1425, device => 0x501b },
    { vendor => 0x1425, device => 0x5080 },
    { vendor => 0x1425, device => 0x5081 },
    { vendor => 0x1425, device => 0x5082 },
    { vendor => 0x1425, device => 0x5083 },
    { vendor => 0x1425, device => 0x5084 },
    { vendor => 0x1425, device => 0x5085 },
    { vendor => 0x1425, device => 0x5086 },
    { vendor => 0x1425, device => 0x5087 },
    { vendor => 0x1425, device => 0x5088 },
    { vendor => 0x1425, device => 0x5089 },
    { vendor => 0x1425, device => 0x5090 },
    { vendor => 0x1425, device => 0x5091 },
    { vendor => 0x1425, device => 0x5092 },
    { vendor => 0x1425, device => 0x5093 },
    { vendor => 0x1425, device => 0x5094 },
    { vendor => 0x1425, device => 0x5095 },
    { vendor => 0x1425, device => 0x5096 },
    { vendor => 0x1425, device => 0x5097 },
    { vendor => 0x1425, device => 0x5098 },
    { vendor => 0x1425, device => 0x5099 },
    { vendor => 0x1425, device => 0x509A },
    { vendor => 0x1425, device => 0x509B },
    { vendor => 0x1425, device => 0x509c },
    { vendor => 0x1425, device => 0x509d },
    { vendor => 0x1425, device => 0x509e },
    { vendor => 0x1425, device => 0x509f },
    { vendor => 0x1425, device => 0x50a0 },
    { vendor => 0x1425, device => 0x50a1 },
    { vendor => 0x1425, device => 0x50a2 },
    { vendor => 0x1425, device => 0x50a3 },
    { vendor => 0x1425, device => 0x50a4 },
    { vendor => 0x1425, device => 0x50a5 },
    { vendor => 0x1425, device => 0x50a6 },
    { vendor => 0x1425, device => 0x50a7 },
    { vendor => 0x1425, device => 0x50a8 },
    { vendor => 0x1425, device => 0x50a9 },
    { vendor => 0x1425, device => 0x50aa },
    { vendor => 0x1425, device => 0x50ab },
    { vendor => 0x1425, device => 0x50ac },
    { vendor => 0x1425, device => 0x50ad },
    { vendor => 0x1425, device => 0x50ae },
    { vendor => 0x1425, device => 0x50af },
    { vendor => 0x1425, device => 0x50b0 },

    # Chelsio T6 adapters
    { vendor => 0x1425, device => 0x6001 },
    { vendor => 0x1425, device => 0x6002 },
    { vendor => 0x1425, device => 0x6003 },
    { vendor => 0x1425, device => 0x6004 },
    { vendor => 0x1425, device => 0x6005 },
    { vendor => 0x1425, device => 0x6006 },
    { vendor => 0x1425, device => 0x6007 },
    { vendor => 0x1425, device => 0x6008 },
    { vendor => 0x1425, device => 0x6009 },
    { vendor => 0x1425, device => 0x600d },
    { vendor => 0x1425, device => 0x6011 },
    { vendor => 0x1425, device => 0x6014 },
    { vendor => 0x1425, device => 0x6015 },
    { vendor => 0x1425, device => 0x6080 },
    { vendor => 0x1425, device => 0x6081 },
    { vendor => 0x1425, device => 0x6082 },
    { vendor => 0x1425, device => 0x6083 },
    { vendor => 0x1425, device => 0x6084 },
    { vendor => 0x1425, device => 0x6085 },
    { vendor => 0x1425, device => 0x6086 },
    { vendor => 0x1425, device => 0x6087 },
    { vendor => 0x1425, device => 0x6088 },
    { vendor => 0x1425, device => 0x6089 },
    { vendor => 0x1425, device => 0x608a },
    { vendor => 0x1425, device => 0x608b },

    # Amazon ena adapters
    { vendor => 0x1D0F, device => 0xEC20 },
    { vendor => 0x1D0F, device => 0xEC21 },
);

# List of Mellanox IB device.
my @ib_devices = (
    # Mellanox ConnectX-4 adapters
    { vendor => 0x15b3, device => 0x1003 },
    { vendor => 0x15b3, device => 0x1004 },
    { vendor => 0x15b3, device => 0x1007 },

    # Mellanox ConnectX-5 dapaters
    { vendor => 0x15b3, device => 0x1013 },
    { vendor => 0x15b3, device => 0x1014 },
    { vendor => 0x15b3, device => 0x1015 },
    { vendor => 0x15b3, device => 0x1016 },
    { vendor => 0x15b3, device => 0x1017 },
    { vendor => 0x15b3, device => 0x1018 },
    { vendor => 0x15b3, device => 0x1019 },
    { vendor => 0x15b3, device => 0x101a },
    { vendor => 0x15b3, device => 0xa2d2 },
    { vendor => 0x15b3, device => 0xa2d3 },

    # Mellanox ConnectX-6 adapters
    { vendor => 0x15b3, device => 0x101b },
    { vendor => 0x15b3, device => 0x101c },
    { vendor => 0x15b3, device => 0x101d },
    { vendor => 0x15b3, device => 0x101e },
);

sub is_supported_pci_device {
    my ( $vendor, $device ) = @_;

    return
      unless grep { $_->{vendor} == $vendor && $_->{device} == $device }
      @pci_devices;
}

sub is_supported_ib_device {
    my ( $vendor, $device ) = @_;

    return
      unless grep { $_->{vendor} == $vendor && $_->{device} == $device }
      @ib_devices;
}

sub is_supported_device {
    my ( $vendor, $device ) = @_;

    if (is_supported_pci_device($vendor, $device)) {
        return 1;
    }

    if (is_supported_ib_device($vendor, $device)) {
        return 1;
    }

    return 0;
}
