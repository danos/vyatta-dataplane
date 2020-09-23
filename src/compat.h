/*
 *  Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 *  Copyright (c) 2011-2015 by Brocade Communications Systems, Inc.
 *  All rights reserved.
 *
 *  SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef COMPAT_H
#define COMPAT_H

#include <netinet/ip.h>

#define _LINUX_IP_H /* linux/ip.h conflicts with netinet/ip.h */
#include <linux/types.h>
#include <linux/version.h>
#include <linux/rtnetlink.h>
#include <linux/netconf.h>
#include <linux/if_link.h>
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include <sys/socket.h>

/* For PKT_RX_VLAN - rte_mbuf has an inline function that uses rte_memcpy */
#include <rte_memcpy.h>
#include <rte_mbuf.h>

#define VRF_NAME_SIZE   128

/* Brocade vrouter T2 Metadata */
#define NSH_MD_CLASS_BROCADE_VROUTER 0xf000

/* NSH defines as in kernel */
#define NSH_TLVC_UINT32 0

#define NSH_MD_TYPE_IFINDEX_IN   1
#define NSH_MD_TYPE_IFINDEX_OUT  2
#define NSH_MD_TYPE_ADDR_IPv4_NH 3
#define NSH_MD_TYPE_ADDR_IPv6_NH 4
#define NSH_MD_TYPE_MARK         5
#define NSH_MD_TYPE_MWID         6
#define NSH_MD_TYPE_VRF_ID       7

/* Lengths in 4 byte words */
#define NSH_MD_LEN_IFINDEX   1
#define NSH_MD_LEN_MARK      1
#define NSH_MD_LEN_ADDR_IPv4 1
#define NSH_MD_LEN_ADDR_IPv6 4
#define NSH_MD_LEN_VRF_ID    1

#ifndef ETH_P_LLDP
#define ETH_P_LLDP	0x88CC
#endif

#ifndef MAX_MP_SELECT_LABELS
/* Maximum number of labels to look ahead at when selecting a path of
 * a multipath route
 */
#define MAX_MP_SELECT_LABELS 4
#endif

typedef uint16_t portid_t;

#ifndef PKT_RX_VLAN
#define PKT_RX_VLAN PKT_RX_VLAN_PKT
#endif
#endif
