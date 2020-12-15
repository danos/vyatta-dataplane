/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VPLANE_DEBUG_H
#define VPLANE_DEBUG_H

#include <stdint.h>

#include "vplane_log.h"
#include "compiler.h"

/*
 * Flags controlling which debug messages show up in the
 * system log.
 *
 * Keep this in sync with debug_bits[] in debug.c
 */
#define DP_DBG_INIT		(1u << 0)
#define DP_DBG_LINK		(1u << 1)
#define DP_DBG_ARP		(1u << 2)
#define DP_DBG_BRIDGE		(1u << 3)
#define DP_DBG_NETLINK_IF	(1u << 4)
#define DP_DBG_NETLINK_ROUTE	(1u << 5)
#define DP_DBG_NETLINK_ADDR	(1u << 6)
#define DP_DBG_NETLINK_NEIGH	(1u << 7)
#define DP_DBG_NETLINK_NETCONF	(1u << 8)
#define DP_DBG_SUBSCRIBER	(1u << 9)
#define DP_DBG_RESYNC		(1u << 10)
#define DP_DBG_ND6		(1u << 11)
#define DP_DBG_ROUTE		(1u << 12)
#define DP_DBG_MACVLAN		(1u << 13)
#define DP_DBG_VXLAN		(1u << 14)
#define DP_DBG_QOS		(1u << 15)
#define DP_DBG_NPF		(1u << 16)
#define DP_DBG_NAT		(1u << 17)
#define DP_DBG_L2TP		(1u << 18)
#define DP_DBG_LAG		(1u << 19)
#define DP_DBG_DEALER		(1u << 20)
#define DP_DBG_NSH		(1u << 21)
#define DP_DBG_VTI		(1u << 22)
#define DP_DBG_CRYPTO		(1u << 23)
#define DP_DBG_CRYPTO_DATA	(1u << 24)
#define DP_DBG_VHOST		(1u << 25)
#define DP_DBG_VRF		(1u << 26)
#define DP_DBG_MULTICAST	(1u << 27)
#define DP_DBG_MPLS_CTRL	(1u << 28)
#define DP_DBG_MPLS_PKTERR	(1ull << 29)
#define DP_DBG_DPI		(1ull << 30) /* Deep Packet Inspection */
#define DP_DBG_QOS_DP		(1ull << 31)
#define DP_DBG_QOS_HW		(1ull << 32)
#define DP_DBG_STORM_CTL        (1ull << 33)
#define DP_DBG_CPP_RL		(1ull << 34)
#define DP_DBG_PTP		(1ull << 35)
#define DP_DBG_CGNAT		(1ull << 36)
#define DP_DBG_FLOW_CACHE	(1ull << 37)
#define DP_DBG_MAC_LIMIT	(1ull << 38)
#define DP_DBG_GPC		(1ull << 39)

/* Default to only debugging startup and link events.
 * Skip ARP and route since they can flood log.
 */
#define DP_DBG_DEFAULT \
	(DP_DBG_INIT | DP_DBG_LINK | DP_DBG_NETLINK_IF)

extern uint64_t dp_debug;
extern uint64_t dp_debug_init;

/*
 * Macro to selectively enable logging by feature.
 * This bypasses the rte_log level.
 */
#define DP_DEBUG(m, l, t, fmt, args...)	do {		\
	if (unlikely(dp_debug & DP_DBG_##m))		\
		rte_log(RTE_LOG_##l, RTE_LOGTYPE_##t,	\
			#t ": " fmt, ## args);		\
	} while (0)

/*
 * Macro to test whether a given debug flag is enabled.
 */
#define DP_DEBUG_ENABLED(m) (unlikely(dp_debug & DP_DBG_##m))

int cmd_debug(FILE *f, int argc, char **argv);
int cmd_log(FILE *f, int argc, char **argv);
void debug_init(void);
#endif /* _MAIN_H_ */
