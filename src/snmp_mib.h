/*-
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * Statistics for SNMP
 *
 * Note the dataplane MIB and it's layout comes from Linux headers.
 * And the Linux header is derived from MIB values
 */

/* __IPSTATS_MIB_MAX in snmp.h is 31 round up to avoid cache thrash */
#ifndef SNMP_MIB_H
#define SNMP_MIB_H

#include <linux/snmp.h>


#define IPSTATS_MIB_MAX __IPSTATS_MIB_MAX

struct ipstats_mib {
	uint64_t mibs[IPSTATS_MIB_MAX];
}  __rte_cache_aligned;

#define IPSTAT_INC_VRF(vrf, mib) do { \
	unsigned int _lcore = dp_lcore_id();	\
	(vrf)->v_stats[_lcore].ip.mibs[mib]++;		\
} while (0)

/* Update statistic for normal case of in/out on interface.
 * Note: since interface is always associated with a VRF there
 *  is no check for NULL here.
 */
#define IPSTAT_INC_IFP(ifp, type) \
	IPSTAT_INC_VRF(if_vrf(ifp), type)

/* Update statistic for case where mbuf is not in state where
 * it is coming in/out of interface (example reassmbly).
 */
#define IPSTAT_INC_MBUF(mb, type) \
	IPSTAT_INC(pktmbuf_get_vrf(mb), type)

#define IPSTAT_INC(vrf_id, type) do {			\
	struct vrf *vrf = vrf_get_rcu(vrf_id);		\
	if (likely(vrf != NULL))			\
		IPSTAT_INC_VRF(vrf, type);		\
} while (0)

#define IP6STAT_INC_VRF(vrf, mib) do { \
	unsigned int _lcore = dp_lcore_id();	\
	(vrf)->v_stats[_lcore].ip6.mibs[mib]++;		\
} while (0)

/* Update statistic for normal case of in/out on interface.
 * Note: since interface is always associated with a VRF there
 *  is no check for NULL here.
 */
#define IP6STAT_INC_IFP(ifp, type) \
	IP6STAT_INC_VRF(if_vrf(ifp), type)

#define IP6STAT_INC(vrf_id, type) do {			\
	struct vrf *vrf = vrf_get_rcu(vrf_id);		\
	if (likely(vrf != NULL))			\
		IP6STAT_INC_VRF(vrf, type);		\
} while (0)

/* Update statistic for case where mbuf is not in state where
 * it is coming in/out of interface (example reassmbly).
 */
#define IP6STAT_INC_MBUF(mb, type) \
	IP6STAT_INC(pktmbuf_get_vrf(mb), type)

#define IP6STAT_INC_VRF(vrf, mib) do { \
	unsigned int _lcore = dp_lcore_id();	\
	(vrf)->v_stats[_lcore].ip6.mibs[mib]++;		\
} while (0)

/* ICMP: Don't bother doing per-core statistics */
#define ICMP_MIB_MAX	__ICMP_MIB_MAX

#define ICMPSTAT_INC(vrf_id, type)  {		\
	struct vrf *vrf = vrf_get_rcu(vrf_id);	\
	if (vrf) {				\
		vrf->v_icmpstats[type]++;	\
	}					\
}

/* ICMP6 */
#define ICMP6_MIB_MAX	__ICMP6_MIB_MAX

#define ICMP6STAT_INC(vrf_id, type)  {		\
	struct vrf *vrf = vrf_get_rcu(vrf_id);	\
	if (vrf) {				\
		vrf->v_icmp6stats[type]++;	\
	}					\
}

/*
 * UDP stats to trace/report tunnel forwarding
 *  Don't bother with per VRF or per core
 */
#define UDP_MIB_MAX     __UDP_MIB_MAX
extern uint64_t udpstats[UDP_MIB_MAX];
#define UDPSTAT_INC(type) udpstats[type]++

/* Names for fields in IP/IPv6 MIB. */
extern const char *ipstat_mib_names[];

#endif /* SNMP_MIB_H */
