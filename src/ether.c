/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */


#include "ether.h"

#include "dp_event.h"
#include "l2_rx_fltr.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "vplane_log.h"

struct ifnet;
struct rte_mbuf;

/*
 * Ether switching input
 *
 * Always consumes the mbuf
 */
__attribute__((noinline)) void
ether_input(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct pl_packet pkt;

	pkt.mbuf = m;
	/* Init to null, to aid compiler optimisation*/
	pkt.nxt.v6 = NULL;
	pkt.in_ifp = ifp;
	pkt.max_data_used = 0;
	pipeline_fused_ether_in(&pkt);
}

/*
 * Ether switching input without support for dynamic pipeline features
 *
 * Always consumes the mbuf
 */
__attribute__((noinline)) void
ether_input_no_dyn_feats(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct pl_packet pkt;

	pkt.mbuf = m;
	/* Init to null, to aid compiler optimisation*/
	pkt.nxt.v6 = NULL;
	pkt.in_ifp = ifp;
	pkt.max_data_used = 0;
	pipeline_fused_no_dyn_feats_ether_in(&pkt);
}

int ether_if_set_l2_address(struct ifnet *ifp, uint32_t l2_addr_len,
			    void *l2_addr)
{
	struct ether_addr *macaddr = l2_addr;
	char b1[32], b2[32];

	if (l2_addr_len != ETHER_ADDR_LEN) {
		RTE_LOG(NOTICE, DATAPLANE,
			"link address is not ethernet (len=%u)!\n",
			l2_addr_len);
		return -EINVAL;
	}

	if (ether_addr_equal(&ifp->eth_addr, macaddr))
		return 1;

	RTE_LOG(INFO, DATAPLANE, "%s change MAC from %s to %s\n",
		ifp->if_name,
		ether_ntoa_r(&ifp->eth_addr, b1),
		ether_ntoa_r(macaddr, b2));

	ifp->eth_addr = *macaddr;

	return 0;
}

int ether_if_set_broadcast(struct ifnet *ifp, bool enable)
{
	static const struct ether_addr ea_broadcast = {
		.addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	};

	/* Setup L2 multicast receive filtering */
	if (enable) {
		if (!l2_mcfltr_node_lookup(ifp, &ea_broadcast))
			l2_rx_fltr_add_addr(ifp, &ea_broadcast);
	} else {
		if (l2_mcfltr_node_lookup(ifp, &ea_broadcast))
			l2_rx_fltr_del_addr(ifp, &ea_broadcast);
	}
	l2_rx_fltr_state_change(ifp);

	return 0;
}
