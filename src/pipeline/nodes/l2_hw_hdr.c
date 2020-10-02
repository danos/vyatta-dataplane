/*
 * l2_hw_hdr.c
 *
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "if_var.h"
#include "ether.h"
#include "util.h"
#include "ether.h"
#include "fal_plugin.h"

#include "capture.h"
#include "compiler.h"
#include "main.h"
#include "pl_common.h"
#include "pl_node.h"
#include "../pl_fused.h"
#include "pl_nodes_common.h"
#include "fal.h"

/* Protocol being parsed for, stored in network order*/
static uint16_t l2_hw_hdr_proto = 0xABCD;

static uint32_t l2_hw_hdr_channel_shared;

static int (*l2_hw_hdr_rx_feat_framer)(struct rte_mbuf *buf,
				       uint16_t *dpdk_port,
				       union fal_pkt_feature_info *feat_info);

static bool (*l2_hw_hdr_rx_framer)(struct rte_mbuf *buf,
				   uint16_t *dpdk_port);

__FOR_EXPORT
int
fal_rx_bp_framer_enable(bool enable, uint32_t bp_port,
			bool shared_channel, uint16_t ether_proto,
			int (*feat_framer)(struct rte_mbuf *buf,
					   uint16_t *dpdk_port,
					   union fal_pkt_feature_info
						 *feat_info))
{
	static struct ifnet *configured_ifp;
	struct ifnet *ifp = ifport_table[bp_port];

	if (!ifp)
		return -1;

	if (!enable) {
		if (pl_node_remove_feature_by_inst(&hw_hdr_in_feat, ifp))
			return -1;
		return 0;
	}

	/*
	 * Check if a parser is already configured
	 * and if so that the params passed identical.
	 */
	if (configured_ifp &&
	    (l2_hw_hdr_channel_shared != shared_channel ||
	     l2_hw_hdr_proto != htons(ether_proto) ||
	     l2_hw_hdr_rx_feat_framer != feat_framer))
		return -1;

	l2_hw_hdr_channel_shared = shared_channel;
	l2_hw_hdr_proto = htons(ether_proto);
	l2_hw_hdr_rx_feat_framer = feat_framer;
	if (pl_node_add_feature_by_inst(&hw_hdr_in_feat, ifp))
		return -1;

	configured_ifp = ifp;
	return 0;
}

static
int default_feat_framer(struct rte_mbuf *mbuf, uint16_t *dpdk_port,
			 union fal_pkt_feature_info *feat_info __unused)
{
	if (l2_hw_hdr_rx_framer(mbuf, dpdk_port))
		return FAL_RET_ETHER_INPUT;

	return -1;
}

/* TODO Deprecate/Remove when plugins start using the new API
 * fal_rx_bp_framer_enable
 */
__FOR_EXPORT
bool
l2_hw_hdr_rx_enable(bool enable, uint32_t bp_port,
		    bool shared_channel, uint16_t ether_proto,
		    bool (*framer)(struct rte_mbuf *buf,
				   uint16_t *dpdk_port))
{
	/* fal_rx_bp_framer_enable returns 0 for success failure otherwise */
	if (fal_rx_bp_framer_enable(enable, bp_port, shared_channel,
				    ether_proto, default_feat_framer))
		return false;

	l2_hw_hdr_rx_framer = framer;

	return true;
}

static void
fal_pkt_feature_info_release_data(void *d)
{
	free(d);
}

PL_REGISTER_STORAGE(fal_pkt_info) = {
	.release = fal_pkt_feature_info_release_data,
};

uint8_t fal_feat_storageid(void)
{
	return	PL_STORAGE_ID(fal_pkt_info);
}

static ALWAYS_INLINE unsigned int
l2_hw_hdr_rx_process(struct pl_packet *pkt)
{
	uint16_t dpdk_port;
	struct rte_mbuf *buff = pkt->mbuf;
	int rc;
	union fal_pkt_feature_info *feature_info;
	union fal_pkt_feature_info feat_info;
	struct ifnet *ifp;

	rc = l2_hw_hdr_rx_feat_framer(pkt->mbuf, &dpdk_port, &feat_info);

	if ((rc != FAL_RET_ETHER_INPUT) &&
	    (rc != FAL_RET_CAPTURE_HW_INPUT)) {

		feature_info = calloc(1, sizeof(*feature_info));
		if (!feature_info)
			goto drop;

		memcpy(feature_info, &feat_info, sizeof(feat_info));

		pl_set_node_data(pkt, PL_STORAGE_ID(fal_pkt_info),
				 feature_info);
	}
	switch (rc) {
	case FAL_RET_ETHER_INPUT:
		ifp = ifnet_byport(dpdk_port);

		if (!ifp)
			goto drop;

		if (!is_team(ifp))
			pkt->mbuf->port = dpdk_port;

		/*
		 * Packet capture, monitor, and dispatch.  Due to
		 * compiler optimizations , known local memory scope,
		 * &pkt->mbuf can not be directly passed if a
		 * performance drop is to be avoid
		 */
		switch_port_process_burst(dpdk_port, &buff, 1);

		/*
		 * Ideally should used next-node of "ether-in" to
		 * dispatch deframed pkt. Due to limitations of the fused
		 * mode code generator and graph loops we can not.
		 */
		return HW_HDR_IN_CONSUME;

	case FAL_RET_PORTMONITOR_HW_INPUT:
		ifp = ifnet_byport(dpdk_port);

		if (!ifp)
			goto drop;

		pkt->mbuf->port = dpdk_port;
		pkt->in_ifp = ifp;
		return HW_HDR_IN_PORTMONITOR;

	case FAL_RET_CAPTURE_HW_INPUT:
		ifp = ifnet_byport(dpdk_port);

		if (!ifp)
			goto drop;

		buff->port = dpdk_port;
		capture_hardware(ifp, buff);
		return HW_HDR_IN_CONSUME;
	}
drop:
	if_incr_dropped(pkt->in_ifp);
	return HW_HDR_IN_DROP;
}

ALWAYS_INLINE unsigned int
l2_hw_hdr_in_check_process(struct pl_packet *pkt, void *context __unused)
{
	struct rte_mbuf *m = pkt->mbuf;

	if (!l2_hw_hdr_channel_shared ||
	    ethhdr(m)->ether_type == l2_hw_hdr_proto)
		return l2_hw_hdr_rx_process(pkt);

	return HW_HDR_IN_ACCEPT;
}

/* Register Node */
PL_REGISTER_NODE(hw_hdr_in_node) = {
	.name = "vyatta:hw-hdr-in",
	.type = PL_PROC,
	.handler = l2_hw_hdr_in_check_process,
	.num_next = HW_HDR_IN_NUM,
	.next = {
		[HW_HDR_IN_PORTMONITOR]  = "portmonitor-hw-in",
		[HW_HDR_IN_ACCEPT]  = "term-noop",
		[HW_HDR_IN_CONSUME]   = "term-finish",
		[HW_HDR_IN_DROP]   = "term-drop",
	}
};

PL_REGISTER_FEATURE(hw_hdr_in_feat) = {
	.name = "vyatta:hw-hdr-in",
	.node_name = "hw-hdr-in",
	.feature_point = "ether-lookup",
	.id = PL_ETHER_LOOKUP_FUSED_FEAT_HW_HDR,
};
