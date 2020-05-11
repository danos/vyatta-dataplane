/*
 * SPAN, RSPAN and ERSPAN Port Monitoring
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <linux/if_ether.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "capture.h"
#include "ether.h"
#include "if/gre.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_if.h"
#include "npf_shim.h"
#include "pktmbuf_internal.h"
#include "portmonitor/portmonitor.h"
#include "portmonitor/portmonitor_hw.h"
#include "urcu.h"

/* Forward packet to SPAN port.
 * Returns 1 if packet was consumed.
 *         0 if span not enabled on port.
 */
int portmonitor_dest_output(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct portmonitor_session *pmsess;
	struct portmonitor_info *pminfo = rcu_dereference(ifp->pminfo);
	uint16_t cos_bso_id_t;
	uint16_t cos_en_id_t;
	uint16_t ver_vlan;
	struct ifnet *dest_ifp;

	if (unlikely(pminfo == NULL))
		return 0;

	if (pminfo->pm_iftype != PM_DST_SESSION_SRC_IF)
		return 0;

	pmsess = pminfo->pm_session;
	if (!pmsess || pmsess->disabled)
		return 0;

	dest_ifp = rcu_dereference(pmsess->dest_ifp);
	if (!dest_ifp)
		return 0;

	if (pmsess->session_type == PORTMONITOR_RSPAN_DESTINATION) {
		if (m->ol_flags & PKT_RX_VLAN)
			pktmbuf_clear_rx_vlan(m);
		if_output(dest_ifp, m, ifp, ETH_P_TEB);
		return 1;
	}

	if (pmsess->session_type != PORTMONITOR_ERSPAN_DESTINATION ||
		pmsess->erspan_hdr_type == 0)
		return 0;

	if (pmsess->erspan_hdr_type == ERSPAN_TYPE_II) {
		struct erspan_v2_hdr *erspan_hdr =
			rte_pktmbuf_mtod(m, struct erspan_v2_hdr *);

		ver_vlan = ntohs(erspan_hdr->version_vlan);
		if (ERSPAN_VERSION(ver_vlan) != pmsess->erspan_hdr_type)
			goto drop;
		cos_en_id_t = ntohs(erspan_hdr->cos_en_t_id);
		if (ERSPAN_ID(cos_en_id_t) != pmsess->erspan_id)
			goto drop;
		switch (ERSPAN_EN(cos_en_id_t)) {
		case ERSPAN_ORIG_FRAME_ISL_ENCAP:
			/* not supported */
			goto drop;
		case ERSPAN_ORIG_FRAME_802_1Q_ENCAP:
			m->ol_flags |= PKT_TX_VLAN_PKT;
			m->vlan_tci = ERSPAN_VLAN(ver_vlan);
			break;
		case ERSPAN_ORIG_FRAME_VLAN_PRESERVED:
		case ERSPAN_ORIG_FRAME_NO_VLAN:
			break;
		}
		if (rte_pktmbuf_adj(m, sizeof(struct erspan_v2_hdr)) == NULL)
			goto drop;
	} else if (pmsess->erspan_hdr_type == ERSPAN_TYPE_III) {
		struct erspan_v3_hdr *erspan_hdr =
			rte_pktmbuf_mtod(m, struct erspan_v3_hdr *);

		ver_vlan = ntohs(erspan_hdr->version_vlan);
		if (ERSPAN_VERSION(ver_vlan) != pmsess->erspan_hdr_type)
			goto drop;
		cos_bso_id_t = ntohs(erspan_hdr->cos_bso_t_id);
		if (ERSPAN_ID(cos_bso_id_t) != pmsess->erspan_id)
			goto drop;
		if (ERSPAN_VLAN(ver_vlan)) {
			m->ol_flags |= PKT_TX_VLAN_PKT;
			m->vlan_tci = ERSPAN_VLAN(ver_vlan);
		}
		if (rte_pktmbuf_adj(m, sizeof(struct erspan_v3_hdr)) == NULL)
			goto drop;
	}
	/* capture mirrored packet received on erspan tunnel */
	if (unlikely(ifp->capturing))
		capture_burst(ifp, &m, 1);
	if_output(dest_ifp, m, ifp, ETH_P_TEB);
	return 1;

drop:
	rte_pktmbuf_free(m);
	return 1;
}

static int portmonitor_encap_erspan_hdr(struct ifnet *ifp,
					struct portmonitor_session *pmsess,
					struct rte_mbuf *m, uint8_t direction)
{
	struct erspan_v2_hdr *v2_hdr;
	struct erspan_v3_hdr *v3_hdr;
	struct timespec ts;
	uint16_t frame_size;
	bool has_vlan = false;
	uint16_t en;

	if (pmsess->erspan_hdr_type == 0)
		return 0;

	if (pmsess->erspan_hdr_type == ERSPAN_TYPE_II) {
		v2_hdr = (struct erspan_v2_hdr *)
			rte_pktmbuf_prepend(m, sizeof(struct erspan_v2_hdr));
		if (v2_hdr == NULL)
			return 0;

		memset(v2_hdr, 0, sizeof(struct erspan_v2_hdr));
		if (direction == PORTMONITOR_DIRECTION_RX) {
			has_vlan = m->ol_flags & PKT_RX_VLAN;
			v2_hdr->version_vlan = htons((pmsess->erspan_hdr_type << 12) |
						pktmbuf_get_rxvlanid(m));
		} else if (direction == PORTMONITOR_DIRECTION_TX) {
			has_vlan = m->ol_flags & PKT_TX_VLAN_PKT;
			v2_hdr->version_vlan = htons((pmsess->erspan_hdr_type << 12) |
						pktmbuf_get_txvlanid(m));
			pktmbuf_clear_tx_vlan(m);
		}
		if (has_vlan) {
			en = ERSPAN_ORIG_FRAME_802_1Q_ENCAP;
		} else {
			en = ERSPAN_ORIG_FRAME_NO_VLAN;
		}
		v2_hdr->cos_en_t_id = htons((pktmbuf_get_vlan_pcp(m) << 13) |
					    (en << 11) | pmsess->erspan_id);
		v2_hdr->index = htonl((ifp->if_port << 4) | direction);
	} else if (pmsess->erspan_hdr_type == ERSPAN_TYPE_III) {
		if (clock_gettime(CLOCK_REALTIME, &ts))
			return 0;

		v3_hdr = (struct erspan_v3_hdr *)
			rte_pktmbuf_prepend(m, sizeof(struct erspan_v3_hdr));
		if (v3_hdr == NULL)
			return 0;

		memset(v3_hdr, 0, sizeof(struct erspan_v3_hdr));
		if (direction == PORTMONITOR_DIRECTION_RX) {
			v3_hdr->version_vlan =
				htons((pmsess->erspan_hdr_type << 12) |
				      pktmbuf_get_rxvlanid(m));
		} else if (direction == PORTMONITOR_DIRECTION_TX) {
			v3_hdr->version_vlan =
				htons((pmsess->erspan_hdr_type << 12) |
				      pktmbuf_get_txvlanid(m));
			pktmbuf_clear_tx_vlan(m);
		}
		frame_size = rte_pktmbuf_pkt_len(m);
		if (frame_size < RTE_ETHER_MIN_LEN) {
			v3_hdr->cos_bso_t_id =
				htons((pktmbuf_get_vlan_pcp(m) << 13) |
				      (ERSPAN_ORIG_FRAME_SHORT << 11) |
				      pmsess->erspan_id);
		} else if (frame_size > RTE_ETHER_MAX_LEN) {
			v3_hdr->cos_bso_t_id =
				htons((pktmbuf_get_vlan_pcp(m) << 13) |
				      (ERSPAN_ORIG_FRAME_OVERSIZED << 11) |
				      pmsess->erspan_id);
		} else {
			v3_hdr->cos_bso_t_id =
				htons((pktmbuf_get_vlan_pcp(m) << 13) |
				      pmsess->erspan_id);
		}
		v3_hdr->p_ft_hwid_d_gra_o = htons((1 << 15) |
						(ERSPAN_HARDWARE_ID << 4) |
						(direction << 3) |
						(ERSPAN_TIMESTAMP_GRA_IEEE_1588 << 1) | 1);
		v3_hdr->timestamp = htonl(ts.tv_nsec);
		v3_hdr->subhdr3.timestamp = htonl(ts.tv_sec);
		v3_hdr->subhdr3.platid_portid = htonl((ERSPAN_SUBHDR_PLATFORM_ID << 26) |
						ifp->if_port);
	}
	return 1;
}

static void portmonitor_source_output(struct ifnet *ifp,
					const struct portmonitor_info *pminfo,
					struct rte_mbuf **m, uint8_t direction)
{
	enum npf_ruleset_type ruleset_type;
	bool filter_active = false;
	int filter_dir;
	npf_result_t result;
	struct rte_mbuf *mirror_pkt;
	struct ifnet *dest_ifp;
	struct portmonitor_session *pmsess;

	if (!pminfo || pminfo->hw_mirroring)
		return;

	pmsess = pminfo->pm_session;
	if (!pmsess || pmsess->disabled)
		return;

	dest_ifp = rcu_dereference(pmsess->dest_ifp);
	if (!dest_ifp)
		return;

	dp_pktmbuf_l2_len(*m) = RTE_ETHER_HDR_LEN;

	struct npf_if *nif = rcu_dereference(ifp->if_npf);
	if (direction == PORTMONITOR_DIRECTION_RX) {
		filter_active = npf_if_active(nif, NPF_PORTMONITOR_IN);
		ruleset_type = NPF_RS_PORTMONITOR_IN;
		filter_dir = PFIL_IN;
	} else if (direction == PORTMONITOR_DIRECTION_TX) {
		filter_active = npf_if_active(nif, NPF_PORTMONITOR_OUT);
		ruleset_type = NPF_RS_PORTMONITOR_OUT;
		filter_dir = PFIL_OUT;
	}
	if (filter_active) {
		struct npf_config *npf_config = npf_if_conf(nif);
		result = npf_hook_notrack(
				npf_get_ruleset(npf_config, ruleset_type),
				m, ifp, filter_dir, 0,
				htons(RTE_ETHER_TYPE_IPV4));
		if (result.decision != NPF_DECISION_PASS)
			return;
	}

	mirror_pkt = pktmbuf_copy(*m, (*m)->pool);
	if (!mirror_pkt)
		return;

	if (((*m)->ol_flags & PKT_RX_VLAN) && ifp->qinq_inner) {
		if (unlikely(vid_encap(ifp->if_vlan, &mirror_pkt,
				RTE_ETHER_TYPE_VLAN) == NULL)) {
			rte_pktmbuf_free(mirror_pkt);
			return;
		}
		ifp = ifp->if_parent;
	}

	switch (pmsess->session_type) {
	case PORTMONITOR_SPAN:
		if ((*m)->ol_flags & PKT_RX_VLAN)
			pktmbuf_convert_rx_to_tx_vlan(mirror_pkt);
		/* fall through */
	case PORTMONITOR_RSPAN_SOURCE:
		if_output(dest_ifp, mirror_pkt, ifp, ETH_P_TEB);
		break;
	case PORTMONITOR_ERSPAN_SOURCE:
		/* capture mirrored packet on erspan tunnel */
		if (unlikely(dest_ifp->capturing))
			capture_burst(dest_ifp, &mirror_pkt, 1);
		if (!portmonitor_encap_erspan_hdr(ifp, pmsess, mirror_pkt,
							direction)) {
			rte_pktmbuf_free(mirror_pkt);
			return;
		}
		if_output(dest_ifp, mirror_pkt, ifp, pmsess->gre_proto);
		break;
	default:
		rte_pktmbuf_free(mirror_pkt);
		break;
	}
}

void portmonitor_src_vif_rx_output(struct ifnet *ifp, struct rte_mbuf **m)
{
	struct portmonitor_info *pminfo;

	if (ifp->if_type != IFT_L2VLAN)
		return;

	pminfo = rcu_dereference(ifp->pminfo);
	if (!pminfo)
		return;

	if (!(pminfo->direction & PORTMONITOR_DIRECTION_RX) ||
		pminfo->pm_iftype != PM_SRC_SESSION_SRC_IF)
		return;

	portmonitor_source_output(ifp, pminfo, m, PORTMONITOR_DIRECTION_RX);
}

void portmonitor_src_vif_tx_output(struct ifnet *ifp, struct rte_mbuf **m)
{
	struct portmonitor_info *pminfo;

	if (ifp->if_type != IFT_L2VLAN)
		return;

	pminfo = rcu_dereference(ifp->pminfo);
	if (!pminfo)
		return;

	if (!(pminfo->direction & PORTMONITOR_DIRECTION_TX) ||
		pminfo->pm_iftype != PM_SRC_SESSION_SRC_IF)
		return;

	portmonitor_source_output(ifp, pminfo, m, PORTMONITOR_DIRECTION_TX);
}

void portmonitor_src_phy_rx_output(struct ifnet *ifp, struct rte_mbuf *mbi[],
					unsigned int n)
{
	struct portmonitor_info *pminfo;
	unsigned int i;

	pminfo = rcu_dereference(ifp->pminfo);
	if (!pminfo)
		return;

	if (!(pminfo->direction & PORTMONITOR_DIRECTION_RX) ||
		pminfo->pm_iftype != PM_SRC_SESSION_SRC_IF)
		return;

	for (i = 0; i < n; i++)
		portmonitor_source_output(ifp, pminfo, &(mbi[i]),
						PORTMONITOR_DIRECTION_RX);
}

void portmonitor_src_phy_tx_output(struct ifnet *ifp, struct rte_mbuf *mbi[],
					unsigned int n)
{
	struct portmonitor_info *pminfo;
	unsigned int i;

	if (ifp->if_type == IFT_L2VLAN)
		return;

	pminfo = rcu_dereference(ifp->pminfo);
	if (!pminfo)
		return;

	if (!(pminfo->direction & PORTMONITOR_DIRECTION_TX) ||
		pminfo->pm_iftype != PM_SRC_SESSION_SRC_IF)
		return;

	for (i = 0; i < n; i++)
		portmonitor_source_output(ifp, pminfo, &(mbi[i]),
						PORTMONITOR_DIRECTION_TX);
}

/* Forward packet to SPAN port.
 * Returns 1 if packet was consumed.
 *         0 if span not enabled on port for the direction
 */
int portmonitor_src_hw_mirror_process(struct ifnet *ifp,
		struct rte_mbuf *m,
		struct fal_pkt_portmonitor_info *fal_pm)
{
	struct portmonitor_session *pmsess;
	struct portmonitor_info *pminfo;
	struct ifnet *dest_ifp;

	if (!ifp)
		return 0;

	/* Return if portmonitor not configured for interface */
	pminfo = rcu_dereference(ifp->pminfo);
	if (!pminfo)
		return 0;

	/* Return if interface is not a source intrerface */
	if (pminfo->pm_iftype != PM_SRC_SESSION_SRC_IF)
		return 0;

	if (!fal_pm)
		return 0;

	if (!(pminfo->direction & fal_pm->mirror_dir))
		return 0;

	pmsess = pminfo->pm_session;
	if (!pmsess || pmsess->disabled)
		return 0;

	dest_ifp = rcu_dereference(pmsess->dest_ifp);
	if (!dest_ifp)
		return 0;

	switch (pmsess->session_type) {
	case PORTMONITOR_SPAN:
		if (m->ol_flags & PKT_RX_VLAN)
			pktmbuf_convert_rx_to_tx_vlan(m);

		if_output(dest_ifp, m, ifp, ETH_P_TEB);
		return 1;
	default:
		/* Only SPAN supported in hardware
		 * TODO consider generic code in future
		 */
		return 0;
	}
}
