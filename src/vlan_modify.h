/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * vlan_modify public headers
 */
#ifndef VLAN_MODIFY_H
#define VLAN_MODIFY_H
#include <linux/rtnetlink.h>
#include "ether.h"

struct vlan_mod_ft_cls_act_vlan {
	uint8_t action;
	int8_t prio;
	uint16_t vlan_id;
	uint16_t proto;
	uint16_t rule;
};

struct vlan_mod_ft_cls_action {
	uint8_t eos;
	uint8_t action_type;
	union {
		struct vlan_mod_ft_cls_act_vlan vlan;
	} data;
};

struct vlan_mod_tbl_entry {
	struct vlan_mod_ft_cls_action *ingress;
	struct vlan_mod_ft_cls_action *egress;
};

#define VLAN_MOD_MAX_TC_FLT_ACT 2

#define VLAN_MOD_FILTER_CLS_ACTION_VLAN    1
#define VLAN_MOD_FILTER_CLS_ACTION_MIRRED  2
#define VLAN_MOD_FILTER_CLS_ACTION_UNKNOWN 3

#define VLAN_MOD_FILTER_ACT_VLAN_POP	1
#define VLAN_MOD_FILTER_ACT_VLAN_PUSH	2
#define VLAN_MOD_FILTER_ACT_VLAN_MOD	3

int vlan_mod_flt_entry_add(const struct nlmsghdr *nlh);
int vlan_mod_flt_entry_delete(const struct nlmsghdr *nlh);
int vlan_mod_flt_chain_delete(const struct nlmsghdr *nlh);
void vlan_mod_cmd(FILE *f, int argc, char **argv);

#define VLAN_MOD_INGRESS_HANDLE 0xFFFF
#define VLAN_MOD_EGRESS_HANDLE 0x32

enum vlan_mod_dir {
	VLAN_MOD_DIR_INGRESS,
	VLAN_MOD_DIR_EGRESS
};

static inline uint8_t
vlan_mod_pcp_arbitrate(struct vlan_mod_ft_cls_action *action, uint8_t pcp)
{
	if (action->data.vlan.prio != 0)
		return action->data.vlan.vlan_id;
	return pcp;
}

static inline uint16_t vlan_mod_alt_proto(uint16_t proto)
{
	return (proto == RTE_ETHER_TYPE_VLAN) ?
		RTE_ETHER_TYPE_QINQ : RTE_ETHER_TYPE_VLAN;
}

static inline void
vlan_mod_ingress_pop_from_pkt(struct ifnet *ifp, struct rte_mbuf *m)
{
	if (ethhdr(m)->ether_type == htons(ifp->tpid) &&
	    !(m->ol_flags & PKT_RX_VLAN)) {
		m->ol_flags |= PKT_RX_VLAN;
		m->vlan_tci = vid_decap(m, ifp->tpid);
	}
}

static inline
void vlan_mod_egress_pop_from_pkt(struct ifnet *ifp, struct rte_mbuf *m)
{
	if (ethhdr(m)->ether_type == htons(ifp->tpid) &&
	    !(m->ol_flags & PKT_TX_VLAN)) {
		m->ol_flags |= PKT_TX_VLAN;
		m->vlan_tci = vid_decap(m, ifp->tpid);
	}
}

static inline bool
vlan_mod_meta_data(struct rte_mbuf *m, enum vlan_mod_dir dir)
{
	uint16_t tci;

	if (dir == VLAN_MOD_DIR_INGRESS)
		tci = pktmbuf_get_rx_vlan_tci(m);
	else
		tci = pktmbuf_get_tx_vlan_tci(m);
	return tci == 0 ? false : true;
}

static inline uint8_t
vlan_mod_get_vlan_pcp(struct rte_mbuf *m, struct ifnet *ifp)
{
	uint16_t proto;
	uint8_t pcp;

	if (m->vlan_tci)
		return pktmbuf_get_vlan_pcp(m);

	/* vlan not in the meta data, check the packet */
	proto = vlan_mod_alt_proto(ifp->tpid);

	if (pcp_from_pkt(m, proto, &pcp))
		return pcp;

	return 0;
}

static inline void
vlan_mod_set_vlan_in_meta_data(struct rte_mbuf *m, uint16_t vlan, uint8_t pcp,
			       enum vlan_mod_dir dir)
{
	pktmbuf_set_vlan_and_pcp(m, vlan, pcp);
	if (dir == VLAN_MOD_DIR_INGRESS)
		m->ol_flags |= PKT_RX_VLAN;
	else
		m->ol_flags |= PKT_TX_VLAN;
}

static inline void
vlan_mod_clear_txrx_meta_data(struct rte_mbuf *m)
{
	pktmbuf_clear_rx_vlan(m);
	pktmbuf_clear_tx_vlan(m);
}

static inline uint16_t
vlan_mod_get_vlan(struct rte_mbuf *m, struct ifnet *ifp,
		  enum vlan_mod_dir dir)
{
	uint16_t vlan;

	if (dir == VLAN_MOD_DIR_INGRESS)
		vlan = pktmbuf_get_rxvlanid(m);
	else
		vlan = pktmbuf_get_txvlanid(m);
	if (vlan != 0)
		return vlan;
	return vid_from_pkt(m, vlan_mod_alt_proto(ifp->tpid));
}

static inline struct rte_mbuf *
vlan_mod_tag_pop(struct ifnet *ifp, struct rte_mbuf **m,
		 enum vlan_mod_dir dir)
{
	bool meta = vlan_mod_meta_data(*m, dir);

	if (meta)
		/* Clear any outer vlan in the meta data
		 */
		vlan_mod_clear_txrx_meta_data(*m);
	else
		/* Remove any outer vlan from the packet if present.
		 * The assumption if there is no meta data it is the
		 * alternative vlan proto if there is any tag in the
		 * packet.
		 */
		vid_decap(*m, vlan_mod_alt_proto(ifp->tpid));

	/* We could have revealed another tag, so move it out
	 * to the meta data if the tpid is same as ifp->tpid
	 */
	if (dir == VLAN_MOD_DIR_INGRESS)
		vlan_mod_ingress_pop_from_pkt(ifp, *m);
	else
		vlan_mod_egress_pop_from_pkt(ifp, *m);

	return *m;
}

static inline struct rte_mbuf *
vlan_mod_tag_push(struct ifnet *ifp, struct rte_mbuf **m,
		  struct vlan_mod_ft_cls_action *action,
		  enum vlan_mod_dir dir)
{
	struct rte_mbuf *ret_buf = *m;
	uint16_t tag = action->data.vlan.vlan_id;
	uint8_t  pcp = action->data.vlan.prio;
	bool meta = vlan_mod_meta_data(ret_buf, dir);

	/* If there is meta data vlan info push it into the packet */
	if (meta) {
		ret_buf = vid_encap(ret_buf->vlan_tci, m, ifp->tpid);
		if (!ret_buf)
			return NULL;
	}

	/* If the new vlan protocol to be pushed is not supported in
	 * meta data push the new vlan into the packet, else push it
	 * to the meta data. Meta data vlan info is supported if
	 * the tpid of the new outer tag is the same as ifp->tpid.
	 */
	if (action->data.vlan.proto != ifp->tpid) {
		vlan_mod_clear_txrx_meta_data(*m);
		tag |= (pcp << VLAN_PCP_SHIFT);
		ret_buf = vid_encap(tag, m, action->data.vlan.proto);
	} else {
		vlan_mod_set_vlan_in_meta_data(ret_buf, tag, pcp, dir);
	}

	return ret_buf;
}

static inline struct rte_mbuf *
vlan_mod_tag_modify(struct ifnet *ifp, struct rte_mbuf **m,
		    struct vlan_mod_ft_cls_action *action,
		    enum vlan_mod_dir dir)
{
	uint16_t vlan = action->data.vlan.vlan_id;
	uint8_t  pcp = vlan_mod_get_vlan_pcp(*m, ifp);
	bool meta = vlan_mod_meta_data(*m, dir);
	struct rte_mbuf *ret_buf = *m;

	pcp = vlan_mod_pcp_arbitrate(action, pcp);

	if (action->data.vlan.proto == ifp->tpid) {
		if (meta) {
			/* There is meta data, so the recevied vlan
			 * protocol is the same as ifp->tpid, and the
			 * new protocol is supported in meta data, so
			 * modify the vlan in the meta data.
			 */
			pktmbuf_set_vlan_and_pcp(ret_buf, vlan, pcp);
		} else {
			/* no meta data, and the dest protocol is same
			 * as ifp->tpid, so we need to pop the rx vlan
			 * from the packet as it is different from
			 * ifp->tpid, and store the modified vlan in the
			 * meta deta
			 */
			vid_decap(*m, vlan_mod_alt_proto(ifp->tpid));
			vlan_mod_set_vlan_in_meta_data(ret_buf, vlan, pcp, dir);
		}
		return ret_buf;
	}

	if (meta) {
		/* Different protocols, and we have meta data, so the
		 * outer/modified tpid protocol is not supported in meta
		 * data, so push vlan tag onto packet and clear the
		 * meta data
		 */
		vlan_mod_clear_txrx_meta_data(*m);
		vlan |= (pcp << VLAN_PCP_SHIFT);
		ret_buf = vid_encap(vlan, m, action->data.vlan.proto);
	} else {
		/* Different protocols, and we currently don't have
		 * meta data, so the modified/outer vlan can be stored in
		 * meta data, so pop vlan from the packet and store
		 * resultant vlan be in the meta data
		 */
		vid_decap(*m, vlan_mod_alt_proto(ifp->tpid));
		vlan_mod_set_vlan_in_meta_data(ret_buf, vlan, pcp, dir);
	}
	return ret_buf;
}

static inline struct vlan_mod_ft_cls_action *
vlan_modify_get_action(struct ifnet *ifp, uint16_t vlan,
		       enum vlan_mod_dir dir)
{
	struct vlan_mod_tbl_entry *vlan_mod_tbl;
	struct vlan_mod_tbl_entry *vlan_mod_default;
	struct vlan_mod_ft_cls_action *action;

	vlan_mod_tbl = rcu_dereference(ifp->vlan_mod_tbl);

	if (!vlan_mod_tbl)
		return NULL;

	if (dir == VLAN_MOD_DIR_INGRESS)
		action = rcu_dereference(vlan_mod_tbl[vlan].ingress);
	else
		action = rcu_dereference(vlan_mod_tbl[vlan].egress);
	if (!action) {
		vlan_mod_default = rcu_dereference(ifp->vlan_mod_default);
		if (!vlan_mod_default)
			return NULL;
		if (dir == VLAN_MOD_DIR_INGRESS)
			action = rcu_dereference(vlan_mod_default->ingress);
		else
			action = rcu_dereference(vlan_mod_default->egress);
		if (!action)
			return NULL;
	}

	if (action->action_type != VLAN_MOD_FILTER_CLS_ACTION_VLAN)
		return NULL;
	return action;
}

#endif /* VLAN_MODIFY_H */
