/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * VLAN interface implementation
 */

#include <stdint.h>
#include <rte_debug.h>

#include "ether.h"
#include "dp_event.h"
#include "if_var.h"
#include "qos.h"
#include "vlan_if.h"
#include "vplane_log.h"
#include "fal.h"

/*
 * Set mac address on a vlan, making sure to register the new mac
 * address with the underlying interface if needed, and to unregister
 * the old mac address if needed.
 */
static int vlan_if_set_l2_address(struct ifnet *ifp, uint32_t l2_addr_len,
				  void *l2_addr)
{
	struct rte_ether_addr *macaddr = l2_addr;
	char b1[32], b2[32];

	if (l2_addr_len != RTE_ETHER_ADDR_LEN) {
		RTE_LOG(NOTICE, DATAPLANE,
			"link address is not ethernet (len=%u)!\n",
			l2_addr_len);
		return -EINVAL;
	}

	if (rte_ether_addr_equal(&ifp->eth_addr, macaddr))
		return 1;

	RTE_LOG(INFO, DATAPLANE, "%s change MAC from %s to %s\n",
		ifp->if_name,
		ether_ntoa_r(&ifp->eth_addr, b1),
		ether_ntoa_r(macaddr, b2));

	if (rte_ether_addr_equal(&ifp->if_parent->eth_addr, macaddr)) {
		if (!rte_ether_addr_equal(&ifp->eth_addr, macaddr))
			if_del_l2_addr(ifp, &ifp->eth_addr);
	} else {
		if (!rte_ether_addr_equal(&ifp->eth_addr, macaddr)) {
			if_add_l2_addr(ifp, macaddr);

			if (!rte_ether_addr_equal(&ifp->eth_addr,
					      &ifp->if_parent->eth_addr))
				if_del_l2_addr(ifp, &ifp->eth_addr);
		}
	}

	ifp->eth_addr = *macaddr;

	return 0;
}

static int
vlan_if_add_l2_addr(struct ifnet *ifp, void *l2_addr)
{
	return if_add_l2_addr(ifp->if_parent, l2_addr);
}

static int
vlan_if_del_l2_addr(struct ifnet *ifp, void *l2_addr)
{
	return if_del_l2_addr(ifp->if_parent, l2_addr);
}

static int
vlan_if_start(struct ifnet *ifp)
{
	int ret;

	ret = if_set_vlan_filter(ifp->if_parent, ifp->if_vlan, true);
	if (ret < 0 && ret != -ENOTSUP)
		return ret;
	return 0;
}

static int
vlan_if_stop(struct ifnet *ifp)
{
	int ret;

	ret = if_set_vlan_filter(ifp->if_parent, ifp->if_vlan, false);
	if (ret < 0 && ret != -ENOTSUP)
		return ret;
	return 0;
}

void
vlan_if_delete(struct ifnet *ifp)
{
	struct ifnet *pifp = ifp->if_parent;

	if (pifp->if_vlantbl == NULL)
		rte_panic("if_vlan_delete: missing vlan table?\n");

	/* remove vlan from parent device */
	pifp->if_vlantbl[ifp->if_vlan] = NULL;
	if (!--pifp->vif_cnt) {
		/* reset tag proto back to default */
		if_vlan_proto_set(pifp, ETH_P_8021Q);
	}

	if (!rte_ether_addr_equal(&ifp->eth_addr, &pifp->eth_addr))
		if_del_l2_addr(ifp, &ifp->eth_addr);

	if (ifp->qinq_inner) {
		if_qinq_deleted(pifp->if_parent);
		qos_disable_inner_marking(pifp->if_parent,
					  pifp->if_vlan);
		ifp->qinq_inner = 0;
	}
}

static int
vlan_if_set_promisc(struct ifnet *ifp, bool enable)
{
	ifpromisc(ifp->if_parent, enable);
	return 0;
}

struct ifnet *
vlan_if_create(struct ifnet *ifp, uint16_t vid,
	       const char *ifname, int ifindex, uint16_t vlan_proto)
{
	struct ifnet *vifp;

	if (ifp->if_vlantbl == NULL) {
		if (ifp->if_parent && ifp->if_parent->if_vlantbl) {
			/* create if_vlantbl for q-in-q. */
			ifp->qinq_outer = 1;
			if_setup_vlan_storage(ifp);
		} else {
			RTE_LOG(ERR, DATAPLANE,
				"attempt to create vlan on non-physical device %s\n",
				ifp->if_name);
			return NULL;
		}
	}

	/* does vlan already exist? */
	vifp = ifp->if_vlantbl[vid];
	if (vifp)
		return vifp;

	vifp = if_alloc(ifname, IFT_L2VLAN, ifp->if_mtu, &ifp->eth_addr,
			ifp->if_socket);
	if (vifp) {
		if_port_inherit(ifp, vifp);

		vifp->if_vlan = vid;
		vifp->if_parent = ifp;
		if (ifp->qinq_outer) {
			vifp->qinq_inner = 1;
			if_qinq_created(vifp->if_parent->if_parent);
			qos_enable_inner_marking(ifp->if_parent, ifp->if_vlan);
		}

		if_set_ifindex(vifp, ifindex);
		if_set_vrf(vifp, ifp->if_vrfid);
		rcu_set_pointer(ifp->if_vlantbl + vid, vifp);
		ifp->vif_cnt++;
		if_vlan_proto_set(vifp, vlan_proto);
	}

	return vifp;
}

struct ifnet *
vlan_if_change(struct ifnet *ifp, uint16_t vid, struct ifnet *vifp,
	       uint16_t vlan_proto)
{
	if (vifp->if_vlan)
		vlan_if_delete(vifp);

	if (ifp->if_vlantbl == NULL) {
		if (ifp->if_parent && ifp->if_parent->if_vlantbl) {
			/* create if_vlantbl for q-in-q. */
			ifp->qinq_outer = 1;
			if_setup_vlan_storage(ifp);
		} else {
			RTE_LOG(ERR, DATAPLANE,
				"attempt to change vlan on non-physical device %s\n",
				ifp->if_name);
			return NULL;
		}
	}

	if_port_inherit(ifp, vifp);
	vifp->if_vlan = vid;
	vifp->if_parent = ifp;
	if (ifp->qinq_outer && !vifp->qinq_inner) {
		vifp->qinq_inner = 1;
		if_qinq_created(vifp->if_parent->if_parent);
		qos_enable_inner_marking(ifp->if_parent, ifp->if_vlan);
	}

	if (vid)
		rcu_set_pointer(ifp->if_vlantbl + vid, vifp);

	if_vlan_proto_set(vifp, vlan_proto);

	return vifp;
}

static int
vlan_if_dump(struct ifnet *ifp, json_writer_t *wr,
	     enum if_dump_state_type type)
{
	struct ifnet *ifp_root;

	switch (type) {
	case IF_DS_STATE:
		/*
		 * For backwards compatibility with commands that rely
		 * on this.
		 */
		for (ifp_root = ifp; ifp_root->if_parent;
		     ifp_root = ifp_root->if_parent)
			;
		if (ifp_root->if_type == IFT_ETHER)
			if_dump_state(ifp_root, wr, IF_DS_STATE);

		jsonw_uint_field(wr, "tag", ifp->if_vlan);
		jsonw_uint_field(wr, "tag-proto", if_tpid(ifp));
		break;
	default:
		break;
	}

	return 0;
}

static int
vlan_if_l3_enable(struct ifnet *ifp)
{
	if (!ifp->if_parent)
		return 0;

	return if_fal_create_l3_intf(ifp);
}

static int
vlan_if_l3_disable(struct ifnet *ifp)
{
	return if_fal_delete_l3_intf(ifp);
}

static int
vlan_if_get_stats(struct ifnet *ifp, struct if_data *stats)
{
	int i;
	int ret;
	uint64_t cntrs[FAL_ROUTER_INTERFACE_STAT_MAX];
	enum fal_router_interface_stat_t
		cntr_ids[FAL_ROUTER_INTERFACE_STAT_MAX];

	if (!ifp->fal_l3)
		return 0;

	for (i = FAL_ROUTER_INTERFACE_STAT_MIN;
	     i < FAL_ROUTER_INTERFACE_STAT_MAX; i++)
		cntr_ids[i] = i;

	memset(cntrs, 0, sizeof(cntrs));
	ret = fal_get_router_interface_stats(ifp->fal_l3,
					     FAL_ROUTER_INTERFACE_STAT_MAX,
					     cntr_ids, cntrs);
	if (ret < 0 && ret != -EOPNOTSUPP)
		return ret;

	if (ret != -EOPNOTSUPP) {
		/*
		 * If HW stats aren't supported then not overwriting
		 * these values here will ensure that at least the
		 * software stats are still maintained based on for-us
		 * traffic
		 */
		stats->ifi_ibytes = cntrs[FAL_ROUTER_INTERFACE_STAT_IN_OCTETS];
		stats->ifi_ipackets =
			cntrs[FAL_ROUTER_INTERFACE_STAT_IN_PACKETS];
	}
	/*
	 * Hw doesn't count from-us packets so sum the hw and sw stats here.
	 */
	stats->ifi_obytes += cntrs[FAL_ROUTER_INTERFACE_STAT_OUT_OCTETS];
	stats->ifi_opackets += cntrs[FAL_ROUTER_INTERFACE_STAT_OUT_PACKETS];
	return 0;
}

static enum dp_ifnet_iana_type
vlan_if_iana_type(struct ifnet *ifp __unused)
{
	return DP_IFTYPE_IANA_L2VLAN;
}

static const struct ift_ops vlan_if_ops = {
	.ifop_set_l2_address = vlan_if_set_l2_address,
	.ifop_add_l2_addr = vlan_if_add_l2_addr,
	.ifop_del_l2_addr = vlan_if_del_l2_addr,
	.ifop_start = vlan_if_start,
	.ifop_stop = vlan_if_stop,
	.ifop_l3_disable = vlan_if_l3_disable,
	.ifop_uninit = vlan_if_delete,
	.ifop_set_broadcast = ether_if_set_broadcast,
	.ifop_set_promisc = vlan_if_set_promisc,
	.ifop_dump = vlan_if_dump,
	.ifop_get_stats = vlan_if_get_stats,
	.ifop_l3_enable = vlan_if_l3_enable,
	.ifop_iana_type = vlan_if_iana_type,
};

static void vlan_init(void)
{
	int ret = if_register_type(IFT_L2VLAN, &vlan_if_ops);
	if (ret < 0)
		rte_panic("Failed to register VLAN type: %s", strerror(-ret));
}

/*
 * If an parent interface changes its MAC address we need to register the
 * existing vlan interfaces (different) mac addresses with the parent
 * afterwards. If that doesn't work we use promisc mode as a fallback.
 */
static void
vlan_callback_mac_addr_changed(struct ifnet *ifp, void *arg)
{
	struct ifnet *pifp = arg;

	if (!ifp->if_vlan || ifp->if_parent != pifp)
		return;

	if (!rte_ether_addr_equal(&ifp->eth_addr, &pifp->eth_addr))
		if_add_l2_addr(ifp, &ifp->eth_addr);
	else
		if_del_l2_addr(ifp, &ifp->eth_addr);
}

static void vlan_event_mac_addr_change(struct ifnet *ifp,
				       __unused const void *l2_addr)
{
	/* sync vlan interface mac addresses */
	dp_ifnet_walk(vlan_callback_mac_addr_changed, ifp);
}

static const struct dp_event_ops vlan_events = {
	.init = vlan_init,
	.if_mac_addr_change = vlan_event_mac_addr_change,
};

DP_STARTUP_EVENT_REGISTER(vlan_events);
