/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * Bridge (L2 forwarding)
 */

#include <errno.h>
#include <libmnl/libmnl.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <netinet/ip.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <urcu/uatomic.h>

#include "arp.h"
#include "bridge.h"
#include "bridge_flags.h"
#include "bridge_vlan_set.h"
#include "capture.h"
#include "compat.h"
#include "config_internal.h"
#include "control.h"
#include "dp_event.h"
#include "ether.h"
#include "fal.h"
#include "fal_plugin.h"
#include "if/gre.h"
#include "if/vxlan.h"
#include "if_var.h"
#include "json_writer.h"
#include "main.h"
#include "mstp.h"
#include "netinet6/nd6_nbr.h"
#include "netlink.h"
#include "npf/npf.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_if.h"
#include "npf_shim.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pktmbuf_internal.h"
#include "pl_node.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "l2_rx_fltr.h"

struct bridge_port;
struct bridge_vlan_set;

/* TODO These constants are from BSD, and should be revisited? */
/* Size of the bridge forwarding table.	 Must be a power of two. */
#define	BRIDGE_RTHASH_MIN	32
#define	BRIDGE_RTHASH_BITS	13
#define	BRIDGE_RTHASH_MAX	(1<<BRIDGE_RTHASH_BITS)

#define	BRIDGE_RTABLE_PRUNE_PERIOD 2 /* secs between each expire tick */
#define	BRIDGE_RTABLE_EXPIRE	(300 / BRIDGE_RTABLE_PRUNE_PERIOD)
#define BRIDGE_AGEING_TIME_MIN	10
#define BRIDGE_AGEING_TIME_MAX	1000000

/* Enable/disable fragmentation on L2 GRE bridge intf */
static bool bridge_frag_enable = true;

static const char *bridge_ifstate_names[STP_IFSTATE_SIZE] = {
	[STP_IFSTATE_DISABLED]	 = "DISABLED",
	[STP_IFSTATE_LISTENING]	 = "LISTENING",
	[STP_IFSTATE_LEARNING]	 = "LEARNING",
	[STP_IFSTATE_FORWARDING] = "FORWARDING",
	[STP_IFSTATE_BLOCKING]	 = "BLOCKING",
};

/*
 * Cisco-specific PVST (per-vlan BPDU) multicast address
 */
static const struct rte_ether_addr pvst_mcast_address = {
	.addr_bytes = {0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd},
};

/*
 * Indicates if the platform includes hardware that always processes
 * (floods) received PVST frames or if the frames are always punted
 * for processing by us (see bridge_flood_local()).
 */
static bool bridge_pvst_flood_local;

/* Forwarding table */
#define	IFBAF_TYPEMASK	0x07	/* address type mask */
#define	IFBAF_DYNAMIC	0x01	/* dynamically learned address */
#define	IFBAF_STATIC	0x02	/* static address */
#define	IFBAF_LOCAL	0x04	/* address of local interface */
#define	IFBAF_ALL       IFBAF_TYPEMASK

static void bridge_newneigh(int ifindex, const struct rte_ether_addr *dst,
			    uint16_t state, uint16_t vlan);
static void bridge_timer(struct rte_timer *, void *);

static bool bridge_intf_is_virt(struct ifnet *ifp)
{
	return (ifp->if_type == IFT_TUNNEL_GRE ||
		(ifp->if_type == IFT_L2TPETH ||
		 (ifp->if_parent && ifp->if_parent->if_type == IFT_L2TPETH)));
}

static bool bridge_pkt_exceeds_mtu(struct rte_mbuf *m,
					  struct ifnet *out_ifp)
{
	if (rte_pktmbuf_pkt_len(m) - ETHER_HDR_LEN > out_ifp->if_mtu) {
		/*
		 * Transparent bridge shouldn't be doing any form of pkt
		 * manipulation, fragmentation or otherwise, but because the
		 * linux kernel does this on a 5400, the customer has requested
		 * we match this behaviour on the DP based VROUTER as well.
		 */
		if (bridge_intf_is_virt(out_ifp) && bridge_frag_enable)
			return false;
		else
			return true;
	}
	return false;

}

static uint16_t
bridge_frame_get_vlan(struct rte_mbuf *m)
{
	if (m->ol_flags & PKT_RX_VLAN)
		return pktmbuf_get_rxvlanid(m);
	return pktmbuf_get_txvlanid(m);
}

static void
bridge_frame_add_rx_vlan(struct rte_mbuf *m, uint16_t vid)
{
	/*
	 * In VLAN aware bridging mode, all frames will have a
	 * VLAN if it is '0' it will be tagged with the PVID
	 * or dropped.
	 */
	m->ol_flags |= PKT_RX_VLAN;
	m->vlan_tci &= ~VLAN_VID_MASK;
	m->vlan_tci |= vid;
}

static void
bridge_frame_rx_vlan_to_tx_vlan(struct rte_mbuf *m)
{
	/*
	 * In VLAN aware bridging mode, frames can't "jump" VLANs,
	 * and all frames have a VLAN (or will be dropped).
	 * So, just turn the RX VLAN into the TX VLAN
	 */
	pktmbuf_convert_rx_to_tx_vlan(m);
}

static void
bridge_frame_remove_tx_vlan(struct rte_mbuf *m)
{
	pktmbuf_clear_tx_vlan(m);
}


static void
bridge_tag_pvid(const struct ifnet *br_ifp,
	struct ifnet *input_ifp, struct rte_mbuf *m)
{
	struct bridge_softc *sc = br_ifp->if_softc;
	if (!sc->scbr_vlan_filter)
		return;

	/* Frame is already tagged, skip PVID. */
	if (bridge_frame_get_vlan(m) != 0)
		return;

	struct bridge_port *port = rcu_dereference(input_ifp->if_brport);
	if (port == NULL)
		return;

	uint16_t pvid = bridge_port_get_pvid(port);

	/* No PVID let this frame will be dropped by the filter */
	if (pvid == 0)
		return;

	bridge_frame_add_rx_vlan(m, pvid);
}

static bool
bridge_is_allowed_vlan(const struct ifnet *br_ifp,
	struct ifnet *ifp, uint16_t vlan)
{
	struct bridge_softc *sc = br_ifp->if_softc;
	if (!sc->scbr_vlan_filter)
		return true;

	struct bridge_port *port = rcu_dereference(ifp->if_brport);
	if (port == NULL)
		return false;
	return bridge_port_lookup_vlan(port, vlan);
}

static void
bridge_untag_vlan(const struct ifnet *br_ifp,
	struct ifnet *out_ifp, struct rte_mbuf *m)
{
	struct bridge_softc *sc = br_ifp->if_softc;
	if (!sc->scbr_vlan_filter)
		return;

	uint16_t vid = bridge_frame_get_vlan(m);
	struct bridge_port *port = rcu_dereference(out_ifp->if_brport);
	if (port == NULL)
		return;

	if (!bridge_port_lookup_untag_vlan(port, vid))
		return;

	bridge_frame_remove_tx_vlan(m);
}

static void if_vlan_in_stats_incr(struct ifnet *ifp,
				  struct bridge_softc *sc,
				  uint16_t vlan,
				  struct rte_mbuf *m)
{
	unsigned int lcore;
	struct bridge_vlan_stat_block *stats;

	/* HW ports will count this in HW */
	if (ifp->hw_forwarding)
		return;

	if (!sc->scbr_vlan_filter)
		/* Is a bridge not a switch */
		return;

	stats = rcu_dereference(sc->vlan_stats[vlan]);
	if (!stats)
		return;

	lcore = dp_lcore_id();
	stats->stats[lcore].rx_octets += rte_pktmbuf_pkt_len(m);
	stats->stats[lcore].rx_pkts++;
}

static void if_vlan_out_stats_incr(struct bridge_softc *sc,
				   uint16_t vlan,
				   struct rte_mbuf *m)
{
	unsigned int lcore;
	struct bridge_vlan_stat_block *stats;

	/* HW ports will not count this in HW */
	stats = rcu_dereference(sc->vlan_stats[vlan]);
	if (!stats)
		return;

	lcore = dp_lcore_id();
	stats->stats[lcore].tx_octets += rte_pktmbuf_pkt_len(m);
	stats->stats[lcore].tx_pkts++;
}

static void if_vlan_out_drop_stats_incr(struct bridge_softc *sc,
					uint16_t vlan)
{
	struct bridge_vlan_stat_block *stats;

	if (!sc->scbr_vlan_filter)
		/* Is a bridge not a switch */
		return;

	stats = rcu_dereference(sc->vlan_stats[vlan]);
	if (!stats)
		return;

	stats->stats[dp_lcore_id()].tx_drops++;
}

static void
bridge_tx_frame(struct ifnet *br_ifp, struct ifnet *in_ifp,
		struct ifnet *out_ifp, struct rte_mbuf *m)
{
	struct bridge_softc *sc = br_ifp->if_softc;
	if (!sc)
		goto drop;

	if (sc->scbr_vlan_filter) {
		uint16_t vlan = bridge_frame_get_vlan(m);

		/*
		 * This is expected when flooding so don't increment
		 * the drop counter for this. If there are no
		 * interfaces with the VLAN allowed then it is
		 * equivalent to having a bridge with no members,
		 * which shouldn't be an error situation.
		 */
		if (!bridge_is_allowed_vlan(br_ifp, out_ifp, vlan))
			goto drop_no_stat;
		/*
		 * Translate a RX VLAN to a TX VLAN
		 * now that we know it is allowed
		 */
		bridge_frame_rx_vlan_to_tx_vlan(m);
		bridge_untag_vlan(br_ifp, out_ifp, m);
		if_vlan_out_stats_incr(sc, vlan, m);
	}

	if_output(out_ifp, m, in_ifp, ETH_P_TEB);
	return;
drop:
	if_incr_dropped(br_ifp);
drop_no_stat:
	rte_pktmbuf_free(m);
}

static inline bool
bridge_is_ifstate_valid(uint8_t brstate)
{
	return brstate <= STP_IFSTATE_MAX;
}

const char *
bridge_get_ifstate_string(uint8_t brstate)
{
	if (bridge_is_ifstate_valid(brstate))
		return bridge_ifstate_names[brstate];
	else
		return "UNKNOWN";
}

static inline bool
bridge_mac_is_dynamic(const struct bridge_rtnode *brt)
{
	return (brt->brt_flags & IFBAF_TYPEMASK) ==
		IFBAF_DYNAMIC;
}

static inline bool
bridge_mac_is_static(const struct bridge_rtnode *brt)
{
	return (brt->brt_flags & IFBAF_TYPEMASK) ==
		IFBAF_STATIC;
}

static inline bool
bridge_mac_is_local(const struct bridge_rtnode *brt)
{
	return (brt->brt_flags & IFBAF_TYPEMASK) ==
		IFBAF_LOCAL;
}

static inline int bridge_key_equal(const struct bridge_key *k1,
	const struct bridge_key *k2)
{
	return rte_ether_addr_equal(&k1->addr, &k2->addr) &&
		k1->vlan == k2->vlan;
}

static inline unsigned long bridge_key_hash(const struct bridge_key *key)
{
	uint64_t val = shift16(*(const uint64_t *) &key->addr);
	val = val | key->vlan;
	return hash64(val, BRIDGE_RTHASH_BITS);
}

static int bridge_rtnode_match(struct cds_lfht_node *node, const void *key)
{
	const struct bridge_rtnode *brt
		= caa_container_of(node, const struct bridge_rtnode, brt_node);

	return bridge_key_equal(&brt->brt_key, key);
}

/*
 * Lookup route node in hash table
 *
 *	Look up a bridge route node for the specified destination.
 */
static struct bridge_rtnode *
bridge_rtnode_lookup(struct bridge_softc *sc,
	const struct rte_ether_addr *addr, uint16_t vid)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	/* Use VLAN id 0 if bridge is not VLAN aware */
	if (!sc->scbr_vlan_filter)
		vid = 0;

	struct bridge_key key = { .addr = *addr, .vlan = vid };
	cds_lfht_lookup(sc->scbr_rthash,
		bridge_key_hash(&key),
		bridge_rtnode_match, &key, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct bridge_rtnode, brt_node);
	else
		return NULL;
}

/*
 * bridge_rtnode_insert:
 *
 *	Insert the specified bridge node into the route table.
 */
static int
bridge_rtnode_insert(struct bridge_softc *sc, struct bridge_rtnode *brt)
{
	struct cds_lfht_node *ret_node;

	cds_lfht_node_init(&brt->brt_node);

	/* Use VLAN id 0 if bridge is not VLAN aware */
	if (!sc->scbr_vlan_filter)
		brt->brt_key.vlan = 0;

	ret_node = cds_lfht_add_unique(sc->scbr_rthash,
				       bridge_key_hash(&brt->brt_key),
				       bridge_rtnode_match, &brt->brt_key,
				       &brt->brt_node);
	return (ret_node != &brt->brt_node) ? EEXIST : 0;
}

/*
 * Update existing forwarding table entry
 */
static void
bridge_rtupdate(struct ifnet *ifp,
	const struct rte_ether_addr *dst,
	uint16_t vlan)
{
	struct bridge_softc *sc =
		bridge_port_get_bridge(ifp->if_brport)->if_softc;
	struct bridge_rtnode *brt;
	/* set attr.state to dynamic ie !NUD_PERMANENT and !NUD_NOARP */
	struct fal_attribute_t attr = {
		FAL_BRIDGE_NEIGH_ATTR_STATE, .value.u16 = 0};

	if (ifp->if_type == IFT_TUNNEL_GRE) {
		/* We shouldn't get in here for tunnels but JIC.
		 *
		 * We rely on the GRE tunnel code to update bridging entries as
		 * it knows about the src IP address of the transport layer.
		 * This is crucial in case of MP GRE tunnels where the spoke is
		 * identified by its transport IP address
		 */
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "bridge_rtupdate: Bridge rt notif for tunnel interface %s\n",
			 ifp->if_name);
		return;
	}

	/*
	 * A route for this destination might already exist.  If so,
	 * update it.
	 */
	brt = bridge_rtnode_lookup(sc, dst, vlan);
	if (unlikely(brt == NULL)) {
		brt = zmalloc_aligned(sizeof(*brt));
		if (unlikely(brt == NULL))
			return;

		brt->brt_difp = ifp;
		brt->brt_flags = IFBAF_DYNAMIC;
		brt->brt_key.addr = *dst;
		brt->brt_key.vlan = vlan;
		brt->brt_expire = 0;

		if (unlikely(bridge_rtnode_insert(sc, brt) != 0)) {
			free(brt);
			return;
		}
		fal_br_new_neigh(ifp->if_index, vlan, dst, 1, &attr);
	} else if ((brt->brt_flags & IFBAF_TYPEMASK) == IFBAF_DYNAMIC) {
		if (unlikely(brt->brt_difp != ifp)) {
			fal_br_upd_neigh(ifp->if_index, vlan, dst, &attr);
			brt->brt_difp = ifp;
		}
	}

	/* Entry is marked used */
	rte_atomic32_clear(&brt->brt_unused);
}

static void
bridge_rtnode_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct bridge_rtnode, brt_rcu));
}

/*
 * bridge_rtnode_destroy:
 *
 *	Destroy a bridge rtnode.
 */
static void
bridge_rtnode_destroy(struct cds_lfht *table, struct bridge_rtnode *brt)
{
	if (!cds_lfht_del(table, &brt->brt_node))
		call_rcu(&brt->brt_rcu, bridge_rtnode_free);
}

/*
 * Create lock free hash table.
 * For now, just use static sized table, and no additional flags.
 */
static void
bridge_rtable_init(struct bridge_softc *sc)
{
	sc->scbr_rthash = cds_lfht_new(BRIDGE_RTHASH_MIN,
				       BRIDGE_RTHASH_MIN,
				       BRIDGE_RTHASH_MAX,
				       CDS_LFHT_AUTO_RESIZE,
				       NULL);
	if (sc->scbr_rthash == NULL)
		rte_panic("Can't allocate rthash\n");
}

int
bridge_newneigh_tunnel(struct bridge_port *brport,
		       const struct rte_ether_addr *dst,
		       in_addr_t dst_ip, uint16_t vlan)
{
	struct ifnet *ifp = bridge_port_get_interface(brport);
	struct ifnet *ifm;
	struct bridge_softc *sc;
	struct bridge_rtnode *brt;
	int err;

	ifm = bridge_port_get_bridge(brport);
	sc = ifm->if_softc;
	brt = bridge_rtnode_lookup(sc, dst, vlan);
	if (brt) {
		/* update exist entry */
		brt->brt_flags = IFBAF_DYNAMIC;
		brt->brt_difp = ifp;
		brt->brt_dip = dst_ip;
		return 0;
	}

	brt = zmalloc_aligned(sizeof(*brt));
	if (!brt) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "out of memory for forwarding entry\n");
		return -ENOMEM;
	}

	brt->brt_difp = ifp;
	brt->brt_key.addr = *dst;
	brt->brt_key.vlan = vlan;
	brt->brt_dip = dst_ip;
	brt->brt_flags = IFBAF_DYNAMIC;
	brt->brt_expire = 0;

	err = bridge_rtnode_insert(sc, brt);
	if (err) {
		/* already created (race) */
		free(brt);
		return err;
	}
	rte_atomic32_clear(&brt->brt_unused);
	return 0;
}

fal_object_t bridge_fal_stp_object(const struct ifnet *ifp)
{
	struct bridge_softc *sc = ifp->if_softc;

	return sc->stp;
}

static void bridge_upd_hw_forwarding(const struct ifnet *ifp)
{
	/*
	 * If this interface is part of a switch/bridge, let the FAL
	 * spanning tree module know that the hardware forwarding
	 * state has change.
	 */
	if (ifp->if_brport != NULL) {
		const struct ifnet *bridge =
			bridge_port_get_bridge(ifp->if_brport);

		fal_stp_upd_hw_forwarding(bridge_fal_stp_object(bridge),
					  ifp->if_index,
					  ifp->hw_forwarding);
		mstp_upd_hw_forwarding(bridge, ifp);
	}
}

/* Create bridge in response to netlink */
struct ifnet *bridge_create(int ifindex, const char *ifname,
			    unsigned int mtu,
			    const struct rte_ether_addr *addr)
{
	struct ifnet *ifp;
	struct bridge_softc *sc;

	ifp = dp_ifnet_byifname(ifname);
	/* existing interface, reuse it */
	if (ifp != NULL) {
		DP_DEBUG(BRIDGE, DEBUG, BRIDGE,
			"reusing old interface: %s\n", ifp->if_name);
		if_unset_ifindex(ifp); /* if_set_ifindex does this. */
		if_set_ifindex(ifp, ifindex);
		return ifp;
	}

	if (addr == NULL) {
		RTE_LOG(NOTICE, BRIDGE, "missing mac address\n");
		return NULL;
	}

	ifp = if_alloc(ifname, IFT_BRIDGE, mtu, addr, SOCKET_ID_ANY);
	if (!ifp) {
		RTE_LOG(NOTICE, BRIDGE, "out of memory to create %s\n",
			ifname);
		return NULL;
	}

	sc = ifp->if_softc;

	if_set_ifindex(ifp, ifindex);
	if (!if_setup_vlan_storage(ifp)) {
		if_free(ifp);
		return NULL;
	}

	const struct fal_attribute_t attr_list[2] = {
		{FAL_STP_ATTR_INSTANCE, .value.u8 = STP_INST_IST},
		{FAL_STP_ATTR_MSTI, .value.u16 = MSTP_MSTI_IST}
	};

	int rc = fal_stp_create(ifindex, 2, &attr_list[0], &sc->stp);
	if (rc < 0)
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "FAL(%u): failed to create STP: '%s'\n",
			 ifindex, strerror(-rc));

	return ifp;
}

static void bridge_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct bridge_softc, scbr_rcu));
}

static void
free_vlan_stats(struct rcu_head *head)
{
	free(caa_container_of(head, struct bridge_vlan_stat_block,
			      vlan_stats_rcu));
}

/* Update bridge in response to netlink */
void bridge_update(const char *ifname, struct nl_bridge_info *br_info)
{
	struct ifnet *ifp;
	struct bridge_softc *sc;
	uint32_t cur_ageing_time;

	ifp = dp_ifnet_byifname(ifname);
	if (ifp == NULL || ifp->if_softc == NULL)
		return;

	sc = ifp->if_softc;

	/*
	 * MAC FDB ageing time.  Setting to 0 means no ageing of dynamic
	 * entries.  Otherwise range is 10-1000000
	 */
	cur_ageing_time = sc->scbr_ageing_ticks * BRIDGE_RTABLE_PRUNE_PERIOD;

	if (cur_ageing_time != br_info->br_ageing_time &&
	    (br_info->br_ageing_time == 0 ||
	     (br_info->br_ageing_time >= BRIDGE_AGEING_TIME_MIN &&
	      br_info->br_ageing_time <= BRIDGE_AGEING_TIME_MAX))) {
		struct fal_attribute_t aging_update = {
			.id = FAL_PORT_ATTR_FDB_AGING_TIME,
			.value.u32 = br_info->br_ageing_time
		};

		sc->scbr_ageing_ticks = br_info->br_ageing_time /
			BRIDGE_RTABLE_PRUNE_PERIOD;
		DP_DEBUG(BRIDGE, DEBUG, BRIDGE,
			 "Ageing time %u -> %u\n",
			 cur_ageing_time,
			 sc->scbr_ageing_ticks * BRIDGE_RTABLE_PRUNE_PERIOD);
		fal_l2_upd_port(ifp->if_index, &aging_update);
	}

	DP_DEBUG(BRIDGE, INFO, BRIDGE,
		"bridge_update(%s) vlan_filter=%s, default_pvid=%u\n",
		 ifname,
		 br_info->br_vlan_filter?"true":"false",
		 br_info->br_vlan_default_pvid);


	if (br_info->br_vlan_filter)
		sc->scbr_vlan_filter = true;
	if (br_info->br_vlan_default_pvid)
		sc->scbr_vlan_default_pvid = br_info->br_vlan_default_pvid;
}


static int bridge_if_init(struct ifnet *ifp)
{
	struct bridge_softc *sc;

	sc = zmalloc_aligned(sizeof(*sc));
	if (!sc)
		return -ENOMEM;

	CDS_INIT_LIST_HEAD(&sc->scbr_porthead);
	bridge_rtable_init(sc);

	rte_timer_init(&sc->scbr_timer);
	rte_timer_reset(&sc->scbr_timer,
			rte_get_timer_hz() * BRIDGE_RTABLE_PRUNE_PERIOD,
			PERIODICAL, rte_get_master_lcore(),
			bridge_timer, sc);
	sc->scbr_ageing_ticks = BRIDGE_RTABLE_EXPIRE;

	ifp->if_softc = sc;

	return 0;
}

static void bridge_if_uninit(struct ifnet *ifp)
{
	struct bridge_softc *sc = ifp->if_softc;
	struct cds_list_head *entry;
	struct bridge_port *brport;
	struct bridge_vlan_stat_block *stats;
	int i;

	if (!sc)
		return;

	/* Delete the member pointers to the bridge */
	bridge_for_each_brport(brport, entry, sc) {
		struct ifnet *dif = bridge_port_get_interface(brport);

		rcu_assign_pointer(dif->if_brport, NULL);
		bridge_port_destroy(brport);
	}

	fal_stp_delete(bridge_fal_stp_object(ifp));

	rte_timer_stop(&sc->scbr_timer);
	cds_lfht_destroy(sc->scbr_rthash, NULL);

	/* make sure all vlan stats storage is cleaned up */
	for (i = 0; i < VLAN_N_VID; i++) {
		if (sc->vlan_stats[i]) {
			stats = rcu_xchg_pointer(&sc->vlan_stats[i], NULL);
			if (stats)
				call_rcu(&stats->vlan_stats_rcu,
					 free_vlan_stats);
		}
	}

	call_rcu(&sc->scbr_rcu, bridge_free);
}

static bool
bridge_can_create_in_fal(struct ifnet *ifp)
{
	/*
	 * Ignore our own feature, and still create in the FAL with
	 * hardware switching disabled since the FAL needs this
	 * programming to aid the operation.
	 */
	return !if_check_any_except_emb_feat(
		ifp, IF_EMB_FEAT_BRIDGE_MEMBER |
		IF_EMB_FEAT_HW_SWITCHING_DISABLED);
}

/* Add port in response to netlink */
static void bridge_newport(int ifindex, const char *name,
			   int ifmaster, uint8_t state,
			   struct rte_ether_addr *lladdr)
{
	struct ifnet *ifm, *ifp;
	struct fal_attribute_t attr_list[1] = {
		{ FAL_BRIDGE_PORT_ATTR_STATE, .value.u8 = state },
	};

	ifm = dp_ifnet_byifindex(ifmaster);
	if (!ifm) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			"bridge_newport: can't find master for ifindex %d\n",
			ifmaster);
		return;
	}
	if  (ifm->if_type != IFT_BRIDGE)
		rte_panic("bridge_newport: ifmaster %d is type %#x\n",
				  ifmaster, ifm->if_type);

	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			"bridge_newport: can't find interface for ifindex %d\n",
			 ifindex);
		return;
	}

	if (ifp->if_brport) {
		if (bridge_port_get_bridge(ifp->if_brport) == ifm) {
			if (bridge_port_get_state(ifp->if_brport) != state) {
				/* Update state of existing port */
				DP_DEBUG(BRIDGE, INFO, BRIDGE,
					 "%s changed state to %s\n", name,
					 bridge_get_ifstate_string(state));
				bridge_port_set_state(ifp->if_brport, state);
				if (bridge_port_is_fal_created(ifp->if_brport))
					fal_br_upd_port(ifindex,
							&attr_list[0]);
			}
		} else {
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				"%s is already part of existing bridge %s\n",
				ifp->if_name, ifm->if_name);
		}

	} else {
		struct bridge_softc *sc = ifm->if_softc;

		struct bridge_port *port = bridge_port_create(ifp, ifm);
		if (!port) {
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				"bridge_newport: can't allocate new bridge port\n");
			return;
		}

		/* Add new bridge port */
		DP_DEBUG(BRIDGE, INFO, BRIDGE, "add port %s to %s\n",
			 ifp->if_name, ifm->if_name);

		pl_node_add_feature_by_inst(&bridge_in_feat, ifp);

		rcu_assign_pointer(ifp->if_brport, port);
		bridge_port_add_to_list(port, &sc->scbr_porthead);

		if_notify_emb_feat_change(ifp);

		ifpromisc(ifp, 1);

		if (bridge_can_create_in_fal(ifp)) {
			fal_br_new_port(ifmaster, ifindex, 1, attr_list);
			bridge_port_set_fal_created(ifp->if_brport, true);
		} else
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				"%s deferring signalling of newport in FAL\n",
				ifp->if_name);

		bridge_port_set_state(ifp->if_brport, state);
	}

	if (lladdr)
		bridge_newneigh(ifindex, lladdr, NUD_PERMANENT, 0);
}

/*
 * Flush FDB for a specified interface, or for all interfaces.  Only flush
 * entries specified by fdb_type mask.
 */
static void
bridge_fdb_flush(struct ifnet *bridge, struct ifnet *ifp,
		 uint8_t fdb_type, uint16_t vlanid, bool flush_fal)
{
	struct bridge_softc *sc = bridge->if_softc;
	struct cds_lfht_iter iter;
	struct bridge_rtnode *brt;

	cds_lfht_for_each_entry(sc->scbr_rthash, &iter, brt, brt_node) {
		if ((ifp == NULL || brt->brt_difp == ifp) &&
		    (vlanid == 0 || brt->brt_key.vlan == vlanid) &&
		    (brt->brt_flags & fdb_type) != 0)
			bridge_rtnode_destroy(sc->scbr_rthash, brt);
	}

	if (flush_fal)
		fal_fdb_flush(bridge->if_index,
			      (ifp == NULL) ? 0 : ifp->if_index,
			      vlanid,
			      (fdb_type & IFBAF_TYPEMASK) == IFBAF_DYNAMIC);
}

void bridge_fdb_dynamic_flush_vlan(struct ifnet *bridge, struct ifnet *port,
				   uint16_t vlanid)
{
	bridge_fdb_flush(bridge, port, IFBAF_DYNAMIC, vlanid, true);
}

static void bridge_fal_delport(struct ifnet *ifp)
{
	struct bridge_port *brport;
	struct ifnet *ifm;
	bool fal_created;

	brport = rcu_dereference(ifp->if_brport);
	if (!brport)
		return;

	ifm = bridge_port_get_bridge(brport);
	fal_created = bridge_port_is_fal_created(brport);

	if (fal_created) {
		fal_fdb_flush(ifm->if_index, ifp->if_index, 0, false);
		fal_br_del_port(ifm->if_index, ifp->if_index);
		bridge_port_set_fal_created(brport, false);
	}
}

static void bridge_fal_newport(struct ifnet *ifp)
{
	struct bridge_port *brport;
	struct ifnet *ifm;
	bool fal_created;

	brport = rcu_dereference(ifp->if_brport);
	if (!brport)
		return;

	ifm = bridge_port_get_bridge(brport);
	fal_created = bridge_port_is_fal_created(brport);

	if (!fal_created) {
		struct bridge_vlan_set *vlans = bridge_vlan_set_create();
		struct bridge_vlan_set *untagged = bridge_vlan_set_create();
		struct fal_attribute_t attr_list[] = {
			{ .id = FAL_BRIDGE_PORT_ATTR_STATE,
			  .value.u8 = bridge_port_get_state(brport) },
			{ .id = FAL_BRIDGE_PORT_ATTR_TAGGED_VLANS,
			  .value.ptr = vlans },
			{ .id = FAL_BRIDGE_PORT_ATTR_UNTAGGED_VLANS,
			  .value.ptr = untagged },
			{ .id = FAL_BRIDGE_PORT_ATTR_PORT_VLAN_ID,
			  .value.u16 = bridge_port_get_pvid(brport) },
		};
		if (vlans && untagged) {
			bridge_port_get_vlans(brport, vlans);
			bridge_port_get_untag_vlans(brport, untagged);

			fal_br_new_port(ifm->if_index, ifp->if_index,
					ARRAY_SIZE(attr_list), attr_list);
			bridge_port_set_fal_created(ifp->if_brport, true);

			bridge_vlan_set_free(vlans);
			bridge_vlan_set_free(untagged);
		} else
			RTE_LOG(ERR, BRIDGE,
				"out of memory allocating vlan sets during FAL newport signalling\n");
	}
}

static void bridge_if_feat_mode_change(
	struct ifnet *ifp, enum if_feat_mode_event event)
{
	switch (event) {
	case IF_FEAT_MODE_EVENT_L2_FAL_ENABLED:
	case IF_FEAT_MODE_EVENT_L2_FAL_DISABLED:
		bridge_upd_hw_forwarding(ifp);
		break;
	case IF_FEAT_MODE_EVENT_EMB_FEAT_CHANGED:
		if (bridge_can_create_in_fal(ifp))
			bridge_fal_newport(ifp);
		else
			bridge_fal_delport(ifp);
		break;
	default:
		break;
	}
}

static void bridge_delport(int ifindex, int ifmaster)
{
	struct ifnet *ifp, *ifm;
	struct bridge_port *brport;
	bool fal_created;

	ifm = dp_ifnet_byifindex(ifmaster);
	if (!ifm) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			"bridge_delport: can't find master for ifindex %d\n",
			ifmaster);
		return;
	}
	if  (ifm->if_type != IFT_BRIDGE)
		rte_panic("bridge_delport: ifmaster %d is type %#x\n",
			  ifmaster, ifm->if_type);

	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			"bridge_delport: can't find bridge port for ifindex %d\n",
			ifindex);
		return;
	}

	brport = rcu_dereference(ifp->if_brport);
	if (!brport || bridge_port_get_bridge(brport) != ifm) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			"%s: is not a member of bridge %s\n",
			ifp->if_name, ifm->if_name);
		return;
	}

	DP_DEBUG(BRIDGE, INFO, BRIDGE, "remove %s from %s\n",
		 ifp->if_name, ifm->if_name);

	pl_node_remove_feature_by_inst(&bridge_in_feat, ifp);

	rcu_assign_pointer(ifp->if_brport, NULL);
	fal_created = bridge_port_is_fal_created(brport);
	bridge_port_destroy(brport);

	ifpromisc(ifp, 0);
	bridge_fdb_flush(ifm, ifp, IFBAF_ALL, 0, fal_created);
	if (fal_created)
		fal_br_del_port(ifm->if_index, ifp->if_index);

	if_notify_emb_feat_change(ifp);
}

static void
bridge_forward_via_tunnel(struct ifnet *br_ifp,
	struct ifnet *ifp, struct ifnet *difp,
	in_addr_t *dip, struct rte_mbuf *m)
{
	struct bridge_softc *sc = br_ifp->if_softc;
	if (sc->scbr_vlan_filter) {
		uint16_t vlan = bridge_frame_get_vlan(m);
		if (!bridge_is_allowed_vlan(br_ifp, difp, vlan))
			goto drop;
		bridge_untag_vlan(br_ifp, difp, m);
		if_vlan_out_stats_incr(sc, vlan, m);
	}

	gre_tunnel_fragment_and_send(ifp, difp, dip, m, ETH_P_TEB);
	return;

drop:
	if_incr_dropped(br_ifp);
	rte_pktmbuf_free(m);
	return;
}

/*
 * bridge_forward:
 *
 *	The forwarding function of the bridge.
 *
 * returns 1 if packet is completely handled,
 *	   0 if needs to continue on slowpath
 */
static int
bridge_forward(struct bridge_softc *sc, struct ifnet *ifp,
	       struct rte_mbuf *m, struct ifnet *brif)
{
	const struct ether_hdr *eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
	struct bridge_rtnode *brt;
	struct ifnet *dif;
	struct bridge_port *port = NULL;

	uint16_t vlan = bridge_frame_get_vlan(m);

	/*
	 * At this point, the port either doesn't participate
	 * in spanning tree or it is in the forwarding state.
	 */
	brt = bridge_rtnode_lookup(sc, &eh->d_addr, vlan);
	if (brt == NULL)
		return BRIDGE_PASS;	/* packet needs to be flooded */

	/* Don't loop packet back out same interface */
	dif = brt->brt_difp;
	port = rcu_dereference(dif->if_brport);
	if (!port)
		goto drop;

	if (unlikely(ifp == dif)) {
		goto drop;
	}

	/*
	 * At this point, we're dealing with a unicast frame
	 * going to a different interface.
	 */
	if (bridge_port_get_state_vlan(port, vlan) != STP_IFSTATE_FORWARDING)
		goto drop;

	/*
	 * When bridging packets that are oversize are dropped.
	 * This can happen when bridging between interfaces with different
	 * mtu's.
	 */
	if (bridge_pkt_exceeds_mtu(m, dif))
		goto drop;	/* XXX add stat for this */

	if_incr_out(brif, m);

	if (unlikely(brif->capturing && brif->cap_info->is_promisc))
		capture_burst(brif, &m, 1);

	/* Mark entry as used */
	rte_atomic32_clear(&brt->brt_unused);

	if (dif->if_type == IFT_TUNNEL_GRE)
		bridge_forward_via_tunnel(brif, ifp, dif, &brt->brt_dip, m);
	else
		bridge_tx_frame(brif, ifp, dif, m);

	return BRIDGE_CONSUMED;

drop:
	if_incr_full_proto(brif, 1);
	if_vlan_out_drop_stats_incr(sc, vlan);
	{
		struct pl_packet pkt = {
			.mbuf = m,
			.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(m),
			.in_ifp = ifp
		};
		pipeline_fused_term_drop(&pkt);
	}
	return BRIDGE_CONSUMED;
}

static void
bridge_gre_clone_and_send(struct ifnet *ifp,
			  struct mgre_rt_info *remote, void *arg)
{
	struct rte_mbuf *n, *m = arg;

	n = pktmbuf_clone(m, m->pool);
	if (unlikely(!n))
		return;

	gre_tunnel_fragment_and_send(NULL, ifp, &remote->iph.daddr, n,
				     ETH_P_TEB);
}

/*
 * Flood on to a tunnel.
 */
static void bridge_flood_on_gre_tunnel(struct ifnet *out_if,
				       struct rte_mbuf *m)
{
	gre_tunnel_peer_walk(out_if, bridge_gre_clone_and_send, m);
}

/* Flood packets on locally hosted interfaces belonging to bridge. */
static void bridge_flood_local(struct bridge_softc *sc, struct ifnet *in_ifp,
			       struct rte_mbuf *m, struct ifnet *br_ifp,
			       bool is_pvst)
{
	struct ifnet *dif, *lastif = NULL;
	struct cds_list_head *entry;
	struct bridge_port *port;
	bool input_hw_fwded;

	if (in_ifp)
		input_hw_fwded = in_ifp->hw_forwarding;
	else
		input_hw_fwded = false;

	/*
	 * The hardware platforms process PVST BPDUs differently. Some
	 * process (flood) the frames others always punt forcing us to
	 * perform the flooding.
	 */
	if (input_hw_fwded && is_pvst && bridge_pvst_flood_local)
		input_hw_fwded = false;

	uint16_t vlan = bridge_frame_get_vlan(m);

	bridge_for_each_brport(port, entry, sc) {
		dif = bridge_port_get_interface(port);

		if (in_ifp && dif == in_ifp)
			continue;

		if (input_hw_fwded && dif->hw_forwarding)
			continue;

		if (bridge_port_get_state_vlan(port, vlan)
			!= STP_IFSTATE_FORWARDING)
			continue;

		if (bridge_pkt_exceeds_mtu(m, dif))
			continue;

		if (lastif) {
			if (lastif->if_type == IFT_TUNNEL_GRE) {
				/* Bridging flooding over tunnel interface will
				 * make the necessary mbuf copy while still
				 * retaining the original mbuf for the last
				 * interface
				 */
				bridge_flood_on_gre_tunnel(lastif, m);
			} else {
				struct rte_mbuf *n
					 = pktmbuf_clone(m, m->pool);

				if (likely(n != NULL))
					bridge_tx_frame(br_ifp, in_ifp,
							lastif, n);
			}
		}

		lastif = dif;
	}

	/* original goes to the last port */
	if (likely(lastif != NULL)) {
		if (lastif->if_type == IFT_TUNNEL_GRE) {
			bridge_flood_on_gre_tunnel(lastif, m);
			/* bridge flood over tunnel always sends a copy */
			rte_pktmbuf_free(m);
		} else
			bridge_tx_frame(br_ifp, in_ifp, lastif, m);
	} else {
		goto drop;
	}

	return;

drop:
	rte_pktmbuf_free(m);
}

/*
 * Destination is unknown unicast, flood to all ports in bridge.
 *
 * Last match gets the original, and other entries get a copy.
 */
static void bridge_flood(struct bridge_softc *sc, struct ifnet *in_ifp,
			 struct rte_mbuf *m, struct ifnet *brif, bool is_pvst)
{
	if_incr_out(brif, m);

	if (unlikely(brif->capturing))
		capture_burst(brif, &m, 1);

	bridge_flood_local(sc, in_ifp, m, brif, is_pvst);
}

/* Send a packet out of a bridge interface.
 * Allows routing between bridge interfaces
 */
void bridge_output(struct ifnet *ifp, struct rte_mbuf *m,
		   struct ifnet *in_ifp)
{
	const struct ether_hdr *eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
	struct bridge_rtnode *brt;
	struct ifnet *dif;
	struct bridge_port *port = NULL;
	uint16_t vlan = bridge_frame_get_vlan(m);
	struct bridge_softc *sc = ifp->if_softc;
	const struct npf_if *nif = rcu_dereference(ifp->if_npf);
	const struct npf_config *npf_config = npf_if_conf(nif);

	if (npf_active(npf_config, NPF_BRIDGE) &&
	    eh->ether_type != htons(ETHER_TYPE_ARP)) {
		npf_result_t result;

		result = npf_hook_notrack(npf_get_ruleset(npf_config,
					  NPF_RS_BRIDGE), &m, ifp, PFIL_IN, 0,
					  ethtype(m, ETHER_TYPE_VLAN));
		if (result.decision != NPF_DECISION_PASS)
			goto drop;

		/* Set eh again in case buffer in m changed. */
		eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
	}

	brt = bridge_rtnode_lookup(sc, &eh->d_addr, vlan);
	if (brt == NULL) {
		bridge_flood(sc, NULL, m, ifp, false);
		return;
	}

	dif = brt->brt_difp;
	port = rcu_dereference(dif->if_brport);
	if (!port)
		goto drop;

	/*
	 * At this point, we're dealing with a unicast frame
	 * going to a different interface.
	 */
	if (bridge_port_get_state_vlan(port, vlan) != STP_IFSTATE_FORWARDING)
		goto drop;

	/*
	 * When bridging packets that are oversize are dropped.
	 * This can happen when bridging between interfaces with different
	 * mtu's.
	 */
	if (rte_pktmbuf_pkt_len(m) - ETHER_HDR_LEN > dif->if_mtu)
		goto drop;	/* XXX add stat for this */

	/* Count L3 forwarded and local packets as outbound on bridge */
	if_incr_out(ifp, m);

	if (unlikely(ifp->capturing))
		capture_burst(ifp, &m, 1);

	/* Mark entry as used */
	rte_atomic32_clear(&brt->brt_unused);

	if (dif->if_type == IFT_TUNNEL_GRE)
		bridge_forward_via_tunnel(ifp, in_ifp, dif, &brt->brt_dip, m);
	else
		bridge_tx_frame(ifp, in_ifp, dif, m);

	return;

drop:
	if_incr_oerror(ifp);
	if_vlan_out_drop_stats_incr(sc, vlan);
	rte_pktmbuf_free(m);
}

/* frame destined to bridge mac, or l2 multicast, it is always consumed */
static void
bridge_input_local(struct rte_mbuf *m, struct ifnet *input_if,
		   struct ifnet *base_bridge)
{
	/* lookup bridge vlan interface */
	uint16_t vlan = bridge_frame_get_vlan(m);
	struct bridge_softc *sc = base_bridge->if_softc;

	if (vlan != 0 && sc->scbr_vlan_filter) {
		struct ifnet *brvlan = if_vlan_lookup(input_if, vlan);
		if (brvlan == NULL) {
			/*
			 * If the packet is local destined,
			 *  but no vlan interface has been configured,
			 *  then it can't be processed locally.
			 */
			DP_DEBUG(BRIDGE, DEBUG, BRIDGE,
				"bridge_input_local: no vlan interface found for "
				"%u on bridge %s\n",
				vlan, input_if->if_name);
			if_incr_no_vlan(input_if);
			rte_pktmbuf_free(m);
			return;
		}
		/* vlan interface must be up */
		if (!(brvlan->if_flags & IFF_UP)) {
			/* Bump counter on the bridge not the bridge vif */
			if_incr_no_vlan(input_if);
			rte_pktmbuf_free(m);
			return;
		}

		input_if = brvlan;

		if (unlikely(input_if->capturing))
			capture_burst(input_if, &m, 1);
	}

	if_incr_in(input_if, m);

	/*
	 * Have we exposed an inner vlan.
	 */
	if (ethhdr(m)->ether_type == htons(ETHER_TYPE_VLAN)) {
		struct pktmbuf_mdata *mdata;

		mdata = pktmbuf_mdata(m);
		mdata->md_bridge.outer_vlan = vlan;
		  /* We need to shuffle the vlan exposed to the meta
		   * data
		   */
		m->ol_flags |= PKT_RX_VLAN;
		m->vlan_tci = vid_decap(m, ETHER_TYPE_VLAN);
		bridge_input_local(m, input_if, base_bridge);
		return;
	}

	struct pl_packet pkt = {
		.mbuf = m,
		.l2_pkt_type = pkt_mbuf_get_l2_traffic_type(m),
		.in_ifp = input_if,
	};
	pipeline_fused_ether_forward(&pkt);
}

/*
 * Receive input from an L2 port.  Tranparently bridge the frame to all other
 * L2 ports.  If L3 bridge interface is interested in the frame, either handle
 * it here or send on slowpath to kernel.
 */
void bridge_input(struct bridge_port *port, struct rte_mbuf *m)
{
	struct ifnet *ifp = bridge_port_get_interface(port);
	struct ifnet *brif = bridge_port_get_bridge(ifp->if_brport);
	struct bridge_softc *sc = brif->if_softc;
	const struct ether_hdr *eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
	struct if_data *ifstat = &ifp->if_data[dp_lcore_id()];
	struct pktmbuf_mdata *mdata;

	/* Tag any frame without a VLAN with the PVID */
	bridge_tag_pvid(brif, ifp, m);

	uint16_t vlan = bridge_frame_get_vlan(m);

	++ifstat->ifi_ibridged;
	if_vlan_in_stats_incr(ifp, sc, vlan, m);

	/*
	 * Note the member interface in case packet needs to be punted
	 * to the kernel.
	 */
	mdata = pktmbuf_mdata(m);
	mdata->md_bridge.member_ifindex = ifp->if_index;
	mdata->md_bridge.outer_vlan = 0;
	pktmbuf_mdata_invar_set(m, PKT_MDATA_INVAR_BRIDGE);

	if (unlikely(brif->capturing && brif->cap_info->is_promisc))
		capture_burst(brif, &m, 1);

	/* bogon filter */
	if (!rte_is_valid_assigned_ether_addr(&eh->s_addr))
		goto errorpath;

	/* bridge must be up */
	if (!(brif->if_flags & IFF_UP))
		goto drop;

	uint8_t state = bridge_port_get_state_vlan(port, vlan);

	/* Port must be up */
	if (state == STP_IFSTATE_DISABLED)
		goto drop;

	/*
	 * Sending ethernet link-local multicast pkts upstream.  This
	 * includes Spanning Tree BPDUs.
	 *
	 * For Cisco PVST BPDUs they either need to be flooded or
	 * punted to the kernel (and from there to mstpd), all depends
	 * on whether or not the Cisco multicast address has been
	 * registered.
	 */
	bool is_pvst = rte_ether_addr_equal(&eh->d_addr, &pvst_mcast_address);

	if (is_link_local_ether_addr(&eh->d_addr) ||
	    (is_pvst &&
	     (l2_mcfltr_node_lookup(ifp, &pvst_mcast_address) != NULL))) {
		ifstat->ifi_imulticast++;
		local_packet(ifp, m);
		return;
	}

	/* Drop any VLAN's that are not allowed */
	if (!bridge_is_allowed_vlan(brif, ifp, vlan))
		goto drop;

	/* Learn the source address */
	if (state == STP_IFSTATE_LEARNING ||
	    state == STP_IFSTATE_FORWARDING)
		bridge_rtupdate(ifp, &eh->s_addr, bridge_frame_get_vlan(m));

	if (state != STP_IFSTATE_FORWARDING)
		goto drop;

	/* Apply firewall here to match local and forwarded frames */
	const struct npf_if *nif = rcu_dereference(brif->if_npf);
	const struct npf_config *npf_config = npf_if_conf(nif);

	if (npf_active(npf_config, NPF_BRIDGE) &&
			       eh->ether_type != htons(ETHER_TYPE_ARP)) {
		npf_result_t result;

		result = npf_hook_notrack(npf_get_ruleset(npf_config,
					  NPF_RS_BRIDGE), &m, brif, PFIL_IN, 0,
					  ethtype(m, ETHER_TYPE_VLAN));
		if (result.decision != NPF_DECISION_PASS)
			goto ignore;

		/* Set eh again in case buffer in m changed. */
		eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
	}
	if (unlikely(rte_ether_addr_equal(&eh->d_addr, &brif->eth_addr))) {
		/* "to us" unicast pkts should always be consumed */
		bridge_input_local(m, brif, brif);
		return;
	}

	bool mcast = false;

	/* Check for multicast and broadcast pkts *after* firewall. */
	if (unlikely(rte_is_multicast_ether_addr(&eh->d_addr))) {
		struct rte_mbuf *m_local = pktmbuf_copy(m, m->pool);

		if (!m_local)
			goto errorpath;
		mcast = true;
		ifstat->ifi_imulticast++;
		if (rte_is_broadcast_ether_addr(&eh->d_addr))
			pkt_mbuf_set_l2_traffic_type(m_local,
						     L2_PKT_BROADCAST);
		else
			pkt_mbuf_set_l2_traffic_type(m_local,
						     L2_PKT_MULTICAST);
		bridge_input_local(m_local, brif, brif);
	}

	/* If mcast or no entry in local forwarding table, then flood. */
	if (mcast || !bridge_forward(sc, ifp, m, brif))
		bridge_flood(sc, ifp, m, brif, is_pvst);

	return;

errorpath:
	if_incr_error(brif);
	rte_pktmbuf_free(m);
	return;
drop:
	if_incr_dropped(brif);
ignore:
	rte_pktmbuf_free(m);
}

/* Should route entry be expired?
 * For dynamic entries only, check if it has been used.
 *  for more than BRIDGE_RTABLE_EXPIRE intervals.
 */
static int
bridge_rtexpired(struct bridge_rtnode *brt, uint32_t ageing_ticks)
{
	if ((brt->brt_flags & IFBAF_TYPEMASK) != IFBAF_DYNAMIC)
		return 0;

	if (rte_atomic32_test_and_set(&brt->brt_unused)) {
		/* Transition from used to unused */
		brt->brt_expire = 0;
		return 0;
	}

	/* If ageing_ticks is 0 then dynamic entries are never timed out */
	if (++brt->brt_expire > ageing_ticks && ageing_ticks > 0)
		return 1; /* expired */

	return 0;
}

/* walk bridge forwarding database and timeout old entries */
static void bridge_timer(struct rte_timer *timer __rte_unused,
			 void *arg __rte_unused)
{
	struct bridge_softc *sc = arg;
	struct cds_lfht_iter iter;
	struct bridge_rtnode *brt;

	rcu_read_lock();
	cds_lfht_for_each_entry(sc->scbr_rthash, &iter, brt, brt_node) {
		if (bridge_rtexpired(brt, sc->scbr_ageing_ticks))
			bridge_rtnode_destroy(sc->scbr_rthash, brt);
	}
	rcu_read_unlock();
}

/*
 * Code for handling netlink message about bridging
 */

/* Validate bridge port attributes */
static int bridge_port_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_BRPORT_MAX) < 0)
		return MNL_CB_OK;

	if (type == IFLA_BRPORT_STATE) {
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"invalid port state attribute %d\n", type);
			return MNL_CB_ERROR;
		}
	}

	tb[type] = attr;
	return MNL_CB_OK;

}

/* new port added to bridge */
static int notify_newport(int ifindex, const char *ifname,
			  struct nlattr *tb[])
{
	int master;
	uint8_t state;
	struct nlattr *pinfo[IFLA_BRPORT_MAX+1] = { NULL };
	struct rte_ether_addr *lladdr = NULL;

	if (!tb[IFLA_MASTER]) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			"missing master in newlink msg\n");
		return MNL_CB_ERROR;
	}

	if (tb[IFLA_PROTINFO]) {
		if (mnl_attr_parse_nested(tb[IFLA_PROTINFO], bridge_port_attr,
					  pinfo) != MNL_CB_OK) {
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				 "unparseable port attributes\n");
			return MNL_CB_ERROR;
		}
	}

	master = mnl_attr_get_u32(tb[IFLA_MASTER]);

	if (tb[IFLA_ADDRESS] && (mnl_attr_get_payload_len(tb[IFLA_ADDRESS]) ==
				 ETHER_ADDR_LEN))
		lladdr = mnl_attr_get_payload(tb[IFLA_ADDRESS]);

	if (pinfo[IFLA_BRPORT_STATE]) {
		state = mnl_attr_get_u8(pinfo[IFLA_BRPORT_STATE]);
		if (!bridge_is_ifstate_valid(state)) {
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				 "invalid bridge state %u, set to blocking\n",
				 state);
			state = STP_IFSTATE_BLOCKING;
		}


		bridge_newport(ifindex, ifname, master, state, lladdr);
	} else {
		if (lladdr)
			bridge_newneigh(ifindex, lladdr, NUD_PERMANENT, 0);
	}

	return MNL_CB_OK;
}

/* remove port from bridge */
static int notify_delport(int ifindex, struct nlattr *tb[])
{
	int master;

	if (tb[IFLA_MASTER])
		master = mnl_attr_get_u32(tb[IFLA_MASTER]);
	else {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			"missing master in newlink msg\n");
		return MNL_CB_ERROR;
	}

	bridge_delport(ifindex, master);
	return MNL_CB_OK;
}

/* Translate netlink state to BSD flags */
static uint8_t ndmstate_to_flags(uint16_t state)
{
	if (state & NUD_PERMANENT)
		return	IFBAF_LOCAL;
	else if (state & NUD_NOARP)
		return IFBAF_STATIC;
	else
		return IFBAF_DYNAMIC;
}

static void bridge_newneigh(int ifindex, const struct rte_ether_addr *dst,
	uint16_t state, uint16_t vlan)
{
	struct ifnet *ifp, *ifm;
	struct bridge_softc *sc;
	struct bridge_rtnode *brt;
	int err;
	struct fal_attribute_t attr_list[1] = {
		{ FAL_BRIDGE_NEIGH_ATTR_STATE, .value.u16 = state },
	};

	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp)
		return;	/* not a DPDK interface */

	if  (ifp->if_type == IFT_BRIDGE)
		ifm = ifp;
	else {
		ifm = ifp->if_brport ?
			bridge_port_get_bridge(ifp->if_brport) : NULL;
		if (ifm == NULL) {
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				 "newneigh for %s but not a bridge port\n",
				 ifp->if_name);
			return;
		}
	}

	sc = ifm->if_softc;
	brt = bridge_rtnode_lookup(sc, dst, vlan);
	if (brt) {
		/* update exist entry */
		brt->brt_flags = ndmstate_to_flags(state);
		fal_br_upd_neigh(ifindex, vlan, dst, &attr_list[0]);
		return;
	}

	brt = zmalloc_aligned(sizeof(*brt));
	if (!brt) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			"out of memory for forwarding entry\n");
		return;
	}

	brt->brt_difp = ifp;
	brt->brt_key.addr = *dst;
	brt->brt_key.vlan = vlan;
	brt->brt_flags = ndmstate_to_flags(state);
	brt->brt_expire = 0;
	rte_atomic32_set(&brt->brt_unused, 1);

	err = bridge_rtnode_insert(sc, brt);
	if (err) {
		/* already created (race) */
		free(brt);
	}
	fal_br_new_neigh(ifindex, vlan, dst, 1, attr_list);
}

static void bridge_delneigh(int ifindex,
	const struct rte_ether_addr *dst, uint16_t vid)
{
	struct ifnet *ifp, *ifm;
	struct bridge_softc *sc;
	struct bridge_rtnode *brt;

	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp)
		return;	/* not a DPDK interface */

	if  (ifp->if_type == IFT_BRIDGE)
		ifm = ifp;
	else {
		ifm = ifp->if_brport ?
			bridge_port_get_bridge(ifp->if_brport) : NULL;
		if (ifm == NULL) {
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				 "delneigh for %s but not a bridge port\n",
				 ifp->if_name);
			return;
		}
	}

	sc = ifm->if_softc;

	brt = bridge_rtnode_lookup(sc, dst, vid);
	if (brt) {
		fal_br_del_neigh(ifindex, vid, dst);
		bridge_rtnode_destroy(sc->scbr_rthash, brt);
	} else {
		DP_DEBUG(BRIDGE, NOTICE, BRIDGE,
			"delneigh for %s but on %s not a in forwarding table\n",
			ether_ntoa(dst), ifp->if_name);
	}
}

static int bridge_neigh_change(const struct nlmsghdr *nlh,
			       const struct ndmsg *ndm,
			       struct nlattr *tb[],
			       enum cont_src_en cont_src)
{
	const struct rte_ether_addr *lladdr;
	int skip = MNL_CB_OK;
	struct ifnet *ifp;
	uint16_t vid;
	unsigned int ifindex;

	if (tb[NDA_LLADDR])
		lladdr = RTA_DATA(tb[NDA_LLADDR]);
	else {
		DP_DEBUG(BRIDGE, NOTICE, BRIDGE,
			"missing link addr in NEIGH msg\n");
		return MNL_CB_ERROR;
	}

	if (tb[NDA_VLAN])
		vid = mnl_attr_get_u16(tb[NDA_VLAN]);
	else
		vid = 0;

	ifindex = cont_src_ifindex(cont_src, ndm->ndm_ifindex);
	ifp = dp_ifnet_byifindex(ifindex);
	if (ifp && ifp->if_type == IFT_VXLAN && vxlan_get_vni(ifp))
		skip = vxlan_neigh_change(nlh, ndm, tb);

	DP_DEBUG(BRIDGE, INFO, BRIDGE,
		 "%s pid %u flags %#x dev %u lladdr %s vid %u flags %#x state %s skip %u\n",
		 nlmsg_type(nlh->nlmsg_type),
		 nlh->nlmsg_pid, nlh->nlmsg_flags,
		 ifindex,
		 ether_ntoa(lladdr),
		 vid,
		 ndm->ndm_flags, ndm_state(ndm->ndm_state),
		 skip);

	switch (nlh->nlmsg_type) {
	case RTM_NEWNEIGH:
		if (skip == MNL_CB_OK)
			bridge_newneigh(ifindex, lladdr, ndm->ndm_state, vid);
		break;

	case RTM_DELNEIGH:
		bridge_delneigh(ifindex, lladdr, vid);
		break;

	default:
		DP_DEBUG(BRIDGE, NOTICE, BRIDGE,
			"unexpected netlink message type %d\n",
			nlh->nlmsg_type);
	}

	return MNL_CB_OK;
}

static void
bridge_process_vlan_info(struct bridge_vlan_set *vlans,
	struct bridge_vlan_set *untagged,
	uint16_t *pvid, uint16_t vlan, uint16_t flags)
{
	bridge_vlan_set_add(vlans, vlan);
	if (flags & BRIDGE_VLAN_INFO_PVID)
		*pvid = vlan;
	if (flags & BRIDGE_VLAN_INFO_UNTAGGED)
		bridge_vlan_set_add(untagged, vlan);
}

static int
bridge_netlink_process_port_vlan_attributes(struct nlattr *tb[],
	struct bridge_vlan_set *vlans,
	struct bridge_vlan_set *untagged,
	uint16_t *pvid)
{
	struct nl_bridge_vlan_info *vinfo_range_start = NULL;
	struct nl_bridge_vlan_info *vinfo = NULL;
	struct nlattr *attr;

	/* Find the new vlan config by parsing the AF_SPEC attribute */
	mnl_attr_for_each_nested(attr, tb[IFLA_AF_SPEC]) {
		vinfo = mnl_attr_get_payload(attr);
		if (!vinfo->vid || vinfo->vid >= VLAN_VID_MASK)
			continue;
		if (vinfo->flags & BRIDGE_VLAN_INFO_RANGE_BEGIN) {
			if (vinfo_range_start) {
				/*
				 * Two starts were seen without an end
				 * the message must be corrupt, stop processing
				 */
				DP_DEBUG(BRIDGE, ERR, BRIDGE,
					"bridge_netlink_process_port_vlan_attributes, "
					"duplicate BRIDGE_INFO_RANGE_BEGIN flag\n");
				return MNL_CB_ERROR;
			}

			/*
			 * only one pvid is allowed, if this occurs,
			 * the message is corrupt, stop processing it
			 */
			if (vinfo->flags & BRIDGE_VLAN_INFO_PVID) {
				DP_DEBUG(BRIDGE, ERR, BRIDGE,
					"bridge_netlink_process_port_vlan_attributes, "
					"PVID supplied in range\n");
				return MNL_CB_ERROR;
			}

			vinfo_range_start = vinfo;
		} else if (vinfo_range_start) {
			int vid, start_vid, end_vid;
			if (!(vinfo->flags & BRIDGE_VLAN_INFO_RANGE_END)) {
				/*
				 * bogus message:
				 * range start without range end
				 */
				DP_DEBUG(BRIDGE, ERR, BRIDGE,
					"bridge_netlink_process_port_vlan_attributes, "
					"BRIDGE_VLAN_INFO_RANGE_BEGIN without "
					"BRIDGE_VLAN_INFO_RANGE_END\n");
				return MNL_CB_ERROR;
			}
			if (vinfo->vid <= vinfo_range_start->vid) {
				/*
				 * bogus message:
				 * range end is less than range start
				 */
				DP_DEBUG(BRIDGE, ERR, BRIDGE,
					"bridge_netlink_process_port_vlan_attributes, "
					"vid range end is less than vid range start\n");
				return MNL_CB_ERROR;
			}
			end_vid = vinfo->vid;
			start_vid = vinfo_range_start->vid;
			for (vid = start_vid; vid <= end_vid; vid++) {
				bridge_process_vlan_info(vlans, untagged,
					pvid, vid, vinfo_range_start->flags);
			}
			vinfo_range_start = NULL;
		} else {
			bridge_process_vlan_info(vlans, untagged,
				pvid, vinfo->vid, vinfo->flags);
		}
	}
	return MNL_CB_OK;
}

static void bridge_netlink_gen_vlan_event(struct ifnet *ifp,
					  struct bridge_vlan_set *old_vlans)
{
	for (int i = 1; i < VLAN_N_VID; i++) {
		/*
		 * if a vlan is no longer associated with a port,
		 * generate a delete event
		 */
		if (bridge_vlan_set_is_member(old_vlans, i) &&
		    !bridge_port_is_vlan_member(ifp->if_brport, i)) {
			RTE_LOG(NOTICE, BRIDGE, "Removing %s from vlan %d\n",
				ifp->if_name, i);
			dp_event(DP_EVT_IF_VLAN_DEL, 0, ifp, i, 0, NULL);
		}

		/*
		 * if a vlan is associated afresh with a port
		 * generate an add event
		 */
		if (!bridge_vlan_set_is_member(old_vlans, i) &&
		    bridge_port_is_vlan_member(ifp->if_brport, i)) {
			RTE_LOG(NOTICE, BRIDGE, "Adding %s to vlan %d\n",
				ifp->if_name, i);
			dp_event(DP_EVT_IF_VLAN_ADD, 0, ifp, i, 0, NULL);
		}
	}
}


/*
 * We are about to configure these vlans on this brport - make sure
 * the stats arrays for these vlans are allocated.
 */
static int bridge_alloc_vlan_stats(struct bridge_port *brport,
				   struct bridge_vlan_set *new_vlans,
				   struct bridge_vlan_set *new_untagged,
				   uint16_t pvid)
{
	struct ifnet *brif = bridge_port_get_bridge(brport);
	struct bridge_softc *sc = brif->if_softc;
	struct bridge_vlan_stat_block *stats;
	int max_core;
	int i;

	max_core = get_lcore_max();
	for (i = 0; i < VLAN_N_VID; i++) {
		if (bridge_vlan_set_is_member(new_vlans, i) ||
		    bridge_vlan_set_is_member(new_untagged, i) ||
			pvid == i) {
			if (!sc->vlan_stats[i]) {
				/* allocate for all cores */
				stats = zmalloc_aligned(
					sizeof(struct bridge_vlan_stat_block) +
					(max_core + 1) *
					sizeof(struct bridge_vlan_stats));
				if (!stats)
					return -ENOMEM;
				rcu_assign_pointer(sc->vlan_stats[i], stats);
			}
		}
	}
	return 0;
}

/*
 * Free stats for a vlan that is no longer a member of any ports on the switch
 */
static void bridge_free_vlan_stats(struct bridge_port *brport)
{
	struct cds_list_head *entry;
	struct bridge_port *port;
	struct ifnet *brif = bridge_port_get_bridge(brport);
	struct bridge_softc *sc = brif->if_softc;
	struct bridge_vlan_stat_block *old_stats;
	bool member;

	for (int i = 1; i < VLAN_N_VID; i++) {
		if (sc->vlan_stats[i]) {
			member = false;
			bridge_for_each_brport(port, entry, sc) {
				if (bridge_port_is_vlan_member(port, i)) {
					member = true;
					break;
				}
			}
			if (!member) {
				old_stats = rcu_xchg_pointer(&sc->vlan_stats[i],
							     NULL);
				if (old_stats)
					call_rcu(&old_stats->vlan_stats_rcu,
						 free_vlan_stats);
			}
		}
	}
}

int bridge_vlan_clear_software_stat(struct bridge_softc *sc,
				    uint16_t vlan)
{
	struct bridge_vlan_stat_block *old_stats;
	struct bridge_vlan_stat_block *new_stats;
	int max_core;

	if (!sc)
		return 0;

	old_stats = rcu_dereference(sc->vlan_stats[vlan]);
	if (old_stats) {
		max_core = get_lcore_max();
		new_stats = zmalloc_aligned(
			sizeof(struct bridge_vlan_stat_block) +
			(max_core + 1) *
			sizeof(struct bridge_vlan_stats));
		if (!new_stats)
			return -ENOMEM;
		if (rcu_cmpxchg_pointer(&sc->vlan_stats[vlan],
					old_stats, new_stats)
		    == old_stats) {
			/* We have swapped out old and replaced with new. */
			call_rcu(&old_stats->vlan_stats_rcu, free_vlan_stats);
		} else {
			free(new_stats);
		}
	}
	return 0;
}

static int
bridge_netlink_update_port(int ifindex, struct nlattr *tb[], int msg_type)
{
	struct bridge_vlan_set *new_vlans = NULL, *old_vlans = NULL;
	struct bridge_vlan_set *new_untagged = NULL;
	uint16_t pvid = 0;
	int rv = MNL_CB_OK;
	struct fal_attribute_t vlan_update;

	struct ifnet *port = dp_ifnet_byifindex(ifindex);
	if (!port)
		return rv;

	struct bridge_port *brport = port->if_brport;
	if (!brport)
		return MNL_CB_OK;

	DP_DEBUG(BRIDGE, DEBUG, BRIDGE,
		"bridge_netlink_update_port: Processing port update message\n");

	new_vlans = bridge_vlan_set_create();
	if (!new_vlans)
		return MNL_CB_ERROR;

	new_untagged = bridge_vlan_set_create();
	if (!new_untagged) {
		rv = MNL_CB_ERROR;
		goto done;
	}

	old_vlans = bridge_vlan_set_create();
	if (!old_vlans) {
		rv = MNL_CB_ERROR;
		goto done;
	}

	for (int i = 0; i < VLAN_N_VID; i++)
		if (bridge_port_is_vlan_member(brport, i))
			bridge_vlan_set_add(old_vlans, i);

	if (msg_type == RTM_NEWLINK) {
		/*
		 * We have implicit delete of the vlans when removing the
		 * port from the bridge, so only parse the vlans on the
		 * NEWLINK.
		 */
		if (tb[IFLA_AF_SPEC]) {
			rv = bridge_netlink_process_port_vlan_attributes(
				tb, new_vlans, new_untagged, &pvid);

			if (rv != MNL_CB_OK)
				goto done;
		}
	}

	rv = bridge_alloc_vlan_stats(brport, new_vlans, new_untagged, pvid);
	if (rv) {
		DP_DEBUG(BRIDGE, ERR, BRIDGE,
			 "out of memory for vlan stats\n");
		goto done;
	}
	rv = MNL_CB_OK;

	/*
	 * compare new vlan config with the old
	 * and synchronize them
	 */
	if (bridge_port_synchronize_vlans(brport, new_vlans) &&
	    bridge_port_is_fal_created(brport)) {
		vlan_update.id = FAL_BRIDGE_PORT_ATTR_TAGGED_VLANS;
		vlan_update.value.ptr = new_vlans;
		fal_br_upd_port(ifindex, &vlan_update);
	}

	if (bridge_port_synchronize_untag_vlans(brport, new_untagged) &&
	    bridge_port_is_fal_created(brport)) {
		vlan_update.id = FAL_BRIDGE_PORT_ATTR_UNTAGGED_VLANS;
		vlan_update.value.ptr = new_untagged;
		fal_br_upd_port(ifindex, &vlan_update);
	}

	if (bridge_port_get_pvid(brport) != pvid) {
		struct fal_attribute_t pvid_update = {
			FAL_BRIDGE_PORT_ATTR_PORT_VLAN_ID,
			.value.u16 = pvid };

		bridge_port_set_pvid(brport, pvid);
		if (bridge_port_is_fal_created(brport))
			fal_br_upd_port(ifindex, &pvid_update);
	}

	bridge_free_vlan_stats(brport);

	bridge_netlink_gen_vlan_event(port, old_vlans);
done:
	bridge_vlan_set_free(new_vlans);
	bridge_vlan_set_free(new_untagged);
	bridge_vlan_set_free(old_vlans);
	return rv;
}

/* Call back to handle netlink link messages of AF_BRIDGE
 * XXX Need to handle MAC change?
 */
static int bridge_link_change(const struct nlmsghdr *nlh,
			      const struct ifinfomsg *ifi,
			      struct nlattr *tb[],
			      enum cont_src_en cont_src)
{
	unsigned int ifindex = cont_src_ifindex(cont_src, ifi->ifi_index);
	const char *ifname;
	int rv = MNL_CB_OK;

	switch (nlh->nlmsg_type) {
	case RTM_NEWLINK:
		if (tb[IFLA_IFNAME])
			ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);
		else {
			DP_DEBUG(BRIDGE, ERR, BRIDGE,
				"missing ifname in link msg\n");
			return MNL_CB_ERROR;
		}

		DP_DEBUG(BRIDGE, DEBUG, BRIDGE,
			"notifying newport: %u %s\n", ifindex, ifname);
		rv = bridge_netlink_update_port(ifindex, tb, nlh->nlmsg_type);
		if (rv != MNL_CB_OK)
			return rv;

		return notify_newport(ifindex, ifname, tb);
	case RTM_DELLINK:
		bridge_netlink_update_port(ifindex, tb, nlh->nlmsg_type);
		return notify_delport(ifindex, tb);
	}

	return MNL_CB_ERROR;
}

struct ifnet *
bridge_cmd_get_port(FILE *f, struct ifnet *bridge, const char *port_name)
{
	struct ifnet *port;

	port = dp_ifnet_byifname(port_name);
	if (!port) {
		fprintf(f, "%s not found\n", port_name);
		return NULL;
	}

	if (port->if_brport == NULL) {
		fprintf(f, "%s is not a bridge port\n", port->if_name);
		return NULL;
	}
	if (bridge_port_get_bridge(port->if_brport) != bridge) {
		fprintf(f, "%s is not a member of bridge %s\n",
			port->if_name, bridge->if_name);
		return NULL;
	}
	return port;
}

static struct rte_ether_addr *
bridge_cmd_get_mac(const char *mac_string, struct rte_ether_addr *eap)
{
	return ether_aton_r(mac_string, eap);
}

static int bridge_macs_show_entry(uint16_t vlanid,
				  const struct rte_ether_addr *dst,
				  unsigned int child_ifindex,
				  uint32_t attr_count,
				  const struct fal_attribute_t *attr_list,
				  void *arg)
{
	json_writer_t *wr = arg;
	uint32_t ageing = 0;
	uint16_t state = 0;
	struct ifnet *ifp;
	char buf[ETH_ADDR_STR_LEN];
	char vbuf[6];
	uint32_t i;

	if (!wr) {
		RTE_LOG(ERR, BRIDGE, "Show macs: no walk argument provided\n");
		return -1;
	}
	ifp = dp_ifnet_byifindex(child_ifindex);
	if (!ifp)
		RTE_LOG(ERR, BRIDGE,
			"Show macs: no interface for ifindex %d (mac: %s)\n",
			child_ifindex, ether_ntoa_r(dst, buf));
	sprintf(vbuf, "%d", vlanid);

	jsonw_start_object(wr);
	jsonw_string_field(wr, "mac", ether_ntoa_r(dst, buf));
	jsonw_string_field(wr, "port", ifp ? ifp->if_name : "");
	jsonw_string_field(wr, "vlan", vbuf);

	for (i = 0; i < attr_count; i++) {
		const struct fal_attribute_t *attr = &attr_list[i];

		switch (attr->id) {
		case FAL_BRIDGE_NEIGH_ATTR_STATE:
			state = attr->value.u16;
			break;
		case FAL_BRIDGE_NEIGH_ATTR_AGEING:
			ageing = attr->value.u32;
			break;
		default:
			break;
		}
	}

	jsonw_uint_field(wr, "ageing", ageing);
	jsonw_bool_field(wr, "dynamic", !(state & (NUD_NOARP | NUD_PERMANENT)));
	jsonw_bool_field(wr, "static", state & NUD_NOARP);
	jsonw_bool_field(wr, "local", state & NUD_PERMANENT);
	jsonw_end_object(wr);

	return 0;
}

static void
bridge_macs_jsonw_one(json_writer_t *wr, const struct bridge_rtnode *brt)
{
	char b[ETH_ADDR_STR_LEN];
	char vlanb[6];

	sprintf(vlanb, "%d", brt->brt_key.vlan);

	jsonw_start_object(wr);
	jsonw_string_field(wr, "mac", ether_ntoa_r(&brt->brt_key.addr, b));
	jsonw_string_field(wr, "port", brt->brt_difp->if_name);
	jsonw_string_field(wr, "vlan", vlanb);

	/* Ageing field is only meaningful for dynamic entries */
	jsonw_uint_field(wr, "ageing",
			 brt->brt_expire * BRIDGE_RTABLE_PRUNE_PERIOD);
	jsonw_bool_field(wr, "dynamic",
			 bridge_mac_is_dynamic(brt));
	jsonw_bool_field(wr, "static", bridge_mac_is_static(brt));
	jsonw_bool_field(wr, "local", bridge_mac_is_local(brt));
	jsonw_end_object(wr);
}

static void
bridge_macs_jsonw_all(json_writer_t *wr, struct bridge_softc *sc,
		      struct ifnet *port, struct rte_ether_addr *macp,
		      uint16_t vlan)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_first(sc->scbr_rthash, &iter);
	while ((node = cds_lfht_iter_get_node(&iter)) != NULL) {
		const struct bridge_rtnode *brt
			= caa_container_of(node, struct bridge_rtnode,
					   brt_node);

		if ((!port || port == brt->brt_difp) &&
		    (!vlan || vlan == brt->brt_key.vlan) &&
		    (!macp || rte_ether_addr_equal(macp, &brt->brt_key.addr)))
			bridge_macs_jsonw_one(wr, brt);

		cds_lfht_next(sc->scbr_rthash, &iter);
	}
}

/*
 * (bridge <bridge> macs) show [port <port>] [mac <mac>] [vlan <vlan>]
 * [hardware]
 */
static int
bridge_macs_show(FILE *f, int argc, char **argv, struct ifnet *bridge)
{
	struct bridge_softc *sc = bridge->if_softc;
	struct ifnet *port = NULL;
	struct rte_ether_addr mac, *macp = NULL;
	fal_br_walk_neigh_fn cb;
	uint16_t vlanid = 0;
	bool hw = false;

	if (argc < 1) {
		fprintf(f, "%s: missing argument: %d", __func__, argc);
		return -1;
	}
	argc--, argv++; /* skip 'show' */

	if (argc >= 2 && strcmp(argv[0], "port") == 0) {
		port = bridge_cmd_get_port(f, bridge, argv[1]);
		if (!port)
			return -1;
		argc -= 2, argv += 2; /* skip 'port <port>' */
	}
	if (argc >= 2 && strcmp(argv[0], "mac") == 0) {
		macp = bridge_cmd_get_mac(argv[1], &mac);
		if (!macp)
			return -1;
		argc -= 2, argv += 2;
	}
	if (argc >= 2 && strcmp(argv[0], "vlan") == 0) {
		vlanid = atoi(argv[1]);
		if (!vlanid)
			return -1;
		argc -= 2, argv += 2;
	}
	if (argc >= 1 && strcmp(argv[0], "hardware") == 0)
		hw = true;

	json_writer_t *wr = jsonw_new(f);

	if (!wr)
		return -1;

	jsonw_string_field(wr, "name", bridge->if_name);

	jsonw_name(wr, "mac_table");
	jsonw_start_array(wr);

	if (hw) {
		cb = bridge_macs_show_entry;
		fal_br_walk_neigh(bridge->if_index, vlanid, macp,
				  port ? port->if_index : 0, cb, wr);
	} else {
		if (macp && vlanid) {
			const struct bridge_rtnode *brt =
				bridge_rtnode_lookup(sc, macp, vlanid);
			if (brt)
				bridge_macs_jsonw_one(wr, brt);
		} else {
			bridge_macs_jsonw_all(wr, sc, port, macp, vlanid);
		}
	}

	jsonw_end_array(wr);
	jsonw_destroy(&wr);
	return 0;
}

/*
 * bridge frag status
 */
static int
bridge_frag_status(FILE *f, int argc, char **argv __rte_unused)
{
	if (argc < 1) {
		fprintf(f, "%s: missing argument: %d", __func__, argc);
		return -1;
	}

	json_writer_t *wr = jsonw_new(f);

	if (!wr)
		return -1;

	jsonw_name(wr, "global_config");
	jsonw_start_object(wr);
	jsonw_bool_field(wr, "bridge_frag_enable", bridge_frag_enable);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	return 0;
}

/*
 * (bridge <bridge> macs) clear [port <port>] [mac <mac>]
 */
static int
bridge_macs_clear(FILE *f, int argc, char **argv, struct ifnet *bridge)
{
	struct bridge_softc *sc = bridge->if_softc;
	struct ifnet *port = NULL;
	struct rte_ether_addr mac, *macp = NULL;

	if (argc < 1) {
		fprintf(f, "%s: missing argument: %d", __func__, argc);
		return -1;
	}
	argc--, argv++; /* skip 'clear' */

	if (argc >= 2 && strcmp(argv[0], "port") == 0) {
		port = bridge_cmd_get_port(f, bridge, argv[1]);
		if (!port)
			return -1;
		argc -= 2, argv -= 2; /* skip 'port <port>' */
	}
	if (argc >= 2 && strcmp(argv[0], "mac") == 0) {
		macp = bridge_cmd_get_mac(argv[1], &mac);
		if (!macp)
			return -1;
	}

	if (macp) {
		struct bridge_rtnode *brt =
			bridge_rtnode_lookup(sc, macp, 0);
		if (brt)
			bridge_rtnode_destroy(sc->scbr_rthash, brt);

		fal_fdb_flush_mac(bridge->if_index,
				  (port == NULL) ? 0 : port->if_index,
				  macp);
	} else {
		bridge_fdb_flush(bridge, port, IFBAF_DYNAMIC, 0, true);
	}
	return 0;
}

/*
 * (bridge <bridge>) macs show [port <port>] [mac <mac>] [vlan <vlan>]
 * [hardware]
 * (bridge <bridge>) macs clear [port <port>] [mac <mac>]
 */
static int
bridge_macs(FILE *f, int argc, char **argv, struct ifnet *bridge)
{
	if (argc < 2) {
		fprintf(f, "%s: missing argument: %d", __func__, argc);
		return -1;
	}
	argc--, argv++; /* skip 'macs' */

	if (strcmp(argv[0], "show") == 0)
		return bridge_macs_show(f, argc, argv, bridge);
	else if (strcmp(argv[0], "clear") == 0)
		return bridge_macs_clear(f, argc, argv, bridge);

	fprintf(f, "Unknown bridge macs command\n");
	return -1;
}

/*
 * bridge frag {disable | enable | show}
 *
 * Enables or disables fragmentation of packets going out on a
 * L2 GRE bridge port with the DF bit unset.
 */
static int
bridge_frag(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		fprintf(f, "%s: missing argument: %d", __func__, argc);
		return -1;
	}
	argc--, argv++; /* skip 'frag' */

	if (strcmp(argv[0], "enable") == 0) {
		bridge_frag_enable = true;
		return 0;
	} else if (strcmp(argv[0], "disable") == 0) {
		bridge_frag_enable = false;
		return 0;
	} else if (strcmp(argv[0], "show") == 0)
		return bridge_frag_status(f, argc, argv);

	fprintf(f, "Unknown bridge frag command\n");
	return -1;
}

/*
 * bridge <bridge> macs show [port <port>] [mac <mac>] [vlan <vlan>] [hardware]
 * bridge <bridge> macs clear [port <port>] [mac <mac>]
 * bridge frag {enable | disable | show}
 */
int
cmd_bridge(FILE *f, int argc, char **argv)
{
	struct ifnet *bridge;

	if (argc < 3) {
		fprintf(f, "%s: missing argument: %d", __func__, argc);
		return -1;
	}
	argc--, argv++; /* skip 'bridge' */

	if (strcmp(argv[0], "frag") == 0)
		return bridge_frag(f, argc, argv);

	bridge = dp_ifnet_byifname(argv[0]);

	if (!bridge || !bridge->if_softc ||
	    bridge->if_type != IFT_BRIDGE) {
		fprintf(f, "Unknown bridge: %s\n", argv[0]);
		return -1;
	}
	argc--, argv++; /* skip '<bridge>' */

	if (strcmp(argv[0], "macs") == 0)
		return bridge_macs(f, argc, argv, bridge);

	fprintf(f, "Unknown bridge command\n");
	return -1;
}

/* Show ports of bridge */
static void show_bridge(json_writer_t *wr, const struct ifnet *ifp)
{
	struct bridge_softc *sc = ifp->if_softc;
	struct bridge_port *port = NULL;
	struct cds_list_head *entry;
	uint16_t i;

	if (!sc)
		return;
	jsonw_name(wr, "bridge");
	jsonw_start_array(wr);

	bridge_for_each_brport(port, entry, sc) {
		ifp = bridge_port_get_interface(port);
		jsonw_start_object(wr);
		jsonw_string_field(wr, "link", ifp->if_name);
		jsonw_string_field(wr, "state",
			bridge_get_ifstate_string(
				bridge_port_get_state(port)));
		if (sc->scbr_vlan_filter) {
			jsonw_name(wr, "vlan_filtering");
			jsonw_start_object(wr);
			jsonw_uint_field(wr, "pvid",
				bridge_port_get_pvid(port));
			jsonw_name(wr, "allowed_vlans");
			jsonw_start_array(wr);
			for (i = 0; i < VLAN_N_VID; i++) {
				if (bridge_port_lookup_vlan(port, i))
					jsonw_uint(wr, i);
			}
			jsonw_end_array(wr);
			jsonw_name(wr, "untag_vlans");
			jsonw_start_array(wr);
			for (i = 0; i < VLAN_N_VID; i++) {
				if (bridge_port_lookup_untag_vlan(
						port, i))
					jsonw_uint(wr, i);
			}
			jsonw_end_array(wr);
			jsonw_end_object(wr);
		}
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);

	jsonw_name(wr, "bridge_master");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "default_pvid", sc->scbr_vlan_default_pvid);
	jsonw_bool_field(wr, "vlan_filtering", sc->scbr_vlan_filter);
	jsonw_end_object(wr);
}

static int
bridge_if_dump(struct ifnet *ifp, json_writer_t *wr,
	       enum if_dump_state_type type)
{
	switch (type) {
	case IF_DS_STATE:
		show_bridge(wr, ifp);
		break;
	default:
		break;
	}

	return 0;
}

static enum dp_ifnet_iana_type
bridge_iana_type(struct ifnet *ifp __unused)
{
	return DP_IFTYPE_IANA_BRIDGE;
}

static const struct ift_ops bridge_if_ops = {
	.ifop_set_l2_address = ether_if_set_l2_address,
	.ifop_init = bridge_if_init,
	.ifop_uninit = bridge_if_uninit,
	.ifop_dump = bridge_if_dump,
	.ifop_iana_type = bridge_iana_type,
};

static const struct netlink_handler bridge_netlink  = {
	.link  = bridge_link_change,
	.neigh = bridge_neigh_change,
};

/* Startup initialization */
static void bridge_init(void)
{
	register_netlink_handler(AF_BRIDGE, &bridge_netlink);
	int ret = if_register_type(IFT_BRIDGE, &bridge_if_ops);
	if (ret < 0)
		rte_panic("Failed to register bridge type: %s",
			  strerror(-ret));

	struct fal_attribute_t punt_pvst = {
		FAL_SWITCH_ATTR_PUNT_PVST};

	if (fal_get_switch_attrs(1, &punt_pvst) == 0)
		bridge_pvst_flood_local = punt_pvst.value.booldata;
	else
		bridge_pvst_flood_local = true;
}

static const struct dp_event_ops bridge_events = {
	.init = bridge_init,
	.if_feat_mode_change = bridge_if_feat_mode_change,
};

DP_STARTUP_EVENT_REGISTER(bridge_events);
