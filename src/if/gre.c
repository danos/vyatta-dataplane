/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * GRE over raw socket
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <libmnl/libmnl.h>
#define _LINUX_IP_H /* linux/ip.h conflicts with netinet/ip.h */
#include <linux/if.h>
#include <linux/if_tunnel.h>
#include <linux/neighbour.h>
#include <linux/netlink.h>
#include <linux/snmp.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <urcu/uatomic.h>

#include "capture.h"
#include "commands.h"
#include "compat.h"
#include "crypto/crypto_forward.h"
#include "dp_event.h"
#include "ether.h"
#include "fal.h"
#include "gre.h"
#include "if/bridge/bridge.h"
#include "if_var.h"
#include "in_cksum.h"
#include "in6.h"
#include "ip_addr.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "iptun_common.h"
#include "json_writer.h"
#include "main.h"
#include "netinet6/ip6_funcs.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "portmonitor/portmonitor.h"
#include "route.h"
#include "route_v6.h"
#include "rt_tracker.h"
#include "shadow.h"
#include "snmp_mib.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "fal_plugin.h"
#include "ecmp.h"

struct gre_info_hash_key {
	union {
		in_addr_t local;
		struct in6_addr local6;
	};
	union {
		in_addr_t remote;
		struct in6_addr remote6;
	};
	uint32_t  key;
	uint16_t  flags;
	uint8_t   family;
};

struct gre_softc {
	struct rcu_head    scg_rcu;
	struct gre_info_st *scg_gre_info;
	bool               scg_multipoint;
	struct cds_lfht    *scg_rtinfo_hash_tun;
	struct cds_lfht    *scg_rtinfo_hash_nbma;
	unsigned long      scg_rtinfo_seed;
	struct rte_timer   scg_rtinfo_timer;
};

/* Size of the gre_info table.	Must be a power of two. */
#define GRE_RTHASH_MIN  32
#define GRE_RTHASH_MAX  64

static void gre_tunnel_delete(struct ifnet *ifp);
static void gre_tunnel_update_tep(void *ctx);

/* GRE local termination netlink/config parsing */

static int
gre_get_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_GRE_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_GRE_OFLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0)
			return MNL_CB_ERROR;
		break;
	case IFLA_GRE_OKEY:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			return MNL_CB_ERROR;
		break;
	case IFLA_GRE_TTL:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
			return MNL_CB_ERROR;
		break;
	case IFLA_GRE_TOS:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
			return MNL_CB_ERROR;
		break;
	case IFLA_GRE_PMTUDISC:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
			return MNL_CB_ERROR;
		break;
	case IFLA_GRE_IGNORE_DF:
		if (mnl_attr_validate(attr, MNL_TYPE_U8) < 0)
			return MNL_CB_ERROR;
		break;
	/* Local and Remote can be IPv4 or IPv6, we check the length later.*/
	case IFLA_GRE_LOCAL:
	case IFLA_GRE_REMOTE:
		break;
	case IFLA_GRE_LINK:
	case IFLA_GRE_IFLAGS:
	case IFLA_GRE_IKEY:
	default:
		/*Only parse options we care about*/
		tb[type] = NULL;
		return MNL_CB_OK;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

/* GRE tunnel info management */
static void
gre_info_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct gre_info_st, gre_rcu));
}

static void
gre_info_destroy(struct gre_info_st *greinfo)
{
	call_rcu(&greinfo->gre_rcu, gre_info_free);
}

static inline int gre_info_match(struct cds_lfht_node *node, const void *key)
{
	const struct gre_info_hash_key *key_gre_info = key;
	const struct gre_info_st *gre_info
		= caa_container_of(node, const struct gre_info_st, gre_node);

	if (gre_info->family != key_gre_info->family)
		return 0;

	if (gre_info->family == AF_INET) {
		if (gre_info->iph.daddr != key_gre_info->remote)
			return 0;
		if (gre_info->iph.saddr != key_gre_info->local)
			return 0;
	} else {
		if (!IN6_ARE_ADDR_EQUAL(&gre_info->iph6.ip6_dst,
					&key_gre_info->remote))
			return 0;
		if (!IN6_ARE_ADDR_EQUAL(&gre_info->iph6.ip6_src,
					&key_gre_info->local))
			return 0;
	}
	if (gre_info->flags & GRE_KEY) {
		if (!(key_gre_info->flags & GRE_KEY))
			return 0;
		if (gre_info->key != key_gre_info->key)
			return 0;
	} else if (key_gre_info->flags & GRE_KEY) {
		return 0;
	}
	return 1;
}

static unsigned int gre_info_hash(const struct gre_info_hash_key *h_key,
				  unsigned long seed)
{
	if (h_key->family == AF_INET)
		return rte_jhash_3words(h_key->remote, h_key->key, h_key->local,
					seed);

	uint32_t hash_keys[9];

	memcpy(hash_keys, &h_key->local6, sizeof(h_key->local6));
	memcpy(hash_keys + 4, &h_key->remote6, sizeof(h_key->remote6));
	hash_keys[8] = h_key->key;

	return rte_jhash_32b(hash_keys, 9, seed);
}

static int
gre_info_insert(struct gre_infotbl_st *gre_infos, struct gre_info_st *greinfo,
		const struct gre_info_hash_key *h_key)
{
	struct cds_lfht_node *ret_node;

	cds_lfht_node_init(&greinfo->gre_node);
	unsigned long hash = gre_info_hash(h_key,
					   gre_infos->gi_greseed);

	ret_node = cds_lfht_add_unique(gre_infos->gi_grehash, hash,
				       gre_info_match, greinfo,
				       &greinfo->gre_node);

	return (ret_node != &greinfo->gre_node) ? EEXIST : 0;
}

static struct gre_info_st *
gre_info_lookup(struct gre_infotbl_st *gre_infos,
		const struct gre_info_hash_key *h_key)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(gre_infos->gi_grehash,
			gre_info_hash(h_key, gre_infos->gi_greseed),
			gre_info_match, h_key, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct gre_info_st, gre_node);
	else
		return NULL;
}

static struct gre_info_st *
gre_info_init(struct vrf *vrf, const struct gre_info_hash_key *h_key)
{
	struct gre_info_st *greinfo;
	int error;

	greinfo = zmalloc_aligned(sizeof(*greinfo));
	if (unlikely(greinfo == NULL))
		return NULL;

	if (h_key->family == AF_INET) {
		/*
		 * Build the IP header so we can memcpy it straight
		 * in each time.
		 */
		greinfo->iph.saddr = h_key->local;
		greinfo->iph.daddr = h_key->remote;
		greinfo->iph.protocol = IPPROTO_GRE;
		greinfo->iph.id = 0;
		greinfo->iph.ihl = 5;
		greinfo->iph.version = IPVERSION;
		greinfo->iph.frag_off = htons(IP_DF);
		greinfo->iph.tos = 0;
		greinfo->family = AF_INET;
	} else {
		greinfo->iph6.ip6_src = h_key->local6;
		greinfo->iph6.ip6_dst = h_key->remote6;
		greinfo->iph6.ip6_vfc = IPV6_VERSION;
		greinfo->iph6.ip6_nxt = IPPROTO_GRE;
		greinfo->family = AF_INET6;
	}

	greinfo->gre_size = sizeof(struct gre_hdr);
	greinfo->ignore_df = false;
	greinfo->flags = h_key->flags;
	greinfo->key = h_key->key;

	/*
	 * When the kernel starts sending transport VRF information
	 * update this accordingly, for now use default transport VRF
	 */
	greinfo->t_vrfid = vrf->v_id;

	if (greinfo->flags & GRE_CSUM)
		greinfo->gre_size += 4;
	if (greinfo->flags & GRE_KEY)
		greinfo->gre_size += 4;
	if (greinfo->flags & GRE_SEQ)
		greinfo->gre_size += 4;

	error = gre_info_insert(vrf->v_gre_infos, greinfo, h_key);
	if (unlikely(error != 0)) {
		free(greinfo);
		return NULL;
	}
	return greinfo;
}

static void
mgre_timer(struct rte_timer *tim __rte_unused, void *arg)
{
	struct gre_softc *sc = arg;
	struct mgre_rt_info *rtinfo;
	struct cds_lfht_iter iter;

	rcu_read_lock();
	cds_lfht_for_each_entry(sc->scg_rtinfo_hash_nbma, &iter,
				rtinfo, rtinfo_node_nbma) {
		/*
		 * Use two bits to determine if the rt_info has not be used for
		 * at least the period of the timer.
		 */
		if (CMM_ACCESS_ONCE(rtinfo->rt_info_bits) &
					RT_INFO_BIT_IS_USED) {
			/*
			 * Set rt_info to used since before the last timer
			 * reset.
			 */
			CMM_ACCESS_ONCE(rtinfo->rt_info_bits) |=
						RT_INFO_BIT_WAS_USED;
		} else {
			CMM_ACCESS_ONCE(rtinfo->rt_info_bits) &=
						~RT_INFO_BIT_WAS_USED;
		}
		CMM_ACCESS_ONCE(rtinfo->rt_info_bits) &= ~RT_INFO_BIT_IS_USED;
	}
	rcu_read_unlock();
}

/* mGRE peer management */
static void
mgre_rt_info_table_init(struct gre_softc *sc)
{
	/* hash table to look up peer based on the tun dst addr */
	sc->scg_rtinfo_hash_tun = cds_lfht_new(GRE_RTHASH_MIN,
					       GRE_RTHASH_MIN,
					       GRE_RTHASH_MAX,
					       CDS_LFHT_AUTO_RESIZE,
					       NULL);
	/* hash table to look up peer based on the nbma addr */
	sc->scg_rtinfo_hash_nbma = cds_lfht_new(GRE_RTHASH_MIN,
						GRE_RTHASH_MIN,
						GRE_RTHASH_MAX,
						CDS_LFHT_AUTO_RESIZE,
						NULL);
	sc->scg_rtinfo_seed = random();
	rte_timer_init(&sc->scg_rtinfo_timer);
	/*
	 * This timer should mimic the kernel.  Use base_reachable_time, which
	 * is the average time a neighbor is valid.
	 */
	rte_timer_reset(&sc->scg_rtinfo_timer,
			rte_get_timer_hz() * RT_INFO_USED_TIMER,
			PERIODICAL, rte_get_master_lcore(),
			mgre_timer, sc);
}

static void
mgre_rtinfo_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct mgre_rt_info, rtinfo_rcu));
}

static void
mgre_rtinfo_destroy(struct mgre_rt_info *rtinfo)
{
	call_rcu(&rtinfo->rtinfo_rcu, mgre_rtinfo_free);
}

static inline unsigned long
mgre_rtinfo_hash(const struct in_addr *tun_addr, unsigned long seed)
{
	return rte_jhash_1word(tun_addr->s_addr, seed);
}

static int
mgre_rtinfo_match_nbma(struct cds_lfht_node *node, const void *key)
{
	const struct in_addr *addr = key;
	const struct mgre_rt_info *rt_info
		= caa_container_of(node, const struct mgre_rt_info,
				   rtinfo_node_nbma);

	return addr->s_addr == rt_info->iph.daddr;
}

static int
mgre_rtinfo_match_tun(struct cds_lfht_node *node, const void *key)
{
	const struct in_addr *addr = key;
	const struct mgre_rt_info *rt_info;

	rt_info = caa_container_of(node, const struct mgre_rt_info,
				   rtinfo_node_tun);
	return addr->s_addr == rt_info->tun_addr.s_addr;
}

const in_addr_t *
mgre_nbma_to_tun_addr(struct ifnet *ifp, const in_addr_t *nbma)
{
	const struct mgre_rt_info *rt_info;
	struct gre_softc *sc;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	const struct in_addr addr = {.s_addr = *nbma};

	sc = rcu_dereference(ifp->if_softc);
	if (!sc || !sc->scg_rtinfo_hash_nbma)
		return nbma;

	cds_lfht_lookup(sc->scg_rtinfo_hash_nbma,
			mgre_rtinfo_hash(&addr, sc->scg_rtinfo_seed),
			mgre_rtinfo_match_nbma, &addr, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node) {
		rt_info = caa_container_of(node, struct mgre_rt_info,
					   rtinfo_node_nbma);
		return &rt_info->tun_addr.s_addr;
	}

	return nbma;
}

static struct mgre_rt_info *
mgre_rtinfo_lookup(struct gre_softc *sc, const struct in_addr *addr)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(sc->scg_rtinfo_hash_tun,
			mgre_rtinfo_hash(addr, sc->scg_rtinfo_seed),
			mgre_rtinfo_match_tun, addr, &iter);

	node = cds_lfht_iter_get_node(&iter);

	if (node)
		return caa_container_of(node, struct mgre_rt_info,
					rtinfo_node_tun);

	return NULL;
}

/*
 * Return values:
 *  0 - Success
 *  1 - Implies another entry for the given NBMA address already exists
 * -1 - Implies that another entry for peer's tunnel address already exists
 *      this should not happen and is an error
 */
static int
mgre_rtinfo_insert(struct gre_softc *sc, struct mgre_rt_info *rt_info,
		   const struct in_addr *nbma_addr)
{
	struct cds_lfht_node *ret_node;
	const struct in_addr *tun_addr = &rt_info->tun_addr;

	unsigned long hash = mgre_rtinfo_hash(nbma_addr,
					      sc->scg_rtinfo_seed);

	cds_lfht_node_init(&rt_info->rtinfo_node_nbma);
	ret_node = cds_lfht_add_unique(sc->scg_rtinfo_hash_nbma, hash,
				       mgre_rtinfo_match_nbma, nbma_addr,
				       &rt_info->rtinfo_node_nbma);

	/*
	 * We are not going to treat this as an error as this can happen
	 * termporarily during phase 2 whereby the first packet, redirect
	 * resolution request, still has to go via the HUB and we get
	 * sent a new neigh update for the other spoke with the HUB's NBMA
	 * address eventually to be replaced by the spoke's NBMA address.
	 * Given that in the absence of any specific entries for the SPOKE's
	 * NBMA address, we will anyway send the packet towards the HUB, it
	 * isn't strictly required.  Adding a non-unique entry to the hash table
	 * poses problems because for host generated traffic, we do a lookup
	 * simply based on NBMA address and having multiple entries could
	 * mean that the packet meant for HUB is sent to an incorrect
	 * recipient.
	 */
	if (ret_node != &rt_info->rtinfo_node_nbma) {
		RTE_LOG(NOTICE, GRE,
			"Skipping adding mGRE DST(%s); NBMA(%s) already exists\n",
			inet_ntoa(*tun_addr), inet_ntoa(*nbma_addr));
		return 1;
	}


	hash = mgre_rtinfo_hash(tun_addr,
				sc->scg_rtinfo_seed);
	cds_lfht_node_init(&rt_info->rtinfo_node_tun);
	ret_node = cds_lfht_add_unique(sc->scg_rtinfo_hash_tun, hash,
				       mgre_rtinfo_match_tun, tun_addr,
				       &rt_info->rtinfo_node_tun);
	if (ret_node != &rt_info->rtinfo_node_tun) {
		cds_lfht_del(sc->scg_rtinfo_hash_nbma,
			     &rt_info->rtinfo_node_nbma);
		return -1;
	}

	return 0;
}

static int
mgre_rtinfo_delete(struct gre_softc *sc, struct mgre_rt_info *rt_info)
{
	struct vrf *vrf;

	vrfid_t nbma_vrfid = rt_info->nbma_vrfid;

	vrf = vrf_get_rcu(nbma_vrfid);
	if (!vrf) {
		DP_LOG_W_VRF(ERR, GRE, rt_info->greinfo->ifp->if_vrfid,
			     "Unable to delete neigh on %s, Id %u\n",
			     rt_info->greinfo->ifp->if_name, nbma_vrfid);
		return 0;
	}

	cds_lfht_del(vrf->v_gre_infos->gi_grehash,
		     &rt_info->greinfo->gre_node);
	gre_info_destroy(rt_info->greinfo);
	cds_lfht_del(sc->scg_rtinfo_hash_nbma,
		     &rt_info->rtinfo_node_nbma);
	cds_lfht_del(sc->scg_rtinfo_hash_tun,
		     &rt_info->rtinfo_node_tun);
	mgre_rtinfo_destroy(rt_info);
	/* Release the lock on the transport VRF */
	vrf_delete(nbma_vrfid);
	return 1;
}

static void
mgre_flush_rtinfo(struct gre_softc *sc)
{
	struct cds_lfht_iter iter;
	struct mgre_rt_info *rtinfo;

	cds_lfht_for_each_entry(sc->scg_rtinfo_hash_nbma, &iter,
				rtinfo, rtinfo_node_nbma)
		mgre_rtinfo_delete(sc, rtinfo);
}

static void
gre_tunnel_set_params(struct gre_info_st *greinfo,
		      struct nlattr *gre_attr[])
{
	if (greinfo->family == AF_INET) {
		/* If the DF bit is set this means do PMTUD. */
		if (gre_attr[IFLA_GRE_PMTUDISC] &&
		    mnl_attr_get_u8(gre_attr[IFLA_GRE_PMTUDISC]))
			greinfo->iph.frag_off = htons(IP_DF);
		else
			greinfo->iph.frag_off = 0;

		if (gre_attr[IFLA_GRE_TTL])
			greinfo->iph.ttl =
				mnl_attr_get_u8(gre_attr[IFLA_GRE_TTL]);
		if (gre_attr[IFLA_GRE_TOS])
			greinfo->iph.tos =
				mnl_attr_get_u8(gre_attr[IFLA_GRE_TOS]);
		if (gre_attr[IFLA_GRE_IGNORE_DF])
			greinfo->ignore_df =
				!!mnl_attr_get_u8(gre_attr[IFLA_GRE_IGNORE_DF]);
	} else {
		uint8_t tos;

		if (gre_attr[IFLA_GRE_TTL])
			greinfo->iph6.ip6_hlim =
				mnl_attr_get_u8(gre_attr[IFLA_GRE_TTL]);
		if (gre_attr[IFLA_GRE_TOS]) {
			tos = mnl_attr_get_u8(gre_attr[IFLA_GRE_TOS]);
			ip6_ver_tc_flow_hdr(&greinfo->iph6, tos, 0);
		}
	}

}

static int gre_fill_key_from_params(struct gre_info_hash_key *h_key,
				    struct nlattr *gre_attr[],
				    const char *name)
{
	void *addr;
	uint16_t addr_len;

	addr_len = mnl_attr_get_payload_len(gre_attr[IFLA_GRE_LOCAL]);
	if (addr_len == 4) {
		h_key->family = AF_INET;
		h_key->local =  mnl_attr_get_u32(gre_attr[IFLA_GRE_LOCAL]);
	} else if (addr_len == sizeof(struct in6_addr)) {
		h_key->family = AF_INET6;
		addr = mnl_attr_get_payload(gre_attr[IFLA_GRE_LOCAL]);
		memcpy(&h_key->local6, addr, addr_len);

	} else {
		RTE_LOG(ERR, GRE, "Invalid length LOCAL IP supplied for: %s\n",
			name);
		return MNL_CB_ERROR;
	}

	addr_len = mnl_attr_get_payload_len(gre_attr[IFLA_GRE_REMOTE]);
	if (addr_len == 4) {
		h_key->remote =  mnl_attr_get_u32(gre_attr[IFLA_GRE_REMOTE]);
	} else if (addr_len == sizeof(struct in6_addr)) {
		addr = mnl_attr_get_payload(gre_attr[IFLA_GRE_REMOTE]);
		memcpy(&h_key->remote6, addr, addr_len);
	} else {
		RTE_LOG(ERR, GRE, "Invalid length REMOTE IP supplied for: %s\n",
			name);
		return MNL_CB_ERROR;
	}

	if (gre_attr[IFLA_GRE_OKEY])
		h_key->key = mnl_attr_get_u32(gre_attr[IFLA_GRE_OKEY]);
	else
		h_key->key = 0;
	if (gre_attr[IFLA_GRE_OFLAGS])
		h_key->flags = mnl_attr_get_u16(gre_attr[IFLA_GRE_OFLAGS]);
	else
		h_key->flags = 0;

	return MNL_CB_OK;
}

static int
gre_tunnel_add_tracker(struct gre_info_st *greinfo, struct vrf *vrf)
{
	struct ip_addr addr;

	addr.type = greinfo->family;
	if (greinfo->family == AF_INET) {
		addr.address.ip_v4.s_addr = greinfo->iph.daddr;
	} else if (greinfo->family == AF_INET6) {
		addr.address.ip_v6 = greinfo->iph6.ip6_dst;
	} else {
		return -1;
	}

	/* Start tracking the tunnel reachability */
	greinfo->ti_info = dp_rt_tracker_add(vrf, &addr, greinfo,
					  &gre_tunnel_update_tep);
	if (!greinfo->ti_info) {
		RTE_LOG(ERR, GRE,
			"Couldn't allocate tracker for GRE tun: %s\n",
			greinfo->ifp->if_name);
		return -1;
	}
	return 0;
}

static void
gre_tunnel_remove_tracker(struct gre_info_st *greinfo, struct vrf *vrf)
{
	struct ip_addr addr;

	if (!greinfo->ti_info)
		return;

	addr.type = greinfo->family;
	if (greinfo->family == AF_INET) {
		addr.address.ip_v4.s_addr = greinfo->iph.daddr;
	} else if (greinfo->family == AF_INET6) {
		addr.address.ip_v6 = greinfo->iph6.ip6_dst;
	} else {
		return;
	}

	dp_rt_tracker_delete(vrf, &addr, greinfo);
}

/* GRE tunnel setup */
static int
setup_gre_tunnel(struct ifnet *ifp, struct nlattr *data)
{
	struct gre_info_hash_key h_key;
	struct nlattr *gre_attr[IFLA_GRE_MAX+1] = { NULL };
	struct gre_info_st *greinfo;
	struct gre_softc *sc;
	/* Assume default transport VRF for now */
	vrfid_t t_vrfid = VRF_DEFAULT_ID;
	struct vrf *vrf;

	sc = malloc(sizeof(struct gre_softc));
	if (!sc) {
		RTE_LOG(ERR, DATAPLANE, "out of memory for GRE softc\n");
		return MNL_CB_ERROR;
	}
	memset(sc, 0, sizeof(struct gre_softc));

	if (mnl_attr_parse_nested(data,
				  gre_get_attr, gre_attr) != MNL_CB_OK) {
		RTE_LOG(ERR, GRE,
			"Could not get GRE attrs for a setup for: %s\n",
			ifp->if_name);
		free(sc);
		return MNL_CB_ERROR;
	}

	if (gre_fill_key_from_params(&h_key, gre_attr,
				     ifp->if_name) != MNL_CB_OK) {
		free(sc);
		return MNL_CB_ERROR;
	}

	/*
	 * Don't need to take a lock on the VRF when searching for existing
	 * gre_infos, if none are found then the lock on the transport VRF
	 * is taken as part of _find_or_create_ call.  The lock on the
	 * overlay VRF is taken when the gre tunnel is set in to a VRF.
	 */
	vrf = vrf_get_rcu(t_vrfid);
	if (vrf) {
		if (gre_info_lookup(vrf->v_gre_infos, &h_key)) {
			RTE_LOG(ERR, GRE, "duplicate GRE tunnel create %s\n",
				ifp->if_name);
			free(sc);
			return MNL_CB_ERROR;
		}
	}
	/*
	 * The tunnel needs to hold lock on both the overlay VRF as well
	 * as the transport VRF
	 */
	vrf = vrf_find_or_create(t_vrfid);
	if (!vrf) {
		DP_LOG_W_VRF(ERR, GRE, ifp->if_vrfid,
			     "Unable to setup GRE tunnel, invalid Id %d\n",
			     t_vrfid);
		free(sc);
		return MNL_CB_ERROR;
	}

	greinfo = gre_info_init(vrf, &h_key);
	if (unlikely(greinfo == NULL)) {
		RTE_LOG(ERR, GRE,
			"Couldn't allocate memory for GRE info: %s\n",
			ifp->if_name);
		free(sc);
		/* Release the lock as the greinfo wasn't added */
		vrf_delete(t_vrfid);
		return MNL_CB_ERROR;
	}

	gre_tunnel_set_params(greinfo, gre_attr);
	greinfo->ifp = ifp;
	sc->scg_gre_info = greinfo;

	if (h_key.family == AF_INET && h_key.remote == INADDR_ANY) {
		/* This is a multipoint tunnel, create the default binding */
		mgre_rt_info_table_init(sc);
		sc->scg_multipoint = 1;
	} else {
		sc->scg_multipoint = 0;
		if (gre_tunnel_add_tracker(greinfo, vrf) < 0) {
			free(sc);
			gre_info_destroy(greinfo);
			/* Release the lock as the greinfo wasn't added */
			vrf_delete(t_vrfid);
			return MNL_CB_ERROR;
		}
	}
	/* To allow deletion from the global table on intf del */
	rcu_assign_pointer(ifp->if_softc, sc);

	return MNL_CB_OK;
}

static struct ifnet *
gre_tunnel_update_tep_internal(struct gre_info_st *greinfo,
			       struct ip_addr *ip)
{
	struct rt_tracker_info *ti_info;
	struct ifnet *nh_ifp = NULL;
	char b[INET6_ADDRSTRLEN];
	uint32_t nh_ifindex;
	uint32_t hash;
	int ret;

	if (!greinfo->ti_info)
		/* Nothing to do, add tep will pick up the correct info */
		return NULL;

	ti_info = greinfo->ti_info;

	if (!ti_info->tracking)
		/* There is no route to the destination */
		return NULL;
	/*
	 * Need to use the correct hashing in case there are multiple
	 * paths to the TEP
	 */
	ip->type = greinfo->family;
	switch (greinfo->family) {
	case AF_INET:
		hash = ecmp_iphdr_hash(&greinfo->iph, 0);
		ret = dp_nh_lookup_by_index(ti_info->nhindex, hash,
					 &ip->address.ip_v4.s_addr,
					 &nh_ifindex);
		if (ip->address.ip_v4.s_addr == INADDR_ANY)
			strncpy(b, "", INET6_ADDRSTRLEN);
		else
			inet_ntop(AF_INET, &ip->address.ip_v4, b, sizeof(b));
		break;
	case AF_INET6:
		hash = ecmp_ip6hdr_hash(&greinfo->iph6, 0);
		ret = dp_nh6_lookup_by_index(ti_info->nhindex, hash,
					  &ip->address.ip_v6,
					  &nh_ifindex);
		if (IN6_ARE_ADDR_EQUAL(&ip->address.ip_v6, &in6addr_any))
			strncpy(b, "", INET6_ADDRSTRLEN);
		else
			inet_ntop(AF_INET6, &ip->address.ip_v6, b, sizeof(b));
		break;
	default:
		return NULL;
	}

	if (ret < 0) {
		RTE_LOG(NOTICE, GRE,
			"%s Tunnel End Point (TEP) not reachable\n",
			greinfo->ifp->if_name);
		return NULL;
	}

	nh_ifp = dp_ifnet_byifindex(nh_ifindex);
	if (!nh_ifp) {
		RTE_LOG(ERR, GRE,
			"Failed to get NH intf for tun %s\n",
			greinfo->ifp->if_name);
		return NULL;
	}

	RTE_LOG(NOTICE, GRE,
		"%s Tunnel End Point (TEP) reachable via %s(%s)\n",
		greinfo->ifp->if_name, b, nh_ifp->if_name);
	return nh_ifp;
}

static void gre_tunnel_update_tep(void *ctx)
{
	struct gre_info_st *greinfo = (struct gre_info_st *)ctx;
	struct fal_attribute_t tun_attrs[8];
	struct ifnet *nh_ifp = NULL;
	unsigned int tun_nattrs = 0;
	struct ip_addr ip;
	uint8_t dscp_val = 0;
	uint8_t ttl = 0;

	/*
	 * If there is no route then we will get a NULL interface back,
	 * but we will still need to send the fal update for the case where
	 * the endpoint has become unreachable.
	 */
	if (!greinfo->fal_tun)
		return;

	switch (greinfo->family) {
	case AF_INET:
		ttl = greinfo->iph.ttl;
		dscp_val = greinfo->iph.tos;
		break;
	case AF_INET6:
		ttl = greinfo->iph6.ip6_hlim;
		dscp_val = ipv6_hdr_get_tos(&greinfo->iph6);
		break;
	}
	tun_attrs[tun_nattrs].id = FAL_TUNNEL_ATTR_ENCAP_DSCP_MODE;
	if (dscp_val & 0x1)
		tun_attrs[tun_nattrs].value.u8 =
			FAL_TUNNEL_DSCP_MODE_UNIFORM_MODEL;
	else {
		tun_attrs[tun_nattrs].value.u8 =
			FAL_TUNNEL_DSCP_MODE_PIPE_MODEL;
		tun_nattrs++;
		tun_attrs[tun_nattrs].id =
			FAL_TUNNEL_ATTR_ENCAP_DSCP_VAL;
		tun_attrs[tun_nattrs].value.u8 = dscp_val;
	}
	tun_nattrs++;

	nh_ifp = gre_tunnel_update_tep_internal(greinfo, &ip);

	tun_attrs[tun_nattrs].id = FAL_TUNNEL_ATTR_NEXTHOP;
	fal_attr_set_ip_addr(&tun_attrs[tun_nattrs], &ip);
	tun_nattrs++;

	tun_attrs[tun_nattrs].id = FAL_TUNNEL_ATTR_UNDERLAY_INTERFACE;
	tun_attrs[tun_nattrs].value.u32 = nh_ifp ? nh_ifp->if_index : 0;
	tun_nattrs++;

	tun_attrs[tun_nattrs].id = FAL_TUNNEL_ATTR_ENCAP_TTL_MODE;
	if (ttl == 0)
		tun_attrs[tun_nattrs].value.u8 =
			FAL_TUNNEL_TTL_MODE_UNIFORM_MODEL;
	else {
		tun_attrs[tun_nattrs].value.u8 =
			FAL_TUNNEL_TTL_MODE_PIPE_MODEL;
		tun_nattrs++;
		tun_attrs[tun_nattrs].id =
			FAL_TUNNEL_ATTR_ENCAP_TTL_VAL;
		tun_attrs[tun_nattrs].value.u8 = ttl;
	}
	tun_nattrs++;

	iptun_set_fal_tep_attr(greinfo->ifp, greinfo->fal_tun, tun_nattrs,
			       tun_attrs);
}

/*
 * Remove a Tunnel End Point (TEP) representation in the hardware.
 */
static void
gre_tunnel_remove_tep(struct ifnet *ifp, struct gre_info_st *tep)
{
	struct gre_softc *sc = ifp->if_softc;
	struct gre_info_st *greinfo;

	if (!tep) {
		/* Only point to point tunnels are supported at the moment */
		if (!sc || !sc->scg_gre_info || sc->scg_multipoint)
			return;

		greinfo = sc->scg_gre_info;
	} else
		greinfo = tep;

	if (greinfo && greinfo->fal_tun)
		iptun_delete_fal_tep(ifp, greinfo->fal_tun);
}

/*
 * Add a Tunnel End Point (TEP) representation in the hardware
 * TEP identifies the tunnel end-point on the underlay network and
 * while for a P2P GRE tunnel, there will only be one such TEP.
 * However, for a P2MP tunnel, there can be multiple such TEPs all
 * belonging to the same overlay L3 interface and they will get
 * programmed in the hardware as when new neighs are discovered
 * by the control plane either via NHRP or other means.
 */
static void
gre_tunnel_add_tep(struct ifnet *ifp, struct gre_info_st *tep)
{
	struct gre_softc *sc;
	struct tun_info_st tun_info;
	struct gre_info_st *greinfo;
	struct ifnet *ul_intf;

	if (!tep) {
		/*
		 * No specific TEP identified, use the first one
		 */
		sc = ifp->if_softc;
		/* Only point to point tunnels are supported at the moment */
		if (!sc || !sc->scg_gre_info || sc->scg_multipoint)
			return;

		greinfo = sc->scg_gre_info;
	} else
		greinfo = tep;

	memset(&tun_info, 0, sizeof(tun_info));
	switch (greinfo->family) {
	case AF_INET:
		tun_info.tun_type = FAL_TUNNEL_TYPE_L3INIP_GRE;

		tun_info.local.type = AF_INET;
		tun_info.local.address.ip_v4.s_addr = greinfo->iph.saddr;

		tun_info.remote.type = AF_INET;
		tun_info.remote.address.ip_v4.s_addr = greinfo->iph.daddr;

		tun_info.ttl_val = greinfo->iph.ttl;
		tun_info.dscp_val = greinfo->iph.tos;
		break;
	case AF_INET6:
		tun_info.tun_type = FAL_TUNNEL_TYPE_L3INIP6_GRE;

		tun_info.local.type = AF_INET6;
		tun_info.local.address.ip_v6 = greinfo->iph6.ip6_src;

		tun_info.remote.type = AF_INET6;
		tun_info.remote.address.ip_v6 = greinfo->iph6.ip6_dst;

		tun_info.ttl_val = greinfo->iph6.ip6_hlim;
		tun_info.dscp_val = ipv6_hdr_get_tos(&greinfo->iph6);
		break;
	}
	if (tun_info.dscp_val & 0x1)
		tun_info.dscp_mode = FAL_TUNNEL_DSCP_MODE_UNIFORM_MODEL;
	else
		tun_info.dscp_mode = FAL_TUNNEL_DSCP_MODE_PIPE_MODEL;

	tun_info.nh_ip.type = greinfo->family;
	tun_info.ol_intf = ifp->if_index;
	tun_info.ul_vrf_id = greinfo->t_vrfid;

	ul_intf = gre_tunnel_update_tep_internal(greinfo, &tun_info.nh_ip);
	if (ul_intf)
		tun_info.ul_intf = ul_intf->if_index;

	if (tun_info.ttl_val == 0)
		tun_info.ttl_mode = FAL_TUNNEL_TTL_MODE_UNIFORM_MODEL;
	else
		tun_info.ttl_mode = FAL_TUNNEL_TTL_MODE_PIPE_MODEL;

	iptun_create_fal_tep(ifp, &tun_info, &greinfo->fal_tun);
}

/* Create GRE tunnel in response to netlink */
struct ifnet *
gre_tunnel_create(int ifindex, const char *ifname,
		  const struct ether_addr *addr, const unsigned int mtu,
		  struct nlattr *data)
{
	struct ifnet *ifp;

	if (!data) {
		RTE_LOG(ERR, DATAPLANE, "GRE: missing linkinfo data\n");
		return NULL;
	}

	ifp = if_alloc(ifname, IFT_TUNNEL_GRE, mtu, addr, SOCKET_ID_ANY);
	if (!ifp) {
		RTE_LOG(ERR, DATAPLANE,
			"out of memory for gre tunnel ifnet\n");
		return NULL;
	}

	if_set_ifindex(ifp, ifindex);

	if (setup_gre_tunnel(ifp, data) != MNL_CB_OK) {
		if_free(ifp);
		return NULL;
	}

	return ifp;
}

void
gre_tunnel_modify(struct ifnet *ifp, struct nlattr *data)
{
	struct nlattr *gre_attr[IFLA_GRE_MAX+1] = { NULL };
	struct gre_info_st *greinfo;
	struct gre_softc *sc;
	/* Assume default transport VRF for now */
	vrfid_t t_vrfid = VRF_DEFAULT_ID;
	struct vrf *vrf = vrf_get_rcu(t_vrfid);

	if (!vrf) {
		DP_LOG_W_VRF(ERR, GRE, ifp->if_vrfid,
			     "Unable to modify %s with invalid id %d",
			     ifp->if_name, t_vrfid);
		return;
	}

	if (mnl_attr_parse_nested(data,
				  gre_get_attr, gre_attr) != MNL_CB_OK) {
		RTE_LOG(ERR, GRE,
			"Could not get GRE attrs for a setup for: %s\n",
			ifp->if_name);
		return;
	}

	sc = ifp->if_softc;
	if (!sc || !sc->scg_gre_info)
		return;
	greinfo = sc->scg_gre_info;

	/* If anything that defines the tunnel changed, delete and recreate. */
	if (gre_attr[IFLA_GRE_LOCAL] && gre_attr[IFLA_GRE_REMOTE]) {
		struct gre_info_hash_key h_key;

		if (gre_fill_key_from_params(&h_key, gre_attr,
					     ifp->if_name) != MNL_CB_OK)
			return;

		if (t_vrfid != greinfo->t_vrfid ||
		    greinfo->flags != h_key.flags ||
		    !gre_info_match(&greinfo->gre_node, &h_key)) {
			/*
			 * The routing info is created/maintained by tunnel
			 * neighbor messages.  A "gre-multicast" tunnel must
			 * have NHRP configured.  Any new feature that uses
			 * "gre-multicast" needs to consider how to handle
			 * the case when the definition of the tunnel
			 * changes.
			 */
			gre_tunnel_delete(ifp);
			setup_gre_tunnel(ifp, data);
			return;
		}
	}
	gre_tunnel_set_params(greinfo, gre_attr);
	/*
	 * Update the FAL with the new attributes
	 */
	gre_tunnel_update_tep(greinfo);
}

static void
gre_softc_free_rcu(struct rcu_head *head)
{
	struct gre_softc *sc = caa_container_of(head, struct gre_softc,
						scg_rcu);

	if (sc->scg_rtinfo_hash_tun) {
		dp_ht_destroy_deferred(sc->scg_rtinfo_hash_nbma);
		dp_ht_destroy_deferred(sc->scg_rtinfo_hash_tun);
	}
	free(sc);
}

static void gre_tunnel_delete(struct ifnet *ifp)
{
	struct gre_softc *sc = ifp->if_softc;
	struct gre_info_st *greinfo;
	vrfid_t t_vrfid;
	struct vrf *vrf;

	if (!sc)
		return;

	greinfo = sc->scg_gre_info;
	t_vrfid = greinfo->t_vrfid;
	vrf = vrf_get_rcu(t_vrfid);
	if (!vrf) {
		DP_LOG_W_VRF(ERR, GRE, ifp->if_vrfid,
			     "Unable to delete %s with invalid id %d",
			     ifp->if_name, t_vrfid);
		return;
	}
	/* Delete tunnel tracker */
	gre_tunnel_remove_tracker(greinfo, vrf);

	if (sc->scg_multipoint) {
		/* Need to flush the mGRE rt info from the hash tables */
		mgre_flush_rtinfo(sc);
	}

	if (sc->scg_rtinfo_hash_tun)
		rte_timer_stop(&sc->scg_rtinfo_timer);

	cds_lfht_del(vrf->v_gre_infos->gi_grehash, &greinfo->gre_node);
	rcu_assign_pointer(ifp->if_softc, NULL);
	rcu_assign_pointer(sc->scg_gre_info, NULL);
	call_rcu(&sc->scg_rcu, gre_softc_free_rcu);

	gre_info_destroy(greinfo);
	/* Release the lock on the transport VRF */
	vrf_delete(t_vrfid);
}

void
gre_tunnel_peer_walk(struct ifnet *ifp,
		     gre_tunnel_peer_iter_func_t func, void *arg)
{
	struct gre_softc *sc;
	struct cds_lfht_iter iter;
	struct mgre_rt_info *rtinfo;

	if (!ifp)
		return;

	sc = ifp->if_softc;
	if (!sc)
		return;

	if (!sc->scg_multipoint) {
		func(ifp, NULL, arg);
		return;
	}
	cds_lfht_for_each_entry(sc->scg_rtinfo_hash_nbma, &iter, rtinfo,
				rtinfo_node_nbma)
		func(ifp, rtinfo, arg);
}

static void
gre_tunnel_peer(struct ifnet *ifp, struct in_addr *tun_addr,
		gre_tunnel_peer_iter_func_t func, void *arg)
{
	struct gre_softc *sc;
	struct mgre_rt_info *rt_info;

	if (!ifp || !tun_addr)
		return;

	sc = rcu_dereference(ifp->if_softc);
	if (!sc)
		return;

	rt_info = mgre_rtinfo_lookup(sc, tun_addr);
	if (!rt_info)
		return;

	func(ifp, rt_info, arg);
}

/* mGRE tunnel netlink message parsing for peer/binding */
static int
mgre_newneigh(struct ifnet *ifp,
	      const struct in_addr *tun_addr,
	      const struct in_addr *nbma_addr)
{
	struct gre_info_st *greinfo, *sub_greinfo;
	/* Assume default transport VRF for now */
	vrfid_t nbma_vrfid = VRF_DEFAULT_ID;
	struct gre_info_hash_key h_key;
	struct gre_softc *sc;
	struct vrf *vrf;
	struct mgre_rt_info *rt_info = NULL;
	int err;

	sc = ifp->if_softc;
	if (!sc)
		return MNL_CB_ERROR;

	/* GRE interface? ignore neigh msg */
	if (!sc->scg_multipoint)
		return MNL_CB_OK;

	rt_info = mgre_rtinfo_lookup(sc, tun_addr);
	if (rt_info) {
		if (nbma_addr->s_addr == rt_info->iph.daddr)
			return MNL_CB_OK;

		/* If nbma address changed, route info needs to be updated. */
		if (!mgre_rtinfo_delete(sc, rt_info))
			return MNL_CB_ERROR;
	}

	greinfo = sc->scg_gre_info;
	if (!greinfo)
		return MNL_CB_ERROR;

	rt_info = zmalloc_aligned(sizeof(*rt_info));
	if (!rt_info) {
		RTE_LOG(ERR, GRE,
			"out of memory for mGRE routing info entry\n");
		return MNL_CB_ERROR;
	}

	rt_info->iph.protocol = IPPROTO_GRE;
	rt_info->iph.id = 0;
	rt_info->iph.ihl = 5;
	rt_info->iph.tos = greinfo->iph.tos;
	rt_info->iph.ttl = greinfo->iph.ttl;
	rt_info->iph.version = IPVERSION;
	rt_info->iph.frag_off = htons(IP_DF);
	rt_info->iph.saddr = greinfo->iph.saddr;
	rt_info->iph.daddr = nbma_addr->s_addr;
	rt_info->tun_addr.s_addr = tun_addr->s_addr;
	rt_info->nbma_vrfid = nbma_vrfid;
	rt_info->rt_info_bits = 0;

	err = mgre_rtinfo_insert(sc, rt_info, nbma_addr);
	if (err != 0) {
		free(rt_info);
		/*
		 * Return code of 1 implies that no new entries
		 * were added to the table because another entry
		 * already exists with the same value. This shouldn't
		 * be processed as a netlink error causing DP to
		 * reset because in case of DMVPN redirects, there
		 * is an transitory new neigh update where the peer
		 * SPOKE's entry contains HUB's NBMA address until
		 * eventually it is replaced with the peer SPOKE's
		 * NBMA address.  Not adding this to the table doesn't
		 * cause any issues since by default traffic for
		 * such a SPOKE would be going to the HUB anyway.
		 */
		return (err > 0 ? MNL_CB_OK : err);
	}

	/*
	 * To enable faster lookups on decap we will add a hash table entry for
	 * this mgre peer
	 */
	h_key.local =  greinfo->iph.saddr;
	h_key.remote = nbma_addr->s_addr;
	h_key.key = greinfo->key;
	h_key.flags = greinfo->flags;
	h_key.family = AF_INET;

	/*
	 * TODO: When the kernel starts sending transport VRF information
	 * update this accordingly, for now use default transport VRF
	 *
	 * The tunnel needs to hold lock on the both the overlay VRF as well as
	 * the transport VRF
	 */
	vrf = vrf_find_or_create(nbma_vrfid);
	if (!vrf) {
		DP_LOG_W_VRF(ERR, GRE, ifp->if_vrfid,
			     "Unable to add mgre neighbour, id %u\n",
			     nbma_vrfid);
		free(rt_info);
		return MNL_CB_ERROR;
	}

	sub_greinfo = gre_info_init(vrf, &h_key);
	if (unlikely(sub_greinfo == NULL)) {
		RTE_LOG(ERR, GRE,
			"Couldn't get mem for sub-GRE info on %s for peer=%s\n",
			ifp->if_name, inet_ntoa(*tun_addr));
		free(rt_info);
		/* Release the lock on the transport VRF acquired above */
		vrf_delete(nbma_vrfid);
		return MNL_CB_ERROR;
	}
	sub_greinfo->iph.ttl = greinfo->iph.ttl;
	sub_greinfo->ifp = ifp;
	rt_info->greinfo = sub_greinfo;
	return MNL_CB_OK;
}

static int
mgre_delneigh(struct ifnet *ifp,
	      const struct in_addr *tun_addr)
{
	struct gre_softc *sc;
	struct mgre_rt_info *rt_info;

	sc = ifp->if_softc;
	if (!sc)
		return MNL_CB_OK;

	/* GRE interface? ignore neigh msg */
	if (!sc->scg_multipoint)
		return MNL_CB_OK;

	rt_info = mgre_rtinfo_lookup(sc, tun_addr);
	if (rt_info) {
		if (!mgre_rtinfo_delete(sc, rt_info))
			return MNL_CB_ERROR;
	} else {
		RTE_LOG(NOTICE, GRE,
			"delneigh for mgre neigh %s but on %s no entry found\n",
			inet_ntoa(*tun_addr), ifp->if_name);
	}
	return MNL_CB_OK;
}

int mgre_ipv4_neigh_change(struct ifnet *ifp,
			   const struct nlmsghdr *nlh,
			   const struct ndmsg *ndm,
			   struct nlattr *tb[])
{
	struct in_addr tun_addr, nbma_addr;
	in_addr_t *neigh_ip, *nbma_ip;

	if (tb[NDA_DST]) {
		if (mnl_attr_get_payload_len(tb[NDA_DST]) != IP_ADDR_LEN) {
			RTE_LOG(NOTICE, GRE,
				"Invalid mGRE dst len in neigh change msg\n");
			return MNL_CB_ERROR;
		}

		neigh_ip = RTA_DATA(tb[NDA_DST]);
		tun_addr.s_addr = *neigh_ip;
	} else {
		RTE_LOG(NOTICE, GRE, "no mGRE DST in NEIGH change msg\n");
		return MNL_CB_ERROR;
	}

	switch (nlh->nlmsg_type) {
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
		if (is_local_ipv4(if_vrfid(ifp), tun_addr.s_addr)) {
			RTE_LOG(NOTICE, GRE,
				"local mGRE DST(%s) in NEIGH change msg; skipping\n",
				inet_ntoa(tun_addr));
			return MNL_CB_OK;
		}

		if ((ndm->ndm_state == NUD_STALE ||
		     ndm->ndm_state == NUD_PROBE) && tb[NDA_LLADDR])
			return MNL_CB_OK;

		if (ndm->ndm_state == NUD_REACHABLE && tb[NDA_LLADDR]) {
			nbma_ip = RTA_DATA(tb[NDA_LLADDR]);
			nbma_addr.s_addr = *nbma_ip;
			return mgre_newneigh(ifp, &tun_addr, &nbma_addr);
		}

		return mgre_delneigh(ifp, &tun_addr);

	default:
		RTE_LOG(NOTICE, GRE,
			"unexpected netlink message type %d\n",
			nlh->nlmsg_type);
	}
	return MNL_CB_OK;
}

/*
 * Find optional gre fields.  Assign field values in network byte order.
 * Return total gre header len.
 */
static uint16_t
gre_parse_header(struct gre_hdr *gre, uint16_t gre_data_len,
		 uint32_t *csum, uint32_t *key, bool *i_seq_flag,
		 uint32_t *seq)
{
	/* GRE header layout depends on the flags set. */
	uint16_t header_len = sizeof(*gre);

	if (gre_data_len < header_len)
		return 0;

	if (gre->flags & GRE_CSUM) {
		if (gre_data_len < header_len + 4)
			return 0;
		*csum = *(uint32_t *)((uint8_t *)gre + header_len);
		header_len += 4;
	} else {
		*csum = 0;
	}

	if (gre->flags & GRE_KEY) {
		if (gre_data_len < header_len + 4)
			return 0;
		*key = *(uint32_t *)((uint8_t *)gre + header_len);
		header_len += 4;
	} else {
		*key = 0;
	}

	if (gre->flags & GRE_SEQ) {
		if (gre_data_len < header_len + 4)
			return 0;
		*i_seq_flag = true;
		*seq = *(uint32_t *)((uint8_t *)gre + header_len);
		header_len += 4;
	} else {
		*i_seq_flag = false;
		*seq = 0;
	}

	return header_len;
}

/*
 * Take an mbuf and return the associated gre_info_st.  Also return:
 * . next_prot: the payload protocol.
 * . decap_size: the total bytes of decap (ip header + gre header)
 */
static struct ifnet *
gre_parse(const struct rte_mbuf *m, struct gre_info_hash_key *h_key,
	  void *gre_start, uint16_t *next_prot, uint16_t *decap_size)
{
	vrfid_t vrfid = pktmbuf_get_vrf(m);
	uint16_t gre_data_len;
	uint16_t gre_hdr_len;
	uint32_t i_seqno;
	bool i_seq_flag;
	struct ifnet *tun_ifp;

	struct vrf *vrf;

	vrf = vrf_get_rcu(vrfid);
	if (!vrf) {
		DP_LOG_W_VRF(ERR, GRE, vrfid,
			     "Packet received in an invalid domain\n");
		return NULL;
	}

	struct gre_info_st *greinfo;
	struct gre_hdr *gre;
	uint32_t csum;

	gre = (struct gre_hdr *)gre_start;

	/*
	 * Calculate number of bytes available to read in the first
	 * segment of the packet from the GRE header onwards.
	 */
	gre_data_len = rte_pktmbuf_data_len(m) - ((char *)gre -
						  rte_pktmbuf_mtod(m, char *));

	gre_hdr_len = gre_parse_header(gre, gre_data_len, &csum,
				       &h_key->key, &i_seq_flag,
				       &i_seqno);
	if (!gre_hdr_len)
		return NULL;
	*decap_size += gre_hdr_len;

	h_key->flags = gre->flags;
	*next_prot = ntohs(gre->ptype);
	greinfo = gre_info_lookup(vrf->v_gre_infos, h_key);
	if (!greinfo) {
		if (h_key->family == AF_INET) {
			h_key->remote = INADDR_ANY;
			greinfo = gre_info_lookup(vrf->v_gre_infos, h_key);
		}
	}

	if (!greinfo)
		return NULL;

	if (greinfo->flags & GRE_SEQ) {
		if (!i_seq_flag)
			/* We expect sequence number, but none received */
			return NULL;
		if ((int32_t)(i_seqno - greinfo->i_seqno) < 0)
			return NULL;
		greinfo->i_seqno = ++i_seqno;
	}

	tun_ifp = greinfo->ifp;
	if (!tun_ifp || !(tun_ifp->if_flags & IFF_UP))
		return NULL;

	return tun_ifp;
}

int ip6_gre_tunnel_in(struct rte_mbuf **m0, struct ip6_hdr *ip6)
{
	struct rte_mbuf *m = *m0;

	//TODO fragments.

	uint16_t decap_size = sizeof(struct ip6_hdr);
	uint16_t next_prot;
	struct ifnet *tun_ifp;
	void *gre_start = (uint8_t *)ip6 + decap_size;
	struct gre_info_hash_key h_key;

	memcpy(&h_key.local6, &ip6->ip6_dst, sizeof(h_key.local6));
	memcpy(&h_key.remote6, &ip6->ip6_src, sizeof(h_key.remote6));
	h_key.key = 0;
	h_key.flags = 0;
	h_key.family = AF_INET6;

	tun_ifp = gre_parse(m, &h_key, gre_start, &next_prot, &decap_size);
	if (!tun_ifp)
		return -1;

	char *inner_ip;

	inner_ip = mbuf_get_inner_ip(m, (char *)ip6, (char *)ip6 + decap_size,
				      &next_prot);

	if (inner_ip) {
		if (ip_tos_ecn_decap(ipv6_hdr_get_tos(ip6), inner_ip,
				     next_prot) == 1)
			return -1;
	}

	if_incr_in(tun_ifp, m);

	pktmbuf_prepare_decap_reswitch(m);

	/*
	 * Set the meta data in case the packet needs to be sent to the kernel.
	 * We may not know that until in the next forwarding pass (ospf on the
	 * tunnel for example) when we will not have the info available.
	 */
	set_spath_rx_meta_data(m, tun_ifp, next_prot, TUN_META_FLAGS_DEFAULT);

	if (iptun_eth_hdr_fixup(m, next_prot, decap_size) != 0)
		return 1;

	switch (next_prot) {
	case ETH_P_IP:
		if (unlikely(tun_ifp->capturing))
			capture_burst(tun_ifp, &m, 1);
		ip_input_decap(tun_ifp, m, L2_PKT_UNICAST);
		break;
	case ETH_P_IPV6:
		{
			struct pl_packet pl_pkt = {
				.mbuf = m,
				.in_ifp = tun_ifp,
			};
			if (unlikely(tun_ifp->capturing))
				capture_burst(tun_ifp, &m, 1);
			pipeline_fused_ipv6_validate(&pl_pkt);
		}
		break;
	default:
		return 1;
	}
	return 0;
}

int ip_gre_tunnel_in(struct rte_mbuf **m0, struct iphdr *ip)
{
	struct rte_mbuf *m = *m0;

	/* Only one fragment contains the GRE header - reassemble */
	if (ip_is_fragment(ip)) {
		m = ipv4_handle_fragment(m);
		if (m == NULL)
			return 0;
		*m0 = m;
		ip = iphdr(m);
	}

	uint16_t decap_size = ip->ihl << 2;
	uint16_t next_prot;
	struct ifnet *tun_ifp;
	struct gre_info_hash_key h_key = { {ip->daddr}, {ip->saddr}, 0, 0,
					   AF_INET };
	void *gre_start = (uint8_t *)ip + decap_size;

	tun_ifp = gre_parse(m, &h_key, gre_start, &next_prot, &decap_size);
	if (!tun_ifp)
		return -1;

	char *inner_ip;

	inner_ip = mbuf_get_inner_ip(m, (char *)ip, (char *)ip + decap_size,
				     &next_prot);
	if (inner_ip)
		if (ip_tos_ecn_decap(ip->tos, inner_ip, next_prot) == 1)
			return -1;

	if_incr_in(tun_ifp, m);

	pktmbuf_prepare_decap_reswitch(m);

	/*
	 * Set the meta data in case the packet needs to be sent to the kernel.
	 * We may not know that until in the next forwarding pass (ospf on the
	 * tunnel for example) when we will not have the info available.
	 */
	set_spath_rx_meta_data(m, tun_ifp, next_prot, TUN_META_FLAGS_DEFAULT);

	if (unlikely(gre_encap_l2_frame(next_prot)))
		rte_pktmbuf_adj(m, decap_size + ETHER_HDR_LEN);
	else
		if (iptun_eth_hdr_fixup(m, next_prot, decap_size) != 0)
			return 1;

	struct bridge_port *brport;

	switch (next_prot) {
	case ETH_P_IP:
		if (unlikely(tun_ifp->capturing))
			capture_burst(tun_ifp, &m, 1);
		ip_input_decap(tun_ifp, m, L2_PKT_UNICAST);
		break;
	case ETH_P_IPV6:
		{
			struct pl_packet pl_pkt = {
				.mbuf = m,
				.in_ifp = tun_ifp,
			};
			if (unlikely(tun_ifp->capturing))
				capture_burst(tun_ifp, &m, 1);
			pipeline_fused_ipv6_validate(&pl_pkt);
		}
		break;
	case ETH_P_ERSPAN_TYPEII:
	case ETH_P_ERSPAN_TYPEIII:
		if (!portmonitor_dest_output(tun_ifp, m))
			return 1;
		break;
	case ETH_P_TEB:
		if (rte_pktmbuf_data_len(m) < sizeof(struct ether_hdr)) {
			if_incr_error(tun_ifp);
			rte_pktmbuf_free(m);
			return 0;
		}

		brport = rcu_dereference(tun_ifp->if_brport);
		if (brport) {
			int err;

			err = bridge_newneigh_tunnel(brport,
						     &ethhdr(m)->s_addr,
						     ip->saddr, 0);
			if (unlikely(err != 0)) {
				rte_pktmbuf_free(m);
				return 0;
			}
		}
		ether_input(tun_ifp, m);
		break;
	default:
		return 1;
	}
	return 0;
}

static void
gre_tunnel_do_send(struct ifnet *tunnel_ifp, struct rte_mbuf *m)
{
	struct iphdr *outer_ip;

	if_incr_out(tunnel_ifp, m);

	/* Give IPsec first crack.  Returns true if packet was consumed */
	if (crypto_policy_check_outbound(tunnel_ifp, &m, RT_TABLE_MAIN,
					 htons(ETHER_TYPE_IPv4), NULL))
		return;

	outer_ip = iphdr(m);

	/* The simple GRE case. */
	if (likely(outer_ip->saddr != outer_ip->daddr)) {
		ip_lookup_and_originate(m, tunnel_ifp);
		return;
	}

	/* A tunnel to ourselves. */
	if (likely(ip_gre_tunnel_in(&m, outer_ip) == 0))
		return;

	rte_pktmbuf_free(m);
}

static bool
gre_tunnel_add_gre_encap(struct gre_info_st *greinfo,
			 struct gre_hdr *gre,
			 const uint16_t proto)
{
	uint32_t offset = 0;

	gre->flags = greinfo->flags;
	gre->ptype = htons(proto);
	offset += sizeof(*gre);
	if (greinfo->flags & GRE_CSUM)
		return false;

	if (greinfo->flags & GRE_KEY) {
		*(uint32_t *)((char *)gre + offset) = greinfo->key;
		offset += 4;
	}
	if (greinfo->flags & GRE_SEQ) {
		*(uint32_t *)((char *)gre + offset) = htonl(greinfo->o_seqno);
		greinfo->o_seqno++;
	}
	return true;
}


static bool
gre_tunnel_add_encap(struct ifnet *tunnel_ifp, struct rte_mbuf *m,
		     const uint16_t proto,
		     const uint16_t inner_len, const uint8_t inner_ttl,
		     const uint8_t inner_tos, const uint16_t dont_frag,
		     char *hdr, struct gre_info_st *greinfo,
		     struct iphdr *outer_ip)
{
	struct gre_hdr *gre;
	struct iphdr *ip = NULL;
	struct ether_hdr *eth_hdr;

	/* Copy GRE header into mbuf then set the pak specific fields */
	gre = (struct gre_hdr *)(hdr + ETHER_HDR_LEN + sizeof(struct iphdr));

	if (!gre_tunnel_add_gre_encap(greinfo, gre, proto)) {
		if_incr_oerror(tunnel_ifp);
		goto drop;
	}

	/* Copy IP header into mbuf, then set the pak specific fields.*/

	/* Need to deal with:
	 *
	 * FRAGMENT:
	 */
	ip = (struct iphdr *) (hdr + ETHER_HDR_LEN);
	memcpy(ip, outer_ip, sizeof(struct iphdr));

	if (ip->ttl == 0)
		ip->ttl = inner_ttl ? inner_ttl : IPDEFTTL;

	/* Need to propagate the DF bit if it is set in the inner pak. */
	if (dont_frag)
		ip->frag_off |= htons(IP_DF);

	/*
	 * Kernel behaviour is that the LSB of the TOS field set means inherit
	 * from inner packet.  If there is also a TOS value set then use that
	 * in the case where the inner packet is not IP.
	 */
	if (outer_ip->tos & 0x1) {
		/*
		 * If the inner packet is not IP, then inner_tos will hold
		 * the correct value to use.
		 */
		ip->tos = inner_tos;
	}

	ip->tot_len =
		htons(inner_len + sizeof(struct iphdr) + greinfo->gre_size);
	ip_tos_ecn_encap(&ip->tos, inner_tos);
	/* RFE-196 CS6 marking by default for GRE/NHRP */
	if (proto == ETH_P_NHRP)
		ip->tos |= IPTOS_PREC_INTERNETCONTROL;
	ip->id = dp_ip_randomid(0);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);

	eth_hdr = (struct ether_hdr *)hdr;
	eth_hdr->ether_type = htons(ETH_P_IP);

	pktmbuf_prepare_encap_out(m);
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;
	dp_pktmbuf_l3_len(m) = sizeof(struct iphdr);

	return true;

drop:
	rte_pktmbuf_free(m);
	return false;
}

struct gre_encap_frag_t {
	struct ifnet *input_ifp;
	const in_addr_t *nxt_ip;
	uint16_t proto;
};

static void
gre_encap_frags(struct ifnet *tunnel_ifp, struct rte_mbuf *m, void *ctx)
{
	const struct gre_encap_frag_t *gre_frag = ctx;

	if (!(tunnel_ifp->if_flags & IFF_NOARP) &&
	    !gre_tunnel_encap(gre_frag->input_ifp, tunnel_ifp,
			      gre_frag->nxt_ip, m, gre_frag->proto))
		return;
	gre_tunnel_send(gre_frag->input_ifp, tunnel_ifp, m,
			gre_frag->proto);
}

void
gre_tunnel_fragment_and_send(struct ifnet *input_ifp, struct ifnet *tunnel_ifp,
			     const in_addr_t *nxt_ip,
			     struct rte_mbuf *m, const uint16_t proto)
{
	struct gre_info_st *greinfo;
	struct gre_softc *sc;
	struct gre_encap_frag_t gre_frag;
	uint16_t mtu_offset = 0;
	bool dont_frag;
	uint16_t inner_len;

	sc = rcu_dereference(tunnel_ifp->if_softc);
	if (!sc || !sc->scg_gre_info) {
		if_incr_oerror(tunnel_ifp);
		goto drop;
	}
	greinfo = sc->scg_gre_info;

	switch (proto) {
	case ETH_P_IP:
	{
		struct iphdr *ip = iphdr(m);

		inner_len = ntohs(ip->tot_len);
		dont_frag = greinfo->ignore_df ? 0
				: ip->frag_off & htons(IP_DF);
		break;
	}
	case ETH_P_IPV6:
	{
		struct ip6_hdr *ip6 = ip6hdr(m);

		inner_len = ntohs(ip6->ip6_plen) + sizeof(*ip6);
		dont_frag = true;
		break;
	}
	case ETH_P_TEB:
	{
		const struct ether_hdr *eh
			= rte_pktmbuf_mtod(m, struct ether_hdr *);

		inner_len = rte_pktmbuf_pkt_len(m);
		dont_frag = true;

		/*
		 * This seems like a layer boundary violation but it is being
		 * done to bring it inline with the linux kernel behaviour
		 * whereby the bridged packets over a GRE interface are
		 * fragmented
		 */
		switch (ntohs(eh->ether_type)) {
		case ETHER_TYPE_IPv4:
		{
			struct iphdr *ip = iphdr(m);

			if (ip_valid_packet(m, ip)) {
				dont_frag =
					greinfo->ignore_df ?
					0 : ip->frag_off & htons(IP_DF);
			}

			break;
		}
		default:
			break;
		}
		mtu_offset = ETHER_HDR_LEN;
		break;
	}
	default:
		if (gre_encap_l2_frame(proto))
			inner_len = rte_pktmbuf_pkt_len(m);
		else
			inner_len = rte_pktmbuf_pkt_len(m) - ETHER_HDR_LEN;
		dont_frag = true;
		break;
	}

	/*
	 * we know how big the header we need to add. Does that cause us
	 * to exceed the tunnel MTU?  If so we fragment into the tunnel, unless
	 * the inner DF bit is set (or is v6).
	 *
	 * The 'mtu_offset' is required because for the TEB GRE interfaces, both
	 * the inner and the outer ETHER_HDR_LEN are already taken into account
	 * by the kernel/control plane when setting the interface's MTU.
	 */
	if (inner_len - mtu_offset > tunnel_ifp->if_mtu) {
		if (dont_frag) {
			switch (proto) {
			case ETH_P_IP:
				IPSTAT_INC_MBUF(m, IPSTATS_MIB_FRAGFAILS);
				icmp_error_out(input_ifp, m, ICMP_DEST_UNREACH,
					   ICMP_FRAG_NEEDED,
					   htons(tunnel_ifp->if_mtu),
					   tunnel_ifp);
				break;
			case ETH_P_IPV6:
				IP6STAT_INC_MBUF(m, IPSTATS_MIB_FRAGFAILS);
				icmp6_error(input_ifp, m, ICMP6_PACKET_TOO_BIG,
					    0, htonl(tunnel_ifp->if_mtu));
				return;
			}
			goto drop;
		} else {
			/*
			 * For each fragment, run the following code to
			 * encap/send.
			 */
			gre_frag.input_ifp = input_ifp;
			gre_frag.nxt_ip = nxt_ip;
			gre_frag.proto = proto;
			ip_fragment(tunnel_ifp, m, &gre_frag, gre_encap_frags);

			return;
		}
	}

	if (!(tunnel_ifp->if_flags & IFF_NOARP) &&
	    !gre_tunnel_encap(input_ifp, tunnel_ifp, nxt_ip, m, proto))
		return;
	gre_tunnel_send(input_ifp, tunnel_ifp, m, proto);
	return;

drop:
	rte_pktmbuf_free(m);
}

/*
 * Apply GRE tunnel to a packet
 *
 * Allocate space and write the encap for packet to be GRE tunnelled,
 * propagating any required information from the payload into the GRE
 * or outer L3 headers.
 *
 * The nexthop address, nxt_ip, is required for mGRE and optional for
 * point-to-point GRE.
 *
 * For non-TEB packets, on calling the packet is expected to be:
 * +-----------------------------------+
 * | 14 bytes of space reserved for L2 |
 * +-----------------------------------+
 * |      Inner L3 (payload)           |
 * +-----------------------------------+
 *
 * For non-TEB packets, on exit the packet is expected to be:
 * +-----------------------------------+
 * | 14 bytes of space reserved for L2 |
 * +-----------------------------------+
 * |      Outer L3 (tunnel src/dst)    |
 * +-----------------------------------+
 * |           GRE headers             |
 * +-----------------------------------+
 * |      Inner L3 (payload)           |
 * +-----------------------------------+
 *
 * For TEB/ERSPAN, on calling:
 * +-----------------------------------+
 * |      Inner L2                     |
 * +-----------------------------------+
 * |      Inner L3 (payload)           |
 * +-----------------------------------+
 *
 * For TEB/ERSPAN, on exit:
 * +-----------------------------------+
 * | 14 bytes of space reserved for L2 |
 * +-----------------------------------+
 * |      Outer L3 (tunnel src/dst)    |
 * +-----------------------------------+
 * |           GRE headers             |
 * +-----------------------------------+
 * |      Inner L2                     |
 * +-----------------------------------+
 * |      Inner L3 (payload)           |
 * +-----------------------------------+
 */
bool
gre_tunnel_encap(struct ifnet *input_ifp, struct ifnet *tunnel_ifp,
		 const in_addr_t *nxt_ip, struct rte_mbuf *m,
		 uint16_t proto)
{
	struct gre_info_st *greinfo;
	struct gre_softc *sc;
	char *hdr;
	struct iphdr *outer_ip = NULL;
	uint16_t new_hdr_len;
	uint16_t inner_len;
	uint8_t inner_ttl;
	uint8_t inner_tos;
	bool inner_df;
	int len_adjust;
	vrfid_t t_vrfid;
	unsigned int eh_offset;
	unsigned int ip_offset;
	const struct ether_hdr *eh;
	uint16_t ether_type;

	sc = rcu_dereference(tunnel_ifp->if_softc);
	if (!sc || !sc->scg_gre_info) {
		if_incr_oerror(tunnel_ifp);
		goto drop;
	}
	greinfo = sc->scg_gre_info;

	if (sc->scg_multipoint && nxt_ip) {
		struct mgre_rt_info *rt_info;
		struct in_addr tun_addr;

		tun_addr.s_addr = *nxt_ip;
		rt_info = mgre_rtinfo_lookup(sc, &tun_addr);
		if (rt_info) {
			outer_ip = &rt_info->iph;
			t_vrfid = rt_info->nbma_vrfid;
			/* Set rt_info to used since the last timer reset */
			CMM_ACCESS_ONCE(rt_info->rt_info_bits) |=
							RT_INFO_BIT_IS_USED;
		} else {
			goto slow_path;
		}
	} else {
		outer_ip = &greinfo->iph;
		t_vrfid = greinfo->t_vrfid;
	}
	/*
	 * TODO - support sequencing and checksum, as it stands these
	 * fields will be put into header (if configured) , but always
	 * set to 0.
	 */
	if (gre_encap_l2_frame(proto)) {
		new_hdr_len = (greinfo->gre_size + sizeof(struct iphdr) +
			       ETHER_HDR_LEN);
		len_adjust = 0;
	} else {
		new_hdr_len = (greinfo->gre_size + sizeof(struct iphdr));
		len_adjust = ETHER_HDR_LEN;
	}

	switch (proto) {
	case ETH_P_IP:
	{
		struct iphdr *ip = iphdr(m);

		inner_len = ntohs(ip->tot_len);
		inner_ttl = ip->ttl;
		inner_tos = ip->tos;
		inner_df =
			greinfo->ignore_df ? 0 : ip->frag_off & htons(IP_DF);
		break;
	}
	case ETH_P_IPV6:
	{
		struct ip6_hdr *ip6 = ip6hdr(m);

		inner_len = ntohs(ip6->ip6_plen) + sizeof(*ip6);
		inner_ttl = ip6->ip6_hlim;
		inner_tos = ipv6_hdr_get_tos(ip6);
		inner_df = true;
		break;
	}
	case ETH_P_ERSPAN_TYPEII:
	case ETH_P_ERSPAN_TYPEIII:
		inner_len = rte_pktmbuf_pkt_len(m);
		inner_ttl = 0;
		inner_tos = 0;
		eh_offset = (proto == ETH_P_ERSPAN_TYPEII ?
					sizeof(struct erspan_v2_hdr) :
					sizeof(struct erspan_v3_hdr));
		eh = rte_pktmbuf_mtod_offset(m, const struct ether_hdr *,
						eh_offset);
		ether_type = eh->ether_type;
		ip_offset = eh_offset + ETHER_HDR_LEN;
		if (ether_type == htons(ETHER_TYPE_IPv4)) {
			const struct iphdr *ip = rte_pktmbuf_mtod_offset(m,
							const struct iphdr *,
							ip_offset);
			inner_ttl = ip->ttl;
			inner_tos = ip->tos;
		} else if (ether_type == htons(ETHER_TYPE_IPv6)) {
			const struct ip6_hdr *ip6 = rte_pktmbuf_mtod_offset(m,
							const struct ip6_hdr *,
							ip_offset);
			inner_ttl = ip6->ip6_hlim;
			inner_tos = ipv6_hdr_get_tos(ip6);
		}
		inner_df = true;
		break;
	case ETH_P_TEB:
	{
		const struct ether_hdr *eh
			= rte_pktmbuf_mtod(m, struct ether_hdr *);

		inner_len = rte_pktmbuf_pkt_len(m) - len_adjust;
		inner_ttl = 0;
		inner_tos = 0;
		inner_df = false;

		switch (ntohs(eh->ether_type)) {
		case ETHER_TYPE_IPv4:
		{
			struct iphdr *ip = iphdr(m);

			if (ip_valid_packet(m, ip)) {
				inner_df =
					greinfo->ignore_df ?
					0 : ip->frag_off & htons(IP_DF);
			}

			break;
		}
		default:
			break;
		}
		break;
	}
	default:
		inner_len = rte_pktmbuf_pkt_len(m) - len_adjust;
		inner_ttl = 0;
		inner_tos = 0;
		inner_df = false;
	}

	pktmbuf_set_vrf(m, t_vrfid);
	if (unlikely(tunnel_ifp->capturing) &&
	    !(proto == ETH_P_ERSPAN_TYPEII ||
	      proto == ETH_P_ERSPAN_TYPEIII))
		capture_burst(tunnel_ifp, &m, 1);

	hdr = rte_pktmbuf_prepend(m, new_hdr_len);
	if (!hdr) {
		if_incr_oerror(tunnel_ifp);
		goto drop;
	}
	return gre_tunnel_add_encap(tunnel_ifp, m, proto, inner_len, inner_ttl,
				    inner_tos, inner_df, hdr, greinfo,
				    outer_ip);

drop:
	rte_pktmbuf_free(m);
	return false;

slow_path:
	if (!input_ifp)
		input_ifp = tunnel_ifp;
	ip_local_deliver(input_ifp, m);
	return false;
}

static bool
gre6_tunnel_add_encap(struct ifnet *tunnel_ifp, struct rte_mbuf *m,
		      const uint16_t proto,
		      const uint16_t inner_len, const uint8_t inner_ttl,
		      const uint8_t inner_tos,
		      char *hdr, struct gre_info_st *greinfo,
		      struct ip6_hdr *outer_ip)
{
	struct gre_hdr *gre;
	struct ip6_hdr *ip6 = NULL;
	struct ether_hdr *eth_hdr;

	/* Copy GRE header into mbuf then set the pak specific fields */
	gre = (struct gre_hdr *)(hdr + ETHER_HDR_LEN + sizeof(struct ip6_hdr));

	if (!gre_tunnel_add_gre_encap(greinfo, gre, proto)) {
		if_incr_oerror(tunnel_ifp);
		goto drop;
	}

	ip6 = (struct ip6_hdr *) (hdr + ETHER_HDR_LEN);
	memcpy(ip6, outer_ip, sizeof(struct ip6_hdr));

	if (ip6->ip6_hlim == 0)
		ip6->ip6_hlim = inner_ttl ? inner_ttl : IPV6_DEFAULT_HOPLIMIT;

	/*
	 * Kernel behaviour is that the LSB of the TOS field set means inherit
	 * from inner packet.  If there is also a TOS value set then use that
	 * in the case where the inner packet is not IP.
	 */
	if (ipv6_hdr_get_tos(ip6) & 0x1) {
		/*
		 * If the inner packet is not IP, then inner_tos will hold
		 * the correct value to use.
		 */
		ip6_ip_dscp_copy_inner(&ip6->ip6_flow, inner_tos);
	}

	ip6->ip6_plen = htons(inner_len + greinfo->gre_size);
	ip6_ip_ecn_encap(&ip6->ip6_flow, inner_tos);

	eth_hdr = (struct ether_hdr *)hdr;
	eth_hdr->ether_type = htons(ETH_P_IPV6);

	pktmbuf_prepare_encap_out(m);
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;
	dp_pktmbuf_l3_len(m) = sizeof(struct ip6_hdr);

	return true;

drop:
	rte_pktmbuf_free(m);
	return false;
}


/*
 * Apply GRE6 tunnel to a packet
 *
 * Allocate space and write the encap for packet to be GRE tunnelled,
 * propagating any required information from the payload into the GRE
 * or outer L3 headers.
 *
 *
 * On calling the packet is expected to be:
 * +-----------------------------------+
 * | 14 bytes of space reserved for L2 |
 * +-----------------------------------+
 * |      Inner L3 (payload)           |
 * +-----------------------------------+
 *
 * On exit the packet is expected to be:
 * +-----------------------------------+
 * | 14 bytes of space reserved for L2 |
 * +-----------------------------------+
 * |      Outer L3 (tunnel src/dst)    |
 * +-----------------------------------+
 * |           GRE headers             |
 * +-----------------------------------+
 * |      Inner L3 (payload)           |
 * +-----------------------------------+
 *
 */
static bool
gre6_tunnel_encap(struct ifnet *tunnel_ifp,
		  struct rte_mbuf *m,
		  uint16_t proto)
{
	struct gre_info_st *greinfo;
	struct gre_softc *sc;
	char *hdr;
	struct ip6_hdr *outer_ip = NULL;
	uint16_t new_hdr_len;
	uint16_t inner_len;
	uint8_t inner_ttl;
	uint8_t inner_tos;
	int len_adjust;
	vrfid_t t_vrfid;

	sc = rcu_dereference(tunnel_ifp->if_softc);
	if (!sc || !sc->scg_gre_info) {
		if_incr_oerror(tunnel_ifp);
		goto drop;
	}
	greinfo = sc->scg_gre_info;

	outer_ip = &greinfo->iph6;
	t_vrfid = greinfo->t_vrfid;

	new_hdr_len = (greinfo->gre_size + sizeof(struct ip6_hdr));
	len_adjust = ETHER_HDR_LEN;

	switch (proto) {
	case ETH_P_IP:
	{
		struct iphdr *ip = iphdr(m);

		inner_len = ntohs(ip->tot_len);
		inner_ttl = ip->ttl;
		inner_tos = ip->tos;
		break;
	}

	case ETH_P_IPV6:
	{
		struct ip6_hdr *ip6 = ip6hdr(m);

		inner_len = ntohs(ip6->ip6_plen) + sizeof(*ip6);
		inner_ttl = ip6->ip6_hlim;
		inner_tos = ipv6_hdr_get_tos(ip6);
		break;
	}
	default:
		inner_len = rte_pktmbuf_pkt_len(m) - len_adjust;
		inner_ttl = 0;
		inner_tos = 0;
	}

	pktmbuf_set_vrf(m, t_vrfid);
	if (unlikely(tunnel_ifp->capturing) &&
	    !(proto == ETH_P_ERSPAN_TYPEII ||
	      proto == ETH_P_ERSPAN_TYPEIII))
		capture_burst(tunnel_ifp, &m, 1);

	hdr = rte_pktmbuf_prepend(m, new_hdr_len);
	if (!hdr) {
		if_incr_oerror(tunnel_ifp);
		goto drop;
	}
	return gre6_tunnel_add_encap(tunnel_ifp, m, proto, inner_len, inner_ttl,
				     inner_tos, hdr, greinfo, outer_ip);

drop:
	rte_pktmbuf_free(m);
	return false;
}

static void
gre6_tunnel_do_send(struct ifnet *tunnel_ifp, struct rte_mbuf *m)
{
	struct ip6_hdr *outer_ip;

	if_incr_out(tunnel_ifp, m);

	/* Give IPsec first crack.  Returns true if packet was consumed */
	if (crypto_policy_check_outbound(tunnel_ifp, &m, RT_TABLE_MAIN,
					 htons(ETHER_TYPE_IPv6), NULL))
		return;

	outer_ip = ip6hdr(m);

	/* The simple GRE case. */
	if (!IN6_ARE_ADDR_EQUAL(&outer_ip->ip6_src,
				&outer_ip->ip6_dst)) {
		ip6_lookup_and_originate(m, tunnel_ifp);
		return;
	}

	/* A tunnel to ourselves. */
	if (likely(ip6_gre_tunnel_in(&m, outer_ip) == 0))
		return;

	rte_pktmbuf_free(m);
}

/*
 * Send a packet on a GRE tunnel interface
 *
 * For IFF_NOARP interfaces (non-multipoint GRE tunnel, not GRE tap)
 * then the encap is applied here prior to sending. For mGRE and GRE
 * tap interfaces, it is expected that the encap should already have
 * been applied by an address resolution protocol (e.g. NHRP for mGRE
 * and ARP for GRE tap).
 */
void
gre_tunnel_send(struct ifnet *input_ifp, struct ifnet *tunnel_ifp,
		struct rte_mbuf *m, const uint16_t proto)
{
	bool send;
	struct gre_softc *sc;

	sc = rcu_dereference(tunnel_ifp->if_softc);
	if (!sc || !sc->scg_gre_info) {
		if_incr_oerror(tunnel_ifp);
		rte_pktmbuf_free(m);
		return;
	}

	if (sc->scg_gre_info->family == AF_INET) {
		if (tunnel_ifp->if_flags & IFF_NOARP)
			send = gre_tunnel_encap(input_ifp, tunnel_ifp, NULL,
						m, proto);
		else
			send = true; /* should already have added encap */
		if (likely(send))
			gre_tunnel_do_send(tunnel_ifp, m);
	} else {
		if (tunnel_ifp->if_flags & IFF_NOARP)
			send = gre6_tunnel_encap(tunnel_ifp, m, proto);
		else
			send = true; /* should already have added encap */
		if (likely(send))
			gre6_tunnel_do_send(tunnel_ifp, m);
	}
}

/* GRE local termination initialisation */
static void
gre_info_table_init(struct gre_infotbl_st *gre_infos)
{
	gre_infos->gi_grehash = cds_lfht_new(GRE_RTHASH_MIN,
					     GRE_RTHASH_MIN,
					     GRE_RTHASH_MAX,
					     CDS_LFHT_AUTO_RESIZE,
					     NULL);
	gre_infos->gi_greseed = random();
	if (gre_infos->gi_grehash == NULL)
		rte_panic("Can't allocate rthash for GRE infos\n");
}

int
gre_table_init(struct vrf *vrf)
{
	vrf->v_gre_infos = malloc(sizeof(struct gre_infotbl_st));
	if (!vrf->v_gre_infos) {
		RTE_LOG(ERR, GRE, "Out of memory for gre_info_softc for %d\n",
			vrf->v_id);
		return -1;
	}

	memset(vrf->v_gre_infos, 0, sizeof(struct gre_infotbl_st));
	gre_info_table_init(vrf->v_gre_infos);
	return 0;
}

void
gre_table_uninit(struct vrf *vrf)
{
	if (!vrf->v_gre_infos)
		return;

	dp_ht_destroy_deferred(vrf->v_gre_infos->gi_grehash);
	free(vrf->v_gre_infos);
	vrf->v_gre_infos = NULL;
}

static void neighbor_dump(struct ifnet *ifp,
			  struct mgre_rt_info *peer, void *arg)
{
	json_writer_t *json = arg;
	char b1[INET_ADDRSTRLEN];
	char b2[INET_ADDRSTRLEN];

	if (!peer) /* not mgre */
		return;

	jsonw_start_object(json);
	jsonw_string_field(json, "ifname", ifp->if_name);
	jsonw_string_field(json, "ip", inet_ntop(AF_INET, &peer->tun_addr,
						 b1, sizeof(b1)));
	jsonw_string_field(json, "nbma", inet_ntop(AF_INET, &peer->iph.daddr,
						   b2, sizeof(b2)));
	jsonw_bool_field(json, "used",
			 (CMM_ACCESS_ONCE(peer->rt_info_bits) &
			 (RT_INFO_BIT_IS_USED|RT_INFO_BIT_WAS_USED)) ? 1 : 0);
	jsonw_end_object(json);
}

static void tun_neighbor_dump(struct ifnet *ifp, void *arg)
{
	if (!is_gre(ifp))
		return;

	gre_tunnel_peer_walk(ifp, neighbor_dump, arg);
}

static int tun_show_neighbors(FILE *f, struct in_addr *tun_addr, int argc,
			      char **argv)
{
	int err = 0;
	json_writer_t *json = jsonw_new(f);

	jsonw_name(json, "neighbors");
	jsonw_start_array(json);

	if (argc == 1) {
		dp_ifnet_walk(tun_neighbor_dump, json);
		goto end;
	}

	while (--argc) {
		struct ifnet *ifp = dp_ifnet_byifname(*++argv);

		if (!ifp) {
			err = -1;
			goto end;
		}
		if (tun_addr == NULL)
			gre_tunnel_peer_walk(ifp, neighbor_dump, json);
		else
			gre_tunnel_peer(ifp, tun_addr, neighbor_dump, json);
	}

 end:
	jsonw_end_array(json);
	jsonw_destroy(&json);
	return err;
}

static void tun_show_tracker(json_writer_t *json, struct gre_info_st *greinfo)
{
	int ret = 0;
	in_addr_t nh;
	uint32_t hash;
	struct ifnet *nifp;
	uint32_t nh_ifindex;
	char b[INET6_ADDRSTRLEN];

	jsonw_name(json, "tracker state");
	jsonw_start_object(json);

	if (!greinfo->ti_info || !greinfo->ti_info->tracking)
		goto unresolved;

	if (greinfo->family == AF_INET) {
		hash = ecmp_iphdr_hash(&greinfo->iph, 0);
		ret = dp_nh_lookup_by_index(greinfo->ti_info->nhindex,
					 hash, &nh, &nh_ifindex);
		if (ret != 0)
			goto unresolved;

		nifp = dp_ifnet_byifindex(nh_ifindex);
		if (!nifp)
			goto unresolved;
		jsonw_string_field(json, "state", "reachable");

		if (nh != INADDR_ANY)
			jsonw_string_field(json, "nexthop",
					   inet_ntop(AF_INET, &nh,
						     b, sizeof(b)));
		else
			jsonw_string_field(json, "nexthop", "attached");

		jsonw_string_field(json, "outgoing_Intf", nifp->if_name);
	}
	/* TBD for v6 */
	jsonw_end_object(json);
	return;

unresolved:
	jsonw_string_field(json, "state", "not reachable");
	jsonw_end_object(json);
}

int cmd_gre(FILE *f, int argc, char **argv)
{
	struct ifnet *ifp;
	struct gre_softc *sc;
	json_writer_t *json;
	struct in_addr tun_addr;
	struct gre_info_st *greinfo;
	struct in_addr *tun_addr_ptr = NULL;

	if (argc == 1)
		return tun_show_neighbors(f, tun_addr_ptr, argc, argv);

	--argc, ++argv;	/* skip "gre" */
	if (strcmp(argv[0], "tun_address") == 0) {
		if (argc < 2) {
			fprintf(f, "usage: gre tun_address <address>\n");
			return -1;
		}
		--argc, ++argv; /* skip "tun_address" */
		if (inet_aton(argv[0], &tun_addr) == 0) {
			fprintf(f, "Invalid address %s\n", argv[2]);
			return -1;
		}
		tun_addr_ptr = &tun_addr;
		--argc, ++argv; /* skip address */
	}

	if (strcmp(argv[0], "tunnel") == 0)
		return tun_show_neighbors(f, tun_addr_ptr, argc, argv);

	if (strcmp(argv[0], "tracker") == 0) {
		if (argc < 2) {
			fprintf(f, "usage: gre tracker <tun intf>\n");
			return -1;
		}
		--argc, ++argv; /* skip "tracker" */
		ifp = dp_ifnet_byifname(*argv);
		if (!ifp) {
			fprintf(f, "Invalid tunnel interface\n");
			return -1;
		}

		sc = rcu_dereference(ifp->if_softc);
		if (!sc || !sc->scg_gre_info)
			return -1;

		greinfo = sc->scg_gre_info;
		if (!greinfo)
			return -1;

		json = jsonw_new(f);
		jsonw_pretty(json, true);
		tun_show_tracker(json, greinfo);
		jsonw_destroy(&json);
		return 0;
	}

	fprintf(f, "Unknown gre command\n");
	return -1;
}

static void gre_show(json_writer_t *wr, struct ifnet *ifp)
{
	struct gre_info_st *greinfo;
	struct gre_softc *sc;
	char b[INET6_ADDRSTRLEN];

	sc = rcu_dereference(ifp->if_softc);
	if (!sc || !sc->scg_gre_info)
		return;
	greinfo = sc->scg_gre_info;

	jsonw_name(wr, "gre");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "key", greinfo->key);
	if (greinfo->family == AF_INET) {
		jsonw_string_field(wr, "source",
				   inet_ntop(AF_INET, &greinfo->iph.saddr,
					     b, sizeof(b)));
		jsonw_string_field(wr, "dest",
				   inet_ntop(AF_INET, &greinfo->iph.daddr,
					     b, sizeof(b)));
		jsonw_uint_field(wr, "tos", greinfo->iph.tos);
		jsonw_uint_field(wr, "ttl", greinfo->iph.ttl);
	} else {
		jsonw_string_field(wr, "source",
				   inet_ntop(AF_INET6, &greinfo->iph6.ip6_src,
					     b, sizeof(b)));
		jsonw_string_field(wr, "dest",
				   inet_ntop(AF_INET6, &greinfo->iph6.ip6_dst,
					     b, sizeof(b)));
		jsonw_uint_field(wr, "tos", ipv6_hdr_get_tos(&greinfo->iph6));
		jsonw_uint_field(wr, "hlim", greinfo->iph6.ip6_hlim);

	}
	jsonw_uint_field(wr, "flags", greinfo->flags);
	jsonw_bool_field(wr, "pmtu-disc",
			 greinfo->iph.frag_off == htons(IP_DF));
	jsonw_bool_field(wr, "ignore-df", greinfo->ignore_df);
	jsonw_uint_field(wr, "transport-vrf", greinfo->t_vrfid);
	tun_show_tracker(wr, greinfo);
	jsonw_end_object(wr);
}

bool gre_tunnel_ignore_df(const struct ifnet *ifp)
{
	struct gre_info_st *greinfo;
	struct gre_softc *sc;

	sc = rcu_dereference(ifp->if_softc);
	if (!sc || !sc->scg_gre_info)
		return false;

	greinfo = sc->scg_gre_info;
	return greinfo->ignore_df;
}

static int
gre_tunnel_dump(struct ifnet *ifp, json_writer_t *wr,
		enum if_dump_state_type type)
{
	switch (type) {
	case IF_DS_STATE:
		gre_show(wr, ifp);
		break;
	default:
		break;
	}

	return 0;
}

static int
gre_if_l3_disable(struct ifnet *ifp)
{
	/* Delete the tunnel object */
	gre_tunnel_remove_tep(ifp, NULL);
	return if_fal_delete_l3_intf(ifp);
}

static int
gre_if_l3_enable(struct ifnet *ifp)
{
	int ret;

	ret = if_fal_create_l3_intf(ifp);
	if (ret < 0)
		return ret;

	gre_tunnel_add_tep(ifp, NULL);

	return 0;
}

static enum dp_ifnet_iana_type
gre_iana_type(struct ifnet *ifp __unused)
{
	return DP_IFTYPE_IANA_TUNNEL;
}

static const struct ift_ops gre_if_ops = {
	.ifop_l3_disable = gre_if_l3_disable,
	.ifop_uninit = gre_tunnel_delete,
	.ifop_dump = gre_tunnel_dump,
	.ifop_l3_enable = gre_if_l3_enable,
	.ifop_iana_type = gre_iana_type,
};

static void gre_type_init(void)
{
	int ret = if_register_type(IFT_TUNNEL_GRE, &gre_if_ops);
	if (ret < 0)
		rte_panic("Failed to register GRE type: %s", strerror(-ret));
}

static const struct dp_event_ops gre_events = {
	.init = gre_type_init,
};

DP_STARTUP_EVENT_REGISTER(gre_events);
