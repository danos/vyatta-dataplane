/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * Watch for rtnetlink events
 */

#include <alloca.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include <linux/netconf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/if_arp.h>
#include <linux/netlink.h>
#include <linux/if.h>
#include <linux/xfrm.h>
#include <czmq.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_memory.h>

#include "compat.h"
#include "compiler.h"
#include "config_internal.h"
#include "crypto/crypto.h"
#include "crypto/crypto_policy.h"
#include "crypto/crypto_sadb.h"
#include "crypto/vti.h"
#include "dp_event.h"
#include "ether.h"
#include "fal.h"
#include "fal_plugin.h"
#include "if/bridge/bridge.h"
#include "if/dpdk-eth/dpdk_eth_if.h"
#include "if/dpdk-eth/vhost.h"
#include "if/gre.h"
#include "if/macvlan.h"
#include "if/vlan/vlan_if.h"
#include "if/vxlan.h"
#include "if_name_types.h"
#include "if_var.h"
#include "ip_mcast.h"
#include "l2_rx_fltr.h"
#include "l2tp/l2tpeth.h"
#include "lag.h"
#include "main.h"
#include "netlink.h"
#include "pipeline/nodes/pppoe/pppoe.h"
#include "route.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "vrf_if.h"
#include "vlan_modify.h"
#include "crypto/xfrm_client.h"

static int linkinfo_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attr to avoid issues with newer kernels */
	if (mnl_attr_type_valid(attr, IFLA_INFO_MAX) < 0)
		return MNL_CB_OK;

	if (type == IFLA_INFO_KIND || type == IFLA_INFO_SLAVE_KIND) {
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"invalid link info kind %d\n", type);
			return MNL_CB_ERROR;
		}
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

struct ifnet *lo_ifp[CONT_SRC_COUNT];

struct ifnet *get_lo_ifp(enum cont_src_en cont_src)
{
	return lo_ifp[cont_src];
}

struct ifnet *lo_or_dummy_create(enum cont_src_en cont_src,
				 unsigned int ifindex,
				 unsigned int flags,
				 const char *ifname,
				 unsigned int mtu,
				 const struct rte_ether_addr *eth_addr)
{
	struct ifnet *ifp;
	struct vfp_softc *vsc;

	ifp = ifnet_byifname_cont_src(cont_src, ifname);
	if (ifp != NULL) {
		vsc = ifp->if_softc;
		vsc->vfp_type = VFP_NONE;
		if_unset_ifindex(ifp);
		if_set_ifindex(ifp, ifindex);
		return ifp;
	}

	ifp = if_alloc(ifname, IFT_LOOP, mtu, eth_addr, SOCKET_ID_ANY, NULL);
	if (!ifp)
		rte_panic("out of memory for lo ifnet\n");

	ifp->if_flags = flags;
	if_set_ifindex(ifp, ifindex);

	vsc = malloc(sizeof(*vsc));
	if (!vsc) {
		if_free(ifp);
		return NULL;
	}
	ifp->if_softc = vsc;
	vsc->vfp_type = VFP_NONE;
	vsc->refcount = 0;

	return ifp;
}

static struct ifnet *lo_create(enum cont_src_en cont_src,
			       unsigned int ifindex,
			       unsigned int flags,
			       const char *ifname,
			       unsigned int mtu,
			       const struct rte_ether_addr *eth_addr)
{
	struct ifnet *lo;

	lo = lo_or_dummy_create(cont_src, ifindex, flags, ifname,
					      mtu, eth_addr);
	/* lo_ifp supported for default vrf only */
	if (streq(ifname, "lo"))
		lo_ifp[cont_src] = lo;

	return lo;
}

static struct ifnet *ppp_create(unsigned int ifindex, const char *ifname,
				unsigned int mtu,
				const struct rte_ether_addr *eth_addr)
{
	struct ifnet *ifp;

	ifp = dp_ifnet_byifname(ifname);
	if (ifp != NULL) {
		if_unset_ifindex(ifp);
		if_set_ifindex(ifp, ifindex);
		return ifp;
	}

	ifp = if_alloc(ifname, IFT_PPP, mtu, eth_addr, SOCKET_ID_ANY, NULL);
	if (!ifp)
		rte_panic("out of memory for ppp ifnet\n");

	if_set_ifindex(ifp, ifindex);
	return ifp;
}

static struct ifnet *other_tunnel_create(unsigned int ifindex,
					 const char *ifname,
					 unsigned int mtu,
					 const struct rte_ether_addr *eth_addr)
{
	struct ifnet *ifp;

	ifp = dp_ifnet_byifname(ifname);
	if (ifp != NULL) {
		if_unset_ifindex(ifp);
		if_set_ifindex(ifp, ifindex);
		return ifp;
	}

	ifp = if_alloc(ifname, IFT_TUNNEL_OTHER, mtu, eth_addr,
		       SOCKET_ID_ANY, NULL);
	if (!ifp)
		rte_panic("out of memory for tunnel ifnet\n");

	if_set_ifindex(ifp, ifindex);
	return ifp;
}

static struct ifnet *pimreg_tunnel_create(unsigned int ifindex,
					 const char *ifname,
					 unsigned int mtu,
					 const struct rte_ether_addr *eth_addr)
{
	struct ifnet *ifp;

	ifp = dp_ifnet_byifname(ifname);
	if (ifp != NULL) {
		if_unset_ifindex(ifp);
		if_set_ifindex(ifp, ifindex);
		return ifp;
	}

	ifp = if_alloc(ifname, IFT_TUNNEL_PIMREG, mtu, eth_addr,
		       SOCKET_ID_ANY, NULL);
	if (!ifp)
		rte_panic("out of memory for tunnel ifnet\n");

	if_set_ifindex(ifp, ifindex);
	return ifp;
}

static void ipip_tunnel_modify(struct ifnet *ifp __unused,
			       struct nlattr *kdata __unused)
{
}

static void tunnel_modify(struct ifnet *ifp,
			  char const *kind, struct nlattr *kdata)
{
	if (!kind) {
		RTE_LOG(NOTICE, DATAPLANE, "missing linkinfo kind\n");
		return;
	}

	if ((strcmp(kind, "gre") == 0) || (strcmp(kind, "gretap") == 0) ||
	    (strcmp(kind, "ip6gre") == 0))
		gre_tunnel_modify(ifp, kdata);
	else if (strcmp(kind, "vti") == 0)
		vti_tunnel_modify(ifp, kdata);
	else if (strcmp(kind, "ipip") == 0)
		ipip_tunnel_modify(ifp, kdata);
}

/* Turns flags into string like "UP,BROADCAST" */
const char *if_flags2str(char *buf, unsigned int flags)
{
	char *cp;

	cp = buf;
#define SPRINT_FLAG(x)	\
	if (flags & IFF_##x)   cp += sprintf(cp, #x ",")

	SPRINT_FLAG(UP);
	SPRINT_FLAG(BROADCAST);
	SPRINT_FLAG(DEBUG);
	SPRINT_FLAG(LOOPBACK);
	SPRINT_FLAG(POINTOPOINT);
	SPRINT_FLAG(NOTRAILERS);
	SPRINT_FLAG(RUNNING);
	SPRINT_FLAG(NOARP);
	SPRINT_FLAG(PROMISC);
	SPRINT_FLAG(ALLMULTI);
	SPRINT_FLAG(MASTER);
	SPRINT_FLAG(SLAVE);
	SPRINT_FLAG(MULTICAST);
	SPRINT_FLAG(PORTSEL);
	SPRINT_FLAG(AUTOMEDIA);
	SPRINT_FLAG(DYNAMIC);
	SPRINT_FLAG(LOWER_UP);
#undef SPRINT_FLAG

	cp[-1] = '\0';
	return buf;
}

static int
vrfinfo_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_VRF_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_VRF_TABLE:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"invalid vrf table attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	default:
		/* Only parse options we care about */
		tb[type] = NULL;
		return MNL_CB_OK;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

/* Create vrf device in response to netlink */
static struct ifnet *
vrf_link_create(const struct ifinfomsg *ifi, const char *ifname,
		struct nlattr *data)
{
	struct nlattr *vrfinfo[IFLA_VRF_MAX+1] = { NULL };

	if (mnl_attr_parse_nested(data,
				  vrfinfo_attr, vrfinfo) != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "Could not get vrfinfo for: %s\n",
			ifname);
		return NULL;
	}

	if (!vrfinfo[IFLA_VRF_TABLE]) {
		RTE_LOG(ERR, DATAPLANE, "Missing VRF table attribute for: %s\n",
			ifname);
		return NULL;
	}

	return vrf_if_create(ifname, ifi->ifi_index,
				mnl_attr_get_u32(vrfinfo[IFLA_VRF_TABLE]));
}

/* Create dataplane tuntap */
static struct ifnet *
dataplane_tuntap_create(unsigned int if_idx, const char *ifname)
{
	return dpdk_eth_if_alloc(ifname, if_idx);
}

/*
 * Handle creation of software interfaces (tunnels, etc)
 * in response to netlink create message.
 */
static struct ifnet *unspec_link_create(const struct ifinfomsg *ifi,
					const char *ifname, struct nlattr *tb[],
					const char *kind, struct nlattr *kdata,
					enum cont_src_en cont_src)
{
	struct rte_ether_addr *macaddr = NULL;
	unsigned int mtu = RTE_ETHER_MTU;
	const uint16_t arphrd = ifi->ifi_type;
	struct ifnet *parent_ifp = NULL;
	unsigned int if_idx = cont_src_ifindex(cont_src, ifi->ifi_index);
	unsigned int parent_idx = 0;

	if (tb[IFLA_ADDRESS])
		macaddr = mnl_attr_get_payload(tb[IFLA_ADDRESS]);

	if (tb[IFLA_MTU])
		mtu = mnl_attr_get_u32(tb[IFLA_MTU]);

	/*
	 * This may be a nested device.
	 *
	 * If the parent index is 0 it indicates it is not associated
	 * with any specific downlink,  and we will ignore it.
	 */
	if (tb[IFLA_LINK])
		parent_idx = cont_src_ifindex(cont_src,
					      mnl_attr_get_u32(tb[IFLA_LINK]));

	/* Ensure we can do strcmp() below */
	kind = (kind) ? kind : "";

	/* First demux on the interface encap type */
	switch (arphrd) {
	case ARPHRD_ETHER:
		/* Handle Ethernet encap types below */
		break;
	case ARPHRD_PPP:
		/* No 'kind' for PPP */
		return ppp_create(if_idx, ifname, mtu, macaddr);
	case ARPHRD_LOOPBACK:
		/* No 'kind' for 'lo' */
		return lo_create(cont_src, if_idx, ifi->ifi_flags, ifname, mtu,
				 macaddr);
	case ARPHRD_TUNNEL: /* IPIP */
		/* Lower layer - ignore it */
		if (!strcmp(ifname, "tunl0") || !strcmp(ifname, "ip_vti0"))
			return NULL;
		if (!strcmp(kind, "vti"))
			return vti_tunnel_create(if_idx, ifname, macaddr, mtu,
						 kdata);

		return other_tunnel_create(if_idx, ifname, mtu, macaddr);
	case ARPHRD_TUNNEL6: /* IP6IP6 */
		/* Lower layer - ignore it */
		if (!strcmp(ifname, "ip6tnl0") || !strcmp(ifname, "ip6_vti0"))
			return NULL;
		if (!strcmp(kind, "vti6"))
			return vti_tunnel_create(if_idx, ifname, macaddr, mtu,
						 kdata);

		return other_tunnel_create(if_idx, ifname, mtu, macaddr);
	case ARPHRD_IPGRE: /* GRE over IP */
		/* Lower layer - ignore it */
		if (!strcmp(ifname, "gre0"))
			return NULL;
		return gre_tunnel_create(if_idx, ifname, macaddr, mtu, kdata);
	case ARPHRD_IP6GRE: /* GRE over IPv6 */
		/* Lower layer - ignore it */
		if (!strcmp(ifname, "ip6gre0"))
			return NULL;
		return gre_tunnel_create(if_idx, ifname, macaddr, mtu, kdata);
	case ARPHRD_SIT: /* IPv6 in IPv4 */
		/* Lower layer - ignore it */
		if (!strcmp(ifname, "sit0"))
			return NULL;
		return other_tunnel_create(if_idx, ifname, mtu, macaddr);
	case ARPHRD_PIMREG:
		return pimreg_tunnel_create(if_idx, ifname, mtu, macaddr);
	case ARPHRD_NONE:
		if (!strcmp(kind, "tun")) {
			/* We do not want an interface for this */
			if (!strcmp(ifname, ".spathintf"))
				return NULL;

			return other_tunnel_create(if_idx, ifname, mtu,
						   macaddr);
		}

		if (!strcmp(kind, "vxlan"))
			return vxlan_create(ifi, ifname, macaddr, tb, kdata,
					    cont_src);

		return NULL;
	default:
		return NULL;
	}

	/*
	 * Various interfaces types with ethernet encapsulation end up here.
	 */

	/*
	 * Use name as 'kind' not present and for nested l2tp interfaces
	 * continue further
	 */
	if (is_l2tpeth(ifname) && !kind[0])
		return l2tpeth_create(if_idx, ifname, mtu, macaddr);

	/* All others should have an explicit 'kind' */
	if (!kind[0])
		return NULL;

	/* brX or vbrX */
	if (!strcmp(kind, "bridge")) {
		return bridge_nl_create(if_idx, ifname, mtu, macaddr, kdata);
	}

	/* Lower for virtual bridge (e.g. vxl-vbr4) */
	if (!strcmp(kind, "vxlan"))
		return vxlan_create(ifi, ifname, macaddr, tb, kdata,
				    cont_src);

	/*
	 * Used by a local tunnel for a GRE bridge.
	 * Our GRE tunnel implementation does not currently support
	 * running over IPv6 so we exclude such interfaces
	 */
	bool is_gretap = false;
	bool is_ip6_gretap = false;

	if (!strcmp(kind, "ip6gretap"))
		is_gretap = is_ip6_gretap = true;
	else if (!strcmp(kind, "gretap"))
		is_gretap = true;

	if (is_gretap) {
		/* Lower layer (only "gretap" kind) - ignore it */
		if (!strcmp(ifname, "gretap0"))
			return NULL;

		if (is_ip6_gretap)
			return NULL;

		return gre_tunnel_create(if_idx, ifname,
					 macaddr, mtu, kdata);
	}

	/* tuntap and openvpn vtun */
	if (!strcmp(kind, "tun")) {
		if (is_dp_intf(ifname))
			return dataplane_tuntap_create(if_idx, ifname);
		if (strncmp(ifname, "vtun", 4) == 0)
			return other_tunnel_create(if_idx, ifname,
						   mtu, macaddr);
	}

	/* bonding e.g. dp0bond1 */
	if (!strcmp(kind, "team"))
		return lag_create(ifi, tb);

	if (strcmp(kind, "vrf") == 0)
		return vrf_link_create(ifi, ifname, kdata);

	/* Loopback (e.g. lo44) or virtual feature point, eg. vfp1 */
	if (!strcmp(kind, "dummy"))
		return lo_or_dummy_create(cont_src, if_idx, ifi->ifi_flags,
					  ifname, mtu, macaddr);

	/* Nested types follow */
	if (parent_idx) {
		parent_ifp = dp_ifnet_byifindex(parent_idx);
		if (!parent_ifp) {
			if (is_ignored_interface(parent_idx))
				RTE_LOG(INFO, DATAPLANE,
					"ignoring link %u not on top of"
					" dataplane interface\n",
					parent_idx);
			return NULL;
		}

		if (!strcmp(kind, "vlan"))
			return vlan_nl_create(parent_ifp, ifname,
					      if_idx, kdata);

		if (!strcmp(kind, "macvlan"))
			return macvlan_create(parent_ifp, ifname,
					      macaddr, if_idx);

		return NULL;
	}

	return NULL;
}

/* Uplink vrf is currently implicit.  When it is explicitly
 * signalled by the local controller, this function can go.
 */
bool
netlink_uplink_vrf(enum cont_src_en cont_src,
		   vrfid_t *vrf_id)
{
	if (cont_src == CONT_SRC_MAIN) {
		/* Leave everything else from CONT_SRC_MAIN alone */
		return true;
	}

	if (cont_src == CONT_SRC_UPLINK &&
	    ((*vrf_id == VRF_DEFAULT_ID) ||
	     (*vrf_id == VRF_UPLINK_ID))) {
		*vrf_id = VRF_UPLINK_ID;
		return true;
	}

	*vrf_id = VRF_INVALID_ID;
	return false;
}

static vrfid_t netlink_get_link_vrf(struct ifnet *ifp,
				    enum cont_src_en cont_src,
				    struct nlattr *tb[])
{
	struct ifnet *team_ifp;

	if (tb[IFLA_MASTER]) {
		uint32_t team;

		team = cont_src_ifindex(cont_src,
					mnl_attr_get_u32(tb[IFLA_MASTER]));
		team_ifp = dp_ifnet_byifindex(team);
		if (team_ifp && team_ifp->if_type == IFT_VRF)
			return vrf_if_get_vrfid(team_ifp);
	} else if (ifp->if_type == IFT_VRF) {
		/*
		 * VRF devices should also be considered to be
		 * inside a VRF
		 */
		return vrf_if_get_vrfid(ifp);
	}

	return VRF_DEFAULT_ID;
}

/* Handle changes to state or parameters to an existing device */
static void unspec_link_modify(struct ifnet *ifp,
			       const struct ifinfomsg *ifi,
			       const char *ifname,
			       struct nlattr *tb[],
			       char const *kind,
			       struct nlattr *kdata,
			       enum cont_src_en cont_src)
{
	struct ifnet *team_ifp = NULL;
	unsigned int flags = ifi->ifi_flags;
	vrfid_t vrf_id, old_vrfid = ifp->if_vrfid;

	/* handle device rename */
	if (strncmp(ifp->if_name, ifname, IFNAMSIZ)) {
		if_rename(ifp, ifname);

		struct fal_attribute_t name_attr = {
			FAL_PORT_ATTR_NAME};

		snprintf(name_attr.value.if_name,
			 sizeof(name_attr.value.if_name),
			 "%s", ifp->if_name);
		fal_l2_upd_port(ifp->if_index, &name_attr);
	}

	if (tb[IFLA_MTU])
		if_set_mtu(ifp, mnl_attr_get_u32(tb[IFLA_MTU]),
			   false);

	if (tb[IFLA_ADDRESS])
		if_set_l2_address(ifp,
				  mnl_attr_get_payload_len(tb[IFLA_ADDRESS]),
				  mnl_attr_get_payload(tb[IFLA_ADDRESS]));

	vrf_id = netlink_get_link_vrf(ifp, cont_src, tb);

	if (!netlink_uplink_vrf(cont_src, &vrf_id))
		return;
	if_set_vrf(ifp, vrf_id);

	if (old_vrfid != ifp->if_vrfid) {
		struct fal_attribute_t l3_vrf_attr = {
			.id = FAL_ROUTER_INTERFACE_ATTR_VRF_OBJ,
			.value.objid = get_vrf(ifp->if_vrfid)->v_fal_obj,
		};

		if_set_l3_intf_attr(ifp, &l3_vrf_attr);
	}

	switch (ifp->if_type) {
	case IFT_BRIDGE:
		bridge_nl_modify(ifp, kdata);
		break;

	case IFT_L2VLAN:
		vlan_nl_modify(ifp, tb, kind, kdata, cont_src);
		break;

	case IFT_VXLAN:
		vxlan_modify(ifp, flags, tb, kdata);
		break;

	case IFT_ETHER:
		if (tb[IFLA_MASTER]) {
			uint32_t if_index;

			if_index = cont_src_ifindex(cont_src,
					mnl_attr_get_u32(tb[IFLA_MASTER]));
			team_ifp = dp_ifnet_byifindex(if_index);

			if (team_ifp == NULL) {
				DP_DEBUG(NETLINK_IF, ERR, DATAPLANE,
					"%s couldn't find bridge or team if_index %d\n",
					ifp->if_name, if_index);
				return;
			}
		}

		if (is_team(team_ifp) || ifp->aggregator)
			lag_nl_member_update(ifi, ifp, team_ifp);
		break;

	case IFT_TUNNEL_GRE:
	case IFT_TUNNEL_VTI:
	case IFT_TUNNEL_OTHER:
		tunnel_modify(ifp, kind, kdata);
		break;
	case IFT_LOOP:
		break;
	case IFT_PPP:
		break; /* Drop though and pickup flags */

	case IFT_MACVLAN:
		break;
	}

	/* Process Admin Up/Down event changes */
	if (ifp->if_flags != flags) {
		struct fal_attribute_t flags_attr = {
			FAL_PORT_ATTR_IFI_FLAGS, .value.u32 = flags };
		uint32_t old_flags = ifp->if_flags;

		ifp->if_flags = flags;

		if (ifp->if_flags & IFF_UP && !(old_flags & IFF_UP))
			if_start(ifp);
		else if (!(ifp->if_flags & IFF_UP) && old_flags & IFF_UP)
			if_stop(ifp);

		if ((ifp->if_flags & IFF_BROADCAST) !=
		    (old_flags & IFF_BROADCAST))
			if_set_broadcast(ifp, ifp->if_flags & IFF_BROADCAST);

		/* IFF_RUNNING may have changed state.  Let the guests
		 * the guests know this.
		 */
		vhost_update_guests(ifp);

		fal_l2_upd_port(ifp->if_index, &flags_attr);
	}
}

static const char *ifitype_name(uint16_t arphrd)
{
	switch (arphrd) {
	case ARPHRD_LOOPBACK: return "loopback";
	case ARPHRD_ETHER: return "ether";
	case ARPHRD_PPP: return "ppp";
	case ARPHRD_TUNNEL: return "tunnel44";
	case ARPHRD_TUNNEL6: return "tunnel66";
	case ARPHRD_IPGRE: return "gre-ip4";
	case ARPHRD_IP6GRE: return "gre-ip6";
	case ARPHRD_SIT: return "tunnel64";
	case ARPHRD_VOID: return "Void";
	case ARPHRD_NONE: return "None";
	default:	 return "Other";
	}
}

/* Messages to AF_UNSPEC about new links */
static int unspec_link_change(const struct nlmsghdr *nlh,
			      const struct ifinfomsg *ifi,
			      struct nlattr *tb[],
			      enum cont_src_en cont_src)
{
	struct ifnet *ifp;
	const char *ifname;
	const char *ifalias = NULL;
	const char *msg;
	int ret = MNL_CB_OK;
	char fbuf[128];
	struct nlattr *linkinfo[IFLA_INFO_MAX+1] = { NULL };
	struct nlattr *kdata = NULL;
	const char *kind = NULL;
	unsigned int ifindex;

	if (tb[IFLA_IFNAME])
		ifname = mnl_attr_get_str(tb[IFLA_IFNAME]);
	else {
		RTE_LOG(NOTICE, DATAPLANE, "missing ifname in link msg\n");
		return MNL_CB_ERROR;
	}

	if (tb[IFLA_IFALIAS])
		ifalias = mnl_attr_get_str(tb[IFLA_IFALIAS]);

	if (tb[IFLA_LINKINFO]) {
		if (mnl_attr_parse_nested(tb[IFLA_LINKINFO],
					  linkinfo_attr,
					  linkinfo) != MNL_CB_OK) {
			RTE_LOG(NOTICE, DATAPLANE, "parse linkinfo failed\n");
			return MNL_CB_ERROR;
		}

		if (linkinfo[IFLA_INFO_KIND])
			kind = mnl_attr_get_str(linkinfo[IFLA_INFO_KIND]);
		kdata = linkinfo[IFLA_INFO_DATA];
	}

	ifindex = cont_src_ifindex(cont_src, ifi->ifi_index);
	ifp = dp_ifnet_byifindex(ifindex);

	if (nlh->nlmsg_type == RTM_NEWLINK)
		msg = (ifp) ? "MOD" : "NEW";
	else if (nlh->nlmsg_type == RTM_DELLINK)
		msg = "DEL";
	else
		msg = nlmsg_type(nlh->nlmsg_type);

	char const *ifp_name = "-";
	char const *ifp_type = "-";
	if (ifp) {
		ifp_name = ifp->if_name;
		ifp_type = iftype_name(ifp->if_type);
	}

	DP_DEBUG(NETLINK_IF, DEBUG, DATAPLANE,
		 "(%s) %u:%s %s link %s/%s (%s/%s/%c) flags <%s> alias %s\n",
		 cont_src_name(cont_src),
		 ifindex, ifname, msg,
		 ifp_name, ifp_type,
		 ifitype_name(ifi->ifi_type),
		 (kind) ? kind : "-",
		 (kdata) ? 'y' : 'n',
		 if_flags2str(fbuf, ifi->ifi_flags),
		 ifalias ? ifalias : "NONE");

	mc_debug_if_flags(ifp, ifi->ifi_flags, nlh->nlmsg_type);

	switch (nlh->nlmsg_type) {
	case RTM_NEWLINK:
		if (ifp) {
			unspec_link_modify(ifp, ifi, ifname, tb, kind, kdata,
					   cont_src);
		} else {
			ifp = unspec_link_create(ifi, ifname, tb, kind,
						 kdata, cont_src);
			if (ifp) {
				vrfid_t vrf_id;

				vrf_id = netlink_get_link_vrf(
					ifp, cont_src, tb);
				if (!netlink_uplink_vrf(cont_src, &vrf_id))
					return MNL_CB_ERROR;
				if_set_vrf(ifp, vrf_id);
				if_set_cont_src(ifp, cont_src);
				ifp->if_flags = ifi->ifi_flags;
				if_set_broadcast(ifp,
						 ifp->if_flags & IFF_BROADCAST);
				if_finish_create(
					ifp, ifitype_name(ifi->ifi_type),
					kind,
					tb[IFLA_ADDRESS] ?
					mnl_attr_get_payload(tb[IFLA_ADDRESS])
					: NULL);
				if (ifp->if_flags & IFF_UP)
					if_start(ifp);
			} else {
				if (is_dp_intf(ifname)) {
					RTE_LOG(WARNING, DATAPLANE,
						 "%u:%s link (%s/%s/%c) Not created\n",
						 ifindex, ifname,
						 ifitype_name(ifi->ifi_type),
						 kind ? kind : "-",
						 kdata ? 'y' : 'n');
				} else {
					incomplete_if_add_ignored(ifindex);
					DP_DEBUG(NETLINK_IF, DEBUG, DATAPLANE,
						 "%u:%s NUL link (%s/%s/%c) Not created\n",
						 ifindex, ifname,
						 ifitype_name(ifi->ifi_type),
						 (kind) ? kind : "-",
						 (kdata) ? 'y' : 'n');
				}
			}
		}
		break;

	case RTM_DELLINK:
		if (is_team(ifp))
			lag_nl_team_delete(ifi, ifp);
		else {
			if (ifp)
				netlink_if_free(ifp);
			else
				incomplete_if_del_ignored(ifindex);
		}
		break;
	}

	return ret;
}

/* Messages to AF_UNSPEC about new mac address */
static int unspec_addr_change(const struct nlmsghdr *nlh,
			      const struct ifaddrmsg *ifa,
			      struct nlattr *tb[],
			      enum cont_src_en cont_src)
{
	const void *addr = NULL;
	struct ifnet *ifp;
	unsigned int ifindex = cont_src_ifindex(cont_src, ifa->ifa_index);

	ifp = dp_ifnet_byifindex(cont_src_ifindex(cont_src, ifindex));

	if (tb[IFA_ADDRESS])
		addr = mnl_attr_get_payload(tb[IFA_ADDRESS]);
	else if (tb[IFA_MULTICAST])
		addr = mnl_attr_get_payload(tb[IFA_MULTICAST]);
	else {
		RTE_LOG(ERR, DATAPLANE,
			"(%s) ifindex %u: missing MAC address in %s\n",
			cont_src_name(cont_src),
			ifindex,
			nlmsg_type(nlh->nlmsg_type));
		return MNL_CB_ERROR;
	}

	DP_DEBUG(NETLINK_ADDR, DEBUG, DATAPLANE,
		 "(%s) %s: unspec addr %s %s\n", cont_src_name(cont_src),
		 ifp ? ifp->if_name : "-",
		 nlmsg_type(nlh->nlmsg_type),
		 ether_ntoa(addr));

	switch (nlh->nlmsg_type) {
	case RTM_NEWADDR:
		if (ifp) {
			l2_rx_fltr_add_addr(ifp, addr);
		} else {
			if (!is_ignored_interface(ifindex))
				RTE_LOG(ERR, DATAPLANE,
					"(%s) unspec addr %s missing interface with index %u\n",
					cont_src_name(cont_src),
					nlmsg_type(nlh->nlmsg_type),
					ifindex);
		}
		break;
	case RTM_DELADDR:
		if (ifp) {
			l2_rx_fltr_del_addr(ifp, addr);
		} else {
			if (!is_ignored_interface(ifindex))
				RTE_LOG(ERR, DATAPLANE,
					"(%s) unspec addr %s missing interface with index %u\n",
					cont_src_name(cont_src),
					nlmsg_type(nlh->nlmsg_type),
					ifindex);
		}
		break;
	default:
		DP_DEBUG(NETLINK_IF, INFO, DATAPLANE,
			 "unexpected netlink message type %d\n",
			 nlh->nlmsg_type);
	}

	return MNL_CB_OK;
}

static const struct netlink_handler unspec_handlers = {
	.link = unspec_link_change,
	.addr = unspec_addr_change,
};

/* Handlers for all possible netlink families.
 * 256 entries because rtm_family is unsigned char.
 */
static const struct netlink_handler *netlink_tbl[256] = {
	[AF_UNSPEC] = &unspec_handlers,
};

void register_netlink_handler(uint8_t family, const struct netlink_handler *h)
{
	if (family > RTNL_FAMILY_MAX)
		rte_panic("invalid family %d registering handler\n", family);

	if (netlink_tbl[family])
		rte_panic("family %u already registered\n", family);

	netlink_tbl[family] = h;
}

/* Call back from libmnl to validate netlink message */
static int neigh_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NDA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

/* Callback to process neighbor messages */
static int notify_neigh(const struct nlmsghdr *nlh, enum cont_src_en cont_src)
{
	struct nlattr *tb[NDA_MAX+1] = { NULL };
	struct ndmsg *ndm = mnl_nlmsg_get_payload(nlh);
	const struct netlink_handler *nlf;
	int ret;

	nlf = netlink_tbl[ndm->ndm_family];
	if (nlf == NULL)
		return MNL_CB_OK;	/* don't care */

	ret = mnl_attr_parse(nlh, sizeof(*ndm), neigh_attr, tb);
	if (ret != MNL_CB_OK) {
		RTE_LOG(NOTICE, DATAPLANE,
			"unparseable neighbour attributes\n");
		return ret;
	}

	if (nlf->neigh) {
		ret = (nlf->neigh)(nlh, ndm, tb, cont_src);
		if (ret != MNL_CB_OK)
			RTE_LOG(NOTICE, DATAPLANE,
				"neighour handler for family=%d failed\n",
				ndm->ndm_family);
		return ret;
	}

	return MNL_CB_OK;
}

/* Callback from attribute parsing to check for expected types */
static int link_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attr to avoid issues with newer kernels */
	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFLA_MTU:
	case IFLA_LINK:
	case IFLA_MASTER:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0)
			goto bad;
		break;


	case IFLA_IFNAME:
	case IFLA_QDISC:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			goto bad;
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
bad:
	RTE_LOG(ERR, DATAPLANE,
		"invalid type %u attribute\n", type);
	return MNL_CB_ERROR;
}

static int notify_link(const struct nlmsghdr *nlh,
		       enum cont_src_en cont_src)
{
	struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[IFLA_MAX+1] = { NULL };
	const struct netlink_handler *nlf;
	int ret;

	nlf = netlink_tbl[ifi->ifi_family];
	if (nlf == NULL)
		return MNL_CB_OK;	/* don't care */

	ret = mnl_attr_parse(nlh, sizeof(*ifi), link_attr, tb);
	if (ret != MNL_CB_OK) {
		RTE_LOG(NOTICE, DATAPLANE,
			"unparseable link attributes\n");
		return ret;
	}

	if (nlf->link) {
		ret = (nlf->link)(nlh, ifi, tb, cont_src);
		if (ret != MNL_CB_OK)
			RTE_LOG(NOTICE, DATAPLANE,
				"link attribute handler (family=%d) failed\n",
				ifi->ifi_family);
		return ret;
	}

	return MNL_CB_OK;
}

/* Call back from libmnl to validate netlink message */
static int addr_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, IFA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case IFA_LABEL:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"invalid link attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	}


	tb[type] = attr;
	return MNL_CB_OK;
}

/* Process new/del address */
static int notify_addr(const struct nlmsghdr *nlh, enum cont_src_en cont_src)
{
	struct ifaddrmsg *ifa =	 mnl_nlmsg_get_payload(nlh);
	const struct netlink_handler *nlf;
	struct nlattr *tb[IFA_MAX+1] = { NULL };
	int ret;

	nlf = netlink_tbl[ifa->ifa_family];
	if (nlf == NULL)
		return MNL_CB_OK;	/* don't care */

	ret = mnl_attr_parse(nlh, sizeof(*ifa), addr_attr, tb);
	if (ret != MNL_CB_OK) {
		RTE_LOG(NOTICE, DATAPLANE,
			"unparseable address attributes\n");
		return ret;
	}

	if (nlf->addr) {
		ret = (nlf->addr)(nlh, ifa, tb, cont_src);
		if (ret != MNL_CB_OK)
			RTE_LOG(NOTICE, DATAPLANE,
				"address handler family=%d failed\n",
				ifa->ifa_family);
		return ret;
	}

	return MNL_CB_OK;
}

static int route_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, RTA_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case RTA_TABLE:
	case RTA_OIF:
	case RTA_FLOW:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"invalid route attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	case RTA_ENCAP_TYPE:
		if (mnl_attr_validate(attr, MNL_TYPE_U16) < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"invalid route attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	case RTA_IIF:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			RTE_LOG(NOTICE, DATAPLANE,
				"invalid route attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

int notify_route(const struct nlmsghdr *nlh, enum cont_src_en cont_src)
{
	struct rtmsg *rtm = mnl_nlmsg_get_payload(nlh);
	const struct netlink_handler *nlf;
	struct nlattr *tb[RTA_MAX+1] = {};
	int ret;

	nlf = netlink_tbl[rtm->rtm_family];
	if (nlf == NULL)
		return MNL_CB_OK; /* don't care */

	/* TODO: skip other address family */
	/* Skip local table? Controller drops local table. */

	ret = mnl_attr_parse(nlh, sizeof(*rtm), route_attr, tb);
	if (ret != MNL_CB_OK) {
		RTE_LOG(NOTICE, DATAPLANE,
			"unparseable route attributes\n");
		return ret;
	}

	if (nlf->route) {
		ret = (nlf->route)(nlh, rtm, tb, cont_src);
		if (ret != MNL_CB_OK)
			RTE_LOG(NOTICE, DATAPLANE,
				"route attribute handler (family=%d) failed\n",
				rtm->rtm_family);
		return ret;
	}

	return MNL_CB_OK;
}

/* Call back from libmnl to validate netlink message */
static int netconf_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NETCONFA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int notify_netconf(const struct nlmsghdr *nlh,
			  enum cont_src_en cont_src)
{
	struct netconfmsg *ncm = mnl_nlmsg_get_payload(nlh);
	const struct netlink_handler *nlf = netlink_tbl[ncm->ncm_family];
	struct nlattr *tb[NETCONFA_MAX+1] = { NULL };
	int ret;

	if (nlf == NULL)
		return MNL_CB_OK;	/* don't care */

	ret = mnl_attr_parse(nlh, sizeof(*ncm), netconf_attr, tb);
	if (ret != MNL_CB_OK) {
		RTE_LOG(NOTICE, DATAPLANE,
			"unparseable netconf attributes\n");
		return ret;
	}

	if (nlf->netconf) {
		ret = (nlf->netconf)(nlh, ncm, tb, cont_src);
		if (ret != MNL_CB_OK)
			RTE_LOG(NOTICE, DATAPLANE,
				"handler for netconf family=%d failed\n",
				ncm->ncm_family);
		return ret;
	}

	return MNL_CB_OK;
}

/* Call back from libmnl to validate netlink message */
static int xfrm_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, XFRMA_MAX + 1) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

/*
 * get_nl_attr_payload()
 *
 * Return pointer to a netlink message attribute if it's
 * present or NULL if it's not.
 */
static inline void *get_nl_attr_payload(const struct nlattr *attr)
{
	if (attr)
		return mnl_attr_get_payload(attr);
	return NULL;
}

static int xfrm_nl_user_tmpl_decode(const struct nlattr *attr,
				    const struct xfrm_user_tmpl **template)
{
	if (!attr)
		return 0;

	*template = mnl_attr_get_payload(attr);
	return mnl_attr_get_payload_len(attr) / sizeof(struct xfrm_user_tmpl);
}

static uint16_t xfrm_attr_offset(uint16_t type)
{
	uint16_t len;

	switch (type) {
	case XFRM_MSG_NEWPOLICY: /* fall through */
	case XFRM_MSG_UPDPOLICY:
		len = sizeof(struct xfrm_userpolicy_info);
		break;
	case XFRM_MSG_DELPOLICY:
		len = sizeof(struct xfrm_userpolicy_id);
		break;
	case XFRM_MSG_POLEXPIRE:
		len = sizeof(struct xfrm_user_polexpire);
		break;
	default:
		/* unknown message types have a huge attribute offset */
		len = -1;
	}
	return len;
}

static void
xfrm_attr_vrf(struct xfrm_selector *sel, vrfid_t *vrfid, uint32_t *ifindex)
{
	if (sel && sel->ifindex) {
		/*
		 * If the ifindex is a vrf then it represents the vrf.
		 * If it is not a vrf, then it means that it is part of
		 * the selector. In this case the vrf will be the vrf
		 * of the given ifindex if set, otherwise the DEFAULT vrf.
		 */
		struct ifnet *ifp = dp_ifnet_byifindex(sel->ifindex);

		if (ifp) {
			if (ifp->if_type == IFT_VRF) {
				*vrfid = vrf_if_get_vrfid(ifp);
				RTE_LOG(INFO, DATAPLANE, "XFRM using VRF %u\n",
					*vrfid);
			} else {
				*vrfid = if_vrfid(ifp);
				RTE_LOG(INFO, DATAPLANE,
					"XFRM using if %d, VRF %u\n",
					sel->ifindex, *vrfid);
			}
			/* Indicate that this is complete */
			*ifindex = 0;
		} else {
			/*
			 * Set to an ifindex that we don't know about yet,
			 * this is likely a race in the order the messages
			 * arrive.
			 */
			*ifindex = sel->ifindex;
		}
	}
}

static int
xfrm_nl_policy_decode(const struct nlmsghdr *nlh,
		      struct xfrm_userpolicy_id **usr_id,
		      const struct xfrm_userpolicy_info **usr_policy,
		      const struct xfrm_user_tmpl **usr_tmpl,
		      const struct xfrm_mark **mark,
		      vrfid_t *vrfid,
		      uint32_t *ifindex)
{
	struct xfrm_user_polexpire *pol_expire;
	struct xfrm_userpolicy_info *pol_info;
	struct nlattr *tb[XFRMA_MAX] = { NULL };
	uint16_t len, offset;
	int ret;

	*usr_policy = NULL;
	*usr_id = NULL;
	*usr_tmpl = NULL;
	*mark = NULL;

	len = mnl_nlmsg_get_payload_len(nlh);
	offset = xfrm_attr_offset(nlh->nlmsg_type);

	/* also checks that mnl_nlmsg_get_payload() below works */
	if (offset > len) {
		RTE_LOG(ERR, DATAPLANE, "Can't parse XFRM attributes\n");
		return -1;
	}

	/* xfrm_attr should always return successful */
	ret = mnl_attr_parse(nlh, offset, xfrm_attr, tb);
	if (ret != MNL_CB_OK) {
		RTE_LOG(ERR, DATAPLANE, "Failed parsing XFRM attributes\n");
		return -1;
	}

	switch (nlh->nlmsg_type) {
	case XFRM_MSG_DELPOLICY:
		*usr_id = mnl_nlmsg_get_payload(nlh);
		if (tb[XFRMA_MARK])
			*mark = mnl_attr_get_payload(tb[XFRMA_MARK]);
		/*
		 * Update VRF from selection index (if supplied)
		 */
		xfrm_attr_vrf(&(*usr_id)->sel, vrfid, ifindex);

		break;
	case XFRM_MSG_POLEXPIRE:
		pol_expire = mnl_nlmsg_get_payload(nlh);
		pol_info = &pol_expire->pol;
		*usr_policy = pol_info;

		/*
		 * Update VRF from selection index (if supplied)
		 */
		xfrm_attr_vrf(&pol_info->sel, vrfid, ifindex);

		break;
	case XFRM_MSG_NEWPOLICY: /* fall through */
	case XFRM_MSG_UPDPOLICY:
		pol_info = mnl_nlmsg_get_payload(nlh);

		if (pol_info->action == XFRM_POLICY_ALLOW) {
			const struct xfrm_user_tmpl *tmpl = NULL;
			int count = xfrm_nl_user_tmpl_decode(tb[XFRMA_TMPL],
							     &tmpl);

			/* there is one template per proto (IPCOMP/ESP/AH) */
			while (count--) {
				if (tmpl->id.proto == IPPROTO_ESP)
					*usr_tmpl = tmpl;
				tmpl++;
			}
		}
		if (tb[XFRMA_MARK])
			*mark = mnl_attr_get_payload(tb[XFRMA_MARK]);
		*usr_policy = pol_info;

		/*
		 * Update VRF from selection index (if supplied)
		 */
		xfrm_attr_vrf(&pol_info->sel, vrfid, ifindex);

		break;
	default:
		RTE_LOG(ERR, DATAPLANE,
			"xfrm: unexpected netlink policy msg %u\n",
			nlh->nlmsg_type);
		return -1;
	}

	return 0;
}

/* Callback for all netlink messages */
int rtnl_process(const struct nlmsghdr *nlh, void *data)
{
	enum cont_src_en cont_src = (uintptr_t)data;

	switch (nlh->nlmsg_type) {
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
		return notify_neigh(nlh, cont_src);

	case RTM_NEWLINK:
	case RTM_DELLINK:
		return notify_link(nlh, cont_src);

	case RTM_NEWADDR:
	case RTM_DELADDR:
		return notify_addr(nlh, cont_src);

	case RTM_NEWROUTE:
	case RTM_DELROUTE:
		return notify_route(nlh, cont_src);

	case RTM_NEWNETCONF:
	case RTM_DELNETCONF:
		return notify_netconf(nlh, cont_src);

	case RTM_NEWCHAIN:
		/* No need to create a new chain, as we create it
		 * implicity when the first filter on the chain is
		 * created.
		 */
		return MNL_CB_OK;
	case RTM_DELCHAIN:
		return vlan_mod_flt_chain_delete(nlh);

	case RTM_NEWTFILTER:
		return vlan_mod_flt_entry_add(nlh);
	case RTM_DELTFILTER:
		return vlan_mod_flt_entry_delete(nlh);

	case RTM_NEWQDISC:
	case RTM_DELQDISC:
		return MNL_CB_OK;
	}
	return MNL_CB_OK;
}

static bool crypto_incmpl_xfrm(uint32_t ifindex)
{
	if (ifindex)
		return true;
	return false;
}

/* Callback for all XFRM POLICY messages */
int rtnl_process_xfrm(const struct nlmsghdr *nlh, void *data)
{
	struct xfrm_userpolicy_id *id = NULL;
	const struct xfrm_userpolicy_info *policy = NULL;
	const struct xfrm_user_tmpl *tmpl = NULL;
	struct xfrm_userpolicy_id tmp_id;
	const struct xfrm_selector *sel;
	uint8_t dir;
	int ret, status = MNL_CB_OK;
	const xfrm_address_t *peer = NULL;
	const struct xfrm_mark *mark = NULL;
	vrfid_t vrfid;
	uint32_t ifindex = 0;
	struct xfrm_client_aux_data *xfrm_aux;

	xfrm_aux = (struct xfrm_client_aux_data *)data;

	vrfid = *xfrm_aux->vrf;
	xfrm_aux->ack_msg = false;

	ret = xfrm_nl_policy_decode(nlh, &id, &policy, &tmpl, &mark, &vrfid,
				    &ifindex);
	if (ret < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to decode XFRM Policy message\n");
		return MNL_CB_ERROR;
	}

	if (policy == NULL && id == NULL) {
		xfrm_aux->ack_msg = true;
		goto out;
	}

	if (policy) {
		sel = &policy->sel;
		dir = policy->dir;
	} else {
		sel = &id->sel;
		dir = id->dir;
	}

	/*
	 * Delete any existing entry for this policy from the incomplete
	 * cache. It will get re-added if required.
	 */
	crypto_incmpl_xfrm_policy_del(ifindex, nlh, sel, mark);

	/*
	 * If the interface a policy depends upon has not yet arrived
	 * then the policy is rejected and strongswan will retry.
	 * later.
	 */
	if (crypto_incmpl_xfrm(ifindex)) {
		RTE_LOG(NOTICE, DATAPLANE, "XFRM policy missing interface\n");
		xfrm_aux->ack_msg = true;
		status = -1;
		goto out;
	}

	/*
	 * If we are in a non default vrf, and the selector ifindex is a
	 * VRF, then set it to 0, as we do not want to compare in the
	 * fastpath for this case. We do this here, instead of when parsing
	 * the attributes, as changing the values before the incomplete
	 * processing can lead to stuff not being removed from the incomplete
	 * list properly.
	 */
	if (vrfid != VRF_DEFAULT_ID) {
		if (sel->ifindex) {
			struct ifnet *ifp = dp_ifnet_byifindex(sel->ifindex);
			struct xfrm_selector *new_sel;

			new_sel = (struct xfrm_selector *)sel;
			if (ifp && ifp->if_type == IFT_VRF)
				new_sel->ifindex = 0;
		}
	}

	if (nlh->nlmsg_type == XFRM_MSG_NEWPOLICY ||
	    nlh->nlmsg_type == XFRM_MSG_UPDPOLICY) {
		if (tmpl) {
			if (tmpl->mode == XFRM_MODE_TUNNEL)
				peer = &tmpl->id.daddr;
			else
				peer = &policy->sel.daddr;

		}
	}

	/*
	 * Ignore _FWD policies since We only create IN and OUT policies.
	 */
	if (dir & ~(XFRM_POLICY_IN|XFRM_POLICY_OUT)) {
		xfrm_aux->ack_msg = true;
		goto out;
	}

	switch (nlh->nlmsg_type) {
	case XFRM_MSG_NEWPOLICY:
		if (crypto_policy_add(policy, peer, tmpl, mark, vrfid,
				      nlh->nlmsg_seq,
				      &xfrm_aux->ack_msg) < 0) {
			RTE_LOG(ERR, DATAPLANE, "NEWPOLICY failure\n");
			status = MNL_CB_ERROR;
		}
		break;
	case XFRM_MSG_UPDPOLICY:
		if (crypto_policy_update(policy, peer, tmpl, mark, vrfid,
					 nlh->nlmsg_seq,
					 &xfrm_aux->ack_msg) < 0) {
			RTE_LOG(ERR, DATAPLANE, "UPDPOLICY failure\n");
			status = MNL_CB_ERROR;
		}
		break;
	case XFRM_MSG_POLEXPIRE:
		memcpy(&tmp_id.sel, sel, sizeof(tmp_id.sel));
		tmp_id.dir = dir;
		tmp_id.index = 0;
		id = &tmp_id;
		/* fall through */
	case XFRM_MSG_DELPOLICY:
		crypto_policy_delete(id, mark, vrfid, nlh->nlmsg_seq,
				     &xfrm_aux->ack_msg);
		break;
	default:
		RTE_LOG(ERR, DATAPLANE, "Unhandled XFRM policy message\n");
		status = MNL_CB_ERROR;
		break;
	}
out:
	return status;
}

/*
 * process_xfrm_newsa()
 *
 * Process an XFRM new or update SA message.
 */
static int process_xfrm_newsa(struct xfrm_usersa_info *sa_info,
			       const char *msg_type_str,
			       struct nlattr **attrs,
			       vrfid_t vrf_id,
			       uint32_t *ifindex)
{
	struct xfrm_algo_aead *aead_algo;
	struct xfrm_algo_auth *auth_trunc_algo;
	struct xfrm_algo *auth_algo;
	struct xfrm_algo *crypto_algo = NULL;
	struct xfrm_encap_tmpl *tmpl = NULL;
	struct xfrm_mark *mark;
	uint32_t mark_val;
	uint32_t extra_flags = 0;
	int rc = MNL_CB_OK;

	/*
	 * VRF. Use topic default if no attribute
	 */
	xfrm_attr_vrf(&sa_info->sel, &vrf_id, ifindex);

	if (crypto_incmpl_xfrm(*ifindex))
		return MNL_CB_ERROR;

	/*
	 * AEAD/crypto algorithm
	 */
	aead_algo = get_nl_attr_payload(attrs[XFRMA_ALG_AEAD]);
	crypto_algo = get_nl_attr_payload(attrs[XFRMA_ALG_CRYPT]);

	/*
	 * Authentication algorithm
	 */
	auth_trunc_algo = get_nl_attr_payload(attrs[XFRMA_ALG_AUTH_TRUNC]);
	auth_algo = get_nl_attr_payload(attrs[XFRMA_ALG_AUTH]);

	/*
	 * TODO: Currently SADB doesn't cope with no AUTH algo, should it?
	 */
	if (!aead_algo && !crypto_algo && !auth_algo) {
		RTE_LOG(ERR, DATAPLANE,
			"Missing XFRMA_ALG_* attribute on XFRM %s message\n",
			msg_type_str);
		rc = MNL_CB_ERROR;
		goto scrub;
	}

	if (attrs[XFRMA_MARK]) {
		mark = get_nl_attr_payload(attrs[XFRMA_MARK]);
		if (!mark) {
			RTE_LOG(ERR, DATAPLANE,
				"Could not decode MARK attr\n");
			rc = MNL_CB_ERROR;
			goto scrub;
		}
		mark_val = mark->v;
	} else
		mark_val = 0;

	if (attrs[XFRMA_SA_EXTRA_FLAGS])
		extra_flags = mnl_attr_get_u32(attrs[XFRMA_SA_EXTRA_FLAGS]);

	if (attrs[XFRMA_ENCAP]) {
		tmpl = get_nl_attr_payload(attrs[XFRMA_ENCAP]);
		if (!tmpl) {
			RTE_LOG(ERR, DATAPLANE,
				"Could not decode ENCAP attr\n");
			rc = MNL_CB_ERROR;
			goto scrub;
		}
	}

	/* create on-stack xfrm_algo to create the SA */
	if (aead_algo) {
		crypto_algo = alloca(sizeof(struct xfrm_algo) +
				     aead_algo->alg_key_len / 8);
		memcpy(crypto_algo->alg_name, aead_algo->alg_name, 64);
		crypto_algo->alg_key_len = aead_algo->alg_key_len;
		memcpy(crypto_algo->alg_key, aead_algo->alg_key,
		       aead_algo->alg_key_len / 8);
		auth_trunc_algo = (struct xfrm_algo_auth *)aead_algo;
	}

	if (crypto_sadb_new_sa(sa_info, crypto_algo, auth_trunc_algo, auth_algo,
			       tmpl, mark_val, extra_flags, vrf_id) != 0)
		rc = MNL_CB_ERROR;
	/* The above failure case needs to fall into scrub */

 scrub:
	/*
	 * Scrub the keys from the inbound netlink message. This is done
	 * so they aren't leaked when the ZMQ buffer is freed.
	 */
	aead_algo = get_nl_attr_payload(attrs[XFRMA_ALG_AEAD]);
	if (aead_algo) {
		memset(aead_algo->alg_key, 0xff,
		       (aead_algo->alg_key_len >> 3));
		if (crypto_algo)
			memset(crypto_algo->alg_key, 0xff,
			       (crypto_algo->alg_key_len >> 3));
	}

	crypto_algo = get_nl_attr_payload(attrs[XFRMA_ALG_CRYPT]);
	if (crypto_algo)
		memset(crypto_algo->alg_key, 0xff,
		       (crypto_algo->alg_key_len >> 3));

	auth_trunc_algo = get_nl_attr_payload(attrs[XFRMA_ALG_AUTH_TRUNC]);
	if (auth_trunc_algo)
		memset(auth_trunc_algo->alg_key, 0xff,
		       (auth_trunc_algo->alg_key_len >> 3));

	auth_algo = get_nl_attr_payload(attrs[XFRMA_ALG_AUTH]);
	if (auth_algo)
		memset(auth_algo->alg_key, 0xff, (auth_algo->alg_key_len >> 3));
	return rc;
}

/*
 * process_xfrm_delsa()
 *
 * Process an XFRM delete SA message.
 */
static int process_xfrm_delsa(struct xfrm_usersa_info *sa_info,
			       vrfid_t vrfid, uint32_t *ifindex)
{
	xfrm_attr_vrf(sa_info ? &sa_info->sel : NULL, &vrfid, ifindex);

	if (crypto_incmpl_xfrm(*ifindex))
		return MNL_CB_ERROR;

	if (crypto_sadb_del_sa(sa_info, vrfid) != 0)
		return MNL_CB_ERROR;
	return MNL_CB_OK;
}

static int
process_xfrm_getsa(const struct xfrm_usersa_id *sa_id,
		   vrfid_t vrf_id, uint32_t seq)
{
	struct crypto_sadb_stats sa;

	if (!crypto_sadb_get_stats(vrf_id, sa_id->daddr,
				   sa_id->family, sa_id->spi, &sa))
		return -1;

	return xfrm_client_send_sa_stats(seq, sa_id->spi, &sa);
}

/*
 * rtnl_process_xfrm_sa()
 *
 * Callback to handle all XFRM SA messages
 */
int rtnl_process_xfrm_sa(const struct nlmsghdr *nlh, void *data)
{
	const size_t payload_size = mnl_nlmsg_get_payload_len(nlh);
	/*
	 * Allow space for new XFRM_SA_EXTRA_FLAGS attribute not
	 * supported in build xfrm.h
	 */
	struct nlattr *attrs[XFRMA_MAX + 1] = { NULL };
	struct xfrm_usersa_info  *sa_info = NULL;
	const struct xfrm_user_expire *expire;
	const struct xfrm_usersa_id *sa_id;
	const char *msg_type_str;
	vrfid_t vrf_id;
	uint32_t seq, ifindex = 0;
	struct xfrm_client_aux_data *xfrm_aux;

	xfrm_aux = (struct xfrm_client_aux_data *)data;
	vrf_id = *xfrm_aux->vrf;
	seq = xfrm_aux->seq;
	xfrm_aux->ack_msg = true;

	switch (nlh->nlmsg_type) {

	case XFRM_MSG_NEWSA: /* fall through */
	case XFRM_MSG_UPDSA:
		msg_type_str = (nlh->nlmsg_type == XFRM_MSG_NEWSA) ? "NEWSA"
								   : "UPDSA";
		if (payload_size < sizeof(*sa_info)) {
			RTE_LOG(ERR, DATAPLANE, "xfrm: too short for %s\n",
				msg_type_str);
			return MNL_CB_ERROR;
		}
		sa_info = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*sa_info),
				   xfrm_attr, attrs) != MNL_CB_OK) {
			RTE_LOG(ERR, DATAPLANE,
				"xfrm: can't parse attributes to %s\n",
				msg_type_str);
			return MNL_CB_ERROR;
		}

		if (process_xfrm_newsa(sa_info, msg_type_str, attrs, vrf_id,
				       &ifindex) != MNL_CB_OK)
			return MNL_CB_ERROR;
		break;

	case XFRM_MSG_DELSA:
		if (payload_size < sizeof(*sa_id)) {
			RTE_LOG(ERR, DATAPLANE, "xfrm: too short for DELSA\n");
			return MNL_CB_ERROR;
		}
		mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*sa_id),
				   xfrm_attr, attrs)  != MNL_CB_OK) {
			RTE_LOG(ERR, DATAPLANE,
				"xfrm: can't parse attributes to DELSA\n");
			return MNL_CB_ERROR;
		}
		sa_info = get_nl_attr_payload(attrs[XFRMA_SA]);
		if (!sa_info) {
			RTE_LOG(ERR, DATAPLANE,
				"Could not decode DELSA XFRM_SA attribute\n");
			return MNL_CB_ERROR;
		}
		if (process_xfrm_delsa(sa_info, vrf_id, &ifindex) != MNL_CB_OK)
			return MNL_CB_ERROR;
		break;

	case XFRM_MSG_EXPIRE:
		if (payload_size < sizeof(*expire)) {
			RTE_LOG(ERR, DATAPLANE, "xfrm: too short for EXPIRE\n");
			return MNL_CB_ERROR;
		}
		expire = mnl_nlmsg_get_payload(nlh);
		if (expire->hard)
			crypto_sadb_del_sa(&expire->state, vrf_id);
		break;

	case XFRM_MSG_GETSA:
		if (payload_size < sizeof(*sa_id)) {
			RTE_LOG(ERR, DATAPLANE, "xfrm: too short for GETSA\n");
			return MNL_CB_ERROR;
		}

		sa_id = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*sa_id),
				   xfrm_attr, attrs)  != MNL_CB_OK) {
			RTE_LOG(ERR, DATAPLANE,
				"xfrm: can't parse attributes to GETA\n");
			return MNL_CB_ERROR;
		}

		if (process_xfrm_getsa(sa_id, vrf_id, seq) < 0)
			return MNL_CB_ERROR;
		/*
		 * If we have successfully processed the stats request
		 * then we do not need to send an ack back, as the
		 * stats response message is in effect the ack.
		 */
		xfrm_aux->ack_msg = false;

		return MNL_CB_OK;
	default:
		RTE_LOG(ERR, DATAPLANE, "xfrm: unexpected netlink SA msg %u\n",
			nlh->nlmsg_type);
		return MNL_CB_ERROR;
	}

	/*
	 * Delete any existing entry for this SA from the incomplete
	 * cache. It will get re-added if required.
	 */
	crypto_incmpl_xfrm_sa_del(ifindex, nlh, sa_info);

	if (crypto_incmpl_xfrm(ifindex))
		crypto_incmpl_xfrm_sa_add(ifindex, nlh, sa_info);
	return MNL_CB_OK;
}
