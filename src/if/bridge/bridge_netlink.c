/*-
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <libmnl/libmnl.h>
#include <linux/if_link.h>

#include "bridge.h"
#include "fal.h"
#include "if_var.h"
#include "vplane_log.h"

/*
 * Nested bridge info attributes
 * [IFLA_LINKINFO] -> [IFLA_INFO_DATA] -> [IFLA_BR_xxx]
 */
static int ifla_br_attr_type[IFLA_BR_MAX+1] = {
	[IFLA_BR_UNSPEC]        = 0,
	[IFLA_BR_FORWARD_DELAY] = MNL_TYPE_U32,
	[IFLA_BR_HELLO_TIME]    = MNL_TYPE_U32,
	[IFLA_BR_MAX_AGE]       = MNL_TYPE_U32,
	[IFLA_BR_AGEING_TIME]   = MNL_TYPE_U32,
	[IFLA_BR_STP_STATE]     = MNL_TYPE_U32,
	[IFLA_BR_PRIORITY]      = MNL_TYPE_U16,
	[IFLA_BR_VLAN_FILTERING]             = MNL_TYPE_U8,
	[IFLA_BR_VLAN_PROTOCOL]              = MNL_TYPE_U16,
	[IFLA_BR_GROUP_FWD_MASK]             = MNL_TYPE_U16,
	[IFLA_BR_GROUP_ADDR]                 = MNL_TYPE_BINARY,
	[IFLA_BR_MCAST_ROUTER]               = MNL_TYPE_U8,
	[IFLA_BR_MCAST_SNOOPING]             = MNL_TYPE_U8,
	[IFLA_BR_MCAST_QUERY_USE_IFADDR]     = MNL_TYPE_U8,
	[IFLA_BR_MCAST_QUERIER]              = MNL_TYPE_U8,
	[IFLA_BR_MCAST_HASH_ELASTICITY]      = MNL_TYPE_U32,
	[IFLA_BR_MCAST_HASH_MAX]             = MNL_TYPE_U32,
	[IFLA_BR_MCAST_LAST_MEMBER_CNT]      = MNL_TYPE_U32,
	[IFLA_BR_MCAST_STARTUP_QUERY_CNT]    = MNL_TYPE_U32,
	[IFLA_BR_MCAST_LAST_MEMBER_INTVL]    = MNL_TYPE_U64,
	[IFLA_BR_MCAST_MEMBERSHIP_INTVL]     = MNL_TYPE_U64,
	[IFLA_BR_MCAST_QUERIER_INTVL]        = MNL_TYPE_U64,
	[IFLA_BR_MCAST_QUERY_INTVL]          = MNL_TYPE_U64,
	[IFLA_BR_MCAST_QUERY_RESPONSE_INTVL] = MNL_TYPE_U64,
	[IFLA_BR_MCAST_STARTUP_QUERY_INTVL]  = MNL_TYPE_U64,
	[IFLA_BR_NF_CALL_IPTABLES]           = MNL_TYPE_U8,
	[IFLA_BR_NF_CALL_IP6TABLES]          = MNL_TYPE_U8,
	[IFLA_BR_NF_CALL_ARPTABLES]          = MNL_TYPE_U8,
	[IFLA_BR_VLAN_DEFAULT_PVID]          = MNL_TYPE_U16
};

/*
 * Callback for mnl_attr_parse_nested for parsing nested attribute
 * IFLA_INFO_DATA
 */
static int bridgeinfo_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attr to avoid issues with newer kernels */
	if (mnl_attr_type_valid(attr, IFLA_BR_MAX) < 0) {
		RTE_LOG(DEBUG, DATAPLANE,
			"unknown bridge info data attribute %d\n", type);
		return MNL_CB_OK;
	}

	if (mnl_attr_validate(attr, ifla_br_attr_type[type]) < 0) {
		RTE_LOG(NOTICE, DATAPLANE,
			"invalid bridge info data attribute %d\n", type);
		return MNL_CB_ERROR;
	}

	tb[type] = attr;

	return MNL_CB_OK;
}

static int
nl_bridge_parse_linkinfo(struct nlattr *kdata, struct nl_bridge_info *br_info)
{
	if (!kdata)
		return -1;

	struct nlattr *bridgeinfo[IFLA_BR_MAX+1] = { NULL };

	if (mnl_attr_parse_nested(kdata, bridgeinfo_attr,
				  bridgeinfo) != MNL_CB_OK) {
		RTE_LOG(NOTICE, DATAPLANE,
			"parse bridge info data failed\n");
		return -1;
	}
	if (bridgeinfo[IFLA_BR_AGEING_TIME]) {
		br_info->br_ageing_time =
			mnl_attr_get_u32(bridgeinfo[IFLA_BR_AGEING_TIME]);
		/* Convert centiseconds to seconds */
		br_info->br_ageing_time /= 100;
	}
	if (bridgeinfo[IFLA_BR_VLAN_FILTERING]) {
		uint8_t vlan_filter = mnl_attr_get_u8(
			bridgeinfo[IFLA_BR_VLAN_FILTERING]);
		br_info->br_vlan_filter = vlan_filter;
	}
	if (bridgeinfo[IFLA_BR_VLAN_DEFAULT_PVID]) {
		uint16_t pvid = mnl_attr_get_u16(
			bridgeinfo[IFLA_BR_VLAN_DEFAULT_PVID]);
		br_info->br_vlan_default_pvid = pvid;
	}

	return 0;
}

/* Process attributes for bridge */
void bridge_nl_modify(struct ifnet *ifp, struct nlattr *kdata)
{
	struct nl_bridge_info br_info = {0};

	if (nl_bridge_parse_linkinfo(kdata, &br_info) == 0)
		bridge_update(ifp->if_name, &br_info);
}

/*
 * Create a bridge interface and then process any associated netlink
 * attributes
 */
struct ifnet *bridge_nl_create(int ifindex, const char *ifname,
			       unsigned int mtu,
			       const struct rte_ether_addr *eth_addr,
			       struct nlattr *kdata)
{
	struct ifnet *ifp = bridge_create(ifindex, ifname,
					  mtu, eth_addr);

	if (ifp != NULL)
		bridge_nl_modify(ifp, kdata);

	return ifp;
}
