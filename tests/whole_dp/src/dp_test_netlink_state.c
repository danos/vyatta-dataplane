/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Routines to generate/send netlink state, from test controller to
 * dataplane over ZMQ.
 */
#include "dp_test_netlink_state_internal.h"

#include <stdio.h>
#include <linux/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/mpls.h>
#include <linux/mpls_iptunnel.h>
#include <linux/lwtunnel.h>
#include <libmnl/libmnl.h>
#include <czmq.h>
#include <syslog.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "main.h"
#include "if/bridge/bridge.h"
#include "if_var.h"
#include "if/vxlan.h"
#include "protobuf/RibUpdate.pb-c.h"
#include "vrf_internal.h"

#include "dp_test_controller.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_route_broker.h"
#include "dp_test_str.h"
#include "dp_test.h"
#include "dp_test_crypto_lib.h"
#include "dp_test_xfrm_server.h"

struct rtvia_v6 {
	__kernel_sa_family_t rtvia_family;
	__u8 rtvia_addr[sizeof(struct in6_addr)];
} via;

/* fwd decl */
static void
dp_test_netlink_route(const char *route_string, uint16_t nl_type,
		      bool replace, bool verify, bool incomplete,
		      const char *file, const char *func, int line);

static void
dp_test_netlink_netconf_ip(const char *ifname, int addr_family,
			   int msg_type, bool forwarding,
			   bool proxy_arp);

#define DP_TEST_MAX_UPSTREAM_VRF 10
struct dp_test_upstream_vrf_entry {
	uint32_t vrf_id;
	uint32_t tableid;
};

static struct dp_test_upstream_vrf_entry upstream_vrf_db[
	DP_TEST_MAX_UPSTREAM_VRF];

bool
dp_test_upstream_vrf_lookup_db(uint32_t vrf_id, char *vrf_name,
			       uint32_t *tableid)
{
	unsigned int i;

	for (i = 0; i < RTE_DIM(upstream_vrf_db); i++) {
		if (upstream_vrf_db[i].vrf_id == vrf_id) {
			if (tableid)
				*tableid = upstream_vrf_db[i].tableid;
			if (vrf_name)
				snprintf(vrf_name, IFNAMSIZ, "vrf%u", vrf_id);
			return true;
		}
	}

	return false;
}

bool
dp_test_upstream_vrf_add_db(uint32_t vrf_id, char *vrf_name, uint32_t *tableid)
{
	unsigned int i;
	uint32_t max_tableid = 255;

	for (i = 0; i < RTE_DIM(upstream_vrf_db); i++) {
		if (upstream_vrf_db[i].tableid > max_tableid)
			max_tableid = upstream_vrf_db[i].tableid;
		if (upstream_vrf_db[i].vrf_id == vrf_id) {
			*tableid = upstream_vrf_db[i].tableid;
			snprintf(vrf_name, IFNAMSIZ, "vrf%u", vrf_id);
			return true;
		}
	}

	for (i = 0; i < RTE_DIM(upstream_vrf_db); i++) {
		if (upstream_vrf_db[i].vrf_id == 0) {
			upstream_vrf_db[i].vrf_id = vrf_id;
			upstream_vrf_db[i].tableid = max_tableid + 1;
			*tableid = upstream_vrf_db[i].tableid;
			snprintf(vrf_name, IFNAMSIZ, "vrf%u", vrf_id);
			return true;
		}
	}

	return false;
}

static bool
dp_test_upstream_vrf_del_db(uint32_t vrf_id, char *vrf_name, uint32_t *tableid)
{
	unsigned int i;

	for (i = 0; i < RTE_DIM(upstream_vrf_db); i++) {
		if (upstream_vrf_db[i].vrf_id == vrf_id) {
			*tableid = upstream_vrf_db[i].tableid;
			snprintf(vrf_name, IFNAMSIZ, "vrf%u", vrf_id);
			upstream_vrf_db[i].tableid = 0;
			upstream_vrf_db[i].vrf_id = 0;
			return true;
		}
	}

	return false;
}

vrfid_t _dp_test_translate_vrf_id(vrfid_t vrf_id, const char *file,
				  int line)
{
	/*
	 * When using upstream model and not using a default VRF ID
	 * then we need to translate the ID (which corresponds to the
	 * name of the VRF) into its ifindex.
	 */
	if (vrf_id != VRF_UPLINK_ID && vrf_id != VRF_DEFAULT_ID) {
		char vrf_name[IFNAMSIZ];
		bool ret;

		ret = dp_test_upstream_vrf_lookup_db(
			vrf_id, vrf_name, NULL);
		_dp_test_fail_unless(ret, file, line,
				     "unable to find vrf interface for vrf %u\n",
				     vrf_id);
		return dp_test_intf_name2index(vrf_name);
	}

	return vrf_id;
}


/*
 * Set Layer 2 parameters on an interface.
 */
static void
dp_test_netlink_interface_l2_all(const char *ifname, int mtu,
				 uint32_t vrf_id, const char *alias,
				 bool admin_up,
				 uint16_t nlmsg_type, bool verify,
				 const char *file, const char *func,
				 int line)
{
	struct ifinfomsg *ifi;
	char topic[DP_TEST_TMP_BUF];
	char broadcast_addr[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	int if_state = 6;
	uint8_t link_mode = 0;
	uint32_t dev_group = 0;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real(ifname, real_ifname);
	if (nlmsg_type == RTM_NEWLINK)
		dp_test_intf_switch_port_activate(real_ifname);
	else
		dp_test_intf_switch_port_deactivate(real_ifname);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_ETHER;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = dp_test_intf_name2index(real_ifname);
	ifi->ifi_flags = (admin_up ? IFF_UP : 0) | IFF_RUNNING |
		IFF_LOWER_UP | IFF_BROADCAST | IFF_MULTICAST;
	ifi->ifi_change = 0xffffffff;

	/*
	 * Real controller sends the attributes without '----' at the front for
	 * a physical ethernet port.
	 *
	 * ---- IFLA_UNSPEC
	 * IFLA_ADDRESS,     mac address, already set at dataplane boot up
	 * IFLA_BROADCAST,
	 * IFLA_IFNAME,
	 * IFLA_MTU,
	 * ---- IFLA_LINK
	 * IFLA_QDISC  (only sent if set, so not sending)
	 * IFLA_STATS  (not sent yet)
	 * ---- IFLA_COST,
	 * ---- IFLA_PRIORITY,
	 * ---- IFLA_MASTER,
	 * ---- IFLA_WIRELESS,
	 * ---- IFLA_PROTINFO,
	 * IFLA_TXQLEN
	 * IFLA_MAP (not sent yet)
	 * ---- IFLA_WEIGHT
	 * IFLA_OPERSTATE,
	 * IFLA_LINKMODE,
	 * IFLA_LINKINFO,
	 * ----IFLA_NET_NS_PID,
	 * ----IFLA_IFALIAS,
	 * ----IFLA_NUM_VF,
	 * ----IFLA_VFINFO_LIST,
	 * IFLA_STATS64 (not sent yet)
	 * ----IFLA_VF_PORTS,
	 * ----IFLA_PORT_SELF,
	 * IFLA_AF_SPEC,  (not done yet)
	 * IFLA_GROUP,
	 * ----IFLA_NET_NS_FD,
	 * ----IFLA_EXT_MASK,
	 */
	mnl_attr_put(nlh, IFLA_ADDRESS, 6, dp_test_intf_name2mac(real_ifname));
	mnl_attr_put(nlh, IFLA_BROADCAST, 6, broadcast_addr);
	mnl_attr_put_strz(nlh, IFLA_IFNAME, real_ifname);
	mnl_attr_put_u32(nlh, IFLA_MTU, mtu);
	if (vrf_id != VRF_DEFAULT_ID && vrf_id != VRF_UPLINK_ID) {
		vrf_id = _dp_test_translate_vrf_id(vrf_id, file, line);
		mnl_attr_put_u32(nlh, IFLA_MASTER, vrf_id);
	}
	mnl_attr_put_u32(nlh, IFLA_TXQLEN, 100);
	mnl_attr_put_u8(nlh, IFLA_OPERSTATE, if_state);
	mnl_attr_put_u8(nlh, IFLA_LINKMODE, link_mode);
	mnl_attr_put_u32(nlh, IFLA_GROUP, dev_group);
	if (alias != NULL)
		mnl_attr_put_strz(nlh, IFLA_IFALIAS, alias);

	/* Set kind to tun/tap "tun", so dp picks up remote interfaces */
	struct nlattr *linkinfo = mnl_attr_nest_start(nlh, IFLA_LINKINFO);

	linkinfo->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_str(nlh, IFLA_INFO_KIND, "tun");
	mnl_attr_nest_end(nlh, linkinfo);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		struct rte_ether_addr *mac_addr;
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;
		char ebuf[32];

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s",
			 real_ifname);
		mac_addr = dp_test_intf_name2mac(real_ifname);
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"ether\": \"%s\","
					       "       \"mtu\": %d,"
					       "       \"vrf_id\": %d,"
					       "       \"flags\": %d,"
					       "    }"
					       "  ]"
					       "}",
					       real_ifname,
					       ether_ntoa_r(mac_addr,
							    ebuf),
					       mtu, vrf_id,
					       ifi->ifi_flags);
		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);

}

void
_dp_test_netlink_set_interface_l2(const char *ifname, bool verify,
				  const char *file, const char *func,
				  int line)
{
	dp_test_netlink_interface_l2_all(ifname, 1500, VRF_DEFAULT_ID, NULL,
					 true, RTM_NEWLINK,
					 verify, file, func, line);
}

void
_dp_test_netlink_del_interface_l2(const char *ifname, bool verify,
				  const char *file, const char *func,
				  int line)
{
	dp_test_netlink_netconf_ip(ifname, AF_INET, RTM_DELNETCONF,
				   false, false);
	dp_test_netlink_netconf_ip(ifname, AF_INET6, RTM_DELNETCONF,
				   false, false);
	dp_test_netlink_interface_l2_all(ifname, 1500, VRF_DEFAULT_ID, NULL,
					 true, RTM_DELLINK,
					 verify, file, func, line);
}

void _dp_test_netlink_set_interface_mtu(const char *name, int mtu, bool verify,
					const char *file, const char *func,
					int line)
{
	dp_test_netlink_interface_l2_all(name, mtu, VRF_DEFAULT_ID, NULL,
					 true, RTM_NEWLINK, verify,
					 file, func, line);
}

void _dp_test_netlink_set_interface_vrf(const char *name, uint32_t vrf_id,
					bool verify,
					const char *file, const char *func,
					int line)
{
	dp_test_netlink_interface_l2_all(name, 1500, vrf_id, NULL,
					 true, RTM_NEWLINK, verify,
					 file, func, line);
}

void _dp_test_netlink_set_interface_admin_status(
	const char *name, bool admin_up, bool verify,
	const char *file, const char *func, int line)
{
	dp_test_netlink_interface_l2_all(name, 1500, VRF_DEFAULT_ID, NULL,
					 admin_up, RTM_NEWLINK, verify,
					 file, func, line);
}

static uint8_t dp_test_gre_tos;
static uint8_t dp_test_gre_tos_old;

void dp_test_set_gre_tos(uint8_t val)
{
	dp_test_gre_tos_old = dp_test_gre_tos;
	dp_test_gre_tos = val;
}

void dp_test_reset_gre_tos(void)
{
	dp_test_gre_tos = dp_test_gre_tos_old;
}

static uint8_t dp_test_gre_ignore_df;
static uint8_t dp_test_gre_ignore_df_old;

void dp_test_set_gre_ignore_df(bool val)
{
	dp_test_gre_ignore_df_old = dp_test_gre_ignore_df;
	dp_test_gre_ignore_df = val;
}

void dp_test_reset_gre_ignore_df(void)
{
	dp_test_gre_ignore_df = dp_test_gre_ignore_df_old;
}

/*
 * Enable IP on an interface.
 */
static void
dp_test_netlink_netconf_ip(const char *ifname, int addr_family,
			   int msg_type, bool forwarding,
			   bool proxy_arp)
{
	struct netconfmsg *ncm;
	char topic[DP_TEST_TMP_BUF];
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real(ifname, real_ifname);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ncm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct netconfmsg));
	ncm->ncm_family = addr_family;

	/*
	 * Attributes are:
	 *
	 * NETCONFA_UNSPEC,
	 * NETCONFA_IFINDEX,
	 * NETCONFA_FORWARDING,
	 * NETCONFA_RP_FILTER,
	 * NETCONFA_MC_FORWARDING,
	 * NETCONFA_PROXY_NEIGH,
	 */
	mnl_attr_put_u32(nlh, NETCONFA_IFINDEX,
			 dp_test_intf_name2index(real_ifname));
	mnl_attr_put_u32(nlh, NETCONFA_FORWARDING, forwarding);
	mnl_attr_put_u32(nlh, NETCONFA_RP_FILTER, 0);
	mnl_attr_put_u32(nlh, NETCONFA_MC_FORWARDING, 0);
	mnl_attr_put_u32(nlh, NETCONFA_PROXY_NEIGH, proxy_arp);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		rte_panic("Could not generate topic\n");

	nl_propagate(topic, nlh);
}

static void
dp_test_netlink_tunnel(const char *tun_name,
		       const char *tun_local,
		       const char *tun_remote,
		       uint32_t key,
		       bool seq,
		       uint32_t vrf_id,
		       enum dp_test_tun_encap_type_e e_type,
		       uint16_t nlmsg_type,
		       bool verify,
		       const char *file, const char *func,
		       int line)
{
	struct ifinfomsg *ifi;
	char topic[DP_TEST_TMP_BUF];
	int tun_index = dp_test_intf_name2index(tun_name);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	uint32_t local4, remote4, result;
	struct in6_addr local6, remote6;
	struct in6_addr ip6_zero = IN6ADDR_ANY_INIT;
	bool v6 = false;

	result = inet_pton(AF_INET, tun_local, &local4);
	if (result != 1) {
		result = inet_pton(AF_INET6, tun_local, &local6);
		v6 = true;
	}
	dp_test_assert_internal(result == 1);
	result = inet_pton(AF_INET, tun_remote, &remote4);
	if (result != 1) {
		result = inet_pton(AF_INET6, tun_remote, &remote6);
		v6 = true;
	}
	dp_test_assert_internal(result == 1);


	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	if (!v6)
		ifi->ifi_type = ARPHRD_IPGRE;
	else
		ifi->ifi_type = ARPHRD_IP6GRE;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = tun_index;
	ifi->ifi_flags = IFF_UP;

	struct nlattr *gre_link, *gre_data;

	if (v6 && memcmp(&remote6, &ip6_zero, sizeof(remote6)) != 0)
		ifi->ifi_flags |= IFF_POINTOPOINT|IFF_NOARP;
	else if (!v6 && remote4 != INADDR_ANY)
		ifi->ifi_flags |= IFF_POINTOPOINT|IFF_NOARP;

	/* Nested GRE */
	gre_link = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	gre_link->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND,
			  (e_type == DP_TEST_TUN_ENCAP_TYPE_BRIDGE) ?
			  "gretap" : "gre");

	/* Nested GRE data */
	uint16_t flags = 0;

	gre_data = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
	gre_data->nla_type &= ~NLA_F_NESTED;

	if (key) {
		/* Key + flags are signalled in network byte order */
		mnl_attr_put_u32(nlh, IFLA_GRE_OKEY, htonl(key));
		flags |= GRE_KEY;
	}
	if (seq) {
		/* Sequencing enabled */
		flags |= GRE_SEQ;
	}
	if (v6) {
		mnl_attr_put(nlh, IFLA_GRE_LOCAL, sizeof(local6), &local6);
		mnl_attr_put(nlh, IFLA_GRE_REMOTE, sizeof(remote6), &remote6);
		mnl_attr_put_u32(nlh, IFLA_GRE_FLOWINFO, 0);
	} else {
		mnl_attr_put_u32(nlh, IFLA_GRE_LOCAL, local4);
		mnl_attr_put_u32(nlh, IFLA_GRE_REMOTE, remote4);
		mnl_attr_put_u8(nlh, IFLA_GRE_TOS, dp_test_gre_tos);
		mnl_attr_put_u8(nlh, IFLA_GRE_IGNORE_DF, dp_test_gre_ignore_df);
		mnl_attr_put_u8(nlh, IFLA_GRE_PMTUDISC, 1);
	}
	mnl_attr_put_u8(nlh, IFLA_GRE_TTL, 0); /* inherit */
	mnl_attr_put_u16(nlh, IFLA_GRE_OFLAGS, flags);

	/* IFLA_GRE_LINK, _IKEY and _IFLAGS are ignored by the dataplane */
	mnl_attr_put_u32(nlh, IFLA_GRE_LINK, tun_index);
	mnl_attr_put_u32(nlh, IFLA_GRE_IKEY, 0);
	mnl_attr_put_u32(nlh, IFLA_GRE_IFLAGS, 0);

	mnl_attr_nest_end(nlh, gre_data);
	mnl_attr_nest_end(nlh, gre_link);

	/* And remaining settings */
	if (vrf_id != VRF_DEFAULT_ID && vrf_id != VRF_UPLINK_ID) {
		vrf_id = _dp_test_translate_vrf_id(vrf_id, file, line);
		mnl_attr_put_u32(nlh, IFLA_MASTER, vrf_id);
	}

	switch (e_type) {
	case DP_TEST_TUN_ENCAP_TYPE_BRIDGE:
		mnl_attr_put_u32(nlh, IFLA_MTU, 1462);
		break;
	case DP_TEST_TUN_ENCAP_TYPE_ERSPAN:
		mnl_attr_put_u32(nlh, IFLA_MTU, 1472);
		break;
	case DP_TEST_TUN_ENCAP_TYPE_IP:
		mnl_attr_put_u32(nlh, IFLA_MTU, 1476);
		break;
	}
	mnl_attr_put(nlh, IFLA_ADDRESS, sizeof(struct rte_ether_addr),
		     dp_test_intf_name2mac(tun_name));
	mnl_attr_put_strz(nlh, IFLA_IFNAME, tun_name);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", tun_name);
		if (!v6)
			expected = dp_test_json_create("{ \"interfaces\":"
						       "  ["
						       "    {"
						       "      \"name\": \"%s\","
						       "      \"gre\":"
						       "        {"
						       "          \"key\": %u,"
						       "          \"source\": \"%s\","
						       "          \"dest\": \"%s\","
						       "          \"tos\": %d,"
						       "          \"ttl\": 0,"
						       "          \"flags\": %u,"
						       "          \"pmtu-disc\": true,"
						       "          \"ignore-df\": %s,"
						       "          \"transport-vrf\": %d,"
						       "        }"
						       "    }"
						       "  ]"
						       "}",
						       tun_name,
						       htonl(key),
						       tun_local,
						       tun_remote,
						       dp_test_gre_tos,
						       flags,
						       dp_test_gre_ignore_df ?
						       "true"
						       : "false",
						       VRF_DEFAULT_ID);
		else
			expected = dp_test_json_create("{ \"interfaces\":"
						       "  ["
						       "    {"
						       "      \"name\": \"%s\","
						       "      \"gre\":"
						       "        {"
						       "          \"key\": %u,"
						       "          \"source\": \"%s\","
						       "          \"dest\": \"%s\","
						       "          \"tos\": %d,"
						       "          \"hlim\": 0,"
						       "          \"flags\": %u,"
						       "          \"transport-vrf\": %d,"
						       "        }"
						       "    }"
						       "  ]"
						       "}",
						       tun_name,
						       htonl(key),
						       tun_local,
						       tun_remote,
						       dp_test_gre_tos,
						       flags,
						       VRF_DEFAULT_ID);

		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);

}

void
_dp_test_netlink_create_tunnel(const char *tun_name,
			       const char *tun_local,
			       const char *tun_remote,
			       uint32_t key,
			       bool seq,
			       uint32_t vrf_id,
			       enum dp_test_tun_encap_type_e e_type,
			       bool verify,
			       const char *file, const char *func,
			       int line)
{
	dp_test_netlink_tunnel(tun_name, tun_local,
			       tun_remote, key, seq, vrf_id, e_type,
			       RTM_NEWLINK, verify, file, func, line);
	dp_test_netlink_netconf_ip(tun_name, AF_INET, RTM_NEWNETCONF,
				   true, false);
}

void
_dp_test_netlink_delete_tunnel(const char *tun_name,
			       const char *tun_local,
			       const char *tun_remote,
			       uint32_t key,
			       bool seq,
			       uint32_t vrf_id,
			       enum dp_test_tun_encap_type_e e_type,
			       bool verify,
			       const char *file, const char *func,
			       int line)
{
	dp_test_netlink_tunnel(tun_name, tun_local,
			       tun_remote, key, seq, vrf_id, e_type,
			       RTM_DELLINK, verify, file, func, line);
}

static void
dp_test_netlink_ppp(const char *intf_name,
		    uint32_t vrf_id,
		    uint16_t nlmsg_type,
		    int mtu,
		    bool verify,
		    const char *file, const char *func,
		    int line)
{
	struct ifinfomsg *ifi;
	char topic[DP_TEST_TMP_BUF];
	int if_index = dp_test_intf_name2index(intf_name);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_PPP;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = if_index;
	ifi->ifi_flags = IFF_UP|IFF_POINTOPOINT|IFF_NOARP;

	if (vrf_id != VRF_DEFAULT_ID && vrf_id != VRF_UPLINK_ID) {
		vrf_id = _dp_test_translate_vrf_id(vrf_id, file, line);
		mnl_attr_put_u32(nlh, IFLA_MASTER, vrf_id);
	}

	mnl_attr_put_u32(nlh, IFLA_MTU, mtu);
	mnl_attr_put_strz(nlh, IFLA_IFNAME, intf_name);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", intf_name);
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "      \"name\": \"%s\","
					       "    }"
					       "  ]"
					       "}",
					       intf_name);

		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);

}

void
_dp_test_netlink_create_ppp(const char *intf_name,
			    uint32_t vrf_id,
			    bool verify,
			    const char *file, const char *func,
			    int line)
{
	dp_test_netlink_ppp(intf_name, vrf_id, RTM_NEWLINK,
			    1500, verify, file, func, line);
	dp_test_netlink_netconf_ip(intf_name, AF_INET, RTM_NEWNETCONF,
				   true, false);
}

void
_dp_test_netlink_delete_ppp(const char *intf_name,
			    uint32_t vrf_id,
			    bool verify,
			    const char *file, const char *func,
			    int line)
{
	dp_test_netlink_ppp(intf_name, vrf_id, RTM_DELLINK,
			    1500, verify, file, func, line);
}

void
_dp_test_intf_ppp_set_mtu(const char *intf_name, uint32_t vrf_id,
			  int mtu, bool verify, const char *file,
			  const char *func, int line)
{
	dp_test_netlink_ppp(intf_name, vrf_id, RTM_NEWLINK,
			    mtu, verify, file, func, line);
}


void
_dp_test_verify_neigh(const char *ifname, const char *ipaddr,
		      const char *mac_str, bool negate_match, const char *file,
		      const char *func, int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	json_object *expected;
	bool ipv4_neigh = false;
	struct dp_test_addr addr;
	uint32_t v4_addr;
	struct rte_ether_addr mac;
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real(ifname, real_ifname);
	_dp_test_fail_unless(dp_test_addr_str_to_addr(ipaddr, &addr),
			     file, line,
			     "unable to parse addr %s", ipaddr);

	if (ether_aton_r(mac_str, &mac) == NULL) {
		/* See if it is an IP address from NHRP */
		ipv4_neigh = inet_pton(AF_INET, mac_str, &v4_addr);
		dp_test_assert_internal(ipv4_neigh || negate_match);
	}

	if (ipv4_neigh) {
		/* ipv4 nhrp nbma address */
		snprintf(cmd, TEST_MAX_CMD_LEN, "gre tunnel %s",
			 ifname);
		expected = dp_test_json_create(
			"{ \"neighbors\":"
			"  ["
			"    {"
			"       \"ifname\": \"%s\","
			"       \"ip\": \"%s\","
			"       \"nbma\": \"%s\","
			"    }"
			"  ]"
			"}",
			ifname,
			ipaddr,
			mac_str);

	} else {
		/* check arp entry is present and correct */
		char new_mac_str[TEST_MAX_CMD_LEN];

		if (strlen(mac_str) == 0)
			new_mac_str[0] = '\0';
		else
			snprintf(new_mac_str, TEST_MAX_CMD_LEN,
				"       \"mac\": \"%s\",", mac_str);

		switch (addr.family) {
		case AF_INET:
			snprintf(cmd, TEST_MAX_CMD_LEN, "arp");
			expected = dp_test_json_create(
				"{ \"arp\":"
				"  ["
				"    {"
				"       \"ip\": \"%s\","
				"       \"ifname\": \"%s\","
				"%s"
				"    }"
				"  ]"
				"}",
				ipaddr,
				real_ifname,
				new_mac_str);
			break;
		case AF_INET6:
			snprintf(cmd, TEST_MAX_CMD_LEN, "nd6");
			expected = dp_test_json_create(
				"{ \"nd6\":"
				"  ["
				"    {"
				"       \"ip\": \"%s\","
				"       \"ifname\": \"%s\","
				"%s"
				"    }"
				"  ]"
				"}",
				ipaddr,
				real_ifname,
				new_mac_str);
			break;
		default:
			assert(0);
		}
	}

	_dp_test_check_json_state(cmd, expected, NULL,
				  DP_TEST_JSON_CHECK_SUBSET,
				  negate_match, false, file, func, line);
	json_object_put(expected);
}

/*
 * For netlink format see /usr/include/linux/neighbour.h
 */
static void
dp_test_netlink_neighbour(const char *ifname, const char *nh_addr_str,
			  const char *mac_str, uint16_t nlmsg_type,
			  bool verify,
			  const char *file, const char *func,
			  int line)
{
	struct dp_test_addr addr;
	struct ndmsg *ndm;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	char topic[DP_TEST_TMP_BUF];
	struct rte_ether_addr mac;
	char real_ifname[IFNAMSIZ];
	bool ipv4_neigh = false;
	uint32_t v4_addr;

	dp_test_intf_real(ifname, real_ifname);

	_dp_test_fail_unless(dp_test_addr_str_to_addr(nh_addr_str, &addr),
			    file, line,
			    "unable to parse addr %s", nh_addr_str);
	if (ether_aton_r(mac_str, &mac) == NULL) {
		/* See if it is an IP address from NHRP */
		ipv4_neigh = inet_pton(AF_INET, mac_str, &v4_addr);
		dp_test_assert_internal(ipv4_neigh);
	}

	/* Build nl msg */
	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;

	ndm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ndmsg));
	ndm->ndm_family = addr.family;
	ndm->ndm_ifindex = dp_test_intf_name2index(real_ifname);
	if (nlmsg_type == RTM_NEWNEIGH)
		ndm->ndm_state = ipv4_neigh ? NUD_REACHABLE : NUD_PERMANENT;
	else
		ndm->ndm_state = NUD_FAILED;
	ndm->ndm_flags = NLM_F_REQUEST;
	ndm->ndm_type = ARPHRD_ETHER;

	mnl_attr_put(nlh, NDA_DST, dp_test_addr_size(&addr), &addr.addr);
	if (ipv4_neigh)
		mnl_attr_put(nlh, NDA_LLADDR, 4, &v4_addr); /* Ipv4 address */
	else
		mnl_attr_put(nlh, NDA_LLADDR, 6, &mac); /* mac address */

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		assert(0);

	if (verify) {

		if (nlmsg_type == RTM_NEWNEIGH) {
			/* Check neighbor is not there already */
			_dp_test_verify_neigh(ifname, nh_addr_str, mac_str,
					      true, file, func, line);
			nl_propagate(topic, nlh);
		}
		/* _NEW:check neigh added OR _DEL check neigh already there */
		_dp_test_verify_neigh(ifname, nh_addr_str, mac_str,
				      false, file, func, line);
		if (nlmsg_type == RTM_DELNEIGH) {
			nl_propagate(topic, nlh);
			_dp_test_verify_neigh(ifname, nh_addr_str, mac_str,
					      true, file, func, line);
		}
	} else
		nl_propagate(topic, nlh);
}

void
_dp_test_netlink_add_neigh(const char *ifname, const char *nh_addr_str,
			   const char *mac_str, bool verify,
			   const char *file, const char *func,
			   int line)
{
	dp_test_netlink_neighbour(ifname, nh_addr_str, mac_str,
				  RTM_NEWNEIGH, verify,
				  file, func, line);
}

void
_dp_test_netlink_del_neigh(const char *ifname, const char *nh_addr_str,
			   const char *mac_str, bool verify,
			   const char *file, const char *func,
			   int line)
{
	dp_test_netlink_neighbour(ifname, nh_addr_str, mac_str,
				  RTM_DELNEIGH, verify,
				  file, func, line);
}

static void
dp_test_verify_interface_ip_address(const char *ifname, const char *prefix_str,
				    bool present, const char *file,
				    const char *func, int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	json_object *expected;
	char real_ifname[IFNAMSIZ];
	struct dp_test_addr addr;
	char ip_addr[TEST_MAX_REPLY_LEN];
	char *end = strchr(prefix_str, '/');

	dp_test_intf_real(ifname, real_ifname);

	strncpy(ip_addr, prefix_str, end - prefix_str);
	ip_addr[end - prefix_str] = '\0';

	_dp_test_fail_unless(dp_test_addr_str_to_addr(ip_addr, &addr),
			     file, line,
			     "unable to parse addr %s", ip_addr);

	snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", real_ifname);
	switch (addr.family) {
	case AF_INET:
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"addresses\":"
					       "         ["
					       "           {"
					       "             \"inet\": \"%s\","
					       "           }"
					       "         ]"
					       "    }"
					       "  ]"
					       "}",
					       real_ifname,
					       prefix_str);
		break;
	case AF_INET6:
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"addresses\":"
					       "         ["
					       "           {"
					       "             \"inet6\": \"%s\","
					       "           }"
					       "         ]"
					       "    }"
					       "  ]"
					       "}",
					       real_ifname,
					       prefix_str);
		break;
	default:
		assert(0);
	}

	if (present)
		_dp_test_check_json_state(cmd, expected,
					  NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
	else
		_dp_test_check_json_state(cmd, expected,
					  NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  true, false,
					  file, func, line);

	json_object_put(expected);
}

static void
dp_test_netlink_ip_address(const char *ifname, const char *prefix_str,
			   uint16_t nlmsg_type, bool verify,
			   const char *file, const char *func,
			   int line)
{
	struct ifaddrmsg *ifm;
	struct dp_test_prefix prefix;
	char topic[DP_TEST_TMP_BUF];
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	char real_ifname[IFNAMSIZ];

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);

	_dp_test_fail_unless(dp_test_prefix_str_to_prefix(prefix_str,
							  &prefix),
			     file, line,
			     "unable to parse prefix %s", prefix_str);

	dp_test_intf_real(ifname, real_ifname);
	switch (nlmsg_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
		nlh->nlmsg_type = nlmsg_type;
		break;
	default:
		dp_test_assert_internal(false); /* Unsupported type */
		break;
	}
	nlh->nlmsg_flags = NLM_F_ACK;

	ifm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
	ifm->ifa_family = prefix.addr.family;
	ifm->ifa_prefixlen = prefix.len;
	ifm->ifa_flags = IFA_F_PERMANENT;
	ifm->ifa_scope = 0;
	ifm->ifa_index = dp_test_intf_name2index(real_ifname);

	/*
	 * Attributes are:
	 *
	 * IFA_UNSPEC,
	 *  ---- IFA_ADDRESS:    Subnet (or Peer) Address
	 * IFA_LOCAL:            Host Address
	 * IFA_LABEL,
	 * IFA_BROADCAST:        Subnet Broadcast
	 *  ---- IFA_ANYCAST,
	 *  ---- IFA_CACHEINFO,
	 *  ---- IFA_MULTICAST,
	 *  ---- IFA_FLAGS,
	 */
	mnl_attr_put(nlh, IFA_LOCAL, dp_test_addr_size(&prefix.addr),
		     &prefix.addr.addr);
	mnl_attr_put_strz(nlh, IFA_LABEL, real_ifname);
	if (prefix.addr.family == AF_INET)
		mnl_attr_put_u32(nlh, IFA_BROADCAST,
				 dp_test_ipv4_addr_to_bcast(
					 prefix.addr.addr.ipv4,
					 prefix.len));

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		/*
		 * And now test addr is there. May move to a more
		 * advanced test later.
		 */
		if (nlmsg_type == RTM_NEWADDR) {
			dp_test_verify_interface_ip_address(ifname, prefix_str,
							    false, file, func,
							    line);
			nl_propagate(topic, nlh);
		}
		dp_test_verify_interface_ip_address(ifname, prefix_str, true,
						    file, func, line);
		if (nlmsg_type == RTM_DELADDR) {
			nl_propagate(topic, nlh);
			dp_test_verify_interface_ip_address(ifname, prefix_str,
							    false, file, func,
							    line);
		}
	} else
		nl_propagate(topic, nlh);

	if (nlmsg_type == RTM_NEWADDR)
		dp_test_intf_add_addr(ifname, &prefix.addr);
	else if (nlmsg_type == RTM_DELADDR)
		dp_test_intf_del_addr(ifname, &prefix.addr);
}

/*
 * Add an IP address to an interface and other IP settings.
 */
void
_dp_test_netlink_add_ip_address(const char *ifname, const char *prefix,
				uint32_t vrf_id, bool verify,
				const char *file, const char *func,
				int line)
{
	struct dp_test_prefix pfx;
	char route_str[100];
	char addr_str[100];

	_dp_test_fail_unless(dp_test_prefix_str_to_prefix(prefix,
							  &pfx),
			     file, line,
			     "unable to parse prefix %s", prefix);

	dp_test_addr_to_str(&pfx.addr, addr_str, sizeof(addr_str));
	if (pfx.addr.family == AF_INET)
		snprintf(route_str, sizeof(route_str),
			 "vrf:%d tbl:%d %s/32 scope:%d nh int:%s",
			 vrf_id, RT_TABLE_LOCAL, addr_str, RT_SCOPE_HOST,
			 ifname);
	else if (pfx.addr.family == AF_INET6)
		/* v6 local ips are signaled on the lo device
		 * [ROUTE]local 2052:1::1 dev lo table local proto none ...
		 * [ROUTE]2052:1::/64 dev up1s3 proto kernel ...
		 */
		snprintf(route_str, sizeof(route_str),
			 "vrf:%d tbl:%d %s/128 scope:%d nh int:lo",
			 vrf_id, RT_TABLE_LOCAL, addr_str, RT_SCOPE_HOST);
	else
		_dp_test_fail_unless(false,
				     file, line,
				     "unknown addr family %d for prefix %s",
				     pfx.addr.family, prefix);
	/*
	 * Verify address is not present
	 */
	if (verify) {
		_dp_test_wait_for_local_addr(prefix, vrf_id, true,
					     file, func, line);
		dp_test_verify_interface_ip_address(ifname, prefix,
						    false, file, func,
						    line);
	}
	/*
	 * send local table route add, netconf to enable ip
	 * and newaddr for the interface address.
	 */
	dp_test_netlink_netconf_ip(ifname, pfx.addr.family, RTM_NEWNETCONF,
				   true, false);
	dp_test_netlink_ip_address(ifname, prefix, RTM_NEWADDR, false,
				   file, func, line);
	dp_test_netlink_route(route_str, RTM_NEWROUTE,
			      false, false, false, file, func, line);
	/*
	 * Verify address is now present
	 */
	if (verify) {
		_dp_test_wait_for_local_addr(prefix, vrf_id, false,
					     file, func, line);
		dp_test_verify_interface_ip_address(ifname, prefix,
						    true, file, func,
						    line);
	}
}

void
_dp_test_netlink_del_ip_address(const char *ifname, const char *prefix,
				uint32_t vrf_id, bool verify,
				const char *file, const char *func,
				int line)
{
	struct dp_test_prefix pfx;
	char route_str[100];
	char addr_str[100];

	_dp_test_fail_unless(dp_test_prefix_str_to_prefix(prefix,
							  &pfx),
			     file, line,
			     "unable to parse prefix %s", prefix);

	dp_test_addr_to_str(&pfx.addr, addr_str, sizeof(addr_str));
	if (pfx.addr.family == AF_INET)
		snprintf(route_str, sizeof(route_str),
			 "vrf:%d tbl:%d %s/32 scope:%d nh int:%s",
			 vrf_id, RT_TABLE_LOCAL, addr_str, RT_SCOPE_HOST,
			 ifname);
	else if (pfx.addr.family == AF_INET6)
		/* v6 local ips are signaled on the lo device */
		snprintf(route_str, sizeof(route_str),
			 "vrf:%d tbl:%d %s/128 scope:%d nh int:lo",
			 vrf_id, RT_TABLE_LOCAL, addr_str, RT_SCOPE_HOST);
	else
		_dp_test_fail_unless(false,
				     file, line,
				     "unknown addr family %d for prefix %s",
				     pfx.addr.family, prefix);

	/*
	 * Verify address is present
	 */
	if (verify) {
		_dp_test_wait_for_local_addr(prefix, vrf_id, false,
					     file, func, line);
		dp_test_verify_interface_ip_address(ifname, prefix,
						    true, file, func,
						    line);
	}

	/*
	 * remove local table routes for the address - don't verify as
	 * currently this message has no effect.
	 */
	dp_test_netlink_route(route_str, RTM_DELROUTE,
			      false, false, false, file, func, line);

	dp_test_netlink_ip_address(ifname, prefix, RTM_DELADDR, false,
				   file, func, line);
	dp_test_netlink_netconf_ip(ifname, pfx.addr.family, RTM_NEWNETCONF,
				   false, false);

	/*
	 * Verify address is not present
	 */
	if (verify) {
		_dp_test_wait_for_local_addr(prefix, vrf_id, true,
					     file, func, line);
		dp_test_verify_interface_ip_address(ifname, prefix,
						    false, file, func,
						    line);
	}
}

/*
 * Set proxy arp on an interface.
 *
 * (Note due to limitations of current infra this function should only
 * be used on interfaces that already have IP addresses and forwarding
 * enabled on them and also that it does not verify so to avoid races
 * place a verifying call - e.g. a route add after it).
 */
void
_dp_test_netlink_set_proxy_arp(const char *ifname, bool enable,
			       const char *file, const char *func,
			       int line)
{
	dp_test_netlink_netconf_ip(ifname, AF_INET, RTM_NEWNETCONF,
				   false, enable);
}

/*
 * Enable/disable MPLS forwarding on an interface.
 */
void
_dp_test_netlink_set_mpls_forwarding(const char *ifname, bool enable,
				     const char *file,
				     const char *func, int line)
{
	struct netconfmsg *ncm;
	char topic[DP_TEST_TMP_BUF];
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real(ifname, real_ifname);

	nlh->nlmsg_type = RTM_NEWNETCONF;
	nlh->nlmsg_flags = NLM_F_ACK;

	ncm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct netconfmsg));
	ncm->ncm_family = AF_MPLS;

	mnl_attr_put_u32(nlh, NETCONFA_IFINDEX,
			 dp_test_intf_name2index(real_ifname));
	mnl_attr_put_u32(nlh, NETCONFA_INPUT, enable);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		rte_panic("Could not generate topic\n");

	nl_propagate(topic, nlh);

	char cmd[TEST_MAX_CMD_LEN];
	json_object *expected;

	snprintf(cmd, TEST_MAX_CMD_LEN, "mpls show ifconfig %s", real_ifname);
	expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"mpls\": \"%s\","
					       "    }"
					       "  ]"
					       "}",
				       real_ifname,
				       enable ? "on" : "off");
	_dp_test_check_json_state(cmd, expected, NULL,
				  DP_TEST_JSON_CHECK_SUBSET,
				  false, false,
				  file, func, line);
	json_object_put(expected);
}

static void
dp_test_netlink_route_nl(struct dp_test_route *route, uint16_t nl_type,
			 bool replace)
{
	struct rtmsg *rtm;
	char topic[DP_TEST_TMP_BUF];
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	unsigned int i;
	struct dp_test_nh *nh;
	unsigned int route_cnt;
	unsigned int route_idx;
	struct nlattr *pl_start;

	if (route->prefix.addr.family == AF_INET6)
		route_cnt = route->nh_cnt ? route->nh_cnt : 1;
	else
		route_cnt = 1;

	for (route_idx = 0; route_idx < route_cnt; route_idx++) {
		memset(buf, 0, sizeof(buf));
		nlh = mnl_nlmsg_put_header(buf);
		switch (nl_type) {
		case RTM_NEWROUTE:
		case RTM_DELROUTE:
			nlh->nlmsg_type = nl_type;
			break;
		default:
			dp_test_assert_internal(false);
			break;
		}
		nlh->nlmsg_flags = NLM_F_ACK;
		if (route_idx == 0)
			nlh->nlmsg_flags |= NLM_F_REPLACE;

		rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
		rtm->rtm_family = route->prefix.addr.family;
		rtm->rtm_dst_len = route->prefix.len;
		rtm->rtm_src_len = 0;
		rtm->rtm_tos = 0;
		if (route->tableid > UINT8_MAX)
			rtm->rtm_table = RT_TABLE_COMPAT;
		else
			rtm->rtm_table = route->tableid;
		rtm->rtm_protocol = RTPROT_UNSPEC;
		rtm->rtm_scope = route->scope;
		if (route->tableid == RT_TABLE_LOCAL)
			rtm->rtm_type = RTN_LOCAL;
		else
			rtm->rtm_type = route->type;
		rtm->rtm_flags = 0;

		/*
		 * RTA_UNSPEC,
		 * RTA_DST,
		 *  ---- RTA_SRC,
		 *  ---- RTA_IIF,
		 * RTA_OIF,      (depending on route type)
		 * RTA_GATEWAY,  (depending on route type)
		 *  ---- RTA_PRIORITY,
		 *  ---- RTA_PREFSRC,
		 *  ---- RTA_METRICS,
		 *  ---- RTA_MULTIPATH,
		 *  ---- RTA_PROTOINFO, // no longer used
		 *  ---- RTA_FLOW,
		 *  ---- RTA_CACHEINFO,
		 *  ---- RTA_SESSION, // no longer used
		 *  ---- RTA_MP_ALGO, // no longer used
		 * RTA_ENCAP_TYPE, (if outlabels present)
		 * RTA_ENCAP,    (if outlabels present)
		 * RTA_TABLE,
		 *  ---- RTA_MARK,
		 *  ---- RTA_MFC_STATS,
		 */
		mnl_attr_put_u32(nlh, RTA_TABLE, route->tableid);
		mnl_attr_put(nlh, RTA_DST,
			     dp_test_addr_size(&route->prefix.addr),
			     &route->prefix.addr.addr);

		if (route->nh_cnt > 1) {
			struct nlattr *mpath_start;
			struct rtnexthop *rtnh;

			if (route->prefix.addr.family == AF_MPLS) {
				pl_start = mnl_attr_nest_start(
					nlh, RTA_MPLS_PAYLOAD);
				mnl_attr_put_u32(nlh, RTMPA_TYPE,
						 route->mpls_payload_type);
				mnl_attr_nest_end(nlh, pl_start);
			}

			mpath_start = mnl_attr_nest_start(nlh, RTA_MULTIPATH);
			for (i = 0; i < route->nh_cnt; i++) {
				nh = &route->nh[i];
				/*
				 * insert an rtnh struct - this is not a
				 * netlink attribute so we can't just use the
				 * attr_put func.
				 */
				rtnh = (struct rtnexthop *)
					mnl_nlmsg_get_payload_tail(nlh);
				nlh->nlmsg_len += MNL_ALIGN(sizeof(*rtnh));
				memset(rtnh, 0, sizeof(*rtnh));
				dp_test_assert_internal(nh->nh_int);
				rtnh->rtnh_ifindex =
					dp_test_intf_name2index(nh->nh_int);
				/* if we have a nh insert a gateway attr */
				if (nh->nh_addr.family != AF_UNSPEC) {
					size_t addr_size = dp_test_addr_size(
						&nh->nh_addr);

					if (route->prefix.addr.family ==
					    nh->nh_addr.family) {
						mnl_attr_put(nlh, RTA_GATEWAY,
							     addr_size,
							     &nh->nh_addr.addr);
					} else if (route->prefix.addr.family ==
						   AF_INET6 &&
						   nh->nh_addr.family ==
						   AF_INET) {
						struct in6_addr v6addr;
#define IN6_SET_ADDR_V4MAPPED(a6, a4) {			\
		(a6)->s6_addr32[0] = 0;			\
		(a6)->s6_addr32[1] = 0;			\
		(a6)->s6_addr32[2] = htonl(0xffff);	\
		(a6)->s6_addr32[3] = (a4);		\
	}
						IN6_SET_ADDR_V4MAPPED(
							&v6addr,
							nh->nh_addr.addr.ipv4);
						mnl_attr_put(nlh,
							     RTA_GATEWAY,
							     sizeof(v6addr),
							     &v6addr);
					} else {
						via.rtvia_family =
							nh->nh_addr.family;
						memcpy(via.rtvia_addr,
						       &nh->nh_addr.addr,
						       addr_size);
						mnl_attr_put(
							nlh, RTA_VIA,
							offsetof(
								struct rtvia_v6,
								rtvia_addr[addr_size]),
							&via);
					}
				}

				if (nh->num_labels == 1 &&
				    nh->labels[0] == MPLS_LABEL_IMPLNULL) {
					/* Nothing to do */
				} else if (nh->num_labels > 0) {
					label_t labels[DP_TEST_MAX_LBLS];
					struct nlattr *encap_start;
					uint8_t i;
					/*
					 * We send labels in network
					 * format - values occupying
					 * top 20 bits, BOS bit set on
					 * the last one, network byte
					 * order.
					 */
					for (i = 0; i < nh->num_labels; i++) {
						labels[i] =
							htonl(nh->labels[i] <<
							      MPLS_LS_LABEL_SHIFT);
					}
					labels[nh->num_labels - 1] |=
						htonl(1 << MPLS_LS_S_SHIFT);

					if (route->prefix.addr.family ==
					    AF_MPLS) {
						mnl_attr_put(
							nlh, RTA_NEWDST,
							nh->num_labels *
							sizeof(labels[0]),
							labels);
					} else {
						mnl_attr_put_u16(
							nlh, RTA_ENCAP_TYPE,
							LWTUNNEL_ENCAP_MPLS);

						encap_start =
							mnl_attr_nest_start(
								nlh, RTA_ENCAP);
						mnl_attr_put(
							nlh, MPLS_IPTUNNEL_DST,
							nh->num_labels *
							sizeof(labels[0]),
							labels);
						mnl_attr_nest_end(nlh,
								  encap_start);
					}
				} else if (route->prefix.addr.family ==
					   AF_MPLS) {
					pl_start = mnl_attr_nest_start(
						nlh, RTA_MPLS_PAYLOAD);
					mnl_attr_put_u32(nlh, RTMPA_NH_FLAGS,
							 RTMPNF_BOS_ONLY);
					mnl_attr_nest_end(nlh, pl_start);
				}

				/*
				 * length of rtnh includes any gateway
				 * attribute
				 */
				rtnh->rtnh_len =
					((char *)mnl_nlmsg_get_payload_tail(
						nlh) - (char *)rtnh);
			}
			mnl_attr_nest_end(nlh, mpath_start);
		} else if (route->nh_cnt == 1) {
			nh = &route->nh[route_idx];
			if (nh->nh_int)
				mnl_attr_put_u32(nlh, RTA_OIF,
						 dp_test_intf_name2index(
							 nh->nh_int));
			if (nh->nh_addr.family != AF_UNSPEC) {
				size_t addr_size = dp_test_addr_size(
					&nh->nh_addr);

				if (route->prefix.addr.family ==
				    nh->nh_addr.family) {
					mnl_attr_put(nlh, RTA_GATEWAY,
						     addr_size,
						     &nh->nh_addr.addr);
				} else if (route->prefix.addr.family ==
					   AF_INET6 &&
					   nh->nh_addr.family ==
					   AF_INET) {
					struct in6_addr v6addr;
					IN6_SET_ADDR_V4MAPPED(
						&v6addr,
						nh->nh_addr.addr.ipv4);
					mnl_attr_put(nlh,
						     RTA_GATEWAY,
						     sizeof(v6addr),
						     &v6addr);
				} else {
					struct rtvia_v6 {
						__kernel_sa_family_t rtvia_family;
						__u8 rtvia_addr[16];
					} via;

					via.rtvia_family = nh->nh_addr.family;
					memcpy(via.rtvia_addr,
					       &nh->nh_addr.addr,
					       addr_size);
					mnl_attr_put(
						nlh, RTA_VIA,
						offsetof(struct rtvia_v6,
							 rtvia_addr[addr_size]),
						&via);
				}
			}
			if (nh->num_labels == 1 &&
			    nh->labels[0] == MPLS_LABEL_IMPLNULL) {
				/* Nothing to do */
			} else if (nh->num_labels > 0) {
				label_t labels[DP_TEST_MAX_LBLS];
				struct nlattr *encap_start;
				uint8_t i;
				/*
				 * We send labels in network format - values
				 * occupying top 20 bits, BOS bit set on the
				 * last one, network byte order.
				 */
				for (i = 0; i < nh->num_labels; i++) {
					labels[i] =
						htonl(nh->labels[i]
						      << MPLS_LS_LABEL_SHIFT);
				}
				labels[nh->num_labels - 1] |=
					htonl(1 << MPLS_LS_S_SHIFT);

				if (route->prefix.addr.family == AF_MPLS) {
					mnl_attr_put(
						nlh, RTA_NEWDST,
						nh->num_labels *
						sizeof(labels[0]),
						labels);
				} else {
					mnl_attr_put_u16(nlh, RTA_ENCAP_TYPE,
							 LWTUNNEL_ENCAP_MPLS);

					encap_start = mnl_attr_nest_start(
						nlh, RTA_ENCAP);
					mnl_attr_put(
						nlh, MPLS_IPTUNNEL_DST,
						nh->num_labels *
						sizeof(labels[0]),
						labels);
					mnl_attr_nest_end(nlh, encap_start);
				}
			}

			if (route->prefix.addr.family == AF_MPLS) {
				pl_start = mnl_attr_nest_start(
					nlh, RTA_MPLS_PAYLOAD);
				mnl_attr_put_u32(nlh, RTMPA_TYPE,
						 route->mpls_payload_type);
				if (!nh->num_labels)
					mnl_attr_put_u32(nlh, RTMPA_NH_FLAGS,
							 RTMPNF_BOS_ONLY);
				mnl_attr_nest_end(nlh, pl_start);
			}
		}

		if (route->vrf_id != VRF_DEFAULT_ID &&
		    route->vrf_id != VRF_UPLINK_ID) {
			uint32_t tableid;
			bool ret;

			ret = dp_test_upstream_vrf_lookup_db(
				route->vrf_id, NULL, &tableid);
			assert(ret);
			if (route->tableid != RT_TABLE_MAIN &&
			    route->tableid != RT_TABLE_LOCAL) {
				mnl_attr_put_u32(nlh, RTA_TABLE,
						 route->tableid);
			} else {
				mnl_attr_put_u32(nlh, RTA_TABLE, tableid);
				if (tableid > UINT8_MAX)
					rtm->rtm_table = RT_TABLE_COMPAT;
				else
					rtm->rtm_table = tableid;
			}
		} else {
			mnl_attr_put_u32(nlh, RTA_TABLE, route->tableid);
		}

		if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
			dp_test_abort_internal();

		nl_propagate_broker(topic, nlh, nlh->nlmsg_len);
	}
}

static void
dp_test_netlink_route_pb(struct dp_test_route *route, uint16_t nl_type)
{
	IPAddressOrLabel prefix = IPADDRESS_OR_LABEL__INIT;
	RibUpdate rtupdate = RIB_UPDATE__INIT;
	uint32_t tableid = route->tableid;
	Route pbroute = ROUTE__INIT;
	struct dp_test_nh *nh;
	IPAddress *gateway;
	Path **paths;
	Path *path;
	uint32_t i;
	size_t len;

	switch (nl_type) {
	case RTM_NEWROUTE:
		/* leave as default */
		break;
	case RTM_DELROUTE:
		rtupdate.action = RIB_UPDATE__ACTION__DELETE;
		rtupdate.has_action = true;
		break;
	default:
		dp_test_assert_internal(false);
		break;
	}

	rtupdate.route = &pbroute;

	pbroute.prefix = &prefix;

	switch (route->prefix.addr.family) {
	case AF_INET:
		prefix.address_oneof_case =
			IPADDRESS_OR_LABEL__ADDRESS_ONEOF_IPV4_ADDR;
		prefix.ipv4_addr = route->prefix.addr.addr.ipv4;
		break;
	case AF_INET6:
		prefix.address_oneof_case =
			IPADDRESS_OR_LABEL__ADDRESS_ONEOF_IPV6_ADDR;
		prefix.ipv6_addr.data =
			(uint8_t *)&route->prefix.addr.addr.ipv6;
		prefix.ipv6_addr.len = sizeof(route->prefix.addr.addr.ipv6);
		break;
	case AF_MPLS:
		prefix.address_oneof_case =
			IPADDRESS_OR_LABEL__ADDRESS_ONEOF_MPLS_LABEL;
		prefix.mpls_label = ntohl(route->prefix.addr.addr.mpls) >>
			MPLS_LS_LABEL_SHIFT;
		break;
	default:
		dp_test_assert_internal(false);
		break;
	}

	pbroute.has_prefix_length = true;
	pbroute.prefix_length = route->prefix.len;

	if (route->vrf_id != VRF_DEFAULT_ID &&
	    route->vrf_id != VRF_UPLINK_ID &&
	    (route->tableid == RT_TABLE_MAIN ||
	     route->tableid == RT_TABLE_LOCAL)) {
		bool ret;

		ret = dp_test_upstream_vrf_lookup_db(
			route->vrf_id, NULL, &tableid);
		assert(ret);
	}

	if (tableid != RT_TABLE_MAIN) {
		pbroute.has_table_id = true;
		pbroute.table_id = tableid;
	}

	pbroute.has_scope = true;
	pbroute.scope = route->scope;

	switch (route->mpls_payload_type) {
	case RTMPT_IP:
		/* default, so leave as-is */
		break;
	case RTMPT_IPV4:
		pbroute.has_payload_type = true;
		pbroute.payload_type = ROUTE__PAYLOAD_TYPE__IPV4;
		break;
	case RTMPT_IPV6:
		pbroute.has_payload_type = true;
		pbroute.payload_type = ROUTE__PAYLOAD_TYPE__IPV6;
		break;
	default:
		dp_test_assert_internal(false);
		break;
	}

	if (route->type == RTN_BLACKHOLE ||
	    route->type == RTN_UNREACHABLE ||
	    route->type == RTN_LOCAL) {
		paths = calloc(1, sizeof(*paths));
		dp_test_assert_internal(paths);

		pbroute.paths = paths;
		pbroute.n_paths = 1;

		path = calloc(1, sizeof(*path));
		paths[0] = path;
		dp_test_assert_internal(path);

		path__init(path);
		path->has_type = true;
		switch (route->type) {
		case RTN_BLACKHOLE:
			path->type = PATH__PATH_TYPE__BLACKHOLE;
			break;
		case RTN_UNREACHABLE:
			path->type = PATH__PATH_TYPE__UNREACHABLE;
			break;
		case RTN_LOCAL:
			path->type = PATH__PATH_TYPE__LOCAL;
			break;
		}
	} else {
		paths = calloc(route->nh_cnt, sizeof(*paths));
		dp_test_assert_internal(paths);

		pbroute.paths = paths;
		pbroute.n_paths = route->nh_cnt;

		for (i = 0; i < route->nh_cnt; i++) {
			path = calloc(1, sizeof(*path) + sizeof(*gateway));
			paths[i] = path;
			gateway = (IPAddress *)(path + 1);
			nh = &route->nh[i];
			dp_test_assert_internal(path);

			path__init(path);
			ipaddress__init(gateway);

			if (route->tableid == RT_TABLE_LOCAL) {
				path->has_type = true;
				path->type = PATH__PATH_TYPE__LOCAL;
			}

			path->has_ifindex = true;
			path->ifindex = dp_test_intf_name2index(nh->nh_int);

			path->has_backup = true;
			path->backup = nh->backup;

			switch (nh->nh_addr.family) {
			case AF_INET:
				path->nexthop = gateway;
				gateway->address_oneof_case =
					IPADDRESS__ADDRESS_ONEOF_IPV4_ADDR;
				gateway->ipv4_addr = nh->nh_addr.addr.ipv4;
				break;
			case AF_INET6:
				path->nexthop = gateway;
				gateway->address_oneof_case =
					IPADDRESS__ADDRESS_ONEOF_IPV6_ADDR;
				gateway->ipv6_addr.data =
					(uint8_t *)&nh->nh_addr.addr.ipv6;
				gateway->ipv6_addr.len =
					sizeof(nh->nh_addr.addr.ipv6);
				break;
			case AF_UNSPEC:
				break;
			}

			if (nh->num_labels == 1 &&
			    nh->labels[0] == MPLS_LABEL_IMPLNULL) {
				/* Nothing to do */
			} else if (nh->num_labels > 0) {
				path->mpls_labels = nh->labels;
				path->n_mpls_labels = nh->num_labels;
			} else if (route->prefix.addr.family == AF_MPLS) {
				path->has_mpls_bos_only = true;
				path->mpls_bos_only = true;
			}
		}
	}

	len = rib_update__get_packed_size(&rtupdate);
	void *buf = malloc(len);
	dp_test_assert_internal(buf);

	rib_update__pack(&rtupdate, buf);

	nl_propagate_broker(NULL, buf, len);

	if (route->type == RTN_BLACKHOLE ||
	    route->type == RTN_UNREACHABLE ||
	    route->type == RTN_LOCAL)
		free(paths[0]);
	else {
		for (i = 0; i < route->nh_cnt; i++)
			free(paths[i]);
	}
	free(paths);
}

/*
 * Add/delete a route, if verify is set then block until oper-state reflects
 * the requested state.
 *
 * incomplete implies no verify as the route will not be installed in a way
 * that lets the show command verify it. The user can do further verification
 * once it becomes complete.
 */
static void
dp_test_netlink_route(const char *route_string, uint16_t nl_type,
		      bool replace, bool verify, bool incomplete,
		      const char *file, const char *func, int line)
{
	struct dp_test_route *route = dp_test_parse_route(route_string);

	if (verify) {
		if (route->tableid == RT_TABLE_LOCAL)
			_dp_test_wait_for_local_addr(
				route_string, route->vrf_id,
				nl_type == RTM_DELROUTE || replace,
				file, func, line);
		else if (nl_type == RTM_DELROUTE || replace)
			_dp_test_wait_for_route(route_string, !replace, false,
						file, func, line);
		else
			dp_test_wait_for_route_gone(route_string, false,
						    file, func, line);
	}

	if (dp_test_cont_src_get() == CONT_SRC_MAIN &&
	    dp_test_route_broker_protobuf)
		dp_test_netlink_route_pb(route, nl_type);
	else
		dp_test_netlink_route_nl(route, nl_type, replace);

	if (verify) {
		if (route->tableid == RT_TABLE_LOCAL)
			_dp_test_wait_for_local_addr(
				route_string, route->vrf_id,
				nl_type == RTM_DELROUTE, file, func, line);
		else if (nl_type == RTM_NEWROUTE)
			_dp_test_wait_for_route(route_string, true, false,
						file, func, line);
		else
			dp_test_wait_for_route_gone(route_string, false,
						    file, func, line);
	}

	dp_test_free_route(route);
}

void
_dp_test_netlink_add_route(const char *route_str, bool verify, bool incomplete,
			   const char *file, const char *func,
			   int line)
{
	dp_test_netlink_route(route_str, RTM_NEWROUTE,
			      false, verify, incomplete, file, func, line);
}

void
_dp_test_netlink_add_route_fmt(bool verify, bool incomplete, const char *file,
			       const char *func, int line, const char *format,
			       ...)
{
	char cmd[DP_TEST_TMP_BUF];
	va_list ap;

	va_start(ap, format);
	vsnprintf(cmd, sizeof(cmd), format, ap);
	va_end(ap);

	dp_test_netlink_route(cmd, RTM_NEWROUTE, false, verify, incomplete,
			      file, func, line);
}

void
_dp_test_netlink_replace_route(const char *route_str, bool verify,
			       bool incomplete, const char *file,
			       const char *func, int line)
{
	dp_test_netlink_route(route_str, RTM_NEWROUTE,
			      true, verify, incomplete, file, func, line);
}

void
_dp_test_netlink_del_route(const char *route_str, bool verify,
			   const char *file, const char *func,
			   int line)
{
	dp_test_netlink_route(route_str, RTM_DELROUTE,
			      false, verify, false, file, func, line);
}

/* Route add/del/replace in a VRF */
void
_dp_test_verify_add_route(const char *route_string, bool match_nh,
			  bool all, const char *file, const char *func,
			  int line)
{
	_dp_test_wait_for_route(route_string, match_nh, all,
				file, func, line);
}

void
_dp_test_verify_del_route(const char *route_string, bool match_nh,
			  const char *file, const char *func,
			  int line)
{
	dp_test_wait_for_route_gone(route_string, match_nh,
				    file, func, line);
}

void
_dp_test_netlink_del_route_fmt(bool verify, const char *file,
			       const char *func, int line,
			       const char *format, ...)
{
	char cmd[DP_TEST_TMP_BUF];
	va_list ap;

	va_start(ap, format);
	vsnprintf(cmd, sizeof(cmd), format, ap);
	va_end(ap);

	dp_test_netlink_route(cmd, RTM_DELROUTE, false, verify, false,
			      file, func, line);
}

/*
 * Add or delete a multicast route
 *
 * nlmsg_type:   RTM_NEWROUTE or RTM_DELROUTE
 * src:          Source address of multicast stream
 * sintf:        Interface multicast stream expected on
 * route_string: "224.0.1.1/32 nh int:dp2T1 nh int:dp2T2"
 */
void _dp_test_mroute_nl(uint16_t nlmsg_type, const char *src,
			const char *sintf, const char *route_string,
			const char *file, const char *func, int line)
{
	char topic[DP_TEST_TMP_BUF];
	char buf[MNL_SOCKET_BUFFER_SIZE];
	char real_eth_name[IFNAMSIZ];
	struct dp_test_route *route;
	struct nlmsghdr *nlh;
	struct rtmsg *rtm;
	int iif;
	int af, alen;

	route = dp_test_parse_route(route_string);
	dp_test_fail_unless(route->type == RTN_MULTICAST, "Not multicast");

	af = route->prefix.addr.family;

	dp_test_fail_unless(af == AF_INET || af == AF_INET6,
			    "Unknown address family");
	dp_test_fail_unless(route->prefix.len == 32 ||
			    route->prefix.len == 128,
			    "Multicast address is not host address");
	dp_test_fail_unless(route->nh_cnt >= 1,
			    "Expect 1 or more nh interfaces");

	alen = (af == AF_INET) ? 4 : 16;

	dp_test_intf_real(sintf, real_eth_name);
	iif = dp_test_intf_name2index(real_eth_name);

	struct in6_addr src_addr;
	inet_pton(af, src, &src_addr);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);

	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	rtm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
	rtm->rtm_family = ((af == AF_INET) ?
			   RTNL_FAMILY_IPMR : RTNL_FAMILY_IP6MR);
	rtm->rtm_type = RTN_MULTICAST;
	rtm->rtm_dst_len = route->prefix.len;
	rtm->rtm_src_len = route->prefix.len;
	rtm->rtm_tos = 0;
	rtm->rtm_table = RT_TABLE_DEFAULT;
	rtm->rtm_protocol = RTPROT_UNSPEC;
	rtm->rtm_scope = 0;
	rtm->rtm_flags = 0;

	mnl_attr_put_u32(nlh, RTA_TABLE, RT_TABLE_DEFAULT);
	mnl_attr_put(nlh, RTA_SRC, alen, src_addr.s6_addr);
	mnl_attr_put(nlh, RTA_DST, alen, &route->prefix.addr.addr);
	mnl_attr_put_u32(nlh, RTA_IIF, iif);

	/*
	 * Add one or more output interfaces
	 */
	struct nlattr *mpath_start;
	uint i;

	mpath_start = mnl_attr_nest_start(nlh, RTA_MULTIPATH);

	for (i = 0; i < route->nh_cnt; i++) {
		struct rtnexthop *rtnh;

		dp_test_intf_real(route->nh[i].nh_int, real_eth_name);

		rtnh = (struct rtnexthop *)mnl_nlmsg_get_payload_tail(nlh);
		nlh->nlmsg_len += MNL_ALIGN(sizeof(*rtnh));

		memset(rtnh, 0, sizeof(*rtnh));
		rtnh->rtnh_ifindex = dp_test_intf_name2index(real_eth_name);
		rtnh->rtnh_len = sizeof(*rtnh);
	}

	mnl_attr_nest_end(nlh, mpath_start);
	dp_test_free_route(route);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	nl_propagate(topic, nlh);
}

/*
 * Verify an IPv4 or IPv6 multicast route
 */
void
_dp_test_wait_for_mroute(const char *source, const char *group,
			 const char *input, const char *output,
			 bool gone, const char *file, const char *func,
			 int line)
{
	json_object *expected_json;
	bool v6 = strchr(source, ':') != NULL;
	char cmd[22];

	expected_json = dp_test_json_create(
		"{"
		"  \"%s\":["
		"    {"
		"      \"source\":\"%s\","
		"      \"group\":\"%s\","
		"      \"input\":\"%s\","
		"      \"output(s)\":\"%s\","
		"      \"forwarding\":\"fast\\/dataplane\""
		"    }"
		"  ]"
		"}",
		v6 ? "route6" : "route",
		source, group, input, output);

	snprintf(cmd, sizeof(cmd), "multicast %s",
		 v6 ? "route6" : "route");

	_dp_test_check_json_state(cmd, expected_json, NULL,
				  DP_TEST_JSON_CHECK_SUBSET, gone, false,
				  file, func, line);
	json_object_put(expected_json);
}

/*
 * Enable or disable multicast on an interface.
 */
void _dp_test_netlink_netconf_mcast(const char *ifname, int af, bool enable,
				    const char *file, const char *func,
				    int line)
{
	struct netconfmsg *ncm;
	char topic[DP_TEST_TMP_BUF];
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real(ifname, real_ifname);

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = RTM_NEWNETCONF;
	nlh->nlmsg_flags = NLM_F_ACK;

	ncm = mnl_nlmsg_put_extra_header(nlh, sizeof(struct netconfmsg));
	ncm->ncm_family = af;

	/*
	 * Attributes are:
	 *
	 * NETCONFA_UNSPEC,
	 * NETCONFA_IFINDEX,
	 * NETCONFA_FORWARDING,
	 * NETCONFA_RP_FILTER,
	 * NETCONFA_MC_FORWARDING,
	 * NETCONFA_PROXY_NEIGH,
	 */
	mnl_attr_put_u32(nlh, NETCONFA_IFINDEX,
			 dp_test_intf_name2index(real_ifname));
	mnl_attr_put_u32(nlh, NETCONFA_FORWARDING, false);
	mnl_attr_put_u32(nlh, NETCONFA_RP_FILTER, 0);
	mnl_attr_put_u32(nlh, NETCONFA_MC_FORWARDING, enable);
	mnl_attr_put_u32(nlh, NETCONFA_PROXY_NEIGH, 0);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	nl_propagate(topic, nlh);
}

/*
 *  * RFC 2863 operational status
 *   *
 *    * From <linux/if.h> but not included in <net/if.h>, so defining here.
 *     */
enum {
	DP_TEST_IF_OPER_UNKNOWN,
	DP_TEST_IF_OPER_NOTPRESENT,
	DP_TEST_IF_OPER_DOWN,
	DP_TEST_IF_OPER_LOWERLAYERDOWN,
	DP_TEST_IF_OPER_TESTING,
	DP_TEST_IF_OPER_DORMANT,
	DP_TEST_IF_OPER_UP,
};

/*
 * Update bridge interface
 */
static void
dp_test_netlink_bridge(const char *br_name, uint16_t nlmsg_type, bool verify,
		       const char *file, const char *func,
		       int line)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	char topic[DP_TEST_TMP_BUF];
	char real_br_name[IFNAMSIZ];
	struct ifinfomsg *ifi;
	struct nlmsghdr *nlh;
	int if_index;

	dp_test_intf_real(br_name, real_br_name);

	switch (nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		if_index = dp_test_intf_name2index(real_br_name);
		break;
	default:
		dp_test_assert_internal(false); /* Unsupported type */
		break;
	}
	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_ETHER;
	ifi->ifi_family = AF_UNSPEC; /* New link so not AF_BRIDGE */
	ifi->ifi_index = if_index;
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = 0xffffffff;

	/*
	 * Netlink Create Bridge Message
	 * IFLA_IFNAME
	 * IFLA_ADDRESS: MAC address
	 * IFLA_MTU
	 * IFLA_LINK
	 * IFLA_OPERSTATE
	 * IFLA_PROTINFO
	 */
	mnl_attr_put_strz(nlh, IFLA_IFNAME, real_br_name);
	mnl_attr_put(nlh, IFLA_ADDRESS, sizeof(struct rte_ether_addr),
		     dp_test_intf_name2mac(real_br_name));
	if (nlmsg_type == RTM_NEWLINK)
		mnl_attr_put_u8(nlh, IFLA_OPERSTATE, DP_TEST_IF_OPER_UP);

	struct nlattr *br_link = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	br_link->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "bridge");
	mnl_attr_nest_end(nlh, br_link);


	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", real_br_name);
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"type\": \"%s\","
					       "    }"
					       "  ]"
					       "}",
					       real_br_name,
					       "bridge");
		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false, file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);

}

static void
dp_test_netlink_bridge_port_state(const char *br_name, const char *eth_name,
				  uint16_t nlmsg_type, uint8_t state,
				  bool verify, const char *file,
				  const char *func, int line)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	char topic[DP_TEST_TMP_BUF];
	char real_eth_name[IFNAMSIZ];
	char real_br_name[IFNAMSIZ];
	struct ifinfomsg *ifi;
	struct nlmsghdr *nlh;
	struct nlattr *br_proto_info;

	dp_test_intf_real(br_name, real_br_name);
	dp_test_intf_real(eth_name, real_eth_name);

	switch (nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		break;
	default:
		dp_test_assert_internal(false); /* Unsupported type */
		break;
	}
	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_ETHER;
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index = dp_test_intf_name2index(real_eth_name);
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = 0xffffffff;
	/*
	 * Netlink Add port to Bridge message
	 *
	 * IFLA_IFNAME:                 Port name
	 * IFLA_MASTER:                 if_index of Bridge
	 * IFLA_PROTINFO:               Bridge protocol information
	 *   IFLA_BRPORT_STATE:         Bridge port state
	 *       BR_STATE_DISABLED 0
	 *       BR_STATE_LISTENING 1
	 *       BR_STATE_LEARNING 2
	 *       BR_STATE_FORWARDING 3
	 *       BR_STATE_BLOCKING 4
	 */
	mnl_attr_put_strz(nlh, IFLA_IFNAME, real_eth_name);
	mnl_attr_put_u32(nlh, IFLA_MASTER,
			 dp_test_intf_name2index(real_br_name));
	br_proto_info = mnl_attr_nest_start(nlh, IFLA_PROTINFO);
	br_proto_info->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_u8(nlh, 1, state); /* 1 IFLA_BRPORT_STATE */
	mnl_attr_nest_end(nlh, br_proto_info);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	/*
	 * And now test it is there. Display bridge and look for port.
	 */
	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", real_br_name);
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"type\": \"%s\","
					       "       \"bridge\" :"
					       "         ["
					       "           {"
					       "             \"link\": \"%s\","
					       "             \"state\": \"%s\","
					       "           }"
					       "         ]"
					       "    }"
					       "  ]"
					       "}",
					       real_br_name,
					       "bridge",
					       real_eth_name,
					       bridge_get_ifstate_string(
						       state));
		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);
}

static void
dp_test_bridge_print_vlan_filter(char **buf, size_t *bufsz,
	uint16_t pvid,
	struct bridge_vlan_set *allowed_vlans,
	struct bridge_vlan_set *untag_vlans)
{
	int i;
	FILE *f = open_memstream(buf, bufsz);
	if (f == NULL)
		return;
	json_writer_t *wr = jsonw_new(f);

	jsonw_uint_field(wr, "pvid", pvid);

	jsonw_name(wr, "allowed_vlans");
	jsonw_start_array(wr);
	if (allowed_vlans != NULL) {
		for (i = 0; i < VLAN_N_VID; i++) {
			if (bridge_vlan_set_is_member(allowed_vlans, i))
				jsonw_uint(wr, i);
		}
	}
	jsonw_end_array(wr);

	jsonw_name(wr, "untag_vlans");
	jsonw_start_array(wr);
	if (untag_vlans != NULL) {
		for (i = 0; i < VLAN_N_VID; i++) {
			if (bridge_vlan_set_is_member(untag_vlans, i))
				jsonw_uint(wr, i);
		}
	}
	jsonw_end_array(wr);

	jsonw_destroy(&wr);
	fclose(f);
}

void
_dp_test_netlink_bridge_port_set(const char *br_name,
	const char *eth_name, uint16_t pvid,
	struct bridge_vlan_set *vlans, struct bridge_vlan_set *untag_vlans,
	uint8_t state, bool verify, const char *file,
	const char *func, int line)
{
	uint16_t nlmsg_type = RTM_NEWLINK;

	char buf[MNL_SOCKET_BUFFER_SIZE];
	char topic[DP_TEST_TMP_BUF];
	char real_eth_name[IFNAMSIZ];
	char real_br_name[IFNAMSIZ];
	struct ifinfomsg *ifi;
	struct nlmsghdr *nlh;
	struct nlattr *br_proto_info;

	dp_test_intf_real(br_name, real_br_name);
	dp_test_intf_real(eth_name, real_eth_name);

	switch (nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		break;
	default:
		dp_test_assert_internal(false); /* Unsupported type */
		break;
	}
	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_ETHER;
	ifi->ifi_family = AF_BRIDGE;
	ifi->ifi_index = dp_test_intf_name2index(real_eth_name);
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = 0xffffffff;
	/*
	 * Netlink Add port to Bridge message
	 *
	 * IFLA_IFNAME:                 Port name
	 * IFLA_MASTER:                 if_index of Bridge
	 * IFLA_AF_SPEC:                Bridge protocol information
	 *   IFLA_BRIDGE_VLAN_INFO...
	 * IFLA_PROTINFO:
	 */
	mnl_attr_put_strz(nlh, IFLA_IFNAME, real_eth_name);
	mnl_attr_put_u32(nlh, IFLA_MASTER,
			 dp_test_intf_name2index(real_br_name));
	br_proto_info = mnl_attr_nest_start(nlh, IFLA_PROTINFO);
	br_proto_info->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_u8(nlh, 1, state); /* 1 IFLA_BRPORT_STATE */
	mnl_attr_nest_end(nlh, br_proto_info);

	if (vlans) {
		struct nlattr *br_af_spec = mnl_attr_nest_start(nlh,
								IFLA_AF_SPEC);
		struct nl_bridge_vlan_info vinfo = { .flags = 0, .vid = 0 };
		int i;

		for (i = 0; i < VLAN_N_VID; i++) {
			if (bridge_vlan_set_is_member(vlans, i)) {
				vinfo.vid = i;
				vinfo.flags = 0;
				if (untag_vlans &&
					bridge_vlan_set_is_member(
						untag_vlans, i))
					vinfo.flags |=
						BRIDGE_VLAN_INFO_UNTAGGED;
				if (i == pvid)
					vinfo.flags |= BRIDGE_VLAN_INFO_PVID;
				mnl_attr_put(nlh, IFLA_BRIDGE_VLAN_INFO,
					sizeof(vinfo), &vinfo);
			}
		}
		mnl_attr_nest_end(nlh, br_af_spec);
	}
	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	/*We need to generate the expected vlan_filtering object*/
	char *vlanbuf = NULL;
	size_t bufsz = 0;
	dp_test_bridge_print_vlan_filter(&vlanbuf, &bufsz,
		pvid, vlans, untag_vlans);
	/*
	 * And now test it is there. Display bridge and look for port.
	 */
	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;
		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", real_br_name);
		expected = dp_test_json_create(
			"{ \"interfaces\":"
			"  ["
			"    {"
			"       \"name\": \"%s\","
			"       \"type\": \"%s\","
			"       \"bridge\" :"
			"         ["
			"           {"
			"             \"link\": \"%s\","
			"             \"state\": \"%s\","
			"             \"vlan_filtering\": %s"
			"           }"
			"         ]"
			"    }"
			"  ]"
			"}",
			real_br_name,
			"bridge",
			real_eth_name,
			bridge_get_ifstate_string(state),
			vlanbuf);
		free(vlanbuf);
		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);
}

void _dp_test_netlink_set_bridge_vlan_filter(const char *br_name, bool verify,
			       const char *file, const char *func,
			       int line)
{
	int nlmsg_type = RTM_NEWLINK;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	char topic[DP_TEST_TMP_BUF];
	char real_br_name[IFNAMSIZ];
	struct ifinfomsg *ifi;
	struct nlmsghdr *nlh;
	int if_index;

	dp_test_intf_real(br_name, real_br_name);

	switch (nlmsg_type) {
	case RTM_NEWLINK:
		if_index = dp_test_intf_name2index(real_br_name);
		break;
	default:
		dp_test_assert_internal(false); /* Unsupported type */
		break;
	}
	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_ETHER;
	ifi->ifi_family = AF_UNSPEC; /* New link so not AF_BRIDGE */
	ifi->ifi_index = if_index;
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = 0xffffffff;

	/*
	 * Netlink Create Bridge Message
	 * IFLA_IFNAME
	 * IFLA_ADDRESS: MAC address
	 * IFLA_MTU
	 * IFLA_LINK
	 * IFLA_OPERSTATE
	 * IFLA_PROTINFO
	 * IFLA_LINKINFO
	 *    IFLA_INFO_KIND: bridge
	 *    IFLA_INFO_DATA:
	 *        IFLA_BR_VLAN_FILTERING: u8
	 */
	mnl_attr_put_strz(nlh, IFLA_IFNAME, real_br_name);
	mnl_attr_put(nlh, IFLA_ADDRESS, sizeof(struct rte_ether_addr),
		     dp_test_intf_name2mac(real_br_name));
	if (nlmsg_type == RTM_NEWLINK)
		mnl_attr_put_u8(nlh, IFLA_OPERSTATE, DP_TEST_IF_OPER_UP);

	struct nlattr *br_link = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	br_link->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "bridge");
	struct nlattr *info_data = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
	mnl_attr_put_u8(nlh, IFLA_BR_VLAN_FILTERING, 1);
	mnl_attr_nest_end(nlh, info_data);
	mnl_attr_nest_end(nlh, br_link);


	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", real_br_name);
		expected = dp_test_json_create(
			"{ \"interfaces\":"
			"  ["
			"    {"
			"       \"name\": \"%s\","
			"       \"type\": \"%s\","
			"       \"bridge_interface\": {"
			"           \"vlan_filtering\": true"
			"      }"
			"    }"
			"  ]"
			"}",
			real_br_name,
			"bridge");
		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false, file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);
}

/*
 * Create a new bridge interface
 */
void
_dp_test_netlink_create_bridge(const char *br_name, bool verify,
			       const char *file, const char *func,
			       int line)
{
	char real_br_name[IFNAMSIZ];

	dp_test_intf_real(br_name, real_br_name);
	switch (dp_test_intf_type(real_br_name)) {
	case DP_TEST_INTF_TYPE_BRIDGE:
		dp_test_netlink_bridge(real_br_name, RTM_NEWLINK, verify,
				       file, func, line);
		break;
	default:
		dp_test_assert_internal(false);
	}
}

/*
 * Delete an existing bridge interface
 */
void
_dp_test_netlink_del_bridge(const char *br_name, bool verify,
			    const char *file, const char *func,
			    int line)
{
	char real_br_name[IFNAMSIZ];

	dp_test_intf_real(br_name, real_br_name);

	switch (dp_test_intf_type(real_br_name)) {
	case DP_TEST_INTF_TYPE_BRIDGE:
		dp_test_netlink_bridge(br_name, RTM_DELLINK, verify,
				       file, func, line);
		break;
	default:
		dp_test_assert_internal(false);
	}
}

static void
dp_test_netlink_bridge_port(const char *br_name, const char *eth_name,
			    uint16_t nlmsg_type, bool verify,
			    const char *file, const char *func,
			    int line)
{
	dp_test_netlink_bridge_port_state(br_name, eth_name, nlmsg_type,
					  BR_STATE_FORWARDING, verify,
					  file, func, line);
}

/*
 * Add eth_name as a port on bridge br_name.
 */
void
_dp_test_netlink_add_bridge_port(const char *br_name, const char *eth_name,
				 bool verify,
				 const char *file, const char *func,
				 int line)
{
	dp_test_netlink_bridge_port(br_name, eth_name, RTM_NEWLINK, verify,
				    file, func, line);
}

/*
 * Add eth_name as a port on bridge br_name.
 */
void
_dp_test_netlink_remove_bridge_port(const char *br_name, const char *eth_name,
				    bool verify,
				    const char *file, const char *func,
				    int line)
{
	dp_test_netlink_bridge_port(br_name, eth_name, RTM_DELLINK, verify,
				    file, func, line);
}

/*
 * Update vxlan interface
 *
 * vxlan_id is vxlan VNI
 * intf_parent is name of parent interface i.e. dpT0
 */
static void
dp_test_netlink_vxlan(const char *vxlan_name, uint16_t nlmsg_type,
		      uint32_t vni, const char *parent_name, bool verify,
		      const char *file, const char *func,
		      int line)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlattr *vxlan_info, *vxlan_data;
	char topic[DP_TEST_TMP_BUF];
	struct ifinfomsg *ifi;
	struct nlmsghdr *nlh;
	int if_index;

	switch (nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		if_index = dp_test_intf_name2index(vxlan_name);
		break;
	default:
		dp_test_assert_internal(false); /* Unsupported type */
		break;
	}
	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_ETHER;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = if_index;
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = 0xffffffff;

	/*
	 * Netlink Create vxlan Message
	 * IFLA_IFNAME
	 * IFLA_ADDRESS: MAC address
	 * IFLA_MTU
	 * IFLA_LINK
	 * IFLA_OPERSTATE
	 */
	mnl_attr_put_strz(nlh, IFLA_IFNAME, vxlan_name);
	mnl_attr_put(nlh, IFLA_ADDRESS, sizeof(struct rte_ether_addr),
		     dp_test_intf_name2mac(vxlan_name));
	if (nlmsg_type == RTM_NEWLINK)
		mnl_attr_put_u8(nlh, IFLA_OPERSTATE, DP_TEST_IF_OPER_UP);

	/*
	 * IFLA_LINKINFO (nested)
	 *   IFLA_INFO_KIND
	 */
	vxlan_info = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	vxlan_info->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "vxlan");

	if (nlmsg_type == RTM_NEWLINK) {
		/* IFLA_INFO_DATA (nested)
		 *   IFLA_VXLAN_ID         [VNI]
		 *   IFLA_VXLAN_GROUP
		 *   IFLA_VXLAN_LOCAL
		 *   IFLA_VXLAN_LINK       [Physical intf id ]
		 *   IFLA_VXLAN_TTL
		 *   IFLA_VXLAN_TOS
		 *   IFLA_VXLAN_LEARNING
		 *   IFLA_VXLAN_PORT_RANGE
		 */
		vxlan_data = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
		vxlan_data->nla_type &= ~NLA_F_NESTED;
		mnl_attr_put_u32(nlh, IFLA_VXLAN_ID, vni);
		if (parent_name)
			mnl_attr_put_u32(nlh, IFLA_VXLAN_LINK,
					 dp_test_intf_name2index(parent_name));
		else
			dp_test_assert_internal(false);
		mnl_attr_nest_end(nlh, vxlan_data);
	}
	mnl_attr_nest_end(nlh, vxlan_info);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", vxlan_name);
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"type\": \"%s\","
					       "       \"vni\": %d,"
					       "    }"
					       "  ]"
					       "}",
					       vxlan_name, "vxlan", vni);
		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);
}

/*
 * Create a new vxlan interface
 */
void
_dp_test_netlink_create_vxlan(const char *vxlan_name, uint32_t vni,
			      const char *parent_name, bool verify,
			      const char *file, const char *func, int line)
{
	dp_test_netlink_vxlan(vxlan_name, RTM_NEWLINK, vni, parent_name,
			      verify,
			      file, func, line);
}

/*
 * Delete an existing vxlan interface
 */
void
_dp_test_netlink_del_vxlan(const char *vxlan_name, uint32_t vni,
			   bool verify,
			   const char *file, const char *func, int line)
{
	dp_test_netlink_vxlan(vxlan_name, RTM_DELLINK, vni, NULL, verify,
			      file, func, line);
}

/*
 * Update vif interface
 *
 * vlan : the vlan id
 * parent_name is name of parent interface i.e. dpT0
 *
 * parent_name can not be NULL.
 */
static void
dp_test_netlink_vlan(const char *vif_name, uint16_t nlmsg_type,
		     const char *parent_name, uint16_t vlan,
		     uint16_t vlan_proto, bool verify,
		     const char *file, const char *func,
		     int line)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlattr *vlan_info, *vlan_data;
	char topic[DP_TEST_TMP_BUF];
	char real_vif_name[IFNAMSIZ];
	char real_parent_name[IFNAMSIZ];
	struct ifinfomsg *ifi;
	struct nlmsghdr *nlh;
	int if_index = 0;

	dp_test_intf_real(vif_name, real_vif_name);
	if (parent_name)
		dp_test_intf_real(parent_name, real_parent_name);

	switch (nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		if_index = dp_test_intf_name2index(real_vif_name);
		break;
	default:
		dp_test_assert_internal(false); /* Unsupported type */
		break;
	}
	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_ETHER;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = if_index;
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = 0xffffffff;

	/*
	 * Netlink Create vlan Message
	 * IFLA_IFNAME
	 * IFLA_ADDRESS: MAC address
	 * IFLA_OPERSTATE
	 */
	mnl_attr_put_strz(nlh, IFLA_IFNAME, real_vif_name);
	if (parent_name)
		mnl_attr_put(nlh, IFLA_ADDRESS, sizeof(struct rte_ether_addr),
			     dp_test_intf_name2mac(real_parent_name));
	if (nlmsg_type == RTM_NEWLINK)
		mnl_attr_put_u8(nlh, IFLA_OPERSTATE, DP_TEST_IF_OPER_UP);

	/*
	 * IFLA_LINKINFO (nested)
	 *   IFLA_KIND
	 */
	vlan_info = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	vlan_info->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "vlan");

	if (nlmsg_type == RTM_NEWLINK) {
		/* IFLA_INFO_DATA (nested)
		 *   IFLA_VLAN_ID
		 */
		vlan_data = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
		vlan_data->nla_type &= ~NLA_F_NESTED;
		mnl_attr_put_u16(nlh, IFLA_VLAN_ID, vlan); /* Vlan Id*/
		/* NB vlan protocol is sent in network byte order */
		mnl_attr_put_u16(nlh, IFLA_VLAN_PROTOCOL, htons(vlan_proto));
		mnl_attr_nest_end(nlh, vlan_data);
	}
	mnl_attr_nest_end(nlh, vlan_info);
	if (parent_name)
		mnl_attr_put_u32(nlh, IFLA_LINK,
				 dp_test_intf_name2index(real_parent_name));

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", real_vif_name);
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"tag\": %d,"
					       "       \"tag-proto\": %d,"
					       "    }"
					       "  ]"
					       "}",
					       real_vif_name,
					       vlan, vlan_proto);
		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);

}

/*
 * Create a new vif interface
 */
void
_dp_test_netlink_create_vif(const char *vif_name,
			    const char *parent_name,
			    uint16_t vlan,
			    uint16_t vlan_proto,
			    bool verify,
			    const char *file, const char *func,
			    int line)
{
	dp_test_netlink_vlan(vif_name, RTM_NEWLINK, parent_name, vlan,
			     vlan_proto, verify,
			     file, func, line);
}

/*
 * Delete an existing vif interface
 */
void
_dp_test_netlink_del_vif(const char *vif_name, uint16_t vlan,
			 uint16_t vlan_proto, bool verify,
			 const char *file, const char *func, int line)
{
	dp_test_netlink_vlan(vif_name, RTM_DELLINK, NULL, vlan, vlan_proto,
			     verify, file, func, line);
}

static void
dp_test_netlink_macvlan(const char *vif_name, uint16_t nlmsg_type,
			const char *parent_name, const char *mac_str,
			bool verify,
			const char *file, const char *func,
			int line)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlattr *vlan_info;
	char topic[DP_TEST_TMP_BUF];
	char real_parent_name[IFNAMSIZ];
	struct rte_ether_addr mac;
	struct ifinfomsg *ifi;
	struct nlmsghdr *nlh;
	int if_index = 0;

	if (parent_name)
		dp_test_intf_real(parent_name, real_parent_name);

	switch (nlmsg_type) {
	case RTM_NEWLINK:
	case RTM_DELLINK:
		if_index = dp_test_intf_name2index(vif_name);
		break;
	default:
		dp_test_assert_internal(false); /* Unsupported type */
		break;
	}
	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_ETHER;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = if_index;
	ifi->ifi_flags = IFF_UP;
	ifi->ifi_change = 0xffffffff;

	/*
	 * Netlink Create vlan Message
	 * IFLA_IFNAME
	 * IFLA_ADDRESS: MAC address
	 * IFLA_OPERSTATE
	 */
	mnl_attr_put_strz(nlh, IFLA_IFNAME, vif_name);
	if (nlmsg_type == RTM_NEWLINK) {
		if (ether_aton_r(mac_str, &mac) == NULL)
			dp_test_assert_internal(false);

		mnl_attr_put(nlh, IFLA_ADDRESS, sizeof(mac), &mac);
		mnl_attr_put_u8(nlh, IFLA_OPERSTATE, DP_TEST_IF_OPER_UP);
	}

	/*
	 * IFLA_LINKINFO (nested)
	 *   IFLA_KIND
	 */
	vlan_info = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	vlan_info->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "macvlan");

	mnl_attr_nest_end(nlh, vlan_info);
	if (parent_name)
		mnl_attr_put_u32(nlh, IFLA_LINK,
				 dp_test_intf_name2index(real_parent_name));

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", vif_name);
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "    }"
					       "  ]"
					       "}",
					       vif_name);
		if (nlmsg_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nlmsg_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else
		nl_propagate(topic, nlh);

}

/*
 * Create a new vif interface
 */
void
_dp_test_netlink_create_macvlan(const char *vif_name,
				const char *parent_name,
				const char *mac_str,
				bool verify,
				const char *file, const char *func,
				int line)
{
	dp_test_netlink_macvlan(vif_name, RTM_NEWLINK, parent_name, mac_str,
				verify, file, func, line);
}

/*
 * Delete an existing vif interface
 */
void
_dp_test_netlink_del_macvlan(const char *vif_name, bool verify,
			     const char *file, const char *func,
			     int line)
{
	dp_test_netlink_macvlan(vif_name, RTM_DELLINK, NULL, NULL, verify,
				file, func, line);
}

static void
dp_test_netlink_vti(const char *tun_name,
		    const char *tun_local,
		    const char *tun_remote,
		    uint16_t nl_type,
		    uint16_t mark,
		    vrfid_t vrf_id,
		    bool verify)
{
	struct ifinfomsg *ifi;
	char topic[DP_TEST_TMP_BUF];
	int tun_index = dp_test_intf_name2index(tun_name);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	int af;

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nl_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_TUNNEL;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = tun_index;
	ifi->ifi_flags = IFF_UP|IFF_POINTOPOINT|IFF_NOARP|IFF_RUNNING;

	uint32_t local[4], remote[4], result;
	result = inet_pton(AF_INET, tun_local, &local);
	if (result == 1) {
		af = AF_INET;
	} else {
		result = inet_pton(AF_INET6, tun_local, &local);
		dp_test_assert_internal(result == 1);
		af = AF_INET6;
	}
	result = inet_pton(af, tun_remote, &remote);
	dp_test_assert_internal(result == 1);

	struct nlattr *vti_link = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	vti_link->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "vti");


	struct nlattr *vti_data = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
	vti_data->nla_type &= ~NLA_F_NESTED;

	mnl_attr_put_u32(nlh, IFLA_VTI_LINK, 0);
	mnl_attr_put_u32(nlh, IFLA_VTI_IKEY, 0);
	mnl_attr_put_u32(nlh, IFLA_VTI_OKEY, mark);
	if (af == AF_INET) {
		mnl_attr_put_u32(nlh, IFLA_VTI_LOCAL, local[0]);
		mnl_attr_put_u32(nlh, IFLA_VTI_REMOTE, remote[0]);
	} else {
		mnl_attr_put(nlh, IFLA_VTI_LOCAL, 16, local);
		mnl_attr_put(nlh, IFLA_VTI_REMOTE, 16, remote);
	}
	mnl_attr_nest_end(nlh, vti_data);
	mnl_attr_nest_end(nlh, vti_link);

	/* And remaining settings */
	if (vrf_id != VRF_DEFAULT_ID && vrf_id != VRF_UPLINK_ID) {
		vrf_id = dp_test_translate_vrf_id(vrf_id);
		mnl_attr_put_u32(nlh, IFLA_MASTER, vrf_id);
	}
	mnl_attr_put_u32(nlh, IFLA_MTU, 1428);
	mnl_attr_put(nlh, IFLA_ADDRESS, sizeof(struct rte_ether_addr),
		     dp_test_intf_name2mac(tun_name));
	mnl_attr_put_strz(nlh, IFLA_IFNAME, tun_name);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	nl_propagate(topic, nlh);

	/*
	 * And now test it is there. Will move to a more advanced test
	 * later.
	 */
	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		char expected[TEST_MAX_REPLY_LEN];
		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", tun_name);
		snprintf(expected, TEST_MAX_REPLY_LEN, "%s", tun_name);
		if (nl_type == RTM_NEWLINK)
			dp_test_check_state_show(cmd, expected, false);
		else
			dp_test_check_state_gone_show(cmd, expected, false);
	}
}

void
dp_test_netlink_create_vti(const char *tun_name,
			   const char *tun_local,
			   const char *tun_remote,
			   uint16_t mark,
			   vrfid_t vrf_id)
{
	dp_test_netlink_vti(tun_name, tun_local,
			    tun_remote, RTM_NEWLINK, mark, vrf_id, true);
}

void
dp_test_netlink_delete_vti(const char *tun_name,
			   const char *tun_local,
			   const char *tun_remote,
			   uint16_t mark,
			   vrfid_t vrf_id)
{
	dp_test_netlink_vti(tun_name, tun_local,
			    tun_remote, RTM_DELLINK, mark, vrf_id, true);
}

static void
dp_test_netlink_lo_or_vfp(const char *name, bool verify, uint16_t nl_type,
			  vrfid_t vrf_id, const char *file, const char *func,
			  int line, bool is_vfp)
{
	struct ifinfomsg *ifi;
	char topic[DP_TEST_TMP_BUF];
	int if_index = dp_test_intf_name2index(name);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct rte_ether_addr addr;

	memset(&addr, 0, sizeof(addr));

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nl_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = is_vfp ? ARPHRD_ETHER : ARPHRD_LOOPBACK;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = if_index;
	ifi->ifi_flags = IFF_UP | IFF_RUNNING |
		(is_vfp ? IFF_NOARP : IFF_LOOPBACK);

	if (is_vfp) {
		struct nlattr *dummy_link =
			mnl_attr_nest_start(nlh, IFLA_LINKINFO);

		dummy_link->nla_type &= ~NLA_F_NESTED;
		mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "dummy");
		mnl_attr_nest_end(nlh, dummy_link);
	}

	/* And remaining settings */
	if (vrf_id != VRF_DEFAULT_ID && vrf_id != VRF_UPLINK_ID) {
		vrf_id = _dp_test_translate_vrf_id(vrf_id, file, line);
		mnl_attr_put_u32(nlh, IFLA_MASTER, vrf_id);
	}
	if (!is_vfp)
		mnl_attr_put_u32(nlh, IFLA_MTU, 65536);
	mnl_attr_put(nlh, IFLA_ADDRESS, sizeof(addr), &addr);
	mnl_attr_put(nlh, IFLA_BROADCAST, sizeof(addr), &addr);
	mnl_attr_put_strz(nlh, IFLA_IFNAME, name);
	mnl_attr_put_u8(nlh, IFLA_OPERSTATE, 6);
	mnl_attr_put_u8(nlh, IFLA_LINKMODE, 0);
	mnl_attr_put_u32(nlh, IFLA_GROUP, 0);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", name);
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"type\": \"loopback\","
					       "    }"
					       "  ]"
					       "}", name);
		if (nl_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nl_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else {
		nl_propagate(topic, nlh);
	}
}

void
_dp_test_netlink_create_lo(const char *name, bool verify,
			   const char *file, const char *func, int line)
{
	dp_test_netlink_lo_or_vfp(name, verify, RTM_NEWLINK, VRF_DEFAULT_ID,
				  file, func, line, false);
}

void
_dp_test_netlink_del_lo(const char *name, bool verify,
			const char *file, const char *func, int line)
{
	dp_test_netlink_lo_or_vfp(name, verify, RTM_DELLINK, VRF_DEFAULT_ID,
				  file, func, line, false);
}

void
_dp_test_netlink_create_vfp(const char *name, vrfid_t vrf_id, bool verify,
			    const char *file, const char *func, int line)
{
	dp_test_netlink_lo_or_vfp(name, verify, RTM_NEWLINK, vrf_id,
				  file, func, line, true);
}

void
_dp_test_netlink_del_vfp(const char *name, vrfid_t vrf_id, bool verify,
			 const char *file, const char *func, int line)
{
	dp_test_netlink_lo_or_vfp(name, verify, RTM_DELLINK, vrf_id,
				  file, func, line, true);
}

static void
dp_test_netlink_vrf_if(const char *name, bool verify, uint16_t nl_type,
			   vrfid_t vrf_id, uint32_t tableid, const char *file,
			   const char *func, int line)
{
	struct ifinfomsg *ifi;
	char topic[DP_TEST_TMP_BUF];
	int if_index = dp_test_intf_name2index(name);
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct rte_ether_addr addr;

	memset(&addr, 0, sizeof(addr));

	memset(buf, 0, sizeof(buf));
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nl_type;
	nlh->nlmsg_flags = NLM_F_ACK;

	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_type = ARPHRD_ETHER;
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = if_index;
	ifi->ifi_flags = IFF_UP|IFF_MASTER|IFF_NOARP|IFF_RUNNING;

	struct nlattr *vrf_link = mnl_attr_nest_start(nlh, IFLA_LINKINFO);
	vrf_link->nla_type &= ~NLA_F_NESTED;
	mnl_attr_put_strz(nlh, IFLA_INFO_KIND, "vrf");
	struct nlattr *info_data = mnl_attr_nest_start(nlh, IFLA_INFO_DATA);
	mnl_attr_put_u32(nlh, IFLA_VRF_TABLE, tableid);
	mnl_attr_nest_end(nlh, info_data);
	mnl_attr_nest_end(nlh, vrf_link);

	/* And remaining settings */
	mnl_attr_put_u32(nlh, IFLA_MTU, 65536);
	mnl_attr_put(nlh, IFLA_ADDRESS, sizeof(addr), &addr);
	mnl_attr_put(nlh, IFLA_BROADCAST, sizeof(addr), &addr);
	mnl_attr_put_strz(nlh, IFLA_IFNAME, name);
	mnl_attr_put_u8(nlh, IFLA_OPERSTATE, 6);
	mnl_attr_put_u8(nlh, IFLA_LINKMODE, 0);
	mnl_attr_put_u32(nlh, IFLA_GROUP, 0);

	if (nl_generate_topic(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();

	if (verify) {
		char cmd[TEST_MAX_CMD_LEN];
		json_object *expected;

		snprintf(cmd, TEST_MAX_CMD_LEN, "ifconfig %s", name);
		expected = dp_test_json_create("{ \"interfaces\":"
					       "  ["
					       "    {"
					       "       \"name\": \"%s\","
					       "       \"type\": \"vrf\","
					       "    }"
					       "  ]"
					       "}", name);
		if (nl_type == RTM_NEWLINK)
			nl_propagate(topic, nlh);
		_dp_test_check_json_state(cmd, expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		if (nl_type == RTM_DELLINK) {
			nl_propagate(topic, nlh);
			_dp_test_check_json_state(cmd, expected, NULL,
						  DP_TEST_JSON_CHECK_SUBSET,
						  true, false,
						  file, func, line);
		}
		json_object_put(expected);
	} else {
		nl_propagate(topic, nlh);
	}
}

void
_dp_test_netlink_create_vrf_if(const char *name, vrfid_t vrf_id,
				   uint32_t tableid, bool verify,
				   const char *file, const char *func,
				   int line)
{
	dp_test_netlink_vrf_if(name, verify, RTM_NEWLINK, vrf_id, tableid,
				   file, func, line);
}

void
_dp_test_netlink_del_vrf_if(const char *name, vrfid_t vrf_id,
				uint32_t tableid, bool verify,
				const char *file, const char *func,
				int line)
{
	dp_test_netlink_vrf_if(name, verify, RTM_DELLINK, vrf_id, tableid,
				  file, func, line);
}

/***************************************************
 * Functions for policy and SA XFRM messages
 ***************************************************/

/* Call back from libmnl to validate netlink message */
static int xfrm_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, XFRMA_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}


static void xfrm_nl_policy_decode(const struct nlmsghdr *nlh,
				  const struct xfrm_userpolicy_info **info,
				  const struct xfrm_userpolicy_id **id)
{
	const struct xfrm_userpolicy_id *pol_id = NULL;
	const struct xfrm_user_polexpire *pol_expire;
	const struct xfrm_userpolicy_info *pol_info = NULL;
	struct nlattr *tb[XFRMA_MAX+1] = { NULL };

	switch (nlh->nlmsg_type) {
	case XFRM_MSG_DELPOLICY:
		pol_id = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*pol_id),
				   xfrm_attr, tb) != MNL_CB_OK) {
			dp_test_assert_internal(false);
		}
		break;

	case XFRM_MSG_POLEXPIRE:
		pol_expire = mnl_nlmsg_get_payload(nlh);
		pol_info = &pol_expire->pol;

		if (mnl_attr_parse(nlh, sizeof(*pol_expire),
				   xfrm_attr, tb) != MNL_CB_OK)
			dp_test_assert_internal(false);
		break;

	case XFRM_MSG_NEWPOLICY: /* fall thru */
	case XFRM_MSG_UPDPOLICY:
		pol_info = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*pol_info),
				   xfrm_attr, tb) != MNL_CB_OK)
			dp_test_assert_internal(false);
		break;

	default:
		dp_test_assert_internal(false);
	}

	*info = pol_info;
	*id = pol_id;
}

static int xfrm_policy_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct xfrm_userpolicy_id *usr_id;
	const struct xfrm_userpolicy_info *usr_policy;
	const struct xfrm_selector *sel;
	__u8 dir;
	char srcip_str[INET6_ADDRSTRLEN];
	char dstip_str[INET6_ADDRSTRLEN];

	xfrm_nl_policy_decode(nlh, &usr_policy, &usr_id);
	if (!usr_policy && !usr_id)
		return -1;

	if (usr_policy) {
		sel = &usr_policy->sel;
		dir = usr_policy->dir;
	} else {
		sel = &usr_id->sel;
		dir = usr_id->dir;
	}

	inet_ntop(sel->family, &sel->saddr, srcip_str, sizeof(srcip_str));
	inet_ntop(sel->family, &sel->daddr, dstip_str, sizeof(dstip_str));

	return snprintf(buf, len-1,
			"xfrm dir %d s_ip:%s d_ip:%s s_port %-5d d_port %-5d proto %-3d",
			dir,
			srcip_str,
			dstip_str,
			sel->sport, sel->dport,
			sel->proto);
}

static const char *xfrm_tunnel_mode_str(uint8_t mode)
{
	switch (mode) {
	case XFRM_MODE_TRANSPORT:
		return "transport";
	case XFRM_MODE_TUNNEL:
		return "tunnel";
	default:
		return "unknown";
	}
}

static void get_mark_value_and_mask(struct nlattr **tb,
				    uint32_t *mark_value, uint32_t *mark_mask)
{
	struct xfrm_mark *xmark;

	if (tb[XFRMA_MARK]) {
		xmark = mnl_attr_get_payload(tb[XFRMA_MARK]);
		*mark_value = xmark->v;
		*mark_mask = xmark->m;
	} else {
		*mark_value = 0;
		*mark_mask = 0;
	}
}

static int xfrm_sa_topic(const struct nlmsghdr *nlh, char *buf, size_t len)
{
	const struct xfrm_usersa_info *sa_info;
	const struct xfrm_user_expire *expire;
	const struct xfrm_usersa_id *sa_id;
	uint32_t mark_value, mark_mask;
	const size_t payload_size = mnl_nlmsg_get_payload_len(nlh);
	struct nlattr *tb[XFRMA_MAX+1] = { NULL };
	char dstip_str[INET6_ADDRSTRLEN];
	char srcip_str[INET6_ADDRSTRLEN];

	switch (nlh->nlmsg_type) {
	case XFRM_MSG_NEWSA:
	case XFRM_MSG_UPDSA:
		dp_test_assert_internal(payload_size >= sizeof(*sa_info));
		sa_info = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*sa_info),
				   xfrm_attr, tb) != MNL_CB_OK)
			dp_test_assert_internal(false);
		inet_ntop(sa_info->family, &sa_info->saddr,
			  srcip_str, sizeof(srcip_str));
		get_mark_value_and_mask(tb, &mark_value, &mark_mask);
		return snprintf(buf, len - 1,
				"saxfrm %s SPI %.8x src %s mode %s Mark 0x%x Mask 0x%x",
				(nlh->nlmsg_type == XFRM_MSG_NEWSA) ? "NEWSA" : "UPDSA",
				sa_info->id.spi, srcip_str,
				xfrm_tunnel_mode_str(sa_info->mode),
				mark_value, mark_mask);
	case XFRM_MSG_DELSA:
		dp_test_assert_internal(payload_size >= sizeof(*sa_id));
		sa_id = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*sa_id),
				   xfrm_attr, tb)  != MNL_CB_OK)
			dp_test_assert_internal(false);
		get_mark_value_and_mask(tb, &mark_value, &mark_mask);
		inet_ntop(sa_id->family, &sa_id->daddr,
			  dstip_str, sizeof(dstip_str));
		return snprintf(buf, len - 1,
				"saxfrm DEL SA dst %s SPI %.8x Mark 0x%x Mask 0x%x",
				dstip_str, sa_id->spi,
				mark_value, mark_mask);
	case XFRM_MSG_EXPIRE:
		dp_test_assert_internal(payload_size >= sizeof(*expire));
		expire = mnl_nlmsg_get_payload(nlh);
		if (mnl_attr_parse(nlh, sizeof(*expire),
				   xfrm_attr, tb) != MNL_CB_OK)
			dp_test_assert_internal(false);
		get_mark_value_and_mask(tb, &mark_value, &mark_mask);
		inet_ntop(expire->state.family, &expire->state.saddr,
			  srcip_str, sizeof(srcip_str));
		return snprintf(buf, len - 1,
				"saxfrm EXPIRE SPI %.8x src %s mode %s Mark 0x%x Mask 0x%x",
				expire->state.id.spi, srcip_str,
				xfrm_tunnel_mode_str(expire->state.mode),
				mark_value, mark_mask);
	default:
		dp_test_assert_internal(false);
		return -1; /* Boo, something went wrong */
	}
}

static int
nl_generate_topic_xfrm(const struct nlmsghdr *nlh, char *buf, size_t buflen)
{
	switch (nlh->nlmsg_type) {

	case XFRM_MSG_NEWPOLICY: /* fall thru */
	case XFRM_MSG_DELPOLICY: /* fall thru */
	case XFRM_MSG_UPDPOLICY: /* fall thru */
		return xfrm_policy_topic(nlh, buf, buflen);

	case XFRM_MSG_NEWSA: /* fall through */
	case XFRM_MSG_UPDSA: /* fall through */
	case XFRM_MSG_DELSA: /* fall through */
	case XFRM_MSG_EXPIRE:
		return xfrm_sa_topic(nlh, buf, buflen);

	default:
		dp_test_assert_internal(false);
	}
	return -1;
}

/*
 * Each netlink xfrm messages is required to have a unique
 * sequence number that is returned back to the xfrm source
 * via an ack message to indicate the successful processing
 * of the message in the dataplane.
 */
uint32_t xfrm_seq;

void _dp_test_netlink_xfrm_policy(uint16_t nlmsg_type,
				  const struct xfrm_selector *sel,
				  const xfrm_address_t *dst,
				  int dst_family,
				  uint8_t dir,
				  uint32_t priority,
				  uint32_t reqid,
				  /* mark_val = 0 => no mark */
				  uint32_t mark_val,
				  uint8_t action,
				  vrfid_t vrfid,
				  bool passthrough,
				  uint32_t rule_no,
				  const char *file,
				  int line)
{
	struct xfrm_userpolicy_info *userpolicy_info_p = NULL;
	struct xfrm_userpolicy_id *userpolicy_id;
	struct nlmsghdr *nlh;
	char *buf = malloc(MNL_SOCKET_BUFFER_SIZE);

	memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = NLM_F_ACK;
	nlh->nlmsg_seq = ++xfrm_seq;

	switch (nlmsg_type) {
	case XFRM_MSG_NEWPOLICY:
	case XFRM_MSG_UPDPOLICY:
		userpolicy_info_p = mnl_nlmsg_put_extra_header(nlh, sizeof(*userpolicy_info_p));
		userpolicy_info_p->priority = priority;
		userpolicy_info_p->dir = dir;
		userpolicy_info_p->index = rule_no;
		userpolicy_info_p->action = action;
		memcpy(&userpolicy_info_p->sel, sel, sizeof(userpolicy_info_p->sel));
		break;
	case XFRM_MSG_DELPOLICY:
		userpolicy_id = mnl_nlmsg_put_extra_header(nlh, sizeof(*userpolicy_id));

		userpolicy_id->dir = dir;
		userpolicy_id->index = rule_no;
		memcpy(&userpolicy_id->sel, sel, sizeof(userpolicy_id->sel));
		break;
	default:
		/* no support for other messages */
		dp_test_assert_internal(false);
	}

	if (mark_val) {
		struct xfrm_mark mark = {
			.v = htonl(mark_val),
			.m = 0xffffffff};
		mnl_attr_put(nlh, XFRMA_MARK, sizeof(struct xfrm_mark), &mark);
	}

	struct xfrm_user_tmpl pol_template;

	memset(&pol_template, 0, sizeof(pol_template));
	mempcpy(&pol_template.id.daddr, dst, sizeof(pol_template.id.daddr));
	pol_template.family = dst_family;
	pol_template.mode = XFRM_MODE_TUNNEL;
	pol_template.id.proto = IPPROTO_ESP;
	pol_template.reqid = reqid;

	if ((dir != XFRM_POLICY_IN) || !passthrough) {
		mnl_attr_put(nlh, XFRMA_TMPL, sizeof(struct xfrm_user_tmpl),
		     &pol_template);
	}

	if (vrfid != VRF_DEFAULT_ID && vrfid != VRF_UPLINK_ID) {
		switch (nlmsg_type) {
		case XFRM_MSG_NEWPOLICY:
		case XFRM_MSG_UPDPOLICY:
			userpolicy_info_p->sel.ifindex =
				_dp_test_translate_vrf_id(vrfid, file, line);
			break;
		case XFRM_MSG_DELPOLICY:
			userpolicy_id->sel.ifindex =
				_dp_test_translate_vrf_id(vrfid, file, line);
			break;
		}
	}

	char topic[DP_TEST_TMP_BUF];

	if (nl_generate_topic_xfrm(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();
	/* Signal an end of batch. This is a single msg batch */
	nl_propagate_xfrm(xfrm_server_push_sock, nlh, nlh->nlmsg_len, "END");
}

void _dp_test_netlink_xfrm_newsa(uint32_t spi, /* Network byte order */
				 const char *dst,
				 const char *src,
				 uint16_t family,
				 uint8_t mode,
				 uint32_t reqid,
				 const struct xfrm_algo *crypto_algo,
				 const struct xfrm_algo_auth *auth_algo,
				 const struct xfrm_algo_auth *auth_algo_trunc,
				 const struct xfrm_algo_aead *aead_algo,
				 /* optional args, not sent if NULL/0 */
				 uint32_t flags,
				 uint32_t extra_flags,
				 const struct xfrm_encap_tmpl *encap_tmpl,
				 uint32_t mark_val,
				 vrfid_t vrfid,
				 const char *file,
				 const char *func,
				 int line)
{

	char topic[DP_TEST_TMP_BUF];
	unsigned int key_len;
	struct nlmsghdr *nlh;
	struct xfrm_usersa_info *sa_info;
	char *buf = malloc(MNL_SOCKET_BUFFER_SIZE);

	memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_ACK;
	nlh->nlmsg_seq = ++xfrm_seq;

	sa_info = mnl_nlmsg_put_extra_header(nlh, sizeof(*sa_info));
	if (dp_test_setup_xfrm_usersa_info(sa_info, dst, src,
					   spi, family, mode, reqid, flags))
		dp_test_abort_internal();

	if (crypto_algo) {
		key_len = crypto_algo->alg_key_len / 8;
		mnl_attr_put(nlh, XFRMA_ALG_CRYPT,
			     sizeof(*crypto_algo) + key_len, crypto_algo);
	}
	if (auth_algo) {
		key_len = auth_algo->alg_key_len / 8;
		mnl_attr_put(nlh, XFRMA_ALG_AUTH,
			     sizeof(*auth_algo) + key_len, auth_algo);
	}
	if (auth_algo_trunc) {
		key_len = auth_algo_trunc->alg_key_len / 8;
		mnl_attr_put(nlh, XFRMA_ALG_AUTH_TRUNC,
			     sizeof(*auth_algo_trunc) + key_len,
			     auth_algo_trunc);
	}
	if (aead_algo) {
		key_len = aead_algo->alg_key_len / 8;
		mnl_attr_put(nlh, XFRMA_ALG_AEAD,
			     sizeof(*aead_algo) + key_len,
			     aead_algo);
	}

	if (extra_flags)
		mnl_attr_put_u32(nlh, XFRMA_SA_EXTRA_FLAGS, extra_flags);
	if (encap_tmpl)
		mnl_attr_put(nlh, XFRMA_ENCAP, sizeof(*encap_tmpl), encap_tmpl);
	if (mark_val) {
		struct xfrm_mark mark = {
			.v = htonl(mark_val),
			.m = 0xffffffff};
		mnl_attr_put(nlh, XFRMA_MARK, sizeof(struct xfrm_mark), &mark);
	}

	if (vrfid != VRF_DEFAULT_ID && vrfid != VRF_UPLINK_ID) {
		sa_info->sel.ifindex =
			_dp_test_translate_vrf_id(vrfid, file, line);
	}

	if (nl_generate_topic_xfrm(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();
	/* Signal an end of batch. This is a single msg batch */
	nl_propagate_xfrm(xfrm_server_push_sock, nlh, nlh->nlmsg_len, "END");
}

void dp_test_netlink_xfrm_delsa(uint32_t spi, /* Network byte order */
				const char *dst,
				const char *src,
				uint16_t family,
				uint8_t mode,
				uint32_t reqid,
				vrfid_t vrfid)
{
	struct xfrm_usersa_info usersa_info;
	struct xfrm_usersa_id *usersa_id;
	char topic[DP_TEST_TMP_BUF];
	struct nlmsghdr *nlh;
	xfrm_address_t daddr;
	char *buf = malloc(MNL_SOCKET_BUFFER_SIZE);

	memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_ACK;
	nlh->nlmsg_seq = ++xfrm_seq;

	usersa_id = mnl_nlmsg_put_extra_header(nlh, sizeof(*usersa_id));
	usersa_id->family = family;

	if (dp_test_prefix_str_to_xfrm_addr(dst, &daddr, NULL, family))
		dp_test_abort_internal();
	memcpy(&usersa_id->daddr, &daddr, sizeof(usersa_id->daddr));
	usersa_id->spi = spi;

	if (dp_test_setup_xfrm_usersa_info(&usersa_info, dst, src,
					   spi, family, mode, reqid, 0))
		dp_test_abort_internal();

	if (vrfid != VRF_DEFAULT_ID && vrfid != VRF_UPLINK_ID) {
		usersa_info.sel.ifindex = dp_test_translate_vrf_id(vrfid);
	}

	mnl_attr_put(nlh, XFRMA_SA, sizeof(usersa_info), &usersa_info);

	if (nl_generate_topic_xfrm(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();
	/* Signal an end of batch. This is a single msg batch */
	nl_propagate_xfrm(xfrm_server_push_sock, nlh, nlh->nlmsg_len, "END");
}

void dp_test_netlink_xfrm_getsa(uint32_t spi, /* Network byte order */
				const char *dst,
				const char *src,
				uint16_t family,
				uint8_t mode,
				uint32_t reqid,
				vrfid_t vrfid)
{
	struct xfrm_usersa_id *usersa_id;
	struct nlmsghdr *nlh;
	xfrm_address_t daddr;
	char *buf = malloc(MNL_SOCKET_BUFFER_SIZE);
	uint32_t ifindex, mark_val = 1;

	memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_GETSA;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq = ++xfrm_seq;

	usersa_id = mnl_nlmsg_put_extra_header(nlh, sizeof(*usersa_id));
	usersa_id->family = family;

	if (dp_test_prefix_str_to_xfrm_addr(dst, &daddr, NULL, family))
		dp_test_abort_internal();
	memcpy(&usersa_id->daddr, &daddr, sizeof(usersa_id->daddr));
	usersa_id->spi = spi;

	if (mark_val) {
		struct xfrm_mark mark = {
			.v = htonl(mark_val),
			.m = 0xffffffff};
		mnl_attr_put(nlh, XFRMA_MARK, sizeof(struct xfrm_mark), &mark);
	}

	if (vrfid != VRF_DEFAULT_ID && vrfid != VRF_UPLINK_ID)
		ifindex = dp_test_translate_vrf_id(vrfid);
	else
		ifindex = 0;

	mnl_attr_put(nlh, XFRMA_IF_ID, sizeof(ifindex), &ifindex);

	nl_propagate_xfrm(xfrm_server_push_sock, nlh, nlh->nlmsg_len, "STATS");
}

void dp_test_netlink_xfrm_expire(uint32_t spi, /* Network byte order */
				 const char *dst,
				 const char *src,
				 uint16_t family,
				 uint8_t mode,
				 uint32_t reqid,
				 bool expire_hard,
				 vrfid_t vrfid)
{
	struct xfrm_user_expire *expire;
	char topic[DP_TEST_TMP_BUF];
	struct nlmsghdr *nlh;
	char *buf = malloc(MNL_SOCKET_BUFFER_SIZE);

	memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = XFRM_MSG_EXPIRE;
	nlh->nlmsg_flags = NLM_F_ACK;
	nlh->nlmsg_seq = ++xfrm_seq;

	expire = mnl_nlmsg_put_extra_header(nlh, sizeof(*expire));
	expire->hard = expire_hard;

	if (dp_test_setup_xfrm_usersa_info(&expire->state, dst, src,
					   spi, family, mode, reqid, 0))
		dp_test_abort_internal();

	if (vrfid != VRF_DEFAULT_ID && vrfid != VRF_UPLINK_ID)
		expire->state.sel.ifindex = dp_test_translate_vrf_id(vrfid);

	if (nl_generate_topic_xfrm(nlh, topic, sizeof(topic)) < 0)
		dp_test_abort_internal();
	/* Signal an end of batch. This is a single msg batch */
	nl_propagate_xfrm(xfrm_server_push_sock, nlh, nlh->nlmsg_len, "END");
}

void
_dp_test_netlink_add_vrf_incmpl(uint32_t vrf_id, uint32_t expected_ref_cnt,
				const char *file, int line)
{
	char vrf_name[IFNAMSIZ + 1];
	uint32_t tableid;
	bool ret;

	ret = dp_test_upstream_vrf_add_db(vrf_id, vrf_name, &tableid);
	_dp_test_fail_unless(ret, file, line, "maximum vrf limit reached\n");
	dp_test_intf_virt_add(vrf_name);
}

void
_dp_test_netlink_add_vrf(uint32_t vrf_id, uint32_t expected_ref_cnt,
			 const char *file, int line)
{
	char vrf_name[IFNAMSIZ + 1];
	uint32_t tableid;
	bool ret;

	ret = dp_test_upstream_vrf_add_db(vrf_id, vrf_name, &tableid);
	_dp_test_fail_unless(ret, file, line, "maximum vrf limit reached\n");
	_dp_test_intf_vrf_if_create(vrf_name, vrf_id, tableid, file, line);
}

void
_dp_test_netlink_del_vrf(uint32_t vrf_id, uint32_t expected_ref_cnt,
			 const char *file, int line)
{
	char vrf_name[IFNAMSIZ];
	uint32_t tableid = 0;
	bool ret;

	ret = dp_test_upstream_vrf_del_db(vrf_id, vrf_name, &tableid);
	_dp_test_fail_unless(ret, file, line,
			     "unable to find vrf interface for %u\n",
			     vrf_id);
	_dp_test_intf_vrf_if_delete(vrf_name, vrf_id, tableid, file, line);
}

/*
 * Adds L3 address.  Adds route for the attached network
 */
void
_dp_test_nl_add_ip_addr_and_connected(const char *intf, const char *addr,
				      vrfid_t vrf_id, const char *file,
				      const char *func, int line)
{
	char netstr[INET6_ADDRSTRLEN];

	if (vrf_id != VRF_DEFAULT_ID && vrf_id != VRF_UPLINK_ID)
		_dp_test_netlink_set_interface_vrf(intf, vrf_id, true,
						   file, func, line);

	dp_test_ipstr_to_netstr(addr, netstr, sizeof(netstr));
	_dp_test_netlink_add_ip_address(intf, addr, vrf_id, true,
					file, func, line);
	_dp_test_fail_unless(RT_SCOPE_LINK == 253, file, line,
			    "link scope is %d instead of 253", RT_SCOPE_LINK);
	_dp_test_netlink_add_route_fmt(true, false, file, func, line,
				       "vrf:%d %s scope:253 nh int:%s",
				       vrf_id, netstr, intf);
}

/*
 * Remove interface address and attached network route
 */
void
_dp_test_nl_del_ip_addr_and_connected(const char *intf, const char *addr,
				      vrfid_t vrf_id, const char *file,
				      const char *func, int line)
{
	char netstr[INET6_ADDRSTRLEN];

	dp_test_ipstr_to_netstr(addr, netstr, sizeof(netstr));
	_dp_test_fail_unless(RT_SCOPE_LINK == 253, file, line,
			     "link scope is %d instead of 253", RT_SCOPE_LINK);
	_dp_test_netlink_del_route_fmt(true, file, func, line,
				       "vrf:%d %s scope:253 nh int:%s",
				       vrf_id, netstr, intf);
	_dp_test_netlink_del_ip_address(intf, addr, vrf_id, true,
					file, func, line);
	if (vrf_id != VRF_DEFAULT_ID && vrf_id != VRF_UPLINK_ID)
		_dp_test_netlink_set_interface_vrf(intf, VRF_DEFAULT_ID, true,
						   file, func, line);
}
