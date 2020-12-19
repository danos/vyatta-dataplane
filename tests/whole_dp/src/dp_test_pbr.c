/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * PBR test cases
 */
#include <errno.h>
#include <time.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>
#include "ip_funcs.h"
#include "ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_console.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"

DP_DECL_TEST_SUITE(pbr_suite);

/*
 * The test topology is a UUT with 3 interfaces - IN, OUT and TEST. A
 * route is established so that normally packets flow from IN to OUT. To
 * exercise PBR, a policy is then imposed on the IN interface so
 * as to redirect selected packets to the TEST interface.
 */

/*
 *  Test PBR mapping policy tableids to kernel tableids.
 */
#define POLICY_PBR_TABLEID_1 1
#define POLICY_PBR_TABLEID_2 128
#define POLICY_NON_PBR_TABLEID 129
#define MAPPED_TABLEID_1 261
#define MAPPED_TABLEID_2 262
#define TEST_TABLEID 4
#define TEST_VRF 50

#define PBR_IPV4 "inet"
#define PBR_IPV6 "inet6"
#define PBR_DROP "action=drop"
#define PBR_ACCEPT "action=accept"
#define PBR_DROP_SHOW "block"
#define PBR_ACCEPT_SHOW "pass"

#define PBR_IN_IFN "dp1T0"
#define PBR_IN_IFN_ADDR4 "1.1.1.1/24"
#define PBR_IN_IFN_ADDR6 "2001:1:1::1/64"

#define PBR_OUT_IFN "dp3T1"
#define PBR_OUT_IFN_ADDR4 "2.2.2.2/24"
#define PBR_OUT_IFN_ADDR6 "2002:2:2::2/64"
#define PBR_OUT_NH4 "2.2.2.1"
#define PBR_OUT_NH6 "2002:2:2::1"
#define PBR_OUT_NH4_MAC "aa:bb:cc:dd:ee:20"
#define PBR_OUT_NH6_MAC "aa:bb:cc:dd:ee:21"

#define PBR_TEST_IFN "dp4T1"
#define PBR_TEST_IFN_ADDR4 "3.3.3.3/24"
#define PBR_TEST_IFN_ADDR6 "2003:3:3::3/64"
#define PBR_TEST_NH4 "3.3.3.1"
#define PBR_TEST_NH6 "2003:3:3::1"
#define PBR_TEST_NH4_MAC "aa:bb:cc:dd:ee:30"
#define PBR_TEST_NH6_MAC "aa:bb:cc:dd:ee:31"

#define PBR_TEST_4SRC "10.73.1.1"
#define PBR_TEST_4DST "10.73.2.1"
#define PBR_TEST_6SRC "2010:73:1::1"
#define PBR_TEST_6DST "2010:73:2::1"
#define PBR_TEST_4DST_2 "10.73.2.2"
#define PBR_TEST_6DST_2 "2010:73:2::2"

/*
 * By default test packets are switched from IN to OUT
 */
static const char *dp_test_default_route_ipv4 =
	"10.73.2.0/24 nh " PBR_OUT_NH4 " int:" PBR_OUT_IFN;
static const char *dp_test_default_route_ipv6 =
	"2010:73:2::/64 nh " PBR_OUT_NH6 " int:" PBR_OUT_IFN;

static bool pbr_debug;

/*
 * Deleting non-existent npf groups will fail, so we need to set fail_on_err
 * to false when called from pbr_del_policy.
 */
static void
pbr_request(const char *cmd, bool print, bool fail_on_err,
	    const char *file, int line)
{
	bool err;

	free(dp_test_console_request_w_err(cmd, &err, print));
	if (fail_on_err)
		_dp_test_fail_unless(!err, file, line, "Failed: %s", cmd);
}

#define pbr_del_policy(intf, name)		\
	_pbr_del_policy(intf, name, __FILE__, __LINE__)

static void
_pbr_del_policy(const char *intf, const char *name, const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	char ifname[IFNAMSIZ];

	dp_test_intf_real(intf, ifname);

	/*
	 * delete interface dataplane <intf> policy route pbr <name>
	 */
	snprintf(cmd, sizeof(cmd),
		 "npf-ut detach interface:%s pbr %s",
		 ifname, name);
	pbr_request(cmd, pbr_debug, false, file, line);

	/*
	 * delete policy route pbr <name>
	 */
	snprintf(cmd, sizeof(cmd),
		 "npf-ut delete %s",
		 name);
	pbr_request(cmd, pbr_debug, false, file, line);

	dp_test_console_request_reply("npf-ut commit", false);
	/*
	 * show policy route
	 */
	dp_test_check_state_show("npf-op show all: pbr", "", pbr_debug);
	dp_test_intf_name_del_state(ifname, DP_TEST_INTF_STATE_PBR);
}

#define pbr_set_policy_ip(intf, name, rule, action, action_show, af, src, dst, \
			  tableid) \
	_pbr_set_policy_ip(intf, name, rule, action, action_show, af, src, \
			   dst, tableid, VRF_INVALID_ID, __FILE__, __LINE__)

#define pbr_set_policy_ip_vrf(intf, name, rule, action, action_show, af, src, \
			      dst, vrf, tableid)			\
	_pbr_set_policy_ip(intf, name, rule, action, action_show, af, src, \
			   dst, tableid, vrf, __FILE__, __LINE__)

static void
_pbr_set_policy_ip(const char *intf, const char *name, int rule,
		   const char *action, const char *action_show, const char *af,
		   const char *src, const char *dst,
		   uint32_t tableid, uint32_t vrf_id,
		   const char *file, int line)
{
	char cmd[TEST_MAX_CMD_LEN];
	char ifname[IFNAMSIZ];
	char *group_name = strdupa(name);
	char *colon_in_name = strchr(group_name, ':');
	char tag[10];
	char vrf_rproc[sizeof("rproc=setvrf(4294967295)")];
	char tag_rproc[sizeof("handle=tag(4294967295)")];

	if (colon_in_name)
		group_name = colon_in_name + 1;

	dp_test_intf_real(intf, ifname);

	if (vrf_id) {
		vrf_id = dp_test_translate_vrf_id(vrf_id);
		snprintf(vrf_rproc, sizeof(vrf_rproc),
			 " rproc=setvrf(%u)", vrf_id);
	}

	if (tableid != RT_TABLE_UNSPEC)
		snprintf(tag_rproc, sizeof(tag_rproc),
			 " handle=tag(%u)", tableid);

	/*
	 * set policy route pbr <name>
	 *     rule <rule>
	 *          action <action>
	 *          address-family <af>
	 *          source address <src>
	 *          destination address <dst>
	 *          table <tableid>
	 *          routing-instance <vrf>
	 */
	snprintf(tag, sizeof(tag), "%u", tableid);
	snprintf(cmd, sizeof(cmd),
		 "npf-ut add %s %d %s family=%s %s%s %s%s %s%s",
		 name, rule, action, af,
		 src == NULL ? "" : "src-addr=", src == NULL ? "" : src,
		 dst == NULL ? "" : "dst-addr=", dst == NULL ? "" : dst,
		 tableid != RT_TABLE_UNSPEC ? tag_rproc : "",
		 vrf_id ? vrf_rproc : "");
	pbr_request(cmd, pbr_debug, true, file, line);

	/*
	 * set interface dataplane <intf> policy route pbr <name>
	 */
	snprintf(cmd, sizeof(cmd), "npf-ut attach interface:%s pbr %s",
		 ifname, name);
	pbr_request(cmd, pbr_debug, true, file, line);

	dp_test_console_request_reply("npf-ut commit", false);

	char match[TEST_MAX_CMD_LEN];
	size_t len = 0;

	len += snprintf(match + len, sizeof(match) - len, "family %s ", af);

	if (src != NULL)
		len += snprintf(match + len, sizeof(match) - len,
				"from %s ", src);
	if (dst != NULL)
		len += snprintf(match + len, sizeof(match) - len,
				"to %s ", dst);
	(void) len;

	if (vrf_id) {
		snprintf(vrf_rproc, sizeof(vrf_rproc),
			 "setvrf(%u)", vrf_id);
	}

	if (tableid != RT_TABLE_UNSPEC)
		snprintf(tag_rproc, sizeof(tag_rproc),
			 "tag(%u)", tableid);

	json_object *expected;

	expected = dp_test_json_create(
	"{ \"config\": "
	"  [ { \"attach_type\": \"interface\", "
	"      \"attach_point\": \"%s\", \"rulesets\":"
	"      [ { \"ruleset_type\": \"pbr\", \"groups\": [ "
	"      { \"class\": \"pbr\", "
	"        \"name\": \"%s\", "
	"        \"direction\": \"in\", "
	"          \"rules\": { \"%u\": "
	"          { \"bytes\": 0, \"packets\": 0, "
	"            \"action\": \"%s \", \"match\": \"%s\", "
	"            \"operation\": \"%s%s%s%s\" "
	"} } } ] } ] } ] }",
	ifname, group_name, rule, action_show, match,
	(tableid != RT_TABLE_UNSPEC || vrf_id) ? "apply " : "",
	vrf_id ? vrf_rproc : "",
	(tableid != RT_TABLE_UNSPEC && vrf_id) ? ", " : "",
	tableid != RT_TABLE_UNSPEC ? tag_rproc : "");

	dp_test_check_json_state("npf-op show all: pbr", expected,
				 DP_TEST_JSON_CHECK_SUBSET,
				 false);
	json_object_put(expected);
}

static struct dp_test_expected *
pbr_create_pak(const char *src, const char *dst, const char *oif,
	       uint16_t type, const char *nh_mac, struct rte_mbuf **pakp,
	       int lineno)
{
	struct rte_mbuf *pak;
	struct dp_test_expected *exp;
	int len = 22;

	if (type == RTE_ETHER_TYPE_IPV4)
		pak = dp_test_create_ipv4_pak(src, dst, 1, &len);
	else
		pak = dp_test_create_ipv6_pak(src, dst, 1, &len);

	_dp_test_fail_unless(pak != NULL, __FILE__, lineno,
			     "failed to create pak");
	if (pak)
		dp_test_pktmbuf_eth_init(pak,
					 dp_test_intf_name2mac_str(PBR_IN_IFN),
					 NULL, type);

	exp = dp_test_exp_create(pak);
	_dp_test_fail_unless(exp != NULL, __FILE__, lineno,
			     "failed to create exp");
	dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp), nh_mac,
				 dp_test_intf_name2mac_str(oif), type);
	if (type == RTE_ETHER_TYPE_IPV4)
		dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	else
		dp_test_ipv6_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_exp_set_oif_name(exp, oif);
	*pakp = pak;
	return exp;
}

static void
pbr_del_route(int tableid, const char *pfx, const char *nh_addr,
	      const char *nh_ifn, const char *nh_mac)
{
	char route[TEST_MAX_CMD_LEN];

	dp_test_netlink_del_neigh(nh_ifn, nh_addr, nh_mac);
	snprintf(route, sizeof(route), "tbl:%d %s nh %s int:%s", tableid, pfx,
		 nh_addr, nh_ifn);
	dp_test_netlink_del_route(route);
}

static void
pbr_set_route(int tableid, const char *pfx, const char *nh_addr,
	      const char *nh_ifn, const char *nh_mac)
{
	char route[TEST_MAX_CMD_LEN];

	/*
	 * set protocols static table <tableid>
	 *                      route <pfx>
	 *                      next-hop <nh>
	 *                      interface <ifn>
	 * set protocols static arp <nh>
	 *                      interface <ifn>
	 *                      hwaddr <mac>
	 */
	snprintf(route, sizeof(route), "tbl:%d %s nh %s int:%s", tableid, pfx,
		 nh_addr, nh_ifn);
	dp_test_netlink_add_route(route);
	dp_test_netlink_add_neigh(nh_ifn, nh_addr, nh_mac);
}

static void
pbr_teardown(void)
{
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");
	dp_test_netlink_del_route(dp_test_default_route_ipv4);
	dp_test_netlink_del_neigh(PBR_OUT_IFN, PBR_OUT_NH4, PBR_OUT_NH4_MAC);
	dp_test_nl_del_ip_addr_and_connected(PBR_IN_IFN, PBR_IN_IFN_ADDR4);
	dp_test_nl_del_ip_addr_and_connected(PBR_OUT_IFN, PBR_OUT_IFN_ADDR4);
	dp_test_nl_del_ip_addr_and_connected(PBR_TEST_IFN, PBR_TEST_IFN_ADDR4);

	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
	dp_test_netlink_del_route(dp_test_default_route_ipv6);
	dp_test_netlink_del_neigh(PBR_OUT_IFN, PBR_OUT_NH6, PBR_OUT_NH6_MAC);
	dp_test_nl_del_ip_addr_and_connected(PBR_IN_IFN, PBR_IN_IFN_ADDR6);
	dp_test_nl_del_ip_addr_and_connected(PBR_OUT_IFN, PBR_OUT_IFN_ADDR6);
	dp_test_nl_del_ip_addr_and_connected(PBR_TEST_IFN, PBR_TEST_IFN_ADDR6);
}

static void
pbr_setup(void)
{
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");
	dp_test_nl_add_ip_addr_and_connected(PBR_IN_IFN, PBR_IN_IFN_ADDR4);
	dp_test_nl_add_ip_addr_and_connected(PBR_OUT_IFN, PBR_OUT_IFN_ADDR4);
	dp_test_nl_add_ip_addr_and_connected(PBR_TEST_IFN, PBR_TEST_IFN_ADDR4);
	dp_test_netlink_add_route(dp_test_default_route_ipv4);
	dp_test_netlink_add_neigh(PBR_OUT_IFN, PBR_OUT_NH4, PBR_OUT_NH4_MAC);

	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
	dp_test_nl_add_ip_addr_and_connected(PBR_IN_IFN, PBR_IN_IFN_ADDR6);
	dp_test_nl_add_ip_addr_and_connected(PBR_OUT_IFN, PBR_OUT_IFN_ADDR6);
	dp_test_nl_add_ip_addr_and_connected(PBR_TEST_IFN, PBR_TEST_IFN_ADDR6);
	dp_test_netlink_add_route(dp_test_default_route_ipv6);
	dp_test_netlink_add_neigh(PBR_OUT_IFN, PBR_OUT_NH6, PBR_OUT_NH6_MAC);
}

#define PBR_V4PAK(s, d, oif, nh, pp) \
	pbr_create_pak(s, d, oif, RTE_ETHER_TYPE_IPV4, nh, pp, __LINE__)
#define PBR_V6PAK(s, d, oif, nh, pp) \
	pbr_create_pak(s, d, oif, RTE_ETHER_TYPE_IPV6, nh, pp, __LINE__)

DP_DECL_TEST_CASE(pbr_suite, pbr, pbr_setup, pbr_teardown);

DP_START_TEST(pbr, configuration)
{
	/*
	 * Double check that the destination address is greater than the
	 * source address (see above).
	 */
	struct in_addr s4, d4;
	struct in6_addr s6, d6;

	dp_test_assert_internal(inet_pton(AF_INET, PBR_TEST_4SRC, &s4) == 1);
	dp_test_assert_internal(inet_pton(AF_INET, PBR_TEST_4DST, &d4) == 1);
	dp_test_assert_internal(d4.s_addr > s4.s_addr);
	dp_test_assert_internal(inet_pton(AF_INET6, PBR_TEST_6SRC, &s6) == 1);
	dp_test_assert_internal(inet_pton(AF_INET6, PBR_TEST_6DST, &d6) == 1);
	dp_test_assert_internal(memcmp(&d6, &s6, 16) > 0);

	/*
	 * Ensure we can add a policy to accept IPv4 packets. Then turn
	 * that into a block policy.
	 */
	int tableid4 = 4;
	const char *dstpfx4 = "10.73.2.0/24";

	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr4", 10, PBR_ACCEPT,
			  PBR_ACCEPT_SHOW, PBR_IPV4, NULL, NULL, tableid4);
	pbr_set_route(tableid4, dstpfx4, PBR_TEST_NH4, PBR_TEST_IFN,
		      PBR_TEST_NH4_MAC);
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr4", 10, PBR_DROP, PBR_DROP_SHOW,
			  PBR_IPV4, NULL, NULL, tableid4);
	pbr_del_route(tableid4, dstpfx4, PBR_TEST_NH4, PBR_TEST_IFN,
		      PBR_TEST_NH4_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");

	/*
	 * Do the same again for IPv6
	 */
	int tableid6 = 6;
	const char *dstpfx6 = "2010:73:2::0/64";

	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr6", 20, PBR_ACCEPT,
			  PBR_ACCEPT_SHOW, PBR_IPV6, NULL, NULL, tableid6);
	pbr_set_route(tableid6, dstpfx6, PBR_TEST_NH6, PBR_TEST_IFN,
		      PBR_TEST_NH6_MAC);
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr6", 20, PBR_DROP, PBR_DROP_SHOW,
			  PBR_IPV6, NULL, NULL, tableid6);
	pbr_del_route(tableid6, dstpfx6, PBR_TEST_NH6, PBR_TEST_IFN,
		      PBR_TEST_NH6_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
} DP_END_TEST;

DP_DECL_TEST_CASE(pbr_suite, pbr_fwd, pbr_setup, pbr_teardown);

DP_START_TEST(pbr_fwd, v4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int tableid = 4;
	const char *dstpfx = PBR_TEST_4DST "/32";

	/*
	 * Generate a packet and ensure that it is forwarded via the
	 * default output interface.
	 */
	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_OUT_IFN, PBR_OUT_NH4_MAC,
			&test_pak);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	/*
	 * Now apply a PBR policy to route the same packet out the test
	 * interface.
	 */
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr4", 10, PBR_ACCEPT,
			  PBR_ACCEPT_SHOW, PBR_IPV4, NULL, dstpfx, tableid);
	pbr_set_route(tableid, dstpfx, PBR_TEST_NH4, PBR_TEST_IFN,
		      PBR_TEST_NH4_MAC);

	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_TEST_IFN, PBR_TEST_NH4_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	pbr_del_route(tableid, dstpfx, PBR_TEST_NH4, PBR_TEST_IFN,
		      PBR_TEST_NH4_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");
} DP_END_TEST;

DP_START_TEST(pbr_fwd, v6)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int tableid = 6;
	const char *dstpfx = PBR_TEST_6DST "/128";

	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_OUT_IFN, PBR_OUT_NH6_MAC,
			&test_pak);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr6", 10, PBR_ACCEPT,
			  PBR_ACCEPT_SHOW, PBR_IPV6, NULL, dstpfx, tableid);
	pbr_set_route(tableid, dstpfx, PBR_TEST_NH6, PBR_TEST_IFN,
		      PBR_TEST_NH6_MAC);

	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_TEST_IFN, PBR_TEST_NH6_MAC,
			&test_pak);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	pbr_del_route(tableid, dstpfx, PBR_TEST_NH6, PBR_TEST_IFN,
		      PBR_TEST_NH6_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
} DP_END_TEST;

DP_DECL_TEST_CASE(pbr_suite, pbr_drop, pbr_setup, pbr_teardown);

DP_START_TEST(pbr_drop, v4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int tableid = 4;
	const char *dstpfx = PBR_TEST_4DST "/32";

	/*
	 * Generate a packet and ensure that it is forwarded via the
	 * default output interface.
	 */
	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_OUT_IFN, PBR_OUT_NH4_MAC,
			&test_pak);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	/*
	 * Now apply a PBR drop policy and ensure the packet is discarded
	 */
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr4", 10, PBR_DROP, PBR_DROP_SHOW,
			  PBR_IPV4, NULL, dstpfx, tableid);
	pbr_set_route(tableid, dstpfx, PBR_TEST_NH4, PBR_TEST_IFN,
		      PBR_TEST_NH4_MAC);

	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_TEST_IFN, PBR_TEST_NH4_MAC,
			&test_pak);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	pbr_del_route(tableid, dstpfx, PBR_TEST_NH4, PBR_TEST_IFN,
		      PBR_TEST_NH4_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");
} DP_END_TEST;

DP_START_TEST(pbr_drop, v6)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int tableid = 6;
	const char *dstpfx = PBR_TEST_6DST "/128";

	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_OUT_IFN, PBR_OUT_NH6_MAC,
			&test_pak);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr6", 10, PBR_DROP, PBR_DROP_SHOW,
			  PBR_IPV6, NULL, dstpfx, tableid);
	pbr_set_route(tableid, dstpfx, PBR_TEST_NH6, PBR_TEST_IFN,
		      PBR_TEST_NH6_MAC);
	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_TEST_IFN, PBR_TEST_NH6_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	pbr_del_route(tableid, dstpfx, PBR_TEST_NH6, PBR_TEST_IFN,
		      PBR_TEST_NH6_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
} DP_END_TEST;

#define STRINGIFZ(x) #x
#define STRINGIFY(x) STRINGIFZ(x)

static void
_pbr_vrf_teardown(void)
{

	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");
	dp_test_netlink_del_route(dp_test_default_route_ipv4);
	dp_test_netlink_del_neigh(PBR_OUT_IFN, PBR_OUT_NH4, PBR_OUT_NH4_MAC);
	dp_test_nl_del_ip_addr_and_connected(PBR_IN_IFN, PBR_IN_IFN_ADDR4);
	dp_test_nl_del_ip_addr_and_connected(PBR_OUT_IFN, PBR_OUT_IFN_ADDR4);
	dp_test_nl_del_ip_addr_and_connected_vrf(PBR_TEST_IFN,
						 PBR_TEST_IFN_ADDR4, TEST_VRF);

	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
	dp_test_netlink_del_route(dp_test_default_route_ipv6);
	dp_test_netlink_del_neigh(PBR_OUT_IFN, PBR_OUT_NH6, PBR_OUT_NH6_MAC);
	dp_test_nl_del_ip_addr_and_connected(PBR_IN_IFN, PBR_IN_IFN_ADDR6);
	dp_test_nl_del_ip_addr_and_connected(PBR_OUT_IFN, PBR_OUT_IFN_ADDR6);
	dp_test_nl_del_ip_addr_and_connected_vrf(PBR_TEST_IFN,
						 PBR_TEST_IFN_ADDR6, TEST_VRF);
	dp_test_netlink_set_interface_vrf(PBR_TEST_IFN, VRF_DEFAULT_ID);
	dp_test_netlink_del_vrf(TEST_VRF, 0);
}

static void
pbr_vrf_teardown(void)
{
	vrfid_t xvrfid = dp_test_translate_vrf_id(TEST_VRF);
	dp_test_send_config_src(dp_test_cont_src_get(),
				"tablemap %d %d 0 %d",
				TEST_VRF,
				TEST_TABLEID,
				xvrfid);
	_pbr_vrf_teardown();
}

static void
_pbr_vrf_setup(void)
{
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");
	dp_test_nl_add_ip_addr_and_connected(PBR_IN_IFN, PBR_IN_IFN_ADDR4);
	dp_test_nl_add_ip_addr_and_connected(PBR_OUT_IFN, PBR_OUT_IFN_ADDR4);
	dp_test_netlink_add_vrf(TEST_VRF, 1);
	dp_test_netlink_set_interface_vrf(PBR_TEST_IFN, TEST_VRF);
	dp_test_nl_add_ip_addr_and_connected_vrf(PBR_TEST_IFN,
						 PBR_TEST_IFN_ADDR4, TEST_VRF);
	dp_test_netlink_add_route(dp_test_default_route_ipv4);
	dp_test_netlink_add_neigh(PBR_OUT_IFN, PBR_OUT_NH4, PBR_OUT_NH4_MAC);

	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
	dp_test_nl_add_ip_addr_and_connected(PBR_IN_IFN, PBR_IN_IFN_ADDR6);
	dp_test_nl_add_ip_addr_and_connected(PBR_OUT_IFN, PBR_OUT_IFN_ADDR6);
	dp_test_nl_add_ip_addr_and_connected_vrf(PBR_TEST_IFN,
						 PBR_TEST_IFN_ADDR6, TEST_VRF);
	dp_test_netlink_add_route(dp_test_default_route_ipv6);
	dp_test_netlink_add_neigh(PBR_OUT_IFN, PBR_OUT_NH6, PBR_OUT_NH6_MAC);

}

static void
pbr_vrf_setup(void)
{
	_pbr_vrf_setup();

	vrfid_t xvrfid = dp_test_translate_vrf_id(TEST_VRF);
	dp_test_send_config_src(dp_test_cont_src_get(),
				"tablemap %d %d %d %d",
				TEST_VRF,
				TEST_TABLEID, MAPPED_TABLEID_1,
				xvrfid);
}


DP_DECL_TEST_CASE(pbr_suite, pbr_x_vrf, pbr_vrf_setup, pbr_vrf_teardown);

DP_START_TEST(pbr_x_vrf, v4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *dstpfx = PBR_TEST_4DST "/32";

	/*
	 * Generate a packet and ensure that it is forwarded via the
	 * default output interface.
	 */
	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_OUT_IFN, PBR_OUT_NH4_MAC,
			&test_pak);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	/*
	 * Now apply a PBR policy to route the same packet out the test
	 * interface.
	 */
	pbr_set_policy_ip_vrf(PBR_IN_IFN, "pbr:pbr4", 10, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV4, NULL, dstpfx,
			      TEST_VRF, RT_TABLE_UNSPEC);
	dp_test_netlink_add_route("vrf:" STRINGIFY(TEST_VRF) " "
				  PBR_TEST_4DST "/32 nh "
				  PBR_TEST_NH4 " int:" PBR_TEST_IFN);
	dp_test_netlink_add_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);

	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_TEST_IFN, PBR_TEST_NH4_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	dp_test_netlink_del_route("vrf:" STRINGIFY(TEST_VRF) " "
				  PBR_TEST_4DST "/32 nh "
				  PBR_TEST_NH4 " int:" PBR_TEST_IFN);
	dp_test_netlink_del_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");
} DP_END_TEST;

DP_START_TEST(pbr_x_vrf, v6)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *dstpfx = PBR_TEST_6DST "/128";

	/*
	 * Generate a packet and ensure that it is forwarded via the
	 * default output interface.
	 */
	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_OUT_IFN, PBR_OUT_NH6_MAC,
			&test_pak);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	/*
	 * Now apply a PBR policy to route the same packet out the test
	 * interface.
	 */
	pbr_set_policy_ip_vrf(PBR_IN_IFN, "pbr:pbr6", 10, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV6, NULL, dstpfx,
			      TEST_VRF, RT_TABLE_UNSPEC);
	dp_test_netlink_add_route("vrf:" STRINGIFY(TEST_VRF) " "
				  PBR_TEST_6DST "/128 nh "
				  PBR_TEST_NH6 " int:" PBR_TEST_IFN);
	dp_test_netlink_add_neigh(PBR_TEST_IFN, PBR_TEST_NH6, PBR_TEST_NH6_MAC);

	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_TEST_IFN, PBR_TEST_NH6_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	dp_test_netlink_del_route("vrf:" STRINGIFY(TEST_VRF) " "
				  PBR_TEST_6DST "/128 nh "
				  PBR_TEST_NH6 " int:" PBR_TEST_IFN);
	dp_test_netlink_del_neigh(PBR_TEST_IFN, PBR_TEST_NH6, PBR_TEST_NH6_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
} DP_END_TEST;

DP_START_TEST(pbr_x_vrf, v4_tableid)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *dstpfx = PBR_TEST_4DST "/32";

	/*
	 * Generate a packet and ensure that it is forwarded via the
	 * default output interface.
	 */
	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_OUT_IFN, PBR_OUT_NH4_MAC,
			&test_pak);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	/*
	 * Now apply a PBR policy to route the same packet out the test
	 * interface.
	 */
	pbr_set_policy_ip_vrf(PBR_IN_IFN, "pbr:pbr4", 10, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV4, NULL, dstpfx,
			      TEST_VRF, TEST_TABLEID);
	dp_test_netlink_add_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_4DST "/32 nh "
				  PBR_TEST_NH4 " int:" PBR_TEST_IFN);
	dp_test_netlink_add_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);

	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_TEST_IFN, PBR_TEST_NH4_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	dp_test_netlink_del_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_4DST "/32 nh "
				  PBR_TEST_NH4 " int:" PBR_TEST_IFN);
	dp_test_netlink_del_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");
} DP_END_TEST;

DP_START_TEST(pbr_x_vrf, v6_tableid)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *dstpfx = PBR_TEST_6DST "/128";

	/*
	 * Generate a packet and ensure that it is forwarded via the
	 * default output interface.
	 */
	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_OUT_IFN, PBR_OUT_NH6_MAC,
			&test_pak);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	/*
	 * Now apply a PBR policy to route the same packet out the test
	 * interface.
	 */
	pbr_set_policy_ip_vrf(PBR_IN_IFN, "pbr:pbr6", 10, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV6, NULL, dstpfx,
			      TEST_VRF, TEST_TABLEID);
	dp_test_netlink_add_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_6DST "/128 nh "
				  PBR_TEST_NH6 " int:" PBR_TEST_IFN);
	dp_test_netlink_add_neigh(PBR_TEST_IFN, PBR_TEST_NH6, PBR_TEST_NH6_MAC);

	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_TEST_IFN, PBR_TEST_NH6_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	dp_test_netlink_del_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_6DST "/128 nh "
				  PBR_TEST_NH6 " int:" PBR_TEST_IFN);
	dp_test_netlink_del_neigh(PBR_TEST_IFN, PBR_TEST_NH6, PBR_TEST_NH6_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
} DP_END_TEST;

static void
pbr_in_vrf_teardown(void)
{
	vrfid_t xvrfid;

	xvrfid = dp_test_translate_vrf_id(TEST_VRF);

	dp_test_send_config_src(dp_test_cont_src_get(),
			"tablemap %d %d 0 %d",
			TEST_VRF,
			POLICY_PBR_TABLEID_2,
			xvrfid);
	dp_test_send_config_src(dp_test_cont_src_get(),
			"tablemap %d %d 0 %d",
			TEST_VRF,
			POLICY_PBR_TABLEID_1,
			xvrfid);

	dp_test_netlink_set_interface_vrf(PBR_TEST_IFN, VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf(PBR_IN_IFN, VRF_DEFAULT_ID);

	_pbr_vrf_teardown();
}

static void
pbr_in_vrf_setup(void)
{
	vrfid_t xvrfid;

	dp_test_netlink_add_vrf(TEST_VRF, 1);
	xvrfid = dp_test_translate_vrf_id(TEST_VRF);
	dp_test_netlink_del_vrf(TEST_VRF, 0);

	_pbr_vrf_setup();

	dp_test_netlink_set_interface_vrf(PBR_TEST_IFN, TEST_VRF);
	dp_test_netlink_set_interface_vrf(PBR_IN_IFN, TEST_VRF);

	dp_test_send_config_src(dp_test_cont_src_get(),
			"tablemap %d %d %d %d",
			TEST_VRF,
			POLICY_PBR_TABLEID_1, MAPPED_TABLEID_1,
			xvrfid);

	dp_test_send_config_src(dp_test_cont_src_get(),
			"tablemap %d %d %d %d",
			TEST_VRF,
			POLICY_PBR_TABLEID_2, MAPPED_TABLEID_2,
			xvrfid);
}

DP_DECL_TEST_CASE(pbr_suite, pbr_in_vrf_map, pbr_in_vrf_setup,
		  pbr_in_vrf_teardown);

DP_START_TEST(pbr_in_vrf_map, v4_tableid)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *dstpfx = PBR_TEST_4DST "/32";
	const char *dstpfx_2 = PBR_TEST_4DST_2 "/32";

	/*
	 * Apply PBR policies to route packet out the test
	 * interface for two different tableids.
	 */
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr4", 10, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV4, NULL, dstpfx,
			      POLICY_PBR_TABLEID_1);
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr4", 20, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV4, NULL, dstpfx_2,
			      POLICY_PBR_TABLEID_2);
	dp_test_netlink_add_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_4DST "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);
	dp_test_netlink_add_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_2) " "
				  PBR_TEST_4DST_2 "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);

	dp_test_netlink_add_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);

	/*
	 * Send packet to match rule 10, first tableid.
	 */
	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_TEST_IFN, PBR_TEST_NH4_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	/*
	 * Send packet to match rule 20, second tableid.
	 */
	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST_2,
			PBR_TEST_IFN, PBR_TEST_NH4_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	dp_test_netlink_del_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_4DST "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);
	dp_test_netlink_del_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_2) " "
				  PBR_TEST_4DST_2 "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);
	dp_test_netlink_del_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");

} DP_END_TEST;

DP_START_TEST(pbr_in_vrf_map, v6_tableid)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *dstpfx = PBR_TEST_6DST "/128";

	/*
	 * Apply a PBR policy to route the same packet out the test
	 * interface.
	 */
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr6", 10, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV6, NULL, dstpfx,
			      POLICY_PBR_TABLEID_1);
	dp_test_netlink_add_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_6DST "/128 nh "
				  PBR_TEST_NH6 " int:" PBR_TEST_IFN);
	dp_test_netlink_add_neigh(PBR_TEST_IFN, PBR_TEST_NH6, PBR_TEST_NH6_MAC);

	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_TEST_IFN, PBR_TEST_NH6_MAC,
			&test_pak);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);
	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	dp_test_netlink_del_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_6DST "/128 nh "
				  PBR_TEST_NH6 " int:" PBR_TEST_IFN);
	dp_test_netlink_del_neigh(PBR_TEST_IFN, PBR_TEST_NH6, PBR_TEST_NH6_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
} DP_END_TEST;

/*
 * Test that we don't map tables > 128
 */
DP_DECL_TEST_CASE(pbr_suite, pbr_in_vrf_no_map, pbr_in_vrf_setup,
		  pbr_in_vrf_teardown);

DP_START_TEST(pbr_in_vrf_no_map, v4_tableid)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *dstpfx = PBR_TEST_4DST "/32";

	/*
	 * Apply a PBR policy to route the same packet out the test
	 * interface.
	 */
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr4", 10, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV4, NULL, dstpfx,
			      POLICY_NON_PBR_TABLEID);
	dp_test_netlink_add_route("tbl:" STRINGIFY(POLICY_NON_PBR_TABLEID) " "
				  PBR_TEST_4DST "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);
	dp_test_netlink_add_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);

	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_TEST_IFN, PBR_TEST_NH4_MAC,
			&test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	dp_test_netlink_del_route("tbl:" STRINGIFY(POLICY_NON_PBR_TABLEID) " "
				  PBR_TEST_4DST "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);
	dp_test_netlink_del_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");
} DP_END_TEST;

DP_START_TEST(pbr_in_vrf_no_map, v6_tableid)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *dstpfx = PBR_TEST_6DST "/128";

	/*
	 * Apply a PBR policy to route the same packet out the test
	 * interface.
	 */
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr6", 10, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV6, NULL, dstpfx,
			      POLICY_NON_PBR_TABLEID);
	dp_test_netlink_add_route("tbl:" STRINGIFY(POLICY_NON_PBR_TABLEID) " "
				  PBR_TEST_6DST "/128 nh "
				  PBR_TEST_NH6 " int:" PBR_TEST_IFN);
	dp_test_netlink_add_neigh(PBR_TEST_IFN, PBR_TEST_NH6, PBR_TEST_NH6_MAC);

	exp = PBR_V6PAK(PBR_TEST_6SRC, PBR_TEST_6DST,
			PBR_TEST_IFN, PBR_TEST_NH6_MAC,
			&test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);
	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	dp_test_netlink_del_route("tbl:" STRINGIFY(POLICY_NON_PBR_TABLEID) " "
				  PBR_TEST_6DST "/128 nh "
				  PBR_TEST_NH6 " int:" PBR_TEST_IFN);
	dp_test_netlink_del_neigh(PBR_TEST_IFN, PBR_TEST_NH6, PBR_TEST_NH6_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr6");
} DP_END_TEST;

static void
pbr_in_vrf_setup_config_before_netlink(void)
{
	vrfid_t xvrfid;

	dp_test_netlink_add_vrf(TEST_VRF, 1);
	xvrfid = dp_test_translate_vrf_id(TEST_VRF);
	dp_test_netlink_del_vrf(TEST_VRF, 0);

	dp_test_send_config_src(dp_test_cont_src_get(),
			"tablemap %d %d %d %d",
			TEST_VRF,
			POLICY_PBR_TABLEID_1, MAPPED_TABLEID_1,
			xvrfid);

	dp_test_send_config_src(dp_test_cont_src_get(),
			"tablemap %d %d %d %d",
			TEST_VRF,
			POLICY_PBR_TABLEID_2, MAPPED_TABLEID_2,
			xvrfid);

	_pbr_vrf_setup();

	dp_test_netlink_set_interface_vrf(PBR_TEST_IFN, TEST_VRF);
	dp_test_netlink_set_interface_vrf(PBR_IN_IFN, TEST_VRF);
}

/*
 * Ensure that we handle tablemap arriving at dataplane before netlinks.
 */
DP_DECL_TEST_CASE(pbr_suite, pbr_in_vrf_map_config_before_netlink,
		pbr_in_vrf_setup_config_before_netlink, pbr_in_vrf_teardown);

DP_START_TEST(pbr_in_vrf_map_config_before_netlink, v4_tableid)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *dstpfx = PBR_TEST_4DST "/32";
	const char *dstpfx_2 = PBR_TEST_4DST_2 "/32";

	/*
	 * Apply PBR policies to route packet out the test
	 * interface for two different tableids.
	 */
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr4", 10, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV4, NULL, dstpfx,
			      POLICY_PBR_TABLEID_1);
	pbr_set_policy_ip(PBR_IN_IFN, "pbr:pbr4", 20, PBR_ACCEPT,
			      PBR_ACCEPT_SHOW, PBR_IPV4, NULL, dstpfx_2,
			      POLICY_PBR_TABLEID_2);
	dp_test_netlink_add_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_4DST "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);
	dp_test_netlink_add_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_2) " "
				  PBR_TEST_4DST_2 "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);

	dp_test_netlink_add_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);

	/*
	 * Send packet to match rule 10, first tableid
	 */
	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST,
			PBR_TEST_IFN, PBR_TEST_NH4_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	/*
	 * Send packet to match rule 20, second tableid.
	 */
	exp = PBR_V4PAK(PBR_TEST_4SRC, PBR_TEST_4DST_2,
			PBR_TEST_IFN, PBR_TEST_NH4_MAC,
			&test_pak);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 0",
				 pbr_debug);

	dp_test_pak_receive(test_pak, PBR_IN_IFN, exp);

	dp_test_check_state_show("npf-op show all: pbr", "\"packets\": 1",
				 pbr_debug);

	dp_test_netlink_del_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_1) " "
				  PBR_TEST_4DST "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);
	dp_test_netlink_del_route("vrf:" STRINGIFY(TEST_VRF) " "
				  "tbl:" STRINGIFY(MAPPED_TABLEID_2) " "
				  PBR_TEST_4DST_2 "/32 nh " PBR_TEST_NH4
				  " int:" PBR_TEST_IFN);
	dp_test_netlink_del_neigh(PBR_TEST_IFN, PBR_TEST_NH4, PBR_TEST_NH4_MAC);
	pbr_del_policy(PBR_IN_IFN, "pbr:pbr4");

} DP_END_TEST;

#undef POLICY_PBR_TABLEID_1
#undef POLICY_PBR_TABLEID_2
#undef POLICY_NON_PBR_TABLEID
#undef MAPPED_TABLEID_1
#undef MAPPED_TABLEID_2
#undef TEST_TABLEID
#undef TEST_VRF
