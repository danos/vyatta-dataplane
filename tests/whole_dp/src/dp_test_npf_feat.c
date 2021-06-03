/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property. All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf pipeline feature enablement unit-tests
 *
 * There are a set of short, simple, test-cases what exercise one aspect
 * related to npf.  They may be used as either a quick test run, or to help
 * debug something, or as templates to copy for further tests.
 */

#include <libmnl/libmnl.h>
#include <netinet/ip_icmp.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"

#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_nat_lib.h"

#define ACTION_ADD     true
#define ACTION_DEL     false

#define EXP_GONE    true
#define EXP_PRESENT false

static void
npf_feat_fw_ruleset(const char *if_name, const char *grp_name,
		    bool in, bool add)
{
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real(if_name, real_ifname);

	if (add) {
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add fw:%s 10 action=accept stateful=y to=any",
			grp_name);
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut add fw:%s 10000 action=drop",
			grp_name);
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut attach interface:%s %s fw:%s",
			real_ifname, in ? "fw-in":"fw-out", grp_name);
	} else {
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut detach interface:%s %s fw:%s",
			real_ifname, in ? "fw-in":"fw-out", grp_name);
		dp_test_npf_cmd_fmt(
			false,
			"npf-ut delete fw:%s",
			grp_name);
	}
	dp_test_npf_commit();
}

static void
npf_feat_nat64_ruleset(const char *if_name, const char *grp_name, bool add)
{
	const struct dp_test_npf_nat64_rule_t rule96 = {
		.rule		= "1",
		.ifname		= if_name,
		.from_addr	= "2001:101:1::/96",
		.to_addr	= "2001:101:2::/96",
		.spl		= 96,
		.dpl		= 96
	};
	if (add)
		dp_test_npf_nat64_add(&rule96, true);
	else
		dp_test_npf_nat64_del(&rule96, true);

	dp_test_npf_commit();
}

static void
_dp_test_wait_for_pl_defrag(const char *ifname, bool exp_gone,
			    const char *file, const char *func, int line)
{
	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv4-defrag-in",
				  "ipv4-validate", exp_gone,
				  file, func, line);

	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv6-defrag-in",
				  "ipv6-validate", exp_gone,
				  file, func, line);

	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv4-defrag-out",
				  "ipv4-out", exp_gone,
				  file, func, line);

	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv6-defrag-out",
				  "ipv6-out", exp_gone,
				  file, func, line);
}
#define dp_test_wait_for_pl_defrag(_intf, _gone)			\
	_dp_test_wait_for_pl_defrag(_intf, _gone,			\
				    __FILE__, __func__, __LINE__)	\

static void
_dp_test_wait_for_pl_fw(const char *ifname, bool exp_gone,
			const char *file, const char *func, int line)
{
	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv4-fw-in",
				  "ipv4-validate", exp_gone,
				  file, func, line);

	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv6-fw-in",
				  "ipv6-validate", exp_gone,
				  file, func, line);

	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv4-snat",
				  "ipv4-out", exp_gone,
				  file, func, line);

	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv6-pre-fw-out",
				  "ipv6-out", exp_gone,
				  file, func, line);
}
#define dp_test_wait_for_pl_fw(_intf, _gone)			\
	_dp_test_wait_for_pl_fw(_intf, _gone,			\
				__FILE__, __func__, __LINE__)	\


static void
_dp_test_wait_for_pl_nat64(const char *ifname, bool exp_gone,
			const char *file, const char *func, int line)
{
	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv4-nat46-in",
				  "ipv4-validate", exp_gone,
				  file, func, line);

	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv6-nat64-in",
				  "ipv6-validate", exp_gone,
				  file, func, line);

	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv4-nat64-out",
				  "ipv4-out", exp_gone,
				  file, func, line);

	_dp_test_wait_for_pl_feat(ifname, "vyatta:ipv6-nat46-out",
				  "ipv6-out", exp_gone,
				  file, func, line);
}
#define dp_test_wait_for_pl_nat64(_intf, _gone)				\
	_dp_test_wait_for_pl_nat64(_intf, _gone,			\
				   __FILE__, __func__, __LINE__)	\


DP_DECL_TEST_SUITE(npf_feat);

/*
 * npf_feat1 - firewall ruleset
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat1
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat1, NULL, NULL);
DP_START_TEST(npf_feat1, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_ADD);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);

	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

} DP_END_TEST;

/*
 * npf_feat2 - zone ruleset
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat2
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat2, NULL, NULL);
DP_START_TEST(npf_feat2, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	/* Add zone with member intfs dp1T0 and dp1T1 */
	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = { NULL, { NULL, NULL, NULL }, false },
		.local = { 0 },
		.pub_to_priv = { 0 },
		.priv_to_pub = { 0 },
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, false);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T2", EXP_PRESENT);

	dpt_zone_cfg(&cfg, false, false);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T2", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

} DP_END_TEST;

/*
 * npf_feat3 - nat64 ruleset
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat3
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat3, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat3, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_ADD);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_PRESENT);

	/* Firewall should not be present */
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);

	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");
} DP_END_TEST;

/*
 * npf_feat4a - firewall and nat64 rulesets.  Remove nat64 first then check
 * firewall still enabled.
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat4
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat4a, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat4a, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	/*
	 * Add nat64 and firewall to dp1T0
	 */
	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_ADD);
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_ADD);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);	/* No fw on dp1T1 */
	dp_test_wait_for_pl_nat64("dp1T1", EXP_PRESENT);

	/*
	 * Remove nat64 from dp1T0.  defrag and fw features should still be
	 * present on dp1T0
	 */
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_GONE);

	/*
	 * Remove firewall from dp1T0
	 */
	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");
} DP_END_TEST;

/*
 * npf_feat4b - firewall and nat64 rulesets.  Remove nat64 first then check
 * firewall still enabled.
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat4
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat4b, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat4b, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	/*
	 * Add nat64 and firewall to dp1T0
	 */
	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_ADD);
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_ADD);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);	/* No fw on dp1T1 */
	dp_test_wait_for_pl_nat64("dp1T1", EXP_PRESENT);

	/*
	 * Remove firewall from dp1T0.  defrag and nat64 features should still
	 * be present on dp1T0
	 */
	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	/*
	 * Remove nat64 from dp1T0.
	 */
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");
} DP_END_TEST;

/*
 * npf_feat5 - nat64 ruleset
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat5
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat5, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat5, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_ADD);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_PRESENT);

	/* Create an incomplete vif interface */
	dp_test_intf_vif_create_incmpl("dp1T1.100", "dp1T1", 100);

	/* Complete the vif interface */
	dp_test_intf_vif_create_incmpl_fin("dp1T1.100", "dp1T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp1T1.100", "2.2.2.2/24");

	/* Check features on vif interface */
	dp_test_wait_for_pl_defrag("dp1T1.100", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T1.100", EXP_PRESENT);

	/* Remove vif interface */
	dp_test_nl_del_ip_addr_and_connected("dp1T1.100", "2.2.2.2/24");
	dp_test_intf_vif_del("dp1T1.100", 100);


	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");
} DP_END_TEST;

/*
 * npf_feat6 - nat64 and zone rulesets
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat6
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat6, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat6, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_ADD);

	/*
	 * Add zone with member intfs dp1T0 and dp1T1
	 */
	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1", NULL },
			.local = false,
		},
		.public = { NULL, { NULL, NULL, NULL }, false },
		.local = { 0 },
		.pub_to_priv = { 0 },
		.priv_to_pub = { 0 },
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, false);

	/*
	 * Check fw and defrag are enabled on zone and non-zone interfaces.
	 */
	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T2", EXP_PRESENT);

	/*
	 * Create vif interface
	 */
	dp_test_intf_vif_create_incmpl("dp1T1.100", "dp1T1", 100);
	dp_test_intf_vif_create_incmpl_fin("dp1T1.100", "dp1T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp1T1.100", "2.2.2.2/24");

	/*
	 * Check fw and defrag features are enabled on vif interface
	 */
	dp_test_wait_for_pl_defrag("dp1T1.100", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1.100", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T1.100", EXP_PRESENT);

	/*
	 * Remove vif interface
	 */
	dp_test_nl_del_ip_addr_and_connected("dp1T1.100", "2.2.2.2/24");
	dp_test_intf_vif_del("dp1T1.100", 100);

	/* Remove nat64 ruleset */
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_DEL);

	/* Check features still enabled */
	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T2", EXP_GONE);

	/* Remove zone */
	dpt_zone_cfg(&cfg, false, false);

	/* Check features are now gone */
	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T2", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");
} DP_END_TEST;

/*
 * npf_feat7 - nat64 and zone rulesets
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat7
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat7, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat7, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected("dp1T2", "3.3.3.3/24");

	/*
	 * Create vif interface *before* nat64 and zone config
	 */
	dp_test_intf_vif_create_incmpl("dp1T1.100", "dp1T1", 100);
	dp_test_intf_vif_create_incmpl_fin("dp1T1.100", "dp1T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp1T1.100", "2.2.2.2/24");

	/* Add nat64 config */
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_ADD);

	/*
	 * Add zone with member intfs dp1T0 and dp1T1.100
	 */
	struct dpt_zone_cfg cfg = {
		.private = {
			.name = "PRIVATE",
			.intf = { "dp1T0", "dp1T1.100", NULL },
			.local = false,
		},
		.public = { NULL, { NULL, NULL, NULL }, false },
		.local = { 0 },
		.pub_to_priv = { 0 },
		.priv_to_pub = { 0 },
		.local_to_priv = { 0 },
		.priv_to_local = { 0 },
		.local_to_pub = { 0 },
		.pub_to_local = { 0 },
	};

	dpt_zone_cfg(&cfg, true, false);

	/*
	 * Check fw and defrag are enabled on zone and non-zone interfaces.
	 */
	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T2", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T1.100", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1.100", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T1.100", EXP_PRESENT);

	/*
	 * Remove vif interface
	 */
	dp_test_nl_del_ip_addr_and_connected("dp1T1.100", "2.2.2.2/24");
	dp_test_intf_vif_del("dp1T1.100", 100);

	/* Remove nat64 ruleset */
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_DEL);

	/* Check features still enabled */
	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T2", EXP_GONE);

	/* Remove zone */
	dpt_zone_cfg(&cfg, false, false);

	/* Check features are now gone */
	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T2", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T2", "3.3.3.3/24");
} DP_END_TEST;

/*
 * npf_feat8 - firewall and nat64 rulesets, VRF 69
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat8
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat8, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat8, test)
{
	uint vrfid = 69;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/*
	 * vrf 69  - dp1T0 and dp1T2
	 * default - dp1T1 and dp1T3
	 */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0",
						 "2001:101:1::a0a:1fe/96",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T2", "3.3.3.3/24", vrfid);
	dp_test_nl_add_ip_addr_and_connected("dp1T3", "3.3.3.3/24");

	/*
	 * Add nat64 and firewall to dp1T0
	 */
	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_ADD);
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_ADD);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T2", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T2", EXP_PRESENT);

	/* Check features on interface in different vrf */
	dp_test_wait_for_pl_defrag("dp1T1", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_PRESENT);

	/*
	 * Remove nat64 from dp1T0.  defrag and fw features should still be
	 * present on dp1T0
	 */
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T2", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T2", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T1", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T1", EXP_GONE);

	/*
	 * Remove firewall from dp1T0
	 */
	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T2", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0",
						 "2001:101:1::a0a:1fe/96",
						 vrfid);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T2", "3.3.3.3/24", vrfid);
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "3.3.3.3/24");

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrfid, 0);
} DP_END_TEST;


/*
 * npf_feat9 - firewall and nat64 rulesets, VRF 69
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat9
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat9, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat9, test)
{
	uint vrfid = 69;

	dp_test_netlink_add_vrf(vrfid, 1);

	/*
	 * vrf 69  - dp1T0 and dp1T2
	 * default - dp1T1 and dp1T3
	 */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0",
						 "2001:101:1::a0a:1fe/96",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T2", "3.3.3.3/24", vrfid);
	dp_test_nl_add_ip_addr_and_connected("dp1T3", "3.3.3.3/24");

	/*
	 * Add nat64 and firewall to dp1T0
	 */
	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_ADD);

	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_ADD);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T2", EXP_PRESENT);

	/*
	 * Delete vrf and set ints back to default
	 */
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0",
						 "2001:101:1::a0a:1fe/96",
						 vrfid);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T2", "3.3.3.3/24", vrfid);
	dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf("dp1T2", VRF_DEFAULT_ID);
	dp_test_netlink_del_vrf(vrfid, 0);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_PRESENT);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T2", EXP_PRESENT);

	/*
	 * Remove nat64 from dp1T0.  defrag and fw features should still be
	 * present on dp1T0
	 */
	npf_feat_nat64_ruleset("dp1T0", "N64_GROUP1", ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_nat64("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_GONE);
	dp_test_wait_for_pl_nat64("dp1T2", EXP_GONE);

	/*
	 * Remove firewall from dp1T0
	 */
	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);

	dp_test_wait_for_pl_defrag("dp1T2", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T2", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "3.3.3.3/24");

} DP_END_TEST;


/*
 * npf_feat10 - firewall rulesets, VRF 69
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat10
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat10, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat10, test)
{
	uint vrfid = 69;

	dp_test_netlink_add_vrf(vrfid, 1);

	/*
	 * vrf 69  - dp1T0 and dp1T2
	 * default - dp1T1 and dp1T3
	 */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0",
						 "2001:101:1::a0a:1fe/96",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T2", "3.3.3.3/24", vrfid);
	dp_test_nl_add_ip_addr_and_connected("dp1T3", "3.3.3.3/24");

	/*
	 * Add firewall to dp1T0
	 */
	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_ADD);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);

	/*
	 * Delete vrf and interfaces
	 */
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0",
						 "2001:101:1::a0a:1fe/96",
						 vrfid);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T2", "3.3.3.3/24", vrfid);
	dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
	dp_test_netlink_set_interface_vrf("dp1T2", VRF_DEFAULT_ID);
	dp_test_netlink_del_vrf(vrfid, 0);

	/*
	 * dp1T0 should still be present, with fw enabled
	 */
	dp_test_wait_for_pl_defrag("dp1T0", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T0", EXP_PRESENT);

	npf_feat_fw_ruleset("dp1T0", "FW_GROUP1", true, ACTION_DEL);

	dp_test_wait_for_pl_defrag("dp1T0", EXP_GONE);
	dp_test_wait_for_pl_fw("dp1T0", EXP_GONE);

	dp_test_nl_del_ip_addr_and_connected("dp1T1", "2002:101:1::a0a:1fe/96");
	dp_test_nl_del_ip_addr_and_connected("dp1T3", "3.3.3.3/24");

} DP_END_TEST;

/*
 * npf_feat11 - Delete vif interface that has stateful fw and active sessions
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=npf_feat11
 */
DP_DECL_TEST_CASE(npf_feat, npf_feat11, NULL, NULL);
DP_START_TEST_FULL_RUN(npf_feat11, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	const char *nh_mac_str1 = "aa:bb:cc:dd:2:a1";
	const char *nh_mac_str2 = "aa:bb:cc:dd:2:a2";
	int len = 22;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11", "aa:bb:cc:dd:1:a1");

	/* Create a vif interface */
	dp_test_intf_vif_create_incmpl("dp1T1.100", "dp1T1", 100);
	dp_test_intf_vif_create_incmpl_fin("dp1T1.100", "dp1T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp1T1.100", "2.2.2.2/24");
	dp_test_netlink_add_neigh("dp1T1.100", "2.2.2.11", nh_mac_str1);
	dp_test_netlink_add_neigh("dp1T1.100", "2.2.2.12", nh_mac_str2);

	/* stateful output firewall on dp1T1.100 */
	npf_feat_fw_ruleset("dp1T1.100", "FW_GROUP1", false, ACTION_ADD);

	/* Check features on vif interface */
	dp_test_wait_for_pl_defrag("dp1T1.100", EXP_PRESENT);
	dp_test_wait_for_pl_fw("dp1T1.100", EXP_PRESENT);

	/*
	 * Test packet 1
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.11", "2.2.2.11", 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");
	dp_test_exp_set_vlan_tci(exp, 100);

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str1,
				       dp_test_intf_name2mac_str("dp1T1"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);


	/*
	 * Test packet 2
	 */
	test_pak = dp_test_create_ipv4_pak("1.1.1.11", "2.2.2.12", 1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");
	dp_test_exp_set_vlan_tci(exp, 100);

	(void)dp_test_pktmbuf_eth_init(dp_test_exp_get_pak(exp),
				       nh_mac_str2,
				       dp_test_intf_name2mac_str("dp1T1"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

	dp_test_pak_receive(test_pak, "dp1T0", exp);


	/* Remove vif interface */
	dp_test_nl_del_ip_addr_and_connected("dp1T1.100", "2.2.2.2/24");
	dp_test_intf_vif_del("dp1T1.100", 100);

	/* Cleanup */
	npf_feat_fw_ruleset("dp1T1.100", "FW_GROUP1", false, ACTION_DEL);
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11", "aa:bb:cc:dd:1:a1");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_npf_cleanup();

} DP_END_TEST;

/*
 * Test that the ipv4-fw-orig feature is enabled on *all* interfaces when it
 * is attached to "global:".
 *
 * This is what happens when an 'originate' ruleset is configured on a
 * loopback interface.
 */
DP_DECL_TEST_CASE(npf_feat, npf_orig_feat, NULL, NULL);

DP_START_TEST_FULL_RUN(npf_orig_feat, test1)
{
	bool rv, debug = false;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

	rv = dp_pipeline_is_feature_enabled_by_inst("vyatta:ipv4-fw-orig",
						    "dpT10");
	dp_test_fail_unless(!rv, "ipv4-fw-orig is enabled");

	dp_test_npf_cmd_fmt(debug, "npf-ut add fw:FW_ORIG 1 action=accept");
	dp_test_npf_cmd_fmt(debug,
			    "npf-ut attach global: originate fw:FW_ORIG");
	dp_test_npf_commit();

	/* Check ipv4-fw-orig enabled on dpT10 */
	rv = dp_pipeline_is_feature_enabled_by_inst("vyatta:ipv4-fw-orig",
						    "dpT10");
	dp_test_fail_unless(rv, "ipv4-fw-orig not enabled on dpT10 "
			    "when attached to \"global:\"");

	/* Check ipv4-fw-orig is enabled on dpT11 */
	rv = dp_pipeline_is_feature_enabled_by_inst("vyatta:ipv4-fw-orig",
						    "dpT11");
	dp_test_fail_unless(rv, "ipv4-fw-orig not enabled on dpT11 "
			    "when attached to \"global:\"");

	/* Check ipv4-defrag-out-spath is enabled on dpT10 */
	rv = dp_pipeline_is_feature_enabled_by_inst(
		"vyatta:ipv4-defrag-out-spath", "dpT10");
	dp_test_fail_unless(rv, "ipv4-defrag-out-spath not enabled on dpT10 "
			    "when attached to \"global:\"");

	/* Check ipv4-defrag-out-spath is enabled on dpT11 */
	rv = dp_pipeline_is_feature_enabled_by_inst(
		"vyatta:ipv4-defrag-out-spath", "dpT11");
	dp_test_fail_unless(rv, "ipv4-defrag-out-spath not enabled on dpT11 "
			    "when attached to \"global:\"");

	/* Check ipv4-defrag-out is NOT enabled on dpT10 */
	rv = dp_pipeline_is_feature_enabled_by_inst(
		"vyatta:ipv4-defrag-out", "dpT10");
	dp_test_fail_unless(!rv, "ipv4-defrag-out enabled on dpT10 "
			    "when attached to \"global:\"");

	dp_test_npf_cmd_fmt(debug,
			    "npf-ut detach global: originate fw:FW_ORIG");
	dp_test_npf_cmd_fmt(debug, "npf-ut delete fw:FW_ORIG");
	dp_test_npf_commit();

	rv = dp_pipeline_is_feature_enabled_by_inst("vyatta:ipv4-fw-orig",
						    "dpT10");
	dp_test_fail_unless(!rv, "ipv4-fw-orig is enabled");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

} DP_END_TEST;

/*
 * Test that the ipv4-fw-orig feature is enabled only on one interface when it
 * is attached to that interface.
 */
DP_START_TEST_FULL_RUN(npf_orig_feat, test2)
{
	bool rv, debug = false;

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

	rv = dp_pipeline_is_feature_enabled_by_inst("vyatta:ipv4-fw-orig",
						    "dpT10");
	dp_test_fail_unless(!rv, "ipv4-fw-orig is enabled");

	dp_test_npf_cmd_fmt(debug, "npf-ut add fw:FW_ORIG 1 action=accept");
	dp_test_npf_cmd_fmt(debug,
			    "npf-ut attach interface:dpT10 "
			    "originate fw:FW_ORIG");
	dp_test_npf_commit();

	/* Check ipv4-fw-orig is enabled on dpT10 */
	rv = dp_pipeline_is_feature_enabled_by_inst("vyatta:ipv4-fw-orig",
						    "dpT10");
	dp_test_fail_unless(rv, "ipv4-fw-orig not enabled on dpT10");

	/* Check ipv4-fw-orig is NOT enabled on dpT11 */
	rv = dp_pipeline_is_feature_enabled_by_inst("vyatta:ipv4-fw-orig",
						    "dpT11");
	dp_test_fail_unless(!rv, "ipv4-fw-orig enabled on dpT11");

	/* Check ipv4-defrag-out-spath is enabled on dpT10 */
	rv = dp_pipeline_is_feature_enabled_by_inst(
		"vyatta:ipv4-defrag-out-spath", "dpT10");
	dp_test_fail_unless(rv, "ipv4-defrag-out-spath not enabled on dpT10");

	/* Check ipv4-defrag-out-spath is NOT enabled on dpT11 */
	rv = dp_pipeline_is_feature_enabled_by_inst(
		"vyatta:ipv4-defrag-out-spath", "dpT11");
	dp_test_fail_unless(!rv, "ipv4-defrag-out-spath not enabled on dpT11");

	/* Check ipv4-defrag-out is NOT enabled on dpT10 */
	rv = dp_pipeline_is_feature_enabled_by_inst(
		"vyatta:ipv4-defrag-out", "dpT10");
	dp_test_fail_unless(!rv, "ipv4-defrag-out enabled on dpT10");

	dp_test_npf_cmd_fmt(debug,
			    "npf-ut detach interface:dpT10 "
			    "originate fw:FW_ORIG");
	dp_test_npf_cmd_fmt(debug, "npf-ut delete fw:FW_ORIG");
	dp_test_npf_commit();

	rv = dp_pipeline_is_feature_enabled_by_inst("vyatta:ipv4-fw-orig",
						    "dpT10");
	dp_test_fail_unless(!rv, "ipv4-fw-orig is enabled");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2",
				  "aa:bb:cc:dd:1:a1");

} DP_END_TEST;
