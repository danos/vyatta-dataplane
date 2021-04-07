/*
 * Copyright (c) 2021, SafePoint.  All rights reserved.
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test pipeline flowstat tests
 */

#include "compiler.h"
#include "dp_test/dp_test_lib.h"
#include "dp_test/dp_test_lib_intf.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test/dp_test_pktmbuf_lib.h"
#include "dp_test/dp_test_netlink_state.h"
#include "dp_test/dp_test_firewall_lib.h"
#include "dp_test/dp_test_session_lib.h"
#include "dp_test_lib_tcp.h"
#include "dp_test_npf_lib.h"

#include "dp_test_npf_sess_lib.h"
#include "dp_test_session_internal_lib.h"

#include <linux/if.h>

#include "flowstat.h"
#include "FlowStatFeatConfig.pb-c.h"
#include "FlowStatFeatOp.pb-c.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"

#include "pcap/http-example.h"
#include "pcap/http-google.h"

struct dp_test_flow_log_result {
	const char *src;
	int src_port;
	const char *dst;
	int dst_port;
	int protocol;
	uint64_t in_pkts;
	uint64_t out_pkts;
	const char *app;
	const char *app_proto;
	const char *app_type;
	const char *if_name;
};

static struct dpt_tcp_flow_pkt tcp_simple_pkt[] = {
	{DPT_FORW, TH_SYN, 0, NULL, 0, NULL},
	{DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL},
	{DPT_FORW, TH_ACK, 0, NULL, 0, NULL},
	{DPT_BACK, TH_ACK, 20, NULL, 0, NULL},
	{DPT_FORW, TH_ACK, 50, NULL, 0, NULL},
	{DPT_BACK, TH_FIN, 0, NULL, 0, NULL},
	{DPT_BACK, TH_ACK, 0, NULL, 0, NULL},
	{DPT_FORW, TH_FIN, 0, NULL, 0, NULL},
	{DPT_FORW, TH_ACK, 0, NULL, 0, NULL},
	{DPT_BACK, TH_ACK, 0, NULL, 0, NULL},
};

void _dp_test_remove_log_file(void)
{
	remove(FLOWSTAT_LOG);
}

void _dp_test_verify_log(const char *log,
			 const struct dp_test_flow_log_result *p,
			 const char *file, int line)
{
	char buf[100];

	sprintf(buf, "src_addr=%s ", p->src);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "src_port=%d ", p->src_port);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "dst_addr=%s ", p->dst);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "dst_port=%d ", p->dst_port);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "in_pkts=%lu ", p->in_pkts);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "out_pkts=%lu ", p->out_pkts);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "protocol=%d ", p->protocol);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "app_name=%s ", p->app);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "app_proto=%s ", p->app_proto);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "app_type=%s ", p->app_type);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);

	sprintf(buf, "if_name=\"%s\"", p->if_name);
	_dp_test_fail_unless(strstr(log, buf) != NULL, file, line,
			     "Expected %s", buf);
}

#define dp_test_verify_log(log, log_result) \
	_dp_test_verify_log(log, log_result, __FILE__, __LINE__)

void _dp_test_verify_log_file(const struct dp_test_flow_log_result *log_result,
			      size_t size,
			      const char *file, int line)
{
	char log_line[1000];

	FILE *f = fopen(FLOWSTAT_LOG, "r");
	_dp_test_fail_unless(f != NULL, file, line,
			     "Expected have log file %s", FLOWSTAT_LOG);

	for (size_t i = 0; i < size; i++) {
		char *rv = fgets(log_line, 1000, f);
		_dp_test_fail_unless(rv != NULL, file, line,
				     "Expected a log line");
		_dp_test_verify_log(log_line, &log_result[i], file, line);
	}

	fclose(f);
}

#define dp_test_verify_log_file(log_result, size) \
	_dp_test_verify_log_file(log_result, size, __FILE__, __LINE__)

void _dp_test_verify_no_log_file(const char *file, int line)
{
	FILE *f = fopen(FLOWSTAT_LOG, "rb");
	_dp_test_fail_unless(f == NULL, file, line,
			     "Expected no log file %s", FLOWSTAT_LOG);
}

#define dp_test_verify_no_log_file() \
	_dp_test_verify_no_log_file(__FILE__, __LINE__)

static void
dp_test_create_and_send_cfg_feat_msg(bool enable, const char *ifname)
{
	int len;
	FlowStatFeatConfig cfg = FLOW_STAT_FEAT_CONFIG__INIT;

	/* set values here */
	cfg.is_active = enable;
	cfg.has_is_active = true;
	/* strings don't have 'has_' */
	cfg.if_name = (char *)ifname;
	len = flow_stat_feat_config__get_packed_size(&cfg);
	void *buf2 = malloc(len);
	assert(buf2);

	flow_stat_feat_config__pack(&cfg, buf2);

	dp_test_lib_pb_wrap_and_send_pb("fstat:fstat-feat", buf2, len);
}

DP_DECL_TEST_SUITE(flowstat);

DP_DECL_TEST_CASE(flowstat, general, NULL, NULL);

/*
 * Test not enabled
 */
DP_START_TEST(general, not_enabled)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	_dp_test_remove_log_file();

	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		dp1T0_mac, "200.201.202.203", 80,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_TCP,
		dp2T1_mac, "100.101.102.103", 49152,
		"aa:bb:cc:18:0:1", "200.201.202.203", 80,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "200.201.202.203", 80,
		dp2T1_mac, "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_TCP,
		dp1T0_mac, "200.201.202.203", 80,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dpt_tcp_flow tcp_call = {
		.text[0] = '\0',
		.isn = {0, 0},
		.desc[DPT_FORW] = {
			.pre = ins_pre,
			.pst = ins_post,
		},
		.desc[DPT_BACK] = {
			.pre = outs_pre,
			.pst = outs_post,
		},
		.test_cb = NULL,
		.post_cb = NULL,
	};

	dpt_tcp_call(&tcp_call, tcp_simple_pkt, ARRAY_SIZE(tcp_simple_pkt),
		     0, 0, NULL, 0);

	/* Simulate export log */
	export_log();

	dp_test_verify_no_log_file();

	/*
	 * End
	 */

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;

DP_DECL_TEST_CASE(flowstat, logflow, NULL, NULL);

/*
 * Test Log simple tcp session
 */
DP_START_TEST(logflow, simple)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	_dp_test_remove_log_file();

	/* Enable the feature */
	char real_ifname[IFNAMSIZ];
	dp_test_create_and_send_cfg_feat_msg(
			true, dp_test_intf_real("dp2T1", real_ifname));

	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		dp1T0_mac, "200.201.202.203", 80,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_TCP,
		dp2T1_mac, "100.101.102.103", 49152,
		"aa:bb:cc:18:0:1", "200.201.202.203", 80,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "200.201.202.203", 80,
		dp2T1_mac, "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_TCP,
		dp1T0_mac, "200.201.202.203", 80,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dpt_tcp_flow tcp_call = {
		.text[0] = '\0',
		.isn = {0, 0},
		.desc[DPT_FORW] = {
			.pre = ins_pre,
			.pst = ins_post,
		},
		.desc[DPT_BACK] = {
			.pre = outs_pre,
			.pst = outs_post,
		},
		.test_cb = NULL,
		.post_cb = NULL,
	};

	dpt_tcp_call(&tcp_call, tcp_simple_pkt, ARRAY_SIZE(tcp_simple_pkt),
		     0, 0, NULL, 0);

	/* Simulate export log */
	export_log();

	struct dp_test_flow_log_result log_result = {
		.src = "100.101.102.103",
		.src_port = 49152,
		.dst = "200.201.202.203",
		.dst_port = 80,
		.protocol = IPPROTO_TCP,
		.in_pkts = 5,
		.out_pkts = 5,
		.app = "",
		.app_proto = "",
		.app_type = "",
		.if_name = dp_test_intf_real("dp2T1", real_ifname),
	};
	dp_test_verify_log_file(&log_result, 1);

	/*
	 * End
	 */

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_create_and_send_cfg_feat_msg(
			false, dp_test_intf_real("dp2T1", real_ifname));
	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;

/*
 * Test log long lived tcp session
 */
static void
dp_test_logflow_ll_tcp_post_cb(uint pktno, bool forw __unused,
			       uint8_t flags __unused,
			       struct dp_test_pkt_desc_t *pre __unused,
			       struct dp_test_pkt_desc_t *post __unused,
			       const char *desc __unused)
{
	if (pktno == 3)
		sleep(2);
}

DP_START_TEST(logflow, long_lived_tcp)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	_dp_test_remove_log_file();

	/* Enable the feature */
	char real_ifname[IFNAMSIZ];
	dp_test_create_and_send_cfg_feat_msg(
			true, dp_test_intf_real("dp2T1", real_ifname));

	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		dp1T0_mac, "200.201.202.203", 80,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_TCP,
		dp2T1_mac, "100.101.102.103", 49152,
		"aa:bb:cc:18:0:1", "200.201.202.203", 80,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "200.201.202.203", 80,
		dp2T1_mac, "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_TCP,
		dp1T0_mac, "200.201.202.203", 80,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dpt_tcp_flow tcp_call = {
		.text[0] = '\0',
		.isn = {0, 0},
		.desc[DPT_FORW] = {
			.pre = ins_pre,
			.pst = ins_post,
		},
		.desc[DPT_BACK] = {
			.pre = outs_pre,
			.pst = outs_post,
		},
		.test_cb = NULL,
		.post_cb = dp_test_logflow_ll_tcp_post_cb,
	};

	struct dpt_tcp_flow_pkt tcp_pkt1[] = {
		{DPT_FORW, TH_SYN, 0, NULL, 0, NULL},
		{DPT_BACK, TH_SYN | TH_ACK, 0, NULL, 0, NULL},
		{DPT_FORW, TH_ACK, 0, NULL, 0, NULL},
		{DPT_BACK, TH_ACK, 20, NULL, 0, NULL},
		/* long lived session */
		{DPT_FORW, TH_ACK, 50, NULL, 0, NULL},
		{DPT_BACK, TH_FIN, 0, NULL, 0, NULL},
		{DPT_BACK, TH_ACK, 0, NULL, 0, NULL},
		{DPT_FORW, TH_FIN, 0, NULL, 0, NULL},
		{DPT_FORW, TH_ACK, 0, NULL, 0, NULL},
		{DPT_BACK, TH_ACK, 0, NULL, 0, NULL},
	};

	dpt_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), 0, 0, NULL, 0);

	/* Simulate export log */
	export_log();

	struct dp_test_flow_log_result log_result[] = {{
		.src = "100.101.102.103",
		.src_port = 49152,
		.dst = "200.201.202.203",
		.dst_port = 80,
		.protocol = IPPROTO_TCP,
		.in_pkts = 2,
		.out_pkts = 3,
		.app = "",
		.app_proto = "",
		.app_type = "",
		.if_name = dp_test_intf_real("dp2T1", real_ifname),
	}, {
		.src = "100.101.102.103",
		.src_port = 49152,
		.dst = "200.201.202.203",
		.dst_port = 80,
		.protocol = IPPROTO_TCP,
		.in_pkts = 3,
		.out_pkts = 2,
		.app = "",
		.app_proto = "",
		.app_type = "",
		.if_name = dp_test_intf_real("dp2T1", real_ifname),
	}};
	dp_test_verify_log_file(log_result, ARRAY_SIZE(log_result));

	/*
	 * End
	 */

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_create_and_send_cfg_feat_msg(
			false, dp_test_intf_real("dp2T1", real_ifname));
	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;

/*
 *            100.101.102.x                  216.58.200.x
 *                            +----------+
 *                          .1|          |.1
 *    .103 -------------------|    UUT   |------------------ .78 (google.com)
 *                       dp1T0|          |dp2T1
 *                            +----------+
 *
 *
 * Test http get google.com
 */
DP_START_TEST(logflow, google)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "216.58.200.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "216.58.200.78",
				  "aa:bb:cc:18:0:1");

	_dp_test_remove_log_file();

	/* Enable the feature */
	char real_ifname[IFNAMSIZ];
	dp_test_create_and_send_cfg_feat_msg(
			true, dp_test_intf_real("dp2T1", real_ifname));

	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		dp1T0_mac, "216.58.200.78", 80,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_TCP,
		dp2T1_mac, "100.101.102.103", 49152,
		"aa:bb:cc:18:0:1", "216.58.200.78", 80,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "216.58.200.78", 80,
		dp2T1_mac, "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_TCP,
		dp1T0_mac, "216.58.200.78", 80,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	struct dp_test_npf_rule_t rules[] = {
		{
			.rule = "10",
			.pass = PASS,
			.stateful = STATEFUL,
			.npf = "to=any"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "FW1_OUT",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rules
	};

	dp_test_npf_fw_add(&fw, false);

	struct dpt_tcp_flow tcp_call = {
		.text[0] = '\0',
		.isn = {0, 0},
		.desc[DPT_FORW] = {
			.pre = ins_pre,
			.pst = ins_post,
		},
		.desc[DPT_BACK] = {
			.pre = outs_pre,
			.pst = outs_post,
		},
		.test_cb = NULL,
		.post_cb = NULL,
	};

	dpt_tcp_call(&tcp_call, http_google_pkt, ARRAY_SIZE(http_google_pkt),
		     0, 0, NULL, 0);

	/* Simulate export log */
	export_log();

	struct dp_test_flow_log_result log_result = {
		.src = "100.101.102.103",
		.src_port = 49152,
		.dst = "216.58.200.78",
		.dst_port = 80,
		.protocol = IPPROTO_TCP,
		.in_pkts = 8,
		.out_pkts = 8,
		.app = "",
		.app_proto = "",
		.app_type = "",
		.if_name = dp_test_intf_real("dp2T1", real_ifname),
	};
	dp_test_verify_log_file(&log_result, 1);

	/*
	 * End
	 */

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_create_and_send_cfg_feat_msg(
			false, dp_test_intf_real("dp2T1", real_ifname));
	dp_test_npf_fw_del(&fw, false);
	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "216.58.200.78",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "216.58.200.1/24");

} DP_END_TEST;

DP_DECL_TEST_CASE(flowstat, logflowdpi, NULL, NULL);

/*
 *            100.101.102.x                  93.184.216.x
 *                            +----------+
 *                          .1|          |.1
 *    .103 -------------------|    UUT   |------------------ .34 (example.com)
 *                       dp1T0|          |dp2T1
 *                            +----------+
 *
 *
 * http get example.com (with DPI)
 */
DP_START_TEST(logflowdpi, example)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "93.184.216.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "93.184.216.34",
				  "aa:bb:cc:18:0:1");

	_dp_test_remove_log_file();

	/* Enable the feature */
	char real_ifname[IFNAMSIZ];
	dp_test_create_and_send_cfg_feat_msg(
			true, dp_test_intf_real("dp2T1", real_ifname));

	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		dp1T0_mac, "93.184.216.34", 80,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_TCP,
		dp2T1_mac, "100.101.102.103", 49152,
		"aa:bb:cc:18:0:1", "93.184.216.34", 80,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "93.184.216.34", 80,
		dp2T1_mac, "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_TCP,
		dp1T0_mac, "93.184.216.34", 80,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	/*
	 * dpi app firewall
	 */
	dp_test_npf_cmd_fmt(false,
			    "npf-ut delete app-firewall:ALLOWED-SITES 10000");
	dp_test_npf_cmd_fmt(false, "npf-ut add app-firewall:ALLOWED-SITES 100 "
				   "action=accept engine=ndpi protocol=http");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false, "npf-ut add fw:DPI 200 action=accept "
				   "proto-final=6 stateful=y dst-port=80 "
				   "rproc=app-firewall(ALLOWED-SITES)");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut add fw:DPI 1000 action=accept stateful=y");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut attach interface:dpT21 fw-out fw:DPI");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");

	struct dpt_tcp_flow tcp_call = {
		.text[0] = '\0',
		.isn = {0, 0},
		.desc[DPT_FORW] = {
			.pre = ins_pre,
			.pst = ins_post,
		},
		.desc[DPT_BACK] = {
			.pre = outs_pre,
			.pst = outs_post,
		},
		.test_cb = NULL,
		.post_cb = NULL,
	};

	dpt_tcp_call(&tcp_call, http_example_pkt, ARRAY_SIZE(http_example_pkt),
		     0, 0, NULL, 0);

	/* Simulate export log */
	export_log();

	struct dp_test_flow_log_result log_result = {
		.src = "100.101.102.103",
		.src_port = 49152,
		.dst = "93.184.216.34",
		.dst_port = 80,
		.protocol = IPPROTO_TCP,
		.in_pkts = 8,
		.out_pkts = 8,
		.app = "HTTP",
		.app_proto = "HTTP",
		.app_type = "Web",
		.if_name = dp_test_intf_real("dp2T1", real_ifname),
	};
	dp_test_verify_log_file(&log_result, 1);

	/*
	 * End
	 */

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_create_and_send_cfg_feat_msg(
			false, dp_test_intf_real("dp2T1", real_ifname));

	dp_test_npf_cmd_fmt(false,
			    "npf-ut delete app-firewall:ALLOWED-SITES 10000");
	dp_test_npf_cmd_fmt(false, "npf-ut delete app-firewall:ALLOWED-SITES");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut detach interface:dpT21 fw-out fw:DPI");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false, "npf-ut delete fw:DPI");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");

	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "93.184.216.34",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "93.184.216.1/24");

} DP_END_TEST;

/*
 *            100.101.102.x                  216.58.200.x
 *                            +----------+
 *                          .1|          |.1
 *    .103 -------------------|    UUT   |------------------ .78 (google.com)
 *                       dp1T0|          |dp2T1
 *                            +----------+
 *
 *
 * http get google.com (with DPI)
 */
DP_START_TEST(logflowdpi, google)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "216.58.200.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "216.58.200.78",
				  "aa:bb:cc:18:0:1");

	_dp_test_remove_log_file();

	/* Enable the feature */
	char real_ifname[IFNAMSIZ];
	dp_test_create_and_send_cfg_feat_msg(
			true, dp_test_intf_real("dp2T1", real_ifname));

	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		dp1T0_mac, "216.58.200.78", 80,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_TCP,
		dp2T1_mac, "100.101.102.103", 49152,
		"aa:bb:cc:18:0:1", "216.58.200.78", 80,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "216.58.200.78", 80,
		dp2T1_mac, "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_TCP,
		dp1T0_mac, "216.58.200.78", 80,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	/*
	 * dpi app firewall
	 */
	dp_test_npf_cmd_fmt(false,
			    "npf-ut delete app-firewall:ALLOWED-SITES 10000");
	dp_test_npf_cmd_fmt(false, "npf-ut add app-firewall:ALLOWED-SITES 100 "
				   "action=accept engine=ndpi protocol=http");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false, "npf-ut add fw:DPI 200 action=accept "
				   "proto-final=6 stateful=y dst-port=80 "
				   "rproc=app-firewall(ALLOWED-SITES)");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut add fw:DPI 1000 action=accept stateful=y");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut attach interface:dpT21 fw-out fw:DPI");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");

	struct dpt_tcp_flow tcp_call = {
		.text[0] = '\0',
		.isn = {0, 0},
		.desc[DPT_FORW] = {
			.pre = ins_pre,
			.pst = ins_post,
		},
		.desc[DPT_BACK] = {
			.pre = outs_pre,
			.pst = outs_post,
		},
		.test_cb = NULL,
		.post_cb = NULL,
	};

	dpt_tcp_call(&tcp_call, http_google_pkt, ARRAY_SIZE(http_google_pkt),
		     0, 0, NULL, 0);

	/* Simulate export log */
	export_log();

	struct dp_test_flow_log_result log_result = {
		.src = "100.101.102.103",
		.src_port = 49152,
		.dst = "216.58.200.78",
		.dst_port = 80,
		.protocol = IPPROTO_TCP,
		.in_pkts = 8,
		.out_pkts = 8,
		.app = "Google",
		.app_proto = "HTTP",
		.app_type = "Web",
		.if_name = dp_test_intf_real("dp2T1", real_ifname),
	};
	dp_test_verify_log_file(&log_result, 1);

	/*
	 * End
	 */

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_create_and_send_cfg_feat_msg(
			false, dp_test_intf_real("dp2T1", real_ifname));

	dp_test_npf_cmd_fmt(false,
			    "npf-ut delete app-firewall:ALLOWED-SITES 10000");
	dp_test_npf_cmd_fmt(false, "npf-ut delete app-firewall:ALLOWED-SITES");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut detach interface:dpT21 fw-out fw:DPI");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false, "npf-ut delete fw:DPI");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");

	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "216.58.200.78", "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "216.58.200.1/24");
} DP_END_TEST;

/*
 *            100.101.102.x                  216.58.200.x
 *                            +----------+
 *                          .1|          |.1
 *    .103 -------------------|    UUT   |------------------ .78 (google.com)
 *                       dp1T0|          |dp2T1
 *                            +----------+
 *
 *
 * http get google.com expired session (with DPI)
 */
DP_START_TEST(logflowdpi, google_expired)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "216.58.200.1/24");

	dp_test_netlink_add_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_add_neigh("dp2T1", "216.58.200.78",
				  "aa:bb:cc:18:0:1");

	_dp_test_remove_log_file();

	/* Enable the feature */
	char real_ifname[IFNAMSIZ];
	dp_test_create_and_send_cfg_feat_msg(
		true, dp_test_intf_real("dp2T1", real_ifname));

	struct dp_test_pkt_desc_t *ins_pre, *ins_post;
	struct dp_test_pkt_desc_t *outs_pre, *outs_post;

	ins_pre = dpt_pdesc_v4_create(
		"Inside pre", IPPROTO_TCP,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		dp1T0_mac, "216.58.200.78", 80,
		"dp1T0", "dp2T1");

	ins_post = dpt_pdesc_v4_create(
		"Inside post", IPPROTO_TCP,
		dp2T1_mac, "100.101.102.103", 49152,
		"aa:bb:cc:18:0:1", "216.58.200.78", 80,
		"dp1T0", "dp2T1");

	outs_pre = dpt_pdesc_v4_create(
		"Outside pre", IPPROTO_TCP,
		"aa:bb:cc:18:0:1", "216.58.200.78", 80,
		dp2T1_mac, "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	outs_post = dpt_pdesc_v4_create(
		"Outside post", IPPROTO_TCP,
		dp1T0_mac, "216.58.200.78", 80,
		"aa:bb:cc:16:0:20", "100.101.102.103", 49152,
		"dp2T1", "dp1T0");

	/*
	 * dpi app firewall
	 */
	dp_test_npf_cmd_fmt(false,
			    "npf-ut delete app-firewall:ALLOWED-SITES 10000");
	dp_test_npf_cmd_fmt(false, "npf-ut add app-firewall:ALLOWED-SITES 100 "
				   "action=accept engine=ndpi protocol=http");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false, "npf-ut add fw:DPI 200 action=accept "
				   "proto-final=6 stateful=y dst-port=80 "
				   "rproc=app-firewall(ALLOWED-SITES)");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut add fw:DPI 1000 action=accept stateful=y");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut attach interface:dpT21 fw-out fw:DPI");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");

	struct dpt_tcp_flow tcp_call = {
		.text[0] = '\0',
		.isn = {0, 0},
		.desc[DPT_FORW] = {
			.pre = ins_pre,
			.pst = ins_post,
		},
		.desc[DPT_BACK] = {
			.pre = outs_pre,
			.pst = outs_post,
		},
		.test_cb = NULL,
		.post_cb = NULL,
	};

	/* Expected LAST-ACK state */
	dpt_tcp_call(&tcp_call, http_google_pkt,
		     ARRAY_SIZE(http_google_pkt) - 1,
		     0, 0, NULL, 0);

	/* Simulate session expired */
	dp_test_session_gc();

	/* Simulate export log */
	export_log();

	struct dp_test_flow_log_result log_result = {
		.src = "100.101.102.103",
		.src_port = 49152,
		.dst = "216.58.200.78",
		.dst_port = 80,
		.protocol = IPPROTO_TCP,
		.in_pkts = 7,
		.out_pkts = 8,
		.app = "Google",
		.app_proto = "HTTP",
		.app_type = "Web",
		.if_name = dp_test_intf_real("dp2T1", real_ifname),
	};
	dp_test_verify_log_file(&log_result, 1);

	/*
	 * End
	 */

	free(ins_pre);
	free(ins_post);
	free(outs_pre);
	free(outs_post);

	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_create_and_send_cfg_feat_msg(
		false, dp_test_intf_real("dp2T1", real_ifname));

	dp_test_npf_cmd_fmt(false,
			    "npf-ut delete app-firewall:ALLOWED-SITES 10000");
	dp_test_npf_cmd_fmt(false, "npf-ut delete app-firewall:ALLOWED-SITES");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut detach interface:dpT21 fw-out fw:DPI");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");
	dp_test_npf_cmd_fmt(false, "npf-ut delete fw:DPI");
	dp_test_npf_cmd_fmt(false, "npf-ut commit");

	dp_test_npf_clear_sessions();

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "216.58.200.78",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "216.58.200.1/24");

} DP_END_TEST;

static const char *plugin_name = "dp_test_pipeline_flowstat";

int dp_ut_plugin_init(const char **name)
{
	int rv = 0;

	*name = plugin_name;

	return rv;
}
