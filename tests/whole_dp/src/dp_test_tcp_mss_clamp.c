/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * TCP MSS Clamp test cases
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
#include "dp_test_netlink_state.h"
#include "dp_test_cmd_check.h"
#include "dp_test_lib.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_tcp.h"

#include "protobuf/TCPMSSConfig.pb-c.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"

static void
dp_test_create_and_send_tcpmss_msg(bool enable,
				   TCPMSSConfig__AddressFamily af,
				   const char *ifname,
				   TCPMSSConfig__MTUType mtu,
				   int mtu_val)
{
	int len;
	void *buf;

	TCPMSSConfig tcpmsscon = TCPMSSCONFIG__INIT;

	/* set values here */
	tcpmsscon.is_enable = enable;
	tcpmsscon.has_is_enable = true;
	tcpmsscon.af = af;
	tcpmsscon.has_af = true;
	tcpmsscon.ifname = (char *)ifname;
	if (mtu != TCPMSSCONFIG__MTUTYPE__NONE) {
		tcpmsscon.mtu_option = mtu;
		tcpmsscon.has_mtu_option = true;
	}
	if (mtu == TCPMSSCONFIG__MTUTYPE__MTU_MINUS ||
	    mtu == TCPMSSCONFIG__MTUTYPE__LIMIT) {
		tcpmsscon.value = mtu_val;
		tcpmsscon.has_value = true;
	}
	len = tcpmssconfig__get_packed_size(&tcpmsscon);
	void *buf2 = malloc(len);
	dp_test_assert_internal(buf2);

	tcpmssconfig__pack(&tcpmsscon, buf2);

	DataplaneEnvelope msg = DATAPLANE_ENVELOPE__INIT;
	msg.type = strdup("vyatta:tcp-mss");
	msg.msg.data = buf2;
	msg.msg.len = len;

	len = dataplane_envelope__get_packed_size(&msg);

	buf = malloc(len);
	dp_test_assert_internal(buf);

	dataplane_envelope__pack(&msg, buf);

	free(buf2);
	free(msg.type);

	dp_test_send_config_src_pb(dp_test_cont_src_get(), buf, len);
	free(buf);
}

/*
 * type:
 * 0 - none
 * 1 - TCP_MSS_CLAMP_MTU         max_mss = mtu - l3l4_size
 * 2 - TCP_MSS_CLAMP_MTU_MINUS   max_mss = mtu - l3l4_size - value
 * 3 - TCP_MSS_CLAMP_LIMIT       max_mss = value
 */
struct mss_clamp_cb_ctx {
	/* mss clamp rproc type and value */
	uint8_t  type;
	uint16_t value;

	/* mss value to use in the test packet */
	uint16_t pre_mss;

	/* Interface mtu */
	uint16_t mtu;

	/* address family */
	uint af;

	/* Size of the l3 and l4 headers */
	uint l3l4_size;
};

#define OPTS_LEN 9

#if 0
static char parse_err_str[10000];
static void
dp_test_print_ifconfig(const char *intf)
{
	json_object *jobj;
	const char *const_str;
	bool err;
	char real_ifname[IFNAMSIZ];
	char cmd[60];
	char *str;

	dp_test_intf_real(intf, real_ifname);
	snprintf(cmd, 60, "ifconfig %s", real_ifname);

	str = dp_test_console_request_w_err(cmd, &err, true);

	if (!str || err)
		return;

	jobj = parse_json(str, parse_err_str, sizeof(parse_err_str));
	free(str);

	const_str = json_object_to_json_string_ext(jobj,
						   JSON_C_TO_STRING_PRETTY);
	if (const_str)
		printf("%s\n", const_str);

	json_object_put(jobj);
}
#endif

/*
 * Set TCP options dependent upon: 1. SYN or SYN-ACK, 2. pre or post packet
 */
static void
dp_test_tcp_mss_opt(uint8_t flags, uint8_t *opts,
			struct mss_clamp_cb_ctx *ctx, bool pre_or_post)
{
	uint i;

	if (ctx->type == 0 || (flags & TH_SYN) == 0)
		return;

	/*
	 * Test with the MSS uint16 at both an even and odd byte boundary
	 */
	static uint8_t opts_syn[OPTS_LEN] = {
		3, 3, 1,
		1,		/* TCPOPT_NOP */
		2, 4, 0, 0,
		0		/* TCPOPT_EOL */
	};
	static uint8_t opts_synack[OPTS_LEN] = {
		3, 3, 1,
		2, 4, 0, 0,
		0,		/* TCPOPT_EOL */
		0
	};

	uint MSS_MSB = 0, MSS_LSB = 0;

	if (flags == TH_SYN) {
		MSS_MSB = 6;
		MSS_LSB = 7;

		for (i = 0; i < OPTS_LEN; i++)
			opts[i] = opts_syn[i];

	} else {
		MSS_MSB = 5;
		MSS_LSB = 6;

		for (i = 0; i < OPTS_LEN; i++)
			opts[i] = opts_synack[i];
	}

	/*
	 * Set the MSS value
	 */
	opts[MSS_MSB] = (ctx->pre_mss >> 8) & 0xFF;
	opts[MSS_LSB] = ctx->pre_mss & 0xFF;

	if (pre_or_post) {
		/*
		 * Post packet.  Adjust MSS is necessary.
		 */
		uint16_t mss_max = 0;

		switch (ctx->type) {
		case 1:
			/* TCP_MSS_CLAMP_MTU */
			mss_max = ctx->mtu;

			if (mss_max > ctx->l3l4_size)
				mss_max -= ctx->l3l4_size;
			break;
		case 2:
			/* TCP_MSS_CLAMP_MTU_MINUS */
			mss_max = ctx->mtu;

			if (mss_max > ctx->l3l4_size)
				mss_max -= ctx->l3l4_size;

			if (mss_max > ctx->value)
				mss_max -= ctx->value;
			break;
		case 3:
			/* TCP_MSS_CLAMP_LIMIT */
			mss_max = ctx->value;
			break;
		default:
			dp_test_fail("Unknown mss-clamp type");
		};

		if (ctx->pre_mss > mss_max) {
			opts[MSS_MSB] = (mss_max >> 8) & 0xFF;
			opts[MSS_LSB] = mss_max & 0xFF;
		}
	}
}

/*
 * Callback from dp_test_tcp_pak_receive.
 *
 * This is mainly a wrapper around dp_test_pak_receive.  We use it to setup
 * TCP options in the SYN and SYN-ACK packets.
 *
 * We have a SYN in the fwd direction and a SYN-ACK in the reverse direction.
 * There is a subtle different in the test code.  For the SYN-ACK we
 * increment the mbuf refcnt to cause the pipeline code to alloc and use
 * another buffer.
 */
static void
dp_test_tcp_test_cb(const char *str,
			uint pktno, enum dp_test_tcp_dir dir,
			uint8_t flags,
			struct dp_test_pkt_desc_t *pre,
			struct dp_test_pkt_desc_t *post,
			void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	struct mss_clamp_cb_ctx *ctx = data;

	static uint8_t tcp_opt_mss_pre[OPTS_LEN];
	static uint8_t tcp_opt_mss_post[OPTS_LEN];

	dp_test_tcp_mss_opt(pre->l4.tcp.flags, tcp_opt_mss_pre, ctx, false);
	dp_test_tcp_mss_opt(post->l4.tcp.flags, tcp_opt_mss_post, ctx, true);

	if (ctx->type != 0 && (pre->l4.tcp.flags & TH_SYN) != 0) {
		pre->l4.tcp.opts = tcp_opt_mss_pre;
		post->l4.tcp.opts = tcp_opt_mss_post;
	}

	if (ctx->af == AF_INET) {
		pre_pak = dp_test_v4_pkt_from_desc(pre);
		post_pak = dp_test_v4_pkt_from_desc(post);
	} else {
		pre_pak = dp_test_v6_pkt_from_desc(pre);
		post_pak = dp_test_v6_pkt_from_desc(post);
	}

	/*
	 * Test with refcnt == 1 for the SYN's and refcnt == 2 for the
	 * SYN-ACKS in order to test the call to
	 * pktmbuf_prepare_for_header_change in the mss clamp process.
	 */
	struct rte_mbuf *dupd_pak = NULL;

	if (pre->l4.tcp.flags == (TH_SYN | TH_ACK)) {
		dupd_pak = pre_pak;
		rte_mbuf_refcnt_update(dupd_pak, 1);
	}

	test_exp = dp_test_exp_from_desc(post_pak, post);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);
	rte_pktmbuf_free(post_pak);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	if (dupd_pak)
		rte_pktmbuf_free(dupd_pak);

	pre->l4.tcp.opts = NULL;
	post->l4.tcp.opts = NULL;

}

DP_DECL_TEST_SUITE(tcp_mss_clamp_suite);



DP_DECL_TEST_CASE(tcp_mss_clamp_suite, tcp_mss_clamp_ipv4, NULL, NULL);

/*
 * Tests TCP mss clamp for IPv4.   Four tests are run:
 *
 * 1.1  Clamp to input interface mtu
 * 1.2  Clamp to input interface mtu minus a value
 * 1.3  Clamp to a set limit on input
 * 1.4  Clamp to a set limit on output
 */
DP_START_TEST(tcp_mss_clamp_ipv4, test1)
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


	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = "aa:bb:cc:16:0:20",
		.l3_dst     = "200.201.202.203",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t ins_post = {
		.text       = "Inside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "100.101.102.103",
		.l2_src     = dp2T1_mac,
		.l3_dst     = "200.201.202.203",
		.l2_dst     = "aa:bb:cc:18:0:1",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs_pre = {
		.text       = "Outside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = "aa:bb:cc:18:0:1",
		.l3_dst     = "100.101.102.103",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t outs_post = {
		.text       = "Outside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "200.201.202.203",
		.l2_src     = dp1T0_mac,
		.l3_dst     = "100.101.102.103",
		.l2_dst     = "aa:bb:cc:16:0:20",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ins_pre,
			.post = &ins_post,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &outs_pre,
			.post = &outs_post,
		},
		.test_cb = dp_test_tcp_test_cb,
		.post_cb = NULL,
	};

	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 20, NULL},
		/* call truncated ... */
	};

	struct mss_clamp_cb_ctx ctx = {
		.type       = 1,     /* TCP_MSS_CLAMP_MTU */
		.value      = 0,
		.pre_mss    = 1600,
		.mtu        = 1500,
		.af         = AF_INET,
		/* IP + TCP (ignore options) */
		.l3l4_size  = 20 + 20,
	};

	char real_ifname[IFNAMSIZ];

	dp_test_intf_real("dp1T0", real_ifname);


	/*****************************************************************
	 * Test 1. Clamp to interface MTU
	 *****************************************************************/

	ctx.type       = 1;     /* TCP_MSS_CLAMP_MTU */
	ctx.value      = 0;
	ctx.pre_mss    = 1600;
	ctx.mtu        = 1500;

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "TCP mss clamp Test 1.1 - mtu");

	/* Enable the feature and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				   TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				   dp_test_intf_real("dp1T0", real_ifname),
				   TCPMSSCONFIG__MTUTYPE__MTU,
				   0);

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-tcp-mss-in",
				 "ipv4-validate");

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-tcp-mss-out",
				 "ipv4-out");

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/*****************************************************************
	 * Test 2. Clamp to interface MTU minus a value
	 *****************************************************************/

	ctx.type       = 2;     /* TCP_MSS_CLAMP_MTU_MINUS */
	ctx.value      = 40;
	ctx.pre_mss    = 1600;
	ctx.mtu        = 1500;

	/* IP + TCP (ignore options) */
	ctx.l3l4_size  = 20 + 20;

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "TCP mss clamp Test 1.2 - mtu-minus");

	/* Enable the feature and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__MTU_MINUS,
				  ctx.value);

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-tcp-mss-in",
				 "ipv4-validate");

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-tcp-mss-out",
				 "ipv4-out");

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/*****************************************************************
	 * Test 3. Clamp to fixed limit on input interface
	 *****************************************************************/

	ctx.type       = 3;     /* TCP_MSS_CLAMP_LIMIT */
	ctx.value      = 540;
	ctx.pre_mss    = 700;
	ctx.mtu        = 1500;

	/* IP + TCP */
	ctx.l3l4_size  = 20 + 20;

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "TCP mss clamp Test 1.3 - limit on input interface");

	/* Enable the feature and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				   TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				   dp_test_intf_real("dp1T0", real_ifname),
				   TCPMSSCONFIG__MTUTYPE__LIMIT,
				   ctx.value);

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-tcp-mss-in",
				 "ipv4-validate");

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-tcp-mss-out",
				 "ipv4-out");

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/* Disable the feature */
	dp_test_create_and_send_tcpmss_msg(false,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__NONE,
				  0);

	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-tcp-mss-in",
				      "ipv4-validate");

	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-tcp-mss-out",
				      "ipv4-out");


	/*****************************************************************
	 * Test 4. Clamp to fixed limit on output interface
	 *****************************************************************/

	/*
	 * We have a SYN in the fwd direction and a SYN-ACK in the reverse
	 * direction.  There is a subtle different in the test code.  For the
	 * SYN-ACK we increment the mbuf refcnt to cause the pipeline code to
	 * alloc and use another buffer.
	 */

	ctx.type       = 3;     /* TCP_MSS_CLAMP_LIMIT */
	ctx.value      = 540;
	ctx.pre_mss    = 700;
	ctx.mtu        = 1500;

	/* IP + TCP */
	ctx.l3l4_size  = 20 + 20;

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "TCP mss clamp Test 1.4 - limit on output interface");

	/* Enable the feature and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  dp_test_intf_real("dp2T1", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__LIMIT,
				  ctx.value);

	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv4-tcp-mss-in",
				 "ipv4-validate");

	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv4-tcp-mss-out",
				 "ipv4-out");
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/* Disable the feature */
	dp_test_create_and_send_tcpmss_msg(false,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  dp_test_intf_real("dp2T1", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__NONE,
				  0);

	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-tcp-mss-in",
				      "ipv4-validate");

	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-tcp-mss-out",
				      "ipv4-out");


	/*****************************************************************
	 * Test 5. Clamp to fixed limit on both interfaces, with different
	 * mss setting on each interface
	 *****************************************************************/

	ctx.type       = 3;     /* TCP_MSS_CLAMP_LIMIT */
	ctx.value      = 540;
	ctx.pre_mss    = 700;
	ctx.mtu        = 1500;

	/* IP + TCP */
	ctx.l3l4_size  = 20 + 20;

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "TCP mss clamp Test 1.5 - limit on both interfaces");

	/* Enable the feature on dp1T0 and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__LIMIT,
				  ctx.value + 10);

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-tcp-mss-in",
				 "ipv4-validate");

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv4-tcp-mss-out",
				 "ipv4-out");

	/* Enable the feature on dp2T1 and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  dp_test_intf_real("dp2T1", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__LIMIT,
				  ctx.value);

	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv4-tcp-mss-in",
				 "ipv4-validate");

	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv4-tcp-mss-out",
				 "ipv4-out");

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/* Disable the feature on dp1T0 */
	dp_test_create_and_send_tcpmss_msg(false,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__NONE,
				  0);

	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-tcp-mss-in",
				      "ipv4-validate");

	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv4-tcp-mss-out",
				      "ipv4-out");


	/* Disable the feature on dp2T1 */
	dp_test_create_and_send_tcpmss_msg(false,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  dp_test_intf_real("dp2T1", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__NONE,
				  0);

	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-tcp-mss-in",
				      "ipv4-validate");

	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-tcp-mss-out",
				      "ipv4-out");


	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_netlink_del_neigh("dp1T0", "100.101.102.103",
				  "aa:bb:cc:16:0:20");
	dp_test_netlink_del_neigh("dp2T1", "200.201.202.203",
				  "aa:bb:cc:18:0:1");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.101.102.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "200.201.202.1/24");

} DP_END_TEST;



DP_DECL_TEST_CASE(tcp_mss_clamp_suite, tcp_mss_clamp_ipv6, NULL, NULL);

/*
 * Tests TCP mss clamp for IPv6.   Four tests are run:
 *
 * 2.1  Clamp to input interface mtu
 * 2.2  Clamp to input interface mtu minus a value
 * 2.3  Clamp to a set limit on input
 */
DP_START_TEST(tcp_mss_clamp_ipv6, test1)
{
	char *dp1T0_mac = dp_test_intf_name2mac_str("dp1T0");
	char *dp2T1_mac = dp_test_intf_name2mac_str("dp2T1");


	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

	dp_test_netlink_add_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");


	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = dp1T0_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 0xDEAD,
				.dport = 0xBEEF,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t ins_post = {
		.text       = "Inside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2001:1:1::2",
		.l2_src     = dp2T1_mac,
		.l3_dst     = "2002:2:2::1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 0xDEAD,
				.dport = 0xBEEF,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	struct dp_test_pkt_desc_t outs_pre = {
		.text       = "Outside pre",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2002:2:2::1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "2001:1:1::2",
		.l2_dst     = dp2T1_mac,
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 0xBEEF,
				.dport = 0xDEAD,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t outs_post = {
		.text       = "Outside post",
		.len	= 0,
		.ether_type = ETHER_TYPE_IPv6,
		.l3_src     = "2002:2:2::1",
		.l2_src     = dp1T0_mac,
		.l3_dst     = "2001:1:1::2",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 0xBEEF,
				.dport = 0xDEAD,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ins_pre,
			.post = &ins_post,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &outs_pre,
			.post = &outs_post,
		},
		.test_cb = dp_test_tcp_test_cb,
		.post_cb = NULL,
	};

	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
		{DP_DIR_BACK, TH_ACK, 20, NULL},
		/* call truncated ... */
	};

	char real_ifname[IFNAMSIZ];

	dp_test_intf_real("dp1T0", real_ifname);


	/*****************************************************************
	 * Test 1. Clamp to interface MTU
	 *****************************************************************/

	struct mss_clamp_cb_ctx ctx = {
		.type       = 1,     /* TCP_MSS_CLAMP_MTU */
		.value      = 0,
		.pre_mss    = 1600,
		.mtu        = 1500,
		.af         = AF_INET6,
		/* IP + TCP */
		.l3l4_size  = 40 + 20,
	};

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "npf TCP mss clamp Test 2.1 - mtu");

	/* Enable the feature and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__MTU,
				  0);

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv6-tcp-mss-in",
				 "ipv6-validate");

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv6-tcp-mss-out",
				 "ipv6-out");

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/*****************************************************************
	 * Test 2. Clamp to interface MTU minus a value
	 *****************************************************************/

	ctx.type       = 2;     /* TCP_MSS_CLAMP_MTU_MINUS */
	ctx.value      = 40;
	ctx.pre_mss    = 1600;
	ctx.mtu        = 1500;
	/* IP + TCP */
	ctx.l3l4_size  = 40 + 20;

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "npf TCP mss clamp Test 2.2 - mtu-minus");

	/* Enable the feature and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__MTU_MINUS,
				  ctx.value);

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv6-tcp-mss-in",
				 "ipv6-validate");

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv6-tcp-mss-out",
				 "ipv6-out");

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/*****************************************************************
	 * Test 3. Clamp to fixed limit on input interface
	 *****************************************************************/

	ctx.type       = 3;     /* TCP_MSS_CLAMP_LIMIT */
	ctx.value      = 540;
	ctx.pre_mss    = 1000;
	ctx.mtu        = 1500;

	/* IP + TCP */
	ctx.l3l4_size  = 40 + 20;

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "npf TCP mss clamp Test 2.3 - limit on input interface");

	/* Enable the feature and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__LIMIT,
				  ctx.value);

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv6-tcp-mss-in",
				 "ipv6-validate");

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv6-tcp-mss-out",
				 "ipv6-out");

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/* Disable the feature */
	dp_test_create_and_send_tcpmss_msg(false,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__NONE,
				  0);

	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv6-tcp-mss-in",
				      "ipv6-validate");

	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv6-tcp-mss-out",
				      "ipv6-out");


	/*****************************************************************
	 * Test 4. Clamp to fixed limit on output interface
	 *****************************************************************/

	ctx.type       = 3;     /* TCP_MSS_CLAMP_LIMIT */
	ctx.value      = 540;
	ctx.pre_mss    = 1000;
	ctx.mtu        = 1500;

	/* IP + TCP */
	ctx.l3l4_size  = 40 + 20;

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "npf TCP mss clamp Test 2.4 - limit on output interface");

	/* Enable the feature and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp2T1", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__LIMIT,
				  ctx.value);

	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv6-tcp-mss-in",
				 "ipv6-validate");

	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv6-tcp-mss-out",
				 "ipv6-out");

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/* Disable the feature */
	dp_test_create_and_send_tcpmss_msg(false,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp2T1", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__NONE,
				  0);

	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv6-tcp-mss-in",
				      "ipv6-validate");

	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv6-tcp-mss-out",
				      "ipv6-out");

	/*****************************************************************
	 * Test 5. Clamp to a different fixed limit on both interfaces
	 *****************************************************************/

	ctx.type       = 3;     /* TCP_MSS_CLAMP_LIMIT */
	ctx.value      = 540;
	ctx.pre_mss    = 1000;
	ctx.mtu        = 1500;

	/* IP + TCP */
	ctx.l3l4_size  = 40 + 20;

	spush(tcp_call.str, sizeof(tcp_call.str),
	      "npf TCP mss clamp Test 2.5 - limit on both interface");

	/* Enable the feature on dp1T0 and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__LIMIT,
				  ctx.value + 10);

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv6-tcp-mss-in",
				 "ipv6-validate");

	dp_test_wait_for_pl_feat("dp1T0", "vyatta:ipv6-tcp-mss-out",
				 "ipv6-out");

	/* Enable the feature on dp2T1 and check it's there */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp2T1", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__LIMIT,
				  ctx.value);

	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv6-tcp-mss-in",
				 "ipv6-validate");

	dp_test_wait_for_pl_feat("dp2T1", "vyatta:ipv6-tcp-mss-out",
				 "ipv6-out");

	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1), &ctx, 0);


	/* Disable the feature on dp1T0 */
	dp_test_create_and_send_tcpmss_msg(false,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp1T0", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__NONE,
				  0);

	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv6-tcp-mss-in",
				      "ipv6-validate");

	dp_test_wait_for_pl_feat_gone("dp1T0", "vyatta:ipv6-tcp-mss-out",
				      "ipv6-out");

	/* Disable the feature on dp2T1 */
	dp_test_create_and_send_tcpmss_msg(false,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  dp_test_intf_real("dp2T1", real_ifname),
				  TCPMSSCONFIG__MTUTYPE__NONE,
				  0);

	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv6-tcp-mss-in",
				      "ipv6-validate");

	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv6-tcp-mss-out",
				      "ipv6-out");

	/*************************************************************
	 * Cleanup
	 *************************************************************/

	dp_test_netlink_del_neigh("dp1T0", "2001:1:1::2",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp2T1", "2002:2:2::1",
				  "aa:bb:cc:dd:2:b1");

	/* Setup interfaces and neighbours */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2001:1:1::1/64");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2002:2:2::2/64");

} DP_END_TEST;

/*
 * There can be a race between the configuration and interface netlink
 * messages arriving in the dataplane.  We get round this by storing the
 * config in a list if the interface does not exist, and then replaying it
 * when the interface is created.
 */
DP_START_TEST(tcp_mss_clamp_ipv4, test2)
{
	/*
	 * Send TCP MSS config down to dataplane before interface is created.
	 */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  "dpT10.100",
				  TCPMSSCONFIG__MTUTYPE__MTU,
				  0);

	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6,
				  "dpT10.100",
				  TCPMSSCONFIG__MTUTYPE__MTU,
				  0);

	dp_test_intf_vif_create("dp1T0.100", "dp1T0", 100);

	/* Verify pipeline feature is enabled on interface */
	dp_test_wait_for_pl_feat("dp1T0.100", "vyatta:ipv4-tcp-mss-in",
				 "ipv4-validate");

	dp_test_wait_for_pl_feat("dp1T0.100", "vyatta:ipv4-tcp-mss-out",
				 "ipv4-out");

	dp_test_wait_for_pl_feat("dp1T0.100", "vyatta:ipv6-tcp-mss-in",
				 "ipv6-validate");

	dp_test_wait_for_pl_feat("dp1T0.100", "vyatta:ipv6-tcp-mss-out",
				 "ipv6-out");

	dp_test_intf_vif_del("dp1T0.100", 100);

	/*
	 * Enable and then disable TCP MSS on a non-existent interface
	 */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  "dpT10.101",
				  TCPMSSCONFIG__MTUTYPE__MTU,
				  0);

	dp_test_create_and_send_tcpmss_msg(false,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  "dpT10.101",
				  TCPMSSCONFIG__MTUTYPE__NONE,
				  0);

	/*
	 * Change the TCP MSS config for an entry on the temporary list
	 */
	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  "dpT10.102",
				  TCPMSSCONFIG__MTUTYPE__MTU,
				  0);

	dp_test_create_and_send_tcpmss_msg(true,
				  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4,
				  "dpT10.102",
				  TCPMSSCONFIG__MTUTYPE__MTU_MINUS,
				  40);

	dp_test_intf_vif_create("dp1T0.102", "dp1T0", 102);

	/* Verify pipeline feature is enabled on interface */
	dp_test_wait_for_pl_feat("dp1T0.102", "vyatta:ipv4-tcp-mss-in",
				 "ipv4-validate");

	dp_test_wait_for_pl_feat("dp1T0.102", "vyatta:ipv4-tcp-mss-out",
				 "ipv4-out");

	dp_test_intf_vif_del("dp1T0.102", 102);

} DP_END_TEST;
