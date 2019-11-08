/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf alg ftp tests.
 *
 * alg_ftp1 - is a plain vanilla ftp call.  No firewall or nat. Passive ftp.
 *
 * alg_ftp2 - adds DNAT in the forwards direction (client-to-server).  There
 * is one ftp payload from the server (a 227 response) that gets reverse NAT'd
 * by the ftp alg.
 *
 * alg_ftp3 - is same as npf_alg_ftp2, but adds both interfaces to a vrf, and
 * then deletes the vrf while the ftp control and data sessions are still in
 * existence.
 *
 * alg_ftp4 - NATing from smaller prefix 10.25.1.0/24 to larger address
 * 159.8.106.21
 *
 * alg_ftp5 - NATing from larger prefix 10.250.100.0/24 to smaller address
 * 15.8.6.1
 *
 * alg_ftp7 - SNAT from client to server, Active ftp
 *
 * alg_ftp8 - SNAT from client to server, Active ftp. Deleting vrf.
 *
 * alg_ftp9 - Same as ftp_alg2, except no parenthesis around 227 msg.
 *
 *
 * To run each test in the chroot setup:
 *
 * make -j4 dataplane_test_run CK_RUN_CASE=alg_ftp1
 * make -j4 dataplane_test_run CK_RUN_CASE=alg_ftp2
 * make -j4 dataplane_test_run CK_RUN_CASE=alg_ftp3
 * make -j4 dataplane_test_run CK_RUN_CASE=alg_ftp4
 * make -j4 dataplane_test_run CK_RUN_CASE=alg_ftp5
 *
 * To run all the tests:
 *
 * make -j4 dataplane_test_run CK_RUN_SUITE=dp_test_npf_alg_ftp.c
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "npf/npf_state.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_netlink_state.h"
#include "dp_test_lib.h"
#include "dp_test_str.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_tcp.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"
#include "dp_test_npf_sess_lib.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_alg_lib.h"


DP_DECL_TEST_SUITE(npf_alg_ftp);

/***************************************************************************
 * alg_ftp1
 *
 * Simulates an ftp call via two TCP calls - one for control channel and one
 * for data channel.
 *
 * No firewall or NAT.
 *
 ***************************************************************************/

static struct dp_test_pkt_desc_t ftp1_fwd_in = {
	.text       = "ftp data Forwards In",
	.len        = 0,
	.ether_type = ETHER_TYPE_IPv4,
	.l3_src     = "1.1.1.11",
	.l2_src     = "aa:bb:cc:dd:1:11",
	.l3_dst     = "2.2.2.11",
	.l2_dst     = "00:00:a4:00:00:64",
	.proto      = IPPROTO_TCP,
	.l4	 = {
		.tcp = {
			.sport = 46682,
			.dport = 21,
			.flags = 0,
			.seq = 0,
			.ack = 0,
			.win = 8192,
			.opts = NULL
		}
	},
	.rx_intf    = "dp1T0",
	.tx_intf    = "dp1T1"
};

static struct dp_test_pkt_desc_t ftp1_fwd_out = {
	.text       = "ftp data Forwards Out",
	.len        = 0,
	.ether_type = ETHER_TYPE_IPv4,
	.l3_src     = "1.1.1.11",
	.l2_src     = "00:00:a4:00:00:64",
	.l3_dst     = "2.2.2.11",
	.l2_dst     = "aa:bb:cc:dd:2:11",
	.proto      = IPPROTO_TCP,
	.l4	 = {
		.tcp = {
			.sport = 46682,
			.dport = 21,
			.flags = 0,
			.seq = 0,
			.ack = 0,
			.win = 8192,
			.opts = NULL
		}
	},
	.rx_intf    = "dp1T0",
	.tx_intf    = "dp1T1"
};

static struct dp_test_pkt_desc_t ftp1_rev_in = {
	.text       = "ftp data Reverse In",
	.len        = 0,
	.ether_type = ETHER_TYPE_IPv4,
	.l3_src     = "2.2.2.11",
	.l2_src     = "aa:bb:cc:dd:2:11",
	.l3_dst     = "1.1.1.11",
	.l2_dst     = "00:00:a4:00:00:64",
	.proto      = IPPROTO_TCP,
	.l4	 = {
		.tcp = {
			.sport = 21,
			.dport = 46682,
			.flags = 0,
			.seq = 0,
			.ack = 0,
			.win = 8192,
			.opts = NULL
		}
	},
	.rx_intf    = "dp1T1",
	.tx_intf    = "dp1T0"
};

static struct dp_test_pkt_desc_t ftp1_rev_out = {
	.text       = "ftp data Reverse Out",
	.len        = 0,
	.ether_type = ETHER_TYPE_IPv4,
	.l3_src     = "2.2.2.11",
	.l2_src     = "00:00:a4:00:00:64",
	.l3_dst     = "1.1.1.11",
	.l2_dst     = "aa:bb:cc:dd:1:11",
	.proto      = IPPROTO_TCP,
	.l4	 = {
		.tcp = {
			.sport = 21,
			.dport = 46682,
			.flags = 0,
			.seq = 0,
			.ack = 0,
			.win = 8192,
			.opts = NULL
		}
	},
	.rx_intf    = "dp1T1",
	.tx_intf    = "dp1T0"
};

/*
 * This is used for all tests.
 */
static void ftp_data_call1(void)
{
	uint16_t fwd_in_sport = ftp1_fwd_in.l4.tcp.sport;
	uint16_t fwd_in_dport = ftp1_fwd_in.l4.tcp.dport;
	uint16_t fwd_out_sport = ftp1_fwd_out.l4.tcp.sport;
	uint16_t fwd_out_dport = ftp1_fwd_out.l4.tcp.dport;

	uint16_t rev_in_sport = ftp1_rev_in.l4.tcp.sport;
	uint16_t rev_in_dport = ftp1_rev_in.l4.tcp.dport;
	uint16_t rev_out_sport = ftp1_rev_out.l4.tcp.sport;
	uint16_t rev_out_dport = ftp1_rev_out.l4.tcp.dport;

	ftp1_fwd_in.l4.tcp.sport = 49888;
	ftp1_fwd_in.l4.tcp.dport = 9819;

	ftp1_fwd_out.l4.tcp.sport = 49888;
	ftp1_fwd_out.l4.tcp.dport = 9819;

	ftp1_rev_in.l4.tcp.sport = 9819;
	ftp1_rev_in.l4.tcp.dport = 49888;

	ftp1_rev_out.l4.tcp.sport = 9819;
	ftp1_rev_out.l4.tcp.dport = 49888;

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ftp1_fwd_in,
			.post = &ftp1_fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &ftp1_rev_in,
			.post = &ftp1_rev_out,
		},
		.test_cb = NULL,
		.post_cb = NULL,
	};

	struct dp_test_tcp_flow_pkt ftp_data_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		{DP_DIR_BACK, TH_ACK, 100, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, ftp_data_pkt1,
			 ARRAY_SIZE(ftp_data_pkt1),
			 NULL, 0);

	ftp1_fwd_in.l4.tcp.sport = fwd_in_sport;
	ftp1_fwd_in.l4.tcp.dport = fwd_in_dport;
	ftp1_fwd_out.l4.tcp.sport = fwd_out_sport;
	ftp1_fwd_out.l4.tcp.dport = fwd_out_dport;

	ftp1_rev_in.l4.tcp.sport = rev_in_sport;
	ftp1_rev_in.l4.tcp.dport = rev_in_dport;
	ftp1_rev_out.l4.tcp.sport = rev_out_sport;
	ftp1_rev_out.l4.tcp.dport = rev_out_dport;
}

/* 'data' context for callback */
struct ftp_ctx {
	const char	**payload;
	uint		payload_len;
	bool		do_data_call;
};

/*
 * Callback function for TCP call simulator for ftp control channel.
 *
 * This prepares the packet, including adding the payload, and then sends the
 * packet.
 *
 * This is used for all tests.
 */
static void tcp_ftp_control_cb1(const char *str,
				uint pktno, enum dp_test_tcp_dir dir,
				uint8_t flags,
				struct dp_test_pkt_desc_t *pre,
				struct dp_test_pkt_desc_t *post,
				void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	struct ftp_ctx *ctx = data;
	const char **ftp = ctx->payload;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	/*
	 * Add ftp payload
	 */
	if (ftp[pktno]) {
		dp_test_tcp_write_payload(pre_pak, strlen(ftp[pktno]),
					  ftp[pktno]);

		dp_test_tcp_write_payload(post_pak, strlen(ftp[pktno]),
					  ftp[pktno]);
	}

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Send the packet */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/*
	 * 227 is a Response from the server that contains the data channel
	 * address and port.  So we can startup the data channel tcp session
	 * here.
	 */
	if (ctx->do_data_call && ftp[pktno] && !strncmp(ftp[pktno], "227", 3))
		ftp_data_call1();
}

/*
 * alg_ftp1
 */
DP_DECL_TEST_CASE(npf_alg_ftp, alg_ftp1, NULL, NULL);
DP_START_TEST(alg_ftp1, test)
{
	uint vrfid = VRF_DEFAULT_ID;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	/*
	 * Packet descriptors of forw and back pre and post packets.
	 */
	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',			/* description */
		.isn = {0, 0},			/* initial seq no */
		.desc[DP_DIR_FORW] = {		/* Forw pkt descriptors */
			.pre = &ftp1_fwd_in,
			.post = &ftp1_fwd_out,
		},
		.desc[DP_DIR_BACK] = {		/* Back pkt descriptors */
			.pre = &ftp1_rev_in,
			.post = &ftp1_rev_out,
		},
		.test_cb = tcp_ftp_control_cb1,	/* Prep and send pkt */
		.post_cb = NULL,		/* Fixup pkt exp */
	};

	/*
	 * Payloads for TCP call
	 */
	const char *ftp[] = {
		[0] = NULL,
		[1] = NULL,
		[2] = NULL,

		[3] = "SYST\x0d\x0a",
		[4] = "215 UNIX Type: L8\x0d\x0a",

		[5] = "TYPE I\x0d\x0a",
		[6] = "200 Switching to Binary mode.\x0d\x0a",

		[7] = "PASV\x0d\x0a",

		/*
		 * Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		[8] = "227 Entering Passive Mode (2,2,2,11,38,91).\r\n",

		/*
		 * Here we get a new TCP call opened for the data channel,
		 * from 1.1.1.11:46682 to 2.2.2.11:9819
		 */

		[9] = NULL,
		[10] = NULL,
		[11] = NULL,
	};

	/*
	 * TCP call packet direction, flags, payload length.
	 */
	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		/* session established */
		{DP_DIR_FORW, TH_ACK, strlen(ftp[3]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[4]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[5]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[6]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[7]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[8]), NULL},

		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
	};
	assert(ARRAY_SIZE(ftp) == ARRAY_SIZE(tcp_pkt1));

	struct ftp_ctx ftp_ctx = {
		.payload = ftp,
		.payload_len = ARRAY_SIZE(ftp),
		.do_data_call = true,	/* Add data call */
	};

	/*
	 * Simulate the TCP call
	 */
	dp_test_tcp_call(&tcp_call,		/* Call context */
			 tcp_pkt1,		/* Per pkt context */
			 ARRAY_SIZE(tcp_pkt1),	/* number of pkts */
			 &ftp_ctx, 0);

	/* Cleanup */
	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrfid, 0);

} DP_END_TEST;


/***************************************************************************
 * alg_ftp2
 *
 * Simulates an ftp call via two TCP calls - one for control channel and one
 * for data channel.
 *
 * dnat is configured.  Destination address 2.2.2.12 is translated to
 * 2.2.2.11 for client-to-server traffic.
 *
 * The server includes the address 2.2.2.11 in its 227 Response packet, which
 * the ftp alg translates to 2.2.2.12.
 *
 ***************************************************************************/

/*
 * Callback function for TCP call simulator.  ftp control channel.
 */
static void tcp_ftp_control_cb2(const char *str,
				uint pktno, enum dp_test_tcp_dir dir,
				uint8_t flags,
				struct dp_test_pkt_desc_t *pre,
				struct dp_test_pkt_desc_t *post,
				void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	struct ftp_ctx *ctx = data;
	const char **ftp = ctx->payload;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	/*
	 * Add ftp payload
	 */
	if (ftp[pktno]) {
		const char *pre_ftp = ftp[pktno];
		const char *post_ftp = ftp[pktno];
		char rnatd[50];

		/* Reverse dNAT the ftp payload for 227 Response pkt */
		if (!strncmp("227 ", post_ftp, 4)) {
			snprintf(rnatd, sizeof(rnatd),
				 "227 Entering Passive Mode "
				 "(2,2,2,12,38,91).\r\n");
			post_ftp = rnatd;
		}

		dp_test_tcp_write_payload(pre_pak, strlen(pre_ftp), pre_ftp);
		dp_test_tcp_write_payload(post_pak, strlen(post_ftp), post_ftp);
	}

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Send the packet */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/*
	 * 227 is a Response from the server that contains the data channel
	 * address and port.  So we can startup the data channel tcp session
	 * here.
	 */
	if (ctx->do_data_call && ftp[pktno] && !strncmp(ftp[pktno], "227", 3))
		ftp_data_call1();
}

/*
 * alg_ftp2
 */
DP_DECL_TEST_CASE(npf_alg_ftp, alg_ftp2, NULL, NULL);
DP_START_TEST(alg_ftp2, test)
{
	uint vrfid = VRF_DEFAULT_ID;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	/*
	 * Add DNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "2.2.2.12",
		.to_port	= NULL,
		.trans_addr	= "2.2.2.11",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	ftp1_fwd_in.l4.tcp.sport = 46682;
	ftp1_fwd_in.l4.tcp.dport = 21;

	ftp1_fwd_out.l4.tcp.sport = 46682;
	ftp1_fwd_out.l4.tcp.dport = 21;

	ftp1_rev_in.l4.tcp.sport = 21;
	ftp1_rev_in.l4.tcp.dport = 46682;

	ftp1_rev_out.l4.tcp.sport = 21;
	ftp1_rev_out.l4.tcp.dport = 46682;

	ftp1_fwd_in.l3_dst = "2.2.2.12";
	ftp1_fwd_out.l3_dst = "2.2.2.11";

	ftp1_rev_in.l3_src = "2.2.2.11";
	ftp1_rev_out.l3_src = "2.2.2.12";

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ftp1_fwd_in,
			.post = &ftp1_fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &ftp1_rev_in,
			.post = &ftp1_rev_out,
		},
		.test_cb = tcp_ftp_control_cb2,
		.post_cb = NULL,
	};

	const char *ftp[] = {
		[0] = NULL,
		[1] = NULL,
		[2] = NULL,

		[3] = "SYST\x0d\x0a",
		[4] = "215 UNIX Type: L8\x0d\x0a",

		[5] = "TYPE I\x0d\x0a",
		[6] = "200 Switching to Binary mode.\x0d\x0a",

		[7] = "PASV\x0d\x0a",

		/*
		 * Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		[8] = "227 Entering Passive Mode (2,2,2,11,38,91).\x0d\x0a",

		/*
		 * Here we get a new TCP call opened for the data channel,
		 * from 1.1.1.11:46682 to 2.2.2.11:9819
		 */

		[9] = NULL,
		[10] = NULL,
		[11] = NULL,
	};


	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		/* session established */
		{DP_DIR_FORW, TH_ACK, strlen(ftp[3]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[4]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[5]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[6]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[7]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[8]), NULL},

		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
	};
	assert(ARRAY_SIZE(ftp) == ARRAY_SIZE(tcp_pkt1));

	struct ftp_ctx ftp_ctx = {
		.payload = ftp,
		.payload_len = ARRAY_SIZE(ftp),
		.do_data_call = true,	/* Add data call */
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1),
			 &ftp_ctx, 0);

	/* Cleanup */

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrfid, 0);

} DP_END_TEST;


/***************************************************************************
 * alg_ftp3
 *
 * Simulates an ftp call via two TCP calls - one for control channel and one
 * for data channel.
 *
 * dnat is configured.  Destination address 2.2.2.12 is translated to
 * 2.2.2.11 for client-to-server traffic.
 *
 * The server includes the address 2.2.2.11 in its 227 Response packet, which
 * the ftp alg translates to 2.2.2.12.
 *
 * Input and output interface are in a non-default VRF.
 *
 ***************************************************************************/

/*
 * alg_ftp3
 */
DP_DECL_TEST_CASE(npf_alg_ftp, alg_ftp3, NULL, NULL);
DP_START_TEST(alg_ftp3, test)
{
	uint vrfid = 69;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	/*
	 * Add DNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "2.2.2.12",
		.to_port	= NULL,
		.trans_addr	= "2.2.2.11",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	ftp1_fwd_in.l4.tcp.sport = 46682;
	ftp1_fwd_in.l4.tcp.dport = 21;

	ftp1_fwd_out.l4.tcp.sport = 46682;
	ftp1_fwd_out.l4.tcp.dport = 21;

	ftp1_rev_in.l4.tcp.sport = 21;
	ftp1_rev_in.l4.tcp.dport = 46682;

	ftp1_rev_out.l4.tcp.sport = 21;
	ftp1_rev_out.l4.tcp.dport = 46682;

	ftp1_fwd_in.l3_dst = "2.2.2.12";
	ftp1_fwd_out.l3_dst = "2.2.2.11";

	ftp1_rev_in.l3_src = "2.2.2.11";
	ftp1_rev_out.l3_src = "2.2.2.12";

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ftp1_fwd_in,
			.post = &ftp1_fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &ftp1_rev_in,
			.post = &ftp1_rev_out,
		},
		.test_cb = tcp_ftp_control_cb2,
		.post_cb = NULL,
	};

	const char *ftp[] = {
		[0] = NULL,
		[1] = NULL,
		[2] = NULL,

		[3] = "SYST\x0d\x0a",
		[4] = "215 UNIX Type: L8\x0d\x0a",

		[5] = "TYPE I\x0d\x0a",
		[6] = "200 Switching to Binary mode.\x0d\x0a",

		[7] = "PASV\x0d\x0a",

		/*
		 * Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		[8] = "227 Entering Passive Mode (2,2,2,11,38,91).\x0d\x0a",

		/*
		 * Here we get a new TCP call opened for the data channel,
		 * from 1.1.1.11:46682 to 2.2.2.11:9819
		 */
	};

	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		/* session established */
		{DP_DIR_FORW, TH_ACK, strlen(ftp[3]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[4]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[5]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[6]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[7]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[8]), NULL},

		/* call not completed */
	};
	assert(ARRAY_SIZE(ftp) == ARRAY_SIZE(tcp_pkt1));

	struct ftp_ctx ftp_ctx = {
		.payload = ftp,
		.payload_len = ARRAY_SIZE(ftp),
		.do_data_call = true,	/* Add data call */
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1),
			 &ftp_ctx, 0);

	/*
	 * ftp control and data channels established
	 */
#if 0
	dp_test_npf_print_session_table(false);
#endif

	/*
	 * Set true to delete vrf before sessions are expired.
	 */
	bool delete_vrf = true;

	if (delete_vrf && vrfid != VRF_DEFAULT_ID) {
		/*
		 * Delete vrf while there are ALG sessions
		 */
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
							 vrfid);
		dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
		dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);
		dp_test_netlink_del_vrf(vrfid, 0);
		dp_test_npf_clear_sessions();
	}

	/* Cleanup */

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	dp_test_npf_cleanup();

	if (!delete_vrf || vrfid == VRF_DEFAULT_ID) {
		/*
		 * Normal test cleanup.
		 */
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
							 vrfid);

		if (vrfid != VRF_DEFAULT_ID)
			dp_test_netlink_del_vrf(vrfid, 0);
	}

} DP_END_TEST;


/******************************************************************
 *
 * alg_ftp4
 *
 * This tests the ftp ALG and NAT where the ftp payload *increases* in size
 * due to NATed embedded address strings.
 *
 * alg_ftp5
 *
 * This tests the ftp ALG and NAT where the ftp payload *decreases* in size
 * due to NATed embedded address strings.
 *
 *****************************************************************/

/*
 * The core of each test is an ftp call that repeats this sequence 'n' times:
 *
 * Fwd:  PORT addr, port
 * Back: 200 ...
 * Fwd:  LIST ...
 * Back: 150 ...
 * Back: 226 ...
 * Fwd:  ack
 *
 * The 'n' repeat count is specified by these defines.  The port number is
 * incremented each repeat.
 */
#define NPF_ALG_FTP5_REPEATS 10
#define NPF_ALG_FTP6_REPEATS 10

static void
npf_alg_ftp_rx(struct dp_test_pkt_desc_t *pre,
	       const char *pre_pload, uint pre_plen,
	       struct dp_test_pkt_desc_t *post,
	       const char *post_pload, uint post_plen,
	       bool fwd)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;

	pre->len = pre_plen;
	post->len = post_plen;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	if (pre_pload)
		dp_test_tcp_write_payload(pre_pak, pre_plen, pre_pload);

	if (post_pload)
		dp_test_tcp_write_payload(post_pak, post_plen, post_pload);

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	/* Run the test */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
}


struct test_tcp {
	struct dp_test_pkt_desc_t *e2w_pre;
	struct dp_test_pkt_desc_t *e2w_post;
	struct dp_test_pkt_desc_t *w2e_pre;
	struct dp_test_pkt_desc_t *w2e_post;
	int east_seq;
	int east_ack;
	int west_seq;
	int west_ack;
	uint8_t *tcp_opts;
	/*
	 * seq/ack cumulative diff for east to west packets.  If > 0 then
	 * packets on west are larger than pkts on east.
	 */
	int e2w_diff;
	int w2e_diff;
};

/*
 * TCP packet, East to West
 */
static void
tcp_pak_rx_e2w(const char *desc, struct test_tcp *tcp, uint16_t tcp_flags,
	       const char *pre_pload, int pre_plen,
	       const char *post_pload, int post_plen)
{
	struct dp_test_pkt_desc_t *pre = tcp->e2w_pre;
	struct dp_test_pkt_desc_t *post = tcp->e2w_post;

	pre->l4.tcp.flags = tcp_flags;
	post->l4.tcp.flags = tcp_flags;

	/* Options are only added to the SYN or SYN|ACK */
	if (tcp_flags & TH_SYN) {
		pre->l4.tcp.opts = tcp->tcp_opts;
		post->l4.tcp.opts = tcp->tcp_opts;
	} else {
		pre->l4.tcp.opts = NULL;
		post->l4.tcp.opts = NULL;
	}
	pre->l4.tcp.seq = tcp->east_seq;
	pre->l4.tcp.ack = tcp->east_ack;

	post->l4.tcp.seq = tcp->east_seq + tcp->e2w_diff;
	post->l4.tcp.ack = tcp->east_ack - tcp->w2e_diff;

	if (!pre_pload || !post_pload)
		tcp->east_seq += 1;
	else
		tcp->east_seq += pre_plen;

	npf_alg_ftp_rx(pre, pre_pload, (uint)pre_plen,
		       post, post_pload, (uint)post_plen, true);

	if (!pre_pload || !post_pload)
		tcp->west_ack += 1;
	else
		tcp->west_ack += post_plen;

	if (pre_plen != post_plen)
		tcp->e2w_diff += post_plen - pre_plen;

}

/*
 * TCP packet, West to East
 */
static void
tcp_pak_rx_w2e(const char *desc, struct test_tcp *tcp, uint16_t tcp_flags,
	       const char *pre_pload, int pre_plen,
	       const char *post_pload, int post_plen)
{
	struct dp_test_pkt_desc_t *pre = tcp->w2e_pre;
	struct dp_test_pkt_desc_t *post = tcp->w2e_post;

	pre->l4.tcp.flags = tcp_flags;
	post->l4.tcp.flags = tcp_flags;

	if (tcp_flags & TH_SYN) {
		pre->l4.tcp.opts = tcp->tcp_opts;
		post->l4.tcp.opts = tcp->tcp_opts;
	} else {
		pre->l4.tcp.opts = NULL;
		post->l4.tcp.opts = NULL;
	}
	pre->l4.tcp.seq = tcp->west_seq;
	pre->l4.tcp.ack = tcp->west_ack;

	post->l4.tcp.seq = tcp->west_seq + tcp->w2e_diff;
	post->l4.tcp.ack = tcp->west_ack - tcp->e2w_diff;

	if (!pre_pload || !post_pload)
		tcp->west_seq += 1;
	else
		tcp->west_seq += pre_plen;

	npf_alg_ftp_rx(pre, pre_pload, (uint)pre_plen,
		       post, post_pload, (uint)post_plen, false);

	if (!pre_pload || !post_pload)
		tcp->east_ack += 1;
	else
		tcp->east_ack += post_plen;

	if (pre_plen != post_plen)
		tcp->w2e_diff += post_plen - pre_plen;

}

/*
 * NATing from smaller prefix 10.25.1.0/24 to larger address 159.8.106.21
 */
DP_DECL_TEST_CASE(npf_alg_ftp, alg_ftp4, NULL, NULL);
DP_START_TEST(alg_ftp4, test)
{
	uint vrfid = VRF_DEFAULT_ID;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "10.25.1.1/24",
						 vrfid);

	/* prefix 159.8.106.16/28 */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "159.8.106.21/28",
						 vrfid);

	dp_test_netlink_add_neigh("dp1T0", "10.25.1.20", "0:50:56:ac:ab:30");

	dp_test_netlink_add_neigh("dp1T1", "159.8.106.17",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("134.158.69.0/24 nh 159.8.106.17 int:dp1T1");

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp1T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "10.25.1.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * TCP packet
	 */
	struct dp_test_pkt_desc_t fwd_in = {
		.text       = "TCP Forwards In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "10.25.1.20",
		.l2_src     = "00:50:56:ac:ab:30",
		.l3_dst     = "134.158.69.171",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 58047,
				.dport = 21,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 14600,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0", /* East */
		.tx_intf    = "dp1T1"  /* West */
	};

	struct dp_test_pkt_desc_t rev_in = {
		.text       = "TCP Reverse In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "134.158.69.171",
		.l2_src     = "aa:bb:cc:dd:2:11",
		.l3_dst     = "159.8.106.21",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 21,
				.dport = 58047,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 14480,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t fwd_out, rev_out;

	/* East to west l2 and l3 changes at output */
	fwd_out = fwd_in;
	fwd_out.l3_src = "159.8.106.21";
	fwd_out.l2_src = "00:00:a4:00:00:64";
	fwd_out.l2_dst = "aa:bb:cc:dd:2:11";

	/* West to east l2 and l3 changes at output */
	rev_out = rev_in;
	rev_out.l3_dst = "10.25.1.20";
	rev_out.l2_src = "00:00:a4:00:00:64";
	rev_out.l2_dst = "00:50:56:ac:ab:30";

	uint8_t tcp_opts[] = {
		2, 4, 5, 180,	/* MSS 1460 bytes */
		4, 2,		/* SACK permitted */
		1,		/* NOOP */
		1,		/* NOOP */
		3, 3, 4,	/* Window scale 4 (x16) */
		1,		/* NOOP */
		0		/* marks end of opts */
	};

	/*
	 * TCP control structure
	 */
	struct test_tcp ttcp = {
		.e2w_pre = &fwd_in,
		.e2w_post = &fwd_out,
		.w2e_pre = &rev_in,
		.w2e_post = &rev_out,
		.east_seq = 0,
		.east_ack = 0,
		.west_seq = 0,
		.west_ack = 0,
		.tcp_opts = tcp_opts,
		.e2w_diff = 0,
		.w2e_diff = 0,
	};
	uint i;

#define FWD true
#define REV false

	/* Packet flow data structure */
	struct ftp_call {
		bool fwd;
		const char *desc;
		uint16_t flags;
		const char *prepl;
		const char *pstpl;
	};

	/*
	 * ftp call.
	 */
	struct ftp_call ftp_call_start[] = {
		{FWD, NULL, TH_SYN, NULL, NULL},
		{REV, NULL, TH_SYN|TH_ACK, NULL, NULL},
		{FWD, NULL, TH_ACK, NULL, NULL}
	};

	struct ftp_call ftp_call_end[] = {
		{FWD, NULL, TH_FIN|TH_ACK, NULL, NULL},
		{REV, NULL, TH_FIN|TH_ACK, NULL, NULL},
		{FWD, NULL, TH_ACK, NULL, NULL},
	};

	struct ftp_call ftp_call[] = {
		{FWD, "1", TH_ACK,  "PORT"},
		{REV, "2", TH_ACK|TH_PUSH,
		 "200 POST command successful. Consider using PASV.\x0d\x0a",
		 NULL},
		{FWD, "3", TH_ACK|TH_PUSH, "LIST\x0d\x0a", NULL},
		{REV, "4", TH_ACK|TH_PUSH,
		 "150 Here comes the directory listing.\x0d\x0a", NULL},
		{REV, "5", TH_ACK|TH_PUSH,
		 "226 Directory send OK.\x0d\x0a", NULL},
		{FWD, "6", TH_ACK, NULL, NULL},
	};

	/*
	 * TCP Call setup
	 */
	for (i = 0; i < ARRAY_SIZE(ftp_call_start); i++) {
		struct ftp_call *call = ftp_call_start;
		int pre_plen = 0, pst_plen = 0;

		if (call[i].prepl)
			pre_plen = strlen(call[i].prepl);
		if (call[i].pstpl)
			pst_plen = strlen(call[i].pstpl);

		if (call[i].fwd) {
			tcp_pak_rx_e2w(call[i].desc, &ttcp, call[i].flags,
				       call[i].prepl, pre_plen,
				       call[i].pstpl, pst_plen);
		} else {
			tcp_pak_rx_w2e(call[i].desc, &ttcp, call[i].flags,
				       call[i].prepl, pre_plen,
				       call[i].pstpl, pst_plen);
		}
	}

	/*
	 * FTP exchange: PORT, LIST, 150, 226
	 */
	uint16_t port = 51712; /* "202,0" */
	uint rpt, repeats = NPF_ALG_FTP5_REPEATS;
	struct test_tcp ttcp_copy = ttcp;

	for (rpt = 0; rpt < repeats; rpt++) {
		/*
		 * This simulates a retransmission of the previous set of
		 * packets.
		 */
		if (rpt == 6)
			ttcp = ttcp_copy;

		ttcp_copy = ttcp;

		for (i = 0; i < ARRAY_SIZE(ftp_call); i++) {
			struct ftp_call *call = ftp_call;
			int pre_plen = 0, pst_plen = 0;
			const char *prepl = call[i].prepl;
			const char *pstpl =
				call[i].pstpl ? call[i].pstpl : prepl;
			char pre_pload[100], pst_pload[100];

			if (prepl && !strcmp(prepl, "PORT")) {
				uint16_t p_msb = ((port+rpt) >> 8) & 0xFF;
				uint16_t p_lsb = (port+rpt) & 0xFF;

				snprintf(pre_pload, sizeof(pre_pload),
					 "PORT 10,25,1,20,%u,%u\x0d\x0a",
					 p_msb, p_lsb);
				snprintf(pst_pload, sizeof(pst_pload),
					 "PORT 159,8,106,21,%u,%u\x0d\x0a",
					 p_msb, p_lsb);

				prepl = pre_pload;
				pstpl = pst_pload;
			}

			if (prepl)
				pre_plen = strlen(prepl);
			if (pstpl)
				pst_plen = strlen(pstpl);

			if (call[i].fwd) {
				tcp_pak_rx_e2w(call[i].desc, &ttcp,
					       call[i].flags, prepl, pre_plen,
					       pstpl, pst_plen);
			} else {
				tcp_pak_rx_w2e(call[i].desc, &ttcp,
					       call[i].flags, prepl, pre_plen,
					       pstpl, pst_plen);
			}
		}
	}

	/*
	 * TCP Call finish
	 */
	for (i = 0; i < ARRAY_SIZE(ftp_call_end); i++) {
		struct ftp_call *call = ftp_call_end;
		int pre_plen = 0, pst_plen = 0;

		if (call[i].prepl)
			pre_plen = strlen(call[i].prepl);
		if (call[i].pstpl)
			pst_plen = strlen(call[i].pstpl);

		if (call[i].fwd) {
			tcp_pak_rx_e2w(call[i].desc, &ttcp, call[i].flags,
				       call[i].prepl, pre_plen,
				       call[i].pstpl, pst_plen);
		} else {
			tcp_pak_rx_w2e(call[i].desc, &ttcp, call[i].flags,
				       call[i].prepl, pre_plen,
				       call[i].pstpl, pst_plen);
		}
	}

	/* Cleanup */

	dp_test_netlink_del_route("134.158.69.0/24 nh 159.8.106.17 int:dp1T1");
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "10.25.1.1/24",
						 vrfid);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "159.8.106.21/28",
						 vrfid);

	dp_test_netlink_del_neigh("dp1T0", "10.25.1.20",
				  "0:50:56:ac:ab:30");
	dp_test_netlink_del_neigh("dp1T1", "159.8.106.17",
				  "aa:bb:cc:dd:2:11");

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrfid, 0);

} DP_END_TEST;

/*
 * NATing from larger prefix 10.250.100.0/24 to smaller address 15.8.6.1
 */
DP_DECL_TEST_CASE(npf_alg_ftp, alg_ftp5, NULL, NULL);
DP_START_TEST(alg_ftp5, test)
{
	uint vrfid = VRF_DEFAULT_ID;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "10.250.100.1/24",
						 vrfid);

	/* prefix 15.8.6.16/28 */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "15.8.6.1/28",
						 vrfid);

	dp_test_netlink_add_neigh("dp1T0", "10.250.100.20", "0:50:56:ac:ab:30");

	dp_test_netlink_add_neigh("dp1T1", "15.8.6.2",
				  "aa:bb:cc:dd:2:11");

	dp_test_netlink_add_route("134.158.69.0/24 nh 15.8.6.2 int:dp1T1");

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp1T1",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "10.250.100.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "masquerade",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * TCP packet
	 */
	struct dp_test_pkt_desc_t fwd_in = {
		.text       = "TCP Forwards In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "10.250.100.20",
		.l2_src     = "00:50:56:ac:ab:30",
		.l3_dst     = "134.158.69.171",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 58047,
				.dport = 21,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 14600,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0", /* East */
		.tx_intf    = "dp1T1"  /* West */
	};

	struct dp_test_pkt_desc_t rev_in = {
		.text       = "TCP Reverse In",
		.len        = 0,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = "134.158.69.171",
		.l2_src     = "aa:bb:cc:dd:2:11",
		.l3_dst     = "15.8.6.1",
		.l2_dst     = "00:00:a4:00:00:64",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = 21,
				.dport = 58047,
				.flags = 0,
				.seq = 0,
				.ack = 0,
				.win = 14480,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T1",
		.tx_intf    = "dp1T0"
	};

	struct dp_test_pkt_desc_t fwd_out, rev_out;

	/* East to west l2 and l3 changes at output */
	fwd_out = fwd_in;
	fwd_out.l3_src = "15.8.6.1";
	fwd_out.l2_src = "00:00:a4:00:00:64";
	fwd_out.l2_dst = "aa:bb:cc:dd:2:11";

	/* West to east l2 and l3 changes at output */
	rev_out = rev_in;
	rev_out.l3_dst = "10.250.100.20";
	rev_out.l2_src = "00:00:a4:00:00:64";
	rev_out.l2_dst = "00:50:56:ac:ab:30";

	uint8_t tcp_opts[] = {
		2, 4, 5, 180,	/* MSS 1460 bytes */
		4, 2,		/* SACK permitted */
		1,		/* NOOP */
		1,		/* NOOP */
		3, 3, 4,	/* Window scale 4 (x16) */
		1,		/* NOOP */
		0		/* marks end of opts */
	};

	/*
	 * TCP control structure
	 */
	struct test_tcp ttcp = {
		.e2w_pre = &fwd_in,
		.e2w_post = &fwd_out,
		.w2e_pre = &rev_in,
		.w2e_post = &rev_out,
		.east_seq = 0,
		.east_ack = 0,
		.west_seq = 0,
		.west_ack = 0,
		.tcp_opts = tcp_opts,
		.e2w_diff = 0,
		.w2e_diff = 0,
	};
	uint i;

#define FWD true
#define REV false

	/* Packet flow data structure */
	struct ftp_call {
		bool fwd;
		const char *desc;
		uint16_t flags;
		const char *prepl;
		const char *pstpl;
	};

	/*
	 * ftp call.
	 */
	struct ftp_call ftp_call_start[] = {
		{FWD, NULL, TH_SYN, NULL, NULL},
		{REV, NULL, TH_SYN|TH_ACK, NULL, NULL},
		{FWD, NULL, TH_ACK, NULL, NULL}
	};

	struct ftp_call ftp_call_end[] = {
		{FWD, NULL, TH_FIN|TH_ACK, NULL, NULL},
		{REV, NULL, TH_FIN|TH_ACK, NULL, NULL},
		{FWD, NULL, TH_ACK, NULL, NULL},
	};

	struct ftp_call ftp_call[] = {
		{FWD, "1", TH_ACK,  "PORT"},
		{REV, "2", TH_ACK|TH_PUSH,
		 "200 POST command successful. Consider using PASV.\x0d\x0a",
		 NULL},

		{FWD, "3", TH_ACK|TH_PUSH,
		 "LIST\x0d\x0a", NULL},
		{REV, "4", TH_ACK|TH_PUSH,
		 "150 Here comes the directory listing.\x0d\x0a", NULL},
		{REV, "5", TH_ACK|TH_PUSH,
		 "226 Directory send OK.\x0d\x0a", NULL},
		{FWD, "6", TH_ACK, NULL, NULL},
	};

	/*
	 * TCP Call setup
	 */
	for (i = 0; i < ARRAY_SIZE(ftp_call_start); i++) {
		struct ftp_call *call = ftp_call_start;
		int pre_plen = 0, pst_plen = 0;

		if (call[i].prepl)
			pre_plen = strlen(call[i].prepl);
		if (call[i].pstpl)
			pst_plen = strlen(call[i].pstpl);

		if (call[i].fwd) {
			tcp_pak_rx_e2w(call[i].desc, &ttcp, call[i].flags,
				       call[i].prepl, pre_plen,
				       call[i].pstpl, pst_plen);
		} else {
			tcp_pak_rx_w2e(call[i].desc, &ttcp, call[i].flags,
				       call[i].prepl, pre_plen,
				       call[i].pstpl, pst_plen);
		}
	}

	/*
	 * FTP exchange: PORT, LIST, 150, 226
	 */
	uint16_t port = 51712; /* "202,0" */
	uint rpt, repeats = NPF_ALG_FTP6_REPEATS;
	struct test_tcp ttcp_copy = ttcp;

	for (rpt = 0; rpt < repeats; rpt++) {
		/*
		 * This simulates a retransmission of the previous set of
		 * packets.
		 */
		if (rpt == 6)
			ttcp = ttcp_copy;

		ttcp_copy = ttcp;

		for (i = 0; i < ARRAY_SIZE(ftp_call); i++) {
			struct ftp_call *call = ftp_call;
			int pre_plen = 0, pst_plen = 0;
			const char *prepl = call[i].prepl;
			const char *pstpl =
				call[i].pstpl ? call[i].pstpl : prepl;
			char pre_pload[100], pst_pload[100];

			if (prepl && !strcmp(prepl, "PORT")) {
				uint16_t p_msb = ((port+rpt) >> 8) & 0xFF;
				uint16_t p_lsb = (port+rpt) & 0xFF;

				snprintf(pre_pload, sizeof(pre_pload),
					 "PORT 10,250,100,20,%u,%u\x0d\x0a",
					 p_msb, p_lsb);
				snprintf(pst_pload, sizeof(pst_pload),
					 "PORT 15,8,6,1,%u,%u\x0d\x0a",
					 p_msb, p_lsb);

				prepl = pre_pload;
				pstpl = pst_pload;
			}

			if (prepl)
				pre_plen = strlen(prepl);
			if (pstpl)
				pst_plen = strlen(pstpl);

			if (call[i].fwd) {
				tcp_pak_rx_e2w(call[i].desc, &ttcp,
					       call[i].flags, prepl, pre_plen,
					       pstpl, pst_plen);
			} else {
				tcp_pak_rx_w2e(call[i].desc, &ttcp,
					       call[i].flags, prepl, pre_plen,
					       pstpl, pst_plen);
			}
		}
	}

	/*
	 * TCP Call finish
	 */
	for (i = 0; i < ARRAY_SIZE(ftp_call_end); i++) {
		struct ftp_call *call = ftp_call_end;
		int pre_plen = 0, pst_plen = 0;

		if (call[i].prepl)
			pre_plen = strlen(call[i].prepl);
		if (call[i].pstpl)
			pst_plen = strlen(call[i].pstpl);

		if (call[i].fwd) {
			tcp_pak_rx_e2w(call[i].desc, &ttcp, call[i].flags,
				       call[i].prepl, pre_plen,
				       call[i].pstpl, pst_plen);
		} else {
			tcp_pak_rx_w2e(call[i].desc, &ttcp, call[i].flags,
				       call[i].prepl, pre_plen,
				       call[i].pstpl, pst_plen);
		}
	}

	/* Cleanup */

	dp_test_netlink_del_route("134.158.69.0/24 nh 15.8.6.2 int:dp1T1");
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "10.250.100.1/24",
						 vrfid);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "15.8.6.1/28",
						 vrfid);

	dp_test_netlink_del_neigh("dp1T0", "10.250.100.20",
				  "0:50:56:ac:ab:30");
	dp_test_netlink_del_neigh("dp1T1", "15.8.6.2",
				  "aa:bb:cc:dd:2:11");

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrfid, 0);

} DP_END_TEST;


/*********************************************************************
 * alg_ftp6
 *
 * Same as alg_ftp3, except we stop all packets and delete the vrf just after
 * the secondary tuple has been created.
 */

DP_DECL_TEST_CASE(npf_alg_ftp, alg_ftp6, NULL, NULL);
DP_START_TEST(alg_ftp6, test)
{
	uint vrfid = 69;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	/*
	 * Add DNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "2.2.2.12",
		.to_port	= NULL,
		.trans_addr	= "2.2.2.11",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	ftp1_fwd_in.l4.tcp.sport = 46682;
	ftp1_fwd_in.l4.tcp.dport = 21;

	ftp1_fwd_out.l4.tcp.sport = 46682;
	ftp1_fwd_out.l4.tcp.dport = 21;

	ftp1_rev_in.l4.tcp.sport = 21;
	ftp1_rev_in.l4.tcp.dport = 46682;

	ftp1_rev_out.l4.tcp.sport = 21;
	ftp1_rev_out.l4.tcp.dport = 46682;

	ftp1_fwd_in.l3_dst = "2.2.2.12";
	ftp1_fwd_out.l3_dst = "2.2.2.11";

	ftp1_rev_in.l3_src = "2.2.2.11";
	ftp1_rev_out.l3_src = "2.2.2.12";

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ftp1_fwd_in,
			.post = &ftp1_fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &ftp1_rev_in,
			.post = &ftp1_rev_out,
		},
		.test_cb = tcp_ftp_control_cb2,
		.post_cb = NULL,
	};

	const char *ftp[] = {
		[0] = NULL,
		[1] = NULL,
		[2] = NULL,

		[3] = "SYST\x0d\x0a",
		[4] = "215 UNIX Type: L8\x0d\x0a",

		[5] = "TYPE I\x0d\x0a",
		[6] = "200 Switching to Binary mode.\x0d\x0a",

		[7] = "PASV\x0d\x0a",

		/*
		 * Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		[8] = "227 Entering Passive Mode (2,2,2,11,38,91).\x0d\x0a",

		/*
		 * Here we delete the vrf
		 */
	};


	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		/* session established */
		{DP_DIR_FORW, TH_ACK, strlen(ftp[3]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[4]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[5]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[6]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[7]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[8]), NULL},

		/* call not completed */
	};
	assert(ARRAY_SIZE(ftp) == ARRAY_SIZE(tcp_pkt1));

	struct ftp_ctx ftp_ctx = {
		.payload = ftp,
		.payload_len = ARRAY_SIZE(ftp),
		.do_data_call = false,
	};

	/* Simulate the partial ftp flow */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1),
			 &ftp_ctx, 0);

	/*
	 * ftp control and data channels established
	 */

	/*
	 * Set true to delete vrf before sessions are expired.
	 */
	bool delete_vrf = true;

	if (delete_vrf && vrfid != VRF_DEFAULT_ID) {
		/*
		 * Delete vrf while there are ALG sessions
		 */
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
							 vrfid);
		dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
		dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);
		dp_test_netlink_del_vrf(vrfid, 0);
		dp_test_npf_clear_sessions();
	}

	/* Cleanup */

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	dp_test_npf_cleanup();

	if (!delete_vrf || vrfid == VRF_DEFAULT_ID) {
		/*
		 * Normal test cleanup.
		 */
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
							 vrfid);

		if (vrfid != VRF_DEFAULT_ID)
			dp_test_netlink_del_vrf(vrfid, 0);
	}

} DP_END_TEST;


/***************************************************************************
 * alg_ftp7 -- SNAT from client to server, Active ftp
 *
 *                  dp1T0         dp1T1
 *        1.1.1.11                      2.2.2.11 (src, pre)
 *                                      2.2.2.12 (src, post
 *        Server                        Client
 * 1.               21     <-----       1026           "PORT 1027"
 * 2.               21     ----->       1026           ack
 * 3.     20               ----->               1027
 * 4.     20               <-----               1027   ack
 *
 * Simulates an ftp call via two TCP calls - one for control channel and one
 * for data channel.
 *
 * snat is configured.  Source address 2.2.2.11 is translated to 2.2.2.12 for
 * client-to-server traffic.
 *
 * Input and output interface are in default VRF.
 *
 ***************************************************************************/

/*
 * TCP packet
 */
static struct dp_test_pkt_desc_t ftp7_fwd_in = {
	.text       = "TCP Forwards In",
	.len        = 0,
	.ether_type = ETHER_TYPE_IPv4,
	.l3_src     = "2.2.2.11",
	.l2_src     = "aa:bb:cc:dd:2:11",
	.l3_dst     = "1.1.1.11",
	.l2_dst     = "00:00:a4:00:00:64",
	.proto      = IPPROTO_TCP,
	.l4	 = {
		.tcp = {
			.sport = 1026,
			.dport = 21,
			.flags = 0,
			.seq = 0,
			.ack = 0,
			.win = 8192,
			.opts = NULL
		}
	},
	.rx_intf    = "dp1T1",
	.tx_intf    = "dp1T0"
};

static struct dp_test_pkt_desc_t ftp7_fwd_out = {
	.text       = "TCP Forwards Out",
	.len        = 0,
	.ether_type = ETHER_TYPE_IPv4,
	.l3_src     = "2.2.2.12",
	.l2_src     = "00:00:a4:00:00:64",
	.l3_dst     = "1.1.1.11",
	.l2_dst     = "aa:bb:cc:dd:1:11",
	.proto      = IPPROTO_TCP,
	.l4	 = {
		.tcp = {
			.sport = 1026,
			.dport = 21,
			.flags = 0,
			.seq = 0,
			.ack = 0,
			.win = 8192,
			.opts = NULL
		}
	},
	.rx_intf    = "dp1T1",
	.tx_intf    = "dp1T0"
};

static struct dp_test_pkt_desc_t ftp7_rev_in = {
	.text       = "TCP Reverse In",
	.len        = 0,
	.ether_type = ETHER_TYPE_IPv4,
	.l3_src     = "1.1.1.11",
	.l2_src     = "aa:bb:cc:dd:1:11",
	.l3_dst     = "2.2.2.12",
	.l2_dst     = "00:00:a4:00:00:64",
	.proto      = IPPROTO_TCP,
	.l4	 = {
		.tcp = {
			.sport = 21,
			.dport = 1026,
			.flags = 0,
			.seq = 0,
			.ack = 0,
			.win = 8192,
			.opts = NULL
		}
	},
	.rx_intf    = "dp1T0",
	.tx_intf    = "dp1T1"
};

static struct dp_test_pkt_desc_t ftp7_rev_out = {
	.text       = "TCP Reverse Out",
	.len        = 0,
	.ether_type = ETHER_TYPE_IPv4,
	.l3_src     = "1.1.1.11",
	.l2_src     = "00:00:a4:00:00:64",
	.l3_dst     = "2.2.2.11",
	.l2_dst     = "aa:bb:cc:dd:2:11",
	.proto      = IPPROTO_TCP,
	.l4	 = {
		.tcp = {
			.sport = 21,
			.dport = 1026,
			.flags = 0,
			.seq = 0,
			.ack = 0,
			.win = 8192,
			.opts = NULL
		}
	},
	.rx_intf    = "dp1T0",
	.tx_intf    = "dp1T1"
};

/*
 * Active ftp data flow starts in the reverse direction
 */
static void ftp_data_call7(void)
{
	uint16_t fwd_in_sport = ftp7_fwd_in.l4.tcp.sport;
	uint16_t fwd_in_dport = ftp7_fwd_in.l4.tcp.dport;
	uint16_t fwd_out_sport = ftp7_fwd_out.l4.tcp.sport;
	uint16_t fwd_out_dport = ftp7_fwd_out.l4.tcp.dport;

	uint16_t rev_in_sport = ftp7_rev_in.l4.tcp.sport;
	uint16_t rev_in_dport = ftp7_rev_in.l4.tcp.dport;
	uint16_t rev_out_sport = ftp7_rev_out.l4.tcp.sport;
	uint16_t rev_out_dport = ftp7_rev_out.l4.tcp.dport;

	ftp7_rev_in.l4.tcp.sport = 20;
	ftp7_rev_in.l4.tcp.dport = 1027;

	ftp7_rev_out.l4.tcp.sport = 20;
	ftp7_rev_out.l4.tcp.dport = 1027;

	ftp7_fwd_in.l4.tcp.sport = 1027;
	ftp7_fwd_in.l4.tcp.dport = 20;

	ftp7_fwd_out.l4.tcp.sport = 1027;
	ftp7_fwd_out.l4.tcp.dport = 20;

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ftp7_rev_in,
			.post = &ftp7_rev_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &ftp7_fwd_in,
			.post = &ftp7_fwd_out,
		},
		.test_cb = NULL,
		.post_cb = NULL,
	};

	struct dp_test_tcp_flow_pkt ftp_data_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		/* call not completed */
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, ftp_data_pkt1,
			 ARRAY_SIZE(ftp_data_pkt1),
			 NULL, 0);

	ftp7_fwd_in.l4.tcp.sport = fwd_in_sport;
	ftp7_fwd_in.l4.tcp.dport = fwd_in_dport;
	ftp7_fwd_out.l4.tcp.sport = fwd_out_sport;
	ftp7_fwd_out.l4.tcp.dport = fwd_out_dport;

	ftp7_rev_in.l4.tcp.sport = rev_in_sport;
	ftp7_rev_in.l4.tcp.dport = rev_in_dport;
	ftp7_rev_out.l4.tcp.sport = rev_out_sport;
	ftp7_rev_out.l4.tcp.dport = rev_out_dport;
}

/*
 * Callback function for TCP call simulator.  ftp control channel.
 */
static void tcp_ftp_control_cb7(const char *str,
				uint pktno, enum dp_test_tcp_dir dir,
				uint8_t flags,
				struct dp_test_pkt_desc_t *pre,
				struct dp_test_pkt_desc_t *post,
				void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	struct ftp_ctx *ctx = data;
	const char **ftp = ctx->payload;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	/*
	 * Add ftp payload
	 */
	if (ftp[pktno]) {
		const char *pre_ftp = ftp[pktno];
		const char *post_ftp = ftp[pktno];
		char rnatd[50];

		/* Reverse SNAT the ftp payload for 'PORT' pkt */
		if (!strncmp("PORT ", post_ftp, 4)) {
			snprintf(rnatd, sizeof(rnatd),
				 "PORT 2,2,2,12,4,3\x0d\x0a");
			post_ftp = rnatd;
		}

		dp_test_tcp_write_payload(pre_pak, strlen(pre_ftp), pre_ftp);
		dp_test_tcp_write_payload(post_pak, strlen(post_ftp), post_ftp);
	}

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Send the packet */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/*
	 * Detect the ACK just after the "PORT" command. We can startup the
	 * data channel tcp session here.
	 */
	if (ctx->do_data_call && pktno > 1 && ftp[pktno - 1] &&
	    !strncmp(ftp[pktno - 1], "PORT", 4))
		ftp_data_call7();
}

/*
 * alg_ftp7
 */
DP_DECL_TEST_CASE(npf_alg_ftp, alg_ftp7, NULL, NULL);
DP_START_TEST(alg_ftp7, test)
{
	uint vrfid = VRF_DEFAULT_ID;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "2.2.2.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.12",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ftp7_fwd_in,
			.post = &ftp7_fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &ftp7_rev_in,
			.post = &ftp7_rev_out,
		},
		.test_cb = tcp_ftp_control_cb7,
		.post_cb = NULL,
	};

	const char *ftp[] = {
		[0] = NULL,
		[1] = NULL,
		[2] = NULL,

		/* Port: 1027 = 4*256 + 3 */
		[3] = "PORT 2,2,2,11,4,3\x0d\x0a",
		[4] = NULL,

		/*
		 * Here we get a new TCP call opened for the data channel,
		 * from 1.1.1.11:46682 to 2.2.2.11:9819
		 */
	};


	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		/* session established */
		{DP_DIR_FORW, TH_ACK, strlen(ftp[3]), NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},

		/* call not completed */
	};
	assert(ARRAY_SIZE(ftp) == ARRAY_SIZE(tcp_pkt1));

	struct ftp_ctx ftp_ctx = {
		.payload = ftp,
		.payload_len = ARRAY_SIZE(ftp),
		.do_data_call = true,	/* Add data call */
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1),
			 &ftp_ctx, 0);

	/*
	 * ftp control and data channels established
	 */
#if 0
	dp_test_npf_print_session_table(false);
#endif

	/*
	 * Set true to delete vrf before sessions are expired.
	 */
	bool delete_vrf = false;

	if (delete_vrf && vrfid != VRF_DEFAULT_ID) {
		/*
		 * Delete vrf while there are ALG sessions
		 */
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
							 vrfid);
		dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
		dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);
		dp_test_netlink_del_vrf(vrfid, 0);
		dp_test_npf_clear_sessions();
	}

	/* Cleanup */

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	dp_test_npf_cleanup();

	if (!delete_vrf || vrfid == VRF_DEFAULT_ID) {
		/*
		 * Normal test cleanup.
		 */
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
							 vrfid);

		if (vrfid != VRF_DEFAULT_ID)
			dp_test_netlink_del_vrf(vrfid, 0);
	}

} DP_END_TEST;


/***************************************************************************
 * alg_ftp8 -- SNAT from client to server, Active ftp.  Deleting vrf.
 *
 *                  dp1T0         dp1T1
 *        1.1.1.11                      2.2.2.11 (src, pre)
 *                                      2.2.2.12 (src, post
 *        Server                        Client
 * 1.               21     <-----       1026           "PORT 1027"
 * 2.               21     ----->       1026           ack
 * 3.     20               ----->               1027
 * 4.     20               <-----               1027   ack
 *
 * Simulates an ftp call via two TCP calls - one for control channel and one
 * for data channel.
 *
 * snat is configured.  Source address 2.2.2.11 is translated to 2.2.2.12 for
 * client-to-server traffic.
 *
 * Input and output interface are in a non-default VRF.
 *
 ***************************************************************************/

DP_DECL_TEST_CASE(npf_alg_ftp, alg_ftp8, NULL, NULL);
DP_START_TEST(alg_ftp8, test)
{
	uint vrfid = 69;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	/*
	 * Add SNAT rule.
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= "2.2.2.11",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.12",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ftp7_fwd_in,
			.post = &ftp7_fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &ftp7_rev_in,
			.post = &ftp7_rev_out,
		},
		.test_cb = tcp_ftp_control_cb7,
		.post_cb = NULL,
	};

	const char *ftp[] = {
		[0] = NULL,
		[1] = NULL,
		[2] = NULL,

		/* Port: 1027 = 4*256 + 3 */
		[3] = "PORT 2,2,2,11,4,3\x0d\x0a",
		[4] = NULL,
	};


	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		/* session established */
		{DP_DIR_FORW, TH_ACK, strlen(ftp[3]), NULL},
		{DP_DIR_BACK, TH_ACK, 0, NULL},

		/* call not completed */
	};
	assert(ARRAY_SIZE(ftp) == ARRAY_SIZE(tcp_pkt1));

	struct ftp_ctx ftp_ctx = {
		.payload = ftp,
		.payload_len = ARRAY_SIZE(ftp),
		.do_data_call = false,
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1),
			 &ftp_ctx, 0);

	/*
	 * ftp control and data channels established
	 */
#if 0
	dp_test_npf_print_session_table(false);
#endif

	/*
	 * Set true to delete vrf before sessions are expired.
	 */
	bool delete_vrf = true;

	if (delete_vrf && vrfid != VRF_DEFAULT_ID) {
		/*
		 * Delete vrf while there are ALG sessions and tuples
		 */
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
							 vrfid);
		dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
		dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID);
		dp_test_netlink_del_vrf(vrfid, 0);
		dp_test_npf_clear_sessions();
	}

	/* Cleanup */

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	dp_test_npf_cleanup();

	if (!delete_vrf || vrfid == VRF_DEFAULT_ID) {
		/*
		 * Normal test cleanup.
		 */
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
							 vrfid);

		if (vrfid != VRF_DEFAULT_ID)
			dp_test_netlink_del_vrf(vrfid, 0);
	}

} DP_END_TEST;


/***************************************************************************
 * alg_ftp9
 *
 * Same as alg_ftp2, except there are no parenthesis around the address and
 * port in the 227 message.
 *
 ***************************************************************************/

/*
 * Callback function for TCP call simulator.  ftp control channel.
 */
static void tcp_ftp_control_cb9(const char *str,
				uint pktno, enum dp_test_tcp_dir dir,
				uint8_t flags,
				struct dp_test_pkt_desc_t *pre,
				struct dp_test_pkt_desc_t *post,
				void *data, uint index)
{
	struct rte_mbuf *pre_pak, *post_pak;
	struct dp_test_expected *test_exp;
	struct ftp_ctx *ctx = data;
	const char **ftp = ctx->payload;

	pre_pak = dp_test_v4_pkt_from_desc(pre);
	post_pak = dp_test_v4_pkt_from_desc(post);

	/*
	 * Add ftp payload
	 */
	if (ftp[pktno]) {
		const char *pre_ftp = ftp[pktno];
		const char *post_ftp = ftp[pktno];
		char rnatd[50];

		/* Reverse dNAT the ftp payload for 227 Response pkt */
		if (!strncmp("227 ", post_ftp, 4)) {
			snprintf(rnatd, sizeof(rnatd),
				 "227 Entering Passive Mode "
				 "2,2,2,12,38,91\r\n");
			post_ftp = rnatd;
		}

		dp_test_tcp_write_payload(pre_pak, strlen(pre_ftp), pre_ftp);
		dp_test_tcp_write_payload(post_pak, strlen(post_ftp), post_ftp);
	}

	test_exp = dp_test_exp_from_desc(post_pak, post);
	rte_pktmbuf_free(post_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	spush(test_exp->description, sizeof(test_exp->description),
	      "%s", str);

	/* Send the packet */
	dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);

	/*
	 * 227 is a Response from the server that contains the data channel
	 * address and port.  So we can startup the data channel tcp session
	 * here.
	 */
	if (ctx->do_data_call && ftp[pktno] && !strncmp(ftp[pktno], "227", 3))
		ftp_data_call1();
}

/*
 * alg_ftp9
 */
DP_DECL_TEST_CASE(npf_alg_ftp, alg_ftp9, NULL, NULL);
DP_START_TEST(alg_ftp9, test)
{
	uint vrfid = VRF_DEFAULT_ID;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	/* Setup interfaces and neighbours */
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_add_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_add_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	/*
	 * Add DNAT rule.
	 */
	struct dp_test_npf_nat_rule_t dnat = {
		.desc		= "dnat rule",
		.rule		= "10",
		.ifname		= "dp1T0",
		.proto		= IPPROTO_TCP,
		.map		= "dynamic",
		.from_addr	= NULL,
		.from_port	= NULL,
		.to_addr	= "2.2.2.12",
		.to_port	= NULL,
		.trans_addr	= "2.2.2.11",
		.trans_port	= NULL
	};

	dp_test_npf_dnat_add(&dnat, true);

	ftp1_fwd_in.l4.tcp.sport = 46682;
	ftp1_fwd_in.l4.tcp.dport = 21;

	ftp1_fwd_out.l4.tcp.sport = 46682;
	ftp1_fwd_out.l4.tcp.dport = 21;

	ftp1_rev_in.l4.tcp.sport = 21;
	ftp1_rev_in.l4.tcp.dport = 46682;

	ftp1_rev_out.l4.tcp.sport = 21;
	ftp1_rev_out.l4.tcp.dport = 46682;

	ftp1_fwd_in.l3_dst = "2.2.2.12";
	ftp1_fwd_out.l3_dst = "2.2.2.11";

	ftp1_rev_in.l3_src = "2.2.2.11";
	ftp1_rev_out.l3_src = "2.2.2.12";

	struct dp_test_tcp_call tcp_call = {
		.str[0] = '\0',
		.isn = {0, 0},
		.desc[DP_DIR_FORW] = {
			.pre = &ftp1_fwd_in,
			.post = &ftp1_fwd_out,
		},
		.desc[DP_DIR_BACK] = {
			.pre = &ftp1_rev_in,
			.post = &ftp1_rev_out,
		},
		.test_cb = tcp_ftp_control_cb9,
		.post_cb = NULL,
	};

	const char *ftp[] = {
		[0] = NULL,
		[1] = NULL,
		[2] = NULL,

		[3] = "SYST\x0d\x0a",
		[4] = "215 UNIX Type: L8\x0d\x0a",

		[5] = "TYPE I\x0d\x0a",
		[6] = "200 Switching to Binary mode.\x0d\x0a",

		[7] = "PASV\x0d\x0a",

		/*
		 * Response: 227.  Server telling client which address and
		 * port to use for data channel.  Address is 2.2.2.11, port is
		 * 9819.  (38 == 0x26, 91 == 0x5B, 0x265B == 9819)
		 */
		[8] = "227 Entering Passive Mode 2,2,2,11,38,91\x0d\x0a",

		/*
		 * Here we get a new TCP call opened for the data channel,
		 * from 1.1.1.11:46682 to 2.2.2.11:9819
		 */

		[9] = NULL,
		[10] = NULL,
		[11] = NULL,
	};


	struct dp_test_tcp_flow_pkt tcp_pkt1[] = {
		{DP_DIR_FORW, TH_SYN, 0, NULL},
		{DP_DIR_BACK, TH_SYN | TH_ACK, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},

		/* session established */
		{DP_DIR_FORW, TH_ACK, strlen(ftp[3]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[4]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[5]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[6]), NULL},

		{DP_DIR_FORW, TH_ACK, strlen(ftp[7]), NULL},
		{DP_DIR_BACK, TH_ACK, strlen(ftp[8]), NULL},

		{DP_DIR_FORW, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_BACK, TH_ACK | TH_FIN, 0, NULL},
		{DP_DIR_FORW, TH_ACK, 0, NULL},
	};
	assert(ARRAY_SIZE(ftp) == ARRAY_SIZE(tcp_pkt1));

	struct ftp_ctx ftp_ctx = {
		.payload = ftp,
		.payload_len = ARRAY_SIZE(ftp),
		.do_data_call = true,	/* Add data call */
	};

	/* Simulate the TCP call */
	dp_test_tcp_call(&tcp_call, tcp_pkt1, ARRAY_SIZE(tcp_pkt1),
			 &ftp_ctx, 0);

	/* Cleanup */

	dp_test_npf_dnat_del(dnat.ifname, dnat.rule, true);

	dp_test_npf_cleanup();

	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_del_ip_addr_and_connected_vrf("dp1T1", "2.2.2.2/24",
						 vrfid);

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.11",
				  "aa:bb:cc:dd:1:11");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.12",
				  "aa:bb:cc:dd:1:12");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.11",
				  "aa:bb:cc:dd:2:11");
	dp_test_netlink_del_neigh("dp1T1", "2.2.2.12",
				  "aa:bb:cc:dd:2:12");

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_del_vrf(vrfid, 0);

} DP_END_TEST;
