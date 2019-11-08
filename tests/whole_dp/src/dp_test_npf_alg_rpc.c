/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane npf alg rpc tests.
 *
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


struct nat_ctx {
	bool		do_check;
	uint16_t	port;
	validate_cb	saved_cb;
};

static struct nat_ctx nat_ctx = {
	.do_check = true,
	.saved_cb = dp_test_pak_verify,
};

static void
_pak_rcv_nat_udp(const char *rx_intf, const char *pre_smac, int pre_vlan,
		 const char *pre_saddr, uint16_t pre_sport,
		 const char *pre_daddr, uint16_t pre_dport,
		 const char *post_saddr, uint16_t post_sport,
		 const char *post_daddr, uint16_t post_dport,
		 const char *post_dmac, int post_vlan, const char *tx_intf,
		 int status, char *payload, uint payload_len,
		 const char *file, const char *func, int line);
#define pak_rcv_nat_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
			_i, _j, _k, _l, _m, _n, _o, _p, _q)		\
	_pak_rcv_nat_udp(_a, _b, _c, _d, _e, _f, _g, _h,		\
			 _i, _j, _k, _l, _m, _n, _o, _p, _q,		\
			 __FILE__, __func__, __LINE__)

/*
 * The rpc tuple is setup in the same direction as the SNAT.  Therefore the
 * data packet would get through regardless of matching a tuple and creating a
 * child session.
 *
 * To get around this, we setup a firewall rule in the forwards direction to
 * only allow packets to port 111.  This means the data packet will *only* get
 * through if it matches the rpc tuple, and causes a child session to be
 * created.
 */
static void
npf_rpc_out_fw(bool enable)
{
	/* UDP */
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = false,
			.npf      = "proto=17 dst-port=111"
		},
		RULE_DEF_BLOCK,
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-out",
		.name   = "OUT_FW",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "out",
		.rules  = rset
	};

	if (enable)
		dp_test_npf_fw_add(&fw, false);
	else
		dp_test_npf_fw_del(&fw, false);
}

DP_DECL_TEST_SUITE(npf_alg_rpc);

/*
 * alg_rpc1 -- Tests RPC Portmapper
 */
DP_DECL_TEST_CASE(npf_alg_rpc, alg_rpc1, NULL, NULL);
DP_START_TEST(alg_rpc1, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.1/24");

	/*
	 * Inside
	 */
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2", "aa:bb:cc:dd:1:a2");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.3", "aa:bb:cc:dd:1:a3");

	/*
	 * Outside
	 */
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.2", "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.3", "aa:bb:cc:dd:2:b3");

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.from_addr	= "1.1.1.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.254",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	npf_rpc_out_fw(true);

	/*
	 * RPC Call
	 */
	char rpc_call[] = {0x01, 0x02, 0x03, 0x04, /* xid (host order) */
			   0x00, 0x00, 0x00, 0x00, /* type (0=call) */
			   0x00, 0x00, 0x00, 0x02, /* RPC version */
			   0x00, 0x01, 0x86, 0xa0, /* Program (100000) */
			   0x00, 0x00, 0x00, 0x00, /* Program version */
			   0x00, 0x00, 0x00, 0x03, /* Procedure (3=getport) */
			   0x00, 0x00, 0x00, 0x00, /* Auth flavor */
			   0x00, 0x00, 0x00, 0x00, /* Auth length */
			   0x00, 0x00, 0x00, 0x00, /* Verifier flavor */
			   0x00, 0x00, 0x00, 0x00, /* Verifier flavor length */
			   0x00, 0x01, 0x86, 0xa0, /* Pmap Program (100000) */
	};

	pak_rcv_nat_udp("dp1T0", "aa:bb:cc:dd:1:a2", 0,
			"1.1.1.2", 50618, "2.2.2.2", 111,
			"2.2.2.254", 50618, "2.2.2.2", 111,
			"aa:bb:cc:dd:2:b2", 0, "dp2T1",
			DP_TEST_FWD_FORWARDED, rpc_call, sizeof(rpc_call));


	/*
	 * RPC Reply
	 *
	 * Will create tuple:
	 * proto 17, dport 1025 Src 1.1.1.2, Dst 2.2.2.2, [MATCH_ANY_SPORT]
	 */
	char rpc_reply[] = {0x01, 0x02, 0x03, 0x04, /* xid (host order) */
			    0x00, 0x00, 0x00, 0x01, /* type (1=reply) */
			    0x00, 0x00, 0x00, 0x00, /* Reply st (0=accepted) */
			    0x00, 0x00, 0x00, 0x00, /* Auth */
			    0x00, 0x00, 0x00, 0x00, /* Auth length */
			    0x00, 0x00, 0x00, 0x00, /* Accept st (0=success) */
			    0x00, 0x00, 0x04, 0x01, /* Port = 1025 */
	};

	pak_rcv_nat_udp("dp2T1", "aa:bb:cc:dd:2:b2", 0,
			"2.2.2.2", 111, "2.2.2.254", 50618,
			"2.2.2.2", 111, "1.1.1.2", 50618,
			"aa:bb:cc:dd:1:a2", 0, "dp1T0",
			DP_TEST_FWD_FORWARDED, rpc_reply, sizeof(rpc_reply));


	/*
	 * RPC Data
	 *
	 * Finds the above tuple, creates a child session, expired the tuple
	 */
	char rpc_data[] = {0x01, 0x02, 0x03, 0x04 };

	pak_rcv_nat_udp("dp1T0", "aa:bb:cc:dd:1:a2", 0,
			"1.1.1.2", 30123, "2.2.2.2", 1025,
			"2.2.2.254", 30123, "2.2.2.2", 1025,
			"aa:bb:cc:dd:2:b2", 0, "dp2T1",
			DP_TEST_FWD_FORWARDED,
			rpc_data, sizeof(rpc_data));


	if (0) {
		dp_test_npf_print_session_table(false);
		dp_test_npf_print_nat_sessions("");
	}

	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	npf_rpc_out_fw(false);
	dp_test_npf_cleanup();

	/* Cleanup */
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2", "aa:bb:cc:dd:1:a2");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.3", "aa:bb:cc:dd:1:a3");

	dp_test_netlink_del_neigh("dp2T1", "2.2.2.2", "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.3", "aa:bb:cc:dd:2:b3");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.1/24");

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * alg_rpc2 -- Tests RPC Portmapper.  vrf is deleted while there is a non-keep
 * tuple.
 */
DP_DECL_TEST_CASE(npf_alg_rpc, alg_rpc2, NULL, NULL);
DP_START_TEST(alg_rpc2, test)
{
	uint vrfid = 69;

	if (vrfid != VRF_DEFAULT_ID)
		dp_test_netlink_add_vrf(vrfid, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
						 vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp2T1", "2.2.2.1/24",
						 vrfid);

	/*
	 * Inside
	 */
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.2", "aa:bb:cc:dd:1:a2");
	dp_test_netlink_add_neigh("dp1T0", "1.1.1.3", "aa:bb:cc:dd:1:a3");

	/*
	 * Outside
	 */
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.2", "aa:bb:cc:dd:2:b2");
	dp_test_netlink_add_neigh("dp2T1", "2.2.2.3", "aa:bb:cc:dd:2:b3");

	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.from_addr	= "1.1.1.0/24",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "2.2.2.254",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * RPC Call
	 */
	char rpc_call[] = {0x01, 0x02, 0x03, 0x04, /* xid (host order) */
			   0x00, 0x00, 0x00, 0x00, /* type (0=call) */
			   0x00, 0x00, 0x00, 0x02, /* RPC version */
			   0x00, 0x01, 0x86, 0xa0, /* Program (100000) */
			   0x00, 0x00, 0x00, 0x00, /* Program version */
			   0x00, 0x00, 0x00, 0x03, /* Procedure (3=getport) */
			   0x00, 0x00, 0x00, 0x00, /* Auth flavor */
			   0x00, 0x00, 0x00, 0x00, /* Auth length */
			   0x00, 0x00, 0x00, 0x00, /* Verifier flavor */
			   0x00, 0x00, 0x00, 0x00, /* Verifier flavor length */
			   0x00, 0x01, 0x86, 0xa0, /* Pmap Program (100000) */
	};

	pak_rcv_nat_udp("dp1T0", "aa:bb:cc:dd:1:a2", 0,
			"1.1.1.2", 50618, "2.2.2.2", 111,
			"2.2.2.254", 50618, "2.2.2.2", 111,
			"aa:bb:cc:dd:2:b2", 0, "dp2T1",
			DP_TEST_FWD_FORWARDED, rpc_call, sizeof(rpc_call));

	/*
	 * RPC Reply
	 *
	 * Will create tuple:
	 * proto 17, dport 1025 Src 1.1.1.2, Dst 2.2.2.2, [MATCH_ANY_SPORT]
	 */
	char rpc_reply[] = {0x01, 0x02, 0x03, 0x04, /* xid (host order) */
			    0x00, 0x00, 0x00, 0x01, /* type (1=reply) */
			    0x00, 0x00, 0x00, 0x00, /* Reply st (0=accepted) */
			    0x00, 0x00, 0x00, 0x00, /* Auth */
			    0x00, 0x00, 0x00, 0x00, /* Auth length */
			    0x00, 0x00, 0x00, 0x00, /* Accept st (0=success) */
			    0x00, 0x00, 0x04, 0x01, /* Port = 1025 */
	};

	pak_rcv_nat_udp("dp2T1", "aa:bb:cc:dd:2:b2", 0,
			"2.2.2.2", 111, "2.2.2.254", 50618,
			"2.2.2.2", 111, "1.1.1.2", 50618,
			"aa:bb:cc:dd:1:a2", 0, "dp1T0",
			DP_TEST_FWD_FORWARDED, rpc_reply, sizeof(rpc_reply));

	if (0) {
		dp_test_npf_print_session_table(false);
		dp_test_npf_print_nat_sessions("");
	}

	bool delete_vrf = true;

	if (delete_vrf && vrfid != VRF_DEFAULT_ID) {
		/*
		 * Delete vrf while there are ALG sessions
		 */

		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp2T1", "2.2.2.1/24",
							 vrfid);

		dp_test_netlink_set_interface_vrf("dp1T0", VRF_DEFAULT_ID);
		dp_test_netlink_set_interface_vrf("dp2T1", VRF_DEFAULT_ID);
		dp_test_netlink_del_vrf(vrfid, 0);
		dp_test_npf_clear_sessions();
	}

	/* Cleanup */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);

	dp_test_netlink_del_neigh("dp1T0", "1.1.1.2", "aa:bb:cc:dd:1:a2");
	dp_test_netlink_del_neigh("dp1T0", "1.1.1.3", "aa:bb:cc:dd:1:a3");

	dp_test_netlink_del_neigh("dp2T1", "2.2.2.2", "aa:bb:cc:dd:2:b2");
	dp_test_netlink_del_neigh("dp2T1", "2.2.2.3", "aa:bb:cc:dd:2:b3");

	dp_test_npf_cleanup();

	if (!delete_vrf || vrfid == VRF_DEFAULT_ID) {
		/*
		 * Normal test cleanup.
		 */
		dp_test_nl_del_ip_addr_and_connected_vrf("dp1T0", "1.1.1.1/24",
							 vrfid);
		dp_test_nl_del_ip_addr_and_connected_vrf("dp2T1", "2.2.2.1/24",
							 vrfid);

		if (vrfid != VRF_DEFAULT_ID)
			dp_test_netlink_del_vrf(vrfid, 0);
	}

} DP_END_TEST;


/*
 * This is called *after* the packet has been modified, but *before* the pkt
 * queued on the tx ring is checked.
 */
static void
nat_validate_cb(struct rte_mbuf *mbuf, struct ifnet *ifp,
		struct dp_test_expected *expected,
		enum dp_test_fwd_result_e fwd_result)
{
	struct nat_ctx *ctx = dp_test_exp_get_validate_ctx(expected);

	/* call the saved check routine */
	if (ctx->do_check) {
		(ctx->saved_cb)(mbuf, ifp, expected, fwd_result);
	} else {
		expected->pak_correct[0] = true;
		expected->pak_checked[0] = true;
	}
}

static bool
udp_payload_init(struct rte_mbuf *pak, struct dp_test_pkt_desc_t *pdesc,
		 char *payload, uint payload_len)
{
	if (!payload || payload_len == 0)
		return true;

	struct udphdr *udp;
	uint32_t poff = pak->l2_len + pak->l3_len + sizeof(*udp);
	uint32_t plen = pak->pkt_len - poff;

	assert(payload_len == plen);

	/* Write test pattern to mbuf payload */
	if (dp_test_pktmbuf_payload_init(pak, poff, payload, plen) == 0)
		return false;

	/* Write UDP header after payload is initialized */
	udp = dp_test_pktmbuf_udp_init(pak, pdesc->l4.udp.sport,
				       pdesc->l4.udp.dport, true);
	if (!udp)
		return false;

	return true;
}

/*
 * pak_rcv_nat_udp
 */
static void
_pak_rcv_nat_udp(const char *rx_intf, const char *pre_smac, int pre_vlan,
		 const char *pre_saddr, uint16_t pre_sport,
		 const char *pre_daddr, uint16_t pre_dport,
		 const char *post_saddr, uint16_t post_sport,
		 const char *post_daddr, uint16_t post_dport,
		 const char *post_dmac, int post_vlan, const char *tx_intf,
		 int status, char *payload, uint payload_len,
		 const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	/* Pre IPv4 UDP packet */
	struct dp_test_pkt_desc_t pre_pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = payload_len,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = pre_sport,
				.dport = pre_dport
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	/* Post IPv4 UDP packet */
	struct dp_test_pkt_desc_t post_pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = payload_len,
		.ether_type = ETHER_TYPE_IPv4,
		.l3_src     = post_saddr,
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = post_daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = post_sport,
				.dport = post_dport
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	test_pak = dp_test_v4_pkt_from_desc(&pre_pkt_UDP);

	udp_payload_init(test_pak, &pre_pkt_UDP, payload, payload_len);

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
	rte_pktmbuf_free(exp_pak);

	udp_payload_init(dp_test_exp_get_pak(test_exp),
			 &post_pkt_UDP, payload, payload_len);

	/* vlan */
	if (pre_vlan > 0)
		dp_test_pktmbuf_vlan_init(test_pak, pre_vlan);

	if (post_vlan > 0) {
		dp_test_exp_set_vlan_tci(test_exp, post_vlan);

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(test_exp),
			post_dmac,
			dp_test_intf_name2mac_str(tx_intf),
			ETHER_TYPE_IPv4);
	}

	dp_test_exp_set_fwd_status(test_exp, status);

	dp_test_exp_set_validate_ctx(test_exp, &nat_ctx, false);
	dp_test_exp_set_validate_cb(test_exp, nat_validate_cb);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);
}
