/*-
 * Copyright (c) 2018-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * PPP tests.
 */

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_controller.h"
#include "dp_test_json_utils.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_ppp.h"

#include "pipeline/nodes/pppoe/pppoe.h"

#include "protobuf/PPPOEConfig.pb-c.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"


DP_DECL_TEST_SUITE(ppp);

static void
dp_test_create_and_send_pppoe_msg(const char *ppp_intf,
				  const char *real_intf,
				  const char *src_mac,
				  const char *dst_mac,
				  int session_id)
{
	int len;
	PPPOEConfig con = PPPOECONFIG__INIT;
	con.has_session = true;
	con.session = session_id;
	con.pppname = (char *)ppp_intf;
	con.undername = (char *)real_intf;
	con.ether = (char *)src_mac;
	con.peer_ether = (char *)dst_mac;

	len = pppoeconfig__get_packed_size(&con);
	void *buf2 = malloc(len);
	dp_test_assert_internal(buf2);

	pppoeconfig__pack(&con, buf2);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:pppoe", buf2, len);
}

void
_dp_test_create_pppoe_session(const char *ppp_intf, const char *under_intf,
			      uint16_t session_id, const char *src_mac,
			      const char *dst_mac, bool create, bool verify,
			      bool valid,
			      const char *file, const char *func, int line)
{
	char real_ifname[IFNAMSIZ];
	json_object *expected;

	dp_test_intf_real(under_intf, real_ifname);

	if (create)
		dp_test_create_and_send_pppoe_msg(ppp_intf,
						  real_ifname,
						  src_mac, dst_mac,
						  session_id);

	if  (verify) {
		expected = dp_test_json_create("{"
					       "  \"pppoe\":"
					       "  ["
					       "    {"
					       "      \"session\": %d,"
					       "      \"device\": \"%s\","
					       "      \"underlying\": \"%s\","
					       "      \"eth\": \"%s\","
					       "      \"peer-eth\": \"%s\","
					       "      \"valid\": \"%s\""
					       "    }"
					       "  ]"
					       "}",
					       session_id, ppp_intf,
					       real_ifname,
					       src_mac, dst_mac,
					       valid ? "yes" : "no");

		_dp_test_check_json_state("pipeline pppoe show", expected, NULL,
					  DP_TEST_JSON_CHECK_SUBSET,
					  false, false,
					  file, func, line);
		json_object_put(expected);
	}
}

struct pppoe_packet *
dp_test_ipv4_pktmbuf_ppp_prepend(struct rte_mbuf *m,
				 const char *dst_mac,
				 const char *src_mac,
				 int v4_len,
				 uint16_t session)
{
	struct pppoe_packet *ppp_hdr;
	int ppp_append_size = 8; /* 6 for ppp, plus 2 ppp payload type */

	/* Now push the ppp header */
	ppp_hdr = (struct pppoe_packet *)rte_pktmbuf_prepend(
		m, ppp_append_size);
	if (!ppp_hdr)
		return NULL;

	(void)dp_test_pktmbuf_eth_init(m, dst_mac, src_mac,
				       ETH_P_PPP_SES);
	ppp_hdr->vertype = 0x11;
	ppp_hdr->code = 0; /* Session is established */
	ppp_hdr->session = htons(session);
	ppp_hdr->length = htons(v4_len + 2); /* 2 for ppp frame protocol */
	ppp_hdr->protocol = htons(PPP_IP);

	return ppp_hdr;
}

DP_DECL_TEST_CASE(ppp, ppp_setup, NULL, NULL);

DP_START_TEST(ppp_setup, ppp)
{
	dp_test_intf_ppp_create("ppp0", VRF_DEFAULT_ID);
	dp_test_intf_ppp_delete("ppp0", VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(ppp_setup, pppoe)
{
	dp_test_intf_ppp_create("pppoe0", VRF_DEFAULT_ID);
	dp_test_create_pppoe_session("pppoe0", "dp1T0", 1,
				     dp_test_intf_name2mac_str("dp1T0"),
				     "aa:bb:cc:dd:ee:ff");
	dp_test_intf_ppp_delete("pppoe0", VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(ppp_setup, pppoe_out_of_order)
{
	dp_test_intf_ppp_create("pppoe0", VRF_DEFAULT_ID);
	dp_test_create_pppoe_session_nv("pppoe0", "dp1T0", 1,
					dp_test_intf_name2mac_str("dp1T0"),
					"aa:bb:cc:dd:ee:ff");
	dp_test_verify_pppoe_session("pppoe0", "dp1T0", 1,
				     dp_test_intf_name2mac_str("dp1T0"),
				     "aa:bb:cc:dd:ee:ff", SESS_VALID);
	dp_test_intf_ppp_delete("pppoe0", VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(ppp_setup, pppoe_out_of_order2)
{
	/*
	 * Verify that we only have 1 session per ppp interface and
	 * that if we change the session details that new session is
	 * stored in the replay store.
	 */
	dp_test_intf_ppp_create("pppoe0", VRF_DEFAULT_ID);
	dp_test_create_pppoe_session_nv("pppoe0", "dp1T0", 1,
					dp_test_intf_name2mac_str("dp1T0"),
					"aa:bb:cc:dd:ee:fe");
	dp_test_verify_pppoe_session("pppoe0", "dp1T0", 1,
				     dp_test_intf_name2mac_str("dp1T0"),
				     "aa:bb:cc:dd:ee:fe", SESS_VALID);
	dp_test_intf_ppp_delete("pppoe0", VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST(ppp_setup, pppoe_out_of_order3)
{
	const char *dst_mac = "aa:bb:cc:dd:ee:ff";
	uint16_t session_id = 3;
	char *src_mac;

	/*
	 * Create ppp interface, and session, but before underlying interface
	 * arrives. Then add underlying interface.
	 */

	dp_test_intf_ppp_create("pppoe0", VRF_DEFAULT_ID);
	/*
	 * Create the interface to find out what its mac address will be.
	 * It will be the same on recreate.
	 */
	dp_test_intf_vif_create("dp2T1.100", "dp2T1", 100);
	src_mac = dp_test_intf_name2mac_str("dp2T1.100");
	dp_test_intf_vif_del("dp2T1.100", 100);

	dp_test_create_pppoe_session_nv("pppoe0", "dp2T1.100", session_id,
					src_mac,
					dst_mac);
	dp_test_verify_pppoe_session("pppoe0", "dp2T1.100", session_id,
				     src_mac,
				     dst_mac, SESS_INVALID);

	dp_test_intf_vif_create("dp2T1.100", "dp2T1", 100);
	dp_test_verify_pppoe_session("pppoe0", "dp2T1.100", session_id,
				     dp_test_intf_name2mac_str("dp2T1.100"),
				     dst_mac, SESS_VALID);
	/* Tidy */
	dp_test_intf_vif_del("dp2T1.100", 100);
	dp_test_intf_ppp_delete("pppoe0", VRF_DEFAULT_ID);

} DP_END_TEST;

DP_DECL_TEST_CASE(ppp, ppp_traffic, NULL, NULL);

/* Basic test, traffic leaving out of ppp interface. */
DP_START_TEST(ppp_traffic, ppp_traffic_1)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	const char *dst_mac = "aa:bb:cc:dd:ee:ff";
	uint16_t session_id = 3;
	struct pppoe_packet *ppp_hdr;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_intf_ppp_create("pppoe0", VRF_DEFAULT_ID);
	dp_test_create_pppoe_session("pppoe0", "dp2T1", session_id,
				     dp_test_intf_name2mac_str("dp2T1"),
				     dst_mac);

	dp_test_netlink_add_route("10.73.2.0/24 nh int:pppoe0");

	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "10.73.2.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	ppp_hdr = dp_test_ipv4_pktmbuf_ppp_prepend(
		dp_test_exp_get_pak(exp),
		dst_mac,
		dp_test_intf_name2mac_str("dp2T1"),
		len + 20 + 8,
		session_id);
	dp_test_fail_unless(ppp_hdr, "Could not prepend ppp header");
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_netlink_del_route("10.73.2.0/24 nh int:pppoe0");
	dp_test_intf_ppp_delete("pppoe0", VRF_DEFAULT_ID);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

/*
 * Traffic sent out of ppp interface once underlying interface has
 * been deleted
 */
DP_START_TEST(ppp_traffic, ppp_traffic_2)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	const char *dst_mac = "aa:bb:cc:dd:ee:ff";
	uint16_t session_id = 3;
	struct pppoe_packet *ppp_hdr;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_intf_vif_create("dp2T1.100", "dp2T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp2T1.100", "3.3.3.3/24");

	dp_test_intf_ppp_create("pppoe0", VRF_DEFAULT_ID);
	dp_test_create_pppoe_session("pppoe0", "dp2T1.100", session_id,
				     dp_test_intf_name2mac_str("dp2T1.100"),
				     dst_mac);

	dp_test_netlink_add_route("10.73.2.0/24 nh int:pppoe0");

	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "10.73.2.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_pktmbuf_vlan_init(dp_test_exp_get_pak(exp), 100);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	ppp_hdr = dp_test_ipv4_pktmbuf_ppp_prepend(
		dp_test_exp_get_pak(exp),
		dst_mac,
		dp_test_intf_name2mac_str("dp2T1.100"),
		len + 20 + 8,
		session_id);
	dp_test_fail_unless(ppp_hdr, "Could not prepend ppp header");
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Send another packet */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "10.73.2.1",
					   1, &len);
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/* Delete the underlying interface */
	dp_test_nl_del_ip_addr_and_connected("dp2T1.100", "3.3.3.3/24");
	dp_test_intf_vif_del("dp2T1.100", 100);

	dp_test_verify_pppoe_session("pppoe0", "dp2T1.100", session_id,
				     dp_test_intf_name2mac_str("dp2T1.100"),
				     dst_mac, SESS_INVALID);

	/* We expect to drop the packet as the underlying interface is gone */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Bring back the underlying interface */
	dp_test_intf_vif_create("dp2T1.100", "dp2T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp2T1.100", "3.3.3.3/24");

	dp_test_verify_pppoe_session("pppoe0", "dp2T1.100", session_id,
				     dp_test_intf_name2mac_str("dp2T1.100"),
				     dst_mac, SESS_VALID);

	/* Send another packet - this one should woprk again */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "10.73.2.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_pktmbuf_vlan_init(dp_test_exp_get_pak(exp), 100);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	ppp_hdr = dp_test_ipv4_pktmbuf_ppp_prepend(
		dp_test_exp_get_pak(exp),
		dst_mac,
		dp_test_intf_name2mac_str("dp2T1.100"),
		len + 20 + 8,
		session_id);
	dp_test_fail_unless(ppp_hdr, "Could not prepend ppp header");
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_netlink_del_route("10.73.2.0/24 nh int:pppoe0");
	dp_test_intf_ppp_delete("pppoe0", VRF_DEFAULT_ID);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1.100", "3.3.3.3/24");
	dp_test_intf_vif_del("dp2T1.100", 100);
} DP_END_TEST;

/* Send traffic, modify ppp interface, send traffic */
DP_START_TEST(ppp_traffic, ppp_traffic_3)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	const char *dst_mac = "aa:bb:cc:dd:ee:ff";
	uint16_t session_id = 3;
	struct pppoe_packet *ppp_hdr;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_intf_ppp_create("pppoe0", VRF_DEFAULT_ID);
	dp_test_create_pppoe_session("pppoe0", "dp2T1", session_id,
				     dp_test_intf_name2mac_str("dp2T1"),
				     dst_mac);

	dp_test_netlink_add_route("10.73.2.0/24 nh int:pppoe0");

	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "10.73.2.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	ppp_hdr = dp_test_ipv4_pktmbuf_ppp_prepend(
		dp_test_exp_get_pak(exp),
		dst_mac,
		dp_test_intf_name2mac_str("dp2T1"),
		len + 20 + 8,
		session_id);
	dp_test_fail_unless(ppp_hdr, "Could not prepend ppp header");
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_intf_ppp_set_mtu("pppoe0", VRF_DEFAULT_ID, 1400);

	/* Resend packet */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "10.73.2.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));
	ppp_hdr = dp_test_ipv4_pktmbuf_ppp_prepend(
		dp_test_exp_get_pak(exp),
		dst_mac,
		dp_test_intf_name2mac_str("dp2T1"),
		len + 20 + 8,
		session_id);
	dp_test_fail_unless(ppp_hdr, "Could not prepend ppp header");
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	dp_test_netlink_del_route("10.73.2.0/24 nh int:pppoe0");
	dp_test_intf_ppp_delete("pppoe0", VRF_DEFAULT_ID);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;

/*
 * Send traffic, delete underlying interface then delete the ppp interface when
 * it is not currently active
 */
DP_START_TEST(ppp_traffic, ppp_traffic_4)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	int len = 22;
	const char *dst_mac = "aa:bb:cc:dd:ee:ff";
	uint16_t session_id = 3;

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "2.2.2.2/24");

	dp_test_intf_vif_create("dp2T1.100", "dp2T1", 100);
	dp_test_nl_add_ip_addr_and_connected("dp2T1.100", "3.3.3.3/24");

	dp_test_intf_ppp_create("pppoe0", VRF_DEFAULT_ID);
	dp_test_create_pppoe_session("pppoe0", "dp2T1.100", session_id,
				     dp_test_intf_name2mac_str("dp2T1.100"),
				     dst_mac);

	dp_test_netlink_add_route("10.73.2.0/24 nh int:pppoe0");

	/* Delete the underlying interface */
	dp_test_nl_del_ip_addr_and_connected("dp2T1.100", "3.3.3.3/24");
	dp_test_intf_vif_del("dp2T1.100", 100);

	dp_test_verify_pppoe_session("pppoe0", "dp2T1.100", session_id,
				     dp_test_intf_name2mac_str("dp2T1.100"),
				     dst_mac, SESS_INVALID);

	/* We expect to drop the packet as the underlying interface is gone */
	test_pak = dp_test_create_ipv4_pak("1.1.1.1", "10.73.2.1",
					   1, &len);
	/* Ingress dp1T0 */
	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       DP_TEST_INTF_DEF_SRC_MAC,
				       RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to receive on the tx ring */
	exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(test_pak, "dp1T0", exp);

	/* Tidy up */
	dp_test_netlink_del_route("10.73.2.0/24 nh int:pppoe0");
	dp_test_intf_ppp_delete("pppoe0", VRF_DEFAULT_ID);
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "2.2.2.2/24");
} DP_END_TEST;
