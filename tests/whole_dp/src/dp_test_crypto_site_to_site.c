/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Site-to-Site crypto tests
 */

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_crypto_utils.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_crypto_lib.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_console.h"
#include "dp_test_controller.h"
#include "dp_test_npf_lib.h"

#include "main.h"
#include "in_cksum.h"
#include "ip_funcs.h"
#include "ip6_funcs.h"

#include "crypto/crypto.h"
#include "crypto/crypto_forward.h"
#include "crypto/crypto_internal.h"

#include "protobuf/IPAddress.pb-c.h"
#include "protobuf/CryptoPolicyConfig.pb-c.h"
#include "protobuf/VFPSetConfig.pb-c.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"

/*
 * The test configuration is centred around UUT. It has two ports, one
 * on 10.10.1.0/24, and the other on 10.10.2.0/24. It has a
 * site-to-site configuration on the 10.10.2.0 network with .3 as its
 * peer. It has routing setup so that packets destined for 10.10.3.4
 * go via 10.10.2.3 and should be encrypted. It is directly connected
 * to the client 10.10.1.1.
 *
 *
 *            2001:1::/64          2001:2::/64           2001:3::/64
 *            10.10.1.0/24         10.10.2.0/24          10.10.3.0
 *                      +----------+          +---------+
 * +-----------+        |          |          |         |         +----------+
 * |           |.1    .2|          | .2   .3  |         |      .4 |          |
 * |Client     +--------+  UUT     +----------+  PEER   + - - - - + Client   |
 * |   local   |        |          |          |         |         |  remote  |
 * |           |        |          |          |         |         |          |
 * +-----------+        |          |          |         |         +----------+
 *                      +----------+          +---------+
 *
 *     WEST<<<<<<<<<<<<<<         >>>>>>>>>>>>>>EAST
 */

#define NETWORK_WEST  "10.10.1.0/24"
#define CLIENT_LOCAL  "10.10.1.1"
#define NETWORK_LOCAL "10.10.1.0/24"
#define PREFIX_LOCAL  "10.10.1.0"
#define PORT_WEST     "10.10.1.2"

#define NETWORK_WEST6  "2001:1::/64"
#define CLIENT_LOCAL6  "2001:1::1"
#define NETWORK_LOCAL6 "2001:1::/64"
#define PREFIX_LOCAL6  "2001:1::0"
#define PORT_WEST6     "2001:1::2"

#define CLIENT_LOCAL_MAC_ADDR "aa:bb:cc:dd:1:1"

#define NETWORK_EAST   "10.10.2.0/24"
#define PEER           "10.10.2.3"
#define PEER_MAC_ADDR  "aa:bb:cc:dd:2:3"
#define PORT_EAST      "10.10.2.2"
#define NETWORK_REMOTE "10.10.3.0/24"
#define PREFIX_REMOTE  "10.10.3.0"

#define NETWORK_EAST6   "2001:2::/64"
#define PEER6           "2001:2::3"
#define PORT_EAST6      "2001:2::2"
#define NETWORK_REMOTE6 "2001:3::/64"
#define PREFIX_REMOTE6  "2001:3::0"

#define CLIENT_REMOTE  "10.10.3.4"
#define CLIENT_REMOTE6  "2001:3::4"

#define MASK 24
#define MASK6 64

#define SPI_OUTBOUND 0xd43d87c7
#define SPI_OUTBOUND6 0x89752ac5
#define SPI_INBOUND 0x10
#define TUNNEL_REQID 1234
#define TEST_VRF 42

#define LINK_LOCAL  "169.254.0.1/32"
#define LINK_LOCAL6 "fe80::1/128"

static void
dp_test_create_and_send_s2s_msg(CryptoPolicyConfig__Action action,
				int af,
				int ifindex,
				int vrf,
				const char *daddr,
				uint32_t dprefix_len,
				const char *saddr,
				uint32_t sprefix_len,
				uint32_t dport,
				uint32_t sport,
				uint32_t proto,
				int sel_ifindex)
{
	int len;

	CryptoPolicyConfig con = CRYPTO_POLICY_CONFIG__INIT;
	con.has_action = true;
	con.action = action;
	con.has_ifindex = true;
	con.ifindex = ifindex;
	con.has_vrf = true;
	con.vrf = vrf;
	con.has_sel_dprefix_len = true;
	con.sel_dprefix_len = dprefix_len;
	con.has_sel_sprefix_len = true;
	con.sel_sprefix_len = sprefix_len;
	con.has_sel_dport = true;
	con.sel_dport = dport;
	con.has_sel_sport = true;
	con.sel_sport = sport;
	con.has_sel_ifindex = true;
	con.sel_ifindex = sel_ifindex;

	uint32_t v6_saddr[4], v6_daddr[4];
	IPAddress ip_daddr = IPADDRESS__INIT;
	IPAddress ip_saddr = IPADDRESS__INIT;

	dp_test_lib_pb_set_ip_addr(&ip_saddr, saddr, &v6_saddr);
	con.sel_saddr = &ip_saddr;

	dp_test_lib_pb_set_ip_addr(&ip_daddr, daddr, &v6_daddr);
	con.sel_daddr = &ip_daddr;

	len = crypto_policy_config__get_packed_size(&con);
	void *buf2 = malloc(len);
	dp_test_assert_internal(buf2);

	crypto_policy_config__pack(&con, buf2);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:crypto-policy", buf2, len);
}

/*
 * Crypto policy definitions used by the tests in this module
 */
static struct dp_test_crypto_policy output_policy = {
	.d_prefix = NETWORK_REMOTE,
	.s_prefix = NETWORK_LOCAL,
	.proto = 0,
	.dst = PEER,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = TUNNEL_REQID,
	.priority = 0,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy output_policy6 = {
	.d_prefix = NETWORK_REMOTE6,
	.s_prefix = NETWORK_LOCAL6,
	.proto = 0,
	.dst = PEER6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET6,
	.reqid = TUNNEL_REQID,
	.priority = 0,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy output_policy46 = {
	.d_prefix = NETWORK_REMOTE,
	.s_prefix = NETWORK_LOCAL,
	.proto = 0,
	.dst = PEER6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET,
	.reqid = TUNNEL_REQID,
	.priority = 0,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy output_policy64 = {
	.d_prefix = NETWORK_REMOTE6,
	.s_prefix = NETWORK_LOCAL6,
	.proto = 0,
	.dst = PEER,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_OUT,
	.family = AF_INET6,
	.reqid = TUNNEL_REQID,
	.priority = 0,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy input_policy = {
	.d_prefix = NETWORK_LOCAL,
	.s_prefix = NETWORK_REMOTE,
	.proto = 0,
	.dst = PORT_EAST,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = TUNNEL_REQID,
	.priority = 0,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_policy input_policy6 = {
	.d_prefix = NETWORK_LOCAL6,
	.s_prefix = NETWORK_REMOTE6,
	.proto = 0,
	.dst = PORT_EAST6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET6,
	.reqid = TUNNEL_REQID,
	.priority = 0,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

/* input == decrypt, so the dst_family is actually the arrival one */
static struct dp_test_crypto_policy input_policy64 = {
	.d_prefix = NETWORK_LOCAL,
	.s_prefix = NETWORK_REMOTE,
	.proto = 0,
	.dst = PORT_EAST6,
	.dst_family = AF_INET6,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET,
	.reqid = TUNNEL_REQID,
	.priority = 0,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

/* input == decrypt, so the dst_family is actually the arrival one */
static struct dp_test_crypto_policy input_policy46 = {
	.d_prefix = NETWORK_LOCAL6,
	.s_prefix = NETWORK_REMOTE6,
	.proto = 0,
	.dst = PORT_EAST,
	.dst_family = AF_INET,
	.dir = XFRM_POLICY_IN,
	.family = AF_INET6,
	.reqid = TUNNEL_REQID,
	.priority = 0,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

/*
 * Crypto SA definitions used by the tests in this module
 */
static struct dp_test_crypto_sa output_sa = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_OUTBOUND,
	.d_addr = PEER,
	.s_addr = PORT_EAST,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUNNEL_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_sa output_sa6 = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_OUTBOUND6,
	.d_addr = PEER6,
	.s_addr = PORT_EAST6,
	.family = AF_INET6,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUNNEL_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_sa input_sa = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_INBOUND,
	.d_addr = PORT_EAST,
	.s_addr = PEER,
	.family = AF_INET,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUNNEL_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};

static struct dp_test_crypto_sa input_sa6 = {
	.auth_algo = CRYPTO_AUTH_HMAC_SHA1,
	.spi = SPI_INBOUND,
	.d_addr = PORT_EAST6,
	.s_addr = PEER6,
	.family = AF_INET6,
	.mode = XFRM_MODE_TUNNEL,
	.reqid = TUNNEL_REQID,
	.mark = 0,
	.vrfid = VRF_DEFAULT_ID
};


/*
 * Null encrypted ICMP packet with no authentication.
 * The trailing 4 bytes  made up two bytes of padding
 * (0x01, 0x02), pad count (0x02) and protocol (0x04)
 */
const char payload_v4_icmp_null_enc[] = {
	0x45, 0x00, 0x00, 0x54, 0xea, 0x53, 0x40, 0x00,
	0x40, 0x01, 0x38, 0x3d, 0x0a, 0x0a, 0x01, 0x01,
	0x0a, 0x0a, 0x03, 0x04, 0x08, 0x00, 0xfc, 0x62,
	0x0a, 0xc9, 0x00, 0x01, 0x2c, 0x57, 0xba, 0x55,
	0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9, 0x08, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x02, 0x04
};

/*
 * Null encrypted ICMP packet with no authentication.
 * The trailing 4 bytes  made up two bytes of padding
 * (0x01, 0x02), pad count (0x02) and protocol (0x04)
 *
 * this is a packet going from the remote to the
 * local site.
 */
const char payload_v4_icmp_null_enc_rem_to_loc[] = {
	0x45, 0x00, 0x00, 0x54, 0xea, 0x53, 0x40, 0x00,
	0x40, 0x01, 0x38, 0x3d, 0x0a, 0x0a, 0x03, 0x04,
	0x0a, 0x0a, 0x01, 0x01, 0x08, 0x00, 0xfc, 0x62,
	0x0a, 0xc9, 0x00, 0x01, 0x2c, 0x57, 0xba, 0x55,
	0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9, 0x08, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
	0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x02, 0x04
};

/*
 * Null encrypted ICMP6 packet with no authentication.
 * The trailing 8 bytes made up of six bytes of padding
 * (0x01, ..0x06), pad count (0x06) and protocol (0x29)
 */
const char payload_v6_icmp_null_enc[] = {
	0x60, 0x03, 0xa8, 0x69, 0x00, 0x40, 0x3a, 0x40,
	0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x20, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
	0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
	0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x29
};

/*
 * Null encrypted ICMP6 packet with no authentication.
 * The trailing 8 bytes made up of six bytes of padding
 * (0x01, ..0x06), pad count (0x06) and protocol (0x29)
 *
 * this is a packet going from the remote to the
 * local site.
 */
const char payload_v6_icmp_null_enc_rem_to_loc[] = {
	0x60, 0x03, 0xa8, 0x69, 0x00, 0x40, 0x3a, 0x40,
	0x20, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
	0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
	0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
	0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x29
};

static void
dp_test_create_and_send_vfp_set_msg(const char *intf,
				    uint32_t ifindex,
				    VFPSetConfig__Action action)
{
	int len;

	VFPSetConfig vfp = VFPSET_CONFIG__INIT;
	vfp.if_name = (char *)intf;
	vfp.has_if_index = true;
	vfp.if_index = ifindex;
	vfp.has_action = true;
	vfp.action = action;
	vfp.has_type = true;
	vfp.type = VFPSET_CONFIG__VFPTYPE__VFP_S2S_CRYPTO;

	len = vfpset_config__get_packed_size(&vfp);
	void *buf2 = malloc(len);
	dp_test_assert_internal(buf2);

	vfpset_config__pack(&vfp, buf2);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:vfp-set", buf2, len);
}

static void _s2s_add_vfp_and_bind(vrfid_t vrfid, const char *file,
				  const char *func, int line)
{
	int ifi;

	/*
	 * This test setup deliberately sends the vfp get and
	 * s2s binds before the interface netlink to check we
	 * can handle this race condition.
	 * The IPv6 version below uses the correct sequence.
	 */
	dp_test_intf_virt_add("vfp1");

	ifi = dp_test_intf_name2index("vfp1");

	dp_test_create_and_send_vfp_set_msg("vfp1",
			    ifi,
			    VFPSET_CONFIG__ACTION__VFP_ACTION_GET);

	dp_test_create_and_send_s2s_msg(
					CRYPTO_POLICY_CONFIG__ACTION__ATTACH,
					AF_INET,
					ifi,
					vrfid,
					PREFIX_REMOTE,
					MASK,
					PREFIX_LOCAL,
					MASK,
					0, 0, 0, 0);

	_dp_test_check_state_show(file, line, "ipsec bind",
				 "\"virtual-feature-point_name\": \"vfp1\"",
				  false, DP_TEST_CHECK_STR_SUBSET);
	_dp_test_netlink_create_vfp("vfp1", vrfid, false, file, func, line);
	_dp_test_netlink_add_ip_address("vfp1", LINK_LOCAL, VRF_DEFAULT_ID,
					true, file, func, line);
}

static void _s2s_del_vfp_and_unbind(vrfid_t vrfid, const char *file,
				    const char *func, int line)
{
	bool verify = true;
	int ifi = dp_test_intf_name2index("vfp1");

	dp_test_create_and_send_s2s_msg(
					CRYPTO_POLICY_CONFIG__ACTION__DETACH,
					AF_INET,
					ifi,
					vrfid,
					PREFIX_REMOTE,
					MASK,
					PREFIX_LOCAL,
					MASK,
					0, 0, 0, 0);

	dp_test_create_and_send_vfp_set_msg("vfp1",
			    ifi,
			    VFPSET_CONFIG__ACTION__VFP_ACTION_PUT);

	_dp_test_netlink_del_ip_address("vfp1", LINK_LOCAL, vrfid, verify,
					file, func, line);
	_dp_test_intf_vfp_delete("vfp1", vrfid, file, func, line);
}

static void _s2s_setup_interfaces(vrfid_t vrfid, enum vfp_presence with_vfp,
				  enum vrf_and_xfrm_order out_of_order,
				  const char *file, const char *func,
				  int line)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];
	bool verify = true;
	bool incomplete = false;

	if (vrfid != VRF_DEFAULT_ID) {
		if (out_of_order == VRF_XFRM_IN_ORDER) {
			_dp_test_netlink_add_vrf(vrfid, 1, file, line);
		} else {
			_dp_test_netlink_add_vrf_incmpl(vrfid, 1, file, line);
			return;
		}
	}

	if (with_vfp == VFP_TRUE)
		_s2s_add_vfp_and_bind(vrfid, file, func, line);
	_dp_test_netlink_set_interface_vrf("dp1T1", vrfid, verify,
					   file, func, line);
	_dp_test_nl_add_ip_addr_and_connected("dp1T1", "10.10.1.2/24",
					      vrfid, file, func, line);
	_dp_test_netlink_add_neigh("dp1T1", CLIENT_LOCAL, CLIENT_LOCAL_MAC_ADDR,
				   verify, file, func, line);
	/* At the moment dp2 is the transport vrf, and always in default */
	_dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID, verify,
					   file, func, line);
	_dp_test_nl_add_ip_addr_and_connected("dp2T2", "10.10.2.2/24",
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_add_neigh("dp2T2", PEER, PEER_MAC_ADDR, verify,
				   file, func, line);

	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 NETWORK_REMOTE, PEER, "dp2T2");

	_dp_test_netlink_add_route(route_name, verify, incomplete,
				   file, func, line);
}
#define s2s_setup_interfaces(vrfid, with_vfp, out_of_order)	\
	_s2s_setup_interfaces(vrfid, with_vfp, out_of_order,	\
			       __FILE__, __func__, __LINE__)

static void _s2s_setup_interfaces_finish(vrfid_t vrfid,
					 enum vfp_presence with_vfp,
					 const char *file, const char *func,
					 int line)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	if (vrfid != VRF_DEFAULT_ID)
		_dp_test_netlink_add_vrf(vrfid, 1, file, line);

	if (with_vfp == VFP_TRUE)
		_s2s_add_vfp_and_bind(vrfid, file, func, line);
	dp_test_netlink_set_interface_vrf("dp1T1", vrfid);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp1T1", "10.10.1.2/24",
						 vrfid);
	dp_test_netlink_add_neigh("dp1T1", CLIENT_LOCAL, CLIENT_LOCAL_MAC_ADDR);
	/* At the moment dp2 is the transport vrf, and always in default */
	dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID);
	dp_test_nl_add_ip_addr_and_connected_vrf("dp2T2", "10.10.2.2/24",
						 VRF_DEFAULT_ID);
	dp_test_netlink_add_neigh("dp2T2", PEER, PEER_MAC_ADDR);

	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 NETWORK_REMOTE, PEER, "dp2T2");

	dp_test_netlink_add_route(route_name);
}
#define s2s_setup_interfaces_finish(vrfid, with_vfp)			\
	_s2s_setup_interfaces_finish(vrfid, with_vfp,			\
				     __FILE__, __func__, __LINE__)

static void _s2s_add_vfp_and_bind6(vrfid_t vrfid, const char *file,
				  const char *func, int line)
{
	int ifi;

	dp_test_intf_vfp_create("vfp1", vrfid);
	dp_test_netlink_add_ip_address("vfp1", LINK_LOCAL6);
	ifi = dp_test_intf_name2index("vfp1");

	dp_test_create_and_send_vfp_set_msg("vfp1", ifi,
				   VFPSET_CONFIG__ACTION__VFP_ACTION_GET);

	dp_test_create_and_send_s2s_msg(
					CRYPTO_POLICY_CONFIG__ACTION__ATTACH,
					AF_INET6,
					ifi,
					vrfid,
					PREFIX_REMOTE6,
					MASK6,
					PREFIX_LOCAL6,
					MASK6,
					0, 0, 0, 0);
	dp_test_check_state_show("ipsec bind",
				 "\"virtual-feature-point_name\": \"vfp1\"",
				 false);
}

static void _s2s_del_vfp_and_unbind6(vrfid_t vrfid, const char *file,
				     const char *func, int line)
{
	bool verify = true;
	int ifi = dp_test_intf_name2index("vfp1");

	dp_test_create_and_send_s2s_msg(
					CRYPTO_POLICY_CONFIG__ACTION__DETACH,
					AF_INET6,
					ifi,
					vrfid,
					PREFIX_REMOTE6,
					MASK6,
					PREFIX_LOCAL6,
					MASK6,
					0, 0, 0, 0);

	dp_test_create_and_send_vfp_set_msg("vfp1", ifi,
				   VFPSET_CONFIG__ACTION__VFP_ACTION_PUT);
	_dp_test_netlink_del_ip_address("vfp1", LINK_LOCAL6, VRF_DEFAULT_ID,
					verify, file, func, line);
	_dp_test_intf_vfp_delete("vfp1", vrfid, file, func, line);

}

static void _s2s_setup_interfaces6(vrfid_t vrfid, enum vfp_presence with_vfp,
				   const char *file, const char *func, int line)
{
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];
	bool verify = true;
	bool incomplete = false;

	if (vrfid != VRF_DEFAULT_ID)
		_dp_test_netlink_add_vrf(vrfid, 1, file, line);

	if (with_vfp == VFP_TRUE)
		_s2s_add_vfp_and_bind6(vrfid, file, func, line);
	_dp_test_netlink_set_interface_vrf("dp1T1", vrfid, verify,
					   file, func, line);
	_dp_test_nl_add_ip_addr_and_connected("dp1T1", "2001:1::2/64",
					      vrfid, file, func, line);
	_dp_test_netlink_add_neigh("dp1T1", CLIENT_LOCAL6,
				   CLIENT_LOCAL_MAC_ADDR, verify,
				   file, func, line);
	/* At the moment dp2 is the transport vrf, and always in default */
	_dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID, verify,
					   file, func, line);
	_dp_test_nl_add_ip_addr_and_connected("dp2T2", "2001:2::2/64",
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_add_neigh("dp2T2", PEER6, PEER_MAC_ADDR, verify,
				   file, func, line);

	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 NETWORK_REMOTE6, PEER6, "dp2T2");

	_dp_test_netlink_add_route(route_name, verify, incomplete,
				   file, func, line);
}
#define s2s_setup_interfaces6(vrfid, with_vfp) \
	_s2s_setup_interfaces6(vrfid, with_vfp, __FILE__, __func__, __LINE__)


static void _s2s_teardown_interfaces(vrfid_t vrfid, enum vfp_presence with_vfp,
				     bool leave_vrf,
				     const char *file, const char *func,
				     int line)
{
	bool verify = true;
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 NETWORK_REMOTE, PEER, "dp2T2");
	_dp_test_netlink_del_route(route_name, verify,
				   file, func, line);
	_dp_test_netlink_del_neigh("dp2T2", PEER, PEER_MAC_ADDR, verify,
				   file, func, line);
	_dp_test_nl_del_ip_addr_and_connected("dp2T2", "10.10.2.2/24",
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_del_neigh("dp1T1", CLIENT_LOCAL, CLIENT_LOCAL_MAC_ADDR,
				   verify, file, func, line);
	_dp_test_nl_del_ip_addr_and_connected("dp1T1", "10.10.1.2/24",
					      vrfid, file, func, line);
	_dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID, verify,
					   file, func, line);
	_dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID, verify,
					   file, func, line);
	if (with_vfp == VFP_TRUE)
		_s2s_del_vfp_and_unbind(vrfid, file, func, line);
	if (!leave_vrf && (vrfid != VRF_DEFAULT_ID))
		_dp_test_netlink_del_vrf(vrfid, 0, file, line);
}
#define s2s_teardown_interfaces(vrfid, with_vfp) \
	_s2s_teardown_interfaces(vrfid, with_vfp, false, \
				 __FILE__, __func__, __LINE__)

#define s2s_teardown_interfaces_leave_vrf(vrfid, with_vfp) \
	_s2s_teardown_interfaces(vrfid, with_vfp, true,	   \
				 __FILE__, __func__, __LINE__)

static void _s2s_teardown_interfaces6(vrfid_t vrfid, enum vfp_presence with_vfp,
				     const char *file, const char *func,
				     int line)
{
	bool verify = true;
	char route_name[DP_TEST_MAX_ROUTE_STRING_LEN];

	_dp_test_netlink_del_neigh("dp2T2", PEER6, PEER_MAC_ADDR, verify,
				   file, func, line);
	snprintf(route_name, sizeof(route_name),
		 "vrf:%d %s nh %s int:%s", VRF_DEFAULT_ID,
		 NETWORK_REMOTE6, PEER6, "dp2T2");
	_dp_test_netlink_del_route(route_name, verify, file, func, line);
	_dp_test_nl_del_ip_addr_and_connected("dp2T2", "2001:2::2/64",
					      VRF_DEFAULT_ID,
					      file, func, line);
	_dp_test_netlink_del_neigh("dp1T1", CLIENT_LOCAL6,
				   CLIENT_LOCAL_MAC_ADDR, verify,
				   file, func, line);
	_dp_test_nl_del_ip_addr_and_connected("dp1T1", "2001:1::2/64",
					      vrfid, file, func, line);

	_dp_test_netlink_set_interface_vrf("dp1T1", VRF_DEFAULT_ID, verify,
					   file, func, line);
	_dp_test_netlink_set_interface_vrf("dp2T2", VRF_DEFAULT_ID, verify,
					   file, func, line);
	if (with_vfp == VFP_TRUE)
		_s2s_del_vfp_and_unbind6(vrfid, file, func, line);
	if (vrfid != VRF_DEFAULT_ID)
		_dp_test_netlink_del_vrf(vrfid, 0, file, line);
}
#define s2s_teardown_interfaces6(vrfid, with_vfp) \
	_s2s_teardown_interfaces6(vrfid, with_vfp, \
				  __FILE__, __func__, __LINE__)

#define s2s_setup_interfaces_v4_v6(vrfid, vfp, vrf_order)		\
	{								\
		s2s_setup_interfaces(vrfid, vfp, vrf_order);		\
		s2s_setup_interfaces6(vrfid, vfp);			\
	}								\

#define s2s_teardown_interfaces_v4_v6(vrfid, vfp)			\
	{								\
		vrfid == VRF_DEFAULT_ID ?				\
			s2s_teardown_interfaces(vrfid, vfp) :		\
			s2s_teardown_interfaces_leave_vrf(vrfid, vfp),	\
		s2s_teardown_interfaces6(vrfid, vfp);			\
	}								\

static void _setup_policies(struct dp_test_crypto_policy *input,
			    struct dp_test_crypto_policy *output,
			    vrfid_t vrfid, const char *file, int line)
{
	bool verify = true;

	input->vrfid = vrfid;
	output->vrfid = vrfid;
	_dp_test_crypto_create_policy(file, line, input, verify);
	_dp_test_crypto_create_policy(file, line, output, verify);
}
#define setup_policies(input, output, vrf) \
	_setup_policies(input, output, vrf, __FILE__, __LINE__)


static void _teardown_policies(struct dp_test_crypto_policy *input,
			       struct dp_test_crypto_policy *output,
			       const char *file, int line)
{
	_dp_test_crypto_delete_policy(file, line, input, true);
	_dp_test_crypto_delete_policy(file, line, output, true);
}
#define teardown_policies(input, output) \
	_teardown_policies(input, output, __FILE__, __LINE__)

static void _setup_sas(struct dp_test_crypto_sa *input,
		       struct dp_test_crypto_sa *output,
		       vrfid_t vrfid,
		       enum dp_test_crypo_cipher_algo cipher,
		       enum dp_test_crypo_auth_algo auth,
		       int mode,
		       const char *file, const char *func,
		       int line)
{
	bool verify = true;

	input->auth_algo = auth;
	output->auth_algo = auth;
	input->cipher_algo = cipher;
	output->cipher_algo = cipher;
	input->mode = mode;
	output->mode = mode;
	input->vrfid = vrfid;
	output->vrfid = vrfid;
	_dp_test_crypto_create_sa(file, func, line, input, verify);
	_dp_test_crypto_create_sa(file, func, line, output, verify);
}
#define setup_sas(input, output, vrfid, cipher, auth, mode)	\
	_setup_sas(input, output, vrfid, cipher, auth, mode,	\
		   __FILE__, __func__, __LINE__)

static void _teardown_sas(struct dp_test_crypto_sa *input,
			  struct dp_test_crypto_sa *output,
			  const char *file, const char *func,
			  int line)
{
	_dp_test_crypto_delete_sa(file, line, input);
	_dp_test_crypto_delete_sa(file, line, output);
}

#define teardown_sas(input, output)	\
	_teardown_sas(input, output, __FILE__, __func__, __LINE__)

static void s2s_common_setup(vrfid_t vrfid,
			     enum dp_test_crypo_cipher_algo cipher_algo,
			     enum dp_test_crypo_auth_algo auth_algo,
			     struct dp_test_crypto_policy *ipolicy,
			     struct dp_test_crypto_policy *opolicy,
			     unsigned int mode, enum vfp_presence with_vfp,
			     enum vrf_and_xfrm_order out_of_order)
{
	/***************************************************
	 * Configure underlying topology
	 */
	struct dp_test_crypto_policy *ipol, *opol;
	bool verify = true;

	ipol = ipolicy ? ipolicy : &input_policy;
	opol = opolicy ? opolicy : &output_policy;

	s2s_setup_interfaces(vrfid, with_vfp, out_of_order);

	ipol->vrfid = vrfid;
	opol->vrfid = vrfid;

	if (out_of_order == VRF_XFRM_OUT_OF_ORDER)
		verify = false;

	dp_test_crypto_create_policy_verify(ipol, verify);
	dp_test_crypto_create_policy_verify(opol, verify);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 0);
	if (with_vfp == VFP_TRUE)
		dp_test_check_state_show("ipsec spd",
					 "virtual-feature-point", false);

	input_sa.auth_algo = auth_algo;
	input_sa.cipher_algo = cipher_algo;
	output_sa.auth_algo = auth_algo;
	output_sa.cipher_algo = cipher_algo;

	input_sa.mode = mode;
	output_sa.mode = mode;
	input_sa.vrfid = vrfid;
	output_sa.vrfid = vrfid;

	dp_test_crypto_create_sa_verify(&input_sa, verify);
	dp_test_crypto_create_sa_verify(&output_sa, verify);

	if (out_of_order == VRF_XFRM_OUT_OF_ORDER) {
		s2s_setup_interfaces_finish(vrfid, with_vfp);
		wait_for_policy(ipol, true);
		wait_for_policy(opol, true);
		wait_for_sa(&input_sa, true);
		wait_for_sa(&output_sa, true);
	}

	if (with_vfp == VFP_TRUE)
		dp_test_check_state_show("ipsec sad",
					 "virtual-feature-point", false);
}

static void s2s_common_setup6(vrfid_t vrfid,
			      enum dp_test_crypo_cipher_algo cipher_algo,
			      enum dp_test_crypo_auth_algo auth_algo,
			      struct dp_test_crypto_policy *ipolicy,
			      struct dp_test_crypto_policy *opolicy,
			      unsigned int mode, enum vfp_presence with_vfp)
{
	/***************************************************
	 * Configure underlying topology
	 */
	s2s_setup_interfaces6(vrfid, with_vfp);

	struct dp_test_crypto_policy *ipol, *opol;

	ipol = ipolicy ? ipolicy : &input_policy6;
	opol = opolicy ? opolicy : &output_policy6;

	ipol->vrfid = vrfid;
	opol->vrfid = vrfid;
	dp_test_crypto_create_policy(ipol);
	dp_test_crypto_create_policy(opol);

	dp_test_crypto_check_sa_count(VRF_DEFAULT_ID, 0);
	if (with_vfp == VFP_TRUE)
		dp_test_check_state_show("ipsec spd",
					 "virtual-feature-point", false);

	input_sa6.auth_algo = auth_algo;
	input_sa6.cipher_algo = cipher_algo;
	output_sa6.auth_algo = auth_algo;
	output_sa6.cipher_algo = cipher_algo;
	input_sa6.mode = mode;
	output_sa6.mode = mode;
	input_sa6.vrfid = vrfid;
	output_sa6.vrfid = vrfid;

	dp_test_crypto_create_sa(&input_sa6);
	dp_test_crypto_create_sa(&output_sa6);
}

static void s2s_common_teardown(vrfid_t vrfid,
				struct dp_test_crypto_policy *ipolicy,
				struct dp_test_crypto_policy *opolicy,
				enum vfp_presence with_vfp,
				enum vrf_and_xfrm_order out_of_order)

{
	if (out_of_order == VRF_XFRM_OUT_OF_ORDER) {
		/*
		 * Tear down the vrf first, this should cause
		 * a flush of all the ipsec state.
		 */
		s2s_teardown_interfaces(vrfid, with_vfp);
		return;
	}

	dp_test_crypto_delete_sa(&input_sa);
	dp_test_crypto_delete_sa(&output_sa);

	dp_test_crypto_delete_policy(ipolicy ? ipolicy : &input_policy);
	dp_test_crypto_delete_policy(opolicy ? opolicy : &output_policy);

	/***************************************************
	 * Tear down topology
	 */
	s2s_teardown_interfaces(vrfid, with_vfp);
	dp_test_npf_cleanup();
}

static void s2s_common_teardown6(vrfid_t vrfid,
				 struct dp_test_crypto_policy *ipolicy,
				 struct dp_test_crypto_policy *opolicy,
				 enum vfp_presence with_vfp)

{
	dp_test_crypto_delete_sa(&input_sa6);
	dp_test_crypto_delete_sa(&output_sa6);

	dp_test_crypto_delete_policy(ipolicy ? ipolicy : &input_policy6);
	dp_test_crypto_delete_policy(opolicy ? opolicy : &output_policy6);

	/***************************************************
	 * Tear down topology
	 */
	s2s_teardown_interfaces6(vrfid, with_vfp);
	dp_test_npf_cleanup();
}

static void _build_pak_and_expected_encrypt(struct rte_mbuf **ping_pkt_p,
					    struct dp_test_expected **exp_p,
					    const char *rx_intf,
					    const char *tx_intf,
					    const char *local,
					    const char *remote,
					    const char *src_addr,
					    const char *dst_addr,
					    char expected_payload[],
					    int payload_len,
					    vrfid_t transport_vrf,
					    uint8_t in_tos,
					    uint8_t exp_tos,
					    const char *file, const char *func,
					    int line)
{
	struct rte_mbuf *ping_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_addr inner_addr;
	struct dp_test_addr outer_addr;

	/* Construct the input ICMP ping packet. */
	dp_test_addr_str_to_addr(local, &inner_addr);
	if (inner_addr.family == AF_INET) {
		uint16_t cksum;

		ping_pkt = build_input_packet(local, remote);
		dp_test_set_pak_ip_field(iphdr(ping_pkt), DP_TEST_SET_TOS,
					 in_tos);

		/* TOS is the 2nd byte of an ip hdr */
		expected_payload[1] = in_tos;
		/* Fixup checksum too, bytes 11,12*/
		expected_payload[11] = 0;
		expected_payload[12] = 0;
		cksum = dp_in_cksum_hdr((struct iphdr *)&expected_payload[0]);
		*((uint16_t *)&expected_payload[11]) = htons(cksum);
	} else {
		ping_pkt = build_input_packet6(local, remote);
		dp_test_set_pak_ip6_field(ip6hdr(ping_pkt), DP_TEST_SET_TOS,
					  in_tos);

		/* Traffic class is bits 5..12 of an ipv6 header */
		expected_payload[0] &= 0xf0;
		expected_payload[1] &= 0x0f;
		expected_payload[0] |= ((in_tos & 0xf0) >> 4);
		expected_payload[1] |= ((in_tos & 0x0f) << 4);
	}
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str(rx_intf),
				       NULL,
				       inner_addr.family == AF_INET ?
					       RTE_ETHER_TYPE_IPV4 :
					       RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet. If src/dst are v4
	 * build a v4 packet, else build v6
	 */
	dp_test_addr_str_to_addr(src_addr, &outer_addr);
	if (outer_addr.family == AF_INET) {
		encrypted_pkt = dp_test_create_esp_ipv4_pak(
			src_addr, dst_addr, 1,
			&payload_len,
			expected_payload,
			SPI_OUTBOUND,
			1 /* seq no */,
			0 /* ip ID */,
			255 /* ttl */,
			NULL, /* udp/esp */
			NULL /* transport_hdr*/);

		dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_TOS,
					 exp_tos);
	} else {
		encrypted_pkt = dp_test_create_esp_ipv6_pak(
			src_addr, dst_addr, 1,
			&payload_len,
			expected_payload,
			SPI_OUTBOUND6,
			1 /* seq no */,
			0 /* ip ID */,
			64 /* hlim */,
			NULL /* transport_hdr*/);

		dp_test_set_pak_ip6_field(ip6hdr(encrypted_pkt),
					  DP_TEST_SET_TOS, exp_tos);
	}
	dp_test_assert_internal(encrypted_pkt != NULL);
	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str(tx_intf),
				       outer_addr.family == AF_INET ?
					       RTE_ETHER_TYPE_IPV4 :
					       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);

	dp_test_exp_set_oif_name(exp, tx_intf);

	*exp_p = exp;
	*ping_pkt_p = ping_pkt;
}
#define build_pak_and_expected_encrypt(ping_pkt, exp, rx_intf, tx_intf, \
				       local, remote, src_addr, dest_addr, \
				       exp_payload, payload_len,	\
				       transport_vrf, in_tos, exp_tos)	\
	_build_pak_and_expected_encrypt(ping_pkt, exp, rx_intf, tx_intf, \
					local, remote, src_addr, dest_addr, \
					exp_payload, payload_len,	\
					transport_vrf, in_tos, exp_tos,	\
					__FILE__, __func__, __LINE__)

static void _build_pak_and_expected_decrypt(struct rte_mbuf **enc_pkt_p,
					    struct dp_test_expected **exp_p,
					    const char *rx_intf,
					    const char *tx_intf,
					    const char *local,
					    const char *remote,
					    const char *src_addr,
					    const char *dst_addr,
					    char transmit_payload[],
					    int payload_len,
					    vrfid_t transport_vrf,
					    const char *file, const char *func,
					    int line)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *encrypted_pkt;
	struct rte_mbuf *expected_pkt;
	struct dp_test_addr inner_addr;
	struct dp_test_addr outer_addr;

	/* Construct the output ICMP ping packet. */
	dp_test_addr_str_to_addr(local, &inner_addr);
	if (inner_addr.family == AF_INET) {
		expected_pkt = build_input_packet(local, remote);
		dp_test_set_pak_ip_field(iphdr(expected_pkt),
					 DP_TEST_SET_TTL, 0x3f);
	} else {
		expected_pkt = build_input_packet6(local, remote);
		dp_test_ipv6_decrement_ttl(expected_pkt);
	}

	(void)dp_test_pktmbuf_eth_init(expected_pkt, CLIENT_LOCAL_MAC_ADDR,
				       dp_test_intf_name2mac_str(tx_intf),
				       inner_addr.family == AF_INET ?
					       RTE_ETHER_TYPE_IPV4 :
					       RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet. If src/dst are v4
	 * build a v4 packet, else build v6
	 */
	dp_test_addr_str_to_addr(src_addr, &outer_addr);
	if (outer_addr.family == AF_INET) {
		encrypted_pkt =
			dp_test_create_esp_ipv4_pak(src_addr, dst_addr, 1,
						    &payload_len,
						    transmit_payload,
						    SPI_INBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    NULL /* transport_hdr*/);

	} else {
		encrypted_pkt =
			dp_test_create_esp_ipv6_pak(src_addr, dst_addr, 1,
						    &payload_len,
						    transmit_payload,
						    SPI_INBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* transport_hdr*/);
	}
	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       dp_test_intf_name2mac_str(rx_intf),
				       PEER_MAC_ADDR,
				       outer_addr.family == AF_INET ?
					       RTE_ETHER_TYPE_IPV4 :
					       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(expected_pkt);
	rte_pktmbuf_free(expected_pkt);
	dp_test_exp_set_oif_name(exp, tx_intf);

	*exp_p = exp;
	*enc_pkt_p = encrypted_pkt;
}

#define build_pak_and_expected_decrypt(ping_pkt, exp, rx_intf, tx_intf, \
				       local, remote, src_addr, dest_addr, \
				       exp_payload, payload_len,	\
				       transport_vrf)			\
	_build_pak_and_expected_decrypt(ping_pkt, exp, rx_intf, tx_intf, \
					local, remote, src_addr, dest_addr, \
					exp_payload, payload_len,	\
					transport_vrf, __FILE__,	\
					__func__, __LINE__)


static void null_encrypt_transport_main(vrfid_t vrfid)
{
	/*
	 * Null encrypted ICMP packet with no authentication.
	 * The trailing 4 bytes  made up two bytes of padding
	 * (0x01, 0x02), pad count (0x02) and protocol (0x04)
	 */
	const char expected_payload[] = {
		0x08, 0x00, 0xfc, 0x62, 0x0a, 0xc9, 0x00, 0x01,
		0x2c, 0x57, 0xba, 0x55, 0x00, 0x00, 0x00, 0x00,
		0xd9, 0xe9, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x02, 0xe0
	};
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	struct iphdr  *trans_mode_hdr;
	int payload_len;

	s2s_common_setup(vrfid, CRYPTO_CIPHER_NULL, CRYPTO_AUTH_NULL,
			 NULL, NULL,
			 XFRM_MODE_TRANSPORT, VFP_FALSE, VRF_XFRM_IN_ORDER);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet(CLIENT_LOCAL, CLIENT_REMOTE);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);
	dp_test_set_pak_ip_field(iphdr(ping_pkt), DP_TEST_SET_PROTOCOL, 224);

	/*
	 * Construct the expected encrypted packet
	 */
	trans_mode_hdr = dp_pktmbuf_mtol3(ping_pkt, struct iphdr *);
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv4_pak(PORT_EAST, PEER, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    trans_mode_hdr);
	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 64);

	s2s_common_teardown(vrfid, NULL, NULL, VFP_FALSE, VRF_XFRM_IN_ORDER);
}

static void encrypt_aesgcm_main(vrfid_t vrfid)
{
		const char expected_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45,
		0x54, 0xd6, 0x58, 0x24, 0x68, 0x3a, 0xb5, 0xaf,
		0xde, 0xb5, 0xd3, 0x1d, 0x42, 0xd5, 0x9d, 0x6d,
		0xfe, 0x60, 0x20, 0x5a, 0x42, 0xa7, 0x34, 0xa4,
		0xb4, 0xd7, 0x75, 0x62, 0xa8, 0x41, 0x57, 0x35,
		0x18, 0xb8, 0x9b, 0xe3, 0xfc, 0x8c, 0xc3, 0xe2,
		0x38, 0x2c, 0xad, 0xeb, 0x2d, 0x2f, 0x39, 0x4c,
		0x36, 0x83, 0xea, 0x2f, 0x10, 0xc5, 0x21, 0x94,
		0xc5, 0x04, 0x88, 0x58, 0xad, 0x43, 0x86, 0x1c,
		0x2c, 0xf4, 0x7a, 0x05, 0xde, 0x61, 0x24, 0x64,
		0x16, 0x43, 0x7e, 0x2c, 0xba, 0x60, 0xb3, 0x26,
		0x28, 0x20, 0x85, 0xca, 0xf3, 0xe5, 0x07, 0xfd,
		0x61, 0x9d, 0x59, 0xe6, 0x55, 0xde, 0x9e, 0x26,
		0xb7, 0x8e, 0x56, 0x28, 0x89, 0x73, 0x21, 0x48,
		0x38, 0x21
	};
	struct if_data start_stats_dp1T1, start_stats_dp2T2;
	struct if_data stats_dp1T1, stats_dp2T2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;

	s2s_common_setup(vrfid, CRYPTO_CIPHER_AES128GCM,
			 CRYPTO_AUTH_HMAC_SHA1,
			 NULL, NULL,
			 XFRM_MODE_TUNNEL, VFP_FALSE, VRF_XFRM_IN_ORDER);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet(CLIENT_LOCAL, CLIENT_REMOTE);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv4_pak(PORT_EAST, PEER, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL, /* udp/esp */
						    NULL /* transport_hdr*/);
	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_intf_initial_stats_for_if("dp1T1", &start_stats_dp1T1);
	dp_test_intf_initial_stats_for_if("dp2T2", &start_stats_dp2T2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	dp_test_intf_delta_stats_for_if("dp1T1", &start_stats_dp1T1,
					&stats_dp1T1);

	dp_test_assert_internal(stats_dp1T1.ifi_ipackets == 1);
	dp_test_assert_internal(stats_dp1T1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp1T1) == 0);

	dp_test_intf_delta_stats_for_if("dp2T2", &start_stats_dp2T2,
					&stats_dp2T2);
	dp_test_assert_internal(stats_dp2T2.ifi_ipackets == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_opackets == 1);
	dp_test_assert_internal(stats_dp2T2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp2T2) == 0);

	s2s_common_teardown(vrfid, NULL, NULL, VFP_FALSE, VRF_XFRM_IN_ORDER);
}

static void encrypt_main(vrfid_t vrfid, enum vrf_and_xfrm_order out_of_order)
{
	const char expected_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6,
		0xb1, 0x0c, 0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3,
		0x44, 0x6c, 0xbe, 0x0e, 0x1f, 0xa5, 0x93, 0xca,
		0xcd, 0x67, 0x6d, 0x61, 0xa6, 0x5d, 0x12, 0xa2,
		0x51, 0xe5, 0xd7, 0x20, 0x9a, 0xd7, 0x88, 0xa8,
		0x68, 0x26, 0x8b, 0xfa, 0x4b, 0xac, 0x67, 0xab,
		0x63, 0xf6, 0x65, 0x07, 0x63, 0xa6, 0x52, 0xa3,
		0xf8, 0xa1, 0x91, 0x5a, 0x60, 0x87, 0x07, 0x8e,
		0x7e, 0xd0, 0x15, 0xab, 0x13, 0x92, 0x18, 0xbe,
		0x16, 0x9f, 0x08, 0xd6, 0xa8, 0xf1, 0x09, 0x33,
		0xc0, 0x54, 0x0b, 0x72, 0x80, 0xc6, 0x35, 0xfb,
		0x08, 0xab, 0x35, 0xa1, 0xe3, 0x7c, 0x29, 0xc2,
		0x9b, 0x88, 0xf1, 0xc0, 0xcf, 0x04, 0xd3, 0x43,
		0x83, 0x78, 0xb9, 0xeb, 0xaf, 0xda, 0xd4, 0x83,
		0x56, 0xc5, 0xe9, 0xd1, 0x03, 0x41, 0xec, 0xbc,
		0x99, 0xa5, 0x9d, 0xaf
	};
	struct if_data start_stats_dp1T1, start_stats_dp2T2;
	struct if_data stats_dp1T1, stats_dp2T2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;

	s2s_common_setup(vrfid, CRYPTO_CIPHER_AES_CBC,
			 CRYPTO_AUTH_HMAC_SHA1,
			 NULL, NULL,
			 XFRM_MODE_TUNNEL, VFP_FALSE, out_of_order);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet(CLIENT_LOCAL, CLIENT_REMOTE);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv4_pak(PORT_EAST, PEER, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    NULL /* transport_hdr*/);
	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_intf_initial_stats_for_if("dp1T1", &start_stats_dp1T1);
	dp_test_intf_initial_stats_for_if("dp2T2", &start_stats_dp2T2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	dp_test_intf_delta_stats_for_if("dp1T1", &start_stats_dp1T1,
					&stats_dp1T1);

	dp_test_assert_internal(stats_dp1T1.ifi_ipackets == 1);
	dp_test_assert_internal(stats_dp1T1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp1T1) == 0);

	dp_test_intf_delta_stats_for_if("dp2T2", &start_stats_dp2T2,
					&stats_dp2T2);
	dp_test_assert_internal(stats_dp2T2.ifi_ipackets == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_opackets == 1);
	dp_test_assert_internal(stats_dp2T2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp2T2) == 0);

	s2s_common_teardown(vrfid, NULL, NULL, VFP_FALSE, out_of_order);
}

static void encrypt6_main(vrfid_t vrfid)
{
	const char expected_payload[] = {
		0x64, 0xc8, 0x6e, 0x89, 0x53, 0x45, 0x54, 0xd6,
		0xb1, 0x0c, 0x8c, 0xca, 0xc4, 0x44, 0xbf, 0xd3,
		0xaf, 0x25, 0xfa, 0x8e, 0x71, 0x62, 0xcc, 0xc0,
		0x77, 0xc3, 0x61, 0x7a, 0xcc, 0x72, 0x31, 0x4b,
		0x38, 0x64, 0x75, 0xb5, 0x2d, 0x24, 0x3a, 0x79,
		0x1b, 0x74, 0x4e, 0x94, 0xbd, 0xe2, 0xe8, 0x72,
		0x74, 0x26, 0x5e, 0x2e, 0x21, 0x36, 0x7a, 0xee,
		0x6c, 0xdf, 0x22, 0xc5, 0x9c, 0xe5, 0x4f, 0x4e,
		0xfb, 0x85, 0x13, 0x61, 0x3c, 0xb1, 0xc0, 0x11,
		0x5f, 0xe3, 0xf0, 0xe4, 0xfe, 0x7f, 0x2f, 0x93,
		0x73, 0xf7, 0xea, 0xad, 0x8c, 0xc8, 0xbd, 0xd0,
		0xea, 0x91, 0x34, 0xeb, 0x2a, 0xe4, 0x38, 0x69,
		0x4c, 0xe2, 0x60, 0x1d, 0x48, 0xdb, 0x24, 0x1d,
		0x3b, 0x61, 0x87, 0x16, 0x05, 0x59, 0x36, 0xcf,
		0xca, 0x88, 0x66, 0xf9, 0x30, 0x2a, 0xbd, 0xc3,
		0x87, 0xd1, 0xd8, 0x16, 0xf1, 0xd3, 0xf9, 0x68,
		0xd0, 0xac, 0xec, 0xd0, 0xf4, 0xe9, 0x06, 0x3a,
		0xe0, 0x6d, 0x0e, 0x13
	};
	struct if_data start_stats_dp1T1, start_stats_dp2T2;
	struct if_data stats_dp1T1, stats_dp2T2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;

	s2s_common_setup6(vrfid, CRYPTO_CIPHER_AES_CBC,
			  CRYPTO_AUTH_HMAC_SHA1,
			  NULL, NULL,
			  XFRM_MODE_TUNNEL, VFP_FALSE);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet6(CLIENT_LOCAL6, CLIENT_REMOTE6);
	dp_test_assert_internal(ping_pkt != NULL);

	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv6_pak(PORT_EAST6, PEER6, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND6,
						    1 /* seq no */,
						    0 /* ip ID */,
						    64 /* hlim */,
						    NULL /* transport_hdr*/);
	dp_test_assert_internal(encrypted_pkt != NULL);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	dp_test_intf_initial_stats_for_if("dp1T1", &start_stats_dp1T1);
	dp_test_intf_initial_stats_for_if("dp2T2", &start_stats_dp2T2);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	dp_test_intf_delta_stats_for_if("dp1T1", &start_stats_dp1T1,
					&stats_dp1T1);

	dp_test_assert_internal(stats_dp1T1.ifi_ipackets == 1);
	dp_test_assert_internal(stats_dp1T1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp1T1) == 0);

	dp_test_intf_delta_stats_for_if("dp2T2", &start_stats_dp2T2,
					&stats_dp2T2);
	dp_test_assert_internal(stats_dp2T2.ifi_ipackets == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_opackets == 1);
	dp_test_assert_internal(stats_dp2T2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp2T2) == 0);

	s2s_common_teardown6(vrfid, NULL, NULL, VFP_FALSE);
}

static void bad_hash_algorithm_main(vrfid_t vrfid)
{
	struct dp_test_expected *exp = dp_test_exp_create(NULL);
	struct rte_mbuf *ping = build_input_packet(CLIENT_LOCAL,
						   CLIENT_REMOTE);

	s2s_common_setup(vrfid, CRYPTO_CIPHER_AES_CBC,
			 CRYPTO_AUTH_HMAC_XCBC,
			 NULL, NULL,
			 XFRM_MODE_TUNNEL, VFP_FALSE, VRF_XFRM_IN_ORDER);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(ping, "dp1T1", exp);

	s2s_common_teardown(vrfid, NULL, NULL, VFP_FALSE, VRF_XFRM_IN_ORDER);
}

static void bad_hash_algorithm6_main(vrfid_t vrfid)
{
	struct dp_test_expected *exp = dp_test_exp_create(NULL);
	struct rte_mbuf *ping = build_input_packet6(CLIENT_LOCAL6,
						    CLIENT_REMOTE6);

	s2s_common_setup6(vrfid, CRYPTO_CIPHER_AES_CBC,
			  CRYPTO_AUTH_HMAC_XCBC,
			  NULL, NULL,
			  XFRM_MODE_TUNNEL, VFP_FALSE);

	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	dp_test_pak_receive(ping, "dp1T1", exp);

	s2s_common_teardown6(vrfid, NULL, NULL, VFP_FALSE);
}

static void null_encrypt_main(vrfid_t vrfid, enum vfp_presence with_vfp)
{
	char expected_payload_novfp[sizeof(payload_v4_icmp_null_enc)];

	/* Using a vfp (correctly) decrements ttl */
	const char expected_payload_vfp[] = {
		0x45, 0x00, 0x00, 0x54, 0xea, 0x53, 0x40, 0x00,
		0x3f, 0x01, 0x39, 0x3d, 0x0a, 0x0a, 0x01, 0x01,
		0x0a, 0x0a, 0x03, 0x04, 0x08, 0x00, 0xfc, 0x62,
		0x0a, 0xc9, 0x00, 0x01, 0x2c, 0x57, 0xba, 0x55,
		0x00, 0x00, 0x00, 0x00, 0xd9, 0xe9, 0x08, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x02, 0x04
	};
	const char *expected_payload = with_vfp ? expected_payload_vfp :
		expected_payload_novfp;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;

	memcpy(expected_payload_novfp, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));

	s2s_common_setup(vrfid, CRYPTO_CIPHER_NULL, CRYPTO_AUTH_NULL,
			 NULL, NULL,
			 XFRM_MODE_TUNNEL, with_vfp, VRF_XFRM_IN_ORDER);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet(CLIENT_LOCAL, CLIENT_REMOTE);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload_novfp);
	encrypted_pkt = dp_test_create_esp_ipv4_pak(PORT_EAST, PEER, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    NULL /* transport_hdr*/);
	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);
	if (with_vfp == VFP_TRUE)
		dp_test_check_state_show("ifconfig vfp1",
					 "tx_packets\": 1", false);

	s2s_common_teardown(vrfid, NULL, NULL, with_vfp, VRF_XFRM_IN_ORDER);
}

static void null_encrypt6_transport_main(vrfid_t vrfid)
{
	/*
	 * Null encrypted ICMP packet with no authentication.
	 */
	const char expected_payload[] = {
		0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
		0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
		0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x3a
	};
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	struct ip6_hdr  *trans_mode_hdr;
	int payload_len;

	s2s_common_setup6(vrfid, CRYPTO_CIPHER_NULL, CRYPTO_AUTH_NULL,
			  NULL, NULL,
			  XFRM_MODE_TRANSPORT, VFP_FALSE);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet6(CLIENT_LOCAL6, CLIENT_REMOTE6);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet
	 */
	trans_mode_hdr = dp_pktmbuf_mtol3(ping_pkt, struct ip6_hdr *);
	payload_len = sizeof(expected_payload);
	encrypted_pkt = dp_test_create_esp_ipv6_pak(PORT_EAST6, PEER6, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND6,
						    1 /* seq no */,
						    0 /* ip ID */,
						    64 /* ttl */,
						    trans_mode_hdr);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 64);

	s2s_common_teardown6(vrfid, NULL, NULL, VFP_FALSE);
}

static void null_encrypt6_main(vrfid_t vrfid, enum vfp_presence with_vfp)
{
	/*
	 * Null encrypted ICMP packet with no authentication.
	 */
	const char expected_payload_novfp[] = {
		0x60, 0x03, 0xa8, 0x69, 0x00, 0x40, 0x3a, 0x40,
		0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
		0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
		0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
		0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x29
	};
	/* Using a vfp (correctly) decrements hop limit */
	const char expected_payload_vfp[] = {
		0x60, 0x03, 0xa8, 0x69, 0x00, 0x40, 0x3a, 0x3f,
		0x20, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x20, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
		0x80, 0x00, 0x96, 0x4e, 0x0d, 0x62, 0x00, 0x01,
		0x57, 0xda, 0xe8, 0x57, 0x00, 0x00, 0x00, 0x00,
		0x91, 0xc3, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x06, 0x29
	};
	const char *expected_payload = with_vfp ? expected_payload_vfp :
		expected_payload_novfp;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	int payload_len;

	s2s_common_setup6(vrfid, CRYPTO_CIPHER_NULL, CRYPTO_AUTH_NULL,
			  NULL, NULL,
			  XFRM_MODE_TUNNEL, with_vfp);

	/*
	 * Construct the input ICMP ping packet.
	 */
	ping_pkt = build_input_packet6(CLIENT_LOCAL6, CLIENT_REMOTE6);
	(void)dp_test_pktmbuf_eth_init(ping_pkt,
				       dp_test_intf_name2mac_str("dp1T1"),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/*
	 * Construct the expected encrypted packet
	 */
	payload_len = sizeof(expected_payload_novfp);
	encrypted_pkt = dp_test_create_esp_ipv6_pak(PORT_EAST6, PEER6, 1,
						    &payload_len,
						    expected_payload,
						    SPI_OUTBOUND6,
						    1 /* seq no */,
						    0 /* ip ID */,
						    64 /* ttl */,
						    NULL /* transport_hdr*/);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       PEER_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp2T2"),
				       RTE_ETHER_TYPE_IPV6);

	exp = dp_test_exp_create(encrypted_pkt);
	rte_pktmbuf_free(encrypted_pkt);
	dp_test_exp_set_oif_name(exp, "dp2T2");

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	if (with_vfp == VFP_TRUE)
		dp_test_check_state_show("ifconfig vfp1",
					 "tx_packets\": 1", false);

	s2s_common_teardown6(vrfid, NULL, NULL, with_vfp);
}

static void s2s_toobig6_main(vrfid_t vrfid)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak;
	struct rte_mbuf *icmp_pak;
	struct icmp6_hdr *icmp6;
	struct ip6_hdr *ip6;
	int len = 1572;
	int icmplen;

	s2s_common_setup6(vrfid, CRYPTO_CIPHER_AES_CBC,
			  CRYPTO_AUTH_HMAC_SHA1,
			  NULL, NULL,
			  XFRM_MODE_TUNNEL, VFP_FALSE);

	/*
	 * Construct oversize packet
	 */
	test_pak = dp_test_create_ipv6_pak(CLIENT_LOCAL6, CLIENT_REMOTE6,
					   1, &len);
	dp_test_pktmbuf_eth_init(test_pak, dp_test_intf_name2mac_str("dp1T1"),
				 CLIENT_LOCAL_MAC_ADDR, RTE_ETHER_TYPE_IPV6);

	/*
	 *  Expected ICMP response
	 *  Note that s2s sets MTU based on policy effective block size
	 */
	icmplen = 1280 - sizeof(struct ip6_hdr) - sizeof(struct icmp6_hdr);
	icmp_pak = dp_test_create_icmp_ipv6_pak(PORT_WEST6, CLIENT_LOCAL6,
						ICMP6_PACKET_TOO_BIG,
						0, /* code */
						1422, /* mtu */
						1, &icmplen,
						ip6hdr(test_pak),
						&ip6, &icmp6);

	/*
	 * Tweak the expected packet
	 */
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       CLIENT_LOCAL_MAC_ADDR,
				       dp_test_intf_name2mac_str("dp1T1"),
				       RTE_ETHER_TYPE_IPV6);

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = dp_test_ipv6_icmp_cksum(icmp_pak, ip6, icmp6);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);
	dp_test_exp_set_oif_name(exp, "dp1T1");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp1T1", exp);

	s2s_common_teardown6(vrfid, NULL, NULL, VFP_FALSE);
}

static void null_decrypt_main(vrfid_t vrfid, enum inner_validity valid)
{
	struct if_data start_stats_dp1T1, start_stats_dp2T2;
	struct if_data stats_dp1T1, stats_dp2T2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pkt;
	int payload_len;

	s2s_common_setup(vrfid, CRYPTO_CIPHER_NULL, CRYPTO_AUTH_NULL,
			 NULL, NULL,
			 XFRM_MODE_TUNNEL, VFP_FALSE, VRF_XFRM_IN_ORDER);

	/*
	 * Construct the output ICMP ping packet. We need to reduce
	 * ttl by 1 to allow for switching.
	 */
	if (valid == INNER_LOCAL) {
		expected_pkt = build_input_packet(CLIENT_REMOTE, PORT_WEST);

		dp_test_pktmbuf_eth_init(expected_pkt,
					 dp_test_intf_name2mac_str("dp2T2"),
					 PEER_MAC_ADDR,
					 RTE_ETHER_TYPE_IPV4);
	} else {
		expected_pkt = build_input_packet(CLIENT_REMOTE, CLIENT_LOCAL);

		if (valid == INNER_INVALID)
			/* Make the checksum wrong */
			iphdr(expected_pkt)->check++;

		dp_test_pktmbuf_eth_init(expected_pkt, CLIENT_LOCAL_MAC_ADDR,
					 dp_test_intf_name2mac_str("dp1T1"),
					 RTE_ETHER_TYPE_IPV4);
	}

	/*
	 * Construct the encrypted packet to inject
	 */

	/*
	 * Add padding to make modulo of blocksize for the cipher plus
	 * padding length and next proto
	 */
	char *trailer = rte_pktmbuf_append(expected_pkt, 4);
	trailer[0] = 1;
	trailer[1] = 2;
	trailer[2] = 2 /* padding length */;
	trailer[3] = IPPROTO_IPIP;

	payload_len = ntohs(iphdr(expected_pkt)->tot_len) + 4;
	encrypted_pkt = dp_test_create_esp_ipv4_pak(PEER, PORT_EAST, 1,
						    &payload_len,
						    (char *)iphdr(expected_pkt),
						    SPI_INBOUND,
						    1 /* seq no */,
						    0 /* ip ID */,
						    255 /* ttl */,
						    NULL /* udp/esp */,
						    NULL /* transport_hdr*/);

	rte_pktmbuf_trim(expected_pkt, 4);
	if (valid != INNER_LOCAL) {
		dp_test_set_pak_ip_field(iphdr(expected_pkt),
					 DP_TEST_SET_TTL, 0x3f);
	}

	dp_test_set_pak_ip_field(iphdr(encrypted_pkt), DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       dp_test_intf_name2mac_str("dp2T2"),
				       PEER_MAC_ADDR,
				       RTE_ETHER_TYPE_IPV4);

	exp = dp_test_exp_create(expected_pkt);
	rte_pktmbuf_free(expected_pkt);
	if (valid == INNER_LOCAL)
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	else if (valid == INNER_INVALID)
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	else
		dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_intf_initial_stats_for_if("dp1T1", &start_stats_dp1T1);
	dp_test_intf_initial_stats_for_if("dp2T2", &start_stats_dp2T2);

	/* transmit the encrypted packet and await the result */
	dp_test_pak_receive(encrypted_pkt, "dp2T2", exp);

	dp_test_intf_delta_stats_for_if("dp1T1", &start_stats_dp1T1,
					&stats_dp1T1);
	dp_test_intf_delta_stats_for_if("dp2T2", &start_stats_dp2T2,
					&stats_dp2T2);

	if (valid == INNER_INVALID) {
		dp_test_crypto_check_sad_packets(vrfid, 0, 0);
	} else {
		dp_test_crypto_check_sad_packets(vrfid, 1, 84);
	}

	dp_test_assert_internal(stats_dp1T1.ifi_ipackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_idropped == 0);
	if (valid == INNER_INVALID || valid == INNER_LOCAL)
		dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	else
		dp_test_assert_internal(stats_dp1T1.ifi_opackets == 1);
	dp_test_assert_internal(ifi_odropped(&stats_dp1T1) == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_ipackets == 1);
	dp_test_assert_internal(stats_dp2T2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp2T2) == 0);

	s2s_common_teardown(vrfid, NULL, NULL, VFP_FALSE, VRF_XFRM_IN_ORDER);
}

static void null_decrypt_main6(vrfid_t vrfid, enum inner_validity valid)
{
	struct if_data start_stats_dp1T1, start_stats_dp2T2;
	struct if_data stats_dp1T1, stats_dp2T2;
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;
	struct rte_mbuf *expected_pkt;
	int payload_len;

	s2s_common_setup6(vrfid, CRYPTO_CIPHER_NULL, CRYPTO_AUTH_NULL,
			  NULL, NULL,
			  XFRM_MODE_TUNNEL, VFP_FALSE);

	if (valid == INNER_LOCAL) {
		expected_pkt = build_input_packet6(CLIENT_REMOTE6, PORT_WEST6);

		dp_test_pktmbuf_eth_init(expected_pkt,
					 dp_test_intf_name2mac_str("dp2T2"),
					 PEER_MAC_ADDR,
					 RTE_ETHER_TYPE_IPV6);
	} else {
		/*
		 * Construct the output ICMP ping packet. We need to reduce
		 * ttl by 1 to allow for switching.
		 */
		expected_pkt = build_input_packet6(CLIENT_REMOTE6,
						   CLIENT_LOCAL6);

		dp_test_pktmbuf_eth_init(expected_pkt,
					 CLIENT_LOCAL_MAC_ADDR,
					 dp_test_intf_name2mac_str("dp1T1"),
					 RTE_ETHER_TYPE_IPV6);
	}

	/*
	 * Construct the encrypted packet to inject
	 */

	/*
	 * Add padding to make modulo of blocksize for the cipher plus
	 * padding length and next proto
	 */
	char *trailer = rte_pktmbuf_append(expected_pkt, 8);
	trailer[0] = 1;
	trailer[1] = 2;
	trailer[2] = 3;
	trailer[3] = 4;
	trailer[4] = 5;
	trailer[5] = 6;
	trailer[6] = 6 /* padding length */;
	trailer[7] = IPPROTO_IPV6;

	payload_len = ntohs(ip6hdr(expected_pkt)->ip6_plen) +
		sizeof(struct ip6_hdr) + 8;

	if (valid == INNER_INVALID)
		/* Make the length longer than the mbuf length */
		ip6hdr(expected_pkt)->ip6_plen = htons(0xff00);

	encrypted_pkt = dp_test_create_esp_ipv6_pak(
		PEER6, PORT_EAST6, 1, &payload_len,
		(char *)ip6hdr(expected_pkt),
		SPI_INBOUND, 1 /* seq no */, 0 /* ip ID */,
		255 /* ttl */, NULL /* transport_hdr*/);
	(void)dp_test_pktmbuf_eth_init(encrypted_pkt,
				       dp_test_intf_name2mac_str("dp2T2"),
				       PEER_MAC_ADDR,
				       RTE_ETHER_TYPE_IPV6);

	rte_pktmbuf_trim(expected_pkt, 8);
	if (valid != INNER_LOCAL)
		dp_test_ipv6_decrement_ttl(expected_pkt);

	exp = dp_test_exp_create(expected_pkt);
	rte_pktmbuf_free(expected_pkt);
	if (valid == INNER_LOCAL)
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_LOCAL);
	else if (valid == INNER_INVALID)
		dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_DROPPED);
	else
		dp_test_exp_set_oif_name(exp, "dp1T1");

	dp_test_intf_initial_stats_for_if("dp1T1", &start_stats_dp1T1);
	dp_test_intf_initial_stats_for_if("dp2T2", &start_stats_dp2T2);

	/* transmit the encrypted packet and await the result */
	dp_test_pak_receive(encrypted_pkt, "dp2T2", exp);

	dp_test_intf_delta_stats_for_if("dp1T1", &start_stats_dp1T1,
					&stats_dp1T1);
	dp_test_intf_delta_stats_for_if("dp2T2", &start_stats_dp2T2,
					&stats_dp2T2);

	if (valid == INNER_INVALID || valid == INNER_LOCAL)
		dp_test_crypto_check_sad_packets(vrfid, 0, 0);
	else
		dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	dp_test_assert_internal(stats_dp1T1.ifi_ipackets == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp1T1.ifi_idropped == 0);
	if (valid == INNER_INVALID || valid == INNER_LOCAL)
		dp_test_assert_internal(stats_dp1T1.ifi_opackets == 0);
	else
		dp_test_assert_internal(stats_dp1T1.ifi_opackets == 1);

	dp_test_assert_internal(ifi_odropped(&stats_dp1T1) == 0);

	dp_test_assert_internal(stats_dp2T2.ifi_ipackets == 1);
	dp_test_assert_internal(stats_dp2T2.ifi_ierrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_opackets == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_oerrors  == 0);
	dp_test_assert_internal(stats_dp2T2.ifi_idropped == 0);
	dp_test_assert_internal(ifi_odropped(&stats_dp2T2) == 0);

	s2s_common_teardown6(vrfid, NULL, NULL, VFP_FALSE);
}

static void
test_plaintext_packet_matching_input_policy(vrfid_t vrfid,
					    const char *ifout,
					    const char *ifin,
					    struct if_data *exp_stats_ifout,
					    struct if_data *exp_stats_ifin,
					    struct dp_test_crypto_policy *ipol,
					    struct dp_test_crypto_policy *opol,
					    const char *saddr,
					    const char *daddr,
					    uint16_t udp_port,
					    int exp_status)
{
	struct if_data start_stats_ifout, start_stats_ifin;
	struct if_data stats_ifout, stats_ifin;
	struct dp_test_expected *exp;
	struct rte_mbuf *pkt;
	int len = 512;
	int dis, del, inp;
	int dis2, del2, inp2;

	s2s_common_setup(vrfid,
			 CRYPTO_CIPHER_AES_CBC,
			 CRYPTO_AUTH_HMAC_SHA1,
			 ipol, opol,
			 XFRM_MODE_TUNNEL, VFP_FALSE, VRF_XFRM_IN_ORDER);

	pkt = dp_test_create_udp_ipv4_pak(saddr, daddr, udp_port, udp_port,
					  1, &len);
	(void)dp_test_pktmbuf_eth_init(pkt,
				       dp_test_intf_name2mac_str(ifin),
				       NULL, RTE_ETHER_TYPE_IPV4);

	/*
	 * The packet should be dropped because it is received in
	 * plain text but matches an input policy, indicating that
	 * it should have been encrypted.
	 */
	if (exp_status != DP_TEST_FWD_DROPPED) {
		exp = dp_test_exp_create(pkt);
		dp_test_exp_set_oif_name(exp, ifout);
		dp_test_exp_set_fwd_status(exp, exp_status);
	} else {
		exp = generate_exp_unreachable(pkt, len, PORT_EAST, saddr,
					       ifin, PEER_MAC_ADDR);
	}

	dp_test_intf_initial_stats_for_if(ifout, &start_stats_ifout);
	dp_test_intf_initial_stats_for_if(ifin, &start_stats_ifin);

	dis = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INNOROUTES);
	del = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INDELIVERS);
	inp = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INPKTS);

	dp_test_pak_receive(pkt, ifin, exp);

	dp_test_crypto_check_sad_packets(vrfid, 0, 0);

	dp_test_intf_delta_stats_for_if(ifout, &start_stats_ifout,
					&stats_ifout);
	dp_test_intf_delta_stats_for_if(ifin, &start_stats_ifin,
					&stats_ifin);

	dp_test_validate_if_stats(&stats_ifout, exp_stats_ifout);
	dp_test_validate_if_stats(&stats_ifin, exp_stats_ifin);
	dis2 = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INNOROUTES);
	del2 = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INDELIVERS);
	inp2 = dp_test_get_vrf_stat(vrfid, AF_INET, IPSTATS_MIB_INPKTS);
	dp_test_verify_vrf_stats(inp, inp2, dis, dis2, del, del2, exp_status);

	s2s_common_teardown(vrfid, ipol, opol, VFP_FALSE, VRF_XFRM_IN_ORDER);
}

static void drop_plaintext_packet_matching_input_policy_main(vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};

	exp_stats_ifin.ifi_ipackets = 1;
	exp_stats_ifin.ifi_opackets = 1;

	test_plaintext_packet_matching_input_policy(vrfid,
						    "dp1T1", "dp2T2",
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    NULL, NULL,
						    CLIENT_REMOTE,
						    CLIENT_LOCAL,
						    0,
						    DP_TEST_FWD_DROPPED);
}

static void drop_plaintext_local_pkt_match_inpolicy(vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};

	struct dp_test_crypto_policy my_ipol = input_policy;
	struct dp_test_crypto_policy my_opol = output_policy;

	exp_stats_ifin.ifi_ipackets = 1;
	exp_stats_ifin.ifi_opackets = 1;
	exp_stats_ifin.ifi_idropped = 0;

	my_ipol.proto = IPPROTO_UDP;
	my_ipol.s_prefix = NETWORK_REMOTE;
	my_ipol.d_prefix = NETWORK_EAST;

	my_opol.proto = IPPROTO_UDP;
	my_opol.s_prefix = NETWORK_EAST;
	my_opol.d_prefix = NETWORK_REMOTE;

	test_plaintext_packet_matching_input_policy(vrfid,
						    "dp1T1", "dp2T2",
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    &my_ipol, &my_opol,
						    CLIENT_REMOTE,
						    PORT_EAST,
						    0,
						    DP_TEST_FWD_DROPPED);

	/*
	 * UDP port 500 (IKE) is a special case as we must not drop
	 * these terminating packets.
	 */
	exp_stats_ifin.ifi_idropped = 0;
	exp_stats_ifin.ifi_opackets = 0;
	test_plaintext_packet_matching_input_policy(vrfid,
						    "dp1T1", "dp2T2",
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    &my_ipol, &my_opol,
						    CLIENT_REMOTE,
						    PORT_EAST,
						    500,
						    DP_TEST_FWD_LOCAL);
}

static void rx_plaintext_local_pkt_notmatch_inpolicy(vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};

	struct dp_test_crypto_policy my_ipol = input_policy;
	struct dp_test_crypto_policy my_opol = output_policy;

	exp_stats_ifin.ifi_ipackets = 1;

	/* Any proto but ICMP to ensure we don't match policy */
	my_ipol.proto = IPPROTO_TCP;
	my_ipol.s_prefix = NETWORK_REMOTE;
	my_ipol.d_prefix = NETWORK_WEST;

	my_opol.proto = IPPROTO_TCP;
	my_opol.s_prefix = NETWORK_WEST;
	my_opol.d_prefix = NETWORK_REMOTE;

	test_plaintext_packet_matching_input_policy(vrfid,
						    "dp2T2", "dp1T1",
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    &my_ipol, &my_opol,
						    CLIENT_REMOTE,
						    PORT_WEST,
						    0,
						    DP_TEST_FWD_LOCAL);
}

static void
test_plaintext_packet_matching_input_policy6(vrfid_t vrfid,
					     const char *ifout,
					     const char *ifin,
					     struct if_data *exp_stats_ifout,
					     struct if_data *exp_stats_ifin,
					     struct dp_test_crypto_policy *ipol,
					     struct dp_test_crypto_policy *opol,
					     const char *saddr,
					     const char *daddr,
					     uint16_t udp_port,
					     int exp_status)
{
	struct if_data start_stats_ifout, start_stats_ifin;
	struct if_data stats_ifout, stats_ifin;
	struct dp_test_expected *exp;
	struct rte_mbuf *pkt;
	int dis, del, inp;
	int dis2, del2, inp2;
	int    len = 512;

	s2s_common_setup6(vrfid, CRYPTO_CIPHER_AES_CBC,
			  CRYPTO_AUTH_HMAC_SHA1,
			  ipol, opol,
			  XFRM_MODE_TUNNEL, VFP_FALSE);

	pkt = dp_test_create_udp_ipv6_pak(saddr, daddr, udp_port, udp_port,
					  1, &len);
	dp_test_assert_internal(pkt != NULL);
	(void)dp_test_pktmbuf_eth_init(pkt,
				       dp_test_intf_name2mac_str(ifin),
				       NULL, RTE_ETHER_TYPE_IPV6);

	/*
	 * The packet may be dropped because if it is received in
	 * plain text but matches an input policy, indicating that
	 * it should have been encrypted.
	 */
	if (exp_status != DP_TEST_FWD_DROPPED) {
		exp = dp_test_exp_create(pkt);
		dp_test_exp_set_oif_name(exp, ifout);
		dp_test_exp_set_fwd_status(exp, exp_status);
	} else {
		exp = generate_exp_unreachable6(pkt, len, PORT_EAST6, saddr,
					       ifin, PEER_MAC_ADDR);
	}

	dp_test_intf_initial_stats_for_if(ifout, &start_stats_ifout);
	dp_test_intf_initial_stats_for_if(ifin, &start_stats_ifin);
	dis = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INNOROUTES);
	del = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INDELIVERS);
	inp = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INPKTS);

	dp_test_pak_receive(pkt, ifin, exp);

	dp_test_crypto_check_sad_packets(vrfid, 0, 0);

	dp_test_intf_delta_stats_for_if(ifout, &start_stats_ifout,
					&stats_ifout);
	dp_test_intf_delta_stats_for_if(ifin, &start_stats_ifin,
					&stats_ifin);
	dp_test_validate_if_stats(&stats_ifout, exp_stats_ifout);
	dp_test_validate_if_stats(&stats_ifin, exp_stats_ifin);
	dis2 = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INNOROUTES);
	del2 = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INDELIVERS);
	inp2 = dp_test_get_vrf_stat(vrfid, AF_INET6, IPSTATS_MIB_INPKTS);
	dp_test_verify_vrf_stats(inp, inp2, dis, dis2, del, del2, exp_status);

	s2s_common_teardown6(vrfid, ipol, opol, VFP_FALSE);
}

static void drop_plaintext_packet_matching_input_policy6_main(vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};

	exp_stats_ifin.ifi_ipackets = 1;
	exp_stats_ifin.ifi_opackets = 1;

	test_plaintext_packet_matching_input_policy6(vrfid,
						     "dp1T1", "dp2T2",
						     &exp_stats_ifout,
						     &exp_stats_ifin,
						     NULL, NULL,
						     CLIENT_REMOTE6,
						     CLIENT_LOCAL6,
						     0,
						     DP_TEST_FWD_DROPPED);
}

static void drop_plaintext_local_pkt_match_inpolicy6(vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};

	struct dp_test_crypto_policy my_ipol = input_policy6;
	struct dp_test_crypto_policy my_opol = output_policy6;

	exp_stats_ifin.ifi_ipackets = 1;
	exp_stats_ifin.ifi_opackets = 1;
	exp_stats_ifin.ifi_idropped = 0;

	my_ipol.proto = IPPROTO_UDP;
	my_ipol.s_prefix = NETWORK_REMOTE6;
	my_ipol.d_prefix = NETWORK_EAST6;

	my_opol.proto = IPPROTO_UDP;
	my_opol.s_prefix = NETWORK_EAST6;
	my_opol.d_prefix = NETWORK_REMOTE6;

	test_plaintext_packet_matching_input_policy6(vrfid,
						     "dp1T1", "dp2T2",
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    &my_ipol, &my_opol,
						    CLIENT_REMOTE6,
						    PORT_EAST6,
						    0,
						    DP_TEST_FWD_DROPPED);

	/*
	 * UDP port 500 (IKE) is a special case as we must not drop
	 * these terminating packets.
	 */
	exp_stats_ifin.ifi_opackets = 0;
	exp_stats_ifin.ifi_idropped = 0;
	test_plaintext_packet_matching_input_policy6(vrfid,
						    "dp1T1", "dp2T2",
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    &my_ipol, &my_opol,
						    CLIENT_REMOTE6,
						    PORT_EAST6,
						    500,
						    DP_TEST_FWD_LOCAL);
}

static void rx_plaintext_local_pkt_notmatch_inpolicy6(vrfid_t vrfid)
{
	struct if_data exp_stats_ifout = {0}, exp_stats_ifin = {0};

	struct dp_test_crypto_policy my_ipol = input_policy6;
	struct dp_test_crypto_policy my_opol = output_policy6;

	exp_stats_ifin.ifi_ipackets = 1;

	/* Any proto but ICMPV6 to ensure we don't match policy */
	my_ipol.proto = IPPROTO_TCP;
	my_ipol.s_prefix = NETWORK_REMOTE6;
	my_ipol.d_prefix = NETWORK_WEST6;

	my_opol.proto = IPPROTO_TCP;
	my_opol.s_prefix = NETWORK_WEST6;
	my_opol.d_prefix = NETWORK_REMOTE6;

	test_plaintext_packet_matching_input_policy6(vrfid,
						     "dp2T2", "dp1T1",
						    &exp_stats_ifout,
						    &exp_stats_ifin,
						    &my_ipol, &my_opol,
						    CLIENT_REMOTE6,
						    PORT_WEST6,
						    0,
						    DP_TEST_FWD_LOCAL);
}

DP_DECL_TEST_SUITE(site_to_site_suite);

DP_DECL_TEST_CASE(site_to_site_suite, encryption, NULL, NULL);

/*
 * can we encrypt a packet?
 *
 */
/*
 * TEST: null_encrypt_transport
 *
 * "encrypt" a packet using null encryption and null authentication
 * in transport mode.
 */
DP_START_TEST_FULL_RUN(encryption, null_encrypt_transport)
{
	null_encrypt_transport_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt_transport_vrf)
{
	null_encrypt_transport_main(TEST_VRF);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt_aesgcm)
{
	encrypt_aesgcm_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt_aesgcm_vrf)
{
	encrypt_aesgcm_main(TEST_VRF);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt)
{
	encrypt_main(VRF_DEFAULT_ID, VRF_XFRM_IN_ORDER);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt_vrf)
{
	encrypt_main(TEST_VRF, VRF_XFRM_IN_ORDER);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt_vrf_out_of_order)
{
	encrypt_main(TEST_VRF, VRF_XFRM_OUT_OF_ORDER);
}  DP_END_TEST;

DP_START_TEST(encryption, encrypt6)
{
	encrypt6_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, encrypt6_vrf)
{
	encrypt6_main(TEST_VRF);
}  DP_END_TEST;

/* test that an SA with an unrecognised algorithm will block traffic */
DP_START_TEST_FULL_RUN(encryption, bad_hash_algorithm)
{
	bad_hash_algorithm_main(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, bad_hash_algorithm_vrf)
{
	bad_hash_algorithm_main(TEST_VRF);
} DP_END_TEST;

/* test that an SA with an unrecognised algorithm will block traffic */
DP_START_TEST_FULL_RUN(encryption, bad_hash_algorithm6)
{
	bad_hash_algorithm6_main(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, bad_hash_algorithm6_vrf)
{
	bad_hash_algorithm6_main(TEST_VRF);
} DP_END_TEST;

/*
 * TEST: null_encrypt
 *
 * "encrypt" a packet using null encryption and null authentication.
 */
DP_START_TEST_FULL_RUN(encryption, null_encrypt)
{
	null_encrypt_main(VRF_DEFAULT_ID, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt_vfp)
{
	null_encrypt_main(VRF_DEFAULT_ID, VFP_TRUE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt_vrf)
{
	null_encrypt_main(TEST_VRF, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6_transport)
{
	null_encrypt6_transport_main(VRF_DEFAULT_ID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6_transport_vrf)
{
	null_encrypt6_transport_main(TEST_VRF);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6)
{
	null_encrypt6_main(VRF_DEFAULT_ID, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6_vfp)
{
	null_encrypt6_main(VRF_DEFAULT_ID, VFP_TRUE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption, null_encrypt6_vrf)
{
	null_encrypt6_main(TEST_VRF, VFP_FALSE);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, s2s_toobig6, NULL, NULL);

DP_START_TEST_FULL_RUN(s2s_toobig6, s2s_toobig6)
{
	s2s_toobig6_main(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(s2s_toobig6, s2s_toobig6_vrf)
{
	s2s_toobig6_main(TEST_VRF);
} DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, decryption, NULL, NULL);

DP_START_TEST_FULL_RUN(decryption, decrypt_null)
{
	null_decrypt_main(VRF_DEFAULT_ID, INNER_VALID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, decrypt_null_invalid)
{
	null_decrypt_main(VRF_DEFAULT_ID, INNER_INVALID);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, decryption_local, NULL, NULL);

DP_START_TEST_FULL_RUN(decryption_local, decrypt_null_local)
{
	null_decrypt_main(VRF_DEFAULT_ID, INNER_LOCAL);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, decrypt_null_vrf)
{
	null_decrypt_main(TEST_VRF, INNER_VALID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, decrypt_null6)
{
	null_decrypt_main6(VRF_DEFAULT_ID, INNER_VALID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, decrypt_null_invalid6)
{
	null_decrypt_main6(VRF_DEFAULT_ID, INNER_INVALID);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption_local, decrypt_null_local6)
{
	null_decrypt_main6(VRF_DEFAULT_ID, INNER_LOCAL);
}  DP_END_TEST;

/*
 * if a packet matches an input policy, then it must be ESP. If it is
 * plaintext, then it might be a spoof and must be dropped with
 * prejudice.
 */
DP_START_TEST_FULL_RUN(decryption, drop_plaintext_packet_matching_input_policy)
{
	drop_plaintext_packet_matching_input_policy_main(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, drop_plaintext_local_pkt_match_inpolicy)
{
	drop_plaintext_local_pkt_match_inpolicy(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, rx_plaintext_local_pkt_notmatch_inpolicy)
{
	rx_plaintext_local_pkt_notmatch_inpolicy(VRF_DEFAULT_ID);
} DP_END_TEST;

/*
 * This test no longer works with overlay vrf support with the underlay in
 * default becasuer the following happens.
 * Packet arrives unencrypted, but the dest address (10.10.1.1) is in the
 * TEST_VRF, not the default, so the route lookup does not find it. There is
 * no route, so an icmp is sent.
 *
 * I don't see a good way to detect that the packet should have been encrypted
 * as we would have to check all policies that have the transport in this vrf.
 * At the moment the check is once we have decided it is local, but we can not
 * even use that as the trigger. So, lets leave this test out.
 */
DP_START_TEST_DONT_RUN(decryption,
		       drop_plaintext_packet_matching_input_policy_vrf)
{
	drop_plaintext_packet_matching_input_policy_main(TEST_VRF);
} DP_END_TEST;

/*
 * This test no longer works with overlay vrf support with the underlay in
 * default becasuer the following happens.
 * Packet arrives unencrypted, but the dest address (10.10.1.1) is in the
 * TEST_VRF, not the default, so the route lookup does not find it. There is
 * no route, so an icmp is sent.
 *
 * I don't see a good way to detect that the packet should have been encrypted
 * as we would have to check all policies that have the transport in this vrf.
 * At the moment the check is once we have decided it is local, but we can not
 * even use that as the trigger. So, lets leave this test out.
 */
DP_START_TEST_DONT_RUN(decryption,
		       drop_plaintext_local_pkt_match_inpolicy_vrf)
{
	drop_plaintext_local_pkt_match_inpolicy(TEST_VRF);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, rx_plaintext_local_pkt_notmatch_inpolicy_vrf)
{
	rx_plaintext_local_pkt_notmatch_inpolicy(TEST_VRF);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, drop_plaintext_packet_matching_input_policy6)
{
	drop_plaintext_packet_matching_input_policy6_main(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, drop_plaintext_local_pkt_match_inpolicy6)
{
	drop_plaintext_local_pkt_match_inpolicy6(VRF_DEFAULT_ID);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption, rx_plaintext_local_pkt_notmatch_inpolicy6)
{
	rx_plaintext_local_pkt_notmatch_inpolicy6(VRF_DEFAULT_ID);
} DP_END_TEST;

/*
 * This test no longer works with overlay vrf support with the underlay in
 * default becasuer the following happens.
 * Packet arrives unencrypted, but the dest address  is in the
 * TEST_VRF, not the default, so the route lookup does not find it. There is
 * no route, so an icmp is sent.
 *
 * I don't see a good way to detect that the packet should have been encrypted
 * as we would have to check all policies that have the transport in this vrf.
 * At the moment the check is once we have decided it is local, but we can not
 * even use that as the trigger. So, lets leave this test out.
 */
DP_START_TEST_DONT_RUN(decryption,
		       drop_plaintext_packet_matching_input_policy6_vrf)
{
	drop_plaintext_packet_matching_input_policy6_main(TEST_VRF);
} DP_END_TEST;

/*
 * This test no longer works with overlay vrf support with the underlay in
 * default becasuer the following happens.
 * Packet arrives unencrypted, but the dest address is in the
 * TEST_VRF, not the default, so the route lookup does not find it. There is
 * no route, so an icmp is sent.
 *
 * I don't see a good way to detect that the packet should have been encrypted
 * as we would have to check all policies that have the transport in this vrf.
 * At the moment the check is once we have decided it is local, but we can not
 * even use that as the trigger. So, lets leave this test out.
 */
DP_START_TEST_DONT_RUN(decryption,
		       drop_plaintext_local_pkt_match_inpolicy6_vrf)
{
	drop_plaintext_local_pkt_match_inpolicy6(TEST_VRF);
} DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption,
		       rx_plaintext_local_pkt_notmatch_inpolicy6_vrf)
{
	rx_plaintext_local_pkt_notmatch_inpolicy6(TEST_VRF);
} DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, encryption46, NULL, NULL);

DP_START_TEST_FULL_RUN(encryption46, encrypt46_tunnel)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v4_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 0, exp_tos = 0;

	memcpy(expected_payload, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));
	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	setup_sas(&input_sa6, &output_sa6, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL, CLIENT_REMOTE,
				       PORT_EAST6, PEER6, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	teardown_sas(&input_sa6, &output_sa6);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;


DP_START_TEST_FULL_RUN(encryption46, encrypt46_ecn_ect)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v4_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 1, exp_tos = 1;

	memcpy(expected_payload, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));
	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	setup_sas(&input_sa6, &output_sa6, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL, CLIENT_REMOTE,
				       PORT_EAST6, PEER6, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	teardown_sas(&input_sa6, &output_sa6);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption46, encrypt46_ecn_ce)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v4_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 3, exp_tos = 2;

	memcpy(expected_payload, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));
	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	setup_sas(&input_sa6, &output_sa6, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL, CLIENT_REMOTE,
				       PORT_EAST6, PEER6, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	teardown_sas(&input_sa6, &output_sa6);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption46, encrypt46_no_ecn)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v4_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 7, exp_tos = 4;

	memcpy(expected_payload, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));
	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	input_sa6.flags = XFRM_STATE_NOECN;
	output_sa6.flags = XFRM_STATE_NOECN;
	setup_sas(&input_sa6, &output_sa6, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);
	input_sa6.flags = 0;
	output_sa6.flags = 0;

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL, CLIENT_REMOTE,
				       PORT_EAST6, PEER6, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	teardown_sas(&input_sa6, &output_sa6);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

/* ecn3 is modified to ecn2, and dscp 1 is dropped */
DP_START_TEST_FULL_RUN(encryption46, encrypt46_no_dscp)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v4_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 7, exp_tos = 2;

	memcpy(expected_payload, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));
	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	input_sa6.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	output_sa6.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	setup_sas(&input_sa6, &output_sa6, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);
	input_sa6.extra_flags = 0;
	output_sa6.extra_flags = 0;

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL, CLIENT_REMOTE,
				       PORT_EAST6, PEER6, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	teardown_sas(&input_sa6, &output_sa6);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption46, encrypt46_no_dscp_no_ecn)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v4_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 7, exp_tos = 0;

	memcpy(expected_payload, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));
	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	input_sa6.flags = XFRM_STATE_NOECN;
	output_sa6.flags = XFRM_STATE_NOECN;
	input_sa6.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	output_sa6.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	setup_sas(&input_sa6, &output_sa6, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);
	input_sa6.flags = 0;
	output_sa6.flags = 0;
	input_sa6.extra_flags = 0;
	output_sa6.extra_flags = 0;

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL, CLIENT_REMOTE,
				       PORT_EAST6, PEER6, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	teardown_sas(&input_sa6, &output_sa6);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption46, encrypt46_tunnel_test_vrf)
{
	vrfid_t vrfid = TEST_VRF;
	char expected_payload[sizeof(payload_v4_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	/* Propagate dscp*/
	uint8_t in_tos = 4, exp_tos = 4;

	memcpy(expected_payload, payload_v4_icmp_null_enc,
	       sizeof(payload_v4_icmp_null_enc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	setup_sas(&input_sa6, &output_sa6, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL, CLIENT_REMOTE,
				       PORT_EAST6, PEER6, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	teardown_sas(&input_sa6, &output_sa6);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, encryption64, NULL, NULL);

DP_START_TEST_FULL_RUN(encryption64, encrypt64)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v6_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 0, exp_tos = 0;

	memcpy(expected_payload, payload_v6_icmp_null_enc,
	       sizeof(payload_v6_icmp_null_enc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy64, &output_policy64, vrfid);
	setup_sas(&input_sa, &output_sa, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL6, CLIENT_REMOTE6,
				       PORT_EAST, PEER, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	teardown_sas(&input_sa, &output_sa);
	teardown_policies(&input_policy64, &output_policy64);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_ecn_ect)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v6_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 1, exp_tos = 1;

	memcpy(expected_payload, payload_v6_icmp_null_enc,
	       sizeof(payload_v6_icmp_null_enc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy64, &output_policy64, vrfid);
	setup_sas(&input_sa, &output_sa, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL6, CLIENT_REMOTE6,
				       PORT_EAST, PEER, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	teardown_sas(&input_sa, &output_sa);
	teardown_policies(&input_policy64, &output_policy64);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_ecn_ce)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v6_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 3, exp_tos = 2;

	memcpy(expected_payload, payload_v6_icmp_null_enc,
	       sizeof(payload_v6_icmp_null_enc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy64, &output_policy64, vrfid);
	setup_sas(&input_sa, &output_sa, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL6, CLIENT_REMOTE6,
				       PORT_EAST, PEER, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	teardown_sas(&input_sa, &output_sa);
	teardown_policies(&input_policy64, &output_policy64);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_no_ecn)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v6_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 7, exp_tos = 4;

	memcpy(expected_payload, payload_v6_icmp_null_enc,
	       sizeof(payload_v6_icmp_null_enc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy64, &output_policy64, vrfid);
	input_sa.flags = XFRM_STATE_NOECN;
	output_sa.flags = XFRM_STATE_NOECN;
	setup_sas(&input_sa, &output_sa, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);
	input_sa.flags = 0;
	output_sa.flags = 0;
	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL6, CLIENT_REMOTE6,
				       PORT_EAST, PEER, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	teardown_sas(&input_sa, &output_sa);
	teardown_policies(&input_policy64, &output_policy64);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

/* ecn3 is modified to ecn2, and dscp 1 is dropped */
DP_START_TEST_FULL_RUN(encryption64, encrypt64_no_dscp)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v6_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 7, exp_tos = 2;

	memcpy(expected_payload, payload_v6_icmp_null_enc,
	       sizeof(payload_v6_icmp_null_enc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy64, &output_policy64, vrfid);
	input_sa.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	output_sa.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	setup_sas(&input_sa, &output_sa, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);
	input_sa.extra_flags = 0;
	output_sa.extra_flags = 0;
	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL6, CLIENT_REMOTE6,
				       PORT_EAST, PEER, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	teardown_sas(&input_sa, &output_sa);
	teardown_policies(&input_policy64, &output_policy64);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_no_dscp_no_ecn)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char expected_payload[sizeof(payload_v6_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	uint8_t in_tos = 7, exp_tos = 0;

	memcpy(expected_payload, payload_v6_icmp_null_enc,
	       sizeof(payload_v6_icmp_null_enc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy64, &output_policy64, vrfid);
	input_sa.flags = XFRM_STATE_NOECN;
	output_sa.flags = XFRM_STATE_NOECN;
	input_sa.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	output_sa.extra_flags = XFRM_SA_XFLAG_DONT_ENCAP_DSCP;
	setup_sas(&input_sa, &output_sa, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);
	input_sa.flags = 0;
	output_sa.flags = 0;
	input_sa.extra_flags = 0;
	output_sa.extra_flags = 0;
	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL6, CLIENT_REMOTE6,
				       PORT_EAST, PEER, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	teardown_sas(&input_sa, &output_sa);
	teardown_policies(&input_policy64, &output_policy64);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(encryption64, encrypt64_test_vrf)
{
	vrfid_t vrfid = TEST_VRF;
	char expected_payload[sizeof(payload_v6_icmp_null_enc)];
	struct dp_test_expected *exp;
	struct rte_mbuf *ping_pkt;
	/* Propagate dscp */
	uint8_t in_tos = 4, exp_tos = 4;

	memcpy(expected_payload, payload_v6_icmp_null_enc,
	       sizeof(payload_v6_icmp_null_enc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy64, &output_policy64, vrfid);
	setup_sas(&input_sa, &output_sa, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_encrypt(&ping_pkt, &exp, "dp1T1", "dp2T2",
				       CLIENT_LOCAL6, CLIENT_REMOTE6,
				       PORT_EAST, PEER, expected_payload,
				       sizeof(expected_payload),
				       VRF_DEFAULT_ID, in_tos, exp_tos);

	/* transmit the ping and await the result */
	dp_test_pak_receive(ping_pkt, "dp1T1", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	teardown_sas(&input_sa, &output_sa);
	teardown_policies(&input_policy64, &output_policy64);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, decryption64, NULL, NULL);

DP_START_TEST_FULL_RUN(decryption64, decrypt64_tunnel)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char transmit_payload[sizeof(payload_v4_icmp_null_enc_rem_to_loc)];
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;

	memcpy(transmit_payload, payload_v4_icmp_null_enc_rem_to_loc,
	       sizeof(payload_v4_icmp_null_enc_rem_to_loc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy64, &output_policy64, vrfid);
	setup_sas(&input_sa6, &output_sa6, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_decrypt(&encrypted_pkt, &exp, "dp2T2", "dp1T1",
				       CLIENT_REMOTE, CLIENT_LOCAL,
				       PEER6, PORT_EAST6, transmit_payload,
				       sizeof(transmit_payload),
				       VRF_DEFAULT_ID);

	/* transmit the ping and await the result */
	dp_test_pak_receive(encrypted_pkt, "dp2T2", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	teardown_sas(&input_sa6, &output_sa6);
	teardown_policies(&input_policy64, &output_policy64);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption64, decrypt64_tunnel_test_vrf)
{
	vrfid_t vrfid = TEST_VRF;
	char transmit_payload[sizeof(payload_v4_icmp_null_enc_rem_to_loc)];
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;

	memcpy(transmit_payload, payload_v4_icmp_null_enc_rem_to_loc,
	       sizeof(payload_v4_icmp_null_enc_rem_to_loc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	setup_sas(&input_sa6, &output_sa6, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_decrypt(&encrypted_pkt, &exp, "dp2T2", "dp1T1",
				       CLIENT_REMOTE, CLIENT_LOCAL,
				       PEER6, PORT_EAST6, transmit_payload,
				       sizeof(transmit_payload),
				       VRF_DEFAULT_ID);

	/* transmit the ping and await the result */
	dp_test_pak_receive(encrypted_pkt, "dp2T2", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 84);

	teardown_sas(&input_sa6, &output_sa6);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_DECL_TEST_CASE(site_to_site_suite, decryption46, NULL, NULL);

DP_START_TEST_FULL_RUN(decryption46, decrypt46_tunnel)
{
	vrfid_t vrfid = VRF_DEFAULT_ID;
	char transmit_payload[sizeof(payload_v6_icmp_null_enc_rem_to_loc)];
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;

	memcpy(transmit_payload, payload_v6_icmp_null_enc_rem_to_loc,
	       sizeof(payload_v6_icmp_null_enc_rem_to_loc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	setup_sas(&input_sa, &output_sa, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_decrypt(&encrypted_pkt, &exp, "dp2T2", "dp1T1",
				       CLIENT_REMOTE6, CLIENT_LOCAL6,
				       PEER, PORT_EAST, transmit_payload,
				       sizeof(transmit_payload),
				       VRF_DEFAULT_ID);

	/* transmit the ping and await the result */
	dp_test_pak_receive(encrypted_pkt, "dp2T2", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	teardown_sas(&input_sa, &output_sa);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;

DP_START_TEST_FULL_RUN(decryption46, decrypt46_tunnel_test_vrf)
{
	vrfid_t vrfid = TEST_VRF;
	char transmit_payload[sizeof(payload_v6_icmp_null_enc_rem_to_loc)];
	struct rte_mbuf *encrypted_pkt;
	struct dp_test_expected *exp;

	memcpy(transmit_payload, payload_v6_icmp_null_enc_rem_to_loc,
	       sizeof(payload_v6_icmp_null_enc_rem_to_loc));

	s2s_setup_interfaces_v4_v6(vrfid, VFP_FALSE, VRF_XFRM_IN_ORDER);
	setup_policies(&input_policy46, &output_policy46, vrfid);
	setup_sas(&input_sa, &output_sa, vrfid, CRYPTO_CIPHER_NULL,
		  CRYPTO_AUTH_NULL, XFRM_MODE_TUNNEL);

	build_pak_and_expected_decrypt(&encrypted_pkt, &exp, "dp2T2", "dp1T1",
				       CLIENT_REMOTE6, CLIENT_LOCAL6,
				       PEER, PORT_EAST, transmit_payload,
				       sizeof(transmit_payload),
				       VRF_DEFAULT_ID);

	/* transmit the ping and await the result */
	dp_test_pak_receive(encrypted_pkt, "dp2T2", exp);
	dp_test_crypto_check_sad_packets(vrfid, 1, 104);

	teardown_sas(&input_sa, &output_sa);
	teardown_policies(&input_policy46, &output_policy46);
	s2s_teardown_interfaces_v4_v6(vrfid, VFP_FALSE);
}  DP_END_TEST;
