/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <errno.h>
#include <time.h>
#include <values.h>
#include <string.h>

#include <linux/if_ether.h>
#include <netinet/ip_icmp.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>
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
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_npf_lib.h"
#include "dp_test_npf_nat_lib.h"
#include "dp_test_npf_sess_lib.h"

#include "npf/nat/nat_pool_public.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_sess_state.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_time.h"
#include "npf/cgnat/cgn_test.h"

DP_DECL_TEST_SUITE(npf_cgnat);

/*
 * cgnat_pre - Checks session structure size
 * cgnat1  - UDP  1 fwd pkt
 * cgnat2  - TCP  1 fwd pkt
 * cgnat3  - ICMP 1 fwd pkt
 *
 * cgnat4  - UDP  1 fwd pkt, 1 back pkt
 * cgnat5  - TCP  1 fwd pkt, 1 back pkt, 5-tuple session
 * cgnat6  - ICMP 1 fwd pkt, 1 back pkt
 *
 * cgnat7  - UDP  1 fwd pkt, 1 back pkt, 1 fwd pkt
 * cgnat8  - TCP  1 fwd pkt, 1 back pkt, 1 fwd pkt
 * cgnat9  - ICMP 1 fwd pkt, 1 back pkt, 1 fwd pkt
 *
 * cgnat10  - UDP, TCP, and ICMP  1 fwd pkt
 * cgnat11  - UDP, TCP, and ICMP  1 fwd pkt, 1 back pkt
 * cgnat12  - Hairpinning.
 * cgnat13  - CGNAT over VRF interface.
 * cgnat15  - VRF interface deleted while CGNAT policy and sessions present
 * cgnat16  - Tests random port allocation within port block.
 * cgnat17  - Exercises op-mode show commands
 * cgnat18  - Tests public address blocklist
 *
 * cgnat20  - UDP  129 pkts with different src addrs
 *
 * cgnat21  - Tests max-blocks-per-subscriber limit.
 *            UDP  'n' pkts with same src addr, diff src ports.  Cfg is
 *            block size 128 and 2 blocks-per-user. Sends 257 pkts.
 *            256 ok, 1 fail.
 *
 * cgnat22  - Tests address-pool paired limit.
 *            TCP  'n' pkts with same src addr, diff src ports.
 *            Port range is limited to 256 ports.  Block size is 128 and
 *            max-blocks-per-user is 4, so APP is the limiting factor.
 *            The public address we are paired with runs out of ports
 *            before the max-blocks-per-subscriber limit is reached.
 *            Sends 257 pkts.  256 ok, 1 fail.
 *
 * cgnat23  - Tests address-pool arbitrary.
 *            TCP  'n' pkts with same src addr, diff src ports.
 *            Tests address-pool arbitrary.  Port range is limited to
 *            256 ports.  Sends 257 pkts.  256 use one address, 1 uses
 *            a different public address.
 *
 * cgnat24  - Tests EIF.
 *            UDP.  1 fwd pkt, 1 back pkt to setup session.
 *            Send 2 ext-to-int pkts, 1 with different src addr and 1 with
 *            different src port.  Dest matches 3-tuple session, so both
 *            are forwarded.
 *            Send 1 pkt  ext-to-int with dest IP matching subscriber IP,
 *            but diff port.  Pkt is dropped.
 *
 * cgnat25  - Tests nested 2-tuple sessions.'n' UDP forwards pkts, same src
 *            addr, diff src ports.
 *
 * cgnat26  - Tests max-blocks-per-subscriber limit, with random port-allocn.
 *
 * cgnat27  - Tests destructive change to a nat pool
 *
 * cgnat30  - CGNAT commands
 * cgnat31  - CGNAT commands
 *
 * cgnat32  - Tests CGNAT and SNAT on same interface
 *
 * cgnat32b - Tests CGNAT and Stateful Firewall on same interface
 *
 * cgnat32c - Tests inbound traffic whose dest is not in nat pool
 *
 * cgnat33  - Tests ICMP error messages with embedded UDP packets
 *            (incl cksum 0)
 *
 * cgnat34  - Tests ICMP error messages with embedded TCP packets (including
 *            truncated)
 *
 * cgnat35 - Tests generation of an ICMP error message *after* CGNAT
 *           translation of an outbound packet but before transmission.  We
 *           undo the *source* CGNAT translation, and send an
 *           ICMP_DEST_UNREACH/FRAG_NEEDED message back to the sender.
 *
 * cgnat36 - As cgnat35, but for an inbound packet.
 *
 * cgnat37 - Test that inbound traffic that matches an snat session but
 *           not a cgnat session is *not* filtered by CGNAT.
 *
 * cgnat38 - 20 UDP forwards pkts, different source addrs and ports
 *
 * cgnat39  - Packet reassembly before translation.
 * cgnat40  - Split TCP header over two chained mbufs
 *
 * cgnat41  - Create multiple sessions and test show command
 *
 * cgnat42  - cgnat scale test (remove '_DONT_RUN' to run it)
 *
 * cgnat43  - cgnat scale test (remove '_DONT_RUN' to run it)
 *
 * cgnat44  - Tests cgnat exclude address group
 *
 * cgnat45  - Tests PCP/unit-test 'map' command
 *
 * cgnat46 - Verify CGNAT responds to echo request sent to CGNAT pool address
 *           on the outside interface.
 *
 * cgnat47 - Excercises threshold add/del code paths, and apm pb full code
 *           path.
 *
 * cgnat48 - Tests a policy being uncfgd and re-cfgd while a subscriber
 *           structure exists
 *
 * cgnat49 - Tests that two different subscribers may be allocated port
 *           blocks from the same public address.
 *
 * cgnat52 - Test NAT pool lookup using the hidden NAT pool address-group.
 *
 * cgnat53 - Test timeout value for TCP 5-tuple session in different states
 *
 * cgnat54 - Tests interface failover
 *
 * make -j4 dataplane_test_run CK_RUN_SUITE=dp_test_npf_cgnat.c
 * make -j4 dataplane_test_run CK_RUN_CASE=cgnat1
 */

static void
_dpt_cgn_cmd_fmt(bool print, bool exp,
		 const char *file, int line, const char *fmt_str, ...)
	__attribute__((__format__(printf, 5, 6)));

#define dpt_cgn_cmd_fmt(print, exp, fmt_str, ...)	 \
	_dpt_cgn_cmd_fmt(print, exp, __FILE__, __LINE__, \
			 fmt_str, ##__VA_ARGS__)


struct cgn_ctx {
	bool		do_check;
	uint16_t	port;
	validate_cb	saved_cb;
};

static struct cgn_ctx cgn_ctx = {
	.do_check = true,
	.saved_cb = dp_test_pak_verify,
};


static void cgn_validate_cb(struct rte_mbuf *mbuf, struct ifnet *ifp,
			    struct dp_test_expected *expected,
			    enum dp_test_fwd_result_e fwd_result);

static void cgnat_setup(void);
static void cgnat_teardown(void);
static int dpt_cgn_show_session(const char *fltr, uint count, bool per_subs,
				bool print, bool debug);

static void
_cgnat_udp(const char *rx_intf, const char *pre_smac, int pre_vlan,
	   const char *pre_saddr, uint16_t pre_sport,
	   const char *pre_daddr, uint16_t pre_dport,
	   const char *post_saddr, uint16_t post_sport,
	   const char *post_daddr, uint16_t post_dport,
	   const char *post_dmac, int post_vlan, const char *tx_intf,
	   int status, bool icmp_err,
	   const char *file, const char *func, int line);

#define cgnat_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		  _i, _j, _k, _l, _m, _n, _o)				\
	_cgnat_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		   _i, _j, _k, _l, _m, _n, _o, false,			\
		   __FILE__, __func__, __LINE__)

#define cgnat_udp_err(_a, _b, _c, _d, _e, _f, _g, _h,			\
		  _i, _j, _k, _l, _m, _n, _o)				\
	_cgnat_udp(_a, _b, _c, _d, _e, _f, _g, _h,			\
		   _i, _j, _k, _l, _m, _n, _o, true,			\
		   __FILE__, __func__, __LINE__)

static void
_cgnat_tcp(uint8_t flags, const char *rx_intf, const char *pre_smac,
	   const char *pre_saddr, uint16_t pre_sport,
	   const char *pre_daddr, uint16_t pre_dport,
	   const char *post_saddr, uint16_t post_sport,
	   const char *post_daddr, uint16_t post_dport,
	   const char *post_dmac, const char *tx_intf,
	   int status,
	   const char *file, const char *func, int line);
#define cgnat_tcp(_a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m, _n) \
	_cgnat_tcp(_a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k, _l, _m, _n, \
		   __FILE__, __func__, __LINE__)

static void
_cgnat_icmp(uint8_t icmp_type, const char *rx_intf, const char *pre_smac,
	    const char *pre_saddr, uint16_t pre_icmp_id,
	    const char *pre_daddr,
	    const char *post_saddr, uint16_t post_icmp_id,
	    const char *post_daddr,
	    const char *post_dmac, const char *tx_intf,
	    const char *file, const char *func, int line);
#define cgnat_icmp(_a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k)	\
	_cgnat_icmp(_a, _b, _c, _d, _e, _f, _g, _h, _i, _j, _k,	\
		    __FILE__, __func__, __LINE__)

/*
 * Get time of day in millisecs
 */
static uint64_t time_ms(void)
{
	struct timeval tod;

	gettimeofday(&tod, NULL);
	return (tod.tv_sec * 1000) + (tod.tv_usec / 1000);
}

/*
 * Used to create a test address in binary and text format.  Return value is
 * in network byte order.
 */
static uint32_t dpt_init_ipaddr(char *str, const char *init_val)
{
	uint32_t addr;

	strcpy(str, init_val);
	inet_pton(AF_INET, init_val, &addr);
	return addr;
}

/*
 * Used to increment a test address in binary and text format. 'addr_n' and
 * return value are in network byte order
 */
static uint32_t dpt_incr_ipaddr(uint32_t addr_n, char *str, size_t str_sz)
{
	uint32_t addr_h = ntohl(addr_n);

	addr_h++;
	addr_n = htonl(addr_h);
	inet_ntop(AF_INET, &addr_n, str, str_sz);
	return addr_n;
}

/*
 * Create a random IP address for the bits covered by the mask param.
 *
 * e.g. dpt_random_ipaddr(0x02000000, 0x00ffffff, ...) will create
 * 2.x.x.x where 'x' is random.
 */
static uint32_t dpt_random_ipaddr(uint32_t addr, uint32_t mask,
				  char *str, size_t str_sz)
{
	uint a, b, c, d;

	a = (random() % 254) + 1;
	b = random() % 255;
	c = random() % 255;
	d = random() % 255;

	uint32_t addr_h = (d << 24) | (c << 16) | (b << 8) | a;
	uint32_t addr_n;

	addr_h = (addr_h & mask) | addr;

	addr_n = htonl(addr_h);
	inet_ntop(AF_INET, &addr_n, str, str_sz);
	return addr_n;
}

static void dpt_cgn_show_summary(bool print)
{
	json_object *jresp;
	char *response;
	bool err;

	response = dp_test_console_request_w_err(
			"cgn-op show summary", &err, false);
	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);

	json_object_put(jresp);
}


static void dpt_cgn_show_error(bool print)
{
	json_object *jresp;
	char *response;
	bool err;

	response = dp_test_console_request_w_err(
			"cgn-op show errors", &err, false);
	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);

	json_object_put(jresp);
}


void dpt_cgn_print_json(const char *cmd, bool print);
void dpt_cgn_print_json(const char *cmd, bool print)
{
	json_object *jobj;
	const char *str;
	char *response;
	bool err;

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err) {
		if (print)
			printf("  no response\n");
		return;
	}

	jobj = parse_json(response, parse_err_str, sizeof(parse_err_str));
	if (!jobj) {
		if (print) {
			printf("  failed to parse json\n");
			printf("%s\n", response);
		}
		free(response);
		return;
	}
	free(response);

	str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);
	json_object_put(jobj);
}


/*
 * Some simply checks before real testing
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat_pre, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat_pre, test)
{
	/* Ensure 2-tuple session fits in two cachelines */
	dp_test_fail_unless(cgn_sess2_size() <= 128,
			    "2-tuple session size %lu, expected <= 128",
			    cgn_sess2_size());

	/* Ensure 3-tuple session fits in four cachelines */
	dp_test_fail_unless(cgn_session_size() <= 256,
			    "3-tuple session size %lu, expected <= 256",
			    cgn_session_size());

} DP_END_TEST;


/*
 * npf_cgnat_1 - 1 UDP forwards pkt
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat1, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat1, test)
{
	/*
	 * pool add POOL1
	 *   address-range=RANGE1/1.1.1.11-1.1.1.20
	 *   prefix=RANGE2/1.1.1.192/26
	 *   port-range=4096-65535
	 *   port-alloc=sequential
	 *   block-size=512
	 *   max-blocks=8
	 *   add-pooling=paired
	 *   addr-alloc=round-robin
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"prefix=RANGE3/204.112.12.224/28 "
			"subnet=RANGE4/204.112.13.224/28 "
			"log-pba=yes "
			"");

	dpt_cgn_print_json("nat-op show pool", false);

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_2 - 1 TCP forwards pkt
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 *
 * Also tests changing a parameter in an existing nat pool
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat2, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat2, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"max-blocks=2 "
			"subnet=RANGE1/1.1.1.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/* Also tests changing a parameter nat pool */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"max-blocks=4 "
			"");

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.193", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_3 - 1 ICMP forwards pkt
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 *
 *
 * This also tests changing a policy to use a different nat pool
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat3, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat3, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL2 "
			"type=cgnat "
			"address-range=RANGE1/1.1.2.11-1.1.2.20 "
			"prefix=RANGE2/1.1.2.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.1.0/24", "POOL2", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	cgnat_policy_add("POLICY2", 10, "100.64.0.0/24", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/* Change nat pool for POLICY1 */
	cgnat_policy_change("POLICY1", 10, "100.64.1.0/24", "POOL1", "dp2T1",
			    CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_icmp(ICMP_ECHO, "dp1T0", "aa:bb:cc:dd:1:a1",
		   "100.64.0.1", 49152, "1.1.1.1",
		   "1.1.1.11", 1024, "1.1.1.1",
		   "aa:bb:cc:dd:2:b1", "dp2T1");

	cgnat_policy_del("POLICY2", 10, "dp2T1");
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL2");

} DP_END_TEST;


/*
 * npf_cgnat_4 - 1 UDP forwards pkt, 1 backwards pkt
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat4, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat4, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_5 - 1 TCP forwards pkt, 1 TCP backwards pkt
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat5, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat5, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.11 "
			"prefix=RANGE2/1.1.1.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_5TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_tcp(TH_SYN | TH_ACK, "dp2T1", "aa:bb:cc:dd:2:b1",
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_tcp(TH_ACK, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);


	dpt_cgn_show_session(NULL, 1, false, false, false);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_6 - 1 ICMP echo req forwards pkt, 1 ICMP echo reply backwards pkt
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat6, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat6, test)
{
	dpt_cgn_cmd_fmt(false, true, "nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE2/1.1.1.11/32");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_icmp(ICMP_ECHO, "dp1T0", "aa:bb:cc:dd:1:a1",
		   "100.64.0.1", 49152, "1.1.1.1",
		   "1.1.1.11", 1024, "1.1.1.1",
		   "aa:bb:cc:dd:2:b1", "dp2T1");

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_icmp(ICMP_ECHOREPLY, "dp2T1", "aa:bb:cc:dd:2:b1",
		   "1.1.1.1", 1024, "1.1.1.11",
		   "1.1.1.1", 49152, "100.64.0.1",
		   "aa:bb:cc:dd:1:a1", "dp1T0");

	/*
	 * Delete policy and pool
	 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	/*
	 * Re-add policy and pool
	 */
	dpt_cgn_cmd_fmt(false, true, "nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE2/1.1.1.11/32");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	cgnat_icmp(ICMP_ECHO, "dp1T0", "aa:bb:cc:dd:1:a1",
		   "100.64.0.1", 49152, "1.1.1.1",
		   "1.1.1.11", 1024, "1.1.1.1",
		   "aa:bb:cc:dd:2:b1", "dp2T1");

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_7 - 1 UDP forwards pkt, 1 backwards pkt
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat7, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat7, test)
{
	/*
	 * pool add POOL1
	 *   address-range=RANGE1/1.1.1.11-1.1.1.20
	 *   prefix=RANGE2/1.1.1.192/26
	 *   port-range=4096-65535
	 *   port-alloc=sequential
	 *   block-size=512
	 *   max-blocks=8
	 *   add-pooling=paired
	 *   addr-alloc=round-robin
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_8 - 1 TCP forwards pkt, 1 TCP backwards pkt
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat8, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat8, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_tcp(TH_SYN | TH_ACK, "dp2T1", "aa:bb:cc:dd:2:b1",
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_tcp(TH_ACK, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_9 - 1 ICMP echo req forwards pkt, 1 ICMP echo reply backwards pkt
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat9, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat9, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE2/1.1.1.192/31 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.192:1024 --> dst 1.1.1.1:80
	 */
	cgnat_icmp(ICMP_ECHO, "dp1T0", "aa:bb:cc:dd:1:a1",
		   "100.64.0.1", 49152, "1.1.1.1",
		   "1.1.1.192", 1024, "1.1.1.1",
		   "aa:bb:cc:dd:2:b1", "dp2T1");

	/*
	 * 1.1.1.1:80  -->  1.1.1.192:1024 / 100.64.0.1:49152
	 */
	cgnat_icmp(ICMP_ECHOREPLY, "dp2T1", "aa:bb:cc:dd:2:b1",
		   "1.1.1.1", 1024, "1.1.1.192",
		   "1.1.1.1", 49152, "100.64.0.1",
		   "aa:bb:cc:dd:1:a1", "dp1T0");

	/*
	 * 100.64.0.1:49152 / 1.1.1.192:1024 --> dst 1.1.1.1:80
	 */
	cgnat_icmp(ICMP_ECHO, "dp1T0", "aa:bb:cc:dd:1:a1",
		   "100.64.0.1", 49152, "1.1.1.1",
		   "1.1.1.192", 1024, "1.1.1.1",
		   "aa:bb:cc:dd:2:b1", "dp2T1");

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_10 - 1 each of UDP, TCP, and ICMP forwards pkts
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat10, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat10, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_icmp(ICMP_ECHO, "dp1T0", "aa:bb:cc:dd:1:a1",
		   "100.64.0.1", 49152, "1.1.1.1",
		   "1.1.1.11", 1024, "1.1.1.1",
		   "aa:bb:cc:dd:2:b1", "dp2T1");

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_11 - 1 each of UDP, TCP, and ICMP forwards and back pkts
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat11, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat11, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_tcp(TH_SYN | TH_ACK, "dp2T1", "aa:bb:cc:dd:2:b1",
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_icmp(ICMP_ECHO, "dp1T0", "aa:bb:cc:dd:1:a1",
		   "100.64.0.1", 49152, "1.1.1.1",
		   "1.1.1.11", 1024, "1.1.1.1",
		   "aa:bb:cc:dd:2:b1", "dp2T1");

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_icmp(ICMP_ECHOREPLY, "dp2T1", "aa:bb:cc:dd:2:b1",
		   "1.1.1.1", 1024, "1.1.1.11",
		   "1.1.1.1", 49152, "100.64.0.1",
		   "aa:bb:cc:dd:1:a1", "dp1T0");

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * cgnat12 - cgnat and hairpinning
 *
 *    Private                                       Public
 *              A --+
 *                  |    dp1T0 +---+ dp2T1
 *    100.64.0.0/24 +----------|   |--------------- 1.1.1.0/24
 *                  |          +---+
 *              B --+
 *
 *  On dp2T1 out we get packet A:inside to B:outside
 *
 *   1. translate source A:inside to A:outside (normal CGNAT)
 *   2. detect that destination addr is a CGNAT outside addr
 *   3. translate B:outside to B:inside
 *   4. Send packet out rx interface dp1T0
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat12, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat12, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.255.255.254 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/* Enable hairpinning */
	dp_test_npf_cmd_fmt(false, "cgn-ut hairpinning on");

	/*
	 * Host A 100.64.0.1 is mapped to 1.1.1.11:1024
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 3000, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Host B 100.64.0.2 is mapped to 1.1.1.12:1024
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a2", 0,
		  "100.64.0.2", 12443, "1.1.1.1", 80,
		  "1.1.1.12", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Send packet from host A internal to host B external addr.
	 *
	 * Src is mapped from 100.64.0.1:3000 to 1.1.1.11:1024
	 * Dst is mapped from  1.1.1.12:1024  to 100.64.0.2:12443
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 3000, "1.1.1.12", 1024,
		  "1.1.1.11", 1024, "100.64.0.2", 12443,
		  "aa:bb:cc:dd:1:a2", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_13 - CGNAT over a pre-existing VRF interface.
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat13, NULL, NULL);
DP_START_TEST_FULL_RUN(cgnat13, test)
{
	dp_test_intf_vif_create("dp2T1.100", "dp2T1", 100);

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.64.0.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1.100", "1.1.1.254/24");

	/*
	 * Inside
	 */
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.2",
				  "aa:bb:cc:dd:1:a2");

	/*
	 * Outside
	 */
	dp_test_netlink_add_neigh("dp2T1.100", "1.1.1.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1.100", "1.1.1.2",
				  "aa:bb:cc:dd:2:b2");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1.100", CGN_MAP_EIM, CGN_FLTR_EIF,
			 CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 100, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 100,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1.100");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	/* Cleanup */
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.1", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.2", "aa:bb:cc:dd:1:a2");

	dp_test_netlink_del_neigh("dp2T1.100", "1.1.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1.100", "1.1.1.2", "aa:bb:cc:dd:2:b2");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.64.0.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T1.100", "1.1.1.254/24");

	dp_test_intf_vif_del("dp2T1.100", 100);

	dp_test_npf_cleanup();

} DP_END_TEST;


/*
 * npf_cgnat_15 - Deleting a VRF interface that has CGNAT
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat15, NULL, NULL);
DP_START_TEST_FULL_RUN(cgnat15, test)
{
	dp_test_intf_vif_create("dp2T1.100", "dp2T1", 100);

	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.64.0.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T1.100", "1.1.1.254/24");

	/*
	 * Inside
	 */
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.2",
				  "aa:bb:cc:dd:1:a2");

	/*
	 * Outside
	 */
	dp_test_netlink_add_neigh("dp2T1.100", "1.1.1.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1.100", "1.1.1.2",
				  "aa:bb:cc:dd:2:b2");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1.100", CGN_MAP_EIM, CGN_FLTR_EIF,
			 CGN_5TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 100, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 100,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	dp_test_netlink_del_neigh("dp2T1.100", "1.1.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1.100", "1.1.1.2", "aa:bb:cc:dd:2:b2");
	dp_test_nl_del_ip_addr_and_connected("dp2T1.100", "1.1.1.254/24");
	dp_test_intf_vif_del("dp2T1.100", 100);

	dpt_addr_grp_destroy("POLICY1_AG", "100.64.0.0/12");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	/* Cleanup */
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.1", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.2", "aa:bb:cc:dd:1:a2");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.64.0.254/24");

	dp_test_npf_cleanup();

} DP_END_TEST;


static void
cgnat16_cb(struct rte_mbuf *mbuf, struct ifnet *ifp,
	   struct dp_test_expected *expected,
	   enum dp_test_fwd_result_e fwd_result)
{
	struct cgn_ctx *ctx = dp_test_exp_get_validate_ctx(expected);
	struct iphdr *ip = iphdr(mbuf);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	uint16_t cksum;

	/* fetch source port (offset 34) */
	ctx->port = ntohs(udp->source);

	struct rte_mbuf *exp_pak = dp_test_exp_get_pak(expected);

	/* update expected pak with source port */
	ip = iphdr(exp_pak);

	/*
	 * If the pkts caused an ICMP error, then no translation will have
	 * occurred
	 */
	if (ip->protocol == IPPROTO_ICMP) {
		struct icmp *ic = (struct icmp *)(ip + 1);

		/* This will need changed if this func is to support pings */
		if (ic->icmp_type != ICMP_UNREACH)
			return;

		/* Embedded pkt does not change */
		goto end;

	}

	udp = (struct udphdr *)(ip + 1);

	/* update source port (offset 34) */
	udp->source = htons(ctx->port);

	/* update tcp checksum */
	udp->check = 0;

	cksum = rte_ipv4_udptcp_cksum((const struct rte_ipv4_hdr *)ip,
				      (const void *)udp);
	udp->check = (cksum == 0xffff) ? 0000 : cksum;

end:
	/* call the saved check routine */
	if (ctx->do_check) {
		dp_test_pak_verify(mbuf, ifp, expected, fwd_result);
	} else {
		expected->pak_correct[0] = true;
		expected->pak_checked[0] = true;
	}
}

/*
 * npf_cgnat_16 - Tests random port allocation within a block
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat16, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat16, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"port-alloc=random");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * The random port selected will be stored in cgn_ctx.port
	 */
	cgn_ctx.saved_cb = cgnat16_cb;

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgn_ctx.saved_cb = dp_test_pak_verify;

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:x / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", cgn_ctx.port,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


static void dpt_cgn_show_source(bool print)
{
	json_object *jresp;
	char *response;
	bool err;

	response = dp_test_console_request_w_err(
			"cgn-op show subscriber detail", &err, false);
	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);

	json_object_put(jresp);
}

static void dpt_cgn_show_subscriber_count(uint start, uint count, bool detail)
{
	char cmd[120];
	json_object *jresp;
	char *response;
	bool err;
	int l = 0;

	l += snprintf(cmd + l, sizeof(cmd) - l, "cgn-op show subscriber");

	if (detail)
		l += snprintf(cmd + l, sizeof(cmd) - l, " detail");

	if (count > 0)
		l += snprintf(cmd + l, sizeof(cmd) - l,
			      " start %u count %u", start, count);

	(void) l;

	response = dp_test_console_request_w_err(cmd, &err, false);

	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);

	json_object_put(jresp);
}

static void dpt_cgn_show_policy(bool print)
{
	json_object *jresp;
	char *response;
	bool err;

	response = dp_test_console_request_w_err(
			"cgn-op show policy", &err, false);
	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);

	json_object_put(jresp);
}

static void dpt_cgn_show_public(bool print, bool detail)
{
	json_object *jresp;
	char *response;
	bool err;

	if (detail)
		response = dp_test_console_request_w_err(
			"cgn-op show apm detail", &err, false);
	else
		response = dp_test_console_request_w_err(
			"cgn-op show apm", &err, false);

	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);

	json_object_put(jresp);
}

static void dpt_cgn_show_public_count(uint start, uint count, bool detail)
{
	char cmd[120];
	json_object *jresp;
	char *response;
	bool err;
	int l = 0;

	l += snprintf(cmd + l, sizeof(cmd) - l, "cgn-op show apm");

	if (detail)
		l += snprintf(cmd + l, sizeof(cmd) - l, " detail");

	if (count > 0)
		l += snprintf(cmd + l, sizeof(cmd) - l,
			      " start %u count %u", start, count);

	(void) l;

	response = dp_test_console_request_w_err(cmd, &err, false);

	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);

	json_object_put(jresp);
}

static int
dpt_cgn_show_session_one(json_object *joutr, bool print, bool debug)
{
	/*
	 * Format string with outer session info
	 */
	const char *subs_addr = NULL, *pub_addr = NULL, *intf = NULL;
	int subs_port = 0, pub_port = 0, proto = 0, timeout = 0, index = 0;
	char outr_str[120];

	dp_test_json_string_field_from_obj(joutr, "subs_addr", &subs_addr);
	dp_test_json_string_field_from_obj(joutr, "pub_addr", &pub_addr);
	dp_test_json_string_field_from_obj(joutr, "intf", &intf);
	dp_test_json_int_field_from_obj(joutr, "subs_port", &subs_port);
	dp_test_json_int_field_from_obj(joutr, "pub_port", &pub_port);
	dp_test_json_int_field_from_obj(joutr, "proto", &proto);
	dp_test_json_int_field_from_obj(joutr, "cur_to", &timeout);
	dp_test_json_int_field_from_obj(joutr, "index", &index);

	snprintf(outr_str, sizeof(outr_str),
		 "%6s %10d %5d %15s %5d %15s %5d %8d",
		 intf, index, proto, subs_addr, subs_port,
		 pub_addr, pub_port, timeout);

	json_object *jarray_inr;

	/*
	 * Get dest sessions array from joutr
	 */
	struct dp_test_json_find_key key[] = {
		{ "destinations", NULL },
		{ "sessions", NULL }
	};

	/* Inner dest sessions array may not exist */
	jarray_inr = dp_test_json_find(joutr, key, ARRAY_SIZE(key));

	if (!jarray_inr) {
		if (print || debug)
			printf("%s\n", outr_str);
		return 1;
	}

	int sess_count = 0;
	uint i, arraylen_inr = 0;

	arraylen_inr = json_object_array_length(jarray_inr);

	for (i = 0; i < arraylen_inr; i++) {
		json_object *jinr;

		/* Get the array element at position i */
		jinr = json_object_array_get_idx(jarray_inr, i);
		if (!jinr)
			break;

		/*
		 * Format string with outer session info
		 */
		const char *dst_addr = NULL;
		int dst_port;
		char inr_str[40];

		dp_test_json_string_field_from_obj(jinr, "dst_addr", &dst_addr);
		dp_test_json_int_field_from_obj(jinr, "dst_port", &dst_port);

		snprintf(inr_str, sizeof(inr_str), "%15s %5d",
			 dst_addr, dst_port);

		if (print || debug)
			printf("%s %s\n", outr_str, inr_str);

		sess_count++;
	}

	json_object_put(jarray_inr);

	if (i == 0) {
		if (print || debug)
			printf("%s\n", outr_str);
		return 1;
	}

	return sess_count;
}

/*
 * Fetches 'count' sessions per call.  Returns number of sessions found.
 */
static int
_dpt_cgn_show_session(char *_cmd, uint count, bool print, bool debug)
{
	int sess_count = 0;
	char *response;
	char cmd[120];
	bool err;
	bool print_json = debug;

	/*
	 * Send command to dataplane
	 */
	snprintf(cmd, sizeof(cmd), "%s count %u", _cmd, count);
	if (debug)
		printf("Cmd: %s\n", cmd);

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err) {
		if (debug)
			printf("No response to command\n");
		return 0;
	}

	/*****************************************************************
	 * Parse response string to get json object
	 */
	json_object *jresp;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);
	if (!jresp) {
		if (debug)
			printf("Failed to parse response\n");
		return 0;
	}

	if (print_json) {
		const char *str;
		str = json_object_to_json_string_ext(jresp,
						     JSON_C_TO_STRING_PRETTY);
		if (str)
			printf("%s\n", str);
	}

	/*****************************************************************
	 * Get the outer 3-tuple sessions json array
	 */
	struct dp_test_json_find_key key[] = {
		{
			"sessions", NULL
		}
	};
	json_object *jarray_outr;
	uint arraylen_outr;

	jarray_outr = dp_test_json_find(jresp, key, ARRAY_SIZE(key));

	/* finished with jresp now */
	json_object_put(jresp);
	jresp = NULL;

	if (!jarray_outr) {
		if (debug)
			printf("Failed to get outer sessions array\n");
		return 0;
	}
	arraylen_outr = json_object_array_length(jarray_outr);

	/* Print banner */
	if (print || debug)
		printf("%6s %10s %5s %15s %5s %15s %5s %8s %15s %5s\n",
		       "Intf", "Index", "Proto", "Src addr", "Port",
		       "Trans Addr", "Port", "Timeout", "Dest Addr", "Port");

	/*****************************************************************
	 * Iterate over the 3-tuple session array
	 */
	uint i;

	for (i = 0; i < arraylen_outr; i++) {
		json_object *joutr;

		/* Get the array element at position i */
		joutr = json_object_array_get_idx(jarray_outr, i);
		if (!joutr)
			break;

		sess_count += dpt_cgn_show_session_one(joutr, print, debug);
	}

	json_object_put(jarray_outr);

	return sess_count;
}

/*
 * Fetch session table in batches of 'count' sessions.  Uses the last session
 * of the previous batch to specify the target for the next batch.
 *
 * If per_subs is true then first fetch the subscriber list, and then fetch
 * the sessions for each subscriber.
 */
static int
dpt_cgn_show_session(const char *fltr, uint count, bool per_subs, bool print,
		     bool debug)
{
	char cmd[120];
	int l;
	int rv, found = 0;

	if (per_subs) {
		/*
		 * Emulates how the control plane uses the subscriber list to
		 * fetch sessions per subscriber address.
		 */
		struct dp_test_json_find_key key[] = { {"subscribers", NULL} };
		json_object *jresp, *jarray;
		char *response;
		uint arraylen, i;
		bool err;

		response = dp_test_console_request_w_err(
			"cgn-op list subscribers", &err, false);
		if (!response || err)
			return 0;

		jresp = parse_json(response, parse_err_str,
				   sizeof(parse_err_str));
		free(response);

		if (!jresp)
			return 0;

		jarray = dp_test_json_find(jresp, key, ARRAY_SIZE(key));
		json_object_put(jresp);

		if (!jarray)
			return 0;

		arraylen = json_object_array_length(jarray);

		for (i = 0; i < arraylen; i++) {
			json_object *jvalue;
			uint32_t subs_addr;

			/* Get the array element at position i */
			jvalue = json_object_array_get_idx(jarray, i);
			if (!jvalue)
				break;

			/* get subscriber address */
			subs_addr = json_object_get_int(jvalue);
			subs_addr = htonl(subs_addr);

			char subs_str[16];

			inet_ntop(AF_INET, &subs_addr, subs_str,
				  sizeof(subs_str));

			snprintf(cmd, sizeof(cmd),
				 "cgn-op show session subs-addr %s", subs_str);

			rv = _dpt_cgn_show_session(cmd, count, print, debug);
			found += rv;
		}
		json_object_put(jarray);

	} else {
		l = snprintf(cmd, sizeof(cmd), "cgn-op show session");

		if (fltr)
			l += snprintf(cmd + l, sizeof(cmd) - l, " %s", fltr);

		(void) l;

		rv = _dpt_cgn_show_session(cmd, count, print, debug);
		found += rv;
	}

	return found;
}

/*
 * Get json object for a 3-tuple session
 */
static json_object *dpt_cgn_sess_json(const char *fltr, bool debug)
{
	char cmd[120];
	char *response;
	bool err;

	dp_test_fail_unless(fltr,
			    "A filter identifying the session must be specd");

	snprintf(cmd, sizeof(cmd), "cgn-op show session %s", fltr);

	/*
	 * Send command to dataplane
	 */
	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err) {
		if (debug)
			printf("No response to command\n");
		return NULL;
	}

	/*****************************************************************
	 * Parse response string to get json object
	 */
	json_object *jresp;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);
	if (!jresp) {
		if (debug)
			printf("Failed to parse response\n");
		return NULL;
	}

	if (debug) {
		const char *str;
		str = json_object_to_json_string_ext(jresp,
						     JSON_C_TO_STRING_PRETTY);
		if (str)
			printf("%s\n", str);
	}

	/*****************************************************************
	 * Get the outer 3-tuple sessions json array
	 */
	struct dp_test_json_find_key key[] = {
		{
			"sessions", NULL
		}
	};
	json_object *jarray_outr;
	uint arraylen_outr;

	jarray_outr = dp_test_json_find(jresp, key, ARRAY_SIZE(key));

	/* finished with jresp now */
	json_object_put(jresp);
	jresp = NULL;

	if (!jarray_outr) {
		if (debug)
			printf("Failed to get outer sessions array\n");
		return NULL;
	}
	arraylen_outr = json_object_array_length(jarray_outr);

	dp_test_fail_unless(arraylen_outr == 1,
			    "More than one outer session");

	/*****************************************************************
	 * Get first session (should only be one)
	 */
	json_object *joutr;

	/* Get the array element at position 0 */
	joutr = json_object_array_get_idx(jarray_outr, 0);
	if (!joutr) {
		json_object_put(jarray_outr);
		return NULL;
	}

	joutr = json_object_get(joutr);
	json_object_put(jarray_outr);

	return joutr;
}

/*
 * Get json object for a 2-tuple session
 */
static json_object *dpt_cgn_inr_sess_json(json_object *joutr, bool debug)
{
	json_object *jarray_inr;

	/*
	 * Get dest sessions array from joutr
	 */
	struct dp_test_json_find_key key[] = {
		{ "destinations", NULL },
		{ "sessions", NULL }
	};

	/* Inner dest sessions array may not exist */
	jarray_inr = dp_test_json_find(joutr, key, ARRAY_SIZE(key));

	if (!jarray_inr)
		return NULL;

	uint arraylen_inr = 0;

	arraylen_inr = json_object_array_length(jarray_inr);

	dp_test_fail_unless(arraylen_inr == 1,
			    "Zero or more than one inner session");

	json_object *jinr;

	/* Get the array element at position 0 */
	jinr = json_object_array_get_idx(jarray_inr, 0);

	if (!jinr)
		return NULL;

	jinr = json_object_get(jinr);

	json_object_put(jarray_inr);
	return jinr;
}

static int dpt_cgn_sess_get_timeout(const char *fltr, bool outer)
{
	json_object *joutr, *jinr;
	int timeout = 0;

	joutr = dpt_cgn_sess_json(fltr, false);
	dp_test_fail_unless(joutr, "Failed to get json object for 3-tuple");

	if (outer) {
		dp_test_json_int_field_from_obj(joutr, "max_to", &timeout);
		json_object_put(joutr);
		return timeout;
	}

	jinr = dpt_cgn_inr_sess_json(joutr, false);
	dp_test_fail_unless(jinr, "Failed to get json object for 2-tuple");

	dp_test_json_int_field_from_obj(jinr, "max_to", &timeout);

	json_object_put(jinr);
	json_object_put(joutr);

	return timeout;
}

static void dpt_cgn_show_pool(bool print)
{
	json_object *jresp;
	char *response;
	bool err;

	response = dp_test_console_request_w_err(
			"nat-op show pool", &err, false);
	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);

	json_object_put(jresp);
}

/*
 * Create a CGNAT mapping using the vplsh command.
 *
 * If pub_addr and pub_port are non NULL, and *pub_port > 0, then these
 * contain mappings to be requested.
 *
 * pub_addr and pub_port will contain the allocated mappings.
 */
static int
dpt_cgn_map(bool print, char *real_intf, uint timeout, uint8_t ipproto,
	    char *subs_addr, uint16_t subs_port,
	    char *pub_addr, int *pub_port)
{
	json_object *jresp, *jmap;
	const char *str;
	char *response;
	char cmd[240];
	bool err, rv;
	int l;

	l = snprintf(cmd, sizeof(cmd),
		     "cgn-op map intf %s timeout %u proto %u "
		     "subs-addr %s subs-port %u",
		     real_intf, timeout, ipproto, subs_addr, subs_port);

	if (pub_addr && strlen(pub_addr) > 0)
		l += snprintf(cmd + l, sizeof(cmd) - l,
			      " pub-addr %s", pub_addr);

	if (pub_port)
		l += snprintf(cmd + l, sizeof(cmd) - l,
			      " pub-port %u", *pub_port);

	response = dp_test_console_request_w_err(cmd, &err, false);

	if (!response || err)
		return -1;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return -2;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);

	struct dp_test_json_find_key key[] = { {"map", NULL} };
	const char *pub_addr_str = NULL;

	jmap = dp_test_json_find(jresp, key, ARRAY_SIZE(key));
	json_object_put(jresp);

	if (!jmap)
		return -3;

	rv = dp_test_json_string_field_from_obj(jmap, "pub_addr",
						&pub_addr_str);
	if (!rv) {
		json_object_put(jmap);
		return -4;
	}
	if (pub_addr)
		strcpy(pub_addr, pub_addr_str);

	if (pub_port) {
		rv = dp_test_json_int_field_from_obj(jmap, "pub_port",
						     pub_port);
		if (!rv) {
			json_object_put(jmap);
			return -5;
		}
	}

	json_object_put(jmap);
	return 0;
}

/*
 * Create a CGNAT mapping directly
 */
static int
dpt_cgn_map2(struct ifnet *ifp, uint timeout, uint8_t ipproto,
	     uint32_t subs_addr, uint16_t subs_port,
	     const uint32_t *pub_addr, const uint16_t *pub_port)
{
	struct cgn_packet cpk;
	struct cgn_session *cse;
	int error = 0;

	memset(&cpk, 0, sizeof(cpk));

	cpk.cpk_saddr = subs_addr;
	cpk.cpk_sid = htons(subs_port);
	cpk.cpk_daddr = 0;
	cpk.cpk_did = 0;
	cpk.cpk_ipproto = ipproto;
	cpk.cpk_ifindex = ifp->if_index;
	cpk.cpk_key.k_ifindex = cgn_if_key_index(ifp);
	cpk.cpk_l4ports = true;

	cpk.cpk_proto = nat_proto_from_ipproto(ipproto);
	cpk.cpk_vrfid = if_vrfid(ifp);
	cpk.cpk_keepalive = true;
	cpk.cpk_pkt_instd = false;

	cpk.cpk_key.k_expired = false;

	/* Setup direction dependent part of hash key */
	cgn_pkt_key_init(&cpk, CGN_DIR_OUT);

	cse = cgn_session_map(ifp, &cpk,
			      pub_addr ? *pub_addr : 0,
			      pub_port ? *pub_port : 0, &error);
	if (!cse)
		return -1;

	return error;
}

static void dpt_cgn_list_subscribers(bool print)
{
	json_object *jresp;
	char *response;
	bool err;

	response = dp_test_console_request_w_err(
			"cgn-op list subscribers", &err, false);
	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);

	json_object_put(jresp);
}

static void dpt_cgn_list_public(bool print)
{
	json_object *jresp;
	char *response;
	bool err;

	response = dp_test_console_request_w_err(
			"cgn-op list public", &err, false);
	if (!response || err)
		return;

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	if (!jresp)
		return;

	const char *str;

	str = json_object_to_json_string_ext(jresp, JSON_C_TO_STRING_PRETTY);
	if (str && print)
		printf("%s\n", str);

	json_object_put(jresp);
}

/*
 * npf_cgnat_17 - Tests cgnat show commands
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat17, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat17, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"");

	dpt_addr_grp_create("LOG_AG1", "100.64.1.0/24");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/24", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	cgnat_policy_add2("POLICY2", 20, "100.64.1.0/24", "POOL1",
			  "dp2T1", "log-sess-group=LOG_AG1");

	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_tcp(TH_SYN | TH_ACK, "dp2T1", "aa:bb:cc:dd:2:b1",
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_icmp(ICMP_ECHO, "dp1T0", "aa:bb:cc:dd:1:a1",
		   "100.64.0.1", 49152, "1.1.1.1",
		   "1.1.1.11", 1024, "1.1.1.1",
		   "aa:bb:cc:dd:2:b1", "dp2T1");

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_icmp(ICMP_ECHOREPLY, "dp2T1", "aa:bb:cc:dd:2:b1",
		   "1.1.1.1", 1024, "1.1.1.11",
		   "1.1.1.1", 49152, "100.64.0.1",
		   "aa:bb:cc:dd:1:a1", "dp1T0");

	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a3", 0,
		  "100.64.1.1", 23001, "1.1.1.2", 80,
		  "1.1.1.12", 1024, "1.1.1.2", 80,
		  "aa:bb:cc:dd:2:b2", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.2:80  -->  1.1.1.12:1024 / 100.64.1.1:23001
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b2", 0,
		  "1.1.1.2", 80, "1.1.1.12", 1024,
		  "1.1.1.2", 80, "100.64.1.1", 23001,
		  "aa:bb:cc:dd:1:a3", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a3", 0,
		  "100.64.1.1", 23001, "1.1.1.1", 80,
		  "1.1.1.12", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	dp_test_npf_cmd_fmt(false, "cgn-op update session");
	dp_test_npf_cmd_fmt(false, "cgn-op update subscriber");

	bool print = false;

	dpt_cgn_show_policy(print);
	dpt_cgn_show_pool(print);
	dpt_cgn_show_public(print, true);
	dpt_cgn_show_source(print);
	dpt_cgn_list_subscribers(print);
	dpt_cgn_list_public(print);
	dpt_cgn_show_summary(print);
	dpt_cgn_show_error(print);

	dp_test_npf_cmd_fmt(false, "cgn-op clear session");
	dp_test_npf_cmd_fmt(false, "cgn-op clear subscriber");
	dp_test_npf_cmd_fmt(false, "cgn-op clear policy");
	dp_test_npf_cmd_fmt(false, "cgn-op clear errors");

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	cgnat_policy_del("POLICY2", 20, "dp2T1");

	dpt_addr_grp_destroy("LOG_AG1", "100.64.1.0/24");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_18 - Tests blocklist
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat18, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat18, test)
{
	dpt_addr_grp_create("BLOCKLIST1", "1.1.1.11/32");
	dp_test_npf_cmd_fmt(false,
			    "npf-ut fw table add BLOCKLIST1 1.1.1.13/32");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.14 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Add blocked address to pool, and run GC to expire sessions using
	 * blocked addresses.
	 *
	 * Blocklist addresses: 1.1.1.11, 1.1.1.13
	 * Useable addresses:   1.1.1.12, 1.1.1.14
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool update POOL1 "
			"blacklist=BLOCKLIST1");

	/*
	 * We need to explicitly clear existing sessions
	 */
	dp_test_npf_cmd_fmt(false,
			    "cgn-op clear session pub-addr 1.1.1.11");

	/*
	 * Repeat earlier packet.  Public address 1.1.1.12 is now used.
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.12", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 100.64.0.2:1234 / 1.1.1.14:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.2", 1234, "1.1.1.1", 80,
		  "1.1.1.14", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * There are now no unused public addresses.  Another new subscriber
	 * should use an unused port-block on an already used public address.
	 * In this case it will use the second port-block on 1.1.1.12.  New
	 * src port is 1536 (1024+512).
	 *
	 * 100.64.0.3:2345 / 1.1.1.12:1536 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.3", 2345, "1.1.1.1", 80,
		  "1.1.1.12", 1536, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_npf_cmd_fmt(false,
			    "npf-ut fw table remove BLOCKLIST1 1.1.1.13/32");
	dpt_addr_grp_destroy("BLOCKLIST1", "1.1.1.11/32");

} DP_END_TEST;


/*
 * npf_cgnat_20 - 129 UDP forwards pkts, different source addrs
 *
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat20, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat20, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.255.255.254 "
			"block-size=128 "
			"max-blocks=2"
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	static char pre_str[20];
	static char post_str[20];
	uint32_t pre_n, post_n;
	uint16_t sport_pre, sport_post;
	uint i, count = 129;

	/* src addr before */
	pre_n = dpt_init_ipaddr(pre_str, "100.64.0.1");

	/* src addr after */
	post_n = dpt_init_ipaddr(post_str, "1.1.1.11");

	sport_pre = 3000;
	sport_post = 1024;

	for (i = 0; i < count; i++) {

		cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
			  pre_str, sport_pre, "1.1.1.1", 80,
			  post_str, sport_post, "1.1.1.1", 80,
			  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
			  DP_TEST_FWD_FORWARDED);

		/* Increment addresses */
		pre_n = dpt_incr_ipaddr(pre_n, pre_str, sizeof(pre_str));
		post_n = dpt_incr_ipaddr(post_n, post_str, sizeof(post_str));

	}

	if (0)
		dpt_cgn_show_public_count(0, 1, true);

	if (0)
		dpt_cgn_show_subscriber_count(0, 1, true);

	/*
	 * Tack on a "clear session" test
	 */
	dp_test_npf_cmd_fmt(false,
			    "cgn-op clear session pool POOL1");

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");


} DP_END_TEST;


/*
 * npf_cgnat_21 - 'n' UDP forwards pkts, same src addr, diff src ports
 *
 * Tests max-blocks-per-user limit.
 *
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat21, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat21, test)
{
	uint block_size = 128;
	uint mbpu = 2;
	uint i, count = (block_size * mbpu) + 1;

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.255.255.254 "
			"block-size=%u "
			"max-blocks=%u"
			"", block_size, mbpu);

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	static char pre_str[20];
	static char post_str[20];
	uint32_t pre_n, post_n;
	uint16_t sport_pre, sport_post;

	/* src addr before */
	pre_n = dpt_init_ipaddr(pre_str, "100.64.0.1");

	/* src addr after */
	post_n = dpt_init_ipaddr(post_str, "1.1.1.11");

	sport_pre = 3000;
	sport_post = 1024;

	for (i = 0; i < count; i++) {

		int status = DP_TEST_FWD_FORWARDED;

		if (i == count - 1)
			status = DP_TEST_FWD_DROPPED;

		if (i > 0) {
			if (sport_pre == 65535) {
				pre_n = dpt_incr_ipaddr(pre_n, pre_str,
							sizeof(pre_str));
				sport_pre = 1024;
			} else
				sport_pre++;

			if (sport_post == 65535) {
				/* Increment addresses */
				post_n = dpt_incr_ipaddr(post_n, post_str,
							 sizeof(post_str));
				sport_post = 1024;
			} else
				sport_post++;
		}

		bool icmp_err = (status == DP_TEST_FWD_DROPPED);

		_cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
			   pre_str, sport_pre, "1.1.1.1", 80,
			   post_str, sport_post, "1.1.1.1", 80,
			   "aa:bb:cc:dd:2:b1", 0, "dp2T1",
			   status, icmp_err,
			   __FILE__, __func__, __LINE__);

	}

	/*
	 * Test clearing one session, and then repeat last packet so that it
	 * finds and uses the cleared mapping
	 *
	 * The session cleared is: 100.64.0.1:3001 which is mapped to
	 * 1.1.1.11:1025.
	 */
	dp_test_npf_cmd_fmt(false,
			    "cgn-op clear session "
			    "subs-addr 100.64.0.1 subs-port 3001");

	for (i = 0; i < CGN_SESS_GC_COUNT + 1; i++)
		dp_test_npf_cmd_fmt(false, "cgn-op ut gc");

	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  pre_str, sport_pre, "1.1.1.1", 80,
		  "1.1.1.11", 1025, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_22 - 'n' TCP forwards pkts, same src addr, diff src ports
 *
 * Tests address-pool paired limit.  Port range is limited to 256 ports.
 * Block size is 128 and max-blocks-per-user is 4, so APP is the limiting
 * factor.
 *
 * The public address we are paired with runs out of ports before the
 * max-blocks-per-subscriber limit is reached.
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat22, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat22, test)
{
	uint16_t port_start = 4096, port_end = 4351;
	uint16_t nports = port_end - port_start + 1;
	uint block_size = 128;
	uint mbpu = 4;
	uint i, count = nports + 1;

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.255.255.254 "
			"port-range=%u-%u "
			"block-size=%u "
			"max-blocks=%u "
			"", port_start, port_end, block_size, mbpu);

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	static char pre_str[20];
	static char post_str[20];
	uint32_t pre_n, post_n;
	uint16_t sport_pre, sport_post;

	/* src addr before */
	pre_n = dpt_init_ipaddr(pre_str, "100.64.0.1");

	/* src addr after */
	post_n = dpt_init_ipaddr(post_str, "1.1.1.11");

	sport_pre = 3000;
	sport_post = port_start;

	for (i = 0; i < count; i++) {

		int status = DP_TEST_FWD_FORWARDED;

		if (i == count - 1)
			status = DP_TEST_FWD_DROPPED;

		cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
			  pre_str, sport_pre, "1.1.1.1", 80,
			  post_str, sport_post, "1.1.1.1", 80,
			  "aa:bb:cc:dd:2:b1", "dp2T1",
			  status);

		if (sport_pre == 65535) {
			pre_n = dpt_incr_ipaddr(pre_n, pre_str,
						sizeof(pre_str));
			sport_pre = 3000;
		} else
			sport_pre++;

		if (sport_post == port_end) {
			/* Increment addresses */
			post_n = dpt_incr_ipaddr(post_n, post_str,
						 sizeof(post_str));
			sport_post = port_start;
		} else
			sport_post++;
	}

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_23 - 'n' TCP forwards pkts, same src addr, diff src ports
 *
 * Tests address-pool arbitrary.  Port range is limited to 256 ports.
 * Block size is 128 and max-blocks-per-user is 4.  Send 1 more pkt than
 * there are mappings in one address.
 *
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat23, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat23, test)
{
	uint16_t port_start = 4096, port_end = 4351;
	uint16_t nports = port_end - port_start + 1;
	uint block_size = 128;
	uint mbpu = 4;
	uint i, count = nports + 1;

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.255.255.254 "
			"port-range=%u-%u "
			"block-size=%u "
			"max-blocks=%u "
			"addr-pooling=arbitrary "
			"", port_start, port_end, block_size, mbpu);

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	static char pre_str[20];
	static char post_str[20];
	uint32_t pre_n, post_n;
	uint16_t sport_pre, sport_post;

	/* src addr before */
	pre_n = dpt_init_ipaddr(pre_str, "100.64.0.1");

	/* src addr after */
	post_n = dpt_init_ipaddr(post_str, "1.1.1.11");

	sport_pre = 3000;
	sport_post = port_start;

	for (i = 0; i < count; i++) {

		cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
			  pre_str, sport_pre, "1.1.1.1", 80,
			  post_str, sport_post, "1.1.1.1", 80,
			  "aa:bb:cc:dd:2:b1", "dp2T1",
			  DP_TEST_FWD_FORWARDED);

		if (sport_pre == 65535) {
			pre_n = dpt_incr_ipaddr(pre_n, pre_str,
						sizeof(pre_str));
			sport_pre = 3000;
		} else
			sport_pre++;

		if (sport_post == port_end) {
			/* Increment addresses */
			post_n = dpt_incr_ipaddr(post_n, post_str,
						 sizeof(post_str));
			sport_post = port_start;
		} else
			sport_post++;

	}

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_24 - Tests EIF.
 *
 * UDP.  1 fwd pkt, 1 back pkt to setup session. Tests EIF.  Send 2 ext-to-int
 * pkts, 1 with different src addr and 1 with different src port.  Dest
 * matches 3-tuple session, so both are forwarded.  Send 1 pkt ext-to-int with
 * dest IP matching subscriber session, but diff port.  Pkt is dropped.
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat24, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat24, test)
{
	/*
	 * pool add POOL1
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"type=cgnat "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.2:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b2", 0,
		  "1.1.1.2", 80, "1.1.1.11", 1024,
		  "1.1.1.2", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:1000  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 1000, "1.1.1.11", 1024,
		  "1.1.1.1", 1000, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1025 / -
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1025,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_DROPPED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_25 - Tests nested 2-tuple sessions.
 *
 * 'n' UDP forwards pkts, same src addr, diff dest addrs
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat25, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat25, test)
{
	uint block_size = 4096;
	uint mbpu = 16;
	uint i, count = 65;

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.255.255.254 "
			"port-range=4096-65535 "
			"block-size=%u "
			"max-blocks=%u"
			"", block_size, mbpu);

	/* 3-tuple session only */
	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_5TUPLE, true);

	const char *daddr;
	const char *dmac;
	uint16_t dport;

	dport = 2000;

	cgn_ctx.do_check = true;

	for (i = 0; i < count; i++) {

		int status = DP_TEST_FWD_FORWARDED;

		/*
		 * 64 dests are allowed per 3-tuple session.  Once that is
		 * reached, further flows will be dropped, and an ICMP error
		 * returned to the sender.
		 */
		if (i == count - 1)
			status = DP_TEST_FWD_DROPPED;

		/* Alternate dest addr */
		if ((i & 1) == 0) {
			daddr = "1.1.1.1";
			dmac = "aa:bb:cc:dd:2:b1";
		} else {
			daddr = "1.1.1.2";
			dmac = "aa:bb:cc:dd:2:b2";
		}

		bool icmp_err = (status == DP_TEST_FWD_DROPPED);

		_cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
			  "100.64.0.1", 1000, daddr, dport,
			  "1.1.1.11",   4096, daddr, dport,
			  dmac, 0, "dp2T1",
			  status, icmp_err,
			   __FILE__, __func__, __LINE__);

		dport++;
	}

	cgn_ctx.do_check = true;

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_26 - Tests max-blocks-per-user limit, with random port allocation.
 *                'n' UDP forwards pkts, same src addr, diff src ports
 *
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat26, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat26, test)
{
	uint block_size = 128;
	uint mbpu = 2;
	uint i, count = (block_size * mbpu) + 1;

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.255.255.254 "
			"block-size=%u "
			"max-blocks=%u "
			"port-alloc=random"
			"", block_size, mbpu);

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	static char pre_str[20];
	uint32_t pre_n;
	uint16_t sport_pre;

	/* src addr before */
	pre_n = dpt_init_ipaddr(pre_str, "100.64.0.1");

	sport_pre = 3000;

	/*
	 * The random source port selected will be stored in cgn_ctx.port
	 */
	cgn_ctx.saved_cb = cgnat16_cb;

	for (i = 0; i < count; i++) {

		int status = DP_TEST_FWD_FORWARDED;

		if (i == count - 1)
			status = DP_TEST_FWD_DROPPED;

		if (i > 0) {
			if (sport_pre == 65535) {
				pre_n = dpt_incr_ipaddr(pre_n, pre_str,
							sizeof(pre_str));
				sport_pre = 1024;
			} else
				sport_pre++;
		}

		bool icmp_err = (status == DP_TEST_FWD_DROPPED);

		_cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
			   pre_str, sport_pre, "1.1.1.1", 80,
			   "1.1.1.11", 0, "1.1.1.1", 80,
			   "aa:bb:cc:dd:2:b1", 0, "dp2T1",
			   status, icmp_err,
			   __FILE__, __func__, __LINE__);
	}

	/*
	 * Test clearing one session, and then repeat last packet so that it
	 * finds and uses the cleared mapping
	 *
	 * The session cleared is: 100.64.0.1:3001 which is mapped to
	 * 1.1.1.11:1025.
	 */
	dp_test_npf_cmd_fmt(false,
			    "cgn-op clear session "
			    "subs-addr 100.64.0.1 subs-port 3001");

	for (i = 0; i < CGN_SESS_GC_COUNT + 1; i++)
		dp_test_npf_cmd_fmt(false, "cgn-op ut gc");

	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  pre_str, sport_pre, "1.1.1.1", 80,
		  "1.1.1.11", 1025, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	cgn_ctx.saved_cb = dp_test_pak_verify;

} DP_END_TEST;


/*
 * npf_cgnat_27 - This tests destructive change to a nat pool
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat27, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat27, test)
{
	/*
	 * pool add POOL1
	 *   address-range=RANGE1/1.1.1.11-1.1.1.20
	 *   prefix=RANGE2/1.1.1.192/26
	 *   port-range=4096-65535
	 *   port-alloc=sequential
	 *   block-size=512
	 *   max-blocks=8
	 *   add-pooling=paired
	 *   addr-alloc=round-robin
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"log-pba=yes "
			"block-size=512 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/* 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	struct nat_pool *np = nat_pool_lookup("POOL1");
	dp_test_fail_unless(np, "!np");

	/*
	 * Test a cgnat when nat pool is de-activated
	 */
	nat_pool_clear_active(np);

	/* No session will exist for Outside to Inside pkt */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_DROPPED);

	/*
	 * New inside to out flow will not find the nat pool, and an ICMP
	 * error will be generated.
	 */
	cgnat_udp_err("dp1T0", "aa:bb:cc:dd:1:a2", 0,
		      "100.64.0.2", 30123, "1.1.1.1", 80,
		      "1.1.1.11", 1024, "1.1.1.1", 80,
		      "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		      DP_TEST_FWD_DROPPED);

	nat_pool_set_active(np);

	/* New inside to out flow should now find the nat pool */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a2", 0,
		  "100.64.0.2", 30123, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* Repeat very first pkt. It should map to 1.1.1.12 now  */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.12", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Test nat pool block size can be changed.  This will tear down all
	 * sessions and mapping that use this pool.
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"block-size=128 "
			"");

	/* Repeat very first pkt. It should map to 1.1.1.11 now  */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_30 - CGNAT commands
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat30, NULL, NULL);
DP_START_TEST_FULL_RUN(cgnat30, test)
{
	/*
	 * Address pool with all options
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.2.0/24 "
			"port-range=4096-65535 "
			"port-alloc=sequential "
			"block-size=512 "
			"max-blocks=8 "
			"add-pooling=paired "
			"addr-alloc=round-robin");

	/* Delete then Re-add with different options */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool delete POOL1");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.2.0/24 "
			"port-range=4096-65535 "
			"port-alloc=random "
			"block-size=64 "
			"max-blocks=2 "
			"add-pooling=arbitrary "
			"addr-alloc=sequential");

	/* Changing block size will succeed */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.2.0/24 "
			"port-range=4096-65535 "
			"port-alloc=random "
			"block-size=128 "
			"max-blocks=2 "
			"add-pooling=arbitrary "
			"addr-alloc=sequential");

	/* Removing a range will succeed */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"port-range=4096-65535 "
			"port-alloc=random "
			"block-size=128 "
			"max-blocks=2 "
			"add-pooling=arbitrary "
			"addr-alloc=sequential");

	/* Adding a range will succeed */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.2.0/24 "
			"address-range=RANGE3/1.1.2.1-1.1.2.10 "
			"port-range=4096-65535 "
			"port-alloc=random "
			"block-size=64 "
			"max-blocks=2 "
			"add-pooling=arbitrary "
			"addr-alloc=sequential");

	/* Changing a range such that an address is removed will succeed */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.19 "
			"prefix=RANGE2/1.1.2.0/24 "
			"address-range=RANGE3/1.1.2.1-1.1.2.10 "
			"port-range=4096-65535 "
			"port-alloc=random "
			"block-size=64 "
			"max-blocks=2 "
			"add-pooling=arbitrary "
			"addr-alloc=sequential");

	/* Changing a range such that an address is added will succeed */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.21 "
			"prefix=RANGE2/1.1.2.0/24 "
			"address-range=RANGE3/1.1.2.1-1.1.2.10 "
			"port-range=4096-65535 "
			"port-alloc=random "
			"block-size=64 "
			"max-blocks=2 "
			"add-pooling=arbitrary "
			"addr-alloc=sequential");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool delete POOL1");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL2 "
			"type=cgnat "
			"prefix=RANGE1/1.1.1.1/32 "
			"prefix=RANGE2/1.1.1.2/32 "
			"prefix=RANGE3/1.1.1.3/32 "
			"prefix=RANGE4/1.1.1.4/32 "
			"prefix=RANGE5/1.1.1.5/32 "
			"prefix=RANGE6/1.1.1.6/32 "
			"prefix=RANGE7/1.1.1.7/32 "
			"prefix=RANGE8/1.1.1.8/32 "
			"prefix=RANGE9/1.1.1.9/32 "
			"prefix=RANGE10/1.1.1.10/32 "
			"prefix=RANGE11/1.1.1.11/32 "
			"prefix=RANGE12/1.1.1.12/32 "
			"prefix=RANGE13/1.1.1.13/32 "
			"prefix=RANGE14/1.1.1.14/32 "
			"prefix=RANGE15/1.1.1.15/32 "
			"prefix=RANGE16/1.1.1.16/32 ");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool delete POOL2");

	/* One prefix too many */
	dpt_cgn_cmd_fmt(false, false,
			"nat-ut pool add POOL3 "
			"type=cgnat "
			"prefix=RANGE1/1.1.1.1/32 "
			"prefix=RANGE2/1.1.1.2/32 "
			"prefix=RANGE3/1.1.1.3/32 "
			"prefix=RANGE4/1.1.1.4/32 "
			"prefix=RANGE5/1.1.1.5/32 "
			"prefix=RANGE6/1.1.1.6/32 "
			"prefix=RANGE7/1.1.1.7/32 "
			"prefix=RANGE8/1.1.1.8/32 "
			"prefix=RANGE9/1.1.1.9/32 "
			"prefix=RANGE10/1.1.1.10/32 "
			"prefix=RANGE11/1.1.1.11/32 "
			"prefix=RANGE12/1.1.1.12/32 "
			"prefix=RANGE13/1.1.1.13/32 "
			"prefix=RANGE14/1.1.1.14/32 "
			"prefix=RANGE15/1.1.1.15/32 "
			"prefix=RANGE16/1.1.1.16/32 "
			"prefix=RANGE17/1.1.1.17/32 ");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool delete POOL3");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL4 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20");

	/* exp ok */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool update POOL4 "
			"max-blocks=3");

	/* exp ok */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool update POOL4 "
			"port-range=6000-7000");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool delete POOL4");

} DP_END_TEST;

/*
 * npf_cgnat_31 - CGNAT commands
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat31, NULL, NULL);
DP_START_TEST_FULL_RUN(cgnat31, test)
{
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real("dp2T1", real_ifname);

	/*
	 * CGNAT Policies
	 */
	dpt_cgn_cmd_fmt(false, true, "nat-ut pool add POOL1 type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20");

	dpt_addr_grp_create("MATCH1", "100.64.1.0/24");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy add POLICY1 "
			"match-ag=MATCH1 pool=POOL1 priority=30");

	dpt_addr_grp_create("MATCH2", "100.64.2.0/24");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy add POLICY2 "
			"match-ag=MATCH2 pool=POOL1 priority=10");

	dpt_addr_grp_create("MATCH3", "100.64.3.0/24");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy add POLICY3 "
			"match-ag=MATCH3 pool=POOL1 priority=20");

	dpt_addr_grp_create("MATCH4", "100.64.4.0/24");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy add POLICY4 "
			"match-ag=MATCH4 pool=POOL1 priority=40");

	/* First policy added to interface */
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy attach intf=%s "
			"name=POLICY1", real_ifname);

	/* 2nd policy.  */
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy attach intf=%s "
			"name=POLICY2", real_ifname);

	/* 3nd policy. */
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy attach intf=%s "
			"name=POLICY3", real_ifname);

	/* 4th policy. */
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy attach intf=%s "
			"name=POLICY4", real_ifname);


	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy detach name=POLICY1 "
			"intf=%s", real_ifname);
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy detach name=POLICY2 "
			"intf=%s", real_ifname);
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy detach name=POLICY3 "
			"intf=%s", real_ifname);
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy detach name=POLICY4 "
			"intf=%s", real_ifname);

	dpt_cgn_cmd_fmt(false, true, "cgn-ut max-sessions 1000000");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut max-dest-per-session 16");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut session-timeouts "
			"tcp-opening 55 udp-estab 600");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut session-timeouts "
			"tcp-opening %u udp-estab %u",
			CGN_DEF_ETIME_TCP_OPENING,
			CGN_DEF_ETIME_TCP_ESTBD);

	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy delete POLICY1");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy delete POLICY2");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy delete POLICY3");
	dpt_cgn_cmd_fmt(false, true, "cgn-ut policy delete POLICY4");
	dpt_cgn_cmd_fmt(false, true, "nat-ut pool delete POOL1");
	dpt_addr_grp_destroy("MATCH1", "100.64.1.0/24");
	dpt_addr_grp_destroy("MATCH2", "100.64.2.0/24");
	dpt_addr_grp_destroy("MATCH3", "100.64.3.0/24");
	dpt_addr_grp_destroy("MATCH4", "100.64.4.0/24");

} DP_END_TEST;


/*
 * npf_cgnat_32
 *
 * Tests CGNAT and SNAT on same interface
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat32, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat32, test)
{
	/*
	 * Add CGNAT config
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.1", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * Send some CGNAT traffic in both directions
	 *
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Add SNAT config
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.from_addr	= "100.64.0.2",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "1.1.1.21",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * Send some SNAT Traffic in both directions
	 *
	 * 100.64.0.2:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */

	/* Outbound packet matches SNAT rule and creates a session */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a2", 0,
		  "100.64.0.2", 0x3344, "1.1.1.2", 80,
		  "1.1.1.21", 0x3344, "1.1.1.2", 80,
		  "aa:bb:cc:dd:2:b2", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* Inbound pkt matches SNAT session, and is *not* dropped in CGNAT */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b2", 0,
		  "1.1.1.2", 80, "1.1.1.21", 0x3344,
		  "1.1.1.2", 80, "100.64.0.2", 0x3344,
		  "aa:bb:cc:dd:1:a2", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Repeat CGNAT Traffic in both directions
	 *
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);


	/*
	 * Cleanup
	 */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_32b
 *
 * Tests CGNAT and Stateful Firewall on same interface
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat32b, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat32b, test)
{
	/*
	 * Add CGNAT config
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.1", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * Send some CGNAT traffic in both directions
	 *
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Add stateful firewall config
	 */
	struct dp_test_npf_rule_t rset[] = {
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = true,
			.npf      = "proto-final=6 dst-port=179"
		},
		{
			.rule     = "10",
			.pass     = PASS,
			.stateful = true,
			.npf      = "proto-final=6 src-port=179"
		},
		NULL_RULE
	};

	struct dp_test_npf_ruleset_t fw = {
		.rstype = "fw-in",
		.name   = "IN_FW",
		.enable = 1,
		.attach_point   = "dp2T1",
		.fwd    = FWD,
		.dir    = "in",
		.rules  = rset
	};

	dp_test_npf_fw_add(&fw, false);

	/*
	 * Inbound pkt that does *not* match firewall rule is dropped by
	 * firewall.
	 */
	cgnat_tcp(TH_SYN, "dp2T1", "aa:bb:cc:dd:2:b2",
		  "1.1.1.30", 2345, "100.64.0.2", 3456,
		  "1.1.1.30", 2345, "100.64.0.2", 3456,
		  "aa:bb:cc:dd:1:a2", "dp1T0",
		  DP_TEST_FWD_DROPPED);

	/*
	 * Inbound pkt that matches stateful firewall rule is *not* dropped by
	 * CGNAT.  npf sets PKT_MDATA_SESSION in the packet meta-data, which
	 * is read by CGNAT.
	 */
	cgnat_tcp(TH_SYN, "dp2T1", "aa:bb:cc:dd:2:b2",
		  "1.1.1.30", 179, "100.64.0.2", 179,
		  "1.1.1.30", 179, "100.64.0.2", 179,
		  "aa:bb:cc:dd:1:a2", "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Repeat CGNAT Traffic
	 *
	 * Outbound packet.  Dropped.  Does not match firewall rule.
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_DROPPED);

	/*
	 * Inbound packet.  Does not match stateful firewall (UNMATCHED) so
	 * defaults to DROP.
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_DROPPED);

	/*
	 * Cleanup
	 */
	dp_test_npf_fw_del(&fw, false);
	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_32c
 *
 * Tests inbound traffic that does *not* match a CGNAT session, and whose
 * destination address is *not* covered by the CGNAT address pool.
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat32c, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat32c, test)
{
	/*
	 * Outside to Inside packet before cfg CGNAT is configured, where dest
	 * addr in *not* in CGNAT pool.
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 2345, "2.2.2.1", 179,
		  "1.1.1.1", 2345, "2.2.2.1", 179,
		  "aa:bb:cc:dd:1:a4", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Add CGNAT config
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.1", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * Send some CGNAT traffic in both directions
	 *
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Repeat outside to Inside packet where dest addr is *not* in CGNAT
	 * pool.
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 2345, "2.2.2.1", 179,
		  "1.1.1.1", 2345, "2.2.2.1", 179,
		  "aa:bb:cc:dd:1:a4", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Outside to Inside packet where dest addr *is* in CGNAT pool but a
	 * CGNAT session does not exist.
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.12", 2345,
		  "1.1.1.1", 80, "1.1.1.12", 2345,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_DROPPED);

	/*
	 * Cleanup
	 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_33
 *
 * Tests ICMP error messages with embedded UDP packets (incl cksum 0)
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat33, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat33, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * Inside to Outside  UDP packet, before
	 */
	struct dp_test_pkt_desc_t int_to_ext_pre = {
		.text       = "IPv4 Inside to Outside UDP pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "100.64.0.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "1.1.1.1",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 49152,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/*
	 * Inside to Outside UDP packet, after
	 */
	struct dp_test_pkt_desc_t int_to_ext_post = {
		.text       = "IPv4 Outside to Inside UDP post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "1.1.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 1024,
				.dport = 80
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};


	test_pak = dp_test_v4_pkt_from_desc(&int_to_ext_pre);
	exp_pak = dp_test_v4_pkt_from_desc(&int_to_ext_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &int_to_ext_post);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(test_pak, "dp1T0", test_exp);

	/*
	 * Outside to Inside UDP packet, before
	 */
	struct dp_test_pkt_desc_t ext_to_int_pre = {
		.text       = "IPv4 Outside to Inside UDP pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "1.1.1.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 1024
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	/*
	 * Outside to Inside UDP packet, after
	 */
	struct dp_test_pkt_desc_t ext_to_int_post = {
		.text       = "IPv4 Outside to Inside UDP post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "100.64.0.1",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_UDP,
		.l4         = {
			.udp = {
				.sport = 80,
				.dport = 49152
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};


	test_pak = dp_test_v4_pkt_from_desc(&ext_to_int_pre);
	exp_pak = dp_test_v4_pkt_from_desc(&ext_to_int_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &ext_to_int_post);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(test_pak, "dp2T1", test_exp);


	/*
	 * Send an ICMP error message inside-to-outside.
	 *
	 * Embedded packet is the UDP outside-to-inside pkt used earlier in
	 * this test.
	 */
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *payload_pak;
	struct icmphdr *icph;
	struct iphdr *ip;
	int icmplen;

	/* Create packet to be embedded in ICMP error message */
	payload_pak = dp_test_v4_pkt_from_desc(&ext_to_int_post);

	/* Create ICMP error message */
	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) +
		ext_to_int_post.len;

	icmp_pak = dp_test_create_icmp_ipv4_pak("100.64.0.1", "1.1.1.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	/* Init l2 header for ICMP error message */
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       "aa:bb:cc:dd:1:a1",
				       RTE_ETHER_TYPE_IPV4);

	/* Create expect */
	payload_pak = dp_test_v4_pkt_from_desc(&ext_to_int_pre);

	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) +
		ext_to_int_pre.len;

	test_pak = dp_test_create_icmp_ipv4_pak("1.1.1.11", "1.1.1.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	test_exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(test_exp, "dp2T1");
	rte_pktmbuf_free(test_pak);
	exp_pak = dp_test_exp_get_pak(test_exp);

	dp_test_ipv4_decrement_ttl(exp_pak);
	(void)dp_test_pktmbuf_eth_init(exp_pak, "aa:bb:cc:dd:2:b1",
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV4);

	/* Send ICMP error message */
	dp_test_pak_receive(icmp_pak, "dp1T0", test_exp);


	/*
	 * Send an ICMP error message outside-to-inside.
	 *
	 * Embedded packet is the outside version of the UDP inside-to-ouside
	 * pkt used earlier in this test.
	 */

	/* Create packet to be embedded in ICMP error message */
	payload_pak = dp_test_v4_pkt_from_desc(&int_to_ext_post);

	/* Create ICMP error message */
	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) +
		int_to_ext_post.len;

	icmp_pak = dp_test_create_icmp_ipv4_pak("1.1.1.1", "1.1.1.11",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	/* Init l2 header for ICMP error message */
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       dp_test_intf_name2mac_str("dp2T1"),
				       "aa:bb:cc:dd:2:b1",
				       RTE_ETHER_TYPE_IPV4);

	/* Create expect */
	payload_pak = dp_test_v4_pkt_from_desc(&int_to_ext_pre);

	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) +
		int_to_ext_pre.len;

	test_pak = dp_test_create_icmp_ipv4_pak("1.1.1.1", "100.64.0.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	test_exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	rte_pktmbuf_free(test_pak);
	exp_pak = dp_test_exp_get_pak(test_exp);

	dp_test_ipv4_decrement_ttl(exp_pak);
	(void)dp_test_pktmbuf_eth_init(exp_pak, "aa:bb:cc:dd:1:a1",
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV4);

	/* Send ICMP error message */
	dp_test_pak_receive(icmp_pak, "dp2T1", test_exp);


	/*
	 * Send an ICMP error message inside-to-outside.
	 *
	 * Embedded packet is the UDP outside-to-inside pkt used earlier in
	 * this test, but with a checksum of 0.
	 */
	struct udphdr *udp;

	/* Create packet to be embedded in ICMP error message */
	payload_pak = dp_test_v4_pkt_from_desc(&ext_to_int_post);
	udp = dp_pktmbuf_mtol4(payload_pak, struct udphdr *);
	udp->check = 0;

	/* Create ICMP error message */
	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) +
		ext_to_int_post.len;

	icmp_pak = dp_test_create_icmp_ipv4_pak("100.64.0.1", "1.1.1.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	/* Init l2 header for ICMP error message */
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       "aa:bb:cc:dd:1:a1",
				       RTE_ETHER_TYPE_IPV4);

	/* Create expect */
	payload_pak = dp_test_v4_pkt_from_desc(&ext_to_int_pre);
	udp = dp_pktmbuf_mtol4(payload_pak, struct udphdr *);
	udp->check = 0;

	icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) +
		ext_to_int_pre.len;

	test_pak = dp_test_create_icmp_ipv4_pak("1.1.1.11", "1.1.1.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	test_exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(test_exp, "dp2T1");
	rte_pktmbuf_free(test_pak);
	exp_pak = dp_test_exp_get_pak(test_exp);

	dp_test_ipv4_decrement_ttl(exp_pak);
	(void)dp_test_pktmbuf_eth_init(exp_pak, "aa:bb:cc:dd:2:b1",
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV4);

	/* Send ICMP error message */
	dp_test_pak_receive(icmp_pak, "dp1T0", test_exp);


	/*
	 * Cleanup
	 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;

#define ICMP_ERROR_MIN_L4_SIZE	8

/*
 * npf_cgnat_34
 *
 * Tests ICMP error messages with embedded TCP packets (including truncated)
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat34, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat34, test)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * Inside to Outside  TCP packet, before
	 */
	struct dp_test_pkt_desc_t int_to_ext_pre = {
		.text       = "IPv4 Inside to Outside UDP pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "100.64.0.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "1.1.1.1",
		.l2_dst     = "aa:bb:cc:dd:1:11",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 49152,
				.dport = 80,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/*
	 * Inside to Outside TCP packet, after
	 */
	struct dp_test_pkt_desc_t int_to_ext_post = {
		.text       = "IPv4 Outside to Inside TCP post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.11",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "1.1.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 1024,
				.dport = 80,
				.flags = TH_SYN,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};


	test_pak = dp_test_v4_pkt_from_desc(&int_to_ext_pre);
	exp_pak = dp_test_v4_pkt_from_desc(&int_to_ext_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &int_to_ext_post);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(test_pak, "dp1T0", test_exp);


	/*
	 * Outside to Inside TCP packet, before
	 */
	struct dp_test_pkt_desc_t ext_to_int_pre = {
		.text       = "IPv4 Outside to Inside TCP pre",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.1",
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = "1.1.1.11",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
				.dport = 1024,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	/*
	 * Outside to Inside TCP packet, after
	 */
	struct dp_test_pkt_desc_t ext_to_int_post = {
		.text       = "IPv4 Outside to Inside TCP post",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = "1.1.1.1",
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "100.64.0.1",
		.l2_dst     = "aa:bb:cc:dd:1:a1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = 80,
				.dport = 49152,
				.flags = TH_SYN | TH_ACK,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp2T1",
		.tx_intf    = "dp1T0"
	};

	test_pak = dp_test_v4_pkt_from_desc(&ext_to_int_pre);
	exp_pak = dp_test_v4_pkt_from_desc(&ext_to_int_post);
	test_exp = dp_test_exp_from_desc(exp_pak, &ext_to_int_post);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(test_pak, "dp2T1", test_exp);


	/*
	 * Send an ICMP error message inside-to-outside.
	 *
	 * Embedded packet is the TCP outside-to-inside pkt used earlier in
	 * this test.
	 */
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *payload_pak;
	struct icmphdr *icph;
	struct iphdr *ip;
	int icmplen;

	/* Create packet to be embedded in ICMP error message */
	payload_pak = dp_test_v4_pkt_from_desc(&ext_to_int_post);

	/* Create ICMP error message */
	icmplen = sizeof(struct iphdr) + sizeof(struct tcphdr) +
		ext_to_int_post.len;

	icmp_pak = dp_test_create_icmp_ipv4_pak("100.64.0.1", "1.1.1.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	/* Init l2 header for ICMP error message */
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       "aa:bb:cc:dd:1:a1",
				       RTE_ETHER_TYPE_IPV4);

	/* Create expect */
	payload_pak = dp_test_v4_pkt_from_desc(&ext_to_int_pre);

	icmplen = sizeof(struct iphdr) + sizeof(struct tcphdr) +
		ext_to_int_pre.len;

	test_pak = dp_test_create_icmp_ipv4_pak("1.1.1.11", "1.1.1.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	test_exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(test_exp, "dp2T1");
	rte_pktmbuf_free(test_pak);
	exp_pak = dp_test_exp_get_pak(test_exp);

	dp_test_ipv4_decrement_ttl(exp_pak);
	(void)dp_test_pktmbuf_eth_init(exp_pak, "aa:bb:cc:dd:2:b1",
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV4);

	/* Send ICMP error message */
	dp_test_pak_receive(icmp_pak, "dp1T0", test_exp);


	/*
	 * Send an ICMP error message outside-to-inside.
	 *
	 * Embedded packet is the outside version of the TCP inside-to-ouside
	 * pkt used earlier in this test.
	 */

	/* Create packet to be embedded in ICMP error message */
	payload_pak = dp_test_v4_pkt_from_desc(&int_to_ext_post);

	/* Create ICMP error message */
	icmplen = sizeof(struct iphdr) + sizeof(struct tcphdr) +
		int_to_ext_post.len;

	icmp_pak = dp_test_create_icmp_ipv4_pak("1.1.1.1", "1.1.1.11",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	/* Init l2 header for ICMP error message */
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       dp_test_intf_name2mac_str("dp2T1"),
				       "aa:bb:cc:dd:2:b1",
				       RTE_ETHER_TYPE_IPV4);

	/* Create expect */
	payload_pak = dp_test_v4_pkt_from_desc(&int_to_ext_pre);

	icmplen = sizeof(struct iphdr) + sizeof(struct tcphdr) +
		int_to_ext_pre.len;

	test_pak = dp_test_create_icmp_ipv4_pak("1.1.1.1", "100.64.0.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	test_exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(test_exp, "dp1T0");
	rte_pktmbuf_free(test_pak);
	exp_pak = dp_test_exp_get_pak(test_exp);

	dp_test_ipv4_decrement_ttl(exp_pak);
	(void)dp_test_pktmbuf_eth_init(exp_pak, "aa:bb:cc:dd:1:a1",
				       dp_test_intf_name2mac_str("dp1T0"),
				       RTE_ETHER_TYPE_IPV4);

	/* Send ICMP error message */
	dp_test_pak_receive(icmp_pak, "dp2T1", test_exp);


	/*
	 * Send an ICMP error message inside-to-outside.
	 *
	 * Embedded packet is a truncated version of the TCP outside-to-inside
	 * pkt used earlier in this test.
	 */

	/* Create packet to be embedded in ICMP error message */
	payload_pak = dp_test_v4_pkt_from_desc(&ext_to_int_post);

	/* Create ICMP error message  with truncated embedded pkt */
	icmplen = sizeof(struct iphdr) + ICMP_ERROR_MIN_L4_SIZE;
	icmp_pak = dp_test_create_icmp_ipv4_pak("100.64.0.1", "1.1.1.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	/* Init l2 header for ICMP error message */
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       dp_test_intf_name2mac_str("dp1T0"),
				       "aa:bb:cc:dd:1:a1",
				       RTE_ETHER_TYPE_IPV4);

	/* Create expect */
	payload_pak = dp_test_v4_pkt_from_desc(&ext_to_int_pre);

	icmplen = sizeof(struct iphdr) + ICMP_ERROR_MIN_L4_SIZE;
	test_pak = dp_test_create_icmp_ipv4_pak("1.1.1.11", "1.1.1.1",
						ICMP_DEST_UNREACH,
						ICMP_NET_UNREACH,
						DPT_ICMP_UNREACH_DATA(0),
						1, &icmplen,
						iphdr(payload_pak),
						&ip, &icph);

	/* No longer need payload pak */
	rte_pktmbuf_free(payload_pak);

	test_exp = dp_test_exp_create(test_pak);
	dp_test_exp_set_oif_name(test_exp, "dp2T1");
	rte_pktmbuf_free(test_pak);
	exp_pak = dp_test_exp_get_pak(test_exp);

	dp_test_ipv4_decrement_ttl(exp_pak);
	(void)dp_test_pktmbuf_eth_init(exp_pak, "aa:bb:cc:dd:2:b1",
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV4);

	/* Send ICMP error message */
	dp_test_pak_receive(icmp_pak, "dp1T0", test_exp);


	/*
	 * Cleanup
	 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");


} DP_END_TEST;


/*
 * Tests generation of an ICMP error message *after* CGNAT translation but
 * before transmission.
 *
 * We undo the *source* CGNAT translation, and send an
 * ICMP_DEST_UNREACH/FRAG_NEEDED message back to the sender.
 *
 *
 *                        +--------------+
 *                  dp3T3 |              | dp1T1
 * 2.2.2.1  --------------|              |--------------- 1.1.1.2
 *                2.2.2.2 |              | 1.1.1.1
 *                        +--------------+ mtu=1400
 *
 *            --------->
 * src 2.2.2.1 is translated to 3.3.3.1
 *
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat35, NULL, NULL);
DP_START_TEST_FULL_RUN(cgnat35, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *neigh3_mac_str = "aa:bb:cc:dd:ee:ff";
	const char *neigh1_mac_str = "bb:aa:cc:ee:dd:ff";
	struct iphdr *ip_inner;
	struct icmphdr *icph;
	struct iphdr *ip;
	int len = 1472;
	int icmplen;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1400);

	/* Add the nh arp we want the packet to follow */
	dp_test_netlink_add_neigh("dp3T3", "2.2.2.1", neigh3_mac_str);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);


	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE2/3.3.3.0/24 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "2.2.2.0/24", "POOL1",
			 "dp1T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/* Create UDP pak to match the route added above */
	test_pak = dp_test_create_ipv4_pak("2.2.2.1", "1.1.1.2",
					   1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp3T3"),
				       neigh3_mac_str, RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("2.2.2.2", "2.2.2.1",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						DPT_ICMP_FRAG_DATA(1400),
						1, &icmplen,
						iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh3_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	ip_inner = (struct iphdr *)(icph + 1);
	/*
	 * The TTL allowed to be changed from the original. From RFC
	 * 1812 s4.3.2.3:
	 *   The returned IP header (and user data) MUST be identical to
	 *   that which was received, except that the router is not
	 *   required to undo any modifications to the IP header that are
	 *   normally performed in forwarding that were performed before
	 *   the error was detected (e.g., decrementing the TTL, or
	 *   updating options)
	 */
	dp_test_set_pak_ip_field(ip_inner, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	dp_test_exp_set_oif_name(exp, "dp3T3");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp3T3", exp);

	/* Clean Up */
	cgnat_policy_del("POLICY1", 10, "dp1T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_netlink_del_neigh("dp3T3", "2.2.2.1", neigh3_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1500);

} DP_END_TEST;


/*
 * Tests generation of an ICMP error message *after* CGNAT translation but
 * before transmission.
 *
 * We undo the *destination* CGNAT translation, and send an
 * ICMP_DEST_UNREACH/FRAG_NEEDED message back to the sender.
 *
 *
 *                        +--------------+
 *                  dp3T3 |              | dp1T1
 * 2.2.2.1  --------------|              |--------------- 1.1.1.2
 *                2.2.2.2 |              | 1.1.1.1
 *                        +--------------+ mtu=1400
 *
 *                                   <---------
 *                          src 1.1.1.2 is translated to 3.3.3.1
 *
 *           >1400 --------->
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat36, NULL, NULL);
DP_START_TEST_FULL_RUN(cgnat36, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *icmp_pak;
	struct rte_mbuf *test_pak;
	const char *neigh3_mac_str = "aa:bb:cc:dd:ee:ff";
	const char *neigh1_mac_str = "bb:aa:cc:ee:dd:ff";
	struct iphdr *ip_inner;
	struct icmphdr *icph;
	struct iphdr *ip;
	int len = 1472;
	int icmplen;

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_add_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1400);

	/* Add the nh arp we want the packet to follow */
	dp_test_netlink_add_neigh("dp3T3", "2.2.2.1", neigh3_mac_str);
	dp_test_netlink_add_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE2/3.3.3.0/24 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "1.1.1.0/24", "POOL1",
			 "dp3T3", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/* Initial packet to create CGNAT session */
	cgnat_udp("dp1T1", neigh1_mac_str, 0,
		  "1.1.1.2", 21, "2.2.2.1", 21000,
		  "3.3.3.1", 1024, "2.2.2.1", 21000,
		  neigh3_mac_str, 0, "dp3T3",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Create UDP pak to match the CGNAT session reverse direction
	 */
	test_pak = dp_test_create_udp_ipv4_pak("2.2.2.1", "3.3.3.1",
					       21000, 1024,
					       1, &len);
	ip = iphdr(test_pak);
	dp_test_set_pak_ip_field(ip, DP_TEST_SET_DF, 1);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp3T3"),
				       neigh3_mac_str, RTE_ETHER_TYPE_IPV4);

	/*
	 * Expected packet
	 */
	/* Create expected icmp packet  */
	icmplen = sizeof(struct iphdr) + 576;
	icmp_pak = dp_test_create_icmp_ipv4_pak("2.2.2.2", "2.2.2.1",
						ICMP_DEST_UNREACH,
						ICMP_FRAG_NEEDED,
						DPT_ICMP_FRAG_DATA(1400),
						1, &icmplen,
						iphdr(test_pak),
						&ip, &icph);
	(void)dp_test_pktmbuf_eth_init(icmp_pak,
				       neigh3_mac_str,
				       dp_test_intf_name2mac_str("dp3T3"),
				       RTE_ETHER_TYPE_IPV4);

	dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
				 IPTOS_PREC_INTERNETCONTROL);

	ip_inner = (struct iphdr *)(icph + 1);
	/*
	 * The TTL allowed to be changed from the original. From RFC
	 * 1812 s4.3.2.3:
	 *   The returned IP header (and user data) MUST be identical to
	 *   that which was received, except that the router is not
	 *   required to undo any modifications to the IP header that are
	 *   normally performed in forwarding that were performed before
	 *   the error was detected (e.g., decrementing the TTL, or
	 *   updating options)
	 */
	dp_test_set_pak_ip_field(ip_inner, DP_TEST_SET_TTL,
				 DP_TEST_PAK_DEFAULT_TTL - 1);

	exp = dp_test_exp_create(icmp_pak);
	rte_pktmbuf_free(icmp_pak);

	dp_test_exp_set_oif_name(exp, "dp3T3");

	/* now send test pak and check we get expected back */
	dp_test_pak_receive(test_pak, "dp3T3", exp);

	/* Clean Up */
	cgnat_policy_del("POLICY1", 10, "dp3T3");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

	dp_test_netlink_del_neigh("dp3T3", "2.2.2.1", neigh3_mac_str);
	dp_test_netlink_del_neigh("dp1T1", "1.1.1.2", neigh1_mac_str);
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
	dp_test_nl_del_ip_addr_and_connected("dp3T3", "2.2.2.2/24");

	dp_test_netlink_set_interface_mtu("dp1T1", 1500);

} DP_END_TEST;


/*
 * npf_cgnat_37 -- Test that inbound traffic that matches an snat session but
 * not a cgnat session is *not* filtered by CGNAT.
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat37, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat37, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.1", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Add SNAT
	 */
	struct dp_test_npf_nat_rule_t snat = {
		.desc		= "snat rule",
		.rule		= "10",
		.ifname		= "dp2T1",
		.proto		= IPPROTO_UDP,
		.map		= "dynamic",
		.from_addr	= "100.64.0.2",
		.from_port	= NULL,
		.to_addr	= NULL,
		.to_port	= NULL,
		.trans_addr	= "1.1.1.21",
		.trans_port	= NULL
	};

	dp_test_npf_snat_add(&snat, true);

	/*
	 * Repeat CGNAT Traffic
	 *
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 1.1.1.1:80  -->  1.1.1.11:1024 / 100.64.0.1:49152
	 */
	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "1.1.1.1", 80, "1.1.1.11", 1024,
		  "1.1.1.1", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * SNAT Traffic
	 *
	 * 100.64.0.2:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a2", 0,
		  "100.64.0.2", 0x3344, "1.1.1.2", 80,
		  "1.1.1.21", 0x3344, "1.1.1.2", 80,
		  "aa:bb:cc:dd:2:b2", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b2", 0,
		  "1.1.1.2", 80, "1.1.1.21", 0x3344,
		  "1.1.1.2", 80, "100.64.0.2", 0x3344,
		  "aa:bb:cc:dd:1:a2", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Cleanup
	 */
	dp_test_npf_snat_del(snat.ifname, snat.rule, true);
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * npf_cgnat_38 - 20 UDP forwards pkts, different source addrs and ports
 *
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */

struct cgnat_test_vals {
	const char	*pre_addr;
	uint16_t	pre_port;
	const char	*post_addr;
	uint16_t	post_port;
};

DP_DECL_TEST_CASE(npf_cgnat, cgnat38, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat38, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.255.255.254 "
			"block-size=128 "
			"max-blocks=2"
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	uint i;

	struct cgnat_test_vals vals[] = {
		{"100.64.0.10", 3000, "1.1.1.11", 1024},
		{"100.64.0.4", 2043, "1.1.1.12", 1024},
		{"100.64.0.20", 6588, "1.1.1.13", 1024},
		{"100.64.0.6", 1933, "1.1.1.14", 1024},
		{"100.64.0.18", 6828, "1.1.1.15", 1024},
		{"100.64.0.6", 1622, "1.1.1.14", 1025},
		{"100.64.0.6", 3554, "1.1.1.14", 1026},
		{"100.64.0.18", 6828, "1.1.1.15", 1024},
		{"100.64.0.18", 6555, "1.1.1.15", 1025},
		{"100.64.0.4", 1643, "1.1.1.12", 1025},
	};

	for (i = 0; i < ARRAY_SIZE(vals); i++) {

		cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
			  vals[i].pre_addr, vals[i].pre_port,
			  "1.1.1.1", 80,
			  vals[i].post_addr, vals[i].post_port,
			  "1.1.1.1", 80,
			  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
			  DP_TEST_FWD_FORWARDED);
	}

	/* Will cause sessions to be added to session list */
	cgn_session_gc_pass();

	/*
	 * Tack on a "clear session" test
	 */
	dp_test_npf_cmd_fmt(false,
			    "cgn-op clear session pool POOL1");

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");


} DP_END_TEST;


/*
 * npf_cgnat_39 - 1 UDP forwards pkt.  Sends 4 fragments, and verifies
 * re-assembled and translated packet.
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat39, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat39, test)
{
	/*
	 * pool add POOL1
	 *   address-range=RANGE1/1.1.1.11-1.1.1.20
	 *   prefix=RANGE2/1.1.1.192/26
	 *   port-range=4096-65535
	 *   port-alloc=sequential
	 *   block-size=512
	 *   max-blocks=8
	 *   add-pooling=paired
	 *   addr-alloc=round-robin
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	const char *rx_intf = "dp1T0";
	const char *pre_smac = "aa:bb:cc:dd:1:a1";
	const char *pre_saddr = "100.64.0.1";
	uint16_t pre_sport = 49152;
	const char *pre_daddr = "1.1.1.1";
	uint16_t pre_dport = 80;
	const char *post_saddr = "1.1.1.11";
	uint16_t post_sport = 1024;
	const char *post_daddr = "1.1.1.1";
	uint16_t post_dport = 80;
	const char *post_dmac = "aa:bb:cc:dd:2:b1";
	const char *tx_intf = "dp2T1";

	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;
	int len = 1200;

	/* Pre IPv4 UDP packet */
	struct dp_test_pkt_desc_t pre_pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = len,
		.ether_type = RTE_ETHER_TYPE_IPV4,
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
		.len        = len,
		.ether_type = RTE_ETHER_TYPE_IPV4,
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

	/* Fragment test pak */
	struct rte_mbuf *frag_pkts[4] =  { 0 };
	uint16_t frag_sizes[4] = { 400, 400, 400, 8 };
	int rc;

	rc = dp_test_ipv4_fragment_packet(test_pak, frag_pkts,
					  ARRAY_SIZE(frag_pkts),
					  frag_sizes, 0);
	dp_test_fail_unless(rc == ARRAY_SIZE(frag_pkts),
			    "dp_test_ipv4_fragment_packet failed: %d", rc);
	rte_pktmbuf_free(test_pak);

	/* 1st fragment */
	test_pak = frag_pkts[0];

	/* Doesn't matter what exp pkt is created ... it will be 'dropped' */
	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);
	rte_pktmbuf_free(exp_pak);

	dp_test_pak_receive(test_pak, rx_intf, test_exp);

	/* 2nd fragment */
	test_pak = frag_pkts[1];

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);
	rte_pktmbuf_free(exp_pak);

	dp_test_pak_receive(test_pak, rx_intf, test_exp);

	/* 3rd fragment */
	test_pak = frag_pkts[2];

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_DROPPED);
	rte_pktmbuf_free(exp_pak);

	dp_test_pak_receive(test_pak, rx_intf, test_exp);

	/* Last fragment */
	test_pak = frag_pkts[3];

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);
	rte_pktmbuf_free(exp_pak);

	dp_test_pak_receive(test_pak, rx_intf, test_exp);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * cgnat40 -- Split TCP header over two chained mbufs
 *
 * First test packet has all the l3 and l4 header in the first mbuf, and all
 * the payload in the second mbuf.
 *
 * Test is repeated 20 times (size of TCP hdr).  Each time round the loop one
 * more byte from the end of the first mbuf is prepended to the start of the
 * second mbuf.
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat40, cgnat_setup, cgnat_teardown);
DP_START_TEST_FULL_RUN(cgnat40, test)
{

	struct rte_mbuf *test_pak, *exp_pak;
	struct dp_test_expected *exp;
	int len[2] = { 0, 20 };
	uint copy_bytes;
	uint copy_max = 20; /* size of TCP header */

	dp_test_npf_cmd_fmt(false,
			    "nat-ut pool add POOL1 "
			    "type=cgnat "
			    "address-range=RANGE1/1.1.1.13-1.1.1.13");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/24", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, false, true);

	for (copy_bytes = 0; copy_bytes < copy_max; copy_bytes++) {

		test_pak = dp_test_create_tcp_ipv4_pak(
			"100.64.0.1", "1.1.1.1", 0x123, 80, TH_SYN,
			0, 0, 5840, NULL, 2, len);

		dp_test_pktmbuf_eth_init(test_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 "aa:bb:cc:dd:1:a1",
					 RTE_ETHER_TYPE_IPV4);

		exp_pak = dp_test_create_tcp_ipv4_pak(
			"1.1.1.13", "1.1.1.1", 1024, 80, TH_SYN,
			0, 0, 5840, NULL, 2, len);

		dp_test_pktmbuf_eth_init(exp_pak,
					 dp_test_intf_name2mac_str("dp1T0"),
					 "aa:bb:cc:dd:1:a1",
					 RTE_ETHER_TYPE_IPV4);

		exp = dp_test_exp_create(exp_pak);
		rte_pktmbuf_free(exp_pak);

		dp_test_exp_set_oif_name(exp, "dp2T1");

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(exp), "aa:bb:cc:dd:2:b1",
			dp_test_intf_name2mac_str("dp2T1"),
			RTE_ETHER_TYPE_IPV4);

		dp_test_ipv4_decrement_ttl(dp_test_exp_get_pak(exp));

		struct rte_mbuf *m = test_pak;
		uint i;
		char *src, *dst;

		/* Copy part of header to second buffer */

		/* assert that src has at least this many bytes */
		assert(copy_bytes < m->data_len);
		src = rte_pktmbuf_mtod(m, char *) + m->data_len - copy_bytes;

		/* assert that dst has at least this much headroom */
		assert(copy_bytes < rte_pktmbuf_headroom(m->next));
		dst = rte_pktmbuf_prepend(m->next, copy_bytes);

		for (i = 0; i < copy_bytes; i++)
			dst[i] = src[i];

		m->data_len -= copy_bytes;

		/* Run the test */
		dp_test_pak_receive(test_pak, "dp1T0", exp);
	}

	cgnat_policy_del("POLICY1", 10, "dp2T1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * cgnat41 -- Tests cgnat show command
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat41, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat41, test)
{
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real("dp2T1", real_ifname);

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=PFX1/1.0.0.0/8 "
			"block-size=4096 "
			"max-blocks=32 "
			"addr-pooling=arbitrary "
			"log-pba=no");

	cgnat_policy_add("POLICY1", 10, "2.0.0.0/8", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);


	static char subs_str[20];
	uint32_t subs_addr;
	uint16_t subs_port;
	bool sequential = true;

	/* Initial addr and port */
	if (sequential) {
		subs_addr = dpt_init_ipaddr(subs_str, "2.0.0.1");
		subs_port = 1024;
	} else {
		/* Random */
		subs_port = random() % 65536;
		subs_addr = dpt_random_ipaddr(0x02000000, 0x00ffffff,
					      subs_str, sizeof(subs_str));
	}

	/*
	 * The inner loop adds sessions by varying the subscriber port.
	 * The outer loop varies the subscriber address.
	 */

	/* The subscriber address is changed for each repeat */
	uint repeat_count = 5;

	/* Number of sessions per repeat */
	uint nsessions_per_repeat = 5;

	uint nrepeats = repeat_count;
	int count;
	uint i;

repeat:
	for (i = 0; i < nsessions_per_repeat; i++) {

		dpt_cgn_map(false, real_ifname, 12000, 17, subs_str, subs_port,
			    NULL, NULL);

		if (sequential) {
			/* Sequential  */
			if (++subs_port == 65535) {
				subs_port = 1024;
				subs_addr = dpt_incr_ipaddr(subs_addr,
							    subs_str,
							    sizeof(subs_str));
			}
		} else
			/* Random subscriber port */
			subs_port = random() % 65536;
	}

	/* Change subscriber address every repeat */
	if (sequential) {
		subs_addr = dpt_incr_ipaddr(subs_addr, subs_str,
					    sizeof(subs_str));
		subs_port = 1024;
	} else {
		subs_addr = dpt_random_ipaddr(0x02000000, 0x00ffffff,
					      subs_str, sizeof(subs_str));
	}

	if (--nrepeats > 0)
		goto repeat;

	/*
	 * Fetch the sessions
	 */
	count = dpt_cgn_show_session(NULL,
				     nsessions_per_repeat * repeat_count,
				     false, false, false);

	dp_test_fail_unless((uint)count == nsessions_per_repeat * repeat_count,
			    "%u sessions in show output, %u expected",
			    count, nsessions_per_repeat * repeat_count);

	/*
	 * Fetch the sessions in per-subscriber batches
	 */
	count = dpt_cgn_show_session(NULL, 1000, true, false, false);

	dp_test_fail_unless((uint)count == nsessions_per_repeat * repeat_count,
			    "%u sessions in show output, %u expected",
			    count, nsessions_per_repeat * repeat_count);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;


/*
 * cgnat42 -- cgnat scale test
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat42, cgnat_setup, cgnat_teardown);
DP_START_TEST_DONT_RUN(cgnat42, test)
{
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real("dp2T1", real_ifname);

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=PFX1/1.0.0.0/8 "
			"block-size=4096 "
			"max-blocks=32 "
			"addr-pooling=arbitrary "
			"log-pba=no");

	cgnat_policy_add("POLICY1", 10, "2.0.0.0/8", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);


	static char subs_str[20];
	uint32_t subs_addr;
	uint16_t subs_port;
	bool sequential = true;

	/* Initial addr and port */
	if (sequential) {
		subs_addr = dpt_init_ipaddr(subs_str, "2.0.0.1");
		subs_port = 1024;
	} else {
		/* Random */
		subs_port = random() % 65536;
		subs_addr = dpt_random_ipaddr(0x02000000, 0x00ffffff,
					      subs_str, sizeof(subs_str));
	}

	/*
	 * The inner loop adds sessions by varying the subscriber port.
	 * The outer loop varies the subscriber address.
	 */

	/* The subscriber address is changed for each repeat */
	uint repeat_count = 1000;

	/* Number of sessions per repeat */
	uint nsessions_per_repeat = 500;

	uint nrepeats = repeat_count;
	uint64_t ms1, ms2;
	int count;
	uint i;

	ms1 = time_ms();

repeat:
	for (i = 0; i < nsessions_per_repeat; i++) {

		dpt_cgn_map(false, real_ifname, 12000, 17, subs_str, subs_port,
			    NULL, NULL);

		if (sequential) {
			/* Sequential  */
			if (++subs_port == 65535) {
				subs_port = 1024;
				subs_addr = dpt_incr_ipaddr(subs_addr,
							    subs_str,
							    sizeof(subs_str));
			}
		} else
			/* Random subscriber port */
			subs_port = random() % 65536;
	}

	/* Change subscriber address every repeat */
	if (sequential) {
		subs_addr = dpt_incr_ipaddr(subs_addr, subs_str,
					    sizeof(subs_str));
		subs_port = 1024;
	} else {
		subs_addr = dpt_random_ipaddr(0x02000000, 0x00ffffff,
					      subs_str, sizeof(subs_str));
	}

	if (--nrepeats > 0)
		goto repeat;

	/* Check the session creation did not take too long */
	ms2 = time_ms();

	dp_test_fail_unless(
		ms2 - ms1 < nsessions_per_repeat * repeat_count * 10,
		"%lu mS to create %u sessions",
		ms2 - ms1, nsessions_per_repeat * repeat_count);

	/*
	 * Fetch the sessions in batches of 1000 at a time
	 */
	ms1 = time_ms();
	count = dpt_cgn_show_session(NULL, 1000, false, false, false);
	ms2 = time_ms();

	dp_test_fail_unless((uint)count == nsessions_per_repeat * repeat_count,
			    "%u sessions in show output, %u expected",
			    count, nsessions_per_repeat * repeat_count);

	dp_test_fail_unless(
		ms2 - ms1 < (nsessions_per_repeat * repeat_count) / 20,
		"%lu mS to return json for %u sessions",
		ms2 - ms1, nsessions_per_repeat * repeat_count);

	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;

static inline uint64_t cgn_time_nsecs(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (ts.tv_sec * 1000000000) + ts.tv_nsec;
}

/*
 * cgnat43 -- More cgnat scale tests
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat43, cgnat_setup, cgnat_teardown);
DP_START_TEST_DONT_RUN(cgnat43, test)
{
	char real_ifname[IFNAMSIZ];

	/*
	 * Setup
	 */
	dp_test_intf_real("dp2T1", real_ifname);
	struct ifnet *ifp = dp_ifnet_byifname(real_ifname);

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE1/1.1.1.192/26 "
			"block-size=4096 "
			"max-blocks=32 "
			"addr-pooling=arbitrary "
			"log-pba=no");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/24", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	cgnat_policy_add("POLICY2", 20, "100.64.1.0/24", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_5TUPLE, true);


	uint i, j, outer_count, inner_count;
	uint64_t nsecs1, nsecs2, elapsed;	/* nanosecs */
	uint64_t average;			/* nanosecs */
	uint64_t overhead;

	static char subs_str[20];
	uint32_t subs_addr;
	uint16_t subs_port;
	int rc, error;
	bool rv;

	/*******************************************************************
	 * Get execution time of gettimeofday()
	 */

	outer_count = 1;
	inner_count = 50000;
	overhead = 0;

	printf("\n");
	printf("Test 1: (%u x %u) gettimeofday()\n",
	       outer_count, inner_count);

loop1:
	nsecs1 = cgn_time_nsecs();
	for (i = 0; i < outer_count; i++) {
		for (j = 0; j < inner_count; j++) {
			if (overhead > 0)
				/* Do task */
				cgn_time_usecs();
		}
	}
	nsecs2 = cgn_time_nsecs();
	elapsed = nsecs2 - nsecs1;
	if (overhead == 0) {
		overhead = elapsed;
		goto loop1;
	}
	if (overhead <= elapsed)
		elapsed -= overhead;
	else
		elapsed = 0;
	average = elapsed / (i * j);
	printf("  Time %lu nS, average %lu nS\n", elapsed, average);


	/*******************************************************************
	 * Create 3-tuple session
	 */

	outer_count = 1;
	inner_count = 50000;
	overhead = 0;

	subs_addr = dpt_init_ipaddr(subs_str, "100.64.0.1");
	subs_port = 1024;

	/* Initial session to create subscriber and apm structs */
	rc = dpt_cgn_map2(ifp, 12000, 17, subs_addr, subs_port++, NULL, NULL);
	dp_test_fail_unless(rc == 0, "dpt_cgn_map2 failed");

	printf("\n");
	printf("Test 2: (%u x %u) Create 3-tuple session\n",
	       outer_count, inner_count);

loop2:
	nsecs1 = cgn_time_nsecs();
	for (i = 0; i < outer_count; i++) {
		for (j = 0; j < inner_count; j++) {
			if (overhead > 0) {
				/* Do task */
				rc = dpt_cgn_map2(ifp, 12000, 17,
						  subs_addr, subs_port,
						  NULL, NULL);
				if (rc < 0)
					goto end2;

				if (++subs_port == 65535) {
					subs_port = 1024;
					subs_addr = dpt_incr_ipaddr(
						subs_addr, subs_str,
						sizeof(subs_str));
				}
			}
		}
		/* Change subs_addr if >1 */
		assert(outer_count == 1);
	}
end2:
	nsecs2 = cgn_time_nsecs();
	elapsed = nsecs2 - nsecs1;
	if (overhead == 0) {
		overhead = elapsed;
		goto loop2;
	}
	if (overhead <= elapsed)
		elapsed -= overhead;
	else
		elapsed = 0;
	average = elapsed / (i * j);
	printf("  Time %lu nS, average %lu nS\n", elapsed, average);

	cgn_session_cleanup();


	/*******************************************************************
	 * Create 5-tuple session
	 */

	outer_count = 1;
	inner_count = 50000;
	overhead = 0;

	subs_addr = dpt_init_ipaddr(subs_str, "100.64.1.1");
	subs_port = 1024;

	/* Initial session to create subscriber and apm structs */
	rc = dpt_cgn_map2(ifp, 12000, 17, subs_addr, subs_port++, NULL, NULL);
	dp_test_fail_unless(rc == 0, "dpt_cgn_map2 failed");

	printf("\n");
	printf("Test 3: (%u x %u) Create 5-tuple session\n",
	       outer_count, inner_count);

loop3:
	nsecs1 = cgn_time_nsecs();
	for (i = 0; i < outer_count; i++) {
		for (j = 0; j < inner_count; j++) {
			if (overhead > 0) {
				/* Do task */
				rc = dpt_cgn_map2(ifp, 12000, 17,
						  subs_addr, subs_port,
						  NULL, NULL);
				if (rc < 0)
					goto end3;

				if (++subs_port == 65535) {
					subs_port = 1024;
					subs_addr = dpt_incr_ipaddr(
						subs_addr, subs_str,
						sizeof(subs_str));
				}
			}
		}
		/* Change subs_addr if >1 */
		assert(outer_count == 1);
	}
end3:
	nsecs2 = cgn_time_nsecs();
	elapsed = nsecs2 - nsecs1;
	if (overhead == 0) {
		overhead = elapsed;
		goto loop3;
	}
	if (overhead <= elapsed)
		elapsed -= overhead;
	else
		elapsed = 0;
	average = elapsed / (i * j);
	printf("  Time %lu nS, average %lu nS\n", elapsed, average);

	cgn_session_cleanup();


	/*******************************************************************
	 * Translate packet, 3-tuple session
	 */

	outer_count = 1;
	inner_count = 50000;
	overhead = 0;

	subs_addr = dpt_init_ipaddr(subs_str, "100.64.0.1");
	subs_port = 1024;

	struct dp_test_pkt_desc_t ins_pre = {
		.text       = "Inside pre",
		.len	    = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = subs_str,
		.l2_src     = "aa:bb:cc:dd:1:a1",
		.l3_dst     = "1.1.1.1",
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4	 = {
			.tcp = {
				.sport = subs_port,
				.dport = 80,
				.flags = TH_ACK,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = "dp1T0",
		.tx_intf    = "dp2T1"
	};

	/* Initial session to create subscriber and apm structs */
	dpt_cgn_map2(ifp, 12000, 6, subs_addr, subs_port, NULL, NULL);

	struct rte_mbuf *orig_mbuf = dp_test_v4_pkt_from_desc(&ins_pre);

	printf("\n");
	printf("Test 4: (%u x %u) Translate packet, 3-tuple session\n",
	       outer_count, inner_count);

loop4:
	nsecs1 = cgn_time_nsecs();
	for (i = 0; i < outer_count; i++) {
		for (j = 0; j < inner_count; j++) {
			struct rte_mbuf *mbuf;

			mbuf = pktmbuf_copy(orig_mbuf, orig_mbuf->pool);
			rv = true;
			error = 0;

			if (overhead > 0)
				/* Do task */
				rv = ipv4_cgnat_test(&mbuf, ifp,
						     CGN_DIR_OUT, &error);

			rte_pktmbuf_free(mbuf);
			if (!rv || error < 0)
				goto end4;
		}
	}
end4:
	rte_pktmbuf_free(orig_mbuf);
	nsecs2 = cgn_time_nsecs();
	elapsed = nsecs2 - nsecs1;
	if (overhead == 0) {
		overhead = elapsed;
		goto loop4;
	}
	if (overhead <= elapsed)
		elapsed -= overhead;
	else
		elapsed = 0;
	average = elapsed / (i * j);
	printf("  Time %lu nS, average %lu nS\n", elapsed, average);

	cgn_session_cleanup();


	/*******************************************************************
	 * Translate packet, 5-tuple session
	 */

	outer_count = 1;
	inner_count = 50000;
	overhead = 0;

	subs_addr = dpt_init_ipaddr(subs_str, "100.64.1.1");
	subs_port = 1024;
	ins_pre.l3_src = subs_str;
	ins_pre.l4.tcp.sport = subs_port;

	/* Initial session to create subscriber and apm structs */
	dpt_cgn_map2(ifp, 12000, 6, subs_addr, subs_port, NULL, NULL);

	orig_mbuf = dp_test_v4_pkt_from_desc(&ins_pre);

	printf("\n");
	printf("Test 5: (%u x %u) Translate packet, 5-tuple session\n",
	       outer_count, inner_count);

loop5:
	nsecs1 = cgn_time_nsecs();
	for (i = 0; i < outer_count; i++) {
		for (j = 0; j < inner_count; j++) {
			struct rte_mbuf *mbuf;

			mbuf = pktmbuf_copy(orig_mbuf, orig_mbuf->pool);
			rv = true;
			error = 0;

			if (overhead > 0)
				/* Do task */
				rv = ipv4_cgnat_test(&mbuf, ifp,
						     CGN_DIR_OUT, &error);

			rte_pktmbuf_free(mbuf);
			if (!rv || error < 0)
				goto end5;
		}
	}
end5:
	rte_pktmbuf_free(orig_mbuf);
	nsecs2 = cgn_time_nsecs();
	elapsed = nsecs2 - nsecs1;
	if (overhead == 0) {
		overhead = elapsed;
		goto loop5;
	}
	if (overhead <= elapsed)
		elapsed -= overhead;
	else
		elapsed = 0;
	average = elapsed / (i * j);
	printf("  Time %lu nS, average %lu nS\n", elapsed, average);

	cgn_session_cleanup();


	/*******************************************************************
	 * Translate packet, new 3-tuple session per packet
	 */

	outer_count = 1;
	inner_count = 50000;
	overhead = 0;

	subs_addr = dpt_init_ipaddr(subs_str, "100.64.0.1");
	subs_port = 1024;
	ins_pre.l3_src = subs_str;
	ins_pre.l4.tcp.sport = subs_port;

	/* Initial session to create subscriber and apm structs */
	dpt_cgn_map2(ifp, 12000, 6, subs_addr, subs_port++, NULL, NULL);

	printf("\n");
	printf("Test 6: (%u x %u) Translate packet, "
	       "new 3-tuple session per pkt\n",
	       outer_count, inner_count);

loop6:
	nsecs1 = cgn_time_nsecs();
	for (i = 0; i < outer_count; i++) {
		for (j = 0; j < inner_count; j++) {
			struct rte_mbuf *mbuf;

			ins_pre.l3_src = subs_str;
			ins_pre.l4.tcp.sport = subs_port++;
			mbuf = dp_test_v4_pkt_from_desc(&ins_pre);

			rv = true;
			error = 0;

			if (overhead > 0)
				/* Do task */
				rv = ipv4_cgnat_test(&mbuf, ifp,
						     CGN_DIR_OUT, &error);

			rte_pktmbuf_free(mbuf);
			if (!rv || error < 0)
				goto end6;
		}
	}
end6:
	nsecs2 = cgn_time_nsecs();
	elapsed = nsecs2 - nsecs1;
	if (overhead == 0) {
		overhead = elapsed;
		goto loop6;
	}
	if (overhead <= elapsed)
		elapsed -= overhead;
	else
		elapsed = 0;
	average = elapsed / (i * j);
	printf("  Time %lu nS, average %lu nS\n", elapsed, average);

	cgn_session_cleanup();


	/*******************************************************************
	 * Translate packet, new 5-tuple session per packet
	 */

	outer_count = 1;
	inner_count = 50000;
	overhead = 0;

	subs_addr = dpt_init_ipaddr(subs_str, "100.64.1.1");
	subs_port = 1024;
	ins_pre.l3_src = subs_str;
	ins_pre.l4.tcp.sport = subs_port;

	/* Initial session to create subscriber and apm structs */
	dpt_cgn_map2(ifp, 12000, 6, subs_addr, subs_port++, NULL, NULL);

	printf("\n");
	printf("Test 7: (%u x %u) Translate packet, "
	       "new 5-tuple session per pkt\n",
	       outer_count, inner_count);

loop7:
	nsecs1 = cgn_time_nsecs();
	for (i = 0; i < outer_count; i++) {
		for (j = 0; j < inner_count; j++) {
			struct rte_mbuf *mbuf;

			ins_pre.l3_src = subs_str;
			ins_pre.l4.tcp.sport = subs_port++;
			mbuf = dp_test_v4_pkt_from_desc(&ins_pre);

			rv = true;
			error = 0;

			if (overhead > 0)
				/* Do task */
				rv = ipv4_cgnat_test(&mbuf, ifp,
						     CGN_DIR_OUT, &error);

			rte_pktmbuf_free(mbuf);
			if (!rv || error < 0)
				goto end7;
		}
	}
end7:
	nsecs2 = cgn_time_nsecs();
	elapsed = nsecs2 - nsecs1;
	if (overhead == 0) {
		overhead = elapsed;
		goto loop7;
	}
	if (overhead <= elapsed)
		elapsed -= overhead;
	else
		elapsed = 0;
	average = elapsed / (i * j);
	printf("  Time %lu nS, average %lu nS\n", elapsed, average);

	cgn_session_cleanup();

	/*
	 * Cleanup
	 */
	printf("\n");
	cgnat_policy_del("POLICY1", 10, "dp2T1");
	cgnat_policy_del("POLICY2", 20, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST;

/*
 * cgnat45 -- cgnat map command (for pcp)
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat45, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat45, test)
{
	char real_ifname[IFNAMSIZ];
	int rc;
	uint i;

	dp_test_intf_real("dp2T1", real_ifname);

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"block-size=4096 "
			"max-blocks=32 "
			"addr-pooling=arbitrary "
			"log-pba=no");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);


	static char subs_str[20];
	uint32_t subs_addr;
	uint16_t subs_port;
	char pub_str[20];
	int pub_port = 0;
	bool debug = false;

	/* Subscriber addr and port */
	subs_addr = dpt_init_ipaddr(subs_str, "100.64.0.1");
	subs_port = 1024;
	dp_test_fail_unless(subs_addr, "subs_addr");

	/**************************************************************
	 * Let dataplane assign mapping
	 */
	dpt_init_ipaddr(pub_str, "0.0.0.0");
	pub_port = 0;

	if (debug)
		printf("Let dataplane assign mapping ...\n");

	rc = dpt_cgn_map(debug, real_ifname, 12000, 17, subs_str, subs_port,
			 pub_str, &pub_port);
	dp_test_fail_unless(rc == 0, "map command");

	dp_test_fail_unless(pub_port == 1024,
			    "Public port %d, expected 1024", pub_port);
	dp_test_fail_unless(!strcmp(pub_str, "1.1.1.11"),
			    "Public address %s, expected 1.1.1.11", pub_str);

	/**************************************************************
	 * Request a specific mapping
	 */
	subs_addr = dpt_init_ipaddr(subs_str, "100.64.0.2");
	subs_port = 1234;
	dp_test_fail_unless(subs_addr, "subs_addr");

	dpt_init_ipaddr(pub_str, "1.1.1.15");
	pub_port = 2000;

	if (debug)
		printf("Request mapping %s port %d\n", pub_str, pub_port);

	rc = dpt_cgn_map(debug, real_ifname, 12000, 17, subs_str, subs_port,
			 pub_str, &pub_port);
	dp_test_fail_unless(rc == 0, "map command rc=%d", -rc);

	dp_test_fail_unless(pub_port == 2000,
			    "Public port %d, expected 2000", pub_port);
	dp_test_fail_unless(!strcmp(pub_str, "1.1.1.15"),
			    "Public address %s, expected 1.1.1.15", pub_str);


	/**************************************************************
	 * Refresh an existing mapping
	 */
	subs_addr = dpt_init_ipaddr(subs_str, "100.64.0.2");
	subs_port = 1234;
	dp_test_fail_unless(subs_addr, "subs_addr");

	dpt_init_ipaddr(pub_str, "1.1.1.15");
	pub_port = 2000;

	if (debug)
		printf("Refresh an existing mapping %s port %d\n",
		       pub_str, pub_port);

	rc = dpt_cgn_map(debug, real_ifname, 12000, 17, subs_str, subs_port,
			 pub_str, &pub_port);
	dp_test_fail_unless(rc == 0, "map command rc=%d", -rc);

	dp_test_fail_unless(pub_port == 2000,
			    "Public port %d, expected 2000", pub_port);
	dp_test_fail_unless(!strcmp(pub_str, "1.1.1.15"),
			    "Public address %s, expected 1.1.1.15", pub_str);

	/**************************************************************
	 * Change policy to be 5-tuple (log-all) then create a mapping
	 */
	cgnat_policy_change("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			    CGN_MAP_EIM, CGN_FLTR_EIF, CGN_5TUPLE, true);

	subs_addr = dpt_init_ipaddr(subs_str, "100.64.0.3");
	subs_port = 22;
	dp_test_fail_unless(subs_addr, "subs_addr");

	dpt_init_ipaddr(pub_str, "1.1.1.16");
	pub_port = 1024;

	if (debug)
		printf("Request mapping %s port %d\n", pub_str, pub_port);

	rc = dpt_cgn_map(false, real_ifname, 12000, 17, subs_str, subs_port,
			 pub_str, &pub_port);

	dp_test_fail_unless(rc == 0, "map command rc=%d", -rc);

	dp_test_fail_unless(pub_port == 1024,
			    "Public port %d, expected 1024", pub_port);
	dp_test_fail_unless(!strcmp(pub_str, "1.1.1.16"),
			    "Public address %s, expected 1.1.1.16", pub_str);

	if (debug) {
		dpt_cgn_show_session("subs-addr 100.64.0.3", 0,
				     false, true, true);

		dp_test_npf_cmd_fmt(false, "cgn-op update session");
		dp_test_npf_cmd_fmt(false, "cgn-op update subscriber");

		for (i = 0; i < CGN_SESS_GC_COUNT + 1; i++)
			dp_test_npf_cmd_fmt(false, "cgn-op ut gc");

		dpt_cgn_show_session("subs-addr 100.64.0.3", 0,
				     false, true, true);

		dpt_cgn_show_summary(true);
	}

	/**************************************************************
	 * Send a packet matching the above 3-tuple session
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.3", 22, "1.1.1.1", 38,
		  "1.1.1.16", 1024, "1.1.1.1", 38,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	if (debug) {
		dp_test_npf_cmd_fmt(false, "cgn-op update session");
		dp_test_npf_cmd_fmt(false, "cgn-op update subscriber");

		dpt_cgn_show_session("subs-addr 100.64.0.3", 0,
				     false, true, true);
	}

	/****************************************************************
	 * Cleanup cgnat45
	 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST; /* cgnat45 */

/*
 * cgnat46 - Verify CGNAT responds to echo request sent to CGNAT pool address
 * on the outside interface.
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat46, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat46, test)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *test_pak, *exp_pak;
	int payload_len = 40;

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * Send ICMP Echo Request to the outside interface dp2T1 with dest
	 * addr set to CGNAT pool address, and check for reply.
	 */
	test_pak = dp_test_create_icmp_ipv4_pak("1.1.1.1",
						"1.1.1.11",
						ICMP_ECHO /* echo request */,
						0 /* no code */,
						DPT_ICMP_ECHO_DATA(0, 0),
						1 /* one mbuf */,
						&payload_len,
						NULL, NULL, NULL);

	(void)dp_test_pktmbuf_eth_init(test_pak,
				       dp_test_intf_name2mac_str("dp2T1"),
				       "aa:bb:cc:dd:2:b1",
				       RTE_ETHER_TYPE_IPV4);

	exp_pak = dp_test_create_icmp_ipv4_pak("1.1.1.11",
					       "1.1.1.1",
						ICMP_ECHOREPLY /* echo reply */,
						0 /* no code */,
						DPT_ICMP_ECHO_DATA(0, 0),
						1 /* one mbuf */,
						&payload_len,
						NULL, NULL, NULL);

	(void)dp_test_pktmbuf_eth_init(exp_pak,
				       "aa:bb:cc:dd:2:b1",
				       dp_test_intf_name2mac_str("dp2T1"),
				       RTE_ETHER_TYPE_IPV4);

	/* Create pak we expect to see in local_packet */
	exp = dp_test_exp_create(exp_pak);
	rte_pktmbuf_free(exp_pak);
	dp_test_exp_set_oif_name(exp, "dp2T1");
	dp_test_exp_set_fwd_status(exp, DP_TEST_FWD_FORWARDED);

	dp_test_pak_receive(test_pak, "dp2T1", exp);

	/* Cleanup cgnat46 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST; /* cgnat46 */

/*
 * npf_cgnat_47 - Tests that two different subscribers may be allocated port
 * blocks from the same public address.  Note, address-pool-pairing must be
 * disabled for this.
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat47, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat47, test)
{
	/* Create address pool with just 2 addresses */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.12,shared=yes "
			"block-size=128 "
			"max-blocks=4 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * Packet #1
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Packet #2
	 * 100.64.0.2:2345 / 1.1.1.12:1024 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a2",
		  "100.64.0.2", 2345, "1.1.1.1", 80,
		  "1.1.1.12", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Packet #3 -- No more free public addrs, so should use second
	 * port-block from first public address.
	 *
	 * 100.64.0.2:2345 / 1.1.1.11:1152 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a4",
		  "100.64.0.3", 4567, "1.1.1.1", 80,
		  "1.1.1.11", 1024 + 128, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* Cleanup cgnat47 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST; /* cgnat47 */

/*
 * cgnat48 -- Excercises threshold add/del code paths, and apm pb full code
 * path.   Does not verify log messages.
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat48, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat48, test)
{
	/*
	 * 10 public addresses, 4 blocks of 64 ports per address
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"port-range=1024-1279 "
			"block-size=64 "
			"log-pba=yes "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_5TUPLE, true);

	dpt_cgn_cmd_fmt(false, true,
			"cgn-ut warning add mapping-table threshold 50");
	dpt_cgn_cmd_fmt(false, true,
			"cgn-ut warning add session-table threshold 50");
	dpt_cgn_cmd_fmt(false, true,
			"cgn-ut warning add subscriber-table threshold 50");
	dpt_cgn_cmd_fmt(false, true,
			"cgn-ut warning add public-addresses threshold 50");

	char real_ifname[IFNAMSIZ];

	dp_test_intf_real("dp2T1", real_ifname);

	uint i, j, outer_count, inner_count;
	static char subs_str[20];
	uint32_t subs_addr;
	uint16_t subs_port;

	outer_count = 10;           /* 10 subscribers == 10 public addrs */
	inner_count = (3 * 64) + 1; /* Causes 4 port-blocks to be allocd */

	/* Initial addr and port */
	subs_addr = dpt_init_ipaddr(subs_str, "100.64.0.1");
	subs_port = 1024;

	for (i = 0; i < outer_count; i++) {
		for (j = 0; j < inner_count; j++) {
			/* Create session */
			dpt_cgn_map(false, real_ifname, 120, 17,
				    subs_str, subs_port, NULL, NULL);
			subs_port++;
		}

		/* New subscriber means new public addr is allocd */
		subs_port = 1024;
		subs_addr = dpt_incr_ipaddr(subs_addr, subs_str,
					    sizeof(subs_str));
	}

	dpt_cgn_show_source(false);

	dp_test_npf_cmd_fmt(false, "cgn-op clear session");

	for (i = 0; i < CGN_SESS_GC_COUNT + 1; i++)
		dp_test_npf_cmd_fmt(false, "cgn-op ut gc");

	dpt_cgn_cmd_fmt(false, true,
			"cgn-ut warning del mapping-table threshold 50");
	dpt_cgn_cmd_fmt(false, true,
			"cgn-ut warning del session-table threshold 50");
	dpt_cgn_cmd_fmt(false, true,
			"cgn-ut warning del subscriber-table threshold 50");
	dpt_cgn_cmd_fmt(false, true,
			"cgn-ut warning del public-addresses threshold 50");

	/* Cleanup cgnat48 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST; /* cgnat48 */

/*
 * cgnat49 - Tests a policy being uncfgd and re-cfgd while a subscriber
 * structure exists
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat49, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat49, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"max-blocks=2 "
			"prefix=RANGE1/1.1.1.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_5TUPLE, true);

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.192", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* Delete and re-add policy */
	cgnat_policy_del("POLICY1", 10, "dp2T1");
	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_5TUPLE, true);

	/*
	 * Pk2 #2.  Same source addr, different source port.
	 *
	 * 100.64.0.1:3456 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 3456, "1.1.1.1", 80,
		  "1.1.1.192", 1025, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* Cleanup cgnat49 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST; /* cgnat49 */


/*
 * cgnat_log_methods -- Tests enabling/disabling of log methods.
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat_log_methods, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat_log_methods, test)
{
	int rc;
	int rte_log_rc;
	enum cgn_log_type ltype;

	/* test using an invalid log type */
	/* add unknown log handler */
	rc = cgn_log_enable_handler(CGN_LOG_TYPE_COUNT, "rte_log");
	dp_test_fail_unless(rc == -EINVAL, "enable logging for invalid "
			    "log type (ltype %d)", CGN_LOG_TYPE_COUNT);

	for (ltype = 0; ltype < CGN_LOG_TYPE_COUNT; ltype++) {
		/* remove rte_log handler, in case it was already enabled */
		rte_log_rc = cgn_log_disable_handler(ltype, "rte_log");

		/* add unknown log handler */
		rc = cgn_log_enable_handler(ltype, "unknown");
		dp_test_fail_unless(rc == -ENOENT, "enable unknown cgnat log "
				    "handler (ltype %d)", ltype);

		/* disable unknown log handler */
		rc = cgn_log_disable_handler(ltype, "unknown");
		dp_test_fail_unless(rc == -ENOENT, "disable unknown cgnat log "
				    "handler (ltype %d)", ltype);

		/* add the rte_log handler */
		rc = cgn_log_enable_handler(ltype, "rte_log");
		dp_test_fail_unless(rc == 0, "enable rte_log cgnat log "
				    "handler (ltype %d)", ltype);

		/* enable the rte_log handler a second time */
		rc = cgn_log_enable_handler(ltype, "rte_log");
		dp_test_fail_unless(rc == -EEXIST, "enable rte_log cgnat log "
				    "handler twice (ltype %d)", ltype);

		/* disable the rte_log handler */
		rc = cgn_log_disable_handler(ltype, "rte_log");
		dp_test_fail_unless(rc == 0, "disable rte_log cgnat log "
				    "handler (ltype %d)", ltype);

		/* disable the rte_log handler when not enabled */
		rc = cgn_log_disable_handler(ltype, "rte_log");
		dp_test_fail_unless(rc == -ENOENT, "disable rte_log cgnat log "
				    "handler when not enabled (ltype %d)",
				    ltype);

		/*
		 * If rte_log handler was initially enabled, then enable it
		 * again.
		 */
		if (rte_log_rc == 0) {
			rc = cgn_log_enable_handler(ltype, "rte_log");
			dp_test_fail_unless(rc == 0, "reenable rte_log cgnat "
					    "log handler (ltype %d)", ltype);
		}
	}
} DP_END_TEST;


/*
 * npf_cgnat_50 - Tests policy address-group prefix matching
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat50, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat50, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.20 "
			"prefix=RANGE2/1.1.1.192/26 "
			"log-pba=yes "
			"");

	/*
	 * Add policy prefix 100.64.0.128/30 and verify that it matches
	 * 100.64.0.128 - 100.64.0.131, and does *not* match 100.64.0.127 or
	 * 100.64.0.132
	 */
	cgnat_policy_add("POLICY1", 10, "100.64.0.128/30", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	/*
	 * 100.64.0.129:1234 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.129", 1234, "1.1.1.1", 80,
		  "1.1.1.11", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 100.64.0.130:4321 / 1.1.1.12:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.130", 4321, "1.1.1.1", 80,
		  "1.1.1.12", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* Src 100.64.0.127 - No translation */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.127", 1234, "1.1.1.1", 80,
		  "100.64.0.127", 1234, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* Src 100.64.0.132 - No translation */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.132", 1235, "1.1.1.1", 80,
		  "100.64.0.132", 1235, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 100.64.0.128:1234 / 1.1.1.13:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.128", 1234, "1.1.1.1", 80,
		  "1.1.1.13", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 100.64.0.131:3333 / 1.1.1.14:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.131", 3333, "1.1.1.1", 80,
		  "1.1.1.14", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Add prefix 100.64.0.0/30 to match address-group and test first and
	 * last address in the prefix
	 */
	dp_test_npf_cmd_fmt(false,
			    "npf-ut fw table add POLICY1_AG 100.64.0.0/30");

	/*
	 * 100.64.0.1:1111 / 1.1.1.15:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 1111, "1.1.1.1", 80,
		  "1.1.1.15", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 100.64.0.3:1111 / 1.1.1.15:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.3", 1111, "1.1.1.1", 80,
		  "1.1.1.16", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 100.64.0.0:2222 / 1.1.1.15:1024 --> dst 1.1.1.1:80
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.0", 2222, "1.1.1.1", 80,
		  "1.1.1.17", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* Cleanup cgnat50 */
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST; /* cgnat50 */

/*
 * cgnat51 - Tests changing a policy match address-group on a live policy
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat51, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat51, test)
{
	char real_ifname[IFNAMSIZ];

	dp_test_intf_real("dp2T1", real_ifname);

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"max-blocks=2 "
			"prefix=RANGE1/1.1.1.192/26 "
			"");

	dpt_addr_grp_create("MATCH_AG1", "100.64.0.0/12");
	dpt_addr_grp_create("MATCH_AG2", "100.64.0.0/12");

	dp_test_npf_cmd_fmt(false,
			    "cgn-ut policy add POLICY1 priority=10 "
			    "match-ag=MATCH_AG1 pool=POOL1 log-sess-all=no");

	dp_test_npf_cmd_fmt(false,
			    "cgn-ut policy attach name=POLICY1 intf=%s",
			    real_ifname);

	/* Change match address-group after attach */
	dp_test_npf_cmd_fmt(false,
			    "cgn-ut policy add POLICY1 priority=10 "
			    "match-ag=MATCH_AG2 pool=POOL1 log-sess-all=no");

	/*
	 * 100.64.0.1:49152 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 49152, "1.1.1.1", 80,
		  "1.1.1.192", 1024, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * Pk2 #2.  Same source addr, different source port.
	 *
	 * 100.64.0.1:3456 / 1.1.1.11:1024 --> dst 1.1.1.1:80
	 */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", 3456, "1.1.1.1", 80,
		  "1.1.1.192", 1025, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	/* Cleanup cgnat51 */
	dp_test_npf_cmd_fmt(false,
			    "cgn-ut policy detach name=POLICY1 intf=%s",
			    real_ifname);

	dp_test_npf_cmd_fmt(false, "cgn-ut policy delete POLICY1");

	dpt_addr_grp_destroy("MATCH_AG1", NULL);
	dpt_addr_grp_destroy("MATCH_AG2", NULL);

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST; /* cgnat51 */


/*
 * cgnat52 - Test NAT pool lookup using the hidden NAT pool address-group.
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat52, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat52, test)
{
	struct nat_pool *np;
	uint32_t haddr;

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/10.0.1.1-10.0.1.9 "
			"prefix=RANGE2/10.0.2.0/24 "
			"prefix=RANGE3/10.0.3.2/31 "
			"prefix=RANGE4/10.0.4.3/32 "
			"address-range=RANGE5/10.0.5.3-10.0.5.3 "
		);

	np = nat_pool_lookup("POOL1");
	dp_test_fail_unless(np, "np");

	haddr = 0x0a000100;
	dp_test_fail_unless(!nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X in pool", haddr);

	haddr = 0x0a000101;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	haddr = 0x0a000109;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	haddr = 0x0a00010a;
	dp_test_fail_unless(!nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X in pool", haddr);

	haddr = 0x0a000201;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	/*
	 * First and last addr of 10.0.2.0/24 should not be in address-group
	 */
	haddr = 0x0a000200;
	dp_test_fail_unless(!nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X in pool", haddr);

	haddr = 0x0a000201;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	haddr = 0x0a0002fe;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	haddr = 0x0a0002ff;
	dp_test_fail_unless(!nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X in pool", haddr);

	/*
	 * 10.0.3.2/31 is a special case.  10.0.3.2 and 10.0.3.3 should be in
	 * addr-grp
	 */
	haddr = 0x0a000302;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	haddr = 0x0a000303;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	/*
	 * 10.0.4.3/32
	 */
	haddr = 0x0a000403;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	/*
	 * 10.0.5.3 - 10.0.5.3
	 */
	haddr = 0x0a000503;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	/*
	 * Add RANGE6.  Only the NAT pool ranges data should be regenerated.
	 * The NAT pool pointer should remain valid.
	 */
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/10.0.1.1-10.0.1.9 "
			"prefix=RANGE2/10.0.2.0/24 "
			"prefix=RANGE3/10.0.3.2/31 "
			"prefix=RANGE4/10.0.4.3/32 "
			"address-range=RANGE5/10.0.5.3-10.0.5.3 "
			"address-range=RANGE6/10.0.6.5-10.0.6.6 "
		);

	haddr = 0x0a000100;
	dp_test_fail_unless(!nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X in pool", haddr);

	/*
	 * 10.0.6.5 - 10.0.6.6
	 */
	haddr = 0x0a000605;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	haddr = 0x0a000606;
	dp_test_fail_unless(nat_pool_is_pool_addr(np, htonl(haddr)),
			    "0x%08X not in pool", haddr);

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST; /* cgnat52 */


/*
 * npf_cgnat_53 - Checks TCP timeout values for a 5-tuple session
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat53, cgnat_setup, cgnat_teardown);
DP_START_TEST(cgnat53, test)
{
	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"address-range=RANGE1/1.1.1.11-1.1.1.11 "
			"prefix=RANGE2/1.1.1.192/26 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1", "dp2T1",
			 CGN_MAP_EIM, CGN_FLTR_EIF, CGN_5TUPLE, true);

	char fltr[200];
	int timeout;
	int exp_timeout = CGN_DEF_ETIME_TCP_ESTBD;
	uint16_t subs_port = 4567;
	uint16_t pub_port = 1024;

	/*
	 * 1st repeat: Default Established timer
	 * 2nd repeat: Set TCP Established port 80 time to 9
	 * 3rd repeat: Set TCP Established port 80 time to 0
	 */
	uint repeat = 2;

repeat:
	snprintf(fltr, sizeof(fltr),
		 "proto 6 subs-addr 100.64.0.1 subs-port %u "
		 "dst-addr 1.1.1.1 dst-port 80", subs_port);

	/*
	 * Check 5-tuple TCP timeout
	 */

	/* Forw SYN */
	cgnat_tcp(TH_SYN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", subs_port, "1.1.1.1", 80,
		  "1.1.1.11", pub_port, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	timeout = dpt_cgn_sess_get_timeout(fltr, false);
	dp_test_fail_unless(timeout == CGN_DEF_ETIME_TCP_OPENING,
			    "Port %u, Timeout %d, expected %d",
			    subs_port, timeout, CGN_DEF_ETIME_TCP_OPENING);

	/* Back SYN */
	cgnat_tcp(TH_SYN | TH_ACK, "dp2T1", "aa:bb:cc:dd:2:b1",
		  "1.1.1.1", 80, "1.1.1.11", pub_port,
		  "1.1.1.1", 80, "100.64.0.1", subs_port,
		  "aa:bb:cc:dd:1:a1", "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/* Session will be in Established state now */
	timeout = dpt_cgn_sess_get_timeout(fltr, false);
	dp_test_fail_unless(timeout == exp_timeout,
			    "Port %u, Timeout %d, expected %d",
			    subs_port, timeout, exp_timeout);

	/* Forw ACK */
	cgnat_tcp(TH_ACK, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", subs_port, "1.1.1.1", 80,
		  "1.1.1.11", pub_port, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	timeout = dpt_cgn_sess_get_timeout(fltr, false);
	dp_test_fail_unless(timeout == exp_timeout,
			    "Port %u, Timeout %d, expected %d",
			    subs_port, timeout, exp_timeout);

	/* Forw FIN */
	cgnat_tcp(TH_FIN, "dp1T0", "aa:bb:cc:dd:1:a1",
		  "100.64.0.1", subs_port, "1.1.1.1", 80,
		  "1.1.1.11", pub_port, "1.1.1.1", 80,
		  "aa:bb:cc:dd:2:b1", "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	timeout = dpt_cgn_sess_get_timeout(fltr, false);
	dp_test_fail_unless(timeout == CGN_DEF_ETIME_TCP_CLOSING,
			    "Timeout %d, expected %d",
			    timeout, CGN_DEF_ETIME_TCP_CLOSING);

	/* Back FIN|ACK */
	cgnat_tcp(TH_FIN | TH_ACK, "dp2T1", "aa:bb:cc:dd:2:b1",
		  "1.1.1.1", 80, "1.1.1.11", pub_port,
		  "1.1.1.1", 80, "100.64.0.1", subs_port,
		  "aa:bb:cc:dd:1:a1", "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	timeout = dpt_cgn_sess_get_timeout(fltr, false);
	dp_test_fail_unless(timeout == CGN_DEF_ETIME_TCP_CLOSING,
			    "Timeout %d, expected %d",
			    timeout, CGN_DEF_ETIME_TCP_CLOSING);

	if (repeat >= 1 && repeat <= 2) {
		char *resp = NULL;
		bool err;

		subs_port++;
		pub_port++;

		if (repeat == 2) {
			/* First repeat */
			resp = dp_test_console_request_w_err(
				"cgn-ut session-timeouts tcp-estab "
				"port 80 timeout 9",
				&err, false);

			/* Expected Estbd timeout is now 9 */
			exp_timeout = 9;

		} else if (repeat == 1) {
			/* Second repeat */
			resp = dp_test_console_request_w_err(
				"cgn-ut session-timeouts tcp-estab "
				"port 80 timeout 0",
				&err, false);

			/* Expected Estbd timeout is now back to default */
			exp_timeout = 7440;
		}

		repeat--;

		if (!resp || err)
			dp_test_fail("cgnat port timeout command failed");

		free(resp);
		goto repeat;
	}

	/* Cleanup */
	cgnat_policy_del("POLICY1", 10, "dp2T1");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");

} DP_END_TEST; /* cgnat53 */


/*
 * cgnat_54 -
 *
 *    Private                                       Public
 *                       dp1T0 +---+ dp2T1
 *    100.64.0.0/24  ----------|   |--------------- 1.1.1.0/24
 *                             |   | dp2T2
 *                             |   |--------------- 2.2.2.0/24
 *                             +---+
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat54, NULL, NULL);
DP_START_TEST(cgnat54, test)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.64.0.254/16");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp2T2", "2.2.2.254/24");

	dp_test_netlink_add_neigh("dp1T0", "100.64.0.1", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.2", "aa:bb:cc:dd:1:a2");

	dp_test_netlink_add_neigh("dp2T1", "1.1.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1", "1.1.1.2", "aa:bb:cc:dd:2:b2");

	dp_test_netlink_add_neigh("dp2T2", "2.2.2.1", "aa:bb:cc:dd:3:c1");
	dp_test_netlink_add_neigh("dp2T2", "2.2.2.2", "aa:bb:cc:dd:3:c2");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL1 "
			"type=cgnat "
			"prefix=RANGE1/10.0.1.0/24 "
			"");

	dpt_cgn_cmd_fmt(false, true,
			"nat-ut pool add POOL2 "
			"type=cgnat "
			"prefix=RANGE1/10.0.2.0/24 "
			"");

	cgnat_policy_add("POLICY1", 10, "100.64.0.0/12", "POOL1",
			 "dp2T1", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	cgnat_policy_add("POLICY2", 10, "100.64.0.0/12", "POOL2",
			 "dp2T2", CGN_MAP_EIM, CGN_FLTR_EIF, CGN_3TUPLE, true);

	bool debug = false;

	dpt_cgn_print_json("cgn-op show interface", debug);

	/*
	 * Add routes:  3.3.3.0/24 -> dp2T1
	 *              4.4.4.0/24 -> dp2T2
	 */
	dp_test_netlink_add_route("3.3.3.0/24 nh 1.1.1.1 int:dp2T1");
	dp_test_netlink_add_route("4.4.4.0/24 nh 2.2.2.1 int:dp2T2");

	/*
	 * 100.64.0.1 -> 3.3.3.3, routed out dp2T1
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "3.3.3.3", 80,
		  "10.0.1.1", 1024, "3.3.3.3", 80,
		  "aa:bb:cc:dd:2:b1", 0, "dp2T1",
		  DP_TEST_FWD_FORWARDED);

	cgnat_udp("dp2T1", "aa:bb:cc:dd:2:b1", 0,
		  "3.3.3.3", 80, "10.0.1.1", 1024,
		  "3.3.3.3", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * 100.64.0.2 -> 4.4.4.4, routed out dp2T2
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a2", 0,
		  "100.64.0.2", 20123, "4.4.4.4", 80,
		  "10.0.2.1", 1024, "4.4.4.4", 80,
		  "aa:bb:cc:dd:3:c1", 0, "dp2T2",
		  DP_TEST_FWD_FORWARDED);

	cgnat_udp("dp2T2", "aa:bb:cc:dd:3:c1", 0,
		  "4.4.4.4", 80, "10.0.2.1", 1024,
		  "4.4.4.4", 80, "100.64.0.2", 20123,
		  "aa:bb:cc:dd:1:a2", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	dpt_cgn_show_session(NULL, 10, false, debug, false);

	/*
	 * Change route:  3.3.3.0/24 -> dp2T2
	 */
	dp_test_netlink_del_route("3.3.3.0/24 nh 1.1.1.1 int:dp2T1");
	dp_test_netlink_add_route("3.3.3.0/24 nh 2.2.2.1 int:dp2T2");

	/*
	 * 100.64.0.1 -> 3.3.3.3, switched from dp2T1 to dp2T2
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 49152, "3.3.3.3", 80,
		  "10.0.1.1", 1024, "3.3.3.3", 80,
		  "aa:bb:cc:dd:3:c1", 0, "dp2T2",
		  DP_TEST_FWD_FORWARDED);

	cgnat_udp("dp2T2", "aa:bb:cc:dd:c:c1", 0,
		  "3.3.3.3", 80, "10.0.1.1", 1024,
		  "3.3.3.3", 80, "100.64.0.1", 49152,
		  "aa:bb:cc:dd:1:a1", 0, "dp1T0",
		  DP_TEST_FWD_FORWARDED);

	/*
	 * What happens to a new flow from 100.64.0.1 to 3.3.3.4 .. ?
	 *
	 * Address-pool pairing means it should use the same public address,
	 * 10.0.1.1.   But this public address is on the policy on dp2T1.
	 */
	cgnat_udp("dp1T0", "aa:bb:cc:dd:1:a1", 0,
		  "100.64.0.1", 30001, "3.3.3.4", 80,
		  "10.0.1.1", 1025, "3.3.3.4", 80,
		  "aa:bb:cc:dd:3:c1", 0, "dp2T2",
		  DP_TEST_FWD_FORWARDED);

	dpt_cgn_print_json("cgn-op show interface", debug);

	dpt_cgn_show_session(NULL, 10, false, debug, false);

	dp_test_netlink_del_route("3.3.3.0/24 nh 2.2.2.1 int:dp2T2");
	dp_test_netlink_del_route("4.4.4.0/24 nh 2.2.2.1 int:dp2T2");

	/* Unconfig */
	cgnat_policy_del("POLICY1", 10, "dp2T1");
	cgnat_policy_del("POLICY2", 10, "dp2T2");

	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL1");
	dp_test_npf_cmd_fmt(false, "nat-ut pool delete POOL2");

	/* Cleanup */
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.1", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.2", "aa:bb:cc:dd:1:a2");

	dp_test_netlink_del_neigh("dp2T1", "1.1.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1", "1.1.1.2", "aa:bb:cc:dd:2:b2");

	dp_test_netlink_del_neigh("dp2T2", "2.2.2.1", "aa:bb:cc:dd:3:c1");
	dp_test_netlink_del_neigh("dp2T2", "2.2.2.2", "aa:bb:cc:dd:3:c2");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.64.0.254/16");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp2T2", "2.2.2.254/24");

} DP_END_TEST; /* cgnat54 */




#ifdef CGN_HASH_COMPARISON

/******************************************************************
 * RTE hash v URCU hash
 *
 * Applies to tests cgnat100 and cgnat101
 */
#define HASH_TEST_TABLE_SIZE (1024 * 128)
#define HASH_TEST_NENTRIES   100000
#define HASH_TEST_NLOOKUPS   200000

/* Hash table key.  Exactly 16 bytes */
struct ipv4_3tuple {
	uint32_t ifindex;
	uint32_t addr;
	uint16_t port;
	uint16_t pad0;
	uint8_t	 expired;
	uint8_t	 ipproto;
	uint16_t pad1;
} __attribute__((__packed__));

/* rte hash table entry */
struct rte_hash_entry {
	struct ipv4_3tuple key;
};

/* hash function used for rte and urcu */
static uint32_t
rte_ipv4_hash(const void *data, __rte_unused uint32_t data_len,
	      uint32_t init_val)
{
	const struct ipv4_3tuple *k = data;
	uint32_t rv;

	rv = rte_jhash_3words(k->port, k->addr, k->ipproto, k->ifindex);
	return rv;
}

/*
 * match function for rte hash.  Return 0 for match.
 *
 * Custom compare function is needed so we can ignore expired keys
 */
static int rte_hash_cmp_eq(const void *key1, const void *key2, size_t key_len)
{
	return memcmp(key1, key2, key_len);
}

struct urcu_hash_entry {
	struct cds_lfht_node node;
	struct ipv4_3tuple   key;
};

/*
 * match function for urcu hash.  Return 1 for match
 */
static int urcu_hash_match(struct cds_lfht_node *node, const void *void_key)
{
	struct urcu_hash_entry *ue1;
	const struct ipv4_3tuple *key = void_key;

	ue1 = caa_container_of(node, struct urcu_hash_entry, node);

	int rc = memcmp(&ue1->key, key, sizeof(ue1->key));

	return rc == 0 ? 1 : 0;
}

/*
 * cgnat100 - URCU hash table
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat100, cgnat_setup, cgnat_teardown);
DP_START_TEST_DONT_RUN(cgnat100, test)
{
	struct urcu_hash_entry *ue, *lookup;
	struct urcu_hash_entry base;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct cds_lfht *ht;
	uint32_t hash;
	uint i;

	/*
	 * URCU hash table is extendable, but we have omitted that here since
	 * the RTE hash table is *not* extendable.
	 */
	ht = cds_lfht_new(HASH_TEST_TABLE_SIZE,
			  HASH_TEST_TABLE_SIZE,
			  HASH_TEST_TABLE_SIZE,
			  0, NULL);
	dp_test_fail_unless(ht != NULL, "urcu hash table");

	base.key.ifindex = 1;
	base.key.addr = 0;
	base.key.port = 1;
	base.key.ipproto = 17;
	base.key.expired = 0;
	base.key.pad0 = 0;
	base.key.pad1 = 0;

	/*
	 * Set count
	 */
	uint lookup_count = HASH_TEST_NLOOKUPS;
	uint nentries     = HASH_TEST_NENTRIES;

	printf("\n");
	printf("URCU Hash Test\n");

	/*
	 * Populate table
	 */
	printf("  Populate table with %u entries, table size %u\n",
	       nentries, HASH_TEST_TABLE_SIZE);

	for (i = 0; i < nentries; i++) {
		ue = zmalloc_aligned(sizeof(*ue));
		dp_test_fail_unless(ue != NULL, "malloc");

		memcpy(&ue->key, &base.key, sizeof(ue->key));
		ue->key.addr = i;

		hash = rte_ipv4_hash(&ue->key, sizeof(ue->key), 0);

		/* Add */
		node = cds_lfht_add_unique(ht, hash, urcu_hash_match,
					   ue, &ue->node);
		dp_test_fail_unless(node == &ue->node, "urcu add");

		/* Lookup */
		cds_lfht_lookup(ht, hash, urcu_hash_match, &ue->key, &iter);
		node = cds_lfht_iter_get_node(&iter);
		lookup = caa_container_of(node, struct urcu_hash_entry, node);
		dp_test_fail_unless(lookup == ue, "urcu lookup");
	}

	uint64_t nsecs1, nsecs2, elapsed;	/* nanosecs */
	uint64_t average, overhead = 0;		/* nanosecs */
	bool do_work = false;
	struct ipv4_3tuple lookup_key;

	memcpy(&lookup_key, &base.key, sizeof(lookup_key));

	/*
	 * First time around loop is to calculate the loop overhead.  Second
	 * time does the work.  We subtract the first loops time from the
	 * second loops time to get an approximate time for the thing we are
	 * interested in.
	 */
	printf("  Do %u table lookups\n", lookup_count);
loop1:
	nsecs1 = cgn_time_nsecs();
	for (i = 0; i < lookup_count; i++) {
		lookup_key.addr = i % nentries;
		ue = NULL;

		if (do_work) {
			hash = rte_ipv4_hash(&lookup_key,
					     sizeof(lookup_key), 0);
			cds_lfht_lookup(ht, hash, urcu_hash_match,
					&lookup_key, &iter);
			node = cds_lfht_iter_get_node(&iter);
			ue = caa_container_of(node, struct urcu_hash_entry,
					      node);
		}
	}
	nsecs2 = cgn_time_nsecs();
	elapsed = nsecs2 - nsecs1;

	if (!do_work) {
		overhead = elapsed;
		do_work = true;
		goto loop1;
	}

	/* Subtract overhead from elapsed to get time taken by work */
	if (overhead <= elapsed)
		elapsed -= overhead;
	else
		elapsed = 0;

	average = elapsed / i;
	printf("  -------------------------------------------------\n");
	printf("  Time %lu nS, average %lu nS\n", elapsed, average);
	printf("  -------------------------------------------------\n");

	/*
	 * Empty table
	 */
	cds_lfht_for_each_entry(ht, &iter, ue, node) {
		(void)cds_lfht_del(ht, &ue->node);
		free(ue);
	}

	cds_lfht_destroy(ht, NULL);

} DP_END_TEST; /* cgnat100 */


/*
 * cgnat101 - RTE hash table
 */
DP_DECL_TEST_CASE(npf_cgnat, cgnat101, cgnat_setup, cgnat_teardown);
DP_START_TEST_DONT_RUN(cgnat101, test)
{
	struct rte_hash_entry *ue, *lookup;
	struct rte_hash *ht;
	uint i;

	struct rte_hash_parameters ipv4_l3fwd_hash_params = {
		.name = "rte hash table",
		.entries = HASH_TEST_TABLE_SIZE,
		.key_len = sizeof(struct ipv4_3tuple),
		.hash_func = rte_ipv4_hash,
		.hash_func_init_val = 0,
		.socket_id = 0,
		.extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE |
		RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL,
	};

	/*
	 * LCORE_ID_ANY is -1.
	 *
	 * If RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD flag is specified when the
	 * hash table is created then rte_hash_add_key_data uses the value
	 * from rte_lcore_id() to index an array *without* first checking the
	 * value returned.   (it is storing the entry in per-core memory).
	 *
	 * The dataplane has its own version, dp_lcore_id, which returns 0
	 * instead of LCORE_ID_ANY for non-dataplane threads.
	 */
	if (rte_lcore_id() != LCORE_ID_ANY) {
		ipv4_l3fwd_hash_params.extra_flag |=
			RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD;
		ipv4_l3fwd_hash_params.extra_flag |=
			RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;
	}

	ht = rte_hash_create(&ipv4_l3fwd_hash_params);
	dp_test_fail_unless(ht != NULL, "rte_hash_create");

	rte_hash_set_cmp_func(ht, rte_hash_cmp_eq);

	struct urcu_hash_entry base;

	base.key.ifindex = 1;
	base.key.addr = 0;
	base.key.port = 1;
	base.key.ipproto = 17;
	base.key.expired = 0;
	base.key.pad0 = 0;
	base.key.pad1 = 0;

	/*
	 * Set count
	 */
	uint lookup_count = HASH_TEST_NLOOKUPS;
	uint nentries     = HASH_TEST_NENTRIES;
	int ret;

	printf("\n");
	printf("RTE Hash Test\n");

	/*
	 * Populate table
	 */
	printf("  Populate table with %u entries\n", nentries);

	for (i = 0; i < nentries; i++) {
		ue = zmalloc_aligned(sizeof(*ue));

		dp_test_fail_unless(ue != NULL, "malloc");

		memcpy(&ue->key, &base.key, sizeof(ue->key));
		ue->key.addr = i;

		/* Add */
		ret = rte_hash_add_key_data(ht, (void *)&ue->key, (void *)ue);
		dp_test_fail_unless(ret >= 0,
				    "rte_hash_add_key returned %d for entry %u",
				    ret, i);

		/* Verify entry has been added */
		ret = rte_hash_lookup_data(ht, (const void *)&ue->key,
					   (void **)&lookup);
		dp_test_fail_unless(ret >= 0,
				    "rte_hash_lookup_data returned %d",
				    ret);
		dp_test_fail_unless(lookup == ue, "rte lookup");
	}

	uint64_t nsecs1, nsecs2, elapsed;	/* nanosecs */
	uint64_t average, overhead = 0;		/* nanosecs */
	bool do_work = false;
	struct ipv4_3tuple lookup_key;

	memcpy(&lookup_key, &base.key, sizeof(lookup_key));

	/*
	 * First time around loop is to calculate the loop overhead.  Second
	 * time does the work.  We subtract the first loops time from the
	 * second loops time to get an approximate time for the thing we are
	 * interested in.
	 */
	printf("  Do %u table lookups\n", lookup_count);
loop1:
	nsecs1 = cgn_time_nsecs();
	for (i = 0; i < lookup_count; i++) {
		lookup_key.addr = i % nentries;
		ue = NULL;

		if (do_work) {
			ret = rte_hash_lookup_data(ht,
						   (const void *)&lookup_key,
						   (void **)&ue);
		}
	}
	nsecs2 = cgn_time_nsecs();
	elapsed = nsecs2 - nsecs1;

	if (!do_work) {
		overhead = elapsed;
		do_work = true;
		goto loop1;
	}

	/* Subtract overhead from elapsed to get time taken by work */
	if (overhead <= elapsed)
		elapsed -= overhead;
	else
		elapsed = 0;

	average = elapsed / i;
	printf("  -------------------------------------------------\n");
	printf("  Time %lu nS, average %lu nS\n", elapsed, average);
	printf("  -------------------------------------------------\n");

	/*
	 * Empty table
	 */
	uint32_t iterator = 0;

	while (true) {
		const void *key;
		void *data;

		ret = rte_hash_iterate(ht, &key, &data, &iterator);
		if (ret < 0)
			break;

		ret = rte_hash_del_key(ht, (void *)key);
		dp_test_fail_unless(ret >= 0, "rte_hash_del_key returned %d",
				    ret);

		if (ret >= 0) {
			rte_hash_free_key_with_position(ht, ret);
			free(data);
		}
	}

	rte_hash_free(ht);

} DP_END_TEST; /* cgnat101 */

#endif /* CGN_HASH_COMPARISON */


/**********************************************************************
 * Support Functions
 *********************************************************************/

/*
 * Issue command to dataplane
 */
static void
_dpt_cgn_cmd(const char *cmd, bool print, bool exp,
	     const char *file, int line)
{
	char *reply;
	bool err;

	reply = dp_test_console_request_w_err(cmd, &err, print);

	/*
	 * Returned string for npf commands is just an empty string, which is
	 * of no interest
	 */
	free(reply);

	_dp_test_fail_unless(err != exp, file, line,
			     "Expd %u, got %u: \"%s\"", exp, !err, cmd);
}

#define CGN_MAX_CMD_LEN 5000

void
_dpt_cgn_cmd_fmt(bool print, bool exp,
		 const char *file, int line, const char *fmt_str, ...)
{
	char cmd[CGN_MAX_CMD_LEN];
	va_list ap;

	va_start(ap, fmt_str);
	vsnprintf(cmd, CGN_MAX_CMD_LEN, fmt_str, ap);
	_dpt_cgn_cmd(cmd, print, exp, file, line);
	va_end(ap);
}

/*
 * This is called *after* the packet has been modified, but *before* the pkt
 * queued on the tx ring is checked.
 */
static void
cgn_validate_cb(struct rte_mbuf *mbuf, struct ifnet *ifp,
		struct dp_test_expected *expected,
		enum dp_test_fwd_result_e fwd_result)
{
	struct cgn_ctx *ctx = dp_test_exp_get_validate_ctx(expected);

	/* call the saved check routine */
	if (ctx->do_check) {
		(ctx->saved_cb)(mbuf, ifp, expected, fwd_result);
	} else {
		expected->pak_correct[0] = true;
		expected->pak_checked[0] = true;
	}
}

static void cgnat_setup(void)
{
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "2.2.2.254/24");
	dp_test_nl_add_ip_addr_and_connected("dp1T0", "100.64.0.254/16");
	dp_test_nl_add_ip_addr_and_connected("dp2T1", "1.1.1.254/24");

	/*
	 * Inside
	 */
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.1",
				  "aa:bb:cc:dd:1:a1");
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.2",
				  "aa:bb:cc:dd:1:a2");
	dp_test_netlink_add_neigh("dp1T0", "100.64.0.3",
				  "aa:bb:cc:dd:1:a4");
	dp_test_netlink_add_neigh("dp1T0", "100.64.1.1",
				  "aa:bb:cc:dd:1:a3");

	dp_test_netlink_add_neigh("dp1T0", "2.2.2.1",
				  "aa:bb:cc:dd:1:a4");

	/*
	 * Outside
	 */
	dp_test_netlink_add_neigh("dp2T1", "1.1.1.1",
				  "aa:bb:cc:dd:2:b1");
	dp_test_netlink_add_neigh("dp2T1", "1.1.1.2",
				  "aa:bb:cc:dd:2:b2");

}

static void cgnat_teardown(void)
{
	/* Check cgnat feature is disabled */
	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-cgnat-in",
				      "ipv4-validate");
	dp_test_wait_for_pl_feat_gone("dp2T1", "vyatta:ipv4-cgnat-out",
				      "ipv4-out");

	/* Cleanup */
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.1", "aa:bb:cc:dd:1:a1");
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.2", "aa:bb:cc:dd:1:a2");
	dp_test_netlink_del_neigh("dp1T0", "100.64.0.3", "aa:bb:cc:dd:1:a4");
	dp_test_netlink_del_neigh("dp1T0", "100.64.1.1", "aa:bb:cc:dd:1:a3");
	dp_test_netlink_del_neigh("dp1T0", "2.2.2.1", "aa:bb:cc:dd:1:a4");

	dp_test_netlink_del_neigh("dp2T1", "1.1.1.1", "aa:bb:cc:dd:2:b1");
	dp_test_netlink_del_neigh("dp2T1", "1.1.1.2", "aa:bb:cc:dd:2:b2");

	dp_test_nl_del_ip_addr_and_connected("dp1T0", "100.64.0.254/16");
	dp_test_nl_del_ip_addr_and_connected("dp2T1", "1.1.1.254/24");
	dp_test_nl_del_ip_addr_and_connected("dp1T0", "2.2.2.254/24");

	dp_test_npf_cleanup();
}

/*
 * cgnat_udp
 */
static void
_cgnat_udp(const char *rx_intf, const char *pre_smac, int pre_vlan,
	   const char *pre_saddr, uint16_t pre_sport,
	   const char *pre_daddr, uint16_t pre_dport,
	   const char *post_saddr, uint16_t post_sport,
	   const char *post_daddr, uint16_t post_dport,
	   const char *post_dmac, int post_vlan, const char *tx_intf,
	   int status, bool icmp_err,
	   const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;
	int len = 20;

	/* Pre IPv4 UDP packet */
	struct dp_test_pkt_desc_t pre_pkt_UDP = {
		.text       = "IPv4 UDP",
		.len        = len,
		.ether_type = RTE_ETHER_TYPE_IPV4,
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
		.len        = len,
		.ether_type = RTE_ETHER_TYPE_IPV4,
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

	/*
	 * Create ICMP error message if expecting a drop for outbound packets
	 */
	if (status == DP_TEST_FWD_DROPPED && icmp_err) {
		struct icmphdr *icph;
		struct iphdr *ip;
		int icmplen;
		struct rte_mbuf *payload_pak;
		const char *intf_addr;

		/* src of icmp error pkt is output intf */
		if (!strcmp(rx_intf, "dp1T0"))
			intf_addr = "100.64.0.254";
		else
			intf_addr = "1.1.1.254";

		icmplen = sizeof(struct iphdr) + sizeof(struct udphdr) +
			pre_pkt_UDP.len;

		payload_pak = dp_test_v4_pkt_from_desc(&pre_pkt_UDP);
		dp_test_ipv4_decrement_ttl(payload_pak);

		exp_pak = dp_test_create_icmp_ipv4_pak(intf_addr,
						       pre_pkt_UDP.l3_src,
						       ICMP_DEST_UNREACH,
						       ICMP_HOST_UNREACH,
						       DPT_ICMP_UNREACH_DATA(0),
						       1, &icmplen,
						       iphdr(payload_pak),
						       &ip, &icph);
		rte_pktmbuf_free(payload_pak);

		test_exp = dp_test_exp_create(exp_pak);
		rte_pktmbuf_free(exp_pak);

		dp_test_exp_set_oif_name(test_exp, rx_intf);
		status = DP_TEST_FWD_FORWARDED;

		exp_pak = dp_test_exp_get_pak(test_exp);
		ip = iphdr(exp_pak);

		/* Set TOS, then reset checksum */
		ip->tos = 0xc0;
		ip->check = 0;
		ip->check = rte_ipv4_cksum((const struct rte_ipv4_hdr *)ip);

		dp_test_pktmbuf_eth_init(
			exp_pak, pre_pkt_UDP.l2_src,
			dp_test_intf_name2mac_str(rx_intf),
			RTE_ETHER_TYPE_IPV4);
	} else {

		exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_UDP);
		test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_UDP);
		rte_pktmbuf_free(exp_pak);
	}

	/* vlan */
	if (pre_vlan > 0)
		dp_test_pktmbuf_vlan_init(test_pak, pre_vlan);

	if (post_vlan > 0) {
		dp_test_exp_set_vlan_tci(test_exp, post_vlan);

		(void)dp_test_pktmbuf_eth_init(
			dp_test_exp_get_pak(test_exp),
			post_dmac,
			dp_test_intf_name2mac_str(tx_intf),
			RTE_ETHER_TYPE_IPV4);
	}

	dp_test_exp_set_fwd_status(test_exp, status);

	dp_test_exp_set_validate_ctx(test_exp, &cgn_ctx, false);
	dp_test_exp_set_validate_cb(test_exp, cgn_validate_cb);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);
}

/*
 * cgnat_tcp
 */
void
_cgnat_tcp(uint8_t flags, const char *rx_intf, const char *pre_smac,
	   const char *pre_saddr, uint16_t pre_sport,
	   const char *pre_daddr, uint16_t pre_dport,
	   const char *post_saddr, uint16_t post_sport,
	   const char *post_daddr, uint16_t post_dport,
	   const char *post_dmac, const char *tx_intf,
	   int status,
	   const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	/* Pre IPv4 TCP packet */
	struct dp_test_pkt_desc_t pre_pkt_TCP = {
		.text       = "IPv4 TCP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = pre_sport,
				.dport = pre_dport,
				.flags = flags,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	/* Post IPv4 TCP packet */
	struct dp_test_pkt_desc_t post_pkt_TCP = {
		.text       = "IPv4 TCP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = post_saddr,
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = post_daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_TCP,
		.l4         = {
			.tcp = {
				.sport = post_sport,
				.dport = post_dport,
				.flags = flags,
				.seq = 0,
				.ack = 0,
				.win = 8192,
				.opts = NULL
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	test_pak = dp_test_v4_pkt_from_desc(&pre_pkt_TCP);

	/*
	 * Create ICMP error message if expecting a drop for outbound packets
	 */
	if (status == DP_TEST_FWD_DROPPED && !strcmp(rx_intf, "dp1T0")) {
		struct icmphdr *icph;
		struct iphdr *ip;
		int icmplen;
		struct rte_mbuf *payload_pak;
		const char *intf_addr;

		/* src of icmp error pkt is output intf */
		if (!strcmp(rx_intf, "dp1T0"))
			intf_addr = "100.64.0.254";
		else
			intf_addr = "1.1.1.254";

		icmplen = sizeof(struct iphdr) + sizeof(struct tcphdr) +
			pre_pkt_TCP.len;

		payload_pak = dp_test_v4_pkt_from_desc(&pre_pkt_TCP);
		dp_test_ipv4_decrement_ttl(payload_pak);

		exp_pak = dp_test_create_icmp_ipv4_pak(intf_addr,
						       pre_pkt_TCP.l3_src,
						       ICMP_DEST_UNREACH,
						       ICMP_HOST_UNREACH,
						       DPT_ICMP_UNREACH_DATA(0),
						       1, &icmplen,
						       iphdr(payload_pak),
						       &ip, &icph);
		rte_pktmbuf_free(payload_pak);

		test_exp = dp_test_exp_create(exp_pak);
		rte_pktmbuf_free(exp_pak);

		dp_test_exp_set_oif_name(test_exp, rx_intf);
		status = DP_TEST_FWD_FORWARDED;

		exp_pak = dp_test_exp_get_pak(test_exp);
		ip = iphdr(exp_pak);

		/* Set TOS, then reset checksum */
		ip->tos = 0xc0;
		ip->check = 0;
		ip->check = rte_ipv4_cksum((const struct rte_ipv4_hdr *)ip);

		dp_test_pktmbuf_eth_init(
			exp_pak, pre_pkt_TCP.l2_src,
			dp_test_intf_name2mac_str(rx_intf),
			RTE_ETHER_TYPE_IPV4);
	} else {

		exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_TCP);
		test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_TCP);
		rte_pktmbuf_free(exp_pak);
	}

	dp_test_exp_set_fwd_status(test_exp, status);

	dp_test_exp_set_validate_ctx(test_exp, &cgn_ctx, false);
	dp_test_exp_set_validate_cb(test_exp, cgn_validate_cb);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);
}


/*
 * cgnat_icmp
 */
static void
_cgnat_icmp(uint8_t icmp_type,
	    const char *rx_intf, const char *pre_smac,
	    const char *pre_saddr, uint16_t pre_icmp_id,
	    const char *pre_daddr,
	    const char *post_saddr, uint16_t post_icmp_id,
	    const char *post_daddr,
	    const char *post_dmac, const char *tx_intf,
	    const char *file, const char *func, int line)
{
	struct dp_test_expected *test_exp;
	struct rte_mbuf *test_pak, *exp_pak;

	/* Pre IPv4 ICMP packet */
	struct dp_test_pkt_desc_t pre_pkt_ICMP = {
		.text       = "IPv4 ICMP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = pre_saddr,
		.l2_src     = pre_smac,
		.l3_dst     = pre_daddr,
		.l2_dst     = "aa:bb:cc:dd:2:b1",
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = icmp_type,
				.code = 0,
				{
					.dpt_icmp_id = pre_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	/* Post IPv4 ICMP packet */
	struct dp_test_pkt_desc_t post_pkt_ICMP = {
		.text       = "Packet A, IPv4 ICMP",
		.len        = 20,
		.ether_type = RTE_ETHER_TYPE_IPV4,
		.l3_src     = post_saddr,
		.l2_src     = "aa:bb:cc:dd:2:b1",
		.l3_dst     = post_daddr,
		.l2_dst     = post_dmac,
		.proto      = IPPROTO_ICMP,
		.l4         = {
			.icmp = {
				.type = icmp_type,
				.code = 0,
				{
					.dpt_icmp_id = post_icmp_id,
					.dpt_icmp_seq = 0,
				},
			}
		},
		.rx_intf    = rx_intf,
		.tx_intf    = tx_intf
	};

	test_pak = dp_test_v4_pkt_from_desc(&pre_pkt_ICMP);

	exp_pak = dp_test_v4_pkt_from_desc(&post_pkt_ICMP);
	test_exp = dp_test_exp_from_desc(exp_pak, &post_pkt_ICMP);
	rte_pktmbuf_free(exp_pak);

	dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

	dp_test_exp_set_validate_ctx(test_exp, &cgn_ctx, false);
	dp_test_exp_set_validate_cb(test_exp, cgn_validate_cb);

	_dp_test_pak_receive(test_pak, rx_intf, test_exp,
			     file, func, line);
}
