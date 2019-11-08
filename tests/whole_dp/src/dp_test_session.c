/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Peter W. Morreale
 *
 * dataplane UT Session tests
 */

#include <libmnl/libmnl.h>
#include <linux/random.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>


#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "session/session.h"
#include "session/session_feature.h"
#include "npf/npf.h"
#include "npf/npf_if.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state.h"
#include "dp_test_lib.h"
#include "dp_test_lib_intf.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib.h"
#include "dp_test_session_lib.h"
#include "dp_test_npf_sess_lib.h"

#define TEST_VRF 69
#define IF_NAME "dp1T0"

DP_DECL_TEST_SUITE(session_suite);

/*
 * Test creation/lookup of an IPv4 UDP session
 */
DP_DECL_TEST_CASE(session_suite, session_udp_lookup, NULL, NULL);
DP_START_TEST(session_udp_lookup, test1)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	struct session *s1;
	struct session *s2;
	int rc;
	bool forw;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	int len = 22;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create forward and reverse packets */
	f = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, 1, &len);

	r = dp_test_create_udp_ipv4_pak("10.73.2.0", "10.73.0.0",
			1003, 1001, 1, &len);

	/* Failed lookup - no sessions */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == -ENOENT, "session failed lookup: %d\n", rc);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s1, &created);
	dp_test_fail_unless(created == true, "session udp not created\n");

	/* Forward lookup */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session forward lookup: %d\n", rc);
	dp_test_fail_unless(forw == true, "session forward lookup: forw: %s\n",
			forw ? "true" : "false");

	/* Reverse lookup */
	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session reverse lookup: %d\n", rc);
	dp_test_fail_unless(s2 == s1, "session reverse lookup: bad sessions");
	dp_test_fail_unless(forw == false, "session reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/*
 * Test creation/lookup of an IPv4 TCP session
 */
DP_DECL_TEST_CASE(session_suite, session_tcp_lookup, NULL, NULL);
DP_START_TEST(session_tcp_lookup, test2)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	struct session *s1;
	struct session *s2;
	int rc;
	bool forw;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	int len = 22;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create forward and reverse packets */
	f = dp_test_create_tcp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, TH_SYN, 0, 0, 5840, NULL, 1, &len);

	r = dp_test_create_tcp_ipv4_pak("10.73.2.0", "10.73.0.0",
			1003, 1001, TH_SYN | TH_ACK, 0, 1, 5840, NULL, 1, &len);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s1, &created);

	/* Forward lookup */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session forward lookup: %d\n", rc);
	dp_test_fail_unless(forw == true, "session forward lookup: forw: %s\n",
			forw ? "true" : "false");

	/* Reverse lookup */
	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session reverse lookup: %d\n", rc);
	dp_test_fail_unless(s2 == s1, "session reverse lookup: bad sessions");
	dp_test_fail_unless(forw == false, "session reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/*
 * Test creation/lookup of an IPv4 ICMP session
 */
DP_DECL_TEST_CASE(session_suite, session_icmp_lookup, NULL, NULL);
DP_START_TEST(session_icmp_lookup, test3)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	struct session *s1;
	struct session *s2;
	int rc;
	bool forw;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	int len = 22;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create forward and reverse packets */
	f  = dp_test_create_icmp_ipv4_pak("10.73.0.0", "10.73.2.0",
			ICMP_ECHO, 0, DPT_ICMP_ECHO_DATA(0xac9, 1),
			1, &len, NULL, NULL, NULL);

	r  = dp_test_create_icmp_ipv4_pak("10.73.2.0", "10.73.0.0",
			ICMP_ECHOREPLY, 0, DPT_ICMP_ECHO_DATA(0xac9, 1),
			1, &len, NULL, NULL, NULL);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s1, &created);

	/* Forward lookup */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session forward lookup: %d\n", rc);
	dp_test_fail_unless(forw == true, "session forward lookup: forw: %s\n",
			forw ? "true" : "false");

	/* Reverse lookup */
	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session reverse lookup: %d\n", rc);
	dp_test_fail_unless(s2 == s1, "session reverse lookup: bad sessions");
	dp_test_fail_unless(forw == false, "session reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/*
 * Test creation/lookup of an IPv6 UDP session
 */
DP_DECL_TEST_CASE(session_suite, session_udp6_lookup, NULL, NULL);
DP_START_TEST(session_udp6_lookup, test4)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	struct session *s1;
	struct session *s2;
	int rc;
	bool forw;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	int len = 22;
	bool created;

	dp_test_nl_add_ip_addr_and_connected(IF_NAME, "2001:1:1::1/64");
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create forward and reverse packets */
	f = dp_test_create_udp_ipv6_pak("2010:73::", "2010:73:2::",
			1001, 1002, 1, &len);

	r = dp_test_create_udp_ipv6_pak("2010:73:2::", "2010:73::",
			1002, 1001, 1, &len);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s1, &created);

	/* Forward lookup */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session forward lookup: %d\n", rc);
	dp_test_fail_unless(forw == true, "session forward lookup: forw: %s\n",
			forw ? "true" : "false");

	/* Reverse lookup */
	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session reverse lookup: %d\n", rc);
	dp_test_fail_unless(s2 == s1, "session reverse lookup: bad sessions");
	dp_test_fail_unless(forw == false, "session reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);
	dp_test_nl_del_ip_addr_and_connected(IF_NAME, "2001:1:1::1/64");
} DP_END_TEST;

/*
 * Test creation/lookup of an IPv6 TCP session
 */
DP_DECL_TEST_CASE(session_suite, session_tcp6_lookup, NULL, NULL);
DP_START_TEST(session_tcp6_lookup, test5)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	struct session *s1;
	struct session *s2;
	int rc;
	bool forw;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	int len = 22;
	bool created;

	dp_test_nl_add_ip_addr_and_connected(IF_NAME, "2001:1:1::1/64");
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create forward and reverse packets */
	f = dp_test_create_tcp_ipv6_pak("2010:73::", "2010:73:2::",
			1001, 1003, TH_SYN, 0, 0, 5840, NULL, 1, &len);

	r = dp_test_create_tcp_ipv6_pak("2010:73:2::", "2010:73::",
			1003, 1001, TH_SYN | TH_ACK, 0, 0, 5840, NULL, 1, &len);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s1, &created);

	/* Forward lookup */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session forward lookup: %d\n", rc);
	dp_test_fail_unless(forw == true, "session forward lookup: forw: %s\n",
			forw ? "true" : "false");

	/* Reverse lookup */
	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session reverse lookup: %d\n", rc);
	dp_test_fail_unless(s2 == s1, "session reverse lookup: bad sessions");
	dp_test_fail_unless(forw == false, "session reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);
	dp_test_nl_del_ip_addr_and_connected(IF_NAME, "2001:1:1::1/64");
} DP_END_TEST;

/*
 * Test creation/lookup of an IPv6 ICMP session
 */
DP_DECL_TEST_CASE(session_suite, session_icmp6_lookup, NULL, NULL);
DP_START_TEST(session_icmp6_lookup, test6)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	struct session *s1;
	struct session *s2;
	int rc;
	bool forw;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	int len = 22;
	bool created;

	dp_test_nl_add_ip_addr_and_connected(IF_NAME, "2001:1:1::1/64");
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create forward and reverse packets */
	f  = dp_test_create_icmp_ipv6_pak("2010:73::", "2010:73:2::",
			ICMP6_ECHO_REQUEST, 0, DPT_ICMP_ECHO_DATA(0xac9, 1),
			1, &len, NULL, NULL, NULL);

	r  = dp_test_create_icmp_ipv6_pak("2010:73:2::", "2010:73::",
			ICMP6_ECHO_REPLY, 0, DPT_ICMP_ECHO_DATA(0xac9, 1),
			1, &len, NULL, NULL, NULL);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s1, &created);

	/* Forward lookup */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session forward lookup: %d\n", rc);
	dp_test_fail_unless(forw == true, "session forward lookup: forw: %s\n",
			forw ? "true" : "false");

	/* Reverse lookup */
	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session reverse lookup: %d\n", rc);
	dp_test_fail_unless(s2 == s1, "session reverse lookup: bad sessions");
	dp_test_fail_unless(forw == false, "session reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);
	dp_test_nl_del_ip_addr_and_connected(IF_NAME, "2001:1:1::1/64");
} DP_END_TEST;

/*
 * Test creation/lookup of an additional sentry
 */
DP_DECL_TEST_CASE(session_suite, session_sentry, NULL, NULL);
DP_START_TEST(session_sentry, test7)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	const struct ifnet *ifp;
	struct session *s1;
	struct session *s2;
	struct in6_addr saddr;
	struct in6_addr daddr;
	bool forw;
	char realname[IFNAMSIZ];
	int len = 22;
	int rc;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create a packet and session */
	f = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, 1, &len);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s1, &created);

	/* Now add a sentry to this session */
	inet_pton(AF_INET, "10.10.10.10", &saddr);
	inet_pton(AF_INET, "10.1.1.1", &daddr);
	rc = dp_test_session_sentry_insert(s1, ifp->if_index,
			SENTRY_FORW | SENTRY_IPv4,
			htons(42), &saddr, htons(4242), &daddr);
	dp_test_fail_unless(rc == 0, "session sentry_insert insert: %d\n", rc);

	/* Create another packet and lookup.  Session must match. */
	r = dp_test_create_udp_ipv4_pak("10.10.10.10", "10.1.1.1",
			42, 4242, 1, &len);

	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	if (rc) {
		unsigned long sen;
		unsigned long se;

		session_table_counts(&sen, &se);
		printf("counts: sen: %lu se: %lu\n", sen, se);
	}
	dp_test_fail_unless(rc == 0, "session sentry_insert lookup: %d\n", rc);
	dp_test_fail_unless(s1 == s2,
			"session sentry insert lookup: s1: %p s2: %p\n",
			s1, s2);
	dp_test_fail_unless(forw == true,
			"session sentry insert lookup: forw: %s\n",
			forw ? "true" : "false");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);

	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/* For session feature testing */
struct feature_data {
	int	destroy;
	int	expire;
};

static void feature_destroy(struct session *s __unused,
		uint32_t if_index __unused,
		enum session_feature_type type, void *data)
{
	struct feature_data *fd = data;

	if (fd)
		fd->destroy = 1;
}

static void feature_expire(struct session *s __unused,
		uint32_t if_index __unused,
		enum session_feature_type type, void *data)
{
	struct feature_data *fd = data;

	if (fd)
		fd->expire = 1;
}

static struct session_feature_ops ops = {
		.destroy = feature_destroy,
		.expired = feature_expire,
};

/*
 * Test session_features.
 */
DP_DECL_TEST_CASE(session_suite, session_feature, NULL, NULL);
DP_START_TEST(session_feature, test8)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	const struct ifnet *ifp;
	struct session *s1 = NULL;
	struct session *s2 = NULL;
	struct feature_data ifp_data = {0, 0};
	struct feature_data session_data = {0, 0};
	void *data;
	bool forw;
	char realname[IFNAMSIZ];
	int len = 22;
	int rc;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create a packet and session */
	f = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, 1, &len);

	session_feature_register(SESSION_FEATURE_TEST_INTERFACE, &ops);
	session_feature_register(SESSION_FEATURE_TEST, &ops);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s1, &created);

	/* Add interface-based feature data. */
	rc = dp_test_session_feature_add(s1, ifp->if_index,
			SESSION_FEATURE_TEST_INTERFACE, &ifp_data);
	dp_test_fail_unless(rc == 0, "session feature add failed %d\n", rc);

	/* Add session-based feature data. */
	rc = dp_test_session_feature_add(s1, 0, SESSION_FEATURE_TEST,
			&session_data);
	dp_test_fail_unless(rc == 0, "session feature add failed %d\n", rc);


	/* Create reverse packet and lookup - force a UDP state change */
	r = dp_test_create_udp_ipv4_pak("10.73.2.0", "10.73.0.0",
			1003, 1001, 1, &len);

	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0,
			"session feature reverse lookup: %d\n", rc);
	dp_test_fail_unless(s1 == s2,
			"session feature reverse lookup: s1 != s2\n");
	dp_test_fail_unless(forw == false,
			"session sentry insert reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	/* lookup the interface feature data, ensure proto op was called */
	data = dp_test_session_feature_get(s2, ifp->if_index,
			SESSION_FEATURE_TEST_INTERFACE);
	dp_test_fail_unless(data == &ifp_data, "session feature get %p != %p\n",
			data, &ifp_data);
	dp_test_fail_unless((ifp_data.expire == 0 && ifp_data.destroy == 0),
			"session feature get ifp_data: %d, %d\n",
			ifp_data.expire, ifp_data.destroy);

	/* lookup the session feature data, ensure proto op was called */
	data = session_feature_get(s2, 0, SESSION_FEATURE_TEST);
	dp_test_fail_unless(data == &session_data,
			"session feature get %p != %p\n", data, &session_data);
	dp_test_fail_unless(
			(session_data.expire == 0 && session_data.destroy == 0),
			"session feature get session_data: %d, %d\n",
			session_data.expire, session_data.destroy);

	/* Verify destroying interface data */
	rc = session_feature_request_expiry(s2, ifp->if_index,
			SESSION_FEATURE_TEST_INTERFACE);
	dp_test_fail_unless(rc == 0, "session feature request expiry rc: %d\n",
			    rc);
	/* Cleanup everything */
	dp_test_session_reset();

	dp_test_fail_unless(ifp_data.expire == 1,
			"session feature_delete ifp_data.expire: %d\n",
			ifp_data.expire);

	/*
	 * Verify that a session table expire function was called on
	 * the session feature data.  We didn't explicitly delete this
	 * feature.
	 */
	dp_test_fail_unless(session_data.destroy == 1,
			"session table expire session_data.destroy: %d\n",
			session_data.destroy);

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);

	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/*
 * Test expiration of an IPv4 UDP session
 */
DP_DECL_TEST_CASE(session_suite, session_expire, NULL, NULL);
DP_START_TEST(session_expire, test9)
{
	struct rte_mbuf *f;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	struct session *s;
	struct session *s2;
	bool forw;
	int len = 22;
	int rc;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create packet */
	f = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, 1, &len);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s, &created);

	/* Expire session and test */
	dp_test_session_expire(s, f);

	/* Lookup must fail with -ENOENT */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == -ENOENT, "session_lookup rc: %d\n", rc);

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/*
 * Test Linking of sessions
 *
 * Create 3 sessions, s, s2, and s3.
 *
 * Link as:  s ==> s2 ==> s3 and manipulate.
 *
 * Also test session_base_parent(), which traverses up the
 * linkage to the top level parent.
 */
DP_DECL_TEST_CASE(session_suite, session_link, NULL, NULL);
DP_START_TEST(session_link, test10)
{
	struct rte_mbuf *pkt[3];
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	struct session *s;
	struct session *s2;
	struct session *s3;
	struct session *s4;
	int len = 22;
	int rc;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create packets */
	pkt[0] = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, 1, &len);
	pkt[1] = dp_test_create_udp_ipv4_pak("10.73.8.0", "10.73.2.0",
			1001, 1003, 1, &len);
	pkt[2] = dp_test_create_udp_ipv4_pak("10.73.4.0", "10.73.2.0",
			1001, 1003, 1, &len);

	dp_test_fail_unless(pkt[0] && pkt[1] && pkt[2], "pkt create failed\n");

	/* Create sessions */
	dp_test_session_establish(pkt[0], ifp, 10, &s, &created);
	dp_test_session_establish(pkt[1], ifp, 10, &s2, &created);
	dp_test_session_establish(pkt[2], ifp, 10, &s3,  &created);

	/* Link s3 to s2, then s2 to s */
	rc = dp_test_session_link(s2, s3);
	dp_test_fail_unless(rc == 0, "session link failed %d\n", rc);

	rc = dp_test_session_link(s, s2);
	dp_test_fail_unless(rc == 0, "session link failed %d\n", rc);

	/* Check session base parent */
	s4 = session_base_parent(s3);
	dp_test_fail_unless(s4 == s, "session base parent failed\n");

	/* Unlink s2 and ensure it still has s3 */
	dp_test_session_unlink(s2);

	/* Check session base parent */
	s4 = session_base_parent(s3);
	dp_test_fail_unless(s4 == s2, "session base parent failed\n");

	/* Relink s2 to s */
	rc = dp_test_session_link(s, s2);
	dp_test_fail_unless(rc == 0, "session link failed %d\n", rc);


	/* Expire and ensure everybody is expired */
	dp_test_session_expire(s, NULL);

	dp_test_session_reset();

	rte_pktmbuf_free(pkt[0]);
	rte_pktmbuf_free(pkt[1]);
	rte_pktmbuf_free(pkt[2]);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/*
 * Test Linking of sessions
 *
 * Create 3 sessions, s, s2, and s3.
 *
 * Link as:  s ==> s2 ==> s3 and manipulate.
 *
 * Also test session_base_parent(), which traverses up the
 * linkage to the top level parent.
 */
DP_DECL_TEST_CASE(session_suite, session_unlink_all, NULL, NULL);
DP_START_TEST(session_unlink_all, test11)
{
	struct rte_mbuf *pkt[3];
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	struct session *s;
	struct session *s2;
	struct session *s3;
	struct session *s4;
	int len = 22;
	int rc;
	bool create;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create packets */
	pkt[0] = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, 1, &len);
	pkt[1] = dp_test_create_udp_ipv4_pak("10.73.8.0", "10.73.2.0",
			1001, 1003, 1, &len);
	pkt[2] = dp_test_create_udp_ipv4_pak("10.73.4.0", "10.73.2.0",
			1001, 1003, 1, &len);

	dp_test_fail_unless(pkt[0] && pkt[1] && pkt[2], "pkt create failed\n");

	/* Create sessions */
	dp_test_session_establish(pkt[0], ifp, 10, &s, &create);
	dp_test_session_establish(pkt[1], ifp, 10, &s2, &create);
	dp_test_session_establish(pkt[2], ifp, 10, &s3, &create);

	/* Link s3 to s2, then s2 to s */
	rc = dp_test_session_link(s2, s3);
	dp_test_fail_unless(rc == 0, "session link failed %d\n", rc);

	rc = dp_test_session_link(s, s2);
	dp_test_fail_unless(rc == 0, "session link failed %d\n", rc);

	/* Check session base parent */
	s4 = session_base_parent(s3);
	dp_test_fail_unless(s4 == s, "session base parent failed\n");

	/* Unlink everybody */
	dp_test_session_unlink_all(s);

	/* Expire and ensure everybody is expired */
	dp_test_session_expire(s, NULL);

	dp_test_session_reset();

	rte_pktmbuf_free(pkt[0]);
	rte_pktmbuf_free(pkt[1]);
	rte_pktmbuf_free(pkt[2]);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;
/*
 * Test GC timeout...
 *
 * Tests GC idle session removal.
 */
DP_DECL_TEST_CASE(session_suite, session_timeout, NULL, NULL);
DP_START_TEST(session_timeout, test12)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	struct session *s1;
	struct session *s2;
	unsigned long sen;
	unsigned long se;
	struct feature_data ifp_data = {0, 0};
	int rc;
	bool forw;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	int len = 22;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create forward and reverse packets */
	f = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, 1, &len);

	r = dp_test_create_udp_ipv4_pak("10.73.2.0", "10.73.0.0",
			1003, 1001, 1, &len);

	session_feature_register(SESSION_FEATURE_TEST_INTERFACE, &ops);

	/* Create session */
	dp_test_session_establish(f, ifp, 1, &s1, &created);

	/* Add interface-based feature data. */
	rc = dp_test_session_feature_add(s1, ifp->if_index,
			SESSION_FEATURE_TEST_INTERFACE, &ifp_data);
	dp_test_fail_unless(rc == 0,
			"session timeout: feature add failed %d\n", rc);

	/*
	 * Reverse lookup (force protocol change).  This forces a
	 * state change into the steady state. (At which point the
	 * custom etime will be referenced)
	 */
	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0,
			"session timeout: reverse lookup: %d\n", rc);
	dp_test_fail_unless(s2 == s1,
			"session timeout: reverse lookup: bad sessions");
	dp_test_fail_unless(forw == false,
			"session timeout: reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	/* Simulate the GC running for multiple periods */
	dp_test_session_gc();

	/*
	 * The feature 'destroy' op is run in the call_rcu context,
	 * so poll here to allow it to run.
	 */
	len = 5;
	while (len) {
		if (ifp_data.destroy)
			break;
		sleep(1);
		len--;
	}

	/* Ensure everything is cleared */
	session_table_counts(&sen, &se);
	dp_test_fail_unless(sen == 0 && se == 0,
			"session timeout:  bad counts: sen: %lu se: %lu\n",
			sen, se);

	/* Ensure we callbacks ran */
	dp_test_fail_unless(ifp_data.expire == 1,
			"session timeout:  feature expire not called\n");
	dp_test_fail_unless(ifp_data.destroy == 1,
			"session timeout:  feature destroy not called\n");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/*
 * Test various IPv4 ICMP scenarios.
 */
DP_DECL_TEST_CASE(session_suite, session_icmp_test, NULL, NULL);
DP_START_TEST(session_icmp_test, test14)
{
	struct rte_mbuf *tst;
	struct rte_mbuf *icmp_pak;
	struct session *se;
	int rc;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	int len = 22;
	struct iphdr *ip;
	struct icmphdr *icph;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Attempt session creation of a echo reply - must pass */
	icmp_pak  = dp_test_create_icmp_ipv4_pak("10.73.2.0", "10.73.0.0",
			ICMP_ECHOREPLY, 0, DPT_ICMP_ECHO_DATA(0xac9, 1),
			1, &len, NULL, NULL, NULL);

	rc = dp_test_session_establish(icmp_pak, ifp, 5, &se, &created);
	dp_test_fail_unless(rc == 0, "session echo reply create: %d\n",
			rc);
	rte_pktmbuf_free(icmp_pak);

	/* Attempt session creation of an unreach - must fail */
	tst = dp_test_create_ipv4_pak("1.1.1.2", "6.6.6.0", 1, &len);
	len = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
	icmp_pak = dp_test_create_icmp_ipv4_pak("1.1.1.1", "1.1.1.2",
			ICMP_DEST_UNREACH, ICMP_NET_UNREACH,
			DPT_ICMP_UNREACH_DATA(0), 1, &len, iphdr(tst),
			&ip, &icph);

	rc = session_establish(icmp_pak, ifp, 5, &se, &created);
	dp_test_fail_unless(rc == -EPERM, "session icmp unreach create: %d\n",
			rc);

	dp_test_session_reset();

	rte_pktmbuf_free(tst);
	rte_pktmbuf_free(icmp_pak);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/*
 * Test creation/lookup of an GRE PPTP session.
 */
DP_DECL_TEST_CASE(session_suite, session_pptp_lookup, NULL, NULL);
DP_START_TEST(session_pptp_lookup, test15)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	struct session *s1;
	struct session *s2;
	int rc;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	bool forw;
	void *payload;
	int len = 22;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create forward and reverse packets */
	f = dp_test_create_gre_pptp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1, &len, 42, 0, 0, &payload);

	r = dp_test_create_gre_pptp_ipv4_pak("10.73.2.0", "10.73.0.0",
			1, &len, 42, 0, 0, &payload);

	/* Create session */
	dp_test_session_establish(f, ifp, 10, &s1, &created);
	dp_test_fail_unless(created == true, "session pptp not created\n");

	/* Forward lookup */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session pptp forward lookup: %d\n", rc);
	dp_test_fail_unless(forw == true,
			"session pptp forward lookup: forw: %s\n",
			forw ? "true" : "false");

	/* Reverse lookup */
	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0, "session pptp reverse lookup: %d\n", rc);
	dp_test_fail_unless(s2 == s1,
			"session pptp reverse lookup: bad sessions");
	dp_test_fail_unless(forw == false,
			"session pptp reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/*
 * Test creation/lookup of session created from a sentry packet struct.
 */
DP_DECL_TEST_CASE(session_suite, session_sentry_packet, NULL, NULL);
DP_START_TEST(session_sentry_packet, test16)
{
	struct rte_mbuf *f;
	struct rte_mbuf *r;
	struct session *s1;
	struct session *s2;
	int rc;
	uint32_t saddr;
	uint32_t daddr;
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	struct sentry_packet sp_forw, sp_back;
	bool forw = true;
	int len = 22;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create forward and reverse packets */
	f = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, 1, &len);

	r = dp_test_create_udp_ipv4_pak("10.73.2.0", "10.73.0.0",
			1003, 1001, 1, &len);


	/* Init the sp struct. */
	inet_pton(AF_INET, "10.73.0.0", &saddr);
	inet_pton(AF_INET, "10.73.2.0", &daddr);

	rc = dp_test_session_init_sentry_packet(&sp_forw, ifp->if_index,
			SENTRY_IPv4, (uint8_t) IPPROTO_UDP, 1, htons(1001),
			&saddr, htons(1003), &daddr);
	dp_test_fail_unless(rc == 0, "session init sentry_packet: %d\n", rc);

	sentry_packet_reverse(&sp_forw, &sp_back);

	/* Create session */
	dp_test_session_create_from_sentry_packets(f, &sp_forw, &sp_back,
			ifp, 10, &s1, &created);

	/* Forward lookup */
	rc = dp_test_session_lookup(f, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0,
			"session sentry packet forward lookup: %d\n", rc);
	dp_test_fail_unless(forw == true,
			"session sentry packet forward lookup: forw: %s\n",
			forw ? "true" : "false");

	/* Reverse lookup, must succeed */
	rc = dp_test_session_lookup(r, ifp->if_index, &s2, &forw);
	dp_test_fail_unless(rc == 0,
			"session sentry packet reverse lookup: %d\n", rc);
	dp_test_fail_unless(s2 == s1,
			"session sentry packet reverse lookup: bad sessions");
	dp_test_fail_unless(forw == false,
			"session sentry packet reverse lookup: forw: %s\n",
			forw ? "true" : "false");

	dp_test_session_reset();

	rte_pktmbuf_free(f);
	rte_pktmbuf_free(r);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;

/* For link walk test below */
static void link_walk_cb(struct session *s, void *data)
{
	int *cnt = data;

	(*cnt)++;
}

/*
 * Test session link walk
 */
DP_DECL_TEST_CASE(session_suite, session_link_walk, NULL, NULL);
DP_START_TEST(session_link_walk, test18)
{
	struct rte_mbuf *pkt[3];
	const struct ifnet *ifp;
	char realname[IFNAMSIZ];
	struct session *s;
	struct session *s2;
	struct session *s3;
	int len = 22;
	int cnt = 0;
	int rc;
	bool created;

	dp_test_netlink_add_vrf(69, 1);

	dp_test_nl_add_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);
	dp_test_intf_real(IF_NAME, realname);
	ifp = ifnet_byifname(realname);

	/* Create packets */
	pkt[0] = dp_test_create_udp_ipv4_pak("10.73.0.0", "10.73.2.0",
			1001, 1003, 1, &len);
	pkt[1] = dp_test_create_udp_ipv4_pak("10.73.8.0", "10.73.2.0",
			1001, 1003, 1, &len);
	pkt[2] = dp_test_create_udp_ipv4_pak("10.73.4.0", "10.73.2.0",
			1001, 1003, 1, &len);

	dp_test_fail_unless(pkt[0] && pkt[1] && pkt[2], "pkt create failed\n");

	/* Create sessions */
	dp_test_session_establish(pkt[0], ifp, 100, &s, &created);
	dp_test_session_establish(pkt[1], ifp, 100, &s2, &created);
	dp_test_session_establish(pkt[2], ifp, 100, &s3, &created);

	/* Link s3 to s2, then s2 to s */
	rc = dp_test_session_link(s2, s3);
	dp_test_fail_unless(rc == 0, "session link failed %d\n", rc);

	rc = dp_test_session_link(s, s2);
	dp_test_fail_unless(rc == 0, "session link failed %d\n", rc);

	/*
	 * Call this directly, little can be done to validate within
	 * a wrapper.  Everybody should be unlinked, and the callback
	 * hit on 3 times.
	 */
	session_link_walk(s, true, link_walk_cb, &cnt);

	/* Must hit on cb 3 times */
	dp_test_fail_unless(cnt == 3,
			"session link walk: cb count: %u\n", cnt);

	/* Check grand parent */
	dp_test_fail_unless(rte_atomic16_read(&s->se_link_cnt) == 0,
			"session link walk: link count: %u\n",
			rte_atomic16_read(&s->se_link_cnt));
	dp_test_fail_unless(cds_list_empty(&s->se_link->sl_children),
			"session link walk: list children\n");

	/* Check s2 */
	dp_test_fail_unless(rte_atomic16_read(&s2->se_link_cnt) == 0,
			"session link walk: link count: %u\n",
			rte_atomic16_read(&s2->se_link_cnt));
	dp_test_fail_unless(cds_list_empty(&s2->se_link->sl_children),
			"session link walk: list children\n");

	/* Check s3 */
	dp_test_fail_unless(rte_atomic16_read(&s3->se_link_cnt) == 0,
			"session link walk: link count: %u\n",
			rte_atomic16_read(&s3->se_link_cnt));
	dp_test_fail_unless(cds_list_empty(&s3->se_link->sl_children),
			"session link walk: list children\n");

	/* Clean up */
	dp_test_session_reset();

	rte_pktmbuf_free(pkt[0]);
	rte_pktmbuf_free(pkt[1]);
	rte_pktmbuf_free(pkt[2]);
	dp_test_nl_del_ip_addr_and_connected_vrf(IF_NAME, "1.1.1.1/24", 69);

	dp_test_netlink_del_vrf(69, 0);
} DP_END_TEST;
