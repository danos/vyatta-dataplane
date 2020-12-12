/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
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
#include <rte_acl.h>
#include <rte_ip.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include "ip_funcs.h"
#include "ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "rldb.h"

#include "dp_test.h"

#define ANY_PROTO 0

static struct rldb_db_handle *dh4, *dh6;

static int _add_rule(uint32_t rule_no, uint32_t prio, uint8_t proto,
		     const char *saddr, uint8_t smasklen,
		     const char *daddr, uint8_t dmasklen,
		     uint16_t sloport, uint16_t shiport,
		     uint16_t dloport, uint16_t dhiport,
		     struct rldb_rule_handle **rule_handle)
{

	uint8_t abytes[16];
	struct rldb_rule_spec rule = { 0 };
	uint8_t af = AF_INET6;
	char *colon;
	struct rldb_db_handle *dh;

	if (!saddr || !daddr || rule_no == 0 || !rule_handle)
		return -EINVAL;

	colon = strchr(saddr, ':');
	if (!colon)
		af = AF_INET;

	switch (af) {
	case AF_INET:
		dh = dh4;
		rule.rldb_flags |= NPFRL_FLAG_V4_PFX;
		break;
	case AF_INET6:
		dh = dh6;
		rule.rldb_flags |= NPFRL_FLAG_V6_PFX;
		break;
	default:
		ck_assert_msg(false, "Unexpected AF");
		return -EAFNOSUPPORT;
	}

	rule.rldb_priority = prio;

	if (proto) {
		rule.rldb_flags |= NPFRL_FLAG_PROTO;
		rule.rldb_proto.npfrl_proto = proto;
	}

	/* src */
	rule.rldb_flags |= NPFRL_FLAG_SRC_PFX;
	ck_assert(inet_pton(af, saddr, abytes) == 1);

	if (af == AF_INET6) {
		struct rldb_v6_prefix *pfx = &rule.rldb_src_addr.v6_pfx;
		memcpy(pfx->npfrl_bytes, abytes,
		       sizeof(pfx->npfrl_bytes));
		pfx->npfrl_plen = smasklen;

	} else if (af == AF_INET) {
		struct rldb_v4_prefix *pfx = &rule.rldb_src_addr.v4_pfx;
		memcpy(pfx->npfrl_bytes, (void *)abytes,
		       sizeof(pfx->npfrl_bytes));
		pfx->npfrl_plen = smasklen;
	} else {
		ck_assert_msg(false, "Unexpected AF");
		return -EAFNOSUPPORT;
	}

	/* dst */
	rule.rldb_flags |= NPFRL_FLAG_DST_PFX;
	ck_assert(inet_pton(af, daddr, abytes) == 1);

	if (af == AF_INET6) {
		struct rldb_v6_prefix *pfx = &rule.rldb_dst_addr.v6_pfx;
		memcpy(pfx->npfrl_bytes, abytes,
		       sizeof(pfx->npfrl_bytes));
		pfx->npfrl_plen = dmasklen;
	} else if (af == AF_INET) {
		struct rldb_v4_prefix *pfx = &rule.rldb_dst_addr.v4_pfx;
		memcpy(pfx->npfrl_bytes, (void *)abytes,
		       sizeof(pfx->npfrl_bytes));
		pfx->npfrl_plen = dmasklen;
	} else {
		ck_assert_msg(false, "Unexpected AF");
		return -EAFNOSUPPORT;
	}

	if (sloport || shiport) {
		rule.rldb_flags |= NPFRL_FLAG_SRC_PORT_RANGE;
		rule.rldb_src_port_range.npfrl_loport = sloport;
		rule.rldb_src_port_range.npfrl_hiport = shiport;
	}

	if (dloport || dhiport) {
		rule.rldb_flags |= NPFRL_FLAG_DST_PORT_RANGE;
		rule.rldb_dst_port_range.npfrl_loport = dloport;
		rule.rldb_dst_port_range.npfrl_hiport = dhiport;
	}

	return rldb_add_rule(dh, rule_no, &rule, rule_handle);
}

static int match_packet4(const char *saddr_pkt, const char *daddr_pkt,
			 uint16_t sport_pkt, uint16_t dport_pkt)
{
	const int len = 22;
	struct rldb_result results[1];
	struct rte_mbuf *pkt;
	struct rte_mbuf *m[1];
	int rc;

	pkt =
	    dp_test_create_udp_ipv4_pak(saddr_pkt, daddr_pkt, sport_pkt,
					dport_pkt, 1, &len);
	m[0] = pkt;
	rc = rldb_match(dh4, m, 1, results);
	rte_pktmbuf_free(pkt);
	if (rc && rc != -ENOENT)
		return rc;

	return results[0].rldb_rule_no;

}

static int match_packet6(const char *saddr_pkt, const char *daddr_pkt,
			 uint16_t sport_pkt, uint16_t dport_pkt)
{
	const int len = 22;
	struct rldb_result results[1];
	struct rte_mbuf *pkt;
	struct rte_mbuf *m[1];
	int rc;

	pkt =
	    dp_test_create_udp_ipv6_pak(saddr_pkt, daddr_pkt, sport_pkt,
					dport_pkt, 1, &len);
	m[0] = pkt;
	rc = rldb_match(dh6, m, 1, results);
	rte_pktmbuf_free(pkt);
	if (rc && rc != -ENOENT)
		return rc;

	return results[0].rldb_rule_no;

}

static int match_packet_tcp4(const char *saddr_pkt, const char *daddr_pkt,
			     uint16_t sport_pkt, uint16_t dport_pkt)
{
	int rc;
	const int len = 22;
	struct rldb_result results;
	struct rte_mbuf *pkt;
	struct rte_mbuf *m[1];

	pkt =
	    dp_test_create_tcp_ipv4_pak(saddr_pkt, daddr_pkt, sport_pkt,
					dport_pkt, 0, 1, 0, 0, NULL, 1, &len);
	m[0] = pkt;
	rc = rldb_match(dh4, m, 1, &results);
	rte_pktmbuf_free(pkt);
	return rc;
}

static int add_rule(uint32_t rule_no, uint32_t prio, uint8_t proto,
		    const char *saddr, uint8_t smasklen,
		    const char *daddr, uint8_t dmasklen,
		    uint16_t sloport, uint16_t shiport,
		    uint16_t dloport, uint16_t dhiport)
{
	struct rldb_rule_handle *rule_handle;
	int rc;

	char *colon;
	struct rldb_db_handle *dh = dh6;

	colon = strchr(saddr, ':');
	if (!colon)
		dh = dh4;

	rc = rldb_start_transaction(dh);
	ck_assert_msg(rc == 0, "Failed to start transaction");

	rc = _add_rule(rule_no, prio, proto,
		       saddr, smasklen,
		       daddr, dmasklen,
		       sloport, shiport, dloport, dhiport, &rule_handle);
	ck_assert_msg(rc == 0, "Failed to add IPv4 rule");

	rc = rldb_commit_transaction(dh);
	ck_assert_msg(rc == 0, "Failed to commit transaction");

	return rc;
}

static void rldb_setup(void)
{
	int rc;

	rc = rldb_create("test4", NPFRL_FLAG_V4_PFX, &dh4);
	ck_assert(rc == 0);

	rc = rldb_create("test6", NPFRL_FLAG_V6_PFX, &dh6);
	ck_assert(rc == 0);
}

static void rldb_teardown(void)
{
	rldb_destroy(dh4);
	dh4 = NULL;
	rldb_destroy(dh6);
	dh6 = NULL;
}

DP_DECL_TEST_SUITE(rldb_suite);
DP_DECL_TEST_CASE(rldb_suite, rldb_rule, rldb_setup, rldb_teardown);

DP_START_TEST(rldb_rule, delete)
{
	int rc;
	int rule_no = 42;
	struct rldb_rule_handle *rule_handle, *rule_handle_unused;
	struct rldb_db_handle *dh = dh4;

	rc = rldb_start_transaction(dh);
	ck_assert_msg(rc == 0, "Failed to start transaction");

	for (int i = 0; i < 100; i++)
		_add_rule(1000 + i, 123, 0, "41.0.0.0", 24, "30.0.0.0", 24, 0,
			  0, 0, 0, &rule_handle_unused);

	rc = _add_rule(rule_no, 123, 0, "40.0.0.0", 24, "30.0.0.0", 24, 0, 0, 0,
		       0, &rule_handle);
	ck_assert_msg(rc == 0, "Failed to add IPv4 rule");

	for (int i = 0; i < 100; i++)
		_add_rule(2000 + i, 123, 0, "42.0.0.0", 24, "30.0.0.0", 24, 0,
			  0, 0, 0, &rule_handle_unused);

	rc = rldb_commit_transaction(dh);
	ck_assert_msg(rc == 0, "Failed to commit transaction");

	ck_assert_msg(match_packet4("40.0.0.0", "30.0.0.0", 8888, 8888) ==
		      rule_no, "Verify rule installation by matching");

	printf("BEFORE DELETE:\n");
	rte_acl_list_dump();
	printf("\n");

	rc = rldb_start_transaction(dh);
	ck_assert_msg(rc == 0, "Failed to start transaction #2");

	rc = rldb_del_rule(dh, rule_handle);
	ck_assert_msg(rc == 0, "Failed delete rule");

	rc = rldb_commit_transaction(dh);
	ck_assert_msg(rc == 0, "Failed to commit transaction #2");


	printf("AFTER DELETE:\n");
	rte_acl_list_dump();
	printf("\n");

	ck_assert_msg(match_packet4("40.0.0.0", "30.0.0.0", 8888, 8888) !=
		      rule_no, "Verify rule removal by negative matching");
} DP_END_TEST;

DP_START_TEST(rldb_rule, match_ipv6)
{
	add_rule(6, 1000, ANY_PROTO, "30::0", 24, "40::0", 24, 0, 0, 0, 0);
	ck_assert_msg(match_packet6("30::1", "40::1", 8888, 8888) == 6,
		      "Addresses-only policy");
	ck_assert_msg(match_packet6("30::1:1", "40::0:1", 8888, 8888) != 0,
		      "Negative addresses-only policy");
	ck_assert_msg(match_packet6("30::0:1", "40::1:1", 8888, 8888) != 0,
		      "Negative addresses-only policy");
} DP_END_TEST;

DP_START_TEST(rldb_rule, match_ipv4)
{
	add_rule(6, 1000, ANY_PROTO, "30.0.0.0", 24, "40.0.0.0", 24, 0, 0, 0,
		 0);
	ck_assert_msg(match_packet4("30.0.0.1", "40.0.0.1", 8888, 8888) == 6,
		      "Addresses-only policy");
	ck_assert_msg(match_packet4("30.0.1.1", "40.0.0.1", 8888, 8888) != 0,
		      "Negative addresses-only policy");
	ck_assert_msg(match_packet4("30.0.0.1", "40.0.1.1", 8888, 8888) != 0,
		      "Negative addresses-only policy");
	add_rule(7, 1000, IPPROTO_UDP, "31.0.0.0", 24, "41.0.0.0", 24, 0, 0, 0,
		 0);
	ck_assert_msg(match_packet4("31.0.0.1", "41.0.0.1", 8888, 8888) == 7,
		      "Protocol-only policy");
	ck_assert_msg(match_packet_tcp4("31.0.0.1", "41.0.0.1", 8888, 8888) !=
		      0, "Negative protocol-only policy");

	add_rule(8, 1000, ANY_PROTO, "32.0.0.1", 32, "42.2.0.1", 32, 0, 0, 0,
		 0);
	ck_assert_msg(match_packet4("32.0.0.1", "42.2.0.1", 8888, 8888) == 8,
		      "Host-to-host policy");
	ck_assert_msg(match_packet4("32.0.0.2", "42.2.0.1", 8888, 8888) != 0,
		      "Negative host-policy source");
	ck_assert_msg(match_packet4("32.0.0.1", "42.2.0.2", 8888, 8888) != 0,
		      "Negative host-policy destination");

	add_rule(9, 1000, ANY_PROTO, "33.0.0.0", 24, "0.0.0.0", 0, 0, 0, 0, 0);
	ck_assert_msg(match_packet4("33.0.0.1", "123.0.0.1", 8888, 8888) == 9,
		      "Anycast destination");
	ck_assert_msg(match_packet4("33.3.3.1", "123.0.0.1", 8888, 8888) != 0,
		      "Negative anycast destination");

	add_rule(10, 1000, IPPROTO_UDP, "33.0.1.0", 24, "0.0.0.0", 0, 8888,
		 8888, 8888, 8888);
	ck_assert_msg(match_packet4("33.0.1.1", "123.0.0.1", 8888, 8888) == 10,
		      "Anycast destination & port");
	ck_assert_msg(match_packet4("33.0.1.1", "123.0.0.1", 8887, 8888) != 0,
		      "Negative anycast destination & port");

	add_rule(11, 1000, IPPROTO_UDP, "34.0.0.0", 24, "44.0.0.0", 24, 8888,
		 8888, 8888, 8888);
	ck_assert_msg(match_packet4("34.0.0.1", "44.0.0.1", 8888, 8888) == 11,
		      "Protocol & port");
	ck_assert_msg(match_packet4("34.0.0.1", "44.0.0.1", 40, 40) != 0,
		      "Negative protocol & port");

	add_rule(1, 1, ANY_PROTO, "0.0.0.0", 0, "0.0.0.0", 0, 0, 0, 0, 0);
	ck_assert_msg(match_packet4("34.0.0.1", "44.0.0.1", 40, 40) == 1,
		      "Catch all rule");
} DP_END_TEST;
