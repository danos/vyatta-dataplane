/**
 * @file dp_test_lib_pkt.c
 * @brief Packet library
 *
 * This contains library functions for creating test packets and test expect
 * object.
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in6.h"
#include "ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"

/*
 * Generate a reverse flow packet descriptor from forwards flow packet
 * descriptor
 */
static void
dp_test_pkt_reverse_desc(const struct dp_test_pkt_desc_t *fwd,
			 struct dp_test_pkt_desc_t *rev)
{
	rev->text = fwd->text;
	rev->len = fwd->len;
	rev->ether_type = fwd->ether_type;
	rev->l3_src = fwd->l3_dst;
	rev->l2_src = fwd->l2_dst;
	rev->l3_dst = fwd->l3_src;
	rev->l2_dst = fwd->l2_src;
	rev->proto = fwd->proto;

	rev->rx_intf = fwd->tx_intf;
	rev->tx_intf = fwd->rx_intf;

	switch (fwd->proto) {
	case IPPROTO_TCP:
		rev->l4.tcp.sport = fwd->l4.tcp.dport;
		rev->l4.tcp.dport = fwd->l4.tcp.sport;
		rev->l4.tcp.flags = 0; /* TODO */
		rev->l4.tcp.seq = 0;
		rev->l4.tcp.ack = 0;
		rev->l4.tcp.win = 0;
		rev->l4.tcp.opts = NULL;
		break;

	case IPPROTO_UDP:
		rev->l4.udp.sport = fwd->l4.udp.dport;
		rev->l4.udp.dport = fwd->l4.udp.sport;
		break;

	case IPPROTO_ICMP:
		switch (fwd->l4.icmp.type) {
		case ICMP_ECHO:
			rev->l4.icmp.type = ICMP_ECHOREPLY;
			break;
		default:
			rev->l4.icmp.type = fwd->l4.icmp.type;
			break;
		}
		/* TODO: These will likely need customized .. */
		rev->l4.icmp.code    = fwd->l4.icmp.code;
		rev->l4.icmp.udata32 = fwd->l4.icmp.udata32;
		break;

	case IPPROTO_ICMPV6:
		switch (fwd->l4.icmp.type) {
		case ICMP6_ECHO_REQUEST:
			rev->l4.icmp.type = ICMP6_ECHO_REPLY;
			break;
		default:
			rev->l4.icmp.type = fwd->l4.icmp.type;
			break;
		}
		/* TODO: These will likely need customized .. */
		rev->l4.icmp.code    = fwd->l4.icmp.code;
		rev->l4.icmp.udata32 = fwd->l4.icmp.udata32;
		break;

	default:
		break;
	}
}

/*
 * Create an IPv4 packet from a packet descriptor
 */
static struct rte_mbuf *
_dp_test_v4_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
			  const char *file, int line)
{
	struct rte_mbuf *mbuf;

	switch (pdesc->proto) {
	case IPPROTO_TCP:
		mbuf = dp_test_create_tcp_ipv4_pak(pdesc->l3_src,
						   pdesc->l3_dst,
						   pdesc->l4.tcp.sport,
						   pdesc->l4.tcp.dport,
						   pdesc->l4.tcp.flags,
						   pdesc->l4.tcp.seq,
						   pdesc->l4.tcp.ack,
						   pdesc->l4.tcp.win,
						   pdesc->l4.tcp.opts,
						   1, &pdesc->len);
		break;

	case IPPROTO_UDP:
		mbuf = dp_test_create_udp_ipv4_pak(pdesc->l3_src,
						   pdesc->l3_dst,
						   pdesc->l4.udp.sport,
						   pdesc->l4.udp.dport,
						   1, &pdesc->len);
		break;

	case IPPROTO_ICMP:
		mbuf = dp_test_create_icmp_ipv4_pak(pdesc->l3_src,
						    pdesc->l3_dst,
						    pdesc->l4.icmp.type,
						    pdesc->l4.icmp.code,
						    pdesc->l4.icmp.udata32,
						    1, &pdesc->len,
						    NULL, NULL, NULL);
		break;
	case IPPROTO_GRE:
		mbuf = dp_test_create_gre_ipv4_pak(pdesc->l3_src,
						   pdesc->l3_dst,
						   1, &pdesc->len,
						   pdesc->l4.gre.prot,
						   pdesc->l4.gre.key,
						   pdesc->l4.gre.seq,
						   NULL);
		break;
	default:
		mbuf = dp_test_create_raw_ipv4_pak(pdesc->l3_src,
						   pdesc->l3_dst,
						   pdesc->proto,
						   1, &pdesc->len);
	}

	_dp_test_fail_unless(mbuf != NULL, file, line,
			     "\nFailed to create IPv4 pak from desc\n");

	if (pdesc->traf_class != 0) {
		struct iphdr *ip = iphdr(mbuf);

		dp_test_set_pak_ip_field(ip, DP_TEST_SET_TOS,
					 pdesc->traf_class);
	}

	return mbuf;
}

/*
 * Create an IPv6 packet from a packet descriptor
 */
static struct rte_mbuf *
_dp_test_v6_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
			  const char *file, int line)
{
	struct rte_mbuf *mbuf;

	switch (pdesc->proto) {
	case IPPROTO_TCP:
		mbuf = dp_test_create_tcp_ipv6_pak(pdesc->l3_src,
						   pdesc->l3_dst,
						   pdesc->l4.tcp.sport,
						   pdesc->l4.tcp.dport,
						   pdesc->l4.tcp.flags,
						   pdesc->l4.tcp.seq,
						   pdesc->l4.tcp.ack,
						   pdesc->l4.tcp.win,
						   pdesc->l4.tcp.opts,
						   1, &pdesc->len);
		break;

	case IPPROTO_UDP:
		mbuf = dp_test_create_udp_ipv6_pak(pdesc->l3_src,
						   pdesc->l3_dst,
						   pdesc->l4.udp.sport,
						   pdesc->l4.udp.dport,
						   1, &pdesc->len);
		break;

	case IPPROTO_ICMPV6:
		mbuf = dp_test_create_icmp_ipv6_pak(pdesc->l3_src,
						    pdesc->l3_dst,
						    pdesc->l4.icmp.type,
						    pdesc->l4.icmp.code,
						    pdesc->l4.icmp.udata32,
						    1, &pdesc->len,
						    NULL, NULL, NULL);
		break;
	default:
		mbuf = dp_test_create_raw_ipv6_pak(pdesc->l3_src,
						   pdesc->l3_dst,
						   pdesc->proto,
						   1, &pdesc->len);
	}

	_dp_test_fail_unless(mbuf != NULL, file, line,
			     "\nFailed to create IPv6 pak from desc\n");

	if (pdesc->traf_class != 0) {
		struct ip6_hdr *ip6 = ip6hdr(mbuf);

		ip6->ip6_flow &= ~IPV6_TCLASS_MASK;
		ip6->ip6_flow |= htonl(pdesc->traf_class << 20);
	}
	return mbuf;
}

/*
 * Create a packet from a packet descriptor
 */
static struct rte_mbuf *
_dp_test_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
		       const char *file, int line)
{
	struct rte_mbuf *mbuf;

	switch (pdesc->ether_type) {
	case RTE_ETHER_TYPE_IPV4:
		mbuf = _dp_test_v4_pkt_from_desc(pdesc, file, line);
		break;
	case RTE_ETHER_TYPE_IPV6:
		mbuf = _dp_test_v6_pkt_from_desc(pdesc, file, line);
		break;
	default:
		mbuf = dp_test_create_l2_pak(pdesc->l2_dst, pdesc->l2_src,
					     pdesc->ether_type, 1, &pdesc->len);

		_dp_test_fail_unless(mbuf != NULL, file, line,
				     "\nFailed to create l2 pak from desc\n");

	}
	return mbuf;
}

/*
 * Create a 'to-be-routed' packet from a packet descriptor
 *
 * The intention is that the packet will be routed, so the destination MAC
 * address is set to the rx_intf MAC address
 */
struct rte_mbuf *
_dp_test_rt_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
			  const char *file, int line)
{
	struct rte_mbuf *mbuf;

	mbuf = _dp_test_pkt_from_desc(pdesc, file, line);
	if (!mbuf)
		return NULL;

	_dp_test_fail_unless(pdesc->rx_intf != NULL, file, line,
			     "\nNULL rx_intf\n");

	_dp_test_fail_unless(pdesc->l2_src != NULL, file, line,
			     "\nNULL l2_src\n");

	dp_test_pktmbuf_eth_init(mbuf,
				 dp_test_intf_name2mac_str(pdesc->rx_intf),
				 pdesc->l2_src, pdesc->ether_type);

	return mbuf;
}

/*
 * Create a reverse-flow 'to-be-routed' packet from a packet descriptor
 */
struct rte_mbuf *
_dp_test_reverse_rt_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
				  const char *file, int line)
{
	struct dp_test_pkt_desc_t rev = {0};

	_dp_test_fail_unless(pdesc->tx_intf != NULL, file, line,
			     "\nNULL tx_intf\n");

	_dp_test_fail_unless(pdesc->l2_dst != NULL, file, line,
			     "\nNULL l2_dst\n");

	dp_test_pkt_reverse_desc(pdesc, &rev);
	return _dp_test_rt_pkt_from_desc(&rev, file, line);
}

/*
 * Create a packet from the slow-path i.e. either originated from the kernel,
 * or forwarded (bridged or routed) by the kernel.
 */
struct rte_mbuf *
_dp_test_from_spath_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
				  const char *file, int line)
{
	struct rte_mbuf *mbuf;

	mbuf = _dp_test_pkt_from_desc(pdesc, file, line);

	if (!mbuf)
		return NULL;

	_dp_test_fail_unless(pdesc->l2_dst != NULL, file, line,
			     "\nNULL l2_dst\n");

	/*
	 * Determine source MAC address.  Use l2_src if it is specified, else
	 * use the tx_intf MAC address
	 */
	const char *smac;

	if (pdesc->l2_src)
		smac = pdesc->l2_src;
	else {
		_dp_test_fail_unless(pdesc->tx_intf != NULL, file, line,
				     "\nNULL tx_intf\n");
		smac = dp_test_intf_name2mac_str(pdesc->tx_intf);
	}

	dp_test_pktmbuf_eth_init(mbuf, pdesc->l2_dst, smac,
				 pdesc->ether_type);

	return mbuf;
}

/*
 * Create a bridge packet from a packet descriptor
 *
 * Destination MAC is set to be the destination host MAC address
 */
struct rte_mbuf *
_dp_test_bridge_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
			      const char *file, int line)
{
	struct rte_mbuf *mbuf;

	mbuf = _dp_test_pkt_from_desc(pdesc, file, line);

	_dp_test_fail_unless(pdesc->l2_src != NULL, file, line,
			     "\nNULL l2_src\n");

	_dp_test_fail_unless(pdesc->l2_dst != NULL, file, line,
			     "\nNULL l2_dst\n");

	dp_test_pktmbuf_eth_init(mbuf, pdesc->l2_dst, pdesc->l2_src,
				 pdesc->ether_type);

	return mbuf;
}

/*
 * Create an expect object for a routed packet from a packet descriptor and
 * packet mbuf
 */
struct dp_test_expected *
_dp_test_exp_from_desc(struct rte_mbuf *mbuf,
		       const struct dp_test_pkt_desc_t *pdesc,
		       struct dp_test_expected *mexp,
		       uint pktno, bool multiple,
		       const char *file, int line)
{
	struct dp_test_expected *exp;
	struct rte_mbuf *exp_mbuf;

	_dp_test_fail_unless(pdesc->tx_intf != NULL, file, line,
			     "\nNULL tx_intf\n");

	_dp_test_fail_unless(pdesc->l2_dst != NULL, file, line,
			     "\nNULL l2_dst\n");

	if (multiple) {
		if (pktno == 0)
			exp = dp_test_exp_create_m(mbuf, 1);
		else {
			exp = mexp;
			dp_test_exp_append_m(exp, mbuf, 1);
		}
		exp_mbuf = dp_test_exp_get_pak_m(exp, pktno);

		dp_test_exp_set_oif_name_m(exp, pktno, pdesc->tx_intf);
	} else {
		exp = dp_test_exp_create(mbuf);
		exp_mbuf = dp_test_exp_get_pak(exp);

		dp_test_exp_set_oif_name(exp, pdesc->tx_intf);
	}


	/*
	 * Setup ethernet header
	 */
	dp_test_pktmbuf_eth_init(exp_mbuf, pdesc->l2_dst,
				 dp_test_intf_name2mac_str(pdesc->tx_intf),
				 pdesc->ether_type);

	/*
	 * Decrement TTL and recalc checksum for routed packets
	 */
	switch (pdesc->ether_type) {
	case RTE_ETHER_TYPE_IPV4:
		dp_test_ipv4_decrement_ttl(exp_mbuf);
		break;
	case RTE_ETHER_TYPE_IPV6:
		dp_test_ipv6_decrement_ttl(exp_mbuf);
		break;
	default:
		break;
	}
	return exp;
}

/*
 * Create an expect object from the reverse of a packet descriptor
 */
struct dp_test_expected *
_dp_test_reverse_exp_from_desc(struct rte_mbuf *mbuf,
			       const struct dp_test_pkt_desc_t *pdesc,
			       const char *file, int line)
{
	struct dp_test_pkt_desc_t rev = {0};

	dp_test_pkt_reverse_desc(pdesc, &rev);
	return _dp_test_exp_from_desc(mbuf, &rev, NULL, 0, false, file, line);
}

