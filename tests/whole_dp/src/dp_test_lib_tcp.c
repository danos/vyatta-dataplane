/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test TCP library
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "netinet6/ip6_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_str.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_tcp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_console.h"


/*
 * dp_test_tcp_flag2str
 *
 * Returns a flags string from TCP flags.  Uses a static buffer, so string
 * should be used immediately.
 *
 * Individual flag strings are separated with the delim string, if one is
 * given, otherwise they are separated with a comma and space.
 */
char *
dp_test_tcp_flag2str(uint8_t flags, const char *delim)
{
	static char str[120];
	uint l = 0;

	if (flags == 0) {
		snprintf(str, sizeof(str), "0");
		return str;
	}

	if (!delim)
		delim = DPT_TCP_FLAG_DELIM_COMMA;

	str[0] = '\0';

	dp_test_fail_unless(TH_CWR == 0x80,
			    "TH_CWR is 0x%02X, expected 0x80", TH_CWR);
	dp_test_fail_unless(TH_ECE == 0x40,
			    "TH_ECE is 0x%02X, expected 0x40", TH_ECE);

	if (flags & TH_CWR)
		l += snprintf(str+l, sizeof(str)-1, "CWR%s", delim);

	if (flags & TH_ECE)
		l += snprintf(str+l, sizeof(str)-1, "ECE%s", delim);

	if (flags & TH_URG)
		l += snprintf(str+l, sizeof(str)-1, "URG%s", delim);

	if (flags & TH_PUSH)
		l += snprintf(str+l, sizeof(str)-1, "PUSH%s", delim);

	if (flags & TH_RST)
		l += snprintf(str+l, sizeof(str)-1, "RST%s", delim);

	if (flags & TH_SYN)
		l += snprintf(str+l, sizeof(str)-1, "SYN%s", delim);

	if (flags & TH_FIN)
		l += snprintf(str+l, sizeof(str)-1, "FIN%s", delim);

	if (flags & TH_ACK)
		l += snprintf(str+l, sizeof(str)-1, "ACK%s", delim);

	/* Remove the last delimiter */
	if (l > strlen(delim))
		str[l-strlen(delim)] = '\0';

	return str;
}


/***************************************************************************
 * TCP Flow Testing
 **************************************************************************/

/*
 * Create an IPv4 TCP or UDP packet descriptor
 */
struct dp_test_pkt_desc_t *
dpt_pdesc_v4_create(const char *text, uint8_t proto,
		    const char *l2_src, const char *l3_src, uint16_t sport,
		    const char *l2_dst, const char *l3_dst, uint16_t dport,
		    const char *rx_intf, const char *tx_intf)
{
	struct dp_test_pkt_desc_t *pkt;

	pkt = calloc(1, sizeof(*pkt));

	pkt->text = text;
	pkt->proto = proto;
	pkt->ether_type = RTE_ETHER_TYPE_IPV4;
	pkt->l2_src = l2_src;
	pkt->l3_src = l3_src;
	pkt->l4.tcp.sport = sport;
	pkt->l4.tcp.dport = dport;
	pkt->l2_dst = l2_dst;
	pkt->l3_dst = l3_dst;
	pkt->rx_intf = rx_intf;
	pkt->tx_intf = tx_intf;

	if (proto == IPPROTO_TCP)
		pkt->l4.tcp.win = 8192;

	return pkt;
}

/*
 * Create an IPv6 TCP or UDP packet descriptor
 */
struct dp_test_pkt_desc_t *
dpt_pdesc_v6_create(const char *text, uint8_t proto,
		    const char *l2_src, const char *l3_src, uint16_t sport,
		    const char *l2_dst, const char *l3_dst, uint16_t dport,
		    const char *rx_intf, const char *tx_intf)
{
	struct dp_test_pkt_desc_t *pkt;

	pkt = calloc(1, sizeof(*pkt));

	pkt->text = text;
	pkt->proto = proto;
	pkt->ether_type = RTE_ETHER_TYPE_IPV6;
	pkt->l2_src = l2_src;
	pkt->l3_src = l3_src;
	pkt->l4.tcp.sport = sport;
	pkt->l4.tcp.dport = dport;
	pkt->l2_dst = l2_dst;
	pkt->l3_dst = l3_dst;
	pkt->rx_intf = rx_intf;
	pkt->tx_intf = tx_intf;

	if (proto == IPPROTO_TCP)
		pkt->l4.tcp.win = 8192;

	return pkt;
}

/*
 * Write TCP payload, and re-calc checksums
 */
void
dpt_tcp_write_v4_payload(struct rte_mbuf *m, uint plen, const char *payload)
{
	struct iphdr *ip;
	struct tcphdr *tcp;
	char *datap;

	if (!m || plen == 0 || !payload)
		return;

	ip = iphdr(m);
	tcp = (struct tcphdr *)(ip + 1);
	tcp->check = 0;

	datap = (char *)tcp + (tcp->doff << 2);
	memcpy(datap, payload, plen);

	ip->check = 0;
	ip->check = ip_checksum(ip, ip->ihl*4);

	tcp->check = dp_test_ipv4_udptcp_cksum(m, ip, tcp);
}

void
dpt_tcp_write_v6_payload(struct rte_mbuf *m, uint plen, const char *payload)
{
	struct ip6_hdr *ip6;
	struct tcphdr *tcp;
	char *datap;

	if (!m || plen == 0 || !payload)
		return;

	ip6 = ip6hdr(m);
	tcp = (struct tcphdr *)(ip6 + 1);
	tcp->check = 0;

	datap = (char *)tcp + (tcp->doff << 2);
	memcpy(datap, payload, plen);

	tcp->check = dp_test_ipv6_udptcp_cksum(m, ip6, tcp);
}

struct tcp_call_ctx {
	bool		do_check;
	validate_cb	saved_cb;
};

static struct tcp_call_ctx tcp_call_ctx = {
	.do_check = true,
	.saved_cb = dp_test_pak_verify,
};

static void
dpt_tcp_call_validate_cb(struct rte_mbuf *pak, struct ifnet *ifp,
			 struct dp_test_expected *exp,
			 enum dp_test_fwd_result_e fwd_result)
{
	struct tcp_call_ctx *ctx = dp_test_exp_get_validate_ctx(exp);
	struct tcphdr *tcp, *exp_tcp;
	struct rte_mbuf *exp_pak;
	struct iphdr *ip;
	uint32_t l3_len;
	bool dbg = false;

	const char *file = exp->file;
	int line = exp->line;

	/* Rcvd pak */
	ip = iphdr(pak);
	l3_len = ip->ihl << 2;
	tcp = (struct tcphdr *)((char *)ip + l3_len);

	/* Exp pak */
	exp_pak = dp_test_exp_get_pak(exp);
	ip = iphdr(exp_pak);
	l3_len = ip->ihl << 2;
	exp_tcp = (struct tcphdr *)((char *)ip + l3_len);

	if (dbg)
		printf("TCP seq %u, ack %u\n",
		       ntohl(tcp->th_seq), ntohl(tcp->th_ack));

	/*
	 * Highlight any errors with the TCP seq and ack numbers before the
	 * main check routine
	 */
	if (tcp->th_seq != exp_tcp->th_seq || tcp->th_ack != exp_tcp->th_ack) {
		printf("\033[1m\033[31m%s %i\033[0m\n", file,  line);

		printf("  Expected TCP SEQ %u, rcvd %u\n",
		       ntohl(exp_tcp->th_seq), ntohl(tcp->th_seq));

		printf("  Expected TCP ACK %u, rcvd %u\n",
		       ntohl(exp_tcp->th_ack), ntohl(tcp->th_ack));
	}

	/* call the saved check routine */
	if (ctx->do_check) {
		(ctx->saved_cb)(pak, ifp, exp, fwd_result);
	} else {
		exp->pak_correct[0] = true;
		exp->pak_checked[0] = true;
	}
}

/*
 * Setup and inject packet for a TCP flow
 */
static void _dpt_tcp_pak_receive(uint pktno, struct dpt_tcp_flow *call,
				 struct dpt_tcp_flow_pkt *df,
				 void *ctx_ptr, uint ctx_uint,
				 const char *file, int line)
{
	struct dp_test_pkt_desc_t *pre;
	struct dp_test_pkt_desc_t *post;
	bool dir = df->forw;
	bool rev = (dir == DPT_FORW) ? DPT_BACK : DPT_FORW;
	uint8_t flags = df->flags;
	char str[120];
	bool is_v6;

	pre = call->desc[dir].pre;
	post = call->desc[dir].pst;

	is_v6 = (pre->ether_type == RTE_ETHER_TYPE_IPV6);

	/*
	 * If data is a string, then dlen will be set to zero to indicate we
	 * need to call strlen for it.
	 */
	if (df->pre_dlen == 0 && df->pre_data != NULL) {
		df->pre_dlen = strnlen(df->pre_data, 2000);
		dp_test_fail_unless(df->pre_dlen < 2000,
				    "Pre data is not a string");
	}

	if (df->pst_dlen == 0 && df->pst_data != NULL) {
		df->pst_dlen = strnlen(df->pst_data, 2000);
		dp_test_fail_unless(df->pst_dlen < 2000,
				    "Pst data is not a string");
	}

	const char *dir_str = (dir == DPT_FORW) ? "OUT" : "IN";

	snprintf(str, sizeof(str),
		 "[%2u] %s %s, flags 0x%02x", pktno, call->text,
		 dir_str, flags);

	/*
	 * Adjust the pre and post pkt descriptors
	 */
	pre->l4.tcp.flags = flags;
	post->l4.tcp.flags = flags;

	/* Post data is same as pre data unless otherwise specd */
	if (df->pst_dlen == 0 || !df->pst_data) {
		df->pst_dlen = df->pre_dlen;
		df->pst_data = df->pre_data;
	}

	pre->len = df->pre_dlen;
	post->len = df->pst_dlen;

	/* Set pre-nat seq/ack */
	pre->l4.tcp.seq = call->seq[dir];
	pre->l4.tcp.ack = call->ack[dir];

	/* Adjust post-nat seq/ack with diffs */
	post->l4.tcp.seq = pre->l4.tcp.seq + call->diff[dir];
	post->l4.tcp.ack = pre->l4.tcp.ack - call->diff[rev];

	/* Set ack that will be used in next pkt in other direction */
	call->ack[rev] = call->seq[dir] + post->len;

	/* Set seq for next pkt in this direction */
	call->seq[dir] += pre->len;

	/* Update cumulative payload difference for this direction */
	call->diff[dir] += (post->len - pre->len);

	/*
	 * Callback may change the packet, result and/or next callback
	 * function
	 */
	if (call->test_cb) {
		(*call->test_cb)(str, pktno, dir, flags, pre, post,
				 ctx_ptr, ctx_uint);
	} else {
		struct rte_mbuf *pre_pak, *post_pak;
		struct dp_test_expected *test_exp;

		if (!is_v6) {
			pre_pak = dp_test_v4_pkt_from_desc(pre);
			post_pak = dp_test_v4_pkt_from_desc(post);

			if (df->pre_dlen > 0 && df->pre_data)
				dpt_tcp_write_v4_payload(
					pre_pak, df->pre_dlen,
					df->pre_data);

			if (df->pst_dlen > 0 && df->pst_data)
				dpt_tcp_write_v4_payload(
					post_pak, df->pst_dlen,
					df->pst_data);
		} else {
			pre_pak = dp_test_v6_pkt_from_desc(pre);
			post_pak = dp_test_v6_pkt_from_desc(post);

			if (df->pre_dlen > 0 && df->pre_data)
				dpt_tcp_write_v6_payload(
					pre_pak, df->pre_dlen,
					df->pre_data);

			if (df->pst_dlen > 0 && df->pst_data)
				dpt_tcp_write_v6_payload(
					post_pak, df->pst_dlen,
					df->pst_data);
		}

		test_exp = dp_test_exp_from_desc(post_pak, post);
		rte_pktmbuf_free(post_pak);
		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		spush(test_exp->description, sizeof(test_exp->description),
		      "%s", str);

		dp_test_exp_set_validate_ctx(test_exp, &tcp_call_ctx, false);
		dp_test_exp_set_validate_cb(test_exp, dpt_tcp_call_validate_cb);


		/* Run the test */
		_dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp,
				     file, __func__, line);
	}

	if (call->post_cb)
		(*call->post_cb)(pktno, dir, flags, pre, post, str);

}

/*
 * TCP call
 *
 * call      Packet descriptors for forw and back packets
 * df_array  Array of direction, flags and pkt size tuples,
 *           one for each packet to be sent
 * df_array_size
 * first     Index of first pkt in df_array
 * last      Index of last pkt in df_array (if > 0 and < df_array_size)
 * ctx_ptr   Pointer context to pass to test_cb
 * ctx_uint  Uint context to pass to test_cb
 */
void _dpt_tcp_call(struct dpt_tcp_flow *call, struct dpt_tcp_flow_pkt *df_array,
		   size_t df_array_size, uint first, uint last,
		   void *ctx_ptr, uint ctx_uint, const char *file, int line)
{
	uint pktno;

	call->seq[DPT_FORW] = 1;
	call->seq[DPT_BACK] = 1;
	call->ack[DPT_FORW] = 0;
	call->ack[DPT_BACK] = 0;
	call->diff[DPT_FORW] = 0;
	call->diff[DPT_BACK] = 0;

	if (last == 0 || last >= df_array_size)
		last = df_array_size - 1;

	for (pktno = first; pktno <= last; pktno++)
		_dpt_tcp_pak_receive(pktno, call, &df_array[pktno],
				     ctx_ptr, ctx_uint, file, line);
}
