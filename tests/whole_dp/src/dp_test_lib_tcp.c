/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test TCP library
 */

#include <libmnl/libmnl.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"

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

/*
 * Write TCP payload, and re-calc checksums
 */
void
dp_test_tcp_write_payload(struct rte_mbuf *m, uint plen, const char *payload)
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

static void
dp_test_tcp_pak_receive(uint pktno,
			struct dp_test_tcp_call *call,
			enum dp_test_tcp_dir dir, uint8_t flags,
			uint dlen, char *data,
			void *ctx_ptr, uint ctx_uint)
{
	struct dp_test_pkt_desc_t *pre;
	struct dp_test_pkt_desc_t *post;
	enum dp_test_tcp_dir rev = DP_DIR_REVERSE(dir);
	char str[80];

	spush(str, sizeof(str),
	      "%s, Pkt #%u %s, flags 0x%x", call->str, pktno,
	      dir == DP_DIR_FORW ? "FORW":"BACK", flags);

	/*
	 * Make copies of the pre and post pkt descriptors in case test_cb
	 * wants to modify them.
	 */
	struct dp_test_pkt_desc_t pre_copy = *call->desc[dir].pre;
	struct dp_test_pkt_desc_t post_copy = *call->desc[dir].post;

	pre = &pre_copy;
	post = &post_copy;

	pre->l4.tcp.flags = flags;
	post->l4.tcp.flags = flags;
	pre->len = post->len = dlen;

	pre->l4.tcp.seq = call->seq[dir] + call->isn[dir];
	post->l4.tcp.seq = call->seq[dir] + call->isn[dir];

	pre->l4.tcp.ack = call->ack[dir];
	post->l4.tcp.ack = call->ack[dir];

	if (flags & (TH_FIN | TH_SYN))
		call->seq[dir] += 1;
	else
		call->seq[dir] += post->len;

	call->ack[rev] = call->seq[dir];

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

		pre_pak = dp_test_v4_pkt_from_desc(pre);
		post_pak = dp_test_v4_pkt_from_desc(post);

		if (dlen > 0 && data) {
			dp_test_tcp_write_payload(pre_pak, dlen, data);
			dp_test_tcp_write_payload(post_pak, dlen, data);
		}

		test_exp = dp_test_exp_from_desc(post_pak, post);
		rte_pktmbuf_free(post_pak);
		dp_test_exp_set_fwd_status(test_exp, DP_TEST_FWD_FORWARDED);

		spush(test_exp->description, sizeof(test_exp->description),
		      "%s", str);

		/* Run the test */
		dp_test_pak_receive(pre_pak, pre->rx_intf, test_exp);
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
 * ctx_ptr   Pointer context to pass to test_cb
 * ctx_uint  Uint context to pass to test_cb
 */
void
dp_test_tcp_call(struct dp_test_tcp_call *call,
		 struct dp_test_tcp_flow_pkt *df_array,
		 size_t df_array_size,
		 void *ctx_ptr, uint ctx_uint)
{
	struct dp_test_tcp_desc *forw, *back;
	uint pktno;

	forw = &call->desc[DP_DIR_FORW];
	back = &call->desc[DP_DIR_BACK];

	call->seq[DP_DIR_FORW] = 0;
	call->seq[DP_DIR_BACK] = 0;
	call->ack[DP_DIR_FORW] = 0;
	call->ack[DP_DIR_BACK] = 0;

	forw->pre->l4.tcp.seq = 0;
	forw->pre->l4.tcp.ack = 0;
	forw->post->l4.tcp.seq = 0;
	forw->post->l4.tcp.ack = 0;
	back->pre->l4.tcp.seq = 0;
	back->pre->l4.tcp.ack = 0;
	back->post->l4.tcp.seq = 0;
	back->post->l4.tcp.ack = 0;

	for (pktno = 0; pktno < df_array_size; pktno++) {
		dp_test_tcp_pak_receive(pktno, call,
					df_array[pktno].dir,
					df_array[pktno].flags,
					df_array[pktno].dlen,
					df_array[pktno].data,
					ctx_ptr, ctx_uint);
	}
}
