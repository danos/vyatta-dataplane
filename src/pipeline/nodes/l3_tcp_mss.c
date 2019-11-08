/*
 * TCP MSS Clamp pipeline feature node
 *
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet6/in6.h>
#include <linux/if.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <urcu/list.h>

#include "compiler.h"
#include "dp_event.h"
#include "if_var.h"
#include "in_cksum.h"
#include "npf/npf_mbuf.h"
#include "pktmbuf.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "util.h"
#include "vplane_log.h"

#include "protobuf.h"
#include "protobuf/TCPMSSConfig.pb-c.h"

/* Ignore L3 options for MSS calculation */
static uint tcp_mss_l3_overhead[TCP_MSS_AF_SIZE] = {
	sizeof(struct ip) + sizeof(struct tcphdr),
	sizeof(struct ip6_hdr) + sizeof(struct tcphdr)
};

/*
 * TCP MSS clamp types:
 *
 * TCP_MSS_MTU       - clamp to interface MTU
 * TCP_MSS_MTU_MINUS - clamp to interface MTU, less a value
 * TCP_MSS_LIMIT     - clamp to configured value
 */
enum tcp_mss_type {
	TCP_MSS_NONE,
	TCP_MSS_MTU,
	TCP_MSS_MTU_MINUS,
	TCP_MSS_LIMIT,
};
#define TCP_MSS_MAX TCP_MSS_LIMIT

/*
 * Temporary store for configuration for situations where the configuration
 * arrives in the dataplane before the interface netlink message, e.g. vif
 * interfaces.
 *
 * We wait for the interface to be created, and then replay the configuration
 * command.  The list entry is deleted after the command is successfully
 * replayed.
 */
static struct cds_list_head *if_list;
static int if_list_count;

/*
 * Entries are identified by name and af
 */
struct tcp_mss_if_list_entry {
	struct cds_list_head  le_node;
	char                  le_ifname[IFNAMSIZ];
	enum tcp_mss_af       le_af;
	char                  *le_buf;
	char                  **le_argv;
	int                   le_argc;
};

/*
 * If an mss option is found, returns offset from start of TCP options to MSS
 * value.  Returns 0 if no MSS option found.
 */
static uint
tcp_fetch_mss(struct rte_mbuf *mbuf, uint16_t l3_len, int opts_len,
	      uint16_t *mss)
{
	uint offset = 0, mss_offset = 0;
	uint8_t buf[40];
	uint8_t *opts;

	/* Max TCP options length is 40 bytes */
	if ((ulong)opts_len > sizeof(buf))
		return 0;

	/*
	 * If TCP options are not in the first mbuf, then copy out to stack
	 * buffer.  This returns NULL if the packet is fragmented such that
	 * all the requested data is not in the packet.
	 */
	opts = (uint8_t *)rte_pktmbuf_read(mbuf, pktmbuf_l2_len(mbuf) +
					   l3_len + sizeof(struct tcphdr),
					   opts_len, buf);
	if (!opts)
		return 0;

	while (opts_len > 0) {
		uint8_t len;

		switch (opts[0]) {
		case TCPOPT_EOL:
			/* Done. */
			return 0;

		case TCPOPT_NOP:
			opts_len--;
			opts += 1;
			offset += 1;
			break;

		case TCPOPT_MAXSEG:
			/* Fetch the option length value, and verify it */
			len = opts[1];

			if (len != TCPOLEN_MAXSEG || len > opts_len)
				return 0;

			/* Fetch the MSS value */
			*mss = *(uint16_t *)(opts + 2);

			mss_offset = offset + 2;

			/* We are not interested in further options */
			return mss_offset;

		default:
			/* Fetch the option length value */
			len = opts[1];

			if (len < 2 || len > opts_len)
				return 0;

			opts += len;
			opts_len -= len;
			offset += len;
			break;
		}
	}
	return 0;
}


/*
 * Clamp the MSS.  Returns true if clamped, else false. '*mss' is in network
 * byte order.
 *
 * If clamping relative to the interface mtu, then we need to subtract the
 * basic IP/IPv6 and TCP header lengths (ignoring options) from the MTU value.
 *
 * The absolute minimum value that MSS may be clamped to is 1.
 */
static void
tcp_mss_clamp(struct rte_mbuf **mbuf, enum tcp_mss_af af, struct ifnet *ifp,
	      uint16_t l3_len, uint16_t opts_len, uint16_t mss,
	      uint mss_offset)
{
	uint16_t delta, orig_mss, mss_max;
	uint overhead;
	uint16_t sum;
	void *n_ptr;
	int rc;

	orig_mss = mss;
	mss_max = 1;

	if (ifp->tcp_mss_type[af] == TCP_MSS_LIMIT) {
		mss_max = ifp->tcp_mss_value[af];
	} else {
		overhead = tcp_mss_l3_overhead[af] + ifp->tcp_mss_value[af];

		if (ifp->if_mtu > overhead)
			mss_max = ifp->if_mtu - overhead;
	}

	if (ntohs(mss) <= mss_max)
		return;

	/*
	 * Need to clamp mss ...
	 */
	mss = htons(mss_max);

	/*
	 * If the buffer is shared, alloc a new header mbuf that
	 * includes the TCP header and options.
	 */
	rc = pktmbuf_prepare_for_header_change(
		mbuf,
		pktmbuf_l2_len(*mbuf) +
		l3_len +
		sizeof(struct tcphdr) + opts_len);
	if (rc)
		return;

	/* Update MSS in mbuf */
	n_ptr = rte_pktmbuf_mtod_offset(*mbuf, char *,
					pktmbuf_l2_len(*mbuf) + l3_len);
	rc = nbuf_advstore(mbuf, &n_ptr, mss_offset, sizeof(mss), &mss);
	if (rc)
		return;

	/* Calculate the TCP checksum delta */
	delta = ip_partial_chksum_adjust(0xFFFF, orig_mss, mss);

	/* byte-swap the delta if the MSS is on an odd-byte boundary */
	if (mss_offset & 1)
		delta = (delta >> 8) | (delta << 8);

	/* Update TCP checksum in mbuf */
	n_ptr = rte_pktmbuf_mtod_offset(*mbuf, char *,
					pktmbuf_l2_len(*mbuf) + l3_len);

	rc = nbuf_advfetch(mbuf, &n_ptr,
			   offsetof(struct tcphdr, check),
			   sizeof(sum), &sum);
	if (rc)
		return;

	sum = ip_fixup16_cksum(sum, 0, delta);
	nbuf_advstore(mbuf, &n_ptr, 0, sizeof(sum), &sum);
}

/*
 * l4_offset - offset of TCP header from start of IP
 */
static void __noinline
tcp_mss_process_common(struct rte_mbuf **mbuf, uint8_t *l3_hdr,
		       enum tcp_mss_af af, struct ifnet *ifp, uint16_t l3_len)
{
	uint16_t mss, off_flags;
	struct tcphdr *tcp_hdr;
	uint8_t tcp_flags;
	int opts_len, rc;
	uint mss_offset;
	void *n_ptr;

	tcp_hdr = (struct tcphdr *)(l3_hdr + l3_len);

	/* Advance mbuf and fetch TCP data offset and flags */
#define DOFF_STEP 12
	n_ptr = (void *)tcp_hdr;
	off_flags = 0;

	rc = nbuf_advfetch(mbuf, &n_ptr, DOFF_STEP, sizeof(off_flags),
			   &off_flags);
	if (unlikely(rc < 0))
		return;

	tcp_flags = off_flags >> 8;

	if (likely((tcp_flags & TH_SYN) == 0))
		return;

	/* TCP hdr size, in words, is in upper 4 bits of lower byte */
	opts_len = ((off_flags >> 2) & 0x3C) - sizeof(struct tcphdr);

	if (likely(opts_len <= 0))
		return;

	mss_offset = tcp_fetch_mss(*mbuf, l3_len, opts_len, &mss);

	if (mss_offset)
		tcp_mss_clamp(mbuf, af, ifp, l3_len, opts_len, mss,
			      mss_offset + sizeof(struct tcphdr));
}

/*
 * IPv4 input node
 */
ALWAYS_INLINE unsigned int
ipv4_tcp_mss_in_process(struct pl_packet *pkt)
{
	struct rte_mbuf *mbuf = pkt->mbuf;
	struct iphdr *ip = pkt->l3_hdr;
	uint16_t l3_len;

	if (likely(pkt->in_ifp->tcp_mss_type[TCP_MSS_V4] == TCP_MSS_NONE))
		return IPV4_TCP_MSS_IN_CONTINUE;

	if (ip->protocol != IPPROTO_TCP)
		return IPV4_TCP_MSS_IN_CONTINUE;

	l3_len = ip->ihl << 2;
	tcp_mss_process_common(&mbuf, pkt->l3_hdr, TCP_MSS_V4, pkt->in_ifp,
			       l3_len);

	/* mbuf may have changed */
	if (mbuf != pkt->mbuf) {
		pkt->mbuf = mbuf;
		pkt->l3_hdr = pktmbuf_mtol3(mbuf, void *);
	}

	return IPV4_TCP_MSS_IN_CONTINUE;
}

/*
 * IPv6 input node
 */
ALWAYS_INLINE unsigned int
ipv6_tcp_mss_in_process(struct pl_packet *pkt)
{
	struct rte_mbuf *mbuf = pkt->mbuf;
	uint8_t ipproto;
	uint16_t l3_len;

	if (likely(pkt->in_ifp->tcp_mss_type[TCP_MSS_V6] == TCP_MSS_NONE))
		return IPV6_TCP_MSS_IN_CONTINUE;

	ipproto = ip6_findpayload(pkt->mbuf, &l3_len);

	if (ipproto != IPPROTO_TCP)
		return IPV6_TCP_MSS_IN_CONTINUE;

	l3_len -= pktmbuf_l2_len(pkt->mbuf);
	tcp_mss_process_common(&mbuf, pkt->l3_hdr, TCP_MSS_V6, pkt->in_ifp,
			       l3_len);

	/* mbuf may have changed */
	if (mbuf != pkt->mbuf) {
		pkt->mbuf = mbuf;
		pkt->l3_hdr = pktmbuf_mtol3(mbuf, void *);
	}

	return IPV6_TCP_MSS_IN_CONTINUE;
}

/* Register Node */
PL_REGISTER_NODE(ipv4_tcp_mss_in_node) = {
	.name = "vyatta:ipv4-tcp-mss-in",
	.type = PL_PROC,
	.handler = ipv4_tcp_mss_in_process,
	.num_next = IPV4_TCP_MSS_IN_NUM,
	.next = {
		[IPV4_TCP_MSS_IN_CONTINUE] = "term-noop",
	}
};

PL_REGISTER_NODE(ipv6_tcp_mss_in_node) = {
	.name = "vyatta:ipv6-tcp-mss-in",
	.type = PL_PROC,
	.handler = ipv6_tcp_mss_in_process,
	.num_next = IPV6_TCP_MSS_IN_NUM,
	.next = {
		[IPV6_TCP_MSS_IN_CONTINUE] = "term-noop",
	}
};

PL_REGISTER_FEATURE(ipv4_tcp_mss_in_feat) = {
	.name = "vyatta:ipv4-tcp-mss-in",
	.node_name = "ipv4-tcp-mss-in",
	.feature_point = "ipv4-validate",
	.id = PL_L3_V4_IN_FUSED_FEAT_TCP_MSS,
	.visit_after = "vyatta:ipv4-rpf",
};

PL_REGISTER_FEATURE(ipv6_tcp_mss_in_feat) = {
	.name = "vyatta:ipv6-tcp-mss-in",
	.node_name = "ipv6-tcp-mss-in",
	.feature_point = "ipv6-validate",
	.id = PL_L3_V6_IN_FUSED_FEAT_TCP_MSS,
};

/*
 * IPv4 output node
 */
ALWAYS_INLINE unsigned int
ipv4_tcp_mss_out_process(struct pl_packet *pkt)
{
	struct rte_mbuf *mbuf = pkt->mbuf;
	struct iphdr *ip = pkt->l3_hdr;
	uint16_t l3_len;

	if (likely(pkt->out_ifp->tcp_mss_type[TCP_MSS_V4] == TCP_MSS_NONE))
		return IPV4_TCP_MSS_OUT_CONTINUE;

	if (ip->protocol != IPPROTO_TCP)
		return IPV4_TCP_MSS_OUT_CONTINUE;

	l3_len = ip->ihl << 2;
	tcp_mss_process_common(&mbuf, pkt->l3_hdr, TCP_MSS_V4, pkt->out_ifp,
			       l3_len);

	/* mbuf may have changed */
	if (mbuf != pkt->mbuf) {
		pkt->mbuf = mbuf;
		pkt->l3_hdr = pktmbuf_mtol3(mbuf, void *);
	}

	return IPV4_TCP_MSS_OUT_CONTINUE;
}

/*
 * IPv6 output node
 */
ALWAYS_INLINE unsigned int
ipv6_tcp_mss_out_process(struct pl_packet *pkt)
{
	struct rte_mbuf *mbuf = pkt->mbuf;
	uint8_t ipproto;
	uint16_t l3_len;

	if (likely(pkt->out_ifp->tcp_mss_type[TCP_MSS_V6] == TCP_MSS_NONE))
		return IPV6_TCP_MSS_OUT_CONTINUE;

	ipproto = ip6_findpayload(pkt->mbuf, &l3_len);

	if (ipproto != IPPROTO_TCP)
		return IPV6_TCP_MSS_OUT_CONTINUE;

	l3_len -= pktmbuf_l2_len(pkt->mbuf);
	tcp_mss_process_common(&mbuf, pkt->l3_hdr, TCP_MSS_V6, pkt->out_ifp,
			       l3_len);

	/* mbuf may have changed */
	if (mbuf != pkt->mbuf) {
		pkt->mbuf = mbuf;
		pkt->l3_hdr = pktmbuf_mtol3(mbuf, void *);
	}

	return IPV6_TCP_MSS_OUT_CONTINUE;
}

/* Register Output Node */
PL_REGISTER_NODE(ipv4_tcp_mss_out_node) = {
	.name = "vyatta:ipv4-tcp-mss-out",
	.type = PL_PROC,
	.handler = ipv4_tcp_mss_out_process,
	.num_next = IPV4_TCP_MSS_OUT_NUM,
	.next = {
		[IPV4_TCP_MSS_OUT_CONTINUE] = "term-noop",
	}
};

PL_REGISTER_NODE(ipv6_tcp_mss_out_node) = {
	.name = "vyatta:ipv6-tcp-mss-out",
	.type = PL_PROC,
	.handler = ipv6_tcp_mss_out_process,
	.num_next = IPV6_TCP_MSS_OUT_NUM,
	.next = {
		[IPV6_TCP_MSS_OUT_CONTINUE] = "term-noop",
	}
};

PL_REGISTER_FEATURE(ipv4_tcp_mss_out_feat) = {
	.name = "vyatta:ipv4-tcp-mss-out",
	.node_name = "ipv4-tcp-mss-out",
	.feature_point = "ipv4-out",
	.id = PL_L3_V4_OUT_FUSED_FEAT_TCP_MSS,
};

PL_REGISTER_FEATURE(ipv6_tcp_mss_out_feat) = {
	.name = "vyatta:ipv6-tcp-mss-out",
	.node_name = "ipv6-tcp-mss-out",
	.feature_point = "ipv6-out",
	.id = PL_L3_V6_OUT_FUSED_FEAT_TCP_MSS,
};

/*
 * Lookup interface name and address family in list
 */
static struct tcp_mss_if_list_entry *
tcp_mss_if_list_lookup(const char *ifname, enum tcp_mss_af af)
{
	struct tcp_mss_if_list_entry *le;

	if (!if_list)
		return NULL;

	cds_list_for_each_entry(le, if_list, le_node) {
		if (!strcmp(ifname, le->le_ifname) && af == le->le_af)
			return le;
	}
	return NULL;
}

static struct cds_list_head *
tcp_mss_if_list_get_or_create(void)
{
	if (!if_list) {
		if_list = zmalloc_aligned(sizeof(*if_list));
		if (!if_list)
			return NULL;

		CDS_INIT_LIST_HEAD(if_list);
		if_list_count = 0;
	}
	return if_list;
}

static int
tcp_mss_if_list_destroy(void)
{
	if (if_list && if_list_count == 0) {
		free(if_list);
		if_list = NULL;
	}
	return 0;
}

static int
tcp_mss_if_list_del(const char *ifname, enum tcp_mss_af af)
{
	struct tcp_mss_if_list_entry *le;

	if (!if_list || if_list_count == 0)
		return -ENOENT;

	le = tcp_mss_if_list_lookup(ifname, af);
	if (!le)
		return -ENOENT;

	cds_list_del(&le->le_node);
	if_list_count--;

	if (le->le_buf)
		free(le->le_buf);
	if (le->le_argv)
		free(le->le_argv);
	free(le);

	if (if_list_count == 0)
		tcp_mss_if_list_destroy();

	return 0;
}

/*
 * TCP MSS configuration has arrived in dataplane before interface has been
 * created.
 */
static int
tcp_mss_if_list_add(char *ifname, enum tcp_mss_af af,
		    char *msg, int len)
{
	static struct cds_list_head *list;
	struct tcp_mss_if_list_entry *le;

	if (strlen(ifname) + 1 > IFNAMSIZ)
		return -EINVAL;

	/* Get or create if_list global */
	list = tcp_mss_if_list_get_or_create();
	if (!list)
		return -ENOMEM;

	le = tcp_mss_if_list_lookup(ifname, af);
	if (!le) {
		le = zmalloc_aligned(sizeof(*le));
		if (!le)
			return -ENOMEM;

		memcpy(le->le_ifname, ifname, strlen(ifname) + 1);
		le->le_af = af;

		cds_list_add_tail(&le->le_node, list);
		if_list_count++;
	} else {
		/* MSS config has changed. Free buffer and argv array. */
		free(le->le_buf);
		free(le->le_argv);
	}

	le->le_buf = malloc(len);
	le->le_argv = NULL;
	le->le_argc = len;

	if (!le->le_buf) {
		tcp_mss_if_list_del(ifname, af);
		return -ENOMEM;
	}

	memcpy(le->le_buf, msg, len);
	return 0;
}

/*
 * <intf> {limit <value> | mtu | mtu-minus <value>}
 */
static int
tcp_mss_feat_enable_cmd(TCPMSSConfig *tcpmss_msg, struct pb_msg *msg)
{

	struct ifnet *ifp;
	int rc;

	ifp = ifnet_byifname(tcpmss_msg->ifname);
	if (!ifp) {
		enum tcp_mss_af af = TCP_MSS_V4;
		if (tcpmss_msg->af == TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6)
			af = TCP_MSS_V6;

		rc = tcp_mss_if_list_add(tcpmss_msg->ifname, af,
					 msg->msg, msg->msg_len);
		return rc;
	}

	assert(ARRAY_SIZE(ifp->tcp_mss_type) == TCP_MSS_AF_SIZE);
	assert(ARRAY_SIZE(ifp->tcp_mss_value) == TCP_MSS_AF_SIZE);

	if (tcpmss_msg->mtu_option == TCPMSSCONFIG__MTUTYPE__MTU) {
		ifp->tcp_mss_type[tcpmss_msg->af] = TCP_MSS_MTU;
		ifp->tcp_mss_value[tcpmss_msg->af] = 0;
	} else {
		if (tcpmss_msg->mtu_option == TCPMSSCONFIG__MTUTYPE__MTU_MINUS)
			ifp->tcp_mss_type[tcpmss_msg->af] = TCP_MSS_MTU_MINUS;
		else if (tcpmss_msg->mtu_option == TCPMSSCONFIG__MTUTYPE__LIMIT)
			ifp->tcp_mss_type[tcpmss_msg->af] = TCP_MSS_LIMIT;
		else {
			pb_cmd_err(msg, "Bad option %d\n",
				   tcpmss_msg->mtu_option);
			return -EINVAL;
		}

		/* 'val' is allowed to be 1-UINT16_MAX */
		if (tcpmss_msg->value == 0 || tcpmss_msg->value > UINT16_MAX) {
			pb_cmd_err(msg, "Bad value %d\n", tcpmss_msg->value);
			return -EINVAL;
		}

		ifp->tcp_mss_value[tcpmss_msg->af] = tcpmss_msg->value;
	}

	if (tcpmss_msg->af ==  TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4) {
		pl_node_add_feature(&ipv4_tcp_mss_in_feat, ifp->if_name);
		pl_node_add_feature(&ipv4_tcp_mss_out_feat, ifp->if_name);
	} else {
		pl_node_add_feature(&ipv6_tcp_mss_in_feat, ifp->if_name);
		pl_node_add_feature(&ipv6_tcp_mss_out_feat, ifp->if_name);
	}

	return 1;
}

/*
 * <intf>
 */
static int
tcp_mss_feat_disable_cmd(TCPMSSConfig *tcpmss_msg, struct pb_msg *msg)
{
	struct ifnet *ifp;
	int ret;

	enum tcp_mss_af af = TCP_MSS_V4;
	if (tcpmss_msg->af == TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V6)
		af = TCP_MSS_V6;

	ret = tcp_mss_if_list_del(tcpmss_msg->ifname, af);
	if (!ret)
		return 1;

	ifp = ifnet_byifname(tcpmss_msg->ifname);
	if (!ifp) {
		pb_cmd_err(msg, "Missing interface %s\n", tcpmss_msg->ifname);
		return -EINVAL;
	}

	ifp->tcp_mss_type[tcpmss_msg->af] = TCP_MSS_NONE;
	ifp->tcp_mss_value[tcpmss_msg->af] = 0;

	if (tcpmss_msg->af == TCPMSSCONFIG__ADDRESS_FAMILY__TCP_MSS_V4) {
		pl_node_remove_feature(&ipv4_tcp_mss_in_feat, ifp->if_name);
		pl_node_remove_feature(&ipv4_tcp_mss_out_feat, ifp->if_name);
	} else {
		pl_node_remove_feature(&ipv6_tcp_mss_in_feat, ifp->if_name);
		pl_node_remove_feature(&ipv6_tcp_mss_out_feat, ifp->if_name);
	}

	return 1;
}

static int
tcp_mss_feat_cmd(struct pb_msg *msg)
{
	int rc;
	
	TCPMSSConfig *tcpmss_msg =
		tcpmssconfig__unpack(NULL, msg->msg_len, msg->msg);
	if (!tcpmss_msg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read tcp-mss protobuf command\n");
		return -1;
	}

	if (tcpmss_msg->is_enable)
		rc = tcp_mss_feat_enable_cmd(tcpmss_msg, msg);
	else
		rc = tcp_mss_feat_disable_cmd(tcpmss_msg, msg);

	tcpmssconfig__free_unpacked(tcpmss_msg, NULL);

	return rc;
}

/*
 * DP_EVT_IF_INDEX_SET
 *
 * Replay any stored configuration now that the interface has been created
 */
static void
tcp_mss_event_if_index_set(struct ifnet *ifp, uint32_t ifindex __unused)
{
	struct tcp_mss_if_list_entry *le;

	le = tcp_mss_if_list_lookup(ifp->if_name, TCP_MSS_V4);
	if (le) {
		struct pb_msg msg = {.fp = NULL,
				    .msg = le->le_buf,
				    .msg_len = le->le_argc };

		tcp_mss_feat_cmd(&msg);
		tcp_mss_if_list_del(ifp->if_name, TCP_MSS_V4);
	}

	le = tcp_mss_if_list_lookup(ifp->if_name, TCP_MSS_V6);
	if (le) {
		struct pb_msg msg = {.fp = NULL,
				    .msg = le->le_buf,
				    .msg_len = le->le_argc };

		tcp_mss_feat_cmd(&msg);
		tcp_mss_if_list_del(ifp->if_name, TCP_MSS_V6);
	}
}

/*
 * DP_EVT_IF_INDEX_UNSET
 */
static void
tcp_mss_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex __unused)
{
	tcp_mss_if_list_del(ifp->if_name, TCP_MSS_V4);
	tcp_mss_if_list_del(ifp->if_name, TCP_MSS_V6);
}

static const struct dp_event_ops tcp_mss_event_ops = {
	.if_index_set = tcp_mss_event_if_index_set,
	.if_index_unset = tcp_mss_event_if_index_unset,
};

static void __attribute__ ((constructor)) tcp_mss_event_init(void)
{
	dp_event_register(&tcp_mss_event_ops);
}


PB_REGISTER_CMD(tcp_mss_cmd) = {
	.cmd = "vyatta:tcp-mss",
	.handler = tcp_mss_feat_cmd,
};
