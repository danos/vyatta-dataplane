/*
 * l3_v6_l4.c
 *
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdbool.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "compiler.h"
#include "crypto/crypto_forward.h"
#include "crypto/crypto.h"
#include "ip6_funcs.h"
#include "l2tp/l2tpeth.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "pl_node.h"
#include "pl_nodes_common.h"
#include "vrf.h"

struct pl_node;

/* Size of the feat hash table */
#define L4_FEAT_HASH_MIN  4
#define L4_FEAT_HASH_MAX  32

static struct cds_lfht *l3_v6_l4_feat_ht;

static inline int
ipv6_l4_feat_match(struct cds_lfht_node *node, const void *key)
{
	const uint32_t *feat_type = key;
	const struct pl_feature_registration *feat;

	feat = caa_container_of(node, const struct pl_feature_registration,
				feat_node);

	if (feat && feat->feat_type == *feat_type)
		return 1;

	return 0;
}

inline __attribute__((always_inline)) int
ipv6_l4_find_feat_id_by_type(uint32_t feat_type)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ret_node;
	const struct pl_feature_registration *feat;

	if (!l3_v6_l4_feat_ht)
		return 0;

	cds_lfht_lookup(l3_v6_l4_feat_ht, feat_type,
			ipv6_l4_feat_match, &feat_type,
			&iter);

	ret_node = cds_lfht_iter_get_node(&iter);
	if (ret_node) {
		feat = caa_container_of(ret_node,
					struct pl_feature_registration,
					feat_node);
		return feat->id;
	}
	return 0;
}

static inline __attribute__((always_inline)) int
ipv6_l4_feat_add_type(struct pl_node_registration *node __unused,
		      struct pl_feature_registration *feat,
		      uint32_t feat_type)
{
	struct cds_lfht_node *ret_node;

	if (!l3_v6_l4_feat_ht) {
		l3_v6_l4_feat_ht = cds_lfht_new(L4_FEAT_HASH_MIN,
						L4_FEAT_HASH_MIN,
						L4_FEAT_HASH_MAX,
						CDS_LFHT_AUTO_RESIZE,
						NULL);
		if (l3_v6_l4_feat_ht == NULL)
			rte_panic("Can't allocate ft node hash\n");
	}
	ret_node = cds_lfht_add_unique(l3_v6_l4_feat_ht, feat_type,
				       ipv6_l4_feat_match, &feat_type,
				       &feat->feat_node);
	return (ret_node != &feat->feat_node) ? EEXIST : 0;
}

static inline __attribute__((always_inline)) bool
ipv6_l4_pre_process(struct pl_packet *pkt, void *context, struct ifnet *ifp)
{
	struct rte_mbuf *m = pkt->mbuf;
	struct ip6_hdr *ip6 = ip6hdr(m);
	int rc = -1;
	uint32_t spi;
	struct ip6_frag *ip6_frag;

	if (crypto_policy_check_inbound_terminating(ifp, &m,
						    htons(RTE_ETHER_TYPE_IPV6)))
		return 0;

	switch (ip6->ip6_nxt) {
	case IPPROTO_L2TPV3:
		rc = l2tp_ipv6_recv_encap(m, ip6,
			(unsigned char *)ip6 + sizeof(struct ip6_hdr));
		break;
	case IPPROTO_GRE:
		rc = ip6_gre_tunnel_in(&m, ip6);
		break;
	case IPPROTO_ESP:
		spi = crypto_retrieve_spi((unsigned char *)ip6 +
					  dp_pktmbuf_l3_len(m));
		rc = crypto_enqueue_inbound_v6(m, ifp, spi);
		break;
	case IPPROTO_FRAGMENT:
		/*
		 * If it is a fragment, and the next proto is ESP send
		 * to the crypto code. It will reassemble it and then find
		 * the SPI, so pass in 0.
		 */
		ip6_frag = (struct ip6_frag *)(ip6 + 1);
		if (ip6_frag->ip6f_nxt == IPPROTO_ESP) {
			rc = crypto_enqueue_inbound_v6(m, ifp, 0);
			break;
		}
		return true;
	default:
		return true;
		/* other protocols */
	}
	if (rc == 0)
		return false;
	if (rc < 0) {
		term_drop_process(pkt, context);
		return false;
	}
	return true;
}

inline __attribute__((always_inline)) unsigned int
ipv6_l4_process_common(struct pl_packet *pkt, void *context,
		       enum pl_mode mode)
{
	struct rte_mbuf *m = pkt->mbuf;
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct ifnet *ifp = pkt->in_ifp;
	uint32_t feat_type = ip6->ip6_nxt;

	if (!ipv6_l4_pre_process(pkt, context, ifp))
		return IPV6_L4_CONSUME;

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv6_l4_features(
			    pkt,
			    ipv6_l4_find_feat_id_by_type_fused(feat_type)))
			return IPV6_L4_CONSUME;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv6_l4_no_dyn_features(
			    pkt,
			    ipv6_l4_find_feat_id_by_type_fused_no_dyn_features(
				    feat_type)))
			return IPV6_L4_CONSUME;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_feature_by_type(
			    ipv6_l4_node_ptr,
			    feat_type, pkt))
			return IPV6_L4_CONSUME;
		break;
	}
	return IPV6_L4_ACCEPT;
}


ALWAYS_INLINE unsigned int
ipv6_l4_process(struct pl_packet *pkt, void *context)
{
	return ipv6_l4_process_common(pkt, context, PL_MODE_REGULAR);
}

/* Register Node */
PL_REGISTER_NODE(ipv6_l4_node) = {
	.name = "vyatta:ipv6-l4",
	.type = PL_PROC,
	.handler = ipv6_l4_process,
	.feat_type_insert = ipv6_l4_feat_add_type,
	.feat_type_find = ipv6_l4_find_feat_id_by_type,
	.num_next = IPV6_L4_NUM,
	.next = {
		[IPV6_L4_ACCEPT]  = "ipv6-local",
		[IPV6_L4_DROP]    = "ipv6-drop",
		[IPV6_L4_CONSUME] = "term-finish",
	}
};

struct pl_node_registration *const ipv6_l4_node_ptr = &ipv6_l4_node;

/*
 * show features ipv6_l4
 */
static int cmd_pl_show_feat_ipv6_l4(struct pl_command *cmd)
{
	json_writer_t *wr;

	wr = jsonw_new(cmd->fp);
	if (!wr)
		return 0;

	jsonw_name(wr, "features");
	jsonw_start_object(wr);

	jsonw_name(wr, "global");
	jsonw_start_array(wr);
	pl_node_iter_features(ipv6_l4_node_ptr, NULL,
			      pl_print_feats, wr);
	jsonw_end_array(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	return 0;
}

PL_REGISTER_OPCMD(pl_show_feat_ipv6_l4) = {
	.cmd = "show features ipv6_l4",
	.handler = cmd_pl_show_feat_ipv6_l4,
};
