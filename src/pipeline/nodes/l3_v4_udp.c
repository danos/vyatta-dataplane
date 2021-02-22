/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdlib.h>
#include "ip_funcs.h"

#include "compiler.h"
#include "../pl_common.h"
#include "../pl_node.h"
#include "../pl_fused.h"
#include "pl_nodes_common.h"

/* Size of the feat hash table */
#define L4_FEAT_HASH_MIN  4
#define L4_FEAT_HASH_MAX  32

static struct cds_lfht *l3_v4_udp_feat_ht;

static inline int
ipv4_udp_in_feat_match(struct cds_lfht_node *node, const void *key)
{
	const uint32_t *feat_type = key;
	const struct pl_feature_registration *feat;

	feat = caa_container_of(node, const struct pl_feature_registration,
				feat_node);

	if (feat && feat->feat_type == *feat_type)
		return 1;

	return 0;
}

ALWAYS_INLINE int
ipv4_udp_in_find_feat_id_by_type(uint32_t feat_type)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *ret_node;
	const struct pl_feature_registration *feat;

	if (!l3_v4_udp_feat_ht)
		return 0;

	cds_lfht_lookup(l3_v4_udp_feat_ht, feat_type,
			ipv4_udp_in_feat_match, &feat_type,
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

static ALWAYS_INLINE int
ipv4_udp_in_feat_add_type(struct pl_node_registration *node  __unused,
			  struct pl_feature_registration *feat,
			  uint32_t feat_type)
{
	struct cds_lfht_node *ret_node;

	if (!l3_v4_udp_feat_ht) {
		l3_v4_udp_feat_ht = cds_lfht_new(L4_FEAT_HASH_MIN,
						 L4_FEAT_HASH_MIN,
						 L4_FEAT_HASH_MAX,
						 CDS_LFHT_AUTO_RESIZE,
						 NULL);
		if (l3_v4_udp_feat_ht == NULL)
			rte_panic("Can't allocate ft node hash\n");
	}
	ret_node = cds_lfht_add_unique(l3_v4_udp_feat_ht, feat_type,
				       ipv4_udp_in_feat_match, &feat_type,
				       &feat->feat_node);
	return (ret_node != &feat->feat_node) ? EEXIST : 0;
}

static ALWAYS_INLINE int
ipv4_udp_in_feat_rem_type(struct pl_node_registration *node  __unused,
			  struct pl_feature_registration *feat __unused,
			  uint32_t feat_type)
{
	struct cds_lfht_node *ret_node;
	struct cds_lfht_iter iter;

	if (!l3_v4_udp_feat_ht)
		return -ENOENT;

	cds_lfht_lookup(l3_v4_udp_feat_ht, feat_type,
			ipv4_udp_in_feat_match, &feat_type,
			&iter);

	ret_node = cds_lfht_iter_get_node(&iter);
	if (!ret_node)
		return -ENOENT;

	return cds_lfht_del(l3_v4_udp_feat_ht, ret_node);
}

ALWAYS_INLINE unsigned int
ipv4_udp_in_process_common(struct pl_packet *pkt, void *context __unused,
			   enum pl_mode mode)
{
	struct rte_mbuf *m = pkt->mbuf;
	struct iphdr *ip = iphdr(m);
	struct udphdr *udp;
	struct ifnet *ifp = pkt->in_ifp;
	int rc;
	uint32_t feat_type;


	rc = ip_udp_tunnel_in(&m, ip, ifp);
	if (likely(rc == 0))
		return IPV4_UDP_CONSUME;
	if (rc < 0)
		return IPV4_UDP_DROP;

	pkt->mbuf = m;

	udp = dp_pktmbuf_mtol4(m, struct udphdr *);
	feat_type = udp->dest;

	switch (mode) {
	case PL_MODE_FUSED:
		if (!pipeline_fused_ipv4_udp_in_features(
			    pkt,
			    ipv4_udp_in_find_feat_id_by_type_fused(feat_type)))
			return IPV4_UDP_CONSUME;
		break;
	case PL_MODE_FUSED_NO_DYN_FEATS:
		if (!pipeline_fused_ipv4_udp_in_no_dyn_features(
			    pkt,
			    ipv4_udp_in_find_feat_id_by_type_fused_no_dyn_features(feat_type)))
			return IPV4_UDP_CONSUME;
		break;
	case PL_MODE_REGULAR:
		if (!pl_node_invoke_feature_by_type(
			    ipv4_udp_in_node_ptr,
			    feat_type, pkt))
			return IPV4_UDP_CONSUME;
		break;
	}
	return IPV4_UDP_ACCEPT;
}

ALWAYS_INLINE unsigned int
ipv4_udp_in_process(struct pl_packet *pkt, void *context)
{
	return ipv4_udp_in_process_common(pkt, context, PL_MODE_REGULAR);
}

PL_REGISTER_NODE(ipv4_udp_in_node) = {
	.name = "vyatta:ipv4-udp-in",
	.type = PL_PROC,
	.handler = ipv4_udp_in_process,
	.feat_type_insert = ipv4_udp_in_feat_add_type,
	.feat_type_remove = ipv4_udp_in_feat_rem_type,
	.feat_type_find = ipv4_udp_in_find_feat_id_by_type,
	.num_next = IPV4_UDP_NUM,
	.next = {
		[IPV4_UDP_ACCEPT]   = "term-noop",
		[IPV4_UDP_DROP]     = "term-drop",
		[IPV4_UDP_CONSUME]  = "term-finish",
	}
};

PL_REGISTER_FEATURE(ipv4_udp_in_feat) = {
	.name = "vyatta:ipv4-udp-in",
	.node_name = "ipv4-udp-in",
	.feature_point = "ipv4-l4",
	.always_on = true,
	.id = PL_L3_V4_L4_FUSED_FEAT_UDP_IN,
	.feat_type = IPPROTO_UDP,
};

struct pl_node_registration *const ipv4_udp_in_node_ptr = &ipv4_udp_in_node;

/*
 * show features ipv4_udp_in
 */
static int cmd_pl_show_feat_ipv4_udp_in(struct pl_command *cmd)
{
	json_writer_t *wr;

	wr = jsonw_new(cmd->fp);
	if (!wr)
		return 0;

	jsonw_name(wr, "features");
	jsonw_start_object(wr);

	jsonw_name(wr, "global");
	jsonw_start_array(wr);
	pl_node_iter_features(ipv4_udp_in_node_ptr, NULL,
			      pl_print_feats, wr);
	jsonw_end_array(wr);

	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	return 0;
}

PL_REGISTER_OPCMD(pl_show_feat_ipv4_udp_in) = {
	.cmd = "show features ipv4_udp_in",
	.handler = cmd_pl_show_feat_ipv4_udp_in,
};
