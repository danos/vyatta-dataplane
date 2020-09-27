/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <assert.h>
#include <czmq.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <rte_branch_prediction.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_ring.h>
#include <rte_timer.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <urcu/uatomic.h>

#include "capture.h"
#include "compiler.h"
#include "crypto.h"
#include "crypto_internal.h"
#include "crypto_main.h"
#include "crypto_policy.h"
#include "crypto_rte_pmd.h"
#include "crypto_sadb.h"
#include "dp_event.h"
#include "esp.h"
#include "ether.h"
#include "event_internal.h"
#include "if_var.h"
#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "json_writer.h"
#include "lcore_sched.h"
#include "main.h"
#include "npf/fragment/ipv6_rsmbl.h"
#include "npf/npf_cache.h"
#include "pktmbuf_internal.h"
#include "pl_common.h"
#include "pl_fused.h"
#include "shadow.h"
#include "udp_handler.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "vti.h"
#include "crypto_rte_pmd.h"

struct cds_list_head;

struct crypto_pkt_buffer *cpbdb[RTE_MAX_LCORE];

/*
 * The return ring size needs to be a multiple of the the PMD ring, as
 * an RX thread could have many packets queued to many PMD rings.
 */
#define PKT_RET_RING_SIZE  PMD_RING_SIZE

#define CRYPTO_PREFETCH_OFFSET 3

static struct crypto_dp g_crypto_dp;
struct crypto_dp *crypto_dp_sp = &g_crypto_dp;
static struct rte_timer flow_cache_timer;

/* between crypto and main thread */
static zsock_t *crypto_main_pull;
static const char crypto_inproc[] = "inproc://crypto_to_main";
static int handle_crypto_event(void *);

/* from the main thread to the rekey listener */
static zsock_t *rekey_listener;

enum crypto_action {
	CRYPTO_ACT_NONE,
	CRYPTO_ACT_VTI_INPUT,
	CRYPTO_ACT_INPUT,
	CRYPTO_ACT_INPUT_WITH_FEATURES,
	CRYPTO_ACT_OUTPUT,
	CRYPTO_ACT_DROP,
};

RTE_DEFINE_PER_LCORE(struct crypto_pkt_buffer *, crypto_pkt_buffer);

static const char * const ipsec_counter_names[] = {
	[ENQUEUED_INPUT_IPV4] = "v4_in",
	[ENQUEUED_INPUT_IPV6] = "v6_in",
	[ENQUEUED_OUTPUT_IPV4] = "v4_out",
	[ENQUEUED_OUTPUT_IPV6] = "v6_out",
	[DROPPED] = "drop",
	[DROPPED_NO_MBUF] = "dropped_no_mbuf",
	[DROPPED_IPV6_UNSUPPORTED] = "dropped_ipv6_unsupported",
	[DROPPED_UNSUPPORTED_PROTOCOL] = "dropped_unsupported_protocol",
	[DROPPED_ESP_OUTPUT_FAIL] = "dropped_esp_output_fail",
	[DROPPED_ESP_INPUT_FAIL] = "dropped_esp_input_fail",
	[DROPPED_BAD_DIRECTION] = "dropped_bad_direction",
	[DROPPED_NO_POLICY_RULE] = "dropped_no_policy_rule",
	[DROPPED_POLICY_BLOCK] = "dropped_policy_block",
	[DROPPED_NO_NEXT_HOP] = "dropped_no_next_hop",
	[DROPPED_BLACKHOLE_OR_BROADCAST] = "dropped_blackhole_or_broadcast",
	[DROPPED_FILTER_REJECT] = "dropped_filter_reject",
	[DROPPED_OVERHEAD_TOO_BIG] = "dropped_overhead_too_big",
	[DROPPED_DF] = "dropped_df",
	[DROPPED_NO_CTX] = "dropped_no_ctx",
	[DROPPED_INVALID_REQID] = "dropped_invalid_reqid",
	[DROPPED_INVALID_VERSION] = "dropped_invalid_version",
	[FAILED_TO_BURST] = "burst_fail",
	[BURST_RING_FULL] = "burst_ring_full",
	[FAILED_TO_ALLOCATE_CTX] = "failed_to_allocate_ctx",
	[NO_DST_SUPPLIED] = "no_dst_supplied",
	[CTX_ALLOCATED] = "ctx_allocated",
	[CTX_FREED] = "ctx_freed",
	[FAILED_TO_RETURN] = "failed to return",
	[RETURNED] = "returned",
	[NO_IN_SA] = "no inbound SA",
	[NO_OUT_SA] = "no outbound SA",
	[NO_VTI] = "no VTI found",
	[OUTSIDE_SEQ_WINDOW] = "outside seq window drop",
	[DROPPED_NO_IFP] = "dropped no ifp",
	[DROPPED_INVALID_PMD_DEV_ID] = "dropped invalid pmd dev id",
	[DROPPED_NO_SPI_TO_SA] = "dropped no SA from SPI",
	[FLOW_CACHE_ADD] = "Entry added to flow cache",
	[FLOW_CACHE_ADD_FAIL] = "Failed to add entry to flow cache",
	[FLOW_CACHE_HIT] = "hit flow cache",
	[FLOW_CACHE_MISS] = "missed flow cache",
	[DROPPED_NO_BIND] = "dropped feature attachment point missing",
	[DROPPED_ON_FP_NO_PR] = "dropped on fp but no policy",
	[DROPPED_COP_ALLOC_FAILED] = "dropped on crypto op allocation failure",
	[CRYPTO_OP_FAILED] = "encrypt/decrypt op failed"
};

unsigned long ipsec_counters[RTE_MAX_LCORE][IPSEC_CNT_MAX] __rte_cache_aligned;

static const char * const xfrm_names[] = {
	[CRYPTO_ENCRYPT] = "Encrypt",
	[CRYPTO_DECRYPT] = "Decrypt",
};

struct crypto_iphdr_ctx {
	unsigned int iphlen;
	uint8_t nxt_proto;
};

static int crypto_vrf_insert(struct crypto_vrf_ctx *vrf_ctx)
{
	struct vrf *vrf;

	vrf = vrf_get_rcu(vrf_ctx->vrfid);
	if (!vrf)
		return -1;

	rcu_assign_pointer(vrf->crypto, vrf_ctx);
	return 0;
}

struct crypto_vrf_ctx *crypto_vrf_find(vrfid_t vrfid)
{
	struct vrf *vrf;

	vrf = vrf_get_rcu(vrfid);
	if (!vrf)
		return NULL;
	return rcu_dereference(vrf->crypto);
}

struct crypto_vrf_ctx *crypto_vrf_find_external(vrfid_t vrfid)
{
	struct vrf *vrf;

	vrf = dp_vrf_get_rcu_from_external(vrfid);
	if (!vrf)
		return NULL;
	return rcu_dereference(vrf->crypto);
}

/*
 * Lookup/create crypto VRF context block
 */
struct crypto_vrf_ctx *crypto_vrf_get(vrfid_t vrfid)
{
	struct crypto_vrf_ctx *vrf_ctx;

	vrf_ctx = crypto_vrf_find(vrfid);
	if (vrf_ctx)
		return vrf_ctx;

	vrf_ctx = zmalloc_aligned(sizeof(*vrf_ctx));
	if (!vrf_ctx)
		return NULL;

	vrf_ctx->vrfid = vrfid;

	/*
	 * SA hash tables
	 */
	if (!crypto_sadb_vrf_init(vrf_ctx))
		goto vrf_ctx_get_fail;

	/*
	 * Allocate policy hash tables
	 */
	vrf_ctx->input_policy_rule_sel_ht =
		cds_lfht_new(POLICY_RULE_HT_MIN_BUCKETS,
			     POLICY_RULE_HT_MIN_BUCKETS,
			     POLICY_RULE_HT_MAX_BUCKETS,
			     CDS_LFHT_AUTO_RESIZE,
			     NULL);
	if (!vrf_ctx->input_policy_rule_sel_ht)
		goto vrf_ctx_get_fail;

	vrf_ctx->output_policy_rule_sel_ht =
		cds_lfht_new(POLICY_RULE_HT_MIN_BUCKETS,
			     POLICY_RULE_HT_MIN_BUCKETS,
			     POLICY_RULE_HT_MAX_BUCKETS,
			     CDS_LFHT_AUTO_RESIZE,
			     NULL);
	if (!vrf_ctx->output_policy_rule_sel_ht)
		goto vrf_ctx_get_fail;

	vrf_ctx->s2s_bind_hash_table =
		cds_lfht_new(POLICY_RULE_HT_MIN_BUCKETS,
			     POLICY_RULE_HT_MIN_BUCKETS,
			     POLICY_RULE_HT_MAX_BUCKETS,
			     CDS_LFHT_AUTO_RESIZE,
			     NULL);
	if (!vrf_ctx->s2s_bind_hash_table)
		goto vrf_ctx_get_fail;

	/*
	 * Hang crypto block off VRF
	 */
	if (crypto_vrf_insert(vrf_ctx) < 0) {
		DP_DEBUG(CRYPTO, ERR, POLICY,
			"Failed to insert crypto VRF %d\n", vrf_ctx->vrfid);
		goto vrf_ctx_get_fail;
	}
	DP_DEBUG(CRYPTO, INFO, POLICY, "Allocated crypto VRF ctx %d\n",
		vrf_ctx->vrfid);
	return vrf_ctx;

vrf_ctx_get_fail:
	crypto_sadb_vrf_clean(vrf_ctx);
	if (vrf_ctx->input_policy_rule_sel_ht)
		cds_lfht_destroy(vrf_ctx->input_policy_rule_sel_ht, NULL);
	if (vrf_ctx->output_policy_rule_sel_ht)
		cds_lfht_destroy(vrf_ctx->output_policy_rule_sel_ht, NULL);
	if (vrf_ctx->s2s_bind_hash_table)
		cds_lfht_destroy(vrf_ctx->s2s_bind_hash_table, NULL);
	free(vrf_ctx);
	return NULL;
}

static inline void crypto_vrf_free(struct rcu_head *head)
{
	struct crypto_vrf_ctx *vrf_ctx;

	vrf_ctx = caa_container_of(head, struct crypto_vrf_ctx, vrf_ctx_rcu);

	dp_ht_destroy_deferred(vrf_ctx->input_policy_rule_sel_ht);
	dp_ht_destroy_deferred(vrf_ctx->output_policy_rule_sel_ht);
	dp_ht_destroy_deferred(vrf_ctx->sadb_hash_table);
	dp_ht_destroy_deferred(vrf_ctx->spi_out_hash_table);
	dp_ht_destroy_deferred(vrf_ctx->s2s_bind_hash_table);

	free(vrf_ctx);
}

void
crypto_vrf_check_remove(struct crypto_vrf_ctx *vrf_ctx)
{
	/*
	 * We can remove crypto VRF context block when we've
	 * deleted all SAs and SPs in the VRF
	 */
	if (vrf_ctx &&
	    !vrf_ctx->crypto_total_ipv4_policies &&
	    !vrf_ctx->crypto_total_ipv6_policies &&
	    !vrf_ctx->count_of_sas &&
	    !vrf_ctx->count_of_peers &&
	    !vrf_ctx->s2s_bindings) {
		struct vrf *vrf;

		DP_DEBUG(CRYPTO, INFO, POLICY,
			 "Delete crypto VRF context %d\n", vrf_ctx->vrfid);

		vrf = get_vrf(vrf_ctx->vrfid);
		if (vrf)
			rcu_assign_pointer(vrf->crypto, NULL);

		call_rcu(&vrf_ctx->vrf_ctx_rcu, crypto_vrf_free);
	}
}

static struct crypto_pkt_ctx *allocate_crypto_packet_ctx(void)
{
	struct crypto_pkt_ctx *ctx;
	struct rte_mempool_cache *cache;

	cache = rte_mempool_default_cache(crypto_dp_sp->pool, rte_lcore_id());

	if (unlikely(rte_mempool_generic_get(crypto_dp_sp->pool, (void *)&ctx,
					     1, cache) != 0)) {
		return NULL;
	}
	IPSEC_CNT_INC(CTX_ALLOCATED);
	return ctx;
}

static void release_crypto_packet_ctx(struct crypto_pkt_ctx *ctx)
{
	struct rte_mempool_cache *cache;

	cache = rte_mempool_default_cache(crypto_dp_sp->pool, rte_lcore_id());
	IPSEC_CNT_INC(CTX_FREED);
	rte_mempool_generic_put(crypto_dp_sp->pool, (void *)&ctx, 1, cache);
}

static inline const
xfrm_address_t *crypto_get_src(void *l3hdr, uint32_t family)
{
	const struct iphdr *ip = l3hdr;
	const struct ip6_hdr *ip6 = l3hdr;

	if (family == AF_INET)
		return (const xfrm_address_t *)&ip->saddr;

	return (const xfrm_address_t *)&ip6->ip6_src;
}

static void crypto_parse_hdr4(struct rte_mbuf *m, struct crypto_iphdr_ctx *h)
{
	const struct iphdr *ip = iphdr(m);

	h->iphlen = (ip->ihl << 2);
	h->nxt_proto = ip->protocol;
}

static void crypto_parse_hdr6(struct rte_mbuf *m, struct crypto_iphdr_ctx *h)
{
	const struct ip6_hdr *ip6 = ip6hdr(m);

	h->iphlen = sizeof(struct ip6_hdr);
	h->nxt_proto = ip6->ip6_nxt;
}

/*
 * For crypto pkts, the port id of the receiving interface in passed in the
 * crypto ctx to the crypto thread and it doesn't modify the port id stored
 * in the mbuf as that is something that needs to be preserved in case the
 * decrypted packet is locally terminating and has been received on a
 * virtual interface. In such cases, the mbuf->portid helps us to identify the
 * correct TAP device to use for the punt.
 */
static void crypto_ctx_save_ifp(struct crypto_pkt_ctx *ctx, struct rte_mbuf *m,
				struct ifnet *ifp)
{
	if (ifp->if_type == IFT_ETHER && ifp->if_local_port) {
		ctx->in_ifp_port = ifp->if_port;
		assert(ctx->in_ifp_port < DATAPLANE_MAX_PORTS);
	} else {
		pktmbuf_mdata(m)->md_ifindex.ifindex = ifp->if_index;
		pktmbuf_mdata_set(m, PKT_MDATA_IFINDEX);
	}
}

static struct ifnet *crypto_ctx_to_in_ifp(struct crypto_pkt_ctx *ctx,
					  struct rte_mbuf *m)
{
	struct ifnet *ifp;

	if (pktmbuf_mdata_exists(m, PKT_MDATA_IFINDEX)) {
		ifp = dp_ifnet_byifindex(pktmbuf_mdata(m)->md_ifindex.ifindex);
		pktmbuf_mdata_clear(m, PKT_MDATA_IFINDEX);
	} else {
		assert(ctx->in_ifp_port < DATAPLANE_MAX_PORTS);
		ifp = ifnet_byport(ctx->in_ifp_port);
	}

	return ifp;
}

static inline void
crypto_post_decrypt_handle_vti(struct crypto_pkt_ctx *cctx,
			       struct rte_mbuf *m,
			       struct ifnet *vti_ifp)
{
	if (!(vti_ifp->if_flags & IFF_UP)) {
		cctx->action = CRYPTO_ACT_DROP;
		return;
	}
	cctx->in_ifp = vti_ifp;
	pktmbuf_clear_rx_vlan(m);
	pktmbuf_set_vrf(m, vti_ifp->if_vrfid);
	set_spath_rx_meta_data(m, vti_ifp,
			       ntohs(ethhdr(m)->ether_type),
			       TUN_META_FLAGS_DEFAULT);
	if (unlikely(vti_ifp->capturing))
		capture_burst(vti_ifp, &m, 1);
	cctx->action = CRYPTO_ACT_VTI_INPUT;
	if_incr_in(vti_ifp, m);
}

static inline void
crypto_post_decrypt_handle_vfp(struct crypto_pkt_ctx *cctx,
			       struct rte_mbuf *m,
			       struct ifnet *vfp_ifp)
{
	if (!(vfp_ifp->if_flags & IFF_UP)) {
		cctx->action = CRYPTO_ACT_DROP;
		return;
	}
	cctx->in_ifp = vfp_ifp;

	if (unlikely(vfp_ifp->capturing))
		capture_burst(vfp_ifp, &m, 1);

	cctx->action = CRYPTO_ACT_INPUT_WITH_FEATURES;
	if_incr_in(vfp_ifp, m);
}

static inline void
crypto_post_decrypt_set_overlay_vrf(struct sadb_sa *sa, struct rte_mbuf *m,
				    struct ifnet *vfp_ifp)
{
	/*
	 * Set the overlay vrf if different from input
	 * VRF. If this goes to the kernel then it
	 * will need the correct vrf set, so set it in
	 * meta too just in case.
	 */
	if (pktmbuf_get_vrf(m) == sa->overlay_vrf_id)
		return;

	pktmbuf_set_vrf(m, sa->overlay_vrf_id);
	set_spath_rx_meta_data(m,
			       vfp_ifp ? vfp_ifp :
			       dp_ifnet_byifindex(
				       dp_vrf_get_external_id(
					       sa->overlay_vrf_id)),
			       ntohs(ethhdr(m)->ether_type),
			       TUN_META_FLAGS_DEFAULT);
}

static inline void
crypto_post_decrypt_handle_packet(struct crypto_pkt_ctx *cctx,
				  struct sadb_sa *sa,
				  struct rte_mbuf *m,
				  int rc, struct ifnet *vti_ifp)
{
	if (rc < 0) {
		if (vti_ifp)
			if_incr_error(vti_ifp);
		CRYPTO_DATA_ERR("ESP Input failed %d\n", rc);
		IPSEC_CNT_INC(DROPPED_ESP_INPUT_FAIL);
		cctx->action = CRYPTO_ACT_DROP;
		return;
	}

	if (vti_ifp)
		crypto_post_decrypt_handle_vti(cctx, m, vti_ifp);
	else {
		struct ifnet *feat_attach_ifp =
			rcu_dereference(sa->feat_attach_ifp);

		/*
		 * If the SA has a virtual feature point bound to
		 * it, then switch the input interface to the feature
		 * point so that input features can be run.
		 */
		if (feat_attach_ifp) {
			crypto_post_decrypt_handle_vfp(cctx, m,
						       feat_attach_ifp);
		} else {
			cctx->in_ifp = crypto_ctx_to_in_ifp(cctx, m);
			if (unlikely(!cctx->in_ifp)) {
				CRYPTO_DATA_ERR("No_ifp\n");
				IPSEC_CNT_INC(DROPPED_NO_IFP);
				cctx->action = CRYPTO_ACT_DROP;
				return;
			}
			cctx->action = CRYPTO_ACT_INPUT;
		}
		crypto_post_decrypt_set_overlay_vrf(sa, m, feat_attach_ifp);
	}
}

static inline void
crypto_process_decrypt_packets(uint16_t count,
			       struct crypto_pkt_ctx *cctx[],
			       uint32_t *bytes)
{
	struct rte_mbuf *m;
	uint16_t i;

	for (i = 0; i < count; i++) {
		if (unlikely(cctx[i]->action == CRYPTO_ACT_DROP))
			continue;

		/*
		 * If this packet has come from a VTI, replace the
		 * physical input interface with the VTI.  Doing so
		 * enables both accounting and input features.
		 */
		unsigned int mark = crypto_sadb_get_mark_val(cctx[i]->sa);

		m = cctx[i]->mbuf;
		if ((mark != 0) &&
		    (vti_handle_inbound(
			    crypto_get_src(dp_pktmbuf_mtol3(m, void *),
					   cctx[i]->family),
			    cctx[i]->family, mark, m,
			    &cctx[i]->vti_ifp) < 0)) {
			CRYPTO_DATA_ERR("No VTI interface found\n");
			IPSEC_CNT_INC(NO_VTI);
			cctx[i]->action = CRYPTO_ACT_DROP;
			continue;
		}
	}

	esp_input(cctx, count);

	for (i = 0; i < count; i++) {
		if (unlikely(cctx[i]->action == CRYPTO_ACT_DROP))
			continue;

		crypto_post_decrypt_handle_packet(cctx[i],
						  cctx[i]->sa,
						  cctx[i]->mbuf,
						  cctx[i]->status,
						  cctx[i]->vti_ifp);
		*bytes += cctx[i]->bytes;
	}
}

static void crypto_process_encrypt_packets(uint16_t count,
					   struct crypto_pkt_ctx *cctx[],
					   uint32_t *bytes)
{
	uint16_t i;
	struct crypto_pkt_ctx *tmp_cctx;

	esp_output(cctx, count);

	for (i = 0; i < count; i++) {
		tmp_cctx = cctx[i];
		if (tmp_cctx->status < 0) {
			if (tmp_cctx->nxt_ifp)
				if_incr_oerror(tmp_cctx->nxt_ifp);
			CRYPTO_DATA_ERR("ESP Output failed %d\n",
					tmp_cctx->status);
			tmp_cctx->action = CRYPTO_ACT_DROP;
			IPSEC_CNT_INC(DROPPED_ESP_OUTPUT_FAIL);
		} else {
			tmp_cctx->in_ifp = crypto_ctx_to_in_ifp(tmp_cctx,
								tmp_cctx->mbuf);
			if (unlikely(!tmp_cctx->in_ifp)) {
				CRYPTO_DATA_ERR("No_ifp\n");
				IPSEC_CNT_INC(DROPPED_NO_IFP);
				tmp_cctx->action = CRYPTO_ACT_DROP;
				continue;
			}
			tmp_cctx->action = CRYPTO_ACT_OUTPUT;
			/*
			 * And put it into the correct vrf now that we
			 * have added new headers. At the moment we only
			 * support default for the transport/underlay.
			 */
			pktmbuf_set_vrf(tmp_cctx->mbuf, VRF_DEFAULT_ID);

			*bytes += tmp_cctx->bytes;
		}
	}
}

static void crypto_pkt_ctx_forward_and_free(struct crypto_pkt_ctx *ctx)
{
	switch (ctx->action) {
	case CRYPTO_ACT_VTI_INPUT:
	case CRYPTO_ACT_INPUT_WITH_FEATURES:
		/* Mark this packet as having been decrypted. */
		ctx->mbuf->ol_flags |= PKT_RX_SEEN_BY_CRYPTO;
		pktmbuf_prepare_decap_reswitch(ctx->mbuf);
		if (ctx->family == AF_INET) {
			struct pl_packet pl_pkt = {
				.mbuf = ctx->mbuf,
				.l2_pkt_type = L2_PKT_UNICAST,
				.in_ifp = ctx->in_ifp,
			};
			pipeline_fused_ipv4_validate(&pl_pkt);
		} else {
			struct pl_packet pl_pkt = {
				.mbuf = ctx->mbuf,
				.in_ifp = ctx->in_ifp,
			};
			pipeline_fused_ipv6_validate(&pl_pkt);
		}
		break;
	case CRYPTO_ACT_INPUT:
		/* Mark this packet as having been decrypted. */
		ctx->mbuf->ol_flags |= PKT_RX_SEEN_BY_CRYPTO;
		pktmbuf_prepare_decap_reswitch(ctx->mbuf);
		if (ctx->family == AF_INET)
			ip_input_from_ipsec(ctx->in_ifp, ctx->mbuf);
		else
			ip6_input_from_ipsec(ctx->in_ifp, ctx->mbuf);
		break;
	case CRYPTO_ACT_OUTPUT:
		ctx->mbuf->ol_flags |= PKT_TX_SEEN_BY_CRYPTO;
		pktmbuf_prepare_encap_out(ctx->mbuf);
		if (ctx->nxt_ifp)
			if_incr_out(ctx->nxt_ifp, ctx->mbuf);
		if (ctx->family == AF_INET)
			ip_lookup_and_originate(ctx->mbuf, ctx->in_ifp);
		else
			ip6_lookup_and_originate(ctx->mbuf, ctx->in_ifp);
		break;
	case CRYPTO_ACT_DROP: /* fall through */
	default:
		IPSEC_CNT_INC(DROPPED);
		rte_pktmbuf_free(ctx->mbuf);
		break;
	}
	release_crypto_packet_ctx(ctx);
}

/*
 * Send all the packets on the threads burst queue over
 * to the crypto thread for encryption or decryption. If the
 * drop flag is set then any left over packets that can't be
 * queued should be purged as the PMD on the cpb could be
 * changing.  If the drop is not set then they should be retained
 * for the next burst attempt.
 */
int crypto_send_burst(struct crypto_pkt_buffer *cpb,
		      enum crypto_xfrm xfrm,
		      bool drop)
{
	uint32_t count = 0;
	struct rte_ring *pmd_ring;
	uint32_t unsent = 0;

	int pmd_dev_id = cpb->pmd_dev_id[xfrm];

	if (cpb->local_q_count[xfrm] == 0)
		return 0;

	pmd_ring = crypto_pmd_get_q(pmd_dev_id, xfrm);
	if (unlikely(!pmd_ring)) {
		drop = true;
		goto drop_check;
	}

	count = rte_ring_mp_enqueue_burst(pmd_ring,
					  (void **)cpb->local_crypto_q[xfrm],
					  cpb->local_q_count[xfrm],
					  NULL);
	if (count < cpb->local_q_count[xfrm]) {
		unsent = cpb->local_q_count[xfrm] - count;
		goto drop_check;
	}
	cpb->local_q_count[xfrm] = 0;
	return 0;
drop_check:
	/*
	 * Drop any packets we failed to queue if the drop flag is set
	 * and release the crypto context.
	 */
	if (drop) {
		for (uint32_t i = count; i < cpb->local_q_count[xfrm]; i++) {
			struct crypto_pkt_ctx *ctx =
				cpb->local_crypto_q[xfrm][i];

			rte_pktmbuf_free(ctx->mbuf);
			release_crypto_packet_ctx(ctx);
			IPSEC_CNT_INC(FAILED_TO_BURST);
		}
		cpb->local_q_count[xfrm] = 0;
		cpb->pmd_dev_id[xfrm] = CRYPTO_PMD_INVALID_ID;
	} else {
		if (count) {
			memmove(cpb->local_crypto_q[xfrm],
				&cpb->local_crypto_q[xfrm][count],
				unsent * sizeof(struct crypto_pkt_ctx *));
			cpb->local_q_count[xfrm] = unsent;
		}
	}
	return cpb->local_q_count[xfrm];
}

/*
 * crypto_enqueue_internal()
 *
 * This allocates a crypto packet context for this packet
 * and adds it to the crypt burst queue for the current lcore.
 */
static int crypto_enqueue_internal(enum crypto_xfrm xfrm,
				   struct rte_mbuf *m,
				   uint8_t orig_family,
				   uint8_t family,
				   xfrm_address_t *dst,
				   struct ifnet *in_ifp,
				   struct ifnet *nxt_ifp,
				   uint32_t reqid, int pmd_dev_id,
				   uint32_t spi,
				   void *l3hdr)
{
	struct crypto_pkt_buffer fallback_cpb;
	struct crypto_pkt_ctx *ctx;
	struct crypto_pkt_buffer *cpb;

	if (unlikely(pmd_dev_id == CRYPTO_PMD_INVALID_ID)) {
		IPSEC_CNT_INC(DROPPED_INVALID_PMD_DEV_ID);
		if (nxt_ifp && is_vti(nxt_ifp))
			if_incr_full_proto(nxt_ifp, 1);
		goto free_mbuf_on_error;
	}

	cpb = RTE_PER_LCORE(crypto_pkt_buffer);
	if (!cpb) {
		/*
		 * Not running on a forwarding thread, so use a dummy
		 * context and send batch immediately.
		 */
		memset(&fallback_cpb, 0, sizeof(fallback_cpb));
		cpb = &fallback_cpb;
	}

	/*
	 * If the burst buffer is full, or there is a change in the
	 * pmd_dev_id queue its contents to the pmd and try
	 * again.
	 */
	if (cpb->local_q_count[xfrm] >= MAX_CRYPTO_PKT_BURST ||
		cpb->pmd_dev_id[xfrm] != pmd_dev_id)
		if (crypto_send_burst(cpb, xfrm,
				      (cpb->pmd_dev_id[xfrm] != pmd_dev_id)) &&
		    (cpb->local_q_count[xfrm] >= MAX_CRYPTO_PKT_BURST)) {
			CRYPTO_DATA_ERR("Crypto burst_ring %u full\n",
				   (uint32_t)xfrm);
			IPSEC_CNT_INC(BURST_RING_FULL);
			if (nxt_ifp && is_vti(nxt_ifp))
				if_incr_full_txring(nxt_ifp, 1);
			goto free_mbuf_on_error;
		}

	ctx = allocate_crypto_packet_ctx();
	if (unlikely(!ctx)) {
		IPSEC_CNT_INC(FAILED_TO_ALLOCATE_CTX);
		if (nxt_ifp && is_vti(nxt_ifp))
			if_incr_full_proto(nxt_ifp, 1);
		goto free_mbuf_on_error;
	}

	ctx->l3hdr = l3hdr;
	ctx->direction = xfrm;
	ctx->mbuf      = m;
	ctx->orig_family    = orig_family;
	ctx->family    = family;
	ctx->reqid     = reqid;
	ctx->action    = CRYPTO_ACT_NONE;
	if (xfrm == CRYPTO_ENCRYPT) {
		/*
		 * For a VTI tunnel, do output crypto processing
		 * in transport VRF context
		 */
		if (!nxt_ifp || nxt_ifp->if_type != IFT_TUNNEL_VTI ||
		    (vti_set_output_vrf(nxt_ifp, m) == 0)) {
			memcpy(&ctx->dst, dst, sizeof(ctx->dst));
		} else {
			IPSEC_CNT_INC(NO_VTI);
			release_crypto_packet_ctx(ctx);
			goto free_mbuf_on_error;
		}
		if (family == AF_INET)
			ctx->out_ethertype = ETH_P_IP;
		else
			ctx->out_ethertype = ETH_P_IPV6;
	}
	ctx->in_ifp = NULL;
	ctx->vti_ifp = NULL;

	crypto_ctx_save_ifp(ctx, m, in_ifp);
	ctx->nxt_ifp = nxt_ifp;
	ctx->spi = spi;
	ctx->vrfid = pktmbuf_get_vrf(m);

	/*
	 * Add to the per thread burst queue.
	 */
	cpb->local_crypto_q[xfrm][cpb->local_q_count[xfrm]++] = ctx;
	cpb->pmd_dev_id[xfrm] = pmd_dev_id;

	/*
	 * If we're called from a non-dataplane thread then we must
	 * send the burst now.
	 */
	if (cpb == &fallback_cpb)
		crypto_send(cpb);
	return 0;

free_mbuf_on_error:
	rte_pktmbuf_free(m);
	return -1;
}


/*
 * Packet must contain crypto headers in first segment
 */
static inline bool crypto_check_hdr_single_seg(struct rte_mbuf *m,
					       struct crypto_iphdr_ctx *h,
					       struct ifnet *in_ifp)
{
	unsigned int len;

	len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m);
	if (len < h->iphlen + sizeof(struct ip_esp_hdr) +
	    ((h->nxt_proto == IPPROTO_UDP) ? sizeof(struct udphdr) : 0)) {
		CRYPTO_DATA_ERR("Bad segment length\n");
		if (in_ifp)
			if_incr_full_proto(in_ifp, 1);
		return false;
	}
	return true;
}

/*
 * crypto_enqueue_inbound_v4()
 *
 * Queue an inbound packet for decryption.
 */
int crypto_enqueue_inbound_v4(struct rte_mbuf *m,
			      const struct iphdr *ip,
			      struct ifnet *input_if,
			      uint32_t spi)
{
	struct crypto_iphdr_ctx h;
	int pmd_dev_id;

	/*
	 * We have to reassemble packets that were fragmented after the
	 * ipsec encap was put on before we can remove the encap properly.
	 * We need to reassemble all packets, as we can't necessarily get
	 * to the inner header to tell if we are interested before reassembly.
	 */
	if (ip_is_fragment(ip)) {
		struct iphdr *ip;

		m = ipv4_handle_fragment(m);
		if (!m)
			return 0;

		ip = iphdr(m);
		spi = crypto_retrieve_spi((unsigned char *)ip +
					  dp_pktmbuf_l3_len(m));
	}

	pmd_dev_id = crypto_spi_to_pmd_dev_id(spi);
	crypto_parse_hdr4(m, &h);
	if (!crypto_check_hdr_single_seg(m, &h, input_if))
		return -1;

	if (!crypto_enqueue_internal(CRYPTO_DECRYPT, m, AF_INET, AF_INET,
				    NULL, input_if, NULL, 0,
				    pmd_dev_id, spi,
				    iphdr(m)))
		IPSEC_CNT_INC(ENQUEUED_INPUT_IPV4);

	return 0;
}

/*
 * Queue an inbound packet for decryption.
 */
int crypto_enqueue_inbound_v6(struct rte_mbuf *m,
			      struct ifnet *input_if,
			      uint32_t spi)
{
	struct crypto_iphdr_ctx h;
	int pmd_dev_id;
	uint16_t npf_flag = NPF_FLAG_CACHE_EMPTY;

	/*
	 * We have to reassemble packets that were fragmented after the
	 * ipsec encap was put on before we can remove the encap properly.
	 * We need to reassemble all packets, as we can't necessarily get
	 * to the inner header to tell if we are interested before reassembly.
	 */
	if (unlikely(npf_ipv6_is_fragment(m, &npf_flag))) {
		struct ip6_hdr *ip6;

		m = ipv6_handle_fragment(m, &npf_flag);
		if (!m)
			return 0;

		ip6 = ip6hdr(m);
		spi = crypto_retrieve_spi((unsigned char *)ip6 +
					  dp_pktmbuf_l3_len(m));
	}

	pmd_dev_id = crypto_spi_to_pmd_dev_id(spi);
	crypto_parse_hdr6(m, &h);
	if (!crypto_check_hdr_single_seg(m, &h, input_if))
		return -1;

	if (!crypto_enqueue_internal(CRYPTO_DECRYPT, m, AF_INET6, AF_INET6,
				    NULL, input_if, NULL, 0,
				    pmd_dev_id, spi,
				    ip6hdr(m)))
		IPSEC_CNT_INC(ENQUEUED_INPUT_IPV6);

	return 0;
}

/*
 * crypto_enqueue_outbound()
 *
 * Queue an outbound packet for encryption.
 */
void crypto_enqueue_outbound(struct rte_mbuf *m, uint16_t orig_family,
			     uint16_t family,
			     xfrm_address_t *dst,
			     struct ifnet *in_ifp,
			     struct ifnet *nxt_ifp,
			     uint32_t reqid, int pmd_dev_id,
			     uint32_t spi)
{
	if (!dst) {
		CRYPTO_DATA_ERR("No destination address\n");
		IPSEC_CNT_INC(NO_DST_SUPPLIED);
		rte_pktmbuf_free(m);
		return;
	}

	if (!crypto_enqueue_internal(CRYPTO_ENCRYPT, m,
				     orig_family, family, dst,
				     in_ifp, nxt_ifp, reqid,
				     pmd_dev_id, spi, iphdr(m))) {
		if (family == AF_INET)
			IPSEC_CNT_INC(ENQUEUED_OUTPUT_IPV4);
		else
			IPSEC_CNT_INC(ENQUEUED_OUTPUT_IPV6);
	}
}

static void crypto_fwd_processed_packets(struct crypto_pkt_ctx **contexts,
					 unsigned int count)
{
	uint32_t i;

	for (i = 0; i < count; i++)
		crypto_pkt_ctx_forward_and_free(contexts[i]);
}

struct crypto_processing_cb {
	void (*process)(uint16_t count, struct crypto_pkt_ctx *ctx_arr[],
			uint32_t *bytes);
	void (*post_process)(struct crypto_pkt_ctx **,  uint32_t);
};

static const struct crypto_processing_cb crypto_cb[MAX_CRYPTO_XFRM] = {
	{crypto_process_encrypt_packets,
	 crypto_fwd_processed_packets},
	{crypto_process_decrypt_packets,
	 crypto_fwd_processed_packets} };

void crypto_purge_queue(struct rte_ring *pmd_queue)
{
	struct crypto_pkt_ctx *contexts[MAX_CRYPTO_PKT_BURST];
	unsigned int count, i;

	while (!rte_ring_empty(pmd_queue)) {
		count = rte_ring_sc_dequeue_burst(pmd_queue,
						  (void **)&contexts,
						  MAX_CRYPTO_PKT_BURST,
						  NULL);
		for (i = 0; i < count; i++) {
			struct crypto_pkt_ctx *ctx =
				contexts[i];

			rte_pktmbuf_free(ctx->mbuf);
			release_crypto_packet_ctx(ctx);
		}
	}
}

void crypto_delete_queue(struct rte_ring *pmd_queue)
{
	rte_ring_free(pmd_queue);
}

static inline struct sadb_sa *
sadb_lookup_sa(struct rte_mbuf *m __unused, enum crypto_xfrm xfrm,
	       struct crypto_pkt_ctx *ctx)
{
	struct sadb_sa *sa = NULL;

	if (xfrm == CRYPTO_ENCRYPT)
		sa = sadb_lookup_sa_outbound(ctx->vrfid,
					     &ctx->dst, ctx->family,
					     ctx->spi);
	else
		sa = sadb_lookup_inbound(ctx->spi);

	if (unlikely(!sa)) {
		struct ifnet *err_ifp;

		ctx->action = CRYPTO_ACT_DROP;
		if (xfrm == CRYPTO_ENCRYPT)
			IPSEC_CNT_INC(NO_OUT_SA);
		err_ifp = ((xfrm == CRYPTO_ENCRYPT) ? ctx->nxt_ifp :
			   crypto_ctx_to_in_ifp(ctx, ctx->mbuf));
		if (err_ifp && is_vti(err_ifp))
			if_incr_oerror(err_ifp);
		return NULL;
	}
	rte_prefetch0(sa->session);
	return sa;
}

static inline unsigned int
crypto_pmd_process_packets(struct crypto_pkt_ctx *contexts[],
			   uint16_t count, enum crypto_xfrm xfrm)
{
	struct rte_mbuf *m;
	unsigned int total_bytes = 0;
	uint16_t i, bad_idx[count], bad_count = 0;

	for (i = 0; i < count; i++) {
		m = contexts[i]->mbuf;
		if (unlikely(!m)) {
			CRYPTO_DATA_ERR("Null mbuf\n");
			contexts[i]->action = CRYPTO_ACT_DROP;
			IPSEC_CNT_INC(DROPPED_NO_MBUF);
			continue;
		}
		assert(contexts[i]->direction == xfrm);

		contexts[i]->bytes = 0;
		contexts[i]->sa = sadb_lookup_sa(m, xfrm, contexts[i]);
		if (unlikely(!contexts[i]->sa)) {
			contexts[i]->status = -1;
			contexts[i]->action = CRYPTO_ACT_DROP;
			bad_idx[bad_count++] = i;
		} else
			contexts[i]->status = 0;
	}

	move_bad_mbufs(contexts, count, bad_idx, bad_count);
	count -= bad_count;

	crypto_cb[xfrm].process(count, contexts, &total_bytes);

	return total_bytes;
}

/*
 * PMD walker callback passed together with a PMD listhead, and called
 * back for each xfrm queue within each PMD.
 *
 * Returning false terminates the pmd  walk.
 */
static bool crypto_pmd_walk_cb(int pmd_dev_id __unused, enum crypto_xfrm xfrm,
			       struct rte_ring *pmd_queue,
			       uint64_t *bytes,
			       uint32_t *packets)
{
	struct crypto_pkt_ctx *contexts[MAX_CRYPTO_PKT_BURST];
	unsigned int count, total_bytes = 0;

	if (!rte_ring_empty(pmd_queue)) {
		count = rte_ring_sc_dequeue_burst(pmd_queue,
						  (void **)&contexts,
						  MAX_CRYPTO_PKT_BURST,
						  NULL);

		total_bytes = crypto_pmd_process_packets(contexts, count, xfrm);

		crypto_cb[xfrm].post_process(contexts, count);
		*packets = count;
		*bytes = total_bytes;
	}

	return true;
}

/*
 * Main crypto packet processing loop.
 */
unsigned int dp_crypto_poll(struct cds_list_head *pmd_head)
{
	return crypto_pmd_walk_per_xfrm(pmd_head,
					crypto_pmd_walk_cb);
}

/*
 * Create an rte ring. Invoked for the creation of the per thread crypto return
 * and the per crypto pmd rings
 */
struct rte_ring *
crypto_create_ring(const char *name, unsigned int count,
		   int socket_id, unsigned int lcore_id,
		   unsigned int flags)
{
	static unsigned int anti_alias;
	char ring_name[RTE_RING_NAMESIZE];
	struct rte_ring *ring;

	snprintf(ring_name, sizeof(ring_name), "crypto-%s-%u(%u)",
		 name, lcore_id, ++anti_alias);

	ring = rte_ring_create(ring_name, count, socket_id,
			       flags);

	if (!ring)
		rte_panic("no memory for %s", ring_name);

	return ring;
}

const char *crypto_xfrm_name(enum crypto_xfrm xfrm)
{
	if (xfrm >= MAX_CRYPTO_XFRM)
		return "Invalid XFRM";

	return xfrm_names[xfrm];
}

/*
 * dp_crypto_lcore_init()
 *
 * Allocate an initialise the crypto packet buffer, which is used to
 * manage the interaction between a forwarding thread and the crypto
 * thread.
 */
static int dp_crypto_lcore_init(unsigned int lcore_id,
				void *arg __unused)
{
	struct crypto_pkt_buffer *cpb;
	unsigned int cpu_socket;
	uint32_t q;
	int err;

	err = crypto_flow_cache_init_lcore(lcore_id);
	if (err)
		rte_panic("Failed to create crypto flow cache for cpu %d\n",
			  lcore_id);

	if (!RTE_PER_LCORE(crypto_pkt_buffer)) {
		cpu_socket = rte_lcore_to_socket_id(lcore_id);

		cpb = rte_zmalloc_socket("crypto_pkt_buffer",
					 sizeof(struct crypto_pkt_buffer),
					 RTE_CACHE_LINE_SIZE,
					 cpu_socket);
		if (!cpb)
			rte_panic("no memory for lcore %u crypto_pkt_buffer\n",
				  lcore_id);
		for (q = MIN_CRYPTO_XFRM; q < MAX_CRYPTO_XFRM; q++)
			cpb->pmd_dev_id[q] = CRYPTO_PMD_INVALID_ID;

		err = crypto_rte_op_alloc(cpb->cops, MAX_CRYPTO_PKT_BURST);
		if (err)
			rte_panic("no memory for crypto ops on lcore %u",
				  lcore_id);

		cpbdb[lcore_id] = cpb;

		RTE_PER_LCORE(crypto_pkt_buffer) = cpb;
	}
	return 0;
}

static int dp_crypto_lcore_teardown(unsigned int lcore_id,
				    void *arg __unused)
{
	struct crypto_pkt_buffer *cpb = cpbdb[lcore_id];

	crypto_rte_op_free(cpb->cops, MAX_CRYPTO_PKT_BURST);
	return crypto_flow_cache_teardown_lcore(lcore_id);
}

static void init_context(struct rte_mempool *pool __unused,
			 void *context __unused,
			 void *obj,
			 unsigned index __unused)
{
	struct crypto_pkt_ctx *ctx = obj;

	memset(ctx, 0, sizeof(*ctx));
}

#define CRYPTO_POOL_SIZE (PKT_RET_RING_SIZE - 1)
#define CRYPTO_POOL_CACHE MAX_CRYPTO_PKT_BURST

/* Callback from event manager when ifp set into vrf */
static void crypto_if_vrf_set(struct ifnet *ifp)
{
	if (ifp->if_type == IFT_VRF) {
		crypto_incmpl_policy_make_complete();
		crypto_incmpl_sa_make_complete();
	}
}

static const struct dp_event_ops crypto_event_ops = {
	.if_vrf_set = crypto_if_vrf_set,
};

static void crypto_incomplete_init(void)
{
	dp_event_register(&crypto_event_ops);
	crypto_incmpl_policy_init();
	crypto_incmpl_sa_init();
}

static struct dp_lcore_events crypto_lcore_events = {
	.dp_lcore_events_init_fn = dp_crypto_lcore_init,
	.dp_lcore_events_teardown_fn = dp_crypto_lcore_teardown,
};


static unsigned int crypto_ctx_pool;
/*
 * General initialisation for crypto services
 */
void dp_crypto_init(void)
{
	unsigned int cores, cache;

	CRYPTO_INFO("Crypto thread initialise begin\n");

	cores = rte_lcore_count();

	CRYPTO_INFO("Crypto initialise: cores %d\n", cores);

	cores  = cores ? cores : 1;

	crypto_ctx_pool = CRYPTO_POOL_SIZE * cores;
	cache = CRYPTO_POOL_CACHE;

	crypto_dp_sp->pool = rte_mempool_create("Crypto context",
				  crypto_ctx_pool,
				  sizeof(struct crypto_pkt_ctx),
				  (cache < RTE_MEMPOOL_CACHE_MAX_SIZE) ?
					     cache : RTE_MEMPOOL_CACHE_MAX_SIZE,
				  0,    /* private_data_size*/
				  NULL, /* mp_init */
				  NULL, /* mp_init_arg */
				  init_context, /* obj_init */
				  NULL, /* obj_init_arg */
				  SOCKET_ID_ANY,
				  0 /* multiple producers and consumers */);

	if (!crypto_dp_sp->pool)
		rte_panic("Could not allocate crypto context pool\n");

	if (crypto_rte_setup())
		rte_panic("Could not set up crypto infrastructure pools\n");

	crypto_engine_load();

	if (crypto_flow_cache_init())
		rte_panic("Could not allocate crypto flow cache");

	if (dp_lcore_events_register(&crypto_lcore_events, NULL))
		rte_panic("can not initialise crypto per thread\n");

	crypto_main_pull = zsock_new_pull(crypto_inproc);

	if (!crypto_main_pull)
		rte_panic("cannot bind to crypto main pull socket\n");

	dp_register_event_socket(zsock_resolve(crypto_main_pull),
				 handle_crypto_event, crypto_main_pull);

	if (crypto_sadb_init() < 0)
		rte_panic("Failed to initialise crypto SADB\n");

	if (crypto_policy_init() < 0)
		rte_panic("Failed to initialise crypto Policy database\n");

	if (udp_handler_register(AF_INET, htons(ESP_PORT), udp_esp_dp) != 0)
		rte_panic("Failed to register ESP handler\n");

	if (udp_handler_register(AF_INET6, htons(ESP_PORT), udp_esp_dp6) != 0)
		rte_panic("Failed to register ESP handler 6\n");

	crypto_incomplete_init();

	crypto_engine_init();
	rte_timer_init(&flow_cache_timer);
	rte_timer_reset(&flow_cache_timer, rte_get_timer_hz(), PERIODICAL,
			rte_get_master_lcore(), crypto_flow_cache_timer_handler,
			NULL);

	CRYPTO_INFO("Crypto initialised\n");
}

void dp_crypto_shutdown(void)
{
	CRYPTO_INFO("crypto shutting down\n");
	dp_unregister_event_socket(zsock_resolve(crypto_main_pull));
	zsock_destroy(&crypto_main_pull);
	zsock_destroy(&rekey_listener);
	udp_handler_unregister(AF_INET, htons(ESP_PORT));
	udp_handler_unregister(AF_INET6, htons(ESP_PORT));
	crypto_engine_shutdown();
	crypto_rte_shutdown();
}

void crypto_show_summary(FILE *f)
{
	int i, j;
	json_writer_t *wr = jsonw_new(f);
	unsigned long agg_counters[IPSEC_CNT_MAX];

	if (!wr)
		return;

	memset(agg_counters, 0, sizeof(agg_counters));
	jsonw_pretty(wr, true);
	jsonw_name(wr, "IPsec-statistics");
	jsonw_start_object(wr);
	RTE_LCORE_FOREACH(i) {
		for (j = 0; j < IPSEC_CNT_MAX; j++)
			agg_counters[j] += ipsec_counters[i][j];
	}

	jsonw_uint_field(wr, "allocated_crypto_ctx", crypto_ctx_pool);
	jsonw_uint_field(wr, "avail_crypto_ctx",
			 rte_mempool_avail_count(crypto_dp_sp->pool));
	jsonw_uint_field(wr, "inuse_crypto_ctx",
			 rte_mempool_in_use_count(crypto_dp_sp->pool));

	for (i = 0; i < IPSEC_CNT_MAX; i++)
		jsonw_uint_field(wr, ipsec_counter_names[i], agg_counters[i]);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

/* runs in the context of a crypto thread */
void crypto_expire_request(uint32_t spi, uint32_t reqid,
			   uint8_t proto, uint8_t hard)
{
	int rv;
	zsock_t *sock;

	sock = zsock_new_push(crypto_inproc);
	if (!sock) {
		CRYPTO_ERR("Failed to get socked for expire event\n");
		return;
	}

	rv = zsock_bsend(sock, "4411", spi, reqid, proto, hard);
	if (rv < 0)
		CRYPTO_ERR("Failed to send expire event to main (%d)\n", rv);

	zsock_destroy(&sock);
}

/* running in the main thread, handle crypto events */
static int handle_crypto_event(void *arg)
{
	zsock_t *sock = (zsock_t *)arg;
	int rc;
	uint8_t proto, hard;
	uint32_t spi, reqid;

	rc = zsock_brecv(sock, "4411", &spi, &reqid, &proto, &hard);
	if (rc < 0) {
		CRYPTO_ERR("Failed to receive event for main\n");
		return 0;
	}

	if (!rekey_listener)
		return 0;

	char *outbuf = NULL;
	size_t outsize = 0;
	FILE *f = open_memstream(&outbuf, &outsize);

	if (!f) {
		CRYPTO_ERR("Failed to open stream for rekey\n");
		return 0;
	}

	json_writer_t *wr = jsonw_new(f);

	if (!wr) {
		CRYPTO_ERR("Failed to open json writer for rekey\n");
		fclose(f);
		free(outbuf);
		return 0;
	}

	jsonw_name(wr, "REKEY");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "SPI", spi);
	jsonw_uint_field(wr, "proto", proto);
	jsonw_uint_field(wr, "reqid", reqid);
	jsonw_uint_field(wr, "hard", hard);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	/* the buffer isn't flushed until fclose */
	fclose(f);
	zstr_send(rekey_listener, outbuf);

	return 0;
}

/* open a socket to the rekey service */
void crypto_add_listener(const char *url)
{
	if (rekey_listener)
		zsock_destroy(&rekey_listener);
	if (url && strlen(url))
		rekey_listener = zsock_new_push(url);
	if (!rekey_listener)
		CRYPTO_ERR("Failed to open rekey socket (%s)\n", url);
}

unsigned long hash_xfrm_address(const xfrm_address_t *addr,
				const uint16_t family)
{
	if (family == AF_INET)
		return addr->a4;
	else
		return (addr->a6[0] + addr->a6[1] + addr->a6[2] + addr->a6[3]);
}

/* The vrf has been deleted so flush all the crypto state in it. */
static void crypto_vrf_flush(struct vrf *vrf)
{
	struct crypto_vrf_ctx *vrf_ctx;

	vrf_ctx = crypto_vrf_find(vrf->v_id);
	if (!vrf_ctx)
		return;

	crypto_policy_flush_vrf(vrf_ctx);
	crypto_sadb_flush_vrf(vrf_ctx);
	policy_feat_flush_vrf(vrf_ctx);
}

static const struct dp_event_ops crypto_events = {
	.vrf_delete = crypto_vrf_flush,
};

DP_STARTUP_EVENT_REGISTER(crypto_events);
