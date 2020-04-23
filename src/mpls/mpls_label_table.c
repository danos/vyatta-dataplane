/*
 * MPLS label table manipulation
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include "json_writer.h"
#include "main.h"
#include "mpls/mpls.h"
#include "mpls_label_table.h"
#include "pktmbuf_internal.h"
#include "route.h"
#include "route_flags.h"
#include "route_v6.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"

struct cds_lfht;

#define LABEL_TABLE_LFHT_INIT	LABEL_TABLE_LFHT_MIN
#define LABEL_TABLE_LFHT_MIN	32
/* Max is full label value range */
#define LABEL_TABLE_LFHT_MAX	(1 << 20)

struct label_table_node {
	uint32_t in_label; /* Incoming label */
	uint32_t next_hop; /* idx of output info */
	uint8_t nh_type;
	uint8_t payload_type;
	struct cds_lfht_node node;
	struct rcu_head rcu_head;
} __rte_cache_aligned;

/*
 * Currently we only support a single label space.  but we preserve
 * the underlying infra in case we ever have more.
 */
int global_label_space_id;
struct cds_lfht *global_label_table;

/* set of labelspaces, for each labelspaces there is label table */
static struct cds_list_head label_table_set;

static struct rte_mempool *mpls_oam_pool;

struct label_table_set_entry {
	struct cds_list_head entry;
	int labelspace; /* labelspace indentificator  */
	int refcount;
	struct cds_lfht *label_table;
	struct rcu_head rcu_head;
};

/*
 * Setup mbuf pool for oam lookup.
 */
static bool
mpls_oam_pool_init(void)
{
#define MPLS_OAM_POOL_NBUFS     (63)
#define MPLS_OAM_POOL_SIZE      (RTE_MBUF_DEFAULT_BUF_SIZE)
	unsigned int nbufs;

	nbufs = rte_align32pow2(MPLS_OAM_POOL_NBUFS) - 1;

	mpls_oam_pool = mbuf_pool_create("mpls oam", nbufs,
					 MBUF_CACHE_SIZE_DEFAULT,
					 MPLS_OAM_POOL_SIZE,
					 rte_socket_id());
	return mpls_oam_pool != NULL;
}

void
mpls_init(void)
{
	CDS_INIT_LIST_HEAD(&label_table_set);

	mpls_netlink_init();
}

static unsigned long
mpls_label_table_node_hash(struct label_table_node *label_table_node)
{
	return hash32(label_table_node->in_label, 32);
}

static int
mpls_label_table_node_match(struct cds_lfht_node *node, const void *key)
{
	const struct label_table_node *m = key;
	struct label_table_node *label_table_node = caa_container_of(node,
			struct label_table_node, node);

	if (m->in_label != label_table_node->in_label)
		return 0;
	return 1;
}

static unsigned long
mpls_label_table_count(struct cds_lfht *label_table)
{
	unsigned long count;
	long dummy;

	cds_lfht_count_nodes(label_table, &dummy, &count, &dummy);
	return count;
}

static void
free_label_table_node_rcu(struct rcu_head *head)
{
	struct label_table_node *label_table_node =
		caa_container_of(head, struct label_table_node, rcu_head);

	free(label_table_node);
}

static void free_label_table_node(struct label_table_node *label_table_entry)
{
	switch (label_table_entry->nh_type) {
	case NH_TYPE_V4GW:
		nexthop_put(AF_INET, label_table_entry->next_hop);
		break;
	case NH_TYPE_V6GW:
		nexthop6_put(AF_INET6, label_table_entry->next_hop);
		break;
	}

	call_rcu(&label_table_entry->rcu_head,
		 free_label_table_node_rcu);
}

static void
free_label_table_set_entry_rcu(struct rcu_head *head)
{
	struct label_table_set_entry *ls_entry =
		caa_container_of(head, struct label_table_set_entry, rcu_head);

	/*
	 * Every label table entry added should have resulted in the
	 * ref count being incremented. The exception is the reserved
	 * labels, but they should have been deleted prior to this
	 * point. Therefore, there should never be any labels left at
	 * this point.
	 */
	assert(!mpls_label_table_count(ls_entry->label_table));

	dp_ht_destroy_deferred(ls_entry->label_table);
	free(ls_entry);
}

static bool
mpls_label_table_ins_lbl_internal(struct cds_lfht *label_table,
				  uint32_t in_label, enum nh_type nh_type,
				  enum mpls_payload_type payload_type,
				  union next_hop_v4_or_v6_ptr hops,
				  size_t size)
{
	struct label_table_node *label_table_node;
	struct cds_lfht_node *node;
	uint32_t nextu_idx;
	int rc;
	bool added_new = false;

	if (!label_table) {
		RTE_LOG(ERR, MPLS,
			"There is no label table for this insertion\n");
		return false;
	}
	if ((unsigned long long)payload_type >
	    (1ull << sizeof(label_table_node->payload_type) * CHAR_BIT) - 1) {
		RTE_LOG(ERR, MPLS, "Bad mpls payload type 0x%x\n",
			payload_type);
		return false;
	}

	label_table_node = malloc_aligned(sizeof(*label_table_node));
	if (!label_table_node) {
		RTE_LOG(ERR, MPLS, "Failed to create label table node\n");
		return false;
	}

	switch (nh_type) {
	case NH_TYPE_V4GW:
		rc = nexthop_new(AF_INET, hops.v4, size, RTPROT_UNSPEC,
				 &nextu_idx);
		if (rc < 0) {
			RTE_LOG(ERR, MPLS,
				"Failed to create nexthops for label table entry: %s\n",
				strerror(-rc));
			free(label_table_node);
			return false;
		}
		break;
	case NH_TYPE_V6GW: {
		rc = nexthop_new(AF_INET6, hops.v6, size, RTPROT_UNSPEC,
				 &nextu_idx);
		if (rc < 0) {
			RTE_LOG(ERR, MPLS,
				"Failed to create nexthops for label table entry: %s\n",
				strerror(-rc));
			free(label_table_node);
			return false;
		}
		break;
	}
	default:
		RTE_LOG(ERR, MPLS,
			"Unsupported nh type %d\n", nh_type);
		free(label_table_node);
		return false;
	}

	label_table_node->next_hop = nextu_idx;
	cds_lfht_node_init(&label_table_node->node);
	label_table_node->in_label = in_label;
	label_table_node->nh_type = nh_type;
	label_table_node->payload_type = (uint8_t)payload_type;

	rcu_read_lock();
	node = cds_lfht_add_replace(label_table,
				    mpls_label_table_node_hash(
					    label_table_node),
				    mpls_label_table_node_match,
				    label_table_node, &label_table_node->node);
	if (node) {
		DP_DEBUG(MPLS_CTRL, DEBUG, MPLS,
			 "Free the old label table entry for label %d\n",
			 in_label);
		label_table_node = caa_container_of(node,
						  struct label_table_node,
						  node);
		free_label_table_node(label_table_node);
	} else {
		added_new = true;
	}
	DP_DEBUG(MPLS_CTRL, DEBUG, MPLS, "%s count = %lu\n", __func__,
			mpls_label_table_count(label_table));
	rcu_read_unlock();

	return added_new;
}

static int
mpls_label_table_rem_lbl_internal(struct cds_lfht *label_table,
				  uint32_t in_label)
{
	struct label_table_node *out, in;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	int rc;

	rcu_read_lock();

	in.in_label = in_label;
	cds_lfht_lookup(label_table, mpls_label_table_node_hash(&in),
			mpls_label_table_node_match, &in, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node) {
		out = caa_container_of(node, struct label_table_node, node);
		if (!cds_lfht_del(label_table, &out->node))
			free_label_table_node(out);
		rc = 0;
	} else {
		rc = -ENOENT;
	}
	DP_DEBUG(MPLS_CTRL, DEBUG, MPLS, "%s rc = %d count = %lu\n",
		 __func__, rc,
		 mpls_label_table_count(label_table));
	rcu_read_unlock();
	return rc;
}

/*
 * Delete entries for the various mpls reserved label values.
 */
static void
mpls_label_table_del_reserved_labels(struct cds_lfht *table)
{
	mpls_label_table_rem_lbl_internal(table, MPLS_IPV4EXPLICITNULL);
	mpls_label_table_rem_lbl_internal(table, MPLS_IPV6EXPLICITNULL);
	mpls_label_table_rem_lbl_internal(table, MPLS_ROUTERALERT);
}

/*
 * Add entries for the various mpls reserved label values.
 */
static bool
mpls_label_table_add_reserved_labels(struct cds_lfht *table)
{
	union next_hop_v4_or_v6_ptr nhop;
	struct ip_addr addr_any = {
		.type = AF_INET,
		.address.ip_v4.s_addr = INADDR_ANY,
	};

	/*
	 * IPv4/6 Exp NULL
	 * Nexthops without gateway or interface but with an imp null
	 * outlabel to indicate that labels should be popped.
	 */
	label_t outlabels[] = {MPLS_IMPLICITNULL};

	nhop.v4 = nexthop_create(NULL, &addr_any, 0, 1, outlabels);
	if (!nhop.v4)
		goto error;
	mpls_label_table_ins_lbl_internal(table, MPLS_IPV4EXPLICITNULL,
					  NH_TYPE_V4GW, MPT_IPV4,
					  nhop, 1);
	mpls_label_table_ins_lbl_internal(table, MPLS_IPV6EXPLICITNULL,
					  NH_TYPE_V4GW, MPT_IPV6,
					  nhop, 1);
	free(nhop.v4);

	nhop.v4 = nexthop_create(NULL, &addr_any, RTF_SLOWPATH, 1, outlabels);
	if (!nhop.v4)
		goto error;
	mpls_label_table_ins_lbl_internal(table, MPLS_ROUTERALERT,
					  NH_TYPE_V4GW, 0, nhop, 1);
	free(nhop.v4);

	return true;

error:
	RTE_LOG(ERR, MPLS,
		"Out of memory allocating nexthops for reserved labels\n");
	mpls_label_table_del_reserved_labels(table);
	return false;
}

static struct label_table_set_entry *
mpls_label_space_entry_get(int labelspace)
{
	struct label_table_set_entry *ls_entry;

	cds_list_for_each_entry_rcu(ls_entry, &label_table_set, entry) {
		if (ls_entry->labelspace == labelspace)
			return ls_entry;
	}

	return NULL;
}

static struct cds_lfht *
mpls_label_table_get_rcu(int labelspace)
{
	struct label_table_set_entry *ls_entry;

	ls_entry = mpls_label_space_entry_get(labelspace);
	if (ls_entry) {
		DP_DEBUG(MPLS_CTRL, DEBUG, MPLS,
			 "label table found for labelspace %d\n",
			labelspace);
		return rcu_dereference(ls_entry->label_table);
	}

	return NULL;
}

/*
 * Find or create a label table and increment its refcount.  Note
 * because we play with the refcount this is NOT safe to call from
 * forwarding threads.
 *
 * There will be a refcount per non-reserved label entry inserted into
 * the table plus one for each interface that references the table
 * plus ones for any transient references that have been got via this
 * function. Note - there is NOT a count held by the global label table
 * pointer or by any references held by RCU readers such as the
 * forwarding path.
 */
struct cds_lfht *
mpls_label_table_get_and_lock(int labelspace)
{
	static bool first_time_alloc = true;
	struct label_table_set_entry *ls_entry;

	if (first_time_alloc) {
		if (!mpls_oam_pool_init()) {
			RTE_LOG(ERR, MPLS, "Failed to allocate oam pool\n");
			return NULL;
		}
		first_time_alloc = false;
	}

	ls_entry = mpls_label_space_entry_get(labelspace);
	if (ls_entry) {
		DP_DEBUG(MPLS_CTRL, DEBUG, MPLS,
			 "label table found for labelspace %d\n",
			labelspace);
		ls_entry->refcount++;
		return ls_entry->label_table;
	}

	DP_DEBUG(MPLS_CTRL, DEBUG, MPLS, "label table not found\n");
	ls_entry = malloc(sizeof(*ls_entry));
	if (!ls_entry) {
		RTE_LOG(ERR, MPLS,
			"Failed to create label table set entry for labelspace %d\n",
			labelspace);
		return NULL;
	}
	ls_entry->labelspace = labelspace;
	ls_entry->label_table = cds_lfht_new(LABEL_TABLE_LFHT_INIT,
					     LABEL_TABLE_LFHT_MIN,
					     LABEL_TABLE_LFHT_MAX,
					     CDS_LFHT_AUTO_RESIZE, NULL);
	if (!ls_entry->label_table) {
		RTE_LOG(ERR, MPLS,
			"Unable to create label table hash table for labelspace %d\n",
			labelspace);
		free(ls_entry);
		return NULL;
	}
	ls_entry->refcount = 1;
	if (!mpls_label_table_add_reserved_labels(ls_entry->label_table)) {
		free_label_table_set_entry_rcu(&ls_entry->rcu_head);
		return NULL;
	}

	cds_list_add_tail_rcu(&ls_entry->entry, &label_table_set);

	/*
	 * If we are allocating the table for the global labelspace then
	 * stash the global pointer to it.
	 */
	if (labelspace == global_label_space_id) {
		assert(!global_label_table);
		rcu_read_lock();
		rcu_assign_pointer(global_label_table,
				   ls_entry->label_table);
		rcu_read_unlock();
	}
	return ls_entry->label_table;
}

/*
 * Decrement the refcount on the label space.
 *
 * There will be a refcount per non-reserved label entry inserted into
 * the table plus one for each interface that references the table
 * plus ones for any transient references that have been got via this
 * function. Note - there is NOT a count held by the global label table
 * pointer or by any references held by RCU readers such as the
 * forwarding path.
 *
 * If the refcount hits zero then rcu delete the table. If the table
 * is for the global labelspace then also clear the global pointer
 * before doing the delete.
 */
static void
mpls_label_table_unlock_internal(struct label_table_set_entry *ls_entry)
{
	DP_DEBUG(MPLS_CTRL, DEBUG, MPLS,
		 "unlocking label table for labelspace %d\n",
		 ls_entry->labelspace);
	ls_entry->refcount--;

	if (ls_entry->refcount == 0) {
		/*
		 * If we are deallocating the table
		 * for the global labelspace then
		 * clear the global pointer to it.
		 */
		if (ls_entry->labelspace == global_label_space_id) {
			assert(global_label_table);
			rcu_assign_pointer(global_label_table, NULL);
		}

		DP_DEBUG(MPLS_CTRL, DEBUG, MPLS,
			 "label table for labelspace %d is being deleted\n",
			 ls_entry->labelspace);
		mpls_label_table_del_reserved_labels(ls_entry->label_table);
		cds_list_del_rcu(&ls_entry->entry);

		call_rcu(&ls_entry->rcu_head, free_label_table_set_entry_rcu);
	}
}

void mpls_label_table_unlock(int labelspace)
{
	struct label_table_set_entry *ls_entry;

	ls_entry = mpls_label_space_entry_get(labelspace);
	if (!ls_entry)
		return;

	mpls_label_table_unlock_internal(ls_entry);
}

void mpls_label_table_insert_label(int labelspace, uint32_t in_label,
			     enum nh_type nh_type,
			     enum mpls_payload_type payload_type,
			     union next_hop_v4_or_v6_ptr hops,
			     size_t size)
{
	struct cds_lfht *label_table =
		mpls_label_table_get_and_lock(labelspace);

	/*
	 * if we inserted a new entry then keep lock on table for
	 * it - otherwise release the refcount we took above.
	 */
	if (!mpls_label_table_ins_lbl_internal(label_table, in_label,
					       nh_type, payload_type,
					       hops, size))
		mpls_label_table_unlock(labelspace);
}

static inline struct label_table_node *
mpls_label_table_lookup_internal(struct cds_lfht *label_table,
				 uint32_t in_label)
{
	struct label_table_node in;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	if (unlikely(!label_table))
		return NULL;
	in.in_label = in_label;
	cds_lfht_lookup(label_table, mpls_label_table_node_hash(&in),
			mpls_label_table_node_match, &in, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (likely(node != NULL)) {
		return caa_container_of(node, struct label_table_node, node);
	}
	return NULL;
}

union next_hop_v4_or_v6_ptr
mpls_label_table_lookup(struct cds_lfht *label_table, uint32_t in_label,
			const struct rte_mbuf *m, uint16_t ether_type,
			enum nh_type *nht,
			enum mpls_payload_type *payload_type)
{
	struct label_table_node *out;
	union next_hop_v4_or_v6_ptr nh = { NULL };

	out = mpls_label_table_lookup_internal(label_table, in_label);
	if (likely(out != NULL)) {
		*nht = out->nh_type;
		*payload_type = out->payload_type;
		return nh_select(*nht, out->next_hop, m, ether_type);
	}
	return nh;
}

void mpls_label_table_remove_label(int labelspace, uint32_t in_label)
{
	struct label_table_set_entry *ls_entry;

	ls_entry = mpls_label_space_entry_get(labelspace);
	if (!ls_entry)
		return;

	if (!mpls_label_table_rem_lbl_internal(ls_entry->label_table, in_label))
		/*
		 * Deleted an entry so lose its lock on the table
		 */
		mpls_label_table_unlock_internal(ls_entry);
}

void mpls_label_table_resize(int labelspace, uint32_t max_label)
{
	struct label_table_node *label_table_entry;
	struct label_table_set_entry *ls_entry;
	struct cds_lfht_iter iter;

	DP_DEBUG(MPLS_CTRL, INFO, MPLS, "mpls label table resize to %u\n",
		 max_label);

	rcu_read_lock();

	ls_entry = mpls_label_space_entry_get(labelspace);
	if (!ls_entry) {
		rcu_read_unlock();
		return;
	}

	cds_lfht_for_each_entry(ls_entry->label_table, &iter,
				label_table_entry, node) {
		if (label_table_entry->in_label >= max_label &&
		    !cds_lfht_del(ls_entry->label_table,
				  &label_table_entry->node)) {
			DP_DEBUG(MPLS_CTRL, DEBUG, MPLS,
				 "purging label %u due to resize\n",
				 label_table_entry->in_label);
			free_label_table_node(label_table_entry);
			/* release lock on table for presence of route */
			mpls_label_table_unlock_internal(ls_entry);
		}
	}

	rcu_read_unlock();
}

static void
mpls_label_table_dump(struct cds_lfht *label_table, json_writer_t *json)
{
	struct label_table_node *label_table_entry;
	struct cds_lfht_iter iter;

	if (!mpls_label_table_count(label_table))
		return;
	jsonw_name(json, "mpls_routes");
	jsonw_start_array(json);
	rcu_read_lock();
	cds_lfht_for_each_entry(label_table, &iter, label_table_entry, node) {
		jsonw_start_object(json);
		jsonw_uint_field(json, "address", label_table_entry->in_label);
		switch (label_table_entry->nh_type) {
		case NH_TYPE_V4GW:
			rt_print_nexthop(json, label_table_entry->next_hop,
					 RT_PRINT_NH_BRIEF);
			break;
		case NH_TYPE_V6GW:
			rt6_print_nexthop(json, label_table_entry->next_hop,
					  RT_PRINT_NH_BRIEF);
			break;
		}
		jsonw_uint_field(json, "payload",
				 label_table_entry->payload_type);
		jsonw_uint_field(json, "nexthop_type",
				 label_table_entry->nh_type);

		jsonw_end_object(json);
	}
	rcu_read_unlock();
	jsonw_end_array(json);
}

void
mpls_label_table_set_dump(FILE *fp, const int labelspace)
{
	struct label_table_set_entry *ls_entry;
	json_writer_t *json = jsonw_new(fp);

	jsonw_name(json, "mpls_tables");
	jsonw_start_array(json);
	cds_list_for_each_entry_rcu(ls_entry, &label_table_set, entry) {
		if (labelspace != -1 && ls_entry->labelspace != labelspace)
			continue;

		jsonw_start_object(json);
		jsonw_uint_field(json, "lblspc", ls_entry->labelspace);
		mpls_label_table_dump(ls_entry->label_table, json);
		jsonw_end_object(json);
	}
	jsonw_end_array(json);
	jsonw_destroy(&json);
}

void
mpls_oam_v4_lookup(int labelspace, uint8_t nlabels, const label_t *labels,
		   uint32_t saddr, uint32_t daddr,
		   unsigned short sport, unsigned short dport,
		   uint64_t bitmask, unsigned int masklen,
		   struct mpls_oam_outinfo outinfo[],
		   unsigned int max_fanout)
{
	union next_hop_v4_or_v6_ptr nh;
	struct cds_lfht *label_table;
	struct label_table_node *out;
	struct next_hop *paths;
	struct rte_mbuf *m;
	struct ether_hdr *eth;
	label_t *lbl_stack;
	struct iphdr *ip;
	struct udphdr *udp;
	int i, addr_index;
	uint8_t npaths, mpls_ttl = 1;
	uint16_t payload, hlen = 0;
	unsigned int oi;

	rcu_read_lock();

	label_table = mpls_label_table_get_rcu(labelspace);
	if (!label_table) {
		rcu_read_unlock();
		return;
	}

	out = mpls_label_table_lookup_internal(label_table, labels[0]);
	if (!out) {
		rcu_read_unlock();
		return;
	}

	if (out->nh_type != NH_TYPE_V4GW) {
		rcu_read_unlock();
		return;
	}

	m = pktmbuf_alloc(mpls_oam_pool, VRF_DEFAULT_ID);
	if (!m) {
		rcu_read_unlock();
		return;
	}

	hlen = nlabels * sizeof(label_t);
	payload = sizeof(struct udphdr) + sizeof(struct iphdr);
	if (!rte_pktmbuf_append(m, sizeof(struct ether_hdr) + hlen +
				payload)) {
		rte_pktmbuf_free(m);
		rcu_read_unlock();
		return;
	}

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);
	memset(eth, 0, sizeof(*eth));
	eth->ether_type = htons(ETH_P_MPLS_UC);
	m->l2_len = sizeof(struct ether_hdr);

	/*
	 * MPLS Incoming Label Stack
	 */
	lbl_stack = dp_pktmbuf_mtol3(m, label_t *);
	for (i = 0; i < nlabels; i++)
		if (i == nlabels - 1)
			*lbl_stack++ = htonl(labels[i] << MPLS_LS_LABEL_SHIFT |
					     1 << MPLS_LS_S_SHIFT | mpls_ttl);
		else
			*lbl_stack++ = htonl(labels[i] << MPLS_LS_LABEL_SHIFT |
					     mpls_ttl);

	m->l2_len += (nlabels * sizeof(label_t));

	/*
	 * IP Header
	 */
	ip = dp_pktmbuf_mtol3(m, struct iphdr *);
	ip->ihl = 5;
	ip->version = 4;
	ip->tot_len = htons(payload);
	ip->id = ip->frag_off = ip->tos = 0;
	ip->ttl = 1;
	ip->protocol = IPPROTO_UDP;
	ip->saddr = saddr;
	m->l3_len = sizeof(struct iphdr);

	/*
	 * UDP MPLS Echo Request
	 */
	udp = dp_pktmbuf_mtol4(m, struct udphdr *);
	memset(udp, 0, sizeof(struct udphdr));
	udp->source = htons(sport);
	udp->dest = htons(dport);

	/*
	 * Reset L2 header to the end of the ethernet header
	 */
	m->l2_len = ETHER_HDR_LEN;

	npaths = 0;
	paths = nexthop_get(out->next_hop, &npaths);
	for (i = 0; i < npaths; i++) {
		nh.v4 = paths + i;
		if (nh.v4->flags & RTF_DEAD)
			continue;
		for (oi = 0; oi < max_fanout; oi++) {
			if (!outinfo[oi].inuse) {
				outinfo[oi].ifp = dp_nh_get_ifp(nh.v4);
				outinfo[oi].gateway = nh.v4->gateway4;
				outinfo[oi].outlabels = nh.v4->outlabels;
				outinfo[oi].bitmask = 0;
				outinfo[oi].inuse = true;
				break;
			}
		}
	}

	daddr = ntohl(daddr);

	for (addr_index = 0, i = (masklen - 1); i >= 0; addr_index++, i--) {
		if (!(bitmask & ((uint64_t)1 << i)))
			continue;
		ip->daddr = htonl(daddr + addr_index);
		ip->check = 0;

		nh = nh_select(out->nh_type, out->next_hop, m, ETH_P_MPLS_UC);
		if (!nh.v4)
			continue;

		for (oi = 0; oi < max_fanout; oi++) {
			if (!outinfo[oi].inuse) {
				outinfo[oi].ifp = dp_nh_get_ifp(nh.v4);
				outinfo[oi].gateway = nh.v4->gateway4;
				outinfo[oi].outlabels = nh.v4->outlabels;
				outinfo[oi].bitmask = ((uint64_t)1 << i);
				outinfo[oi].inuse = true;
				break;
			}
			if ((outinfo[oi].ifp == dp_nh_get_ifp(nh.v4)) &&
			    (outinfo[oi].gateway == nh.v4->gateway4) &&
			     nh_outlabels_cmpfn(&outinfo[oi].outlabels,
						&nh.v4->outlabels)) {
				outinfo[oi].bitmask |=
					((uint64_t)1 << i);
				break;
			}
		}
	}

	rte_pktmbuf_free(m);
	rcu_read_unlock();
}
