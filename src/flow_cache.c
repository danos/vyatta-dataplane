/*-
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <inttypes.h>
#include <rte_mbuf.h>
#include <urcu.h>
#include <urcu/uatomic.h>
#include <rte_jhash.h>
#include "vplane_log.h"
#include "vplane_debug.h"
#include "json_writer.h"
#include "flow_cache.h"
#include "ip.h"
#include "vrf_internal.h"
#include "ip_funcs.h"
#include "../netinet6/ip6_funcs.h"

#define FLOW_CACHE_DEBUG(args...)			\
	DP_DEBUG(FLOW_CACHE, DEBUG, POLICY, args)

#define FLOW_CACHE_ERR(args...)				\
	DP_DEBUG(FLOW_CACHE, ERR, POLICY, args)

#define FLOW_CACHE_NOTICE(args...)			\
	DP_DEBUG(FLOW_CACHE, NOTICE, POLICY, args)

#define FLOW_CACHE_INFO(args...)			\
	DP_DEBUG(FLOW_CACHE, INFO, POLICY, args)

#define FLOW_CACHE_SIZE 4096

#define FLOW_CACHE_HASH_SEED 0xDEAFCAFE

struct flow_cache_hash_key {
	enum flow_cache_ftype af;
	union addr_u src;
	union addr_u dst;
	uint32_t proto;
	vrfid_t vrfid;
};

struct flow_cache_entry {
	struct cds_lfht_node fl_node;
	struct flow_cache_hash_key key;
	void     *rule;
	uint16_t context;
	uint32_t hit_count;
	uint32_t last_hit_count;
	struct rcu_head  flow_cache_rcu;
	char *padding[0] __rte_cache_aligned;
};

#define FLOW_CACHE_HASH_MIN  8
#define FLOW_CACHE_HASH_MAX  2048

#define FLOW_CACHE_MAX_COUNT  4096
#define FLOW_CACHE_MAX_MARKER  (FLOW_CACHE_MAX_COUNT + 1)

struct flow_cache_af {
	struct cds_lfht *cache_tbl;
	rte_atomic32_t  cache_cnt;
};

struct flow_cache_lcore {
	struct flow_cache_af cache_af[FLOW_CACHE_MAX];
};

struct flow_cache {
	uint32_t max_lcore_entries;

	/* array of hash tables indexed by dp_lcore_id */
	struct flow_cache_lcore *cache_lcore;
};

/* PR cache management */
static inline void
flow_cache_entry_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct flow_cache_entry,
			      flow_cache_rcu));
}

static inline void
flow_cache_entry_destroy(struct flow_cache_entry *cache_entry)
{
	call_rcu(&cache_entry->flow_cache_rcu, flow_cache_entry_free);
}

static inline bool
flow_cache_match_addr_v4(const struct flow_cache_entry *cache_entry,
			 const struct flow_cache_hash_key *flow_cache_key)
{
	if ((!addr_u_eq_v4(&cache_entry->key.src, &flow_cache_key->src) ||
	     (!addr_u_eq_v4(&cache_entry->key.dst, &flow_cache_key->dst))))
		return false;

	return true;
}

static inline bool
flow_cache_match_addr_v6(const struct flow_cache_entry *cache_entry,
			 const struct flow_cache_hash_key *flow_cache_key)
{
	if ((!addr_u_eq_v6(&cache_entry->key.src, &flow_cache_key->src) ||
	     (!addr_u_eq_v6(&cache_entry->key.dst, &flow_cache_key->dst))))
		return false;

	return true;
}

static inline int
flow_cache_match(struct cds_lfht_node *node, const void *key)
{
	const struct flow_cache_hash_key *flow_cache_key = key;
	const struct flow_cache_entry *cache_entry = caa_container_of(
		node, const struct flow_cache_entry, fl_node);
	int ret;

	if (cache_entry->key.af == FLOW_CACHE_IPV4)
		ret = flow_cache_match_addr_v4(cache_entry, flow_cache_key);
	else
		ret = flow_cache_match_addr_v6(cache_entry, flow_cache_key);

	if (!ret)
		return 0;

	if ((cache_entry->key.proto != flow_cache_key->proto) ||
	    (cache_entry->key.vrfid != flow_cache_key->vrfid))
		return 0;

	return 1;
}

_Static_assert(sizeof(struct flow_cache_hash_key) % 4 == 0,
	       "struct flow_cache_hash_key must be a multiple of 4 bytes");

static inline uint32_t
flow_cache_hash(const struct flow_cache_hash_key *h_key)
{
	return rte_jhash(h_key, sizeof(*h_key), FLOW_CACHE_HASH_SEED);
}

static inline void
flow_cache_entry_remove(struct flow_cache_lcore *cache_lcore,
			struct flow_cache_entry *cache_entry)
{
	enum flow_cache_ftype af = cache_entry->key.af;

	/*
	 * To avoid a race where an entry has been added but the count
	 * hasn't been bumped
	 */
	if (rte_atomic32_read(&cache_lcore->cache_af[af].cache_cnt) == 0)
		return;

	cds_lfht_del(cache_lcore->cache_af[af].cache_tbl,
		     &cache_entry->fl_node);
	flow_cache_entry_destroy(cache_entry);
	rte_atomic32_dec(&cache_lcore->cache_af[af].cache_cnt);
}

static int
flow_cache_insert(struct cds_lfht *tbl, struct flow_cache_entry *cache_entry,
		  uint32_t rss_hash, const struct flow_cache_hash_key *h_key)
{
	struct cds_lfht_node *ret_node;
	uint32_t hash;

	cds_lfht_node_init(&cache_entry->fl_node);

	if (rss_hash)
		hash = rss_hash;
	else
		hash = flow_cache_hash(h_key);

	ret_node = cds_lfht_add_unique(tbl, hash, flow_cache_match, h_key,
				       &cache_entry->fl_node);

	return (ret_node != &cache_entry->fl_node) ? -1 : 0;
}

static inline void
flow_cache_parse_hdr(struct rte_mbuf *m, enum flow_cache_ftype af,
		     struct flow_cache_hash_key *h)
{
	const struct iphdr *ip;
	const struct ip6_hdr *ip6;

	h->af = af;
	if (af == FLOW_CACHE_IPV4) {
		ip = iphdr(m);
		h->dst.ip_v4.s_addr = ip->daddr;
		h->src.ip_v4.s_addr = ip->saddr;
		h->proto = ip->protocol;
	} else if (af == FLOW_CACHE_IPV6) {
		ip6 = ip6hdr(m);
		memcpy(&h->dst.ip_v6, &ip6->ip6_dst, sizeof(ip6->ip6_dst));
		memcpy(&h->src.ip_v6, &ip6->ip6_src, sizeof(ip6->ip6_src));
		h->proto = ip6->ip6_nxt;
	}
	h->vrfid = pktmbuf_get_vrf(m);
}

int flow_cache_lookup(struct flow_cache *cache, struct rte_mbuf *m,
		      enum flow_cache_ftype af,
		      struct flow_cache_entry **entry)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct flow_cache_hash_key h_key;
	struct cds_lfht *table;
	unsigned int lcore = dp_lcore_id();
	uint32_t hash;

	if (unlikely(!cache || !m || !entry))
		return -EINVAL;

	table = rcu_dereference(
		cache->cache_lcore[lcore].cache_af[af].cache_tbl);
	if (!table)
		return -ENOENT;

	flow_cache_parse_hdr(m, af, &h_key);

	hash = m->hash.rss;
	if (!hash)
		hash = flow_cache_hash(&h_key);
	cds_lfht_lookup(table, hash, flow_cache_match, &h_key,
			&iter);

	node = cds_lfht_iter_get_node(&iter);
	if (!node)
		return -ENOENT;

	*entry =  caa_container_of(node, struct flow_cache_entry,
				   fl_node);

	(*entry)->hit_count++;
	return 0;
}

int flow_cache_entry_get_info(struct flow_cache_entry *entry,
			      void **rule, uint16_t *context)
{
	if (unlikely(!entry || !rule || !context))
		return -EINVAL;

	*rule = entry->rule;
	*context = entry->context;
	return 0;
}

int flow_cache_entry_set_info(struct flow_cache_entry *entry,
			      void *rule, uint16_t context)
{
	if (unlikely(!entry))
		return -EINVAL;

	entry->rule = rule;
	entry->context = context;
	return 0;
}

int
flow_cache_add(struct flow_cache *flow_cache, void *rule, uint16_t ctx,
	       struct rte_mbuf *m, enum flow_cache_ftype af)
{
	struct flow_cache_entry *cache_entry;
	int error;
	struct flow_cache_hash_key h_key;
	struct flow_cache_af *cache_af =
		&flow_cache->cache_lcore[dp_lcore_id()].cache_af[af];
	struct cds_lfht *table = rcu_dereference(cache_af->cache_tbl);

	if (!table)
		return -1;

	flow_cache_parse_hdr(m, af, &h_key);
	cache_entry = malloc_aligned(sizeof(struct flow_cache_entry));
	if (unlikely(cache_entry == NULL))
		return -1;

	cache_entry->key = h_key;
	cache_entry->rule = rule;
	cache_entry->hit_count = cache_entry->last_hit_count = 0;

	error = flow_cache_insert(table, cache_entry, m->hash.rss, &h_key);

	if (unlikely(error != 0)) {
		free(cache_entry);
		return -1;
	}
	flow_cache_entry_set_info(cache_entry, rule, ctx);
	rte_atomic32_inc(&cache_af->cache_cnt);
	return 0;
}

int
flow_cache_init_lcore(struct flow_cache *flow_cache, unsigned int lcore)
{
	enum flow_cache_ftype af, tmp_af;
	struct flow_cache_lcore *cache_lcore;

	if (!flow_cache || !flow_cache->cache_lcore ||
	    (lcore >= rte_lcore_count()))
		return -EINVAL;

	cache_lcore = &flow_cache->cache_lcore[lcore];
	for (af = FLOW_CACHE_IPV4; af < FLOW_CACHE_MAX; af++) {
		cache_lcore->cache_af[af].cache_tbl =
		cds_lfht_new(FLOW_CACHE_HASH_MIN,
			     FLOW_CACHE_HASH_MIN,
			     flow_cache->max_lcore_entries,
			     CDS_LFHT_AUTO_RESIZE,
			     NULL);
		if (cache_lcore->cache_af[af].cache_tbl == NULL)
			goto err;
	}
	return 0;

err:
	FLOW_CACHE_ERR("Failed to create flow cache table for cpu %d af %d\n",
		       lcore, af);
	for (tmp_af = FLOW_CACHE_IPV4; tmp_af < af; tmp_af++)
		if (cache_lcore->cache_af[tmp_af].cache_tbl) {
			cds_lfht_destroy(
				cache_lcore->cache_af[tmp_af].cache_tbl, NULL);
			cache_lcore->cache_af[tmp_af].cache_tbl = NULL;
		}
	return -ENOMEM;
}

struct flow_cache *flow_cache_init(uint32_t max_size)
{
	struct flow_cache *cache;

	cache = malloc(sizeof(*cache));
	if (!cache) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate flow cache\n");
		return NULL;
	}

	cache->max_lcore_entries = max_size;
	cache->cache_lcore = calloc(1, (sizeof(struct flow_cache_lcore) *
					rte_lcore_count()));
	if (!cache->cache_lcore) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate per-core flow cache table\n");
		free(cache);
		return NULL;
	}

	return cache;
}

void flow_cache_age(struct flow_cache *flow_cache)
{
	unsigned int lcore_id, max_lcores = rte_lcore_count();
	struct flow_cache_entry *cache_entry;
	struct flow_cache_lcore *cache_lcore;
	struct flow_cache_af *cache_af;
	enum flow_cache_ftype af;
	struct cds_lfht_iter iter;
	struct cds_lfht *table;

	for (lcore_id = 0; lcore_id < max_lcores; lcore_id++) {
		cache_lcore = &flow_cache->cache_lcore[lcore_id];
		for (af = FLOW_CACHE_IPV4; af < FLOW_CACHE_MAX; af++) {
			cache_af = &cache_lcore->cache_af[af];
			table = rcu_dereference(cache_af->cache_tbl);
			if (!table)
				continue;

			cds_lfht_for_each_entry(table, &iter, cache_entry,
						fl_node) {
				/*
				 * if hit count wasn't cached, cache it and
				 * wait for the next iteration. If not, remove
				 * the entry if there have been no more hits
				 */
				if (!cache_entry->last_hit_count &&
				    cache_entry->hit_count)
					cache_entry->last_hit_count =
						cache_entry->hit_count;
				else if (cache_entry->last_hit_count ==
					 cache_entry->hit_count)
					flow_cache_entry_remove(cache_lcore,
								cache_entry);
			}
		}
	}
}

static void
flow_cache_empty_table(struct flow_cache *flow_cache, unsigned int lcore,
		       enum flow_cache_ftype af)
{
	struct flow_cache_lcore *cache_lcore = &flow_cache->cache_lcore[lcore];
	struct flow_cache_entry *cache_entry;
	struct cds_lfht_iter iter;
	struct cds_lfht *table;

	table = rcu_dereference(cache_lcore->cache_af[af].cache_tbl);
	if (!table)
		return;

	cds_lfht_for_each_entry(table, &iter, cache_entry, fl_node)
		flow_cache_entry_remove(cache_lcore, cache_entry);
}

static void
flow_cache_destroy_table(struct flow_cache *flow_cache, unsigned int lcore,
			 enum flow_cache_ftype af)
{
	struct flow_cache_lcore *cache_lcore = &flow_cache->cache_lcore[lcore];
	struct cds_lfht *table;

	table = rcu_dereference(cache_lcore->cache_af[af].cache_tbl);
	if (!table)
		return;

	rcu_assign_pointer(cache_lcore->cache_af[af].cache_tbl, NULL);

	if (cds_lfht_destroy(table, NULL))
		FLOW_CACHE_ERR("Cache tbl destroy failed for lcore %d af %d\n",
			       lcore, af);
}

/*
 * This may be called in an rcu_callback or in the master thread. In the
 * rcu_callback it must be in clear_only mode.
 */
void
flow_cache_invalidate(struct flow_cache *flow_cache, bool disable,
		      bool clear_only)
{
	unsigned int lcore_id, max_lcores = rte_lcore_count();
	enum flow_cache_ftype af;

	for (lcore_id = 0; lcore_id < max_lcores; lcore_id++) {
		for (af = FLOW_CACHE_IPV4; af < FLOW_CACHE_MAX; af++) {
			flow_cache_empty_table(flow_cache, lcore_id, af);
			if (disable && !clear_only)
				flow_cache_destroy_table(flow_cache, lcore_id,
							 af);
		}
	}

	FLOW_CACHE_INFO("Flow cache %s\n",
			disable && !clear_only ? "disabled" : "invalidated");
}

static const char *af_names[FLOW_CACHE_MAX] = {
	[FLOW_CACHE_IPV4] = "ipv4",
	[FLOW_CACHE_IPV6] = "ipv6"
};

void flow_cache_dump(struct flow_cache *flow_cache, json_writer_t *wr,
		     bool detail, flow_cache_dump_cb dump_helper)
{
	unsigned int i;
	char addrbuf[INET6_ADDRSTRLEN];

	if (!wr)
		return;

	jsonw_start_object(wr);
	jsonw_start_array(wr);

	for (i = 0; i < rte_lcore_count(); i++) {
		struct flow_cache_lcore *cache_lcore;
		struct flow_cache_af *cache_af;
		struct flow_cache_entry *cache_entry;
		struct cds_lfht_iter iter;
		struct cds_lfht *table;
		bool disabled = false;

		jsonw_uint_field(wr, "core_id", i);

		cache_lcore = &flow_cache->cache_lcore[i];

		jsonw_start_array(wr);

		for (enum flow_cache_ftype af = FLOW_CACHE_IPV4;
		     af < FLOW_CACHE_MAX; af++) {
			jsonw_name(wr, af_names[af]);
			jsonw_start_object(wr);

			cache_af = &cache_lcore->cache_af[af];
			table = rcu_dereference(cache_af->cache_tbl);
			if (!table)
				disabled = true;

			if (disabled) {
				jsonw_string_field(wr, "flow_cache",
						   "disabled");
				continue;
			}
			jsonw_string_field(wr, "flow_cache", "enabled");
			jsonw_start_object(wr);
			jsonw_uint_field(wr, "cache_cnt",
					 rte_atomic32_read(
						 &cache_af->cache_cnt));
			jsonw_end_object(wr);
			if (!detail)
				continue;

			jsonw_start_array(wr);
			cds_lfht_for_each_entry(table, &iter,
						cache_entry, fl_node) {
				int af;
				struct flow_cache_hash_key *cache_key;

				cache_key = &cache_entry->key;
				af = cache_key->af == FLOW_CACHE_IPV4 ?
					AF_INET : AF_INET6;
				jsonw_start_object(wr);
				jsonw_string_field(wr, "dst",
						   inet_ntop(af,
							     &cache_key->dst,
							     addrbuf,
							     sizeof(addrbuf)));
				jsonw_string_field(wr, "src",
						   inet_ntop(af,
							     &cache_key->src,
							     addrbuf,
							     sizeof(addrbuf)));
				jsonw_uint_field(wr, "proto", cache_key->proto);
				dump_helper(cache_entry, detail, wr);
				jsonw_end_object(wr);
			}
			jsonw_end_array(wr);
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
	}

	jsonw_end_array(wr);
	jsonw_end_object(wr);
}

