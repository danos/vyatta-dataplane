/*-
 * Copyright (c) 2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef FLOW_CACHE_H

#define FLOW_CACHE_H

struct flow_cache;
struct flow_cache_entry;

/*
 * set of flow types supported by flow cache
 * allows af to be used as index and enables common code
 */
enum flow_cache_ftype {
	FLOW_CACHE_IPV4,
	FLOW_CACHE_IPV6,
	FLOW_CACHE_MAX
};

/**
 * Set up flow cache. The flow cache consists of an array of lock-free
 * hash tables indexed by dp_lcore_id. Each hash table contains entries
 * keyed by RSS hash of the packet or hash value computed by the library.
 *
 * @param max_entries
 *   Maximum number of entries in cache
 *
 * @return
 *   The pointer to the flow cache on success
 *   NULL if allocation fails
 */
struct flow_cache *flow_cache_init(uint32_t max_entries);

/**
 * Initialize table specific to the lcore
 * Invoked when lcore is brought up
 *
 * @param cache
 *   Address of flow cache to be operated on
 *
 * @param
 *   core id returned by dp_lcore_id()
 *
 * @return
 *   0 on success
 *   -ENOMEM on failure
 */
int flow_cache_init_lcore(struct flow_cache *cache, unsigned int lcore_id);
int flow_cache_teardown_lcore(struct flow_cache *cache, unsigned int lcore_id);

/**
 *
 * Add an entry to the flow cache corresponding to the lcore from
 * which the function is invoked.
 *
 * @param cache
 *   Address of the flow cache to which entry is to be added
 *
 * @param rule
 *   Pointer to the application-specific rule for the entry.
 *   A NULL value indicates a flow entry that does not match
 *   any rule in the application's ruleset
 *
 * @param context
 *   Application specific context corresponding to rule
 *
 * @param m
 *   Packet belonging to flow. The address family is expected
 *   to match the address family used to create the cache
 *
 * @return
 *   0 on success
 *   -EINVAL if the address family of the packet does not match
 *   -ENOMEM if there is a memory allocation failure
 *   -ENOSPC if the cache is full
 */
int flow_cache_add(struct flow_cache *cache, void *rule, uint16_t context,
		   struct rte_mbuf *m, enum flow_cache_ftype ftype);

/**
 *
 * Look up cache entry corresponding to packet in lcore-specific cache
 *
 * @param cache
 *   Address of the flow cache in which the lookup is to be performed
 *
 * @param m
 *   Packet for which lookup is to be performed
 *
 * @param ftype
 *   Type of flow. Determines the table and match function used
 *
 * @param entry
 *   Output parameter. Cache entry corresponding to packet.
 *   NULL indicates that this is a flow without a cache entry.
 *
 * @return
 *   0 on success
 *   -ENOENT if there is no entry
 */
int flow_cache_lookup(struct flow_cache *cache, struct rte_mbuf *m,
		      enum flow_cache_ftype ftype,
		      struct flow_cache_entry **entry);

/**
 *
 * Accessor to retrieve information from cache entry
 *
 * @param entry
 *   Cache entry to retrieve information from
 *
 * @param rule
 *   Output parameter. Rule provided by application when the cache
 *   entry was created. Can be NULL. The NULL value is used in cases where
 *   an application needs to cache flows that do not match any rules
 *   in their rulesets.
 *
 * @param context
 *   Output parameter. Context provided by application when the cache entry
 *   is created.
 *
 */
int flow_cache_entry_get_info(struct flow_cache_entry *entry, void **rule,
			      uint16_t *context);

/**
 *
 * Accessor to set information in cache entry
 *
 * @param entry
 *   Cache entry to set information in
 *
 * @param rule
 *   Input parameter. Rule provided by application when the cache
 *   entry is created/updated. Can be NULL. The NULL value is used in cases
 *   where an application needs to cache flows that do not match any rules
 *   in their rulesets.
 *
 * @param context
 *   Input parameter. Context provided by application when the cache entry
 *   is created/updated.
 *
 */
int flow_cache_entry_set_info(struct flow_cache_entry *entry, void *rule,
			      uint16_t context);

/**
 *
 * Invalidate the flow cache. All entries in the cache are deleted.
 *
 * @param cache
 *   Address of the flow cache to be invalidated.
 *
 * @param disable
 *   Enable/disable flow cache
 *
 * @param clear_only
 *   If true, only the entries present are flushed.
 *   If false and disable is set to true, the entire table is destroyed
 *
 */
void flow_cache_invalidate(struct flow_cache *cache, bool disable,
			   bool clear_only);

/**
 * Walk the entire flow cache and age out entries for which
 * hit count has not changed. The aging interval and timer
 * are the responsibility of the calling application.
 *
 * @param cache
 *   Address of the flow cache
 */
void flow_cache_age(struct flow_cache *cache);


typedef void (*flow_cache_dump_cb)(struct flow_cache_entry *entry,
				   bool detail, json_writer_t *wr);
/**
 *
 * Dump entries in the flow cache
 *
 * @param cache
 *   Address of the flow cache
 *
 * @param wr
 *   json writer object to dump entries
 *
 * @param detail
 *   controls level of detail in output. if true, dump addresses
 *   If true, detailed information about flows is dumped.
 *
 * @param helper
 *   Callback invoked for each entry to emit application-specific info
 */
void flow_cache_dump(struct flow_cache *cache, json_writer_t *wr,
		     bool detail, flow_cache_dump_cb helper);

/**
 *
 * Destroy flow cache. Free up all entries
 *
 * @param cache
 *   Address of the flow cache to be cleaned up
 */
void flow_cache_destroy(struct flow_cache *cache);

#endif
