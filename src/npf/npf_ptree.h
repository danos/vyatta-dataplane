/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_PTREE_H
#define NPF_PTREE_H

#include <stdint.h>

struct ptree_node;
struct ptree_table;

struct ptree_table *ptree_table_create(uint8_t keylen);
int ptree_table_destroy(struct ptree_table *pt);

/*
 * Find longest match. key in network byte order.
 */
struct ptree_node *ptree_longest_match(struct ptree_table *pt,
				       const uint8_t *key);

/*
 * Find shortest match. key in network byte order.
 */
struct ptree_node *ptree_shortest_match(struct ptree_table *pt,
					const uint8_t *key);

/*
 * Insert or remove a key from the tree.  Key is in network byte order
 */
int ptree_insert(struct ptree_table *pt, const uint8_t *key, uint8_t mask);
int ptree_remove(struct ptree_table *pt, const uint8_t *key, uint8_t mask);

/*
 * Walk tree
 */
enum pt_walk_dir {
	PT_UP,
	PT_DOWN,
};

typedef int (pt_walk_cb)(struct ptree_node *, void *);

/*
 * Walk all leaves.  Return non-zero to stop.
 */
int ptree_walk(struct ptree_table *pt, enum pt_walk_dir dir,
	       pt_walk_cb *cb, void *data);

/*
 * Walk IPv4 address tree, and callback for each leaf with address range info
 * for each prefix.  Addresses returned in host byte order.
 */
struct ptree_ipv4_range_ctx {
	uint32_t  addr_naddrs;
	uint32_t  addr_first;
	uint32_t  addr_last;
	uint32_t  addr_mask;

	/* Callers data */
	uint8_t   data[0];
};
typedef int (pt_ipv4_range_cb)(struct ptree_ipv4_range_ctx *ctx);

int ptree_ipv4_addr_range_walk(struct ptree_table *pt, pt_ipv4_range_cb *cb,
			       struct ptree_ipv4_range_ctx *ctx);

/*
 * Walks an IPv4 address tree and adds up the the usable addresses for all
 * prefixes.
 */
uint64_t ptree_ipv4_table_range(struct ptree_table *pt);

/*
 * Table accessor functions
 */
uint8_t  ptree_get_table_keylen(struct ptree_table *pt);
uint32_t ptree_get_table_leaf_count(struct ptree_table *pt);
uint32_t ptree_get_table_branch_count(struct ptree_table *pt);

/*
 * Leaf node accessor functions
 */
uint8_t *ptree_get_key(struct ptree_node *n);
uint8_t  ptree_get_keylen(struct ptree_node *n);
uint8_t  ptree_get_mask(struct ptree_node *n);

#endif /* NPF_PTREE_H */
