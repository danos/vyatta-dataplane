/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_CIDR_UTIL_H
#define NPF_CIDR_UTIL_H

#include <stdint.h>

/**
 * @file npf_cidr_util.h
 * @brief IPv4 and IPv6 CIDR Block Calculator
 *
 * A utility to generate canonized lists of CIDR notation netblocks from
 * expressions like "10.0.0.0-10.22.255.255" and/or "10.0.0.0/24"
 *
 * All addresses are in *host* byte order.
 *
 * Usage:
 *
 * // Callback for each canonized CIDR notation netblock
 * static int
 * client_cb(uint8_t *prefix, int alen, int mask, void *ctx)
 * {
 *     return 0;
 * }
 *
 * struct cidr_tree tree;
 *
 * npf_cidr_tree_init(&tree, alen);
 *
 * npf_cidr_save_range(&tree, start1, end1);
 * npf_cidr_save_range(&tree, start2, end2);
 * npf_cidr_save_prefix(&tree, addr, mask);
 * ...
 * npf_cidr_tree_walk(&tree, client_cb, ae);
 * npf_cidr_tree_free(&tree);
 */

struct cidr_node;

struct cidr_tree {
	int               alen;
	struct cidr_node *root;
};


/**
 * @brief Initialize tree root
 *
 * @param tree Pointer to tree
 */
void npf_cidr_tree_init(struct cidr_tree *tree, int alen);

/**
 * @brief Free tree
 *
 * @param tree Pointer to tree
 */
void npf_cidr_tree_free(struct cidr_tree *tree);

/**
 * @brief Save an address range to the tree
 *
 * @param tree Pointer to tree
 * @param a1 Start address in host byte order
 * @param a2 End address in host byte order
 */
void npf_cidr_save_range(struct cidr_tree *tree, uint8_t *a1,
			 uint8_t *a2);

/**
 * @brief Save a prefix/mask to the tree
 *
 * @param tree Pointer to tree
 * @param addr Prefix in host byte order
 * @param mask Mask length
 */
void npf_cidr_save_prefix(struct cidr_tree *tree, uint8_t *addr, int mask);

/**
 * @brief Callback function prototype for npf_cidr_tree_walk
 *
 * Called for each canonized CIDR notation netblock when npf_cidr_tree_walk is
 * called.
 *
 * @param prefix Pointer to CIDR netblock in host byte order
 * @param alen Address length
 * @param mask Mask length
 * @param ctx User supplied context
 * @return 0 to continue tree walk, < 0 to terminate
 */
typedef int (cidr_tree_walk_cb)(uint8_t *, int, int, void *);

/**
 * @brief Call callback function for each netblock in a tree
 *
 * Walks the tree in order, calling the supplied function for each CIDR
 * netblock.
 *
 * @param tree Pointer to tree
 * @param cb User supplied callback function
 * @param ctx User supplied context
 */
void npf_cidr_tree_walk(struct cidr_tree *tree, int alen,
			cidr_tree_walk_cb *cb, void *ctx);

#endif
