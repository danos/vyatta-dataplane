/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>

#include "compiler.h"
#include "npf_addr.h"
#include "npf_ptree.h"
#include "util.h"


/*
 * Patricia Tree
 *
 * A binary Radix trie where single-path nodes have been collapsed.  Separate
 * nodes are used for branches and leaves.
 *
 * Memory requirements are: 32 bytes per entry for IPv4, and 44 for IPv6.
 *
 * Address lookup starts at the root node, and at the most-significant bit,
 * bit 0, of the search key.
 *
 * If bit 0 is 0 we branch left, else we branch right.
 *
 * If the next node is a branch node, then it contains the next bit to check
 * in the search key.  In the example below, it is bit 2 on the right of the
 * root node.
 *
 * We keep branching left or right until we hit a leaf node *or* we reach a
 * point below which we know there is an entry with a mask length less or
 * equal to the branch bit.  From here we simply descend left to get to the
 * shortest prefix.
 *
 * Once we reach a leaf node, then we must do a key comparison since not all
 * bits are always checked on the descent to the leaf node.
 *
 * Simple Example with a 1 byte key (default mask length is 8)
 *
 * A:0x0C      0000 1100
 * B:0x20      0010 0000
 * C:0x40      0100 0000
 * D:0x44      0100 0100
 * E:0x80/6    1000 00**
 * F:0x82      1000 0010
 * G:0x88      1000 1000
 * H:0xA0      1010 0000
 *
 * The '0***' etc show which bits have been matched up to the node in
 * question.  So the '1*0' below and left of [g,2] mean we have matched a 1 at
 * bit 0 and a 0 at bit 2.
 *
 *                                    [a,0]
 *                           0****    /   \   1****
 *                                   /     \
 *                    +-------------+       +------------------+
 *                   /                                          \
 *                  /                                            \
 *               [c,1]                                          [g,2]
 *          00 /       \ 01                                   /       \
 *            /         \                               1*0  /         \ 1*1
 *           /           \                                  /           \
 *        [b,2]           \                              [f,4]         0xA0/8
 *   000  /   \001         \                     1*0*0   /   \ 1*0*1   H
 *       /     \            \                           /     \
 *      /       \            \                         /      0x88/8
 *   0x0C/8    0x20/8       [d,5]                    [e,6]    G
 *   A         B           /	  \                 /     \
 *                 01***0 /  01***1\       1*0*0*0 /       \ 1*0*0*1
 *                       /          \             /         \
 *                     0x40/8      0x44/8      0x80/6     0x82/8
 *                     C           D            E         F
 *
 *
 * Duplicate keys, with different masks, are not allowed.  It is expected that
 * the layer above will handle this if required, and only store the shortest
 * mask.
 */

/* Must be a multiple of 4 */
#define PT_KEYLEN_MAX      16

enum ptree_node_type {
	PN_TYPE_BRANCH = 0,
	PN_TYPE_LEAF,
};

enum {
	PN_LEFT  = 0,
	PN_RIGHT = 1
};

/*
 * Ptree branch node.
 */
struct ptree_node {
	uint8_t            pn_type;	/* Must be first */
	uint8_t            pn_min_mask;
	uint8_t            pn_bit;
	uint8_t            pn_pad[5];
	struct ptree_node *pn_branch[2];
};

#define pn_left   pn_branch[PN_LEFT]
#define pn_right  pn_branch[PN_RIGHT]

/*
 * Ptree entry.  key is in network-byte order
 */
struct ptree_leaf {
	uint8_t            pl_type;	/* Must be first */
	uint8_t            pl_mask;	/* Mask length bits */
	uint8_t            pl_keylen;	/* Key length bytes */
	uint8_t            pl_pad[1];
	uint8_t            pl_key[0];	/* Must be last */
};

/*
 * We pass and store pointers to nodes, so casts are required to access leaf
 * objects
 */
#define PL_KEY(_l)    (((struct ptree_leaf *)(_l))->pl_key)
#define PL_KEYLEN(_l) (((struct ptree_leaf *)(_l))->pl_keylen)
#define PL_MASK(_l)   (((struct ptree_leaf *)(_l))->pl_mask)


/*
 * Ptree table.
 *
 * pt_leaf_count   - Number of leaf nodes in the table
 * pt_branch_count - Number of branch nodes in the table, excl. root
 * pt_keylen       - key length in bytes
 * pt_root         - Root node.  Always a branch node.
 */
struct ptree_table {
	uint32_t           pt_leaf_count;
	uint32_t           pt_branch_count;
	uint8_t            pt_keylen;
	uint8_t            pt_pad[3];
	struct ptree_node  pt_root;	/* Must be last */
};

/*
 * Forward declarations
 */
static void ptree_branch_init(struct ptree_table *pt, struct ptree_node *n);

/* Is this a branch node? */
static ALWAYS_INLINE bool
pn_is_branch(struct ptree_node *n)
{
	return n && n->pn_type == PN_TYPE_BRANCH;
}

/* Is this a leaf node? */
static ALWAYS_INLINE bool
pn_is_leaf(struct ptree_node *n)
{
	return n && n->pn_type == PN_TYPE_LEAF;
}

/*
 * Is bit b set in key?
 *
 * It assumes that bit 0 is the most-significant bit and (alen*8 - 1) is the
 * least-significant bit.
 */
static bool bitisset(uint b, const uint8_t *key)
{
	return (key[b/8] & (1u << (7 - (b & 0x07)))) != 0;
}

/*
 * Branch left or right at node n
 */
static struct ptree_node *
ptree_branch(struct ptree_node *n, const uint8_t *key)
{
	return n->pn_branch[bitisset(n->pn_bit, key)];
}

/*
 * Find most-significant bit set in a word.  Bit 0 is most-significant bit,
 * and bit 31 is least-significant bit.  If no bits are set in the word then
 * it returns 32.
 */
static int msbit_word(uint32_t x)
{
	/* Change to host order, and count leading zeros */
	return npf_clz(ntohl(x));
}

/*
 * Find the most-significant bit that differs between two keys, each of which
 * are at least 'len' bytes long, where len is greater or equal to 4 and a
 * multiple of 4.
 *
 * Returns a bit position number in range 0 to (klen*8 - 1) if a difference is
 * found, where 0 is the most-significant bit and (klen*8 - 1) is the
 * least-significant bit.  Returns klen*8 if arrays are identical.
 */
static uint8_t
ptree_key_diff(const uint8_t *key1, const uint8_t *key2, uint8_t klen)
{
	int w, nwords = klen / 4;
	const uint32_t *w1 = (uint32_t *)key1, *w2 = (uint32_t *)key2;

	/* For each word, starting with the most significant */
	for (w = 0; w < nwords; w++)	{
		if (w1[w] != w2[w])
			return msbit_word(w1[w] ^ w2[w]) + w*32;
	}

	/* Byte keys are identical */
	return klen * 8;
}

/*
 * Compare the most-significant 'nbits' of two keys of length klen, one word
 * at a time.  Return true if they match.
 */
static bool
ptree_key_match(const uint8_t *key1, const uint8_t *key2, uint8_t nbits)
{
	int b, w;
	const uint32_t *w1 = (uint32_t *)key1, *w2 = (uint32_t *)key2;

	/* Compare whole words, starting at most significant word */
	for (b = nbits, w = 0; b >= 32; b -= 32, w++) {
		if (w1[w] != w2[w])
			return false;
	}

	/* Compare any remaining bits */
	if (b > 0) {
		uint32_t mask = htonl(npf_prefix_to_net_mask4(b));

		if ((w1[w] & mask) != (w2[w] & mask))
			return false;
	}

	return true;
}

/*
 * Copies masklen bits from src to dest.  Only copies significant bits in
 * order to leave host bits zeroed.
 */
static void
ptree_key_cpy(uint8_t *dest, const uint8_t *src, uint8_t masklen)
{
	int i, j;

	/* Copy whole bytes */
	for (i = masklen, j = 0; i >= 8; i -= 8, j++)
		dest[j] = src[j];

	/* Copy partial byte */
	if (i > 0)
		dest[j] = src[j] & (0xffu << (8-i));
}

/*
 * Create table
 */
struct ptree_table *
ptree_table_create(uint8_t keylen)
{
	struct ptree_table *pt = NULL;

	/* keylen must be between 4 and 16, and a multiple of 4 */
	if (keylen < 4 || keylen > PT_KEYLEN_MAX ||
	    (keylen & 0x3) != 0)
		return NULL;

	/* Ensure key starts on a word boundary */
	assert((offsetof(struct ptree_leaf, pl_key) & 0x3) == 0);

	if ((offsetof(struct ptree_leaf, pl_key) & 0x3) != 0)
		return NULL;

	/* type field must be in same place in leaf and branch struct */
	assert(offsetof(struct ptree_node, pn_type) ==
	       offsetof(struct ptree_leaf, pl_type));

	pt = zmalloc_aligned(sizeof(*pt));
	if (!pt)
		return NULL;

	pt->pt_keylen = keylen;
	pt->pt_leaf_count = 0;
	pt->pt_branch_count = 1;
	ptree_branch_init(pt, &pt->pt_root);

	return pt;
}

/*
 * Recurse down the tree.  Nullify pointers on way down, and free nodes on way
 * up.
 */
static void
ptree_table_destroyR(struct ptree_table *pt, struct ptree_node *n)
{
	if (!n)
		return;

	if (n->pn_type == PN_TYPE_LEAF) {
		pt->pt_leaf_count--;
		/* Free leaf */
		free(n);
		return;
	}

	/* Else must be a branch node */
	struct ptree_node *t;

	t = n->pn_left;
	n->pn_left = NULL;
	ptree_table_destroyR(pt, t);

	t = n->pn_right;
	n->pn_right = NULL;
	ptree_table_destroyR(pt, t);

	/* Free branch */
	pt->pt_branch_count--;
	free(n);
}

/*
 * Table destroy.  Remove and free all nodes, then free the table.
 */
int
ptree_table_destroy(struct ptree_table *pt)
{
	if (!pt)
		return -EINVAL;

	struct ptree_node *n = &pt->pt_root;

	/*
	 * Destroy left and right sub-trees separately so that
	 * ptree_table_destroyR doesn't try and free the root node.
	 */
	if (n->pn_left) {
		ptree_table_destroyR(pt, n->pn_left);
		n->pn_left = NULL;
	}

	if (n->pn_right) {
		ptree_table_destroyR(pt, n->pn_right);
		n->pn_right = NULL;
	}

	free(pt);

	return 0;
}

/*
 * Search for the given key, ignoring masks.  key is in network byte order.
 */
struct ptree_node *
ptree_find_key(struct ptree_table *pt, const uint8_t *key)
{
	uint8_t klen = pt->pt_keylen;
	struct ptree_node *p, *t;

	t = &pt->pt_root;

	do {
		p = t;
		t = ptree_branch(p, key);
	} while (pn_is_branch(t));

	/* t is a leaf or NULL */
	if (pn_is_leaf(t) && !memcmp(PL_KEY(t), key, klen))
		return t;

	return NULL;
}

/*
 * Descend tree from node 't', switching left or right depending on the
 * value of the branch bit in the search key.
 *
 * Stop at, or just below, the branch node where the branch node bit is
 * greater or equal to the min mask length for that node, or we hit a leaf
 * node.
 */
static inline struct ptree_node *
ptree_find_node(struct ptree_node *t, const uint8_t *key)
{
	struct ptree_node *p;

	/*
	 * Follow the tree down until branch node bit is greater or equal to
	 * the min mask length for that node, or we hit a leaf node
	 */
	while (pn_is_branch(t) && t->pn_bit < t->pn_min_mask) {
		p = t;
		t = ptree_branch(p, key);
	}

	/* empty branch under root node */
	if (unlikely(t == NULL))
		return NULL;

	return t;
}

/*
 * Find longest match for the given key.  Find best matching branch node, then
 * iteratively walk tree from that point.
 */
struct ptree_node *
ptree_longest_match(struct ptree_table *pt, const uint8_t *key)
{
	uint8_t klen = pt->pt_keylen;
	struct ptree_node *t;

	/* Descend tree, switching left or right on branch node bit */
	t = ptree_find_node(&pt->pt_root, key);

	if (!t)
		return NULL;

	if (t->pn_type == PN_TYPE_LEAF) {
		if (ptree_key_match(PL_KEY(t), key, PL_MASK(t)))
			return t;
		return NULL;
	}

	/*
	 * Walk tree from node 't' to find longest match
	 */
	int top = -1;
	struct ptree_node *stack[klen * 8 + 1];
	struct ptree_node *lm = NULL;

	stack[++top] = t->pn_right;			/* push right */
	stack[++top] = t->pn_left;			/* push left */

	while (top >= 0) {
		/*
		 * t may be NULL first time round this loop if left of root is
		 * empty
		 */
		t = stack[top--];			/* pop */
		if (!t)
			continue;

		if (t->pn_type == PN_TYPE_LEAF) {
			/*
			 * Dont bother with key comparison if nodes mask is
			 * less or equal to current longest-match candidate.
			 */
			if (!lm || PL_MASK(t) > PL_MASK(lm)) {
				if (ptree_key_match(PL_KEY(t), key, PL_MASK(t)))
					lm = t;
			}
		} else {
			stack[++top] = t->pn_right;	/* push right */
			stack[++top] = t->pn_left;	/* push left */
		}
	}
	return lm;
}

/*
 * Find shortest match for the given key.
 */
struct ptree_node *
ptree_shortest_match(struct ptree_table *pt, const uint8_t *key)
{
	struct ptree_node *t, *p;

	/* Descend tree, switching left or right on branch node bit */
	t = ptree_find_node(&pt->pt_root, key);

	if (!t)
		return NULL;

	if (pn_is_leaf(t)) {
		if (ptree_key_match(PL_KEY(t), key, PL_MASK(t)))
			return t;

		return NULL;
	}

	/*
	 * t is at the node where the branch bit is greater or equal to the
	 * min mask for this sub-tree.
	 *
	 * All bits in the search key up to the branch bit for t either match
	 * all leaves below here or match none.  Since we are only interested
	 * in any or shortest match, then we simply need to follow the left
	 * branches down to the node with the min mask, and compare the search
	 * key against that.
	 */
	do {
		p = t;
		t = p->pn_left;
	} while (pn_is_branch(t));

	assert(pn_is_leaf(t));

	if (ptree_key_match(PL_KEY(t), key, PL_MASK(t)))
		return t;

	return NULL;
}

static void
ptree_branch_init(struct ptree_table *pt, struct ptree_node *n)
{
	n->pn_type = PN_TYPE_BRANCH;
	n->pn_min_mask = pt->pt_keylen * 8;
	n->pn_bit = 0;
	n->pn_left = n->pn_right = NULL;
}

static struct ptree_node *
ptree_branch_create(struct ptree_table *pt)
{
	struct ptree_node *n;

	n = malloc_aligned(sizeof(*n));
	if (!n)
		return NULL;

	ptree_branch_init(pt, n);
	pt->pt_branch_count++;
	return n;
}

/*
 * Set the initial min_mask value for a new branch node as the minimum value
 * of the nodes to the left and right of the new branch node.
 */
static uint8_t
ptree_min_mask_initial_value(struct ptree_node *n, uint8_t klen)
{
	/* If n is a leaf, then min mask is simply the mask */
	if (pn_is_leaf(n))
		return PL_MASK(n);

	uint8_t left_mm = klen * 8;
	uint8_t right_mm = klen * 8;

	/* min mask on left of n */
	if (n->pn_left) {
		left_mm = pn_is_branch(n->pn_left) ?
			n->pn_left->pn_min_mask :
			PL_MASK(n->pn_left);
	}

	/* min mask on right of n */
	if (n->pn_right) {
		right_mm = pn_is_branch(n->pn_right) ?
			n->pn_right->pn_min_mask :
			PL_MASK(n->pn_right);
	}

	return MIN(left_mm, right_mm);
}

/*
 * Walk the tree and either 1. set the min mask for each node, or
 * 2. check the min mask is correct.
 */
struct ptree_min_mask_ctx {
	bool             set;
	bool             check;
	uint8_t          keylen;
};

static uint8_t
ptree_min_mask_walkR(struct ptree_node *n, struct ptree_min_mask_ctx *ctx,
		     uint8_t min_mask)
{
	uint8_t mml = min_mask, mmr = ctx->keylen * 8;

	/* escape condition, probably an error has been detected */
	if (min_mask == 0)
		return 0;

	if (!n)
		return MIN(mml, mmr);

	/* Is the leaf mask less than the current min? */
	if (pn_is_leaf(n)) {
		uint8_t leaf_mask = PL_MASK(n);

		return MIN(min_mask, leaf_mask);
	}

	/*
	 * Else must be a branch node.  Find min mask value on left and right
	 * sub-trees.
	 */
	mml = ptree_min_mask_walkR(n->pn_left, ctx, mml);
	mmr = ptree_min_mask_walkR(n->pn_right, ctx, mmr);

	if (ctx->check) {
		assert(n->pn_min_mask <= mmr);
		assert(n->pn_min_mask == MIN(mml, mmr));
	}

	if (ctx->set)
		n->pn_min_mask = MIN(mml, mmr);

	return MIN(mml, mmr);
}

#define PT_MM_SET   0x01
#define PT_MM_CHECK 0x02

static uint8_t
ptree_min_mask_walk(struct ptree_table *pt, uint8_t flags)
{
	struct ptree_min_mask_ctx ctx = {
		.set   = (flags & PT_MM_SET) != 0,
		.check = (flags & PT_MM_CHECK) != 0,
		.keylen = pt->pt_keylen,
	};
	uint8_t mml = ctx.keylen * 8, mmr = ctx.keylen * 8;

	mml = ptree_min_mask_walkR(pt->pt_root.pn_left, &ctx, mml);
	assert(mml);

	mmr = ptree_min_mask_walkR(pt->pt_root.pn_right, &ctx, mmr);
	assert(mmr);

	if (ctx.check)
		assert(pt->pt_root.pn_min_mask == MIN(mml, mmr));

	if (ctx.set)
		pt->pt_root.pn_min_mask = MIN(mml, mmr);

	return MIN(mml, mmr);
}

/* Time to turn over a new leaf ... */
static struct ptree_leaf *
ptree_leaf_create(struct ptree_table *pt, const uint8_t *key,
		      uint8_t masklen)
{
	struct ptree_leaf *l;

	l = zmalloc_aligned(sizeof(*l) + sizeof(uint8_t) * pt->pt_keylen);
	if (!l)
		return NULL;

	l->pl_type = PN_TYPE_LEAF;
	l->pl_mask = masklen;
	l->pl_keylen = pt->pt_keylen;
	ptree_key_cpy(l->pl_key, key, masklen);
	pt->pt_leaf_count++;
	return l;
}

/*
 * Create new branch node and leaf in order to insert new key into table.
 *
 * p - Note below which we want to add new leaf
 * t - Existing node below p.
 */
static int
ptree_leaf_insert(struct ptree_table *pt, const uint8_t *key,
		  uint8_t masklen, struct ptree_node *t,
		  struct ptree_node *p)
{
	uint8_t klen = pt->pt_keylen;
	struct ptree_node *b;
	struct ptree_leaf *n;

	/*
	 * Insert new branch node and leaf node
	 */
	b = ptree_branch_create(pt);
	if (!b)
		return -ENOMEM;

	/* New leaf node */
	n = ptree_leaf_create(pt, key, masklen);
	if (!n) {
		pt->pt_branch_count--;
		free(b);
		return -ENOMEM;
	}

	/*
	 * If we terminated at a leaf that does *not* match the key, then we
	 * need to create a new branch node.
	 *
	 * First we need to determine which bit the key differs from this leaf
	 * node.
	 *
	 * If this diff bit is greater or equal than the leaf nodes parent
	 * bit, then we can insert a new branch node below the parent node, in
	 * which case the new key will be inserted under the new branch node
	 * (on other branch from t).
	 *
	 * If 'diff' is less than the leaf nodes parent bit, then we need to
	 * add a new branch node above p.
	 */
	struct ptree_node *x, *y;

	b->pn_bit = ptree_key_diff(key, PL_KEY(t), klen);

	/*
	 * Using the given key, follow the tree down.  But this time we stop
	 * when we reach a branch node, y, who's bit is equal or greater than
	 * the diff bit, where x is the parent of y.
	 *
	 * We insert the new branch node b below x, and then insert new leaf n
	 * and leaf/branch y below b, e.g.
	 *
	 *             [x,1]                   [x,1]
	 *            /    \                  /
	 *           /                     [b,2]
	 *          /          ==>        /    \
	 *      [y,3]                  [y,3]   [n] (leaf)
	 *       /                    /
	 *    [t] (leaf)            [t] (leaf)
	 *
	 *
	 * We have either:
	 *
	 * x/p -> y/t
	 * x -> y/p -> t
	 * x -> y -> p -> t
	 * x -> y -> ... -> p -> t
	 *
	 * where t is a leaf node, and all others are branch nodes (except
	 * when y == t).
	 *
	 * We want to insert the new branch node b below x.
	 */
	x = y = &pt->pt_root;

	while (pn_is_branch(y) && b->pn_bit > y->pn_bit) {
		x = y;
		y = ptree_branch(x, key);
	}

	if (b->pn_bit >= p->pn_bit)
		assert(y == t);

	/* Link b as child of x */
	if (bitisset(x->pn_bit, PL_KEY(t)))
		x->pn_right = b;
	else
		x->pn_left = b;

	/* Link y and n as children of b */
	if (bitisset(b->pn_bit, PL_KEY(n))) {
		b->pn_right = (struct ptree_node *)n;
		b->pn_left = y;
	} else {
		b->pn_left = (struct ptree_node *)n;
		b->pn_right = y;
	}

	/*
	 * Set the initial min_mask value for a new branch node as the minimum
	 * value of the nodes to the left and right of the new branch node.
	 */
	b->pn_min_mask = ptree_min_mask_initial_value(b, klen);

	/*
	 * If the new leaf nodes mask length is less than the grand-parent p
	 * min mask then recalculate the min mask values for all nodes between
	 * root and the new node.
	 */
	if (masklen < p->pn_min_mask)
		ptree_min_mask_walk(pt, PT_MM_SET);

#ifndef	NDEBUG
	do {
		uint8_t mm;

		mm = ptree_min_mask_walk(pt, PT_MM_CHECK);
		assert(mm);
	} while (0);
#endif
	return 0;
}

/*
 * Create leaf directly under root node.
 *
 * p - Note below which we want to add new leaf
 * t - Existing node below p.
 */
static int
ptree_leaf_insert_at_root(struct ptree_table *pt, const uint8_t *key,
			  uint8_t masklen)
{
	struct ptree_node *p = &pt->pt_root;
	struct ptree_leaf *n;

	n = ptree_leaf_create(pt, key, masklen);
	if (!n)
		return -ENOMEM;

	if (bitisset(p->pn_bit, key)) {
		/* Insert right */
		assert(p->pn_right == NULL);
		p->pn_right = (struct ptree_node *)n;
	} else {
		/* Insert left */
		assert(p->pn_left == NULL);
		p->pn_left = (struct ptree_node *)n;
	}

	/*
	 * Re-calculate the min mask value for the root node
	 */
	p->pn_min_mask = MIN(p->pn_min_mask, masklen);

#ifndef	NDEBUG
	do {
		uint8_t mm;

		mm = ptree_min_mask_walk(pt, PT_MM_CHECK);
		assert(mm);
	} while (0);
#endif
	return 0;
}

/*
 * A key already exists in the table that matches the key we want to insert.
 * Check if we can replace it.
 *
 * t - target node we are replacing
 * p - parent node
 */
static int
ptree_leaf_replace(struct ptree_table *pt __unused, const uint8_t *key __unused,
		   uint8_t masklen __unused, struct ptree_node *t __unused,
		   struct ptree_node *p __unused)
{
	/* Duplicate keys not supported just yet */
	return -EEXIST;
}

/*
 * Insert a key and mask into the table.  Scenarios:
 *
 * 1. New leaf directly under the root node
 * 2. Duplicate key and mask
 * 3. Duplicate key but different mask.  Replace node with new node that
 *    includes a list of masks.
 * 4. New leaf that isn't directly under the root.
 */
int
ptree_insert(struct ptree_table *pt, const uint8_t *key, uint8_t masklen)
{
	if (!pt || !key || masklen > pt->pt_keylen * 8)
		return -EINVAL;

	uint8_t klen = pt->pt_keylen;
	struct ptree_node *p, *t;

	/*
	 * Using the given key, follow the tree down until we hit a leaf or
	 * NULL node.  (We will *only* ever hit a NULL node at one of the root
	 * node branches.)
	 */
	t = &pt->pt_root;

	do {
		p = t;
		t = ptree_branch(p, key);
	} while (pn_is_branch(t));

	if (t == NULL) {
		/*
		 * Insert new leaf node under the root node
		 */
		assert(p == &pt->pt_root);
		return ptree_leaf_insert_at_root(pt, key, masklen);
	}

	/*
	 * t is not NULL and not a branch, so must be a leaf node.  Check if
	 * key is an exact match.
	 */
	assert(pn_is_leaf(t));

	/*
	 * Is key already in the table?
	 */
	if (memcmp(PL_KEY(t), key, klen) == 0)
		return ptree_leaf_replace(pt, key, masklen, t, p);

	/* Insert new leaf */
	return ptree_leaf_insert(pt, key, masklen, t, p);
}


/*
 * Remove leaf node from the table
 */
int
ptree_remove(struct ptree_table *pt, const uint8_t *key, uint8_t masklen)
{
	if (!pt || !key || masklen > pt->pt_keylen * 8)
		return -EINVAL;

	uint8_t klen = pt->pt_keylen;
	struct ptree_node *c, *g, *p, *t;

	/*
	 * Using the given key, follow the tree down until we hit a leaf or
	 * NULL node (We will *only* ever hit a NULL node at one of the root
	 * node branches.)
	 */
	p = t = &pt->pt_root;

	do {
		g = p;
		p = t;
		t = ptree_branch(p, key);
	} while (pn_is_branch(t));

	/* empty branch under root node */
	if (t == NULL)
		return -ENOENT;

	/*
	 * t is not NULL and not a branch, so must be a leaf node.  Check if
	 * key is an exact match.
	 */
	assert(pn_is_leaf(t));

	if (memcmp(PL_KEY(t), key, klen) != 0 || PL_MASK(t) != masklen)
		return -ENOENT;

	/*
	 * We have one of:
	 *
	 *       [g,p]                         [g]
	 *      /     \                       /
	 *   [c]       [t]     or          [p]
	 *                                /   \
	 *                             [c]     [t]
	 *
	 * g and p are branch nodes.  t is a leaf node.  Other child c may be a
	 * branch or a leaf.
	 *
	 * when g==p we are at the root
	 */

	/*
	 * NULL the branch of p that points to t.  Remember the other branch
	 * of p, c, so can later re-attach it below g.
	 */
	if (bitisset(p->pn_bit, key)) {
		p->pn_right = NULL;
		c = p->pn_left;
	} else {
		p->pn_left = NULL;
		c = p->pn_right;
	}

	if (g == p) {
		/*
		 * p is root node.  Just free leaf.  Do not delete p.
		 *
		 *       [g,p]                       [g,p]
		 *      /     \       ==>           /
		 *   [c]       [t]               [c]
		 */
		assert(p == &pt->pt_root);

		/*
		 * A node below the root has been deleted.  Simply
		 * re-initialize the min mask value for the root.  as the he
		 * minimum value of the nodes to the left and right of the
		 * root node.
		 */
		p->pn_min_mask = ptree_min_mask_initial_value(p, klen);

		/* Free leaf node */
		free(t);
		pt->pt_leaf_count--;

#ifndef	NDEBUG
		do {
			uint8_t mm;

			mm = ptree_min_mask_walk(pt, PT_MM_CHECK);
			assert(mm);
		} while (0);
#endif
		return 0;
	}

	/*
	 * Removing leaf node t will result in the parent branch node p
	 * becoming a one-way branch node, so we remove this, and point the
	 * grand-parent to the other child node of p, c.
	 *
	 *              [g]                     [g]
	 *             /                       /
	 *          [p]         ==>          [c]
	 *         /   \
	 *      [t]     [c]
	 */
	if (bitisset(g->pn_bit, key))
		g->pn_right = c;
	else
		g->pn_left = c;

	free(p);
	pt->pt_branch_count--;
	p = NULL;

	/*
	 * Re-calculate min mask lengths
	 */
	ptree_min_mask_walk(pt, PT_MM_SET);

	/* Free leaf node */
	free(t);
	pt->pt_leaf_count--;

#ifndef	NDEBUG
	do {
		uint8_t mm;

		mm = ptree_min_mask_walk(pt, PT_MM_CHECK);
		assert(mm);
	} while (0);
#endif
	return 0;
}

/*
 * Walk a tree from the given node and call the callback function for each
 * leaf.
 *
 * dir - Direction to walk the table PT_UP or PT_DOWN.
 *
 * Walk terminates if callback function returns non zero.
 */
int ptree_walk(struct ptree_table *pt, enum pt_walk_dir dir,
	       pt_walk_cb *cb, void *data)
{
	if (!pt || !cb)
		return -EINVAL;

	uint8_t klen = pt->pt_keylen;
	int rc, top = -1;
	struct ptree_node *stack[klen * 8 + 1];
	struct ptree_node *t = &pt->pt_root;
	bool up = (dir == PT_UP);

	stack[++top] = up ? t->pn_right : t->pn_left;
	stack[++top] = up ? t->pn_left  : t->pn_right;

	while (top >= 0) {
		/*
		 * t may be NULL first time round this loop if left of root is
		 * empty
		 */
		t = stack[top--];	/* pop */
		if (!t)
			continue;

		if (t->pn_type == PN_TYPE_LEAF) {
			/* Callback for leaf */
			rc = (*cb)(t, data);

			if (rc != 0)
				return rc;
		} else {
			stack[++top] = up ? t->pn_right : t->pn_left;
			stack[++top] = up ? t->pn_left  : t->pn_right;
		}
	}
	return 0;
}

/*
 * Walk IPv4 address tree, and callback for each leaf with address range info
 * for each prefix.  Addresses returned in host byte order.
 */
int ptree_ipv4_addr_range_walk(struct ptree_table *pt, pt_ipv4_range_cb *cb,
			       struct ptree_ipv4_range_ctx *ctx)
{
	if (!pt || pt->pt_keylen != 4 || !cb || !ctx)
		return -EINVAL;

	uint8_t klen = pt->pt_keylen;
	int rc, top = -1;
	struct ptree_node *stack[klen * 8 + 1];
	struct ptree_node *t = &pt->pt_root;

	stack[++top] = t->pn_right;
	stack[++top] = t->pn_left;

	while (top >= 0) {
		/*
		 * t may be NULL first time round this loop if left of root is
		 * empty
		 */
		t = stack[top--];	/* pop */
		if (!t)
			continue;

		if (t->pn_type == PN_TYPE_LEAF) {
			struct ptree_leaf *l = (struct ptree_leaf *)t;
			uint32_t addr;
			uint8_t masklen = PL_MASK(t);

			/* Copy key to avoid punned ptr error */
			memcpy(&addr, l->pl_key, 4);
			addr = ntohl(addr);

			if (masklen >= 32) {
				ctx->addr_naddrs = 1;
				ctx->addr_mask   = 0xFFFFFFFF;
				ctx->addr_first  = addr;
				ctx->addr_last   = addr;
			} else if (masklen == 31) {
				ctx->addr_naddrs = 2;
				ctx->addr_mask   = 0xFFFFFFFE;
				ctx->addr_first  = addr;
				ctx->addr_last   = addr + 1;
			} else {
				ctx->addr_naddrs =
					npf_prefix_to_useable_naddrs4(masklen);
				ctx->addr_mask  =
					npf_prefix_to_net_mask4(masklen);
				ctx->addr_first = addr + 1;
				ctx->addr_last  = ctx->addr_first +
					ctx->addr_naddrs - 1;
			}
			/* Call handler */
			rc = (*cb)(ctx);

			if (rc != 0)
				return rc;
		} else {
			stack[++top] = t->pn_right;
			stack[++top] = t->pn_left;
		}
	}
	return 0;
}

/*
 * Total the usable addresses for all prefixes in an IPv4 table.  Doesn't count
 * all zero or all ones addresses in each prefix.
 */
uint64_t
ptree_ipv4_table_range(struct ptree_table *pt)
{
	if (!pt || pt->pt_keylen != 4)
		return 0ul;

	int top = -1;
	struct ptree_node *stack[32 + 1];
	struct ptree_node *n = &pt->pt_root;
	uint64_t total = 0ul;

	stack[++top] = n->pn_right;	/* push right */
	stack[++top] = n->pn_left;	/* push left */

	while (top >= 0) {
		/*
		 * t may be NULL first time round this loop if left of root is
		 * empty
		 */
		n = stack[top--];	/* pop */
		if (!n)
			continue;

		if (n->pn_type == PN_TYPE_LEAF)
			total += npf_prefix_to_useable_naddrs4(PL_MASK(n));
		else {
			stack[++top] = n->pn_right;	/* push right */
			stack[++top] = n->pn_left;	/* push left */
		}
	}

	return total;
}

/*
 * Table accessor functions
 */
struct ptree_node *ptree_get_table_root(struct ptree_table *pt)
{
	return pt ? &pt->pt_root : NULL;
}

uint8_t ptree_get_table_keylen(struct ptree_table *pt)
{
	return pt ? pt->pt_keylen : 0;
}

uint32_t ptree_get_table_leaf_count(struct ptree_table *pt)
{
	return pt ? pt->pt_leaf_count : 0;
}

uint32_t ptree_get_table_branch_count(struct ptree_table *pt)
{
	return pt ? pt->pt_branch_count : 0;
}

/*
 * Leaf node accessor functions
 */
uint8_t *ptree_get_key(struct ptree_node *n)
{
	return pn_is_leaf(n) ? PL_KEY(n) : NULL;
}

uint8_t ptree_get_keylen(struct ptree_node *n)
{
	return pn_is_leaf(n) ? PL_KEYLEN(n) : 0;
}

uint8_t ptree_get_mask(struct ptree_node *n)
{
	return pn_is_leaf(n) ? PL_MASK(n) : 0;
}
