/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "npf_cidr_util.h"

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/*
 * CIDR Block Calculator
 *
 * A utility to generate canonized lists of CIDR notation netblocks from
 * expressions like "10.0.0.0-10.22.255.255" and "10.0.0.0/24"
 *
 * Source: Derived from public domain (no license) code available at
 * http://www.spamshield.org/
 *
 * The original code supported IPv4 only, and used unsigned longs to store
 * addresses in host byte order.
 *
 * It has been changed to use uint8_t pointers to addresses so that IPv6 can
 * also be supported.
 *
 * However the algorithms have not been changed, which means that a number of
 * simple ulong operations (compare, add, shift, mask, set bit, test bit etc.)
 * have been replaced with functions.
 *
 * It works by creating an populating a tree, with a binary radix node for
 * every bit.  Each node only stores two pointers to child nodes.  It
 * collapses fully populated sub-trees as it goes, and marks this by pointing
 * to the 'ALL' static node.
 *
 * Once fully populated, the optimised set of prefixes is obtained by walking
 * the tree.  It starts with an all-zero's address, and sets or clears bits in
 * the address as it descends and ascends the tree.  Anytime it reaches a leaf
 * node, it calls the callback function with the address-so-far.
 */

/*
 * For IPv4, 0 is lsbit and 31 is msbit
 */
#define MAX_BIT_IPV4 31
#define MAX_BIT_IPv6 127

#define MAX_BIT(_alen) (_alen == 4 ? MAX_BIT_IPV4 : MAX_BIT_IPv6)


struct cidr_node {
	struct cidr_node *sub[2];
};

/*
 * The NONE and ALL node 'markers'.
 */
static struct cidr_node none;
#define NONE (&none)

static struct cidr_node all;
#define ALL (&all)


/*
 * Set bit in an address.  Address is in host byte order.  Least significant
 * bit is bit 0.
 */
static inline void set_bit(uint8_t *a, int bit)
{
	a[bit/8] |= (1 << bit%8);
}

/*
 * Clear bit in an address.  Address is in host byte order.  Least significant
 * bit is bit 0.
 */
static inline void clear_bit(uint8_t *a, int bit)
{
	a[bit/8] &= ~(1 << bit%8);
}

/*
 * Is bit set in an address?  Address is in host byte order.  Least
 * significant bit is bit 0.
 */
static inline bool test_bit(uint8_t *a, int bit)
{
	return (a[bit/8] >> bit%8) & 1;
}

/*
 * Clear host bits
 */
static void clear_host_bits(uint8_t *a, int alen, int mask)
{
	int i, b;

	/* Start at least significant byte */
	for (i = 0, b = alen*8 - mask; i < alen && b > 7; i++, b -= 8)
		a[i] = 0;

	/* partial byte */
	if (b)
		a[i] = a[i] & (0xFF << b);
}

/*
 * Compare two addresses.  Return -1 if a1 < a2, +1 id a1 > a2, 0 id a1 == a2.
 */
static int addr_cmp(uint8_t *a1, uint8_t *a2, int alen)
{
	int i;

	/* Start at most significant byte */
	for (i = alen - 1; i >= 0; i--) {
		if (a1[i] < a2[i])
			return -1;
		else if (a1[i] > a2[i])
			return 1;
	}
	return 0;
}

/*
 * Right shift address 1 bit
 */
static void addr_sr(uint8_t *addr, int alen)
{
	int i;
	uint8_t lsb = 0, msb = 0;

	/*
	 * Start at most significant byte, carrying the 'shifted-out' bit each
	 * iteration.
	 */
	for (i = alen - 1; i >= 0; i--) {
		/* Save ls bit that gets shifted out */
		lsb = addr[i] & 1;

		addr[i] = (addr[i] >> 1) | msb;

		/* ls bit in this byte becomes ms bit in next byte */
		msb = lsb << 7;
	}
}

/*
 * Add a2 to a1 and store the result in r.  Returns 0 if successful, else -1.
 * r may point to the same memory as either a1 or a2.
 */
static int addr_add(uint8_t *r, uint8_t *a1, uint8_t *a2, int alen)
{
	int i;
	uint x, co = 0;

	/* Start at the least significant byte */
	for (i = 0; i < alen; i++) {
		x = a1[i] + a2[i] + co;
		r[i] = x & 0xFF;

		/* Carry-over for next byte */
		co = x >> 8;
	}

	/* fail if there is any carry over */
	return co == 0 ? 0 : -1;
}

/*
 * add 1 to address. Returns 0 if successful, else -1.
 */
static int addr_incr(uint8_t *addr, int alen)
{
	int i;
	uint x, co;

	for (i = 0, co = 1; i < alen && co > 0; i++) {
		x = addr[i] + co;
		addr[i] = x & 0xFF;

		/* We are done when there is no carry over */
		co = x >> 8;
		if (co == 0)
			return 0;
	}

	/* fail if there is any carry over */
	return -1;
}

/*
 * Assuming 'addr' is a prefix with the host bits set to zero, then calculate
 * the host mask for that prefix.
 *
 * e.g. 0x0A000080 gives 0x0000007F
 *      0x0A000008 gives 0x00000007
 *      0x0A001000 gives 0x00000FFF
 */
static void host_mask(uint8_t *addr, uint8_t *mask, int alen)
{
	int i;

	/* Start at the least significant byte */
	for (i = 0; i < alen; i++) {
		if (addr[i])
			break;
		/* set host bits */
		mask[i] = 0xFF;
	}

	if (i < alen) {
		/* partial byte */
		mask[i] = (addr[i] - 1) & ~addr[i];

		/* clear non-host bits */
		for (i++; i < alen; i++)
			mask[i] = 0;
	}
}

/*
 * Count the number of leading zeros in an address
 */
static int addr_clz(uint8_t *addr, int alen)
{
	assert(alen >= 4 && (alen & 0x3) == 0);

	int w, nwords = alen >> 2;
	int clz = 0;

	for (w = nwords-1; w >= 0; w--)	{
		uint32_t word;

		word = *((uint32_t *)addr + w);
		if (word == 0) {
			clz += 32;
			continue;
		}

		/* Count leading zeros builtin */
		return clz + __builtin_clz(word);
	}

	/* No bits are set in addr */
	return clz;
}

/*
 * Free a node and all nodes under it.  Useful when we're setting ALL at a
 * point relatively far up in the tree (which happens if a range or block
 * subsumes some already-entered individual addresses).
 */
static void free_tree(struct cidr_node *n)
{
	if ((n == NONE) || (n == ALL))
		return;

	free_tree(n->sub[0]);
	free_tree(n->sub[1]);
	free(n);
}

/*
 * Add an address to a node.  Conceptually, you pass a node to this routine.
 * But since it may want to replace the node with ALL, it needs to actually be
 * passed an additional level of pointer, struct cidr_node ** instead of
 * struct cidr_node *.  This has the convenient property that this routine can
 * also handle replacing NONE nodes with real nodes.  a is the address being
 * added.  bit says how far down in the tree this node is, or more accurately
 * how far up; 31 (or 127) corresponds to the root, 0 to the last level of
 * internal nodes, and -1 to leaves.  end is a value which describes how large
 * a block is being added; it is -1 to add a single leaf (a /32 or /128), 0 to
 * add a pair of addresses (a /31 or /127), etc.
 *
 * Algorithm: Recursive.  If the node is already ALL, everything we want to
 * add is already present, so do nothing.  Otherwise, if we've reached the
 * level at which we want to operate (bit <= end), free the subtree if it's
 * not NONE (it can't be ALL; we already checked) and replace it with ALL, and
 * we're done.  Otherwise, we have to walk down either the 0 link or the 1
 * link.  If this node is presently NONE, we have to create a real node; then
 * we recurse down whichever branch of the tree corresponds to the appropriate
 * bit of a.  After adding, we check, and if both our subtrees are ALL, we
 * collapse this node into an ALL.  (If further collapsing is possible at the
 * next level up, our caller will take care of it.)
 */
static void
add_to_node(struct cidr_node **np, uint8_t *k, int alen, int bit, int end)
{
	struct cidr_node *n;

	n = *np;
	if (n == ALL)
		return;

	if (bit <= end)	{
		if (n != NONE)
			free_tree(n);
		*np = ALL;
		return;
	}

	if (n == NONE) {
		n = malloc(sizeof(struct cidr_node));
		if (!n)
			return;
		n->sub[0] = NONE;
		n->sub[1] = NONE;
		*np = n;
	}

	add_to_node(&n->sub[test_bit(k, bit)], k, alen, bit-1, end);

	if ((n->sub[0] == ALL) && (n->sub[1] == ALL)) {
		free(n);
		*np = ALL;
	}
}

/*
 * Walk tree.  This calls the callback function for each address node. If the
 * node is NONE, there's nothing under it, so don't do anything.  If it's ALL,
 * we've found a CIDR block; call callback function and return.  Otherwise, we
 * recurse, first down the 0 branch, then the 1 branch.  v is the
 * address-so-far, maintained as part of the recursive calls.
 *
 * The abort is a can't-happen; it indicates that we have a node that's not
 * NONE or ALL at the bottom level of the tree, which is supposed to hold only
 * leaves.
 */
static int walk_tree(struct cidr_node *n, uint8_t *a, int alen, int bit,
		     cidr_tree_walk_cb *cb, void *ctx)
{
	if (n == NONE)
		return 0;

	if (n == ALL) {
		if ((*cb)(a, alen, MAX_BIT(alen) - bit, ctx) < 0)
			return -1; /* abort */
		return 0;
	}
	if (bit < 0)
		return -1; /* abort */

	/* Descend left */
	if (walk_tree(n->sub[0], a, alen, bit-1, cb, ctx) < 0)
		return -1;

	/* Descend right */
	set_bit(a, bit);
	if (walk_tree(n->sub[1], a, alen, bit-1, cb, ctx) < 0)
		return -1;

	/* Restore 'a' to its original value */
	clear_bit(a, bit);

	return 0;
}

void
npf_cidr_tree_init(struct cidr_tree *tree, int alen)
{
	if (!tree)
		return;

	tree->root = NONE;
	tree->alen = alen;
}

void
npf_cidr_tree_free(struct cidr_tree *tree)
{
	if (!tree)
		return;

	free_tree(tree->root);
	tree->root = NULL;
}

/*
 * Add a range of addresses.  This is used for the "10.20.30.40 - 10.20.32.77"
 * style of input.  All we do is start at the bottom of the range and loop,
 * each time computing the largest block that doesn't go below the bottom,
 * shrinking it as far as necessary to ensure it doesn't go above the top,
 * adding it, and moving the `bottom' value to just above the block.  Lather,
 * rinse, repeat...until the whole range is covered.
 */
void
npf_cidr_save_range(struct cidr_tree *tree, uint8_t *a1, uint8_t *a2)
{
	if (!tree || !tree->root)
		return;

	int bit, alen = tree->alen;
	uint8_t m[alen], tmp[alen];


	/* a1 must be less than a2 */
	if (addr_cmp(a1, a2, alen) >= 0)
		return;

	/* while a1 <= a2 */
	while (addr_cmp(a1, a2, alen) <= 0) {
		/*
		 * m = (a1 - 1) & ~a1
		 *
		 * If a1 where a prefix, then m is the host mask, e.g.
		 * An a1 of 10.0.0.8 gives an 'm' of 0x00000007
		 */
		host_mask(a1, m, alen);

		/*
		 * Right-shift 'm' until a1+m is no longer greater than a2
		 */
		addr_add(tmp, a1, m, alen);

		while (addr_cmp(tmp, a2, alen) > 0) {
			/* m >>= 1 */
			addr_sr(m, alen);

			/* tmp = a1 + m */
			addr_add(tmp, a1, m, alen);
		}

		/*
		 * mask to bit. Count how many right-shifts it takes for
		 * 'm' to become 0.
		 *
		 *  e.g. t of 0x07 gives 2, 0x03 -> 1, 0x01 -> 0 etc.  If t is
		 *  0x00 then bit remains at -1, indicating a host address.
		 *
		 * The original code copied 'm' and right-shifted it in a loop
		 * until it became 0.  An easier way to achieve the same thing
		 * with a byte array is to simple count the leading zeros, and
		 * subtract that from 31 or 127.
		 */
		bit = MAX_BIT(alen) - addr_clz(m, alen);
		add_to_node(&tree->root, a1, alen, MAX_BIT(alen), bit);

		/* a1 += m+1 */
		addr_incr(m, alen);
		addr_add(a1, a1, m, alen);
	}
}

/*
 * Add a CIDR-style block.  This matches our storage method so well it's just
 * a single call to add_to_node.
 */
void
npf_cidr_save_prefix(struct cidr_tree *tree, uint8_t *a, int mask)
{
	if (!tree)
		return;

	/* Ensure host bits are clear */
	clear_host_bits(a, tree->alen, mask);

	add_to_node(&tree->root, a, tree->alen, MAX_BIT(tree->alen),
		    MAX_BIT(tree->alen)-mask);
}

/*
 * Call the callback function for each node in the tree
 */
void
npf_cidr_tree_walk(struct cidr_tree *tree, int alen, cidr_tree_walk_cb *cb,
		   void *ctx)
{
	uint8_t addr[alen];

	/*
	 * Start with an address of all-zeros, and set/clear bits accordingly
	 * as we descend the tree.
	 */
	memset(addr, 0, alen);

	if (tree->root)
		walk_tree(tree->root, addr, alen, MAX_BIT(alen), cb, ctx);
}
