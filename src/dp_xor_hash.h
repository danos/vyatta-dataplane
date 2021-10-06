/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef DP_XOR_HASH_H
#define DP_XOR_HASH_H

#include <stdint.h>

/*
 * The following are to be called instead of the rte_jhash*() functions,
 * if a simple quick hash is needed. The rte_jhash*() functions use a
 * lot of instructions, which was seen by profiling using "perf record".
 * Therefore, when a hash is just used to index a hash table, a simple
 * XOR may be sufficient and is a lot quicker.
 */

static inline uint32_t
dp_xor_1word(uint32_t a, uint32_t initval)
{
	return a ^ initval;
}

static inline uint32_t
dp_xor_2words(uint32_t a, uint32_t b, uint32_t initval)
{
	return a ^ b ^ initval;
}

static inline uint32_t
dp_xor_3words(uint32_t a, uint32_t b, uint32_t c, uint32_t initval)
{
	return a ^ b ^ c ^ initval;
}

static inline uint32_t
dp_xor_4words(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t initval)
{
	return a ^ b ^ c ^ d ^ initval;
}

static inline uint32_t
dp_xor_array32(const uint32_t *array, uint32_t length, uint32_t initval)
{
	uint32_t i;

	for (i = 0; i < length; i++)
		initval ^= array[i];
	return initval;
}

#endif /* DP_XOR_HASH_H */
