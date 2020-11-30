/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * bitset implemented in manner similar to FreeBSD
 * but without as many macros!
 */

#ifndef BITMASK_H
#define BITMASK_H

#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <sys/param.h>
/* For UINT64_BIT - avoid include races and redefine errors */
#include <rte_ethdev.h>

#include "urcu.h"

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE 8
#endif

#ifndef howmany
#define howmany(x, y) (((x) + ((y) - 1)) / (y))
#endif
#define BITMASK_BITS MAX(RTE_MAX_LCORE, RTE_MAX_ETHPORTS)
#ifndef UINT64_BIT
#define UINT64_BIT 64
#endif
#define BITMASK_SZ howmany(BITMASK_BITS, UINT64_BIT)
#define BITMASK_STRSZ ((BITMASK_SZ * 16) + 1)
#define BITMASK_BYTESZ (BITMASK_BITS / BITS_PER_BYTE)

struct bitmask {
	uint64_t _bits[BITMASK_SZ];
};
typedef struct bitmask bitmask_t;

static inline void bitmask_set(bitmask_t *mask, unsigned int n)
{
	CMM_STORE_SHARED(mask->_bits[n / UINT64_BIT],
		 mask->_bits[n / UINT64_BIT] | 1ull << (n % UINT64_BIT));
}

static inline void bitmask_clear(bitmask_t *mask, unsigned int n)
{
	CMM_STORE_SHARED(mask->_bits[n / UINT64_BIT],
		 mask->_bits[n / UINT64_BIT] & ~(1ull << (n % UINT64_BIT)));
}

static inline bool bitmask_isset(const bitmask_t *mask, unsigned int n)
{
	return (CMM_LOAD_SHARED(mask->_bits[n / UINT64_BIT])
					& 1ull << (n % UINT64_BIT)) != 0;
}

static inline void bitmask_zero(bitmask_t *msk)
{
	memset(msk, 0, sizeof(bitmask_t));
}

static inline bool bitmask_isempty(const bitmask_t *mask)
{
	for (unsigned int i = 0; i < BITMASK_SZ; i++) {
		if (CMM_LOAD_SHARED(mask->_bits[i]))
			return false;
	}

	return true;
}

static inline unsigned int bitmask_numset(const bitmask_t *mask)
{
	int num = 0;

	for (unsigned int pos = 0; pos < BITMASK_SZ * UINT64_BIT; pos++)
		if (bitmask_isset(mask, pos))
			num++;
	return num;
}

static inline void bitmask_and(bitmask_t *c,
			       const bitmask_t *a, const bitmask_t *b)
{
	for (unsigned int pos = 0; pos < BITMASK_SZ; pos++)
		CMM_STORE_SHARED(c->_bits[pos],
				 CMM_LOAD_SHARED(a->_bits[pos]) &
				 CMM_LOAD_SHARED(b->_bits[pos]));
}

static inline void bitmask_or(bitmask_t *c,
			      const bitmask_t *a, const bitmask_t *b)
{
	for (unsigned int pos = 0; pos < BITMASK_SZ; pos++)
		CMM_STORE_SHARED(c->_bits[pos],
				 CMM_LOAD_SHARED(a->_bits[pos]) |
				 CMM_LOAD_SHARED(b->_bits[pos]));
}

static inline void bitmask_copy(bitmask_t *a,
				const bitmask_t *b)
{
	for (unsigned int pos = 0; pos < BITMASK_SZ; pos++)
		CMM_STORE_SHARED(a->_bits[pos],
				 CMM_LOAD_SHARED(b->_bits[pos]));
}

static inline bool bitmask_equal(const bitmask_t *a,
				 const bitmask_t *b)
{
	for (unsigned int pos = 0; pos < BITMASK_SZ; pos++)
		if (CMM_LOAD_SHARED(a->_bits[pos]) !=
		    CMM_LOAD_SHARED(b->_bits[pos]))
			return false;
	return true;
}

int bitmask_parse(bitmask_t *msk, const char *str);
void bitmask_sprint(const bitmask_t *msk, char *buf, size_t sz);
int bitmask_parse_bytes(bitmask_t *mask, const uint8_t *bytes, uint8_t len);

#endif /* BITMASK_H */
