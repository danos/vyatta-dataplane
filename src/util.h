/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef	UTIL_H
#define	UTIL_H
/*
 * Common utility routines
 */

#include <czmq.h>
#include <limits.h>
#include <mm_malloc.h>
#include <rte_branch_prediction.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_per_lcore.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/capability.h>
#include <time.h>

#include "compiler.h"
#include "urcu.h"
#include "vrf.h"

struct cds_lfht;
struct rte_ether_addr;

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

/* number of bits in a type.  needs limits.h */
#define NBITS(type) (sizeof(type) * CHAR_BIT)

#define US_PER_MS 1000u
#define S_PER_DAY 86400u
#define USEC_PER_SEC 1000000u
#define NSEC_PER_USEC 1000


#ifndef _NETINET_ETHER_H
/* Convert 48 bit Ethernet ADDRess to ASCII.  */
char *ether_ntoa(const struct rte_ether_addr *__addr);
char *ether_ntoa_r(const struct rte_ether_addr *__addr, char *__buf);

/* Convert ASCII string S to 48 bit Ethernet address.  */
struct rte_ether_addr *ether_aton(const char *__asc);
struct rte_ether_addr *ether_aton_r(const char *__asc,
					struct rte_ether_addr *__addr);
#endif

/*
 * Compiler memory barrier.
 * Protects against compiler optimization of ordered operations.
 */
#define barrier() asm volatile("" : : : "memory")

struct free_huge_info {
	void *ptr;
	size_t sz;
};

/*
 * Fibonacci hash functions
 * The constants are chosen to be based on Golden Ratio
 *   1       2
 *  --- = --------
 *  phi    1 + √5
 *
 * Therefore for various word sizes choose largest value relatively prime
 * relative to word size.
 */
#define GOLDEN_RATIO_32 2654435769U
#define	GOLDEN_RATIO_64	11400714819323198485UL

static inline uint32_t hash32(uint32_t val, unsigned int bits)
{
	val *= GOLDEN_RATIO_32;
	return val >> (32 - bits);
}

static inline uint64_t hash64(uint64_t val, unsigned int bits)
{
	val *= GOLDEN_RATIO_64;
	return val >> (64 - bits);
}

/* Allocate memory aligned on cache line boundary */
static inline void *malloc_aligned(size_t sz)
{
	void *ptr;

	if (unlikely(posix_memalign(&ptr, RTE_CACHE_LINE_SIZE, sz)))
		return NULL;
	return ptr;
}

/* Allocate and clear memory aligned on cache boundary */
static inline void *zmalloc_aligned(size_t sz)
{
	void *ptr = malloc_aligned(sz);
	if (ptr)
		memset(ptr, 0, sz);
	return ptr;
}

/* Set bit position bit_num in field32 */
static inline void set_bit_32(uint32_t *field32, uint8_t bit_num)
{
	if (bit_num >= 32)
		return;
	*field32 |= (1U << bit_num);
}

/* Like rte_lcore_id()
 * but for all non-dataplane threads returns 0 instead of LCORE_ID_ANY
 */
RTE_DECLARE_PER_LCORE(unsigned int, _dp_lcore_id);
static ALWAYS_INLINE
unsigned int dp_lcore_id(void)
{
	return RTE_PER_LCORE(_dp_lcore_id);
}

/* Iterate each lcore id that dp_lcore_id could return */
#define FOREACH_DP_LCORE(_i) \
	for ((_i) = 0; (_i) <= get_lcore_max(); (_i)++)

/* Current time since boot */
static inline time_t get_dp_uptime(void)
{
	return (time_t) (rte_get_timer_cycles() / rte_get_timer_hz());
}

static inline uint64_t timespec_diff_us(struct timespec *start,
					struct timespec *end)
{
	struct timespec temp;

	if ((end->tv_nsec - start->tv_nsec) < 0) {
		temp.tv_sec = end->tv_sec - start->tv_sec - 1;
		temp.tv_nsec = (USEC_PER_SEC * NSEC_PER_USEC) +
			end->tv_nsec - start->tv_nsec;
	} else {
		temp.tv_sec = end->tv_sec - start->tv_sec;
		temp.tv_nsec = end->tv_nsec - start->tv_nsec;
	}
	return (temp.tv_sec * USEC_PER_SEC) + (temp.tv_nsec / NSEC_PER_USEC);
}

void random_init(void);
const char *nlmsg_type(unsigned int type);
const char *ndm_state(uint16_t);
int get_bool(const char *str, bool *ptr);
int get_unsigned(const char *str, unsigned int *ptr);
int get_signed(const char *str, int *ptr);
int get_signed_char(const char *str, signed char *ptr);
int get_unsigned_short(const char *str, unsigned short *ptr);
int get_unsigned_char(const char *str, unsigned char *ptr);
float get_float(const char *str, float *ptr);
int net_ratelimit(void);
bool secondary_cpu(unsigned int id);
int str_unsplit(char *, size_t, int, char **);
size_t snprintfcat(char *buf, size_t size, const char *fmt, ...)
	__attribute__ ((__format__(__printf__, 3, 4)));

const char *hypervisor_id(void);
unsigned int get_lcore_max(void);

void *malloc_huge_aligned(size_t sz);
void free_huge(void *ptr, size_t sz);
int defer_rcu_huge(void *ptr, size_t sz);

void check_broken_firmware(void);

void dp_ht_destroy_deferred(struct cds_lfht *table);

bool get_switch_dev_info(const char *drv_name,
						 const char *drv_dev_name,
						 int *switch_id,
						 char *dev_name);

int change_capability(cap_value_t capability, bool on);
void renice(int value);

#endif  /* UTIL_H */
