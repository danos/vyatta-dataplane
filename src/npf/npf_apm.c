/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <values.h>

#include "compiler.h"
#include "json_writer.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_apm.h"
#include "npf/npf_nat.h"
#include "npf_tblset.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

/*
 * NPF Address Port Map (APM)
 *
 * For DNAT, we use a round-robin method of pseudo allocations for
 * the port within the ranges defined. If the port is
 * within the defined range, the original is used.
 *
 * For SNAT, we consider the entire translation space (2^32 addrs * 2^16
 * ports) by using an RCU hash table for a per-addr port translation
 * bitmap. This hash table is referenced by all snat users.
 *
 * The portmap is a sparse bitmap implementation - The entire range
 * of the bitmap (2^16 bits) is divided into 'sections', which are
 * dynamically allocated and freed as usage warrants. When usage of a
 * portmap section goes to zero, the section is freed. Note that bit
 * zero of a portmap cannot be allocated, so the bits of the portmap are
 * a one-to-one correspondence with a port.
 *
 * A spin lock is involved in protecting sections, since multiple users
 * could be attempting to update the same portmap concurrently.
 *
 * Since heavy usage, with a large number of translations could result in
 * huge memory allocation, a simple loose maximum memory limit is used.
 * Once this limit is reached, no further translations can be provided
 * until the memory usage goes below the limit.
 *
 * Similar to DNAT, SNAT requests will attempt to allocate the existing
 * port providing the input port falls within the port translation
 * range.
 *
 * Otherwise, (assuming no mask) we choose both a random translation
 * address and random port as the starting point for snat translations.
 * From that point we increment both until the request can be satisfied.
 *
 * Port bitmaps are reclaimed from the hash table using a two-phase
 * deletion process in a hash table periodic garbage collection routine.
 * When the last bit from the port bitmap is released, the routine will set
 * a REMOVABLE flag in the first pass.  If the flag is still set in the
 * next pass, the callback will set a DEAD flag, indicating that this
 * porttmap can no longer be referenced.  A third pass will delete the
 * portmap.  Note that a lookup for a port bitmap cannot return a DEAD entry.
 *
 *
 * There are two races of note wrt the garbage collection routine and
 * users referencing portmaps.  The first is on initial creation, the
 * portmap contains zero entries and its possible for the GC routine to
 * find this and mark it as REMOVABLE.  The second is a user obtaining
 * access to a REMOVABLE portmap and the GC routine about to mark it as
 * DEAD.  Both of these races are handled by having the user clear the
 * flags during port allocation.  Because of the two-phase deletion approach,
 * requiring 3 passes,these races are handled correctly.
 *
 * The allocation algorithm enforces the following SNAT behaviors:
 *
 * - The original port is allocated if possible
 * - A limit of 64 consecutive ports is enforced.
 * - Port 0 (zero) cannot be allocated.
 * - Ports are allocated randomly within the range.
 * - address/port allocation combinations cannot be overloaded.
 * - 'sharing' of port bitmaps happens automatically.
 * - Requests for consecutive ports cannot span sections
 *
 */

/* Hash table buckets */
#define PM_HT_INIT		(1 << 9)
#define PM_HT_MIN		(1 << 10)
#define PM_HT_MAX		(1 << 20)

#define APM_INTERVAL	5

static struct rte_timer		apm_timer;
static struct cds_lfht		*apm_ht;

/*
 *  Ultimately we are limited by the number of sessions, but max
 *  sessions are dynamic.  So set a max entries based on memory usage
 *  alone.  This is an approximate limit.
 *
 *  Overall, this is roughly a 512MiB memory limit.
 */
#define PM_MEM_LIMIT	(1 << 29)
rte_atomic64_t		pm_mem_used;

/* Port max */
#define PORT_MAX USHRT_MAX

/* For strerror_r */
#define ERR_MSG_LEN	64

/* macros for the bitmap, these allow us to span words in a section */
#define BIT_WORD(n)     ((n)/LONGBITS)
#define BIT_MASK(a, b)  (((unsigned long)-1 >> (LONGBITS-(b))) << \
				(((a)) % LONGBITS))

/* Various macros related to sections */
#define PM_SECTION_WORDS	(PM_SECTION_BITS / LONGBITS)
#define PM_SECTION_CNT          ((PORT_MAX+1) / PM_SECTION_BITS)

/* portmap entry removal bits. */
#define PM_FLAG_REMOVABLE	01
#define PM_FLAG_DEAD		02

/* using a table? */
#define APM_USES_TABLE(a)	((a)->apm_table_id != NPF_TBLID_NONE)

struct port_section {
	unsigned long	ps_bm[PM_SECTION_WORDS];/* section bitmap */
	uint16_t	ps_used;		/* bits allocated */
	uint16_t	pad[3];			/* Pad to cache line */
};

struct port_map {
	struct port_section	*pm_sections[PM_SECTION_CNT];
	rte_spinlock_t		pm_lock;	/* for sync'ing updates */
	uint16_t		pm_used;	/* # allocated ports */
	uint8_t			pm_flags;	/* for removal */
	uint32_t		pm_addr;	/* addr of this port map */
	vrfid_t			pm_vrfid;
	struct cds_lfht_node	pm_node;
	struct rcu_head		pm_rcu_head;
};

/* For matching a portmap */
struct match {
	vrfid_t		m_vrfid;
	uint32_t	m_addr;
};

struct npf_apm_range {
	uint32_t	ar_addr_start;	/* start translation address */
	uint32_t	ar_addr_stop;	/* stop translation address */
	uint32_t	ar_addr_next;	/* next translation address*/
	uint32_t	ar_addr_range;	/* Range of addrs */
	uint32_t	ar_addr_mask;	/* Address mask */
	in_port_t	ar_port_start;	/* port translation start, host order */
	in_port_t	ar_port_stop;	/* Port translation end, host order */
	in_port_t	ar_port_next;	/* next port translation, host order */
	uint16_t	ar_port_range;	/* Range of ports */
};

struct npf_apm {
	struct npf_apm_range	apm_ar;
	uint32_t		apm_table_id;	/* Addr table id */
	uint8_t			apm_type;	/* NPF_NATIN/NPF_NATOUT */
	rte_atomic64_t		apm_dnat_used;	/* Dnat translation count */
	rte_spinlock_t		apm_dnat_lock;	/* Lock expressly for dnat */
};

/* Struct for walking a table address range */
struct apm_table_params {
	struct npf_apm		*ap_apm;
	int			ap_nr_ports;
	int			ap_rc;
	vrfid_t			ap_vrfid;
	uint32_t		ap_addr;
	uint32_t		ap_map_flags;
	in_port_t		ap_port;
};

/* Set bits in a section, span words if needed */
static void set_bits(unsigned long bit, int nr_bits, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(bit, nr_bits);
	unsigned long *a = ((unsigned long *) addr) + BIT_WORD(bit);
	int span = npf_apm_span_word(bit, nr_bits);

	*a |= mask;

	if (unlikely(span)) {
		a++;
		mask = BIT_MASK((bit + (nr_bits - span)), (span));
		*a |= mask;
	}
}

/* Clear bits in a section, span words if needed */
static void clear_bits(unsigned long bit, int nr_bits, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(bit, nr_bits);
	unsigned long *a = ((unsigned long *) addr) + BIT_WORD(bit);
	int span = npf_apm_span_word(bit, nr_bits);

	*a &= ~mask;

	if (unlikely(span)) {
		a++;
		mask = BIT_MASK((bit + (nr_bits - span)), (span));
		*a &= ~mask;
	}
}

/* Test bits in a section, span words if needed */
static int test_bits(unsigned long bit, int nr_bits, unsigned long *addr)
{
	unsigned long mask = BIT_MASK(bit, nr_bits);
	unsigned long mask2;
	unsigned long *a = ((unsigned long *) addr) + BIT_WORD(bit);
	int span = npf_apm_span_word(bit, nr_bits);

	if (unlikely(span)) {
		mask2 = BIT_MASK((bit + (nr_bits - span)), (span));
		return (*a & mask) != 0 || (*(++a) & mask2) != 0;
	}

	return (*a & mask) != 0;
}

static void port_stats_inc(int nr_ports, struct port_map *pm,
				struct port_section *ps)
{
	pm->pm_used += nr_ports;
	ps->ps_used += nr_ports;
}

static void port_stats_dec(struct port_map *pm, struct port_section *ps)
{
	pm->pm_used--;
	ps->ps_used--;
}

/* Free the entry */
static void map_rcu_free(struct rcu_head *head)
{
	struct port_map *pm = caa_container_of(head, struct port_map,
								pm_rcu_head);
	int i;

	/* Sanity, can only happen with a bug */
	for (i = 0; i < PM_SECTION_CNT; i++) {
		if (pm->pm_sections[i] && pm->pm_sections[i]->ps_used)
			rte_panic("NPF port map: section: %d used: %d\n",
						i, pm->pm_sections[i]->ps_used);
	}
	rte_free(pm);
}

/* Hash table GC - eliminate stale port maps.  */
static void map_gc(struct rte_timer *timer __rte_unused, void *arg __rte_unused)
{
	struct cds_lfht_iter iter;
	struct port_map *pm;

	/*
	 * two-phase approach to deleting dead portmaps.
	 *
	 * The assumption here is that all contending threads on the pm
	 * lock will obtain the lock and complete their ops prior
	 * to the next iteration of this thread.
	 */
	cds_lfht_for_each_entry(apm_ht, &iter, pm, pm_node) {

		rte_spinlock_lock(&pm->pm_lock);

		if (pm->pm_flags & PM_FLAG_DEAD) {
			if (!cds_lfht_del(apm_ht, &pm->pm_node)) {
				call_rcu(&pm->pm_rcu_head, map_rcu_free);
				rte_atomic64_sub(&pm_mem_used,
						sizeof(struct port_map));
			}
		} else if (pm->pm_flags & PM_FLAG_REMOVABLE)
			pm->pm_flags |= PM_FLAG_DEAD;
		else if (!pm->pm_used)
			pm->pm_flags = PM_FLAG_REMOVABLE;

		rte_spinlock_unlock(&pm->pm_lock);
	}

	/* Reset timer if dataplane is up */
	if (running)
		rte_timer_reset(&apm_timer, APM_INTERVAL * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), map_gc, NULL);
}

static void apm_delete_all(void)
{
	struct cds_lfht_iter iter;
	struct port_map *pm;

	cds_lfht_for_each_entry(apm_ht, &iter, pm, pm_node) {
		if (!cds_lfht_del(apm_ht, &pm->pm_node))
			call_rcu(&pm->pm_rcu_head, map_rcu_free);
	}
}

/* Hash table match. */
static int map_match(struct cds_lfht_node *node, const void *key)
{
	struct port_map *pm =
			caa_container_of(node, struct port_map, pm_node);
	const struct match *m = key;

	/*
	 * Never return a dead entry.  This can race with the GC
	 * routine (setting DEAD), however we are allocating a port and all
	 * flags will be cleared.
	 */
	if (pm->pm_flags & PM_FLAG_DEAD)
		return 0;

	/* Wildcard the vrfid for stats */
	if (pm->pm_vrfid != m->m_vrfid)
		return 0;

	if (pm->pm_addr != m->m_addr)
		return 0;
	return 1;
}

static unsigned long apm_hash(uint32_t addr, vrfid_t vrfid)
{
	return rte_jhash_32b(&addr, 1, vrfid);
}

static struct port_map *map_get(uint32_t addr, vrfid_t vrfid, bool create)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct port_map *pm;
	uint64_t sz = sizeof(struct port_map);
	struct match m = { .m_addr = addr, .m_vrfid = vrfid };
	unsigned long hash;

	/* Lookup first, then add if not found. */
	hash = apm_hash(addr, vrfid);
	cds_lfht_lookup(apm_ht, hash, map_match, &m, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct port_map, pm_node);

	/* Create it? */
	if (!create)
		return NULL;

	/* Alloc/init a new port map */
	pm = rte_zmalloc("apm", sz, RTE_CACHE_LINE_SIZE);
	if (!pm)
		return NULL;

	/* Deal with memory limit, yes, this is racy */
	if (rte_atomic64_add_return(&pm_mem_used, sz) > PM_MEM_LIMIT) {
		rte_atomic64_sub(&pm_mem_used, sz);
		rte_free(pm);
		return NULL;
	}

	rte_spinlock_init(&pm->pm_lock);
	pm->pm_addr = addr;
	pm->pm_vrfid = vrfid;
	cds_lfht_node_init(&pm->pm_node);

	node = cds_lfht_add_unique(apm_ht, hash, map_match, &m,
								&pm->pm_node);
	if (node != &pm->pm_node) {
		/* Lost the race, return existing */
		rte_atomic64_sub(&pm_mem_used, sz);
		rte_free(pm);
		pm = caa_container_of(node, struct port_map, pm_node);
	}

	return pm;
}

/* Get a portmap section, allocate if needed */
static struct port_section *map_get_section(struct port_map *pm,
						int n, bool create)
{
	size_t sz = sizeof(struct port_section);

	if (pm->pm_sections[n] || !create)
		return pm->pm_sections[n];

	/* memory limit.  Yes, this is racy */
	if (rte_atomic64_add_return(&pm_mem_used, sz) > PM_MEM_LIMIT) {
		rte_atomic64_sub(&pm_mem_used, sz);
		return NULL;
	}

	pm->pm_sections[n] = rte_zmalloc("apm", sz, RTE_CACHE_LINE_SIZE);

	return pm->pm_sections[n];
}

/* Put a port section, free if unused.  assumes lock held */
static void map_put_section(struct port_map *pm,
				struct port_section *ps, int n)
{
	if (!ps->ps_used) {
		pm->pm_sections[n] = NULL;
		rte_atomic64_sub(&pm_mem_used, sizeof(struct port_section));
		rte_free(ps);
	}
}

static bool ports_in_range(const struct npf_apm_range *ar, int nr_ports,
		uint16_t port)
{
	return (port >= ar->ar_port_start &&
			(port + nr_ports - 1) <= ar->ar_port_stop);
}

static bool addr_in_range(const struct npf_apm_range *ar, uint32_t addr)
{
	return (addr >= ar->ar_addr_start && addr <= ar->ar_addr_stop);
}

static inline int port_alloc_ports(struct port_map *pm, uint32_t map_flags,
		int nr_bits, uint16_t *port)
{
	unsigned long bit = PM_SECTION_BIT(*port);
	struct port_section *ps;
	int section;

	/*
	 * Don't bother if we need to start on an even port.
	 * We will loop for the next port.
	 */
	if ((map_flags & NPF_NAT_MAP_EVEN_PORT) && !(bit & 1))
		return -EADDRINUSE;

	/* cannot span a section */
	if (unlikely(npf_apm_span_section(*port, nr_bits)))
		return -ENOSPC;

	section = PM_SECTION_OF_PORT(*port);
	ps = map_get_section(pm, section, true);
	if (!ps)
		return -ENOMEM;

	if (ps->ps_used >= PM_SECTION_BITS)
		return -ENOSPC;

	if (test_bits(bit, nr_bits, ps->ps_bm))
		return -EADDRINUSE;

	set_bits(bit, nr_bits, ps->ps_bm);
	port_stats_inc(nr_bits, pm, ps);
	*port = PM_BIT_TO_PORT(bit) + (section * PM_SECTION_BITS);

	return 0;
}

/* Get a set of ports if desired */
static int map_allocate_ports(struct npf_apm_range *ar, uint32_t map_flags,
		struct port_map *pm, int nr_ports, uint16_t *port)
{
	int rc = 0;
	uint16_t i;

	/*
	 * Do we want more ports than the configured range?
	 */
	if (nr_ports > ar->ar_port_range)
		return -ERANGE;

	/*
	 * If the port(s) are in the range, use it, otherwise
	 * choose a random start port in the range, but ensure
	 * we do not exceed the range.
	 */
	if (!ports_in_range(ar, nr_ports, *port))
		*port = ar->ar_port_start +
			(random() % (ar->ar_port_range - (nr_ports - 1)));

	rte_spinlock_lock(&pm->pm_lock);

	/* Room at the Inn? */
	if ((pm->pm_used + nr_ports) > ar->ar_port_range) {
		rte_spinlock_unlock(&pm->pm_lock);
		return -ENOSPC;
	}

	/*
	 * Loop through the range.
	 *
	 * The pathological case is consecutive ports in a highly
	 * fragmented map. Otherwise we converge fairly quickly for
	 * single port allocations.
	 *
	 * Note that we do not span sections for a consecutive port
	 * request.
	 */
	for (i = 0; i < ar->ar_port_range; i++) {
		rc = port_alloc_ports(pm, map_flags, nr_ports, port);

		switch (rc) {
		case 0:
		case -ENOMEM:
			goto done;
		case -ENOSPC: /* Section is full, skip to next one */
			*port = PM_SECTION_SPAN_NEXT(*port);
			break;
		case -EADDRINUSE: /* Try next port */
			(*port)++;
			break;
		}

		/* Wrap? */
		if (!ports_in_range(ar, nr_ports, *port))
			*port = ar->ar_port_start;
	}

	/*
	 * Handle special case.  If the port map is highly fragmented,
	 * its possible for a multi-port request to fail with a -EADDRINUSE
	 * IOW, the bits are available, but they are not sequential
	 *
	 * So return the correct error, we are out of space.
	 */
	if ((rc == -EADDRINUSE) && (nr_ports > 1))
		rc = -ENOSPC;

done:
	/* Reset the flags, if we allocated */
	if (!rc && pm->pm_flags)
		pm->pm_flags = 0;

	rte_spinlock_unlock(&pm->pm_lock);

	return rc;
}

/* Map input addr - returns starting trans addr */
static uint32_t map_translate_addr(struct npf_apm_range *ar, uint32_t inaddr)
{
	uint32_t mask;

	if (addr_in_range(ar, inaddr))
		return inaddr;

	if (ar->ar_addr_mask) {
		mask = ((1 << (INTBITS - ar->ar_addr_mask)) - 1);
		return (ar->ar_addr_start & (~mask)) | (inaddr & mask);
	}

	return ar->ar_addr_start + (inaddr % ar->ar_addr_range);
}

/* Get the snat translation address/ports */
static int map_snat(struct npf_apm_range *ar, int nr_ports,
		vrfid_t vrfid, uint32_t *addr, in_port_t *port,
		uint32_t map_flags)
{
	int rc;
	struct port_map *pm;
	uint32_t i;

	*addr = map_translate_addr(ar, *addr);

	if (!(map_flags & NPF_NAT_MAP_PORT))
		return 0;

	if (!*port || !nr_ports)
		return 0;

	if (nr_ports > (int) LONGBITS)
		return -EINVAL;

	/* Bad configuration? */
	if (nr_ports > ar->ar_port_range)
		return -ERANGE;

	rc = 0; /* Hush up gcc, range is always at least 1 */
	for (i = 0; i < ar->ar_addr_range; i++) {
		pm = map_get(*addr, vrfid, true);
		if (!pm)
			return -ENOMEM;

		rc = map_allocate_ports(ar, map_flags, pm, nr_ports, port);
		if (!rc || rc == -ENOMEM)
			break;

		/* try a new addr, wrap */
		(*addr)++;
		if (*addr > ar->ar_addr_stop)
			*addr = ar->ar_addr_start;
	}

	return rc;
}

/* Get dnat translation addr/port */
static int map_dnat(npf_apm_t *apm, struct npf_apm_range *ar,
		int nr_ports, uint32_t *addr, in_port_t *port)
{
	int rc = -ERANGE;

	rte_spinlock_lock(&apm->apm_dnat_lock);

	*addr = map_translate_addr(ar, *addr);

	if (!nr_ports) {
		rc = 0;
		goto done;
	}

	/* Are requested port(s) in range? */
	if (ports_in_range(ar, nr_ports, *port)) {
		rc = 0;
		goto done;
	}

	if (nr_ports > ar->ar_port_range) {
		rc = -ERANGE;
		goto done;
	}

	if ((ar->ar_port_next + nr_ports) > ar->ar_port_stop)
		ar->ar_port_next = ar->ar_port_start;

	*port = ar->ar_port_next;

	ar->ar_port_next += nr_ports;

	rc = 0;

done:
	rte_spinlock_unlock(&apm->apm_dnat_lock);
	return rc;
}

static int map_release_port(struct port_section *ps, uint16_t port)
{
	unsigned long bit = PM_SECTION_BIT(port);

	if (!ps)
		return -ENOENT;

	if (test_bits(bit, 1, ps->ps_bm))
		clear_bits(bit, 1, ps->ps_bm);
	else
		return -EINVAL;
	return 0;
}

/* Return a mapped address & port to the map */
int npf_apm_put_map(npf_apm_t *apm, uint32_t map_flags, vrfid_t vrfid,
		npf_addr_t ipaddr, in_port_t ipport)
{
	uint32_t addr;
	uint16_t port;
	struct port_map *pm;
	struct port_section *ps;
	int n;
	int rc;

	if (!apm || !ipport)
		return 0;

	/* Nothing to do for DNAT, we assign round-robin */
	if (unlikely(apm->apm_type == NPF_NATIN)) {
		rte_atomic64_dec(&apm->apm_dnat_used);
		return 0;
	}

	/* Only return a mapped port when necessary */
	if (!(map_flags & NPF_NAT_MAP_PORT))
		return 0;

	addr = NPF_ADDR_TO_UINT32(&ipaddr);
	port = ntohs(ipport);

	pm = map_get(addr, vrfid, false);
	if (!pm)
		return -ENOENT;

	n = PM_SECTION_OF_PORT(port);
	rte_spinlock_lock(&pm->pm_lock);

	ps = map_get_section(pm, n, false);
	rc = map_release_port(ps, port);
	if (!rc) {
		port_stats_dec(pm, ps);
		map_put_section(pm, ps, n);
	}

	rte_spinlock_unlock(&pm->pm_lock);

	return rc;
}

/* Allocate a mapping given the address range */
static int map_allocate_from_range(struct npf_apm *apm,
		struct npf_apm_range *ar, int nr_ports, vrfid_t vrfid,
		uint32_t *addr, in_port_t *port, uint32_t map_flags)
{
	int rc = -EINVAL;

	switch (apm->apm_type) {
	case NPF_NATIN:
		rc = map_dnat(apm, ar, nr_ports, addr, port);
		break;
	case NPF_NATOUT:
		rc = map_snat(ar, nr_ports, vrfid, addr, port, map_flags);
		break;
	}
	return rc;
}

/*
 * Callback for walking an address-group table.  Parameters are the start and
 * stop address of each entry in the address group, and the number of
 * addresses (range).  For host entries, start == stop and range == 1.
 */
static int apm_table_cb(uint32_t start, uint32_t stop, uint32_t range,
			void *data)
{
	struct apm_table_params *ap = data;
	struct npf_apm_range ar;

	/*
	 * Create a range from the table node data and the
	 * port range.  Override the addresses with the table address
	 */
	memcpy(&ar, &ap->ap_apm->apm_ar, sizeof(struct npf_apm_range));

	ar.ar_addr_range = range;
	ar.ar_addr_start = start;
	ar.ar_addr_stop = stop;
	ar.ar_addr_next = start;

	/* Always clear the mask, not host mapping here */
	ar.ar_addr_mask = 0;

	ap->ap_rc = map_allocate_from_range(ap->ap_apm, &ar,
			ap->ap_nr_ports, ap->ap_vrfid, &ap->ap_addr,
			&ap->ap_port, ap->ap_map_flags);

	/* Only keep going on full portmaps */
	if (ap->ap_rc == -ENOSPC)
		return 0;

	/* stop address-group walk */
	return 1;
}

/* map_allocate_from_table - Walk a table */
static int map_allocate_from_table(struct npf_apm *apm, int nr_ports,
		vrfid_t vrfid, uint32_t *addr, in_port_t *port,
		uint32_t map_flags)
{
	struct apm_table_params ap;
	int rc;

	ap.ap_apm = apm;
	ap.ap_nr_ports = nr_ports;
	ap.ap_addr = *addr;
	ap.ap_port = *port;
	ap.ap_vrfid = vrfid;
	ap.ap_map_flags = map_flags;
	ap.ap_rc = 0;

	/* Walk address-group table lists */
	rc = npf_addrgrp_ipv4_range_walk(apm->apm_table_id,
					 apm_table_cb, &ap);

	/* Bad table? */
	if (rc < 0) {
		RTE_LOG(ERR, FIREWALL,
				"NPF APM: Bad table walk. Table: %u rc: %d\n",
				apm->apm_table_id, rc);
		return rc;
	}

	/* Only update if successful */
	if (!ap.ap_rc) {
		*addr = ap.ap_addr;
		*port = ap.ap_port;
	}

	/* Result of the allocation attempt */
	return ap.ap_rc;
}

/* Get an address & port from the map */
int npf_apm_get_map(npf_apm_t *apm, uint32_t map_flags, int nr_ports,
		vrfid_t vrfid, npf_addr_t *ipaddr, in_port_t *ipport)
{
	uint32_t addr = NPF_ADDR_TO_UINT32(ipaddr);
	uint32_t *ipaddrp = (uint32_t *) ipaddr;
	in_port_t port = ntohs(*ipport);
	int rc;

	/*
	 * If we are using a table for the address range, then we must
	 * iterate through the table's IPv4 ptree to obtain the address
	 * range(s).
	 *
	 * Otherwise, allocate using the range in the apm.
	 */
	if (APM_USES_TABLE(apm))
		rc = map_allocate_from_table(apm, nr_ports, vrfid,
				&addr, &port, map_flags);
	else
		rc = map_allocate_from_range(apm, &apm->apm_ar,
				nr_ports, vrfid, &addr, &port, map_flags);
	if (!rc) {
		if (apm->apm_type == NPF_NATIN)
			rte_atomic64_add(&apm->apm_dnat_used, nr_ports);

		*ipaddrp = htonl(addr);
		*ipport = htons(port);
	}
	return rc;
}

/* Destroy an address map */
void npf_apm_destroy(npf_apm_t *apm)
{
	free(apm);
}

/*
 * Create an address/port map - Only called (externally) under the nat
 * policy lock
 */
void npf_apm_update(npf_apm_t *apm, uint32_t match_mask,
		uint8_t type, npf_addr_t a_start,
		npf_addr_t a_stop, in_port_t p_start, in_port_t p_stop)
{
	/* Address */
	apm->apm_ar.ar_addr_start = NPF_ADDR_TO_UINT32(&a_start);
	apm->apm_ar.ar_addr_stop = NPF_ADDR_TO_UINT32(&a_stop);
	apm->apm_ar.ar_addr_next = apm->apm_ar.ar_addr_start;

	if (apm->apm_ar.ar_addr_stop < apm->apm_ar.ar_addr_start)
		apm->apm_ar.ar_addr_stop = apm->apm_ar.ar_addr_start;

	apm->apm_ar.ar_addr_range = apm->apm_ar.ar_addr_stop -
					apm->apm_ar.ar_addr_start + 1;

	/* Determine whether host mapping is desired. */
	if (npf_is_range_subnet4(match_mask, apm->apm_ar.ar_addr_start,
				 apm->apm_ar.ar_addr_stop))
		apm->apm_ar.ar_addr_mask = match_mask;

	/* Port */
	apm->apm_ar.ar_port_start = p_start;
	apm->apm_ar.ar_port_stop = p_stop;

	if (!apm->apm_ar.ar_port_start)
		apm->apm_ar.ar_port_start = 1;

	if (!apm->apm_ar.ar_port_stop)
		apm->apm_ar.ar_port_stop = PORT_MAX;

	apm->apm_ar.ar_port_range = apm->apm_ar.ar_port_stop -
				apm->apm_ar.ar_port_start + 1;
	apm->apm_ar.ar_port_next = apm->apm_ar.ar_port_start;

	apm->apm_type = type;
}

/* Create an address/port map */
npf_apm_t *npf_apm_create(uint32_t match_mask, uint32_t table_id,
		uint8_t type, npf_addr_t a_start,
		npf_addr_t a_stop, in_port_t p_start, in_port_t p_stop)
{
	npf_apm_t *apm = zmalloc_aligned(sizeof(struct npf_apm));

	if (!apm) {
		if (net_ratelimit())
			RTE_LOG(ERR, FIREWALL, "NAT portmap create: ENOMEM\n");
		return NULL;
	}

	rte_spinlock_init(&apm->apm_dnat_lock);
	npf_apm_update(apm, match_mask,
			type, a_start, a_stop, p_start, p_stop);

	/* Cannot change the table id during an update, so set it now */
	apm->apm_table_id = table_id;

	return apm;
}

/* Clone - allocates a copy of the apm */
npf_apm_t *npf_apm_clone(npf_apm_t *apm)
{
	struct npf_apm *clone;

	clone = malloc_aligned(sizeof(struct npf_apm));
	if (!clone)
		return NULL;

	memcpy(clone, apm, sizeof(struct npf_apm));
	rte_spinlock_init(&clone->apm_dnat_lock);
	return clone;
}

void npf_apm_init(void)
{
	apm_ht = cds_lfht_new(PM_HT_INIT, PM_HT_MIN, PM_HT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!apm_ht)
		return;

	rte_timer_init(&apm_timer);
	rte_timer_reset(&apm_timer, APM_INTERVAL * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), map_gc, NULL);
}

void npf_apm_uninit(void)
{
	/* Ensure all is deleted */
	apm_delete_all();

	rcu_read_unlock();
	cds_lfht_destroy(apm_ht, NULL);
	rcu_read_lock();
}

/* jsonify a section */
static void json_ps(json_writer_t *json, struct port_section *ps,
							uint32_t section)
{
	uint32_t i;

	for (i = 0; i < PM_SECTION_BITS; i++) {
		if (test_bits(i, 1, ps->ps_bm))
			jsonw_uint(json,
				((section*PM_SECTION_BITS)+PM_BIT_TO_PORT(i)));
	}
}

/* Jsonify a pm */
static void json_pm(json_writer_t *json, struct port_map *pm)
{
	unsigned int i;
	struct port_section *ps;
	uint32_t naddr;
	char buf[INET6_ADDRSTRLEN];

	naddr = htonl(pm->pm_addr);
	inet_ntop(AF_INET, &naddr, buf, sizeof(buf));

	jsonw_start_object(json);
	jsonw_string_field(json, "address", buf);

	if (pm->pm_flags & PM_FLAG_DEAD)
		jsonw_string_field(json, "state", "DEAD");
	else if (pm->pm_flags & PM_FLAG_REMOVABLE)
		jsonw_string_field(json, "state", "REMOVABLE");
	else
		jsonw_string_field(json, "state", "ACTIVE");

	jsonw_uint_field(json, "used", pm->pm_used);

	if (!pm->pm_used) {
		jsonw_end_object(json);
		return;
	}

	jsonw_name(json, "ports");
	jsonw_start_array(json);
	for (i = 0; i < PM_SECTION_CNT; i++) {
		ps = pm->pm_sections[i];
		if (ps)
			json_ps(json, ps, i);
	}
	jsonw_end_array(json);
	jsonw_end_object(json);
}

/*
 * Dump the hash table:
 *
 *  % /opt/vyatta/bin/vplsh -l -c 'npf fw dump-portmap'
 */
void npf_apm_dump(FILE *fp)
{
	json_writer_t *json;
	struct cds_lfht_iter iter;
	struct port_map *pm;
	uint64_t count = 0;

	json = jsonw_new(fp);
	jsonw_name(json, "apm");
	jsonw_start_object(json);

	jsonw_int_field(json, "section_size", PM_SECTION_SIZE);
	jsonw_uint_field(json, "hash_memory",
			rte_atomic64_read(&pm_mem_used));

	jsonw_name(json, "portmaps");
	jsonw_start_array(json);
	cds_lfht_for_each_entry(apm_ht, &iter, pm, pm_node) {
		rte_spinlock_lock(&pm->pm_lock);
		json_pm(json, pm);
		count += pm->pm_used;
		rte_spinlock_unlock(&pm->pm_lock);
	}
	jsonw_end_array(json);

	jsonw_uint_field(json, "mapping_count", count);
	jsonw_end_object(json);
	jsonw_destroy(&json);
}

/*
 * To fully test npf via the whole-dataplane unit tests we need a mechanism to
 * flush the address and portmaps immediately.
 */
void npf_apm_flush_all(void)
{

	apm_delete_all();
}

/*
 * Get the allocation status for a particular address and port.
 *
 * ipaddr	translation address
 * port		port in host order
 */
bool
npf_apm_get_allocated(vrfid_t vrfid, npf_addr_t ipaddr, in_port_t port)
{
	uint32_t addr;
	unsigned long bit;
	struct port_map *pm;
	struct port_section *ps;
	int n;

	addr = NPF_ADDR_TO_UINT32(&ipaddr);

	pm = map_get(addr, vrfid, false);
	if (!pm)
		return false;

	n = PM_SECTION_OF_PORT(port);
	ps = map_get_section(pm, n, false);

	if (!ps)
		return false;

	bit = PM_SECTION_BIT(port);

	if (test_bits(bit, 1, ps->ps_bm))
		return true;

	return false;
}

