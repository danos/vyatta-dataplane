/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 *  NPF Address Port Map (APM) header
 */

#ifndef NPF_APM_H
#define NPF_APM_H

#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <rte_timer.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <values.h>

#include "npf/npf.h"
#include "util.h"
#include "vrf_internal.h"

typedef struct npf_apm npf_apm_t;

/*
 * APM section macros
 */
#define PM_SECTION_SIZE		512
#define PM_SECTION_BITS		(PM_SECTION_SIZE << 3)
#define PM_BIT_FROM_PORT(p)	((p)-1)
#define PM_BIT_TO_PORT(p)	((p)+1)
#define PM_SECTION_BIT(p)	(PM_BIT_FROM_PORT(p) % PM_SECTION_BITS)
#define PM_SECTION_OF_PORT(p)	(PM_BIT_FROM_PORT(p) / PM_SECTION_BITS)

/* Next section after the one for the given port */
#define PM_SECTION_NEXT(p)	(PM_SECTION_OF_PORT(p) + 1)

/* First port of a section */
#define PM_SECTION_FIRST_PORT(s) ((s)*PM_SECTION_BITS + 1)

/* First port in the section following the given ports section */
#define PM_SECTION_SPAN_NEXT(p) PM_SECTION_FIRST_PORT(PM_SECTION_NEXT(p))

/*
 * If this bit range spans a word boundary then returns the number of bits
 * that fall in the next word, else return 0.
 *
 * e.g. bit 63 (port 64), nr_bits 2, will return 1.
 */
static inline uint
npf_apm_span_word(ulong bit, uint nr_bits)
{
	if (likely(bit % LONGBITS + nr_bits - 1 < LONGBITS))
		return 0;
	else
		return bit % LONGBITS + nr_bits - LONGBITS;
}

/*
 * Does this port range span a section?
 *
 * e.g. port 4095 and 3 ports will span a section so we want to jump to the
 * start of the next section (port 4097) for our allocation.
 */
static inline bool
npf_apm_span_section(in_port_t port, uint nr_ports)
{
	/* Treat as a bit array indice */
	return ((PM_SECTION_BIT(port) + nr_ports - 1) > (PM_SECTION_BITS - 1));
}

void npf_apm_init(void);
void npf_apm_uninit(void);

int npf_apm_get_map(npf_apm_t *apm, uint32_t map_flags, int nr_ports,
		vrfid_t vrfid, npf_addr_t *addr, in_port_t *port);
int npf_apm_put_map(npf_apm_t *apm, uint32_t map_flags, vrfid_t vrfid,
		npf_addr_t addr, in_port_t port);
npf_apm_t *npf_apm_create(uint32_t mask, uint32_t table_id, uint8_t type,
		npf_addr_t start_addr, npf_addr_t stop_addr,
		in_port_t start_port, in_port_t stop_port);
void npf_apm_update(npf_apm_t *apm, uint32_t mask, uint8_t type,
		npf_addr_t addr_start, npf_addr_t addr_stop,
		in_port_t start_port, in_port_t stop_port);
void npf_apm_destroy(npf_apm_t *apm);
npf_apm_t *npf_apm_clone(npf_apm_t *apm);
void npf_apm_flush_all(void);
void npf_apm_dump(FILE *fp);

/*
 * Get the allocation status for a particular address and port.
 *
 * ipaddr	translation address
 * port		port in host order
 */
bool
npf_apm_get_allocated(vrfid_t ctfid, npf_addr_t ipaddr, in_port_t port);

#endif /* NPF_APM_H */
