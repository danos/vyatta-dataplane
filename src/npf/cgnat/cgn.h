/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_H_
#define _CGN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rte_atomic.h>
#include <rte_log.h>
#include "vplane_log.h"

/*
 * Packet direction relative to interface with cgnat policy.  Note that this
 * is 1 bit in 'struct cgn_sess2'.
 */
enum cgn_dir {
	CGN_DIR_IN = 0,
	CGN_DIR_OUT = 1
};
#define CGN_DIR_SZ 2

/* Sometimes it makes more sense to refer to forw and back */
enum cgn_flow {
	CGN_DIR_FORW = CGN_DIR_OUT,
	CGN_DIR_BACK = CGN_DIR_IN
};

static inline enum cgn_dir cgn_reverse_dir(enum cgn_dir dir)
{
	return (dir == CGN_DIR_OUT) ? CGN_DIR_IN : CGN_DIR_OUT;
}

extern bool cgn_hairpinning_gbl;
extern bool cgn_snat_alg_bypass_gbl;
extern rte_atomic64_t cgn_sess2_ht_created;
extern rte_atomic64_t cgn_sess2_ht_destroyed;

/* For unit-tests */
struct ifnet;
struct rte_mbuf;

void dp_test_npf_clear_cgnat(void);
bool ipv4_cgnat_test(struct rte_mbuf **mbufp, struct ifnet *ifp,
		     int dir, int *error);

#endif
