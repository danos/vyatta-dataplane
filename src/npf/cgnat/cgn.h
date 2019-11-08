/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_H_
#define _CGN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rte_log.h>
#include "vplane_log.h"

/*
 * Packet direction relative to interface with cgnat policy.
 */
enum cgn_dir {
	CGN_DIR_IN,
	CGN_DIR_OUT
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
extern rte_atomic64_t cgn_hairpinned_pkts;

/*
 * CGNAT Dataplane Event Handlers
 */
void cgn_event_if_index_set(struct ifnet *ifp, uint32_t ifindex);
void cgn_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex);

struct rte_mbuf *cgn_copy_or_clone_and_undo(struct rte_mbuf *mbuf,
					    const struct ifnet *in_ifp,
					    const struct ifnet *out_if,
					    bool copy);

/* Convert a soft_ticks value in milliseconds to an Epoch time in microsecs */
uint64_t cgn_ticks2timestamp(uint64_t ticks);

/* Convert start time in soft_ticks into duration in microseconds */
uint64_t cgn_start2duration(uint64_t start_time);

/* Extract int from string */
int cgn_arg_to_int(const char *arg);

/* Format host byte order address to string */
char *cgn_addrstr(uint32_t addr, char *str, size_t slen);

/* For unit-tests */
void dp_test_npf_clear_cgnat(void);

#endif
