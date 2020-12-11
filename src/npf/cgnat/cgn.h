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

/**************************************************************************
 * CGNAT Global Variables
 **************************************************************************/

/* Hairpinning config enable/disable */
extern bool cgn_hairpinning_gbl;

/* snat-alg-bypass config enable/disable */
extern bool cgn_snat_alg_bypass_gbl;

/* Configurable max number of 3-tuple sessions */
extern int32_t cgn_sessions_max;

/*
 * Count of all 3-tuple sessions.  Incremented and compared against
 * cgn_sessions_max before a 3-tuple session is created.  If it exceeds
 * cgn_sessions_max then cgn_session_table_full is set true.
 */
extern rte_atomic32_t cgn_sessions_used;

/* Is session table full? */
extern bool cgn_session_table_full;

/*
 * Simple global counts for the number of dest addr (sess2) hash tables
 * created and destroyed.  These URCU hash tables are fairly resource
 * intensive, so we want to get some idea of how often they are required.
 */
extern rte_atomic64_t cgn_sess2_ht_created;
extern rte_atomic64_t cgn_sess2_ht_destroyed;

/* max 2-tuple sessions per 3-tuple session*/
extern int16_t cgn_dest_sessions_max;

/* Size of 2-tuple hash table that may be added per 3-tuple session */
extern int16_t cgn_dest_ht_max;

/* Global count of all 5-tuple sessions */
extern rte_atomic32_t cgn_sess2_used;

/* Is CGNAT helper core enabled? */
extern uint8_t cgn_helper_thread_enabled;

#endif
