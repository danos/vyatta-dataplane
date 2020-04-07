/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _APT_H_
#define _APT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <rte_atomic.h>
#include <rte_spinlock.h>
#include <urcu.h>
#include "vrf.h"

/*
 * Destination port table
 */
struct apt_dport_tbl {
	struct cds_lfht	*dt_ht;
	rte_atomic32_t	dt_count[ALG_FEAT_MAX];
};

/*
 * Tuple table
 *
 * tt_lock is used for paired tuples to prevent simultaneous sessions being
 * created in two directions.
 */
struct apt_tuple_tbl {
	struct cds_lfht	*tt_ht;
	rte_atomic32_t	tt_count[ALG_FEAT_MAX];
	rte_spinlock_t	tt_lock[ALG_FEAT_MAX];
};

/*
 * APT VRF Instance
 */
struct apt_instance {
	vrfid_t			ai_vrfid;	/* external vrf id */
	rte_atomic32_t		ai_refcnt;

	/*
	 * Entries may only be made to the tables when the instance is
	 * enabled.
	 */
	bool			ai_enabled;

	/* Destination port table */
	struct apt_dport_tbl	ai_dport;

	/* Tuple table */
	struct apt_tuple_tbl	ai_tuple;

	struct rcu_head		ai_rcu;
};

#endif /* _APT_H_ */
