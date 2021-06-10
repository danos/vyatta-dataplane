/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef ALG_H
#define ALG_H

#include "npf/cgnat/alg/alg_defs.h"

enum cgn_alg_stat_e {
	CAS_CTRL_SESS_CRTD,
	CAS_CTRL_SESS_DSTD,
	CAS_DATA_SESS_CRTD,
	CAS_DATA_SESS_DSTD,
};

#define CGN_ALG_STATS_FIRST	CAS_CTRL_SESS_CRTD
#define CGN_ALG_STATS_LAST	CAS_DATA_SESS_DSTD
#define CGN_ALG_STATS_MAX	(CGN_ALG_STATS_LAST + 1)

void cgn_alg_stats_inc(enum cgn_alg_id id, enum cgn_alg_stat_e stat);
uint64_t cgn_alg_stats_read(enum cgn_alg_id id, enum cgn_alg_stat_e stat);
void cgn_alg_stats_clear(enum cgn_alg_id id);

/**
 * ALG ID to name
 *
 * @param id ALG ID
 * @return ALG name if found, else "-"
 */
const char *cgn_alg_id_name(enum cgn_alg_id id);

#endif /* ALG_H */
