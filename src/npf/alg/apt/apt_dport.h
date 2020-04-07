/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * apt_dport.h - Private header file for APT destination port table
 */

#ifndef _APT_DPORT_H_
#define _APT_DPORT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rte_log.h>
#include "vplane_log.h"
#include "vrf.h"

struct apt_dport_tbl;

/*
 * For all entries matching the match key:
 *   1. delete any expired entries, and
 *   2. expire entries if flush_all is true
 */
void apt_dport_tbl_flush(struct apt_dport_tbl *dt, int feat, bool flush_all,
			 apt_match_func_t match_fn, void *match_key);
void apt_dport_tbl_gc(struct apt_dport_tbl *dt);
int apt_dport_tbl_create(struct apt_dport_tbl *dt);
void apt_dport_tbl_destroy(struct apt_dport_tbl *dt);
void apt_dport_tbl_jsonw(struct json_writer *json, struct apt_dport_tbl *dt);

#endif /* _APT_DPORT_H_ */
