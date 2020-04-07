/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _APT_TUPLE_H_
#define _APT_TUPLE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <rte_log.h>
#include "vplane_log.h"
#include "vrf.h"

struct apt_tuple_tbl;
struct json_writer;

int apt_tuple_tbl_create(struct apt_tuple_tbl *tt);
void apt_tuple_tbl_destroy(struct apt_tuple_tbl *tt);
void apt_tuple_tbl_flush(struct apt_tuple_tbl *tt, int feat, bool flush_all,
			 apt_match_func_t match_fn, void *match_key);
void apt_tuple_tbl_gc(struct apt_tuple_tbl *tt, uint64_t current);
void apt_tuple_tbl_jsonw(struct json_writer *json, struct apt_tuple_tbl *tt);

#endif /* _APT_TUPLE_H_ */
