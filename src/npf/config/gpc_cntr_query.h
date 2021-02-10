/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GPC_CNTR_QUERY_H
#define GPC_CNTR_QUERY_H

#include <stdint.h>
#include <stdbool.h>

struct gpc_cntg;
struct gpc_cntr;
enum gpc_feature;

/*
 * Type of counters in the counter group, either named or numbered.
 * Numbered can be created on demand, named have to be explicitly created.
 */
enum gpc_cntr_type {
	GPC_CNTT_NAMED = 1,
	GPC_CNTT_NUMBERED,
};

/*
 * What to count, a bitmask.
 * Appropriate bits set for each possibility.
 */
enum gpc_cntr_what {
	GPC_CNTW_PACKET = (1 << 0),
	GPC_CNTW_L3BYTE = (1 << 1),
};

/*
 * How counters are shared.
 * Only 'per-interface' for the moment.
 */
enum gpc_cntr_share {
	GPC_CNTS_INTERFACE = 1,
};

/* -- counter group accessors -- */

enum gpc_cntr_type gpc_cntg_type(struct gpc_cntg const *cntg);
enum gpc_cntr_what gpc_cntg_what(struct gpc_cntg const *cntg);
enum gpc_cntr_share gpc_cntg_share(struct gpc_cntg const *cntg);

struct gpc_group *gpc_cntg_get_group(struct gpc_cntg const *cntg);

struct gpc_cntg *gpc_cntg_first(enum gpc_feature feat);
struct gpc_cntg *gpc_cntg_next(struct gpc_cntg const *cursor);

#define GPC_CNTR_GROUP_FOREACH(feat, var) \
	for ((var) = gpc_cntg_first((feat)); \
	     (var); \
	     (var) = gpc_cntg_next((var)))

/* -- counter accessors -- */

struct gpc_cntg *gpc_cntr_get_cntg(struct gpc_cntr const *cntr);
char const *gpc_cntr_get_name(struct gpc_cntr const *cntr);
bool gpc_cntr_pkt_enabled(struct gpc_cntr const *cntr);
bool gpc_cntr_byt_enabled(struct gpc_cntr const *cntr);

uintptr_t gpc_cntr_get_objid(struct gpc_cntr const *cntr);
void gpc_cntr_set_objid(struct gpc_cntr *cntr, uintptr_t objid);

struct gpc_cntr *gpc_cntr_first(struct gpc_cntg const *cntg);
struct gpc_cntr *gpc_cntr_last(struct gpc_cntg const *cntg);
struct gpc_cntr *gpc_cntr_next(struct gpc_cntr const *cursor);

#define GPC_CNTR_FOREACH(var, head) \
	for ((var) = gpc_cntr_first((head)); \
	     (var); \
	     (var) = gpc_cntr_next((var)))

/* -- old shimmed counter accessors -- */

struct gpc_group *gpc_cntr_old_get_group(struct gpc_cntr const *ark);
uintptr_t gpc_cntr_old_get_objid(struct gpc_cntr const *cntr);
void gpc_cntr_old_set_objid(struct gpc_cntr *ark, uintptr_t objid);
char const *gpc_cntr_old_get_name(struct gpc_cntr const *cntr);
bool gpc_cntr_old_pkt_enabled(struct gpc_cntr const *cntr);
bool gpc_cntr_old_byt_enabled(struct gpc_cntr const *cntr);

#endif /* GPC_CNTR_QUERY_H */
