/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GPC_CNTR_CONTROL_H
#define GPC_CNTR_CONTROL_H

#include <stdint.h>
#include <stdbool.h>

struct gpc_group;
struct gpc_cntg;
struct gpc_cntr;
enum gpc_cntr_type;
enum gpc_cntr_what;
enum gpc_cntr_share;

/* -- counter group -- */

struct gpc_cntg *gpc_cntg_create(struct gpc_group *gprg,
				 enum gpc_cntr_type type,
				 enum gpc_cntr_what what,
				 enum gpc_cntr_share share);
void gpc_cntg_retain(struct gpc_cntg *cntg);
void gpc_cntg_release(struct gpc_cntg *cntg);

/* -- counter -- */

struct gpc_cntr *gpc_cntr_create_named(struct gpc_cntg *cntg,
				       char const *name);
struct gpc_cntr *gpc_cntr_create_numbered(struct gpc_cntg *cntg,
					  uint16_t number);
struct gpc_cntr *gpc_cntr_find_and_retain(struct gpc_cntg *cntg,
					  char const *name);
void gpc_cntr_retain(struct gpc_cntr *cntr);
void gpc_cntr_release(struct gpc_cntr *cntr);

#endif /* GPC_CNTR_CONTROL_H */
