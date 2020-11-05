/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef GPC_DB_CONTROL_H
#define GPC_DB_CONTROL_H

#include <stdint.h>
#include <stdbool.h>

struct gpc_rlset;
struct gpc_group;
struct gpc_cntr;
struct gpc_rule;

/* -- ruleset -- */

void gpc_rlset_set_if_created(struct gpc_rlset *gprs);
bool gpc_rlset_set_ifp(struct gpc_rlset *gprs);
void gpc_rlset_clear_ifp(struct gpc_rlset *gprs);

struct gpc_rlset *gpc_rlset_create(bool ingress, char const *if_name,
				   void *owner);
void gpc_rlset_delete(struct gpc_rlset *gprs);

/* -- group -- */

/* -- cntr -- */

/* -- rule -- */

#endif /* GPC_DB_CONTROL_H */
