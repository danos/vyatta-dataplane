/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef	NPF_ZONE_PRIVATE_H
#define	NPF_ZONE_PRIVATE_H

#include <stdio.h>
#include "npf/npf.h"

struct npf_zone;
struct npf_zone_intf;

#define NPF_ZONES_SHOW_INTFS 0x01
#define NPF_ZONES_SHOW_POLS  0x02
#define NPF_ZONES_SHOW_RSETS 0x04
#define NPF_ZONES_SHOW_ALL   (NPF_ZONES_SHOW_INTFS | NPF_ZONES_SHOW_POLS | \
			      NPF_ZONES_SHOW_RSETS)

/* local zone */
struct npf_zone *npf_zone_local(void);
extern struct npf_zone *local_zone;

/* Get interface zone */
struct npf_zone *npf_zone_zif2zone_private(const struct npf_zone_intf *zif);

struct npf_zone_policy *npf_zone_policy_ht_lookup(
	const struct npf_zone *fm_zone, const struct npf_zone *to_zone);

int npf_zone_cfg(const char *name);
int npf_zone_uncfg(const char *name);
int npf_zone_local_set(const char *name, bool set);
int npf_zone_policy_add(const char *from_zone, const char *to_zone);
int npf_zone_policy_del(const char *from_zone, const char *to_zone);
int npf_zone_intf_add(const char *name, const char *ifname);
int npf_zone_intf_del(const char *name, const char *ifname);
void npf_zone_intf_get(struct npf_zone_intf *zif);
void npf_zone_intf_put(struct npf_zone_intf **zifp);
struct npf_zone_intf *npf_zone_ifname2zif(const char *ifname);
const char *npf_zone_name(struct npf_zone *nz);

struct npf_config *npf_zone_config(const struct npf_zone *from_zone,
				   const struct npf_zone *to_zone);

void npf_zone_show_private(json_writer_t *json, const char *zone,
			   const char *policy, uint8_t flags);

void npf_zone_inst_destroy_private(void);

#endif
