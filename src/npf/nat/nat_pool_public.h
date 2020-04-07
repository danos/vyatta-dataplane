/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _NAT_POOL_PUBLIC_H_
#define _NAT_POOL_PUBLIC_H_

#include "npf/nat/nat_pool_event.h"

struct nat_pool;

/* Clear address hints */
void nat_pool_clear_addr_hints(struct nat_pool *np);

/* Walk all pools in hash table */
typedef int (*nat_poolwalk_cb)(struct nat_pool *, void *);
int nat_pool_walk(nat_poolwalk_cb cb, void *data);

/* Get pool name */
char *nat_pool_name(struct nat_pool *np);

bool nat_pool_type_is_cgnat(struct nat_pool *np);

/* Is NAT pool active? */
bool nat_pool_is_active(struct nat_pool *np);

/* Activate pool */
void nat_pool_set_active(struct nat_pool *np);

/* De-activate pool */
void nat_pool_clear_active(struct nat_pool *np);

/* Log port-block alloc and release? */
bool nat_pool_log_pba(struct nat_pool *np);

/* Is this a blacklisted address? */
bool nat_pool_is_blacklist_addr(struct nat_pool *np, uint32_t addr);

/*
 * Check if an address in in a NAT pool.  'addr' is in network-byte order.
 * This should be reasonably efficient as it looks up the address-group
 * representation of the NAT pool (i.e. a Patricia Tree lookup).
 */
bool nat_pool_is_pool_addr(const struct nat_pool *np, uint32_t addr);

/* lookup nat pool in hash table */
struct nat_pool *nat_pool_lookup(const char *name);

/* reference nat pool */
struct nat_pool *nat_pool_get(struct nat_pool *np);

/* release nat pool */
void nat_pool_put(struct nat_pool *np);

/* add/delete/update nat pool config */
int nat_pool_cfg_add(FILE *f, int argc, char **argv);
int nat_pool_cfg_delete(FILE *f, int argc, char **argv);

void nat_pool_show(FILE *f, int argc, char **argv);

/* init/uninit of nat pool module */
void nat_pool_init(void);
void nat_pool_uninit(void);

/**************************************************************************
 * NAT Pool to Client API
 **************************************************************************/

/*
 * Allow space for 2 clients
 */
#define NP_CLIENT_MAX_OPS	2

/* Per-client functions */
struct np_client_ops {
	/* Get the number of users and addresses using this NAT pool */
	void (*np_client_counts)(struct nat_pool *np, uint32_t *nusers,
				 uint64_t *naddrs);
};

/* Register client ops */
bool nat_pool_client_register(const struct np_client_ops *ops);

/* Unregister event ops */
void nat_pool_client_unregister(const struct np_client_ops *ops);

#endif
