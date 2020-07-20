/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_jhash.h>
#include <stdint.h>
#include <stdio.h>

#include "json_writer.h"
#include "compiler.h"
#include "if_var.h"
#include "npf/npf.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_cache.h"
#include "npf/npf_if.h"
#include "npf/npf_nat.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_session.h"
#include "npf/npf_state.h"
#include "npf/npf_timeouts.h"
#include "npf/rproc/npf_ext_session_limit.h"
#include "npf_shim.h"
#include "pktmbuf_internal.h"
#include "urcu.h"
#include "vplane_log.h"
#include "npf/zones/npf_zone_public.h"
#include "npf/zones/npf_zone_private.h"

/*
 *                   npf_zone                policy           policy
 *                   +-------+               +-------+        +-------+
 *                   | ZONEA | policy        | ZONEB |        | ZONEC |
 *                   |       |-------------->|       |------->|       |
 *                   |       | list+hash     |       |        |       |
 *                   +-------+               +-------+        +-------+
 *              intf  |    ^                     |                |
 *              list  |    |                     v                v
 *                    |    | back            npf_config       npf_config
 *                    v    | ptr
 *  +-----+          +------+                attach-point     attach-point
 *  |     |          |      |                "ZONEA>ZONEB"    "ZONEA>ZONEC"
 *  |     |--------->|      |
 *  |     |          |      |
 *  +-----+          +------+
 *  npf if           npf_zone_intf
 *
 *                    |    ^
 *                    |    |
 *                    |    |
 *                    v    |
 *  +-----+          +------+
 *  |     |          |      |
 *  |     |--------->|      |
 *  |     |          |      |
 *  +-----+          +------+
 *  npf if           npf_zone_intf
 *
 *
 * In the output context, we use the receive interface and transmit interface
 * to get the 'from' and 'to' zones.
 *
 * To find the relevant policy (which contains the ruleset), we hash the
 * 'to' zone pointer and lookup the 'from' zones policy hash table.
 */

/*
 * zone instance
 */
struct npf_zone_inst {
	struct cds_list_head	zi_zone_list;   /* npf_zone list */
	uint32_t		zi_zone_count;
};

/* Single, global, zone instance */
static struct npf_zone_inst *zone_inst;

/*
 * zone policy
 *
 * A zone policy is created on a 'from' for every 'to' zone reference.  For
 * example is rulesets are configured for ZONEA to ZONEB and ZONEA to ZONEC
 * then zone policies are created for ZONEB and ZONEC, and these are added to
 * the hash table of ZONEA.
 *
 * Also, when a zone policy makes reference to a zone that currently does not
 * exist, then a zone structure will be created for it.  This is necessary
 * since we use the pointer to a zone structure to generate a hash value and
 * for the hash lookup match.
 */
struct npf_zone_policy {
	struct cds_list_head	zp_list_node;    /* nz_policy_list node */
	struct cds_lfht_node	zp_lfht_node;
	char                    *zp_name;
	/* Locks held by zone policy list and attach point */
	uint32_t		zp_refcnt;
	struct npf_zone         *zp_to_zone;
	struct npf_config	*zp_conf;
};

/*
 * zone
 *
 * Interface and policy lists are only ever updated from the main thread.
 * The policy hash table is updated by the main thread, but looked-up by the
 * forwarding threads.
 */
struct npf_zone {
	struct cds_list_head	nz_node;        /* zi_zone_list node */
	char                    *nz_name;
	bool                    nz_local;
	uint32_t                nz_hash;        /* hash of nz pointer */
	uint32_t		nz_refcnt;
	struct cds_list_head	nz_intf_list;   /* npf_zone_intf list */
	uint32_t		nz_intf_count;
	struct cds_list_head	nz_policy_list;
	struct cds_lfht		*nz_policy_ht;
	uint32_t		nz_policy_count;
};

/*
 * zone interface
 */
struct npf_zone_intf {
	struct cds_list_head	zif_node;       /* nz_intf_list node */
	char                    *zif_ifname;
	struct npf_zone         *zif_zone;      /* back ptr to zone */
	uint32_t		zif_refcnt;
};

struct npf_zone *local_zone;


/* Forward reference */
static uint32_t npf_zone_policy_ht_hash(const uintptr_t nz);
static int npf_zone_list_insert(struct npf_zone *nz);
static int npf_zone_list_remove(struct npf_zone *nz);
static void npf_zone_list_remove_all(struct npf_zone_inst *zi);
static void npf_zone_intf_list_remove_all(struct npf_zone **nzp);
static void npf_zone_policy_remove_all(struct npf_zone **nzp);
static struct npf_zone_policy *npf_zone_policy_create(const char *policy_name);
static void npf_zone_policy_destroy(struct npf_zone_policy **zpp);


/***************************   instance   **********************************/

static struct npf_zone_inst *
npf_zone_inst_create(void)
{
	struct npf_zone_inst *zi;

	zi = zmalloc_aligned(sizeof(*zi));
	if (!zi)
		return NULL;

	CDS_INIT_LIST_HEAD(&zi->zi_zone_list);

	return zi;
}

static struct npf_zone_inst *
npf_zone_inst_find_or_create(void)
{
	if (!zone_inst)
		zone_inst = npf_zone_inst_create();

	return zone_inst;
}

static struct npf_zone_inst *
npf_zone_inst_find(void)
{
	return zone_inst;
}

void
npf_zone_inst_destroy_private(void)
{
	if (!zone_inst)
		return;

	npf_zone_list_remove_all(zone_inst);
	free(zone_inst);
	zone_inst = NULL;
}

/*
 * Remove zone from instance list and destroy.  Should only be called when ref
 * count reaches zero.
 */
static void
npf_zone_destroy(struct npf_zone **nzp)
{
	struct npf_zone *nz = *nzp;

	if (!nz)
		return;

	assert(nz->nz_refcnt == 0);
	assert(nz->nz_intf_count == 0);

	npf_zone_list_remove(nz);

	if (nz->nz_name)
		free(nz->nz_name);
	if (nz->nz_policy_ht)
		cds_lfht_destroy(nz->nz_policy_ht, NULL);

	free(nz);
	*nzp = NULL;
}

/* Hash table config */
#define ZONE_POLICY_HT_INIT	32
#define ZONE_POLICY_HT_MIN	32
#define ZONE_POLICY_HT_MAX	1024

/*
 * Create a zone structure, and insert it into zone instance list.  The caller
 * should call npf_zone_get to increment the zones ref count.
 */
static struct npf_zone *
npf_zone_create(const char *name)
{
	struct npf_zone *nz;
	int rc;

	nz = zmalloc_aligned(sizeof(*nz));
	if (!nz)
		return NULL;

	nz->nz_name = strdup(name);
	nz->nz_refcnt = 0;
	CDS_INIT_LIST_HEAD(&nz->nz_intf_list);
	CDS_INIT_LIST_HEAD(&nz->nz_policy_list);
	nz->nz_policy_ht = cds_lfht_new(ZONE_POLICY_HT_INIT,
					ZONE_POLICY_HT_MIN,
					ZONE_POLICY_HT_MAX,
					CDS_LFHT_AUTO_RESIZE |
					CDS_LFHT_ACCOUNTING, NULL);
	if (!nz->nz_policy_ht) {
		npf_zone_destroy(&nz);
		return NULL;
	}

	/*
	 * Pre-compute the hash for use when looking up the zone policy
	 * corresponding to this zone in another zones hash table.
	 */
	nz->nz_hash = npf_zone_policy_ht_hash((uintptr_t)nz);

	rc = npf_zone_list_insert(nz);
	if (rc) {
		npf_zone_destroy(&nz);
		return NULL;
	}

	return nz;
}

/*
 * A ref count is held for a zone when either user configures a zone, an
 * interface is added to a zone, or when a zone policy references a zone.
 */
static void
npf_zone_get(struct npf_zone *nz)
{
	nz->nz_refcnt++;
}

static void
npf_zone_put(struct npf_zone **nzp)
{
	struct npf_zone *nz = *nzp;

	assert(nzp);
	assert(nz);

	if (nz && --nz->nz_refcnt == 0)
		npf_zone_destroy(nzp);
}

static struct npf_zone *
npf_zone_list_find(const char *name)
{
	struct npf_zone *nz;
	struct npf_zone_inst *zi;

	if (!name)
		return NULL;

	zi = npf_zone_inst_find();
	if (!zi)
		return NULL;

	if (zi->zi_zone_count == 0)
		return NULL;

	cds_list_for_each_entry(nz, &zi->zi_zone_list, nz_node) {
		if (!strcmp(name, nz->nz_name))
			return nz;
	}
	return NULL;
}

static int
npf_zone_list_insert(struct npf_zone *nz)
{
	struct npf_zone_inst *zi;

	zi = npf_zone_inst_find_or_create();
	if (!zi)
		return -EINVAL;

	cds_list_add_tail(&nz->nz_node, &zi->zi_zone_list);
	zi->zi_zone_count++;

	return 0;
}

static int
npf_zone_list_remove(struct npf_zone *nz)
{
	struct npf_zone_inst *zi;

	/*
	 * A zone might not be in the list if npf_zone_create failed to add it
	 */
	if (cds_list_empty(&nz->nz_node))
		return -1;

	zi = npf_zone_inst_find();
	if (!zi)
		return -1;

	cds_list_del(&nz->nz_node);
	zi->zi_zone_count--;

	npf_zone_intf_list_remove_all(&nz);
	npf_zone_policy_remove_all(&nz);

	return 0;
}

static void
npf_zone_list_remove_all(struct npf_zone_inst *zi)
{
	struct npf_zone *nz, *tmp;

	if (zi->zi_zone_count == 0)
		return;

	cds_list_for_each_entry_safe(nz, tmp, &zi->zi_zone_list, nz_node) {
		cds_list_del(&nz->nz_node);
		zi->zi_zone_count--;
		npf_zone_intf_list_remove_all(&nz);
		npf_zone_policy_remove_all(&nz);
		npf_zone_put(&nz);
	}
}

static struct npf_zone *
npf_zone_find_or_create(const char *name)
{
	struct npf_zone *nz;

	nz = npf_zone_list_find(name);
	if (!nz)
		nz = npf_zone_create(name);

	return nz;
}

const char *npf_zone_name(struct npf_zone *nz)
{
	if (nz)
		return nz->nz_name;
	return NULL;
}

struct npf_zone *npf_zone_zif2zone_private(const struct npf_zone_intf *zif)
{
	if (zif)
		return zif->zif_zone;
	return NULL;
}

struct npf_zone *npf_zone_local(void)
{
	return local_zone;
}

/*************************  zone intf *********************************/

static void
npf_zone_intf_destroy(struct npf_zone_intf **zifp)
{
	struct npf_zone_intf *zif = *zifp;

	if (zif) {
		if (zif->zif_ifname)
			free(zif->zif_ifname);
		free(zif);
		*zifp = NULL;
	}
}

static struct npf_zone_intf *
npf_zone_intf_create(const char *ifname)
{
	struct npf_zone_intf *zif;

	zif = zmalloc_aligned(sizeof(*zif));
	if (!zif)
		return NULL;

	zif->zif_ifname = strdup(ifname);
	if (!zif->zif_ifname) {
		npf_zone_intf_destroy(&zif);
		return NULL;
	}
	zif->zif_refcnt = 0;

	return zif;
}

void
npf_zone_intf_get(struct npf_zone_intf *zif)
{
	zif->zif_refcnt++;
}

void
npf_zone_intf_put(struct npf_zone_intf **zifp)
{
	struct npf_zone_intf *zif = *zifp;

	assert(zif);
	assert(zif->zif_refcnt > 0);

	if (zif && --zif->zif_refcnt == 0)
		npf_zone_intf_destroy(zifp);
}

/*
 * Lookup interface by interface name in a zones interface list
 */
static struct npf_zone_intf *
npf_zone_intf_list_find(const struct npf_zone *nz, const char *ifname)
{
	struct npf_zone_intf *zif;

	if (nz->nz_intf_count == 0)
		return NULL;

	cds_list_for_each_entry(zif, &nz->nz_intf_list, zif_node) {
		if (!strcmp(ifname, zif->zif_ifname))
			return zif;
	}
	return NULL;
}

static int
npf_zone_intf_list_insert(struct npf_zone *nz, struct npf_zone_intf *zif)
{
	assert(zif->zif_zone == NULL);

	/* Store back pointer to zone in zone intf */
	zif->zif_zone = nz;
	npf_zone_get(nz);

	/* Add zone intf to zone list  */
	cds_list_add_tail(&zif->zif_node, &nz->nz_intf_list);
	nz->nz_intf_count++;
	npf_zone_intf_get(zif);

	return 0;
}

static int
npf_zone_intf_list_remove(struct npf_zone **nzp, struct npf_zone_intf **zifp)
{
	struct npf_zone *nz = *nzp;
	struct npf_zone_intf *zif = *zifp;

	if (!nz || !zif)
		return 0;

	assert(nz == zif->zif_zone);

	cds_list_del(&zif->zif_node);
	nz->nz_intf_count--;

	zif->zif_zone = NULL;
	npf_zone_intf_put(zifp);
	npf_zone_put(nzp);

	return 0;
}

static void
npf_zone_intf_list_remove_all(struct npf_zone **nzp)
{
	struct npf_zone_intf *zif, *tmp;
	struct npf_zone *nz = *nzp;

	if (!nz || nz->nz_intf_count == 0)
		return;

	cds_list_for_each_entry_safe(zif, tmp, &nz->nz_intf_list, zif_node) {
		npf_zone_intf_list_remove(nzp, &zif);
	}
}

/*
 * Get zones config.  Called from forwarding threads.
 */
struct npf_config *
npf_zone_config(const struct npf_zone *fm_zone,
		const struct npf_zone *to_zone)
{
	struct npf_zone_policy *zp;

	if (!fm_zone || !to_zone)
		return NULL;

	zp = npf_zone_policy_ht_lookup(fm_zone, to_zone);
	if (!zp)
		return NULL;

	return rcu_dereference(zp->zp_conf);
}

static void
npf_zone_policy_destroy(struct npf_zone_policy **zpp)
{
	struct npf_zone_policy *zp = *zpp;

	if (zp) {
		*zpp = NULL;
		if (zp->zp_to_zone)
			npf_zone_put(&zp->zp_to_zone);
		if (zp->zp_name)
			free(zp->zp_name);
		free(zp);
	}
}

static struct npf_zone_policy *
npf_zone_policy_create(const char *policy_name)
{
	struct npf_zone_policy *zp;

	zp = zmalloc_aligned(sizeof(*zp));
	if (!zp)
		return NULL;

	zp->zp_name = strdup(policy_name);
	if (!zp->zp_name) {
		npf_zone_policy_destroy(&zp);
		return NULL;
	}
	zp->zp_refcnt = 0;

	/*
	 * Create the 'to' zone to which this policy refers to.  We use the
	 * 'to' zone pointer to create a hash when storing the zone policy in
	 * the 'from' zones hash table, and for the hash match function in the
	 * hash lookup.
	 */
	zp->zp_to_zone = npf_zone_find_or_create(policy_name);

	if (!zp->zp_to_zone) {
		npf_zone_policy_destroy(&zp);
		return NULL;
	}
	npf_zone_get(zp->zp_to_zone);

	return zp;
}

static void
npf_zone_policy_get(struct npf_zone_policy *zp)
{
	zp->zp_refcnt++;
}

static void
npf_zone_policy_put(struct npf_zone_policy **zpp)
{
	struct npf_zone_policy *zp = *zpp;

	assert(zpp);
	assert(zp);

	if (zp && --zp->zp_refcnt == 0)
		npf_zone_policy_destroy(zpp);
}

static struct npf_zone_policy *
npf_zone_policy_list_find(const struct npf_zone *nz, const char *policy_name)
{
	struct npf_zone_policy *zp;

	if (!policy_name || nz->nz_policy_count == 0)
		return NULL;

	cds_list_for_each_entry(zp, &nz->nz_policy_list, zp_list_node) {
		if (!strcmp(policy_name, zp->zp_name))
			return zp;
	}
	return NULL;
}

static int
npf_zone_policy_list_insert(struct npf_zone *nz, struct npf_zone_policy *zp)
{
	cds_list_add_tail(&zp->zp_list_node, &nz->nz_policy_list);
	nz->nz_policy_count++;

	return 0;
}

static int
npf_zone_policy_list_remove(struct npf_zone *nz, struct npf_zone_policy *zp)
{
	cds_list_del(&zp->zp_list_node);
	nz->nz_policy_count--;

	return 0;
}

static uint32_t
npf_zone_policy_ht_hash(const uintptr_t nz)
{
	return rte_jhash_2words((uint64_t)nz >> 32, (uint32_t)nz, 0);
}

static int
npf_zone_policy_ht_match(struct cds_lfht_node *ht_node, const void *key)
{
	struct npf_zone *nz = (struct npf_zone *)key;
	struct npf_zone_policy *zp = caa_container_of(ht_node,
						      struct npf_zone_policy,
						      zp_lfht_node);

	return zp->zp_to_zone == nz;
}

static int
npf_zone_policy_ht_insert(struct npf_zone *nz, struct npf_zone_policy *zp)
{
	struct cds_lfht_node *node;

	node = cds_lfht_add_unique(
		nz->nz_policy_ht,
		npf_zone_policy_ht_hash((uintptr_t)zp->zp_to_zone),
		npf_zone_policy_ht_match,
		zp->zp_to_zone,
		&zp->zp_lfht_node);

	if (node != &zp->zp_lfht_node) {
		npf_zone_policy_destroy(&zp);
		return -EEXIST;
	}
	return 0;
}

struct npf_zone_policy *
npf_zone_policy_ht_lookup(const struct npf_zone *fm_zone,
			  const struct npf_zone *to_zone)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct npf_zone_policy *zp = NULL;

	cds_lfht_lookup(fm_zone->nz_policy_ht, to_zone->nz_hash,
			npf_zone_policy_ht_match, to_zone, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		zp = caa_container_of(node, struct npf_zone_policy,
				      zp_lfht_node);

	return zp;
}

static int
npf_zone_policy_ht_remove(const struct npf_zone *nz,
			  struct npf_zone_policy *zp)
{
	if (npf_zone_policy_ht_lookup(nz, zp->zp_to_zone)) {
		cds_lfht_del(nz->nz_policy_ht, &zp->zp_lfht_node);
		return 0;
	}
	return -EINVAL;
}

/*
 * Remove all zone policies from a zone
 */
static void
npf_zone_policy_remove_all(struct npf_zone **nzp)
{
	struct npf_zone_policy *zp, *tmp;
	struct npf_zone *nz = *nzp;
	int rc;

	if (!nz || nz->nz_policy_count == 0)
		return;

	cds_list_for_each_entry_safe(zp, tmp, &nz->nz_policy_list,
				     zp_list_node) {
		rc = npf_zone_policy_ht_remove(nz, zp);
		if (rc)
			continue;

		npf_zone_policy_list_remove(nz, zp);
		npf_zone_policy_put(&zp);
	}
}


/***************************   config     **********************************/

int npf_zone_cfg(const char *name)
{
	struct npf_zone *nz;

	/* Zone may already exist if a policy refers to it */
	nz = npf_zone_find_or_create(name);
	if (!nz)
		return -ENOMEM;

	npf_zone_get(nz);

	return 0;
}

int npf_zone_uncfg(const char *name)
{
	struct npf_zone *nz;

	nz = npf_zone_list_find(name);
	if (!nz)
		return 0;

	if (nz == local_zone)
		local_zone = NULL;

	npf_zone_put(&nz);

	return 0;
}

/*
 * Set or clear the assigned local_zone
 */
int npf_zone_local_set(const char *name, bool set)
{
	struct npf_zone *nz;

	nz = npf_zone_list_find(name);
	if (!nz)
		return -EEXIST;

	if (set) {
		if (local_zone)
			/* Only one zone can be the local zone */
			return -EINVAL;
		local_zone = nz;
		nz->nz_local = true;
	} else {
		if (local_zone != nz)
			return -EINVAL;
		local_zone = NULL;
		nz->nz_local = false;
	}

	return 0;
}

/*
 * Add a policy to a zone
 */
int
npf_zone_policy_add(const char *zname, const char *policy_name)
{
	struct npf_zone *nz;
	struct npf_zone_policy *zp;
	char *ap_name;
	int rc;

	nz = npf_zone_list_find(zname);
	if (!nz)
		return -EINVAL;

	if (npf_zone_policy_list_find(nz, policy_name))
		return -EINVAL;

	zp = npf_zone_policy_create(policy_name);
	if (!zp)
		return 0;

	rc = npf_zone_policy_ht_insert(nz, zp);
	if (rc)
		return rc;

	ap_name = alloca(strlen(zname) + strlen(policy_name) + 2);
	sprintf(ap_name, "%s>%s", zname, policy_name);

	rc = npf_attpt_item_set_up(NPF_ATTACH_TYPE_ZONE, ap_name, &zp->zp_conf,
				   NULL);
	if (rc != 0) {
		RTE_LOG(ERR, DATAPLANE, "NPF attpt raise fail: zone/%s\n",
			ap_name);
		npf_zone_policy_ht_remove(nz, zp);
		return rc;
	}

	npf_zone_policy_list_insert(nz, zp);

	/*
	 * Take a single ref count for the policy being in both hash table and
	 * list
	 */
	npf_zone_policy_get(zp);
	return 0;
}

int
npf_zone_policy_del(const char *zname, const char *policy_name)
{
	struct npf_zone *nz;
	struct npf_zone_policy *zp;
	char *ap_name;
	int rc;

	nz = npf_zone_list_find(zname);
	if (!nz)
		return 0;

	zp = npf_zone_policy_list_find(nz, policy_name);
	if (!zp)
		return 0;

	/* remove from hash table */
	rc = npf_zone_policy_ht_remove(nz, zp);
	if (rc)
		return rc;

	/* remove from list */
	npf_zone_policy_list_remove(nz, zp);

	ap_name = alloca(strlen(zname) + strlen(policy_name) + 2);
	sprintf(ap_name, "%s>%s", zname, policy_name);
	rc = npf_attpt_item_set_down(NPF_ATTACH_TYPE_ZONE, ap_name);
	if (rc != 0)
		RTE_LOG(ERR, DATAPLANE, "NPF attpt down fail: zone/%s\n",
			ap_name);

	npf_zone_policy_put(&zp);
	return 0;
}

/*
 * Adds zone intf struct to zone list.  Interface may not yet exist.
 */
int npf_zone_intf_add(const char *zname, const char *ifname)
{
	struct npf_zone *nz;
	struct npf_zone_intf *zif;
	int rc;

	nz = npf_zone_list_find(zname);
	if (!nz)
		return -EINVAL;

	zif = npf_zone_intf_list_find(nz, ifname);
	if (zif)
		return -EINVAL;

	zif = npf_zone_intf_create(ifname);
	if (!zif)
		return -ENOMEM;

	npf_zone_intf_list_insert(nz, zif);

	struct ifnet *ifp = dp_ifnet_byifname(ifname);

	assert(npf_zone_ifname2zif(ifname) == zif);

	/*
	 * Interface may not exist yet.  If this is the case then the
	 * remainder of this initialization occurs from npf_if_enable when the
	 * interface is created, and an index assigned to it.
	 */
	if (!ifp || !ifp->if_index)
		return 0;

	/* Set pointer from npf_if_internal to zone intf */
	rc = npf_if_zone_assign(ifp, zif, true);
	if (!rc)
		npf_zone_intf_get(zif);

	return rc;
}

int npf_zone_intf_del(const char *zname, const char *ifname)
{
	struct npf_zone *nz;
	struct npf_zone_intf *zif;
	int rc;

	nz = npf_zone_list_find(zname);
	if (!nz)
		return 0;

	zif = npf_zone_intf_list_find(nz, ifname);
	if (!zif)
		return 0;

	/* remove from list and free */
	npf_zone_intf_list_remove(&nz, &zif);

	/* Interface may have been removed, or may have never existed */
	struct ifnet *ifp = dp_ifnet_byifname(ifname);

	/*
	 * ifp will be NULL if the interface was deleted before the zone
	 * config was removed.  In this case, npf_zone_if_index_unset will have
	 * already called npf_if_zone_assign and npf_zone_intf_put.
	 */
	if (!ifp || !ifp->if_index)
		return 0;

	/* Clear pointer from npf_if_internal to zone intf */
	rc = npf_if_zone_assign(ifp, NULL, true);
	if (!rc && zif)
		npf_zone_intf_put(&zif);

	return rc;
}

/*
 * npf_zone_ifname2zif is used when an interface is created after it has been
 * added to a zone.
 */
struct npf_zone_intf *
npf_zone_ifname2zif(const char *ifname)
{
	struct npf_zone *nz;
	struct npf_zone_inst *zi;
	struct npf_zone_intf *zif;

	if (!ifname)
		return NULL;

	zi = npf_zone_inst_find();
	if (!zi)
		return NULL;

	if (zi->zi_zone_count == 0)
		return NULL;

	cds_list_for_each_entry(nz, &zi->zi_zone_list, nz_node) {
		zif = npf_zone_intf_list_find(nz, ifname);
		if (zif)
			return zif;
	}
	return NULL;
}

/*********************      Show commands            ***********************/

static void
npf_zone_show_interface(json_writer_t *json, const struct npf_zone_intf *zif)
{
	jsonw_start_object(json);

	jsonw_string_field(json, "name", zif->zif_ifname);

	jsonw_end_object(json);
}

static void
npf_zone_show_policy(json_writer_t *json, const struct npf_zone *nz,
		     const struct npf_zone_policy *zp, uint8_t flags)
{
	char ap_name[100];

	snprintf(ap_name, sizeof(ap_name), "%s>%s",
		 nz->nz_name, zp->zp_name);

	jsonw_start_object(json);

	jsonw_string_field(json, "name", zp->zp_name);

	if (flags & NPF_ZONES_SHOW_RSETS) {
		struct npf_attpt_item *ap;

		jsonw_name(json, "config");
		jsonw_start_array(json);

		if (npf_attpt_item_find_up(NPF_ATTACH_TYPE_ZONE,
					   ap_name, &ap) >= 0)
			npf_show_attach_point_rulesets(json, ap, NPF_ZONE);

		jsonw_end_array(json);
	}

	jsonw_end_object(json);
}

static void
npf_zone_show_zone(json_writer_t *json, const struct npf_zone *nz,
		   const char *policy, uint8_t flags)
{
	jsonw_start_object(json);

	jsonw_string_field(json, "name", nz->nz_name);
	jsonw_bool_field(json, "local-zone", nz->nz_local && nz == local_zone);

	/* Interface list */
	if (flags & NPF_ZONES_SHOW_INTFS) {
		struct npf_zone_intf *zif;

		jsonw_name(json, "interfaces");
		jsonw_start_array(json);

		cds_list_for_each_entry(zif, &nz->nz_intf_list, zif_node)
			npf_zone_show_interface(json, zif);

		jsonw_end_array(json); /* interface list */
	}

	/* Policy list */
	if (flags & (NPF_ZONES_SHOW_POLS | NPF_ZONES_SHOW_RSETS)) {
		struct npf_zone_policy *zp;

		jsonw_name(json, "policies");
		jsonw_start_array(json);

		cds_list_for_each_entry(zp, &nz->nz_policy_list, zp_list_node)
			if (!policy || !strcmp(policy, zp->zp_name))
				npf_zone_show_policy(json, nz, zp, flags);

		jsonw_end_array(json); /* policy list */
	}

	jsonw_end_object(json); /* zone object */
}

void
npf_zone_show_private(json_writer_t *json, const char *zone,
		      const char *policy, uint8_t flags)
{
	struct npf_zone_inst *zi;
	struct npf_zone *nz;

	zi = npf_zone_inst_find();

	jsonw_pretty(json, true);
	jsonw_name(json, "zones");
	jsonw_start_array(json);

	if (zi) {
		cds_list_for_each_entry(nz, &zi->zi_zone_list, nz_node) {
			/* Looking for one particular zone? */
			if (zone && strcmp(zone, nz->nz_name))
				continue;

			/*
			 * Do not show zones that have been instantiated by a
			 * zones policy reference only.  The local-zone never
			 * has any associated interfaces.
			 */
			if (nz->nz_intf_count == 0 && !nz->nz_local)
				continue;

			npf_zone_show_zone(json, nz, policy, flags);
		}
	}

	jsonw_end_array(json);
}
