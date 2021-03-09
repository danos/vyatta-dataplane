/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Application resource group database.
 */

#include <rte_jhash.h>
#include "src/npf/config/npf_config.h"
#include "src/npf/dpi/dpi_internal.h"
#include "app_group_db.h"
#include "app_group.h"

#define APP_GRP_NAME_HT_SIZE	32
#define APP_GRP_NAME_HT_MIN	32
#define APP_GRP_NAME_HT_MAX	8192
#define APP_GRP_NAME_HT_FLAGS	(CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

/* App group DB garbage collector. */
static CDS_LIST_HEAD(app_group_db_gc_list);
static struct rte_timer ag_gc_timer;
#define AG_GC_INTERVAL     30

/* Application resource group database hash table. */
static struct cds_lfht *app_grp_ht;

static uint32_t hash_seed;

/* Forward */
static void
app_group_db_gc(struct rte_timer *t __rte_unused, void *arg __rte_unused);

bool
app_group_db_init(void)
{
	if (app_grp_ht)
		return true;

	app_grp_ht = cds_lfht_new(APP_GRP_NAME_HT_SIZE,
				  APP_GRP_NAME_HT_MIN,
				  APP_GRP_NAME_HT_MAX,
				  APP_GRP_NAME_HT_FLAGS,
				  NULL);

	if (!app_grp_ht)
		return false;

	hash_seed = random();

	/* Start the GC timer. */
	rte_timer_init(&ag_gc_timer);
	rte_timer_reset(&ag_gc_timer,
			(AG_GC_INTERVAL * rte_get_timer_hz()), PERIODICAL,
			rte_get_master_lcore(), app_group_db_gc, NULL);

	return true;
}

bool
app_group_db_rm_entry(struct agdb_entry *entry)
{
	if (!entry)
		return false;

	cds_lfht_del(app_grp_ht, &entry->ht_node);
	cds_list_add(&entry->deadlist, &app_group_db_gc_list);

	return true;
}

/*
 * Periodic garbage collection
 */
static void
app_group_db_gc(struct rte_timer *t __rte_unused, void *arg __rte_unused)
{
	struct agdb_entry *entry, *tmp;

	cds_list_for_each_entry_safe(entry, tmp, &app_group_db_gc_list,
				     deadlist) {
		if (entry->is_dead) {
			cds_list_del(&entry->deadlist);
			app_group_destroy(entry->group);
			free(entry);
		} else {
			entry->is_dead = true;
		}
	}

	/* Finally, remove any old app groups. */
	app_group_gc();
}

/*
 * Match function for the app_grp name hash table.
 * Returns zero for a non-match, and non-zero for a match.
 */
static int
app_group_db_match(struct cds_lfht_node *ht_node, const void *data)
{
	struct agdb_entry *entry;
	entry = caa_container_of(ht_node, struct agdb_entry, ht_node);

	return !strcmp(data, entry->name);
}

struct agdb_entry *
app_group_db_find_name(const char *name)
{
	struct cds_lfht_iter iter;
	unsigned long hash = rte_jhash(name, strlen(name), hash_seed);

	if (!app_grp_ht)
		return NULL;

	cds_lfht_lookup(app_grp_ht, hash, app_group_db_match,
			name, &iter);

	struct cds_lfht_node *ht_node;
	ht_node = cds_lfht_iter_get_node(&iter);

	if (ht_node)
		return caa_container_of(ht_node, struct agdb_entry, ht_node);
	else
		return NULL;
}

static int
app_group_db_cmp(struct cds_lfht_node *node, const void *key)
{
	struct agdb_entry *entry;
	entry = caa_container_of(node, struct agdb_entry, ht_node);

	return strcmp(entry->name, key);
}

struct agdb_entry *
app_group_db_find_or_alloc(const char *name)
{
	/* No name? No entry. */
	if (!name || !*name)
		return NULL;

	/* First, search for an existing entry. */
	struct agdb_entry *entry = app_group_db_find_name(name);
	if (entry) {
		/* Already exists, so return it */
		return entry;
	}

	/* Not found, so create a new DB entry. */
	entry = zmalloc_aligned(sizeof(struct agdb_entry));
	if (!entry)
		return NULL;

	entry->group = app_group_init();
	if (!entry->group) {
		free(entry);
		return NULL;
	}

	entry->name = strdup(name);
	if (!entry->name) {
		app_group_destroy(entry->group);
		free(entry);
		return NULL;
	}

	/* Add to app_grp hash table.
	 * Entries are hashed by name.
	 */
	cds_lfht_node_init(&entry->ht_node);
	unsigned long hash = rte_jhash(name, strlen(name), hash_seed);

	struct cds_lfht_node *node;
	node = cds_lfht_add_unique(app_grp_ht, hash, app_group_db_cmp, name,
				   &entry->ht_node);

	if (node != &entry->ht_node) {
		/* There's an existing entry that we didn't find earlier.
		 * So delete the new node and return the existing one.
		 */
		app_group_destroy(entry->group);
		free(entry);
		return caa_container_of(node, struct agdb_entry, ht_node);
	}

	return entry;
}
