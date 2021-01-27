/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Application resource group database.
 */

#include <rte_jhash.h>
#include "npf/config/npf_config.h"
#include "npf/dpi/dpi_internal.h"
#include "app_group_db.h"

#define APP_GRP_NAME_HT_SIZE	32
#define APP_GRP_NAME_HT_MIN	32
#define APP_GRP_NAME_HT_MAX	8192
#define APP_GRP_NAME_HT_FLAGS	(CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

/* Application resource group database hash table. */
static struct cds_lfht *app_grp_ht;

static uint32_t hash_seed;

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
	return true;
}

static void
ag_entry_free(struct rcu_head *head)
{
	struct agdb_entry *entry;
	entry = caa_container_of(head, struct agdb_entry, rcu);

	free(entry);
}

bool
app_group_db_rm_entry(struct agdb_entry *entry)
{
	if (!entry)
		return false;

	cds_lfht_del(app_grp_ht, &entry->ht_node);
	app_group_destroy(entry->group);
	call_rcu(&entry->rcu, ag_entry_free);

	return true;
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
