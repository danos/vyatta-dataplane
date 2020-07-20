/*
 * Copyright (c) 2020 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Application name database.
 */

#include <rte_jhash.h>
#include "npf/config/npf_config.h"
#include "npf/dpi/dpi_internal.h"
#include "dpi/npf_appdb.h"

#define APP_NAME_HT_SIZE	32
#define APP_NAME_HT_MIN		32
#define APP_NAME_HT_MAX		8192
#define APP_NAME_HT_FLAGS	(CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

#define APP_ID_HT_SIZE		32
#define APP_ID_HT_MIN		32
#define APP_ID_HT_MAX		8192
#define APP_ID_HT_FLAGS		(CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

/* Application database entry. */
struct adb_entry {
	char *ae_name;				/* Name string */
	uint32_t ae_id;				/* Application ID */
	uint32_t ae_refcount;			/* Refcount */
	struct cds_lfht_node ae_name_ht_node;	/* App name hash table */
	struct cds_lfht_node ae_id_ht_node;	/* App ID hash table */
	struct rcu_head e_rcu_head;
};

/* Application database hash tables. Appls are hashed by name and by ID. */
static struct cds_lfht *app_name_ht;	/* Hash table of application names */
static struct cds_lfht *app_id_ht;	/* Hash table of application IDs */

static uint32_t name_hash_seed;

static struct adb_entry *appdb_add(const char *name, uint32_t id);

/*
 * Match function for the app name hash table.
 * Returns zero for a non-match, and non-zero for a match.
 */
static int
appdb_name_match(struct cds_lfht_node *ht_node, const void *data)
{
	struct adb_entry *entry = caa_container_of(ht_node, struct adb_entry,
						   ae_name_ht_node);

	return !strcmp(data, entry->ae_name);
}

/*
 * Lookup the given application name in the application DB.
 * Return a pointer to the entry, or NULL if not found.
 */
static struct adb_entry *
appdb_find_name(const char *name)
{
	struct cds_lfht_iter iter;
	unsigned long hash = rte_jhash(name, strlen(name),
				       name_hash_seed);

	if (!app_name_ht)
		return NULL;

	cds_lfht_lookup(app_name_ht, hash, appdb_name_match, name, &iter);

	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);

	if (ht_node)
		return caa_container_of(ht_node, struct adb_entry,
					ae_name_ht_node);
	else
		return NULL;
}

/*
 * Match function for the app id hash table.
 * Returns zero for a non-match, and non-zero for a match.
 */
static int
appdb_id_match(struct cds_lfht_node *ht_node, const void *data)
{
	struct adb_entry *entry = caa_container_of(ht_node, struct adb_entry,
						   ae_id_ht_node);
	const uint32_t *id = data;

	return *id == entry->ae_id;
}

/*
 * Lookup the given application ID in the application DB.
 * Return a pointer to the entry, or NULL if not found.
 */
static struct adb_entry *
appdb_find_id(uint32_t app_id)
{
	struct cds_lfht_iter iter;
	unsigned long hash = app_id;

	if (!app_id_ht)
		return NULL;

	cds_lfht_lookup(app_id_ht, hash, appdb_id_match, &app_id, &iter);

	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);

	if (ht_node)
		return caa_container_of(ht_node, struct adb_entry,
					ae_id_ht_node);
	else
		return NULL;
}

int
appdb_init(void)
{
	if (app_name_ht && app_id_ht)
		/* Already init'd. */
		return 0;

	app_name_ht = cds_lfht_new(APP_NAME_HT_SIZE,
				   APP_NAME_HT_MIN,
				   APP_NAME_HT_MAX,
				   APP_NAME_HT_FLAGS,
				   NULL);

	if (!app_name_ht)
		return -ENOMEM;

	app_id_ht = cds_lfht_new(APP_ID_HT_SIZE,
				 APP_ID_HT_MIN,
				 APP_ID_HT_MAX,
				 APP_ID_HT_FLAGS,
				 NULL);

	if (!app_id_ht) {
		cds_lfht_destroy(app_name_ht, NULL);
		app_name_ht = NULL;
		return -ENOMEM;
	}

	/* Add default entries. */
	appdb_add("Unavailable", DPI_APP_USER_NA);
	appdb_add("Error", DPI_APP_USER_ERROR);
	appdb_add("Unknown", DPI_APP_USER_UNDETERMINED);

	name_hash_seed = random();
	return 0;
}

void
appdb_destroy(void)
{
	if (app_name_ht)
		cds_lfht_destroy(app_name_ht, NULL);

	if (app_id_ht)
		cds_lfht_destroy(app_id_ht, NULL);

	app_name_ht = NULL;
	app_id_ht = NULL;
}

/*
 * Return the application ID from the given adb_entry.
 */
uint32_t
appdb_entry_get_id(struct adb_entry *e)
{
	if (e)
		return e->ae_id;

	return DPI_APP_USER_NA;
}

/*
 * Convert the given app DB name entry to JSON.
 * This is a callback from appdb_name_walk.
 */
int
appdb_name_entry_to_json(json_writer_t *json, struct adb_entry *entry)
{
	char buf[11]; /* "id" is u32. "0x" + 8 digits + null = 11. */

	jsonw_name(json, entry->ae_name);
	jsonw_start_object(json);
	snprintf(buf, sizeof(buf), "%#x", entry->ae_id);
	jsonw_string_field(json, "id", buf);
	jsonw_uint_field(json, "refcount", entry->ae_refcount);
	jsonw_end_object(json);

	/* Tell the walker to continue. */
	return 0;
}

/*
 * Walk the app name hash.
 */
int
appdb_name_walk(json_writer_t *json, app_walker_t *callback)
{
	struct cds_lfht_iter iter;
	struct adb_entry *entry;
	int rc = 0;

	if (!app_name_ht)
		return rc;

	cds_lfht_for_each_entry(app_name_ht, &iter, entry, ae_name_ht_node) {
		rc = callback(json, entry);
		if (rc)
			break;
	}

	return rc;
}

/*
 * Lookup the given application name in the application DB.
 * Return the application ID, or DPI_APP_NA if not found.
 */
uint32_t
appdb_name_to_id(const char *name)
{
	struct adb_entry *entry = appdb_find_name(name);

	return entry ? entry->ae_id : DPI_APP_NA;
}

/* Convert the given app DB ID entry to JSON.
 * This is a callback from appdb_id_walk.
 */
int
appdb_id_entry_to_json(json_writer_t *json, struct adb_entry *entry)
{
	char buf[11]; /* "id" is u32. "0x" + 8 digits + null = 11. */

	snprintf(buf, sizeof(buf), "%#x", entry->ae_id);
	jsonw_name(json, buf);
	jsonw_start_object(json);
	jsonw_string_field(json, "name", entry->ae_name);
	jsonw_uint_field(json, "refcount", entry->ae_refcount);
	jsonw_end_object(json);

	/* Tell the walker to continue. */
	return 0;
}

/* Walk the app ID hash. */
int
appdb_id_walk(json_writer_t *json, app_walker_t *callback)
{
	struct cds_lfht_iter iter;
	struct adb_entry *entry;
	int rc = 0;

	if (!app_id_ht)
		return rc;

	cds_lfht_for_each_entry(app_id_ht, &iter, entry, ae_id_ht_node) {
		rc = callback(json, entry);
		if (rc)
			break;
	}

	return rc;
}

/*
 * Lookup the given application ID in the application DB.
 * Return the application name, or NULL if not found.
 */
const char *
appdb_id_to_name(uint32_t app_id)
{
	struct adb_entry *entry = appdb_find_id(app_id);

	return entry ? entry->ae_name : NULL;
}

static struct adb_entry *
appdb_add(const char *name, uint32_t id)
{
	struct adb_entry *entry = zmalloc_aligned(sizeof(struct adb_entry));
	if (!entry)
		return NULL;

	entry->ae_name = strdup(name);
	if (!entry->ae_name) {
		free(entry);
		return NULL;
	}

	entry->ae_id = id;
	entry->ae_refcount = 1;

	/* Add to app name hash table. */
	cds_lfht_node_init(&entry->ae_name_ht_node);
	unsigned long name_hash = rte_jhash(name, strlen(name),
					    name_hash_seed);
	cds_lfht_add(app_name_ht, name_hash, &entry->ae_name_ht_node);

	/* Add to app ID hash table. */
	cds_lfht_node_init(&entry->ae_id_ht_node);
	cds_lfht_add(app_id_ht, entry->ae_id, &entry->ae_id_ht_node);

	return entry;
}

/*
 * Find an existing app DB entry with the given name and increment its refcount.
 * If not found, then create a new entry.
 */
struct adb_entry *
appdb_find_or_alloc(const char *name)
{
	static uint32_t user_app_id = DPI_APP_USER_BASE;

	/* No name? No entry. */
	if ((!name) || (!*name))
		return NULL;

	/* First, search for an existing entry. */
	struct adb_entry *entry = appdb_find_name(name);
	if (entry) {
		/* We only need to bump the refcount
		 * for an existing entry.
		 */
		entry->ae_refcount++;
		return entry;
	}

	/* Not found, so we need to create a new app DB entry. */

	if (user_app_id == 0)
		/* All the IDs have been consumed. */
		return NULL;

	return appdb_add(name, user_app_id++);
}

/*
 * Free the DB entry. Called from RCU callback.
 */
static void
appdb_entry_free(struct rcu_head *head)
{
	struct adb_entry *entry = caa_container_of(head, struct adb_entry,
						   e_rcu_head);

	free(entry->ae_name);
	free(entry);
}

/*
 * Decrement the given appDB entry's refcount.
 * If zero then remove the entry from the appDB.
 */
bool
appdb_dealloc(struct adb_entry *entry)
{
	if (!entry)
		return false;

	if (--entry->ae_refcount == 0) {
		cds_lfht_del(app_name_ht, &entry->ae_name_ht_node);
		cds_lfht_del(app_id_ht, &entry->ae_id_ht_node);
		call_rcu(&entry->e_rcu_head, appdb_entry_free);
	}

	return true;
}
