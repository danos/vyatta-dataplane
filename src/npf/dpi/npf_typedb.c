/*
 * Copyright (c) 2020 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Application type database.
 */

#include <rte_jhash.h>
#include "npf/config/npf_config.h"
#include "npf/dpi/dpi_internal.h"
#include "npf/dpi/npf_typedb.h"

#define TYPE_NAME_HT_SIZE	32
#define TYPE_NAME_HT_MIN	32
#define TYPE_NAME_HT_MAX	8192
#define TYPE_NAME_HT_FLAGS	(CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

#define TYPE_ID_HT_SIZE		32
#define TYPE_ID_HT_MIN		32
#define TYPE_ID_HT_MAX		8192
#define TYPE_ID_HT_FLAGS	(CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

/* Type database entry. */
struct tdb_entry {
	char *te_name;				/* Name string */
	uint32_t te_id;				/* Type ID */
	uint32_t te_refcount;			/* Refcount */
	struct cds_lfht_node te_name_ht_node;	/* Type name hash table */
	struct cds_lfht_node te_id_ht_node;	/* Type ID hash table */
	struct rcu_head t_rcu_head;
};

/* Application database hash tables. Appls are hashed by name and by ID. */
static struct cds_lfht *type_name_ht;	/* Hash table of type names */
static struct cds_lfht *type_id_ht;	/* Hash table of type IDs */

static uint32_t name_hash_seed;

/*
 * Match function for the type name hash table.
 * Returns zero for a non-match, and non-zero for a match.
 */
static int
typedb_name_match(struct cds_lfht_node *ht_node, const void *data)
{
	struct tdb_entry *entry = caa_container_of(ht_node, struct tdb_entry,
						   te_name_ht_node);

	return !strcmp(data, entry->te_name);
}

/*
 * Lookup the given type name in the type DB.
 * Return a pointer to the entry, or NULL if not found.
 */
static struct tdb_entry *
typedb_find_name(const char *name)
{
	struct cds_lfht_iter iter;
	unsigned long hash = rte_jhash(name, strlen(name),
				       name_hash_seed);

	if (!type_name_ht)
		return NULL;

	cds_lfht_lookup(type_name_ht, hash, typedb_name_match, name, &iter);

	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);

	if (ht_node)
		return caa_container_of(ht_node, struct tdb_entry,
					te_name_ht_node);
	else
		return NULL;
}

/*
 * Match function for the type id hash table.
 * Returns zero for a non-match, and non-zero for a match.
 */
static int
typedb_id_match(struct cds_lfht_node *ht_node, const void *data)
{
	struct tdb_entry *entry = caa_container_of(ht_node, struct tdb_entry,
						   te_id_ht_node);
	const uint32_t *id = data;

	return *id == entry->te_id;
}

/*
 * Lookup the given type ID in the type DB.
 * Return a pointer to the entry, or NULL if not found.
 */
static struct tdb_entry *
typedb_find_id(uint32_t type_id)
{
	struct cds_lfht_iter iter;
	unsigned long hash = type_id;

	if (!type_id_ht)
		return NULL;

	cds_lfht_lookup(type_id_ht, hash, typedb_id_match, &type_id, &iter);

	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);

	if (ht_node)
		return caa_container_of(ht_node, struct tdb_entry,
					te_id_ht_node);
	else
		return NULL;
}

int
typedb_init(void)
{
	if (type_name_ht && type_id_ht)
		/* Already init'd. */
		return 0;

	type_name_ht = cds_lfht_new(TYPE_NAME_HT_SIZE,
				   TYPE_NAME_HT_MIN,
				   TYPE_NAME_HT_MAX,
				   TYPE_NAME_HT_FLAGS,
				   NULL);

	if (!type_name_ht)
		return -ENOMEM;

	type_id_ht = cds_lfht_new(TYPE_ID_HT_SIZE,
				 TYPE_ID_HT_MIN,
				 TYPE_ID_HT_MAX,
				 TYPE_ID_HT_FLAGS,
				 NULL);

	if (!type_id_ht) {
		cds_lfht_destroy(type_name_ht, NULL);
		type_name_ht = NULL;
		return -ENOMEM;
	}

	name_hash_seed = random();
	return 0;
}

/*
 * Return the type ID from the given tdb_entry
 */
uint32_t
typedb_entry_get_id(struct tdb_entry *e)
{
	if (e)
		return e->te_id;

	return DPI_APP_TYPE_NONE;
}

/*
 * Lookup the given type name in the type DB.
 * Return the type ID, or DPI_APP_TYPE_NONE if not found.
 */
uint32_t
typedb_name_to_id(const char *name)
{
	struct tdb_entry *entry = typedb_find_name(name);

	return entry ? entry->te_id : DPI_APP_TYPE_NONE;
}

/*
 * Lookup the given type ID in the type DB.
 * Return the type name, or NULL if not found.
 */
const char *
typedb_id_to_name(uint32_t type_id)
{
	if (type_id == DPI_APP_TYPE_NONE)
		return (char *)"None";

	struct tdb_entry *entry = typedb_find_id(type_id);

	return entry ? entry->te_name : NULL;
}

static struct tdb_entry *
typedb_add(const char *name, uint32_t id)
{
	struct tdb_entry *entry = zmalloc_aligned(sizeof(struct tdb_entry));
	if (!entry)
		return NULL;

	entry->te_name = strdup(name);
	if (!entry->te_name) {
		free(entry);
		return NULL;
	}

	entry->te_id = id;
	entry->te_refcount = 1;

	/* Add to type name hash table. */
	cds_lfht_node_init(&entry->te_name_ht_node);

	/* Make an aligned copy of 'name' that we can hash on. */
	char __name[RTE_ALIGN(strlen(name), 4)]
		__rte_aligned(sizeof(uint32_t));

	memcpy(__name, name, strlen(name));
	unsigned long name_hash = rte_jhash(__name, strlen(name),
					    name_hash_seed);
	cds_lfht_add(type_name_ht, name_hash, &entry->te_name_ht_node);

	/* Add to type ID hash table. */
	cds_lfht_node_init(&entry->te_id_ht_node);
	cds_lfht_add(type_id_ht, entry->te_id, &entry->te_id_ht_node);

	return entry;
}

/*
 * Find an existing type DB entry with the given name and increment its
 * refcount. If not found, then create a new entry.
 */
struct tdb_entry *
typedb_find_or_alloc(const char *name)
{
	static uint32_t user_type_id = DPI_APP_BASE;

	/* No name? No entry. */
	if ((!name) || (!*name))
		return NULL;

	/* First, search for an existing entry. */
	struct tdb_entry *entry = typedb_find_name(name);
	if (entry) {
		/* We only need to bump the refcount
		 * for an existing entry.
		 */
		entry->te_refcount++;
		return entry;
	}

	/* Not found, so we need to create a new type DB entry. */

	if (user_type_id == 0)
		/* All the IDs have been consumed. */
		return NULL;

	return typedb_add(name, user_type_id++);
}

/*
 * Free the DB entry. Called from RCU callback.
 */
static void typedb_entry_free(struct rcu_head *head)
{
	struct tdb_entry *entry = caa_container_of(head, struct tdb_entry,
						   t_rcu_head);

	free(entry->te_name);
	free(entry);
}

/*
 * Decrement the given type DB entry's refcount.
 * If zero then remove the entry from the typeDB.
 */
bool
typedb_dealloc(struct tdb_entry *entry)
{
	if (!entry)
		return false;

	if (--entry->te_refcount == 0) {
		cds_lfht_del(type_name_ht, &entry->te_name_ht_node);
		cds_lfht_del(type_id_ht, &entry->te_id_ht_node);
		call_rcu(&entry->t_rcu_head, typedb_entry_free);
	}

	return true;
}
