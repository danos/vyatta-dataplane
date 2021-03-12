/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef APP_GROUP_DB_H
#define APP_GROUP_DB_H

#include <stdbool.h>
#include <stdint.h>
#include "json_writer.h"
#include "app_group.h"
#include "urcu.h"

/* Application group database entry. */
struct agdb_entry {
	char *name;				/* Name string */
	struct app_group *group;		/* Application group */
	uint32_t refcount;			/* Refcount */
	struct cds_lfht_node ht_node;		/* Group hash table */
	struct cds_list_head deadlist;		/* Memento mori */
	bool is_dead;
};

typedef int (*app_grp_walker_t)(void *ctx, struct agdb_entry *entry);

/**
 * Initialise the application resource group database.
 *
 * @return true on success; false on failure.
 */
bool app_group_db_init(void);

/**
 * Decrement the given appDB entry's refcount.
 * If zero then remove the entry from the appDB.
 *
 * @param entry pointer to the appDB entry to be decremented.
 * @return true on success; false on failure.
 */
bool app_group_db_rm_entry(struct agdb_entry *entry);

/**
 * Lookup the given application resource group name
 * in the application resource group database.
 *
 * @param name entry name to be looked up.
 * @return pointer to the new appDB entry, or NULL on failure.
 */
struct agdb_entry *app_group_db_find_name(const char *name);

/**
 * Find an existing appDB entry with the given name and increment its refcount.
 * If not found, then create a new entry.
 *
 * @param name entry name to be looked up or created.
 * @return pointer to the new appDB entry, or NULL on failure.
 */
struct agdb_entry *app_group_db_find_or_alloc(const char *name);

#endif /* APP_GROUP_DB_H */
