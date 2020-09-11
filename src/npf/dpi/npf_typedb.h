/*
 * Copyright (c) 2020 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_TYPEDB_H
#define NPF_TYPEDB_H

#include <stdbool.h>
#include <stdint.h>
#include "json_writer.h"

/**
 * Walker prototype.
 */
struct tdb_entry;
typedef int (type_walker_t)(json_writer_t *json, struct tdb_entry *entry);

/**
 * Initialise the type database.
 * Returns zero on success; errno on failure.
 */
int typedb_init(void);

/*
 * Lookup the given type name in the type DB.
 * Return the type ID, or DPI_TYPE_NA if not found.
 */
uint32_t typedb_name_to_id(const char *name);

/*
 * Lookup the given type ID in the type DB.
 * Return the type name, or NULL if not found.
 */
const char *typedb_id_to_name(uint32_t type_id);

/*
 * Find an existing type DB entry with the given name and increment its
 * refcount. If not found, then create a new entry.
 */
struct tdb_entry *typedb_find_or_alloc(const char *name);

/*
 * Decrement the given typeDB entry's refcount.
 * If zero then remove the entry from the typeDB.
 */
bool typedb_dealloc(struct tdb_entry *entry);

/**
 * Return the type ID from the given tdb_entry,
 * or return DPI_APP_TYPE_NONE if the given entry doesn't exist.
 */
uint32_t typedb_entry_get_id(struct tdb_entry *e);

#endif /* NPF_TYPEDB_H */
