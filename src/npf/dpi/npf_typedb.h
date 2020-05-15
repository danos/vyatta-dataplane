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
 * Returns true on success.
 */
bool typedb_init(void);

/**
 * Destroy the type database.
 */
void typedb_destroy(void);

/**
 * Write the JSON representation of the type database name entry, given
 * with the data pointer.
 * Intended for use with typedb_name_walk. Therefore, returns 0 on success.
 */
int typedb_name_entry_to_json(json_writer_t *json, struct tdb_entry *entry);

/**
 * Walk the type database name entries.
 */
int typedb_name_walk(json_writer_t *json, type_walker_t *callback);

/*
 * Lookup the given type name in the type DB.
 * Return the type ID, or DPI_TYPE_NA if not found.
 */
uint32_t typedb_name_to_id(const char *name);

/**
 * Write the JSON representation of the type database ID entry, given
 * with the data pointer.
 * Intended for use with typedb_id_walk. Therefore, returns 0 on success.
 */
int typedb_id_entry_to_json(json_writer_t *json, struct tdb_entry *entry);

/**
 * Walk the type database ID entries.
 */
int typedb_id_walk(json_writer_t *json, type_walker_t *callback);

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
