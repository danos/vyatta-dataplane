/*
 * Copyright (c) 2020 AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_APPDB_H
#define NPF_APPDB_H

#include <stdbool.h>
#include <stdint.h>
#include "json_writer.h"

/**
 * Walker prototype.
 */
struct adb_entry;
typedef int (app_walker_t)(json_writer_t *json, struct adb_entry *entry);

/**
 * Initialise the application database.
 * Returns 0 on success; errno on failure.
 */
int appdb_init(void);

/**
 * Destroy the application database.
 */
void appdb_destroy(void);

/**
 * Write the JSON representation of the application database name entry, given
 * with the data pointer.
 * Intended for use with appdb_name_walk. Therefore, returns 0 on success.
 */
int appdb_name_entry_to_json(json_writer_t *json, struct adb_entry *entry);

/**
 * Walk the application database name entries.
 */
int appdb_name_walk(json_writer_t *json, app_walker_t *callback);

/*
 * Lookup the given application name in the application DB.
 * Return the application ID, or DPI_APP_NA if not found.
 */
uint32_t appdb_name_to_id(const char *name);

/**
 * Write the JSON representation of the application database ID entry, given
 * with the data pointer.
 * Intended for use with appdb_id_walk. Therefore, returns 0 on success.
 */
int appdb_id_entry_to_json(json_writer_t *json, struct adb_entry *entry);

/**
 * Walk the application database ID entries.
 */
int appdb_id_walk(json_writer_t *json, app_walker_t *callback);

/*
 * Lookup the given application ID in the application DB.
 * Return the application name, or NULL if not found.
 */
const char *appdb_id_to_name(uint32_t app_id);

/*
 * Find an existing app DB entry with the given name and increment its
 * refcount. If not found, then create a new entry.
 */
struct adb_entry *appdb_find_or_alloc(const char *name);

/*
 * Decrement the given appDB entry's refcount.
 * If zero then remove the entry from the appDB.
 */
bool appdb_dealloc(struct adb_entry *entry);

/**
 * Return the application ID from the given adb_entry,
 * or return DPI_APP_USER_NA if the given entry doesn't exist.
 */
uint32_t appdb_entry_get_id(struct adb_entry *e);

#endif /* NPF_APPDB_H */
