/*
 * Copyright (c) 2017-2019,2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file npf_tblset.h
 * @brief API to managed table service
 *
 * Tables entries are created and deleted (using a name) from config on the
 * main thread, and may be looked-up from the dataplane forwarding threads
 * using a tableset handle and a table ID.
 *
 * Table entries are created via a named reference in config (e.g. firewall
 * address-group).  The hash is used to store the entry in a hash table.
 *
 * A table entry ID is assigned when an entry is created. This is the index
 * into an array.  The dataplane (e.g. firewall grouper) stores the entry ID
 * to allow fast lookup.
 *
 * RCU protection is in place for:
 *
 * 1. Setting the table array pointer, nt_table
 * 2. Freeing the table array memory, nt_table
 * 2. Setting table entry pointers
 * 3. Freeing table entry memory (rcu callback)
 *
 * The user is responsible for rcu-assigning their "struct npf_tbl" pointer.
 *
 * Changes to the hash table should only take place from the main thread.
 *
 * A table may be re-sized if it reaches its maximum size and the
 * TS_TBL_RESIZE flag is set.
 */

#ifndef NPF_TBLSET_H
#define NPF_TBLSET_H

#include <stdint.h>
#include <sys/types.h>

#include "util.h"

/*
 * Provide a common define for tblset clients (and their clients) to denote an
 * invalid table ID.
 */
#define NPF_TBLID_NONE UINT32_MAX

/*
 * User flags.
 *
 * TS_TBL_RESIZE Resize table when tables becomes full.  If the table size is
 * less than 1024 then it is doubled in size, else it is increased in size by
 * 1024 entries.  Both are subject to an absolute maximum of tbl_sz_max
 * entries.
 */
#define TS_TBL_RESIZE     0x01
#define TS_TBL_USER_MASK  0x0F

struct npf_tbl;

/**
 * @brief Create a table
 *
 * @param id          Optional user table ID
 * @param tbl_sz      Initial maximum table entries
 * @param tbl_sz_max  Maximum maximum table entries
 * @param data_sz     Size of per-entry user data
 * @return Pointer to table if successful, else NULL
 *
 * Example:
 *
 *	#define NPF_FOO_SZ     32
 *	#define NPF_FOO_SZ_MAX 1024
 *	struct npf_tbl *foo_tbl;
 *
 *	foo_tbl = npf_tbl_create(0, NPF_FOOTBL_SZ, NPF_FOO_SZ_MAX,
 *				sizeof(struct foo_tbl_entry),
 *				TS_TBL_RESIZE);
 *
 */
struct npf_tbl *npf_tbl_create(uint32_t id, uint tbl_sz, uint tbl_sz_max,
			       uint data_sz, uint8_t flags);

/**
 * @brief Destroy a table
 *
 * Table must be empty.  Use walk function to empty a table prior to
 * calling npf_tbl_destroy.
 *
 * @param nt Table handle
 * @return 0 if successful, else < 0
 *
 * Example:
 *
 *	if (npf_tbl_size(foo_tbl) == 0)
 *		npf_tbl_destroy(foo_tbl);
 */
int npf_tbl_destroy(struct npf_tbl *nt);

/**
 * @brief Get number of entries in a table
 *
 * @param nt Table handle
 * @return Number of items in the table
 *
 * Example:
 *
 *	uint nentries = npf_tbl_size(foo_tbl);
 */
uint npf_tbl_size(struct npf_tbl *nt);

/**
 * @brief Set entry free function
 *
 * Free or tidy client data
 */
typedef void (npf_tbl_entry_free_fn)(void *data);

void npf_tbl_set_entry_freefn(struct npf_tbl *nt,
			      npf_tbl_entry_free_fn *free_fn);


/**
 * @brief Create a table entry
 *
 * @param nt Table handle
 * @param name Name of entry. Must be unique
 * @return Returns pointer to user data object within the table entry
 *
 * Example:
 *
 *	struct foo_tbl_entry entry;
 *
 *	entry = npf_tbl_entry_create(foo_tbl, "FOO1");
 *	if (entry) {
 *		tid = npf_tbl_entry_insert(foo_tbl, entry);
 *		if (tid < 0) {
 *			npf_tbl_entry_destroy(entry);
 *			return;
 *		}
 *	}
 */
void *npf_tbl_entry_create(struct npf_tbl *nt, const char *name);

/**
 * @brief Destroy a table entry that is *not* in a table.
 *
 * Should only be used to destroy a table entry that has not been inserted
 * into a table
 *
 * @param td Pointer to entry data object within table entry
 * @return 0 if successful, else < 0
 *
 * Example:
 *
 *	tid = npf_tbl_entry_insert(foo_tbl, entry);
 *	if (tid < 0) {
 *		npf_tbl_entry_destroy(entry);
 *	}
 */
int npf_tbl_entry_destroy(void *td);

/**
 * @brief Insert entry into table.
 *
 * Will resize the table if there is no space and the resize flag is set.
 * Returns an index which (if equal to or greater than 0) may be used with
 * npf_tbl_id_lookup for fast lookup from forwarding thread.
 *
 * @param nt Table handle
 * @param td Pointer to entry data object within table entry
 * @param tid Pointer to the table ID allocated by this function.
 *            Set to NPF_TBLID_NONE if unsuccessful.
 * @return 0 if successful, less than 0 if unsuccessful
 */
int npf_tbl_entry_insert(struct npf_tbl *nt, void *td, uint32_t *tid);

/**
 * @brief Remove entry from table and destroy it
 *
 * Removes from hash table immediately, removes from index table via rcu,
 * and schedules entry for destruction via rcu callback.
 *
 * @param nt Table handle
 * @param td Pointer to entry data object within table entry
 * @return 0 if successfully removed from table and scheduled for rcu free.
 *
 * Example:
 *
 *	struct foo_tbl_entry *entry;
 *	...
 *	// Cleanup struct foo_tbl_entry here
 *
 *	if (npf_tbl_entry_remove(foo_tbl, entry) < 0) {
 *		// error
 *	}
 */
int npf_tbl_entry_remove(struct npf_tbl *nt, void *td);

/**
 * @brief Take reference on table entry
 */
void *npf_tbl_entry_get(void *td);

/**
 * @brief Release reference on table entry
 */
void npf_tbl_entry_put(void *td);

/**
 * @brief Table walk callback function
 *
 * @param name Entry name
 * @param id Entry ID
 * @param data Entry user data pointer
 * @param ctx User context
 * @return non-zero to stop, zero to continue
 */
typedef int (npf_tbl_walk_cb)(const char *name, uint id, void *data, void *ctx);

/**
 * @brief Walk all table entries
 *
 * @param nt Table handle
 * @param cb Callback function
 * @param ctx User context
 * @return zero if walk completed, non-zero if callback terminated the walk
 *
 * Example: Using walk function to destroy all entries in a table ...
 *
 *	int
 *	foo_tbl_destroy_cb(const char *name, int id, void *data, void *ctx) {
 *		struct foo_tbl_entry *entry = data;
 *		struct npf_tbl *tbl = ctx;
 *
 *		// Cleanup struct foo_tbl_entry here
 *
 *		if (npf_tbl_entry_remove(foo_tbl, entry) < 0)
 *			return -1;
 *		return 0;
 *	}
 *
 *	// 'ctx' is pointer to table
 *	npf_tbl_walk(foo_tbl, foo_tbl_destroy_cb, foo_tbl);
 *
 */
int npf_tbl_walk(struct npf_tbl *nt, npf_tbl_walk_cb *cb, void *ctx);

/**
 * @brief Get the table entry ID for a given name
 *
 * @param nt Table handle
 * @param name Table entry name
 * @return Table ID or NPF_TBLID_NONE if not found
 */
uint32_t npf_tbl_name2id(struct npf_tbl *nt, const char *name);

/**
 * @brief Get the table entry name for a given table entry ID
 *
 * @param nt Table handle
 * @param id Table entry ID
 * @return Table entry name or NULL if not found
 */
/* ID to name */
const char *npf_tbl_id2name(struct npf_tbl *nt, uint id);

/**
 * @brief Lookup a table entry by name
 *
 * @param nt Table handle
 * @param name Table entry name
 * @return Pointer to user data within table entry or NULL if not found
 */
void *npf_tbl_name_lookup(struct npf_tbl *nt, const char *name);

/**
 * @brief Lookup a table entry by ID
 *
 * This is the *only* tableset function that should be called from a
 * forwarding thread.
 *
 * @param nt Table handle
 * @param id Table entry ID
 * @return Pointer to user data within table entry or NULL if not found
 */
void *npf_tbl_id_lookup(struct npf_tbl *nt, uint id);

/**
 * @brief Is this table ID valid?
 *
 * May be called from a forwarding thread.
 *
 * @param id Table entry ID
 * @return true if valid, else false
 */
static ALWAYS_INLINE bool npf_tbl_id_is_valid(uint id)
{
	return id != NPF_TBLID_NONE;
}

#endif /* NPF_TBLSET_H */
