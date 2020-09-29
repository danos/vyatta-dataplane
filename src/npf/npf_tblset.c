/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <assert.h>
#include <czmq.h>
#include <errno.h>
#include <rte_branch_prediction.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <urcu/uatomic.h>

#include "npf_tblset.h"
#include "urcu.h"
#include "util.h"

/*
 * Managed table service.
 *
 * Tables entries are created and deleted (using a name) from config on the
 * main thread, and may be looked-up from the dataplane forwarding threads
 * using a tableset handle and a table ID.
 *
 * Table entries are created via a named reference in config (e.g. firewall
 * address-group).  The hash is used to store the entry in a table.
 *
 * A table entry ID is assigned when an entry is created. This is the index
 * into an array.  The dataplane (e.g. firewall bytecode) stores the entry ID
 * to allow fast lookup.
 *
 * RCU protection is in place for:
 *
 * 1. Setting the table array pointer, nt_table
 * 2. Freeing the table array memory,
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


/*
 * Table entry
 *
 * te_tbl is set when the entry is inserted into a table, and unset when it is
 * removed from a table.
 *
 * te_memguard is used to verify that a pointer to te_data is actually within
 * a table entry.
 */
struct npf_tbl_entry {
	char            *te_name;	/* entry name */
	struct rcu_head  te_rcu;	/* rcu for freeing an entry */
	struct npf_tbl  *te_tbl;	/* back pointer to table */
	uint32_t         te_id;		/* ID/index */
	rte_atomic32_t   te_refcnt;
	npf_tbl_entry_free_fn *te_free_fn;
#ifndef NDEBUG
	uint32_t         te_memguard;	/* used to verify te_data ptr */
#endif
	uint8_t          te_data[0];	/* user data */
};

#define TS_MEMGUARD 0xDEADBEEF
#define TS_RESIZE_INCR_MAX 1024

/*
 * Table
 */
struct npf_tbl {
	struct npf_tbl_entry **nt_table;
	zhash_t               *nt_hash;
	struct rcu_head        nt_rcu;	/* rcu for freeing struct npf_tbl */
	uint8_t                nt_flags;
	uint32_t               nt_id;   /* user table id */
	npf_tbl_entry_free_fn  *nt_entry_free_fn;
	/* Start search for next available table index at nt_hint */
	uint                   nt_hint; /* used to find a free slot */
	uint                   nt_entry_data_sz; /* size of te_data */
	uint                   nt_sz;     /* cur max entries */
	uint                   nt_sz_max; /* absolute max entries */
	uint                   nt_nentries; /* number of entries */
};

/*
 * The TS_TBL_ACTIVE will only ever be clear when a table is waiting for
 * call_rcu callback to free it.
 */
#define TS_TBL_ACTIVE  0x10

/*
 * Get table entry pointer from user data pointer
 */
static struct npf_tbl_entry *npf_tbl_data2entry(void *data)
{
	struct npf_tbl_entry *te;

	if (!data)
		return NULL;

	te = caa_container_of(data, struct npf_tbl_entry, te_data);

	assert(te->te_memguard == TS_MEMGUARD);

	return te;
}

/*
 * Short lived structure used to rcu-free an nt_table array
 */
struct npf_tbl_rcu {
	struct rcu_head        tr_rcu;
	struct npf_tbl_entry **tr_table;
};

static void
npf_tbl_table_free_rcu(struct rcu_head *head)
{
	struct npf_tbl_rcu *tr;

	tr = caa_container_of(head, struct npf_tbl_rcu, tr_rcu);

	free(tr->tr_table);
	free(tr);
}

/*
 * RCU assign nt->nt_table pointer; and free old table if one exists
 */
static void
npf_tbl_table_rcu_assign(struct npf_tbl *nt, struct npf_tbl_entry **ptr)
{
	struct npf_tbl_rcu *tr = NULL;

	if (nt->nt_table) {
		/*
		 * If we fail to malloc tr then we will leak the old table
		 * memory.  There is no good way to recover for this.  However
		 * if that ever happens then the box is likely unusable
		 * anyway.
		 */
		tr = malloc(sizeof(*tr));
		if (tr)
			tr->tr_table = nt->nt_table;
	}

	rcu_assign_pointer(nt->nt_table, ptr);

	if (tr)
		call_rcu(&tr->tr_rcu, npf_tbl_table_free_rcu);
}

/*
 * Create a table
 */
struct npf_tbl *
npf_tbl_create(uint32_t id, uint tbl_sz, uint tbl_sz_max, uint data_sz,
	       uint8_t flags)
{
	struct npf_tbl_entry **table;
	struct npf_tbl *nt;

	if (tbl_sz == 0 || data_sz == 0)
		return NULL;

	/* table container */
	nt = zmalloc_aligned(sizeof(*nt));
	if (!nt)
		return NULL;

	/* table */
	table = zmalloc_aligned(tbl_sz * sizeof(void *));
	if (!table) {
		free(nt);
		return NULL;
	}

	nt->nt_hash = zhash_new();
	if (!nt->nt_hash) {
		free(table);
		free(nt);
		return NULL;
	}

	nt->nt_id = id;
	nt->nt_entry_data_sz = data_sz;
	nt->nt_sz = tbl_sz;
	nt->nt_sz_max = MAX(nt->nt_sz, tbl_sz_max);
	nt->nt_flags = TS_TBL_ACTIVE | (flags & TS_TBL_USER_MASK);

	/* rcu assign nt->nt_table */
	npf_tbl_table_rcu_assign(nt, table);

	return nt;
}

void npf_tbl_set_entry_freefn(struct npf_tbl *nt,
			      npf_tbl_entry_free_fn *free_fn)
{
	nt->nt_entry_free_fn = free_fn;
}

static void
npf_tbl_destroy_rcu(struct rcu_head *head)
{
	struct npf_tbl *nt;

	nt = caa_container_of(head, struct npf_tbl, nt_rcu);

	assert(nt->nt_table == NULL);
	free(nt);
}

/*
 * Destroy all table entries
 */
static int npf_tbl_destroy_entries(struct npf_tbl *nt)
{
	struct npf_tbl_entry *te;
	uint i;
	int rc = 0;

	for (i = 0; i < nt->nt_sz; i++) {
		te = nt->nt_table[i];
		if (te) {
			rc = npf_tbl_entry_remove(nt, te->te_data);
			if (rc)
				return rc;
		}
	}
	return 0;
}

/*
 * Destroy table.
 */
int
npf_tbl_destroy(struct npf_tbl *nt)
{
	if (!nt)
		return -EINVAL;

	/* Delete and free all table entries */
	npf_tbl_destroy_entries(nt);

	/* Table must be empty */
	if (nt->nt_nentries != 0)
		return -EEXIST;

	/* Do not destroy twice */
	if ((nt->nt_flags & TS_TBL_ACTIVE) == 0)
		return 0;

	nt->nt_flags &= ~TS_TBL_ACTIVE;

	zhash_destroy(&nt->nt_hash);

	/* rcu free nt_table */
	npf_tbl_table_rcu_assign(nt, NULL);

	/* rcu free of nt */
	call_rcu(&nt->nt_rcu, npf_tbl_destroy_rcu);

	return 0;
}

/*
 * Number of entries in the table
 */
uint npf_tbl_size(struct npf_tbl *nt)
{
	if (nt)
		return nt->nt_nentries;
	return 0;
}

/*
 * Resize a table
 *
 * If TS_TBL_RESIZE flag is set, then resize table when tables becomes full.
 * If the table size is less than 1024 then it is doubled in size, else it is
 * increased in size by 1024 entries.  Both are subject to an absolute maximum
 * of nt_sz_max entries.
 */
static int npf_tbl_resize(struct npf_tbl *nt)
{
	struct npf_tbl_entry **old, **new;
	uint i, new_sz;

	if ((nt->nt_flags & TS_TBL_RESIZE) == 0 ||
	    nt->nt_sz == nt->nt_sz_max)
		return -ENOSPC;

	/* Double in size up until 1024 entries, then increase by 1024 */
	new_sz = nt->nt_sz + MIN(nt->nt_sz, TS_RESIZE_INCR_MAX);

	/* But dont exceed the absolute maximum, nt_sz_max */
	new_sz = MIN(new_sz, nt->nt_sz_max);

	/* Allocate new table */
	new = zmalloc_aligned(new_sz * sizeof(void *));
	if (!new)
		return -ENOMEM;

	/* Copy across existing entries */
	old = nt->nt_table;

	for (i = 0; i < nt->nt_sz; i++)
		new[i] = old[i];

	/* rcu assign new nt_table, and rcu free old table */
	npf_tbl_table_rcu_assign(nt, new);

	/* finally make new space visible */
	nt->nt_sz = new_sz;

	return 0;
}

/*
 * Find a free slot in the table.
 *
 * We start looking at 'hint' entry.  This starts at 0 when the table is first
 * created, and is set to the next slot when a slot filled.  Except when a
 * slot is emptied, in which case 'hint' becomes the lower of the current
 * 'hint' and the newly emptied slot.
 *
 * Returns 0 for success, or less thanb 0 for error.
 */
static int
npf_tbl_entry_id_alloc(struct npf_tbl *nt, uint32_t hint, uint32_t *id)
{
	uint32_t i, tmp = hint;

	if (nt->nt_nentries >= nt->nt_sz)
		return -ENOSPC;

	for (i = 0; i < nt->nt_sz; i++) {
		if (!nt->nt_table[tmp]) {
			/* Empty slot found */
			*id = tmp;
			return 0;
		}

		if (++tmp >= nt->nt_sz)
			tmp = 0;
	}

	/* should never get here if nt_nentries is accurate */
	assert(false);

	/* No free slots */
	return -ENOSPC;
}

/*
 * Create a named table entry.  Return pointer to the user data.
 */
void *
npf_tbl_entry_create(struct npf_tbl *nt, const char *name)
{
	struct npf_tbl_entry *te;

	te = zmalloc_aligned(sizeof(*te) + nt->nt_entry_data_sz);
	if (!te)
		return NULL;

	te->te_name = strdup(name);
	rte_atomic32_set(&te->te_refcnt, 0);
	te->te_free_fn = nt->nt_entry_free_fn;
#ifndef NDEBUG
	te->te_memguard = TS_MEMGUARD;
#endif

	return te->te_data;
}

/*
 * There are two paths from which a table entries is freed.  Path #1 is for an
 * entry that was successfully added to a table.
 *
 * Path #1:
 *
 * npf_tbl_entry_remove -> zhash_delete -> npf_tbl_zhash_delete_cb
 *   -> call_rcu -> npf_tbl_entry_free_rcu -> _npf_tbl_entry_destroy
 *
 * Path #2:
 *
 * npf_tbl_entry_destroy -> _npf_tbl_entry_destroy
 */
static int
_npf_tbl_entry_destroy(struct npf_tbl_entry *te)
{
	/* do not destroy an entry if it is still in a table */
	if (!te || te->te_tbl)
		return -EINVAL;

	/* Let client cleanup its data first */
	if (te->te_free_fn)
		(*te->te_free_fn)(te->te_data);

	if (te->te_name)
		free(te->te_name);

	free(te);
	return 0;
}

/*
 * Should only be called by the user if an entry failed to be inserted into
 * the table.
 */
int npf_tbl_entry_destroy(void *td)
{
	struct npf_tbl_entry *te;

	te = npf_tbl_data2entry(td);
	if (!te)
		return -EINVAL;

	return _npf_tbl_entry_destroy(te);
}

static void
npf_tbl_entry_free_rcu(struct rcu_head *head)
{
	struct npf_tbl_entry *te;

	te = caa_container_of(head, struct npf_tbl_entry, te_rcu);

	/* Destroy */
	_npf_tbl_entry_destroy(te);
}

/*
 * Take reference on table entry
 */
static struct npf_tbl_entry *_npf_tbl_entry_get(struct npf_tbl_entry *te)
{
	if (te)
		rte_atomic32_inc(&te->te_refcnt);
	return te;
}

void *npf_tbl_entry_get(void *td)
{
	struct npf_tbl_entry *te;

	te = npf_tbl_data2entry(td);
	if (!te)
		return NULL;

	_npf_tbl_entry_get(te);
	return td;
}

/*
 * Release reference on table entry
 */
static void _npf_tbl_entry_put(struct npf_tbl_entry *te)
{
	if (te && rte_atomic32_dec_and_test(&te->te_refcnt))
		call_rcu(&te->te_rcu, npf_tbl_entry_free_rcu);
}

void npf_tbl_entry_put(void *td)
{
	struct npf_tbl_entry *te;

	te = npf_tbl_data2entry(td);
	if (!te)
		return;
	_npf_tbl_entry_put(te);
}

/*
 * Callback from zhash_delete
 */
static void npf_tbl_zhash_delete_cb(void *data)
{
	struct npf_tbl_entry *te = data;

	_npf_tbl_entry_put(te);
}

/*
 * Insert an entry into a table
 */
int npf_tbl_entry_insert(struct npf_tbl *nt, void *td, uint32_t *tid)
{
	struct npf_tbl_entry *te;
	int rc;

	*tid = NPF_TBLID_NONE;

	if (!nt || (nt->nt_flags & TS_TBL_ACTIVE) == 0)
		return -EINVAL;

	te = npf_tbl_data2entry(td);
	if (!te)
		return -EINVAL;

	if (te->te_tbl)
		return -EEXIST;

	/* Get a free slot in the table */
	rc = npf_tbl_entry_id_alloc(nt, nt->nt_hint, tid);

	/* Try and resize table if it is full */
	if (rc == -ENOSPC) {
		rc = npf_tbl_resize(nt);
		if (rc < 0)
			return rc;
		rc = npf_tbl_entry_id_alloc(nt, nt->nt_hint, tid);
	}
	if (rc < 0)
		return rc;

	/* Insert into hash table */
	if (zhash_insert(nt->nt_hash, te->te_name, te) < 0)
		return -EEXIST;

	/* Insert into table array */
	te->te_id = *tid;
	rcu_assign_pointer(nt->nt_table[te->te_id], te);

	nt->nt_nentries++;
	nt->nt_hint = *tid + 1;

	/* mark entry as being inserted into table */
	te->te_tbl = nt;

	/* Set zhash_delete callback function. */
	zhash_freefn(nt->nt_hash, te->te_name, npf_tbl_zhash_delete_cb);

	/* Take reference on table entry */
	_npf_tbl_entry_get(te);

	return 0;
}

/*
 * Remove and destroy a table entry.  Assumes user has already cleaned up
 * te_data.
 */
int
npf_tbl_entry_remove(struct npf_tbl *nt, void *td)
{
	struct npf_tbl_entry *te;

	if (!nt)
		return -EINVAL;

	te = npf_tbl_data2entry(td);
	if (!te)
		return -EINVAL;

	/* Don't remove and destroy an entry twice! */
	if (!nt->nt_table[te->te_id] || te->te_tbl == NULL)
		return -EEXIST;

	assert(nt->nt_nentries > 0);
	rcu_assign_pointer(nt->nt_table[te->te_id], NULL);
	nt->nt_nentries--;

	if (te->te_id < nt->nt_hint)
		nt->nt_hint = te->te_id;

	/* mark entry as being removed from table */
	te->te_tbl = NULL;

	/*
	 * Schedule the entry destruction via zhash free fn.
	 *
	 * This will call _npf_tbl_entry_put to release the reference we took
	 * when inserted.
	 */
	zhash_delete(nt->nt_hash, te->te_name);

	return 0;
}

/*
 * Walk all table entries.  Entries may be removed from table and destroyed
 * from callback.
 */
int
npf_tbl_walk(struct npf_tbl *nt, npf_tbl_walk_cb *cb, void *ctx)
{
	struct npf_tbl_entry *te;
	uint i;
	int rc = 0;

	if (!nt)
		return -1;

	for (i = 0; i < nt->nt_sz; i++) {
		te = nt->nt_table[i];
		if (te) {
			rc = (*cb)(te->te_name, te->te_id, te->te_data, ctx);
			if (rc)
				return rc;
		}
	}
	return 0;
}

/*
 * Lookup entry name is hash table, and return entry ID.
 */
uint32_t npf_tbl_name2id(struct npf_tbl *nt, const char *name)
{
	struct npf_tbl_entry *te;

	te = zhash_lookup(nt->nt_hash, name);
	if (te)
		return te->te_id;

	return NPF_TBLID_NONE;
}

/*
 * Lookup entry ID name is array table, and return entry name.
 */
const char *
npf_tbl_id2name(struct npf_tbl *nt, uint id)
{
	struct npf_tbl_entry *te;

	if (unlikely(nt == NULL || nt->nt_table == NULL ||
		     id >= nt->nt_sz))
		return NULL;

	te = nt->nt_table[id];
	if (te)
		return te->te_name;

	return NULL;
}

/*
 * Lookup entry name is hash table, and return pointer to user data.
 */
void *
npf_tbl_name_lookup(struct npf_tbl *nt, const char *name)
{
	struct npf_tbl_entry *te;

	if (unlikely(nt == NULL))
		return NULL;

	te = zhash_lookup(nt->nt_hash, name);
	return te ? te->te_data : NULL;
}

/*
 * Lookup entry ID name is array table, and return pointer to user data.
 *
 * This is the *only* tableset function that should be called from a
 * forwarding thread.
 */
void *
npf_tbl_id_lookup(struct npf_tbl *nt, uint id)
{
	struct npf_tbl_entry *te;

	if (unlikely(nt == NULL || nt->nt_table == NULL ||
		     (nt->nt_flags & TS_TBL_ACTIVE) == 0 ||
		     id >= nt->nt_sz))
		return NULL;

	te = rcu_dereference(nt->nt_table[id]);
	return te ? te->te_data : NULL;
}
