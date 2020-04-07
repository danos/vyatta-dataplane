/*
 * Path monitor dataplane code
 *
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 * Copyright (c) 2017,2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 *
 * A Path Monitor (pathmon) instance represents the state of a path
 * (compliant or non-compliant) as determined by the monitord
 * daemon. The instance state is used to "feed" a PBR (NPF) RPROC
 * object during packet forwarding.
 *
 * A pathmon entry is created through the processing of one of a pair of
 * configuration commands - an NPF RPROC constructor call or through the
 * receipt of an "init" command from monitord - whichever arrives
 * first. A command (RPROC or init) that arrives subsequently simply
 * increments a reference count. Similarly if the pathmon RPROC element
 * is referenced by multiple PBR policies, multiple calls to the
 * constructor increments the reference count.
 *
 * Deletion of an entry mirrors the creation logic: RPROC destructor
 * call(s) and the receipt of a "delete" command from monitord.
 *
 * All 4 operations take place in the context of the control (master)
 * thread, i.e. these commands are serialized.
 *
 * The "init" command is used to establish the (user configured) initial
 * state of the path. Subsequent changes to the state from monitord
 * arrive as "update" commands. Updates arrive on the console thread.
 *
 * The above set of operations allow for a pathmon instance to be
 * created with an initial state and subsequently updated with the
 * results from monitord. At some later point, as the associated PBR
 * rule is configured, the forwarding thread(s) can immediately apply
 * the RPROC with the "correct" (current) pathmon state.
 */
#include <czmq.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"
#include "json_writer.h"
#include "pathmonitor.h"


/* Pathmon hash. */
static zhash_t *pathmon_db;

/* Pathmon spinlock. */
static rte_spinlock_t pathmon_lock = RTE_SPINLOCK_INITIALIZER;

/* Pathmon entry structure. */
struct pathmon_entry_t {
	enum pathmon_status status;
	uint16_t refcount;
	bool initdone;
	char *name;
};

/*
 * The caller of the following pathmon helper functions (locate,
 * increment the reference count and decrement the reference count) must
 * hold the associated spinlock.
 */

static struct pathmon_entry_t *
pathmon_find(const char *name)
{
	struct pathmon_entry_t *pme = NULL;

	if (pathmon_db != NULL)
		pme = zhash_lookup(pathmon_db, name);

	return pme;
}

static struct pathmon_entry_t *
pathmon_get(const char *name)
{
	if (!pathmon_db)
		pathmon_db = zhash_new();

	struct pathmon_entry_t *entry = zhash_lookup(pathmon_db, name);
	if (!entry) {
		/* Entry doesn't exist, so create it. */
		entry = malloc(sizeof(*entry));
		if (!entry)
			return NULL;

		/* Remember our own name, sigh. */
		entry->name = strdup(name);
		if (!entry->name) {
			free(entry);
			return NULL;
		}

		entry->status = PM_DEFAULT;
		entry->refcount = 0;
		entry->initdone = false;
		zhash_insert(pathmon_db, name, entry);
	}

	entry->refcount++;
	return entry;
}

static void
pathmon_put(struct pathmon_entry_t *entry)
{
	if (--entry->refcount == 0) {
		/* No more clients, so delete the entry. */
		zhash_delete(pathmon_db, entry->name);
		free(entry->name);
		free(entry);

		/* Delete the hash too? */
		if (zhash_size(pathmon_db) == 0) {
			zhash_destroy(&pathmon_db);
			pathmon_db = NULL;
		}
	}
}

/* Public API
 *
 * Client registration for the named pathmon entry.
 *
 * Create the hash if needs be.
 * If the specified entry doesn't exist, then create it with a default status.
 * If it already exists, then increment the refcount.
 *
 * Return: handle to pathmon entry.
 */
struct pathmon_entry_t *
pathmon_register(const char *name)
{
	rte_spinlock_lock(&pathmon_lock);
	struct pathmon_entry_t *entry = pathmon_get(name);
	rte_spinlock_unlock(&pathmon_lock);
	return entry;
}

/* Public API
 *
 * Client deregistration for the specified pathmonitor entry.
 *
 * Decrement the refcount.
 * If it reaches zero, then delete the entry.
 * If there are no more entries, then delete the entire hash.
 */
void
pathmon_deregister(struct pathmon_entry_t *entry)
{
	rte_spinlock_lock(&pathmon_lock);
	pathmon_put(entry);
	rte_spinlock_unlock(&pathmon_lock);
}

/* Public API
 *
 * Return the compliance status of the specified pathmon entry.
 */
enum pathmon_status
pathmon_get_status(struct pathmon_entry_t *entry)
{
	return entry->status;
}

static void
pathmon_init(const char *name, enum pathmon_status status)
{
	rte_spinlock_lock(&pathmon_lock);

	struct pathmon_entry_t *pme = pathmon_find(name);

	/*
	 * If the entry does not exist or if it exists but has yet to be
	 * initialized, go ahead and create the entry. Ignore this
	 * command if the entry exists and has already been initialized,
	 * i.e. its a spurious "init" command, most likely following a
	 * restart of the Path Monitor daemon.
	 */
	if (!pme || !pme->initdone) {
		pme = pathmon_get(name);
		if (pme) {
			pme->initdone = true;
			pme->status = status;
		}
	}

	rte_spinlock_unlock(&pathmon_lock);
}

/* Update the pathmonitor entry with the specified name.
 *
 * However, discard the update if the specified entry doesn't exist
 * because no clients have registered for the entry.
 *
 * NB Updates do not cause objects to be created.
 *
 * Return: 0 if the entry was successfully updated, else -1.
 */
static int
pathmon_update(const char *name, enum pathmon_status status)
{
	int r = -1;

	rte_spinlock_lock(&pathmon_lock);

	struct pathmon_entry_t *entry = pathmon_find(name);
	if (entry) {
		entry->status = status;
		r = 0; /* success */
	}

	rte_spinlock_unlock(&pathmon_lock);
	return r;
}

static void
pathmon_delete(const char *name)
{
	rte_spinlock_lock(&pathmon_lock);

	struct pathmon_entry_t *pme = pathmon_find(name);

	/*
	 * Attempt to delete an entry, but only if it exists and has
	 * been fully initialized.
	 */
	if (pme && pme->initdone) {
		pme->initdone = false;
		pathmon_put(pme);
	}

	rte_spinlock_unlock(&pathmon_lock);
}

/* Show all the pathmon entries. */
static int
pathmon_show(FILE *f)
{
	json_writer_t *json = jsonw_new(f);

	if (!json)
		return -1;

	jsonw_pretty(json, true);
	jsonw_name(json, "pathmonitor-policy");
	jsonw_start_array(json);

	if (!pathmon_db)
		goto done;

	rte_spinlock_lock(&pathmon_lock);

	for (struct pathmon_entry_t *entry = zhash_first(pathmon_db);
	     entry != NULL;
	     entry = zhash_next(pathmon_db)) {

		jsonw_start_object(json);

		jsonw_string_field(json, "policy",
			zhash_cursor(pathmon_db));

		jsonw_string_field(json, "status",
			(entry->status == PM_COMPLIANT) ? "compliant" :
			(entry->status == PM_NONCOMPLIANT) ? "noncompliant" :
			"unknown");

		jsonw_bool_field(json, "initdone", entry->initdone);
		jsonw_uint_field(json, "refcount", entry->refcount);

		jsonw_end_object(json);
	}

	rte_spinlock_unlock(&pathmon_lock);

done:
	jsonw_end_array(json);
	jsonw_destroy(&json);
	return 0;
}

/* Pathmon command dispatcher
 *
 * pathmonitor init <monitor.instance> { compliant | noncompliant }
 * pathmonitor delete <monitor.instance>
 * pathmonitor updated <monitor.instance> { compliant | noncompliant }
 * pathmonitor show
 *
 * Take care if any new commands are introduced; the "init" and "delete"
 * commands (as well as the RPROC functions) are serialized through the
 * master thread. The other commands ("show" & "update") operate on the
 * console thread.
 */
int
cmd_pathmonitor(FILE *f, int argc, char **argv)
{
	const char *cmd = argv[1];
	const char *name = argv[2];
	const char *statusstr = argv[3];

	switch (argc) {
	case 2:
		if (streq(cmd, "show"))
			return pathmon_show(f);
		break;
	case 3:
		if (streq(cmd, "delete")) {
			pathmon_delete(name);
			return 0;
		}
		break;
	case 4:
	{
		enum pathmon_status status;

		if (streq(statusstr, "compliant"))
			status = PM_COMPLIANT;
		else if (streq(statusstr, "noncompliant"))
			status = PM_NONCOMPLIANT;
		else
			break;

		if (streq(cmd, "init")) {
			pathmon_init(name, status);
			return 0;
		}

		if (streq(cmd, "update")) {
			pathmon_update(name, status);
			return 0;
		}

		break;
	}
	default:
		fprintf(f, "wrong number of arguments: %d", argc);
		return -1;
	}

	fprintf(f, "unknown or bad command: '%s'", cmd);
	return -1;
}
