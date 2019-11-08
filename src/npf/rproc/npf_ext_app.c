/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Application rproc and application database.
 */

#include <rte_mbuf.h>
#include <time.h>
#include <ini.h>
#include <rte_jhash.h>

#include "ip_funcs.h"
#include "ip6_funcs.h"
#include "pktmbuf.h"
#include "npf/npf_ruleset.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/dpi/dpi.h"
#include "npf/dpi/dpi_private.h"

#define APP_NAME_HT_SIZE	32
#define APP_NAME_HT_MIN		32
#define APP_NAME_HT_MAX		8192
#define APP_NAME_HT_FLAGS	(CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

#define APP_ID_HT_SIZE		32
#define APP_ID_HT_MIN		32
#define APP_ID_HT_MAX		8192
#define APP_ID_HT_FLAGS		(CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)


/* Application database hash tables. Appls are hashed by name and by ID. */
static struct cds_lfht *app_name_ht;	/* Hash table of application names */
static struct cds_lfht *app_id_ht;	/* Hash table of application IDs */

/* Application database entry. */
struct adb_entry {
	char *ae_name;				/* Name string */
	uint32_t ae_id;				/* Application ID */
	uint32_t ae_refcount;			/* Refcount */
	struct cds_lfht_node ae_name_ht_node;	/* App name hash table */
	struct cds_lfht_node ae_id_ht_node;	/* App ID hash table */
};

/* App information to be saved for later. */
struct app_info {
	struct adb_entry *ai_app_name;
	struct adb_entry *ai_app_proto;
	uint64_t ai_app_type; /* bitfield */
};

static uint32_t name_hash_seed;

/*
 * Match function for the app name hash table.
 * Returns zero for a non-match, and non-zero for a match.
 */
static int
appdb_name_match(struct cds_lfht_node *ht_node, const void *data)
{
	struct adb_entry *entry = caa_container_of(
			ht_node, struct adb_entry, ae_name_ht_node);

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

	cds_lfht_lookup(app_name_ht, hash, appdb_name_match,
			name, &iter);

	struct cds_lfht_node *ht_node =
		cds_lfht_iter_get_node(&iter);

	if (ht_node)
		return caa_container_of(ht_node,
				struct adb_entry,
				ae_name_ht_node);
	else
		return NULL;
}

/*
 * Convert the given app DB name entry to JSON.
 */
int
appdb_name_entry_to_json(json_writer_t *json, void *data)
{
	struct adb_entry *entry = data;
	char buf[11]; /* "id" is u32. "0x" + 8 digits + null = 11. */

	jsonw_name(json, entry->ae_name);
	jsonw_start_object(json);
	snprintf(buf, 11, "%#x", entry->ae_id);
	jsonw_string_field(json, "id", buf);
	jsonw_uint_field(json, "refcount", entry->ae_refcount);
	jsonw_end_object(json);

	return 0;
}

/*
 * Walk the app name hash.
 */
int
appdb_name_walk(json_writer_t *json, app_walker_t callback)
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

/*
 * Match function for the app id hash table.
 * Returns zero for a non-match, and non-zero for a match.
 */
static int
appdb_id_match(struct cds_lfht_node *ht_node, const void *data)
{
	struct adb_entry *entry = caa_container_of(
			ht_node, struct adb_entry, ae_id_ht_node);
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

	cds_lfht_lookup(app_id_ht, hash, appdb_id_match,
			&app_id, &iter);

	struct cds_lfht_node *ht_node =
		cds_lfht_iter_get_node(&iter);

	if (ht_node)
		return caa_container_of(ht_node,
				struct adb_entry,
				ae_id_ht_node);
	else
		return NULL;
}

/* Convert the given app DB ID entry to JSON. */
int
appdb_id_entry_to_json(json_writer_t *json, void *data)
{
	struct adb_entry *entry = data;
	char buf[11]; /* "id" is u32. "0x" + 8 digits + null = 11. */

	snprintf(buf, 11, "%#x", entry->ae_id);
	jsonw_name(json, buf);
	jsonw_start_object(json);
	jsonw_string_field(json, "name", entry->ae_name);
	jsonw_uint_field(json, "refcount", entry->ae_refcount);
	jsonw_end_object(json);

	return 0;
}

/* Walk the app ID hash. */
int
appdb_id_walk(json_writer_t *json, app_walker_t callback)
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
char *
appdb_id_to_name(uint32_t app_id)
{
	struct adb_entry *entry = appdb_find_id(app_id);

	return entry ? entry->ae_name : NULL;
}

/*
 * Find an existing app DB entry with the given name and increment its refcount.
 * If not found, then create a new entry.
 */
static struct adb_entry *
adb_find_or_alloc(char *name)
{
	/* No name? No entry. */
	if ((!name) || (!*name))
		return NULL;

	/* First, search for an existing entry. */
	struct adb_entry *entry = appdb_find_name(name);
	if (entry) {
		/* We only need to bump the refcount. for an existing entry. */
		entry->ae_refcount++;
		return entry;
	}

	/* Not found, so create a new app DB entry. */
	entry = zmalloc_aligned(sizeof(struct adb_entry));
	if (!entry)
		return NULL;

	entry->ae_name = strdup(name);
	if (!entry->ae_name) {
		free(entry);
		return NULL;
	}

	/* Internally assigned application IDs all have the Q bit set. */
	static uint32_t user_app_id = APP_ID_Q | DPI_APP_BASE;

	/*
	 * Search for existing Qosmos app ID.
	 * No need to search the ADB since appdb_find_name
	 * already did that above.
	 */
	entry->ae_id = dpi_app_name_to_id_qosmos(name);
	if (entry->ae_id == DPI_APP_NA)
		/* No Qosmos ID, so allocate an internal ID. */
		entry->ae_id = DPI_ENGINE_USER | user_app_id++;
	else {
		/*
		 * This is a user-defined, Qosmos compatible ID.
		 * So change the Qosmos engine ID to the "user" engine ID.
		 */
		entry->ae_id &= DPI_APP_MASK;
		entry->ae_id |= DPI_ENGINE_USER;
	}

	entry->ae_refcount = 1;

	/* Add to app name hash table. */
	cds_lfht_node_init(&entry->ae_name_ht_node);
	unsigned long name_hash = rte_jhash(name, strlen(name),
					    name_hash_seed);
	cds_lfht_add(app_name_ht, name_hash, &entry->ae_name_ht_node);

	/* Add to app ID hash table. */
	cds_lfht_node_init(&entry->ae_id_ht_node);
	unsigned long id_hash = entry->ae_id;
	cds_lfht_add(app_id_ht, id_hash, &entry->ae_id_ht_node);

	return entry;
}

/*
 * Decrement the given appDB entry's refcount.
 * If zero then remove the entry from the appDB.
 */
static bool
adb_dealloc(struct adb_entry *entry)
{
	if (!entry)
		return false;

	if (--entry->ae_refcount == 0) {
		cds_lfht_del(app_name_ht, &entry->ae_name_ht_node);
		cds_lfht_del(app_id_ht, &entry->ae_id_ht_node);
		free(entry->ae_name);
		free(entry);
	}

	return true;
}

/* Initialisation. */
static bool
app_ht_init(void)
{
	static bool init;

	if (init)
		return true;

	app_name_ht = cds_lfht_new(APP_NAME_HT_SIZE,
				   APP_NAME_HT_MIN,
				   APP_NAME_HT_MAX,
				   APP_NAME_HT_FLAGS,
				   NULL);

	if (!app_name_ht)
		return false;

	app_id_ht = cds_lfht_new(APP_ID_HT_SIZE,
				 APP_ID_HT_MIN,
				 APP_ID_HT_MAX,
				 APP_ID_HT_FLAGS,
				 NULL);

	if (!app_id_ht) {
		cds_lfht_destroy(app_name_ht, NULL);
		app_name_ht = NULL;
		return false;
	}

	name_hash_seed = random();
	init = true;
	return true;
}

/*
 * App rproc constructor.
 * Save application information from the rule for later matching.
 */
static int
app_ctor(npf_rule_t *rl __unused, const char *params, void **handle)
{
	/* Ensure the DPI engine is enabled */
	if (!dpi_init())
		return -ENOMEM;

	/* Ensure hash tables have been init'd */
	if (!app_ht_init())
		return -ENOMEM;

	/*
	 * Application name, type, and proto are received from the config layer
	 * as comma-separated strings.
	 *
	 * Here we convert the strings to IDs and save them for later matching.
	 */

	/* Take a copy of params which we can modify. */
	char *args = strdup(params);
	if (!args)
		return -ENOMEM;

	/* Memory to store the app info. */
	struct app_info *app_info =
		zmalloc_aligned(sizeof(struct app_info));

	if (!app_info) {
		free(args);
		return -ENOMEM;
	}

	/*
	 * The name and type are comma-separated,
	 * so we find the comma at position X,
	 * overwrite it with a '\0'
	 * and get the type string at X+1.
	 */
	char *delim1 = strchr(args, ',');
	if (delim1 == NULL) {
		free(args);
		free(app_info);
		return -EINVAL;
	}
	*delim1 = '\0';

	/* Now "args" contains the null-terminated app name. */
	app_info->ai_app_name = adb_find_or_alloc(args);

	/*
	 * strtoll reads the type number,
	 * storing the delimiting comma in 'delim2'
	 *
	 * Use delim2 because strtoll(c+1, &c, ...) doesn't work.
	 */
	char *delim2;
	app_info->ai_app_type  = (int64_t) strtoll(delim1+1, &delim2, 10);

	/*
	 * "delim2" points to the comma between the type and the proto.
	 * The proto follows the type at delim2+1.
	 */
	app_info->ai_app_proto = adb_find_or_alloc(delim2+1);

	*handle = app_info;
	free(args);

	return 0;
}

/*
 * App rproc destructor.
 * Destroy previously saved app information.
 */
static void
app_dtor(void *handle)
{
	if (!handle)
		return;

	struct app_info *app_info = handle;

	adb_dealloc(app_info->ai_app_name);
	adb_dealloc(app_info->ai_app_proto);
	free(handle);
}

/*
 * App rproc action function.
 *
 * A packet matched the rules,
 * so store the classification in the session's dpi_flow structure.
 */
static bool
app_action(npf_cache_t *npc __unused, struct rte_mbuf **nbuf __unused,
	   void *arg, npf_session_t *se, npf_rproc_result_t *result)
{
	/* NB: we don't modify decision. */
	if (result->decision == NPF_DECISION_BLOCK)
		return true;

	if (!se)
		return true;

	if (!arg)
		return true;

	struct dpi_flow *dpi_flow = npf_session_get_dpi(se);

	if (!dpi_flow)
		return true;

	struct app_info *app_info = arg;

	/*
	 * Use DPI_APP_USER_NA rather than DPI_APP_NA if there's no name / proto
	 * else appfw_decision will exit early.
	 */
	dpi_flow->app_name =
		app_info->ai_app_name ? app_info->ai_app_name->ae_id
				      : DPI_APP_USER_NA;
	dpi_flow->app_proto =
		app_info->ai_app_proto ? app_info->ai_app_proto->ae_id
				       : DPI_APP_USER_NA;
	dpi_flow->app_type = app_info->ai_app_type;
	dpi_flow->key = NULL;
	dpi_flow->wrkr_id = 0;	/* NB not dp_lcore_id() since no DPI work. */
	dpi_flow->offloaded = true;
	dpi_flow->error = false;
	dpi_flow->update_stats = true;

	return true; /* Continue rproc processing. */
}

/* App RPROC ops. */
const npf_rproc_ops_t npf_app_ops = {
	.ro_name   = "app",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_APP,
	.ro_bidir  = true,
	.ro_ctor   = app_ctor,
	.ro_dtor   = app_dtor,
	.ro_action = app_action,
};
