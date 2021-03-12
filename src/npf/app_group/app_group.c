/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "util.h"
#include "app_group.h"
#include "npf/dpi/dpi_internal.h"

#define AG_APP_HT_SIZE        4
#define AG_APP_HT_MIN         4
#define AG_APP_HT_MAX         1024
#define AG_APP_HT_FLAGS       (CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

#define AG_TYPE_HT_SIZE        4
#define AG_TYPE_HT_MIN         4
#define AG_TYPE_HT_MAX         1024
#define AG_TYPE_HT_FLAGS       (CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

#define AG_PROTO_HT_SIZE        4
#define AG_PROTO_HT_MIN         4
#define AG_PROTO_HT_MAX         1024
#define AG_PROTO_HT_FLAGS       (CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING)

/* App group garbage collection list. */
static CDS_LIST_HEAD(app_group_gc_list);

/* Application ID hash table entry. */
struct ag_app_entry {
	uint32_t app;			/* Application ID */
	struct cds_lfht_node ht_node;	/* Hash table node */
	struct rcu_head rcu;
};

/* Application type hash table entry.
 * Application type is unique per engine,
 * so both type and engine ID are stored.
 */
struct ag_type_entry {
	uint32_t type;			/* Application type */
	uint8_t engine;			/* Application engine ID */
	struct cds_lfht_node ht_node;	/* Hash table node */
	struct rcu_head rcu;
};

/* Application protocol hash table entry. */
struct ag_proto_entry {
	uint32_t proto;			/* Protocol ID */
	struct cds_lfht_node ht_node;	/* Hash table node */
	struct rcu_head rcu;
};

/**
 * Add an engine to the given resource group
 * if the engine is not already in the given resource group.
 *
 * Return true on success (engine_id was pushed).
 * Return false on failure (engine_id wasn't pushed);
 */
static inline bool
push_engine(struct app_group *group, uint8_t engine_id)
{
	int32_t idx = dpi_engine_id_to_idx(engine_id);

	if (idx == -1)
		/* Engine_id wasn't recognised */
		return false;

	if (group->engine_refcount[idx] == UINT32_MAX)
		return false;

	group->engine_refcount[idx]++;

	return true;
}

/**
 * Remove an engine from the given resource group
 * if no application or protocol in the group still requires it.
 *
 * Return true on success (engine_id was popped).
 * Return false on failure (engine_id wasn't popped);
 */
static inline bool
pop_engine(struct app_group *group, uint8_t engine_id)
{
	int32_t idx = dpi_engine_id_to_idx(engine_id);

	if (idx == -1)
		/* Engine_id wasn't recognised */
		return false;

	if (group->engine_refcount[idx] == 0)
		/* recount mismatch */
		return false;

	group->engine_refcount[idx]--;
	return true;
}

struct app_group *
app_group_init(void)
{
	struct app_group *group = zmalloc_aligned(sizeof(struct app_group));
	if (!group)
		return NULL;

	group->ag_app_ht = cds_lfht_new(AG_APP_HT_SIZE,
					AG_APP_HT_MIN,
					AG_APP_HT_MAX,
					AG_APP_HT_FLAGS,
					NULL);

	if (!group->ag_app_ht) {
		free(group);
		return NULL;
	}

	group->ag_type_ht = cds_lfht_new(AG_TYPE_HT_SIZE,
					 AG_TYPE_HT_MIN,
					 AG_TYPE_HT_MAX,
					 AG_TYPE_HT_FLAGS,
					 NULL);

	if (!group->ag_type_ht) {
		cds_lfht_destroy(group->ag_app_ht, NULL);
		free(group);
		return NULL;
	}

	group->ag_proto_ht = cds_lfht_new(AG_PROTO_HT_SIZE,
					  AG_PROTO_HT_MIN,
					  AG_PROTO_HT_MAX,
					  AG_PROTO_HT_FLAGS,
					  NULL);

	if (!group->ag_type_ht) {
		cds_lfht_destroy(group->ag_app_ht, NULL);
		cds_lfht_destroy(group->ag_type_ht, NULL);
		free(group);
		return NULL;
	}

	return group;
}

/*
 * Delete the given application group.
 */
void
app_group_destroy(struct app_group *group)
{
	if (group->ag_app_ht) {
		app_group_del_all_apps(group);
		cds_lfht_destroy(group->ag_app_ht, NULL);
	}

	if (group->ag_type_ht) {
		app_group_del_all_types(group);
		cds_lfht_destroy(group->ag_type_ht, NULL);
	}

	if (group->ag_proto_ht) {
		app_group_del_all_protos(group);
		cds_lfht_destroy(group->ag_proto_ht, NULL);
	}

	/* Be safe. */
	group->ag_app_ht = NULL;
	group->ag_type_ht = NULL;
	group->ag_proto_ht = NULL;
	group->engine_refcount[0] = 0;
	group->engine_refcount[1] = 0;

	free(group);
}

/*
 * Add app group to the GC list for later deletion.
 */
void
app_group_rm_group(struct app_group *group)
{
	if (group)
		cds_list_add(&group->deadlist, &app_group_gc_list);
}

/*
 * Periodic garbage collection.
 */
void
app_group_gc(void)
{
	struct app_group *ag, *tmp;

	cds_list_for_each_entry_safe(ag, tmp, &app_group_gc_list, deadlist) {
		if (ag->is_dead) {
			cds_list_del(&ag->deadlist);
			app_group_destroy(ag);
		} else {
			ag->is_dead = true;
		}
	}
}

static int
app_group_cmp_app(struct cds_lfht_node *node, const void *key)
{
	struct ag_app_entry *entry;
	entry = caa_container_of(node, struct ag_app_entry, ht_node);

	uint32_t app = *(uint32_t *)key;

	return (entry->app == app);
}

int
app_group_add_app(struct app_group *group, uint32_t app)
{
	if (!group)
		return -EINVAL;

	/* Create the hash table entry. */
	struct ag_app_entry *
		entry = zmalloc_aligned(sizeof(*entry));
	if (!entry)
		return -ENOMEM;

	/* Store the app. */
	entry->app = app;

	/* Add to hash table. */
	cds_lfht_node_init(&entry->ht_node);
	unsigned long name_hash = app;

	struct cds_lfht_node *node;
	node = cds_lfht_add_unique(group->ag_app_ht, name_hash,
				   app_group_cmp_app, &app,
				   &entry->ht_node);

	if (node != &entry->ht_node) {
		free(entry);
		return -EEXIST;
	}

	/* Save engine ID. */
	uint8_t engine = (uint8_t) (app >> DPI_ENGINE_SHIFT);
	if (!push_engine(group, engine)) {
		/* Failed to push engine.
		 * Remove app from hash table.
		 */
		app_group_del_app(group, app, false);
		return -EINVAL;
	}

	return 0;
}

static int
app_group_cmp_type(struct cds_lfht_node *node, const void *key)
{
	struct ag_type_entry *entry;
	entry = caa_container_of(node, struct ag_type_entry, ht_node);

	uint32_t type = *(unsigned long *)key;

	return (entry->type == type);
}

int
app_group_add_type(struct app_group *group, uint32_t type, uint8_t engine)
{
	if (!group)
		return -EINVAL;

	/* Create the hash table entry. */
	struct ag_type_entry *entry;
	entry = zmalloc_aligned(sizeof(struct ag_type_entry));
	if (!entry)
		return -ENOMEM;

	/* Store the type and engine ID,
	 * because types are unique per engine.
	 */
	entry->type = type;
	entry->engine = engine;

	/* Add to hash table. */
	cds_lfht_node_init(&entry->ht_node);
	unsigned long hash = ((ulong)engine << 32) | type;

	struct cds_lfht_node *node;
	node = cds_lfht_add_unique(group->ag_type_ht, hash,
				   app_group_cmp_type, &hash, &entry->ht_node);

	if (node != &entry->ht_node) {
		free(entry);
		return -EEXIST;
	}

	/* Save engine ID. */
	if (!push_engine(group, engine)) {
		/* Failed to push engine.
		 * Remove type from hash table.
		 */
		app_group_del_type(group, type, engine, false);
		return -EINVAL;
	}

	return 0;
}

static int
app_group_cmp_proto(struct cds_lfht_node *node, const void *key)
{
	struct ag_proto_entry *entry;
	entry = caa_container_of(node, struct ag_proto_entry, ht_node);

	uint32_t proto = *(uint32_t *)key;

	return (entry->proto == proto);
}

int
app_group_add_proto(struct app_group *group, uint32_t proto)
{
	if (!group)
		return -EINVAL;

	/* Create the hash table entry. */
	struct ag_proto_entry *entry;
	entry = zmalloc_aligned(sizeof(struct ag_proto_entry));
	if (!entry)
		return -ENOMEM;

	/* Store the protocol. */
	entry->proto = proto;

	/* Add to hash table. */
	cds_lfht_node_init(&entry->ht_node);
	unsigned long hash = proto;

	struct cds_lfht_node *node;
	node = cds_lfht_add_unique(group->ag_proto_ht, hash,
				   app_group_cmp_proto, &proto,
				   &entry->ht_node);

	if (node != &entry->ht_node) {
		free(entry);
		return -EEXIST;
	}

	/* Save engine ID. */
	uint8_t engine = (uint8_t) (proto >> DPI_ENGINE_SHIFT);
	if (!push_engine(group, engine)) {
		/* Failed to push engine.
		 * Remove proto from hash table.
		 */
		app_group_del_proto(group, proto, false);
		return -EINVAL;
	}

	return 0;
}

static int
ag_app_match(struct cds_lfht_node *node, const void *data)
{
	uint32_t wanted = *(uint32_t *)data;
	struct ag_app_entry *entry;

	entry = caa_container_of(node, struct ag_app_entry, ht_node);

	return wanted == entry->app;
}

static int
ag_type_match(struct cds_lfht_node *node, const void *data)
{
	uint64_t wanted = *(uint64_t *)data;
	struct ag_type_entry *entry;

	entry = caa_container_of(node, struct ag_type_entry, ht_node);

	return wanted == entry->type;
}

static int
ag_proto_match(struct cds_lfht_node *node, const void *data)
{
	uint32_t wanted = *(uint32_t *)data;
	struct ag_proto_entry *entry;

	entry = caa_container_of(node, struct ag_proto_entry, ht_node);

	return wanted == entry->proto;
}

static void
ag_app_free(struct rcu_head *head)
{
	struct ag_app_entry *entry;
	entry = caa_container_of(head, struct ag_app_entry, rcu);

	free(entry);
}

static int
_app_group_del_app(struct cds_lfht *ht, struct cds_lfht_node *node,
		   struct app_group *group,
		   bool remove_engine)
{
	struct ag_app_entry *entry;
	entry = caa_container_of(node, struct ag_app_entry, ht_node);

	cds_lfht_del(ht, node);
	call_rcu(&entry->rcu, ag_app_free);

	if (!remove_engine)
		/* No need to remove the engine,
		 * so declare success.
		 */
		return 0;

	uint8_t engine = (uint8_t) (entry->app >> DPI_ENGINE_SHIFT);

	return pop_engine(group, engine) ? 0 : -EINVAL;
}

int
app_group_del_app(struct app_group *group, uint32_t app, bool remove_engine)
{
	if (!group)
		return -EINVAL;

	/* Search for node. */
	struct cds_lfht_node *ht_node;

	ht_node = app_group_find_app(group, app);
	if (!ht_node)
		return -EINVAL;

	return _app_group_del_app(group->ag_app_ht, ht_node, group,
				  remove_engine);
}

void
app_group_del_all_apps(struct app_group *group)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	struct cds_lfht *ht = group->ag_app_ht;
	if (!ht)
		return;

	cds_lfht_first(ht, &iter);

	while ((node = cds_lfht_iter_get_node(&iter)) != NULL) {

		_app_group_del_app(ht, node, group, true);
		cds_lfht_next(ht, &iter);
	}
}

static void
ag_type_free(struct rcu_head *head)
{
	struct ag_type_entry *entry;
	entry = caa_container_of(head, struct ag_type_entry, rcu);

	free(entry);
}

static int
_app_group_del_type(struct cds_lfht *ht, struct cds_lfht_node *node,
		    struct app_group *group,
		    bool remove_engine, uint8_t engine)
{
	struct ag_type_entry *entry;
	entry = caa_container_of(node, struct ag_type_entry, ht_node);

	cds_lfht_del(ht, node);
	call_rcu(&entry->rcu, ag_type_free);

	if (!remove_engine)
		/* No need to remove the engine,
		 * so declare success.
		 */
		return 0;

	return pop_engine(group, engine) ? 0 : -EINVAL;
}

int
app_group_del_type(struct app_group *group, uint32_t type, uint8_t engine,
		   bool remove_engine)
{
	if (!group)
		return -EINVAL;

	/* Search for node. */
	struct cds_lfht_node *ht_node;

	ht_node = app_group_find_type(group, type, engine);
	if (!ht_node)
		return -EINVAL;

	return _app_group_del_type(group->ag_type_ht, ht_node, group,
				   remove_engine, engine);
}

void
app_group_del_all_types(struct app_group *group)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	struct cds_lfht *ht = group->ag_type_ht;
	if (!ht)
		return;

	cds_lfht_first(ht, &iter);

	while ((node = cds_lfht_iter_get_node(&iter)) != NULL) {
		struct ag_type_entry *entry;
		entry = caa_container_of(node, struct ag_type_entry, ht_node);

		_app_group_del_type(ht, node, group, true, entry->engine);

		cds_lfht_next(ht, &iter);
	}
}

static void
ag_proto_free(struct rcu_head *head)
{
	struct ag_proto_entry *entry;
	entry = caa_container_of(head, struct ag_proto_entry, rcu);

	free(entry);
}

static int
_app_group_del_proto(struct cds_lfht *ht, struct cds_lfht_node *node,
		     struct app_group *group,
		     bool remove_engine)
{
	struct ag_proto_entry *entry;
	entry = caa_container_of(node, struct ag_proto_entry, ht_node);

	cds_lfht_del(ht, node);
	call_rcu(&entry->rcu, ag_proto_free);

	if (!remove_engine)
		/* No need to remove the engine,
		 * so declare success.
		 */
		return 0;

	uint8_t engine = (uint8_t) (entry->proto >> DPI_ENGINE_SHIFT);

	return pop_engine(group, engine) ? 0 : -EINVAL;
}

int
app_group_del_proto(struct app_group *group, uint32_t proto, bool remove_engine)
{
	if (!group)
		return -EINVAL;

	/* Search for node. */
	struct cds_lfht_node *ht_node;

	ht_node = app_group_find_proto(group, proto);
	if (!ht_node)
		return -EINVAL;

	return _app_group_del_proto(group->ag_proto_ht, ht_node, group,
				    remove_engine);
}

/* Remove all the protocols from an application group. */
void
app_group_del_all_protos(struct app_group *group)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	struct cds_lfht *ht = group->ag_proto_ht;
	if (!ht)
		return;

	cds_lfht_first(ht, &iter);

	while ((node = cds_lfht_iter_get_node(&iter)) != NULL) {

		_app_group_del_proto(ht, node, group, true);
		cds_lfht_next(ht, &iter);
	}
}

struct cds_lfht_node*
app_group_find_app(struct app_group *group, uint32_t app)
{
	struct cds_lfht_iter iter;
	unsigned long hash = app;

	if (!group->ag_app_ht)
		return NULL;

	cds_lfht_lookup(group->ag_app_ht, hash, ag_app_match, &app, &iter);
	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);

	return ht_node;
}

struct cds_lfht_node*
app_group_find_type(struct app_group *group, uint32_t type, uint8_t engine)
{
	struct cds_lfht_iter iter;
	unsigned long etype = ((unsigned long)engine << 32) | type;
	unsigned long hash = etype;

	cds_lfht_lookup(group->ag_type_ht, hash, ag_type_match, &etype, &iter);
	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);

	return ht_node;
}

struct cds_lfht_node*
app_group_find_proto(struct app_group *group, uint32_t proto)
{
	struct cds_lfht_iter iter;
	unsigned long hash = proto;

	cds_lfht_lookup(group->ag_proto_ht, hash, ag_proto_match,
			&proto, &iter);
	struct cds_lfht_node *ht_node = cds_lfht_iter_get_node(&iter);

	return ht_node;
}
