/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef APP_GROUP_H
#define APP_GROUP_H

#include <stdbool.h>
#include <urcu.h>

/**
 * Application resource group.
 */
struct app_group {
	struct cds_lfht *ag_app_ht;	// App-group "application" hash table
	struct cds_lfht *ag_type_ht;	// App-group "type" hash table
	struct cds_lfht *ag_proto_ht;	// App-group "protocol" hash table
	uint32_t engine_refcount[2];	// DPI engine refcounts
	struct rcu_head rcu;
};

/**
 * Create a new, empty application resource group.
 *
 * @return new application resource group or NULL on allocation failure.
 */
struct app_group *
app_group_init(void);

/**
 * Destroy the given application resource group.
 *
 * @param group Group to destroy, can be NULL.
 * @return void.
 */
void
app_group_destroy(struct app_group *group);

/**
 * Add an application to the given application resource group.
 *
 * @param group group to add to.
 * @param app application ID.
 * @return -EINVAL if group is NULL, -ENOMEM if not enough memory to add ID, or
 * 0 otherwise.
 */
int
app_group_add_app(struct app_group *group, uint32_t app);

/**
 * Add a type to the given application resource group.
 *
 * @param group group to add to.
 * @param type type ID.
 * @param engine_id Engine ID associated with the type.
 * @return -EINVAL if group is NULL, -ENOMEM if not enough memory to add ID, or
 * 0 otherwise.
 */
int
app_group_add_type(struct app_group *group, uint32_t type, uint8_t engine_id);

/**
 * Add a protocol to the given application resource group.
 *
 * @param group group to add to.
 * @param proto protocol ID.
 * @return -EINVAL if group is NULL, -ENOMEM if not enough memory to add ID, or
 * 0 otherwise.
 */
int
app_group_add_proto(struct app_group *group, uint32_t proto);

/**
 * Remove an application from the given application resource group.
 *
 * @param group group to remove from.
 * @param app application ID.
 * @param remove_engine pop the engine if true.
 * @return -EINVAL if group is NULL, 1 if no matching ID is found, 0 otherwise.
 */
int
app_group_del_app(struct app_group *group, uint32_t app, bool remove_engine);

/**
 * Remove all applications from the given application resource group.
 *
 * @param group group to remove from.
 */
void
app_group_del_all_apps(struct app_group *group);

/**
 * Remove a type from the given application resource group.
 *
 * @param group group to remove from.
 * @param type the type ID to be removed.
 * @param engine_id the engine ID associated with the type.
 * @param remove_engine pop the engine if true.
 * @return -EINVAL if group is NULL, 1 if no matching ID is found, 0 otherwise.
 */
int
app_group_del_type(struct app_group *group, uint32_t type, uint8_t engine_id,
		   bool remove_engine);

/**
 * Remove all types from the given application resource group.
 *
 * @param group group to remove from.
 */
void
app_group_del_all_types(struct app_group *group);

/**
 * Remove a proto from the given application resource group.
 *
 * @param group group to remove from.
 * @param proto proto ID.
 * @param remove_engine pop the engine if true.
 * @return -EINVAL if group is NULL, 1 if no matching ID is found, 0 otherwise.
 */
int
app_group_del_proto(struct app_group *group, uint32_t proto,
		    bool remove_engine);

/**
 * Remove all protos from the given application resource group.
 *
 * @param group group to remove from.
 * @return void.
 */
void
app_group_del_all_protos(struct app_group *group);

/**
 * Determine if the given application ID is in the given application
 * resource group.
 *
 * @param group group to check.
 * @param app ID to look for.
 * @return pointer to node if found; NULL if not found.
 */
struct cds_lfht_node*
app_group_find_app(struct app_group *group, uint32_t app);

/**
 * Determine if the given type ID is in the given application
 * resource group.
 *
 * @param group group to check.
 * @param type ID to look for.
 * @param engine_id engine ID associated with the type.
 * @return pointer to node if found; NULL if not found.
 */
struct cds_lfht_node*
app_group_find_type(struct app_group *group, uint32_t type, uint8_t engine_id);

/**
 * Determine if the given protocol ID is in the given application
 * resource group.
 *
 * @param group group to check.
 * @param proto ID to look for.
 * @return pointer to node if found; NULL if not found.
 */
struct cds_lfht_node*
app_group_find_proto(struct app_group *group, uint32_t proto);

#endif /* APP_GROUP_H */
