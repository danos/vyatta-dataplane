/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_branch_prediction.h>
#include <stdint.h>
#include "app_group.h"
#include "app_group_db.h"
#include "app_group_cmd.h"
#include "npf/dpi/dpi_internal.h"

/**
 * Split the given "engine:name" string.
 *
 * Split data at the first ':'.
 * Replace ':' with '\0' and set *second to the * char after.
 */
static bool
split_data(char *data, char **second)
{
	char *split = strchr(data, ':');

	/* Can only happen if 'end-app-res-grp' did not create arguments */
	if (unlikely(!split))
		return false;

	*split = '\0';
	split++;

	*second = split;

	return true;
}

/* Parse a single "engine:application" string.
 * Add it to, or remove it from, the specified application group.
 */
static int
parse_app(char *data, struct app_group *group, bool del)
{
	char *app_name;
	if (!split_data(data, &app_name))
		return -EINVAL;

	uint8_t engine_id = dpi_engine_name_to_id(data);
	if (engine_id == IANA_RESERVED)
		return -EINVAL;

	int ret = dpi_init(engine_id);
	if (ret != 0)
		return -ENOMEM;

	uint32_t app_id = dpi_app_name_to_id(engine_id, app_name);
	if (app_id == DPI_APP_ERROR)
		return -EINVAL;

	if (del)
		return app_group_del_app(group, app_id, true);

	return app_group_add_app(group, app_id);
}

/* Parse a single "engine:type" string.
 * Add it to, or remove it from, the specified application group.
 */
static int
parse_type(char *data, struct app_group *group, bool del)
{
	char *type_name;
	if (!split_data(data, &type_name))
		return -EINVAL;

	uint8_t engine_id = dpi_engine_name_to_id(data);
	if (engine_id == IANA_RESERVED)
		return -EINVAL;

	int ret = dpi_init(engine_id);
	if (ret != 0)
		return -ENOMEM;

	uint32_t type_id = dpi_app_type_name_to_id(engine_id, type_name);
	if (type_id == DPI_APP_ERROR)
		return -EINVAL;

	if (del)
		return app_group_del_type(group, type_id, engine_id, true);

	return app_group_add_type(group, type_id, engine_id);
}

/* Parse a single "engine:protocol" string.
 * Add it to, or remove it from, the specified application group.
 */
static int
parse_proto(char *data, struct app_group *group, bool del)
{
	char *proto_name;
	if (!split_data(data, &proto_name))
		return -EINVAL;

	uint8_t engine_id = dpi_engine_name_to_id(data);
	if (engine_id == IANA_RESERVED)
		return -EINVAL;

	int ret = dpi_init(engine_id);
	if (ret != 0)
		return -ENOMEM;

	uint32_t proto_id = dpi_app_name_to_id(engine_id, proto_name);
	if (proto_id == DPI_APP_ERROR)
		return -EINVAL;

	if (del)
		return app_group_del_proto(group, proto_id, true);

	return app_group_add_proto(group, proto_id);
}

/**
 * Find each entry in args, NULL-terminate it and pass it to parse_arg.
 *
 * Expected structure:
 *	arg  := engine:name
 *	args := arg | arg,...,arg
 *
 * Each arg entry is passed to parse_arg.
 *
 * @param group Application resource group to modify.
 * @param args arguments to parse.
 * @param parse_arg function to parse each entry.
 * @param del True if should delete parsed entries from given group.
 */
static int
parse_argument(struct app_group *group, char *args, bool del,
	       int (*parse_arg)(char *, struct app_group*, bool del))
{
	char *next;
	int ret;

	while ((next = strchr(args, ',')) != NULL) {
		*next = '\0';
		next++;
		ret = parse_arg(args, group, del);
		if (ret != 0)
			return ret;

		args = next;
	}

	/* Handle both single arg and final arg */
	return parse_arg(args, group, del);
}

int
app_group_add(char *name, char *args)
{
	/* Name is required. */
	if (!name)
		return -EINVAL;

	/* Ensure database is initialised */
	if (!app_group_db_init())
		return -ENOMEM;

	/* Split args into apps, protos, types. */
	char *apps = args;

	char *protos = strchr(apps, ';');
	if (!protos)
		return -EINVAL;

	*protos = '\0';
	protos++;

	char *types = strchr(protos, ';');
	if (!types)
		return -EINVAL;

	*types = '\0';
	types++;

	/* Create a new, empty, group. */
	struct app_group *new_group = app_group_init();

	/* Add any new applications. */
	if (*apps != '\0') {
		int ret = parse_argument(new_group, apps, false, parse_app);
		if (ret != 0)
			return ret;
	}

	/* Add any new types. */
	if (*types != '\0') {
		int ret = parse_argument(new_group, types, false, parse_type);
		if (ret != 0)
			return ret;
	}

	/* Add any new protocols. */
	if (*protos != '\0') {
		int ret = parse_argument(new_group, protos, false, parse_proto);
		if (ret != 0)
			return ret;
	}

	/* Either find an existing entry with the same name
	 * - we will update that entry.
	 *
	 * Or create a new entry.
	 */
	struct agdb_entry *entry = app_group_db_find_name(name);
	if (!entry) {
		/* There's no existing entry, so we need to make a new one. */

		entry = app_group_db_find_or_alloc(name);
		if (!entry) {
			/* We weren't able to make the new entry. */
			app_group_destroy(new_group);
			return -ENOMEM;
		}
	}

	/* If we're modifying an existing struct agdb_entry:
	 *
	 * Application firewalls cache struct agdb_entry in struct appfw_rule,
	 * so we can't just free the old agdb_entry and create a new one
	 * since appFWs would be left holding a stale pointer.
	 *
	 * So we'd need to walk all the appFWs and swap in the new agdb_entry.
	 * Then we could free the old one.
	 *
	 * But agdb_entry is hashed by name, so at least temporarily
	 * we'd have two entries with the same name. To prevent a
	 * parallel config process from picking up the old agdb_entry
	 * while we're walking all the appFWs, we'd need to remove the old
	 * agdb_entry->name and wait for an RCU interval before
	 * walking all the appFWs to swap in the new one.
	 *
	 * More simply, just leave the appFWs with their cached agdb_entry,
	 * and just swap the new struct app_group which we've just made
	 * into the existing agdb_entry.
	 *
	 * So there's no need to wait for an RCU period
	 * nor to walk the appFWs.
	 */
	struct app_group *old_group = entry->group;
	if (!old_group) {
		/* The entry has no group. */
		app_group_destroy(new_group);
		return -EINVAL;
	}

	/* Now swap the contents of new_group with the old_group. */

	new_group->ag_app_ht =
	    rcu_xchg_pointer(&old_group->ag_app_ht, new_group->ag_app_ht);
	new_group->ag_type_ht =
	    rcu_xchg_pointer(&old_group->ag_type_ht, new_group->ag_type_ht);
	new_group->ag_proto_ht =
	    rcu_xchg_pointer(&old_group->ag_proto_ht, new_group->ag_proto_ht);
	old_group->engine_refcount[0] = new_group->engine_refcount[0];
	old_group->engine_refcount[1] = new_group->engine_refcount[1];

	/* Delete the old stuff that's been swapped into new_group. */
	app_group_rm_group(new_group);

	return 0;
}

bool
app_group_del(char *name)
{
	if (!name)
		return false;

	struct agdb_entry *entry = app_group_db_find_name(name);

	return app_group_db_rm_entry(entry);
}
