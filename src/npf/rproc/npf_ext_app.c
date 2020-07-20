/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * User-defined application rproc.
 */

#include <rte_mbuf.h>
#include <time.h>
#include <ini.h>
#include <rte_jhash.h>

#include "ip_funcs.h"
#include "ip6_funcs.h"
#include "pktmbuf_internal.h"
#include "npf/npf_ruleset.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/dpi/dpi_internal.h"
#include "npf/dpi/dpi_user.h"
#include "npf/dpi/npf_appdb.h"
#include "npf/dpi/npf_typedb.h"

/* App information to be saved for later. */
struct app_info {
	struct adb_entry *ai_app_name;
	struct adb_entry *ai_app_proto;
	struct tdb_entry *ai_app_type;
};

/*
 * App rproc constructor.
 * Save application information from the rule for later matching.
 */
static int
app_ctor(npf_rule_t *rl __unused, const char *params, void **handle)
{
	/* Ensure the user DPI engine is enabled */
	int ret = dpi_init(IANA_USER);
	if (ret != 0)
		return ret;

	/*
	 * Application name, type, and proto are received from the config layer
	 * as comma-separated strings.
	 *
	 * Here we convert the strings to IDs and save them for later matching.
	 */

	/* Take a copy of params which we can modify. */
	char *name = strdup(params);
	if (!name)
		return -ENOMEM;

	/* Memory to store the app info. */
	struct app_info *app_info =
		zmalloc_aligned(sizeof(struct app_info));

	if (!app_info) {
		free(name);
		return -ENOMEM;
	}

	/*
	 * The name and type are comma-separated,
	 * so we find the comma at position X,
	 * overwrite it with a '\0'
	 * and get the type string at X+1.
	 */
	char *type = strchr(name, ',');
	if (type == NULL)
		goto err_bad_args;

	*type = '\0';
	type++;

	/* Now "name" contains the null-terminated app name. */
	app_info->ai_app_name = appdb_find_or_alloc(name);

	char *proto = strchr(type, ',');
	if (!proto) {
		appdb_dealloc(app_info->ai_app_name);
		goto err_bad_args;
	}
	*proto = '\0';
	proto++;
	app_info->ai_app_type = typedb_find_or_alloc(type);

	/*
	 * "proto" points to the comma between the type and the proto.
	 * The proto follows the type at proto+1.
	 */
	app_info->ai_app_proto = appdb_find_or_alloc(proto);

	*handle = app_info;
	free(name);

	return 0;

err_bad_args:
	free(name);
	free(app_info);
	return -EINVAL;
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

	appdb_dealloc(app_info->ai_app_name);
	appdb_dealloc(app_info->ai_app_proto);
	typedb_dealloc(app_info->ai_app_type);
	free(handle);
	dpi_terminate(IANA_USER);
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

	struct user_flow *dpi_flow = (struct user_flow *)dpi_get_engine_flow(
			npf_session_get_dpi(se), IANA_USER);

	if (!dpi_flow)
		return true;

	struct app_info *app_info = arg;

	/*
	 * Use DPI_APP_USER_NA rather than DPI_APP_NA if there's no name / proto
	 * else appfw_decision will exit early.
	 */
	dpi_flow->application = appdb_entry_get_id(app_info->ai_app_name);
	dpi_flow->protocol = appdb_entry_get_id(app_info->ai_app_proto);
	dpi_flow->type = typedb_entry_get_id(app_info->ai_app_type);

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
