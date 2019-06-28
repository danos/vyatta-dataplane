/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <rte_log.h>

#include "json_writer.h"
#include "mpls/mpls_label_table.h"
#include "pd_show.h"
#include "route.h"
#include "vplane_log.h"
#include "fal.h"
#include "ipmc_pd_show.h"

static const char * const pd_obj_state_names[] = {
	"full",
	"partial",
	"no_resource",
	"no_support",
	"not_needed",
	"error",
};

static int pd_show_obj(json_writer_t *wr, const char *dp, uint32_t *stats)
{
	int i;

	jsonw_start_object(wr);
	jsonw_string_field(wr, "dp", dp);
	for (i = 0; i < PD_OBJ_STATE_LAST; i++)
		jsonw_uint_field(wr, pd_obj_state_names[i], stats[i]);
	jsonw_end_object(wr);

	return 0;
}

struct pd_show_cmd {
	const char *name;
	uint32_t * (*get_sw_stats)(void);
	uint32_t * (*get_hw_stats)(void);
	int (*get_subset_data)(json_writer_t *json, enum pd_obj_state subset);
	const char *help;
};
static const struct pd_show_cmd pd_show_cmd_table[] = {
	{ "route",      route_sw_stats_get, route_hw_stats_get,
	  route_get_pd_subset_data,  "Show route" },
	{ "route6",     route6_sw_stats_get, route6_hw_stats_get,
	  route6_get_pd_subset_data,  "Show route" },
	{ "mroute",     NULL, mroute_hw_stats_get,
	  mroute_get_pd_subset_data,  "Show route" },
	{ "mroute6",    NULL, mroute6_hw_stats_get,
	  mroute6_get_pd_subset_data,  "Show route" },
	{ "mpls-route", NULL, mpls_label_table_hw_stats_get,
	  mpls_label_table_get_pd_subset_data,  "Show route" },
	{ NULL, NULL, NULL, NULL, NULL },
};

static int pd_show_dataplane(FILE *f, const char *name,
			     enum pd_obj_state subset)
{
	json_writer_t *wr;
	const struct pd_show_cmd *cmd;
	int rc;
	uint32_t *stats;
	bool show_hw = true;

	wr = jsonw_new(f);
	jsonw_name(wr, "objects");
	jsonw_start_array(wr);

	if (!fal_plugins_present())
		show_hw = false;

	for (cmd = pd_show_cmd_table; cmd->name; ++cmd) {
		if (name && strcmp(cmd->name, name))
			continue;

		if (subset != PD_OBJ_STATE_LAST) {
			if (show_hw && cmd->get_subset_data)
				rc = cmd->get_subset_data(wr, subset);
			else
				rc = 0;
			jsonw_end_array(wr);
			jsonw_destroy(&wr);
			return rc;
		}

		jsonw_start_object(wr);

		jsonw_name(wr, cmd->name);
		jsonw_start_array(wr);

		if (cmd->get_sw_stats) {
			stats = cmd->get_sw_stats();
			rc = pd_show_obj(wr, "sw-dataplane", stats);
			if (rc)
				RTE_LOG(ERR, DATAPLANE,
					"failed to get SW PD stats for %s\n",
					cmd->name);
		}

		if (show_hw) {
			stats = cmd->get_hw_stats();
			rc = pd_show_obj(wr, "hw", stats);
			if (rc)
				RTE_LOG(ERR, DATAPLANE,
					"failed to get HW PD stats for %s\n",
					cmd->name);
		}
		jsonw_end_array(wr);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);

	return 0;
}

static enum pd_obj_state pd_obj_state_parse(const char *name)
{
	int i;

	for (i = PD_OBJ_STATE_PARTIAL; i < PD_OBJ_STATE_LAST; i++)
		if (strcasecmp(pd_obj_state_names[i], name) == 0)
			return i;

	return PD_OBJ_STATE_LAST;
}

/*
 * pd show dataplane
 *   [{route} [no_resource|no_support|not_needed|partial|error]]
 */
int cmd_pd(FILE *f, int argc, char **argv)
{
	const char *name = NULL;
	enum pd_obj_state subset = PD_OBJ_STATE_LAST;

	if (argc < 3)
		return -1;

	if (strcmp(argv[1], "show") == 0)
		if (strcmp(argv[2], "dataplane") == 0) {

			if (argc >= 4) {
				name = argv[3];
				if (argc >= 5) {
					subset = pd_obj_state_parse(argv[4]);
					if (subset == PD_OBJ_STATE_LAST)
						return -1;
				}
			}
			return pd_show_dataplane(f, name, subset);
		}


	return -1;
}

enum pd_obj_state fal_state_to_pd_state(int fal_state)
{
	switch (fal_state) {
	case 0:
		return PD_OBJ_STATE_FULL;
	case FAL_RC_NOT_REQ:
		return PD_OBJ_STATE_NOT_NEEDED;
	case -ENOSPC:
		return PD_OBJ_STATE_NO_RESOURCE;
	case -EOPNOTSUPP:
		return PD_OBJ_STATE_NO_SUPPORT;
	}
	return PD_OBJ_STATE_ERROR;
}

bool fal_state_is_obj_present(enum pd_obj_state pd_obj_state)
{
	switch (pd_obj_state) {
	case PD_OBJ_STATE_FULL:
	case PD_OBJ_STATE_PARTIAL:
		return true;
	default:
		return false;
	}
}
