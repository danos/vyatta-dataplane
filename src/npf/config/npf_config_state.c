/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "json_writer.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_config_state.h"
#include "npf/config/npf_gen_ruleset.h"
#include "npf/config/npf_rule_group.h"
#include "npf/npf_ruleset.h"
#include "vplane_log.h"

/*
 * This file returns json state.  It can be exercised via the following getree
 * commands:
 *
 * gettree /service/nat json | python -mjson.tool
 * gettree /interfaces/dataplane/dp0p1s1/firewall json | python -mjson.tool
 * gettree /interfaces/dataplane/dp0p1s1/policy json | python -mjson.tool
 *
 * As well as invoking the script directly:
 *
 * /opt/vyatta/sbin/npf-get-state-pbr
 * /opt/vyatta/sbin/npf-get-state-fw
 * /opt/vyatta/sbin/npf-get-state-nat
 *
 * The commands sent to the dataplane are:
 *
 * npf-op state all: fw-in fw-out bridge local
 * npf-op state all: nat64 snat dnat
 * npf-op state all: pbr
 */


static const struct npf_rs_state_subtree {
	const char *subtree[3];
	uint       subtree_count;
} npf_rs_state_subtree[NPF_RS_TYPE_COUNT] =  {
	[NPF_RS_FW_IN] = {
		.subtree = {"firewall", "state", "in"},
		.subtree_count = 3,
	},
	[NPF_RS_FW_OUT] = {
		.subtree = {"firewall", "state", "out"},
		.subtree_count = 3,
	},
	[NPF_RS_LOCAL] = {
		.subtree = {"firewall", "state", "local"},
		.subtree_count = 3,
	},
	[NPF_RS_BRIDGE] = {
		.subtree = {"firewall", "state", "l2"},
		.subtree_count = 3,
	},
	[NPF_RS_PBR] = {
		.subtree = {"policy", "route", "pbr-state"},
		.subtree_count = 3,
	},
	[NPF_RS_DNAT] = {
		.subtree = {"destination", NULL, NULL},
		.subtree_count = 1,
	},
	[NPF_RS_SNAT] = {
		.subtree = {"source", NULL, NULL},
		.subtree_count = 1,
	},
	[NPF_RS_NAT64] = {
		.subtree = {"ipv6-to-ipv4", NULL, NULL},
		.subtree_count = 1,
	},
	[NPF_RS_IPSEC] = {
		.subtree_count = 0,
	},
	[NPF_RS_CUSTOM_TIMEOUT] = {
		.subtree_count = 0,
	},
	[NPF_RS_QOS] = {
		.subtree_count = 0,
	},
	[NPF_RS_SESSION_RPROC] = {
		.subtree_count = 0,
	},
	[NPF_RS_PORTMONITOR_IN] = {
		.subtree_count = 0,
	},
	[NPF_RS_PORTMONITOR_OUT] = {
		.subtree_count = 0,
	},
	[NPF_RS_APPLICATION] = {
		.subtree_count = 0,
	},
	[NPF_RS_NPTV6_IN] = {
		.subtree_count = 0,
	},
	[NPF_RS_NPTV6_OUT] = {
		.subtree_count = 0,
	},
};

/*
 * Generic state context structure.  Used to pass info to walker functions and
 * callbacks.
 */
struct npf_ruleset_state_ctx {
	json_writer_t		*json;
	struct ruleset_select	*sel;
	/* Set false after first ruleset has been added to json */
	bool			first;
	enum npf_ruleset_type	rs_type;
};

/*
 * Start subtree json according to ruleset type
 */
static void npf_show_state_subtree_start(json_writer_t *json,
					 enum npf_ruleset_type rs_type)
{
	const struct npf_rs_state_subtree *st;
	uint i;

	st = &npf_rs_state_subtree[rs_type];

	for (i = 0; i < st->subtree_count; i++) {
		jsonw_name(json, st->subtree[i]);
		jsonw_start_object(json);
	}
}

/*
 * End subtree json according to ruleset type
 */
static void npf_show_state_subtree_end(json_writer_t *json,
				       enum npf_ruleset_type rs_type)
{
	const struct npf_rs_state_subtree *st;
	uint i;

	st = &npf_rs_state_subtree[rs_type];

	for (i = 0; i < st->subtree_count; i++)
		jsonw_end_object(json);
}

/*
 * Callback for each rule in a ruleset
 */
static bool npf_show_state_rule_cb(npf_rule_t *rl, void *ctx)
{
	struct npf_ruleset_state_ctx *info = ctx;
	json_writer_t *json = info->json;
	struct npf_rule_stats rs;

	jsonw_start_object(json);

	jsonw_uint_field(json, "rule-number", npf_rule_get_num(rl));

	rule_sum_stats(rl, &rs);
	jsonw_uint_field(json, "bytes", rs.bytes_ct);
	jsonw_uint_field(json, "packets", rs.pkts_ct);

	jsonw_end_object(json);
	return true;
}

/*
 * Callback for each ruleset of a given type on an attach-point.  Used for
 * interface types (fw-in, fw-out, local, bridge and pbr).  (nat uses a
 * different callback function)
 */
static bool npf_show_state_ruleset_cb(npf_rule_group_t *rg, void *ctx)
{
	struct npf_ruleset_state_ctx *info = ctx;
	json_writer_t *json = info->json;
	const char *group_name = npf_ruleset_get_name(rg);

	if (!group_name)
		group_name = "";

	jsonw_start_object(json);
	jsonw_string_field(json, "group-name", group_name);

	jsonw_name(json, "rule");
	jsonw_start_array(json);

	npf_rules_walk(rg, info->sel, npf_show_state_rule_cb, info);

	jsonw_end_array(json);
	jsonw_end_object(json);

	info->first = false;
	return true;
}

/************************************************************************
 * fw-in, fw-out, local, bridge, pbr
 *
 * "firewall":{
 *   "state":{
 *     "out":{
 *       "name":[
 *         {
 *           "group-name":"FW_OUT1",
 *           "rule":[
 *             {
 *               "rule-number":10,
 *               "bytes":0,
 *               "packets":0
 *             }
 *           ]
 *         }
 *       ]
 *     }
 *   }
 * }
 *
 * "policy":{
 *   "route":{
 *     "pbr-state":{
 *       "name":[
 *         {
 *           "group-name":"PBR11",
 *           "rule":[
 *             {
 *               "rule-number":10,
 *               "bytes":0,
 *               "packets":0
 *             }
 *           ]
 *         }
 *       ]
 *     }
 *   }
 * }
 */

/*
 * npf_show_state_intf_rs
 */
static void npf_show_state_intf_rs(json_writer_t *json,
				   struct npf_config *npf_conf,
				   enum npf_ruleset_type rs_type,
				   struct npf_ruleset_state_ctx *info)
{
	unsigned long rs_type_bit = BIT(rs_type);
	char *ap_name = NULL;
	char *vif = NULL;

	/* Is this ruleset type active on this interface? */
	if (!npf_active(npf_conf, rs_type_bit))
		return;

	/*
	 * Only start the outer json array once we know there is at least one
	 * ruleset.
	 */
	if (info->first) {
		jsonw_name(json, "dataplane");
		jsonw_start_array(json);
		info->first = false;
	}

	/*
	 * Each array element contains a tagnode object and a subtree
	 * containing the rulesets.
	 */
	jsonw_start_object(json);

	/* Work with a copy of the attach point name
	 * so it can be modified in case of a vif.
	 */
	ap_name = strdupa(npf_conf->nc_attach_point);
	if (!ap_name)
		return;

	/* If it's an interface with a dot in the attach point name,
	 * we treat it as interface.vrf
	 */
	if (npf_conf->nc_attach_type == NPF_ATTACH_TYPE_INTERFACE) {
		vif = strchr(ap_name, '.');
		if (vif) {
			/* Change the dot to a null
			 * so we can emit just the interface name.
			 */
			*vif = 0;
		}
	} else if (npf_conf->nc_attach_type == NPF_ATTACH_TYPE_GLOBAL)
		ap_name = (char *) "lo";

	jsonw_string_field(json, "tagnode", ap_name);

	if (vif) {
		/* Start the vif subtree:
		 *
		 *   "vif": [{
		 *       "tagnode": NN,
		 */
		*vif = '.';
		jsonw_name(json, "vif");
		jsonw_start_array(json);
		jsonw_start_object(json);
		jsonw_string_field(json, "tagnode", vif+1);
	}

	npf_show_state_subtree_start(json, rs_type);

	const npf_ruleset_t *ruleset = npf_get_ruleset(npf_conf, rs_type);

	jsonw_name(json, "name");
	jsonw_start_array(json);

	npf_ruleset_group_walk(ruleset, info->sel,
			       npf_show_state_ruleset_cb, info);

	jsonw_end_array(json);

	npf_show_state_subtree_end(json, rs_type);

	if (vif) {
		/* End the vif subtree:
		 *
		 * }]
		 */
		jsonw_end_object(json);
		jsonw_end_array(json);
	}

	jsonw_end_object(json);
}

/*
 * npf_show_state_intf
 */
static void
npf_show_state_intf(json_writer_t *json,
		    struct npf_attpt_item *ap,
		    struct npf_ruleset_state_ctx *info)
{
	struct npf_config **npf_conf_p = npf_attpt_item_up_data_context(ap);
	if (!npf_conf_p)
		return;

	struct npf_config *npf_conf = *npf_conf_p;
	if (!npf_conf)
		return;

	enum npf_ruleset_type rs_type;
	ulong rulesets = info->sel->rulesets;

	/* fw-in, fw-out, local, bridge and/or pbr */
	for (rs_type = 0; rs_type < NPF_RS_TYPE_COUNT; rs_type++)
		if ((rulesets & BIT(rs_type)) != 0)
			npf_show_state_intf_rs(json, npf_conf, rs_type,
					       info);
}

/*
 * "all attach points" callback.
 */
static bool
npf_show_state_intf_cb(struct npf_attpt_item *ap, void *ctx)
{
	struct npf_ruleset_state_ctx *info = ctx;

	npf_show_state_intf(info->json, ap, info);

	return true;
}

/*
 * npf_show_ruleset_state_intf
 *
 * Show firewall or pbr state for one or all interface attach-points.
 */
static int
npf_show_ruleset_state_intf(json_writer_t *json, struct ruleset_select *sel)
{
	struct npf_ruleset_state_ctx info = {
		.json	= json,
		.sel	= sel,
		.first	= true,
	};

	jsonw_pretty(json, true);

	if (sel->attach_type == NPF_ATTACH_TYPE_ALL) {
		npf_attpt_item_walk_up(npf_show_state_intf_cb, &info);
	} else {
		struct npf_attpt_item *ap;

		if (npf_attpt_item_find_up(sel->attach_type,
					   sel->attach_point, &ap) >= 0) {
			npf_show_state_intf(json, ap, &info);
		}
	}

	/*
	 * Was the "dataplane" outer json array started in
	 * npf_show_state_intf_rs?  Is so, then we need to end it.
	 */
	if (!info.first)
		jsonw_end_array(json);

	return 0;
}

/************************************************************************
 * SNAT, DNAT, NAT64, NAT46
 *
 * The format of nat state is different from firewall.  There is a single
 * ruleset per interface attach point, and rule numbers are unique globally
 * (are they really?).  So we walk all dnat attach points and format a single
 * array of dnat rulesets, then do the same for snat and nat64. e.g.
 *
 * {
 *   "destination":{
 *     "rule":[
 *       {
 *         "rule-number":10,
 *         "bytes":0,
 *         "packets":0
 *       },
 *       {
 *         "rule-number":20,
 *         "bytes":0,
 *         "packets":0
 *       }
 *     ]
 *   }
 * }
 */

/*
 * Callback for each ruleset of a given type on an attach-point.  Used for
 * snat, dnat, nat64 and nat46.
 *
 * This differs from npf_show_state_ruleset_cb in that we place rulesets from
 * multiple attach points into the same 'rule' array.
 */
static bool
npf_show_state_nat_ruleset_cb(npf_rule_group_t *rg, void *ctx)
{
	struct npf_ruleset_state_ctx *info = ctx;
	json_writer_t *json = info->json;

	if (info->first) {
		/* start subtree */
		npf_show_state_subtree_start(json, info->rs_type);

		jsonw_name(json, "rule");
		jsonw_start_array(json);

		info->first = false;
	}

	npf_rules_walk(rg, info->sel, npf_show_state_rule_cb, info);

	return true;
}

static void
npf_show_state_nat_rs(json_writer_t *json __unused,
		      struct npf_config *npf_conf,
		      enum npf_ruleset_type rs_type,
		      struct npf_ruleset_state_ctx *info)
{
	unsigned long rs_type_bit = BIT(rs_type);

	if (!npf_active(npf_conf, rs_type_bit))
		return;

	const npf_ruleset_t *ruleset = npf_get_ruleset(npf_conf, rs_type);

	npf_ruleset_group_walk(ruleset, info->sel,
			       npf_show_state_nat_ruleset_cb, info);
}

/*
 * npf_show_state_nat
 *
 * snat, dnat, nat64, nat46
 */
static void
npf_show_state_nat(json_writer_t *json, struct npf_attpt_item *ap,
		   struct npf_ruleset_state_ctx *info)
{
	struct npf_config **npf_conf_p = npf_attpt_item_up_data_context(ap);
	if (!npf_conf_p)
		return;

	struct npf_config *npf_conf = *npf_conf_p;
	if (!npf_conf)
		return;

	npf_show_state_nat_rs(json, npf_conf, info->rs_type, info);
}

static bool
npf_show_state_nat_cb(struct npf_attpt_item *ap, void *ctx)
{
	struct npf_ruleset_state_ctx *info = ctx;

	npf_show_state_nat(info->json, ap, info);
	return true;
}

/*
 * npf_show_ruleset_state_nat
 */
static int
npf_show_ruleset_state_nat(json_writer_t *json, struct ruleset_select *sel)
{
	struct npf_ruleset_state_ctx info = {
		.json	= json,
		.sel	= sel,
		.first	= true,
	};

	jsonw_pretty(json, true);

	enum npf_ruleset_type rs_type;

	for (rs_type = 0; rs_type < NPF_RS_TYPE_COUNT; rs_type++) {
		if ((sel->rulesets & BIT(rs_type)) == 0)
			continue;

		info.rs_type = rs_type;
		info.first = true;

		if (sel->attach_type == NPF_ATTACH_TYPE_ALL) {
			npf_attpt_item_walk_up(npf_show_state_nat_cb, &info);
		} else {
			struct npf_attpt_item *ap;
			if (npf_attpt_item_find_up(
				    sel->attach_type,
				    sel->attach_point, &ap) >= 0) {
				npf_show_state_nat(json, ap, &info);
			}
		}

		if (!info.first) {
			/* end "rule" array */
			jsonw_end_array(json);

			/* end subtree */
			npf_show_state_subtree_end(json, rs_type);
		}
	}

	return 0;
}

/*
 * npf_show_ruleset_state
 *
 * Returned state is dependent on ruleset type, which reflects where the
 * corresponding config exists in the tree.
 */
#define RULESET_INTF (NPF_FW_IN | NPF_FW_OUT | NPF_BRIDGE | NPF_LOCAL | NPF_PBR)
#define RULESET_NAT  (NPF_SNAT | NPF_DNAT | NPF_NAT64 | NPF_NAT46)

int
npf_show_ruleset_state(FILE *fp, struct ruleset_select *sel)
{
	json_writer_t *json = jsonw_new(fp);

	if (json == NULL) {
		RTE_LOG(ERR, DATAPLANE, "failed to create json stream\n");
		return -ENOMEM;
	}

	if ((sel->rulesets & RULESET_INTF) != 0) {
		npf_show_ruleset_state_intf(json, sel);
		goto done;
	}

	if ((sel->rulesets & RULESET_NAT) != 0) {
		npf_show_ruleset_state_nat(json, sel);
		goto done;
	}

done:
	jsonw_destroy(&json);
	return 0;
}
