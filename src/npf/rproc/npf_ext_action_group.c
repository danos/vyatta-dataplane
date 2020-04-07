/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <czmq.h>
#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "compiler.h"
#include "json_writer.h"
#include "npf/npf.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_rule_group.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_ruleset.h"
#include "npf/rproc/npf_ext_action_group.h"
#include "npf/rproc/npf_rproc.h"
#include "qos.h"
#include "vplane_log.h"

struct ifnet;
struct rte_mbuf;
struct subport_info;

#define RULE_ARGS	128
#define	PREFIX_STR	"rproc="
#define	CMD_POS		6	/* rproc= */
#define	MARKDSCP_ARGS	15	/* rproc=markdscp( */
#define	MARKPCP_ARGS	14	/* rproc=markpcp( */
#define	POLICE_ARGS	8	/* policer( */
char MARKDSCP_CMD[] = "markdscp";
char MARKPCP_CMD[] = "markpcp";
char POLICER_CMD[] = "policer";

struct npf_act_grp {
	char *name;
	void *policer_hndl;
	bool (*policer_action)(npf_cache_t *npc,
			       struct rte_mbuf **nbuf,
			       void *handle,
			       npf_session_t *se,
			       npf_rproc_result_t *result);
	bool (*mark_action)(npf_cache_t *npc,
			    struct rte_mbuf **nbuf,
			    void *handle,
			    npf_session_t *se,
			    npf_rproc_result_t *result);
	enum {
		MARK_UNDEF,
		MARK_DSCP,
		MARK_PCP
	} mark_type;
	void *mark_hndl;
	uint8_t refcnt;
	bool setup;
	npf_rule_t *rl;
	struct npf_act_grp *next;        /* Different action groups by name */
	struct subport_info *subport;
};


static struct npf_act_grp *
npf_action_group_find(struct subport_info *subport, const char *name)
{
	struct npf_act_grp *ptr;

	for (ptr = qos_ag_get_head(subport); ptr; ptr = ptr->next) {
		if (!strcmp(ptr->name, name))
			break;
	}
	return ptr;
}

static void
npf_action_group_add(struct subport_info *subport, struct npf_act_grp *ptr)
{
	struct npf_act_grp *tptr;

	ptr->subport = subport;

	tptr = qos_ag_set_or_get_head(subport, ptr);
	if (!tptr)
		return;

	for ( ; tptr->next; tptr = tptr->next)
		;

	tptr->next = ptr;
}

static bool
npf_action_group_cb(void *param, struct npf_cfg_rule_walk_state *state)
{
	char rule_args[RULE_ARGS];
	char *mark_ptr = NULL, *pol_ptr = NULL;
	const char *copy_ptr;
	struct npf_act_grp *act_grp = param;
	int i = 0, j = CMD_POS;
	const npf_rproc_ops_t *ops;

	/*
	 * The rule should be:
	 *
	 *   "rproc=[markdscp|markpcp(x)];[policer(x,x,x,x[,x],x)]"
	 *
	 * The mark and police are optional, however we shouldn't be here if
	 * at least one isn't configured. NB order should always be mark then
	 * police, or mark or police only.
	 */
	if (strncmp(&(state->rule[0]), PREFIX_STR, CMD_POS))
		goto format_err;

	if (!strncmp(&(state->rule[CMD_POS]), "markdscp(", 9)) {
		for (mark_ptr = &rule_args[0],
		     copy_ptr = &(state->rule[MARKDSCP_ARGS]);
		     i < RULE_ARGS && *(copy_ptr + i) != ')'; i++)
			mark_ptr[i] = state->rule[MARKDSCP_ARGS + i];

		if (i < RULE_ARGS)
			mark_ptr[i++] = '\0';
		j = (MARKDSCP_ARGS + i + 1); /* add 1 to skip ; */
		act_grp->mark_type = MARK_DSCP;

	} else if (!strncmp(&(state->rule[CMD_POS]), "markpcp(", 8)) {
		for (mark_ptr = &rule_args[0],
		     copy_ptr = &(state->rule[MARKPCP_ARGS]);
		     i < RULE_ARGS && *(copy_ptr + i) != ')'; i++)
			mark_ptr[i] = state->rule[MARKPCP_ARGS + i];

		if (i < RULE_ARGS)
			mark_ptr[i++] = '\0';
		j = (MARKPCP_ARGS + i + 1); /* add 1 to skip ; */
		act_grp->mark_type = MARK_PCP;
	}

	if (i >= RULE_ARGS)
		goto format_err;

	if (!strncmp(&(state->rule[j]), "policer(", POLICE_ARGS)) {
		copy_ptr = &(state->rule[j + POLICE_ARGS]); /* policer args */
		pol_ptr = &rule_args[i];
		i = RULE_ARGS - i; /* space left */
		for (j = 0; copy_ptr[j] != ')'; j++) {
			if (j >= i)
				goto format_err;
			pol_ptr[j] = copy_ptr[j];
		}

		pol_ptr[j] = '\0';
	}

	RTE_LOG(DEBUG, QOS,
		"name %s rule %s\n", act_grp->name, state->rule);

	if (act_grp->mark_type == MARK_DSCP) {
		ops = npf_find_rproc_by_id(NPF_RPROC_ID_MARKDSCP);
		if (!ops)
			goto ops_err;

		if (npf_create_rproc(ops, act_grp->rl, mark_ptr,
				     &(act_grp->mark_hndl)))
			goto ops_err;
		act_grp->mark_action = ops->ro_action;
	} else if (act_grp->mark_type == MARK_PCP) {
		ops = npf_find_rproc_by_id(NPF_RPROC_ID_MARKPCP);
		if (!ops)
			goto ops_err;

		if (npf_create_rproc(ops, act_grp->rl, mark_ptr,
				     &(act_grp->mark_hndl)))
			goto ops_err;
		act_grp->mark_action = ops->ro_action;
	}
	if (pol_ptr) {
		ops = npf_find_rproc_by_id(NPF_RPROC_ID_POLICER);
		if (!ops)
			goto ops_err;
		if (npf_create_rproc(ops, act_grp->rl, pol_ptr,
				     &act_grp->policer_hndl))
			goto ops_err;
		act_grp->policer_action = ops->ro_action;
	}

	act_grp->setup = true;
	return true;

ops_err:
	RTE_LOG(ERR, QOS, "rproc ops lookup failure'%s'\n", state->rule);
	return false;

format_err:
	RTE_LOG(ERR, QOS, "Invalid rule format '%s'\n", state->rule);
	return false;
}

static bool
npf_action_group_getinfo(const char *name, struct npf_act_grp *act_grp)
{
	npf_cfg_rule_group_walk(NPF_RULE_CLASS_ACTION_GROUP, name, act_grp,
				npf_action_group_cb);

	return true;
}

static int
npf_action_group_create(npf_rule_t *rl, const char *params, void **handle)
{
	struct npf_act_grp *act_grp;
	int len;
	enum npf_attach_type attach_type;
	const char *attach_point;
	int ret;
	struct subport_info *subport;
	struct ifnet *ifp;

	ret = npf_rule_get_attach_point(rl, &attach_type, &attach_point);
	if (ret) {
		RTE_LOG(ERR, QOS, "Failed to attached to target\n");
		return -ENOENT;
	}
	if (attach_type != NPF_ATTACH_TYPE_QOS) {
		RTE_LOG(ERR, QOS, "Invalid attach type\n");
		return -EINVAL;
	}

	subport = qos_get_subport(attach_point, &ifp);
	if (!subport) {
		RTE_LOG(ERR, QOS, "Failed to find subport\n");
		return -ENOENT;
	}

	/*
	 * Check to see if we have the action-group already associated
	 * with this target.  If we do return it since it'll be sharing
	 * the feature between the rules.
	 */
	act_grp = npf_action_group_find(subport, params);
	if (act_grp) {
		act_grp->refcnt++;
		RTE_LOG(DEBUG, QOS,
			"Action-group %s already attached %s refs %d\n",
			params, attach_point, act_grp->refcnt);
		*handle = act_grp;
		return 0;
	}

	len = strlen(params);
	act_grp = zmalloc(sizeof(struct npf_act_grp) + len + 1);
	if (!act_grp) {
		RTE_LOG(ERR, QOS, "out of memory\n");
		return -ENOMEM;
	}

	act_grp->name = (char *)act_grp + sizeof(*act_grp);
	strncpy(act_grp->name, params, len);
	act_grp->refcnt = 1;
	act_grp->rl = rl;

	/*
	 * This adds the action_group structure to the subport.
	 * It's then freed along with the subport.
	 * The call to setup the rprocs is driven by npf_action_group_getinfo
	 * via npf.  So we let npf control the allocation/deletion of the
	 * rproc resources.
	 */
	npf_action_group_add(subport, act_grp);
	npf_action_group_getinfo(params, act_grp);

	RTE_LOG(DEBUG, QOS, "action-group %s target %s added\n",
		params, attach_point);

	*handle = act_grp;

	return 0;
}

static void
npf_action_group_destroy(void *handle)
{
	struct npf_act_grp *act_grp = handle;

	if (!act_grp) {
		RTE_LOG(ERR, QOS, "Invalid action-group destroy, NULL\n");
		return;
	}

	/* Only free the action-group once all references are removed */
	if (--act_grp->refcnt) {
		RTE_LOG(DEBUG, QOS, "action-group %s destroy refcnt %d\n",
			act_grp->name, act_grp->refcnt);
		return;
	}

	if (act_grp->policer_hndl) {
		const npf_rproc_ops_t *ops;

		ops = npf_find_rproc_by_id(NPF_RPROC_ID_POLICER);
		if (ops)
			npf_destroy_rproc(ops, act_grp->policer_hndl);
	}
	RTE_LOG(DEBUG, QOS, "Action-group %s removed\n", act_grp->name);

	free(act_grp);
}

static bool
npf_action_group(npf_cache_t *npc, struct rte_mbuf **nbuf, void *arg,
		 npf_session_t *se __unused, npf_rproc_result_t *result)
{
	struct npf_act_grp *act_grp = arg;

	/* Ignore dropped packets */
	if (result->decision == NPF_DECISION_BLOCK)
		return true;

	/* Assume this is a setup problem */
	if (unlikely(act_grp == NULL)) {
		result->decision = NPF_DECISION_BLOCK;
		RTE_LOG(ERR, QOS, "NULL action-group\n");
		return true;
	}

	if (act_grp->mark_action) {
		act_grp->mark_action(npc, nbuf, act_grp->mark_hndl,
				     se, result);
	}

	if (act_grp->policer_action) {
		act_grp->policer_action(npc, nbuf, act_grp->policer_hndl,
					se, result);
	}
	return true;
}

static void
npf_action_group_clear_stats(void *arg)
{
	struct npf_act_grp *act_grp = arg;

	if (!act_grp->setup)
		return;

	if (act_grp->policer_hndl) {
		const npf_rproc_ops_t *ops;

		ops = npf_find_rproc_by_id(NPF_RPROC_ID_POLICER);
		if (ops)
			ops->ro_clear_stats(act_grp->policer_hndl);
	}
}

void
npf_action_group_show(json_writer_t *wr, struct npf_act_grp *ptr,
		      const char *name)
{
	struct npf_act_grp *act_grp = ptr;
	char handle[20];

	while (act_grp) {
		jsonw_start_object(wr);
		jsonw_string_field(wr, "name", act_grp->name);
		jsonw_string_field(wr, "subport", name);
		jsonw_uint_field(wr, "refs", (unsigned int)act_grp->refcnt);
		jsonw_uint_field(wr, "mark_type",
				 (unsigned int)act_grp->mark_type);
		sprintf(handle, "%p", act_grp->mark_hndl);
		jsonw_string_field(wr, "mark", handle);
		sprintf(handle, "%p", act_grp->policer_hndl);
		jsonw_string_field(wr, "policer", handle);

		jsonw_end_object(wr);
		act_grp = act_grp->next;
	}
}

static bool
npf_action_group_rule_cb(void *param, struct npf_cfg_rule_walk_state *state)
{
	char buf[sizeof("4294967296")];
	json_writer_t *json = param;

	snprintf(buf, sizeof(buf), "%u", state->index);
	jsonw_name(json, buf);
	jsonw_start_object(json);

	jsonw_string_field(json, "rule", state->rule);

	jsonw_end_object(json);

	return true;
}

void npf_action_group_show_policer(struct npf_act_grp *act_grp,
				   struct qos_show_context *context)
{
	json_writer_t *wr = context->wr;

	do {
		if (act_grp->policer_hndl)
			policer_show(wr, act_grp->policer_hndl);
		act_grp = act_grp->next;
	} while (act_grp);
}

static void
npf_action_group_json(json_writer_t *json, npf_rule_t *rl __unused,
		      const char *params __unused, void *handle)
{
	if (!handle)
		return;

	struct npf_act_grp *act_grp = handle;

	if (!act_grp->setup)
		return;

	jsonw_string_field(json, "name", act_grp->name);

	jsonw_name(json, "rules");
	jsonw_start_object(json);
	npf_cfg_rule_group_walk(NPF_RULE_CLASS_ACTION_GROUP,
				act_grp->name, json,
				npf_action_group_rule_cb);
	jsonw_end_object(json);

	if (act_grp->policer_hndl) {
		jsonw_name(json, "policer");
		jsonw_start_object(json);
		npf_policer_json(json, NULL, NULL, act_grp->policer_hndl);
		jsonw_end_object(json);
	}

	if (act_grp->mark_type == MARK_PCP) {
		jsonw_name(json, "markpcp");
		jsonw_start_object(json);
		npf_markpcp_json(json, NULL, NULL, act_grp->mark_hndl);
		jsonw_end_object(json);
	}
}

const npf_rproc_ops_t npf_action_group_ops = {
	.ro_name   = "action-group",
	.ro_type   = NPF_RPROC_TYPE_ACTION,
	.ro_id     = NPF_RPROC_ID_ACTIONGRP,
	.ro_bidir  = false,
	.ro_ctor   = npf_action_group_create,
	.ro_dtor   = npf_action_group_destroy,
	.ro_action = npf_action_group,
	.ro_clear_stats = npf_action_group_clear_stats,
	.ro_json   = npf_action_group_json,
};
