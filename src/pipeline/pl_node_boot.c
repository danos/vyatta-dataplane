/*
 * pl_node_boot.c
 *
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <czmq.h>
#include <limits.h>
#include <rte_debug.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include "json_writer.h"
#include "pl_commands.h"
#include "pl_common.h"
#include "pl_internal.h"
#include "util.h"
#include "vplane_log.h"

#ifdef FUSED_MODE
#include "pl_fused_gen.h"
#else
#define PL_NODE_NUM_IDS 0
#endif

zhash_t *g_pl_opcmds;

TAILQ_HEAD(pl_node_reg_list_head, pl_node_registration);
TAILQ_HEAD(pl_feat_reg_list_head, pl_feature_registration);

struct pl_node_reg_list_head pl_node_reg_list =
	TAILQ_HEAD_INITIALIZER(pl_node_reg_list);

struct pl_feat_reg_list_head pl_feature_reg_list =
	TAILQ_HEAD_INITIALIZER(pl_feature_reg_list);

void
pl_add_node_registration(struct pl_node_registration *node)
{
	if (!node->name)
		rte_panic("pipeline node name is required\n");
	if (!strchr(node->name, ':'))
		rte_panic("domain missing from pipeline node name %s\n",
			  node->name);

	pl_gen_fused_init(node);

	TAILQ_INSERT_TAIL(&pl_node_reg_list, node, links);
}

/*
 * Parse the domain out of a name and domain string separated by a
 * colon.
 */
static char *parse_domain(const char *name)
{
	const char *colon;
	size_t domain_len;
	char *domain;

	colon = strchr(name, ':');
	if (!colon)
		return NULL;

	domain_len = colon - name;
	domain = malloc(domain_len + 1);
	if (!domain)
		return NULL;
	memcpy(domain, name, domain_len);
	domain[domain_len] = '\0';
	return domain;
}

/*
 * Construct a name and domain string separated by a colon based on
 * either a fully specified name and domain, or a name only and
 * inferring the domain from another source.
 */
static char *construct_name_and_domain(const char *name,
				       const char *default_domain)
{
	char *name_and_domain;
	const char *colon;
	size_t domain_len;
	size_t name_len;

	colon = strchr(name, ':');
	if (colon)
		return strdup(name);

	name_len = strlen(name);
	domain_len = strlen(default_domain);

	name_and_domain = malloc(domain_len + 1 + name_len + 1);
	if (!name_and_domain)
		return NULL;
	memcpy(name_and_domain, default_domain, domain_len);
	name_and_domain[domain_len] = ':';
	memcpy(name_and_domain + domain_len + 1, name, name_len);
	name_and_domain[domain_len + 1 + name_len] = '\0';
	return name_and_domain;
}

static void
pl_feature_node_validate_static_id(struct pl_feature_registration *feat,
				   zhashx_t *feat_name_hash)
{
	struct pl_feature_registration *before_feat;
	struct pl_feature_registration *after_feat;
	char *default_domain = parse_domain(feat->name);
	char *before_feat_name;
	char *after_feat_name;

	if (!default_domain)
		rte_panic("unable to allocate default domain\n");

	if (feat->visit_before) {
		before_feat_name = construct_name_and_domain(
			feat->visit_before, default_domain);
		before_feat = zhashx_lookup(feat_name_hash,
					    before_feat_name);
		if (!before_feat)
			RTE_LOG(WARNING, DATAPLANE,
				"unknown before feature %s for feature %s\n",
				before_feat_name, feat->name);
		if (before_feat && before_feat->id <= feat->id)
			rte_panic(
				"id %u of before feature %s is not less than id %u of feature %s\n",
				before_feat->id,
				before_feat_name, feat->id,
				feat->name);
		free(before_feat_name);
	}
	if (feat->visit_after) {
		after_feat_name = construct_name_and_domain(
			feat->visit_after, default_domain);
		after_feat = zhashx_lookup(feat_name_hash,
					   after_feat_name);
		if (!after_feat)
			RTE_LOG(WARNING, DATAPLANE,
				"unknown after feature %s for feature %s\n",
				after_feat_name, feat->name);
		if (after_feat && after_feat->id >= feat->id)
			rte_panic(
				"id %u of after feature %s is not greater than id %u of feature %s\n",
				after_feat->id,
				after_feat_name, feat->id,
				feat->name);
		free(after_feat_name);
	}

	free(default_domain);
}

static void
pl_feature_node_alloc_id(struct pl_feature_registration *feat,
			 zhashx_t *feat_name_hash)
{
	struct pl_feature_registration *before_feat = NULL;
	struct pl_feature_registration *after_feat = NULL;
	char *default_domain = parse_domain(feat->name);
	char *before_feat_name;
	char *after_feat_name;
	unsigned int max = UINT_MAX;
	unsigned int min = 0;
	unsigned int id;

	if (!default_domain)
		rte_panic("unable to allocate default domain\n");

	if (feat->visit_before) {
		before_feat_name = construct_name_and_domain(
			feat->visit_before, default_domain);
		before_feat = zhashx_lookup(feat_name_hash,
					    before_feat_name);
		if (before_feat)
			max = before_feat->id - 1;
		else
			RTE_LOG(WARNING, DATAPLANE,
				"unknown before feature %s for feature %s\n",
				before_feat_name, feat->name);
		free(before_feat_name);
	}
	if (feat->visit_after) {
		after_feat_name = construct_name_and_domain(
			feat->visit_after, default_domain);
		after_feat = zhashx_lookup(feat_name_hash,
					   after_feat_name);
		if (after_feat)
			min = after_feat->id + 1;
		else
			RTE_LOG(WARNING, DATAPLANE,
				"unknown after feature %s for feature %s\n",
				after_feat_name, feat->name);
		free(after_feat_name);
	}

	free(default_domain);

	/*
	 * if min == max + 1 then that means that the constraints are
	 * valid, but there's no space so don't treat that as a
	 * constraint error
	 */
	if (before_feat && after_feat && min > max + 1)
		rte_panic(
			"id %u of before feature %s is greater than id %u of after feature %s for feature declaration %s\n",
			before_feat->id, before_feat_name,
			after_feat->id, after_feat_name, feat->name);


	for (id = min; id <= max; id++) {
		/* id 0 is reserved */
		if (id == 0)
			continue;

		/* candidate id already allocated */
		if (feat->node->max_feature_reg_idx > id &&
		    feat->node->feature_regs[id])
			continue;

		/* found an unallocated id */
		feat->id = id;
		feat->dynamic = true;
		return;
	}


	rte_panic(
		"no available id for feature %s %s%s%s%s\n",
		feat->name, feat->visit_before ? "before " : "",
		feat->visit_before ? feat->visit_before : "",
		feat->visit_after ? "after " : "",
		feat->visit_after ? feat->visit_after : "");
}

void
pl_graph_validate(void)
{
	struct pl_node_registration *feat_point_node;
	struct pl_node_registration *next_node;
	zhashx_t *feat_name_hash = zhashx_new();
	struct pl_feature_registration *feat;
	struct pl_node_registration *node;
	zhashx_t *name_hash = zhashx_new();
	char *default_domain;
	uint16_t next_idx;
	char *node_name;
	int next_dyn_node_id = PL_NODE_NUM_IDS;

	if (!name_hash)
		rte_panic("unable to allocate pipeline graph node name hash\n");
	if (!feat_name_hash)
		rte_panic(
			"unable to allocate pipeline graph feature name hash\n");

	TAILQ_FOREACH(node, &pl_node_reg_list, links)
		if (zhashx_insert(name_hash, node->name, node) == -1)
			rte_panic("duplicate node name %s\n", node->name);

	TAILQ_FOREACH(node, &pl_node_reg_list, links) {
		switch (node->type) {
		case PL_CONTINUE:
		case PL_OUTPUT:
			if (node->num_next)
				rte_panic(
					"%s pipeline node %s cannot have next nodes\n",
					node->type == PL_CONTINUE ? "continue" :
					"output",
					node->name);
			break;
		case PL_PROC:
			break;
		default:
			rte_panic("invalid type %d for pipeline node %s\n",
				  node->type, node->name);
		}

		default_domain = parse_domain(node->name);
		if (!default_domain)
			rte_panic("unable to allocate default domain\n");
		node->next_nodes = malloc_aligned(
			node->num_next * sizeof(*node->next_nodes));
		if (!node->next_nodes)
			rte_panic(
				"unable to allocate node next_nodes\n");
		for (next_idx = 0; next_idx < node->num_next; next_idx++) {
			char *next_node_name = construct_name_and_domain(
				node->next[next_idx], default_domain);

			next_node = zhashx_lookup(name_hash, next_node_name);
			if (!next_node)
				rte_panic("unknown next node %s for node %s\n",
					  next_node_name, node->name);
			node->next_nodes[next_idx] = next_node;
			free(next_node_name);
		}
		free(default_domain);

		if (!node->node_decl_id)
			node->node_decl_id = next_dyn_node_id++;
	}

	TAILQ_FOREACH(feat, &pl_feature_reg_list, links) {
		default_domain = parse_domain(feat->name);
		if (zhashx_insert(feat_name_hash, feat->name, feat) == -1)
			rte_panic("duplicate feature name %s\n",
				  feat->name);
		node_name = construct_name_and_domain(
			feat->node_name, default_domain);
		node = zhashx_lookup(name_hash, node_name);
		if (!node)
			rte_panic("unknown node %s for feature %s\n",
				  node_name, feat->name);
		free(node_name);
		feat->node = node;
		node_name = construct_name_and_domain(
			feat->feature_point, default_domain);
		node = zhashx_lookup(name_hash, node_name);
		if (!node)
			rte_panic(
				"unknown feature point node %s for feature %s\n",
				node_name, feat->name);
		free(node_name);
		feat->feature_point_node = node;
		free(default_domain);
	}

	/* check feature point constraints */
	TAILQ_FOREACH(feat, &pl_feature_reg_list, links) {
		if (feat->id)
			pl_feature_node_validate_static_id(feat,
							   feat_name_hash);
		else
			pl_feature_node_alloc_id(feat, feat_name_hash);
		feat_point_node = feat->feature_point_node;
		if (feat_point_node->max_feature_reg_idx <= feat->id) {
			struct pl_feature_registration **new_feature_regs;

			new_feature_regs = zmalloc_aligned(
				sizeof(*new_feature_regs) *
				(feat->id + 1));
			if (!new_feature_regs)
				rte_panic(
					"unable to allocate feature registrations for node %s\n",
					feat_point_node->name);
			memcpy(new_feature_regs, feat_point_node->feature_regs,
			       sizeof(*new_feature_regs) *
			       feat_point_node->max_feature_reg_idx);
			free(feat_point_node->feature_regs);
			feat_point_node->feature_regs = new_feature_regs;
			feat_point_node->max_feature_reg_idx =
				feat->id + 1;
		}
		if (feat_point_node->feature_regs[feat->id])
			rte_panic(
				"duplicate ids for features %s and %s\n",
				feat->name,
				feat_point_node->feature_regs[feat->id]->name);
		feat_point_node->feature_regs[feat->id] = feat;
	}

	zhashx_destroy(&name_hash);
	zhashx_destroy(&feat_name_hash);

	g_pl_node_stats = zmalloc_aligned(sizeof(uint64_t) *
					  RTE_MAX_LCORE *
					  next_dyn_node_id);
	if (!g_pl_node_stats)
		rte_panic("out of memory allocating pipeline stats\n");
}

void
pl_add_node_command(struct pl_node_command *cmd)
{
	char *toks = strdupa(cmd->cmd);

	if (!g_pl_opcmds)
		g_pl_opcmds = zhash_new();

	pl_recurse_cmds(g_pl_opcmds, cmd, toks);
}

void
pl_add_feature_registration(struct pl_feature_registration *feat)
{
	if (!feat->name)
		rte_panic("pipeline feature name is required\n");
	if (!strchr(feat->name, ':'))
		rte_panic("domain missing from pipeline feature name %s\n",
			  feat->name);

	TAILQ_INSERT_TAIL(&pl_feature_reg_list, feat, links);
}

void
pl_dump_nodes(json_writer_t *json)
{
	struct pl_feature_registration *feat;
	struct pl_node_registration *node;

	jsonw_name(json, "node");
	jsonw_start_object(json);
	TAILQ_FOREACH(node, &pl_node_reg_list, links) {
		jsonw_name(json, node->name);
		jsonw_start_object(json);
		jsonw_uint_field(json, "pkt-count",
				 pl_get_node_stats(node->node_decl_id));
		jsonw_string_field(json, "disable",
				   node->disable ? "true" : "false");
		jsonw_name(json, "next");
		jsonw_start_array(json);
		int i;
		for (i = 0; i < node->num_next; ++i)
			jsonw_string(json, node->next[i]);
		jsonw_end_array(json);
		jsonw_end_object(json);
	}
	jsonw_end_object(json);

	jsonw_name(json, "feature");
	jsonw_start_object(json);
	TAILQ_FOREACH(feat, &pl_feature_reg_list, links) {
		if (feat && feat->name) {
			jsonw_name(json, feat->name);
			jsonw_start_object(json);
			jsonw_string_field(
					   json, "node-name", feat->node_name);
			jsonw_string_field(json, "feature-point",
					   feat->feature_point_node->name);
			if (feat->visit_before)
				jsonw_string_field
					(json, "before", feat->visit_before);
			if (feat->visit_after)
				jsonw_string_field
					(json, "after", feat->visit_after);
			jsonw_end_object(json);
		}
	}
	jsonw_end_object(json);
}
