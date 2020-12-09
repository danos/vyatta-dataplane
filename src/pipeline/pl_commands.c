/*
 * pl_commands.c
 *
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"
#include "feature_commands.h"
#include "pl_commands.h"
#include "pl_common.h"
#include "pl_internal.h"

#include "vplane_log.h"

#include "protobuf.h"
#include "protobuf/PipelineStatsConfig.pb-c.h"

struct pl_cmd_entry {
	zhash_t *next;
	pl_cmd_proc *handler;
	uint32_t version;
};

/*
 * Command error
 *
 * cmd->fp may be NULL if a command is deferred and then replayed, for
 * example after an interface event.
 */
__attribute__((format(printf, 2, 3)))
void pl_cmd_err(struct pl_command *cmd, const char *fmt, ...)
{
	if (!cmd || !cmd->fp)
		return;

	va_list args;

	va_start(args, fmt);
	vfprintf(cmd->fp, fmt, args);
	va_end(args);
}

/*
 * This function reads in the initialized registered pl data
 * defined in this file to build up a nested hash of hashes
 * n-level tree. Each node in the hash is a unique keyword
 * with an optional function ptr or handler.
 *
 * The intent here is that any user issued command matches
 * against deepest matching node with a command handler.
 */
void
pl_recurse_cmds(zhash_t *cmds, const struct pl_node_command *c, char *toks)
{
	const char *tok;

	tok = strsep(&toks, " ");

	if (tok) {
		if (!zhash_lookup(cmds, tok)) {
			struct pl_cmd_entry *c_entry =
				calloc(sizeof(struct pl_cmd_entry), 1);
			c_entry->next = zhash_new();
			c_entry->version = c->version;
			zhash_insert(cmds, tok, c_entry);
		}
		struct pl_cmd_entry *c_entry = zhash_lookup(cmds, tok);
		if (toks == NULL)
			c_entry->handler = c->handler;
		pl_recurse_cmds(c_entry->next, c, toks);
	}
}

static int
pl_cmd_pipeline(FILE *f, int argc, char **argv, zhash_t *cmd_tree)
{
	if (!cmd_tree) {
		fprintf(f, "unknown command");
		return -1;
	}

	/* skip over "pipeline" initial level */
	--argc; ++argv;

	struct pl_cmd_entry *last_cmd_entry = NULL;
	int tokid;
	int depth = 0;
	for (tokid = 0; tokid < argc; ++tokid) {
		char *tok = argv[tokid];

		struct pl_cmd_entry *c_entry = zhash_lookup(cmd_tree, tok);
		if (c_entry) {
			if (c_entry->handler) {
				last_cmd_entry = c_entry;
				depth = tokid + 1;
			}
			cmd_tree = c_entry->next;
		}
	}

	while (depth != 0) {
		--argc; ++argv;
		--depth;
	}

	if (last_cmd_entry) {
		struct pl_command cmd = {.fp = f,
					 .argc = argc,
					 .argv = argv};
		return last_cmd_entry->handler(&cmd);
	}
	fprintf(f, "unknown command");
	return -1;
}

int
op_pipeline(FILE *f, int argc, char **argv)
{
	return pl_cmd_pipeline(f, argc, argv, g_pl_opcmds);
}


static int
cmd_pipeline_show_nodes(struct pl_command *cmd)
{
	json_writer_t *json = jsonw_new(cmd->fp);
	if (!json)
		return 0;

	jsonw_name(json, "pl-framework");
	jsonw_start_object(json);

	pl_dump_nodes(json);

	jsonw_end_object(json);
	jsonw_destroy(&json);
	return 0;
}

static void list_all_pipeline_versions(FILE *f, zhash_t *cmds)
{
	struct pl_cmd_entry *cmd;

	cmd = zhash_first(cmds);
	while (cmd) {
		fprintf(f, "pl_%s %u\n", zhash_cursor(cmds), cmd->version);
		cmd = zhash_next(cmds);
	}
}

void list_all_pipeline_msg_versions(FILE *f)
{
	list_all_pipeline_versions(f, g_pl_opcmds);
}

PL_REGISTER_OPCMD(pipeline_show_nodes) = {
	.cmd = "framework dump nodes",
	.handler = cmd_pipeline_show_nodes,
};

/* pipeline statistics config commands
 */
static int cmd_pipeline_stats_cfg(struct pb_msg *msg)
{
	void *payload = (void *)((char *)msg->msg);
	int len = msg->msg_len;

	PipelineStatsConfig *smsg =
		pipeline_stats_config__unpack(NULL, len,
					      payload);
	if (!smsg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read pipeline stats protobuf command\n");
		return -1;
	}
	g_stats_enabled = smsg->enable_stats;

	pipeline_stats_config__free_unpacked(smsg, NULL);

	return 0;
}

PB_REGISTER_CMD(pipeline_stats_cmd) = {
	.cmd = "vyatta:pipeline-stats",
	.handler = cmd_pipeline_stats_cfg,
};

bool pl_print_feats(struct pl_feature_registration *feat_reg, void *context)
{
	json_writer_t *wr = context;

	jsonw_string(wr, feat_reg->name);

	return true;
}
