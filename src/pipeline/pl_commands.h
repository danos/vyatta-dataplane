/*
 * pl_commands.h
 *
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016, 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PL_COMMANDS_H
#define PL_COMMANDS_H

#include <czmq.h>

#include "json_writer.h"

struct pl_node_command;

extern zhash_t *g_pl_cmds;
extern zhash_t *g_pl_opcmds;

void
pl_recurse_cmds(zhash_t *h, const struct pl_node_command *c, char *s);

void
pl_dump_nodes(json_writer_t *json);

void list_all_pipeline_cmd_versions(FILE *f);
void list_all_pipeline_msg_versions(FILE *f);

#endif /* PL_COMMANDS_H */
