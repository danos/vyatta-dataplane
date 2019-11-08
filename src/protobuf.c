/*-
 * Copyright (c) 2018, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <czmq.h>

#include "compiler.h"
#include "vplane_log.h"
#include "protobuf/DataplaneEnvelope.pb-c.h"
#include "commands.h"
#include "protobuf.h"

static zhash_t *g_pb_cmds;

__attribute__((format(printf, 2, 3)))
void pb_cmd_err(struct pb_msg *msg, const char *fmt, ...)
{
	if (!msg || !msg->fp)
		return;

	va_list args;

	va_start(args, fmt);
	vfprintf(msg->fp, fmt, args);
	va_end(args);
}

/*
 * Dispatcher for received protobuf commands.
 */
int
pb_cmd(void *data, size_t size, FILE *f)
{
	int status = -1;

	if (!g_pb_cmds) {
		RTE_LOG(ERR, DATAPLANE,
			"protobuf not initialized\n");
		return status;
	}

	/* first validate against pb command set */
	DataplaneEnvelope *dmsg =
		dataplane_envelope__unpack(NULL,
					   size,
					   (unsigned char *)data);
	if (!dmsg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read protobuf command\n");
		return status;
	}

	if (!dmsg->type) {
		RTE_LOG(ERR, DATAPLANE,
			"protobuf type not found\n");
		goto cleanup;
	}

	struct pb_msg_handler *c_entry = zhash_lookup(g_pb_cmds, dmsg->type);
	if (c_entry) {
		struct pb_msg cmd = {.fp = f,
				     .msg = dmsg->msg.data,
				     .msg_len = dmsg->msg.len};
		status = c_entry->handler(&cmd);
		goto cleanup;
	}

	RTE_LOG(ERR, DATAPLANE,	"protobuf handler not found: %s\n", dmsg->type);
cleanup:
	dataplane_envelope__free_unpacked(dmsg, NULL);
	return status;
}

/*
 * Registers new protocol buffer commands
 * via the PB_REGISTER_CMD macro.
 */
int
pb_add_command(const struct pb_msg_handler *cmd)
{
	char *tok = strdupa(cmd->cmd);

	if (!g_pb_cmds) {
		g_pb_cmds = zhash_new();
		if (g_pb_cmds == 0) {
			RTE_LOG(ERR, DATAPLANE,
				"memory allocation failure: protobuf collection\n");
			return -1;
		}
	}

	struct pb_msg_handler *c_entry =
		calloc(sizeof(*c_entry), 1);
	if (c_entry == 0) {
		RTE_LOG(ERR, DATAPLANE,
			"memory allocation failure: protobuf cmd\n");
		return -1;
	}
	c_entry->handler = cmd->handler;
	if (zhash_insert(g_pb_cmds, tok, c_entry) != 0) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to register protobuf cmd: %s (%s)\n",
			tok, strerror(errno));
		return -1;
	}
	return 0;
}

void list_all_protobuf_msg_versions(FILE *f)
{
	struct pb_msg_handler *cmd;

	cmd = zhash_first(g_pb_cmds);
	while (cmd) {
		fprintf(f, "pb_%s %u\n", zhash_cursor(g_pb_cmds), cmd->version);
		cmd = zhash_next(g_pb_cmds);
	}
}

void pb_register_cmd_err(const char *cmd)
{
	RTE_LOG(ERR, DATAPLANE,
		"Error registering command: %s\n",
		cmd);
}

