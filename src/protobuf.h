/*-
 * Copyright (c) 2018-2019,2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PROTOBUF_H
#define PROTOBUF_H

#include <czmq.h>

#include "feature_commands.h"

int pb_cmd(void *data, size_t size, FILE *f);
int pb_op_cmd(zsock_t *sock, void *data, size_t size, FILE *f);

struct pb_msg_handler {
	uint32_t version;
	const char  *cmd;
	pb_cmd_proc *handler;
};

int
pb_add_command(const struct pb_msg_handler *cmd, int mode);

void
pb_register_cmd_err(const char *cmd);


#define PB_REGISTER_CMD(x, ...)				    \
	__VA_ARGS__ struct pb_msg_handler x;		    \
	static void __pb_add_command_##x(void)		    \
		__attribute__((__constructor__));           \
	static void __pb_add_command_##x(void)		    \
	{ if (pb_add_command(&x, 0) != 0)		    \
			pb_register_cmd_err(x.cmd); }	    \
	__VA_ARGS__ struct pb_msg_handler x


#define PB_REGISTER_OPCMD(x, ...)                           \
	__VA_ARGS__ struct pb_msg_handler x;                \
	static void __pb_add_command_##x(void)		    \
		__attribute__((__constructor__));           \
	static void __pb_add_command_##x(void)		    \
	{ if (pb_add_command(&x, 1) != 0)		    \
			pb_register_cmd_err(x.cmd); }	    \
	__VA_ARGS__ struct pb_msg_handler x

void list_all_protobuf_msg_versions(FILE *f);

#endif /* PROTOBUF_H */
