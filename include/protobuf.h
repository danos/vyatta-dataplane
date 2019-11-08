/*-
 * Copyright (c) 2018, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef PROTOBUF_H
#define PROTOBUF_H

int pb_cmd(void *data, size_t size, FILE *f);

/* command structure */
struct pb_msg {
	/* input */
	void *msg;
	size_t msg_len;

	/* output */
	FILE *fp;
};

typedef int
(pb_cmd_proc)(struct pb_msg *cmd);

struct pb_msg_handler {
	uint32_t version;
	const char  *cmd;
	pb_cmd_proc *handler;
};

int
pb_add_command(const struct pb_msg_handler *cmd);

void
pb_register_cmd_err(const char *cmd);


#define PB_REGISTER_CMD(x, ...)                             \
	__VA_ARGS__ struct pb_msg_handler x;                \
	static void __pb_add_command_##x(void)              \
		__attribute__((__constructor__));           \
	static void __pb_add_command_##x(void)              \
	{ if (pb_add_command(&x) != 0)                      \
			pb_register_cmd_err(x.cmd); }	    \
	__VA_ARGS__ struct pb_msg_handler x

/*
 * Use pb_cmd_err instead of fprintf(msg->fp, "").  msg->fp may be NULL
 * if a command is deferred and then replayed, for example after an
 * interface event.
 */
void pb_cmd_err(struct pb_msg *msg, const char *fmt, ...);

void list_all_protobuf_msg_versions(FILE *f);

#endif
