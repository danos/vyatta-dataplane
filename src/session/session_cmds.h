/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef SESSION_CMDS_H
#define SESSION_CMDS_H

#include <stdio.h>

struct session;

void cmd_session_json(struct session *s, json_writer_t *json, bool add_feat,
		      bool is_json_array);
int cmd_session_op(FILE *f, int argc, char **argv);
int cmd_session_ut(FILE *f, int argc, char **argv);
int cmd_session_cfg(FILE *f, int argc, char **argv);

#endif /* SESSION_CMDS_H */
