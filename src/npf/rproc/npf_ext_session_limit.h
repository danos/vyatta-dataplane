/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_EXT_SESSION_LIMIT_H
#define NPF_EXT_SESSION_LIMIT_H

#include <stdio.h>

int cmd_npf_sess_limit_param_add(FILE *f, int argc, char **argv);
int cmd_npf_sess_limit_param_delete(FILE *f, int argc, char **argv);
int cmd_npf_sess_limit_show(FILE *f, int argc, char **argv);
int cmd_npf_sess_limit_clear(FILE *f, int argc, char **argv);

struct npf_rule;

struct npf_rule *npf_sess_limit_get_global_rule(void);

/* Used by dataplane reset only */
void npf_sess_limit_inst_destroy(void);

/*
 * Called from npf_session_establish to determine if we want to allow this
 * session to be created. Returns 'true' to prevent session being created.
 */
bool npf_sess_limit_check(npf_rule_t *rl);

/*
 * Called when the session belonging to a limit-enabled rproc rule changes
 * state.  May be called from both master and forwarding threads.
 */
void npf_sess_limit_state_change(void *handle, uint8_t proto_idx,
				 uint8_t prev_state, uint8_t state);

#endif


