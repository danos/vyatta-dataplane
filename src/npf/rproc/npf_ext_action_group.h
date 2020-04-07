/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_EXT_ACTION_GROUP_H
#define NPF_EXT_ACTION_GROUP_H

#include "npf/npf_ruleset.h"
#include "qos.h"

struct npf_act_grp;

void npf_action_group_show(json_writer_t *wr, struct npf_act_grp *ptr,
			   const char *name);
void npf_action_group_show_policer(struct npf_act_grp *ptr,
				   struct qos_show_context *context);

#endif /* NPF_EXT_ACTION_GROUP_H */
