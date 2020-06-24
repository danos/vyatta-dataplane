/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NPF OP mode commands (Firewall/NAT/PBR)
 */

#include <czmq.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"
#include "control.h"
#include "compiler.h"
#include "npf/alg/alg_npf.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_config_state.h"
#include "npf/config/npf_dump.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/config/pmf_att_rlgrp.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_apm.h"
#include "npf/npf_cmd.h"
#include "npf/npf_session.h"
#include "npf/npf_state.h"
#include "npf/npf_timeouts.h"
#include "npf/npf_rc.h"
#include "npf/zones/npf_zone_public.h"
#include "npf/rproc/npf_ext_session_limit.h"
#include "npf/rproc/npf_ext_nptv6.h"
#include "npf_shim.h"
#include "vrf_internal.h"

static zhash_t *g_npf_op_cmds;

static int
cmd_acl_show_counters(FILE *f, int argc, char **argv)
{
	int dir = 0;
	char const *ifname = NULL;
	char const *rgname = NULL;

	if (argc > 3) {
		npf_cmd_err(f, "too many arguments (%d)", argc);
		return -EINVAL;
	}

	if (argc > 0)
		ifname = argv[0];

	if (argc > 1) {
		if (strcmp(argv[1], "in") == 0)
			dir = -1;
		else if (strcmp(argv[1], "out") == 0)
			dir = 1;
		else {
			npf_cmd_err(f, "bad direction argument");
			return -EINVAL;
		}
	}

	if (argc > 2)
		rgname = argv[2];

	return pmf_arlg_cmd_show_counters(f, ifname, dir, rgname);
}

static int
cmd_acl_clear_counters(FILE *f, int argc, char **argv)
{
	int dir = 0;
	char const *ifname = NULL;
	char const *rgname = NULL;

	if (argc > 3) {
		npf_cmd_err(f, "too many arguments (%d)", argc);
		return -EINVAL;
	}

	if (argc > 0)
		ifname = argv[0];

	if (argc > 1) {
		if (strcmp(argv[1], "in") == 0)
			dir = -1;
		else if (strcmp(argv[1], "out") == 0)
			dir = 1;
		else {
			npf_cmd_err(f, "bad direction argument");
			return -EINVAL;
		}
	}

	if (argc > 2)
		rgname = argv[2];

	return pmf_arlg_cmd_clear_counters(ifname, dir, rgname);
}

static int
cmd_dump_portmap(FILE *f, int argc __unused, char **argv __unused)
{
	npf_apm_dump(f);
	return 0;
}

static int
cmd_npf_clear_portmap(FILE *f __unused, int argc __unused, char **argv __unused)
{
	npf_apm_flush_all();
	return 0;
}

static int
cmd_dump_alg(FILE *f, int argc __unused, char **argv __unused)
{
	npf_alg_dump(f, VRF_INVALID_ID);
	return 0;
}

static int
cmd_dump_groups(FILE *f, int argc __unused, char **argv __unused)
{
	npf_dump_rule_groups(f);
	return 0;
}

static int
cmd_dump_acls(FILE *f, int argc __unused, char **argv __unused)
{
	pmf_arlg_dump(f);
	return 0;
}

static int
cmd_dump_attach_points(FILE *f, int argc __unused, char **argv __unused)
{
	npf_dump_attach_points(f);
	return 0;
}

/*
 * show one or more zones
 */
static int
cmd_show_zones(FILE *f, int argc, char **argv)
{
	return npf_zone_show(f, argc, argv);
}

static int get_ruleset_selection(FILE *f, struct ruleset_select *sel, int argc,
				 char **argv)
{
	int ret;

	sel->group_class = NPF_RULE_CLASS_COUNT;	/* all classes */
	sel->rule_no = 0;				/* all rules */

	while (argc >= 1) {
		if (strcmp(argv[0], "-n") == 0) {
			argc--, argv++;
			if (argc < 1) {
				npf_cmd_err(f, "selected ruleset name missing "
					    "for option -n");
				return -EINVAL;
			}
			ret = npf_extract_class_and_group(argv[0],
				&(sel->group_class), &(sel->group_name));

			if (ret < 0) {
				npf_cmd_err(f, "invalid group for selected "
					    "attach point: %s (%d)", argv[0],
					    ret);
				return ret;
			}
			argc--, argv++;
		} else if (strcmp(argv[0], "-r") == 0) {
			char *endp;

			argc--, argv++;
			if (argc < 1) {
				npf_cmd_err(f, "selected ruleset number "
					    "missing for option -r");
				return -EINVAL;
			}
			sel->rule_no = strtoul(argv[0], &endp, 10);

			if (sel->rule_no == 0) {
				npf_cmd_err(f, "invalid rule number for "
					    "selected attach point: %s",
					    argv[0]);
				return -EINVAL;
			}
			argc--, argv++;
		} else
			break;
	}

	if (argc < 1) {
		sel->attach_type = NPF_ATTACH_TYPE_ALL;
		sel->attach_point = "";
		sel->rulesets = ULONG_MAX;
		return 0;
	}

	ret = npf_str2ap_type_and_point(argv[0], &sel->attach_type,
					&sel->attach_point);

	if (ret < 0) {
		npf_cmd_err(f, "invalid selected attach point: %s (%d)",
			    argv[0], ret);
		return ret;
	}

	if (argc == 1) {
		sel->rulesets = ULONG_MAX;
		return 0;
	}

	enum npf_ruleset_type ruleset_type;

	sel->rulesets = 0;
	while (argc > 1) {
		argc--, argv++;
		ret = npf_get_ruleset_type(argv[0], &ruleset_type);
		if (ret < 0) {
			npf_cmd_err(f, "invalid selected ruleset type: %s (%d)",
				    argv[0], ret);
			return ret;
		}
		sel->rulesets |= BIT(ruleset_type);
	}

	return 0;
}

int
cmd_show_rulesets(FILE *f, int argc, char **argv)
{
	struct ruleset_select sel = {0};
	int ret = get_ruleset_selection(f, &sel, argc, argv);

	if (ret < 0)
		return -1;

	ret = npf_show_selected_rulesets(f, &sel);

	if (ret < 0) {
		npf_cmd_err(f, "failed showing rulesets (%d)", ret);
		return -1;
	}

	return 0;
}

/*
 * cmd_show_ruleset_state
 */
static int
cmd_show_ruleset_state(FILE *f, int argc, char **argv)
{
	struct ruleset_select sel = {0};
	int ret = get_ruleset_selection(f, &sel, argc, argv);

	if (ret < 0)
		return -1;

	ret = npf_show_ruleset_state(f, &sel);

	if (ret < 0) {
		npf_cmd_err(f, "failed showing ruleset state (%d)", ret);
		return -1;
	}

	return 0;
}

static int
cmd_clear_rulesets(FILE *f, int argc, char **argv)
{
	struct ruleset_select sel = {0};
	int ret = get_ruleset_selection(f, &sel, argc, argv);

	if (ret < 0)
		return -1;

	ret = npf_clear_selected_rulesets(&sel);

	if (ret < 0) {
		npf_cmd_err(f, "failed clearing rulesets (%d)", ret);
		return -1;
	}

	return 0;
}

/*
 * Used by unit-tests to flush ruleset garbage collection heap
 */
static int
cmd_flush_rulesets(FILE *f, int argc __unused, char **argv __unused)
{
	int ret;

	ret = npf_flush_rulesets();

	if (ret < 0) {
		npf_cmd_err(f, "failed flushing rulesets (%d)", ret);
		return -1;
	}

	return 0;
}

/*
 * Show address groups
 */
static int
cmd_npf_show_addrgrp_args(int argc, char **argv, struct npf_show_ag_ctl *ctl)
{
	/* Set defaults */
	ctl->af[AG_IPv4] = true;
	ctl->af[AG_IPv6] = true;
	ctl->detail = false;
	ctl->brief = false;
	ctl->tree = false;
	ctl->optimal = false;
	ctl->name = NULL;

	while (argc > 0) {
		char *a, *p;

		/*
		 * Separate parameter and argument
		 */
		p = strdupa(argv[0]);
		if (!p)
			break;

		a = strchr(p, '=');
		if (!a)
			break;
		*a = '\0';
		a += 1;

		if (!strcmp(p, "af")) {
			if (!strcmp(a, "ipv4"))
				ctl->af[AG_IPv6] = false;
			else if (!strcmp(a, "ipv6"))
				ctl->af[AG_IPv4] = false;

		} else if (!strcmp(p, "name")) {
			ctl->name = strdup(a);

		} else if (!strcmp(p, "option")) {
			if (!strcmp(a, "detail"))
				ctl->detail = true;
			else if (!strcmp(a, "brief"))
				ctl->brief = true;
			else if (!strcmp(a, "tree"))
				ctl->tree = true;
			else if (!strcmp(a, "optimal"))
				ctl->optimal = true;
		}

		argc--;
		argv++;
	}

	return 0;
}

static int
cmd_npf_show_addrgrp(FILE *f, int argc, char **argv)
{
	struct npf_show_ag_ctl ctl = {0};

	/* Parse args */
	cmd_npf_show_addrgrp_args(argc, argv, &ctl);

	npf_addrgrp_show(f, &ctl);

	if (ctl.name)
		free(ctl.name);

	return 0;
}

/*
 * This is for use in testing rset behaviour - should normally only
 * have its config reset by the dataplane event. It should reflect
 * the actions performed by function npf_reset_config().
 */

static int
cmd_reset_config(FILE *f, int argc, char **argv)
{
	for (; argc > 0; argc--, argv++) {

		printf("reset: %s\n", argv[0]);
		if (strcmp(argv[0], "all") == 0) {
			npf_reset_config(CONT_SRC_MAIN);
			continue;
		}
		if (strcmp(argv[0], "attach-points") == 0) {
			npf_cfg_detach_all();
			continue;
		}
		if (strcmp(argv[0], "groups") == 0) {
			npf_cfg_all_group_delete();
			continue;
		}
		if (strcmp(argv[0], "commit") == 0) {
			npf_cfg_commit_all();
			continue;
		}
		if (strcmp(argv[0], "address-table") == 0) {
			npf_addrgrp_tbl_destroy();
			continue;
		}
		if (strcmp(argv[0], "icmp-strict") == 0) {
			npf_state_set_icmp_strict(false);
			continue;
		}
		if (strcmp(argv[0], "tcp-strict") == 0) {
			npf_state_set_tcp_strict(false);
			continue;
		}
		if (strcmp(argv[0], "session-log") == 0) {
			npf_reset_session_log();
			continue;
		}
		if (strcmp(argv[0], "session-limit") == 0) {
			npf_sess_limit_inst_destroy();
			continue;
		}
		if (strcmp(argv[0], "state-timeouts") == 0) {
			npf_timeout_reset();
			continue;
		}
		if (strcmp(argv[0], "alg") == 0) {
			npf_alg_reset(true);
			continue;
		}

		npf_cmd_err(f, "unknown reset option: %s", argv[0]);
		return -1;
	}

	return 0;
}

enum {
	ACL_SHOW_COUNTERS,
	ACL_CLEAR_COUNTERS,
	FW_SHOW_SESSION_LIMIT,
	FW_CLEAR_SESSION_LIMIT,
	FW_SHOW_ADDRGRP,
	PORTMAP_CLEAR,
	PORTMAP_DUMP,
	DUMPALG,
	DUMP_GROUPS,
	DUMP_ACLS,
	DUMP_ATTACH_POINTS,
	SHOW_ZONES,
	SHOW_STATE,
	RC_SHOW_COUNTERS,
	RC_CLEAR_COUNTERS,
	SHOW,
	CLEAR,
	FLUSH,
	RESET,
	NUM_NPF_CMDS,
};

/*
 * Below are the list of Operational Mode commands.
 * Insert these in order from most-specific to least-specific
 * (but notice they are clustered around base commands).
 *
 * Finally wild-cards can be added to help reduce duplicated commands.
 *
 * Note that when an incompatible change is made to commands here the
 * version number for the "npf-op" entry within cmd_table[] (see
 * src/commands.c) should be updated, and the dependent version
 * within vplane-config-npf and vyatta-service-snmp updated.
 */
static const struct npf_command npf_cmd_op[] = {
	[ACL_SHOW_COUNTERS] = {
		.tokens = "acl show counters",
		.handler = cmd_acl_show_counters,
	},
	[ACL_CLEAR_COUNTERS] = {
		.tokens = "acl clear counters",
		.handler = cmd_acl_clear_counters,
	},
	[FW_SHOW_SESSION_LIMIT] = {
		.tokens = "fw show session-limit",
		.handler = cmd_npf_sess_limit_show,
	},
	[FW_CLEAR_SESSION_LIMIT] = {
		.tokens = "fw clear session-limit",
		.handler = cmd_npf_sess_limit_clear,
	},
	[FW_SHOW_ADDRGRP] = {
		.tokens = "fw show address-group",
		.handler = cmd_npf_show_addrgrp,
	},
	[PORTMAP_CLEAR] = {
		.tokens = "fw portmap clear",
		.handler = cmd_npf_clear_portmap,
	},
	[PORTMAP_DUMP] = {
		.tokens = "fw dump-portmap",
		.handler = cmd_dump_portmap,
	},
	[DUMPALG] = {
		.tokens = "fw dump-alg",
		.handler = cmd_dump_alg,
	},
	[DUMP_GROUPS] = {
		.tokens = "dump groups",
		.handler = cmd_dump_groups,
	},
	[DUMP_ACLS] = {
		.tokens = "dump acls",
		.handler = cmd_dump_acls,
	},
	[DUMP_ATTACH_POINTS] = {
		.tokens = "dump attach-points",
		.handler = cmd_dump_attach_points,
	},
	[SHOW_ZONES] = {
		.tokens = "show zones",
		.handler = cmd_show_zones,
	},
	[RC_SHOW_COUNTERS] = {
		.tokens = "rc show counters",
		.handler = npf_show_rc_counts,
	},
	[RC_CLEAR_COUNTERS] = {
		.tokens = "rc clear counters",
		.handler = npf_clear_rc_counts,
	},
	[SHOW_STATE] = {
		.tokens = "state",
		.handler = cmd_show_ruleset_state,
	},
	[SHOW] = {
		.tokens = "show",
		.handler = cmd_show_rulesets,
	},
	[CLEAR] = {
		.tokens = "clear",
		.handler = cmd_clear_rulesets,
	},
	[FLUSH] = {
		.tokens = "flush",
		.handler = cmd_flush_rulesets,
	},
	[RESET] = {
		.tokens = "reset",
		.handler = cmd_reset_config,
	},
};

static __attribute__((constructor)) void
npf_cmd_op_initialize(void)
{
	g_npf_op_cmds = npf_cmd_hash_init(npf_cmd_op, NUM_NPF_CMDS);
}

int cmd_npf_op(FILE *f, int argc, char **argv)
{
	return npf_cmd_handle(f, argc, argv, g_npf_op_cmds);
}
