/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NPF Configure mode commands (Firewall/NAT/PBR)
 */

#include <czmq.h>
#include <errno.h>
#include <netinet/in.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "commands.h"
#include "compiler.h"
#include "config_internal.h"
#include "npf/npf.h"
#include "npf/alg/alg_npf.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_auto_attach.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/config/pmf_att_rlgrp.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_cache.h"
#include "npf/npf_cmd.h"
#include "npf/npf_rule_gen.h"
#include "npf/npf_session.h"
#include "npf/npf_state.h"
#include "npf/npf_timeouts.h"
#include "npf/rproc/npf_ext_session_limit.h"
#include "npf/zones/npf_zone_public.h"
#include "util.h"
#include "vplane_log.h"
#include "qos_public.h"

#define NPF_MAX_CMDLINE 1024

static zhash_t *g_npf_cfg_cmds;

/*
 * Command dispatch routines below
 */
static int
cmd_npf_fw_alg(FILE *f, int argc, char **argv)
{
	return npf_alg_cfg(f, argc, argv);
}

static int
cmd_npf_fw_session_log_add(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}
	if (npf_enable_session_log(argv[0], argv[1]) < 0) {
		npf_cmd_err(f, "failed to enable session log");
		return -1;
	}
	return 0;
}

static int
cmd_npf_fw_session_log_remove(FILE *f, int argc, char **argv)
{
	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}
	if (npf_disable_session_log(argv[0], argv[1]) < 0) {
		npf_cmd_err(f, "failed to disable session log");
		return -1;
	}
	return 0;
}

/*
 * Create an address-group and add it into the global address-group tableset
 *
 * npf fw table create <name>
 */
static int
cmd_npf_addrgrp_create(FILE *f, int argc, char **argv)
{
	struct npf_addrgrp *t;
	const char *name;

	if (argc < 1) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}
	name = argv[0];

	/* Does this address-group already exist? */
	if (npf_addrgrp_lookup_name(name) != NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"npf address-group \"%s\" already exists\n", name);
		return -EEXIST;
	}

	/*
	 * Create an address-group and insert into the address-group tableset
	 */
	t = npf_addrgrp_cfg_add(name);
	if (t == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not create npf address-group \"%s\"\n",
			name);
		return -ENOSPC;
	}

	return 0;
}

/*
 * Delete an address-group
 *
 * npf fw table delete <name>
 */
static int
cmd_npf_addrgrp_delete(FILE *f, int argc, char **argv)
{
	const char *name;

	if (argc < 1) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}
	name = argv[0];

	/* Does this address-group exist? */
	if (npf_addrgrp_lookup_name(name) == NULL) {
		npf_cmd_err(f, "npf address-group %s not found", name);
		return -ENOENT;
	}

	/*
	 * Remove from tableset immediately.  Only free memory when ref count
	 * is zero.
	 */
	npf_addrgrp_cfg_delete(name);

	return 0;
}

/*
 * Parse an address string for an address-group entry.  Returns address length
 * if successful, else returns < 0.
 */
static int
cmd_npf_parse_addrgrp_addr(char *str, sa_family_t *af, npf_addr_t *addr,
			   npf_netmask_t *masklen)
{
	bool negate;
	int alen, rc;

	rc = npf_parse_ip_addr(str, af, addr, masklen, &negate);

	if (rc < 0) {
		RTE_LOG(ERR, FIREWALL, "npf: invalid value for address-group "
			"address: %s\n", str);
		return rc;
	}

	if (*af != AF_INET && *af != AF_INET6) {
		RTE_LOG(ERR, FIREWALL, "npf: unexpected family %u for "
			"address-group address: %s\n", *af, str);
		return -EINVAL;
	}

	if (negate) {
		RTE_LOG(ERR, FIREWALL, "npf: negation (\"!\") for address "
			"in address-group entry is not supported: %s\n",
			str);
		return -EINVAL;
	}

	alen = (*af == AF_INET) ? sizeof(struct in_addr) :
				  sizeof(struct in6_addr);

	return alen;
}

/*
 * Add an entry to an address-group
 *
 * Prefix entry:
 *   npf fw table add <name> <prefix>
 *
 * Range entry:
 *   npf fw table add <name> <addr1> <addr2>
 */
static int
cmd_npf_addrgrp_entry_add(FILE *f, int argc, char **argv)
{
	npf_netmask_t masklen;
	const char *name;
	npf_addr_t addr1, addr2;
	sa_family_t af;
	int alen;
	int rc;

	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -EINVAL;
	}
	name = argv[0];

	/* Does this address-group exist? */
	if (npf_addrgrp_lookup_name(name) == NULL) {
		RTE_LOG(ERR, DATAPLANE,	"address-group \"%s\" does not exist\n",
			name);
		return -ENOENT;
	}

	/* masklen will be set to NPF_NO_NETMASK if no mask is present */
	rc = cmd_npf_parse_addrgrp_addr(argv[1], &af, &addr1, &masklen);
	if (rc < 0)
		goto end;
	alen = rc;

	/* Is just an address group and address or prefix specified? */
	if (argc == 2) {
		rc = npf_addrgrp_prefix_insert(name, &addr1, alen, masklen);
		goto end;
	}

	/* If more than 2 args then must be an address range */
	rc = cmd_npf_parse_addrgrp_addr(argv[2], &af, &addr2, &masklen);
	if (rc < 0)
		goto end;

	rc = npf_addrgrp_range_insert(name, &addr1, &addr2, alen);

end:
	if (rc < 0)
		npf_cmd_err(f, "failed to add table item (errno %d)", -rc);
	return rc;
}

/*
 * Remove an entry from an address-group
 *
 *
 * Prefix entry:
 *   npf fw table remove <name> <prefix>
 *
 * Range entry:
 *   npf fw table remove <name> <addr1> <addr2>
 */
static int
cmd_npf_addrgrp_entry_del(FILE *f, int argc, char **argv)
{
	npf_netmask_t masklen;
	const char *name;
	npf_addr_t addr1, addr2;
	sa_family_t af;
	int alen;
	int rc;

	if (argc < 2) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -EINVAL;
	}
	name = argv[0];

	/* Does this address-group exist? */
	if (npf_addrgrp_lookup_name(name) == NULL) {
		npf_cmd_err(f, "npf address-group %s not found", name);
		return -ENOENT;
	}

	/* masklen will be set to NPF_NO_NETMASK if no mask is present */
	rc = cmd_npf_parse_addrgrp_addr(argv[1], &af, &addr1, &masklen);
	if (rc < 0)
		return rc;
	alen = rc;

	/* Is just an address group and address or prefix specified? */
	if (argc == 2) {
		rc = npf_addrgrp_prefix_remove(name, &addr1, alen, masklen);
		return rc;
	}

	/* If more than 2 args then must be an address range */
	rc = cmd_npf_parse_addrgrp_addr(argv[2], &af, &addr2, &masklen);
	if (rc < 0)
		return rc;

	rc = npf_addrgrp_range_remove(name, &addr1, &addr2, alen);

	return rc;
}

static int
cmd_npf_global_icmp_strict_enable(FILE *f __unused, int argc __unused,
				 char **argv __unused)
{
	npf_state_set_icmp_strict(true);
	return 0;
}

static int
cmd_npf_global_icmp_strict_disable(FILE *f __unused,
				  int argc __unused,
				  char **argv __unused)
{
	npf_state_set_icmp_strict(false);
	return 0;
}

static int
cmd_npf_global_tcp_strict_enable(FILE *f __unused, int argc __unused,
				 char **argv __unused)
{
	npf_state_set_tcp_strict(true);
	return 0;
}

static int
cmd_npf_global_tcp_strict_disable(FILE *f __unused,
				  int argc __unused,
				  char **argv __unused)
{
	npf_state_set_tcp_strict(false);
	return 0;
}

static int
cmd_npf_global_timeout(FILE *f, int argc, char **argv)
{
	vrfid_t vrfid;
	uint8_t s;
	char *p;
	uint32_t tout;
	uint8_t proto_index;
	enum npf_timeout_action action;

	if (argc < 5) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing_arg);
		return -1;
	}

	/* Parse vrf id */
	vrfid = strtoul(argv[0], NULL, 10);
	if ((vrfid == VRF_INVALID_ID) || (vrfid >= VRF_ID_MAX)) {
		npf_cmd_err(f, "%s", "invalid global timeout VRF");
		return -1;
	}


	/* Parse action */
	if (!strcmp(argv[1], "update"))
		action = TIMEOUT_SET;
	else if (!strcmp(argv[1], "delete"))
		action = TIMEOUT_DEL;
	else {
		npf_cmd_err(f, "%s", "invalid global timeout action");
		return -1;
	}

	/* Parse protocol */
	proto_index = npf_proto_idx_from_str(argv[2]);
	if (proto_index == NPF_PROTO_IDX_NONE) {
		npf_cmd_err(f, "%s", "invalid global timeout protocol");
		return -1;
	}

	if (proto_index == NPF_PROTO_IDX_TCP)
		s = npf_map_str_to_tcp_state(argv[3]);
	else
		s = npf_map_str_to_generic_state(argv[3]);

	/* Parse timeout */
	tout = strtoul(argv[4], &p, 10);
	if (*p != '\0') {
		npf_cmd_err(f, "%s", "invalid global timeout value");
		return -1;
	}


	return npf_timeout_set(vrfid, action, proto_index, s, tout);
}

/*
 * If an application firewall ruleset changes, we have to mark
 * dirty all rulesets which could make use of these rulesets.
 * This is because we do not yet track rule groups which are
 * using an application firewall groups that is being changed.
 */
static void
npf_dirty_app_fw_users(void)
{
	enum npf_ruleset_type ruleset_type;

	struct ruleset_select sel = {
		.attach_type = NPF_ATTACH_TYPE_ALL,
		.attach_point = "",
		.rulesets = 0
	};

	for (ruleset_type = 0; ruleset_type < NPF_RS_TYPE_COUNT;
	     ruleset_type++) {
		if ((npf_get_ruleset_type_flags(ruleset_type) &
		    NPF_RS_FLAG_APP_FW))
			sel.rulesets |= BIT(ruleset_type);
	}

	npf_dirty_selected_rulesets(&sel);
}

static int
cmd_add_rule(FILE *f, int argc, char **argv)
{
	enum npf_rule_class group_class;
	char *group;
	char rule[NPF_MAX_CMDLINE];
	uint32_t index;
	int ret;

	if (argc < 3) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	ret = npf_extract_class_and_group(argv[0], &group_class, &group);
	if (ret < 0) {
		npf_cmd_err(f, "invalid group name: %s (%d)", argv[0], ret);
		return -1;
	}
	index = (uint32_t)strtoul(argv[1], NULL, 10);
	if (index == 0) {
		if (strcmp(argv[1], "0") != 0)  {
			npf_cmd_err(f, "invalid index: %s", argv[1]);
			return -1;
		} else if (group_class == NPF_RULE_CLASS_ACL)
			index = UINT32_MAX;
	}

	if (str_unsplit(rule, NPF_MAX_CMDLINE, argc - 2, argv + 2) < 0) {
		npf_cmd_err(f, "%s", npf_cmd_str_too_many_chars);
		return -1;
	}

	ret = npf_cfg_auto_attach_rule_add(group_class, group, index, rule);
	if (ret < 0) {
		npf_cmd_err(f, "failed adding rule to group (%d)", ret);
		return -1;
	}

	/*
	 * If a ruleset containing resource tables changes, we have to mark
	 * dirty all rulesets which could make use of resource tables.
	 * This is because we do not yet track rule groups are using the
	 * resource groups that are changing.
	 */
	if (group_class == NPF_RULE_CLASS_PORT_GROUP ||
	    group_class == NPF_RULE_CLASS_ICMP_GROUP ||
	    group_class == NPF_RULE_CLASS_ICMPV6_GROUP ||
	    group_class == NPF_RULE_CLASS_DSCP_GROUP ||
	    group_class == NPF_RULE_CLASS_PROTOCOL_GROUP) {

		enum npf_ruleset_type ruleset_type;

		struct ruleset_select sel = {
			.attach_type = NPF_ATTACH_TYPE_ALL,
			.attach_point = "",
			.rulesets = 0
		};

		for (ruleset_type = 0; ruleset_type < NPF_RS_TYPE_COUNT;
		     ruleset_type++) {
			if ((npf_get_ruleset_type_flags(ruleset_type) &
			    NPF_RS_FLAG_NOTABLES) == 0)
				sel.rulesets |= BIT(ruleset_type);
		}

		npf_dirty_selected_rulesets(&sel);
	}

	if (group_class == NPF_RULE_CLASS_APP_FW)
		npf_dirty_app_fw_users();

	if (group_class == NPF_RULE_CLASS_DSCP_GROUP)
		qos_sched_res_grp_update(group);

	return 0;
}

static int
cmd_delete_rule(FILE *f, int argc, char **argv)
{
	enum npf_rule_class group_class;
	char *group;
	char rule[NPF_MAX_CMDLINE];
	uint32_t index;
	int ret;

	if (argc < 1) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	ret = npf_extract_class_and_group(argv[0], &group_class, &group);
	if (ret < 0) {
		npf_cmd_err(f, "invalid group name: %s (%d)", argv[0], ret);
		return -1;
	}

	if (argc == 1) { /* delete whole group of rules */
		ret = npf_cfg_group_delete(group_class, group);
		if (ret < 0 && ret != -ENOENT) {
			npf_cmd_err(f, "failed deleting rule group (%d)", ret);
			return -1;
		}
		if (group_class == NPF_RULE_CLASS_APP_FW && ret == 0)
			npf_dirty_app_fw_users();
		return 0;
	}

	index = (uint32_t)strtoul(argv[1], NULL, 10);
	if (index == 0) {
		if (strcmp(argv[1], "0"))  {
			npf_cmd_err(f, "invalid index: %s", argv[1]);
			return -1;
		}
		if (argc < 3) {
			npf_cmd_err(f, "need rule when index is 0");
			return -1;
		}
	}

	if (str_unsplit(rule, NPF_MAX_CMDLINE, argc - 2, argv + 2) < 0) {
		npf_cmd_err(f, "%s", npf_cmd_str_too_many_chars);
		return -1;
	}

	ret = npf_cfg_auto_attach_rule_delete(group_class, group, index, rule);
	if (ret < 0 && ret != -ENOENT) {
		npf_cmd_err(f, "failed deleting rule from group (%d)", ret);
		return -1;
	}
	if (group_class == NPF_RULE_CLASS_APP_FW && ret == 0)
		npf_dirty_app_fw_users();
	return 0;
}

static int
cmd_attach_group(FILE *f, int argc, char **argv)
{
	enum npf_attach_type attach_type;
	const char *attach_point;
	enum npf_ruleset_type ruleset_type;
	enum npf_rule_class group_class;
	char *group;
	int ret;

	if (argc < 3) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	ret = npf_str2ap_type_and_point(argv[0], &attach_type, &attach_point);
	if (ret < 0) {
		npf_cmd_err(f, "invalid attach point: %s (%d)", argv[0], ret);
		return -1;
	}

	ret = npf_get_ruleset_type(argv[1], &ruleset_type);
	if (ret < 0) {
		npf_cmd_err(f, "invalid ruleset type: %s (%d)", argv[1], ret);
		return -1;
	}

	ret = npf_extract_class_and_group(argv[2], &group_class, &group);
	if (ret < 0) {
		npf_cmd_err(f, "invalid group name: %s (%d)", argv[2], ret);
		return -1;
	}

	ret = npf_cfg_attach_group(attach_type, attach_point, ruleset_type,
				   group_class, group);
	if (ret < 0) {
		npf_cmd_err(f, "failed attaching group to attach point (%d)",
			    ret);
		return -1;
	}
	return 0;
}

static int
cmd_detach_group(FILE *f, int argc, char **argv)
{
	enum npf_attach_type attach_type;
	const char *attach_point;
	enum npf_ruleset_type ruleset_type;
	enum npf_rule_class group_class;
	char *group;
	int ret;

	if (argc < 3) {
		npf_cmd_err(f, "%s", npf_cmd_str_missing);
		return -1;
	}

	ret = npf_str2ap_type_and_point(argv[0], &attach_type, &attach_point);
	if (ret < 0) {
		npf_cmd_err(f, "invalid attach point: %s (%d)", argv[0], ret);
		return -1;
	}

	ret = npf_get_ruleset_type(argv[1], &ruleset_type);
	if (ret < 0) {
		npf_cmd_err(f, "invalid ruleset type: %s (%d)", argv[1], ret);
		return -1;
	}

	ret = npf_extract_class_and_group(argv[2], &group_class, &group);
	if (ret < 0) {
		npf_cmd_err(f, "invalid group name: %s (%d)", argv[2], ret);
		return -1;
	}

	ret = npf_cfg_detach_group(attach_type, attach_point, ruleset_type,
				   group_class, group);
	if (ret < 0 && ret != -ENOENT) {
		npf_cmd_err(f, "failed detaching group to attach point (%d)",
			    ret);
		return -1;
	}
	return 0;
}

static int
cmd_commit(FILE *f, int argc, char **argv __unused)
{
	if (argc != 0) {
		npf_cmd_err(f, "%s", "too many arguments");
		return -1;
	}

	pmf_arlg_commit();
	npf_cfg_commit_all();
	return 0;
}

static int
cmd_npf_zone_add(FILE *f, int argc, char **argv)
{
	return npf_zone_cfg_add(f, argc, argv);
}

static int
cmd_npf_zone_remove(FILE *f, int argc, char **argv)
{
	return npf_zone_cfg_remove(f, argc, argv);
}

static int
cmd_npf_zone_local(FILE *f, int argc, char **argv)
{
	return npf_zone_cfg_local(f, argc, argv);
}

static int
cmd_npf_zone_policy_add(FILE *f, int argc, char **argv)
{
	return npf_zone_cfg_policy_add(f, argc, argv);
}

static int
cmd_npf_zone_policy_remove(FILE *f, int argc, char **argv)
{
	return npf_zone_cfg_policy_remove(f, argc, argv);
}

static int
cmd_npf_zone_intf_add(FILE *f, int argc, char **argv)
{
	return npf_zone_cfg_intf_add(f, argc, argv);
}

static int
cmd_npf_zone_intf_remove(FILE *f, int argc, char **argv)
{
	return npf_zone_cfg_intf_remove(f, argc, argv);
}

enum {
	FW_ALG,
	FW_TABLE_CREATE,
	FW_TABLE_DELETE,
	FW_TABLE_ADD,
	FW_TABLE_REMOVE,
	FW_SESSION_LIMIT_PARAM_ADD,
	FW_SESSION_LIMIT_PARAM_DELETE,
	FW_SESSIONLOG_ADD,
	FW_SESSIONLOG_REMOVE,
	FW_GLOBAL_ICMPSTRICT_ENABLE,
	FW_GLOBAL_ICMPSTRICT_DISABLE,
	FW_GLOBAL_TCPSTRICT_ENABLE,
	FW_GLOBAL_TCPSTRICT_DISABLE,
	FW_GLOBAL_TIMEOUT,
	FW_ZONE_ADD,
	FW_ZONE_REMOVE,
	FW_ZONE_LOCAL,
	FW_ZONE_INTF_ADD,
	FW_ZONE_INTF_REMOVE,
	FW_ZONE_POLICY_ADD,
	FW_ZONE_POLICY_REMOVE,
	ADD_RULE,
	DELETE_RULE,
	ATTACH_GROUP,
	DETACH_GROUP,
	COMMIT,
	NUM_NPF_CMDS,
};

/*
 * Below are the list of Configuration Mode commands.
 * Insert these in order from most-specific to least-specific
 * (but notice they are clustered around base commands).
 *
 * Finally wild-cards can be added to help reduce duplicated commands.
 *
 * Note that when an incompatible change is made to commands here the
 * version number for the "npf-cfg" entry within message_handlers[]
 * (see src/control.c) should be updated, and the dependent version
 * within vplane-config-npf updated.
 */
static const struct npf_command npf_cmd_cfg[] = {
	[FW_ALG] = {
		.tokens = "fw alg",
		.handler = cmd_npf_fw_alg,
	},
	[FW_TABLE_CREATE] = {
		.tokens = "fw table create",
		.handler = cmd_npf_addrgrp_create,
	},
	[FW_TABLE_DELETE] = {
		.tokens = "fw table delete",
		.handler = cmd_npf_addrgrp_delete,
	},
	[FW_TABLE_ADD] = {
		.tokens = "fw table add",
		.handler = cmd_npf_addrgrp_entry_add,
	},
	[FW_TABLE_REMOVE] = {
		.tokens = "fw table remove",
		.handler = cmd_npf_addrgrp_entry_del,
	},
	[FW_SESSION_LIMIT_PARAM_ADD] = {
		.tokens = "fw session-limit param add",
		.handler = cmd_npf_sess_limit_param_add,
	},
	[FW_SESSION_LIMIT_PARAM_DELETE] = {
		.tokens = "fw session-limit param delete",
		.handler = cmd_npf_sess_limit_param_delete,
	},
	[FW_SESSIONLOG_ADD] = {
		.tokens = "fw session-log add",
		.handler = cmd_npf_fw_session_log_add,
	},
	[FW_SESSIONLOG_REMOVE] = {
		.tokens = "fw session-log remove",
		.handler = cmd_npf_fw_session_log_remove,
	},
	[FW_GLOBAL_ICMPSTRICT_ENABLE] = {
		.tokens = "fw global icmp-strict enable",
		.handler = cmd_npf_global_icmp_strict_enable,
	},
	[FW_GLOBAL_ICMPSTRICT_DISABLE] = {
		.tokens = "fw global icmp-strict disable",
		.handler = cmd_npf_global_icmp_strict_disable,
	},
	[FW_GLOBAL_TCPSTRICT_ENABLE] = {
		.tokens = "fw global tcp-strict enable",
		.handler = cmd_npf_global_tcp_strict_enable,
	},
	[FW_GLOBAL_TCPSTRICT_DISABLE] = {
		.tokens = "fw global tcp-strict disable",
		.handler = cmd_npf_global_tcp_strict_disable,
	},
	[FW_GLOBAL_TIMEOUT] = {
		.tokens = "fw global timeout",
		.handler = cmd_npf_global_timeout,
	},
	[FW_ZONE_ADD] = {
		.tokens = "zone add",
		.handler = cmd_npf_zone_add,
	},
	[FW_ZONE_REMOVE] = {
		.tokens = "zone remove",
		.handler = cmd_npf_zone_remove,
	},
	[FW_ZONE_LOCAL] = {
		.tokens = "zone local",
		.handler = cmd_npf_zone_local,
	},
	[FW_ZONE_POLICY_ADD] = {
		.tokens = "zone policy add",
		.handler = cmd_npf_zone_policy_add,
	},
	[FW_ZONE_POLICY_REMOVE] = {
		.tokens = "zone policy remove",
		.handler = cmd_npf_zone_policy_remove,
	},
	[FW_ZONE_INTF_ADD] = {
		.tokens = "zone intf add",
		.handler = cmd_npf_zone_intf_add,
	},
	[FW_ZONE_INTF_REMOVE] = {
		.tokens = "zone intf remove",
		.handler = cmd_npf_zone_intf_remove,
	},
	[ADD_RULE] = {
		.tokens = "add",
		.handler = cmd_add_rule,
	},
	[DELETE_RULE] = {
		.tokens = "delete",
		.handler = cmd_delete_rule,
	},
	[ATTACH_GROUP] = {
		.tokens = "attach",
		.handler = cmd_attach_group,
	},
	[DETACH_GROUP] = {
		.tokens = "detach",
		.handler = cmd_detach_group,
	},
	[COMMIT] = {
		.tokens = "commit",
		.handler = cmd_commit,
	},
};

static __attribute__((constructor)) void
npf_cmd_cfg_initialize(void)
{
	g_npf_cfg_cmds = npf_cmd_hash_init(npf_cmd_cfg, NUM_NPF_CMDS);
}

int cmd_npf_cfg(FILE *f, int argc, char **argv)
{
	return npf_cmd_handle(f, argc, argv, g_npf_cfg_cmds);
}

int cmd_npf_ut(FILE *f, int argc, char **argv)
{
	return npf_cmd_handle(f, argc, argv, g_npf_cfg_cmds);
}
