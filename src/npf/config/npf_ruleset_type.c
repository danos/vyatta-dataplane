/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "npf/config/npf_ruleset_type.h"
#include "if_feat.h"
#include "vplane_log.h"

static const struct npf_ruleset_features {
	const char *name;
	const unsigned int flags;
	const unsigned int feat_flags;
	uint32_t log_level;
	const char *log_name;
} npf_ruleset_features[NPF_RS_TYPE_COUNT] =  {
	[NPF_RS_ACL_IN] = {
		.name = "acl-in",
		.flags = NPF_RS_FLAG_DIR_IN | NPF_RS_FLAG_FEAT_INTF
		       | NPF_RS_FLAG_NOTRACK | NPF_RS_FLAG_NOTABLES,
		.feat_flags = IF_FEAT_FLAG_ACL_IN,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "acl",
	},
	[NPF_RS_ACL_OUT] = {
		.name = "acl-out",
		.flags = NPF_RS_FLAG_DIR_OUT | NPF_RS_FLAG_FEAT_INTF
		       | NPF_RS_FLAG_NOTRACK | NPF_RS_FLAG_NOTABLES,
		.feat_flags = IF_FEAT_FLAG_ACL_OUT,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "acl",
	},
	[NPF_RS_FW_IN] = {
		.name = "fw-in",
		.flags = NPF_RS_FLAG_DIR_IN | NPF_RS_FLAG_APP_FW
			| NPF_RS_FLAG_FEAT_INTF,
		.feat_flags = IF_FEAT_FLAG_DEFRAG | IF_FEAT_FLAG_FW,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "fw",
	},
	[NPF_RS_FW_OUT] = {
		.name = "fw-out",
		.flags = NPF_RS_FLAG_DIR_OUT | NPF_RS_FLAG_APP_FW
			| NPF_RS_FLAG_FEAT_INTF,
		.feat_flags = IF_FEAT_FLAG_DEFRAG | IF_FEAT_FLAG_FW,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "fw",
	},
	[NPF_RS_DNAT] = {
		.name = "dnat",
		.flags = NPF_RS_FLAG_DIR_IN | NPF_RS_FLAG_FEAT_INTF,
		.feat_flags = IF_FEAT_FLAG_DEFRAG | IF_FEAT_FLAG_FW,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "dnat",
	},
	[NPF_RS_SNAT] = {
		.name = "snat",
		.flags = NPF_RS_FLAG_DIR_OUT | NPF_RS_FLAG_FEAT_INTF,
		.feat_flags = IF_FEAT_FLAG_DEFRAG | IF_FEAT_FLAG_FW,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "snat",
	},
	[NPF_RS_ZONE] = {
		.name = "zone",
		.flags = NPF_RS_FLAG_DIR_OUT | NPF_RS_FLAG_APP_FW
			| NPF_RS_FLAG_FEAT_INTF_ALL,
		.feat_flags = IF_FEAT_FLAG_DEFRAG | IF_FEAT_FLAG_FW,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "fw",
	},
	[NPF_RS_LOCAL] = {
		.name = "local",
		.flags = NPF_RS_FLAG_NOTRACK | NPF_RS_FLAG_DIR_IN,
		.feat_flags = 0,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "local",
	},
	[NPF_RS_ORIGINATE] = {
		.name = "originate",
		.flags = NPF_RS_FLAG_NOTRACK | NPF_RS_FLAG_DIR_OUT
			| NPF_RS_FLAG_FEAT_INTF | NPF_RS_FLAG_FEAT_GBL,
		.feat_flags = IF_FEAT_FLAG_DEFRAG | IF_FEAT_FLAG_FW_ORIG,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "originate",
	},
	[NPF_RS_BRIDGE] = {
		.name = "bridge",
		.flags = NPF_RS_FLAG_NOTRACK | NPF_RS_FLAG_DIR_IN,
		.feat_flags = 0,
		.log_level = RTE_LOGTYPE_BRIDGE,
		.log_name = "bridge",
	},
	[NPF_RS_IPSEC] = {
		.name = "ipsec",
		.flags = NPF_RS_FLAG_DIR_OUT | NPF_RS_FLAG_DIR_IN
			| NPF_RS_FLAG_NOTRACK | NPF_RS_FLAG_NOTABLES
			| NPF_RS_FLAG_NO_STATS | NPF_RS_FLAG_HASH_TBL,
		.feat_flags = 0,
		.log_level = RTE_LOGTYPE_DATAPLANE,
		.log_name = "IPsec",
	},
	[NPF_RS_PBR] = {
		.name = "pbr",
		.flags = NPF_RS_FLAG_NOTRACK | NPF_RS_FLAG_DIR_IN
			| NPF_RS_FLAG_FEAT_INTF,
		.feat_flags = IF_FEAT_FLAG_PBR,
		.log_level = RTE_LOGTYPE_ROUTE,
		.log_name = "pbr",
	},
	[NPF_RS_CUSTOM_TIMEOUT] = {
		.name = "custom-timeout",
		.flags = NPF_RS_FLAG_NOTRACK | NPF_RS_FLAG_DIR_IN,
		.feat_flags = 0,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "custom-timeout",
	},
	[NPF_RS_NAT64] = {
		.name = "nat64",
		.flags = NPF_RS_FLAG_NOTABLES | NPF_RS_FLAG_DIR_IN
			| NPF_RS_FLAG_FEAT_INTF_ALL,
		.feat_flags = IF_FEAT_FLAG_DEFRAG | IF_FEAT_FLAG_NAT64,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "nat64",
	},
	[NPF_RS_NAT46] = {
		.name = "nat46",
		.flags = NPF_RS_FLAG_NOTABLES | NPF_RS_FLAG_DIR_IN
			| NPF_RS_FLAG_FEAT_INTF_ALL,
		.feat_flags = IF_FEAT_FLAG_DEFRAG | IF_FEAT_FLAG_NAT64,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "nat46",
	},
	[NPF_RS_QOS] = {
		.name = "qos",
		.flags = NPF_RS_FLAG_DIR_OUT | NPF_RS_FLAG_NOTRACK,
		.feat_flags = 0,
		.log_level = RTE_LOGTYPE_QOS,
		.log_name = "qos",
	},
	[NPF_RS_SESSION_RPROC] = {
		.name = "session-rproc",
		.flags = NPF_RS_FLAG_DIR_IN | NPF_RS_FLAG_DIR_OUT
			| NPF_RS_FLAG_NOTRACK | NPF_RS_FLAG_NOTABLES,
		.feat_flags = 0,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "session-rproc",
	},
	[NPF_RS_PORTMONITOR_IN] = {
		.name = "portmonitor-in",
		.flags = NPF_RS_FLAG_DIR_IN | NPF_RS_FLAG_NOTRACK,
		.feat_flags = 0,
		.log_level = RTE_LOGTYPE_DATAPLANE,
		.log_name = "portmonitor",
	},
	[NPF_RS_PORTMONITOR_OUT] = {
		.name = "portmonitor-out",
		.flags = NPF_RS_FLAG_DIR_OUT | NPF_RS_FLAG_NOTRACK,
		.feat_flags = 0,
		.log_level = RTE_LOGTYPE_DATAPLANE,
		.log_name = "portmonitor",
	},
	[NPF_RS_APPLICATION] = {
		.name = "app",
		.flags = NPF_RS_FLAG_DIR_IN | NPF_RS_FLAG_DIR_OUT
			| NPF_RS_FLAG_NOTRACK,
		.feat_flags = 0,
		.log_level = RTE_LOGTYPE_APP,
		.log_name = "application",
	},
	[NPF_RS_NPTV6_IN] = {
		.name = "nptv6-in",
		.flags = NPF_RS_FLAG_DIR_IN | NPF_RS_FLAG_NOTRACK
			| NPF_RS_FLAG_FEAT_INTF,
		.feat_flags = IF_FEAT_FLAG_NPTV6,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "nptv6",
	},
	[NPF_RS_NPTV6_OUT] = {
		.name = "nptv6-out",
		.flags = NPF_RS_FLAG_DIR_OUT | NPF_RS_FLAG_NOTRACK
			| NPF_RS_FLAG_FEAT_INTF,
		.feat_flags = IF_FEAT_FLAG_NPTV6,
		.log_level = RTE_LOGTYPE_FIREWALL,
		.log_name = "nptv6",
	},
};

unsigned int npf_get_ruleset_type_flags(enum npf_ruleset_type type)
{
	if (type >= NPF_RS_TYPE_COUNT)
		return 0;
	return npf_ruleset_features[type].flags;
}

unsigned int npf_get_ruleset_type_feat_flags(enum npf_ruleset_type type)
{
	if (type >= NPF_RS_TYPE_COUNT)
		return 0;
	return npf_ruleset_features[type].feat_flags;
}

const char *npf_get_ruleset_type_name(enum npf_ruleset_type type)
{
	if (type >= NPF_RS_TYPE_COUNT)
		return NULL;
	return npf_ruleset_features[type].name;
}

int npf_get_ruleset_type(const char *name, enum npf_ruleset_type *type)
{
	enum npf_ruleset_type t;

	for (t = 0; t < NPF_RS_TYPE_COUNT; t++) {
		if (strcmp(name, npf_ruleset_features[t].name) == 0) {
			*type = t;
			return 0;
		}
	}

	return -ENOENT;
}

uint32_t npf_get_ruleset_type_log_level(enum npf_ruleset_type type)
{
	if (type >= NPF_RS_TYPE_COUNT)
		return 0;
	return npf_ruleset_features[type].log_level;
}

const char *npf_get_ruleset_type_log_name(enum npf_ruleset_type type)
{
	if (type >= NPF_RS_TYPE_COUNT)
		return NULL;
	return npf_ruleset_features[type].log_name;
}
