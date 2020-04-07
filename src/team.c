/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <linux/genetlink.h>
#include <libmnl/libmnl.h>
#include <rte_log.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "compiler.h"
#include "if_var.h"
#include "lag.h"
#include "vplane_debug.h"
#include "vplane_log.h"

struct nlattr;
struct nlmsghdr;

#include <linux/if_team.h>

struct team_port_info {
	struct ifnet *ifp_master;
	struct ifnet *ifp_slave;
	uint32_t ifindex;
	uint32_t port_ifindex;
	int changed;
	int linkup;
	int removed;
	uint32_t speed;
	uint8_t duplex;
};

struct team_option_info {
	struct ifnet *ifp_master;
	struct ifnet *ifp_slave;
	uint32_t ifindex;
	uint32_t changed;
	union {
		uint32_t u32;
		char *str;
		void *binary;
		uint8_t u8;
	} data;
	char name[16];
	uint32_t removed;
	uint32_t port_ifindex;
	uint32_t array_index;
	uint8_t type;
};

static int team_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, TEAM_ATTR_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int team_port(const struct nlattr *attr, void *data)
{
	struct team_port_info *info = data;
	int type = mnl_attr_get_type(attr);

	switch (type) {
	case TEAM_ATTR_PORT_IFINDEX:
		info->port_ifindex = mnl_attr_get_u32(attr);
		break;
	case TEAM_ATTR_PORT_CHANGED:
		info->changed = 1;
		break;
	case TEAM_ATTR_PORT_LINKUP:
		info->linkup = 1;
		break;
	case TEAM_ATTR_PORT_REMOVED:
		info->removed = 1;
		break;
	case TEAM_ATTR_PORT_SPEED:
		info->speed = mnl_attr_get_u32(attr);
		break;
	case TEAM_ATTR_PORT_DUPLEX:
		info->duplex = mnl_attr_get_u8(attr);
		break;
	default:
		return MNL_CB_ERROR;
	}

	return MNL_CB_OK;
}

static int team_port_list(const struct nlattr *attr, void *data)
{
	return mnl_attr_parse_nested(attr, team_port, data);
}

static int process_team_ports(const struct team_port_info *info)
{
	int rv;

	if (!info->changed)
		return MNL_CB_OK;

	if (info->removed)
		rv = lag_slave_delete(info->ifp_master, info->ifp_slave);
	else
		rv = lag_slave_add(info->ifp_master, info->ifp_slave);

	DP_DEBUG(LAG, INFO, DATAPLANE, "team %s %u %u %s%s\n",
		 info->removed ? "remove" : "add",
		 info->ifindex,
		 info->port_ifindex,
		 rv ? "failed" : "ok",
		 rv == -EEXIST ? " (already exists)" : "");

	return MNL_CB_OK;
}

static int process_team_portlist(const struct nlmsghdr *nlh)
{
	struct nlattr *tb[TEAM_ATTR_MAX + 1] = {NULL, };
	struct team_port_info info = {.ifindex = 0, };
	int ret;

	ret = mnl_attr_parse(nlh, GENL_HDRLEN, team_attr, tb);
	if (ret != MNL_CB_OK)
		return ret;

	if (!tb[TEAM_ATTR_LIST_PORT])
		return MNL_CB_OK;

	if (tb[TEAM_ATTR_TEAM_IFINDEX])
		info.ifindex = mnl_attr_get_u32(tb[TEAM_ATTR_TEAM_IFINDEX]);

	ret = mnl_attr_parse_nested(tb[TEAM_ATTR_LIST_PORT],
				    team_port_list, &info);
	if (ret != MNL_CB_OK)
		return ret;

	info.ifp_master = ifnet_byteam(info.ifindex);
	if (info.ifp_master == NULL) {
		DP_DEBUG(LAG, ERR, DATAPLANE,
			 "team unable to find master for slave ifindex %d\n",
			 info.port_ifindex);
		return MNL_CB_OK;
	}

	if (info.port_ifindex) {
		info.ifp_slave = dp_ifnet_byifindex(info.port_ifindex);

		if (info.ifp_slave == NULL) {
			DP_DEBUG(LAG, ERR, DATAPLANE,
				 "team unable to find slave ifindex %d\n",
				 info.port_ifindex);
			return MNL_CB_OK;
		}

		if (info.ifp_slave->aggregator != NULL &&
		    info.ifp_slave->aggregator != info.ifp_master) {
			DP_DEBUG(LAG, ERR, DATAPLANE,
				 "team slave ifindex %d unexpected master\n",
				 info.port_ifindex);
			return MNL_CB_OK;
		}
	}

	process_team_ports(&info);

	return MNL_CB_OK;
}

static void team_option_data_free(struct team_option_info *info)
{
	if ((info->type == MNL_TYPE_STRING || info->type == MNL_TYPE_BINARY)
	    && info->data.binary)
		free(info->data.binary);
}

static int team_option(const struct nlattr *attr, void *data)
{
	int type = mnl_attr_get_type(attr);
	struct team_option_info *info = data;
	uint16_t payload_len;

	switch (type) {
	case TEAM_ATTR_OPTION_UNSPEC:
		break;
	case TEAM_ATTR_OPTION_NAME:
	{
		const char *opt_name = mnl_attr_get_str(attr);

		if (strlen(opt_name) >= sizeof(info->name))
			RTE_LOG(NOTICE, DATAPLANE,
				"Truncating too long team option name: %s\n",
				opt_name);
		snprintf(info->name, sizeof(info->name), "%s", opt_name);
		break;
	}
	case TEAM_ATTR_OPTION_CHANGED:
		info->changed = 1;
		break;
	case TEAM_ATTR_OPTION_TYPE:
		info->type = mnl_attr_get_u8(attr);
		break;
	case TEAM_ATTR_OPTION_DATA:
		switch (info->type) {
		case MNL_TYPE_UNSPEC:
		case MNL_TYPE_U16:
		case MNL_TYPE_U64:
		case MNL_TYPE_MSECS:
		case MNL_TYPE_NESTED:
		case MNL_TYPE_NESTED_COMPAT:
		case MNL_TYPE_NUL_STRING:
			break;

		case MNL_TYPE_U8:
			info->data.u8 = mnl_attr_get_u8(attr);
			break;
		case MNL_TYPE_U32:
		case MNL_TYPE_FLAG:
			info->data.u32 = mnl_attr_get_u32(attr);
			break;
		case MNL_TYPE_STRING:
			info->data.str = strdup(mnl_attr_get_str(attr));
			break;
		case MNL_TYPE_BINARY:
			payload_len = mnl_attr_get_payload_len(attr);
			info->data.binary = malloc(payload_len);
			if (info->data.binary == NULL)
				break;

			memcpy(info->data.binary,
			       mnl_attr_get_payload(attr), payload_len);
			break;

		default:
			/* catch signed 32-bit ints here.  There is no
			 * MNL_TYPE_ defined for this.
			 */
			info->data.u32 = mnl_attr_get_u32(attr);
		}
		break;

	case TEAM_ATTR_OPTION_REMOVED:
		info->removed = 1;
		break;
	case TEAM_ATTR_OPTION_PORT_IFINDEX:
		info->port_ifindex = mnl_attr_get_u32(attr);
		break;
	case TEAM_ATTR_OPTION_ARRAY_INDEX:
		info->array_index = mnl_attr_get_u32(attr);
		break;
	default:
		return MNL_CB_ERROR;
	}

	return MNL_CB_OK;
}

static int team_option_list(const struct nlattr *attr, void *data)
{
	return mnl_attr_parse_nested(attr, team_option, data);
}

static int process_team_options(const struct team_option_info *info)
{
	if (!strcmp(info->name, "enabled")) {
		lag_select(info->ifp_slave, info->data.u32);
		lag_slave_sync_mac_address(info->ifp_slave);
	} else if (!strcmp(info->name, "mode")) {
		if (!strcmp(info->data.str, "activebackup"))
			lag_mode_set_activebackup(info->ifp_master);
		else if (!strcmp(info->data.str, "loadbalance"))
			lag_mode_set_balance(info->ifp_master);
		else {
			DP_DEBUG(LAG, ERR, DATAPLANE,
				 "team unknown mode \"%s\"\n", info->data.str);
			return MNL_CB_OK;
		}

		DP_DEBUG(LAG, NOTICE, DATAPLANE,
			 "teamd runner set ifindex %d mode to %s\n",
			 info->ifindex, info->data.str);
	} else if (!strcmp(info->name, "bpf_hash_func"))
		/* future work */
		return MNL_CB_OK;
	else if (!strcmp(info->name, "activeport")) {
		struct ifnet *ifp_slave = dp_ifnet_byifindex(info->data.u32);

		if (ifp_slave)
			lag_set_activeport(info->ifp_master, ifp_slave);
		else
			DP_DEBUG(LAG, ERR, DATAPLANE,
				 "team cannot find activeport ifindex %u\n",
				 info->data.u32);
	} else {
		DP_DEBUG(LAG, ERR, DATAPLANE,
			 "team unhandled option \"%s\"\n", info->name);
		return MNL_CB_OK;
	}

	return MNL_CB_OK;
}

static int process_team_optionlist(const struct nlmsghdr *nlh)
{
	struct team_option_info info = { .ifindex = 0,};
	struct nlattr *tb[TEAM_ATTR_MAX + 1] = {NULL, };
	int ret;

	ret = mnl_attr_parse(nlh, GENL_HDRLEN, team_attr, tb);
	if (ret != MNL_CB_OK)
		return ret;

	if (!tb[TEAM_ATTR_LIST_OPTION])
		return MNL_CB_OK;

	if (tb[TEAM_ATTR_TEAM_IFINDEX])
		info.ifindex = mnl_attr_get_u32(tb[TEAM_ATTR_TEAM_IFINDEX]);

	ret = mnl_attr_parse_nested(tb[TEAM_ATTR_LIST_OPTION],
				    team_option_list, &info);
	if (ret != MNL_CB_OK)
		return ret;

	info.ifp_master = ifnet_byteam(info.ifindex);
	if (info.ifp_master == NULL) {
		DP_DEBUG(LAG, ERR, DATAPLANE,
			 "team cannot find master ifindex %d\n", info.ifindex);
		return MNL_CB_OK;
	}

	if (info.port_ifindex) {
		info.ifp_slave = dp_ifnet_byifindex(info.port_ifindex);
		if (!info.ifp_slave ||
				info.ifp_slave->aggregator != info.ifp_master) {
			DP_DEBUG(LAG, ERR, DATAPLANE,
				 "team master changed for slave ifindex %d\n",
				 info.port_ifindex);
			return MNL_CB_OK;
		}
	}

	ret = process_team_options(&info);
	team_option_data_free(&info);

	return ret;
}

int rtnl_process_team(const struct nlmsghdr *nlh, void *data __unused)
{
	struct genlmsghdr *genlhdr = mnl_nlmsg_get_payload(nlh);
	int ret;

	switch (genlhdr->cmd) {
	case TEAM_CMD_OPTIONS_SET:
		ret = MNL_CB_OK;
		break;
	case TEAM_CMD_OPTIONS_GET:
		ret = process_team_optionlist(nlh);
		break;
	case TEAM_CMD_PORT_LIST_GET:
		ret = process_team_portlist(nlh);
		break;
	default:
		DP_DEBUG(LAG, NOTICE, DATAPLANE, "unknown team command %d\n",
			genlhdr->cmd);
		ret = -1;
		break;
	}
	return ret;
}
