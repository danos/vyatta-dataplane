/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * Routing debug commands
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <rte_spinlock.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <net/if_arp.h>

#include "arp.h"
#include "commands.h"
#include "compat.h"
#include "ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "ip_addr.h"
#include "ip_mcast.h"
#include "json_writer.h"
#include "netinet6/nd6.h"
#include "netinet6/nd6_nbr.h"
#include "route.h"
#include "util.h"
#include "vrf_internal.h"
#include "vrf_if.h"
#include "fal.h"
#include "control.h"
#include "dp_event.h"
#include "vplane_log.h"

#include "protobuf.h"
#include "protobuf/GArpConfig.pb-c.h"

/*
 * Commands:
 *      route - show main table
 *      route [vrf_id ID] table <N> - show PBR table
 *      route [vrf_id ID] [table N] summary - show main table summary
 *      route [vrf_id ID] [table N] lookup <address> [<prefix-length>]
 *      route [vrf_id ID] [table N] all - show all local optimisations
 *      route [vrf_id ID] [table N] platform [cnt]- show routes in
 *					       the platform (hardware)
 */
int cmd_route(FILE *f, int argc, char **argv)
{
	uint32_t tblid = RT_TABLE_MAIN;
	vrfid_t vrf_id = VRF_DEFAULT_ID;
	struct vrf *vrf;

	if (argc >= 3 && strcmp(argv[1], "vrf_id") == 0) {
		vrf_id = strtoul(argv[2], NULL, 10);

		argc -= 2;
		argv += 2;
	}

	if (argc > 1 && strcmp(argv[1], "table") == 0) {
		if (argc == 2) {
			fprintf(f, "missing table id\n");
			return -1;
		}

		const char *name = argv[2];
		char *endp;

		tblid = strtoul(name, &endp, 0);
		if (*name == '\0' || *endp != '\0') {
			fprintf(f, "invalid table id\n");
			return -1;
		}
		/* skip "table N" */
		argc -= 2;
		argv += 2;
	}

	if (vrf_is_vrf_table_id(tblid)) {
		if (vrf_lookup_by_tableid(tblid, &vrf_id, &tblid) < 0) {
			fprintf(f, "no vrf exists for table %u\n", tblid);
			return -1;
		}
		vrf = vrf_get_rcu(vrf_id);
	} else {
		vrf = dp_vrf_get_rcu_from_external(vrf_id);
	}

	if (vrf == NULL) {
		fprintf(f, "no vrf exists\n");
		return -1;
	}

	json_writer_t *json = jsonw_new(f);

	int err = -1;
	if (argc == 1 || strcmp(argv[1], "show") == 0 ||
	    strcmp(argv[1], "all") == 0) {
		enum rt_walk_type route_type = RT_WALK_RIB;

		if (argc > 1 && strcmp(argv[1], "all") == 0)
			route_type = RT_WALK_ALL;

		if (argc >= 6  && strcmp(argv[2], "get-next") == 0) {
			struct in_addr in;
			long plen;
			long cnt;

			if (inet_aton(argv[3], &in) == 0) {
				fprintf(f, "invalid address\n");
				goto error;
			}
			plen = strtol(argv[4], NULL, 10);
			if (plen < 0 || plen > 32) {
				fprintf(f, "invalid prefix length\n");
				goto error;
			}
			cnt = strtol(argv[5], NULL, 10);
			if (cnt < 0 || cnt > UINT32_MAX) {
				fprintf(f, "invalid count\n");
				goto error;
			}

			jsonw_name(json, "route_show");
			jsonw_start_array(json);
			err = rt_walk_next(&vrf->v_rt4_head, json, tblid,
					   &in, plen, cnt, route_type);
			jsonw_end_array(json);
		} else {
			long cnt;

			if (argc > 2) {
				cnt = strtol(argv[2], NULL, 10);
				if (cnt < 0 || cnt > UINT32_MAX) {
					fprintf(f, "invalid count\n");
					goto error;
				}
			} else {
				cnt = UINT32_MAX;
			}

			jsonw_name(json, "route_show");
			jsonw_start_array(json);

			err = rt_walk(&vrf->v_rt4_head, json, tblid,
				      cnt, route_type);
			jsonw_end_array(json);
		}
	} else if (strcmp(argv[1], "summary") == 0) {
		jsonw_name(json, "route_stats");
		jsonw_start_object(json);
		err = rt_stats(&vrf->v_rt4_head, json, tblid);
		jsonw_end_object(json);
	} else if (strcmp(argv[1], "lookup") == 0) {
		struct in_addr in;
		long plen = -1;

		if (argc == 2) {
			fprintf(f, "missing address\n");
			goto error;
		}

		if (inet_aton(argv[2], &in) == 0) {
			fprintf(f, "invalid address\n");
			goto error;
		}

		if (argc > 3) {
			plen = strtol(argv[3], NULL, 10);
			if (plen < 0 || plen > 32) {
				fprintf(f, "invalid prefix length\n");
				goto error;
			}
		}

		jsonw_name(json, "route_lookup");
		jsonw_start_array(json);
		if (plen >= 0)
			err = rt_show_exact(&vrf->v_rt4_head, json, tblid, &in,
					    plen);
		else
			err = rt_show(&vrf->v_rt4_head, json, tblid, &in);
		jsonw_end_array(json);
	} else if (strcmp(argv[1], "platform") == 0) {

		long cnt = UINT32_MAX;

		if (argc > 2) {
			cnt = strtol(argv[2], NULL, 10);
			if (cnt < 0 || cnt > UINT32_MAX) {
				fprintf(f, "invalid count\n");
				goto error;
			}
		}
		struct fal_attribute_t attr_list[] = {
			{ FAL_ROUTE_WALK_ATTR_VRFID,
			.value.u32 = vrf_id },
			{ FAL_ROUTE_WALK_ATTR_TABLEID,
			.value.u32 = tblid },
			{ FAL_ROUTE_WALK_ATTR_CNT,
			.value.u32 = cnt },
			{ FAL_ROUTE_WALK_ATTR_FAMILY,
			.value.u32 = FAL_IP_ADDR_FAMILY_IPV4 },
			{ FAL_ROUTE_WALK_ATTR_TYPE,
			.value.u32 = FAL_ROUTE_WALK_TYPE_ALL },
		};

		jsonw_name(json, "route_platform_show");

		jsonw_start_array(json);

		err = fal_ip_walk_routes(rt_show_platform_routes,
					 RTE_DIM(attr_list),
					 attr_list, json);
		jsonw_end_array(json);

		/*TODO For scale, get_next from a prefix can be added */

	} else {
		fprintf(f,
		    "Usage: route [vrf_id ID] [table N] [show]\n"
		    "       route [vrf_id ID] [table N] all\n"
		    "       route [vrf_id ID] [table N] summary\n"
		    "       route [vrf_id ID] [table N] lookup ADDR [PREFIXLENGTH]\n"
		    "       route [vrf_id ID] [table N] platform [cnt]\n");
	}

error:
	jsonw_destroy(&json);
	return err;
}

static const struct mcast_cmd {
	const char *name;
	void (*func)(FILE *, struct vrf *);
} mcast_cmds[] = {
	{ "fcstat",	mfc_stat  },
	{ "fcstat6",	mfc6_stat },
	{ "rtstat",	mrt_stat  },
	{ "rtstat6",	mrt6_stat },
	{ "route",	mrt_dump  },
	{ "route6",	mrt6_dump },
	{ "mif",	mvif_dump },
	{ "mif6",	mvif6_dump },
	{ "all",	mc_dumpall },
	{ NULL,		NULL },
};

int cmd_multicast(FILE *f, int argc, char **argv)
{
	const struct mcast_cmd *cmd;
	vrfid_t vrf_id = VRF_DEFAULT_ID;
	struct vrf *vrf;

	if (argc >= 4 && strcmp(argv[2], "vrf_id") == 0)
		vrf_id = strtoul(argv[3], NULL, 10);

	vrf = dp_vrf_get_rcu_from_external(vrf_id);
	if (!vrf) {
		fprintf(f, "vrf %u does not exist\n", vrf_id);
		return -1;
	}

	for (cmd = mcast_cmds; cmd->name; ++cmd) {
		if (argc >= 2 && strcmp(cmd->name, argv[1]) == 0) {
			(cmd->func)(f, vrf);
			return 0;
		}
	}

	fprintf(f, "Unknown multicast command\n");
	return -1;
}

/**********************************************************/

static const char *arp_flags(uint16_t flags)
{
	static char buf[32];

	flags &= ~LLE_INTERNAL_MASK;

	if (flags & LLE_DELETED)
		return "DELETED";
	if (flags & LLE_STATIC)
		return "STATIC";
	if (flags & LLE_VALID)
		return "VALID";
	if (flags & LLE_LOCAL)
		return "LOCAL";
	if (flags == 0)
		return "PENDING";

	snprintf(buf, sizeof(buf), "%#x", flags);
	return buf;
}

/* Mimic /proc/net/arp output */
static void lle_dump(const struct ifnet *ifp, struct llentry *la, void *arg)
{
	json_writer_t *json = arg;
	const struct sockaddr_in *sin = satosin(ll_sockaddr(la));
	char b1[INET_ADDRSTRLEN];
	char mac[40];

	if (ll_sockaddr(la)->sa_family != AF_INET)
		return;

	jsonw_start_object(json);
	jsonw_string_field(json, "ip", inet_ntop(AF_INET, &sin->sin_addr, b1, sizeof(b1)));
	jsonw_string_field(json, "flags", arp_flags(la->la_flags));

	ether_ntoa_r(&la->ll_addr, mac);
	jsonw_string_field(json, "mac", mac);
	jsonw_string_field(json, "ifname", ifp->if_name);

	if (la->la_flags & LLE_CREATED_IN_HW) {
		jsonw_name(json, "platform_state");
		jsonw_start_object(json);
		fal_ip4_dump_neigh(ifp->if_index, sin, json);
		jsonw_end_object(json);
	}

	jsonw_end_object(json);
}

/* Nested iterators.. woot */
static void arp_dump(struct ifnet *ifp, void *arg)
{
	arp_walk(ifp, lle_dump, arg);
}

/* Callback to delete entry in arp table if matches address */
static void arp_flush_addr(const struct ifnet *ifp,
			   struct llentry *la, void *arg)
{
	struct in_addr *in = arg;
	struct sockaddr *sa = ll_sockaddr(la);

	if (la->la_flags & LLE_STATIC)
		return;

	if (sa->sa_family != AF_INET)
		return;

	if (satosin(sa)->sin_addr.s_addr == in->s_addr) {
		rte_spinlock_lock(&la->ll_lock);
		arp_entry_destroy(ifp->if_lltable, la);
		rte_spinlock_unlock(&la->ll_lock);
	}
}

/* Flush all non-static references to address (arg == &in_addr) */
static void arp_flush_dev(struct ifnet *ifp, void *arg)
{
	arp_walk(ifp, arp_flush_addr, arg);
}

/* Flush all non-static entries on device */
static unsigned int arp_flush_entry(struct lltable *llt, struct llentry *la,
				void *arg __unused)
{
	struct sockaddr *sa = ll_sockaddr(la);

	if (la->la_flags & LLE_STATIC)
		return 0;

	if (sa->sa_family != AF_INET)
		return 0;

	arp_entry_destroy(llt, la);

	/* Dropped pkts are tracked in the ARP stats */
	return 0;
}

static const char *const nd6_state[ND6_LLINFO_MAX + 1] = {
	"INCOMPLETE", "REACHABLE", "STALE", "DELAY", "PROBE"};

static void lle6_dump(const struct ifnet *ifp, struct llentry *la, void *arg)
{
	json_writer_t *json = arg;
	const struct sockaddr_in6 *sin6 = satosin6(ll_sockaddr(la));
	char b1[INET6_ADDRSTRLEN];
	char mac[ETH_ADDR_STR_LEN];

	if (ll_sockaddr(la)->sa_family != AF_INET6)
		return;

	jsonw_start_object(json);
	jsonw_string_field(json, "ip", inet_ntop(AF_INET6, &sin6->sin6_addr,
						 b1, sizeof(b1)));
	jsonw_string_field(json, "flags", arp_flags(la->la_flags));
	jsonw_string_field(json, "state",
			   la->la_state > ND6_LLINFO_MAX ? "UNKNOWN" :
			   nd6_state[la->la_state]);
	ether_ntoa_r(&la->ll_addr, mac);
	jsonw_string_field(json, "mac", mac);
	jsonw_string_field(json, "ifname", ifp->if_name);

	if (la->la_flags & LLE_CREATED_IN_HW) {
		jsonw_name(json, "platform_state");
		jsonw_start_object(json);
		fal_ip6_dump_neigh(ifp->if_index, sin6, json);
		jsonw_end_object(json);
	}

	jsonw_end_object(json);
}

/* Nested iterators.. woot */
static void nd6_dump(struct ifnet *ifp, void *arg)
{
	nd6_nbr_walk(ifp, lle6_dump, arg);
}

/* Callback to delete entry in nd table if matches address */
static void nd6_flush_addr(const struct ifnet *ifp,
			   struct llentry *la, void *arg)
{
	struct in6_addr *in = arg;
	struct sockaddr *sa = ll_sockaddr(la);

	if (la->la_flags & LLE_STATIC)
		return;

	if (sa->sa_family != AF_INET6)
		return;

	if (IN6_ARE_ADDR_EQUAL(&satosin6(sa)->sin6_addr, in)) {
		rte_spinlock_lock(&la->ll_lock);
		nd6_entry_destroy(ifp->if_lltable6, la);
		rte_spinlock_unlock(&la->ll_lock);
	}
}

/* Flush all non-static references to address (arg == &in_addr) */
static void nd6_flush_dev(struct ifnet *ifp, void *arg)
{
	nd6_nbr_walk(ifp, nd6_flush_addr, arg);
}

/* Callback to flush all non-static entries on device */
static unsigned int nd6_flush_entry(struct lltable *llt, struct llentry *la,
				    void *arg __unused)
{
	struct sockaddr *sa = ll_sockaddr(la);

	if (la->la_flags & LLE_STATIC)
		return 0;

	if (sa->sa_family != AF_INET6)
		return 0;

	nd6_entry_destroy(llt, la);

	/* Dropped pkts are tracked in the ND stats */
	return 0;
}

static int nbr_res_show(FILE *f, sa_family_t af, int argc, char **argv)
{
	int err = 0;
	json_writer_t *json = jsonw_new(f);

	jsonw_name(json, af == AF_INET ? "arp" : "nd6");
	jsonw_start_array(json);

	if (argc == 1) {
		if (af == AF_INET)
			dp_ifnet_walk(arp_dump, json);
		else
			dp_ifnet_walk(nd6_dump, json);
		goto end;
	}

	while (--argc) {
		struct ifnet *ifp = dp_ifnet_byifname(*++argv);

		if (!ifp) {
			err = -1;
			goto end;
		}
		if (af == AF_INET)
			arp_walk(ifp, lle_dump, json);
		else
			nd6_nbr_walk(ifp, lle6_dump, json);
	}

 end:
	jsonw_end_array(json);
	jsonw_destroy(&json);
	return err;
}

/* Process "flush ... " sub-command */
static int nbr_res_flush(FILE *f, sa_family_t af, int argc, char **argv)
{
	if (argc < 3) {
		fprintf(f, "missing arguments to flush\n");
		return -1;
	}

	if (strcmp(argv[1], "to") == 0) {
		struct ip_addr addr;

		if (inet_pton(af, argv[2], &addr.address) == 0) {
			fprintf(f, "invalid address\n");
			return -1;
		}

		if (af == AF_INET)
			dp_ifnet_walk(arp_flush_dev, &addr.address.ip_v4);
		else
			dp_ifnet_walk(nd6_flush_dev, &addr.address.ip_v6);
	} else if (strcmp(argv[1], "dev") == 0) {
		struct ifnet *ifp = dp_ifnet_byifname(argv[2]);

		if (!ifp) {
			fprintf(f, "unknown interface\n");
			return -1;
		}

		if (af == AF_INET)
			lltable_walk(ifp->if_lltable, arp_flush_entry, NULL);
		else
			lltable_walk(ifp->if_lltable6, nd6_flush_entry, NULL);
	} else {
		fprintf(f, "bad argument to flush (expect to or dev)\n");
		return -1;
	}
	return 0;
}

/* Process get sub-command */
static int nbr_res_get_cfg(FILE *f, sa_family_t af)
{
	if (af == AF_INET)
		return cmd_arp_get_cfg(f);

	return cmd_nd6_get_cfg(f);
}

struct garp_op_ctx {
	const char           *if_name;
	bool                 set;
	int                  op;
	enum garp_pkt_action action;
};

static void if_garp_op_update(struct ifnet *ifp, void *param)
{
	struct garp_op_ctx *ctx = param;

	/* Update interface only if inheriting default */
	if (ctx->op == ARPOP_REQUEST && ifp->ip_garp_op.garp_req_default)
		ifp->ip_garp_op.garp_req_action = ctx->action;
	else if (ctx->op == ARPOP_REPLY && ifp->ip_garp_op.garp_rep_default)
		ifp->ip_garp_op.garp_rep_action = ctx->action;
}

static int cmd_garp_global(struct garp_op_ctx *ctx)
{
	if (!ctx->set)
		ctx->action = GARP_PKT_UPDATE;
	set_garp_cfg(ctx->op, ctx->action);
	dp_ifnet_walk(if_garp_op_update, ctx);

	return 0;
}

static void cmd_garp_intf_arpop(struct garp_op_ctx *ctx, struct ifnet *ifp)
{
	struct garp_cfg glob_cfg;
	if (ctx->set) {
		if (ctx->op == ARPOP_REQUEST) {
			ifp->ip_garp_op.garp_req_default = 0;
			ifp->ip_garp_op.garp_req_action = ctx->action;
		} else {
			ifp->ip_garp_op.garp_rep_default = 0;
			ifp->ip_garp_op.garp_rep_action = ctx->action;
		}
	} else {
		get_garp_cfg(&glob_cfg);
		if (ctx->op == ARPOP_REQUEST) {
			ifp->ip_garp_op.garp_req_default = 1;
			ifp->ip_garp_op.garp_req_action =
				glob_cfg.garp_req_action;
		} else {
			ifp->ip_garp_op.garp_rep_default = 1;
			ifp->ip_garp_op.garp_rep_action =
				glob_cfg.garp_rep_action;
		}
	}
}

static int cmd_garp_intf_pb(struct garp_op_ctx *ctx)
{

	struct ifnet *ifp;

	ifp = dp_ifnet_byifname(ctx->if_name);
	if (!ifp) {
		RTE_LOG(INFO, DATAPLANE,
			"garp applied, but interface missing %s\n",
			ctx->if_name);
		return -1;
	}

	cmd_garp_intf_arpop(ctx, ifp);
	return 0;
}

/*
 * cmd_garp
 *
 * arp gratuitous <SET|DELETE> < all | <ifname> > <request|reply> <update|drop>
 * SET    <ifname> -> clear default bit, set value on interface
 * DELETE <ifname> -> set default bit, restore default value on interface
 * SET    all      -> set value on interfaces which don't have an override
 * DELETE all      -> set default to UPDATE. update all interfaces which
 *                    don't have an override
 */

/* Process neighbor resolution operational command */
static int cmd_nbr_res(FILE *f, sa_family_t af, int argc, char **argv)
{
	if (argc == 1)
		return nbr_res_show(f, af, argc, argv);

	--argc, ++argv;	/* skip "arp" or "nd6" keyword */
	if (strcmp(argv[0], "show") == 0)
		return nbr_res_show(f, af, argc, argv);

	if (strcmp(argv[0], "flush") == 0)
		return nbr_res_flush(f, af, argc, argv);

	if (!strcmp(argv[0], "get"))
		return nbr_res_get_cfg(f, af);

	fprintf(f, "unknown command action\n");
	return -1;
}

/* Process "arp ..." command */
int cmd_arp(FILE *f, int argc, char **argv)
{
	return cmd_nbr_res(f, AF_INET, argc, argv);
}

/*
 * cmd_garp_cfg_handler (replacing cmd_garp)
 * Protobuf handler for gratuitous arp commands.
 * See the GArpConfig.proto file for details.
 */
static int
cmd_garp_cfg_handler(struct pb_msg *msg)
{
	void *payload = (void *)((char *)msg->msg);
	int len = msg->msg_len;
	int ret = 0;

	GArpConfig *smsg = garp_config__unpack(NULL, len, payload);

	if (!smsg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read GArpConfig protobuf command\n");
		return -1;
	}

	struct garp_op_ctx ctx;

	ctx.set = smsg->set;
	ctx.if_name = smsg->ifname;
	switch (smsg->op) {
	case GARP_CONFIG__ARP_OP__ARPOP_REQUEST:
		ctx.op = ARPOP_REQUEST;
		break;
	case GARP_CONFIG__ARP_OP__ARPOP_REPLY:
		ctx.op = ARPOP_REPLY;
		break;
	default:
		RTE_LOG(ERR, DATAPLANE,
			"Error: Invalid garp command\n");
		ret = -1;
		goto end;
	}

	switch (smsg->action) {
	case GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_DROP:
		ctx.action = GARP_PKT_DROP;
		break;
	case GARP_CONFIG__GARP_PKT_ACTION__GARP_PKT_UPDATE:
		ctx.action = GARP_PKT_UPDATE;
		break;
	default:
		RTE_LOG(ERR, DATAPLANE,
			"Error: Invalid garp command\n");
		ret = -1;
		goto end;
	}

	if (*ctx.if_name == '\0' || !strcmp(ctx.if_name, "all"))
		cmd_garp_global(&ctx);
	else
		cmd_garp_intf_pb(&ctx);
end:
	garp_config__free_unpacked(smsg, NULL);
	return ret;
}

PB_REGISTER_CMD(garp_cfg_cmd) = {
	.cmd = "vyatta:garp",
	.handler = cmd_garp_cfg_handler,
};

/* Process "nd6 ..." command */
int cmd_nd6(FILE *f, int argc, char **argv)
{
	return cmd_nbr_res(f, AF_INET6, argc, argv);
}

int rt_show_platform_routes(const struct fal_ip_address_t *pfx,
			    uint8_t prefixlen,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    void *arg)
{
	uint32_t i, nh_idx;
	char buf[INET6_ADDRSTRLEN+4];
	json_writer_t *wr = (json_writer_t *)arg;
	const char *ifname = NULL;
	fal_object_t nhg = 0;
	struct fal_attribute_t attr;
	struct fal_attribute_t *nhg_attr_list;
	int rv;
	uint32_t nhc;
	enum fal_packet_action_t action = UINT32_MAX;

	if (!arg || !pfx)
		return -1;
	sprintf(buf, "%s/%u", fal_ip_address_t_to_str(pfx, buf,
		sizeof(buf)), prefixlen);

	jsonw_start_object(wr);
	jsonw_string_field(wr, "prefix", buf);

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP:
			nhg = attr_list[i].value.objid;
			break;
		case FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION:
			action = attr_list[i].value.u32;
			break;
		default:
			RTE_LOG(INFO, DATAPLANE,
				"%s: Unhandled list attribute %d\n",
				__func__, attr_list[i].id);
		}
	}
	switch (action) {
	case FAL_PACKET_ACTION_DROP:
		jsonw_string_field(wr, "action", "Drop");
		break;
	case FAL_PACKET_ACTION_FORWARD:
		jsonw_string_field(wr, "action", "Forward");
		break;
	case FAL_PACKET_ACTION_TRAP:
		jsonw_string_field(wr, "action", "Punt");
		break;
	default:
		break;
	}
	if (!nhg) {
		jsonw_end_object(wr);
		return 0;
	}
	/* Get next hop count */
	attr.id = FAL_NEXT_HOP_GROUP_ATTR_NEXTHOP_COUNT;

	rv = fal_ip_get_next_hop_group_attrs(nhg, 1, &attr);
	if (rv) {
		jsonw_end_object(wr);
		return 0;
	}
	nhc = attr.value.u32;
	if (!nhc) {
		jsonw_end_object(wr);
		return 0;
	}
	/* Get list of next hop object ids from next hop group object */
	nhg_attr_list = calloc(nhc, sizeof(*nhg_attr_list));
	if (!nhg_attr_list) {
		RTE_LOG(ERR, DATAPLANE, "%s: out of memory\n", __func__);
		return -ENOMEM;
	}
	for (nh_idx = 0; nh_idx < nhc; nh_idx++)
		nhg_attr_list[nh_idx].id =
			FAL_NEXT_HOP_GROUP_ATTR_NEXTHOP_OBJECT;

	rv = fal_ip_get_next_hop_group_attrs(nhg, nhc, nhg_attr_list);
	if (rv) {
		jsonw_end_object(wr);
		free(nhg_attr_list);
		return 0;
	}
	jsonw_name(wr, "nexthop");
	jsonw_start_array(wr);

	for (nh_idx = 0; nh_idx < nhc; nh_idx++) {
		struct fal_attribute_t nh_attr_list[] = {
			{ FAL_NEXT_HOP_ATTR_INTF,
			.value.u32 = UINT32_MAX },
			{ FAL_NEXT_HOP_ATTR_IP,
			.value.ipaddr = { 0 } },
		};

		rv = fal_ip_get_next_hop_attrs(
				nhg_attr_list[nh_idx].value.objid,
				RTE_DIM(nh_attr_list),
				nh_attr_list);
		if (rv) {
			RTE_LOG(ERR, DATAPLANE,
				"%s: nhg get attr failed rv %d\n",
				__func__, rv);
			jsonw_end_array(wr);
			jsonw_end_object(wr);
			free(nhg_attr_list);
			return 0;
		}
		jsonw_start_object(wr);

		if (nh_attr_list[0].value.u32 != UINT32_MAX) {
			ifname = ifnet_indextoname_safe(
					nh_attr_list[0].value.u32);
			if (ifname)
				jsonw_string_field(wr, "ifname", ifname);
		}
		if (!fal_is_ipaddr_empty(&nh_attr_list[1].value.ipaddr)) {

			fal_ip_address_t_to_str(&nh_attr_list[1].value.ipaddr,
						buf, sizeof(buf));
			jsonw_string_field(wr, "via", buf);
		}
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
	free(nhg_attr_list);
	return 0;
}
