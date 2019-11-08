/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
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
#include "vrf.h"
#include "fal.h"
#include "control.h"
#include "dp_event.h"
#include "vplane_log.h"

/*
 * Commands:
 *      route - show main table
 *      route [vrf_id ID] table <N> - show PBR table
 *      route [vrf_id ID] [table N] summary - show main table summary
 *      route [vrf_id ID] [table N] lookup address
 *      route [vrf_id ID] [table N] all - show all local optimisations
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

	vrf = vrf_get_rcu_from_external(vrf_id);
	if (vrf == NULL) {
		fprintf(f, "no vrf exist\n");
		return -1;
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

		if (argc == 2) {
			fprintf(f, "missing address\n");
			goto error;
		}

		if (inet_aton(argv[2], &in) == 0) {
			fprintf(f, "invalid address\n");
			goto error;
		}

		jsonw_name(json, "route_lookup");
		jsonw_start_array(json);
		err = rt_show(&vrf->v_rt4_head, json, tblid, &in);
		jsonw_end_array(json);
	} else {
		fprintf(f,
		    "Usage: route [vrf_id ID] [table N] [show]\n"
		    "       route [vrf_id ID] [table N] all\n"
		    "       route [vrf_id ID] [table N] summary\n"
		    "       route [vrf_id ID] [table N] lookup ADDR\n");
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

	vrf = vrf_get_rcu_from_external(vrf_id);
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

	if (flags & LLE_DELETED)
		return "DELETED";
	if (flags & LLE_STATIC)
		return "STATIC";
	if (flags & LLE_VALID)
		return "VALID";
	if (flags & LLE_LOCAL)
		return "LOCAL";
	if (flags == 0 || flags == LLE_FWDING)
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
		llentry_destroy(ifp->if_lltable, la);
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
	unsigned int count;

	if (la->la_flags & LLE_STATIC)
		return 0;

	if (sa->sa_family != AF_INET)
		return 0;

	count = llentry_destroy(llt, la);

	return count;
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
			ifnet_walk(arp_dump, json);
		else
			ifnet_walk(nd6_dump, json);
		goto end;
	}

	while (--argc) {
		struct ifnet *ifp = ifnet_byifname(*++argv);

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
			ifnet_walk(arp_flush_dev, &addr.address.ip_v4);
		else
			ifnet_walk(nd6_flush_dev, &addr.address.ip_v6);
	} else if (strcmp(argv[1], "dev") == 0) {
		struct ifnet *ifp = ifnet_byifname(argv[2]);

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

static struct cfg_if_list *cfg_garp_list;
static int cmd_garp(FILE *f, int argc, char **argv);

static void
garp_event_if_index_set(struct ifnet *ifp, uint32_t ifindex);
static void
garp_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex);

static const struct dp_event_ops garp_event_ops = {
	.if_index_set = garp_event_if_index_set,
	.if_index_unset = garp_event_if_index_unset,
};

static void
garp_event_if_index_set(struct ifnet *ifp, uint32_t ifindex __unused)
{
	struct cfg_if_list_entry *le;

	if (!cfg_garp_list)
		return;

	le = cfg_if_list_lookup(cfg_garp_list, ifp->if_name);
	if (!le)
		return;

	RTE_LOG(INFO, DATAPLANE,
			"Replaying garp command %s for interface %s\n",
			le->le_buf, ifp->if_name);
	cmd_garp(NULL, le->le_argc, le->le_argv);
	cfg_if_list_del(cfg_garp_list, ifp->if_name);
	if (!cfg_garp_list->if_list_count) {
		cfg_if_list_destroy(&cfg_garp_list);
		dp_event_unregister(&garp_event_ops);
	}
}

static void
garp_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex __unused)
{
	if (!cfg_garp_list)
		return;

	cfg_if_list_del(cfg_garp_list, ifp->if_name);
	if (!cfg_garp_list->if_list_count) {
		cfg_if_list_destroy(&cfg_garp_list);
		dp_event_unregister(&garp_event_ops);
	}
}

static int garp_replay_init(void)
{
	if (!cfg_garp_list) {
		cfg_garp_list = cfg_if_list_create();
		if (!cfg_garp_list)
			return -ENOMEM;
	}
	dp_event_register(&garp_event_ops);
	return 0;
}

static int cmd_garp_global(struct garp_op_ctx *ctx)
{
	if (!ctx->set)
		ctx->action = GARP_PKT_UPDATE;
	set_garp_cfg(ctx->op, ctx->action);
	ifnet_walk(if_garp_op_update, ctx);

	return 0;
}

static int cmd_garp_intf(struct garp_op_ctx *ctx,
			 int argc, char **argv)
{
	struct garp_cfg glob_cfg;
	struct ifnet *ifp;

	ifp = ifnet_byifname(ctx->if_name);
	if (!ifp) {
		if (!cfg_garp_list && garp_replay_init()) {
			RTE_LOG(ERR, DATAPLANE,
				"Could not set up cmd replay cache\n");
			return -ENOMEM;
		}

		RTE_LOG(INFO, DATAPLANE,
			"Caching garp command for interface %s\n",
			argv[3]);
		cfg_if_list_add(cfg_garp_list, ctx->if_name, argc, argv);
		return 0;
	}

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
static int cmd_garp(FILE *f, int argc, char **argv)
{
	struct garp_op_ctx ctx;

	if (argc != 6)
		goto error;

	if (!strcmp(argv[2], "SET"))
		ctx.set = true;
	else if (!strcmp(argv[2], "DELETE"))
		ctx.set = false;
	else
		goto error;

	if (!strcmp(argv[3], "all"))
		ctx.if_name = NULL;
	else
		ctx.if_name = argv[3];

	if (!strcmp(argv[4], "request"))
		ctx.op = ARPOP_REQUEST;
	else if (!strcmp(argv[4], "reply"))
		ctx.op = ARPOP_REPLY;
	else
		goto error;

	if (!strcmp(argv[5], "update"))
		ctx.action = GARP_PKT_UPDATE;
	else if (!strcmp(argv[5], "drop"))
		ctx.action = GARP_PKT_DROP;
	else
		goto error;

	if (!ctx.if_name)
		cmd_garp_global(&ctx);
	else
		cmd_garp_intf(&ctx, argc, argv);

	return 0;

error:
	if (f)
		fprintf(f,
			"Usage: arp gratuitous <SET|DELETE> <intf> <request|reply> <update|drop>\n");
	return -1;
}

/* Process neighbor resolution command */
static int cmd_nbr_res(FILE *f, sa_family_t af, int argc, char **argv)
{
	if (argc == 1)
		return nbr_res_show(f, af, argc, argv);

	--argc, ++argv;	/* skip "arp" */
	if (strcmp(argv[0], "show") == 0)
		return nbr_res_show(f, af, argc, argv);

	else if (strcmp(argv[0], "flush") == 0)
		return nbr_res_flush(f, af, argc, argv);

	else {
		fprintf(f, "unknown command action\n");
		return -1;
	}
}

/* Process "arp ..." command */
int cmd_arp(FILE *f, int argc, char **argv)
{
	return cmd_nbr_res(f, AF_INET, argc, argv);
}

/* Process "arp ..." config command */
int cmd_arp_cfg(FILE *f, int argc, char **argv)
{
	if (argc < 2)
		goto error;

	if (strcmp(argv[1], "gratuitous") == 0)
		return cmd_garp(f, argc, argv);

error:
	fprintf(f, "unknown command action\n");
	return -1;
}


/* Process "nd6 ..." command */
int cmd_nd6(FILE *f, int argc, char **argv)
{
	return cmd_nbr_res(f, AF_INET6, argc, argv);
}
