/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/snmp.h>
#include <malloc.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <urcu/list.h>
#include <zmq.h>

#ifdef HAVE_SYSTEMD
 #include <systemd/sd-daemon.h>
#endif /* HAVE_SYSTEMD */

#include <czmq.h>
#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_memzone.h>

#include "arp.h"
#include "bitmask.h"
#include "capture.h"
#include "commands.h"
#include "compat.h"
#include "compiler.h"
#include "config_internal.h"
#include "control.h"
#include "crypto/crypto.h"
#include "dp_event.h"
#include "event_internal.h"
#include "feature_plugin_internal.h"
#include "if/bridge/bridge.h"
#include "if/bridge/bridge_port.h"
#include "if/bridge/switch.h"
#include "if/dpdk-eth/vhost.h"
#include "if/gre.h"
#include "if/vxlan.h"
#include "if_var.h"
#include "json_writer.h"
#include "l2_rx_fltr.h"
#include "l2tp/l2tpeth.h"
#include "lag.h"
#include "main.h"
#include "controller.h"
#include "mstp.h"
#include "netinet6/nd6_nbr.h"
#include "netinet6/route_v6.h"
#include "netinet6/ip6_funcs.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pktmbuf_internal.h"
#include "pd_show.h"
#include "pl_commands.h"
#include "pl_common.h"
#include "pl_node.h"
#include "power.h"
#include "protobuf.h"
#include "protobuf/SpeedConfig.pb-c.h"
#include "protobuf/SynceConfig.pb-c.h"
#include "protobuf/BreakoutConfig.pb-c.h"
#include "rcu.h"
#include "rt_tracker.h"
#include "session/session_cmds.h"
#include "shadow.h"
#include "snmp_mib.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "vrf_if.h"
#include "fal.h"
#include "npf/dpi/app_cmds.h"
#include "storm_ctl.h"
#include "mac_limit.h"
#include "ip_icmp.h"
#include "backplane.h"
#include "vlan_modify.h"
#include "ptp.h"
#include "protobuf/PauseConfig.pb-c.h"

#define MAX_CMDLINE 512
#define MAX_ARGS    128

enum console_cmd_main_flags {
	CONSOLE_CMD_ASYNC = 1<<0,
};

/*
 * Simple command parser
 */

typedef struct cmd {
	uint32_t version;
	const char *name;
	cmd_func_t func;
	const char *help;
} cmd_t;
static const cmd_t cmd_table[];

const char *console_endpoint = "ipc:///var/run/vplane.socket";

/*
 * Socket pair to send commands from the console thread to the
 * main thread for execution and get response back. Note that
 * only a pass/fail response is returned. If command output is
 * required then the command must run only on the console thread.
 *
 * The only current user of this is the "reset" command.
 */
const char *cmd_server_endpoint = "@inproc://main_cmd_event";
const char *cmd_client_endpoint = ">inproc://main_cmd_event";
static zsock_t *main_cmd_server; /* only to be used on main thread */
static zsock_t *console_cmd_client; /* only to be used on console thread */

static const char *rtscope(uint32_t scope)
{
	static char b[16];

	switch (scope) {
	case RT_SCOPE_UNIVERSE:	return "Universe";
	case RT_SCOPE_SITE:	return "Site";
	case RT_SCOPE_HOST:	return "Host";
	case RT_SCOPE_LINK:	return "Link";
	case RT_SCOPE_NOWHERE:	return "Nowhere";
	default:
		sprintf(b, "%d", scope);
		return b;
	}
}

void show_address(json_writer_t *wr, const struct ifnet *ifp)
{
	struct if_addr *ifa;

	jsonw_name(wr, "addresses");
	jsonw_start_array(wr);

	cds_list_for_each_entry(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *) &ifa->ifa_addr;
		const struct sockaddr_in *sin;
		const struct sockaddr_in6 *sin6;
		char b[INET6_ADDRSTRLEN];
		char pfx[INET6_ADDRSTRLEN + 4];

		jsonw_start_object(wr);
		switch (sa->sa_family) {
		case AF_INET:
			sin = satosin(sa);
			snprintf(pfx, sizeof(pfx), "%s/%u",
				 inet_ntop(AF_INET, &sin->sin_addr,
					   b, sizeof(b)),
				 ifa->ifa_prefixlen);

			jsonw_string_field(wr, "inet", pfx);

			sin = satosin((struct sockaddr *)&ifa->ifa_broadcast);
			jsonw_string_field(wr, "broadcast",
					   inet_ntop(AF_INET, &sin->sin_addr,
						     b, sizeof(b)));
			break;
		case AF_INET6:
			sin6 = satosin6(sa);
			snprintf(pfx, sizeof(pfx), "%s/%u",
				 inet_ntop(AF_INET6, &sin6->sin6_addr,
					   b, sizeof(b)),
				 ifa->ifa_prefixlen);
			jsonw_string_field(wr, "inet6", pfx);
			jsonw_string_field(wr, "scope",
					   rtscope(sin6->sin6_scope_id));
			break;
		}
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
}

static int cmd_led(FILE *f, int argc, char **argv)
{

	json_writer_t *wr = jsonw_new(f);
	jsonw_name(wr, "response");
	jsonw_start_object(wr);
	if (argc < 3) {
		jsonw_string_field(wr, "msg", "Error");
		goto out;
	}

	struct ifnet *ifp = dp_ifnet_byifname(argv[1]);
	if (!ifp) {
		jsonw_string_field(wr, "msg", "Error");
		goto out;
	}

	if (strcmp(argv[2], "on") == 0) {
		if (if_blink(ifp, true) < 0) {
			jsonw_string_field(wr, "msg",
				   "Error");
			goto out;
		}
	} else if (strcmp(argv[2], "off") == 0) {
		if_blink(ifp, false);
	} else {
		jsonw_string_field(wr, "msg", "Error");
		goto out;
	}

	jsonw_string_field(wr, "msg", "Ok");
out:
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
	return 0;
}

/* Names for fields in IP/IPv6 MIB. */
const char *ipstat_mib_names[] = {
	[IPSTATS_MIB_INPKTS] = "InReceives",
	[IPSTATS_MIB_INHDRERRORS] = "InHdrErrors",
	[IPSTATS_MIB_INTOOBIGERRORS] = "InTooBigErrors",
	[IPSTATS_MIB_INNOROUTES] = "InNoRoutes",
	[IPSTATS_MIB_INADDRERRORS] = "InAddrErrors",
	[IPSTATS_MIB_INUNKNOWNPROTOS] = "InUnknownProtos",
	[IPSTATS_MIB_INTRUNCATEDPKTS] = "InTruncatedPkts",
	[IPSTATS_MIB_INDISCARDS] = "InDiscards",
	[IPSTATS_MIB_INDELIVERS] = "InDelivers",
	[IPSTATS_MIB_OUTFORWDATAGRAMS] = "OutForwDatagrams",
	[IPSTATS_MIB_OUTPKTS] = "OutRequests",
	[IPSTATS_MIB_OUTDISCARDS] = "OutDiscards",
	[IPSTATS_MIB_OUTNOROUTES] = "OutNoRoutes",
	[IPSTATS_MIB_REASMTIMEOUT] = "ReasmTimeout",
	[IPSTATS_MIB_REASMREQDS] = "ReasmReqds",
	[IPSTATS_MIB_REASMOKS] = "ReasmOKs",
	[IPSTATS_MIB_REASMFAILS] = "ReasmFails",
	[IPSTATS_MIB_FRAGOKS] = "FragOKs",
	[IPSTATS_MIB_FRAGFAILS] = "FragFails",
	[IPSTATS_MIB_FRAGCREATES] = "FragCreates",
	[IPSTATS_MIB_INMCASTPKTS] = "InMcastPkts",
	[IPSTATS_MIB_OUTMCASTPKTS] = "OutMcastPkts",
	[IPSTATS_MIB_INBCASTPKTS] = "InBcastPkts",
	[IPSTATS_MIB_OUTBCASTPKTS] = "OutBcastPkts",
	[IPSTATS_MIB_INOCTETS] = "InOctets",
	[IPSTATS_MIB_OUTOCTETS] = "OutOctets",
	[IPSTATS_MIB_INMCASTOCTETS] = "InMcastOctets",
	[IPSTATS_MIB_OUTMCASTOCTETS] = "OutMcastOctets",
	[IPSTATS_MIB_INBCASTOCTETS] = "InBcastOctets",
	[IPSTATS_MIB_OUTBCASTOCTETS] = "OutBcastOctets",
};

/* Display IP and related mib */
static void show_ipstat(json_writer_t *wr, struct vrf *vrf)
{
	uint64_t sum[IPSTATS_MIB_MAX];
	unsigned int i, lcore;

	memset(sum, 0, sizeof(sum));
	FOREACH_DP_LCORE(lcore) {
		for (i = 0; i < IPSTATS_MIB_MAX; i++)
			sum[i] += vrf->v_stats[lcore].ip.mibs[i];
	}

	jsonw_name(wr, "ip");
	jsonw_start_object(wr);
	for (i = 0; i < ARRAY_SIZE(ipstat_mib_names); i++)
		if (ipstat_mib_names[i])
			jsonw_uint_field(wr, ipstat_mib_names[i], sum[i]);
	jsonw_end_object(wr);
}

static const char *icmpstat_mib_names[] = {
	[ICMP_MIB_INMSGS] = "InMsgs",
	[ICMP_MIB_INERRORS] = "InErrors",
	[ICMP_MIB_INDESTUNREACHS] = "InDestUnreachs",
	[ICMP_MIB_INTIMEEXCDS] = "InTimeExcds",
	[ICMP_MIB_INPARMPROBS] = "InParmProbs",
	[ICMP_MIB_INSRCQUENCHS] = "InSrcQuenchs",
	[ICMP_MIB_INREDIRECTS] = "InRedirects",
	[ICMP_MIB_INECHOS] = "InEchos",
	[ICMP_MIB_INECHOREPS] = "InEchoReps",
	[ICMP_MIB_INTIMESTAMPS] = "InTimestamps",
	[ICMP_MIB_INTIMESTAMPREPS] = "InTimestampReps",
	[ICMP_MIB_INADDRMASKS] = "InAddrMasks",
	[ICMP_MIB_INADDRMASKREPS] = "InAddrMaskReps",
	[ICMP_MIB_OUTMSGS] = "OutMsgs",
	[ICMP_MIB_OUTERRORS] = "OutErrors",
	[ICMP_MIB_OUTDESTUNREACHS] = "OutDestUnreachs",
	[ICMP_MIB_OUTTIMEEXCDS] = "OutTimeExcds",
	[ICMP_MIB_OUTPARMPROBS] = "OutParmProbs",
	[ICMP_MIB_OUTSRCQUENCHS] = "OutSrcQuenchs",
	[ICMP_MIB_OUTREDIRECTS] = "OutRedirects",
	[ICMP_MIB_OUTECHOS] = "OutEchos",
	[ICMP_MIB_OUTECHOREPS] = "OutEchoReps",
	[ICMP_MIB_OUTTIMESTAMPS] = "OutTimestamps",
	[ICMP_MIB_OUTTIMESTAMPREPS] = "OutTimestampReps",
	[ICMP_MIB_OUTADDRMASKS] = "OutAddrMasks",
	[ICMP_MIB_OUTADDRMASKREPS] = "OutAddrMaskReps",
};

static void show_icmpstat(json_writer_t *wr, struct vrf *vrf)
{
	unsigned int i;

	jsonw_name(wr, "icmp");
	jsonw_start_object(wr);
	for (i = 0; i < ARRAY_SIZE(icmpstat_mib_names); i++)
		if (icmpstat_mib_names[i])
			jsonw_uint_field(wr, icmpstat_mib_names[i],
					 vrf->v_icmpstats[i]);
	jsonw_end_object(wr);
}

static const char *arpstat_names[] = {
	"tx_request",	"tx_reply",
	"rx_request",	"rx_reply",
	"received",	"rx_ignored",
	"duplicate_ip",	"dropped",
	"timeout",	"proxy",
	"garp_reqs_dropped", "garp_reps_dropped",
	"mpool_fail", "mem_fail", "cache_limit"
};

static void show_arpstat(json_writer_t *wr, struct vrf *vrf)
{
	unsigned int i;
	const uint64_t *arpstats =  &(vrf->v_arpstat).txrequests;

	/* Not really a MIB */
	jsonw_name(wr, "arp");
	jsonw_start_object(wr);
	for (i = 0; i < ARRAY_SIZE(arpstat_names); i++)
		jsonw_uint_field(wr, arpstat_names[i], arpstats[i]);
	jsonw_end_object(wr);
}

static void show_ip6stat(json_writer_t *wr, struct vrf *vrf)
{
	uint64_t sum[IPSTATS_MIB_MAX];
	unsigned int i, lcore;

	memset(sum, 0, sizeof(sum));
	FOREACH_DP_LCORE(lcore) {
		for (i = 0; i < IPSTATS_MIB_MAX; i++)
			sum[i] += vrf->v_stats[lcore].ip6.mibs[i];
	}

	jsonw_name(wr, "ip6");
	jsonw_start_object(wr);
	for (i = 1; i < ARRAY_SIZE(ipstat_mib_names); i++)
		jsonw_uint_field(wr, ipstat_mib_names[i], sum[i]);
	jsonw_end_object(wr);
}

static const char *icmp6stat_mib_names[] = {
	NULL,
	"InMsgs",
	"InErrors",
	"OutMsgs",
	"OutErrors"
};

static void show_icmp6stat(json_writer_t *wr, struct vrf *vrf)
{
	unsigned int i;

	jsonw_name(wr, "icmp6");
	jsonw_start_object(wr);
	for (i = 1; i < ARRAY_SIZE(icmp6stat_mib_names); i++)
		jsonw_uint_field(wr, icmp6stat_mib_names[i],
				 vrf->v_icmp6stats[i]);

	/* TODO: per-device statistics */
	jsonw_end_object(wr);
}

static const char *nd6stat_names[] = {
	"nd_received", "rx_ignored", "na_rx", "na_tx", "ns_rx", "ns_tx",
	"nd_punt", "duplicate_ip", "dropped", "bad_packet", "timeouts",
	"nud_fail", "res_throttle", "cache_limit", "mpool_fail"
};

static void show_nd6stat(json_writer_t *wr, struct vrf *vrf __unused)
{
	const uint64_t *nd6stats = &nd6nbrstat.received;
	unsigned int i;

	jsonw_name(wr, "nd6");
	jsonw_start_object(wr);
	for (i = 0; i < ARRAY_SIZE(nd6stat_names); i++)
		jsonw_uint_field(wr, nd6stat_names[i], nd6stats[i]);
	jsonw_end_object(wr);
}

static const char * const udpstat_mib_names[] = {
	NULL,
	"InDatagrams",
	"NoPorts",
	"InErrors",
	"OutDatagrams",
	"RcvBufErrors",
	"SndBufErrors"
};

static void show_udpstat(json_writer_t *wr, struct vrf *vrf __unused)
{
	unsigned int i;

	jsonw_name(wr, "udp");
	jsonw_start_object(wr);
	for (i = 1; i < ARRAY_SIZE(udpstat_mib_names); i++)
		jsonw_uint_field(wr, udpstat_mib_names[i], udpstats[i]);
	jsonw_end_object(wr);
}

/* Show SNMP (and related) statistics for forwarding */
static int cmd_netstat(FILE *f, int argc, char **argv)
{
	struct vrf *vrf = NULL;
	vrfid_t vrf_id = VRF_DEFAULT_ID;

	json_writer_t *wr = jsonw_new(f);

	if (!wr)
		return -1;

	/* Get VRF-ID, if specified. */
	if (argc >= 3 &&
		strcmp(argv[1], "vrf_id") == 0) {

		vrf_id = strtoul(argv[2], NULL, 10);
		if (vrf_id < VRF_DEFAULT_ID) {
			fprintf(f, "Invalid VRF ID\n");
			jsonw_destroy(&wr);
			return -1;
		}
	}

	vrf = dp_vrf_get_rcu_from_external(vrf_id);
	if (vrf == NULL) {
		fprintf(f, "Unknown VRF ID\n");
		jsonw_destroy(&wr);
		return -1;
	}

	show_ipstat(wr, vrf);
	show_icmpstat(wr, vrf);
	show_arpstat(wr, vrf);
	show_ip6stat(wr, vrf);
	show_icmp6stat(wr, vrf);
	show_nd6stat(wr, vrf);
	show_udpstat(wr, vrf);
	jsonw_destroy(&wr);

	return 0;
}

/* Show shadow statistics */
static int cmd_shadow(FILE *f, int argc, char **argv)
{
	if (argc == 1)
		shadow_show_summary(f, NULL);
	else
		shadow_show_summary(f, argv[1]);
	return 0;
}

static int cmd_ipsec_engine(FILE *f, int argc, char **argv)
{
	argc -= 2;
	argv += 2;
	(void) argc;

	if (strcmp(argv[0], "probe") == 0)
		return crypto_engine_probe(f);

	fprintf(f, "Invalid IPsec command\n");
	return -1;
}

static vrfid_t
cmd_ipsec_getvrf(FILE *f, int argc, char **argv)
{
	vrfid_t vrf_id = VRF_DEFAULT_ID;

	if (argc > 3 && strcmp(argv[2], "vrf_id") == 0) {
		vrf_id = strtoul(argv[3], NULL, 10);
		if (vrf_id < VRF_DEFAULT_ID)
			fprintf(f, "Invalid VRF ID\n");
	}
	return vrf_id;
}

/* Show IPsec SA statistics */
static int cmd_ipsec(FILE *f, int argc, char **argv)
{
#define CMD_IPSEC_SA		(1 << 0)
#define CMD_IPSEC_POLICY	(1 << 1)
#define CMD_IPSEC_COUNTERS	(1 << 2)
#define CMD_IPSEC_LISTENER	(1 << 3)
#define CMD_IPSEC_SHOW_PMD      (1 << 4)
#define CMD_IPSEC_SHOW_SPI_MAP  (1 << 5)
#define CMD_IPSEC_ENGINE        (1 << 6)
#define CMD_IPSEC_CACHE         (1 << 7)
#define CMD_IPSEC_BIND          (1 << 8)

	unsigned int run_cmds = 0;
	vrfid_t vrfid = VRF_DEFAULT_ID;
	bool brief = false;
	int brief_arg = 0;

	if (argc < 2 || strcmp(argv[1], "sad") == 0) {
		run_cmds |= CMD_IPSEC_SA;
		vrfid = cmd_ipsec_getvrf(f, argc, argv);
		if (vrfid < VRF_DEFAULT_ID)
			return -1;
	}
	if (argc < 2 || strcmp(argv[1], "spd") == 0) {
		run_cmds |= CMD_IPSEC_POLICY;
		vrfid = cmd_ipsec_getvrf(f, argc, argv);
		if (vrfid < VRF_DEFAULT_ID)
			return -1;

		if (argc == 3)
			brief_arg = 2;
		else if (argc == 5)
			brief_arg = 4;
		if (strcmp(argv[brief_arg], "brief") == 0)
			brief = true;
	}
	if (argc < 2 || strcmp(argv[1], "bind") == 0) {
		run_cmds |= CMD_IPSEC_BIND;
		vrfid = cmd_ipsec_getvrf(f, argc, argv);
		if (vrfid < VRF_DEFAULT_ID)
			return -1;
	}
	if (argc < 2 || strcmp(argv[1], "counters") == 0)
		run_cmds |= CMD_IPSEC_COUNTERS;
	if (argc < 2 || strcmp(argv[1], "cache") == 0)
		run_cmds |= CMD_IPSEC_CACHE;
	if (argc == 3 && strcmp(argv[1], "listener") == 0)
		run_cmds |= CMD_IPSEC_LISTENER;
	if (argc < 2 || strcmp(argv[1], "pmd") == 0)
		run_cmds |= CMD_IPSEC_SHOW_PMD;
	if (argc < 2 || strcmp(argv[1], "spi") == 0) {
		run_cmds |= CMD_IPSEC_SHOW_SPI_MAP;
		vrfid = cmd_ipsec_getvrf(f, argc, argv);
		if (vrfid < VRF_DEFAULT_ID)
			return -1;
	}
	if (argc > 2 && strcmp(argv[1], "engine") == 0)
		run_cmds = CMD_IPSEC_ENGINE;

	if (argc > 5 ||
	    (argc > 2 &&
	     run_cmds & ~(CMD_IPSEC_CACHE | CMD_IPSEC_LISTENER |
			  CMD_IPSEC_ENGINE | CMD_IPSEC_SA | CMD_IPSEC_POLICY |
			  CMD_IPSEC_SHOW_SPI_MAP | CMD_IPSEC_BIND))
	    || !run_cmds) {
		fprintf(f, "Invalid IPsec command\n");
		return -1;
	}

	if (run_cmds & CMD_IPSEC_SA)
		crypto_sadb_show_summary(f, vrfid);
	if (run_cmds & CMD_IPSEC_POLICY)
		crypto_policy_show_summary(f, vrfid, brief);
	if (run_cmds & CMD_IPSEC_BIND)
		crypto_policy_bind_show_summary(f, vrfid);
	if (run_cmds & CMD_IPSEC_COUNTERS)
		crypto_show_summary(f);
	if (run_cmds & CMD_IPSEC_CACHE) {
		if (argc > 2)
			crypto_show_cache(f, argv[2]);
		else
			crypto_show_cache(f, NULL);
	}
	if (run_cmds & CMD_IPSEC_LISTENER)
		crypto_add_listener(argv[2]);
	if (run_cmds & CMD_IPSEC_SHOW_PMD)
		crypto_show_pmd(f);
	if (run_cmds & CMD_IPSEC_SHOW_SPI_MAP)
		crypto_sadb_show_spi_mapping(f, vrfid);
	if (run_cmds & CMD_IPSEC_ENGINE)
		cmd_ipsec_engine(f, argc, argv);

	return 0;
}

/* Show memory statistics */
static void mempool_dump(struct rte_mempool *mp, void *arg)
{
	json_writer_t *wr = arg;
	unsigned long mem;

	/* compute mempool size */
	mem = (mp->header_size + mp->elt_size + mp->trailer_size)
		* mp->size;
	mem += sizeof(struct rte_mempool) + mp->private_data_size;

	jsonw_start_object(wr);
	jsonw_string_field(wr, "name", mp->name);
	jsonw_uint_field(wr, "avail",  rte_mempool_avail_count(mp));
	jsonw_uint_field(wr, "inuse",  rte_mempool_in_use_count(mp));
	jsonw_uint_field(wr, "memory",	mem);
	jsonw_end_object(wr);
}

static void mempool_summary(json_writer_t *wr)
{
	jsonw_name(wr, "mempool");
	jsonw_start_array(wr);
	rte_mempool_walk(mempool_dump, wr);
	jsonw_end_array(wr);
}

static void memzone_dump(const struct rte_memzone *mz, void *arg)
{
	json_writer_t *wr = arg;

	jsonw_start_object(wr);
	jsonw_string_field(wr, "name", mz->name);
	jsonw_uint_field(wr, "size", mz->len);
	jsonw_uint_field(wr, "socket", mz->socket_id);
	jsonw_uint_field(wr, "flags", mz->flags);
	jsonw_end_object(wr);
}

static void memzone_summary(json_writer_t *wr)
{
	jsonw_name(wr, "memzone");
	jsonw_start_array(wr);
	rte_memzone_walk(memzone_dump, wr);
	jsonw_end_array(wr);
}

static void malloc_summary(json_writer_t *wr)
{
	struct mallinfo info = mallinfo();

	jsonw_name(wr, "malloc");
	jsonw_start_object(wr);
	jsonw_int_field(wr, "arena", info.arena);
	jsonw_int_field(wr, "ordblks", info.ordblks);
	jsonw_int_field(wr, "smblks", info.smblks);
	jsonw_int_field(wr, "hblks", info.hblks);
	jsonw_int_field(wr, "hblkhd", info.hblkhd);
	jsonw_int_field(wr, "usmblks", info.usmblks);
	jsonw_int_field(wr, "fsmblks", info.fsmblks);
	jsonw_int_field(wr, "uordblks", info.uordblks);
	jsonw_int_field(wr, "fordblks", info.fordblks);
	jsonw_int_field(wr, "keepcost", info.keepcost);
	jsonw_end_object(wr);
}

static void rte_malloc_summary(json_writer_t *wr)
{
	unsigned int socket;
	struct rte_malloc_socket_stats stats;

	/* Iterate through all initialised heaps */
	jsonw_name(wr, "rte_malloc");
	jsonw_start_array(wr);
	for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
		if ((rte_malloc_get_socket_stats(socket, &stats) < 0))
			continue;

		jsonw_start_object(wr);
		jsonw_uint_field(wr, "heap_total_bytes",
				 stats.heap_totalsz_bytes);
		jsonw_uint_field(wr, "free_bytes",
			stats.heap_freesz_bytes);
		jsonw_uint_field(wr, "greatest_free",
			stats.greatest_free_size);
		jsonw_uint_field(wr, "alloc_bytes",
			stats.heap_allocsz_bytes);
		jsonw_uint_field(wr, "alloc_count",
			stats.alloc_count);
		jsonw_uint_field(wr, "free_count",
			stats.free_count);
		jsonw_uint_field(wr, "heap_alloc_bytes",
			stats.heap_allocsz_bytes);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
}

static int cmd_memory(FILE *f,
		       int argc __rte_unused, char **argv __rte_unused)
{
	json_writer_t *wr = jsonw_new(f);

	mempool_summary(wr);
	memzone_summary(wr);
	rte_malloc_summary(wr);
	malloc_summary(wr);
	jsonw_destroy(&wr);

	return 0;
}

/* Display port affinity
 *  affinity show <ifname> -show given port
 */
static int cmd_affinity(FILE *f, int argc, char **argv)
{
	--argc, ++argv;
	if (argc < 1) {
		fprintf(f, "usage: missing affinity command\n");
		return -1;
	}

	if (strcmp(argv[0], "show") == 0)
		return show_affinity(f, argc, argv);

	fprintf(f, "usage: affinity show ...\n");
	return -1;
}

/* Set port affinity
 *  affinity <ifindex> delete     - restore default
 *  affinity <ifindex> set <mask> - set new mask for port
 */
int cmd_affinity_cfg(FILE *f, int argc, char **argv)
{
	unsigned int ifindex;
	bitmask_t rx_mask;
	bitmask_t tx_mask;
	bitmask_t mask;

	--argc, ++argv;
	if (argc < 1) {
		fprintf(f, "usage: missing affinity command\n");
		return -1;
	}

	if (get_unsigned(argv[0], &ifindex) < 0) {
		fprintf(f, "usage: affinity IFINDEX ...\n");
		return -1;
	}

	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);
	if (ifp == NULL) {
		fprintf(f, "unknown ifindex %u\n", ifindex);
		return -1;
	}

	if (ifp->if_type != IFT_ETHER) {
		fprintf(f, "%s is not a ethernet port\n", argv[2]);
		return -1;
	}

	--argc, ++argv;		/* skip IFINDEX */
	if (argc < 1) {
		fprintf(f, "missing affinity action\n");
		return -1;
	}

	if (strcmp(argv[0], "delete") == 0)
		set_port_affinity(ifp->if_port, NULL, NULL);
	else if (strcmp(argv[0], "set") == 0) {
		if (argc < 2) {
			fprintf(f, "missing cpu mask\n");
			return -1;
		}

		if (bitmask_parse(&mask, argv[1]) < 0) {
			fprintf(f, "%s invalid cpu mask\n", argv[1]);
			return -1;
		}

		set_port_affinity(ifp->if_port, &mask, &mask);
	} else if (strcmp(argv[0], "set-rx-tx") == 0) {
		if (argc < 3) {
			fprintf(f, "missing rx & tx cpu masks\n");
			return -1;
		}

		if (bitmask_parse(&rx_mask, argv[1]) < 0) {
			fprintf(f, "%s invalid cpu mask\n", argv[1]);
			return -1;
		}

		if (bitmask_parse(&tx_mask, argv[2]) < 0) {
			fprintf(f, "%s invalid cpu mask\n", argv[2]);
			return -1;
		}

		set_port_affinity(ifp->if_port, &rx_mask, &tx_mask);
	} else {
		fprintf(f,
			"usage: affinity <ifindex> set|set-rx-tx|delete ...\n");
		return -1;
	}

	return 0;
}

static int cmd_cpu(FILE *f, int argc __unused, char **argv __unused)
{
	show_per_core(f);
	return 0;
}

/* Reset connection to controller */
static int cmd_reset(FILE *f __unused, int argc __unused, char **argv __unused)
{
	reset_dataplane(CONT_SRC_MAIN, false);
	return 0;
}

static int cmd_local(FILE *f, int argc, char **argv)
{
	vrfid_t vrf_id = VRF_DEFAULT_ID;
	struct vrf *vrf = NULL;

	if (argc == 3) {
		if (strcmp(argv[1], "vrf_id") == 0)
			vrf_id = atoi(argv[2]);
	}
	vrf = dp_vrf_get_rcu_from_external(vrf_id);
	if (!vrf)
		return -1;

	rt_local_show(&vrf->v_rt4_head, RT_TABLE_MAIN, f);
	fprintf(f, "\n");

	rt6_local_show(&vrf->v_rt6_head, f);

	return 0;
}

static int cmd_vrf(FILE *f, int argc __unused, char **argv __unused)
{
	json_writer_t *wr = jsonw_new(f);
	struct vrf *vrf;
	vrfid_t i;

	if (!wr)
		return -1;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "vrf_table");
	jsonw_start_array(wr);
	for (i = 0; i < VRF_ID_MAX; i++) {
		vrf = vrf_get_rcu(i);
		if (vrf) {
			jsonw_start_object(wr);
			jsonw_uint_field(wr, "vrf_id",
					 dp_vrf_get_external_id(vrf->v_id));
			jsonw_uint_field(wr, "internal_vrf_id", vrf->v_id);
			jsonw_uint_field(wr, "ref_count", vrf->v_ref_count);
			jsonw_end_object(wr);
		}
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
	return 0;
}

/* Display help	 */
static int cmd_help(FILE *f, int argc __unused, char **argv __unused)
{
	const cmd_t *cmd;

	for (cmd = cmd_table; cmd->name; ++cmd)
		fprintf(f, "  %-10s %s\n", cmd->name, cmd->help);
	return 0;
}

/* SNMP system statistics command
 *
 * Analogous to "cat /proc/net/snmp"
 */
static int cmd_snmp(FILE *f, int argc, char **argv)
{
	const char *arg;
	json_writer_t *wr;
	vrfid_t vrf_id = VRF_DEFAULT_ID;
	struct vrf *vrf = NULL;

	/* One arg is required */
	if (argc < 2) {
		fprintf(f, "%s: missing argument: %d", __func__, argc);
		return -1;
	}

	/* Get VRF-ID, if specified. */
	if (argc > 2 &&
		strcmp(argv[1], "vrf_id") == 0) {

		vrf_id = strtoul(argv[2], NULL, 10);
		if (vrf_id < VRF_DEFAULT_ID) {
			fprintf(f, "Invalid VRF ID\n");
			return -1;
		}
		argv += 2;
	}
	vrf = dp_vrf_get_rcu_from_external(vrf_id);
	if (vrf == NULL) {
		fprintf(f, "Unknown VRF ID\n");
		return -1;
	}

	/* Determine if we are collecting ipv4 or ipv6 stats */
	arg = *++argv;
	if (*arg != '-') {
		fprintf(f, "%s: invalid argument: %s", __func__, arg);
		return -1;
	}


	wr = jsonw_new(f);
	if (!wr)
		return -1;

	if (arg[1] == '6')
		show_ip6stat(wr, vrf);
	else
		show_ipstat(wr, vrf);
	jsonw_destroy(&wr);
	return 0;
}

/* Show information l2tp session in JSON */
static void l2tp_show_session(void *s, void *arg)
{
	json_writer_t *wr = arg;
	char addr[INET6_ADDRSTRLEN+1];
	uint32_t family = AF_INET;
	char cookie[64];
	const struct l2tp_session *session = s;

	if (!session)
		return;

	jsonw_start_object(wr);

	jsonw_uint_field(wr, "hdr_len", session->hdr_len);
	if (!(session->flags & L2TP_ENCAP_IPV4)) {
		family = AF_INET6;
		jsonw_string_field(wr, "peer_addr",
				   inet_ntop(family, &session->d_addr.ipv6,
					     addr, sizeof(addr)));
		jsonw_string_field(wr, "local_addr",
				   inet_ntop(family, &session->s_addr.ipv6,
					     addr, sizeof(addr)));
	} else {
		jsonw_string_field(wr, "peer_addr",
				   inet_ntop(family, &session->d_addr.ipv4,
					     addr, sizeof(addr)));
		jsonw_string_field(wr, "local_addr",
				   inet_ntop(family, &session->s_addr.ipv4,
					     addr, sizeof(addr)));
	}
	jsonw_uint_field(wr, "cookie_len", session->cookie_len);

	const uint32_t *ck1 = (const uint32_t *)&session->cookie[0];
	const uint32_t *ck2 = (const uint32_t *)&session->cookie[4];

	if (session->cookie_len == 4)
		sprintf(cookie, "%X", htonl(*ck1));
	else
		sprintf(cookie, "%X%X", htonl(*ck1), htonl(*ck2));
	jsonw_string_field(wr, "cookie", cookie);
	jsonw_uint_field(wr, "peer_cookie_len", session->peer_cookie_len);

	ck1 = (const uint32_t *)&session->peer_cookie[0];
	ck2 = (const uint32_t *)&session->peer_cookie[4];

	if (session->peer_cookie_len == 4)
		sprintf(cookie, "%X", htonl(*ck1));
	else
	  sprintf(cookie, "%X%x", htonl(*ck1), htonl(*ck2));
	jsonw_string_field(wr, "peer_cookie", cookie);
	jsonw_uint_field(wr, "session", session->session_id);
	jsonw_uint_field(wr, "peer_session", session->peer_session_id);
	jsonw_uint_field(wr, "flags", session->flags);
	jsonw_uint_field(wr, "local_seq", session->local_seq);
	jsonw_uint_field(wr, "peer_seq", session->peer_seq);
	jsonw_uint_field(wr, "local_udp_port", session->sport);
	jsonw_uint_field(wr, "peer_udp_port", session->dport);
	jsonw_uint_field(wr, "tunnel", session->tunnel->tunnel_id);
	jsonw_uint_field(wr, "peer_tunnel", session->tunnel->peer_tunnel_id);
	jsonw_string_field(wr, "ifname",
			   session->ifp ? session->ifp->if_name : "");
	jsonw_uint_field(wr, "ip_forwarding",
			 session->ifp ? !pl_node_is_feature_enabled_by_inst(
				 &ipv4_in_no_forwarding_feat,
				 session->ifp) : 0);
	jsonw_uint_field(wr, "ipv6_forwarding",
			 session->ifp ? !pl_node_is_feature_enabled_by_inst(
				 &ipv6_in_no_forwarding_feat,
				 session->ifp) : 0);
	struct ifnet *ifp_xconnect = NULL;

	if (session->xconnect_ifidx)
		ifp_xconnect = dp_ifnet_byifindex(session->xconnect_ifidx);
	jsonw_string_field(wr, "xconnect_ifname",
			   ifp_xconnect ? ifp_xconnect->if_name : "");
	jsonw_uint_field(wr, "xconnect_ttl", session->ttl);
	jsonw_uint_field(wr, "mtu", session->ifp ?
			 session->ifp->if_mtu : 0);
	jsonw_uint_field(wr, "ref_cnt", rte_atomic16_read(&session->refcnt));

	struct l2tp_stats stats;

	l2tp_stats(session, &stats);
	jsonw_name(wr, "stats");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "rx_oos_discards", stats.rx_oos_discards);
	jsonw_uint_field(wr, "rx_cookie_discard", stats.rx_cookie_discards);
	jsonw_end_object(wr);

	jsonw_end_object(wr);
}

/* Show information l2tp tunnel in JSON */
static void l2tp_show_tunnel(void *t, void *arg)
{
	json_writer_t *wr = arg;
	char addr[INET6_ADDRSTRLEN+1];
	uint32_t family = AF_INET;
	struct l2tp_tunnel_cfg *tunnel = (struct l2tp_tunnel_cfg *)t;

	if (!tunnel)
		return;

	jsonw_start_object(wr);

	jsonw_uint_field(wr, "flags", tunnel->flags);
	if (!(tunnel->flags & L2TP_TUNNEL_ENCAP_IPV4))
		family = AF_INET6;
	jsonw_string_field(wr, "peer_addr",
			   inet_ntop(family, &tunnel->d_addr.ipv4,
				     addr, sizeof(addr)));
	jsonw_string_field(wr, "local_addr",
			   inet_ntop(family, &tunnel->s_addr.ipv4,
				     addr, sizeof(addr)));
	jsonw_uint_field(wr, "tunnel_id", tunnel->tunnel_id);
	jsonw_uint_field(wr, "peer_tunnel_id", tunnel->peer_tunnel_id);
	jsonw_uint_field(wr, "udp_port", tunnel->local_udp_port);
	jsonw_uint_field(wr, "peer_udp_port", tunnel->peer_udp_port);
	jsonw_uint_field(wr, "ref_cnt", rte_atomic16_read(&tunnel->refcnt));

	jsonw_end_object(wr);
}

/* L2TP session command
 */
static int cmd_l2tp(FILE *f, int argc, char **argv)
{

	/* One arg is required */
	if (argc < 2) {
		fprintf(f, "%s: missing argument: %d", __func__, argc);
		return -1;
	}

	if (strcmp(argv[1], "-c") == 0) {
		if (argc < 6)
			return -1;
		return l2tp_set_xconnect(argv[2], argv[3], argv[4], argv[5]);
	}

	if (strcmp(argv[1], "-s") == 0) {
		json_writer_t *wr = jsonw_new(f);

		if (!wr)
			return -1;

		jsonw_pretty(wr, true);
		jsonw_name(wr, "l2tp");
		jsonw_start_array(wr);

		if (argc == 2)
			l2tp_session_walk(l2tp_show_session, wr);
		else {
			struct ifnet *ifp = dp_ifnet_byifname(argv[2]);
			if (ifp && ifp->if_softc) {
				struct l2tp_softc *sc = ifp->if_softc;
				l2tp_show_session(sc->sclp_session, wr);
			}
		}
		jsonw_end_array(wr);
		jsonw_destroy(&wr);

		return 0;
	}

	if (strcmp(argv[1], "-t") == 0) {
		json_writer_t *wr = jsonw_new(f);

		if (!wr)
			return -1;


		jsonw_pretty(wr, true);
		jsonw_name(wr, "l2tp_tun");
		jsonw_start_array(wr);

		if (argc == 2)
			l2tp_tunnel_walk(l2tp_show_tunnel, wr);
		jsonw_end_array(wr);
		jsonw_destroy(&wr);
		return 0;
	}

	if (strcmp(argv[1], "clear") == 0) {
		if (argc == 2)
			l2tp_init_stats(NULL);
		else
			l2tp_init_stats(l2tp_session_byid(atoi(argv[2])));
		return 0;
	}

	fprintf(f, "%s: wrong command %s", __func__, argv[1]);
	return -1;
}

static int cmd_lag(FILE *f, int argc __unused, char **argv __unused)
{
	lag_summary(f);
	return 0;
}

/*
 * Set the speed and duplex of an interface
 *
 * speed set <ifname> <auto|10|100|1000|...> [auto|full|half]
 */
static int
cmd_speed_handler(struct pb_msg *msg)
{
	void *payload = (void *)((char *)msg->msg);
	int len = msg->msg_len;
	int ret = 0;

	SpeedConfig *smsg = speed_config__unpack(NULL, len, payload);

	if (!smsg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read SpeedConfig protobuf command\n");
		return -1;
	}

	struct ifnet *ifp;
	uint32_t speed;
	int duplex = -1;
	bool autoneg = false;

	duplex = (smsg->duplex_option);
	switch (smsg->speed_case) {
	case SPEED_CONFIG__SPEED_NUMSPEED:
		speed = (smsg->numspeed);
		if (speed == 0) {
			ret = -1;
			goto OUT;
		}
		break;
	default:
		autoneg = true;
		speed = 0;
		break;
	}

	ifp = dp_ifnet_byifname(smsg->ifname);
	if (!ifp) {
		RTE_LOG(ERR, DATAPLANE,
			"speed applied, but interface missing %s\n",
			smsg->ifname);
		goto OUT;
	}
	if_set_speed(ifp, autoneg, speed, duplex);

 OUT:
	speed_config__free_unpacked(smsg, NULL);
	return ret;
}

PB_REGISTER_CMD(speed_cmd) = {
	.cmd = "vyatta:speed",
	.handler = cmd_speed_handler,
};

static int cmd_synce_handler(struct pb_msg *msg)
{
	void *payload = (void *)((char *)msg->msg);
	struct fal_attribute_t synce_attr;
	int len = msg->msg_len;
	int ret = -1;
	int action = -1;
	int ifindex = -1;

	SynceConfig *smsg = synce_config__unpack(NULL, len, payload);

	if (!smsg) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to read SynceConfig protobuf command\n");
		return ret;
	}

	action = smsg->action;
	ifindex = smsg->ifindex;

	switch (action) {
	case SYNCE_CONFIG__ACTION__SYNCE_ENABLE_INTF:
		synce_attr.id = FAL_PORT_ATTR_SYNCE_ADMIN_STATUS;
		synce_attr.value.u8 = FAL_PORT_SYNCE_ENABLE;
		ret = fal_l2_upd_port(ifindex, &synce_attr);
		if (ret < 0) {
			RTE_LOG(ERR, DATAPLANE, "ENABLE_INTF failed for "
					"ifindex:%d, %d (%s)\n", ifindex, ret,
					strerror(ret));
		}
		break;
	case SYNCE_CONFIG__ACTION__SYNCE_DISABLE_INTF:
		synce_attr.id = FAL_PORT_ATTR_SYNCE_ADMIN_STATUS;
		synce_attr.value.u8 = FAL_PORT_SYNCE_DISABLE;
		ret = fal_l2_upd_port(ifindex, &synce_attr);
		if (ret < 0) {
			RTE_LOG(ERR, DATAPLANE, "DISABLE_INTF failed for "
					"ifindex:%d, %d (%s)\n", ifindex, ret,
					strerror(ret));
		}

		break;
	case SYNCE_CONFIG__ACTION__SYNCE_SET_CLK_SRC:
		synce_attr.id = FAL_SWITCH_ATTR_SYNCE_CLOCK_SOURCE_PORT;
		synce_attr.value.u32 = ifindex;

		ret = fal_set_switch_attr(&synce_attr);

		if (ret < 0) {
			RTE_LOG(ERR, DATAPLANE, "CMD_SET_CLK_SRC failed for "
					"ifindex:%d, %d (%s)\n", ifindex, ret,
					strerror(ret));
		}
		break;
	default:
		RTE_LOG(ERR, DATAPLANE, "%s %d", __func__, __LINE__);
		break;
	}

	synce_config__free_unpacked(smsg, NULL);
	smsg = NULL;

	return ret;
}

PB_REGISTER_CMD(synce_cmd) = {
	.cmd = "vyatta:synce",
	.handler = cmd_synce_handler,
};

static const char *poe_class_to_string(fal_port_poe_class_t class)
{
	switch (class) {
	case FAL_PORT_POE_CLASS_TYPE1_CLASS0:
		return "Type1-Class0";
	case FAL_PORT_POE_CLASS_TYPE1_CLASS1:
		return "Type1-Class1";
	case FAL_PORT_POE_CLASS_TYPE1_CLASS2:
		return "Type1-Class2";
	case FAL_PORT_POE_CLASS_TYPE1_CLASS3:
		return "Type1-Class3";
	case FAL_PORT_POE_CLASS_TYPE2_CLASS0:
		return "Type2-Class0";
	case FAL_PORT_POE_CLASS_TYPE2_CLASS1:
		return "Type2-Class1";
	case FAL_PORT_POE_CLASS_TYPE2_CLASS2:
		return "Type2-Class2";
	case FAL_PORT_POE_CLASS_TYPE2_CLASS3:
		return "Type2-Class3";
	case FAL_PORT_POE_CLASS_TYPE2_CLASS4:
		return "Type2-Class4";
	default:
		return NULL;
	}

	return NULL;
}

static void poe_status(struct ifnet *ifp, void *arg)
{
	json_writer_t *wr = arg;
	int rc;
	bool admin_status = false, oper_status = false;

	rc = if_get_poe(ifp, &admin_status, &oper_status);
	if (rc == 0) {
		struct fal_attribute_t poe_attr;

		jsonw_start_object(wr);
		jsonw_string_field(wr, "name", ifp->if_name);
		jsonw_bool_field(wr, "admin-status", admin_status);
		jsonw_bool_field(wr, "oper-status", oper_status);

		/* get some optional attributes */
		poe_attr.id = FAL_PORT_ATTR_POE_CLASS;
		if (fal_l2_get_attrs(ifp->if_index, 1, &poe_attr) == 0) {
			const char *poe_class =
					poe_class_to_string(poe_attr.value.u8);

			if (poe_class)
				jsonw_string_field(wr, "class", poe_class);
		}

		jsonw_end_object(wr);
	}
}

/*
 * Set the PoE mode of an interface
 *
 * poe enable <ifname> [priority [low|high|ciritcal]]
 *     disable <ifname>
 *     status
 */
int cmd_poe(FILE *f, int argc, char **argv)
{
	struct ifnet *ifp;
	fal_port_poe_priority_t priority = FAL_PORT_POE_PRIORITY_LOW;
	struct fal_attribute_t poe_attr = { .id = FAL_PORT_ATTR_POE_PRIORITY, };
	int rc = 0;

	if (argc < 2)
		goto usage;

	if ((strcmp(argv[1], "enable") == 0 && argc >= 3) ||
	    (strcmp(argv[1], "disable") == 0 && argc == 3)) {
		bool enable;

		if (argc > 3 && strcmp(argv[3], "priority") == 0) {
			if (argc < 5)
				goto usage;
			if (strcmp(argv[4], "low") == 0)
				priority = FAL_PORT_POE_PRIORITY_LOW;
			else if (strcmp(argv[4], "high") == 0)
				priority = FAL_PORT_POE_PRIORITY_HIGH;
			else if (strcmp(argv[4], "critical") == 0)
				priority = FAL_PORT_POE_PRIORITY_CRITICAL;
			else
				goto usage;
		}

		ifp = dp_ifnet_byifname(argv[2]);
		if (!ifp) {
			RTE_LOG(ERR, DATAPLANE,
				"poe applied, but interface missing %s\n",
				argv[2]);
			fprintf(f, "%s: failed to find %s\n",
				__func__, argv[2]);
			goto err_out;
		}

		poe_attr.value.u8 = priority;
		fal_l2_upd_port(ifp->if_index, &poe_attr);

		enable = strcmp(argv[1], "enable") == 0 ? true : false;
		rc = if_set_poe(ifp, enable);
	} else
		goto usage;

	return rc;

usage:
	if (f)
		fprintf(f, "%s: usage: poe [enable|disable <interface>] "
		   "[priority low|high|critical]\n", __func__);
err_out:
	return -1;
}

static int cmd_poe_op(FILE *f, int argc, char **argv)
{
	struct ifnet *ifp = NULL;
	json_writer_t *wr;
	int rc = 0;

	if (argc < 2)
		goto usage;

	if ((strcmp(argv[1], "status") == 0)) {
		if (argc == 3) {
			ifp = dp_ifnet_byifname(argv[2]);
			if (!ifp) {
				RTE_LOG(ERR, DATAPLANE,
					"%s: failed to find %s\n",
					__func__, argv[2]);
				goto err_out;
			}
		}

		wr = jsonw_new(f);

		jsonw_pretty(wr, true);
		jsonw_name(wr, "poe-status");
		jsonw_start_array(wr);

		if (ifp)
			poe_status(ifp, wr);
		else
			dp_ifnet_walk(poe_status, wr);

		jsonw_end_array(wr);
		jsonw_destroy(&wr);
	} else
		goto usage;

	return rc;

usage:
	fprintf(f, "%s: poe [status [interface]]\n", __func__);
err_out:
	return -1;
}

static int cmd_poe_ut(FILE *f, int argc, char **argv)
{
	return cmd_poe(f, argc, argv);
}

static int cmd_ring(FILE *f, int argc, char **argv)
{
	if (argc == 1)
		rte_ring_list_dump(f);
	else {
		while (--argc > 0) {
			const struct rte_ring *r = rte_ring_lookup(*++argv);
			if (r)
				rte_ring_dump(f, r);
		}
	}
	return 0;
}

static int
cmd_pause_handler(struct pb_msg *msg)
{
	struct fal_attribute_t attr;
	void *payload = msg->msg;
	int len = msg->msg_len;
	struct ifnet *ifp;
	int rv = 0;
	enum fal_port_flow_control_mode_t pause_mode;

	PauseConfig *bmsg = pause_config__unpack(NULL, len, payload);

	if (!bmsg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read PauseConfig protobuf command\n");
		return -1;
	}

	switch (bmsg->mtype_case) {
	case PAUSE_CONFIG__MTYPE_PAUSEIF:
		if (!bmsg->pauseif->ifname)
			goto free_msg;

		ifp = dp_ifnet_byifname(bmsg->pauseif->ifname);
		if (!ifp) {
			RTE_LOG(ERR, DATAPLANE,
			"Invalid interface in PauseConfig protobuf command\n");
			rv = -1;
			goto free_msg;
		}

		RTE_LOG(DEBUG, DATAPLANE,
			"Rcvd Pause Mode: %d of interface %s\n",
				bmsg->pauseif->value, ifp->if_name);

		switch (bmsg->pauseif->value) {
		case PAUSE_CONFIG__PAUSE_VALUE__NONE:
			pause_mode = FAL_PORT_FLOW_CONTROL_MODE_DISABLE;
			break;
		case PAUSE_CONFIG__PAUSE_VALUE__RX:
			pause_mode = FAL_PORT_FLOW_CONTROL_MODE_RX_ONLY;
			break;
		case PAUSE_CONFIG__PAUSE_VALUE__TX:
			pause_mode = FAL_PORT_FLOW_CONTROL_MODE_TX_ONLY;
			break;
		case PAUSE_CONFIG__PAUSE_VALUE__BOTH:
			pause_mode = FAL_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE;
			break;
		default:
			RTE_LOG(ERR, DATAPLANE,
					"Unknown PAUSE_CONFIG__PAUSE_VALUE\n");
			rv = -1;
			goto free_msg;
		}
		break;
	default:
		RTE_LOG(ERR, DATAPLANE,
				"Unknown mtype pauseif message :");
		rv = -1;
		goto free_msg;
	}

	attr.value.u8 = pause_mode;
	ifp->if_pause = pause_mode;
	attr.id = FAL_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE;

	rv = fal_l2_upd_port(ifp->if_index, &attr);
	if (rv < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Fal l2 update for port: %d Failed\n", ifp->if_index);
	}

free_msg:
	pause_config__free_unpacked(bmsg, NULL);
	return rv;
}

PB_REGISTER_CMD(pause_cmd) = {
	.cmd = "vyatta:pause",
	.handler = cmd_pause_handler,
};

static struct cfg_if_list *breakout_cfg_list;

static void
breakout_event_if_index_set(struct ifnet *ifp);
static void
breakout_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex __unused);
static int
cmd_breakout_handler(struct pb_msg *msg);

static const struct dp_event_ops breakout_event_ops = {
	.if_index_set = breakout_event_if_index_set,
	.if_index_unset = breakout_event_if_index_unset,
};

static void
breakout_event_if_index_set(struct ifnet *ifp)
{
	struct cfg_if_list_entry *le;
	struct pb_msg msg;

	if (!breakout_cfg_list)
		return;

	le = cfg_if_list_lookup(breakout_cfg_list, ifp->if_name);
	if (!le)
		return;

	msg.msg_len = le->le_argc;
	msg.msg = le->le_buf;
	msg.fp = NULL;
	cmd_breakout_handler(&msg);

	cfg_if_list_del(breakout_cfg_list, ifp->if_name);
	if (!breakout_cfg_list->if_list_count) {
		dp_event_unregister(&breakout_event_ops);
		cfg_if_list_destroy(&breakout_cfg_list);
	}
}

static void
breakout_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex __unused)
{
	if (!breakout_cfg_list)
		return;

	cfg_if_list_del(breakout_cfg_list, ifp->if_name);
	if (!breakout_cfg_list->if_list_count) {
		dp_event_unregister(&breakout_event_ops);
		cfg_if_list_destroy(&breakout_cfg_list);
	}
}

static int breakout_replay_init(void)
{
	if (!breakout_cfg_list) {
		breakout_cfg_list = cfg_if_list_create();
		if (!breakout_cfg_list)
			return -ENOMEM;

		dp_event_register(&breakout_event_ops);
	}
	return 0;
}

static int
cmd_breakout_handler(struct pb_msg *msg)
{
	struct ifnet *reserved_ifp = NULL;
	struct fal_attribute_t attr;
	void *payload = msg->msg;
	int len = msg->msg_len;
	struct ifnet *ifp;
	BreakoutConfig *bmsg = breakout_config__unpack(NULL, len, payload);

	if (!bmsg) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read BreakoutConfig protobuf command\n");
		return -1;
	}

	switch (bmsg->mtype_case) {
	case BREAKOUT_CONFIG__MTYPE_BREAKOUTIF:
		ifp = dp_ifnet_byifname(bmsg->breakoutif->ifname);
		if (!ifp) {
			if (breakout_replay_init() == 0)
				cfg_if_list_bin_add(breakout_cfg_list,
						    bmsg->breakoutif->ifname,
						    payload, len);
			goto free_msg;
		}
		/* reserved interface is optional */
		if (bmsg->breakoutif->reservedifname) {
			reserved_ifp = dp_ifnet_byifname(
				bmsg->breakoutif->reservedifname);
			if (!reserved_ifp) {
				if (breakout_replay_init())
					goto free_msg;
				cfg_if_list_bin_add(
					breakout_cfg_list,
					bmsg->breakoutif->reservedifname,
					payload, len);
				goto free_msg;
			}
		}

		attr.id = FAL_PORT_ATTR_BREAKOUT;
		switch (bmsg->breakoutif->action) {
		case BREAKOUT_CONFIG__ACTION__DELETE:
			RTE_LOG(INFO, DATAPLANE,
				"Removing breakout of interface %s\n",
				ifp->if_name);
			attr.value.u8 = 0;
			ifp->if_broken_out = 0;
			if (reserved_ifp)
				reserved_ifp->if_broken_out = 0;
			break;
		case BREAKOUT_CONFIG__ACTION__SET:
			if (bmsg->breakoutif->numsubports > UINT8_MAX) {
				RTE_LOG(INFO, DATAPLANE,
					"number of sub-ports too large in BreakoutConfig message: %d, max %d\n",
					bmsg->breakoutif->numsubports,
					UINT8_MAX);
				goto free_msg;
			}
			if (reserved_ifp) {
				/*
				 * For the purposes of the dataplane,
				 * this interface is broken out. No
				 * need to notify FAL plugin beyond
				 * the feature cleanup.
				 */
				reserved_ifp->if_broken_out = 1;
				if_notify_emb_feat_change(reserved_ifp);
				RTE_LOG(INFO, DATAPLANE,
					"Reserved breakout interface %s\n",
					reserved_ifp->if_name);
			}
			attr.value.u8 = bmsg->breakoutif->numsubports;
			RTE_LOG(INFO, DATAPLANE,
				"Breaking out interface %s into %d ports\n",
				ifp->if_name, attr.value.u8);
			ifp->if_broken_out = 1;
			if_notify_emb_feat_change(ifp);
			break;
		default:
			goto free_msg;
		}

		fal_l2_upd_port(ifp->if_index, &attr);

		/*
		 * only do this after updating FAL to avoid incorrect
		 * transient state
		 */
		if (!ifp->if_broken_out)
			if_notify_emb_feat_change(ifp);
		if (reserved_ifp && !reserved_ifp->if_broken_out)
			if_notify_emb_feat_change(reserved_ifp);

		break;
	default:
		RTE_LOG(INFO, DATAPLANE,
			"unhandled BreakoutConfig message type %d\n",
			bmsg->mtype_case);
		goto free_msg;
	}

free_msg:
	breakout_config__free_unpacked(bmsg, NULL);
	return 0;
}

PB_REGISTER_CMD(breakout_cmd) = {
	.cmd = "vyatta:breakout",
	.handler = cmd_breakout_handler,
};

static int cmd_vlan_mod(FILE *f, int argc __unused, char **argv __unused)
{
	vlan_mod_cmd(f, argc, argv);
	return 0;
}

struct dynamic_op_command_entry {
	cmd_t cmd;
	struct cds_list_head list_entry;
};

static struct cds_list_head dynamic_op_command_list_head =
	CDS_LIST_HEAD_INIT(dynamic_op_command_list_head);

/*
 * Table of possible commands.
 * Add new commands in alpha order to keep help output sorted.
 */
static const cmd_t cmd_table[] = {
	{ 0,	"affinity",	cmd_affinity,	"Show/set CPU affinity" },
	{ 0,	"app-op",	cmd_app_op,      "Application commands" },
	{ 0,	"arp",		cmd_arp,	"Show/reset ARP table" },
	{ 1,	"arp",		cmd_arp,	"Show/reset ARP table" },
	{ 0,    "backplane",    cmd_backplane_op, "Backplane op mode cmds" },
	{ 0,	"bridge",	cmd_bridge,	"Show/clear bridge MAC table" },
	{ 0,	"capture",	cmd_capture,	"Enable/disable packet capture" },
	{ 0,	"cgn-op",	cmd_cgn_op,	"CG-NAT OP mode" },
	{ 0,	"cgn-ut",	cmd_cgn_ut,	"CG-NAT UT mode" },
	{ 0,	"cpp-rl-op",	cmd_cpp_rl_op,	"Show/clear CPP stats" },
	{ 0,	"cpu",		cmd_cpu,	"Show CPU load" },
	{ 0,	"debug",	cmd_debug,	"Debug logging level" },
	{ 0,	"ecmp",		cmd_ecmp,	"Show/set ecmp options" },
	{ 0,	"fal",		cmd_fal,	"FAL debugging commands" },
	{ 0,	"gre",		cmd_gre,	"Show gre information" },
	{ 0,	"help",		cmd_help,	"This help" },
	{ 0,	"hotplug",	cmd_hotplug,	"Hotplug event" },
	{ 0,	"ifconfig",	cmd_ifconfig,	"Show interface settings" },
	{ 1,	"ifconfig",	cmd_ifconfig,	"Show interface settings" },
	{ 2,	"ifconfig",	cmd_ifconfig,	"Show interface settings" },
	{ 3,	"ifconfig",	cmd_ifconfig,	"Show interface settings" },
	{ 0,	"incomplete",	cmd_incomplete,	"Show incomplete stats" },
	{ 0,	"ipsec",	cmd_ipsec,	"Show IPsec information" },
	{ 0,	"l2tpeth",	cmd_l2tp,	"Show l2tp sessions" },
	{ 0,	"lag",		cmd_lag,	"Show Link Aggregation" },
	{ 0,	"led",		cmd_led,	"Toggle interface LED" },
	{ 0,	"local",	cmd_local,	"Show local IP addresses" },
	{ 0,	"log",		cmd_log,	"Show log messages" },
	{ 0,	"main",		cmd_main,	"state machine information" },
	{ 0,	"memory",	cmd_memory,	"Memory pool statistics" },
	{ 0,	"mode",		cmd_power_show,	"Power management mode" },
	{ 0,	"mpls",		cmd_mpls,	"Show mpls information" },
	{ 1,	"mpls",		cmd_mpls,	"Show mpls information" },
	{ 0,	"mstp-op",	cmd_mstp_op,	"MSTP operational commands" },
	{ 0,	"mstp-ut",	cmd_mstp_ut,	"MSTP unit-test" },
	{ 0,	"multicast",	cmd_multicast,	"Multicast information" },
	{ 0,	"nat-op",	cmd_nat_op,	"NAT OP mode" },
	{ 0,	"nat-ut",	cmd_nat_ut,	"NAT UT mode" },
	{ 2,	"nd6",		cmd_nd6,	"IPv6 Neighbour discovery" },
	{ 0,	"netstat",	cmd_netstat,	"Network statistics" },
	{ 1,	"npf-op",	cmd_npf_op,	"NPF (FW/NAT/PBR) OP mode" },
	{ 1,	"npf-ut",	cmd_npf_ut,	"NPF (FW/NAT/PBR) UT mode" },
	{ 1,	"pathmonitor",	cmd_pathmonitor, "pathmonitor command" },
	{ 1,    "pd",           cmd_pd,         "Platform dependent data" },
	{ 0,	"pipeline",	op_pipeline,	"Pipeline op dispatcher" },
	{ 0,    "feat-plugin",  cmd_feat_plugin,"Feature plugin commands" },
	{ 0,	"poe",		cmd_poe_op,	"poe commands" },
	{ 0,	"poe-ut",	cmd_poe_ut,	"poe commands" },
	{ 0,	"portmonitor",	cmd_portmonitor, "portmonitor command" },
	{ 1,	"portmonitor",	cmd_portmonitor, "portmonitor command" },
	{ 0,	"ptp",		cmd_ptp_op,	"PTP commands" },
	{ 0,	"ptp-ut",	cmd_ptp_ut,	"PTP (unit tests)" },
	{ 9,	"qos",		cmd_qos_op,	"Show Qos information" },
	{ 0,	"reset",	cmd_reset,	"Reset dataplane" },
	{ 0,	"ring",		cmd_ring,	"Display ring information" },
	{ 0,	"route",	cmd_route,	"Display routing information" },
	{ 1,	"route",	cmd_route,	"Display routing information" },
	{ 0,	"route6",	cmd_route6,	"Display ipv6 routing information" },
	{ 0,    "rt-tracker",   cmd_rt_tracker_op, "Route Tracker commands" },
	{ 0,	"session-op",	cmd_session_op,	"Display session table info" },
	{ 0,	"session-ut",	cmd_session_ut,	"session table UT cmds" },
	{ 0,	"slowpath",	cmd_shadow,	"Slow path statistics" },
	{ 0,	"snmp",		cmd_snmp,	"SNMP network statistics" },
	{ 2,    "storm-ctl",    cmd_storm_ctl_op, "Storm control commands" },
	{ 0,    "switch",       cmd_switch_op,  "Switch op-mode commands" },
	{ 0,	"vhost-client",	cmd_vhost_client,
					"vhost-client interface management" },
	{ 2,	"vhost-client",	cmd_vhost_client,
					"vhost-client interface management" },
	{ 1,	"vhost",	cmd_vhost,	"vhost interface management" },
	{ 0,	"vlan_mod",	cmd_vlan_mod,	"show vlan_mod info" },
	{ 0,	"vrf",		cmd_vrf,	"Show VRF information" },
	{ 0,	"vxlan",	cmd_vxlan,      "VXLAN commands" },
	{ 0,	"mac-limit",    cmd_mac_limit_op, "MAC limiting commands" },
	{ 0,	NULL,		NULL,		NULL }
};

void list_all_cmd_versions(FILE *f)
{
	for (const cmd_t *cmd = cmd_table; cmd->name; ++cmd)
		fprintf(f, "%s %u\n", cmd->name, cmd->version);
}

static const struct cmd *find_cmd(const struct cmd *tbl, const char *name)
{
	const cmd_t *cmd = NULL;
	struct dynamic_op_command_entry	*dynamic_op_cmd = NULL;

	if (name[0] != '#' && name[0] != 0) {
		for (cmd = tbl; cmd->name; ++cmd)
			if (strcmp(cmd->name, name) == 0)
				return cmd;
	}

	/* And check the dynamically registered commands too */
	cds_list_for_each_entry_rcu(dynamic_op_cmd,
				    &dynamic_op_command_list_head,
				    list_entry) {
		if (strcmp(dynamic_op_cmd->cmd.name, name) == 0)
			return &dynamic_op_cmd->cmd;
	}

	return NULL;
}

int dp_feature_register_string_op_handler(const char *name,
					  const char *help,
					  feature_string_op_fn *fn)
{
	const cmd_t *cmd = NULL;
	struct dynamic_op_command_entry	*dynamic_op_cmd;

	if (!name || !fn || !help)
		return -EINVAL;

	cmd = find_cmd(cmd_table, name);
	if (cmd) {
		RTE_LOG(ERR, DATAPLANE,
			 "Can not register op cmd. Cmd %s already exists\n",
			 cmd->name);
		return -EINVAL;
	}

	dynamic_op_cmd = calloc(1, sizeof(*dynamic_op_cmd));
	if (!dynamic_op_cmd) {
		RTE_LOG(ERR, DATAPLANE,
			 "Can not register op cmd. No memory\n");
		return -EINVAL;
	}

	dynamic_op_cmd->cmd.version = 0;
	dynamic_op_cmd->cmd.name = strdup(name);
	if (!dynamic_op_cmd->cmd.name) {
		RTE_LOG(ERR, DATAPLANE,
			 "Can not register op cmd. No memory\n");
		free(dynamic_op_cmd);
		return -EINVAL;
	}
	dynamic_op_cmd->cmd.func = fn;
	dynamic_op_cmd->cmd.help = help;

	cds_list_add_rcu(&dynamic_op_cmd->list_entry,
			 &dynamic_op_command_list_head);
	return 0;
}

void feature_unregister_all_string_op_handlers(void)
{
	struct dynamic_op_command_entry	*cmd = NULL;
	struct cds_list_head *this_entry, *next;

	cds_list_for_each_safe(this_entry, next,
			       &dynamic_op_command_list_head) {
		cmd = cds_list_entry(this_entry,
				     struct dynamic_op_command_entry,
				     list_entry);

		cds_list_del_rcu(&cmd->list_entry);
		free((char *)cmd->cmd.name);
		free(cmd);
	}
}

/* Split command string into argument vector.
 * NB: Silently truncates if too many arguments given.
 */
static int split(char *line, char **argv, size_t maxargs)
{
	unsigned int i;
	const char whitespace[] = " \t\r\n";
	char *saveptr;

	argv[0] = strtok_r(line, whitespace, &saveptr);

	for (i = 1; i < maxargs-1; i++) {
		argv[i] = strtok_r(NULL, whitespace, &saveptr);
		if (argv[i] == NULL)
			break;
	}

	return i;
}

/*
 * Join a string.
 * returns NULL if the size isn't right.
 */
static const char *unsplit(char *line, int size, int argc, char **argv)
{
	int i;
	int total = 0;

	for (i = 0; i < argc; ++i) {
		int n;
		n = snprintf(line + total, size - total, "%s ", argv[i]);
		if (n < 0 || n >= size - total)
			return NULL;
		total += n;
	}
	line[--total] = '\0'; /* Remove trailing NUL */
	return line;
}

/* Free the memory that was allocated by open_memstream() to
   hold output of command. Called by zmq when send completes. */
static void out_free(void *data, void *hint __unused)
{
	free(data);
}

/* Send console command to be handled on the main thread.
 * async == true: don't wait for a response.
 */
static int send_console_cmd(cmd_func_t fn, int argc, char **argv, bool async)
{
	int rv = -1;
	int cmd_response;
	enum console_cmd_main_flags flags = 0;
	char line[MAX_CMDLINE];

	if (async)
		flags |= CONSOLE_CMD_ASYNC;

	rcu_read_unlock();
	rcu_thread_offline();

	if (unsplit(line, MAX_CMDLINE, argc, argv) == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"send console cmd: too many args\n");
		goto out;
	}

	rv = zsock_send(console_cmd_client, "psi", fn, line, flags);
	if (rv < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to send console cmd to main\n");
		goto out;
	}

	if (async)
		goto out;

	rv = zsock_recv(console_cmd_client, "i", &cmd_response);

	if (rv < 0)
		RTE_LOG(ERR, DATAPLANE,
			"failed to get console cmd response from main\n");
	else
		rv = cmd_response;
out:
	rcu_thread_online();
	rcu_read_lock();

	return rv;
}

int console_cmd(char *line, char **outbuf, size_t *outsize, cmd_func_t fn,
		bool on_main)
{
	char *argv[MAX_ARGS] = { NULL };
	int argc = split(line, argv, MAX_ARGS);

	int rc = -1;
	if (argv[0]) {
		const cmd_t *cmd = NULL;
		FILE *f = open_memstream(outbuf, outsize);
		if (f == NULL)
			return -1;

		if (!fn) {
			cmd = find_cmd(cmd_table, argv[0]);
			if (cmd == NULL) {
				fprintf(f, "Unknown command: %s\n", argv[0]);
				fn = NULL;
			} else
				fn = cmd->func;
		}

		if (fn) {
			/*
			 * The reset command can only run on the main thread.
			 * If this is reset and we are not on the main
			 * thread, send it there.
			 */
			if (!on_main && (fn == cmd_reset))
				rc = send_console_cmd(fn, argc, argv, true);
			else
				/* Stash output from command in buffer. */
				rc = (*fn)(f, argc, argv);
		}

		fclose(f);
	}

	return rc;
}

static int
console_request(zloop_t *loop __rte_unused, zsock_t *sock,
		void *arg __rte_unused)
{
	char *line = zstr_recv(sock);

	if (!line) {
		if (zsys_interrupted)
			return -1;

		if (errno == EAGAIN || errno == EINTR)
			return 0;

		RTE_LOG(ERR, DATAPLANE,
			"console msg receive failed: %s\n", strerror(errno));
		return -1;
	}
	rcu_thread_online();

	char *outbuf = NULL;
	size_t outsize = 0;
	rcu_read_lock();

	int rc = 0;

	/* dispatch protobuf op commands here */
	if (strncmp(line, "protobuf", 8) == 0) {
		zmsg_t *msg = zmsg_recv(sock);
		zframe_t *frame = zmsg_first(msg);
		unsigned char *data = zframe_data(frame);
		int len = zframe_size(frame);

		rc = pb_op_cmd(sock, data, len, NULL);

		zmsg_destroy(&msg);
		rcu_read_unlock();
		rcu_thread_offline();
		zstr_free(&line);

		return rc;
	}

	rc = console_cmd(line, &outbuf, &outsize, NULL, false);

	rcu_read_unlock();

	rcu_thread_offline();

	zstr_free(&line);

	/* Send two-part response */
	const char *resp = (rc == 0) ? "OK" : "ERROR";
	zstr_sendm(sock, resp);

	zmq_msg_t m;
	zmq_msg_init_data(&m, outbuf, outsize, out_free, NULL);
	rc = zmq_msg_send(&m, zsock_resolve(sock), 0);
	zmq_msg_close(&m);

	return (rc < 0) ? rc : 0;
}

static void
set_nonroot_user_access(const char *endpoint)
{
	/* allow non-root user access */
	if (dataplane_gid != 0 && strncmp(endpoint, "ipc://", 6) == 0) {
		const char *console_path = endpoint + 6;

		/* Make socket accessible from vyatta user */
		if (chmod(console_path, 0770) < 0)
			rte_panic("can't chmod %s (%s)\n",
				  console_path, strerror(errno));

		if (chown(console_path, dataplane_uid, dataplane_gid) < 0)
			rte_panic("can't chown %s (%s)\n",
				  console_path, strerror(errno));
	}
}

static int
console_pair_request(zloop_t *loop __rte_unused, zsock_t *sock, void *arg)
{
	char *ep = NULL;
	zsock_t *console_sock = arg;
	char *line = zstr_recv(sock);

	if (!line) {
		if (zsys_interrupted)
			return -1;

		RTE_LOG(ERR, DATAPLANE,
			"console pair msg receive failed: %s\n",
			strerror(errno));
		return -1;
	}

	char *argv[MAX_ARGS] = { NULL };
	int argc = split(line, argv, MAX_ARGS);

	int rc = 0;

	if (argv[0]) {
		if (!strcmp(argv[0], "BIND")) {
			if (argc < 2) {
				RTE_LOG(ERR, DATAPLANE,
					"console pair BIND expects an endpoint\n");
				rc = -1;
				goto free_and_return;
			}
			if (zsock_bind(console_sock, "%s", argv[1]) < 0)
				rte_panic("console bind %s (%s)\n", argv[1],
					strerror(errno));
			ep = zsock_last_endpoint(console_sock);
			if (ep == NULL)
				rte_panic("zsock_last_endpoint (%s)\n",
					strerror(errno));
			/* Allow non-root user access on console_endpoint */
			set_nonroot_user_access(ep);
			zstr_sendm(sock, "OK");
			zstr_send(sock, ep);
			free(ep);
		} else if (!strcmp(argv[0], "UNBIND")) {
			if (argc < 2) {
				RTE_LOG(ERR, DATAPLANE,
					"console pair UNBIND expects an "
					"endpoint\n");
				rc = -1;
				goto free_and_return;
			}
			if (zsock_unbind(console_sock, "%s", argv[1]) < 0)
				zstr_send(sock, "FAIL");
			else
				zstr_send(sock, "OK");
		} else if (!strcmp(argv[0], "$TERM")) {
			rc = -1;
		} else {
			RTE_LOG(ERR, DATAPLANE, "Unknown message %s"
				" received by %s\n", argv[0], __func__);
			rc = -1;
		}
	}

free_and_return:
	zstr_free(&line);

	return rc;
}

/* Console handling thread */
static void
console_handler(zsock_t *pipe, void *arg __rte_unused)
{
	zsock_t *console_sock;
	pthread_setname_np(pthread_self(), "dataplane/con");

	console_sock = zsock_new_rep(console_endpoint);
	if (!console_sock)
		rte_panic("can't bind console endpoint: %s : %s\n",
			  console_endpoint, strerror(errno));

	/* Socket to send commands to the main thread */
	console_cmd_client = zsock_new_pair(cmd_client_endpoint);
	if (!console_cmd_client)
		rte_panic("failed to create cmd socket: %s\n", strerror(errno));

	/* Allow non-root user access on console_endpoint */
	set_nonroot_user_access(console_endpoint);

	zloop_t *loop = zloop_new();
	if (loop == NULL)
		rte_panic("zloop failed for console handler\n");

#ifdef HAVE_SYSTEMD
	/* notify systemd that we are ready */
	sd_notify(0, "READY=1");
#endif /* HAVE_SYSTEMD */

	zloop_reader(loop, console_sock, console_request, NULL);
	zloop_reader(loop, pipe, console_pair_request, console_sock);

	/* Tell main thread we are ready */
	zsock_signal(pipe, 0);
	zstr_send(pipe, NULL);

	dp_rcu_register_thread();
	rcu_thread_offline();
	while (!zsys_interrupted) {
		if (zloop_start(loop) != 0)
			break;	/* error detected */
	}
	dp_rcu_unregister_thread();
	zloop_destroy(&loop);
	zsock_destroy(&console_sock);
	zsock_destroy(&console_cmd_client);
}

/*
 * Receive commands from the console thread that require execution
 * on the main thread and optionally send a response back.
 */
static int console_cmd_main_handler(void *arg)
{
	zsock_t *sock = (zsock_t *)arg;
	int rv, cmd_response;
	cmd_func_t fn;
	char *line;
	enum console_cmd_main_flags flags;
	char *outbuf = NULL;
	size_t outsize = 0;

	rv = zsock_recv(sock, "psi", &fn, &line, &flags);
	if (rv < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to get cmd from console\n");
		return rv;
	}

	cmd_response = console_cmd(line, &outbuf, &outsize, fn, true);
	if (!(flags & CONSOLE_CMD_ASYNC))
		rv = zsock_send(sock, "i", cmd_response);
	free(line);
	free(outbuf);
	return rv;
}

static zactor_t *console_actor;

/*
 * Setup the console thread and communication between it
 * and the main thread
 */
void console_setup(void)
{
	console_actor = zactor_new(console_handler, NULL);
	if (console_actor == NULL)
		rte_panic("zactor_new failed for console handler\n");
	free(zstr_recv(console_actor));

	main_cmd_server = zsock_new_pair(cmd_server_endpoint);
	if (!main_cmd_server)
		rte_panic("main cmd server socket failed");

	dp_register_event_socket(zsock_resolve(main_cmd_server),
				 console_cmd_main_handler, main_cmd_server);
}

void
console_destroy(void)
{
	free(config.console_url_bound);
	free(config.console_url_bound_uplink);
	zactor_destroy(&console_actor);
	zsock_destroy(&main_cmd_server);
}

int
console_bind(enum cont_src_en cont_src)
{
	const char *console_url = NULL;
	char *response = NULL;
	char *console_url_bound = NULL;

	if (cont_src == CONT_SRC_MAIN)
		console_url = config.console_url;
	else if (cont_src == CONT_SRC_UPLINK)
		console_url = config.console_url_uplink;

	zstr_sendf(console_actor, "BIND %s", console_url);
	int parts = zstr_recvx(console_actor, &response, &console_url_bound,
		NULL);

	int rc = -1;

	if (response) {
		if (!strcmp(response, "OK")) {
			if (parts < 2)
				rte_panic("didn't receive bound endpoint in "
					"response\n");
			if (cont_src == CONT_SRC_MAIN)
				config.console_url_bound =
					strdup(console_url_bound);
			else if (cont_src == CONT_SRC_UPLINK)
				config.console_url_bound_uplink =
					strdup(console_url_bound);
			rc = 0;
		}
	}

	zstr_free(&console_url_bound);
	zstr_free(&response);

	return rc;
}

void
console_unbind(enum cont_src_en cont_src)
{
	char *response;
	char *console_url_bound = NULL;

	if (!console_actor)
		return;

	if (cont_src == CONT_SRC_MAIN)
		console_url_bound = config.console_url_bound;
	else if (cont_src == CONT_SRC_UPLINK)
		console_url_bound = config.console_url_bound_uplink;

	if (!console_url_bound)
		return;

	zstr_sendf(console_actor, "UNBIND %s", console_url_bound);

	response = zstr_recv(console_actor);
	if (response) {
		if (strcmp(response, "OK") != 0)
			RTE_LOG(ERR, DATAPLANE, "Console unbind"
				" failed for ep %s\n", console_url_bound);
	}
	zstr_free(&response);
	free(console_url_bound);

	if (cont_src == CONT_SRC_MAIN)
		config.console_url_bound = NULL;
	else if (cont_src == CONT_SRC_UPLINK)
		config.console_url_bound_uplink = NULL;
}

void
console_endpoint_set(const char *endpoint)
{
	console_endpoint = endpoint;
}
