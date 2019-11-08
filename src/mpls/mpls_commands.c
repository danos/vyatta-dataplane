/*
 * MPLS Commands
 *
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 * Copyright (c) 2017, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <getopt.h>

#include "commands.h"
#include "compat.h"
#include "if_var.h"
#include "json_writer.h"
#include "mpls/mpls.h"
#include "mpls_forward.h"
#include "mpls_label_table.h"
#include "urcu.h"

static void show_mpls_stats(json_writer_t *wr, struct ifnet *ifp)
{
	struct if_mpls_data swstats;

	jsonw_name(wr, "mpls statistics");
	jsonw_start_object(wr);

	if_mpls_stats(ifp, &swstats);
	/* Generic (lower part of if_data) */
	jsonw_uint_field(wr, "in_octets", swstats.ifm_in_octets);
	jsonw_uint_field(wr, "in_ucastpkts", swstats.ifm_in_ucastpkts);
	jsonw_uint_field(wr, "out_octets", swstats.ifm_out_octets);
	jsonw_uint_field(wr, "out_ucastpkts", swstats.ifm_out_ucastpkts);
	jsonw_uint_field(wr, "in_errors", swstats.ifm_in_errors);
	jsonw_uint_field(wr, "out_errors", swstats.ifm_out_errors);
	jsonw_uint_field(wr, "lbl_lookup_failures",
			swstats.ifm_lbl_lookup_failures);
	jsonw_uint_field(wr, "out_fragment_pkts",
			 swstats.ifm_out_fragment_pkts);

	jsonw_end_object(wr);
}



/* Show information mpls interface in JSON */
static void mifconfig(struct ifnet *ifp, void *arg)
{
	json_writer_t *wr = arg;

	jsonw_start_object(wr);

	jsonw_string_field(wr, "name", ifp->if_name);
	jsonw_uint_field(wr, "ifindex", ifp->if_index);
	jsonw_string_field(wr, "mpls",
			   rcu_dereference(ifp->mpls_label_table) ?
			   "on" : "off");
	jsonw_uint_field(wr, "mtu", ifp->if_mtu);
	jsonw_uint_field(wr, "flags", ifp->if_flags);

	show_address(wr, ifp);
	show_mpls_stats(wr, ifp);

	jsonw_end_object(wr);
}

static void mifconfig_up(struct ifnet *ifp, void *arg)
{
	if (ifp->if_flags & IFF_UP && ifp->mpls_label_table)
		mifconfig(ifp, arg);
}


static int cmd_mifconfig(FILE *f, int argc, char **argv)
{
	json_writer_t *wr = jsonw_new(f);

	if (!wr)
		return -1;
	jsonw_pretty(wr, true);
	jsonw_name(wr, "interfaces");
	jsonw_start_array(wr);
	if (argc == 3)
		ifnet_walk(mifconfig_up, wr);
	else if (argc > 3 && strcmp(argv[3], "-a") == 0)
		ifnet_walk(mifconfig, wr);
	else {
		while (--argc > 0) {
			struct ifnet *ifp = ifnet_byifname(*++argv);

			if (ifp)
				mifconfig(ifp, wr);
		}
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);

	return 0;
}

static int mpls_config_dump(FILE *f)
{
	json_writer_t *wr = jsonw_new(f);

	if (!wr)
		return -1;

	jsonw_name(wr, "config");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "ipttlpropagate",
			 mpls_global_get_ipttlpropagate());
	jsonw_int_field(wr, "defaultttl", mpls_global_get_defaultttl());
	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	return 0;
}

static int mpls_oam_lookup(FILE *f, int labelspace,
			   uint8_t nlabels, label_t *labels,
			   uint32_t saddr, uint32_t daddr,
			   unsigned short sport, unsigned short dport,
			   uint64_t bitmask, int masklen)
{
	struct mpls_oam_outinfo outinfo[MPLS_OAM_MAX_FANOUT];
	json_writer_t *wr = jsonw_new(f);
	int oi;

	if (!wr)
		return -1;

	jsonw_name(wr, "mpls oam");
	jsonw_start_array(wr);

	memset(outinfo, 0, sizeof(outinfo));

	masklen = MIN(64, masklen);

	mpls_oam_v4_lookup(labelspace, nlabels, labels, saddr, daddr,
			   sport, dport, bitmask, masklen, outinfo,
			   MPLS_OAM_MAX_FANOUT);

	for (oi = 0; oi < MPLS_OAM_MAX_FANOUT; oi++) {
		char b1[INET_ADDRSTRLEN];

		if (!outinfo[oi].inuse)
			break;

		jsonw_start_object(wr);
		jsonw_uint_field(wr, "inlabel", labels[0]);
		jsonw_uint_field(wr, "bitmask hi",
				 outinfo[oi].bitmask >> 32);
		jsonw_uint_field(wr, "bitmask lo",
				 outinfo[oi].bitmask & 0xFFFFFFFF);
		jsonw_uint_field(wr, "masklen", masklen);
		jsonw_string_field(wr, "downstream inet",
				   inet_ntop(AF_INET, &outinfo[oi].gateway,
					     b1, sizeof(b1)));
		jsonw_uint_field(wr, "oifindex", outinfo[oi].ifp->if_index);
		show_address(wr, outinfo[oi].ifp);
		if (nh_outlabels_present(&outinfo[oi].outlabels)) {
			label_t label;
			unsigned int j;

			jsonw_name(wr, "outlabels");
			jsonw_start_array(wr);

			NH_FOREACH_OUTLABEL(&outinfo[oi].outlabels,
					    j, label)
				jsonw_uint(wr, label);

			jsonw_end_array(wr);
		}
		jsonw_end_object(wr);
	}

	jsonw_end_array(wr);
	jsonw_destroy(&wr);

	return 0;
}

int cmd_mpls(FILE *f, int argc, char **argv)
{
	if (argc == 3 && !strcmp(argv[1], "labeltablesize")) {
		int size = atoi(argv[2]);

		mpls_label_table_resize(global_label_space_id, size);
		return 0;
	} else if (argc == 3 && !strcmp(argv[1], "ipttlpropagate")) {
		bool enable = !strcmp(argv[2], "enable");

		mpls_global_set_ipttlpropagate(enable);
		return 0;
	} else if (argc == 3 && !strcmp(argv[1], "defaultttl")) {
		int ttl = atoi(argv[2]);

		mpls_global_set_defaultttl(ttl);
		return 0;
	} else if (argc >= 3 && !strcmp(argv[1], "show")) {
		if (!strcmp(argv[2], "tables")) {
			mpls_label_table_set_dump(f, -1);
			return 0;
		} else if (!strcmp(argv[2], "ifconfig")) {
			cmd_mifconfig(f, argc, argv);
			return 0;
		} else if (!strcmp(argv[2], "config")) {
			mpls_config_dump(f);
			return 0;
		}
	} else if (argc >= 3 && !strcmp(argv[1], "oam")) {
#define MAX_OAM_LABEL_STACK_DEPTH	(MAX_MP_SELECT_LABELS + 1)
		int opt, opt_index = 0, labelspace = 0;
		label_t labels[MAX_OAM_LABEL_STACK_DEPTH];
		uint32_t saddr = 0, daddr = 0;
		const char *src = NULL, *dest = NULL;
		unsigned short sport = 0, dport = 3503;
		uint64_t bitmask = 0x0;
		uint32_t masklen = 0;
		uint8_t nlabels = 0;
		const char usage[] = "mpls oam usage: -l <label space> "
				"-s <source_ip> -d <dest_ip> "
				"-p <port_source> -t <port_dest> "
				"-i <in_label> -m <mask>";
		const struct option lgopts[] = {
			{ "bitmask",	required_argument, NULL, 'b' },
			{ "dest_ip",	required_argument, NULL, 'd' },
			{ "in_label",	required_argument, NULL, 'i' },
			{ "labelspace",	required_argument, NULL, 'l' },
			{ "masklen",	required_argument, NULL, 'm' },
			{ "port_source", required_argument, NULL, 'p' },
			{ "source_ip",	required_argument, NULL, 's' },
			{ "port_dest",	required_argument, NULL, 't' },
			{ NULL,	0, NULL, 0}
		};

		argc--; argv++;
		while ((opt = getopt_long(argc, argv, "b:d:i:l:m:p:s:t:",
					  lgopts, &opt_index)) != EOF) {
			switch (opt) {
			case 'b':
				bitmask = strtoull(optarg, NULL, 16);
				break;
			case 'd':
				dest = optarg;
				if (inet_pton(AF_INET, dest, &daddr) != 1) {
					fprintf(f, "Invalid dest %s\n",
						optarg);
					optind = 0;
					return -1;
				}
				break;
			case 'i':
				/*
				 * store the label stack up to the max used for
				 * mpls ecmp hash + 1. In this case ecmp hash
				 * will not take into account the ip header
				 * since the bos label is beyond the max label
				 * limit used for ecmp hash.
				 */
				if (nlabels < MAX_OAM_LABEL_STACK_DEPTH) {
					labels[nlabels] = strtol(optarg, NULL,
								 10);
					nlabels++;
				}
				break;
			case 'l':
				labelspace = strtol(optarg, NULL, 10);
				break;
			case 'm':
				masklen = strtol(optarg, NULL, 10);
				break;
			case 'p':
				sport = strtol(optarg, NULL, 10);
				break;
			case 's':
				src = optarg;
				if (inet_pton(AF_INET, src, &saddr) != 1) {
					fprintf(f, "Invalid src %s\n", optarg);
					optind = 0;
					return -1;
				}
				break;
			case 't':
				dport = strtol(optarg, NULL, 10);
				break;
			default:
				fprintf(f, "%s\n", usage);
				optind = 0;
				return -1;
			}
		}

		optind = 0;

		if (!src || !dest || !nlabels) {
			fprintf(f, "%s\n", usage);
			return -1;
		}
		mpls_oam_lookup(f, labelspace, nlabels, labels, saddr, daddr,
				sport, dport, bitmask, masklen);
		return 0;
	}

	fprintf(f, "mpls command invalid\n");
	return -1;
}
