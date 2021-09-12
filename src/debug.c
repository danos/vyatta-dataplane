/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <string.h>

#include "debug.h"
#include "json_writer.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"

uint64_t dp_debug = DP_DBG_DEFAULT;
uint64_t dp_debug_init = DP_DBG_DEFAULT;
static uint64_t dp_debug_allocated_flags;
static uint32_t dp_log_level_init;

struct dp_debug_event_type {
	const char *event_type;
	uint64_t id;
	int bit;
	struct cds_list_head  list_entry;
};

static struct cds_list_head dp_debug_event_list_head;

static int cmd_log_level(FILE *f, int argc, char **argv)
{
	if (argc > 1)
		rte_log_set_global_level(atoi(argv[1]));
	else {
		json_writer_t *wr = jsonw_new(f);

		jsonw_uint_field(wr, "level", rte_log_get_global_level());
		jsonw_destroy(&wr);
	}

	return 0;
}

/* Log types (see rte_log.h) */
static const char *log_type_bits[] = {
	[0] = "EAL",	[1] = "MALLOC",	[2] = "RING",	[3] = "MEMPOOL",
	[4] = "TIMER",	[5] = "PMD",	[6] = "HASH",	[7] = "LPM",
	[8] = "KNI",	[9] = "ACL",	[10] = "POWER", [11] = "METER",
	[12] = "SCHED",	[13] = "PORT",	[14] = "TABLE",	[15] = "PIPELINE",
	[16] = "MBUF",	[17] = "CRYPTODEV", [18] = "EFD", [19] = "EVENTDEV",

	[24] = "USER1",	[25] = "USER2",	[26] = "USER3",	[27] = "USER4",
	[28] = "USER5",	[29] = "USER6",	[30] = "USER7",	[31] = "USER8",
};

static int cmd_log_type(FILE *f, int argc, char **argv)
{
	unsigned int i;
	unsigned int log_type_size = ARRAY_SIZE(log_type_bits);
	const char *name;
	int level;

	if (argc == 1) {
		json_writer_t *wr = jsonw_new(f);

		for (i = 0; i < log_type_size; i++) {
			name = log_type_bits[i];
			if (!name)
				continue;
			level = rte_log_get_level(i);
			if (level < 0)
				continue;
			jsonw_int_field(wr, name, level);
		}
		jsonw_destroy(&wr);
		return 0;
	}

	while (--argc) {
		const char *arg = *++argv;
		int enable = 1;

		if (*arg == '-') {
			enable = 0;
			++arg;
		}

		for (i = 0; i < log_type_size; i++) {
			name = log_type_bits[i];
			if (!name)
				continue;
			if (strcasecmp(name, arg) == 0) {
				rte_log_set_level(i,
					enable ? RTE_LOG_DEBUG
					       : rte_log_get_global_level());
				break;
			}
		}
		if (i == log_type_size) {
			fprintf(f, "%s unknown log type\n", arg);
			return -1;
		}
	}
	return 0;
}

int cmd_log(FILE *f, int argc, char **argv)
{

	if (argc == 1) {
		fprintf(f, "missing log command\n");
		return -1;
	}
	--argc, ++argv;

	if (strcmp(argv[0], "level") == 0)
		return cmd_log_level(f, argc, argv);
	if (strcmp(argv[0], "type") == 0)
		return cmd_log_type(f, argc, argv);

	fprintf(f, "unknown log command: %s\n", argv[0]);
	return -1;
}

/* Control over debug settings */
/* Keep this in sync with vplane_debug.h */
static const char *debug_bits[] = {
	"init",		"link",		"arp",		"bridge",
	"nl_interface",	"nl_route",	"nl_address",	"nl_neighbor",
	"nl_netconf",	"subscribe",	"resync",	"nd6",
	"route",	"macvlan",	"vxlan",	"qos",
	"npf",		"nat",		"l2tp",		"lag",
	"dealer",	"nsh",
	"vti",		"crypto",	"crypto_data",	"vhost",
	"vrf",		"multicast",		"mpls_control",
	"mpls_pkterr",	"dpi",          "qos_dp",       "qos_hw",
	"storm_ctl",	"cpp_rl",	"ptp",          "cgnat",
	"flow-cache",	"mac-limit",	"gpc",		"rldb-acl",
	"twamp",        "sfp-list",     "sfp-mon",
};

/* find debug bit based on name, allow abbreviation */
static int find_debug_bit(const char *str)
{
	unsigned int i;
	struct dp_debug_event_type *event;

	/* Check the hardcoded ones first */
	for (i = 0; i < ARRAY_SIZE(debug_bits); i++)
		if (strncmp(debug_bits[i], str, strlen(str)) == 0)
			return i;

	/* And then the dynamically registered ones */
	cds_list_for_each_entry_rcu(event, &dp_debug_event_list_head,
				    list_entry) {
		if (strcmp(event->event_type, str) == 0)
			return event->bit;
	}

	return -1;
}

static int dp_debug_enable_disable(const char *event_type, bool enable)
{
	int i;

	i = find_debug_bit(event_type);
	if (i < 0)
		return i;

	if (enable)
		dp_debug |= (1ul << i);
	else
		dp_debug &= ~(1ul << i);

	return 0;
}

int dp_debug_enable(const char *event_type)
{
	return dp_debug_enable_disable(event_type, true);
}

int dp_debug_disable(const char *event_type)
{
	return dp_debug_enable_disable(event_type, false);
}

bool dp_debug_is_enabled(uint64_t event_id)
{
	return event_id & dp_debug;
}

static void show_debug(FILE *f)
{
	unsigned int i;
	struct dp_debug_event_type *event;
	char debug_id[2 + (sizeof(dp_debug) * 2) + 1];

	snprintf(debug_id, sizeof(dp_debug), "%#lx", dp_debug);

	/* Output debug in JSON format */
	json_writer_t *wr = jsonw_new(f);
	jsonw_name(wr, "debug");
	jsonw_start_object(wr);
	jsonw_name(wr, debug_id);
	jsonw_start_array(wr);

	for (i = 0; i < ARRAY_SIZE(debug_bits); i++)
		if (dp_debug & (1ul<<i))
			jsonw_string(wr, debug_bits[i]);

	cds_list_for_each_entry_rcu(event, &dp_debug_event_list_head,
				    list_entry) {
		if (dp_debug & event->id)
			jsonw_string(wr, event->event_type);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);
}

int cmd_debug(FILE *f, int argc, char **argv)
{
	int i;

	if (argc == 1) {
		show_debug(f);
		return 0;
	}

	while (--argc) {
		const char *arg = *++argv;

		if (strcmp(arg, "all") == 0) {
			dp_debug = ~0ul;
			rte_log_set_global_level(RTE_LOG_DEBUG);
		} else if (strcmp(arg, "-all") == 0) {
			/* Revert back to the startup debugs */
			dp_debug = dp_debug_init;
			rte_log_set_global_level(dp_log_level_init);
		} else if (*arg == '-') {

			i = dp_debug_disable(arg+1);
			if (i < 0) {
				fprintf(f, "Unknown debug flag %s\n", arg+1);
				return -1;
			}
			if (dp_debug == dp_debug_init)
				rte_log_set_global_level(dp_log_level_init);
		} else {
			i = dp_debug_enable(arg);
			if (i < 0) {
				fprintf(f, "Unknown debug flag %s\n", arg);
				return -1;
			}
			rte_log_set_global_level(RTE_LOG_DEBUG);
		}
	}
	return 0;
}

uint64_t dp_debug_register(const char *event_type)
{
	struct dp_debug_event_type *event;
	int i;

	if (!event_type)
		return 0;

	if (find_debug_bit(event_type) > 0)
		return 0;

	if (dp_debug_allocated_flags == UINT64_MAX) {
		RTE_LOG(ERR, DATAPLANE,
			"no space left for new debug event\n");
		return 0;
	}

	event = malloc(sizeof(*event));
	if (!event) {
		RTE_LOG(ERR, DATAPLANE,
			"no memory for new debug event\n");
		return 0;
	}

	for (i = 0; i < 64; i++) {
		if (!((1ul << i) & dp_debug_allocated_flags)) {
			event->event_type = strdup(event_type);
			if (!event->event_type) {
				free(event);
				RTE_LOG(ERR, DATAPLANE,
					"no memory for new debug event\n");
				return 0;

			}
			dp_debug_allocated_flags |= 1ul << i;
			event->id = 1ul << i;
			event->bit = i;

			cds_list_add_rcu(&event->list_entry,
					 &dp_debug_event_list_head);
			return event->id;
		}
	}
	free(event);
	RTE_LOG(ERR, DATAPLANE,
		"Could not register new debug event\n");
	return 0;
}

void debug_init(void)
{
	unsigned int i;

	CDS_INIT_LIST_HEAD(&dp_debug_event_list_head);

	/* Take a note of the hardcoded flags that are allocated */
	for (i = 0; i < ARRAY_SIZE(debug_bits); i++)
		dp_debug_allocated_flags |= (1ul << i);

	dp_log_level_init = rte_log_get_global_level();

	/*
	 * Set user types to the debug log level, since we are in
	 * control of debugs and these should be controlled by
	 * facility-specific debug flags in combination with the
	 * global log level.
	 */
	for (i = RTE_LOGTYPE_USER1; i <= RTE_LOGTYPE_USER5; i++)
		rte_log_set_level(i, RTE_LOG_DEBUG);
}
