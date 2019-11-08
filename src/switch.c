/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * switch command handling
 */
#include <stdio.h>
#include "json_writer.h"
#include "fal.h"
#include "bridge.h"
#include "bridge_vlan_set.h"
#include "switch.h"

static void switch_get_vlans(struct ifnet *ifp,
			     struct bridge_vlan_set *active_vlans)
{
	struct cds_list_head *entry;
	struct bridge_port *port;
	struct bridge_softc *sc = rcu_dereference(ifp->if_softc);

	bridge_for_each_brport(port, entry, sc)
		for (int i = 1; i < VLAN_N_VID; i++)
			if (bridge_port_lookup_vlan(port, i) ||
			    bridge_port_lookup_untag_vlan(port, i))
				bridge_vlan_set_add(active_vlans, i);
}

static void switch_vlan_emit_stats(json_writer_t *wr, uint16_t vlan,
				   struct bridge_vlan_stats *stats)
{
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "vlan", vlan);
	jsonw_uint_field(wr, "rx_bytes", stats->rx_octets);
	jsonw_uint_field(wr, "rx_pkts", stats->rx_pkts);
	jsonw_uint_field(wr, "rx_ucast_pkts", stats->rx_ucast_pkts);
	jsonw_uint_field(wr, "rx_nucast_pkts", stats->rx_nucast_pkts);
	jsonw_uint_field(wr, "rx_drops", stats->rx_drops);
	jsonw_uint_field(wr, "rx_errors", stats->rx_errors);
	jsonw_uint_field(wr, "tx_bytes", stats->tx_octets);
	jsonw_uint_field(wr, "tx_pkts", stats->tx_pkts);
	jsonw_uint_field(wr, "tx_ucast_pkts", stats->tx_ucast_pkts);
	jsonw_uint_field(wr, "tx_nucast_pkts", stats->tx_nucast_pkts);
	jsonw_uint_field(wr, "tx_drops", stats->tx_drops);
	jsonw_uint_field(wr, "tx_errors", stats->tx_errors);
	jsonw_end_object(wr);
}

static int switch_vlan_get_stats(struct ifnet *ifp, uint16_t vlan,
				 struct bridge_vlan_stats *stats)
{
	int rc;
	uint64_t cntrs[FAL_VLAN_STAT_MAX];
	enum fal_vlan_stat_type cntr_ids[FAL_VLAN_STAT_MAX];
	struct bridge_vlan_stats *software_stats;
	struct bridge_softc *sc = ifp->if_softc;
	unsigned int lcore;
	struct bridge_vlan_stat_block *stats_ptr;

	/* TODO: only perform action for switches with h/w binding */
	for (int i = FAL_VLAN_STAT_IN_OCTETS; i < FAL_VLAN_STAT_MAX; i++)
		cntr_ids[i] = i;

	memset(cntrs, 0, sizeof(cntrs));
	rc = fal_vlan_get_stats(vlan, FAL_VLAN_STAT_MAX,
				cntr_ids, cntrs);
	if (rc)
		return rc;

	stats->rx_octets = cntrs[FAL_VLAN_STAT_IN_OCTETS];
	stats->rx_pkts = cntrs[FAL_VLAN_STAT_IN_PACKETS];
	stats->rx_ucast_pkts = cntrs[FAL_VLAN_STAT_IN_UCAST_PKTS];
	stats->rx_nucast_pkts = cntrs[FAL_VLAN_STAT_IN_NON_UCAST_PKTS];
	stats->rx_drops = cntrs[FAL_VLAN_STAT_IN_DISCARDS];
	stats->rx_errors = cntrs[FAL_VLAN_STAT_IN_ERRORS];

	stats->tx_octets = cntrs[FAL_VLAN_STAT_OUT_OCTETS];
	stats->tx_pkts = cntrs[FAL_VLAN_STAT_OUT_PACKETS];
	stats->tx_ucast_pkts = cntrs[FAL_VLAN_STAT_OUT_UCAST_PKTS];
	stats->tx_nucast_pkts = cntrs[FAL_VLAN_STAT_OUT_NON_UCAST_PKTS];
	stats->tx_drops = cntrs[FAL_VLAN_STAT_OUT_DISCARDS];
	stats->tx_errors = cntrs[FAL_VLAN_STAT_OUT_ERRORS];

	/* Add the software stats */
	FOREACH_DP_LCORE(lcore) {
		stats_ptr = rcu_dereference(sc->vlan_stats[vlan]);
		if (!stats_ptr)
			continue;
		software_stats = &stats_ptr->stats[lcore];
		stats->rx_octets += software_stats->rx_octets;
		stats->rx_pkts += software_stats->rx_pkts;
		stats->rx_ucast_pkts += software_stats->rx_ucast_pkts;
		stats->rx_nucast_pkts += software_stats->rx_nucast_pkts;
		stats->rx_drops += software_stats->rx_drops;
		stats->rx_errors += software_stats->rx_errors;

		stats->tx_octets += software_stats->tx_octets;
		stats->tx_pkts += software_stats->tx_pkts;
		stats->tx_ucast_pkts += software_stats->tx_ucast_pkts;
		stats->tx_nucast_pkts += software_stats->tx_nucast_pkts;
		stats->tx_drops += software_stats->tx_drops;
		stats->tx_errors += software_stats->tx_errors;
	}

	return rc;
}

static void switch_vlan_show_stats(struct ifnet *ifp, uint16_t vlan,
				   FILE *f)
{
	int rc;
	struct bridge_vlan_set *vlans;
	struct bridge_vlan_stats stats = { 0 };
	json_writer_t *wr;

	wr = jsonw_new(f);
	jsonw_pretty(wr, true);
	jsonw_name(wr, "vlan_stats");
	jsonw_start_array(wr);

	if (vlan) {
		rc = switch_vlan_get_stats(ifp, vlan, &stats);
		if (!rc)
			switch_vlan_emit_stats(wr, vlan, &stats);
	} else {
		vlans = bridge_vlan_set_create();
		if (!vlans) {
			fprintf(f, "Could not allocate vlan set");
			jsonw_destroy(&wr);
			return;
		}
		switch_get_vlans(ifp, vlans);
		for (int i = 1; i < VLAN_N_VID; i++) {
			if (bridge_vlan_set_is_member(vlans, i)) {
				rc = switch_vlan_get_stats(ifp, i, &stats);
				if (!rc)
					switch_vlan_emit_stats(wr, i, &stats);
			}
		}
		bridge_vlan_set_free(vlans);
	}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

static void switch_vlan_clear_stats(struct ifnet *ifp, uint16_t vlan,
				    FILE *f)
{
	int rc;
	enum fal_vlan_stat_type cntr_ids[FAL_VLAN_STAT_MAX];
	struct bridge_vlan_set *vlans;
	struct bridge_softc *sc = ifp->if_softc;

	/* TODO: only perform action for switches with h/w binding */
	for (int i = FAL_VLAN_STAT_IN_OCTETS; i < FAL_VLAN_STAT_MAX; i++)
		cntr_ids[i] = i;

	if (vlan) {
		rc = bridge_vlan_clear_software_stat(sc, vlan);
		if (rc)
			fprintf(f, "Could not clear software stats for vlan %d",
				vlan);
		rc = fal_vlan_clear_stats(vlan, FAL_VLAN_STAT_MAX, cntr_ids);
		if (rc)
			fprintf(f, "Could not clear stats for vlan %d", vlan);
	} else {
		vlans = bridge_vlan_set_create();
		if (!vlans) {
			fprintf(f, "Could not allocate vlan set");
			return;
		}
		switch_get_vlans(ifp, vlans);
		for (int i = 1; i < VLAN_N_VID; i++)
			if (bridge_vlan_set_is_member(vlans, i)) {
				rc = bridge_vlan_clear_software_stat(sc, i);
				if (rc)
					fprintf(f,
						"Could not clear software stats for vlan %d",
						i);

				rc = fal_vlan_clear_stats(i,
							  FAL_VLAN_STAT_MAX,
							  cntr_ids);
				if (!rc)
					continue;

				fprintf(f,
					"Could not clear stats for vlan %d", i);
			}
		bridge_vlan_set_free(vlans);
	}
}

static int cmd_switch_vlan(struct ifnet *ifp, FILE *f, int argc, char **argv)
{
	uint16_t vlan = 0;

	if (strcmp(argv[4], "stats"))
		goto error;

	if (argc == 6)
		vlan = atoi(argv[5]);

	if (!strcmp(argv[3], "show"))
		switch_vlan_show_stats(ifp, vlan, f);
	else if (!strcmp(argv[3], "clear"))
		switch_vlan_clear_stats(ifp, vlan, f);
	else
		goto error;

	return 0;
error:
	fprintf(f, "Usage: switch <name> vlan <show|clear> stats [<vlan>]");
	return -1;
}

int cmd_switch_op(FILE *f, int argc, char **argv)
{
	struct ifnet *ifp;

	if (argc < 5)
		goto error;

	ifp = ifnet_byifname(argv[1]);
	if (!ifp) {
		fprintf(f, "Could not find interface %s", argv[1]);
		return -1;
	}

	if (ifp->if_type != IFT_BRIDGE ||
	    (strstr(ifp->if_name, "sw") != ifp->if_name)) {
		fprintf(f, "%s is not a switch interface", ifp->if_name);
		return -1;
	}

	if (!strcmp(argv[2], "vlan"))
		cmd_switch_vlan(ifp, f, argc, argv);

	return 0;
error:
	fprintf(f, "Usage: switch <name> vlan <cmd> <params>");
	return -1;
}
