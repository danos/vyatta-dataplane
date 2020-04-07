/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * backplane command handling
 */

#include <stdio.h>
#include <string.h>
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_bus_pci.h>
#include <rte_pci.h>
#include "backplane.h"
#include "control.h"
#include "dp_event.h"
#include "fal.h"
#include "if/bridge/bridge.h"
#include "if_var.h"
#include "json_writer.h"
#include "vplane_log.h"

static struct cfg_if_list *bp_cfg_list;

#define MAX_BP_INTFS 4

struct bp_interface {
	unsigned int        ifindex;
	struct rte_pci_addr pci_addr;
	char                *name;
};

static unsigned int num_bp_intfs;
static struct bp_interface bp_intfs[MAX_BP_INTFS];

static void backplane_replay_destroy(void);

static int backplane_port_get_index_and_name(uint16_t dpdk_port, int *index,
					     char **name_p)
{
	struct rte_eth_dev_info dev;
	unsigned int i;

	rte_eth_dev_info_get(dpdk_port, &dev);
	const struct rte_bus *bus = rte_bus_find_by_device(dev.device);
	struct rte_pci_device *pci = NULL;

	if (bus && streq(bus->name, "pci"))
		pci = RTE_DEV_TO_PCI(dev.device);
	if (!pci)
		return -ENOENT;

	const struct rte_pci_addr *loc;

	loc = &pci->addr;
	for (i = 0; i < num_bp_intfs; i++) {
		if (loc->domain == bp_intfs[i].pci_addr.domain &&
		    loc->bus == bp_intfs[i].pci_addr.bus &&
		    loc->devid == bp_intfs[i].pci_addr.devid &&
		    loc->function == bp_intfs[i].pci_addr.function) {
			*index = i;
			if (bp_intfs[i].name && name_p)
				*name_p = bp_intfs[i].name;
			else if (name_p)
				*name_p = NULL;
			return 0;
		}
	}
	return -ENOENT;
}

int backplane_port_get_index(uint16_t dpdk_port, int *index)
{
	return backplane_port_get_index_and_name(dpdk_port, index, NULL);
}

int backplane_port_get_name(uint16_t dpdk_port, char **name)
{
	int index;
	int rc;

	rc = backplane_port_get_index_and_name(dpdk_port, &index, name);
	if (rc == 0 && *name)
		return 0;

	return -ENOENT;
}

static int backplane_cache_ifindex(struct ifnet *ifp)
{
	int rv, index;

	rv = backplane_port_get_index(ifp->if_port, &index);
	if (rv)
		return rv;

	bp_intfs[index].ifindex = ifp->if_index;
	return rv;
}

static void
backplane_event_if_index_set(struct ifnet *ifp)
{
	struct cfg_if_list_entry *le, *tmp_le;

	if (!if_is_hwport(ifp))
		return;

	if (!backplane_cache_ifindex(ifp)) {
		if (!bp_cfg_list)
			return;
		cds_list_for_each_entry_safe(le, tmp_le, &bp_cfg_list->if_list,
					     le_node) {
			ifp = dp_ifnet_byifname(le->le_ifname);
			if (!ifp)
				continue;
			RTE_LOG(INFO, BACKPLANE,
				"Replaying backplane command %s for interface %s\n",
				le->le_buf, ifp->if_name);

			cmd_backplane_cfg(NULL, le->le_argc, le->le_argv);
			cfg_if_list_del(bp_cfg_list, ifp->if_name);
		}
		backplane_replay_destroy();
		return;
	}

	if (!bp_cfg_list)
		return;
	le = cfg_if_list_lookup(bp_cfg_list, ifp->if_name);
	if (!le)
		return;

	RTE_LOG(INFO, BACKPLANE,
		"Replaying backplane command %s for interface %s\n",
		le->le_buf, ifp->if_name);

	cmd_backplane_cfg(NULL, le->le_argc, le->le_argv);
	cfg_if_list_del(bp_cfg_list, ifp->if_name);
	backplane_replay_destroy();
}

static void
backplane_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex __unused)
{
	if (!bp_cfg_list)
		return;

	cfg_if_list_del(bp_cfg_list, ifp->if_name);
	backplane_replay_destroy();
}

static const struct dp_event_ops backplane_event_ops = {
	.if_index_set = backplane_event_if_index_set,
	.if_index_unset = backplane_event_if_index_unset,
};

static int backplane_replay_init(void)
{
	if (!bp_cfg_list) {
		bp_cfg_list = cfg_if_list_create();
		if (!bp_cfg_list)
			return -ENOMEM;
		dp_event_register(&backplane_event_ops);
	}
	return 0;
}

static void backplane_replay_destroy(void)
{
	if (!bp_cfg_list)
		return;

	if (!bp_cfg_list->if_list_count) {
		cfg_if_list_destroy(&bp_cfg_list);
	}
}

int cmd_backplane_cfg(FILE *f, int argc, char **argv)
{
	struct ifnet *ifp, *bp_ifp;
	int rv;

	if (argc != 4) {
		fprintf(f, "\nInvalid command : ");
		for (int i = 0; i < argc; i++)
			fprintf(f, "%s ", argv[i]);
		goto error;
	}

	if (strcmp(argv[1], "SET"))
		goto error;

	ifp = dp_ifnet_byifname(argv[2]);
	bp_ifp = dp_ifnet_byifname(argv[3]);
	if (!ifp || !bp_ifp) {
		if (!bp_cfg_list && backplane_replay_init()) {
			RTE_LOG(ERR, BACKPLANE,
				"Could not set up command replay cache\n");
			return -ENOMEM;
		}

		RTE_LOG(INFO, BACKPLANE,
			"Caching backplane command for interface %s\n",
			argv[2]);
		cfg_if_list_add(bp_cfg_list, argv[2], argc, argv);
		return 0;
	}

	rv = backplane_cache_ifindex(bp_ifp);
	if (rv)
		return rv;

	rv = if_set_backplane(ifp, bp_ifp->if_index);
	if (rv) {
		RTE_LOG(ERR, BACKPLANE,
			"Could not set backplane interface for %s : %s\n",
			ifp->if_name, strerror(-rv));
		return rv;
	}

	rv = fal_backplane_bind(bp_ifp->if_index, ifp->if_index);
	if (rv) {
		RTE_LOG(ERR, BACKPLANE,
			"Could not bind %s to backplane %s : %s\n",
			ifp->if_name, bp_ifp->if_name, strerror(rv));
		return rv;
	}

	RTE_LOG(INFO, DATAPLANE, "Interface %s bound to backplane %s\n",
		ifp->if_name, bp_ifp->if_name);

	return 0;
error:
	fprintf(f, "Usage: backplane SET <ifname> <bp-ifname>\n");
	return -EINVAL;
}

static void backplane_show(json_writer_t *wr, unsigned int i)
{
	struct ifnet *ifp;
	struct dp_ifnet_link_status link;

	jsonw_start_object(wr);
	jsonw_name(wr, "pci_address");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "domain", bp_intfs[i].pci_addr.domain);
	jsonw_uint_field(wr, "bus", bp_intfs[i].pci_addr.bus);
	jsonw_uint_field(wr, "devid", bp_intfs[i].pci_addr.devid);
	jsonw_uint_field(wr, "function", bp_intfs[i].pci_addr.function);
	jsonw_end_object(wr);
	jsonw_uint_field(wr, "ifindex", bp_intfs[i].ifindex);
	ifp = dp_ifnet_byifindex(bp_intfs[i].ifindex);
	if (ifp) {
		dp_ifnet_link_status(ifp, &link);

		jsonw_string_field(wr, "name", ifp->if_name);
		jsonw_string_field(wr, "link_state",
				   link.link_status ? "up" : "down");
		fal_backplane_dump(bp_intfs[i].ifindex, wr);
	}
	jsonw_end_object(wr);
}

int cmd_backplane_op(FILE *f, int argc, char **argv)
{
	int rv = 0;
	json_writer_t *wr;
	struct ifnet *ifp;
	unsigned int i;

	if (argc < 2) {
		rv = -EINVAL;
		goto usage;
	}

	if (strcmp(argv[1], "show")) {
		rv = -EINVAL;
		goto usage;
	}

	if (argc == 3) {
		ifp = dp_ifnet_byifname(argv[2]);
		if (!ifp) {
			fprintf(f, "Could not find backplane interface %s\n",
				argv[2]);
			return -ENOENT;
		}
	}

	wr = jsonw_new(f);
	if (!wr) {
		fprintf(f, "Could not create json writer\n");
		rv = -ENOMEM;
		goto error;
	}

	jsonw_pretty(wr, true);
	jsonw_name(wr, "backplane_info");
	if (argc == 3) {
		for (i = 0; i < num_bp_intfs; i++)
			if (bp_intfs[i].ifindex == ifp->if_index)
				backplane_show(wr, i);
	} else {
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "num_bp_intfs", num_bp_intfs);
		jsonw_name(wr, "bp_intfs");
		jsonw_start_array(wr);
		for (unsigned int i = 0; i < num_bp_intfs; i++)
			backplane_show(wr, i);
		jsonw_end_array(wr);
		jsonw_end_object(wr);
	}
	jsonw_destroy(&wr);

	return 0;

usage:
	fprintf(f, "Usage: backplane show [ <bp intf name> ]");
error:
	return rv;
}

int backplane_init(struct pci_list *bp_list)
{
	const struct bkplane_pci *bp;
	int i = 0;

	if (!bp_list)
		return 0;

	LIST_FOREACH(bp, bp_list, link) {
		if (i >= MAX_BP_INTFS) {
			RTE_LOG(ERR, BACKPLANE,
				"Too many backplane interfaces %d\n", i);
			return -ENOSPC;
		}
		memcpy(&bp_intfs[i].pci_addr, &bp->pci_addr,
		       sizeof(bp->pci_addr));
		bp_intfs[i].name = bp->name;
		i++;
	}
	num_bp_intfs = i;

	if (num_bp_intfs)
		dp_event_register(&backplane_event_ops);
	return 0;
}
