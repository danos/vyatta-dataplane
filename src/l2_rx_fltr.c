/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * L2 Receive filter in dataplane (software based)
 */

#include <assert.h>
#include <errno.h>
#include <rte_branch_prediction.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <stdlib.h>
#include <string.h>

#include "fal.h"
#include "if_var.h"
#include "l2_rx_fltr.h"
#include "lag.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

/* Size of the l2 mcast filter table. Must be a power of two. */
#define	L2_MCFLTRHASH_MIN	32
#define	L2_MCFLTRHASH_MAX	(1<<L2_MCFLTRHASH_BITS)

/*
 * Insert the specified mcast filter node into the mcast filter table.
 */
static int
l2_mcfltr_node_insert(struct ifnet *ifp, struct l2_mcfltr_node *bmf)
{
	struct cds_lfht_node *ret_node;

	cds_lfht_node_init(&bmf->l2mf_node);

	ret_node = cds_lfht_add_unique(ifp->if_mcfltr_hash,
				       l2_mcfltr_node_hash(&bmf->l2mf_addr),
				       l2_mcfltr_node_match, &bmf->l2mf_addr,
				       &bmf->l2mf_node);
	if (ret_node != &bmf->l2mf_node)
		return -EEXIST;

	l2_rx_fltr_set_reprogram(ifp);
	return 0;
}

/*
 * Set or clear the HW filter.
 */
static void
l2_mcfltr_set_hw(struct ifnet *ifp)
{
	struct cds_lfht_iter iter;
	struct l2_mcfltr_node *l2mf;
	struct ether_addr l2mf_addr[L2_MCFLTRHASH_MAX];
	int count = 0;
	int ret;

	if (ifp->if_type != IFT_ETHER) {
		DP_DEBUG(MULTICAST, INFO, MCAST,
			 "HW MAC address filtering ignored on non-DPDK interface %s.\n",
			 ifp->if_name);
		return;
	}

	if (!ifp->if_mac_filtr_supported) {
		DP_DEBUG(MULTICAST, INFO, MCAST,
			 "HW MAC address filtering unsupported on dev %s.\n",
			 ifp->if_name);
		return;
	}

	if (ifp->if_mac_filtr_active) {
		/*
		 * Note that the HW filter is cleared (count = 0) if
		 * the filter is not active
		 */
		cds_lfht_for_each_entry(ifp->if_mcfltr_hash, &iter, l2mf,
					l2mf_node) {
			l2mf_addr[count++] = l2mf->l2mf_addr;
		}
	}

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Sending %d MAC addresses to dev %s for HW filtering.\n",
		 count, ifp->if_name);
	ret = rte_eth_dev_set_mc_addr_list(ifp->if_port, l2mf_addr, count);

	/* In error case, enable multicast promiscuous mode as a fallback*/
	if (ret < 0) {
		DP_DEBUG(MULTICAST, INFO, MCAST,
			 "Failure (%s) to enable HW filtering on dev %s.\n",
			 strerror(-ret), ifp->if_name);

		rte_eth_allmulticast_enable(ifp->if_port);
		ifp->if_mac_filtr_supported = 0;
	}
}

/*
 * Add/update an mcast filter table entry
 */
static void
l2_mcfltr_add_entry(struct ifnet *ifp, const struct ether_addr *dst)
{
	struct l2_mcfltr_node *bmf;

	bmf = l2_mcfltr_node_lookup(ifp, dst);
	if (unlikely(bmf == NULL)) {
		bmf = zmalloc_aligned(sizeof(*bmf));
		if (unlikely(bmf == NULL)) {
			RTE_LOG(ERR, DATAPLANE,
				"%s: new entry but mcast Rx filter malloc error)\n",
				ifp->if_name);
			return;
		}

		bmf->l2mf_if = ifp;
		bmf->l2mf_addr = *dst;
		bmf->l2mf_ref = 1;

		int error = l2_mcfltr_node_insert(ifp, bmf);

		if (unlikely(error != 0)) {
			DP_DEBUG(MULTICAST, INFO, MCAST,
				 "Failure to insert %s into filter table for %s.\n",
				 ether_ntoa(dst), ifp->if_name);
			free(bmf);
			return;
		}

		DP_DEBUG(MULTICAST, INFO, MCAST,
				 "Inserted %s into filter table for %s.\n",
				 ether_ntoa(dst), ifp->if_name);
		l2_rx_fltr_state_change(ifp);
		fal_l2_new_addr(ifp->if_index, dst, 0, NULL);
	} else {
		/*
		 * A filter entry for this address already exists so update it.
		 */
		if (unlikely(bmf->l2mf_if != ifp))
			/* Would this ever happen */
			bmf->l2mf_if = ifp;

		bmf->l2mf_ref += 1;
		fal_l2_upd_addr(ifp->if_index, dst, NULL);

		DP_DEBUG(MULTICAST, INFO, MCAST,
			 "Ref count for %s in filter table for %s now %d.\n",
			 ether_ntoa(dst), ifp->if_name, bmf->l2mf_ref);
	}
}

static void
l2_mcfltr_node_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct l2_mcfltr_node, l2mf_rcu));
}

/*
 *	Destroy a mcast filter node.
 */
static void
l2_mcfltr_node_destroy(struct l2_mcfltr_node *bmf)
{
	call_rcu(&bmf->l2mf_rcu, l2_mcfltr_node_free);
}

/*
 * Create lock free hash table.
 */
int
l2_rx_fltr_init(struct ifnet *ifp)
{
	ifp->if_mcfltr_hash = cds_lfht_new(L2_MCFLTRHASH_MIN,
					   L2_MCFLTRHASH_MIN,
					   L2_MCFLTRHASH_MAX,
					   CDS_LFHT_AUTO_RESIZE,
					   NULL);
	if (ifp->if_mcfltr_hash == NULL)
		return -ENOMEM;

	return 0;
}

static void
l2_mcfltr_del_entry(struct ifnet *ifp, const struct ether_addr *dst)
{
	struct l2_mcfltr_node *bmf = l2_mcfltr_node_lookup(ifp, dst);

	if (bmf) {
		bmf->l2mf_ref -= 1;
		assert(bmf->l2mf_ref >= 0);

		if (!bmf->l2mf_ref) {
			fal_l2_del_addr(ifp->if_index, dst);
			cds_lfht_del(ifp->if_mcfltr_hash, &bmf->l2mf_node);
			l2_mcfltr_node_destroy(bmf);
			DP_DEBUG(MULTICAST, INFO, MCAST,
				 "Deleted %s from filter table for %s.\n",
				 ether_ntoa(dst), ifp->if_name);
			l2_rx_fltr_set_reprogram(ifp);
			l2_rx_fltr_state_change(ifp);
		} else {
			DP_DEBUG(MULTICAST, INFO, MCAST,
				 "Ref count for %s in filter table for %s now %d.\n",
				 ether_ntoa(dst), ifp->if_name, bmf->l2mf_ref);
		}
	} else {
		DP_DEBUG(MULTICAST, INFO, MCAST,
			 "No entry exists when deleting %s from filter table for %s.\n",
			 ether_ntoa(dst), ifp->if_name);
	}
}

void
l2_rx_fltr_cleanup(struct ifnet *ifp)
{
	ifp->if_mac_filtr_active = 0;
}

void l2_rx_fltr_delete_rcu(struct ifnet *ifp)
{
	struct cds_lfht_iter iter;
	struct l2_mcfltr_node *bmf;

	/* Clear all entries. */
	cds_lfht_for_each_entry(ifp->if_mcfltr_hash, &iter, bmf, l2mf_node) {
		cds_lfht_del(ifp->if_mcfltr_hash, &bmf->l2mf_node);
		l2_mcfltr_node_destroy(bmf);
	}
	dp_ht_destroy_deferred(ifp->if_mcfltr_hash);
	DP_DEBUG(MULTICAST, INFO, MCAST, "Filter table for %s destroyed.\n",
		 ifp->if_name);
}

/*
 * Sets a flag so as to force the multicast filter to be reprogrammed in the HW
 * on the next call to check the L2 state change, regardless of whether the
 * multicast filter is already active.
 */
void l2_rx_fltr_set_reprogram(struct ifnet *ifp)
{
	ifp->if_mac_filtr_reprogram = 1;
}

/*
 * Process a change in interface mac filter state .
 */
void l2_rx_fltr_state_change(struct ifnet *ifp)
{
	int orig_active = ifp->if_mac_filtr_active;
	const char *orig_state = orig_active != 0 ? "active" : "disabled";

	if (!ifp->if_allmcast_ref && !ifp->if_pcount)
		/* Multicast routing disabled & not promiscuous mode */
		ifp->if_mac_filtr_active = 1;
	else
		ifp->if_mac_filtr_active = 0;

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Potential MAC filter state change for %s. Promiscuous ref count: %d, allmulti ref count: %d.\n",
		 ifp->if_name, ifp->if_pcount, ifp->if_allmcast_ref);

	if (orig_active == ifp->if_mac_filtr_active &&
	    !ifp->if_mac_filtr_reprogram)
		return;

	if (ifp->if_allmcast_ref) {
		DP_DEBUG(MULTICAST, INFO, MCAST,
			 "Enabling multicast promiscuous mode for %s.\n",
			 ifp->if_name);
		if (ifp->if_type == IFT_ETHER)
			rte_eth_allmulticast_enable(ifp->if_port);
	} else if (ifp->if_mac_filtr_supported) {
		/* Disable only when HW mac filtering supported */
		DP_DEBUG(MULTICAST, INFO, MCAST,
			 "Disabling multicast promiscuous mode for %s.\n",
			 ifp->if_name);
		if (ifp->if_type == IFT_ETHER)
			rte_eth_allmulticast_disable(ifp->if_port);
	}

	const char *current_state = ifp->if_mac_filtr_active != 0
		? "active" : "disabled";

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "MAC filter state  for %s: %s -> %s\n",
		 ifp->if_name, orig_state, current_state);

	if (ifp->if_mac_filtr_active)
		/* Forget any previous HW errors */
		ifp->if_mac_filtr_supported = 1;

	ifp->if_mac_filtr_reprogram = 0;

	l2_mcfltr_set_hw(ifp);
}

/*
 * Add/update an mcast filter table entry to a bonded slave physical interface
 */
static void
l2_mcfltr_add_bonded_entry(struct ifnet *ifp, void *grp)
{
	const struct ether_addr *dst = grp;

	l2_mcfltr_add_entry(ifp, dst);
}

/*
 * Delete a mcast filter table entry from a bonded slave physical interface
 */
static void
l2_mcfltr_del_bonded_entry(struct ifnet *ifp, void *grp)
{
	const struct ether_addr *dst = grp;

	l2_mcfltr_del_entry(ifp, dst);
}

/*
 * Process a netlink add address message
 */
void l2_rx_fltr_add_addr(struct ifnet *ifp, const struct ether_addr *dst)
{
	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Processing RTM_NEWADDR for %s; MAC address: %s.\n",
		 ifp->if_name, ether_ntoa(dst));

	/*
	 * If unplugged the interface will shortly be removed, so
	 * don't even update the software state.
	 */
	if (ifp->unplugged)
		return;

	if (is_multicast_ether_addr(dst)) {
		l2_mcfltr_add_entry(ifp, dst);
		/* If adding to a vlan also add to parent (real IF) */
		if (ifp->if_parent)
			l2_mcfltr_add_entry(ifp->if_parent, dst);

		/* If adding to a bonded IF add to slaves (physical IF) */
		if (ifp->if_team) {
			int err;
			struct ether_addr *grp = (struct ether_addr *)dst;
			err = lag_walk_bond_slaves
				(ifp, l2_mcfltr_add_bonded_entry, grp);
			if (err < 0)
				DP_DEBUG(MULTICAST, INFO, MCAST,
					 "Failure to insert %s into slave "
					 "filter tables for %s.\n",
					 ether_ntoa(dst), ifp->if_name);
		}
	} else
		RTE_LOG(DEBUG, DATAPLANE,
			"%s: Add %s to mcast Rx filter but not mcast\n",
			ifp->if_name, ether_ntoa(dst));
}

/*
 * Process a delete address netlink message
 */
void l2_rx_fltr_del_addr(struct ifnet *ifp, const struct ether_addr *dst)
{
	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Processing RTM_DELADDR for %s; MAC address: %s.\n",
		 ifp->if_name, ether_ntoa(dst));

	/*
	 * If unplugged the interface will shortly be removed, so
	 * don't even update the software state.
	 */
	if (ifp->unplugged)
		return;

	if (is_multicast_ether_addr(dst)) {
		/* If deleting from a bonded IF delete from slaves (phys IF) */
		if (ifp->if_team) {
			int err;
			struct ether_addr *grp = (struct ether_addr *)dst;
			err = lag_walk_bond_slaves
				(ifp, l2_mcfltr_del_bonded_entry, grp);
			if (err < 0)
				DP_DEBUG(MULTICAST, INFO, MCAST,
					 "Failure to remove %s from slave "
					 "filter tables for %s.\n",
					 ether_ntoa(dst), ifp->if_name);
		}

		l2_mcfltr_del_entry(ifp, dst);

		/* If deleting from a vlan also del from parent (real IF) */
		if (ifp->if_parent)
			l2_mcfltr_del_entry(ifp->if_parent, dst);
	} else {
		RTE_LOG(DEBUG, DATAPLANE,
			"%s: delete %s from mcast Rx filter but not mcast\n",
			ifp->if_name, ether_ntoa(dst));
	}
}
