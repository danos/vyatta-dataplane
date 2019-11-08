/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef L2_RX_FLTR_H
#define L2_RX_FLTR_H

#include <rte_ether.h>
#include <stddef.h>
#include <stdint.h>

#include "ether.h"
#include "if_var.h"
#include "urcu.h"
#include "util.h"

/*
 * Multicast filter node.
 */
struct l2_mcfltr_node {
	struct rcu_head       l2mf_rcu;	  /* for deletion via rcu */
	struct cds_lfht_node  l2mf_node;  /* hash table node  */
	struct ifnet	      *l2mf_if;	  /* associated if */
	struct ether_addr     l2mf_addr;  /* multicast mac address */
	int16_t               l2mf_ref;   /* ref count (overloaded 24 bits) */
};

/* Given key (ether address) generate a hash using jhash */
#define	L2_MCFLTRHASH_BITS	13

static inline unsigned long
l2_mcfltr_node_hash(const struct ether_addr *key)
{
	return eth_addr_hash(key, L2_MCFLTRHASH_BITS);
}

/* Test if ether address matches value for this entry */
static inline int
l2_mcfltr_node_match(struct cds_lfht_node *node, const void *key)
{
	const struct l2_mcfltr_node *bmf
		= caa_container_of(node, const struct l2_mcfltr_node,
				   l2mf_node);

	return ether_addr_equal(&bmf->l2mf_addr, key);
}

/*
 * Lookup route node in hash table
 *
 *	Look up a mcast filter node for the specified destination.
 */
static inline struct l2_mcfltr_node *
l2_mcfltr_node_lookup(const struct ifnet *ifp, const struct ether_addr *addr)
{
	struct cds_lfht_iter iter;

	cds_lfht_lookup(ifp->if_mcfltr_hash,
			l2_mcfltr_node_hash(addr),
			l2_mcfltr_node_match, addr, &iter);

	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);

	if (node)
		return caa_container_of(node, struct l2_mcfltr_node, l2mf_node);
	else
		return NULL;
}

int l2_rx_fltr_init(struct ifnet *ifp);

void l2_rx_fltr_cleanup(struct ifnet *ifp);
void l2_rx_fltr_delete_rcu(struct ifnet *ifp);

void l2_rx_fltr_add_addr(struct ifnet *ifp, const struct ether_addr *dst);

void l2_rx_fltr_del_addr(struct ifnet *ifp, const struct ether_addr *dst);

void l2_rx_fltr_state_change(struct ifnet *ifp);

void l2_rx_fltr_set_reprogram(struct ifnet *ifp);

#endif /* L2_RX_FLTR_H */
