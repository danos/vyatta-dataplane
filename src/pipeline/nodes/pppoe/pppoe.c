/*
 * Copyright (c) 2018, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <limits.h>
#include <linux/if_ether.h>
#include <inttypes.h>
#include <rte_jhash.h>

#include "dp_event.h"
#include "ether.h"
#include "if_llatbl.h"
#include "pppoe.h"
#include "vplane_log.h"

static bool pppoe_track_underlying;
CDS_LIST_HEAD(pppoe_conn_list);

static void
ppp_tunnel_delete(struct ifnet *ifp);

struct cds_list_head *pppoe_get_conn_list(void)
{
	return &pppoe_conn_list;
}

static struct cds_lfht *
pppoe_map_get_ht(void)
{
	struct pppoe_map_tbl *tbl;

	tbl = rcu_dereference(pppoe_map_tbl);

	if (tbl)
		return rcu_dereference(tbl->ht);

	return NULL;
}

static void
pppoe_softc_free_rcu(struct rcu_head *head)
{
	struct pppoe_connection *conn;

	conn = caa_container_of(head, struct pppoe_connection, scpppoe_rcu);
	free(conn);
}

/* The underlying interface is going away, so mark this as invalid */
static void pppoe_validate_conn(struct ifnet *ifp, struct ifnet *new_ifp)
{
	struct pppoe_connection *old_conn;
	struct pppoe_connection *new_conn;

	old_conn = ifp->if_softc;

	new_conn = zmalloc_aligned(sizeof(struct pppoe_connection));
	if (!new_conn) {
		RTE_LOG(ERR, PPPOE,
			"Can not modify pppoe underlying interface.");
		ppp_tunnel_delete(ifp);
		return;
	}

	*new_conn = *old_conn;
	new_conn->underlying_interface = new_ifp;
	new_conn->underlying_ifindex = new_ifp->if_index;
	new_conn->valid = 1;

	rcu_assign_pointer(ifp->if_softc, new_conn);
	cds_list_replace_rcu(&old_conn->list_node, &new_conn->list_node);
	call_rcu(&old_conn->scpppoe_rcu, pppoe_softc_free_rcu);
	pppoe_init_session(ifp, new_conn->session);
}

/*
 * The underlying interface is going away, so mark this connection
 * as invalid, and get rid of the associated session.
 */
static void pppoe_invalidate_conn(struct ifnet *ifp, uint32_t old_ifindex)
{
	struct pppoe_connection *old_conn;
	struct pppoe_connection *new_conn;

	old_conn = ifp->if_softc;
	ppp_remove_ses(old_ifindex, old_conn->session);
	new_conn = zmalloc_aligned(sizeof(struct pppoe_connection));
	if (!new_conn) {
		RTE_LOG(ERR, PPPOE,
			"Can not modify pppoe underlying interface.");
		ppp_tunnel_delete(ifp);
		return;
	}

	*new_conn = *old_conn;
	new_conn->underlying_interface = NULL;
	new_conn->underlying_ifindex = 0;
	new_conn->valid = 0;

	rcu_assign_pointer(ifp->if_softc, new_conn);
	cds_list_replace_rcu(&old_conn->list_node, &new_conn->list_node);
	call_rcu(&old_conn->scpppoe_rcu, pppoe_softc_free_rcu);
}

/*
 * Walk through all the pppoe sessions and find any that are not valid,
 * and have this interface as the one they need.
 */
static void
pppoe_track_if_index_set(struct ifnet *new_ifp, uint32_t ifindex __unused)
{
	struct pppoe_connection *conn;

	cds_list_for_each_entry_rcu(conn, pppoe_get_conn_list(), list_node) {
		if (!conn->valid) {
			if (strcmp(conn->underlying_name,
				   new_ifp->if_name) == 0) {
				/* Underlying interface is arriving */
				pppoe_validate_conn(conn->ifp, new_ifp);
			}
		}
	}
}

/*
 * Walk through all the pppoe connections and mark any that use this
 * interface as not valid.
 */
static void
pppoe_track_if_index_unset(struct ifnet *going_ifp, uint32_t ifindex)
{
	struct cds_lfht *pppoe_tbl = pppoe_map_get_ht();
	struct cds_lfht_iter iter;
	struct pppoe_map_node *pnode = NULL;
	struct ifnet *ifp;
	struct pppoe_connection *conn;

	if (pppoe_tbl)
		cds_lfht_for_each_entry(pppoe_tbl, &iter, pnode, pnode) {
			if (!pnode->ppp)
				continue;

			ifp = pnode->ppp;
			conn = ifp->if_softc;

			if (conn && conn->underlying_interface == going_ifp) {
				/* Underlying interface is going away */
				pppoe_invalidate_conn(ifp, ifindex);
			}
		}
}

static const struct dp_event_ops pppoe_tracking_event_ops = {
	.if_index_set = pppoe_track_if_index_set,
	.if_index_unset = pppoe_track_if_index_unset,
};

void pppoe_track_underlying_interfaces(void)
{
	if (!pppoe_track_underlying) {
		pppoe_track_underlying = true;
		dp_event_register(&pppoe_tracking_event_ops);
	}
}

static void pppoe_no_track_underlying_interfaces(void)
{
	if (pppoe_track_underlying) {
		pppoe_track_underlying = false;
		dp_event_unregister(&pppoe_tracking_event_ops);
	}
}

static int
pppoe_classify_map_hash(const struct pppoe_session_key *key)
{
	return rte_jhash_2words(key->session, key->underlying_ifindex, 0);
}

static int
pppoe_classify_map_match(struct cds_lfht_node *node, const void *_key)
{
	struct pppoe_map_node *pnode =
		caa_container_of(node, struct pppoe_map_node, pnode);
	const struct pppoe_session_key *key = _key;
	struct pppoe_connection *conn = rcu_dereference(pnode->ppp->if_softc);

	return key->session == pnode->session && conn &&
		key->underlying_ifindex == conn->underlying_ifindex;
}

struct ifnet *
ppp_lookup_ses(struct ifnet *underlying_interface, uint16_t session)
{
	struct pppoe_session_key key = {
		.session = session,
		.underlying_ifindex = underlying_interface->if_index,
	};

	struct cds_lfht *p_map_htbl = pppoe_map_get_ht();
	if (!p_map_htbl)
		return NULL;

	struct cds_lfht_iter iter;

	rcu_read_lock();
	cds_lfht_lookup(p_map_htbl, pppoe_classify_map_hash(&key),
			pppoe_classify_map_match, &key, &iter);
	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);

	if (node) {
		struct pppoe_map_node *pnode =
			caa_container_of(node, struct pppoe_map_node, pnode);
		if (pnode->ppp) {
			rcu_read_unlock();
			return pnode->ppp;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void
pppoe_entry_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct pppoe_map_node, pppoe_rcu));
}

void
ppp_remove_ses(uint32_t ifindex, uint16_t session)
{
	struct pppoe_session_key key = {
		.session = session,
		.underlying_ifindex = ifindex,
	};

	struct cds_lfht *p_map_htbl = pppoe_map_get_ht();

	if (!p_map_htbl)
		return;

	struct cds_lfht_iter iter;

	rcu_read_lock();
	cds_lfht_lookup(p_map_htbl, pppoe_classify_map_hash(&key),
			pppoe_classify_map_match, &key, &iter);
	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);

	if (node) {
		struct pppoe_map_node *pnode =
			caa_container_of(node, struct pppoe_map_node, pnode);

		cds_lfht_del(p_map_htbl, node);
		call_rcu(&pnode->pppoe_rcu, pppoe_entry_free);
	}

	rcu_read_unlock();
}

bool
pppoe_init_session(struct ifnet *ppp_dev, uint16_t session)
{
	struct pppoe_connection *conn = ppp_dev->if_softc;
	struct pppoe_session_key key = {
		.session = session,
		.underlying_ifindex =
			conn->underlying_ifindex,
	};

	struct cds_lfht *pppoe_tbl = pppoe_map_get_ht();

	/* Create PPPoE Session table if it doesn't exist */
	if (!pppoe_tbl) {
		struct pppoe_map_tbl *tbl;

		tbl = zmalloc_aligned(sizeof(*tbl));

		if (!tbl)
			return false;
		pppoe_tbl = cds_lfht_new(PPPOE_HASH_MIN_BUCKETS,
			PPPOE_HASH_MIN_BUCKETS, PPPOE_HASH_MAX_BUCKETS,
				CDS_LFHT_AUTO_RESIZE, NULL);
		if (!pppoe_tbl) {
			free(tbl);
			return false;
		}
		tbl->ht = pppoe_tbl;
		rcu_set_pointer(&pppoe_map_tbl, tbl);
	}

	struct cds_lfht_iter iter;
	struct pppoe_map_node *pnode = NULL;
	struct cds_lfht_node *node;

	/* Does session already exist? */
	rcu_read_lock();
	cds_lfht_lookup(pppoe_tbl, pppoe_classify_map_hash(&key),
			pppoe_classify_map_match, &key, &iter);
	node = cds_lfht_iter_get_node(&iter);

	if (!node) {
		pnode = zmalloc_aligned(sizeof(*pnode));
		if (pnode) {
			cds_lfht_node_init(&pnode->pnode);
			pnode->session = session;
			pnode->ppp = ppp_dev;
			cds_lfht_add(pppoe_tbl, pppoe_classify_map_hash(&key),
					&pnode->pnode);
		}
	}
	rcu_read_unlock();

	return true;
}


/* Global PPPoE encap function. Generally you want to set output = true
 * as this is the defacto way this encap function should work, however
 * there is a corner case where we have to re-encap a pipeline packet after
 * having stripped the header on Pipeline input before punting it to
 * the kernel after ipv4_l4_process_common()->ipv4-local().
 */
bool
ppp_do_encap(struct rte_mbuf *m, struct pppoe_connection *conn,
		uint16_t proto, bool output)
{
	if (!conn->valid)
		return false;

	/* Add some extra space to the front of the packet, enough for the pppoe
	 * header plus existing ether.
	 */
	struct pppoe_packet *pheader =
		(struct pppoe_packet *)rte_pktmbuf_prepend(
			m, sizeof(struct pppoe_packet) -
			sizeof(struct ether_hdr));
	if (unlikely(!pheader))
		return false;
	pheader->session = htons(conn->session);
	if (output) {
		memcpy(&pheader->eth_hdr.d_addr, &conn->peer_eth,
				sizeof(struct ether_addr));
		memcpy(&pheader->eth_hdr.s_addr, &conn->my_eth,
				sizeof(struct ether_addr));
	} else {
		memcpy(&pheader->eth_hdr.d_addr, &conn->my_eth,
				sizeof(struct ether_addr));
		memcpy(&pheader->eth_hdr.s_addr, &conn->peer_eth,
				sizeof(struct ether_addr));
	}
	pheader->eth_hdr.ether_type = htons(ETH_P_PPP_SES);
	pheader->vertype = PPPOE_VER_TYPE(1, 1);
	pheader->code = 0x00;
	/* +2 for PPPoE Proto field */
	pheader->length = htons(rte_pktmbuf_pkt_len(m) -
			sizeof(struct pppoe_packet) + 2);

	switch (proto) {
	case ETH_P_IP:
		pheader->protocol = htons(PPP_IP);
		break;
	case ETH_P_IPV6:
		pheader->protocol = htons(PPP_IPV6);
		break;
	default:
		return false;
	}
	return true;
}

void
ppp_tunnel_output(struct ifnet *ifp, struct rte_mbuf *m,
		  struct ifnet *input_ifp, uint16_t proto)
{
	struct pppoe_connection *conn;

	conn = rcu_dereference(ifp->if_softc);

	if (!conn) {
		/*
		 * This may happen during a transient period whereby
		 * the routes from the kernel aren't fully populated
		 * and an ICMP error is generated but that too can't
		 * be sent as the output interface for the src addr of
		 * the original packet isn't fully setup and neither
		 * can we punt to the kernel for the input virtual
		 * interface
		 */
		if (!input_ifp) {
			if_incr_oerror(ifp);
			rte_pktmbuf_free(m);
			return;
		}
		local_packet(input_ifp, m);
		return;
	}

	if (!ppp_do_encap(m, conn, proto, true)) {
		if_incr_oerror(ifp);
		rte_pktmbuf_free(m);
		return;
	}

	if_output(conn->underlying_interface, m, ifp, 0);
}

static void
ppp_tunnel_delete(struct ifnet *ifp)
{
	if (!ifp->if_softc)
		return;

	struct pppoe_connection *conn = ifp->if_softc;

	if (conn->valid)
		ppp_remove_ses(conn->underlying_ifindex,
			       conn->session);
	cds_list_del_rcu(&conn->list_node);
	call_rcu(&conn->scpppoe_rcu, pppoe_softc_free_rcu);

	/* If this is the last tunnel, then we can unregister for tracking. */
	if (cds_list_empty(pppoe_get_conn_list()))
		pppoe_no_track_underlying_interfaces();
}

static const struct ift_ops ppp_if_ops = {
	.ifop_uninit = ppp_tunnel_delete,
};

static void ppp_init(void)
{
	int ret = if_register_type(IFT_PPP, &ppp_if_ops);
	if (ret < 0)
		rte_panic("Failed to register PPP type: %s", strerror(-ret));
}

static const struct dp_event_ops ppp_events = {
	.init = ppp_init,
};

DP_STARTUP_EVENT_REGISTER(ppp_events);
