/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <arpa/inet.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <urcu/list.h>

#include "compiler.h"
#include "crypto.h"
#include "crypto/crypto_main.h"
#include "crypto_internal.h"
#include "crypto_sadb.h"
#include "esp.h"
#include "if_var.h"
#include "json_writer.h"
#include "lcore_sched.h"
#include "route.h"
#include "route_v6.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"

#define SADB_DEBUG(args...)				\
	DP_DEBUG(CRYPTO, DEBUG, SADB, args)

#define SADB_ERR(args...)				\
	DP_DEBUG(CRYPTO, ERR, SADB, args)

#define SADB_INFO(args...)				\
	DP_DEBUG(CRYPTO, INFO, SADB, args)

/*
 * struct sadb_peer
 *
 * This struct describes a single IPsec peer.
 *
 * All the SAs associated with the peer are in the peer's
 * sa_list. New SAs are inserted at the head of the list.
 */
struct sadb_peer {
	struct cds_lfht_node ht_node;
	struct cds_list_head sa_list;
	xfrm_address_t dst;
	uint16_t family;
	char SPARE[6];
	struct rcu_head peer_rcu;
	/* --- cacheline 1 boundary (64 bytes) was 8 bytes ago --- */
	struct crypto_overhead_list observers;
};

/* peer_rcu and observers are both control plane fields.
 * Ensure that the other fields do not reach into the 2nd cache line.
 */
static_assert(offsetof(struct sadb_peer, peer_rcu) < 64,
	      "first cache line exceeded");

/*
 * Key for hash table entries for the F(spi,dest) to
 * output SA hash tree lookup
 */
struct sadb_spi_out_key {
	const xfrm_address_t *dst;
	uint32_t spi;
	uint16_t family;
};

static uint64_t sa_epoch;

/*
 * Hash seed used when hashing the spi and dest address
 * for an output SA lookup.
 */
static unsigned int sadb_spi_out_seed;

/*
 * This is a utility structure used for looking up
 * a peer in hash table.
 */
struct sadb_peer_key {
	const xfrm_address_t *dst;
	uint16_t family;
};

/*
 * Lock free hash table of SAs indexed by SPI.
 */
static struct cds_lfht *spi_in_hash_table;

/*
 * Hash is just the SPI. This only works because we only
 * enter decryption SAs (i.e. those for which we've allocated
 * the SPI) in to the hash table, not (possibly non-unique)
 * encrytion SAs.
 */
static unsigned int sadb_spi_in_hash(uint32_t *spi_p)
{
	return *spi_p;
}

/*
 * Comparison function used when searching the SA SPI hash table.
 * Returns TRUE if the SA containing node matches the search key.
 */
static int sadb_spi_in_match(struct cds_lfht_node *node, const void *key)
{
	const uint32_t *search_spi;
	const struct sadb_sa *sa;

	search_spi = (const uint32_t *)key;
	sa = caa_container_of(node, const struct sadb_sa, spi_ht_node);

	return (sa->spi == *search_spi);
}

/*
 * Used by the fast path to lookup an input (decrypt) SA by SPI.
 */
struct sadb_sa *sadb_lookup_sa_by_spi_in(uint32_t spi)
{
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	cds_lfht_lookup(spi_in_hash_table,
			sadb_spi_in_hash(&spi),
			sadb_spi_in_match,
			&spi, &iter);

	node = cds_lfht_iter_get_node(&iter);

	return node ? caa_container_of(node, struct sadb_sa,
				       spi_ht_node) : NULL;
}

/*
 * Used by the fastpath to map input spi to  pmd_dev_id
 */
int crypto_spi_to_pmd_dev_id(uint32_t spi)
{
	struct sadb_sa *sa;

	sa = sadb_lookup_sa_by_spi_in(spi);
	if (!sa) {
		IPSEC_CNT_INC(DROPPED_NO_SPI_TO_SA);
		return CRYPTO_PMD_INVALID_ID;
	}

	return sa->pmd_dev_id;
}

static bool sadb_add_sa_to_spi_in_hash(struct sadb_sa *sa)
{
	struct cds_lfht_node *ret_node;

	/*
	 * We only need to find SAs by SPI for packets
	 * we are going to decrypt, so ignore this SA
	 * it's for encryption.
	 */
	if (sa->dir != CRYPTO_DIR_IN)
		return true;

	cds_lfht_node_init(&sa->spi_ht_node);
	ret_node = cds_lfht_add_unique(spi_in_hash_table,
				       sadb_spi_in_hash(&sa->spi),
				       sadb_spi_in_match,
				       &sa->spi,
				       &sa->spi_ht_node);

	if (ret_node != &sa->spi_ht_node) {
		SADB_ERR("Failed to add SA to SPI hash table\n");
		return false;
	}

	return true;
}

static void sadb_remove_sa_from_spi_in_hash(struct sadb_sa *sa)
{
	if (sa->dir == CRYPTO_DIR_IN)
		cds_lfht_del(spi_in_hash_table, &sa->spi_ht_node);
}

/*
 * Hash is  the SPI and the dest address.
 */
static unsigned int
sadb_spi_out_hash(struct sadb_spi_out_key *key)
{
	const xfrm_address_t *dst = key->dst;
	unsigned long h;

	if (key->family == AF_INET)
		h = dst->a4;
	else
		h = dst->a6[0] + dst->a6[1] + dst->a6[2] + dst->a6[3];

	return rte_jhash_2words(key->spi, h, sadb_spi_out_seed);
}

/*
 * Comparison function used when searching the SA outbuond hash table.
 * Returns TRUE if the SA containing node matches the search key.
 */
static int sadb_spi_out_match(struct cds_lfht_node *node, const void *key)
{
	struct sadb_spi_out_key *search_key;
	struct sadb_sa *sa;

	search_key = (struct sadb_spi_out_key *)key;
	sa = caa_container_of(node, struct sadb_sa, spi_ht_node);

	return ((sa->spi == search_key->spi) &&
		(sa->family == search_key->family) &&
		xfrm_addr_eq(&sa->dst, search_key->dst, sa->family));
}

/*
 * Used by the fast path to lookup an output (encrypt) SA by SPI and dest addr.
 */
struct sadb_sa *sadb_lookup_sa_outbound(vrfid_t vrfid,
					const xfrm_address_t *dst,
					uint16_t family, uint32_t spi)
{
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct sadb_spi_out_key search_key;
	struct sadb_sa *sa;
	struct crypto_vrf_ctx *vrf_ctx;

	vrf_ctx = crypto_vrf_find(vrfid);
	if (!vrf_ctx)
		return NULL;

	search_key.spi = spi;
	search_key.family = family;
	search_key.dst = dst;

	cds_lfht_lookup(vrf_ctx->spi_out_hash_table,
			sadb_spi_out_hash(&search_key),
			sadb_spi_out_match,
			&search_key, &iter);

	node = cds_lfht_iter_get_node(&iter);

	sa =  node ? caa_container_of(node, struct sadb_sa,
				      spi_ht_node) : NULL;

	if (!sa) {
		IPSEC_CNT_INC(DROPPED_NO_SPI_TO_SA);
		return NULL;
	}

	if (sa->blocked)
		return NULL;

	return sa;
}


static bool sadb_add_sa_to_spi_out_hash(struct sadb_sa *sa,
					struct crypto_vrf_ctx *vrf_ctx)
{
	struct cds_lfht_node *ret_node;
	struct sadb_spi_out_key search_key;

	/*
	 * We only need to find SAs by SPI for packets
	 * we are going to decrypt, so ignore this SA
	 * it's for encryption.
	 */
	if (sa->dir != CRYPTO_DIR_OUT)
		return true;

	search_key.spi = sa->spi;
	search_key.family = sa->family;
	search_key.dst = &sa->dst;

	cds_lfht_node_init(&sa->spi_ht_node);
	ret_node = cds_lfht_add_unique(vrf_ctx->spi_out_hash_table,
				       sadb_spi_out_hash(&search_key),
				       sadb_spi_out_match,
				       &search_key,
				       &sa->spi_ht_node);

	if (ret_node != &sa->spi_ht_node) {
		SADB_ERR("Failed to add SA to SPI hash table\n");
		return false;
	}

	return true;
}

static void sadb_remove_sa_from_spi_out_hash(struct sadb_sa *sa,
					     vrfid_t vrfid)
{
	struct crypto_vrf_ctx *vrf_ctx;

	vrf_ctx = crypto_vrf_find(vrfid);
	if (!vrf_ctx)
		return;

	if (sa->dir == CRYPTO_DIR_OUT)
		cds_lfht_del(vrf_ctx->spi_out_hash_table, &sa->spi_ht_node);
}

/*
 * sadb_peer_hash()
 *
 * Address hash function used to select a bucket in
 * the SADB hash table.
 */
static unsigned long sadb_peer_hash(struct sadb_peer_key *key)

{
	const xfrm_address_t *dst = key->dst;
	unsigned long h;

	if (key->family == AF_INET)
		h = dst->a4;
	else
		h = dst->a6[0] + dst->a6[1] + dst->a6[2] + dst->a6[3];

	return h;
}

/*
 * sadb_peer_match()
 *
 * Comparison function used when searching the peer hash table.
 * Returns TRUE if the peer containing node matches the search key.
 */
static int sadb_peer_match(struct cds_lfht_node *node, const void *key)
{
	const struct sadb_peer_key *search_key;
	const struct sadb_peer *peer;

	search_key = (const struct sadb_peer_key *)key;
	peer = caa_container_of(node, const struct sadb_peer, ht_node);

	return ((peer->family == search_key->family) &&
		 xfrm_addr_eq(&peer->dst, search_key->dst, peer->family));
}

/*
 * sadb_lookup_peer()
 *
 * Lookup and IPsec peer in the hash table using its address.
 * Return NULL if there is no entry for the peer.
 *
 * This can be called from any thread that is registered as
 * an RCU read and is in a RCU read critical section
 */
static struct sadb_peer *sadb_lookup_peer(const xfrm_address_t *dst,
					  uint16_t family, vrfid_t vrfid)
{
	struct sadb_peer_key search_key;
	struct crypto_vrf_ctx *vrf_ctx;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	vrf_ctx = crypto_vrf_find(vrfid);
	if (!vrf_ctx)
		return NULL;

	search_key.family = family;
	search_key.dst = dst;

	cds_lfht_lookup(vrf_ctx->sadb_hash_table, sadb_peer_hash(&search_key),
			sadb_peer_match, &search_key, &iter);

	node = cds_lfht_iter_get_node(&iter);

	return node ? caa_container_of(node, struct sadb_peer, ht_node) : NULL;
}

/*
 * sadb_lookup_or_create_peer()
 *
 * Lookup and IPsec peer in the hash table using its address.
 * If there is no hash table entry for the peer, create one
 * and insert into the table.
 *
 * NOTE: This may only be called from the main thread.
 */
static struct sadb_peer *sadb_lookup_or_create_peer(const xfrm_address_t *dst,
						    uint16_t family,
						    vrfid_t vrfid)
{
	struct cds_lfht_node *ret_node;
	struct sadb_peer_key key;
	struct sadb_peer *peer;
	struct crypto_vrf_ctx *vrf_ctx;

	/*
	 * Lookup/create VRF context
	 */
	vrf_ctx = crypto_vrf_get(vrfid);
	if (!vrf_ctx)
		return NULL;

	peer = sadb_lookup_peer(dst, family, vrfid);
	if (peer)
		return peer;

	peer = zmalloc_aligned(sizeof(*peer));
	if (!peer) {
		SADB_ERR("Failed to allocate IPsec peer\n");
		return NULL;
	}

	memcpy(&peer->dst, dst, sizeof(peer->dst));
	peer->family = family;
	CDS_INIT_LIST_HEAD(&peer->sa_list);
	cds_lfht_node_init(&peer->ht_node);
	TAILQ_INIT(&peer->observers);


	key.dst = &peer->dst;
	key.family = peer->family;

	ret_node = cds_lfht_add_unique(vrf_ctx->sadb_hash_table,
				       sadb_peer_hash(&key),
				       sadb_peer_match, &key, &peer->ht_node);
	/*
	 * We've just done a lookup that didn't find the peer. If we're
	 * now told that the key we're trying to insert is not unique,
	 * then something is wrong somewhere.
	 */
	if (ret_node != &peer->ht_node) {
		SADB_ERR("Failed to insert IPsec peer in hash table\n");
		free(peer);
		return NULL;
	}
	vrf_ctx->count_of_peers++;

	return peer;
}

/*
 * sadb_peer_rcu_free()
 *
 * RCU callback to free a peer that has been removed
 * from the hash table.
 */
static void sadb_peer_rcu_free(struct rcu_head *head)
{
	free(caa_container_of(head, struct sadb_peer, peer_rcu));
}

/*
 * sadb_remove_peer()
 *
 * Remove the entry for an IPsec peer from the hash table.
 */
static void sadb_remove_peer(struct sadb_peer *peer, vrfid_t vrfid)
{
	struct crypto_vrf_ctx *vrf_ctx;

	vrf_ctx = crypto_vrf_find(vrfid);
	if (!vrf_ctx)
		return;

	cds_lfht_del(vrf_ctx->sadb_hash_table, &peer->ht_node);
	call_rcu(&peer->peer_rcu, sadb_peer_rcu_free);
	vrf_ctx->count_of_peers--;
}

static void sadb_refresh_osbervers_of_sa(struct sadb_sa *sa,
					 struct sadb_peer *peer,
					 bool unique)
{
	struct cds_list_head *this_entry;
	struct crypto_overhead *observer;
	struct sadb_sa *tmp_sa;
	unsigned int count = 0;

	/*
	 * When deleting an SA, if might have been replaced by a new
	 * SA with the same peer/reqid. If so we can not update any
	 * observers as they will be refreshed with details of SA
	 * being purged, i.e an invalid PMD. The unique flag indicates
	 * we need to ensure the SA being deleted is unique and not
	 * one that has just been replaced, i.e we will not find an SA
	 * with the same peer, reqid in the list.
	*/
	if (unique) {
		cds_list_for_each(this_entry, &peer->sa_list) {
			tmp_sa = cds_list_entry(this_entry, struct sadb_sa,
						peer_links);
			if (tmp_sa->reqid == sa->reqid) {
				count++;
				break;
			}
		}
	}

	if ((unique && count == 0) || !unique) {
		TAILQ_FOREACH(observer, &peer->observers, links) {
			if (observer->reqid == sa->reqid) {
				observer->bytes =
				 cipher_get_encryption_overhead(sa,
								sa->family);
				observer->pmd_dev_id = sa->pmd_dev_id;
				observer->spi = sa->spi;
			}
		}
	}
}

/*
 * Look up for an old SA. Return the least old one.
 */
static struct sadb_sa *
sadb_find_old_sa(struct sadb_sa *sa, vrfid_t vrfid, struct sadb_peer **ret_peer)
{
	struct sadb_peer *peer;
	struct cds_list_head *this_entry;
	struct sadb_sa *tmp_sa, *match_sa = NULL;

	peer = sadb_lookup_peer(&sa->dst, sa->family, vrfid);
	if (!peer)
		return NULL;

	cds_list_for_each(this_entry, &peer->sa_list) {
		tmp_sa = cds_list_entry(this_entry, struct sadb_sa,
					peer_links);
		if (tmp_sa->reqid == sa->reqid &&
		    tmp_sa->spi != sa->spi) {
			if (!match_sa)
				match_sa = tmp_sa;
			else if (match_sa->epoch < tmp_sa->epoch)
				match_sa = tmp_sa;
		}
	}

	*ret_peer = peer;
	return match_sa;
}
/*
 * Look up for a duplicate SA.
 */
static struct sadb_sa *
sadb_find_matching_sa(struct sadb_sa *sa, bool ign_pending_del, vrfid_t vrfid)
{
	struct sadb_peer *peer;
	struct cds_list_head *this_entry;
	struct sadb_sa *tmp_sa;

	peer = sadb_lookup_peer(&sa->dst, sa->family, vrfid);
	if (!peer)
		return NULL;

	cds_list_for_each(this_entry, &peer->sa_list) {
		tmp_sa = cds_list_entry(this_entry, struct sadb_sa,
					peer_links);
		if (tmp_sa->reqid == sa->reqid &&
		    tmp_sa->spi != sa->spi &&
		    ((!ign_pending_del && !tmp_sa->pending_del) ||
		     ign_pending_del))
			return tmp_sa;
	}
	return NULL;
}
/*
 * Insert an SA into the SADB table. If the table already
 * contains an SA with the same (dst, src, spi) tuple, the
 * new SA will mask it, but the old SA will not be removed.
 *
 * This function should only be called from the main thread.
 */
static int sadb_insert_sa(struct sadb_sa *sa, struct crypto_vrf_ctx *vrf_ctx)
{
	struct sadb_peer *peer;

	if (!sa)
		return -1;

	if (!sadb_add_sa_to_spi_in_hash(sa)) {
		SADB_ERR("Failed to add SA to SPI in hash table");
		return -1;
	}

	if (!sadb_add_sa_to_spi_out_hash(sa, vrf_ctx)) {
		SADB_ERR("Failed to add SA to SPI out hash table");
		return -1;
	}

	peer = sadb_lookup_or_create_peer(&sa->dst, sa->family,
					  vrf_ctx->vrfid);
	if (!peer) {
		sadb_remove_sa_from_spi_in_hash(sa);
		sadb_remove_sa_from_spi_out_hash(sa, vrf_ctx->vrfid);
		SADB_ERR("Could not insert SA, failed to find IPsec peer\n");
		return -2;
	}

	cds_list_add_rcu(&sa->peer_links, &peer->sa_list);

	/*
	 * Update the crypto overhead of any observers that
	 * are registered for this peer and reqid.
	 */
	sadb_refresh_osbervers_of_sa(sa, peer, false);

	return 1;
}

/*
 * sabd_remove_sa()
 *
 * Search the SADB for an SA matching (dst, src, spi) and
 * remove it from the table. If a matching entry is found,
 * it is returned. A return value of NULL indicates that no
 * match was found. If the table contains multiple SAs that
 * match the least recently added SA is removed and returned.
 *
 * This function is called from the main thread only.
 */
static struct sadb_sa *sadb_remove_sa(const xfrm_address_t *dst,
				      const xfrm_address_t *src,
				      uint32_t spi,
				      uint16_t family,
				      vrfid_t vrfid)
{
	struct cds_list_head *this_entry, *next_entry;
	struct sadb_peer *peer;
	struct sadb_sa *sa;

	if (!dst || !src || ((family != AF_INET) && (family != AF_INET6)))
		return NULL;

	peer = sadb_lookup_peer(dst, family, vrfid);
	if (!peer)
		return NULL;

	/*
	 * In most cases we're looking to remove an old SA that
	 * has expired, so start looking from the tail of the list.
	 */
	cds_list_for_each_prev_safe(this_entry, next_entry, &peer->sa_list) {
		sa = cds_list_entry(this_entry, struct sadb_sa, peer_links);
		if (sa->spi == spi) {
			cds_list_del_rcu(&sa->peer_links);
			goto done;
		}
	}

	sa = NULL;

done:
	if (sa) {
		sa->pmd_dev_id = CRYPTO_PMD_INVALID_ID;
		sadb_remove_sa_from_spi_in_hash(sa);
		sadb_remove_sa_from_spi_out_hash(sa, vrfid);

		/*
		 * Update the crypto overhead pmd_dev_id of any
		 * observers that are registered for this peer and
		 * reqid.
		 */
		sadb_refresh_osbervers_of_sa(sa, peer, true);
	}

	/*
	 * If there are no more SAs for this peer and no
	 * overhead observers then we can remove it.
	 */
	if (cds_list_empty(&peer->sa_list) && TAILQ_EMPTY(&peer->observers))
		sadb_remove_peer(peer, vrfid);

	return sa;
}

/*
 * sadb_lookup_inbound()
 *
 * For an inbound lookup we must return the exact match
 * on (dst, src, spi). There should be exactly one match
 * (though we don't check this here).
 *
 * This function is called from forwarding threads only.
 */
struct sadb_sa *sadb_lookup_inbound(uint32_t spi)
{
	struct sadb_sa *sa;

	sa = sadb_lookup_sa_by_spi_in(spi);
	if (!sa) {
		IPSEC_CNT_INC(DROPPED_NO_SPI_TO_SA);
		return NULL;
	}


	if (!sa->blocked)
		return sa;
	else
		return NULL;
}

static void sadb_sa_destroy(struct sadb_sa *sa)
{
	cipher_teardown_ctx(sa);
	free(sa);
}

static enum crypto_xfrm crypto_sa_to_xfrm(struct sadb_sa *sa)
{
	return sa->dir == CRYPTO_DIR_IN ?
		CRYPTO_DECRYPT : CRYPTO_ENCRYPT;
}
/*
 * crypto_sadb_new_sa()
 *
 * Process a new or update SA message from the control plane.
 *
 * This function is called from the main thread only.
 */
void crypto_sadb_new_sa(const struct xfrm_usersa_info *sa_info,
			const struct xfrm_algo *crypto_algo,
			const struct xfrm_algo_auth *auth_algo,
			const struct xfrm_encap_tmpl *tmpl,
			uint32_t mark_val, uint32_t extra_flags,
			vrfid_t vrf_id)
{
	const struct xfrm_lifetime_cfg *lft = &sa_info->lft;
	struct sadb_sa *sa, *retiring_sa;
	struct crypto_vrf_ctx *vrf_ctx;
	struct ifnet *ifp;

	if (!sa_info || !crypto_algo) {
		SADB_ERR("Bad parameters on attempt to add SA\n");
		return;
	}

	vrf_ctx = crypto_vrf_get(vrf_id);
	if (!vrf_ctx)
		return;

	SADB_DEBUG("NEWSA SPI = %x Mark = %x VRF %d\n",
		   ntohl(sa_info->id.spi), mark_val, vrf_id);

	sa = zmalloc_aligned(sizeof(*sa));
	if (!sa) {
		SADB_ERR("Failed to allocate SA\n");
		return;
	}

	sa->family = sa_info->family;
	sa->src = sa_info->saddr;
	sa->dst = sa_info->id.daddr;
	sa->spi = sa_info->id.spi;
	sa->mark_val = mark_val;
	sa->reqid = sa_info->reqid;
	sa->byte_limit = lft->hard_byte_limit;
	sa->packet_limit = lft->hard_packet_limit;
	sa->overlay_vrf_id = vrf_id;
	sa->epoch = ++sa_epoch;

	if (sa_info->family == AF_INET) {
		if (is_local_ipv4(VRF_DEFAULT_ID, sa_info->id.daddr.a4))
			sa->dir = CRYPTO_DIR_IN;
		else
			sa->dir = CRYPTO_DIR_OUT;
	} else {
		const struct in6_addr *v6_dst;

		v6_dst = (const struct in6_addr *)&sa_info->id.daddr.a6;
		if (is_local_ipv6(VRF_DEFAULT_ID, v6_dst))
			sa->dir = CRYPTO_DIR_IN;
		else
			sa->dir = CRYPTO_DIR_OUT;
	}

	CDS_INIT_LIST_HEAD(&sa->peer_links);

	if (cipher_setup_ctx(crypto_algo, auth_algo, sa_info, tmpl,
			     sa, extra_flags))
		sa->blocked = true;
	/*
	 * Need to allocate the crypto_pmd before inserting the sa as
	 * the insertion triggers an update for any registered
	 * observers, i.e policies.
	 */
	retiring_sa = sadb_find_matching_sa(sa, false, vrf_id);
	if (retiring_sa) {
		retiring_sa->pending_del = true;
		crypto_pmd_mod_pending_del(retiring_sa->pmd_dev_id,
					   crypto_sa_to_xfrm(retiring_sa),
					   true);
	}

	sa->del_pmd_dev_id = sa->pmd_dev_id =
		crypto_allocate_pmd(crypto_sa_to_xfrm(sa));
	if (sadb_insert_sa(sa, vrf_ctx) < 0) {
		/*
		 * Even though the SA insert failed, we know
		 * there is a pending del on the retiring_sa,
		 * and so we should not unmark the dup_sa and
		 * the  PMD it is attached to.
		 */
		SADB_ERR("Failed to insert SA into SADB\n");
		sadb_sa_destroy(sa);
		return;
	}

	/*
	 * Check if the policy matching this reqid has a virtual feature
	 * point bound to it.
	 */
	ifp = (sa->dir == CRYPTO_DIR_IN) ?
		crypto_policy_feat_attach_by_reqid(sa->reqid) : NULL;
	rcu_assign_pointer(sa->feat_attach_ifp, ifp);

	vrf_ctx->count_of_sas++;
}

/*
 * sadb_sa_rcu_free()
 *
 * RCU callback to free an SA that has been removed
 * from a peer's list.
 */
static void sadb_sa_rcu_free(struct rcu_head *head)
{
	struct sadb_sa *sa;

	sa = caa_container_of(head, struct sadb_sa, sa_rcu);
	sadb_sa_destroy(sa);
}

static void crypto_sadb_resurrect_sa(struct sadb_sa *sa, vrfid_t vrfid)
{
	struct sadb_peer *peer = NULL;
	struct sadb_sa *old_sa = sadb_find_old_sa(sa, vrfid, &peer);

	if (!old_sa || !peer)
		return;

	SADB_DEBUG("Resurrect old SA %x\n", ntohl(old_sa->spi));

	old_sa->pending_del = false;
	crypto_pmd_mod_pending_del(old_sa->pmd_dev_id,
				   crypto_sa_to_xfrm(old_sa), false);
	/*
	 * Update the crypto overhead of any observers that
	 * are registered for this peer and reqid.
	 */
	sadb_refresh_osbervers_of_sa(old_sa, peer, false);
}

static void crypto_sadb_del_sa_internal(const xfrm_address_t *dst,
					const xfrm_address_t *src,
					uint32_t spi,
					uint16_t family,
					struct crypto_vrf_ctx *vrf_ctx,
					bool resurrect_old_sa)
{
	static struct sadb_sa *sa;

	ASSERT_MASTER();

	SADB_DEBUG("DELSA SPI = %x VRF %d\n", ntohl(spi), vrf_ctx->vrfid);

	/*
	 * Trigger the deletion of the SA, and set its pmd_dev_id to
	 * invalid, This will then get reflected to all the observers.
	 * We can not detatch from the PMD at this point, as that
	 * might trigger a PMD delete, and their might be traffic in
	 * flow. The PMD detatch is handled in the rcu callback for the
	 * sa delete.
	 */
	sa = sadb_remove_sa(dst, src, spi, family, vrf_ctx->vrfid);

	if (!sa) {
		char dstip_str[INET6_ADDRSTRLEN];

		inet_ntop(family, &dst,
			  dstip_str, sizeof(dstip_str));

		SADB_ERR("SA delete for %s SPI %x failed: not found\n",
			 dstip_str, ntohl(spi));
		return;
	}

	/* If this is an active SA, then we need to restore an old SA
	 * if one exists
	 */
	if (resurrect_old_sa && !sa->pending_del)
		crypto_sadb_resurrect_sa(sa, vrf_ctx->vrfid);

	crypto_remove_sa_from_pmd(sa->del_pmd_dev_id,
				  crypto_sa_to_xfrm(sa),
				  sa->pending_del);
	call_rcu(&sa->sa_rcu, sadb_sa_rcu_free);
	vrf_ctx->count_of_sas--;

	crypto_vrf_check_remove(vrf_ctx);
}

/*
 * crypto_sadb_del_sa()
 *
 * Delete an SA from the SADB and free the memory
 *
 * This function is called from the main thread only.
 */
void crypto_sadb_del_sa(const struct xfrm_usersa_info *sa_info, vrfid_t vrfid)
{
	struct crypto_vrf_ctx *vrf_ctx;

	if (!sa_info)
		return;

	vrf_ctx = crypto_vrf_find(vrfid);
	if (!vrf_ctx)
		return;

	crypto_sadb_del_sa_internal(&sa_info->id.daddr,
				    &sa_info->saddr,
				    sa_info->id.spi,
				    sa_info->family,
				    vrf_ctx,
				    true);
}

void crypto_sadb_flush_vrf(struct crypto_vrf_ctx *vrf_ctx)
{
	struct cds_lfht_iter iter;
	struct sadb_sa *sa;

	SADB_DEBUG("Flush all SAs for VRF %d\n", vrf_ctx->vrfid);

	cds_lfht_for_each_entry(vrf_ctx->spi_out_hash_table,
				&iter, sa, spi_ht_node) {
		crypto_sadb_del_sa_internal(&sa->dst,
					    &sa->src,
					    sa->spi,
					    sa->family,
					    vrf_ctx,
					    false);
	}

	cds_lfht_for_each_entry(spi_in_hash_table,
				&iter, sa, spi_ht_node) {
		if (sa->overlay_vrf_id == vrf_ctx->vrfid)
			crypto_sadb_del_sa_internal(&sa->dst,
						    &sa->src,
						    sa->spi,
						    sa->family,
						    vrf_ctx,
						    false);
	}
}

/*
 * Hash table size parameters. These must be powers of two.
 * Since we expect a small number of IPsec peers, we keep
 * the initial size of the hash table small.
 */
#define SADB_HT_MAX_BUCKETS 2048
#define SADB_HT_MIN_BUCKETS  8

/*
 * crypto_sadb_init()
 *
 * Initialise the SADB's hash table and counters.
 */
int crypto_sadb_init(void)
{
	/* As we only add spi entries for income SAs then the max
	 * number of buckets is half the number of max SAs.
	 */
	spi_in_hash_table = cds_lfht_new(SADB_HT_MIN_BUCKETS,
				      SADB_HT_MIN_BUCKETS,
				      SADB_HT_MAX_BUCKETS / 2,
				      CDS_LFHT_AUTO_RESIZE,
				      NULL);
	if (!spi_in_hash_table)
		rte_panic("Failed to allocate SPI in hash table\n");

	sadb_spi_out_seed = random();
	return 1;
}

int crypto_sadb_vrf_init(struct crypto_vrf_ctx *vrf_ctx)
{
	vrf_ctx->sadb_hash_table = cds_lfht_new(SADB_HT_MIN_BUCKETS,
						SADB_HT_MIN_BUCKETS,
						SADB_HT_MAX_BUCKETS,
						CDS_LFHT_AUTO_RESIZE,
						NULL);
	if (!vrf_ctx->sadb_hash_table)
		return 0;

	vrf_ctx->spi_out_hash_table = cds_lfht_new(SADB_HT_MIN_BUCKETS,
						   SADB_HT_MIN_BUCKETS,
						   SADB_HT_MAX_BUCKETS / 2,
						   CDS_LFHT_AUTO_RESIZE,
						   NULL);
	if (!vrf_ctx->spi_out_hash_table) {
		cds_lfht_destroy(vrf_ctx->sadb_hash_table, NULL);
		return 0;
	}

	return 1;
}

void crypto_sadb_vrf_clean(struct crypto_vrf_ctx *vrf_ctx)
{
	if (vrf_ctx->sadb_hash_table)
		cds_lfht_destroy(vrf_ctx->sadb_hash_table, NULL);
	if (vrf_ctx->spi_out_hash_table)
		cds_lfht_destroy(vrf_ctx->spi_out_hash_table, NULL);
}

uint32_t crypto_sadb_get_mark_val(struct sadb_sa *sa)
{
	if (sa)
		return sa->mark_val;
	else
		return 0;
}

static const char *xfrm_addr_to_str(uint16_t family,
				    const xfrm_address_t *addr,
				    char *buf, size_t blen)
{
	const char *addrstr;

	switch (family) {
	case AF_INET:
		addrstr = inet_ntop(family, &addr->a4, buf, blen);
		break;
	case AF_INET6:
		addrstr = inet_ntop(family, &addr->a6, buf, blen);
		break;
	default:
		addrstr = NULL;
	}

	return addrstr ?: "[bad address]";
}

#define SPI_LEN_IN_HEXCHARS (8+1) /* 32 bit SPI */

void crypto_sadb_show_summary(FILE *f, vrfid_t vrfid)
{
	json_writer_t *wr;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct crypto_vrf_ctx *vrf_ctx;
	struct ifnet *ifp;

	if (!dp_vrf_get_rcu_from_external(vrfid))
		return;

	wr = jsonw_new(f);
	if (!wr)
		return;

	vrf_ctx = crypto_vrf_find_external(vrfid);

	jsonw_pretty(wr, true);
	jsonw_name(wr, "ipsec-sas");
	jsonw_start_object(wr);

	/*
	 * Return a count of zero if no crypto context
	 */
	jsonw_uint_field(wr, "vrf", vrfid);
	jsonw_uint_field(wr, "total-sas",
			 vrf_ctx ? vrf_ctx->count_of_sas : 0);
	jsonw_end_object(wr);
	jsonw_name(wr, "sas");
	jsonw_start_array(wr);
	if (!vrf_ctx)
		goto sa_finished;

	cds_lfht_first(vrf_ctx->sadb_hash_table, &iter);

	while ((node = cds_lfht_iter_get_node(&iter)) != NULL) {
		const struct sadb_peer *peer;
		const struct sadb_sa *sa;
		char spi_as_hexstring[SPI_LEN_IN_HEXCHARS];
		char addrbuf[INET6_ADDRSTRLEN];

		peer = caa_container_of(node, struct sadb_peer, ht_node);
		cds_list_for_each_entry_rcu(sa,  &peer->sa_list, peer_links) {
			jsonw_start_object(wr);
			spi_to_hexstr(spi_as_hexstring, sa->spi);
			jsonw_string_field(wr, "spi", spi_as_hexstring);
			jsonw_uint_field(wr, "pmd_dev_id", sa->pmd_dev_id);
			jsonw_string_field(wr, "pending_delete",
					   sa->pending_del ? "Yes" : "No");
			crypto_engine_summary(wr, sa);
			jsonw_uint_field(wr, "replay_window",
					 sa->replay_window);
			jsonw_uint_field(wr, "replay_bitmap",
					 sa->replay_bitmap);
			jsonw_uint_field(wr, "seq", sa->seq);
			jsonw_uint_field(wr, "af", sa->family);
			jsonw_string_field(wr, "dst",
					   xfrm_addr_to_str(sa->family,
							    &sa->dst,
							    addrbuf,
							    sizeof(addrbuf)));
			jsonw_string_field(wr, "src",
					   xfrm_addr_to_str(sa->family,
							    &sa->src,
							    addrbuf,
							    sizeof(addrbuf)));
			jsonw_uint_field(wr, "reqid", sa->reqid);
			jsonw_uint_field(wr, "bytes", sa->byte_count);
			jsonw_uint_field(wr, "byte_limit", sa->byte_limit);
			jsonw_uint_field(wr, "packets", sa->packet_count);
			jsonw_uint_field(wr, "packet_limit", sa->packet_limit);
			jsonw_bool_field(wr, "blocked", sa->blocked);
			jsonw_uint_field(wr, "out_of_seq_drop",
					 sa->seq_drop);
			jsonw_string_field(wr, "direction",
					   sa->dir == CRYPTO_DIR_IN ? "in" :
					   "out");

			ifp = rcu_dereference(sa->feat_attach_ifp);
			if (ifp) {
				jsonw_string_field(
				    wr, "virtual-feature-point", ifp->if_name);
			}
			jsonw_end_object(wr);
		}
		cds_lfht_next(vrf_ctx->sadb_hash_table, &iter);
	}
sa_finished:
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

void crypto_sadb_show_spi_mapping(FILE *f, vrfid_t vrfid)
{
	json_writer_t *wr;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	char spi_as_hexstring[SPI_LEN_IN_HEXCHARS];
	struct crypto_vrf_ctx *vrf_ctx;

	vrf_ctx = crypto_vrf_find_external(vrfid);
	if (!vrf_ctx)
		return;

	wr = jsonw_new(f);
	if (!wr)
		return;

	jsonw_pretty(wr, true);
	jsonw_name(wr, "spi_in->pmd_dev_id");
	jsonw_start_array(wr);
	cds_lfht_first(spi_in_hash_table, &iter);
	while ((node = cds_lfht_iter_get_node(&iter)) != NULL) {
		const struct sadb_sa *sa;

		sa =  caa_container_of(node, struct sadb_sa,
				       spi_ht_node);
		jsonw_start_object(wr);
		spi_to_hexstr(spi_as_hexstring, sa->spi);
		jsonw_string_field(wr, "spi", spi_as_hexstring);
		jsonw_uint_field(wr, "pmd_dev_id", sa->pmd_dev_id);
		jsonw_end_object(wr);

		cds_lfht_next(spi_in_hash_table, &iter);
	};

	jsonw_end_array(wr);

	jsonw_name(wr, "spi_out->pmd_dev_id");
	jsonw_start_array(wr);
	cds_lfht_first(vrf_ctx->spi_out_hash_table, &iter);
	while ((node = cds_lfht_iter_get_node(&iter)) != NULL) {
		const struct sadb_sa *sa;

		sa =  caa_container_of(node, struct sadb_sa,
				       spi_ht_node);
		jsonw_start_object(wr);
		spi_to_hexstr(spi_as_hexstring, sa->spi);
		jsonw_string_field(wr, "spi", spi_as_hexstring);
		jsonw_uint_field(wr, "pmd_dev_id", sa->pmd_dev_id);
		jsonw_end_object(wr);

		cds_lfht_next(vrf_ctx->spi_out_hash_table, &iter);
	};

	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

void crypto_sadb_increment_counters(struct sadb_sa *sa, uint32_t bytes,
				    uint32_t packets)
{
	sa->packet_count += packets;
	sa->byte_count   += bytes;

	if ((sa->packet_count > sa->packet_limit) ||
	    (sa->byte_count > sa->byte_limit)) {
		crypto_sadb_mark_as_blocked(sa);
		crypto_expire_request(sa->spi, sa->reqid,
				      IPPROTO_ESP, 0 /* hard */);
	}
}

static void cypto_sadb_overhead_refresh(struct sadb_peer *peer,
					struct crypto_overhead *overhead)
{
	struct sadb_sa *sa;

	/*
	 * Pick up the overhead from the most
	 * recent matching SA if there is one.
	 */
	cds_list_for_each_entry_rcu(sa, &peer->sa_list, peer_links) {
		if (sa->reqid != overhead->reqid)
			continue;

		unsigned int block_size = sa->session ?
			crypto_session_block_size(sa->session) : 1;
		overhead->bytes = cipher_get_encryption_overhead(sa,
								 sa->family);
		overhead->block_size = RTE_ALIGN(block_size,
						 ESP_PAYLOAD_MIN_ALIGN);
		overhead->pmd_dev_id = sa->pmd_dev_id;
		overhead->spi = sa->spi;
		break;
	}
}

void crypto_sadb_peer_overhead_subscribe(const xfrm_address_t *peer_address,
					 uint16_t family, uint32_t reqid,
					 struct crypto_overhead *overhead,
					 vrfid_t vrfid)
{
	struct sadb_peer *peer;

	peer = sadb_lookup_or_create_peer(peer_address, family, vrfid);
	if (!peer) {
		SADB_ERR("Could not subscribe to peer overhead\n");
		return;
	}

	overhead->bytes = 0;
	overhead->reqid = reqid;
	overhead->pmd_dev_id = CRYPTO_PMD_INVALID_ID;
	overhead->block_size = ESP_PAYLOAD_MIN_ALIGN;
	overhead->spi = 0;
	TAILQ_INSERT_TAIL(&peer->observers, overhead, links);
	cypto_sadb_overhead_refresh(peer, overhead);
}

void crypto_sadb_peer_overhead_unsubscribe(const xfrm_address_t *peer_address,
					   uint16_t family,
					   struct crypto_overhead *overhead,
					   vrfid_t vrfid)
{
	struct sadb_peer *peer;

	peer = sadb_lookup_peer(peer_address, family, vrfid);
	if (!peer) {
		SADB_ERR("Overhead unsubscribe failed: peer not found.\n");
		return;
	}

	TAILQ_REMOVE(&peer->observers, overhead, links);
	overhead->bytes = 0;
	overhead->pmd_dev_id = CRYPTO_PMD_INVALID_ID;
	overhead->spi = 0;
	/*
	 * If there are no more observers and
	 * no SAs then we can remove the peer.
	 */
	if (cds_list_empty(&peer->sa_list) && TAILQ_EMPTY(&peer->observers))
		sadb_remove_peer(peer, vrfid);
}

int crypto_sadb_peer_overhead_change_reqid(const xfrm_address_t *peer_address,
					   uint16_t family, uint32_t reqid,
					   struct crypto_overhead *overhead,
					   vrfid_t vrfid)
{
	struct sadb_peer *peer;

	peer = sadb_lookup_peer(peer_address, family, vrfid);
	if (!peer) {
		SADB_ERR("Overhead reqid change failed: peer not found.\n");
		return -1;
	}

	overhead->bytes = 0;
	overhead->reqid = reqid;
	overhead->block_size = ESP_PAYLOAD_MIN_ALIGN;
	cypto_sadb_overhead_refresh(peer, overhead);

	return 1;
}

uint32_t crypto_sadb_get_reqid(struct sadb_sa *sa)
{
	return sa->reqid;
}

void crypto_sadb_mark_as_blocked(struct sadb_sa *sa)
{
	sa->blocked = true;
}

void crypto_sadb_seq_drop_inc(struct sadb_sa *sa)
{
	sa->seq_drop++;
	IPSEC_CNT_INC(OUTSIDE_SEQ_WINDOW);
}

/*
 * For an updated binding between policy and virtual feature point
 * interface, if there are any SAs present, we need to find them via
 * the policy reqid and bind or unbind them to/from the virtual feature point.
 *
 * Note we only do this for input SAs. On the output side, the binding
 * is created in the policy rule.
 */
void crypto_sadb_feat_attach_in(uint32_t reqid, struct ifnet *ifp)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_first(spi_in_hash_table, &iter);
	while ((node = cds_lfht_iter_get_node(&iter)) != NULL) {
		struct sadb_sa *sa;

		sa = caa_container_of(node, struct sadb_sa, spi_ht_node);

		if (sa->reqid == reqid)
			rcu_assign_pointer(sa->feat_attach_ifp, ifp);

		cds_lfht_next(spi_in_hash_table, &iter);
	}
}

struct crypto_incmpl_xfrm_sa_stats {
	uint64_t sa_add;
	uint64_t sa_update;
	uint64_t sa_del;
	uint64_t sa_missing;
	uint64_t if_complete;
	uint64_t mem_fails;
};

#define CRYPTO_INCMPL_XFRM_HASH_MIN 2
#define CRYPTO_INCMPL_XFRM_HASH_MAX 64

struct cds_lfht *crypto_incmpl_sa;
static struct crypto_incmpl_xfrm_sa_stats crypto_incmpl_xfrm_sa_stats;

struct crypto_sa_key {
	uint32_t spi;
	xfrm_address_t addr;
	uint16_t family;
};

struct crypto_incmpl_xfrm_sa {
	struct cds_lfht_node hash_node;
	struct rcu_head rcu;

	/* keys */
	struct crypto_sa_key key;

	/* netlink message */
	struct nlmsghdr *nlh;
};


void crypto_incmpl_sa_init(void)
{
	crypto_incmpl_sa = cds_lfht_new(CRYPTO_INCMPL_XFRM_HASH_MIN,
					    CRYPTO_INCMPL_XFRM_HASH_MAX,
					    CRYPTO_INCMPL_XFRM_HASH_MAX,
					    CDS_LFHT_AUTO_RESIZE |
					    CDS_LFHT_ACCOUNTING,
					    NULL);
	if (!crypto_incmpl_sa)
		rte_panic("Can't allocate hash for incomplete xfrm saicies\n");
}

static int crypto_incmpl_sa_match_fn(struct cds_lfht_node *node,
				      const void *key)
{
	const struct crypto_incmpl_xfrm_sa *sa;
	const struct crypto_incmpl_xfrm_sa *search_key = key;

	sa = caa_container_of(node,
			       const struct crypto_incmpl_xfrm_sa,
			       hash_node);

	return (sa->key.spi == search_key->key.spi &&
		xfrm_addr_eq(&sa->key.addr, &search_key->key.addr,
			     sa->key.family));
}

static void
crypto_incmpl_xfrm_sa_free(struct rcu_head *head)
{
	struct crypto_incmpl_xfrm_sa *sa;

	sa = caa_container_of(head, struct crypto_incmpl_xfrm_sa, rcu);
	free(sa->nlh);
	free(sa);
}

static unsigned long crypto_sa_hash(const struct crypto_sa_key *key)
{
	unsigned long h;

	h = hash_xfrm_address(&key->addr,
			      key->family);
	h += key->spi;

	return h;
}

/*
 * Add an incomplete sa (waiting on the vrf master). If we already have
 * an entry for the key (spi + addr) then update the message.
 *
 * The values come from different places depending on the msg type.
 */
void crypto_incmpl_xfrm_sa_add(uint32_t ifindex __unused,
			       const struct nlmsghdr *nlh,
			       const struct xfrm_usersa_info *sa_info)
{
	struct crypto_incmpl_xfrm_sa *sa;
	struct cds_lfht_node *ret_node;

	sa = calloc(1, sizeof(*sa));
	if (!sa) {
		crypto_incmpl_xfrm_sa_stats.mem_fails++;
		return;
	}

	sa->key.spi = sa_info->id.spi;
	sa->key.addr = sa_info->id.daddr;
	sa->key.family = sa_info->family ?: AF_INET;

	sa->nlh = malloc(nlh->nlmsg_len);
	if (!sa->nlh) {
		free(sa);
		crypto_incmpl_xfrm_sa_stats.mem_fails++;
		return;
	}
	memcpy(sa->nlh, nlh, nlh->nlmsg_len);

	ret_node = cds_lfht_add_replace(crypto_incmpl_sa,
					crypto_sa_hash(&sa->key),
					crypto_incmpl_sa_match_fn,
					sa,
					&sa->hash_node);
	if (ret_node == NULL) {
		/* added, but was no old entry */
		crypto_incmpl_xfrm_sa_stats.sa_add++;
	} else if (ret_node != &sa->hash_node) {
		/* replaced, so free old one */
		crypto_incmpl_xfrm_sa_stats.sa_update++;
		sa = caa_container_of(ret_node,
				       struct crypto_incmpl_xfrm_sa,
				       hash_node);
		call_rcu(&sa->rcu, crypto_incmpl_xfrm_sa_free);
	}
}

void crypto_incmpl_xfrm_sa_del(uint32_t ifindex __unused,
			       const struct nlmsghdr *nlh __unused,
			       const struct xfrm_usersa_info *sa_info)

{
	struct crypto_incmpl_xfrm_sa sa;
	struct crypto_incmpl_xfrm_sa *found;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	if (!sa_info)
		return;
	memset(&sa, 0, sizeof(sa));

	sa.key.spi = sa_info->id.spi;
	sa.key.addr = sa_info->id.daddr;
	sa.key.family = sa_info->family ?: AF_INET;

	cds_lfht_lookup(crypto_incmpl_sa,
			crypto_sa_hash(&sa.key),
			crypto_incmpl_sa_match_fn,
			&sa,
			&iter);

	node = cds_lfht_iter_get_node(&iter);
	if (!node) {
		crypto_incmpl_xfrm_sa_stats.sa_missing++;
		return;
	}
	cds_lfht_del(crypto_incmpl_sa, node);
	found = caa_container_of(node, struct crypto_incmpl_xfrm_sa,
				 hash_node);
	call_rcu(&found->rcu, crypto_incmpl_xfrm_sa_free);
	crypto_incmpl_xfrm_sa_stats.sa_del++;
}

void crypto_incmpl_sa_make_complete(void)
{
	struct cds_lfht_iter iter;
	struct crypto_incmpl_xfrm_sa *sa;
	vrfid_t vrf_id = VRF_DEFAULT_ID;

	crypto_incmpl_xfrm_sa_stats.if_complete++;

	cds_lfht_for_each_entry(crypto_incmpl_sa, &iter,
				sa, hash_node) {
		rtnl_process_xfrm_sa(sa->nlh, &vrf_id);
	}
}

