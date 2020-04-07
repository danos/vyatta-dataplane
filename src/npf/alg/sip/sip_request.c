/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * SIP request hash table and media list functions; SIP request handling.
 *
 * SIP request structures (struct sip_alg_request) are stored in a hash table
 * in the alg private data structure (struct sip_alg_private).  The lookup key
 * is the SIP request Call-ID number.
 *
 * SIP media structures are stored in a list in the SIP request structures.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <rte_atomic.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <urcu.h>

#include "dp_event.h"
#include "vrf.h"
#include "util.h"
#include "vplane_log.h"

#include "npf/alg/alg.h"
#include "npf/alg/sip/sip.h"
#include "npf/alg/sip/sip_osip.h"

/* Hash table config */
#define SIP_HT_INIT	32
#define SIP_HT_MIN	32
#define SIP_HT_MAX	1024

/*
 * Struct for matching hash table requests
 */
struct sip_request_match {
	osip_call_id_t *sm_call_id;
	uint32_t	sm_if_idx;
};

/*
 * Default lifetime for a request in the hash table.
 */
#define SIP_DEFAULT_REQUEST_TIMEOUT 32


/* Forward reference */
static int sip_alg_add_invite(const struct npf_alg *sip,
			      struct sip_alg_request *sr);


/***************************************************************
 * Media List
 **************************************************************/

/*
 * sip_alg_release_translation() - Release preallocated translation data.
 */
static void sip_alg_release_translation(struct sip_alg_media *m,
		npf_addr_t taddr, in_port_t port)
{

	if (m->m_np)
		npf_nat_free_map(m->m_np, m->m_rl,
				m->m_nat_flags, m->m_vrfid, taddr, htons(port));
}

/*
 * sip_media_alloc() - Allocate a media struct
 */
struct sip_alg_media *sip_media_alloc(npf_session_t *se,
				      struct sip_alg_request *sr, int m_proto)
{
	struct sip_alg_media *m;
	npf_nat_t *nat = npf_session_get_nat(se);

	m = calloc(1, sizeof(struct sip_alg_media));
	if (!m)
		return NULL;

	CDS_INIT_LIST_HEAD(&m->m_node);
	m->m_np = npf_nat_get_policy(nat);
	if (m->m_np) {
		m->m_rl = npf_nat_get_rule(nat);
		m->m_nat_flags = npf_nat_get_map_flags(nat);
		m->m_vrfid = npf_session_get_vrfid(se);
	}

	m->m_proto = m_proto;
	m->m_type = sip_nat_type(sr);
	return m;
}

/*
 * Free a ports struct, if the ports were
 * allocated from a nat pool, return them.
 */
void sip_media_free(void *_m)
{
	struct sip_alg_media *m = _m;

	if (!m)
		return;
	if (m->m_type != sip_nat_inspect) {
		if (m->m_rtp_reserved)
			sip_alg_release_translation(m,
					m->m_trtp_addr, m->m_trtp_port);
		if (m->m_rtcp_reserved)
			sip_alg_release_translation(m,
					m->m_trtcp_addr, m->m_trtcp_port);
	}
	free(m);
}

/* Free dead media structs from the instance */
static void sip_free_dead_media(struct sip_private *sp)
{
	struct sip_alg_media *m;
	struct sip_alg_media *tmp;

	if (!sp)
		return;

	rte_spinlock_lock(&sp->sp_media_lock);
	cds_list_for_each_entry_safe(m, tmp, &sp->sp_dead_media, m_node) {
		cds_list_del(&m->m_node);
		sip_media_free(m);
	}
	rte_spinlock_unlock(&sp->sp_media_lock);
}

/*
 * sip_media_count()
 */
int sip_media_count(struct cds_list_head *h)
{
	struct cds_list_head *p;
	int i = 0;

	cds_list_for_each(p, h)
		i++;

	return i;
}


/***************************************************************
 * SIP Request
 **************************************************************/

/*
 * sip_alg_request_alloc()
 */
struct sip_alg_request *sip_alg_request_alloc(bool init_sip,
					      uint32_t if_idx)
{
	struct sip_alg_request *sr;

	sr = calloc(1, sizeof(struct sip_alg_request));
	if (!sr)
		return NULL;

	CDS_INIT_LIST_HEAD(&sr->sr_media_list_head);
	sr->sr_if_idx = if_idx;

	if (init_sip && osip_message_init(&sr->sr_sip)) {
		free(sr);
		sr = NULL;
	}

	return sr;
}

static void sip_request_free_rcu(struct rcu_head *head)
{
	struct sip_alg_request *sr = caa_container_of(head,
				struct sip_alg_request, sr_rcu_head);
	struct sip_private *sp = sr->sr_sip_alg->na_private;

	/*
	 * Move medias to the instance for deletion
	 * via the sip GC
	 */
	if (sp) {
		rte_spinlock_lock(&sp->sp_media_lock);
		cds_list_splice(&sr->sr_media_list_head, &sp->sp_dead_media);
		rte_spinlock_unlock(&sp->sp_media_lock);
	}

	if (sr->sr_sip)
		osip_message_free(sr->sr_sip);
	if (sr->sr_sdp)
		sdp_message_free(sr->sr_sdp);
	free(sr);
}

/*
 * Free a sip msg, always via RCU.
 */
void
sip_alg_request_free(const struct npf_alg *sip, struct sip_alg_request *sr)
{
	if (sr) {
		sr->sr_sip_alg = sip;
		call_rcu(&sr->sr_rcu_head, sip_request_free_rcu);
	}
}

/*
 * Synchronously free a sip msg.
 * Used when destroying the sip instance.
 */
static void sip_alg_request_free_sync(const struct npf_alg *sip,
		struct sip_alg_request *sr)
{
	if (sr) {
		sr->sr_sip_alg = sip;
		/* Call the rcu free variant synchronously */
		sip_request_free_rcu(&sr->sr_rcu_head);
	}
}

/*
 * sip_parse_reply_path() - Parse the first VIA for reply path parameters.
 */
static int sip_parse_reply_path(struct sip_alg_request *sr, npf_session_t *se)
{
	struct sip_alg_session *ss = npf_alg_session_get_private(se);
	int rc;

	/*
	 * The SIP RFC states that responses are always routed to the
	 * VIA path.  In the case of newer Cicso phones, a high number
	 * sport is used with replies expected on the SIP default port
	 * (5060).  See the inspect and nat routines for more details.
	 *
	 * This means we may need to translate all replies after
	 * receiving the first msg.  So grab the needed addr/port here and
	 * save it in the session handle.
	 */

	if (!ss)
		return -ENOENT;

	rc = 0;
	if (!ss->ss_via_port) {
		osip_via_t *v = NULL;

		ss->ss_ifx = npf_session_get_if_index(se);
		osip_message_get_via(sr->sr_sip, 0, &v);
		if (v) {
			/*
			 * This may fail if a port number is not specified in
			 * VIA string.  This is ok.  When this occurs the
			 * default SIP port is used.
			 */
			ss->ss_via_port = htons(npf_port_from_str(
							osip_via_get_port(v)));

			/*
			 * Note, this my fail if the VIA address is a FQDN, in
			 * which case ss_via_alen will be left at 0.
			 */
			ss->ss_via_alen = 0;
			sip_addr_from_str(osip_via_get_host(v),
					  &ss->ss_via_addr, &ss->ss_via_alen);
			rc = 0;

		} else
			rc = -EINVAL;
	}
	return rc;
}

/*
 * Create and add a tuple from a session, but with a wildcard source port.
 * This tuple is subsequently expired when the SIP Request is expired.
 */
static int sip_alg_add_cntl_tuple(npf_session_t *se, npf_cache_t *npc)
{
	struct npf_alg *sip = npf_alg_session_get_alg(se);
	struct apt_match_key m = { 0 };
	struct apt_tuple *at;
	npf_addr_t dstip;
	uint16_t dport;


	npf_nat_get_trans(npf_session_get_nat(se), &dstip,
			  &dport);

	m.m_proto = IPPROTO_UDP;
	m.m_match = APT_MATCH_ANY_SPORT;
	m.m_ifx = npf_session_get_if_index(se);
	m.m_alen = 4;
	m.m_sport = 0;
	m.m_dport = dport;
	m.m_srcip = npf_cache_dstip(npc);
	m.m_dstip = &dstip;

	at = apt_tuple_create_and_insert(sip->na_ai->ai_apt, &m,
					 npf_alg_get(sip),
					 SIP_ALG_ALT_CNTL_FLOW,
					 NPF_ALG_SIP_NAME, false, true);

	if (!at) {
		npf_alg_put(sip);
		return -EINVAL;
	}

	apt_tuple_set_session(at, se);
	apt_tuple_set_multimatch(at, true);
	npf_alg_session_set_flag(se, SIP_ALG_ALT_TUPLE_SET);

	return 0;
}

/*
 * Add a control tuple if we are using SNAT.  Cisco SIP Gateways send SIP
 * response messages with a (per-call?) random source port.  This sets up a
 * tuple in the reverse direction (c/w with REQUEST) that matches on any
 * source port.
 */
static int sip_alg_manage_cntl(npf_session_t *se, npf_cache_t *npc,
		struct sip_alg_request *sr)
{
	struct sip_alg_session *ss;
	uint32_t flags = npf_alg_session_get_flags(se);

	/* Already added? */
	if (flags & SIP_ALG_ALT_TUPLE_SET)
		return 0;

	/* Only if this is a UDP connection. */
	if (npf_session_get_proto(se)  != IPPROTO_UDP)
		return 0;

	/* Only add from a CNTL session. */
	if (!(flags & SIP_ALG_CNTL_FLOW))
		return 0;

	ss = npf_alg_session_get_private(se);
	if (!ss)
		return 0;

	/* Only in forward direction */
	if (!sip_forw(sr))
		return 0;

	/* Currently only supports SNAT */
	if (!sip_is_snat(sr))
		return 0;

	return sip_alg_add_cntl_tuple(se, npc);
}

/*
 * Add the call id on the session handle private data.
 * We will expire these then the session handle is expired.
 *
 * Note this is non-fatal if we cannot add it.  All it means is
 * that the INVITES will timeout/expire.
 */
static void sip_alg_add_session_call_id(npf_session_t *se,
		struct sip_alg_request *sr)
{
	osip_call_id_t *cid;
	struct sip_alg_session *ss;
	int i;
	size_t sz;

	/* Only CNTL sessions have private data */
	ss = npf_alg_session_get_private(se);
	if (!ss)
		return;

	cid = osip_message_get_call_id(sr->sr_sip);
	if (!cid)
		return;

	/* Only add unique, ignore re-transmissions... */
	for (i = 0; i < ss->ss_call_id_count; i++) {
		if (osip_call_id_match(cid, ss->ss_call_ids[i])
							== OSIP_SUCCESS)
			return;
	}

	sz = sizeof(osip_call_id_t *) * (ss->ss_call_id_count + 1);
	ss->ss_call_ids = realloc(ss->ss_call_ids, sz);
	if (!ss->ss_call_ids)
		return;
	if (osip_call_id_clone(cid, &ss->ss_call_ids[ss->ss_call_id_count]) !=
			OSIP_SUCCESS)
		return;

	ss->ss_call_id_count++;
}

/* Expire all SIP requests on this session handle */
void sip_expire_session_request(npf_session_t *se)
{
	struct sip_alg_session *ss = npf_alg_session_get_private(se);
	struct npf_alg *sip = npf_alg_session_get_alg(se);
	struct sip_alg_request *sr;
	uint32_t if_idx = npf_session_get_if_index(se);
	int i;

	if (!ss)
		return;


	for (i = 0 ; i < ss->ss_call_id_count; i++) {
		sr = sip_request_lookup_by_call_id(sip, if_idx,
				ss->ss_call_ids[i]);
		if (sr)
			sip_request_expire(sr);
		/* free this call id */
		osip_call_id_free(ss->ss_call_ids[i]);
	}

	/* reset so expire/destroy doesn't repeat */
	ss->ss_call_id_count = 0;
	free(ss->ss_call_ids);
	ss->ss_call_ids = NULL;
}

/*
 * Manage all SIP requests.  If appropriate, add
 * an INVITE to the sip hash table.
 *
 * Note that all call-ids for INVITEs are added to the
 * CNTL session handle, and are expired (if they exist)
 * when the session handle is expired.
 *
 * We will also add the ALT CNTL tuple in here, but only
 * once.
 */
int sip_manage_request(npf_session_t *se, npf_cache_t *npc,
		       struct sip_alg_request *sr,
		       struct sip_alg_request *tsr,
		       npf_nat_t *nat, bool *consumed)
{
	struct npf_alg *sip = npf_alg_session_get_alg(se);
	int rc;

	/* Set per-packet info */
	npc->npc_alg_flags = SIP_NPC_REQUEST;

	if (MSG_IS_CANCEL(tsr->sr_sip) || MSG_IS_BYE(tsr->sr_sip)) {
		sip_request_lookup_and_expire(sip, tsr);
		return 0;
	}

	/*
	 * Get the reply path from the VIA header, must be present.  Note that
	 * this call returns an error for Requests in the reverse direction,
	 * hence we handle the CANCEL and BYE Requests above.
	 */
	rc = sip_parse_reply_path(sr, se);
	if (rc)
		return rc;

	/* This will only add the alt cntl tuple once */
	rc = sip_alg_manage_cntl(se, npc, tsr);
	if (rc)
		return rc;

	/* Either parse and add the INVITE, or handle a BYE/etc */
	if (MSG_IS_INVITE(tsr->sr_sip)) {
		if (!sr->sr_sdp)
			return -EINVAL;

		rc = sip_alg_manage_media(se, nat, tsr);
		if (rc)
			return rc;

		rc = sip_alg_add_invite(sip, tsr);
		if (!rc) {
			sip_alg_add_session_call_id(se, tsr);
			*consumed = true;
		}

	}

	return rc;
}


/***************************************************************
 * SIP Request Hash Table
 **************************************************************/

/*
 * sip_alg_hash() -  Create a hash out of the Call-ID number. This is unique.
 *
 * The jhash reads in 4 byte words, so make sure that it doesn't read off
 * the end of allocated mem.
 */
static unsigned long sip_alg_hash(struct sip_request_match *sm)
{
	char *tmp;
	unsigned long hash = 0;

	if (!sm->sm_call_id)
		return hash;

	tmp = osip_call_id_get_number(sm->sm_call_id);
	if (tmp) {
		char __tmp[RTE_ALIGN(strlen(tmp), 4)]
			__rte_aligned(sizeof(uint32_t));

		memcpy(__tmp, tmp, strlen(tmp) + 1);
		hash = rte_jhash(__tmp, strlen(tmp), hash);
	}

	tmp = osip_call_id_get_host(sm->sm_call_id);
	if (tmp) {
		char __tmp[RTE_ALIGN(strlen(tmp), 4)]
			__rte_aligned(sizeof(uint32_t));

		memcpy(__tmp, tmp, strlen(tmp) + 1);
		hash = rte_jhash(__tmp, strlen(tmp), hash);
	}

	return hash ? rte_jhash_1word(sm->sm_if_idx, hash) : 0;
}

/*
 * sip_ht_match() - Match function for hash table
 */
static int sip_ht_match(struct cds_lfht_node *node, const void *key)
{
	const struct sip_alg_request *sr = caa_container_of(node,
			struct sip_alg_request, sr_node);
	const struct sip_request_match *sm = key;

	if (sr->sr_flags & SIP_REQUEST_EXPIRED)
		return 0;

	if (sm->sm_if_idx != sr->sr_if_idx)
		return 0;

	return !osip_call_id_match(osip_message_get_call_id(sr->sr_sip),
			sm->sm_call_id);
}

/*
 * sip_request_lookup_by_call_id() - Lookup by call id.
 */
struct sip_alg_request *
sip_request_lookup_by_call_id(const struct npf_alg *sip, uint32_t if_idx,
			      osip_call_id_t *call_id)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	unsigned long hash;
	struct sip_alg_request *sr;
	struct sip_private *sp;
	struct sip_request_match sm = {
		.sm_call_id = call_id,
		.sm_if_idx = if_idx
	};

	if (!sip)
		return NULL;

	sp = sip->na_private;
	if (!sp)
		return NULL;

	hash = sip_alg_hash(&sm);
	if (!hash)
		return NULL;

	cds_lfht_lookup(sp->sp_ht, hash, sip_ht_match, &sm, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node)
		sr = caa_container_of(node, struct sip_alg_request, sr_node);
	else
		sr = NULL;

	return sr;
}

/*
 * sip_request_lookup() - Lookup a request
 */
struct sip_alg_request *sip_request_lookup(const struct npf_alg *sip,
					   struct sip_alg_request *incoming)
{
	osip_call_id_t *call_id;

	call_id = osip_message_get_call_id(incoming->sr_sip);
	return sip_request_lookup_by_call_id(sip, incoming->sr_if_idx, call_id);
}

/*
 * sip_request_expire() - Expire an invite from the hash table.
 */
void sip_request_expire(struct sip_alg_request *sr)
{
	if (!(sr->sr_flags & SIP_REQUEST_EXPIRED))
		sr->sr_flags |= SIP_REQUEST_EXPIRED;
}

/*
 * sip_request_lookup_and_expire() - Expire an invite from the hash table.
 */
void sip_request_lookup_and_expire(const struct npf_alg *sip,
				   struct sip_alg_request *incoming)
{
	struct sip_alg_request *sr;

	if (incoming) {
		sr = sip_request_lookup(sip, incoming);
		if (sr)
			sip_request_expire(sr);
	}
}

/*
 * sip_alg_expires() - Get an expiration time for this request
 */
static uint64_t sip_alg_expires(struct sip_alg_request *sr)
{
	osip_header_t *expires;
	unsigned long timeout = 0;
	char *end;
	int rc;

	/* Does the request have an expires field? */
	rc = osip_message_get_expires(sr->sr_sip, 0, &expires);
	if (rc >= 0 && expires->hvalue) {
		timeout = strtoul(expires->hvalue, &end, 10);
		if (*end)
			timeout = 0;
	}

	/*
	 * If unset or bogus, or greater than 24h, set a default.
	 */
	if (!timeout || timeout > 84600)
		timeout = SIP_DEFAULT_REQUEST_TIMEOUT;

	return (uint64_t) timeout;
}

/*
 * sip_alg_add_invite() - Add an invite to the hash table.
 */
static int sip_alg_add_invite(const struct npf_alg *sip,
			      struct sip_alg_request *sr)
{
	unsigned long hash;
	struct cds_lfht_node *node;
	struct sip_request_match sm;
	struct sip_private *sp = sip->na_private;

	if (!MSG_IS_INVITE(sr->sr_sip))
		return -EINVAL;

	if (!sp)
		return -EINVAL;

	sm.sm_call_id = osip_message_get_call_id(sr->sr_sip);
	sm.sm_if_idx = sr->sr_if_idx;
	hash = sip_alg_hash(&sm);
	if (!hash)
		return -EINVAL;

	cds_lfht_node_init(&sr->sr_node);
	sr->sr_timeout = sip_alg_expires(sr);
	sr->sr_timeout *= rte_get_timer_hz(); /* to cycles */
	sr->sr_timeout += rte_get_timer_cycles(); /* add current time */

	node = cds_lfht_add_unique(sp->sp_ht, hash, sip_ht_match, &sm,
					&sr->sr_node);
	if (node != &sr->sr_node)
		return -EEXIST;

	return 0;
}

/*
 * sip_delete_request() - Delete an invite from the hash table.
 */
static void sip_delete_request(struct npf_alg *sip,
		struct sip_alg_request *sr)
{
	struct sip_private *sp = sip->na_private;

	if (sr && sp && !cds_lfht_del(sp->sp_ht, &sr->sr_node))
		sip_alg_request_free(sip, sr);
}

void sip_destroy_ht(struct npf_alg *sip)
{
	struct cds_lfht_iter iter;
	struct sip_alg_request *sr;
	struct sip_private *sp = sip->na_private;
	int rc;

	if (!sp)
		return;

	/*
	 * Free each request synchronously - ensures we
	 * sync return APM mappings prior tp APM instance destroy
	 */
	cds_lfht_for_each_entry(sp->sp_ht, &iter, sr, sr_node) {
		if (!cds_lfht_del(sp->sp_ht, &sr->sr_node))
			sip_alg_request_free_sync(sip, sr);
	}

	rcu_read_unlock();
	rc = cds_lfht_destroy(sp->sp_ht, NULL);
	rcu_read_lock();
	if (rc)
		RTE_LOG(ERR, FIREWALL, "ALG: SIP cds_lfht_destroy\n");

	/* Destroy any dead media added during ht destroy */
	sip_free_dead_media(sp);
}

/*
 * Create SIP alg hash table.
 *
 * We manage Invites and responses by using a hash table.  New invites are
 * added to the table, and corresponding responses pull them from the hash
 * table.
 */
int sip_ht_create(struct sip_private *sp)
{
	sp->sp_ht = cds_lfht_new(SIP_HT_INIT, SIP_HT_MIN, SIP_HT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!sp->sp_ht)
		return -EINVAL;

	return 0;
}

static bool sip_ht_expired(uint64_t curr, struct sip_alg_request *sr)
{
	if (sr->sr_flags & SIP_REQUEST_EXPIRED)
		return true;
	if (sr->sr_timeout < curr) {
		sip_request_expire(sr);
		return true;
	}
	return false;
}

/*
 * sip_ht_gc()  - Clean stale entries from the hash table.
 */
void sip_ht_gc(struct npf_alg *sip)
{
	struct cds_lfht_iter iter;
	struct sip_alg_request *sr;
	uint64_t current = rte_get_timer_cycles();
	struct sip_private *sp = sip->na_private;

	if (!sp)
		return;

	/* Always free any medias first */
	sip_free_dead_media(sp);

	cds_lfht_for_each_entry(sp->sp_ht, &iter, sr, sr_node) {
		if (!sip_ht_expired(current, sr))
			continue;

		if (sr->sr_flags & SIP_REQUEST_REMOVING)
			sip_delete_request(sip, sr);
		else
			sr->sr_flags |= SIP_REQUEST_REMOVING;
	}
}

