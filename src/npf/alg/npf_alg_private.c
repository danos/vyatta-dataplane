/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*-
 * Copyright (c) 2010 The NetBSD Foundation, Inc.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * Substantially re-written from the original BSD source by Brocade.
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NPF interface for application level gateways (ALGs).
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <urcu/uatomic.h>
#include <czmq.h>

#include "if_var.h"
#include "json_writer.h"
#include "npf/npf.h"
#include "npf/alg/npf_alg_private.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"
#include "npf/npf_cache.h"
#include "npf/npf_vrf.h"
#include "vplane_log.h"
#include "vrf.h"

struct rte_mbuf;

/* Minimum lifetime for a tuple */
#define NPF_ALG_MIN_TIMEOUT 5

/* Retry count for tuple insertions. */
#define NPF_ALG_RETRY_COUNT	10

/* ALG periodic timer - for GC */
static struct rte_timer alg_timer;
#define ALG_INTERVAL 5

/* A zero addr */
static npf_addr_t zero_addr;

/*
 * We need to store disable requests for ALGs in VRFs not yet seen.
 * So we have a hash for each unseen VRF (by external-id), that
 * points to a list of algs which should be disabled.
 */
struct alg_late_vrf {
	struct alg_late_vrf	*nv_prev;
	struct alg_late_vrf	*nv_next;
	char			nv_key[32];
	uint32_t		nv_vrfid;
	zhash_t			*nv_algs;
};

static struct alg_late_vrf *alg_late_vrfs;
static zhash_t *alg_late_vrf_hash;

static void
npf_alg_late_vrfs_destroy(void)
{
	struct alg_late_vrf *late_vrf;
	struct alg_late_vrf *next_vrf;

	for (late_vrf = alg_late_vrfs; late_vrf; late_vrf = next_vrf) {
		next_vrf = late_vrf->nv_next;
		zhash_destroy(&late_vrf->nv_algs);

		zhash_delete(alg_late_vrf_hash, late_vrf->nv_key);
	}

	alg_late_vrfs = NULL;
}

static struct alg_late_vrf *
npf_alg_late_vrf_find(uint32_t ext_vrfid)
{
	char hash_key[32];
	snprintf(hash_key, sizeof(hash_key), "%x", ext_vrfid);

	return zhash_lookup(alg_late_vrf_hash, hash_key);
}

static struct alg_late_vrf *
npf_alg_late_vrf_add(uint32_t ext_vrfid)
{
	struct alg_late_vrf *late_vrf = malloc(sizeof(*late_vrf));
	if (!late_vrf)
		return NULL;

	late_vrf->nv_vrfid = ext_vrfid;
	late_vrf->nv_algs = zhash_new();
	snprintf(late_vrf->nv_key, sizeof(late_vrf->nv_key), "%x", ext_vrfid);

	late_vrf->nv_prev = NULL;
	late_vrf->nv_next = alg_late_vrfs;
	if (alg_late_vrfs)
		alg_late_vrfs->nv_prev = late_vrf;
	alg_late_vrfs = late_vrf;

	zhash_insert(alg_late_vrf_hash, late_vrf->nv_key, late_vrf);

	return late_vrf;
}

static void
npf_alg_late_vrf_del(struct alg_late_vrf *late_vrf)
{
	if (!late_vrf)
		return;

	if (late_vrf->nv_next)
		late_vrf->nv_next->nv_prev = late_vrf->nv_prev;
	if (late_vrf->nv_prev)
		late_vrf->nv_prev->nv_next = late_vrf->nv_next;
	else
		alg_late_vrfs = late_vrf->nv_next;

	zhash_destroy(&late_vrf->nv_algs);

	zhash_delete(alg_late_vrf_hash, late_vrf->nv_key);
}

static void
npf_alg_late_vrf_set_alg(struct alg_late_vrf *late_vrf, char const *name,
			 bool on)
{
	bool *alg_on = malloc(sizeof(*alg_on));
	if (!alg_on)
		return;

	*alg_on = on;

	int rc = zhash_insert(late_vrf->nv_algs, name, alg_on);
	if (!rc)
		return;	/* Insert ok */

	free(alg_on);

	/* Duplicate - probably will never occur */
	if (rc == -1) {
		alg_on = zhash_lookup(late_vrf->nv_algs, name);
		if (alg_on)
			*alg_on = on;
	}
}

/*
 * ALG tuple hash table.
 *
 * The ALG framework consists of an API, executed at certain points
 * along a packets path throughout NPF, as well as an expected flow
 * tuple database.
 *
 * The tuple database consists of a specialized hash table. A set of
 * hash tables are associated with a IP protocol, each table representing
 * the type of tuple match.  The tables represent 'wildcard' matching of
 * various parts of a possible 6-tuple (proto/interface/addrs/ports).
 *
 * Tuple matching is a perfect candidate for a grouper2 match, however
 * grouper2 does not allow for dynamic sorted-insertion/deletion of rows during
 * runtime.  Matches must be made in a 'most-restrictive'
 * to 'least-restrictive' manner, meaning a match for a 4-5 tuple must
 * be made prior to a match for a 3 tuple within the same protocol.
 *
 * When a packet enters the framework, a lookup into its protocol struct
 * is performed and if a match is made, the packet is forwarded to the
 * alg set in the tuple.  Matches are made against the incoming packet's
 * 'npc' struct directly.
 *
 * When algs register with the framework, they tell the framework which
 * IP protocols they use, and the framework initializes the protocols if
 * needed.  Various ALGs may share the same IP protocols, they are not
 * unique to an ALG.
 *
 * During a disable, delete all alg-specific tuples. We also set
 * a disable flag on the alg struct so future incoming packets are
 * prevented from reaching the alg.  This mechanism also allows packets
 * in-flight at the time of the disable to complete their path through
 * the alg.
 *
 * On an enable, the config system will send down all configuration data
 * to all ALGs and they will re-populate the expected tuples.
 */

#define APT_INIT	32
#define APT_MIN		128
#define APT_MAX		(8*1024)

/* Max number of nodes in a protocol, inserts fail after this */
#define APT_MAX_NODES	(64*1024)

/* For hash table matching */
struct apt_match {
	npf_addr_t	*m_srcip;
	npf_addr_t	*m_dstip;
	uint32_t	m_ifx;
	in_port_t	m_dport;
	in_port_t	m_sport;
	uint16_t	m_flag;
	uint8_t		m_proto;
	uint8_t		m_alen;
};

/* For a walking the protos to reset an alg */
struct alg_walk_params {
	struct npf_alg	*ap_alg;
	bool		ap_all;
};

/* typedef for a list walking function */
typedef void (algwalk_t)(struct alg_ht *ht, struct npf_alg_tuple *, void *);

/* Set ALG private data */
void
npf_alg_session_set_private(struct npf_session *se, void *data)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		sa->sa_private = data;
}

/* Get ALG private data */
void *
npf_alg_session_get_private(const struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_private;
	return NULL;
}

/* Get previous ALG private data, and set new value as one operation */
void *
npf_alg_session_get_and_set_private(const npf_session_t *se, void *data)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);
	if (sa)
		return rcu_xchg_pointer(&(sa->sa_private), data);
	return NULL;
}

/* Test flag */
int
npf_alg_session_test_flag(const struct npf_session *se, uint32_t flag)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_flags & flag;
	return 0;
}

/* Set flag */
void
npf_alg_session_set_flag(struct npf_session *se, uint32_t flag)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		sa->sa_flags |= flag;
}

/* Get all flags */
uint32_t
npf_alg_session_get_flags(const struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_flags;
	return 0;
}

/* Get inspect */
bool
npf_alg_session_inspect(struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_inspect;
	return false;
}

/* Set inspect */
void
npf_alg_session_set_inspect(struct npf_session *se, bool v)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		sa->sa_inspect = v;
}

/* Get the alg from this session */
const struct npf_alg *
npf_alg_session_get_alg(const struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_alg;
	return NULL;
}

/*
 * Allocate ALG data on the session handle
 */
int
npf_alg_session_set_alg(struct npf_session *se, const struct npf_alg *alg)
{

	struct npf_session_alg *sa = malloc(sizeof(struct npf_session_alg));

	if (!sa)
		return -ENOMEM;

	sa->sa_alg = npf_alg_get((struct npf_alg *)alg);
	sa->sa_private = NULL;
	sa->sa_flags = 0;
	sa->sa_inspect = false;

	npf_session_set_alg_ptr(se, sa);

	return 0;
}

/* Get a proto struct */
struct alg_protocol_tuples *alg_get_apt(struct npf_alg_instance *ai,
					uint8_t proto)
{
	if (proto <= NPF_ALG_MAX_PROTOS)
		return rcu_dereference(ai->ai_apts[proto]);
	return NULL;
}

/* Allocate an apt */
static struct alg_protocol_tuples *apt_alloc(void)
{
	struct alg_protocol_tuples *apt =
			zmalloc_aligned(sizeof(struct alg_protocol_tuples));
	if (!apt)
		return NULL;

	rte_spinlock_init(&apt->apt_lock);

	apt->apt_any_sport.a_ht = cds_lfht_new(APT_INIT, APT_MIN, APT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!apt->apt_any_sport.a_ht)
		goto out;

	apt->apt_all.a_ht = cds_lfht_new(APT_INIT, APT_MIN, APT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!apt->apt_all.a_ht)
		goto any_sport;

	apt->apt_port.a_ht = cds_lfht_new(APT_INIT, APT_MIN, APT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!apt->apt_port.a_ht)
		goto all;

	apt->apt_proto.a_ht = cds_lfht_new(APT_INIT, APT_MIN, APT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	if (!apt->apt_proto.a_ht)
		goto port;

	return apt;

port:
	cds_lfht_destroy(apt->apt_port.a_ht, NULL);
all:
	cds_lfht_destroy(apt->apt_all.a_ht, NULL);
any_sport:
	cds_lfht_destroy(apt->apt_any_sport.a_ht, NULL);
out:
	free(apt);
	return NULL;
}

/* Get the specific hash table based on flag */
static struct alg_ht *apt_ht(struct alg_protocol_tuples *apt, uint16_t flag)
{
	struct alg_ht *a;

	switch (flag & NPF_TUPLE_MATCH_MASK) {
	case NPF_TUPLE_MATCH_ANY_SPORT:
		a = &apt->apt_any_sport;
		break;
	case NPF_TUPLE_MATCH_ALL:
		a = &apt->apt_all;
		break;
	case NPF_TUPLE_MATCH_PROTO_PORT:
		a = &apt->apt_port;
		break;
	case NPF_TUPLE_MATCH_PROTO:
		a = &apt->apt_proto;
		break;
	default:
		a = NULL;
	}

	return a;
}

/* Matching function */
static int apt_matcher(struct cds_lfht_node *node, const void *key)
{
	const struct apt_match *m = key;
	struct npf_alg_tuple *nt;

	nt = caa_container_of(node, struct npf_alg_tuple, nt_node);

	/* Never return if in expired state */
	if (nt->nt_flags & NPF_TUPLE_EXPIRED)
		return 0;

	/* interface index, optional */
	if (nt->nt_ifx && (nt->nt_ifx != m->m_ifx))
		return 0;

	/* flag */
	if (!(nt->nt_flags & m->m_flag))
		return 0;

	switch (m->m_flag) {
	case NPF_TUPLE_MATCH_ANY_SPORT:
	case NPF_TUPLE_MATCH_ALL:
		if (m->m_alen != nt->nt_alen)
			return 0;
		if (m->m_flag == NPF_TUPLE_MATCH_ALL)
			if (nt->nt_sport != m->m_sport)
				return 0;
		if (nt->nt_dport != m->m_dport)
			return 0;
		if (memcmp(&nt->nt_srcip, m->m_srcip, m->m_alen))
			return 0;
		if (memcmp(&nt->nt_dstip, m->m_dstip, m->m_alen))
			return 0;
		break;
	case NPF_TUPLE_MATCH_PROTO_PORT:
		if (nt->nt_dport != m->m_dport)
			return 0;
		break;
	case NPF_TUPLE_MATCH_PROTO:
		if (nt->nt_proto != m->m_proto)
			return 0;
		break;
	default:
		return 0; /* wtf?? */
	}

	return 1;
}

/* Hash table node count */
static inline int64_t apt_ht_count(struct alg_ht *a)
{
	return rte_atomic64_read(&a->a_cnt);
}

/* Protocol node count */
static int64_t apt_count(struct alg_protocol_tuples *apt)
{
	int64_t count = apt_ht_count(&apt->apt_all);

	count += apt_ht_count(&apt->apt_port);
	count += apt_ht_count(&apt->apt_proto);
	return count;
}

/* Hash generator */
static unsigned long apt_ht_hash(struct apt_match *m)
{
	uint32_t hash;
	const uint32_t *src;
	const uint32_t *dst;

	switch (m->m_flag) {
	case NPF_TUPLE_MATCH_PROTO:
		hash = m->m_proto;
		break;
	case NPF_TUPLE_MATCH_PROTO_PORT:
		hash = (m->m_dport << 16) | m->m_proto;
		break;
	case NPF_TUPLE_MATCH_ANY_SPORT: /* Fall through */
	case NPF_TUPLE_MATCH_ALL:
		src = m->m_srcip->s6_addr32;
		dst = m->m_dstip->s6_addr32;
		/* Don't use sport, it can be wildcarded */
		hash = rte_jhash_2words(m->m_dport, m->m_proto, 0);

		if (m->m_alen == 4)
			return rte_jhash_2words(src[0], dst[0], hash);

		const uint32_t sz = m->m_alen >> 2;

		hash = rte_jhash_32b(src, sz, hash);
		hash = rte_jhash_32b(dst, sz, hash);
		break;
	default:
		hash = 0;
		break;
	}

	assert(hash);

	return (unsigned long) hash;
}

/* Search a list for a match */
static struct npf_alg_tuple *apt_search_ht(struct alg_ht *a,
						struct apt_match *m)
{
	struct npf_alg_tuple *nt;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(a->a_ht, apt_ht_hash(m), apt_matcher, m, &iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node)
		nt = caa_container_of(node, struct npf_alg_tuple, nt_node);
	else
		nt = NULL;

	return nt;
}

/* Fill a match struct based on npc */
static void alg_fill_match(npf_cache_t *npc, uint8_t proto,
		uint32_t ifx, struct apt_match *m)
{
	/* Fill in the match struct */
	m->m_ifx = ifx;
	m->m_proto = proto;
	m->m_srcip = npf_cache_srcip(npc);
	m->m_dstip = npf_cache_dstip(npc);
	m->m_alen = npc->npc_alen;

	/* Get ports if applicable */
	if (npf_iscached(npc, NPC_L4PORTS)) {
		struct npf_ports *ports = &npc->npc_l4.ports;

		m->m_dport = ports->d_port;
		m->m_sport = ports->s_port;
	} else {
		m->m_dport = 0;
		m->m_sport = 0;
	}
}

/* lookup by npc */
static struct npf_alg_tuple *alg_lookup(struct npf_alg_instance *ai,
					npf_cache_t *npc, uint32_t ifx)
{
	struct alg_protocol_tuples *apt;
	struct npf_alg_tuple *nt;
	struct apt_match m;
	uint8_t proto = npf_cache_ipproto(npc);

	apt = alg_get_apt(ai, proto);
	if (!apt)
		return NULL;

	if (!apt_ht_count(&apt->apt_port) && !apt_ht_count(&apt->apt_proto))
		return NULL;

	alg_fill_match(npc, proto, ifx, &m);

	/* Search on dport */
	m.m_flag = NPF_TUPLE_MATCH_PROTO_PORT;
	nt = apt_search_ht(&apt->apt_port, &m);
	if (nt)
		return nt;

	/* Search on proto */
	m.m_flag = NPF_TUPLE_MATCH_PROTO;
	nt = apt_search_ht(&apt->apt_proto, &m);

	return nt;
}

/* Lookup by tuple */
struct npf_alg_tuple *
npf_alg_tuple_lookup(struct npf_alg_instance *ai, struct npf_alg_tuple *nt)
{
	struct alg_protocol_tuples *apt;
	struct apt_match m;
	struct alg_ht *a;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct npf_alg_tuple *result = NULL;

	apt = alg_get_apt(ai, nt->nt_proto);
	if (!apt)
		return NULL;

	/* Fill in the match struct */
	m.m_flag = (nt->nt_flags & NPF_TUPLE_MATCH_MASK);
	m.m_ifx = nt->nt_ifx;
	m.m_proto = nt->nt_proto;
	m.m_dport = nt->nt_dport;
	m.m_sport = nt->nt_sport;
	m.m_srcip = &nt->nt_srcip;
	m.m_dstip = &nt->nt_dstip;
	m.m_alen = nt->nt_alen;

	a = apt_ht(apt, nt->nt_flags);
	if (a) {
		cds_lfht_lookup(a->a_ht, apt_ht_hash(&m), apt_matcher,
				&m, &iter);
		node = cds_lfht_iter_get_node(&iter);
		if (node)  {
			result = caa_container_of(node, struct npf_alg_tuple,
						  nt_node);
		}
	}

	return result;
}

/* Lookup by npc */
struct npf_alg_tuple *alg_lookup_npc(struct npf_alg_instance *ai,
				     npf_cache_t *npc, uint32_t ifx)
{
	struct npf_alg_tuple *nt = npf_cache_get_tuple(npc);

	if (!npf_iscached(npc, NPC_ALG_TLUP)) {
		npc->npc_info |= NPC_ALG_TLUP;
		nt = alg_lookup(ai, npc, ifx);
		npf_cache_set_tuple(npc, (void *)nt);
	}
	return nt;
}

/* Free tuple */
static void apt_free_tuple(struct rcu_head *head)
{
	struct npf_alg_tuple *nt = caa_container_of(head,
					struct npf_alg_tuple, nt_rcu_head);
	free(nt);
}


static void apt_release_node_nat(struct npf_alg_tuple *nt)
{
	npf_nat_t *nat;
	npf_natpolicy_t *np;
	npf_rule_t *rl;

	if (nt->nt_nat) {
		nat = npf_session_get_nat(nt->nt_se);
		np = npf_nat_get_policy(nat);
		rl = npf_nat_get_rule(nat);
		npf_nat_free_map(np, rl, NPF_NAT_MAP_PORT, nt->nt_nat->an_vrfid,
				 nt->nt_nat->an_taddr, nt->nt_nat->an_tport);
	}
	free(nt->nt_nat);
}

static void apt_release_node(struct npf_alg_tuple *nt)
{
	if (nt) {
		if (nt->nt_data && nt->nt_reap)
			nt->nt_reap(nt->nt_data);
		if (nt->nt_nat)
			apt_release_node_nat(nt);
		call_rcu(&nt->nt_rcu_head, apt_free_tuple);
	}
}

/* Set tuple expired */
void apt_expire_tuple(struct npf_alg_tuple *nt)
{
	if (nt) {
		struct alg_ht *a = rcu_dereference(nt->nt_aht);
		uint16_t exp = nt->nt_flags & ~NPF_TUPLE_EXPIRED;

		/* Only expire once */
		if (a && rte_atomic16_cmpset(&nt->nt_flags, exp,
					(exp | NPF_TUPLE_EXPIRED)))
			rte_atomic64_dec(&a->a_cnt);
	}
}

/* internal delete tuple */
static void apt_del_tuple(struct alg_ht *a, struct npf_alg_tuple *nt)
{
	if (a && !cds_lfht_del(a->a_ht, &nt->nt_node)) {
		apt_expire_tuple(nt);
		apt_release_node(nt);
	}
}

/* internal tuple insert */
static int apt_insert_tuple(struct npf_alg_instance *ai,
			struct npf_alg_tuple *nt, bool addreplace)
{
	struct alg_protocol_tuples *apt;
	struct cds_lfht_node *node;
	struct apt_match m;
	int rc;
	int retry;
	struct alg_ht *a;

	/* Proto exists? */
	apt = alg_get_apt(ai, nt->nt_proto);
	if (!apt)
		return -ENOENT;

	/* At max? */
	if (unlikely(apt_count(apt) >= APT_MAX_NODES)) {
		if (net_ratelimit())
			RTE_LOG(DEBUG, FIREWALL,
					"ALG:  Expected flow table full\n");
		return -ENOSPC;
	}

	/* Fill in the match struct */
	m.m_flag = (nt->nt_flags & NPF_TUPLE_MATCH_MASK);
	m.m_ifx = nt->nt_ifx;
	m.m_proto = nt->nt_proto;
	m.m_dport = nt->nt_dport;
	m.m_sport = nt->nt_sport;
	m.m_srcip = &nt->nt_srcip;
	m.m_dstip = &nt->nt_dstip;
	m.m_alen = nt->nt_alen;

	cds_lfht_node_init(&nt->nt_node);

	rc = -ENOENT;
	a = apt_ht(apt, nt->nt_flags);
	if (!a)
		return rc;

	/*
	 * If 'addreplace', then the alg is attemping to replace an
	 * existing tuple.  Do this by expiring the existing tuple and
	 * retrying for a limited number of times.
	 */
	rc = -EEXIST;
	retry = NPF_ALG_RETRY_COUNT;
	while (retry--) {
		node = cds_lfht_add_unique(a->a_ht, apt_ht_hash(&m),
					apt_matcher, &m, &nt->nt_node);
		if (node == &nt->nt_node) {
			rc = 0;
			break;
		}

		/* Expire if necessary */
		if (addreplace)
			apt_expire_tuple(caa_container_of(node,
						struct npf_alg_tuple, nt_node));
		else
			break;
	}

	if (!rc) {
		rte_atomic64_inc(&a->a_cnt);
		rcu_assign_pointer(nt->nt_aht, a);
	}

	return rc;
}

/* walk a proto list and apply 'func' */
static void apt_walk_proto(struct alg_protocol_tuples *apt, algwalk_t func,
			   void *data)
{
	struct cds_lfht_iter iter;
	struct npf_alg_tuple *nt;

	if (!apt)
		return;

	cds_lfht_for_each_entry(apt->apt_any_sport.a_ht, &iter, nt, nt_node) {
		func(&apt->apt_any_sport, nt, data);
	}

	cds_lfht_for_each_entry(apt->apt_all.a_ht, &iter, nt, nt_node) {
		func(&apt->apt_all, nt, data);
	}

	cds_lfht_for_each_entry(apt->apt_port.a_ht, &iter, nt, nt_node) {
		func(&apt->apt_port, nt, data);
	}

	cds_lfht_for_each_entry(apt->apt_proto.a_ht, &iter, nt, nt_node) {
		func(&apt->apt_proto, nt, data);
	}
}

/* reset tuples */
static void apt_reset_tuples(struct alg_ht *a, struct npf_alg_tuple *nt,
					void *data)
{
	struct alg_walk_params *ap = data;

	if (nt->nt_alg != ap->ap_alg)
		return;

	/* delete all KEEP tuples, optionally delete ALL tuples */
	if (nt->nt_flags & NPF_TUPLE_KEEP)
		apt_del_tuple(a, nt);
	else if (ap->ap_all)
		apt_expire_tuple(nt);
}

/* delete all tuples */
static void alg_del_tuples_all(struct alg_ht *a, struct npf_alg_tuple *nt,
					void *data __unused)
{
	apt_del_tuple(a, nt);
}

/* Destroy all apt hash tables */
void alg_destroy_apts(struct npf_alg_instance *ai)
{
	int i;

	for (i = 0; i < NPF_ALG_MAX_PROTOS; i++) {
		apt_walk_proto(ai->ai_apts[i], alg_del_tuples_all, NULL);
		if (ai->ai_apts[i]) {
			cds_lfht_destroy(ai->ai_apts[i]->apt_any_sport.a_ht,
					NULL);
			cds_lfht_destroy(ai->ai_apts[i]->apt_all.a_ht, NULL);
			cds_lfht_destroy(ai->ai_apts[i]->apt_port.a_ht, NULL);
			cds_lfht_destroy(ai->ai_apts[i]->apt_proto.a_ht, NULL);

			ai->ai_apts[i]->apt_any_sport.a_ht = NULL;
			ai->ai_apts[i]->apt_all.a_ht = NULL;
			ai->ai_apts[i]->apt_port.a_ht = NULL;
			ai->ai_apts[i]->apt_proto.a_ht = NULL;
		}
		free(ai->ai_apts[i]);
	}
}

/*
 * Expire tuples containing this session.
 *
 * Its possible that the alg vrf instance has been deleted, in which case
 * alg->na_ai will be NULL.  Just return in these cases.
 */
static void alg_expire_se_tuples(npf_session_t *se, uint8_t proto)
{
	const struct npf_alg *alg = npf_alg_session_get_alg(se);
	struct alg_protocol_tuples *apt;
	struct cds_lfht_iter iter;
	struct npf_alg_tuple *nt;

	if (!proto || !alg->na_ai)
		return;

	apt = alg_get_apt(alg->na_ai, proto);
	if (!apt)
		return;

	/* Walk the 'all' hash table and expire matching tuples */
	if (apt_ht_count(&apt->apt_all) && apt->apt_all.a_ht) {
		cds_lfht_for_each_entry(apt->apt_all.a_ht,
					&iter, nt, nt_node) {
			if (nt->nt_se == se)
				apt_expire_tuple(nt);
		}
	}

	/* Now the 'any_sport' hash table and expire matching tuples */
	if (apt_ht_count(&apt->apt_any_sport) && apt->apt_any_sport.a_ht) {
		cds_lfht_for_each_entry(apt->apt_any_sport.a_ht,
					&iter, nt, nt_node) {
			if (nt->nt_se == se)
				apt_expire_tuple(nt);
		}
	}
}

/* expire tuples by session */
void alg_expire_session_tuples(const struct npf_alg *alg, npf_session_t *se)
{
	int i;
	int n;

	/*
	 * Walk the configs to get all protocols this alg
	 * references.
	 */
	for (i = 0; i < alg->na_num_configs; i++) {
		const struct npf_alg_config *ac = &alg->na_configs[i];

		for (n = 0; n < ac->ac_item_cnt; n++)
			alg_expire_se_tuples(se, ac->ac_items[n].ci_proto);
	}
}

/* Dump tuple */
static void apt_tuple_dump(struct alg_ht *a __unused,
			   struct npf_alg_tuple *nt, void *data)
{
	json_writer_t *json = data;
	int family = 0;
	char buf[INET6_ADDRSTRLEN];

	/* Only display initialized fields */

	jsonw_start_object(json);
	jsonw_string_field(json, "alg", nt->nt_alg->na_ops->name);

	if (nt->nt_exp_ts)
		jsonw_uint_field(json, "timestamp", nt->nt_exp_ts);
	if (nt->nt_proto)
		jsonw_uint_field(json, "protocol", nt->nt_proto);
	if (nt->nt_se)
		jsonw_bool_field(json, "session", true);
	if (nt->nt_ifx)
		jsonw_uint_field(json, "if_index", nt->nt_ifx);
	if (nt->nt_alg_flags)
		jsonw_uint_field(json, "alg_flags", nt->nt_alg_flags);

	if (nt->nt_timeout)
		jsonw_uint_field(json, "timeout", nt->nt_timeout);
	if (nt->nt_flags)
		jsonw_uint_field(json, "flags", nt->nt_flags);

	if (nt->nt_sport)
		jsonw_uint_field(json, "sport", ntohs(nt->nt_sport));
	if (nt->nt_dport)
		jsonw_uint_field(json, "dport", ntohs(nt->nt_dport));

	switch (nt->nt_alen) {
	case 4:
		family = AF_INET;
		break;
	case 16:
		family = AF_INET6;
		break;
	default:
		family = 0;

	}

	if (family) {
		inet_ntop(family, &nt->nt_srcip, buf, sizeof(buf));
		jsonw_string_field(json, "srcip", buf);
		inet_ntop(family, &nt->nt_dstip, buf, sizeof(buf));
		jsonw_string_field(json, "dstip", buf);
		jsonw_uint_field(json, "alen", nt->nt_alen);
	}

	if (nt->nt_data)
		jsonw_bool_field(json, "tuple_data", true);
	if (nt->nt_reap)
		jsonw_bool_field(json, "reap", true);
	jsonw_end_object(json);
}

/*
 * A tuples' NPF_TUPLE_EXPIRED may be set in three ways:
 *  1. When the current time exceeds the tuples timestamp (non-KEEP tuples), or
 *  2. When a tuple is deleted unconditionally (e.g. KEEP tuple is deleted via
 *     config)
 *  3. Manually by an alg.
 */
static bool apt_tuple_is_expired(uint64_t current, struct npf_alg_tuple *nt)
{
	if (nt->nt_flags & NPF_TUPLE_EXPIRED)
		return true;

	/* Do not timeout KEEP tuples */
	if (nt->nt_flags & NPF_TUPLE_KEEP)
		return false;

	if (current > nt->nt_exp_ts) {
		apt_expire_tuple(nt);
		return true;
	}
	return false;
}

/* tuple garbage collection */
static void apt_gc(struct alg_ht *a, struct npf_alg_tuple *nt,
		   void *data)
{
	uint64_t current = *((uint64_t *) data);

	/*
	 * Manually expired or timed out?
	 *
	 * Two passes to reclaim.  First sets removing flag
	 */
	if (apt_tuple_is_expired(current, nt)) {
		if (nt->nt_flags & NPF_TUPLE_REMOVING)
			apt_del_tuple(a, nt);
		else
			nt->nt_flags |= NPF_TUPLE_REMOVING;
	}
}

/* Flush all non-config tuples - Expressly for UT's. */
static void apt_flush_tuples(struct alg_ht *a, struct npf_alg_tuple *nt,
			void *data __unused)
{
	/*
	 * N.B. MULTIMATCH tuples have a dependency on a
	 * session handle, which are flushed after
	 * algs in the UTs.  So expire them now.
	 */
	if ((nt->nt_flags & NPF_TUPLE_MULTIMATCH) ||
			!(nt->nt_flags & NPF_TUPLE_KEEP) ||
			(nt->nt_flags & NPF_TUPLE_EXPIRED))
		apt_del_tuple(a, nt);
}

/* Purge all tuples - Used during instance destroy */
static void apt_tuple_purge(struct alg_ht *a, struct npf_alg_tuple *nt,
			void *data __unused)
{
	apt_del_tuple(a, nt);
}

/* Get alg from name */
static struct npf_alg *alg_name_to_alg(struct npf_alg_instance *ai,
					const char *name)
{
	if (ai->ai_ftp && !strcmp(ai->ai_ftp->na_ops->name, name))
		return ai->ai_ftp;
	else if (ai->ai_tftp && !strcmp(ai->ai_tftp->na_ops->name, name))
		return ai->ai_tftp;
	else if (ai->ai_sip && !strcmp(ai->ai_sip->na_ops->name, name))
		return ai->ai_sip;
	else if (ai->ai_rpc && !strcmp(ai->ai_rpc->na_ops->name, name))
		return ai->ai_rpc;
	return NULL;
}

/* Periodic delete expired tuples */
static void apt_worker(struct npf_alg_instance *ai)
{
	uint8_t i;
	struct alg_protocol_tuples *apt;
	uint64_t current = get_time_uptime();

	for (i = 0; i <= NPF_ALG_MAX_PROTOS; i++) {
		apt = rcu_dereference(ai->ai_apts[i]);
		apt_walk_proto(apt, apt_gc, &current);
	}
}

/* Sanity check on tuples. */
static int alg_tuple_sanity(struct npf_alg_tuple *nt)
{
	/* No alg? */
	if (!nt->nt_alg)
		return -EINVAL;

	/* Unsupported proto */
	if (nt->nt_proto > NPF_ALG_MAX_PROTOS)
		return -EINVAL;

	/*
	 * start with most restrictive first
	 */

	switch (nt->nt_flags & NPF_TUPLE_MATCH_MASK) {
	case NPF_TUPLE_MATCH_ANY_SPORT:
	case NPF_TUPLE_MATCH_ALL:
		if (!nt->nt_ifx)
			return -EINVAL;
		if (!nt->nt_alen)
			return -EINVAL;
		if (!memcmp(&nt->nt_srcip, &zero_addr, nt->nt_alen))
			return -EINVAL;
		if (!memcmp(&nt->nt_dstip, &zero_addr, nt->nt_alen))
			return -EINVAL;
		if (!nt->nt_dport)
			return -EINVAL;
		break;
	case NPF_TUPLE_MATCH_PROTO_PORT:
		if (!nt->nt_dport)
			return -EINVAL;
		break;
	case NPF_TUPLE_MATCH_PROTO:
		break;
	default:
		/* Too many flags set, can only be one of the above */
		return -EINVAL;
	}

	/* non-keep needs a reasonable timeout */
	if (!(nt->nt_flags & NPF_TUPLE_KEEP) &&
					nt->nt_timeout < NPF_ALG_MIN_TIMEOUT)
		nt->nt_timeout = NPF_ALG_MIN_TIMEOUT;

	return 0;
}

/* Expire a tuple */
void npf_alg_tuple_expire(struct npf_alg_tuple *nt)
{
	apt_expire_tuple(nt);
}

/*
 * Allocate a tuple
 */
struct npf_alg_tuple *npf_alg_tuple_alloc(void)
{
	struct npf_alg_tuple *nt = zmalloc_aligned(
					sizeof(struct npf_alg_tuple));
	return nt;
}

/*
 * free a tuple - Must NOT be inserted in the hash
 */
void npf_alg_tuple_free(struct npf_alg_tuple *nt)
{
	free(nt);
}

/* link two tuples together */
void npf_alg_tuple_pair(struct npf_alg_tuple *nt1, struct npf_alg_tuple *nt2)
{
	nt1->nt_paired = nt2;
	nt2->nt_paired = nt1;
}

/* Unpair a set of tuples */
void npf_alg_tuple_unpair(struct npf_alg_tuple *nt)
{
	struct npf_alg_tuple *nt2 = nt->nt_paired;

	nt->nt_paired = NULL;
	if (nt2)
		nt2->nt_paired = NULL;
}

/* Expire a set of paired tuples */
void npf_alg_tuple_expire_pair(struct npf_alg_tuple *nt)
{
	struct npf_alg_tuple *nt2 = nt->nt_paired;

	apt_expire_tuple(nt);
	nt->nt_paired = NULL;
	apt_expire_tuple(nt2);
	if (nt2)
		nt2->nt_paired = NULL;
}

/*
 * Insert a tuple into the hash table.
 */
int npf_alg_tuple_insert(struct npf_alg_instance *ai, struct npf_alg_tuple *nt)
{
	/* Sanity check the tuple */
	if (alg_tuple_sanity(nt))
		return -EINVAL;

	if (!(nt->nt_flags & NPF_TUPLE_KEEP))
		nt->nt_exp_ts = get_time_uptime() + nt->nt_timeout;

	return apt_insert_tuple(ai, nt, false);
}

/* tuple add/replace */
int npf_alg_tuple_add_replace(struct npf_alg_instance *ai,
		struct npf_alg_tuple *nt)
{
	/* Sanity check the tuple */
	if (alg_tuple_sanity(nt))
		return -EINVAL;

	if (!(nt->nt_flags & NPF_TUPLE_KEEP))
		nt->nt_exp_ts = get_time_uptime() + nt->nt_timeout;

	return apt_insert_tuple(ai, nt, true);
}

/* Delete a tuple, unconditionally */
static int npf_alg_tuple_delete(struct npf_alg_instance *ai,
				struct npf_alg_tuple *nt)
{
	struct alg_protocol_tuples *apt;
	struct apt_match m;
	struct alg_ht *a;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	int rc;

	apt = alg_get_apt(ai, nt->nt_proto);
	if (!apt)
		return -ENOENT;

	/* Fill in the match struct */
	m.m_flag = (nt->nt_flags & NPF_TUPLE_MATCH_MASK);
	m.m_ifx = nt->nt_ifx;
	m.m_proto = nt->nt_proto;
	m.m_dport = nt->nt_dport;
	m.m_sport = nt->nt_sport;
	m.m_srcip = &nt->nt_srcip;
	m.m_dstip = &nt->nt_dstip;
	m.m_alen = nt->nt_alen;

	rc = -ENOENT;
	a = apt_ht(apt, nt->nt_flags);
	if (a) {
		cds_lfht_lookup(a->a_ht, apt_ht_hash(&m), apt_matcher,
							&m, &iter);
		node = cds_lfht_iter_get_node(&iter);
		if (node)  {
			nt = caa_container_of(node, struct npf_alg_tuple,
								nt_node);
			apt_expire_tuple(nt);
			rc = 0;
		}
	}

	return rc;
}

static int alg_add_port(struct npf_alg *na,
		const struct npf_alg_config_item *ci)
{
	struct npf_alg_tuple *nt = npf_alg_tuple_alloc();
	int rc = -ENOMEM;

	if (nt) {
		nt->nt_proto = ci->ci_proto;
		nt->nt_dport = htons(ci->ci_datum);
		nt->nt_alg_flags = ci->ci_alg_flags;
		nt->nt_flags = ci->ci_flags;
		nt->nt_alg = na;
		rc = npf_alg_tuple_insert(na->na_ai, nt);
		if (rc)
			npf_alg_tuple_free(nt);
	}
	return rc;
}

static int alg_delete_port(struct npf_alg *na,
		const struct npf_alg_config_item *ci)
{
	struct npf_alg_tuple nt;

	nt.nt_proto = ci->ci_proto;
	nt.nt_dport = htons(ci->ci_datum);
	nt.nt_flags = ci->ci_flags;
	nt.nt_alg = na;
	nt.nt_ifx = 0;
	nt.nt_sport = 0;
	nt.nt_alen = 0;
	return npf_alg_tuple_delete(na->na_ai, &nt);
}

int npf_alg_port_handler(struct npf_alg *na, int op,
		const struct npf_alg_config_item *ci)
{
	int rc;

	switch (op) {
	case NPF_ALG_CONFIG_SET:
		rc = alg_add_port(na, ci);
		break;
	case NPF_ALG_CONFIG_DELETE:
		rc = alg_delete_port(na, ci);
		break;
	default:
		return -EINVAL;
	}
	return rc;
}

/* Manage the default config as a unit */
static int alg_manage_config(struct npf_alg *na, int op,
		struct npf_alg_config *ac)
{
	int rc = 0;
	int i;

	if ((op == NPF_ALG_CONFIG_SET) && ac->ac_default_set)
		return 0;

	if ((op == NPF_ALG_CONFIG_DELETE) && !ac->ac_default_set)
		return 0;

	for (i = 0; i < ac->ac_item_cnt; i++) {
		/* Handler for default config is optional */
		if (ac->ac_handler) {
			rc = ac->ac_handler(na, op, &ac->ac_items[i]);
			if (rc)
				return rc;
		}
	}

	/* Keep track of whether the default config is installed */
	if (!rc)
		ac->ac_default_set = (op == NPF_ALG_CONFIG_SET) ? true : false;

	return rc;
}

/* Called to reset an alg to a known state. */
static int alg_reset_alg(struct npf_alg *alg, bool hard)
{
	struct alg_walk_params ap;
	struct alg_protocol_tuples *apt;
	uint8_t i;
	int rc;

	/* First let the alg do whatever it needs */
	if (alg_has_op(alg, reset)) {
		rc = alg->na_ops->reset(alg, hard);
		if (rc)
			return rc;
	}

	/*
	 * Delete all KEEP tuples and if 'hard' is set,
	 * all tuples for this alg
	 */
	ap.ap_alg = alg;
	ap.ap_all = hard;
	for (i = 0; i < NPF_ALG_MAX_PROTOS; i++) {
		apt = alg_get_apt(alg->na_ai, i);
		apt_walk_proto(apt, apt_reset_tuples, &ap);
	}

	/* Now reset the state of the configs and re-install. */
	for (i = 0; i < alg->na_num_configs; i++) {
		struct npf_alg_config *ac = &alg->na_configs[i];

		ac->ac_cli_refcnt = 0;
		ac->ac_default_set = false;
		rc = alg_manage_config(alg, NPF_ALG_CONFIG_SET, ac);
	}

	/* Now reset state to default of enabled */
	if (!alg->na_enabled)
		alg->na_enabled = true;

	return rc;
}


static void alg_reset_alg_module(struct npf_alg *alg, bool hard)
{
	int rc;

	if (!alg)
		rte_panic("reset called on null alg");

	rc = alg_reset_alg(alg, hard);
	if (rc)
		RTE_LOG(ERR, FIREWALL, "ALG: Reset: %s hard: %s rc: %d\n",
				alg->na_ops->name,
				hard ? "true" : "false", -rc);
}

/* Reset a specific alg instance */
void
alg_reset_instance(struct vrf *vrf, struct npf_alg_instance *ai, bool hard)
{

	uint32_t count;

	if (!ai)
		return;

	/* 'ai' may be freed */
	count = ai->ai_ref_count;
	ai->ai_ref_count = 0;

	alg_reset_alg_module(ai->ai_ftp, hard);
	alg_reset_alg_module(ai->ai_tftp, hard);
	alg_reset_alg_module(ai->ai_sip, hard);
	alg_reset_alg_module(ai->ai_rpc, hard);

	while (count--)
		vrf_delete_by_ptr(vrf);
}

/* Called by algs to manage a CLI config item */
int npf_alg_manage_config_item(struct npf_alg *na, struct npf_alg_config *ac,
		int op, struct npf_alg_config_item *ci)
{
	int rc;

	/* make sure the default config is deleted */
	if (op == NPF_ALG_CONFIG_SET) {
		rc = alg_manage_config(na, NPF_ALG_CONFIG_DELETE, ac);
		if (rc)
			return rc;
	}

	/* There must be a config item handler */
	rc = ac->ac_handler(na, op, ci);
	if (rc)
		goto reset;

	/*  manage ref counts. */
	switch (op) {
	case NPF_ALG_CONFIG_SET:
		ac->ac_cli_refcnt++;
		break;
	case NPF_ALG_CONFIG_DELETE:
		ac->ac_cli_refcnt--;
		/* Restore default config? */
		if (!ac->ac_cli_refcnt)
			(void) alg_manage_config(na, NPF_ALG_CONFIG_SET, ac);
		break;
	}

	return rc;

reset:
	/*
	 * Best attempt to restore default config.
	 * But only if no other CLI config is present.
	 */
	if ((op == NPF_ALG_CONFIG_SET) && !ac->ac_cli_refcnt)
		(void) alg_manage_config(na, NPF_ALG_CONFIG_SET, ac);

	return rc;
}

/* register protocols */
static int alg_register_protos(struct npf_alg *na,
		const struct npf_alg_config *ac)
{
	struct alg_protocol_tuples *apt;
	uint8_t proto;
	int i;

	for (i = 0; i < ac->ac_item_cnt; i++) {
		proto = ac->ac_items[i].ci_proto;
		if (!proto) /* Non-protocol config item */
			continue;
		if (proto >= NPF_ALG_MAX_PROTOS)
			rte_panic("ALG unsupported protocol %u\n", proto);
		apt = alg_get_apt(na->na_ai, proto);
		if (!apt) {
			rcu_assign_pointer(na->na_ai->ai_apts[proto],
					apt_alloc());
			if (!na->na_ai->ai_apts[proto])
				return -ENOMEM;
		}
	}
	return 0;
}

/* Free a reserved translation */
int npf_alg_free_translation(npf_session_t *se, npf_addr_t *addr,
		in_port_t port)
{
	npf_nat_t *nat = npf_session_get_nat(se);
	npf_natpolicy_t *np = npf_nat_get_policy(nat);
	npf_rule_t *rl = npf_nat_get_rule(nat);
	uint32_t map_flags;
	vrfid_t vrfid = npf_session_get_vrfid(se);

	/* Currently, all algs use a mapped port */
	map_flags = NPF_NAT_MAP_PORT;

	return npf_nat_free_map(np, rl, map_flags, vrfid, *addr, port);
}

/* Reserve translations for an alg.  */
int npf_alg_reserve_translations(npf_session_t *parent, int nr_ports,
		bool start_even, uint8_t alen,
		npf_addr_t *addr, in_port_t *port)
{
	npf_nat_t *pnat = npf_session_get_nat(parent);
	npf_natpolicy_t *np = npf_nat_get_policy(pnat);
	npf_rule_t *rl = npf_nat_get_rule(pnat);
	in_port_t tmp;
	npf_addr_t paddr;
	uint32_t nat_flags;
	vrfid_t vrfid = npf_session_get_vrfid(parent);
	int i;
	int rc;

	/* Currently, all algs need a mapped port */
	nat_flags = NPF_NAT_MAP_PORT;

	/* Start on even boundary? */
	if (start_even)
		nat_flags |= NPF_NAT_MAP_EVEN_PORT;

	/* allocate from parent translation addr */
	npf_nat_get_trans(pnat, addr, &tmp);
	paddr = *addr;

	rc = npf_nat_alloc_map(np, rl, nat_flags, vrfid, addr,
			port, nr_ports);
	if (rc)
		return rc;

	/*
	 * Ensure that the translations come from the same
	 * (parent) translation address.
	 */
	if (memcmp(addr, &paddr, alen)) {
		tmp = ntohs(*port);
		for (i = 0; i < nr_ports; i++)
			npf_nat_free_map(np, rl, nat_flags, vrfid,
					*addr, htons(tmp + i));
		return -ENOSPC;
	}

	return 0;
}

/*
 * Create and assign a nat struct to a session handle.
 *
 * Used by algs to create nat structs for reverse secondary flows.
 * On success, will consume the alg nat params.  Otherwise we leave
 * that to tuple destroy. (There may be a reservation)
 *
 * Called as desired by algs during their npf_alg_session_init().
 *
 */
int npf_alg_session_nat(npf_session_t *se, npf_nat_t *pnat, npf_cache_t *npc,
		const int di, struct npf_alg_tuple *nt)
{
	struct npf_alg_nat *an = nt->nt_nat;
	npf_nat_t *nat;

	/*
	 * Only if we have an alg nat on the tuple.
	 * May be called in fw stateful matches for algs. (eg: non-nat)
	 */
	if (!an)
		return 0;

	/* Must have a parent nat */
	if (!pnat)
		return -ENOENT;

	/* Create the nat, possibly reversed of the pnat */
	nat = npf_nat_custom_nat(pnat, an->an_flags);
	if (!nat)
		return -ENOMEM;

	if (an->an_flags & NPF_NAT_REVERSE) {
		npf_nat_set_trans(nat, &an->an_oaddr, an->an_oport);
		npf_nat_set_orig(nat, &an->an_taddr, an->an_tport);
	} else {
		npf_nat_set_trans(nat, &an->an_taddr, an->an_tport);
		npf_nat_set_orig(nat, &an->an_oaddr, an->an_oport);
	}

	npf_nat_finalise(npc, se, di, nat);

	npf_session_setnat(se, nat, true);

	/* Mark as consumed so tuple destroy doesn't see it */
	free(nt->nt_nat);
	nt->nt_nat = NULL;

	return 0;
}

/*
 * Register a application protocol alg.
 *
 * - Create the tuple hash tables
 * - Insert default config(s)
 *
 * Do not attempt to recover from partial success.  Failure to
 * register a specific ALG will result in failure of the
 * ALG instance creation, will result in complete cleanup.
 */
int npf_alg_register(struct npf_alg *na)
{
	struct npf_alg_config *ac = na->na_configs;
	int rc = 0;
	int i;

	for (i = 0; i < na->na_num_configs; i++) {
		rc = alg_register_protos(na, ac);
		if (rc)
			break;

		rc = alg_manage_config(na, NPF_ALG_CONFIG_SET, ac);
		if (rc)
			break;
		ac++;
	}

	if (rc)
		RTE_LOG(ERR, FIREWALL, "ALG: register: %s failed: rc: %d\n",
				na->na_ops->name, rc);

	return rc;
}

static int alg_config(struct npf_alg_instance *ai, const char *name, int op,
				int argc, char **argv)
{
	struct npf_alg *alg;

	alg = alg_name_to_alg(ai, name);
	if (alg_has_op(alg, config))
		return alg->na_ops->config(alg, op, argc, argv);
	return -ENOENT;
}

/* config() - Set/delete options to an alg */
int npf_alg_config(uint32_t ext_vrfid, const char *name, int op,
		int argc, char **argv)
{
	struct vrf *vrf;
	struct npf_alg_instance *ai;
	int rc;

	vrf = vrf_find_or_create(ext_vrfid); /* Bug */
	if (!vrf)
		return -EINVAL;
	ai = vrf_get_npf_alg(vrf);
	if (!ai)
		return -EINVAL;

	rc = alg_config(ai, name, op, argc, argv);
	if (!rc) {
		switch (op) {
		case NPF_ALG_CONFIG_SET:
			vrf_find_or_create(ext_vrfid); /* Bug */
			ai->ai_ref_count++;
			break;
		case NPF_ALG_CONFIG_DELETE:
			vrf_delete_by_ptr(vrf);
			ai->ai_ref_count++;
			break;
		}
	}

	vrf_delete_by_ptr(vrf);
	return rc;
}

/*
 * alg_search_all_and_any_sport()
 *
 * Certain algs (sip notably) can add multiple tuples that can match a
 * single packet.  This is because they may wild-card the sport (eg: set to
 * zero) due to the connection-less nature of UDP.
 *
 * We need to ensure that a tuple containing both a sport and dport is matched
 * prior to a tuple with a matching dport and sport == 0, so search both in
 * that order.
 */
struct npf_alg_tuple *
alg_search_all_then_any_sport(struct alg_protocol_tuples *apt,
			      struct npf_cache *npc, const struct ifnet *ifp)
{
	struct apt_match m;
	struct npf_alg_tuple *nt;
	uint64_t all_count;
	uint64_t any_sport;


	/* Ensure we have some in either */
	all_count = apt_ht_count(&apt->apt_all);
	any_sport = apt_ht_count(&apt->apt_any_sport);
	if (!all_count && !any_sport)
		return NULL;

	alg_fill_match(npc, npf_cache_ipproto(npc), ifp->if_index, &m);

	/* Search 'all' first */
	if (all_count) {
		m.m_flag = NPF_TUPLE_MATCH_ALL;
		nt = apt_search_ht(&apt->apt_all, &m);
		if (nt)
			return nt;
	}

	/* Not found, try the 'any_sport' */
	if (any_sport) {
		m.m_flag = NPF_TUPLE_MATCH_ANY_SPORT;
		nt = apt_search_ht(&apt->apt_any_sport, &m);
	}

	return nt;
}

/* Get the base parent's nat struct */
struct npf_nat *npf_alg_parent_nat(npf_session_t *se)
{
	return npf_session_get_nat(npf_session_get_base_parent(se));
}

static void alg_info_json(struct npf_alg *alg, json_writer_t *json)
{
	if (alg) {
		jsonw_start_object(json);
		jsonw_string_field(json, "name", alg->na_ops->name);
		jsonw_bool_field(json, "enabled", alg->na_enabled);
		jsonw_end_object(json);
	}
}

int
alg_dump(struct npf_alg_instance *ai, vrfid_t vrfid, json_writer_t *json)
{
	struct alg_protocol_tuples *apt;
	uint8_t i;

	jsonw_start_object(json);
	jsonw_uint_field(json, "vrfid", vrf_get_external_id(vrfid));

	jsonw_name(json, "algs");
	jsonw_start_array(json);
	alg_info_json(ai->ai_ftp, json);
	alg_info_json(ai->ai_tftp, json);
	alg_info_json(ai->ai_sip, json);
	alg_info_json(ai->ai_rpc, json);
	jsonw_end_array(json);

	jsonw_name(json, "tuples");
	jsonw_start_array(json);
	for (i = 0; i < NPF_ALG_MAX_PROTOS; i++) {
		apt = alg_get_apt(ai, i);
		apt_walk_proto(apt, apt_tuple_dump, json);
	}
	jsonw_end_array(json);
	jsonw_end_object(json);
	return 0;
}

/* alg enable */
int npf_alg_state_set(uint32_t ext_vrfid, const char *name, int op)
{
	struct vrf *vrf;
	struct npf_alg_instance *ai;
	struct npf_alg *alg;

	vrf = vrf_get_rcu_from_external(ext_vrfid);
	if (!vrf) {
		struct alg_late_vrf *late_vrf
			= npf_alg_late_vrf_find(ext_vrfid);
		if (!late_vrf)
			late_vrf = npf_alg_late_vrf_add(ext_vrfid);

		const bool off = (op == NPF_ALG_CONFIG_DISABLE);
		npf_alg_late_vrf_set_alg(late_vrf, name, !off);

		return 0;
	}

	ai = vrf_get_npf_alg(vrf);
	if (!ai)
		return -EINVAL;

	alg = alg_name_to_alg(ai, name);
	if (!alg)
		return -ENOENT;

	/*
	 *  Note that algs are enabled by default
	 */
	switch (op) {
	case NPF_ALG_CONFIG_ENABLE:
		if (!alg->na_enabled)
			alg->na_enabled = true;
		break;
	case NPF_ALG_CONFIG_DISABLE:
		if (alg->na_enabled)
			alg->na_enabled = false;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

const char *npf_alg_id2name(enum npf_alg_id id)
{
	switch (id) {
	case NPF_ALG_ID_FTP:
		return NPF_ALG_FTP_NAME;
	case NPF_ALG_ID_TFTP:
		return NPF_ALG_TFTP_NAME;
	case NPF_ALG_ID_RPC:
		return NPF_ALG_RPC_NAME;
	case NPF_ALG_ID_SIP:
		return NPF_ALG_SIP_NAME;
	};
	return "-";
}

void npf_alg_destroy_alg(struct npf_alg *alg)
{
	alg->na_enabled = false;
	alg->na_ops = NULL;
	free(alg);
}

struct npf_alg *
npf_alg_create_alg(struct npf_alg_instance *ai, enum npf_alg_id id)
{
	struct npf_alg *alg;

	alg = zmalloc_aligned(sizeof(struct npf_alg));
	if (!alg)
		return NULL;

	rte_atomic32_set(&alg->na_refcnt, 0);
	alg->na_ai = ai;
	alg->na_id = id;
	alg->na_enabled = true;

	return alg;
}

static void
alg_periodic(struct rte_timer *timer __rte_unused, void *data __rte_unused)
{
	struct npf_alg_instance *ai;
	struct vrf *vrf;
	vrfid_t vrfid;

	VRF_FOREACH(vrf, vrfid) {
		ai = vrf_get_npf_alg(vrf);
		if (ai) {
			/* Call an alg's periodic routine */
			if (alg_has_op(ai->ai_sip, periodic))
				ai->ai_sip->na_ops->periodic(ai->ai_sip);
			apt_worker(ai);
		}
	}

	/* Until we graceful shutdown the dataplane */
	if (running)
		npf_alg_timer_reset();
}

/*
 * Create a per-vrf ALG instance
 */
struct npf_alg_instance *npf_alg_create_instance(uint32_t ext_vrfid)
{
	struct npf_alg_instance *ai;

	ai = zmalloc_aligned(sizeof(struct npf_alg_instance));
	if (!ai)
		return NULL;

	/* Now specific alg instances */
	ai->ai_tftp = npf_alg_tftp_create_instance(ai);
	if (!ai->ai_tftp)
		goto out;
	ai->ai_ftp = npf_alg_ftp_create_instance(ai);
	if (!ai->ai_ftp)
		goto out;
	ai->ai_sip = npf_alg_sip_create_instance(ai);
	if (!ai->ai_sip)
		goto out;
	ai->ai_rpc = npf_alg_rpc_create_instance(ai);
	if (!ai->ai_rpc)
		goto out;

	/* Find any disabled ALGs on the lookaside list */
	struct alg_late_vrf *late_vrf
		= npf_alg_late_vrf_find(ext_vrfid);
	if (late_vrf) {
		zhash_t *algs = late_vrf->nv_algs;
		bool *on_p;
		for (on_p = zhash_first(algs); on_p; on_p = zhash_next(algs)) {
			char const *name = zhash_cursor(algs);
			struct npf_alg *alg = alg_name_to_alg(ai, name);
			if (!alg)
				continue;
			alg->na_enabled = *on_p;
		}
		npf_alg_late_vrf_del(late_vrf);
	}

	return ai;
out:
	npf_alg_destroy_instance(ai);
	return NULL;
}

/*
 * ALG GC timer
 *
 * We can never safely free an allocated timer, so
 * create a global one for all ALG instances.
 */
void
npf_alg_timer_init(void)
{
	rte_timer_init(&alg_timer);

	alg_late_vrf_hash = zhash_new();
}

void
npf_alg_timer_uninit(void)
{
	rte_timer_stop_sync(&alg_timer);

	npf_alg_late_vrfs_destroy();
	zhash_destroy(&alg_late_vrf_hash);
}

void
npf_alg_timer_reset(void)
{
	rte_timer_reset(&alg_timer, ALG_INTERVAL * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), alg_periodic, NULL);
}

/*
 * Called from whole dp unit-tests to delete all non-KEEP tuples
 */
static void npf_alg_flush(struct npf_alg_instance *ai)
{
	uint8_t i;
	struct alg_protocol_tuples *apt;

	if (!ai)
		return;

	for (i = 0; i <= NPF_ALG_MAX_PROTOS; i++) {
		apt = rcu_dereference(ai->ai_apts[i]);
		apt_walk_proto(apt, apt_flush_tuples, NULL);
	}
}

/*
 * Called from whole dp unit-tests to delete all non-KEEP tuples
 */
void npf_alg_flush_all(void)
{
	struct vrf *vrf;
	vrfid_t vrfid;

	VRF_FOREACH(vrf, vrfid) {
		npf_alg_flush(vrf_get_npf_alg_rcu(vrfid));
	}
}

/*
 * ALG tuple purge - Delete all tuples.
 *
 * Called during an NPF instance delete.
 */
void npf_alg_purge(struct npf_alg_instance *ai)
{
	uint8_t i;
	struct alg_protocol_tuples *apt;

	for (i = 0; i <= NPF_ALG_MAX_PROTOS; i++) {
		apt = rcu_dereference(ai->ai_apts[i]);
		apt_walk_proto(apt, apt_tuple_purge, NULL);
	}
}
