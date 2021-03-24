/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * ALG Protocol Tuple (APT) Database
 */

#include <rte_jhash.h>
#include "json_writer.h"
#include "vplane_log.h"
#include "util.h"

#include "npf/npf_vrf.h"
#include "npf/alg/alg_apt.h"

/* Reqd until apt instance is moved from alg instance to vrf */
#include "npf/alg/alg.h"

/*
 * ALG tuple hash table.
 *
 * The ALG framework consists of an API, executed at certain points along a
 * packets path throughout NPF, as well as an expected flow tuple database.
 *
 * The tuple database consists of a set of three hash tables, each table
 * representing the type of tuple match.  The tables represent 'wildcard'
 * matching of various parts of a possible 6-tuple
 *
 * 2-tuple (proto and dest port).
 * 5-tuple (intf, proto, saddr, daddr, dport).  Aka 'any source port' table.
 * 6-tuple (intf, proto, saddr, daddr, dport, sport). Aka 'all' table.
 *
 * Matches must be made in a 'most-restrictive' to 'least-restrictive' manner,
 * meaning a match for a 6 tuple must be made prior to a match for a 5 tuple.
 *
 * When a packet enters the framework, a lookup into the tuple database is
 * performed and if a match is made, the packet is forwarded to the alg set in
 * the tuple.
 *
 * In practise, we can divide tuples into two types: 'keep' and 'non-keep'.
 *
 * 'keep' tuples are added via ALG configuration, and consist of a protocol
 * and well known port.  These are typically added to the 2 tuple (proto and
 * dest port) table, and are used to identify the initial flow of an ALG.
 *
 * One exception is SIP, which adds a 'keep' tuple to the 'any src port' table
 * to detect a secondary flow.  It does this since it uses its own mechanism
 * to timeout SIP Requests, and hence the tuple.
 *
 * 'non-keep' tuples are added by the ALGs themselves when they determine
 * secondary flow information from the initial flow packets.  These are added
 * to either the 'all' table or the 'any source port' table.  They always
 * match on protocol, and usually all match on interface, .i.e. they are
 * 5-tuple or 6-tuple.
 */


/*
 * Each apt instance contains three hash tables.  Each table has the following
 * parameters.
 */
#define APT_INIT	32
#define APT_MIN		256
#define APT_MAX		(16*1024)

/* Retry count for tuple insertions. */
#define APT_RETRY_COUNT	10

/* Default timeout */
#define APT_TIMEOUT 10

/* Tuple garbage collector */
#define APT_GC_INTERVAL 5
static struct rte_timer apt_timer;

static rte_atomic32_t apt_instance_count;
static rte_atomic32_t apt_init_flag;

/*
 * APT Hash Table
 */
struct apt_table {
	struct cds_lfht	*at_ht;
	rte_atomic32_t	at_count;
};

/*
 * APT Instance
 *
 * Currently hangs off the alg instance structure 'struct npf_alg_instance'
 * (which, in turn, hangs off the vrf instance).
 */
struct apt_instance {
	rte_atomic32_t		ai_refcnt;
	uint32_t		ai_vrfid;

	rte_spinlock_t		ai_lock;	/* Used by paired tuples */

	/* Hash tables */
	struct apt_table	ai_dport;	/* 2-tuple (pcol, dest port) */
	struct apt_table	ai_any_sport;	/* 5-tuple (any src port) */
	struct apt_table	ai_all;		/* 6-tuple */
};

/*
 * Longest name is 'tftp'.  at_client_name is only used when generating json,
 * and it avoids us having to get the name from the client.
 */
#define APT_NAME_MAX 5

/*
 * Tuple
 */
struct apt_tuple {
	/* Private fields */
	struct cds_lfht_node	at_node;	/* hash table node */
	struct rcu_head		at_rcu_head;
	uint64_t		at_exp_ts;	/* Expire timestamp */
	struct apt_table	*at_ht;		/* back ptr to hash table */
	rte_atomic32_t		at_refcnt;

	/* Public fields */

	/*
	 * Client (ALG) handle and context.  'at_client' is a pointer to an
	 * 'struct npf_alg' structure for npf.  Only sip and rsh have
	 * client_data.
	 */
	void			*at_client;
	uint32_t		at_client_flags;
	void			*at_client_data;
	char			at_client_name[APT_NAME_MAX];

	/*
	 * npf context.
	 *
	 * 'at_session' is a pointer to the 'parent' session that created the
	 * tuple.  When a packet matches this tuple then a new 'child' session
	 * is created and linked to the parent tuple, after which the tuple is
	 * deleted.
	 *
	 * 'at_nat' is a short-lived data structure that contains some basic
	 * npf nat information about the parent session.
	 */
	void			*at_session;
	void			*at_nat;	/* struct npf_alg_nat */

	/*
	 * 'at_paired' points to a paired tuple.  This is used by SIP when the
	 * first packet of a secondary flow may occur from either direction.
	 * First tuple of the pair to see this flow 'wins'.
	 */
	struct apt_tuple	*at_paired;

	uint8_t			at_keep:1;	/* Do not timeout */
	uint8_t			at_expired:1;
	uint8_t			at_removing:1;

	/*
	 * 'multimatch' tuples are special SIP tuples.  They are 5-tuples (any
	 * src port) with the well known SIP dest port(5060).  They are not
	 * expired after the initial packet has matched the tuple, and hence
	 * are used to match multiple flows.  They are expired when the parent
	 * session is expired.
	 */
	uint8_t			at_multimatch:1;
	uint16_t		at_timeout;	/* Timeout in seconds */

	/* Match type */
	enum apt_match_table	at_match;

	/* Match key */
	uint8_t			at_proto;	/* IP protocol */
	uint8_t			at_alen;	/* addr len */
	uint16_t		at_sport;	/* src port */
	uint16_t		at_dport;	/* dst port */
	uint32_t		at_ifx;		/* Interface index */
	npf_addr_t		at_srcip;	/* src addr */
	npf_addr_t		at_dstip;	/* dst addr */
};


/* Forward references */
static struct apt_tuple *apt_tuple_lookup_key(struct apt_instance *ai,
					      struct apt_match_key *m);
static void apt_init(void);
static void apt_uninit(void);


/*
 * APT client registration.  Used for notification of APT database events to
 * ALGs.
 *
 * Currently the only notification is when a tuple is being deleted in order
 * to allow ALGs to cleanup.
 */
static struct apt_event_ops *apt_ops[APT_EVENT_MAX_OPS];

void apt_event_register(const struct apt_event_ops *ops)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(apt_ops); i++) {
		const struct apt_event_ops *tmp;
		tmp = rcu_dereference(apt_ops[i]);

		/* Do not register same thing twice */
		if (tmp && tmp == ops)
			return;
	}

	for (i = 0; i < ARRAY_SIZE(apt_ops); i++) {
		if (!rcu_cmpxchg_pointer(&apt_ops[i], NULL,
					(struct apt_event_ops *)ops))
			return;
	}
}

/*
 * Hash table matching function
 */
static int apt_table_match(struct cds_lfht_node *node, const void *key)
{
	const struct apt_match_key *m = key;
	struct apt_tuple *at;

	at = caa_container_of(node, struct apt_tuple, at_node);

	/* Never match expired tuples */
	if (at->at_expired)
		return 0;

	/*
	 * Interface match is optional.  This is not used for 2-tuple (proto,
	 * dest port) matches, but is used for 'all' and 'any sport' matches.
	 */
	if (at->at_ifx && (at->at_ifx != m->m_ifx))
		return 0;

	/* Always match on protocol */
	if (at->at_proto != m->m_proto)
		return 0;

	/* Which table are we matching in? */
	switch (m->m_match) {
	case APT_MATCH_DPORT:
		/*
		 * Match on destination port.  This is used to detect the
		 * primary ALG flow.
		 */
		if (at->at_dport != m->m_dport)
			return 0;
		break;

	case APT_MATCH_ANY_SPORT:
		/* fall through */
	case APT_MATCH_ALL:
		/*
		 * 6-tuple of 5-tuple matches are typically used to detect the
		 * secondary ALG flow.  For some protocols, we do not know the
		 * source address.
		 */
		if (at->at_alen != m->m_alen)
			return 0;
		if (m->m_match == APT_MATCH_ALL &&
		    at->at_sport != m->m_sport)
			return 0;
		if (at->at_dport != m->m_dport)
			return 0;
		if (memcmp(&at->at_srcip, m->m_srcip, m->m_alen))
			return 0;
		if (memcmp(&at->at_dstip, m->m_dstip, m->m_alen))
			return 0;
		break;

	case APT_MATCH_NONE:
		return 1;
	}

	return 1;
}

/*
 * Tuple hash function
 */
static uint32_t apt_table_hash(const struct apt_match_key *m)
{
	const uint32_t *src;
	const uint32_t *dst;
	uint32_t hash = 0;

	switch (m->m_match) {
	case APT_MATCH_DPORT:
		hash = (m->m_dport << 16) | m->m_proto;
		break;

	case APT_MATCH_ANY_SPORT:
		/* fall through */
	case APT_MATCH_ALL:
		/* Don't use sport, it can be wildcarded */
		src = m->m_srcip->s6_addr32;
		dst = m->m_dstip->s6_addr32;

		hash = rte_jhash_2words(m->m_dport, m->m_proto, 0);

		if (m->m_alen == 4)
			return rte_jhash_2words(src[0], dst[0], hash);

		const uint32_t sz = m->m_alen >> 2;

		hash = rte_jhash_32b(src, sz, hash);
		hash = rte_jhash_32b(dst, sz, hash);
		break;

	case APT_MATCH_NONE:
		break;
	}

	return hash;
}

/*
 * Select table from match enum
 */
static struct apt_table *
apt_table_select(struct apt_instance *ai, enum apt_match_table match)
{
	switch (match) {
	case APT_MATCH_DPORT:
		return &ai->ai_dport;
	case APT_MATCH_ALL:
		return &ai->ai_all;
	case APT_MATCH_ANY_SPORT:
		return &ai->ai_any_sport;
	case APT_MATCH_NONE:
		return NULL;
	}
	return NULL;
}

/* Get number of entries (expired and unexpired) in a table */
uint32_t apt_table_count(struct apt_instance *ai, enum apt_match_table tt)
{
	struct apt_table *tbl;

	tbl = apt_table_select(ai, tt);
	if (!tbl)
		return 0;

	return rte_atomic32_read(&tbl->at_count);
}


/* Create a tuple */
static struct apt_tuple *apt_tuple_create(void)
{
	struct apt_tuple *at;

	at = zmalloc_aligned(sizeof(*at));

	if (at) {
		rte_atomic32_init(&at->at_refcnt);
		at->at_client_name[0] = '\0';
	}

	return at;
}

/* Free tuple */
static void apt_tuple_free(struct rcu_head *head)
{
	struct apt_tuple *at =
		caa_container_of(head, struct apt_tuple, at_rcu_head);
	free(at);
}

/*
 * Take reference on tuple
 *
 * A reference is taken:
 *  1. When a tuple is added to a hash table, or
 *  2. When a tuple is paired with another tuple.
 */
static struct apt_tuple *apt_tuple_get(struct apt_tuple *at)
{
	if (at)
		rte_atomic32_inc(&at->at_refcnt);
	return at;
}

/*
 * Release reference on tuple
 */
static void apt_tuple_put(struct apt_tuple *at)
{
	if (at && rte_atomic32_dec_and_test(&at->at_refcnt))
		call_rcu(&at->at_rcu_head, apt_tuple_free);
}

/*
 * Link two tuples together.  Used when the first packet of a secondary flow
 * can occur in either direction.
 */
int alg_apt_tuple_pair(struct apt_tuple *at1, struct apt_tuple *at2)
{
	assert(at1->at_paired == NULL);
	assert(at2->at_paired == NULL);

	if (!at1->at_paired && !at2->at_paired) {
		at1->at_paired = apt_tuple_get(at2);
		at2->at_paired = apt_tuple_get(at1);
		return 0;
	}
	return -EINVAL;
}

/*
 * Unlink two tuples
 */
static void apt_tuple_unpair(struct apt_tuple *at1, struct apt_tuple *at2)
{
	if (at1) {
		apt_tuple_put(at1->at_paired);
		at1->at_paired = NULL;
	}
	if (at2) {
		apt_tuple_put(at2->at_paired);
		at2->at_paired = NULL;
	}
}

/*
 * Unlink two tuples, and expire them
 */
static void apt_tuple_unpair_and_expire(struct apt_tuple *at1)
{
	if (!at1)
		return;

	struct apt_tuple *at2 = at1->at_paired;

	apt_tuple_unpair(at1, at2);
	alg_apt_tuple_expire(at1);
	alg_apt_tuple_expire(at2);
}

/*
 * Verify the tuple of a secondary flow before creating a child session.
 * Called from npf_alg_session
 */
bool apt_tuple_verify_and_expire(struct apt_instance *ai, struct apt_tuple *at)
{
	bool do_drop = false;

	/*
	 * There is one race we are concerned with: Possible receipt of both a
	 * forward and reverse packet.
	 *
	 * This race is problematic.  We could wind up with two session
	 * handles, one containing the forward sentry and one containing its
	 * backward sentry. We cannot allow that.  So detect and drop on the
	 * basis of tuple expiration.
	 *
	 * Regardless, expire all tuples for this match.
	 */
	if (unlikely(at->at_paired)) {
		/* Paired tuple */
		rte_spinlock_lock(&ai->ai_lock);

		if (at->at_expired)
			do_drop = true;
		apt_tuple_unpair_and_expire(at);

		rte_spinlock_unlock(&ai->ai_lock);
	} else {
		/* Not paired */
		if (!at->at_multimatch)
			alg_apt_tuple_expire(at);
	}

	return do_drop;
}

/*
 * Insert tuple into a table
 */
static int apt_tuple_insert(struct apt_instance *ai, struct apt_tuple *at,
			    bool replace)
{
	struct apt_match_key m;
	struct apt_table *tbl;
	uint32_t hash;
	int rc, retry;

	/* Select table from match flags */
	tbl = apt_table_select(ai, at->at_match);
	if (!tbl)
		return -ENOENT;

	if (unlikely(rte_atomic32_read(&tbl->at_count) >= APT_MAX)) {
		if (net_ratelimit())
			RTE_LOG(DEBUG, FIREWALL,
				"APT: table full\n");
		return -ENOSPC;
	}

	rcu_assign_pointer(at->at_ht, tbl);

	if (!at->at_keep)
		apt_tuple_set_timeout(at, APT_TIMEOUT);

	/* Fill-in the match structure */
	m.m_match = at->at_match;
	m.m_srcip = &at->at_srcip;
	m.m_dstip = &at->at_dstip;
	m.m_ifx   = at->at_ifx;
	m.m_dport = at->at_dport;
	m.m_sport = at->at_sport;
	m.m_proto = at->at_proto;
	m.m_alen  = at->at_alen;

	cds_lfht_node_init(&at->at_node);
	hash = apt_table_hash(&m);

	/*
	 * If 'replace' is true, then the alg is attempting to replace an
	 * existing tuple.  Do this by expiring the existing tuple and
	 * retrying for a limited number of times.
	 */
	rc = -EEXIST;
	retry = APT_RETRY_COUNT;

	while (retry--) {
		struct cds_lfht_node *node;

		node = cds_lfht_add_unique(tbl->at_ht, hash, apt_table_match,
					   &m, &at->at_node);
		if (node == &at->at_node) {
			/* Success */
			apt_tuple_get(at);
			rte_atomic32_inc(&tbl->at_count);

			return 0;
		}

		/* Tuple already exists.  Expire if necessary */
		if (replace) {
			struct apt_tuple *old;
			old = caa_container_of(node, struct apt_tuple,
					       at_node);
			alg_apt_tuple_expire(old);
		} else
			break;
	}

	return rc;
}

/*
 * Create a tuple, and insert into table
 */
struct apt_tuple *
apt_tuple_create_and_insert(struct apt_instance *ai, struct apt_match_key *m,
			    void *client, uint32_t client_flags,
			    const char *client_name, bool replace, bool keep)
{
	struct apt_tuple *at;
	int rc;

	at = apt_tuple_create();
	if (!at)
		return NULL;

	at->at_match = m->m_match;
	if (client_name) {
		strncpy(at->at_client_name, client_name, APT_NAME_MAX);
		at->at_client_name[APT_NAME_MAX-1] = '\0';
	}

	if (m->m_srcip && m->m_alen)
		memcpy(&at->at_srcip.s6_addr, &m->m_srcip->s6_addr, m->m_alen);

	if (m->m_dstip && m->m_alen)
		memcpy(&at->at_dstip.s6_addr, &m->m_dstip->s6_addr, m->m_alen);

	at->at_ifx = m->m_ifx;
	at->at_dport = m->m_dport;
	at->at_sport = m->m_sport;
	at->at_proto = m->m_proto;
	at->at_alen = m->m_alen;

	at->at_keep = keep;
	at->at_client = client;
	at->at_client_flags = client_flags;

	rc = apt_tuple_insert(ai, at, replace);
	if (rc < 0) {
		free(at);
		return NULL;
	}

	return at;
}

/*
 * Expire a tuple
 */
void alg_apt_tuple_expire(struct apt_tuple *at)
{
	if (!at)
		return;

	at->at_expired = true;

	/* If a tuple is paired then we always expire both */
	if (at->at_paired)
		apt_tuple_unpair(at, at->at_paired);
}

/*
 * Lookup tuple and expire if found
 */
int alg_apt_tuple_lookup_and_expire(struct apt_instance *ai,
				    struct apt_match_key *m)
{
	struct apt_tuple *at;

	at = apt_tuple_lookup_key(ai, m);
	if (!at)
		return -ENOENT;

	alg_apt_tuple_expire(at);
	return 0;
}

/*
 * Notify interested clients (the ALG infra) that a tuple has been deleted
 */
static void apt_tuple_delete_event(struct apt_tuple *at)
{
	uint32_t i;
	struct apt_event_ops *ops;

	for (i = 0; i < ARRAY_SIZE(apt_ops); i++) {
		ops = rcu_dereference(apt_ops[i]);
		if (ops && ops->apt_delete)
			ops->apt_delete(at);
	}
}

/*
 * Delete a tuple
 */
static void apt_tuple_delete(struct apt_table *tbl, struct apt_tuple *at)
{
	if (!at)
		return;

	if (!tbl)
		tbl = rcu_dereference(at->at_ht);

	/* Mark expired, if not already expired */
	alg_apt_tuple_expire(at);

	if (tbl && !cds_lfht_del(tbl->at_ht, &at->at_node)) {
		/* Successfully removed from hash table */
		rte_atomic32_dec(&tbl->at_count);

		/* Notify interested clients */
		apt_tuple_delete_event(at);

		/* Release reference */
		apt_tuple_put(at);
	}
}

/*
 * Lookup one or more hash tables in an apt instance.
 */
static struct apt_tuple *
apt_tuple_lookup(struct apt_instance *ai, struct apt_match_key *m,
		 enum apt_match_table *match_tbls, uint ntables)
{
	struct apt_table *tbl;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct apt_tuple *at = NULL;
	uint i;

	/* For each table to lookup ... */
	for (i = 0; i < ntables; i++) {
		m->m_match = match_tbls[i];

		/* Select table from instance and match enum */
		tbl = apt_table_select(ai, m->m_match);
		if (!tbl)
			continue;

		if (rte_atomic32_read(&tbl->at_count) == 0)
			continue;

		cds_lfht_lookup(tbl->at_ht, apt_table_hash(m), apt_table_match,
				m, &iter);

		node = cds_lfht_iter_get_node(&iter);
		if (node) {
			at = caa_container_of(node, struct apt_tuple, at_node);
			return at;
		}
	}

	return NULL;
}

/*
 * Lookup 6-tuple (all) table, then lookup 5-tuple (any source port) table,
 * then any dest port table.
 */
struct apt_tuple *
apt_tuple_lookup_all_any_dport(struct apt_instance *ai,
			       struct apt_match_key *m)
{
	enum apt_match_table match_tbl[] = {APT_MATCH_ALL,
					    APT_MATCH_ANY_SPORT,
					    APT_MATCH_DPORT};

	return apt_tuple_lookup(ai, m, match_tbl, ARRAY_SIZE(match_tbl));
}

/*
 * Lookup 6-tuple (all) table, then lookup 5-tuple (any source port) table.
 */
struct apt_tuple *
apt_tuple_lookup_all_any(struct apt_instance *ai, struct apt_match_key *m)
{
	enum apt_match_table match_tbl[] = {APT_MATCH_ALL,
					    APT_MATCH_ANY_SPORT};

	return apt_tuple_lookup(ai, m, match_tbl, ARRAY_SIZE(match_tbl));
}

/*
 * Lookup destination port table
 */
struct apt_tuple *
apt_tuple_lookup_dport(struct apt_instance *ai, struct apt_match_key *m)
{
	enum apt_match_table match_tbl[] = {APT_MATCH_DPORT};

	return apt_tuple_lookup(ai, m, match_tbl, ARRAY_SIZE(match_tbl));
}

/*
 * Lookup table specified in the match key object, m_match
 */
static struct apt_tuple *
apt_tuple_lookup_key(struct apt_instance *ai, struct apt_match_key *m)
{
	enum apt_match_table match_tbl[] = {m->m_match};

	return apt_tuple_lookup(ai, m, match_tbl, ARRAY_SIZE(match_tbl));
}

/*******************************************************************
 *  Tuple accessors start
 */

/* Get client handle */
void *apt_tuple_get_client_handle(struct apt_tuple *at)
{
	return at->at_client;
}

/*
 * Set the client handle to NULL when the tuple is being deleted, and we have
 * released the handle.
 */
void apt_tuple_clear_client_handle(struct apt_tuple *at)
{
	at->at_client = NULL;
}

/* Get client flags */
uint32_t apt_tuple_get_client_flags(struct apt_tuple *at)
{
	return at->at_client_flags;
}

/* Get client data */
void *apt_tuple_get_client_data(struct apt_tuple *at)
{
	return at->at_client_data;
}

/* Set client data */
void apt_tuple_set_client_data(struct apt_tuple *at, void *data)
{
	at->at_client_data = data;
}

/* Set session handle */
void apt_tuple_set_session(struct apt_tuple *at, void *session)
{
	at->at_session = session;
}

/* Get session handle */
void *apt_tuple_get_session(struct apt_tuple *at)
{
	return at->at_session;
}

/* Get session handle only if active */
void *apt_tuple_get_active_session(struct apt_tuple *at)
{
	void *se = apt_tuple_get_session(at);

	if (!se)
		return NULL;

	return npf_session_is_active(se) ? se : NULL;
}

/* Set NAT handle */
void apt_tuple_set_nat(struct apt_tuple *at, void *nat)
{
	at->at_nat = nat;
}

/* Get NAT handle */
void *apt_tuple_get_nat(struct apt_tuple *at)
{
	return at->at_nat;
}

/* Set tuple timeout */
void apt_tuple_set_timeout(struct apt_tuple *at, uint32_t timeout)
{
	at->at_timeout = timeout;
	at->at_exp_ts = get_time_uptime() + timeout;
}

/* Set multimatch attribute */
void apt_tuple_set_multimatch(struct apt_tuple *at, bool val)
{
	at->at_multimatch = val;
}

/* Get tuple table type */
enum apt_match_table apt_tuple_get_table_type(struct apt_tuple *at)
{
	return at->at_match;
}

/*
 *  Tuple accessors end
 *******************************************************************/

/*
 * Destroy an apt instance table
 */
static void apt_table_destroy(struct apt_table *tbl)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *at;

	if (!tbl->at_ht)
		return;

	/*
	 * For each tuple in hash table: remove from hash table, mark as
	 * expired, and rcu-free.
	 */
	cds_lfht_for_each_entry(tbl->at_ht, &iter, at, at_node)
		apt_tuple_delete(tbl, at);

	dp_ht_destroy_deferred(tbl->at_ht);
	tbl->at_ht = NULL;
}

/*
 * Destroy an apt instance
 */
static void apt_instance_destroy(struct apt_instance *ai)
{
	if (ai) {
		apt_table_destroy(&ai->ai_all);
		apt_table_destroy(&ai->ai_any_sport);
		apt_table_destroy(&ai->ai_dport);
		free(ai);

		/* Last instance? */
		if (rte_atomic32_dec_and_test(&apt_instance_count)) {
			apt_uninit();
			rte_atomic32_clear(&apt_init_flag);
		}
	}
}

/*
 * Create an apt instance hash table
 */
static struct cds_lfht *apt_table_create(void)
{
	return cds_lfht_new(APT_INIT, APT_MIN, APT_MAX,
			    CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
}

/*
 * Create an apt instance
 */
struct apt_instance *alg_apt_instance_create(uint32_t ext_vrfid)
{
	struct apt_instance *ai;

	ai = zmalloc_aligned(sizeof(*ai));
	if (!ai)
		return NULL;

	rte_atomic32_inc(&apt_instance_count);

	/* First instance? */
	if (rte_atomic32_test_and_set(&apt_init_flag))
		apt_init();

	rte_atomic32_init(&ai->ai_refcnt);
	ai->ai_vrfid = ext_vrfid;

	rte_spinlock_init(&ai->ai_lock);

	ai->ai_all.at_ht = apt_table_create();
	if (!ai->ai_all.at_ht)
		goto error;

	ai->ai_any_sport.at_ht = apt_table_create();
	if (!ai->ai_any_sport.at_ht)
		goto error;

	ai->ai_dport.at_ht = apt_table_create();
	if (!ai->ai_dport.at_ht)
		goto error;

	return ai;

error:
	apt_instance_destroy(ai);
	return NULL;
}

/*
 * Take reference on instance.
 *
 * A reference is taken by the ALG instance plus each ALG on that ALG
 * instance.
 */
struct apt_instance *alg_apt_instance_get(struct apt_instance *ai)
{
	if (ai)
		rte_atomic32_inc(&ai->ai_refcnt);
	return ai;
}

/* Release reference on instance */
void alg_apt_instance_put(struct apt_instance *ai)
{
	if (ai && rte_atomic32_dec_and_test(&ai->ai_refcnt))
		apt_instance_destroy(ai);
}

/*
 * Write json for one tuple
 */
static void apt_tuple_jsonw(struct apt_tuple *at, json_writer_t *json)
{
	int family = 0;
	char buf[INET6_ADDRSTRLEN];

	/* Only display initialized fields */

	jsonw_start_object(json);
	jsonw_string_field(json, "alg", at->at_client_name);

	if (at->at_exp_ts)
		jsonw_uint_field(json, "timestamp", at->at_exp_ts);
	if (at->at_proto)
		jsonw_uint_field(json, "protocol", at->at_proto);
	if (at->at_session)
		jsonw_bool_field(json, "session", true);
	if (at->at_ifx)
		jsonw_uint_field(json, "if_index", at->at_ifx);
	if (at->at_client_flags)
		jsonw_uint_field(json, "alg_flags", at->at_client_flags);

	if (at->at_timeout)
		jsonw_uint_field(json, "timeout", at->at_timeout);

	/*
	 * Create old-style flags bitmap until config scripts are updated.
	 */
	uint32_t at_flags = 0;

	switch (at->at_match) {
	case APT_MATCH_DPORT:
		at_flags |= NPF_TUPLE_MATCH_PROTO_PORT;
		break;
	case APT_MATCH_ALL:
		at_flags |= NPF_TUPLE_MATCH_ALL;
		break;
	case APT_MATCH_ANY_SPORT:
		at_flags |= NPF_TUPLE_MATCH_ANY_SPORT;
		break;
	case APT_MATCH_NONE:
		break;
	}

	if (at->at_keep)
		at_flags |= NPF_TUPLE_KEEP;
	if (at->at_removing)
		at_flags |= NPF_TUPLE_REMOVING;
	if (at->at_expired)
		at_flags |= NPF_TUPLE_EXPIRED;
	if (at->at_multimatch)
		at_flags |= NPF_TUPLE_MULTIMATCH;

	if (at_flags)
		jsonw_uint_field(json, "flags", at_flags);

	if (at->at_sport)
		jsonw_uint_field(json, "sport", ntohs(at->at_sport));
	if (at->at_dport)
		jsonw_uint_field(json, "dport", ntohs(at->at_dport));

	switch (at->at_alen) {
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
		inet_ntop(family, &at->at_srcip, buf, sizeof(buf));
		jsonw_string_field(json, "srcip", buf);
		inet_ntop(family, &at->at_dstip, buf, sizeof(buf));
		jsonw_string_field(json, "dstip", buf);
		jsonw_uint_field(json, "alen", at->at_alen);
	}

	if (at->at_client_data)
		jsonw_bool_field(json, "tuple_data", true);

	jsonw_end_object(json);
}

/*
 * Write json for an apt table
 */
static void apt_table_jsonw(struct apt_table *tbl, json_writer_t *json)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *at;

	if (!tbl->at_ht)
		return;

	if (rte_atomic32_read(&tbl->at_count) == 0)
		return;

	cds_lfht_for_each_entry(tbl->at_ht, &iter, at, at_node)
		apt_tuple_jsonw(at, json);
}

/*
 * Write json for an apt instance
 */
void alg_apt_instance_jsonw(struct apt_instance *ai, json_writer_t *json)
{
	jsonw_name(json, "tuples");
	jsonw_start_array(json);

	apt_table_jsonw(&ai->ai_dport, json);
	apt_table_jsonw(&ai->ai_any_sport, json);
	apt_table_jsonw(&ai->ai_all, json);

	jsonw_end_array(json);
}

/*
 * Expire tuples for a given session
 */
static void apt_table_expire_session(struct apt_table *tbl, const void *session)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *at;

	if (rte_atomic32_read(&tbl->at_count) == 0)
		return;

	cds_lfht_for_each_entry(tbl->at_ht, &iter, at, at_node) {
		if (at->at_session != session)
			continue;

		alg_apt_tuple_expire(at);
	}
}

/*
 * Notification that a session has been expired.
 *
 * Expire tuples all tuples that contain this session handle. Only applies to
 * 'all' and 'any_sport' tables since these are the only ones created via a
 * session.  (The 'dest' table is managed via config)
 */
void alg_apt_instance_expire_session(struct apt_instance *ai,
				     const void *session)
{
	if (ai) {
		/* dest port table tuples will never have a session */
		apt_table_expire_session(&ai->ai_all, session);
		apt_table_expire_session(&ai->ai_any_sport, session);
	}
}

static void
apt_table_destroy_session(struct apt_table *tbl, const void *session)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *at;

	if (rte_atomic32_read(&tbl->at_count) == 0)
		return;

	cds_lfht_for_each_entry(tbl->at_ht, &iter, at, at_node) {
		if (at->at_session != session)
			continue;

		apt_tuple_delete(tbl, at);
	}
}

/*
 * Delete any tuples created by the given session.  Only applies to the 'all'
 * and 'any_sport' tables since these are the only ones created via a session.
 * (The 'dest' table is managed via config)
 */
void alg_apt_instance_destroy_session(struct apt_instance *ai,
				      const void *session)
{
	if (ai) {
		apt_table_destroy_session(&ai->ai_all, session);
		apt_table_destroy_session(&ai->ai_any_sport, session);
	}
}

/*
 * Reset tuples for a specific client and instance.
 *
 * Delete 'keep' tuples and expire non 'keep' tuples.  Typically this is
 * called when a client (alg) is reset, in which case it will re-add its
 * 'keep' tuples immediately after this call.
 */
static void apt_table_client_reset(struct apt_table *tbl, const void *client)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *at;

	if (rte_atomic32_read(&tbl->at_count) == 0)
		return;

	cds_lfht_for_each_entry(tbl->at_ht, &iter, at, at_node) {
		if (at->at_client != client)
			continue;

		if (at->at_keep)
			apt_tuple_delete(tbl, at);
		else
			alg_apt_tuple_expire(at);
	}
}

/*
 * Reset tuples for a specific client and instance.
 */
void
alg_apt_instance_client_reset(struct apt_instance *ai, const void *client)
{
	apt_table_client_reset(&ai->ai_all, client);
	apt_table_client_reset(&ai->ai_any_sport, client);
	apt_table_client_reset(&ai->ai_dport, client);
}

/*
 * Delete all tuples for a specific client.
 */
static void apt_table_client_destroy(struct apt_table *tbl, const void *client)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *at;

	if (rte_atomic32_read(&tbl->at_count) == 0)
		return;

	cds_lfht_for_each_entry(tbl->at_ht, &iter, at, at_node) {
		if (at->at_client != client)
			continue;

		apt_tuple_delete(tbl, at);
	}
}

/*
 * Delete all tuples for a specific client and instance.
 */
void
alg_apt_instance_client_destroy(struct apt_instance *ai, const void *client)
{
	apt_table_client_destroy(&ai->ai_all, client);
	apt_table_client_destroy(&ai->ai_any_sport, client);
	apt_table_client_destroy(&ai->ai_dport, client);
}

/*
 * Called from whole dp unit-tests to delete all non-keep or multimatch
 * tuples, and any expired 'keep' tuples.
 */
static void apt_table_flush(struct apt_table *tbl)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *at;

	if (rte_atomic32_read(&tbl->at_count) == 0)
		return;

	/*
	 * For each qualifying tuple in each hash table: remove from hash
	 * table, mark as expired, and rcu-free.
	 */
	cds_lfht_for_each_entry(tbl->at_ht, &iter, at, at_node) {
		if (at->at_multimatch || !at->at_keep || at->at_expired)
			apt_tuple_delete(tbl, at);
	}
}

/*
 * Called from whole dp unit-tests to delete all non-keep or multimatch
 * tuples, and any expired 'keep' tuples.
 */
void alg_apt_instance_flush(struct apt_instance *ai)
{
	apt_table_flush(&ai->ai_all);
	apt_table_flush(&ai->ai_any_sport);
	apt_table_flush(&ai->ai_dport);
}

/*
 * Is tuple expired or timed-out?
 */
static bool apt_tuple_is_expired(struct apt_tuple *at, uint64_t current)
{
	if (at->at_expired)
		return true;

	/*
	 * 'keep' entries never timeout.  They must be explicitly expired
	 * and/or deleted.
	 */
	if (at->at_keep)
		return false;

	if (current > at->at_exp_ts) {
		alg_apt_tuple_expire(at);
		return true;
	}
	return false;
}

/*
 * Garbage collect an APT table
 *
 * 1st pass: Timed-out entries are marked as expired
 * 2nd pass: Expired entries are marked for removing
 * 3rd pass: Entries are removed from hash table
 *
 * Expired entries are no longer found when doing a table lookup.
 *
 * 'keep' entries never timeout.  They must be explicitly expired and/or
 * deleted.
 */
static void apt_table_gc(struct apt_table *tbl, uint64_t current)
{
	struct cds_lfht_iter iter;
	struct apt_tuple *at;

	if (rte_atomic32_read(&tbl->at_count) == 0)
		return;

	cds_lfht_for_each_entry(tbl->at_ht, &iter, at, at_node) {
		if (apt_tuple_is_expired(at, current)) {
			if (at->at_removing)
				apt_tuple_delete(tbl, at);
			else
				at->at_removing = true;
		}
	}
}

/*
 * Garbage collect instance
 */
static void apt_instance_gc(struct apt_instance *ai)
{
	uint64_t current = get_time_uptime();

	apt_table_gc(&ai->ai_all, current);
	apt_table_gc(&ai->ai_any_sport, current);
	apt_table_gc(&ai->ai_dport, current);
}

/*
 * Garbage collector
 */
static void apt_gc(struct rte_timer *timer __unused, void *arg __unused)
{
	struct npf_alg_instance *ai;
	struct apt_instance *ai_apt;
	struct vrf *vrf;
	vrfid_t vrfid;

	VRF_FOREACH(vrf, vrfid) {
		ai = vrf_get_npf_alg(vrf);
		if (!ai)
			continue;

		ai_apt = ai->ai_apt;
		if (!ai_apt)
			continue;

		apt_instance_gc(ai_apt);
	}

	/* Restart timer if dataplane still running */
	if (running)
		rte_timer_reset(&apt_timer,
				APT_GC_INTERVAL * rte_get_timer_hz(),
				SINGLE, rte_get_master_lcore(), apt_gc,
				NULL);
}

/*
 * APT timer is started when first instance is created, and stopped when last
 * instance is destroyed.
 */
static void apt_init(void)
{
	rte_timer_init(&apt_timer);
	rte_timer_reset(&apt_timer,
			APT_GC_INTERVAL * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), apt_gc,
			NULL);
}

static void apt_uninit(void)
{
	rte_timer_stop_sync(&apt_timer);
}
