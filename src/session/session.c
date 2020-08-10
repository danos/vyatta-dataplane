/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <rte_atomic.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_timer.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "dp_event.h"
#include "dp_session.h"
#include "if_var.h"
#include "main.h"
#include "netinet6/in6.h"
#include "npf_shim.h"
#include "netinet6/ip6_funcs.h"
#include "pktmbuf_internal.h"
#include "session.h"
#include "session_feature.h"
#include "urcu.h"
#include "vplane_log.h"
#include "npf_pack.h"

/*
 * Session implementation for dataplane features.
 *
 * A session is an object designed to track all the forward and
 * reverse packets for a flow, regardless of which interfaces the packets
 * traverse or which packet manipulations occur in the dataplane.
 *
 * Sessions can be created for All IPv4 and IPv6 protocols.
 * However for ICMP/ICMPV6, only echo request/response (ping/pong) are
 * supported.
 *
 * Sessions are created by features in response to their configuration and
 * their need to manage flow state for the lifetime of the flow. Once created,
 * a feature must explicitly perform a session lookup to obtain a
 * session.
 *
 * When a session is created, or accessed, the session is cached on the
 * packet so future lookups for that session can be avoided for the lifetime
 * of the packet in the dataplane.
 *
 * Mechanisms exist to allow various dataplane features to manage all of
 * flow-specific data or interface-specific data to the session handle.
 *
 * The relation of these objects looks like this:
 *
 *  ----------                             -----------
 * | session  | <------------------------>| interface |
 * |          |                      |    |  feature  |
 *                                        |   object  |
 *  ----------                       |     -----------
 *      ^                            |     -----------
 *      |            ----------      |    | interface |
 *       ---------->|   flow   |     ---->|  feature  |
 *      |           |  feature |          |  object   |
 *      |           |  object  |           -----------
 *      |            ----------
 *      |            ----------
 *       ---------->|   flow   |
 *                  |  feature |
 *                  |  object  |
 *                   ----------
 *
 * In general, features access their objects with a well-known identifier
 * identifier used in an hash table.
 *
 * Note that a single session can be referenced in multiple forwarding threads
 * and multiple instances of the same feature concurrently.  Think of
 * the multicast case as an example.  Consequently the implementation makes
 * use of several RCU hash tables to provide for a lockless management of
 * the various objects.
 *
 * Sessions can also manage feature data on either session, or
 * session/interface basis.  It is up to the feature to decide
 * which is appropriate.
 *
 * What all this means is that there are, in general, a minimum of two
 * lookups involved in obtaining data for a flow - One for the session
 * lookup and one for the particular feature datum. This is sometimes
 * mitigated by the session caching on the packet (assuming a packet
 * hits on multiple features in its path).
 *
 * Features adding data to a session have the option of including a set of
 * 'session operations' along with the data.  These operations are executed
 * when the session changes state so the feature can be notified for such
 * things as freeing state during session destruction, etc.
 *
 * Sessions also have a specific timeout period.  If packets for the flow
 * are not received in a timely manner, a session will timeout and be reclaimed.
 * One exception to this is if the session is linked (meaning it is a
 * either parent to a child, or a child), then the session will
 * remain after its timeout period until the children have
 * timed out.
 *
 * There are two reference counts associated with a session - a sentry count
 * and a link count.  As mentioned above, the link count must be cleared
 * for a session to timeout and/or be reclaimed by the sentry table GC.
 *
 * Once all sentry and link counts go to zero, the sentry table GC will
 * reclaim the session.
 *
 * We use two hash tables for managing sessions, one for the sentries
 * themselves and another for sessions.  The session table is
 * used for displaying sessions for the op mode command.
 *
 * Sessions are live as their sentries are inserted and exist until they either
 * go idle and timeout, or the get marked as expired.
 *
 * All session and feature data are always freed asynchronously in a
 * call_rcu context.  At the point of feature datum free, the feature
 * is guaranteed that no inflight access can occur.
 */

/* Session id */
static rte_atomic64_t	session_id;

/*
 * For UT cleanup, we need to wait until the call_rcu context
 * executes and cleansup everything.  Use a counter so
 * we can poll.
 */
rte_atomic32_t session_rcu_counter;

/*
 * For all supported protocols, we only need and reference the first two 32bit
 * words of the L4 header to obtain the sentry ids for matching.
 */

/* For port-based protos. */
struct ports {
	uint16_t	p_sport;
	uint16_t	p_dport;
};

/*
 * Session hash table buckets.
 * Must be powers of 2.
 */
#define SENTRY_HT_INIT	4096
#define SENTRY_HT_MIN	4096
#define SENTRY_HT_MAX	1048576

/* GC Interval (seconds) */
#define SENTRY_GC_INTERVAL	5

/* Sentry and session hash tables */
struct cds_lfht *sentry_ht;
struct cds_lfht *session_ht;

/* GC Timer */
struct rte_timer session_gc_timer;

/* For GC... */
static inline int time_after(time_t t0, time_t t1)
{
	return (int)(t0 - t1) > 0;
}

/* Direction of sentry */
#define sentry_is_forw(s)  (((s)->sen_flags & SENTRY_FORW) ? true : false)

/* Max entries in the session table */
#define DEFAULT_MAX_SESSIONS 1048576
static rte_atomic32_t	sessions_used;
static int32_t		sessions_max = DEFAULT_MAX_SESSIONS;
static bool		session_gc_run = true;

static int32_t		user_data_id = -1;

/* Global session logging configuration */
static struct session_log_cfg session_global_log_cfg;

static void sentry_rcu_free(struct rcu_head *h)
{
	rte_atomic32_dec(&session_rcu_counter);
	free(caa_container_of(h, struct sentry, sen_rcu_head));
}

static void session_rcu_free(struct rcu_head *h)
{
	struct session *s = caa_container_of(h, struct session, se_rcu_head);

	/*
	 * Feature destroy references sessions, so just requeue if
	 * features are outstanding
	 */
	if (rte_atomic16_read(&s->se_feature_count))
		call_rcu(&s->se_rcu_head, session_rcu_free);

	rte_atomic32_dec(&session_rcu_counter);
	free(s->se_link);
	free(s);
}

/* Walk function for counting features */
static int se_feature_count(struct session *s,
		struct session_feature *sf, void *data)
{
	struct session_counts *sc = data;

	/* Count the feature type */
	sc->sc_feature_counts[sf->sf_type]++;

	/*
	 * Special case for NPF features, handle NAT counts
	 * across multiple interfaces.
	 *
	 * This shows up as separate NPF features on this dataplane session
	 */
	if (sf->sf_type == SESSION_FEATURE_NPF) {
		sc->sc_nat += npf_feature_is_nat(sf->sf_data) ? 1 : 0;
		sc->sc_nat64 += session_is_nat64(s) ? 1 : 0;
		sc->sc_nat46 += session_is_nat46(s) ? 1 : 0;
	}

	return 0;
}

/* Walk function for count natted sessions  (for UTs) */
static int se_counts(struct session *s, void *data)
{
	struct session_counts *sc = data;

	/*
	 * Get feature counts for this session
	 */
	session_feature_walk_session(s, SESSION_FEATURE_ALL, se_feature_count,
			data);

	switch (s->se_protocol) {
	case IPPROTO_TCP:
		sc->sc_tcp += 1;
		break;
	case IPPROTO_UDP:
		sc->sc_udp += 1;
		break;
	case IPPROTO_ICMP:
		sc->sc_icmp += 1;
		break;
	case IPPROTO_ICMPV6:
		sc->sc_icmp6 += 1;
		break;
	default:
		sc->sc_other += 1;
		break;
	}
	return 0;
}

/* walk function for logging features */
static int se_feature_log(struct session *s, struct session_feature *sf,
			  void *data)
{
	enum session_log_event *evp = data;

	if (sf->sf_ops && sf->sf_ops->log)
		sf->sf_ops->log(*evp, s, sf);

	return 0;
}

static void session_log(struct session *s, enum session_log_event log_event)
{
	session_feature_walk_session(s, SESSION_FEATURE_ALL, se_feature_log,
				     &log_event);
}

/* Get an entry for a new session, check against max limit */
static ALWAYS_INLINE int slot_get(void)
{
	if (rte_atomic32_add_return(&sessions_used, 1) <= sessions_max)
		return 0;

	rte_atomic32_dec(&sessions_used);
	if (net_ratelimit() && session_gc_run) {
		session_gc_run = false;
		RTE_LOG(ERR, DATAPLANE,
			"Session table limit reached. Used: %u Max: %u\n",
			rte_atomic32_read(&sessions_used), sessions_max);
	}
	return -ENOSPC;
}

/*
 * sentry flag sanity.
 * Must have one of IPv4/6 and FORW/BACK.
 */
static inline int sentry_flag_sanity(uint16_t flags)
{
	const uint16_t flg_fam = flags & (SENTRY_IPv4 | SENTRY_IPv6);
	const uint16_t flg_dir = flags & (SENTRY_FORW | SENTRY_BACK);

	if (!flg_fam || flg_fam == (SENTRY_IPv4 | SENTRY_IPv6))
		return -EINVAL;

	if (flg_dir == (SENTRY_FORW | SENTRY_BACK))
		return -EINVAL;

	return 0;
}

static inline void cache_sentry(struct rte_mbuf *m, struct sentry *sen)
{
	struct pktmbuf_mdata *mdata = pktmbuf_mdata(m);
	mdata->md_sentry = sen;
	pktmbuf_mdata_set(m, PKT_MDATA_SESSION_SENTRY);
}

/* Return entry to max limit */
static ALWAYS_INLINE void slot_put(void)
{
	rte_atomic32_dec(&sessions_used);
}

static void expire_kids(struct session *s);

/* Expire a session */
static ALWAYS_INLINE
void se_expire(struct session *s)
{
	uint16_t exp = s->se_flags & ~SESSION_EXPIRED;

	if (rte_atomic16_cmpset(&s->se_flags, exp, (exp | SESSION_EXPIRED)))
		session_feature_session_expire(s);
}

static inline void sl_unlink(struct session_link *sl)
{
	if (rte_atomic16_dec_and_test(&sl->sl_refcnt)) {
		cds_list_del_init(&sl->sl_link);
		rte_atomic16_dec(&sl->sl_parent->se_link_cnt);
		rte_atomic16_set(&sl->sl_refcnt, 1);
		sl->sl_parent = NULL;
	}
}

/* Recursively unlink and destroy all children */
static void expire_kids(struct session *s)
{
	struct session_link *child;
	struct session_link *tmp;
	struct session_link *sl = rcu_dereference(s->se_link);

	if (!sl)
		return;

	rte_spinlock_lock(&sl->sl_lock);
	cds_list_for_each_entry_safe(child, tmp, &sl->sl_children, sl_link) {
		se_expire(child->sl_self);
		expire_kids(child->sl_self);
		sl_unlink(child);
	}
	rte_spinlock_unlock(&sl->sl_lock);
}

/* Reclaim session once all sentries are gone */
static void session_reclaim(struct session *s)
{
	/*
	 * N.B. This routine is called from both the GC as well
	 * as during runtime in the event that a session_establish()
	 * fails (session not inserted in this case).
	 *
	 * All we need to do here is ensure that exactly one thread sees
	 * a zero sentry count to know we need to reclaim it.
	 *
	 * Setting the refcount to non-zero is safe as once we have
	 * passed this point, it is guaranteed that the session will
	 * be deleted.
	 */
	if (rte_atomic16_test_and_set(&s->se_sen_cnt)) {
		slot_put();
		if (s->se_flags & SESSION_INSERTED)
			cds_lfht_del(session_ht, &s->se_node);
		rte_atomic32_inc(&session_rcu_counter);
		call_rcu(&s->se_rcu_head, session_rcu_free);
	}
}

/* Unlink a sentry from the hash tables and reclaim. */
static ALWAYS_INLINE
void sentry_delete(struct sentry *sen)
{
	if (!cds_lfht_del(sentry_ht, &sen->sen_node)) {
		if (sen->sen_session->se_sen == sen) {
			/* Clear INIT sentry cache */
			sen->sen_session->se_sen = NULL;
		}
		rte_atomic16_dec(&sen->sen_session->se_sen_cnt);
		rte_atomic32_inc(&session_rcu_counter);
		call_rcu(&sen->sen_rcu_head, sentry_rcu_free);
	}
}

/*
 * Determine a sessions time-to-expire.  Note that this can go negative due
 * the periodic nature of the garbage collection.  Used by show command.
 */
int sess_time_to_expire(const struct session *s)
{
	int tmp;

	if (s->se_flags & SESSION_EXPIRED)
		tmp = 0;
	else if (!s->se_etime)
		tmp = s->se_custom_timeout ?
			s->se_custom_timeout : s->se_timeout;
	else
		tmp = (int) (s->se_etime - get_dp_uptime());

	return tmp;
}

/* Get etime based on config */
static inline uint32_t se_timeout(struct session *s)
{
	return (s->se_custom_timeout) ?  s->se_custom_timeout : s->se_timeout;
}

/* Determine whether this session is still valid */
static ALWAYS_INLINE
int reclaim_session(struct session *s, uint64_t uptime)
{
	int rc = 0;

	/* Expired is the same as a timeout */
	if (s->se_flags & SESSION_EXPIRED) {
		return 1;
	}

	if (!s->se_idle) {
		/* Session not idle, update etime */
		s->se_idle = 1;
		s->se_etime = uptime + se_timeout(s);
	} else {
		/* Session idle, expired? */
		if (time_after(uptime, s->se_etime)) {
			se_expire(s);
			/* Expire features now, as we are called from GC */
			session_feature_session_expire_requested(s);
			rc = 1;
		}
	}

	return rc;
}

/* GC worker routine, Reclaim expired/timedout sessions */
static void sentry_gc_inspect(struct sentry *sen, uint64_t uptime)
{
	struct session *s = sen->sen_session;

	if (s->se_log_creation) {
		s->se_log_creation = 0;
		session_log(s, SESSION_LOG_CREATION);
	}

	if (s->se_log_periodic && time_after(uptime, s->se_ltime)) {
		s->se_ltime = uptime + s->se_log_interval;
		session_log(s, SESSION_LOG_PERIODIC);
	}

	/*
	 * Expire features that requested it.
	 */
	if (rte_atomic16_read(&s->se_feature_exp_count))
		session_feature_session_expire_requested(s);

	/*
	 * If we have children then do nothing, a parent session
	 * must exist until children are removed.
	 */
	if (rte_atomic16_read(&s->se_link_cnt))
		return;

	/*
	 * Session reclaimed after all children are unlinked,
	 * and all sentries reclaimed
	 */
	if (reclaim_session(s, uptime)) {
		s->se_log_periodic = 0;
		sentry_delete(sen);
		session_reclaim(s);
	}
}

static void sentry_gc_walk(uint64_t uptime)
{
	struct cds_lfht_iter iter;
	struct sentry *sen;

	/* No point */
	if (!rte_atomic32_read(&sessions_used))
		return;

	/* Clean the sentry table */
	cds_lfht_for_each_entry(sentry_ht, &iter, sen, sen_node)
		sentry_gc_inspect(sen, uptime);

	/*
	 * Reduce msg flood on a full session table.
	 * See if we cleared some slots.  This will only limit
	 * the number of error msgs until the next time GC is run.
	 */
	if (rte_atomic32_read(&sessions_used) < sessions_max)
		session_gc_run = true;
}

static void
sentry_gc(struct rte_timer *timer __rte_unused, void *arg __rte_unused)
{
	uint64_t uptime = get_dp_uptime();

	/* Walk the sentry table */
	sentry_gc_walk(uptime);

	/* Do it again, as long as we are running */
	if (running)
		rte_timer_reset(&session_gc_timer,
				SENTRY_GC_INTERVAL * rte_get_timer_hz(),
				SINGLE, rte_get_master_lcore(),
				sentry_gc, NULL);
}

static int sentry_match(struct cds_lfht_node *node, const void *key)
{
	const struct sentry *sen = caa_container_of(node, struct sentry,
			sen_node);
	struct session *s = sen->sen_session;
	const struct sentry_packet *sp = key;
	int i;

	/* Deal with expire race */
	if (s->se_flags & SESSION_EXPIRED)
		return 0;

	if (sp->sp_ifindex != sen->sen_ifindex)
		return 0;
	/* Account for IPv4 vs. IPv6 */
	if (sp->sp_len != sen->sen_len)
		return 0;
	if (sp->sp_protocol != sen->sen_protocol)
		return 0;

	/*
	 * Note that VRF IDs are not compared, as they may differ
	 * if VRF leaking is used.
	 */

	/* Faster than memcmp */
	for (i = 0; i < sp->sp_len; i++)
		if (sp->sp_addrids[i] != sen->sen_addrids[i])
			return 0;
	return 1;
}

static ALWAYS_INLINE
unsigned long sentry_hash(const struct sentry_packet *sp)
{
	unsigned long hash;

	hash = rte_jhash_1word(sp->sp_protocol, sp->sp_ifindex);
	return rte_jhash_32b(sp->sp_addrids, sp->sp_len, hash);
}

/*
 * sentry_table_lookup - Lookup a session based on a
 * packet decomp.
 */
static int sentry_table_lookup(const struct sentry_packet *sp,
		struct sentry **sen)
{
	unsigned long hash;
	struct cds_lfht_node *snode;
	struct cds_lfht_iter iter;

	/* Any? */
	if (!rte_atomic32_read(&sessions_used))
		return -ENOENT;

	hash = sentry_hash(sp);
	cds_lfht_lookup(sentry_ht, hash, sentry_match, sp, &iter);
	snode = cds_lfht_iter_get_node(&iter);
	if (!snode)
		return -ENOENT;

	*sen = caa_container_of(snode, struct sentry, sen_node);
	return 0;
}

/* Insert a sentry into the table */
static int sentry_insert(const struct sentry_packet *sp, struct sentry *sen,
		struct sentry **old)
{
	struct cds_lfht_node *node;
	struct session *s = sen->sen_session;

	node = cds_lfht_add_unique(sentry_ht, sentry_hash(sp), sentry_match,
			sp, &sen->sen_node);
	if (node != &sen->sen_node) {
		*old = caa_container_of(node, struct sentry, sen_node);
		return -EEXIST;
	}

	/* session sentry count */
	rte_atomic16_inc(&s->se_sen_cnt);

	return 0;
}

/* Walk the session table and issue the callback.  */
int session_table_walk(session_walk_t cb, void *data)
{
	struct cds_lfht_iter iter;
	struct session *s;
	int rc = 0;

	if (!cb)
		return -ENOENT;

	cds_lfht_for_each_entry(session_ht, &iter, s, se_node) {
		rc = cb(s, data);
		if (rc)
			break;
	}
	return rc;
}

/* Walk the sentry table and issue the callback.  */
int sentry_table_walk(sentry_walk_t cb, void *data)
{
	struct cds_lfht_iter iter;
	struct sentry *sen;
	int rc = 0;

	if (!cb)
		return -ENOENT;

	cds_lfht_for_each_entry(sentry_ht, &iter, sen, sen_node) {
		rc = cb(sen, data);
		if (rc)
			break;
	}
	return rc;
}

static void se_link_walk(struct session *s, bool do_unlink,
		session_link_walk_t *cb, void *data)
{
	struct session_link *child;
	struct session_link *tmp;
	struct session_link *sl;

	sl = rcu_dereference(s->se_link);

	/* Walk the list and apply both unlink and cb.  */
	rte_spinlock_lock(&sl->sl_lock);
	cds_list_for_each_entry_safe(child, tmp, &sl->sl_children, sl_link) {
		se_link_walk(child->sl_self, do_unlink, cb, data);
		if (do_unlink)
			sl_unlink(child);
		cb(child->sl_self, data);
	}
	rte_spinlock_unlock(&sl->sl_lock);
}


/*
 * Walk the linked list of sessions and
 * execute 'cb'/unlink for each session found.
 */
void session_link_walk(struct session *s, bool do_unlink,
		session_link_walk_t *cb, void *data)
{
	struct session_link *sl;

	if (!s)
		return;

	sl = rcu_dereference(s->se_link);
	if (!sl)
		return; /* Not linked */

	/* Deal with children first */
	se_link_walk(s, do_unlink, cb, data);

	if (do_unlink)
		session_unlink(s);
	cb(s, data);
}

/*
 * Destroy the contents of the session table.
 * Used by UTs to cleanup between tests.
 */
int session_table_destroy_all(void)
{
	long dummy;
	unsigned long count;
	struct cds_lfht_iter iter;
	struct sentry *sen;

	/*
	 * Forcibly delete all existing sessions by
	 * arbitrarily expiring them.
	 *
	 * Simulates session GC/explicit expiration and ensures that we
	 * perform cleanup correctly.
	 */
	if (rte_atomic32_read(&sessions_used)) {
		cds_lfht_for_each_entry(sentry_ht, &iter, sen, sen_node) {
			se_expire(sen->sen_session);
			sentry_gc_inspect(sen, 0);
		}

		/*
		 * Poll the rcu counter to ensure that all
		 * call_rcu items have been cleaned up.
		 */
		while (rte_atomic32_read(&session_rcu_counter))
			usleep(1000);
	}

	/* For UT purposes, ensure we have nothing left. */
	cds_lfht_count_nodes(sentry_ht, &dummy, &count, &dummy);
	return count;
}

/* Get counts of nodes in sentry and session ht's - for UTs */
void session_table_counts(unsigned long *sen_ht, unsigned long *sess_ht)

{
	long dummy;

	cds_lfht_count_nodes(sentry_ht, &dummy, sen_ht, &dummy);
	cds_lfht_count_nodes(session_ht, &dummy, sess_ht, &dummy);
}

/*
 * Get various counts of the sessions and features
 */
void session_counts(uint32_t *used, uint32_t *max, struct session_counts *sc)
{
	*used = rte_atomic32_read(&sessions_used);
	*max = sessions_max;

	session_table_walk(se_counts, sc);
}

/* Set the max session limit */
void session_set_max_sessions(uint32_t count)
{
	sessions_max = count ? count : DEFAULT_MAX_SESSIONS;
}

void session_set_global_logging_cfg(struct session_log_cfg *scfg)
{
	session_global_log_cfg = *scfg;
}

/* Init the hash tables */
static void init_tables(void)
{
	sentry_ht = cds_lfht_new(SENTRY_HT_INIT, SENTRY_HT_MIN, SENTRY_HT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);

	rte_timer_init(&session_gc_timer);
	rte_timer_reset(&session_gc_timer,
			SENTRY_GC_INTERVAL * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), sentry_gc, NULL);

	session_ht = cds_lfht_new(SENTRY_HT_INIT, SENTRY_HT_MIN, SENTRY_HT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
}

static ALWAYS_INLINE
void ids_set(uint32_t *loc, uint16_t sid, uint16_t did)
{
	*loc = sid << 16 | did;
}

static ALWAYS_INLINE
void ids_extract(uint32_t *loc, uint16_t *sid, uint16_t *did)
{
	*sid = *loc >> 16;
	*did = *loc & 0xFFFF;
}

/*
 * Parse ids from the L4 header.
 * Note we only need the first two words of the header.
 */
static int se_parse_ids(struct rte_mbuf *m,
		uint16_t off, uint8_t ipproto, uint16_t *sid,
		uint16_t *did)
{
	unsigned char buf[8];
	void *l4;

	/*
	 * The ids (ports/etc)
	 *
	 * For all protocols, we support, that require an id, we can
	 * obtain the id from the first two (32bit) words of the
	 * protocol header.
	 *
	 * However, we can only count on the IP header in the
	 * first segment, so we may need to copy.
	 */
	l4 = (void *)rte_pktmbuf_read(m, off, sizeof(buf), buf);

	switch (ipproto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_DCCP:
	case IPPROTO_SCTP:
		{
			if (!l4)
				return -EINVAL;

			struct ports *p = l4;

			/* src/dst ports */
			*sid = p->p_sport;
			*did = p->p_dport;
			break;
		}
	case IPPROTO_ICMP:
		/* Only for Echo Request/Reply */
		{
			if (!l4)
				return -EINVAL;

			struct icmp *ic = l4;

			if (ic->icmp_type == ICMP_ECHO ||
				ic->icmp_type == ICMP_ECHOREPLY) {
				*sid = ic->icmp_id;
				*did = ic->icmp_id;
			} else
				return -EPERM;
		}
		break;
	case IPPROTO_ICMPV6:
		/* Again, only for Echo Request/Reply */
		{
			if (!l4)
				return -EINVAL;

			struct icmp6_hdr *ic6 = l4;

			if (ic6->icmp6_type == ICMP6_ECHO_REQUEST ||
					ic6->icmp6_type == ICMP6_ECHO_REPLY) {
				*sid = ic6->icmp6_id;
				*did = ic6->icmp6_id;
			} else
				return -EPERM;
		}
		break;
	default: /* All other IP protocols */
		*sid = 0;
		*did = 0;
		break;
	}

	return 0;
}

static int pkt_parse_ipv4(struct rte_mbuf *m, uint32_t if_index,
		struct sentry_packet *sp)
{
	struct iphdr *ip;
	unsigned char buf[sizeof(struct iphdr)];
	unsigned int off;
	int rc;
	uint16_t sid;
	uint16_t did;

	/* Ensure IP header is available */
	off = dp_pktmbuf_l2_len(m);
	ip = (struct iphdr *)rte_pktmbuf_read(m, off,
					      sizeof(struct iphdr), buf);
	if (!ip)
		return -EINVAL;

	sp->sp_ifindex = if_index;
	sp->sp_protocol = ip->protocol;

	sp->sp_sentry_flags = SENTRY_IPv4;
	sp->sp_vrfid = pktmbuf_get_vrf(m);

	/* Length of the array match */
	sp->sp_len = SENTRY_LEN_IPV4;

	off = dp_pktmbuf_l2_len(m) + dp_pktmbuf_l3_len(m);
	rc = se_parse_ids(m, off, ip->protocol, &sid, &did);
	if (rc)
		return rc;

	/*
	 * Now pack the 'addrids' array:
	 * - ids are first word
	 * - source addr
	 * - dest addr
	 */
	ids_set(&sp->sp_addrids[0], sid, did);
	sp->sp_addrids[1] = ip->saddr;
	sp->sp_addrids[2] = ip->daddr;

	return 0;
}

static int pkt_parse_ipv6(struct rte_mbuf *m, uint32_t if_index,
		struct sentry_packet *sp)
{
	uint16_t off;
	uint8_t ipproto;
	uint16_t sid;
	uint16_t did;
	int rc;

	/*
	 * Skip to the payload header and copy the two words
	 * we need for the sentry ids.
	 */
	ipproto = ip6_findpayload(m, &off);

	sp->sp_ifindex = if_index;
	sp->sp_protocol = ipproto;
	sp->sp_sentry_flags = SENTRY_IPv6;
	sp->sp_vrfid = pktmbuf_get_vrf(m);

	/* Length of the array match */
	sp->sp_len = SENTRY_LEN_IPV6;

	struct ip6_hdr *ip6 = ip6hdr(m);

	rc = se_parse_ids(m, off, ipproto, &sid, &did);
	if (rc)
		return rc;

	/*
	 * Now pack 'addrids':
	 * - ids first
	 * - source addr
	 * - dest addr
	 */
	ids_set(&sp->sp_addrids[0], sid, did);

	sp->sp_addrids[1] = ip6->ip6_src.s6_addr32[0];
	sp->sp_addrids[2] = ip6->ip6_src.s6_addr32[1];
	sp->sp_addrids[3] = ip6->ip6_src.s6_addr32[2];
	sp->sp_addrids[4] = ip6->ip6_src.s6_addr32[3];

	sp->sp_addrids[5] = ip6->ip6_dst.s6_addr32[0];
	sp->sp_addrids[6] = ip6->ip6_dst.s6_addr32[1];
	sp->sp_addrids[7] = ip6->ip6_dst.s6_addr32[2];
	sp->sp_addrids[8] = ip6->ip6_dst.s6_addr32[3];

	return 0;
}

int sentry_packet_from_mbuf(struct rte_mbuf *m, uint32_t if_index,
			    struct sentry_packet *sp)
{
	const struct iphdr *ip = iphdr(m);

	switch (ip->version) {
	case 4:
		return pkt_parse_ipv4(m, if_index, sp);
		break;
	case 6:
		return pkt_parse_ipv6(m, if_index, sp);
		break;
	}

	return -EINVAL;
}

/* Return a session cached on a packet */
static int get_packet_session(struct rte_mbuf *m, uint32_t if_index,
		struct session **se, bool *forw)
{
	struct pktmbuf_mdata *mdata;
	struct sentry *sen;
	struct session *s;

	/* packet cache? */
	if (!pktmbuf_mdata_exists(m, PKT_MDATA_SESSION_SENTRY))
		return -ENOENT;

	mdata = pktmbuf_mdata(m);
	sen = mdata->md_sentry;
	s = sen->sen_session;

	if (s->se_flags & SESSION_EXPIRED || sen->sen_ifindex != if_index) {
		pktmbuf_mdata_clear(m, PKT_MDATA_SESSION_SENTRY);
		return -ENOENT;
	}

	*forw = sentry_is_forw(sen);

	if (s->se_idle)
		s->se_idle = 0;

	*se = s;
	return 0;
}

/* Find a session either in the packet cache, or the hash table.  */
int session_lookup(struct rte_mbuf *m, uint32_t if_index,
		struct session **se, bool *forw)
{
	struct sentry *sen;
	struct sentry_packet sp;
	int rc;

	/* packet cache? */
	if (!get_packet_session(m, if_index, se, forw))
		return 0;

	rc = sentry_packet_from_mbuf(m, if_index, &sp);
	if (rc)
		return rc;

	/*
	 * Lookup.  Its possible that after the lookup, the state
	 * changes to expired, that's ok, we are considered in-flight.
	 *
	 * matching the forw or back sentry sets the packet direction.
	 */
	rc = sentry_table_lookup(&sp, &sen);
	if (rc)
		return rc;

	/* Post lookup packet operations */
	cache_sentry(m, sen);
	*forw = sentry_is_forw(sen);

	struct session *s = sen->sen_session;
	if (s->se_idle)
		s->se_idle = 0;
	*se = s;
	return 0;
}

static struct sentry *sentry_create(struct session *s,
		uint16_t flag, struct sentry_packet *sp)
{
	struct sentry *sen;
	size_t sz;
	int i;

	sz = sizeof(struct sentry) + (sp->sp_len * sizeof(uint32_t));
	sen = malloc(sz);
	if (!sen)
		return NULL;

	cds_lfht_node_init(&sen->sen_node);
	sen->sen_session = s;
	sen->sen_ifindex = sp->sp_ifindex;
	sen->sen_flags = flag | sp->sp_sentry_flags;
	sen->sen_len = sp->sp_len;
	sen->sen_protocol = sp->sp_protocol;

	if ((sp->sp_sentry_flags & SENTRY_IPv6 &&
	     sp->sp_len > SENTRY_LEN_IPV6) ||
	    (sp->sp_sentry_flags & SENTRY_IPv4 &&
	     sp->sp_len > SENTRY_LEN_IPV4)) {
		free(sen);
		return NULL;
	}

	for (i = 0; i < sp->sp_len; i++)
		sen->sen_addrids[i] = sp->sp_addrids[i];

	return sen;
}

/* Reverse a sentry packet decomp */
void sentry_packet_reverse(struct sentry_packet *sp, struct sentry_packet *rsp)
{
	uint16_t sid;
	uint16_t did;

	rsp->sp_ifindex = sp->sp_ifindex;
	rsp->sp_sentry_flags = sp->sp_sentry_flags;
	rsp->sp_vrfid = sp->sp_vrfid;
	rsp->sp_protocol = sp->sp_protocol;
	rsp->sp_len = sp->sp_len;

	/* Reverse ids */
	ids_extract(&sp->sp_addrids[0], &sid, &did);
	ids_set(&rsp->sp_addrids[0], did, sid);

	/* reverse addrs */
	if (rsp->sp_sentry_flags & SENTRY_IPv4) {
		rsp->sp_addrids[1] = sp->sp_addrids[2];
		rsp->sp_addrids[2] = sp->sp_addrids[1];
	} else {
		rsp->sp_addrids[1] = sp->sp_addrids[5];
		rsp->sp_addrids[2] = sp->sp_addrids[6];
		rsp->sp_addrids[3] = sp->sp_addrids[7];
		rsp->sp_addrids[4] = sp->sp_addrids[8];

		rsp->sp_addrids[5] = sp->sp_addrids[1];
		rsp->sp_addrids[6] = sp->sp_addrids[2];
		rsp->sp_addrids[7] = sp->sp_addrids[3];
		rsp->sp_addrids[8] = sp->sp_addrids[4];
	}
}


static int sentry_packet_insert(struct session *s, uint16_t flags,
		struct sentry_packet *sp, struct sentry **sen, bool *created)
{
	struct sentry *ss;
	int rc;

	ss = sentry_create(s, flags, sp);
	if (!ss)
		return -ENOMEM;

	rc = sentry_insert(sp, ss, sen);
	if (rc) {
		free(ss);

		/*
		 * Ignore attempts to insert a duplicate sentry for
		 * an existing session.
		 */
		if ((rc == -EEXIST) && (s == (*sen)->sen_session)) {
			*created = false;
			rc = 0;
		}
		return rc;
	}
	*created = true;
	*sen = ss;
	return rc;
}

/* Create and add the forw and back sentries */
static int sentry_packet_insert_both(struct session *s,
		struct sentry_packet *sp_forw,
		struct sentry_packet *sp_back, uint16_t init_flag,
		struct sentry **sen_forwp, bool *created)
{
	struct sentry *sen_back;
	struct sentry *sen_forw;
	int rc;

	/*
	 * Add sentry init flag, means this is the
	 * initial sentry for a session. Referenced when
	 * we walk the table
	 *
	 * If we find the session already exists, return now.
	 */
	rc = sentry_packet_insert(s, (SENTRY_FORW | init_flag), sp_forw,
			&sen_forw, created);
	if (rc)
		return rc;

	*sen_forwp = sen_forw;

	if (!created)
		return 0;

	/* Create and add the back sentry */
	rc = sentry_packet_insert(s, SENTRY_BACK, sp_back, &sen_back, created);
	if (rc) {
		sentry_delete(sen_forw);
		return rc;
	}

	/*
	 * For the 'show session-table' commands, we need the initial sentry,
	 * so store it directly on the session.
	 */
	if ((init_flag & SENTRY_INIT) && !s->se_sen)
		s->se_sen = sen_forw;

	return rc;
}

static struct session *se_alloc(void)
{
	struct session *s;

	s = zmalloc_aligned(sizeof(struct session));
	if (s) {
		cds_lfht_node_init(&s->se_node);
		s->se_id = rte_atomic64_add_return(&session_id, 1);
	}

	return s;
}

/* Initialise the logging requirements of the session */
static void se_init_logging(struct session *s)
{
	s->se_log_creation = session_global_log_cfg.slc_log_creation;
	s->se_log_deletion = session_global_log_cfg.slc_log_deletion;
	s->se_log_periodic = session_global_log_cfg.slc_log_periodic;

	if (s->se_log_periodic) {
		s->se_log_interval = session_global_log_cfg.slc_log_interval;
		s->se_ltime = get_dp_uptime() + s->se_log_interval;
	}
}

/* Allocate and init a session */
static struct session *se_create(struct sentry_packet *sp, uint32_t timeout)
{
	struct session *s;

	s = se_alloc();
	if (!s)
		return NULL;

	s->se_protocol = sp->sp_protocol;
	s->se_timeout = timeout;

	s->se_vrfid = sp->sp_vrfid;
	s->se_create_time = rte_get_timer_cycles();
	rte_atomic64_init(&s->se_pkts_in);
	rte_atomic64_init(&s->se_bytes_in);
	rte_atomic64_init(&s->se_pkts_out);
	rte_atomic64_init(&s->se_bytes_out);
	se_init_logging(s);

	return s;
}

/*
 * Establish a session.
 *
 * This will atomically return an existing session, or create one.
 */
int session_establish(struct rte_mbuf *m, const struct ifnet *ifp,
		uint32_t timeout, struct session **se, bool *created)
{
	int rc;
	struct sentry_packet sp_forw, sp_back;

	rc = sentry_packet_from_mbuf(m, ifp->if_index, &sp_forw);
	if (rc)
		return rc;

	sentry_packet_reverse(&sp_forw, &sp_back);

	return session_create_from_sentry_packets(m, &sp_forw, &sp_back,
			ifp, timeout, se, created);
}

/* Set the protocol timeout, and current protocol state */
void session_set_protocol_state_timeout(struct session *s, uint8_t state,
					enum dp_session_state gen_state,
					uint32_t timeout)
{
	s->se_timeout = timeout;
	s->se_protocol_state = state;
	s->se_gen_state = gen_state;
}

/* Set the custom timeout */
void session_set_custom_timeout(struct session *s, uint32_t timeout)
{
	s->se_custom_timeout = timeout;
}

/* Insert forw/back sentries based on packet. */
int session_sentry_insert_pkt(struct session *s, uint32_t if_index,
			      struct rte_mbuf *m)
{
	int rc;
	struct sentry_packet sp_forw, sp_back;
	struct sentry *old;
	bool dummy; /* Unused */

	rc = sentry_packet_from_mbuf(m, if_index, &sp_forw);
	if (rc)
		return rc;

	sentry_packet_reverse(&sp_forw, &sp_back);

	return sentry_packet_insert_both(s, &sp_forw, &sp_back, 0, &old,
					 &dummy);
}

/* Insert another sentry for this session */
int session_sentry_insert(struct session *se, uint32_t if_index, uint16_t flags,
		uint16_t sid, const void *sa,
		uint16_t did, const void *da)
{
	struct sentry_packet sp;
	struct sentry *sen;
	const struct in6_addr *saddr = sa;
	const struct in6_addr *daddr = da;
	bool dummy; /* unused */

	if (sentry_flag_sanity(flags))
		return -EINVAL;

	sp.sp_ifindex = if_index;
	sp.sp_sentry_flags = flags;
	sp.sp_vrfid = se->se_vrfid;
	sp.sp_protocol = se->se_protocol;

	ids_set(&sp.sp_addrids[0], sid, did);
	if (flags & SENTRY_IPv4) {
		sp.sp_len = SENTRY_LEN_IPV4;
		sp.sp_addrids[1] = saddr->s6_addr32[0];
		sp.sp_addrids[2] = daddr->s6_addr32[0];
	} else {
		sp.sp_len = SENTRY_LEN_IPV6;
		sp.sp_addrids[1] = saddr->s6_addr32[0];
		sp.sp_addrids[2] = saddr->s6_addr32[1];
		sp.sp_addrids[3] = saddr->s6_addr32[2];
		sp.sp_addrids[4] = saddr->s6_addr32[3];

		sp.sp_addrids[5] = daddr->s6_addr32[0];
		sp.sp_addrids[6] = daddr->s6_addr32[1];
		sp.sp_addrids[7] = daddr->s6_addr32[2];
		sp.sp_addrids[8] = daddr->s6_addr32[3];
	}

	return sentry_packet_insert(se, 0,  &sp, &sen, &dummy);
}

/* Extract addrs/ids from a sentry */
void session_sentry_extract(struct sentry *sen, uint32_t *if_index, int *af,
		const void **saddr, uint16_t *sid, const void **daddr,
		uint16_t *did)
{
	*if_index = sen->sen_ifindex;
	if (sen->sen_flags & SENTRY_IPv4) {
		*af = AF_INET;
		*saddr = &sen->sen_addrids[1];
		*daddr = &sen->sen_addrids[2];
	} else if (sen->sen_flags & SENTRY_IPv6) {
		*af = AF_INET6;
		*saddr = &sen->sen_addrids[1];
		*daddr = &sen->sen_addrids[5];
	} else {
		*af = 0;
		*saddr = NULL;
		*daddr = NULL;
		*sid = 0;
		*did = 0;
		return;
	}

	ids_extract(&sen->sen_addrids[0], sid, did);
}

/* Extract addrs from a sentry */
void session_sentry_extract_addrs(const struct sentry *sen, int *af,
				  const void **saddr, const void **daddr)
{
	if (sen->sen_flags & SENTRY_IPv4) {
		*af = AF_INET;
		*saddr = &sen->sen_addrids[1];
		*daddr = &sen->sen_addrids[2];
	} else if (sen->sen_flags & SENTRY_IPv6) {
		*af = AF_INET6;
		*saddr = &sen->sen_addrids[1];
		*daddr = &sen->sen_addrids[5];
	} else {
		*af = 0;
		*saddr = NULL;
		*daddr = NULL;
	}
}

/* Destroy a session */
void session_expire(struct session *s, struct rte_mbuf *m)
{
	/* Reset packet cache if we have a pkt. */
	if (m)
		pktmbuf_mdata_clear(m, PKT_MDATA_SESSION_SENTRY);

	/* Set the expired flag  and expire all children */
	se_expire(s);
	expire_kids(s);
}

/* Get/Create a session link struct */
static struct session_link *se_get_session_link(struct session *s)
{

	struct session_link *sl = rcu_dereference(s->se_link);

	/*
	 * N.B. Same session could be concurrently used on
	 * multiple forwarding threads, on multiple interfaces.
	 */
	if (!sl) {
		struct session_link *old;

		sl = malloc(sizeof(struct session_link));
		if (!sl)
			return NULL;
		CDS_INIT_LIST_HEAD(&sl->sl_children);
		CDS_INIT_LIST_HEAD(&sl->sl_link); /* Yes, init this */
		sl->sl_parent = NULL;
		sl->sl_self = s;
		rte_spinlock_init(&sl->sl_lock);
		rte_atomic16_set(&sl->sl_refcnt, 1);
		old = rcu_cmpxchg_pointer(&s->se_link, NULL, sl);

		/* Lost the race?  Use the old */
		if (old) {
			free(sl);
			sl = old;
		}
	}
	return sl;
}

/* Return the top-level parent for a linkage of sessions. */
struct session *session_base_parent(struct session *s)
{
	struct session_link *sl;
	struct session *parent;

	if (!s)
		return NULL;

	sl = s->se_link;
	if (!sl)
		return s;

	rte_spinlock_lock(&sl->sl_lock);
	parent = session_base_parent(sl->sl_parent);
	rte_spinlock_unlock(&sl->sl_lock);

	if (!parent)
		parent = s;
	return parent;
}

/*
 * Session link - Link child to parent
 *
 * Note multiple features can link same child to same parent,
 * we use a ref count.
 */
int session_link(struct session *parent, struct session *child)
{
	struct session_link *psl;
	struct session_link *csl;

	psl = se_get_session_link(parent);
	if (!psl)
		return -ENOMEM;
	csl = se_get_session_link(child);
	if (!csl)
		return -ENOMEM;

	rte_spinlock_lock(&psl->sl_lock);

	/*
	 * Check for expired sessions now, after the lock.
	 *
	 * This prevents a race where main could be expiring sessions
	 * while a link is about to occur.
	 */
	if ((parent->se_flags | child->se_flags) & SESSION_EXPIRED) {
		rte_spinlock_unlock(&psl->sl_lock);
		return -EINVAL;
	}

	/* Already linked? */
	if (csl->sl_parent) {
		/* No cross linking */
		if (csl->sl_parent != parent) {
			rte_spinlock_unlock(&psl->sl_lock);
			return -EPERM;
		}
		rte_spinlock_unlock(&psl->sl_lock);
		rte_atomic16_inc(&csl->sl_refcnt);
		return 0;
	}

	cds_list_add_tail(&csl->sl_link, &psl->sl_children);
	rte_atomic16_inc(&parent->se_link_cnt);
	csl->sl_parent = parent;

	rte_spinlock_unlock(&psl->sl_lock);

	return 0;
}

/* Unlink the session from its parent */
void session_unlink(struct session *s)
{
	struct session_link *sl = rcu_dereference(s->se_link);
	struct session *parent;

	if (sl) {
		parent = sl->sl_parent;
		if (parent) {
			rte_spinlock_lock(&parent->se_link->sl_lock);
			/*
			 * Need to check sl->sl_parent again, as may have
			 * been cleared before we got the lock, due to the
			 * session being unlinked on another thread.
			 */
			sl = rcu_dereference(s->se_link);
			if (sl->sl_parent)
				sl_unlink(sl);
			rte_spinlock_unlock(&parent->se_link->sl_lock);
		}

	}
}

static void se_unlink_children(struct session_link *sl)
{
	struct session_link *child;
	struct session_link *tmp;

	if (sl) {
		rte_spinlock_lock(&sl->sl_lock);
		cds_list_for_each_entry_safe(child, tmp, &sl->sl_children,
								sl_link) {
			se_unlink_children(child);
			sl_unlink(child);
		}
		rte_spinlock_unlock(&sl->sl_lock);
	}
}

/* Unlink all sessions from its parent */
void session_unlink_all(struct session *s)
{
	struct session_link *sl;

	if (s) {
		sl = rcu_dereference(s->se_link);
		if (!sl)
			return;
		se_unlink_children(sl);
		session_unlink(s);
	}
}

/*
 * Initialize a session packet struct via args
 *
 * Flags must indicate IPv4/6.  A session packet always
 * represents a forward packet.
 */
int session_init_sentry_packet(struct sentry_packet *sp, uint32_t if_index,
		uint16_t flags, uint8_t proto, vrfid_t vrfid,
		uint16_t sid, const void *saddr,
		uint16_t did, const void *daddr)
{
	const uint32_t *u32p;

	if (sentry_flag_sanity(flags))
		return -EINVAL;

	sp->sp_ifindex = if_index;
	sp->sp_sentry_flags = flags;

	sp->sp_vrfid = vrfid;
	sp->sp_protocol = proto;

	ids_set(&sp->sp_addrids[0], sid, did);

	if (flags & SENTRY_IPv4) {
		u32p = saddr;
		sp->sp_addrids[1] = *u32p;
		u32p = daddr;
		sp->sp_addrids[2] = *u32p;
		sp->sp_len = SENTRY_LEN_IPV4;
	} else {
		u32p = saddr;
		sp->sp_addrids[1] = *u32p++;
		sp->sp_addrids[2] = *u32p++;
		sp->sp_addrids[3] = *u32p++;
		sp->sp_addrids[4] = *u32p;
		u32p = daddr;
		sp->sp_addrids[5] = *u32p++;
		sp->sp_addrids[6] = *u32p++;
		sp->sp_addrids[7] = *u32p++;
		sp->sp_addrids[8] = *u32p;
		sp->sp_len = SENTRY_LEN_IPV6;
	}

	return 0;
}

/* Create a session based on a sentry packet.  */
int session_create_from_sentry_packets(struct rte_mbuf *m,
		struct sentry_packet *sp_forw,
		struct sentry_packet *sp_back,
		const struct ifnet *ifp, uint32_t timeout,
		struct session **se, bool *created)
{
	int rc;
	struct session *s;
	struct sentry *sen_forw;
	bool forw;

	*created = false;

	/*
	 * Lookup on the packet first, as don't need to create the
	 * dataplane session if it is cached.
	 */
	rc = get_packet_session(m, ifp->if_index, se, &forw);
	if (!rc)
		return sentry_packet_insert_both(*se, sp_forw, sp_back,
				SENTRY_INIT, &sen_forw, created);

	/* Bad doggie, no biscuit */
	if (!timeout)
		return -EINVAL;

	rc = slot_get();
	if (rc)
		return rc;

	s = se_create(sp_forw, timeout);
	if (!s) {
		slot_put();
		return -ENOMEM;
	}

	rc = sentry_packet_insert_both(s, sp_forw, sp_back, SENTRY_INIT,
				       &sen_forw, created);
	if (rc) {
		session_reclaim(s);
		return rc;
	}

	/* Add the session to the session hash table.  */
	cds_lfht_add(session_ht, s->se_id, &s->se_node);
	s->se_flags = SESSION_INSERTED;

	cache_sentry(m, sen_forw);

	*se = s;

	return rc;
}

/* Lookup by sentry packet */
int session_lookup_by_sentry_packet(const struct sentry_packet *sp,
		struct session **se, bool *forw)
{
	struct sentry *sen;
	int rc;

	rc = sentry_table_lookup(sp, &sen);
	if (!rc) {
		*forw = sentry_is_forw(sen);
		*se = sen->sen_session;
	}
	return rc;
}

/* Used by session UTs to simulate the GC clearing out idle sessions */
void session_gc(void)
{
	uint64_t uptime = get_dp_uptime();

	/* Sets the idle flag on each session */
	sentry_gc_walk(uptime);

	/* Simulate time into the future */
	sentry_gc_walk(uptime + (10 * SENTRY_GC_INTERVAL));
}

/* Allocate/init a session struct (for session syncing) */
struct session *session_alloc(void)
{
	return se_alloc();
}

void session_init(void)
{
	init_tables();
	session_feature_init();
}

static int se_vrf_expire(struct session *s, void *data)
{
	vrfid_t *vrfid = data;

	if (s->se_vrfid == *vrfid)
		session_expire(s, NULL);
	return 0;
}

/* Expire sessions for a deleted VRF.  */
static void se_vrf_delete(struct vrf *vrf)
{
	vrfid_t vrfid = vrf->v_id;

	session_table_walk(se_vrf_expire, &vrfid);
}

/* Event ops - Only need these */
static const struct dp_event_ops ops = {
	.vrf_delete = se_vrf_delete,
};

/* Event init  */
static void __attribute__ ((constructor)) session_event_init(void)
{
	dp_event_register(&ops);
}


int session_npf_pack_stats_pack(struct session *s,
				struct npf_pack_session_stats *stats)
{
	if (!s || !stats)
		return -EINVAL;

	stats->se_pkts_in = rte_atomic64_read(&s->se_pkts_in);
	stats->se_bytes_in = rte_atomic64_read(&s->se_bytes_in);
	stats->se_pkts_out = rte_atomic64_read(&s->se_pkts_out);
	stats->se_bytes_out = rte_atomic64_read(&s->se_bytes_out);

	return 0;
}

int session_npf_pack_stats_restore(struct session *s,
				   struct npf_pack_session_stats *stats)
{
	if (!s || !stats)
		return -EINVAL;

	rte_atomic64_set(&s->se_pkts_in, stats->se_pkts_in);
	rte_atomic64_set(&s->se_bytes_in, stats->se_bytes_in);
	rte_atomic64_set(&s->se_pkts_out, stats->se_pkts_out);
	rte_atomic64_set(&s->se_bytes_out, stats->se_bytes_out);

	return 0;
}

int session_npf_pack_sentry_pack(struct session *s,
				 struct npf_pack_sentry *sen)
{
	struct sentry *s_sen;
	struct sentry_packet *sp_forw;
	struct sentry_packet *sp_back;
	struct ifnet *ifp;
	int i;

	if (!s || !sen)
		return -EINVAL;

	s_sen = s->se_sen;
	if (!s_sen)
		return -EINVAL;

	ifp = dp_ifnet_byifindex(s_sen->sen_ifindex);
	if (!ifp)
		return -EINVAL;
	strncpy(sen->ifname, ifp->if_name, IFNAMSIZ);

	sp_forw = &sen->sp_forw;
	sp_forw->sp_sentry_flags = s_sen->sen_flags;
	if (s_sen->sen_flags & SENTRY_IPv4)
		sp_forw->sp_sentry_flags = SENTRY_IPv4;
	else
		sp_forw->sp_sentry_flags = SENTRY_IPv6;
	sp_forw->sp_protocol = s_sen->sen_protocol;
	sp_forw->sp_len = s_sen->sen_len;
	for (i = 0; i < s_sen->sen_len; i++)
		sp_forw->sp_addrids[i] = s_sen->sen_addrids[i];

	sp_back = &sen->sp_back;
	memset(sp_back, 0, sizeof(struct sentry_packet));
	sentry_packet_reverse(sp_forw, sp_back);

	return 0;
}

int session_npf_pack_sentry_restore(struct npf_pack_sentry *sen,
				    struct ifnet **ifp)
{
	struct ifnet *s_ifp;

	if (!sen)
		return -EINVAL;

	s_ifp = dp_ifnet_byifname(sen->ifname);
	if (!s_ifp)
		return -EINVAL;

	sen->sp_forw.sp_vrfid = s_ifp->if_vrfid;
	sen->sp_back.sp_vrfid = s_ifp->if_vrfid;
	sen->sp_forw.sp_ifindex = s_ifp->if_index;
	sen->sp_back.sp_ifindex = s_ifp->if_index;

	*ifp = s_ifp;

	return 0;
}

int session_npf_pack_pack(struct session *s, struct npf_pack_dp_session *dps,
			  struct npf_pack_sentry *sen,
			  struct npf_pack_session_stats *stats)
{
	if (!s || !dps || !sen || !stats)
		return -EINVAL;

	dps->se_id = s->se_id;
	dps->se_flags = s->se_flags;
	dps->se_protocol = s->se_protocol;
	dps->se_custom_timeout = s->se_custom_timeout;
	dps->se_timeout = s->se_timeout;
	dps->se_protocol_state = s->se_protocol_state;
	dps->se_gen_state = s->se_gen_state;
	dps->se_snat = session_is_snat(s);
	dps->se_dnat = session_is_dnat(s);
	dps->se_nat64 = session_is_nat64(s);
	dps->se_nat46 = session_is_nat46(s);
	dps->se_alg = session_is_alg(s);
	dps->se_in = session_is_in(s);
	dps->se_out = session_is_out(s);
	dps->se_app = session_is_app(s);

	if (session_npf_pack_stats_pack(s, stats))
		return -EINVAL;

	return session_npf_pack_sentry_pack(s, sen);
}

struct session *session_npf_pack_restore(struct npf_pack_dp_session *dps,
					 struct npf_pack_sentry *sen,
					 struct npf_pack_session_stats *stats)
{
	struct session *s;
	struct sentry_packet sp_forw;
	struct sentry_packet sp_back;
	struct sentry_packet *forw = &sp_forw;
	struct sentry_packet *back = &sp_back;
	struct sentry *sen_forw;
	struct ifnet *ifp;
	bool created = false;
	int rc;

	if (!dps || !sen)
		return NULL;

	rc = session_npf_pack_sentry_restore(sen, &ifp);
	if (rc)
		return NULL;

	rc = slot_get();
	if (rc)
		return NULL;

	s = session_alloc();
	if (!s) {
		slot_put();
		return NULL;
	}

	s->se_vrfid = ifp->if_vrfid;
	s->se_flags = dps->se_flags;
	s->se_protocol = dps->se_protocol;
	s->se_custom_timeout = dps->se_custom_timeout;
	s->se_timeout = dps->se_timeout;
	s->se_etime = get_dp_uptime() + se_timeout(s);
	s->se_protocol_state = dps->se_protocol_state;
	s->se_gen_state = dps->se_gen_state;
	s->se_snat = dps->se_snat;
	s->se_dnat = dps->se_dnat;
	s->se_nat64 = dps->se_nat64;
	s->se_nat46 = dps->se_nat46;
	s->se_alg = dps->se_alg;
	s->se_in = dps->se_in;
	s->se_out = dps->se_out;
	s->se_app = dps->se_app;

	s->se_create_time = rte_get_timer_cycles();
	rte_atomic64_init(&s->se_pkts_in);
	rte_atomic64_init(&s->se_bytes_in);
	rte_atomic64_init(&s->se_pkts_out);
	rte_atomic64_init(&s->se_bytes_out);
	se_init_logging(s);

	memcpy(forw, &sen->sp_forw, sizeof(struct sentry_packet));
	memcpy(back, &sen->sp_back, sizeof(struct sentry_packet));
	rc = sentry_packet_insert_both(s, forw, back, SENTRY_INIT,
				       &sen_forw, &created);
	if (rc || !created)
		goto error;

	/* Add the session to the session hash table.  */
	cds_lfht_add(session_ht, s->se_id, &s->se_node);
	s->se_flags = SESSION_INSERTED;

	if (session_npf_pack_stats_restore(s, stats))
		goto error;

	return s;

error:
	slot_put();
	free(s);
	return NULL;
}

uint32_t session_get_npf_pack_timeout(struct session *s)
{
	if (s)
		return se_timeout(s);
	return 0;
}

int dp_session_user_data_register(void)
{
	int old = uatomic_cmpxchg(&user_data_id, -1, 0);
	if (old != -1)
		return -EBUSY;
	return 0;
}

int dp_session_user_data_unregister(int id)
{
	int old = uatomic_cmpxchg(&user_data_id, -1, id);
	if (old != id)
		return -ENOENT;
	return 0;

}

bool dp_session_set_private(int id __unused,
			    struct session *session, void *data)
{
	void *old;

	if (!session)
		return 0;

	if (data == NULL) {
		old = rcu_xchg_pointer(&session->se_private, NULL);
		return old != NULL;
	}

	old = rcu_cmpxchg_pointer(&session->se_private, NULL, data);
	return old == NULL;
}

void *dp_session_get_private(int id __unused,
			     const struct session *session)
{
	if (!session)
		return NULL;

	return rcu_dereference(session->se_private);
}

bool dp_session_is_established(const struct session *session)
{
	if (!session)
		return false;
	return session->se_gen_state == SESSION_STATE_ESTABLISHED;
}

bool dp_session_is_expired(const struct session *session)
{
	return !session || (session->se_flags & SESSION_EXPIRED);
}

enum dp_session_state dp_session_get_state(const struct session *session)
{
	return session->se_gen_state;
}

const char *dp_session_get_state_name(const struct session *session, bool upper)
{
	return dp_session_state_name(session->se_gen_state, upper);
}

uint64_t dp_session_unique_id(const struct session *session)
{
	if (!session)
		return 0;
	return session->se_id;
}
