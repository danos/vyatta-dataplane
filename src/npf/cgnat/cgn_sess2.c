/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_sess2.c - cgnat nested 2-tuple session hash table
 *
 * cgn_session.c contains the main 3-tuple (source IP, source port, protocol)
 * session hash table.
 *
 * Optionally, each main session may have its own 2-tuple session table
 * ("sess2") whenre each entry contains destination IP and destination port.
 */

#include <stdlib.h>
#include <errno.h>
#include <values.h>
#include <rte_jhash.h>

#include "util.h"
#include "soft_ticks.h"
#include "if_var.h"

#include "npf/nat/nat_proto.h"
#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/cgn_sess_state.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_source.h"


/*
 * s2 session table entry (aka 'sentry')
 */
struct cgn_s2entry {
	struct cds_lfht_node	s2e_node;	/* hash tbl node */
	struct cgn_2tuple_key	s2e_key;	/* Hash key */
};

/*
 * Forward and backwards stats are split over two cachelines.
 *
 * idle flag is in s2_state.
 */
struct cgn_sess2 {
	struct cgn_s2entry	s2_sentry[CGN_DIR_SZ];

	uint64_t		s2_start_time;  /* unix epoch microsecs */
	rte_atomic32_t		s2_pkts_out;	/* pkts out in last interval */
	rte_atomic32_t		s2_bytes_out;	/* bytes out in last interval */
	/* --- cacheline 1 boundary (64 bytes) --- */

	struct cgn_state	s2_state;	/* 32 bytes */
	rte_atomic32_t		s2_pkts_in;	/* pkts in in last interval */
	rte_atomic32_t		s2_bytes_in;	/* bytes in in last interval */

	/*
	 * The following are not accessed regularly in the forwarding path
	 */
	uint32_t		s2_etime;       /* expiry time */
	uint32_t		s2_id;
	struct cgn_sess_s2	*s2_cs2;        /* back pointer */
	uint8_t			s2_dir:1;
	uint8_t			s2_log_start:1;
	uint8_t			s2_log_end:1;
	uint8_t			s2_log_active:1;
	uint8_t			s2_gc_pass;
	uint16_t		s2_log_countdown;
	uint32_t		s2_pkts_out_tot;  /* pkts out total */
	/* --- cacheline 2 boundary (128 bytes) --- */

	uint64_t		s2_bytes_out_tot; /* bytes out total */
	uint64_t		s2_pkts_in_tot;   /* pkts in total */
	uint64_t		s2_bytes_in_tot;  /* bytes in total */
	struct rcu_head		s2_rcu_head;
};

static_assert(offsetof(struct cgn_sess2, s2_state) == 64,
	      "cgn_sess2 structure: first cache line size exceeded");
static_assert(offsetof(struct cgn_sess2, s2_bytes_out_tot) == 128,
	      "cgn_sess2 structure: second cache line size exceeded");

#define s2_node     s2_sentry[CGN_DIR_OUT].s2e_node
#define s2_key      s2_sentry[CGN_DIR_OUT].s2e_key

#define s2_addr     s2_sentry[CGN_DIR_OUT].s2e_key.k_addr
#define s2_port     s2_sentry[CGN_DIR_OUT].s2e_key.k_port
#define s2_expired  s2_sentry[CGN_DIR_OUT].s2e_key.k_expired


/* Forward references */
static struct cds_lfht *cgn_sess2_ht_create(ulong max);
static void cgn_sess2_ht_destroy(struct cds_lfht **htp);
static int cgn_sess2_add(struct cgn_sess_s2 *cs2, struct cgn_sess2 *s2);

/*
 * API with cgn_session.c
 */

/*
 * Disable recording of dest addr and port for a given 3-tuple session.
 */
void cgn_sess_s2_disable(struct cgn_sess_s2 *cs2)
{
	cs2->cs2_enbld = false;

	/* Destroy s2 hash table if present */
	assert(cgn_sess_s2_count(cs2) == 0);

	if (cs2->cs2_ht)
		cgn_sess2_ht_destroy(&cs2->cs2_ht);
}

/* Get number of s2 sessions in this record */
int16_t cgn_sess_s2_count(struct cgn_sess_s2 *cs2)
{
	return rte_atomic16_read(&cs2->cs2_used);
}

static inline void cgn_sess_s2_set_full(struct cgn_sess_s2 *cs2)
{
	struct cgn_session *cse = cgn_sess_from_cs2(cs2);

	cgn_log_resource_dest_session_table(
		CGN_RESOURCE_FULL, cse,
		rte_atomic16_read(&cs2->cs2_used),
		cs2->cs2_max);

	/*
	 * Mark nested session table as full.  This is reset in the gc when
	 * the session count reduces.
	 */
	cs2->cs2_full = true;

}

static void cgn_sess_s2_set_available(struct cgn_sess_s2 *cs2)
{
	struct cgn_session *cse = cgn_sess_from_cs2(cs2);

	cgn_log_resource_dest_session_table(
		CGN_RESOURCE_AVAILABLE, cse,
		rte_atomic16_read(&cs2->cs2_used),
		cs2->cs2_max);

	cs2->cs2_full = false;
}

/*
 * Is there space in the nested session table?
 *
 * We reserve a slot *before* creating the session.  If the session
 * subsequently fails to be activated for any reason then we must call
 * cgn_sess_s2_slot_put to return the reserved slot.
 */
static bool cgn_sess_s2_slot_get(struct cgn_sess_s2 *cs2)
{
	if (rte_atomic16_add_return(&cs2->cs2_used, 1) <= cs2->cs2_max) {
		/* Success */
		rte_atomic32_inc(&cgn_sess2_used);
		return true;
	}

	/*
	 * No slots available.  Decrement cs2_used again.
	 */
	rte_atomic16_dec(&cs2->cs2_used);

	if (!cs2->cs2_full)
		cgn_sess_s2_set_full(cs2);

	return false;
}

static void cgn_sess_s2_slot_put(struct cgn_sess_s2 *cs2)
{
	/* Decrement count on parent session */
	rte_atomic16_dec(&cs2->cs2_used);

	/* Decrement global count */
	rte_atomic32_dec(&cgn_sess2_used);
}

/*
 * Activate an s2 session
 */
int cgn_sess_s2_activate(struct cgn_sess_s2 *cs2, struct cgn_sess2 *s2)
{
	int rc;

	rc = cgn_sess2_add(cs2, s2);

	if (unlikely(rc < 0)) {
		/*
		 * Failed to s2.  Return reserved slot and free s2.
		 */
		cgn_sess_s2_slot_put(cs2);
		free(s2);
		return rc;
	}

	s2->s2_log_start = cs2->cs2_log_start;
	s2->s2_log_end = cs2->cs2_log_end;

	return 0;
}

/*
 * Accessor functions
 */
struct cgn_session *cgn_sess2_session(struct cgn_sess2 *s2)
{
	return cgn_sess_from_cs2(s2->s2_cs2);
}

struct cgn_state *cgn_sess2_state(struct cgn_sess2 *s2)
{
	return &(s2->s2_state);
}

uint32_t cgn_sess2_id(struct cgn_sess2 *s2)
{
	return s2->s2_id;
}

uint32_t cgn_sess2_ipproto(struct cgn_sess2 *s2)
{
	struct cgn_session *cse;

	/* Get ipproto from parent 3-tuple session */
	cse = cgn_sess_from_cs2(s2->s2_cs2);
	return cgn_session_ipproto(cse);
}

uint32_t cgn_sess2_addr(struct cgn_sess2 *s2)
{
	return s2->s2_addr;
}

uint16_t cgn_sess2_port(struct cgn_sess2 *s2)
{
	return s2->s2_port;
}

uint64_t cgn_sess2_start_time(struct cgn_sess2 *s2)
{
	return s2->s2_start_time;
}

uint32_t cgn_sess2_pkts_out_tot(struct cgn_sess2 *s2)
{
	return s2->s2_pkts_out_tot;
}

uint64_t cgn_sess2_bytes_out_tot(struct cgn_sess2 *s2)
{
	return s2->s2_bytes_out_tot;
}

uint64_t cgn_sess2_pkts_in_tot(struct cgn_sess2 *s2)
{
	return s2->s2_pkts_in_tot;
}

uint64_t cgn_sess2_bytes_in_tot(struct cgn_sess2 *s2)
{
	return s2->s2_bytes_in_tot;
}

uint8_t cgn_sess2_dir(struct cgn_sess2 *s2)
{
	return s2->s2_dir;
}

/* Is t0 after t1? */
static inline int time_after(uint32_t t0, uint32_t t1)
{
	return (int)(t0 - t1) >= 0;
}

/* Hash function */
static ALWAYS_INLINE ulong cgn_sess2_hash(const struct cgn_2tuple_key *key)
{
	static_assert(sizeof(*key) == 8,
		      "cgn sess2 key is wrong size");

	/*
	 * A special optimized version of jhash that handles 1 or more of
	 * uint32_ts.
	 */
	return rte_jhash_32b((const uint32_t *)key,
			     sizeof(*key) / sizeof(uint32_t), 0);
}

/*
 * Hash table match function.
 *
 * key  - Either a pointer to the key of the entry we are inserting, or
 *        a key we are looking up. (type 'struct cgn_2tuple_key')
 * node - Pointer to an existing table node.
 *
 * Return 1 for a match.
 */
static int cgn_sess2_match(struct cds_lfht_node *node, const void *key)
{
	const struct cgn_sess2 *s2;

	s2 = caa_container_of(node, struct cgn_sess2, s2_node);

	return !memcmp(&s2->s2_key, key, sizeof(s2->s2_key));
}

/*
 * Sub-sessions require a 1ms precision timestamp for TCP RTT calculations.
 */
uint64_t cgn_sess2_timestamp(void)
{
	struct timespec ts;

	/* Get unix epoch time.  Precision of 1ms. */
	clock_gettime(CLOCK_REALTIME_COARSE, &ts);

	return (ts.tv_sec * USEC_PER_SEC) + (ts.tv_nsec / NSEC_PER_USEC);
}

/*
 * Create an s2 session. Sessions are only ever created in the 'out' context.
 */
struct cgn_sess2 *
cgn_sess_s2_establish(struct cgn_sess_s2 *cs2, struct cgn_packet *cpk,
		      int *error)
{
	struct cgn_sess2 *s2;

	/*
	 * Reserve a slot from the counters.  The slot should be returned if
	 * an error occurs at any point before the session is activated.
	 */
	if (unlikely(!cgn_sess_s2_slot_get(cs2))) {
		*error = -CGN_S2_ENOSPC;
		return NULL;
	}

	s2 = zmalloc_aligned(sizeof(struct cgn_sess2));
	if (!s2) {
		/* Return reserved slot */
		cgn_sess_s2_slot_put(cs2);
		*error = -CGN_S2_ENOMEM;
		return NULL;
	}

	s2->s2_addr = cpk->cpk_daddr;
	s2->s2_port   = cpk->cpk_did;
	rte_atomic32_inc(&s2->s2_pkts_out);
	rte_atomic32_add(&s2->s2_bytes_out, cpk->cpk_len);

	s2->s2_cs2 = cs2;
	s2->s2_dir = CGN_DIR_OUT;
	s2->s2_expired = false;
	s2->s2_start_time = cgn_sess2_timestamp();
	s2->s2_id = rte_atomic32_add_return(&cs2->cs2_id, 1);

	/* Randomise the initial logging interval */
	if (cs2->cs2_log_periodic > 0)
		s2->s2_log_countdown = (random() % cs2->cs2_log_periodic) + 1;

	cgn_sess_state_init(&s2->s2_state,
			    nat_proto_from_ipproto(cpk->cpk_ipproto),
			    ntohs(s2->s2_port));
	cgn_sess_state_inspect(&s2->s2_state, cpk, CGN_DIR_OUT,
			       s2->s2_start_time);

	return s2;
}

/*
 * Add a 2-tuple sub session to the 3-tuple main session
 */
static int cgn_sess2_add(struct cgn_sess_s2 *cs2, struct cgn_sess2 *s2)
{
	/* Insert into table */
	struct cds_lfht_node *node;

	/*
	 * Is this the first ever s2 session to be activated?  If so, then we
	 * add this directly to the cs2 structure.
	 */
	if (!rcu_dereference(cs2->cs2_ht) && !rcu_dereference(cs2->cs2_s2)) {
		struct cgn_sess2 *old;

		old = rcu_cmpxchg_pointer(&cs2->cs2_s2, NULL, s2);

		if (old == NULL)
			/* Success! */
			return 0;

		/* Lost race to add s2 as the embedded session */
		if (!memcmp(&s2->s2_key, &old->s2_key, sizeof(s2->s2_key)))
			return -CGN_S2_EEXIST;

		/* Fall thru to add s2 to hash table */
	}

	/*
	 * Is this the second ever s2 session to be activated?  If so, then
	 * create a hash table for it.
	 */
	if (!rcu_dereference(cs2->cs2_ht)) {
		struct cds_lfht *old, *new;

		/*
		 * cgn_dest_sessions_max and cgn_dest_ht_max may have changed
		 * since the 3-tuple session was created, so reset cs2_max at
		 * the same time the hash table is created since we must
		 * ensure cs2->cs2_max <= cgn_dest_ht_max at this point.
		 */
		cs2->cs2_max = cgn_dest_sessions_max;

		new = cgn_sess2_ht_create(cgn_dest_ht_max);
		if (!new)
			return -CGN_S2_ENOMEM;

		old = rcu_cmpxchg_pointer(&cs2->cs2_ht, NULL, new);
		if (old != NULL)
			/* Lost race to add hash table.  Thats ok. */
			cgn_sess2_ht_destroy(&new);
	}

	node = cds_lfht_add_unique(cs2->cs2_ht, cgn_sess2_hash(&s2->s2_key),
				   cgn_sess2_match, &s2->s2_key, &s2->s2_node);

	/* Did we loose the race to insert s2? */
	if (node != &s2->s2_node)
		return -CGN_S2_EEXIST;

	return 0;
}

static void cgn_sess2_del(struct cgn_sess_s2 *cs2, struct cgn_sess2 *s2)
{
	/* Increment 2-tuple sessions destroyed in subscriber */
	struct cgn_source *src = cgn_src_from_cs2(cs2);
	cgn_source_stats_sess2_destroyed(src);

	/* Is this the embedded session? */
	if (s2 == cs2->cs2_s2) {
		cs2->cs2_s2 = NULL;
		return;
	}

	/* Remove from table */
	if (cs2->cs2_ht)
		(void)cds_lfht_del(cs2->cs2_ht, &s2->s2_node);
}

/* Populate lookup key from packet cache */
static inline void
cgn_sess2_lookup_key_from_cpk(struct cgn_2tuple_key *key,
			      struct cgn_packet *cpk, enum cgn_dir dir)
{
	key->k_expired = false;
	key->k_pad = 0;

	if (dir == CGN_DIR_OUT) {
		key->k_addr = cpk->cpk_daddr;
		key->k_port = cpk->cpk_did;
	} else {
		key->k_addr = cpk->cpk_saddr;
		key->k_port = cpk->cpk_sid;
	}
}

static struct cgn_sess2 *
cgn_sess2_lookup(struct cgn_sess_s2 *cs2, struct cgn_2tuple_key *key)
{
	/* Does key match embedded session? */
	if (likely(cs2->cs2_s2 &&
		   cgn_sess2_match(&cs2->cs2_s2->s2_node, key)))
		return cs2->cs2_s2;

	if (unlikely(!cs2->cs2_ht))
		return NULL;

	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	cds_lfht_lookup(cs2->cs2_ht, cgn_sess2_hash(key), cgn_sess2_match,
			key, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct cgn_sess2, s2_node);

	return NULL;
}

/*
 * Does the cached packet match a destination session?
 */
struct cgn_sess2 *
cgn_sess_s2_inspect(struct cgn_sess_s2 *cs2, struct cgn_packet *cpk,
		    enum cgn_dir dir)
{
	struct cgn_2tuple_key key;
	struct cgn_sess2 *s2;

	cgn_sess2_lookup_key_from_cpk(&key, cpk, dir);

	s2 = cgn_sess2_lookup(cs2, &key);
	if (!s2)
		return NULL;

	/*
	 * Crank the state machine, and clear idle timer if allowed.
	 */
	cgn_sess_state_inspect(&s2->s2_state, cpk, dir, s2->s2_start_time);

	if (dir == CGN_DIR_OUT) {
		rte_atomic32_inc(&s2->s2_pkts_out);
		rte_atomic32_add(&s2->s2_bytes_out, cpk->cpk_len);
	} else {
		rte_atomic32_inc(&s2->s2_pkts_in);
		rte_atomic32_add(&s2->s2_bytes_in, cpk->cpk_len);
	}

	return s2;
}

/*
 * Periodic stats update.
 */
static void cgn_sess2_stats_periodic_inline(struct cgn_sess2 *s2)
{
	uint32_t pkts_out, pkts_in, bytes_out = 0, bytes_in = 0;

	pkts_out = rte_atomic32_exchange(
		(volatile uint32_t *)&s2->s2_pkts_out.cnt, 0);

	if (pkts_out) {
		/* There can't be bytes without packets */
		bytes_out = rte_atomic32_exchange(
			(volatile uint32_t *)&s2->s2_bytes_out.cnt, 0);

		s2->s2_pkts_out_tot += pkts_out;
		s2->s2_bytes_out_tot += bytes_out;
	}

	pkts_in = rte_atomic32_exchange(
		(volatile uint32_t *)&s2->s2_pkts_in.cnt, 0);

	if (pkts_in) {
		bytes_in = rte_atomic32_exchange(
			(volatile uint32_t *)&s2->s2_bytes_in.cnt, 0);

		s2->s2_pkts_in_tot += pkts_in;
		s2->s2_bytes_in_tot += bytes_in;
	}

	/* Add stats to 3-tuple session totals */
	if (pkts_out || pkts_in)
		cgn_session_update_stats(cgn_sess_from_cs2(s2->s2_cs2),
					 pkts_out, bytes_out,
					 pkts_in, bytes_in);
}

static void cgn_sess2_stats_periodic(struct cgn_sess2 *s2)
{
	cgn_sess2_stats_periodic_inline(s2);
}

/*
 * Get expiry time for a 2-tuple session
 */
static inline uint32_t cgn_sess2_expiry_time(struct cgn_sess2 *s2)
{
	struct cgn_state *st = &s2->s2_state;
	struct cgn_sess_s2 *cs2 = s2->s2_cs2;
	uint32_t etime;

	/* PCP timeout (if set) takes precedence */
	if (cs2->cs2_map_timeout)
		etime = cs2->cs2_map_timeout;
	else
		/* Get state-dependent expiry time  */
		etime = cgn_sess_state_expiry_time(st->st_proto,
						   st->st_dst_port,
						   st->st_state);

	return etime;
}

/*
 * Count of unexpired sessions
 */
uint32_t cgn_sess_s2_unexpired(struct cgn_sess_s2 *cs2)
{
	uint32_t count = 0;

	/* Check embedded session */
	if (cs2->cs2_s2 && !cs2->cs2_s2->s2_expired)
		count++;

	if (!cs2->cs2_ht)
		return count;

	struct cds_lfht_iter iter;
	struct cgn_sess2 *s2;

	cds_lfht_for_each_entry(cs2->cs2_ht, &iter, s2, s2_node) {
		if (!s2->s2_expired)
			count++;
	}
	return count;
}

/*
 * Expire a 2-tuple session.
 *
 * If the session has been closed already (e.g. after a timeout), then 'close'
 * will be set to false.  'close' will be true if sessions are being cleared
 * due to a clear command or a config change, in which case we close the
 * session before expiring it.
 *
 * If 'log' is true, and session end logging is enabled, then we log the
 * session end.  'log' will only be true if the 2-tuple session closed
 * naturally after a timeout.
 */
static void cgn_sess2_set_expired(struct cgn_sess2 *s2, bool close, bool log)
{
	if (close)
		cgn_sess_state_close(&s2->s2_state);

	s2->s2_expired = true;

	/* Add stats to 3-tuple session totals */
	cgn_sess2_stats_periodic(s2);

	if (!log)
		s2->s2_log_end = false;
}

/*
 * Is session expired?  Returns true if session is expired.
 */
static inline bool cgn_sess2_expired(struct cgn_sess2 *s2)
{
	uint32_t etime;

	/* Already expired? */
	if (unlikely(s2->s2_expired))
		return true;

	if (rte_atomic16_test_and_set(&s2->s2_state.st_idle)) {
		/* Session changed to idle */

		/* Get expiry time */
		etime = cgn_sess2_expiry_time(s2);

		/* Set expiry time */
		s2->s2_etime = get_dp_uptime() + etime;

		return false;
	}

	/*
	 * Session was already idle.  Has it timed-out?
	 */
	if (time_after(get_dp_uptime(), s2->s2_etime)) {
		/* yes, session has timed-out */

		/*
		 * Crank state-machine with timeout event, and get the timeout
		 * value for the new state.
		 */
		bool closed = cgn_sess_state_timeout(&s2->s2_state);

		/* Did timeout cause session to close? */
		if (closed) {
			/* yes. Mark session as expired */
			cgn_sess2_set_expired(s2, false, true);
			return true;
		}

		/* Else reset expiry timer */
		s2->s2_etime = get_dp_uptime() + cgn_sess2_expiry_time(s2);
	}

	return false;
}

static void cgn_sess2_rcu_free(struct rcu_head *head)
{
	struct cgn_sess2 *s2 = caa_container_of(head, struct cgn_sess2,
						s2_rcu_head);
	free(s2);
}

static void
cgn_sess2_destroy(struct cgn_sess2 *s2)
{
	call_rcu(&s2->s2_rcu_head, cgn_sess2_rcu_free);
}

static inline unsigned int
cgn_sess2_log_start_and_active(struct cgn_sess2 *s2)
{
	unsigned int count = 0;

	if (unlikely(s2->s2_log_start)) {
		cgn_log_sess_start(s2);
		s2->s2_log_start = false;
		count++;
	}

	if (unlikely(s2->s2_log_active)) {
		cgn_log_sess_active(s2);
		s2->s2_log_active = false;
		count++;
	}

	return count;
}

/*
 * We log the end of the sub-session using the dataplane timestamp.  This has
 * less precision than the mechanism we used for setting s2_start_time, but
 * thats ok.  10ms is ok for logging, whereas the s2_start_time required 1ms
 * precision since it is also used for TCP RTT calculations.
 */
static inline unsigned int
cgn_sess2_log_end(struct cgn_sess2 *s2)
{
	if (unlikely(s2->s2_expired && s2->s2_log_end)) {
		cgn_log_sess_end(s2, unix_epoch_us);
		s2->s2_log_end = false;
		return 1;
	}

	return 0;
}

static void
cgn_sess2_gc_inspect_inline(struct cgn_sess2 *s2, uint *unexpd, uint *expd,
			    struct cgn_sess_s2 *cs2)
{
	cgn_sess2_stats_periodic_inline(s2);

	if (s2->s2_log_countdown) {
		s2->s2_log_countdown -= 1;

		if (unlikely(s2->s2_log_countdown == 0)) {
			s2->s2_log_countdown = cs2->cs2_log_periodic;
			s2->s2_log_active = true;
		}
	}

	if (!cgn_helper_thread_enabled)
		cgn_sess2_log_start_and_active(s2);

	if (likely(!cgn_sess2_expired(s2))) {
		(*unexpd)++;
		return;
	}

	if (!cgn_helper_thread_enabled)
		cgn_sess2_log_end(s2);

	if (s2->s2_log_start || s2->s2_log_end) {
		/*
		 * Ensure that the session is not freed until the
		 * logging has been performed.
		 */
		(*expd)++;
		return;
	}

	if (!s2->s2_gc_pass) {
		s2->s2_gc_pass = true;
		(*expd)++;
		return;
	}

	/* Remove from hash table */
	cgn_sess2_del(cs2, s2);

	/* Release the slot */
	cgn_sess_s2_slot_put(cs2);

	/* Schedule rcu free */
	cgn_sess2_destroy(s2);
}

static void
cgn_sess2_gc_inspect(struct cgn_sess2 *s2, uint *unexpd, uint *expd,
		     struct cgn_sess_s2 *cs2)
{
	cgn_sess2_gc_inspect_inline(s2, unexpd, expd, cs2);
}

void cgn_sess_s2_gc_walk(struct cgn_sess_s2 *cs2, uint *unexpd, uint *expd)
{
	/* Check embedded session */
	if (likely(cs2->cs2_s2))
		cgn_sess2_gc_inspect_inline(cs2->cs2_s2, unexpd, expd, cs2);

	if (unlikely(cs2->cs2_ht)) {
		struct cds_lfht_iter iter;
		struct cgn_sess2 *s2;

		cds_lfht_for_each_entry(cs2->cs2_ht, &iter, s2, s2_node)
			cgn_sess2_gc_inspect(s2, unexpd, expd, cs2);
	}

	/*
	 * If the dest session table was full, check if it is still
	 * full.
	 */
	if (unlikely(cs2->cs2_full)) {
		if (rte_atomic16_read(&cs2->cs2_used) < cs2->cs2_max)
			cgn_sess_s2_set_available(cs2);
	}
}

static inline uint cgn_sess_s2_expire_one(struct cgn_sess2 *s2)
{
	if (!s2->s2_expired) {
		cgn_sess2_set_expired(s2, true, false);
		return 1;
	}
	return 0;
}

uint cgn_sess_s2_expire_all(struct cgn_sess_s2 *cs2)
{
	uint count = 0;

	if (cs2->cs2_s2)
		count += cgn_sess_s2_expire_one(cs2->cs2_s2);

	if (!cs2->cs2_ht)
		return count;

	struct cds_lfht_iter iter;
	struct cgn_sess2 *s2;

	cds_lfht_for_each_entry(cs2->cs2_ht, &iter, s2, s2_node)
		count += cgn_sess_s2_expire_one(s2);

	return count;
}

/*
 * Expire session by ID
 */
static inline uint
cgn_sess_s2_expire_id_one(struct cgn_sess2 *s2, uint32_t s2_id)
{
	if (!s2->s2_expired && (s2_id == 0 || s2_id == s2->s2_id)) {
		cgn_sess2_set_expired(s2, true, false);
		return 1;
	}
	return 0;
}

uint cgn_sess_s2_expire_id(struct cgn_sess_s2 *cs2, uint32_t s2_id)
{
	uint count = 0;

	if (cs2->cs2_s2)
		count += cgn_sess_s2_expire_id_one(cs2->cs2_s2, s2_id);

	if (!cs2->cs2_ht)
		return count;

	struct cds_lfht_iter iter;
	struct cgn_sess2 *s2;

	cds_lfht_for_each_entry(cs2->cs2_ht, &iter, s2, s2_node)
		count += cgn_sess_s2_expire_id_one(s2, s2_id);

	return count;
}

static void cgn_sess2_clear_or_update_stats_one(struct cgn_sess2 *s2,
						bool clear)
{
	if (s2->s2_expired)
		return;

	cgn_sess2_stats_periodic(s2);

	if (clear) {
		s2->s2_pkts_out_tot = 0;
		s2->s2_bytes_out_tot = 0UL;
		s2->s2_pkts_in_tot = 0UL;
		s2->s2_bytes_in_tot = 0UL;
	}
}

void cgn_sess2_clear_or_update_stats(struct cgn_sess_s2 *cs2, bool clear)
{
	struct cds_lfht_iter iter;
	struct cgn_sess2 *s2;

	if (cs2->cs2_s2)
		cgn_sess2_clear_or_update_stats_one(cs2->cs2_s2, clear);

	if (!cs2->cs2_ht)
		return;

	cds_lfht_for_each_entry(cs2->cs2_ht, &iter, s2, s2_node)
		cgn_sess2_clear_or_update_stats_one(s2, clear);
}

static inline unsigned int
cgn_sess2_log_inspect(struct cgn_sess2 *s2)
{
	return cgn_sess2_log_start_and_active(s2) + cgn_sess2_log_end(s2);
}

int cgn_sess_s2_log_walk(struct cgn_sess_s2 *cs2)
{
	unsigned int count = 0;

	/* Check embedded session */
	if (likely(cs2->cs2_s2))
		count += cgn_sess2_log_inspect(cs2->cs2_s2);

	if (unlikely(cs2->cs2_ht)) {
		struct cds_lfht_iter iter;
		struct cgn_sess2 *s2;

		cds_lfht_for_each_entry(cs2->cs2_ht, &iter, s2, s2_node)
			count += cgn_sess2_log_inspect(s2);
	}

	return count;
}

static void
cgn_sess2_jsonw_one(json_writer_t *json, struct cgn_sess2 *s2)
{
	char dst_str[16];
	uint32_t uptime = get_dp_uptime();
	uint32_t max_timeout = cgn_sess2_expiry_time(s2);

	inet_ntop(AF_INET, &s2->s2_addr, dst_str, sizeof(dst_str));

	jsonw_start_object(json);

	jsonw_string_field(json, "dst_addr", dst_str);
	jsonw_uint_field(json, "dst_port", htons(s2->s2_port));
	jsonw_uint_field(json, "id", s2->s2_id);

	cgn_sess_state_jsonw(json, &s2->s2_state);

	jsonw_uint_field(json, "start_time", s2->s2_start_time);
	jsonw_uint_field(json, "duration", unix_epoch_us - s2->s2_start_time);

	jsonw_bool_field(json, "exprd", s2->s2_expired);

	if (rte_atomic16_read(&s2->s2_state.st_idle))
		jsonw_uint_field(json, "cur_to",
				 (s2->s2_etime > uptime) ?
				 (s2->s2_etime - uptime) : 0);
	else
		jsonw_uint_field(json, "cur_to", max_timeout);

	jsonw_uint_field(json, "max_to", max_timeout);

	/* Forward counts */
	jsonw_uint_field(json, "out_pkts", s2->s2_pkts_out_tot);
	jsonw_uint_field(json, "out_bytes", s2->s2_bytes_out_tot);

	/* Backward counts */
	jsonw_uint_field(json, "in_pkts", s2->s2_pkts_in_tot);
	jsonw_uint_field(json, "in_bytes", s2->s2_bytes_in_tot);

	jsonw_end_object(json);
}

static bool
cgn_sess2_show_fltr(struct cgn_sess2 *s2, struct cgn_sess_fltr *fltr)
{
	/* Filter on destination address and port */
	if (fltr->cf_dst_mask &&
	    fltr->cf_dst.k_addr != (s2->s2_addr & fltr->cf_dst_mask))
		return false;

	if (fltr->cf_dst.k_port && fltr->cf_dst.k_port != s2->s2_port)
		return false;

	/* Filter on session ID */
	if (fltr->cf_id2 && fltr->cf_id2 != s2->s2_id)
		return false;

	return true;
}

/*
 * How many s2 sessions match a filter?
 */
uint cgn_sess_s2_fltr_count(struct cgn_sess_s2 *cs2,
			    struct cgn_sess_fltr *fltr)
{
	struct cgn_sess2 *s2;

	/*
	 * Are there enough filter params to match embedded session, or a hash
	 * table session?
	 */
	if (fltr->cf_dst_mask == 0xffffffff &&
	    cgn_s2_key_valid(&fltr->cf_dst)) {

		s2 = cgn_sess2_lookup(cs2, &fltr->cf_dst);
		if (s2 && cgn_sess2_show_fltr(s2, fltr))
			return 1;
	}

	uint32_t count = 0;

	if (cs2->cs2_s2)
		if (cgn_sess2_show_fltr(cs2->cs2_s2, fltr))
			count++;

	if (!cs2->cs2_ht)
		return count;

	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(cs2->cs2_ht, &iter, s2, s2_node) {
		if (cgn_sess2_show_fltr(s2, fltr))
			count++;
	}
	return count;
}

uint cgn_sess_s2_show(json_writer_t *json, struct cgn_sess_s2 *cs2,
		      struct cgn_sess_fltr *fltr)
{
	struct cgn_sess2 *s2;
	uint count = 0;

	jsonw_name(json, "destinations");
	jsonw_start_object(json);

	jsonw_name(json, "sessions");
	jsonw_start_array(json);

	/*
	 * Are there enough filter params to do a hash lookup?
	 */
	if (fltr->cf_dst_mask == 0xffffffff &&
	    cgn_s2_key_valid(&fltr->cf_dst)) {

		s2 = cgn_sess2_lookup(cs2, &fltr->cf_dst);

		if (s2 && cgn_sess2_show_fltr(s2, fltr)) {
			cgn_sess2_jsonw_one(json, s2);
			count++;
		}
		goto end;
	}

	if (cs2->cs2_s2 && cgn_sess2_show_fltr(cs2->cs2_s2, fltr)) {
		cgn_sess2_jsonw_one(json, cs2->cs2_s2);
		count++;
	}

	if (!cs2->cs2_ht)
		goto end;

	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(cs2->cs2_ht, &iter, s2, s2_node) {

		if (cgn_sess2_show_fltr(s2, fltr)) {
			cgn_sess2_jsonw_one(json, s2);
			count++;
		}
	}

end:
	jsonw_end_array(json);
	jsonw_end_object(json);

	return count;
}

#define CGN_SESS2_MIN_BUCKETS 32

/*
 * Create hash table
 */
static struct cds_lfht *cgn_sess2_ht_create(ulong max)
{
	struct cds_lfht *ht;

	/* Number of hash buckets must be a power of two */
	max = rte_align32pow2(max);

	/*
	 * Table is used for both forwards and backwards sentries, so double
	 * the max session value.
	 */
	max <<= 1;

	ht = cds_lfht_new(CGN_SESS2_MIN_BUCKETS, CGN_SESS2_MIN_BUCKETS, max,
			  CDS_LFHT_AUTO_RESIZE, NULL);

	if (likely(ht))
		rte_atomic64_inc(&cgn_sess2_ht_created);

	return ht;
}

static void cgn_sess2_ht_destroy(struct cds_lfht **htp)
{
	struct cds_lfht *ht = *htp;

	if (ht) {
		/* Destroy sess2 hash table */
		dp_ht_destroy_deferred(ht);
		*htp = NULL;

		rte_atomic64_inc(&cgn_sess2_ht_destroyed);
	}
}

/* Used by unit-tests only */
size_t cgn_sess2_size(void)
{
	return sizeof(struct cgn_sess2);
}
