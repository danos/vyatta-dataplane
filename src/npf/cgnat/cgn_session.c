/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_session.c - cgnat 3-tuple session hash table
 *
 * Main 3-tuple session hash table.  Each session comprises two sentrys', one
 * each for forwards and backwards flows:
 *
 *   Forward flow:   Subscriber IP and port, protocol
 *   Backwards flow: Public IP and port, protocol
 *
 * The sentry's are added to two separate hash table, one for the forward flow
 * and one for the backwards flow.
 *
 * Each session may contain a nested 2-tuple session table ("sess2")
 * containing destination IP and port information.  When a nested table is
 * in-use for a main session that that takes over the timing out of the main
 * session.
 */

#include <errno.h>
#include <values.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <rte_atomic.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_timer.h>

#include "compiler.h"
#include "if_var.h"
#include "in_cksum.h"
#include "lcore_sched.h"
#include "pktmbuf_internal.h"
#include "rcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

#include "npf/npf_addrgrp.h"
#include "npf/nat/nat_pool_public.h"

#include "npf/cgnat/alg/alg_public.h"
#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_cmd_cfg.h"
#include "npf/cgnat/cgn_dir.h"
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_if.h"
#include "npf/cgnat/cgn_hash_key.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_map.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/cgn_sess_state.h"
#include "npf/cgnat/cgn_source.h"


/*
 * cgnat session table entry.  64 bytes.  The forw sentry is used to timeout a
 * session
 */
struct cgn_sentry {
	struct cds_lfht_node	ce_node;     /* sentry tbl node */
	rte_atomic64_t		ce_pkts;
	rte_atomic64_t		ce_bytes;
	uint64_t		ce_pkts_tot;
	uint64_t		ce_bytes_tot;
	struct cgn_3tuple_key	ce_key;      /* hash key (12 bytes) */
	uint8_t			ce_active;   /* True if sentry in table */
	uint8_t			ce_established;
	uint8_t			ce_pad2[2];
};

/*
 * ce_ifindex (ce_key.k_ifindex) defaults to a vrf ID based value.
 */
#define ce_addr		ce_key.k_addr
#define ce_ifindex	ce_key.k_ifindex
#define ce_port		ce_key.k_port
#define ce_ipproto	ce_key.k_ipproto
#define ce_expired	ce_key.k_expired

/*
 * cgnat session.
 */
struct cgn_session {
	struct cgn_sentry	cs_forw_entry;	/* 64 bytes MUST. be first */
	/* --- cacheline 1 boundary (64 bytes) --- */

	struct cgn_sentry	cs_back_entry;
	/* --- cacheline 2 boundary (128 bytes) --- */

	vrfid_t			cs_vrfid;	/* VRF id (uint32_t) */
	uint32_t		cs_etime;	/* expiry time */
	struct cgn_source	*cs_src;	/* Back ptr to subscriber */

	/* Dest addr and port table and state (32 bytes) */
	struct cgn_sess_s2	cs_s2;

	/* Session instantiated by map cmd and/or a packet */
	uint8_t			cs_pkt_instd:1;
	uint8_t			cs_map_instd:1;
	uint8_t			cs_alg_parent:1;  /* ALG parent session */
	uint8_t			cs_alg_child:1;   /* ALG child session */
	uint8_t			cs_alg_inspect:1; /* ALG inspect */
	uint8_t			cs_pad1[1];

	uint16_t		cs_l3_chk_delta;
	uint16_t		cs_l4_chk_delta;
	rte_atomic16_t		cs_idle;

	rte_atomic64_t		cs_unk_pkts;

	/* --- cacheline 3 boundary (192 bytes) --- */

	uint64_t		cs_unk_pkts_tot;
	struct rcu_head		cs_rcu_head;	/* 16 bytes */
	uint64_t		cs_start_time;	/* unix epoch us */
	uint64_t		cs_end_time;	/* unix epoch us */

	struct cgn_alg_sess_ctx	*cs_alg;	/* ALG session data */

	uint32_t		cs_id;		/* unique identifier */
	uint32_t		cs_ifindex;	/* Copy of ifp->ifindex */
	rte_atomic16_t		cs_refcnt;	/* reference count */
	uint16_t		cs_map_flag;	/* True if mapping exists */
	uint8_t			cs_gc_pass;

	uint8_t			cs_pad3[3];	/* pad to cacheline boundary */
	/* --- cacheline 4 boundary (256 bytes) --- */
};

static_assert(offsetof(struct cgn_session, cs_back_entry) == 64,
	      "cgn_session structure: first cache line size exceeded");
static_assert(offsetof(struct cgn_session, cs_vrfid) == 128,
	      "cgn_session structure: second cache line size exceeded");
static_assert(offsetof(struct cgn_session, cs_unk_pkts_tot) == 192,
	      "cgn_session structure: third cache line size exceeded");
static_assert(sizeof(struct cgn_session) == 256,
	      "cgn_session structure: larger than expected");

/* session hash tables */
static struct cds_lfht *cgn_sess_ht[CGN_DIR_SZ];

/* GC Timer */
static struct rte_timer cgn_gc_timer;

/*
 * Monotonically increasing count.  Used to assign a value to a new session
 * in the sessions cs_id object.  Wraps when it reaches max.
 */
static rte_atomic32_t cgn_id_resource;


/* Forward references */
static void cgn_session_clear_mapping(struct cgn_session *cse);
static void cgn_session_expire_all(bool clear_map, bool restart_timer);

static void session_table_threshold_timer_expiry(
		struct rte_timer *timer __unused,
		void *arg __unused);


/* Time prototypes and functions. */
static void cgn_session_start_timer(void);
static void cgn_session_stop_timer(void);

/* Session table threshold, time, and timer */
static int32_t session_table_threshold_cfg;  /* configured percent */
static int32_t session_table_threshold;      /* threshold value */
static bool session_table_threshold_been_below = true;
static uint32_t session_table_threshold_time;
static struct rte_timer session_table_threshold_timer;

/* Session logging thread defines and variables */
#define CGNAT_MAX_HELPER_INTERVAL_US	1000000 /* 1 second in microseconds */

#define ASSERT_CGN_HELPER_THREAD() \
{ \
	if (!is_cgn_helper_thread()) \
		rte_panic("not on cgnat helper thread\n"); \
}

#define CGN_HELPER_INVALID_CORE_NUM	UINT_MAX

/* The core number requested due to configuration */
static unsigned int cgn_desired_helper_core_num = CGN_HELPER_INVALID_CORE_NUM;

/* The core number currently running on */
static unsigned int cgn_helper_core_num = CGN_HELPER_INVALID_CORE_NUM;

static pthread_t cgn_helper_pthread;
static unsigned int cgn_sleep_interval;

/* Structure counting logs sent */
struct lcore_cgnat {
	uint64_t logs;		/* CGNAT logs transmitted on this core */
};

/* Same size as ptr so no value in doing alloc when first configured */
static struct lcore_cgnat cgn_per_lcore[RTE_MAX_LCORE];

static struct lcore_cgnat *lcore_conf_get_cgnat(unsigned int lcore_id)
{
	if (lcore_id >= RTE_MAX_LCORE)
		return NULL;

	return &cgn_per_lcore[lcore_id];
}

/* Is t0 after t1? */
static inline int time_after(uint32_t t0, uint32_t t1)
{
	return (int)(t0 - t1) >= 0;
}

/*
 * Update 3-tuple session stats from a 2-tuple session.  Called periodically
 * by the 2-tuple session, and when the 2-tuple session is expired.
 */
void cgn_session_update_stats(struct cgn_session *cse,
			      uint32_t pkts_out, uint32_t bytes_out,
			      uint32_t pkts_in, uint32_t bytes_in)
{
	if (pkts_out) {
		rte_atomic64_add(&cse->cs_forw_entry.ce_pkts, pkts_out);
		rte_atomic64_add(&cse->cs_forw_entry.ce_bytes, bytes_out);
	}

	if (pkts_in) {
		rte_atomic64_add(&cse->cs_back_entry.ce_pkts, pkts_in);
		rte_atomic64_add(&cse->cs_back_entry.ce_bytes, bytes_in);
	}
}

/*
 * Called by session gc.
 */
static inline void
cgn_session_stats_periodic_inline(struct cgn_session *cse)
{
	uint64_t pkts_out, pkts_in, bytes_out = 0, bytes_in = 0;
	uint64_t unk_pkts_in;

	pkts_out = rte_atomic64_exchange(
		(volatile uint64_t *)&cse->cs_forw_entry.ce_pkts.cnt, 0UL);

	if (pkts_out) {
		bytes_out = rte_atomic64_exchange(
			(volatile uint64_t *)&cse->cs_forw_entry.ce_bytes.cnt,
			0UL);

		cse->cs_forw_entry.ce_pkts_tot += pkts_out;
		cse->cs_forw_entry.ce_bytes_tot += bytes_out;
	}

	/*
	 * unk_pkts are inbound pkts that matched a 3-tuple session but not a
	 * 2-tuple session (when 2-tuple are enabled).
	 */
	unk_pkts_in = rte_atomic64_exchange(
		(volatile uint64_t *)&cse->cs_unk_pkts.cnt, 0UL);
	if (unlikely(unk_pkts_in))
		cse->cs_unk_pkts_tot += unk_pkts_in;

	pkts_in = rte_atomic64_exchange(
		(volatile uint64_t *)&cse->cs_back_entry.ce_pkts.cnt, 0UL);

	if (pkts_in) {
		bytes_in = rte_atomic64_exchange(
			(volatile uint64_t *)&cse->cs_back_entry.ce_bytes.cnt,
			0UL);

		cse->cs_back_entry.ce_pkts_tot += pkts_in;
		cse->cs_back_entry.ce_bytes_tot += bytes_in;
	}

	/* Add stats to source totals */
	if (pkts_out || pkts_in || unk_pkts_in)
		cgn_source_update_stats(cse->cs_src, pkts_out, bytes_out,
					pkts_in, bytes_in, unk_pkts_in);
}

static void
cgn_session_stats_periodic(struct cgn_session *cse)
{
	cgn_session_stats_periodic_inline(cse);
}

static inline struct cgn_session *
sentry2session(const struct cgn_sentry *ce, enum cgn_dir dir)
{
	if (dir == CGN_DIR_OUT)
		return caa_container_of(ce, struct cgn_session, cs_forw_entry);

	return caa_container_of(ce, struct cgn_session, cs_back_entry);
}

static inline struct cgn_sentry *dir2sentry(struct cgn_session *cse,
					    enum cgn_dir dir)
{
	if (dir == CGN_DIR_OUT)
		return &cse->cs_forw_entry;

	return &cse->cs_back_entry;
}

uint8_t cgn_session_ipproto(struct cgn_session *cse)
{
	return cse->cs_forw_entry.ce_ipproto;
}

vrfid_t cgn_session_vrfid(struct cgn_session *cse)
{
	return cse->cs_vrfid;
}

uint32_t cgn_session_forw_addr(struct cgn_session *cse)
{
	return cse->cs_forw_entry.ce_addr;
}

uint32_t cgn_session_forw_id(struct cgn_session *cse)
{
	return cse->cs_forw_entry.ce_port;
}

uint32_t cgn_session_back_addr(struct cgn_session *cse)
{
	return cse->cs_back_entry.ce_addr;
}

uint32_t cgn_session_back_id(struct cgn_session *cse)
{
	return cse->cs_back_entry.ce_port;
}

/*
 * Get forward sentry address and port/id
 */
void cgn_session_get_forw(const struct cgn_session *cse,
			  uint32_t *addr, uint16_t *id)
{
	*addr = cse->cs_forw_entry.ce_addr;
	*id = cse->cs_forw_entry.ce_port;
}

/*
 * Get backwards sentry address and port/id
 */
void cgn_session_get_back(const struct cgn_session *cse,
			  uint32_t *addr, uint16_t *id)
{
	*addr = cse->cs_back_entry.ce_addr;
	*id = cse->cs_back_entry.ce_port;
}

uint16_t cgn_session_get_l3_delta(const struct cgn_session *cse, bool forw)
{
	return forw ? cse->cs_l3_chk_delta : ~cse->cs_l3_chk_delta;
}
uint16_t cgn_session_get_l4_delta(const struct cgn_session *cse, bool forw)
{
	return forw ? cse->cs_l4_chk_delta : ~cse->cs_l4_chk_delta;
}

/* Get pointer to the subscriber of this cse structure */
struct cgn_source *cgn_src_from_cse(struct cgn_session *cse)
{
	if (cse)
		return rcu_dereference(cse->cs_src);
	return NULL;
}

/* Get pointer to the policy of this cse structure. */
struct cgn_policy *cgn_policy_from_cse(struct cgn_session *cse)
{
	struct cgn_source *src = cgn_src_from_cse(cse);

	if (src)
		return rcu_dereference(src->sr_policy);
	return NULL;
}

/*
 * cgn_session_create
 */
static struct cgn_session *cgn_session_create(int *error)
{
	struct cgn_session *cse = NULL;

	/* Do not alloc memory if table is full */
	if (cgn_session_table_full) {
		*error = -CGN_S1_ENOSPC;
		return NULL;
	}

	cse = zmalloc_aligned(sizeof(struct cgn_session));
	if (unlikely(cse == NULL)) {
		*error = -CGN_S1_ENOMEM;
		return NULL;
	}

	assert(cse == sentry2session(&cse->cs_forw_entry, CGN_DIR_OUT));
	assert(cse == sentry2session(&cse->cs_back_entry, CGN_DIR_IN));

	return cse;
}

static void cgn_session_rcu_free(struct rcu_head *head)
{
	struct cgn_session *cse = caa_container_of(head, struct cgn_session,
						   cs_rcu_head);

	free(cse->cs_alg);
	free(cse);
}

/*
 * cgn_session_destroy
 *
 * Destroy session. Either session has just been removed from hash table in
 * garbage collector, or was never added to the hash table.  In the former
 * case, rcu_free is set to 'true', in the latter it is set to false so that
 * memory is freed immediately.
 */
void cgn_session_destroy(struct cgn_session *cse, bool rcu_free)
{
	if (!cse)
		return;

	assert(cse->cs_src);

	/* Release mapping if one exists */
	cgn_session_clear_mapping(cse);

	/* Release reference on source */
	cgn_source_put(cse->cs_src);

	/* Disable a session from recording dest addr and port */
	cgn_sess_s2_disable(&cse->cs_s2);

	if (rcu_free)
		call_rcu(&cse->cs_rcu_head, cgn_session_rcu_free);
	else {
		free(cse->cs_alg);
		free(cse);
	}
}

/*
 * Take reference on session.  A reference is held in two places:
 *
 * 1. While the session in in the session table.  A ref is taken by
 * cgn_session_activate when the session is added to the table. It is released
 * during garbage collection by cgn_session_deactivate when the session is
 * removed from the table.
 *
 * 2. alg session back pointer (multiple per session)
 */
struct cgn_session *cgn_session_get(struct cgn_session *cse)
{
	if (cse)
		rte_atomic16_inc(&cse->cs_refcnt);

	return cse;
}

/*
 * Release reference on session
 */
void cgn_session_put(struct cgn_session *cse)
{
	if (cse && rte_atomic16_dec_and_test(&cse->cs_refcnt))
		cgn_session_destroy(cse, true);
}

/*
 * Set maximum CGN sessions;
 * recalc session table threshold.
 */
void cgn_session_set_max(int32_t val)
{
	if (val > CGN_SESSIONS_MAX)
		val = CGN_SESSIONS_MAX;

	cgn_sessions_max = val;
	session_table_threshold_set(session_table_threshold_cfg,
				    session_table_threshold_time);
}

/*
 * Set ALG session context
 *
 * Called when the session is created, and *before* it is added to the session
 * table.  Once set, this is never cleared.
 */
struct cgn_alg_sess_ctx *cgn_session_alg_set(struct cgn_session *cse,
					     struct cgn_alg_sess_ctx *as)
{
	if (cse)
		return rcu_cmpxchg_pointer(&cse->cs_alg, NULL, as);
	return NULL;
}

/* Get ALG session context */
struct cgn_alg_sess_ctx *cgn_session_alg_get(struct cgn_session *cse)
{
	if (cse)
		return rcu_dereference(cse->cs_alg);
	return NULL;
}

/*
 * ALG parent flag
 *
 * Examined by *every* CGNAT pkt to determine if the main ALG inspection
 * routine is called at the end of the main pipeline routine,
 * ipv4_cgnat_common.
 */
void cgn_session_set_alg_parent(struct cgn_session *cse, bool val)
{
	cse->cs_alg_parent = val;
}

bool cgn_session_is_alg_parent(struct cgn_session *cse)
{
	return cse->cs_alg_parent;
}

/*
 * ALG child flag
 *
 * This determines if cgn_alg_sess2_init for new sub-sessions (some fixups are
 * required for PPTP).
 */
void cgn_session_set_alg_child(struct cgn_session *cse, bool val)
{
	cse->cs_alg_child = val;
}

bool cgn_session_is_alg_child(struct cgn_session *cse)
{
	return cse->cs_alg_child;
}

bool cgn_session_is_alg_pptp_child(struct cgn_session *cse)
{
	return cse->cs_alg_child && cgn_alg_get_id(cse->cs_alg) == CGN_ALG_PPTP;
}

/*
 * ALG inspect flag
 *
 * Examined by *every* CGNAT pkt to determine if all of the packet should be
 * pulled-up into the first packet segment.
 *
 * Initially set true for parent sessions, and false for child sessions.  Some
 * parent sessions may later set it to false.
 */
void cgn_session_set_alg_inspect(struct cgn_session *cse, bool val)
{
	cse->cs_alg_inspect = val;
}

bool cgn_session_get_alg_inspect(struct cgn_session *cse)
{
	return cse->cs_alg_inspect;
}

/*
 * Generate session table threshold log
 * and restart timer if required.
 */
static void session_table_threshold_log(int32_t val, int32_t max)
{
	cgn_log_resource_session_table(
		CGN_RESOURCE_THRESHOLD, val, max);

	if (session_table_threshold_time)
		rte_timer_reset(&session_table_threshold_timer,
			session_table_threshold_time * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(),
			session_table_threshold_timer_expiry,
			NULL);
}

/*
 * Warn if over the configured session table threshold
 */
static void session_table_threshold_check(int32_t val)
{
	if (session_table_threshold &&
	    session_table_threshold_been_below &&
	    (val >= session_table_threshold) &&
	    (!rte_timer_pending(&session_table_threshold_timer))) {

		session_table_threshold_been_below = false;
		session_table_threshold_log(val, cgn_sessions_max);
	}
}

/*
 * Set session table threshold
 *
 * threshold is in percent; interval is in seconds.
 */
void session_table_threshold_set(int32_t threshold, uint32_t interval)
{
	rte_timer_stop(&session_table_threshold_timer);
	session_table_threshold_cfg = threshold;
	session_table_threshold =
		(cgn_sessions_max * threshold + 99) / 100;
	session_table_threshold_time = interval;
	session_table_threshold_been_below = true;

	/* Warn if over configured threshold */
	int32_t val = rte_atomic32_read(&cgn_sessions_used);
	session_table_threshold_check(val);
}

/*
 * Handle session table threshold timer expiry.
 */
static void session_table_threshold_timer_expiry(
		struct rte_timer *timer __unused,
		void *arg __unused)
{
	int32_t val = rte_atomic32_read(&cgn_sessions_used);

	if (session_table_threshold &&
		(val >= session_table_threshold)) {

		session_table_threshold_log(val, cgn_sessions_max);
	}
}

/*
 * Mark the session table as full
 */
static void cgn_session_set_full(void)
{
	cgn_log_resource_session_table(CGN_RESOURCE_FULL,
				       rte_atomic32_read(&cgn_sessions_used),
				       cgn_sessions_max);

	cgn_session_table_full = true;
}

/*
 * Mark the session table as available.  Called after the garbage collection
 * walk if sessions used in now below max.
 */
static void cgn_session_set_available(void)
{
	cgn_log_resource_session_table(CGN_RESOURCE_AVAILABLE,
				       rte_atomic32_read(&cgn_sessions_used),
				       cgn_sessions_max);

	cgn_session_table_full = false;
}

/*
 * Is there space in the session table?
 *
 * We reserve a slot *before* creating the session.  If the session
 * subsequently fails to be activated for any reason then we MUST call
 * cgn_session_slot_put to return the reserved slot.
 */
static bool cgn_session_slot_get(void)
{
	int32_t val = rte_atomic32_add_return(&cgn_sessions_used, 1);

	/* Warn if over configured threshold */
	session_table_threshold_check(val);

	/* Error if table is full */

	if (val <= cgn_sessions_max)
		return true;

	rte_atomic32_dec(&cgn_sessions_used);

	if (!cgn_session_table_full)
		cgn_session_set_full();

	return false;
}

static void cgn_session_slot_put(void)
{
	assert(rte_atomic32_read(&cgn_sessions_used) > 0);

	int32_t val = rte_atomic32_sub_return(&cgn_sessions_used, 1);

	if (val < session_table_threshold)
		session_table_threshold_been_below = true;
}

/*
 * cgn_session_establish
 *
 * The session table entry is created from two main sources -
 *
 * 1. The packet cache, cpk
 * 2. The mapping info, cmi
 *
 * Pkt dir	Sentry	Source			Destination
 * -------	------	-----------------	------------------
 * Out		Out	cmi_oaddr:cmi_oid	{cpk_daddr:cpk_did}
 *		In	{cpk_daddr:cpk_did}	cmi_taddr:cmi_tport
 *
 * In		Out	cmi_oaddr:cmi_oid	{cpk_saddr:cpk_sid}
 *		In	{cpk_saddr:cpk_sid}	cpk_daddr:cpk_did
 *
 * For normal traffic 'cmi_oaddr:cmi_oid' will be 'cpk_saddr:cpk_sid'. However
 * these may be set differently if an ALG is in use.
 *
 * An inbound pkt will *only* create a session if an ALG pinhole is found.
 *
 * {} = sub-session, 'struct cgn_sess2'
 */
struct cgn_session *
cgn_session_establish(struct cgn_packet *cpk, struct cgn_map *cmi,
		      enum cgn_dir dir, int *error)
{
	struct cgn_source *src = cmi->cmi_src;
	struct cgn_session *cse;

	assert(src);
	assert(cmi->cmi_oaddr);
	assert(cmi->cmi_taddr);
	assert(cmi->cmi_tid);
	assert(cmi->cmi_reserved);

	/* A policy and subscriber structure should already exist */
	if (!src || !src->sr_policy)
		return NULL;

	/*
	 * Reserve a slot from the counters.  The slot MUST be returned if an
	 * error occurs at any point before the session is activated.
	 */
	if (unlikely(!cgn_session_slot_get())) {
		*error = -CGN_S1_ENOSPC;
		return NULL;
	}

	cse = cgn_session_create(error);
	if (!cse) {
		/* Return reserved slot */
		cgn_session_slot_put();
		return NULL;
	}

	/*
	 * Populate forw sentry.  Extract source addr and port from cache.
	 *
	 * Note that cpk_key.k_ifindex may be different from cpk_ifindex.  The
	 * latter is always ifp->if_index whereas cpk_key.k_ifindex will
	 * either be ifp->if_index or a cgnat interface group index value.
	 */
	if (likely(dir == CGN_DIR_OUT)) {
		cse->cs_forw_entry.ce_ifindex =	cpk->cpk_key.k_ifindex;
		cse->cs_forw_entry.ce_ipproto = cpk->cpk_ipproto;
		cse->cs_forw_entry.ce_addr = cmi->cmi_oaddr;
		cse->cs_forw_entry.ce_port = cmi->cmi_oid;
		cse->cs_forw_entry.ce_established = false;

		/* Populate back entry */
		cse->cs_back_entry.ce_ifindex =	cpk->cpk_key.k_ifindex;
		cse->cs_back_entry.ce_ipproto = cpk->cpk_ipproto;
		cse->cs_back_entry.ce_addr = cmi->cmi_taddr;
		cse->cs_back_entry.ce_port = cmi->cmi_tid;
		cse->cs_back_entry.ce_established = false;
	} else {
		/*
		 * We only ever get here if an inbound packet matched an ALG
		 * pinhole, which means that this is an ALG data flow.
		 */
		assert(cpk->cpk_alg_id);

		cse->cs_forw_entry.ce_ifindex =	cpk->cpk_key.k_ifindex;
		cse->cs_forw_entry.ce_ipproto = cpk->cpk_ipproto;
		cse->cs_forw_entry.ce_addr = cmi->cmi_oaddr;
		cse->cs_forw_entry.ce_port = cmi->cmi_oid;
		cse->cs_forw_entry.ce_established = false;

		/* Populate back entry */
		cse->cs_back_entry.ce_ifindex =	cpk->cpk_key.k_ifindex;
		cse->cs_back_entry.ce_ipproto = cpk->cpk_ipproto;
		cse->cs_back_entry.ce_addr = cpk->cpk_daddr;
		cse->cs_back_entry.ce_port = cpk->cpk_did;
		cse->cs_back_entry.ce_established = false;
	}

	/*
	 * If algs are enabled we lookup the dest port and proto here so that
	 * we can enable 5-tuple sessions if required.  If we matched a tuple
	 * earlier in the pkt path then cpk_alg_id will already be set.
	 */
	if (dir == CGN_DIR_OUT && cgn_alg_is_enabled() &&
	    cpk->cpk_alg_id == CGN_ALG_NONE)
		cpk->cpk_alg_id = cgn_alg_dest_port_lookup(cpk->cpk_proto,
							   cpk->cpk_did);

	rte_atomic16_set(&cse->cs_refcnt, 0);
	rte_atomic16_set(&cse->cs_idle, 0);
	cse->cs_vrfid = cpk->cpk_vrfid;
	cse->cs_ifindex = cpk->cpk_ifindex;
	cse->cs_start_time = unix_epoch_us;

	/* Was the session created by a packet or by map command? */
	cse->cs_pkt_instd = cpk->cpk_pkt_instd;
	cse->cs_map_instd = !cpk->cpk_pkt_instd;

	/* calculate checksum deltas */
	const uint32_t *oip32 = (const uint32_t *)&cmi->cmi_oaddr;
	const uint32_t *nip32 = (const uint32_t *)&cmi->cmi_taddr;

	cse->cs_l3_chk_delta = ~ip_fixup32_cksum(0, *oip32, *nip32);
	cse->cs_l4_chk_delta = ~ip_fixup16_cksum(0, cmi->cmi_oid, cmi->cmi_tid);

	/*
	 * Remember the dest port that created this session.  This is unknown
	 * for PCP sessions.
	 */
	if (likely(cse->cs_pkt_instd))
		cse->cs_s2.cs2_dst_port = cpk->cpk_did;

	/* Take reference on source */
	cse->cs_src = cgn_source_get(cmi->cmi_src);

	/* We already have a mapping */
	cse->cs_map_flag = true;

	/* The session now holds the mapping */
	cmi->cmi_reserved = false;

	cse->cs_id = rte_atomic32_add_return(&cgn_id_resource, 1);

	/*
	 * ALG session init.  This will add some ALG generic and specific
	 * context to the session, and optionally allow ALGs to adjust the
	 * sentries if a pinhole has been matched.
	 *
	 * cpk_alg_id is set when either 1. An ALG dest port is matched, or
	 * 2. An ALG pinhole is matched.
	 */
	if (unlikely(cpk->cpk_alg_id)) {
		int rc = cgn_alg_session_init(cpk, cse, dir);

		if (unlikely(rc < 0)) {
			*error = rc;
			return NULL;
		}
	}

	return cse;
}

/*
 * Create a mapping and session via control plane.  Used by unit-test and PCP.
 *
 * If pub_addr and pub_port are specified (!= 0) then we will try and obtain
 * that mapping.   pub_addr and pub_port are in network byte order.
 */
struct cgn_session *
cgn_session_map(struct ifnet *ifp, struct cgn_packet *cpk, struct cgn_map *cmi,
		int *error)
{
	struct cgn_session *cse, *in_cse = NULL;
	struct cgn_policy *cp;
	int rc = 0;
	vrfid_t vrfid = cpk->cpk_vrfid;

	/*
	 * Currently only support both public address and port being
	 * specified, or neither being specified.
	 */
	if (!!cmi->cmi_taddr ^ !!cmi->cmi_tid) {
		*error = -CGN_PCP_EINVAL;
		return NULL;
	}

	/* Look for existing forwards, or outbound, session */
	cse = cgn_session_lookup(&cpk->cpk_key, CGN_DIR_OUT);

	/* Look for existing backwards, or inbound, session */
	if (cmi->cmi_taddr && cmi->cmi_tid) {
		in_cse = cgn_session_lookup(&cpk->cpk_key, CGN_DIR_IN);

		/*
		 * If the requested public address and port are currently
		 * in-use, and either there is no outbound session (cse==NULL)
		 * or the outbound session is using a different public address
		 * and port (in_cse!=cse), then we fail.
		 */
		if (in_cse && in_cse != cse) {
			*error = -CGN_PCP_ENOSPC;
			return NULL;
		}
	}

	/*
	 * Are we refreshing, or trying to create, an existing session?
	 */
	if (cse) {
		/*
		 * We have found an existing session matching the protocol,
		 * subscriber address, and subscriber port.
		 *
		 * We mark this as 'map instantiated' and return it to the
		 * user, regardless of any specific public address and port
		 * they specified.
		 */

		/* clear idle flag */
		if (rte_atomic16_read(&cse->cs_idle) != 0)
			rte_atomic16_clear(&cse->cs_idle);

		return cse;
	}

	/*
	 * Lookup source address in policy list on the interface
	 */
	cp = cgn_if_find_policy_by_addr(ifp, cmi->cmi_oaddr);
	if (!cp) {
		*error = -CGN_PCY_ENOENT;

		return NULL;
	}

	/* Check if session table is full *before* getting a mapping. */
	if (unlikely(cgn_session_table_full)) {
		*error = -CGN_S1_ENOSPC;

		return NULL;
	}

	assert(cmi->cmi_oaddr);

	/*
	 * Allocate public address and port.
	 *
	 * If a public address or port is not specified then we use the same
	 * function as packet flows, cgn_map_get.  This obtains a mapping
	 * using the config in the relevant policy.
	 */
	if (cmi->cmi_taddr == 0 && cmi->cmi_tid == 0)
		rc = cgn_map_get(cmi, cp, vrfid);
	else
		/* Use specified public address and port */
		rc = cgn_map_get2(cmi, cp, vrfid);

	if (rc) {
		*error = rc;
		return NULL;
	}

	/* Create a session. */
	cse = cgn_session_establish(cpk, cmi, CGN_DIR_OUT, error);
	if (!cse)
		goto error;

	/* Check if we want to record sub-sessions */
	cgn_session_try_enable_sub_sess(cse, cp, cmi->cmi_oaddr);

	/* Add session to hash tables */
	rc = cgn_session_activate(cse, cpk, CGN_DIR_OUT);

	if (rc) {
		*error = rc;
		cgn_session_destroy(cse, false);
		return NULL;
	}
	return cse;

error:
	if (cmi->cmi_reserved) {
		/* Release mapping */
		cgn_map_put(cmi, vrfid);
		assert(!cmi->cmi_reserved);
	}

	return NULL;
}

/*
 * Get pointer to the 3-tuple session that contains this cs2 structure
 */
struct cgn_session *cgn_sess_from_cs2(struct cgn_sess_s2 *cs2)
{
	struct cgn_session *cse = NULL;

	if (cs2)
		cse = caa_container_of(cs2, struct cgn_session, cs_s2);
	return cse;
}

/*
 * Get pointer to the subscriber of this cs2 structure
 */
struct cgn_source *cgn_src_from_cs2(struct cgn_sess_s2 *cs2)
{
	struct cgn_session *cse = NULL;

	if (cs2)
		cse = caa_container_of(cs2, struct cgn_session, cs_s2);

	return cse ? cse->cs_src : NULL;
}

uint32_t cgn_session_ifindex(struct cgn_session *cse)
{
	return cse->cs_ifindex;
}

/* session ID.  (not port) */
uint32_t cgn_session_id(struct cgn_session *cse)
{
	return cse->cs_id;
}

static int cgn_sentry_insert(struct cgn_sentry *ce, struct cgn_sentry **old,
			     enum cgn_dir dir);
static void cgn_sentry_delete(struct cgn_sentry *ce, enum cgn_dir dir);

/*
 * Is recording of destination address and port enabled for this 3-tuple
 * session?
 */
static inline bool cgn_sess_s2_is_enabled(struct cgn_session *cse)
{
	return cse->cs_s2.cs2_enbld;
}

/*
 * Check if we can enable sub-sessions on this 3-tuple session
 *
 * sub-sessions are enabled for ALG sessions.  sub-sessions allows a much
 * faster session expiry for TCP sessions since we can monitor FINs and RSTs.
 */
void cgn_session_try_enable_sub_sess(struct cgn_session *cse,
				     struct cgn_policy *cp, uint32_t oaddr)
{
	struct cgn_sess_s2 *cs2 = &cse->cs_s2;

	/* Already enabled? */
	if (cs2->cs2_enbld)
		return;

	if (cgn_policy_record_dest(cp, oaddr) || cse->cs_alg) {
		cs2->cs2_enbld = true;

		/*
		 * The max value cannot change after the HT is created, so set
		 * it here from the user-configurable global.
		 */
		cs2->cs2_max = cgn_dest_sessions_max;

		cs2->cs2_log_start = cp->cp_log_sess_start ? 1 : 0;
		cs2->cs2_log_end = cp->cp_log_sess_end ? 1 : 0;
		cs2->cs2_log_periodic = cp->cp_log_sess_periodic;
	}
}

/*
 * cgn_session_activate
 *
 * Activate new 3-tuple session.
 */
int cgn_session_activate(struct cgn_session *cse,
			 struct cgn_packet *cpk, enum cgn_dir dir)
{
	struct cgn_sentry *old;
	int rc = 0;

	/*
	 * Already active? (Both or neither are active, so just check forw
	 * sentry)
	 */
	if (cse->cs_forw_entry.ce_active)
		return 0;

	/* Insert forw sentry into table */
	rc = cgn_sentry_insert(&cse->cs_forw_entry, &old, CGN_DIR_OUT);
	if (unlikely(rc < 0)) {
		cgn_session_slot_put();
		return rc;
	}

	/* Insert back sentry into table */
	rc = cgn_sentry_insert(&cse->cs_back_entry, &old, CGN_DIR_IN);
	if (unlikely(rc < 0)) {
		cgn_sentry_delete(&cse->cs_forw_entry, CGN_DIR_OUT);
		cgn_session_slot_put();
		return rc;
	}

	/* Hold reference on session while it it in the table */
	(void)cgn_session_get(cse);

	/* Increment 3-tuple sessions created in subscriber */
	cgn_source_stats_sess_created(cse->cs_src);

	/*
	 * Add a nested 2-tuple session?  cpk_keepalive is only ever set for a
	 * real packet.  It is *not* set for PCP ('map') instantiated
	 * sessions.
	 */
	if (cgn_sess_s2_is_enabled(cse) && cpk->cpk_keepalive) {
		struct cgn_sess2 *s2;
		int error = 0;

		/* Create an s2 session */
		s2 = cgn_sess_s2_establish(&cse->cs_s2, cpk, dir, &error);
		if (s2)
			error = cgn_sess_s2_activate(&cse->cs_s2, s2);

		/* Count the error, then ignore it */
		if (error < 0)
			cgn_rc_inc(dir, error);
		else
			cgn_source_stats_sess2_created(cse->cs_src);
	} else {
		struct cgn_sentry *ce = dir2sentry(cse, dir);

		/* Increment stats if session was created by a packet */
		if (likely(cse->cs_pkt_instd)) {
			rte_atomic64_inc(&ce->ce_pkts);
			rte_atomic64_add(&ce->ce_bytes, cpk->cpk_len);
		}
	}
	return rc;
}

/*
 * deactivate an expired session
 */
static void
cgn_session_deactivate(struct cgn_session *cse)
{
	if (cse->cs_forw_entry.ce_active) {
		/* Remove from sentry table */
		cgn_sentry_delete(&cse->cs_forw_entry, CGN_DIR_OUT);
		cgn_sentry_delete(&cse->cs_back_entry, CGN_DIR_IN);

		/* Release the slot */
		cgn_session_slot_put();

		/* Increment 3-tuple sessions destroyed in subscriber */
		cgn_source_stats_sess_destroyed(cse->cs_src);

		/* Release reference on session */
		cgn_session_put(cse);
	}
}

static ALWAYS_INLINE ulong cgn_hash(const struct cgn_3tuple_key *key)
{
	static_assert(sizeof(*key) == 12,
		      "cgn 3 tuple key is wrong size");

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
 *        a key we are lookng up. (type 'struct cgn_3tuple_key')
 * node - Pointer to an existing table node.
 *
 * Return 1 for a match.
 */
static int
cgn_sess_match(struct cds_lfht_node *node, const void *key)
{
	const struct cgn_sentry *ce;

	ce = caa_container_of(node, struct cgn_sentry, ce_node);

	return !memcmp(&ce->ce_key, key, sizeof(ce->ce_key));
}

/*
 * Lookup hash table with given key.  Return pointer to hash table node.
 */
static ALWAYS_INLINE struct cds_lfht_node *
cgn_session_node(const struct cgn_3tuple_key *key, enum cgn_dir dir,
		 struct cds_lfht_iter *iter)
{
	cds_lfht_lookup(cgn_sess_ht[dir], cgn_hash(key), cgn_sess_match,
			key, iter);

	return cds_lfht_iter_get_node(iter);
}

/*
 *  Lookup hash table with given key and return the next node.
 */
static inline struct cds_lfht_node *
cgn_session_node_next(const struct cgn_3tuple_key *key, enum cgn_dir dir,
		      struct cds_lfht_iter *iter)
{
	struct cds_lfht_node *node;

	cds_lfht_lookup(cgn_sess_ht[dir], cgn_hash(key), cgn_sess_match,
			key, iter);

	node = cds_lfht_iter_get_node(iter);
	if (!node)
		return NULL;

	cds_lfht_next(cgn_sess_ht[dir], iter);

	return cds_lfht_iter_get_node(iter);
}

/*
 * Get the first node in the hash table.
 */
static inline struct cds_lfht_node *
cgn_session_node_first(enum cgn_dir dir, struct cds_lfht_iter *iter)
{
	cds_lfht_first(cgn_sess_ht[dir], iter);
	return cds_lfht_iter_get_node(iter);
}

/*
 * Insert sentry into hash table
 */
static int
cgn_sentry_insert(struct cgn_sentry *ce, struct cgn_sentry **old,
		  enum cgn_dir dir)
{
	struct cds_lfht_node *node;

	node = cds_lfht_add_unique(cgn_sess_ht[dir], cgn_hash(&ce->ce_key),
				   cgn_sess_match, &ce->ce_key, &ce->ce_node);

	/* Did we loose the race to create a session? */
	if (node != &ce->ce_node) {
		*old = caa_container_of(node, struct cgn_sentry, ce_node);
		return -CGN_S1_EEXIST;
	}
	ce->ce_active = true;

	return 0;
}

/*
 * Delete sentry from the hash table
 */
static void cgn_sentry_delete(struct cgn_sentry *ce, enum cgn_dir dir)
{
	if (cgn_sess_ht[dir])
		(void)cds_lfht_del(cgn_sess_ht[dir], &ce->ce_node);
	ce->ce_active = false;
}

/*
 * cgn_sentry_lookup
 *
 * 'dir' - determines which table we lookup - forw (out) table or back (in)
 *         table.
 */
static inline struct cgn_sentry *
cgn_sentry_lookup(const struct cgn_3tuple_key *key, enum cgn_dir dir)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	node = cgn_session_node(key, dir, &iter);
	if (!node)
		return NULL;

	return caa_container_of(node, struct cgn_sentry, ce_node);
}

/*
 * cgn_session_lookup
 */
struct cgn_session *
cgn_session_lookup(const struct cgn_3tuple_key *key, enum cgn_dir dir)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct cgn_sentry *ce;

	node = cgn_session_node(key, dir, &iter);
	if (!node)
		return NULL;

	ce = caa_container_of(node, struct cgn_sentry, ce_node);
	return sentry2session(ce, dir);
}

/*
 * Lookup a packet embedded in an ICMP error message
 */
struct cgn_session *
cgn_session_lookup_icmp_err(struct cgn_packet *cpk, enum cgn_dir dir)
{
	/*
	 * Setup direction dependent part of hash key.  Note that this is the
	 * reverse of normal.
	 *
	 * For embedded ICMP packets we switch the hash key address and port.
	 * For inbound traffic, lookup the embedded source address.  For
	 * outbound traffic, lookup the embedded destination address.
	 */
	cgn_pkt_key_init(cpk, cgn_reverse_dir(dir));

	return cgn_session_lookup(&cpk->cpk_key, dir);
}

/* Is there a cached CGNAT session handle in the packet? */
struct cgn_session *cgn_session_find_cached(struct rte_mbuf *mbuf)
{
	struct cgn_session *cse = NULL;

	if (pktmbuf_mdata_exists(mbuf, PKT_MDATA_CGNAT_SESSION)) {
		struct pktmbuf_mdata *mdata = pktmbuf_mdata(mbuf);

		cse = mdata->md_cgn_session;
		if (cse->cs_forw_entry.ce_expired)
			cse = NULL;
	}
	return cse;
}

/*
 * Change all sub-session to closing state if they are currently in init or
 * established states.
 */
void cgn_session_set_closing(struct cgn_session *cse)
{
	/*
	 * Only call cgn_sess_s2_set_all_closing if sub-sessions are enabled
	 * for this main session.
	 */
	if (cgn_sess_s2_is_enabled(cse))
		cgn_sess_s2_set_all_closing(&cse->cs_s2);
}

static int
cgn_session_inspect_s2(struct cgn_session *cse, struct cgn_sentry *ce,
		       struct cgn_packet *cpk, enum cgn_dir dir)
{
	struct cgn_sess2 *s2;
	int error = 0;

	/*
	 * ICMP only has one ID field.  We store the 'dest' ID in the
	 * 2-tuple session for inside-to-outside packets.  This is the
	 * pre-translation (inside) ID.  For outside-to-inside, we
	 * lookup the 'source' ID, which will be the outside ID, and
	 * hence we will not find the 2-tuple session.
	 *
	 * A workaround for this is to copy the 3-tuple session
	 * forward entry ID to the packet decomposition source ID
	 * field such that the 2-tuple lookup will now find the
	 * session.
	 */
	if (dir == CGN_DIR_IN && cpk->cpk_ipproto == IPPROTO_ICMP)
		cpk->cpk_sid = cse->cs_forw_entry.ce_port;

	/*
	 * If we fail to find an s2 session here, then that means this
	 * packet is being sent to a different dest addr and/or port.
	 */
	s2 = cgn_sess_s2_inspect(&cse->cs_s2, cpk, dir);

	/* Add a nested 2-tuple session? */
	if (unlikely(!s2)) {
		/*
		 * cpk_keepalive is only set true for certain pkts in
		 * the outbound direction.  Pkts for which it is *not*
		 * set also include: TCP RST and all ICMP pkts except
		 * Echo Requests.
		 */
		if (cpk->cpk_keepalive) {
			assert(dir == CGN_DIR_OUT);

			/* Create an s2 session */
			s2 = cgn_sess_s2_establish(&cse->cs_s2, cpk,
						   dir, &error);
			if (s2)
				error = cgn_sess_s2_activate(&cse->cs_s2, s2);

			if (error == 0)
				cgn_source_stats_sess2_created(cse->cs_src);
			else if (error == -CGN_S2_EEXIST) {
				/*
				 * Lost race to add 2-tuple session.  Count
				 * the error, then ignore it.
				 */
				cgn_rc_inc(dir, error);
				error = 0;
			}

			/*
			 * If error is still < 0 here then that is returned,
			 * and the flow will be blocked.  If we cannot log a
			 * 2-tuple session then we do not want to allow the
			 * flow.
			 */
		} else {
			/*
			 * Inbound pkt from unknown src addr or port.  If dest
			 * session table is full then drop inbound pkts from
			 * an unknown source even of we know the dest addr and
			 * port.
			 */
			if (cse->cs_s2.cs2_full)
				/* Block inbound pkt */
				error = -CGN_S2_ENOSPC;
			else {
				rte_atomic64_inc(&cse->cs_unk_pkts);
				rte_atomic64_inc(&ce->ce_pkts);
				rte_atomic64_add(&ce->ce_bytes, cpk->cpk_len);
			}
		}
	}

	return error;
}

/*
 * Inspect an already activated 3-tuple session.  *Only* called by the packet
 * path.
 */
struct cgn_session *
cgn_session_inspect(struct cgn_packet *cpk, enum cgn_dir dir, int *error)
{
	struct cgn_sentry *ce;

	ce = cgn_sentry_lookup(&cpk->cpk_key, dir);
	if (!ce)
		return NULL;

	struct cgn_session *cse = sentry2session(ce, dir);

	/* Simple state mechanism for 3-tuple sessions */
	if (unlikely(dir == CGN_DIR_IN && !ce->ce_established))
		ce->ce_established = true;

	/*
	 * If a map instantiated session subsequently 'sees' a packet then set
	 * the pkt instantiated flag.
	 */
	if (unlikely(!cse->cs_pkt_instd))
		cse->cs_pkt_instd = true;

	/* If we find a session then it must be a CGNAT packet */
	cpk->cpk_pkt_cgnat = true;

	/*
	 * If we have nested 2-tuple sessions then they take care of sessions
	 * idle monitoring and stats.
	 */
	if (unlikely(cgn_sess_s2_is_enabled(cse)))
		*error = cgn_session_inspect_s2(cse, ce, cpk, dir);
	else {
		if (likely(cpk->cpk_keepalive)) {
			/*
			 * Clear idle flag, if packet is eligible.
			 */
			if (unlikely(rte_atomic16_read(&cse->cs_idle) != 0))
				rte_atomic16_clear(&cse->cs_idle);

			/*
			 * Is dest (or reverse src) port different from that
			 * used when cse was created?
			 */
			uint16_t fwd_dst_port = ((dir == CGN_DIR_OUT) ?
						 cpk->cpk_did : cpk->cpk_sid);

			if (unlikely(cse->cs_s2.cs2_dst_port != 0 &&
				     cse->cs_s2.cs2_dst_port != fwd_dst_port))
				cse->cs_s2.cs2_dst_port = 0;
		}

		rte_atomic64_inc(&ce->ce_pkts);
		rte_atomic64_add(&ce->ce_bytes, cpk->cpk_len);
	}

	return cse;
}

/*
 * State dependent expiry time for 3-tuple sessions
 */
static uint32_t cgn_session_expiry_time(struct cgn_session *cse)
{
	enum nat_proto proto;
	uint8_t state;
	uint32_t etime;

	if (cse->cs_back_entry.ce_expired)
		return 0;

	proto = nat_proto_from_ipproto(cse->cs_forw_entry.ce_ipproto);

	if (cse->cs_back_entry.ce_established)
		state = CGN_SESS_STATE_ESTABLISHED;
	else
		state = CGN_SESS_STATE_INIT;

	/* PCP timeout (if set) takes precedence */
	if (unlikely(cse->cs_map_instd))
		etime = cse->cs_s2.cs2_map_timeout;
	else
		/* Get state-dependent expiry time  */
		etime = cgn_sess_state_expiry_time(
			proto, ntohs(cse->cs_s2.cs2_dst_port), state);

	return etime;
}

static void __attribute__((format(printf, 2, 3))) cmd_err(FILE *f,
		const char *format, ...)
{
	char str[100];
	va_list ap;

	va_start(ap, format);
	vsnprintf(str, sizeof(str), format, ap);
	va_end(ap);

#ifdef DEBUG
	printf("cmd_err: %s\n", str);
#endif

	RTE_LOG(DEBUG, CGNAT, "%s\n", str);

	if (f) {
		json_writer_t *json = jsonw_new(f);
		if (json) {
			jsonw_string_field(json, "__error", str);
			jsonw_destroy(&json);
		}
	}
}

/*
 * Parse op-mode session options into fltr struct
 *
 * all
 * proto <proto>
 * subs-addr <prefix/len>
 * subs-port <port>
 * pub-addr <prefix/len>
 * pub-port <port>
 * dst-addr <prefix/len>
 * dst-port <port>
 * id <id1[.id2]>
 * intf <intf-name>
 * pool <pool-name>
 * alg any | <alg-name>
 * detail
 * timeout <timeout>
 * count <num>
 */
static int cgn_session_op_parse(FILE *f, int argc, char **argv,
				struct cgn_sess_fltr *fltr)
{
	npf_addr_t npf_addr;
	npf_netmask_t pl;
	sa_family_t fam;
	bool negate;
	int rc, tmp, prev;
	int i, l = 0;

	memset(fltr, 0, sizeof(*fltr));

	fltr->cf_all = true;

	/* Save clear/show command to fltr->cf_desc */
	for (i = 0; i < argc && l < (int)sizeof(fltr->cf_desc); i++)
		l += snprintf(fltr->cf_desc + l, sizeof(fltr->cf_desc) - l,
			      "%s ", argv[i]);
	if (l > 0)
		fltr->cf_desc[l-1] = '\0';

	while (argc > 0) {
		prev = argc;

		if (!strcmp(argv[0], "all")) {
			fltr->cf_all = true;

		} else if (!strcmp(argv[0], "proto") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > UCHAR_MAX) {
				cmd_err(f, "invalid protocol: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_subs.k_ipproto = tmp;
			fltr->cf_pub.k_ipproto = tmp;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "subs-addr") && argc >= 2) {
			rc = npf_parse_ip_addr(argv[1], &fam, &npf_addr,
					       &pl, &negate);
			if (rc < 0) {
				cmd_err(f, "invalid subs-addr: %s\n", argv[1]);
				return rc;
			}

			pl = MIN(32, pl);
			memcpy(&fltr->cf_subs.k_addr, &npf_addr, 4);
			tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
			fltr->cf_subs_mask = htonl(tmp);
			fltr->cf_subs.k_addr &= fltr->cf_subs_mask;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "subs-port") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > USHRT_MAX) {
				cmd_err(f, "invalid subs-port: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_subs.k_port = htons(tmp);

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "pub-addr") && argc >= 2) {
			rc = npf_parse_ip_addr(argv[1], &fam, &npf_addr,
					       &pl, &negate);
			if (rc < 0) {
				cmd_err(f, "invalid pub-addr: %s\n", argv[1]);
				return rc;
			}

			pl = MIN(32, pl);
			memcpy(&fltr->cf_pub.k_addr, &npf_addr, 4);
			tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
			fltr->cf_pub_mask = htonl(tmp);
			fltr->cf_pub.k_addr &= fltr->cf_pub_mask;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "pub-port") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > USHRT_MAX) {
				cmd_err(f, "invalid pub-port: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_pub.k_port = htons(tmp);

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "dst-addr") && argc >= 2) {
			rc = npf_parse_ip_addr(argv[1], &fam, &npf_addr,
					       &pl, &negate);
			if (rc < 0) {
				cmd_err(f, "invalid dst-addr: %s\n", argv[1]);
				return rc;
			}

			pl = MIN(32, pl);
			memcpy(&fltr->cf_dst.k_addr, &npf_addr, 4);
			tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
			fltr->cf_dst_mask = htonl(tmp);
			fltr->cf_dst.k_addr &= fltr->cf_dst_mask;
			/* iterate, or lookup, the 'out' sentries */
			fltr->cf_dst.k_dir = CGN_DIR_OUT;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "dst-port") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > USHRT_MAX) {
				cmd_err(f, "invalid dst-port: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_dst.k_port = htons(tmp);

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "id1") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp <= 0) {
				cmd_err(f, "invalid id1: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_id1 = tmp;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "id2") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp <= 0) {
				cmd_err(f, "invalid id2: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_id2 = tmp;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "intf") && argc >= 2) {
			struct ifnet *ifp = dp_ifnet_byifname(argv[1]);

			if (!ifp) {
				cmd_err(f, "invalid interface: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_subs.k_ifindex = cgn_if_key_index(ifp);
			fltr->cf_pub.k_ifindex = cgn_if_key_index(ifp);
			fltr->cf_ifindex = ifp->if_index;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "tgt-addr") && argc >= 2) {
			rc = npf_parse_ip_addr(argv[1], &fam, &npf_addr,
					       &pl, &negate);
			if (rc < 0) {
				cmd_err(f, "invalid tgt-addr: %s\n", argv[1]);
				return rc;
			}
			memcpy(&fltr->cf_tgt.k_addr, &npf_addr, 4);

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "tgt-port") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > USHRT_MAX) {
				cmd_err(f, "invalid tgt-port: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_tgt.k_port = htons(tmp);

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "tgt-proto") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > UCHAR_MAX) {
				cmd_err(f, "invalid tgt-proto: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_tgt.k_ipproto = tmp;

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "tgt-intf") && argc >= 2) {
			struct ifnet *ifp = dp_ifnet_byifname(argv[1]);

			if (!ifp) {
				cmd_err(f, "invalid tgt-intf: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_tgt.k_ifindex = cgn_if_key_index(ifp);

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "dir") && argc >= 2) {
			/* Direction to traverse sessions */
			if (!strcmp(argv[1], "down"))
				fltr->cf_dir = CGN_SHOW_DIR_DOWN;
			else
				fltr->cf_dir = CGN_SHOW_DIR_UP;

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "pool") && argc >= 2) {
			fltr->cf_pool_name = argv[1];
			fltr->cf_np = nat_pool_lookup(fltr->cf_pool_name);
			if (!fltr->cf_np) {
				cmd_err(f, "invalid pool: %s\n", argv[1]);
				return -1;
			}

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "alg") && argc >= 2) {
			fltr->cf_alg = true;
			fltr->cf_alg_id = cgn_alg_name2id(argv[1]);

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "detail")) {
			fltr->cf_detail = true;

			argc -= 1;
			argv += 1;

		} else if (!strcmp(argv[0], "outer")) {
			/* Outer 3-tuple sessions only */
			fltr->cf_no_sess2 = true;

			argc -= 1;
			argv += 1;

		} else if (!strcmp(argv[0], "count") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);
			if (tmp < 0)
				cmd_err(f, "invalid count: %s\n", argv[1]);

			fltr->cf_count = tmp;

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "timeout") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);
			if (tmp < 0 || tmp > USHRT_MAX)
				cmd_err(f, "invalid timeout: %s\n", argv[1]);

			fltr->cf_timeout = (uint16_t)tmp;

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "statistics")) {
			/* Clear statistics */
			fltr->cf_clear_stats = true;

			argc -= 1;
			argv += 1;

		} else {
			cmd_err(f, "invalid option: %s\n", argv[0]);
			return -1;
		}

		if (prev == argc) {
			argc -= 1;
			argv += 1;
		}
	}

	fltr->cf_all_sess2 = true;

	if (fltr->cf_dst.k_addr || fltr->cf_dst.k_port || fltr->cf_id2) {
		fltr->cf_all = false;
		fltr->cf_all_sess2 = false;
	}

	if (fltr->cf_dir == 0)
		fltr->cf_dir = CGN_SHOW_DIR_UP;

	if (fltr->cf_all && fltr->cf_all_sess2)
		snprintf(fltr->cf_desc, sizeof(fltr->cf_desc), "all");

	return 0;
}

/*
 * Create a mapping and session via control plane
 *
 * Convert session op-mode params to session cache structure, then call into
 * the same code used by the forwarding path.
 */
int cgn_op_session_map(FILE *f, int argc, char **argv)
{
	struct cgn_sess_fltr fltr;
	struct cgn_packet cpk;
	struct cgn_session *cse;
	json_writer_t *json;
	struct ifnet *ifp = NULL;
	uint8_t ipproto = 0;
	char *sa_arg = NULL;
	char *pa_arg = NULL;
	int rc, i, error = 0;

	memset(&fltr, 0, sizeof(fltr));
	memset(&cpk, 0, sizeof(cpk));

	/* Result is returned in json */
	json = jsonw_new(f);
	if (!json) {
		cgn_rc_inc(CGN_DIR_OUT, CGN_PCP_ERR);
		return -1;
	}

	if (argc < 12) {
		error = -CGN_PCP_EINVAL;
		goto error;
	}

	/* Remove "cgn-op map" */
	argc -= 2;
	argv += 2;

	/* Note the subscriber params in case of error */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i-1], "subs-addr"))
			sa_arg = argv[i];
		if (!strcmp(argv[i-1], "pub-addr"))
			pa_arg = argv[i];
	}

	/* Parse options */
	rc = cgn_session_op_parse(f, argc, argv, &fltr);
	if (rc < 0) {
		error = -CGN_PCP_EINVAL;
		goto error;
	}

	/* check the subscriber (private) address and port */
	if (fltr.cf_subs.k_addr == 0 || fltr.cf_subs_mask != 0xFFFFFFFF ||
	    fltr.cf_subs.k_port == 0) {
		error = -CGN_PCP_EINVAL;
		goto error;
	}

	/* check the protocol */
	ipproto = fltr.cf_subs.k_ipproto;

	if (ipproto != IPPROTO_TCP && ipproto != IPPROTO_UDP &&
	    ipproto != IPPROTO_UDPLITE && ipproto != IPPROTO_DCCP) {
		error = -CGN_PCP_EINVAL;
		goto error;
	}

	/* check the interface */
	ifp = dp_ifnet_byifindex(fltr.cf_ifindex);
	if (!ifp) {
		error = -CGN_PCP_EINVAL;
		goto error;
	}

	/*
	 * convert fltr params to cgnat cache params.
	 *
	 * cpk_daddr and cpk_did are set to the requested public address and
	 * port (if specified) in order to lookup the 'in' sentry.
	 */
	cpk.cpk_saddr = fltr.cf_subs.k_addr;
	cpk.cpk_sid = fltr.cf_subs.k_port;
	cpk.cpk_daddr = fltr.cf_pub.k_addr;
	cpk.cpk_did = fltr.cf_pub.k_port;
	cpk.cpk_ipproto = ipproto;
	cpk.cpk_ifindex = ifp->if_index;
	cpk.cpk_key.k_ifindex = cgn_if_key_index(ifp);
	cpk.cpk_l4ports = true;

	cpk.cpk_proto = nat_proto_from_ipproto(cpk.cpk_ipproto);
	cpk.cpk_vrfid = if_vrfid(ifp);
	cpk.cpk_key.k_expired = false;
	cpk.cpk_pkt_instd = false;

	/* Setup direction dependent part of hash key */
	cgn_pkt_key_init(&cpk, CGN_DIR_OUT);

	struct cgn_map cmi;

	memset(&cmi, 0, sizeof(cmi));

	cmi.cmi_proto = cpk.cpk_proto;
	cmi.cmi_oid = fltr.cf_subs.k_port;
	cmi.cmi_oaddr = fltr.cf_subs.k_addr;
	cmi.cmi_tid = fltr.cf_pub.k_port;
	cmi.cmi_taddr = fltr.cf_pub.k_addr;

	/* Get mapping, create a session, and activate session */
	cse = cgn_session_map(ifp, &cpk, &cmi, &error);
	if (!cse)
		goto error;

#define CGN_MAP_INSTD_FLAG (1 << 0)
#define CGN_PKT_INSTD_FLAG (1 << 1)
	int result = 0;

	if (cse->cs_map_instd)
		result |= CGN_MAP_INSTD_FLAG;

	if (cse->cs_pkt_instd)
		result |= CGN_PKT_INSTD_FLAG;

	cse->cs_s2.cs2_map_timeout = fltr.cf_timeout;

	/*
	 * Return result in json
	 */
	char subs_addr[16];
	char pub_addr[16];

	inet_ntop(AF_INET, &cse->cs_forw_entry.ce_addr,
		  subs_addr, sizeof(subs_addr));

	inet_ntop(AF_INET, &cse->cs_back_entry.ce_addr,
		  pub_addr, sizeof(pub_addr));

	jsonw_name(json, "map");
	jsonw_start_object(json);

	jsonw_int_field(json, "result", result);
	jsonw_string_field(json, "intf", ifp->if_name);
	jsonw_uint_field(json, "proto", ipproto);
	jsonw_string_field(json, "subs_addr", subs_addr);
	jsonw_uint_field(json, "subs_port", ntohs(cse->cs_forw_entry.ce_port));
	jsonw_string_field(json, "pub_addr", pub_addr);
	jsonw_uint_field(json, "pub_port", ntohs(cse->cs_back_entry.ce_port));
	jsonw_uint_field(json, "timeout", fltr.cf_timeout);

	jsonw_end_object(json);
	jsonw_destroy(&json);

	cgn_rc_inc(CGN_DIR_OUT, CGN_PCP_OK);
	return 0;

error:
	cgn_rc_inc(CGN_DIR_OUT, CGN_PCP_ERR);
	/*
	 * Count the specific error.  This may or may not be a PCP specific
	 * error.
	 */
	cgn_rc_inc(CGN_DIR_OUT, error);

	jsonw_name(json, "map");
	jsonw_start_object(json);

	jsonw_int_field(json, "result", error);
	jsonw_string_field(json, "error", cgn_rc_str(error));

	jsonw_string_field(json, "intf", ifp ? ifp->if_name : "?");
	jsonw_uint_field(json, "proto", ipproto);
	jsonw_string_field(json, "subs_addr", sa_arg ? sa_arg : "0.0.0.0");
	jsonw_uint_field(json, "subs_port", ntohs(fltr.cf_subs.k_port));
	jsonw_string_field(json, "pub_addr", pa_arg ? pa_arg : "0.0.0.0");
	jsonw_uint_field(json, "pub_port", ntohs(fltr.cf_pub.k_port));
	jsonw_uint_field(json, "timeout", 0);

	jsonw_end_object(json);
	jsonw_destroy(&json);

	return 0;
}

/*
 * Returns number of sessions added to json
 */
static uint
cgn_session_jsonw_one(json_writer_t *json, struct cgn_sess_fltr *fltr,
		      struct cgn_session *cse)
{
	struct cgn_sentry *fw, *bk;
	char src_str[16];
	char trans_str[16];
	struct ifnet *ifp;
	uint count = 1;
	uint64_t bk_pkts;
	uint16_t subs_port;

	/*
	 * If nested sessions are enabled and the user has specified some
	 * filter criteria for those sessions then do not display the outer
	 * 3-tuple session if no 2-tuple sessions match the criteria.
	 */
	if (cgn_sess_s2_is_enabled(cse) && cse->cs_pkt_instd &&
	    !fltr->cf_all_sess2 && !fltr->cf_no_sess2) {

		uint s2_count = cgn_sess_s2_fltr_count(&cse->cs_s2, fltr);

		if (s2_count == 0)
			return 0;
	}

	inet_ntop(AF_INET, &cse->cs_forw_entry.ce_addr,
		  src_str, sizeof(src_str));
	inet_ntop(AF_INET, &cse->cs_back_entry.ce_addr,
		  trans_str, sizeof(trans_str));
	ifp = dp_ifnet_byifindex(cse->cs_ifindex);

	jsonw_start_object(json);

	jsonw_uint_field(json, "id", cse->cs_id);

	jsonw_string_field(json, "subs_addr", src_str);

	/* PPTP ALG subs_port needs fetched from the PPTP session context */
	if (cgn_session_is_alg_pptp_child(cse))
		subs_port = cgn_alg_pptp_orig_call_id(cse, NULL);
	else
		subs_port = cse->cs_forw_entry.ce_port;

	jsonw_uint_field(json, "subs_port", htons(subs_port));

	jsonw_string_field(json, "pub_addr", trans_str);
	jsonw_uint_field(json, "pub_port", htons(cse->cs_back_entry.ce_port));

	jsonw_uint_field(json, "proto", cse->cs_forw_entry.ce_ipproto);
	jsonw_string_field(json, "intf", ifp->if_name);
	jsonw_uint_field(json, "index", cse->cs_forw_entry.ce_ifindex);

	if (cse->cs_s2.cs2_dst_port)
		jsonw_uint_field(json, "init_dst_port",
				 htons(cse->cs_s2.cs2_dst_port));

	/* Has the session seen at least one packet? */
	jsonw_bool_field(json, "pkt_instd", cse->cs_pkt_instd);

	/* Was session created via PCP? */
	jsonw_bool_field(json, "map_instd", cse->cs_map_instd);
	if (cse->cs_map_instd)
		jsonw_uint_field(json, "map_timeout",
				 cse->cs_s2.cs2_map_timeout);

	if (fltr->cf_detail) {
		struct nat_pool *np;

		if (cse->cs_src && cse->cs_src->sr_policy)
			jsonw_string_field(json, "policy",
					   cse->cs_src->sr_policy->cp_name);

		np = cgn_source_get_pool(cse->cs_src);
		if (np)
			jsonw_string_field(json, "pool", nat_pool_name(np));
	}

	/* Forwards stats */
	fw = &cse->cs_forw_entry;
	jsonw_uint_field(json, "out_pkts", rte_atomic64_read(&fw->ce_pkts) +
			 fw->ce_pkts_tot);
	jsonw_uint_field(json, "out_bytes", rte_atomic64_read(&fw->ce_bytes) +
			 fw->ce_bytes_tot);

	/* Backwards stats */
	bk = &cse->cs_back_entry;
	bk_pkts = rte_atomic64_read(&bk->ce_pkts);
	jsonw_uint_field(json, "in_pkts", rte_atomic64_read(&bk->ce_pkts) +
			 bk->ce_pkts_tot);
	jsonw_uint_field(json, "in_bytes", rte_atomic64_read(&bk->ce_bytes) +
			 bk->ce_bytes_tot);

	/* Inbound pkts from unknown source addr or port */
	jsonw_uint_field(json, "unk_pkts_in",
			 rte_atomic64_read(&cse->cs_unk_pkts) +
			 cse->cs_unk_pkts_tot);

	jsonw_bool_field(json, "exprd", cse->cs_forw_entry.ce_expired);
	jsonw_uint_field(json, "refcnt", rte_atomic16_read(&cse->cs_refcnt));

	/* ALG info, if present */
	cgn_alg_show_session(json, fltr, cgn_session_alg_get(cse));

	/*
	 * We use the 2-tuple expiry mechanism if 2-tuple session are enabled
	 * and the session has seen at least one packet.
	 *
	 * We use the 3-tuple expiry mechanism if 2-tuple sessions are
	 * disabled *or* the session was created by PCP (or the map command)
	 * and has *not* seen a packet.
	 */
	if (cgn_sess_s2_is_enabled(cse) && cse->cs_pkt_instd) {
		ulong ht_count;

		/* count may be less than ht_count if there are filters */
		if (!fltr->cf_no_sess2)
			count = cgn_sess_s2_show(json, &cse->cs_s2, fltr);

		ht_count = cgn_sess_s2_count(&cse->cs_s2);
		jsonw_uint_field(json, "nsessions", ht_count);

		/*
		 * They way session table entries are displayed in table
		 * format means that the a single 3-tuple session is displayed
		 * as one line, and a single 5-tuple session is displayed as
		 * one line.  The context of the count returned here is is
		 * relation to the number of lines that will be displayed,
		 * hence if there were no 2-tuple sessions, then we count the
		 * outer 3-tuple session.
		 *
		 * Also see the comment earlier in this function where it calls
		 * cgn_sess2_show_count
		 */
		if (count == 0)
			count = 1;

		/*
		 * Set something sensible for the outer session state when
		 * nested sessions are in use.
		 */
		if (cse->cs_forw_entry.ce_expired)
			jsonw_uint_field(json, "state", CGN_SESS_STATE_CLOSED);
		else if (bk_pkts)
			jsonw_uint_field(json, "state",
					 CGN_SESS_STATE_ESTABLISHED);
		else
			jsonw_uint_field(json, "state", CGN_SESS_STATE_INIT);
	} else {
		if (cse->cs_forw_entry.ce_expired)
			jsonw_uint_field(json, "state", CGN_SESS_STATE_CLOSED);
		else if (cse->cs_back_entry.ce_established)
			jsonw_uint_field(json, "state",
					 CGN_SESS_STATE_ESTABLISHED);
		else
			jsonw_uint_field(json, "state", CGN_SESS_STATE_INIT);

		jsonw_uint_field(json, "nsessions", 0);
	}

	if (!cgn_sess_s2_is_enabled(cse) || cse->cs_map_instd) {
		uint32_t uptime = get_dp_uptime();
		uint32_t max_timeout = cgn_session_expiry_time(cse);

		if (rte_atomic16_read(&cse->cs_idle))
			jsonw_uint_field(json, "cur_to",
					 (cse->cs_etime > uptime) ?
					 (cse->cs_etime - uptime) : 0);
		else
			jsonw_uint_field(json, "cur_to", max_timeout);

		jsonw_uint_field(json, "max_to", max_timeout);
	}

	jsonw_uint_field(json, "start_time", cse->cs_start_time);
	jsonw_uint_field(json, "duration", unix_epoch_us - cse->cs_start_time);

	jsonw_end_object(json);

	return count;
}

/*
 * Returns true if session matches filter criteria
 */
static bool
cgn_session_show_fltr(struct cgn_session *cse, struct cgn_sess_fltr *fltr)
{
	struct cgn_sentry *fw, *bk;

	fw = &cse->cs_forw_entry;
	bk = &cse->cs_back_entry;

	/* Filter on Subscriber address and port */
	if (fltr->cf_subs_mask &&
	    fltr->cf_subs.k_addr != (fw->ce_addr & fltr->cf_subs_mask))
		return false;

	if (fltr->cf_subs.k_port && fltr->cf_subs.k_port != fw->ce_port)
		return false;

	/* Filter on IP protocol */
	if (fltr->cf_subs.k_ipproto &&
	    fltr->cf_subs.k_ipproto != fw->ce_ipproto)
		return false;

	/* Filter on interface */
	if (fltr->cf_ifindex && fltr->cf_ifindex != cse->cs_ifindex)
		return false;

	/* Filter on ALG id */
	if (fltr->cf_alg || fltr->cf_alg_id) {
		if (cse->cs_alg == NULL)
			return false;

		if (fltr->cf_alg_id &&
		    fltr->cf_alg_id != cgn_alg_get_id(cse->cs_alg))
			return false;
	}

	/* Filter on Public address and port */
	if (fltr->cf_pub_mask &&
	    fltr->cf_pub.k_addr != (bk->ce_addr & fltr->cf_pub_mask))
		return false;

	/*
	 * Filter on destination port.  This is the special case where 2-tuple
	 * sessions are *not* enabled, and we have only ever seen one dest
	 * port inuse on the 3-tuple session.
	 */
	if (fltr->cf_dst.k_port && !cgn_sess_s2_is_enabled(cse) &&
	    cse->cs_s2.cs2_dst_port != 0 &&
	    fltr->cf_dst.k_port != cse->cs_s2.cs2_dst_port)
		return false;

	if (fltr->cf_pub.k_port && fltr->cf_pub.k_port != bk->ce_port)
		return false;

	/* Filter on session ID */
	if (fltr->cf_id1 && fltr->cf_id1 != cse->cs_id)
		return false;

	/* Filter on NAT pool */
	if (fltr->cf_np &&
	    fltr->cf_np != cgn_source_get_pool(cse->cs_src))
		return false;

	return true;
}

static void
cgn_session_show_json(json_writer_t *json, struct cgn_sess_fltr *fltr)
{
	struct cgn_session *cse;
	uint count = 0;

	jsonw_name(json, "sessions");
	jsonw_start_array(json);

	if (!cgn_sess_ht[CGN_DIR_OUT])
		return;

	/*
	 * Are there enough filter params to do a hash lookup in the forwards
	 * sentries?  We need subscriber (source) address and port, interface,
	 * and protocol.
	 */
	if (fltr->cf_subs_mask == 0xffffffff &&
	    cgn_sess_key_valid(&fltr->cf_subs)) {

		cse = cgn_session_lookup(&fltr->cf_subs, CGN_DIR_OUT);

		if (cse && cgn_session_show_fltr(cse, fltr))
			cgn_session_jsonw_one(json, fltr, cse);
		return;
	}

	/*
	 * Are there enough filter params to do a hash lookup in the backwards
	 * sentries?  We need public (dest) address and port, interface, and
	 * protocol.
	 */
	if (fltr->cf_pub_mask == 0xffffffff &&
	    cgn_sess_key_valid(&fltr->cf_pub)) {

		cse = cgn_session_lookup(&fltr->cf_pub, CGN_DIR_IN);

		if (cse && cgn_session_show_fltr(cse, fltr))
			cgn_session_jsonw_one(json, fltr, cse);
		return;
	}

	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct cgn_sentry *ce;

	/* Start at the node *after* the specified target, if any */
	if (cgn_sess_key_valid(&fltr->cf_tgt))
		node = cgn_session_node_next(&fltr->cf_tgt, CGN_DIR_OUT, &iter);
	else
		/* else start at start */
		node = cgn_session_node_first(CGN_DIR_OUT, &iter);

	for (; node != NULL;
	     cds_lfht_next(cgn_sess_ht[CGN_DIR_OUT], &iter),
		     node = cds_lfht_iter_get_node(&iter)) {

		ce = caa_container_of(node, struct cgn_sentry, ce_node);
		cse = sentry2session(ce, CGN_DIR_OUT);

		if (cgn_session_show_fltr(cse, fltr))
			count += cgn_session_jsonw_one(json, fltr, cse);

		/* Have we added enough sessions yet? */
		if (fltr->cf_count > 0 && count >= fltr->cf_count)
			break;
	}
}

/*
 * cgn-op show session ...
 */
void cgn_session_show(FILE *f, int argc, char **argv)
{
	struct cgn_sess_fltr fltr;
	json_writer_t *json;
	int rc;

	/* Remove "cgn-op show session" */
	argc -= 3;
	argv += 3;

	rc = cgn_session_op_parse(f, argc, argv, &fltr);
	if (rc < 0)
		return;

	json = jsonw_new(f);
	if (!json)
		return;

	cgn_session_show_json(json, &fltr);

	jsonw_end_array(json);
	jsonw_destroy(&json);
}

/* Only used by UTs. */
void cgn_ut_show_sessions(char **buf, size_t *bufsz,
			  struct cgn_sess_fltr *fltr)
{
	json_writer_t *json;
	FILE *f = open_memstream(buf, bufsz);

	if (!f)
		return;

	json = jsonw_new(f);
	if (!json) {
		fclose(f);
		return;
	}

	cgn_session_show_json(json, fltr);

	jsonw_end_array(json);
	jsonw_destroy(&json);

	fclose(f);
}

/*
 * Return list of session IDs
 */
void cgn_session_id_list(FILE *f, int argc __unused, char **argv __unused)
{
	json_writer_t *json;
	struct cds_lfht_iter iter;
	struct cgn_session *cse;
	struct cgn_sentry *fw;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "ids");
	jsonw_start_array(json);

	if (!cgn_sess_ht[CGN_DIR_OUT])
		goto end;

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_OUT], &iter, fw, ce_node) {
		if (fw->ce_expired)
			continue;

		cse = caa_container_of(fw, struct cgn_session, cs_forw_entry);
		jsonw_uint(json, cse->cs_id);
	}

end:
	jsonw_end_array(json);
	jsonw_destroy(&json);
}

/*
 * Mark session as expired
 */
static void
cgn_session_set_expired(struct cgn_session *cse, bool update_stats)
{
	cse->cs_forw_entry.ce_expired = true;
	cse->cs_back_entry.ce_expired = true;
	cse->cs_end_time = unix_epoch_us;
	cse->cs_etime = 0;

	/* ALG */
	struct cgn_alg_sess_ctx *as = cgn_session_alg_get(cse);
	if (as)
		cgn_alg_session_uninit(cse, as);

	/*
	 * Add stats to source totals.  Do not do if called via gc, as this
	 * will be updating the stats anyway.
	 */
	if (unlikely(update_stats))
		cgn_session_stats_periodic(cse);
}

/*
 * Force clearing of a session mapping
 */
static void cgn_session_clear_mapping(struct cgn_session *cse)
{
	/* Release mapping immediately */
	if (rte_atomic16_cmpset(&cse->cs_map_flag, true, false)) {
		struct cgn_map cmi;

		memset(&cmi, 0, sizeof(cmi));
		cgn_session_get_back(cse, &cmi.cmi_taddr, &cmi.cmi_tid);
		cmi.cmi_reserved = true;
		cmi.cmi_src = cse->cs_src;
		cmi.cmi_proto = nat_proto_from_ipproto(
			cse->cs_forw_entry.ce_ipproto);

		cgn_map_put(&cmi, cse->cs_vrfid);
	}
}

/* Expire a session */
void cgn_session_expire_one(struct cgn_session *cse)
{
	if (cgn_sess_s2_is_enabled(cse))
		cgn_sess_s2_expire_all(&cse->cs_s2);

	cgn_session_set_expired(cse, true);
}

/*
 * addr must be specified.  port=0 means any/all ports.
 */
static void
cgn_session_clear_fltr(struct cgn_sess_fltr *fltr, bool clear_map,
		       bool restart_timer)
{
	struct cds_lfht_iter iter;
	struct cgn_session *cse;
	struct cgn_sentry *ce, *bk;
	uint count = 0; /* count 2-tuple sessions cleared */

	if (!cgn_sess_ht[CGN_DIR_OUT])
		return;

	/*
	 * We do not want an expired timer competing with the cli or ut, so
	 * stop timer while expiring sessions.
	 */
	cgn_session_stop_timer();

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_OUT], &iter, ce, ce_node) {
		if (!clear_map && ce->ce_expired)
			continue;

		/* Filter on IP protocol */
		if (fltr->cf_subs.k_ipproto &&
		    fltr->cf_subs.k_ipproto != ce->ce_ipproto)
			continue;

		/* Filter on Subscriber address and port */
		if (fltr->cf_subs_mask &&
		    fltr->cf_subs.k_addr != (ce->ce_addr & fltr->cf_subs_mask))
			continue;

		if (fltr->cf_subs.k_port && fltr->cf_subs.k_port != ce->ce_port)
			continue;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);
		bk = &cse->cs_back_entry;

		/* Filter on Public address and port */
		if (fltr->cf_pub_mask &&
		    fltr->cf_pub.k_addr != (bk->ce_addr & fltr->cf_pub_mask))
			continue;

		if (fltr->cf_pub.k_port && fltr->cf_pub.k_port != bk->ce_port)
			continue;

		/*
		 * Filter on destination port.  This is the special case where
		 * 2-tuple sessions are *not* enabled, and we have only ever
		 * seen one dest port inuse on the 3-tuple session.
		 */
		if (fltr->cf_dst.k_port && !cgn_sess_s2_is_enabled(cse) &&
		    cse->cs_s2.cs2_dst_port != 0 &&
		    fltr->cf_dst.k_port != cse->cs_s2.cs2_dst_port)
			continue;

		/* Filter on session ID */
		if (fltr->cf_id1) {
			if (fltr->cf_id1 != cse->cs_id)
				continue;

			/* Expire one or all 2-tuple sessions */
			if (cgn_sess_s2_is_enabled(cse))
				count += cgn_sess_s2_expire_id(&cse->cs_s2,
							       fltr->cf_id2);

			/*
			 * If no unexpired 2-tuple sessions remain then expire
			 * 3-tuple session and clear mapping.
			 */
			if (!cgn_sess_s2_is_enabled(cse) ||
			    cgn_sess_s2_unexpired(&cse->cs_s2) == 0) {

				if (!ce->ce_expired)
					cgn_session_set_expired(cse, true);

				if (clear_map)
					cgn_session_clear_mapping(cse);
			}

			continue;
		}

		/* Filter on interface */
		if (fltr->cf_ifindex && fltr->cf_ifindex != cse->cs_ifindex)
			continue;

		/* Filter on NAT pool */
		if (fltr->cf_np &&
		    fltr->cf_np != cgn_source_get_pool(cse->cs_src))
			continue;

		if (!ce->ce_expired) {
			if (cgn_sess_s2_is_enabled(cse))
				count += cgn_sess_s2_expire_all(&cse->cs_s2);

			cgn_session_set_expired(cse, true);
		}

		if (clear_map)
			cgn_session_clear_mapping(cse);
	}

	/* Log session clear command instead of every session */
	if (count)
		cgn_log_sess_clear(fltr->cf_desc, count, unix_epoch_us);

	if (restart_timer)
		cgn_session_start_timer();
}

/*
 * Clear or update stats for one session
 */
static void
cgn_session_clear_or_update_stats(struct cgn_session *cse, bool clear)
{
	if (cgn_sess_s2_is_enabled(cse))
		cgn_sess2_clear_or_update_stats(&cse->cs_s2, clear);

	/* Clear the periodic counters, and update subscriber counts */
	cgn_session_stats_periodic(cse);

	/* Clear totals */
	if (clear) {
		cse->cs_forw_entry.ce_pkts_tot = 0UL;
		cse->cs_forw_entry.ce_bytes_tot = 0UL;
		cse->cs_back_entry.ce_pkts_tot = 0UL;
		cse->cs_back_entry.ce_bytes_tot = 0UL;
		cse->cs_unk_pkts_tot = 0UL;
	}
}

/*
 * Clear or update stats for all sessions
 */
static void cgn_session_clear_or_update_stats_all(bool clear)
{
	struct cds_lfht_iter iter;
	struct cgn_session *cse;
	struct cgn_sentry *ce;

	if (!cgn_sess_ht[CGN_DIR_OUT])
		return;

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_OUT], &iter, ce, ce_node) {
		if (ce->ce_expired)
			continue;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);
		cgn_session_clear_or_update_stats(cse, clear);
	}
}

/*
 * Clear or update stats for specific sessions
 */
static void
cgn_session_clear_or_update_stats_fltr(struct cgn_sess_fltr *fltr, bool clear)
{
	struct cds_lfht_iter iter;
	struct cgn_session *cse;
	struct cgn_sentry *ce, *bk;

	if (!cgn_sess_ht[CGN_DIR_OUT])
		return;

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_OUT], &iter, ce, ce_node) {
		if (ce->ce_expired)
			continue;

		/* Filter on IP protocol */
		if (fltr->cf_subs.k_ipproto &&
		    fltr->cf_subs.k_ipproto != ce->ce_ipproto)
			continue;

		/* Filter on Subscriber address and port */
		if (fltr->cf_subs_mask &&
		    fltr->cf_subs.k_addr != (ce->ce_addr & fltr->cf_subs_mask))
			continue;

		if (fltr->cf_subs.k_port && fltr->cf_subs.k_port != ce->ce_port)
			continue;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);
		bk = &cse->cs_back_entry;

		/* Filter on Public address and port */
		if (fltr->cf_pub_mask &&
		    fltr->cf_pub.k_addr != (bk->ce_addr & fltr->cf_pub_mask))
			continue;

		if (fltr->cf_pub.k_port && fltr->cf_pub.k_port != bk->ce_port)
			continue;

		/*
		 * Filter on destination port.  This is the special case where
		 * 2-tuple sessions are *not* enabled, and we have only ever
		 * seen one dest port inuse on the 3-tuple session.
		 */
		if (fltr->cf_dst.k_port && !cgn_sess_s2_is_enabled(cse) &&
		    cse->cs_s2.cs2_dst_port != 0 &&
		    fltr->cf_dst.k_port != cse->cs_s2.cs2_dst_port)
			continue;

		/* Filter on session ID */
		if (fltr->cf_id1 && fltr->cf_id1 != cse->cs_id)
			continue;

		/* Filter on interface */
		if (fltr->cf_ifindex && fltr->cf_ifindex != cse->cs_ifindex)
			continue;

		/* Filter on NAT pool */
		if (fltr->cf_np &&
		    fltr->cf_np != cgn_source_get_pool(cse->cs_src))
			continue;

		cgn_session_clear_or_update_stats(cse, clear);
	}
}

/*
 * cgn-op clear session ...
 *
 * all
 * proto <proto>
 * subs-addr <prefix/len>
 * subs-port <port>
 * pub-addr <prefix/len>
 * pub-port <port>
 * id <id1.id2>
 * intf <intf-name>
 * pool <pool-name>
 */
void cgn_session_clear(FILE *f, int argc, char **argv)
{
	struct cgn_sess_fltr fltr;
	int rc;

	/* Remove "cgn-op clear session" */
	argc -= 3;
	argv += 3;

	rc = cgn_session_op_parse(f, argc, argv, &fltr);
	if (rc < 0)
		return;

	if (fltr.cf_clear_stats) {
		/* Clear session stats */
		if (fltr.cf_all)
			cgn_session_clear_or_update_stats_all(true);
		else
			cgn_session_clear_or_update_stats_fltr(&fltr, true);
	} else {
		/* Clear sessions */
		if (fltr.cf_all)
			cgn_session_expire_all(true, true);
		else
			cgn_session_clear_fltr(&fltr, true, true);
	}
}

/*
 * Update subscriber with session stats
 */
void cgn_session_update(FILE *f, int argc, char **argv)
{
	struct cgn_sess_fltr fltr;
	int rc;

	/* Remove "cgn-op update session" */
	argc -= 3;
	argv += 3;

	rc = cgn_session_op_parse(f, argc, argv, &fltr);
	if (rc < 0)
		return;

	if (fltr.cf_all)
		cgn_session_clear_or_update_stats_all(false);
	else
		cgn_session_clear_or_update_stats_fltr(&fltr, false);
}

static void
cgn_session_expire_all(bool clear_map, bool restart_timer)
{
	struct cds_lfht_iter iter;
	struct cgn_session *cse;
	struct cgn_sentry *ce;
	uint count = 0;

	if (!cgn_sess_ht[CGN_DIR_OUT])
		return;

	/*
	 * We do not want an expired timer competing with the cli or ut, so
	 * stop timer while expiring sessions.
	 */
	cgn_session_stop_timer();

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_OUT], &iter, ce, ce_node) {
		if (!clear_map && ce->ce_expired)
			continue;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);

		if (!ce->ce_expired) {
			if (cgn_sess_s2_is_enabled(cse))
				count += cgn_sess_s2_expire_all(&cse->cs_s2);

			cgn_session_set_expired(cse, true);
		}

		if (clear_map)
			cgn_session_clear_mapping(cse);
	}

	/* Log session clear command instead of every session */
	if (count)
		cgn_log_sess_clear("all", count, unix_epoch_us);

	if (restart_timer)
		cgn_session_start_timer();
}

/*
 * Expire all sessions that use public addresses from the given nat pool.
 *
 * If clear_mapping is true, then also release mapping used by any sessions
 * that are expired.
 */
void cgn_session_expire_pool(bool restart_timer, struct nat_pool *np,
			     bool clear_mapping)
{
	struct cds_lfht_iter iter;
	struct cgn_session *cse;
	struct cgn_sentry *ce;
	uint count = 0;

	if (!cgn_sess_ht[CGN_DIR_OUT])
		return;

	/*
	 * We do not want an expired timer competing with the cli or ut, so
	 * stop timer while expiring sessions.
	 */
	cgn_session_stop_timer();

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_OUT], &iter, ce, ce_node) {
		struct nat_pool *cs_np;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);

		cs_np = cgn_source_get_pool(cse->cs_src);
		if (cs_np != np)
			continue;

		if (!ce->ce_expired) {
			if (cgn_sess_s2_is_enabled(cse))
				count += cgn_sess_s2_expire_all(&cse->cs_s2);

			cgn_session_set_expired(cse, true);
		}

		if (clear_mapping)
			cgn_session_clear_mapping(cse);
	}

	/* Clear address hints */
	nat_pool_clear_addr_hints(np);

	/* Log session clear command instead of every session */
	if (count) {
		char desc[60];
		snprintf(desc, sizeof(desc), "pool %s", nat_pool_name(np));
		cgn_log_sess_clear(desc, count, unix_epoch_us);
	}

	if (restart_timer)
		cgn_session_start_timer();
}

/*
 * Expire all sessions associated with a specific policy
 */
void cgn_session_expire_policy(bool restart_timer, struct cgn_policy *cp)
{
	struct cds_lfht_iter iter;
	struct cgn_session *cse;
	struct cgn_sentry *ce;
	uint count = 0;

	if (!cgn_sess_ht[CGN_DIR_OUT])
		return;

	/*
	 * We do not want an expired timer competing with the cli or ut, so
	 * stop timer while expiring sessions.
	 */
	cgn_session_stop_timer();

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_OUT], &iter, ce, ce_node) {
		if (ce->ce_expired)
			continue;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);

		if (cse->cs_src && cse->cs_src->sr_policy != cp)
			continue;

		if (cgn_sess_s2_is_enabled(cse))
			count += cgn_sess_s2_expire_all(&cse->cs_s2);

		cgn_session_set_expired(cse, true);
	}

	/* Log session clear command instead of every session */
	if (count) {
		char desc[60];
		snprintf(desc, sizeof(desc), "policy %s", cp->cp_name);
		cgn_log_sess_clear(desc, count, unix_epoch_us);
	}

	if (restart_timer)
		cgn_session_start_timer();
}

/*
 * Is session expired?  Returns true if session is expired.
 */
static inline bool cgn_session_expired(struct cgn_session *cse)
{
	uint32_t etime;

	/* Already expired? */
	if (unlikely(cse->cs_forw_entry.ce_expired))
		return true;

	if (rte_atomic16_test_and_set(&cse->cs_idle)) {
		/* Session changed to idle */

		/* Get state-dependent expiry time */
		etime = cgn_session_expiry_time(cse);

		/* Set expiry time */
		cse->cs_etime = get_dp_uptime() + etime;

		return false;
	}

	/*
	 * Session was already idle.  Has it timed-out?
	 */
	if (time_after(get_dp_uptime(), cse->cs_etime)) {
		/* yes, session has timed-out */

		/* Mark session as expired */
		cgn_session_set_expired(cse, false);
		return true;
	}

	return false;
}

/*
 * Session expiry and removal:
 *
 * In gc:
 *   1. if idle flag not set then set idle flag and start expiry time
 *   2. if idle flag set and expiry time has elapsed then set expired flag
 *   3. If expired flag and no-one holds a reference on the session then
 *      set the cs_gc_pass boolean and exit
 *   4. If the cs_gc_pass boolean is set then deactivate the session and
 *      rcu-free
 *
 * Idle flag is cleared every time a packet matches the session
 * (cgn_session_inspect)
 */

/*
 * GC worker routine, Reclaim expired/timed-out sessions
 */
static inline void
cgn_session_gc_inspect(struct cgn_session *cse)
{
	uint s2_unexpd = 0, s2_expd = 0;

	/*
	 * We use the 2-tuple expiry mechanism if 2-tuple session are enabled
	 * and the session has seen at least one packet.
	 *
	 * We use the 3-tuple expiry mechanism if 2-tuple sessions are
	 * disabled *or* the session was created by PCP (or the map command).
	 */
	if (cgn_sess_s2_is_enabled(cse)) {

		/* Are there any unexpired 2-tuple sessions? */
		cgn_sess_s2_gc_walk(&cse->cs_s2, &s2_unexpd, &s2_expd);

		/*
		 * Mark the session as expired when there are no unexpired
		 * nested sessions remaining *and* the session was not created
		 * by PCP (PCP sessions use the timeout value specified in the
		 * PCP request).
		 */
		if (unlikely(s2_unexpd == 0 &&
			     !cse->cs_forw_entry.ce_expired &&
			     !cse->cs_map_instd)) {
			cgn_session_set_expired(cse, false);

			/*
			 * The next GC pass will exit before cs_gc_pass is
			 * tested and incremented since 's2_expd > 0', so we
			 * initialise the pass count to 1 here so that the
			 * 3-tuple session is destroyed on the second pass
			 * after this one (which is consistent with 3-tuple
			 * sessions with no 2-tuple sessions).
			 */
			cse->cs_gc_pass = 1;
		}
	}

	/*
	 * Update subscriber entry with the stats.  This must be done after
	 * the s2 walk, if one occurred.
	 */
	cgn_session_stats_periodic_inline(cse);

	/* Only progress with gc when no nested sessions remain */
	if ((s2_unexpd + s2_expd) > 0)
		return;

	/* Is session expired? */
	if (likely(!cgn_session_expired(cse)))
		return;

	if (cse->cs_gc_pass++ < CGN_SESS_GC_COUNT)
		return;

	/* Remove sentrys' from table, release mapping */
	cgn_session_deactivate(cse);
}

static inline void start_timer(struct rte_timer *timer);

/*
 * Session table garbage collect walk
 */
static void cgn_session_gc(struct rte_timer *timer, void *arg __rte_unused)
{
	struct cds_lfht_iter iter;
	struct cgn_sentry *ce;
	struct cgn_session *cse;

	if (!cgn_sess_ht[CGN_DIR_OUT])
		return;

	/* Walk the forwards-flow session table */
	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_OUT], &iter, ce, ce_node) {

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);
		cgn_session_gc_inspect(cse);
	}

	/* Is table still full? */
	if (cgn_session_table_full &&
	    rte_atomic32_read(&cgn_sessions_used) < cgn_sessions_max)
		cgn_session_set_available();

	/* Restart timer if dataplane is still running. */
	start_timer(timer);
}

static bool is_cgn_helper_thread(void)
{
	return pthread_equal(pthread_self(), cgn_helper_pthread);
}

/*
 * Session table walk to perform logs
 */
static int cgn_session_log_walk(void)
{
	struct cds_lfht_iter iter;
	struct cgn_sentry *ce;
	struct cgn_session *cse;
	unsigned int count = 0;

	ASSERT_CGN_HELPER_THREAD();

	if (!cgn_sess_ht[CGN_DIR_OUT])
		return 0;

	/* Walk the forwards-flow session table */
	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_OUT], &iter, ce, ce_node) {

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);

		if (cgn_sess_s2_is_enabled(cse))
			count += cgn_sess_s2_log_walk(&cse->cs_s2);
	}

	return count;
}

static int cgn_log_sessions(void)
{
	unsigned int count = cgn_session_log_walk();

	/* Increase the sleep interval up to max if nothing to log */
	if (count == 0) {
		if (cgn_sleep_interval < CGNAT_MAX_HELPER_INTERVAL_US) {
			cgn_sleep_interval *= 2;

			cgn_sleep_interval = MIN(cgn_sleep_interval,
				CGNAT_MAX_HELPER_INTERVAL_US);
		}
	} else {
		unsigned int lcore_id = rte_lcore_id();
		struct lcore_cgnat *lcore_info = lcore_conf_get_cgnat(lcore_id);

		lcore_info->logs += count;

		cgn_sleep_interval = 1;
	}

	return cgn_sleep_interval;
}

int cgn_helper_thread_func(unsigned int core_num, void *arg __unused)
{
	RTE_LOG(DEBUG, CGNAT, "Launching CGNAT help thread on core %u\n",
		core_num);

	cgn_helper_core_num = core_num;
	cgn_helper_pthread = pthread_self();
	cgn_sleep_interval = CGNAT_MAX_HELPER_INTERVAL_US;

	CMM_STORE_SHARED(cgn_helper_thread_enabled, 1);

	dp_rcu_register_thread();
	dp_rcu_thread_offline();

	while (CMM_LOAD_SHARED(running) &&
	       CMM_LOAD_SHARED(cgn_helper_thread_enabled)) {
		dp_rcu_thread_online();
		dp_rcu_read_lock();

		cgn_sleep_interval = cgn_log_sessions();

		dp_rcu_read_unlock();
		dp_rcu_thread_offline();
		DP_DEBUG(CGNAT, DEBUG, CGNAT, "On core %u, thread %lu, "
			 "enabled %d, interval %u\n", core_num,
			 cgn_helper_pthread, cgn_helper_thread_enabled,
			 cgn_sleep_interval);
		if (cgn_sleep_interval > 1)
			usleep(cgn_sleep_interval);
	}

	dp_rcu_unregister_thread();
	cgn_helper_core_num = CGN_HELPER_INVALID_CORE_NUM;
	cgn_helper_pthread = 0;
	CMM_STORE_SHARED(cgn_helper_thread_enabled, 0);

	return 0;
}

static void cgn_helper_get_tx(unsigned int lcore_id,
			      uint64_t *pkts)
{
	struct lcore_cgnat *stats;

	stats = lcore_conf_get_cgnat(lcore_id);
	if (stats)
		*pkts = stats->logs;
}

struct dp_lcore_feat cgn_feat = {
	.name = "cgnat",
	.dp_lcore_feat_fn = cgn_helper_thread_func,
	.dp_lcore_feat_get_rx = NULL,
	.dp_lcore_feat_get_tx = cgn_helper_get_tx,
};

static int cgn_stop_helper_thread(void)
{
	unsigned int lcore = cgn_helper_core_num;

	RTE_LOG(DEBUG, CGNAT, "Stopping cgn helper on core %u\n",
		cgn_helper_core_num);

	/* Request the thread exit */
	CMM_STORE_SHARED(cgn_helper_thread_enabled, 0);

	return dp_unallocate_lcore_from_feature(lcore);
}

int cgn_set_helper_thread(unsigned int core_num)
{
	int rc;

	if (CMM_LOAD_SHARED(cgn_helper_thread_enabled)) {
		if (core_num == cgn_helper_core_num)    /* no change */
			return 0;
		cgn_stop_helper_thread();
	}

	RTE_LOG(DEBUG, CGNAT, "Setting helper on core %u\n", core_num);
	cgn_desired_helper_core_num = core_num;

	rc = dp_allocate_lcore_to_feature(core_num, &cgn_feat);
	if (rc)
		RTE_LOG(ERR, CGNAT, "Failed to assign core %u\n", core_num);

	return 0;
}

int cgn_disable_helper_thread(void)
{
	cgn_desired_helper_core_num = CGN_HELPER_INVALID_CORE_NUM;

	return cgn_stop_helper_thread();
}

/*
 * Called from unit-test and from cgn_source_uninit.
 */
void cgn_session_cleanup(void)
{
	uint i;

	/* Stop timer, and expire all entries. Do not restart gc timer */
	cgn_session_expire_all(false, false);

	for (i = 0; i < CGN_SESS_GC_COUNT + 2; i++)
		/* Do not restart gc timer */
		cgn_session_gc(NULL, NULL);
}

/*
 * Called via hidden vplsh command.  Used by unit-test and by dev testers.
 */
void cgn_session_gc_pass(void)
{
	cgn_session_stop_timer();
	cgn_session_gc(&cgn_gc_timer, NULL);
}

/* Start gc timer */
static inline void start_timer(struct rte_timer *timer)
{
	/* Restart timer if dataplane is still running. */
	if (running && timer)
		rte_timer_reset(timer,
				CGN_SESS_GC_INTERVAL * rte_get_timer_hz(),
				SINGLE, rte_get_master_lcore(),
				cgn_session_gc, NULL);
}

/* Stop gc timer */
static inline void stop_timer(struct rte_timer *timer)
{
	if (timer)
		rte_timer_stop(timer);
}

static void cgn_session_start_timer(void)
{
	start_timer(&cgn_gc_timer);
}

static void cgn_session_stop_timer(void)
{
	stop_timer(&cgn_gc_timer);
}

/*
 * Called from DP_EVT_INIT event handler
 */
void cgn_session_init(void)
{
	if (cgn_sess_ht[CGN_DIR_OUT])
		return;

	cgn_sess_ht[CGN_DIR_OUT] =
		cds_lfht_new(CGN_SESSION_HT_INIT, CGN_SESSION_HT_MIN,
			     CGN_SESSION_HT_MAX,
			     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
			     NULL);

	cgn_sess_ht[CGN_DIR_IN] =
		cds_lfht_new(CGN_SESSION_HT_INIT, CGN_SESSION_HT_MIN,
			     CGN_SESSION_HT_MAX,
			     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
			     NULL);

	rte_timer_init(&cgn_gc_timer);
	start_timer(&cgn_gc_timer);
}

/*
 * Called from DP_EVT_UNINIT event handler
 */
void cgn_session_uninit(void)
{
	if (!cgn_sess_ht[CGN_DIR_OUT])
		return;

	/* Expire all entries and run gc multiple times */
	cgn_session_cleanup();

	/* Destroy the session hash tables */
	dp_ht_destroy_deferred(cgn_sess_ht[CGN_DIR_OUT]);
	cgn_sess_ht[CGN_DIR_OUT] = NULL;

	dp_ht_destroy_deferred(cgn_sess_ht[CGN_DIR_IN]);
	cgn_sess_ht[CGN_DIR_IN] = NULL;
}
