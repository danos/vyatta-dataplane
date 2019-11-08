/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
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
#include <time.h>

#include "compiler.h"
#include "pktmbuf.h"
#include "if_var.h"
#include "vplane_log.h"
#include "util.h"
#include "in_cksum.h"

#include "npf/npf_addrgrp.h"
#include "npf/nat/nat_pool_public.h"

#include "npf/cgnat/cgn.h"
#include "npf/apm/apm.h"
#include "npf/cgnat/cgn_cmd_cfg.h"
#include "npf/cgnat/cgn_errno.h"
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

	uint32_t		ce_ifindex;  /* Interface index */
	uint32_t		ce_addr;     /* Address (net order) */
	uint16_t		ce_port;       /* port or id (net order) */
	uint8_t			ce_ipproto;  /* not cgn_proto */
	uint8_t			ce_active;   /* True if sentry in table */
	uint8_t			ce_expired;  /* Expired session */
	uint8_t			ce_established;
	uint8_t			ce_pad2[2];
};

/*
 * cgnat session.
 */
struct cgn_session {
	struct cgn_sentry	cs_forw_entry;	/* 64 bytes MUST. be first */
	/* --- cacheline 1 boundary (64 bytes) --- */

	struct cgn_sentry	cs_back_entry;
	/* --- cacheline 2 boundary (128 bytes) --- */

	uint8_t			cs_gc_pass;
	uint8_t			cs_pad0[1];
	rte_atomic16_t		cs_refcnt;	/* reference count */
	uint32_t		cs_id;		/* unique identifier */
	vrfid_t			cs_vrfid;	/* VRF id (uint32_t) */
	uint32_t		cs_etime;	/* expiry time */
	struct cds_lfht		*cs_sess2_ht;	/* Nested hash table */
	struct cgn_source	*cs_src;	/* Back ptr to subscriber */
	uint64_t		cs_start_time;
	uint64_t		cs_end_time;
	rte_atomic32_t		cs_sess2_id;	/* sess2 ID resource */
	rte_atomic16_t		cs_sess2_used;	/* sess2 count */
	uint8_t			cs_sess2_full;	/* sess2 full */

	/* Logging parameter to be passed to any nested 2-tuple sessions */
	uint8_t			cs_log_start:1;
	uint8_t			cs_log_end:1;

	/* Session instantiated by map cmd and/or a packet */
	uint8_t			cs_pkt_instd:1;
	uint8_t			cs_map_instd:1;

	uint16_t		cs_l3_chk_delta;
	uint16_t		cs_l4_chk_delta;
	uint16_t		cs_map_flag;	/* True if mapping exists */
	rte_atomic16_t		cs_idle;
	/* --- cacheline 3 boundary (192 bytes) --- */

	struct rcu_head		cs_rcu_head;	/* 16 bytes */
	uint16_t		cs_log_periodic;

	/* timeout for a map instantiated session */
	uint32_t		cs_map_timeout;

	uint8_t			cs_pad3[42];	/* pad to cacheline boundary */
	/* --- cacheline 4 boundary (256 bytes) --- */
};


/* session hash tables */
struct cds_lfht *cgn_sess_ht[CGN_DIR_SZ];

/* GC Timer */
struct rte_timer cgn_gc_timer;

/* cs_id resource */
static rte_atomic32_t cgn_id_resource;

/* max sessions, and sessions used */
int32_t cgn_sessions_max = CGN_SESSIONS_MAX;
int16_t cgn_dest_sessions_max = CGN_DEST_SESSIONS_MAX;

/* Global count of all 3-tuple sessions */
rte_atomic32_t cgn_sessions_used;

/* Global count of all 5-tuple sessions */
rte_atomic32_t cgn_sess2_used;

/* Set true when table is full.  Re-evaluated after GC. */
bool cgn_session_table_full;

/* Forward references */
static void cgn_session_expire_all(bool clear_map, bool restart_timer);


/* Time prototypes and functions. */
static void cgn_session_start_timer(void);
static void cgn_session_stop_timer(void);

/*
 * get current monotonic time in approximate seconds
 */
static inline uint32_t cgn_get_time_uptime(void)
{
	/* divide millisecond soft_ticks by 1024 */
	return (uint32_t)(soft_ticks >> 10);
}

/* Is t0 after t1? */
static inline int time_after(uint32_t t0, uint32_t t1)
{
	return (int)(t0 - t1) >= 0;
}

/*
 * Basic log string for a 3-tuple session
 */
static int cgn_session_log_str(struct cgn_session *cse, bool incl_trans,
				 char *log_str, uint log_str_sz)
{
#define ADDR_CHARS 16
	char str1[ADDR_CHARS];
	struct ifnet *ifp;
	uint32_t pid = cgn_session_id(cse);
	uint32_t int_src = cgn_session_forw_addr(cse);
	uint16_t int_port = cgn_session_forw_id(cse);
	uint len;

	ifp = ifnet_byifindex(cgn_session_ifindex(cse));

	len = snprintf(log_str, log_str_sz,
		       "ifname=%s session-id=%u proto=%u "
		       "addr=%s port=%u",
		       ifp ? ifp->if_name : "-", pid,
		       cse->cs_forw_entry.ce_ipproto,
		       cgn_addrstr(ntohl(int_src), str1, ADDR_CHARS),
		       ntohs(int_port));

	if (incl_trans) {
		uint32_t ext_src = cgn_session_back_addr(cse);
		uint16_t ext_port = cgn_session_back_id(cse);

		len += snprintf(log_str + len, log_str_sz - len,
				" cgn-addr=%s cgn-port=%u",
				cgn_addrstr(ntohl(ext_src), str1, ADDR_CHARS),
				ntohs(ext_port));
	}

	return len;
}

/*
 * Update 3-tuple session stats from a 2-tuple session.  Called periodically
 * by the 2-tuple session, and when the 2-tuple session is expired.
 */
void cgn_session_update_stats(struct cgn_session *cse,
			      uint32_t pkts_out, uint32_t bytes_out,
			      uint32_t pkts_in, uint32_t bytes_in,
			      bool expired)
{
	if (expired)
		cgn_source_stats_sess_destroyed(cse->cs_src);

	rte_atomic64_add(&cse->cs_forw_entry.ce_pkts, pkts_out);
	rte_atomic64_add(&cse->cs_forw_entry.ce_bytes, bytes_out);
	rte_atomic64_add(&cse->cs_back_entry.ce_pkts, pkts_in);
	rte_atomic64_add(&cse->cs_back_entry.ce_bytes, bytes_in);
}

/*
 * Called by session gc.
 */
static void
cgn_session_stats_periodic(struct cgn_session *cse)
{
	uint64_t pkts_out, pkts_in, bytes_out, bytes_in;

	pkts_out = rte_atomic64_exchange(
		(volatile uint64_t *)&cse->cs_forw_entry.ce_pkts.cnt, 0UL);

	bytes_out = rte_atomic64_exchange(
		(volatile uint64_t *)&cse->cs_forw_entry.ce_bytes.cnt, 0UL);

	pkts_in = rte_atomic64_exchange(
		(volatile uint64_t *)&cse->cs_back_entry.ce_pkts.cnt, 0UL);

	bytes_in = rte_atomic64_exchange(
		(volatile uint64_t *)&cse->cs_back_entry.ce_bytes.cnt, 0UL);

	cse->cs_forw_entry.ce_pkts_tot += pkts_out;
	cse->cs_forw_entry.ce_bytes_tot += bytes_out;
	cse->cs_back_entry.ce_pkts_tot += pkts_in;
	cse->cs_back_entry.ce_bytes_tot += bytes_in;

	/* Add stats to source totals */
	cgn_source_update_stats(cse->cs_src, pkts_out, bytes_out,
				pkts_in, bytes_in);
}

/* Count hash table nodes */
static ulong cgn_session_table_nodes(struct cds_lfht *ht)
{
	unsigned long count;
	long dummy;

	if (!ht)
		return 0;

	cds_lfht_count_nodes(ht, &dummy, &count, &dummy);
	return count;
}

ulong cgn_session_count(void)
{
	return cgn_session_table_nodes(cgn_sess_ht[CGN_DIR_FORW]);
}

static inline struct cgn_session *
sentry2session(const struct cgn_sentry *ce, int dir)
{
	if (dir == CGN_DIR_FORW)
		return caa_container_of(ce, struct cgn_session, cs_forw_entry);
	else
		return caa_container_of(ce, struct cgn_session, cs_back_entry);
}

static inline struct cgn_sentry *dir2sentry(struct cgn_session *cse, int dir)
{
	if (dir == CGN_DIR_FORW)
		return &cse->cs_forw_entry;
	else
		return &cse->cs_back_entry;
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

uint32_t cgn_session_get_ifindex(const struct cgn_session *cse)
{
	return cse->cs_forw_entry.ce_ifindex;
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

	assert(cse == sentry2session(&cse->cs_forw_entry, CGN_DIR_FORW));
	assert(cse == sentry2session(&cse->cs_back_entry, CGN_DIR_BACK));

	return cse;
}

static void cgn_session_rcu_free(struct rcu_head *head)
{
	struct cgn_session *cse = caa_container_of(head, struct cgn_session,
						   cs_rcu_head);

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

	/* Release address and port mapping */
	uint32_t taddr, oaddr;
	uint16_t tport, oport;
	struct nat_pool *np;
	uint8_t proto;

	/* todo - store forw/rev flag at session creation time */
	cgn_session_get_back(cse, &taddr, &tport);
	cgn_session_get_forw(cse, &oaddr, &oport);
	proto = nat_proto_from_ipproto(cse->cs_forw_entry.ce_ipproto);

	np = cgn_source_get_pool(cse->cs_src);
	assert(np);

	/* Release mapping if one exists */
	if (rte_atomic16_cmpset(&cse->cs_map_flag, true, false))
		cgn_map_put(np, cse->cs_vrfid, CGN_DIR_OUT,
			    proto, oaddr, taddr, tport);

	/* Release reference on source */
	cgn_source_put(cse->cs_src);

	/* Destroy nested hash table? */
	if (cse->cs_sess2_ht)
		cgn_sess2_ht_destroy(&cse->cs_sess2_ht);

	if (rcu_free)
		call_rcu(&cse->cs_rcu_head, cgn_session_rcu_free);
	else
		free(cse);
}

/*
 * cgn_session_get: Get a reference to a cgnat session
 */
struct cgn_session *cgn_session_get(struct cgn_session *cse)
{
	if (cse)
		rte_atomic16_inc(&cse->cs_refcnt);
	return cse;
}

/*
 * cgn_session_put: release a reference, which might allow G/C thread
 * to destroy this session.
 */
void cgn_session_put(struct cgn_session *cse)
{
	if (cse) {
		assert(rte_atomic16_read(&cse->cs_refcnt) > 0);
		rte_atomic16_dec(&cse->cs_refcnt);
	}
}

/*
 * Is there space in the session table?
 */
static bool cgn_session_slot_get(void)
{
	if (rte_atomic32_add_return(&cgn_sessions_used, 1) <= cgn_sessions_max)
		return true;

	rte_atomic32_dec(&cgn_sessions_used);

	if (!cgn_session_table_full)
		RTE_LOG(ERR, CGNAT, "SESSION_TABLE_FULL count=%u/%u\n",
			rte_atomic32_read(&cgn_sessions_used),
			cgn_sessions_max);

	/*
	 * Mark session table as full.  This is reset in the gc when the
	 * session count reduces.
	 */
	cgn_session_table_full = true;

	return false;
}

static void cgn_session_slot_put(void)
{
	rte_atomic32_dec(&cgn_sessions_used);
}

/*
 * cgn_session_establish
 */
struct cgn_session *
cgn_session_establish(struct cgn_packet *cpk, int dir,
		      uint32_t taddr, uint16_t tid, int *error,
		      struct cgn_source *src)
{
	struct cgn_session *cse;
	struct cgn_policy *cp = src->sr_policy;
	uint32_t oaddr;
	uint16_t oid;

	if (dir == CGN_DIR_OUT) {
		oaddr = cpk->cpk_saddr;
		oid   = cpk->cpk_sid;
	} else {
		oaddr = cpk->cpk_daddr;
		oid   = cpk->cpk_did;
	}

	cse = cgn_session_create(error);
	if (!cse)
		return NULL;

	/*
	 * Populate forw sentry.  Extract source addr and port from cache.
	 */
	cse->cs_forw_entry.ce_ifindex =	cpk->cpk_ifindex;
	cse->cs_forw_entry.ce_ipproto = cpk->cpk_ipproto;
	cse->cs_forw_entry.ce_addr = oaddr;
	cse->cs_forw_entry.ce_port = oid;
	cse->cs_forw_entry.ce_established = false;

	/* Populate back entry */
	cse->cs_back_entry.ce_ifindex =	cpk->cpk_ifindex;
	cse->cs_back_entry.ce_ipproto = cpk->cpk_ipproto;
	cse->cs_back_entry.ce_addr = taddr;
	cse->cs_back_entry.ce_port = tid;
	cse->cs_back_entry.ce_established = false;

	rte_atomic16_set(&cse->cs_refcnt, 0);
	rte_atomic16_set(&cse->cs_idle, 0);
	cse->cs_vrfid = cpk->cpk_vrfid;
	cse->cs_start_time = soft_ticks;
	cse->cs_log_start = cp->cp_log_sess_start ? 1 : 0;
	cse->cs_log_end = cp->cp_log_sess_end ? 1 : 0;
	cse->cs_log_periodic = cp->cp_log_sess_periodic;

	/* calculate checksum deltas */
	const uint32_t *oip32 = (const uint32_t *)&oaddr;
	const uint32_t *nip32 = (const uint32_t *)&taddr;

	cse->cs_l3_chk_delta = ~ip_fixup32_cksum(0, *oip32, *nip32);
	cse->cs_l4_chk_delta = ~ip_fixup16_cksum(0, oid, tid);

	/*
	 * Does session need nested 2-tuple table?
	 */
	if (cgn_policy_record_dest(cp, oaddr, dir)) {
		cse->cs_sess2_ht = cgn_sess2_ht_create();

		if (!cse->cs_sess2_ht) {
			*error = -CGN_S1_ENOMEM;
			free(cse);
			return NULL;
		}
	}

	/* Take reference on source */
	cse->cs_src = cgn_source_get(src);

	/* We already have a mapping */
	cse->cs_map_flag = true;

	cse->cs_id = rte_atomic32_add_return(&cgn_id_resource, 1);

	return cse;
}

bool cgn_session_log_start(struct cgn_session *cse)
{
	return cse->cs_log_start;
}

bool cgn_session_log_end(struct cgn_session *cse)
{
	return cse->cs_log_end;
}

/* Units of session gc intervals (i.e. 10 secs) */
uint16_t cgn_session_log_periodic(struct cgn_session *cse)
{
	return cse->cs_log_periodic;
}

uint32_t cgn_session_ifindex(struct cgn_session *cse)
{
	return cse->cs_forw_entry.ce_ifindex;
}

/* session ID.  (not port) */
uint32_t cgn_session_id(struct cgn_session *cse)
{
	return cse->cs_id;
}

static int cgn_sentry_insert(struct cgn_sentry *ce, struct cgn_sentry **old,
			     enum cgn_flow dir);
static void cgn_sentry_delete(struct cgn_sentry *ce, enum cgn_flow dir);

/*
 * Is there space in the nested session table?
 */
static bool cgn_sess2_slot_get(struct cgn_session *cse)
{
	if (rte_atomic16_add_return(&cse->cs_sess2_used, 1) <=
	    cgn_dest_sessions_max) {
		/* Success */
		rte_atomic32_inc(&cgn_sess2_used);
		return true;
	}

	/*
	 * No slots available.  Decrement cs_sess2_used again.
	 */
	rte_atomic16_dec(&cse->cs_sess2_used);

	if (net_ratelimit() && !cse->cs_sess2_full) {
		char log_str[140];

		cgn_session_log_str(cse, true, log_str, sizeof(log_str));

		RTE_LOG(ERR, CGNAT, "DEST_SESSIONS_FULL count=%u %s\n",
			rte_atomic16_read(&cse->cs_sess2_used), log_str);
	}

	/*
	 * Mark nested session table as full.  This is reset in the gc when
	 * the session count reduces.
	 */
	cse->cs_sess2_full = true;

	return false;
}

void cgn_sess2_slot_put(struct cgn_session *cse)
{
	rte_atomic16_dec(&cse->cs_sess2_used);
	rte_atomic32_dec(&cgn_sess2_used);
}

/*
 * Create a nested session
 */
static int
cgn_sess2_establish_and_activate(struct cgn_session *cse,
				 struct cgn_packet *cpk, int dir)
{
	struct cgn_sess2 *s2;
	int rc;

	/* Reserve a slot from the counters */
	if (unlikely(!cgn_sess2_slot_get(cse)))
		return -CGN_S2_ENOSPC;

	s2 = cgn_sess2_establish(cse, cpk, &cse->cs_sess2_id, dir);
	if (unlikely(!s2)) {
		cgn_sess2_slot_put(cse);
		return -CGN_S2_ENOMEM;
	}

	rc = cgn_sess2_activate(cse->cs_sess2_ht, s2);
	if (unlikely(rc < 0)) {
		/* Lost race to insert sess2 */
		cgn_sess2_slot_put(cse);
		free(s2);
		return rc;
	}

	cgn_source_stats_sess_created(cse->cs_src);
	return 0;
}

/*
 * cgn_session_activate
 *
 * Activate new 3-tuple session.
 */
int cgn_session_activate(struct cgn_session *cse,
			 struct cgn_packet *cpk, int dir)
{
	struct cgn_sentry *old;
	int rc = 0;

	/*
	 * Already active?  (Both or  neither are active,  so just  check forw
	 * sentry)
	 */
	if (cse->cs_forw_entry.ce_active)
		return 0;

	/* Reserve a slot from the counters */
	if (unlikely(!cgn_session_slot_get()))
		return -CGN_S1_ENOSPC;

	/* Insert forw sentry into table */
	rc = cgn_sentry_insert(&cse->cs_forw_entry, &old, CGN_DIR_FORW);
	if (unlikely(rc < 0)) {
		cgn_session_slot_put();
		goto end;
	}

	/* Insert back sentry into table */
	rc = cgn_sentry_insert(&cse->cs_back_entry, &old, CGN_DIR_BACK);
	if (unlikely(rc < 0)) {
		cgn_sentry_delete(&cse->cs_forw_entry, CGN_DIR_FORW);
		cgn_session_slot_put();
		goto end;
	}

	/* Add a nested 2-tuple session? */
	if (cse->cs_sess2_ht && cpk->cpk_keepalive) {
		rc = cgn_sess2_establish_and_activate(cse, cpk, dir);

		/* Count the error, then ignore it */
		if (rc < 0) {
			cgn_error_inc(rc, dir);
			rc = 0;
		}
	} else {
		struct cgn_sentry *ce = dir2sentry(cse, dir);

		cgn_source_stats_sess_created(cse->cs_src);
		rte_atomic64_inc(&ce->ce_pkts);
		rte_atomic64_add(&ce->ce_bytes, cpk->cpk_len);
	}

end:
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
		cgn_sentry_delete(&cse->cs_forw_entry, CGN_DIR_FORW);
		cgn_sentry_delete(&cse->cs_back_entry, CGN_DIR_BACK);

		/* Release the slot */
		cgn_session_slot_put();

		/* If nested sessions are in-use then we count them */
		if (!cse->cs_sess2_ht)
			cgn_source_stats_sess_destroyed(cse->cs_src);
	}
}

static ALWAYS_INLINE ulong
cgn_hash(uint16_t id, uint32_t addr, uint32_t ifindex, uint8_t ipproto)
{
	return rte_jhash_3words(id, addr, ipproto, ifindex);
}

static ulong
cgn_hash_sentry(const struct cgn_sentry *ce)
{
	ulong hash;

	hash = cgn_hash(ce->ce_port, ce->ce_addr, ce->ce_ifindex,
			ce->ce_ipproto);
	return hash;
}

static ALWAYS_INLINE int
cgn_sess_match(const struct cgn_sentry *ce, uint16_t id, uint32_t addr,
	       uint32_t ifindex, uint8_t proto)
{
	/* Ports are expected to vary most */
	if (ce->ce_port != id)
		return 0;

	if (ce->ce_addr != addr)
		return 0;

	if (ce->ce_ifindex != ifindex)
		return 0;

	if (ce->ce_ipproto != proto)
		return 0;

	return 1;
}

/*
 * cgn_sess_node_match.  Used when inserting a sentry.
 */
static int
cgn_sess_node_match(struct cds_lfht_node *node, const void *key)
{
	const struct cgn_sentry *ce1, *ce2;
	int rc;

	ce1 = caa_container_of(node, struct cgn_sentry, ce_node);
	ce2 = key;

	if (unlikely(ce1->ce_expired))
		return 0;

	rc = cgn_sess_match(ce1, ce2->ce_port, ce2->ce_addr,
			    ce2->ce_ifindex, ce2->ce_ipproto);
	return rc;
}

/*
 * lfht match function, key is a pointer to a 'struct sess_lookup_key' object
 */
static int
cgn_sess_lkey_match(struct cds_lfht_node *node, const void *key)
{
	const struct sess_lookup_key *lkey = key;
	const struct cgn_sentry *ce;
	int rc;

	ce = caa_container_of(node, struct cgn_sentry, ce_node);

	if (unlikely(ce->ce_expired))
		return 0;

	rc = cgn_sess_match(ce, lkey->sk_id, lkey->sk_addr,
			    lkey->sk_ifindex, lkey->sk_ipproto);

	return rc;
}

/*
 * Lookup hash table with given key.  Return pointer to hash table node.
 */
static inline struct cds_lfht_node *
cgn_session_node(struct sess_lookup_key *key, int dir,
		 struct cds_lfht_iter *iter)
{
	ulong hash;

	hash = cgn_hash(key->sk_id, key->sk_addr, key->sk_ifindex,
			key->sk_ipproto);

	cds_lfht_lookup(cgn_sess_ht[dir], hash, cgn_sess_lkey_match,
			key, iter);

	return cds_lfht_iter_get_node(iter);
}

/*
 *  Lookup hash table with given key and return the next node.
 */
static inline struct cds_lfht_node *
cgn_session_node_next(struct sess_lookup_key *key, int dir,
		      struct cds_lfht_iter *iter)
{
	struct cds_lfht_node *node;
	ulong hash;

	hash = cgn_hash(key->sk_id, key->sk_addr, key->sk_ifindex,
			key->sk_ipproto);

	cds_lfht_lookup(cgn_sess_ht[dir], hash, cgn_sess_lkey_match,
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
cgn_session_node_first(int dir, struct cds_lfht_iter *iter)
{
	cds_lfht_first(cgn_sess_ht[dir], iter);
	return cds_lfht_iter_get_node(iter);
}

/*
 * Insert sentry into hash table
 */
static int
cgn_sentry_insert(struct cgn_sentry *ce, struct cgn_sentry **old,
		  enum cgn_flow dir)
{
	struct cds_lfht_node *node;

	node = cds_lfht_add_unique(cgn_sess_ht[dir], cgn_hash_sentry(ce),
				   cgn_sess_node_match, ce, &ce->ce_node);

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
static void cgn_sentry_delete(struct cgn_sentry *ce, enum cgn_flow dir)
{
	if (cgn_sess_ht[dir])
		(void)cds_lfht_del(cgn_sess_ht[dir], &ce->ce_node);
	ce->ce_active = false;
}

/*
 * If dir is CGN_DIR_OUT, then key represents a source address and port.
 * If dir is CGN_DIR_IN, then key represents a dest address and port.
 */
static inline struct cgn_sentry *
cgn_sentry_lookup_by_key(struct sess_lookup_key *key, int dir)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	node = cgn_session_node(key, dir, &iter);
	if (!node)
		return NULL;

	return caa_container_of(node, struct cgn_sentry, ce_node);
}

/*
 * cgn_sentry_lookup
 *
 * 'dir' - determines which table we lookup - forw (out) table or back (in)
 *         table.
 *
 * 'lookup_src' - lookup source addr and port (true when 'dir == CGN_DIR_OUT'
 *                for normal operation, and 'dir == CGN_DIR_IN' for icmp
 *                errors)
 */
static inline struct cgn_sentry *
cgn_sentry_lookup(struct cgn_packet *cpk, int dir, bool lookup_src)
{
	struct sess_lookup_key lkey;

	/* Populate lookup key */
	lkey.sk_ifindex = cpk->cpk_ifindex;
	lkey.sk_ipproto = cpk->cpk_ipproto;

	if (lookup_src) {
		lkey.sk_addr = cpk->cpk_saddr;
		lkey.sk_id   = cpk->cpk_sid;
	} else {
		lkey.sk_addr = cpk->cpk_daddr;
		lkey.sk_id   = cpk->cpk_did;
	}

	return cgn_sentry_lookup_by_key(&lkey, dir);
}

/*
 * cgn_session_lookup
 */
struct cgn_session *
cgn_session_lookup(struct cgn_packet *cpk, int dir)
{
	struct cgn_sentry *ce;

	ce = cgn_sentry_lookup(cpk, dir, (dir == CGN_DIR_OUT));
	if (ce) {
		struct cgn_session *cse = sentry2session(ce, dir);

		return cse;
	}

	return NULL;
}

/*
 * If dir is CGN_DIR_OUT, then key represents a source address and port.
 * If dir is CGN_DIR_IN, then key represents a dest address and port.
 */
static struct cgn_session *
cgn_session_lookup_by_key(struct sess_lookup_key *key, int dir)
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
cgn_session_lookup_icmp_err(struct cgn_packet *cpk, int dir)
{
	struct cgn_sentry *ce;

	/*
	 * For inbound traffic, lookup the embedded source address.  For
	 * outbound traffic, lookup the embedded destination address.
	 */
	ce = cgn_sentry_lookup(cpk, dir, (dir == CGN_DIR_IN));
	if (ce) {
		struct cgn_session *cse = sentry2session(ce, dir);

		return cse;
	}

	return NULL;
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
 * Inspect an already activated 3-tuple session.
 */
struct cgn_session *
cgn_session_inspect(struct cgn_packet *cpk, int dir)
{
	struct cgn_sentry *ce;

	ce = cgn_sentry_lookup(cpk, dir, (dir == CGN_DIR_OUT));
	if (!ce)
		return NULL;

	struct cgn_session *cse = sentry2session(ce, dir);

	/* Simple state mechanism for 3-tuple sessions */
	if (unlikely(dir == CGN_DIR_BACK && !ce->ce_established))
		ce->ce_established = true;

	/* session may have been created by a map cmd */
	if (unlikely(!cse->cs_pkt_instd))
		cse->cs_pkt_instd = true;

	/*
	 * If we have nested 2-tuple sessions then they take care of sessions
	 * idle monitoring and stats.
	 */
	if (unlikely(cse->cs_sess2_ht)) {
		struct cgn_sess2 *s2;

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
		s2 = cgn_sess2_inspect(cse->cs_sess2_ht, cpk, dir);

		/* Add a nested 2-tuple session? */
		if (!s2 && cpk->cpk_keepalive) {
			int rc;
			rc = cgn_sess2_establish_and_activate(cse, cpk, dir);

			/* Count the error, then ignore it */
			if (rc < 0)
				cgn_error_inc(rc, dir);
		}
	} else {
		/*
		 * Clear idle flag, if packet is eligible.
		 */
		if (cpk->cpk_keepalive &&
		    rte_atomic16_read(&cse->cs_idle) != 0)
			rte_atomic16_clear(&cse->cs_idle);

		rte_atomic64_inc(&ce->ce_pkts);
		rte_atomic64_add(&ce->ce_bytes, cpk->cpk_len);
	}

	return cse;
}

/*
 * Session  walk
 */
int cgn_session_walk(cgn_sesswalk_cb cb, void *data)
{
	struct cds_lfht_iter iter;
	struct cgn_session *cse;
	struct cgn_sentry *ce;
	int rc;

	if (!cgn_sess_ht[CGN_DIR_FORW])
		return -ENOENT;

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_FORW], &iter, ce, ce_node) {

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);

		rc = cb(cse, data);
		if (rc)
			return rc;
	}
	return 0;
}

/*
 * State dependent expiry time for 3-tuple sessions
 */
static uint32_t cgn_session_expiry_time(struct cgn_session *cse)
{
	uint8_t proto, state;

	if (cse->cs_back_entry.ce_expired)
		return 0;

	proto = nat_proto_from_ipproto(cse->cs_forw_entry.ce_ipproto);

	if (cse->cs_back_entry.ce_established)
		state = CGN_SESS_STATE_ESTABLISHED;
	else
		state = CGN_SESS_STATE_INIT;

	return cgn_sess_state_expiry_time(proto, state);
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
	for (i = 0; i < argc; i++)
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
			fltr->cf_subs.sk_ipproto = tmp;
			fltr->cf_pub.sk_ipproto = tmp;

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
			memcpy(&fltr->cf_subs.sk_addr, &npf_addr, 4);
			tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
			fltr->cf_subs_mask = htonl(tmp);
			fltr->cf_subs.sk_addr &= fltr->cf_subs_mask;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "subs-port") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > USHRT_MAX) {
				cmd_err(f, "invalid subs-port: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_subs.sk_id = htons(tmp);

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
			memcpy(&fltr->cf_pub.sk_addr, &npf_addr, 4);
			tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
			fltr->cf_pub_mask = htonl(tmp);
			fltr->cf_pub.sk_addr &= fltr->cf_pub_mask;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "pub-port") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > USHRT_MAX) {
				cmd_err(f, "invalid pub-port: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_pub.sk_id = htons(tmp);

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
			memcpy(&fltr->cf_dst.s2k_addr, &npf_addr, 4);
			tmp = (0xFFFFFFFF << (32 - pl)) & 0xFFFFFFFF;
			fltr->cf_dst_mask = htonl(tmp);
			fltr->cf_dst.s2k_addr &= fltr->cf_dst_mask;

			argc -= 2;
			argv += 2;
			fltr->cf_all = false;

		} else if (!strcmp(argv[0], "dst-port") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > USHRT_MAX) {
				cmd_err(f, "invalid dst-port: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_dst.s2k_id = htons(tmp);

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
			struct ifnet *ifp = ifnet_byifname(argv[1]);

			if (!ifp) {
				cmd_err(f, "invalid interface: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_subs.sk_ifindex = ifp->if_index;
			fltr->cf_pub.sk_ifindex = ifp->if_index;

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
			memcpy(&fltr->cf_tgt.sk_addr, &npf_addr, 4);

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "tgt-port") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > USHRT_MAX) {
				cmd_err(f, "invalid tgt-port: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_tgt.sk_id = htons(tmp);

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "tgt-proto") && argc >= 2) {
			tmp = cgn_arg_to_int(argv[1]);

			if (tmp < 0 || tmp > UCHAR_MAX) {
				cmd_err(f, "invalid tgt-proto: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_tgt.sk_ipproto = tmp;

			argc -= 2;
			argv += 2;

		} else if (!strcmp(argv[0], "tgt-intf") && argc >= 2) {
			struct ifnet *ifp = ifnet_byifname(argv[1]);

			if (!ifp) {
				cmd_err(f, "invalid tgt-intf: %s\n", argv[1]);
				return -1;
			}
			fltr->cf_tgt.sk_ifindex = ifp->if_index;

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
			if (tmp < 0)
				cmd_err(f, "invalid timeout: %s\n", argv[1]);

			fltr->cf_timeout = tmp;

			argc -= 2;
			argv += 2;

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

	if (fltr->cf_dst.s2k_addr || fltr->cf_dst.s2k_id || fltr->cf_id2) {
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
	uint8_t proto = 0;
	char *sa_arg = NULL;
	int rc, i, error = 0;

	memset(&fltr, 0, sizeof(fltr));
	memset(&cpk, 0, sizeof(cpk));

	/* Result is returned in json */
	json = jsonw_new(f);
	if (!json)
		return -1;

	if (argc < 12)
		goto error;

	/* Remove "cgn-op map" */
	argc -= 2;
	argv += 2;

	/* Note the subscriber params in case of error */
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i-1], "subs-addr"))
			sa_arg = argv[i];
	}

	/* Parse options */
	rc = cgn_session_op_parse(f, argc, argv, &fltr);
	if (rc < 0)
		goto error;

	/* check the subscriber (private) address and port */
	if (fltr.cf_subs.sk_addr == 0 || fltr.cf_subs_mask != 0xFFFFFFFF ||
	    fltr.cf_subs.sk_id == 0)
		goto error;

	/* check the protocol */
	proto = fltr.cf_subs.sk_ipproto;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	    proto != IPPROTO_UDPLITE && proto != IPPROTO_DCCP)
		goto error;

	/* check the interface */
	ifp = ifnet_byifindex(fltr.cf_subs.sk_ifindex);
	if (!ifp)
		goto error;

	/* convert fltr params to cgnat cache params */
	cpk.cpk_saddr = fltr.cf_subs.sk_addr;
	cpk.cpk_sid = fltr.cf_subs.sk_id;
	cpk.cpk_ipproto = proto;
	cpk.cpk_ifindex = fltr.cf_subs.sk_ifindex;
	cpk.cpk_l4ports = true;

	cpk.cpk_proto = nat_proto_from_ipproto(cpk.cpk_ipproto);
	cpk.cpk_vrfid = if_vrfid(ifp);

	/* Create and activate a session */
	cse = cgn_session_map(ifp, &cpk, CGN_DIR_OUT, &error);
	if (!cse)
		goto error;

	cse->cs_map_timeout = fltr.cf_timeout;
	cse->cs_map_instd = true;

	char subs_addr[16];
	char pub_addr[16];

	inet_ntop(AF_INET, &cse->cs_forw_entry.ce_addr,
		  subs_addr, sizeof(subs_addr));

	inet_ntop(AF_INET, &cse->cs_back_entry.ce_addr,
		  pub_addr, sizeof(pub_addr));

	jsonw_name(json, "map");
	jsonw_start_object(json);

	jsonw_int_field(json, "result", 0);
	jsonw_string_field(json, "intf", ifp->if_name);
	jsonw_uint_field(json, "proto", proto);
	jsonw_string_field(json, "subs_addr", subs_addr);
	jsonw_uint_field(json, "subs_port", ntohs(cse->cs_forw_entry.ce_port));
	jsonw_string_field(json, "pub_addr", pub_addr);
	jsonw_uint_field(json, "pub_port", ntohs(cse->cs_back_entry.ce_port));
	jsonw_uint_field(json, "timeout", fltr.cf_timeout);

	jsonw_end_object(json);
	jsonw_destroy(&json);

	return 0;

error:
	jsonw_name(json, "map");
	jsonw_start_object(json);

	if (error >= 0)
		error = -CGN_ERR_UNKWN;

	jsonw_int_field(json, "result", error);
	jsonw_string_field(json, "error", cgn_errno_str(error));

	jsonw_string_field(json, "intf", ifp ? ifp->if_name : "?");
	jsonw_uint_field(json, "proto", proto);
	jsonw_string_field(json, "subs_addr", sa_arg ? sa_arg : "0.0.0.0");
	jsonw_uint_field(json, "subs_port", ntohs(fltr.cf_subs.sk_id));
	jsonw_string_field(json, "pub_addr", "0.0.0.0");
	jsonw_uint_field(json, "pub_port", 0);
	jsonw_uint_field(json, "timeout", fltr.cf_timeout);

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

	/*
	 * If nested sessions are enabled and the user has specified some
	 * filter criteria for those sessions then do not display the outer
	 * 3-tuple session if no 2-tuple sessions match the criteria.
	 */
	if (cse->cs_sess2_ht && !fltr->cf_all_sess2 && !fltr->cf_no_sess2) {
		uint s2_count = cgn_sess2_show_count(cse->cs_sess2_ht, fltr);

		if (s2_count == 0)
			return 0;
	}

	inet_ntop(AF_INET, &cse->cs_forw_entry.ce_addr,
		  src_str, sizeof(src_str));
	inet_ntop(AF_INET, &cse->cs_back_entry.ce_addr,
		  trans_str, sizeof(trans_str));
	ifp = ifnet_byifindex(cse->cs_forw_entry.ce_ifindex);

	jsonw_start_object(json);

	jsonw_uint_field(json, "id", cse->cs_id);

	jsonw_string_field(json, "subs_addr", src_str);
	jsonw_uint_field(json, "subs_port", htons(cse->cs_forw_entry.ce_port));

	jsonw_string_field(json, "pub_addr", trans_str);
	jsonw_uint_field(json, "pub_port", htons(cse->cs_back_entry.ce_port));

	jsonw_uint_field(json, "proto", cse->cs_forw_entry.ce_ipproto);
	jsonw_string_field(json, "intf", ifp->if_name);

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

	jsonw_bool_field(json, "exprd", cse->cs_forw_entry.ce_expired);
	jsonw_uint_field(json, "refcnt", rte_atomic16_read(&cse->cs_refcnt));

	if (cse->cs_sess2_ht) {
		ulong ht_count;

		/* count may be less than ht_count if there are filters */
		if (!fltr->cf_no_sess2)
			count = cgn_sess2_show(json, cse->cs_sess2_ht, fltr);

		ht_count = cgn_sess2_count(cse->cs_sess2_ht);
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

		jsonw_uint_field(json, "max_to", 0);
		jsonw_uint_field(json, "cur_to", 0);
	} else {
		uint32_t uptime = cgn_get_time_uptime();
		uint32_t max_timeout = cgn_session_expiry_time(cse);

		if (cse->cs_forw_entry.ce_expired)
			jsonw_uint_field(json, "state", CGN_SESS_STATE_CLOSED);
		else if (cse->cs_back_entry.ce_established)
			jsonw_uint_field(json, "state",
					 CGN_SESS_STATE_ESTABLISHED);
		else
			jsonw_uint_field(json, "state", CGN_SESS_STATE_INIT);

		if (rte_atomic16_read(&cse->cs_idle))
			jsonw_uint_field(json, "cur_to",
					 (cse->cs_etime > uptime) ?
					 (cse->cs_etime - uptime) : 0);
		else
			jsonw_uint_field(json, "cur_to", max_timeout);

		jsonw_uint_field(json, "max_to", max_timeout);
		jsonw_uint_field(json, "nsessions", 0);
	}

	jsonw_uint_field(json, "start_time",
			 cgn_ticks2timestamp(cse->cs_start_time));
	jsonw_uint_field(json, "duration",
			 cgn_start2duration(cse->cs_start_time));

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
	    fltr->cf_subs.sk_addr != (fw->ce_addr & fltr->cf_subs_mask))
		return false;

	if (fltr->cf_subs.sk_id && fltr->cf_subs.sk_id != fw->ce_port)
		return false;

	/* Filter on IP protocol */
	if (fltr->cf_subs.sk_ipproto &&
	    fltr->cf_subs.sk_ipproto != fw->ce_ipproto)
		return false;

	/* Filter on interface */
	if (fltr->cf_subs.sk_ifindex &&
	    fltr->cf_subs.sk_ifindex != fw->ce_ifindex)
		return false;

	/* Filter on Public address and port */
	if (fltr->cf_pub_mask &&
	    fltr->cf_pub.sk_addr != (bk->ce_addr & fltr->cf_pub_mask))
		return false;

	if (fltr->cf_pub.sk_id && fltr->cf_pub.sk_id != bk->ce_port)
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

/*
 * cgn-op show session ...
 */
void cgn_session_show(FILE *f, int argc, char **argv)
{
	struct cgn_sess_fltr fltr;
	struct cgn_session *cse;
	json_writer_t *json;
	uint count = 0;
	int rc;

	/* Remove "cgn-op show session" */
	argc -= 3;
	argv += 3;

	json = jsonw_new(f);
	if (!json)
		return;

	jsonw_name(json, "sessions");
	jsonw_start_array(json);

	rc = cgn_session_op_parse(f, argc, argv, &fltr);
	if (rc < 0)
		goto end;

	if (!cgn_sess_ht[CGN_DIR_FORW])
		goto end;

	/*
	 * Are there enough filter params to do a hash lookup in the forwards
	 * sentries?  We need subscriber (source) address and port, interface,
	 * and protocol.
	 */
	if (fltr.cf_subs_mask == 0xffffffff &&
	    cgn_sess_key_valid(&fltr.cf_subs)) {

		cse = cgn_session_lookup_by_key(&fltr.cf_subs, CGN_DIR_OUT);

		if (cse && cgn_session_show_fltr(cse, &fltr))
			cgn_session_jsonw_one(json, &fltr, cse);
		goto end;
	}

	/*
	 * Are there enough filter params to do a hash lookup in the backwards
	 * sentries?  We need public (dest) address and port, interface, and
	 * protocol.
	 */
	if (fltr.cf_pub_mask == 0xffffffff &&
	    cgn_sess_key_valid(&fltr.cf_pub)) {

		cse = cgn_session_lookup_by_key(&fltr.cf_pub, CGN_DIR_IN);

		if (cse && cgn_session_show_fltr(cse, &fltr))
			cgn_session_jsonw_one(json, &fltr, cse);
		goto end;
	}

	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct cgn_sentry *ce;

	/* Start at the node *after* the specified target, if any */
	if (cgn_sess_key_valid(&fltr.cf_tgt))
		node = cgn_session_node_next(&fltr.cf_tgt, CGN_DIR_OUT, &iter);
	else
		/* else start at start */
		node = cgn_session_node_first(CGN_DIR_OUT, &iter);

	for (; node != NULL;
	     cds_lfht_next(cgn_sess_ht[CGN_DIR_OUT], &iter),
		     node = cds_lfht_iter_get_node(&iter)) {

		ce = caa_container_of(node, struct cgn_sentry, ce_node);
		cse = sentry2session(ce, CGN_DIR_OUT);

		if (cgn_session_show_fltr(cse, &fltr))
			count += cgn_session_jsonw_one(json, &fltr, cse);

		/* Have we added enough sessions yet? */
		if (fltr.cf_count > 0 && count >= fltr.cf_count)
			break;
	}

end:
	jsonw_end_array(json);
	jsonw_destroy(&json);
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

	if (!cgn_sess_ht[CGN_DIR_FORW])
		goto end;

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_FORW], &iter, fw, ce_node) {
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
cgn_session_set_expired(struct cgn_session *cse)
{
	cse->cs_forw_entry.ce_expired = true;
	cse->cs_back_entry.ce_expired = true;
	cse->cs_end_time = soft_ticks;
	cse->cs_etime = 0;

	/* Add stats to source totals */
	cgn_session_stats_periodic(cse);
}

/*
 * Force clearing of a session mapping
 */
static void cgn_session_clear_mapping(struct cgn_session *cse)
{
	struct nat_pool *np;

	if (cse->cs_src)
		cse->cs_src->sr_paired_addr = 0;

	np = cgn_source_get_pool(cse->cs_src);
	assert(np);

	/* Release mapping immediately */
	if (rte_atomic16_cmpset(&cse->cs_map_flag, true, false)) {
		uint32_t taddr, oaddr;
		uint16_t tport, oport;
		uint8_t proto;

		cgn_session_get_back(cse, &taddr, &tport);
		cgn_session_get_forw(cse, &oaddr, &oport);
		proto = nat_proto_from_ipproto(cse->cs_forw_entry.ce_ipproto);

		cgn_map_put(np, cse->cs_vrfid, CGN_DIR_OUT, proto, oaddr,
			    taddr, tport);
	}
}

/*
 * Log a session clear event.  This is done when one or more 2-tuple sessions
 * are cleared manually, either from a clear command or a change in config
 * (e.g. nat pool block size changes).  This log message replaces the
 * multiple SESSION_END log messages in order to avoid scale issues.
 */
static void
cgn_log_sess_clear(const char *desc, uint count, uint64_t clear_time)
{
#define LOG_STR_SZ 300
	char log_str[LOG_STR_SZ];

	snprintf(log_str, sizeof(log_str),
			"desc=\"%s\" count=%u time=%lu", desc, count,
			cgn_ticks2timestamp(clear_time));

	RTE_LOG(NOTICE, CGNAT, "SESSION_CLEAR %s\n", log_str);
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

	if (!cgn_sess_ht[CGN_DIR_FORW])
		return;

	/*
	 * We do not want an expired timer competing with the cli or ut, so
	 * stop timer while expiring sessions.
	 */
	cgn_session_stop_timer();

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_FORW], &iter, ce, ce_node) {
		if (!clear_map && ce->ce_expired)
			continue;

		/* Filter on IP protocol */
		if (fltr->cf_subs.sk_ipproto &&
		    fltr->cf_subs.sk_ipproto != ce->ce_ipproto)
			continue;

		/* Filter on Subscriber address and port */
		if (fltr->cf_subs_mask &&
		    fltr->cf_subs.sk_addr != (ce->ce_addr & fltr->cf_subs_mask))
			continue;

		if (fltr->cf_subs.sk_id && fltr->cf_subs.sk_id != ce->ce_port)
			continue;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);
		bk = &cse->cs_back_entry;

		/* Filter on Public address and port */
		if (fltr->cf_pub_mask &&
		    fltr->cf_pub.sk_addr != (bk->ce_addr & fltr->cf_pub_mask))
			continue;

		if (fltr->cf_pub.sk_id && fltr->cf_pub.sk_id != bk->ce_port)
			continue;

		/* Filter on session ID */
		if (fltr->cf_id1) {
			if (fltr->cf_id1 != cse->cs_id)
				continue;

			/* Expire one or all 2-tuple sessions */
			if (cse->cs_sess2_ht)
				count += cgn_sess2_expire_id(cse->cs_sess2_ht,
							     fltr->cf_id2);

			/*
			 * If no unexpired 2-tuple sessions remain then expire
			 * 3-tuple session and clear mapping.
			 */
			if (!cse->cs_sess2_ht ||
			    cgn_sess2_unexpired(cse->cs_sess2_ht) == 0) {

				if (!ce->ce_expired)
					cgn_session_set_expired(cse);

				if (clear_map)
					cgn_session_clear_mapping(cse);
			}

			continue;
		}

		/* Filter on interface */
		if (fltr->cf_subs.sk_ifindex &&
		    fltr->cf_subs.sk_ifindex != ce->ce_ifindex)
			continue;

		/* Filter on NAT pool */
		if (fltr->cf_np &&
		    fltr->cf_np != cgn_source_get_pool(cse->cs_src))
			continue;

		if (!ce->ce_expired) {
			if (cse->cs_sess2_ht)
				count += cgn_sess2_expire_all(cse->cs_sess2_ht);

			cgn_session_set_expired(cse);
		}

		if (clear_map)
			cgn_session_clear_mapping(cse);
	}

	/* Log session clear command instead of every session */
	if (count)
		cgn_log_sess_clear(fltr->cf_desc, count, soft_ticks);

	if (running && restart_timer)
		cgn_session_start_timer();
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

	if (fltr.cf_all) {
		cgn_session_expire_all(true, true);
		return;
	}

	cgn_session_clear_fltr(&fltr, true, true);
}

static void
cgn_session_expire_all(bool clear_map, bool restart_timer)
{
	struct cds_lfht_iter iter;
	struct cgn_session *cse;
	struct cgn_sentry *ce;
	uint count = 0;

	if (!cgn_sess_ht[CGN_DIR_FORW])
		return;

	/*
	 * We do not want an expired timer competing with the cli or ut, so
	 * stop timer while expiring sessions.
	 */
	cgn_session_stop_timer();

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_FORW], &iter, ce, ce_node) {
		if (!clear_map && ce->ce_expired)
			continue;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);

		if (!ce->ce_expired) {
			if (cse->cs_sess2_ht)
				count += cgn_sess2_expire_all(cse->cs_sess2_ht);

			cgn_session_set_expired(cse);
		}

		if (clear_map)
			cgn_session_clear_mapping(cse);
	}

	/* Log session clear command instead of every session */
	if (count)
		cgn_log_sess_clear("all", count, soft_ticks);

	if (running && restart_timer)
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

	if (!cgn_sess_ht[CGN_DIR_FORW])
		return;

	/*
	 * We do not want an expired timer competing with the cli or ut, so
	 * stop timer while expiring sessions.
	 */
	cgn_session_stop_timer();

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_FORW], &iter, ce, ce_node) {
		struct nat_pool *cs_np;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);

		cs_np = cgn_source_get_pool(cse->cs_src);
		if (cs_np != np)
			continue;

		if (!ce->ce_expired) {
			if (cse->cs_sess2_ht)
				count += cgn_sess2_expire_all(cse->cs_sess2_ht);

			cgn_session_set_expired(cse);
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
		cgn_log_sess_clear(desc, count, soft_ticks);
	}

	if (running && restart_timer)
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

	if (!cgn_sess_ht[CGN_DIR_FORW])
		return;

	/*
	 * We do not want an expired timer competing with the cli or ut, so
	 * stop timer while expiring sessions.
	 */
	cgn_session_stop_timer();

	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_FORW], &iter, ce, ce_node) {
		if (ce->ce_expired)
			continue;

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);

		if (cse->cs_src && cse->cs_src->sr_policy != cp)
			continue;

		if (cse->cs_sess2_ht)
			count += cgn_sess2_expire_all(cse->cs_sess2_ht);

		cgn_session_set_expired(cse);
	}

	/* Log session clear command instead of every session */
	if (count) {
		char desc[60];
		snprintf(desc, sizeof(desc), "policy %s", cp->cp_name);
		cgn_log_sess_clear(desc, count, soft_ticks);
	}

	if (running && restart_timer)
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
		if (likely(!cse->cs_map_instd))
			etime = cgn_session_expiry_time(cse);
		else
			etime = cse->cs_map_timeout;

		/* Set expiry time */
		cse->cs_etime = cgn_get_time_uptime() + etime;

		return false;
	}

	/*
	 * Session was already idle.  Has it timed-out?
	 */
	if (time_after(cgn_get_time_uptime(), cse->cs_etime)) {
		/* yes, session has timed-out */

		/* Mark session as expired */
		cgn_session_set_expired(cse);
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

	if (cse->cs_sess2_ht) {
		uint unexpd = 0, expd = 0;

		/* Are there any unexpired 2-tuple sessions? */
		cgn_sess2_gc_walk(cse->cs_sess2_ht, &unexpd, &expd);

		/*
		 * sentry pkt and bytes counts will have been updated by the
		 * sess2 walk.  Call cgn_session_stats_periodic to update
		 * subscriber entry with the stats.
		 */
		cgn_session_stats_periodic(cse);

		/* Is the nested table still full? */
		if (cse->cs_sess2_full &&
		    rte_atomic16_read(&cse->cs_sess2_used) <
		    cgn_dest_sessions_max) {
			char log_str[140];

			cgn_session_log_str(cse, true, log_str,
					    sizeof(log_str));

			RTE_LOG(ERR, CGNAT,
				"DEST_SESSIONS_AVAILABLE count=%u %s\n",
				rte_atomic16_read(&cse->cs_sess2_used),
				log_str);

			cse->cs_sess2_full = false;
		}

		/*
		 * Mark the session as expired when all nested sessions have
		 * expired
		 */
		if (unexpd == 0 && !cse->cs_forw_entry.ce_expired)
			cgn_session_set_expired(cse);

		/* Only progress with gc when no nested sessions remain */
		if ((unexpd + expd) > 0)
			return;
	} else
		cgn_session_stats_periodic(cse);

	/* Is session expired? */
	if (!cgn_session_expired(cse))
		return;

	/* Wait until all references on the session have been removed */
	if (rte_atomic16_read(&cse->cs_refcnt))
		return;

	if (cse->cs_gc_pass++ < CGN_SESS_GC_COUNT)
		return;

	/* Remove sentrys' from table */
	cgn_session_deactivate(cse);

	/* Release map and policy, schedule rcu-free */
	cgn_session_destroy(cse, true);
}

/*
 * Session table garbage collect walk
 */
static void cgn_session_gc_walk(void)
{
	struct cds_lfht_iter iter;
	struct cgn_sentry *ce;
	struct cgn_session *cse;

	if (!cgn_sess_ht[CGN_DIR_FORW])
		return;

	/* Walk the forwards-flow session table */
	cds_lfht_for_each_entry(cgn_sess_ht[CGN_DIR_FORW], &iter, ce, ce_node) {

		cse = caa_container_of(ce, struct cgn_session, cs_forw_entry);
		cgn_session_gc_inspect(cse);
	}

	/* Is table still full? */
	if (cgn_session_table_full &&
	    rte_atomic32_read(&cgn_sessions_used) < cgn_sessions_max) {

		RTE_LOG(ERR, CGNAT, "SESSION_TABLE_AVAILABLE count=%u/%u\n",
			rte_atomic32_read(&cgn_sessions_used),
			cgn_sessions_max);

		cgn_session_table_full = false;
	}
}

/*
 * garbage collector timer callback
 */
static void
cgn_session_gc(struct rte_timer *timer __rte_unused, void *arg __rte_unused)
{
	/* Walk the session table. */
	cgn_session_gc_walk();

	/* Restart timer if dataplane still running. */
	if (running)
		cgn_session_start_timer();
}

/*
 * Unit-test only
 */
void cgn_session_cleanup(void)
{
	uint i;

	/* Stop timer, and expire all entries */
	cgn_session_expire_all(false, false);

	/*
	 * 1. set idle flags, start expiry timer of 0 secs
	 * 2. expiry time elapsed, set idle flags, start pass 2
	 * 3. pass 2 done, deactivate and destroy session
	 */
	for (i = 0; i < CGN_SESS_GC_COUNT + 2; i++)
		cgn_session_gc_walk();
}

/*
 * Unit-test only.
 */
void cgn_session_gc_pass(void)
{
	cgn_session_stop_timer();
	cgn_session_gc_walk();
}

static void cgn_session_start_timer(void)
{
	rte_timer_reset(&cgn_gc_timer,
			CGN_SESS_GC_INTERVAL * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), cgn_session_gc, NULL);
}

static void cgn_session_stop_timer(void)
{
	rte_timer_stop(&cgn_gc_timer);
}

/*
 * cgn_session_init
 */
void cgn_session_init(void)
{
	if (cgn_sess_ht[CGN_DIR_FORW])
		return;

	cgn_sess_ht[CGN_DIR_FORW] =
		cds_lfht_new(CGN_SESSION_HT_INIT, CGN_SESSION_HT_MIN,
			     CGN_SESSION_HT_MAX,
			     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
			     NULL);

	cgn_sess_ht[CGN_DIR_BACK] =
		cds_lfht_new(CGN_SESSION_HT_INIT, CGN_SESSION_HT_MIN,
			     CGN_SESSION_HT_MAX,
			     CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING,
			     NULL);

	rte_timer_init(&cgn_gc_timer);
	cgn_session_start_timer();
}

/*
 * cgn_session_uninit
 */
void cgn_session_uninit(void)
{
	uint i;

	if (!cgn_sess_ht[CGN_DIR_FORW])
		return;

	/* Stop timer and expire all entries */
	cgn_session_expire_all(false, false);

	/*
	 * 1. set idle flags, start expiry timer of 0 secs
	 * 2. expiry time elapsed, set idle flags, start pass 2
	 * 3. pass 2 done, deactivate and destroy session
	 */
	for (i = 0; i <= CGN_SESS_GC_COUNT; i++)
		cgn_session_gc_walk();

	assert(cgn_session_table_nodes(cgn_sess_ht[CGN_DIR_FORW]) == 0);
	assert(cgn_session_table_nodes(cgn_sess_ht[CGN_DIR_BACK]) == 0);

	/* Destroy the session hash tables */
	dp_ht_destroy_deferred(cgn_sess_ht[CGN_DIR_FORW]);
	cgn_sess_ht[CGN_DIR_FORW] = NULL;

	dp_ht_destroy_deferred(cgn_sess_ht[CGN_DIR_BACK]);
	cgn_sess_ht[CGN_DIR_BACK] = NULL;
}
