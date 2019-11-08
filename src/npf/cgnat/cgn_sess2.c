/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
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

#include <errno.h>
#include <values.h>
#include <rte_jhash.h>

#include "util.h"
#include "soft_ticks.h"
#include "if_var.h"

#include "npf/nat/nat_proto.h"
#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_errno.h"
#include "npf/cgnat/cgn_limits.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/cgn_sess_state.h"
#include "npf/cgnat/cgn_session.h"


/*
 * Forward and backwards stats are split over two cachelines.
 *
 * idle flag is in s2_state.
 */
struct cgn_sess2 {
	struct cds_lfht_node	s2_node;        /* session tbl node */
	struct cgn_session	*s2_cse;        /* back pointer */
	rte_atomic32_t		s2_pkts_in;	/* pkts in in last interval */
	rte_atomic32_t		s2_bytes_in;	/* bytes in in last interval */
	uint64_t		s2_bytes_in_tot;/* bytes in total */
	uint64_t		s2_pkts_in_tot; /* pkts in total */
	uint32_t		s2_addr;        /* Address (net order) */
	uint32_t		s2_etime;       /* expiry time */
	uint32_t		s2_id;
	uint16_t		s2_port;        /* port or id (net order) */
	uint8_t			s2_dir;
	uint8_t			s2_ipproto;
	/* --- cacheline 1 boundary (64 bytes) --- */

	rte_atomic32_t		s2_pkts_out;	/* pkts out in last interval */
	rte_atomic32_t		s2_bytes_out;	/* bytes out in last interval */
	uint32_t		s2_pkts_out_tot; /* pkts out total */
	uint16_t		s2_log_countdown;
	uint8_t			s2_gc_pass;
	uint8_t			s2_expired;
	uint64_t		s2_bytes_out_tot; /* bytes out total */
	struct rcu_head		s2_rcu_head;
	uint64_t		s2_start_time;

	struct cgn_state	s2_state;	/* 32 bytes */
	/* --- cacheline 2 boundary (128 bytes) --- */
};


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

/* Count hash table nodes */
ulong cgn_sess2_count(struct cds_lfht *ht)
{
	unsigned long count;
	long dummy;

	if (!ht)
		return 0;

	cds_lfht_count_nodes(ht, &dummy, &count, &dummy);
	return count;
}

static ALWAYS_INLINE int
cgn_sess2_match(const struct cgn_sess2 *s2, uint16_t id, uint32_t addr)
{
	if (s2->s2_port != id)
		return 0;

	if (s2->s2_addr != addr)
		return 0;

	return 1;
}

/*
 * lfht match function, key is a pointer to a 'struct s2_lookup_key' object
 */
static int
cgn_sess2_lkey_match(struct cds_lfht_node *node, const void *key)
{
	const struct s2_lookup_key *lkey = key;
	const struct cgn_sess2 *s2;
	int rc;

	s2 = caa_container_of(node, struct cgn_sess2, s2_node);

	if (s2->s2_expired)
		return 0;

	rc = cgn_sess2_match(s2, lkey->s2k_id, lkey->s2k_addr);

	return rc;
}

static int cgn_sess2_node_match(struct cds_lfht_node *node, const void *key)
{
	const struct cgn_sess2 *s2a, *s2b;
	int rc;

	s2a = caa_container_of(node, struct cgn_sess2, s2_node);

	if (s2a->s2_expired)
		return 0;

	s2b = key;

	rc = cgn_sess2_match(s2a, s2b->s2_port, s2b->s2_addr);

	return rc;
}

/*
 * Create a nested session
 */
struct cgn_sess2 *
cgn_sess2_establish(struct cgn_session *cse, struct cgn_packet *cpk,
		    rte_atomic32_t *id_rsc, int dir)
{
	struct cgn_sess2 *s2;

	s2 = zmalloc_aligned(sizeof(struct cgn_sess2));
	if (!s2)
		return NULL;

	if (dir == CGN_DIR_OUT) {
		s2->s2_addr = cpk->cpk_daddr;
		s2->s2_port   = cpk->cpk_did;
		rte_atomic32_inc(&s2->s2_pkts_out);
		rte_atomic32_add(&s2->s2_bytes_out, cpk->cpk_len);
	} else {
		s2->s2_addr = cpk->cpk_saddr;
		s2->s2_port   = cpk->cpk_sid;
		rte_atomic32_inc(&s2->s2_pkts_in);
		rte_atomic32_add(&s2->s2_bytes_in, cpk->cpk_len);
	}

	s2->s2_dir = dir;
	s2->s2_expired = false;
	s2->s2_cse = cse;
	s2->s2_ipproto = cpk->cpk_ipproto;
	s2->s2_start_time = soft_ticks;
	s2->s2_id = rte_atomic32_add_return(id_rsc, 1);
	s2->s2_log_countdown = cgn_session_log_periodic(cse);

	cgn_sess_state_init(&s2->s2_state,
			    nat_proto_from_ipproto(cpk->cpk_ipproto));
	cgn_sess_state_inspect(&s2->s2_state, cpk, dir, s2->s2_start_time);

	return s2;
}

/*
 * Log 5-tuple session
 */
static uint
cgn_log_sess_common(struct cgn_sess2 *s2, char *log_str, uint log_str_sz)
{
#define ADDR_CHARS 16
	char str1[ADDR_CHARS];
	char str2[ADDR_CHARS];
	char str3[ADDR_CHARS];
	char state_str[12];
	struct ifnet *ifp;
	struct cgn_session *cse = s2->s2_cse;
	uint32_t pid = cgn_session_id(cse);
	uint32_t int_src = cgn_session_forw_addr(cse);
	uint16_t int_port = cgn_session_forw_id(cse);
	uint32_t ext_src = cgn_session_back_addr(cse);
	uint16_t ext_port = cgn_session_back_id(cse);
	uint len;

	ifp = ifnet_byifindex(cgn_session_ifindex(cse));

	if (s2->s2_state.st_proto == NAT_PROTO_TCP)
		snprintf(state_str, sizeof(state_str), "%s[%u/0x%02X]",
			 cgn_sess_state_str_short(&s2->s2_state),
			 s2->s2_state.st_state, s2->s2_state.st_hist);
	else
		snprintf(state_str, sizeof(state_str), "%s[%u]",
			 cgn_sess_state_str_short(&s2->s2_state),
			 s2->s2_state.st_state);

	len = snprintf(log_str, log_str_sz,
		       "ifname=%s session-id=%u.%u proto=%u "
		       "addr=%s->%s port=%u->%u cgn-addr=%s cgn-port=%u "
		       "state=%s start-time=%lu",
		       ifp ? ifp->if_name : "-", pid,
		       s2->s2_id, s2->s2_ipproto,
		       cgn_addrstr(ntohl(int_src), str1, ADDR_CHARS),
		       cgn_addrstr(ntohl(s2->s2_addr), str2, ADDR_CHARS),
		       ntohs(int_port), ntohs(s2->s2_port),
		       cgn_addrstr(ntohl(ext_src), str3, ADDR_CHARS),
		       ntohs(ext_port), state_str,
		       cgn_ticks2timestamp(s2->s2_start_time));

	return len;
}

/*
 * SESSION_CREATE
 */
static void cgn_log_sess_start(struct cgn_sess2 *s2)
{
#define LOG_STR_SZ 400
	char log_str[LOG_STR_SZ];

	cgn_log_sess_common(s2, log_str, sizeof(log_str));
	RTE_LOG(NOTICE, CGNAT, "SESSION_CREATE %s\n", log_str);
}

/*
 * SESSION_ACTIVE - Periodic logging
 */
static void cgn_log_sess_active(struct cgn_sess2 *s2)
{
#define LOG_STR_SZ 400
	char log_str[LOG_STR_SZ];
	uint len;

	len = cgn_log_sess_common(s2, log_str, sizeof(log_str));

	len += snprintf(log_str + len, sizeof(log_str) - len,
			" cur-time=%lu", cgn_ticks2timestamp(soft_ticks));

	len += snprintf(log_str + len, sizeof(log_str) - len,
			" out=%u/%lu in=%lu/%lu",
			s2->s2_pkts_out_tot, s2->s2_bytes_out_tot,
			s2->s2_pkts_in_tot, s2->s2_bytes_in_tot);

	if (s2->s2_state.st_proto == NAT_PROTO_TCP)
		/* TCP round-trip time in microsecs */
		snprintf(log_str + len, sizeof(log_str) - len,
			 " int-rtt=%u ext-rtt=%u",
			 s2->s2_state.st_int_rtt * 1000,
			 s2->s2_state.st_ext_rtt * 1000);

	RTE_LOG(NOTICE, CGNAT, "SESSION_ACTIVE %s\n", log_str);
}

/*
 * Log 5-tuple session end
 */
static void cgn_log_sess_end(struct cgn_sess2 *s2, uint64_t end_time)
{
#define LOG_STR_SZ 400
	char log_str[LOG_STR_SZ];
	uint len;

	len = cgn_log_sess_common(s2, log_str, sizeof(log_str));

	len += snprintf(log_str + len, sizeof(log_str) - len,
			" end-time=%lu", cgn_ticks2timestamp(end_time));

	len += snprintf(log_str + len, sizeof(log_str) - len,
			" out=%u/%lu in=%lu/%lu",
			s2->s2_pkts_out_tot, s2->s2_bytes_out_tot,
			s2->s2_pkts_in_tot, s2->s2_bytes_in_tot);

	if (s2->s2_state.st_proto == NAT_PROTO_TCP)
		/* TCP round-trip time in microsecs */
		snprintf(log_str + len, sizeof(log_str) - len,
			 " int-rtt=%u ext-rtt=%u",
			 s2->s2_state.st_int_rtt * 1000,
			 s2->s2_state.st_ext_rtt * 1000);

	RTE_LOG(NOTICE, CGNAT, "SESSION_DELETE %s\n", log_str);
}

/*
 * Activate a nested session
 */
int
cgn_sess2_activate(struct cds_lfht *ht, struct cgn_sess2 *s2)
{
	/* Insert into table */
	struct cds_lfht_node *node;
	ulong hash;

	hash = rte_jhash_1word(s2->s2_addr, s2->s2_port);

	node = cds_lfht_add_unique(ht, hash, cgn_sess2_node_match,
				   s2, &s2->s2_node);

	/* Did we loose the race to insert s2? */
	if (node != &s2->s2_node)
		return -CGN_S2_EEXIST;

	if (cgn_session_log_start(s2->s2_cse))
		cgn_log_sess_start(s2);

	return 0;
}

static void
cgn_sess2_deactivate(struct cds_lfht *ht, struct cgn_sess2 *s2)
{
	/* Remove from table */
	(void)cds_lfht_del(ht, &s2->s2_node);

	/* Release the slot */
	cgn_sess2_slot_put(s2->s2_cse);
}

struct cgn_sess2 *
cgn_sess2_lookup(struct cds_lfht *ht, struct cgn_packet *cpk, int dir)
{
	struct s2_lookup_key lkey;

	if (dir == CGN_DIR_OUT) {
		lkey.s2k_addr = cpk->cpk_daddr;
		lkey.s2k_id   = cpk->cpk_did;
	} else {
		lkey.s2k_addr = cpk->cpk_saddr;
		lkey.s2k_id   = cpk->cpk_sid;
	}

	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	ulong hash;

	hash = rte_jhash_1word(lkey.s2k_addr, lkey.s2k_id);

	cds_lfht_lookup(ht, hash, cgn_sess2_lkey_match,	&lkey, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		return caa_container_of(node, struct cgn_sess2, s2_node);

	return NULL;
}

static struct cgn_sess2 *
cgn_sess2_lookup_by_key(struct cds_lfht *ht, struct s2_lookup_key *key)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;
	struct cgn_sess2 *s2;
	ulong hash;

	hash = rte_jhash_1word(key->s2k_addr, key->s2k_id);

	cds_lfht_lookup(ht, hash, cgn_sess2_lkey_match,	key, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node) {
		s2 = caa_container_of(node, struct cgn_sess2, s2_node);
		return s2;
	}

	return NULL;
}

/*
 * Inspect
 */
struct cgn_sess2 *
cgn_sess2_inspect(struct cds_lfht *ht, struct cgn_packet *cpk, int dir)
{
	struct cgn_sess2 *s2;

	s2 = cgn_sess2_lookup(ht, cpk, dir);
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
static void cgn_sess2_stats_periodic(struct cgn_sess2 *s2, bool expired)
{
	uint32_t pkts_out, pkts_in, bytes_out, bytes_in;

	pkts_out = rte_atomic32_exchange(
		(volatile uint32_t *)&s2->s2_pkts_out.cnt, 0);

	bytes_out = rte_atomic32_exchange(
		(volatile uint32_t *)&s2->s2_bytes_out.cnt, 0);

	pkts_in = rte_atomic32_exchange(
		(volatile uint32_t *)&s2->s2_pkts_in.cnt, 0);

	bytes_in = rte_atomic32_exchange(
		(volatile uint32_t *)&s2->s2_bytes_in.cnt, 0);

	s2->s2_pkts_out_tot += pkts_out;
	s2->s2_bytes_out_tot += bytes_out;
	s2->s2_pkts_in_tot += pkts_in;
	s2->s2_bytes_in_tot += bytes_in;

	/* Add stats to 3-tuple session totals */
	cgn_session_update_stats(s2->s2_cse, pkts_out, bytes_out,
				 pkts_in, bytes_in, expired);
}

/*
 * Get state-dependent expiry time for a 2-tuple session
 */
static inline uint32_t cgn_sess2_state_expiry_time(struct cgn_state *st)
{
	return cgn_sess_state_expiry_time(st->st_proto, st->st_state);
}

/*
 * Count of unexpired sessions
 */
uint32_t cgn_sess2_unexpired(struct cds_lfht *ht)
{
	struct cds_lfht_iter iter;
	struct cgn_sess2 *s2;
	uint32_t count = 0;

	if (!ht)
		return 0;

	cds_lfht_for_each_entry(ht, &iter, s2, s2_node) {
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
	cgn_sess2_stats_periodic(s2, true);

	if (log && cgn_session_log_end(s2->s2_cse))
		cgn_log_sess_end(s2, soft_ticks);
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

		/* Get state-dependent expiry time */
		etime = cgn_sess2_state_expiry_time(&s2->s2_state);

		/* Set expiry time */
		s2->s2_etime = cgn_get_time_uptime() + etime;

		return false;
	}

	/*
	 * Session was already idle.  Has it timed-out?
	 */
	if (time_after(cgn_get_time_uptime(), s2->s2_etime)) {
		/* yes, session has timed-out */

		/*
		 * Crank state-machine with timeout event, and get the timeout
		 * value for the new state.
		 */
		etime = cgn_sess_state_timeout(&s2->s2_state);

		/* Did timeout cause session to close? */
		if (etime == 0) {
			/* yes. Mark session as expired */
			cgn_sess2_set_expired(s2, false, true);
			return true;
		}

		/* Else reset timer */
		etime = cgn_sess_state_timeout(&s2->s2_state);

		/* Set expiry time */
		s2->s2_etime = cgn_get_time_uptime() + etime;
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

void cgn_sess2_gc_walk(struct cds_lfht *ht, uint *unexpd, uint *expd)
{
	struct cds_lfht_iter iter;
	struct cgn_sess2 *s2;

	cds_lfht_for_each_entry(ht, &iter, s2, s2_node) {

		cgn_sess2_stats_periodic(s2, false);

		if (s2->s2_log_countdown) {
			s2->s2_log_countdown -= 1;

			if (s2->s2_log_countdown == 0) {
				s2->s2_log_countdown =
					cgn_session_log_periodic(s2->s2_cse);
				cgn_log_sess_active(s2);
			}
		}

		if (!cgn_sess2_expired(s2)) {
			(*unexpd)++;
			continue;
		}

		if (!s2->s2_gc_pass) {
			s2->s2_gc_pass = true;
			(*expd)++;
			continue;
		}

		/* Remove from hash table */
		cgn_sess2_deactivate(ht, s2);

		/* Schedule rcu free */
		cgn_sess2_destroy(s2);
	}
}

uint cgn_sess2_expire_all(struct cds_lfht *ht)
{
	struct cds_lfht_iter iter;
	struct cgn_sess2 *s2;
	uint count = 0;

	cds_lfht_for_each_entry(ht, &iter, s2, s2_node) {
		if (!s2->s2_expired) {
			cgn_sess2_set_expired(s2, true, false);
			count++;
		}
	}
	return count;
}

/*
 * Expire session by ID
 */
uint cgn_sess2_expire_id(struct cds_lfht *ht, uint32_t s2_id)
{
	struct cds_lfht_iter iter;
	struct cgn_sess2 *s2;
	uint count = 0;

	cds_lfht_for_each_entry(ht, &iter, s2, s2_node) {
		if (!s2->s2_expired && (s2_id == 0 || s2_id == s2->s2_id)) {
			cgn_sess2_set_expired(s2, true, false);
			count++;
		}
	}
	return count;
}

static void
cgn_sess2_jsonw_one(json_writer_t *json, struct cgn_sess2 *s2)
{
	char dst_str[16];
	uint32_t uptime = cgn_get_time_uptime();
	uint32_t max_timeout = cgn_sess2_state_expiry_time(&s2->s2_state);

	inet_ntop(AF_INET, &s2->s2_addr, dst_str, sizeof(dst_str));

	jsonw_start_object(json);

	jsonw_string_field(json, "dst_addr", dst_str);
	jsonw_uint_field(json, "dst_port", htons(s2->s2_port));
	jsonw_uint_field(json, "id", s2->s2_id);

	cgn_sess_state_jsonw(json, &s2->s2_state);

	jsonw_uint_field(json, "start_time",
			 cgn_ticks2timestamp(s2->s2_start_time));
	jsonw_uint_field(json, "duration",
			 cgn_start2duration(s2->s2_start_time));

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
	    fltr->cf_dst.s2k_addr != (s2->s2_addr & fltr->cf_dst_mask))
		return false;

	if (fltr->cf_dst.s2k_id && fltr->cf_dst.s2k_id != s2->s2_port)
		return false;

	/* Filter on session ID */
	if (fltr->cf_id2 && fltr->cf_id2 != s2->s2_id)
		return false;

	return true;
}

/*
 * Determine how many sessions a filter might match in cgn_sess2_show.
 */
uint cgn_sess2_show_count(struct cds_lfht *ht, struct cgn_sess_fltr *fltr)
{
	struct cds_lfht_iter iter;
	struct cgn_sess2 *s2;
	uint32_t count = 0;

	if (!ht)
		return 0;

	/*
	 * Are there enough filter params to do a hash lookup?
	 */
	if (fltr->cf_dst_mask == 0xffffffff &&
	    cgn_s2_key_valid(&fltr->cf_dst)) {

		s2 = cgn_sess2_lookup_by_key(ht, &fltr->cf_dst);
		if (s2 && cgn_sess2_show_fltr(s2, fltr))
			return 1;
	}

	cds_lfht_for_each_entry(ht, &iter, s2, s2_node) {
		if (cgn_sess2_show_fltr(s2, fltr))
			count++;
	}
	return count;
}

uint cgn_sess2_show(json_writer_t *json, struct cds_lfht *ht,
		    struct cgn_sess_fltr *fltr)
{
	struct cds_lfht_iter iter;
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

		s2 = cgn_sess2_lookup_by_key(ht, &fltr->cf_dst);

		if (s2 && cgn_sess2_show_fltr(s2, fltr)) {
			cgn_sess2_jsonw_one(json, s2);
			count++;
		}
		goto end;
	}

	cds_lfht_for_each_entry(ht, &iter, s2, s2_node) {

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

struct cds_lfht *cgn_sess2_ht_create(void)
{
	struct cds_lfht *ht;

	ht = cds_lfht_new(CGN_SESS2_HT_INIT, CGN_SESS2_HT_MIN,
			  CGN_SESS2_HT_MAX, CGN_SESS2_HT_FLAGS, NULL);
	return ht;
}

void cgn_sess2_ht_destroy(struct cds_lfht **htp)
{
	struct cds_lfht *ht = *htp;

	if (ht) {
		assert(cgn_sess2_count(ht) == 0);

		/* Destroy sess2 hash table */
		dp_ht_destroy_deferred(ht);
		*htp = NULL;
	}
}

