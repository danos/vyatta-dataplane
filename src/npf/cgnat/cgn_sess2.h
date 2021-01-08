/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_sess2.h - cgnat nested 2-tuple session hash table
 */

#ifndef _CGN_SESS2_H_
#define _CGN_SESS2_H_

#include "urcu.h"
#include "json_writer.h"
#include "npf/cgnat/cgn_hash_key.h"

struct cgn_session;
struct cgn_packet;
struct cgn_sess2;
struct cgn_state;
struct cds_lfht;

/*
 * The s2 dest info container in each 3-tuple cse session.
 *
 * cs2_ht    - Hash table. Used when there are more than one session.
 * cs2_s2    - Embedded sessions.  Used for first session.
 * cs2_id    - Resource to allocate session IDs from. Always increases.
 * cs2_dst_port - The dest port from the pkt that created the 3-tuple session.
 *             May be used to determine session expiry time. Net order.
 * cs2_used  - Atomic count of sessions.
 * cs2_max   - Maximum number of sessions.
 * cs2_full  - Set true when session count exceeds max.
 * cs2_enbld - True when dest info is being kept for this 3-tuple session.
 *
 * Only the very first session is added to cs2_s2.  If further sessions are
 * added then a hash table is created.  We keep using cs2_s2, provided it has
 * not expired.
 *
 * Therefore in every lookup or iteration over all sessions we must check both
 * cs2_ht and cs2_s2, as either or both may be NULL.
 */
struct cgn_sess_s2 {
	struct cds_lfht		*cs2_ht;
	struct cgn_sess2	*cs2_s2;
	rte_atomic32_t		cs2_id;
	uint16_t		cs2_dst_port;
	rte_atomic16_t		cs2_used;
	int16_t			cs2_max;

	/*
	 * Timeout for a map instantiated session.  May be used for any
	 * 2-tuple sessions created on a PCP 3-tuplr sesion.
	 */
	uint16_t		cs2_map_timeout;

	/* s2 session logging parameters */
	uint16_t		cs2_log_periodic; /* Units of gc intervals */
	uint8_t			cs2_full:1;
	uint8_t			cs2_enbld:1;
	uint8_t			cs2_log_start:1;
	uint8_t			cs2_log_end:1;

	uint8_t			cs2_pad[1];	/* Pad to 8 byte boundary */
};

static inline bool cgn_sess_key_valid(struct cgn_3tuple_key *key)
{
	if (key->k_ifindex && key->k_addr && key->k_port && key->k_ipproto)
		return true;
	return false;
}

static inline bool cgn_s2_key_valid(struct cgn_2tuple_key *key)
{
	return (key->k_addr && key->k_port &&
		!key->k_expired && key->k_pad == 0);
}

enum cgn_show_dir {
	CGN_SHOW_DIR_UP = 1,
	CGN_SHOW_DIR_DOWN,
};

/*
 * Op-mode sessions parameters.  Used for show command filters etc. and for
 * the map op-mode command.
 *
 * Addresses, masks and ports are it network-byte order.
 */
#define CGN_SESS_FLTR_DESC_SZ 200
struct cgn_sess_fltr {
	char		cf_desc[CGN_SESS_FLTR_DESC_SZ];
	bool		cf_all;
	bool		cf_all_sess2;
	bool		cf_no_sess2;
	uint32_t	cf_ifindex;
	struct cgn_3tuple_key cf_subs;
	struct cgn_3tuple_key cf_pub;
	struct cgn_2tuple_key cf_dst;
	uint32_t	cf_subs_mask;
	uint32_t	cf_pub_mask;
	uint32_t	cf_dst_mask;
	uint32_t	cf_id1;		/* Outer sess ID */
	uint32_t	cf_id2;		/* Inner sess ID */
	char		*cf_pool_name;
	struct nat_pool *cf_np;

	/* Target session for batch request */
	struct cgn_3tuple_key cf_tgt;
	enum cgn_show_dir cf_dir;

	/* Show related */
	bool		cf_detail;
	uint32_t	cf_count;

	/* Op-mode map command */
	uint16_t	cf_timeout;
	bool		cf_clear_stats;
};

/*
 * API with 3-tuple parent session in cgn_session.c
 *
 * 'struct cgn_sess_s2' is the 2-tuple table and state embedded in each
 * 3-tuple session.
 */
int cgn_sess_s2_enable(struct cgn_sess_s2 *cs2);
void cgn_sess_s2_disable(struct cgn_sess_s2 *cs2);
int16_t cgn_sess_s2_count(struct cgn_sess_s2 *cs2);
uint64_t cgn_sess2_timestamp(void);
struct cgn_sess2 *cgn_sess_s2_establish(struct cgn_sess_s2 *cs2,
					struct cgn_packet *cpk,
					int dir, int *error);
int cgn_sess_s2_activate(struct cgn_sess_s2 *cs2, struct cgn_sess2 *s2);
struct cgn_sess2 *cgn_sess_s2_inspect(struct cgn_sess_s2 *cs2,
				      struct cgn_packet *cpk, int dir);
uint cgn_sess_s2_fltr_count(struct cgn_sess_s2 *cs2,
			    struct cgn_sess_fltr *fltr);
uint32_t cgn_sess_s2_unexpired(struct cgn_sess_s2 *cs2);
uint cgn_sess_s2_expire_all(struct cgn_sess_s2 *cs2);
uint cgn_sess_s2_expire_id(struct cgn_sess_s2 *cs2, uint32_t s2_id);
void cgn_sess2_clear_or_update_stats(struct cgn_sess_s2 *cs2, bool clear);
uint cgn_sess_s2_show(json_writer_t *json, struct cgn_sess_s2 *cs2,
		      struct cgn_sess_fltr *fltr);
void cgn_sess_s2_gc_walk(struct cgn_sess_s2 *cs2, uint *unexpd, uint *expd);
int cgn_sess_s2_log_walk(struct cgn_sess_s2 *cs2);

/*
 * s2 session accessor functions
 */
struct cgn_session *cgn_sess2_session(struct cgn_sess2 *s2);
struct cgn_state *cgn_sess2_state(struct cgn_sess2 *s2);
uint32_t cgn_sess2_id(struct cgn_sess2 *s2);
uint32_t cgn_sess2_ipproto(struct cgn_sess2 *s2);
uint32_t cgn_sess2_addr(struct cgn_sess2 *s2);
uint16_t cgn_sess2_port(struct cgn_sess2 *s2);
uint64_t cgn_sess2_start_time(struct cgn_sess2 *s2);
uint32_t cgn_sess2_pkts_out_tot(struct cgn_sess2 *s2);
uint64_t cgn_sess2_bytes_out_tot(struct cgn_sess2 *s2);
uint64_t cgn_sess2_pkts_in_tot(struct cgn_sess2 *s2);
uint64_t cgn_sess2_bytes_in_tot(struct cgn_sess2 *s2);
uint8_t cgn_sess2_dir(struct cgn_sess2 *s2);

/* Used by unit-tests only */
size_t cgn_sess2_size(void);

#endif
