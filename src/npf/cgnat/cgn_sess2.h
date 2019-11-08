/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
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

struct cgn_session;
struct cgn_packet;
struct cgn_sess2;
struct cgn_state;

/* 3-tuple session lookup key */
struct sess_lookup_key {
	uint32_t sk_ifindex;
	uint32_t sk_addr;
	uint16_t sk_id;
	uint8_t  sk_ipproto;
};

/* 2-tuple session lookup key */
struct s2_lookup_key {
	uint32_t s2k_addr;
	uint16_t s2k_id;
};

static inline bool cgn_sess_key_valid(struct sess_lookup_key *sk)
{
	if (sk->sk_ifindex && sk->sk_addr && sk->sk_id && sk->sk_ipproto)
		return true;
	return false;
}

static inline bool cgn_s2_key_valid(struct s2_lookup_key *sk)
{
	return (sk->s2k_addr && sk->s2k_id);
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
#define CGN_SESS_FLTR_DESC_SZ 100
struct cgn_sess_fltr {
	char		cf_desc[CGN_SESS_FLTR_DESC_SZ];
	bool		cf_all;
	bool		cf_all_sess2;
	bool		cf_no_sess2;
	struct sess_lookup_key cf_subs;
	struct sess_lookup_key cf_pub;
	struct s2_lookup_key cf_dst;
	uint32_t	cf_subs_mask;
	uint32_t	cf_pub_mask;
	uint32_t	cf_dst_mask;
	uint32_t	cf_id1;		/* Outer sess ID */
	uint32_t	cf_id2;		/* Inner sess ID */
	char		*cf_pool_name;
	struct nat_pool *cf_np;

	/* Target session for batch request */
	struct sess_lookup_key cf_tgt;
	enum cgn_show_dir cf_dir;

	/* Show related */
	bool		cf_detail;
	uint32_t	cf_count;

	/* Op-mode map command */
	uint		cf_timeout;
};

struct cgn_sess2 *cgn_sess2_establish(struct cgn_session *cse,
				      struct cgn_packet *cpk,
				      rte_atomic32_t *id_rsc, int dir);

int cgn_sess2_activate(struct cds_lfht *ht, struct cgn_sess2 *s2);

struct cgn_sess2 *cgn_sess2_inspect(struct cds_lfht *ht,
				    struct cgn_packet *cpk, int dir);
uint32_t cgn_sess2_unexpired(struct cds_lfht *ht);

struct cgn_sess2 *cgn_sess2_lookup(struct cds_lfht *ht,
				   struct cgn_packet *cpk, int dir);

ulong cgn_sess2_count(struct cds_lfht *ht);
void cgn_sess2_gc_walk(struct cds_lfht *ht, uint *unexpd, uint *expd);
uint cgn_sess2_expire_all(struct cds_lfht *ht);
uint cgn_sess2_expire_id(struct cds_lfht *ht, uint32_t s2_id);

struct cds_lfht *cgn_sess2_ht_create(void);
void cgn_sess2_ht_destroy(struct cds_lfht **htp);

uint cgn_sess2_show_count(struct cds_lfht *ht, struct cgn_sess_fltr *fltr);
uint cgn_sess2_show(json_writer_t *json, struct cds_lfht *ht,
		    struct cgn_sess_fltr *fltr);

#endif
