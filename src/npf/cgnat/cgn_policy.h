/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_POLICY_H_
#define _CGN_POLICY_H_

#include "npf/cgnat/cgn.h"

struct cgn_policy;
struct cgn_session;
struct nat_pool;

/* cgm mapping type */
enum cgn_map_type {
	CGN_MAP_EIM,	/* Endpoint independent mapping */
	CGN_MAP_EDM,	/* Endpoint dependent mapping */
};

/* cgm filter type */
enum cgn_fltr_type {
	CGN_FLTR_EIF,	/* Endpoint independent filtering */
	CGN_FLTR_EDF,	/* Endpoint dependent filtering */
};

/* cgm translation type */
enum cgn_trans_type {
	CGN_TRANS_NAPT44_DYNAMIC,
	CGN_TRANS_NAPT44_DETERMINISTIC,
};

struct cgn_policy_cfg {
	/* Identity */
	const char		*cp_name;
	uint			cp_priority;

	/* Match config */
	uint32_t		cp_prefix;
	uint8_t			cp_prefix_len;

	/* Translation config */
	const char		*cp_pool_name;
	enum cgn_map_type	cp_map_type;
	enum cgn_fltr_type	cp_fltr_type;
	enum cgn_trans_type	cp_trans_type;

	/* Config to log 5-tuple sessions. true or false. */
	uint8_t			cp_log_sess_all;
	char			*cp_log_sess_name; /* addr grp name */
	uint8_t			cp_log_sess_start;
	uint8_t			cp_log_sess_end;
	uint16_t		cp_log_sess_periodic;

	uint8_t			cp_log_subs;

};

/*
 * cgnat policy.  cp_prefix and cp_mask are in network byte order.
 *
 * Multiple cgnat policies may reference the same cgnat pool.
 */
struct cgn_policy {
	struct cds_lfht_node	cp_table_node;
	struct cds_list_head	cp_list_node;

	/* Policy identity */
	char			*cp_name;
	uint			cp_priority;

	/* Match config */
	uint32_t		cp_prefix;
	uint32_t		cp_mask;
	uint8_t			cp_prefix_len;

	/* Translation config */
	struct nat_pool		*cp_pool;      /* public address pool */
	enum cgn_map_type	cp_map_type;   /* EIM or EDM */
	enum cgn_fltr_type	cp_fltr_type;  /* EIF or EDF */
	enum cgn_trans_type	cp_trans_type; /* dynamic or deterministic */

	struct cgn_intf		*cp_ci;        /* Back ptr to interface */

	/* Config to log 5-tuple sessions. true or false. */
	uint8_t			cp_log_sess_all;
	struct npf_addrgrp	*cp_log_sess_ag;
	uint8_t			cp_log_sess_start;
	uint8_t			cp_log_sess_end;
	uint16_t		cp_log_sess_periodic;

	/* Log subscriber start and end */
	uint8_t			cp_log_subs;

	/* Control for nested 2-tuple sessions. */
	uint8_t			cp_sess2_enabled;

	struct rcu_head		cp_rcu_head;
	rte_atomic32_t		cp_refcnt;
	rte_atomic32_t		cp_source_count;

	uint64_t		cp_sess_created;
	uint64_t		cp_sess_destroyed;
	uint64_t		cp_pkts[CGN_DIR_SZ];
	uint64_t		cp_bytes[CGN_DIR_SZ];
};

bool cgn_policy_record_dest(struct cgn_policy *cp, uint32_t addr, int dir);

void cgn_policy_update_stats(struct cgn_policy *cp,
			     uint64_t pkts_out, uint64_t bytes_out,
			     uint64_t pkts_in, uint64_t bytes_in,
			     uint64_t sess_created, uint64_t sess_destroyed);

/*
 * Compare two policies.  Returns -1, 0, or 1 is p1 is less than, equal, or
 * greater than p2.
 */
int cgn_policy_cmp(struct cgn_policy *p1, struct cgn_policy *p2);

struct cgn_policy *cgn_policy_lookup(const char *name);
struct cgn_policy *cgn_policy_get(struct cgn_policy *cp);
void cgn_policy_put(struct cgn_policy *cp);

void cgn_policy_inc_source_count(struct cgn_policy *cp);
void cgn_policy_dec_source_count(struct cgn_policy *cp);

struct nat_pool *cgn_policy_get_pool(struct cgn_policy *cp);
void cgn_policy_stats_sess_created(struct cgn_policy *cp);
void cgn_policy_stats_sess_destroyed(struct cgn_policy *cp);

int cgn_policy_cfg_add(FILE *f, int argc, char **argv);
int cgn_policy_cfg_delete(FILE *f, int argc, char **argv);

void cgn_policy_if_index_unset(struct ifnet *ifp, struct cgn_policy *cp);

void cgn_policy_jsonw_summary(json_writer_t *json);
void cgn_policy_show(FILE *f, int argc, char **argv);

void cgn_policy_init(void);
void cgn_policy_uninit(void);

#endif
