/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_POLICY_H_
#define _CGN_POLICY_H_

#include "npf/cgnat/cgn.h"

struct cgn_policy;
struct cgn_session;
struct nat_pool;

/* Max length of names, enforced by config, is 42 */
#define NAT_POLICY_NAME_MAX	43

/*
 * Subscriber session rates
 */
struct cgn_policy_sess_rate {
	struct cds_list_head	ps_list_node;
	uint32_t		ps_subs_addr;
	uint32_t		ps_sess_rate_max;
	uint64_t		ps_sess_rate_max_time;
};

#define CGN_POLICY_SESS_RATE_MAX 5

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
	char			cp_name[NAT_POLICY_NAME_MAX];
	uint			cp_priority;

	/* Match config */
	const char		*cp_match_ag_name; /* addr grp name */

	/* Translation config */
	const char		*cp_pool_name;
	enum cgn_map_type	cp_map_type;
	enum cgn_fltr_type	cp_fltr_type;
	enum cgn_trans_type	cp_trans_type;

	/* Config to log 5-tuple sessions. true or false. */
	uint8_t			cp_log_sess_all;
	const char		*cp_log_sess_name; /* addr grp name */
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
	struct cds_list_head	cp_list_node;	/* Intf list node */
	struct nat_pool		*cp_pool;	/* Public address pool */

	struct npf_addrgrp	*cp_match_ag;	/* Match addess-group */

	rte_atomic32_t		cp_refcnt;
	rte_atomic32_t		cp_source_count;

	enum cgn_map_type	cp_map_type;   /* EIM or EDM */
	enum cgn_fltr_type	cp_fltr_type;  /* EIF or EDF */
	enum cgn_trans_type	cp_trans_type; /* dynamic or deterministic */

	uint8_t			cp_log_subs;	/* Log subs start/end */
	uint8_t			cp_log_sess_start;
	uint8_t			cp_log_sess_end;

	uint16_t		cp_log_sess_periodic;
	uint8_t			cp_log_sess_all;
	uint8_t			cp_pad2[5];

	/* --- cacheline 1 boundary (64 bytes) --- */

	uint64_t		cp_sess_created;
	uint64_t		cp_sess_destroyed;
	uint64_t		cp_sess2_created;
	uint64_t		cp_sess2_destroyed;
	uint64_t		cp_pkts[CGN_DIR_SZ];
	uint64_t		cp_bytes[CGN_DIR_SZ];

	/* --- cacheline 2 boundary (128 bytes) --- */

	/* List of subscribers with highest 1 minute session rates */
	struct cds_list_head	cp_sess_rate_list;
	uint			cp_sess_rate_count;

	uint			cp_priority;
	struct cds_lfht_node	cp_table_node;
	struct rcu_head		cp_rcu_head;
	struct cgn_intf		*cp_ci;

	/* --- cacheline 3 boundary (192 bytes) --- */

	char			cp_name[NAT_POLICY_NAME_MAX];
	struct npf_addrgrp	*cp_log_sess_ag;
	uint8_t			cp_sess2_enabled;
	uint8_t			cs_pad5[4];
	uint64_t		cp_unk_pkts_in;
	uint64_t		cp_unk_pkts_in_tot;

};

static_assert(offsetof(struct cgn_policy, cp_sess_created) == 64,
	      "first cache line exceeded");
static_assert(offsetof(struct cgn_policy, cp_sess_rate_list) == 128,
	      "second cache line exceeded");
static_assert(offsetof(struct cgn_policy, cp_name) == 192,
	      "third cache line exceeded");

bool cgn_policy_record_dest(struct cgn_policy *cp, uint32_t addr, int dir);

void cgn_policy_update_stats(struct cgn_policy *cp,
			     uint64_t pkts_out, uint64_t bytes_out,
			     uint64_t pkts_in, uint64_t bytes_in,
			     uint64_t unk_pkts_in,
			     uint64_t sess_created, uint64_t sess_destroyed,
			     uint64_t sess2_created, uint64_t sess2_destroyed);

void cgn_policy_update_sess_rate(struct cgn_policy *cp,
				 uint32_t subs_addr,
				 uint32_t sess_rate_max,
				 uint64_t sess_rate_max_time);

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
const char *cgn_policy_get_name(struct cgn_policy *cp);
void cgn_policy_stats_sess_created(struct cgn_policy *cp);
void cgn_policy_stats_sess_destroyed(struct cgn_policy *cp);

int cgn_policy_cfg_add(FILE *f, int argc, char **argv);
int cgn_policy_cfg_delete(FILE *f, int argc, char **argv);

void cgn_policy_if_disable(struct ifnet *ifp);

void cgn_policy_jsonw_summary(json_writer_t *json);
void cgn_policy_show(FILE *f, int argc, char **argv);
void cgn_policy_clear(int argc, char **argv);

void cgn_policy_init(void);
void cgn_policy_uninit(void);

#endif
