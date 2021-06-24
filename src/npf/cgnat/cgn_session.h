/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_SESSION_H_
#define _CGN_SESSION_H_

#include "util.h"
#include "npf/cgnat/cgn_dir.h"

struct cgn_alg_sess_ctx;
struct cgn_3tuple_key;
struct cgn_session;
struct cgn_sess_s2;
struct cgn_packet;
struct cgn_policy;
struct cgn_source;
struct cgn_sess2;
struct cgn_map;
struct nat_pool;
struct ifnet;

uint32_t cgn_session_ifindex(struct cgn_session *cse);
uint32_t cgn_session_id(struct cgn_session *cse);

struct cgn_session *cgn_sess_from_cs2(struct cgn_sess_s2 *cs2);
struct cgn_source *cgn_src_from_cs2(struct cgn_sess_s2 *cs2);
struct cgn_source *cgn_src_from_cse(struct cgn_session *cse);
struct cgn_policy *cgn_policy_from_cse(struct cgn_session *cse);

/*
 * Update 3-tuple session stats from a just-expired 2-tuple session.  This is
 * called via the main thread, so 2-tuple stats total will appear there.
 */
void cgn_session_update_stats(struct cgn_session *cse,
			      uint32_t pkts_out, uint32_t bytes_out,
			      uint32_t pkts_in, uint32_t bytes_in);

uint8_t cgn_session_ipproto(struct cgn_session *cse);
vrfid_t cgn_session_vrfid(struct cgn_session *cse);
uint32_t cgn_session_forw_addr(struct cgn_session *cse);
uint32_t cgn_session_forw_id(struct cgn_session *cse);
uint32_t cgn_session_back_addr(struct cgn_session *cse);
uint32_t cgn_session_back_id(struct cgn_session *cse);

void cgn_session_get_forw(const struct cgn_session *cse,
			  uint32_t *addr, uint16_t *id);
void cgn_session_get_back(const struct cgn_session *cse,
			  uint32_t *addr, uint16_t *id);

uint16_t cgn_session_get_l3_delta(const struct cgn_session *cse, bool forw);
uint16_t cgn_session_get_l4_delta(const struct cgn_session *cse, bool forw);

void cgn_session_try_enable_sub_sess(struct cgn_session *cse,
				     struct cgn_policy *cp, uint32_t oaddr);

struct cgn_session *cgn_session_establish(struct cgn_packet *cpk,
					  struct cgn_map *cmi,
					  enum cgn_dir dir, int *error);

struct cgn_session *cgn_session_get(struct cgn_session *cse);
void cgn_session_put(struct cgn_session *cse);

int cgn_session_activate(struct cgn_session *cse,
			 struct cgn_packet *cpk, enum cgn_dir dir);

void cgn_session_destroy(struct cgn_session *cse, bool rcu_free);

struct cgn_session *cgn_session_lookup(const struct cgn_3tuple_key *key,
				       enum cgn_dir dir);
struct cgn_session *cgn_session_inspect(struct cgn_packet *cpk,
					enum cgn_dir dir, int *error);
struct cgn_session *cgn_session_lookup_icmp_err(struct cgn_packet *cpk,
						enum cgn_dir dir);

void cgn_session_set_closing(struct cgn_session *cse);

struct cgn_session *cgn_session_find_cached(struct rte_mbuf *mbuf);

void cgn_session_set_max(int32_t val);

struct cgn_alg_sess_ctx *cgn_session_alg_set(struct cgn_session *cse,
					     struct cgn_alg_sess_ctx *as);
struct cgn_alg_sess_ctx *cgn_session_alg_get(struct cgn_session *cse);

void cgn_session_set_alg_parent(struct cgn_session *cse, bool val);
bool cgn_session_is_alg_parent(struct cgn_session *cse);
void cgn_session_set_alg_child(struct cgn_session *cse, bool val);
bool cgn_session_is_alg_child(struct cgn_session *cse);
bool cgn_session_is_alg_pptp_child(struct cgn_session *cse);
void cgn_session_set_alg_inspect(struct cgn_session *cse, bool val);
bool cgn_session_get_alg_inspect(struct cgn_session *cse);

/* Threshold */
void session_table_threshold_set(int32_t threshold, uint32_t interval);

void cgn_session_init(void);
void cgn_session_uninit(void);

void cgn_session_id_list(FILE *f, int argc, char **argv);
void cgn_session_show(FILE *f, int argc, char **argv);
void cgn_session_clear(FILE *f, int argc, char **argv);
void cgn_session_update(FILE *f, int argc, char **argv);

void cgn_session_expire_one(struct cgn_session *cse);
void cgn_session_expire_policy(bool restart_timer, struct cgn_policy *cp);
void cgn_session_expire_pool(bool restart_timer, struct nat_pool *np,
			     bool clear_mapping);

int cgn_op_session_map(FILE *f, int argc, char **argv);
struct cgn_session *cgn_session_map(struct ifnet *ifp, struct cgn_packet *cpk,
				    struct cgn_map *cmi, int *error);

/* Used by unit-tests only to initiate a gc pass */
void cgn_session_gc_pass(void);
void cgn_sess_list_show(void);

void cgn_session_cleanup(void);

/* Session Logging thread */
int cgn_set_helper_thread(unsigned int core_num);
int cgn_disable_helper_thread(void);
int cgn_helper_thread_func(unsigned int core_num, void *arg);

#endif /* _CGN_SESSION_H_ */
