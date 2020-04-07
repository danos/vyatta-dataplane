/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_SESSION_H_
#define _CGN_SESSION_H_

#include "util.h"

struct cgn_3tuple_key;
struct cgn_session;
struct cgn_sess_s2;
struct cgn_packet;
struct cgn_policy;
struct cgn_source;
struct cgn_sess2;
struct nat_pool;
struct ifnet;


extern int32_t cgn_sessions_max;
extern int16_t cgn_dest_sessions_max;

/* Global count of all 3-tuple sessions */
extern rte_atomic32_t cgn_sessions_used;

/* Global count of all 5-tuple sessions */
extern rte_atomic32_t cgn_sess2_used;

/* Is session table full? */
extern bool cgn_session_table_full;

/* Is CGNAT helper core enabled? */
extern uint8_t cgn_helper_thread_enabled;

uint32_t cgn_session_ifindex(struct cgn_session *cse);
uint32_t cgn_session_id(struct cgn_session *cse);

struct cgn_session *cgn_sess_from_cs2(struct cgn_sess_s2 *cs2);
struct cgn_source *cgn_src_from_cs2(struct cgn_sess_s2 *cs2);

/*
 * Update 3-tuple session stats from a just-expired 2-tuple session.  This is
 * called via the master thread, so 2-tuple stats total will appear there.
 */
void cgn_session_update_stats(struct cgn_session *cse,
			      uint32_t pkts_out, uint32_t bytes_out,
			      uint32_t pkts_in, uint32_t bytes_in);

uint32_t cgn_session_forw_addr(struct cgn_session *cse);
uint32_t cgn_session_forw_id(struct cgn_session *cse);
uint8_t cgn_session_ipproto(struct cgn_session *cse);
uint32_t cgn_session_back_addr(struct cgn_session *cse);
uint32_t cgn_session_back_id(struct cgn_session *cse);

void cgn_session_get_forw(const struct cgn_session *cse,
			  uint32_t *addr, uint16_t *id);
void cgn_session_get_back(const struct cgn_session *cse,
			  uint32_t *addr, uint16_t *id);

uint16_t cgn_session_get_l3_delta(const struct cgn_session *cse, bool forw);
uint16_t cgn_session_get_l4_delta(const struct cgn_session *cse, bool forw);

/*
 * taddr   - translation addr
 * tid     - translation ID
 * add_dst - Add 2-tuple table
 */
struct cgn_session *cgn_session_establish(struct cgn_packet *cpk, int dir,
					  uint32_t taddr, uint16_t tid,
					  int *error, struct cgn_source *src);

int cgn_session_activate(struct cgn_session *cse,
			 struct cgn_packet *cpk, int dir);

void cgn_session_destroy(struct cgn_session *cse, bool rcu_free);

struct cgn_session *cgn_session_lookup(const struct cgn_3tuple_key *key,
				       int dir);
struct cgn_session *cgn_session_inspect(struct cgn_packet *sp, int dir);
struct cgn_session *cgn_session_lookup_icmp_err(struct cgn_packet *sp, int dir);

struct cgn_session *cgn_session_find_cached(struct rte_mbuf *mbuf);

struct cgn_session *cgn_session_get(struct cgn_session *cse);
void cgn_session_put(struct cgn_session *cse);

void cgn_session_set_max(int32_t val);

/* Threshold */
void session_table_threshold_set(int32_t threshold, uint32_t interval);

void cgn_session_init(void);
void cgn_session_uninit(void);

void cgn_session_id_list(FILE *f, int argc, char **argv);
void cgn_session_show(FILE *f, int argc, char **argv);
void cgn_session_clear(FILE *f, int argc, char **argv);
void cgn_session_update(FILE *f, int argc, char **argv);
ulong cgn_session_count(void);

void cgn_session_expire_policy(bool restart_timer, struct cgn_policy *cp);
void cgn_session_expire_pool(bool restart_timer, struct nat_pool *np,
			     bool clear_mapping);

int cgn_op_session_map(FILE *f, int argc, char **argv);
struct cgn_session *cgn_session_map(struct ifnet *ifp, struct cgn_packet *cpk,
				    uint32_t pub_addr, uint16_t pub_port,
				    int *error);

/*
 * Session walk
 */
typedef int (*cgn_sesswalk_cb)(struct cgn_session *, void *);
int cgn_session_walk(cgn_sesswalk_cb cb, void *data);

/* Used by unit-tests only to initiate a gc pass */
void cgn_session_gc_pass(void);
void cgn_sess_list_show(void);

void cgn_session_cleanup(void);

/* Used by unit-tests only */
size_t cgn_session_size(void);

/* Session Logging thread */
int cgn_set_helper_thread(unsigned int core_num);
int cgn_disable_helper_thread(void);
int cgn_helper_thread_func(unsigned int core_num, void *arg);

#endif /* _CGN_SESSION_H_ */
