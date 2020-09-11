/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * ALG Protocol Tuple Database
 */

#ifndef _ALG_TUPLE_H_
#define _ALG_TUPLE_H_

#include <rte_atomic.h>
#include <rte_spinlock.h>

#include "urcu.h"
#include "util.h"
#include "npf/npf.h"

struct apt_instance;
struct apt_tuple;


/*
 * Old ALG tuple flags.  Keep until config scripts are updated.
 *
 * NB: flags values for KEEP, REMOVING, and EXPIRED are used directly by
 * script vyatta-dp-npf-show-alg-state in package vplane-config-npf, so
 * if these values change then the script will need updating.
 */
#define NPF_TUPLE_KEEP			(1<<0)
#define NPF_TUPLE_MATCH_PROTO_PORT	(1<<2)
#define NPF_TUPLE_MATCH_ALL		(1<<3)
#define NPF_TUPLE_MATCH_ANY_SPORT		(1<<4)
#define NPF_TUPLE_REMOVING		(1<<5)
#define NPF_TUPLE_EXPIRED		(1<<6)
#define NPF_TUPLE_MULTIMATCH		(1<<7)
#define NPF_TUPLE_MATCH_MASK		(NPF_TUPLE_MATCH_PROTO_PORT |	\
					NPF_TUPLE_MATCH_ALL |           \
					NPF_TUPLE_MATCH_ANY_SPORT)

/* Match table type */
enum apt_match_table {
	APT_MATCH_NONE = 0,
	APT_MATCH_DPORT,
	APT_MATCH_ALL,
	APT_MATCH_ANY_SPORT
};
#define APT_MATCH_FIRST	APT_MATCH_DPORT
#define APT_MATCH_LAST	APT_MATCH_ANY_SPORT
#define APT_MATCH_SZ	(APT_MATCH_LAST + 1)

/* Hash table match key */
struct apt_match_key {
	enum apt_match_table	m_match;
	uint8_t			m_proto;
	uint8_t			m_alen;
	uint16_t		m_sport;
	uint16_t		m_dport;
	uint32_t		m_ifx;
	const npf_addr_t	*m_srcip;
	const npf_addr_t	*m_dstip;
};

struct apt_tuple *apt_tuple_lookup_all_any_dport(struct apt_instance *ai,
						 struct apt_match_key *m);

/* Lookup ALL table then ANY_SPORT table */
struct apt_tuple *apt_tuple_lookup_all_any(struct apt_instance *ai,
					   struct apt_match_key *m);

/* Lookup proto and dest port table */
struct apt_tuple *apt_tuple_lookup_dport(struct apt_instance *ai,
					 struct apt_match_key *m);

struct apt_tuple *apt_tuple_create_and_insert(struct apt_instance *ai,
					      struct apt_match_key *m,
					      void *client,
					      uint32_t client_flags,
					      const char *client_name,
					      bool replace, bool keep);

/* Get number of entries (expired and unexpired) in a table */
uint32_t apt_table_count(struct apt_instance *ai, enum apt_match_table tt);

void alg_apt_tuple_expire(struct apt_tuple *at);
int alg_apt_tuple_lookup_and_expire(struct apt_instance *ai,
				struct apt_match_key *m);
bool apt_tuple_verify_and_expire(struct apt_instance *ai, struct apt_tuple *at);
int alg_apt_tuple_pair(struct apt_tuple *at1, struct apt_tuple *at2);

/*
 * Accessors
 */
void *apt_tuple_get_client_handle(struct apt_tuple *at);
void apt_tuple_clear_client_handle(struct apt_tuple *at);
uint32_t apt_tuple_get_client_flags(struct apt_tuple *at);
void *apt_tuple_get_client_data(struct apt_tuple *at);
void apt_tuple_set_client_data(struct apt_tuple *at, void *data);

void apt_tuple_set_session(struct apt_tuple *at, void *session);
void *apt_tuple_get_session(struct apt_tuple *at);
void *apt_tuple_get_active_session(struct apt_tuple *at);
void apt_tuple_set_nat(struct apt_tuple *at, void *nat);
void *apt_tuple_get_nat(struct apt_tuple *at);
void apt_tuple_set_timeout(struct apt_tuple *at, uint32_t timeout);
void apt_tuple_set_multimatch(struct apt_tuple *at, bool val);
enum apt_match_table apt_tuple_get_table_type(struct apt_tuple *at);

/*
 * APT Instance
 */
struct apt_instance *alg_apt_instance_create(uint32_t ext_vrfid);
struct apt_instance *alg_apt_instance_get(struct apt_instance *ai);
void alg_apt_instance_put(struct apt_instance *ai);
void alg_apt_instance_jsonw(struct apt_instance *ai, json_writer_t *json);

void alg_apt_instance_expire_session(struct apt_instance *ai,
				     const void *session);
void alg_apt_instance_client_reset(struct apt_instance *ai, const void *client);
void alg_apt_instance_client_destroy(struct apt_instance *ai,
				     const void *client);

/* Unit-test only */
void alg_apt_instance_flush(struct apt_instance *ai);

/*
 * APT registration
 */

/* Max size of the event operations structs array */
#define APT_EVENT_MAX_OPS	4

enum apt_evt {
	APT_EVT_DELETE = 1,
};

struct apt_event_ops {
	void (*apt_delete)(struct apt_tuple *at);
};

void apt_event_register(const struct apt_event_ops *ops);

#endif /* _ALG_TUPLE_H_ */
