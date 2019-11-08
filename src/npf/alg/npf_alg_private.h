/*
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_ALG_PRIVATE
#define NPF_ALG_PRIVATE

typedef struct npf_alg npf_alg_t;

#include <netinet/in.h>
#include <rte_atomic.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <urcu.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "urcu.h"
#include "util.h"

/* Forward Declarations */
struct npf_session;
struct ifnet;
struct npf_alg;
struct rte_mbuf;
struct npf_nat;

/* IANA defined IP protocols */
#define NPF_ALG_MAX_PROTOS      143

/* ALG Nat */
struct npf_alg_nat {
	npf_addr_t		an_oaddr;
	npf_addr_t		an_taddr;
	in_port_t		an_oport;
	in_port_t		an_tport;
	uint32_t		an_flags;
	vrfid_t			an_vrfid;
};

/* The protocol hash table set */
struct alg_ht {
	struct cds_lfht *a_ht;  /* Hash table */
	rte_atomic64_t  a_cnt;  /* Counter */
};

struct alg_protocol_tuples {
	rte_spinlock_t	apt_lock;
	struct alg_ht   apt_all;        /* NPF_TUPLE_MATCH_ALL */
	struct alg_ht   apt_any_sport;    /* NPF_TUPLE_MATCH_ANY_SPORT */
	struct alg_ht   apt_port;       /* NPF_TUPLE_MATCH_PROTO_PORT */
	struct alg_ht   apt_proto;      /* NPF_TUPLE_MATCH_PROTO */
};

/* For resetting an alg's config */
struct npf_alg_reset {
	const char	*ar_name;
	bool		ar_hard;
};

struct npf_alg;

/* ALG Instance */
struct npf_alg_instance {
	struct alg_protocol_tuples	*ai_apts[NPF_ALG_MAX_PROTOS+1];
	uint32_t			ai_ref_count;
	struct npf_alg			*ai_ftp;
	struct npf_alg			*ai_tftp;
	struct npf_alg			*ai_sip;
	struct npf_alg			*ai_rpc;
};

/* The ALG tuple */
struct npf_alg_tuple {
	/* Private fields, don't touch these */
	struct cds_lfht_node	nt_node;	/* for CDS hash table */
	struct rcu_head		nt_rcu_head;	/* for rcu call */
	uint64_t		nt_exp_ts;	/* Expire timestamp */
	void			*nt_aht;	/* hash table */
	npf_session_t		*nt_se;		/* For a session handle */

	/* ALG specific fields, touch these */
	const struct npf_alg	*nt_alg;	/* Alg handle for this tuple */
	struct npf_alg_nat	*nt_nat;	/* Nat for secondary flows */
	uint32_t		nt_ifx;		/* Interface index */
	uint32_t		nt_alg_flags;	/* Alg specific flags */
	uint16_t		nt_flags;	/* flags */
	uint16_t		nt_timeout;	/* Timeout in seconds */
	uint8_t			nt_proto;	/* IP protocol */
	uint8_t			nt_alen;	/* addr len */
	uint16_t		nt_sport;	/* src port */
	uint16_t		nt_dport;	/* dst port */
	npf_addr_t		nt_srcip;	/* src addr */
	npf_addr_t		nt_dstip;	/* dst addr */
	void			*nt_data;	/* Optional data */
	void			(*nt_reap)(void *data);	/* Reap for 'data' */
	void			*nt_paired;	/* Part of a pair? */
};

/* Forward ref for *config */
struct npf_alg;

/* ALG operations struct */
struct npf_alg_ops {
	int		(*se_init)(npf_session_t *, npf_cache_t *,
				struct npf_alg_tuple *, const int di);
	void		(*se_destroy)(npf_session_t *se);
	void		(*se_expire)(npf_session_t *se);
	void		(*inspect)(npf_session_t *, npf_cache_t *,
				struct rte_mbuf *, struct ifnet *, int);
	int		(*config)(struct npf_alg *, int type, int argc,
				char *const argv[]);
	int		(*reset)(struct npf_alg *, bool);
	void		(*nat_inspect)(npf_session_t *, npf_cache_t *,
				struct npf_nat *, int);
	int		(*nat_in)(npf_session_t *, npf_cache_t *,
				struct rte_mbuf *, struct npf_nat *);
	int		(*nat_out)(npf_session_t *, npf_cache_t *,
				 struct rte_mbuf *, struct npf_nat *);
	void		(*periodic)(struct npf_alg *);
	const char	*name;
};

#define alg_has_op(a, o) ((a) && (a)->na_ops && (a)->na_ops->o)

/* A default config item */
struct npf_alg_config_item {
	uint8_t         ci_proto;
	uint32_t        ci_flags;
	uint32_t        ci_alg_flags;
	uint32_t	ci_datum;	/* port/etc */
};

/* config item handler */
typedef int (*config_item_handler_t)(struct npf_alg *, int,
					const struct npf_alg_config_item *);

/* Struct for a default configuration */
#define NPF_ALG_MAX_CONFIG	2
struct npf_alg_config {
	uint16_t			ac_cli_refcnt;
	bool				ac_default_set;
	uint8_t				ac_item_cnt;
	config_item_handler_t		ac_handler;
	const struct npf_alg_config_item *ac_items;
};

/* ALG ID */
enum npf_alg_id {
	NPF_ALG_ID_FTP = 1,
	NPF_ALG_ID_TFTP,
	NPF_ALG_ID_RPC,
	NPF_ALG_ID_SIP,
};

/* ALG application instance struct */
struct npf_alg {
	enum npf_alg_id			na_id;
	bool				na_enabled;
	void				*na_private;
	const struct npf_alg_ops	*na_ops;
	struct npf_alg_instance		*na_ai;
	rte_atomic32_t			na_refcnt;
	uint8_t				na_num_configs;
	struct npf_alg_config		na_configs[NPF_ALG_MAX_CONFIG];
};

/* 'struct npf_session' s_alg handle */
struct npf_session_alg {
	const struct npf_alg	*sa_alg;	/* ALG handle */
	void			*sa_private;	/* ALG private data */
	uint32_t		sa_flags;	/* For ALG usage */
	bool			sa_inspect;	/* inspect packets? */
};

/* ALG tuple flags */
/*
 * NB: flags values for KEEP, REMOVING, and EXPIRED are used directly by
 * script vyatta-dp-npf-show-alg-state in package vplane-config-npf, so
 * if these values change then the script will need updating.
 */
#define NPF_TUPLE_KEEP			(1<<0)
#define NPF_TUPLE_MATCH_PROTO		(1<<1)
#define NPF_TUPLE_MATCH_PROTO_PORT	(1<<2)
#define NPF_TUPLE_MATCH_ALL		(1<<3)
#define NPF_TUPLE_MATCH_ANY_SPORT		(1<<4)
#define NPF_TUPLE_REMOVING		(1<<5)
#define NPF_TUPLE_EXPIRED		(1<<6)
#define NPF_TUPLE_MULTIMATCH		(1<<7)
#define NPF_TUPLE_MATCH_MASK		(NPF_TUPLE_MATCH_PROTO |	\
					NPF_TUPLE_MATCH_PROTO_PORT |	\
					NPF_TUPLE_MATCH_ALL |           \
					NPF_TUPLE_MATCH_ANY_SPORT)

/* ALG names */
#define NPF_ALG_FTP_NAME	"ftp"
#define NPF_ALG_TFTP_NAME	"tftp"
#define NPF_ALG_RPC_NAME	"rpc"
#define NPF_ALG_SIP_NAME	"sip"

/* ALG config ops */
#define NPF_ALG_CONFIG_SET      1
#define NPF_ALG_CONFIG_DELETE   2
#define NPF_ALG_CONFIG_ENABLE   3
#define NPF_ALG_CONFIG_DISABLE  4

const char *npf_alg_id2name(enum npf_alg_id id);

/* Convenience macros to get various instances from an alg instance */
#define alg_to_alg_inst(a)	((a)->na_ai)
#define alg_to_npf_inst(a)	(alg_to_alg_inst(a)->ai_ni)

/* 'struct npf_session_alg' accessors */
void npf_alg_session_set_private(struct npf_session *se, void *data);
void *npf_alg_session_get_private(const struct npf_session *se);
void *npf_alg_session_get_and_set_private(const npf_session_t *se, void *data);

int npf_alg_session_test_flag(const struct npf_session *se, uint32_t flag);
void npf_alg_session_set_flag(struct npf_session *se, uint32_t flag);
uint32_t npf_alg_session_get_flags(const struct npf_session *se);
bool npf_alg_session_inspect(struct npf_session *se);
void npf_alg_session_set_inspect(struct npf_session *se, bool v);
int npf_alg_session_set_alg(struct npf_session *se, const struct npf_alg *alg);
const struct npf_alg *npf_alg_session_get_alg(const struct npf_session *se);

struct alg_protocol_tuples *alg_get_apt(struct npf_alg_instance *ai,
					uint8_t proto);
struct npf_alg_tuple *alg_search_all_then_any_sport(
	struct alg_protocol_tuples *apt, struct npf_cache *npc,
	const struct ifnet *ifp);
void apt_expire_tuple(struct npf_alg_tuple *nt);

/* Protos */
int npf_alg_register(struct npf_alg *np);
void alg_reset_instance(struct vrf *vrf, struct npf_alg_instance *ai,
			bool hard);
int npf_alg_manage_config_item(struct npf_alg *na, struct npf_alg_config *ac,
			       int op, struct npf_alg_config_item *ci);
int npf_alg_port_handler(struct npf_alg *na, int op,
			 const struct npf_alg_config_item *ci);
int npf_alg_session_nat(npf_session_t *se, struct npf_nat *nat,
			npf_cache_t *npc, const int di,
			struct npf_alg_tuple *nt);
int npf_alg_reserve_translations(npf_session_t *se, int nr_ports,
				 bool start_even, uint8_t alen,
				 npf_addr_t *addr, in_port_t *port);
int npf_alg_free_translation(npf_session_t *se, npf_addr_t *addr,
			     in_port_t port);
void npf_alg_destroy_alg(struct npf_alg *alg);
struct npf_alg *npf_alg_create_alg(struct npf_alg_instance *ai,
				   enum npf_alg_id id);
void npf_alg_timer_init(void);
void npf_alg_timer_uninit(void);
void npf_alg_timer_reset(void);
void alg_destroy_apts(struct npf_alg_instance *ai);
void npf_alg_tuple_pair(struct npf_alg_tuple *nt1, struct npf_alg_tuple *nt2);
void npf_alg_tuple_unpair(struct npf_alg_tuple *nt);
void npf_alg_tuple_expire_pair(struct npf_alg_tuple *nt);
void alg_expire_session_tuples(const struct npf_alg *alg, npf_session_t *se);
void npf_alg_tuple_expire(struct npf_alg_tuple *nt);
struct npf_alg_tuple *npf_alg_tuple_alloc(void);
void npf_alg_tuple_free(struct npf_alg_tuple *nt);
int npf_alg_tuple_add_replace(struct npf_alg_instance *ai,
			      struct npf_alg_tuple *nt);
int npf_alg_tuple_insert(struct npf_alg_instance *ai, struct npf_alg_tuple *nt);
struct npf_alg_tuple *npf_alg_tuple_lookup(struct npf_alg_instance *ai,
					   struct npf_alg_tuple *nt);
void npf_alg_tuple_get(struct npf_alg_tuple *nt);
struct npf_alg_tuple *alg_lookup_npc(struct npf_alg_instance *ai,
				     npf_cache_t *npc, uint32_t ifx);

struct npf_nat *npf_alg_parent_nat(npf_session_t *se);

int alg_dump(struct npf_alg_instance *ai, vrfid_t vrfid,
	     json_writer_t *json);
int npf_alg_config(uint32_t ext_vrfid, const char *name, int op, int argc,
		   char **argv);
int npf_alg_state_set(uint32_t ext_vrfid, const char *name, int op);
struct npf_alg *npf_alg_tftp_create_instance(struct npf_alg_instance *ai);
void npf_alg_tftp_destroy_instance(struct npf_alg *na);
struct npf_alg *npf_alg_ftp_create_instance(struct npf_alg_instance *ai);
void npf_alg_ftp_destroy_instance(struct npf_alg *na);
struct npf_alg *npf_alg_sip_create_instance(struct npf_alg_instance *ai);
void npf_alg_sip_destroy_instance(struct npf_alg *na);
struct npf_alg *npf_alg_rpc_create_instance(struct npf_alg_instance *ai);
void npf_alg_rpc_destroy_instance(struct npf_alg *na);
void npf_alg_flush_all(void);
void npf_alg_purge(struct npf_alg_instance *ai);

#endif /* End of NPF_ALG_PRIVATE */
