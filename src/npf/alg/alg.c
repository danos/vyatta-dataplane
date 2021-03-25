/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*-
 * Copyright (c) 2010 The NetBSD Foundation, Inc.
 * Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * Substantially re-written from the original BSD source by Brocade.
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NPF interface for application level gateways (ALGs).
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <urcu/uatomic.h>
#include <czmq.h>

#include "if_var.h"
#include "json_writer.h"
#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/alg/alg_sip.h"
#include "npf/alg/alg_rpc.h"
#include "npf/alg/alg_ftp.h"
#include "npf/alg/alg_tftp.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"
#include "npf/npf_cache.h"
#include "npf/npf_vrf.h"
#include "vplane_log.h"
#include "vrf_internal.h"

struct rte_mbuf;

/* Minimum lifetime for a tuple */
#define NPF_ALG_MIN_TIMEOUT 5

/* Retry count for tuple insertions. */
#define NPF_ALG_RETRY_COUNT	10

/* ALG periodic timer - for GC */
static struct rte_timer alg_timer;
#define ALG_INTERVAL 5

/*
 * We need to store disable requests for ALGs in VRFs not yet seen.
 * So we have a hash for each unseen VRF (by external-id), that
 * points to a list of algs which should be disabled.
 */
struct alg_late_vrf {
	struct alg_late_vrf	*nv_prev;
	struct alg_late_vrf	*nv_next;
	char			nv_key[32];
	uint32_t		nv_vrfid;
	zhash_t			*nv_algs;
};

static struct alg_late_vrf *alg_late_vrfs;
static zhash_t *alg_late_vrf_hash;

static void
npf_alg_late_vrfs_destroy(void)
{
	struct alg_late_vrf *late_vrf;
	struct alg_late_vrf *next_vrf;

	for (late_vrf = alg_late_vrfs; late_vrf; late_vrf = next_vrf) {
		next_vrf = late_vrf->nv_next;
		zhash_destroy(&late_vrf->nv_algs);

		zhash_delete(alg_late_vrf_hash, late_vrf->nv_key);
	}

	alg_late_vrfs = NULL;
}

static struct alg_late_vrf *
npf_alg_late_vrf_find(uint32_t ext_vrfid)
{
	char hash_key[32];
	snprintf(hash_key, sizeof(hash_key), "%x", ext_vrfid);

	return zhash_lookup(alg_late_vrf_hash, hash_key);
}

static struct alg_late_vrf *
npf_alg_late_vrf_add(uint32_t ext_vrfid)
{
	struct alg_late_vrf *late_vrf = malloc(sizeof(*late_vrf));
	if (!late_vrf)
		return NULL;

	late_vrf->nv_vrfid = ext_vrfid;
	late_vrf->nv_algs = zhash_new();
	snprintf(late_vrf->nv_key, sizeof(late_vrf->nv_key), "%x", ext_vrfid);

	late_vrf->nv_prev = NULL;
	late_vrf->nv_next = alg_late_vrfs;
	if (alg_late_vrfs)
		alg_late_vrfs->nv_prev = late_vrf;
	alg_late_vrfs = late_vrf;

	zhash_insert(alg_late_vrf_hash, late_vrf->nv_key, late_vrf);

	return late_vrf;
}

static void
npf_alg_late_vrf_del(struct alg_late_vrf *late_vrf)
{
	if (!late_vrf)
		return;

	if (late_vrf->nv_next)
		late_vrf->nv_next->nv_prev = late_vrf->nv_prev;
	if (late_vrf->nv_prev)
		late_vrf->nv_prev->nv_next = late_vrf->nv_next;
	else
		alg_late_vrfs = late_vrf->nv_next;

	zhash_destroy(&late_vrf->nv_algs);

	zhash_delete(alg_late_vrf_hash, late_vrf->nv_key);
}

static void
npf_alg_late_vrf_set_alg(struct alg_late_vrf *late_vrf, char const *name,
			 bool on)
{
	bool *alg_on = malloc(sizeof(*alg_on));
	if (!alg_on)
		return;

	*alg_on = on;

	int rc = zhash_insert(late_vrf->nv_algs, name, alg_on);
	if (!rc)
		return;	/* Insert ok */

	free(alg_on);

	/* Duplicate - probably will never occur */
	if (rc == -1) {
		alg_on = zhash_lookup(late_vrf->nv_algs, name);
		if (alg_on)
			*alg_on = on;
	}
}

/* Set ALG private data */
void
npf_alg_session_set_private(struct npf_session *se, void *data)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		sa->sa_private = data;
}

/* Get ALG private data */
void *
npf_alg_session_get_private(const struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_private;
	return NULL;
}

/* Get previous ALG private data, and set new value as one operation */
void *
npf_alg_session_get_and_set_private(const npf_session_t *se, void *data)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);
	if (sa)
		return rcu_xchg_pointer(&(sa->sa_private), data);
	return NULL;
}

/* Test flag */
int
npf_alg_session_test_flag(const struct npf_session *se, uint32_t flag)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_flags & flag;
	return 0;
}

/* Set flag */
void
npf_alg_session_set_flag(struct npf_session *se, uint32_t flag)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		sa->sa_flags |= flag;
}

/* Get all flags */
uint32_t
npf_alg_session_get_flags(const struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return sa->sa_flags;
	return 0;
}

/* Set inspect */
void
npf_alg_session_set_inspect(struct npf_session *se, bool v)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		sa->sa_inspect = v;
}

/* Get the alg from this session */
struct npf_alg *
npf_alg_session_get_alg(const struct npf_session *se)
{
	struct npf_session_alg *sa = npf_session_get_alg_ptr(se);

	if (sa)
		return (struct npf_alg *)sa->sa_alg;
	return NULL;
}

/*
 * Allocate ALG data on the session handle
 */
int
npf_alg_session_set_alg(struct npf_session *se, const struct npf_alg *alg)
{

	struct npf_session_alg *sa = malloc(sizeof(struct npf_session_alg));

	if (!sa)
		return -ENOMEM;

	sa->sa_alg = npf_alg_get((struct npf_alg *)alg);
	sa->sa_private = NULL;
	sa->sa_flags = 0;
	sa->sa_inspect = false;

	npf_session_set_alg_ptr(se, sa);

	return 0;
}

/*
 * Populate a tuple match key from the npc cache
 */
static void alg_npc_to_tuple_key(const npf_cache_t *npc, uint32_t ifx,
				 struct apt_match_key *m)
{
	m->m_ifx = ifx;
	m->m_proto = npf_cache_ipproto(npc);
	m->m_srcip = npf_cache_srcip(npc);
	m->m_dstip = npf_cache_dstip(npc);
	m->m_alen = npc->npc_alen;

	/* Get ports if applicable */
	if (npf_iscached(npc, NPC_L4PORTS)) {
		const struct npf_ports *ports = &npc->npc_l4.ports;

		m->m_dport = ports->d_port;
		m->m_sport = ports->s_port;
	} else {
		m->m_dport = 0;
		m->m_sport = 0;
	}
}

/*
 * Lookup all tuple tables.  Do not change cache.
 */
struct apt_tuple *
alg_lookup_every_table(const struct ifnet *ifp, const npf_cache_t *npc)
{
	struct npf_alg_instance *ai;
	struct apt_match_key key;
	struct apt_tuple *at;

	ai = vrf_get_npf_alg_rcu(ifp->if_vrfid);
	if (!ai)
		return NULL;

	alg_npc_to_tuple_key(npc, ifp->if_index, &key);
	at = apt_tuple_lookup_all_any_dport(ai->ai_apt, &key);

	return at;
}

/*
 * Lookup destination port tuple table
 */
static struct apt_tuple *
alg_lookup(struct npf_alg_instance *ai, npf_cache_t *npc, uint32_t ifx)
{
	struct apt_match_key m;
	struct apt_tuple *at;

	/* Is table empty? */
	if (apt_table_count(ai->ai_apt, APT_MATCH_DPORT) == 0)
		return NULL;

	alg_npc_to_tuple_key(npc, ifx, &m);
	at = apt_tuple_lookup_dport(ai->ai_apt, &m);

	return at;
}

/* Lookup by npc */
struct apt_tuple *alg_lookup_npc(struct npf_alg_instance *ai,
				 npf_cache_t *npc, uint32_t ifx)
{
	struct apt_tuple *at = npf_cache_get_tuple(npc);

	if (!npf_iscached(npc, NPC_ALG_TLUP)) {
		npc->npc_info |= NPC_ALG_TLUP;
		at = alg_lookup(ai, npc, ifx);
		npf_cache_set_tuple(npc, (void *)at);
	}
	return at;
}

/*
 * Expire tuples containing this session.
 *
 * Its possible that the alg vrf instance has been deleted, in which case
 * alg->na_ai will be NULL.  Just return in these cases.
 */
void alg_expire_session_tuples(const struct npf_alg *alg, npf_session_t *se)
{
	if (alg->na_ai)
		alg_apt_instance_expire_session(alg->na_ai->ai_apt, se);
}

/*
 * Delete any tuples created by the given session
 */
void alg_destroy_session_tuples(const struct npf_alg *alg, npf_session_t *se)
{
	if (alg->na_ai)
		alg_apt_instance_destroy_session(alg->na_ai->ai_apt, se);
}

/* Get alg from name */
static struct npf_alg *alg_name_to_alg(struct npf_alg_instance *ai,
					const char *name)
{
	if (ai->ai_ftp && !strcmp(NPF_ALG_FTP_NAME, name))
		return ai->ai_ftp;
	if (ai->ai_tftp && !strcmp(NPF_ALG_TFTP_NAME, name))
		return ai->ai_tftp;
	if (ai->ai_sip && !strcmp(NPF_ALG_SIP_NAME, name))
		return ai->ai_sip;
	if (ai->ai_rpc && !strcmp(NPF_ALG_RPC_NAME, name))
		return ai->ai_rpc;
	return NULL;
}

static int
alg_add_port(struct npf_alg *na, const struct npf_alg_config_item *ci)
{

	struct apt_match_key m = { 0 };
	struct apt_tuple *at;
	bool keep = false;

	m.m_proto = ci->ci_proto;
	m.m_dport = htons(ci->ci_datum);

	if (ci->ci_flags & NPF_TUPLE_MATCH_PROTO_PORT)
		m.m_match = APT_MATCH_DPORT;
	else if (ci->ci_flags & NPF_TUPLE_MATCH_ALL)
		m.m_match = APT_MATCH_ALL;
	else if (ci->ci_flags & NPF_TUPLE_MATCH_ANY_SPORT)
		m.m_match = APT_MATCH_ANY_SPORT;

	if (ci->ci_flags & NPF_TUPLE_KEEP)
		keep = true;

	assert(m.m_match == APT_MATCH_DPORT);
	assert(keep);

	at = apt_tuple_create_and_insert(na->na_ai->ai_apt, &m,
					 npf_alg_get(na),
					 ci->ci_alg_flags,
					 npf_alg_id2name(na->na_id),
					 false, keep);

	if (!at) {
		npf_alg_put(na);
		return -ENOMEM;
	}

	return 0;
}

/* Lookup tuple an mark as expired */
static int alg_delete_port(struct npf_alg *na,
			   const struct npf_alg_config_item *ci)
{
	int rc;

	struct apt_match_key m = { 0 };

	m.m_proto = ci->ci_proto;
	m.m_dport = htons(ci->ci_datum);

	if (ci->ci_flags & NPF_TUPLE_MATCH_PROTO_PORT)
		m.m_match = APT_MATCH_DPORT;
	else if (ci->ci_flags & NPF_TUPLE_MATCH_ALL)
		m.m_match = APT_MATCH_ALL;
	else if (ci->ci_flags & NPF_TUPLE_MATCH_ANY_SPORT)
		m.m_match = APT_MATCH_ANY_SPORT;

	rc = alg_apt_tuple_lookup_and_expire(na->na_ai->ai_apt, &m);

	return rc;
}

int npf_alg_port_handler(struct npf_alg *na, int op,
		const struct npf_alg_config_item *ci)
{
	int rc;

	switch (op) {
	case NPF_ALG_CONFIG_SET:
		rc = alg_add_port(na, ci);
		break;
	case NPF_ALG_CONFIG_DELETE:
		rc = alg_delete_port(na, ci);
		break;
	default:
		rc = -EINVAL;
	}
	return rc;
}

/* Manage the default config as a unit */
static int alg_manage_config(struct npf_alg *na, int op,
		struct npf_alg_config *ac)
{
	int rc = 0;
	int i;

	if ((op == NPF_ALG_CONFIG_SET) && ac->ac_default_set)
		return 0;

	if ((op == NPF_ALG_CONFIG_DELETE) && !ac->ac_default_set)
		return 0;

	for (i = 0; i < ac->ac_item_cnt; i++) {
		/* Handler for default config is optional */
		if (ac->ac_handler) {
			rc = ac->ac_handler(na, op, &ac->ac_items[i]);
			if (rc)
				return rc;
		}
	}

	/* Keep track of whether the default config is installed */
	if (!rc)
		ac->ac_default_set = (op == NPF_ALG_CONFIG_SET) ? true : false;

	return rc;
}

/* Called to reset an alg to a known state. */
static int alg_reset_alg(struct npf_alg *alg)
{
	uint8_t i;
	int rc = 0;

	/* Only rpc requires notification of a reset */
	if (alg->na_id == NPF_ALG_ID_RPC)
		rc = rpc_alg_reset(alg);

	/* Delete 'keep' tuples; expire non-keep tuples */
	alg_apt_instance_client_reset(alg->na_ai->ai_apt, alg);

	/* Now reset the state of the configs and re-install. */
	for (i = 0; i < alg->na_num_configs; i++) {
		struct npf_alg_config *ac = &alg->na_configs[i];

		ac->ac_cli_refcnt = 0;
		ac->ac_default_set = false;
		rc = alg_manage_config(alg, NPF_ALG_CONFIG_SET, ac);
	}

	/* Now reset state to default of enabled */
	if (!alg->na_enabled)
		alg->na_enabled = true;

	return rc;
}


static void alg_reset_alg_module(struct npf_alg *alg)
{
	int rc;

	if (!alg)
		rte_panic("reset called on null alg");

	rc = alg_reset_alg(alg);
	if (rc)
		RTE_LOG(ERR, FIREWALL, "ALG: Reset: %s rc: %d\n",
				npf_alg_id2name(alg->na_id), -rc);
}

/* Reset a specific alg instance */
void alg_reset_instance(struct vrf *vrf, struct npf_alg_instance *ai)
{

	uint32_t count;

	if (!ai)
		return;

	/* 'ai' may be freed */
	count = ai->ai_ref_count;
	ai->ai_ref_count = 0;

	alg_reset_alg_module(ai->ai_ftp);
	alg_reset_alg_module(ai->ai_tftp);
	alg_reset_alg_module(ai->ai_sip);
	alg_reset_alg_module(ai->ai_rpc);

	while (count--)
		vrf_delete_by_ptr(vrf);
}

/* Called by algs to manage a CLI config item */
int npf_alg_manage_config_item(struct npf_alg *na, struct npf_alg_config *ac,
			       enum alg_config_op op,
			       struct npf_alg_config_item *ci)
{
	int rc;

	/* make sure the default config is deleted */
	if (op == NPF_ALG_CONFIG_SET) {
		rc = alg_manage_config(na, NPF_ALG_CONFIG_DELETE, ac);
		if (rc)
			return rc;
	}

	/* There must be a config item handler */
	rc = ac->ac_handler(na, op, ci);
	if (rc)
		goto reset;

	/*  manage ref counts. */
	switch (op) {
	case NPF_ALG_CONFIG_SET:
		ac->ac_cli_refcnt++;
		break;
	case NPF_ALG_CONFIG_DELETE:
		ac->ac_cli_refcnt--;
		/* Restore default config? */
		if (!ac->ac_cli_refcnt)
			(void) alg_manage_config(na, NPF_ALG_CONFIG_SET, ac);
		break;
	case NPF_ALG_CONFIG_ENABLE:
	case NPF_ALG_CONFIG_DISABLE:
		/* ENABLE and DISABLE are handled by npf_alg_state_set */
		return -EINVAL;
	}

	return rc;

reset:
	/*
	 * Best attempt to restore default config.
	 * But only if no other CLI config is present.
	 */
	if ((op == NPF_ALG_CONFIG_SET) && !ac->ac_cli_refcnt)
		(void) alg_manage_config(na, NPF_ALG_CONFIG_SET, ac);

	return rc;
}

/* Free a reserved translation */
int npf_alg_free_translation(npf_session_t *se, npf_addr_t *addr,
		in_port_t port)
{
	npf_nat_t *nat = npf_session_get_nat(se);
	npf_natpolicy_t *np = npf_nat_get_policy(nat);
	npf_rule_t *rl = npf_nat_get_rule(nat);
	uint32_t map_flags;
	vrfid_t vrfid = npf_session_get_vrfid(se);

	/* Currently, all algs use a mapped port */
	map_flags = NPF_NAT_MAP_PORT;

	return npf_nat_free_map(np, rl, map_flags, npf_session_get_proto(se),
				vrfid, *addr, port);
}

/* Reserve translations for an alg.  */
int npf_alg_reserve_translations(npf_session_t *parent, int nr_ports,
		bool start_even, uint8_t alen,
		npf_addr_t *addr, in_port_t *port)
{
	npf_nat_t *pnat = npf_session_get_nat(parent);
	npf_natpolicy_t *np = npf_nat_get_policy(pnat);
	npf_rule_t *rl = npf_nat_get_rule(pnat);
	in_port_t tmp;
	npf_addr_t paddr;
	uint32_t nat_flags;
	vrfid_t vrfid = npf_session_get_vrfid(parent);
	uint8_t ip_prot = npf_session_get_proto(parent);
	int i;
	int rc;

	/* Currently, all algs need a mapped port */
	nat_flags = NPF_NAT_MAP_PORT;

	if ((npf_nat_get_map_flags(pnat) & NPF_NAT_PA_SEQ) != 0)
		nat_flags |= NPF_NAT_PA_SEQ;

	/* Start on even boundary? */
	if (start_even)
		nat_flags |= NPF_NAT_MAP_EVEN_PORT;

	/* allocate from parent translation addr */
	npf_nat_get_trans(pnat, addr, &tmp);
	paddr = *addr;

	rc = npf_nat_alloc_map(np, rl, nat_flags, ip_prot, vrfid, addr,
			port, nr_ports);
	if (rc)
		return rc;

	/*
	 * Ensure that the translations come from the same
	 * (parent) translation address.
	 */
	if (memcmp(addr, &paddr, alen) != 0) {
		tmp = ntohs(*port);
		for (i = 0; i < nr_ports; i++)
			npf_nat_free_map(np, rl, nat_flags, ip_prot, vrfid,
					*addr, htons(tmp + i));
		return -ENOSPC;
	}

	return 0;
}

/*
 * Create and assign a nat struct to a session handle.
 *
 * Used by algs to create nat structs for reverse secondary flows.
 * On success, will consume the alg nat params.  Otherwise we leave
 * that to tuple destroy. (There may be a reservation)
 *
 * Called as desired by algs during their npf_alg_session_init().
 *
 * There are two instances (sip and tftp) where 'nt' is NULL and 'an' is
 * passed into the function instead.
 */
int npf_alg_session_nat(npf_session_t *se, npf_nat_t *pnat, npf_cache_t *npc,
			const int di, struct apt_tuple *nt,
			struct npf_alg_nat *an)
{
	npf_nat_t *nat;

	if (!an && nt)
		an = apt_tuple_get_nat(nt);

	/*
	 * Only if we have an alg nat on the tuple.
	 * May be called in fw stateful matches for algs. (eg: non-nat)
	 */
	if (!an)
		return 0;

	/* Must have a parent nat */
	if (!pnat)
		return -ENOENT;

	/* Create the nat, possibly reversed of the pnat */
	nat = npf_nat_custom_nat(pnat, an->an_flags);
	if (!nat)
		return -ENOMEM;

	if (an->an_flags & NPF_NAT_REVERSE) {
		npf_nat_set_trans(nat, &an->an_oaddr, an->an_oport);
		npf_nat_set_orig(nat, &an->an_taddr, an->an_tport);
	} else {
		npf_nat_set_trans(nat, &an->an_taddr, an->an_tport);
		npf_nat_set_orig(nat, &an->an_oaddr, an->an_oport);
	}

	npf_nat_finalise(npc, se, di, nat);

	npf_session_setnat(se, nat, true);

	/* Mark as consumed so tuple destroy doesn't see it */
	if (nt)
		apt_tuple_set_nat(nt, NULL);
	free(an);

	return 0;
}

/*
 * Register a application protocol alg.
 *
 * - Create the tuple hash tables
 * - Insert default config(s)
 *
 * Do not attempt to recover from partial success.  Failure to
 * register a specific ALG will result in failure of the
 * ALG instance creation, will result in complete cleanup.
 */
int npf_alg_register(struct npf_alg *na)
{
	struct npf_alg_config *ac = na->na_configs;
	int rc = 0;
	int i;

	for (i = 0; i < na->na_num_configs; i++) {
		rc = alg_manage_config(na, NPF_ALG_CONFIG_SET, ac);
		if (rc)
			break;
		ac++;
	}

	if (rc)
		RTE_LOG(ERR, FIREWALL, "ALG: register: %s failed: rc: %d\n",
			npf_alg_id2name(na->na_id), rc);

	return rc;
}

/*
 * ALG protocol and port configuration
 */
static int alg_config(struct npf_alg_instance *ai, const char *name, int op,
		      int argc, char **argv)
{
	struct npf_alg *alg;
	int rc = -ENOENT;

	alg = alg_name_to_alg(ai, name);

	assert(alg);
	if (!alg)
		return rc;

	switch (alg->na_id) {
	case NPF_ALG_ID_FTP:
		rc = ftp_alg_config(alg, op, argc, argv);
		break;
	case NPF_ALG_ID_TFTP:
		rc = tftp_alg_config(alg, op, argc, argv);
		break;
	case NPF_ALG_ID_RPC:
		rc = rpc_alg_config(alg, op, argc, argv);
		break;
	case NPF_ALG_ID_SIP:
		rc = sip_alg_config(alg, op, argc, argv);
		break;
	};
	return rc;
}

/* config() - Set/delete options to an alg */
int npf_alg_config(uint32_t ext_vrfid, const char *name, enum alg_config_op op,
		   int argc, char **argv)
{
	struct vrf *vrf;
	struct npf_alg_instance *ai;
	int rc;

	vrf = vrf_find_or_create(ext_vrfid); /* Bug */
	if (!vrf)
		return -EINVAL;
	ai = vrf_get_npf_alg(vrf);
	if (!ai)
		return -EINVAL;

	rc = alg_config(ai, name, op, argc, argv);
	if (!rc) {
		switch (op) {
		case NPF_ALG_CONFIG_SET:
			vrf_find_or_create(ext_vrfid); /* Bug */
			ai->ai_ref_count++;
			break;
		case NPF_ALG_CONFIG_DELETE:
			vrf_delete_by_ptr(vrf);
			ai->ai_ref_count++;
			break;
		case NPF_ALG_CONFIG_ENABLE:
		case NPF_ALG_CONFIG_DISABLE:
			/* Not used for ENABLE or DISABLE */
			return -EINVAL;
		}
	}

	vrf_delete_by_ptr(vrf);
	return rc;
}

/*
 * alg_search_all_and_any_sport()
 *
 * Certain algs (sip notably) can add multiple tuples that can match a
 * single packet.  This is because they may wild-card the sport (eg: set to
 * zero) due to the connection-less nature of UDP.
 *
 * We need to ensure that a tuple containing both a sport and dport is matched
 * prior to a tuple with a matching dport and sport == 0, so search both in
 * that order.
 */
struct apt_tuple *
alg_search_all_then_any_sport(struct npf_alg_instance *ai,
			      struct npf_cache *npc, uint32_t ifx)
{
	struct apt_match_key m;
	struct apt_tuple *at;

	alg_npc_to_tuple_key(npc, ifx, &m);
	at = apt_tuple_lookup_all_any(ai->ai_apt, &m);

	return at;
}

/* Get the base parent's nat struct */
struct npf_nat *npf_alg_parent_nat(npf_session_t *se)
{
	return npf_session_get_nat(npf_session_get_base_parent(se));
}

static void alg_info_json(struct npf_alg *alg, json_writer_t *json)
{
	if (alg) {
		jsonw_start_object(json);
		jsonw_string_field(json, "name", npf_alg_id2name(alg->na_id));
		jsonw_bool_field(json, "enabled", alg->na_enabled);
		jsonw_end_object(json);
	}
}

int
alg_dump(struct npf_alg_instance *ai, vrfid_t vrfid, json_writer_t *json)
{
	jsonw_start_object(json);
	jsonw_uint_field(json, "vrfid", dp_vrf_get_external_id(vrfid));

	jsonw_name(json, "algs");
	jsonw_start_array(json);
	alg_info_json(ai->ai_ftp, json);
	alg_info_json(ai->ai_tftp, json);
	alg_info_json(ai->ai_sip, json);
	alg_info_json(ai->ai_rpc, json);
	jsonw_end_array(json);

	alg_apt_instance_jsonw(ai->ai_apt, json);

	jsonw_end_object(json);
	return 0;
}

/* alg enable */
int npf_alg_state_set(uint32_t ext_vrfid, const char *name,
		      enum alg_config_op op)
{
	struct vrf *vrf;
	struct npf_alg_instance *ai;
	struct npf_alg *alg;

	vrf = dp_vrf_get_rcu_from_external(ext_vrfid);
	if (!vrf) {
		struct alg_late_vrf *late_vrf
			= npf_alg_late_vrf_find(ext_vrfid);
		if (!late_vrf)
			late_vrf = npf_alg_late_vrf_add(ext_vrfid);

		const bool off = (op == NPF_ALG_CONFIG_DISABLE);
		npf_alg_late_vrf_set_alg(late_vrf, name, !off);

		return 0;
	}

	ai = vrf_get_npf_alg(vrf);
	if (!ai)
		return -EINVAL;

	alg = alg_name_to_alg(ai, name);
	if (!alg)
		return -ENOENT;

	/*
	 *  Note that algs are enabled by default
	 */
	switch (op) {
	case NPF_ALG_CONFIG_ENABLE:
		if (!alg->na_enabled)
			alg->na_enabled = true;
		break;
	case NPF_ALG_CONFIG_DISABLE:
		if (alg->na_enabled)
			alg->na_enabled = false;
		break;
	case NPF_ALG_CONFIG_SET:
	case NPF_ALG_CONFIG_DELETE:
		/* SET and DELETE are handled by npf_alg_manage_config_item */
		return -EINVAL;
	}

	return 0;
}

const char *npf_alg_id2name(enum npf_alg_id id)
{
	switch (id) {
	case NPF_ALG_ID_FTP:
		return NPF_ALG_FTP_NAME;
	case NPF_ALG_ID_TFTP:
		return NPF_ALG_TFTP_NAME;
	case NPF_ALG_ID_RPC:
		return NPF_ALG_RPC_NAME;
	case NPF_ALG_ID_SIP:
		return NPF_ALG_SIP_NAME;
	};
	return "-";
}

void npf_alg_destroy_alg(struct npf_alg *alg)
{

	alg->na_enabled = false;
	alg->na_ops = NULL;

	alg_apt_instance_put(alg->na_ai_apt);
	alg->na_ai_apt = NULL;

	free(alg);
}

struct npf_alg *
npf_alg_create_alg(struct npf_alg_instance *ai, enum npf_alg_id id)
{
	struct npf_alg *alg;

	alg = zmalloc_aligned(sizeof(struct npf_alg));
	if (!alg)
		return NULL;

	rte_atomic32_set(&alg->na_refcnt, 0);
	alg->na_ai = ai;
	alg->na_id = id;
	alg->na_enabled = true;

	alg->na_ai_apt = alg_apt_instance_get(ai->ai_apt);

	return alg;
}

static void
alg_periodic(struct rte_timer *timer __rte_unused, void *data __rte_unused)
{
	struct npf_alg_instance *ai;
	struct vrf *vrf;
	vrfid_t vrfid;

	VRF_FOREACH(vrf, vrfid) {
		ai = vrf_get_npf_alg(vrf);
		if (!ai)
			continue;

		/*
		 * Only SIP has a periodic routine (to manage Invite hash
		 * table).
		 */
		sip_alg_periodic(ai->ai_sip);
	}

	/* Until we graceful shutdown the dataplane */
	if (running)
		npf_alg_timer_reset();
}

/*
 * Create a per-vrf ALG instance
 */
struct npf_alg_instance *npf_alg_create_instance(uint32_t ext_vrfid)
{
	struct npf_alg_instance *ai;

	ai = zmalloc_aligned(sizeof(struct npf_alg_instance));
	if (!ai)
		return NULL;

	/* Create tuple instance */
	ai->ai_apt = alg_apt_instance_create(ext_vrfid);
	alg_apt_instance_get(ai->ai_apt);

	ai->ai_vrfid = ext_vrfid;

	/* Now specific alg instances */
	ai->ai_ftp = npf_alg_ftp_create_instance(ai);
	if (!ai->ai_ftp)
		goto out;
	ai->ai_tftp = npf_alg_tftp_create_instance(ai);
	if (!ai->ai_tftp)
		goto out;
	ai->ai_sip = npf_alg_sip_create_instance(ai);
	if (!ai->ai_sip)
		goto out;
	ai->ai_rpc = npf_alg_rpc_create_instance(ai);
	if (!ai->ai_rpc)
		goto out;

	/* Find any disabled ALGs on the lookaside list */
	struct alg_late_vrf *late_vrf
		= npf_alg_late_vrf_find(ext_vrfid);
	if (late_vrf) {
		zhash_t *algs = late_vrf->nv_algs;
		bool *on_p;
		for (on_p = zhash_first(algs); on_p; on_p = zhash_next(algs)) {
			char const *name = zhash_cursor(algs);
			struct npf_alg *alg = alg_name_to_alg(ai, name);
			if (!alg)
				continue;
			alg->na_enabled = *on_p;
		}
		npf_alg_late_vrf_del(late_vrf);
	}

	return ai;
out:
	npf_alg_destroy_instance(ai);
	return NULL;
}

/*
 * Notification from APT manager that a tuple is being deleted
 */
static void npf_alg_apt_delete_evt(struct apt_tuple *at)
{
	npf_session_t *se;
	npf_nat_t *nat;
	npf_natpolicy_t *np;
	npf_rule_t *rl;
	struct npf_alg_nat *an;


	an = apt_tuple_get_nat(at);


	if (an) {
		apt_tuple_set_nat(at, NULL);

		/* Free port reserved for the secondary flow */
		se = apt_tuple_get_session(at);
		nat = npf_session_get_nat(se);
		np = npf_nat_get_policy(nat);
		rl = npf_nat_get_rule(nat);
		npf_nat_free_map(np, rl, NPF_NAT_MAP_PORT,
				 npf_session_get_proto(se),
				 an->an_vrfid, an->an_taddr, an->an_tport);

		free(an);
	}

	/*
	 * Notify ALG that one of its tuples has been deleted
	 */
	struct npf_alg *alg;

	alg = (struct npf_alg *)apt_tuple_get_client_handle(at);
	if (alg && alg->na_id == NPF_ALG_ID_SIP)
		sip_alg_apt_delete(at);

	/*
	 * client_data should now be NULL
	 */
	assert(!apt_tuple_get_client_data(at));

	/*
	 * We can now release the reference that we took on the alg when the
	 * tuple was added.
	 */
	if (alg) {
		npf_alg_put(alg);
		apt_tuple_clear_client_handle(at);
	}
}

static const struct apt_event_ops alg_apt_event_ops = {
	.apt_delete = npf_alg_apt_delete_evt,
};

/*
 * ALG GC timer
 *
 * We can never safely free an allocated timer, so
 * create a global one for all ALG instances.
 */
void
npf_alg_timer_init(void)
{
	rte_timer_init(&alg_timer);

	alg_late_vrf_hash = zhash_new();

	/* One-time registration to get tuple delete notifications */
	apt_event_register(&alg_apt_event_ops);
}

void
npf_alg_timer_uninit(void)
{
	rte_timer_stop_sync(&alg_timer);

	npf_alg_late_vrfs_destroy();
	zhash_destroy(&alg_late_vrf_hash);
}

void
npf_alg_timer_reset(void)
{
	rte_timer_reset(&alg_timer, ALG_INTERVAL * rte_get_timer_hz(),
			SINGLE, rte_get_master_lcore(), alg_periodic, NULL);
}

/*
 * Called from whole dp unit-tests to delete all non-keep or multimatch
 * tuples, and any expired 'keep' tuples.
 */
void npf_alg_flush_all(void)
{
	struct npf_alg_instance *ai;
	struct apt_instance *ai_apt;
	struct vrf *vrf;
	vrfid_t vrfid;

	VRF_FOREACH(vrf, vrfid) {
		ai = vrf_get_npf_alg(vrf);
		if (!ai)
			continue;

		ai_apt = ai->ai_apt;
		if (!ai_apt)
			continue;

		alg_apt_instance_flush(ai_apt);
	}
}
