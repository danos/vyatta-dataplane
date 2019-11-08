/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_IF_H
#define NPF_IF_H

#include <assert.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stdint.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "npf/config/npf_config.h"
#include "urcu.h"

struct ifnet;
struct npf_config;
struct cgn_intf;

struct npf_if {
	struct npf_config	nif_conf;
	uint32_t		nif_sess;
	struct ifnet		*nif_ifp;
};

void npf_if_sessions_handling_enable(struct ifnet *ifp, bool nif_exists);
void npf_if_sessions_handling_disable(struct ifnet *ifp, bool lock);

static ALWAYS_INLINE struct npf_config *npf_if_conf(const struct npf_if *nif)
{
	const struct npf_config *conf = nif ? &(nif->nif_conf) : NULL;

	return (struct npf_config *) conf;
}

static ALWAYS_INLINE bool
npf_if_active(struct npf_if *nif, uint32_t bitmask)
{
	if (unlikely(!nif))
		return false;

	struct npf_config *nif_conf = npf_if_conf(nif);
	if (npf_active(nif_conf, bitmask))
		return true;

	if ((bitmask & NPF_IF_SESSION) && uatomic_read(&nif->nif_sess))
		return true;

	return false;
}

static inline void npf_if_session_inc(struct ifnet *ifp)
{
	struct npf_if *nif = rcu_dereference(ifp->if_npf);

	if (unlikely(!nif))
		npf_if_sessions_handling_enable(ifp, false);
	else {
		uint32_t next = uatomic_add_return(&nif->nif_sess, 1);

		if (unlikely(next == 1))
			npf_if_sessions_handling_enable(ifp, true);
	}
}

/*
 * Ensure this does not underflow if the control plane zeros the count
 * upon interface rename or reindex.
 */
static inline void npf_if_session_dec(struct ifnet *ifp)
{
	struct npf_if *nif = rcu_dereference(ifp->if_npf);

	assert(nif != NULL);

	uint32_t old, new;
	do {
		old = uatomic_read(&nif->nif_sess);
		assert(old != 0);
		if (!old)
			return;
		new = old - 1;
	} while (uatomic_cmpxchg(&nif->nif_sess, old, new) != old);

	if (unlikely(nif->nif_sess == 0))
		npf_if_sessions_handling_disable(ifp, true);
}

void npf_if_rs_count_incr(struct ifnet *ifp, enum npf_ruleset_type rs_type);
void npf_if_rs_count_decr(struct ifnet *ifp, enum npf_ruleset_type rs_type);
void npf_if_reference_all(void);
void npf_if_reference_one(struct ifnet *ifp, void *arg);
void npf_if_release_all(void);
void npf_if_release_one(struct ifnet *ifp, void *arg);

void npf_if_enable(struct ifnet *ifp, uint32_t ifindex);
void npf_if_disable(struct ifnet *ifp, uint32_t ifindex);
void npf_if_rename(struct ifnet *ifp, const char *old_ifname);

void npf_if_init(void);
void npf_if_cleanup(void);

/*
 * Update rulesets for an interface address change.
 * @param - Pointer to interface index.
 */
void npf_if_addr_change(enum cont_src_en cont_src, struct ifnet *ifp,
		uint32_t if_index, int af, const void *addr);

#endif /* NPF_IF_H */
