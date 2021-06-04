/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_SHIM
#define NPF_SHIM

#include <stdbool.h>
#include <stdint.h>

#include "control.h"

#include "npf/config/npf_config.h"
#include "npf/npf.h"
#include "session/session.h"
#include "util.h"
#include "vrf_internal.h"

struct ifnet;
/* Forward Declarations */
struct rte_mbuf;

typedef struct npf_ruleset npf_ruleset_t;

/* Global firewall config */
extern struct npf_config *npf_global_config;

void npf_init(void);
void npf_cleanup(void);
npf_result_t npf_hook_track(struct ifnet *in_ifp, struct rte_mbuf **m,
			    struct npf_if *nif, int dir, uint16_t npf_flags,
			    uint16_t eth_type);
npf_result_t npf_hook_notrack(const npf_ruleset_t *rlset, struct rte_mbuf **m,
			      struct ifnet *ifp, int dir, uint16_t npf_flags,
			      uint16_t eth_type, int *rcp);

npf_decision_t
npf_apply_firewall(const struct npf_ruleset *rs,
		   npf_session_t *se, npf_cache_t *npc,
		   const struct ifnet *ifp, struct rte_mbuf *nbuf,
		   int dir, npf_rule_t **rl,
		   uint16_t npf_flag, bool reverse_stateful);
void
npf_shim_rproc(npf_cache_t *npc, struct rte_mbuf **nbuf,
	       int dir, npf_rule_t *rl,
	       npf_session_t *se, npf_decision_t *decision);


void npf_vrf_create(struct vrf *vrf);
void npf_vrf_delete(struct vrf *vrf);
void npf_vrf_destroy(struct vrf *vrf);
struct npf_config *vrf_get_npf_conf_rcu(vrfid_t vrf_id);

bool npf_local_fw(struct ifnet *ifp, struct rte_mbuf **m, uint16_t ether_type);
bool npf_originate_fw(struct ifnet *ifp, uint16_t npf_flags,
		struct rte_mbuf **m, uint16_t ether_type);
void npf_reset_config(enum cont_src_en cont_src);
void npf_print_state_stats(json_writer_t *json);

bool npf_feature_is_nat(void *data);
#endif /* NPF_SHIM */
