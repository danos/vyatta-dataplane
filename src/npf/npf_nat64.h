/*
 * Copyright (c) 2019-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _NPF_NAT64_H_
#define _NPF_NAT64_H_

#include <stdbool.h>
#include <stdint.h>

#include "npf/npf.h"
#include "npf/npf_cache.h"
#include "npf/npf_session.h"
#include "npf/npf_nat.h"

/* Forward Declarations */
struct ifnet;
struct npf_config;
struct rte_mbuf;
struct npf_nat64;
struct npf_pack_nat64;
typedef struct npf_rule npf_rule_t;
typedef struct npf_cache npf_cache_t;
typedef struct npf_session npf_session_t;

/*
 * Input
 *	UNMATCHED  Did not match nat64 rule
 *	TO_V4      Switch from V6 to V4
 *	TO_V6      Switch from V4 to V6
 *	PASS       n/a
 *	DROP       Pkt ineligible, or error occurred
 *
 * Output
 *	UNMATCHED  Not switched from other addr family
 *	TO_V4      n/a
 *	TO_V6      n/a
 *	PASS       Switched from other af and both sessions exist
 *	DROP       Error occurred
 */
typedef enum {
	NAT64_DECISION_UNMATCHED,
	NAT64_DECISION_TO_V4,
	NAT64_DECISION_TO_V6,
	NAT64_DECISION_PASS,
	NAT64_DECISION_DROP,
} nat64_decision_t;

static inline const char *nat64_decision_str(nat64_decision_t decision)
{
	switch (decision) {
	case NAT64_DECISION_UNMATCHED:
		return "UNMATCHED";
	case NAT64_DECISION_TO_V4:
		return "TO_V4";
	case NAT64_DECISION_TO_V6:
		return "TO_V6";
	case NAT64_DECISION_PASS:
		return "PASS";
	case NAT64_DECISION_DROP:
		return "DROP";
	};
	return "Unkn";
}

nat64_decision_t
npf_nat64_6to4_in(const struct npf_config *npf_config,
		  npf_session_t **sep, struct ifnet *ifp, npf_cache_t *npc,
		  struct rte_mbuf **m, uint16_t *npf_flag, int *rcp);

nat64_decision_t
npf_nat64_4to6_in(const struct npf_config *npf_config,
		  npf_session_t **sep, struct ifnet *ifp, npf_cache_t *npc,
		  struct rte_mbuf **m, uint16_t *npf_flag, int *rcp);

nat64_decision_t
npf_nat64_6to4_out(npf_session_t **sep, struct ifnet *ifp, npf_cache_t *npc,
		   struct rte_mbuf **m, const uint16_t *npf_flag, int *rcp);

nat64_decision_t
npf_nat64_4to6_out(npf_session_t **sep, struct ifnet *ifp, npf_cache_t *npc,
		   struct rte_mbuf **m, const uint16_t *npf_flag, int *rcp);

int npf_nat64_session_link(struct npf_session *se1, struct npf_session *se2);
void npf_nat64_session_unlink(struct npf_session *se);
void npf_nat64_session_destroy(struct npf_session *se);
bool npf_nat64_session_is_nat64(npf_session_t *se);
void npf_nat64_session_json(json_writer_t *json, npf_session_t *se);

npf_rule_t *npf_nat64_get_rule(struct npf_nat64 *n64);
int npf_nat64_get_rproc_id(struct npf_nat64 *n64);
uint8_t npf_nat64_is_v6(struct npf_nat64 *n64);
uint8_t npf_nat64_is_linked(struct npf_nat64 *n64);
void npf_nat64_get_trans(struct npf_nat64 *n64,
			npf_addr_t *addr, in_port_t *port);
bool npf_nat64_has_peer(struct npf_nat64 *n64);
npf_session_t *npf_nat64_get_peer(struct npf_nat64 *n64);
bool npf_nat64_session_log_enabled(struct npf_nat64 *n64);
int npf_nat64_npf_pack_restore(struct npf_session *se,
			       struct npf_pack_nat64 *pn64);

#endif /* _NPF_NAT64_H_ */
