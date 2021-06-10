/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef NPF_OUT
#define NPF_OUT

npf_decision_t npf_out_track_fw(struct pl_packet *pkt);
npf_decision_t npf_out_track_snat(struct ifnet *in_ifp, struct rte_mbuf **m,
				       struct npf_if *nif, uint16_t *npf_flags);
npf_decision_t npf_out_track_v6_fw(struct pl_packet *pkt);
#endif /* NPF_OUT */
