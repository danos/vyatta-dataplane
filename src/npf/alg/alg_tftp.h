/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_TFTP_H_
#define _ALG_TFTP_H_

struct npf_session;
struct npf_cache;
struct apt_tuple;
struct rte_mbuf;
struct npf_nat;

/**
 * Setup TFTP ALG parent session.  Called a new npf session is created, and
 * the destination port matches the configured TFTP ALG port and protocol is
 * UDP.
 *
 * @param se Pointer to the parent session
 * @param npc Pointer to the npf packet cache
 * @param nt Pointer to the ALG tuple (pinhole) that was matched
 * @param di Direction of packet relative to interface (in or out)
 * @return 0 if successful
 */
int tftp_alg_session_init(struct npf_session *se, struct npf_cache *npc,
			  struct apt_tuple *nt, const int di);

/**
 * Inspect non-NATd packets
 *
 * @param se Pointer to the parent session
 * @param npc Pointer to the npf packet cache
 * @param nbuf Packet buffer
 * @param tftp ALG data
 */
void tftp_alg_inspect(struct npf_session *se, struct npf_cache *npc,
		      struct rte_mbuf *nbuf, struct npf_alg *tftp);

/**
 * Is this a TFTP control session?
 *
 * @param sa ALG session data
 * @return true is TFTP_ALG_CNTL flag set
 */
bool tftp_alg_cntl_session(struct npf_session_alg *sa);

/**
 * Inspect NATd packets
 *
 * @param se Pointer to the parent session
 * @param npc Pointer to the npf packet cache
 * @param nbuf Packet buffer
 * @param nt NAT data
 * @param alg ALG data
 * @param dir Direction of packet relative to interface (in or out)
 * @return 0 if successful
 */
int tftp_alg_nat(struct npf_session *se, struct npf_cache *npc,
		 struct rte_mbuf *nbuf, struct npf_nat *nat,
		 const struct npf_alg *alg, int dir);
#endif
