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

#endif
