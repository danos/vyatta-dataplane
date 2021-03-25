/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_RPC_H_
#define _ALG_RPC_H_

struct npf_session;
struct npf_cache;
struct apt_tuple;
struct rte_mbuf;
struct npf_nat;

/**
 * Setup RPC portmapper ALG parent session.  Called a new npf session is
 * created, and the destination port matches the configured RPC ALG port and
 * protocol is TCP or UDP.
 *
 * @param se Pointer to the parent session
 * @param nt Pointer to the ALG tuple (pinhole) that was matched
 * @return 0 if successful
 */
int rpc_alg_session_init(struct npf_session *se, struct apt_tuple *nt);

/**
 * An RPC ALG session is being destroyed
 *
 * @param se Pointer to the session
 */
void rpc_alg_session_destroy(struct npf_session *se);

/**
 * Inspect non-NATd packets
 *
 * @param se Pointer to the parent session
 * @param npc Pointer to the npf packet cache
 * @param nbuf Packet buffer
 * @param alg ALG data
 */
void rpc_alg_inspect(struct npf_session *se, struct npf_cache *npc,
		     struct rte_mbuf *nbuf, struct npf_alg *alg);

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
int rpc_alg_nat(struct npf_session *se, struct npf_cache *npc,
		struct rte_mbuf *nbuf, struct npf_nat *nt,
		const struct npf_alg *alg, int dir);

/**
 * Notification ALG is being reset
 *
 * @param rpc ALG data
 * @return 0 is successful
 */
int rpc_alg_reset(struct npf_alg *rpc);

#endif
