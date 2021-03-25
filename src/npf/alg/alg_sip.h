/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_SIP_H_
#define _ALG_SIP_H_

#include "npf/alg/alg_defs.h"

struct json_writer;
struct npf_session;
struct npf_cache;
struct apt_tuple;
struct rte_mbuf;
struct npf_nat;

/**
 * Setup SIP ALG parent session.  Called a new npf session is created, and the
 * destination port matches the configured SIP ALG port and protocol is TCP or
 * UDP.
 *
 * @param se Pointer to the parent session
 * @param npc Pointer to the npf packet cache
 * @param nt Pointer to the ALG tuple (pinhole) that was matched
 * @param di Direction of packet relative to interface (in or out)
 * @return 0 if successful else -errno
 */
int sip_alg_session_init(struct npf_session *se, struct npf_cache *npc,
			 struct apt_tuple *nt, const int di);

/**
 * An SIP ALG session is being expired
 *
 * @param se Pointer to the session
 */
void sip_alg_session_expire(struct npf_session *se);

/**
 * An SIP ALG session is being destroyed
 *
 * @param se Pointer to the session
 */
void sip_alg_session_destroy(struct npf_session *se);

/**
 * Write ALG session json
 *
 * @param json JSON write structure
 * @param se Pointer to the session
 */
void sip_alg_session_json(struct json_writer *json, struct npf_session *se);

/**
 * Inspect non-NATd packets
 *
 * @param se Pointer to the parent session
 * @param npc Pointer to the npf packet cache
 * @param nbuf Packet buffer
 * @param alg ALG data
 * @param di Direction of packet relative to interface (in or out)
 */
void sip_alg_inspect(struct npf_session *se, struct npf_cache *npc,
		     struct rte_mbuf *nbuf, struct npf_alg *alg, int di);

/**
 * Is this a SIP control session?
 *
 * @param sa ALG session data
 * @return true if SIP_ALG_CNTL_FLOW or SIP_ALG_ALT_CNTL_FLOW flag set
 */
bool sip_alg_cntl_session(struct npf_session_alg *sa);

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
int sip_alg_nat(struct npf_session *se, struct npf_cache *npc,
		struct rte_mbuf *nbuf, struct npf_nat *nt,
		const struct npf_alg *alg, int dir);

/**
 * ALG periodic function
 *
 * @param sip ALG data
 */
void sip_alg_periodic(struct npf_alg *sip);

/**
 * Notification from APT manager that a tuple is being deleted
 *
 * @param nt Tuple object
 */
void sip_alg_apt_delete(struct apt_tuple *nt);

/**
 * ALG protocol and port configuration
 *
 * @param sip ALG data instance
 * @param op ALG config operations
 * @param argc Number of args
 * @param argv Argument list
 * @return 0 if successful
 */
int sip_alg_config(struct npf_alg *sip, enum alg_config_op op, int argc,
		   char *const argv[]);

#endif
