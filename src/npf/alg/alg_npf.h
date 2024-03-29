/*
 * Copyright (c) 2018-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_NPF_H_
#define _ALG_NPF_H_

#include <stdio.h>
#include "util.h"

struct npf_alg;
struct npf_alg_instance;
struct npf_session_alg;
struct npf_session;
struct json_writer;
struct npf_cache;
struct rte_mbuf;
struct npf_nat;
struct ifnet;


void npf_alg_init(void);
void npf_alg_uninit(void);

struct npf_alg_instance *npf_alg_create_instance(uint32_t ext_vrfid);
void npf_alg_destroy_instance(struct npf_alg_instance *ai);

struct npf_alg *npf_alg_get(struct npf_alg *alg);
void npf_alg_put(struct npf_alg *alg);

/**
 * ALG inspect for (mostly) non-NATd packets.  Look for data flow port info in
 * the packet payload, and create tuples (pinholes) if found.  Some ALGs
 * (notably SIP) require to inspect multiple control packets before pinholes
 * can be created, and store state locally during this time (e.g. SIP invite
 * request hash table). Called at the end of npf_hook_track just before stats
 * and rprocs.
 *
 * @param se Pointer to the session
 * @param npc Pointer to the npf packet cache
 * @param nbuf Packet buffer
 * @param di Direction of packet relative to interface (in or out)
 * @param sa Pointer to the ALG session data
 */
void npf_alg_inspect(struct npf_session *se, struct npf_cache *npc,
		     struct rte_mbuf *nbuf, int di,
		     struct npf_session_alg *sa);

/**
 * ALG NAT initial inspect.  Called for the first packet in an ALG NAT flow.
 * Conditionally links the session NAT info with an ALG by setting the nt_alg
 * pointer in the NAT data.  This determines if npf_alg_nat_inspect 'sees'
 * subsequent pkts for this flow.
 *
 * @param nat Session NAT data
 * @param sa Pointer to the ALG session data
 */
void npf_alg_nat_inspect(struct npf_nat *nat, struct npf_session_alg *sa);

/**
 * ALG inspect for NATd packets.  Look for data flow port info in the packet
 * payload, and creates NAT mappings and tuples (pinholes) if found.  Some
 * ALGs (notably SIP) require to inspect multiple control packets before
 * pinholes can be created, and store state locally during this time (e.g. SIP
 * invite request hash table). Called *before* the layer 3 and layer 4 headers
 * are translated.
 *
 * @param se Pointer to the session
 * @param npc Pointer to the npf packet cache
 * @param nbuf Packet buffer
 * @param nat Session NAT data
 * @param alg ALG instance data
 * @param di Direction of packet relative to interface (in or out)
 * @return 0 if successful else -errno
 */
int npf_alg_nat(struct npf_session *se, struct npf_cache *npc,
		struct rte_mbuf *nbuf, struct npf_nat *nat,
		struct npf_alg *alg, const int di);

bool npf_alg_bypass_cgnat(const struct ifnet *ifp, struct rte_mbuf *m);

/**
 * ALG session init.  Called when a session has just been created, and has
 * been identified as an ALG session.  If a data/child session has been
 * identified then the tuple (pinhole) is attached to the packet cache.
 *
 * @param se Pointer to the session
 * @param npc Pointer to the npf packet cache
 * @param di Direction of packet relative to interface (in or out)
 * @return 0 if successful else -errno
 */
int npf_alg_session_init(struct npf_session *se, struct npf_cache *npc, int di);

/**
 * ALG session destroy.  Called when an ALG session is being destroyed.  ALGs
 * use this to clean up any session ALG state that is still present.  Normally
 * called from a dataplane session RCU callback.
 *
 * @param se Pointer to the session
 * @param sa Pointer to the ALG session data
 */
void npf_alg_session_destroy(struct npf_session *se,
			     struct npf_session_alg *sa);

struct npf_session *npf_alg_session(struct npf_cache *npc,
				    struct rte_mbuf *nbuf,
				    const struct ifnet *ifp, const int di,
				    int *error);

/**
 * ALG session expire.  Called when an ALG session has been expired. Expire
 * any tuples (pinholes) created by this session.  Expire any unresolved SIP
 * invites for this session.
 *
 * @param se Pointer to the session
 * @param sa Pointer to the ALG session data
 */
void npf_alg_session_expire(struct npf_session *se, struct npf_session_alg *sa);

int npf_alg_session_json(struct json_writer *json, struct npf_session *se,
			 struct npf_session_alg *sa);

void npf_alg_reset(void);
int npf_alg_cfg(FILE *f, int argc, char **argv);
void npf_alg_dump(FILE *fp, vrfid_t vrfid);
const char *npf_alg_name(struct npf_session *se);

#endif /* ALG_NPF_H */
