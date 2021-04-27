/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef ALG_PUBLIC_H
#define ALG_PUBLIC_H

#include "npf/nat/nat_proto.h"		/* enum nat_proto */
#include "npf/cgnat/cgn_dir.h"		/* enum cgn_dir */
#include "npf/cgnat/alg/alg_defs.h"	/* enum cgn_alg_id */

/*
 * CGNAT ALG Public API
 */

struct cgn_alg_sess_ctx;
struct cgn_session;
struct cgn_packet;
struct cgn_map;

/**
 * Is any CGNAT ALG enabled?
 */
bool cgn_alg_is_enabled(void);

/**
 * Is this new session an ALG control (or parent) session?
 *
 * Lookup the destination port to determine if pkt belongs to an enabled ALG
 * protocol.  Called when a CGNAT session is created for an outbound packet.
 *
 * @param proto NAT_PROTO_TCP, NAT_PROTO_UDP, or NAT_PROTO_OTHER
 * @param port Destination port in network byte order
 * @return Return an ALG ID, or CGN_ALG_NONE if no ALG matched
 */
enum cgn_alg_id cgn_alg_dest_port_lookup(enum nat_proto proto, uint16_t port);

/**
 * Initialisation routine for new CGNAT control (dest port match) or data
 * (pinhole match) sessions.
 *
 * @param cpk Pointer to CGNAT packet cache
 * @param cse Pointer to main (3-tuple) session
 * @param dir CGN_DIR_IN or CGN_DIR_OUT
 * @return 0 if successful else -CGN_ALG_ERR_SESS
 */
int cgn_alg_session_init(struct cgn_packet *cpk, struct cgn_session *cse,
			 enum cgn_dir dir);

/**
 * Called when a CGNAT ALG session has been expired expired.  Expires any ALG
 * pinholes created by this session.
 *
 * @param cse Pointer to main (3-tuple) session
 * @param as Pointer to ALG session context
 */
void cgn_alg_session_uninit(struct cgn_session *cse,
			    struct cgn_alg_sess_ctx *as);

/**
 * Enable ALG
 */
int cgn_alg_enable(const char *name);

/**
 * Disable ALG
 */
int cgn_alg_disable(const char *name);

/**
 * Called via DP_EVT_INIT event handler
 */
void cgn_alg_init(void);

/**
 * Called via DP_EVT_UNINIT event handler
 */
void cgn_alg_uninit(void);

#endif /* ALG_PUBLIC_H */
