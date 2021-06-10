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
struct cgn_sess_fltr;
struct cgn_session;
struct cgn_packet;
struct cgn_sess2;
struct rte_mbuf;
struct cgn_map;

/**
 * Is any CGNAT ALG enabled?
 */
bool cgn_alg_is_enabled(void);

/**
 * Is any CGNAT PPTP ALG enabled?
 */
bool cgn_alg_pptp_is_enabled(void);

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
 * Lookup CGNAT ALG pinhole table.  Is this an ALG data (child) flow?
 *
 * Called after a pkt fails to match a CGNAT session.  If a pinhole is found
 * then the mapping info, cmi, will be populated from the pinhole and
 * subsequently used by CGNAT create a new CGNAT session.
 *
 * @param cpk Pointer to CGNAT packet cache
 * @param cmi Pointer to mapping info to be populated from pinhole
 * @param dir CGN_DIR_IN or CGN_DIR_OUT
 * @return 0 or -CGN_ALG_ERR_PHOLE
 */
int cgn_alg_pinhole_lookup(struct cgn_packet *cpk, struct cgn_map *cmi,
			   enum cgn_dir dir);

/**
 * Main CGNAT ALG packet inspection and payload translation routine.
 *
 * Called at the end of the CGNAT packet pipeline node if session is an ALG
 * control (parent) session.
 *
 * @param cse Pointer to main (3-tuple) session
 * @param cpk Pointer to CGNAT packet cache
 * @param mbuf Pointer to packet
 * @param dir Direction of packet relative to CGNAT config (in or out)
 * @return Error number or 0
 */
int cgn_alg_inspect(struct cgn_session *cse, struct cgn_packet *cpk,
		    struct rte_mbuf *mbuf, enum cgn_dir dir);

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
 * Called when a 2-tuple sub-session is added to an ALG main session.
 *
 * Currently only of use to PPTP sessions, where the sub-session 'port' number
 * needs to change to match the PPTP translation ID.
 *
 * @param cpk Pointer to CGNAT packet cache
 * @param s2 Pointer to 2-tuple sub-session
 * @return Negative error number or 0
 */
int cgn_alg_sess2_init(struct cgn_packet *cpk, struct cgn_sess2 *s2);

/**
 * Get the ALG ID from a CGNAT sessions ALG context.  Used in the show filter.
 *
 * @param as Pointer to ALG session context
 * @return ALG ID enum
 */
enum cgn_alg_id cgn_alg_get_id(struct cgn_alg_sess_ctx *as);

/**
 * Get an ALG ID from a name.  Used in the show commands.
 */
enum cgn_alg_id cgn_alg_name2id(const char *name);

/**
 * Get the PPTP Call ID of the inside client
 *
 * In order to translate inbound GRE packets we need to retrieve the Call ID
 * of the inside client.
 *
 * If we have just matched an ALG PPTP pinhole then the child GRE session will
 * not exist yet so we need get it from the parent PPTP session context.  For
 * established GRE session the Call ID is cached in the PPTP specific session
 * context (aps_orig_call_id)
 *
 * Note, may be also called with cpk == NULL in order to simply get the orig
 * Call ID from a session.
 *
 * At least one of cse and cpk must be non-NULL.
 *
 * @param cse Pointer to main (3-tuple) session.  May be NULL.
 * @param cpk Pointer to CGNAT packet cache.  May be NULL.
 * @return Call ID in network byte order.
 */
uint16_t cgn_alg_pptp_orig_call_id(struct cgn_session *cse,
				   struct cgn_packet *cpk);

/**
 * Get the PPTP Call ID of the peer (outside) server
 *
 * @param cse Pointer to main (3-tuple) session.
 * @return Call ID in network byte order.
 */
uint16_t cgn_alg_pptp_peer_call_id(struct cgn_session *cse);

/**
 * Write the ALG specific json for a CGNAT ALG session
 */
void cgn_alg_show_session(struct json_writer *json, struct cgn_sess_fltr *fltr,
			  struct cgn_alg_sess_ctx *as);

/**
 * Write CGNAT ALG summary json
 */
void cgn_alg_show(FILE *f, int argc, char **argv);

/**
 * Clear CGNAT ALG inspect and session stats
 */
void cgn_alg_clear(int argc, char **argv);

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
