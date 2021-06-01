/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <values.h>
#include <rte_jhash.h>
#include <rte_mbuf.h>
#include <rte_timer.h>
#include "util.h"
#include "json_writer.h"
#include "soft_ticks.h"
#include "in_cksum.h"

#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_rc.h"
#include "npf/cgnat/cgn_map.h"
#include "npf/cgnat/cgn_mbuf.h"
#include "npf/cgnat/cgn_policy.h"
#include "npf/cgnat/cgn_session.h"
#include "npf/cgnat/cgn_sess2.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/nat/nat_pool_event.h"
#include "npf/nat/nat_pool_public.h"

#include "npf/cgnat/alg/alg.h"
#include "npf/cgnat/alg/alg_rc.h"
#include "npf/cgnat/alg/alg_pinhole.h"
#include "npf/cgnat/alg/alg_pptp.h"
#include "npf/cgnat/alg/alg_session.h"

/*
 * ALG PPTP Session (sub-session) context
 *
 * Mapping info is saved to session when the PPTP_OUT_CALL_REQ msg is seen,
 * and then used to create pinhole when subsequent PPTP_OUT_CALL_REPLY msg is
 * seen.
 */
struct cgn_alg_pptp_session {
	/* Must always be first */
	struct cgn_alg_sess_ctx	aps_as;
	struct cgn_map		aps_cmi;

	/*
	 * Call ID in outbound TCP control/parent pkts is translated from
	 * aps_orig_call_id to aps_trans_call_id
	 *
	 * Peer call ID in inbound TCP control/parent pkts is translated from
	 * aps_trans_call_id to aps_orig_call_id
	 *
	 * Call ID in inbound GRE data/child pkts is translated from
	 * aps_trans_call_id to aps_orig_call_id.  (outbound GRE pkts require
	 * no payload translation)
	 *
	 * aps_orig_call_id and aps_trans_call_id are set when the outbound
	 * PPTP_OUT_CALL_REQ TCP ctrl msg is seen.
	 *
	 * aps_peer_call_id is set when the subsequent inbound
	 * PPTP_OUT_CALL_REPLY TCP ctrl msg is seen.
	 */
	uint16_t	aps_orig_call_id;	/* client inside call ID */
	uint16_t	aps_trans_call_id;	/* client outside call ID */
	uint16_t	aps_peer_call_id;	/* server call ID */
};

static_assert(offsetof(struct cgn_alg_pptp_session, aps_as) == 0,
	      "cgn_alg_pptp_session: aps_as not first");

#define aps_cse		aps_as.as_cse
#define aps_vrfid	aps_as.as_vrfid
#define aps_proto	aps_as.as_proto
#define aps_min_payload	aps_as.as_min_payload

#define PPTP_PINHOLE_TIMEOUT 10


enum pptp_msg {
	PPTP_MSG_CTRL = 1,
	PPTP_MSG_MGMT = 2,
};

enum pptp_ctrl {
	/* Control Connection Management */
	PPTP_START_CTRL_CONN_REQ = 1,
	PPTP_START_CTRL_CONN_REPLY = 2,
	PPTP_STOP_CTRL_CONN_REQ = 3,
	PPTP_STOP_CTRL_CONN_REPLY = 4,
	PPTP_ECHO_REQ = 5,
	PPTP_ECHO_REPLY = 6,

	/* Call Management */
	PPTP_OUT_CALL_REQ = 7,
	PPTP_OUT_CALL_REPLY = 8,
	PPTP_IN_CALL_REQ = 9,
	PPTP_IN_CALL_REPLY = 10,
	PPTP_IN_CALL_CONND = 11,
	PPTP_CALL_CLEAR_REQ = 12,
	PPTP_CALL_DISCONN_NOTIFY = 13,

	/* Error Reporting */
	PPTP_WAN_ERROR_NOTIFY = 14,

	/* PPP Session Control */
	PPTP_SET_LINK_INFO = 15,
};

/* Enum to bit */
#define PPTP_CTRL_MSG_BIT(pc)	(1 << ((pc) - 1))

/* These ctrl msgs require outbound payload translation */
#define PPTP_MSG_CALL_ID						\
	(PPTP_CTRL_MSG_BIT(PPTP_OUT_CALL_REQ) |				\
	 PPTP_CTRL_MSG_BIT(PPTP_OUT_CALL_REPLY) |			\
	 PPTP_CTRL_MSG_BIT(PPTP_IN_CALL_REQ) |				\
	 PPTP_CTRL_MSG_BIT(PPTP_IN_CALL_REPLY) |			\
	 PPTP_CTRL_MSG_BIT(PPTP_IN_CALL_CONND) |			\
	 PPTP_CTRL_MSG_BIT(PPTP_CALL_CLEAR_REQ) |			\
	 PPTP_CTRL_MSG_BIT(PPTP_CALL_DISCONN_NOTIFY) |			\
	 PPTP_CTRL_MSG_BIT(PPTP_WAN_ERROR_NOTIFY))

#define PPTP_MSG_HAS_CALL_ID(pc) (PPTP_CTRL_MSG_BIT(pc) & PPTP_MSG_CALL_ID)

/* These ctrl msgs require inbound payload translation */
#define PPTP_MSG_PEER_CALL_ID					\
	(PPTP_CTRL_MSG_BIT(PPTP_OUT_CALL_REPLY) |		\
	 PPTP_CTRL_MSG_BIT(PPTP_IN_CALL_REPLY))

#define PPTP_MSG_HAS_PEER_CALL_ID(pc)			\
	(PPTP_CTRL_MSG_BIT(pc) & PPTP_MSG_PEER_CALL_ID)

#define PPTP_MAGIC_COOKIE	0x1A2B3C4D

/*
 * PPTP Packet Header
 *
 * Each PPTP Control Connection message begins with an 8 octet fixed header
 * portion
 */
struct pptp {
	uint16_t	pptp_length;
	uint16_t	pptp_type;
	uint32_t	pptp_magic_cookie;
};

/*
 * PPTP Packet Header
 *
 * All the Call Management messages (7-13) and the WAN Error msg (14) have the
 * Call ID in the same location.
 *
 * The peer Call ID field is only in PPTP_OUT_CALL_REPLY (8) and
 * PPTP_IN_CALL_REPLY (10) messages.
 */
struct pptp_call_mgmt {
	uint16_t	pptp_length;
	uint16_t	pptp_type;
	uint32_t	pptp_magic_cookie;
	uint16_t	pptp_ctrl_type;
	uint16_t	pptp_reserved0;
	uint16_t	pptp_call_id;
	uint16_t	pptp_peer_call_id;
};


/*
 * PPTP_OUT_CALL_REQ.  Get CGNAT mapping, and store in session ctx.
 */
static int
cgn_pptp_inspect_out_call_req(struct cgn_alg_pptp_session *aps,
			      struct pptp_call_mgmt *pptp_call)
{
	struct cgn_alg_sess_ctx *as = &aps->aps_as;
	struct cgn_policy *cp;
	int rc;

	assert(aps);
	assert(as->as_cse);
	/*
	 * This mapping is for GRE PPTP, whereas the parent session is TCP.
	 * GRE PPTP ports are allocated from the NAT_PROTO_OTHER space (along
	 * with ICMP, SCCP etc.).
	 *
	 * cmi_oid is set to the server call ID when the PPTP_OUT_CALL_REPLY
	 * msg from the server is seen.
	 */
	struct cgn_map *cmi = &aps->aps_cmi;

	cmi->cmi_proto = NAT_PROTO_OTHER;
	cmi->cmi_oaddr = cgn_session_forw_addr(as->as_cse);

	assert(aps->aps_orig_call_id == 0);

	/* Save inside Call ID to the parent session */
	aps->aps_orig_call_id = pptp_call->pptp_call_id;

	/* Get the CGNAT policy from the session */
	cp = cgn_policy_from_cse(aps->aps_cse);

	/* Get a new mapping */
	rc = cgn_map_get(cmi, cp, as->as_vrfid);

	if (rc < 0)
		return -ALG_ERR_PPTP_MAP;

	/* Store trans Call ID for subsequent use by cgn_pptp_translate */
	aps->aps_trans_call_id = cmi->cmi_tid;

	/*
	 * Pinhole is not created until the out-call-reply has been seen.
	 * However we need the mapping now to translate the Call ID in the
	 * PPTP header.
	 */

	return 0;
}

/*
 * PPTP_OUT_CALL_REPLY.  Create forw and back pinholes.  Fetch CGNAT mapping
 * from session ctx, and store in a forw pinhole.
 */
static int
cgn_pptp_inspect_out_call_reply(struct cgn_packet *cpk,
				struct cgn_alg_pptp_session *aps,
				struct pptp_call_mgmt *pptp_call)
{
	struct cgn_map *cmi = &aps->aps_cmi;
	int rc = 0;

	/* Do we already know the outside Call ID? */
	if (aps->aps_peer_call_id)
		/* Should not happen */
		return -ALG_ERR_PPTP_REPLY;

	/* Save outside Call ID to the parent session */
	aps->aps_peer_call_id = pptp_call->pptp_call_id;

	/* The session should have a mapping in the ALG mapping info */
	if (!cmi->cmi_reserved)
		return -ALG_ERR_PPTP_REPLY;

	cmi->cmi_oid = aps->aps_peer_call_id; /* Server Call ID */

	/*
	 * Create forwards and reverse pinholes
	 *
	 * We can create pinhole now.  Inbound.  ip:gre.   Call ID == trans ID.
	 *
	 * Once GRE child session created:
	 *    Out: GRE pkts require src IP translated only.
	 *    In:  GRE pkts require dst IP *and* GRE Call ID translated.
	 */
	struct alg_pinhole_key key;
	struct alg_pinhole *fw_ap, *bk_ap;

	/* Forwards pinhole */
	key.pk_vrfid = aps->aps_vrfid;
	key.pk_ipproto = IPPROTO_GRE;

	key.pk_saddr = cmi->cmi_oaddr;
	key.pk_sid = cmi->cmi_oid;
	key.pk_daddr = cpk->cpk_saddr;
	key.pk_did = aps->aps_peer_call_id; /* Server Call ID */

	fw_ap = alg_pinhole_add(&key, aps->aps_cse, CGN_ALG_PPTP, CGN_DIR_OUT,
				PPTP_PINHOLE_TIMEOUT, &rc);
	if (!fw_ap)
		goto error;

	/* Transfer mapping info responsibility to the fwds pinhole */
	cgn_map_transfer(alg_pinhole_map(fw_ap), cmi);

	/* Reverse pinhole */
	key.pk_saddr = cpk->cpk_saddr;
	key.pk_sid = cmi->cmi_tid; /* 'outside' client Call ID */;
	key.pk_daddr = cmi->cmi_taddr;
	key.pk_did = cmi->cmi_tid; /* 'outside' client Call ID */

	bk_ap = alg_pinhole_add(&key, aps->aps_cse, CGN_ALG_PPTP, CGN_DIR_IN,
				PPTP_PINHOLE_TIMEOUT, &rc);
	if (!bk_ap) {
		alg_pinhole_expire(fw_ap);
		goto error;
	}

	/* Pair the two pinholes */
	alg_pinhole_link_pair(fw_ap, bk_ap);

	/* Activate pinholes so that they are findable by lookup */
	cgn_alg_pinhole_activate(fw_ap);
	cgn_alg_pinhole_activate(bk_ap);

	return 0;

error:
	/* Release mapping if its still held in the the PPTP session ctx */
	if (cmi->cmi_reserved)
		cgn_map_put(cmi, aps->aps_vrfid);

	return rc;
}

/* Translate PPTP header in TCP packet */
static int
cgn_pptp_translate(struct cgn_packet *cpk, struct rte_mbuf *mbuf,
		   enum cgn_dir dir, struct cgn_alg_pptp_session *aps,
		   struct pptp_call_mgmt *pptp_call)
{
	char *n_ptr = dp_pktmbuf_mtol3(mbuf, char *);
	struct tcphdr *th = (struct tcphdr *)(n_ptr + cpk->cpk_l3_len);

	/* Translate call ID */
	if (dir == CGN_DIR_OUT && aps->aps_trans_call_id) {
		assert(pptp_call->pptp_call_id == aps->aps_orig_call_id);

		pptp_call->pptp_call_id = aps->aps_trans_call_id;

		/* Update TCP checksum */
		th->check = ip_fixup16_cksum(th->check, aps->aps_orig_call_id,
					     pptp_call->pptp_call_id);
	}

	/* Translate peer call ID */
	if (dir == CGN_DIR_IN && aps->aps_trans_call_id) {
		assert(pptp_call->pptp_peer_call_id == aps->aps_trans_call_id);

		pptp_call->pptp_peer_call_id = aps->aps_orig_call_id;

		/* Update TCP checksum */
		th->check = ip_fixup16_cksum(th->check, aps->aps_trans_call_id,
					     pptp_call->pptp_peer_call_id);
	}
	return 0;
}

static int
cgn_alg_pptp_inspect_out(struct cgn_packet *cpk, struct rte_mbuf *mbuf,
			 struct cgn_alg_pptp_session *aps,
			 struct pptp_call_mgmt *pptp_call,
			 enum pptp_ctrl ctrl_type)
{
	int rc;

	/* Inside peers Call ID is in the PPTP_OUT_CALL_REQ msg */
	if (ctrl_type == PPTP_OUT_CALL_REQ) {
		rc = cgn_pptp_inspect_out_call_req(aps, pptp_call);

		if (rc < 0)
			return rc;
	}

	if (PPTP_MSG_HAS_CALL_ID(ctrl_type))
		cgn_pptp_translate(cpk, mbuf, CGN_DIR_OUT, aps, pptp_call);

	return 0;
}

static int
cgn_alg_pptp_inspect_in(struct cgn_packet *cpk, struct rte_mbuf *mbuf,
			struct cgn_alg_pptp_session *aps,
			struct pptp_call_mgmt *pptp_call,
			enum pptp_ctrl ctrl_type)
{
	int rc;

	/* Outside peers Call ID is in the PPTP_OUT_CALL_REPLY msg */
	if (ctrl_type == PPTP_OUT_CALL_REPLY) {
		rc = cgn_pptp_inspect_out_call_reply(cpk, aps, pptp_call);

		if (rc < 0)
			return rc;
	}

	if (PPTP_MSG_HAS_PEER_CALL_ID(ctrl_type))
		cgn_pptp_translate(cpk, mbuf, CGN_DIR_IN, aps, pptp_call);

	return 0;
}

/*
 * Inspect PPTP control message
 */
int cgn_alg_pptp_inspect(struct cgn_packet *cpk, struct rte_mbuf *mbuf,
			 enum cgn_dir dir, struct cgn_alg_sess_ctx *as)
{
	struct cgn_alg_pptp_session *aps;
	struct pptp *pptp;
	int rc;

	pptp = (struct pptp *)(dp_pktmbuf_mtol3(mbuf, char *) +
			       cpk->cpk_l3_len + cpk->cpk_l4_len);

	aps = caa_container_of(as, struct cgn_alg_pptp_session, aps_as);

	/* We are only interested in control messages */
	if (pptp->pptp_type != ntohs(PPTP_MSG_CTRL))
		return 0;

	/* Verify magic cookie constant */
	if (ntohl(PPTP_MAGIC_COOKIE) != pptp->pptp_magic_cookie)
		return -ALG_ERR_PPTP_MC;

	struct pptp_call_mgmt *pptp_call = (struct pptp_call_mgmt *)pptp;
	enum pptp_ctrl ctrl_type = ntohs(pptp_call->pptp_ctrl_type);

	if (dir == CGN_DIR_OUT)
		rc = cgn_alg_pptp_inspect_out(cpk, mbuf, aps, pptp_call,
					      ctrl_type);
	else
		rc = cgn_alg_pptp_inspect_in(cpk, mbuf, aps, pptp_call,
					      ctrl_type);

	return rc;
}

/*
 * Called when inbound GRE packets are rcvd in order to determine the client
 * inside Call ID.  We need to handle two scenarios:
 *
 * 1. The GRE s2 session has already been setup, or
 * 2. This is the first GRE packet in the data flow
 *
 * For the latter we need to get the client inside Call ID from the parent
 * session attached to the pinhole that has just been matched.
 *
 * Note, may be also called with cpk == NULL in order to simply get the orig
 * Call ID from a session.
 */
uint16_t cgn_alg_pptp_orig_call_id(struct cgn_session *cse,
				   struct cgn_packet *cpk)
{
	struct cgn_alg_pptp_session *aps = NULL;
	struct cgn_alg_sess_ctx *as = NULL;

	if (!cse && cpk && cpk->cpk_alg_pinhole)
		/* Get call ID from parent session */
		cse = alg_pinhole_cse(cpk->cpk_alg_pinhole);

	if (!cse)
		return 0;

	as = cgn_session_alg_get(cse);
	if (!as)
		return 0;

	aps = caa_container_of(as, struct cgn_alg_pptp_session, aps_as);

	return aps->aps_orig_call_id;
}

/*
 * Get peer Call ID
 */
uint16_t cgn_alg_pptp_peer_call_id(struct cgn_session *cse)
{
	struct cgn_alg_pptp_session *aps = NULL;
	struct cgn_alg_sess_ctx *as = NULL;

	if (!cse)
		return 0;

	as = cgn_session_alg_get(cse);
	if (!as)
		return 0;

	aps = caa_container_of(as, struct cgn_alg_pptp_session, aps_as);

	return aps->aps_peer_call_id;
}

/*
 * A PPTP pinhole table entry has been matched.
 *
 * Populate the passed-in cgn_map struct so that cgnat has all it needs to
 * create a session when we exit from this function.
 */
int cgn_alg_pptp_pinhole_found(struct alg_pinhole *ap, struct cgn_map *cmi)
{
	struct alg_pinhole *ap2, *map_ap = NULL;

	/* PPTP pinholes should be in pairs */
	ap2 = alg_pinhole_pair(ap);
	if (!ap2)
		return -CGN_ALG_ERR_PHOLE;

	/* One of the pair of pinholes should have a mapping */
	if (alg_pinhole_has_mapping(ap))
		map_ap = ap;
	else if (alg_pinhole_has_mapping(ap2))
		map_ap = ap2;

	if (!map_ap)
		return -CGN_ALG_ERR_PHOLE;

	/*
	 * Transfer mapping info and reservation from the pinhole to the
	 * passed-in map structure.
	 */
	cgn_map_transfer(cmi, alg_pinhole_map(map_ap));

	/* Assert that all the required fields are initialized */
	assert(cmi->cmi_taddr);
	assert(cmi->cmi_tid);
	assert(cmi->cmi_oaddr);
	assert(cmi->cmi_oid);
	assert(cmi->cmi_src);

	return 0;
}

/*
 * Initialise PPTP child session (enhanced GRE)
 */
static void
cgn_alg_pptp_child_sess_init(struct alg_pinhole *ap,
			     struct cgn_alg_pptp_session *aps)
{
	struct cgn_alg_pptp_session *parent_aps;
	struct cgn_alg_sess_ctx *parent_as;
	struct cgn_session *parent_cse;

	parent_cse = alg_pinhole_cse(ap);
	parent_as = cgn_session_alg_get(parent_cse);
	parent_aps = caa_container_of(parent_as, struct cgn_alg_pptp_session,
				      aps_as);

	/*
	 * aps_orig_call_id and aps_trans_call_id are setup in the parent
	 * session when the PPTP_OUT_CALL_REQ msg is inspected.
	 *
	 * aps_peer_call_id is setup in the parent session when the
	 * PPTP_OUT_CALL_REPLY msg is inspected.
	 */
	aps->aps_orig_call_id = parent_aps->aps_orig_call_id;
	aps->aps_trans_call_id = parent_aps->aps_trans_call_id;
	aps->aps_peer_call_id = parent_aps->aps_peer_call_id;
}

/*
 * A new CGNAT 5-tuple session has just been created.
 *
 * If 'te' is set then it is a child session, else it is a parent session.
 */
struct cgn_alg_sess_ctx *
cgn_alg_pptp_sess_init(struct cgn_session *cse, struct alg_pinhole *ap)
{
	struct cgn_alg_pptp_session *aps;

	aps = zmalloc_aligned(sizeof(*aps));
	if (!aps)
		return NULL;

	struct cgn_alg_sess_ctx *as = &aps->aps_as;

	/* Set 'inspect' if this is parent flow (!ap) */
	cgn_alg_common_session_init(as, cse, !ap);

	if (ap)
		/* Child flow */
		cgn_alg_pptp_child_sess_init(ap, aps);

	return as;
}

void cgn_alg_pptp_sess_uninit(struct cgn_alg_sess_ctx *as)
{
	struct cgn_alg_pptp_session *aps;

	/* If parent session */
	if (!as->as_is_child) {
		aps = caa_container_of(as, struct cgn_alg_pptp_session,
				       aps_as);

		/* free any unused GRE session mapping */
		if (aps && aps->aps_cmi.cmi_reserved)
			cgn_map_put(&aps->aps_cmi, aps->aps_vrfid);
	}
}

/*
 * Init PPTP child (GRE) sub-session
 *
 * Adjust the sub-session sentry.  The ID/port needs to change to match the
 * translation ID.
 */
int cgn_alg_pptp_child_sess2_init(struct cgn_alg_sess_ctx *as,
				  struct cgn_sess2 *s2)
{
	struct cgn_alg_pptp_session *aps;

	aps = caa_container_of(as, struct cgn_alg_pptp_session, aps_as);

	cgn_sess2_set_sentry_id(s2, CGN_DIR_OUT, aps->aps_peer_call_id);
	cgn_sess2_set_sentry_id(s2, CGN_DIR_IN, aps->aps_trans_call_id);

	return 0;
}

/*
 * Write json for ALG PPTP session info
 */
void cgn_alg_show_pptp_session(json_writer_t *json,
			      struct cgn_alg_sess_ctx *as)
{
	struct cgn_alg_pptp_session *aps;

	aps = caa_container_of(as, struct cgn_alg_pptp_session, aps_as);
	(void)aps;

	jsonw_name(json, "pptp");
	jsonw_start_object(json);

	jsonw_uint_field(json, "orig_call_id", ntohs(aps->aps_orig_call_id));
	jsonw_uint_field(json, "trans_call_id", ntohs(aps->aps_trans_call_id));
	jsonw_uint_field(json, "peer_call_id", ntohs(aps->aps_peer_call_id));

	cgn_map_json(json, "mapping", &aps->aps_cmi);

	jsonw_end_object(json);
}
