/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf_session.c,v 1.18 2012/09/13 21:09:36 joerg Exp $	*/

/*-
 * Copyright (c) 2010-2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include "compiler.h"
#include "if_var.h"
#include "json_writer.h"
#include "npf/npf.h"
#include "npf/alg/alg_npf.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/dpi/dpi_internal.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/rproc/npf_ext_session_limit.h"
#include "npf/npf_dataplane_session.h"
#include "npf/npf_icmp.h"
#include "npf/npf_if.h"
#include "npf/npf_nat.h"
#include "npf/npf_nat64.h"
#include "npf/npf_pack.h"
#include "npf/npf_rc.h"
#include "npf/npf_ruleset.h"
#include "npf/npf_session.h"
#include "npf/npf_state.h"
#include "npf/npf_timeouts.h"
#include "npf/npf_cache.h"
#include "npf/npf_rule_gen.h"
#include "npf_shim.h"
#include "pktmbuf_internal.h"
#include "session/session_watch.h"
#include "urcu.h"
#include "vplane_log.h"

struct rte_mbuf;
struct npf_nat64;

/*
 * NPF session.
 */
struct npf_session {
	npf_state_t		s_state;
	int			s_flags;
	vrfid_t			s_vrfid;
	struct session		*s_session;
	/* --- cacheline 1 boundary (64 bytes) --- */
	npf_nat_t		*s_nat;
	struct npf_session_alg	*s_alg;
	npf_rule_t		*s_fw_rule;
	struct npf_nat64	*s_nat64;
	session_pkt_hook	*s_hook;
	void			*s_dpi;
	uint32_t		s_if_idx;
	npf_decision_t		s_appfw_decision;
	npf_rule_t		*s_rproc_rule;
	/* --- cacheline 2 boundary (128 bytes) --- */
	struct npf_session	*s_parent;	/* NULL if this == parent */
	uint8_t			s_proto;
	enum npf_proto_idx	s_proto_idx;
};

static_assert(offsetof(struct npf_session, s_nat) == 64,
	      "first cache line exceeded");
static_assert(offsetof(struct npf_session, s_parent) == 128,
	      "second cache line exceeded");

/*
 * Session flags:
 * - PFIL_IN and PFIL_OUT values are reserved for direction.
 * - SE_ACTIVE: session is active i.e. visible on inspection.
 * - SE_PASS: a "pass" session.
 * - SE_EXPIRE: explicitly expire the session.
 * - SE_GC_PASS_TWO: in the 2nd pass of the GC process
 * - SE_SECONDARY: an ALG created secondary flow
 * - SE_LOCAL_ZONE_NAT: Indicates NAT session for local traffic
 * - SE_IF_DISABLED: The interface associated with this session was disabled
 */
#define	SE_ACTIVE		0x004
#define	SE_PASS			0x008
#define	SE_EXPIRE		0x010
#define	SE_GC_PASS_TWO		0x020
#define	SE_SECONDARY		0x040
#define	SE_LOCAL_ZONE_NAT	0x080
#define	SE_IF_DISABLED		0x100
#define	SE_NAT_PINHOLE		0x200

/*
 * session logging.  Allows for 4 protocols, and up to 16 flags per protocol.
 */
static uint64_t npf_log_flag;

#define NPF_SET_SESSION_LOG_FLAG(p, f) (npf_log_flag |=  (1ull << ((p<<4) + f)))
#define NPF_CLR_SESSION_LOG_FLAG(p, f) (npf_log_flag &= ~(1ull << ((p<<4) + f)))
#define NPF_TST_SESSION_LOG_FLAG(p, f) (npf_log_flag &   (1ull << ((p<<4) + f)))
#define NPF_SESSION_LOG_MASK(p) (0x000000000000ffffull << (p<<4))

/* Forward reference */
static void sess_clear_nat64_peer(npf_session_t *se);

/*
 * Get the dataplane session ID given an npf session.  If se or se->s_session
 * are NULL then 0 is returned.
 */
uint64_t npf_session_get_id(struct npf_session *se)
{
	if (se)
		return session_get_id(se->s_session);
	return 0;
}

static inline bool npf_test_session_log_proto(enum npf_proto_idx proto_idx)
{
	assert(NPF_PROTO_IDX_TCP == 0);
	assert(NPF_PROTO_IDX_UDP == 1);
	assert(NPF_PROTO_IDX_ICMP == 2);
	assert(NPF_PROTO_IDX_OTHER == 3);
	assert(NPF_TCPS_LAST < 16);

	return (npf_log_flag & NPF_SESSION_LOG_MASK(proto_idx)) != 0;
}

static inline bool
npf_test_session_log_flag(uint8_t state, enum npf_proto_idx proto_idx)
{
	return NPF_TST_SESSION_LOG_FLAG(proto_idx, state) != 0;
}

/*
 * Reset session logging back to initial configuration
 */
void npf_reset_session_log(void)
{
	npf_log_flag = 0;
}

static void __cold_func
npf_session_log(npf_session_t *se, const char *state_name, uint32_t timeout,
		uint8_t proto, const char *proto_name)
{
	/* Cannot log unactivated sessions */
	if (unlikely(!se->s_session))
		return;

	struct sentry *sen = rcu_dereference(se->s_session->se_sen);

	/* Racing with session expiration */
	if (unlikely(!sen))
		return;

	const void *saddr;
	const void *daddr;
	int af;
	uint32_t if_index;
	uint16_t sid;
	uint16_t did;
	char srcip_str[INET6_ADDRSTRLEN];
	char dstip_str[INET6_ADDRSTRLEN];
	char dpi_info_str[MAX_DPI_LOG_SIZE];

	session_sentry_extract(sen, &if_index, &af, &saddr, &sid, &daddr, &did);

	inet_ntop(af, saddr, srcip_str, sizeof(srcip_str));
	inet_ntop(af, daddr, dstip_str, sizeof(dstip_str));

	dpi_info_str[0] = '\0';
	if (se->s_dpi)
		dpi_info_log(se->s_dpi, dpi_info_str, MAX_DPI_LOG_SIZE);

	RTE_LOG(NOTICE, FIREWALL,
		"session table: id(%lu) [%s] %s(%d)"
		" timeout=%d src=%s(%d) dst=%s(%d) ifname=%s%s%s\n",
		se->s_session->se_id, state_name, proto_name, proto, timeout,
		srcip_str,
		ntohs(sid),
		dstip_str,
		ntohs(did), ifnet_indextoname_safe(if_index),
		(dpi_info_str[0] == '\0') ? "" : " ",
		dpi_info_str);
}

static inline void
npf_session_tcp_log(npf_session_t *se, enum tcp_session_state state)
{
	uint32_t timeout;
	npf_state_t *nst = &se->s_state;

	if (!npf_test_session_log_proto(NPF_PROTO_IDX_TCP))
		return;

	/* return immediately if the flag is not set */
	if (likely(!npf_test_session_log_flag(state, NPF_PROTO_IDX_TCP)))
		return;

	const char *state_name = npf_state_get_state_tcp_name(state);

	timeout = npf_tcp_timeout_get(nst, state,
				      se->s_session->se_custom_timeout);

	npf_session_log(se, state_name, timeout, IPPROTO_TCP, "tcp");
}

static inline void
npf_session_gen_log(npf_session_t *se, enum dp_session_state state,
		    uint8_t proto_idx)
{
	uint32_t timeout;
	npf_state_t *nst = &se->s_state;

	if (!npf_test_session_log_proto(proto_idx))
		return;

	/* return immediately if the flag is not set */
	if (likely(!npf_test_session_log_flag(state, proto_idx)))
		return;

	const char *state_name = dp_session_state_name(state, true);
	const char *proto_name = npf_get_protocol_name_from_idx(proto_idx);

	timeout = npf_gen_timeout_get(nst, state, proto_idx,
				      se->s_session->se_custom_timeout);

	npf_session_log(se, state_name, timeout, se->s_proto, proto_name);
}

/*
 * Log nat64 and nat46 sessions
 *   1. After egress session is created, or
 *   2. When either ingress or egress sessions are expired
 */
void __cold_func
npf_session_nat64_log(npf_session_t *se, bool created)
{
	npf_session_t *peer;
	struct sentry *sen;

	sen = rcu_dereference(se->s_session->se_sen);
	if (!sen)
		return;

	/*
	 * peer will be NULL when ingress session is activated.  We log the
	 * sessions when the egress session is create.
	 */
	peer = npf_nat64_get_peer(se->s_nat64);
	if (created && !peer)
		return;

	char msg[200];
	int l = 0, sz = sizeof(msg);
	char srcip_str[INET6_ADDRSTRLEN];
	char dstip_str[INET6_ADDRSTRLEN];
	struct sentry *peer_sen;
	const void *saddr;
	const void *daddr;
	uint32_t if_index;
	uint16_t sid;
	uint16_t did;
	int af;

	l += snprintf(msg+l, sz-l, "session %7s:",
		      created ? "created":"closed");

	/* Ingress session */
	peer_sen = peer ? rcu_dereference(peer->s_session->se_sen) : NULL;
	if (created && peer_sen) {
		session_sentry_extract(peer_sen, &if_index, &af, &saddr, &sid,
				       &daddr, &did);
		inet_ntop(af, saddr, srcip_str, sizeof(srcip_str));
		inet_ntop(af, daddr, dstip_str, sizeof(dstip_str));

		l += snprintf(msg+l, sz-l, " [%lu] %s/%u->%s/%u %s",
			      peer->s_session->se_id,
			      srcip_str, ntohs(sid), dstip_str, ntohs(did),
			      ifnet_indextoname_safe(if_index));
	}

	/* Only (or Egress) session */
	session_sentry_extract(sen, &if_index, &af, &saddr, &sid,
			       &daddr, &did);
	inet_ntop(af, saddr, srcip_str, sizeof(srcip_str));
	inet_ntop(af, daddr, dstip_str, sizeof(dstip_str));

	l += snprintf(msg+l, sz-l, "%s[%lu] %s/%u->%s/%u %s",
		      (peer && created) ? ", ":" ",
		      se->s_session->se_id,
		      srcip_str, ntohs(sid), dstip_str, ntohs(did),
		      ifnet_indextoname_safe(if_index));

	const char *proto_name;
	const char *ruleset_name;
	rule_no_t rule_number = 0;
	npf_rule_t *rl;

	proto_name = npf_get_protocol_name_from_idx(se->s_proto_idx);
	rl = npf_nat64_get_rule(se->s_nat64);
	ruleset_name = npf_rule_get_name(rl);
	if (rl)
		rule_number = npf_rule_get_num(rl);

	l += snprintf(msg+l, sz-l, ", %s", proto_name);

	if (ruleset_name)
		l += snprintf(msg+l, sz-l, " %s/%u",
			      ruleset_name, rule_number);

	if (!created)
		snprintf(msg+l, sz-l, " [%lu]",
			 peer ? peer->s_session->se_id : 0);

	if (npf_nat64_session_is_nat64(se))
		RTE_LOG(NOTICE, NAT64, "%s\n", msg);
	else
		RTE_LOG(NOTICE, NAT46, "%s\n", msg);
}

/* return the IP protocol of this session */
uint8_t npf_session_get_proto(npf_session_t *se)
{
	return se ? se->s_proto : 0;
}

static npf_rule_t *npf_session_get_fw_rule(const npf_session_t *s)
{
	return  s ?  rcu_dereference(s->s_fw_rule) : NULL;
}

void npf_session_add_fw_rule(npf_session_t *s, npf_rule_t *r)
{
	if (s) {
		if (!rcu_cmpxchg_pointer(&s->s_fw_rule, NULL, npf_rule_get(r)))
			s->s_flags |= SE_PASS;
		else
			npf_rule_put(r);
	}
}

bool npf_session_is_fw(npf_session_t *s)
{
	return s && (s->s_flags & SE_PASS) != 0;
}


/* Set the expire flag and contact ALG framework */
static void sess_set_expired(npf_session_t *se)
{
	uint32_t exp = se->s_flags & ~SE_EXPIRE;

	/* Must ensure this happens only once */
	if (rte_atomic32_cmpset((uint32_t *) &se->s_flags, exp,
				(exp | SE_EXPIRE))) {
		npf_alg_session_expire(se, se->s_alg);
		if (se->s_session)
			session_feature_request_expiry(se->s_session,
						       se->s_if_idx,
						       SESSION_FEATURE_NPF);
	}
}

void npf_session_set_local_zone_nat(npf_session_t *se)
{
	if (se && !(se->s_flags & SE_LOCAL_ZONE_NAT))
		se->s_flags |= SE_LOCAL_ZONE_NAT;
}

bool npf_session_is_local_zone_nat(npf_session_t *se)
{
	return se && (se->s_flags & SE_LOCAL_ZONE_NAT);
}

/* Clear parent */
static void sess_clear_parent(npf_session_t *se)
{
	se->s_parent = NULL;
}

/* Closes a session, which will result in it being marked as expired. */
static void sess_close(npf_session_t *se)
{
	if (se->s_proto_idx == NPF_PROTO_IDX_TCP)
		npf_state_set_tcp_closed(&se->s_state,
					 (se->s_flags & SE_ACTIVE));
	else
		npf_state_set_gen_closed(&se->s_state,
					 (se->s_flags & SE_ACTIVE),
					 se->s_proto_idx);
}

void npf_session_set_appfw_decision(npf_session_t *se, npf_decision_t decision)
{
	se->s_appfw_decision = decision;
}

npf_decision_t npf_session_get_appfw_decision(npf_session_t *se)
{
	return se->s_appfw_decision;
}

struct npf_session_alg *
npf_session_get_alg_ptr(const npf_session_t *se)
{
	if (se && se->s_alg)
		return se->s_alg;
	return NULL;
}

void
npf_session_set_alg_ptr(npf_session_t *se, struct npf_session_alg *sa)
{
	if (se)
		se->s_alg = sa;
}

bool npf_session_uses_alg(npf_session_t *se)
{
	if (se && se->s_alg)
		return true;
	return false;
}

/* Get session if index */
uint32_t npf_session_get_if_index(npf_session_t *se)
{
	return se->s_if_idx;
}

/* npf_session_link_child() - Link a child session to its parent.  */
void npf_session_link_child(struct npf_session *parent, struct npf_session *c)
{
	/* Check to ensure this parent is still active */
	if (!(parent->s_flags & SE_EXPIRE)) {
		c->s_flags |= SE_SECONDARY;
		c->s_parent = parent;
	}
}

bool npf_session_is_child(const npf_session_t *se)
{
	if (se->s_parent)
		return true;

	return false;
}

/* Get the parent pointer */
struct npf_session *npf_session_get_parent(const struct npf_session *se)
{
	if (se)
		return se->s_parent;
	return NULL;
}

/* Get the base-level session of a parent/child chain */
const struct npf_session *npf_session_get_base_parent(
		const struct npf_session *se)
{
	npf_session_t *parent = npf_session_get_parent(se);

	if (parent)
		return npf_session_get_base_parent(parent);
	return se;
}

/*
 * Get the NPF session feature, which is an npf_session_t from the
 * dataplane session.
 *
 * Perform various tests to ensure correctness.
 */
static inline npf_session_t *npf_session_feature_get(struct session *s,
		const struct ifnet *ifp, const int di, bool forw,
		bool *internal_hairpin)
{
	npf_session_t *se = session_feature_get(s, ifp->if_index,
			SESSION_FEATURE_NPF);

	if (!se)
		return NULL;

	/* Check if session is active and not expired. */
	if (unlikely((se->s_flags & (SE_ACTIVE | SE_EXPIRE)) != SE_ACTIVE))
		return NULL;

	/*
	 * Can skip session processing of the packet if not in the expected
	 * direction, as it will be because of a packet going in and out
	 * the same interface (hairpinning). This prevents the packet
	 * getting processed a second time.
	 */
	const bool npf_forw = (se->s_flags & PFIL_ALL) == di;
	if (unlikely(forw != npf_forw)) {
		if (internal_hairpin)
			*internal_hairpin = true;
		else
			return NULL;
	}

	return se;
}

/*
 * Find an established, non expired session datum.
 *
 * The caller must ensure that npf_session_trackable_p() has been
 * called first,  and allowed the lookup to occur.
 */
npf_session_t *npf_session_find(struct rte_mbuf *m, const int di,
		const struct ifnet *ifp, bool *sfwd, bool *internal_hairpin)
{
	struct session *s;

	if (session_lookup(m, ifp->if_index, &s, sfwd))
		return NULL;

	return npf_session_feature_get(s, ifp, di, *sfwd, internal_hairpin);
}

/* Find an NPF session via an npc. */
npf_session_t *npf_session_find_by_npc(npf_cache_t *npc, const int di,
		const struct ifnet *ifp, bool embedded)
{
	struct sentry_packet sp;
	struct session *s;
	uint16_t src_id;
	uint16_t dst_id;
	uint16_t flags;
	bool forw;

	flags = (npc->npc_alen == 4) ? SENTRY_IPv4 : SENTRY_IPv6;

	if (likely(npf_iscached(npc, NPC_L4PORTS))) {
		struct npf_ports *ports = &npc->npc_l4.ports;
		src_id = ports->s_port;
		dst_id = ports->d_port;
	} else if (npf_iscached(npc, NPC_ICMP_ECHO)) {
		const struct icmp *ic = &npc->npc_l4.icmp;
		src_id = dst_id = ic->icmp_id;
	} else {
		src_id = dst_id = 0;
	}

	if (likely(embedded)) {
		/*
		 * Embedded packets reflect the original packet, so
		 * source and destination need reversed for it to
		 * match a session.
		 */
		if (session_init_sentry_packet(&sp, ifp->if_index, flags,
					       npf_cache_ipproto(npc),
					       if_vrfid(ifp), dst_id,
					       npf_cache_dstip(npc), src_id,
					       npf_cache_srcip(npc)))
			return NULL;
	} else {
		if (session_init_sentry_packet(&sp, ifp->if_index, flags,
					       npf_cache_ipproto(npc),
					       if_vrfid(ifp), src_id,
					       npf_cache_srcip(npc), dst_id,
					       npf_cache_dstip(npc)))
			return NULL;
	}

	if (session_lookup_by_sentry_packet(&sp, &s, &forw))
		return NULL;

	return npf_session_feature_get(s, ifp, di, forw, NULL);
}

static npf_rule_t *npf_session_get_rproc_rule(const npf_session_t *s)
{
	return  s ?  rcu_dereference(s->s_rproc_rule) : NULL;
}

static void npf_session_add_rproc_rule(npf_session_t *s, npf_rule_t *r)
{
	s->s_rproc_rule = npf_rule_get(r);
}

/*
 *  Update initial dataplane state/timeout
 */
void npf_session_update_state(npf_session_t *se)
{
	if (se->s_proto_idx == NPF_PROTO_IDX_TCP)
		npf_state_update_tcp_session(se->s_session, &se->s_state);
	else
		npf_state_update_gen_session(se->s_session, se->s_proto_idx,
					     &se->s_state);
}

/*
 * Calls session watch hook if needed
 */
static inline void npf_session_do_watch(npf_session_t *se,
					enum dp_session_hook hook)
{
	if (!is_watch_on())
		return;

	if (se->s_session)
		session_do_watch(se->s_session, hook);
}

/*
 * Callback from npf_state.c after a UDP, ICMP etc. session changes state.
 */
void npf_session_gen_state_change(npf_state_t *nst,
				  enum dp_session_state old_state,
				  enum dp_session_state new_state,
				  enum npf_proto_idx proto_idx)
{
	npf_session_t *se = caa_container_of(nst, npf_session_t, s_state);
	npf_rule_t *rproc_rl;

	/* session logging */
	npf_session_gen_log(se, new_state, proto_idx);

	/* Update the dataplane session state/timeout */
	npf_state_update_gen_session(se->s_session, proto_idx, nst);

	/* Session rproc */
	rproc_rl = npf_session_get_rproc_rule(se);

	void *handle = npf_rule_rproc_handle_from_id(rproc_rl,
						     NPF_RPROC_ID_SLIMIT);

	if (handle && new_state != old_state)
		npf_sess_limit_state_change(handle, proto_idx,
					    old_state, new_state);

	if (new_state == SESSION_STATE_CLOSED)
		sess_set_expired(se);

	npf_session_do_watch(se, SESSION_STATE_CHANGE);
}

/*
 * Callback from npf_state.c after a TCP session changes state.
 */
void npf_session_tcp_state_change(npf_state_t *nst,
				  enum tcp_session_state old_state,
				  enum tcp_session_state new_state)
{
	npf_session_t *se = caa_container_of(nst, npf_session_t, s_state);
	npf_rule_t *rproc_rl;

	/* session logging */
	npf_session_tcp_log(se, new_state);

	/* Update the dataplane session state/timeout */
	npf_state_update_tcp_session(se->s_session, nst);

	/* Session rproc */
	rproc_rl = npf_session_get_rproc_rule(se);

	void *handle = npf_rule_rproc_handle_from_id(rproc_rl,
						     NPF_RPROC_ID_SLIMIT);
	if (handle && new_state != old_state)
		npf_sess_limit_state_change(handle, NPF_PROTO_IDX_TCP,
					    old_state, new_state);

	if (new_state == NPF_TCPS_CLOSED)
		sess_set_expired(se);

	npf_session_do_watch(se, SESSION_STATE_CHANGE);
}

/*
 * Determine if the packet can have (or create) session tracking state.
 *
 * An ICMP error packet can not create session tracking state, but its
 * embedded packet may have done so.  So such an error can 'have' session
 * tracking state,  but we require the caller to parse within them itself
 * such that here we can consider ICMP error to have no state.  This is
 * achieved simply be ensure an ICMP is one which can create state.
 */
static bool
npf_session_trackable_p(npf_cache_t *npc)
{
	if (!npf_iscached(npc, NPC_IP46) || npf_iscached(npc, NPC_IPFRAG))
		return false;
	if (npf_iscached(npc, NPC_ICMP) && !npf_iscached(npc, NPC_ICMP_ECHO))
		return false;

	return true;
}


/*
 * Find a session matching the packet passed in for inspection.
 *
 * When we find an existing session, we also validate and update
 * the protocol state of the session (e.g. TCP strict stateful),
 * possibly returning an error if an invalid state progression
 * is observed.
 */
npf_session_t *
npf_session_inspect(npf_cache_t *npc, struct rte_mbuf *nbuf,
		const struct ifnet *ifp, const int di, int *error,
		bool *internal_hairpin)
{
	npf_session_t *se;

	/* Can the packet have session tracking state? */
	if (!npf_session_trackable_p(npc))
		return NULL;

	/* Don't create sessions for traffic on the invalid VRF. */
	if (pktmbuf_get_vrf(nbuf) == VRF_INVALID_ID)
		return NULL;

	bool sforw = false;
	int rc;

	/* Try to find an existing session */
	se = npf_session_find(nbuf, di, ifp, &sforw, internal_hairpin);
	if (!se)
		return NULL;

	npc->npc_proto_idx = se->s_proto_idx;

	if (internal_hairpin && *internal_hairpin)
		return se;

	/* Update the state of a session based on the supplied packet */
	rc = npf_state_inspect(npc, nbuf, &se->s_state, se->s_proto_idx, sforw);
	if (unlikely(rc < 0)) {
		/* Silently block invalid packets. */
		*error = rc;
		return NULL;
	}

	/* Give the session packet hook a chance to see and drop it */
	if (se->s_hook) {
		if (!se->s_hook(se, npc, nbuf, di)) {
			*error = -NPF_RC_SESS_HOOK;
			return NULL;
		}
	}

	return se;
}

/*
 * Find a session matching the packet passed in for inspection.
 *
 * If this is not an ICMP error packet, and we fail to find one,
 * then we look to see if we should create a 'parent' tuple based
 * session, returning that if we do.
 *
 * Note that if '*error' is set < 0 then the packet is dropped.
 */
npf_session_t *
npf_session_inspect_or_create(npf_cache_t *npc, struct rte_mbuf *nbuf,
		const struct ifnet *ifp, const int di, uint16_t *npf_flag,
		int *error, bool *internal_hairpin)
{
	npf_session_t *se;

	/* Skip to ICMP errors parsing ASAP */
	if (npf_iscached(npc, NPC_ICMP_ERR))
		goto icmp_err_session;

	se = npf_session_inspect(npc, nbuf, ifp, di, error, internal_hairpin);
	if (se) {
		/*
		 * ZBF skip processing tries to approximate IBF behaviour.
		 * So this allows through packets matching sessions for:
		 *  1) Stateful firewall rules
		 *  2) ALG enabled secondary flows
		 *  3) Reverse NAT traffic
		 */
		if ((se->s_flags & (SE_PASS|SE_SECONDARY)) ||
		    ((se->s_flags & SE_NAT_PINHOLE) &&
		     ((se->s_flags & PFIL_ALL) != di)))
			*npf_flag |= NPF_FLAG_IN_SESSION;
		return se;
	}

	/* this will potentially create a tuple based session */
	if (!*error) {
		se = npf_alg_session(npc, nbuf, ifp, di, error);

		if (se) {
			npc->npc_proto_idx = se->s_proto_idx;
			*npf_flag |= NPF_FLAG_IN_SESSION;
		}
	}

	return se;

	/* The packet is an ICMP error.  Does it match a session? */
icmp_err_session: __cold_label;

	se = npf_icmp_err_session_find(di, nbuf, npc, ifp);
	if (se) {
		if (se->s_nat)
			npc->npc_info |= NPC_ICMP_ERR_NAT;
		/* The session pkt was embedded in an ICMP error */
		if (se->s_nat || (se->s_flags & (SE_PASS|SE_SECONDARY)))
			*npf_flag |= NPF_FLAG_IN_SESSION | NPF_FLAG_ERR_SESSION;
	}
	return NULL;
}

/*
 * Try to find and any session cached against the packet, and ensure it
 * is not expired. Optionally also validate that it is for the expected
 * interface and direction.
 * If any of the checks fail then the cache is invalidated, and NULL returned.
 */
static npf_session_t *
npf_session_find_valid_cached(struct rte_mbuf *mbuf,
			      const struct ifnet *ifp, int dir)
{
	npf_session_t *se = NULL;

	if (pktmbuf_mdata_exists(mbuf, PKT_MDATA_SESSION)) {
		struct pktmbuf_mdata *mdata = pktmbuf_mdata(mbuf);
		se = mdata->md_session;
		if ((se->s_flags & SE_EXPIRE) || (ifp &&
		    (npf_session_get_if_index(se) != ifp->if_index ||
		     !npf_session_forward_dir(se, dir)))) {
			pktmbuf_mdata_clear(mbuf, PKT_MDATA_SESSION);
			se = NULL;
		}
	}

	return se;
}

/*
 * Try to find and any session cached against the packet, and ensure it
 * is not expired.
 */
npf_session_t *
npf_session_find_cached(struct rte_mbuf *mbuf)
{
	return npf_session_find_valid_cached(mbuf, NULL, 0);
}

/*
 * This for use by non features to allow them to find any existing
 * session created by firewall or NAT (possibly cached in the packet),
 * and if not to create and activate such a session.
 */
npf_session_t *
npf_session_find_or_create(npf_cache_t *npc, struct rte_mbuf *mbuf,
			   const struct ifnet *ifp, int dir, int *error)
{
	npf_session_t *se = npf_session_find_valid_cached(mbuf, ifp, dir);
	if (se)
		return se;

	/* Try to find what we created previously */
	se = npf_session_inspect(npc, mbuf, ifp, dir, error, NULL);
	if (*error)
		return NULL;

	/* Try to create a new session for this interface */
	if (!se) {
		/* Potentially create an ALG associated session */
		se = npf_alg_session(npc, mbuf, ifp, dir, error);
		if (*error)
			return NULL;
		/* Create a session for this packet */
		if (!se)
			se = npf_session_establish(npc, mbuf, ifp, dir, error);
		if (!se || *error)
			return NULL;
	}

	if (npf_session_activate(se, ifp, npc, mbuf) < 0) {
		*error = -EEXIST;
		return NULL;
	}

	/* Attach the session to the packet */
	struct pktmbuf_mdata *mdata = pktmbuf_mdata(mbuf);
	mdata->md_session = se;
	pktmbuf_mdata_set(mbuf, PKT_MDATA_SESSION);

	return se;
}

/*
 * Session create rproc. Return 'false' to block session creation.
 */
static bool npf_rproc_session_create(npf_cache_t *npc, struct rte_mbuf *nbuf,
				     const struct ifnet *ifp, const int di,
				     npf_rule_t **rlp)
{
	const npf_ruleset_t *npf_rs = NULL;
	npf_rule_t *rl;

	/*
	 * First look for per-interface session rproc.  If we dont find one,
	 * then check the global session rproc
	 */
	struct npf_if *nif = rcu_dereference(ifp->if_npf);
	struct npf_config *npf_config = npf_if_conf(nif);
	if (npf_active(npf_config, NPF_SESSION_RPROC))
		npf_rs = npf_get_ruleset(npf_config, NPF_RS_SESSION_RPROC);

	if (!npf_rs) {
		if (npf_active(npf_global_config, NPF_SESSION_RPROC)) {
			npf_rs = npf_get_ruleset(npf_global_config,
						 NPF_RS_SESSION_RPROC);
			if (!npf_rs)
				return true;
		} else
			return true;
	}

	rl = npf_ruleset_inspect(npc, nbuf, npf_rs, NULL, NULL, di);

	if (rl) {
		if (npf_sess_limit_check(rl)) {
			/* block session creation */
			npf_add_pkt(rl, 0);
			return false;
		}

		/*
		 * We are not interested in the bytes count here, so use
		 * 'pkts_ct' to store the matches, and 'bytes_ct' to store the
		 * passes.  The blocked count is then pkts_ct - bytes_ct.
		 */
		npf_add_pkt(rl, 1);
		*rlp = rl;

	}

	return true;
}

static npf_session_t *
npf_session_create(npf_cache_t *npc, struct rte_mbuf *nbuf,
		   const struct ifnet *ifp, const int di, int *error)
{
	npf_rule_t *rproc_rl = NULL;
	npf_session_t *se = NULL;

	/* session rproc */
	if (!npf_rproc_session_create(npc, nbuf, ifp, di, &rproc_rl)) {
		*error = -NPF_RC_SESS_LIMIT;
		return NULL;
	}

	/* Allocate and initialize new state. */
	se = zmalloc_aligned(sizeof(npf_session_t));
	if (unlikely(se == NULL)) {
		*error = -NPF_RC_SESS_ENOMEM;
		return NULL;
	}

	/*
	 * Save the rproc session rule so the rproc can monitor state changes.
	 */
	if (rproc_rl)
		npf_session_add_rproc_rule(se, rproc_rl);

	return se;
}

/*
 * npf_establish_session: create a new session, insert into the
 * forward table-instance list.
 */
npf_session_t *
npf_session_establish(npf_cache_t *npc, struct rte_mbuf *nbuf,
		const struct ifnet *ifp, const int di, int *error)
{
	npf_session_t *se = NULL;
	uint8_t proto;

	assert(*error == 0);

	/* Can the packet create session tracking state */
	if (!npf_session_trackable_p(npc))
		return NULL;

	se = npf_session_create(npc, nbuf, ifp, di, error);
	if (!se)
		return NULL;

	se->s_flags = (di & PFIL_ALL);

	proto = npf_cache_ipproto(npc);
	npc->npc_proto_idx = npf_proto_idx_from_proto(proto);
	se->s_proto_idx = npc->npc_proto_idx;
	se->s_vrfid = pktmbuf_get_vrf(nbuf);

	/* Initialize protocol state. */
	if (!npf_state_init(se->s_vrfid, npc->npc_proto_idx, &se->s_state)) {
		*error = -NPF_RC_INTL;
		goto fail;
	}

	se->s_proto = proto;
	se->s_if_idx = ifp->if_index;

	/*
	 * See if this matches an ALG expected flow
	 *
	 * This may attach a nat struct to this new
	 * session handle.
	 */
	*error = npf_alg_session_init(se, npc, di);
	if (*error) {
		*error = -NPF_RC_ALG_ERR;
		goto fail;
	}

	return se;

fail:
	free(se);
	return NULL;
}

bool npf_session_is_active(const npf_session_t *se)
{
	return se->s_flags & SE_ACTIVE;
}

int npf_session_activate(npf_session_t *se, const struct ifnet *ifp,
		npf_cache_t *npc, struct rte_mbuf *nbuf)
{
	int rc;

	if ((se->s_flags & SE_ACTIVE) == 0) {
		rc = npf_state_inspect(npc, nbuf, &se->s_state,
				       se->s_proto_idx, true);
		if (unlikely(rc < 0)) {
			/* Silently block invalid packets. */
			npf_session_destroy(se);
			return rc;
		}

		/*
		 * If pkt is a TCP reset then the new sessions state will be
		 * CLOSED.  We want to allow the packet though, but not
		 * activate the session.
		 */
		if (npf_tcp_state_is_closed(&se->s_state, se->s_proto_idx)) {
			npf_session_destroy(se);
			return -NPF_RC_ENOSTR;
		}

		/*
		 * Create a dataplane session with the npf session as
		 * a feature.
		 */
		bool out = (se->s_flags & PFIL_OUT) != 0;
		rc = npf_dataplane_session_establish(se, npc, nbuf, ifp, out);
		if (rc)
			return rc;

		npf_if_session_inc((struct ifnet *)ifp);

		se->s_flags |= SE_ACTIVE;

		if (npf_nat64_session_log_enabled(se->s_nat64))
			npf_session_nat64_log(se, true);

		npf_session_do_watch(se, SESSION_ACTIVATE);
	}

	return 0;
}

static int npf_session_disassoc_nif_feat_cb(struct session *s __unused,
					    struct session_feature *sf,
					    void *data)
{
	npf_session_t *se = sf->sf_data;
	unsigned int if_index = (uintptr_t) data;

	if (!(se->s_flags & SE_IF_DISABLED) && se->s_if_idx == if_index) {
		se->s_flags |= SE_IF_DISABLED;
		npf_session_expire(se);
	}

	return 0;
}

static int npf_session_disassoc_nif_cb(struct session *s, void *data)
{
	return session_feature_walk_session(s, SESSION_FEATURE_NPF,
		npf_session_disassoc_nif_feat_cb, data);
}

void npf_session_disassoc_nif(unsigned int if_index)
{
	session_table_walk(npf_session_disassoc_nif_cb,
			   (void *)(uintptr_t)if_index);
}

/*
 * Destroy a session.  Free various attachments and the handle itself.
 */
void npf_session_destroy(npf_session_t *se)
{
	/* Ensure we change to the expired state */
	if (!(se->s_flags & SE_EXPIRE))
		npf_session_expire(se);

	/* Decrement per-interface count if activated and still valid */
	if ((se->s_flags & (SE_IF_DISABLED|SE_ACTIVE)) == SE_ACTIVE) {
		struct ifnet *ifp = dp_ifnet_byifindex(se->s_if_idx);

		if (ifp)
			npf_if_session_dec(ifp);
	}

	/* Tell an alg that its session is being destroyed */
	npf_alg_session_destroy(se, se->s_alg);

	/* Release the fw rule, if any */
	npf_rule_put(se->s_fw_rule);

	/* Release the session rproc rule, if any */
	npf_rule_put(se->s_rproc_rule);

	/* Release any NAT related structures. */
	if (se->s_nat)
		npf_nat_expire(se->s_nat, se->s_vrfid);

	/* Release any NAT64 related structures. */
	if (npf_session_is_nat64(se))
		npf_nat64_session_destroy(se);

	/* Destroy the state. */
	npf_state_destroy(&se->s_state, se->s_proto_idx);

	dpi_session_flow_destroy(se->s_dpi);
	free(se->s_alg);
	free(se);
}

/* Get vrfid */
vrfid_t npf_session_get_vrfid(npf_session_t *se)
{
	if (se)
		return se->s_vrfid;
	return VRF_INVALID_ID;
}

/* Get nat */
npf_nat_t *npf_session_get_nat(const npf_session_t *se)
{
	if (se)
		return se->s_nat;
	return NULL;
}

void npf_session_set_dp_session(npf_session_t *se, struct session *s)
{
	se->s_session = s;
}

struct session *npf_session_get_dp_session(npf_session_t *se)
{
	return se->s_session;
}

int
npf_session_sentry_extract(npf_session_t *se, uint32_t *if_index, int *af,
			   npf_addr_t **src, uint16_t *sid,
			   npf_addr_t **dst, uint16_t *did)
{
	struct sentry *sen;
	const void **saddr = (const void **)src;
	const void **daddr = (const void **)dst;

	sen = rcu_dereference(se->s_session->se_sen);
	if (!sen)
		return -ENOENT;

	session_sentry_extract(sen, if_index, af, saddr, sid, daddr, did);
	return 0;
}

/* Associate NAT entry with the session */
void
npf_session_setnat(npf_session_t *se, npf_nat_t *nt, bool pinhole)
{
	/* set the nat */
	se->s_nat = nt;
	if (pinhole)
		se->s_flags |= SE_NAT_PINHOLE;
}

/*
 * The function hooked here gets to see each packet in a session within
 * npf_session_inspect().
 */
void npf_session_set_pkt_hook(npf_session_t *se, session_pkt_hook *fn)
{
	se->s_hook = fn;
}

/*
 * The structure attached here will be free'ed after the RCU period
 * just before the session is freed.
 * Do we need a notification callout?
 */
bool npf_session_set_dpi(npf_session_t *se, void *data)
{
	if (!se || se->s_dpi)
		return false;

	uint64_t * const ptr = (uint64_t *)&se->s_dpi;
	uint64_t const new = (uintptr_t)data;
	uint64_t const expected = 0;

	/* Mark this session as containing DPI */
	session_set_app(npf_session_get_dp_session(se));

	if (rte_atomic64_cmpset(ptr, expected, new))
		return true;

	return false;
}

void *npf_session_get_dpi(npf_session_t *se)
{
	return se->s_dpi;
}

static void sess_expire(struct session *s, void *data)
{
	uint32_t *if_index = data;
	npf_session_t *se;

	se = session_feature_get(s, *if_index, SESSION_FEATURE_NPF);
	if (se) {
		sess_clear_parent(se);
		sess_clear_nat64_peer(se);
		sess_close(se);
	}
}

/*
 * npf_session_expire: explicitly mark session as expired.
 */
void npf_session_expire(npf_session_t *se)
{
	if (se) {
		sess_clear_parent(se);
		sess_clear_nat64_peer(se);
		sess_close(se);
		session_link_walk(se->s_session, true, sess_expire,
				&se->s_if_idx);

		/* Send out expiry only if the watch was acked before */
		npf_session_do_watch(se, SESSION_EXPIRE);
	}
}

/*
 * Determine if this this a f/w "pass" session.
 * If so, also pass back the firewall rule for it.
 */
bool
npf_session_is_pass(const npf_session_t *se, npf_rule_t **rl)
{
	if ((se->s_flags & SE_PASS) != 0) {
		if (rl)
			*rl = npf_session_get_fw_rule(se);
		return true;
	}
	return false;
}

/*
 * Determine if this is a NAT session for which the packet direction
 * is granted a f/w pinhole (i.e. a reverse direction flow).
 */
bool
npf_session_is_nat_pinhole(const npf_session_t *se,  int dir)
{
	if (se->s_nat && (se->s_flags & SE_NAT_PINHOLE) &&
	    ((se->s_flags & PFIL_ALL) != dir))
		return true;
	return false;
}

/*
 * npf_session_forward_dir: returns true if this is the forward direction
 * for the session.
 */
bool
npf_session_forward_dir(npf_session_t *se, int di)
{
	return (se->s_flags & PFIL_ALL) == di;
}

/*
 * npf_session_retnat: return associated NAT data entry and indicate
 * whether it is a "forwards" or "backwards" stream.
 */
npf_nat_t *
npf_session_retnat(npf_session_t *se, const int di, bool *forw)
{
	*forw = npf_session_forward_dir(se, di);
	return se->s_nat;
}

void
npf_session_set_nat64(npf_session_t *se, struct npf_nat64 *nat64)
{
	if (se)
		se->s_nat64 = nat64;
}

struct npf_nat64 *
npf_session_get_nat64(npf_session_t *se)
{
	return se ? se->s_nat64 : NULL;
}

/*
 * Is this a nat64 (or nat46) session?
 */
bool npf_session_is_nat64(npf_session_t *se)
{
	return (se && se->s_nat64);
}

/* Clear peer */
static void sess_clear_nat64_peer(npf_session_t *se)
{
	if (npf_session_is_nat64(se))
		npf_nat64_session_unlink(se);
}

int
npf_enable_session_log(const char *proto, const char *state)
{
	uint8_t state_index = 0;
	enum npf_proto_idx proto_idx;

	if (!proto || !state)
		return -1;

	proto_idx = npf_proto_idx_from_str(proto);
	if (proto_idx == NPF_PROTO_IDX_NONE)
		return -1;

	/* timeout state no longer used so ignore request to enable log */
	if (strcmp(state, "timeout") == 0)
		return 0;

	if (proto_idx == NPF_PROTO_IDX_TCP) {
		state_index = npf_map_str_to_tcp_state(state);
		if (state_index == NPF_TCPS_NONE)
			return -1;
	} else {
		state_index = dp_session_name2state(state);
		if (state_index == SESSION_STATE_NONE)
			return -1;
	}
	NPF_SET_SESSION_LOG_FLAG(proto_idx, state_index);

	return 0;
}

int
npf_disable_session_log(const char *proto, const char *state)
{
	uint8_t state_index = 0;
	enum npf_proto_idx proto_idx;

	if (!proto || !state)
		return -1;

	proto_idx = npf_proto_idx_from_str(proto);
	if (proto_idx == NPF_PROTO_IDX_NONE)
		return -1;

	/* timeout state no longer used so ignore request to disable log */
	if (strcmp(state, "timeout") == 0)
		return 0;

	if (proto_idx == NPF_PROTO_IDX_TCP) {
		state_index = npf_map_str_to_tcp_state(state);
		if (state_index == NPF_TCPS_NONE)
			return -1;
	} else {
		state_index = dp_session_name2state(state);
		if (state_index == SESSION_STATE_NONE)
			return -1;
	}
	NPF_CLR_SESSION_LOG_FLAG(proto_idx, state_index);

	return 0;
}

static void npf_session_json_rule(json_writer_t *json, npf_rule_t *rl)
{
	if (!rl)
		return;

	const char *name = npf_rule_get_name(rl);
	rule_no_t num = npf_rule_get_num(rl);

	jsonw_name(json, "rule");
	jsonw_start_object(json);

	jsonw_string_field(json, "name", name ? name : "<UNKNOWN>");
	jsonw_uint_field(json, "number", num);

	jsonw_end_object(json);
}

static void npf_session_json_nat(json_writer_t *json, npf_session_t *se)
{
	npf_addr_t taddr;
	uint16_t tport;
	int type;
	u_int masq = 0;
	char buf[INET_ADDRSTRLEN];
	npf_nat_t *nt = se->s_nat;

	if (!nt || !npf_nat_info(nt, &type, &taddr, &tport, &masq))
		return;

	jsonw_name(json, "nat");
	jsonw_start_object(json);

	jsonw_uint_field(json, "trans_type", type);
	jsonw_string_field(json, "trans_addr",
			inet_ntop(AF_INET, &taddr, buf, sizeof(buf)));
	jsonw_uint_field(json, "trans_port", ntohs(tport));
	jsonw_uint_field(json, "masquerade", masq);

	npf_session_json_rule(json, npf_nat_get_rule(nt));

	jsonw_end_object(json);
}

static void npf_session_json_fw(json_writer_t *json, npf_session_t *se)
{
	npf_rule_t *rl = npf_session_get_fw_rule(se);

	if (!rl)
		return;

	jsonw_name(json, "firewall");
	jsonw_start_object(json);

	npf_session_json_rule(json, rl);

	jsonw_end_object(json);
}

void npf_session_feature_json(json_writer_t *json, npf_session_t *se)
{
	struct ifnet *ifp = dp_ifnet_byifindex(se->s_if_idx);

	if (ifp)
		jsonw_string_field(json, "interface", ifp->if_name);
	else
		jsonw_string_field(json, "interface", "unkn");

	jsonw_uint_field(json, "flags", se->s_flags);

	/* Firewall json */
	if (npf_session_is_fw(se))
		npf_session_json_fw(json, se);

	/* NAT json */
	if (se->s_nat)
		npf_session_json_nat(json, se);

	/* NAT64 json */
	if (npf_session_is_nat64(se))
		npf_nat64_session_json(json, se);

	/* DPI json */
	if (se->s_dpi)
		dpi_info_json(se->s_dpi, json);

	/* ALG json */
	if (se->s_alg)
		npf_alg_session_json(json, se, se->s_alg);
}

int npf_session_feature_nat_info(npf_session_t *se, uint32_t *taddr,
				 uint16_t *tport)
{
	npf_nat_t *nt = se->s_nat;
	npf_addr_t npf_taddr;
	int type;
	uint masq = 0;

	if (!nt)
		return -EINVAL;

	if (!npf_nat_info(nt, &type, &npf_taddr, tport, &masq))
		return -EINVAL;

	*taddr = npf_taddr.s6_addr32[0];
	return 0;
}

static inline const char *npf_session_log_event(
	enum session_log_event event)
{
	switch (event) {
	case SESSION_LOG_CREATION:
		return "SESSION_CREATE";
	case SESSION_LOG_DELETION:
		return "SESSION_DELETE";
	case SESSION_LOG_PERIODIC:
		return "SESSION_ACTIVE";
	default:
		return "SESSION";
	}
}

/* size of buffer to store the log message */
#define LOGBUF_SIZE	1024

static inline const char *
npf_get_protocol_name_from_num(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_SCTP:
		return "sctp";
	case IPPROTO_DCCP:
		return "dccp";
	case IPPROTO_UDPLITE:
		return "udplite";
	case IPPROTO_ICMP:
		return "icmp";
	case IPPROTO_ICMPV6:
		return "icmpv6";
	default:
		return "other";
	}
}

static inline void
npf_session_log_duration(char *buf, size_t *used_buf_len,
			 const size_t total_buf_len,
			 uint64_t create_time, uint64_t expire_time)
{
	uint64_t duration = (expire_time ? expire_time :
			     rte_get_timer_cycles()) - create_time;
	uint64_t duration_s = duration / rte_get_timer_hz();
	uint64_t duration_ms = ((duration * 1000) / rte_get_timer_hz()) % 1000;

	buf_app_printf(buf, used_buf_len, total_buf_len,
		       " duration=%lu.%03lu", duration_s, duration_ms);
}

static inline void
npf_session_log_addrs(char *buf, size_t *used_buf_len,
		      const size_t total_buf_len, int af, const void *saddr,
		      const void *daddr)
{
	char srcip_str[INET6_ADDRSTRLEN];
	char dstip_str[INET6_ADDRSTRLEN];

	inet_ntop(af, saddr, srcip_str, sizeof(srcip_str));
	inet_ntop(af, daddr, dstip_str, sizeof(dstip_str));

	buf_app_printf(buf, used_buf_len, total_buf_len,
		       " addr=%s->%s", srcip_str, dstip_str);
}

static inline void
npf_session_log_ports_or_echo_id(char *buf, size_t *used_buf_len,
				 const size_t total_buf_len,
				 uint8_t proto, uint16_t sid, uint16_t did)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
	case IPPROTO_UDPLITE:
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       " port=%u->%u", ntohs(sid), ntohs(did));
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       " icmp-id=%u", ntohs(sid));
		break;
	default:
		break;
	}
}

static inline void
npf_session_log_parent_id(char *buf, size_t *used_buf_len,
			  const size_t total_buf_len, struct session *s)
{
	/* Get parent id info */
	if (s->se_link && s->se_link->sl_parent)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       " parent-id=%lu", s->se_link->sl_parent->se_id);
}

static inline void
npf_session_log_counters(char *buf, size_t *used_buf_len,
			 const size_t total_buf_len,
			 struct session *s __unused,
			 enum session_log_event event)
{
	/* Only emit this for deletion and periodic events,
	 * and specifically not for creation events.
	 */
	if (event == SESSION_LOG_DELETION ||
	    event == SESSION_LOG_PERIODIC) {
		buf_app_printf(buf, used_buf_len, total_buf_len,
		       " out=%lu/%lu in=%lu/%lu",
		       rte_atomic64_read(&s->se_pkts_out),
		       rte_atomic64_read(&s->se_bytes_out),
		       rte_atomic64_read(&s->se_pkts_in),
		       rte_atomic64_read(&s->se_bytes_in));
	}
}

static inline void
npf_session_log_rule_info(char *buf, size_t *used_buf_len,
			  const size_t total_buf_len, npf_session_t *se)
{
	npf_rule_t *rl = npf_session_get_fw_rule(se);
	if (rl) {
		const char *gr_name = npf_rule_get_name(rl);
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       " fw-rule=%s:%u",
			       gr_name ? gr_name : "<UNKNOWN>",
			       npf_rule_get_num(rl));
	}
}

static inline void
npf_session_log_dnat_snat_info(char *buf, size_t *used_buf_len,
			       const size_t total_buf_len, npf_nat_t *npf_nat,
			       uint8_t proto)
{
	if (npf_nat) {
		npf_addr_t taddr;
		uint16_t tport;
		int type;
		u_int masq = 0;

		if (npf_nat_info(npf_nat, &type, &taddr, &tport, &masq)) {
			char taddr_str[INET_ADDRSTRLEN];
			const char *type_str;

			inet_ntop(AF_INET, &taddr, taddr_str,
				  sizeof(taddr_str));

			if (type == NPF_NATOUT)
				type_str = "snat";
			else if (type == NPF_NATIN)
				type_str = "dnat";
			else
				type_str = "unknown-nat";

			buf_app_printf(buf, used_buf_len, total_buf_len,
				       " %s-addr=%s", type_str, taddr_str);

			if (npf_nat_get_map_flags(npf_nat) & NPF_NAT_MAP_PORT) {
				if (proto == IPPROTO_ICMP ||
				    proto == IPPROTO_ICMPV6)
					buf_app_printf(buf, used_buf_len,
						       total_buf_len,
						       " %s-icmp-id=%u",
							type_str, ntohs(tport));
				else
					buf_app_printf(buf, used_buf_len,
						       total_buf_len,
						       " %s-port=%u", type_str,
							ntohs(tport));
			}
		}
	}
}

static inline void
npf_session_log_nat64_info(char *buf, size_t *used_buf_len,
			   const size_t total_buf_len,
			   struct npf_nat64 *nat64)
{
	if (nat64) {
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       " nat64");
	}
}

static inline void
npf_session_log_alg_info(char *buf, size_t *used_buf_len,
			 const size_t total_buf_len, npf_session_t *se)
{
	const char *alg_name = npf_alg_name(se);
	if (alg_name)
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       " alg=%s", alg_name);
}

static inline void
npf_session_log_dpi_info(char *buf, size_t *used_buf_len,
			 const size_t total_buf_len, void *dpi_info)
{
	if (dpi_info) {
		char dpi_str[MAX_DPI_LOG_SIZE];
		dpi_info_log(dpi_info, dpi_str, MAX_DPI_LOG_SIZE);
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       " %s", dpi_str);
	}
}

void npf_session_feature_log(enum session_log_event event, struct session *s,
			     struct session_feature *sf)
{
	struct sentry *sen = rcu_dereference(s->se_sen);
	npf_session_t *se = sf->sf_data;
	char buf[LOGBUF_SIZE];
	size_t used_buf_len = 0;
	uint32_t if_index;
	int af;
	const void *saddr, *daddr;
	uint16_t sid, did;

	if (!sen)
		return;

	buf_app_printf(buf, &used_buf_len, sizeof(buf),
		       "%s", npf_session_log_event(event));

	npf_session_log_duration(buf, &used_buf_len, sizeof(buf),
				 s->se_create_time, sf->sf_expire_time);

	session_sentry_extract(sen, &if_index, &af, &saddr, &sid, &daddr, &did);

	buf_app_printf(buf, &used_buf_len, sizeof(buf),
		       " ifname=%s session-id=%lu proto=%s(%u) dir=%s",
		       ifnet_indextoname_safe(if_index), s->se_id,
		       npf_get_protocol_name_from_num(s->se_protocol),
		       s->se_protocol,
		       npf_session_forward_dir(se, PFIL_IN) ? "in" : "out");

	npf_session_log_addrs(buf, &used_buf_len, sizeof(buf), af,
			      saddr, daddr);

	npf_session_log_ports_or_echo_id(buf, &used_buf_len, sizeof(buf),
					 s->se_protocol, sid, did);

	npf_session_log_parent_id(buf, &used_buf_len, sizeof(buf), s);

	npf_session_log_counters(buf, &used_buf_len, sizeof(buf), s, event);

	npf_session_log_rule_info(buf, &used_buf_len, sizeof(buf), se);

	npf_session_log_dnat_snat_info(buf, &used_buf_len, sizeof(buf),
				       se->s_nat, s->se_protocol);

	npf_session_log_nat64_info(buf, &used_buf_len, sizeof(buf),
				   se->s_nat64);

	npf_session_log_alg_info(buf, &used_buf_len, sizeof(buf), se);

	npf_session_log_dpi_info(buf, &used_buf_len, sizeof(buf), se->s_dpi);

	RTE_LOG(NOTICE, FIREWALL, "%s\n", buf);
}

void npf_save_stats(npf_session_t *se, int dir, uint64_t bytes)
{
	assert(se);

	if (se->s_session) {
		se_save_stats(se->s_session,
			      dir == PFIL_IN ? true : false,
			      bytes);
		npf_session_do_watch(se, SESSION_STATS_UPDATE);
	}
}

/*
 * Pack session state for protocols other than TCP
 */
int npf_session_pack_state_pack_gen(struct npf_session *se,
				    struct npf_pack_session_state *pst)
{
	npf_state_t *nst;

	if (!se || !pst)
		return -EINVAL;

	nst = &se->s_state;

	pst->pst_state = nst->nst_state;

	return 0;
}

/*
 * Pack session state for TCP
 */
int npf_session_pack_state_pack_tcp(struct npf_session *se,
				    struct npf_pack_session_state *pst)
{
	npf_state_t *nst;
	enum npf_flow_dir fl;

	if (!se || !pst)
		return -EINVAL;

	nst = &se->s_state;

	for (fl = NPF_FLOW_FIRST; fl <= NPF_FLOW_LAST; fl++)
		memcpy(&pst->pst_tcp_win[fl], &nst->nst_tcp_win[fl],
		       sizeof(*pst->pst_tcp_win));

	pst->pst_state = nst->nst_tcp_state;

	return 0;
}

/*
 * Restore session state for protocols other than TCP
 */
static int
npf_session_pack_state_restore_gen(struct npf_session *se,
				   struct npf_pack_session_state *pst,
				   vrfid_t vrfid,
				   enum npf_proto_idx proto_idx)
{
	npf_state_t *nst;
	bool state_changed = false;
	int rc;

	nst = &se->s_state;
	npf_state_init(vrfid, proto_idx, nst);

	rc = npf_state_npf_pack_update_gen(nst, pst->pst_state, proto_idx,
					   &state_changed);
	return rc;
}

/*
 * Restore session state for TCP
 */
static int
npf_session_pack_state_restore_tcp(struct npf_session *se,
				   struct npf_pack_session_state *pst,
				   vrfid_t vrfid)
{
	npf_state_t *nst;
	bool state_changed = false;
	int rc;

	nst = &se->s_state;
	npf_state_init(vrfid, NPF_PROTO_IDX_TCP, nst);

	rc = npf_state_npf_pack_update_tcp(nst, pst, &state_changed);
	return rc;
}

/*
 * State update for protocols other than TCP
 */
int npf_session_pack_state_update_gen(struct npf_session *se,
				      struct npf_pack_session_state *pst)
{
	npf_state_t *nst;
	uint8_t old_state;
	struct session *s;
	enum npf_proto_idx proto_idx;
	bool state_changed = false;

	if (!se || !pst)
		return -EINVAL;

	nst = &se->s_state;
	proto_idx = se->s_proto_idx;
	old_state = nst->nst_state;

	if (npf_state_npf_pack_update_gen(nst, pst->pst_state, proto_idx,
					  &state_changed))
		return -EINVAL;

	if (state_changed)
		npf_session_gen_state_change(nst, old_state, pst->pst_state,
					     proto_idx);

	s = se->s_session;
	if (s)
		s->se_etime = get_dp_uptime() +
				  session_get_npf_pack_timeout(s);

	return 0;
}

/*
 * State update for TCP
 */
int npf_session_pack_state_update_tcp(struct npf_session *se,
				      struct npf_pack_session_state *pst)
{
	npf_state_t *nst;
	uint8_t old_state;
	struct session *s;
	bool state_changed = false;

	if (!se || !pst)
		return -EINVAL;

	nst = &se->s_state;
	old_state = nst->nst_tcp_state;

	if (npf_state_npf_pack_update_tcp(nst, pst, &state_changed))
		return -EINVAL;

	if (state_changed)
		npf_session_tcp_state_change(nst, old_state, pst->pst_state);

	s = se->s_session;
	if (s)
		s->se_etime = get_dp_uptime() +
				  session_get_npf_pack_timeout(s);

	return 0;
}

int npf_session_npf_pack_pack(npf_session_t *se,
			      struct npf_pack_npf_session *pns,
			      struct npf_pack_session_state *pst)
{
	npf_rule_t *rule;
	int rc;

	if (!se || !pns)
		return -EINVAL;

	pns->pns_flags = se->s_flags;
	rule = npf_session_get_fw_rule(se);
	pns->pns_fw_rule_hash = (rule ? npf_rule_get_hash(rule) : 0);
	rule = npf_session_get_rproc_rule(se);
	pns->pns_rproc_rule_hash = (rule ? npf_rule_get_hash(rule) : 0);

	if (se->s_proto_idx == NPF_PROTO_IDX_TCP)
		rc = npf_session_pack_state_pack_tcp(se, pst);
	else
		rc = npf_session_pack_state_pack_gen(se, pst);

	return rc;
}

struct npf_session *
npf_session_npf_pack_restore(struct npf_pack_npf_session *pns,
			     struct npf_pack_session_state *pst,
			     vrfid_t vrfid, uint8_t protocol,
			     uint32_t ifindex)
{
	npf_rule_t *fw_rl;
	npf_rule_t *rproc_rl;
	npf_session_t *se;
	int rc;

	if (!pns || !pst)
		return NULL;

	se = zmalloc_aligned(sizeof(*se));
	if (!se)
		return NULL;

	fw_rl = pns->pns_fw_rule_hash ?
			npf_get_rule_by_hash(pns->pns_fw_rule_hash) : NULL;
	if (fw_rl)
		npf_session_add_fw_rule(se, fw_rl);

	rproc_rl = pns->pns_rproc_rule_hash ?
		npf_get_rule_by_hash(pns->pns_rproc_rule_hash) : NULL;
	if (rproc_rl)
		npf_session_add_rproc_rule(se, rproc_rl);

	se->s_flags = pns->pns_flags;
	se->s_vrfid = vrfid;
	se->s_if_idx = ifindex;
	se->s_proto = protocol;
	se->s_proto_idx = npf_proto_idx_from_proto(protocol);

	if (se->s_proto_idx == NPF_PROTO_IDX_TCP)
		rc = npf_session_pack_state_restore_tcp(se, pst, vrfid);
	else
		rc = npf_session_pack_state_restore_gen(se, pst, vrfid,
							se->s_proto_idx);

	if (rc)
		goto error;

	rte_spinlock_init(&se->s_state.nst_lock);

	return se;

error:
	if (fw_rl)
		npf_rule_put(fw_rl);
	if (rproc_rl)
		npf_rule_put(rproc_rl);
	free(se);
	return NULL;
}

int npf_session_npf_pack_activate(struct npf_session *se, struct ifnet *ifp)
{
	if (!se || !ifp)
		return -EINVAL;

	npf_if_session_inc(ifp);
	se->s_flags |= SE_ACTIVE;
	return 0;
}
