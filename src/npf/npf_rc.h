/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _NPF_RC_H_
#define _NPF_RC_H_

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <rte_atomic.h>

#include "if_var.h"
#include "npf/npf_if.h"
#include "npf/npf.h"

/*
 * npf return codes
 *
 * The return code counter is effectively a multi-dimensional array of 64-bit
 * counters arranged as follows:
 *
 *    cpu-core[].type[].direction[].counter[]
 *
 * 'cpu-core' is at the outer level as it is the only dynamic element.
 *
 * 'type' is either IPv4 or IPv6 for npf_hook_track
 *
 * 'direction' is inbound or outbound.
 */

/*
 * Return code type.
 *
 * NPF_RCT_FW4 and NPF_RCT_FW6 are used for npf_hook_track IPv4 and IPv6.  We
 * may want to add further entries here for npf_hook_notrack at some point,
 * but that is somewhat more complicated.
 */
enum npf_rc_type {
	NPF_RCT_FW4 = 0,
	NPF_RCT_FW6,
	NPF_RCT_L2,
	NPF_RCT_NAT64,
};
#define NPF_RCT_LAST	NPF_RCT_NAT64
#define NPF_RCT_SZ	(NPF_RCT_LAST + 1)
#define NPF_RCT_ALL	NPF_RCT_SZ

#define RCT2BIT(_rct) (1 << (_rct))

#define	RCT_BIT_FW4	RCT2BIT(NPF_RCT_FW4)
#define	RCT_BIT_FW6	RCT2BIT(NPF_RCT_FW6)
#define	RCT_BIT_L2	RCT2BIT(NPF_RCT_L2)
#define	RCT_BIT_NAT64	RCT2BIT(NPF_RCT_NAT64)
#define	RCT_BIT_ALL	(RCT_BIT_FW4 | RCT_BIT_FW6 | RCT_BIT_L2 | RCT_BIT_NAT64)

/* Eth type to rc type.  For npf_hook_Track only */
#define ETH2RCT(_et) (((_et) == htons(RTE_ETHER_TYPE_IPV4)) ? \
		      NPF_RCT_FW4 : NPF_RCT_FW6)


static inline const char *npf_rct_str(enum npf_rc_type rct)
{
	switch (rct) {
	case NPF_RCT_FW4:
		return "ip";
	case NPF_RCT_FW6:
		return "ip6";
	case NPF_RCT_L2:
		return "l2";
	case NPF_RCT_NAT64:
		return "nat64";
	}
	return "Unkn";
}

static inline enum npf_rc_type npf_rct_str2enum(const char *rct_str)
{
	enum npf_rc_type rct;

	for (rct = 0; rct < NPF_RCT_SZ; rct++)
		if (!strcmp(rct_str, npf_rct_str(rct)))
			return rct;

	return NPF_RCT_ALL;
}

/*
 * We keep inbound and outbound rc counts
 */
enum npf_rc_dir {
	NPF_RC_IN = 0,
	NPF_RC_OUT = 1
};
#define NPF_DIR_SZ 2
#define NPF_DIR_ALL NPF_DIR_SZ

/* Converts PFIL_IN or PFIL_OUT to 'enum npf_rc_dir' */
#define PFIL2RC(_dir) ((_dir) >> 1)

static inline const char *npf_rc_dir_str(enum npf_rc_dir dir)
{
	return (dir == NPF_RC_IN) ? "in" : "out";
}

/*
 * Return codes
 *
 * Default return code is NPF_RC_UNMATCHED.  This indicates that a node saw
 * the packet, but the node had no effect on the packet disposition.
 *
 * The convention is to negate a return code if its an error or drop reason.
 * So for example, a function might set "rc = -NPF_RC_INTL" if an internal
 * error is detected.  NPF_RC_PASS and NPF_RC_BLOCK are not errors or drops,
 * so they would not be negated (we differentiate 'blocks' from 'drops').
 */
enum npf_rc_en {
	NPF_RC_UNMATCHED = 0,
	NPF_RC_PASS,	/* Matched session or pass rule, or no ruleset */
	NPF_RC_BLOCK,	/* Explicit or implicit block */

	/* Not enough L3 hdr present in pkt */
	NPF_RC_L3_SHORT,

	/* Not enough L4 hdr present in pkt or icmp err embd pkt */
	NPF_RC_L4_SHORT,

	/* L3 protocol value does not match pkt addr family */
	NPF_RC_L3_PROTO,

	/*
	 * If a ping session does not exist, it can only be created by an ICMP
	 * echo request. If it exists, the fwd direction will conditionally
	 * ('strict' enabled) only pass requests and the backward only
	 * replies.  Note, the 'strict' bit needs to be disabled because of MS
	 * Windows clients.  NPF_RC_ICMP_ECHO rc occurs when an ICMP echo
	 * fails to meet these conditions, and is dropped.
	 */
	NPF_RC_ICMP_ECHO,

	/*
	 * TCP RST pkt not permitted to create a session. This is handled
	 * differently from other 'error' return codes.  A session is not
	 * created, but the packet is allowed to pass.
	 */
	NPF_RC_ENOSTR,

	/* Only a TCP SYN may create a session (strict) */
	NPF_RC_TCP_SYN,

	/* Invalid state transition (strict) */
	NPF_RC_TCP_STATE,

	/* TCP window error */
	NPF_RC_TCP_WIN,

	/* Failed to allocate session */
	NPF_RC_SESS_ENOMEM,

	/* Session limiter */
	NPF_RC_SESS_LIMIT,

	/* Unspecified session hook dropped pkt */
	NPF_RC_SESS_HOOK,

	/* Dataplane session create failed */
	NPF_RC_DP_SESS_ESTB,

	/* New mbuf failed to be allocated */
	NPF_RC_MBUF_ENOMEM,

	/* No translation ports available */
	NPF_RC_NAT_ENOSPC,

	/* Failed to allocate a nat struct or port map */
	NPF_RC_NAT_ENOMEM,

	/* Fragmented NAT port mappings */
	NPF_RC_NAT_EADDRINUSE,

	/* NAT port range too small */
	NPF_RC_NAT_ERANGE,

	/* Pkt exceeds intf MTU and is marked DF */
	NPF_RC_NAT_E2BIG,

	/* Failed to translate pkt embedded in ICMP error */
	NPF_RC_ICMP_ERR_NAT,

	/* ALG tuple match race lost */
	NPF_RC_ALG_EEXIST,

	/* Unspecified ALG error */
	NPF_RC_ALG_ERR,

	NPF_RC_INTL,	/* Internal error */
};
#define NPF_RC_LAST	NPF_RC_INTL
#define NPF_RC_SZ	(NPF_RC_LAST + 1)

static inline enum npf_rc_en
npf_decision2rc(npf_decision_t decision)
{
	switch (decision) {
	case NPF_DECISION_UNMATCHED:
		return NPF_RC_UNMATCHED;
	case NPF_DECISION_PASS:
		return NPF_RC_PASS;
	case NPF_DECISION_BLOCK:
	case NPF_DECISION_BLOCK_UNACCOUNTED:
		return NPF_RC_BLOCK;
	case NPF_DECISION_UNKNOWN:
		return NPF_RC_INTL;
	}
	return NPF_RC_INTL;
}

/*
 * Per-core return code counters
 */
struct npf_rc_counts {
	struct _af {
		struct _dir {
			uint64_t count[NPF_RC_SZ];
		} dir[NPF_DIR_SZ];
	} type[NPF_RCT_SZ];
};

/*
 * Increment a return code counter
 */
static ALWAYS_INLINE void
npf_rc_inc(struct ifnet *ifp, enum npf_rc_type rct, enum npf_rc_dir dir, int rc,
	   npf_decision_t decision)
{
	assert(dir == NPF_RC_IN || dir == NPF_RC_OUT);

	if (likely(rc < 0))
		rc = -rc;
	if (unlikely(rc > NPF_RC_LAST))
		rc = NPF_RC_INTL;

	/* Change return code if it is not already set */
	if (rc == NPF_RC_UNMATCHED && decision != NPF_DECISION_UNMATCHED)
		rc = npf_decision2rc(decision);

	struct npf_rc_counts *rcc = npf_if_get_rcc(ifp);
	if (unlikely(!rcc))
		return;

	rcc[dp_lcore_id()].type[rct].dir[dir].count[rc]++;
}

/*
 * Create return code counters
 */
struct npf_rc_counts *npf_rc_counts_create(void);

void npf_rc_counts_destroy(struct npf_rc_counts **rcc);

/*
 * Return code short string and description
 */
const char *npf_rc_str(int rc);
const char *npf_rc_detail_str(int rc);

/*
 * Show/clear return code counters
 */
int npf_show_rc_counts(FILE *f, int argc, char **argv);
int npf_clear_rc_counts(FILE *f, int argc, char **argv);

#endif	/* _NPF_RC_H_ */
