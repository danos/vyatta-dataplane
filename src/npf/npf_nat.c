/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf_nat.c,v 1.17 2012/08/15 18:44:56 rmind Exp $	*/

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
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
/*
 * NPF network address port translation (NAPT).
 * Described in RFC 2663, RFC 3022.  Commonly just "NAT".
 *
 * Overview
 *
 *	There are few mechanisms: NAT policy, port map and translation.
 *	NAT module has a separate ruleset, where rules contain associated
 *	NAT policy, thus flexible filter criteria can be used.
 *
 * Translation types
 *
 *	There are two types of translation: outbound (NPF_NATOUT) and
 *	inbound (NPF_NATIN).  It should not be confused with connection
 *	direction.
 *
 *	Outbound NAT rewrites:
 *	- Source on "forwards" stream.
 *	- Destination on "backwards" stream.
 *	Inbound NAT rewrites:
 *	- Destination on "forwards" stream.
 *	- Source on "backwards" stream.
 *
 *	It should be noted that bi-directional NAT is a combined outbound
 *	and inbound translation, therefore constructed as two policies.
 *
 * NAT policies and port maps
 *
 *	NAT (translation) policy is applied when a packet matches the rule.
 *	Apart from filter criteria, NAT policy has a translation IP address
 *	and associated port map.  Port map is a bitmap used to reserve and
 *	use unique TCP/UDP ports for translation.  Port maps are unique to
 *	the IP addresses, therefore multiple NAT policies with the same IP
 *	will share the same port map.
 *
 * Sessions, translation entries and their life-cycle
 *
 *	NAT module relies on session management module.  Each translated
 *	session has an associated translation entry (npf_nat_t), which
 *	contains information used for backwards stream translation, i.e.
 *	original IP address with port and translation port, allocated from
 *	the port map.  Each NAT entry is associated with the policy, which
 *	contains translation IP address.  Allocated port is returned to the
 *	port map and NAT entry is destroyed when session expires.
 */
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "compiler.h"
#include "config_internal.h"
#include "in_cksum.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "npf/npf.h"
#include "npf/alg/alg_npf.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_apm.h"
#include "npf/npf_cache.h"
#include "npf/npf_icmp.h"
#include "npf/npf_mbuf.h"
#include "npf/npf_nat.h"
#include "npf/npf_ruleset.h"
#include "npf/rproc/npf_ext_log.h"
#include "npf/npf_pack.h"
#include "npf_tblset.h"
#include "npf_addr.h"
#include "pktmbuf_internal.h"
#include "urcu.h"
#include "vplane_log.h"

struct npf_session;

/*
 * NAT policy structure.
 */
struct npf_natpolicy {
	struct rcu_head	n_rcu_head;
	npf_apm_t	*n_apm;
	rte_atomic32_t	n_refcnt;
	npf_addr_t	n_taddr;
	npf_addr_t	n_taddr_stop; /* for addr range */
	in_port_t	n_tport;      /* in host order */
	in_port_t	n_tport_stop; /* in host order, end port */
	uint32_t	n_flags;
	uint32_t	n_match_mask;
	uint8_t		n_type;
	uint8_t		n_addr_sz;
	uint32_t	n_table_id;
};

/* For strerror_r */
#define ERR_MSG_LEN     64

/*
 * Structs/etc for TCP sequence/ack adjustments.
 *
 * May be referenced during nat operations for adjusting seq/ack numbers
 * for natted protocol payloads
 */
struct npf_seq_ack_diff {
	uint32_t sad_position;/* Position of last modification */
	int16_t sad_before;   /* Offset before and after last modification */
	int16_t sad_after;
};

struct npf_seq_ack {
	struct npf_seq_ack_diff sa_diffs[2];
};

struct npf_tcp_sack {
	uint32_t        start_seq;
	uint32_t        end_seq;
};


/*
 * NAT translation entry for a session.
 */
struct npf_nat {
	uint16_t		nt_l3_chk;
	uint16_t		nt_l4_chk;	/* 0x0000 if no L4 update */
	uint32_t		nt_map_flags;	/* flags for mapping */
	npf_rule_t		*nt_rl;
	const struct npf_alg	*nt_alg;
	npf_session_t		*nt_session;
	npf_natpolicy_t		*nt_natpolicy;
	struct npf_seq_ack	*nt_sa;
	uint32_t		nt_taddr;
	uint32_t		nt_oaddr;
	uint16_t		nt_tport;
	uint16_t		nt_oport;
	uint16_t		nt_mtu;		/* kludge for dnat+snat */
};

/* Helpers for seq/ack usage */
static inline bool before(uint32_t n1, uint32_t n2)
{
	return (((int32_t) (n1 - n2)) < 0 ? true : false);
}
#define after(n2, n1) before(n1, n2)
#define direction_index(a)  (a == PFIL_IN ? 0 : 1)

#define TCP_SACK_PERBLOCK 8

/*
 * npf_nat_policy_get() - Get a ref to a nat policy
 */
npf_natpolicy_t *npf_nat_policy_get(npf_natpolicy_t *np)
{
	rte_atomic32_inc(&np->n_refcnt);
	return np;
}

/*
 * Free the nat policy.
 * Called from both a call_rcu thread context as well
 * as from the main thread.
 */
static void npf_nat_policy_free(struct rcu_head *head)
{
	npf_natpolicy_t *np = caa_container_of(head, struct npf_natpolicy,
			n_rcu_head);

	npf_apm_destroy(np->n_apm);
	free(np);
}

/*
 * npf_nat_policy_put() - Release ref to nat policy
 */
void npf_nat_policy_put(npf_natpolicy_t *np)
{
	if (rte_atomic32_dec_and_test(&np->n_refcnt))
		npf_nat_policy_free(&np->n_rcu_head);
}

/*
 * npf_nat_policy_put_rcu() - Release ref to nat policy
 *
 * called during a nat masquerade address change.
 *
 * This is for nat policies with no references to them. Otherwise
 * its variant above will be called.
 */
static void npf_nat_policy_put_rcu(npf_natpolicy_t *np)
{
	if (rte_atomic32_dec_and_test(&np->n_refcnt))
		call_rcu(&np->n_rcu_head, npf_nat_policy_free);
}

static void npf_update_sack(npf_cache_t *npc, struct rte_mbuf *nbuf,
			    struct npf_tcp_sack *sack,
			    struct npf_seq_ack_diff *sd)
{

	uint32_t start;
	uint32_t end;
	uint32_t orig_start = sack->start_seq;
	uint32_t orig_end = sack->end_seq;

	if (after(ntohl(sack->start_seq) - sd->sad_before, sd->sad_position))
		start = htonl(ntohl(sack->start_seq) - sd->sad_after);
	else
		start = htonl(ntohl(sack->start_seq) - sd->sad_before);

	if (after(ntohl(sack->end_seq) - sd->sad_before, sd->sad_position))
		end = htonl(ntohl(sack->end_seq) - sd->sad_after);
	else
		end = htonl(ntohl(sack->end_seq) - sd->sad_before);

	sack->start_seq = htonl(start);
	sack->end_seq = htonl(end);

	/*
	 * Update cksum if needed
	 */
	if (orig_start != sack->start_seq)
		npf_update_tcp_cksum(npc, nbuf, orig_start, sack->start_seq);

	if (orig_end != sack->end_seq)
		npf_update_tcp_cksum(npc, nbuf, orig_end, sack->end_seq);
}

/* Adjust a block of SACK options */
static void npf_nat_adjust_sack(npf_cache_t *npc, struct rte_mbuf *nbuf,
			void *block, int count, struct npf_seq_ack_diff *sd)
{
	struct npf_tcp_sack *sack = (struct npf_tcp_sack *) block;

	while (count) {
		npf_update_sack(npc, nbuf, sack, sd);
		sack++;
		count -= TCP_SACK_PERBLOCK;
	}
}

/* npf_nat_update_sack() - Update the SACK options if any. */
static void npf_nat_update_sack(npf_cache_t *npc, struct rte_mbuf *nbuf,
		struct npf_seq_ack_diff *sd)
{
	/*
	 * Retrieve the TCP options into a buffer,
	 * parse and reset them there.
	 *
	 * We'll need to recalculate a cksum if we modify.
	 */
	struct tcphdr *th = &npc->npc_l4.tcp;
	uint16_t optlen = (th->doff << 2) - sizeof(struct tcphdr);
	char buf[64];
	char *b;

	memset(buf, '\0', sizeof(buf));
	if (!npf_get_tcp_options(npc, nbuf, buf))
		return;

	b = buf;
	while (optlen) {
		switch (*b) {
		case TCPOPT_EOL:
			goto done;
		case TCPOPT_NOP:
			b++;
			optlen--;
			break;
		case TCPOPT_SACK:
			/* Make sure we have the full option */
			if ((optlen <  b[1]) || b[1] < 2)
				goto done;

			/* Deal with the entire block */
			if ((b[1] >= 2 + TCP_SACK_PERBLOCK &&
			     (b[1] - 2) % TCP_SACK_PERBLOCK) == 0)
				npf_nat_adjust_sack(npc, nbuf,
						    &b[2], (b[1]-2), sd);
			optlen -= b[1];
			b += b[1];
			break;
		default:
			optlen -= b[1];
			b += b[1];
			break;
		}
	}
done:
	npf_store_tcp_options(npc, nbuf, buf);
}

/*
 * npf_nat_set_seq_ack() - Save a payload length diff for TCP seq/ack mods
 */
void npf_nat_set_seq_ack(npf_session_t *se, npf_cache_t *npc,
		int16_t diff, int di)
{
	struct npf_seq_ack *s;
	struct npf_seq_ack_diff *sd;
	struct tcphdr *th = &npc->npc_l4.tcp;
	uint32_t seq = ntohl(th->seq);
	npf_nat_t *nt = npf_session_get_nat(se);

	/* Paranoia: Should never happen as always called after nat allocated */
	if (!nt)
		return;

	s = nt->nt_sa;
	if (!s)
		s = calloc(1, sizeof(struct npf_seq_ack));
	if (!s)
		return;

	/* 'Add' the difference in this direction */
	sd = &s->sa_diffs[direction_index(di)];
	if (sd->sad_before == sd->sad_after || before(sd->sad_position, seq)) {
		sd->sad_position = seq;
		sd->sad_before = sd->sad_after;
		sd->sad_after += diff;
	}

	nt->nt_sa = s;
}

static void npf_nat_adjust_seq(npf_cache_t *npc, struct rte_mbuf *nbuf,
		struct npf_seq_ack_diff *sd)
{
	struct tcphdr *th = &npc->npc_l4.tcp;
	uint32_t oseq = ntohl(th->seq);
	uint32_t seq = oseq;
	void *ptr;
	uint16_t offset;

	/*
	 * sad_position is the post-nat seq number of the last packet (pkt
	 * 'n') that had its payload translated.
	 *
	 * The seq number is the seq number in the current packet *before*
	 * nat.
	 *
	 * The pre-nat seq number of packet 'n' is found by subtracting
	 * sad_before from sad_position, i.e. sad_position - sad_before.
	 *
	 * For pak 'n+m', if (seq <= sad_position - sad_before) then it must
	 * be a re-transmission in which case we adjust using sad_before, else
	 * we adjust using sad_after.
	 *
	 * i.e.
	 * its *not* a retransmission if "seq > sad_position - sad_before", or
	 * put another way: "seq + sad_before > sad_position"
	 *
	 * sad_before, sad_after and sad_position are *only* updated when an
	 * ftp payload (or other ALG payload) changes length because of NAT.
	 *
	 * However the seq/ack adjustment determination is made for every
	 * packet of that flow.
	 */
	if (after((seq + sd->sad_before), sd->sad_position))
		seq += sd->sad_after;
	else
		seq += sd->sad_before;

	if (seq == oseq)
		return;

	npf_update_tcp_cksum(npc, nbuf, oseq, seq);

	th->seq = htonl(seq);
	offset = npf_cache_hlen(npc) + offsetof(struct tcphdr, seq);
	ptr = npf_iphdr(nbuf);
	nbuf_advstore(&nbuf, &ptr, offset, sizeof(uint32_t), &th->seq);
}

static void npf_nat_adjust_ack(npf_cache_t *npc, struct rte_mbuf *nbuf,
			struct npf_seq_ack_diff *sd)
{
	struct tcphdr *th = &npc->npc_l4.tcp;
	uint32_t oack = ntohl(th->ack_seq);
	uint32_t ack = oack;
	void *ptr;
	uint16_t offset;

	/*
	 * sad_position is the post-nat seq number of the last packet (pkt
	 * 'n') that had its payload translated.
	 *
	 * The ack number is the ack number in the current packet *before* we
	 * reverse the nat.  In this respect we can directly compare the ack
	 * number with sad_position.
	 */
	if (after(ack, sd->sad_position))
		ack -= sd->sad_after;
	else
		ack -= sd->sad_before;

	if (ack == oack)
		return;

	npf_update_tcp_cksum(npc, nbuf, oack, ack);

	th->ack_seq = htonl(ack);
	offset = npf_cache_hlen(npc) + offsetof(struct tcphdr, ack_seq);
	ptr = npf_iphdr(nbuf);
	nbuf_advstore(&nbuf, &ptr, offset, sizeof(uint32_t), &th->ack_seq);
}

/*
 * Adjust the TCP seq/ack values.
 */
static void __cold_func __noinline
npf_nat_adjust_seq_ack(struct npf_seq_ack *s, npf_cache_t *npc,
		       struct rte_mbuf *nbuf, int di)
{
	struct npf_seq_ack_diff *sd;

	sd = &s->sa_diffs[direction_index(di)];
	npf_nat_adjust_seq(npc, nbuf, sd);

	sd = &s->sa_diffs[!direction_index(di)];
	npf_nat_adjust_ack(npc, nbuf, sd);

	npf_nat_update_sack(npc, nbuf, sd);
}

int
npf_create_natpolicy(npf_rule_t *rl, uint8_t type, uint32_t flags,
		     uint32_t table_id, uint8_t addr_sz, npf_addr_t *taddr,
		     npf_addr_t *taddr_stop, uint32_t match_mask,
		     in_port_t tport, in_port_t tport_stop)
{
	npf_natpolicy_t *np = calloc(1, sizeof(npf_natpolicy_t));

	if (np == NULL) {
		RTE_LOG(ERR, FIREWALL,
			"failed to allocate memory for natpolicy\n");
		return -ENOMEM;
	}

	rte_atomic32_set(&np->n_refcnt, 1);

	np->n_type = type;
	np->n_flags = flags;
	np->n_addr_sz = addr_sz;
	memcpy(&np->n_taddr, taddr, addr_sz);
	memcpy(&np->n_taddr_stop, taddr_stop, addr_sz);
	np->n_match_mask = match_mask;
	np->n_tport = tport;
	np->n_tport_stop = tport_stop;
	np->n_table_id = table_id;

	/* Create the address port map */
	np->n_apm = npf_apm_create(np->n_match_mask, table_id,
				   np->n_type, np->n_taddr,
				   np->n_taddr_stop, np->n_tport,
				   np->n_tport_stop);
	if (!np->n_apm) {
		free(np);
		return -ENOMEM;
	}

	npf_rule_set_natpolicy(rl, np);
	return 0;
}

/*
 * Update a rule's nat policy for a masquerade addr change
 */
void npf_natpolicy_update_masq(npf_rule_t *rl, const npf_addr_t *new_addr)
{
	npf_natpolicy_t *new;
	npf_natpolicy_t *np = npf_rule_get_natpolicy(rl);

	/* An exclude rule has no policy */
	if (!np)
		return;

	if (!(np->n_flags & NPF_NAT_MASQ))
		return;

	/* Changed? */
	if (!memcmp(&np->n_taddr, new_addr, 4))
		return;

	/*
	 * Clone the existing nat policy and create a new apm.
	 *
	 * Note we lose the stats on the old apm, but apm stats
	 * are only used for the unit tests.
	 */
	new = malloc_aligned(sizeof(npf_natpolicy_t));
	if (!new)
		return;
	memcpy(new, np, sizeof(npf_natpolicy_t));
	rte_atomic32_set(&new->n_refcnt, 1);
	new->n_taddr = *new_addr;
	new->n_taddr_stop = *new_addr;

	new->n_apm = npf_apm_create(new->n_match_mask, new->n_table_id,
			new->n_type, new->n_taddr, new->n_taddr_stop,
			new->n_tport, new->n_tport_stop);
	if (!new->n_apm) {
		free(new);
		return;
	}

	/* Now atomically set it on the rule. */
	npf_rule_set_natpolicy(rl, new);

	/* Release the rule reference to the old policy */
	npf_nat_policy_put_rcu(np);
}

/*
 * npf_nat_get_original_tuple()
 *
 * Derive the original tuple params from the npc and nat struct.  Used to
 * create the dataplane session during NAT initialization.
 */
void npf_nat_get_original_tuple(npf_nat_t *nt, npf_cache_t *npc,
		const void **saddr, uint16_t *sid,
		const void **daddr, uint16_t *did)
{

	/* Extract addresses */
	switch (nt->nt_natpolicy->n_type) {
	case NPF_NATIN:
		*daddr = &nt->nt_oaddr;
		*saddr = npf_cache_srcip(npc);
		break;
	case NPF_NATOUT:
		*saddr = &nt->nt_oaddr;
		*daddr = npf_cache_dstip(npc);
		break;
	}

	/* Now the ids, based on protocol */
	if (npf_iscached(npc, NPC_L4PORTS)) {
		struct npf_ports *ports = &npc->npc_l4.ports;

		switch (nt->nt_natpolicy->n_type) {
		case NPF_NATIN:
			*did = nt->nt_oport;
			*sid = ports->s_port;
			break;
		case NPF_NATOUT:
			*sid = nt->nt_oport;
			*did = ports->d_port;
			break;
		}
	} else if (npf_iscached(npc, NPC_ICMP_ECHO)) {
		/* always use oport - original icmp */
		*sid = *did = nt->nt_oport;
	} else
		*sid = *did = 0;
}

/*
 * npf_nat_create: create a new NAT translation entry.
 */
static npf_nat_t *
npf_nat_create(npf_rule_t *rl,
		npf_cache_t *npc, npf_natpolicy_t *np, vrfid_t vrfid)
{
	npf_nat_t *nt;
	int nr_ports = 0;
	int rc;

	/* Create a nat struct */
	nt = malloc_aligned(sizeof(npf_nat_t));
	if (nt == NULL)
		return NULL;

	nt->nt_natpolicy = npf_nat_policy_get(np);
	nt->nt_alg = NULL;
	nt->nt_sa = NULL;
	nt->nt_rl = npf_rule_get(rl);
	nt->nt_map_flags = 0;

	/* Save the original address which may be rewritten. */
	if (np->n_type == NPF_NATOUT) {
		/* Source (local) for Outbound NAT. */
		memcpy(&nt->nt_oaddr, npf_cache_srcip(npc), npc->npc_alen);
	} else {
		/* Destination (external) for Inbound NAT. */
		memcpy(&nt->nt_oaddr, npf_cache_dstip(npc), npc->npc_alen);
	}

	nt->nt_taddr = nt->nt_oaddr;

	/*
	 * Set the NAT parameters, as well as decide which
	 * protocols allocate a mapped addr, port, or both.
	 */
	if (npf_iscached(npc, NPC_L4PORTS)) {
		struct npf_ports *ports = &npc->npc_l4.ports;

		nr_ports = 1;
		nt->nt_oport = (np->n_type == NPF_NATOUT) ?
		    ports->s_port : ports->d_port;
		nt->nt_tport = nt->nt_oport;

		/* Only these protocols get a mapped port */
		if (npf_cache_ipproto(npc) != IPPROTO_SCTP)
			nt->nt_map_flags |= NPF_NAT_MAP_PORT;

	} else if (npf_iscached(npc, NPC_ICMP_ECHO)) {
		const struct icmp *ic = &npc->npc_l4.icmp;

		nt->nt_tport = nt->nt_oport = ic->icmp_id;

		if (np->n_type == NPF_NATOUT) {
			nr_ports = 1;
			nt->nt_map_flags |= NPF_NAT_MAP_PORT;
		}
	} else
		nt->nt_oport = nt->nt_tport = 0;

	rc = npf_nat_alloc_map(np, rl, nt->nt_map_flags, npf_cache_ipproto(npc),
			vrfid, (npf_addr_t *) &nt->nt_taddr,
			&nt->nt_tport, nr_ports);
	if (unlikely(rc != 0)) {
		npf_nat_destroy(nt);
		return NULL;
	}

	return nt;
}

/*
 * Create a custom nat policy. Used by algs for secondary flows.
 *
 * handle these cases:
 *
 *   - a forward secondary flow with a reservation from parent.
 *   - a reverse secondary flow with no reservation.
 *
 */
static npf_natpolicy_t *npf_nat_custom_policy(npf_nat_t *nat, uint32_t flags)
{
	npf_natpolicy_t *np;
	npf_natpolicy_t *old = nat->nt_natpolicy;
	uint32_t old_flags;

	np = zmalloc_aligned(sizeof(struct npf_natpolicy));
	if (!np)
		return NULL;

	rte_atomic32_set(&np->n_refcnt, 1);

	if ((flags & NPF_NAT_REVERSE) != (old->n_flags & NPF_NAT_REVERSE)) {
		if (old->n_type == NPF_NATIN)
			np->n_type = NPF_NATOUT;
		else
			np->n_type = NPF_NATIN;
	} else
		np->n_type = old->n_type;

	/* Set flags but remove MASQ and REVERSE from them */
	old_flags = old->n_flags & ~(NPF_NAT_MASQ | NPF_NAT_REVERSE);
	np->n_flags = old_flags | flags;

	if (flags & NPF_NAT_CLONE_APM) {
		np->n_apm = npf_apm_clone(old->n_apm);
		if (!np->n_apm) {
			free(np);
			np = NULL;
		}
	}
	return np;
}

uint32_t npf_nat_get_map_flags(npf_nat_t *nt)
{
	return nt->nt_map_flags;
}

/* Create a nat of an existing parent nat with a custom nat policy.  */
npf_nat_t *npf_nat_custom_nat(npf_nat_t *pnat, uint32_t flags)
{
	npf_nat_t *nt;

	nt = zmalloc_aligned(sizeof(npf_nat_t));
	if (nt == NULL)
		return NULL;

	nt->nt_natpolicy = npf_nat_custom_policy(pnat, flags);
	if (!nt->nt_natpolicy) {
		free(nt);
		return NULL;
	}

	/* Set the map port flag, if it was set in the parent */
	nt->nt_map_flags = flags & NPF_NAT_MAP_PORT;

	/* packet stats always go against existing rule */
	nt->nt_rl = npf_rule_get(pnat->nt_rl);

	return nt;
}

/*
 * The 5-tuple's for pre and post NAT state are now fixed.
 *
 * Calculate the L3 and L4 checksum deltas; these use
 * ones-complement arithmetic,  and hence have two
 * representations for zero: 0x0000 and 0xffff.
 *
 * Ensure that we always calculate the 0xffff form,
 * and so can make use of the 0x0000 to indicate that
 * the corresponding checksum needs no update.
 */
void
npf_nat_finalise(npf_cache_t *npc, npf_session_t *se, int di, npf_nat_t *nt)
{
	const uint32_t *oip32 = (const uint32_t *)&nt->nt_oaddr;
	const uint32_t *nip32 = (const uint32_t *)&nt->nt_taddr;

	nt->nt_l3_chk = ~ip_fixup32_cksum(0, *oip32, *nip32);
	nt->nt_l4_chk = 0;

	/* Set the session */
	nt->nt_session = se;

	if (unlikely(!npf_iscached(npc, NPC_L4PORTS))) {
		if (npf_iscached(npc, NPC_ICMP_ECHO) &&
		    nt->nt_tport != nt->nt_oport)
			goto calc_l4_chk_delta;
		return;
	}

	struct npf_ports *ports = &npc->npc_l4.ports;

	/* Ensure tport is set, if not already */
	if (!nt->nt_tport) {
		if (di == PFIL_OUT) /* SNAT */
			nt->nt_tport = ports->s_port;
		else /* DNAT */
			nt->nt_tport = ports->d_port;
	}

	/* We never NAT ports for SCTP */
	if (npf_cache_ipproto(npc) == IPPROTO_SCTP)
		return;

calc_l4_chk_delta:


	/* We're allowed to NAT the port,  and so it may well change */
	if (nt->nt_oport != nt->nt_tport)
		nt->nt_l4_chk =
			~ip_fixup16_cksum(0, nt->nt_oport, nt->nt_tport);

	/*
	 * At this point nt->nt_l4_chk being 0x0000 means we are not changing
	 * the ports and so can also skip rewriting them in the packet,  as
	 * well as skip updating the grouper.
	 *
	 * Note that changing between ports 0x0000 and 0xffff will yield a delta
	 * of 0xffff.
	 */

}

/*
 * perform address and/or port translation.
 */
static ALWAYS_INLINE int
npf_nat_translate_at(npf_cache_t *npc, struct rte_mbuf *nbuf,
		     npf_nat_t *nt, const bool forw, int di,
		     void *n_ptr, bool undo)
{
	const npf_addr_t *addr;
	in_port_t port;

	/*
	 * Pick the appropriate address and port
	 *
	 * The session forwards entries have the original values,
	 * and the backwards entries have the translation values.
	 *
	 * An outbound packet is being SNAT'ed (either an SNAT
	 * rule forward flow, or a DNAT rule backward flow),
	 * and the correct values are found in the destination
	 * fields.  For an inbound flow the correct values are
	 * in the source fields.
	 * These all get reversed when we are undoing the translate.
	 */

	if (!undo) {
		if (!forw) {
			port = nt->nt_oport;
			addr = (const npf_addr_t *)&nt->nt_oaddr;
		} else {
			port = nt->nt_tport;
			addr = (const npf_addr_t *)&nt->nt_taddr;
		}
	} else {
		if (forw) {
			port = nt->nt_oport;
			addr = (const npf_addr_t *)&nt->nt_oaddr;
		} else {
			port = nt->nt_tport;
			addr = (const npf_addr_t *)&nt->nt_taddr;
		}
	}

	/* Extract L3/L4 checksum deltas and L4 changed status */
	uint16_t l3_chk_delta = nt->nt_l3_chk;
	uint16_t l4_chk_delta = nt->nt_l4_chk;
	bool l4_changed = l4_chk_delta;
	int rc;

	/*
	 * This expression is not ambiguous
	 * since ((!forw) ^ undo) == (!(forw ^ undo) :
	 *
	 * forw | undo | (!forw) ^ undo | !(forw ^ undo)
	 * -----+------+----------------+---------------
	 *  0   |  0   |        1       |       1
	 *  0   |  1   |        0       |       0
	 *  1   |  0   |        0       |       0
	 *  1   |  1   |        1       |       1
	 */
	if (!forw ^ undo) {
		l3_chk_delta = ~l3_chk_delta;
		l4_chk_delta = ~l4_chk_delta;
	}

	/* Rewrite IP and possibly the transport checksums */
	rc = npf_v4_rwrcksums(npc, nbuf, n_ptr, l3_chk_delta, l4_chk_delta);
	if (rc < 0) {
		/*
		 * It is okay to fail for packets embedded in short ICMP
		 * error messages, as it just has a partial L4 header.
		 */
		if (!(npc->npc_info & NPC_SHORT_ICMP_ERR))
			return -EINVAL;
	}

	/* Rewrite source or destination address */
	if (npf_rwrip(npc, nbuf, n_ptr, di, addr) < 0)
		return -EINVAL;

	/* Maybe rewrite some L4 information */
	if (l4_changed) {
		if (likely(npf_iscached(npc, NPC_L4PORTS))) {
			/* Rewrite source or destination port  */
			if (npf_rwrport(npc, nbuf, n_ptr, di, port) < 0)
				return -EINVAL;
		} else if (npf_iscached(npc, NPC_ICMP_ECHO)) {
			/* Rewrite ICMP query/response ID */
			if (npf_rwricmpid(npc, nbuf, n_ptr, port) < 0)
				return -EINVAL;
		}
	}

	/* Set the natted flag */
	npc->npc_info |= NPC_NATTED;

	return 0;
}

static int
npf_nat_translate(npf_cache_t *npc, struct rte_mbuf *nbuf,
		  npf_nat_t *nt, const bool forw, const int di)
{
	void *n_ptr = dp_pktmbuf_mtol3(nbuf, void *);

	int rc = npf_nat_translate_at(npc, nbuf, nt, forw, di,
				      n_ptr, false);
	if (rc)
		return rc;

	/* Mark as SNAT / DNAT for the rest of the packet path */
	uint32_t pkt_flags
		= (di == PFIL_IN) ? PKT_MDATA_DNAT : PKT_MDATA_SNAT;

	pktmbuf_mdata_set(nbuf, pkt_flags);

	return 0;
}

int
npf_nat_untranslate_at(npf_cache_t *npc, struct rte_mbuf *nbuf,
		       npf_nat_t *nt, const bool forw,
		       const int di, void *n_ptr)
{
	return npf_nat_translate_at(npc, nbuf, nt, forw, di,
				    n_ptr, true);
}

/*
 * Undo DNAT for local packets going to the kernel
 */
int
npf_local_undnat(struct rte_mbuf **m, npf_cache_t *npc, npf_session_t *se)
{
	npf_nat_t *nt = npf_session_get_nat(se);

	if (nt) {
		void *n_ptr = npf_iphdr(*m);
		bool forw = npf_session_forward_dir(se, PFIL_IN);
		int error = npf_nat_untranslate_at(npc, *m, nt, forw,
						   PFIL_IN, n_ptr);

		if (error)
			return -EINVAL;

		pktmbuf_mdata_clear(*m, PKT_MDATA_DNAT);
	}
	return 0;
}

/* Perform a stateless L3 NAT translation */
bool
npf_nat_translate_l3_at(npf_cache_t *npc, struct rte_mbuf *mbuf,
			void *n_ptr, bool dnat,
			const npf_addr_t *addr)
{
	const uint32_t *old_src = &npc->npc_ip.v4.ip_src.s_addr;
	const uint32_t *old_dst = &npc->npc_ip.v4.ip_dst.s_addr;

	const uint32_t *old_addr = dnat ? old_dst : old_src;
	const uint32_t *new_addr = (const uint32_t *)addr;

	uint16_t l3_delta =
		ip_fixup32_cksum(0, *old_addr, *new_addr);
	if (npf_v4_rwrcksums(npc, mbuf, n_ptr, ~l3_delta, 0) < 0)
		return false;
	if (npf_rwrip(npc, mbuf, n_ptr, dnat ? PFIL_IN : PFIL_OUT, addr) < 0)
		return false;

	/* Set the natted flag */
	npc->npc_info |= NPC_NATTED;

	return true;
}

/*
 * Try to return a packet which has had its NAT translation undone.
 *
 * Amongst other reasons, this can currently fail if the packet
 * experienced DNAT then SNAT, or if the packet has looped around
 * a 'tunnel to ourselves'.  The latter as it clears the metadata
 * cache, and the former as it replaced the cached session.
 */
struct rte_mbuf *
npf_nat_clone_and_undo(struct rte_mbuf *mbuf, const struct ifnet *in_ifp,
		       const struct ifnet *out_ifp)
{
	bool did_snat = pktmbuf_mdata_exists(mbuf, PKT_MDATA_SNAT);
	bool did_dnat = pktmbuf_mdata_exists(mbuf, PKT_MDATA_DNAT);

	/* Can not handle this yet */
	if (did_snat && did_dnat)
		return NULL;

	/* Sanity */
	if (!did_snat && !did_dnat)
		return NULL;

	if (did_snat && !out_ifp)
		return NULL;

	if (did_dnat && !in_ifp)
		return NULL;

	/* Find the session */
	npf_session_t *se = npf_session_find_cached(mbuf);
	if (!se)
		return NULL;

	/* Validate the session */
	const struct ifnet *se_ifp = (did_dnat) ? in_ifp : out_ifp;
	if (npf_session_get_if_index(se) != se_ifp->if_index)
		return NULL;
	npf_nat_t *nt  = npf_session_get_nat(se);
	if (!nt)
		return NULL;

	/* Make a clone, and set up to untranslate */
	struct rte_mbuf *unnat = pktmbuf_clone(mbuf, mbuf->pool);
	if (!unnat)
		return NULL;

	npf_cache_t npc;
	npf_cache_init(&npc);

	void *n_ptr = npf_iphdr(unnat);

	if (npf_cache_all(&npc, unnat, htons(RTE_ETHER_TYPE_IPV4)) < 0 ||
	    !npf_iscached(&npc, NPC_IP4) ||
	    (npc.npc_info & NPC_ICMP_ERR)) {
		rte_pktmbuf_free(unnat);
		return NULL;
	}

	int dir = (did_dnat) ? PFIL_IN : PFIL_OUT;
	bool forw = npf_session_forward_dir(se, dir);

	int error =
		npf_nat_untranslate_at(&npc, unnat, nt, forw, dir, n_ptr);
	if (error) {
		rte_pktmbuf_free(unnat);
		return NULL;
	}

	return unnat;
}

/*
 * Try to return a packet which has had its NAT translation undone.
 *
 * Amongst other reasons, this can currently fail if the packet
 * experienced DNAT then SNAT, or if the packet has looped around
 * a 'tunnel to ourselves'.  The latter as it clears the metadata
 * cache, and the former as it replaced the cached session.
 */
struct rte_mbuf *
npf_nat_copy_and_undo(struct rte_mbuf *mbuf, const struct ifnet *in_ifp,
		      const struct ifnet *out_ifp)
{
	bool did_snat = pktmbuf_mdata_exists(mbuf, PKT_MDATA_SNAT);
	bool did_dnat = pktmbuf_mdata_exists(mbuf, PKT_MDATA_DNAT);

	/* Can not handle this yet */
	if (did_snat && did_dnat)
		return NULL;

	/* Sanity */
	if (!did_snat && !did_dnat)
		return NULL;

	if (did_snat && !out_ifp)
		return NULL;

	if (did_dnat && !in_ifp)
		return NULL;

	/* Find the session */
	npf_session_t *se = npf_session_find_cached(mbuf);
	if (!se)
		return NULL;

	/* Validate the session */
	const struct ifnet *se_ifp = (did_dnat) ? in_ifp : out_ifp;
	if (npf_session_get_if_index(se) != se_ifp->if_index)
		return NULL;
	npf_nat_t *nt  = npf_session_get_nat(se);
	if (!nt)
		return NULL;

	/* Make a copy, and set up to untranslate */
	struct rte_mbuf *unnat = pktmbuf_copy(mbuf, mbuf->pool);
	if (!unnat)
		return NULL;

	npf_cache_t npc;
	npf_cache_init(&npc);

	void *n_ptr = npf_iphdr(unnat);

	if (npf_cache_all(&npc, unnat, htons(RTE_ETHER_TYPE_IPV4)) < 0 ||
	    !npf_iscached(&npc, NPC_IP4) ||
	    (npc.npc_info & NPC_ICMP_ERR)) {
		rte_pktmbuf_free(unnat);
		return NULL;
	}

	int dir = (did_dnat) ? PFIL_IN : PFIL_OUT;
	bool forw = npf_session_forward_dir(se, dir);

	int error =
		npf_nat_untranslate_at(&npc, unnat, nt, forw, dir, n_ptr);
	if (error) {
		rte_pktmbuf_free(unnat);
		return NULL;
	}

	return unnat;
}

/*
 * nat_do_subsequent:
 *   Translate packets for which we already have an session established
 *   with complete translation structure.
 */
int
nat_do_subsequent(npf_cache_t *npc, struct rte_mbuf **nbuf,
			npf_session_t *se, npf_nat_t *nt,
			const int di)
{
	int error;
	bool forw = npf_session_forward_dir(se, di);

	npf_rule_t *rl = nt->nt_rl;

	/* Stats irrespective of errors */
	npf_add_pkt(rl, rte_pktmbuf_pkt_len(*nbuf));

	/*
	 * In a double NAT case, we can not undo the first translation,
	 * so check for packet too big on output here before we NAT.
	 *
	 * Also log the pre-NAT packet as it will differ from that logged
	 * by any subsequent firewall rule.
	 */
	if (di == PFIL_OUT) {
		uint16_t if_mtu = nt->nt_mtu;
		bool obey_df = nt->nt_map_flags & NPF_NAT_OBEY_DF;

		struct iphdr *ip = iphdr(*nbuf);
		unsigned int ip_len = ntohs(ip->tot_len);
		if (unlikely(ip_len > if_mtu)) {
			if (obey_df && (ip->frag_off & htons(IP_DF)))
				return -E2BIG;
		}

		/* Log any matched (or session matched) packet immediately */
		if (unlikely(npf_rule_has_rproc_logger(rl)))
			npf_log_pkt(npc, *nbuf, rl, di);
	}

	/* We only need these for ALGs */
	if (unlikely(!!nt->nt_alg)) {
		error = pktmbuf_prepare_for_header_change(nbuf, 0);
		if (error)
			return error;

		/* Adjust the TCP seq/ack if required */
		struct npf_seq_ack *asa = nt->nt_sa;
		if (asa)
			npf_nat_adjust_seq_ack(asa, npc, *nbuf, di);

		/* Perform the per ALG tasks */
		if (npf_alg_nat(se, npc, *nbuf, nt, di))
			return -EINVAL;
	}

	error = npf_prepare_for_l4_header_change(nbuf, npc);
	if (error)
		return error;

	/* Perform the translation. */
	int rc = npf_nat_translate(npc, *nbuf, nt, forw, di);

	/*
	 * Now log the post-NAT packet as it will differ from that logged
	 * by any prior firewall rule.
	 */
	if (!rc && (di == PFIL_IN) && unlikely(npf_rule_has_rproc_logger(rl)))
		npf_log_pkt(npc, *nbuf, rl, di);

	return rc;
}

/*
 * nat_do_icmp_err:
 *   Process an ICMP error packet.
 *   If it is one for a NAT session, then translate it.
 */
int
nat_do_icmp_err(npf_cache_t *npc, struct rte_mbuf **nbuf,
		const struct ifnet *ifp, const int di)
{
	/* We only manipulate IPv4 packets */
	if (!npf_iscached(npc, NPC_IP4) || npf_iscached(npc, NPC_IPFRAG))
		return 0;

	/* Special handling for ICMP errors needing NAT */
	if (npf_iscached(npc, NPC_ICMP_ERR_NAT))
		return npf_icmp_err_nat(npc, nbuf, ifp, di);

	/* ICMP errors for non NAT'ed sessions are not changed */
	return 0;
}

/*
 * nat_try_initial:
 *   Try to translate packets for which we do not already have a complete
 *   translation structure.  If we will translate, establish all required
 *   structures.
 *	- Inspect packet for a NAT policy, unless a session with a NAT
 *	  association already exists.  In such case, determine whether it
 *	  is a "forwards" or "backwards" stream.
 *	- Perform translation: rewrite source or destination fields,
 *	  depending on translation type and direction.
 *	- Associate a NAT policy with a session (may establish a new).
 */
int
nat_try_initial(const struct npf_config *npf_config, npf_cache_t *npc,
		npf_session_t **se_ptr, struct rte_mbuf **nbuf,
		const struct ifnet *ifp, const int di)
{
	npf_session_t *nse = NULL;
	npf_session_t *se = *se_ptr;
	npf_natpolicy_t *np;
	npf_nat_t *nt = NULL;
	int error = 0;

	/*
	 * If this is an existing active session (e.g. from old f/w config)
	 * then do not allow NAT to mess with it.
	 */
	if (se && npf_session_is_active(se))
		return 0;

	/* We only manipulate IPv4 packets */
	if (!npf_iscached(npc, NPC_IP4) || npf_iscached(npc, NPC_IPFRAG))
		return 0;

	/*
	 * Inspect the packet for a NAT policy, we must
	 * have a nat policy to continue.
	 */
	const npf_ruleset_t *rlset = npf_get_ruleset(npf_config,
		(di == PFIL_IN) ? NPF_RS_DNAT : NPF_RS_SNAT);

	npf_rule_t *rl =
		npf_ruleset_inspect(npc, *nbuf, rlset, NULL, ifp, di);

	/* No matching rule */
	if (!rl)
		return 0;

	/* NAT exclusion rule */
	if (!npf_rule_get_pass(rl)) {
no_nat_work:
		/* Stats immediately */
		npf_add_pkt(rl, rte_pktmbuf_pkt_len(*nbuf));
		/* Log any matched rule immediately */
		if (unlikely(npf_rule_has_rproc_logger(rl)))
			npf_log_pkt(npc, *nbuf, rl, di);

		return error;
	}

	np = npf_rule_get_natpolicy(rl);
	if (unlikely(!np))
		goto no_nat_work;

	uint16_t if_mtu = ifp->if_mtu;
	bool obey_df = !if_ignore_df(ifp);

	/*
	 * In a double NAT case, we can not undo the first translation,
	 * so check for packet too big on output here before we NAT.
	 */
	if (di == PFIL_OUT) {
		struct iphdr *ip = iphdr(*nbuf);
		unsigned int ip_len = ntohs(ip->tot_len);
		if (unlikely(ip_len > if_mtu)) {
			if (obey_df && (ip->frag_off & htons(IP_DF))) {
				error = -E2BIG;
				goto no_nat_work;
			}
		}
	}

	/* Create the nat struct */
	nt = npf_nat_create(rl, npc, np, pktmbuf_get_vrf(*nbuf));
	if (!nt) {
		error = -ENOMEM;
		goto no_nat_work;
	}

	nt->nt_mtu = if_mtu;
	nt->nt_map_flags |= (obey_df) ? NPF_NAT_OBEY_DF : 0;

	/* Create a session now, if we don't have one.  */
	if (!se) {
		nse = npf_session_establish(npc, *nbuf, ifp, di, &error);
		if (nse == NULL || error) {
			npf_nat_expire(nt, pktmbuf_get_vrf(*nbuf));
			error = (error) ? error : -ENOMEM;
			goto no_nat_work;
		}
		*se_ptr = se = nse;
	}

	/*
	 * Allow an ALG to inspect the nat struct.
	 */
	npf_alg_nat_inspect(se, npc, nt, di);

	/* Finish setting the nat struct fields */
	npf_nat_finalise(npc, se, di, nt);

	/* Associate NAT translation entry with the session. */
	npf_session_setnat(se, nt, (np->n_flags & NPF_NAT_PINHOLE));

	/* Forward translation */
	return nat_do_subsequent(npc, nbuf, se, nt, di);
}

/*
 * npf_nat_get_trans: return translation IP address and port.
 */
void
npf_nat_get_trans(const npf_nat_t *nt, npf_addr_t *addr, in_port_t *port)
{
	addr->s6_addr32[0] = nt->nt_taddr;
	*port = nt->nt_tport;
}

/*
 * npf_nat_getorig: return original IP address and port from translation entry.
 */
void
npf_nat_get_orig(const npf_nat_t *nt, npf_addr_t *addr, in_port_t *port)
{
	addr->s6_addr32[0] = nt->nt_oaddr;
	*port = nt->nt_oport;
}

/*
 * npf_nat_set_trans: Set the translation IP address and port in a nat
 */
void npf_nat_set_trans(npf_nat_t *nt, const npf_addr_t *addr, in_port_t port)
{
	nt->nt_taddr = addr->s6_addr32[0];
	nt->nt_tport = port;
}

/*
 * npf_nat_set_orig: Set the origin IP address and port in a nat
 */
void npf_nat_set_orig(npf_nat_t *nt, const npf_addr_t *addr, in_port_t port)
{
	nt->nt_oaddr = addr->s6_addr32[0];
	nt->nt_oport = port;
}

/*
 * npf_nat_setalg: associate an ALG with the NAT entry.
 */
void npf_nat_setalg(npf_nat_t *nt, struct npf_alg *alg)
{
	if (alg)
		/* Take reference on alg */
		alg = npf_alg_get(alg);
	else if (nt->nt_alg)
		/* Release reference on alg */
		npf_alg_put((struct npf_alg *)nt->nt_alg);

	nt->nt_alg = alg;
}

/*
 * npf_nat_getalg: get ALG in the NAT entry.
 */
const struct npf_alg *npf_nat_getalg(npf_nat_t *nt)
{
	if (!nt)
		return NULL;
	return nt->nt_alg;
}

static uint64_t npf_natpolicy_table_range(const npf_natpolicy_t *np)
{
	return npf_addrgrp_naddrs(AG_IPv4, np->n_table_id, false);
}

/* get mapping range from nat policy */
uint64_t npf_natpolicy_get_map_range(const npf_natpolicy_t *np)
{
	uint16_t ports = np->n_tport_stop - np->n_tport + 1;
	uint32_t addrs;

	if (np->n_table_id == NPF_TBLID_NONE)
		addrs = NPF_ADDR_TO_UINT32(&np->n_taddr_stop) -
			NPF_ADDR_TO_UINT32(&np->n_taddr) + 1;
	else
		addrs = npf_natpolicy_table_range(np);
	return (uint64_t)addrs * ports;
}

/* Return the type of nat (SNAT/DNAT) from the policy */
uint8_t npf_natpolicy_get_type(npf_natpolicy_t *np)
{
	return np->n_type;
}

/* Get the type of nat (NATIN/NATOUT) */
uint8_t npf_nat_type(npf_nat_t *nt)
{
	return nt->nt_natpolicy->n_type;
}

/*
 * Get the nat policy
 */
npf_natpolicy_t *npf_nat_get_policy(const npf_nat_t *nt)
{
	if (!nt)
		return NULL;
	return nt->nt_natpolicy;
}

/* Get the rule from a nat */
npf_rule_t *npf_nat_get_rule(const npf_nat_t *nt)
{
	return nt->nt_rl;
}

/* Destroy a nat */
void npf_nat_destroy(npf_nat_t *nt)
{
	npf_nat_setalg(nt, NULL);
	npf_rule_put(nt->nt_rl);
	npf_nat_policy_put(nt->nt_natpolicy);
	free(nt->nt_sa);
	free(nt);
}

void
npf_nat_expire(npf_nat_t *nt, vrfid_t vrfid)
{
	npf_natpolicy_t *np = nt->nt_natpolicy;
	npf_addr_t t_addr;
	in_port_t t_port;

	/*
	 * If this is a reverse translation (from an ALG),
	 * the side containing the translation addr/port was reversed.
	 */
	if (unlikely(np->n_flags & NPF_NAT_REVERSE))
		npf_nat_get_orig(nt, &t_addr, &t_port);
	else
		npf_nat_get_trans(nt, &t_addr, &t_port);

	npf_nat_free_map(np, nt->nt_rl, nt->nt_map_flags,
			npf_session_get_proto(nt->nt_session), vrfid,
			t_addr, t_port);

	npf_nat_destroy(nt);
}

/* APM map op failure msg. */
static void npf_nat_log_map_error(const char *which, npf_rule_t *rl,
		struct npf_natpolicy *np, uint8_t ip_prot,
		const npf_addr_t *addr, in_port_t port, int nr_ports, int rc)
{

	if (net_ratelimit()) {
		char addrstr[INET6_ADDRSTRLEN];
		char buf[ERR_MSG_LEN];
		uint64_t overall, used[NAT_PROTO_COUNT];
		enum nat_proto nprot = nat_proto_from_ipproto(ip_prot);

		npf_rule_get_overall_used(rl, used, &overall);

		inet_ntop(AF_INET, addr, addrstr, sizeof(addrstr));
		RTE_LOG(ERR, FIREWALL, "%cNAT: map %s %d (%s:%d prot %u) "
				"`failed: %s, used %"PRIu64"/%"PRIu64"\n",
				np->n_type == NPF_NATIN ? 'D' : 'S',
				which,
				nr_ports, addrstr, ntohs(port), ip_prot,
				strerror_r(-rc, buf, ERR_MSG_LEN),
				used[nprot], overall);
	}
}


/* Allocate one or more mappings from an APM */
int npf_nat_alloc_map(npf_natpolicy_t *np, npf_rule_t *rl, uint32_t map_flags,
		uint8_t ip_prot, vrfid_t vrfid, npf_addr_t *addr,
		in_port_t *port, int num)
{
	int rc;

	rc = npf_apm_get_map(np->n_apm, map_flags, ip_prot, num, vrfid, addr,
			     port);
	if (!rc)
		npf_rule_update_map_stats(rl, num, map_flags, ip_prot);
	else
		npf_nat_log_map_error("get", rl, np, ip_prot, addr, *port, num,
				      rc);
	return rc;
}

/* Return a single mapping to an APM */
int npf_nat_free_map(npf_natpolicy_t *np, npf_rule_t *rl, uint32_t map_flags,
		uint8_t ip_prot, vrfid_t vrfid, const npf_addr_t addr,
		in_port_t port)
{
	int rc;

	rc = npf_apm_put_map(np->n_apm, map_flags, ip_prot, vrfid, addr, port);
	if (!rc)
		npf_rule_update_map_stats(rl, -1, map_flags, ip_prot);
	else
		npf_nat_log_map_error("put", rl, np, ip_prot, &addr, port, 1,
				      rc);
	return rc;
}

static void npf_natpolicy_dump(const npf_natpolicy_t *np)
{
	char start[INET_ADDRSTRLEN], stop[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &np->n_taddr, start, sizeof(start));
	inet_ntop(AF_INET, &np->n_taddr_stop, stop, sizeof(stop));
	RTE_LOG(ERR, FIREWALL, " NATP(%p): type %s flags 0x%x refcnt: %u\n",
			np, (np->n_type == NPF_NATOUT) ? "NATOUT" : "NATIN",
			np->n_flags, rte_atomic32_read(&np->n_refcnt));

	if (!(np->n_flags & NPF_NAT_TABLE)) {
		RTE_LOG(ERR, FIREWALL,
		"           taddr %s-%s tport %d-%d addr_sz: %hhu\n",
		start, stop, np->n_tport, np->n_tport_stop, np->n_addr_sz);
	} else {
		RTE_LOG(ERR, FIREWALL,
		"           table %s tport %d-%d addr_sz: %hhu\n",
		npf_addrgrp_tid2name(np->n_table_id), np->n_tport,
		np->n_tport_stop, np->n_addr_sz);
	}
}

void npf_nat_dump(const npf_nat_t *nt)
{
	char oaddr[INET_ADDRSTRLEN], taddr[INET_ADDRSTRLEN];
	npf_addr_t t_addr, o_addr;
	in_port_t t_port, o_port;

	npf_nat_get_orig(nt, &o_addr, &o_port);
	npf_nat_get_trans(nt, &t_addr, &t_port);

	inet_ntop(AF_INET, &o_addr, oaddr, sizeof(oaddr));
	inet_ntop(AF_INET, &t_addr, taddr, sizeof(taddr));

	npf_natpolicy_dump(nt->nt_natpolicy);
}

bool
npf_nat_info(npf_nat_t *nat, int *type, npf_addr_t *addr,
	     in_port_t *port, u_int *masq)
{
	*masq = (nat->nt_natpolicy->n_flags & NPF_NAT_MASQ);
	*type = nat->nt_natpolicy->n_type;
	npf_nat_get_trans(nat, addr, port);

	return true;
}

int npf_nat_npf_pack_pack(npf_nat_t *nt, struct npf_pack_npf_nat *nat,
			  struct sentry_packet *sp_back)
{
	npf_rule_t *rule;

	if (!nat)
		return -EINVAL;

	rule = npf_nat_get_rule(nt);
	nat->nt_rule_hash = (rule ? npf_rule_get_hash(rule) : 0);

	nat->nt_l3_chk = nt->nt_l3_chk;
	nat->nt_l4_chk = nt->nt_l4_chk;
	nat->nt_map_flags = npf_nat_get_map_flags(nt);
	nat->nt_taddr = nt->nt_taddr;
	nat->nt_tport = nt->nt_tport;
	nat->nt_oaddr = nt->nt_oaddr;
	nat->nt_oport = nt->nt_oport;

	/* Set translation address in back sentry */
	switch (nt->nt_natpolicy->n_type) {
	case NPF_NATIN:
		sp_back->sp_addrids[1] = nt->nt_taddr;
		break;
	case NPF_NATOUT:
		sp_back->sp_addrids[2] = nt->nt_taddr;
		break;
	}

	return 0;
}

int npf_nat_npf_pack_restore(struct npf_session *se,
			     struct npf_pack_npf_nat *nat,
			     struct ifnet *ifp)
{
	npf_nat_t *nt;
	npf_rule_t *rl;
	npf_natpolicy_t *np;
	int rc = -ENOENT;

	if (!se || !nat || !ifp)
		return -EINVAL;

	/* Create a nat struct */
	nt = zmalloc_aligned(sizeof(npf_nat_t));
	if (!nt)
		return -ENOMEM;

	rl = nat->nt_rule_hash ? npf_get_rule_by_hash(nat->nt_rule_hash) : NULL;
	if (!rl)
		goto error;

	nt->nt_rl = npf_rule_get(rl);

	np = npf_rule_get_natpolicy(rl);
	if (!np || np->n_apm)
		goto error;
	nt->nt_natpolicy = np;

	nt->nt_l3_chk = nat->nt_l3_chk;
	nt->nt_l4_chk = nat->nt_l4_chk;
	nt->nt_map_flags = nat->nt_map_flags;
	nt->nt_taddr = nat->nt_taddr;
	nt->nt_tport = nat->nt_tport;
	nt->nt_oaddr = nat->nt_oaddr;
	nt->nt_oport = nat->nt_oport;

	vrfid_t vrfid = npf_session_get_vrfid(se);

	rc = npf_nat_alloc_map(nt->nt_natpolicy, rl, nt->nt_map_flags, vrfid,
			npf_session_get_proto(se), (npf_addr_t *) &nt->nt_taddr,
			&nt->nt_tport, 1);
	if (rc)
		goto error;

	nt->nt_mtu = ifp->if_mtu;
	nt->nt_session = se;
	npf_session_setnat(se, nt,
			(nt->nt_natpolicy->n_flags & NPF_NAT_PINHOLE));

	return 0;
error:
	npf_rule_put(nt->nt_rl);
	free(nt);
	return rc;
}
