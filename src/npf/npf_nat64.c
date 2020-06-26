/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NPF NAT64 for v6-to-v4 and v4-to-v6 address/ip packet header conversion
 */

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "in_cksum.h"
#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "netinet6/in6.h"
#include "pktmbuf_internal.h"
#include "vplane_log.h"
#include "urcu.h"
#include "util.h"

#include "npf/npf.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat64.h"
#include "npf/npf_session.h"
#include "npf/npf_ruleset.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/rproc/npf_ext_nat64.h"
#include "npf/npf_pack.h"

struct ifnet;
struct rte_mbuf;

/*
 * NAT64 session stats
 */
struct nat64_sess_stats {
	uint64_t	pkts_ct;
	uint64_t	bytes_ct;
};

/*
 * Size of counter per-cpu array based on highest active lcore.
 */
#define NAT64_STATS_SIZE	(sizeof(struct nat64_sess_stats) *	\
				 (get_lcore_max() + 1))

/*
 * NAT64 session data
 *
 * n64_rproc_id is either NPF_RPROC_ID_NAT64 or NPF_RPROC_ID_NAT46.
 *
 * Set when nat64 peer sessions are linked via dataplane session
 * log session creation and closure
 */
struct npf_nat64 {
	struct npf_session	*n64_peer;
	rte_spinlock_t		n64_lock;
	npf_rule_t		*n64_rule; /* Set for ingress session */
	int			n64_rproc_id;
	uint8_t			n64_v6:1,
				n64_linked:1,
				n64_log_sessions:1;

	/* If v4 src addr is obtained from an apm */
	npf_natpolicy_t		*n64_np;
	uint32_t		n64_map_flags;
	vrfid_t			n64_vrfid;
	npf_addr_t		n64_t_addr;
	in_port_t		n64_t_port;

	/* session stats - per-core arrays */
	struct nat64_sess_stats	*n64_stats_in;
	struct nat64_sess_stats	*n64_stats_out;
};

npf_rule_t *
npf_nat64_get_rule(struct npf_nat64 *n64)
{
	return n64 ? n64->n64_rule : NULL;
}

uint8_t npf_nat64_is_v6(struct npf_nat64 *n64)
{
	return n64->n64_v6 ? 1 : 0;
}

uint8_t npf_nat64_is_linked(struct npf_nat64 *n64)
{
	return n64->n64_linked ? 1 : 0;
}

void npf_nat64_get_trans(struct npf_nat64 *n64,
			npf_addr_t *addr, in_port_t *port)
{
	memcpy(addr, &n64->n64_t_addr, sizeof(npf_addr_t));
	*port = n64->n64_t_port;
}

/*
 * Does this nat64 session have a peer session?
 */
bool npf_nat64_has_peer(struct npf_nat64 *n64)
{
	return n64 ? (n64->n64_peer != NULL) : false;
}

/*
 * Get nat64 peer session
 */
npf_session_t *
npf_nat64_get_peer(struct npf_nat64 *n64)
{
	return n64 ? n64->n64_peer : NULL;
}

/*
 * Is session logging enabled for nat64/nat46 session creation/closure?
 */
bool
npf_nat64_session_log_enabled(struct npf_nat64 *n64)
{
	return n64 ? n64->n64_log_sessions : false;
}

/*
 * Extracts v4 address from v6 addresses according to
 * specifications in table 2.2 in rfc6052.
 */
static bool
extract_6052_addr(uint32_t *ip4addr, char *ip6addr, uint8_t mask)
{
	/* 32, 40, 48, 56, 64, or 96 */
	switch (mask) {
	case 32:
		memcpy((char *)ip4addr, ip6addr + 4, 4);
		break;
	case 40:
		memcpy((char *)ip4addr, ip6addr + 5, 3);
		memcpy((char *)ip4addr + 3, ip6addr + 9, 1);
		break;
	case 48:
		memcpy((char *)ip4addr, ip6addr + 6, 2);
		memcpy((char *)ip4addr + 2, ip6addr + 9, 2);
		break;
	case 56:
		memcpy((char *)ip4addr, ip6addr + 7, 1);
		memcpy((char *)ip4addr + 1, ip6addr + 9, 3);
		break;
	case 64:
		memcpy((char *)ip4addr, ip6addr + 9, 4);
		break;
	case 96:
		memcpy((char *)ip4addr, ip6addr + 12, 4);
		break;
	default:
		if (net_ratelimit())
			RTE_LOG(ERR, NAT64,
				"unexpected value for prefix length %d "
				"in 6to4 conversion\n",
				mask);
		return false;
	}
	return true;
}

/*
 * Add an IPv4 address to an IPv6 prefix as specified by rfc6052.
 */
static bool
insert_6052_addr(uint32_t *ip4addr, uint8_t *ip6addr, uint8_t mask)
{
	switch (mask) {
	case 32:
		memcpy(ip6addr + 4, (char *)ip4addr, 4);
		break;
	case 40:
		memcpy(ip6addr + 5, (char *)ip4addr, 3);
		memcpy(ip6addr + 9, (char *)ip4addr + 3, 1);
		break;
	case 48:
		memcpy(ip6addr + 6, (char *)ip4addr, 2);
		memcpy(ip6addr + 9, (char *)ip4addr + 2, 2);
		break;
	case 56:
		memcpy(ip6addr + 7, (char *)ip4addr, 1);
		memcpy(ip6addr + 9, (char *)ip4addr + 1, 3);
		break;
	case 64:
		memcpy(ip6addr + 9, (char *)ip4addr, 4);
		break;
	case 96:
		memcpy(ip6addr + 12, (char *)ip4addr, 4);
		break;
	default:
		if (net_ratelimit())
			RTE_LOG(ERR, NAT64,
				"unexpected value for prefix length %d "
				"in 4to6 conversion\n",
				mask);
		return false;
	}
	return true;
}

/*
 * Get an IPv4 address from nat64 rproc and IPv6 address
 *
 * se6     - nat64 IPv6 ingress session
 * ip_prot - IP protocol
 * id      - L4 ID, e.g. TCP port
 * nm      - nat64 rproc address mapping configuration and state
 * v6_addr - IPv6 address source or dest of packet to be translated
 * v4_addr - New IPv4 address is written to this uint32_t
 *
 * Note that if ICMP is given a unique pool to allocate ID's from,
 * then the NAT64 code needs checked to ensure that the it works as expected,
 * as NAT64 maps between ICMPv4 (protocol 1) and ICMPv6 (protocol 58).
 */
static int
nat64_get_map_v4(struct npf_nat64 *nat64, npf_rule_t *rl, uint8_t ip_prot,
		 uint16_t *id, struct nat64_map *nm, uint32_t *v4_addr,
		 char *v6_addr, vrfid_t vrfid)
{
	int rc;

	assert(nat64);

	switch (nm->nm_type) {
	case NPF_NAT64_RFC6052:
		/*
		 * Extract the v4 addrs from the v6 addrs
		 */
		if (!extract_6052_addr(v4_addr, v6_addr,
				       nm->nm_mask))
			return -EINVAL;
		break;

	case NPF_NAT64_ONE2ONE:
		/*
		 * One-to-one mapping.  Address is stored in rproc.
		 */
		*v4_addr = nm->nm_addr.s6_addr32[0];

		/* Optional dest port mapping */
		if (id && nm->nm_start_port)
			*id = nm->nm_start_port;
		break;

	case NPF_NAT64_OVERLOAD:
		if (!rl)
			return -EINVAL;

		npf_natpolicy_t *np = npf_rule_get_natpolicy(rl);
		if (!np)
			return -EINVAL;

		assert(!nat64->n64_np);

		if (!nat64->n64_np) {
			nat64->n64_np = npf_nat_policy_get(np);
			nat64->n64_map_flags = NPF_NAT_MAP_PORT;
			nat64->n64_vrfid = vrfid;
			nat64->n64_t_addr.s6_addr32[0] =
				nm->nm_start_addr.s6_addr32[0];
		}
		nat64->n64_t_port = *id;

		/*
		 * n64_t_addr is initially 0.0.0.0
		 */
		rc = npf_nat_alloc_map(np, rl,
				       nat64->n64_map_flags, ip_prot,
				       nat64->n64_vrfid,
				       &nat64->n64_t_addr,
				       &nat64->n64_t_port, 1);

		if (rc != 0)
			return -EINVAL;

		*v4_addr = nat64->n64_t_addr.s6_addr32[0];
		*id = nat64->n64_t_port;

		break;

	case NPF_NAT64_NONE:
		return -EINVAL;
	};

	return 0;
}

/*
 * Get an IPv6 address from nat46 rproc and IPv4 address
 *
 * id      - L4 ID, e.g. TCP port
 * nm      - nat64 rproc address mapping configuration and state
 * v4_addr - IPv4 address source or dest of packet to be translated
 * v6_addr - New IPv6 address is written to this pointer
 */
static int
nat64_get_map_v6(uint16_t *id, struct nat64_map *nm, npf_addr_t *v6_addr,
		 uint32_t v4_addr)
{
	switch (nm->nm_type) {
	case NPF_NAT64_RFC6052:
		/* Copy prefix */
		memcpy(v6_addr, nm->nm_addr.s6_addr, 16);

		if (!insert_6052_addr(&v4_addr, v6_addr->s6_addr,
				      nm->nm_mask))
			return -EINVAL;
		break;
	case NPF_NAT64_ONE2ONE:
		/*
		 * One-to-one mapping.  Address is stored in rproc.
		 */
		memcpy(v6_addr, nm->nm_addr.s6_addr, 16);

		/* Optional dest port mapping */
		if (id && nm->nm_start_port)
			*id = nm->nm_start_port;
		break;
	case NPF_NAT64_OVERLOAD:
		return -EINVAL;
	case NPF_NAT64_NONE:
		return -EINVAL;
	};

	return 0;
}

/*
 * Conversion utility to go from v4 to v6 space. Only supports tcp/udp and
 * icmp echos.
 */
static bool
npf_4to6_convert(struct rte_mbuf **m, npf_cache_t *npc,
		 npf_addr_t *src, uint16_t sid,
		 npf_addr_t *dst, uint16_t did)
{
	if (!*m || !npc)
		return false;

	struct iphdr *ip = iphdr(*m);
	uint16_t proto = npf_cache_ipproto(npc);
	uint16_t ttl = ip->ttl;
	uint hlen = npf_cache_hlen(npc);

	/* ip->tot_len is length of packet, including IP header */
	uint32_t data_len = ntohs(ip->tot_len) - hlen;

	if (npf_prepare_for_l4_header_change(m, npc) != 0)
		return false;

	/*
	 * Grow the l3 header space so there is just enough
	 * space for a simple IPv6 header.
	 */
	char *l2, *new_l2;

	l2 = rte_pktmbuf_mtod(*m, char *);
	new_l2 = rte_pktmbuf_prepend(*m, sizeof(struct ip6_hdr) - hlen);
	if (!new_l2)
		return false;

	memmove(new_l2, l2, (*m)->l2_len);
	l2 = new_l2;

	/* Reset the L3 length */
	dp_pktmbuf_l3_len(*m) = sizeof(struct ip6_hdr);

	struct ip6_hdr *ip6 = ip6hdr(*m);
	char *l4hdr = (char *)(ip6 + 1);

	/* fix up ether type */
	if ((*m)->l2_len == RTE_ETHER_HDR_LEN) {
		struct rte_ether_hdr *eth = (struct rte_ether_hdr *)l2;
		eth->ether_type = htons(RTE_ETHER_TYPE_IPV6);
	}

	ip6->ip6_flow = 0;
	ip6->ip6_vfc = IPV6_VERSION;
	ip6->ip6_plen = htons(data_len);
	ip6->ip6_hlim = ttl;

	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_DCCP:
	case IPPROTO_SCTP:
	{
		struct tcphdr *th = (struct tcphdr *)l4hdr;

		th->th_sport = sid;
		th->th_dport = did;
		break;
	}
	case IPPROTO_ICMP:
		/* Already filtered out non echo req/reply pkts */
		proto = IPPROTO_ICMPV6;
		uint8_t v6_icmp =
			npf_iscached(npc, NPC_ICMP_ECHO_REQ) ?
			ICMP6_ECHO_REQUEST : ICMP6_ECHO_REPLY;
		struct icmp6_hdr *icmp = (struct icmp6_hdr *)l4hdr;

		icmp->icmp6_type = v6_icmp;
		icmp->icmp6_code = 0;
		icmp->icmp6_id = sid;
		break;
	}

	ip6->ip6_nxt = proto;
	memcpy(&ip6->ip6_src, src, 16);
	memcpy(&ip6->ip6_dst, dst, 16);

	/* now recompute checksum */
	npf_ipv6_cksum(*m, proto, l4hdr);

	return true;
}

/*
 * Conversion utility to go from v6 to v4 space. Only supports tcp/udp and
 * icmp echos.
 */
static bool
npf_6to4_convert(struct rte_mbuf **m, npf_cache_t *npc,
		 uint32_t v4_saddr, uint16_t sid,
		 uint32_t v4_daddr, uint16_t did)
{
	if (!*m || !npc)
		return false;

	struct ip6_hdr *ip6 = ip6hdr(*m);
	uint16_t proto = npf_cache_ipproto(npc);
	uint16_t hlim = ip6->ip6_hlim;
	uint hlen = npf_cache_hlen(npc);

	/*
	 * ip6_plen is length of packet, including extension hdrs,
	 * but not the fixed IPv6 hdr
	 */
	uint32_t data_len = ntohs(ip6->ip6_plen) - hlen +
			    sizeof(struct ip6_hdr);

	if (npf_prepare_for_l4_header_change(m, npc) != 0)
		return false;

	/*
	 * Shrink l3 header size such that we are left with space for
	 * an IPv4 header
	 */
	char *l2, *new_l2;

	l2 = rte_pktmbuf_mtod(*m, char *);
	new_l2 = rte_pktmbuf_adj(*m, hlen - sizeof(struct iphdr));
	if (!new_l2)
		return false;

	memmove(new_l2, l2, (*m)->l2_len);
	l2 = new_l2;

	/* Reset the L3 length */
	dp_pktmbuf_l3_len(*m) = sizeof(struct iphdr);

	struct iphdr *ip = iphdr(*m);
	char *l4hdr = (char *)(ip + 1);

	/* fix up ether type */
	if ((*m)->l2_len == RTE_ETHER_HDR_LEN) {
		struct rte_ether_hdr *eth = (struct rte_ether_hdr *)l2;
		eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	}

	ip->ihl = sizeof(struct iphdr) >> 2; /* fixed 20 bytes for now */
	ip->version = IPVERSION;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(struct iphdr) + data_len);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = hlim;

	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_DCCP:
	case IPPROTO_SCTP:
	{
		struct tcphdr *th = (struct tcphdr *)l4hdr;

		th->th_sport = sid;
		th->th_dport = did;
		break;
	}
	case IPPROTO_ICMPV6:
		/* Already filtered out non echo req/reply pkts */
		proto = IPPROTO_ICMP;
		uint8_t v4_icmp =
			npf_iscached(npc, NPC_ICMP_ECHO_REQ) ?
			ICMP_ECHO : ICMP_ECHOREPLY;
		struct icmp *icmp = (struct icmp *)l4hdr;

		icmp->icmp_type = v4_icmp;
		icmp->icmp_code = 0;
		icmp->icmp_id = sid;
		break;
	}

	ip->protocol = proto;
	ip->saddr = v4_saddr;
	ip->daddr = v4_daddr;

	/* now recompute checksum */
	ip->check = 0;
	ip->check = in_cksum(ip, sizeof(struct iphdr));

	/* now fixup proto cksums */
	npf_ipv4_cksum(*m, proto, l4hdr);

	return true;
}

/*
 * npf_nat64_session_establish
 *
 * Create a nat64 session, or add a nat64 structure to an existing session.
 */
static int
npf_nat64_session_establish(npf_session_t **sep, npf_cache_t *npc,
			    struct rte_mbuf *m, const struct ifnet *ifp,
			    npf_rule_t *rl, const int dir,
			    enum npf_rproc_id rproc_id,
			    bool log_sessions)
{
	struct npf_nat64 *nat64;
	npf_session_t *se = *sep;
	bool new = false;
	int error, rc = 0;

	if (!se) {
		se = npf_session_establish(npc, m, ifp, dir, &error);
		if (error)
			return error;
		if (se == NULL)
			return -EINVAL;
		new = true;
	}

	nat64 = npf_session_get_nat64(se);
	if (!nat64) {
		nat64 = zmalloc(sizeof(*nat64));
		if (!nat64) {
			if (new)
				npf_session_destroy(se);
			return -ENOMEM;
		}
		nat64->n64_v6 = npf_iscached(npc, NPC_IP6);
		nat64->n64_rproc_id = rproc_id;
		nat64->n64_rule = npf_rule_get(rl);
		nat64->n64_log_sessions = log_sessions;
		rte_spinlock_init(&nat64->n64_lock);

		nat64->n64_stats_in  = zmalloc_aligned(NAT64_STATS_SIZE);
		nat64->n64_stats_out = zmalloc_aligned(NAT64_STATS_SIZE);
		if (!nat64->n64_stats_in || !nat64->n64_stats_out) {
			rc = -ENOMEM;
			goto error;
		}
		npf_session_set_nat64(se, nat64);
	}

	if (new)
		*sep = se;
	return 0;

error:
	free(nat64->n64_stats_in);
	free(nat64->n64_stats_out);
	free(nat64);
	if (new)
		npf_session_destroy(se);
	return rc;
}

/*
 * npf_nat64_session_link.  se1 is the ingress session, and se2 is the egress
 * session.
 *
 *                 v4 pkt
 *                   v
 * v6(in) --> nat64 ---> v4 route ---> v4(out)a --> nat64 --> v4(out)b
 *              ^                                     ^         ^
 *              1                                     2,3       4
 *
 *  1 - v6 session created and activated
 *  2 - v4 session created
 *  3 - v4 and v6 sessions linked as nat64 peers
 *  4 - v4 session activated and linked to v6 session with dataplane linkage
 *
 * This function is called twice in normal operation.  First time it links the
 * two npf sessions as nat64 peers.
 *
 * Second time (when the egress session is activated), it links the two
 * sessions via the dataplane session linkage mechanism.
 *
 * If simultaneous v4 and v6 sessions are created on different interfaces by
 * orthogonal nat64 rules then the behaviour is different.
 *
 * Ingress v4 and an ingress v6 nat64 sessions will be created and activated
 * before either packet reaches the nat64 output.
 *
 * The first packet to reach egress will find the other session in the session
 * lookup in npf_hook_track.  When npf_nat64_session_link is called it will
 * links the two sessions via the dataplane session linkage mechanism *and*
 * links the two npf sessions as nat64 peers.
 *
 * npf_nat64_session_link will be called again when the second packet reaches
 * nat64 egress.  This will be somewhat of a noop, as it will find the two
 * sessions already linked as dataplane parent-child, and nat64 peers.
 */
int
npf_nat64_session_link(struct npf_session *se1, struct npf_session *se2)
{
	struct npf_nat64 *m1, *m2;
	rte_spinlock_t *lock;

	m1 = npf_session_get_nat64(se1);
	m2 = npf_session_get_nat64(se2);
	if (!m1 || !m2)
		return -EINVAL;

	/* We always use the lock from the v6 session */
	lock = m1->n64_v6 ? &m1->n64_lock : &m2->n64_lock;

	rte_spinlock_lock(lock);

	/*
	 * Link nat64 sessions at the dataplane session level if they are
	 * active and not already linked.
	 */
	if (npf_session_get_dp_session(se1) &&
	    npf_session_get_dp_session(se2) &&
	    !m1->n64_linked && !m2->n64_linked) {
		struct session *p_s = npf_session_get_dp_session(se1);
		struct session *c_s = npf_session_get_dp_session(se2);
		int rc;

		/*
		 * Only link the dataplane sessions when either they are not
		 * already linked, or they are linked with p_s as parent and
		 * c_s as child.  In the latter case, the call to session_link
		 * just increments a ref count.
		 */
		if ((session_base_parent(c_s) == c_s ||
		     session_base_parent(c_s) == p_s) &&
		    session_base_parent(p_s) == p_s) {

			/* link dataplane sessions */
			rc = session_link(p_s, c_s);
			if (rc) {
				m1->n64_peer = NULL;
				m2->n64_peer = NULL;

				rte_spinlock_unlock(lock);

				if (net_ratelimit())
					RTE_LOG(ERR, NAT64,
						"Failed to link sessions "
						"id(%lu) and id(%lu)\n",
						npf_session_get_id(se1),
						npf_session_get_id(se2));

				return -EINVAL;
			}
			m1->n64_linked = true;
			m2->n64_linked = true;
		} else {
			m1->n64_peer = NULL;
			m2->n64_peer = NULL;

			rte_spinlock_unlock(lock);

			if (net_ratelimit())
				RTE_LOG(ERR, NAT64,
					"Unable to link sessions "
					"id(%lu) and id(%lu)\n",
					npf_session_get_id(se1),
					npf_session_get_id(se2));
			return -EINVAL;
		}
	}

	if (!m1->n64_peer && !m2->n64_peer) {
		/*
		 * Link the npf sessions via nat64 peer pointers
		 */
		m1->n64_peer = se2;
		m2->n64_peer = se1;
	}

	rte_spinlock_unlock(lock);

	return 0;
}

/*
 * npf_nat64_session_unlink.  Called when either peer session is expired.
 */
void npf_nat64_session_unlink(struct npf_session *se)
{
	struct npf_nat64 *n64 = npf_session_get_nat64(se);
	npf_session_t *peer = npf_nat64_get_peer(n64);
	struct npf_nat64 *n64_peer = npf_session_get_nat64(peer);

	if (npf_nat64_session_log_enabled(n64))
		npf_session_nat64_log(se, false);

	if (n64)
		n64->n64_peer = NULL;
	if (n64_peer)
		n64_peer->n64_peer = NULL;
}

void
npf_nat64_session_destroy(struct npf_session *se)
{
	struct npf_nat64 *nat64;

	nat64 = npf_session_get_nat64(se);

	if (!nat64)
		return;

	struct npf_nat64 *peer;

	peer = npf_session_get_nat64(nat64->n64_peer);
	if (peer)
		peer->n64_peer = NULL;

	if (nat64->n64_np) {
		npf_nat_free_map(nat64->n64_np, nat64->n64_rule,
				 nat64->n64_map_flags,
				 npf_session_get_proto(se),
				 nat64->n64_vrfid,
				 nat64->n64_t_addr,
				 nat64->n64_t_port);

		npf_nat_policy_put(nat64->n64_np);
	}
	npf_rule_put(nat64->n64_rule);

	free(nat64->n64_stats_in);
	free(nat64->n64_stats_out);
	free(nat64);
	npf_session_set_nat64(se, NULL);
}

/* Get rproc_id */
int npf_nat64_get_rproc_id(struct npf_nat64 *n64)
{
	return n64->n64_rproc_id;
}

/*
 * Is this a nat64 session?
 */
bool npf_nat64_session_is_nat64(npf_session_t *se)
{
	struct npf_nat64 *nat64;

	nat64 = npf_session_get_nat64(se);
	if (nat64)
		return nat64->n64_rproc_id == NPF_RPROC_ID_NAT64;
	return false;
}

/*
 * Is this a nat46 session?
 */
bool npf_nat64_session_is_nat46(npf_session_t *se)
{
	struct npf_nat64 *nat64;

	nat64 = npf_session_get_nat64(se);
	if (nat64)
		return nat64->n64_rproc_id == NPF_RPROC_ID_NAT46;
	return false;
}

/*
 * Add nat64 session stats
 */
static inline void
npf_nat64_add_pkt_in(struct npf_nat64 *n64, uint64_t bytes)
{
	if (!n64)
		return;

	unsigned int core = dp_lcore_id();

	n64->n64_stats_in[core].pkts_ct++;
	n64->n64_stats_in[core].bytes_ct += bytes;
}

static inline void
npf_nat64_add_pkt_out(struct npf_nat64 *n64, uint64_t bytes)
{
	if (!n64)
		return;

	unsigned int core = dp_lcore_id();

	n64->n64_stats_out[core].pkts_ct++;
	n64->n64_stats_out[core].bytes_ct += bytes;
}

static void
npf_nat64_sum_stats(struct npf_nat64 *n64, bool in,
		    struct nat64_sess_stats *ss)
{
	unsigned int i;

	memset(ss, 0, sizeof(struct nat64_sess_stats));

	FOREACH_DP_LCORE(i) {
		if (in) {
			ss->bytes_ct  += n64->n64_stats_in[i].bytes_ct;
			ss->pkts_ct   += n64->n64_stats_in[i].pkts_ct;
		} else {
			ss->bytes_ct  += n64->n64_stats_out[i].bytes_ct;
			ss->pkts_ct   += n64->n64_stats_out[i].pkts_ct;
		}
	}
}

/*
 * Write nat64 session json
 */
void
npf_nat64_session_json(json_writer_t *json, npf_session_t *se)
{
	struct npf_nat64 *n64 = npf_session_get_nat64(se);

	if (!n64)
		return;

	const char *type_str;

	if (n64->n64_rproc_id == NPF_RPROC_ID_NAT64)
		type_str = "nat64";
	else
		type_str = "nat46";

	jsonw_name(json, "nat64");
	jsonw_start_object(json);

	jsonw_string_field(json, "type", type_str);
	jsonw_uint_field(json, "peer_id", npf_session_get_id(n64->n64_peer));
	jsonw_bool_field(json, "in", npf_session_forward_dir(se, PFIL_IN));

	if (n64->n64_rule) {
		const char *gr_name = npf_rule_get_name(n64->n64_rule);

		jsonw_string_field(json, "ruleset",
				   gr_name ? gr_name : "<UNKNOWN>");
		jsonw_uint_field(json, "rule",
				 npf_rule_get_num(n64->n64_rule));
	}

	struct nat64_sess_stats ss;

	/* Input stats */
	jsonw_name(json, "stats_in");
	jsonw_start_object(json);

	npf_nat64_sum_stats(n64, true, &ss);
	jsonw_uint_field(json, "bytes", ss.bytes_ct);
	jsonw_uint_field(json, "packets", ss.pkts_ct);

	jsonw_end_object(json);

	/* Output stats */
	jsonw_name(json, "stats_out");
	jsonw_start_object(json);

	npf_nat64_sum_stats(n64, false, &ss);
	jsonw_uint_field(json, "bytes", ss.bytes_ct);
	jsonw_uint_field(json, "packets", ss.pkts_ct);

	jsonw_end_object(json);

	jsonw_end_object(json);
}

/*
 * v6-to-v4 Ingress.  Packet is v6.
 *
 * There are four scenarios with regard to the ingress and egress nat64
 * sessions:
 *
 *   1. No v6 ingress session exists.
 *   2. v6 ingress session exists, but is not a nat64 session.
 *   3. v6 ingress session exists, is a nat64 session, but it *not* linked
 *      to a v4 egress session.
 *   4. v6 ingress session exists, is a nat64 session, and *is* linked
 *      to a v4 egress session.
 *
 * Scenarios #1 and #4 are the typical expected scenarios.  #1 is usually the
 * first packet of a flow, and #4 is subsequent packets.  #2 is also possible
 * if a stateful firewall or nat created a session.
 *
 * #3 is the unlikely scenario.  This implies that a previous packet created
 * an ingress nat64 session but, for whatever reason, an egress session was
 * not created.
 *
 * In this scenario we need to lookup the nat64 rule again in order to
 * translate the packet, and then add the v6 session to the pkt metadata again
 * so that nat64 has another opportunity to create an egress session and link
 * it to the ingress session.
 */
nat64_decision_t
npf_nat64_6to4_in(const struct npf_config *npf_config,
		  npf_session_t **sep, struct ifnet *ifp, npf_cache_t *npc,
		  struct rte_mbuf **m, uint16_t *npf_flag)
{
	nat64_decision_t decision = NAT64_DECISION_UNMATCHED;
	npf_addr_t saddr = NPF_ADDR_ZERO, daddr = NPF_ADDR_ZERO;
	npf_addr_t *src = &saddr, *dst = &daddr;
	npf_session_t *se6 = *sep;
	npf_session_t *se4 = NULL;
	struct npf_nat64 *n64;
	npf_rule_t *rl = NULL;
	bool new_flow = false;
	uint16_t sid, did;
	int rc;

	/*
	 * If an ingress session exist and it is a nat64 session, then get the
	 * peer egress session.
	 */
	n64 = npf_session_get_nat64(se6);
	if (likely(n64 != NULL)) {
		se4 = n64->n64_peer;
		rl = n64->n64_rule;
	}

	if (unlikely(!se4)) {
		const npf_ruleset_t *rlset;
		struct nat64 *rproc;
		struct ip6_hdr *ip6;
		int error = 0;
		uint8_t ip_prot;

		/*
		 * Peer egress session not found.
		 *
		 * This will be the case for the firstpacket of a flow, in
		 * which case we need to lookup the nat64 ruleset.  However it
		 * may also occur if, for whatever reason, an egress session
		 * was not created by a previous packet. In the latter case,
		 * the rule may be found on the ingress session.
		 */
		if (!rl) {
			rlset =	npf_get_ruleset(npf_config, NPF_RS_NAT64);
			rl = npf_ruleset_inspect(npc, *m, rlset, NULL, ifp,
						 PFIL_IN);

			if (!rl)
				return NAT64_DECISION_UNMATCHED;
		}

		/*
		 * If we matched a nat64 rule then this *must* be a nat64
		 * rproc.  (rule class "nat64" is used for v6-to-v4 and
		 * v4-to-v6 rulesets).
		 *
		 * Get the nat64 rproc handle.  This contains the info we need
		 * to translate the first packet of the flow.
		 */
		rproc = npf_rule_rproc_handle_from_id(rl, NPF_RPROC_ID_NAT64);
		if (!rproc)
			/* This should never happen */
			return NAT64_DECISION_DROP;

		/*
		 * Check packet is eligible for v6-to-v4 translation *before*
		 * creating v6 session or doing translation.
		 *
		 * Only consider 1. IPv6, 2. TCP/UDP and 3. ICMP echo req/reply
		 */
		if (!npf_iscached(npc, NPC_IP6) ||
		    (!npf_iscached(npc, NPC_L4PORTS) &&
		     !npf_iscached(npc, NPC_ICMP_ECHO)))
			return NAT64_DECISION_DROP;

		/*
		 * Create or update v6 ingress session.  Add s_nat64 to
		 * session.
		 *
		 * We do not want to expose a new session to npf_hook_track so
		 * use local variable, se6.
		 */
		rc = npf_nat64_session_establish(
			&se6, npc, *m, ifp, rl,	PFIL_IN, NPF_RPROC_ID_NAT64,
			(rproc->n6_log & N64_LOG_SESSIONS) != 0);
		if (rc < 0)
			return NAT64_DECISION_DROP;

		vrfid_t vrfid = npf_session_get_vrfid(se6);

		/* Get src and dst ports from cache */
		npf_cache_extract_ids(npc, &sid, &did);
		ip6 = ip6hdr(*m);

		n64 = npf_session_get_nat64(se6);
		if (unlikely(!n64)) {
			/* Should never happen */
			decision = NAT64_DECISION_DROP;
			goto error;
		}

		/* Get mapping for v4 src addr */
		ip_prot = npf_cache_ipproto(npc);
		rc = nat64_get_map_v4(n64, rl, ip_prot, &sid, &rproc->n6_src,
				      saddr.s6_addr32, (char *)&ip6->ip6_src,
				      vrfid);
		if (rc) {
			decision = NAT64_DECISION_DROP;
			goto error;
		}

		/* Get mapping for v4 dst addr */
		rc = nat64_get_map_v4(n64, rl, ip_prot, &did, &rproc->n6_dst,
				      daddr.s6_addr32, (char *)&ip6->ip6_dst,
				      vrfid);
		if (rc) {
			decision = NAT64_DECISION_DROP;
			goto error;
		}

		/*
		 * We need to activate the session before the mbuf changes
		 */
		error = npf_session_activate(se6, ifp, npc, *m);
		if (unlikely(error)) {
			decision = NAT64_DECISION_DROP;
			goto error;
		}

		new_flow = true;
	} else {
		/*
		 * Session is a nat64 session.  Get v4 addrs from v4 peer
		 * session.
		 */
		uint32_t if_index;
		bool forw;
		int rc, af;

		forw = npf_session_forward_dir(se6, PFIL_IN);

		/*
		 * Extract v4 addrs and IDs from the peer v4 session.
		 */
		if (forw)
			rc = npf_session_sentry_extract(se4, &if_index, &af,
							&src, &sid, &dst, &did);
		else
			rc = npf_session_sentry_extract(se4, &if_index, &af,
							&dst, &did, &src, &sid);

		if (unlikely(rc || af != AF_INET))
			return NAT64_DECISION_DROP;
	}

	/*
	 * Do the 6-to-4 conversion
	 */
	uint64_t bytes = rte_pktmbuf_pkt_len(*m);
	bool ok = npf_6to4_convert(m, npc, src->s6_addr32[0], sid,
				   dst->s6_addr32[0], did);

	if (likely(ok)) {
		/*
		 * stats.  NOTE, this is currently only recording stats if a
		 * session does not exist.
		 */
		npf_nat64_add_pkt_in(n64, bytes);

		decision = NAT64_DECISION_TO_V4;

		/* Flag to output pipeline */
		*npf_flag |= NPF_FLAG_FROM_IPV6;

		if (unlikely(new_flow)) {
			/*
			 * Add v6 session to nat64 pkt mdata
			 */
			struct pktmbuf_mdata *mdata = pktmbuf_mdata(*m);
			mdata->md_nat64.n64_se = se6;
			pktmbuf_mdata_invar_set(*m, PKT_MDATA_INVAR_NAT64);
		}
	} else {
		decision = NAT64_DECISION_DROP;
		goto error;
	}

	return decision;

error:
	/*
	 * An error occurred.  If an inactive session exists then destroy it.
	 * If the inactive session was created by the calling function
	 * (i.e. *sep == se4), then set *sep to NULL.
	 */
	if (se6 && !npf_session_is_active(se6)) {
		npf_session_destroy(se6);
		if (*sep == se6)
			*sep = NULL;
	}
	return decision;
}

/*
 * v6-to-v4 Out.  Packet is v4.
 *
 * There are x scenarios with regard to the egress session:
 *
 *   1. No v4 egress session exists.
 *   2. v4 egress session exists, but is not a nat64 session.
 *   3. v4 egress session exists, is a nat64 session, but is *not* linked
 *      to a v6 ingress session.
 *   4. v4 egress session exists, is a nat64 session, and *is* linked
 *      to a v6 ingress session.
 *
 * Scenarios #1 and #4 are the typical expected scenarios.  #1 is usually the
 * first packet of a flow, and #4 is subsequent packets.  #2 is also possible
 * if a stateful firewall or nat created a session.
 *
 * #3 is the unlikely scenario. It may occur if orthogonal nat64 and nat46
 * rules create ingress sessions simultaneously.
 */
nat64_decision_t
npf_nat64_6to4_out(npf_session_t **sep, struct ifnet *ifp, npf_cache_t *npc,
		   struct rte_mbuf **m, uint16_t *npf_flag)
{
	npf_session_t *se4 = *sep;
	struct npf_nat64 *n64;
	int rc;

	if ((*npf_flag & NPF_FLAG_FROM_IPV6) == 0)
		return NAT64_DECISION_UNMATCHED;

	/*
	 * 6-to-4 packets will contain nat64 metadata as long as ingress and
	 * egress sessions are not linked.  Once linked, the nat64 metadata
	 * will not be present, and we can jump to do the stats.
	 */
	if (!pktmbuf_mdata_invar_exists(*m, PKT_MDATA_INVAR_NAT64))
		goto stats;

	struct pktmbuf_mdata *mdata = pktmbuf_mdata(*m);
	npf_session_t *se6;

	/* Get the v6 session and its nat64 struct */
	se6 = mdata->md_nat64.n64_se;
	n64 = npf_session_get_nat64(se6);
	if (unlikely(!se6 || !n64))
		/* This should never happen */
		return NAT64_DECISION_DROP;

	/*
	 * Create an IPv4 session if one does not already exist (#1).  Add a
	 * nat64 structure if its a new session (#1), or an non-nat64 existing
	 * session (#2).  We copy some stuff from the v6 session such as rl
	 * and log state.
	 */
	rc = npf_nat64_session_establish(&se4, npc, *m, ifp, n64->n64_rule,
					 PFIL_OUT, NPF_RPROC_ID_NAT64,
					 n64->n64_log_sessions);
	if (rc < 0 || se4 == NULL)
		return NAT64_DECISION_DROP;

	/*
	 * Link v4 and v6 sessions.  This handles scenario #3, where we have a
	 * race between two packet flows in different directions.
	 */
	rc = npf_nat64_session_link(se6, se4);

	if (rc < 0)
		return NAT64_DECISION_DROP;

	if (!*sep)
		*sep = se4;

stats:
	/* Stats. */
	npf_nat64_add_pkt_out(npf_session_get_nat64(se4),
			      rte_pktmbuf_pkt_len(*m));

	return NAT64_DECISION_PASS;
}

/*
 * v4-to-v6 Ingress.  Packet is v4.
 *
 * There are four scenarios with regard to the ingress and egress nat64
 * sessions:
 *
 *   1. No v4 ingress session exists.
 *   2. v4 ingress session exists, but is not a nat64 session.
 *   3. v4 ingress session exists, is a nat64 session, but it *not* linked
 *      to a v6 egress session.
 *   4. v4 ingress session exists, is a nat64 session, and *is* linked
 *      to a v6 egress session.
 *
 * Scenarios #1 and #4 are the typical expected scenarios.  #1 is usually the
 * first packet of a flow, and #4 is subsequent packets.  #2 is also possible
 * if a stateful firewall or nat created a session.
 *
 * #3 is the unlikely scenario.  This implies that a previous packet created
 * an ingress nat64 session but, for whatever reason, an egress session was
 * not created.
 *
 * In this scenario we need to lookup the nat64 rule again in order to
 * translate the packet, and then add the v6 session to the pkt metadata again
 * so that nat64 has another opportunity to create an egress session and link
 * it to the ingress session.
 */
nat64_decision_t
npf_nat64_4to6_in(const struct npf_config *npf_config,
		  npf_session_t **sep, struct ifnet *ifp, npf_cache_t *npc,
		  struct rte_mbuf **m, uint16_t *npf_flag)
{
	nat64_decision_t decision = NAT64_DECISION_UNMATCHED;
	npf_addr_t saddr = NPF_ADDR_ZERO, daddr = NPF_ADDR_ZERO;
	npf_addr_t *src = &saddr, *dst = &daddr;
	npf_session_t *se4 = *sep;
	npf_session_t *se6 = NULL;
	struct npf_nat64 *n64;
	npf_rule_t *rl = NULL;
	bool new_flow = false;
	uint16_t sid, did;
	int rc;

	/*
	 * If an ingress session exist and it is a nat64 session, then get the
	 * peer egress session.
	 */
	n64 = npf_session_get_nat64(se4);
	if (likely(n64 != NULL)) {
		se6 = n64->n64_peer;
		rl = n64->n64_rule;
	}

	if (unlikely(!se6)) {
		const npf_ruleset_t *rlset;
		struct nat64 *rproc;
		struct iphdr *ip;
		int error = 0;

		/*
		 * Peer egress session not found.
		 *
		 * This will be the case for the firstpacket of a flow, in
		 * which case we need to lookup the nat64 ruleset.  However it
		 * may also occur if, for whatever reason, an egress session
		 * was not created by a previous packet. In the latter case,
		 * the rule may be found on the ingress session.
		 */
		if (!rl) {
			rlset =	npf_get_ruleset(npf_config, NPF_RS_NAT46);
			rl = npf_ruleset_inspect(npc, *m, rlset, NULL, ifp,
						 PFIL_IN);

			if (!rl)
				return NAT64_DECISION_UNMATCHED;
		}

		/*
		 * If we matched a nat64 rule then this *must* be a nat46
		 * rproc.  (rule class "nat64" is used for v6-to-v4 and
		 * v4-to-v6 rulesets).
		 *
		 * Get the nat46 rproc handle.  This contains the info we need
		 * to translate the first packet of the flow.
		 */
		rproc = npf_rule_rproc_handle_from_id(rl, NPF_RPROC_ID_NAT46);
		if (!rproc)
			/* This should never happen */
			return NAT64_DECISION_DROP;

		/*
		 * Check packet is eligible for v4-to-v6 translation *before*
		 * creating v4 session or doing translation.
		 *
		 * Only consider 1. IPv4, 2. TCP/UDP and 3. ICMP echo req/reply
		 */
		if (!npf_iscached(npc, NPC_IP4) ||
		    (!npf_iscached(npc, NPC_L4PORTS) &&
		     !npf_iscached(npc, NPC_ICMP_ECHO)))
			return NAT64_DECISION_DROP;

		/*
		 * Create or update v4 ingress session.
		 *
		 * We do not want to expose a new session to npf_hook_track so
		 * use local variable, se4.
		 */
		rc = npf_nat64_session_establish(
			&se4, npc, *m, ifp, rl,
			PFIL_IN, NPF_RPROC_ID_NAT46,
			(rproc->n6_log & N64_LOG_SESSIONS) != 0);
		if (rc < 0)
			return NAT64_DECISION_DROP;

		/* Get src and dst ports from cache */
		npf_cache_extract_ids(npc, &sid, &did);
		ip = iphdr(*m);

		n64 = npf_session_get_nat64(se4);
		if (unlikely(!n64)) {
			/* Should never happen */
			decision = NAT64_DECISION_DROP;
			goto error;
		}

		/* Get mapping for v4 src addr */
		rc = nat64_get_map_v6(NULL, &rproc->n6_src, src, ip->saddr);
		if (rc) {
			decision = NAT64_DECISION_DROP;
			goto error;
		}

		/*
		 * Get v6 dst addr from the rproc and/or pkt
		 */
		rc = nat64_get_map_v6(&did, &rproc->n6_dst, dst, ip->daddr);
		if (rc) {
			decision = NAT64_DECISION_DROP;
			goto error;
		}

		/*
		 * We need to activate the session now before the mbuf changes
		 */
		error = npf_session_activate(se4, ifp, npc, *m);
		if (unlikely(error)) {
			decision = NAT64_DECISION_DROP;
			goto error;
		}

		new_flow = true;
	} else {
		/*
		 * Session is a nat46 session.  Get v6 addrs from v6 peer
		 * session.
		 */
		uint32_t if_index;
		bool forw;
		int rc, af;

		forw = npf_session_forward_dir(se4, PFIL_IN);

		/*
		 * Extract v6 addrs and IDs from the peer v6 session.
		 */
		if (forw)
			rc = npf_session_sentry_extract(se6, &if_index, &af,
							&src, &sid, &dst, &did);
		else
			rc = npf_session_sentry_extract(se6, &if_index, &af,
							&dst, &did, &src, &sid);

		if (unlikely(rc || af != AF_INET6))
			return NAT64_DECISION_DROP;
	}

	/*
	 * Do the 4-to-6 conversion
	 */
	uint64_t bytes = rte_pktmbuf_pkt_len(*m);
	bool ok = npf_4to6_convert(m, npc, src, sid, dst, did);

	if (likely(ok)) {
		/*
		 * stats.  NOTE, this is currently only recording stats if a
		 * session does not exist.
		 */
		npf_nat64_add_pkt_in(n64, bytes);

		decision = NAT64_DECISION_TO_V6;

		/* Flag to output pipeline */
		*npf_flag |= NPF_FLAG_FROM_IPV4;

		if (unlikely(new_flow)) {
			/*
			 * Add v4 session to nat64 pkt mdata
			 */
			struct pktmbuf_mdata *mdata = pktmbuf_mdata(*m);
			mdata->md_nat64.n64_se = se4;
			pktmbuf_mdata_invar_set(*m, PKT_MDATA_INVAR_NAT64);
		}
	} else {
		decision = NAT64_DECISION_DROP;
		goto error;
	}

	return decision;

error:
	/*
	 * An error occurred.  If an inactive session exists then destroy it.
	 * If the inactive session was created by the calling function
	 * (i.e. *sep == se4), then set *sep to NULL.
	 */
	if (se4 && !npf_session_is_active(se4)) {
		npf_session_destroy(se4);
		if (*sep == se4)
			*sep = NULL;
	}
	return decision;
}

/*
 * v4-to-v6 Out.  Packet is v6.
 *
 * There are x scenarios with regard to the egress session:
 *
 *   1. No v6 egress session exists.
 *   2. v6 egress session exists, but is not a nat64 session.
 *   3. v6 egress session exists, is a nat64 session, but is *not* linked
 *      to a v4 ingress session.
 *   4. v6 egress session exists, is a nat64 session, and *is* linked
 *      to a v4 ingress session.
 *
 * Scenarios #1 and #4 are the typical expected scenarios.  #1 is usually the
 * first packet of a flow, and #4 is subsequent packets.  #2 is also possible
 * if a stateful firewall or nat created a session.
 *
 * #3 is the unlikely scenario. It may occur if orthogonal nat64 and nat46
 * rules create ingress sessions simultaneously.
 */
nat64_decision_t
npf_nat64_4to6_out(npf_session_t **sep, struct ifnet *ifp, npf_cache_t *npc,
		   struct rte_mbuf **m, uint16_t *npf_flag)
{
	npf_session_t *se6 = *sep;
	struct npf_nat64 *n64;
	int rc;

	if ((*npf_flag & NPF_FLAG_FROM_IPV4) == 0)
		return NAT64_DECISION_UNMATCHED;

	/*
	 * 4-to-6 packets will contain nat64 metadata as long as ingress and
	 * egress sessions are not linked.  Once linked, the nat64 metadata
	 * will not be present, and we can jump to do the stats.
	 */
	if (!pktmbuf_mdata_invar_exists(*m, PKT_MDATA_INVAR_NAT64))
		goto stats;

	struct pktmbuf_mdata *mdata = pktmbuf_mdata(*m);
	npf_session_t *se4;

	/* Get the v4 session and its nat64 struct */
	se4 = mdata->md_nat64.n64_se;
	n64 = npf_session_get_nat64(se4);
	if (!se4 || !n64)
		/* This should never happen */
		return NAT64_DECISION_DROP;

	/*
	 * Create an IPv6 session if one does not already exist (#1).  Add a
	 * nat64 structure if its a new session (#1), or an non-nat64 existing
	 * session (#2).  We copy some stuff from the v4 session such as rl
	 * and log state.
	 */
	rc = npf_nat64_session_establish(&se6, npc, *m, ifp, n64->n64_rule,
					 PFIL_OUT, NPF_RPROC_ID_NAT46,
					 n64->n64_log_sessions);
	if (rc < 0 || se6 == NULL)
		return NAT64_DECISION_DROP;

	/*
	 * Link v6 and v4 sessions.  This handles scenario #3, where we have a
	 * race between two packet flows in different directions.
	 */
	rc = npf_nat64_session_link(se4, se6);

	if (rc < 0)
		return NAT64_DECISION_DROP;

	if (!*sep)
		*sep = se6;

stats:
	/* Stats. */
	npf_nat64_add_pkt_out(npf_session_get_nat64(se6),
			      rte_pktmbuf_pkt_len(*m));

	return NAT64_DECISION_PASS;
}

int npf_nat64_npf_pack_pack(struct npf_nat64 *n64,
			    struct npf_pack_npf_nat64 *cn64)
{
	npf_rule_t *rule;

	if (!n64 || !cn64)
		return -EINVAL;

	rule = npf_nat64_get_rule(n64);
	cn64->n64_rule_hash = (rule ? npf_rule_get_hash(rule) : 0);
	cn64->n64_rproc_id = npf_nat64_get_rproc_id(n64);
	cn64->n64_map_flags = n64->n64_map_flags;
	cn64->n64_v6 = npf_nat64_is_v6(n64);
	cn64->n64_linked = npf_nat64_is_linked(n64);
	npf_nat64_get_trans(n64, &cn64->n64_t_addr, &cn64->n64_t_port);

	return 0;
}

int npf_nat64_npf_pack_restore(struct npf_session *se,
			       struct npf_pack_npf_nat64 *nat64)
{
	struct npf_nat64 *n64;
	npf_rule_t *rl;
	int rc = -EINVAL;

	if (!se || !nat64)
		return -EINVAL;

	/* Create a nat64 struct */
	n64 = zmalloc(sizeof(struct npf_nat64));
	if (!n64)
		return -ENOMEM;

	rl = nat64->n64_rule_hash ?
		npf_get_rule_by_hash(nat64->n64_rule_hash) : NULL;

	if (rl) {
		n64->n64_rule = npf_rule_get(rl);
		n64->n64_np = npf_rule_get_natpolicy(rl);
	}

	n64->n64_rproc_id = nat64->n64_rproc_id;
	n64->n64_map_flags = nat64->n64_map_flags;
	n64->n64_vrfid = npf_session_get_vrfid(se);

	memcpy(&n64->n64_t_addr, &nat64->n64_t_addr, sizeof(npf_addr_t));
	n64->n64_t_port = nat64->n64_t_port;

	n64->n64_v6 = nat64->n64_v6;
	if (!nat64->n64_linked)
		goto error;

	rte_spinlock_init(&n64->n64_lock);
	n64->n64_stats_in  = zmalloc_aligned(NAT64_STATS_SIZE);
	n64->n64_stats_out = zmalloc_aligned(NAT64_STATS_SIZE);
	if (!n64->n64_stats_in || !n64->n64_stats_out) {
		rc = -ENOMEM;
		goto error;
	}

	npf_session_set_nat64(se, n64);

	return 0;

error:
	npf_rule_put(n64->n64_rule);
	free(n64);
	return rc;
}
