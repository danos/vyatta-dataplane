/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */
/*	$NetBSD: nd6_nbr.c,v 1.90 2008/07/31 18:24:07 matt Exp $	*/
/*	$KAME: nd6_nbr.c,v 1.61 2001/02/10 16:06:14 jinmei Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-3-Clause)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/neighbour.h>
#include <linux/snmp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <urcu/list.h>

#include "arp.h"
#include "compiler.h"
#include "dp_event.h"
#include "ether.h"
#include "fal.h"
#include "fal_plugin.h"
#include "if/macvlan.h"
#include "if_ether.h"
#include "if_llatbl.h"
#include "if_var.h"
#include "in6.h"
#include "in6_var.h"
#include "in_cksum.h"
#include "ip6_funcs.h"
#include "lcore_sched.h"
#include "main.h"
#include "nd6.h"
#include "nd6_nbr.h"
#include "pktmbuf_internal.h"
#include "protobuf.h"
#include "protobuf/NbrResConfig.pb-c.h"
#include "snmp_mib.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

struct rte_timer;

#define LLADDR_PENDING_KEEP	10

#define ND6_DEBUG(format, args...)	\
	DP_DEBUG(ND6, DEBUG, ND6, format, ##args)
#define PRINT6(addr, buf) inet_ntop(AF_INET6, addr, buf, sizeof(buf))

/* Statistics. */
struct nd6_nbr_stats nd6nbrstat;
#define ND6NBR_ADD(name, val)	nd6nbrstat.name += (val)
#define ND6NBR_INC(name)	ND6NBR_ADD(name, 1)

/* preventing too many loops in ND option parsing */
static const int nd6_maxndopt = 10;  /* max # of ND options allowed */

/*
 * Synchronise control plane
 * If true use aggressive synchronisation to pass conformance
 */
static bool nd6_sync;

static const char *const nd6_dbgstate[] = {
	"INCMPL", "REACH", "STALE", "DELAY", "PROBE"};

static const struct in6_addr in6addr_allnodes =
	IN6ADDR_LINKLOCAL_ALLNODES_INIT;

static const char in6ether_allnodes[RTE_ETHER_ADDR_LEN] = {
	0x33, 0x33, 0x00, 0x00, 0x00, 0x01};

static struct nd6_nbr_cfg nd6_cfg = {
	.nd6_ns_retries		= ND6_NS_RETRIES,
	.nd6_reachable_time	= ND6_REACHABLE_TIME,
	.nd6_scavenge_time	= ND6_SCAVENGE_TIME,
	.nd6_delay_time		= ND6_DELAY_TIME,
	.nd6_max_entry		= ND6_MAX_ENTRY,
	.nd6_res_token		= ND6_RES_TOKEN,
	.nd6_unr_token		= ND6_UNR_TOKEN,
	.nd6_maxhold		= ND6_MAXHOLD,
};

static void nd6_log_conflict(struct ifnet *ifp,
			     const struct rte_ether_addr *lladdr,
			     struct in6_addr *saddr)
{
	char b1[ETH_ADDR_STR_LEN];

	if (net_ratelimit())
		RTE_LOG(NOTICE, ND6,
			"%s is using my IPv6 address %s on %s!\n",
			lladdr ? ether_ntoa_r(lladdr, b1) : "Unknown",
			ip6_sprintf(saddr),
			ifp->if_name);

	ND6NBR_INC(dupips);
}

static const char *lladdr_ntop6(struct llentry *la)
{
	static char buf[INET6_ADDRSTRLEN];
	const struct sockaddr_in6 *sin6 = satosin6(ll_sockaddr(la));

	return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf));
}

/*
 * Check target against our addresses
 */
static int
nd6_forus(struct ifnet *ifp, const struct in6_addr *src,
	  const struct in6_addr *target)
{
	struct if_addr *ifa;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *)&ifa->ifa_addr;

		if (sa->sa_family != AF_INET6)
			continue;

		/*
		 * Check for node using our address
		 */
		const struct sockaddr_in6 *sin6 = satosin6(sa);

		if (unlikely(IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, src)))
			return -EADDRINUSE;

		if (IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, target))
			return 0;
	}

	return -ENOENT;
}

static void
nd6_option_init(void *opt, int icmp6len, union nd_opts *ndopts)
{

	memset(ndopts, 0, sizeof(*ndopts));
	ndopts->nd_opts_search = (struct nd_opt_hdr *)opt;
	ndopts->nd_opts_last
		= (struct nd_opt_hdr *)(((u_char *)opt) + icmp6len);
	if (icmp6len == 0) {
		ndopts->nd_opts_done = 1;
		ndopts->nd_opts_search = NULL;
	}
}

/*
 * Take one ND option.
 */
static struct nd_opt_hdr *
nd6_option(union nd_opts *ndopts)
{
	struct nd_opt_hdr *nd_opt;
	int olen;

	assert(ndopts != NULL);
	assert(ndopts->nd_opts_last != NULL);
	if (ndopts->nd_opts_search == NULL)
		return NULL;
	if (ndopts->nd_opts_done)
		return NULL;

	nd_opt = ndopts->nd_opts_search;

	/* make sure nd_opt_len is inside the buffer */
	if ((void *)&nd_opt->nd_opt_len >= (void *)ndopts->nd_opts_last) {
		memset(ndopts, 0, sizeof(*ndopts));
		return NULL;
	}

	olen = nd_opt->nd_opt_len << 3;
	if (olen == 0) {
		/*
		 * Message validation requires that all included
		 * options have a length that is greater than zero.
		 */
		memset(ndopts, 0, sizeof(*ndopts));
		return NULL;
	}

	ndopts->nd_opts_search = (struct nd_opt_hdr *)((char *)nd_opt + olen);
	if (ndopts->nd_opts_search > ndopts->nd_opts_last) {
		/* option overruns the end of buffer, invalid */
		memset(ndopts, 0, sizeof(*ndopts));
		return NULL;
	}
	if (ndopts->nd_opts_search == ndopts->nd_opts_last) {
		/* reached the end of options chain */
		ndopts->nd_opts_done = 1;
		ndopts->nd_opts_search = NULL;
	}
	return nd_opt;
}

/*
 * Parse multiple ND options.
 * This function is much easier to use, for ND routines that do not need
 * multiple options of the same type.
 */
static int
nd6_options(union nd_opts *ndopts)
{
	struct nd_opt_hdr *nd_opt;
	int i = 0;

	assert(ndopts != NULL);
	assert(ndopts->nd_opts_last != NULL);
	if (ndopts->nd_opts_search == NULL)
		return 0;

	while (1) {
		nd_opt = nd6_option(ndopts);
		if (nd_opt == NULL && ndopts->nd_opts_last == NULL) {
			/*
			 * Message validation requires that all included
			 * options have a length that is greater than zero.
			 */
			memset(ndopts, 0, sizeof(*ndopts));
			return -1;
		}

		if (nd_opt == NULL)
			goto skip1;

		switch (nd_opt->nd_opt_type) {
		case ND_OPT_SOURCE_LINKADDR:
		case ND_OPT_TARGET_LINKADDR:
		case ND_OPT_MTU:
		case ND_OPT_REDIRECTED_HEADER:
			if (ndopts->nd_opt_array[nd_opt->nd_opt_type]) {
				ND6_DEBUG(
					"duplicated ND6 option found (type=%d)\n",
					nd_opt->nd_opt_type);
				/* XXX bark? */
			} else {
				ndopts->nd_opt_array[nd_opt->nd_opt_type]
					= nd_opt;
			}
			break;
		case ND_OPT_PREFIX_INFORMATION:
			if (ndopts->nd_opt_array[nd_opt->nd_opt_type] == NULL) {
				ndopts->nd_opt_array[nd_opt->nd_opt_type]
					= nd_opt;
			}
			ndopts->nd_opts_pi_end =
				(struct nd_opt_prefix_info *)nd_opt;
			break;
		default:
			/*
			 * Unknown options must be silently ignored,
			 * to accommodate future extension to the protocol.
			 */
			ND6_DEBUG(
				"nd6_options: unsupported option %d - "
				"option ignored\n", nd_opt->nd_opt_type);
		}

skip1:
		i++;
		if (i > nd6_maxndopt) {
			ND6_DEBUG("too many loop in nd opt\n");
			break;
		}

		if (ndopts->nd_opts_done)
			break;
	}

	return 0;
}

/*
 * Change cache entry state
 * Caller must have a spinlock on the entry if required
 */
static inline void
nd6_change_state(struct ifnet *ifp, struct llentry *lle, uint8_t state,
		 uint16_t expire)
{
	if (lle->la_flags & (LLE_STATIC | LLE_DELETED))
		return;

	ND6_DEBUG("%s/%s %s->%s\n", ifp->if_name, lladdr_ntop6(lle),
		  nd6_dbgstate[lle->la_state], nd6_dbgstate[state]);

	lle->la_state = state;
	lle->ll_expire = rte_get_timer_cycles() + expire * rte_get_timer_hz();
}

/* should be called with la->ll_lock held */
static inline void
nd6_update_lla(struct ifnet *ifp, struct llentry *la,
	       const struct rte_ether_addr *enaddr)
{
	char buf[ETH_ADDR_STR_LEN];

	ND6_DEBUG("%s/%s LLA %s\n", ifp->if_name, lladdr_ntop6(la),
		  ether_ntoa_r(enaddr, buf));

	ll_addr_set(la, enaddr);
	la->la_flags |= LLE_HW_UPD_PENDING;

	/*
	 * Fire the timer for this table immediately on the main
	 * thread so that FAL updates can be issued.
	 */
	rte_timer_reset(&ifp->if_lltable6->lle_timer, 0,
			SINGLE, rte_get_master_lcore(),
			in6_lladdr_timer, ifp->if_lltable6);
}

/*
 * Update an existing ND cache entry
 * Always makes it complete
 */
static inline void
nd6_entry_amend(struct ifnet *ifp, struct llentry *la, uint8_t state,
		const struct rte_ether_addr *enaddr, uint16_t secs, u_int flags)
{
	struct lltable *llt = ifp->if_lltable6;

	rte_spinlock_lock(&la->ll_lock);

	/*
	 * Only a Static update can amend an existing Static entry
	 */
	if ((la->la_flags & LLE_STATIC) && !(flags & LLE_STATIC)) {
		rte_spinlock_unlock(&la->ll_lock);
		return;
	}

	if (la->la_flags & LLE_VALID) {
		/*
		 * Valid entry, update MAC.
		 */
		if (!rte_ether_addr_equal(enaddr, &la->ll_addr))
			nd6_update_lla(ifp, la, enaddr);

		la->la_flags |= flags;
		la->la_state = state;
		la->ll_expire = secs ?
			rte_get_timer_cycles() + rte_get_timer_hz() * secs : 0;
	} else {
		/*
		 * Invalid (incomplete) entry.
		 */
		if (rte_atomic16_read(&llt->lle_restoken) <
		    nd6_cfg.nd6_res_token)
			rte_atomic16_inc(&llt->lle_restoken);

		nd6_update_lla(ifp, la, enaddr);
		rte_wmb();
		la->la_flags |= (flags | LLE_VALID);
		la->la_state = state;
		la->ll_expire = secs ?
			rte_get_timer_cycles() + rte_get_timer_hz() * secs : 0;

		/*
		 * Send any queued data if now valid
		 */
		if (la->la_numheld > 0) {
			unsigned int i;

			for (i = 0; i < la->la_numheld; ++i) {
				struct rte_mbuf *m = la->la_held[i];
				struct rte_ether_hdr *eh;

				if (!m)
					break;

				eh = rte_pktmbuf_mtod(m,
						      struct rte_ether_hdr *);

				la->la_held[i] = NULL;
				rte_ether_addr_copy(enaddr, &eh->d_addr);
				if_output(ifp, m, NULL, ntohs(eh->ether_type));
			}
			la->la_numheld = 0;
		}
	}
	rte_spinlock_unlock(&la->ll_lock);
}

/*
 * Select source for outgoing packet
 */
static const struct in6_addr *
nd6_select_source(struct ifnet *ifp, const struct in6_addr *addr)
{
	struct if_addr *ifa;
	int global = addr ? !IN6_IS_ADDR_LINKLOCAL(addr) : 0;

	cds_list_for_each_entry_rcu(ifa, &ifp->if_addrhead, ifa_link) {
		struct sockaddr *sa = (struct sockaddr *)&ifa->ifa_addr;

		if (sa->sa_family != AF_INET6)
			continue;

		if (global && IN6_ARE_ADDR_EQUAL(addr, IFA_IN6(ifa)))
			return IFA_IN6(ifa);

		if (IN6_IS_ADDR_LINKLOCAL(IFA_IN6(ifa)))
			return IFA_IN6(ifa);
	}
	return NULL;
}

/* Convert a ipv6 address to a hash value. */
static uint32_t lla_hash6(const struct lltable *llt,
			  const struct in6_addr *addr)
{
	return in6_addr_hash(addr, sizeof(*addr), llt->lle_seed);
}

/*
 * Compare the IPv6 address of the entry with the desired value.
 */
static __hot_func int
lla_match6(struct cds_lfht_node *node, const void *key)
{
	struct llentry *lle = caa_container_of(node, struct llentry, ll_node);
	struct sockaddr_in6 *sa2 = satosin6(ll_sockaddr(lle));
	const struct in6_addr *addr = key;

	return IN6_ARE_ADDR_EQUAL(&sa2->sin6_addr, addr);
}

/*
 * Create an ND cache entry in valid state
 */
static struct llentry *
nd6_create_valid(struct ifnet *ifp, const struct in6_addr *addr,
		 uint8_t state, const struct rte_ether_addr *enaddr,
		 uint16_t secs, u_int flags)
{
	struct lltable *llt = ifp->if_lltable6;
	struct llentry *lle;
	struct sockaddr_in6 sin6 = {
		.sin6_family =	AF_INET6,
		.sin6_addr = *addr,
	};
	const struct fal_attribute_t attr_list[] = {
		{ .id = FAL_NEIGH_ENTRY_ATTR_DST_MAC_ADDRESS,
		  .value.mac = *enaddr },
	};
	char b[INET6_ADDRSTRLEN];
	int ret;

	if (rte_atomic32_read(&llt->lle_size) >= nd6_cfg.nd6_max_entry) {
		ND6NBR_INC(tablimit);
		return NULL;
	}

	lle = llentry_new(&sin6, sizeof(sin6), ifp);
	if (!lle)
		return NULL;

	lle->ll_expire = secs ? rte_get_timer_cycles() +
		rte_get_timer_hz() * secs : 0;

	lle->la_state = state;
	lle->la_flags = (LLE_VALID | flags);
	ll_addr_set(lle, enaddr);

	ND6_DEBUG("%s/%s Create valid, state %s\n", ifp->if_name,
		  ip6_sprintf(addr), nd6_dbgstate[lle->la_state]);

	struct cds_lfht_node *node;

	node = cds_lfht_add_unique(llt->llt_hash,
				   lla_hash6(llt, addr),
				   lla_match6, addr, &lle->ll_node);

	if (unlikely(node != &lle->ll_node)) {
		/*
		 * We lost a table entry insertion race
		 * Only other creator of entries (ouside ND worker)
		 * is a forwarding thread
		 */
		llentry_free(lle);
		lle = caa_container_of(node, struct llentry, ll_node);
		nd6_entry_amend(ifp, lle, ND6_LLINFO_REACHABLE, enaddr, secs,
				(LLE_VALID | flags));
	} else {
		rte_atomic32_inc(&llt->lle_size);
		if (is_main_thread() && if_is_features_mode_active(
			    lle->ifp, IF_FEAT_MODE_EVENT_L3_FAL_ENABLED)) {
			ret = fal_ip6_new_neigh(ifp->if_index, ifp->fal_l3,
						&sin6,
						RTE_DIM(attr_list), attr_list);
			if (ret < 0 && ret != -EOPNOTSUPP) {
				RTE_LOG(NOTICE, DATAPLANE,
					"FAL new neighbour for %s, %s failed: %s\n",
					inet_ntop(AF_INET6, &sin6.sin6_addr,
						  b, sizeof(b)),
					ifp->if_name, strerror(-ret));
			}
			if (ret >= 0) {
				rte_spinlock_lock(&lle->ll_lock);
				lle->la_flags |= LLE_CREATED_IN_HW;
				rte_spinlock_unlock(&lle->ll_lock);
			}
		} else {
			rte_spinlock_lock(&lle->ll_lock);
			lle->la_flags |= LLE_HW_UPD_PENDING;
			rte_spinlock_unlock(&lle->ll_lock);
		}
	}

	/*
	 * Fire the timer for this table immediately on main. It
	 * doesn't matter if it fails as it will get picked up on
	 * the next firing in that case.
	 */
	rte_timer_reset(&ifp->if_lltable6->lle_timer, 0,
			SINGLE, rte_get_master_lcore(),
			in6_lladdr_timer, ifp->if_lltable6);

	return lle;
}

/*
 * Send an NA packet
 */
static void
nd6_na_output(struct ifnet *ifp, const struct rte_ether_addr *lladdr,
	      const struct in6_addr *daddr6,
	      const struct in6_addr *taddr6, uint32_t flags,
	      int tlladdr)
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *eh;
	struct ip6_hdr *ip6;
	struct nd_neighbor_advert *nd_na;
	const struct in6_addr *src;
	uint16_t paylen, optlen, pktlen;

	/*
	 * Virtual interfaces have no valid portid, so use portid 0. And do so
	 * for all interfaces for reasons of consistency. This is safe as the
	 * mbuf pool stays in use even if the device for portid 0 is unplugged.
	 */
	m = pktmbuf_alloc(mbuf_pool(0), if_vrfid(ifp));
	if (!m) {
		ND6NBR_INC(mpoolfail);
		return;
	}

	dp_pktmbuf_l2_len(m) = RTE_ETHER_HDR_LEN;
	paylen = sizeof(*nd_na);
	if (tlladdr) {
		optlen = (sizeof(struct nd_opt_hdr) +
			  RTE_ETHER_ADDR_LEN + 7) & ~7;
		paylen += optlen;
	}
	pktlen = sizeof(*eh) + sizeof(*ip6) + paylen;

	eh = (struct rte_ether_hdr *)rte_pktmbuf_append(m, pktlen);
	rte_ether_addr_copy(&ifp->eth_addr, &eh->s_addr);
	if (lladdr)
		rte_ether_addr_copy(lladdr, &eh->d_addr);
	eh->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	ip6 = (struct ip6_hdr *)(eh + 1);
	ip6->ip6_flow = htonl(IPTOS_PREC_INTERNETCONTROL << 20);
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	ip6->ip6_plen = htons((uint16_t)paylen);
	ip6->ip6_dst = *daddr6;

	/*
	 * Use linklocal source
	 */
	src = nd6_select_source(ifp, 0);
	if (!src) {
		ND6_DEBUG("No source for NA\n");
		rte_pktmbuf_free(m);
		return;
	}
	ip6->ip6_src = *src;

	nd_na = (struct nd_neighbor_advert *)(ip6 + 1);
	nd_na->nd_na_type = ND_NEIGHBOR_ADVERT;
	nd_na->nd_na_code = 0;
	nd_na->nd_na_target = *taddr6;

	/*
	 * Include LLA option if required
	 */
	if (tlladdr) {
		struct nd_opt_hdr *nd_opt = (struct nd_opt_hdr *)(nd_na + 1);

		memset((void *)nd_opt, 0, optlen);
		nd_opt->nd_opt_type = ND_OPT_TARGET_LINKADDR;
		nd_opt->nd_opt_len = optlen >> 3;
		memcpy((void *)(nd_opt + 1),
		       &ifp->eth_addr, RTE_ETHER_ADDR_LEN);
	} else {
		flags &= ~ND_NA_FLAG_OVERRIDE;
	}
	nd_na->nd_na_flags_reserved = flags;
	nd_na->nd_na_cksum = 0;
	nd_na->nd_na_cksum =
	    in6_cksum(ip6, IPPROTO_ICMPV6, sizeof(struct ip6_hdr), paylen);

	ND6_DEBUG("%s/%s Tx NA lla:%d\n", ifp->if_name, ip6_sprintf(taddr6),
		  lladdr ? 1 : 0);
	ND6NBR_INC(natx);

	if (ip6_spath_filter(ifp, &m))
		return;

	/*
	 * Send NA. If we don't have dest MAC then resolve it
	 */
	if (lladdr || !nd6_resolve(NULL, ifp, m, daddr6, &eh->d_addr))
		if_output(ifp, m, NULL, ntohs(eh->ether_type));
}

/*
 * Process received Neighbor Solicitation
 * Return 1 if control plane needs to see packet
 */
static int
nd6_ns_input(struct ifnet *ifp, struct rte_mbuf *m, unsigned int off,
	     unsigned int icmp6len)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct nd_neighbor_solicit *nd_ns;
	struct in6_addr saddr6 = ip6->ip6_src;
	struct in6_addr daddr6 = ip6->ip6_dst;
	struct in6_addr taddr6;
	const struct in6_addr *dest;
	const struct rte_ether_addr *lladdr = NULL;
	union nd_opts ndopts;
	char buf0[INET6_ADDRSTRLEN], buf1[INET6_ADDRSTRLEN],
		buf2[INET6_ADDRSTRLEN];
	uint32_t flags;
	int rc;
	bool punt = false;
	struct ifnet *vrrp_ifp;
	struct sockaddr_storage sock_storage;
	struct sockaddr_in6 *ip_storage =
		(struct sockaddr_in6 *) &sock_storage;

	ND6NBR_INC(nsrx);

	nd_ns = ip6_exthdr(m, off, icmp6len);
	if (!nd_ns)
		goto bad;

	taddr6 = nd_ns->nd_ns_target;
	ND6_DEBUG("%s/%s Rx NS src %s dst %s\n", ifp->if_name,
		  PRINT6(&taddr6, buf0), PRINT6(&saddr6, buf1),
		  PRINT6(&daddr6, buf2));

	if ((IN6_IS_ADDR_LOOPBACK(&taddr6) &&
	     !(ifp->if_flags & IFF_LOOPBACK)) || IN6_IS_ADDR_MULTICAST(&taddr6))
		goto bad;

	if (IN6_IS_ADDR_UNSPECIFIED(&saddr6)) {
		/* dst has to be a solicited node multicast address. */
		if (daddr6.s6_addr16[0] == IPV6_ADDR_INT16_MLL &&
		    daddr6.s6_addr32[1] == 0 &&
		    daddr6.s6_addr32[2] == IPV6_ADDR_INT32_ONE &&
		    daddr6.s6_addr[12] == 0xff)
			; /* good */
		else
			goto bad;
	}

	icmp6len -= sizeof(*nd_ns);
	nd6_option_init(nd_ns + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0)
		goto bad;

	if (ndopts.nd_opts_src_lladdr) {
		lladdr = (const struct rte_ether_addr *)
			(ndopts.nd_opts_src_lladdr + 1);
		if (!rte_is_valid_assigned_ether_addr(lladdr)) {
			char buf[ETH_ADDR_STR_LEN];
			ND6_DEBUG("Bad MAC %s\n",
				  ether_ntoa_r(lladdr, buf));
			goto bad;
		}
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&saddr6) && lladdr) {
		ND6_DEBUG("%s bad DAD packet, LLA\n", ifp->if_name);
		goto bad;
	}

	/*
	 * Check for us. Also detect impersonators
	 */
	rc = nd6_forus(ifp, &saddr6, &taddr6);
	ip_storage->sin6_family = AF_INET6;
	ip_storage->sin6_addr = taddr6;
	vrrp_ifp = macvlan_get_vrrp_ip_if(ifp,
					  (struct sockaddr *)&sock_storage);
	if (unlikely(rc != 0 && vrrp_ifp == NULL)) {
		if (rc == -EADDRINUSE) {
			nd6_log_conflict(ifp, lladdr, &saddr6);
		} else {
			/*
			 * Not apparently for us.
			 * Let controller see DAD NS
			 */
			if (IN6_IS_ADDR_UNSPECIFIED(&saddr6))
				return 1;
			ND6NBR_INC(rxignored);
		}
		goto freeit;
	}

	/*
	 * Glean on SLLA
	 * Create a Stale entry if non exists
	 * Amend an existing entry if MAC change
	 */
	if (lladdr) {
		struct llentry *la = NULL;

		la = in6_lltable_lookup(ifp, 0, &saddr6);
		if (!la) {
			nd6_create_valid(ifp, &saddr6, ND6_LLINFO_STALE,
					 lladdr, nd6_cfg.nd6_scavenge_time, 0);
			if (nd6_sync)
				punt = true;
		} else {
			if (!rte_ether_addr_equal(lladdr, &la->ll_addr)) {
				nd6_entry_amend(ifp, la, ND6_LLINFO_STALE,
						lladdr,
						nd6_cfg.nd6_scavenge_time,
						LLE_VALID);
				if (nd6_sync)
					punt = true;
			}
		}
	}

	/*
	 * Should not send OVERRIDE if anycast or proxy
	 */
	flags = (ND_NA_FLAG_OVERRIDE | ND_NA_FLAG_SOLICITED |
		 ND_NA_FLAG_ROUTER);

	/*
	 * Multicast response to DAD NS
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&saddr6)) {
		dest = &in6addr_allnodes;
		lladdr = (const struct rte_ether_addr *)in6ether_allnodes;
		flags &= ~ND_NA_FLAG_SOLICITED;
	} else {
		dest = &saddr6;
	}
	nd6_na_output(ifp, lladdr, dest, &taddr6, flags, 1);
	if (punt) {
		ND6NBR_INC(ndpunt);
		return 1;
	}
freeit:
	rte_pktmbuf_free(m);
	return 0;
bad:
	ND6_DEBUG("Bad NS on %s\n", ifp->if_name);
	ND6NBR_INC(badpkt);
	rte_pktmbuf_free(m);
	return 0;
}

/*
 * Process received Neighbor Advertisement
 * Return 1 if control plane needs to see packet
 */
static int
nd6_na_input(struct ifnet *ifp, struct rte_mbuf *m,
	     unsigned int off, int icmp6len)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct nd_neighbor_advert *nd_na;
	struct in6_addr daddr6 = ip6->ip6_dst;
	struct in6_addr saddr6 = ip6->ip6_src;
	struct in6_addr taddr6;
	struct llentry *la = NULL;
	int flags;
	int is_solicited;
	int is_override;
	int is_mcast;
	const struct rte_ether_addr *lladdr = NULL;
	int lladdrlen = 0;
	struct if_addr *ifa;
	union nd_opts ndopts;
	int mac_addrlen = sizeof(struct rte_ether_addr);
	char buf0[INET6_ADDRSTRLEN], buf1[INET6_ADDRSTRLEN],
		buf2[INET6_ADDRSTRLEN];
	bool punt = false;

	ND6NBR_INC(narx);

	nd_na = ip6_exthdr(m, off, icmp6len);
	if (!nd_na)
		goto bad;

	flags = nd_na->nd_na_flags_reserved;
	is_solicited = ((flags & ND_NA_FLAG_SOLICITED) != 0);
	is_override = ((flags & ND_NA_FLAG_OVERRIDE) != 0);
	is_mcast = IN6_IS_ADDR_MULTICAST(&daddr6);

	taddr6 = nd_na->nd_na_target;
	ND6_DEBUG("%s/%s Rx NA src %s dst %s (s:%d o:%d)\n", ifp->if_name,
		  PRINT6(&taddr6, buf0), PRINT6(&saddr6, buf1),
		  PRINT6(&daddr6, buf2), is_solicited, is_override);

	if ((IN6_IS_ADDR_LOOPBACK(&taddr6) &&
	     !(ifp->if_flags & IFF_LOOPBACK)) ||
		IN6_IS_ADDR_MULTICAST(&taddr6))
		goto bad;

	if (is_solicited && is_mcast)
		goto bad;

	/*
	 * Get options and look for TLLA
	 */
	icmp6len -= sizeof(*nd_na);
	nd6_option_init(nd_na + 1, icmp6len, &ndopts);
	if (nd6_options(&ndopts) < 0) {
		ND6_DEBUG("NA has invalid option, ignored\n");
		goto bad;
	}

	if (ndopts.nd_opts_tgt_lladdr) {
		lladdr = (const struct rte_ether_addr *)
			(ndopts.nd_opts_tgt_lladdr + 1);
		lladdrlen = ndopts.nd_opts_tgt_lladdr->nd_opt_len << 3;
		if (!rte_is_valid_assigned_ether_addr(lladdr)) {
			char buf[ETH_ADDR_STR_LEN];

			ND6_DEBUG("Bad MAC %s\n",
				  ether_ntoa_r(lladdr, buf));
			goto bad;
		}
	}

	/*
	 * Check for someone claiming to own our address
	 */
	ifa = in6ifa_ifpwithaddr(ifp, &taddr6);
	if (ifa) {
		nd6_log_conflict(ifp, (const struct rte_ether_addr *)lladdr,
				 &taddr6);
		goto freeit;
	}

	if (lladdr && ((mac_addrlen + 2 + 7) & ~7) != lladdrlen) {
		ND6_DEBUG("nd6_na_input: lladdrlen mismatch for %s "
			  "(if %d, NA packet %d)\n", ip6_sprintf(&taddr6),
			  mac_addrlen, lladdrlen - 2);
		goto bad;
	}

	/*
	 * Lookup target in ND cache. If we don't have an entry
	 * then assume its for the control plane
	 */
	la = in6_lltable_lookup(ifp, 0, &taddr6);
	if (!la) {
		punt = true;
		goto done;
	}

	/*
	 * Never modify Static entries
	 */
	if (la->la_flags & LLE_STATIC)
		goto done;

	/*
	 * Incomplete
	 */
	if (!(la->la_flags & LLE_VALID)) {
		uint8_t state;
		uint16_t time;

		if (!lladdr) {
			ND6_DEBUG("NA, no target LLA\n");
			goto done;
		}

		if (is_solicited) {
			state = ND6_LLINFO_REACHABLE;
			time = nd6_cfg.nd6_reachable_time;
		} else {
			state = ND6_LLINFO_STALE;
			time = ND6_SCAVENGE_TIME;
		}
		/*
		 * Make entry complete
		 */
		nd6_entry_amend(ifp, la, state, lladdr, time, LLE_VALID);
		goto done;
	}

	/*
	 * Complete entry.
	 * Any change below does not affect forwarding
	 */
	int llchange = 0;

	/*
	 * Give packet to control plane if:
	 * - unrequested NA
	 * - DAD defence
	 * - control plane has interest in entry
	 */
	rte_spinlock_lock(&la->ll_lock);
	punt = (la->la_state != ND6_LLINFO_PROBE) ||
		(!is_solicited && is_mcast) ||
		(la->la_flags & LLE_CTRL);

	llchange = (lladdr &&
		    !rte_ether_addr_equal(lladdr, &la->ll_addr));

	if (!is_override && llchange) {
		if (la->la_state == ND6_LLINFO_REACHABLE)
			nd6_change_state(ifp, la, ND6_LLINFO_STALE,
					 nd6_cfg.nd6_scavenge_time);
		rte_spinlock_unlock(&la->ll_lock);
		goto done;
	}

	if (is_override || !llchange) {
		if (llchange) {
			nd6_update_lla(ifp, la, lladdr);
			if (!is_solicited)
				nd6_change_state(ifp, la, ND6_LLINFO_STALE,
						 nd6_cfg.nd6_scavenge_time);
		}
		if (is_solicited && (la->la_state != ND6_LLINFO_REACHABLE))
			nd6_change_state(ifp, la, ND6_LLINFO_REACHABLE,
					 ND6_REACHABLE_TIME);
	}
	rte_spinlock_unlock(&la->ll_lock);
done:
	if (punt) {
		ND6_DEBUG("%s/%s NA for control plane\n", ifp->if_name,
			  ip6_sprintf(&taddr6));
		ND6NBR_INC(ndpunt);
		return 1;
	}
freeit:
	rte_pktmbuf_free(m);
	return 0;
bad:
	ND6_DEBUG("Bad NA on %s\n", ifp->if_name);
	ND6NBR_INC(badpkt);
	rte_pktmbuf_free(m);
	return 0;
}

/*
 * Build a Neighbor Solicitation Message.
 */
static struct rte_mbuf *
nd6_ns_build(struct ifnet *ifp, const struct in6_addr *res_src,
	     const struct in6_addr *taddr6,
	     const struct rte_ether_addr *dst_mac)
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *eh;
	struct ip6_hdr *ip6;
	struct nd_neighbor_solicit *nd_ns;
	const struct in6_addr *src;
	struct nd_opt_hdr *nd_opt;
	uint16_t paylen, optlen, pktlen;

	/*
	 * Virtual interfaces have no valid portid, so use portid 0. And do so
	 * for all interfaces for reasons of consistency. This is safe as the
	 * mbuf pool stays in use even if the device for portid 0 is unplugged.
	 */
	m = pktmbuf_alloc(mbuf_pool(0), if_vrfid(ifp));
	if (!m) {
		ND6NBR_INC(mpoolfail);
		return NULL;
	}

	dp_pktmbuf_l2_len(m) = RTE_ETHER_HDR_LEN;
	optlen = (sizeof(struct nd_opt_hdr) + RTE_ETHER_ADDR_LEN + 7) & ~7;
	paylen = sizeof(*nd_ns) + optlen;
	pktlen = sizeof(*eh) + sizeof(*ip6) + paylen;

	eh = (struct rte_ether_hdr *)rte_pktmbuf_append(m, pktlen);
	rte_ether_addr_copy(&ifp->eth_addr, &eh->s_addr);
	eh->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	ip6 = (struct ip6_hdr *)(eh + 1);
	ip6->ip6_flow = htonl(IPTOS_PREC_INTERNETCONTROL << 20);
	ip6->ip6_vfc &= ~IPV6_VERSION_MASK;
	ip6->ip6_vfc |= IPV6_VERSION;
	ip6->ip6_nxt = IPPROTO_ICMPV6;
	ip6->ip6_hlim = 255;
	ip6->ip6_plen = htons((uint16_t)paylen);

	/*
	 * Use destination address if unicast. Otherwise
	 * send to solicited node mcast for target
	 */
	if (dst_mac) {
		ip6->ip6_dst = *taddr6;
		rte_ether_addr_copy(dst_mac, &eh->d_addr);
	} else {
		ip6->ip6_dst.s6_addr16[0] = IPV6_ADDR_INT16_MLL;
		ip6->ip6_dst.s6_addr16[1] = 0;
		ip6->ip6_dst.s6_addr32[1] = 0;
		ip6->ip6_dst.s6_addr32[2] = IPV6_ADDR_INT32_ONE;
		ip6->ip6_dst.s6_addr32[3] = taddr6->s6_addr32[3];
		ip6->ip6_dst.s6_addr[12] = 0xff;

		eh->d_addr.addr_bytes[0] = 0x33;
		eh->d_addr.addr_bytes[1] = 0x33;
		memcpy(&eh->d_addr.addr_bytes[2], &ip6->ip6_dst.s6_addr[12], 4);
	}

	/*
	 * Use data source if local address, otherwise linklocal
	 */
	src = nd6_select_source(ifp, res_src);
	if (!src) {
		ND6_DEBUG("No source for NS\n");
		rte_pktmbuf_free(m);
		return NULL;
	}
	ip6->ip6_src = *src;

	nd_ns = (struct nd_neighbor_solicit *)(ip6 + 1);
	nd_ns->nd_ns_type = ND_NEIGHBOR_SOLICIT;
	nd_ns->nd_ns_code = 0;
	nd_ns->nd_ns_reserved = 0;
	nd_ns->nd_ns_target = *taddr6;

	nd_opt = (struct nd_opt_hdr *)(nd_ns + 1);
	memset((void *)nd_opt, 0, optlen);
	nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	nd_opt->nd_opt_len = optlen >> 3;
	rte_ether_addr_copy(&ifp->eth_addr, (void *)(nd_opt + 1));

	nd_ns->nd_ns_cksum = 0;
	nd_ns->nd_ns_cksum =
	    in6_cksum(ip6, IPPROTO_ICMPV6, sizeof(*ip6), paylen);

	ND6_DEBUG("%s/%s Tx NS\n", ifp->if_name, ip6_sprintf(taddr6));
	ND6NBR_INC(nstx);

	return m;
}

static void nd6_ns_output(struct ifnet *ifp,
			  const struct in6_addr *res_src,
			  const struct in6_addr *taddr6,
			  const struct rte_ether_addr *dst_mac)
{
	struct rte_mbuf *m;

	m = nd6_ns_build(ifp, res_src, taddr6, dst_mac);

	if (m) {
		if (!ip6_spath_filter(ifp, &m))
			if_output(ifp, m, NULL, ETH_P_IPV6);
	}
}

/*
 * Resolve ipv6 destination for a forwarded data packet.
 * Return zero on success, non-zero if packet consumed
 */
int nd6_resolve(struct ifnet *in_ifp, struct ifnet *ifp,
		struct rte_mbuf *m, const struct in6_addr *addr,
		struct rte_ether_addr *desten)
{
	struct lltable *llt = ifp->if_lltable6;
	struct llentry *la;
	char b[INET6_ADDRSTRLEN];
	bool send_ns = false;

lookup:
	la = in6_lltable_lookup(ifp, 0, addr);
	if (likely(la && (la->la_flags & LLE_VALID))) {
resolved:
		rte_atomic16_clear(&la->ll_idle);
		rte_ether_addr_copy(&la->ll_addr, desten);
		return 0;
	}

	/* Create if necessary */
	if (la == NULL) {

		/*
		 * Check resolution and cache size limits
		 */
		if (unlikely(rte_atomic16_read(&llt->lle_restoken) <= 0)) {
			ND6NBR_INC(resthrot);
			rte_pktmbuf_free(m);
			return -ENOMEM;
		}
		if (unlikely(rte_atomic32_read(&llt->lle_size) >=
			     nd6_cfg.nd6_max_entry)) {
			ND6NBR_INC(tablimit);
			rte_pktmbuf_free(m);
			return -ENOMEM;
		}

		la = in6_lltable_lookup(ifp, LLE_CREATE, addr);
		if (unlikely(la == NULL)) {
			RTE_LOG(NOTICE, ND6,
				"in6_lltable_lookup create failed\n");
			rte_pktmbuf_free(m);
			return -ENOMEM;
		}

		ND6_DEBUG("%s/%s new entry\n", ifp->if_name,
			  PRINT6(addr, b));
	}

	/* Lock entry to hold off update and timer */
	rte_spinlock_lock(&la->ll_lock);

	if (unlikely(la->la_flags & LLE_VALID)) {
		rte_spinlock_unlock(&la->ll_lock);
		goto resolved;
	}

	if (unlikely(la->la_flags & LLE_DELETED)) {
		rte_spinlock_unlock(&la->ll_lock);
		goto lookup;
	}

	/*
	 * Incomplete ND cache entry. Queue packet on entry
	 * Discard oldest if queue limit is exceeded
	 */
	if (in_ifp)
		pktmbuf_save_ifp(m, in_ifp);
	if (la->la_numheld >= nd6_cfg.nd6_maxhold) {
		ND6NBR_INC(dropped);
		rte_pktmbuf_free(la->la_held[0]);
		memmove(&la->la_held[0], &la->la_held[1],
			(nd6_cfg.nd6_maxhold - 1) * sizeof(la->la_held[0]));
		la->la_held[nd6_cfg.nd6_maxhold - 1] = m;
	} else {
		la->la_held[la->la_numheld++] = m;
	}

	/*
	 * Build and send an NS if newly-created
	 */
	if (!la->la_asked) {
		la->la_asked = 1;
		send_ns = true;
	}
	rte_spinlock_unlock(&la->ll_lock);

	if (send_ns) {
		struct ip6_hdr *ip6 = ip6hdr(m);

		nd6_ns_output(ifp, &ip6->ip6_src, addr, NULL);
	}

	return -EWOULDBLOCK;
}

/*
 * Check if the locally-terminating packet is an ND NA/NS.
 * return 0 if consumed, otherwise 1
 */
int nd6_input(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	struct icmp6_hdr *icmp6;
	unsigned int off, icmp6len;

	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
		return 1;

	off = dp_pktmbuf_l2_len(m) + sizeof(*ip6);
	icmp6 = ip6_exthdr(m, off, sizeof(*icmp6));
	if (unlikely(!icmp6)) {
		IP6STAT_INC(if_vrfid(ifp), IPSTATS_MIB_INDISCARDS);
		rte_pktmbuf_free(m);
		return 0;
	}

	if ((icmp6->icmp6_type != ND_NEIGHBOR_SOLICIT) &&
	    (icmp6->icmp6_type != ND_NEIGHBOR_ADVERT))
		return 1;

	if (unlikely(icmp6->icmp6_code != 0)) {
		ND6NBR_INC(badpkt);
		rte_pktmbuf_free(m);
		return 0;
	}

	if (unlikely(ip6->ip6_hlim != 255)) {
		ND6NBR_INC(badpkt);
		rte_pktmbuf_free(m);
		return 0;
	}

	uint16_t plen;

	plen = htons(ip6->ip6_plen);
	plen -= (char *)icmp6 - ((char *)ip6 + sizeof(*ip6));
	if (in6_cksum(ip6, IPPROTO_ICMPV6, sizeof(*ip6), plen) != 0) {
		ND6_DEBUG("Bad ND cksum on %s\n", ifp->if_name);
		ND6NBR_INC(badpkt);
		rte_pktmbuf_free(m);
		return 0;
	}

	ND6NBR_INC(received);
	icmp6len = rte_pktmbuf_pkt_len(m) - off;

	switch (icmp6->icmp6_type) {
	case ND_NEIGHBOR_SOLICIT:
		return nd6_ns_input(ifp, m, off, icmp6len);

	case ND_NEIGHBOR_ADVERT:
		return nd6_na_input(ifp, m, off, icmp6len);

	default:
		return 1;
	}
}

/*
 * Walk the ND6 table.
 * Only called by console (main thread);
 * Can not be called safely from forwarding loop.
 */
void
nd6_nbr_walk(const struct ifnet *ifp, ll_walkhash_f_t *f, void *arg)
{
	const struct lltable *llt = ifp->if_lltable6;
	struct llentry	*lle;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(llt->llt_hash, &iter, lle, ll_node) {
		(*f)(ifp, lle, arg);
	}
}

/*
 * Destroy an ND cache entry
 * Caller must have a spinlock on the entry
 */
void
nd6_entry_destroy(struct lltable *llt, struct llentry *lle)
{
	unsigned int pkts_dropped;

	if (lle->la_flags & LLE_DELETED)
		return;

	/*
	 * Update resolution tokens
	 */
	if (!(lle->la_flags & LLE_VALID) &&
	    rte_atomic16_read(&llt->lle_restoken) < nd6_cfg.nd6_res_token)
		rte_atomic16_inc(&llt->lle_restoken);

	pkts_dropped = llentry_destroy(llt, lle);

	ND6NBR_ADD(dropped, pkts_dropped);
}

/*
 * Fast link layer address lookup function for IPv6
 * Assumes dp_rcu_read_lock
 */
struct llentry *
lla_lookup6(struct lltable *llt, const struct in6_addr *addr)
{
	struct cds_lfht_iter iter;

	cds_lfht_lookup(llt->llt_hash,
			lla_hash6(llt, addr),
			lla_match6, addr, &iter);

	struct cds_lfht_node *node = cds_lfht_iter_get_node(&iter);

	return likely(node != NULL)
		? caa_container_of(node, struct llentry, ll_node) : NULL;
}

/*
 * Return NULL if not found or marked for deletion.
 */
struct llentry *
in6_lltable_lookup(struct ifnet *ifp, u_int flags,
		   const struct in6_addr *addr)
{
	struct lltable *llt = ifp->if_lltable6;
	struct llentry *lle;
	char b[INET6_ADDRSTRLEN];
	int ret;

	lle = lla_lookup6(llt, addr);
	if (unlikely(lle == NULL)) {
		struct sockaddr_in6 sin6 = {
			.sin6_family =	AF_INET6,
			.sin6_addr = *addr,
		};
		const struct fal_attribute_t attr_list[] = {
		};

		if (!(flags & LLE_CREATE))
			return NULL;

		ND6_DEBUG("%s/%s Create\n", ifp->if_name, ip6_sprintf(addr));

		lle = llentry_new(&sin6, sizeof(sin6), ifp);
		if (lle == NULL)
			return NULL;

		lle->la_state = ND6_LLINFO_INCOMPLETE;

		/* Use a 1 second timeout for now */
		lle->ll_expire = 1 * rte_get_timer_hz();
		lle->la_flags = flags & ~LLE_CREATE;
		lle->la_asked = 0;

		struct cds_lfht_node *node;
		node = cds_lfht_add_unique(llt->llt_hash,
					   lla_hash6(llt, addr),
					   lla_match6, addr, &lle->ll_node);

		/* If lost race on insert, use the winner. */
		if (unlikely(node != &lle->ll_node)) {
			llentry_free(lle);
			lle = caa_container_of(node, struct llentry, ll_node);
		} else {
			rte_atomic32_inc(&llt->lle_size);
			if (is_main_thread() && if_is_features_mode_active(
				    lle->ifp,
				    IF_FEAT_MODE_EVENT_L3_FAL_ENABLED)) {
				ret = fal_ip6_new_neigh(ifp->if_index,
							ifp->fal_l3, &sin6,
							RTE_DIM(attr_list),
							attr_list);
				if (ret < 0 && ret != -EOPNOTSUPP) {
					RTE_LOG(NOTICE, DATAPLANE,
						"FAL new neighbour for %s, %s failed: %s\n",
						inet_ntop(AF_INET6,
							  &sin6.sin6_addr,
							  b, sizeof(b)),
						ifp->if_name, strerror(-ret));
				}
				if (ret >= 0) {
					rte_spinlock_lock(&lle->ll_lock);
					lle->la_flags |= LLE_CREATED_IN_HW;
					rte_spinlock_unlock(&lle->ll_lock);
				}
			} else {
				rte_spinlock_lock(&lle->ll_lock);
				lle->la_flags |= LLE_HW_UPD_PENDING;
				rte_spinlock_unlock(&lle->ll_lock);
			}

			/*
			 * Fire the timer for this table immediately
			 * on main. It doesn't matter if it fails as
			 * it will get picked up on the next firing in
			 * that case.
			 */
			rte_timer_reset(&ifp->if_lltable6->lle_timer, 0,
					SINGLE, rte_get_master_lcore(),
					in6_lladdr_timer, ifp->if_lltable6);

			/*
			 * Count outstanding resolutions
			 */
			if (!(flags & LLE_VALID))
				rte_atomic16_dec(&llt->lle_restoken);
		}
	} else if (flags & LLE_DELETE) {
		/*
		 * Only delete static entries or stale entries that are idle.
		 * Leave dynamic in-use entries to time out - kernel may
		 * think they are stale but they may be in active use
		 * by the dataplane.
		 */
		if ((lle->la_flags & LLE_STATIC) ||
		    ((lle->la_state == ND6_LLINFO_STALE) &&
		     !llentry_has_been_used(lle))) {
			ND6_DEBUG("%s/%s Delete\n", ifp->if_name,
				  ip6_sprintf(addr));

			rte_spinlock_lock(&lle->ll_lock);
			nd6_entry_destroy(llt, lle);
			rte_spinlock_unlock(&lle->ll_lock);
			lle = NULL;
		}
	}

	return lle;
}

/*
 * Called from main thread
 * Handle ND cache change notification from control plane
 */
int
nd6_lladdr_add(struct ifnet *ifp, struct in6_addr *addr,
	       const struct rte_ether_addr *mac, uint16_t state,
	       uint8_t ntf_flags)
{
	struct llentry *lle;
	uint8_t flags = 0;
	uint16_t secs = 0;

	ND6_DEBUG("%s/%s ADD state %s (0x%x) ntf %x\n", ifp->if_name,
		  ip6_sprintf(addr),
		  (state == NUD_PERMANENT) ? "PERM" :
		  (state == NUD_REACHABLE) ? "REACH" :
		  (state == NUD_FAILED) ? "FAIL" :
		  (state == NUD_STALE) ? "STALE" : "Other",
		  state, ntf_flags);

	if (!(state & (NUD_PERMANENT | NUD_REACHABLE | NUD_FAILED)))
		return 0;

	dp_rcu_read_lock();

	lle = in6_lltable_lookup(ifp, 0, addr);

	if (state & NUD_PERMANENT) {
		flags = LLE_STATIC;
	} else if (state & NUD_REACHABLE) {
		flags = LLE_CTRL;
		secs = nd6_cfg.nd6_reachable_time;
	}

	if (state & NUD_FAILED) {
		/*
		 * Ignore fail notification unless entry exists.
		 */
		if (lle) {
			struct lltable *llt = ifp->if_lltable6;
			rte_spinlock_lock(&lle->ll_lock);
			nd6_entry_destroy(llt, lle);
			rte_spinlock_unlock(&lle->ll_lock);
		}
	} else {
		/*
		 * Entry is reachable in control plane so
		 * make it the same here.
		 */
		if (lle) {
			nd6_entry_amend(ifp, lle, ND6_LLINFO_REACHABLE, mac,
					secs, (flags | LLE_VALID));
		} else {
			nd6_create_valid(ifp, addr, ND6_LLINFO_REACHABLE,
					 mac, secs, flags);
		}
	}

	dp_rcu_read_unlock();

	return 0;
}

/*
 * the caller acquires and releases the lock on the lltbls
 * Returns the llentry locked
 */
struct llentry *
nd6_lookup(const struct in6_addr *addr6, const struct ifnet *ifp)
{
	return lla_lookup6(ifp->if_lltable6, addr6);
}

/*
 * Handle unreachable neighbour
 * Caller must have a spinlock on the entry if required
 */
static void
nd6_unreachable(struct ifnet *ifp, struct llentry *lle,
		struct rte_mbuf **m_for_icmp_unreach,
		struct ifnet **ifp_for_icmp_unreach)
{
	struct lltable *llt = ifp->if_lltable6;

	/*
	 * Do a rate-limited Destination Unreachable
	 * Do not attempt for locally-generated packet
	 */
	if (lle->la_numheld > 0) {
		struct rte_mbuf *m = lle->la_held[0];
		struct ifnet *in_ifp = pktmbuf_restore_ifp(m);

		if (llt->lle_unrtoken && in_ifp) {
			llt->lle_unrtoken--;
			/*
			 * We have the spinlock held for the ND entry,
			 * so defer the sending of the ICMP unreachable
			 * until later to minimise the time that the lock
			 * is held and to avoid a deadlock when the
			 * response needs to use the same entry that is
			 * being resolved.
			 */
			*m_for_icmp_unreach = m;
			*ifp_for_icmp_unreach = in_ifp;
			/*
			 * First pkt will be consumed, flush rest of
			 * queued data.
			 */
			if (lle->la_numheld > 1)
				pktmbuf_free_bulk(&lle->la_held[1],
						  lle->la_numheld - 1);
		} else {
			/* Flush queued data */
			pktmbuf_free_bulk(lle->la_held, lle->la_numheld);
		}
		ND6NBR_ADD(dropped, lle->la_numheld);
		lle->la_numheld = 0;
	}
	nd6_entry_destroy(llt, lle);
}

/*
 * Resolution retry timer expiry
 */
static struct rte_mbuf *
nd6_resolve_timeout(struct lltable *llt, struct llentry *lle,
		    uint64_t cur_time, bool nud,
		    struct rte_mbuf **m_for_icmp_unreach,
		    struct ifnet **ifp_for_icmp_unreach)
{
	struct ifnet *ifp = llt->llt_ifp;

	if (++lle->la_asked <= nd6_cfg.nd6_ns_retries) {
		struct sockaddr_in6 *sin6 = satosin6(ll_sockaddr(lle));

		/*
		 * Assume 1-second timeout
		 */
		lle->ll_expire = cur_time + rte_get_timer_hz();

		return nd6_ns_build(ifp, NULL, &sin6->sin6_addr,
				    nud ? &lle->ll_addr : NULL);
	}

	/*
	 * Reached retry limit. Delete entry
	 */
	ND6_DEBUG("%s/%s Retry limit\n", ifp->if_name,
		  lladdr_ntop6(lle));

	if (nud)
		ND6NBR_INC(nudfail);
	else
		ND6NBR_INC(timeouts);

	nd6_unreachable(ifp, lle, m_for_icmp_unreach,
			ifp_for_icmp_unreach);
	return NULL;
}

static struct rte_mbuf *
nd6_reachable_timeout(struct lltable *llt, struct llentry *lle)
{
	struct ifnet *ifp = llt->llt_ifp;

	nd6_change_state(ifp, lle, ND6_LLINFO_STALE, nd6_cfg.nd6_scavenge_time);

	return NULL;
}

static struct rte_mbuf *
nd6_stale_timeout(struct lltable *llt, struct llentry *lle,
		  uint64_t cur_time __unused)
{
	struct ifnet *ifp = llt->llt_ifp;

	ND6_DEBUG("%s/%s, Scavenge\n", ifp->if_name, lladdr_ntop6(lle));
	nd6_entry_destroy(llt, lle);

	return NULL;
}

static struct rte_mbuf *
nd6_delay_timeout(struct lltable *llt, struct llentry *lle)
{
	struct ifnet *ifp = llt->llt_ifp;
	struct sockaddr_in6 *sin6 = satosin6(ll_sockaddr(lle));

	lle->la_asked = 1;
	nd6_change_state(ifp, lle, ND6_LLINFO_PROBE, 1);

	/*
	 * NUD NS are unicast to destination
	 */
	return nd6_ns_build(ifp, NULL, &sin6->sin6_addr, &lle->ll_addr);
}

/*
 * Age ND cache entries and call expiry routine
 */
static void
in6_ll_age(struct lltable *llt, struct llentry *lle, uint64_t cur_time)
{
	struct ifnet *ifp = llt->llt_ifp;

	/*
	 * Check for traffic in Stale state
	 */
	if (llentry_has_been_used_and_clear(lle) &&
	    (lle->la_state == ND6_LLINFO_STALE)) {
		rte_spinlock_lock(&lle->ll_lock);
		if (lle->la_state == ND6_LLINFO_STALE)
			nd6_change_state(ifp, lle, ND6_LLINFO_DELAY,
					 nd6_cfg.nd6_delay_time);
		rte_spinlock_unlock(&lle->ll_lock);

		return;
	}

	if ((int64_t)(cur_time - lle->ll_expire) >= 0) {
		struct rte_mbuf *m = NULL;
		struct rte_mbuf *m_for_icmp_unreach = NULL;
		struct ifnet *ifp_for_icmp_unreach = NULL;

		rte_spinlock_lock(&lle->ll_lock);
		switch (lle->la_state) {
		case ND6_LLINFO_INCOMPLETE:
			m = nd6_resolve_timeout(llt, lle, cur_time, false,
						&m_for_icmp_unreach,
						&ifp_for_icmp_unreach);
			break;

		case ND6_LLINFO_REACHABLE:
			m = nd6_reachable_timeout(llt, lle);
			break;

		case ND6_LLINFO_STALE:
			m = nd6_stale_timeout(llt, lle, cur_time);
			break;

		case ND6_LLINFO_DELAY:
			m = nd6_delay_timeout(llt, lle);
			break;

		case ND6_LLINFO_PROBE:
			m = nd6_resolve_timeout(llt, lle, cur_time, true,
						&m_for_icmp_unreach,
						&ifp_for_icmp_unreach);
			break;

		default:
			nd6_entry_destroy(llt, lle);
			break;
		}
		rte_spinlock_unlock(&lle->ll_lock);

		if (m) {
			if (!ip6_spath_filter(ifp, &m))
				if_output(ifp, m, NULL, ETH_P_IPV6);
		}

		if (m_for_icmp_unreach)
			icmp6_error(ifp_for_icmp_unreach,
				    m_for_icmp_unreach,
				    ICMP6_DST_UNREACH,
				    ICMP6_DST_UNREACH_ADDR, htonl(0));
	}
}

static void
nd6_cache_purge(struct lltable *llt)
{
	struct llentry *lle;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(llt->llt_hash, &iter, lle, ll_node) {
		rte_spinlock_lock(&lle->ll_lock);
		nd6_entry_destroy(llt, lle);
		rte_spinlock_unlock(&lle->ll_lock);
	}
}

static void
nd6_cache_age(struct lltable *llt, bool refresh_timer_expired)
{
	struct llentry *lle;
	struct cds_lfht_iter iter;
	uint64_t cur_time = rte_get_timer_cycles();

	cds_lfht_for_each_entry(llt->llt_hash, &iter, lle, ll_node) {
		if (lle->la_flags & LLE_DELETED) {
			rte_spinlock_lock(&lle->ll_lock);
			__llentry_destroy(llt, lle);
			rte_spinlock_unlock(&lle->ll_lock);
			continue;
		}

		llentry_issue_pending_fal_updates(lle);

		if ((lle->la_flags & (LLE_VALID | LLE_FWDING)) == LLE_VALID)
			llentry_routing_install(lle);

		if (lle->la_flags & LLE_STATIC)
			continue;

		if (lle->ll_expire == 0 || !refresh_timer_expired)
			continue;

		in6_ll_age(llt, lle, cur_time);
	}
}

/*
 * Walk the ll addr table and look for entries that have been used
 */
void in6_lladdr_timer(struct rte_timer *tim __rte_unused, void *arg)
{
	struct lltable *llt = arg;
	struct ifnet *ifp = llt->llt_ifp;
	bool refresh_timer_fired = false;
	uint64_t cur_time = rte_get_timer_cycles();

	if (llt->lle_refresh_expire < cur_time) {
		refresh_timer_fired = true;

		/*
		 * Refresh resolution tokens
		 */
		rte_atomic16_set(&llt->lle_restoken, nd6_cfg.nd6_res_token);
		llt->lle_unrtoken = nd6_cfg.nd6_unr_token;

		/* one second later */
		llt->lle_refresh_expire = cur_time + rte_get_timer_hz();
	}

	dp_rcu_read_lock();
	if (!(ifp->if_flags & IFF_UP))
		nd6_cache_purge(llt);
	else
		nd6_cache_age(llt, refresh_timer_fired);

	cur_time = rte_get_timer_cycles();
	rte_timer_reset(&llt->lle_timer,
			llt->lle_refresh_expire < cur_time ? 0 :
			llt->lle_refresh_expire - cur_time,
			SINGLE, rte_get_master_lcore(),
			in6_lladdr_timer, llt);
	dp_rcu_read_unlock();
}

/*
 * nd6-cfg ND6 {SET|DELETE} <param enum> <param value>
 */
static int cmd_nd6_cfg_handler(struct pb_msg *pbmsg)
{
	NbrResConfig *msg = nbr_res_config__unpack(NULL, pbmsg->msg_len,
							 pbmsg->msg);
	uint32_t val;
	char *ifname;
	int ret = -1;
	bool set;

	if (!msg) {
		RTE_LOG(ERR, ND6,
			"Cfg failed to read NbrResConfig protobuf cmd\n");
		return ret;
	}
	if (msg->prot != NBR_RES_CONFIG__PROT__ND6) {
		RTE_LOG(ERR, ND6,
			"Cfg incorrect protocol (%d)\n", msg->prot);
		goto end;
	}
	ifname = msg->ifname;
	if (ifname && (*ifname != '\0' && strncmp("all", ifname, 4) != 0)) {
		RTE_LOG(ERR, ND6,
			"Cfg per-interface config not yet supported\n");
		goto end;
	}
	set = msg->action == NBR_RES_CONFIG__ACTION__SET;
	val = msg->value;

	switch (msg->param) {
	case NBR_RES_CONFIG__PARAM__MAX_ENTRY:
		/*
		 * Changes to cache size only impact subsequent resolutions.
		 * So if cache size is reduced to less than the number of
		 * entries for an interface, then the latter number decreases
		 * only as entries fail to re-resolve.
		 */
		if (set && (int)val <= 0) {
			RTE_LOG(ERR, ND6,
				"Cfg max entry value %d out of range\n", val);
			goto end;
		}
		nd6_cfg.nd6_max_entry = set ? val : ND6_MAX_ENTRY;
		ND6_DEBUG("Cfg param nd6_max_entry (cache size) set to: %d\n",
			  nd6_cfg.nd6_max_entry);
		break;
	case NBR_RES_CONFIG__PARAM__RES_TOKEN:
		/*
		 * Changes to resolution throttling only impact subsequent
		 * resolutions. So if this limit is reduced to less than the
		 * number of pending resolutions for an interface in a given
		 * second, these are not affected. Value must be a +ve int16_t.
		 */
		if (set && (val == 0 || val >= 1 << 15)) {
			RTE_LOG(ERR, ND6,
				"Cfg res token value %d out of range\n", val);
			goto end;
		}
		nd6_cfg.nd6_res_token = set ? val : ND6_RES_TOKEN;
		ND6_DEBUG("Cfg param nd6_res_token (resolution throttling) set "
			  "to: %d\n", nd6_cfg.nd6_res_token);
		break;
	default:
		RTE_LOG(ERR, ND6,
			"Cfg parameter not supported (%d)\n", msg->param);
		goto end;
	}

	ret = 0;
end:
	nbr_res_config__free_unpacked(msg, NULL);
	return ret;
}

PB_REGISTER_CMD(nd6_cfg_cmd) = {
	.cmd = "vyatta:nd6",
	.handler = cmd_nd6_cfg_handler,
};

int cmd_nd6_get_cfg(FILE *f)
{
	json_writer_t *wr = jsonw_new(f);

	if (!wr) {
		RTE_LOG(NOTICE, DATAPLANE,
			"nd6: Error creating JSON object for cfg params\n");
		return -1;
	}

	jsonw_pretty(wr, true);

	jsonw_uint_field(wr, "NS retries",	   nd6_cfg.nd6_ns_retries);
	jsonw_uint_field(wr, "Reachable time",	   nd6_cfg.nd6_reachable_time);
	jsonw_uint_field(wr, "Scavenge time",	   nd6_cfg.nd6_scavenge_time);
	jsonw_uint_field(wr, "Delay time",	   nd6_cfg.nd6_delay_time);
	jsonw_int_field(wr, "Max entries",	   nd6_cfg.nd6_max_entry);
	jsonw_int_field(wr, "Resolution tokens",   nd6_cfg.nd6_res_token);
	jsonw_uint_field(wr, "Unreachable tokens", nd6_cfg.nd6_unr_token);
	jsonw_uint_field(wr, "Max hold",	   nd6_cfg.nd6_maxhold);

	jsonw_destroy(&wr);

	return 0;
}

static void
nd6_lladdr_if_feat_mode_change(struct ifnet *ifp,
			       enum if_feat_mode_event event)
{
	if (event != IF_FEAT_MODE_EVENT_L3_FAL_ENABLED &&
	    event != IF_FEAT_MODE_EVENT_L3_FAL_DISABLED)
		return;

	if (lltable_fal_l3_change(
		    ifp->if_lltable6,
		    event == IF_FEAT_MODE_EVENT_L3_FAL_ENABLED))
		rte_timer_reset(&ifp->if_lltable6->lle_timer, 0,
				SINGLE, rte_get_master_lcore(),
				in6_lladdr_timer, ifp->if_lltable6);
}

static const struct dp_event_ops nd6_lladdr_events = {
	.if_feat_mode_change = nd6_lladdr_if_feat_mode_change,
};

DP_STARTUP_EVENT_REGISTER(nd6_lladdr_events);
