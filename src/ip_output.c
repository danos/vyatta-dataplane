/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * ip output
 */

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/snmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "compat.h"
#include "compiler.h"
#include "ether.h"
#include "if_var.h"
#include "in_cksum.h"
#include "ip_funcs.h"
#include "mpls/mpls.h"
#include "mpls/mpls_forward.h"
#include "nh_common.h"
#include "pktmbuf_internal.h"
#include "route.h"
#include "route_flags.h"
#include "snmp_mib.h"
#include "urcu.h"
#include "util.h"
#include "vplane_log.h"

/* Minimal version of IP output for sending icmp etc */
void ip_output(struct rte_mbuf *m, bool srced_forus)
{
	struct next_hop *nxt;
	struct ether_hdr *eh = ethhdr(m);
	struct iphdr *ip = iphdr(m);
	struct ifnet *ifp;

	eh->ether_type = htons(ETHER_TYPE_IPv4);

	/* Do route lookup */
	nxt = dp_rt_lookup(srced_forus ? ip->saddr : ip->daddr,
			   RT_TABLE_MAIN, m);
	if (!nxt) {
		/*
		 * Since there is no output interface count against
		 * the VRF associated with the packet.
		 */
		IPSTAT_INC_MBUF(m, IPSTATS_MIB_OUTNOROUTES);
		goto drop;
	}

	/* ifp can be changed by nxt->ifp. use protected deref. */
	ifp = dp_nh_get_ifp(nxt);

	/* MPLS imposition required because nh has given us a label */
	if (nh_outlabels_present(&nxt->outlabels)) {
		mpls_unlabeled_input(ifp, m, NH_TYPE_V4GW, nxt, ip->ttl);
		return;
	}

	if (unlikely(ifp == NULL)) {
		if (net_ratelimit()) {
			char b[INET_ADDRSTRLEN];
			RTE_LOG(ERR, ROUTE,
				"ip output called for %s which is slowpath\n",
				inet_ntop(AF_INET, &ip->daddr, b, sizeof(b)));
		}
		goto drop;
	}

	if (!(ifp->if_flags & IFF_UP))
		goto drop;

	if (srced_forus) {
		ether_addr_copy(&ifp->eth_addr, &eh->d_addr);
		/*
		 * We want the kernel to believe this came from the interface
		 * that we failed the mtu check on.
		 */
		m->port = ifp->if_port;
		ip_local_deliver(ifp, m);
		return;
	}

	if (dp_ip_l2_nh_output(NULL, m, nxt, ETH_P_IP))
		IPSTAT_INC_IFP(ifp, IPSTATS_MIB_OUTPKTS);

	return;
drop:
	rte_pktmbuf_free(m);
}

/*
 * Copy multisegment mbuf starting at offset for len bytes.
 *
 * Added complexity dealing with segmented mbufs
 */
int ip_mbuf_copy(struct rte_mbuf *m, const struct rte_mbuf *n,
		 unsigned int off, unsigned int len)
{
	struct rte_mbuf *m0 = m;
	void *tail;

	if (off + len > rte_pktmbuf_pkt_len(n))
		return -1;		/* outside of data in overall packet */
	while (len > 0) {
		unsigned int count, room;

		tail = rte_pktmbuf_mtod(m, char *) + rte_pktmbuf_data_len(m);
		if (off >= n->data_len) {
			off -= n->data_len;
			n = n->next;
			if (n == NULL)
				return -1;	/* segments exhausted */
			continue;
		}

		if (n->data_len < len + off)
			count = n->data_len - off;
		else
			count = len;

		room = rte_pktmbuf_tailroom(m);
		if (room < count)
			count = room;

		memcpy(tail, rte_pktmbuf_mtod(n, char *) + off, count);
		m->data_len += count;
		m0->pkt_len += count;
		len -= count;

		if (len > 0) {
			if (rte_pktmbuf_tailroom(m) == 0) {
				m = m->next;
				if (m == NULL)
					return -1; /* target out of space */
			}

			off += count;
			if (off >= n->data_len) {
				off -= n->data_len;
				n = n->next;
				if (n == NULL)
					return -1; /* source exhausted */
			}
		}
	}

	return 0;
}

/*
 * Copy options from ip to jp, omitting those not copied during
 * fragmentation.
 */
static unsigned int
ip_optcopy(const struct iphdr *ip, struct iphdr *jp)
{
	const uint8_t *cp = (const uint8_t *) (ip + 1);
	uint8_t *dp = (uint8_t *)(jp + 1);
	unsigned int cnt = (ip->ihl << 2) - sizeof(struct ip);
	unsigned int optlen = 0;

	for (; cnt > 0; cnt -= optlen, cp += optlen) {
		uint8_t opt = cp[0];

		if (opt == IPOPT_EOL)
			break;

		if (opt == IPOPT_NOP) {
			/* Preserve for IP mcast tunnel's LSRR alignment. */
			*dp++ = IPOPT_NOP;
			optlen = 1;
			continue;
		}

		optlen = cp[IPOPT_OLEN];

		/* Bogus lengths should have been caught by ip_dooptions. */
		if (optlen > cnt)
			optlen = cnt;

		if (IPOPT_COPIED(opt)) {
			memcpy(dp, cp, optlen);
			dp += optlen;
		}
	}

	for (optlen = dp - (u_char *)(jp+1); optlen & 0x3; optlen++)
		*dp++ = IPOPT_EOL;

	return optlen;
}

/*
 * Copy mbuf that needs to be fragmented into a new packet
 * mbuf to be fragmented.
 */
void ip_fragment(struct ifnet *ifp, struct rte_mbuf *m0,
		 void *ctx, output_t frag_out)
{
	ip_fragment_mtu(ifp, ifp->if_mtu, m0, ctx, frag_out);
}

void ip_fragment_mtu(struct ifnet *ifp, unsigned int mtu, struct rte_mbuf *m0,
		     void *ctx, output_t frag_out)
{
	struct iphdr *ip = iphdr(m0);
	struct vrf *vrf = if_vrf(ifp);
	unsigned int hlen = dp_pktmbuf_l3_len(m0);
	uint16_t iplen = ntohs(ip->tot_len);
	unsigned int len = (mtu - hlen) & ~7;	/* size of payload  */
	struct rte_mbuf *m;
	unsigned int off, sz;
	int frag_number = 1;
	struct iphdr *mhip;

	/*
	 * Must be able to put at least 8 bytes per fragment.
	 */
	if (len < 8)
		goto drop;

	/*
	 * Loop through length of segment after first fragment,
	 * make new header and copy data of each part and link onto chain.
	 * Here, m0 is the original packet, m is the fragment being created.
	 *
	 * Fragments are sent as created, then the header last.
	 */
	for (off = hlen + len; off < iplen; off += sz) {
		unsigned int mhlen = sizeof(struct iphdr);
		bool last_frag = false;

		if (off + len >= iplen) {
			sz = iplen - off;
			last_frag = true;
		} else {
			sz = len;
		}

		m = pktmbuf_allocseg(m0->pool, pktmbuf_get_vrf(m0),
				     sz + ETHER_HDR_LEN + hlen);
		if (m == NULL)
			goto drop;

		pktmbuf_copy_meta(m, m0);

		memcpy(rte_pktmbuf_mtod(m, char *),
		       rte_pktmbuf_mtod(m0, char *),
		       dp_pktmbuf_l2_len(m0) + mhlen);

		mhip = iphdr(m);
		if (hlen > sizeof(struct iphdr)) {
			mhlen += ip_optcopy(ip, mhip);
			mhip->version = IPVERSION;
			mhip->ihl = mhlen >> 2;
		}
		dp_pktmbuf_l3_len(m) = mhlen;
		rte_pktmbuf_data_len(m) = dp_pktmbuf_l2_len(m) + mhlen;
		rte_pktmbuf_pkt_len(m) = rte_pktmbuf_data_len(m);
		mhip->frag_off = htons(((len * frag_number) >> 3) +
				       ntohs(ip->frag_off));
		if (!last_frag)
			mhip->frag_off |= htons(IP_MF);

		mhip->tot_len = htons(sz + mhlen);
		mhip->check = 0;
		mhip->check = in_cksum(mhip, mhlen);

		if (ip_mbuf_copy(m, m0, off + dp_pktmbuf_l2_len(m0), sz) < 0) {
			rte_pktmbuf_free(m);
			goto drop;
		}

		IPSTAT_INC_VRF(vrf, IPSTATS_MIB_FRAGCREATES);
		frag_out(ifp, m, ctx);
		frag_number++;
	}

	/*
	 * Copy first fragment and update header.
	 */
	m = pktmbuf_allocseg(m0->pool, pktmbuf_get_vrf(m0),
			     len + dp_pktmbuf_l2_len(m0) + hlen);
	if (m == NULL)
		goto drop;

	pktmbuf_copy_meta(m, m0);

	memcpy(rte_pktmbuf_mtod(m, char *),
	       rte_pktmbuf_mtod(m0, char *), dp_pktmbuf_l2_len(m0) + hlen);
	dp_pktmbuf_l3_len(m) = hlen;
	rte_pktmbuf_data_len(m) = dp_pktmbuf_l2_len(m0) + hlen;
	rte_pktmbuf_pkt_len(m) = rte_pktmbuf_data_len(m);

	mhip = iphdr(m);
	mhip->tot_len = htons(hlen + len);
	mhip->frag_off |= htons(IP_MF);

	mhip->check = 0;
	mhip->check = in_cksum(mhip, hlen);

	int res = ip_mbuf_copy(m, m0, dp_pktmbuf_l2_len(m0) + hlen, len);
	if (res < 0) {
		rte_pktmbuf_free(m);
		goto drop;
	}

	IPSTAT_INC_VRF(vrf, IPSTATS_MIB_FRAGCREATES);
	IPSTAT_INC_VRF(vrf, IPSTATS_MIB_FRAGOKS);
	rte_pktmbuf_free(m0);

	frag_out(ifp, m, ctx);
	return;
drop: __cold_label;
	IPSTAT_INC_VRF(vrf, IPSTATS_MIB_OUTDISCARDS);
	rte_pktmbuf_free(m0);
}
