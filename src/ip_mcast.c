/*
 * IPv4 multicast routing
 *
 * Implements low level multicast functionality.
 * Integration with FreeBSD multicast APIs
 *
 * Copyright (c) 2014-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 * Copyright (c) 2017,2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#define MC_VMAJ 0
#define MC_VMIN 1

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/snmp.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <string.h>

#include "if/gre.h"
#include "if_var.h"
#include "ip6_mroute.h"
#include "ip_icmp.h"
#include "ip_mcast.h"
#include "main.h"
#include "netinet/ip_mroute.h"
#include "pktmbuf_internal.h"
#include "snmp_mib.h"
#include "vplane_debug.h"
#include "vplane_log.h"

/* destination ethernet address is unique for each mcast group */
static void mcast_eth_output(struct rte_mbuf *m, struct ifnet *ifp,
			     struct ifnet *rcvif)
{

	struct rte_ether_hdr *eth_hdr;

	/* set ethernet source address */
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	rte_ether_addr_copy(&ifp->eth_addr, &eth_hdr->s_addr);

	IPSTAT_INC_IFP(ifp, IPSTATS_MIB_OUTMCASTPKTS);
	if_output(ifp, m, rcvif, ETH_P_IP);
}

static void mcast_ip_fragment(struct rte_mbuf *mm, struct ifnet *ifp)
{
	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Multicast packet fragmentation unsupported on %s.\n",
		 ifp->if_name);
	IPSTAT_INC_IFP(ifp, IPSTATS_MIB_OUTDISCARDS);
	rte_pktmbuf_free(mm);
}

/* fast-path output */
int mc_ip_output(struct ifnet *rcvif,
		 struct rte_mbuf *m, struct ifnet *ifp, struct iphdr *ip)
{
	/* Destination device is not up?  */
	if (unlikely(!(ifp->if_flags & IFF_UP)))
		return -1;

	/*
	 * is fragmentation necessary
	 */
	if (likely(ntohs(ip->tot_len) <= ifp->if_mtu))
		mcast_eth_output(m, ifp, rcvif); /* send it */
	else if (ip->frag_off & htons(IP_DF)) {
		/* Handle with icmp reply needfrag for TCP MTU discovery */
		IPSTAT_INC_IFP(rcvif, IPSTATS_MIB_FRAGFAILS);
		icmp_error(rcvif, m, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			   htons(ifp->if_mtu));
		rte_pktmbuf_free(m);
	} else
		mcast_ip_fragment(m, ifp); /* needs fragmentation */

	return 0;
}

/*
 * Display old and new value of interface flags of interest to
 * multicast, after receipt of RTM_NEWLINK or RTM_DELLINK message.
 */
void mc_debug_if_flags(struct ifnet *ifp, unsigned int new_flags,
		       unsigned int msg_type)
{
	unsigned int old_flags;

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Processing %s for %s.\n",
		 nlmsg_type(msg_type),
		 ifp ? ifp->if_name : "UNKNOWN");

	if (ifp)
		old_flags = ifp->if_flags;
	else
		old_flags = 0;

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Interesting flags (old value/new value): IFF_UP:%s/%s, IFF_MULTICAST:%s/%s, IFF_PROMISC:%s/%s, IFF_ALLMULTI:%s/%s.\n",
		 (old_flags & IFF_UP) ? "set" : "clr",
		 (new_flags & IFF_UP) ? "set" : "clr",
		 (old_flags & IFF_MULTICAST) ? "set" : "clr",
		 (new_flags & IFF_MULTICAST) ? "set" : "clr",
		 (old_flags & IFF_PROMISC) ? "set" : "clr",
		 (new_flags & IFF_PROMISC) ? "set" : "clr",
		 (old_flags & IFF_ALLMULTI) ? "set" : "clr",
		 (new_flags & IFF_ALLMULTI) ? "set" : "clr");
}

void mc_del_if(int ifindex)
{
	del_vif(ifindex);
	del_m6if(ifindex);
}

void mrt_purge(struct ifnet *ifp)
{
	mrt4_purge(ifp);
	mrt6_purge(ifp);
}

void mc_dumpall(FILE *f, struct vrf *vrf)
{
	mvif_dump(f, vrf);
	mrt_dump(f, vrf);
	mrt_stat(f, vrf);
	mfc_stat(f, vrf);

	mvif6_dump(f, vrf);
	mrt6_dump(f, vrf);
	mrt6_stat(f, vrf);
	mfc6_stat(f, vrf);
}

/* Function to create a new header mbuf which is chained to a supplied
 * data mbuf to support efficient replication.
 *
 * Inputs are two mbufs: m_header and m_data.  m_header contains the
 * L2 and IP(v6) header and is chained to m_data. m_data may be direct
 * or cloned/indirect but must contain or reference the entirety of
 * data to be replicated.
 *
 * Output is a newly allocated mbuf, m_newheader, which contains the
 * IP(v6) and L2 header from m_header and is chained to m_data, with
 * the ref count on m_data being incremented due to this new dependency.
 */
struct rte_mbuf *mcast_create_l2l3_header(struct rte_mbuf *m_header,
					  struct rte_mbuf *m_data,
					  int iphdrlen)
{
	struct rte_mbuf *m_newheader;

	/* Allocate new header mbuf and copy in L2 and IP(v6) headers
	 * from input header mbuf.
	 */
	m_newheader = pktmbuf_alloc(m_header->pool,
				    pktmbuf_get_vrf(m_header));
	if (m_newheader) {
		char *hdr_ptr = rte_pktmbuf_append(
			m_newheader,
			dp_pktmbuf_l2_len(m_header) + iphdrlen);
		memcpy(hdr_ptr, rte_pktmbuf_mtod(m_header, char *),
		       dp_pktmbuf_l2_len(m_header) + iphdrlen);
		dp_pktmbuf_l2_len(m_newheader) = dp_pktmbuf_l2_len(m_header);

		/* Attach mew header mbuf to data mbuf.  Increment
		 * ref count on data mbuf due to new attachment.
		 */
		rte_mbuf_refcnt_update(m_data, 1);
		m_newheader->next = m_data;
		m_newheader->nb_segs += m_data->nb_segs;
		m_newheader->pkt_len += m_data->pkt_len;
		m_newheader->port = m_data->port;
	}

	return m_newheader;
}

/*
 * Callback function invoked by GRE for each endpoint in P2MP tunnel
 * (or the single end point in a P2P tunnel).  Respsonsible for
 * replicating packet and then invoking GRE API to transmit packet
 * to specific tunnel endpoint.
 *
 * Since the tunnel interface must be in the olist, the supplied mbuf
 * is the output of multicast's original replication, i.e. a  header
 * mbuf (containing with Ethernet and IP headers) chained to cloned
 * mbuf(s) (referencing the payload of the original packet).
 * This relationship between the mbufs allows the function used
 * to create the headers for the original replication to be re-used.
 */
void
mcast_mgre_tunnel_endpoint_send(struct ifnet *out_ifp,
				struct mgre_rt_info *remote,
				void *arg)
{
	struct mcast_mgre_tun_walk_ctx *mgre_tun_walk_ctx;
	int16_t proto;
	struct ifnet *in_ifp;
	struct vif *out_vifp;
	struct mif6 *out_mifp;
	int hdr_len, pkt_len;
	struct rte_mbuf *m, *m_header;
	in_addr_t *tun_endpoint_addr;

	mgre_tun_walk_ctx = arg;
	proto = mgre_tun_walk_ctx->proto;
	in_ifp = mgre_tun_walk_ctx->in_ifp;
	pkt_len = mgre_tun_walk_ctx->pkt_len;
	hdr_len = mgre_tun_walk_ctx->hdr_len;

	m = mgre_tun_walk_ctx->mbuf;
	m_header = mcast_create_l2l3_header(m, m->next, hdr_len);

	/*
	 * Note that for P2P tunnel, no state for remote endpoint is
	 * supplied so NULL is passed for the address in the following
	 * API call, leading to the default encaps being used by GRE.
	 */
	tun_endpoint_addr = remote ? &remote->tun_addr.s_addr : NULL;

	if (proto == ETH_P_IP) {
		out_vifp = mgre_tun_walk_ctx->out_vif;
		out_vifp->v_pkt_out++;
		out_vifp->v_bytes_out += pkt_len;
		IPSTAT_INC_IFP(in_ifp, IPSTATS_MIB_OUTMCASTPKTS);
	} else {
		out_mifp = mgre_tun_walk_ctx->out_vif;
		out_mifp->m6_pkt_out++;
		out_mifp->m6_bytes_out += pkt_len;
		IP6STAT_INC(if_vrfid(in_ifp), IPSTATS_MIB_OUTMCASTPKTS);
	}

	gre_tunnel_fragment_and_send(in_ifp, out_ifp,
				     tun_endpoint_addr, m_header, proto);
}

/*
 * allocate a per-vrf index for the multicast VIF. This allows us to have up
 * to 256 multicast enabled interfaces per vrf.
 */
int mcast_iftable_get_free_slot(struct if_set *mfc_ifset, int ifindex,
				unsigned char *vif_index)
{
	unsigned char index = (unsigned char)ifindex;
	int i;

	if (!mfc_ifset)
		return -1;

	/* if the mod 8 of the ifindex is available use it */
	if (!IF_ISSET(index, mfc_ifset)) {
		IF_SET(index, mfc_ifset);
		*vif_index = index;
		return 0;
	}

	/* iterate up to limit of the if_set to find a free slot */
	for (i = index + 1; i < IF_SETSIZE; i++) {
		if (!IF_ISSET(i, mfc_ifset)) {
			IF_SET(i, mfc_ifset);
			*vif_index = i;
			return 0;
		}
	}

	/* start iterating up from 0 if we have not already done so */
	if (index) {
		for (i = 0; i < index; i++) {
			if (!IF_ISSET(i, mfc_ifset)) {
				IF_SET(i, mfc_ifset);
				*vif_index = i;
				return 0;
			}
		}
	}

	return -ENOSPC;
}
