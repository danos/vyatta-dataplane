/*
 * MPLS forwarder
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <assert.h>
#include <linux/snmp.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_ether.h>

#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_mbuf.h>

#include "compiler.h"
#include "compat.h"
#include "ecmp.h"
#include "ether.h"
#include "if_var.h"
#include "in6.h"
#include "in_cksum.h"
#include "ip6_funcs.h"
#include "ip_addr.h"
#include "ip_funcs.h"
#include "ip_icmp.h"
#include "ip_ttl.h"
#include "main.h"
#include "mpls/mpls.h"
#include "mpls_forward.h"
#include "mpls_label_table.h"
#include "nh.h"
#include "npf/npf.h"
#include "npf_shim.h"
#include "pktmbuf_internal.h"
#include "route.h"
#include "route_flags.h"
#include "route_v6.h"
#include "snmp_mib.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"

struct mplshdr;

/* RFC4950 definitions */
#define ICMP_EXT_MPLS_LS		1	/* mpls label stack class */
#define ICMP_EXT_MPLS_LS_INCOMING	1	/* incoming ls subclass */

#define MAX_TTL 255

/* debug for pkt on exception/error paths */
#define DBG_MPLS_PKTERR(ifp, mbuf, fmt, args...) do {			\
		if (unlikely(dp_debug & DP_DBG_MPLS_PKTERR)) {		\
			rte_log(RTE_LOG_DEBUG, RTE_LOGTYPE_MPLS,	\
				"if %s lbl %d " fmt,			\
				ifp ? ifp->if_name : "(local)",		\
				mpls_ls_get_label(mplshdr(mbuf)->ls),	\
				## args);				\
		}							\
	} while (0)

enum mpls_propagate_ttl_setting {
	TTL_PROPAGATE_ENABLED,
	TTL_PROPAGATE_DISABLED,
};

static int cfg_default_ttl = -1;
static uint8_t default_ttl = MAX_TTL;
static enum mpls_propagate_ttl_setting propagate_ttl = TTL_PROPAGATE_ENABLED;

struct mplshdr {
	/* encoded label-stack entry in network order */
	uint32_t ls;
};

/*
 * Label cache is used to hold the output labels until the packet is ready to
 * send. The input labels remain in the packet for as long as possible in case
 * they are needed for ICMP generation or if the packet needs to be punted.
 * Popped labels are handled by increasing the L2 len. The original packet
 * is recovered by restoring the L2 len to ETHER_HDR_LEN.
 *
 * Pkt:  Ethernet hdr | Popped lbls (0..Np) | Remaining lbls (0..Nb) | IP hdr
 *       <--------- l2 len ---------------->
 * Plus: Cached lbls (0..Nc)
 *
 * For IP imposition, Popped and Remaining lbls are 0, all the imposition
 * labels are Cached lbls.
 *
 * For IP disposition, Popped lbls will be 1 or more, Remaining and Cached lbls
 * will be 0.
 *
 * For MPLS swap and forward, there will be 1 or more Popped lbls and 1 or more
 * Cached lbls. There may be 0 or more Remaining lbls.
 *
 * For MPLS pop and forward, there will be 1 or more Popped lbls, 0 Cached lbls
 * and 1 or more remaining lbls.
 *
 */
#define MAX_LABEL_CACHE_DEPTH	NH_MAX_OUT_LABELS /* max num labels can push */
struct mpls_label_cache {
	unsigned int num_labels;
	struct mplshdr label[MAX_LABEL_CACHE_DEPTH];
};

static void mpls_output(struct rte_mbuf *m);

bool mpls_global_get_ipttlpropagate(void)
{
	return (propagate_ttl == TTL_PROPAGATE_ENABLED ? true : false);
}

void mpls_global_set_ipttlpropagate(bool enable)
{
	propagate_ttl = enable ? TTL_PROPAGATE_ENABLED : TTL_PROPAGATE_DISABLED;
}

int mpls_global_get_defaultttl(void)
{
	return cfg_default_ttl;
}

void mpls_global_set_defaultttl(int ttl)
{
	cfg_default_ttl = ttl;
	if (cfg_default_ttl != -1)
		default_ttl = ttl;
	else
		default_ttl = MAX_TTL;
}

static inline struct mplshdr *
mplshdr(const struct rte_mbuf *m)
{
	return ((struct mplshdr *)
		(rte_pktmbuf_mtod(m, char *) + m->l2_len));
}

static inline struct mplshdr *
mplshdr_safe(struct rte_mbuf *m)
{
	unsigned int len;

	/*
	 * Validate that the remaining non-L2 data in the first
	 * segment is long enough to contain at least one label
	 */
	len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m);
	if (unlikely(len < sizeof(struct mplshdr)))
		return NULL;

	return mplshdr(m);
}

static inline void
mpls_label_cache_init(struct mpls_label_cache *cache)
{
	cache->num_labels = 0;
}

/*
 * push one label onto the cache
 */
static bool
mpls_label_cache_push(struct mpls_label_cache *cache, label_t label,
		      uint8_t bos)
{
	struct mplshdr *hdr;

	if (unlikely(cache->num_labels >= MAX_LABEL_CACHE_DEPTH)) {
		DP_DEBUG(MPLS_PKTERR, ERR, MPLS, "Label cache full\n");
		return false;
	}
	hdr = &cache->label[cache->num_labels++];
	hdr->ls = 0;
	mpls_ls_set_label(&hdr->ls, label);
	mpls_ls_set_bos(&hdr->ls, bos);

	return true;
}

/*
 * return difference in space between cached and popped labels
 */
static inline int
mpls_label_cache_adjust(struct rte_mbuf *m, struct mpls_label_cache *cache,
			uint8_t l2_len)
{
	return (cache->num_labels * sizeof(struct mplshdr)) -
		(dp_pktmbuf_l2_len(m) - l2_len);
}

/*
 * write label cache into the packet and update ttl, returning false if no room
 */
static bool
mpls_label_cache_write(struct rte_mbuf *m,
		       struct mpls_label_cache *cache, uint8_t ttl,
		       uint8_t l2_len)
{
	struct mplshdr *hdr = mplshdr(m);
	struct mplshdr label;
	unsigned int i;
	int adjust;

	/*
	 * Make space for new labels
	 */
	adjust = mpls_label_cache_adjust(m, cache, l2_len);
	if (adjust > 0) {
		if (unlikely(!rte_pktmbuf_prepend(m, adjust))) {
			DP_DEBUG(MPLS_PKTERR, ERR, MPLS,
				"Not enough room for pushing label stack\n");
			return false;
		}
	} else if (adjust < 0) {
		if (unlikely(!rte_pktmbuf_adj(m, -adjust))) {
			DP_DEBUG(MPLS_PKTERR, ERR, MPLS,
				"%s assert for rte_pktmbuf_adj\n",
				__func__);
			return false;
		}
	}

	/*
	 * Copy cached labels into the space, starting from bottom
	 */
	for (i = 0; i < cache->num_labels; i++) {
		hdr--;
		label = cache->label[i];
		mpls_ls_set_ttl(&label.ls, ttl);
		hdr->ls = label.ls;
	}

	dp_pktmbuf_l2_len(m) = l2_len;

	/*
	 * If not pushing any labels, update TTL in top-most label
	 */
	if (!cache->num_labels)
		mpls_ls_set_ttl(&mplshdr(m)->ls, ttl);

	return true;
}

static inline bool
push_labels(const union next_hop_outlabels *new_labels, uint8_t bos,
	    struct mpls_label_cache *cache)
{
	unsigned int i;
	label_t label;

	NH_FOREACH_OUTLABEL(new_labels, i, label) {
		if (!mpls_label_cache_push(cache, label, bos))
			return false;

		/*
		 * Only the bottom-most label should have the
		 * bottom-of-stack flag set.
		 */
		bos = 0;
	}

	return true;
}

static inline bool
swap_labels(struct rte_mbuf *m,
	    const union next_hop_outlabels *new_labels,
	    struct mpls_label_cache *cache)
{
	struct mplshdr *hdr = mplshdr(m);
	uint8_t bos;

	bos = mpls_ls_get_bos(hdr->ls);

	if (!push_labels(new_labels, bos, cache))
		return false;

	/*
	 * Make swapped label part of l2_len as we don't care about it anymore
	 */
	dp_pktmbuf_l2_len(m) += sizeof(struct mplshdr);

	return true;
}

static inline bool
pop_label(struct rte_mbuf *m)
{
	struct mplshdr *hdr = mplshdr(m);

	/*
	 * Make this label part of l2_len as we don't care about it anymore
	 */
	dp_pktmbuf_l2_len(m) += sizeof(struct mplshdr);

	if (mpls_ls_get_bos(hdr->ls))
		return true;
	else
		return false;
}

static inline bool
is_mpls_ip_oam(const struct iphdr *ip, unsigned int len)
{
	unsigned int hlen;

	if (len < sizeof(*ip))
		return false;

	switch (ip->version) {
	case 4:
		if (ip->ttl != 1)
			return false;
		if (!IN_LOOPBACK(ntohl(ip->daddr)))
			return false;
		hlen = ip->ihl << 2;
		if (len < hlen)
			return false;
		if (ip_checksum(ip, hlen))
			return false;
		break;
	default:
		return false;
	}

	return true;
}

static bool
is_mpls_oam(const struct ifnet *ifp, const struct rte_mbuf *m)
{
	const struct mplshdr *hdr;
	const struct iphdr *ip;
	unsigned int lssize;
	unsigned int len;

	hdr = mplshdr(m);
	lssize = 1;
	len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m) - sizeof(*hdr);
	while (!mpls_ls_get_bos(hdr->ls)) {
		if (++lssize > MAX_LABEL_STACK_DEPTH)
			return false;
		if (len < sizeof(*hdr))
			return false;
		len -= sizeof(*hdr);
		hdr++;
	}

	ip = (struct iphdr *)(hdr + 1);
	if (!is_mpls_ip_oam(ip, len))
		return false;

	DBG_MPLS_PKTERR(ifp, m, "mpls oam\n");
	return true;
}

/*
 * Attempt to construct an ICMP error packet with the incoming label stack in
 * the ICMP extended header.
 * This packet should replace the original and be forwarded along the LSP.
 */
static struct rte_mbuf *
mpls_error(struct ifnet *ifp, struct rte_mbuf *m,
	   struct mpls_label_cache *cache,
	   enum mpls_payload_type payload_type,
	   int type, int code, int destmtu)
{
	struct mplshdr *hdr;
	unsigned int pop_offset;
	struct rte_mbuf *n;
	struct ip6_hdr *ip6;
	struct iphdr *ip;
	unsigned int lssize;
	void *lstack;
	unsigned int len;
	in_addr_t t;
	uint8_t ttl;
	unsigned int i;

	DBG_MPLS_PKTERR(ifp, m,
			"mpls error: type %d, code %d, mtu %d\n",
			type, code, destmtu);

	/*
	 * Note offset of popped labels and restore original packet
	 */
	pop_offset = dp_pktmbuf_l2_len(m) - ETHER_HDR_LEN;
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;

	len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m);

	/*
	 * Find the IP header, within reason
	 */
	hdr = lstack = mplshdr(m);
	for (lssize = 1; ; lssize++) {
		/*
		 * Verify that the MPLS header fits in the first segment
		 */
		if (len < lssize * sizeof(*hdr)) {
			DBG_MPLS_PKTERR(ifp, m,
					"mpls error: end of packet found when searching for bos - %u\n",
					len);
			return NULL;
		}
		if (mpls_ls_get_bos(hdr->ls))
			break;
		if (lssize > MAX_LABEL_STACK_DEPTH) {
			DBG_MPLS_PKTERR(ifp, m,
					"mpls error: too many (%u) labels in stack\n",
					lssize);
			return NULL;
		}
		hdr++;
	}

	ip = (struct iphdr *)(hdr + 1);
	if (payload_type == MPT_UNSPEC) {
		if (len < lssize * sizeof(*hdr) + 1) {
			DBG_MPLS_PKTERR(ifp, m,
					"mpls error: payload not long enough - %d bytes\n",
					len - (int)(lssize * sizeof(*hdr)));
			return NULL;
		}
		switch (ip->version) {
		case 4:
			if (IN_MULTICAST(ntohl(ip->daddr)) ||
			    IN_EXPERIMENTAL(ntohl(ip->daddr)) ||
			    IN_ZERONET(ntohl(ip->daddr)))
				return NULL;
			payload_type = MPT_IPV4;
			break;
		case 6:
			switch (type) {
			case ICMP_TIME_EXCEEDED:
				type = ICMP6_TIME_EXCEEDED;
				code = ICMP6_TIME_EXCEED_TRANSIT;
				break;
			default:
				return NULL;
			}
			payload_type = MPT_IPV6;
			break;
		default:
			DBG_MPLS_PKTERR(ifp, m,
					"mpls error: bad ip version - %u\n",
					*(uint8_t *)ip >> 4);
			return NULL;
		}
	}

	switch (payload_type) {
	case MPT_IPV4: {
		dp_pktmbuf_l2_len(m) += (lssize * sizeof(struct mplshdr));
		dp_pktmbuf_l3_len(m) = ip->ihl << 2;

		if (!ip_valid_packet(m, ip)) {
			DBG_MPLS_PKTERR(ifp, m,
					"mpls error: packet not valid\n");
			return NULL;
		}

		n = icmp_do_error(m, type, code, htons(destmtu), NULL, NULL);
		if (n == NULL)
			return NULL;

		dp_pktmbuf_l3_len(n) = dp_pktmbuf_l3_len(m);
		if (icmp_do_exthdr(n, ICMP_EXT_MPLS_LS,
				   ICMP_EXT_MPLS_LS_INCOMING, lstack,
				   lssize * sizeof(struct mplshdr))) {
			rte_pktmbuf_free(n);
			return NULL;
		}

		/*
		 * Reflect the ip packet back to the source
		 */
		ip = iphdr(n);
		t = ip->daddr;
		ip->daddr = ip->saddr;

		t = ip_select_source(ifp, t);
		if (t) {
			ip->saddr = t;
			ip->ttl = ttl = IPDEFTTL;
		} else {
			/*
			 * Should never get here. it means packet was received
			 * on an interface without any IP address
			 */
			rte_pktmbuf_free(n);
			return NULL;
		}

		icmp_prepare_send(n);

		/* restore original l2 length */
		dp_pktmbuf_l2_len(n) -= (lssize * sizeof(struct mplshdr));

		break;
	}

	case MPT_IPV6:
		dp_pktmbuf_l2_len(m) += (lssize * sizeof(struct mplshdr));
		dp_pktmbuf_l3_len(m) = sizeof(*ip6);

		ip6 = (struct ip6_hdr *)ip;
		if (!ip6_valid_packet(m, ip6)) {
			DBG_MPLS_PKTERR(ifp, m,
					"mpls error: ipv6 packet not valid\n");
			return NULL;
		}

		/* Require source address to be global scope */
		n = icmp6_do_error(ifp, m, type, code, htonl(destmtu),
				   IPV6_ADDR_SCOPE_GLOBAL);
		if (n == NULL)
			return NULL;

		dp_pktmbuf_l3_len(n) = dp_pktmbuf_l3_len(m);
		if (icmp6_do_exthdr(n, ICMP_EXT_MPLS_LS,
				    ICMP_EXT_MPLS_LS_INCOMING, lstack,
				    lssize * sizeof(struct mplshdr))) {
			rte_pktmbuf_free(n);
			return NULL;
		}

		ttl = IPV6_DEFAULT_HOPLIMIT;

		icmp6_prepare_send(n);

		/* restore original l2 length */
		dp_pktmbuf_l2_len(n) -= (lssize * sizeof(struct mplshdr));

		break;
	default:
		return NULL;
	}

	/*
	 * Copy layer 2 header and label stack to new packet
	 * Restore pop offset in new packet
	 */
	memcpy(ethhdr(n), ethhdr(m), dp_pktmbuf_l2_len(m));
	dp_pktmbuf_l2_len(n) += pop_offset;

	/*
	 * Set default TTL in all labels in the packet - those in label cache
	 * and any remaining labels in the packet.
	 * There will be no labels for disposition case
	 */
	for (i = 0; i < cache->num_labels; i++)
		mpls_ls_set_ttl(&cache->label[i].ls, ttl);
	hdr = mplshdr(n);
	for (i = pop_offset / sizeof(struct mplshdr); i < lssize; i++) {
		mpls_ls_set_ttl(&hdr->ls, ttl);
		hdr++;
	}

	return n;
}

static struct rte_mbuf *
mpls_icmp_ttl(struct ifnet *ifp, struct rte_mbuf *m,
	      struct mpls_label_cache *cache)
{
	return mpls_error(ifp, m, cache, MPT_UNSPEC, ICMP_TIME_EXCEEDED,
			  ICMP_EXC_TTL, 0);
}

static struct rte_mbuf *
mpls_icmp_df(struct ifnet *ifp, struct rte_mbuf *m,
	     struct mpls_label_cache *cache,
	     enum mpls_payload_type payload_type,
	     int destmtu)
{
	return mpls_error(ifp, m, cache, payload_type, ICMP_DEST_UNREACH,
			  ICMP_FRAG_NEEDED, destmtu);
}

static inline bool
mpls_oam_ip_exception(struct rte_mbuf *m)
{
	struct mplshdr *hdr;
	unsigned int len;

	/* Check for OAM packet when pop last label and forward to IP */
	len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m);
	if (!is_mpls_ip_oam(iphdr(m), len))
		return false;

	/*
	 * Currently we have to force top label TTL to 1 so that kernel will
	 * punt to OAM daemon (if listening) or else drop the packet rather
	 * than forward it.
	 */
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;
	hdr = mplshdr(m);
	mpls_ls_set_ttl(&hdr->ls, 1);
	return true;
}

/*
 * Forward an mpls packet to a nexthop.  m is a buffer that is known
 * to hold an MPLS packet encapsulating a payload packet of type
 * payload_type and where m->l2_len is the offset of the label that we
 * are currently processing (i.e. it points to the local label that
 * have just looked up), or it may hold an unlabeled packet of payload_type
 * that is being MPLS encapsulated.
 * Returns a result code and m will be altered so that m->l2_len is
 * the offset of the new top of stack label (if any).
 */
static inline enum nh_fwd_ret
nh_fwd_mpls(enum nh_type nht, union next_hop_v4_or_v6_ptr nh,
	    struct rte_mbuf *m, bool have_labels,
	    enum mpls_payload_type payload_type,
	    struct mpls_label_cache *cache, bool *pop)
{
	label_t new_label;
	const union next_hop_outlabels *labels;
	unsigned int num_labels;

	if (unlikely(nh_get_flags(nht, nh) & RTF_SLOWPATH))
		return NH_FWD_SLOWPATH;

	/*
	 * Impose outlabels, if any
	 */
	labels = nh_get_labels(nht, nh);
	new_label = nh_outlabels_get_value(labels, 0);
	num_labels = nh_outlabels_get_cnt(labels);

	if (have_labels)
		*pop = (num_labels == 0);

	if (new_label == MPLS_IMPLICITNULL || num_labels == 0) {
		struct ifnet *ifp = nh_get_if(nht, nh);
		/* imp-null should be the only outlabel */
		assert(num_labels <= 1);

		if ((!have_labels && !cache->num_labels) ||
		    (have_labels && pop_label(m))) {
			/* Bottom of stack */
			if (unlikely(payload_type == MPT_UNSPEC)) {
				/* Peek into the IP header */
				const struct iphdr *ip = iphdr(m);
				switch (ip->version) {
				case 4:
					payload_type = MPT_IPV4;
					break;
				case 6:
					payload_type = MPT_IPV6;
					break;
				default:
					/* Leave as MPT_UNSPEC */
					break;
				}
			}
			if (likely(payload_type == MPT_IPV4)) {
				if (have_labels && num_labels == 0 &&
				    unlikely(mpls_oam_ip_exception(m)))
					return NH_FWD_SLOWPATH;
				return ifp && !is_lo(ifp) ?
					NH_FWD_IPv4 : NH_FWD_RESWITCH_IPv4;
			} else if (likely(payload_type == MPT_IPV6)) {
				if (have_labels && num_labels == 0 &&
				    unlikely(mpls_oam_ip_exception(m)))
					return NH_FWD_SLOWPATH;
				return ifp && !is_lo(ifp) ?
					NH_FWD_IPv6 : NH_FWD_RESWITCH_IPv6;
			} else
				return NH_FWD_FAILURE;
		} else {
			/* Non-bottom of stack */

			/*
			 * If the nexthop is unlabeled then drop the packet
			 */
			if (unlikely(!num_labels))
				return NH_FWD_FAILURE;

			if (!have_labels || ifp)
				return NH_FWD_SUCCESS;
			else
				return NH_FWD_RESWITCH_MPLS;
		}
	} else if (have_labels) {
		if (!swap_labels(m, labels, cache))
			return NH_FWD_FAILURE;
	} else {
		uint8_t bos = cache->num_labels == 0;

		if (!push_labels(labels, bos, cache))
			return NH_FWD_FAILURE;
	}

	return NH_FWD_SUCCESS;
}

/*
 * Loadbalance hash for an mpls packet.
 */
uint32_t
mpls_ecmp_hash(const struct rte_mbuf *m)
{
	struct mplshdr *hdr;
	int label_cnt;
	label_t label;
	bool eli_seen = false;
	bool bos;
	uint32_t hash = 0;
	unsigned int len;

	hdr = mplshdr(m);
	/*
	 * don't hash first label as it is the local label that we
	 * looked up
	 */
	bos = mpls_ls_get_bos(hdr->ls);
	hdr++;

	len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m);

	for (label_cnt = 0; label_cnt < MAX_MP_SELECT_LABELS && !bos;
	     label_cnt++) {
		if (len < (label_cnt + 1) * sizeof(*hdr))
			break;
		label = mpls_ls_get_label(hdr->ls);
		if (label == MPLS_LABEL_ENTROPY) {
			eli_seen = true;
		} else if (label >= MPLS_LABEL_FIRST_UNRESERVED) {
			hash = rte_jhash_1word(label, hash);
			if (eli_seen)
				break;
		}
		bos = mpls_ls_get_bos(hdr->ls);
		hdr++;
	}
	if (bos && likely(len >= (label_cnt + 1) * sizeof(*hdr) + 1)) {
		const struct iphdr *v4hdr = (const struct iphdr *)hdr;
		unsigned int l3offs = (label_cnt + 1) * sizeof(*hdr);

		if (v4hdr->version == 4 &&
		    likely(len >= l3offs + sizeof(struct iphdr)))
			hash = rte_jhash_1word(
				hash,
				ecmp_ipv4_hash(m,
					       dp_pktmbuf_l2_len(m) + l3offs));
		else if (v4hdr->version == 6 &&
			 likely(len >= l3offs + sizeof(struct ip6_hdr)))
			hash = rte_jhash_1word(
				hash,
				ecmp_ipv6_hash(m,
					       dp_pktmbuf_l2_len(m) + l3offs));
	}
	return hash;
}

/*
 * Packet format at this point should look like this:
 *   Ethernet hdr | Popped lbls (0..Np) | Remaining Lbls (0..Nb) | IP hdr
 *   <--------- l2 len ---------------->
 *   Cached labels: 0..Nc
 * i.e. the original label stack is still present, but the L2 len has been
 * adjusted to account for any popped labels.
 * Any labels to be pushed are in the label cache.
 * There must be at least one label, either in the label cache, in the
 * remaining labels, or both.
 */
static inline void nh_eth_output_mpls(enum nh_type nh_type,
				      union next_hop_v4_or_v6_ptr nh,
				      uint8_t ttl, struct rte_mbuf *m,
				      struct mpls_label_cache *cache,
				      struct ifnet *input_ifp)
{
	struct ether_hdr *hdr;
	unsigned int len;

	/*
	 * Replace any popped labels with any labels in the cache
	 */
	if (unlikely(!mpls_label_cache_write(m, cache, ttl, ETHER_HDR_LEN))) {
		mpls_if_incr_out_errors(nh_get_if(nh_type, nh));
		rte_pktmbuf_free(m);
		return;
	}

	/*
	 * Start of buffer should be one eth hdr before the current label.
	 */
	assert(dp_pktmbuf_l2_len(m) == ETHER_HDR_LEN);
	/*
	 * Set the ethertype (the src and dest mac addrs will be in
	 * the output function.
	 */
	hdr = ethhdr(m);
	hdr->ether_type = htons(ETH_P_MPLS_UC);

	len = rte_pktmbuf_pkt_len(m);
	if (nh_type == NH_TYPE_V6GW) {
		if (unlikely((nh.v6->flags & RTF_MAPPED_IPV6))) {
			struct next_hop v4nh = {
				.flags = RTF_GATEWAY,
				.gateway4 = V4MAPPED_IPV6_TO_IPV4(
					nh.v6->gateway6),
				.u.ifp = dp_nh_get_ifp(nh.v6),
			};

			if (dp_ip_l2_nh_output(input_ifp, m, &v4nh,
					       ETH_P_MPLS_UC))
				mpls_if_incr_out_ucastpkts(
						dp_nh_get_ifp(nh.v6),
						len);
		} else {
			struct next_hop v6nh = {
				.flags = RTF_GATEWAY,
				.gateway6 = nh.v6->gateway6,
				.u.ifp = dp_nh_get_ifp(nh.v6),
			};

			if (dp_ip6_l2_nh_output(input_ifp, m,
						&v6nh, ETH_P_MPLS_UC))
				mpls_if_incr_out_ucastpkts(
						dp_nh_get_ifp(nh.v6),
						len);
		}
	} else {
		assert(nh_type == NH_TYPE_V4GW);
		struct next_hop v4nh = {
			.flags = RTF_GATEWAY,
			.gateway4 = nh.v4->gateway4,
			.u.ifp = dp_nh_get_ifp(nh.v4),
		};

		if (dp_ip_l2_nh_output(input_ifp, m, &v4nh,
				       ETH_P_MPLS_UC))
			mpls_if_incr_out_ucastpkts(dp_nh_get_ifp(nh.v4), len);
	}
}

/*
 * mpls fragmentation object
 */
struct mpls_frag_obj_cb {
	unsigned int num_labels;
	unsigned int pop_offset;
	uint8_t ttl;
	enum nh_type nht;
	union next_hop_v4_or_v6_ptr nh;
	struct mpls_label_cache *cache;
	struct mplshdr *remaining_labels;
	struct ifnet *input_ifp;
};

static void
nh_mpls_frag_out(struct ifnet *out_ifp, struct rte_mbuf *m, void *obj)
{
	struct mpls_frag_obj_cb *fobj = obj;
	struct mplshdr *hdr;
	uint32_t offset;

	/*
	 * Prepend back the label stack
	 */
	offset = fobj->num_labels * sizeof(struct mplshdr);
	if (unlikely(!rte_pktmbuf_prepend(m, offset))) {
		DBG_MPLS_PKTERR(out_ifp, m,
				"Not enough room for pushing %d label\n",
				fobj->num_labels);
		mpls_if_incr_out_errors(out_ifp);
		rte_pktmbuf_free(m);
		return;
	}

	/* Copy any remaining labels into the fragment */
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN + fobj->pop_offset;
	hdr = mplshdr(m);
	memcpy(hdr, fobj->remaining_labels, offset - fobj->pop_offset);

	/* Apply cached labels and send mpls pak */
	nh_eth_output_mpls(fobj->nht, fobj->nh, fobj->ttl, m, fobj->cache,
			   fobj->input_ifp);
}

static void
nh_mpls_ip_fragment(struct ifnet *out_ifp, enum mpls_payload_type payload_type,
		    enum nh_type nht, union next_hop_v4_or_v6_ptr nh,
		    bool have_labels, int adjust, uint8_t ttl,
		    struct rte_mbuf *m, struct mpls_label_cache *cache,
		    struct ifnet *input_ifp)
{
	unsigned int mpls_mtu;
	struct mpls_frag_obj_cb fobj;
	struct mplshdr *hdr;
	struct rte_mbuf *icmp;
	unsigned int num_labels;
	unsigned int len;
	uint32_t offset;

	/*
	 * Note offset of popped labels and reset pkt back to original state
	 */
	fobj.remaining_labels = mplshdr(m);
	fobj.pop_offset = dp_pktmbuf_l2_len(m) - ETHER_HDR_LEN;
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;

	if (have_labels) {
		len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m);

		hdr = mplshdr(m);
		for (num_labels = 1; ; hdr++, num_labels++) {
			if (len < num_labels * sizeof(*hdr) ||
			    num_labels > MAX_LABEL_STACK_DEPTH) {
				DBG_MPLS_PKTERR(out_ifp, m,
						"Packet needing fragmentation label stack not valid\n");
				mpls_if_incr_out_errors(out_ifp);
				rte_pktmbuf_free(m);
				return;
			}
			if (mpls_ls_get_bos(hdr->ls))
				break;
		}
	} else {
		num_labels = 0;
	}

	fobj.num_labels = num_labels;
	fobj.nht = nht;
	fobj.nh = nh;
	fobj.ttl = ttl;
	fobj.cache = cache;
	fobj.input_ifp = input_ifp;

	offset = (num_labels * sizeof(struct mplshdr));

	if (payload_type == MPT_IPV4) {
		const struct iphdr *ip;

		dp_pktmbuf_l2_len(m) += offset;

		ip = iphdr(m);
		if (!ip_valid_packet(m, ip)) {
			dp_pktmbuf_l2_len(m) -= offset;
			DBG_MPLS_PKTERR(out_ifp, m,
				 "Packet needing fragmentation not valid\n");
			mpls_if_incr_out_errors(out_ifp);
			rte_pktmbuf_free(m);
			return;
		}

		/* check for ip df bit */
		if (ip->frag_off & htons(IP_DF)) {
			dp_pktmbuf_l2_len(m) = dp_pktmbuf_l2_len(m) -
				offset + fobj.pop_offset;
			if (have_labels) {
				icmp = mpls_icmp_df(out_ifp, m, cache,
						    payload_type,
						    out_ifp->if_mtu);
				if (icmp)
					nh_eth_output_mpls(
						nht, nh, IPDEFTTL,
						icmp, cache, input_ifp);
				else
					mpls_if_incr_out_errors(out_ifp);
			} else {
				icmp_error(out_ifp, m,
					   ICMP_DEST_UNREACH,
					   ICMP_FRAG_NEEDED,
					   htons(out_ifp->if_mtu));
			}
			rte_pktmbuf_free(m);
			return;
		}

		/* strip off the label stack */
		if (!rte_pktmbuf_adj(m, offset)) {
			DP_DEBUG(MPLS_PKTERR, ERR, MPLS,
				 "%s assert for rte_pktmbuf_adj\n",
				 __func__);
			rte_pktmbuf_free(m);
			return;
		}
		dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;
		dp_pktmbuf_l3_len(m) = ip->ihl << 2;

		mpls_if_incr_out_fragment_pkts(out_ifp);

		/*
		 * MPLS MTU takes into account the available MTU
		 * adjusting for any pushed labels from the cache and
		 * any remaining labels before the IP header.
		 */
		mpls_mtu = (adjust <= 0) ? out_ifp->if_mtu :
			out_ifp->if_mtu - adjust;
		mpls_mtu = mpls_mtu - offset + fobj.pop_offset;

		ip_fragment_mtu(out_ifp, mpls_mtu, m, &fobj, nh_mpls_frag_out);
	} else {
		mpls_if_incr_out_errors(out_ifp);
		rte_pktmbuf_free(m);
	}
}

/*
 * forward mpls packet
 * m should hold the mpls packet with m->l2_offset pointing passed popped
 * label and with m->data_offset pointing to where the ethernet header should
 * go. cache should hold any labels to be pushed.
 */
static inline void
nh_mpls_forward(enum mpls_payload_type payload_type,
		enum nh_type nht, union next_hop_v4_or_v6_ptr nh,
		bool have_labels, uint8_t ttl,
		struct rte_mbuf *m, struct mpls_label_cache *cache,
		struct ifnet *input_ifp)
{
	struct ifnet *out_ifp;
	int adjust;

	assert(dp_pktmbuf_l2_len(m) >= ETHER_HDR_LEN);

	/*
	 * Check for fragmentation
	 * adjust pkt len for difference between cached and popped labels
	 */
	out_ifp = nh_get_if(nht, nh);
	adjust = mpls_label_cache_adjust(m, cache, ETHER_HDR_LEN);
	if (likely(rte_pktmbuf_pkt_len(m) + adjust - ETHER_HDR_LEN <=
		   out_ifp->if_mtu)) {
		nh_eth_output_mpls(nht, nh, ttl, m, cache,
					input_ifp);
	} else
		nh_mpls_ip_fragment(out_ifp, payload_type, nht, nh,
				    have_labels, adjust, ttl, m, cache,
				    input_ifp);
}

static inline bool mpls_propagate_ttl_to_ip(struct iphdr *ip, uint8_t ttl,
					    bool pop)
{
	if (propagate_ttl == TTL_PROPAGATE_ENABLED) {
		/*
		 * In uniform model propagate mpls ttl into
		 * encapsulated frame.
		 */
		ip_set_ttl(ip, ttl);
	} else if (pop) {
		/*
		 * In pipe model without php, check & decrement ip ttl.
		 */
		if (unlikely(ip->ttl <= IPTTLDEC))
			return false;
		ip_set_ttl(ip, ip->ttl - 1);
	}
	return true;
}

static inline bool mpls_propagate_ttl_to_ip6(struct ip6_hdr *ip6, uint8_t ttl,
					     bool pop)
{
	if (propagate_ttl == TTL_PROPAGATE_ENABLED) {
		/*
		 * In uniform model propagate mpls ttl into
		 * encapsulated frame.
		 */
		ip6->ip6_hlim = ttl;
	} else if (pop) {
		/*
		 * In pipe model without php, check & decrement ip ttl.
		 */
		if (unlikely(ip6->ip6_hlim <= IPV6_HLIMDEC))
			return false;
		ip6->ip6_hlim -= IPV6_HLIMDEC;
	}
	return true;
}

static ALWAYS_INLINE void
mpls_forward_to_ipv4(struct ifnet *ifp, bool local,
		     struct rte_mbuf *m, struct next_hop *v4nh,
		     uint8_t ttl, bool pop)
{
	uint32_t pop_offset;
	struct iphdr *ip;
	unsigned int len;

	/*
	 * Disposition to ipv4.
	 */
	assert(dp_pktmbuf_l2_len(m) >= ETHER_HDR_LEN);
	/*
	 * Fixup mbuf before we give it back to ip.
	 * Adjust the pkt start to be one eth hdr in
	 * front of current l2 offset - to componsate
	 * for any pops.
	 */
	pop_offset = dp_pktmbuf_l2_len(m) - ETHER_HDR_LEN;
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;

	if (!rte_pktmbuf_adj(m, pop_offset)) {
		DBG_MPLS_PKTERR(ifp, m,
			"%s assert for rte_pktmbuf_adj\n",
			__func__);
		if (likely(ifp != NULL))
			mpls_if_incr_in_errors(ifp);
		rte_pktmbuf_free(m);
		return;
	}

	ethhdr(m)->ether_type = htons(ETHER_TYPE_IPv4);

	/*
	 * Is packet big enough.
	 * (i.e is there a valid IP header in first segment)
	 */
	len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m);
	if (unlikely(len < sizeof(struct iphdr))) {
		DBG_MPLS_PKTERR(ifp, m,
			 "Truncated packet during forward as IPv4 (%u). Dropping...\n",
			 len);
		if (likely(ifp != NULL))
			mpls_if_incr_in_errors(ifp);
		rte_pktmbuf_free(m);
		return;
	}

	pktmbuf_set_vrf(m, if_vrfid(dp_nh_get_ifp(v4nh)));

	ip = iphdr(m);
	if (!local && unlikely(!mpls_propagate_ttl_to_ip(ip, ttl, pop))) {
		IPSTAT_INC_IFP(ifp, IPSTATS_MIB_INHDRERRORS);
		if (ip_valid_packet(m, ip))
			icmp_error(ifp, m, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);
		rte_pktmbuf_free(m);
		return;
	}

	enum ip4_features ip4_feat = IP4_FEA_DECAPPED;
	if (local) {
		ip4_feat |= IP4_FEA_ORIGINATE;
		/*
		 * ifp must be non-NULL, but all we've got is the
		 * output ifp so use that.
		 */
		ifp = dp_nh_get_ifp(v4nh);
		if (!ifp) {
			rte_pktmbuf_free(m);
			return;
		}
	}
	ip_out_features(m, ifp, ip, v4nh, v4nh->gateway4, ip4_feat,
			NPF_FLAG_CACHE_EMPTY);
}

static void mpls_forward_to_ipv6(struct ifnet *ifp, bool local,
				 struct rte_mbuf *m,
				 struct next_hop *v6nh,
				 uint8_t ttl, bool pop)
{
	uint32_t pop_offset;
	struct ip6_hdr *ip6;
	unsigned int len;

	/*
	 * Disposition to ipv6.
	 */
	assert(dp_pktmbuf_l2_len(m) >= ETHER_HDR_LEN);

	/*
	 * Fixup mbuf before we give it back to ip.
	 * Adjust the pkt start to be one eth hdr in
	 * front of current l2 offset - to componsate
	 * for any pops.
	 */
	pop_offset = dp_pktmbuf_l2_len(m) - ETHER_HDR_LEN;
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;

	if (!rte_pktmbuf_adj(m, pop_offset)) {
		DBG_MPLS_PKTERR(ifp, m,
			"%s assert for rte_pktmbuf_adj\n",
			__func__);
		if (likely(ifp != NULL))
			mpls_if_incr_in_errors(ifp);
		rte_pktmbuf_free(m);
		return;
	}

	ethhdr(m)->ether_type = htons(ETHER_TYPE_IPv6);

	/*
	 * Is packet big enough.
	 * (i.e is there a valid IPv6 header in first segment)
	 */
	len = rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m);
	if (unlikely(len < sizeof(struct ip6_hdr))) {
		DBG_MPLS_PKTERR(ifp, m,
			"Truncated packet during forward as IPv6 (%u). Dropping...\n",
			len);
		if (likely(ifp != NULL))
			mpls_if_incr_in_errors(ifp);
		rte_pktmbuf_free(m);
		return;
	}

	pktmbuf_set_vrf(m, if_vrfid(dp_nh_get_ifp(v6nh)));

	ip6 = ip6hdr(m);
	if (!local && unlikely(!mpls_propagate_ttl_to_ip6(ip6, ttl, pop))) {
		IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INHDRERRORS);
		if (ip6_valid_packet(m, ip6)) {
			struct rte_mbuf *n;

			n = icmp6_do_error(ifp, m, ICMP6_TIME_EXCEEDED,
					   ICMP6_TIME_EXCEED_TRANSIT, 0,
					   IPV6_ADDR_SCOPE_GLOBAL);
			if (n)
				icmp6_reflect(ifp, n);
		}
		rte_pktmbuf_free(m);
		return;
	}

	enum ip6_features ip6_feat = IP6_FEA_DECAPPED;

	if (local) {
		ip6_feat |= IP4_FEA_ORIGINATE;
		/*
		 * ifp must be non-NULL, but all we've got is the
		 * output ifp so use that.
		 */
		ifp = dp_nh_get_ifp(v6nh);
		if (!ifp) {
			rte_pktmbuf_free(m);
			return;
		}
	}
	ip6_out_features(m, ifp, ip6, v6nh, ip6_feat, NPF_FLAG_CACHE_EMPTY);
}

/*
 * Deliver local destined MPLS encapsulated vpnv4 packet to slow path
 * Cut down version of ip_local_deliver which does firewall only
 */
static void mpls_vpnv4_local_deliver(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct vrf *vrf = if_vrf(ifp);
	struct iphdr *ip = iphdr(m);

	/* Real MTU on slow path maybe lower
	 *  because of the overhead of GRE header
	 */
	if (slowpath_mtu && ntohs(ip->tot_len) > slowpath_mtu) {
		if (ip->frag_off & htons(IP_DF)) {
			/* Handle with icmp reply needfrag
			 * for TCP MTU discovery
			 */
			IPSTAT_INC_VRF(vrf, IPSTATS_MIB_FRAGFAILS);
			icmp_error(ifp, m, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
				   htonl(slowpath_mtu));
			rte_pktmbuf_free(m);
			return;
		}
		/* Let raw socket in kernel handle fragmentation */
	}

	/*
	 * CPP input firewall. Enables RFC-6192.
	 *
	 * Run the local firewall,  and discard if so instructed.
	 */
	if (npf_local_fw(ifp, &m, htons(ETHER_TYPE_IPv4)))
		goto discard;

	IPSTAT_INC_VRF(vrf, IPSTATS_MIB_INDELIVERS);
	local_packet(ifp, m);
	return;

discard:
	IPSTAT_INC_VRF(vrf, IPSTATS_MIB_INDISCARDS);
	rte_pktmbuf_free(m);
}

static bool mpls_reswitch_as_ipv4(struct ifnet *input_ifp,
				  struct rte_mbuf *m, vrfid_t vrfid,
				  uint8_t ttl)
{
	struct iphdr *ip = iphdr(m);
	uint32_t pop_offset;
	bool is_local;

	if (unlikely(!ip_valid_packet(m, ip))) {
		DBG_MPLS_PKTERR(input_ifp, m,
				"failed to reswitch as ipv4 - invalid pkt\n");
		return false;
	}

	pktmbuf_set_vrf(m, vrfid);

	/* Is it for a local address on this host? */
	if (likely(input_ifp != NULL))
		is_local = is_local_ipv4(vrfid, ip->daddr);
	else
		is_local = false;

	/*
	 * For local delivery into a vrf, run local firewall then punt with
	 * MPLS encap intact so that kernel can handle the cross-vrf deagg
	 * correctly.
	 */
	if (vrfid != VRF_DEFAULT_ID && is_local) {
		mpls_vpnv4_local_deliver(input_ifp, m);
		return true;
	}

	/*
	 * Fixup mbuf before we give it back to ip.  Currently this
	 * means setting the ether header to be in front of our
	 * current label and setting the ethertype to be ip.
	 */
	assert(dp_pktmbuf_l2_len(m) >= ETHER_HDR_LEN);
	pop_offset = dp_pktmbuf_l2_len(m) - ETHER_HDR_LEN;

	memmove((uint8_t *)ethhdr(m) + pop_offset, ethhdr(m), ETH_HLEN);
	if (!rte_pktmbuf_adj(m, pop_offset)) {
		DBG_MPLS_PKTERR(input_ifp, m,
			"%s assert for rte_pktmbuf_adj\n",
			__func__);
		return false;
	}
	ethhdr(m)->ether_type = htons(ETHER_TYPE_IPv4);
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;

	if (likely(input_ifp != NULL)) {
		/* Propagate or decrement (if not local) the ttl */
		if (unlikely(!mpls_propagate_ttl_to_ip(ip, ttl, !is_local))) {
			IPSTAT_INC_IFP(input_ifp, IPSTATS_MIB_INHDRERRORS);
			icmp_error(input_ifp, m, ICMP_TIME_EXCEEDED,
				   ICMP_EXC_TTL, 0);
			return false;
		}

		/* Is it for a local address on this host? */
		if (is_local) {
			if (l4_input(&m, input_ifp) > 0)
				ip_local_deliver(input_ifp, m);
			return true;
		}

		pktmbuf_prepare_decap_reswitch(m);
		ip_lookup_and_forward(m, input_ifp, true,
				      NPF_FLAG_CACHE_EMPTY);
	} else {
		ip_output(m, false);
	}
	return true;
}

/*
 * Deliver local destined MPLS encapsulated vpnv6 packet to slow path
 * Cut down version of ip6_local_deliver which does firewall only
 */
static void mpls_vpnv6_local_deliver(struct ifnet *ifp, struct rte_mbuf *m)
{
	struct ip6_hdr *ip6 = ip6hdr(m);

	/* Real MTU on slow path maybe lower
	 * because of the overhead of GRE header
	 */
	if (slowpath_mtu
	    && ntohs(ip6->ip6_plen) + sizeof(*ip6) > slowpath_mtu) {
		IP6STAT_INC_MBUF(m, IPSTATS_MIB_FRAGFAILS);
		icmp6_error(ifp, m, ICMP6_PACKET_TOO_BIG, 0,
			    slowpath_mtu);
		return;
	}

	/*
	 * CPP input firewall. Enables RFC-6192.
	 *
	 * Run the local firewall,  and discard if so instructed.
	 */
	if (npf_local_fw(ifp, &m, htons(ETHER_TYPE_IPv6)))
		goto discard;

	IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INDELIVERS);
	local_packet(ifp, m);
	return;

discard:
	IP6STAT_INC_IFP(ifp, IPSTATS_MIB_INDISCARDS);
	rte_pktmbuf_free(m);
}

static bool mpls_reswitch_as_ipv6(struct ifnet *input_ifp,
				  struct rte_mbuf *m, vrfid_t vrfid,
				  uint8_t ttl)
{
	struct ip6_hdr *ip6 = ip6hdr(m);
	uint32_t pop_offset;
	bool is_local;

	if (unlikely(!ip6_valid_packet(m, ip6))) {
		DBG_MPLS_PKTERR(input_ifp, m,
				"failed to reswitch as ipv6 - invalid pkt");
		return false;
	}

	pktmbuf_set_vrf(m, vrfid);

	/* Is it for a local address on this host? */
	if (likely(input_ifp != NULL))
		is_local = is_local_ipv6(vrfid, &ip6->ip6_dst);
	else
		is_local = false;

	/*
	 * For local delivery into a vrf, run local firewall then punt with
	 * MPLS encap intact so that kernel can handle the cross-vrf deagg
	 * correctly.
	 */
	if (vrfid != VRF_DEFAULT_ID && is_local) {
		mpls_vpnv6_local_deliver(input_ifp, m);
		return true;
	}

	/*
	 * Fixup mbuf before we give it back to ip.  Currently this
	 * means setting the ether header to be in front of our
	 * current label and setting the ethertype to be ipv6.
	 */
	assert(dp_pktmbuf_l2_len(m) >= ETHER_HDR_LEN);
	pop_offset = dp_pktmbuf_l2_len(m) - ETHER_HDR_LEN;

	memmove((uint8_t *)ethhdr(m) + pop_offset, ethhdr(m), ETH_HLEN);
	if (!rte_pktmbuf_adj(m, pop_offset)) {
		DBG_MPLS_PKTERR(input_ifp, m,
			"%s assert for rte_pktmbuf_adj\n",
			__func__);
		return false;
	}
	ethhdr(m)->ether_type = htons(ETHER_TYPE_IPv6);
	dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;

	if (likely(input_ifp != NULL)) {
		/* Propagate or decrement (if not local) the ttl */
		if (unlikely(!mpls_propagate_ttl_to_ip6(ip6, ttl, !is_local))) {
			IP6STAT_INC_IFP(input_ifp, IPSTATS_MIB_INHDRERRORS);
			if (ip6_valid_packet(m, ip6)) {
				struct rte_mbuf *n;

				n = icmp6_do_error(input_ifp, m,
						   ICMP6_TIME_EXCEEDED,
						   ICMP6_TIME_EXCEED_TRANSIT,
						   0, IPV6_ADDR_SCOPE_GLOBAL);
				if (n)
					icmp6_reflect(input_ifp, n);
			}
			return false;
		}

		/* Is it for a local address on this host? */
		if (is_local) {
			ip6_l4_input(m, input_ifp);
			return true;
		}

		pktmbuf_prepare_decap_reswitch(m);
		ip6_lookup_and_forward(m, input_ifp, true,
				       NPF_FLAG_CACHE_EMPTY);
	} else {
		ip6_output(m, false);
	}
	return true;
}

static ALWAYS_INLINE void
mpls_labeled_forward(struct ifnet *input_ifp, bool local,
		     struct rte_mbuf *m)
{
	enum mpls_payload_type payload_type;
	struct mpls_label_cache cache;
	struct cds_lfht *label_table;
	struct mplshdr *hdr;
	enum nh_fwd_ret ret;
	uint32_t in_label;
	enum nh_type nht;
	uint8_t ttl;
	union next_hop_v4_or_v6_ptr nh;
	bool pop;

	mpls_label_cache_init(&cache);

	if (!local)
		mpls_if_incr_in_ucastpkts(
			input_ifp, rte_pktmbuf_pkt_len(m));

	hdr = mplshdr_safe(m);
	if (unlikely(!hdr)) {
		DBG_MPLS_PKTERR(input_ifp, m,
				"mpls_labeled_input truncated packet %u if %s(%d)\n",
				rte_pktmbuf_data_len(m) - dp_pktmbuf_l2_len(m),
				local ? "(local)" : input_ifp->if_name,
				local ? 0 : input_ifp->if_index);
		goto drop;
	}
	ttl = mpls_ls_get_ttl(hdr->ls);

	if (unlikely(ttl <= 1) && !local) {
		struct rte_mbuf *icmp;

		if (is_mpls_oam(input_ifp, m)) {
			/*
			 * CPP input firewall. Enables RFC-6192.
			 *
			 * Run the local firewall, and discard if so instructed.
			 */
			if (npf_local_fw(input_ifp, &m, htons(ETH_P_MPLS_UC)))
				goto drop;
			local_packet(input_ifp, m);
			return;
		}

		icmp = mpls_icmp_ttl(input_ifp, m, &cache);
		if (!icmp)
			goto drop;
		rte_pktmbuf_free(m);
		mpls_output(icmp);
		return;
	}

	/*
	 * Decrement ttl unless this is a locally generated packet
	 */
	if (!local)
		ttl--;

	do {
		in_label = mpls_ls_get_label(hdr->ls);

		if (local)
			label_table = rcu_dereference(global_label_table);
		else
			label_table = rcu_dereference(
				input_ifp->mpls_label_table);
		nh = mpls_label_table_lookup(label_table, in_label, m,
					     ETH_P_MPLS_UC, &nht,
					     &payload_type);
		if (unlikely(!nh.v4)) {
			if (!local && label_table) {
				DBG_MPLS_PKTERR(input_ifp, m,
						"label table entry not found\n");
				mpls_if_incr_lbl_lookup_failures(input_ifp);
			} else
				DBG_MPLS_PKTERR(input_ifp, m,
						"dropping as forwarding not enabled on interface\n");
			break;
		}

		ret = nh_fwd_mpls(nht, nh, m, true, payload_type, &cache, &pop);

		if (likely(ret == NH_FWD_IPv4)) {
			mpls_forward_to_ipv4(input_ifp, local, m, nh.v4, ttl,
					     pop);
			return;
		} else if (likely(ret == NH_FWD_SUCCESS)) {
			nh_mpls_forward(payload_type, nht, nh, true,
					ttl, m, &cache, input_ifp);
			return;
		} else if (likely(ret == NH_FWD_IPv6)) {
			mpls_forward_to_ipv6(input_ifp, local, m, nh.v6, ttl,
					     pop);
			return;
		} else if (unlikely(ret == NH_FWD_RESWITCH_IPv4)) {
			if (!mpls_reswitch_as_ipv4(
				    input_ifp, m, dp_nh_get_ifp(nh.v4) ?
				    if_vrfid(dp_nh_get_ifp(nh.v6)) :
				    VRF_DEFAULT_ID, ttl))
				goto drop;
			return;
		} else if (unlikely(ret == NH_FWD_RESWITCH_IPv6)) {
			if (!mpls_reswitch_as_ipv6(
				    input_ifp, m, dp_nh_get_ifp(nh.v6) ?
				    if_vrfid(dp_nh_get_ifp(nh.v6)) :
				    VRF_DEFAULT_ID, ttl))
				goto drop;
			return;
		} else if (unlikely(ret == NH_FWD_SLOWPATH)) {
			/*
			 * Put the packet back to its newly arrived
			 * state.  NOTE: we are assuming that we
			 * haven't swapped or pushed or popped any
			 * labels here so that we can simply reset
			 * the L2 len to ethernet.
			 */
			dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;
			if (unlikely(local))
				break;
			/*
			 * CPP input firewall. Enables RFC-6192.
			 *
			 * Run the local firewall, and discard if so instructed.
			 */
			if (npf_local_fw(input_ifp, &m, htons(ETH_P_MPLS_UC)))
				break;
			local_packet(input_ifp, m);
			return;
		} else if (unlikely(ret == NH_FWD_FAILURE)) {
			break;
		}
		/*
		 * We don't support push/swap and lookup semantics so we
		 * cannot currently have labels in the label cache when we get
		 * here.
		 */
		assert(!cache.num_labels);
		hdr = mplshdr_safe(m);
		if (unlikely(!hdr))
			break;
	} while (unlikely(ret == NH_FWD_RESWITCH_MPLS));
drop:
	if (!local) {
		DBG_MPLS_PKTERR(input_ifp, m,
				"Dropping mpls pkt\n");
		mpls_if_incr_in_errors(input_ifp);
	}
	rte_pktmbuf_free(m);
}

void mpls_labeled_input(struct ifnet *input_ifp, struct rte_mbuf *m)
{
	mpls_labeled_forward(input_ifp, false /* non-local */, m);
}

static void mpls_output(struct rte_mbuf *m)
{
	mpls_labeled_forward(NULL, true /* locally generated */, m);
}

void mpls_unlabeled_input(struct ifnet *input_ifp, struct rte_mbuf *m,
			  enum nh_type ip_nh_type,
			  union next_hop_v4_or_v6_ptr ip_nh,
			  uint8_t ttl)
{
	const union next_hop_outlabels *labels;
	enum mpls_payload_type payload_type;
	struct mpls_label_cache cache;
	unsigned int num_labels;
	uint32_t local_label;
	uint16_t ether_type;
	enum nh_fwd_ret ret;
	unsigned int i = 0;
	enum nh_type nht;
	union next_hop_v4_or_v6_ptr nh;
	label_t label;
	uint8_t bos;

	mpls_label_cache_init(&cache);

	if (propagate_ttl != TTL_PROPAGATE_ENABLED)
		ttl = default_ttl;

	if (unlikely(nh_get_flags(ip_nh_type, ip_nh) & RTF_OUTLABEL)) {
		/*
		 * Output labels are provided
		 * Payload type is not required for imposition but needs to be
		 * initialized.
		 */
		nht = ip_nh_type;
		nh = ip_nh;
		payload_type = MPT_UNSPEC;
	} else {
		/*
		 * Push all except the top (local) label onto the label cache
		 */
		labels = nh_get_labels(ip_nh_type, ip_nh);
		num_labels = nh_outlabels_get_cnt(labels);
		assert(num_labels);
		bos = true;
		/*
		 * Avoid uninit variable compilation error.
		 * This will never get used but compiler can't tell.
		 */
		local_label = MPLS_IMPLICITNULL;
		NH_FOREACH_OUTLABEL(labels, i, label) {
			if (i < (num_labels - 1)) {
				if (!mpls_label_cache_push(&cache, label, bos))
					goto drop;
			} else
				local_label = label;
			bos = false;
		}

		/* Assumes nexthop address family == link address family */
		if (ip_nh_type == NH_TYPE_V6GW)
			ether_type = ETHER_TYPE_IPv6;
		else {
			assert(ip_nh_type == NH_TYPE_V4GW);
			ether_type = ETHER_TYPE_IPv4;
		}

		/*
		 * Lookup in label table using top (local) label
		 */
		nh = mpls_label_table_lookup(
			rcu_dereference(global_label_table), local_label,
			m, ether_type, &nht, &payload_type);

		if (unlikely(!nh.v4)) {
			DBG_MPLS_PKTERR(input_ifp, m,
				 "%s %s: no route for %d\n", __func__,
				 input_ifp ? input_ifp->if_name : "(local)",
					local_label);
			goto drop;
		}
	}

	ret = nh_fwd_mpls(nht, nh, m, false, payload_type, &cache, NULL);

	if (likely(ret == NH_FWD_SUCCESS)) {
		nh_mpls_forward(payload_type, nht, nh, false, ttl,
				m, &cache, input_ifp);
		return;
	} else if (likely(ret == NH_FWD_IPv4)) {
		mpls_forward_to_ipv4(input_ifp, input_ifp == NULL, m,
				     nh.v4, ttl, false);
		return;
	} else if (likely(ret == NH_FWD_IPv6)) {
		mpls_forward_to_ipv6(input_ifp, input_ifp == NULL, m,
				     nh.v6, ttl, false);
		return;
	} else if (unlikely(ret == NH_FWD_SLOWPATH)) {
		/*
		 * Put the packet back to its newly arrived
		 * state.  NOTE: we are assuming that we
		 * haven't swapped or pushed or popped any
		 * labels here so that we can simply reset
		 * the L2 len to ethernet.
		 */
		dp_pktmbuf_l2_len(m) = ETHER_HDR_LEN;
		if (nht == NH_TYPE_V4GW) {
			struct iphdr *ip = iphdr(m);

			ip_set_ttl(ip, ip->ttl + 1);
		}
		local_packet(input_ifp, m);
		return;
	}

	DBG_MPLS_PKTERR(input_ifp, m,
			"mpls_unlabeled_input unexpected switch result %d\n",
			ret);

drop:
	if (likely(input_ifp != NULL))
		mpls_if_incr_in_errors(input_ifp);
	rte_pktmbuf_free(m);
}
