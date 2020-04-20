/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdbool.h>
#include <stdint.h>
/*
 * Equal-cost multi-path routing
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/mpls.h>
#include <linux/mpls_iptunnel.h>
#include <linux/lwtunnel.h>
#include <linux/netlink.h>
#include <libmnl/libmnl.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_jhash.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "compiler.h"
#include "commands.h"
#include "ecmp.h"
#include "if_var.h"
#include "ip_forward.h"
#include "ip_funcs.h"
#include "json_writer.h"
#include "mpls/mpls.h"
#include "mpls/mpls_forward.h"
#include "netinet6/in6.h"
#include "netinet6/route_v6.h"
#include "pktmbuf_internal.h"
#include "route.h"
#include "route_flags.h"
#include "util.h"
#include "vplane_log.h"

#define IN6_SET_ADDR_V4MAPPED(a6, a4) {			\
		(a6)->s6_addr32[0] = 0;			\
		(a6)->s6_addr32[1] = 0;			\
		(a6)->s6_addr32[2] = htonl(0xffff);	\
		(a6)->s6_addr32[3] = (a4);		\
	}

/* Global ECMP mode */
static uint8_t ecmp_mode = ECMP_HRW;

/* Global ECMP max path param */
uint16_t ecmp_max_path = UINT16_MAX;

/* ECMP modes */
static const char *ecmp_modes[ECMP_MAX] = {
	[ECMP_DISABLED]		= "disable",
	[ECMP_HASH_THRESHOLD]	= "hash-threshold",
	[ECMP_HRW]		= "hrw",
	[ECMP_MODULO_N]		= "modulo-n",
};

/* Callback to store route attributes */
static int route_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	unsigned int type = mnl_attr_get_type(attr);

	if (type <= RTA_MAX)
		tb[type] = attr;

	return MNL_CB_OK;
}

/* Fill nexthop struct */
static bool nexthop_fill(struct nlattr *ntb_gateway, struct nlattr *ntb_encap,
			 struct rtnexthop *nhp, struct next_hop *next)
{
	label_t labels[NH_MAX_OUT_LABELS];
	uint16_t num_labels = 0;
	void *labels_ptr;
	uint32_t len;
	int err;
	struct ifnet *ifp;

	nh_outlabels_set(&next->outlabels, 0, NULL);

	nh4_set_ifp(next, dp_ifnet_byifindex(nhp->rtnh_ifindex));
	if (!dp_nh4_get_ifp(next) && !is_ignored_interface(nhp->rtnh_ifindex))
		return true;
	if (ntb_gateway) {
		next->gateway4 = mnl_attr_get_u32(ntb_gateway);
		next->flags = RTF_GATEWAY;
	} else {
		next->gateway4 = INADDR_ANY;
		next->flags = 0;
	}

	if (ntb_encap) {
		len = mnl_attr_get_payload_len(ntb_encap);
		labels_ptr = mnl_attr_get_payload(ntb_encap);
		err = rta_encap_get_labels(labels_ptr, len,
					   ARRAY_SIZE(labels),
					   labels, &num_labels);
		if (err) {
			RTE_LOG(NOTICE, MPLS,
				"malformed label stack in netlink message\n");
			return false;
		}
		nh_outlabels_set(&next->outlabels, num_labels, labels);
	}

	ifp = dp_nh4_get_ifp(next);
	if ((!ifp || ifp->if_type == IFT_LOOP) &&
	    num_labels == 0)
		/* no dp interface or via loopback */
		next->flags |= RTF_SLOWPATH;

	if (num_labels > 0 && !is_lo(ifp))
		/* Output label rather than local label */
		next->flags |= RTF_OUTLABEL;

	return false;
}

static int mpls_payload_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, RTMPA_NH_FLAGS) < 0)
		return MNL_CB_OK;

	switch (type) {
	case RTMPA_TYPE:
	case RTMPA_NH_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			RTE_LOG(NOTICE, MPLS,
				"invalid mpls payload attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static bool nexthop_fill_mpls_common(const struct nlattr *ntb_newdst,
				     union next_hop_outlabels *outlabels,
				     bool bos_only)
{
	label_t labels[NH_MAX_OUT_LABELS];
	uint16_t num_labels = 0;
	void *labels_ptr;
	uint32_t len;
	int ret;

	if (ntb_newdst) {
		len = mnl_attr_get_payload_len(ntb_newdst);
		labels_ptr = mnl_attr_get_payload(ntb_newdst);
		ret = rta_encap_get_labels(labels_ptr, len,
					   ARRAY_SIZE(labels),
					   labels, &num_labels);
		if (ret) {
			RTE_LOG(NOTICE, MPLS,
				"malformed label stack in netlink message\n");
			return false;
		}
		nh_outlabels_set(outlabels, num_labels, labels);
	}

	/*
	 * If there are no labels and BOS_ONLY not
	 * set, then this implies the implicit-null
	 * label. This won't go out on the wire and is
	 * for signaling only.
	 */
	if (num_labels == 0 && !bos_only) {
		label_t lbl[1] = { MPLS_LABEL_IMPLNULL };

		nh_outlabels_set(outlabels, 1, lbl);
	}

	return false;
}

/*
 * Fill nh struct from an mpls route add netlink - which uses different
 * attributes - via, newdest instead of gateway, encap.
 */
static bool nexthop_fill_mpls(struct nlattr *ntb_via, struct nlattr *ntb_newdst,
			      struct nlattr *ntb_payload,
			      struct rtnexthop *nhp, struct next_hop *next)
{
	const struct nlattr *pl_tb[RTMPA_NH_FLAGS+1];
	bool bos_only = false;
	int ret;

	if (ntb_payload) {
		ret = mnl_attr_parse_nested(ntb_payload, mpls_payload_attr,
					    &pl_tb);
		if (ret == MNL_CB_OK && pl_tb[RTMPA_NH_FLAGS])
			bos_only = (mnl_attr_get_u32(pl_tb[RTMPA_NH_FLAGS]) &
				    RTMPNF_BOS_ONLY) != 0;
	}

	/* initialize out labels to NULL */
	nh_outlabels_set(&next->outlabels, 0, NULL);

	nh4_set_ifp(next, dp_ifnet_byifindex(nhp->rtnh_ifindex));
	if (!dp_nh4_get_ifp(next) && !is_ignored_interface(nhp->rtnh_ifindex))
		return true;
	if (ntb_via) {
		const struct rtvia *via;
		in_addr_t nh = INADDR_NONE;

		via = mnl_attr_get_payload(ntb_via);
		if (via->rtvia_family == AF_INET) {
			memcpy(&nh, &via->rtvia_addr, sizeof(nh));
			next->flags = RTF_GATEWAY;
		} else {
			RTE_LOG(NOTICE, MPLS,
				"unsupported via AF %d in netlink message\n",
				via->rtvia_family);
		}

		next->gateway4 = nh;
	} else {
		next->gateway4 = INADDR_ANY;
		next->flags = 0;
	}

	ret = nexthop_fill_mpls_common(ntb_newdst, &next->outlabels, bos_only);
	if (!dp_nh4_get_ifp(next))
		next->flags |= RTF_SLOWPATH;

	return ret;
}

/*
 * Fill nh6 struct from an mpls route add netlink.
 */
static bool nexthop6_fill_mpls(const struct nlattr *ntb_via,
			       const struct nlattr *ntb_newdst,
			       const struct nlattr *ntb_payload,
			       const struct rtnexthop *nhp,
			       struct next_hop_v6 *next)
{
	const struct nlattr *pl_tb[RTMPA_NH_FLAGS+1];
	struct in6_addr nh6 = IN6ADDR_ANY_INIT;
	bool bos_only = false;
	int ret;

	if (ntb_payload) {
		ret = mnl_attr_parse_nested(ntb_payload, mpls_payload_attr,
					    &pl_tb);
		if (ret == MNL_CB_OK && pl_tb[RTMPA_NH_FLAGS])
			bos_only = (mnl_attr_get_u32(pl_tb[RTMPA_NH_FLAGS]) &
				    RTMPNF_BOS_ONLY) != 0;
	}

	/* initialise out labels to NULL */
	nh_outlabels_set(&next->outlabels, 0, NULL);

	nh6_set_ifp(next, dp_ifnet_byifindex(nhp->rtnh_ifindex));
	if (!dp_nh6_get_ifp(next) && !is_ignored_interface(nhp->rtnh_ifindex))
		return true;
	if (ntb_via) {
		const struct rtvia *via;
		in_addr_t nh = INADDR_NONE;

		via = mnl_attr_get_payload(ntb_via);
		if (via->rtvia_family == AF_INET) {
			memcpy(&nh, &via->rtvia_addr, sizeof(nh));
			IN6_SET_ADDR_V4MAPPED(&nh6, nh);
		} else if (via->rtvia_family == AF_INET6) {
			memcpy(&nh6, &via->rtvia_addr, sizeof(nh6));
		} else {
			RTE_LOG(NOTICE, MPLS,
				"unsupported via AF %d in netlink message\n",
				via->rtvia_family);
		}

		next->gateway = nh6;
		next->flags = RTF_GATEWAY;
		if (IN6_IS_ADDR_V4MAPPED(&nh6))
			next->flags |= RTF_MAPPED_IPV6;
	} else {
		next->gateway = nh6;
		next->flags = 0;
	}

	ret = nexthop_fill_mpls_common(ntb_newdst, &next->outlabels, bos_only);
	if (!dp_nh6_get_ifp(next))
		next->flags |= RTF_SLOWPATH;

	return ret;
}

static int mpls_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, MPLS_IPTUNNEL_MAX) < 0)
		return MNL_CB_OK;

	tb[type] = attr;
	return MNL_CB_OK;
}

/* Create nexthop struct */
struct next_hop *ecmp_create(struct nlattr *mpath, uint32_t *count,
			     bool *missing_ifp)
{
	size_t size = 0, i;
	struct next_hop *next, *n;
	void *vnhp;

	/*
	 * Need to loop over the paths to find out how many there are
	 * as the size is not fixed because the gateway is optional.
	 */
	mnl_attr_for_each_nested(vnhp, mpath) {
		size++;
	}

	if (!size)
		return NULL;

	n = next = calloc(sizeof(struct next_hop), size);
	if (!next)
		return NULL;

	mnl_attr_for_each_nested(vnhp, mpath) {
		struct rtnexthop *nhp = vnhp;

		if (nhp->rtnh_len == sizeof(*nhp)) {
			/* There is a NH with no extra attrs */
			if (nexthop_fill(NULL, NULL, nhp, n))
				goto missing;
			n++;

		} else if (nhp->rtnh_len > sizeof(*nhp)) {
			struct nlattr *ntb[RTA_MAX+1] = { NULL };
			struct nlattr *mpls_ntb[MPLS_IPTUNNEL_MAX+1] = { NULL };

			int res = mnl_attr_parse_payload(RTNH_DATA(vnhp),
						 nhp->rtnh_len - sizeof(*nhp),
						 route_attr, ntb);

			if (res != MNL_CB_OK)
				goto failed;

			if (ntb[RTA_ENCAP] && ntb[RTA_ENCAP_TYPE] &&
			    (mnl_attr_get_u16(ntb[RTA_ENCAP_TYPE]) ==
			     LWTUNNEL_ENCAP_MPLS)) {
				res = mnl_attr_parse_nested(ntb[RTA_ENCAP],
							    mpls_attr,
							    mpls_ntb);
				if (res != MNL_CB_OK) {
					RTE_LOG(NOTICE, DATAPLANE,
						"unparseable mpls attributes\n");
					goto failed;
				}
			}

			res = mnl_attr_parse_payload(
				RTNH_DATA(vnhp), nhp->rtnh_len - sizeof(*nhp),
				route_attr, ntb);

			if (res != MNL_CB_OK)
				goto failed;

			if (ntb[RTA_VIA]) {
				if (nexthop_fill_mpls(ntb[RTA_VIA],
						      ntb[RTA_NEWDST],
						      ntb[RTA_MPLS_PAYLOAD],
						      nhp, n)) {
					goto missing;
				}
			} else {
				if (nexthop_fill(ntb[RTA_GATEWAY],
						 mpls_ntb[MPLS_IPTUNNEL_DST],
						 nhp, n)) {
					goto missing;
				}
			}
			n++;
		}
	}

	*count = n - next;

	return next;

missing:
	*missing_ifp = true;
failed:
	size = n - next;
	for (i = 0; i < size; i++)
		nh_outlabels_destroy(&next[i].outlabels);
	free(next);
	return NULL;
}

static const struct in6_addr anyaddr;

/* Fill nexthop struct */
static bool nexthop6_fill(struct nlattr *ntb_gateway,
			  struct nlattr *ntb_encap,
			  struct rtnexthop *nhp, struct next_hop_v6 *next)
{
	label_t labels[NH_MAX_OUT_LABELS];
	uint16_t num_labels = 0;
	void *labels_ptr;
	uint32_t len;
	int err;
	struct ifnet *ifp;

	nh_outlabels_set(&next->outlabels, 0, NULL);

	nh6_set_ifp(next, dp_ifnet_byifindex(nhp->rtnh_ifindex));
	if (!dp_nh6_get_ifp(next) && !is_ignored_interface(nhp->rtnh_ifindex))
		return true;

	if (ntb_gateway) {
		next->gateway = *(struct in6_addr *)mnl_attr_get_payload(
			ntb_gateway);
		next->flags = RTF_GATEWAY;
	} else {
		next->gateway = anyaddr;
		next->flags = 0;
	}

	if (ntb_encap) {
		len = mnl_attr_get_payload_len(ntb_encap);
		labels_ptr = mnl_attr_get_payload(ntb_encap);
		err = rta_encap_get_labels(labels_ptr, len,
					   ARRAY_SIZE(labels),
					   labels, &num_labels);
		if (err) {
			RTE_LOG(NOTICE, MPLS,
				"malformed label stack in netlink message\n");
			return false;
		}
		nh_outlabels_set(&next->outlabels, num_labels, labels);
	}

	ifp = dp_nh6_get_ifp(next);
	if ((!ifp || ifp->if_type == IFT_LOOP) &&
	    num_labels == 0)
		/* no dp interface or via loopback */
		next->flags |= RTF_SLOWPATH;

	if (num_labels > 0 && !is_lo(ifp))
		/* Output label rather than local label */
		next->flags |= RTF_OUTLABEL;

	return false;
}

/* Create nexthop struct */
struct next_hop_v6 *ecmp6_create(struct nlattr *mpath, uint32_t *count,
				 bool *missing_ifp)
{
	size_t size = 0, i;
	struct next_hop_v6 *next, *n;
	void *vnhp;

	/*
	 * Need to loop over the paths to find out how many there are
	 * as the size is not fixed because the gateway is optional.
	 */
	mnl_attr_for_each_nested(vnhp, mpath) {
		size++;
	}

	if (size == 0)
		return NULL;

	n = next = calloc(sizeof(struct next_hop_v6), size);
	if (!next)
		return NULL;

	mnl_attr_for_each_nested(vnhp, mpath) {
		struct rtnexthop *nhp = vnhp;

		if (nhp->rtnh_len == sizeof(*nhp)) {
			/* There is a NH with no extra attrs */
			if (nexthop6_fill(NULL, NULL, nhp, n))
				goto missing;
			n++;

		} else if (nhp->rtnh_len > sizeof(*nhp)) {
			struct nlattr *ntb[RTA_MAX+1] = { NULL };
			struct nlattr *mpls_ntb[MPLS_IPTUNNEL_MAX+1] = { NULL };

			int res = mnl_attr_parse_payload(RTNH_DATA(vnhp),
						 nhp->rtnh_len - sizeof(*nhp),
						 route_attr, ntb);

			if (res != MNL_CB_OK)
				goto failed;

			if (ntb[RTA_ENCAP] && ntb[RTA_ENCAP_TYPE] &&
			    (mnl_attr_get_u16(ntb[RTA_ENCAP_TYPE]) ==
			     LWTUNNEL_ENCAP_MPLS)) {
				res = mnl_attr_parse_nested(ntb[RTA_ENCAP],
							    mpls_attr,
							    mpls_ntb);
				if (res != MNL_CB_OK) {
					RTE_LOG(NOTICE, DATAPLANE,
						"unparseable mpls attributes\n");
					goto failed;
				}
			}

			res = mnl_attr_parse_payload(
				RTNH_DATA(vnhp), nhp->rtnh_len - sizeof(*nhp),
				route_attr, ntb);

			if (res != MNL_CB_OK)
				goto failed;

			if (ntb[RTA_VIA]) {
				if (nexthop6_fill_mpls(ntb[RTA_VIA],
						       ntb[RTA_NEWDST],
						       ntb[RTA_MPLS_PAYLOAD],
						       nhp, n)) {
					goto missing;
				}
			} else {
				if (nexthop6_fill(ntb[RTA_GATEWAY],
						  mpls_ntb[MPLS_IPTUNNEL_DST],
						  nhp, n)) {
					goto missing;
				}
			}
			n++;
		}
	}

	*count = n - next;

	return next;

missing:
	*missing_ifp = true;
failed:
	size = n - next;
	for (i = 0; i < size; i++)
		nh_outlabels_destroy(&next[i].outlabels);
	free(next);
	return NULL;
}

/* Create nexthop struct */
union next_hop_v4_or_v6_ptr ecmp_mpls_create(struct nlattr *mpath,
					     uint32_t *count,
					     enum nh_type *nh_type,
					     bool *missing_ifp)
{
	union next_hop_v4_or_v6_ptr nh = { NULL };
	size_t size = 0;
	void *vnhp;
	struct nlattr *attr;

	/*
	 * Need to loop over the paths to find out how many there are
	 * and what type of nexthop we need.
	 */
	*nh_type = NH_TYPE_V4GW;
	mnl_attr_for_each_nested(vnhp, mpath) {
		struct rtnexthop *nhp = vnhp;

		mnl_attr_for_each_payload((void *)RTNH_DATA(nhp),
					  nhp->rtnh_len - sizeof(*nhp)) {
			/*
			 * If at least one of the vias is an IPv6
			 * address, then all nexthops are represented
			 * as IPv6.
			 */
			if (attr->nla_type == RTA_VIA) {
				const struct rtvia *via = RTA_DATA(attr);

				if (via->rtvia_family == AF_INET6)
					*nh_type = NH_TYPE_V6GW;
				break;
			}
		}
		size++;
	}

	switch (*nh_type) {
	case NH_TYPE_V4GW:
		nh.v4 = ecmp_create(mpath, count, missing_ifp);
		break;
	case NH_TYPE_V6GW:
		nh.v6 = ecmp6_create(mpath, count, missing_ifp);
		break;
	}
	return nh;
}

/*
 * All of the common L4 transport protocols (TCP/UDP/SCTP/UDP-Lite/DCCP)
 * have their port numbers at the same offset.  Also ESP has a 32 bit
 * SPI field there which can serve the same purpose.
 */
static uint32_t l4_key(const struct rte_mbuf *m, unsigned int l4offs,
		       uint8_t proto)
{
	const void *l4hdr = rte_pktmbuf_mtod(m, const char *) + l4offs;

	if (unlikely(rte_pktmbuf_data_len(m) < l4offs + sizeof(uint32_t)))
		return 0;

	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ESP:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
	case IPPROTO_UDPLITE:
		return *(const uint32_t *)l4hdr;

	default:
		return 0;
	}
}

uint32_t ecmp_iphdr_hash(const struct iphdr *ip, uint32_t l4key)
{
	return rte_jhash_3words(ip->saddr, ip->daddr, l4key, ip->protocol);
}

uint32_t ecmp_ipv4_hash(const struct rte_mbuf *m, unsigned int l3offs)
{
	const struct iphdr *ip = (const struct iphdr *)
		(rte_pktmbuf_mtod(m, const char *) + l3offs);
	unsigned int l4offs = l3offs + (ip->ihl << 2);
	uint32_t l4key = ip_is_fragment(ip) ? ip->id : l4_key(m, l4offs,
							      ip->protocol);
	return ecmp_iphdr_hash(ip, l4key);
}

uint32_t ecmp_ip6hdr_hash(const struct ip6_hdr *ip6, uint32_t l4_key)
{
	uint32_t hkey[9];

	memcpy(hkey,     &ip6->ip6_src, sizeof(struct in6_addr));
	memcpy(hkey + 4, &ip6->ip6_dst, sizeof(struct in6_addr));

	/* RFC 6437 - Flow label spec. If set do not look further.  */
	hkey[8] = l4_key;

	return rte_jhash_32b(hkey, 9, ip6->ip6_nxt);
}

uint32_t ecmp_ipv6_hash(const struct rte_mbuf *m, unsigned int l3offs)
{
	const struct ip6_hdr *ip6 = (const struct ip6_hdr *)
		(rte_pktmbuf_mtod(m, const char *) + l3offs);
	unsigned int l4offs = l3offs + sizeof(*ip6);
	uint32_t flow = ip6->ip6_flow & IPV6_FLOWLABEL_MASK;

	return ecmp_ip6hdr_hash(ip6, flow ? : l4_key(m, l4offs, ip6->ip6_nxt));
}

/*
 * Weighted random function
 * Based on original Highest Random Weight paper:
 *   Thaler, David; Chinya Ravishankar.
 *   "A Name-Based Mapping Scheme for Rendezvous".
 *   University of Michigan Technical Report CSE-TR-316-96
 */
static uint32_t wrand2(uint32_t key, uint32_t i)
{
	const uint32_t a = 1103515245;
	const uint32_t b = 12345;
	const uint32_t m = (1u << 31) - 1;

	return (a * ((a * (key & m) + b) ^ i) + b) & m;
}

static unsigned int ecmp_hrw(uint32_t key, uint32_t size)
{
	unsigned int nxt, selected = 0;
	uint32_t hweight = wrand2(key, 0);

	for (nxt = 1; nxt < size; nxt++) {
		uint32_t weight = wrand2(key, nxt);
		if (weight > hweight) {
			hweight = weight;
			selected = nxt;
		}
	}

	return selected;
}

/*
 * Calculate flow key based protocols fields
 */
ALWAYS_INLINE uint32_t
ecmp_mbuf_hash(const struct rte_mbuf *m, uint16_t ether_type)
{
	if (!m)
		return 0;

	if (ether_type == ETH_P_MPLS_UC)
		return mpls_ecmp_hash(m);
	else if (ether_type == ETHER_TYPE_IPv6)
		return ecmp_ipv6_hash(m, dp_pktmbuf_l2_len(m));
	else
		return ecmp_ipv4_hash(m, dp_pktmbuf_l2_len(m));
}

static unsigned int
ecmp_lookup_alg(enum ecmp_modes ecmp_alg, uint32_t size, uint32_t key)
{
	switch (ecmp_alg) {
	case ECMP_HASH_THRESHOLD:
		return key / (UINT32_MAX / size);

	case ECMP_HRW:
		return ecmp_hrw(key, size);

	case ECMP_MODULO_N:
		return key % size;

	default:
		return 0;
	}
}

/*
 * ECMP nexthop lookup based on configured algorithm
 */
unsigned int ecmp_lookup(uint32_t size, uint32_t key)
{
	return ecmp_lookup_alg(ecmp_mode, size, key);
}

static void ecmp_show(json_writer_t *json)
{
	jsonw_string_field(json, "mode", ecmp_modes[ecmp_mode]);
	jsonw_uint_field(json, "max-path", ecmp_max_path);
}

static int ecmp_set_mode(const char *mode)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(ecmp_modes); i++) {
		const char *name = ecmp_modes[i];

		if (name && strcmp(mode, name) == 0) {
			ecmp_mode = i;
			return 0;
		}
	}

	return -1;
}

static int ecmp_set_max_path(int val)
{
	ecmp_max_path = val;

	return 0;
}

#define ECMP_MODES \
	"hash-threshold|hrw|modulo-n|disable"

#define CMD_ECMP_USAGE                     \
	"Usage: ecmp show\n"               \
"       ecmp max-path <2-65535>\n" \
"       ecmp mode <"ECMP_MODES">\n"

/*
 * Commands:
 *      ecmp show - show ecmp options
 *      ecmp mode - set ecmp mode
 *      ecmp max-path - set ecmp max-path option
 */
int cmd_ecmp(FILE *f, int argc, char **argv)
{
	json_writer_t *json;

	if (argc == 3 && !strcmp(argv[1], "mode")) {
		if (strstr(ECMP_MODES, argv[2]))
			return ecmp_set_mode(argv[2]);
	} else if (argc == 3 && !strcmp(argv[1], "max-path")) {
		unsigned int val = strtoul(argv[2], NULL, 0);

		if (val == 0 || (val >= 2 && val <= 65535))
			return ecmp_set_max_path(val);

	} else if (argc == 2 && !strcmp(argv[1], "show")) {
		json = jsonw_new(f);
		jsonw_name(json, "ecmp_show");
		jsonw_start_object(json);
		ecmp_show(json);
		jsonw_end_object(json);
		jsonw_destroy(&json);
		return 0;
	}

	fprintf(f, CMD_ECMP_USAGE);
	return -1;
}

uint32_t dp_ecmp_hash(const struct ecmp_hash_param *hash_param)
{
	struct iphdr iph;
	struct ip6_hdr ip6h;
	uint32_t hash = 0;
	uint32_t l4key = htonl((hash_param->src_port << 16) |
				hash_param->dst_port);

	if (hash_param->src_ip.type == hash_param->dst_ip.type) {
		if (hash_param->src_ip.type == AF_INET) {
			iph.saddr = hash_param->src_ip.address.ip_v4.s_addr;
			iph.daddr = hash_param->dst_ip.address.ip_v4.s_addr;
			iph.protocol = hash_param->protocol;
			hash = ecmp_iphdr_hash(&iph, l4key);
		} else if (hash_param->src_ip.type == AF_INET6) {
			ip6h.ip6_src = hash_param->src_ip.address.ip_v6;
			ip6h.ip6_dst = hash_param->dst_ip.address.ip_v6;
			ip6h.ip6_nxt = hash_param->protocol;
			hash = ecmp_ip6hdr_hash(&ip6h, l4key);
		}
	}
	return hash;
}
