/*
 * Handle IPv4 rtnetlink events
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/if_addr.h>
#include <linux/lwtunnel.h>
#include <linux/mroute6.h>
#include <linux/mpls_iptunnel.h>
#include <linux/neighbour.h>
#include <linux/netconf.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_log.h>

#include "address.h"
#include "control.h"
#include "ecmp.h"
#include "dp_event.h"
#include "if/gre.h"
#include "if_ether.h"
#include "if_var.h"
#include "ip_addr.h"
#include "ip_funcs.h"
#include "ip_mcast.h"
#include "master.h"
#include "mpls/mpls.h"
#include "netinet/ip_mroute.h"
#include "netinet6/ip6_funcs.h"
#include "netinet6/route_v6.h"
#include "netlink.h"
#include "npf/npf_event.h"
#include "pipeline/nodes/pl_nodes_common.h"
#include "pl_node.h"
#include "route.h"
#include "route_flags.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"
#include "vrf_if.h"

static const char anyaddr[16];

/* Callback to process neighbor messages */
static int inet_neigh_change(const struct nlmsghdr *nlh,
			     const struct ndmsg *ndm,
			     struct nlattr *tb[],
			     enum cont_src_en cont_src)
{
	struct ifnet *ifp;
	const void *lladdr = NULL;
	struct ether_addr ea;
	const void *dst = anyaddr;
	size_t llen = 0;

	/* ignore neighbor updates for non DPDK interfaces */
	ifp = dp_ifnet_byifindex(cont_src_ifindex(cont_src, ndm->ndm_ifindex));
	if (!ifp)
		return MNL_CB_OK;

	if (tb[NDA_LLADDR])
		llen =  mnl_attr_get_payload_len(tb[NDA_LLADDR]);

	if (is_gre(ifp) && llen <= IP_ADDR_LEN)
		/* Only interested in NHRP notification */
		return mgre_ipv4_neigh_change(ifp, nlh, ndm, tb);

	if (tb[NDA_DST])
		dst = mnl_attr_get_payload(tb[NDA_DST]);

	if (llen) {
		if (llen > ETHER_ADDR_LEN) {
			/* We do not support neighbours with IPv6 as the NH.*/
			RTE_LOG(DEBUG, ROUTE,
				"neighbor message with addrlen = %zd not processed\n",
				llen);
			return MNL_CB_OK;
		}

		lladdr = mnl_attr_get_payload(tb[NDA_LLADDR]);
		if (llen < ETHER_ADDR_LEN && lladdr != NULL) {
			memset(&ea, 0, ETHER_ADDR_LEN);
			/* Don't use ether_addr_copy here */
			lladdr = memcpy(&ea, lladdr, llen);
			RTE_LOG(DEBUG, ROUTE,
				"neighbor message with addrlen = %zd %s\n",
				llen, ether_ntoa(&ea));
		}
	}

	lladdr_nl_event(ndm->ndm_family, ifp, nlh->nlmsg_type, ndm,
			dst, lladdr);
	return MNL_CB_OK;
}

static int handle_route(vrfid_t vrf_id, uint16_t type, const struct rtmsg *rtm,
			uint32_t table, const void *dest,
			const void *nexthop, uint32_t ifindex, uint8_t scope,
			struct nlattr *mpath, uint32_t nlmsg_flags,
			uint16_t num_labels, label_t *labels)
{
	uint8_t depth;
	uint32_t dst;
	uint8_t proto;
	bool missing_ifp = false;

	if (rtm->rtm_type != RTN_UNICAST  &&
	    rtm->rtm_type != RTN_LOCAL &&
	    rtm->rtm_type != RTN_BLACKHOLE &&
	    rtm->rtm_type != RTN_UNREACHABLE)
		return 0;

	if (rtm->rtm_family != AF_INET)
		return 0;

	dst = *(const uint32_t *)dest;
	depth = rtm->rtm_dst_len;
	proto = rtm->rtm_protocol;

	/* prevent loopback prefix getting installed from local table */
	if (IN_LOOPBACK(ntohl(dst)))
		return 0;

	/* May resize route tables and that code calls defer_rcu
	 * which is not safe inside RCU read lock
	 */
	rcu_read_unlock();

	if (type == RTM_NEWROUTE) {
		struct ifnet *ifp = dp_ifnet_byifindex(ifindex);
		uint32_t gw = 0;
		uint32_t flags = 0;
		struct next_hop *next;
		uint32_t size;
		bool exp_ifp = true;

		if (rtm->rtm_type == RTN_BLACKHOLE) {
			flags |= RTF_BLACKHOLE;
			exp_ifp = false;
		} else if (rtm->rtm_type == RTN_UNREACHABLE) {
			flags |= RTF_REJECT;
			exp_ifp = false;
		} else if (rtm->rtm_type == RTN_LOCAL) {
			flags |= RTF_LOCAL;
			/* no need to store ifp for local routes */
			ifp = NULL;
			exp_ifp = false;
		} else if ((!ifp || is_lo(ifp))
			   && num_labels == 0) {
			/* no dp interface or via loopback */
			flags |= RTF_SLOWPATH;
		}

		if (num_labels > 0 && !is_lo(ifp))
			/* Output label rather than local label */
			flags |= RTF_OUTLABEL;

		if (nexthop != anyaddr) {
			flags |= RTF_GATEWAY;
			gw = *(const uint32_t *) nexthop;
		}

		if (mpath) {
			assert(num_labels == 0);
			next = ecmp_create(mpath, &size, &missing_ifp);
			if (missing_ifp) {
				rcu_read_lock();
				return -1;
			}
		} else {
			if (exp_ifp && !ifp && !is_ignored_interface(ifindex)) {
				rcu_read_lock();
				return -1;
			}
			size = 1;
			next = nexthop_create(ifp, gw, flags,
					      num_labels, labels);
		}

		if (unlikely(!next)) {
			rcu_read_lock();
			return 0;	/* no memory */
		}

		rt_insert(vrf_id, dst, depth, table, scope, proto, next, size,
			  !!(nlmsg_flags & NLM_F_REPLACE));

		free(next);
	} else if (type == RTM_DELROUTE) {
		rt_delete(vrf_id, dst, depth, table, scope);
	}
	rcu_read_lock();
	return 0;
}

#ifdef DP_DEBUG
static const char *mroute_ntop(int af, const void *src, char *dst,
			       socklen_t size)
{
	switch (af) {
	case RTNL_FAMILY_IPMR:
		return inet_ntop(AF_INET, src, dst, size);

	case RTNL_FAMILY_IP6MR:
		return inet_ntop(AF_INET6, src, dst, size);

	default:
		break;
	}
	return NULL;
}
#endif

static int inet_mroute_ifset(struct nlattr *tb[], struct vmfcctl *mfcc)
{
	void *vnhp;
	struct rtnexthop *nhp;
	struct vif *vifp;
	int err = 0;
	uint32_t if_count = 0;

	mnl_attr_for_each_nested(vnhp, tb[RTA_MULTIPATH]) {
		nhp = (struct rtnexthop *) vnhp;
		if (nhp->rtnh_len != sizeof(*nhp)) {
			err = -EINVAL;
			continue;
		}
		if (nhp->rtnh_flags != 0) {
			err = -EINVAL;
			continue;
		}

		vifp = get_vif_by_ifindex(nhp->rtnh_ifindex);
		if (!vifp) {
			char b1[INET6_ADDRSTRLEN], b2[INET6_ADDRSTRLEN];
			RTE_LOG(NOTICE, MCAST,
				"Ignoring mroute ifset for (%s, %s); "
				"incoming interface: %s; no IPv4 VIF for "
				"outgoing interface: %s.\n",
				inet_ntop(AF_INET, &mfcc->mfcc_origin.s_addr,
					  b2, sizeof(b2)),
				inet_ntop(AF_INET, &mfcc->mfcc_mcastgrp.s_addr,
					  b1, sizeof(b1)),
				ifnet_indextoname(mfcc->mfcc_parent),
				ifnet_indextoname(nhp->rtnh_ifindex));
			/*
			 * There is no route to the nexthop for the
			 * interface. This can occur when the mroute
			 * update has arrived from the kernel after
			 * the dataplane has restarted and routing
			 * convergence is incomplete. Silently ignore
			 * to avoid a dataplane restart.
			 */
			continue;
		}
		vifp->v_threshold = nhp->rtnh_hops;
		IF_SET(vifp->v_vif_index, &mfcc->mfcc_ifset);
		if_count++;
	}
	mfcc->if_count = if_count;
	return err;
}

static int inet_mroute6_ifset(struct nlattr *tb[], struct vmf6cctl *mf6cc)
{
	void *vnhp;
	struct rtnexthop *nhp;
	struct mif6 *mifp;
	int err = 0;
	uint32_t if_count = 0;

	mnl_attr_for_each_nested(vnhp, tb[RTA_MULTIPATH]) {
		nhp = (struct rtnexthop *) vnhp;
		if (nhp->rtnh_len != sizeof(*nhp)) {
			err = -EINVAL;
			continue;
		}
		if (nhp->rtnh_flags != 0) {
			err = -EINVAL;
			continue;
		}
		mifp = get_mif_by_ifindex(nhp->rtnh_ifindex);
		if (!mifp) {
			char b1[INET6_ADDRSTRLEN], b2[INET6_ADDRSTRLEN];
			RTE_LOG(NOTICE, MCAST,
				"Ignoring mroute ifset for (%s, %s); "
				"incoming interface: %s; no IPv6 VIF for "
				"outgoing interface: %s.\n",
				inet_ntop(AF_INET6,
					  &mf6cc->mf6cc_origin.sin6_addr,
					  b2, sizeof(b2)),
				inet_ntop(AF_INET6,
					  &mf6cc->mf6cc_mcastgrp.sin6_addr,
					  b1, sizeof(b1)),
				ifnet_indextoname(mf6cc->mf6cc_parent),
				ifnet_indextoname(nhp->rtnh_ifindex));
			/*
			 * There is no route to the nexthop for the
			 * interface. This can occur when the mroute
			 * update has arrived from the kernel after
			 * the dataplane has restarted and routing
			 * convergence is incomplete. Silently ignore
			 * to avoid a dataplane restart.
			 */
			continue;
		}
		IF_SET(mifp->m6_mif_index, &mf6cc->mf6cc_ifset);
		if_count++;
	}
	mf6cc->if_count = if_count;
	return err;
}

static int inet_mroute_change(vrfid_t vrf_id, const struct nlmsghdr *nlh,
			      const struct rtmsg *rtm, struct nlattr *tb[])
{
	const void *grp = NULL, *origin = NULL;
	int ifindex = 0;
	char b1[INET6_ADDRSTRLEN], b2[INET6_ADDRSTRLEN];
	struct vmfcctl mfcc;
	struct vmf6cctl mf6cc;
	uint16_t attr_len;
	uint16_t addr_len = (rtm->rtm_family == RTNL_FAMILY_IPMR) ?
		sizeof(struct in_addr) : sizeof(struct in6_addr);

	if (tb[RTA_DST]) {
		attr_len = mnl_attr_get_payload_len(tb[RTA_DST]);
		if (attr_len == addr_len)
			grp = mnl_attr_get_payload(tb[RTA_DST]);
	}

	if (tb[RTA_SRC]) {
		attr_len = mnl_attr_get_payload_len(tb[RTA_SRC]);
		if (attr_len == addr_len)
			origin = mnl_attr_get_payload(tb[RTA_SRC]);
	}
	if (tb[RTA_IIF])
		ifindex = mnl_attr_get_u32(tb[RTA_IIF]);

	if (!grp || !origin) {
		RTE_LOG(NOTICE, ROUTE,
			"Malformed MFC %s message for interface %s\n",
			nlmsg_type(nlh->nlmsg_type),
			ifnet_indextoname(ifindex));
		return MNL_CB_ERROR;
	}

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Processing %s for (%s, %s); "
		 "incoming interface: %s.\n",
		 nlmsg_type(nlh->nlmsg_type),
		 mroute_ntop(rtm->rtm_family, origin, b2, sizeof(b2)),
		 mroute_ntop(rtm->rtm_family, grp, b1, sizeof(b1)),
		 ifnet_indextoname(ifindex));

	switch (rtm->rtm_family) {
	case RTNL_FAMILY_IPMR:
		memset(&mfcc, 0, sizeof(struct vmfcctl));
		mfcc.mfcc_origin.s_addr = *((const in_addr_t *) origin);
		mfcc.mfcc_mcastgrp.s_addr = *((const in_addr_t *) grp);
		mfcc.mfcc_parent = ifindex;
		if (tb[RTA_MULTIPATH] &&
		    inet_mroute_ifset(tb, &mfcc))
			return -1;

		switch (nlh->nlmsg_type) {
		case RTM_NEWROUTE:
			add_mfc(vrf_id, &mfcc);
			break;
		case RTM_DELROUTE:
			del_mfc(vrf_id, &mfcc);
			break;
		default:
			break;
		}
		break;

	case RTNL_FAMILY_IP6MR:
		memset(&mf6cc, 0, sizeof(struct vmf6cctl));
		mf6cc.mf6cc_origin.sin6_addr
			= *((const struct in6_addr *) origin);
		mf6cc.mf6cc_mcastgrp.sin6_addr
			= *((const struct in6_addr *) grp);
		mf6cc.mf6cc_parent = ifindex;
		if (tb[RTA_MULTIPATH] &&
		    inet_mroute6_ifset(tb, &mf6cc))
			return -1;

		switch (nlh->nlmsg_type) {
		case RTM_NEWROUTE:
			add_m6fc(vrf_id, &mf6cc);
			break;
		case RTM_DELROUTE:
			del_m6fc(vrf_id, &mf6cc);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return MNL_CB_OK;
}

/* 8 labels - each up to 6 digits plus space plus 'labels: '*/
#define LABEL_STRLEN (7*8 + 8)
static char *mpls_labels_to_str(label_t *labels, uint16_t num_labels,
				char *buf, size_t bufsz)
{
	unsigned int written, i;

	if (!bufsz)
		return buf;

	written = 0;
	if (num_labels > 0) {
		written += snprintf(buf + written, bufsz - written,
				    "labels: ");

		for (i = 0; i < num_labels; i++) {
			written += snprintf(buf + written, bufsz - written,
					    " %u", labels[i]);
		}
		buf[bufsz-1] = '\0';
	} else
		buf[0] = '\0';

	return buf;
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

static int inet_route_change(const struct nlmsghdr *nlh,
			     const struct rtmsg *rtm,
			     struct nlattr *tb[],
			     enum cont_src_en cont_src)
{
	unsigned int ifindex = 0;
	const void *dest, *nexthop;
	char b1[INET6_ADDRSTRLEN], b2[INET6_ADDRSTRLEN], b3[LABEL_STRLEN];
	uint32_t nl_flags = 0;
	label_t labels[NH_MAX_OUT_LABELS];
	uint16_t num_labels = 0;
	vrfid_t vrf_id = VRF_DEFAULT_ID;
	uint32_t kernel_table;
	uint32_t table;

	if (tb[RTA_TABLE])
		kernel_table = mnl_attr_get_u32(tb[RTA_TABLE]);
	else
		kernel_table = rtm->rtm_table;

	table = kernel_table;

	if (rtm->rtm_type == RTN_MULTICAST) {
		/*
		 * Multicast routes do not come down out of order
		 * w.r.t. netlink link updates, since they don't use
		 * the route broker and the controller ensures that
		 * during replay the link updates are played out
		 * first. So they don't need incomplete route handling
		 * when either the VRF or the interfaces contained in
		 * the route update don't exist - instead these are
		 * logged and treated as an error.
		 */
		if (vrf_is_vrf_table_id(kernel_table) &&
		    vrf_lookup_by_tableid(kernel_table, &vrf_id,
					  &table) < 0) {
			RTE_LOG(NOTICE, ROUTE,
				"unknown VRF table %d\n", kernel_table);
			return MNL_CB_ERROR;
		}

		if (!netlink_uplink_vrf(cont_src, &vrf_id))
			return MNL_CB_ERROR;

		return inet_mroute_change(vrf_id, nlh, rtm, tb);
	}

	if (tb[RTA_DST])
		dest = mnl_attr_get_payload(tb[RTA_DST]);
	else
		dest = anyaddr;

	if (tb[RTA_GATEWAY])
		nexthop = mnl_attr_get_payload(tb[RTA_GATEWAY]);
	else {
		nexthop = anyaddr;
		nl_flags |= NL_FLAG_ANY_ADDR;
	}

	if (tb[RTA_OIF])
		ifindex = cont_src_ifindex(cont_src,
					   mnl_attr_get_u32(tb[RTA_OIF]));

	if (tb[RTA_ENCAP] && tb[RTA_ENCAP_TYPE] &&
	    mnl_attr_get_u16(tb[RTA_ENCAP_TYPE]) == LWTUNNEL_ENCAP_MPLS) {
		const struct nlattr *mpls_tb[MPLS_IPTUNNEL_MAX+1];
		int ret;

		ret = mnl_attr_parse_nested(tb[RTA_ENCAP], mpls_attr, mpls_tb);
		if (ret != MNL_CB_OK) {
			RTE_LOG(NOTICE, MPLS,
				"unparseable mpls netlink attributes\n");
			return ret;
		}

		if (mpls_tb[MPLS_IPTUNNEL_DST]) {
			void *labels_ptr;
			uint32_t len;

			len = mnl_attr_get_payload_len(
				mpls_tb[MPLS_IPTUNNEL_DST]);
			labels_ptr = mnl_attr_get_payload(
				mpls_tb[MPLS_IPTUNNEL_DST]);
			ret = rta_encap_get_labels(labels_ptr, len,
						   ARRAY_SIZE(labels),
						   labels,
						   &num_labels);
			if (ret < 0) {
				RTE_LOG(NOTICE, MPLS,
					"malformed label stack in netlink message\n");
				return MNL_CB_ERROR;
			}
		}
	}

	DP_DEBUG_W_VRF(NETLINK_ROUTE, INFO, ROUTE, vrf_id,
		       "%s table %u type %s dst %s/%u gw %s dev %u scope %u proto %u %s\n",
		       nlmsg_type(nlh->nlmsg_type), table,
		       rtm->rtm_type == RTN_UNICAST ? "unicast" : "multicast",
		       inet_ntop(rtm->rtm_family, dest, b1, sizeof(b1)),
		       rtm->rtm_dst_len,
		       inet_ntop(rtm->rtm_family, nexthop, b2, sizeof(b2)),
		       ifindex, rtm->rtm_scope, rtm->rtm_protocol,
		       mpls_labels_to_str(labels, num_labels, b3, sizeof(b3)));

	/*
	 * Delete any existing entry for this prefix in the incomplete cache.
	 * If still incomplete it will get re-added with correct details
	 */
	incomplete_route_del(dest, rtm->rtm_family,
			     rtm->rtm_dst_len, kernel_table,
			     rtm->rtm_scope, rtm->rtm_protocol);

	if (vrf_is_vrf_table_id(kernel_table) &&
	    vrf_lookup_by_tableid(kernel_table, &vrf_id, &table) < 0) {
		/*
		 * Route came down before the vrfmaster device
		 * RTM_NEWLINK - defer route installation until it
		 * arrives.
		 */
		incomplete_route_add(dest,
				     rtm->rtm_family,
				     rtm->rtm_dst_len,
				     kernel_table,
				     rtm->rtm_scope,
				     rtm->rtm_protocol,
				     nlh);
		return MNL_CB_OK;
	}

	if (!netlink_uplink_vrf(cont_src, &vrf_id))
		return MNL_CB_ERROR;

	switch (rtm->rtm_family) {
	case AF_INET:
		if (handle_route(vrf_id, nlh->nlmsg_type, rtm, table,
				 dest, nexthop, ifindex,
				 rtm->rtm_scope, tb[RTA_MULTIPATH],
				 nlh->nlmsg_flags, num_labels, labels) < 0) {
			incomplete_route_add(dest,
					     rtm->rtm_family,
					     rtm->rtm_dst_len,
					     kernel_table,
					     rtm->rtm_scope,
					     rtm->rtm_protocol,
					     nlh);
		}
		break;

	case AF_INET6:
		if (handle_route6(vrf_id, nlh->nlmsg_type, rtm, table,
				  dest, nexthop, ifindex,
				  rtm->rtm_scope, tb[RTA_MULTIPATH],
				  nlh->nlmsg_flags | nl_flags,
				  num_labels, labels) < 0) {
			incomplete_route_add(dest,
					     rtm->rtm_family,
					     rtm->rtm_dst_len,
					     kernel_table,
					     rtm->rtm_scope,
					     rtm->rtm_protocol,
					     nlh);
		}
		break;

	default:
		break;
	}
	return MNL_CB_OK;
}

static int inet_addr_change(const struct nlmsghdr *nlh,
			    const struct ifaddrmsg *ifa,
			    struct nlattr *tb[],
			    enum cont_src_en cont_src)
{
	const void *addr, *broadcast = NULL;
	int ifindex = cont_src_ifindex(cont_src, ifa->ifa_index);
	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);

	switch (nlh->nlmsg_type) {
	case RTM_NEWADDR:
		if (tb[IFA_LOCAL]) {
			addr = mnl_attr_get_payload(tb[IFA_LOCAL]);
		} else if (tb[IFA_ADDRESS]) {
			addr = mnl_attr_get_payload(tb[IFA_ADDRESS]);
		} else {
			RTE_LOG(ERR, ROUTE, "missing address in RTM_NEWADDR\n");
			break;
		}

		if (tb[IFA_BROADCAST])
			broadcast  = mnl_attr_get_payload(tb[IFA_BROADCAST]);
		else
			broadcast = NULL;

		if (ifp) {
			ifa_add(ifindex, ifa->ifa_family, ifa->ifa_scope,
				addr, ifa->ifa_prefixlen, broadcast);
		} else {
			if (!is_ignored_interface(ifindex))
				missed_nl_inet_addr_add(ifindex,
							ifa->ifa_family,
							addr, nlh);
		}

		dp_event(DP_EVT_IF_ADDR_ADD, cont_src, ifp, ifindex,
				ifa->ifa_family, addr);

		break;

	case RTM_DELADDR:
		if (tb[IFA_LOCAL]) {
			addr = mnl_attr_get_payload(tb[IFA_LOCAL]);
		} else if (tb[IFA_ADDRESS]) {
			addr = mnl_attr_get_payload(tb[IFA_ADDRESS]);
		} else {
			RTE_LOG(ERR, ROUTE, "missing address in RTM_DELADDR\n");
			break;
		}

		if (ifp) {
			ifa_remove(ifindex,
				   ifa->ifa_family, addr, ifa->ifa_prefixlen);
		} else {
			if (!is_ignored_interface(ifindex))
				missed_nl_inet_addr_del(ifindex,
							ifa->ifa_family,
							addr);
		}

		dp_event(DP_EVT_IF_ADDR_DEL, cont_src, ifp, ifindex,
				ifa->ifa_family, addr);
		break;
	}

	return MNL_CB_OK;
}

static void inet_netconf_change_mroute(int ifindex, struct nlattr *tb[],
				       uint8_t af)
{
	uint32_t mc_forwarding = mnl_attr_get_u32(tb[NETCONFA_MC_FORWARDING]);

	DP_DEBUG(MULTICAST, INFO, MCAST,
		 "Processing RTM_NEWNETCONF for %s; %s NETCONFA_MC_FORWARDING %s.\n",
		 ifnet_indextoname(ifindex),
		 (af == AF_INET) ? "IPv4" : "IPv6",
		 mc_forwarding ? "set" : "clear");

	if (!mc_forwarding) {
		if (af == AF_INET)
			del_vif(ifindex);
		else
			del_m6if(ifindex);
		return;
	}

	if (af == AF_INET)
		add_vif(ifindex);
	else
		add_m6if(ifindex);
}

/* Attribute changed */
static void ipv4_netconf_change(struct ifnet *ifp, struct nlattr *tb[])
{
	uint32_t rp_filter = 0;
	bool forwarding = false;

	if (tb[NETCONFA_FORWARDING]) {
		forwarding = mnl_attr_get_u32(tb[NETCONFA_FORWARDING]);
		if (forwarding)
			pl_node_remove_feature_by_inst(
				&ipv4_in_no_forwarding_feat, ifp);
		else
			pl_node_add_feature_by_inst(
				&ipv4_in_no_forwarding_feat, ifp);

		fal_if_update_forwarding(ifp, AF_INET, false);
	}


	if (tb[NETCONFA_RP_FILTER]) {
		rp_filter = mnl_attr_get_u32(tb[NETCONFA_RP_FILTER]);

		switch (rp_filter) {
		case 1:
		case 2:
			pl_node_add_feature_by_inst(&ipv4_rpf_feat, ifp);
			ifp->ip_rpf_strict = rp_filter == 1;
			break;
		default:
			pl_node_remove_feature_by_inst(&ipv4_rpf_feat, ifp);
			break;
		}
	}

	if (tb[NETCONFA_MC_FORWARDING]) {
		ifp->ip_mc_forwarding = mnl_attr_get_u32(tb[NETCONFA_MC_FORWARDING]);
		fal_if_update_forwarding(ifp, AF_INET, true);
	}

	if (tb[NETCONFA_PROXY_NEIGH])
		ifp->ip_proxy_arp = mnl_attr_get_u32(tb[NETCONFA_PROXY_NEIGH]);

	DP_DEBUG(NETLINK_NETCONF, DEBUG, DATAPLANE,
		 "%s ip forwarding %d mc_forwarding %d proxy_arp %d rpf %d\n",
		 ifp->if_name,
		 forwarding, ifp->ip_mc_forwarding,
		 ifp->ip_proxy_arp, rp_filter);
}

/* Callback to process netconf messages */
static int inet_netconf_change(const struct nlmsghdr *nlh,
			       const struct netconfmsg *ncm,
			       struct nlattr *tb[],
			       enum cont_src_en cont_src)
{
	struct ifnet *ifp;
	int signed_ifindex;

	if (!tb[NETCONFA_IFINDEX])
		return MNL_CB_OK;

	signed_ifindex = mnl_attr_get_u32(tb[NETCONFA_IFINDEX]);
	if (signed_ifindex < 0)
		return MNL_CB_OK;	/* NETCONFA_IFINDEX_ALL */

	unsigned int ifindex = cont_src_ifindex(cont_src, signed_ifindex);
	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp && !is_ignored_interface(ifindex)) {
		if (nlh->nlmsg_type == RTM_NEWNETCONF)
			missed_nl_inet_netconf_add(ifindex,
						   ncm->ncm_family,
						   nlh);
		else
			missed_nl_inet_netconf_del(ifindex,
						   ncm->ncm_family);
	}

	/*
	 * Only given just before a delete, so we'll just let the
	 * interface depart this mortal coil without any extra handling.
	 */
	if (nlh->nlmsg_type == RTM_DELNETCONF)
		return MNL_CB_OK;

	switch (ncm->ncm_family) {
	case AF_INET:
		if (tb[NETCONFA_MC_FORWARDING])
			inet_netconf_change_mroute(ifindex, tb, AF_INET);
		if (!ifp)  /* not local to DP */
			return MNL_CB_OK;
		ipv4_netconf_change(ifp, tb);
		break;

	case AF_INET6:
		if (tb[NETCONFA_MC_FORWARDING])
			inet_netconf_change_mroute(ifindex, tb, AF_INET6);
		if (!ifp)
			return MNL_CB_OK;
		ipv6_netconf_change(ifp, tb);
		break;
	default:
		break;
	}
	return MNL_CB_OK;
}

static const struct netlink_handler inet_netlink = {
	.neigh = inet_neigh_change,
	.addr  = inet_addr_change,
	.route = inet_route_change,
	.netconf = inet_netconf_change,
};

void inet_netlink_init(void)
{
	register_netlink_handler(AF_INET, &inet_netlink);
	register_netlink_handler(AF_INET6, &inet_netlink);
	register_netlink_handler(RTNL_FAMILY_IPMR, &inet_netlink);
	register_netlink_handler(RTNL_FAMILY_IP6MR, &inet_netlink);
}
