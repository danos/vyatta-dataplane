/*
 * Handle MPLS Netlink events
 *
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <arpa/inet.h>
#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <urcu/uatomic.h>
#include <linux/netconf.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_log.h>

#include "compat.h"
#include "control.h"
#include "ecmp.h"
#include "if_var.h"
#include "mpls/mpls.h"
#include "mpls_label_table.h"
#include "netlink.h"
#include "nh.h"
#include "route.h"
#include "route_flags.h"
#include "route_v6.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_internal.h"

#ifndef MIN
# define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

bool
nh_outlabels_set(union next_hop_outlabels *olbls,
		 uint16_t num_labels, label_t *labels)
{
	uint16_t lidx;
	label_t *label_blk = olbls->labels;

	if (num_labels > NH_MAX_OUT_LABELS) {
		olbls->labels[0] = 0;
		return false;
	}
	if (!num_labels) {
		olbls->labels[0] = 0;
		return true;
	}
	labels += num_labels;
	if (unlikely(num_labels > NH_MAX_OUT_ARRAY_LABELS)) {
		label_blk = malloc(sizeof(label_t) * num_labels);
		if (!label_blk) {
			olbls->labels[0] = 0;
			return false;
		}
		olbls->lbl_blk.lb_count = 0;
		olbls->lbl_blk.labels = label_blk;
	}
	for (lidx = 0; lidx < num_labels; lidx++) {
		/* store labels in push order */
		*label_blk++ = *--labels;
	}
	/* store number of labels in spare byte of first label */
	olbls->labels[0] |= (num_labels << 24);
	return true;
}

void
nh_outlabels_destroy(union next_hop_outlabels *olbls)
{
	if (nh_outlabels_get_cnt(olbls) > NH_MAX_OUT_ARRAY_LABELS) {
		free(olbls->lbl_blk.labels);
		olbls->lbl_blk.labels = NULL;
		olbls->lbl_blk.lb_count = 0;
	}
}

bool
nh_outlabels_copy(union next_hop_outlabels *old, union next_hop_outlabels *copy)
{
	unsigned int count = nh_outlabels_get_cnt(old);
	label_t *labels;

	if (count > NH_MAX_OUT_ARRAY_LABELS) {
		labels = malloc(sizeof(label_t) * count);
		if (!labels)
			return false;
		memcpy(labels, old->lbl_blk.labels, sizeof(label_t) * count);
		copy->lbl_blk.labels = labels;
	}
	return true;
}

/* extract out label array from an RTA_ENCAP */
int
rta_encap_get_labels(void *payload, uint16_t payload_len, uint16_t max_labels,
		     label_t *labels, uint16_t *num_labels)
{
	int bytes_read = 0;
	label_t *lbl_ptr;
	label_t *lbl_end_ptr;
	uint8_t bos;

	lbl_ptr = payload;
	lbl_end_ptr = lbl_ptr + max_labels;
	do {
		if (lbl_ptr >= lbl_end_ptr)
			return -ENOSPC;
		if (bytes_read + sizeof(label_t) > payload_len)
			return -EINVAL;

		bytes_read += sizeof(label_t);
		labels[*num_labels] = mpls_ls_get_label(*lbl_ptr);
		(*num_labels)++;
		bos = mpls_ls_get_bos(*lbl_ptr);
		lbl_ptr++;
	} while (!bos);

	if (bytes_read != payload_len)
		return -EINVAL;

	return 0;
}

char *mpls_labels_ntop(const uint32_t *label_stack, unsigned int num_labels,
		       char *buffer, size_t len)
{
	unsigned int i;
	int ret;

	if (!num_labels) {
		snprintf(buffer, len, "none");
		return buffer;
	}

	if (len)
		buffer[0] = '\0';

	for (i = 0; i < num_labels; i++) {
		uint32_t label_value = mpls_ls_get_label(label_stack[i]);
		ret = snprintfcat(buffer, len, "%s%u", i == 0 ? "" : "/",
				  label_value);
		if (ret < 0)
			break;
	}

	return buffer;
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
			RTE_LOG(NOTICE, DATAPLANE,
				"invalid mpls payload attribute %d\n", type);
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

static int mpls_route_change(const struct nlmsghdr *nlh,
			     const struct rtmsg *rtm,
			     struct nlattr *tb[],
			     enum cont_src_en cont_src)
{
	int ifindex = 0;
	const uint32_t *out_labels = NULL;
	uint32_t in_label;
	char b2[256];
	char b3[INET6_ADDRSTRLEN];
	int out_label_count = 0;
	const struct rtvia *via = NULL;
	union {
		in_addr_t v4;
		struct in6_addr v6;
	} nh = { INADDR_ANY };
	struct ip_addr ip_addr;
	struct next_hop *nhops;
	uint32_t size = 0;
	struct ifnet *oifp = NULL;
	uint32_t flags = 0;
	bool missing_ifp = false;

	if (cont_src != CONT_SRC_MAIN) {
		RTE_LOG(ERR, MPLS,
			"(%s) mpls route change invalid controller\n",
			cont_src_name(cont_src));
		return MNL_CB_ERROR;
	}

	if (tb[RTA_DST])
		in_label = mnl_attr_get_u32(tb[RTA_DST]);
	else {
		RTE_LOG(ERR, MPLS,
			"missing destination in route change message\n");
		return MNL_CB_ERROR;
	}

	in_label = mpls_ls_get_label(in_label);

	/*
	 * Delete any existing entry for this label in the incomplete cache.
	 * If still incomplete it will get re-added with correct details
	 */
	incomplete_route_del(&in_label,
			     rtm->rtm_family,
			     rtm->rtm_dst_len,
			     rtm->rtm_table,
			     rtm->rtm_scope,
			     rtm->rtm_protocol);

	if (nlh->nlmsg_type == RTM_NEWROUTE) {
		label_t hl_out_labels[MAX_LABEL_STACK_DEPTH];
		enum nh_type nh_type = NH_TYPE_V4GW;
		uint32_t payload_type = MPT_UNSPEC;
		bool bos_only = false;
		int i;

		if (tb[RTA_MPLS_PAYLOAD]) {
			const struct nlattr *pl_tb[RTMPA_NH_FLAGS+1] = { NULL };
			int ret;

			ret = mnl_attr_parse_nested(tb[RTA_MPLS_PAYLOAD],
						    mpls_payload_attr,
						    &pl_tb);
			if (ret != MNL_CB_OK)
				return -1;

			if (pl_tb[RTMPA_TYPE])
				payload_type =
					mnl_attr_get_u32(pl_tb[RTMPA_TYPE]);
			if (pl_tb[RTMPA_NH_FLAGS])
				bos_only =
					(mnl_attr_get_u32(
						pl_tb[RTMPA_NH_FLAGS]) &
					 RTMPNF_BOS_ONLY) != 0;
		}

		if (tb[RTA_MULTIPATH]) {
			nhops = ecmp_mpls_create(tb[RTA_MULTIPATH],
						 &size, &nh_type,
						 &missing_ifp);
			if (missing_ifp) {
				incomplete_route_add(&in_label,
						     rtm->rtm_family,
						     rtm->rtm_dst_len,
						     rtm->rtm_table,
						     rtm->rtm_scope,
						     rtm->rtm_protocol,
						     nlh);
				return MNL_CB_OK;
			}
		} else {
			size = 1;
			if (tb[RTA_NEWDST]) {
				out_labels =
				  mnl_attr_get_payload(tb[RTA_NEWDST]);
				out_label_count =
				  mnl_attr_get_payload_len(tb[RTA_NEWDST]) / 4;
			}

			if (tb[RTA_VIA]) {
				via = mnl_attr_get_payload(tb[RTA_VIA]);
				switch (via->rtvia_family) {
				case AF_INET:
					memcpy(&nh.v4, &via->rtvia_addr,
					       sizeof(nh.v4));
					flags |= RTF_GATEWAY;
					break;
				case AF_INET6:
					memcpy(&nh.v6, &via->rtvia_addr,
					       sizeof(nh.v6));
					flags |= RTF_GATEWAY;
					break;
				}
			}

			if (tb[RTA_OIF]) {
				ifindex = cont_src_ifindex(cont_src,
						mnl_attr_get_u32(tb[RTA_OIF]));
				oifp = dp_ifnet_byifindex(ifindex);
			}

			if (out_label_count > MAX_LABEL_STACK_DEPTH) {
				RTE_LOG(ERR, MPLS,
					"too many (%u) outlabels\n",
					out_label_count);
				return MNL_CB_ERROR;
			}

			for (i = 0; i < out_label_count; i++)
				hl_out_labels[i] = mpls_ls_get_label(
					out_labels[i]);

			/*
			 * If there are no labels and BOS_ONLY not
			 * set, then this implies the implicit-null
			 * label. This won't go out on the wire and is
			 * for signalling only.
			 */
			if (out_label_count == 0 && !bos_only) {
				out_label_count = 1;
				hl_out_labels[0] = MPLS_LABEL_IMPLNULL;
			}

			if (!oifp) {
				flags |= RTF_SLOWPATH;
				if (!is_ignored_interface(ifindex)) {
					incomplete_route_add(&in_label,
							     rtm->rtm_family,
							     rtm->rtm_dst_len,
							     rtm->rtm_table,
							     rtm->rtm_scope,
							     rtm->rtm_protocol,
							     nlh);
					return MNL_CB_OK;
				}
			}

			if (!via || via->rtvia_family == AF_INET) {
				ip_addr.type = AF_INET;
				ip_addr.address.ip_v4.s_addr = nh.v4;
				nhops = nexthop_create(oifp, &ip_addr,
						       flags,
						       out_label_count,
						       hl_out_labels);
			} else if (via->rtvia_family == AF_INET6) {
				nh_type = NH_TYPE_V6GW;
				ip_addr.type = AF_INET6;
				ip_addr.address.ip_v6 = nh.v6;

				nhops = nexthop_create(oifp,
						       &ip_addr,
						       flags,
						       out_label_count,
						       hl_out_labels);
			} else {
				RTE_LOG(INFO, MPLS,
					"unsupported via address in route change message: %u\n",
					via->rtvia_family);
				nhops = NULL;
			}
		}

		DP_DEBUG(MPLS_CTRL, INFO, MPLS,
			 "%s table %u type %s scope %u proto %u in %d payload %u out %s dev %s via %s\n",
			 nlmsg_type(nlh->nlmsg_type), rtm->rtm_table,
			 rtm->rtm_type == RTN_UNICAST ? "unicast" : "multicast",
			 rtm->rtm_scope, rtm->rtm_protocol, in_label,
			 payload_type,
			 mpls_labels_ntop(hl_out_labels, out_label_count,
					  b2, sizeof(b2)),
			 oifp ? oifp->if_name : "none",
			 via ? inet_ntop(via->rtvia_family, via->rtvia_addr,
					 b3, sizeof(b3)) : "none");

		if (nhops == NULL)
			RTE_LOG(ERR, MPLS,
				"No next-hops for route change message\n");
		else
			mpls_label_table_insert_label(global_label_space_id,
						      in_label, nh_type,
						      payload_type, nhops,
						      size);

		if (nh_type == NH_TYPE_V6GW)
			free(nhops);
		else
			free(nhops);
	} else {
		mpls_label_table_remove_label(global_label_space_id, in_label);
	}

	return MNL_CB_OK;
}

static void
mpls_forwarding_enable(struct ifnet *ifp, bool enable, uint32_t label_space)
{
	if (enable) {
		if (ifp->mpls_label_table)
			mpls_label_table_unlock(ifp->mpls_labelspace);
		ifp->mpls_labelspace = label_space;
		rcu_assign_pointer(ifp->mpls_label_table,
				   mpls_label_table_get_and_lock(label_space));
	} else if (ifp->mpls_label_table) {
		rcu_assign_pointer(ifp->mpls_label_table, NULL);
		mpls_label_table_unlock(ifp->mpls_labelspace);
	}
	fal_if_update_forwarding(ifp, AF_MPLS, false);
}

/* Callback to process netconf messages */
static int mpls_netconf_change(const struct nlmsghdr *nlh,
			       const struct netconfmsg *ncm __rte_unused,
			       struct nlattr *tb[],
			       enum cont_src_en cont_src)
{
	struct ifnet *ifp;
	int signed_ifindex;

	if (cont_src != CONT_SRC_MAIN) {
		RTE_LOG(ERR, MPLS,
			"(%s) mpls netconf change invalid controller\n",
			cont_src_name(cont_src));
		return MNL_CB_ERROR;
	}

	if (!tb[NETCONFA_IFINDEX])
		return MNL_CB_OK;

	signed_ifindex = mnl_attr_get_u32(tb[NETCONFA_IFINDEX]);
	if (signed_ifindex < 0)
		return MNL_CB_OK;	/* NETCONFA_IFINDEX_ALL */

	unsigned int ifindex = cont_src_ifindex(cont_src, signed_ifindex);
	ifp = dp_ifnet_byifindex(ifindex);
	if (!ifp)  /* not local to DP */
		return MNL_CB_OK;

	if (tb[NETCONFA_INPUT]) {
		bool enabled = !!mnl_attr_get_u32(tb[NETCONFA_INPUT]);

		DP_DEBUG(MPLS_CTRL, INFO, MPLS,
			 "%s %s: input %s\n",
			 nlmsg_type(nlh->nlmsg_type),
			 ifp->if_name, enabled ? "enabled" : "disabled");
		mpls_forwarding_enable(ifp,
				       enabled,
				       global_label_space_id);
	}

	return MNL_CB_OK;
}

static const struct netlink_handler mpls_netlink = {
	.route = mpls_route_change,
	.netconf = mpls_netconf_change,
};

void mpls_netlink_init(void)
{
	register_netlink_handler(AF_MPLS, &mpls_netlink);
}
