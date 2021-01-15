/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Route update protobuf handling for IP & MPLS
 */

#include "if_var.h"
#include "ip_rt_protobuf.h"
#include "mpls/mpls_label_table.h"
#include "netinet6/in6.h"
#include "netinet6/route_v6.h"
#include "netlink.h"
#include "nh_common.h"
#include "protobuf/RibUpdate.pb-c.h"
#include "route.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "vrf_if.h"
#include "vrf_internal.h"

#define IN6_SET_ADDR_V4MAPPED(a6, a4) {			\
		(a6)->s6_addr32[0] = 0;			\
		(a6)->s6_addr32[1] = 0;			\
		(a6)->s6_addr32[2] = htonl(0xffff);	\
		(a6)->s6_addr32[3] = (a4);		\
	}

static bool nexthop_fill_common(struct next_hop *next, Path *path,
				bool *missing_ifp)
{
	struct ifnet *ifp;
	bool exp_ifp = true;

	ifp = dp_ifnet_byifindex(path->ifindex);

	switch (path->type) {
	case PATH__PATH_TYPE__BLACKHOLE:
		next->flags |= RTF_BLACKHOLE;
		exp_ifp = false;
		break;
	case PATH__PATH_TYPE__UNREACHABLE:
		next->flags |= RTF_REJECT;
		exp_ifp = false;
		break;
	case PATH__PATH_TYPE__LOCAL:
		next->flags |= RTF_LOCAL;
		/* no need to store ifp for local routes */
		ifp = NULL;
		exp_ifp = false;
		break;
	case PATH__PATH_TYPE__UNICAST:
		break;
	default:
		RTE_LOG(NOTICE, DATAPLANE,
			"unexpected path type %d in RibUpdate protobuf message\n",
			path->type);
		return false;
	}

	nh_set_ifp(next, ifp);
	if (!ifp && exp_ifp && !is_ignored_interface(path->ifindex)) {
		*missing_ifp = true;
		return false;
	}

	nh_outlabels_set(&next->outlabels, path->n_mpls_labels,
			 path->mpls_labels);

	if ((!ifp || (is_lo(ifp) && path->n_mpls_labels == 0)) &&
	    exp_ifp)
		/* no dp interface or via loopback */
		next->flags |= RTF_SLOWPATH;

	if (path->n_mpls_labels > 0 && !is_lo(ifp))
		/* Output label rather than local label */
		next->flags |= RTF_OUTLABEL;

	if (path->backup)
		next->flags |= RTF_BACKUP;

	return true;
}

/*
 * Returns true on success, false on failure. Failure includes a
 * missing ifp.
 */
static bool nexthop_fill(struct next_hop *next, Path *path, bool *missing_ifp)
{
	if (path->nexthop) {
		/* Cannot store IPv4 routes with IPv6 nexthops */
		if (path->nexthop->address_oneof_case !=
		    IPADDRESS__ADDRESS_ONEOF_IPV4_ADDR) {
			RTE_LOG(NOTICE, DATAPLANE,
				"unexpected nexthop address %d in IPv4 RibUpdate protobuf message\n",
				path->nexthop->address_oneof_case);
			return false;
		}
		next->gateway.address.ip_v4.s_addr = path->nexthop->ipv4_addr;
		next->gateway.type = AF_INET;
		next->flags |= RTF_GATEWAY;
	}

	if (!nexthop_fill_common(next, path, missing_ifp))
		return false;

	return true;
}

/*
 * Returns true on success, false on failure. Failure includes a
 * missing ifp.
 */
static bool nexthop6_fill(struct next_hop *next, Path *path,
			  bool *missing_ifp)
{
	if (path->nexthop) {
		if (path->nexthop->address_oneof_case ==
		    IPADDRESS__ADDRESS_ONEOF_IPV6_ADDR &&
		    path->nexthop->ipv6_addr.len ==
		    sizeof(next->gateway.address)) {
			memcpy(&next->gateway.address,
			       path->nexthop->ipv6_addr.data,
			       sizeof(next->gateway.address));
		} else if (path->nexthop->address_oneof_case ==
			   IPADDRESS__ADDRESS_ONEOF_IPV4_ADDR) {
			IN6_SET_ADDR_V4MAPPED(&next->gateway.address.ip_v6,
					      path->nexthop->ipv4_addr);
		} else {
			RTE_LOG(NOTICE, DATAPLANE,
				"path nexthop address type %d in RibUpdate protobuf message\n",
				path->nexthop->address_oneof_case);
			return false;
		}
		next->gateway.type = AF_INET6;

		if (IN6_IS_ADDR_V4MAPPED(&next->gateway.address.ip_v6))
			next->flags |= RTF_MAPPED_IPV6;
		next->flags |= RTF_GATEWAY;
	}

	if (!nexthop_fill_common(next, path, missing_ifp))
		return false;

	if (path->backup)
		next->flags |= RTF_BACKUP;

	return true;
}

static struct next_hop *
nexthop_list_create(Route *route, enum nh_type nh_type, bool *missing_ifp)
{
	struct next_hop *next, *n;
	size_t size;
	Path *path;
	size_t i;

	next = calloc(sizeof(*next), route->n_paths);
	if (!next)
		return NULL;

	for (i = 0; i < route->n_paths; i++) {
		path = route->paths[i];
		n = &next[i];

		if (nh_type == NH_TYPE_V4GW) {
			if (!nexthop_fill(n, path, missing_ifp))
				goto fail;
		} else {
			if (!nexthop6_fill(n, path, missing_ifp))
				goto fail;
		}
	}

	return next;

fail:
	size = i;
	for (i = 0; i < size; i++)
		nh_outlabels_destroy(&next[i].outlabels);
	free(next);
	return NULL;
}

static bool ip_rt_pb_table_to_vrf(
	RibUpdate *rtupdate, enum cont_src_en cont_src,
	bool *add_incomplete, uint32_t *table, vrfid_t *vrf_id)
{
	*vrf_id = VRF_DEFAULT_ID;

	if (vrf_is_vrf_table_id(*table) &&
	    vrf_lookup_by_tableid(*table, vrf_id, table) < 0) {
		/*
		 * Route came down before the vrf device
		 * RTM_NEWLINK - defer route installation until it
		 * arrives.
		 */
		if (rtupdate->action == RIB_UPDATE__ACTION__UPDATE)
			*add_incomplete = true;
		return false;
	}

	if (!netlink_uplink_vrf(cont_src, vrf_id)) {
		if (rtupdate->action == RIB_UPDATE__ACTION__UPDATE)
			*add_incomplete = true;
		return false;
	}

	return true;
}

static int ipv4_route_pb_handler(RibUpdate *rtupdate,
				 enum cont_src_en cont_src,
				 bool *add_incomplete)
{
	Route *route = rtupdate->route;
	uint32_t table = route->table_id;
	char b1[INET6_ADDRSTRLEN];
	struct next_hop *next;
	vrfid_t vrf_id;

	if (!ip_rt_pb_table_to_vrf(rtupdate, cont_src, add_incomplete,
				   &table, &vrf_id))
		return 0;

	DP_DEBUG_W_VRF(NETLINK_ROUTE, INFO, ROUTE, vrf_id,
		       "%s table %u dst %s/%u scope %u proto %u num_paths %lu\n",
		       rtupdate->action == RIB_UPDATE__ACTION__DELETE ?
		       "delete" : "add/update",
		       table,
		       inet_ntop(AF_INET, &route->prefix->ipv4_addr, b1,
				 sizeof(b1)),
		       route->prefix_length, route->scope,
		       route->routing_protocol, route->n_paths);

	if (rtupdate->action == RIB_UPDATE__ACTION__DELETE) {
		rt_delete(vrf_id, route->prefix->ipv4_addr,
			  route->prefix_length, table, route->scope);
		return 0;
	}
	if (rtupdate->action != RIB_UPDATE__ACTION__UPDATE) {
		RTE_LOG(NOTICE, DATAPLANE,
			"unexpected action %d in RibUpdate protobuf message\n",
			rtupdate->action);
		return 0;
	}

	next = nexthop_list_create(route, NH_TYPE_V4GW, add_incomplete);
	if (!next && *add_incomplete)
		return 0;
	if (!next)
		return -1;

	rt_insert(vrf_id, route->prefix->ipv4_addr,
		  route->prefix_length, table, route->scope,
		  route->routing_protocol, next, route->n_paths, true);

	free(next);

	return 0;
}

static int ipv6_route_pb_handler(RibUpdate *rtupdate,
				 enum cont_src_en cont_src,
				 bool *add_incomplete)
{
	Route *route = rtupdate->route;
	uint32_t table = route->table_id;
	char b1[INET6_ADDRSTRLEN];
	struct next_hop *next;
	struct in6_addr dst;
	vrfid_t vrf_id;

	if (!ip_rt_pb_table_to_vrf(rtupdate, cont_src, add_incomplete,
				   &table, &vrf_id))
		return 0;

	memcpy(&dst, route->prefix->ipv6_addr.data, sizeof(dst));

	DP_DEBUG_W_VRF(NETLINK_ROUTE, INFO, ROUTE, vrf_id,
		       "%s table %u dst %s/%u scope %u proto %u num_paths %lu\n",
		       rtupdate->action == RIB_UPDATE__ACTION__DELETE ?
		       "delete" : "add/update",
		       table,
		       inet_ntop(AF_INET6, &dst, b1, sizeof(b1)),
		       route->prefix_length, route->scope,
		       route->routing_protocol, route->n_paths);

	if (rtupdate->action == RIB_UPDATE__ACTION__DELETE) {
		bool local;

		local = route->n_paths == 1 &&
			route->paths[0]->type == PATH__PATH_TYPE__LOCAL;

		rt6_delete(vrf_id, &dst, route->prefix_length, table,
			   route->scope, local);
		return 0;
	}
	if (rtupdate->action != RIB_UPDATE__ACTION__UPDATE) {
		RTE_LOG(NOTICE, DATAPLANE,
			"unexpected action %d in RibUpdate protobuf message\n",
			rtupdate->action);
		return 0;
	}

	next = nexthop_list_create(route, NH_TYPE_V6GW, add_incomplete);
	if (!next && *add_incomplete)
		return 0;
	if (!next)
		return -1;

	rt6_add(vrf_id, &dst, route->prefix_length, table,
		route->scope, next, route->n_paths);

	free(next);

	return 0;
}

static int mpls_route_pb_handler(RibUpdate *rtupdate, bool *add_incomplete)
{
	enum nh_type nh_type = NH_TYPE_V4GW;
	uint32_t payload_type = MPT_UNSPEC;
	Route *route = rtupdate->route;
	struct next_hop *next;
	Path *path;
	size_t i;

	if (rtupdate->action == RIB_UPDATE__ACTION__DELETE) {
		mpls_label_table_remove_label(global_label_space_id,
					      route->prefix->mpls_label);
		return 0;
	}
	if (rtupdate->action != RIB_UPDATE__ACTION__UPDATE) {
		RTE_LOG(NOTICE, DATAPLANE,
			"unexpected action %d in RibUpdate protobuf message\n",
			rtupdate->action);
		return 0;
	}

	switch (route->payload_type) {
	case ROUTE__PAYLOAD_TYPE__IPV4:
		payload_type = MPT_IPV4;
		break;
	case ROUTE__PAYLOAD_TYPE__IPV6:
		payload_type = MPT_IPV6;
		break;
	case ROUTE__PAYLOAD_TYPE__UNSPEC:
		break;
	default:
		RTE_LOG(NOTICE, DATAPLANE,
			"unexpected payload_type %d in RibUpdate protobuf message for label %u\n",
			route->payload_type, route->prefix->mpls_label);
		return -1;
	}

	for (i = 0; i < route->n_paths; i++) {
		path = route->paths[i];

		/*
		 * MPLS route uses IPv6 addresses if there is at least
		 * one IPv6 nexthop present, or if it's a deagg for an
		 * IPv6 payload. This is done for compatibility
		 * reasons since the RIB previously sent down a
		 * nexthop of IPv6 unspecified in this case, but no
		 * longer does.
		 */
		if ((path->nexthop && path->nexthop->address_oneof_case ==
		     IPADDRESS__ADDRESS_ONEOF_IPV6_ADDR) ||
		    (payload_type == MPT_IPV6 &&
		     is_lo(dp_ifnet_byifindex(path->ifindex)))) {
			nh_type = NH_TYPE_V6GW;
			break;
		}
	}

	next = nexthop_list_create(route, nh_type, add_incomplete);
	if (!next && *add_incomplete)
		return 0;
	if (!next)
		return -1;

	for (i = 0; i < route->n_paths; i++) {
		if (!route->paths[i]->mpls_bos_only &&
		    route->paths[i]->n_mpls_labels == 0) {
			/*
			 * If there are no labels and BOS_ONLY not
			 * set, then this implies the implicit-null
			 * label. This won't go out on the wire and is
			 * for signaling only.
			 */
			label_t lbl[1] = { MPLS_LABEL_IMPLNULL };

			nh_outlabels_set(&next[i].outlabels, 1, lbl);
		}

		/*
		 * Also remove setting of RTF_SLOWPATH done by
		 * nexthop[6]_fill, since it doesn't know that it's
		 * called from MPLS context and thus route with no
		 * labels via loopback means de-agg.
		 * In addition, set the gateway flag for preserving
		 * compatibility of show output where we showed for a
		 * deagg:
		 *
		 * in label: 53760, fec:ipv6
		 * 	nexthop via ::, vrfred
		 *
		 */
		if (is_lo(dp_nh_get_ifp(&next[i]))) {
			next[i].flags &= ~RTF_SLOWPATH;
			next[i].flags |= RTF_GATEWAY;
		}
	}

	mpls_label_table_insert_label(global_label_space_id,
				      route->prefix->mpls_label, nh_type,
				      payload_type, next,
				      route->n_paths);

	free(next);

	return 0;
}

int ip_route_pb_handler(void *data, size_t len, enum cont_src_en cont_src)
{
	bool add_incomplete = false;
	RibUpdate *rtupdate;
	Route *route;
	int rc = -1;
	void *dest;
	int af;

	rtupdate = rib_update__unpack(NULL, len, data);
	if (!rtupdate) {
		RTE_LOG(ERR, DATAPLANE,
			"failed to read RibUpdate protobuf message\n");
		return -1;
	}

	if (!rtupdate->route) {
		RTE_LOG(NOTICE, DATAPLANE,
			"missing route in RibUpdate protobuf message\n");
		goto free_msg;
	}

	if (!rtupdate->route->prefix) {
		RTE_LOG(NOTICE, DATAPLANE,
			"missing prefix in RibUpdate protobuf message\n");
		goto free_msg;
	}

	if (rtupdate->route->n_paths == 0 &&
	    rtupdate->action != RIB_UPDATE__ACTION__DELETE) {
		RTE_LOG(NOTICE, DATAPLANE,
			"Invalid n_paths in RibUpdate protobuf message\n");
		goto free_msg;
	}

	route = rtupdate->route;

	switch (rtupdate->route->prefix->address_oneof_case) {
	case IPADDRESS_OR_LABEL__ADDRESS_ONEOF_IPV4_ADDR:
		af = AF_INET;
		dest = &rtupdate->route->prefix->ipv4_addr;
		break;
	case IPADDRESS_OR_LABEL__ADDRESS_ONEOF_IPV6_ADDR:
		if (route->prefix->ipv6_addr.len != sizeof(struct in6_addr)) {
			RTE_LOG(NOTICE, DATAPLANE,
				"bad prefix address length %lu in RibUpdate protobuf message\n",
				route->prefix->ipv6_addr.len);
			rc = -1;
			goto free_msg;
		}

		af = AF_INET6;
		dest = rtupdate->route->prefix->ipv6_addr.data;
		break;
	case IPADDRESS_OR_LABEL__ADDRESS_ONEOF_MPLS_LABEL:
		af = AF_MPLS;
		dest = &rtupdate->route->prefix->mpls_label;
		break;
	default:
		rc = -2;
		goto free_msg;
	}

	incomplete_route_del(dest, af, route->prefix_length,
			     route->table_id, route->scope,
			     route->routing_protocol);

	switch (rtupdate->route->prefix->address_oneof_case) {
	case IPADDRESS_OR_LABEL__ADDRESS_ONEOF_IPV4_ADDR:
		rc = ipv4_route_pb_handler(rtupdate, cont_src, &add_incomplete);
		break;
	case IPADDRESS_OR_LABEL__ADDRESS_ONEOF_IPV6_ADDR:
		rc = ipv6_route_pb_handler(rtupdate, cont_src, &add_incomplete);
		break;
	case IPADDRESS_OR_LABEL__ADDRESS_ONEOF_MPLS_LABEL:
		rc = mpls_route_pb_handler(rtupdate, &add_incomplete);
		break;
	default:
		break;
	}

	if (!rc && add_incomplete)
		incomplete_route_add_pb(dest, af,
					route->prefix_length,
					route->table_id, route->scope,
					route->routing_protocol, data,
					len);

free_msg:
	rib_update__free_unpacked(rtupdate, NULL);
	return rc;
}
