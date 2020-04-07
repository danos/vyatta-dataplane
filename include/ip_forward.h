/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef VYATTA_DATAPLANE_IP_FORWARD_H
#define VYATTA_DATAPLANE_IP_FORWARD_H

#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <rte_mbuf.h>

#include "interface.h"
#include "ip.h"
#include "vrf.h"
#include "fal_plugin.h"

/*
 * This file declares IP forwarding, nexthop related APIs and route tracker
 * APIs exported by dataplane for IPv4 and IPv6 address families
 */

/*
 * Holds parameters needed for calculating ecmp hash
 */
struct ecmp_hash_param {
	const struct ip_addr src_ip;
	const struct ip_addr dst_ip;
	uint32_t src_port;
	uint32_t dst_port;
	uint8_t  protocol;
};

/*
 * Forward declaration of next_hop structure for Ipv4 and IPv6
 */
struct next_hop;
struct next_hop_v6;

typedef void (*tracker_change_notif)(void *cb_ctx);

/*
 * Tracker information for route resolution
 */
struct rt_tracker_info;

/*
 * Get tracking status from RT Tracker
 * @param[in] rt_info  Route tracker information
 *
 * @return  true if being tracking, false otherwise.
 */
bool dp_get_rt_tracker_tracking(struct rt_tracker_info *rt_info);

/*
 * Get tracking status from RT Tracker
 * @param[in] rt_info  Route tracker information
 *
 * @return  Index of NH.
 */
uint32_t dp_get_rt_tracker_nh_index(struct rt_tracker_info *rt_info);

/*
 * Add a tracker to track the route resolution of a given destination
 *
 * @param[in]  vrf    VRF of the destination to be tracked
 * @param[in]  addr   IP address to be tracked
 * @param[in]  cb_ctx Context for the callback
 * @param[in]  cb     Registered callback, in case there are changes
 *
 * @return Tracker Information for route
 */
struct rt_tracker_info *dp_rt_tracker_add(struct vrf *vrf,
			struct ip_addr *addr, void *cb_ctx,
			tracker_change_notif cb);

/*
 * Delete a tracker to track the route resolution of a given destination
 *
 * @param[in]  vrf    VRF of the destination to be tracked
 * @param[in]  addr   IP address to be tracked
 * @param[in]  cb_ctx Context for the callback
 */
void dp_rt_tracker_delete(const struct vrf *vrf, struct ip_addr *addr,
			void *cb_ctx);

/*
 * IPv4 route lookup function for a given destination for the table id passed.
 * Route table is identified by the tbl_id parameter. Table ids values
 * as defined by Linux kernel(rtnetlink.h) are used. RT_TABLE_MAIN = 254 can
 * be used for a lookup in the main table. Dataplane uses 1-128 table ids for
 * PBR and table ids above 255 are used for VRF. The table ids for reference
 * RT_TABLE_UNSPEC=0,
 * 1-128 reserved for PBR
 * RT_TABLE_COMPAT=252,
 * RT_TABLE_DEFAULT=253,
 * RT_TABLE_MAIN=254,
 * RT_TABLE_LOCAL=255,
 *
 * @param[in] dst destination ipv4 address
 * @param[in] tbl_id Table id for route lookup
 * @param[in] m pointer to mbuf
 *
 * @return nexthop v4 pointer
 */
struct next_hop *dp_rt_lookup(in_addr_t dst, uint32_t tbl_id,
			      const struct rte_mbuf *m);

/*
 * Lookup NH information based on NH index, and use the hash in case
 * the NH is a multi-path nexthop
 *
 * @param[in] nhindex  NH index
 * @param[in] hash     Hash value used to obtain the path information in case
 *                     of multi-path nexthop
 * @param[out] nh      IP address of the next hop
 * @param[out] ifindex If index of the outgoing interface
 *
 * @return 0 for success, otherwise -1
 */
int dp_nh_lookup_by_index(uint32_t nhindex, uint32_t hash, in_addr_t *nh,
		       uint32_t *ifindex);

/*
 * IPv6 route lookup function for a given destination for the table id passed.
 * Route table is identified by the tbl_id parameter. Table ids values
 * as defined by Linux kernel(rtnetlink.h) are used. RT_TABLE_MAIN = 254 can
 * be used for a lookup in the main table. Dataplane uses 1-128 table ids for
 * PBR and table ids above 255 are used for VRF. The table ids for reference
 * RT_TABLE_UNSPEC=0,
 * 1-128 reserved for PBR
 * RT_TABLE_COMPAT=252,
 * RT_TABLE_DEFAULT=253,
 * RT_TABLE_MAIN=254,
 * RT_TABLE_LOCAL=255,
 *
 * @param[in] dst destination IPv6 address
 * @param[in] tbl_id Table id for route lookup
 * @param[in] m pointer to mbuf
 *
 * @return nexthop v6 pointer
 */
struct next_hop_v6 *dp_rt6_lookup(const struct in6_addr *dst,
				  uint32_t tbl_id,
				  const struct rte_mbuf *m);

/*
 * Lookup IPv6 NH information based on NH index, and use the hash in case
 * the NH is a multi-path nexthop
 *
 * @param[in] nhindex  IPv6 NH index
 * @param[in] hash     Hash value used to obtain the path information in case
 *                     of multi-path nexthop
 * @param[out] nh      IPv6 address of the next hop
 * @param[out] ifindex If index of the outgoing interface
 *
 * @return 0 for success, otherwise -1
 */
int dp_nh6_lookup_by_index(uint32_t nhindex, uint32_t hash,
			struct in6_addr *nh, uint32_t *ifindex);

/*
 * Get interface pointer for IPv4 next hop
 *
 * @param[in] next_hop IPv4 next_hop pointer
 * @return interface pointer
 */
struct ifnet *
dp_nh4_get_ifp(const struct next_hop *next_hop);

/*
 * Get address for IPv4 next hop
 *
 * @param[in] next_hop IPv4 next_hop pointer
 * @return the ip_address
 */
const struct in_addr *
dp_nh4_get_addr(const struct next_hop *next_hop);

/*
 * Get interface pointer for IPv6 next hop
 *
 * @param[in] next_hop IPv6 nexthop pointer
 * @return interface pointer
 */
struct ifnet *
dp_nh6_get_ifp(const struct next_hop_v6 *next_hop);

/*
 * Get address for IPv6 next hop
 *
 * @param[in] next_hop IPv6 next_hop pointer
 * @return pointer to the ip_address
 */
const struct in6_addr *
dp_nh6_get_addr(const struct next_hop_v6 *next_hop);

/*
 * IPv6 output function to transmit packet on a given output interface.
 * This function will populate the l2 address based on the output
 * interface passed.
 *
 * @param[in] in_ifp Input interface pointer
 * @param[in] m pointer to mbuf
 * @param[in] out_ifp Output interface pointer
 * @param[in] proto protocol
 *
 * @return True if packet sent , False otherwise
 */
bool
dp_ip6_l2_intf_output(struct ifnet *in_ifp,
		      struct rte_mbuf *m,
		      struct ifnet *out_ifp,
		      uint16_t proto);

/*
 * Function to transmit an IPv6 packet based on the forwarding information
 * in the provided next_hop. This function will populate the l2 address
 * based on the next_hop passed in.

 *
 * @param[in]      in_ifp  Input interface of the packet.
 * @param[in, out] mbuf    Pointer to mbuf
 * @param[out]     nh      Next hop that provides information about the output
 *                         interface and the L2 encap.
 * @param[in]      proto   The Layer 2 protocol.
 *
 * @return True if packet sent , False otherwise
 *
 */
bool dp_ip6_l2_nh_output(struct ifnet *in_ifp, struct rte_mbuf *m,
			 struct next_hop_v6 *nh, uint16_t proto);

/*
 * IPv4 output function to transmit packet on a given output interface.
 * This function will populate the l2 address based on the output
 * interface passed.
 *
 * @param[in] in_ifp Input interface pointer
 * @param[in] m pointer to mbuf
 * @param[in] out_ifp Output interface pointer
 * @param[in] proto protocol
 * @return True if packet sent, False otherwise
 */
bool
dp_ip_l2_intf_output(struct ifnet *in_ifp,
		     struct rte_mbuf *m,
		     struct ifnet *out_ifp,
		     uint16_t proto);

/*
 * Function to transmit an IPv4 packet based on the forwarding information
 * in the provided next_hop. This function will populate the l2 address
 * based on the next_hop passed in.
 *
 * @param[in]      in_ifp  Input interface of the packet.
 * @param[in, out] mbuf    Pointer to mbuf
 * @param[out]     nh      Next hop that provides information about the output
 *                         interface and the L2 encap.
 * @param[in]      proto   The Layer 2 protocol.
 *
 * @return True if packet sent , False otherwise
 *
 */
bool dp_ip_l2_nh_output(struct ifnet *in_ifp, struct rte_mbuf *m,
			struct next_hop *nh, uint16_t proto);

/**
 * Calculate ecmp hash with parameters held in structure
 * 'struct ecmp_hash_param'.
 *
 * @param[in] hash_param  Const poniter to data structure holding parameters
 *                        for ecmp hash calculation
 *
 * @return  hash value
 */
uint32_t dp_ecmp_hash(const struct ecmp_hash_param *hash_param);

#endif /* VYATTA_DATAPLANE_IP_FORWARD_H */
