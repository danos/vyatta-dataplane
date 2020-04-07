/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef VYATTA_DATAPLANE_INTERFACE_H
#define VYATTA_DATAPLANE_INTERFACE_H

#include <stdint.h>
#include <sys/socket.h>

#include "vrf.h"
#include "fal_plugin.h"

/*
 * This declares functions exported by dataplane to access
 * interface structure. Each Interface is represented via
 * structure ifnet pointer and has an interface index associated
 * with it.
 */
struct ifnet;

/**
 * @brief The duplex status of an interface
 */
enum dp_ifnet_link_duplex_type {
	DP_IFNET_LINK_DUPLEX_HALF = 0,
	DP_IFNET_LINK_DUPLEX_FULL = 1,
	DP_IFNET_LINK_DUPLEX_UNKNOWN = 2,
};

/**
 * @brief Value used for interface with unknown speed
 */
static const uint32_t DP_IFNET_LINK_SPEED_UNKNOWN = 0;

/**
 * @brief The status of an interface
 *
 * link_status true if interface is up. false otherwise. ifOperStatus in rfc2233
 * link_duplex duplex status of interface.
 * link_speed speed in Mbps. ifHighSpeed in rfc2233
 */
struct dp_ifnet_link_status {
	bool link_status;
	enum dp_ifnet_link_duplex_type link_duplex;
	uint32_t link_speed;
};

/**
 * @brief Get interface status
 *
 * @param ifp interface to get status of
 * @param if_link the status of the interface
 */
void dp_ifnet_link_status(struct ifnet *ifp,
			  struct dp_ifnet_link_status *if_link);

/*
 * Iterator function for walk of interfaces
 *
 * @param[in] ifp interface
 * @param[in] arg opaque caller context
 */
typedef void dp_ifnet_iter_func_t(struct ifnet *ifp, void *arg);

/*
 * Walk all interfaces
 *
 * @param[in] func function to call in each interface
 * @param[in] arg opaque caller context
 */
void dp_ifnet_walk(dp_ifnet_iter_func_t func, void *arg);

/*
 * Get interface index, Assumes valid ifnet pointer
 * @param[in] ifp Pointer to ifnet structure
 * @return interface index for a given interface pointer
 */
unsigned int dp_ifnet_ifindex(const struct ifnet *ifp);

/*
 * Get interface name, Assumes valid ifnet pointer
 * @param[in] ifp Pointer to ifnet structure
 * @return interface name for a given interface pointer
 */
const char *dp_ifnet_ifname(const struct ifnet *ifp);

/*
 * Get interface vrfid, Assumes valid ifnet pointer
 * @param[in] ifp Pointer to ifnet structure
 * @return interface vrfid for a given interface pointer
 */
vrfid_t dp_ifnet_vrfid(const struct ifnet *ifp);

/*
 * Get interface FAL L3 object.
 * @param[in] ifp Pointer to ifnet structure
 * @return interface fal_l3 for a given interface pointer
 */
fal_object_t dp_ifnet_fal_l3_if(const struct ifnet *ifp);

/*
 * Get ifnet pointer from interface index
 * @param[in] ifindex Interface index
 * @return interface structure  pointer for the given index
 */
struct ifnet *dp_ifnet_byifindex(unsigned int ifindex);

/*
 * Get ifnet pointer from interface name
 * @param[in] name Interface Name
 * @return interface structure  pointer for the given index
 */
struct ifnet *dp_ifnet_byifname(const char *name);

/*
 * Interface types as defined in the ianaiftype-mib register specified
 * as part of rfc2233
 */
enum dp_ifnet_iana_type {
	DP_IFTYPE_IANA_OTHER = 1,
	DP_IFTYPE_IANA_ETHERNETCSMACD = 6,
	DP_IFTYPE_IANA_PPP = 23,
	DP_IFTYPE_IANA_SOFTWARELOOPBACK = 24,
	DP_IFTYPE_IANA_TUNNEL = 131,
	DP_IFTYPE_IANA_L2VLAN = 135,
	DP_IFTYPE_IANA_BRIDGE = 209,
};

/*
 * Get the rfc2233 interface type, Assumes valid ifnet pointer
 * @param[in] ifp Pointer to ifnet interface
 * @return interface type as defined in the ianaiftype-mib
 */
enum dp_ifnet_iana_type dp_ifnet_iana_type(struct ifnet *ifp);

/*
 * Is an interface a member of a bridge
 *
 * @param[in] ifp Pointer to the interface
 *
 * @return True if the interface is a bridge member
 * @return False if the interface is nota bridge member
 */
bool dp_ifnet_is_bridge_member(struct ifnet *ifp);

/**
 * @brief rfc2233 IfEntry counters
 *
 * See https://tools.ietf.org/html/rfc2233
 */
struct dp_ifnet_mib_counters {
	uint64_t dp_ifnet_mib_counter_inoctets;
	uint64_t dp_ifnet_mib_counter_inucastpkts;
	uint64_t dp_ifnet_mib_counter_inmulticastpkts;
	uint64_t dp_ifnet_mib_counter_inbroadcastpkts;
	uint64_t dp_ifnet_mib_counter_indiscards;
	uint64_t dp_ifnet_mib_counter_inerrors;
	uint64_t dp_ifnet_mib_counter_inunknownprotos;
	uint64_t dp_ifnet_mib_counter_outoctets;
	uint64_t dp_ifnet_mib_counter_outucastpkts;
	uint64_t dp_ifnet_mib_counter_outmulticastpkts;
	uint64_t dp_ifnet_mib_counter_outbroadcastpkts;
	uint64_t dp_ifnet_mib_counter_outdiscards;
	uint64_t dp_ifnet_mib_counter_outerrors;
};

/**
 * @brief Get MIB counters for an interface
 *
 * @note outmulticastpkts and outbroadcastpkts will always 0
 *
 * @param ifp[in] interface to get counters for
 * @param counter[out] the counters to populate
 * @return 0 if counters populated. Non zero if not.
 */
int dp_ifnet_mib_counters(struct ifnet *ifp,
			  struct dp_ifnet_mib_counters *counters);

/**
 * Iterator function for walk of interface addresses
 *
 * @param[in] addr address associated with the interface
 * @param[in] prefixlen prefix length of the address
 * @param[in] arg opaque caller context
 *
 * @return 0 on success. Non zero terminates walk
 */
typedef int dp_ifnet_addr_iter_func_t(struct sockaddr *addr, uint8_t prefixlen,
				      void *arg);

/**
 * Walk all addresses on an interface
 *
 * @param[in] ifp interface to walk addresses on
 * @param[in] func function to call for each address
 * @param[in] arg opaque caller context
 *
 * @return 0 on success. Non zero, walk was terminated.
 */
int dp_ifnet_addr_walk(struct ifnet *ifp, dp_ifnet_addr_iter_func_t func,
		       void *arg);

#endif /* VYATTA_DATAPLANE_INTERFACE_H */
