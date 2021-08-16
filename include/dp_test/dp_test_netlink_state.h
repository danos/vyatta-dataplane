/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A test controller/console for the dataplane test harness.
 * This file provides a minimal implementation of a controlled
 * and the console so that the dataplane can be programmed and
 * queried.
 */

#ifndef _DP_TEST_NETLINK_STATE_H_
#define _DP_TEST_NETLINK_STATE_H_

#include <stdint.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <linux/xfrm.h>
#include <linux/if_bridge.h>

#include "../vrf.h"

void _dp_test_netlink_add_neigh(const char *ifname,
				const char *nh_addr_str,
				const char *mac_str,
				bool verify,
				const char *file, const char *func,
				int line);
#define dp_test_netlink_add_neigh(ifname, nh_addr_str, mac_str)		\
	_dp_test_netlink_add_neigh(ifname, nh_addr_str, mac_str,	\
				   true,				\
				   __FILE__, __func__, __LINE__)

void _dp_test_netlink_del_neigh(const char *ifname,
				const char *nh_addr_str,
				const char *mac_str, bool verify,
				const char *file, const char *func,
				int line);
#define dp_test_netlink_del_neigh(ifname, nh_addr_str, mac_str)		\
	_dp_test_netlink_del_neigh(ifname, nh_addr_str, mac_str,	\
				   true,				\
				   __FILE__, __func__, __LINE__)

void _dp_test_verify_neigh(const char *ifname,
			   const char *ipaddr,
			   const char *mac_str,
			   bool negate_match,
			   const char *file, const char *func,
			   int line);
#define dp_test_verify_neigh(ifname, nh_addr_str, mac_str, negate_match) \
	_dp_test_verify_neigh(ifname, nh_addr_str, mac_str,		\
			      negate_match,				\
			      __FILE__, __func__, __LINE__)

/* VRF creation / deletion macros */
void _dp_test_netlink_add_vrf(uint32_t vrf_id, uint32_t expected_ref_cnt,
			      const char *file, int line);

#define dp_test_netlink_add_vrf(vrf_id, expected_ref_cnt)		\
	_dp_test_netlink_add_vrf(vrf_id, expected_ref_cnt,		\
				 __FILE__, __LINE__)

void _dp_test_netlink_del_vrf(uint32_t vrf_id, uint32_t expected_ref_cnt,
			      const char *file, int line);

#define dp_test_netlink_del_vrf(vrf_id, expected_ref_cnt)		\
	_dp_test_netlink_del_vrf(vrf_id, expected_ref_cnt,		\
				 __FILE__, __LINE__)
/*
 * Bind interface to VRF (note sets MTU to default value).
 */
void _dp_test_netlink_set_interface_vrf(const char *name, uint32_t vrf_id,
					bool verify,
					const char *file, const char *func,
					int line);
#define dp_test_netlink_set_interface_vrf(name, vrf_id)	         \
	_dp_test_netlink_set_interface_vrf(name, vrf_id, true,         \
					   __FILE__, __func__, __LINE__)
/**
 * @brief Adds L3 address and adds route for the attached network
 *
 * @param [in] intf Name of the interface
 * @param [in] addr IPv4 or IPv6 address string for the interface, of the
 *             form "addr/prefix"
 */
#define dp_test_nl_add_ip_addr_and_connected(intf, addr)		\
	_dp_test_nl_add_ip_addr_and_connected(intf, addr,		\
					      VRF_DEFAULT_ID, __FILE__,	\
					      __func__, __LINE__)

#define dp_test_nl_add_ip_addr_and_connected_vrf(intf, addr, vrf_id)	\
	_dp_test_nl_add_ip_addr_and_connected(intf, addr, vrf_id,	\
					      __FILE__,  __func__,	\
					      __LINE__)

void
_dp_test_nl_add_ip_addr_and_connected(const char *intf, const char *addr,
				      vrfid_t vrf_id, const char *file,
				      const char *func, int line);

/**
 * @brief Remove interface address and attached network route
 *
 * @param [in] intf Name of the interface
 * @param [in] addr IPv4 or IPv6 address string for the interface, of the
 *             form "addr/prefix"
 */
#define dp_test_nl_del_ip_addr_and_connected(intf, addr)		\
	_dp_test_nl_del_ip_addr_and_connected(intf, addr,		\
					      VRF_DEFAULT_ID, __FILE__,	\
					      __func__, __LINE__)

#define dp_test_nl_del_ip_addr_and_connected_vrf(intf, addr, vrf_id)	\
	_dp_test_nl_del_ip_addr_and_connected(intf, addr, vrf_id,	\
					      __FILE__, __func__,	\
					      __LINE__)

void
_dp_test_nl_del_ip_addr_and_connected(const char *intf, const char *addr,
				      vrfid_t vrf_id, const char *file,
				      const char *func, int line);


/*
 * Add a route
 *
 * @param [in] route_str The route expressed as a string
 */
#define dp_test_netlink_add_route(route_str)		   \
	_dp_test_netlink_add_route(route_str, true, false, \
				   __FILE__, __func__, __LINE__)

void _dp_test_netlink_add_route(const char *route_str, bool verify,
				bool incomplete, const char *file,
				const char *func, int line);

/*
 * Delete a route
 *
 * @param [in] route_str The route expressed as a string
 */
#define dp_test_netlink_del_route(route_str)				\
	_dp_test_netlink_del_route(route_str, true,			\
				   __FILE__, __func__, __LINE__)

void _dp_test_netlink_del_route(const char *route_str, bool verify,
				const char *file, const char *func, int line);

/*
 * Add addresses to an interface
 */
void _dp_test_netlink_add_ip_address(const char *ifname, const char *prefix,
				     uint32_t vrf, bool verify,
				     const char *file, const char *func,
				     int line);
#define dp_test_netlink_add_ip_address(ifname, prefix)			\
	_dp_test_netlink_add_ip_address(ifname, prefix, VRF_DEFAULT_ID, true, \
					__FILE__, __func__, __LINE__)

#define dp_test_netlink_add_ip_address_noverify(ifname, prefix)		       \
	_dp_test_netlink_add_ip_address(ifname, prefix, VRF_DEFAULT_ID, false, \
					__FILE__, __func__, __LINE__)

#define dp_test_netlink_add_ip_address_vrf(ifname, prefix, vrf)	\
	_dp_test_netlink_add_ip_address(ifname, prefix, vrf, true,	\
					__FILE__, __func__, __LINE__)

/*
 * Delete addresses from an interface
 */
void _dp_test_netlink_del_ip_address(const char *ifname, const char *prefix,
				     uint32_t vrf, bool verify,
				     const char *file, const char *func,
				     int line);
#define dp_test_netlink_del_ip_address(ifname, prefix)			\
	_dp_test_netlink_del_ip_address(ifname,	prefix, VRF_DEFAULT_ID, true, \
					__FILE__, __func__, __LINE__)
#define dp_test_netlink_del_ip_address_noverify(ifname, prefix)		       \
	_dp_test_netlink_del_ip_address(ifname,	prefix, VRF_DEFAULT_ID, false, \
					__FILE__, __func__, __LINE__)
#define dp_test_netlink_del_ip_address_vrf(ifname, prefix, vrf)	\
	_dp_test_netlink_del_ip_address(ifname,	prefix,  vrf, \
					true,				\
					__FILE__, __func__, __LINE__)
#endif /* DP_TEST_NETLINK_STATE_H */
