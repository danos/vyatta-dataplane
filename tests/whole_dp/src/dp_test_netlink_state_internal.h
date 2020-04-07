/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
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

#ifndef _DP_TEST_NETLINK_STATE_INTERNAL_H_
#define _DP_TEST_NETLINK_STATE_INTERNAL_H_

#include <stdint.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <linux/xfrm.h>
#include <linux/if_bridge.h>

#include "vrf_internal.h"
#include "if/bridge/bridge_port.h"

#include "dp_test_lib_intf_internal.h"
#include "dp_test/dp_test_netlink_state.h"

void _dp_test_netlink_set_interface_l2(const char *name, bool verify,
				       const char *file, const char *func,
				       int line);
#define dp_test_netlink_set_interface_l2(name)                  \
	_dp_test_netlink_set_interface_l2(name, true,                 \
					  __FILE__, __func__, __LINE__)
#define dp_test_netlink_set_interface_l2_noverify(name)         \
	_dp_test_netlink_set_interface_l2(name, false,                \
					  __FILE__, __func__, __LINE__)

void _dp_test_netlink_del_interface_l2(const char *name, bool verify,
				       const char *file, const char *func,
				       int line);
#define dp_test_netlink_del_interface_l2(name)                  \
	_dp_test_netlink_del_interface_l2(name, true,                 \
					  __FILE__, __func__, __LINE__)
#define dp_test_netlink_del_interface_l2_noverify(name)          \
	_dp_test_netlink_del_interface_l2(name, false,                \
					  __FILE__, __func__, __LINE__)

void _dp_test_netlink_set_interface_mtu(const char *name, int mtu, bool verify,
					const char *file, const char *func,
					int line);
/*
 * Set MTU (note sets VRF to default VRF).
 */
#define dp_test_netlink_set_interface_mtu(name, mtu)	         \
	_dp_test_netlink_set_interface_mtu(name, mtu, true,            \
					   __FILE__, __func__, __LINE__)

void _dp_test_netlink_set_interface_admin_status(
	const char *name, bool admin_up, bool verify,
	const char *file, const char *func, int line);

/*
 * Change admin status of interface (note sets VRF and MTU to default values).
 */
#define dp_test_netlink_set_interface_admin_status(name, admin_up)     \
	_dp_test_netlink_set_interface_admin_status(		       \
		name, admin_up, true, __FILE__, __func__, __LINE__)

/*
 * Set/reset the tos to be used when sending tunnel create messages.
 */
void dp_test_set_gre_tos(uint8_t val);
void dp_test_reset_gre_tos(void);

/*
 * Set/reset the DF handling to be used when sending tunnel create messages.
 */
void dp_test_set_gre_ignore_df(bool val);
void dp_test_reset_gre_ignore_df(void);

void _dp_test_netlink_create_tunnel(const char *name,
				    const char *local,
				    const char *remote,
				    uint32_t key,
				    bool seq,
				    uint32_t vrf_id,
				    enum dp_test_tun_encap_type_e e_type,
				    bool verify,
				    const char *file, const char *func,
				    int line);
#define dp_test_netlink_create_tunnel(name, local, remote, key,		 \
				      seq, vrf_id, e_type)		 \
	_dp_test_netlink_create_tunnel(name, local,			 \
				       remote, key, seq, vrf_id, e_type, \
				       true, __FILE__, __func__, __LINE__)

void _dp_test_netlink_delete_tunnel(const char *name,
				    const char *local,
				    const char *remote,
				    uint32_t key,
				    bool seq,
				    uint32_t vrf_id,
				    enum dp_test_tun_encap_type_e e_type,
				    bool verify,
				    const char *file, const char *func,
				    int line);
#define dp_test_netlink_delete_tunnel(name, local, remote, key,		 \
				      seq, vrf_id, e_type)		 \
	_dp_test_netlink_delete_tunnel(name, local,			 \
				       remote, key, seq, vrf_id, e_type, \
				       true, __FILE__, __func__, __LINE__)

void
_dp_test_netlink_create_ppp(const char *intf_name, uint32_t vrf_id,
			    bool verify, const char *file,
			    const char *func, int line);
void
_dp_test_netlink_delete_ppp(const char *intf_name, uint32_t vrf_id,
			    bool verify, const char *file,
			    const char *func, int line);
void
_dp_test_intf_ppp_set_mtu(const char *intf_name, uint32_t vrf_id,
			  int mtu, bool verify, const char *file,
			  const char *func, int line);

#define dp_test_intf_ppp_set_mtu(intf_name, vrf, mtu) \
	_dp_test_intf_ppp_set_mtu(intf_name, vrf, mtu, true, __FILE__,	\
				  __func__, __LINE__)

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

void
_dp_test_netlink_set_mpls_forwarding(const char *ifname, bool enable,
				     const char *file,
				     const char *func, int line);
#define dp_test_netlink_set_mpls_forwarding(ifname, enable)		\
	_dp_test_netlink_set_mpls_forwarding(ifname, enable, __FILE__,	\
					     __func__, __LINE__)
#define dp_test_netlink_add_route_nv(route_string)		\
	_dp_test_netlink_add_route(route_string, false, false,  \
				   __FILE__, __func__, __LINE__)

#define dp_test_netlink_add_incmpl_route(route_string)		\
	_dp_test_netlink_add_route(route_string, false, true,	\
				   __FILE__, __func__, __LINE__)
#define dp_test_netlink_del_incmpl_route(route_string)		\
	_dp_test_netlink_del_route(route_string, false,	\
				   __FILE__, __func__, __LINE__)

#define dp_test_netlink_add_route_nv(route_string)		\
	_dp_test_netlink_add_route(route_string, false,	false,	\
				   __FILE__, __func__, __LINE__)


void
_dp_test_netlink_add_route_fmt(bool verify, bool incomplete,
			       const char *file, const char *func,
			       int line, const char *format, ...)
	__attribute__((__format__(printf, 6, 7)));

#define dp_test_nl_add_route_fmt(verify, fmt_str, ...)			\
	_dp_test_netlink_add_route_fmt(verify, false, __FILE__, __func__, \
				       __LINE__, fmt_str, ##__VA_ARGS__)

#define dp_test_nl_add_route_incomplete_fmt(fmt_str, ...)		\
	_dp_test_netlink_add_route_fmt(false, true, __FILE__, __func__, \
				       __LINE__, fmt_str, ##__VA_ARGS__)

void _dp_test_netlink_replace_route(const char *route_string, bool verify,
				    bool incomplete,
				    const char *file, const char *func,
				    int line);
#define dp_test_netlink_replace_route(route_string)		  \
	_dp_test_netlink_replace_route(route_string, true, false, \
				   __FILE__, __func__, __LINE__)

void
_dp_test_netlink_replace_route_fmt(bool verify, bool incomplete,
				   const char *file, const char *func,
				   int line, const char *format, ...)
	__attribute__((__format__(printf, 6, 7)));

#define dp_test_nl_replace_route_fmt(verify, fmt_str, ...)		\
	_dp_test_netlink_replace_route_fmt(verify, __FILE__, __func__,	\
					   __LINE__, fmt_str,		\
					   ##__VA_ARGS__)

#define dp_test_netlink_del_route_nv(route_str)			\
	_dp_test_netlink_del_route(route_str, false,			\
				   __FILE__, __func__, __LINE__)

void
_dp_test_netlink_del_route_fmt(bool verify, const char *file,
			       const char *func,
			       int line, const char *format, ...)
	__attribute__((__format__(printf, 5, 6)));

#define dp_test_nl_del_route_fmt(verify, fmt_str, ...)			\
	_dp_test_netlink_del_route_fmt(verify, __FILE__, __func__,	\
				       __LINE__, fmt_str, ##__VA_ARGS__)

#define dp_test_nl_del_route_incomplete_fmt(fmt_str, ...)		\
	_dp_test_netlink_del_route_fmt(false, __FILE__, __func__,	\
				       __LINE__, fmt_str, ##__VA_ARGS__)

/* Verify route in a VRF */
void _dp_test_verify_add_route(const char *route_string, bool match_nh,
			       bool all, const char *file, const char *func,
			       int line);

#define dp_test_verify_add_route(route_string, match_nh)		\
	_dp_test_verify_add_route(route_string, match_nh, false,	\
				  __FILE__, __func__, __LINE__)

#define dp_test_verify_add_route_all(route_string, match_nh)		\
	_dp_test_verify_add_route(route_string, match_nh, true,		\
				  __FILE__, __func__, __LINE__)

void _dp_test_verify_del_route(const char *route_string, bool match_nh,
			       const char *file, const char *func, int line);

#define dp_test_verify_del_route(route_string, match_nh)		\
	_dp_test_verify_del_route(route_string, match_nh,		\
				  __FILE__, __func__, __LINE__)

void _dp_test_netlink_add_vrf_incmpl(uint32_t vrf_id,
				     uint32_t expected_ref_cnt,
				     const char *file, int line);
#define dp_test_netlink_add_vrf_incmpl(vrf_id, expected_ref_cnt)	\
	_dp_test_netlink_add_vrf_incmpl(vrf_id, expected_ref_cnt,	\
				 __FILE__, __LINE__)

#define dp_test_netlink_add_vrf_incmpl_fin(vrf_id, expected_ref_cnt)	\
	_dp_test_netlink_add_vrf(vrf_id, expected_ref_cnt,		\
				 __FILE__, __LINE__)

void _dp_test_netlink_create_bridge(const char *br_name,
				    bool verify,
				    const char *file, const char *func,
				    int line);
#define dp_test_netlink_create_bridge(br_name)			\
	_dp_test_netlink_create_bridge(br_name, true,			\
				       __FILE__, __func__, __LINE__)

void _dp_test_netlink_del_bridge(const char *br_name,
				 bool verify,
				 const char *file, const char *func,
				 int line);
#define dp_test_netlink_del_bridge(br_name)			\
	_dp_test_netlink_del_bridge(br_name, true,			\
				    __FILE__, __func__, __LINE__)

void _dp_test_netlink_add_bridge_port(const char *br_name,
				      const char *eth_name, bool verify,
				      const char *file, const char *func,
				      int line);
#define dp_test_netlink_add_bridge_port(br_name, eth_name)	\
	_dp_test_netlink_add_bridge_port(br_name, eth_name, true,	\
					 __FILE__, __func__, __LINE__)

void _dp_test_netlink_remove_bridge_port(const char *br_name,
					 const char *eth_name,
					 bool verify,
					 const char *file, const char *func,
					 int line);
#define dp_test_netlink_remove_bridge_port(br_name, eth_name)	\
	_dp_test_netlink_remove_bridge_port(br_name, eth_name, true,	\
					    __FILE__, __func__, __LINE__)

void _dp_test_netlink_set_bridge_vlan_filter(const char *br_name,
	bool verify, const char *file,
	const char *func, int line);
#define dp_test_netlink_set_bridge_vlan_filter(br_name)	\
	_dp_test_netlink_set_bridge_vlan_filter(br_name,	\
		true, __FILE__, __func__, __LINE__)

void _dp_test_netlink_bridge_port_set(const char *br_name,
	const char *eth_name, uint16_t pvid,
	struct bridge_vlan_set *vlans,
	struct bridge_vlan_set *untag_vlans,
	uint8_t state, bool verify,
	const char *file, const char *func,
	int line);
#define dp_test_netlink_bridge_port_set_vlans(br_name, eth_name, \
	pvid, vlans, untag_vlans) \
	_dp_test_netlink_bridge_port_set(br_name, eth_name, \
		pvid, vlans, untag_vlans, BR_STATE_FORWARDING, true, \
		__FILE__, __func__, __LINE__)

#define dp_test_netlink_bridge_port_set_vlans_state(br_name, eth_name, \
	pvid, vlans, untag_vlans, state) \
	_dp_test_netlink_bridge_port_set(br_name, eth_name, \
		pvid, vlans, untag_vlans, state, true, \
		__FILE__, __func__, __LINE__)

void _dp_test_netlink_create_vxlan(const char *vxlan_name, uint32_t vni,
				   const char *parent_name,
				   bool verify,
				   const char *file, const char *func,
				   int line);
#define dp_test_netlink_create_vxlan(vxlan_name, vni, parent_name) \
	_dp_test_netlink_create_vxlan(vxlan_name, vni, parent_name, true,\
				      __FILE__, __func__, __LINE__)

void _dp_test_netlink_del_vxlan(const char *vxlan_name, uint32_t vni,
				bool verify,
				const char *file, const char *func,
				int line);
#define dp_test_netlink_del_vxlan(vxlan_name, vni)	\
	_dp_test_netlink_del_vxlan(vxlan_name, vni, true,	\
				   __FILE__, __func__, __LINE__)

void
_dp_test_netlink_create_vif(const char *vif_name,
			    const char *parent_name,
			    uint16_t vlan,
			    uint16_t vlan_proto,
			    bool verify,
			    const char *file, const char *func,
			    int line);
#define dp_test_netlink_create_vif(vif_name, parent_name, vlan)	\
	_dp_test_netlink_create_vif(vif_name, parent_name, vlan, ETH_P_8021Q, \
				    true, __FILE__, __func__, __LINE__)

void _dp_test_netlink_del_vif(const char *vif_name, uint16_t vlan,
			      uint16_t vlan_proto, bool verify,
			      const char *file, const char *func,
			      int line);
#define dp_test_netlink_del_vif(vif_name, vlan)				\
	_dp_test_netlink_del_vif(vif_name, vlan, ETH_P_8021Q, true,	\
				 __FILE__, __func__, __LINE__)

void
_dp_test_netlink_create_macvlan(const char *vif_name,
				const char *parent_name,
				const char *mac_str,
				bool verify,
				const char *file, const char *func,
				int line);

void _dp_test_netlink_del_macvlan(const char *vif_name, bool verify,
				  const char *file, const char *func,
				  int line);

void dp_test_netlink_create_vti(const char *name,
				const char *local,
				const char *remote,
				uint16_t mark,
				vrfid_t vrf_id);
void dp_test_netlink_delete_vti(const char *name,
				const char *local,
				const char *remote,
				uint16_t mark,
				vrfid_t vrf_id);

void _dp_test_netlink_create_lo(const char *name, bool verify,
				const char *file, const char *func, int line);
#define dp_test_netlink_create_lo(name, verify)				\
	_dp_test_netlink_create_lo(name, verify, __FILE__, __func__, __LINE__)

void _dp_test_netlink_del_lo(const char *name, bool verify, const char *file,
			     const char *func, int line);
#define dp_test_netlink_del_lo(name, verify)				\
	_dp_test_netlink_del_lo(name, verify, __FILE__, __func__, __LINE__)

void _dp_test_netlink_create_lord(const char *name, vrfid_t vrf_id, bool verify,
				  const char *file, const char *func, int line);

void _dp_test_netlink_del_lord(const char *name, vrfid_t vrf_id, bool verify,
			       const char *file, const char *func, int line);
#define dp_test_netlink_create_lord(name, vrf_id, verify)		\
	_dp_test_netlink_create_lord(name, vrf_id, verify,		\
				     __FILE__, __func__, __LINE__)
#define dp_test_netlink_del_lord(name, vrf_id, verify)			\
	_dp_test_netlink_del_lord(name, vrf_id, verify,			\
				  __FILE__, __func__, __LINE__)

void _dp_test_netlink_create_vfp(const char *name, vrfid_t vrf_id, bool verify,
				 const char *file, const char *func, int line);

void _dp_test_netlink_del_vfp(const char *name, vrfid_t vrf_id, bool verify,
			      const char *file, const char *func, int line);
#define dp_test_netlink_create_vfp(name, vrf_id, verify)		\
	_dp_test_netlink_create_vfp(name, vrf_id, verify,		\
				    __FILE__, __func__, __LINE__)
#define dp_test_netlink_del_vfp(name, vrf_id, verify)			\
	_dp_test_netlink_del_vfp(name, vrf_id, verify,			\
				 __FILE__, __func__, __LINE__)

void
_dp_test_netlink_create_vrf_master(const char *name, vrfid_t vrf_id,
				   uint32_t tableid, bool verify,
				   const char *file, const char *func,
				   int line);
void
_dp_test_netlink_del_vrf_master(const char *name, vrfid_t vrf_id,
				uint32_t tableid, bool verify,
				const char *file, const char *func,
				int line);

void _dp_test_netlink_create_nondp(const char *name, const char *file,
				   const char *func, int line);
#define dp_test_netlink_create_nondp(name)			      \
	_dp_test_netlink_set_interface_l2(name, false, __FILE__,      \
					  __func__, __LINE__)
void _dp_test_netlink_del_nondp(const char *name, const char *file,
				const char *func, int line);
#define dp_test_netlink_del_nondp(name)					\
	_dp_test_netlink_del_interface_l2(name, false, __FILE__,        \
					  __func__, __LINE__)

void
_dp_test_netlink_set_proxy_arp(const char *ifname, bool enable,
			       const char *file, const char *func,
			       int line);
#define dp_test_netlink_set_proxy_arp(ifname, enable)	\
	_dp_test_netlink_set_proxy_arp(ifname, enable,  \
				       __FILE__, __func__, __LINE__)

void _dp_test_netlink_xfrm_policy(uint16_t nlmsg_type,
				  const struct xfrm_selector *sel,
				  const xfrm_address_t *dst,
				  int dst_family,
				  uint8_t dir,
				  uint32_t priority,
				  uint32_t reqid,
				  uint32_t mark_val,
				  uint8_t action,
				  vrfid_t vrfid,
				  bool passthrough,
				  const char *file,
				  int line);
#define dp_test_netlink_xfrm_policy(nlmsg_type, sel, dst, dst_family, dir,    \
				    priority, reqid, mark_val, action, vrfid, \
				    passthrough)			\
	_dp_test_netlink_xfrm_policy(nlmsg_type, sel, dst, dst_family, dir, \
				     priority, reqid, mark_val, action, \
				     vrfid, passthrough, __FILE__, __LINE__)

void _dp_test_netlink_xfrm_newsa(uint32_t spi, /* Network byte order */
				 const char *dst,
				 const char *src,
				 uint16_t family,
				 uint8_t mode,
				 uint32_t reqid,
				 const struct xfrm_algo *crypto_algo,
				 const struct xfrm_algo_auth *auth_algo,
				 const struct xfrm_algo_auth *auth_algo_trunc,
				 const struct xfrm_algo_aead *aead_algo,
				 /* optional args, not sent if NULL/0 */
				 uint32_t flags,
				 uint32_t extra_flags,
				 const struct xfrm_encap_tmpl *encap_tmpl,
				 uint32_t mark_val,
				 vrfid_t vrf,
				 const char *file,
				 const char *func,
				 int line);

#define dp_test_netlink_xfrm_newsa(spi, dst, src, family, mode, reqid,	\
				   crypto_algo, auth_algo, auth_algo_trunc, \
				   aead_algo, extra_flags, encap_tmpl,	\
				   mark_val, vrf)			\
	_dp_test_netlink_xfrm_newsa(spi, dst, src, family, mode, reqid,	\
				    crypto_algo, auth_algo, auth_algo_trunc, \
				    aead_algo, extra_flags, encap_tmpl,	\
				    mark_val,  __FILE__, __func__,	\
				    __LINE__)

void dp_test_netlink_xfrm_delsa(uint32_t spi, /* Network byte order */
				const char *dst,
				const char *src,
				uint16_t family,
				uint8_t mode,
				uint32_t reqid,
				vrfid_t vrfid);

void dp_test_netlink_xfrm_expire(uint32_t spi, /* Network byte order */
				 const char *dst,
				 const char *src,
				 uint16_t family,
				 uint8_t mode,
				 uint32_t reqid,
				 bool expire_hard,
				 vrfid_t vrfid);

#endif /* _DP_TEST_NETLINK_STATE_INTERNAL_H_ */
