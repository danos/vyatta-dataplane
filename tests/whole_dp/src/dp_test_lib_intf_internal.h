/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane UT Interface helpers
 */

#ifndef _DP_TEST_LIB_INTF_INTERNAL_H_
#define _DP_TEST_LIB_INTF_INTERNAL_H_

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h> /* conflicts with linux/if_bridge.h */
#include <linux/if_bridge.h>

#include "if/bridge/bridge_port.h"
#include "if_var.h"

#include "dp_test/dp_test_lib_intf.h"

#include "dp_test_lib_internal.h"
#include "dp_test_json_utils.h"

/* Needs to match IF_PORT_ID_INVALID */
#define DP_TEST_INTF_INVALID_PORT_ID UCHAR_MAX

#define DP_TEST_INTF_NON_DP_PREAMBLE "nondp"
enum dp_test_intf_type_e {
	DP_TEST_INTF_TYPE_DP, /* Normal dataplane interface i.e dpT0 */
	DP_TEST_INTF_TYPE_BRIDGE,
	DP_TEST_INTF_TYPE_VXLAN,
	DP_TEST_INTF_TYPE_GRE,
	DP_TEST_INTF_TYPE_ERSPAN,
	DP_TEST_INTF_TYPE_VTI,
	DP_TEST_INTF_TYPE_NON_DP,
	DP_TEST_INTF_TYPE_LO,
	DP_TEST_INTF_TYPE_MACVLAN,
	DP_TEST_INTF_TYPE_VFP,
	DP_TEST_INTF_TYPE_SWITCH_PORT,
	DP_TEST_INTF_TYPE_PPP,
	DP_TEST_INTF_TYPE_ERROR, /* Oops, error */
};

enum dp_test_tun_encap_type_e {
	DP_TEST_TUN_ENCAP_TYPE_IP, /* Normal dataplane interface i.e dpT0 */
	DP_TEST_TUN_ENCAP_TYPE_BRIDGE,
	DP_TEST_TUN_ENCAP_TYPE_ERSPAN,
};

enum dp_test_intf_type_e dp_test_intf_type(const char *if_name);

void dp_test_intf_dpdk_init(void);
void dp_test_intf_init(void);
int dp_test_intf_virt_add(const char *if_name);
void dp_test_intf_virt_del(const char *if_name);

void dp_test_intf_create_default_set(json_object *intf_set);
void dp_test_reset_expected_ifconfig(void);
uint8_t dp_test_intf_count(void);
uint8_t dp_test_intf_count_local(void);
uint8_t dp_test_intf_clean_count(void);
uint16_t dp_test_intf2default_dpid(const char *if_name);

/* Get interface information */
enum dp_test_intf_loc_e dp_test_intf_loc(const char *if_name);
unsigned int dp_test_cont_src_ifindex(unsigned int ifindex);
uint8_t dp_test_intf_name2port(const char *if_name);
struct rte_ether_addr *dp_test_intf_name2mac(const char *if_name);

#define DP_TEST_INTF_STATE_BRIDGE 0x01
#define DP_TEST_INTF_STATE_PBR    0x02
void dp_test_intf_name_add_state(const char *if_name, uint8_t state);
void dp_test_intf_name_del_state(const char *if_name, uint8_t state);
void dp_test_intf_port2name(portid_t port_id, char *if_name);
int dp_test_intf_port2index(portid_t port_id);
void dp_test_intf_add_addr(const char *if_name, struct dp_test_addr *addr);
void dp_test_intf_del_addr(const char *if_name, struct dp_test_addr *addr);
void dp_test_intf_initial_stats_for_if(const char *ifname,
				       struct if_data *stats);
void dp_test_intf_delta_stats_for_if(const char *ifname,
				     const struct if_data *initial_stats,
				     struct if_data *stats);

void _dp_test_intf_bridge_enable_vlan_filter(const char *br_name,
					     const char *file, const char *func,
					     int line);
#define dp_test_intf_bridge_enable_vlan_filter(br_name) \
	_dp_test_intf_bridge_enable_vlan_filter(br_name, \
						__FILE__, __func__, __LINE__)

void _dp_test_intf_bridge_port_set(const char *br_name,
	const char *if_name, uint16_t pvid,
	struct bridge_vlan_set *vlans,
	struct bridge_vlan_set *untag_vlans,
	uint8_t state,
	const char *file, const char *func,
	int line);
#define dp_test_intf_bridge_port_set_vlans(br_name, if_name, pvid, vlans, \
					   untag_vlans) \
	_dp_test_intf_bridge_port_set(br_name, if_name, pvid, vlans, \
				      untag_vlans, BR_STATE_FORWARDING, \
				      __FILE__, __func__, __LINE__)
#define dp_test_intf_bridge_port_set_vlans_state( \
	br_name, if_name, pvid, vlans, untag_vlans, state)	     \
	_dp_test_intf_bridge_port_set(br_name, if_name, pvid, vlans, \
				      untag_vlans, state, \
				      __FILE__, __func__, __LINE__)

#define dp_test_intf_switch_create(switch_name) \
	_dp_test_intf_bridge_create(switch_name, \
				    __FILE__, __func__, __LINE__)

#define dp_test_intf_switch_del(switch_name)	  \
	_dp_test_intf_bridge_del(switch_name, \
				 __FILE__, __func__, __LINE__)

#define dp_test_intf_switch_add_port(switch_name, if_name)	\
	_dp_test_intf_bridge_add_port(switch_name, if_name, \
				      __FILE__, __func__, __LINE__)

#define dp_test_intf_switch_remove_port(switch_name, if_name) \
	_dp_test_intf_bridge_remove_port(switch_name, if_name, \
					 __FILE__, __func__, __LINE__)

void _dp_test_intf_vxlan_create(const char *vxlan_name, uint32_t vni,
				const char *parent_name,
				const char *file, const char *func,
				int line);
#define dp_test_intf_vxlan_create(vxlan_name, vni, parent_name) \
	_dp_test_intf_vxlan_create(vxlan_name, vni, parent_name, \
				   __FILE__, __func__, __LINE__)

void _dp_test_intf_vxlan_del(const char *vxlan_name, uint32_t vni,
			     const char *file, const char *func,
			     int line);
#define dp_test_intf_vxlan_del(vxlan_name, vni) \
	_dp_test_intf_vxlan_del(vxlan_name, vni, \
			       __FILE__, __func__, __LINE__)

void dp_test_intf_vif_create_incmpl(const char *vif_name,
				    const char *parent_name, uint16_t vlan);
void dp_test_intf_vif_create_incmpl_fin(const char *vif_name,
					const char *parent_name,
					uint16_t vlan);

void _dp_test_intf_macvlan_create(const char *if_name,
				  const char *parent_name,
				  const char *mac_str,
				  const char *file, const char *func,
				  int line);
#define dp_test_intf_macvlan_create(if_name, parent_name, mac_str)	\
	_dp_test_intf_macvlan_create(if_name, parent_name, mac_str,	\
				     __FILE__, __func__, __LINE__)

void _dp_test_intf_macvlan_del(const char *if_name, const char *file,
			       const char *func, int line);
#define dp_test_intf_macvlan_del(if_name)			\
	_dp_test_intf_macvlan_del(if_name, __FILE__, __func__,	\
				  __LINE__)

void dp_test_intf_gre_create(const char *gre_name,
			     const char *gre_local, const char *gre_remote,
			     uint32_t gre_key, uint32_t vrf_id);
void dp_test_intf_gre_l2_create(const char *gre_name,
			     const char *gre_local, const char *gre_remote,
			     uint32_t gre_key);
void dp_test_intf_gre_delete(const char *gre_name,
			     const char *gre_local, const char *gre_remote,
			     uint32_t gre_key, uint32_t vrf_id);
void dp_test_intf_gre_l2_delete(const char *gre_name,
				const char *gre_local, const char *gre_remote,
				uint32_t gre_key);
void dp_test_intf_erspan_create(const char *erspan_name,
				const char *erspan_local,
				const char *erspan_remote,
				uint32_t gre_key, bool gre_seq,
				uint32_t vrf_id);
void dp_test_intf_erspan_delete(const char *erspan_name,
				const char *erspan_local,
				const char *erspan_remote,
				uint32_t gre_key, bool gre_seq,
				uint32_t vrf_id);

void _dp_test_intf_loopback_create(const char *name,
				   const char *file, const char *func,
				   int line);
#define dp_test_intf_loopback_create(name) \
	_dp_test_intf_loopback_create(name, __FILE__, __func__, __LINE__)

void _dp_test_intf_loopback_delete(const char *name,
				   const char *file, const char *func,
				   int line);
#define dp_test_intf_loopback_delete(name) \
	_dp_test_intf_loopback_delete(name, __FILE__, __func__, __LINE__)

void dp_test_intf_nondp_create(const char *name);
void dp_test_intf_nondp_create_incmpl(const char *name);
void dp_test_intf_nondp_create_incmpl_fin(const char *name);
void dp_test_intf_nondp_delete(const char *name);

void dp_test_intf_ppp_create(const char *intf_name, uint32_t vrf_id);
void dp_test_intf_ppp_delete(const char *intf_name, uint32_t vrf_id);

uint8_t dp_test_intf_switch_port_count(void);
bool dp_test_intf_switch_port_over_bkp(const char *real_if_name);
void dp_test_intf_switch_port_activate(const char *real_if_name);
void dp_test_intf_switch_port_deactivate(const char *real_if_name);

void _dp_test_intf_vrf_if_create(const char *name, vrfid_t vrf_id,
				     uint32_t tableid, const char *file,
				     int line);
void _dp_test_intf_vrf_if_delete(const char *name, vrfid_t vrf_id,
				     uint32_t tableid, const char *file,
				     int line);

bool
dp_test_upstream_vrf_lookup_db(uint32_t vrf_id, char *vrf_name,
			       uint32_t *tableid);
bool
dp_test_upstream_vrf_add_db(uint32_t vrf_id, char *vrf_name, uint32_t *tableid);

void dp_test_pak_add_to_ring(const char *iif_name,
			     struct rte_mbuf **paks_to_send,
			     uint32_t num_paks,
			     bool wait_until_processed);

int dp_test_pak_get_from_ring(const char *if_name,
			      struct rte_mbuf **bufs,
			      int count);

#endif /* DP_TEST_LIB_INTF_INTERNAL_H */
