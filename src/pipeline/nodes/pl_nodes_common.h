/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#ifndef PL_NODES_COMMON_H
#define PL_NODES_COMMON_H

#include "pl_common.h"

extern struct pl_node_registration *const ether_lookup_node_ptr;

extern struct pl_node_registration *const ipv4_drop_node_ptr;
extern struct pl_node_registration *const ipv4_validate_node_ptr;
extern struct pl_node_registration *const ipv4_out_node_ptr;
extern struct pl_node_registration *const ipv4_encap_node_ptr;
extern struct pl_node_registration *const ipv4_route_lookup_node_ptr;
extern struct pl_node_registration *const ipv4_l4_node_ptr;
extern struct pl_node_registration *const ipv4_udp_in_node_ptr;
extern struct pl_node_registration *const ipv4_out_spath_node_ptr;

extern struct pl_node_registration *const ipv6_drop_node_ptr;
extern struct pl_node_registration *const ipv6_l4_node_ptr;
extern struct pl_node_registration *const ipv6_validate_node_ptr;
extern struct pl_node_registration *const ipv6_out_node_ptr;
extern struct pl_node_registration *const ipv6_encap_node_ptr;
extern struct pl_node_registration *const ipv6_route_lookup_node_ptr;
extern struct pl_node_registration *const ipv6_udp_in_node_ptr;
extern struct pl_node_registration *const ipv6_out_spath_node_ptr;

extern struct pl_node_registration *const l2_consume_node_ptr;
extern struct pl_node_registration *const l2_local_node_ptr;
extern struct pl_node_registration *const l2_output_node_ptr;

extern struct pl_node_registration *const term_drop_node_ptr;

PL_DECLARE_FEATURE(ipv4_rpf_feat);
PL_DECLARE_FEATURE(ipv4_in_no_address_feat);
PL_DECLARE_FEATURE(ipv6_in_no_address_feat);
PL_DECLARE_FEATURE(ipv4_in_no_forwarding_feat);
PL_DECLARE_FEATURE(ipv6_in_no_forwarding_feat);
PL_DECLARE_FEATURE(ipv4_ipsec_out_feat);
PL_DECLARE_FEATURE(ipv6_ipsec_out_feat);
PL_DECLARE_FEATURE(sw_vlan_in_feat);
PL_DECLARE_FEATURE(capture_ether_in_feat);
PL_DECLARE_FEATURE(capture_l2_output_feat);
PL_DECLARE_FEATURE(portmonitor_in_feat);
PL_DECLARE_FEATURE(portmonitor_out_feat);
PL_DECLARE_FEATURE(bridge_in_feat);
PL_DECLARE_FEATURE(cross_connect_ether_feat);
PL_DECLARE_FEATURE(hw_hdr_in_feat);
PL_DECLARE_FEATURE(vlan_mod_in_feat);
PL_DECLARE_FEATURE(vlan_mod_out_feat);

PL_DECLARE_FEATURE(ipv4_defrag_in_feat);
PL_DECLARE_FEATURE(ipv4_defrag_out_feat);
PL_DECLARE_FEATURE(ipv6_defrag_in_feat);
PL_DECLARE_FEATURE(ipv6_defrag_out_feat);
PL_DECLARE_FEATURE(ipv4_defrag_out_spath_feat);
PL_DECLARE_FEATURE(ipv6_defrag_out_spath_feat);

PL_DECLARE_FEATURE(ipv4_dpi_in_feat);
PL_DECLARE_FEATURE(ipv6_dpi_in_feat);
PL_DECLARE_FEATURE(ipv4_dpi_out_feat);
PL_DECLARE_FEATURE(ipv6_dpi_out_feat);

PL_DECLARE_FEATURE(ipv4_acl_in_feat);
PL_DECLARE_FEATURE(ipv4_acl_out_feat);
PL_DECLARE_FEATURE(ipv6_acl_in_feat);
PL_DECLARE_FEATURE(ipv6_acl_out_feat);
PL_DECLARE_FEATURE(ipv4_acl_out_spath_feat);
PL_DECLARE_FEATURE(ipv6_acl_out_spath_feat);

PL_DECLARE_FEATURE(ipv4_fw_in_feat);
PL_DECLARE_FEATURE(ipv4_snat_feat);
PL_DECLARE_FEATURE(ipv6_fw_in_feat);
PL_DECLARE_FEATURE(ipv6_pre_fw_out_feat);
PL_DECLARE_FEATURE(ipv4_fw_orig_feat);
PL_DECLARE_FEATURE(ipv6_fw_orig_feat);
PL_DECLARE_FEATURE(ipv4_snat_spath_feat);
PL_DECLARE_FEATURE(ipv6_pre_fw_out_spath_feat);

PL_DECLARE_FEATURE(ipv4_pbr_feat);
PL_DECLARE_FEATURE(ipv6_pbr_feat);

PL_DECLARE_FEATURE(nptv6_in_feat);
PL_DECLARE_FEATURE(nptv6_out_feat);

PL_DECLARE_FEATURE(ipv4_cgnat_in_feat);
PL_DECLARE_FEATURE(ipv4_cgnat_out_feat);

PL_DECLARE_FEATURE(ipv4_nat46_in_feat);
PL_DECLARE_FEATURE(ipv6_nat64_in_feat);
PL_DECLARE_FEATURE(ipv6_nat46_out_feat);
PL_DECLARE_FEATURE(ipv4_nat64_out_feat);

#endif /* PL_NODES_COMMON_H */
