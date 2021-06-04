# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020-2021, AT&T Intellectual Property. All rights reserved.

pipeline_sources = files(
	'pl_commands.c',
	'pl_node.c',
	'pl_node_boot.c'
)

pipeline_node_sources = files(
	'nodes/l2_bridge_in.c',
	'nodes/l2_capture.c',
	'nodes/cross_connect/l2_cross_connect_node.c',
	'nodes/cross_connect/l2_cross_connect_cmd.c',
	'nodes/cross_connect/cross_connect.c',
	'nodes/ipv4_drop.c',
	'nodes/ipv6_drop.c',
	'nodes/l2_consume.c',
	'nodes/l2_ether_in.c',
	'nodes/l2_ether_forward.c',
	'nodes/l2_ether_lookup.c',
	'nodes/l2_hw_hdr.c',
	'nodes/l2_local.c',
	'nodes/l2_output.c',
	'nodes/l2_portmonitor.c',
	'nodes/l2_portmonitor_hw.c',
	'nodes/l2_vlan_mod.c',
	'nodes/pppoe/l2_pppoe_node.c',
	'nodes/pppoe/l2_pppoe_cmd.c',
	'nodes/pppoe/pppoe.c',
	'nodes/l2_sw_vlan.c',
	'nodes/l3_acl.c',
	'nodes/l3_arp.c',
	'nodes/l3_dpi.c',
	'nodes/l3_fw_in.c',
	'nodes/fw_out_snat/npf_shim_out.c',
	'nodes/l3_fw_out.c',
	'nodes/l3_nat64.c',
	'nodes/l3_pbr.c',
	'nodes/l3_tcp_mss.c',
	'nodes/l3_v4_cgnat.c',
	'nodes/l3_v4_defrag.c',
	'nodes/l3_v4_encap.c',
	'nodes/l3_v4_gre.c',
	'nodes/l3_v4_ipsec.c',
	'nodes/l3_v4_l2tpv3.c',
	'nodes/l3_v4_l4.c',
	'nodes/l3_v4_no_address.c',
	'nodes/l3_v4_no_forwarding.c',
	'nodes/l3_v4_out.c',
	'nodes/l3_v4_out_spath.c',
	'nodes/l3_v4_post_route_lookup.c',
	'nodes/l3_v4_route_lookup.c',
	'nodes/l3_v4_rpf.c',
	'nodes/l3_v4_udp.c',
	'nodes/l3_v4_val.c',
	'nodes/l3_v6_defrag.c',
	'nodes/l3_v6_encap.c',
	'nodes/l3_v6_ipsec.c',
	'nodes/l3_v6_l4.c',
	'nodes/l3_v6_no_address.c',
	'nodes/l3_v6_no_forwarding.c',
	'nodes/l3_v6_out.c',
	'nodes/l3_v6_out_spath.c',
	'nodes/l3_v6_post_route_lookup.c',
	'nodes/l3_v6_route_lookup.c',
	'nodes/l3_v6_udp.c',
	'nodes/l3_v6_val.c',
	'nodes/l3_v6_nptv6.c',
	'nodes/term.c',
	'nodes/term_drop.c'
)

pl_gen_fused_opts = [
	'--include', 'pl_fused_gen.h',
	'--include', 'nodes/pl_nodes_common.h',
	'--include', 'pl_fused.h',
	'--entry', 'vyatta:ether-forward',
	'--entry', 'vyatta:ether-in',
	'--entry', 'vyatta:arp-in-nothot',
	'--entry', 'vyatta:ipv4-validate',
	'--entry', 'vyatta:ipv6-validate',
	'--entry', 'vyatta:ipv4-route-lookup',
	'--entry', 'vyatta:ipv4-out',
	'--entry', 'vyatta:ipv6-out',
	'--entry', 'vyatta:ipv4-out-spath',
	'--entry', 'vyatta:ipv6-out-spath',
	'--entry', 'vyatta:ipv6-defrag-out-spath',
	'--entry', 'vyatta:ipv4-encap',
	'--entry', 'vyatta:ipv6-encap',
	'--entry', 'vyatta:ipv4-encap-only',
	'--entry', 'vyatta:ipv6-encap-only',
	'--entry', 'vyatta:ipv4-l4',
	'--entry', 'vyatta:ipv6-l4',
	'--entry', 'vyatta:l2-consume',
	'--entry', 'vyatta:l2-local',
	'--entry', 'vyatta:l2-output',
	'--entry', 'vyatta:term-drop',
	'--entry', 'vyatta:ipv4-drop',
	'--entry', 'vyatta:ipv6-drop',
	'--feature-point', 'vyatta:ether-lookup',
	'--feature-point', 'vyatta:ipv4-drop',
	'--feature-point', 'vyatta:ipv4-l4',
	'--feature-point', 'vyatta:ipv4-validate',
	'--feature-point', 'vyatta:ipv4-route-lookup',
	'--feature-point', 'vyatta:ipv4-out',
	'--feature-point', 'vyatta:ipv4-out-spath',
	'--feature-point', 'vyatta:ipv4-encap',
	'--feature-point', 'vyatta:ipv4-udp-in',
	'--feature-point', 'vyatta:ipv6-drop',
	'--feature-point', 'vyatta:ipv6-l4',
	'--feature-point', 'vyatta:ipv6-validate',
	'--feature-point', 'vyatta:ipv6-route-lookup',
	'--feature-point', 'vyatta:ipv6-out',
	'--feature-point', 'vyatta:ipv6-out-spath',
	'--feature-point', 'vyatta:ipv6-encap',
	'--feature-point', 'vyatta:ipv6-udp-in',
	'--feature-point', 'vyatta:l2-consume',
	'--feature-point', 'vyatta:l2-local',
	'--feature-point', 'vyatta:l2-output',
 	'--feature-point', 'vyatta:term-drop'
]

pl_gen_fused = files('../../scripts/pl_gen_fused')

pl_fused_gen_h = custom_target('pl_fused_gen.h',
        output: 'pl_fused_gen.h',
        input: pipeline_node_sources,
        command: [pl_gen_fused,  pl_gen_fused_opts, '--header-out', '@OUTPUT@', '@INPUT@']
)

pl_fused_gen_c = custom_target('pl_fused_gen.c',
        output: 'pl_fused_gen.c',
        input: pipeline_node_sources,
        command: [pl_gen_fused,  pl_gen_fused_opts, '--impl-out', '@OUTPUT@', '@INPUT@'],
        depends: pl_fused_gen_h
)

pipeline_inc = include_directories('.')

# TODO: Consider making a static_library
# pipeline_lib = static_library('pipeline',
# 	sources: [
# 		pl_fused_gen_c,
# 		pipeline_sources,
# 		pipeline_node_sources
# 	],
# 	include_directories: [public_include, internal_inc],
# 	dependencies: [
# 		dpdk_dep
# 	]
# )

pipeline_dep = declare_dependency(
        include_directories: pipeline_inc,
        sources: [pl_fused_gen_h],
	# link_with: pipeline_lib
)
