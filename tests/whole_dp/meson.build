# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.

internal_test_inc = include_directories(
        'src'
)

test_sources = files(
        'src/dp_test_pktmbuf_lib.c',
        'src/dp_test_crypto_lib.c',
        'src/dp_test.c',
        'src/dp_test_arp.c',
        'src/dp_test_bitmask.c',
        'src/dp_test_bridge.c',
        'src/dp_test_bridge_vlan_filter.c',
        'src/dp_test_bridge_n.c',
        'src/dp_test_cmd_check.c',
        'src/dp_test_cmd_state.c',
        'src/dp_test_console.c',
        'src/dp_test_controller.c',
        'src/dp_test_cpp_lim.c',
        'src/dp_test_cpp_lim_fal.c',
        'src/dp_test_cross_connect.c',
        'src/dp_test_crypto_block_policy.c',
        'src/dp_test_crypto_multi_tunnel.c',
        'src/dp_test_crypto_perf_scale.c',
        'src/dp_test_crypto_policy.c',
        'src/dp_test_crypto_site_to_site.c',
        'src/dp_test_crypto_site_to_site_passthru.c',
        'src/dp_test_crypto_utils.c',
        'src/dp_test_esp.c',
        'src/dp_test_fails.c',
        'src/dp_test_gre.c',
        'src/dp_test_gre6.c',
        'src/dp_test_if_config.c',
        'src/dp_test_intf_incomplete.c',
        'src/dp_test_ip.c',
        'src/dp_test_ip_arp.c',
        'src/dp_test_ip_n.c',
        'src/dp_test_ip_pic_edge.c',
        'src/dp_test_ip6.c',
        'src/dp_test_ip6_icmp.c',
        'src/dp_test_ip6_neigh.c',
        'src/dp_test_ip_icmp.c',
        'src/dp_test_ip_multicast.c',
        'src/dp_test_json_utils.c',
        'src/dp_test_lib.c',
        'src/dp_test_lib_exp.c',
        'src/dp_test_lib_intf.c',
        'src/dp_test_lib_pb.c',
        'src/dp_test_lib_pkt.c',
        'src/dp_test_lib_portmonitor.c',
        'src/dp_test_lib_tcp.c',
        'src/dp_test_mac_limit.c',
        'src/dp_test_mpls.c',
        'src/dp_test_mstp_cmds.c',
        'src/dp_test_mstp_fwd.c',
        'src/dp_test_nat.c',
        'src/dp_test_netlink_state.c',
        'src/dp_test_npf_acl.c',
        'src/dp_test_npf_commands.c',
        'src/dp_test_npf_feat.c',
        'src/dp_test_npf_defrag.c',
        'src/dp_test_npf_golden.c',
        'src/dp_test_npf_bridge.c',
        'src/dp_test_npf_cgnat.c',
        'src/dp_test_npf_dscp.c',
        'src/dp_test_npf_tblset.c',
        'src/dp_test_npf_addrgrp.c',
        'src/dp_test_npf_fw.c',
        'src/dp_test_npf_fw_ipv6.c',
        'src/dp_test_npf_fw_lib.c',
        'src/dp_test_npf_hairpin.c',
        'src/dp_test_npf_icmp.c',
        'src/dp_test_npf_lib.c',
        'src/dp_test_npf_local.c',
        'src/dp_test_npf_mbuf.c',
        'src/dp_test_npf_ptree.c',
        'src/dp_test_npf_nat.c',
        'src/dp_test_npf_nat64.c',
        'src/dp_test_npf_nat_lib.c',
        'src/dp_test_npf_nptv6.c',
        'src/dp_test_npf_alg_lib.c',
        'src/dp_test_npf_alg_sip_call.c',
        'src/dp_test_npf_alg_sip_lib.c',
        'src/dp_test_npf_alg_sip_parse.c',
        'src/dp_test_npf_alg_ftp.c',
        'src/dp_test_npf_alg_tftp.c',
        'src/dp_test_npf_alg_rpc.c',
        'src/dp_test_npf_alg_sip_1.c',
        'src/dp_test_npf_alg_sip_2.c',
        'src/dp_test_npf_alg_sip_3.c',
        'src/dp_test_npf_alg_sip_4.c',
        'src/dp_test_npf_qos.c',
        'src/dp_test_npf_portmap_lib.c',
        'src/dp_test_npf_prot_group.c',
        'src/dp_test_npf_ruleset_state.c',
        'src/dp_test_npf_sess_lib.c',
        'src/dp_test_npf_session_limit.c',
        'src/dp_test_npf_snat_overrun.c',
        'src/dp_test_npf_tcp.c',
        'src/dp_test_npf_vti.c',
        'src/dp_test_npf_zone.c',
        'src/dp_test_pbr.c',
        'src/dp_test_poe_cmds.c',
        'src/dp_test_portmonitor_commands.c',
        'src/dp_test_portmonitor.c',
        'src/dp_test_ppp.c',
        'src/dp_test_ptp.c',
        'src/dp_test_qos_basic.c',
        'src/dp_test_qos_burst.c',
        'src/dp_test_qos_ext_buf_monitor.c',
        'src/dp_test_qos_fal.c',
        'src/dp_test_qos_class.c',
        'src/dp_test_qos_lib.c',
        'src/dp_test_route_broker.c',
        'src/dp_test_route_tracker.c',
        'src/dp_test_slow_path.c',
        'src/dp_test_session_internal_lib.c',
        'src/dp_test_session_lib.c',
        'src/dp_test_session.c',
        'src/dp_test_session_cmds.c',
        'src/dp_test_sfp.c',
        'src/dp_test_storm_ctl.c',
        'src/dp_test_str.c',
        'src/dp_test_stubs.c',
        'src/dp_test_stubs_linux.c',
        'src/dp_test_switch.c',
        'src/dp_test_switch_vlan.c',
        'src/dp_test_tcp_mss_clamp.c',
        'src/dp_test_vrf.c',
        'src/dp_test_vti.c',
        'src/dp_test_vxlan.c',
        'src/dp_test_wrapped_funcs.c',
        'src/dp_test_xfrm.c'
)

if get_option('all_tests')
  dataplane_test_full_run = ['-DDP_TEST_FULL_RUN']
else
  dataplane_test_full_run = []
endif

dataplane_test = executable(
        'dataplane_test',
        sources: [
                dataplane_common_sources,
                test_sources
        ],
        dependencies: [
                check_dep,
                dataplane_deps,
                json_dep,
                rte_pmd_ring_dep,
        ],
        include_directories: [
                public_include,
                internal_inc,
                public_test_include,
                internal_test_inc
        ],
        override_options: [
                'optimization=0',
                'b_lto=false'
        ],
        c_args: [
                dataplane_test_full_run,
                '-DFUSED_MODE',
                '-U_FILE_OFFSET_BITS', # dp_test_stubs_linux.c does not like this
                cc.get_supported_arguments([
                        '-Wno-unused-parameter',
                        '-Wno-format-overflow'
                ])
        ],
        link_args : [
                '-Wl,-wrap,main',
                '-Wl,-wrap,RAND_bytes',
                '-Wl,-wrap,rte_pktmbuf_pool_create',
                '-Wl,-wrap,rte_mempool_create',
                '-Wl,-wrap,rte_eal_init',
                '-Wl,-wrap,popen',
                '-Wl,-wrap,pclose'
        ],
        link_with: [jsonw_library],
        export_dynamic: true,
        install: true,
        install_dir: get_option('prefix') / get_option('bindir')
)

sample_test_plugin_sources = files(
        'src/dp_test_pipeline.c',
)

sample_test_plugin = shared_module('sample_test',
        sources: [sample_test_plugin_sources, sample_generated_protobuf_c],
        include_directories: [public_include, public_test_include],
        dependencies: [dpdk_dep, protobuf_generated_c_dependency]
)

fal_test_plugin_sources = files(
        'src/fal_plugin_test.c',
        'src/fal_plugin_sw_port.c',
        'src/fal_plugin_framer.c',
        'src/fal_plugin_qos.c',
        'src/fal_plugin_pm.c',
        'src/fal_plugin_policer.c',
        'src/fal_plugin_cpp_limiter.c',
        'src/fal_plugin_ptp.c'
)

fal_test_plugin = shared_module('fal_plugin_test',
        sources: [fal_test_plugin_sources],
        dependencies: [
                check_dep,
                dpdk_dep,
                json_dep,
                pipeline_dep,
                protobuf_generated_c_dependency,
                swport_dep,
        ],
        include_directories: [public_include, internal_inc],
        override_options: [
                'optimization=0',
                'b_lto=false'
        ],
        c_args: [
                '-Wno-unused-parameter'
        ],
        gnu_symbol_visibility: 'hidden',
        name_prefix: '',
        install: true,
        install_dir: get_option('prefix') / get_option('libdir') / meson.project_name()
)

test_driver_config = configure_file(
        input: '../../dataplane-drivers-default.conf',
        output: 'dataplane-drivers-default.conf',
        copy: true)

dummyfs = custom_target('dummyfs',
        command: ['ln', '-s',
                meson.source_root() / 'tests/whole_dp/dummyfs',
                meson.current_build_dir() / 'dummyfs'],
        output: 'dummyfs'
)

dataplane_test_env = environment()
if get_option('b_sanitize') == 'address'
        dataplane_test_env.set('ASAN_OPTIONS', 'verify_asan_link_order=0:detect_leaks=0')
endif

test('dataplane_test', dataplane_test,
        depends: [sample_plugin, sample_test_plugin, fal_test_plugin, dummyfs],
        workdir: meson.current_build_dir(),
        args: ['-d2', '-F', meson.build_root() / 'src/pipeline/nodes/sample', '-P', meson.current_build_dir()],
        env: dataplane_test_env,
        timeout: 600 # 10 minutes
)

