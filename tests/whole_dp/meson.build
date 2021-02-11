# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020-2021, AT&T Intellectual Property. All rights reserved.

internal_test_inc = include_directories(
        'src'
)

test_lib_sources = files(
        'src/dp_test.c',
        'src/dp_test_cmd_check.c',
        'src/dp_test_cmd_state.c',
        'src/dp_test_console.c',
        'src/dp_test_controller.c',
        'src/dp_test_cpp_lim.c',
        'src/dp_test_crypto_lib.c',
        'src/dp_test_crypto_utils.c',
        'src/dp_test_json_utils.c',
        'src/dp_test_lib.c',
        'src/dp_test_lib_exp.c',
        'src/dp_test_lib_intf.c',
        'src/dp_test_lib_pb.c',
        'src/dp_test_lib_pkt.c',
        'src/dp_test_lib_portmonitor.c',
        'src/dp_test_lib_tcp.c',
        'src/dp_test_netlink_state.c',
        'src/dp_test_npf_alg_lib.c',
        'src/dp_test_npf_alg_sip_data.c',
        'src/dp_test_npf_alg_sip_data1.c',
        'src/dp_test_npf_alg_sip_data2.c',
        'src/dp_test_npf_alg_sip_data3.c',
        'src/dp_test_npf_alg_sip_data4.c',
        'src/dp_test_npf_fw_lib.c',
        'src/dp_test_npf_lib.c',
        'src/dp_test_npf_nat_lib.c',
        'src/dp_test_npf_portmap_lib.c',
        'src/dp_test_npf_sess_lib.c',
        'src/dp_test_pktmbuf_lib.c',
        'src/dp_test_qos_lib.c',
        'src/dp_test_route_broker.c',
        'src/dp_test_session_internal_lib.c',
        'src/dp_test_session_lib.c',
        'src/dp_test_str.c',
        'src/dp_test_stubs.c',
        'src/dp_test_stubs_linux.c',
        'src/dp_test_wrapped_funcs.c',
        'src/dp_test_xfrm_server.c',
)

# Only files that declare a CK test suite (using DP_DECL_TEST_SUITE())
# These will be iterated over using CK_RUN_SUITE for testing
# Everything else belongs in test_lib_sources above
check_tests = [
        'dp_test_arp.c',
        'dp_test_bitmask.c',
        'dp_test_bridge.c',
        'dp_test_bridge_n.c',
        'dp_test_bridge_vlan_filter.c',
        'dp_test_cpp_lim_fal.c',
        'dp_test_cross_connect.c',
        'dp_test_crypto_block_policy.c',
        'dp_test_crypto_multi_tunnel.c',
        'dp_test_crypto_perf_scale.c',
        'dp_test_crypto_policy.c',
        'dp_test_crypto_site_to_site.c',
        'dp_test_crypto_site_to_site_passthru.c',
        'dp_test_esp.c',
        'dp_test_fails.c',
        'dp_test_gpc_pb.c',
        'dp_test_gre.c',
        'dp_test_gre6.c',
        'dp_test_if_config.c',
        'dp_test_intf_incomplete.c',
        'dp_test_ip.c',
        'dp_test_ip6.c',
        'dp_test_ip6_icmp.c',
        'dp_test_ip6_neigh.c',
        'dp_test_ip_arp.c',
        'dp_test_ip_icmp.c',
        'dp_test_ip_multicast.c',
        'dp_test_ip_n.c',
        'dp_test_ip_pic_edge.c',
        'dp_test_mac_limit.c',
        'dp_test_mpls.c',
        'dp_test_mstp_cmds.c',
        'dp_test_mstp_fwd.c',
        'dp_test_nat.c',
        'dp_test_npf_acl.c',
        'dp_test_npf_addrgrp.c',
        'dp_test_npf_alg_ftp.c',
        'dp_test_npf_alg_sip.c',
        'dp_test_npf_alg_rpc.c',
        'dp_test_npf_alg_tftp.c',
        'dp_test_npf_bridge.c',
        'dp_test_npf_cgnat.c',
        'dp_test_npf_commands.c',
        'dp_test_npf_defrag.c',
        'dp_test_npf_dscp.c',
        'dp_test_npf_feat.c',
        'dp_test_npf_fw.c',
        'dp_test_npf_fw_ipv6.c',
        'dp_test_npf_golden.c',
        'dp_test_npf_hairpin.c',
        'dp_test_npf_icmp.c',
        'dp_test_npf_local.c',
        'dp_test_npf_mbuf.c',
        'dp_test_npf_nat.c',
        'dp_test_npf_nat64.c',
        'dp_test_npf_nptv6.c',
        'dp_test_npf_prot_group.c',
        'dp_test_npf_ptree.c',
        'dp_test_npf_qos.c',
        'dp_test_npf_rldb.c',
        'dp_test_npf_ruleset_state.c',
        'dp_test_npf_session_limit.c',
        'dp_test_npf_snat_overrun.c',
        'dp_test_npf_tblset.c',
        'dp_test_npf_tcp.c',
        'dp_test_npf_vti.c',
        'dp_test_npf_zone.c',
        'dp_test_pbr.c',
        'dp_test_poe_cmds.c',
        'dp_test_portmonitor.c',
        'dp_test_portmonitor_commands.c',
        'dp_test_ppp.c',
        'dp_test_ptp.c',
        'dp_test_qos_basic.c',
        'dp_test_qos_burst.c',
        'dp_test_qos_class.c',
        'dp_test_qos_ext_buf_monitor.c',
        'dp_test_qos_fal.c',
        'dp_test_route_tracker.c',
        'dp_test_session.c',
        'dp_test_session_cmds.c',
        'dp_test_sfp.c',
        'dp_test_slow_path.c',
        'dp_test_storm_ctl.c',
        'dp_test_switch.c',
        'dp_test_switch_vlan.c',
        'dp_test_tcp_mss_clamp.c',
        'dp_test_vrf.c',
        'dp_test_vti.c',
        'dp_test_vxlan.c',
        'dp_test_xfrm.c',
]

check_test_sources = []
foreach test : check_tests
        check_test_sources += files('src' / test)
endforeach

if get_option('all_tests')
  dataplane_test_full_run = ['-DDP_TEST_FULL_RUN']
  test_timeout = 600
else
  dataplane_test_full_run = []
  test_timeout = 120
endif

dataplane_test = executable(
        'dataplane_test',
        sources: [
                check_test_sources,
                dataplane_common_sources,
                test_lib_sources
        ],
        dependencies: [
                check_dep,
                dataplane_deps,
                json_dep,
                rte_net_ring_dep,
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

if get_option('b_sanitize') == 'address'
        dataplane_test_env=['ASAN_OPTIONS=verify_asan_link_order=0:detect_leaks=0']
else
        dataplane_test_env = []
endif

lcore_number = 0
cores_available = run_command('nproc').stdout().to_int()

foreach suite : check_tests + ['dp_test_pipeline.c']

        suite_env = ['CK_RUN_SUITE=@0@'.format(suite), 'CK_XML_LOG_FILE_NAME=test_@0@.xml'.format(suite)] + dataplane_test_env

        test(suite, dataplane_test,
                depends: [sample_plugin, sample_test_plugin, fal_test_plugin, dummyfs],
                workdir: meson.current_build_dir(),
                args: ['-l @0@'.format(lcore_number), '-d1', '-F', meson.build_root() / 'src/pipeline/nodes/sample', '-P', meson.current_build_dir()],
                env: suite_env,
                timeout: test_timeout
        )

        lcore_number += 1
        if (lcore_number >= cores_available)
                lcore_number = 0
	endif

endforeach

valgrind = find_program('valgrind', required: false)
if valgrind.found()
        add_test_setup('valgrind',
                exe_wrapper : [valgrind,
                        '--error-exitcode=1', '--tool=memcheck', '--leak-check=full', '--show-reachable=no',
                        '--suppressions=@0@'.format(meson.current_source_dir() / 'valgrind_suppressions')
                ],
                timeout_multiplier : 100)
endif
