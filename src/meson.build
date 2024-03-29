# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020-2021, AT&T Intellectual Property. All rights reserved.

jsonw_library = shared_library(
        'vyatta-jsonw',
        sources: ['json_writer.c'],
        include_directories: public_include,
        install: true,
        version: '1.0.0'
)

internal_inc = include_directories(
        '.',
        'npf',
        'netinet6',
        'pipeline'
)

crypto_sources = files(
        'crypto/crypto.c',
        'crypto/crypto_engine.c',
        'crypto/crypto_policy.c',
        'crypto/crypto_rte_pmd.c',
        'crypto/crypto_sadb.c',
        'crypto/esp.c',
        'crypto/vti.c',
        'crypto/xfrm_client.c',
        'crypto/crypto_pmd.c'
)

ipv6_sources = files(
        'netinet6/in6.c',
        'netinet6/ip6_commands.c',
        'netinet6/ip6_forward.c',
        'netinet6/ip6_icmp.c',
        'netinet6/ip6_main.c',
        'netinet6/ip6_mroute.c',
        'netinet6/ip6_options.c',
        'netinet6/nd6_nbr.c',
        'netinet6/route_v6.c',
        'netinet6/scope6.c'
)

mpls_sources = files(
        'mpls/mpls_commands.c',
        'mpls/mpls_forward.c',
        'mpls/mpls_label_table.c',
        'mpls/mpls_netlink.c'
)

session_sources = files(
        'session/session.c',
        'session/session_cmds.c',
        'session/session_feature.c',
        'session/session_op.c',
        'session/session_pack_pb.c',
        'session/session_watch.c'
)

core_sources = files(
        'arp.c',
        'backplane.c',
        'bpf_filter.c',
        'bridge_vlan_set.c',
        'commands.c',
        'protobuf.c',
        'protobuf_util.c',
        'config.c',
        'control.c',
        'cpp_rate_limiter.c',
        'dealer.c',
        'debug.c',
        'dp_control_thread.c',
        'dp_event.c',
        'ecmp.c',
        'ether.c',
        'event.c',
        'fal.c',
        'feature_plugin.c',
        'flow_cache.c',
        'if/bridge/bridge.c',
        'if/bridge/bridge_netlink.c',
        'if/bridge/bridge_port.c',
        'if/bridge/switch.c',
        'if/dpdk-eth/hotplug.c',
        'if/dpdk-eth/devinfo.c',
        'if/dpdk-eth/dpdk_eth_if.c',
        'if/dpdk-eth/dpdk_eth_linkwatch.c',
        'if/dpdk-eth/dpdk_lag.c',
        'if/dpdk-eth/fal_lag.c',
        'if/dpdk-eth/vhost.c',
        'if/gre.c',
        'if/ipip_tunnel.c',
        'if/loopback.c',
        'if/macvlan.c',
        'if/vlan/vlan_if.c',
        'if/vlan/vlan_if_netlink.c',
        'if/vxlan.c',
        'if.c',
        'if_ether.c',
        'if_feat.c',
        'if_llatbl.c',
        'in.c',
        'in_cksum.c',
        'ip_forward.c',
        'ip_commands.c',
        'ip_icmp.c',
        'ip_mcast.c',
        'ip_mcast_fal_interface.c',
        'ip_netlink.c',
        'ip_nud_ulr.c',
        'ip_options.c',
        'ip_output.c',
        'ip_route.c',
        'ip_rt_protobuf.c',
        'iptun_common.c',
        'l2_rx_fltr.c',
        'l2tp/l2tpeth_decap.c',
        'l2tp/l2tpeth_dp.c',
        'l2tp/l2tpeth_netlink.c',
        'lag.c',
        'lcore_sched.c',
        'log.c',
        'lpm/lpm.c',
        'lpm/lpm6.c',
        'mac_limit.c',
        'main.c',
        'controller.c',
        'mstp.c',
        'netinet/ip_mroute.c',
        'netlink.c',
        'nh_common.c',
        'nsh.c',
        'pd_show.c',
        'pktmbuf.c',
        'pathmonitor/pathmonitor_cmds.c',
        'portmonitor/portmonitor_cmds.c',
        'portmonitor/portmonitor_dp.c',
        'power.c',
        'ptp.c',
        'qos_sched.c',
        'qos_dpdk.c',
        'qos_ext_buf_monitor.c',
        'qos_hw.c',
        'qos_hw_show.c',
        'qos_obj_db.c',
        'rcu.c',
        'route.c',
        'route_broker.c',
        'rt_commands.c',
        'rt_tracker.c',
        'storm_ctl.c',
        'sfp.c',
        'sfp_permit_list.c',
        'switchport.c',
        'udp_handler.c',
        'util.c',
        'vlan_modify.c',
        'vrf.c',
        'shadow.c',
        'zmq_dp.c'
)

not_for_test_sources = files(
        'capture.c',
        'ip_id.c',
        'team.c',
        'shadow_receive.c'
)

gpc_sources = files(
        'gpc/gpc_op_mode.c',
        'gpc/gpc_pb_config.c',
        'gpc/gpc_util.c'
)

twamp_sources = files(
        'twamp_ctrl.c',
        'twamp_io.c',
)

npf_sources = files(
        'npf/alg/alg_apt.c',
        'npf/apm/apm.c',
        'npf/alg/alg.c',
        'npf/alg/alg_npf.c',
        'npf/alg/alg_session.c',
        'npf/alg/alg_ftp.c',
        'npf/alg/alg_tftp.c',
        'npf/alg/alg_rpc.c',
        'npf/alg/alg_sip.c',
        'npf/alg/sip/sip_request.c',
        'npf/alg/sip/sip_response.c',
        'npf/alg/sip/sip_parse.c',
        'npf/alg/sip/sip_translate.c',
        'npf/cgnat/cgn.c',
        'npf/cgnat/cgn_cmd_cfg.c',
        'npf/cgnat/cgn_cmd_op.c',
        'npf/cgnat/cgn_if.c',
        'npf/cgnat/cgn_log.c',
        'npf/cgnat/cgn_log_rte.c',
        'npf/cgnat/cgn_log_protobuf_zmq.c',
        'npf/cgnat/cgn_map.c',
        'npf/cgnat/cgn_mbuf.c',
        'npf/cgnat/cgn_policy.c',
        'npf/cgnat/cgn_rc.c',
        'npf/cgnat/cgn_session.c',
        'npf/cgnat/cgn_sess2.c',
        'npf/cgnat/cgn_sess_state.c',
        'npf/cgnat/cgn_source.c',
        'npf/cgnat/cgn_test.c',
        'npf/cgnat/alg/alg.c',
        'npf/cgnat/alg/alg_pinhole.c',
        'npf/cgnat/alg/alg_pptp.c',
        'npf/cgnat/alg/alg_rc.c',
        'npf/cgnat/alg/alg_session.c',
        'npf/cgnat/alg/sip/csip_parse_sdp.c',
        'npf/cgnat/alg/sip/csip_parse_sip.c',
        'npf/cgnat/alg/sip/csip_parse_utils.c',
        'npf/cgnat/alg/sip/csip_request.c',
        'npf/cgnat/alg/sip/csip_response.c',
        'npf/config/gpc_acl_cli.c',
        'npf/config/gpc_cntr.c',
        'npf/config/gpc_db.c',
        'npf/config/gpc_hw.c',
        'npf/config/npf_attach_point.c',
        'npf/config/npf_auto_attach.c',
        'npf/config/npf_config.c',
        'npf/config/npf_config_state.c',
        'npf/config/npf_dump.c',
        'npf/config/npf_gen_ruleset.c',
        'npf/config/npf_rule_group.c',
        'npf/config/npf_ruleset_type.c',
        'npf/config/pmf_rule.c',
        'npf/config/pmf_parse.c',
        'npf/config/pmf_dump.c',
        'npf/config/pmf_att_rlgrp.c',
        'npf/fragment/ipv4_frag_tbl.c',
        'npf/fragment/ipv4_rsmbl.c',
        'npf/fragment/ipv6_rsmbl.c',
        'npf/fragment/ipv6_rsmbl_tbl.c',
        'npf/nat/nat_cmd_cfg.c',
        'npf/nat/nat_cmd_op.c',
        'npf/nat/nat_pool.c',
        'npf/nat/nat_pool_event.c',
        'npf/bstr.c',
        'npf/grouper2.c',
        'npf/npf_nat64.c',
        'npf/npf_addrgrp.c',
        'npf/npf_apm.c',
        'npf/npf_cache.c',
        'npf/npf_cidr_util.c',
        'npf/npf_cmd.c',
        'npf/npf_cmd_cfg.c',
        'npf/npf_cmd_op.c',
        'npf/npf_dataplane_session.c',
        'npf/npf_disassemble.c',
        'npf/npf_event.c',
        'npf/npf_grouper.c',
        'npf/npf_icmp.c',
        'npf/npf_if.c',
        'npf/npf_if_feat.c',
        'npf/npf_instr.c',
        'npf/npf_match.c',
        'npf/npf_mbuf.c',
        'npf/npf_nat.c',
        'npf/npf_ncgen.c',
        'npf/npf_pack.c',
        'npf/npf_pack_pb.c',
        'npf/npf_unpack.c',
        'npf/npf_processor.c',
        'npf/npf_ptree.c',
        'npf/npf_rc.c',
        'npf/npf_rte_acl.c',
        'npf/npf_rule_gen.c',
        'npf/npf_ruleset.c',
        'npf/npf_session.c',
        'npf/npf_state.c',
        'npf/npf_state_tcp.c',
        'npf/npf_tblset.c',
        'npf/npf_timeouts.c',
        'npf/npf_vrf.c',
        'npf/rldb.c',
        'npf/zones/npf_zone_private.c',
        'npf/zones/npf_zone_public.c',
        'npf/rproc/npf_ext_action_group.c',
        'npf/rproc/npf_ext_counter.c',
        'npf/rproc/npf_ext_ctrdef.c',
        'npf/rproc/npf_ext_ctrref.c',
        'npf/rproc/npf_ext_log.c',
        'npf/rproc/npf_ext_mark.c',
        'npf/rproc/npf_ext_nat64.c',
        'npf/rproc/npf_ext_nptv6.c',
        'npf/rproc/npf_ext_policer.c',
        'npf/rproc/npf_ext_pathmon.c',
        'npf/rproc/npf_ext_session_limit.c',
        'npf/rproc/npf_ext_setvrf.c',
        'npf/rproc/npf_ext_tag.c',
        'npf/rproc/npf_rproc.c',
        'npf_shim.c'
)

dpi_sources = files(
        'npf/dpi/app_cmds.c',
        'npf/dpi/dpi_public.c',
        'npf/dpi/dpi_user.c',
        'npf/dpi/npf_appdb.c',
        'npf/dpi/npf_typedb.c',
        'npf/rproc/npf_ext_app.c',
        'npf/dpi/dpi.c',
        'npf/rproc/npf_ext_appfw.c',
        'npf/rproc/npf_ext_dpi.c',
        'npf/dpi/ndpi.c'
)

app_group_sources = files(
        'npf/app_group/app_group_cmd.c',
        'npf/app_group/app_group_db.c',
        'npf/app_group/app_group.c'
)

dataplane_deps = [
        cap_dep,
        crypto_dep,
        czmq_dep,
        dl_dep,
        dpdk_dep,
        ini_dep,
        m_dep,
        mnl_dep,
        ndpi_dep,
        osip2_dep,
        pcap_dep,
        pipeline_dep,
        protobuf_generated_c_dependency,
        proto_c_dep,
        rte_bus_vdev_dep,
        rte_net_bond_dep,
        rte_net_vhost_dep,
        swport_dep,
        systemd_dep,
        threads_dep,
        urcu_cds_dep,
        urcu_dep,
        urcu_qsbr_dep,
        zmq_dep
]

dataplane_common_sources = [
        app_group_sources,
        core_sources,
        crypto_sources,
        dpi_sources,
        gpc_sources,
        twamp_sources,
        ipv6_sources,
        mpls_sources,
        npf_sources,
        pipeline_node_sources,
        pipeline_sources,
        pl_fused_gen_c,
        session_sources
]

executable(
        'dataplane',
        sources: [dataplane_common_sources, not_for_test_sources],
        override_options: [
                'b_ndebug=true'
        ],
        dependencies: dataplane_deps,
        include_directories: [public_include, internal_inc],
        link_with: [jsonw_library],
        export_dynamic: true,
        install: true,
        install_dir: get_option('prefix') / get_option('sbindir')
)
