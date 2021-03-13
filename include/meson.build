# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.

install_headers(
        'bridge_flags.h',
        'bridge_vlan_set.h',
        'compiler.h',
        'config.h',
        'debug.h',
        'dpi.h',
        'dp_session.h',
        'event.h',
        'fal_bfd.h',
        'fal_plugin.h',
        'feature_commands.h',
        'feature_plugin.h',
        'interface.h',
        'ip.h',
        'ip_checksum.h',
        'ip_forward.h',
        'json_writer.h',
        'lcore_sched.h',
        'pktmbuf.h',
        'pipeline.h',
        'protobuf_util.h',
        'rcu.h',
        'urcu.h',
        'vrf.h',
        subdir: meson.project_name()
)

public_include = include_directories('.')

install_headers(
        'dp_test/dp_test_cmd_check.h',
        'dp_test/dp_test_lib.h',
        'dp_test/dp_test_lib_intf.h',
        'dp_test/dp_test_macros.h',
        'dp_test/dp_test_netlink_state.h',
        'dp_test/dp_test_pktmbuf_lib.h',
        'dp_test/dp_test_firewall_lib.h',
        'dp_test/dp_test_session_lib.h',
        subdir: meson.project_name() / 'dp_test'
)

public_test_include = include_directories('dp_test')
