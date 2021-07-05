# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020-2021, AT&T Intellectual Property. All rights reserved.

project('vyatta-dataplane', ['c', 'cpp'],
        version: run_command('scripts/get_version', check : true).stdout().strip(),
        default_options: [
                'debug=true',
                'optimization=3',
                'werror=true',
                'warning_level=2',
                'c_std=gnu11',
                'b_lto=true'
        ]
)

cc = meson.get_compiler('c')

configure_file(
        output : 'build_config.h',
        configuration : {
                'PACKAGE_VERSION' : '"' + meson.project_version() + '"',
                'HAVE_SYSTEMD' : get_option('use_systemd').enabled(),
                'FUSED_MODE' : get_option('fused_mode').enabled(),
                'VYATTA_SYSCONF_DIR' : '"' + get_option('prefix') / get_option('sysconfdir') / 'vyatta' + '"',
                'VYATTA_DATA_DIR' : '"' + get_option('prefix') / get_option('datadir') / 'vyatta' + '"',
                'PKGLIB_DIR' : '"' + get_option('prefix') / get_option('libdir') / meson.project_name() + '"',
                'HAVE_GETTID' : cc.has_function('gettid')
        }
)

add_project_arguments(
        '-include', 'build_config.h',
        '-D_GNU_SOURCE',
        cc.get_supported_arguments([
                '-Wno-deprecated-declarations',
                '-Wno-stringop-overflow',
                '-Wno-stringop-truncation',
                '-Wno-format-truncation'
        ]),
        language: 'c'
)

add_project_link_arguments(
        cc.get_supported_link_arguments([
                '-Wno-stringop-overflow' # 3 warnings in npf code
        ]),
        language: 'c'
)

cap_dep = dependency('libcap')
check_dep = dependency('check', required: get_option('with_tests'))
crypto_dep = dependency('libcrypto')
czmq_dep = dependency('libczmq', version: '>= 3.0.2')
dl_dep = cc.find_library('dl', required : true)
dpdk_dep = dependency('libdpdk', version: '>= 19.11')
ini_dep = cc.find_library('inih', required: true)
json_dep = dependency('json-c', required: get_option('with_tests'))
m_dep = cc.find_library('m', required : true)
mnl_dep = dependency('libmnl')
ndpi_dep = dependency('libndpi', version: '>= 3.4')
osip2_dep = dependency('libosip2')
pcap_dep = cc.find_library('libpcap', required: true)
protobuf_dep = dependency('protobuf')
proto_c_dep = dependency('libprotobuf-c', version: '>= 1.0.0')
rte_bus_vdev_dep = cc.find_library('rte_bus_vdev', required : true)
rte_net_bond_dep = cc.find_library('rte_net_bond', required : true)
rte_net_ring_dep = cc.find_library('rte_net_ring', required: get_option('with_tests'))
rte_net_vhost_dep = cc.find_library('rte_net_vhost', required : true)
swport_dep = dependency('vyatta-dpdk-swport', version: '>= 0.1.3')
systemd_dep = dependency('libsystemd', required: get_option('use_systemd'))
threads_dep = dependency('threads')
urcu_cds_dep = dependency('liburcu-cds', version: '>= 0.8.0')
urcu_dep = dependency('liburcu', version: '>= 0.8.0')
urcu_qsbr_dep = dependency('liburcu-qsbr', version: '>= 0.8.0')
zmq_dep = dependency('libzmq', version: '>= 4.0.4')

subdir('include')
subdir('protobuf')
subdir('src/pipeline')
subdir('src')

if get_option('with_tests').enabled()
        subdir('src/pipeline/nodes/sample')
        subdir('tests/whole_dp')
endif

install_data('dataplane-drivers.conf',
        install_dir: get_option('sysconfdir') / 'vyatta'
)

install_data('dataplane-drivers-default.conf',
        install_dir: get_option('datadir') / 'vyatta'
)

install_data('mlx4_core.conf',
        install_dir: '/etc/modprobe.d'
)

pkg = import('pkgconfig')
pkg.generate(
        filebase: 'vyatta-dataplane-dev',
        name: 'Vyatta Dataplane',
        description: 'Dataplane Plugin Development',
        subdirs: 'vyatta-dataplane',
        libraries: jsonw_library
)
pkg.generate(
        filebase: 'libvyattafal',
        name: 'Vyatta Forwarding Abstraction Layer',
        description: 'Dataplane FAL Plugin Development',
        subdirs: 'vyatta-dataplane',
        libraries: []
)

run_clang_tidy = find_program('run-clang-tidy', required: false)
if run_clang_tidy.found() and (cc.get_id() == 'clang')
        run_target('clang-tidy',
                command: [ 'scripts/run-clang-tidy_wrapper.sh' ],
                depends: [pl_fused_gen_c, protobuf_generated_c, sample_generated_protobuf_c]
        )
else
        run_target('clang-tidy',
                command: ['echo', 'install clang-tidy and configure CC=clang', '&&', 'false'])
endif
