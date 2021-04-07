# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2021, SafePoint. All rights reserved.
# Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.

flowstat_plugin_sources = files(
        'src/flowstat.c'
)

subdir('protobuf')

flowstat_plugin = shared_module('flowstat_plugin',
        sources: [flowstat_plugin_sources, flowstat_generated_protobuf_c],
        dependencies: [dl_dep, dpdk_dep, proto_c_dep, threads_dep, urcu_cds_dep, urcu_dep, urcu_qsbr_dep],
        include_directories: public_include,
        name_prefix: '',
        install: true,
        install_dir: get_option('prefix') / get_option('libdir') / meson.project_name() / 'pipeline' / 'plugins'
)

flowstat_include = include_directories('src')
