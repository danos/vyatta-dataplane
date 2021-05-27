# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020-2021, AT&T Intellectual Property. All rights reserved.

protobuf_sources= [
        'DataplaneEnvelope.proto',
        'XConnectConfig.proto',
        'PPPOEConfig.proto',
        'TCPMSSConfig.proto',
        'PipelineStatsConfig.proto',
        'CryptoPolicyConfig.proto',
        'IPAddress.proto',
        'VFPSetConfig.proto',
        'cpp_rl.proto',
        'IP6RedirectsConfig.proto',
        'SpeedConfig.proto',
        'GArpConfig.proto',
        'CgnatLogging.proto',
        'BreakoutConfig.proto',
        'IPAddressOrLabel.proto',
        'Route.proto',
        'RibUpdate.proto',
        'MacLimitConfig.proto',
        'PauseConfig.proto',
        'SynceConfig.proto',
        'LAGConfig.proto',
        'GPCConfig.proto',
        'FeatureAffinityConfig.proto',
        'NbrResConfig.proto',
        'SessionPack.proto',
        'ICMPRateLimConfig.proto'
]

install_data(protobuf_sources,
        install_dir: get_option('datadir') / meson.project_name() / 'protobuf'
)

protoc = find_program('protoc')
perl_protobuf_generator = files('../scripts/vyatta-generate-pb-perl.pl')

protobuf_generated_c = []
protobuf_generated_c_headers = []
protobuf_generated_cxx = []
protobuf_generated_py = []
protobuf_generated_go = []
protobuf_generated_perl = []
foreach protobuf_definition : protobuf_sources

        generated_c = custom_target('c_' + protobuf_definition,
                command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--c_out=@OUTDIR@', '@INPUT@'],
                input: protobuf_definition,
                output: ['@BASENAME@.pb-c.c', '@BASENAME@.pb-c.h'],
                install: true,
                install_dir: [false, get_option('includedir') / meson.project_name() / 'protobuf']
        )
        protobuf_generated_c += generated_c
        protobuf_generated_c_headers += generated_c[1]

        protobuf_generated_cxx += custom_target('cxx_' + protobuf_definition,
                command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--cpp_out=@OUTDIR@', '@INPUT@'],
                input: protobuf_definition,
                output: ['@BASENAME@.pb.cc', '@BASENAME@.pb.h'],
                install: true,
                install_dir: [false, get_option('includedir') / meson.project_name() / 'protobuf']
        )

        protobuf_generated_py += custom_target('py_' + protobuf_definition,
                command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--python_out=@OUTDIR@', '@INPUT@'],
                input: protobuf_definition,
                output: '@BASENAME@_pb2.py',
                install: true,
                install_dir: 'lib/python3/dist-packages/vyatta/proto'
        )

        protobuf_generated_go += custom_target('go_' + protobuf_definition,
                command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--go_out=paths=source_relative:@OUTDIR@', '@INPUT@'],
                input: protobuf_definition,
                output: '@BASENAME@.pb.go',
                install: true,
                install_dir: 'share/gocode/src/github.com/danos/vyatta-dataplane/protobuf/go/@0@'.format(protobuf_definition.split('.')[0])
        )

        protobuf_generated_perl += custom_target('pl_' + protobuf_definition,
                command: [perl_protobuf_generator, '@INPUT@', '@OUTDIR@', '@CURRENT_SOURCE_DIR@'],
                input: protobuf_definition,
                output: '@BASENAME@.pm',
                install: true,
                install_dir: 'share/perl5/vyatta/proto'
        )

endforeach

protobuf_generated_c_includes = include_directories('..')

protobuf_c_library = shared_library(
        'vyatta-dataplane-proto-c',
        sources: [protobuf_generated_c],
        dependencies: [proto_c_dep],
        install: true,
        version: '1.0.0'
)

protobuf_generated_c_dependency = declare_dependency(
        include_directories: protobuf_generated_c_includes,
        sources: protobuf_generated_c_headers,
        link_with: protobuf_c_library
)

protobuf_cxx_library = shared_library(
        'vyatta-dataplane-proto',
        sources: [protobuf_generated_cxx],
        dependencies: [protobuf_dep],
        install: true,
        version: '1.0.0'
)

pkg = import('pkgconfig')
pkg.generate(protobuf_cxx_library, subdirs: 'vyatta-dataplane/protobuf')
pkg.generate(protobuf_c_library, subdirs: 'vyatta-dataplane/protobuf')
