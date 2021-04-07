# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2021, SafePoint. All rights reserved.
# Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.


flowstat_protobuf_sources = [
        'FlowStatFeatConfig.proto',
        'FlowStatFeatOp.proto',
]

install_data(flowstat_protobuf_sources,
        install_dir: get_option('datadir') / 'flowstat_plugin' / 'protobuf'
)

flowstat_generated_protobuf_c = []
flowstat_generated_protobuf_c_headers = []
foreach protobuf_definition : flowstat_protobuf_sources
        generated_c = custom_target('c_' + protobuf_definition,
                command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--c_out=@OUTDIR@', '@INPUT@'],
                input: protobuf_definition,
                output: ['@BASENAME@.pb-c.c', '@BASENAME@.pb-c.h'],
        )
        flowstat_generated_protobuf_c += generated_c
        flowstat_generated_protobuf_c_headers += generated_c[1]

        protobuf_generated_perl += custom_target('pl_' + protobuf_definition,
                command: [perl_protobuf_generator, '@INPUT@', '@OUTDIR@', '@CURRENT_SOURCE_DIR@'],
                input: protobuf_definition,
                output: '@BASENAME@.pm',
                install: true,
                install_dir: 'share/perl5/flowstat_plugin/proto'
        )
endforeach