# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.

sample_plugin_sources = files('sample.c')

sample_protobuf_sources = [
        'SampleFeatConfig.proto',
        'SampleFeatOp.proto'
]

sample_generated_protobuf_c = []
sample_generated_protobuf_c_headers = []
foreach protobuf_definition : sample_protobuf_sources
        generated_c = custom_target('c_' + protobuf_definition,
                command: [protoc, '--proto_path=@CURRENT_SOURCE_DIR@', '--c_out=@OUTDIR@', '@INPUT@'],
                input: protobuf_definition,
                output: ['@BASENAME@.pb-c.c', '@BASENAME@.pb-c.h'],
        )
        sample_generated_protobuf_c += generated_c
        sample_generated_protobuf_c_headers += generated_c[1]
endforeach

sample_plugin = shared_module('sample_plugin',
        sources: [sample_plugin_sources, sample_generated_protobuf_c],
        include_directories: public_include,
        name_prefix: '',
        install: true,
        install_dir: get_option('prefix') / get_option('libdir') / meson.project_name() / 'pipeline' / 'plugins'
)
