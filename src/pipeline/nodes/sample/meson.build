# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2020, AT&T Intellectual Property. All rights reserved.

sample_plugin_sources = files('sample.c')

sample_protobuf_sources = files(
        'SampleFeatConfig.proto',
        'SampleFeatOp.proto'
)

protoc_gen = generator(protoc,
        output: ['@BASENAME@.pb-c.c', '@BASENAME@.pb-c.h'],
        arguments: [
                '--proto_path=@CURRENT_SOURCE_DIR@',
                '--c_out=@BUILD_DIR@',
                '@INPUT@'
        ]
)

sample_generated_protobuf_c = protoc_gen.process(sample_protobuf_sources)

sample_plugin = shared_module('sample_plugin',
        sources: [sample_plugin_sources, sample_generated_protobuf_c],
        include_directories: public_include,
        name_prefix: '',
        install: true,
        install_dir: get_option('prefix') / get_option('libdir') / meson.project_name() / 'pipeline' / 'plugins'
)
