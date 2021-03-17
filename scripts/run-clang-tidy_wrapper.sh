#!/bin/sh

# Workaround for: https://github.com/mesonbuild/meson/pull/8365
sed -i 's/-Xclang -fcolor-diagnostics/-fcolor-diagnostics/g' \
	"${MESON_BUILD_ROOT}/compile_commands.json"

run-clang-tidy -quiet -j "$(nproc)" -p "${MESON_BUILD_ROOT}" \
	-header-filter='^((?!\.pb).)*\.h$' \
	'.*(?<!pb.cc)(?<!pb-c.c)(?<!pl_fused_gen.[ch])$'
