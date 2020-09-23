
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
# NOTE: We don't make use of AC_PACKAGE_VERSION so always set to 1.0.0
AC_INIT([Vyatta-Dataplane], [m4_esyscmd_s([dpkg-parsechangelog -S Version])])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([build_config.h])
AM_INIT_AUTOMAKE([1.13.2 subdir-objects foreign -Wall tar-ustar])
AM_SILENT_RULES([yes])

AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_GNU_SOURCE
AC_PROG_CC
# not explicitly required since AM 1.14 but kept for backwards compatibility
AM_PROG_CC_C_O
AX_CHECK_COMPILE_FLAG([-std=gnu11], [CFLAGS+=" -std=gnu11"], [AC_PROG_CC_C99])
AC_PROG_CPP
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX(11)
AM_PROG_AR
LT_INIT([dlopen])
AC_PROG_MAKE_SET
AX_PTHREAD

# Exactly match the architecture flags used by dpdk or inlining errors during build
AC_CANONICAL_HOST
AS_CASE([$host_cpu],
	[x86_64], [EXTRA_CFLAGS="$EXTRA_CFLAGS -m64 -march=corei7" EXTRA_CXXFLAGS="$EXTRA_CXXFLAGS -m64 -march=corei7"],
	[AC_MSG_ERROR([unsupported CPU architecture: $host_cpu])]
	)

COMMON_WARNINGS="-Wall -Wextra
            -Wundef
            -Wwrite-strings
            -Wpointer-arith
            -Wmissing-declarations
            -Wredundant-decls
            -Wno-missing-field-initializers
            -Wformat=2
            -Wformat-nonliteral
            -Wformat-security
            -Wsign-compare
            -Wstrict-aliasing
            -Wmissing-format-attribute
            -Wmissing-noreturn
            -Winit-self
            -Wredundant-decls
            -Wmissing-include-dirs
            -Wunused-but-set-variable
            -Warray-bounds
            -Wreturn-type
            -Wlogical-op
            -Wno-deprecated-declarations
            -Wno-suggest-attribute=format"

AC_LANG_PUSH([C])
AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option],
[extra_test_flag="-Werror=unknown-warning-option"],
[extra_test_flag=""])
AX_APPEND_COMPILE_FLAGS([ $COMMON_WARNINGS \
            -Wnested-externs \
            -Wmissing-prototypes \
            -Wstrict-prototypes \
            -Wold-style-definition \
            -Wimplicit-function-declaration \
	    -Wno-stringop-overflow \
	    -Wno-stringop-truncation \
	    -Wno-format-truncation \
	    -Wno-format-nonliteral \
	    -Wno-format-overflow \
	    -Wno-tautological-constant-out-of-range-compare \
	    ], EXTRA_CFLAGS, [$extra_test_flag])
AX_APPEND_FLAG([-Werror], EXTRA_CFLAGS)
AC_SUBST(EXTRA_CFLAGS)
AC_LANG_POP([C])

AC_LANG_PUSH([C++])
AX_CHECK_COMPILE_FLAG([-Werror=unknown-warning-option],
[extra_test_flag="-Werror=unknown-warning-option"],
[extra_test_flag=""])
AX_APPEND_COMPILE_FLAGS([ $COMMON_WARNINGS \
            -Wno-overloaded-virtual \
	    -Wno-deprecated-register \
	    ], EXTRA_CXXFLAGS, [$extra_test_flag])
AX_APPEND_FLAG([-Werror], EXTRA_CXXFLAGS)
AC_SUBST(EXTRA_CXXFLAGS)
AC_LANG_POP([C++])

AX_CODE_COVERAGE

AX_VALGRIND_DFLT([sgcheck], [off])
AX_VALGRIND_DFLT([helgrind], [off])
AX_VALGRIND_DFLT([drd], [off])
AX_VALGRIND_DFLT([memcheck], [on])
AX_VALGRIND_CHECK

# Checks for libraries.
PKG_CHECK_MODULES(LIBCAP, [libcap], , [
	AC_SEARCH_LIBS([cap_get_proc], [cap], , [
		AC_MSG_ERROR([No library 'libcap' found])
	])
])

AC_SEARCH_LIBS([ini_parse_file], [inih], , [
		AC_MSG_ERROR([unable to find the ini_parse_file() function])])
AC_CHECK_HEADER([ini.h])

PKG_CHECK_MODULES(CHECK, [check])
PKG_CHECK_MODULES(JSON_C, [json-c])
PKG_CHECK_MODULES(LIBCRYPTO, [libcrypto])
PKG_CHECK_MODULES(LIBCZMQ, [libczmq >= 3.0.2])
PKG_CHECK_MODULES(LIBZMQ, [libzmq >= 4.0.4])
PKG_CHECK_MODULES(LIBURCU_CDS, [liburcu-cds >= 0.8.0])
PKG_CHECK_MODULES(LIBURCU_QSBR, [liburcu-qsbr >= 0.8.0])
PKG_CHECK_MODULES(LIBMNL, [libmnl])
PKG_CHECK_MODULES(LIBOSIP2, [libosip2])
PKG_CHECK_MODULES_STATIC(DPDK, [libdpdk >= 19.11])
PKG_CHECK_MODULES(SWPORT, [vyatta-dpdk-swport >= 0.1.3])
PKG_CHECK_MODULES([PROTOBUF_C], [libprotobuf-c >= 1.0.0])

AC_ARG_VAR([PROTOC_C], [protobuf compiler command])
AC_PATH_PROG([PROTOC_C], [protoc-c], [],
			 [`$PKG_CONFIG --variable=exec_prefix libprotobuf-c`/bin:$PATH])
if test -z "$PROTOC_C"; then
   AC_MSG_ERROR([Could not find protoc-c])
fi

AC_ARG_WITH([dpi], AS_HELP_STRING([--without-dpi], [Build without ndpi library (default: test)]))

AS_IF([test "x$with_dpi" != "xno"], [
	PKG_CHECK_MODULES(DPI, [libndpi >= 2.6.0] , [HAVE_NDPI=1] , [HAVE_NDPI=0]
		AC_MSG_WARN([nDPI engine not found]))
])

AM_CONDITIONAL([USE_NDPI], [test "$HAVE_NDPI" = 1])
AM_COND_IF([USE_NDPI], [AC_DEFINE([USE_NDPI], [], [Use nDPI library])], [])

# Always use the Gold linker so we can specify text section locations with/without LTO
AX_CHECK_LINK_FLAG([-fuse-ld=gold], [LDFLAGS+=" -fuse-ld=gold"],
		   [AC_MSG_ERROR([Gold linker required])])

AC_ARG_WITH([lto], AS_HELP_STRING([--without-lto], [Build without link time optimsation]))
AS_IF([test "x$with_lto" != "xno"],
      # Do parallel LTO if the compiler supports it as it's quicker
      [AX_CHECK_COMPILE_FLAG([-Werror -flto=1], [AC_SUBST(DATAPLANE_LTO_FLAG, '-flto=$(shell nproc)')],
						[AC_SUBST(DATAPLANE_LTO_FLAG, '-flto')])
])

AC_CHECK_HEADERS(valgrind/memcheck.h)
AC_CHECK_HEADERS(openssl/hmac.h)
AC_CHECK_DECLS([HMAC_CTX_new],,,[#include<openssl/hmac.h>])

AC_CHECK_MEMBERS([struct bpf_aux_data.vlan_tag], [],
	[AC_MSG_ERROR([No library 'libpcap' with 'struct bpf_aux_data' found])],
	[[#include <pcap.h>]])

CFLAGS_BACK=$CFLAGS
CFLAGS+=" $DPDK_CFLAGS -Werror"
AC_MSG_CHECKING([whether DPDK's port IDs are uint16_t])
AC_COMPILE_IFELSE(
	[AC_LANG_PROGRAM(
		[[
#include <rte_ethdev.h>
int foo(uint16_t a, enum rte_eth_event_type b, void *c, void *d)
{
    return 0;
}
		]],
		[[
rte_eth_dev_callback_register(0, 0, foo, NULL);
		]])
	],[
		AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_RTE_PORT_ID_16_BITS, [1],
		    [whether DPDK's port IDs are uint16_t])
	],[
		AC_MSG_RESULT([no])
])
CFLAGS=$CFLAGS_BACK

AC_ARG_WITH([systemd],
    AS_HELP_STRING([--without-systemd], [Ignore presence of systemd and disable it]))

AS_IF([test "x$with_systemd" != "xno"],
      [PKG_CHECK_MODULES(SYSTEMD, [libsystemd], [have_systemd=yes], [have_systemd=no])],
      [have_systemd=no])

AS_IF([test "x$have_systemd" = "xyes"],
      [AC_DEFINE(HAVE_SYSTEMD, 1, [Have systemd])],
      [AS_IF([test "x$with_systemd" = "xyes"],
             [AC_MSG_ERROR([systemd requested but not found])
      ])
])

# Allow whole_dp unit tests to be disabled as they have issues
# running in a chroot without /proc and /sys, which is the case when
# running dpkg-buildpackage in OBS.
AC_ARG_ENABLE([whole_dp_test],
AS_HELP_STRING([--disable-whole_dp_test], [disable whole_dp unit tests]),
[case "${enableval}" in
  yes) whole_dp_test=true ;;
  no)  whole_dp_test=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-whole_dp_test]) ;;
esac],[whole_dp_test=true])
AM_CONDITIONAL([WHOLE_DP_TEST], [test "x$whole_dp_test" = "xtrue"])

# Run all the whole_dp unit tests. By default only a representative set of
# them are run.
AC_ARG_ENABLE([whole_dp_all_tests],
AS_HELP_STRING([--enable-whole_dp_all_tests], [enable all whole_dp unit tests]),
[case "${enableval}" in
  yes) whole_dp_all_tests=true ;;
  no)  whole_dp_all_tests=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-whole_dp_all_tests]) ;;
esac],[whole_dp_all_tests=false])
AM_CONDITIONAL([WHOLE_DP_ALL_TESTS], [test "x$whole_dp_all_tests" = "xtrue"])

# Run with the address sanitizer enabled.
AC_ARG_ENABLE([dataplane_sanitizer],
AS_HELP_STRING([--enable-dataplane_sanitizer], [enable the address sanitizer]),
[case "${enableval}" in
  yes) dataplane_sanitizer=true ;;
  no)  dataplane_sanitizer=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-dataplane_sanitizer]) ;;
esac],[dataplane_sanitizer=false])
AM_CONDITIONAL([DATAPLANE_SANITIZER], [test "x$dataplane_sanitizer" = "xtrue"])

# Needed so dataplane_test can find it's hardcoded config
# files during a VPATH build.
AC_CONFIG_LINKS(dataplane-drivers-default.conf:dataplane-drivers-default.conf)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/proc/cpuinfo:tests/whole_dp/dummyfs/proc/cpuinfo)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/sys/bus/pci/devices/.dummy:tests/whole_dp/dummyfs/sys/bus/pci/devices/.dummy)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/sys/devices/system/cpu/online:tests/whole_dp/dummyfs/sys/devices/system/cpu/online)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu0/topology/core_id:tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu0/topology/core_id)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu0/topology/physical_package_id:tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu0/topology/physical_package_id)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu0/topology/thread_siblings:tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu0/topology/thread_siblings)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu1/topology/core_id:tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu1/topology/core_id)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu1/topology/physical_package_id:tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu1/topology/physical_package_id)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu1/topology/thread_siblings:tests/whole_dp/dummyfs/sys/devices/system/cpu/cpu1/topology/thread_siblings)
AC_CONFIG_LINKS(tests/whole_dp/dummyfs/sys/module/.dummy:tests/whole_dp/dummyfs/sys/module/.dummy)

PKG_PROG_PKG_CONFIG
PKG_INSTALLDIR

AC_CONFIG_FILES([Makefile src/version.h protobuf/vyatta-dataplane-proto.pc debian/vyatta-dataplane-dev.pc debian/libvyattafal.pc])
AC_OUTPUT
