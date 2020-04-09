include $(top_srcdir)/common.mk

ACLOCAL_AMFLAGS=-I m4

OTHER_LINKER_FLAGS = -rdynamic # Needed for backtraces
# Fix the start of the hot_text section in an attempt to provide more
# stability between builds of forwarding performance.
#
# This isn't a scientifically chosen value, but merely one that was
# chosen as the address of ether_input before it was put into a
# section with a fixed start address and where it was observed to have
# good performance.
OTHER_LINKER_FLAGS += -Wl,--section-start,.text=429e00
OTHER_LINKER_FLAGS += -Wl,--section-ordering-file,$(srcdir)/dataplane.section-ordering

# Needed for -flto
AR = gcc-ar
RANLIB = gcc-ranlib

CRYTPO_FILES = \
	src/crypto/crypto.c \
	src/crypto/crypto_engine.c \
	src/crypto/crypto_policy.c \
	src/crypto/crypto_sadb.c \
	src/crypto/esp.c \
	src/crypto/vti.c \
	src/crypto/crypto_pmd.c

IPV6_FILES = \
	src/netinet6/in6.c \
	src/netinet6/ip6_commands.c \
	src/netinet6/ip6_forward.c \
	src/netinet6/ip6_icmp.c \
	src/netinet6/ip6_main.c \
	src/netinet6/ip6_mroute.c \
	src/netinet6/ip6_options.c \
	src/netinet6/nd6_nbr.c \
	src/netinet6/route_v6.c \
	src/netinet6/scope6.c

MPLS_FILES = \
	src/mpls/mpls_commands.c \
	src/mpls/mpls_forward.c \
	src/mpls/mpls_label_table.c \
	src/mpls/mpls_netlink.c

PIPELINE_FILES = \
	src/pipeline/pl_commands.c \
	src/pipeline/pl_fused_gen.c \
	src/pipeline/pl_node.c \
	src/pipeline/pl_node_boot.c \
	$(PIPELINE_NODE_FILES)

PIPELINE_NODE_FILES = \
	src/pipeline/nodes/l2_bridge_in.c \
	src/pipeline/nodes/l2_capture.c \
	src/pipeline/nodes/cross_connect/l2_cross_connect_node.c \
	src/pipeline/nodes/cross_connect/l2_cross_connect_cmd.c \
	src/pipeline/nodes/cross_connect/cross_connect.c \
	src/pipeline/nodes/ipv4_drop.c \
	src/pipeline/nodes/ipv6_drop.c \
	src/pipeline/nodes/l2_consume.c \
	src/pipeline/nodes/l2_ether_in.c \
	src/pipeline/nodes/l2_ether_forward.c \
	src/pipeline/nodes/l2_ether_lookup.c \
	src/pipeline/nodes/l2_hw_hdr.c \
	src/pipeline/nodes/l2_local.c \
	src/pipeline/nodes/l2_output.c \
	src/pipeline/nodes/l2_portmonitor.c \
	src/pipeline/nodes/l2_portmonitor_hw.c \
	src/pipeline/nodes/l2_vlan_mod.c \
	src/pipeline/nodes/pppoe/l2_pppoe_node.c \
	src/pipeline/nodes/pppoe/l2_pppoe_cmd.c \
	src/pipeline/nodes/pppoe/pppoe.c \
	src/pipeline/nodes/l2_sw_vlan.c \
	src/pipeline/nodes/l3_acl.c \
	src/pipeline/nodes/l3_arp.c \
	src/pipeline/nodes/l3_fw_in.c \
	src/pipeline/nodes/l3_fw_out.c \
	src/pipeline/nodes/l3_nat64.c \
	src/pipeline/nodes/l3_pbr.c \
	src/pipeline/nodes/l3_tcp_mss.c \
	src/pipeline/nodes/l3_v4_cgnat.c \
	src/pipeline/nodes/l3_v4_defrag.c \
	src/pipeline/nodes/l3_v4_encap.c \
	src/pipeline/nodes/l3_v4_gre.c \
	src/pipeline/nodes/l3_v4_ipsec.c \
	src/pipeline/nodes/l3_v4_l2tpv3.c \
	src/pipeline/nodes/l3_v4_l4.c \
	src/pipeline/nodes/l3_v4_no_address.c \
	src/pipeline/nodes/l3_v4_no_forwarding.c \
	src/pipeline/nodes/l3_v4_out.c \
	src/pipeline/nodes/l3_v4_post_route_lookup.c \
	src/pipeline/nodes/l3_v4_route_lookup.c \
	src/pipeline/nodes/l3_v4_rpf.c \
	src/pipeline/nodes/l3_v4_udp.c \
	src/pipeline/nodes/l3_v4_val.c \
	src/pipeline/nodes/l3_v6_defrag.c \
	src/pipeline/nodes/l3_v6_encap.c \
	src/pipeline/nodes/l3_v6_ipsec.c \
	src/pipeline/nodes/l3_v6_l4.c \
	src/pipeline/nodes/l3_v6_no_address.c \
	src/pipeline/nodes/l3_v6_no_forwarding.c \
	src/pipeline/nodes/l3_v6_out.c \
	src/pipeline/nodes/l3_v6_post_route_lookup.c \
	src/pipeline/nodes/l3_v6_route_lookup.c \
	src/pipeline/nodes/l3_v6_udp.c \
	src/pipeline/nodes/l3_v6_val.c \
	src/pipeline/nodes/l3_v6_nptv6.c \
	src/pipeline/nodes/term.c \
	src/pipeline/nodes/term_drop.c

SESSION_FILES = \
	src/session/session.c \
	src/session/session_cmds.c \
	src/session/session_feature.c \
	src/session/session_watch.c

CORE_FILES = \
	src/arp.c \
	src/backplane.c \
	src/bpf_filter.c \
	src/bridge_vlan_set.c \
	src/commands.c \
	src/protobuf.c \
	src/protobuf_util.c \
	src/config.c \
	src/control.c \
	src/cpp_rate_limiter.c \
	src/dealer.c \
	src/debug.c \
	src/devinfo.c \
	src/dp_event.c \
	src/ecmp.c \
	src/ether.c \
	src/event.c \
	src/fal.c \
	src/feature_plugin.c \
	src/if/bridge/bridge.c \
	src/if/bridge/bridge_netlink.c \
	src/if/bridge/bridge_port.c \
	src/if/bridge/switch.c \
	src/if/dpdk-eth/hotplug.c \
	src/if/dpdk-eth/dpdk_eth_if.c \
	src/if/dpdk-eth/dpdk_eth_linkwatch.c \
	src/if/dpdk-eth/dpdk_lag.c \
	src/if/dpdk-eth/fal_lag.c \
	src/if/dpdk-eth/vhost.c \
	src/if/gre.c \
	src/if/ipip_tunnel.c \
	src/if/loopback.c \
	src/if/macvlan.c \
	src/if/vlan/vlan_if.c \
	src/if/vlan/vlan_if_netlink.c \
	src/if/vxlan.c \
	src/if.c \
	src/if_ether.c \
        src/if_feat.c \
	src/if_llatbl.c \
	src/in.c \
	src/in_cksum.c \
	src/ip_forward.c \
	src/ip_commands.c \
	src/ip_icmp.c \
	src/ip_mcast.c \
	src/ip_mcast_fal_interface.c \
	src/ip_netlink.c \
	src/ip_options.c \
	src/ip_output.c \
	src/iptun_common.c \
	src/json_writer.c \
	src/l2_rx_fltr.c \
	src/l2tp/l2tpeth_decap.c \
	src/l2tp/l2tpeth_dp.c \
	src/l2tp/l2tpeth_netlink.c \
	src/lag.c \
	src/lcore_sched.c \
	src/log.c \
	src/lpm/lpm.c \
	src/lpm/lpm6.c \
	src/main.c \
	src/master.c \
	src/mstp.c \
	src/netinet/ip_mroute.c \
	src/netlink.c \
	src/nh.c \
	src/nsh.c \
	src/pd_show.c \
	src/pktmbuf.c \
	src/pathmonitor/pathmonitor_cmds.c \
	src/portmonitor/portmonitor_cmds.c \
	src/portmonitor/portmonitor_dp.c \
	src/power.c \
	src/ptp.c \
	src/qos_sched.c \
	src/qos_dpdk.c \
	src/qos_ext_buf_monitor.c \
	src/qos_hw.c \
	src/qos_hw_show.c \
	src/qos_obj_db.c \
	src/route.c \
	src/route_broker.c \
	src/rt_commands.c \
	src/rt_tracker.c \
	src/storm_ctl.c \
	src/sfp.c \
	src/switchport.c \
	src/udp_handler.c \
	src/util.c \
	src/vlan_modify.c \
	src/vrf.c \
	src/shadow.c \
	src/zmq_dp.c

FILES_NOT_FOR_TEST = \
	src/capture.c \
	src/ip_id.c \
	src/team.c \
	src/shadow_receive.c

NPF_FILES = \
	src/npf/alg/apt/apt.c \
	src/npf/alg/apt/apt_dport.c \
	src/npf/alg/apt/apt_tuple.c \
        src/npf/alg/alg_apt.c \
        src/npf/apm/apm.c \
        src/npf/alg/alg.c \
        src/npf/alg/alg_npf.c \
        src/npf/alg/alg_ftp.c \
        src/npf/alg/alg_tftp.c \
        src/npf/alg/alg_rpc.c \
        src/npf/alg/alg_sip.c \
        src/npf/alg/sip/sip_request.c \
        src/npf/alg/sip/sip_response.c \
        src/npf/alg/sip/sip_parse.c \
        src/npf/alg/sip/sip_translate.c \
        src/npf/cgnat/cgn.c \
        src/npf/cgnat/cgn_cmd_cfg.c \
        src/npf/cgnat/cgn_cmd_op.c \
        src/npf/cgnat/cgn_if.c \
        src/npf/cgnat/cgn_log.c \
        src/npf/cgnat/cgn_log_rte.c \
        src/npf/cgnat/cgn_log_protobuf_zmq.c \
        src/npf/cgnat/cgn_map.c \
        src/npf/cgnat/cgn_mbuf.c \
        src/npf/cgnat/cgn_policy.c \
        src/npf/cgnat/cgn_session.c \
        src/npf/cgnat/cgn_sess2.c \
        src/npf/cgnat/cgn_sess_state.c \
        src/npf/cgnat/cgn_source.c \
        src/npf/config/npf_attach_point.c \
        src/npf/config/npf_auto_attach.c \
        src/npf/config/npf_config.c \
        src/npf/config/npf_config_state.c \
        src/npf/config/npf_dump.c \
        src/npf/config/npf_gen_ruleset.c \
        src/npf/config/npf_rule_group.c \
        src/npf/config/npf_ruleset_type.c \
        src/npf/config/pmf_rule.c \
        src/npf/config/pmf_parse.c \
        src/npf/config/pmf_dump.c \
        src/npf/config/pmf_att_rlgrp.c \
        src/npf/config/pmf_hw.c \
        src/npf/fragment/ipv4_frag_tbl.c \
        src/npf/fragment/ipv4_rsmbl.c \
        src/npf/fragment/ipv6_rsmbl.c \
        src/npf/fragment/ipv6_rsmbl_tbl.c \
        src/npf/nat/nat_cmd_cfg.c \
        src/npf/nat/nat_cmd_op.c \
        src/npf/nat/nat_pool.c \
        src/npf/nat/nat_pool_event.c \
        src/npf/grouper2.c \
        src/npf/npf_nat64.c \
        src/npf/npf_addrgrp.c \
        src/npf/npf_apm.c \
        src/npf/npf_cache.c \
        src/npf/npf_cidr_util.c \
        src/npf/npf_cmd.c \
        src/npf/npf_cmd_cfg.c \
        src/npf/npf_cmd_op.c \
        src/npf/npf_dataplane_session.c \
        src/npf/npf_disassemble.c \
        src/npf/npf_event.c \
        src/npf/npf_grouper.c \
        src/npf/npf_icmp.c \
        src/npf/npf_if.c \
        src/npf/npf_if_feat.c \
        src/npf/npf_instr.c \
        src/npf/npf_match.c \
        src/npf/npf_mbuf.c \
        src/npf/npf_nat.c \
        src/npf/npf_ncgen.c \
        src/npf/npf_pack.c \
        src/npf/npf_unpack.c \
        src/npf/npf_processor.c \
        src/npf/npf_ptree.c \
        src/npf/npf_rte_acl.c \
        src/npf/npf_rule_gen.c \
        src/npf/npf_ruleset.c \
        src/npf/npf_session.c \
        src/npf/npf_state.c \
        src/npf/npf_state_tcp.c \
        src/npf/npf_tblset.c \
        src/npf/npf_timeouts.c \
        src/npf/npf_vrf.c \
        src/npf/zones/npf_zone_private.c \
        src/npf/zones/npf_zone_public.c \
        src/npf/rproc/npf_ext_action_group.c \
        src/npf/rproc/npf_ext_counter.c \
        src/npf/rproc/npf_ext_ctrdef.c \
        src/npf/rproc/npf_ext_ctrref.c \
        src/npf/rproc/npf_ext_log.c \
        src/npf/rproc/npf_ext_mark.c \
        src/npf/rproc/npf_ext_nat64.c \
        src/npf/rproc/npf_ext_nptv6.c \
        src/npf/rproc/npf_ext_policer.c \
        src/npf/rproc/npf_ext_pathmon.c \
        src/npf/rproc/npf_ext_session_limit.c \
        src/npf/rproc/npf_ext_setvrf.c \
        src/npf/rproc/npf_ext_tag.c \
        src/npf/rproc/npf_rproc.c \
        src/npf_shim.c

if USE_DPI
DPI_FILES = src/npf/dpi/dpi.c src/npf/rproc/npf_ext_dpi.c \
	    src/npf/dpi/dpi_public.c src/npf/rproc/npf_ext_appfw.c \
	    src/npf/dpi/app_cmds.c \
	    src/npf/rproc/npf_ext_app.c
PIPELINE_NODE_FILES += src/pipeline/nodes/l3_dpi.c
else
DPI_FILES = src/npf/dpi/dpi_stubs.c
endif

PL_GEN_FUSED_OPTS = \
	--include pl_fused_gen.h \
	--include nodes/pl_nodes_common.h \
	--include pl_fused.h \
	--entry vyatta:ether-forward \
	--entry vyatta:ether-in \
	--entry vyatta:arp-in-nothot \
	--entry vyatta:ipv4-validate \
	--entry vyatta:ipv6-validate \
	--entry vyatta:ipv4-route-lookup \
	--entry vyatta:ipv4-out \
	--entry vyatta:ipv6-out \
	--entry vyatta:ipv4-defrag-out-spath \
	--entry vyatta:ipv6-defrag-out-spath \
	--entry vyatta:ipv4-encap \
	--entry vyatta:ipv6-encap \
	--entry vyatta:ipv4-encap-only \
	--entry vyatta:ipv6-encap-only \
	--entry vyatta:ipv4-l4 \
	--entry vyatta:ipv6-l4 \
	--entry vyatta:l2-consume \
	--entry vyatta:l2-local \
	--entry vyatta:l2-output \
	--entry vyatta:term-drop \
	--entry vyatta:ipv4-drop \
	--entry vyatta:ipv6-drop \
	--feature-point vyatta:ether-lookup \
	--feature-point vyatta:ipv4-drop \
	--feature-point vyatta:ipv4-l4 \
	--feature-point vyatta:ipv4-validate \
	--feature-point vyatta:ipv4-route-lookup \
	--feature-point vyatta:ipv4-out \
	--feature-point vyatta:ipv4-encap \
	--feature-point vyatta:ipv4-udp-in \
	--feature-point vyatta:ipv6-drop \
	--feature-point vyatta:ipv6-l4 \
	--feature-point vyatta:ipv6-validate \
	--feature-point vyatta:ipv6-route-lookup \
	--feature-point vyatta:ipv6-out \
	--feature-point vyatta:ipv6-encap \
	--feature-point vyatta:ipv6-udp-in \
	--feature-point vyatta:l2-consume \
	--feature-point vyatta:l2-local \
	--feature-point vyatta:l2-output \
	--feature-point vyatta:term-drop

src/pipeline/pl_fused_gen.h: $(PIPELINE_NODE_FILES) $(srcdir)/scripts/pl_gen_fused
	$(AM_V_GEN)$(srcdir)/scripts/pl_gen_fused $(PL_GEN_FUSED_OPTS) --header-out $@ $(PIPELINE_NODE_FILES:%=$(srcdir)/%)
src/pipeline/pl_fused_gen.c: $(PIPELINE_NODE_FILES) $(srcdir)/scripts/pl_gen_fused src/pipeline/pl_fused_gen.h
	$(AM_V_GEN)$(srcdir)/scripts/pl_gen_fused $(PL_GEN_FUSED_OPTS) --impl-out $@ $(PIPELINE_NODE_FILES:%=$(srcdir)/%)

BUILT_SOURCES = src/pipeline/pl_fused_gen.h $(PROTO_FILES:.proto=.pb-c.h) $(SAMPLE_PROTO_FILES:.proto=.pb-c.h)
BUILT_SOURCES += $(PROTO_FILES:.proto=.pb.h)
CLEANFILES = src/pipeline/pl_fused_gen.h src/pipeline/pl_fused_gen.c
CLEANFILES += $(PROTO_FILES:.proto=.pb-c.c) $(PROTO_FILES:.proto=.pb-c.h)
CLEANFILES += $(SAMPLE_PROTO_FILES:.proto=.pb-c.c) $(SAMPLE_PROTO_FILES:.proto=.pb-c.h)
CLEANFILES += $(PROTO_FILES:.proto=.pb.c) $(PROTO_FILES:.proto=.pb.h)

PROTO_FILES = \
	protobuf/DataplaneEnvelope.proto \
	protobuf/XConnectConfig.proto \
	protobuf/PPPOEConfig.proto \
	protobuf/TCPMSSConfig.proto \
	protobuf/PipelineStatsConfig.proto \
	protobuf/CryptoPolicyConfig.proto \
	protobuf/IPAddress.proto \
	protobuf/VFPSetConfig.proto \
	protobuf/cpp_rl.proto \
	protobuf/IP6RedirectsConfig.proto \
	protobuf/SpeedConfig.proto \
	protobuf/GArpConfig.proto \
	protobuf/CgnatLogging.proto \
	protobuf/BreakoutConfig.proto


SAMPLE_PROTO_FILES = src/pipeline/nodes/sample/SampleFeatConfig.proto \
	src/pipeline/nodes/sample/SampleFeatOp.proto

%.pb-c.c %.pb-c.h: %.proto
	$(AM_V_GEN)@PROTOC_C@ -I=$(dir $^) --c_out=$(dir $@) $^

%.pb.cc %.pb.h: %.proto
	$(AM_V_GEN)protoc -I=$(dir $^) --cpp_out=$(dir $@) $^

%_pb2.py: %.proto
	$(AM_V_GEN)protoc -I=$(dir $^) --python_out=$(dir $@) $^

%.pm: %.proto
	$(AM_V_GEN)$(srcdir)/scripts/vyatta-generate-pb-perl.pl $^ $(dir $@)

%.pb.go: %.proto
	$(AM_V_GEN)protoc -I=$(dir $^) --go_out=paths=source_relative:$(dir $@) $^

protopythonmodulesdir=$(prefix)/lib/python3/dist-packages/vyatta/proto
protopythonmodules_DATA = $(PROTO_FILES:%.proto=%_pb2.py)

protoperlmodulesdir=$(datarootdir)/perl5/vyatta/proto
protoperlmodules_DATA = $(PROTO_FILES:%.proto=%.pm)

GO_PROTO_GENERATED_FILES = $(foreach P,$(basename $(notdir $(PROTO_FILES))),protobuf/go/$P/$P.pb.go)

$(GO_PROTO_GENERATED_FILES): $(PROTO_FILES:%.proto=%.pb.go)
#	Copy the generated protobuf files into an appropriate go package
#	structure.
	mkdir -p $(dir $@)
	cp protobuf/$(notdir $@) $(dir $@)

protogopkgsdir=/usr/share/gocode/src/github.com/danos/vyatta-dataplane/
nobase_protogopkgs_DATA = $(GO_PROTO_GENERATED_FILES)

pkgconfig_DATA = protobuf/vyatta-dataplane-proto.pc debian/vyatta-dataplane-dev.pc debian/libvyattafal.pc
lib_LTLIBRARIES = libvyatta-dataplane-proto.la
libvyatta_dataplane_proto_la_SOURCES = $(PROTO_FILES:.proto=.pb.cc)
libvyatta_dataplane_proto_la_CPPFLAGS = $(AM_CPPFLAGS) $(shell pkg-config --cflags protobuf)
libvyatta_dataplane_proto_la_LDFLAGS = $(shell pkg-config --cflags --libs protobuf) -version-info 1:0:0 -shared

includeprotodir = /usr/include/vyatta-dataplane/protobuf
includeproto_HEADERS = $(PROTO_FILES:%.proto=%.pb.h) $(PROTO_FILES:%.proto=%.pb-c.h)

sbin_PROGRAMS = dataplane
bin_PROGRAMS = dataplane_test

dataplane_SOURCES = $(CORE_FILES) $(FILES_NOT_FOR_TEST) $(CRYTPO_FILES) $(IPV6_FILES) $(NPF_FILES) $(MPLS_FILES) $(DPI_FILES) $(PIPELINE_FILES) $(SESSION_FILES) $(PROTO_FILES:.proto=.pb-c.c)

dataplane_CPPFLAGS = $(AM_CPPFLAGS)
dataplane_CPPFLAGS += -I./src \
		      -I$(srcdir)/include \
		      -I$(srcdir)/src \
		      -I$(srcdir)/src/npf \
		      -I$(srcdir)/src/netinet6 \
		      -I$(srcdir)/src/pipeline \
		      -I$(builddir)/src/pipeline

dataplane_CFLAGS = $(EXTRA_CFLAGS) $(DPDK_CFLAGS) $(DPI_CFLAGS) $(LIBMNL_CFLAGS) $(LIBCAP_CFLAGS) $(LIBCZMQ_CFLAGS) $(LIBZMQ_CFLAGS) $(LIBURCU_QSBR_CFLAGS) $(LIBURCU_CDS_CFLAGS) $(LIBOSIP2_CFLAGS) $(LIBCRYPTO_CFLAGS) -O3 $(DATAPLANE_LTO_FLAG) -DNDEBUG -DFUSED_MODE $(PTHREAD_CFLAGS) $(SYSTEMD_CFLAGS) -ffunction-sections

dataplane_LDFLAGS = $(EXTRA_LDFLAGS) $(OTHER_LINKER_FLAGS)
dataplane_LDADD = $(DPDK_LIBS) $(DPI_LIBS) $(LIBMNL_LIBS) $(LIBCAP_LIBS) $(LIBCZMQ_LIBS) $(LIBZMQ_LIBS) $(LIBURCU_QSBR_LIBS) $(LIBURCU_CDS_LIBS) $(LIBOSIP2_LIBS) $(LIBCRYPTO_LIBS) $(PTHREAD_LIBS) $(SYSTEMD_LIBS) -ldl $(PROTOBUF_C_LIBS) $(SWPORT_LIBS)
EXTRA_dataplane_DEPENDENCIES = $(srcdir)/dataplane.section-ordering


dataplane_test_SOURCES = $(CORE_FILES) $(CRYTPO_FILES) $(IPV6_FILES) $(NPF_FILES) $(MPLS_FILES) $(DPI_FILES) $(PIPELINE_FILES) $(SESSION_FILES) $(PROTO_FILES:.proto=.pb-c.c) $(SAMPLE_PROTO_FILES:.proto=.pb-c.c) $(CONNSYNC_FILES)
dataplane_test_SOURCES += \
	tests/common/src/dp_test_pktmbuf_lib.c \
	tests/common/src/dp_test_crypto_lib.c \
	tests/whole_dp/src/dp_test.c \
	tests/whole_dp/src/dp_test_arp.c \
	tests/whole_dp/src/dp_test_bitmask.c \
	tests/whole_dp/src/dp_test_bridge.c \
	tests/whole_dp/src/dp_test_bridge_vlan_filter.c \
	tests/whole_dp/src/dp_test_bridge_n.c \
	tests/whole_dp/src/dp_test_cmd_check.c \
	tests/whole_dp/src/dp_test_cmd_state.c \
	tests/whole_dp/src/dp_test_console.c \
	tests/whole_dp/src/dp_test_controller.c \
	tests/whole_dp/src/dp_test_cpp_lim.c \
	tests/whole_dp/src/dp_test_cpp_lim_fal.c \
	tests/whole_dp/src/dp_test_cross_connect.c \
	tests/whole_dp/src/dp_test_crypto_block_policy.c \
	tests/whole_dp/src/dp_test_crypto_multi_tunnel.c \
	tests/whole_dp/src/dp_test_crypto_perf_scale.c \
	tests/whole_dp/src/dp_test_crypto_policy.c \
	tests/whole_dp/src/dp_test_crypto_site_to_site.c \
	tests/whole_dp/src/dp_test_crypto_site_to_site_passthru.c \
	tests/whole_dp/src/dp_test_crypto_utils.c \
	tests/whole_dp/src/dp_test_esp.c \
	tests/whole_dp/src/dp_test_fails.c \
	tests/whole_dp/src/dp_test_gre.c \
	tests/whole_dp/src/dp_test_gre6.c \
	tests/whole_dp/src/dp_test_if_config.c \
	tests/whole_dp/src/dp_test_intf_incomplete.c \
	tests/whole_dp/src/dp_test_ip.c \
	tests/whole_dp/src/dp_test_ip_arp.c \
	tests/whole_dp/src/dp_test_ip_n.c \
	tests/whole_dp/src/dp_test_ip6.c \
	tests/whole_dp/src/dp_test_ip6_icmp.c \
	tests/whole_dp/src/dp_test_ip6_neigh.c \
	tests/whole_dp/src/dp_test_ip_icmp.c \
	tests/whole_dp/src/dp_test_ip_multicast.c \
	tests/whole_dp/src/dp_test_json_utils.c \
	tests/whole_dp/src/dp_test_lib.c \
	tests/whole_dp/src/dp_test_lib_cmd.c \
	tests/whole_dp/src/dp_test_lib_exp.c \
	tests/whole_dp/src/dp_test_lib_intf.c \
	tests/whole_dp/src/dp_test_lib_pb.c \
	tests/whole_dp/src/dp_test_lib_pkt.c \
	tests/whole_dp/src/dp_test_lib_portmonitor.c \
	tests/whole_dp/src/dp_test_lib_tcp.c \
	tests/whole_dp/src/dp_test_missed_netlink.c \
	tests/whole_dp/src/dp_test_mpls.c \
	tests/whole_dp/src/dp_test_mstp_cmds.c \
	tests/whole_dp/src/dp_test_mstp_fwd.c \
	tests/whole_dp/src/dp_test_nat.c \
	tests/whole_dp/src/dp_test_netlink_state.c \
	tests/whole_dp/src/dp_test_npf_commands.c \
	tests/whole_dp/src/dp_test_npf_feat.c \
	tests/whole_dp/src/dp_test_npf_defrag.c \
	tests/whole_dp/src/dp_test_npf_golden.c \
	tests/whole_dp/src/dp_test_npf_bridge.c \
	tests/whole_dp/src/dp_test_npf_cgnat.c \
	tests/whole_dp/src/dp_test_npf_dscp.c \
	tests/whole_dp/src/dp_test_npf_tblset.c \
	tests/whole_dp/src/dp_test_npf_addrgrp.c \
	tests/whole_dp/src/dp_test_npf_fw.c \
	tests/whole_dp/src/dp_test_npf_fw_ipv6.c \
	tests/whole_dp/src/dp_test_npf_fw_lib.c \
	tests/whole_dp/src/dp_test_npf_hairpin.c \
	tests/whole_dp/src/dp_test_npf_icmp.c \
	tests/whole_dp/src/dp_test_npf_lib.c \
	tests/whole_dp/src/dp_test_npf_local.c \
	tests/whole_dp/src/dp_test_npf_mbuf.c \
	tests/whole_dp/src/dp_test_npf_ptree.c \
	tests/whole_dp/src/dp_test_npf_nat.c \
	tests/whole_dp/src/dp_test_npf_nat64.c \
	tests/whole_dp/src/dp_test_npf_nat_lib.c \
	tests/whole_dp/src/dp_test_npf_nptv6.c \
	tests/whole_dp/src/dp_test_npf_apt.c \
	tests/whole_dp/src/dp_test_npf_alg_lib.c \
	tests/whole_dp/src/dp_test_npf_alg_sip_call.c \
	tests/whole_dp/src/dp_test_npf_alg_sip_lib.c \
	tests/whole_dp/src/dp_test_npf_alg_sip_parse.c \
	tests/whole_dp/src/dp_test_npf_alg_ftp.c \
	tests/whole_dp/src/dp_test_npf_alg_tftp.c \
	tests/whole_dp/src/dp_test_npf_alg_rpc.c \
	tests/whole_dp/src/dp_test_npf_alg_sip_1.c \
	tests/whole_dp/src/dp_test_npf_alg_sip_2.c \
	tests/whole_dp/src/dp_test_npf_alg_sip_3.c \
	tests/whole_dp/src/dp_test_npf_alg_sip_4.c \
	tests/whole_dp/src/dp_test_npf_qos.c \
	tests/whole_dp/src/dp_test_npf_portmap_lib.c \
	tests/whole_dp/src/dp_test_npf_prot_group.c \
	tests/whole_dp/src/dp_test_npf_ruleset_state.c \
	tests/whole_dp/src/dp_test_npf_sess_lib.c \
	tests/whole_dp/src/dp_test_npf_session_limit.c \
	tests/whole_dp/src/dp_test_npf_snat_overrun.c \
	tests/whole_dp/src/dp_test_npf_tcp.c \
	tests/whole_dp/src/dp_test_npf_vti.c \
	tests/whole_dp/src/dp_test_npf_zone.c \
	tests/whole_dp/src/dp_test_pbr.c \
	tests/whole_dp/src/dp_test_pipeline.c \
	tests/whole_dp/src/dp_test_poe_cmds.c \
	tests/whole_dp/src/dp_test_portmonitor_commands.c \
	tests/whole_dp/src/dp_test_portmonitor.c \
	tests/whole_dp/src/dp_test_ppp.c \
	tests/whole_dp/src/dp_test_ptp.c \
	tests/whole_dp/src/dp_test_qos_basic.c \
	tests/whole_dp/src/dp_test_qos_burst.c \
	tests/whole_dp/src/dp_test_qos_ext_buf_monitor.c \
	tests/whole_dp/src/dp_test_qos_fal.c \
	tests/whole_dp/src/dp_test_qos_class.c \
	tests/whole_dp/src/dp_test_qos_lib.c \
	tests/whole_dp/src/dp_test_route_broker.c \
	tests/whole_dp/src/dp_test_route_tracker.c \
	tests/whole_dp/src/dp_test_slow_path.c \
	tests/whole_dp/src/dp_test_session_internal_lib.c \
	tests/whole_dp/src/dp_test_session_lib.c \
	tests/whole_dp/src/dp_test_session.c \
	tests/whole_dp/src/dp_test_session_cmds.c \
	tests/whole_dp/src/dp_test_sfp.c \
	tests/whole_dp/src/dp_test_storm_ctl.c \
	tests/whole_dp/src/dp_test_str.c \
	tests/whole_dp/src/dp_test_stubs.c \
	tests/whole_dp/src/dp_test_stubs_linux.c \
	tests/whole_dp/src/dp_test_switch.c \
	tests/whole_dp/src/dp_test_switch_vlan.c \
	tests/whole_dp/src/dp_test_tcp_mss_clamp.c \
	tests/whole_dp/src/dp_test_vrf.c \
	tests/whole_dp/src/dp_test_vti.c \
	tests/whole_dp/src/dp_test_vxlan.c \
	tests/whole_dp/src/dp_test_wrapped_funcs.c \
	tests/whole_dp/src/dp_test_xfrm.c

fal_plugin_test_la_SOURCES = \
	tests/whole_dp/src/fal_plugin_test.c \
	tests/whole_dp/src/fal_plugin_sw_port.c \
	tests/whole_dp/src/fal_plugin_framer.c \
	tests/whole_dp/src/fal_plugin_qos.c \
	tests/whole_dp/src/fal_plugin_pm.c \
	tests/whole_dp/src/fal_plugin_policer.c \
	tests/whole_dp/src/fal_plugin_cpp_limiter.c \
	tests/whole_dp/src/fal_plugin_ptp.c

pkginclude_HEADERS = \
	include/bridge_flags.h \
	include/bridge_vlan_set.h \
	include/compiler.h \
	include/config.h \
	include/debug.h \
	include/dpi.h \
	include/dp_session.h \
	include/dp_test/dp_test_cmd_check.h \
	include/dp_test/dp_test_lib.h \
	include/dp_test/dp_test_lib_intf.h \
	include/dp_test/dp_test_macros.h \
	include/dp_test/dp_test_netlink_state.h \
	include/dp_test/dp_test_pktmbuf_lib.h \
	include/dp_test/dp_test_firewall_lib.h \
	include/dp_test/dp_test_session_lib.h \
	include/event.h \
	include/fal_bfd.h \
	include/fal_plugin.h \
	include/feature_commands.h \
	include/feature_plugin.h \
	include/interface.h \
	include/ip.h \
	include/ip_checksum.h \
	include/ip_forward.h \
	include/json_writer.h \
	include/lcore_sched.h \
	include/pktmbuf.h \
	include/pipeline.h \
	include/protobuf_util.h \
	include/urcu.h	\
	include/vrf.h

pkgplugindir = $(pkglibdir)/pipeline/plugins

pkgplugin_LTLIBRARIES = sample_plugin.la
sample_plugin_la_SOURCES = src/pipeline/nodes/sample/sample.c $(SAMPLE_PROTO_FILES:.proto=.pb-c.c)
sample_plugin_la_CPPFLAGS = -I$(srcdir)/include -I$(builddir)/src/pipeline/nodes/sample $(DPDK_CFLAGS) -I$(builddir)/src/pipeline/nodes/sample
sample_plugin_la_LDFLAGS = -avoid-version -module -shared -export-dynamic

if DATAPLANE_SANITIZER
dataplane_CFLAGS += -fsanitize=address -DSANITIZE_ADDRESS
dataplane_LDFLAGS += -fsanitize=address
export SANITIZER = SANITIZER
export ASAN_OPTIONS = verify_asan_link_order=0:detect_leaks=0
endif

@CODE_COVERAGE_RULES@

@VALGRIND_CHECK_RULES@
VALGRIND_FLAGS = --trace-children=yes
VALGRIND_SUPPRESSIONS_FILES = $(srcdir)/tests/whole_dp/valgrind_suppressions
EXTRA_DIST = $(VALGRIND_SUPPRESSIONS_FILES)

dataplane_test_CPPFLAGS = $(dataplane_CPPFLAGS) $(JSON_C_CFLAGS)
dataplane_test_CPPFLAGS += -I$(srcdir)/tests/whole_dp/src -I$(srcdir)/tests/common/inc
dataplane_test_CPPFLAGS += $(sample_plugin_la_CPPFLAGS)

dataplane_test_CFLAGS = $(dataplane_CFLAGS) -fno-lto -UNDEBUG -O0 -g $(CODE_COVERAGE_CFLAGS)
dataplane_test_CFLAGS += -Wno-unused-parameter

dataplane_test_LDADD =  $(CHECK_LIBS) $(JSON_C_LIBS) $(CODE_COVERAGE_LIBS) $(dataplane_LDADD)

dataplane_test_LDFLAGS = $(dataplane_LDFLAGS)
dataplane_test_LDFLAGS += -Wl,-wrap,main
dataplane_test_LDFLAGS += -Wl,-wrap,RAND_bytes
dataplane_test_LDFLAGS += -Wl,-wrap,rte_pktmbuf_pool_create
dataplane_test_LDFLAGS += -Wl,-wrap,rte_mempool_create
dataplane_test_LDFLAGS += -Wl,-wrap,rte_eal_init
dataplane_test_LDFLAGS += -Wl,-wrap,popen
dataplane_test_LDFLAGS += -Wl,-wrap,pclose
EXTRA_dataplane_test_DEPENDENCIES = $(EXTRA_dataplane_DEPENDENCIES) tests/whole_dp/dummyfs/run/dataplane/platform.conf

dist_check_SCRIPTS = tests/whole_dp/dataplane_test.sh
fal_plugin_test_la_CPPFLAGS = $(dataplane_CPPFLAGS) $(JSON_C_CFLAGS)
fal_plugin_test_la_CPPFLAGS += -I$(srcdir)/tests/whole_dp/src -I$(srcdir)/tests/common/inc $(SWPORT_CFLAGS)

fal_plugin_test_la_CFLAGS = $(dataplane_CFLAGS) -fPIC -UNDEBUG -O0 -g $(CODE_COVERAGE_CFLAGS)
fal_plugin_test_la_CFLAGS += -Wno-unused-parameter

fal_plugin_test_la_LIBADD = $(dataplane_LDADD) $(CHECK_LIBS) $(JSON_C_LIBS) $(CODE_COVERAGE_LIBS)

fal_plugin_test_la_LDFLAGS = $(EXTRA_LDFLAGS) $(SWPORT_LIBS)
fal_plugin_test_la_LDFLAGS += -avoid-version -module -shared -export-dynamic
fal_plugin_test_la_LDFLAGS += -export-symbols $(srcdir)/tests/whole_dp/src/fal_plugin_test.sym

tests/whole_dp/dummyfs/run/dataplane/platform.conf:
	mkdir -p `dirname $@`
	echo '[dataplane]' > $@
	echo 'fal_plugin = .libs/fal_plugin_test.so' >> $@

if WHOLE_DP_TEST
pkglib_LTLIBRARIES = fal_plugin_test.la
check_PROGRAMS = dataplane_test
TESTS = $(dist_check_SCRIPTS)
endif

if WHOLE_DP_ALL_TESTS
dataplane_test_CFLAGS += -DDP_TEST_FULL_RUN
endif

DATAPLANE_TEST_ARGS = $(__dataplane_test_args_@AM_V@)
__dataplane_test_args_ = $(__dataplane_test_args_@AM_DEFAULT_V@)
__dataplane_test_args_0 = "-d0"
__dataplane_test_args_1 = "-d2"

dataplane_test_run: dataplane_test
	catchsegv ./dataplane_test -P $(builddir)/.libs $(DATAPLANE_TEST_ARGS)

.PHONY: dataplane_test_run

vyattasysconfdir=$(sysconfdir)/vyatta
vyattasysconf_DATA = dataplane-drivers.conf

vyattadatadir=$(datadir)/vyatta
vyattadata_DATA = dataplane-drivers-default.conf

vyattadpdatadir=$(datadir)/vyatta-dataplane/protobuf
vyattadpdata_DATA = $(PROTO_FILES)
