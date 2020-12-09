/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane ptp command tests
 */

#include <libmnl/libmnl.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "ptp.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"

#define POLL_CNT 1

struct dp_test_command_t {
	const char *cmd;
	const char *exp_reply; /* expected reply */
	bool        exp_ok;    /* expected cmd success or fail */
	bool        exp_json;  /* true if json response expected */
};

static const struct dp_test_command_t ptp_cmds[] = {
	/* setup and delete a two port boundary clock */
	{
		"ptp-ut clock create 0 "
			"domain-number=0 "
			"number-ports=2 "
			"clock-identity=0:1:2:3:4:5:6:7 "
			"priority1=128 "
			"priority2=128 "
			"slave-only=0 "
			"two-step=0 "
			"profile=default-profile",
		"",
		true,
		false,
	},
	{
		"ptp-ut port create 1 "
			"clock-id=0 "
			"underlying-interface=dpT10 "
			"vlan-id=10 "
			"log-min-delay-req-interval=1 "
			"log-announce-interval=2 "
			"announce-receipt-timeout=3 "
			"log-min-pdelay-req-interval=1 "
			"log-sync-interval=1 "
			"ip=192.168.10.1 "
			"mac=0:0:0:0:a:1 "
			"dscp=0 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer create "
			"clock-id=0 "
			"port-id=1 "
			"type=master "
			"ip=192.168.10.2 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut port create 2 "
			"clock-id=0 "
			"underlying-interface=dpT11 "
			"vlan-id=20 "
			"log-min-delay-req-interval=1 "
			"log-announce-interval=2 "
			"announce-receipt-timeout=3 "
			"log-min-pdelay-req-interval=1 "
			"log-sync-interval=1 "
			"ip=192.168.20.1 "
			"mac=0:0:0:0:14:1 "
			"dscp=0 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer create "
			"clock-id=0 "
			"port-id=2 "
			"type=slave "
			"ip=192.168.20.2 ",
		"",
		true,
		false,
	},
	{
		"ptp clock dump 0",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer delete clock-id=0 port-id=1 type=master ip=192.168.10.2",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer delete clock-id=0 port-id=2 type=slave ip=192.168.20.2",
		"",
		true,
		false,
	},
	{
		"ptp-ut port delete 1 clock-id=0",
		"",
		true,
		false,
	},
	{
		"ptp-ut port delete 2 clock-id=0",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock delete 0",
		"",
		true,
		false,
	},

	/* redundant deletes should fail */
	{
		"ptp-ut clock delete 0",
		"ptp: unable to find clock 0",
		false,
		false,
	},

	/* missing clock */
	{
		"ptp-ut port delete 1",
		"ptp: specify clock for port 1",
		false,
		false,
	},

	/* non-existent clock */
	{
		"ptp-ut port delete 1 clock-id=0",
		"ptp: clock 0 does not exist",
		false,
		false,
	},

	/* missing required elements */
	{
		"ptp-ut peer delete clock-id=0 port-id=1",
		"ptp: type required for peer",
		false,
		false,
	},
	{
		"ptp-ut peer delete clock-id=0 port-id=1 type=master",
		"ptp: ip address required for peer",
		false,
		false,
	},
	/* test g.8275.2 profiles */
	{
		"ptp-ut clock create 0 "
			"domain-number=0 "
			"number-ports=2 "
			"clock-identity=0:1:2:3:4:5:6:7 "
			"priority1=128 "
			"priority2=128 "
			"slave-only=0 "
			"two-step=0 "
			"profile=g82752-profile",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock delete 0",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock create 0 "
			"domain-number=0 "
			"number-ports=2 "
			"clock-identity=0:1:2:3:4:5:6:7 "
			"priority1=128 "
			"priority2=128 "
			"slave-only=0 "
			"two-step=0 "
			"antenna-delay=100 "
			"profile=g82752-apts-profile",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock delete 0",
		"",
		true,
		false,
	},
	/* additional-path */
	{
		"ptp-ut clock create 0 "
			"domain-number=0 "
			"number-ports=1 "
			"clock-identity=0:1:2:3:4:5:6:7 "
			"priority1=128 "
			"priority2=128 "
			"slave-only=0 "
			"two-step=0 "
			"profile=default-profile",
		"",
		true,
		false,
	},
	{
		"ptp-ut port create 1 "
			"clock-id=0 "
			"underlying-interface=dpT10 "
			"vlan-id=10 "
			"log-min-delay-req-interval=1 "
			"log-announce-interval=2 "
			"announce-receipt-timeout=3 "
			"log-min-pdelay-req-interval=1 "
			"log-sync-interval=1 "
			"ip=192.168.10.1 "
			"mac=0:0:0:0:a:1 "
			"dscp=0 "
			"additional-path=dpT11,100 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut port delete 1 clock-id=0",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock delete 0",
		"",
		true,
		false,
	},
	/* test g.8275.1 profiles */
	{
		"ptp-ut clock create 0 "
			"domain-number=24 "
			"number-ports=2 "
			"clock-identity=0:1:2:3:4:5:6:7 "
			"priority1=128 "
			"priority2=128 "
			"slave-only=0 "
			"two-step=0 "
			"profile=g82751-forwardable-profile",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock delete 0",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock create 0 "
			"domain-number=24 "
			"number-ports=2 "
			"clock-identity=0:1:2:3:4:5:6:7 "
			"priority1=128 "
			"priority2=128 "
			"slave-only=0 "
			"two-step=0 "
			"antenna-delay=100 "
			"profile=g82751-non-forwardable-profile",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock delete 0",
		"",
		true,
		false,
	},
	/* test multiple peers with the same IP address */
	{
		"ptp-ut clock create 0 "
			"domain-number=0 "
			"number-ports=2 "
			"clock-identity=0:1:2:3:4:5:6:7 "
			"priority1=128 "
			"priority2=128 "
			"slave-only=0 "
			"two-step=0 "
			"profile=default-profile",
		"",
		true,
		false,
	},
	{
		"ptp-ut port create 1 "
			"clock-id=0 "
			"underlying-interface=dpT10 "
			"vlan-id=10 "
			"log-min-delay-req-interval=1 "
			"log-announce-interval=2 "
			"announce-receipt-timeout=3 "
			"log-min-pdelay-req-interval=1 "
			"log-sync-interval=1 "
			"ip=192.168.10.1 "
			"mac=0:0:0:0:a:1 "
			"dscp=0 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut port create 2 "
			"clock-id=0 "
			"underlying-interface=dpT11 "
			"vlan-id=20 "
			"log-min-delay-req-interval=1 "
			"log-announce-interval=2 "
			"announce-receipt-timeout=3 "
			"log-min-pdelay-req-interval=1 "
			"log-sync-interval=1 "
			"ip=192.168.10.1 "
			"mac=0:0:0:0:a:1 "
			"dscp=0 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer create clock-id=0 port-id=1 type=master ip=192.168.10.2 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer create clock-id=0 port-id=2 type=master ip=192.168.10.2 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer delete clock-id=0 port-id=2 type=master ip=192.168.10.2",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer delete clock-id=0 port-id=1 type=master ip=192.168.10.2",
		"",
		true,
		false,
	},
	{
		"ptp-ut port delete 2 clock-id=0",
		"",
		true,
		false,
	},
	{
		"ptp-ut port delete 1 clock-id=0",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock delete 0",
		"",
		true,
		false,
	},
	/* test create/delete of hotplug ports */
	{
		"ptp-ut clock create 0 "
			"domain-number=0 "
			"number-ports=1 "
			"clock-identity=0:1:2:3:4:5:6:7 "
			"priority1=128 "
			"priority2=128 "
			"slave-only=0 "
			"two-step=0 "
			"profile=default-profile",
		"",
		true,
		false,
	},
	{
		"ptp-ut port create 1 "
			"clock-id=0 "
			"underlying-interface=dp0ce0p1 "
			"vlan-id=10 "
			"log-min-delay-req-interval=1 "
			"log-announce-interval=2 "
			"announce-receipt-timeout=3 "
			"log-min-pdelay-req-interval=1 "
			"log-sync-interval=1 "
			"ip=192.168.10.1 "
			"mac=0:0:0:0:a:1 "
			"dscp=0 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer create clock-id=0 port-id=1 type=master ip=192.168.10.2 ",
		"",
		true,
		false,
	},
	{
		"ptp-ut peer delete clock-id=0 port-id=1 type=master ip=192.168.10.2",
		"",
		true,
		false,
	},
	{
		"ptp-ut port delete 1 clock-id=0",
		"",
		true,
		false,
	},
	{
		"ptp-ut clock delete 0",
		"",
		true,
		false,
	},
};

DP_DECL_TEST_SUITE(ptp);

DP_DECL_TEST_CASE(ptp, ptp_cmds, NULL, NULL);

DP_START_TEST(ptp_cmds, basic)
{
	unsigned int i;
	json_object *jexp;

	for (i = 0; i < ARRAY_SIZE(ptp_cmds); i++) {
		if (ptp_cmds[i].exp_json) {
			jexp = dp_test_json_create("%s",
					ptp_cmds[i].exp_reply);
			dp_test_check_json_poll_state(
					ptp_cmds[i].cmd, jexp,
					DP_TEST_JSON_CHECK_SUBSET,
					false, POLL_CNT);
			json_object_put(jexp);
		} else {
			dp_test_check_state_poll_show(
					ptp_cmds[i].cmd,
					ptp_cmds[i].exp_reply,
					ptp_cmds[i].exp_ok,
					false, POLL_CNT);
		}
	}
} DP_END_TEST;

DP_START_TEST(ptp_cmds, resolver)
{
	struct rte_mbuf *mbufs[64];
	int i, count;
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();

	bridge_vlan_set_add(allowed_vlans, 10);
	bridge_vlan_set_add(allowed_vlans, 20);

	dp_test_intf_bridge_create("sw0");
	dp_test_intf_vif_create("sw0.10", "sw0", 10);
	dp_test_intf_vif_create("sw0.20", "sw0", 20);
	dp_test_intf_bridge_enable_vlan_filter("sw0");
	dp_test_intf_bridge_add_port("sw0", "dpT10");
	dp_test_intf_bridge_add_port("sw0", "dpT11");
	dp_test_intf_bridge_port_set_vlans("sw0", "dpT10", 0,
					   allowed_vlans, NULL);
	dp_test_intf_bridge_port_set_vlans("sw0", "dpT11", 0,
					   allowed_vlans, NULL);

	dp_test_nl_add_ip_addr_and_connected("sw0.10", "192.168.10.1/24");
	dp_test_nl_add_ip_addr_and_connected("sw0.20", "192.168.20.1/24");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut clock create 0 "
				"domain-number=0 "
				"number-ports=2 "
				"clock-identity=0:1:2:3:4:5:6:7 "
				"priority1=128 "
				"priority2=128 "
				"slave-only=0 "
				"two-step=0 "
				"profile=default-profile");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port create 1 "
				"clock-id=0 "
				"underlying-interface=dpT10 "
				"vlan-id=10 "
				"log-min-delay-req-interval=1 "
				"log-announce-interval=2 "
				"announce-receipt-timeout=3 "
				"log-min-pdelay-req-interval=1 "
				"log-sync-interval=1 "
				"ip=192.168.10.1 "
				"mac=0:0:0:0:a:1 "
				"dscp=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer create "
				"clock-id=0 "
				"port-id=1 "
				"type=master "
				"ip=192.168.10.2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port create 2 "
				"clock-id=0 "
				"underlying-interface=dpT11 "
				"vlan-id=20 "
				"log-min-delay-req-interval=1 "
				"log-announce-interval=2 "
				"announce-receipt-timeout=3 "
				"log-min-pdelay-req-interval=1 "
				"log-sync-interval=1 "
				"ip=192.168.20.1 "
				"mac=0:0:0:0:14:1 "
				"dscp=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer create "
				"clock-id=0 "
				"port-id=2 "
				"type=slave "
				"ip=192.168.20.2");

	dp_test_check_state_show("ptp resolver trigger", "", true);

	/* Until we have neighbors, the peers will not install. */
	dp_test_check_state_show("ptp resolver dump",
			"{[{\n"
			"            \"peer\": \"192.168.20.2\",\n"
			"            \"installed\": false,\n"
			"            \"port-id\": 2,\n"
			"            \"type\": \"slave\"\n"
			"        },{\n"
			"            \"peer\": \"192.168.10.2\",\n"
			"            \"installed\": false,\n"
			"            \"port-id\": 1,\n"
			"            \"type\": \"master\"\n"
			"        }\n"
			"    ]\n"
			"    }\n", true);

	/* There should be two ARPs per interface  */
	count = dp_test_pak_get_from_ring("dpT10", mbufs, 64);
	for (i = 0; i < count; i++)
		rte_pktmbuf_free(mbufs[i]);
	dp_test_assert_internal(count == 2);

	count = dp_test_pak_get_from_ring("dpT11", mbufs, 64);
	for (i = 0; i < count; i++)
		rte_pktmbuf_free(mbufs[i]);
	dp_test_assert_internal(count == 2);

	/* Add peer resolution and re-run the resolver */
	dp_test_netlink_add_neigh("sw0.10", "192.168.10.2", "0:0:0:0:0:1");
	dp_test_netlink_add_neigh("sw0.20", "192.168.20.2", "0:0:0:0:0:2");
	dp_test_check_state_show("ptp resolver trigger", "", true);

	dp_test_check_state_show("ptp resolver dump",
			"{[{\n"
			"            \"peer\": \"192.168.20.2\",\n"
			"            \"installed\": true,\n"
			"            \"port-id\": 2,\n"
			"            \"mac\": \"0:0:0:0:0:2\",\n"
			"            \"type\": \"slave\"\n"
			"        },{\n"
			"            \"peer\": \"192.168.10.2\",\n"
			"            \"installed\": true,\n"
			"            \"port-id\": 1,\n"
			"            \"mac\": \"0:0:0:0:0:1\",\n"
			"            \"type\": \"master\"\n"
			"        }\n"
			"    ]\n"
			"    }\n", true);

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer delete "
				"clock-id=0 port-id=1 "
				"type=master "
				"ip=192.168.10.2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer delete "
				"clock-id=0 "
				"port-id=2 "
				"type=slave "
				"ip=192.168.20.2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port delete 1 clock-id=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port delete 2 clock-id=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut clock delete 0");

	dp_test_netlink_del_neigh("sw0.10", "192.168.10.2", "0:0:0:0:0:1");
	dp_test_netlink_del_neigh("sw0.20", "192.168.20.2", "0:0:0:0:0:2");
	dp_test_nl_del_ip_addr_and_connected("sw0.10", "192.168.10.1/24");
	dp_test_nl_del_ip_addr_and_connected("sw0.20", "192.168.20.1/24");
	dp_test_intf_bridge_remove_port("sw0", "dpT11");
	dp_test_intf_bridge_remove_port("sw0", "dpT10");
	dp_test_intf_vif_del("sw0.10", 10);
	dp_test_intf_vif_del("sw0.20", 20);
	dp_test_intf_bridge_del("sw0");
	bridge_vlan_set_free(allowed_vlans);

} DP_END_TEST;

DP_START_TEST(ptp_cmds, resolver_two_uplinks)
{
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();

	bridge_vlan_set_add(allowed_vlans, 10);
	bridge_vlan_set_add(allowed_vlans, 20);

	dp_test_intf_bridge_create("sw0");
	dp_test_intf_vif_create("sw0.10", "sw0", 10);
	dp_test_intf_vif_create("sw0.20", "sw0", 20);
	dp_test_intf_bridge_enable_vlan_filter("sw0");
	dp_test_intf_bridge_add_port("sw0", "dpT10");
	dp_test_intf_bridge_add_port("sw0", "dpT11");
	dp_test_intf_bridge_port_set_vlans("sw0", "dpT10", 0,
					   allowed_vlans, NULL);
	dp_test_intf_bridge_port_set_vlans("sw0", "dpT11", 0,
					   allowed_vlans, NULL);

	dp_test_nl_add_ip_addr_and_connected("sw0.10", "192.168.10.1/24");
	dp_test_nl_add_ip_addr_and_connected("sw0.20", "192.168.20.1/24");
	dp_test_netlink_add_neigh("sw0.10", "192.168.10.2", "0:0:0:0:0:1");
	dp_test_netlink_add_neigh("sw0.20", "192.168.20.2", "0:0:0:0:0:2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut clock create 0 "
				"domain-number=0 "
				"number-ports=2 "
				"clock-identity=0:1:2:3:4:5:6:7 "
				"priority1=128 "
				"priority2=128 "
				"slave-only=0 "
				"two-step=0 "
				"profile=default-profile");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port create 1 "
				"clock-id=0 "
				"underlying-interface=dpT10 "
				"vlan-id=10 "
				"log-min-delay-req-interval=1 "
				"log-announce-interval=2 "
				"announce-receipt-timeout=3 "
				"log-min-pdelay-req-interval=1 "
				"log-sync-interval=1 "
				"ip=192.168.10.1 "
				"mac=0:0:0:0:a:1 "
				"dscp=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer create "
				"clock-id=0 "
				"port-id=1 "
				"type=master "
				"ip=192.168.30.2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port create 2 "
				"clock-id=0 "
				"underlying-interface=dpT11 "
				"vlan-id=20 "
				"log-min-delay-req-interval=1 "
				"log-announce-interval=2 "
				"announce-receipt-timeout=3 "
				"log-min-pdelay-req-interval=1 "
				"log-sync-interval=1 "
				"ip=192.168.20.1 "
				"mac=0:0:0:0:14:1 "
				"dscp=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer create "
				"clock-id=0 "
				"port-id=2 "
				"type=master "
				"ip=192.168.30.2");

	/* Until we have neighbors, the peers will not install. */
	dp_test_check_state_show("ptp resolver dump",
			"{[{\n"
			"            \"peer\": \"192.168.30.2\",\n"
			"            \"installed\": false,\n"
			"            \"port-id\": 1,\n"
			"            \"type\": \"master\"\n"
			"        },[{\n"
			"                \"peer\": \"192.168.30.2\",\n"
			"                \"installed\": false,\n"
			"                \"port-id\": 2,\n"
			"                \"type\": \"master\"\n"
			"            }\n"
			"        ]\n"
			"    ]\n"
			"    }\n", true);

	/* Add route to peer via sw0.10 and run the resolver */
	dp_test_netlink_add_route("192.168.30.0/24 nh 192.168.10.2 int:sw0.10");
	dp_test_check_state_show("ptp resolver trigger", "", true);

	dp_test_check_state_show("ptp resolver dump",
			"{[{\n"
			"            \"peer\": \"192.168.30.2\",\n"
			"            \"installed\": true,\n"
			"            \"port-id\": 1,\n"
			"            \"mac\": \"0:0:a5:0:3:e9\",\n"
			"            \"type\": \"master\"\n"
			"        },[{\n"
			"                \"peer\": \"192.168.30.2\",\n"
			"                \"installed\": false,\n"
			"                \"port-id\": 2,\n"
			"                \"type\": \"master\"\n"
			"            }\n"
			"        ]\n"
			"    ]\n"
			"    }\n", true);

	/* Move route to peer to sw0.20 and re-run the resolver */
	dp_test_netlink_del_route("192.168.30.0/24 nh 192.168.10.2 int:sw0.10");
	dp_test_netlink_add_route("192.168.30.0/24 nh 192.168.20.2 int:sw0.20");
	dp_test_check_state_show("ptp resolver trigger", "", true);

	dp_test_check_state_show("ptp resolver dump",
			"{[{\n"
			"            \"peer\": \"192.168.30.2\",\n"
			"            \"installed\": false,\n"
			"            \"port-id\": 1,\n"
			"            \"type\": \"master\"\n"
			"        },[{\n"
			"                \"peer\": \"192.168.30.2\",\n"
			"                \"installed\": true,\n"
			"                \"port-id\": 2,\n"
			"                \"mac\": \"0:0:a5:0:3:e9\",\n"
			"                \"type\": \"master\"\n"
			"            }\n"
			"        ]\n"
			"    ]\n"
			"    }\n", true);

	/* And if there are no routes, no peer should be active */
	dp_test_netlink_del_route("192.168.30.0/24 nh 192.168.20.2 int:sw0.20");
	dp_test_check_state_show("ptp resolver trigger", "", true);
	dp_test_check_state_show("ptp resolver dump",
			"{[{\n"
			"            \"peer\": \"192.168.30.2\",\n"
			"            \"installed\": false,\n"
			"            \"port-id\": 1,\n"
			"            \"type\": \"master\"\n"
			"        },[{\n"
			"                \"peer\": \"192.168.30.2\",\n"
			"                \"installed\": false,\n"
			"                \"port-id\": 2,\n"
			"                \"type\": \"master\"\n"
			"            }\n"
			"        ]\n"
			"    ]\n"
			"    }\n", true);

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer delete "
				"clock-id=0 port-id=1 "
				"type=master "
				"ip=192.168.30.2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer delete "
				"clock-id=0 "
				"port-id=2 "
				"type=master "
				"ip=192.168.30.2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port delete 1 clock-id=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port delete 2 clock-id=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut clock delete 0");

	dp_test_netlink_del_neigh("sw0.10", "192.168.10.2", "0:0:0:0:0:1");
	dp_test_netlink_del_neigh("sw0.20", "192.168.20.2", "0:0:0:0:0:2");
	dp_test_nl_del_ip_addr_and_connected("sw0.10", "192.168.10.1/24");
	dp_test_nl_del_ip_addr_and_connected("sw0.20", "192.168.20.1/24");
	dp_test_intf_bridge_remove_port("sw0", "dpT11");
	dp_test_intf_bridge_remove_port("sw0", "dpT10");
	dp_test_intf_vif_del("sw0.10", 10);
	dp_test_intf_vif_del("sw0.20", 20);
	dp_test_intf_bridge_del("sw0");
	bridge_vlan_set_free(allowed_vlans);

} DP_END_TEST;

DP_START_TEST(ptp_cmds, resolver_edge_cases)
{
	struct bridge_vlan_set *allowed_vlans = bridge_vlan_set_create();

	bridge_vlan_set_add(allowed_vlans, 10);
	bridge_vlan_set_add(allowed_vlans, 20);

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut clock create 0 "
				"domain-number=0 "
				"number-ports=2 "
				"clock-identity=0:1:2:3:4:5:6:7 "
				"priority1=128 "
				"priority2=128 "
				"slave-only=0 "
				"two-step=0 "
				"profile=default-profile");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port create 1 "
				"clock-id=0 "
				"underlying-interface=dpT10 "
				"vlan-id=10 "
				"log-min-delay-req-interval=1 "
				"log-announce-interval=2 "
				"announce-receipt-timeout=3 "
				"log-min-pdelay-req-interval=1 "
				"log-sync-interval=1 "
				"ip=192.168.10.1 "
				"mac=0:0:0:0:a:1 "
				"dscp=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer create "
				"clock-id=0 "
				"port-id=1 "
				"type=master "
				"ip=192.168.10.2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port create 2 "
				"clock-id=0 "
				"underlying-interface=dpT11 "
				"vlan-id=20 "
				"log-min-delay-req-interval=1 "
				"log-announce-interval=2 "
				"announce-receipt-timeout=3 "
				"log-min-pdelay-req-interval=1 "
				"log-sync-interval=1 "
				"ip=192.168.20.1 "
				"mac=0:0:0:0:14:1 "
				"dscp=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer create "
				"clock-id=0 "
				"port-id=2 "
				"type=slave "
				"ip=192.168.20.2");

	/* missing switch */
	dp_test_check_state_show("ptp resolver trigger", "", true);

	/* bridge configured */
	dp_test_intf_bridge_create("sw0");
	dp_test_intf_bridge_enable_vlan_filter("sw0");
	dp_test_intf_bridge_add_port("sw0", "dpT10");
	dp_test_intf_bridge_add_port("sw0", "dpT11");
	dp_test_intf_bridge_port_set_vlans("sw0", "dpT10", 0,
					   allowed_vlans, NULL);
	dp_test_intf_bridge_port_set_vlans("sw0", "dpT11", 0,
					   allowed_vlans, NULL);
	dp_test_check_state_show("ptp resolver trigger", "", true);

	/* routing interfaces */
	dp_test_intf_vif_create("sw0.10", "sw0", 10);
	dp_test_intf_vif_create("sw0.20", "sw0", 20);
	dp_test_check_state_show("ptp resolver trigger", "", true);

	dp_test_nl_add_ip_addr_and_connected("sw0.10", "192.168.10.1/24");
	dp_test_nl_add_ip_addr_and_connected("sw0.20", "192.168.20.1/24");
	dp_test_netlink_add_neigh("sw0.10", "192.168.10.2", "0:0:0:0:0:1");
	dp_test_netlink_add_neigh("sw0.20", "192.168.20.2", "0:0:0:0:0:2");
	dp_test_check_state_show("ptp resolver trigger", "", true);

	/* admin down interfaces */
	dp_test_netlink_set_interface_admin_status("dpT10", false);
	dp_test_netlink_set_interface_admin_status("dpT11", false);
	dp_test_check_state_show("ptp resolver trigger", "", true);

	/* admin up interfaces */
	dp_test_netlink_set_interface_admin_status("dpT10", true);
	dp_test_netlink_set_interface_admin_status("dpT11", true);
	dp_test_check_state_show("ptp resolver trigger", "", true);

	dp_test_check_state_show("ptp resolver dump",
			"{[{\n"
			"            \"peer\": \"192.168.20.2\",\n"
			"            \"installed\": true,\n"
			"            \"port-id\": 2,\n"
			"            \"mac\": \"0:0:0:0:0:2\",\n"
			"            \"type\": \"slave\"\n"
			"        },{\n"
			"            \"peer\": \"192.168.10.2\",\n"
			"            \"installed\": true,\n"
			"            \"port-id\": 1,\n"
			"            \"mac\": \"0:0:0:0:0:1\",\n"
			"            \"type\": \"master\"\n"
			"        }\n"
			"    ]\n"
			"    }\n", true);

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer delete "
				"clock-id=0 port-id=1 "
				"type=master "
				"ip=192.168.10.2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut peer delete "
				"clock-id=0 "
				"port-id=2 "
				"type=slave "
				"ip=192.168.20.2");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port delete 1 clock-id=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut port delete 2 clock-id=0");

	dp_test_send_config_src(dp_test_cont_src_get(),
				"ptp-ut clock delete 0");

	dp_test_netlink_del_neigh("sw0.10", "192.168.10.2", "0:0:0:0:0:1");
	dp_test_netlink_del_neigh("sw0.20", "192.168.20.2", "0:0:0:0:0:2");
	dp_test_nl_del_ip_addr_and_connected("sw0.10", "192.168.10.1/24");
	dp_test_nl_del_ip_addr_and_connected("sw0.20", "192.168.20.1/24");
	dp_test_intf_bridge_remove_port("sw0", "dpT11");
	dp_test_intf_bridge_remove_port("sw0", "dpT10");
	dp_test_intf_vif_del("sw0.10", 10);
	dp_test_intf_vif_del("sw0.20", 20);
	dp_test_intf_bridge_del("sw0");
	bridge_vlan_set_free(allowed_vlans);

} DP_END_TEST;
