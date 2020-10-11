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

#include "dp_test.h"
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
