/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Program the dataplane by sending console commands
 */
#include "dp_test_cmd_state.h"

#include <stdio.h>
#include <netinet/in.h>
#include <czmq.h>

#include "if_var.h"
#include "if_llatbl.h"
#include "netinet6/nd6_nbr.h"

#include "dp_test/dp_test_macros.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_controller.h"
#include "dp_test_console.h"
#include "dp_test_netlink_state_internal.h"

/*
 * Example CLI -> string cmd for nat
 *
 * 1) This configuration.
 *
 * tta@vr0-latest# show service nat
 * nat {
 *		destination {
 *			rule 10 {
 *				inbound-interface dp1s7
 *				source {
 *					address 70.70.70.70
 *				}
 *				translation {
 *					address 90.90.90.90
 *				}
 *			}
 *		}
 *	}
 *
 * 2) Translates to this string command executed on the dataplane.
 *
 * cmd = "npf-ut add dnat:\"dpT10\" 10 nat-type=dnat trans-addr=90.90.90.90 "
 *       "src-addr=70.70.70.70";
 *
 * 3) And this JSON show reply to the command "npf-op show all: dnat"
 *
 *  "config": [{
 *      "attach_type": "interface",
 *      "attach_point": "dpT10".
 *      "rulesets": [{
 *	"ruleset_type": "dnat",
 *	      "groups": [{
 *		 "name": "dpT10",
 *		  "direction": "in",
 *		  "rules": {
 *		      "10":{
 *                         "bytes":0,
 *                         "packets":0,
 *                         "action": "pass in ",
 *                         "match": "on dpT10 proto-final 6 from 100.0.100.100",
 *                         "map": "dynamic 10.0.10.10 port 80-80 <- any",
 *                         "total_ts": 0,
 *                         "used_ts": 0
 *                      }
 *		     }
 *		  }
 *	      ]
 *	  } ]
 *    } ]
 */
void
dp_test_cmd_replace_dnat(int rule_num, const char *ifname, const char *orig_ip,
			 const char *dnat_ip, uint8_t proto, uint16_t dnat_port)
{
	char real_if_name[IFNAMSIZ];
	char cmd[TEST_MAX_CMD_LEN];

	dp_test_intf_real(ifname, real_if_name);
	snprintf(cmd, sizeof(cmd), "npf-ut add dnat:%s %i nat-type=dnat "
		 "trans-addr=%s trans-port=%i proto-final=%d "
		 "src-addr=%s", real_if_name, rule_num,
		 dnat_ip, dnat_port, proto, orig_ip);
	dp_test_console_request_reply(cmd, false);
	dp_test_console_request_reply("npf-ut commit", false);
	/*
	 * And now test it is there using "npf-op show all: dnat" command
	 */
	char expected[TEST_MAX_REPLY_LEN];

	snprintf(cmd, TEST_MAX_CMD_LEN, "npf-op show all: dnat");
	snprintf(expected, TEST_MAX_REPLY_LEN, "proto-final %d from %s",
		 proto, orig_ip);
	dp_test_check_state_show(cmd, expected, false);
}

void
dp_test_cmd_delete_dnat(int rule_num, const char *ifname, const char *orig_ip,
			uint8_t proto)
{
	char state_cmd[TEST_MAX_CMD_LEN];
	char cmd[TEST_MAX_CMD_LEN];
	char expected[TEST_MAX_REPLY_LEN];
	char real_if_name[IFNAMSIZ];

	snprintf(state_cmd, TEST_MAX_CMD_LEN, "npf-op show all: dnat");
	snprintf(expected, TEST_MAX_REPLY_LEN, "proto-final %d from %s",
		 proto, orig_ip);

	dp_test_check_state_show(state_cmd, expected, false);

	dp_test_intf_real(ifname, real_if_name);
	snprintf(cmd, sizeof(cmd), "npf-ut delete dnat:%s %i", real_if_name,
		 rule_num);
	dp_test_console_request_reply(cmd, false);
	dp_test_console_request_reply("npf-ut commit", false);

	dp_test_check_state_gone_show(state_cmd, expected, false);
}

void
dp_test_cmd_replace_snat(int rule_num, const char *ifname, const char *orig_ip,
			 const char *snat_ip, struct dp_test_port_range *ports)
{
	char real_if_name[IFNAMSIZ];
	char cmd[TEST_MAX_CMD_LEN];
	char tmp[TEST_MAX_CMD_LEN];

	dp_test_intf_real(ifname, real_if_name);

	if (ports)
		snprintf(tmp, sizeof(tmp), " trans-port=%u-%u",
			 ports->start, ports->end);
	else
		/*
		 * No port range specified, so we don't send one in the
		 * command.  Internally this is equivalent to giving the
		 * range 1-65535, i.e. all ports.
		 */
		tmp[0] = '\0';

	snprintf(cmd, sizeof(cmd),
		 "npf-ut add snat:%s %i nat-type=snat trans-addr=%s"
		 "%s src-addr=%s",
		 real_if_name, rule_num, snat_ip, tmp, orig_ip);

	dp_test_console_request_reply(cmd, false);
	dp_test_console_request_reply("npf-ut commit", false);
	/*
	 * And now test it is not there using "npf-op show all: snat" command
	 */
	char expected[TEST_MAX_REPLY_LEN];

	snprintf(cmd, TEST_MAX_CMD_LEN, "npf-op show all: snat");
	snprintf(expected, TEST_MAX_REPLY_LEN, "from %s", orig_ip);
	dp_test_check_state_show(cmd, expected, false);
}

void
dp_test_cmd_delete_snat(int rule_num, const char *ifname, const char *orig_ip)
{
	char expected[TEST_MAX_REPLY_LEN];
	char state_cmd[TEST_MAX_CMD_LEN];
	char cmd[TEST_MAX_CMD_LEN];
	char real_if_name[IFNAMSIZ];

	snprintf(state_cmd, TEST_MAX_CMD_LEN, "npf-op show all: snat");
	snprintf(expected, TEST_MAX_REPLY_LEN, "from %s", orig_ip);

	dp_test_check_state_show(state_cmd, expected, false);

	dp_test_intf_real(ifname, real_if_name);
	snprintf(cmd, sizeof(cmd), "npf-ut delete snat:%s %i", real_if_name,
		 rule_num);
	dp_test_console_request_reply(cmd, false);
	dp_test_console_request_reply("npf-ut commit", false);

	dp_test_check_state_gone_show(state_cmd, expected, false);
}

/*
 * Remove existing neighbour entry for ipaddr.
 */
void
_dp_test_neigh_clear_entry(const char *ifname, const char *ipaddr,
			   const char *file, const char *func,
			   int line)
{
	struct dp_test_addr addr;
	int ifindex;
	struct ifnet *ifp;
	struct llentry *lle;

	ifindex = dp_test_intf_name2index(ifname);
	ifp = dp_ifnet_byifindex(ifindex);

	_dp_test_fail_unless(dp_test_addr_str_to_addr(ipaddr, &addr),
			     file, line,
			     "unable to parse addr %s", ipaddr);

	switch (addr.family) {
	case AF_INET:
		lle = in_lltable_lookup(ifp, 0, addr.addr.ipv4);
		if (lle)
			rte_atomic16_test_and_set(&lle->ll_idle);
		in_lltable_lookup(ifp, LLE_DELETE | LLE_LOCAL, addr.addr.ipv4);
		break;
	case AF_INET6:
		lle = in6_lltable_lookup(ifp, 0, &addr.addr.ipv6);
		if (lle)
			rte_atomic16_test_and_set(&lle->ll_idle);
		in6_lltable_lookup(ifp, LLE_DELETE, &addr.addr.ipv6);
		break;
	}
	_dp_test_verify_neigh(ifname, ipaddr, "", true, file, func, line);
}
