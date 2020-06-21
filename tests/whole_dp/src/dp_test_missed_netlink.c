/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Missed netlink unit tests
 */
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <linux/if_bridge.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <libmnl/libmnl.h>
#include <czmq.h>
#include <syslog.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "main.h"
#include "if_var.h"
#include "vrf_internal.h"

#include "compat.h"

#include "dp_test/dp_test_cmd_check.h"
#include "dp_test_console.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_str.h"
#include "dp_test.h"

DP_DECL_TEST_SUITE(missed_netlink);

#define dp_test_wait_for_missed_count(added, updated, deleted) \
	_dp_test_wait_for_missed_count(added, updated, deleted, \
				       __FILE__, __func__, __LINE__)

static void _dp_test_wait_for_missed_count(int added, int updated, int deleted,
					   const char *file,
					   const char *func, int line)
{
	json_object *expected;

	expected = dp_test_json_create("{ \"incomplete\":"
				       "  {"
				       "     \"missed_add\": %d,"
				       "     \"missed_update\": %d,"
				       "     \"missed_del\": %d,"
				       "  }"
				       "}", added, updated, deleted);
	_dp_test_check_json_poll_state("incomplete",
				       expected, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, file, func, line);
	json_object_put(expected);
}

#define dp_test_verify_missed_nl_counts(replayed, added, updated, deleted) \
	_dp_test_verify_missed_nl_counts(replayed, added, updated, deleted, \
					 __FILE__, __func__, __LINE__)

static void _dp_test_verify_missed_nl_counts(int replayed,
					     int added,
					     int updated,
					     int deleted,
					     const char *file,
					     const char *func,
					     int line)
{
	json_object *expected;

	expected = dp_test_json_create("{ \"incomplete\":"
				       "  {"
				       "     \"missed_replayed\": %d,"
				       "     \"missed_add\": %d,"
				       "     \"missed_update\": %d,"
				       "     \"missed_del\": %d,"
				       "  }"
				       "}", replayed, added, updated, deleted);
	_dp_test_check_json_state("incomplete",
				  expected, NULL,
				  DP_TEST_JSON_CHECK_SUBSET,
				  false, file, func, line);
	json_object_put(expected);
}

static void dp_test_get_missed_nl_counts(unsigned int *replayed,
					 unsigned int *added,
					 unsigned int *updated,
					 unsigned int *deleted)
{
	const char *cmd = "incomplete";
	bool err;
	json_object *jresp;
	json_object *jrule;
	char *response;
	struct dp_test_json_find_key incomplete_key[] = {
		{ "incomplete", NULL },
	};

	response = dp_test_console_request_w_err(cmd, &err, false);
	if (!response || err)
		dp_test_fail("no response from dataplane");

	jresp = parse_json(response, parse_err_str, sizeof(parse_err_str));
	free(response);

	jrule = dp_test_json_find(jresp, incomplete_key,
				  ARRAY_SIZE(incomplete_key));

	if (!dp_test_json_int_field_from_obj(jrule, "missed_replayed",
					     (int *)replayed))
		dp_test_fail("Could not get missed_replayed from dataplane");

	if (!dp_test_json_int_field_from_obj(jrule, "missed_add",
					     (int *)added))
		dp_test_fail("Could not get missed_add from dataplane");

	if (!dp_test_json_int_field_from_obj(jrule, "missed_update",
					     (int *)updated))
		dp_test_fail("Could not get missed_update from dataplane");

	if (!dp_test_json_int_field_from_obj(jrule, "missed_del",
					     (int *)deleted))
		dp_test_fail("Could not get missed_del from dataplane");
	json_object_put(jrule);
	json_object_put(jresp);
}

DP_DECL_TEST_CASE(missed_netlink, basic_operation, NULL, NULL);
DP_START_TEST(basic_operation, basic_operation)
{
	unsigned int added = 0, updated = 0, deleted = 0, replayed = 0;
	unsigned int saved_ifindex = dp_test_intf_name2index("dpT11");

	dp_test_get_missed_nl_counts(&replayed, &added, &updated, &deleted);
	dp_test_verify_missed_nl_counts(replayed, added, updated, deleted);

	/* simple adds and replay */
	dp_test_netlink_del_interface_l2("dp1T1");
	dp_test_netlink_add_ip_address_noverify("dp1T1", "1.1.1.1/24");
	added += 2;
	replayed += 2;
	dp_test_wait_for_missed_count(added, updated, deleted);
	dp_test_netlink_set_interface_l2("dp1T1");
	dp_test_verify_missed_nl_counts(replayed, added, updated, deleted);
	/* second replay shouldn't change counters */
	missed_netlink_replay(saved_ifindex);
	dp_test_verify_missed_nl_counts(replayed, added, updated, deleted);

	/* adds, updates and deletes -- no replays */
	dp_test_netlink_del_interface_l2("dp1T1");
	dp_test_netlink_add_ip_address_noverify("dp1T1", "1.1.1.1/24");
	dp_test_netlink_del_ip_address_noverify("dp1T1", "1.1.1.1/24");
	added += 2;
	updated += 1;
	deleted += 1;
	replayed += 1;
	dp_test_wait_for_missed_count(added, updated, deleted);
	dp_test_netlink_set_interface_l2("dp1T1");
	dp_test_verify_missed_nl_counts(replayed, added, updated, deleted);
	/* second replay shouldn't change counters */
	missed_netlink_replay(saved_ifindex);
	dp_test_verify_missed_nl_counts(replayed, added, updated, deleted);

	/* add and update -- one replay each */
	dp_test_netlink_del_interface_l2("dp1T1");
	dp_test_netlink_add_ip_address_noverify("dp1T1", "1.1.1.1/24");
	dp_test_netlink_add_ip_address_noverify("dp1T1", "1.1.1.1/24");
	added += 2;
	updated += 2;
	replayed += 2;
	dp_test_wait_for_missed_count(added, updated, deleted);
	dp_test_netlink_set_interface_l2("dp1T1");
	dp_test_verify_missed_nl_counts(replayed, added, updated, deleted);
	/* second replay shouldn't change counters */
	missed_netlink_replay(saved_ifindex);
	dp_test_verify_missed_nl_counts(replayed, added, updated, deleted);

	/* multiple adds, updates, deletes -- no replays */
	dp_test_netlink_del_interface_l2("dp1T1");
	dp_test_netlink_add_ip_address_noverify("dp1T1", "1.1.1.1/24");
	dp_test_netlink_del_ip_address_noverify("dp1T1", "1.1.1.1/24");
	dp_test_netlink_add_ip_address_noverify("dp1T1", "1.1.1.1/24");
	dp_test_netlink_del_ip_address_noverify("dp1T1", "1.1.1.1/24");
	dp_test_netlink_add_ip_address_noverify("dp1T1", "1.1.1.1/24");
	dp_test_netlink_del_ip_address_noverify("dp1T1", "1.1.1.1/24");
	added += 4;
	updated += 5;
	deleted += 3;
	replayed += 1;
	dp_test_wait_for_missed_count(added, updated, deleted);
	dp_test_netlink_set_interface_l2("dp1T1");
	dp_test_verify_missed_nl_counts(replayed, added, updated, deleted);
	/* second replay shouldn't change counters */
	missed_netlink_replay(saved_ifindex);
	dp_test_verify_missed_nl_counts(replayed, added, updated, deleted);

	/* set known state and clean up */
	dp_test_netlink_add_ip_address_noverify("dp1T1", "1.1.1.1/24");
	dp_test_netlink_add_route("vrf:1 1.1.1.0/24 scope:253 nh int:dp1T1");
	dp_test_nl_del_ip_addr_and_connected("dp1T1", "1.1.1.1/24");
} DP_END_TEST;
