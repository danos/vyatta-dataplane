/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * dataplane route tracker tests
 */

#include <libmnl/libmnl.h>
#include <linux/random.h>

#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "rt_tracker.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_console.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_cmd_state.h"

#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_route_tracker.h"

DP_DECL_TEST_SUITE(route_tracker);


#define DP_TEST_MAX_TRACKERS 10

struct dp_test_rt_tracker_ctx {
	bool used;
	uint32_t count;
};

uint32_t pre_count[DP_TEST_MAX_TRACKERS];
struct dp_test_rt_tracker_ctx tracker_ctx[DP_TEST_MAX_TRACKERS];

static void dp_test_route_tracker_store_pre_counts(void)
{
	int i;

	for (i = 0; i < DP_TEST_MAX_TRACKERS; i++)
		pre_count[i] = tracker_ctx[i].count;
}

void dp_test_route_tracker_cb(void *cb_ctx)
{
	struct dp_test_rt_tracker_ctx *track = cb_ctx;

	track->count++;
}

/* Command handler to get stuff to main */
static int dp_test_cmd_route_tracker_cfg(FILE *f, int argc, char **argv)
{
	bool add;
	struct ip_addr addr;
	int rc;
	struct vrf *vrf = get_vrf(VRF_DEFAULT_ID);
	uint32_t index;

	if (argc < 4)
		return -1;

	if (!strcmp(argv[1], "ADD"))
		add = true;
	else if  (!strcmp(argv[1], "DELETE"))
		add = false;
	else
		return -1;

	/* Process the string */
	rc = parse_ipaddress(&addr, argv[2]);
	if (rc != 1)
		return -1;

	rc = get_unsigned(argv[3], &index);
	dp_test_assert_internal(rc == 0);
	dp_test_assert_internal(index < DP_TEST_MAX_TRACKERS);

	if (add) {
		dp_test_assert_internal(tracker_ctx[index].used == false);
		dp_rt_tracker_add(vrf, &addr,
			       &tracker_ctx[index],
			       dp_test_route_tracker_cb);
		tracker_ctx[index].used = true;
	} else {
		dp_test_assert_internal(tracker_ctx[index].used);
		dp_rt_tracker_delete(vrf, &addr,
				  &tracker_ctx[index]);
		tracker_ctx[index].used = false;
	}

	return 0;
}

static void _dp_test_verify_tracker(const char *addr, int count,
				    const char *cover,
				    const char *file,
				    const char *function,
				    int line)
{
	char cmd_str[100];
	char count_str[100];
	char cover_str[100];
	json_object *jexp;

	snprintf(cmd_str, 100, "rt-tracker show");

	if (count)
		snprintf(count_str, 100, "        \"count\": %d, ", count);
	else
		/* Check tracker does not exist */
		count_str[0] = '\0';

	if (cover)
		snprintf(cover_str, 100, "        \"cover\": \"%s\", ", cover);
	else
		cover_str[0] = '\0';

	jexp = dp_test_json_create(
		"{ "
		"  \"route_tracker_state\": "
		"    [ "
		"      { "
		"        \"dest\": \"%s\", "
		"%s"
		"%s"
		"      }"
		"    ] "
		"} ",
		addr, count_str, cover_str);

	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       count == 0, 0, file,
				       function, line);
	json_object_put(jexp);
}

#define dp_test_verify_tracker(addr, count, cover)		\
	_dp_test_verify_tracker(addr, count, cover, __FILE__,	\
				__func__, __LINE__)

#define dp_test_verify_tracker_gone(addr)			\
	_dp_test_verify_tracker(addr, 0, NULL, __FILE__,	\
				__func__, __LINE__)

DP_DECL_TEST_CASE(route_tracker, route_tracker, NULL, NULL);


const char *v4_interface_addr[] = { "1.1.1.1/24", "2.2.2.2/24" };
const char *v6_interface_addr[] = { "1:1:1::1/64", "2:2:2::2/64" };

const char *v4_routes[] = { "0.0.0.0/0 nh 2.2.2.1 int:dp2T1",
			    "10.1.1.0/24 nh 2.2.2.1 int:dp2T1",
			    "100.1.1.0/24 nh 2.2.2.1 int:dp2T1",
			    "50.1.1.0/24 nh 2.2.2.1 int:dp2T1" };
const char *v6_routes[] = { "::/0 nh 2:2:2::1 int:dp2T1",
			    "10:1:1::0/64 nh 2:2:2::1 int:dp2T1",
			    "100:1:1::0/64 nh 2:2:2::1 int:dp2T1",
			    "50:1:1::0/64 nh 2:2:2::1 int:dp2T1" };

const char *v4_trackers[] = { "10.1.1.1",
			      "100.1.1.1"};
const char *v6_trackers[] = { "10:1:1::1",
			      "100:1:1::1"};

const char *v4_cover[] = { "0.0.0.0/0",
			   "10.1.1.0/24",
			   "100.1.1.0/24",
			   "No route"};
const char *v6_cover[] = { "::/0",
			   "10:1:1::/64",
			   "100:1:1::/64",
			   "No route"};

/*
 * Check that we can track routes
 */
static void rt_tracker_test(const char *addresses[], const char *routes[],
			    const char *tracker[], const char *cover[])
{
	cmd_rt_tracker_cfg_test_set(dp_test_cmd_route_tracker_cfg);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected("dp1T0", addresses[0]);
	dp_test_nl_add_ip_addr_and_connected("dp2T1", addresses[1]);

	/* Add first tracker - no route for it at the moment, and no default */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"tracker-ut ADD %s 0", tracker[0]);
	dp_test_verify_tracker(tracker[0], 1, cover[3]);

	/* Add the default route and check it gets picked up by the tracker */
	dp_test_route_tracker_store_pre_counts();
	dp_test_netlink_add_route(routes[0]);
	dp_test_fail_unless(pre_count[0] + 1 == tracker_ctx[0].count,
			    "Wrong count %s", tracker[0]);
	dp_test_verify_tracker(tracker[0], 1, cover[0]);

	/* Remove the default route and check we get back to no route */
	dp_test_route_tracker_store_pre_counts();
	dp_test_netlink_del_route(routes[0]);
	dp_test_fail_unless(pre_count[0] + 1 == tracker_ctx[0].count,
			    "Wrong count %s", tracker[0]);
	dp_test_verify_tracker(tracker[0], 1, cover[3]);

	/* Add the default route back */
	dp_test_route_tracker_store_pre_counts();
	dp_test_netlink_add_route(routes[0]);
	dp_test_fail_unless(pre_count[0] + 1 == tracker_ctx[0].count,
			    "Wrong count %s", tracker[0]);
	dp_test_verify_tracker(tracker[0], 1, cover[0]);

	/* Add the other 2 trackers, they will pick up the default */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"tracker-ut ADD %s 1", tracker[1]);
	dp_test_verify_tracker(tracker[1], 1, cover[0]);
	dp_test_send_config_src(dp_test_cont_src_get(),
				"tracker-ut ADD %s 2", tracker[1]);
	dp_test_verify_tracker(tracker[1], 2, cover[0]);


	/* Add route that should hit tracker 0 */
	dp_test_route_tracker_store_pre_counts();
	dp_test_netlink_add_route(routes[1]);
	dp_test_fail_unless(pre_count[0] + 1 == tracker_ctx[0].count,
			    "Wrong count %s", tracker[0]);
	dp_test_fail_unless(pre_count[1] == tracker_ctx[1].count,
			    "Wrong count %s", tracker[1]);
	dp_test_verify_tracker(tracker[0], 1, cover[1]);

	/* Add route that should hit trackers 1 and 2 */
	dp_test_route_tracker_store_pre_counts();
	dp_test_netlink_add_route(routes[2]);
	dp_test_fail_unless(pre_count[1] + 1 == tracker_ctx[1].count,
			    "Wrong count %s", tracker[1]);
	dp_test_verify_tracker(tracker[1], 2, cover[2]);
	dp_test_fail_unless(pre_count[2] + 1 == tracker_ctx[2].count,
			    "Wrong count %s", tracker[1]);

	/* Add route that should hit no trackers */
	dp_test_route_tracker_store_pre_counts();
	dp_test_netlink_add_route(routes[3]);
	dp_test_fail_unless(pre_count[0] == tracker_ctx[0].count,
			    "Wrong count %s", tracker[0]);
	dp_test_fail_unless(pre_count[1] == tracker_ctx[1].count,
			    "Wrong count %s", tracker[1]);
	dp_test_verify_tracker(tracker[1], 2, cover[2]);

	dp_test_netlink_del_route(routes[0]);
	dp_test_netlink_del_route(routes[1]);
	dp_test_netlink_del_route(routes[2]);
	dp_test_netlink_del_route(routes[3]);

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", addresses[0]);
	dp_test_nl_del_ip_addr_and_connected("dp2T1", addresses[1]);

	dp_test_send_config_src(dp_test_cont_src_get(),
				"tracker-ut DELETE %s 0", tracker[0]);
	dp_test_verify_tracker_gone("10.1.1.1");
	dp_test_send_config_src(dp_test_cont_src_get(),
				"tracker-ut DELETE %s 1", tracker[1]);
	dp_test_send_config_src(dp_test_cont_src_get(),
				"tracker-ut DELETE %s 2", tracker[1]);
	dp_test_verify_tracker_gone("100.1.1.1");

	cmd_rt_tracker_cfg_test_set(NULL);
}

DP_START_TEST(route_tracker, route_tracker_simple)
{
	rt_tracker_test(v4_interface_addr, v4_routes, v4_trackers, v4_cover);
	rt_tracker_test(v6_interface_addr, v6_routes, v6_trackers, v6_cover);
} DP_END_TEST;

#define IIFNAME "dp1T0"
#define PEER_MAC "be:ef:60:d:f0:d"
#define PEER_IP "1.1.1.2"
#define OUR_IP  "1.1.1.1"
#define OUR_ADDRESS  "1.1.1.1/24"
#define PEER_ROUTE  "1.1.1.2/32 nh 1.1.1.2 int:dp1T0"

DP_START_TEST(route_tracker, route_tracker_race)
{
	cmd_rt_tracker_cfg_test_set(dp_test_cmd_route_tracker_cfg);

	/* Set up the interface addresses */
	dp_test_nl_add_ip_addr_and_connected(IIFNAME, OUR_ADDRESS);

	/* Add a tracker and ensure it is resolved through the connected */
	dp_test_send_config_src(dp_test_cont_src_get(),
				"tracker-ut ADD %s 0", PEER_IP);
	dp_test_verify_tracker(PEER_IP, 1, "1.1.1.0/24");

	/*
	 * Add a neigh entry, which will end up creating /32 neigh_created
	 * route and as a result the tracker should be updated to point
	 * to this new rule/route.
	 */
	dp_test_netlink_add_neigh(IIFNAME, PEER_IP, PEER_MAC);

	/* ARP based route should now resolve the tracker with a /32 cover */
	dp_test_verify_tracker(PEER_IP, 1, "1.1.1.2/32");

	/*
	 * This is a higher scope route and as a result should replace the
	 * ARP created route/rule but the tracker should resolve via the
	 * /32
	 */
	dp_test_netlink_add_route(PEER_ROUTE);

	/* Should still be reoslved with the /32 cover */
	dp_test_verify_tracker(PEER_IP, 1, "1.1.1.2/32");

	/*
	 * Now remove the neigh entry and the tracker should remain unaffected
	 */
	dp_test_neigh_clear_entry(IIFNAME, PEER_IP);
	dp_test_verify_tracker(PEER_IP, 1, "1.1.1.2/32");

	/*
	 * Now get rid of the /32 route and the tracker should re-resolve via
	 * the /24 connected route
	 */
	dp_test_netlink_del_route(PEER_ROUTE);
	dp_test_verify_tracker(PEER_IP, 1, "1.1.1.0/24");

	/* Clean Up */
	dp_test_nl_del_ip_addr_and_connected("dp1T0", OUR_ADDRESS);
	dp_test_send_config_src(dp_test_cont_src_get(),
				"tracker-ut DELETE %s 0", PEER_IP);
	dp_test_verify_tracker_gone(PEER_IP);
	cmd_rt_tracker_cfg_test_set(NULL);
} DP_END_TEST;
