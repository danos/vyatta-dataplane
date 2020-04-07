/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane portmonitor command tests
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
#include "dp_test_lib_portmonitor.h"
#include "dp_test_npf_fw_lib.h"
#include "dp_test_npf_lib.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"

static bool portmonitor_debug;

/*
 * Issue portmonitor command to dataplane
 */
void
_dp_test_portmonitor_request(const char *cmd, bool print,
				const char *file, int line)
{
	bool err;

	free(dp_test_console_request_w_err(cmd, &err, print));
	_dp_test_fail_unless(!err, file, line,
				"portmonitor cmd failed: \"%s\"", cmd);
}

static void
dp_test_portmonitor_show_session(const char *desc)
{
	const char *str;
	json_object *jresp;
	char *response;
	bool err;

	if (desc)
		printf("%s\n", desc);

	response = dp_test_console_request_w_err("portmonitor show session",
						 &err, false);
	if (!response || err)
		return;
	jresp = parse_json(response,
			   parse_err_str, sizeof(parse_err_str));

	free(response);

	if (!jresp)
		return;
	str = json_object_to_json_string_ext(jresp,
					     JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
	json_object_put(jresp);
}

static void
dp_test_portmonitor_show_npf(const char *desc)
{
	const char *str;
	json_object *jresp;
	char *response;
	bool err;

	if (desc)
		printf("%s\n", desc);

	response = dp_test_console_request_w_err("npf-op show",
						 &err, false);
	if (!response || err)
		return;
	jresp = parse_json(response,
			   parse_err_str, sizeof(parse_err_str));

	free(response);

	if (!jresp)
		return;
	str = json_object_to_json_string_ext(jresp,
					     JSON_C_TO_STRING_PRETTY);
	if (str)
		printf("%s\n", str);
	json_object_put(jresp);
}

void
dp_test_portmonitor_create_filter(const char *filter, uint32_t rule, bool pass,
				const char *fromaddr, const char *toaddr)
{
	dp_test_npf_cmd_fmt(portmonitor_debug,
			    "npf-ut add fw:%s %d %s %s %s",
			    filter, rule, npf_action_string(pass),
			    fromaddr, toaddr);
	dp_test_npf_cmd_fmt(portmonitor_debug, "npf-ut add fw:%s 10000 %s",
			    filter, npf_action_string(!pass));
}

void
dp_test_portmonitor_delete_filter(const char *filter)
{
	dp_test_npf_cmd_fmt(portmonitor_debug, "npf-ut delete fw:%s", filter);
}

void
dp_test_portmonitor_attach_filter(const char *filter, const char *type,
				const char *intf)
{
	char real_intf[IFNAMSIZ];

	dp_test_intf_real(intf, real_intf);
	dp_test_npf_cmd_fmt(portmonitor_debug,
				"npf-ut attach interface:%s portmonitor-%s fw:%s",
				real_intf, type, filter);
	dp_test_npf_commit();
	if (portmonitor_debug)
		dp_test_portmonitor_show_npf(NULL);
}

void
dp_test_portmonitor_detach_filter(const char *filter, const char *type,
				const char *intf)
{
	char real_intf[IFNAMSIZ];

	dp_test_intf_real(intf, real_intf);
	dp_test_npf_cmd_fmt(portmonitor_debug,
				"npf-ut detach interface:%s portmonitor-%s fw:%s",
				real_intf, type, filter);
	dp_test_npf_commit();
	if (portmonitor_debug)
		dp_test_portmonitor_show_npf(NULL);
}

void
dp_test_portmonitor_delete_session(uint32_t session)
{
	json_object *expected;
	char cmd[TEST_MAX_CMD_LEN];

	sprintf(cmd, "portmonitor del session %u 0 0 0 0", session);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	expected = dp_test_json_create(
	  "{ \"portmonitor_information\": []"
	  "}");
	dp_test_check_json_state("portmonitor show session", expected,
				 DP_TEST_JSON_CHECK_SUBSET, false);
	json_object_put(expected);
}

void
dp_test_portmonitor_create_span(uint32_t id, const char *srcif,
				const char *dstif, const char *ifilter,
				const char *ofilter)
{
	char cmd[TEST_MAX_CMD_LEN];
	char real_src_ifname[IFNAMSIZ];
	char real_dst_ifname[IFNAMSIZ];

	dp_test_intf_real(srcif, real_src_ifname);
	dp_test_intf_real(dstif, real_dst_ifname);

	sprintf(cmd, "portmonitor set session %u type 1 0 0", id);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u srcif %s 0 0", id,
		real_src_ifname);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u dstif %s 0 0", id,
		real_dst_ifname);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	if (ifilter) {
		sprintf(cmd, "portmonitor set session %u filter-in %s 0 0",
				id, ifilter);
		dp_test_portmonitor_request(cmd, portmonitor_debug);
	}
	if (ofilter) {
		sprintf(cmd, "portmonitor set session %u filter-out %s 0 0",
				id, ofilter);
		dp_test_portmonitor_request(cmd, portmonitor_debug);
	}
	if (portmonitor_debug)
		dp_test_portmonitor_show_session(NULL);
}

void
dp_test_portmonitor_create_rspansrc(uint32_t id, const char *srcif,
				const char *dstif, uint8_t vid,
				const char *ifilter, const char *ofilter)
{
	char cmd[TEST_MAX_CMD_LEN];
	char real_src_ifname[IFNAMSIZ];
	char real_dst_ifname[IFNAMSIZ];

	dp_test_intf_real(srcif, real_src_ifname);
	dp_test_intf_real(dstif, real_dst_ifname);

	sprintf(cmd, "portmonitor set session %u type 2 0 0", id);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u srcif %s 0 0", id,
		real_src_ifname);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u dstif %s %u 0",
		id, real_dst_ifname, vid);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	if (ifilter) {
		sprintf(cmd, "portmonitor set session %u filter-in %s 0 0",
				id, ifilter);
		dp_test_portmonitor_request(cmd, portmonitor_debug);
	}
	if (ofilter) {
		sprintf(cmd, "portmonitor set session %u filter-out %s 0 0",
				id, ofilter);
		dp_test_portmonitor_request(cmd, portmonitor_debug);
	}
	if (portmonitor_debug)
		dp_test_portmonitor_show_session(NULL);
}

void
dp_test_portmonitor_create_rspandst(uint32_t id, const char *srcif,
				uint8_t vid, const char *dstif)
{
	char cmd[TEST_MAX_CMD_LEN];
	char real_src_ifname[IFNAMSIZ];
	char real_dst_ifname[IFNAMSIZ];

	dp_test_intf_real(srcif, real_src_ifname);
	dp_test_intf_real(dstif, real_dst_ifname);

	sprintf(cmd, "portmonitor set session %u type 3 0 0", id);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u srcif %s %u 0",
			id, real_src_ifname, vid);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u dstif %s 0 0", id,
		real_dst_ifname);
	dp_test_portmonitor_request(cmd, portmonitor_debug);
	if (portmonitor_debug)
		dp_test_portmonitor_show_session(NULL);
}

void
dp_test_portmonitor_create_erspansrc(uint32_t id, const char *srcif,
				const char *dstif, uint16_t erspanid,
				uint8_t erspanhdr, const char *ifilter,
				const char *ofilter)
{
	char cmd[TEST_MAX_CMD_LEN];
	char real_src_ifname[IFNAMSIZ];
	char real_dst_ifname[IFNAMSIZ];

	dp_test_intf_real(srcif, real_src_ifname);
	dp_test_intf_real(dstif, real_dst_ifname);

	sprintf(cmd, "portmonitor set session %u type 4 0 0", id);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u srcif %s 0 0", id,
		real_src_ifname);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u dstif %s 0 0", id,
		real_dst_ifname);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u erspanid %u 0 0",
			id, erspanid);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u erspanhdr %u 0 0",
			id, erspanhdr);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	if (ifilter) {
		sprintf(cmd, "portmonitor set session %u filter-in %s 0 0",
				id, ifilter);
		dp_test_portmonitor_request(cmd, portmonitor_debug);
	}
	if (ofilter) {
		sprintf(cmd, "portmonitor set session %u filter-out %s 0 0",
				id, ofilter);
		dp_test_portmonitor_request(cmd, portmonitor_debug);
	}
	if (portmonitor_debug)
		dp_test_portmonitor_show_session(NULL);
}

void
dp_test_portmonitor_create_erspandst(uint32_t id, const char *srcif,
				const char *dstif, uint16_t erspanid,
				uint8_t erspanhdr)
{
	char cmd[TEST_MAX_CMD_LEN];
	char real_src_ifname[IFNAMSIZ];
	char real_dst_ifname[IFNAMSIZ];

	dp_test_intf_real(srcif, real_src_ifname);
	dp_test_intf_real(dstif, real_dst_ifname);

	sprintf(cmd, "portmonitor set session %u type 5 0 0", id);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u srcif %s 0 0", id,
		real_src_ifname);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u dstif %s 0 0", id,
		real_dst_ifname);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u erspanid %u 0 0",
			id, erspanid);
	dp_test_portmonitor_request(cmd, portmonitor_debug);

	sprintf(cmd, "portmonitor set session %u erspanhdr %u 0 0",
			id, erspanhdr);
	dp_test_portmonitor_request(cmd, portmonitor_debug);
	if (portmonitor_debug)
		dp_test_portmonitor_show_session(NULL);
}
