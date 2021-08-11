/*
 * Copyright (c) 2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <dlfcn.h>
#include "dp_test/dp_test_macros.h"
#include "util.h"
#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_cmd_state.h"
#include "dp_test_console.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "protobuf/SFPMonitor.pb-c.h"

#define SFPD_NOTIFY sfpd_send_msg(NULL, 0, "SFP_PRESENCE_NOTIFY")

#define INTF1 "dpT10"
#define INTF2 "dpT11"
#define INTF3 "dpT12"
#define INTF4 "dpT13"

#define PORT1 1
#define PORT2 2
#define PORT3 3
#define PORT4 4

static void
generate_sfpd_file(const char *sfpd_file, uint8_t port,
		   const char *port_name,
		   const char *part_id)
{
	FILE *f;

	f = fopen(sfpd_file, "w");
	if (!f) {
		perror("fopen");
		exit(2);
	}

	fprintf(f, "[%d]\n", port);
	fprintf(f, "port_name = %s\n", port_name);
	fprintf(f, "part_id = %s\n", part_id);
	fprintf(f, "vendor_name = Cisco\n");
	fprintf(f, "vendor_oui = aa.bb.cc\n");
	fprintf(f, "vendor_rev = 44.5a\n");
	fprintf(f, "detection_time = %u\n", dp_test_sys_uptime());
	fclose(f);
}

static void
_sfp_permit_match_check(const char *match_str, bool match,
			const char *file, int line)
{
	json_object *jexp;
	char cmd_str[50];

	sprintf(cmd_str, "sfp-permit-list match %s", match_str);
	jexp = dp_test_json_create(
		"{ "
		"\"sfp-permit-match\": "
		"{ \"%s\":\"%s\" } }", match_str,
		match ? "True" : "False");

	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, file,
				       "", line);
	json_object_put(jexp);
}

#define sfp_permit_match_check(_match_string_, _match_)		\
	_sfp_permit_match_check(_match_string_,			\
				_match_, __FILE__, __LINE__)

static void
_show_sfp_permit_mismatch_info(bool enforcement, bool logging, uint32_t delay,
		const char *file, int line)
{
	json_object *jexp;
	char cmd_str[50];

	sprintf(cmd_str, "sfp-permit-list dump mismatch");
	jexp = dp_test_json_create(
		"{ "
		"\"sfp-permit-list-mismatch\": "
			"{ "
				"\"logging enabled\":"
				"\"%s\","
				"\"enforcement enabled\":"
				"\"%s\","
				"\"enforcement delay\":"
				"%u"
			"}"
		"}",
		enforcement ? "True" : "False",
		logging ? "True" : "False",
		delay
		);

	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, file,
				       "", line);
	json_object_put(jexp);
}

#define show_sfp_permit_mismatch_info(enforcement, logging, delay)				\
	_show_sfp_permit_mismatch_info(enforcement, logging, delay, \
				__FILE__, __LINE__)

static void
_show_sfp_permit_list_info(const char *list_name, uint32_t index,
		const char *part, const char *vendor, const char *oui,
		const char *rev, const char *file, int line)
{
	json_object *jexp;
	char cmd_str[50];

	sprintf(cmd_str, "sfp-permit-list dump list");

	/*
	 * Expected JSON depends on whether an intf is specified
	 * and if so, whether is it assigned a profile.
	 */
	if (part != NULL) {
		if (vendor != NULL) {
			if (oui != NULL && rev != NULL) {
				jexp = dp_test_json_create(
					"{"
					"\"sfp-permit-list\":"
					"{\"lists\":["
					"{\"Name\":\"%s\","
					"\"lists\":["
					"{\"part_index\":"
					"%u,"
					"\"vendor_part\":"
					"\"%s\","
					"\"vendor\":"
					"\"%s\","
					"\"vendor_oui\":"
					"\"%s\","
					"\"vendor_rev\":"
					"\"%s\""
					"}"
					"]"
					"}"
					"]}}", list_name, index,  part,
					vendor, oui, rev);
			} else {
				jexp = dp_test_json_create(
					"{"
					"\"sfp-permit-list\":"
					"{\"lists\":["
					"{\"Name\":\"%s\","
					"\"lists\":["
					"{\"part_index\":"
					"%u,"
					"\"vendor_part\":"
					"\"%s\","
					"\"vendor\":"
					"\"%s\""
					"}"
					"]"
					"}"
					"]}}", list_name, index, part, vendor);
			}
		} else {
			jexp = dp_test_json_create(
				"{"
				"\"sfp-permit-list\":"
				"{\"lists\":["
				"{\"Name\":\"%s\","
				"\"lists\":["
				"{\"part_index\":"
				"%u,"
				"\"vendor_part\":"
				"\"%s\""
				"}"
				"]"
				"}"
				"]}}", list_name, index, part);
		}
	} else {
		jexp = dp_test_json_create(
			"{ "
			"\"sfp-permit-list\": "
			"{ \"lists\" : [ "
			"] } }");
	}
	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, file,
				       "", line);
	json_object_put(jexp);
}

#define show_sfp_permit_list_info(list_name, index, parts, vendor, oui, rev) \
	_show_sfp_permit_list_info(list_name, index, parts, vendor, oui, rev, \
				   __FILE__, __LINE__)

static void
_show_sfp_permit_list_device(const char *intf_name, bool enforcement, const char *part_id,
			     uint32_t time, bool approved, bool disabled,
			     bool present, const char *file, int line)
{
	json_object *jexp;
	char cmd_str[50];

	sprintf(cmd_str, "sfp-permit-list dump devices");

	/*
	 * Expected JSON depends on whether an intf is specified
	 * and if so, whether is it assigned a profile.
	 */
	if (present) {
		jexp = dp_test_json_create(
			"{"
			"\"sfp-permit-list-devices\":"
			"{\"enforcement-mode\":%s,"
			"\"up-time\":%d,"
			"\"devices\": ["
			"{"
			"\"intf_name\":"
			"\"%s\","
			"\"part_id\":"
			"\"%s\","
			"\"vendor_name\":"
			"\"Cisco\","
			"\"vendor_oui\":"
			"\"aa.bb.cc\","
			"\"vendor_rev\":"
			"\"44.5\","
			"\"detection_time\":"
			"%u,"
			"\"approved\":"
			"%s,"
			"\"disabled\":"
			"%s}"
			"]"
			"} }", enforcement ? "true" : "false",
			time, intf_name, part_id, time,
			approved ? "true" : "false",
			disabled ? "true" : "false");
	} else {
		jexp = dp_test_json_create(
			"{ "
			"\"sfp-permit-list-devices\": "
			"{ \"lists\" : [ "
			"] } }");
	}
	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, file,
				       "", line);
	json_object_put(jexp);
}

#define show_sfp_permit_list_device(intf_name, enforcement, parts, time, approved, \
				    disabled, present)		      \
	_show_sfp_permit_list_device(intf_name, enforcement, parts, time, approved,  \
				     disabled, present,	__FILE__, __LINE__)

static void sfp_permit_list_send(SfpPermitConfig *Cfg)
{
	void *buf;
	int len;

	len  = sfp_permit_config__get_packed_size(Cfg);
	buf = malloc(len);
	dp_test_assert_internal(buf);

	sfp_permit_config__pack(Cfg, buf);

	dp_test_lib_pb_wrap_and_send_pb("vyatta:sfppermitlist", buf, len);
}

SfpPermitConfig__ListConfig ListCfg =
	SFP_PERMIT_CONFIG__LIST_CONFIG__INIT;

SfpPermitConfig__SFP SFP_1 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 1, "SIMON", "Cisco", NULL, NULL};
SfpPermitConfig__SFP SFP_2 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 2, "PAULINE", "Brocade", "bb.cc.dd", "rev1"};
SfpPermitConfig__SFP SFP_3 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 3, "ALLAN", "Cisco", "aa.bb.cc", NULL };
SfpPermitConfig__SFP SFP_4 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 4, "DESMOND", NULL, NULL, NULL};
SfpPermitConfig__SFP SFP_5 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 5, "DES*", NULL, NULL, NULL};
SfpPermitConfig__SFP SFP_6 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 6, "PAUL", NULL, NULL, NULL};
SfpPermitConfig__SFP SFP_7 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 7, "AL*", "Cisco", NULL, NULL};
SfpPermitConfig__SFP SFP_8 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 8, "THOMAS", "Brocade", "bb.cc.dd", "rev2"};
SfpPermitConfig__SFP SFP_9 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 9, "THOMAS", "Brocade", "bb.cc.dd", "rev1"};
SfpPermitConfig__SFP SFP_10 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 10, "CAT*", NULL, NULL, NULL};
SfpPermitConfig__SFP SFP_11 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp__descriptor),
	true, 11, "BI*", NULL, NULL, NULL};

SfpPermitConfig__SFP *SFP_list[11] = {
	&SFP_1, &SFP_2, &SFP_3, &SFP_4, &SFP_5,
	&SFP_6, &SFP_7, &SFP_8, &SFP_9, &SFP_10, &SFP_11};

static void sfp_list_build_and_send(const char *list_name,
				    SfpPermitConfig__SFP **sfps, uint32_t num_sfps,
					int action)
{

	SfpPermitConfig Cfg = SFP_PERMIT_CONFIG__INIT;
	Cfg.mtype_case = SFP_PERMIT_CONFIG__MTYPE_LIST;
	Cfg.list = &ListCfg;
	ListCfg.action = action;
	ListCfg.name = (char *)list_name;
	ListCfg.n_sfps = num_sfps;
	ListCfg.sfps = sfps;

	sfp_permit_list_send(&Cfg);
}

static void sfp_list_add(const char *name,
			 SfpPermitConfig__SFP **Indices,
			 uint32_t num_indices)
{
	sfp_list_build_and_send(name, Indices, num_indices,
				SFP_PERMIT_CONFIG__ACTION__SET);
}
static void sfp_list_delete(const char *name)
{
	sfp_list_build_and_send(name, NULL, 0,
				SFP_PERMIT_CONFIG__ACTION__DELETE);
}

SfpPermitConfig__MisMatchConfig MismatchCfg =
	SFP_PERMIT_CONFIG__MIS_MATCH_CONFIG__INIT;

static void sfp_mismatch_action_send(bool enforcement, bool logging, uint32_t delay)
{
	SfpPermitConfig Cfg = SFP_PERMIT_CONFIG__INIT;
	Cfg.mtype_case = SFP_PERMIT_CONFIG__MTYPE_MISMATCH;
	Cfg.mismatch = &MismatchCfg;

	MismatchCfg.has_logging = true;
	MismatchCfg.logging = logging ? SFP_PERMIT_CONFIG__LOGGING__ENABLE :
		SFP_PERMIT_CONFIG__LOGGING__DISABLE;

	MismatchCfg.has_enforcement = true;
	MismatchCfg.enforcement = enforcement ? SFP_PERMIT_CONFIG__ENFORCEMENT__ENFORCE :
		SFP_PERMIT_CONFIG__ENFORCEMENT__MONITOR;

	MismatchCfg.has_delay = true;
	MismatchCfg.delay = delay;
	sfp_permit_list_send(&Cfg);
	sleep(5);
}

DP_DECL_TEST_SUITE(sfp_permit_list);

DP_DECL_TEST_CASE(sfp_permit_list, list, NULL, NULL);

DP_START_TEST(list, test1)
{
	dp_test_console_request_reply("debug sfp-list", true);

	/*
	 * Set up the mismatch global info.
	 */
	sfp_mismatch_action_send(true, true, 300);

	show_sfp_permit_mismatch_info(true, true, 300);

	dp_test_sys_uptime_inc(10);

	/* Add a list of allowed SFPs */
	sfp_list_add("List_1", &SFP_list[0], 5);
	show_sfp_permit_list_info("List_1", 1, "SIMON", "Cisco", NULL, NULL);
	show_sfp_permit_list_info("List_1", 2, "PAULINE", "Brocade", "bb.cc.dd", "rev1");

	/* Add an SFP of part_id 'CATHERINE' that is not in the list */
	generate_sfpd_file("sfpd_status", PORT1, INTF1, "CATHERINE");
	SFPD_NOTIFY;
	show_sfp_permit_list_device(INTF1, false, "CATHERINE", 10, false, false, true);

	/* Add a second list of allowed SFPs */
	sfp_list_add("List_2", &SFP_list[5], 5);

	show_sfp_permit_list_info("List_2", 7, "AL*", "Cisco", NULL, NULL);
	show_sfp_permit_list_info("List_2", 8, "THOMAS", "Brocade", "bb.cc.dd", "rev2");
	show_sfp_permit_list_info("List_2", 9, "THOMAS", "Brocade", "bb.cc.dd", "rev1");

	/* Check a few part_id matches in the permit list */
	sfp_permit_match_check("SIMON", true);
	sfp_permit_match_check("DE", false);
	sfp_permit_match_check("DES", true);
	sfp_permit_match_check("DESa", true);
	sfp_permit_match_check("Yoda", false);

	/* Add an SFP  part_id 'BILL' that is not in the allowed list, but will
	 * not be diabled as the enforcement delay has not expired
	 */
	dp_test_sys_uptime_inc(10);

	generate_sfpd_file("sfpd_status", PORT2, INTF2, "BILL");
	SFPD_NOTIFY;
	show_sfp_permit_list_device(INTF2, false,  "BILL", 20, false, false, true);

	/* Add 'BILL' to the allowed list */
	sfp_list_add("List_2", &SFP_list[5], 6);

	show_sfp_permit_list_device(INTF2, false, "BILL", 20, true, false, true);

	/* Walk past the enforcement delay and add a disallowed SFP
	 * 'HUGH'
	 */
	dp_test_sys_uptime_inc(300);

	generate_sfpd_file("sfpd_status", PORT3, INTF3, "HUGH");
	SFPD_NOTIFY;
	show_sfp_permit_list_device(INTF3, true, "HUGH", 320, false, true, true);

	/* Change the mode to monitor and check if the disallowed SFP is brought up again */
	sfp_mismatch_action_send(false, true, 300);
	show_sfp_permit_list_device(INTF3, false, "HUGH", 320, false, false, true);

	/* Now start to clean up */
	sfp_list_delete("List_1");

	show_sfp_permit_list_info("List_1", 0, NULL, NULL, NULL, NULL);
	show_sfp_permit_list_info("List_2", 7, "AL*", "Cisco", NULL, NULL);

	sfp_list_delete("List_2");

	show_sfp_permit_list_info("List_2", 0, NULL, NULL, NULL, NULL);

	/* Now try some two vendor tests in one list */

	sfp_list_add("List_1", &SFP_list[0], 10);
	show_sfp_permit_list_info("List_1", 1, "SIMON", "Cisco", NULL, NULL);
	show_sfp_permit_list_info("List_1", 2, "PAULINE", "Brocade", NULL, NULL);

	sfp_list_delete("List_1");

	/* Disable enforcement */
	sfp_mismatch_action_send(false, true, 300);

	dp_test_console_request_reply("debug sfp-list", false);

} DP_END_TEST;
