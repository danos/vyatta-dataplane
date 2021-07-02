/*
 * Copyright (c) 2020, AT&T Intellectual Property.
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
	fprintf(f, "detection_time = %d\n", dp_test_sys_uptime());
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
_show_sfp_permit_mismatch_info(const char *file, int line)
{
	json_object *jexp;
	char cmd_str[50];

	sprintf(cmd_str, "sfp-permit-list dump mismatch");
	jexp = dp_test_json_create(
		"{ "
		"\"sfp-permit-list-mismatch\": "
		"{ } }");

	_dp_test_check_json_poll_state(cmd_str, jexp, NULL,
				       DP_TEST_JSON_CHECK_SUBSET,
				       false, 0, file,
				       "", line);
	json_object_put(jexp);

}

#define show_sfp_permit_mismatch_info()				\
	_show_sfp_permit_mismatch_info(__FILE__, __LINE__)

static void
_show_sfp_permit_list_info(const char *list_name, const char *part,
			   bool present, const char *file, int line)
{
	json_object *jexp;
	char cmd_str[50];

	sprintf(cmd_str, "sfp-permit-list dump list");

	/*
	 * Expected JSON depends on whether an intf is specified
	 * and if so, whether is it assigned a profile.
	 */
	if (present) {
		jexp = dp_test_json_create(
			"{"
			"\"sfp-permit-list\":"
			"{\"lists\":["
			"{\"Name\":\"%s\","

			"\"lists\":["

			"{\"vendor_part\":"
			"\"%s\"}"
			"]"

			"}"
			"]}}", list_name, part);
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

#define show_sfp_permit_list_info(list_name, parts, present)	\
	_show_sfp_permit_list_info(list_name, parts, present,	\
				   __FILE__, __LINE__)

static void
_show_sfp_permit_list_device(const char *intf_name, const char *part_id,
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
			"{\"enforcement-mode\":true,"
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
			"%d,"
			"\"approved\":"
			"%s,"
			"\"disabled\":"
			"%s}"
			"]"
			"} }", time, intf_name, part_id, time,
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

#define show_sfp_permit_list_device(intf_name, parts, time, approved, \
				    disabled, present)		      \
	_show_sfp_permit_list_device(intf_name, parts, time, approved,  \
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

SfpPermitConfig__Vendor Vendor =
		SFP_PERMIT_CONFIG__VENDOR__INIT;

SfpPermitConfig__Vendor *Vendor_list[1] = {&Vendor};

SfpPermitConfig__Part Part_1 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"SIMON"};
SfpPermitConfig__Part Part_2 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"PAULINE"};
SfpPermitConfig__Part Part_3 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"ALLAN"};
SfpPermitConfig__Part Part_4 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"DESMOND"};
SfpPermitConfig__Part Part_5 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"DES*"};
SfpPermitConfig__Part Part_6 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"PAUL"};
SfpPermitConfig__Part Part_7 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"AL*"};
SfpPermitConfig__Part Part_8 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"THOMAS"};
SfpPermitConfig__Part Part_9 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"TOM"};
SfpPermitConfig__Part Part_10 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"CAT*"
};
SfpPermitConfig__Part Part_11 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__part__descriptor),
	"BI*"
};

SfpPermitConfig__Part *Part_list[11] = {
	&Part_1, &Part_2, &Part_3, &Part_4, &Part_5,
	&Part_6, &Part_7, &Part_8, &Part_9, &Part_10, &Part_11};



static void sfp_list_build_and_send(const char *list_name,
					SfpPermitConfig__Part **Part,
					uint32_t num_parts,
				    int action)
{

	SfpPermitConfig Cfg = SFP_PERMIT_CONFIG__INIT;
	Cfg.mtype_case = SFP_PERMIT_CONFIG__MTYPE_LIST;
	Cfg.list = &ListCfg;
	ListCfg.action = action;
	ListCfg.name = (char *)list_name;
	ListCfg.n_vendors = 1;
	ListCfg.vendors = &Vendor_list[0];
	Vendor_list[0]->n_parts = num_parts;
	Vendor_list[0]->name = "Cisco";
	Vendor_list[0]->oui = "aa.bb.cc";
	Vendor_list[0]->parts = Part;
	sfp_permit_list_send(&Cfg);
}

static void sfp_list_add(const char *name,
			 SfpPermitConfig__Part **Parts,
			 uint32_t num_parts)
{
	sfp_list_build_and_send(name, Parts, num_parts,
				SFP_PERMIT_CONFIG__ACTION__SET);
}
static void sfp_list_delete(const char *name,
			 SfpPermitConfig__Part **Parts,
			 uint32_t num_parts)
{
	sfp_list_build_and_send(name, Parts, num_parts,
				SFP_PERMIT_CONFIG__ACTION__DELETE);
}

SfpPermitConfig__MisMatchConfig MismatchCfg =
	SFP_PERMIT_CONFIG__MIS_MATCH_CONFIG__INIT;

static void sfp_mismatch_action_send(bool enforcement, bool logging, uint32_t delay)
{
	SfpPermitConfig Cfg = SFP_PERMIT_CONFIG__INIT;
	Cfg.mtype_case = SFP_PERMIT_CONFIG__MTYPE_MISMATCH;
	Cfg.mismatch = &MismatchCfg;

	MismatchCfg.logging = logging ? SFP_PERMIT_CONFIG__LOGGING__ENABLE :
		SFP_PERMIT_CONFIG__LOGGING__DISABLE;
	MismatchCfg.enforcement = enforcement ? SFP_PERMIT_CONFIG__ENFORCEMENT__ENFORCE :
		SFP_PERMIT_CONFIG__ENFORCEMENT__MONITOR;

	MismatchCfg.delay = delay;
	sfp_permit_list_send(&Cfg);
}

DP_DECL_TEST_SUITE(sfp_permit_list);

DP_DECL_TEST_CASE(sfp_permit_list, list, NULL, NULL);

DP_START_TEST(list, test1)
{
	dp_test_console_request_reply("debug sfp-list", true);

	/*
	 * Set up the mismatch global info.
	 */
	sfp_mismatch_action_send(TRUE, TRUE, 300);

	show_sfp_permit_mismatch_info();

	dp_test_sys_uptime_inc(10);

	/* Add a list of allowed SFPs */
	sfp_list_add("List_1", &Part_list[0], 5);
	show_sfp_permit_list_info("List_1", "SIMON", true);

	/* Add an SFP of part_id 'CATHERINE' that is not in the list */
	generate_sfpd_file("sfpd_status", PORT1, INTF1, "CATHERINE");
	SFPD_NOTIFY;
	show_sfp_permit_list_device(INTF1, "CATHERINE", 10, false, false, true);

	/* Add a second list of allowed SFPs */
	sfp_list_add("List_2", &Part_list[5], 5);

	show_sfp_permit_list_info("List_2", "AL*", true);

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
	show_sfp_permit_list_device(INTF2, "BILL", 20, false, false, true);

	/* Add 'BILL' to the allowed list */
	sfp_list_add("List_2", &Part_list[5], 6);

	show_sfp_permit_list_device(INTF2, "BILL", 20, true, false, true);

	/* Walk past the enforcement delay and add a disallowed SFP
	 * 'HUGH'
	 */
	dp_test_sys_uptime_inc(300);

	generate_sfpd_file("sfpd_status", PORT3, INTF3, "HUGH");
	SFPD_NOTIFY;
	show_sfp_permit_list_device(INTF3, "HUGH", 320, false, true, true);

	/* Now start to clean up */
	sfp_list_delete("List_1", &Part_list[0], 5);

	show_sfp_permit_list_info("List_1", NULL, false);
	show_sfp_permit_list_info("List_2", "AL*", true);

	sfp_list_delete("List_2", &Part_list[5], 6);

	show_sfp_permit_list_info("List_2", "NULL", false);

	/* Disable enforcement */
	sfp_mismatch_action_send(false, TRUE, 300);

	dp_test_console_request_reply("debug sfp-list", false);

} DP_END_TEST;
