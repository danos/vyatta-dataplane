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
#include "protobuf/SFPMonitor.pb-c.h"

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

SfpPermitConfig__SfpPermitListConfig ListCfg =
	SFP_PERMIT_CONFIG__SFP_PERMIT_LIST_CONFIG__INIT;

SfpPermitConfig__SfpPart Part_1 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"SIMON"};
SfpPermitConfig__SfpPart Part_2 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"PAULINE"};
SfpPermitConfig__SfpPart Part_3 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"ALLAN"};
SfpPermitConfig__SfpPart Part_4 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"DESMOND"};
SfpPermitConfig__SfpPart Part_5 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"DES*"};
SfpPermitConfig__SfpPart Part_6 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"PAUL"};
SfpPermitConfig__SfpPart Part_7 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"AL*"};
SfpPermitConfig__SfpPart Part_8 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"THOMAS"};
SfpPermitConfig__SfpPart Part_9 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"TOM"};
SfpPermitConfig__SfpPart Part_10 = {
	PROTOBUF_C_MESSAGE_INIT(&sfp_permit_config__sfp_part__descriptor),
	"CAT*"
};

SfpPermitConfig__SfpPart *Part_list[10] = {
	&Part_1, &Part_2, &Part_3, &Part_4, &Part_5,
	&Part_6, &Part_7, &Part_8, &Part_9, &Part_10};

static void sfp_list_build_and_send(const char *list_name,
				    SfpPermitConfig__SfpPart **Part,
				    uint32_t num_parts,
				    int action)
{

	SfpPermitConfig Cfg = SFP_PERMIT_CONFIG__INIT;
	Cfg.mtype_case = SFP_PERMIT_CONFIG__MTYPE_LIST;
	Cfg.list = &ListCfg;
	ListCfg.action = action;
	ListCfg.name = (char *)list_name;
	ListCfg.vendor = "Cisco";
	ListCfg.vendor_oui = "aa.bb.cc";
	ListCfg.vendor_parts = Part;
	ListCfg.n_vendor_parts = num_parts;

	sfp_permit_list_send(&Cfg);
}

static void sfp_list_add(const char *name,
			 SfpPermitConfig__SfpPart **Parts,
			 uint32_t num_parts)
{
	sfp_list_build_and_send(name, Parts, num_parts,
				SFP_PERMIT_CONFIG__ACTION__SET);
}
static void sfp_list_delete(const char *name,
			 SfpPermitConfig__SfpPart **Parts,
			 uint32_t num_parts)
{
	sfp_list_build_and_send(name, Parts, num_parts,
				SFP_PERMIT_CONFIG__ACTION__DELETE);
}

DP_DECL_TEST_SUITE(sfp_permit_list);

DP_DECL_TEST_CASE(sfp_permit_list, list, NULL, NULL);

DP_START_TEST(list, test1)
{
	dp_test_console_request_reply("debug sfp-list", true);

	/*
	 * Set up a list.
	 */
	sfp_list_add("List_1", &Part_list[0], 5);

	show_sfp_permit_list_info("List_1", "SIMON", true);

	sfp_list_add("List_2", &Part_list[5], 5);

	show_sfp_permit_list_info("List_2", "AL*", true);

	sfp_list_delete("List_1", &Part_list[0], 5);

	show_sfp_permit_list_info("List_1", NULL, false);
	show_sfp_permit_list_info("List_2", "AL*", true);

	sfp_list_delete("List_2", &Part_list[5], 5);

	show_sfp_permit_list_info("List_2", "NULL", false);

	dp_test_console_request_reply("debug sfp-list", false);

} DP_END_TEST;
