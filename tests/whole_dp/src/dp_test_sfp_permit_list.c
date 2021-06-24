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

SfpPermitConfig__SfpPart *Part[10] = {
	&Part_1, &Part_2, &Part_3, &Part_4, &Part_5,
	&Part_6, &Part_7, &Part_8, &Part_9, &Part_10};

static void sfp_list_build_and_send(const char *list_name)
{

	SfpPermitConfig Cfg = SFP_PERMIT_CONFIG__INIT;
	Cfg.mtype_case = SFP_PERMIT_CONFIG__MTYPE_LIST;
	Cfg.list = &ListCfg;
	ListCfg.action = SFP_PERMIT_CONFIG__ACTION__SET;
	ListCfg.name = (char *)list_name;
	ListCfg.vendor = "Cisco";
	ListCfg.vendor_oui = "aa.bb.cc";
	ListCfg.vendor_parts = Part;
	ListCfg.n_vendor_parts = 10;

	sfp_permit_list_send(&Cfg);
}

DP_DECL_TEST_SUITE(sfp_permit_list);

DP_DECL_TEST_CASE(sfp_permit_list, list, NULL, NULL);

DP_START_TEST(list, test1)
{
	dp_test_console_request_reply("debug sfp-list", true);

	/*
	 * Set up a list.
	 */
	sfp_list_build_and_send("List_1");

	dp_test_console_request_reply("debug sfp-list", false);

} DP_END_TEST;
