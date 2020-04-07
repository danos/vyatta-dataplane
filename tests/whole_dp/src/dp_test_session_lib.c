/*
 * Copyright (c) 2017-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <libmnl/libmnl.h>
#include <linux/random.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "npf/npf_pack.h"

#include "dp_test.h"
#include "dp_test_controller.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_session_internal_lib.h"

#include "dp_test/dp_test_session_lib.h"

void _dp_test_session_msg_valid(void *packed_session, uint32_t size,
				const char *file, int line)
{
	struct npf_pack_message *msg = packed_session;

	_dp_test_fail_unless(npf_pack_validate_msg(msg, size), file, line,
				"npf_pack message invalid\n");
}

bool _dp_test_session_msg_full(void *packed_session,
				const char *file, int line)
{
	struct npf_pack_message *msg = packed_session;

	if (npf_pack_get_msg_type(msg) == SESSION_PACK_FULL)
		return true;
	return false;
}

bool _dp_test_session_msg_update(void *packed_session,
				const char *file, int line)
{
	struct npf_pack_message *msg = packed_session;

	if (npf_pack_get_msg_type(msg) == SESSION_PACK_UPDATE)
		return true;
	return false;
}

uint64_t _dp_test_session_msg_get_id(void *packed_session,
				const char *file, int line)
{
	struct npf_pack_message *msg = packed_session;

	return npf_pack_get_session_id(msg);
}

void _dp_test_session_msg_check_rcvd(void *packed_session,
				uint64_t pkts_per_session,
				struct dp_test_session sess[],
				const char *file, int line)
{
	int i;
	uint64_t se_id;
	struct npf_pack_session_stats *stats;
	struct npf_pack_message *msg = packed_session;

	_dp_test_fail_unless(sess, file, line,
			"npf_pack sess input invalid\n");
	se_id = dp_test_session_msg_get_id(msg);
	stats =  npf_pack_get_session_stats(msg);
	_dp_test_fail_unless(stats, file, line,
			"Couldn't get stats from npf_pack message\n");
	if (stats->se_pkts_in == pkts_per_session &&
	    stats->se_pkts_out == pkts_per_session) {
		for (i = 0; i < DP_TEST_MAX_TEST_SESSIONS; i++) {
			if (sess[i].se_id == se_id) {
				sess[i].completed = true;
				return;
			}
		}
		for (i = 0; i < DP_TEST_MAX_TEST_SESSIONS; i++) {
			if (sess[i].se_id == 0) {
				sess[i].se_id = se_id;
				sess[i].completed = true;
				return;
			}
		}
	}
}

bool _dp_test_session_msg_pulled_all(void *packed_session,
				uint64_t pkts_per_session,
				struct dp_test_session sess[],
				const char *file, int line)
{
	int i;
	struct npf_pack_message *msg = packed_session;

	_dp_test_fail_unless(sess, file, line,
			"npf_pack sess input invalid\n");
	dp_test_session_msg_check_rcvd(msg, pkts_per_session, sess);

	for (i = 0; i < DP_TEST_MAX_TEST_SESSIONS; i++) {
		if (sess[i].completed == false)
			return false;
	}
	return true;
}
