/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * QoS external buffer monitor tests
 */

#include <libmnl/libmnl.h>

#include "ip6_funcs.h"
#include "ip_funcs.h"
#include "in_cksum.h"
#include "if_var.h"
#include "main.h"
#include "qos_ext_buf_monitor.h"

#include "dp_test.h"
#include "dp_test_str.h"
#include "dp_test_lib_internal.h"
#include "dp_test_lib_exp.h"
#include "dp_test_lib_pkt.h"
#include "dp_test_lib_intf_internal.h"
#include "dp_test_pktmbuf_lib_internal.h"
#include "dp_test_netlink_state_internal.h"
#include "dp_test/dp_test_macros.h"
#include "dp_test_console.h"
#include "dp_test_json_utils.h"

struct qos_counters {
	uint32_t buf_free;
	uint32_t dropped;
	enum qos_ext_buf_state state;
};

DP_DECL_TEST_SUITE(qos_ext_buf_monitor);

DP_DECL_TEST_CASE(qos_ext_buf_monitor, ext_buf_monitor_test, NULL, NULL);

static void qos_ext_buf_test_init(void)
{
	memset(&buf_stats, 0, sizeof(buf_stats));

	buf_stats.max_buf_desc = 98302;
	buf_stats.buf_cfg_threshold = 85;
	buf_stats.cur_state.state = EXT_BUF_S_CLEAR;
	buf_stats.cur_state.period_data.notify_mode =
		EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC;
}

static void dp_test_qos_ext_buf_state_transition(void)
{
	int ret;
	struct qos_ext_buf_state_record *cur_state = &buf_stats.cur_state;
	enum qos_ext_buf_event evt;

	qos_ext_buf_test_init();

	/* test unchanged CLEAR state */
	cur_state->state = EXT_BUF_S_CLEAR;
	evt = EXT_BUF_EVT_CLEAR;
	ret = qos_ext_buf_state_transit(cur_state, evt);
	dp_test_fail_unless(!ret && cur_state->state == EXT_BUF_S_CLEAR,
		"S_CLEAR state is expected!");

	/* test S_CLEAR -> S_THRESHOLD state transition */
	cur_state->state = EXT_BUF_S_CLEAR;
	evt = EXT_BUF_EVT_THRESHOLD_ONLY;
	ret = qos_ext_buf_state_transit(cur_state, evt);
	dp_test_fail_unless(ret == 1 &&
			    cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
			    "S_THRESHOLD_ONLY state is expected!");
	dp_test_fail_unless(cur_state->consecutive_periods_cnt == 1,
		"Bad periods cnt is expected to be 1!");

	/* test EVT_THRESHOLD won't trigger state S_REJECTPKT change */
	cur_state->state = EXT_BUF_S_REJECTPKT_ONLY;
	evt = EXT_BUF_EVT_THRESHOLD_ONLY;
	ret = qos_ext_buf_state_transit(cur_state, evt);
	dp_test_fail_unless(ret == 0 &&
			    cur_state->state == EXT_BUF_S_REJECTPKT_ONLY,
			    "S_REJECTPKT_ONLY state is expected!");

	/* S_REJECTPKT -> S_THRESHOLD_REJECTPKT */
	cur_state->state = EXT_BUF_S_REJECTPKT_ONLY;
	evt = EXT_BUF_EVT_THRESHOLD_REJECTPKT;
	ret = qos_ext_buf_state_transit(cur_state, evt);
	dp_test_fail_unless(ret == 1 &&
			    cur_state->state == EXT_BUF_S_THRESHOLD_REJECTPKT,
			    "S_THRESHOLD_AND_REJECTPKT state is expected!");

	/* S_REJECTPKT -> S_CLEAR */
	cur_state->state = EXT_BUF_S_REJECTPKT_ONLY;
	evt = EXT_BUF_EVT_CLEAR;
	ret = qos_ext_buf_state_transit(cur_state, evt);
	dp_test_fail_unless(ret == 1 && cur_state->state == EXT_BUF_S_CLEAR,
		"S_CLEAR state is expected!");
}

static void dp_test_qos_ext_buf_event_from_sample_result(void)
{
	struct qos_ext_buf_state_record *cur_state = &buf_stats.cur_state;
	enum qos_ext_buf_event evt = EXT_BUF_EVT_NONE;
	enum qos_ext_buf_sample_result smp_result;
	uint32_t clear_cnt = MAX_CONSECUTIVE_SAMPLES_ON_CLEAR;

	qos_ext_buf_test_init();

	/* no state behavior for good sample result */
	cur_state->state = EXT_BUF_S_THRESHOLD_ONLY;
	cur_state->consecutive_good_samples_cnt = clear_cnt - 3;
	smp_result = EXT_BUF_SPL_R_NONE;
	evt = qos_ext_buf_get_evt_by_sample_result(cur_state, smp_result);
	dp_test_fail_unless(evt == EXT_BUF_EVT_NONE &&
		cur_state->consecutive_good_samples_cnt == (clear_cnt-2),
		"EVT_NONE is expected!");

	/* Get EVT_CLEAR when accumulating good samples */
	cur_state->state = EXT_BUF_S_THRESHOLD_ONLY;
	cur_state->consecutive_good_samples_cnt = clear_cnt - 1;
	smp_result = EXT_BUF_SPL_R_NONE;
	evt = qos_ext_buf_get_evt_by_sample_result(cur_state, smp_result);
	dp_test_fail_unless(evt == EXT_BUF_EVT_CLEAR,
		"EVT_CLEAR is expected!");

	/* Get event from bad sample */
	memset(cur_state, 0, sizeof(*cur_state));
	cur_state->state = EXT_BUF_S_CLEAR;
	smp_result = EXT_BUF_SPL_R_THRESHOLD_ONLY;
	evt = qos_ext_buf_get_evt_by_sample_result(cur_state, smp_result);
	dp_test_fail_unless(evt == EXT_BUF_EVT_THRESHOLD_ONLY,
		"EVT_THRESHOLD_ONLY is expected!");
}

static void dp_test_qos_ext_buf_schedule_action_with_samples_result(void)
{
	struct qos_ext_buf_state_record *cur_state = &buf_stats.cur_state;
	struct qos_external_buffer_sample *sample = &buf_stats.buf_samples[0];

	qos_ext_buf_test_init();

	/* No change in S_CLEAR state */
	cur_state->state = EXT_BUF_S_CLEAR;
	sample->result = EXT_BUF_SPL_R_NONE;
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_CLEAR,
		"S_CLEAR is expected!");

	/* State changed due to more severe event
	 * NOtification mode changed to TEN_SEC,
	 * periods counters is expected to be 1
	 */
	cur_state->state = EXT_BUF_S_THRESHOLD_ONLY;
	sample->result = EXT_BUF_SPL_R_REJECTPKT_ONLY;
	cur_state->period_data.notify_mode =
		EXT_BUF_EVT_NOTIFY_MODE_MINUTE;
	cur_state->period_data.samples_cnt = 4;
	cur_state->consecutive_periods_cnt = 2;
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_REJECTPKT_ONLY,
		"S_REJECTPKT_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.notify_mode ==
		EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC,
		"EVT_NOTIFY_MODE_TEN_SEC is expected!");
	dp_test_fail_unless(cur_state->consecutive_periods_cnt == 1,
		"Value is expected to be 1! But actual value is %d.",
		cur_state->consecutive_periods_cnt);
	dp_test_fail_unless(cur_state->bad_periods_in_notification_mode == 1,
		"Value is expected to be 1! But actual value is %d.",
		cur_state->bad_periods_in_notification_mode);
	dp_test_fail_unless(cur_state->period_data.samples_cnt == 0,
		"Value is expected to be 0! But actual value is %d.",
		cur_state->period_data.samples_cnt);

	/* State not changed due to less severe event */
	memset(cur_state, 0, sizeof(*cur_state));
	cur_state->state = EXT_BUF_S_REJECTPKT_ONLY;
	sample->result = EXT_BUF_SPL_R_THRESHOLD_ONLY;
	cur_state->period_data.notify_mode =
		EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC;
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_REJECTPKT_ONLY,
		"S_REJECTPKT_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.bad_sample_in_period == 0,
		"EVT_NOTIFY_MODE_HOURLY is expected!");

	/* tune notification mode TEN_SEC -> MINUTE */
	memset(cur_state, 0, sizeof(*cur_state));
	cur_state->state = EXT_BUF_S_THRESHOLD_ONLY;
	sample->result = EXT_BUF_SPL_R_THRESHOLD_ONLY;
	cur_state->period_data.notify_mode =
		EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC;
	cur_state->period_data.samples_cnt = 0;
	cur_state->period_data.bad_sample_in_period = 0;
	cur_state->consecutive_periods_cnt = 2;
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
		"S_THRESHOLD_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.notify_mode ==
		EXT_BUF_EVT_NOTIFY_MODE_MINUTE,
		"EVT_NOTIFY_MODE_MINUTELY is expected!");
	dp_test_fail_unless(cur_state->consecutive_periods_cnt == 0,
		"Value is expected to be 0! But actual value is %d.",
		cur_state->consecutive_periods_cnt);
	/* mode not change with one event in new period */
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
		"S_THRESHOLD_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.notify_mode ==
		EXT_BUF_EVT_NOTIFY_MODE_MINUTE,
		"EVT_NOTIFY_MODE_MINUTELY is expected!");
	dp_test_fail_unless(cur_state->consecutive_periods_cnt == 0,
		"Value is expected to be 0! But actual value is %d.",
		cur_state->consecutive_periods_cnt);

	/* tune notification mode MINUTE -> HOUR */
	memset(cur_state, 0, sizeof(*cur_state));
	cur_state->state = EXT_BUF_S_THRESHOLD_ONLY;
	sample->result = EXT_BUF_SPL_R_THRESHOLD_ONLY;
	cur_state->period_data.notify_mode =
		EXT_BUF_EVT_NOTIFY_MODE_MINUTE;
	cur_state->period_data.samples_cnt = 3;
	cur_state->period_data.bad_sample_in_period = 0;
	cur_state->consecutive_periods_cnt = 2;
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
		"S_THRESHOLD_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.notify_mode ==
		EXT_BUF_EVT_NOTIFY_MODE_MINUTE,
		"EVT_NOTIFY_MODE_MINUTELY is expected!");
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
		"S_THRESHOLD_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.notify_mode ==
		EXT_BUF_EVT_NOTIFY_MODE_MINUTE,
		"EVT_NOTIFY_MODE_MINUTELY is expected!");
	dp_test_fail_unless(cur_state->consecutive_periods_cnt == 2,
		"Value is expected to be 2! But actual value is %d.",
		cur_state->consecutive_periods_cnt);
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
		"S_THRESHOLD_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.notify_mode ==
		EXT_BUF_EVT_NOTIFY_MODE_HOUR,
		"EVT_NOTIFY_MODE_HOURLY is expected!");

	/* state from S_CLEAR -> S_THRESHOLD
	 * mode from TEN_SEC -> MINUTE after 3 consecutive bad samples
	 */
	memset(cur_state, 0, sizeof(*cur_state));
	cur_state->state = EXT_BUF_S_CLEAR;
	sample->result = EXT_BUF_SPL_R_THRESHOLD_ONLY;
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
		"S_THRESHOLD_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.notify_mode ==
		EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC,
		"EVT_NOTIFY_MODE_TEN_SEC is expected!");
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
			"S_THRESHOLD_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.notify_mode ==
			EXT_BUF_EVT_NOTIFY_MODE_MINUTE,
			"EVT_NOTIFY_MODE_MINUTELY is expected!");
	/* mode from MINUTE -> HOUR after 3 consecutive bad 1-minute periods */
	for (uint32_t i = 0; i < 3; i++) {
		uint32_t j = 0;

		for (; j < 5; j++) {
			qos_ext_buf_schedule_state_machine(cur_state, sample);
			dp_test_fail_unless(cur_state->state ==
				EXT_BUF_S_THRESHOLD_ONLY,
				"S_THRESHOLD_ONLY is expected!");
			dp_test_fail_unless(
				cur_state->period_data.notify_mode ==
				EXT_BUF_EVT_NOTIFY_MODE_MINUTE,
				"EVT_NOTIFY_MODE_MINUTELY is expected!");
			dp_test_fail_unless(cur_state->msg_warning_cnt == 3+i,
				"Warning cnt should be %d! Actual value %d",
				3+i, cur_state->msg_warning_cnt);
		}

		qos_ext_buf_schedule_state_machine(cur_state, sample);
		dp_test_fail_unless(cur_state->msg_warning_cnt == 4+i,
			"Warning msg cnt is expected to be %d! Actual value %d",
			4+i, cur_state->msg_warning_cnt);
		dp_test_fail_unless(cur_state->state ==
			EXT_BUF_S_THRESHOLD_ONLY,
			"S_THRESHOLD_ONLY is expected!");

		if (i == 2 && j == 5) {
			dp_test_fail_unless(
				cur_state->period_data.notify_mode ==
				EXT_BUF_EVT_NOTIFY_MODE_HOUR,
				"EVT_NOTIFY_MODE_HOURLY is expected! Actual value %d",
				cur_state->period_data.notify_mode);
		} else {
			dp_test_fail_unless(
				cur_state->period_data.notify_mode ==
				EXT_BUF_EVT_NOTIFY_MODE_MINUTE,
				"MODE_MINUTELY is expected! Actual value %d. P%d, S%d",
				cur_state->period_data.notify_mode, i, j);
		}
	}
	/* keep HOUR mode following tests above */
	for (int i = 0; i < 180; i++)
		qos_ext_buf_schedule_state_machine(cur_state, sample);
	sample->result = EXT_BUF_SPL_R_NONE;
	for (int i = 0; i < 180; i++)
		qos_ext_buf_schedule_state_machine(cur_state, sample);

	dp_test_fail_unless(cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
		"S_THRESHOLD_ONLY is expected!");
	dp_test_fail_unless(cur_state->period_data.notify_mode ==
		EXT_BUF_EVT_NOTIFY_MODE_HOUR,
		"EVT_NOTIFY_MODE_HOURLY is expected! Actual value %d",
		cur_state->period_data.notify_mode);
	dp_test_fail_unless(cur_state->msg_warning_cnt == 7,
		"Warning msg cnt is expected to be %d! Actual value %d",
		7, cur_state->msg_warning_cnt);
	/* CLEAR after 360 good samples since last bad one */
	sample->result = EXT_BUF_SPL_R_NONE;
	for (int i = 0; i < 179; i++)
		qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_THRESHOLD_ONLY,
		"S_THRESHOLD_ONLY is expected!");
	qos_ext_buf_schedule_state_machine(cur_state, sample);
	dp_test_fail_unless(cur_state->state == EXT_BUF_S_CLEAR,
		"S_CLEAR is expected!");
}

static void dp_test_qos_ext_buf_tmr_hdlr(void)
{
	struct qos_ext_buf_state_record *cur_state = &buf_stats.cur_state;

	/* same values as fal_plugin_qos_get_counters() */
	struct qos_counters values[] = {
		{50000, 0, EXT_BUF_S_CLEAR},
		{3000,  0, EXT_BUF_S_THRESHOLD_ONLY},
		{50000, 0, EXT_BUF_S_THRESHOLD_ONLY},
		{50000, 1, EXT_BUF_S_REJECTPKT_ONLY},
		{3000,  0, EXT_BUF_S_REJECTPKT_ONLY},
		{3000,  1, EXT_BUF_S_THRESHOLD_REJECTPKT},
		{3000,  0, EXT_BUF_S_THRESHOLD_REJECTPKT}
	};

	int size = ARRAY_SIZE(values);

	qos_ext_buf_test_init();

	for (int i = 0; i < size; i++) {
		struct qos_external_buffer_sample *sample =
			&buf_stats.buf_samples[buf_stats.cur_sample_idx];

		qos_external_buffer_congestion_tmr_hdlr(NULL, NULL);

		dp_test_fail_unless(cur_state->state == values[i].state,
			"Timer %d, S_CLEAR is expected! Actual state is %d",
			i, cur_state->state);
		dp_test_fail_unless(sample->ext_buf_free == values[i].buf_free,
			"Timer %d, buf_free expected/actual %u/%" PRIu64,
			i, values[i].buf_free, sample->ext_buf_free);
		dp_test_fail_unless(
			sample->ext_buf_pkt_reject == values[i].dropped,
			"Timer %d, Pkt_dropped expected/actual %u/%" PRIu64,
			i, values[i].dropped, sample->ext_buf_pkt_reject);
	}
}

DP_START_TEST(ext_buf_monitor_test, test1)
{
	dp_test_qos_ext_buf_state_transition();

	dp_test_qos_ext_buf_event_from_sample_result();

	dp_test_qos_ext_buf_schedule_action_with_samples_result();

	dp_test_qos_ext_buf_tmr_hdlr();
} DP_END_TEST;
