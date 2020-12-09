/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <zmq_dp.h>
#include <controller.h>
#include <time.h>
#include <pthread.h>

#include "event.h"
#include "fal.h"
#include "fal_plugin.h"
#include "qos.h"
#include "qos_ext_buf_monitor.h"
#include "vplane_debug.h"
#include "vplane_log.h"

enum qos_ext_buf_msg_type {
	EXT_BUF_MSG_MIBINIT = 0,
	EXT_BUF_MSG_CLEAR,
	EXT_BUF_MSG_WARNING,
	EXT_BUF_MSG_ALERT,
	EXT_BUF_MSG_UPDATE,
	EXT_BUF_MSG_NONE
};

struct qos_ext_buf_notification_set {
	enum qos_ext_buf_evt_notify_mode mode;
	uint32_t max_samples;
	uint32_t max_periods;
};

struct qos_external_buffer_congest_stats buf_stats;
static struct rte_timer qos_external_buf_timer;

static const struct qos_ext_buf_notification_set
notifi_mode_set[EXT_BUF_EVT_NOTIFY_MODE_NUM] = {
	{EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC, 1, 3},
	{EXT_BUF_EVT_NOTIFY_MODE_MINUTE,  6, 3},
	{EXT_BUF_EVT_NOTIFY_MODE_HOUR,  360, 1}
};

static const char * const notification_tag[] = {
	"MIBINIT", "CLEAR", "WARNING", "ALERT", "UPDATE"
};

static uint32_t qos_external_buf_counter_ids[] = {
	FAL_QOS_EXTERNAL_BUFFER_COUNTER_ID,
	FAL_QOS_EXTERNAL_BUFFER_PKT_REJECT_COUNTER_ID,
	FAL_QOS_EXTERNAL_BUFFER_MAX_ID
};

static pthread_mutex_t mtx;

static void
qos_ext_buf_stats_data_init(void)
{
	time_t t = time(NULL);

	buf_stats.initial_tm = *localtime(&t);
	buf_stats.prev_sample_idx = EXT_BUF_STATUS_STATS_CNT - 1;
	pthread_mutex_init(&mtx, NULL);
}

static int
qos_ext_buf_state_evt_compare(enum qos_ext_buf_state state,
	enum qos_ext_buf_event event)
{
	switch (state) {
	case EXT_BUF_S_THRESHOLD_ONLY:
		return event < EXT_BUF_EVT_THRESHOLD_ONLY;
	case EXT_BUF_S_REJECTPKT_ONLY:
		return event < EXT_BUF_EVT_REJECTPKT_ONLY;
	case EXT_BUF_S_THRESHOLD_REJECTPKT:
		return event < EXT_BUF_EVT_THRESHOLD_REJECTPKT;
	default:
		break;
	}
	return 0;
}

static int
qos_ext_buf_send_notification(
	struct qos_external_buffer_congest_stats *stats,
	enum qos_ext_buf_msg_type msg_type)
{
	if (!stats)
		return -EINVAL;

	zmsg_t *msg = zmsg_new();

	if (!msg)
		return -ENOMEM;

	if (zmsg_addstr(msg, EXT_BUF_ZMSG_QUEUE) < 0 ||
		zmsg_addstr(msg, notification_tag[msg_type]) < 0)
		goto err;

	if (msg_type == EXT_BUF_MSG_MIBINIT) {
		if (zmsg_addu32(msg, buf_stats.max_buf_desc) < 0)
			goto err;
	} else if (msg_type == EXT_BUF_MSG_UPDATE) {
		struct qos_external_buffer_sample *sample =
			&stats->buf_samples[stats->cur_sample_idx];
		if (zmsg_addu32(msg, buf_stats.max_buf_desc -
			sample->ext_buf_free) < 0 ||
			zmsg_addu32(msg, stats->rejected_pkt_cnt))
			goto err;
	} else if (msg_type == EXT_BUF_MSG_CLEAR) {
		if (zmsg_addu32(msg, MAX_CONSECUTIVE_SAMPLES_ON_CLEAR) < 0)
			goto err;
	} else {
		/* For tag WARNING or ALERT */
		struct qos_external_buffer_sample *sample =
			&stats->buf_samples[stats->cur_sample_idx];
		struct qos_ext_buf_notify_period *period_data =
			&stats->cur_state.period_data;
		uint32_t *cnt = period_data->results_cnt;

		if (zmsg_addu32(msg, buf_stats.buf_cfg_threshold) < 0 ||
			zmsg_addu32(msg,
				cnt[EXT_BUF_SPL_R_THRESHOLD_ONLY]) < 0 ||
			zmsg_addu32(msg,
				cnt[EXT_BUF_SPL_R_REJECTPKT_ONLY]) < 0 ||
			zmsg_addu32(msg,
				cnt[EXT_BUF_SPL_R_THRESHOLD_REJECTPKT]) < 0 ||
			zmsg_addu32(msg, period_data->notify_mode) < 0)
			goto err;

		if (period_data->notify_mode ==
			EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC) {
			if (zmsg_addu32(msg, sample->utilization_rate) < 0)
				goto err;
		}
	}
	return dp_send_event_to_vplaned(msg);
err:
	RTE_LOG(ERR, DATAPLANE,
		"Could not send QoS ext buffer congestion notification.\n");
	zmsg_destroy(&msg);
	return -EINVAL;
}

static void
qos_ext_buf_exec_state_action(struct qos_ext_buf_state_record *cur_state)
{
	if (!cur_state || !buf_stats.buf_cfg_threshold)
		return;

	if (cur_state->state == EXT_BUF_S_CLEAR)
		qos_ext_buf_send_notification(&buf_stats, EXT_BUF_MSG_CLEAR);
	else if (cur_state->state == EXT_BUF_S_THRESHOLD_ONLY) {
		cur_state->msg_warning_cnt++;
		qos_ext_buf_send_notification(&buf_stats, EXT_BUF_MSG_WARNING);
	} else if (cur_state->state == EXT_BUF_S_REJECTPKT_ONLY) {
		cur_state->msg_alert_cnt++;
		qos_ext_buf_send_notification(&buf_stats, EXT_BUF_MSG_ALERT);
	} else if (cur_state->state == EXT_BUF_S_THRESHOLD_REJECTPKT) {
		cur_state->msg_alert_cnt++;
		qos_ext_buf_send_notification(&buf_stats, EXT_BUF_MSG_ALERT);
	}
}

int
qos_ext_buf_state_transit(struct qos_ext_buf_state_record *cur_state,
	enum qos_ext_buf_event evt)
{
	if (!cur_state || evt == EXT_BUF_EVT_NONE)
		return 0;

	enum qos_ext_buf_state new_state = cur_state->state;

	if (evt == EXT_BUF_EVT_CLEAR)
		new_state = EXT_BUF_S_CLEAR;
	else {
		switch (cur_state->state) {
		case EXT_BUF_S_CLEAR:
			if (evt == EXT_BUF_EVT_THRESHOLD_ONLY)
				new_state = EXT_BUF_S_THRESHOLD_ONLY;
			else if (evt == EXT_BUF_EVT_REJECTPKT_ONLY)
				new_state = EXT_BUF_S_REJECTPKT_ONLY;
			else if (evt == EXT_BUF_EVT_THRESHOLD_REJECTPKT)
				new_state = EXT_BUF_S_THRESHOLD_REJECTPKT;
			break;
		case EXT_BUF_S_THRESHOLD_ONLY:
			if (evt == EXT_BUF_EVT_REJECTPKT_ONLY)
				new_state = EXT_BUF_S_REJECTPKT_ONLY;
			else if (evt == EXT_BUF_EVT_THRESHOLD_REJECTPKT)
				new_state = EXT_BUF_S_THRESHOLD_REJECTPKT;
			break;
		case EXT_BUF_S_REJECTPKT_ONLY:
			if (evt == EXT_BUF_EVT_THRESHOLD_REJECTPKT)
				new_state = EXT_BUF_S_THRESHOLD_REJECTPKT;
			break;
		case EXT_BUF_S_THRESHOLD_REJECTPKT:
		default:
			break;
		}
	}

	if (cur_state->state != new_state) {
		cur_state->state = new_state;
		qos_ext_buf_exec_state_action(cur_state);
		if (new_state != EXT_BUF_S_CLEAR) {
			cur_state->bad_periods_in_notification_mode = 1;
			cur_state->consecutive_periods_cnt = 1;
		} else {
			cur_state->bad_periods_in_notification_mode = 0;
			cur_state->consecutive_periods_cnt = 0;
		}
		cur_state->consecutive_good_samples_cnt = 0;
		memset(&cur_state->period_data, 0,
			sizeof(cur_state->period_data));
		return 1;
	}
	return 0;
}

enum qos_ext_buf_event
qos_ext_buf_get_evt_by_sample_result(
	struct qos_ext_buf_state_record *cur_state,
	enum qos_ext_buf_sample_result sample_result)
{
	if (!cur_state)
		return EXT_BUF_EVT_NONE;

	if (sample_result == EXT_BUF_SPL_R_THRESHOLD_ONLY)
		return EXT_BUF_EVT_THRESHOLD_ONLY;
	if (sample_result == EXT_BUF_SPL_R_REJECTPKT_ONLY)
		return EXT_BUF_EVT_REJECTPKT_ONLY;
	if (sample_result == EXT_BUF_SPL_R_THRESHOLD_REJECTPKT)
		return EXT_BUF_EVT_THRESHOLD_REJECTPKT;
	if (sample_result == EXT_BUF_SPL_R_NONE) {
		if (cur_state->state == EXT_BUF_S_CLEAR)
			return EXT_BUF_EVT_NONE;
		cur_state->consecutive_good_samples_cnt++;
		if (cur_state->consecutive_good_samples_cnt >=
			MAX_CONSECUTIVE_SAMPLES_ON_CLEAR)
			return EXT_BUF_EVT_CLEAR;
	}
	return EXT_BUF_EVT_NONE;
}

static void
qos_ext_buf_tune_notification_rate(struct qos_ext_buf_state_record *cur_state,
	struct qos_external_buffer_sample *sample,
	enum qos_ext_buf_event evt)
{
	if (!cur_state || !sample)
		return;

	enum qos_ext_buf_evt_notify_mode *mode =
		&cur_state->period_data.notify_mode;
	uint32_t max_periods = notifi_mode_set[*mode].max_periods;
	int update_notify_mode = 0;

	if (sample->result != EXT_BUF_SPL_R_NONE) {
		cur_state->consecutive_good_samples_cnt = 0;
		/* Because current state event is more severe,
		 * bypass less severe event
		 */
		if (!qos_ext_buf_state_evt_compare(cur_state->state, evt))
			cur_state->period_data.bad_sample_in_period++;
	}

	/* check if end of notification period is reached */
	if (cur_state->period_data.samples_cnt <
		notifi_mode_set[*mode].max_samples)
		return;

	cur_state->consecutive_periods_cnt++;

	if (cur_state->period_data.bad_sample_in_period > 0) {
		cur_state->bad_periods_in_notification_mode++;
		qos_ext_buf_exec_state_action(cur_state);

		update_notify_mode =
			(cur_state->consecutive_periods_cnt >= max_periods) ||
			(cur_state->consecutive_periods_cnt !=
			cur_state->bad_periods_in_notification_mode);
	} else {
		update_notify_mode =
			cur_state->consecutive_periods_cnt >= (max_periods/2);
	}

	/* one sampling period is over, reset data */
	cur_state->period_data.samples_cnt = 0;
	cur_state->period_data.bad_sample_in_period = 0;
	memset(&cur_state->period_data.results_cnt, 0,
		sizeof(cur_state->period_data.results_cnt));

	/* Update notification mode for samples in next period */
	if (update_notify_mode) {
		cur_state->bad_periods_in_notification_mode = 0;
		cur_state->consecutive_periods_cnt = 0;
		*mode = (*mode == EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC) ?
			EXT_BUF_EVT_NOTIFY_MODE_MINUTE :
			((*mode == EXT_BUF_EVT_NOTIFY_MODE_MINUTE) ?
			EXT_BUF_EVT_NOTIFY_MODE_HOUR : *mode);
	}
}

void
qos_ext_buf_schedule_state_machine(
	struct qos_ext_buf_state_record *cur_state,
	struct qos_external_buffer_sample *sample)
{
	enum qos_ext_buf_event event = 0;

	if (!cur_state || !sample)
		return;

	if (cur_state->state == EXT_BUF_S_CLEAR &&
		sample->result == EXT_BUF_SPL_R_NONE)
		return;

	event = qos_ext_buf_get_evt_by_sample_result(cur_state,
			sample->result);

	cur_state->period_data.samples_cnt++;
	cur_state->period_data.results_cnt[sample->result]++;

	if (!qos_ext_buf_state_transit(cur_state, event))
		qos_ext_buf_tune_notification_rate(cur_state, sample, event);
}

static void
qos_ext_buf_process_sample_value(uint64_t buf_free, uint64_t rejected_pkt)
{
	struct qos_external_buffer_sample *sample =
		&buf_stats.buf_samples[buf_stats.cur_sample_idx];
	time_t t = time(NULL);
	struct tm smp_tm = *localtime(&t);
	int e1, e2, e3;

	pthread_mutex_lock(&mtx);

	buf_stats.results_cnt[sample->result]++;
	buf_stats.rejected_pkt_cnt += rejected_pkt;
	buf_stats.total_samples_cnt++;
	sample->sample_tm = smp_tm;
	sample->ext_buf_free = buf_free;
	sample->ext_buf_pkt_reject = rejected_pkt;
	sample->utilization_rate =
		100 - (buf_free * 100) / buf_stats.max_buf_desc;
	e1 = sample->utilization_rate > buf_stats.buf_cfg_threshold;
	e2 = rejected_pkt > 0;
	e3 = e1 && e2;

	sample->result = e3 ? EXT_BUF_SPL_R_THRESHOLD_REJECTPKT :
		(e2 ? EXT_BUF_SPL_R_REJECTPKT_ONLY :
		(e1 ? EXT_BUF_SPL_R_THRESHOLD_ONLY : EXT_BUF_SPL_R_NONE));
	/* update SNMP MIB if values change */
	if ((buf_stats.buf_samples[buf_stats.prev_sample_idx].ext_buf_free !=
		buf_free) || rejected_pkt)
		qos_ext_buf_send_notification(&buf_stats, EXT_BUF_MSG_UPDATE);

	qos_ext_buf_schedule_state_machine(&buf_stats.cur_state, sample);

	buf_stats.prev_sample_idx = buf_stats.cur_sample_idx;
	buf_stats.cur_sample_idx = (buf_stats.cur_sample_idx + 1) %
		EXT_BUF_STATUS_STATS_CNT;

	pthread_mutex_unlock(&mtx);
}

void
qos_external_buffer_congestion_tmr_hdlr(struct rte_timer *tim __rte_unused,
	void *arg __rte_unused)
{
	int ret;
	uint64_t values[FAL_QOS_EXTERNAL_BUFFER_MAX_COUNTER] = { 0 };

	if (buf_stats.total_samples_cnt == 0)
		qos_ext_buf_send_notification(&buf_stats, EXT_BUF_MSG_MIBINIT);

	ret = fal_qos_get_counters(qos_external_buf_counter_ids,
		ARRAY_SIZE(qos_external_buf_counter_ids), values);

	if (ret) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"FAL failed to get external buffer counters, status: %d\n",
			ret);
		return;
	}
	qos_ext_buf_process_sample_value(
		values[FAL_QOS_EXTERNAL_BUFFER_DESC_FREE],
		values[FAL_QOS_EXTERNAL_BUFFER_PKT_REJECT]);
}

void
qos_external_buf_monitor_init(void)
{
	int ret;
	struct fal_attribute_t max_buffers;

	if (!fal_plugins_present()) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			"FAL plugins not present, external buffer monitor init failed.");
		return;
	}

	max_buffers.id = FAL_SWITCH_ATTR_MAX_BUF_DESCRIPTOR;
	ret = fal_get_switch_attrs(1, &max_buffers);

	if (ret) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			"FAL failed to get max buffer descriptors, status: %d\n",
			ret);
		return;
	}

	qos_ext_buf_stats_data_init();
	/* TODO: need to clarify if 2 BDBs are reserved in Broadcom TM */
	buf_stats.max_buf_desc = max_buffers.value.u32 - 2;

	rte_timer_init(&qos_external_buf_timer);
}

void
qos_external_buf_threshold_interval(unsigned int value)
{
	buf_stats.buf_cfg_threshold = value;
	if (!buf_stats.monitor_started && buf_stats.buf_cfg_threshold) {
		buf_stats.monitor_started = 1;
		rte_timer_reset(&qos_external_buf_timer,
			EXT_BUF_STATUS_SAMPLE_INTERVAL * rte_get_timer_hz(),
			PERIODICAL, rte_get_master_lcore(),
			qos_external_buffer_congestion_tmr_hdlr, NULL);
	}
}

int
qos_ext_buf_get_stats(struct qos_external_buffer_congest_stats *stats)
{
	if (!stats)
		return 0;

	pthread_mutex_lock(&mtx);

	memcpy(stats, &buf_stats, sizeof(buf_stats));

	pthread_mutex_unlock(&mtx);

	return 1;
}

int qos_ext_buf_get_threshold(uint32_t *threshold)
{
	if (!buf_stats.monitor_started)
		return 0;

	*threshold = buf_stats.buf_cfg_threshold;
	return 1;
}
