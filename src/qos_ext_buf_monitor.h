/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef QOS_EXT_BUF_MONITOR_H
#define QOS_EXT_BUF_MONITOR_H

#include <pthread.h>

#define EXT_BUF_STATUS_STATS_CNT 6
#define EXT_BUF_STATUS_SAMPLE_INTERVAL 10 /* 10 sec */
#define MAX_CONSECUTIVE_SAMPLES_ON_CLEAR 360 /* 360 consecutive samples */

#define EXT_BUF_ZMSG_QUEUE "QosExtBufCongestion"

enum qos_ext_buf_evt_notify_mode {
	EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC = 0,
	EXT_BUF_EVT_NOTIFY_MODE_MINUTE,
	EXT_BUF_EVT_NOTIFY_MODE_HOUR,
	EXT_BUF_EVT_NOTIFY_MODE_NUM
};

enum qos_ext_buf_event {
	EXT_BUF_EVT_NONE = 0,
	EXT_BUF_EVT_THRESHOLD_ONLY,
	EXT_BUF_EVT_REJECTPKT_ONLY,
	EXT_BUF_EVT_THRESHOLD_REJECTPKT,
	EXT_BUF_EVT_CLEAR
};

enum qos_ext_buf_state {
	EXT_BUF_S_CLEAR = 0,
	EXT_BUF_S_THRESHOLD_ONLY,
	EXT_BUF_S_REJECTPKT_ONLY,
	EXT_BUF_S_THRESHOLD_REJECTPKT
};

enum qos_ext_buf_sample_result {
	EXT_BUF_SPL_R_NONE = 0,
	EXT_BUF_SPL_R_THRESHOLD_ONLY,
	EXT_BUF_SPL_R_REJECTPKT_ONLY,
	EXT_BUF_SPL_R_THRESHOLD_REJECTPKT,
	EXT_BUF_SPL_R_NUM
};

struct qos_ext_buf_notify_period {
	enum qos_ext_buf_evt_notify_mode notify_mode;
	uint16_t samples_cnt; /* total samples in a period */
	uint16_t bad_sample_in_period;
	uint32_t results_cnt[EXT_BUF_SPL_R_NUM];
};

struct qos_ext_buf_state_record {
	enum qos_ext_buf_state state;
	uint32_t consecutive_good_samples_cnt;
	uint32_t consecutive_periods_cnt;
	uint32_t bad_periods_in_notification_mode;
	uint32_t msg_warning_cnt;
	uint32_t msg_alert_cnt;
	struct qos_ext_buf_notify_period period_data;
};

struct qos_external_buffer_sample {
	uint64_t ext_buf_free;
	uint64_t ext_buf_pkt_reject;
	uint32_t utilization_rate;
	enum qos_ext_buf_sample_result result;
	struct tm sample_tm;
};

struct qos_external_buffer_congest_stats {
	struct qos_external_buffer_sample
		buf_samples[EXT_BUF_STATUS_STATS_CNT];
	int cur_sample_idx;
	int prev_sample_idx;
	struct qos_ext_buf_state_record cur_state;
	uint64_t rejected_pkt_cnt;
	uint64_t results_cnt[EXT_BUF_SPL_R_NUM];
	uint64_t total_samples_cnt;
	uint32_t max_buf_desc;
	uint32_t buf_cfg_threshold;
	int monitor_started;
	struct tm initial_tm;
};

int qos_ext_buf_state_transit(
	struct qos_ext_buf_state_record *cur_state,
	enum qos_ext_buf_event evt);
enum qos_ext_buf_event qos_ext_buf_get_evt_by_sample_result(
	struct qos_ext_buf_state_record *cur_state,
	enum qos_ext_buf_sample_result sample_result);
void qos_ext_buf_schedule_state_machine(
	struct qos_ext_buf_state_record *cur_state,
	struct qos_external_buffer_sample *sample);
int qos_ext_buf_get_stats(struct qos_external_buffer_congest_stats *stats);
int qos_ext_buf_get_threshold(uint32_t *threshold);
void qos_external_buffer_congestion_tmr_hdlr(
	struct rte_timer *tim __rte_unused,
	void *arg __rte_unused);

void qos_external_buf_monitor_init(void);
void qos_external_buf_threshold_interval(unsigned int value);

#endif /* QOS_EXT_BUF_MONITOR_H */
