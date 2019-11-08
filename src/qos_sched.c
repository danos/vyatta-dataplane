/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2013-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/if.h>
#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_meter.h>
#include <rte_red.h>
#include <rte_sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <urcu/uatomic.h>

#include "commands.h"
#include "compiler.h"
#include "dp_event.h"
#include "ether.h"
#include "if_var.h"
#include "ip_funcs.h"
#include "json_writer.h"
#include "main.h"
#include "netinet6/ip6_funcs.h"
#include "npf/npf.h"
#include "npf/config/npf_attach_point.h"
#include "npf/config/npf_auto_attach.h"
#include "npf/config/npf_config.h"
#include "npf/config/npf_rule_group.h"
#include "npf/config/npf_ruleset_type.h"
#include "npf/npf_ruleset.h"
#include "npf/rproc/npf_ext_action_group.h"
#include "npf/rproc/npf_rproc.h"
#include "npf/npf_rule_gen.h"
#include "npf_shim.h"
#include "pktmbuf.h"
#include "qos.h"
#include "qos_obj_db.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

struct qos_dev qos_devices[NUM_DEVS] = {
	{ qos_dpdk_disable,
	  qos_dpdk_enable,
	  qos_dpdk_start,
	  qos_dpdk_stop,
	  qos_dpdk_free,
	  qos_dpdk_subport_read_stats,
	  qos_dpdk_subport_clear_stats,
	  qos_dpdk_queue_read_stats,
	  qos_dpdk_queue_clear_stats,
	  qos_dpdk_dscp_resgrp_json,
	},
	{ qos_hw_disable,
	  qos_hw_enable,
	  qos_hw_start,
	  qos_hw_stop,
	  qos_hw_free,
	  qos_hw_subport_read_stats,
	  qos_hw_subport_clear_stats,
	  qos_hw_queue_read_stats,
	  qos_hw_queue_clear_stats,
	  qos_hw_dscp_resgrp_json,
	}
};

/*
 * Carry out any one-time initialisation that required when the
 * vyatta-dataplane starts up.
 */
void
qos_init(void)
{
	if (rte_red_set_scaling(MAX_RED_QUEUE_LENGTH) != 0)
		rte_panic("Failed to set RED scaling\n");
}

/* Sets the PCP value to map to the given queue for a particular profile. */
static int qos_sched_profile_pcp_map_set(struct sched_info *qinfo,
					 unsigned int profile, uint8_t pcp,
					 uint8_t q)
{
	struct queue_map *qmap = &qinfo->queue_map[profile];

	if (qmap->dscp_enabled == 1) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Cannot configure PCP and DSCP map together.\n");
		return 0;
	}

	qmap->pcp2q[pcp] = q;

	if (qmap->pcp_enabled == 0) {
		DP_DEBUG(QOS, INFO, DATAPLANE,
			 "PCP map not enabled, enabling\n");
		qmap->pcp_enabled = 1;
	}

	return 1;
}

/* Sets the DSCP value to map to the given queue for a particular profile. */
static int qos_sched_profile_dscp_map_set(struct sched_info *qinfo,
					  unsigned int profile, uint8_t dscp,
					  uint8_t q, bool local_priority)
{
	struct queue_map *qmap = &qinfo->queue_map[profile];

	if (qmap->pcp_enabled == 1) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Cannot configure DSCP and PCP maps together.\n");
		return 0;
	}

	if (local_priority) {
		uint8_t i;

		/*
		 * This queue is to be used for high priority (>= cs6) locally
		 * generated traffic.
		 */
		for (i = 0; i < MAX_DSCP; i++)
			if ((qmap->dscp2q[i] & RTE_SCHED_TC_WRR_MASK) == q) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Queue %u configured for local traffic"
					 " is already in use.\n", q);
				return 0;
			}

		qmap->local_priority_queue = q;
		qmap->local_priority = 1;
	} else
		qmap->dscp2q[dscp] = q;

	if (qmap->dscp_enabled == 0) {
		DP_DEBUG(QOS, INFO, DATAPLANE,
			 "DSCP map not enabled, enabling\n");
		qmap->dscp_enabled = 1;
	}

	return 1;
}

/*
 * Returns the rate (bytes/sec) for the given bandwidth structure. If bandwidth
 * is given as a percentage, calculates the rate from the parent. Otherwise
 * returns the rate provided in the bandwidth structure.
 */
static uint32_t qos_rate_get(struct qos_rate_info *bw_info, uint32_t parent_bw)
{
	return bw_info->bw_is_percent ?
		((uint64_t)parent_bw * bw_info->rate.bw_percent) / 100 :
		bw_info->rate.bandwidth;
}

/*
 * Sets the rate (bytes/sec) into the given bandwidth structure. Returns
 * the calculated rate of the entity (see qos_rate_get for details)
 */
static uint32_t qos_rate_set(struct qos_rate_info *bw_info,
			uint32_t bw, bool is_percent, uint32_t parent_bw)
{
	bw_info->bw_is_percent = is_percent;

	if (is_percent)
		bw_info->rate.bw_percent = bw;
	else
		bw_info->rate.bandwidth = bw;

	return qos_rate_get(bw_info, parent_bw);
}

/*
 * Returns the period of the given entity. Currently this is a stub and
 * can be implemented if deemed necessary.
 */
static uint32_t qos_period_get(struct qos_rate_info *bw_info, uint32_t period)
{
	(void)bw_info;
	return period;
}

/*
 * Sets the period of the given entity. Currently this is a stub and
 * can be implemented if deemed necessary.
 */
static uint32_t qos_period_set(struct qos_rate_info *bw_info, uint32_t period)
{
	bw_info->period = period;
	return qos_period_get(bw_info, period);
}

/*
 * NB: Releasing of NPF resources needs done outside of RCU as a)
 * the database of config is not designed for RCU and so will result
 * in out-of-order events and b) the NPF running config does its own
 * RCU actions, so should not be called from within an RCU callback.
 */
void qos_subport_npf_free(struct sched_info *qinfo)
{
	unsigned int i;
	uint32_t j;

	for (i = 0, j = 0;
	     i < qinfo->port_params.n_subports_per_port;
	     j = 0, i++) {
		struct subport_info *sinfo = qinfo->subport + i;
		int ret_val;
		struct mark_reqs *mark_list, *free_mark;

		while (j++ < sinfo->match_id) {
			ret_val = npf_cfg_auto_attach_rule_delete(
				NPF_RULE_CLASS_QOS, sinfo->attach_name,
				j, NULL);
			if (ret_val < 0) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Deleting match for class failed.\n");
			}
		}
		for (mark_list = sinfo->marks; mark_list; ) {
			free_mark = mark_list;
			mark_list = mark_list->next;
			free(free_mark);
			DP_DEBUG(QOS, DEBUG, DATAPLANE,
				 "freeing mark from subport %s\n",
				 sinfo->attach_name);
		}
		npf_attpt_item_set_down(NPF_ATTACH_TYPE_QOS,
					sinfo->attach_name);
	}
}

static void qos_subport_free(struct sched_info *qinfo)
{
	unsigned int i;

	for (i = 0; i < qinfo->port_params.n_subports_per_port; i++) {
		struct subport_info *sinfo = qinfo->subport + i;

		free(sinfo->profile_map);
	}
	free(qinfo->subport);
}

/* Destroy QoS scheduler object */
void qos_sched_free(struct sched_info *qinfo)
{
	unsigned int i;
	struct rte_sched_pipe_params *pp;

	for (i = 0; i < qinfo->port_params.n_pipe_profiles; i++) {
		struct profile_wred_info *profile_wred =
			&qinfo->wred_profiles[i];
		unsigned int j;

		pp = &qinfo->port_params.pipe_profiles[i];
		rte_red_free_q_params(pp, i);
		for (j = 0; j < RTE_SCHED_QUEUES_PER_PIPE; j++) {
			struct queue_wred_info *queue_wred =
				&profile_wred->queue_wred[j];
			unsigned int k;

			for (k = 0; k < queue_wred->num_maps; k++)
				free(queue_wred->dscp_grp_names[k]);
		}
	}

	free(qinfo->wred_profiles);
	free(qinfo->port_params.pipe_profiles);
	free(qinfo->profile_rates);
	free(qinfo->profile_tc_rates);
	if (qinfo->subport)
		qos_subport_free(qinfo);

	free(qinfo->queue_map);
	free(qinfo->queue_stats);
	QOS_FREE(qinfo)(qinfo);
	free(qinfo);
}

void qos_sched_free_rcu(struct rcu_head *head)
{
	qos_sched_free(caa_container_of(head, struct sched_info, rcu));
}

/* Create new QoS scheduler object.
 * The object is not ready to use until all the profiles and other
 * tables are configured
 */
struct sched_info *qos_sched_new(struct ifnet *ifp,
				 unsigned int subports,
				 unsigned int pipes,
				 unsigned int profiles,
				 int32_t overhead)
{
	struct sched_info *qinfo;
	unsigned int i, j;
	struct rte_sched_pipe_params *pipe_params;
	struct qos_rate_info *profile_rates;
	struct qos_tc_rate_info *profile_tc_rates;
	int socketid = rte_eth_dev_socket_id(ifp->if_port);
	char sched_name[32];
	unsigned int queues;

	if (socketid < 0) /* SOCKET_ID_ANY */
		socketid = 0;

	qinfo = zmalloc_aligned(sizeof(struct sched_info));
	if (!qinfo)
		goto nomem0;

	qinfo->queue_map = calloc(profiles, sizeof(struct queue_map));
	if (!qinfo->queue_map)
		goto nomem1;

	queues = RTE_SCHED_QUEUES_PER_PIPE * pipes * subports;
	qinfo->queue_stats = calloc(queues, sizeof(struct queue_stats));
	if (!qinfo->queue_stats)
		goto nomem1;

	qinfo->subport = calloc(subports, sizeof(struct subport_info));
	if  (!qinfo->subport)
		goto nomem1;

	qinfo->wred_profiles = calloc(profiles, sizeof(*qinfo->wred_profiles));
	if (!qinfo->wred_profiles)
		goto nomem1;

	profile_rates = calloc(profiles, sizeof(struct qos_rate_info));
	if (!profile_rates)
		goto nomem1;
	qinfo->profile_rates = profile_rates;

	profile_tc_rates = calloc(profiles, sizeof(struct qos_tc_rate_info));
	if (!profile_tc_rates)
		goto nomem1;
	qinfo->profile_tc_rates = profile_tc_rates;

	pipe_params = calloc(profiles, sizeof(struct rte_sched_pipe_params));
	if (!pipe_params)
		goto nomem1;
	qinfo->port_params.pipe_profiles = pipe_params;


	/* XXX this is really unused by current DPDK code. */
	snprintf(sched_name, sizeof(sched_name),
		 "qos_port_%u", ifp->if_port);
	qinfo->port_params.name = sched_name;

	qinfo->enabled = false;
	qinfo->port_params.socket = socketid;
	qinfo->port_params.frame_overhead = overhead;
	qinfo->port_params.n_subports_per_port = subports;
	qinfo->port_params.n_pipes_per_subport = pipes;
	qinfo->port_params.n_pipe_profiles = profiles;
	rte_spinlock_init(&qinfo->stats_lock);

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		qinfo->port_params.qsize[i] = DEFAULT_QSIZE;

	/* Default parms for pipes */
	for (i = 0; i < profiles; i++) {
		struct rte_sched_pipe_params *pp = &pipe_params[i];
		struct queue_map *qmap = &qinfo->queue_map[i];

		pp->tb_rate = qos_rate_set(&profile_rates[i],
					    UINT32_MAX, false, 0);
		pp->tb_size = profile_rates[i].burst = DEFAULT_TBSIZE;
		pp->tc_period = qos_period_set(&profile_rates[i], 10);
#ifdef RTE_SCHED_SUBPORT_TC_OV
		pp->tc_ov_weight = 0;
#endif
		for (j = 0; j < RTE_SCHED_QUEUES_PER_PIPE; j++)
			pp->wrr_weights[j] = 1;

		for (j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++) {
			pp->tc_rate[j] =
				qos_rate_set(&profile_tc_rates[i].tc_rate[j],
						UINT32_MAX, false, 0);
		}

		qmap->dscp_enabled = 0;
		for (j = 0; j < MAX_DSCP; j++)
			qmap->dscp2q[j] = (~j >>
					   (DSCP_BITS - RTE_SCHED_TC_BITS))
				& RTE_SCHED_TC_MASK;

		qmap->pcp_enabled = 0;
		for (j = 0; j < MAX_PCP; j++)
			qmap->pcp2q[j] = (~j >> (PCP_BITS - RTE_SCHED_TC_BITS))
				& RTE_SCHED_TC_MASK;

		qmap->local_priority = 0;

		/*
		 * Set up the default pipe-queue to tc-n/wrr-0 qmap information
		 */
		for (j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++)
			qmap->conf_ids[QMAP(j, 0)] = CONF_ID_Q_DEFAULT |
				(j * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);

		SLIST_INIT(&pp->qred_head);
	}

	for (i = 0; i < subports; i++) {
		struct subport_info *sp = &qinfo->subport[i];
		int ret;

		snprintf(sp->attach_name, sizeof(sp->attach_name), "%s/%u",
			 ifp->if_name, i);
		ret = npf_attpt_item_set_up(NPF_ATTACH_TYPE_QOS,
					    sp->attach_name,
					    &sp->npf_config, NULL);
		if (ret != 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Failed to register %s with NPF, %s(%d)\n",
				 sp->attach_name, strerror(-ret), ret);
			goto nomem1;
		}
		sp->match_id = 0;
		sp->profile_map = calloc(pipes, sizeof(uint8_t));

		/* Default params */
		sp->params.tb_rate = qos_rate_set(&sp->subport_rate, UINT32_MAX,
						false, 0);
		sp->params.tb_size = sp->subport_rate.burst = DEFAULT_TBSIZE;
		sp->params.tc_period = qos_period_set(&sp->subport_rate, 10);

		for (j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++) {
			sp->params.tc_rate[j] =
				qos_rate_set(&sp->sp_tc_rates.tc_rate[j],
						UINT32_MAX, false, 0);
			sp->qsize[j] = 0;    // Default to inherit from port
		}
	}

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
		 "New Qos configuration %s\n", qinfo->port_params.name);

	return qinfo;

 nomem1:
	qos_subport_npf_free(qinfo);
	qos_sched_free(qinfo);

 nomem0:
	return NULL;
}

/* Ensure the parameters are within acceptable bounds */
void qos_sched_subport_params_check(
		struct rte_sched_subport_params *params,
		struct qos_rate_info *config_rate,
		struct qos_rate_info *config_tc_rate,
		uint16_t max_pkt_len, uint32_t bps)
{
	uint32_t min_rate = (max_pkt_len * 1000) / params->tc_period;
	uint32_t tc_period = 0, period = 0;
	unsigned int i;

	params->tb_rate = qos_rate_get(config_rate, bps);

	/* squash rate down to actual line rate */
	if (params->tb_rate > bps)
		params->tb_rate = bps;

	params->tb_size = config_rate->burst;

	if (params->tb_size < max_pkt_len)
		params->tb_size = max_pkt_len;

	period = params->tc_period;
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		params->tc_rate[i] = qos_rate_get(&config_tc_rate[i],
						  params->tb_rate);
		if (params->tc_rate[i] > bps)
			params->tc_rate[i] = bps;
		if (params->tc_rate[i] > params->tb_rate)
			params->tc_rate[i] = params->tb_rate;

		if (params->tc_rate[i] < min_rate) {
			tc_period = (max_pkt_len * 1000) / params->tc_rate[i];
			/* account for rounding, ensure non-zero */
			tc_period++;
			if (tc_period > period)
				period = tc_period;
		}
	}
	if (period != params->tc_period)
		params->tc_period = period;
}

/* Allocate and initialize a handle to QoS scheduler.
 * Only called by master thread.
 */
int qos_sched_start(struct ifnet *ifp, uint64_t speed)
{
	struct sched_info *qinfo = ifp->if_qos;
	uint32_t bps;
	uint16_t max_pkt_len;

	/* NB if_mtu_adjusted allows for any QinQ vlan headers
	 * VLAN_HDR_LEN also includes the mac header.
	 * Only account for frame_overhead if it's +ve.
	 * -ve means we're accounting for ethernet header stripping
	 * off box.
	 */
	max_pkt_len = ifp->if_mtu_adjusted + VLAN_HDR_LEN;
	if (qinfo->port_params.frame_overhead > 0)
		max_pkt_len += qinfo->port_params.frame_overhead;

	if (!qinfo->enabled) {
		/* race, link came up while qos being configured */
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "Qos start called but not enabled\n");
		return -1;
	}

	bps = (speed * 1000 * 1000) / 8;	/* bytes/sec */
	DP_DEBUG(QOS, INFO, DATAPLANE,
		 "Qos start %s rate = %"PRIu32" bytes/sec\n",
		 ifp->if_name, bps);

	qinfo->port_params.mtu = ifp->if_mtu_adjusted;
	qinfo->port_params.rate = bps;
	qinfo->port_rate.rate.bandwidth = bps;

	if (QOS_START(qinfo)(ifp, qinfo, bps, max_pkt_len)) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"QoS config port failed\n");
		return -1;
	}

	return 0;
}

/* Cleanup scheduler when link goes down
 * Use RCU to set the pointer because destroyed by master thread
 * but referenced by Tx thread
 */
void qos_sched_stop(struct ifnet *ifp)
{
	struct sched_info *qinfo = ifp->if_qos;

	if (qinfo == NULL)
		return; /* qos not enabled */

	DP_DEBUG(QOS, INFO, DATAPLANE, "Qos stopped on %s\n", ifp->if_name);

	QOS_STOP(qinfo)(ifp, qinfo);
}

/* Operational mode display functions */
static void qos_show_subport(json_writer_t *wr,
			     struct sched_info *qinfo,
			     uint32_t subport)
{
	unsigned int i;
	struct subport_info *sinfo = qinfo->subport + subport;
	struct rte_sched_subport_stats64 *queue_stats = &sinfo->queue_stats;
	struct rte_sched_subport_stats64 *clear_stats = &sinfo->clear_stats;

	if (QOS_SUBPORT_RD_STATS(qinfo)(qinfo, subport, queue_stats) < 0)
		return;

	/* Show per traffic class stats */
	jsonw_name(wr, "tc");
	jsonw_start_array(wr);
	rte_spinlock_lock(&qinfo->stats_lock);
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		uint64_t packets;
		uint64_t bytes;
		uint64_t dropped;
		uint64_t random_drop;

		/*
		 * Subtract the non-zeroing counters from the counter values
		 * at the last time the counters were cleared.
		 */
		packets = queue_stats->n_pkts_tc[i] - clear_stats->n_pkts_tc[i];
		bytes = queue_stats->n_bytes_tc[i] - clear_stats->n_bytes_tc[i];
		dropped = queue_stats->n_pkts_tc_dropped[i] -
			clear_stats->n_pkts_tc_dropped[i];
		random_drop = queue_stats->n_pkts_red_dropped[i] -
			clear_stats->n_pkts_red_dropped[i];

		jsonw_start_object(wr);
		jsonw_uint_field(wr, "packets", packets);
		jsonw_uint_field(wr, "bytes", bytes);
		jsonw_uint_field(wr, "dropped", dropped);
		jsonw_uint_field(wr, "random_drop", random_drop);
		jsonw_end_object(wr);
	}
	rte_spinlock_unlock(&qinfo->stats_lock);
	jsonw_end_array(wr);

	if (sinfo->mark_map)
		jsonw_string_field(wr, "mark_map",
				   sinfo->mark_map->map_name);
}

static void qos_show_pipe_config(json_writer_t *wr,
				 const struct sched_info *qinfo,
				 unsigned int subport, unsigned int pipe)
{
	const struct subport_info *sinfo = &qinfo->subport[subport];
	struct rte_sched_pipe_params *p =
	    qinfo->port_params.pipe_profiles + sinfo->profile_map[pipe];
	unsigned int i;

	jsonw_name(wr, "params");
	jsonw_start_object(wr);

	jsonw_name(wr, "tb_rate");
	jsonw_uint(wr, p->tb_rate);

	jsonw_name(wr, "tb_size");
	jsonw_uint(wr, p->tb_size);

	jsonw_name(wr, "tc_rates");
	jsonw_start_array(wr);
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		jsonw_uint(wr, p->tc_rate[i]);

	jsonw_end_array(wr);

	jsonw_name(wr, "tc_period");
	jsonw_uint(wr, p->tc_period);

	jsonw_name(wr, "wrr_weights");
	jsonw_start_array(wr);
	for (i = 0; i < RTE_SCHED_QUEUES_PER_PIPE; i++)
		jsonw_uint(wr, p->wrr_weights[i]);

	jsonw_end_array(wr);

	jsonw_end_object(wr);
}

static void qos_show_map(json_writer_t *wr, const struct sched_info *qinfo,
			 unsigned int subport, unsigned int pipe,
			 bool optimised_json)
{
	const struct subport_info *sinfo = &qinfo->subport[subport];
	uint8_t profile = sinfo->profile_map[pipe];
	const struct queue_map *qmap = &qinfo->queue_map[profile];
	unsigned int i;

	/*
	 * If we are optimising the JSON, only return either the DSCP or
	 * PCP map.  If we aren't optimising, return both.
	 * We only ever use the PCP map if it has been explicitly enabled.
	 * See qos_npf_classify.
	 */
	if (!qmap->pcp_enabled || !optimised_json) {
		jsonw_name(wr, "dscp2q");
		jsonw_start_array(wr);
		for (i = 0; i < MAX_DSCP; i++)
			jsonw_uint(wr, qmap->dscp2q[i] & RTE_SCHED_TC_WRR_MASK);

		jsonw_end_array(wr);
	}
	if (qmap->pcp_enabled || !optimised_json) {
		jsonw_name(wr, "pcp2q");
		jsonw_start_array(wr);
		for (i = 0; i < MAX_PCP; i++)
			jsonw_uint(wr, qmap->pcp2q[i]);
		jsonw_end_array(wr);
	}
}

uint32_t qos_sched_calc_qindex(struct sched_info *qinfo, unsigned int subport,
			       unsigned int pipe, unsigned int tc,
			       unsigned int q)
{
	uint32_t qid;

	qid = subport * qinfo->port_params.n_pipes_per_subport +
		pipe;
	qid = qid * RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE + tc;
	qid = qid * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS + q;

	return qid;
}

static void qos_do_random_dscp_stats(uint64_t *random_dscp_drop,
				     struct queue_stats *queue_stats)
{
	uint32_t i;

	for (i = 0; i < RTE_NUM_DSCP_MAPS; i++)
		random_dscp_drop[i] = queue_stats->n_pkts_red_dscp_dropped[i] -
			queue_stats->n_pkts_red_dscp_dropped_lc[i];
}

static void qos_show_stats(json_writer_t *wr, struct sched_info *qinfo,
			   unsigned int subport, unsigned int pipe,
			   bool optimised_json)
{
	const struct subport_info *sinfo = &qinfo->subport[subport];
	uint8_t profile = sinfo->profile_map[pipe];
	const struct queue_map *qmap = &qinfo->queue_map[profile];
	uint32_t tc, q;
	bool queue_used;

	jsonw_name(wr, "tc");
	jsonw_start_array(wr);
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; ++tc) {

		jsonw_start_array(wr);
		for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; ++q) {
			uint32_t qid;
			uint64_t qlen;
			bool qlen_in_pkts;
			struct queue_stats *queue_stats;

			/*
			 * If the returned JSON is being optimised, only return
			 * counters for queues that are actually mapped onto
			 * DSCP or PCP values.  With the default DSCP/PCP
			 * mappings only queue 0 of each TC is used.
			 */
			queue_used = qmap->conf_ids[QMAP(tc, q)] &
				CONF_ID_Q_IN_USE;
			if (optimised_json && !queue_used)
				continue;

			qid = qos_sched_calc_qindex(qinfo, subport, pipe, tc,
						    q);
			queue_stats = qinfo->queue_stats + qid;

			if (QOS_QUEUE_RD_STATS(qinfo)(qinfo, subport, pipe,
						      tc, q, queue_stats,
						      &qlen,
						      &qlen_in_pkts) != 0)
				continue;

			jsonw_start_object(wr);
			if (queue_used && !(qmap->conf_ids[QMAP(tc, q)] &
					    CONF_ID_Q_DEFAULT)) {
				/*
				 * Don't display the default pipe-queue-ids.
				 */
				jsonw_uint_field(wr, "cfgid",
						 qmap->conf_ids[QMAP(tc, q)]
						 & ~CONF_ID_Q_IN_USE);
			}
			if (optimised_json) {
				/*
				 * The optimised JSON must identify which
				 * TC and queue the counters belong to.
				 */
				jsonw_uint_field(wr, "traffic-class", tc);
				jsonw_uint_field(wr, "queue", q);
			}

			uint64_t packets;
			uint64_t bytes;
			uint64_t dropped;
			uint64_t random_drop;
			uint64_t random_dscp_drop[RTE_NUM_DSCP_MAPS];

			/*
			 * Subtract the clear_stats from the queue_stats
			 * to calculate the values since that counters were
			 * last cleared.
			 */
			rte_spinlock_lock(&qinfo->stats_lock);
			packets = queue_stats->n_pkts - queue_stats->n_pkts_lc;
			bytes = queue_stats->n_bytes - queue_stats->n_bytes_lc;
			dropped = queue_stats->n_pkts_dropped -
				queue_stats->n_pkts_dropped_lc;
			random_drop = queue_stats->n_pkts_red_dropped -
				queue_stats->n_pkts_red_dropped_lc;
			qos_do_random_dscp_stats(random_dscp_drop,
						 queue_stats);

			rte_spinlock_unlock(&qinfo->stats_lock);

			jsonw_uint_field(wr, "packets", packets);
			jsonw_uint_field(wr, "bytes", bytes);
			jsonw_uint_field(wr, "dropped", dropped);
			jsonw_uint_field(wr, "random_drop", random_drop);

			QOS_DSCP_RESGRP_JSON(qinfo)(qinfo, subport, pipe, tc, q,
						    random_dscp_drop, wr);

			if (qlen_in_pkts)
				jsonw_uint_field(wr, "qlen", (uint16_t)qlen);
			else
				jsonw_uint_field(wr, "qlen-bytes", qlen);
			jsonw_bool_field(wr, "prio_local",
					 qmap->local_priority &&
					 (QMAP(tc, q) ==
					  qmap->local_priority_queue));
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
	}
	jsonw_end_array(wr);
}

static void qos_show_pipes(json_writer_t *wr,
			   struct sched_info *qinfo, unsigned int subport,
			   bool optimised_json)
{
	uint32_t pipe;

	jsonw_name(wr, "pipes");
	jsonw_start_array(wr);
	for (pipe = 0; pipe < qinfo->n_pipes; ++pipe) {
		jsonw_start_object(wr);
		qos_show_pipe_config(wr, qinfo, subport, pipe);
		qos_show_map(wr, qinfo, subport, pipe, optimised_json);
		qos_show_stats(wr, qinfo, subport, pipe, optimised_json);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
}

static void show_ifp_qos_act_grps(struct ifnet *ifp, void *arg)
{
	struct sched_info *qinfo = ifp->if_qos;
	struct qos_show_context *context = arg;
	json_writer_t *wr = context->wr;
	struct subport_info *sport;
	unsigned int i;

	if (qinfo == NULL)
		return;

	jsonw_name(wr, ifp->if_name);
	for (i = 0; i < qinfo->port_params.n_subports_per_port; i++) {
		struct npf_act_grp *act_grp;

		sport = &qinfo->subport[i];
		act_grp = sport->act_grp_list;
		if (!act_grp)
			continue;

		npf_action_group_show(wr, act_grp, sport->attach_name);
	}
}

static void qos_show_ifp_platform(json_writer_t *wr,
				  const struct sched_info *qinfo)
{
	uint i, j;

	jsonw_name(wr, "subports");
	jsonw_start_array(wr);
	for (i = 0; i < qinfo->n_subports; i++) {
		jsonw_start_object(wr);
		if (QOS_CONFIGURED(qinfo)) {
			qos_hw_dump_subport(wr, qinfo, i);

			jsonw_name(wr, "pipes");
			jsonw_start_array(wr);
			for (j = 0; j < qinfo->n_pipes; j++) {
				jsonw_start_object(wr);
				qos_hw_dump_map(wr, qinfo, i, j);
				jsonw_end_object(wr);
			}
			jsonw_end_array(wr);  /* pipes */
		}
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);  /* subports */
}

static void show_ifp_qos(struct ifnet *ifp, void *arg)
{
	struct qos_show_context *context = arg;
	json_writer_t *wr = context->wr;
	struct sched_info *qinfo = ifp->if_qos;
	unsigned int i;

	if (qinfo == NULL)
		return;

	jsonw_name(wr, ifp->if_name);
	jsonw_start_object(wr);

	/* Put "shaper" tag on to allow for future alternates */
	jsonw_name(wr, "shaper");
	jsonw_start_object(wr);

	/* Show VLAN to subport mapping - skip default slots */
	jsonw_name(wr, "vlans");
	jsonw_start_array(wr);
	for (i = 1; i < 4096; i++) {
		unsigned int s = qinfo->vlan_map[i];

		if (s != 0) {
			jsonw_start_object(wr);
			jsonw_uint_field(wr, "tag", i);
			jsonw_uint_field(wr, "subport", s);
			jsonw_end_object(wr);
		}

	}
	jsonw_end_array(wr);

	if (context->is_platform) {
		qos_show_ifp_platform(wr, qinfo);
		jsonw_end_object(wr); /* shaper */
		jsonw_end_object(wr); /* ifname */
		return;
	}

	jsonw_name(wr, "subports");
	jsonw_start_array(wr);
	for (i = 0; i < qinfo->n_subports; ++i) {
		jsonw_start_object(wr);

		if (QOS_CONFIGURED(qinfo)) {
			qos_show_subport(wr, qinfo, i);
			qos_show_pipes(wr, qinfo, i, context->optimised_json);
		}

		jsonw_name(wr, "rules");
		jsonw_start_object(wr);

		const struct npf_config *npf_config =
			rcu_dereference(qinfo->subport[i].npf_config);
		const npf_ruleset_t *rlset = npf_get_ruleset(npf_config,
							     NPF_RS_QOS);

		if (rlset)
			npf_json_ruleset(rlset, wr);
		jsonw_end_object(wr);

		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);  /* subports */
	jsonw_end_object(wr); /* shaper */
	jsonw_end_object(wr); /* ifname */
}

static CDS_LIST_HEAD(qos_mark_map_list_head);

static struct qos_mark_map *qos_mark_map_find(char *map_name)
{
	struct qos_mark_map *mark_map;

	cds_list_for_each_entry(mark_map, &qos_mark_map_list_head, list) {
		if (strcmp(mark_map->map_name, map_name) == 0)
			return mark_map;
	}
	return NULL;
}

static int qos_mark_map_store(char *map_name, uint64_t dscp_set,
			      uint8_t pcp_value)
{
	struct qos_mark_map *mark_map;
	uint8_t dscp;

	mark_map = qos_mark_map_find(map_name);
	if (!mark_map) {
		/* Allocate enough memory for the mark_map and its name */
		mark_map = calloc(1, sizeof(*mark_map) + strlen(map_name) + 1);
		if (!mark_map) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "no memory for mark-map\n");
			return -ENOMEM;
		}
		strcpy(mark_map->map_name, map_name);
		cds_list_add_tail_rcu(&mark_map->list,
				      &qos_mark_map_list_head);
	}
	for (dscp = 0; dscp < MAX_DSCP; dscp++) {
		if (dscp_set & (1ul << dscp))
			mark_map->pcp_value[dscp] = pcp_value;
	}
	return 0;
}

static void qos_mark_map_delete_rcu(struct rcu_head *head)
{
	struct qos_mark_map *mark_map =
		caa_container_of(head, struct qos_mark_map, obj_rcu);

	free(mark_map);
}

static int qos_mark_map_delete(char *map_name)
{
	struct qos_mark_map *mark_map;

	mark_map = qos_mark_map_find(map_name);
	if (!mark_map) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "failed to find mark-map %s during delete\n",
			 map_name);
		return -ENOENT;
	}
	cds_list_del_rcu(&mark_map->list);
	call_rcu(&mark_map->obj_rcu, qos_mark_map_delete_rcu);
	return 0;
}

static void show_qos_mark_map(struct qos_show_context *context)
{
	json_writer_t *wr = context->wr;
	struct qos_mark_map *mark_map;
	uint32_t i;

	jsonw_name(wr, "mark-maps");
	jsonw_start_array(wr);
	cds_list_for_each_entry(mark_map, &qos_mark_map_list_head, list) {
		jsonw_start_object(wr);
		jsonw_string_field(wr, "map-name", mark_map->map_name);
		jsonw_name(wr, "pcp-values");
		jsonw_start_array(wr);
		for (i = 0; i < MAX_DSCP; i++)
			jsonw_uint(wr, mark_map->pcp_value[i]);

		jsonw_end_array(wr);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
}

/* Handle: "qos show [interface]"
 * Output is in JSON
 */
static int cmd_qos_show(FILE *f, int argc, char **argv)
{
	struct qos_show_context context;

	if (argc >= 2 && !strcmp(argv[1], "platform")) {
		context.is_platform = true;
		argc--;
		argv++;
	} else
		context.is_platform = false;

	context.wr = jsonw_new(f);
	if (!context.wr)
		return -1;

	jsonw_pretty(context.wr, true);

	context.optimised_json = false;
	if (argc == 1)
		ifnet_walk(show_ifp_qos, &context);
	else {
		if (!strcmp(argv[1], "action-groups")) {
			ifnet_walk(show_ifp_qos_act_grps, &context);
		} else if (strcmp(argv[1], "mark-maps") == 0) {
			show_qos_mark_map(&context);
		} else {
			while (--argc > 0) {
				struct ifnet *ifp = ifnet_byifname(*++argv);

				if (!ifp) {
					fprintf(f, "Unknown interface: %s\n",
						*argv);
					jsonw_destroy(&context.wr);
					return -1;
				}
				show_ifp_qos(ifp, &context);
			}
		}
	}
	jsonw_destroy(&context.wr);

	return 0;
}

/* Handle: "qos optimised-show"
 * Output is in JSON
 */
static int cmd_qos_optimised_show(FILE *f, int argc, char **argv)
{
	struct qos_show_context context;

	if (argc > 2) {
		fprintf(f, "Too many arguments: %s\n", argv[1]);
		return -1;
	}

	context.wr = jsonw_new(f);
	if (!context.wr)
		return -1;

	context.optimised_json = true;
	context.is_platform = false;

	if (argc == 1)
		ifnet_walk(show_ifp_qos, &context);
	else {
		struct ifnet *ifp = ifnet_byifname(*++argv);

		if (!ifp) {
			fprintf(f, "Unknown interface: %s\n",
				*argv);
			jsonw_destroy(&context.wr);
			return -1;
		}
		show_ifp_qos(ifp, &context);
	}

	jsonw_destroy(&context.wr);
	return 0;
}

static void qos_clear_pipe_stats(struct sched_info *qinfo, uint32_t subport,
				 uint32_t pipe)
{
	uint32_t tc;
	uint32_t q;

	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; ++tc) {
		for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++)
			QOS_QUEUE_CLR_STATS(qinfo)(qinfo, subport, pipe, tc, q);
	}
}

static void qos_clear_subport_stats(struct sched_info *qinfo, uint32_t subport)
{
	struct subport_info *sinfo = qinfo->subport + subport;
	const struct npf_config *npf_config =
		rcu_dereference(sinfo->npf_config);
	const npf_ruleset_t *rlset = npf_get_ruleset(npf_config, NPF_RS_QOS);
	uint32_t pipe;

	if (QOS_SUBPORT_CLR_STATS(qinfo)(qinfo, subport) < 0) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "Failed to clear subport stats for subport: %u\n",
			 subport);
		return;
	}

	if (rlset)
		npf_clear_stats(rlset, NPF_RULE_CLASS_COUNT, NULL, 0);

	for (pipe = 0; pipe < qinfo->n_pipes; pipe++)
		qos_clear_pipe_stats(qinfo, subport, pipe);
}

static void clear_ifp_qos_stats(struct ifnet *ifp, void *arg)
{
	struct sched_info *qinfo = ifp->if_qos;
	uint32_t subport;
	char *viftag = arg;

	if (!qinfo || !QOS_CONFIGURED(qinfo))
		return;

	if (!viftag) {
		/*
		 * No viftag, clear all subports.
		 */
		for (subport = 0; subport < qinfo->n_subports; ++subport)
			qos_clear_subport_stats(qinfo, subport);

	} else {
		/*
		 * Clear the subport selected by the viftag.
		 */
		uint32_t vid;

		vid = strtoul(viftag, NULL, 10);
		subport = qinfo->vlan_map[vid];
		qos_clear_subport_stats(qinfo, subport);
	}
}

/* Handle: "qos clear"
 * Output is in JSON
 */
static int cmd_qos_clear(FILE *f, int argc, char **argv)
{
	if (argc == 1) {
		/*
		 * No interface name, clear all interfaces.
		 */
		ifnet_walk(clear_ifp_qos_stats, NULL);
	} else if (argc == 2) {
		/*
		 * Clear the selected interface.
		 */
		char if_name[IFNAMSIZ];
		char *dot;
		char *viftag;
		char vif_zero[] = "0";
		struct ifnet *ifp;

		/* Initial interface name check */
		ifp = ifnet_byifname(*++argv);
		if (!ifp) {
			fprintf(f, "Unknown interface: %s\n", *argv);
			return -1;
		}

		snprintf(if_name, IFNAMSIZ, "%s", *argv);
		dot = strchr(if_name, '.');
		if (dot) {
			/*
			 * We are dealing with a VIF.  Get a pointer to the VIF
			 * number, and truncate the interface name to the trunk.
			 */
			viftag = dot + 1;
			*dot = '\0';
		} else {
			/*
			 * We are dealing with a trunk interface.
			 * Set the VIF number to zero.
			 */
			viftag = vif_zero;
		}

		/* Get the trunk interface */
		ifp = ifnet_byifname(if_name);
		if (!ifp) {
			fprintf(f, "Unknown interface: %s\n", *argv);
			return -1;
		}
		clear_ifp_qos_stats(ifp, viftag);
	} else {
		fprintf(f, "Too many arguments: %s\n", argv[1]);
		return -1;
	}
	return 0;
}

static void show_ifp_qos_hw(struct ifnet *ifp, void *arg)
{
	if (ifp->if_qos == NULL || ifp->if_qos->dev_id != QOS_HW_ID)
		return;

	(void)qos_hw_show_port(ifp, arg);
}

/* Handle: "qos hw"
 * Output is in JSON
 */
static int cmd_qos_hw(FILE *f, int argc, char **argv)
{
	struct qos_show_context context;
	int ret = 0;

	context.wr = jsonw_new(f);
	if (!context.wr)
		return -1;

	jsonw_pretty(context.wr, true);
	context.optimised_json = false;

	if (argc == 1) {
		ifnet_walk(show_ifp_qos_hw, &context);
	} else if (argc == 2) {
		struct ifnet *ifp;

		/* Initial interface name check */
		ifp = ifnet_byifname(*++argv);
		if (!ifp) {
			fprintf(f, "Unknown interface: %s\n", *argv);
			jsonw_destroy(&context.wr);
			return -1;
		}
		if (!ifp->if_qos || ifp->if_qos->dev_id != QOS_HW_ID) {
			jsonw_destroy(&context.wr);
			return 0;
		}
		ret = qos_hw_show_port(ifp, &context);
	}
	jsonw_destroy(&context.wr);
	return ret;
}

static int
qos_show_obj_db(void *arg, struct qos_obj_db_obj *db_obj,
		enum qos_obj_db_level level, uint32_t *ids)
{
	struct qos_show_context *context = (struct qos_show_context *)arg;
	json_writer_t *wr = context->wr;
	char ids_str[QOS_OBJ_DB_MAX_ID_LEN];
	const char *out_str = qos_obj_db_get_ids_string(level, ids,
							QOS_OBJ_DB_MAX_ID_LEN,
							ids_str);
	enum qos_obj_sw_state sw_state;
	enum qos_obj_hw_type hw_type;
	fal_object_t object_id;
	int32_t hw_status;

	jsonw_name(wr, out_str);
	jsonw_start_object(wr);
	jsonw_name(wr, "sw-object");
	jsonw_start_object(wr);
	qos_obj_db_sw_get(db_obj, &sw_state);
	out_str = qos_obj_db_get_sw_state_str(sw_state);
	jsonw_string_field(wr, "sw-state", out_str);
	jsonw_name(wr, "hw-objects");
	jsonw_start_array(wr);
	for (hw_type = QOS_OBJ_HW_TYPE_MIN; hw_type <= QOS_OBJ_HW_TYPE_MAX;
	     hw_type++) {
		qos_obj_db_hw_get(db_obj, hw_type, &hw_status, &object_id);
		if (hw_status != 0 || object_id != FAL_QOS_NULL_OBJECT_ID) {
			jsonw_start_object(wr);
			out_str = qos_obj_db_get_hw_type_str(hw_type);
			jsonw_string_field(wr, "hw-type", out_str);
			jsonw_string_field(wr, "hw-status",
					   strerror(-hw_status));
			jsonw_uint_field(wr, "object-id", object_id);
			jsonw_end_object(wr);
		}
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
	jsonw_end_object(wr);
	return 0;
}

/* Handle: "qos obj-db"
 * Output is in JSON
 */
static int cmd_qos_obj_db(FILE *f)
{
	struct qos_show_context context;
	int ret = 0;

	context.wr = jsonw_new(f);
	if (!context.wr)
		return -1;

	jsonw_pretty(context.wr, true);
	context.optimised_json = false;

	ret = qos_obj_db_walk(qos_show_obj_db, &context);

	jsonw_destroy(&context.wr);
	return ret;
}

static int cmd_qos_port(struct ifnet *ifp, int argc, char **argv)
{
	unsigned int subports = 0, pipes = 0, profiles = 1;
	int32_t overhead = RTE_SCHED_FRAME_OVERHEAD_DEFAULT;
	int ret;

	/*
	 * Expected command format:
	 *
	 * "port <a> subports <b> pipes <c> profiles <d> [overhead <e>]"
	 *
	 * <a> - port-id
	 * <b> - number of configured subports
	 * <c> - number of configured pipes
	 * <d> - number of configured profiles
	 * <e> - frame-overhead
	 */
	--argc, ++argv;	/* skip "port" */
	while (argc > 0) {
		unsigned int value;

		if (argc < 2) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "missing value qos port ... %s\n", argv[0]);
			return -EINVAL;
		}

		if (strcmp(argv[0], "overhead") == 0) {
			int inp_ov;

			if (get_signed(argv[1], &inp_ov) < 0) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "number expected after %s\n", argv[0]);
				return -EINVAL;
			}
			overhead = inp_ov;
		} else {
			if (get_unsigned(argv[1], &value) < 0) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "number expected after %s\n", argv[0]);
				return -EINVAL;
			}

			if (strcmp(argv[0], "subports") == 0)
				subports = value;
			else if (strcmp(argv[0], "pipes") == 0)
				pipes = value;
			else if (strcmp(argv[0], "profiles") == 0)
				profiles = value;
			else {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "unknown port parameter: '%s'\n",
					 argv[0]);
				return -EINVAL;
			}
		}
		argc -= 2, argv += 2;
	}

	if (subports == 0 || subports > ETHER_MAX_VLAN_ID) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "bad subports value: %u\n", subports);
		return -EINVAL;
	}

	/*
	 * ENODEV means there's no hardware support for this device
	 */
	ret = qos_hw_port(ifp, subports, pipes, profiles, overhead);
	if (ret == -ENODEV)
		return qos_dpdk_port(ifp, subports, pipes, profiles, overhead);


	return ret;
}

static int cmd_qos_subport_queue(struct subport_info *sinfo, unsigned int qid,
				 int argc, char **argv)
{
	/*
	 * Called from cmd_qos_subport after "queue <a>" has been parsed.
	 *
	 * Expected command formats:
	 *
	 * "queue <a> rate <b> size <c>"
	 * "queue <a> percent <d> size <c>"
	 *
	 * <a> - traffic-class-id (0..3)
	 * <b> - traffic-class shaper bandwidth rate
	 * <c> - traffic-class shaper max-burst size (not-used)
	 * <d> - traffic class shaper percentage bandwidth rate
	 */

	/* parse qos subport S queue Q rate R */
	bool rate_given = false;
	bool rate_is_percent = false;

	if (argc < 4) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "queue missing tc rate\n");
		return -EINVAL;
	}

	if (strcmp(argv[2], "rate") == 0) {
		rate_given = true;
	} else if (strcmp(argv[2], "percent") == 0) {
		rate_given = true;
		rate_is_percent = true;
	}

	if (rate_given) {
		unsigned int rate;
		struct rte_sched_subport_params *params = &sinfo->params;

		if (get_unsigned(argv[3], &rate) < 0) {
			RTE_LOG(ERR, QOS, "missing rate for queue\n");
			return -EINVAL;
		}

		if (rate_is_percent && rate > 100) {
			RTE_LOG(ERR, QOS,
				"rate percentage %u out of range\n", rate);
			return -EINVAL;
		}

		if (qid >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) {
			RTE_LOG(ERR, QOS, "traffic-class %u out of range\n",
				qid);
			return -EINVAL;
		}

		params->tc_rate[qid] =
			qos_rate_set(
			    &sinfo->sp_tc_rates.tc_rate[qid],
			    rate, rate_is_percent,
			    params->tb_rate);
	} else {
		RTE_LOG(ERR, QOS,
			"unknown subport queue parameter: '%s'\n", argv[2]);
		return -EINVAL;
	}

	/* don't continue parsing line (ignore size) */
	return 0;
}

/* Per VLAN QoS characteristics */
static int cmd_qos_subport(struct ifnet *ifp, int argc, char **argv)
{
	struct sched_info *qinfo = ifp->if_qos;
	unsigned int subport;

	if (!qinfo) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "port not initialized\n");
		return -ENOENT;
	}

	/*
	 * Expected command format:
	 *
	 * "subport <a> rate <b> size <c> [period <d>]"
	 * "subport <a> percent <i> size <c> [period <d>]"
	 * "subport <a> queue <e> rate <f> size <g>"
	 * "subport <a> queue <e> percent <j> size <g>"
	 * "subport <a> mark-map <h>
	 *
	 * <a> - subport-id
	 * <b> - subport shaper bandwidth rate
	 * <c> - subport shaper max-burst size
	 * <d> - subport token-bucket period
	 * <e> - traffic-class-id (0..3)
	 * <f> - traffic-class shaper bandwidth rate
	 * <g> - traffic-class shaper max-burst size (not-used)
	 * <h> - mark-map name
	 * <i> - subport shaper percentage bandwidth rate
	 * <j> - traffic class shaper percentage bandwidth rate
	 */
	--argc, ++argv; /* skip "subport" */
	if (argc < 2) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "subport missing id\n");
		return -EINVAL;
	}

	if (get_unsigned(argv[0], &subport) < 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "subport id not a number: %s\n",
			 argv[0]);
		return -EINVAL;
	}

	if (subport >= qinfo->port_params.n_subports_per_port) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "subport %u out of range %u\n",
			 subport, qinfo->port_params.n_subports_per_port);
		return -EINVAL;
	}
	--argc, ++argv;

	struct subport_info *sinfo = qinfo->subport + subport;
	struct rte_sched_subport_params *params = &sinfo->params;

	while (argc > 0) {
		unsigned int value;

		if (argc < 2) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "missing value qos subport ... %s\n", argv[0]);
			return -EINVAL;
		}

		if (strcmp(argv[0], "mark-map") == 0) {
			struct qos_mark_map *mark_map;

			mark_map = qos_mark_map_find(argv[1]);
			if (mark_map == NULL) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "failed to find mark-map %s\n",
					 argv[1]);
				return -EINVAL;
			}
			/*
			 * Save the mark-map pointer in the subport
			 */
			sinfo->mark_map = mark_map;
		} else {
			if (get_unsigned(argv[1], &value) < 0) {
				RTE_LOG(ERR, QOS, "number expected after %s\n",
					argv[0]);
				return -EINVAL;
			}

			if (strcmp(argv[0], "rate") == 0) {
				/* bytes/sec */
				params->tb_rate =
				       qos_rate_set(&sinfo->subport_rate,
						    value, false, 0);
			} else if (strcmp(argv[0], "percent") == 0) {
				/* bytes/sec */
				params->tb_rate =
				       qos_rate_set(&sinfo->subport_rate,
						value, true,
						ifp->if_qos->port_params.rate);
			} else if (strcmp(argv[0], "size") == 0) {
				/* credits (bytes) */
				params->tb_size = sinfo->subport_rate.burst =
					value;
			} else if (strcmp(argv[0], "period") == 0) {
				params->tc_period =
				       qos_period_set(&sinfo->subport_rate,
						      value);
			} else if (strcmp(argv[0], "queue") == 0) {
				/*
				 * Parse qos subport S queue Q rate R
				 * Nothing more to parse after queue so can
				 * just return.
				 */
				return cmd_qos_subport_queue(sinfo, value,
							     argc, argv);
			}
		}
		argc -= 2, argv += 2;
	}

	return 0;
}

static int cmd_qos_pipe(struct ifnet *ifp, int argc, char **argv)
{
	struct sched_info *qinfo = ifp->if_qos;
	unsigned int pipe, subport, profile;

	if (!qinfo) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "port not initialized\n");
		return -ENOENT;
	}

	/*
	 * Expected command format:
	 *
	 * "pipe <a> <b> <c>"
	 *
	 * <a> - subport-id
	 * <b> - pipe-id (0..255)
	 * <c> - profile-id
	 */
	--argc, ++argv; /* skip "pipe" */
	if (argc < 3)
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "pipe missing subport pipe profile\n");
	else if (get_unsigned(argv[0], &subport) < 0)
		DP_DEBUG(QOS, ERR, DATAPLANE, "subport id not a number: %s\n",
			 argv[0]);
	else if (get_unsigned(argv[1], &pipe) < 0)
		DP_DEBUG(QOS, ERR, DATAPLANE, "pipe id not a number: %s\n",
			 argv[1]);
	else if (get_unsigned(argv[2], &profile) < 0)
		DP_DEBUG(QOS, ERR, DATAPLANE, "profile id not a number: %s\n",
			 argv[2]);
	else if (subport >= qinfo->n_subports)
		DP_DEBUG(QOS, ERR, DATAPLANE, "subport %u out of range %u\n",
			 subport, qinfo->port_params.n_subports_per_port);
	else if (pipe >= qinfo->n_pipes)
		DP_DEBUG(QOS, ERR, DATAPLANE, "pipe %u out of range %u\n", pipe,
			 qinfo->port_params.n_pipes_per_subport);
	else if (profile >= qinfo->port_params.n_pipe_profiles)
		DP_DEBUG(QOS, ERR, DATAPLANE, "profile %u out of range %u\n",
			 profile, qinfo->port_params.n_pipe_profiles);
	else {
		qinfo->subport[subport].profile_map[pipe]  = profile;
		qinfo->subport[subport].pipe_configured[pipe] = true;
		return 0;
	}
	return -EINVAL;
}

/* Check that the composit queue map (traffic-class and weighted-round-robin)
 * is valid.
 */
static bool valid_qmap(unsigned int q)
{
	uint8_t tc = qmap_to_tc(q);
	uint8_t wrr = qmap_to_wrr(q);
	uint8_t dp = qmap_to_dp(q);

	if (tc >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "traffic class %u out of range\n", tc);
		return false;
	}
	if (wrr >= RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "queue %u out of range\n", wrr);
		return false;
	}
	if (dp > QOS_MAX_DROP_PRECEDENCE) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "drop-precedence %u out of range\n", dp);
		return false;
	}
	return true;
}

static int cmd_qos_profile_queue(struct sched_info *qinfo, unsigned int profile,
				 int value, int argc, char **argv)
{
	/*
	 * Called from cmd_qos_profile after "profile <a> queue <b>" has been
	 * parsed.
	 *
	 * Expected command formats:
	 *
	 * "queue <a> rate <b> size <c>"
	 * "queue <a> percent <k> size <c>"
	 * "queue <d> wrr-weight <e>"
	 * "queue <d> dscp-group <f> <g> <h> <i>"
	 * "queue <d> wred-weight <j>"
	 *
	 * <a> - traffic-class-id (0..3)
	 * <b> - traffic-class shaper bandwidth rate
	 * <c> - traffic-class burst size (not-used)
	 * <d> - qmap (wrr-id << 3 | tc_id)
	 * <e> - pipe-queue's wrr-weight (1..100)
	 * <f> - Name of the DSCP resource group
	 * <g> - wred max threshold (1..8191)
	 * <h> - wred min threshold (1..8190)
	 * <i> - wred mark probability (1..255)
	 * <j> - wred filter weight (1..12)
	 * <k> - traffic-class shaper percentage bandwidth rate
	 */
	struct rte_sched_pipe_params *pipe
		= qinfo->port_params.pipe_profiles + profile;
	struct qos_rate_info *pipe_tc_rates =
			qinfo->profile_tc_rates[profile].tc_rate;
	bool rate_given = false;
	bool rate_is_percent = false;

	if (strcmp(argv[2], "rate") == 0) {
		rate_given = true;
	} else if (strcmp(argv[2], "percent") == 0) {
		rate_given = true;
		rate_is_percent = true;
	}

	if (rate_given) {
		unsigned int rate;
		bool rate_valid = false;

		if (value >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "traffic-class %u out of range\n", value);
			return -EINVAL;
		}

		if (argc >= 4) {
			if (get_unsigned(argv[3], &rate) == 0) {
				if (!rate_is_percent || rate <= 100)
					rate_valid = true;
			}
		}

		if (!rate_valid) {
			const char *err_msg = rate_is_percent ?
				"bad percentage rate for queue" :
				"bad rate for queue";
			DP_DEBUG(QOS, ERR, DATAPLANE, "%s\n", err_msg);
			return -EINVAL;
		}
		pipe->tc_rate[value] = qos_rate_set(&pipe_tc_rates[value],
						rate, rate_is_percent,
						pipe->tb_rate);
	} else if (strcmp(argv[2], "wrr-weight") == 0) {
		unsigned int weight;
		unsigned int qindex;
		unsigned int conf_id;
		struct queue_map *qmap = &qinfo->queue_map[profile];

		qindex = q_from_mask(value);
		if (qindex >= RTE_SCHED_QUEUES_PER_PIPE) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "q mask 0x%x out of range\n", value);
			return -EINVAL;
		}
		if (argc < 4 || get_unsigned(argv[3], &weight) < 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE, "bad weight for queue\n");
			return -EINVAL;
		}
		pipe->wrr_weights[qindex] = weight;

		if (argc < 5 || (get_unsigned(argv[4], &conf_id) < 0) ||
		    conf_id >= RTE_SCHED_QUEUES_PER_PIPE) {
			DP_DEBUG(QOS, ERR, DATAPLANE, "bad q config id\n");
			return -EINVAL;
		}
		qmap->conf_ids[value & RTE_SCHED_TC_WRR_MASK] =
			conf_id | CONF_ID_Q_CONFIG;

		/*
		 * Is this a high priority queue for
		 * local traffic?
		 */
		if (argc == 6 && !strcmp(argv[5], "prio-loc")) {
			if (!qos_sched_profile_dscp_map_set(qinfo, profile, 0,
							    value, true))
				return -EINVAL;
		}
	} else if (strcmp(argv[2], "dscp-group") == 0) {
		unsigned int qmax, qmin, prob;
		unsigned int qindex;
		uint64_t dscp_set;
		int err;
		struct rte_red_pipe_params *qred_info;
		struct profile_wred_info *profile_wred;
		struct queue_wred_info *queue_wred;
		uint8_t map_index;

		if (argc < 7 ||
		    get_unsigned(argv[5], &qmax) < 0 ||
		    get_unsigned(argv[6], &qmin) < 0 ||
		    get_unsigned(argv[7], &prob) < 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Invalid per queue RED input\n");
			return -EINVAL;
		}
		err = npf_dscp_group_getmask(argv[3], &dscp_set);
		if (err) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "dscp mask retrieval failed\n");
			return -EINVAL;
		}
		/*
		 * Store the wred-map information for the DPDK
		 */
		qindex = q_from_mask(value);
		profile_wred = &qinfo->wred_profiles[profile];
		queue_wred = &profile_wred->queue_wred[qindex];
		map_index = queue_wred->num_maps;
		if (!strcmp(argv[4], "packets")) {
			qred_info = rte_red_find_q_params(pipe, qindex);
			if (!qred_info)
				qred_info = rte_red_alloc_q_params(pipe,
								   qindex);
			if (!qred_info)
				return -EINVAL;

			err = rte_red_init_q_params(&qred_info->red_q_params,
					qmax, qmin, prob, dscp_set, argv[3]);
			if (err < 0)
				return -EINVAL;
			queue_wred->unit = WRED_PACKETS;
		} else if (!strcmp(argv[4], "bytes")) {
			/*
			 * Store the wred-map information for the FAL
			 */
			uint8_t name_len;
			char *name_ptr;
			struct red_params *red_ptr;

			if (map_index > QOS_MAX_DROP_PRECEDENCE) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					"profile %u queue %u has too many"
					" wred-maps\n",
					 profile, qindex);
				return -EINVAL;
			}
			name_len = strlen(argv[3]);
			name_ptr = malloc(name_len + 1);
			if (name_ptr == NULL) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					"out of memory\n");
				return -ENOMEM;
			}
			strcpy(name_ptr, argv[3]);
			queue_wred->dscp_grp_names[map_index] = name_ptr;
			red_ptr =
			    &queue_wred->params.map_params_bytes[map_index];
			red_ptr->min_th = qmin;
			red_ptr->max_th = qmax;
			red_ptr->maxp_inv = prob;
			queue_wred->num_maps++;
			queue_wred->unit = WRED_BYTES;
		} else {
			DP_DEBUG(QOS, ERR, DATAPLANE, "Invalid unit field\n");
			return -EINVAL;
		}
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "per Q red prof %d dscp-grp %s %u %u prob %u "
			 "mask %"PRIx64", map %u\n", profile, argv[3], qmin,
			 qmax, prob, dscp_set, map_index);
	} else if (strcmp(argv[2], "wred-weight") == 0) {
		unsigned int wred_weight;
		unsigned int qindex;
		struct rte_red_pipe_params *qred_info;
		struct rte_red_q_params *qred;
		int i;
		struct profile_wred_info *profile_wred;
		struct queue_wred_info *queue_wred;

		if (argc < 3 || get_unsigned(argv[3], &wred_weight) < 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Invalid per queue RED weight\n");
			return -EINVAL;
		}

		qindex = q_from_mask(value);
		profile_wred = &qinfo->wred_profiles[profile];
		queue_wred = &profile_wred->queue_wred[qindex];

		/*
		 * Store the queue's filter weight for the DPDK
		 */
		if (queue_wred->unit == WRED_PACKETS) {
			qred_info = rte_red_find_q_params(pipe, qindex);
			if (!qred_info) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					"Invalid wred-weight command\n");
				return -EINVAL;
			}
			for (i = 0, qred = &qred_info->red_q_params;
			     i < qred->num_maps; i++) {
				qred->qparams[i].wq_log2 = wred_weight;
			}
		} else {

			/*
			 * Store the queue's filter weight for the FAL
			 */
			queue_wred->filter_weight = wred_weight;
		}
	} else {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "unknown profile queue parameter: '%s'\n", argv[2]);
		return -EINVAL;
	}
	return 0;
}

static int cmd_qos_profile(struct ifnet *ifp, int argc, char **argv)
{
	struct sched_info *qinfo = ifp->if_qos;
	unsigned int profile;

	if (!qinfo) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "port not initialized\n");
		return -ENOENT;
	}

	/*
	 * Expected command formats:
	 *
	 * "profile <a> rate <b> size <c> [period <d>]"
	 * "profile <a> percent <r> size <c> [period <d>]"
	 * "profile <a> queue <e> rate <f> size <g>"
	 * "profile <a> [queue <h> wrr-weight <i>]"
	 * "profile <a> [queue <h> dscp-group <m> <n> <o> <p>]"
	 * "profile <a> [queue <h> wred-weight <q>]"
	 * "profile <a> [over-weight <j>]"
	 * "profile <a> [pcp <k> <h>]"
	 * "profile <a> [dscp <l> <h>]"
	 *
	 * <a> - profile-id
	 * <b> - profile shaper bandwidth rate
	 * <c> - profile shaper max-burst size
	 * <d> - profile token-bucket period
	 * <e> - traffic-class-id (0..3)
	 * <f> - traffic-class shaper bandwidth rate
	 * <g> - traffic-class burst size (not-used)
	 * <h> - (dp << 5) | (wrr-queue-id << 3) | traffic-class-id (0x0..0x1F)
	 * <i> - pipe-queue's wrr-weight
	 * <j> - profile overweight value
	 * <k> - PCP value (0..7)
	 * <l> - DSCP value (0..63)
	 * <m> - Name of the DSCP resource group
	 * <n> - wred max threshold (1..8191)
	 * <o> - wred min threshold (1..8190)
	 * <p> - wred mark probability (1..255)
	 * <q> - wred filter weight (1..12)
	 * <r> - profile shaper percentage bandwidth rate
	 */
	--argc, ++argv; /* skip "profile" */
	if (argc < 2) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "pipe missing profile\n");
		return -EINVAL;
	}
	if (get_unsigned(argv[0], &profile) < 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "profile id not a number: %s\n",
			 argv[0]);
		return -EINVAL;
	}
	if (profile >= qinfo->port_params.n_pipe_profiles) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "profile %u out of range %u\n",
			 profile, qinfo->port_params.n_pipe_profiles);
		return -EINVAL;
	}
	--argc, ++argv; /* skip profile id */

	struct rte_sched_pipe_params *pipe
		= qinfo->port_params.pipe_profiles + profile;

	while (argc > 0) {
		unsigned int value;
		bool rate_given = false;
		bool rate_is_percent = false;

		if (argc < 2) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "missing value qos profile ... %s\n", argv[0]);
			return -EINVAL;
		}

		if (get_unsigned(argv[1], &value) < 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "number expected after %s\n", argv[0]);
			return -EINVAL;
		}

		if (strcmp(argv[0], "rate") == 0) {
			rate_given = true;
		} else if (strcmp(argv[0], "percent") == 0) {
			rate_given = true;
			rate_is_percent = true;
		}

		if (rate_given) {
			if (rate_is_percent && value > 100) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					"bad percentage rate for queue\n");
				return -EINVAL;
			}
			/* bytes/sec */
			pipe->tb_rate = qos_rate_set(
					    &qinfo->profile_rates[profile],
					    value, rate_is_percent,
					    qinfo->port_params.rate);
		} else if (strcmp(argv[0], "size") == 0) {
			pipe->tb_size = qinfo->profile_rates[profile].burst =
				value; /*credits*/

		} else if (strcmp(argv[0], "period") == 0) {
			pipe->tc_period = qos_period_set(
					    &qinfo->profile_rates[profile],
					    value); /* ms */
#ifdef RTE_SCHED_SUBPORT_TC_OV
		} else if (strcmp(argv[0], "over-weight") == 0) {
			pipe->tc_ov_weight = value;
#endif
		} else if (strcmp(argv[0], "pcp") == 0) {
			unsigned int q;

			if (value >= MAX_PCP) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "pcp queue %u out of range\n", value);
				return -EINVAL;
			}

			if (get_unsigned(argv[2], &q) < 0) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "missing queue for pcp\n");
				return -EINVAL;
			}

			if (!valid_qmap(q))
				return -EINVAL;

			if (!qos_sched_profile_pcp_map_set
			    (qinfo, profile, value, q))
				return -EINVAL;
			break; /* don't continue parsing line */
		} else if (strcmp(argv[0], "dscp") == 0) {
			unsigned int q;

			if (value >= MAX_DSCP) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "dscp queue %u out of range\n", value);
				return -EINVAL;
			}

			if (get_unsigned(argv[2], &q) < 0) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "missing queue for dscp\n");
				return -EINVAL;
			}
			if (!valid_qmap(q))
				return -EINVAL;

			if (!qos_sched_profile_dscp_map_set
			    (qinfo, profile, value, q, false))
				return -1;
			break; /* don't continue parsing line */
		} else if (strcmp(argv[0], "queue") == 0) {
			int status;

			status = cmd_qos_profile_queue(qinfo, profile, value,
						       argc, argv);
			if (!status)
				return status;

			break; /* don't continue parsing line */
		} else {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "unknown pipe parameter: %s\n", argv[0]);
			return -EINVAL;
		}
		argc -= 2, argv += 2;
	}

	return 0;
}

static int cmd_qos_vlan(struct ifnet *ifp, int argc, char **argv)
{
	struct sched_info *qinfo = ifp->if_qos;
	unsigned int tci, subport;

	if (!qinfo) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "port not initialized\n");
		return -ENOENT;
	}

	/*
	 * Expected command formats:
	 *
	 * "vlan <a> <b>"
	 *
	 * <a> - vlan-id
	 * <b> - subport-id
	 */
	--argc, ++argv; /* skip "vlan" */
	if (argc < 2) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "vlan missing tag and subport\n");
		return -EINVAL;
	}

	if (get_unsigned(argv[0], &tci) < 0)
		DP_DEBUG(QOS, ERR, DATAPLANE, "bad vlan id\n");
	else if (get_unsigned(argv[1], &subport) < 0)
		DP_DEBUG(QOS, ERR, DATAPLANE, "bad subport\n");
	else if (tci >= 4096)
		DP_DEBUG(QOS, ERR, DATAPLANE, "vlan out of range\n");
	else if (subport >= qinfo->port_params.n_subports_per_port)
		DP_DEBUG(QOS, ERR, DATAPLANE, "subport out of range\n");
	else {
		qinfo->vlan_map[tci] = subport;
		qinfo->subport[subport].vlan_id = tci;
		return 0;
	}
	return -EINVAL;

}

/* process "qos IF match SUBPORT CLASS proto P from ... to ... */
static int cmd_qos_match(struct ifnet *ifp, int argc, char **argv)
{
	struct sched_info *qinfo = ifp->if_qos;
	unsigned int i, pipe;

	if (!qinfo) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "port not initialized\n");
		return -ENOENT;
	}

	/*
	 * Expected command formats:
	 *
	 * "match <a> <b> <c>"
	 *
	 * <a> - subport-id
	 * <b> - pipe-id (0..255)
	 * <c> - NPF-rule
	 */
	if (argc < 3) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "subport missing subport, pipe ...\n");
		return -EINVAL;
	}

	if (get_unsigned(argv[1], &i) < 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "bad subport\n");
		return -EINVAL;
	}

	if (get_unsigned(argv[2], &pipe) < 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "bad pipe\n");
		return -EINVAL;
	}

	/* Rest is NPF rule */
	char rule[PATH_MAX];

	if (str_unsplit(rule, PATH_MAX, argc - 3, argv + 3) < 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "rule too long\n");
		return -EINVAL;
	}


	struct subport_info *subport = qinfo->subport + i;
	int ret;

	/*
	 * The match_id is used as the rule index so we need to make
	 * them unique for each match within a class otherwise we'll
	 * reuse the same index.  We can't use the pipe index coz we
	 * only have 1 per class but we want to support multiple matches.
	 */

	ret = npf_cfg_auto_attach_rule_add(NPF_RULE_CLASS_QOS,
					   subport->attach_name,
					   ++subport->match_id, rule);
	if (ret != 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "Error adding rule %u to %s.\n",
			 subport->match_id, subport->attach_name);
		return -EINVAL;
	}

	return 0;
}

/* configure RED parameters */
static int cmd_qos_red(struct rte_red_params red_params[][e_RTE_METER_COLORS],
		       unsigned int tc, int argc, char *argv[])
{
	unsigned int value, color;
	struct rte_red_params red;

	/*
	 * Expected command format:
	 *
	 * "red <e> <f> <g> <h> <i>"
	 *
	 * <e> - meter-colour (not-used: green/yellow/red)
	 * <f> - min-threshold
	 * <g> - max-threshold
	 * <h> - mark-probability
	 * <i> - filter-weight
	 */
	if (argc < 6)
		return -1;

	if (get_unsigned(argv[1], &color) < 0)
		return -2;

	if (color >= e_RTE_METER_COLORS)
		return -3;

	if (get_unsigned(argv[2], &value) < 0)
		return -4;
	red.min_th = value;

	if (get_unsigned(argv[3], &value) < 0)
		return -5;
	red.max_th = value;

	if (get_unsigned(argv[4], &value) < 0)
		return -6;
	red.maxp_inv = value;

	if (get_unsigned(argv[5], &value) < 0)
		return -7;
	red.wq_log2 = value;

	red_params[tc][color] = red;
	return 0;
}

/* at port level, allow per traffic class parameters */
static int cmd_qos_params(struct ifnet *ifp, int argc, char **argv)
{
	struct sched_info *qinfo = ifp->if_qos;
	unsigned int subport_id = 0;
	unsigned int tc_id;

	if (!qinfo) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "port not initialized\n");
		return -ENOENT;
	}

	/*
	 * Expected command format:
	 *
	 * "param [subport <b>] <c> [limit <d>] [red <e> <f> <g> <h> <i>]"
	 *
	 * <b> - subport-id
	 * <c> - traffic-class-id (0..3)
	 * <d> - queue-limit
	 * <e> - meter-colour (not-used: green/yellow/red)
	 * <f> - min-threshold
	 * <g> - max-threshold
	 * <h> - mark-probability
	 * <i> - filter-weight
	 */
	--argc, ++argv; /* skip "param" */
	if (argc < 2) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "param missing id\n");
		return -EINVAL;
	}

	if (strcmp(argv[0], "subport") == 0) {
		if (get_unsigned(argv[1], &subport_id) < 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "subport-id not a number: %s\n", argv[1]);
			return -EINVAL;
		}
		if (subport_id > qinfo->n_subports) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "subport-id %u out of range\n", subport_id);
			return -EINVAL;
		}
		argc -= 2, argv += 2; /* skip "subport" and <subport-id> */
	}
	if (argc < 1) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "param missing id\n");
		return -EINVAL;
	}

	if (get_unsigned(argv[0], &tc_id) < 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "tc-id not a number: %s\n",
			 argv[0]);
		return -EINVAL;
	}

	if (tc_id >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "tc-id %u out of range\n", tc_id);
		return -EINVAL;
	}
	--argc, ++argv; /* skip <tc-id> */
	while (argc > 0) {
		struct subport_info *sinfo = &qinfo->subport[subport_id];

		if (strcmp(argv[0], "limit") == 0) {
			unsigned int value;

			if (argc < 3) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "missing queue limit parameter\n");
				return -EINVAL;
			}

			if (get_unsigned(argv[2], &value) < 0) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "number expected after limit units\n");
				return -EINVAL;
			}

			/*
			 * If it's packets we round down the value to 8192
			 * otherwise it's bytes which aren't limited
			 */
			if (strcmp(argv[1], "packets") == 0) {
				if (value > MAX_QSIZE) {
					value = MAX_QSIZE;
					RTE_LOG(INFO, QOS,
					    "Rounding down qsize to %d on %s\n",
					    MAX_QSIZE, ifp->if_name);
				}
			}
			if (subport_id == 0)
				qinfo->port_params.qsize[tc_id] = value;

			sinfo->qsize[tc_id] = value;
			argc--, argv++;	/* Allow for new unit field */
		} else if (strcmp(argv[0], "red") == 0) {
			int rc;

			rc = cmd_qos_red(sinfo->red_params, tc_id,
					 argc, argv);
			if (rc < 0) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "red config error: %d\n", rc);
				return -EINVAL;
			}
			break;
		} else {
			DP_DEBUG(QOS, ERR, DATAPLANE, "unknown parameter: %s\n",
				 argv[0]);
			return -EINVAL;
		}
		argc -= 2, argv += 2;
	}

	return 0;
}

static int cmd_qos_disable(struct ifnet *ifp,
			   int argc __unused, char **argv __unused)
{
	struct sched_info *qinfo = ifp->if_qos;

	if (!qinfo)
		return 0;

	/*
	 * Expected command format:
	 *
	 * "disable"
	 */
	ifp->qos_software_fwd = 0;
	DP_DEBUG(QOS, DEBUG, DATAPLANE,	"QoS disabled on %s\n", ifp->if_name);

	return QOS_DISABLE(qinfo)(ifp, qinfo);
}

static int cmd_qos_enable(struct ifnet *ifp,
			  int argc __unused, char **argv __unused)
{
	struct sched_info *qinfo = ifp->if_qos;

	/*
	 * Expected command format:
	 *
	 * "enable"
	 */
	if (!qinfo) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "Qos not configured\n");
		return -ENOENT;
	}

	if (qinfo->enabled) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "Qos already enabled\n");
		return -EINVAL;
	}

	qinfo->enabled = true;

	if (QOS_ENABLE(qinfo)(ifp, qinfo))
		return -ENODEV;

	DP_DEBUG(QOS, DEBUG, DATAPLANE, "QoS enabled on %s\n", ifp->if_name);
	return 0;
}

static int cmd_qos_mark_map(int argc, char **argv)
{
	char *map_name;
	char *dscp_group_name;
	int err;
	uint32_t pcp_value;
	uint64_t dscp_set;

	/*
	 * Expected command format:
	 *
	 * "mark-map <a> dscp-group <b> pcp <c>"
	 * "mark-map <a> delete"
	 *
	 * <a> - mark-map name
	 * <b> - dscp-group resource group name
	 * <c> - pcp-value (0..7)
	 */

	--argc, ++argv; /* skip "mark-map" */
	if (argc < 1) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE, "mark-map name missing\n");
		return -EINVAL;
	}

	map_name = argv[0];

	--argc, ++argv; /* skip "map-name" */
	if (argc == 1 && strcmp(argv[0], "delete") == 0) {
		/*
		 * We are deleting a mark-map
		 */
		return qos_mark_map_delete(map_name);
	} else if (argc != 4) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "wrong number of mark-map arguments\n");
		return -EINVAL;
	}

	if (strcmp(argv[0], "dscp-group") != 0) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "unknown mark-map keyword %s\n", argv[0]);
		return -EINVAL;
	}
	dscp_group_name = argv[1];
	err = npf_dscp_group_getmask(dscp_group_name, &dscp_set);
	if (err) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "dscp mark retrieval failed\n");
		return -EINVAL;
	}

	if (strcmp(argv[2], "pcp") != 0) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "unknown mark-map keyword %s\n", argv[2]);
			return -EINVAL;
		}
	if (get_unsigned(argv[3], &pcp_value) < 0) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "invalid mark-map pcp value %s\n", argv[3]);
		return -EINVAL;
	}
	if (pcp_value > 7) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "invalid mark-map pcp value %u\n", pcp_value);
		return -EINVAL;
	}
	return qos_mark_map_store(map_name, dscp_set, (uint8_t)pcp_value);
}

/* Echo command to log */
static void debug_cmd(int argc, char **argv)
{
	char buf[BUFSIZ], *cp;
	int i;

	cp = buf;
	for (i = 0; i < argc; i++) {
		sprintf(cp, " %s", argv[i]);
		cp += strlen(argv[i]) + 1;
	}
	*cp = 0;

	DP_DEBUG(QOS, INFO, DATAPLANE, "qos%s\n", buf);
}

/* Process qos related op-mode commands */
int cmd_qos_op(FILE *f, int argc, char **argv)
{
	--argc, ++argv;		/* skip "qos" */
	if (argc < 1) {
		fprintf(f, "usage: missing qos command\n");
		return -1;
	}

	/* Check for op-mode commands first */
	if (strcmp(argv[0], "show") == 0)
		return cmd_qos_show(f, argc, argv);
	else if (strcmp(argv[0], "optimised-show") == 0)
		return cmd_qos_optimised_show(f, argc, argv);
	else if (strcmp(argv[0], "clear") == 0)
		return cmd_qos_clear(f, argc, argv);
	else if (strcmp(argv[0], "hw") == 0)
		return cmd_qos_hw(f, argc, argv);
	else if (strcmp(argv[0], "obj-db") == 0)
		return cmd_qos_obj_db(f);
	else
		fprintf(f, "unknown qos command: %s\n", argv[0]);

	return -1;
}

/* Process qos related config commands */
int cmd_qos_cfg(__unused FILE * f, int argc, char **argv)
{
	unsigned int ifindex;

	--argc, ++argv;		/* skip "qos" */
	if (argc < 1) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "usage: missing qos command\n");
		return -EINVAL;
	}

	debug_cmd(argc, argv);

	/* Config-mode commands start with ifindex */
	if (get_unsigned(argv[0], &ifindex) < 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "usage: qos IFINDEX ...\n");
		return -ENODEV;
	}

	/*
	 * QoS uses an if-index of zero to signal a global object, i.e.
	 * one that isn't tied to one particular interface.
	 */
	if (ifindex == 0) {
		--argc, ++argv; /* skip IFINDEX */
		if (argc < 1) {
			RTE_LOG(ERR, QOS, "missing qos subcommand\n");
			return -EINVAL;
		}

		if (strcmp(argv[0], "mark-map") == 0)
			return cmd_qos_mark_map(argc, argv);

		return -EINVAL;
	}

	struct ifnet *ifp = ifnet_byifindex(ifindex);

	if (!ifp) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "unknown ifindex %u\n", ifindex);
		return -ENODEV;
	}
	if (ifp->if_type != IFT_ETHER) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Qos only possible on physical ports\n");
		return -EINVAL;
	}

	if (ifp->if_port == IF_PORT_ID_INVALID)
		return 0;

	--argc, ++argv;		/* skip IFINDEX */
	if (argc < 1) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "missing qos subcommand\n");
		return -EINVAL;
	}

	if (strcmp(argv[0], "port") == 0)
		return cmd_qos_port(ifp, argc, argv);
	else if (strcmp(argv[0], "param") == 0)
		return cmd_qos_params(ifp, argc, argv);
	else if (strcmp(argv[0], "subport") == 0)
		return cmd_qos_subport(ifp, argc, argv);
	else if (strcmp(argv[0], "pipe") == 0)
		return cmd_qos_pipe(ifp, argc, argv);
	else if (strcmp(argv[0], "profile") == 0)
		return cmd_qos_profile(ifp, argc, argv);
	else if (strcmp(argv[0], "vlan") == 0)
		return cmd_qos_vlan(ifp, argc, argv);
	else if (strcmp(argv[0], "match") == 0)
		return cmd_qos_match(ifp, argc, argv);
	else if (strcmp(argv[0], "disable") == 0)
		return cmd_qos_disable(ifp, argc, argv);
	else if (strcmp(argv[0], "enable") == 0)
		return cmd_qos_enable(ifp, argc, argv);
	else
		DP_DEBUG(QOS, ERR, DATAPLANE, "unknown qos command: %s\n",
			 argv[0]);

	return -EINVAL;
}

static const char *
qos_extract_attachpoint(char const *name, struct ifnet **ifp)
{
	char ifname[IFNAMSIZ];
	int len;

	for (len = 0; len < IFNAMSIZ ; len++) {
		ifname[len] = name[len];
		if (name[len] != '/')
			continue;

		ifname[len] = '\0';
		*ifp = ifnet_byifname(ifname);
		if (!*ifp)
			return NULL;
		return name + len + 1;
	}
	return NULL;
}

/*
 * Search for and return the subport given the attach_point name.
 * The attach point will normally be something like dp0s3/0 so find
 * the ifnet then look for the subport.
 */
struct subport_info *qos_get_subport(const char *name, struct ifnet **ifp)
{
	struct sched_info *qinfo;
	uint32_t index;
	const char *subport_str;

	subport_str = qos_extract_attachpoint(name, ifp);
	if (!(*ifp) || !subport_str)
		return NULL;
	qinfo = (*ifp)->if_qos;
	if (!qinfo)
		return NULL;
	index = atoi(subport_str);
	if (index > qinfo->n_subports)
		return NULL;

	return qinfo->subport + index;
}

struct ifnet *qos_get_vlan_ifp(const char *att_pnt, uint16_t *vlan_id)
{
	struct subport_info *subport;
	struct ifnet *ifp = NULL;
	char vlan_ifp_name[IFNAMSIZ];

	subport = qos_get_subport(att_pnt, &ifp);
	if (!subport)
		return NULL;

	*vlan_id = subport->vlan_id;

	/*
	 * We've always allowed pcp marking on the trunk so we
	 * can't start blocking it now.
	 */
	if (!(*vlan_id))
		return ifp;

	snprintf(&vlan_ifp_name[0], IFNAMSIZ, "%s.%d", ifp->if_name, *vlan_id);
	ifp = ifnet_byifname(vlan_ifp_name);
	return ifp;
}

struct npf_act_grp *qos_ag_get_head(struct subport_info *subport)
{
	return subport->act_grp_list;
}

struct npf_act_grp *qos_ag_set_or_get_head(struct subport_info *subport,
					   struct npf_act_grp *act_grp)
{
	if (!subport->act_grp_list) {
		subport->act_grp_list = act_grp;
		return NULL;
	}
	return subport->act_grp_list;
}

int16_t qos_get_overhead_from_ifnet(struct ifnet *ifp)
{
	struct sched_info *qinfo;

	if (!ifp)
		return 0;
	qinfo = ifp->if_qos;
	if (!qinfo)
		return 0;
	return qinfo->port_params.frame_overhead;
}

/*
 * Given an attach_point name (eg dp0s9/0) get the ifnet and
 * then retrieve the overhead parameters from the DPDK structure
 */
int16_t qos_get_overhead(const char *name)
{
	struct ifnet *ifp = NULL;

	(void)qos_extract_attachpoint(name, &ifp);
	if (!ifp)
		return 0;

	return qos_get_overhead_from_ifnet(ifp);
}

static void
qos_sched_update_subport_stats(struct sched_info *qinfo, unsigned int subport)
{
	struct subport_info *sinfo = qinfo->subport + subport;
	struct rte_sched_subport_stats64 *queue_stats = &sinfo->queue_stats;

	QOS_SUBPORT_RD_STATS(qinfo)(qinfo, subport, queue_stats);
}

static void
qos_sched_update_pipe_stats(struct sched_info *qinfo, unsigned int subport,
			    unsigned int pipe)
{
	uint32_t tc;
	uint32_t q;

	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		for (q = 0; q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q++) {
			uint32_t qid;
			uint64_t qlen;
			bool qlen_in_pkts;
			struct queue_stats *queue_stats;

			qid = qos_sched_calc_qindex(qinfo, subport, pipe, tc,
						    q);
			queue_stats = qinfo->queue_stats + qid;

			QOS_QUEUE_RD_STATS(qinfo)(qinfo, subport, pipe, tc,
						  q, queue_stats, &qlen,
						  &qlen_in_pkts);
		}
	}
}

void qos_sched_update_if_stats(const struct ifnet *ifp)
{
	struct sched_info *qinfo = ifp->if_qos;
	unsigned int subport;
	unsigned int pipe;

	if (qinfo == NULL)
		return;

	for (subport = 0; subport < qinfo->n_subports; subport++) {
		if (QOS_CONFIGURED(qinfo)) {
			qos_sched_update_subport_stats(qinfo, subport);
			for (pipe = 0; pipe < qinfo->n_pipes; pipe++)
				qos_sched_update_pipe_stats(qinfo, subport,
							    pipe);
		}
	}
}

bool qos_sched_subport_get_stats(struct sched_info *qinfo, uint16_t vlan_id,
				 struct rte_sched_subport_stats64 *stats)
{
	unsigned int subport;
	uint32_t tc;
	struct subport_info *sinfo;
	struct rte_sched_subport_stats64 *queue_stats;

	if (!qinfo || vlan_id >= VLAN_N_VID || !stats)
		return false;

	subport = qinfo->vlan_map[vlan_id];
	sinfo = qinfo->subport + subport;
	queue_stats = &sinfo->queue_stats;

	if (QOS_SUBPORT_RD_STATS(qinfo)(qinfo, subport, queue_stats) < 0) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "Failed to read subport stats for subport: %u\n",
			 subport);
		return false;
	}

	rte_spinlock_lock(&qinfo->stats_lock);
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		/*
		 * The caller is only interested in the drop counters.
		 */
		stats->n_bytes_tc_dropped[tc] =
			queue_stats->n_bytes_tc_dropped[tc];
		stats->n_pkts_tc_dropped[tc] =
			queue_stats->n_pkts_tc_dropped[tc];
		stats->n_pkts_red_dropped[tc] =
			queue_stats->n_pkts_red_dropped[tc];
	}
	rte_spinlock_unlock(&qinfo->stats_lock);
	return true;
}

void qos_save_mark_req(const char *att_pnt, enum qos_mark_type type,
		       uint16_t no_qinqs, void **handle)
{
	struct subport_info *subport;
	struct ifnet *ifp = NULL;
	struct mark_reqs *mark_req;

	subport = qos_get_subport(att_pnt, &ifp);
	if (!subport)
		return;

	mark_req = malloc(sizeof(struct mark_reqs));
	if (!mark_req) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Mark inner requested alloc failed\n");
		return;
	}

	mark_req->handle = handle;
	mark_req->type = type;
	mark_req->next = subport->marks;
	mark_req->refs = no_qinqs;
	subport->marks = mark_req;

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
		 "Saving mark to subport %s type %d refs %d\n",
		 subport->attach_name, type, mark_req->refs);
}

void qos_save_mark_v_pol(npf_rule_t *rl, void *po)
{
	enum npf_attach_type attach_type;
	const char *attach_point;
	int ret;
	uint16_t vlan_id;
	struct ifnet *ifp;
	bool active = false;

	ret = npf_rule_get_attach_point(rl, &attach_type,
					&attach_point);
	if (ret || attach_type != NPF_ATTACH_TYPE_QOS) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "Invalid attach type\n");
		return;
	}

	ifp = qos_get_vlan_ifp(attach_point, &vlan_id);
	if (ifp && ifp->qinq_inner) {
		police_enable_inner_marking(po);
		active = true;
	}

	qos_save_mark_req(attach_point, POLICE, active, po);
}

static struct subport_info *
qos_get_subport_from_parent(struct ifnet *ifp, uint16_t vlan_id)
{
	struct sched_info *qinfo = ifp->if_qos;
	uint32_t index;
	struct subport_info *sinfo;

	if (!qinfo || !vlan_id)
		return NULL;

	index = qinfo->vlan_map[vlan_id];
	if (index > qinfo->port_params.n_subports_per_port)
		return NULL;

	sinfo = &qinfo->subport[index];
	if (sinfo->vlan_id != vlan_id)
		return NULL;

	return sinfo;
}

void qos_enable_inner_marking(struct ifnet *ifp, uint16_t vlan_id)
{
	struct subport_info *sinfo;
	struct mark_reqs *marks;

	sinfo = qos_get_subport_from_parent(ifp, vlan_id);
	if (!sinfo)
		return;

	for (marks = sinfo->marks; marks; marks = marks->next) {
		if (marks->refs++)
			continue;
		if (marks->type == MARK)
			mark_enable_inner_marking(marks->handle);
		else
			police_enable_inner_marking(marks->handle);
	}
}

void qos_disable_inner_marking(struct ifnet *ifp, uint16_t vlan_id)
{
	struct subport_info *sinfo;
	struct mark_reqs *marks;

	if (!ifp || !vlan_id)
		return;

	sinfo = qos_get_subport_from_parent(ifp, vlan_id);
	if (!sinfo)
		return;

	for (marks = sinfo->marks; marks; marks = marks->next) {
		/* If there's multiple inner-vlans on same outer vlan */
		if (--marks->refs)
			continue;
		if (marks->type == MARK)
			mark_disable_inner_marking(marks->handle);
		else
			police_disable_inner_marking(marks->handle);
	}
}

static void
qos_if_link_change(struct ifnet *ifp, bool up,
		   uint32_t speed)
{
	if (!ifp->if_qos)
		return;

	if (up)
		qos_sched_start(ifp, speed);
	else
		qos_sched_stop(ifp);
}

static void
qos_if_delete(struct ifnet *ifp)
{
	struct sched_info *qinfo = ifp->if_qos;

	if (!qinfo)
		return;

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
		 "QoS disabled for interface %s delete\n", ifp->if_name);

	QOS_DISABLE(qinfo)(ifp, qinfo);
}

static const struct dp_event_ops qos_events = {
	.if_link_change = qos_if_link_change,
	.if_delete = qos_if_delete,
};

DP_STARTUP_EVENT_REGISTER(qos_events);
