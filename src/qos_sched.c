/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
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
#include "fal.h"
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
#include "pktmbuf_internal.h"
#include "qos.h"
#include "qos_ext_buf_monitor.h"
#include "qos_obj_db.h"
#include "qos_public.h"
#include "urcu.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

static CDS_LIST_HEAD(qos_ingress_maps);
static CDS_LIST_HEAD(qos_egress_maps);

struct qos_qinfo_list {
	SLIST_HEAD(qinfo_head, sched_info) qinfo_head;
};

static struct qos_qinfo_list qos_qinfos;

struct qos_dev qos_devices[NUM_DEVS] = {
	{ NULL,
	  qos_dpdk_disable,
	  qos_dpdk_enable,
	  qos_dpdk_start,
	  qos_dpdk_stop,
	  qos_dpdk_free,
	  qos_dpdk_subport_read_stats,
	  qos_dpdk_subport_clear_stats,
	  qos_dpdk_queue_read_stats,
	  qos_dpdk_queue_clear_stats,
	  qos_dpdk_dscp_resgrp_json,
	  qos_dpdk_check_rate,
	},
	{ qos_hw_init,
	  qos_hw_disable,
	  qos_hw_enable,
	  qos_hw_start,
	  qos_hw_stop,
	  qos_hw_free,
	  qos_hw_subport_read_stats,
	  qos_hw_subport_clear_stats,
	  qos_hw_queue_read_stats,
	  qos_hw_queue_clear_stats,
	  qos_hw_dscp_resgrp_json,
	  qos_hw_check_rate,
	}
};

struct qos_ingressm qos_ingressm = {0};
struct qos_egressm qos_egressm = {0};

struct qos_ingress_map *qos_im_sysdef;

/* Used for legacy configs */
fal_object_t qos_global_map_obj = FAL_QOS_NULL_OBJECT_ID;

static const char *qos_dps[NUM_DPS] = {"green", "yellow", "red"};

static inline void QOS_RM_GLOBAL_MAP(void)
{
	if (SLIST_EMPTY(&qos_qinfos.qinfo_head)) {
		if (qos_global_map_obj) {
			qos_hw_del_map(qos_global_map_obj);
			qos_global_map_obj = FAL_QOS_NULL_OBJECT_ID;
		}
	}
}

static void qos_sched_npf_commit(void)
{
	struct sched_info *qinfo;
	unsigned int i;

	SLIST_FOREACH(qinfo, &qos_qinfos.qinfo_head, list) {

		for (i = 0; i < qinfo->port_params.n_pipe_profiles; i++) {
			struct queue_map *qmap = &qinfo->queue_map[i];

			qmap->reset_mask = 0;
		}

		if (qinfo->reset_port != QOS_NPF_COMMIT)
			continue;

		struct rte_eth_link link;

		QOS_STOP(qinfo)(qinfo->ifp, qinfo);

		/*
		 * If it exists, the global map obj must apply to all
		 * policy instances and all policy instances must have
		 * been affected by the resource group change we are
		 * responding to. So it is safe to delete it now
		 * and it will be reinstalled when the first policy is
		 * reinstalled.
		 */
		if (qos_global_map_obj) {
			qos_hw_del_map(qos_global_map_obj);
			qos_global_map_obj = FAL_QOS_NULL_OBJECT_ID;
		}

		rte_eth_link_get_nowait(qinfo->ifp->if_port, &link);
		if (link.link_status) {
			int ret;

			ret = qos_sched_start(qinfo->ifp, link.link_speed);
			if (ret != 0)
				qinfo->enabled = false;
		}
		qinfo->reset_port = QOS_NPF_READY;

		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "Port restart via npf res grp, link state %s\n",
			 (link.link_status) ? "up" : "down");
	}
}

/*
 * The mask passed in assigned dscp values to queues, the group used
 * to setup the mask is being changed so reset the dscp values to their
 * default queues.
 */
static void qos_dscp_reset_map(struct queue_map *qmap, uint64_t dscp_mask)
{
	unsigned int i;
	uint64_t j;

	for (i = 0, j = 1; i < MAX_DSCP; i++, j <<= 1) {
		if (j & dscp_mask) {
			/*
			 * If the dscp value has already been reassigned to
			 * another queue in a previous resource update do not
			 * reset it to the default queue otherwise we'll be
			 * overwriting a previous classifier.
			 */
			if (j & qmap->reset_mask)
				continue;

			qmap->dscp2q[i] =
				(~i >> (DSCP_BITS - RTE_SCHED_TC_BITS))
					   & RTE_SCHED_TC_MASK;
		}
	}
}

/*
 * This will assign new dscp to queue classification entries when a
 * resource group is changed.
 */
static void qos_dscp_init_map(struct queue_map *qmap, uint64_t dscp_mask,
			      uint8_t q_class)
{
	uint64_t i, j;

	for (i = 0, j = 1; i < MAX_DSCP; i++, j <<= 1) {
		if (dscp_mask & j)
			qmap->dscp2q[i] = q_class;
	}

	/* Keep track of the values we've already assigned */
	qmap->reset_mask |= dscp_mask;
}

static int qos_sched_update_wred_prof(struct sched_info *qinfo, char *grp,
				      struct qos_red_pipe_params *wred,
				      uint64_t new_dscp_mask)
{
	int j;

	for (j = 0; j < wred->red_q_params.num_maps; j++) {
		if (!strcmp(wred->red_q_params.grp_names[j], grp)) {
			if (wred->red_q_params.dscp_set[j] == new_dscp_mask)
				return -1;
			wred->red_q_params.dscp_set[j] = new_dscp_mask;
			qinfo->reset_port = QOS_NPF_COMMIT;
			return 0;
		}
	}
	return 0;
}

static int qos_sched_update_map(struct sched_info *qinfo, char *grp,
				struct queue_map *qmap,
				uint64_t new_dscp_mask)
{
	unsigned int j;
	struct qos_dscp_map *map;

	map = qmap->dscp_maps;
	if (!map)
		return 0;

	for (j = 0; j < map->num_maps; j++) {
		if (!strcmp(grp, map->dscp_grp_names[j])) {
			if (map->dscp_mask[j] == new_dscp_mask)
				return -1;
			qos_dscp_reset_map(qmap, map->dscp_mask[j]);
			qos_dscp_init_map(qmap, new_dscp_mask, map->qmap[j]);
			map->dscp_mask[j] = new_dscp_mask;
			qinfo->reset_port = QOS_NPF_COMMIT;
			return 0;
		}
	}
	return 0;
}

/*
 * Search the installed policies to check if any are using the resource group
 * which has been changed and update the dscp mask.
 */
void
qos_sched_res_grp_update(char *grp)
{
	struct sched_info *qinfo;
	unsigned int i;
	uint64_t new_dscp_mask;
	int ret;

	ret = npf_dscp_group_getmask(grp, &new_dscp_mask);
	if (ret) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Failed to retrieve resource group %s\n", grp);
		return;
	}

	DP_DEBUG(QOS, DEBUG, DATAPLANE, "Qos resource grp %s mask %"PRIx64"\n",
		grp, new_dscp_mask);

	SLIST_FOREACH(qinfo, &qos_qinfos.qinfo_head, list) {
		/*
		 * We're called at policy install which we want to ignore.
		 * Set the state to NPF_READY which means any indications
		 * after policy install we need to check the resource groups.
		 */
		if (qinfo->reset_port == QOS_INSTALL) {
			qinfo->reset_port = QOS_NPF_READY;
			continue;
		}

		for (i = 0; i < qinfo->port_params.n_pipe_profiles; i++) {
			struct qos_pipe_params *prof =
					&qinfo->port_params.pipe_profiles[i];
			struct qos_red_pipe_params *wred;

			SLIST_FOREACH(wred, &prof->red_head, list) {
				ret = qos_sched_update_wred_prof(qinfo, grp,
								 wred,
								 new_dscp_mask);
				if (ret == -1)
					return;
			}

			struct queue_map *qmap = &qinfo->queue_map[i];

			ret = qos_sched_update_map(qinfo, grp, qmap,
						   new_dscp_mask);
			if (ret == -1)
				return;
		}
	}
}

/*
 * Carry out any one-time initialisation that required when the
 * vyatta-dataplane starts up.
 */
void
qos_init(void)
{
	int i, ret;

	if (rte_red_set_scaling(MAX_RED_QUEUE_LENGTH) != 0)
		rte_panic("Failed to set RED scaling\n");

	qos_external_buf_monitor_init();
	SLIST_INIT(&qos_qinfos.qinfo_head);

	for (i = 0; i < NUM_DEVS; i++) {
		if (qos_devices[i].qos_init) {
			ret = (qos_devices[i].qos_init)();
			if (ret)
				rte_panic("Failed to initialize dev %d\n", i);
		}
	}
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

	if (qmap->designation == 0 && qmap->dscp_enabled == 0) {
		DP_DEBUG(QOS, INFO, DATAPLANE,
			 "DSCP map not enabled, enabling\n");
		qmap->dscp_enabled = 1;
	}

	return 1;
}

static int qos_sched_setup_dscp_map(struct sched_info *qinfo,
				    unsigned int profile, uint64_t dscp_mask,
				    char *name, uint8_t q)
{
	struct queue_map *qmap = &qinfo->queue_map[profile];
	struct qos_dscp_map *map = qmap->dscp_maps;
	int i;

	if (!map) {
		map = calloc(1, sizeof(struct qos_dscp_map));
		if (!map) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Queue dscp map allocation failure\n");
			return -1;
		}
		qmap->dscp_maps = map;
	} else if (map->num_maps == QOS_MAX_DSCP_MAPS) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "Too many dscp maps\n");
		return -1;
	}

	i = strlen(name) + 1;
	map->dscp_grp_names[map->num_maps] = calloc(1, i);
	if (!map->dscp_grp_names[map->num_maps]) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Failed to alloc dscp map\n");
		if (!map->num_maps) {
			free(qmap->dscp_maps);
			qmap->dscp_maps = NULL;
		}
		return -1;
	}

	strcpy(map->dscp_grp_names[map->num_maps], name);
	map->dscp_mask[map->num_maps] = dscp_mask;
	map->qmap[map->num_maps] = q;
	map->num_maps++;

	return 0;
}

/*
 * Returns the rate (bytes/sec) for the given bandwidth structure. If bandwidth
 * is given as a percentage, calculates the rate from the parent. Otherwise
 * returns the rate provided in the bandwidth structure.
 */
static uint32_t qos_rate_get(struct qos_rate_info *bw_info, uint32_t parent_bw,
			     struct sched_info *qinfo)
{
	uint32_t rate;

	if (bw_info->bw_is_percent) {
		const float precision = 0.0001;
		float full_pct = bw_info->rate.bw_percent;
		uint32_t whole_pct = (uint32_t)bw_info->rate.bw_percent;

		if (fabs(full_pct - (float)whole_pct) < precision)
			rate = ((uint64_t)parent_bw * whole_pct) / 100;
		else
			rate = (parent_bw * full_pct) / 100;
	} else
		rate = bw_info->rate.bandwidth;

	rate = QOS_CHECK_RATE(qinfo)(rate, parent_bw);

	return rate;
}

/*
 * Sets the rate (bytes/sec) into the given bandwidth structure. Returns
 * the rate provided.
 */
static uint32_t qos_abs_rate_set(struct qos_rate_info *bw_info, uint32_t abs_bw,
				 uint32_t parent_bw, struct sched_info *qinfo)
{
	bw_info->bw_is_percent = false;
	bw_info->rate.bandwidth = abs_bw;
	return qos_rate_get(bw_info, parent_bw, qinfo);
}

/*
 * Sets the rate percentage into the given bandwidth structure. Returns
 * the actual rate of the entity (see qos_rate_get for details)
 */
static uint32_t qos_percent_rate_set(struct qos_rate_info *bw_info,
			float percent_bw, uint32_t parent_bw,
			struct sched_info *qinfo)
{
	bw_info->bw_is_percent = true;
	bw_info->rate.bw_percent = percent_bw;
	return qos_rate_get(bw_info, parent_bw, qinfo);
}

/*
 * Returns the burst (bytes) for the given bandwidth structure. If burst
 * is specified in msec, calculates the burst value based on the given
 * rate (bytes/sec).
 */
static uint32_t qos_burst_get(struct qos_rate_info *bw_info, uint32_t rate)
{
	#define DEFAULT_BURST_MS (4)

	if (bw_info->burst_is_time)
		return (rate * bw_info->burst.time_ms) / 1000;

	if (bw_info->burst.size)
		return bw_info->burst.size;

	return (rate * DEFAULT_BURST_MS) / 1000;
}

/*
 * Sets the burst size (bytes) into the given bandwidth structure. Returns
 * the burst size provided.
 */
static uint32_t qos_abs_burst_set(struct qos_rate_info *bw_info,
				  uint32_t burst)
{
	bw_info->burst_is_time = false;
	bw_info->burst.size = burst;
	return burst;
}

/*
 * Sets the burst time (msec) into the given bandwidth structure. Returns
 * the calculated burst of the entity (see qos_burst_get for details)
 */
static uint32_t qos_time_burst_set(struct qos_rate_info *bw_info,
				   uint32_t burst, uint32_t rate)
{
	bw_info->burst_is_time = true;
	bw_info->burst.time_ms = burst;
	return qos_burst_get(bw_info, rate);
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

struct qos_red_pipe_params *
qos_red_find_q_params(struct qos_pipe_params *pipe, unsigned int qindex)
{
	struct qos_red_pipe_params *wred_params = NULL;

	SLIST_FOREACH(wred_params, &pipe->red_head, list) {
		if (wred_params->qindex == qindex)
			break;
	}
	return wred_params;
}

static int
qos_red_init_q_params(struct qos_red_q_params *wred_params,
		      unsigned int qmax, unsigned int qmin, unsigned int prob,
		      bool wred_per_dscp, uint64_t dscp_set, char *grp_name,
		      uint8_t dp)
{
	int wred_index, ret;

	if (!wred_params || wred_params->num_maps > RTE_MAX_DSCP_MAPS) {
		RTE_LOG(ERR, SCHED, "Invalid DSCP map init params\n");
		return -1;
	}

	if (wred_per_dscp)
		wred_index = wred_params->num_maps;
	else
		wred_index = dp;
	wred_params->dps_in_use |= (1 << wred_index);
	wred_params->qparams[wred_index].max_th = qmax;
	wred_params->qparams[wred_index].min_th = qmin;
	wred_params->qparams[wred_index].maxp_inv = prob;
	wred_params->dscp_set[wred_index] = dscp_set;
	ret = asprintf(&wred_params->grp_names[wred_index], "%s", grp_name);
	if (ret < 0) {
		wred_params->grp_names[wred_index] = NULL;
		return ret;
	}
	wred_params->num_maps++;
	return 0;
}

struct qos_red_pipe_params *
qos_red_alloc_q_params(struct qos_pipe_params *pipe, unsigned int qindex)
{
	struct qos_red_pipe_params *wred_params;

	wred_params = calloc(1, sizeof(struct qos_red_pipe_params));
	if (!wred_params) {
		RTE_LOG(ERR, SCHED, "qred_info calloc failed\n");
		return NULL;
	}
	wred_params->qindex = qindex;
	SLIST_INSERT_HEAD(&pipe->red_head, wred_params, list);
	return wred_params;
}

static void qos_free_q_params(struct qos_pipe_params *pipe, int i)
{
	struct qos_red_pipe_params *wred_params;
	struct qos_red_q_params *qparams;

	while ((wred_params = SLIST_FIRST(&pipe->red_head)) != NULL) {
		int j;

		SLIST_REMOVE_HEAD(&pipe->red_head, list);
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "Freeing Q RED params qindex %u profile "
			 "%u pipe %p wred_params %p\n",
			 wred_params->qindex, i, pipe, wred_params);
		qparams = &(wred_params->red_q_params);
		for (j = 0; j < RTE_NUM_DSCP_MAPS; j++) {
			if (qparams->grp_names[j])
				free(qparams->grp_names[j]);
		}
		free(wred_params);
	}
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

	if (!qinfo->subport)
		return;

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
	struct qos_pipe_params *pp;

	for (i = 0; i < qinfo->port_params.n_pipe_profiles; i++) {
		unsigned int j;
		struct queue_map *qmap;

		pp = &qinfo->port_params.pipe_profiles[i];
		qos_free_q_params(pp, i);
		qmap = &qinfo->queue_map[i];
		if (qmap && qmap->dscp_maps) {
			for (j = 0; j < qmap->dscp_maps->num_maps; j++)
				free(qmap->dscp_maps->dscp_grp_names[j]);
			free(qmap->dscp_maps);
		}
	}

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
	struct qos_pipe_params *pipe_params;
	struct qos_rate_info *profile_rates;
	struct qos_tc_rate_info *profile_tc_rates;
	unsigned int queues;

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

	profile_rates = calloc(profiles, sizeof(struct qos_rate_info));
	if (!profile_rates)
		goto nomem1;
	qinfo->profile_rates = profile_rates;

	profile_tc_rates = calloc(profiles, sizeof(struct qos_tc_rate_info));
	if (!profile_tc_rates)
		goto nomem1;
	qinfo->profile_tc_rates = profile_tc_rates;

	pipe_params = calloc(profiles, sizeof(struct qos_pipe_params));
	if (!pipe_params)
		goto nomem1;
	qinfo->port_params.pipe_profiles = pipe_params;

	qinfo->enabled = false;
	qinfo->ifp = ifp;
	qinfo->port_params.frame_overhead = overhead;
	qinfo->port_params.n_subports_per_port = subports;
	qinfo->port_params.n_pipes_per_subport = pipes;
	qinfo->port_params.n_pipe_profiles = profiles;
	qinfo->reset_port = QOS_INSTALL;
	rte_spinlock_init(&qinfo->stats_lock);

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		qinfo->port_params.qsize[i] = DEFAULT_QSIZE;

	/* Default parms for pipes */
	for (i = 0; i < profiles; i++) {
		struct qos_pipe_params *pp = &pipe_params[i];
		struct queue_map *qmap = &qinfo->queue_map[i];

		pp->shaper.tb_rate = qos_abs_rate_set(&profile_rates[i],
						      UINT32_MAX, 0, qinfo);
		pp->shaper.tb_size = qos_abs_burst_set(&profile_rates[i],
						       DEFAULT_TBSIZE);
		pp->shaper.tc_period = qos_period_set(&profile_rates[i], 10);
#ifdef RTE_SCHED_SUBPORT_TC_OV
		pp->shaper.tc_ov_weight = 0;
#endif
		for (j = 0; j < RTE_SCHED_QUEUES_PER_PIPE; j++)
			pp->wrr_weights[j] = 1;

		for (j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++) {
			pp->shaper.tc_rate[j] =
			    qos_abs_rate_set(&profile_tc_rates[i].tc_rate[j],
					     UINT32_MAX, 0, qinfo);
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
		qmap->designation = 0;

		/*
		 * Set up the default pipe-queue to tc-n/wrr-0 qmap information
		 */
		for (j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++)
			qmap->conf_ids[QMAP(j, 0)] = CONF_ID_Q_DEFAULT |
				(j * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);

		SLIST_INIT(&pp->red_head);
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
		sp->params.tb_rate = qos_abs_rate_set(&sp->subport_rate,
						      UINT32_MAX, 0, qinfo);
		sp->params.tb_size = qos_abs_burst_set(&sp->subport_rate,
						       DEFAULT_TBSIZE);
		sp->params.tc_period = qos_period_set(&sp->subport_rate, 10);

		for (j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++) {
			sp->params.tc_rate[j] =
				qos_abs_rate_set(&sp->sp_tc_rates.tc_rate[j],
						 UINT32_MAX, 0, qinfo);
			sp->qsize[j] = 0;    // Default to inherit from port
		}
	}

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
		 "New Qos configuration qos_port_%u\n", ifp->if_port);

	SLIST_INSERT_HEAD(&qos_qinfos.qinfo_head, qinfo, list);

	return qinfo;

 nomem1:
	qos_subport_npf_free(qinfo);
	qos_sched_free(qinfo);

 nomem0:
	return NULL;
}

/* Ensure the parameters are within acceptable bounds */
void qos_sched_subport_params_check(
		struct qos_shaper_conf *params,
		struct qos_rate_info *config_rate,
		struct qos_rate_info *config_tc_rate,
		uint16_t max_pkt_len, uint32_t max_burst_size, uint32_t bps,
		struct sched_info *qinfo)
{
	uint32_t min_rate = (max_pkt_len * 1000) / params->tc_period;
	uint32_t tc_period = 0, period = 0;
	unsigned int i;

	params->tb_rate = qos_rate_get(config_rate, bps, qinfo);

	/* squash rate down to actual line rate */
	if (params->tb_rate > bps)
		params->tb_rate = bps;

	params->tb_size = qos_burst_get(config_rate, params->tb_rate);

	if (params->tb_size < max_pkt_len)
		params->tb_size = max_pkt_len;

	if (params->tb_size > max_burst_size)
		params->tb_size = max_burst_size;

	period = params->tc_period;
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		params->tc_rate[i] = qos_rate_get(&config_tc_rate[i],
						  params->tb_rate, qinfo);
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
 * Only called by main thread.
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

	qinfo->reset_port = QOS_NPF_READY;

	return 0;
}

/* Cleanup scheduler when link goes down
 * Use RCU to set the pointer because destroyed by main thread
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
	struct qos_pipe_params *p =
	    qinfo->port_params.pipe_profiles + sinfo->profile_map[pipe];
	unsigned int i;

	jsonw_name(wr, "params");
	jsonw_start_object(wr);

	jsonw_name(wr, "tb_rate");
	jsonw_uint(wr, p->shaper.tb_rate);

	jsonw_name(wr, "tb_size");
	jsonw_uint(wr, p->shaper.tb_size);

	jsonw_name(wr, "tc_rates");
	jsonw_start_array(wr);
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		jsonw_uint(wr, p->shaper.tc_rate[i]);

	jsonw_end_array(wr);

	jsonw_name(wr, "tc_period");
	jsonw_uint(wr, p->shaper.tc_period);

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
	if (qmap->dscp_enabled || !optimised_json) {
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
	if (qmap->designation || !optimised_json) {
		struct qos_pipe_params *params =
			&qinfo->port_params.pipe_profiles[profile];

		jsonw_name(wr, "designation");
		jsonw_start_array(wr);
		for (i = 0; i < INGRESS_DESIGNATORS; i++)
			jsonw_uint(wr, params->designation[i]);
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

struct qos_sched_ing_map_info {
	uint16_t vlan;
	fal_object_t ingress_map;
};

static void show_ifp_qos(struct ifnet *ifp, void *arg)
{
	struct qos_show_context *context = arg;
	json_writer_t *wr = context->wr;
	struct sched_info *qinfo = ifp->if_qos;
	unsigned int i, num_maps = 0;
	struct cds_lfht_iter iter;
	struct if_vlan_feat *vlan_feat;
	struct fal_attribute_t ing_map_attr;
	struct qos_sched_ing_map_info ingress_maps[VLAN_N_VID];
	int rv;

	if (context->is_platform) {
		ing_map_attr.id = FAL_PORT_ATTR_QOS_INGRESS_MAP_ID;
		rv = fal_l2_get_attrs(ifp->if_index, 1, &ing_map_attr);

		if (rv != -ENOENT && ing_map_attr.value.objid) {
			ingress_maps[0].ingress_map = ing_map_attr.value.objid;
			ingress_maps[0].vlan = 0;
			num_maps++;
		}

		if (ifp->vlan_feat_table) {
			cds_lfht_for_each_entry(ifp->vlan_feat_table, &iter,
						vlan_feat, vlan_feat_node) {
				struct fal_attribute_t ing_map_attr;

				ing_map_attr.id =
				FAL_VLAN_FEATURE_ATTR_QOS_INGRESS_MAP_ID;
				fal_vlan_feature_get_attr(
						  vlan_feat->fal_vlan_feat, 1,
						  &ing_map_attr);
				if (ing_map_attr.value.objid) {
					ingress_maps[num_maps].ingress_map =
						ing_map_attr.value.objid;
					ingress_maps[num_maps].vlan =
						vlan_feat->vlan;
					num_maps++;
				}
			}
		}

		if (!context->sent_sysdef_map) {
			if (qos_im_sysdef) {
				jsonw_name(wr, "sysdef-map");
				jsonw_start_object(wr);
				jsonw_uint_field(wr, "vlan", VLAN_N_VID);
				fal_qos_dump_map(qos_im_sysdef->map_obj, wr);
				jsonw_end_object(wr);
				context->sent_sysdef_map = true;
			}
		}

	}

	if (qinfo == NULL && num_maps == 0)
		return;

	jsonw_name(wr, ifp->if_name);
	jsonw_start_object(wr);

	if (context->is_platform && num_maps) {
		jsonw_name(wr, "ingress-maps");
		jsonw_start_array(wr);
		for (i = 0; i < num_maps; i++) {
			jsonw_start_object(wr);
			jsonw_uint_field(wr, "vlan", ingress_maps[i].vlan);
			fal_qos_dump_map(ingress_maps[i].ingress_map, wr);
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);  /* ingress maps */

		if (qinfo == NULL) {
			jsonw_end_object(wr); /* ifname */
			return;
		}
	}

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

	cds_list_for_each_entry_rcu(mark_map, &qos_mark_map_list_head, list) {
		if (strcmp(mark_map->map_name, map_name) == 0)
			return mark_map;
	}
	return NULL;
}

static int qos_mark_map_store(char *map_name, enum egress_map_type type,
			      uint64_t dscp_set, uint8_t designation,
			      enum fal_packet_colour color,
			      uint8_t remark_value)
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
		mark_map->type = type;
	} else if (mark_map->type != type) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Invalid mark-map type, types must be the same\n");
		return -EINVAL;
	}

	if (type == EGRESS_DSCP) {
		for (dscp = 0; dscp < MAX_DSCP; dscp++) {
			if (dscp_set & (1ul << dscp))
				mark_map->pcp_value[dscp] = remark_value;
		}
	} else {
		int index = designation * FAL_NUM_PACKET_COLOURS + color;
		struct qos_mark_map_entry *entry =
			&mark_map->entries[index];

		entry->des = designation;
		entry->color = color;
		entry->pcp_value = remark_value;
	}
	return 0;
}

static void qos_mark_map_delete_rcu(struct rcu_head *head)
{
	struct qos_mark_map *mark_map =
		caa_container_of(head, struct qos_mark_map, obj_rcu);

	if (mark_map->mark_obj)
		qos_hw_del_map(mark_map->mark_obj);

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
	uint32_t i, num;

	jsonw_name(wr, "mark-maps");
	jsonw_start_array(wr);
	cds_list_for_each_entry_rcu(mark_map, &qos_mark_map_list_head, list) {
		jsonw_start_object(wr);
		jsonw_string_field(wr, "map-name", mark_map->map_name);
		if (mark_map->type == EGRESS_DSCP) {
			jsonw_string_field(wr, "map-type", "dscp");
			num = MAX_DSCP;
		} else {
			jsonw_string_field(wr, "map-type", "designation");
			num = FAL_QOS_MAP_DES_DP_VALUES;
		}
		jsonw_name(wr, "pcp-values");
		jsonw_start_array(wr);
		for (i = 0; i < num; i++)
			if (mark_map->type == EGRESS_DSCP)
				jsonw_uint(wr, mark_map->pcp_value[i]);
			else
				jsonw_uint(wr, mark_map->entries[i].pcp_value);

		jsonw_end_array(wr);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
}

static void show_qos_buf_threshold(
	struct qos_show_context *context)
{
	json_writer_t *wr = context->wr;
	char str[40];
	uint32_t threshold = 0;

	if (!qos_ext_buf_get_threshold(&threshold))
		sprintf(str, "Not configured yet");
	else
		sprintf(str, "%d%%", threshold);

	jsonw_name(wr, "buf-threshold");
	jsonw_start_object(wr);
	jsonw_string_field(wr, "threshold", str);
	jsonw_end_object(wr);
}

static void show_qos_buf_utilization(
	struct qos_show_context *context)
{
	json_writer_t *wr = context->wr;
	struct qos_external_buffer_congest_stats buf_stats;
	struct qos_external_buffer_sample *samples = 0;
	enum qos_ext_buf_evt_notify_mode n_mode = 0;

	if (!qos_ext_buf_get_stats(&buf_stats)) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			"failed to get buffer-utilization\n");
		return;
	}

	samples = buf_stats.buf_samples;
	n_mode = buf_stats.cur_state.period_data.notify_mode;

	jsonw_name(wr, "ext-buf-stats");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "total-buf-units", buf_stats.max_buf_desc);
	jsonw_uint_field(wr, "total-rejected-packets",
		buf_stats.rejected_pkt_cnt);

	if (n_mode == EXT_BUF_EVT_NOTIFY_MODE_MINUTE)
		jsonw_string_field(wr, "mode", "1-minute");
	else if (n_mode == EXT_BUF_EVT_NOTIFY_MODE_TEN_SEC)
		jsonw_string_field(wr, "mode", "10-seconds");
	else if (n_mode == EXT_BUF_EVT_NOTIFY_MODE_HOUR) {
		if (buf_stats.cur_state.period_data.bad_sample_in_period)
			jsonw_string_field(wr, "mode",
				"1-hour (with pending SNMP notification)");
		else
			jsonw_string_field(wr, "mode", "1-hour");
	}

	jsonw_name(wr, "latest-samples");
	jsonw_start_array(wr);
	for (int i = 0; i < EXT_BUF_STATUS_STATS_CNT; i++) {
		/* show latest sample at first */
		int idx = (buf_stats.cur_sample_idx - i +
			EXT_BUF_STATUS_STATS_CNT) % EXT_BUF_STATUS_STATS_CNT;
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "free", samples[idx].ext_buf_free);
		jsonw_uint_field(wr, "used", buf_stats.max_buf_desc -
			samples[idx].ext_buf_free);
		jsonw_uint_field(wr, "uti-rate",
			samples[idx].utilization_rate);
		jsonw_uint_field(wr, "rejected",
			samples[idx].ext_buf_pkt_reject);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);

	jsonw_end_object(wr);
}

static void show_qos_ingress_map(struct qos_show_context *context,
				 struct qos_ingress_map *map)
{
	json_writer_t *wr = context->wr;
	int i, j;

	jsonw_start_object(wr);
	jsonw_string_field(wr, "name", map->name);
	jsonw_string_field(wr, "type",
			(map->type == INGRESS_DSCP) ? "dscp" : "pcp");
	jsonw_bool_field(wr, "system-default", map->sysdef);
	jsonw_name(wr, "map");
	jsonw_start_array(wr);
	for (i = 0; i < INGRESS_DESIGNATORS; i++) {
		if (!map->designation[i].dps_in_use)
			continue;
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "designation", i);
		jsonw_name(wr, "DPs");
		jsonw_start_array(wr);
		for (j = 0; j < NUM_DPS; j++) {
			if (!(map->designation[i].dps_in_use & (1 << j)))
				continue;
			jsonw_start_object(wr);
			jsonw_uint_field(wr, "DP", j);
			jsonw_uint_field(wr, "pcp/mask",
					map->designation[i].mask[j]);
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
}

static struct qos_ingress_map *qos_lookup_map_byobj(fal_object_t objid)
{
	struct qos_ingress_map *map;

	cds_list_for_each_entry_rcu(map, &qos_ingress_maps, list)
		if (map->map_obj == objid)
			return map;

	return NULL;
}

static struct qos_mark_map *qos_lookup_egress_map_byobj(fal_object_t objid)
{
	struct qos_mark_map *map;

	cds_list_for_each_entry_rcu(map, &qos_egress_maps, list)
		if (map->mark_obj == objid)
			return map;

	return NULL;
}

static void show_qos_ingress_maps(struct qos_show_context *context,
				  struct ifnet *ifp, unsigned int vlan)
{
	json_writer_t *wr = context->wr;
	fal_object_t objid;
	struct qos_ingress_map *map;

	if (ifp) {
		objid = qos_hw_get_att_ingress_map(ifp, vlan);
		if (!objid) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				"No ingress-map created\n");
			return;
		}
		map = qos_lookup_map_byobj(objid);
		if (!map) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				"No ingress-map matching obj %lu\n", objid);
			return;
		}
		jsonw_name(wr, "ingress-maps");
		jsonw_start_array(wr);

		show_qos_ingress_map(context, map);

		jsonw_end_array(wr);
		return;
	}

	/*
	 * Let's see what map type we have if any
	 * The first if is the new api where we separate the classfication
	 * into ingress maps separate from the policy.
	 * The second is a legacy config where the classification is still
	 * part of the policy.
	 */
	if (!cds_list_empty(&qos_ingress_maps)) {
		jsonw_name(wr, "ingress-maps");
		jsonw_start_array(wr);

		cds_list_for_each_entry_rcu(map, &qos_ingress_maps, list)
			show_qos_ingress_map(context, map);

		jsonw_end_array(wr);
	} else if (!SLIST_EMPTY(&qos_qinfos.qinfo_head)) {
		struct sched_info *qinfo;
		struct queue_map *qmap;

		/*
		 * We only support a single profile on this platform so
		 * the qmap will always be index 0
		 */
		qinfo = SLIST_FIRST(&qos_qinfos.qinfo_head);
		qmap = &qinfo->queue_map[0];
		if (!qmap || !qmap->dscp_enabled) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				"Invalid map type configuration\n");
			return;
		}
		qos_hw_show_legacy_map(qmap, wr);
	}
}

static void show_qos_egress_map(struct qos_show_context *context,
				 struct qos_mark_map *map)
{
	json_writer_t *wr = context->wr;
	int i;

	jsonw_start_object(wr);
	jsonw_string_field(wr, "name", map->map_name);
	jsonw_string_field(wr, "type",
			(map->type == EGRESS_DESIGNATION_DSCP) ?
			"dscp" : "pcp");
	jsonw_name(wr, "map");
	jsonw_start_array(wr);
	for (i = 0; i < INGRESS_DESIGNATORS; i++) {
		jsonw_start_object(wr);
		jsonw_uint_field(wr, "designation", i);
		jsonw_uint_field(wr, "value", map->pcp_value[i]);
		jsonw_end_object(wr);
	}
	jsonw_end_array(wr);
	jsonw_end_object(wr);
}

static void show_qos_egress_maps(struct qos_show_context *context,
				  struct ifnet *ifp, unsigned int vlan)
{
	json_writer_t *wr = context->wr;
	fal_object_t objid;
	struct qos_mark_map *map;

	if (ifp) {
		if ((ifp->if_type == IFT_BRIDGE) ||
				(ifp->if_type == IFT_L2VLAN)) {
			objid = ifp->egr_map_obj;
		} else {
			objid = qos_hw_get_att_egress_map(ifp, vlan);
			if (!objid) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					"No egress-map created\n");
				return;
			}
		}
		map = qos_lookup_egress_map_byobj(objid);
		if (!map) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				"No egress-map matching obj %lu\n", objid);
			return;
		}
		jsonw_name(wr, "egress-maps");
		jsonw_start_array(wr);

		show_qos_egress_map(context, map);

		jsonw_end_array(wr);
		return;
	}

	if (!cds_list_empty(&qos_egress_maps)) {
		jsonw_name(wr, "egress-maps");
		jsonw_start_array(wr);

		cds_list_for_each_entry_rcu(map, &qos_egress_maps, list) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				"egress-map %s\n", map->map_name);
			show_qos_egress_map(context, map);
		}

		jsonw_end_array(wr);
	}
}

/* Handle: "qos show [interface]"
 *         "qos show platform"
 *         "qos show platform buf-threshold"
 *         "qos show platform buf-utilization"
 *         "qos show ingress-maps"
 *         "qos show [interface] ingress-map"
 *         "qos show policers [interface]"
 *         "qos show egress-maps"
 *         "qos show [interface] egress-map"
 * Output is in JSON
 */
static int cmd_qos_show(FILE *f, int argc, char **argv)
{
	struct qos_show_context context;

	if (argc >= 2 && !strcmp(argv[1], "platform")) {
		context.is_platform = true;
		context.sent_sysdef_map = false;
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
		dp_ifnet_walk(show_ifp_qos, &context);
	else {
		if (!strcmp(argv[1], "action-groups")) {
			dp_ifnet_walk(show_ifp_qos_act_grps, &context);
		} else if (strcmp(argv[1], "mark-maps") == 0) {
			show_qos_mark_map(&context);
		} else if (strcmp(argv[1], "buf-threshold") == 0) {
			show_qos_buf_threshold(&context);
		} else if (strcmp(argv[1], "buf-utilization") == 0) {
			show_qos_buf_utilization(&context);
		} else if (strcmp(argv[1], "ingress-maps") == 0) {
			struct ifnet *ifp = NULL;
			unsigned int vlan = 0;

			if (argc == 5) {
				if (strcmp("vlan", argv[2]) ||
				    get_unsigned(argv[3], &vlan) < 0) {
					fprintf(f,
					    "Invalid syntax interface\n");
					return -1;
				}
				ifp = dp_ifnet_byifname(argv[4]);
				if (!ifp) {
					fprintf(f, "Unknown interface: %s\n",
						*argv);
					return -1;
				}
			}
			show_qos_ingress_maps(&context, ifp, vlan);
		} else if (strcmp(argv[1], "egress-maps") == 0) {
			struct ifnet *ifp = NULL;
			unsigned int vlan = 0;

			if (argc == 5) {
				if (strcmp("vlan", argv[2]) ||
				    get_unsigned(argv[3], &vlan) < 0) {
					fprintf(f,
					    "Invalid syntax interface\n");
					return -1;
				}
				ifp = dp_ifnet_byifname(argv[4]);
				if (!ifp) {
					fprintf(f, "Unknown interface: %s\n",
						*argv);
					return -1;
				}
			}
			show_qos_egress_maps(&context, ifp, vlan);
		} else if (argc > 2 && !strcmp(argv[1], "policers")) {
			argv += 2;

			struct ifnet *ifp = dp_ifnet_byifname(*argv);
			if (!ifp) {
				fprintf(f, "Unknown interface: %s\n", *argv);
				return -1;
			}
			struct sched_info *qinfo = ifp->if_qos;
			if (!qinfo) {
				fprintf(f, "No qos on interface: %s\n", *argv);
				return -1;
			}
			struct subport_info *sport;
			unsigned int i;
			for (i = 0; i < qinfo->port_params.n_subports_per_port;
			     i++) {
				struct npf_act_grp *act_grp;
				sport = &qinfo->subport[i];
				act_grp = sport->act_grp_list;
				if (!act_grp)
					continue;

				npf_action_group_show_policer(act_grp,
							      &context);
			}
		} else if (argc == 2 && !strcmp(argv[1], "buffer-errors")) {
			qos_hw_dump_buf_errors(context.wr);
		} else {
			while (--argc > 0) {
				struct ifnet *ifp = dp_ifnet_byifname(*++argv);

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
		dp_ifnet_walk(show_ifp_qos, &context);
	else {
		struct ifnet *ifp = dp_ifnet_byifname(*++argv);

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
		dp_ifnet_walk(clear_ifp_qos_stats, NULL);
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
		ifp = dp_ifnet_byifname(*++argv);
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
		ifp = dp_ifnet_byifname(if_name);
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
		dp_ifnet_walk(show_ifp_qos_hw, &context);
	} else if (argc == 2) {
		struct ifnet *ifp;

		/* Initial interface name check */
		ifp = dp_ifnet_byifname(*++argv);
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
	bool hw_config = false;
	int ret;

	/*
	 * Expected command format:
	 *
	 * "port <a> subports <b> pipes <c> profiles <d> [overhead <e>] <f>"
	 *
	 * <a> - port-id
	 * <b> - number of configured subports
	 * <c> - number of configured pipes
	 * <d> - number of configured profiles
	 * <e> - frame-overhead
	 * <f> - queue limit type, "ql_packets" or "ql_bytes"
	 *
	 * Note that we can currently only support queue limits in
	 * bytes in hardware and only support queue limits in packets
	 * in software (DPDK). So use this setting to force the port to
	 * have hardware or software qos. If the current port type is
	 * such that the config cannot be applied, ie. byte limits on
	 * a software port or packet limits on a hw port then the port
	 * will not be qos enabled unless/until hardware forwarding is
	 * enabled/disabled.
	 */
	--argc, ++argv;	/* skip "port" */
	while (argc > 0) {
		unsigned int value;

		if (argc == 1 && !strncmp(argv[0], "ql_", 3)) {
			hw_config = !strcmp(argv[0], "ql_bytes");
			break;
		}

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

	if (subports == 0 || subports > RTE_ETHER_MAX_VLAN_ID) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "bad subports value: %u\n", subports);
		return -EINVAL;
	}

	if (hw_config)
		ret = qos_hw_port(ifp, subports, pipes, profiles, overhead);
	else
		ret = qos_dpdk_port(ifp, subports, pipes, profiles, overhead);

	return ret;
}

static int cmd_qos_subport_queue(struct subport_info *sinfo, unsigned int qid,
				 int argc, char **argv,
				 struct sched_info *qinfo)
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
	struct qos_shaper_conf *params = &sinfo->params;

	if (argc < 4) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "queue missing tc rate\n");
		return -EINVAL;
	}

	if (qid >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) {
		RTE_LOG(ERR, QOS, "traffic-class %u out of range\n", qid);
		return -EINVAL;
	}

	if (strcmp(argv[2], "percent") == 0) {
		float rate;

		if (get_float(argv[3], &rate) < 0 ||
		    rate < 0 || rate > 100) {
			RTE_LOG(ERR, QOS,
				"rate percentage %s out of range\n", argv[3]);
				return -EINVAL;
		}
		params->tc_rate[qid] =
			qos_percent_rate_set(
				&sinfo->sp_tc_rates.tc_rate[qid],
				rate, params->tb_rate, qinfo);
	} else if (strcmp(argv[2], "rate") == 0) {
		unsigned int rate;

		if (get_unsigned(argv[3], &rate) < 0) {
			RTE_LOG(ERR, QOS, "missing rate for queue\n");
			return -EINVAL;
		}

		params->tc_rate[qid] =
			qos_abs_rate_set(
				&sinfo->sp_tc_rates.tc_rate[qid], rate,
				params->tb_rate, qinfo);
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
	 * "subport <a> rate <b> msec <k> [period <d>]"
	 * "subport <a> percent <i> size <c> [period <d>]"
	 * "subport <a> percent <i> msec <k> [period <d>]"
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
	 * <k> - subport shaper max-burst size in msec
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
	struct qos_shaper_conf *params = &sinfo->params;

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
		} else if (strcmp(argv[0], "percent") == 0) {
			float percent_bw;

			if (get_float(argv[1], &percent_bw) < 0 ||
			    percent_bw < 0 || percent_bw > 100) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
				  "rate percentage %s out of range\n", argv[1]);
				return -EINVAL;
			}
			/* bytes/sec */
			params->tb_rate = qos_percent_rate_set(
					    &sinfo->subport_rate, percent_bw,
					    ifp->if_qos->port_params.rate,
					    qinfo);
		} else if (get_unsigned(argv[1], &value) < 0) {
			RTE_LOG(ERR, QOS, "number expected after %s\n",
				argv[0]);
			return -EINVAL;
		} else if (strcmp(argv[0], "rate") == 0) {
			/* bytes/sec */
			params->tb_rate =
				qos_abs_rate_set(&sinfo->subport_rate, value,
						 0, qinfo);
		} else if (strcmp(argv[0], "size") == 0) {
			/* credits (bytes) */
			params->tb_size =
				qos_abs_burst_set(&sinfo->subport_rate, value);
		} else if (strcmp(argv[0], "msec") == 0) {
			/* credits (bytes) */
			params->tb_size =
				qos_time_burst_set(&sinfo->subport_rate, value,
						   params->tb_rate);
		} else if (strcmp(argv[0], "period") == 0) {
			params->tc_period =
				qos_period_set(&sinfo->subport_rate, value);
		} else if (strcmp(argv[0], "queue") == 0) {
			/*
			 * Parse qos subport S queue Q rate R
			 * Nothing more to parse after queue so can
			 * just return.
			 */
			return cmd_qos_subport_queue(sinfo, value, argc, argv,
						     qinfo);
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
		struct queue_map *qmap = &qinfo->queue_map[profile];

		qinfo->subport[subport].profile_map[pipe]  = profile;
		qinfo->subport[subport].pipe_configured[pipe] = true;
		/* Default map is DSCP */
		if (!qmap->pcp_enabled && !qmap->designation)
			qmap->dscp_enabled = 1;
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
	 * "queue <d> drop-prec <l> <g> <h> <i>"
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
	 * <l> - drop precedence; "green", "yellow" or "red"
	 */
	struct qos_pipe_params *pipe
		= qinfo->port_params.pipe_profiles + profile;
	struct qos_rate_info *pipe_tc_rates =
			qinfo->profile_tc_rates[profile].tc_rate;

	if (argc < 4) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "not enough arguments\n");
		return -EINVAL;
	}

	if (strcmp(argv[2], "percent") == 0) {
		float percent_bw;

		if (value >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "traffic-class %u out of range\n", value);
			return -EINVAL;
		}

		if (get_float(argv[3], &percent_bw) < 0 ||
		    percent_bw < 0 || percent_bw > 100) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
			    "rate percentage %s out of range\n", argv[3]);
			return -EINVAL;
		}

		pipe->shaper.tc_rate[value] = qos_percent_rate_set(
						&pipe_tc_rates[value],
						percent_bw,
						pipe->shaper.tb_rate, qinfo);
	} else if (strcmp(argv[2], "rate") == 0) {
		unsigned int rate;

		if (value >= RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "traffic-class %u out of range\n", value);
			return -EINVAL;
		}

		if (get_unsigned(argv[3], &rate) < 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
			    "bad rate %s for queue\n", argv[3]);
			return -EINVAL;
		}
		pipe->shaper.tc_rate[value] = qos_abs_rate_set(
						&pipe_tc_rates[value], rate,
						pipe->shaper.tb_rate, qinfo);
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
		if (get_unsigned(argv[3], &weight) < 0) {
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
	} else if ((strcmp(argv[2], "dscp-group") == 0) ||
		   (strcmp(argv[2], "drop-prec") == 0)) {
		unsigned int qmax, qmin, prob;
		unsigned int qindex;
		bool wred_per_dscp;
		uint64_t dscp_set = 0;
		uint8_t dp = 0;
		int err;
		struct qos_red_pipe_params *qred_info;

		if (argc < 7 ||
		    get_unsigned(argv[5], &qmax) < 0 ||
		    get_unsigned(argv[6], &qmin) < 0 ||
		    get_unsigned(argv[7], &prob) < 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Invalid per queue RED input\n");
			return -EINVAL;
		}

		wred_per_dscp = strcmp(argv[2], "dscp-group") == 0;

		if (wred_per_dscp) {
			err = npf_dscp_group_getmask(argv[3], &dscp_set);
			if (err) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "dscp mask retrieval failed\n");
				return -EINVAL;
			}
		} else {
			/*
			 * If we are using ingress maps, the wred parameters
			 * are identified directly against a drop precedence
			 * (colour) rather than a dscp-group as the same
			 * dscp group could classify to different colours in
			 * different ingress maps.
			 */
			for (dp = 0; dp < NUM_DPS; dp++) {
				if (!strcmp(argv[3], qos_dps[dp]))
					break;
			}
			if (dp == NUM_DPS) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Invalid drop-precedence value\n");
				return -EINVAL;
			}
		}

		/*
		 * Store the wred-map information for the DPDK
		 */
		qindex = q_from_mask(value);
		qred_info = qos_red_find_q_params(pipe, qindex);
		if (!qred_info)
			qred_info = qos_red_alloc_q_params(pipe, qindex);
		if (!qred_info)
			return -EINVAL;

		err = qos_red_init_q_params(&qred_info->red_q_params, qmax,
					    qmin, prob, wred_per_dscp,
					    dscp_set, argv[3], dp);
		if (err < 0) {
			if (qred_info->red_q_params.num_maps == 0) {
				SLIST_REMOVE_HEAD(&pipe->red_head, list);
				free(qred_info);
			}
			return -EINVAL;
		}

		if (!strcmp(argv[4], "packets"))
			qred_info->red_q_params.unit = WRED_PACKETS;
		else if (!strcmp(argv[4], "bytes"))
			qred_info->red_q_params.unit = WRED_BYTES;
		else {
			DP_DEBUG(QOS, ERR, DATAPLANE, "Invalid unit field\n");
			return -EINVAL;
		}
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "per Q red prof %d dscp-grp %s %u %u prob %u "
			 "mask %"PRIx64"\n", profile, argv[3], qmin,
			 qmax, prob, dscp_set);
	} else if (strcmp(argv[2], "wred-weight") == 0) {
		unsigned int wred_weight;
		unsigned int qindex;
		struct qos_red_pipe_params *qred_info;
		struct qos_red_q_params *qred;
		int i;

		if (get_unsigned(argv[3], &wred_weight) < 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Invalid per queue RED weight\n");
			return -EINVAL;
		}

		qindex = q_from_mask(value);
		qred_info = qos_red_find_q_params(pipe, qindex);
		if (!qred_info) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				"Invalid wred-weight command\n");
			return -EINVAL;
		}

		for (i = 0, qred = &qred_info->red_q_params;
		     i < NUM_DPS; i++) {
			if (qred->dps_in_use & (1 << i))
				qred->qparams[i].wq_log2 = wred_weight;
		}
		qred->filter_weight = wred_weight;
	} else {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "unknown profile queue parameter: '%s'\n", argv[2]);
		return -EINVAL;
	}
	return 0;
}

static int cmd_qos_profile_designation(struct queue_map *qmap,
				       struct qos_pipe_params *pipe,
				       int argc, char **argv)
{
	unsigned int des;
	unsigned int value;

	/*
	 * Expected command format:
	 *
	 * "qos <a> profile <b> designation <c> queue <d>"
	 *
	 * <a> - port id
	 * <b> - profile id
	 * <c> - designation, classifier to queue (0..7)
	 * <d> - queue, tc and wrr mask
	 */
	if ((get_unsigned(argv[0], &des) < 0) || des > MAX_DESIGNATOR) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "Invalid designation id: %s\n",
			 argv[0]);
		return -EINVAL;
	}
	argc--; argv++;

	if (strcmp(argv[0], "queue")) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "Invalid designation cmd: %s\n",
			 argv[0]);
		return -EINVAL;
	}
	argc--; argv++;

	if (get_unsigned(argv[0], &value) < 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "Invalid queue index: %s\n",
			 argv[0]);
		return -EINVAL;
	}

	pipe->designation[des] = value;
	pipe->des_set |= (1 << des);
	qmap->designation = 1;

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
	 * "profile <a> rate <b> msec <s> [period <d>]"
	 * "profile <a> percent <r> size <c> [period <d>]"
	 * "profile <a> percent <r> msec <s> [period <d>]"
	 * "profile <a> queue <e> rate <f> size <g>"
	 * "profile <a> [queue <h> wrr-weight <i>]"
	 * "profile <a> [queue <h> dscp-group <m> <n> <o> <p>]"
	 * "profile <a> [queue <h> drop-prec <u> <n> <o> <p>]"
	 * "profile <a> [queue <h> wred-weight <q>]"
	 * "profile <a> [over-weight <j>]"
	 * "profile <a> [pcp <k> <h>]"
	 * "profile <a> [dscp <l> <h>]"
	 * "profile <a> [dscp-group <m> <h>]"
	 * "profile <a> designation <t> queue <h>
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
	 * <s> - profile shaper max-burst size in msec
	 * <t> - classification value used to determine queue
	 * <u> - drop precedence; "green", "yellow" or "red"
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

	struct qos_pipe_params *pipe
		= qinfo->port_params.pipe_profiles + profile;

	while (argc > 0) {
		unsigned int value;

		if (argc < 2) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "missing value qos profile ... %s\n", argv[0]);
			return -EINVAL;
		}

		if (strcmp(argv[0], "dscp-group") == 0) {
			unsigned int q;
			uint64_t dscp_mask, i;
			int err, j;

			err = npf_dscp_group_getmask(argv[1], &dscp_mask);
			if (err) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
				    "Failed to extract dscp mask from group\n");
				return -EINVAL;
			}
			if (get_unsigned(argv[2], &q) < 0) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "missing queue for dscp-group\n");
				return -EINVAL;
			}
			if (!valid_qmap(q))
				return -EINVAL;

			for (i = 1, j = 0; j <= 63; i = i << 1, j++) {
				if (dscp_mask & i) {
					if (!qos_sched_profile_dscp_map_set
							(qinfo, profile, j,
							 q, false)) {
						DP_DEBUG(QOS, ERR, DATAPLANE,
						  "profile_dscp_set failed\n");
						return -1;
					}
				}
			}

			if (qos_sched_setup_dscp_map(qinfo, profile, dscp_mask,
						     argv[1], (uint8_t)q)) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					  "dscp map setup failed\n");
				return -1;
			}

			DP_DEBUG(QOS, DEBUG, DATAPLANE,
				 "map dscp-group %s %"PRIx64" %x\n",
				 argv[1], dscp_mask, q);
			break; /* don't continue parsing line */
		}

		if (strcmp(argv[0], "percent") == 0) {
			float percent_bw;

			if (get_float(argv[1], &percent_bw) < 0 ||
			    percent_bw < 0 || percent_bw > 100) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
				  "rate percentage %s out of range\n", argv[1]);
				return -EINVAL;
			}
			/* bytes/sec */
			pipe->shaper.tb_rate = qos_percent_rate_set(
						 &qinfo->profile_rates[profile],
						 percent_bw,
						 qinfo->port_params.rate,
						 qinfo);
		} else if (get_unsigned(argv[1], &value) < 0) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "number expected after %s\n", argv[0]);
			return -EINVAL;
		} else if (strcmp(argv[0], "rate") == 0) {
			pipe->shaper.tb_rate = qos_abs_rate_set(
						 &qinfo->profile_rates[profile],
						 value,
						 qinfo->port_params.rate,
						 qinfo);
		} else if (strcmp(argv[0], "size") == 0) {
			pipe->shaper.tb_size = qos_abs_burst_set(
						 &qinfo->profile_rates[profile],
						 value); /*credits*/
		} else if (strcmp(argv[0], "msec") == 0) {
			pipe->shaper.tb_size = qos_time_burst_set(
						 &qinfo->profile_rates[profile],
						 value, pipe->shaper.tb_rate);
		} else if (strcmp(argv[0], "period") == 0) {
			pipe->shaper.tc_period =
				qos_period_set(&qinfo->profile_rates[profile],
						value); /* ms */
#ifdef RTE_SCHED_SUBPORT_TC_OV
		} else if (strcmp(argv[0], "over-weight") == 0) {
			pipe->shaper.tc_ov_weight = value;
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
		} else if (strcmp(argv[0], "designation") == 0) {
			argc--; argv++;
			return cmd_qos_profile_designation(
						&qinfo->queue_map[profile],
						pipe, argc, argv);
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
static int cmd_qos_red(struct qos_red_params red_params[][RTE_COLORS],
		       unsigned int tc, int argc, char *argv[])
{
	unsigned int value, color;
	struct qos_red_params red;

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

	if (color >= RTE_COLORS)
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
	DP_DEBUG(QOS, DEBUG, DATAPLANE,	"QoS disabled on %s\n", ifp->if_name);

	SLIST_REMOVE(&qos_qinfos.qinfo_head, qinfo, sched_info, list);

	QOS_RM_GLOBAL_MAP();

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
	uint32_t designation;
	enum egress_map_type type;
	enum fal_packet_colour color;

	/*
	 * Expected command format:
	 *
	 * "mark-map <a> dscp-group <b> pcp <c>"
	 * "mark-map <a> designation <d> drop-prec <e> pcp <c>"
	 * "mark-map <a> delete"
	 *
	 * <a> - mark-map name
	 * <b> - dscp-group resource group name
	 * <c> - pcp-value (0..7)
	 * <d> - designation value (0..7)
	 * <e> - drop precedence ("green", "yellow", "red")
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
	}

	if (!strcmp(argv[0], "dscp-group")) {
		if (argc != 4) {
			DP_DEBUG(QOS, DEBUG, DATAPLANE,
				 "wrong number of dscp mark-map arguments\n");
			return -EINVAL;
		}
		dscp_group_name = argv[1];
		err = npf_dscp_group_getmask(dscp_group_name, &dscp_set);
		if (err) {
			DP_DEBUG(QOS, DEBUG, DATAPLANE,
				 "dscp mark retrieval failed\n");
			return -EINVAL;
		}
		type = EGRESS_DSCP;
	} else if (!strcmp(argv[0], "designation")) {
		if (argc != 6) {
			DP_DEBUG(QOS, DEBUG, DATAPLANE,
				 "wrong number of des mark-map arguments\n");
			return -EINVAL;
		}
		if ((get_unsigned(argv[1], &designation) < 0) ||
		     designation > MAX_DESIGNATOR) {
			DP_DEBUG(QOS, DEBUG, DATAPLANE,
				 "invalid mark-map designation value %s\n",
				 argv[3]);
			return -EINVAL;
		}
		if (!strcmp(argv[2], "drop-prec")) {
			for (color = 0; color < NUM_DPS; color++) {
				if (!strcmp(argv[3], qos_dps[color]))
					break;
			}
			if (color == NUM_DPS) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Invalid drop-precedence value\n");
				return -EINVAL;
			}
		} else {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Missing ingress map drop-precedence\n");
			return -EINVAL;
		}
		type = EGRESS_DESIGNATION;

		/* account for extra drop-prec <value> args */
		argc -= 2;
		argv += 2;
	} else {

		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "unknown mark-map keyword %s\n", argv[0]);
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
	return qos_mark_map_store(map_name, type, dscp_set,
				  (uint8_t)designation, color,
				  (uint8_t)pcp_value);
}

static int cmd_qos_platform_buf_threshold(int argc, char **argv)
{
	unsigned int threshold;

	/*
	 * Expected command format:
	 *
	 * "buffer-threshold <a>"
	 * "buffer-threshold <a> delete"
	 *
	 * <a> - threshold value in percentage
	 */
	--argc, ++argv; /* skip "buffer-threshold" */
	if (argc < 1) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"buffer-threshold missing threshold value\n");
		return -EINVAL;
	}

	if (get_unsigned(argv[0], &threshold) < 0) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"Buffer threshold is not a number: %s\n", argv[0]);
		return -EINVAL;
	}

	if (argc == 1)
		qos_external_buf_threshold_interval(threshold);
	else if (argc == 2 && (strcmp(argv[1], "delete") == 0))
		qos_external_buf_threshold_interval(0);
	else {
		char str[512] = {0};
		for (int i = 0; i < argc; i++)
			sprintf(str + strlen(str), "%s ", argv[i]);
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"Buffer threshold unknown parameter: %s\n", str);
		return -EINVAL;
	}

	return 0;
}

static int cmd_qos_platform(int argc, char **argv)
{
	--argc, ++argv; /* skip "platform" */
	if (argc < 1) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "platform parameter missing\n");
		return -EINVAL;
	}

	if (strcmp(argv[0], "buffer-threshold") == 0)
		return cmd_qos_platform_buf_threshold(argc, argv);

	return 0;
}

static uint8_t priority_local_designator = INGRESS_DESIGNATORS;

uint8_t qos_get_prio_lp_des(void)
{
	return priority_local_designator;
}

static int cmd_qos_local_prio_des(int argc, char **argv)
{
	uint8_t des;

	/*
	 * Expected command format:
	 *
	 * "lp-des <a>"
	 * "lp-des delete"
	 *
	 * <a> - designator value, 0-7
	 */
	--argc, ++argv; /* skip "lp-des" */
	if (argc != 1) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "lp-des wrong number of args\n");
		return -EINVAL;
	}

	if (!strcmp(argv[0], "delete")) {
		priority_local_designator = INGRESS_DESIGNATORS;
		return 0;
	}

	if (!get_unsigned_char(argv[0], &des)) {
		if (des >= INGRESS_DESIGNATORS) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "lp-des value %d out of range (0-7)\n", des);
			return -EINVAL;
		}
		priority_local_designator = des;
		return 0;
	}

	DP_DEBUG(QOS, ERR, DATAPLANE, "Invalid designation value\n");
	return -EINVAL;
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

static struct qos_ingress_map *qos_ingress_map_find(char const *name)
{
	struct qos_ingress_map *map;

	cds_list_for_each_entry(map, &qos_ingress_maps, list) {
		if (!strcmp(map->name, name))
			return map;
	}
	return NULL;
}

static int qos_ingressm_trgt_attach(unsigned int ifindex, unsigned int vlan,
				    char const *name)
{
	struct qos_ingress_map *map;
	int ret;

	if (!qos_ingressm.qos_ingressm_attach) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Device doesn't support ingress maps");
		return -EOPNOTSUPP;
	}

	map = qos_ingress_map_find(name);
	if (!map) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Ingress target cmd failed no map %s\n", name);
		return -EINVAL;
	}

	ret = (*qos_ingressm.qos_ingressm_attach)(ifindex, vlan, map);
	if (ret)
		return ret;

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
		 "Attaching ingress map %s ifindex %u vlan %u\n",
		 name, ifindex, vlan);
	return 0;
}

static int qos_ingressm_trgt_detach(unsigned int ifindex, unsigned int vlan)
{
	int ret;

	if (!qos_ingressm.qos_ingressm_detach) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Device doesn't support ingress maps");
		return -EOPNOTSUPP;
	}

	DP_DEBUG(QOS, DEBUG, DATAPLANE, "Detach ingress map target %u %u\n",
		 ifindex, vlan);

	ret = (*qos_ingressm.qos_ingressm_detach)(ifindex, vlan);

	return ret;
}

static struct qos_ingress_map *qos_ingress_map_create(char const *name)
{
	struct qos_ingress_map *map;

	DP_DEBUG(QOS, DEBUG, DATAPLANE, "Create ingress-map %s\n", name);
	map = calloc(1, sizeof(struct qos_ingress_map) + strlen(name) + 1);
	if (!map)
		return NULL;
	strcpy(map->name, name);
	map->type = INGRESS_UNDEF;
	cds_list_add_tail_rcu(&map->list, &qos_ingress_maps);
	return map;
}

static void qos_ingress_map_delete_rcu(struct rcu_head *head)
{
	struct qos_ingress_map *map =
		caa_container_of(head, struct qos_ingress_map, obj_rcu);
	free(map);
}

static int qos_ingress_map_delete(char const *name)
{
	struct qos_ingress_map *map;
	int ret = 0;

	map = qos_ingress_map_find(name);
	if (!map) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Invalid ingress-map delete %s\n", name);
		return -ENOENT;
	}
	DP_DEBUG(QOS, ERR, DATAPLANE, "Delete ingress-map %s\n", name);
	cds_list_del_rcu(&map->list);
	ret = (*qos_ingressm.qos_ingressm_config)(map, false);
	if (qos_im_sysdef == map)
		qos_im_sysdef = NULL;
	call_rcu(&map->obj_rcu, qos_ingress_map_delete_rcu);
	return ret;
}

static int
qos_ingress_map_get(char const *name, enum ingress_map_type type,
		    uint64_t mask, uint8_t des, uint8_t dp)
{
	struct qos_ingress_map *map;

	map = qos_ingress_map_find(name);
	if (!map) {
		map = qos_ingress_map_create(name);
		if (!map)
			return -ENOMEM;
		map->type = type;
	} else if (map->type != type) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Invalid type for ingress-map %s\n", name);
		return -EINVAL;
	}

	map->designation[des].dps_in_use |= (1 << dp);
	map->designation[des].mask[dp] |= mask;

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
	    "Added map name %s type %d des %u dp %u mask %"PRIx64"\n",
	     name, type, des, dp, mask);

	return 0;
}

static int qos_ingress_map_sysdef(char const *name)
{
	struct qos_ingress_map *map;

	if (!qos_ingressm.qos_ingressm_config) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Device doesn't support ingress maps");
		return -EOPNOTSUPP;
	}

	map = qos_ingress_map_find(name);
	if (!map) {
		if (qos_im_sysdef) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Ingress map system-default already alloced");
			return -EINVAL;
		}
		map = qos_ingress_map_create(name);
		if (!map)
			return -ENOMEM;
	} else {
		if (qos_im_sysdef && strcmp(qos_im_sysdef->name, map->name)) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Ingress map system-default already alloced");
			return -EINVAL;
		}
	}

	map->sysdef = true;
	qos_im_sysdef = map;

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
		 "Set system default ingress-map to %s\n", name);

	return 0;
}

static int qos_ingress_map_complete(char const *name)
{
	struct qos_ingress_map *map;
	int ret;

	map = qos_ingress_map_find(name);
	if (!map) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "No ingress map found %s\n", name);
		return -ENOENT;
	}

	DP_DEBUG(QOS, ERR, DATAPLANE, "Completed ingress map %s\n", name);

	ret = (*qos_ingressm.qos_ingressm_config)(map, true);

	return ret;
}

static int cmd_qos_ingress_map(struct ifnet *ifp, int argc, char **argv)
{
	const char *map_name;
	uint64_t mask = 0;
	enum ingress_map_type type = INGRESS_UNDEF;
	uint8_t des, dp;
	int ret;

	/* Skip ingress-map */
	argc--; argv++;

	/*
	 * Expected command format:
	 *
	 * "ingress-map <a> dscp-group <b> designator <c> drop-prec <f>"
	 * "ingress-map <a> pcp <d> designator <c> drop-prec <f>"
	 * "ingress-map <a> complete"
	 * "ingress-map <a> delete"
	 * "ingress-map <a> system-default"
	 * "ingress-map <a> vlan <e>"
	 * "ingress-map <a> vlan <e> delete"
	 *
	 * <a> - ingress-map name
	 * <b> - dscp-group resource group name
	 * <c> - TC queue designation (0..7)
	 * <d> - PCP value (0..7)
	 * <e> - vlan (0..4095)
	 * <f> - drop precedence ("green", "yellow", "red")
	 */

	map_name = argv[0];
	--argc, ++argv; /* skip name */

	switch (argc) {
	case 1:
		/*
		 * delete - We are deleting an ingress-map
		 * system-default - We are setting a system-default
		 * complete - The definition of an ingress-map is complete
		 */
		if (!strcmp(argv[0], "delete"))
			return qos_ingress_map_delete(map_name);
		else if (!strcmp(argv[0], "system-default"))
			return qos_ingress_map_sysdef(map_name);
		else if (!strcmp(argv[0], "complete"))
			return qos_ingress_map_complete(map_name);
		break;

	case 2:
	case 3:
		if (strcmp(argv[0], "vlan"))
			break;

		unsigned int vlan;
		argc--; argv++;
		if ((get_unsigned(argv[0], &vlan) < 0) ||
		    vlan >= VLAN_N_VID) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Invalid vlan value\n");
			return -EINVAL;
		}

		if (!ifp) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Invalid ifp\n");
			return -EINVAL;
		}

		argc--; argv++;
		if (!argc)
			return(qos_ingressm_trgt_attach(ifp->if_index, vlan,
							map_name));
		else if (!strcmp(argv[0], "delete"))
			return(qos_ingressm_trgt_detach(ifp->if_index,
							vlan));
		break;

	case 6:
		if (!strcmp(argv[0], "dscp-group")) {
			argc--; argv++;
			ret = npf_dscp_group_getmask(argv[0], &mask);
			if (ret) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Failed to retrieve dscp group %s\n",
					 argv[0]);
				return -ENOENT;
			}
			argc--; argv++;
			type = INGRESS_DSCP;
		} else if (!strcmp(argv[0], "pcp")) {
			unsigned int pcp;

			argc--; argv++;
			if ((get_unsigned(argv[0], &pcp) < 0) ||
			    pcp > MAX_DESIGNATOR) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Invalid PCP value\n");
				return -EINVAL;
			}
			argc--; argv++;
			mask = (uint64_t)(1 << pcp);
			type = INGRESS_PCP;
		} else {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Missing ingress map type\n");
			return -EINVAL;
		}


		if (!strcmp(argv[0], "designation")) {
			argc--; argv++;
			if ((get_unsigned_char(argv[0], &des) < 0) ||
			    des > MAX_DESIGNATOR) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Invalid designation value\n");
				return -EINVAL;
			}
			argc--; argv++;
		} else {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Missing ingress map designation\n");
			return -EINVAL;
		}

		if (!strcmp(argv[0], "drop-prec")) {
			argc--; argv++;
			for (dp = 0; dp < NUM_DPS; dp++) {
				if (!strcmp(argv[0], qos_dps[dp]))
					break;
			}
			if (dp == NUM_DPS) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Invalid drop-precedence value\n");
				return -EINVAL;
			}
		} else {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Missing ingress map drop-precedence\n");
			return -EINVAL;
		}

		return(qos_ingress_map_get(map_name, type, mask, des, dp));
	default:
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Ingress map command has wrong number of args\n");
		break;
	}

	DP_DEBUG(QOS, ERR, DATAPLANE,
		 "Invalid ingress-map command\n");

	return -EINVAL;
}

struct qos_mark_map *qos_egress_map_find(char const *name)
{
	struct qos_mark_map *map;

	cds_list_for_each_entry(map, &qos_egress_maps, list) {
		if (!strcmp(map->map_name, name))
			return map;
	}
	return NULL;
}

static int qos_egressm_trgt_attach(unsigned int ifindex, unsigned int vlan,
				    char const *name)
{
	struct qos_mark_map *map;
	int ret;

	if (!qos_egressm.qos_egressm_attach) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Device doesn't support egress maps");
		return -EOPNOTSUPP;
	}

	map = qos_egress_map_find(name);
	if (!map) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Egress target cmd failed no map %s\n", name);
		return -EINVAL;
	}

	ret = (*qos_egressm.qos_egressm_attach)(ifindex, vlan, map);
	if (ret) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Failed to attach egress "
			 "map:%s on ifindex:%d, vlan:%d ret:%d\n",
			 name, ifindex, vlan, ret);
		return ret;
	}

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
		 "Attaching egress map %s ifindex %u vlan %u\n",
		 name, ifindex, vlan);
	return 0;
}

static int qos_egressm_trgt_detach(unsigned int ifindex, unsigned int vlan,
				    char const *name)
{
	struct qos_mark_map *map;
	int ret;

	if (!qos_egressm.qos_egressm_detach) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Device doesn't support egress maps");
		return -EOPNOTSUPP;
	}

	map = qos_egress_map_find(name);
	if (!map) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Egress target cmd failed no map %s\n", name);
		return -EINVAL;
	}

	DP_DEBUG(QOS, DEBUG, DATAPLANE, "Detach egress map target %u %u\n",
		 ifindex, vlan);

	ret = (*qos_egressm.qos_egressm_detach)(ifindex, vlan, map);

	return ret;
}

static struct qos_mark_map *qos_egress_map_create(char const *name)
{
	struct qos_mark_map *map;

	DP_DEBUG(QOS, DEBUG, DATAPLANE, "Create egress-map %s\n", name);
	map = calloc(1, sizeof(struct qos_mark_map) + strlen(name) + 1);
	if (!map)
		return NULL;
	strcpy(map->map_name, name);
	map->type = EGRESS_UNDEF;
	cds_list_add_tail_rcu(&map->list, &qos_egress_maps);
	return map;
}

static void qos_egress_map_delete_rcu(struct rcu_head *head)
{
	struct qos_mark_map *map =
		caa_container_of(head, struct qos_mark_map, obj_rcu);
	free(map);
}

static int qos_egress_map_delete(char const *name)
{
	struct qos_mark_map *map;
	int ret = 0;

	map = qos_egress_map_find(name);
	if (!map) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Invalid egress-map delete %s\n", name);
		return -ENOENT;
	}
	DP_DEBUG(QOS, ERR, DATAPLANE, "Delete egress-map %s\n", name);
	cds_list_del_rcu(&map->list);
	ret = (*qos_egressm.qos_egressm_config)(map, false);
	call_rcu(&map->obj_rcu, qos_egress_map_delete_rcu);
	return ret;
}

static int
qos_egress_map_set(char const *name, enum egress_map_type type,
		uint8_t designation, uint8_t remark_value)
{
	struct qos_mark_map *map;

	map = qos_egress_map_find(name);
	if (!map) {
		map = qos_egress_map_create(name);
		if (!map)
			return -ENOMEM;
		map->type = type;
	} else if (map->type != type) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Invalid type for egress-map %s\n", name);
		return -EINVAL;
	}

	map->type = type;
	map->pcp_value[designation] = remark_value;
	map->des_used |= (1 << designation);
	DP_DEBUG(QOS, DEBUG, DATAPLANE,
	    "Added map name %s type %d remark_value %d designation %d\n",
	    name, type, remark_value, designation);

	return 0;
}

static int qos_egress_map_complete(char const *name)
{
	struct qos_mark_map *map;
	int ret;

	map = qos_egress_map_find(name);
	if (!map) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "No egress map found %s\n", name);
		return -ENOENT;
	}

	DP_DEBUG(QOS, ERR, DATAPLANE, "Completed egress map %s\n", name);

	ret = (*qos_egressm.qos_egressm_config)(map, true);

	return ret;
}

static int cmd_qos_egress_map(struct ifnet *ifp, int argc, char **argv)
{
	const char *map_name;
	enum egress_map_type type = EGRESS_UNDEF;
	uint8_t remark_value;
	unsigned int desg;

	int i = 0;
	for (i = 0; i < argc; i++)
		DP_DEBUG(QOS, ERR, DATAPLANE, "%s - "
				"argv[%d]:%s\n",
				__func__, i, argv[i]);
	/* Skip egress-map */
	argc--; argv++;

	/*
	 * Expected command format:
	 *
	 * "egress-map <a> designation <b> dscp <c>"
	 * "egress-map <a> delete"
	 * "egress-map <a> complete"
	 * "egress-map <a> vlan <d>"
	 * "egress-map <a> vlan <d> delete"
	 *
	 * <a> - egress-map name
	 * <b> - designation value (0..7)
	 * <c> - dscp-value (0..63)
	 * <d> - vlan
	 *
	 */

	map_name = argv[0];
	--argc, ++argv; /* skip name */

	switch (argc) {
	case 1:
		/*
		 * delete - We are deleting an ingress-map
		 * system-default - We are setting a system-default
		 * complete - The definition of an ingress-map is complete
		 */
		if (!strcmp(argv[0], "delete"))
			return qos_egress_map_delete(map_name);
		else if (!strcmp(argv[0], "complete"))
			return qos_egress_map_complete(map_name);
		break;

	case 2:
	case 3:
		if (strcmp(argv[0], "vlan"))
			break;

		unsigned int vlan;
		argc--; argv++;
		if ((get_unsigned(argv[0], &vlan) < 0) ||
		    vlan >= VLAN_N_VID) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Invalid vlan value\n");
			return -EINVAL;
		}

		if (!ifp) {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Invalid ifp\n");
			return -EINVAL;
		}

		argc--; argv++;
		if (!argc)
			return(qos_egressm_trgt_attach(ifp->if_index, vlan,
							map_name));
		else if (!strcmp(argv[0], "delete"))
			return(qos_egressm_trgt_detach(ifp->if_index, vlan,
							map_name));
		break;

	case 4:
		if (!strcmp(argv[0], "designation")) {
			argc--; argv++;
			if ((get_unsigned(argv[0], &desg) < 0) ||
			    desg > MAX_DESIGNATOR) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Invalid Desigation value\n");
				return -EINVAL;
			}
			argc--; argv++;
		} else {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Missing egress map type\n");
			return -EINVAL;
		}


		if (!strcmp(argv[0], "dscp")) {
			argc--; argv++;
			if ((get_unsigned_char(argv[0], &remark_value) < 0) ||
			    remark_value > MAX_DSCP) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "Invalid DSCP value\n");
				return -EINVAL;
			}
			argc--; argv++;
			type = EGRESS_DESIGNATION_DSCP;
		} else if (!strcmp(argv[0], "pcp")) {
			argc--; argv++;
			if ((get_unsigned_char(argv[0], &remark_value) < 0) ||
				remark_value > MAX_PCP) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
				"Invalid PCP value\n");
				return -EINVAL;
			}
			argc--; argv++;
			type = EGRESS_DESIGNATION_PCP;
		} else {
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "Missing egress map DSCP or PCP value\n");
			return -EINVAL;
		}

		return(qos_egress_map_set(map_name, type, desg, remark_value));

	default:
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Egress map command has wrong number of args\n");
		break;
	}

	DP_DEBUG(QOS, ERR, DATAPLANE,
		 "Invalid egress-map command\n");

	return -EINVAL;
}

/*
 * There is a race between NEWLINK messages from the kernel
 * and the NEWPORT response from the controller. So we need
 * to store interface specific commands for which there is no
 * interface in the expectation that the ifp will exist shortly :-(
 */
static struct cfg_if_list *qos_cfg_list;

static void
qos_if_index_set(struct ifnet *ifp)
{
	int rv;

	rv = cfg_if_list_replay(&qos_cfg_list, ifp->if_name, cmd_qos_cfg);

	if (rv)
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "qos cache replay failed for %s, rv %d (%s)",
			 ifp->if_name, rv, strerror(-rv));
}

static void
qos_if_index_unset(struct ifnet *ifp, uint32_t ifindex __unused)
{
	int rv;

	rv = cfg_if_list_replay(&qos_cfg_list, ifp->if_name, NULL);

	if (rv)
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "qos cache remove failed for %s, rv %d (%s)",
			 ifp->if_name, rv, strerror(-rv));
}

/* Process qos related config commands */
int cmd_qos_cfg(__unused FILE * f, int argc, char **argv)
{
	int rv;

	if (argc < 2) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "usage: missing qos command\n");
		return -EINVAL;
	}

	debug_cmd(argc-1, argv+1);

	if (argc == 2 && !strcmp(argv[1], "commit")) {
		qos_sched_npf_commit();
		return 0;
	}

	/*
	 * QoS uses a special marker to signal a global object, i.e.
	 * one that isn't tied to one particular interface. The string
	 * is deliberately longer than IFNAMSIZ so it can never be confused
	 * with a real ifname.
	 */
	if (!strcmp(argv[1], "global-object-cmd")) {
		--argc, ++argv; /* skip "qos" */
		--argc, ++argv; /* skip global marker*/
		if (argc < 1) {
			RTE_LOG(ERR, QOS, "missing qos subcommand\n");
			return -EINVAL;
		}

		if (strcmp(argv[0], "mark-map") == 0)
			return cmd_qos_mark_map(argc, argv);
		else if (strcmp(argv[0], "platform") == 0)
			return cmd_qos_platform(argc, argv);
		else if (strcmp(argv[0], "ingress-map") == 0)
			return cmd_qos_ingress_map(NULL, argc, argv);
		else if (strcmp(argv[0], "egress-map") == 0)
			return cmd_qos_egress_map(NULL, argc, argv);
		else if (strcmp(argv[0], "lp-des") == 0)
			return cmd_qos_local_prio_des(argc, argv);

		return -EINVAL;
	}

	/*
	 * All other Config-mode commands start with an interface name which
	 * vplaned should guarantee will be present. Unfortunately due to
	 * a race condition we currently have a cache/replay mechanism to
	 * cope with that not being the case.
	 */
	struct ifnet *ifp = dp_ifnet_byifname(argv[1]);

	if (!ifp) {
		/*
		 * Interface not found, attempt to cache the command for replay
		 * if it turns up later.
		 */
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "qos interface %s not found, cache cmd\n", argv[1]);
		rv = cfg_if_list_cache_command(&qos_cfg_list, argv[1],
					       argc, argv);
		if (rv)
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "qos cache cmd for %s failed %d(%s)\n",
				 argv[1], rv, strerror(-rv));
		return rv;
	}

	--argc, ++argv; /* skip "qos" */
	--argc, ++argv;	/* skip IFNAME */
	if (argc < 1) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "missing qos subcommand\n");
		return -EINVAL;
	}

	/*
	 * Egress-map is still supported on VIF although its part of
	 * policymap
	 */
	if ((ifp->if_type != IFT_ETHER) &&
			(strcmp(argv[0], "egress-map") != 0)) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Qos only possible on physical ports\n");
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
	else if (strcmp(argv[0], "ingress-map") == 0)
		return cmd_qos_ingress_map(ifp, argc, argv);
	else if (strcmp(argv[0], "egress-map") == 0)
		return cmd_qos_egress_map(ifp, argc, argv);
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
		*ifp = dp_ifnet_byifname(ifname);
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
	ifp = dp_ifnet_byifname(vlan_ifp_name);
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
	if (!ifp->if_qos || speed == ETH_SPEED_NUM_NONE)
		return;

	/*
	 * We can only start QoS if the config (hw vs sw) matches
	 * the current state of the port (hw vs sw).
	 */
	if ((ifp->if_qos->dev_id == QOS_HW_ID && ifp->hw_forwarding) ||
	    (ifp->if_qos->dev_id == QOS_DPDK_ID && !ifp->hw_forwarding)) {

		if (up)
			qos_sched_start(ifp, speed);
		else
			qos_sched_stop(ifp);
	}
}

static void
qos_if_mtu_change(struct ifnet *ifp, uint32_t mtu __unused)
{
	struct rte_eth_link link;

	if (!ifp->if_qos)
		return;

	rte_eth_link_get_nowait(ifp->if_port, &link);
	if (link.link_status) {
		/*
		 * Since changing the MTU can influence the burst size and as
		 * result affect the shaper functionality,  ensure that for
		 * software based QoS support the scheduler is stopped and
		 * started.  HW Qos support is able to cope with this and
		 * as a result doesn't need changing.
		 */
		if (ifp->if_qos->dev_id == QOS_DPDK_ID && !ifp->hw_forwarding) {
			qos_sched_stop(ifp);
			qos_sched_start(ifp, link.link_speed);
		}
	}
}

static void
qos_if_delete(struct ifnet *ifp)
{
	struct sched_info *qinfo = ifp->if_qos;

	if (!qinfo)
		return;

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
		 "QoS disabled for interface %s delete\n", ifp->if_name);

	SLIST_REMOVE(&qos_qinfos.qinfo_head, qinfo, sched_info, list);

	QOS_RM_GLOBAL_MAP();

	QOS_DISABLE(qinfo)(ifp, qinfo);
}

static void
qos_if_feat_mode_change(struct ifnet *ifp, enum if_feat_mode_event event)
{
	struct sched_info *qinfo = ifp->if_qos;
	bool up = false;

	if (!qinfo)
		return;

	if (event == IF_FEAT_MODE_EVENT_L2_FAL_ENABLED) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			"Hw switching enabled for Interface %s\n",
			ifp->if_name);
		if (ifp->if_qos->dev_id == QOS_HW_ID)
			up = true;
	} else if (event == IF_FEAT_MODE_EVENT_L2_FAL_DISABLED) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			"Hw switching disabled for Interface %s\n",
			ifp->if_name);
		if (ifp->if_qos->dev_id == QOS_DPDK_ID)
			up = true;
	}

	if (up) {
		struct rte_eth_link link;

		rte_eth_link_get_nowait(ifp->if_port, &link);
		if (link.link_status && link.link_speed != ETH_SPEED_NUM_NONE)
			qos_sched_start(ifp, link.link_speed);
	} else {
		qos_sched_stop(ifp);
	}
}

static const struct dp_event_ops qos_events = {
	.if_link_change = qos_if_link_change,
	.if_delete = qos_if_delete,
	.if_feat_mode_change = qos_if_feat_mode_change,
	.if_index_set = qos_if_index_set,
	.if_index_unset = qos_if_index_unset,
	.if_mtu_change = qos_if_mtu_change,
};

DP_STARTUP_EVENT_REGISTER(qos_events);
