
/*-
 * Copyright (c) 2018-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_red.h>
#include <rte_sched.h>
#include "qos.h"
#include "json_writer.h"
#include "netinet6/ip6_funcs.h"
#include "npf/config/npf_config.h"
#include "npf_shim.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "ether.h"

/*
 * Return the DSCP wred resource group name associated with a map entry
 * in a queue index.
 */
static char *qos_get_dscp_grp(struct sched_info *qinfo, uint32_t qid, int i)
{
	struct qos_pipe_params *pp;
	struct qos_red_pipe_params *wred_params;
	int profile;

	profile = rte_sched_get_profile_for_pipe(qinfo->dev_info.dpdk.port,
						 qid);
	if (profile < 0)
		return NULL;

	pp = &qinfo->port_params.pipe_profiles[profile];
	wred_params = qos_red_find_q_params(pp, qid);
	if (wred_params)
		return wred_params->red_q_params.grp_names[i];

	return NULL;
}

void qos_dpdk_dscp_resgrp_json(struct sched_info *qinfo, uint32_t subport,
			       uint32_t pipe, uint32_t tc, uint32_t q,
			       uint64_t *random_dscp_drop, json_writer_t *wr)
{
	uint32_t qid;
	int i, num_maps;

	qid = qos_sched_calc_qindex(qinfo, subport, pipe, tc, q);

	num_maps = rte_red_queue_num_maps(qinfo->dev_info.dpdk.port, qid);
	if (num_maps) {
		char *grp_name;

		jsonw_name(wr, "wred_map");
		jsonw_start_array(wr);
		for (i = 0; i < num_maps; i++) {
			grp_name = qos_get_dscp_grp(qinfo, qid, i);
			if (grp_name == NULL)
				break;
			jsonw_start_object(wr);
			jsonw_string_field(wr, "res_grp", grp_name);
			jsonw_uint_field(wr, "random_dscp_drop",
					 random_dscp_drop[i]);
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
	}
}

int qos_dpdk_subport_read_stats(struct sched_info *qinfo,
				uint32_t subport,
				struct rte_sched_subport_stats64 *queue_stats)
{
	uint32_t over[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
	struct rte_sched_port *port = qinfo->dev_info.dpdk.port;
	struct rte_sched_subport_stats64 stats;
	int ret, i;

	rte_spinlock_lock(&qinfo->stats_lock);
	ret = rte_sched_subport_read_stats64(port, subport, &stats, over);
	if (ret == 0) {
		for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
			queue_stats->n_pkts_tc[i] += stats.n_pkts_tc[i];
			queue_stats->n_bytes_tc[i] += stats.n_bytes_tc[i];
			queue_stats->n_pkts_tc_dropped[i] +=
				stats.n_pkts_tc_dropped[i];
			queue_stats->n_pkts_red_dropped[i] +=
				stats.n_pkts_red_dropped[i];
		}
	}
	rte_spinlock_unlock(&qinfo->stats_lock);

	return ret;
}

int qos_dpdk_subport_clear_stats(struct sched_info *qinfo, uint32_t subport)
{
	struct subport_info *sinfo = qinfo->subport + subport;
	struct rte_sched_subport_stats64 *queue_stats = &sinfo->queue_stats;
	struct rte_sched_subport_stats64 *clear_stats = &sinfo->clear_stats;
	uint32_t tc;

	/*
	 * Read the DPDK's subport counters to clear them.
	 */
	if (qos_dpdk_subport_read_stats(qinfo, subport, queue_stats) < 0) {
		DP_DEBUG(QOS, DEBUG, DATAPLANE,
			 "Failed to read subport stats for subport: %u\n",
			 subport);
		return -1;
	}

	/*
	 * Copy the current queue_stats for each TC, into the clear_stats so
	 * that we can provide the difference between updated queue_stats and
	 * the clear_stats when we receive a "show stats" command.
	 */
	rte_spinlock_lock(&qinfo->stats_lock);
	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		clear_stats->n_pkts_tc[tc] = queue_stats->n_pkts_tc[tc];
		clear_stats->n_bytes_tc[tc] = queue_stats->n_bytes_tc[tc];
		clear_stats->n_pkts_tc_dropped[tc] =
			queue_stats->n_pkts_tc_dropped[tc];
		clear_stats->n_bytes_tc_dropped[tc] =
			queue_stats->n_bytes_tc_dropped[tc];
		clear_stats->n_pkts_red_dropped[tc] =
			queue_stats->n_pkts_red_dropped[tc];
	}
	rte_spinlock_unlock(&qinfo->stats_lock);
	return 0;
}

int qos_dpdk_queue_read_stats(struct sched_info *qinfo,
			      uint32_t subport, uint32_t pipe,
			      uint32_t tc, uint32_t q,
			      struct queue_stats *queue_stats,
			      uint64_t *qlen, bool *qlen_in_pkts)
{
	struct rte_sched_queue_stats64 stats;
	struct rte_sched_port *port = qinfo->dev_info.dpdk.port;
	uint32_t qid = qos_sched_calc_qindex(qinfo, subport, pipe, tc, q);
	uint16_t qlen_16;
	int ret, i;

	/*
	 * The DPDK always measures queue length in the number of packets.
	 */
	*qlen_in_pkts = true;
	rte_spinlock_lock(&qinfo->stats_lock);
	ret = rte_sched_queue_read_stats64(port, qid, &stats, &qlen_16);
	if (ret == 0) {
		queue_stats->n_pkts += stats.n_pkts;
		queue_stats->n_bytes += stats.n_bytes;
		queue_stats->n_pkts_dropped += stats.n_pkts_dropped;
		queue_stats->n_pkts_red_dropped += stats.n_pkts_red_dropped;
		for (i = 0; i < RTE_NUM_DSCP_MAPS; i++)
			queue_stats->n_pkts_red_dscp_dropped[i] +=
				stats.n_pkts_red_dscp_dropped[i];
		*qlen = qlen_16;
	}
	rte_spinlock_unlock(&qinfo->stats_lock);

	return ret;
}

int qos_dpdk_queue_clear_stats(struct sched_info *qinfo,
			       uint32_t subport, uint32_t pipe,
			       uint32_t tc, uint32_t q)
{
	uint32_t qid = qos_sched_calc_qindex(qinfo, subport, pipe, tc, q);
	struct queue_stats *queue_stats = qinfo->queue_stats + qid;
	bool qlen_in_pkts;
	uint64_t qlen;
	uint32_t i;
	int rv;

	rv = qos_dpdk_queue_read_stats(qinfo, subport, pipe, tc, q, queue_stats,
				       &qlen, &qlen_in_pkts);
	if (rv == 0) {
		/*
		 * Remember the value the dataplane's counters when they were
		 * cleared.
		 */
		rte_spinlock_lock(&qinfo->stats_lock);
		queue_stats->n_pkts_lc = queue_stats->n_pkts;
		queue_stats->n_bytes_lc = queue_stats->n_bytes;
		queue_stats->n_pkts_dropped_lc = queue_stats->n_pkts_dropped;
		queue_stats->n_pkts_red_dropped_lc =
			queue_stats->n_pkts_red_dropped;
		for (i = 0; i < RTE_NUM_DSCP_MAPS; i++)
			queue_stats->n_pkts_red_dscp_dropped_lc[i] =
				queue_stats->n_pkts_red_dscp_dropped[i];
		rte_spinlock_unlock(&qinfo->stats_lock);
	}
	return rv;
}

void qos_dpdk_free(struct sched_info *qinfo)
{
	if (qinfo->dev_info.dpdk.port)
		rte_sched_port_free(qinfo->dev_info.dpdk.port);
}

int qos_dpdk_port(struct ifnet *ifp,
		  unsigned int subports, unsigned int pipes,
		  unsigned int profiles, unsigned int overhead)
{
	unsigned int n_subports, n_pipes;

	n_subports = subports;
	subports = rte_align32pow2(subports);

	if (pipes == 0 || pipes > RTE_SCHED_PIPE_PROFILES_PER_PORT) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE, "bad pipes value: %u\n",
			 pipes);
		return -EINVAL;
	}
	n_pipes = pipes;
	pipes = rte_align32pow2(pipes);

	if (profiles == 0 || profiles > RTE_SCHED_PIPE_PROFILES_PER_PORT) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE, "bad profiles value: %u\n",
			 profiles);
		return -EINVAL;
	}

	/* Intel code has silent requirement that:
	 * queues_per_pipe * n_pipes_per_subport * n_subports % 512 == 0
	 * See RTE_BITMAP_CL_BIT_SIZE
	 */
	unsigned int queues = RTE_SCHED_QUEUES_PER_PIPE * subports * pipes;

	queues = RTE_ALIGN(queues, RTE_CACHE_LINE_SIZE * 8);
	pipes = queues / (RTE_SCHED_QUEUES_PER_PIPE * subports);

	DP_DEBUG(QOS_DP, DEBUG, DATAPLANE,
		 "Rounded to subports %u pipes %u profiles %u\n",
		 subports, pipes, profiles);

	/* Drop old config if any */
	struct sched_info *qinfo = ifp->if_qos;

	if (qinfo) {
		qos_subport_npf_free(qinfo);
		rcu_assign_pointer(ifp->if_qos, NULL);
		call_rcu(&qinfo->rcu, qos_sched_free_rcu);
	}

	qinfo = qos_sched_new(ifp, subports,
			      pipes, profiles, overhead);
	if (!qinfo) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE, "out of memory for qos\n");
		return -ENOMEM;
	}

	qinfo->n_subports = n_subports;
	qinfo->n_pipes = n_pipes;
	qinfo->dev_id = QOS_DPDK_ID;

	rcu_assign_pointer(ifp->if_qos, qinfo);
	return 0;
}

int qos_dpdk_disable(struct ifnet *ifp, struct sched_info *qinfo)
{
	qos_dpdk_stop(ifp, qinfo);
	rcu_assign_pointer(ifp->if_qos, NULL);

	qos_subport_npf_free(qinfo);
	call_rcu(&qinfo->rcu, qos_sched_free_rcu);

	return 0;
}

int qos_dpdk_enable(struct ifnet *ifp,
		    struct sched_info *qinfo)
{
	struct dp_ifnet_link_status link;

	if (!ifp->hw_forwarding) {
		/* If link is already up, then start now */
		dp_ifnet_link_status(ifp, &link);

		if (link.link_status &&
		    link.link_speed != ETH_SPEED_NUM_NONE &&
		    qos_sched_start(ifp, link.link_speed) < 0) {
			DP_DEBUG(QOS_DP, ERR, DATAPLANE, "Qos start failed\n");
			qinfo->enabled = false;
			return -ENODEV;
		} else {
			DP_DEBUG(QOS_DP, DEBUG, DATAPLANE,
				 "link status %s, speed %d, QoS not started\n",
				 link.link_status ? "up" : "down",
				 link.link_speed);
		}
	} else {
		DP_DEBUG(QOS_DP, DEBUG, DATAPLANE,
			 "interface not sw forwarding, QoS not started\n");
	}

	return 0;
}

/* Callback after all forwarding threads have cleared. */
static void qos_dpdk_port_free_rcu(void *arg)
{
	rte_sched_port_free(arg);
}

/* Return the total queue-array length for the subport.
 * If the subport doesn't have its TC queue-limits explicitly defined inherit
 * the port's queue-limits.
 */
static uint32_t qos_sched_subport_qsize(struct qos_port_params *pp,
					uint32_t *qsize)
{
	uint32_t queue_array_size = 0;
	uint32_t tc;

	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		if (qsize[tc] == 0)
			qsize[tc] = pp->qsize[tc];

		queue_array_size += qsize[tc];
	}

	return (queue_array_size * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS *
		pp->n_pipes_per_subport * sizeof(struct rte_mbuf *));
}

static void qos_copy_red_params(struct rte_red_params
						dpdk[][RTE_COLORS],
				struct subport_info *sinfo)
{
	int i, j;

	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++) {
		for (j = 0; j < RTE_COLORS; j++) {
			dpdk[i][j].min_th =
				(uint16_t)sinfo->red_params[i][j].min_th;
			dpdk[i][j].max_th =
				(uint16_t)sinfo->red_params[i][j].max_th;
			dpdk[i][j].maxp_inv =
				(uint16_t)sinfo->red_params[i][j].maxp_inv;
			dpdk[i][j].wq_log2 =
				(uint16_t)sinfo->red_params[i][j].wq_log2;
		}
	}
}

static int qos_dpdk_setup_params(struct ifnet *ifp, struct sched_info *qinfo,
				 struct rte_sched_port_params *dpdk_port_params)
{
	struct qos_port_params *qos_params = &qinfo->port_params;
	int socketid = rte_eth_dev_socket_id(ifp->if_port);
	unsigned int i, j;
	struct rte_sched_pipe_params *pipe_profiles;

	pipe_profiles = calloc(qos_params->n_pipe_profiles,
			       sizeof(*pipe_profiles));
	if (!pipe_profiles)
		return -1;

	dpdk_port_params->pipe_profiles = pipe_profiles;

	if (socketid < 0) /* SOCKET_ID_ANY */
		socketid = 0;

	dpdk_port_params->socket = socketid;
	dpdk_port_params->n_pipe_profiles = qos_params->n_pipe_profiles;
	dpdk_port_params->rate = qos_params->rate;
	dpdk_port_params->mtu = qos_params->mtu;
	dpdk_port_params->frame_overhead = qos_params->frame_overhead;
	dpdk_port_params->n_subports_per_port = qos_params->n_subports_per_port;
	dpdk_port_params->n_pipes_per_subport = qos_params->n_pipes_per_subport;
	for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
		dpdk_port_params->qsize[i] = qos_params->qsize[i];
	for (i = 0; i < qos_params->n_pipe_profiles; i++) {
		struct rte_sched_pipe_params *to = &pipe_profiles[i];
		struct qos_pipe_params *from =
				qos_params->pipe_profiles + i;
		struct qos_red_pipe_params *wred_params = NULL;

		to->tc_period = from->shaper.tc_period;
		to->tb_size = from->shaper.tb_size;
#ifdef RTE_SCHED_SUBPORT_TC_OV
		to->tc_tc_ov_weight = from->shaper.tc_ov_weight;
#endif
		to->tb_rate = from->shaper.tb_rate;
		for (j = 0; j < RTE_SCHED_QUEUES_PER_PIPE; j++)
			to->wrr_weights[j] = from->wrr_weights[j];
		for (j = 0; j < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; j++)
			to->tc_rate[j] = from->shaper.tc_rate[j];
		SLIST_FOREACH(wred_params, &from->red_head, list) {
			struct rte_red_pipe_params *qred_info;
			int err, k;

			qred_info = rte_red_alloc_q_params(to,
							wred_params->qindex);
			if (!qred_info)
				return -ENOMEM;
			for (k = 0; k < wred_params->red_q_params.num_maps;
			     k++) {
				struct qos_red_q_params *params;
				params = &wred_params->red_q_params;

				err = rte_red_init_q_params(
						&qred_info->red_q_params,
						params->qparams[k].max_th,
						params->qparams[k].min_th,
						params->qparams[k].maxp_inv,
						params->dscp_set[k],
						params->grp_names[k]);
				if (err < 0)
					return -ENOMEM;
				qred_info->red_q_params.qparams[k].wq_log2 =
					params->qparams[k].wq_log2;
			}
		}
	}
	return 0;
}

static void qos_dpdk_free_params(struct rte_sched_port_params *dpdk_port_params)
{
	unsigned int i;

	for (i = 0; i < dpdk_port_params->n_pipe_profiles; i++) {
		struct rte_sched_pipe_params *pp =
					dpdk_port_params->pipe_profiles + i;
		rte_red_free_q_params(pp, i);
	}
	free(dpdk_port_params->pipe_profiles);
}

/* Allocate and initialize a handle to QoS scheduler.
 * Only called by main thread.
 */
int qos_dpdk_start(struct ifnet *ifp, struct sched_info *qinfo,
		   uint64_t bps, uint16_t max_pkt_len)
{
	struct rte_sched_port *port, *old_port = NULL;
	unsigned int subport, pipe;
	int ret;
	uint32_t q_array_size;
	struct rte_sched_port_params dpdk_port_params = {0};
	const uint32_t max_burst_size = QOS_MAX_BURST_SIZE_DPDK;

	if (enable_transmit_thread(ifp->if_port) < 0) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE,
			 "Transmit thread setup failed on %s, portid %u\n",
			 ifp->if_name, ifp->if_port);
		qinfo->enabled = false;
		return -ENODEV;
	}

	ifp->qos_software_fwd = 1;

	/*
	 * Allow subports to inherit their queue sizes from the port, and
	 * calculate the total size of queue array this port will need.
	 */
	q_array_size = 0;
	for (subport = 0; subport < qinfo->n_subports; subport++) {
		struct subport_info *sinfo = &qinfo->subport[subport];

		q_array_size += qos_sched_subport_qsize(&qinfo->port_params,
							sinfo->qsize);

		/*
		 * Establish subport rates before checking pipes so that the
		 * pipes can be checked against their actual subport rates.
		 */
		qos_sched_subport_params_check(
			&sinfo->params, &sinfo->subport_rate,
			sinfo->sp_tc_rates.tc_rate, max_pkt_len,
			max_burst_size, bps);
	}

	qos_sched_pipe_check(qinfo, max_pkt_len, max_burst_size, bps);

	if (qos_dpdk_setup_params(ifp, qinfo, &dpdk_port_params)) {
		qos_dpdk_free_params(&dpdk_port_params);
		DP_DEBUG(QOS_DP, ERR, DATAPLANE,
			 "QoS DPDK config setup failed\n");
		goto out_disable_tx;
	}

	port = rte_sched_port_config_v2(&dpdk_port_params, q_array_size);
	if (port == NULL) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE,
			 "QoS config port failed\n");
		qos_dpdk_free_params(&dpdk_port_params);
		goto out_disable_tx;
	}

	for (subport = 0; subport < qinfo->n_subports; subport++) {
		struct subport_info *sinfo = &qinfo->subport[subport];
		struct qos_shaper_conf *qos_params = &sinfo->params;
		struct rte_sched_subport_params dpdk_params;
		uint16_t qsize[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE];
		struct rte_red_params
			dpdk_red_params[RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE]
				       [RTE_COLORS];
		int i;

		for (i = 0; i < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; i++)
			qsize[i] = (uint16_t)sinfo->qsize[i];

		assert(sizeof(dpdk_params) == sizeof(*qos_params));
		memcpy(&dpdk_params, qos_params, sizeof(*qos_params));
		qos_copy_red_params(dpdk_red_params, sinfo);

		ret = rte_sched_subport_config_v2(port, subport, &dpdk_params,
						  &qsize[0], dpdk_red_params);
		if (ret != 0) {
			DP_DEBUG(QOS_DP, ERR, DATAPLANE,
				 "Qos config subport %u failed: %d\n",
				 subport, ret);
			goto out_free_sched;
		}

		for (pipe = 0; pipe < qinfo->n_pipes; pipe++) {
			uint8_t profile = sinfo->profile_map[pipe];

			ret = rte_sched_pipe_config_v2(port, subport,
						       pipe, profile,
						       &dpdk_port_params);
			if  (ret != 0) {
				DP_DEBUG(QOS_DP, ERR, DATAPLANE,
					 "Qos config pipe subport %u pipe %u"
					 " profile %u failed: %d\n",
					 subport, pipe, profile, ret);
				goto out_free_sched;
			}
		}

		/* Update NPF rules */
		npf_cfg_commit_all();
	}

	/* Use RCU to set the pointer because changed by main thread
	 * but referenced by Tx thread
	 */
	DP_DEBUG(QOS_DP, DEBUG, DATAPLANE,  "QoS on port %s enabled\n",
		 ifp->if_name);
	old_port = qinfo->dev_info.dpdk.port;
	rcu_assign_pointer(qinfo->dev_info.dpdk.port, port);
	defer_rcu(qos_dpdk_port_free_rcu, old_port);
	qos_dpdk_free_params(&dpdk_port_params);
	return 0;

 out_free_sched:
	rte_sched_port_free(port);
	qos_dpdk_free_params(&dpdk_port_params);
 out_disable_tx:
	ifp->qos_software_fwd = 0;
	disable_transmit_thread(ifp->if_port);
	return -1;
}

int qos_dpdk_stop(struct ifnet *ifp, struct sched_info *qinfo)
{
	struct rte_sched_port *port = qinfo->dev_info.dpdk.port;

	if (port == NULL)
		return 0; /* qos not started */

	rcu_assign_pointer(qinfo->dev_info.dpdk.port, NULL);
	defer_rcu(qos_dpdk_port_free_rcu, port);

	ifp->qos_software_fwd = 0;
	disable_transmit_thread(ifp->if_port);

	return 0;
}

/* Classify packet for QoS
 * Fixed mapping based on:
 *    VLAN  => subport
 *    NPF match => pipe
 *    DSCP   => traffic class
 *    hash    => queue
 * Non IP traffic, default to best effort and no flow
 */
static
int qos_npf_classify(struct ifnet *ifp, const struct sched_info *qinfo,
		     struct rte_mbuf **m)
{
	uint16_t ether_type = ethtype(*m, RTE_ETHER_TYPE_VLAN);
	uint32_t subport, pipe = 0, q = DEFAULT_Q;
	npf_result_t result = { .decision = NPF_DECISION_PASS };

	uint16_t vlan = pktmbuf_get_txvlanid(*m);

	if (vlan) {
		struct ifnet *vlan_ifp;

		vlan_ifp = if_vlan_lookup(ifp, vlan);
		if (vlan_ifp)
			ifp = vlan_ifp;
	}

	subport = qinfo->vlan_map[vlan];
	struct subport_info *sinfo = &qinfo->subport[subport];

	/* Do stateless classification */
	const struct npf_config *npf_config =
				rcu_dereference(sinfo->npf_config);

	if (npf_active(npf_config, NPF_QOS)) {
		result = npf_hook_notrack(npf_get_ruleset(npf_config,
					  NPF_RS_QOS), m, ifp, PFIL_OUT, 0,
					  ether_type, NULL);
		if (result.tag_set)
			pipe = result.tag;
	}

	if (pipe >= qinfo->n_pipes) {
		DP_DEBUG(QOS_DP, ERR, DATAPLANE,
			 "NPF returned invalid tag %u, max-pipe:%u\n",
			 pipe, qinfo->n_pipes);
		return NPF_DECISION_BLOCK;
	}
	uint8_t profile = sinfo->profile_map[pipe];
	const struct queue_map *qmap = &qinfo->queue_map[profile];
	uint8_t pcp = pktmbuf_get_vlan_pcp(*m);
	uint8_t dscp = MAX_DSCP;

	/* Decide which queue to map to. Note that we only use the PCP map when
	 * the user hasn't configured a DSCP map but has configured a PCP map.
	 */
	if (vlan != 0 && !qmap->dscp_enabled && qmap->pcp_enabled) {
		q = qmap->pcp2q[pcp];
	} else {
		if (ether_type == htons(RTE_ETHER_TYPE_IPV4))
			dscp = ip_dscp_get(iphdr(*m));
		else if (ether_type == htons(RTE_ETHER_TYPE_IPV6))
			dscp = ip6_dscp_get(ip6hdr(*m));

		/*
		 * If DSCP was extracted we will either use the local high
		 * priority queue or a queue from the map.
		 * Otherwise, the default queue initialised above will be used.
		 */
		if (dscp < MAX_DSCP) {
			/*
			 * If this is a from-us packet with high enough
			 * priority, use the local priority queue if one
			 * is configured.
			 */
			if (qmap->local_priority &&
			    dscp >= (IPTOS_PREC_INTERNETCONTROL >> 2) &&
			    pktmbuf_mdata_exists(*m, PKT_MDATA_FROM_US))
				q = qmap->local_priority_queue;
			else
				q = qmap->dscp2q[dscp];
		}
	}

	rte_sched_port_pkt_write_v2(*m, subport, pipe,
				 qmap_to_tc(q), qmap_to_wrr(q),
				 RTE_COLOR_GREEN, dscp);
	return result.decision;
}

static int qos_classify(struct ifnet *ifp, struct sched_info *qinfo,
			struct rte_mbuf *enq_pkts[], uint32_t n_pkts)
{
	uint32_t i, j;

	/*
	 * Classify the packets to the Qos queues.
	 * NPF is run for classification to the pipe level
	 * so we need to check whether a packet has been
	 * dropped via policing and repack the array.
	 */
	for (i = j = 0; i < n_pkts; i++) {
		if (qos_npf_classify(ifp, qinfo,
				     &(enq_pkts[i])) == NPF_DECISION_BLOCK) {
			rte_pktmbuf_free(enq_pkts[i]);
			continue;
		}

		/*
		 * Ensure session is cleared from pkts.
		 */
		pktmbuf_mdata_clear(enq_pkts[i], PKT_MDATA_SESSION_SENTRY);
		if (i != j)
			enq_pkts[j] = enq_pkts[i];
		j++;
	}
	return j;
}

/* Put/get packets currently ready to send from DPDK */
int qos_sched(struct ifnet *ifp, struct sched_info *qinfo,
	      struct rte_mbuf *enq_pkts[], uint32_t n_pkts,
	      struct rte_mbuf *deq_pkts[], uint32_t space)
{
	struct rte_sched_port *port =
		rcu_dereference(qinfo->dev_info.dpdk.port);

	if (unlikely(port == NULL)) {
		/* qos not started, because link down or race */
		pktmbuf_free_bulk(enq_pkts, n_pkts);
		return 0;
	}

	if (n_pkts > 0) {
		n_pkts = qos_classify(ifp, qinfo, enq_pkts, n_pkts);

		/*
		 * In case we've dropped the packets whilst policing
		 */
		if (n_pkts)
			rte_sched_port_enqueue(port, enq_pkts, n_pkts);
	}

	/* Get what is available to send */
	if (space > 0)
		return rte_sched_port_dequeue(port, deq_pkts, space);
	else
		return 0;
}
