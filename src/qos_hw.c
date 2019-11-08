/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
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
#include "qos_obj_db.h"
#include "json_writer.h"
#include "netinet6/ip6_funcs.h"
#include "npf/config/npf_config.h"
#include "npf_shim.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "ether.h"
#include "fal.h"

_Static_assert(MAX_DSCP == FAL_QOS_MAP_DSCP_VALUES, "max DSCP value mismatch");
_Static_assert(MAX_PCP == FAL_QOS_MAP_PCP_VALUES, "max PCP value mismatch");

static fal_object_t
qos_hw_get_map(uint32_t port_obj_id, uint32_t subport_id,
	       uint32_t pipe_id, enum qos_obj_hw_type hw_type)
{
	fal_object_t map = FAL_QOS_NULL_OBJECT_ID;
	uint32_t ids[QOS_OBJ_DB_ID_ARRAY_LEN] = {
		0, port_obj_id, subport_id, pipe_id
	};
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status db_ret;
	int32_t hw_status;

	db_ret = qos_obj_db_retrieve(QOS_OBJ_DB_LEVEL_PIPE, ids, &db_obj);
	if (!db_ret)
		qos_obj_db_hw_get(db_obj, hw_type, &hw_status, &map);
	return map;
}

fal_object_t
qos_hw_get_ingress_map(uint32_t port_obj_id, uint32_t subport_id,
		       uint32_t pipe_id)
{
	return qos_hw_get_map(port_obj_id, subport_id, pipe_id,
			      QOS_OBJ_HW_TYPE_INGRESS_MAP);
}

fal_object_t
qos_hw_get_egress_map(uint32_t port_obj_id, uint32_t subport_id,
		       uint32_t pipe_id)
{
	return qos_hw_get_map(port_obj_id, subport_id, pipe_id,
			      QOS_OBJ_HW_TYPE_EGRESS_MAP);
}

static fal_object_t
qos_hw_get_queue(uint32_t port_obj_id, uint32_t subport_id, uint32_t pipe_id,
		 uint32_t tc_id, int32_t queue_id)
{
	fal_object_t queue_obj = FAL_QOS_NULL_OBJECT_ID;
	uint32_t ids[QOS_OBJ_DB_ID_ARRAY_LEN] = {
		0, port_obj_id, subport_id, pipe_id, tc_id, queue_id
	};
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status db_ret;
	int32_t hw_status;

	db_ret = qos_obj_db_retrieve(QOS_OBJ_DB_LEVEL_QUEUE, ids, &db_obj);
	if (!db_ret) {
		qos_obj_db_hw_get(db_obj, QOS_OBJ_HW_TYPE_QUEUE, &hw_status,
				  &queue_obj);
	}
	return queue_obj;
}

fal_object_t
qos_hw_get_subport_sg(uint32_t port_obj_id, uint32_t subport_id)
{
	fal_object_t sg_obj = FAL_QOS_NULL_OBJECT_ID;
	uint32_t ids[QOS_OBJ_DB_ID_ARRAY_LEN] = {
		0, port_obj_id, subport_id
	};
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status db_ret;
	int32_t hw_status;

	db_ret = qos_obj_db_retrieve(QOS_OBJ_DB_LEVEL_SUBPORT, ids, &db_obj);
	if (!db_ret)
		qos_obj_db_hw_get(db_obj, QOS_OBJ_HW_TYPE_SCHED_GROUP,
				  &hw_status, &sg_obj);
	return sg_obj;
}

static fal_object_t
qos_hw_get_wred(uint32_t port_obj_id, uint32_t subport_id, uint32_t pipe_id,
		uint32_t tc_id, int32_t queue_id)
{
	fal_object_t wred_obj = FAL_QOS_NULL_OBJECT_ID;
	uint32_t ids[QOS_OBJ_DB_ID_ARRAY_LEN] = {
		0, port_obj_id, subport_id, pipe_id, tc_id, queue_id
	};
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status db_ret;
	int32_t hw_status;

	db_ret = qos_obj_db_retrieve(QOS_OBJ_DB_LEVEL_QUEUE, ids, &db_obj);
	if (!db_ret) {
		qos_obj_db_hw_get(db_obj, QOS_OBJ_HW_TYPE_WRED, &hw_status,
				  &wred_obj);
	}
	return wred_obj;
}

void qos_hw_dscp_resgrp_json(struct sched_info *qinfo, uint32_t subport,
			     uint32_t pipe, uint32_t tc, uint32_t q,
			     uint64_t *random_dscp_drop, json_writer_t *wr)
{
	int i, num_maps;

	struct subport_info *sinfo = qinfo->subport + subport;
	uint8_t profile_id = sinfo->profile_map[pipe];
	struct profile_wred_info *p_wred_info =
		&qinfo->wred_profiles[profile_id];
	uint8_t qindex = (tc * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS) + q;
	struct queue_wred_info *q_wred_info = &p_wred_info->queue_wred[qindex];

	num_maps = q_wred_info->num_maps;
	if (num_maps) {
		char *grp_name;

		jsonw_name(wr, "wred_map");
		jsonw_start_array(wr);
		for (i = 0; i < num_maps; i++) {
			grp_name = q_wred_info->dscp_grp_names[i];
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

/*
 * The order of the counter-ids in this array defines the order of the
 * returned counter values in the results array returned by the fal call:
 * fal_qos_get_queue_stats
 */
static uint32_t qos_subport_hw_counter_ids[] = {
	FAL_QOS_QUEUE_STAT_PACKETS,
	FAL_QOS_QUEUE_STAT_DROPPED_PACKETS,
	FAL_QOS_QUEUE_STAT_BYTES,
	FAL_QOS_QUEUE_STAT_DROPPED_BYTES
};

static int
qos_hw_process_queue_stats(struct sched_info *qinfo, uint32_t subport,
			   uint32_t pipe, uint32_t tc, uint32_t q,
			   struct rte_sched_subport_stats64 *subport_stats)
{
	fal_object_t queue_id;
	fal_object_t wred_id;
	uint32_t port_obj_id;
	uint64_t values[5];
	uint32_t qid;
	int ret = 0;

	port_obj_id = qinfo->dev_info.fal.hw_port_id;

	queue_id = qos_hw_get_queue(port_obj_id, subport, pipe, tc, q);

	if (queue_id == FAL_QOS_NULL_OBJECT_ID)
		/*
		 * We only create queue objects that have DSCP values assigned
		 * to them and queue objects disappear temporarily during
		 * link-flaps.
		 */
		return 0;

	wred_id = qos_hw_get_wred(port_obj_id, subport, pipe, tc, q);
	/*
	 * The order of the counters returned by fal_qos_get_queue_stats_ext is
	 * defined by the order of counter-ids in qos_subport_hw_counter_ids
	 */
	ret = fal_qos_get_queue_stats_ext(queue_id,
				      ARRAY_SIZE(qos_subport_hw_counter_ids),
				      qos_subport_hw_counter_ids, true, values);
	if (!ret) {
		struct queue_stats *queue_stats;

		/*
		 * Get the platform-agnostic queue counters block for the queue
		 * in question.
		 */
		qid = qos_sched_calc_qindex(qinfo, subport, pipe, tc, q);
		queue_stats = qinfo->queue_stats + qid;

		/*
		 * Every time we read the FAL's queue counters, we just get
		 * given the differences between the current read and the
		 * previous one.  So whenever we read them, we must update the
		 * platform agnostic queue counters.
		 */
		queue_stats->n_pkts += values[0];
		queue_stats->n_pkts_dropped += values[1];
		queue_stats->n_bytes += values[2];
		queue_stats->n_bytes_dropped += values[3];
		/*
		 * 'red' isn't a packet-colour here, it means 'wred'.
		 * Some platforms do not count tail-drops and wred-drops
		 * separately, when WRED is configured they are wred-drops.
		 */
		if (wred_id != FAL_QOS_NULL_OBJECT_ID)
			queue_stats->n_pkts_red_dropped += values[1];

		/*
		 * Now we have updated the platform agnostic queue counters,
		 * accumulate the subport's TC counters.  We must allow for
		 * the queue counters having been cleared at some point in the
		 * past.
		 */
		subport_stats->n_pkts_tc[tc] +=
			(queue_stats->n_pkts - queue_stats->n_pkts_lc);
		subport_stats->n_pkts_tc_dropped[tc] +=
			(queue_stats->n_pkts_dropped -
			 queue_stats->n_pkts_dropped_lc);
		subport_stats->n_bytes_tc[tc] +=
			(queue_stats->n_bytes - queue_stats->n_bytes_lc);
		subport_stats->n_bytes_tc_dropped[tc] +=
			(queue_stats->n_bytes_dropped -
			 queue_stats->n_bytes_dropped_lc);
		if (wred_id != FAL_QOS_NULL_OBJECT_ID)
			subport_stats->n_pkts_red_dropped[tc] +=
				(queue_stats->n_pkts_red_dropped -
				 queue_stats->n_pkts_red_dropped_lc);
	}
	return ret;
}

int qos_hw_subport_read_stats(struct sched_info *qinfo, uint32_t subport,
			      struct rte_sched_subport_stats64 *stats)
{
	struct rte_sched_subport_stats64 local_stats;
	int ret = 0;
	uint32_t pipe;
	uint32_t tc;
	uint32_t q;

	/*
	 * If we have a qinfo, but no hw_port_sched_group, the link must have
	 * gone down, so we won't be able to read the queue counters.
	 */
	if (qinfo->dev_info.fal.hw_port_sched_group == FAL_QOS_NULL_OBJECT_ID)
		return 0;

	/*
	 * Zero the local counters before we start accumulating in them.
	 */
	memset(&local_stats, 0, sizeof(local_stats));

	for (pipe = 0; pipe <= qinfo->n_pipes; pipe++) {
		for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
			for (q = 0;
			     !ret && q < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
			     q++) {
				ret = qos_hw_process_queue_stats(qinfo, subport,
								 pipe, tc, q,
								 &local_stats);
			}
		}
	}
	if (!ret) {
		/*
		 * Copy the accumulated values back into the dataplane's stats.
		 */
		rte_spinlock_lock(&qinfo->stats_lock);
		memcpy(stats, &local_stats, sizeof(local_stats));
		rte_spinlock_unlock(&qinfo->stats_lock);
	}

	return 0;
}

int qos_hw_subport_clear_stats(struct sched_info *qinfo __unused,
			       uint32_t subport __unused)
{
	/*
	 * For the hardware-platforms we synthesize the subport
	 * counters from the queue counters, so we have nothing to do
	 * here.
	 */
	return 0;
}

/*
 * The order of the counter-ids in this array defines the order of the
 * returned counter values in the results array returned by the fal call:
 * fal_qos_get_queue_stats_ext
 */
static uint32_t qos_queue_hw_counter_ids[] = {
	FAL_QOS_QUEUE_STAT_PACKETS,
	FAL_QOS_QUEUE_STAT_DROPPED_PACKETS,
	FAL_QOS_QUEUE_STAT_BYTES,
	FAL_QOS_QUEUE_STAT_DROPPED_BYTES,
	FAL_QOS_QUEUE_STAT_GREEN_DROPPED_PACKETS,
	FAL_QOS_QUEUE_STAT_YELLOW_DROPPED_PACKETS,
	FAL_QOS_QUEUE_STAT_RED_DROPPED_PACKETS
};

static uint32_t qos_queue_length_counter_ids[] = {
	FAL_QOS_QUEUE_STAT_CURR_OCCUPANCY_BYTES
};

int qos_hw_queue_read_stats(struct sched_info *qinfo, uint32_t subport,
			    uint32_t pipe, uint32_t tc, uint32_t q,
			    struct queue_stats *stats,
			    uint64_t *qlen, bool *qlen_in_pkts)
{
	int ret = -1;
	uint64_t values[9] = { 0 };
	uint32_t port_obj_id;
	fal_object_t queue_id;

	/*
	 * Currently all the hardware platforms that support QoS return
	 * queue-length in bytes.
	 */
	*qlen_in_pkts = false;

	port_obj_id = qinfo->dev_info.fal.hw_port_id;
	queue_id = qos_hw_get_queue(port_obj_id, subport, pipe, tc, q);
	if (queue_id == FAL_QOS_NULL_OBJECT_ID) {
		/*
		 * We only populate the FAL with queues that are being used.
		 * The queues also disappears when a link flaps.
		 * In both cases don't update the stats, just return success.
		 */
		*qlen = 0;
		ret = 0;
	} else {
		/*
		 * Find out if this queue has WRED configured and if so
		 * how many colours are configured.
		 */
		fal_object_t wred_id;
		uint32_t counter_ids = 4;

		wred_id = qos_hw_get_wred(port_obj_id, subport, pipe, tc, q);
		if (wred_id != FAL_QOS_NULL_OBJECT_ID) {
			struct fal_attribute_t attr_list[] = {
				{ .id = FAL_QOS_WRED_ATTR_GREEN_ENABLE,
				  .value.booldata = 0 },
				{ .id = FAL_QOS_WRED_ATTR_YELLOW_ENABLE,
				  .value.booldata = 0 },
				{ .id = FAL_QOS_WRED_ATTR_RED_ENABLE,
				  .value.booldata = 0 },
			};

			ret = fal_qos_get_wred_attrs(wred_id,
						     ARRAY_SIZE(attr_list),
						     attr_list);
			if (ret) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "FAL failed to get wred attributes, "
					 "status: %d\n",
					 ret);
			} else {
				/*
				 * Increase the number of counter-ids if
				 * coloured WRED is configured
				 */
				counter_ids += attr_list[0].value.booldata;
				counter_ids += attr_list[1].value.booldata;
				counter_ids += attr_list[2].value.booldata;
			}

		}
		ret = fal_qos_get_queue_stats_ext(queue_id, counter_ids,
						  qos_queue_hw_counter_ids,
						  true, values);
		if (!ret) {
			rte_spinlock_lock(&qinfo->stats_lock);

			stats->n_pkts += values[0];
			stats->n_pkts_dropped += values[1];
			stats->n_bytes += values[2];
			stats->n_bytes_dropped += values[3];
			/*
			 * 'red' isn't a packet-colour, but means 'wred'
			 * Some platforms do not count tail-drops and
			 * wred-drops separately, when WRED is configured
			 * they are wred-drops.
			 */
			if (counter_ids > 4)
				stats->n_pkts_red_dropped += values[1];

			/*
			 * Get the coloured WRED drop counts
			 */
			stats->n_pkts_red_dscp_dropped[0] += values[4];
			stats->n_pkts_red_dscp_dropped[1] += values[5];
			stats->n_pkts_red_dscp_dropped[2] += values[6];
			rte_spinlock_unlock(&qinfo->stats_lock);
		} else if (ret == -EOPNOTSUPP) {
			ret = fal_qos_get_queue_stats(queue_id, counter_ids,
						      qos_queue_hw_counter_ids,
						      values);
			if (!ret) {
				rte_spinlock_lock(&qinfo->stats_lock);

				stats->n_pkts = values[0];
				stats->n_pkts_dropped = values[1];
				stats->n_bytes = values[2];
				stats->n_bytes_dropped = values[3];

				/*
				 * 'red' isn't a packet-colour, but means 'wred'
				 * Some platforms do not count tail-drops
				 * and wred-drops separately, when WRED is
				 * configured they are wred-drops.
				 */
				if (counter_ids > 4)
					stats->n_pkts_red_dropped = values[1];

				/*
				 * Get the coloured WRED drop counts
				 */
				stats->n_pkts_red_dscp_dropped[0] = values[4];
				stats->n_pkts_red_dscp_dropped[1] = values[5];
				stats->n_pkts_red_dscp_dropped[2] = values[6];
				rte_spinlock_unlock(&qinfo->stats_lock);
			}
		}

		/*
		 * Finally try to get the current queue length.  This call
		 * will have to remain separate from the other get-queue-stats
		 * calls as an incremental version of the queue length doesn't
		 * make a lot of sense.
		 */
		ret = fal_qos_get_queue_stats(queue_id, 1,
					      qos_queue_length_counter_ids,
					      values);
		if (ret) {
			*qlen = 0;
			ret = 0;
		} else {
			*qlen = values[0];
		}
	}

	return ret;
}

int qos_hw_queue_clear_stats(struct sched_info *qinfo, uint32_t subport,
			    uint32_t pipe, uint32_t tc, uint32_t q)
{
	uint32_t qid = qos_sched_calc_qindex(qinfo, subport, pipe, tc, q);
	struct queue_stats *queue_stats = qinfo->queue_stats + qid;
	bool qlen_in_pkts;
	uint64_t qlen;
	uint32_t i;
	int rv;

	rv = qos_hw_queue_read_stats(qinfo, subport, pipe, tc, q, queue_stats,
				     &qlen, &qlen_in_pkts);
	if (!rv) {
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

void qos_hw_free(__unused struct sched_info *qinfo)
{
	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "%s\n", __func__);
}

int qos_hw_port(struct ifnet *ifp, unsigned int subports, unsigned int pipes,
		unsigned int profiles, unsigned int overhead)
{
	int retval = 0;

	/*
	 * No hardware support
	 */
	if (!ifp->hw_forwarding)
		return -ENODEV;

	/* Drop old config if any */
	struct sched_info *qinfo = ifp->if_qos;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "hardware port, if-index: %u\n",
		 ifp->if_index);

	if (qinfo)
		qos_subport_npf_free(qinfo);

	qinfo = qos_sched_new(ifp, subports, pipes, profiles, overhead);
	if (!qinfo) {
		ifp->if_qos = NULL;
		DP_DEBUG(QOS_HW, ERR, DATAPLANE, "out of memory for qos\n");
		return -1;
	}

	qinfo->n_subports = subports;
	qinfo->n_pipes = pipes;

	qinfo->dev_id = QOS_HW_ID;
	ifp->if_qos = qinfo;
	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE,
		 "ifp %s hardware forwarding enabled\n", ifp->if_name);

	/*retval = fal_tastic();*/
	if (retval) {
		ifp->if_qos = NULL;
		qos_subport_npf_free(qinfo);
		qos_sched_free(qinfo);
	}

	/*
	 * No hardware support
	 */
	return retval;
}

int qos_hw_disable(struct ifnet *ifp, struct sched_info *qinfo)
{
	int ret;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "hardware disable, if-index: %u\n",
		 ifp->if_index);

	assert(qinfo == ifp->if_qos);

	ret = qos_hw_stop(ifp, qinfo);

	rcu_assign_pointer(ifp->if_qos, NULL);
	qos_subport_npf_free(qinfo);
	call_rcu(&qinfo->rcu, qos_sched_free_rcu);

	return ret;
}

int qos_hw_enable(struct ifnet *ifp, struct sched_info *qinfo)
{
	struct rte_eth_link link;
	int ret = 0;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "hardware enable, if-index: %u\n",
		 ifp->if_index);

	rte_eth_link_get_nowait(ifp->if_port, &link);
	if (link.link_status) {
		ret = qos_sched_start(ifp, link.link_speed);
		if (ret != 0)
			qinfo->enabled = false;
	}

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "hardware enable - done ret %d\n",
		 ret);

	return ret;
}

int qos_hw_stop(struct ifnet *ifp, struct sched_info *qinfo)
{
	uint32_t ids[QOS_OBJ_DB_ID_ARRAY_LEN] = { 0 };
	char ids_str[QOS_OBJ_DB_MAX_ID_LEN + 1];
	enum qos_obj_db_status db_ret;
	char *out_str;

	ids[QOS_OBJ_DB_LEVEL_PORT] = ifp->if_index;
	out_str = qos_obj_db_get_ids_string(QOS_OBJ_DB_LEVEL_PORT, ids,
					    QOS_OBJ_DB_MAX_ID_LEN,
					    ids_str);

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "hardware stop, id: %s\n",
		 out_str);

	if (qinfo->dev_info.fal.hw_port_id) {
		/*
		 * Delete all objects for this port in the QoS object database
		 */
		db_ret = qos_obj_db_delete(QOS_OBJ_DB_LEVEL_PORT, ids);
		if (db_ret) {
			DP_DEBUG(QOS_HW, ERR, DATAPLANE,
				 "failed to delete QoS object from object "
				 "database, id: %s, status: %d\n",
				 out_str, db_ret);
			return -1;
		}

		/*
		 * The link has gone down, clear the port's sched_group id.
		 */
		qinfo->dev_info.fal.hw_port_sched_group =
			FAL_QOS_NULL_OBJECT_ID;
	}
	return 0;
}

static int
qos_hw_update_sched_group(fal_object_t sched_group_obj, uint32_t attr_id,
			  fal_object_t object_id)
{
	int ret;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE,
		 "updating sched-group with attr: %u, obj: %lx\n",
		 attr_id, object_id);

	if (sched_group_obj == FAL_QOS_NULL_OBJECT_ID ||
	    (attr_id != FAL_QOS_SCHED_GROUP_ATTR_SCHEDULER_ID &&
	     attr_id != FAL_QOS_SCHED_GROUP_ATTR_INGRESS_MAP_ID &&
	     attr_id != FAL_QOS_SCHED_GROUP_ATTR_EGRESS_MAP_ID &&
	     attr_id != FAL_QOS_SCHED_GROUP_ATTR_PARENT_ID))
		return -EINVAL;

	struct fal_attribute_t attr = {
		.id = attr_id, .value.objid = object_id
	};

	ret = fal_qos_upd_sched_group(sched_group_obj, &attr);
	if (ret)
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "FAL failed to update sched-group with attr: %u, "
			 "status: %d\n", attr_id, ret);

	return ret;
}

static int
qos_hw_update_queue(fal_object_t queue_obj, uint32_t attr_id,
		    fal_object_t object_id)
{
	int ret;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE,
		 "updating queue with attr: %u, obj: %lx\n",
		 attr_id, object_id);

	if (queue_obj == FAL_QOS_NULL_OBJECT_ID ||
	    (attr_id != FAL_QOS_QUEUE_ATTR_SCHEDULER_ID &&
	     attr_id != FAL_QOS_QUEUE_ATTR_PARENT_ID &&
	     attr_id != FAL_QOS_QUEUE_ATTR_WRED_ID))
		return -EINVAL;

	struct fal_attribute_t attr = {
		.id = attr_id, .value.objid = object_id
	};

	ret = fal_qos_upd_queue(queue_obj, &attr);
	if (ret)
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "FAL failed to update queue with attr: %u, "
			 "status: %d\n", attr_id, ret);

	return ret;
}

/*
 * Create a combination of a scheduler-group and scheduler.
 * The scheduler-group is the child of a parent object (either a port
 * or a higher level scheduler-group [with a lower level number]).
 * Return the object-id of the child scheduler-group, which will become
 * the parent to its own child objects, either lower level scheduler-groups
 * or queues.
 */
static int
qos_hw_create_group_and_sched(struct qos_obj_db_obj *db_obj,
			      uint32_t sched_group_id, fal_object_t parent_obj,
			      uint8_t level, uint16_t max_children,
			      uint8_t sched_type, uint64_t bandwidth,
			      uint64_t burst, int8_t overhead,
			      fal_object_t *child_obj, uint16_t vlan)
{
	fal_object_t sch_obj;
	fal_object_t grp_obj = FAL_QOS_NULL_OBJECT_ID;
	uint32_t attr_count;
	uint32_t switch_id = 0;
	int ret;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE,
		 "creating sched-group and scheduler\n");

	*child_obj = FAL_QOS_NULL_OBJECT_ID;

	struct fal_attribute_t sch_attr_list[] = {
		{ .id = FAL_QOS_SCHEDULER_ATTR_SCHEDULING_TYPE,
		  .value.u8 = sched_type },
		{ .id = FAL_QOS_SCHEDULER_ATTR_METER_TYPE,
		  .value.u8 = FAL_QOS_METER_TYPE_BYTES },
		{ .id = FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE,
		  .value.u64 = bandwidth },
		{ .id = FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE,
		  .value.u64 = burst },
		{ .id = FAL_QOS_SCHEDULER_ATTR_FRAME_OVERHEAD,
		  .value.i8 = overhead },
	};

	ret = fal_qos_new_scheduler(switch_id, ARRAY_SIZE(sch_attr_list),
				    sch_attr_list, &sch_obj);

	qos_obj_db_hw_set(db_obj, QOS_OBJ_HW_TYPE_SCHEDULER, ret, sch_obj);

	if (ret) {
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "FAL failed to create scheduler object, status: %d\n",
			 ret);
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_FAILED);
		return ret;
	}

	struct fal_attribute_t grp_attr_list[6] = {
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_SG_INDEX,
		  .value.u32 = sched_group_id },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_LEVEL,
		  .value.u8 = level },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_SCHEDULER_ID,
		  .value.objid = sch_obj },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_MAX_CHILDREN,
		  .value.u16 = max_children },
	};

	attr_count = 4;

	if (level == FAL_QOS_SCHED_GROUP_LEVEL_SUBPORT && vlan) {
		grp_attr_list[attr_count].id = FAL_QOS_SCHED_GROUP_ATTR_VLAN_ID;
		grp_attr_list[attr_count].value.u16 = vlan;
		attr_count++;
	}

	/*
	 * If this is at the top level, the port is our parent, and we don't
	 * need the FAL_QOS_SCHED_GROUP_ATTR_PARENT_ID attribute.
	 */
	if (level != FAL_QOS_SCHED_GROUP_LEVEL_PORT) {
		grp_attr_list[attr_count].id =
			FAL_QOS_SCHED_GROUP_ATTR_PARENT_ID;
		grp_attr_list[attr_count].value.objid =
			(fal_object_t) parent_obj;
		attr_count++;
	}

	ret = fal_qos_new_sched_group(switch_id, attr_count, grp_attr_list,
				      &grp_obj);

	qos_obj_db_hw_set(db_obj, QOS_OBJ_HW_TYPE_SCHED_GROUP, ret, grp_obj);

	if (ret)
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "FAL failed to create sched-group object, status: "
			 "%d\n", ret);
	else
		*child_obj = grp_obj;

	return ret;
}

static void
qos_hw_delete_callback(struct qos_obj_db_obj *db_obj)
{
	fal_object_t sched_group_obj;
	fal_object_t scheduler_obj;
	fal_object_t queue_obj;
	fal_object_t wred_obj;
	fal_object_t ingress_map_obj;
	fal_object_t egress_map_obj;
	int32_t hw_status;

	assert(db_obj != NULL);

	qos_obj_db_hw_get(db_obj, QOS_OBJ_HW_TYPE_SCHED_GROUP, &hw_status,
			  &sched_group_obj);

	qos_obj_db_hw_get(db_obj, QOS_OBJ_HW_TYPE_SCHEDULER, &hw_status,
			  &scheduler_obj);

	qos_obj_db_hw_get(db_obj, QOS_OBJ_HW_TYPE_INGRESS_MAP, &hw_status,
			  &ingress_map_obj);

	qos_obj_db_hw_get(db_obj, QOS_OBJ_HW_TYPE_EGRESS_MAP, &hw_status,
			  &egress_map_obj);

	qos_obj_db_hw_get(db_obj, QOS_OBJ_HW_TYPE_QUEUE, &hw_status,
			  &queue_obj);

	qos_obj_db_hw_get(db_obj, QOS_OBJ_HW_TYPE_WRED, &hw_status,
			  &wred_obj);

	if (sched_group_obj && scheduler_obj)
		(void)qos_hw_update_sched_group(sched_group_obj,
					FAL_QOS_SCHED_GROUP_ATTR_SCHEDULER_ID,
					FAL_QOS_NULL_OBJECT_ID);

	if (sched_group_obj && ingress_map_obj)
		(void)qos_hw_update_sched_group(sched_group_obj,
					FAL_QOS_SCHED_GROUP_ATTR_INGRESS_MAP_ID,
					FAL_QOS_NULL_OBJECT_ID);

	if (sched_group_obj && egress_map_obj)
		(void)qos_hw_update_sched_group(sched_group_obj,
					FAL_QOS_SCHED_GROUP_ATTR_EGRESS_MAP_ID,
					FAL_QOS_NULL_OBJECT_ID);

	if (queue_obj && scheduler_obj)
		(void)qos_hw_update_queue(queue_obj,
					  FAL_QOS_QUEUE_ATTR_SCHEDULER_ID,
					  FAL_QOS_NULL_OBJECT_ID);

	if (queue_obj && wred_obj)
		(void)qos_hw_update_queue(queue_obj,
					  FAL_QOS_QUEUE_ATTR_WRED_ID,
					  FAL_QOS_NULL_OBJECT_ID);

	if (queue_obj)
		(void)qos_hw_update_queue(queue_obj,
					  FAL_QOS_QUEUE_ATTR_PARENT_ID,
					  FAL_QOS_NULL_OBJECT_ID);

	if (sched_group_obj) {
		(void)qos_hw_update_sched_group(sched_group_obj,
					FAL_QOS_SCHED_GROUP_ATTR_PARENT_ID,
					FAL_QOS_NULL_OBJECT_ID);
		(void)fal_qos_del_sched_group(sched_group_obj);
	}

	if (scheduler_obj)
		(void)fal_qos_del_scheduler(scheduler_obj);

	if (ingress_map_obj)
		(void)fal_qos_del_map(ingress_map_obj);

	if (egress_map_obj)
		(void)fal_qos_del_map(egress_map_obj);

	if (queue_obj)
		(void)fal_qos_del_queue(queue_obj);

	if (wred_obj)
		(void)fal_qos_del_wred(wred_obj);
}

static void
qos_hw_upd_bool_attr(struct fal_attribute_t *attr_list, uint32_t array_size,
		    uint32_t attr_id, bool value)
{
	uint32_t index = 0;

	while (index < array_size) {
		if (attr_list[index].id == attr_id) {
			attr_list[index].value.booldata = value;
			return;
		}
		index++;
	}
}

static void
qos_hw_upd_u32_attr(struct fal_attribute_t *attr_list, uint32_t array_size,
		    uint32_t attr_id, uint32_t value)
{
	uint32_t index = 0;

	while (index < array_size) {
		if (attr_list[index].id == attr_id) {
			attr_list[index].value.u32 = value;
			return;
		}
		index++;
	}
}

static int
qos_hw_create_wred(struct qos_obj_db_obj *db_obj,
		   struct rte_red_params *wred_params,
		   struct queue_wred_info *q_wred_info, fal_object_t *wred_obj)
{
	uint32_t switch_id = 0;
	int ret = 0;

	/*
	 * We can get WRED configurations from two different places.  Either
	 * from the "... traffic-class <0..3> random-detect ..." command or
	 * the "... queue <0..31> wred-map dscp-group ..." command, but the
	 * QoS perl validation scripts should mean that we never have both.
	 */
	if ((wred_params->min_th != 0 && wred_params->max_th != 0) &&
	    (q_wred_info != NULL && q_wred_info->num_maps != 0)) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "Conflicting WRED configurations\n");
		return -EINVAL;
	}

	/*
	 * The queue can have an optional wred object associated with it.
	 * Create the wred object if wred has been configured.
	 * When wred is configured both min_th and max_th are non-zero.
	 */
	if (wred_params->min_th != 0 && wred_params->max_th != 0) {
		struct fal_attribute_t wred_attr_list[] = {
			{ .id = FAL_QOS_WRED_ATTR_GREEN_ENABLE,
			  .value.u8 = true },
			{ .id = FAL_QOS_WRED_ATTR_GREEN_MIN_THRESHOLD,
			  .value.u32 = wred_params->min_th },
			{ .id = FAL_QOS_WRED_ATTR_GREEN_MAX_THRESHOLD,
			  .value.u32 = wred_params->max_th },
			{ .id = FAL_QOS_WRED_ATTR_GREEN_DROP_PROBABILITY,
			  .value.u32 = wred_params->maxp_inv },
			{ .id = FAL_QOS_WRED_ATTR_WEIGHT,
			  .value.u8 = wred_params->wq_log2 },
		};

		DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "creating wred\n");

		ret = fal_qos_new_wred(switch_id, ARRAY_SIZE(wred_attr_list),
				       wred_attr_list, wred_obj);

	} else if (q_wred_info != NULL && q_wred_info->num_maps != 0) {
		uint8_t colour;

		/*
		 * The wred-map QoS CLI does allow us to make use of
		 * packet colours by allowing up to three different
		 * wred configurations on the same queue.
		 */
		struct fal_attribute_t wred_attr_list[] = {
			{ .id = FAL_QOS_WRED_ATTR_WEIGHT,
			  .value.u8 = q_wred_info->filter_weight },
			{ .id = FAL_QOS_WRED_ATTR_GREEN_ENABLE,
			  .value.booldata = false },
			{ .id = FAL_QOS_WRED_ATTR_GREEN_MIN_THRESHOLD,
			  .value.u32 = 0 },
			{ .id = FAL_QOS_WRED_ATTR_GREEN_MAX_THRESHOLD,
			  .value.u32 = 0 },
			{ .id = FAL_QOS_WRED_ATTR_GREEN_DROP_PROBABILITY,
			  .value.u32 = 0 },
			{ .id = FAL_QOS_WRED_ATTR_YELLOW_ENABLE,
			  .value.booldata = false },
			{ .id = FAL_QOS_WRED_ATTR_YELLOW_MIN_THRESHOLD,
			  .value.u32 = 0 },
			{ .id = FAL_QOS_WRED_ATTR_YELLOW_MAX_THRESHOLD,
			  .value.u32 = 0 },
			{ .id = FAL_QOS_WRED_ATTR_YELLOW_DROP_PROBABILITY,
			  .value.u32 = 0 },
			{ .id = FAL_QOS_WRED_ATTR_RED_ENABLE,
			  .value.booldata = false },
			{ .id = FAL_QOS_WRED_ATTR_RED_MIN_THRESHOLD,
			  .value.u32 = 0 },
			{ .id = FAL_QOS_WRED_ATTR_RED_MAX_THRESHOLD,
			  .value.u32 = 0 },
			{ .id = FAL_QOS_WRED_ATTR_RED_DROP_PROBABILITY,
			  .value.u32 = 0 },
		};

		for (colour = FAL_PACKET_COLOUR_GREEN;
		     colour < q_wred_info->num_maps; colour++) {
			struct red_params *colour_params =
				&q_wred_info->params.map_params_bytes[colour];

			uint32_t min_th = colour_params->min_th;
			uint32_t max_th = colour_params->max_th;
			bool enabled;

			enabled = (min_th != 0 && max_th != 0) ? true : false;

			if (enabled)
				DP_DEBUG(QOS_HW, DEBUG, DATAPLANE,
					 "creating wred\n");

			switch (colour) {
			case FAL_PACKET_COLOUR_GREEN:
				qos_hw_upd_bool_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_GREEN_ENABLE,
				     enabled);
				qos_hw_upd_u32_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_GREEN_MIN_THRESHOLD,
				     min_th);
				qos_hw_upd_u32_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_GREEN_MAX_THRESHOLD,
				     max_th);
				qos_hw_upd_u32_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_GREEN_DROP_PROBABILITY,
				     colour_params->maxp_inv);
				break;

			case FAL_PACKET_COLOUR_YELLOW:
				qos_hw_upd_bool_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_YELLOW_ENABLE,
				     enabled);
				qos_hw_upd_u32_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_YELLOW_MIN_THRESHOLD,
				     min_th);
				qos_hw_upd_u32_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_YELLOW_MAX_THRESHOLD,
				     max_th);
				qos_hw_upd_u32_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_YELLOW_DROP_PROBABILITY,
				     colour_params->maxp_inv);
				break;

			case FAL_PACKET_COLOUR_RED:
				qos_hw_upd_bool_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_RED_ENABLE,
				     enabled);
				qos_hw_upd_u32_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_RED_MIN_THRESHOLD,
				     min_th);
				qos_hw_upd_u32_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_RED_MAX_THRESHOLD,
				     max_th);
				qos_hw_upd_u32_attr(wred_attr_list,
				     ARRAY_SIZE(wred_attr_list),
				     FAL_QOS_WRED_ATTR_RED_DROP_PROBABILITY,
				     colour_params->maxp_inv);
				break;
			default:
				DP_DEBUG(QOS_HW, ERR, DATAPLANE,
					 "invalid discard-index/packet-colour "
					 "%u\n", colour);
				return -EINVAL;
			}
		}

		ret = fal_qos_new_wred(switch_id, ARRAY_SIZE(wred_attr_list),
				       wred_attr_list, wred_obj);
	}

	qos_obj_db_hw_set(db_obj, QOS_OBJ_HW_TYPE_WRED, ret, *wred_obj);

	if (ret)
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "FAL failed to create wred object, status: %d\n", ret);

	return ret;
}

static int
qos_hw_create_queue_and_sched(struct qos_obj_db_obj *db_obj,
			      fal_object_t parent_obj, uint32_t queue_limit,
			      uint8_t wrr_weight,
			      struct rte_red_params *wred_params,
			      struct queue_wred_info *q_wred_info,
			      uint32_t tc_id,
			      uint32_t q_id,
			      bool local_priority_queue,
			      fal_object_t *child_obj)
{
	fal_object_t wred_obj = FAL_QOS_NULL_OBJECT_ID;
	fal_object_t sch_obj = FAL_QOS_NULL_OBJECT_ID;
	fal_object_t queue_obj = FAL_QOS_NULL_OBJECT_ID;
	uint32_t switch_id = 0;
	int ret;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "creating queue and scheduler\n");

	*child_obj = FAL_QOS_NULL_OBJECT_ID;

	ret = qos_hw_create_wred(db_obj, wred_params, q_wred_info, &wred_obj);
	if (ret)
		return ret;

	/*
	 * Create the schedule object
	 */
	struct fal_attribute_t sch_attr_list[] = {
		{ .id = FAL_QOS_SCHEDULER_ATTR_SCHEDULING_TYPE,
		  .value.u8 = FAL_QOS_SCHEDULING_TYPE_WRR },
		{ .id = FAL_QOS_SCHEDULER_ATTR_SCHEDULING_WEIGHT,
		  .value.u8 = wrr_weight },
		{ .id = FAL_QOS_SCHEDULER_ATTR_METER_TYPE,
		  .value.u8 = FAL_QOS_METER_TYPE_BYTES },
	};

	ret = fal_qos_new_scheduler(switch_id, ARRAY_SIZE(sch_attr_list),
				    sch_attr_list, &sch_obj);

	qos_obj_db_hw_set(db_obj, QOS_OBJ_HW_TYPE_SCHEDULER, ret, sch_obj);

	if (ret) {
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "FAL failed to create scheduler object, status: %d\n",
			 ret);
		return ret;
	}

	/*
	 * Create the queue object
	 */
	struct fal_attribute_t queue_attr_list[] = {
		{ .id = FAL_QOS_QUEUE_ATTR_INDEX,
		  .value.u8 = q_id },
		{ .id = FAL_QOS_QUEUE_ATTR_PARENT_ID,
		  .value.objid = parent_obj },
		{ .id = FAL_QOS_QUEUE_ATTR_WRED_ID,
		  .value.objid = wred_obj },
		{ .id = FAL_QOS_QUEUE_ATTR_BUFFER_ID,
		  .value.objid = FAL_QOS_NULL_OBJECT_ID },
		{ .id = FAL_QOS_QUEUE_ATTR_SCHEDULER_ID,
		  .value.objid = sch_obj },
		{ .id = FAL_QOS_QUEUE_ATTR_QUEUE_LIMIT,
		  .value.u32 = queue_limit },
		{ .id = FAL_QOS_QUEUE_ATTR_TYPE,
		  .value.u8 = FAL_QOS_QUEUE_TYPE_ALL },
		{ .id = FAL_QOS_QUEUE_ATTR_TC,
		  .value.u8 = tc_id },
		{ .id = FAL_QOS_QUEUE_ATTR_LOCAL_PRIORITY,
		  .value.booldata = local_priority_queue },
	};

	ret = fal_qos_new_queue(switch_id, ARRAY_SIZE(queue_attr_list),
				queue_attr_list, &queue_obj);

	qos_obj_db_hw_set(db_obj, QOS_OBJ_HW_TYPE_QUEUE, ret, queue_obj);

	if (ret)
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "FAL failed to create queue object, status: %d\n",
			 ret);
	else
		*child_obj = queue_obj;

	return ret;
}

static int
qos_hw_new_wrr_queue(fal_object_t tc_sched_obj, uint32_t queue_limit,
		     uint8_t local_priority_wrr, uint8_t wrr_weight,
		     struct rte_red_params *red_params,
		     struct queue_wred_info *q_wred_info, uint32_t *ids)
{
	char ids_str[QOS_OBJ_DB_MAX_ID_LEN + 1];
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status db_ret;
	fal_object_t queue_obj;
	char *out_str;
	int ret = 0;

	out_str = qos_obj_db_get_ids_string(QOS_OBJ_DB_LEVEL_QUEUE, ids,
					    QOS_OBJ_DB_MAX_ID_LEN, ids_str);
	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "creating new queue, id: %s\n",
		 out_str);

	db_ret = qos_obj_db_create(QOS_OBJ_DB_LEVEL_QUEUE, ids,
				   qos_hw_delete_callback, &db_obj);
	if (db_ret) {
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "failed to create queue object, id: %s, status: %d\n",
			 out_str, db_ret);
		return db_ret;
	}

	qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_IN_PROGRESS);

	ret = qos_hw_create_queue_and_sched(db_obj, tc_sched_obj,
					    queue_limit, wrr_weight, red_params,
					    q_wred_info,
					    ids[QOS_OBJ_DB_LEVEL_TC],
					    ids[QOS_OBJ_DB_LEVEL_QUEUE],
					    (local_priority_wrr ==
					     ids[QOS_OBJ_DB_LEVEL_QUEUE]),
					    &queue_obj);
	if (ret)
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_FAILED);
	else
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_SUCCESSFUL);

	return ret;
}

static int
qos_hw_new_tc(uint32_t tc_id, fal_object_t pipe_sched_obj,
	      uint32_t tc_rate, uint32_t tc_size, uint32_t queue_limit,
	      uint8_t local_priority_wrr, uint8_t *wrr_weight,
	      struct rte_red_params *red_params,
	      struct queue_wred_info **q_wred_info, uint32_t *ids,
	      int8_t overhead)
{
	char ids_str[QOS_OBJ_DB_MAX_ID_LEN + 1];
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status db_ret;
	fal_object_t tc_sched_obj;
	uint32_t queues_configured = 0;
	char *out_str;
	uint8_t q_id;
	int ret;

	out_str = qos_obj_db_get_ids_string(QOS_OBJ_DB_LEVEL_TC, ids,
					    QOS_OBJ_DB_MAX_ID_LEN, ids_str);
	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "creating new TC, id: %s\n",
		 out_str);

	db_ret = qos_obj_db_create(QOS_OBJ_DB_LEVEL_TC, ids,
				   qos_hw_delete_callback, &db_obj);
	if (db_ret) {
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "failed to create tc object, id: %s status: %u\n",
			 out_str, db_ret);
		return db_ret;
	}

	qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_IN_PROGRESS);

	/*
	 * How many wrr-queues are being used by this TC?
	 * Count the number of non-zero wrr-weights.
	 */
	for (q_id = 0; q_id < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS; q_id++)
		if (wrr_weight[q_id])
			queues_configured++;

	ret = qos_hw_create_group_and_sched(db_obj, tc_id, pipe_sched_obj,
					    FAL_QOS_SCHED_GROUP_LEVEL_TC,
					    queues_configured,
					    FAL_QOS_SCHEDULING_TYPE_WRR,
					    tc_rate, tc_size, overhead,
					    &tc_sched_obj, 0);

	for (q_id = 0; !ret && q_id < RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
	     q_id++) {
		if (wrr_weight[q_id]) {
			ids[QOS_OBJ_DB_LEVEL_QUEUE] = q_id;
			ret = qos_hw_new_wrr_queue(tc_sched_obj,
						   queue_limit,
						   local_priority_wrr,
						   wrr_weight[q_id],
						   red_params,
						   q_wred_info[q_id],
						   ids);
		}
	}

	if (ret)
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_FAILED);
	else
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_SUCCESSFUL);

	return ret;
}

static int
qos_hw_create_and_attach_map(struct qos_obj_db_obj *db_obj,
			     fal_object_t pipe_sched_obj,
			     enum qos_obj_hw_type hw_type,
			     enum fal_qos_map_type_t map_type,
			     struct fal_qos_map_list_t *map_list,
			     bool local_priority)

{
	enum fal_qos_sched_group_attr_t sched_group_map_id;
	struct fal_attribute_t attr_list[] = {
		{ .id = FAL_QOS_MAP_ATTR_TYPE,
		  .value.u8 = map_type },
		{ .id = FAL_QOS_MAP_ATTR_MAP_TO_VALUE_LIST,
		  .value.maplist = map_list },
		{ .id = FAL_QOS_MAP_ATTR_LOCAL_PRIORITY_QUEUE,
		  .value.booldata = local_priority },
	};
	fal_object_t map_obj;
	int ret;

	/*
	 * Create the map object and attach it to the pipe sched-group.
	 */
	ret = fal_qos_new_map(pipe_sched_obj, ARRAY_SIZE(attr_list), attr_list,
			      &map_obj);

	qos_obj_db_hw_set(db_obj, hw_type, ret, map_obj);

	if (hw_type == QOS_OBJ_HW_TYPE_INGRESS_MAP)
		sched_group_map_id = FAL_QOS_SCHED_GROUP_ATTR_INGRESS_MAP_ID;
	else
		sched_group_map_id = FAL_QOS_SCHED_GROUP_ATTR_EGRESS_MAP_ID;

	if (ret)
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "FAL failed to create qos-map, status: %d\n", ret);
	else
		ret = qos_hw_update_sched_group(pipe_sched_obj,
						sched_group_map_id,
						map_obj);

	return ret;
}

static int
qmap_to_fal_colour(uint8_t q, enum fal_packet_colour *fal_colour)
{
	/* the switch assumes that 2 is the maximum */
	_Static_assert(QOS_MAX_DROP_PRECEDENCE == 2,
		       "QOS_MAX_DROP_PRECEDENCE has been changed without updating mapping to FAL colours");

	switch (qmap_to_dp(q)) {
	case 0:
		*fal_colour = FAL_PACKET_COLOUR_GREEN;
		break;
	case 1:
		*fal_colour = FAL_PACKET_COLOUR_YELLOW;
		break;
	case 2:
		*fal_colour = FAL_PACKET_COLOUR_RED;
		break;
	default:
		RTE_LOG(WARNING, QOS,
			"Invalid packet colour %d for queue index 0x%x\n",
			qmap_to_dp(q), q);
		return -EINVAL;
	}

	return 0;
}

static int
qos_hw_create_ingress_map(struct qos_obj_db_obj *db_obj,
			  fal_object_t pipe_sched_obj, struct queue_map *qmap)
{
	uint8_t cp;
	uint8_t q;
	uint8_t map_type;
	struct fal_qos_map_list_t map_list;
	int ret;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "creating ingress qos-map\n");

	if (qmap->pcp_enabled == 1) {
		map_type = FAL_QOS_MAP_TYPE_DOT1P_TO_TC;
		map_list.count = MAX_PCP;
		for (cp = 0; cp < MAX_PCP; cp++) {
			q = qmap->pcp2q[cp];
			map_list.list[cp].key.dot1p = cp;
			map_list.list[cp].value.tc = qmap_to_tc(q);
			map_list.list[cp].value.wrr = qmap_to_wrr(q);
			ret = qmap_to_fal_colour(
				q, &map_list.list[cp].value.color);
			if (ret < 0)
				return ret;
		}
	} else {
		map_type = FAL_QOS_MAP_TYPE_DSCP_TO_TC;
		map_list.count = MAX_DSCP;
		for (cp = 0; cp < MAX_DSCP; cp++) {
			q = qmap->dscp2q[cp];
			map_list.list[cp].key.dscp = cp;
			map_list.list[cp].value.tc = qmap_to_tc(q);
			map_list.list[cp].value.wrr = qmap_to_wrr(q);
			ret = qmap_to_fal_colour(
				q, &map_list.list[cp].value.color);
			if (ret < 0)
				return ret;
		}
	}

	ret = qos_hw_create_and_attach_map(db_obj, pipe_sched_obj,
					   QOS_OBJ_HW_TYPE_INGRESS_MAP,
					   map_type, &map_list,
					   qmap->local_priority);

	return ret;
}

static int
qos_hw_create_egress_map(struct qos_obj_db_obj *db_obj,
			 fal_object_t pipe_sched_obj,
			 struct qos_mark_map *mark_map)
{
	struct fal_qos_map_list_t map_list;
	uint32_t dscp;

	for (dscp = 0; dscp < FAL_QOS_MAP_DSCP_VALUES; dscp++) {
		map_list.list[dscp].key.dscp = dscp;
		map_list.list[dscp].value.dot1p = mark_map->pcp_value[dscp];
	}
	map_list.count = FAL_QOS_MAP_DSCP_VALUES;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "creating egress qos-map\n");
	return qos_hw_create_and_attach_map(db_obj, pipe_sched_obj,
					    QOS_OBJ_HW_TYPE_EGRESS_MAP,
					    FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P,
					    &map_list, false);
}

static int
qos_hw_new_pipe(uint32_t pipe_id, fal_object_t subport_sched_obj,
		uint16_t *port_qsize, struct subport_info *sinfo,
		struct rte_sched_pipe_params *pipe_params,
		struct queue_map *qmap, struct profile_wred_info *p_wred_info,
		uint32_t *ids, int8_t overhead)
{
	uint32_t tb_rate = pipe_params->tb_rate;
	uint32_t tb_size = pipe_params->tb_size;
	char ids_str[QOS_OBJ_DB_MAX_ID_LEN + 1];
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status db_ret;
	fal_object_t pipe_sched_obj;
	uint32_t tc_id;
	char *out_str;
	int ret;

	out_str = qos_obj_db_get_ids_string(QOS_OBJ_DB_LEVEL_PIPE, ids,
					    QOS_OBJ_DB_MAX_ID_LEN, ids_str);
	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "creating new pipe, id: %s\n",
		 out_str);

	db_ret = qos_obj_db_create(QOS_OBJ_DB_LEVEL_PIPE, ids,
				   qos_hw_delete_callback, &db_obj);
	if (db_ret) {
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			"failed to create pipe object, id: %s status: %u\n",
			 out_str, db_ret);
		return db_ret;
	}

	qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_IN_PROGRESS);

	ret = qos_hw_create_group_and_sched(db_obj, pipe_id,
					    subport_sched_obj,
					    FAL_QOS_SCHED_GROUP_LEVEL_PIPE,
					    RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE,
					    FAL_QOS_SCHEDULING_TYPE_STRICT,
					    tb_rate, tb_size, overhead,
					    &pipe_sched_obj, 0);

	if (!ret)
		ret = qos_hw_create_ingress_map(db_obj, pipe_sched_obj, qmap);

	if (!ret && sinfo->mark_map)
		ret = qos_hw_create_egress_map(db_obj, pipe_sched_obj,
					       sinfo->mark_map);

	for (tc_id = 0; !ret && tc_id < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE;
	     tc_id++) {
		uint64_t dscp_bitmap = 0;
		uint8_t pcp_bitmap = 0;
		uint8_t cp;
		uint8_t q;
		uint8_t qindex;
		uint8_t weight;
		uint8_t tc;
		uint8_t wrr;
		uint8_t local_priority_wrr = RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS;
		uint8_t wrr_weight[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS] = { 0 };
		struct queue_wred_info *q_wred_info
			[RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS] = { NULL };

		if (qmap->pcp_enabled == 1) {
			for (cp = 0; cp < MAX_PCP; cp++) {
				q = qmap->pcp2q[cp];
				qindex = q_from_mask(q);
				weight = pipe_params->wrr_weights[qindex];
				tc = qmap_to_tc(q);
				wrr = qmap_to_wrr(q);
				if (tc == tc_id) {
					pcp_bitmap |= 1 << cp;
					wrr_weight[wrr] = weight;
				}
			}
		} else {
			/*
			 * If PCP mapping isn't explicitly configured, we're
			 * using DSCP mapping.
			 */
			for (cp = 0; cp < MAX_DSCP; cp++) {
				q = qmap->dscp2q[cp];
				qindex = q_from_mask(q);
				weight = pipe_params->wrr_weights[qindex];
				tc = qmap_to_tc(q);
				wrr = qmap_to_wrr(q);
				if (tc == tc_id) {
					dscp_bitmap |= 1ul << cp;
					wrr_weight[wrr] = weight;
					q_wred_info[wrr] =
					    &p_wred_info->queue_wred[qindex];
				}
			}
			if (qmap->local_priority) {
				q = qmap->local_priority_queue;
				qindex = q_from_mask(q);
				weight = pipe_params->wrr_weights[qindex];
				tc = qmap_to_tc(q);
				wrr = qmap_to_wrr(q);
				if (tc == tc_id) {
					local_priority_wrr = wrr;
					wrr_weight[wrr] = weight;
				}
			}
		}

		/*
		 * If bitmap is zero and it doesn't have the local priority
		 * queue, don't create this TC as it isn't used.
		 */
		if (!ret &&
		    ((local_priority_wrr <
		      RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS) || pcp_bitmap ||
		     dscp_bitmap)) {
			uint32_t queue_limit = sinfo->qsize[tc_id] ?
				sinfo->qsize[tc_id] : port_qsize[tc_id];

			ids[QOS_OBJ_DB_LEVEL_TC] = tc_id;
			ret = qos_hw_new_tc(tc_id, pipe_sched_obj,
					    pipe_params->tc_rate[tc_id],
					    tb_size, queue_limit,
					    local_priority_wrr,
					    &wrr_weight[0],
					    &sinfo->red_params[tc_id]
					    [e_RTE_METER_GREEN],
					    &q_wred_info[0], ids, overhead);
		}
	}

	if (ret)
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_FAILED);
	else
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_SUCCESSFUL);

	return ret;
}

static int
qos_hw_new_subport(uint32_t subport_id, fal_object_t port_sched_obj,
		   struct sched_info *qinfo, uint32_t *ids)
{
	struct subport_info *sinfo = qinfo->subport +
		ids[QOS_OBJ_DB_LEVEL_SUBPORT];
	uint32_t tb_rate = sinfo->params.tb_rate;
	uint32_t tb_size = sinfo->params.tb_size;
	char ids_str[QOS_OBJ_DB_MAX_ID_LEN + 1];
	fal_object_t subport_sched_obj;
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status db_ret;
	uint32_t pipe_count = 0;
	uint32_t pipe_id;
	char *out_str;
	int ret;
	int8_t overhead = qinfo->port_params.frame_overhead;

	out_str = qos_obj_db_get_ids_string(QOS_OBJ_DB_LEVEL_SUBPORT, ids,
					    QOS_OBJ_DB_MAX_ID_LEN, ids_str);
	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "creating new subport, id: %s\n",
		 out_str);

	db_ret = qos_obj_db_create(QOS_OBJ_DB_LEVEL_SUBPORT, ids,
				   qos_hw_delete_callback, &db_obj);
	if (db_ret) {
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "failed to create subport object, id: %s, status: "
			 "%u\n", out_str, db_ret);
		return db_ret;
	}

	qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_IN_PROGRESS);

	for (pipe_id = 0; pipe_id < MAX_PIPES; pipe_id++) {
		if (sinfo->pipe_configured[pipe_id])
			pipe_count++;
	}

	ret = qos_hw_create_group_and_sched(db_obj, subport_id, port_sched_obj,
					    FAL_QOS_SCHED_GROUP_LEVEL_SUBPORT,
					    pipe_count,
					    FAL_QOS_SCHEDULING_TYPE_WRR,
					    tb_rate, tb_size,
					    overhead, &subport_sched_obj,
					    qinfo->subport[subport_id].vlan_id);

	for (pipe_id = 0; !ret && pipe_id < MAX_PIPES; pipe_id++) {
		if (sinfo->pipe_configured[pipe_id]) {
			uint8_t profile_id = sinfo->profile_map[pipe_id];
			struct rte_sched_pipe_params *pipe_params =
				qinfo->port_params.pipe_profiles + profile_id;
			struct queue_map *qmap = &qinfo->queue_map[profile_id];
			uint16_t *port_qsize = &qinfo->port_params.qsize[0];
			struct profile_wred_info *p_wred_info =
				&qinfo->wred_profiles[profile_id];

			ids[QOS_OBJ_DB_LEVEL_PIPE] = pipe_id;
			ret = qos_hw_new_pipe(pipe_id, subport_sched_obj,
					      port_qsize, sinfo, pipe_params,
					      qmap, p_wred_info, ids, overhead);
		}
	}

	if (ret)
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_FAILED);
	else
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_SUCCESSFUL);

	return ret;
}

static int
qos_hw_new_port(struct ifnet *ifp, struct sched_info *qinfo, uint64_t linerate)
{
	uint32_t port_obj_id = ifp->if_index;
	fal_object_t port_sched_group_obj;
	uint32_t ids[QOS_OBJ_DB_ID_ARRAY_LEN] = { 0 };
	char ids_str[QOS_OBJ_DB_MAX_ID_LEN + 1];
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status db_ret;
	uint32_t subports_successful;
	uint32_t subports_failed;
	uint32_t subport_id;
	char *out_str;
	int ret;
	int8_t overhead = qinfo->port_params.frame_overhead;

	ids[QOS_OBJ_DB_LEVEL_PORT] = ifp->if_index;

	out_str = qos_obj_db_get_ids_string(QOS_OBJ_DB_LEVEL_PORT, ids,
					    QOS_OBJ_DB_MAX_ID_LEN, ids_str);
	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "creating new port, id: %s\n",
		 out_str);

	db_ret = qos_obj_db_create(QOS_OBJ_DB_LEVEL_PORT, ids,
				   qos_hw_delete_callback, &db_obj);
	if (db_ret) {
		/*
		 * If we can't create the port object, we are completely
		 * stuffed.
		 */
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "failed to create port db object, id: %s, status: "
			 "%d\n", out_str, db_ret);
		return db_ret;
	}

	qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_IN_PROGRESS);

	/*
	 * Create the port level scheduling-group and scheduler object-pair
	 */
	ret = qos_hw_create_group_and_sched(db_obj, port_obj_id,
					    (fal_object_t)NULL,
					    FAL_QOS_SCHED_GROUP_LEVEL_PORT,
					    qinfo->n_subports,
					    FAL_QOS_SCHEDULING_TYPE_WRR,
					    linerate, 0, overhead,
					    &port_sched_group_obj, 0);
	if (ret)
		qos_obj_db_sw_set(db_obj, QOS_OBJ_SW_STATE_HW_PROG_FAILED);
	else {
		/*
		 * Create the required subports
		 */
		subports_failed = 0;
		subports_successful = 0;
		for (subport_id = 0; subport_id < qinfo->n_subports;
		     subport_id++) {
			ids[QOS_OBJ_DB_LEVEL_SUBPORT] = subport_id;
			/*
			 * Ignore individual subport failures as we want to
			 * operate with as many subports as we can allocate.
			 */
			ret = qos_hw_new_subport(subport_id,
						 port_sched_group_obj, qinfo,
						 ids);
			if (ret)
				subports_failed++;
			else
				subports_successful++;
		}

		qinfo->dev_info.fal.hw_port_id = ifp->if_index;
		qinfo->dev_info.fal.hw_port_sched_group = port_sched_group_obj;

		if (subports_successful && !subports_failed)
			qos_obj_db_sw_set(db_obj,
					  QOS_OBJ_SW_STATE_HW_PROG_SUCCESSFUL);
		else if (subports_successful && subports_failed)
			qos_obj_db_sw_set(db_obj,
					  QOS_OBJ_SW_STATE_HW_PROG_PARTIAL);
		else
			qos_obj_db_sw_set(db_obj,
					  QOS_OBJ_SW_STATE_HW_PROG_FAILED);
	}

	return ret;
}

int qos_hw_start(struct ifnet *ifp, struct sched_info *qinfo, uint64_t bps,
		 uint16_t max_pkt_len)
{
	unsigned int subport;
	int ret;

	DP_DEBUG(QOS_HW, DEBUG, DATAPLANE, "hardware start, if-index: %u",
		 ifp->if_index);

	for (subport = 0; subport < qinfo->n_subports; subport++) {
		struct subport_info *sinfo = &qinfo->subport[subport];
		struct rte_sched_subport_params *params = &sinfo->params;

		/*
		 * Establish subport rates before checking pipes so that the
		 * pipes can be checked against their actual subport rates.
		 */
		qos_sched_subport_params_check(params, &sinfo->subport_rate,
				sinfo->sp_tc_rates.tc_rate, max_pkt_len, bps);

		/* Update NPF rules */
		npf_cfg_commit_all();
	}
	qos_sched_pipe_check(qinfo, max_pkt_len, bps);

	ret = qos_hw_new_port(ifp, qinfo, bps);
	if (ret)
		DP_DEBUG(QOS_HW, ERR, DATAPLANE,
			 "failed to create port, status: %d\n", ret);

	return ret;
}
