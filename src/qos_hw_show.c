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

#include "json_writer.h"
#include "qos.h"
#include "qos_obj_db.h"
#include "netinet6/ip6_funcs.h"
#include "npf/config/npf_config.h"
#include "npf_shim.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "ether.h"
#include "fal.h"

static
const char *get_sched_type_str(uint32_t sched_type)
{
	const char *ret_str;

	switch (sched_type) {
	case FAL_QOS_SCHEDULING_TYPE_STRICT:
		ret_str = "Strict Priority";
		break;

	case FAL_QOS_SCHEDULING_TYPE_WRR:
		ret_str = "Weighted Round-Robin";
		break;

	case FAL_QOS_SCHEDULING_TYPE_DWRR:
		ret_str = "Deficit Weight Round-Robin";
		break;

	default:
		ret_str = "Unknown scheduling type";
		break;
	}
	return ret_str;
}

static
const char *get_meter_type_str(uint32_t meter_type)
{
	const char *ret_str;

	switch (meter_type) {
	case FAL_QOS_METER_TYPE_BYTES:
		ret_str = "Bytes Per Second";
		break;

	case FAL_QOS_METER_TYPE_PACKETS:
		ret_str = "Packets Per Second";
		break;

	default:
		ret_str = "Unknown meter type";
		break;
	}
	return ret_str;
}

static
const char *get_queue_type_str(uint32_t queue_type)
{
	const char *ret_str;

	switch (queue_type) {
	case FAL_QOS_QUEUE_TYPE_ALL:
		ret_str = "All traffic types";
		break;

	case FAL_QOS_QUEUE_TYPE_UNICAST:
		ret_str = "Unicast traffic only";
		break;

	case FAL_QOS_QUEUE_TYPE_NON_UNICAST:
		ret_str = "Multicast and broadcast traffic";
		break;

	default:
		ret_str = "Unknown traffic type";
		break;
	}
	return ret_str;
}

static
void qos_hw_show_scheduler(fal_object_t scheduler, json_writer_t *wr)
{
	int ret;
	uint64_t max_bandwidth;
	uint64_t max_burst;
	uint32_t sched_type;
	uint32_t meter_type;
	uint8_t sched_weight;
	int8_t overhead;

	struct fal_attribute_t attr_list[] = {
		{ .id = FAL_QOS_SCHEDULER_ATTR_SCHEDULING_TYPE,
		  .value.u32 = FAL_QOS_SCHEDULER_ATTR_MAX + 1 },
		{ .id = FAL_QOS_SCHEDULER_ATTR_SCHEDULING_WEIGHT,
		  .value.u8 = 0 },
		{ .id = FAL_QOS_SCHEDULER_ATTR_METER_TYPE,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE,
		  .value.u64 = 0 },
		{ .id = FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE,
		  .value.u64 = 0 },
		{ .id = FAL_QOS_SCHEDULER_ATTR_FRAME_OVERHEAD,
		  .value.i8 = 0 },
	};

	ret = fal_qos_get_scheduler_attrs(scheduler, ARRAY_SIZE(attr_list),
					  attr_list);
	if (ret) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"FAL failed to get scheduler attributes, status: %d\n",
			ret);
	}
	/*
	 * We know the order of the IDs in attr-list, but should we use a
	 * get_attribute_value(attr_list, ATTR_ID, &value) to search for them
	 */
	sched_type = attr_list[0].value.u32;
	sched_weight = attr_list[1].value.u8;
	meter_type = attr_list[2].value.u32;
	max_bandwidth = attr_list[3].value.u64;
	max_burst = attr_list[4].value.u64;
	overhead = attr_list[5].value.i8;

	jsonw_name(wr, "scheduler");
	jsonw_start_object(wr);
	jsonw_string_field(wr, "type", get_sched_type_str(sched_type));
	jsonw_string_field(wr, "meter-type", get_meter_type_str(meter_type));
	if (sched_type != FAL_QOS_SCHEDULING_TYPE_STRICT)
		jsonw_uint_field(wr, "weight", sched_weight);
	jsonw_uint_field(wr, "max-bandwidth", max_bandwidth);
	jsonw_uint_field(wr, "max-burst", max_burst);
	jsonw_int_field(wr, "overhead", overhead);
	jsonw_end_object(wr);
}

static
void qos_hw_show_wred(fal_object_t wred, json_writer_t *wr)
{
	bool enabled;
	uint32_t min_threshold;
	uint32_t max_threshold;
	uint32_t drop_probability;
	uint8_t filter_weight;
	int ret;

	struct fal_attribute_t attr_list[] = {
		{ .id = FAL_QOS_WRED_ATTR_GREEN_ENABLE,
		  .value.booldata = 0 },
		{ .id = FAL_QOS_WRED_ATTR_GREEN_MIN_THRESHOLD,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_WRED_ATTR_GREEN_MAX_THRESHOLD,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_WRED_ATTR_GREEN_DROP_PROBABILITY,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_WRED_ATTR_YELLOW_ENABLE,
		  .value.booldata = 0 },
		{ .id = FAL_QOS_WRED_ATTR_YELLOW_MIN_THRESHOLD,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_WRED_ATTR_YELLOW_MAX_THRESHOLD,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_WRED_ATTR_YELLOW_DROP_PROBABILITY,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_WRED_ATTR_RED_ENABLE,
		  .value.booldata = 0 },
		{ .id = FAL_QOS_WRED_ATTR_RED_MIN_THRESHOLD,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_WRED_ATTR_RED_MAX_THRESHOLD,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_WRED_ATTR_RED_DROP_PROBABILITY,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_WRED_ATTR_WEIGHT,
		  .value.u8 = 0 },
	};

	ret = fal_qos_get_wred_attrs(wred, ARRAY_SIZE(attr_list), attr_list);
	if (ret) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"FAL failed to get wred attributes, status: %d\n",
			ret);
	}

	/*
	 * Get the green attributes
	 */
	enabled = attr_list[0].value.booldata;
	min_threshold = attr_list[1].value.u32;
	max_threshold = attr_list[2].value.u32;
	drop_probability = attr_list[3].value.u32;

	jsonw_name(wr, "wred");
	jsonw_start_object(wr);
	jsonw_bool_field(wr, "green-enabled", enabled);
	if (enabled) {
		jsonw_uint_field(wr, "green-min-threshold", min_threshold);
		jsonw_uint_field(wr, "green-max-threshold", max_threshold);
		jsonw_uint_field(wr, "green-drop-probability",
				 drop_probability);
	}

	/*
	 * Get the yellow attributes
	 */
	enabled = attr_list[4].value.booldata;
	min_threshold = attr_list[5].value.u32;
	max_threshold = attr_list[6].value.u32;
	drop_probability = attr_list[7].value.u32;

	jsonw_bool_field(wr, "yellow-enabled", enabled);
	if (enabled) {
		jsonw_uint_field(wr, "yellow-min-threshold", min_threshold);
		jsonw_uint_field(wr, "yellow-max-threshold", max_threshold);
		jsonw_uint_field(wr, "yellow-drop-probability",
				 drop_probability);
	}

	/*
	 * Get the red attributes
	 */
	enabled = attr_list[8].value.booldata;
	min_threshold = attr_list[9].value.u32;
	max_threshold = attr_list[10].value.u32;
	drop_probability = attr_list[11].value.u32;

	jsonw_bool_field(wr, "red-enabled", enabled);
	if (enabled) {
		jsonw_uint_field(wr, "red-min-threshold", min_threshold);
		jsonw_uint_field(wr, "red-max-threshold", max_threshold);
		jsonw_uint_field(wr, "red-drop-probability",
				 drop_probability);
	}

	filter_weight = attr_list[12].value.u8;
	jsonw_uint_field(wr, "filter-weight", filter_weight);
	jsonw_end_object(wr);
}


static
void qos_hw_show_queue(fal_object_t queue, uint32_t id, json_writer_t *wr)
{
	fal_object_t scheduler_id;
	fal_object_t wred_id;
	uint32_t queue_limit;
	uint32_t queue_type;
	uint8_t queue_index;
	uint8_t tc;
	uint8_t designator;
	int ret;

	struct fal_attribute_t attr_list[] = {
		{ .id = FAL_QOS_QUEUE_ATTR_TYPE,
		  .value.u32 = FAL_QOS_QUEUE_ATTR_MAX + 1 },
		{ .id = FAL_QOS_QUEUE_ATTR_INDEX,
		  .value.u8 = 0xFF },
		{ .id = FAL_QOS_QUEUE_ATTR_PARENT_ID,
		  .value.objid = FAL_QOS_NULL_OBJECT_ID },
		{ .id = FAL_QOS_QUEUE_ATTR_WRED_ID,
		  .value.objid = FAL_QOS_NULL_OBJECT_ID },
		{ .id = FAL_QOS_QUEUE_ATTR_BUFFER_ID,
		  .value.objid = FAL_QOS_NULL_OBJECT_ID },
		{ .id = FAL_QOS_QUEUE_ATTR_SCHEDULER_ID,
		  .value.objid = FAL_QOS_NULL_OBJECT_ID },
		{ .id = FAL_QOS_QUEUE_ATTR_QUEUE_LIMIT,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_QUEUE_ATTR_TC,
		  .value.u8 = 0xFF },
		{ .id = FAL_QOS_QUEUE_ATTR_DESIGNATOR,
		  .value.u8 = 0 },
	};

	ret = fal_qos_get_queue_attrs(queue, ARRAY_SIZE(attr_list), attr_list);
	if (ret) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"FAL failed to get queue attributes, status: %d\n",
			ret);
	}
	/*
	 * We know the order of the IDs in attr-list, but should we use a
	 * get_attribute_value(attr_list, ATTR_ID, &value) to search for them
	 */
	queue_type = attr_list[0].value.u32;
	queue_index = attr_list[1].value.u8;
	wred_id = attr_list[3].value.objid;
	scheduler_id = attr_list[5].value.objid;
	queue_limit = attr_list[6].value.u32;
	tc = attr_list[7].value.u8;
	designator = attr_list[8].value.u8;

	jsonw_name(wr, "queue");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "id", id);
	jsonw_string_field(wr, "type", get_queue_type_str(queue_type));
	jsonw_uint_field(wr, "queue-limit", queue_limit);
	jsonw_uint_field(wr, "queue-index", queue_index);
	jsonw_uint_field(wr, "tc", tc);
	jsonw_uint_field(wr, "designation", designator);

	if (scheduler_id != FAL_QOS_NULL_OBJECT_ID)
		qos_hw_show_scheduler(scheduler_id, wr);

	if (wred_id != FAL_QOS_NULL_OBJECT_ID)
		qos_hw_show_wred(wred_id, wr);

	jsonw_end_object(wr);
}

static
void qos_hw_show_to_tc_map_list(uint8_t map_type __unused,
				struct fal_qos_map_list_t *map_list,
				json_writer_t *wr)
{
	uint64_t cp_bitmap[RTE_SCHED_QUEUES_PER_PIPE *
			   (QOS_MAX_DROP_PRECEDENCE + 1)] = { 0 };
	uint32_t tc;
	uint32_t dp;
	uint32_t mli;
	uint32_t bmi;

	for (mli = 0; mli < map_list->count; mli++) {
		struct fal_qos_map_t *map = &map_list->list[mli];
		uint8_t key;

		key = map->key.dscp;

		if (mli != key)
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "map-list not in order\n");

		bmi = (map->value.dp * RTE_SCHED_QUEUES_PER_PIPE) +
			(map->value.des * RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);

		cp_bitmap[bmi] |= (1ul << key);
	}

	for (tc = 0; tc < RTE_SCHED_TRAFFIC_CLASSES_PER_PIPE; tc++) {
		for (dp = 0; dp <= QOS_MAX_DROP_PRECEDENCE; dp++) {
			bmi = (dp * RTE_SCHED_QUEUES_PER_PIPE) +
				(tc *
				 RTE_SCHED_QUEUES_PER_TRAFFIC_CLASS);

			if (cp_bitmap[bmi]) {
				char str_bitmap[22];

				jsonw_start_object(wr);
				snprintf(str_bitmap, 21, "%lu", cp_bitmap[bmi]);
				jsonw_string_field(wr, "cp-bitmap", str_bitmap);
				jsonw_uint_field(wr, "designator", tc);
				jsonw_uint_field(wr, "drop-precedence", dp);
				jsonw_end_object(wr);
			}
		}
	}
}

static void
qos_hw_show_to_dot1p_map_list(struct fal_qos_map_list_t *map_list,
			      json_writer_t *wr)
{
	uint64_t cp_bitmap[MAX_PCP] = { 0 };
	uint32_t pcp;
	uint32_t mli;

	for (mli = 0; mli < map_list->count; mli++) {
		struct fal_qos_map_t *map = &map_list->list[mli];
		uint8_t dscp;

		dscp = map->key.dscp;

		if (mli != dscp)
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "map-list not in order\n");

		pcp = map->value.dot1p;
		cp_bitmap[pcp] |= (1ul << dscp);
	}

	for (pcp = 0; pcp < MAX_PCP; pcp++) {
		if (cp_bitmap[pcp]) {
			char str_bitmap[22];

			jsonw_start_object(wr);
			snprintf(str_bitmap, 21, "%lu", cp_bitmap[pcp]);
			jsonw_string_field(wr, "dscp-bitmap", str_bitmap);
			jsonw_uint_field(wr, "pcp", pcp);
			jsonw_end_object(wr);
		}
	}
}

static
void qos_hw_show_map_list(uint8_t map_type, struct fal_qos_map_list_t *map_list,
			  json_writer_t *wr)
{
	switch (map_type) {
	case FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR:
	case FAL_QOS_MAP_TYPE_DOT1P_TO_DESIGNATOR:
		jsonw_name(wr, "ingress-map");
		break;
	case FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P:
	case FAL_QOS_MAP_TYPE_DESIGNATOR_TO_DOT1P:
		jsonw_name(wr, "egress-map");
		break;
	default:
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "unsupported map-type: %u\n", map_type);
		return;
	}

	jsonw_start_object(wr);
	jsonw_uint_field(wr, "map-type", map_type);
	jsonw_name(wr, "map-list");
	jsonw_start_array(wr);

	if (map_type == FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR)
		qos_hw_show_to_tc_map_list(map_type, map_list, wr);
	else
		qos_hw_show_to_dot1p_map_list(map_list, wr);

	jsonw_end_array(wr);
	jsonw_end_object(wr);
}

/*
 * How many entry a qosmap has depends upon its type.
 * DOT1P and TC qosmaps have eight entries, DSCP qosmaps have 64.
 */
const uint8_t qos_map_entries[FAL_QOS_MAP_TYPE_MAX + 1] = {
	8,  /* FAL_QOS_MAP_TYPE_DOT1P_TO_TC */
	8,  /* FAL_QOS_MAP_TYPE_DOT1P_TO_COLOR */
	64, /* FAL_QOS_MAP_TYPE_DSCP_TO_TC */
	64, /* FAL_QOS_MAP_TYPE_DSCP_TO_COLOR */
	8,  /* FAL_QOS_MAP_TYPE_TC_TO_QUEUE */
	8,  /* FAL_QOS_MAP_TYPE_TC_AND_COLOR_TO_DSCP */
	8,  /* FAL_QOS_MAP_TYPE_TC_AND_COLOR_TO_DOT1P */
	8,  /* FAL_QOS_MAP_TYPE_TC_TO_PRIORITY_GROUP */
	64, /* FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P */
	64, /* FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR */
	8,  /* FAL_QOS_MAP_TYPE_DOT1P_TO_DESIGNATOR */
	8,  /* FAL_QOS_MAP_TYPE_DESIGNATOR_TO_DOT1P */
};

static
void qos_hw_show_map(fal_object_t map, json_writer_t *wr)
{
	struct fal_qos_map_list_t map_list;
	uint8_t map_type;
	int ret;

	struct fal_attribute_t attr_list[] = {
		{ .id = FAL_QOS_MAP_ATTR_TYPE,
		  .value.u8 = FAL_QOS_MAP_TYPE_MAX + 1 },
	};

	/*
	 * Only get the map type on the first get-map-attrs call
	 */
	ret = fal_qos_get_map_attrs(map, 1, attr_list);
	if (ret) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"FAL failed to get map attributes, status: %d\n", ret);
		return;
	}

	map_type = attr_list[0].value.u8;
	if (map_type > FAL_QOS_MAP_TYPE_MAX) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "map type (%u) out of range\n",
			 map_type);
		return;
	}

	map_list.count = qos_map_entries[map_type];

	/*
	 * Reuse the attr-list now we know the map type and its size.
	 */
	attr_list[0].id = FAL_QOS_MAP_ATTR_MAP_TO_VALUE_LIST;
	attr_list[0].value.ptr = &map_list;

	ret = fal_qos_get_map_attrs(map, ARRAY_SIZE(attr_list), attr_list);
	if (ret)
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"FAL failed to get map attributes, status: %d\n", ret);
	else {
		if (map_list.count != qos_map_entries[map_type])
			DP_DEBUG(QOS, ERR, DATAPLANE,
				 "wrong map-list count returned\n");
		else
			qos_hw_show_map_list(map_type, &map_list, wr);
	}
}

/*
 * Forward function declaration
 */
static
void qos_hw_show_sched_group(fal_object_t sched_group, uint32_t id,
			     json_writer_t *wr);

static
void qos_hw_show_sched_group_children(fal_object_t sched_group, uint8_t level,
				      uint32_t child_count, json_writer_t *wr)
{
	struct fal_object_list_t *obj_list;
	uint32_t id;
	int ret;

	obj_list = calloc(1, sizeof(*obj_list) + (child_count *
						  sizeof(fal_object_t)));
	if (!obj_list) {
		DP_DEBUG(QOS, ERR, DATAPLANE, "out of memory\n");
		return;
	}

	struct fal_attribute_t attr_list[] = {
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_CHILD_LIST,
		  .value.objlist = obj_list },
	};

	ret = fal_qos_get_sched_group_attrs(sched_group, ARRAY_SIZE(attr_list),
					    attr_list);
	if (ret) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"FAL failed to get sched-group attributes, status: "
			"%d\n", ret);
		free(obj_list);
		return;
	}

	if (obj_list->count != child_count)
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "wrong obj-list count returned\n");
	else {
		jsonw_name(wr, "children");
		jsonw_start_array(wr);
		for (id = 0; id < child_count; id++) {
			fal_object_t child = obj_list->list[id];

			if (child != FAL_QOS_NULL_OBJECT_ID) {
				jsonw_start_object(wr);
				if (level == FAL_QOS_SCHED_GROUP_LEVEL_TC)
					qos_hw_show_queue(child, id, wr);
				else
					qos_hw_show_sched_group(child, id, wr);

				jsonw_end_object(wr);
			}
		}
		jsonw_end_array(wr);
	}
	free(obj_list);
}

static
void qos_hw_show_sched_group(fal_object_t sched_group, uint32_t id,
			     json_writer_t *wr)
{
	fal_object_t scheduler_id;
	fal_object_t ingress_map_id;
	fal_object_t egress_map_id;
	uint32_t child_count;
	uint32_t max_children;
	uint8_t level;
	uint16_t vlan;
	uint8_t lp_des;
	int ret;

	struct fal_attribute_t attr_list[] = {
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_SG_INDEX,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_LEVEL,
		  .value.u8 = 0 },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_MAX_CHILDREN,
		  .value.u8 = 0 },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_CHILD_COUNT,
		  .value.u32 = 0 },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_SCHEDULER_ID,
		  .value.objid = FAL_QOS_NULL_OBJECT_ID },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_PARENT_ID,
		  .value.objid = FAL_QOS_NULL_OBJECT_ID },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_INGRESS_MAP_ID,
		  .value.objid = FAL_QOS_NULL_OBJECT_ID },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_EGRESS_MAP_ID,
		  .value.objid = FAL_QOS_NULL_OBJECT_ID },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_VLAN_ID,
		  .value.u16 = 0 },
		{ .id = FAL_QOS_SCHED_GROUP_ATTR_LOCAL_PRIORITY_DESIGNATOR,
		  .value.u8 = 0 },
	};

	ret = fal_qos_get_sched_group_attrs(sched_group, ARRAY_SIZE(attr_list),
					    attr_list);
	if (ret) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			"FAL failed to get sched-group attributes, status: "
			"%d\n", ret);
		return;
	}

	/*
	 * We know the order of the IDs in attr-list, but should we use a
	 * get_attribute_value(attr_list, ATTR_ID, &value) to search for them
	 */
	level = attr_list[1].value.u8;
	max_children = attr_list[2].value.u8;
	child_count = attr_list[3].value.u32;
	scheduler_id = attr_list[4].value.objid;
	ingress_map_id = attr_list[6].value.objid;
	egress_map_id = attr_list[7].value.objid;
	vlan = attr_list[8].value.u16;
	lp_des = attr_list[9].value.u8;

	jsonw_name(wr, "sched-group");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "level", level);
	jsonw_uint_field(wr, "id", id);

	if (scheduler_id != FAL_QOS_NULL_OBJECT_ID)
		qos_hw_show_scheduler(scheduler_id, wr);

	jsonw_uint_field(wr, "max-children", max_children);
	jsonw_uint_field(wr, "current-children", child_count);

	if (level == FAL_QOS_SCHED_GROUP_LEVEL_PIPE) {
		jsonw_uint_field(wr, "local-priority-des", lp_des);
		if (ingress_map_id != FAL_QOS_NULL_OBJECT_ID)
			qos_hw_show_map(ingress_map_id, wr);

		if (egress_map_id != FAL_QOS_NULL_OBJECT_ID)
			qos_hw_show_map(egress_map_id, wr);
	}

	/*
	 * Don't show the vlan for subport 0 which corresponds to
	 * the trunk policy.
	 */
	if (level == FAL_QOS_SCHED_GROUP_LEVEL_SUBPORT && id)
		jsonw_uint_field(wr, "subport-vlan-id", vlan);

	if (child_count)
		qos_hw_show_sched_group_children(sched_group, level,
						 child_count, wr);

	jsonw_end_object(wr);
}

int qos_hw_show_port(struct ifnet *ifp, void *arg)
{
	struct qos_show_context *context = arg;
	json_writer_t *wr = context->wr;
	struct sched_info *qinfo = ifp->if_qos;

	if (!qinfo) {
		DP_DEBUG(QOS, ERR, DATAPLANE,
			 "missing port-sched obj on get port\n");
		return -EINVAL;
	}

	jsonw_name(wr, ifp->if_name);
	jsonw_start_object(wr);
	qos_hw_show_sched_group(qinfo->dev_info.fal.hw_port_sched_group,
				ifp->if_index, wr);
	jsonw_end_object(wr);
	return 0;
}

void qos_hw_dump_map(json_writer_t *wr, const struct sched_info *qinfo,
		     uint32_t subport, uint32_t pipe)
{
	fal_object_t map;

	map = qos_hw_get_ingress_map(qinfo->dev_info.fal.hw_port_id,
				     subport, pipe);
	if (map)
		fal_qos_dump_map(map, wr);

	map = qos_hw_get_egress_map(qinfo->dev_info.fal.hw_port_id,
				    subport, pipe);
	if (map)
		fal_qos_dump_map(map, wr);
}

void qos_hw_dump_subport(json_writer_t *wr, const struct sched_info *qinfo,
			 uint32_t subport)
{
	fal_object_t subport_sg;

	subport_sg = qos_hw_get_subport_sg(qinfo->dev_info.fal.hw_port_id,
					   subport);

	if (subport_sg)
		fal_qos_dump_sched_group(subport_sg, wr);
}

void qos_hw_dump_buf_errors(json_writer_t *wr)
{
	fal_qos_dump_buf_errors(wr);
}
