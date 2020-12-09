/*-
 * Copyright (c) 2018-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <fal_plugin.h>
#include <rte_log.h>
#include <stdint.h>
#include <stdio.h>
#include <bsd/sys/tree.h>

#include "dp_test.h"
#include "dp_test/dp_test_macros.h"
#include "fal_plugin_test.h"

#define LOG(l, t, ...)						\
	rte_log(RTE_LOG_ ## l,					\
		RTE_LOGTYPE_USER1, # t ": " __VA_ARGS__)

#define DEBUG(...)						\
	do {							\
		if (dp_test_debug_get() == 2)			\
			LOG(DEBUG, FAL_TEST, __VA_ARGS__);	\
	} while (0)

#define INFO(...) LOG(INFO, FAL_TEST,  __VA_ARGS__)
#define ERROR(...) LOG(ERR, FAL_TEST, __VA_ARGS__)

/**
 * Local structure definitions
 */

struct fal_bcm_code_point {
	uint8_t tc_id;
	uint8_t queue_id;
	uint8_t drop_precedence;
	uint8_t dot1p;
	uint8_t des;
};

struct fal_bcm_qos_map {
	uint8_t map_type;
	struct fal_bcm_code_point code_points[FAL_QOS_MAP_DSCP_VALUES];
	bool system_default;
};

struct fal_bcm_qos_queue {
	TAILQ_ENTRY(fal_bcm_qos_queue) peer_list;
	fal_object_t switch_id;
	fal_object_t port_id;
	fal_object_t parent_id;
	fal_object_t sched_id;
	fal_object_t buffer_id;
	fal_object_t wred_id;
	uint16_t queue_limit;
	uint8_t queue_index;
	uint8_t queue_type;
	uint8_t tc;
	uint8_t designator;
};

struct fal_bcm_qos_sched {
	fal_object_t switch_id;
	uint64_t max_bandwidth;
	uint64_t max_burst;
	uint8_t sched_type;
	uint8_t sched_weight;
	uint8_t meter_type;
	int8_t overhead;
};

struct fal_bcm_qos_sched_group {
	TAILQ_ENTRY(fal_bcm_qos_sched_group) peer_list;
	fal_object_t switch_id;
	fal_object_t sg_index;
	fal_object_t parent_id;
	fal_object_t sched_id;
	fal_object_t ingress_map_id;
	fal_object_t egress_map_id;
	uint8_t sched_level;
	uint8_t max_children;
	uint16_t vlan;
	uint8_t local_prio_des;
	TAILQ_HEAD(children, fal_bcm_qos_sched_group) child_list;
	TAILQ_HEAD(queues, fal_bcm_qos_queue) queue_list;
};

struct fal_bcm_qos_wred {
	bool green_enabled;
	uint32_t green_min_threshold;
	uint32_t green_max_threshold;
	uint32_t green_drop_probability;
	bool yellow_enabled;
	uint32_t yellow_min_threshold;
	uint32_t yellow_max_threshold;
	uint32_t yellow_drop_probability;
	bool red_enabled;
	uint32_t red_min_threshold;
	uint32_t red_max_threshold;
	uint32_t red_drop_probability;
	uint8_t filter_weight;
};

struct fal_bcm_qos_ext_buf_cntr {
	uint32_t buf_free;
	uint32_t dropped;
};

/**
 * @brief New QOS Map
 *
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] new_map_id QOS Map Id
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_new_map(fal_object_t switch_id,
			   uint32_t attr_count,
			   const struct fal_attribute_t *attr_list,
			   fal_object_t *new_map_id)
{
	uint8_t map_type = FAL_QOS_MAP_TYPE_MAX + 1;
	bool sys_def = false;
	struct fal_qos_map_list_t *map_list = NULL;
	uint32_t i;
	int ret = 0;

	DEBUG("%s, attr-count: %u\n", __func__, attr_count);

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_MAP_ATTR_TYPE:
			map_type = attr_list[i].value.u8;
			break;

		case FAL_QOS_MAP_ATTR_MAP_TO_VALUE_LIST:
			map_list = attr_list[i].value.maplist;
			break;

		case FAL_QOS_MAP_ATTR_INGRESS_SYSTEM_DEFAULT:
			sys_def = attr_list[i].value.booldata;
			break;

		default:
			ERROR("%s: unknown qos map attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			break;
		}
	}

	/*
	 * Mandatory create argument checking
	 */
	if (map_type > FAL_QOS_MAP_TYPE_MAX || map_list == NULL) {
		ERROR("%s: mandatory map create argument missing\n",
		      __func__);
		return -EINVAL;
	}
	switch (map_type) {
	case FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR:
	case FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P:
		*new_map_id = FAL_QOS_NULL_OBJECT_ID;
		if (map_list->count != FAL_QOS_MAP_DSCP_VALUES) {
			ERROR("%s: map-type (%u), expected %d values, got %d\n",
			      __func__, map_type, FAL_QOS_MAP_DSCP_VALUES,
			      map_list->count);
			return -EINVAL;
		}
		break;
	case FAL_QOS_MAP_TYPE_DOT1P_TO_DESIGNATOR:
		*new_map_id = FAL_QOS_NULL_OBJECT_ID;
		if (map_list->count != FAL_QOS_MAP_PCP_VALUES) {
			ERROR("%s: map-type (%u), expected %d values, got %d\n",
			      __func__, map_type, FAL_QOS_MAP_PCP_VALUES,
			      map_list->count);
			return -EINVAL;
		}
		break;

	case FAL_QOS_MAP_TYPE_DESIGNATOR_TO_DOT1P:
		if (map_list->count != FAL_QOS_MAP_DES_DP_VALUES) {
			ERROR("%s: map-type (%u), expected %d values, got %d\n",
			      __func__, map_type,
			      FAL_QOS_MAP_DES_DP_VALUES,
			      map_list->count);
			return -EINVAL;
		}
		if (*new_map_id) {
			DEBUG("%s, egress-map already setup %"PRIxPTR"\n",
			      __func__, *new_map_id);
			return 0;
		}
		break;

	default:
		ERROR("%s: unsupported map-type (%u)\n", __func__,
		      map_type);
		return -EINVAL;
	}

	if (!ret) {
		struct fal_bcm_qos_map *map;
		uint8_t cp;
		uint8_t i;

		map = fal_calloc(1, sizeof(*map));
		if (!map)
			return -ENOMEM;

		map->map_type = map_type;
		map->system_default = sys_def;
		if (map_type == FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR ||
		    map_type == FAL_QOS_MAP_TYPE_DOT1P_TO_DESIGNATOR) {
			for (i = 0; i < map_list->count; i++) {
				cp = map_type ==
					FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR ?
					map_list->list[i].key.dscp :
					map_list->list[i].key.dot1p;
				map->code_points[cp].tc_id =
					map_list->list[i].value.des;
				map->code_points[cp].drop_precedence =
					map_list->list[i].value.dp;
				map->code_points[cp].des =
					map_list->list[i].value.des;
			}
		} else if (map_type == FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P) {
			for (i = 0; i < FAL_QOS_MAP_DSCP_VALUES; i++) {
				cp = map_list->list[i].key.dscp;
				map->code_points[cp].dot1p =
					map_list->list[i].value.dot1p;
				map->code_points[cp].drop_precedence = 0;
			}
		} else if (map_type == FAL_QOS_MAP_TYPE_DESIGNATOR_TO_DOT1P) {
			for (i = 0; i < map_list->count; i++) {
				cp = map_list->list[i].key.des;
				map->code_points[cp].dot1p =
					map_list->list[i].value.dot1p;
			}
		} else {
			ERROR("%s: unsupported map type: %u\n",
			      __func__, map_type);
			ret = -EINVAL;
			fal_free_deferred(map);
			return ret;
		}
		*new_map_id = (fal_object_t)map;
	}
	return ret;
}

/**
 * @brief Delete QOS Map
 *
 * @param[in] map_id QOS Map id to be removed.
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_del_map(fal_object_t map_id)
{
	struct fal_bcm_qos_map *map = (struct fal_bcm_qos_map *)map_id;

	DEBUG("%s - %lx\n", __func__, map_id);

	if (map_id == FAL_QOS_NULL_OBJECT_ID)
		return -EINVAL;

	fal_free_deferred(map);
	return 0;
}

/**
 * @brief Update QoS map attribute
 *
 * @param[in] map_id QOS Map Id
 * @param[in] attr Attribute to set
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_upd_map(fal_object_t map_id,
			   const struct fal_attribute_t *attr)
{
	struct fal_bcm_qos_map *map = (struct fal_bcm_qos_map *)map_id;
	struct fal_qos_map_list_t *map_list;
	uint8_t cp;
	uint8_t i;

	DEBUG("%s - %lx\n", __func__, map_id);

	if (map_id == FAL_QOS_NULL_OBJECT_ID ||
	    attr->id != FAL_QOS_MAP_ATTR_MAP_TO_VALUE_LIST)
		return -EINVAL;

	map_list = attr->value.maplist;

	if (map->map_type == FAL_QOS_MAP_TYPE_DOT1P_TO_DESIGNATOR) {
		if (map_list->count != FAL_QOS_MAP_PCP_VALUES)
			return -EINVAL;

		for (i = 0; i < FAL_QOS_MAP_PCP_VALUES; i++) {
			cp = map_list->list[i].key.dot1p;
			map->code_points[cp].des = map_list->list[i].value.des;
			map->code_points[cp].drop_precedence =
				map_list->list[i].value.dp;
		}
	} else if (map->map_type == FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR) {
		if (map_list->count != FAL_QOS_MAP_DSCP_VALUES)
			return -EINVAL;

		for (i = 0; i < FAL_QOS_MAP_DSCP_VALUES; i++) {
			cp = map_list->list[i].key.dscp;
			map->code_points[cp].des =
				map_list->list[i].value.des;
			map->code_points[cp].drop_precedence =
				map_list->list[i].value.dp;
		}
	} else { /* map->map_type == FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P */
		if (map_list->count != FAL_QOS_MAP_DSCP_VALUES)
			return -EINVAL;

		for (i = 0; i < FAL_QOS_MAP_DSCP_VALUES; i++) {
			cp = map_list->list[i].key.dscp;
			map->code_points[cp].dot1p =
				map_list->list[i].value.dot1p;
			map->code_points[cp].drop_precedence = 0;
		}
	}
	return 0;
}

/**
 * @brief Get attributes of QOS map
 *
 * @param[in] map_id Map id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_get_map_attrs(fal_object_t map_id, uint32_t attr_count,
				 struct fal_attribute_t *attr_list)
{
	struct fal_bcm_qos_map *map = (struct fal_bcm_qos_map *)map_id;
	struct fal_qos_map_list_t *map_list = NULL;
	uint32_t i;
	int ret = 0;

	DEBUG("%s - %lx, attr-count: %u\n", __func__, map_id, attr_count);

	if (map == FAL_QOS_NULL_OBJECT_ID)
		return -EINVAL;

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_MAP_ATTR_TYPE:
			attr_list[i].value.u8 = map->map_type;
			break;

		case FAL_QOS_MAP_ATTR_MAP_TO_VALUE_LIST:
			map_list = attr_list[i].value.maplist;
			break;

		default:
			ERROR("%s: unknown qos map attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			break;
		}
	}

	if (map_list) {
		if (map->map_type == FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR ||
		    map->map_type == FAL_QOS_MAP_TYPE_DOT1P_TO_DESIGNATOR) {
			uint count =
				map->map_type ==
				FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR ?
				FAL_QOS_MAP_DSCP_VALUES :
				FAL_QOS_MAP_PCP_VALUES;

			if (map_list->count != count)
				return -EINVAL;

			for (i = 0; i < count; i++) {
				if (map->map_type ==
				    FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR)
					map_list->list[i].key.dscp = i;
				else
					map_list->list[i].key.dot1p = i;
				map_list->list[i].value.dp =
					map->code_points[i].drop_precedence;
				map_list->list[i].value.des =
					map->code_points[i].des;
			}
		} else { /* map->map_type == FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P */
			if (map_list->count != FAL_QOS_MAP_DSCP_VALUES)
				return -EINVAL;

			for (i = 0; i < FAL_QOS_MAP_DSCP_VALUES; i++) {
				map_list->list[i].key.dscp = i;
				map_list->list[i].value.dot1p =
					map->code_points[i].dot1p;
				map_list->list[i].value.dp =
					map->code_points[i].drop_precedence;
				map_list->list[i].value.des =
					map->code_points[i].des;
			}
		}
	}
	return ret;
}

__FOR_EXPORT
void fal_plugin_qos_dump_map(fal_object_t map_id, json_writer_t *wr)
{
	struct fal_bcm_qos_map *map = (struct fal_bcm_qos_map *)map_id;
	int i;

	switch (map->map_type) {
	case FAL_QOS_MAP_TYPE_DSCP_TO_DESIGNATOR:
		jsonw_name(wr, "fal-qos-dscp2des");
		jsonw_start_array(wr);
		for (i = 0; i < FAL_QOS_MAP_DSCP_VALUES; i++) {
			int tc, dp;

			tc = map->code_points[i].tc_id;
			dp = map->code_points[i].drop_precedence;

			jsonw_start_object(wr);
			jsonw_uint_field(wr, "dscp", i);
			jsonw_uint_field(wr, "des", tc);
			jsonw_uint_field(wr, "dp", dp);
			jsonw_end_object(wr);
		}

		jsonw_end_array(wr);
		break;

	case FAL_QOS_MAP_TYPE_DOT1P_TO_DESIGNATOR:
		jsonw_name(wr, "fal-qos-dot1p2des");
		jsonw_start_array(wr);
		for (i = 0; i < FAL_QOS_MAP_PCP_VALUES; i++) {
			int tc, dp;

			tc = map->code_points[i].tc_id;
			dp = map->code_points[i].drop_precedence;

			jsonw_start_object(wr);
			jsonw_uint_field(wr, "pcp", i);
			jsonw_uint_field(wr, "des", tc);
			jsonw_uint_field(wr, "dp", dp);
			jsonw_end_object(wr);
		}

		jsonw_end_array(wr);
		break;

	case FAL_QOS_MAP_TYPE_DSCP_TO_DOT1P:
		jsonw_name(wr, "fal-qos-dscp2dot1p");
		jsonw_start_array(wr);
		for (i = 0; i < FAL_QOS_MAP_DSCP_VALUES; i++) {
			uint8_t pcp;

			pcp = map->code_points[i].dot1p;

			jsonw_start_object(wr);
			jsonw_uint_field(wr, "dscp", i);
			jsonw_uint_field(wr, "pcp", pcp);
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
		break;

	case FAL_QOS_MAP_TYPE_DESIGNATOR_TO_DOT1P:
		jsonw_name(wr, "fal-qos-des2dot1p");
		jsonw_start_array(wr);
		for (i = 0; i < FAL_QOS_MAP_DES_DP_VALUES; i++) {
			uint8_t pcp;

			pcp = map->code_points[i].dot1p;

			jsonw_start_object(wr);
			jsonw_uint_field(wr, "des",
					 i/FAL_NUM_PACKET_COLOURS);
			jsonw_uint_field(wr, "dp",
					 i%FAL_NUM_PACKET_COLOURS);
			jsonw_uint_field(wr, "pcp", pcp);
			jsonw_end_object(wr);
		}
		jsonw_end_array(wr);
		break;

	default:
		ERROR("Dump of unsupported map type\n");
		break;
	}
}


/**
 * @brief New QoS queue
 *
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] new_queue_id Queue id
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_new_queue(fal_object_t switch_id, uint32_t attr_count,
			     const struct fal_attribute_t *attr_list,
			     fal_object_t *new_queue_id)
{
	struct fal_bcm_qos_queue *queue;
	fal_object_t parent_id = FAL_QOS_NULL_OBJECT_ID;
	fal_object_t sched_id = FAL_QOS_NULL_OBJECT_ID;
	fal_object_t wred_id = FAL_QOS_NULL_OBJECT_ID;
	fal_object_t buffer_id = FAL_QOS_NULL_OBJECT_ID;
	uint16_t queue_limit = 0;
	uint8_t queue_type = FAL_QOS_QUEUE_TYPE_MAX + 1; /* invalid value */
	uint8_t queue_index = 0;
	uint8_t tc = 0;
	uint8_t designator = 0;
	uint32_t i;
	int ret = 0;

	DEBUG("%s - attr-count: %u\n", __func__, attr_count);

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_QUEUE_ATTR_TYPE:
			queue_type = attr_list[i].value.u8;
			break;

		case FAL_QOS_QUEUE_ATTR_INDEX:
			queue_index = attr_list[i].value.u8;
			break;

		case FAL_QOS_QUEUE_ATTR_PARENT_ID:
			parent_id = attr_list[i].value.objid;
			break;

		case FAL_QOS_QUEUE_ATTR_WRED_ID:
			wred_id = attr_list[i].value.objid;
			break;

		case FAL_QOS_QUEUE_ATTR_BUFFER_ID:
			buffer_id = attr_list[i].value.objid;
			break;

		case FAL_QOS_QUEUE_ATTR_SCHEDULER_ID:
			sched_id = attr_list[i].value.objid;
			break;

		case FAL_QOS_QUEUE_ATTR_QUEUE_LIMIT:
			queue_limit = attr_list[i].value.u16;
			break;

		case FAL_QOS_QUEUE_ATTR_TC:
			tc = attr_list[i].value.u8;
			break;

		case FAL_QOS_QUEUE_ATTR_DESIGNATOR:
			designator = attr_list[i].value.u8;
			break;

		default:
			ERROR("%s: unknown qos queue attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			break;
		}
	}

	/*
	 * Mandatory create argument checking
	 */
	if (parent_id == FAL_QOS_NULL_OBJECT_ID ||
	    sched_id == FAL_QOS_NULL_OBJECT_ID ||
	    queue_type > FAL_QOS_QUEUE_TYPE_MAX) {
		ERROR("%s: mandatory queue create argument missing\n",
		      __func__);
		ret = -EINVAL;
	}
	if (!ret) {
		struct fal_bcm_qos_sched_group *parent_group;

		queue = fal_calloc(1, sizeof(*queue));
		if (!queue)
			return -ENOMEM;

		queue->switch_id = switch_id;
		queue->parent_id = parent_id;
		queue->sched_id = sched_id;
		queue->buffer_id = buffer_id;
		queue->wred_id = wred_id;
		queue->queue_index = queue_index;
		queue->queue_type = queue_type;
		queue->queue_limit = queue_limit;
		queue->tc = tc;
		queue->designator = designator;

		parent_group = (struct fal_bcm_qos_sched_group *)parent_id;
		TAILQ_INSERT_TAIL(&parent_group->queue_list, queue, peer_list);

		*new_queue_id = (fal_object_t)queue;
	}
	return 0;
}

/**
 * @brief Delete QoS queue
 *
 * @param[in] queue_id Queue id of queue to delete
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_del_queue(fal_object_t queue_id)
{
	struct fal_bcm_qos_queue *queue =
		(struct fal_bcm_qos_queue *)queue_id;
	int ret = 0;

	DEBUG("%s - %lx\n", __func__, queue_id);

	if (!queue)
		return -EINVAL;

	if (queue->parent_id != FAL_QOS_NULL_OBJECT_ID)
		ERROR("%s - deleting queue with link to parent\n", __func__);

	if (queue->sched_id != FAL_QOS_NULL_OBJECT_ID)
		ERROR("%s - deleting queue with link to scheduler\n", __func__);

	if (queue->wred_id != FAL_QOS_NULL_OBJECT_ID)
		ERROR("%s - deleting queue with link to wred\n", __func__);

	/*
	 * Finally free this queue.
	 */
	fal_free_deferred(queue);
	return ret;
}

/**
 * @brief Update QoS queue attribute
 *
 * @param[in] queue_id Queue ID to update
 * @param[in] attr Attribute to set
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_upd_queue(fal_object_t queue_id,
			     const struct fal_attribute_t *attr)
{
	struct fal_bcm_qos_queue *queue =
		(struct fal_bcm_qos_queue *)queue_id;
	struct fal_bcm_qos_sched_group *parent_group;
	int ret = 0;

	DEBUG("%s: queue: %lx, attribute-id: %u, object-id: %lx\n",
	     __func__, queue_id, attr->id, attr->value.objid);

	/*
	 * The only updates we allow are to break links to other objects
	 */
	if (attr->value.objid != FAL_QOS_NULL_OBJECT_ID) {
		ERROR("%s: cannot update queue with non-NULL object-id\n",
		      __func__);
		return -EINVAL;
	}

	switch (attr->id) {
	case FAL_QOS_QUEUE_ATTR_SCHEDULER_ID:
		queue->sched_id = attr->value.objid;
		break;

	case FAL_QOS_QUEUE_ATTR_WRED_ID:
		queue->wred_id = attr->value.objid;
		break;

	case FAL_QOS_QUEUE_ATTR_PARENT_ID:
		/*
		 * Detach the child from its parent.
		 */
		parent_group =
			(struct fal_bcm_qos_sched_group *)queue->parent_id;

		TAILQ_REMOVE(&parent_group->queue_list, queue, peer_list);
		queue->parent_id = attr->value.objid;
		break;

	case FAL_QOS_QUEUE_ATTR_TYPE:
	case FAL_QOS_QUEUE_ATTR_INDEX:
	case FAL_QOS_QUEUE_ATTR_BUFFER_ID:
	case FAL_QOS_QUEUE_ATTR_QUEUE_LIMIT:
	case FAL_QOS_QUEUE_ATTR_TC:
	case FAL_QOS_QUEUE_ATTR_DESIGNATOR:
		ERROR("%s: cannot update queue attribute-id %u\n",
		      __func__, attr->id);
		ret = -EINVAL;
		break;

	default:
		ERROR("%s: unknown queue attribute-id: %u\n",
		      __func__, attr->id);
		ret = -EINVAL;
		break;
	}
	return ret;
}

/**
 * @brief Get attributes from QoS Queue
 *
 * @param[in] queue_id Queue id to get the attributes from
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_get_queue_attrs(fal_object_t queue_id, uint32_t attr_count,
				   struct fal_attribute_t *attr_list)
{
	struct fal_bcm_qos_queue *queue =
		(struct fal_bcm_qos_queue *)queue_id;
	uint32_t i;
	int ret = 0;

	DEBUG("%s - %lx, attr-count: %u\n", __func__, queue_id, attr_count);

	if (!queue)
		return -EINVAL;

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_QUEUE_ATTR_TYPE:
			attr_list[i].value.u8 = queue->queue_type;
			break;

		case FAL_QOS_QUEUE_ATTR_INDEX:
			attr_list[i].value.u8 = queue->queue_index;
			break;

		case FAL_QOS_QUEUE_ATTR_PARENT_ID:
			attr_list[i].value.objid = queue->parent_id;
			break;

		case FAL_QOS_QUEUE_ATTR_WRED_ID:
			attr_list[i].value.objid = queue->wred_id;
			break;

		case FAL_QOS_QUEUE_ATTR_BUFFER_ID:
			attr_list[i].value.objid = queue->buffer_id;
			break;

		case FAL_QOS_QUEUE_ATTR_SCHEDULER_ID:
			attr_list[i].value.objid = queue->sched_id;
			break;

		case FAL_QOS_QUEUE_ATTR_QUEUE_LIMIT:
			attr_list[i].value.u16 = queue->queue_limit;
			break;

		case FAL_QOS_QUEUE_ATTR_TC:
			attr_list[i].value.u8 = queue->tc;
			break;

		case FAL_QOS_QUEUE_ATTR_DESIGNATOR:
			attr_list[i].value.u8 = queue->designator;
			break;

		default:
			ERROR("%s: unknown qos scheduler attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			break;
		}
	}
	return ret;
}

/**
 * @brief Get queue statistics counters.
 *
 * @param[in] queue_id Queue id to get the queue counters from
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[out] counters Array of resulting counter values.
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_get_queue_stats(fal_object_t queue_id,
				   uint32_t number_of_counters,
				   const uint32_t *counter_ids,
				   uint64_t *counters)
{
	struct fal_bcm_qos_queue *queue =
		(struct fal_bcm_qos_queue *)queue_id;
	uint32_t i;
	int rv = 0;

	if (!queue)
		return -EINVAL;

	for (i = 0; i < number_of_counters; i++) {
		switch (counter_ids[i]) {

		case FAL_QOS_QUEUE_STAT_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_DROPPED_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_DROPPED_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_GREEN_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_GREEN_DROPPED_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_GREEN_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_GREEN_DROPPED_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_YELLOW_DROPPED_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_YELLOW_DROPPED_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_RED_DROPPED_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_RED_DROPPED_BYTES:
			counters[i] = 0;
			break;

		default:
			DEBUG("%s: unknown qos queue counter-id %u\n",
			      __func__, counter_ids[i]);
			rv = -EINVAL;
			break;

		}
	}
	return rv;
}

/**
 * @brief Get queue statistics counters extended.
 *
 * Operates in two ways: just read the counter, or read and clear the counter.
 *
 * @param[in] queue_id Queue id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 * @param[in] read_and_clear Determines the mode of operation
 * @param[out] counters Array of resulting counter values
 *
 * @return 0 on success, failure status code on error
 */
int fal_plugin_qos_get_queue_stats_ext(fal_object_t queue_id,
				       uint32_t number_of_counters,
				       const uint32_t *counter_ids,
				       bool read_and_clear, uint64_t *counters)
{
	struct fal_bcm_qos_queue *queue =
		(struct fal_bcm_qos_queue *)queue_id;
	uint32_t i;
	int rv = 0;

	if (!queue)
		return -EINVAL;

	for (i = 0; i < number_of_counters; i++) {
		switch (counter_ids[i]) {

		case FAL_QOS_QUEUE_STAT_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_DROPPED_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_DROPPED_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_GREEN_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_GREEN_DROPPED_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_GREEN_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_GREEN_DROPPED_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_YELLOW_DROPPED_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_YELLOW_DROPPED_BYTES:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_RED_DROPPED_PACKETS:
			counters[i] = 0;
			break;

		case FAL_QOS_QUEUE_STAT_RED_DROPPED_BYTES:
			counters[i] = 0;
			break;

		default:
			ERROR("%s: unknown qos queue counter-id %u\n",
			      __func__, counter_ids[i]);
			rv = -EINVAL;
			break;

		}
	}
	return rv;
}

/**
 * @brief Clear queue statistics counters.
 *
 * @param[in] queue_id Queue id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_clear_queue_stats(fal_object_t queue_id,
				     uint32_t number_of_counters,
				     const uint32_t *counter_ids)
{
	DEBUG("%s - %lx - to be implemented\n", __func__, queue_id);
	return 0;
}

/**
 * @brief New Scheduler Profile
 *
 * @param[in] switch_id Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] new_scheduer_id Scheduler id
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_new_scheduler(fal_object_t switch_id, uint32_t attr_count,
				 const struct fal_attribute_t *attr_list,
				 fal_object_t *new_sched_id)
{
	struct fal_bcm_qos_sched *sched;
	uint8_t sched_type = FAL_QOS_SCHEDULING_TYPE_MAX + 1;  /* bad value */
	uint8_t sched_weight = 1;
	uint8_t meter_type = FAL_QOS_METER_TYPE_MAX + 1;  /* bad value */
	uint64_t max_bandwidth = 0;
	uint64_t max_burst = 0;
	int8_t overhead = 0;
	uint32_t i;
	int ret = 0;

	DEBUG("%s - attr-count: %u\n", __func__, attr_count);
	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_SCHEDULER_ATTR_SCHEDULING_TYPE:
			sched_type = attr_list[i].value.u8;
			break;

		case FAL_QOS_SCHEDULER_ATTR_SCHEDULING_WEIGHT:
			sched_weight = attr_list[i].value.u8;
			break;

		case FAL_QOS_SCHEDULER_ATTR_METER_TYPE:
			meter_type = attr_list[i].value.u8;
			break;

		case FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE:
			max_bandwidth = attr_list[i].value.u64;
			break;

		case FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE:
			max_burst = attr_list[i].value.u64;
			break;

		case FAL_QOS_SCHEDULER_ATTR_FRAME_OVERHEAD:
			overhead = attr_list[i].value.i8;
			break;

		default:
			ERROR("%s: unknown qos scheduler attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			break;
		}
	}

	/*
	 * Mandatory create argument checking
	 */
	if (sched_type > FAL_QOS_SCHEDULING_TYPE_MAX ||
	    meter_type > FAL_QOS_METER_TYPE_MAX) {
		ERROR("%s: mandatory scheduler create attribute missing\n",
		      __func__);
		ret = -EINVAL;
	}

	if (!ret) {
		sched = fal_calloc(1, sizeof(*sched));
		if (!sched)
			return -ENOMEM;

		sched->switch_id = switch_id;
		sched->sched_type = sched_type;
		sched->sched_weight = sched_weight;
		sched->meter_type = meter_type;
		sched->max_bandwidth = max_bandwidth;
		sched->max_burst = max_burst;
		sched->overhead = overhead;
		*new_sched_id = (fal_object_t)sched;
	}
	return ret;
}

/**
 * @brief Delete Scheduler profile
 *
 * @param[in] scheduler_id Scheduler id of scheduler to delete
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_del_scheduler(fal_object_t sched_id)
{
	struct fal_bcm_qos_sched *sched =
		(struct fal_bcm_qos_sched *)sched_id;

	DEBUG("%s - %lx\n", __func__, sched_id);
	if (!sched)
		return -EINVAL;

	fal_free_deferred(sched);
	return 0;
}

/**
 * @brief Set Scheduler Attribute
 *
 * @param[in] scheduler_id Scheduler id to update
 * @param[in] attr Attribute to set
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_upd_scheduler(fal_object_t sched_id,
				 const struct fal_attribute_t *attr)
{
	struct fal_bcm_qos_sched *sched =
		(struct fal_bcm_qos_sched *)sched_id;
	int ret = 0;

	DEBUG("%s - %lx\n", __func__, sched_id);

	if (!sched)
		return -EINVAL;

	switch (attr->id) {
	case FAL_QOS_SCHEDULER_ATTR_SCHEDULING_TYPE:
		if (sched->sched_type != attr->value.u8) {
			/*
			 * There is probably some real work to do here
			 */
			sched->sched_type = attr->value.u8;
		}
		break;

	case FAL_QOS_SCHEDULER_ATTR_SCHEDULING_WEIGHT:
		if (sched->sched_weight != attr->value.u8) {
			/*
			 * There is probably some real work to do here
			 */
			sched->sched_weight = attr->value.u8;
		}
		break;

	case FAL_QOS_SCHEDULER_ATTR_METER_TYPE:
		if (sched->meter_type != attr->value.u8) {
			/*
			 * There is probably some real work to do here
			 */
			sched->meter_type = attr->value.u8;
		}
		break;

	case FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE:
		if (sched->max_bandwidth != attr->value.u64) {
			/*
			 * There is probably some real work to do here
			 */
			sched->max_bandwidth = attr->value.u64;
		}
		break;

	case FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE:
		if (sched->max_burst != attr->value.u64) {
			/*
			 * There is probably some real work to do here
			 */
			sched->max_burst = attr->value.u64;
		}
		break;

	case FAL_QOS_SCHEDULER_ATTR_FRAME_OVERHEAD:
		if (sched->overhead != attr->value.i8) {
			/*
			 * There is probably some real work to do here
			 */
			sched->overhead = attr->value.i8;
		}
		break;

	default:
		ERROR("%s: unknown qos scheduler attribute-id %u\n",
		      __func__, attr->id);
		ret = -EINVAL;
		break;
	}

	return ret;
}

/**
 * @brief Get Scheduler attributes
 *
 * @param[in] scheduler_id Scheduler id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_get_scheduler_attrs(fal_object_t sched_id,
				       uint32_t attr_count,
				       struct fal_attribute_t *attr_list)
{
	struct fal_bcm_qos_sched *sched =
		(struct fal_bcm_qos_sched *)sched_id;
	uint32_t i;
	int ret = 0;

	DEBUG("%s - %lx, attr-count: %u\n", __func__, sched_id, attr_count);

	if (!sched)
		return -EINVAL;

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_SCHEDULER_ATTR_SCHEDULING_TYPE:
			attr_list[i].value.u8 = sched->sched_type;
			break;

		case FAL_QOS_SCHEDULER_ATTR_SCHEDULING_WEIGHT:
			attr_list[i].value.u8 = sched->sched_weight;
			break;

		case FAL_QOS_SCHEDULER_ATTR_METER_TYPE:
			attr_list[i].value.u8 = sched->meter_type;
			break;

		case FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_RATE:
			attr_list[i].value.u64 = sched->max_bandwidth;
			break;

		case FAL_QOS_SCHEDULER_ATTR_MAX_BANDWIDTH_BURST_RATE:
			attr_list[i].value.u64 = sched->max_burst;
			break;

		case FAL_QOS_SCHEDULER_ATTR_FRAME_OVERHEAD:
			attr_list[i].value.i8 = sched->overhead;
			break;

		default:
			ERROR("%s: unknown qos scheduler attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			break;
		}
	}
	return ret;
}

/**
 * @brief New Scheduler group
 *
 * @param[in] switch_id The Switch id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] new_sched_group_id Scheduler group id
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_new_sched_group(fal_object_t switch_id,
				   uint32_t attr_count,
				   const struct fal_attribute_t *attr_list,
				   fal_object_t *new_sched_group_id)
{
	struct fal_bcm_qos_sched_group *sched_group;
	fal_object_t sg_index = FAL_QOS_NULL_OBJECT_ID;
	fal_object_t sched_id = FAL_QOS_NULL_OBJECT_ID;
	fal_object_t parent_id = FAL_QOS_NULL_OBJECT_ID;
	fal_object_t ingress_map_id = FAL_QOS_NULL_OBJECT_ID;
	fal_object_t egress_map_id = FAL_QOS_NULL_OBJECT_ID;
	uint8_t max_children = 0;
	uint8_t sched_level;
	uint16_t vlan = 0;
	bool sg_index_present = false;
	bool sched_level_present = false;
	uint8_t lp_des;
	bool lp_des_present = false;
	uint32_t i;
	int ret = 0;

	DEBUG("%s - attr-count: %u\n", __func__, attr_count);

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_SCHED_GROUP_ATTR_SG_INDEX:
			sg_index = attr_list[i].value.objid;
			sg_index_present = true;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_LEVEL:
			sched_level = attr_list[i].value.u8;
			sched_level_present = true;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_MAX_CHILDREN:
			max_children = attr_list[i].value.u8;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_SCHEDULER_ID:
			sched_id = attr_list[i].value.objid;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_PARENT_ID:
			parent_id = attr_list[i].value.objid;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_INGRESS_MAP_ID:
			ingress_map_id = attr_list[i].value.objid;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_EGRESS_MAP_ID:
			egress_map_id = attr_list[i].value.objid;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_VLAN_ID:
			vlan = attr_list[i].value.u16;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_LOCAL_PRIORITY_DESIGNATOR:
			lp_des = attr_list[i].value.u8;
			lp_des_present = true;
			break;

		default:
			ERROR("%s: unknown sched-group attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			break;
		}
	}

	/*
	 * Mandatory create argument checking
	 */
	if (!ret && (sg_index_present == false ||
		     sched_level_present == false ||
		     max_children == 0 ||
		     (sched_level != FAL_QOS_SCHED_GROUP_LEVEL_PORT &&
		      parent_id == FAL_QOS_NULL_OBJECT_ID))) {
		ERROR("%s: mandatory sched-group create attribute missing\n",
		      __func__);
		ret = -EINVAL;
	}
	if (!ret && (sched_level != FAL_QOS_SCHED_GROUP_LEVEL_PIPE &&
		     ingress_map_id != FAL_QOS_NULL_OBJECT_ID &&
		     egress_map_id != FAL_QOS_NULL_OBJECT_ID)) {
		ERROR("%s: map-id specified for non pipe-level sched-group\n",
		      __func__);
		ret = -EINVAL;
	}

	if (!ret) {
		struct fal_bcm_qos_sched_group *parent_group;

		sched_group = fal_calloc(1, sizeof(*sched_group));
		if (!sched_group)
			return -ENOMEM;

		sched_group->sg_index = sg_index;
		sched_group->sched_level = sched_level;
		sched_group->max_children = max_children;
		sched_group->sched_id = sched_id;
		sched_group->parent_id = parent_id;
		sched_group->ingress_map_id = ingress_map_id;
		sched_group->egress_map_id = egress_map_id;
		sched_group->vlan = vlan;
		sched_group->local_prio_des = lp_des_present ? lp_des : -1;
		TAILQ_INIT(&sched_group->child_list);
		TAILQ_INIT(&sched_group->queue_list);
		if (parent_id != FAL_QOS_NULL_OBJECT_ID) {
			/*
			 * If we have a parent sched-group, add this sched-group
			 * to the parent's child list
			 */
			parent_group =
				(struct fal_bcm_qos_sched_group *)parent_id;
			TAILQ_INSERT_TAIL(&parent_group->child_list,
					  sched_group, peer_list);
		}
		*new_sched_group_id = (fal_object_t)sched_group;
	}
	return ret;
}

/**
 * @brief Delete Scheduler group
 *
 * @param[in] sched_group_id Scheduler group id
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_del_sched_group(fal_object_t sched_group_id)
{
	struct fal_bcm_qos_sched_group *sched_group =
		(struct fal_bcm_qos_sched_group *)sched_group_id;
	int ret = 0;

	DEBUG("%s - %lx\n", __func__, sched_group_id);

	if (!sched_group)
		return -EINVAL;

	if (sched_group->parent_id != FAL_QOS_NULL_OBJECT_ID)
		ERROR("%s: deleting sched-group with link to parent\n",
		      __func__);

	if (sched_group->sched_id != FAL_QOS_NULL_OBJECT_ID)
		ERROR("%s: deleting sched-group with link to scheduler\n",
		      __func__);

	if (sched_group->ingress_map_id != FAL_QOS_NULL_OBJECT_ID)
		ERROR("%s: deleting sched-group with link to ingress map\n",
		      __func__);

	if (sched_group->egress_map_id != FAL_QOS_NULL_OBJECT_ID)
		ERROR("%s: deleting sched-group with link to egress map\n",
		      __func__);

	if (sched_group->child_list.tqh_first != NULL)
		ERROR("%s: deleting sched-group with link to child "
		      "sched-group\n", __func__);

	if (sched_group->queue_list.tqh_first != NULL)
		ERROR("%s: deleting sched-group with link to child queue\n",
		      __func__);

	/*
	 * Finally free this sched-group.
	 */
	fal_free_deferred(sched_group);
	return ret;
}

/**
 * @brief Update Scheduler-group Attribute
 *
 * @param[in] sched_group_id Scheduler group id to be updated
 * @param[in] attr Attribute to set
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_upd_sched_group(fal_object_t sched_group_id,
				   const struct fal_attribute_t *attr)
{
	struct fal_bcm_qos_sched_group *sched_group =
		(struct fal_bcm_qos_sched_group *)sched_group_id;
	int ret = 0;

	if (sched_group == FAL_QOS_NULL_OBJECT_ID)
		return -EINVAL;

	DEBUG("%s - %lx\n", __func__, sched_group_id);

	switch (attr->id) {
	case FAL_QOS_SCHED_GROUP_ATTR_SG_INDEX:
	case FAL_QOS_SCHED_GROUP_ATTR_LEVEL:
	case FAL_QOS_SCHED_GROUP_ATTR_MAX_CHILDREN:
	case FAL_QOS_SCHED_GROUP_ATTR_VLAN_ID:
	case FAL_QOS_SCHED_GROUP_ATTR_LOCAL_PRIORITY_DESIGNATOR:
		ERROR("%s: cannot update sched-group attribute-id %u\n",
		      __func__, attr->id);
		ret = -EINVAL;
		break;

	case FAL_QOS_SCHED_GROUP_ATTR_PARENT_ID:
		if (sched_group->parent_id != attr->value.objid) {
			/*
			 * Detach the child from its parent.
			 */
			struct fal_bcm_qos_sched_group *parent_group =
				(struct fal_bcm_qos_sched_group *)
				sched_group->parent_id;

			TAILQ_REMOVE(&parent_group->child_list, sched_group,
				     peer_list);
			sched_group->parent_id = attr->value.objid;
		}
		break;

	case FAL_QOS_SCHED_GROUP_ATTR_SCHEDULER_ID:
		if (sched_group->sched_id != attr->value.objid) {
			/*
			 * There is probably some real work to do here
			 */
			sched_group->sched_id = attr->value.objid;
		}
		break;

	case FAL_QOS_SCHED_GROUP_ATTR_INGRESS_MAP_ID:
		if (sched_group->ingress_map_id != attr->value.objid) {
			/*
			 * There is probably some real work to do here
			 */
			sched_group->ingress_map_id = attr->value.objid;
		}
		break;

	case FAL_QOS_SCHED_GROUP_ATTR_EGRESS_MAP_ID:
		if (sched_group->egress_map_id != attr->value.objid) {
			/*
			 * There is probably some real work to do here
			 */
			sched_group->egress_map_id = attr->value.objid;
		}
		break;

	default:
		ERROR("%s: unknown sched-group attribute-id %u\n",
		      __func__, attr->id);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static
uint32_t get_sched_group_child_count(struct fal_bcm_qos_sched_group *parent)
{
	struct  fal_bcm_qos_sched_group *child;
	struct  fal_bcm_qos_queue *queue;
	uint32_t child_count = 0;

	if (parent->sched_level == FAL_QOS_SCHED_GROUP_LEVEL_TC)
		TAILQ_FOREACH(queue, &parent->queue_list, peer_list) {
			child_count++;
		}
	else
		TAILQ_FOREACH(child, &parent->child_list, peer_list) {
			child_count++;
		}

	return child_count;
}

/**
 * @brief Get Scheduler Group attributes
 *
 * @param[in] sched_group_id Scheduler group id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_get_sched_group_attrs(fal_object_t sched_group_id,
					 uint32_t attr_count,
					 struct fal_attribute_t *attr_list)
{
	struct fal_bcm_qos_sched_group *sched_group =
		(struct fal_bcm_qos_sched_group *)sched_group_id;
	struct fal_bcm_qos_sched_group *child;
	struct fal_bcm_qos_queue *queue;
	struct fal_object_list_t *obj_list;
	uint32_t child_count = 0;
	uint32_t i;

	DEBUG("%s - %lx, attr-count: %u\n",
	     __func__, sched_group_id, attr_count);

	if (!sched_group)
		return -EINVAL;

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_SCHED_GROUP_ATTR_SG_INDEX:
			attr_list[i].value.objid = sched_group->sg_index;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_LEVEL:
			attr_list[i].value.u8 = sched_group->sched_level;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_MAX_CHILDREN:
			attr_list[i].value.u8 = sched_group->max_children;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_SCHEDULER_ID:
			attr_list[i].value.objid = sched_group->sched_id;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_PARENT_ID:
			attr_list[i].value.objid = sched_group->parent_id;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_CHILD_COUNT:
			attr_list[i].value.u32 =
				get_sched_group_child_count(sched_group);
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_CHILD_LIST:
			obj_list = attr_list[i].value.objlist;
			obj_list->count = child_count;
			if (sched_group->sched_level ==
			    FAL_QOS_SCHED_GROUP_LEVEL_TC)
				TAILQ_FOREACH(queue, &sched_group->queue_list,
					      peer_list) {
					obj_list->list[child_count] =
						(fal_object_t)queue;
					obj_list->count = ++child_count;
				}
			else
				TAILQ_FOREACH(child, &sched_group->child_list,
					      peer_list) {
					obj_list->list[child_count] =
						(fal_object_t)child;
					obj_list->count = ++child_count;
				}
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_INGRESS_MAP_ID:
			attr_list[i].value.objid = sched_group->ingress_map_id;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_EGRESS_MAP_ID:
			attr_list[i].value.objid = sched_group->egress_map_id;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_VLAN_ID:
			attr_list[i].value.u16 = sched_group->vlan;
			break;

		case FAL_QOS_SCHED_GROUP_ATTR_LOCAL_PRIORITY_DESIGNATOR:
			attr_list[i].value.u8 = sched_group->local_prio_des;
			break;

		default:
			DEBUG("%s - attr-id %u not yet implemented\n",
			     __func__, attr_list[i].id);
			break;
		}
	}
	return 0;
}

/**
 * @brief New WRED Profile
 *
 * @param[in] switch_id Switch Id
 * @param[in] attr_count Number of attributes
 * @param[in] attr_list Array of attributes
 * @param[out] new_wred_id WRED profile Id.
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_new_wred(fal_object_t switch_id, uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *new_wred_id)
{
	struct fal_bcm_qos_wred *wred;
	bool green_enabled = false;
	uint32_t green_min_threshold = 0;
	uint32_t green_max_threshold = 0;
	uint32_t green_drop_probability = 0;
	bool yellow_enabled = false;
	uint32_t yellow_min_threshold = 0;
	uint32_t yellow_max_threshold = 0;
	uint32_t yellow_drop_probability = 0;
	bool red_enabled = false;
	uint32_t red_min_threshold = 0;
	uint32_t red_max_threshold = 0;
	uint32_t red_drop_probability = 0;
	uint32_t filter_weight = 0;
	uint32_t i;
	int ret = 0;

	DEBUG("%s - attr-count: %u\n", __func__, attr_count);

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_WRED_ATTR_GREEN_ENABLE:
			green_enabled = attr_list[i].value.booldata;
			break;

		case FAL_QOS_WRED_ATTR_GREEN_MIN_THRESHOLD:
			green_min_threshold = attr_list[i].value.u32;
			break;

		case FAL_QOS_WRED_ATTR_GREEN_MAX_THRESHOLD:
			green_max_threshold = attr_list[i].value.u32;
			break;

		case FAL_QOS_WRED_ATTR_GREEN_DROP_PROBABILITY:
			green_drop_probability = attr_list[i].value.u32;
			break;

		case FAL_QOS_WRED_ATTR_YELLOW_ENABLE:
			yellow_enabled = attr_list[i].value.booldata;
			break;

		case FAL_QOS_WRED_ATTR_YELLOW_MIN_THRESHOLD:
			yellow_min_threshold = attr_list[i].value.u32;
			break;

		case FAL_QOS_WRED_ATTR_YELLOW_MAX_THRESHOLD:
			yellow_max_threshold = attr_list[i].value.u32;
			break;

		case FAL_QOS_WRED_ATTR_YELLOW_DROP_PROBABILITY:
			yellow_drop_probability = attr_list[i].value.u32;
			break;

		case FAL_QOS_WRED_ATTR_RED_ENABLE:
			red_enabled = attr_list[i].value.booldata;
			break;

		case FAL_QOS_WRED_ATTR_RED_MIN_THRESHOLD:
			red_min_threshold = attr_list[i].value.u32;
			break;

		case FAL_QOS_WRED_ATTR_RED_MAX_THRESHOLD:
			red_max_threshold = attr_list[i].value.u32;
			break;

		case FAL_QOS_WRED_ATTR_RED_DROP_PROBABILITY:
			red_drop_probability = attr_list[i].value.u32;
			break;

		case FAL_QOS_WRED_ATTR_WEIGHT:
			filter_weight = attr_list[i].value.u8;
			break;

		default:
			ERROR("%s: unknown qos scheduler attribute-id %u\n",
			      __func__, attr_list[i].id);
			ret = -EINVAL;
			break;
		}
	}

	/*
	 * Mandatory create argument checking
	 */
	if (!ret && (green_min_threshold == 0 || green_max_threshold == 0)) {
		ERROR("%s: mandatory wred create attribute missing\n",
		      __func__);
		ret = -EINVAL;
	}

	if (!ret) {
		wred = fal_calloc(1, sizeof(*wred));
		if (!wred)
			return -ENOMEM;

		wred->green_enabled = green_enabled;
		wred->green_min_threshold = green_min_threshold;
		wred->green_max_threshold = green_max_threshold;
		wred->green_drop_probability = green_drop_probability;
		wred->yellow_enabled = yellow_enabled;
		wred->yellow_min_threshold = yellow_min_threshold;
		wred->yellow_max_threshold = yellow_max_threshold;
		wred->yellow_drop_probability = yellow_drop_probability;
		wred->red_enabled = red_enabled;
		wred->red_min_threshold = red_min_threshold;
		wred->red_max_threshold = red_max_threshold;
		wred->red_drop_probability = red_drop_probability;
		wred->filter_weight = filter_weight;

		*new_wred_id = (fal_object_t)wred;
	}
	return ret;
}

/**
 * @brief Delete WRED Profile
 *
 * @param[in] wred_id WRED profile Id to be deleted.
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_del_wred(fal_object_t wred_id)
{
	struct fal_bcm_qos_wred *wred = (struct fal_bcm_qos_wred *)wred_id;

	DEBUG("%s - %lx\n", __func__, wred_id);

	if (!wred)
		return -EINVAL;

	fal_free_deferred(wred);
	return 0;
}

/**
 * @brief Update attribute of WRED profile.
 *
 * @param[in] wred_id WRED profile Id.
 * @param[in] attr Attribute
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_upd_wred(fal_object_t wred_id,
			    const struct fal_attribute_t *attr)
{
	DEBUG("%s - %lx - to be implemented\n", __func__, wred_id);
	return 0;
}

/**
 * @brief Get WRED profile attributes
 *
 * @param[in] wred_if WRED Profile Id
 * @param[in] attr_count Number of attributes
 * @param[inout] attr_list Array of attributes
 *
 * @return 0 on success, failure status code on error
 */
__FOR_EXPORT
int fal_plugin_qos_get_wred_attrs(fal_object_t wred_id, uint32_t attr_count,
				  struct fal_attribute_t *attr_list)
{
	struct fal_bcm_qos_wred *wred =	(struct fal_bcm_qos_wred *)wred_id;
	uint32_t i;

	DEBUG("%s - %lx, attr_count: %u\n",  __func__, wred_id, attr_count);

	if (!wred)
		return -EINVAL;

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_QOS_WRED_ATTR_GREEN_ENABLE:
			attr_list[i].value.booldata = wred->green_enabled;
			break;

		case FAL_QOS_WRED_ATTR_GREEN_MIN_THRESHOLD:
			attr_list[i].value.u32 = wred->green_min_threshold;
			break;

		case FAL_QOS_WRED_ATTR_GREEN_MAX_THRESHOLD:
			attr_list[i].value.u32 = wred->green_max_threshold;
			break;

		case FAL_QOS_WRED_ATTR_GREEN_DROP_PROBABILITY:
			attr_list[i].value.u32 = wred->green_drop_probability;
			break;

		case FAL_QOS_WRED_ATTR_YELLOW_ENABLE:
			attr_list[i].value.booldata = wred->yellow_enabled;
			break;

		case FAL_QOS_WRED_ATTR_YELLOW_MIN_THRESHOLD:
			attr_list[i].value.u32 = wred->yellow_min_threshold;
			break;

		case FAL_QOS_WRED_ATTR_YELLOW_MAX_THRESHOLD:
			attr_list[i].value.u32 = wred->yellow_max_threshold;
			break;

		case FAL_QOS_WRED_ATTR_YELLOW_DROP_PROBABILITY:
			attr_list[i].value.u32 = wred->yellow_drop_probability;
			break;

		case FAL_QOS_WRED_ATTR_RED_ENABLE:
			attr_list[i].value.booldata = wred->red_enabled;
			break;

		case FAL_QOS_WRED_ATTR_RED_MIN_THRESHOLD:
			attr_list[i].value.u32 = wred->red_min_threshold;
			break;

		case FAL_QOS_WRED_ATTR_RED_MAX_THRESHOLD:
			attr_list[i].value.u32 = wred->red_max_threshold;
			break;

		case FAL_QOS_WRED_ATTR_RED_DROP_PROBABILITY:
			attr_list[i].value.u32 = wred->red_drop_probability;
			break;

		case FAL_QOS_WRED_ATTR_WEIGHT:
			attr_list[i].value.u8 = wred->filter_weight;
			break;

		default:
			DEBUG("%s - attr-id %u not yet implemented\n",
			     __func__, attr_list[i].id);
			break;
		}
	}

	return 0;
}

/**
 * @brief Get value from hardware counter registers
 *
 * @param[in] cntr_ids   Array for IDs of counters
 * @param[in] num_cntrs  Number of ID in 'cntr_ids'
 * @param[inout] cntrs   Array for value of counters
 *
 * @return 0 on success, failure otherwise
 */
__FOR_EXPORT
int fal_plugin_qos_get_counters(const uint32_t *cntr_ids, uint32_t num_cntrs,
			uint64_t *cntrs)
{
	static int idx;
	struct fal_bcm_qos_ext_buf_cntr buf_cntr[] = {
		{50000, 0}, {3000, 0}, {50000, 0}, {50000, 1}, {3000, 0},
		{3000, 1}, {3000, 0}
	};
	int array_size = ARRAY_SIZE(buf_cntr);

	for (uint32_t i = 0; i < num_cntrs; i++) {
		if (cntr_ids[i] == FAL_QOS_EXTERNAL_BUFFER_COUNTER_ID)
			cntrs[i] = buf_cntr[idx].buf_free;
		else if (cntr_ids[i] ==
			FAL_QOS_EXTERNAL_BUFFER_PKT_REJECT_COUNTER_ID)
			cntrs[i] = buf_cntr[idx].dropped;
	}

	idx = (idx + 1) % array_size;

	return 0;
}
