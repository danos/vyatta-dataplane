/*-
 * Copyright (c) 2018, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef QOS_OBJ_DB_H
#define QOS_OBJ_DB_H

#include <stdarg.h>
#include <fal_plugin.h>

#include "json_writer.h"

enum qos_obj_db_level {
	QOS_OBJ_DB_LEVEL_MIN = 1,
	QOS_OBJ_DB_LEVEL_PORT = QOS_OBJ_DB_LEVEL_MIN,
	QOS_OBJ_DB_LEVEL_SUBPORT,
	QOS_OBJ_DB_LEVEL_PIPE,
	QOS_OBJ_DB_LEVEL_TC,
	QOS_OBJ_DB_LEVEL_QUEUE,
	QOS_OBJ_DB_LEVEL_MAX = QOS_OBJ_DB_LEVEL_QUEUE,

};
#define QOS_OBJ_DB_ID_ARRAY_LEN (QOS_OBJ_DB_LEVEL_MAX + 1)

enum qos_obj_db_status {
	QOS_OBJ_DB_STATUS_SUCCESS = 0,
	QOS_OBJ_DB_STATUS_INVARG,
	QOS_OBJ_DB_STATUS_NOTFOUND,
	QOS_OBJ_DB_STATUS_NOMEM,
	QOS_OBJ_DB_STATUS_WALKSTOPPED,
	QOS_OBJ_DB_STATUS_OBJEXISTS,
};

enum qos_obj_sw_state {
	QOS_OBJ_SW_STATE_NULL = 0,
	QOS_OBJ_SW_STATE_ALLOCATED,
	QOS_OBJ_SW_STATE_HW_PROG_IN_PROGRESS,
	QOS_OBJ_SW_STATE_HW_PROG_FAILED,
	QOS_OBJ_SW_STATE_HW_PROG_PARTIAL,
	QOS_OBJ_SW_STATE_HW_PROG_SUCCESSFUL,
	QOS_OBJ_SW_STATE_HW_DEL_IN_PROGRESS,
	QOS_OBJ_SW_STATE_HW_DEL_COMPLETE,
	QOS_OBJ_SW_STATE_MAX = QOS_OBJ_SW_STATE_HW_DEL_COMPLETE,
};
#define QOS_OBJ_SW_STATE_ARRAY_LEN (QOS_OBJ_SW_STATE_MAX + 1)

enum qos_obj_hw_type {
	QOS_OBJ_HW_TYPE_MIN = 0,
	QOS_OBJ_HW_TYPE_SCHED_GROUP = QOS_OBJ_HW_TYPE_MIN,
	QOS_OBJ_HW_TYPE_SCHEDULER,
	QOS_OBJ_HW_TYPE_INGRESS_MAP,
	QOS_OBJ_HW_TYPE_EGRESS_MAP,
	QOS_OBJ_HW_TYPE_QUEUE,
	QOS_OBJ_HW_TYPE_WRED,
	QOS_OBJ_HW_TYPE_MAX = QOS_OBJ_HW_TYPE_WRED,
};
#define QOS_OBJ_HW_TYPE_ARRAY_LEN (QOS_OBJ_HW_TYPE_MAX + 1)

struct qos_obj_db_obj;

/*
 * Maximum ids string length is 18 characters, rounded up to the next power of
 * two to allow for some leeway = 32.
 * 18 = 4 for port-id, 4 for subport-id, 3 for pipe-id, 1 for tc-id, 1 for
 * queue-id, plus 4 spaces and the trailing NULL terminator.
 */
#define QOS_OBJ_DB_MAX_ID_LEN 32

const char *qos_obj_db_get_sw_state_str(enum qos_obj_sw_state sw_state);

const char *qos_obj_db_get_hw_type_str(enum qos_obj_hw_type hw_type);

char *qos_obj_db_get_ids_string(enum qos_obj_db_level level, uint32_t *ids,
				int32_t max_len, char *ids_string);

enum qos_obj_db_status qos_obj_db_create(enum qos_obj_db_level level,
					 uint32_t *ids,
					 void(*delete_callback)
					 (struct qos_obj_db_obj *db_obj),
					 struct qos_obj_db_obj **out_db_obj);

enum qos_obj_db_status qos_obj_db_retrieve(enum qos_obj_db_level level,
					   uint32_t *ids,
					   struct qos_obj_db_obj **out_db_obj);

void qos_obj_db_sw_set(struct qos_obj_db_obj *db_obj,
		       enum qos_obj_sw_state sw_state);

void qos_obj_db_sw_get(struct qos_obj_db_obj *db_obj,
		       enum qos_obj_sw_state *sw_state);

void qos_obj_db_hw_set(struct qos_obj_db_obj *db_obj,
		       enum qos_obj_hw_type hw_type, int32_t hw_status,
		       fal_object_t object_id);

void qos_obj_db_hw_get(struct qos_obj_db_obj *db_obj,
		       enum qos_obj_hw_type hw_type, int32_t *hw_status,
		       fal_object_t *hw_object_id);

enum qos_obj_db_status qos_obj_db_delete(enum qos_obj_db_level level,
					 uint32_t *ids);

enum qos_obj_db_status qos_obj_db_walk(int (*walk_callback)
				       (void *context,
					struct qos_obj_db_obj *db_obj,
					enum qos_obj_db_level level,
					uint32_t *ids),
				       void *context);
#endif /* QOS_OBJ_DB_H */
