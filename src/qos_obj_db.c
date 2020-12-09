/*-
 * Copyright (c) 2018-2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * The module provides a five-level object database.
 * Objects at the top "port" level have a single identifier. Objects at the
 * "subport" level have two identifiers.  This pattern continues down to
 * the lowest "queue" level objects that have five identifiers.
 *
 * Objects have a sw part and multiple hw parts.  The idea is to allow sw
 * objects to exist and try to create their associated hw objects, which may
 * fail due to restrictions of the hardware platform.  We don't want to delete
 * the sw object when this happens as we want to be able to operate with a
 * partial configuration and also be able to report where and why these partial
 * configurations occurred.
 *
 * Some words of warning!
 *
 * Creating a lower level object will create all the necessary higher level
 * objects if they don't already exist.
 *
 * Deleting an upper level object will delete all the child objects below it.
 *
 * The current implementation is crude and uses a list of nodes at each level,
 * with each node having a list of children nodes that belong to the next level
 * down.  The lists are not ordered and need to be searched from head to tail
 * to find the appropriate matching node.
 *
 * Since we know the three lower layers have bounded ranges: pipes 0-255,
 * tcs 0-3 and queues 0-7, the three lower layers could be implemented as a
 * radix tree.
 */

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <rte_log.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include <fal_plugin.h>

#include "json_writer.h"
#include "qos_obj_db.h"
#include "urcu.h"
#include "vplane_debug.h"
#include "vplane_log.h"

_Static_assert((uint32_t)QOS_OBJ_DB_LEVEL_PORT ==
	       (uint32_t)FAL_QOS_SCHED_GROUP_LEVEL_PORT,
	       "FAL/QoS object database port-level mismatch");
_Static_assert((uint32_t)QOS_OBJ_DB_LEVEL_SUBPORT ==
	       (uint32_t)FAL_QOS_SCHED_GROUP_LEVEL_SUBPORT,
	       "FAL/QoS object database subport-level mismatch");
_Static_assert((uint32_t)QOS_OBJ_DB_LEVEL_PIPE ==
	       (uint32_t)FAL_QOS_SCHED_GROUP_LEVEL_PIPE,
	       "FAL/QoS object database pipe-level mismatch");
_Static_assert((uint32_t)QOS_OBJ_DB_LEVEL_TC ==
	       (uint32_t)FAL_QOS_SCHED_GROUP_LEVEL_TC,
	       "FAL/QoS object database tc-level mismatch");
_Static_assert((uint32_t)QOS_OBJ_DB_LEVEL_QUEUE ==
	       (uint32_t)FAL_QOS_SCHED_GROUP_LEVEL_QUEUE,
	       "FAL/QoS object database queue-level mismatch");

struct qos_obj_hw_obj {
	int32_t hw_status;
	fal_object_t object_id;
};

struct qos_obj_db_obj {
	struct rcu_head obj_rcu;
	struct cds_list_head peer_list;
	uint32_t id;
	void (*delete_callback)(struct qos_obj_db_obj *db_obj);
	enum qos_obj_sw_state sw_state;
	struct qos_obj_hw_obj hw_object[QOS_OBJ_HW_TYPE_ARRAY_LEN];
	struct cds_list_head child_list;
};

static CDS_LIST_HEAD(qos_obj_db_head);

const char *qos_obj_sw_state_str[QOS_OBJ_SW_STATE_ARRAY_LEN] = {
	[QOS_OBJ_SW_STATE_NULL] = "null",
	[QOS_OBJ_SW_STATE_ALLOCATED] = "allocated",
	[QOS_OBJ_SW_STATE_HW_PROG_IN_PROGRESS] = "hw programming in progress",
	[QOS_OBJ_SW_STATE_HW_PROG_FAILED] = "hw programming failed",
	[QOS_OBJ_SW_STATE_HW_PROG_PARTIAL] =
	"hw programming partially successful",
	[QOS_OBJ_SW_STATE_HW_PROG_SUCCESSFUL] = "hw programming successful",
	[QOS_OBJ_SW_STATE_HW_DEL_IN_PROGRESS] =
	"hw programming deletion in progress",
	[QOS_OBJ_SW_STATE_HW_DEL_COMPLETE] = "hw programming deletion complete"
};

const char *
qos_obj_db_get_sw_state_str(enum qos_obj_sw_state sw_state)
{
	return qos_obj_sw_state_str[sw_state];
}

const char *qos_obj_hw_type_str[QOS_OBJ_HW_TYPE_ARRAY_LEN] = {
	[QOS_OBJ_HW_TYPE_SCHED_GROUP] = "scheduler-group",
	[QOS_OBJ_HW_TYPE_SCHEDULER] = "scheduler",
	[QOS_OBJ_HW_TYPE_INGRESS_MAP] = "ingress-map",
	[QOS_OBJ_HW_TYPE_EGRESS_MAP] = "egress-map",
	[QOS_OBJ_HW_TYPE_QUEUE] = "queue",
	[QOS_OBJ_HW_TYPE_WRED] = "wred"
};

const char *
qos_obj_db_get_hw_type_str(enum qos_obj_hw_type hw_type)
{
	return qos_obj_hw_type_str[hw_type];
}

char *
qos_obj_db_get_ids_string(enum qos_obj_db_level level, uint32_t *ids,
			  int32_t max_len, char *ids_string)
{
	int32_t total_len = 0;
	int32_t len = 0;
	uint32_t i;

	for (i = 1; max_len > 0 && len >= 0 && i <= level; i++) {
		len = snprintf(ids_string + total_len, max_len, "%u ", ids[i]);
		total_len += len;
		max_len -= len;
	}
	if (max_len >= 0 && len >= 0) {
		ids_string[total_len - 1] = '\0';
		return ids_string;
	}
	return NULL;
}

static void
qos_obj_db_init_obj(struct qos_obj_db_obj *db_obj, uint32_t id)
{
	/* No need to initialise other fields, the db_obj has been zeroed */
	db_obj->id = id;
	CDS_INIT_LIST_HEAD(&db_obj->child_list);
}

enum qos_obj_db_status
qos_obj_db_create(enum qos_obj_db_level level, uint32_t *ids,
		  void (*delete_callback)(struct qos_obj_db_obj *db_obj),
		  struct qos_obj_db_obj **out_db_obj)
{
	struct qos_obj_db_obj *db_obj;
	struct cds_list_head *headp;
	char ids_str[QOS_OBJ_DB_MAX_ID_LEN + 1];
	char *out_str;
	enum qos_obj_db_status ret = QOS_OBJ_DB_STATUS_NOTFOUND;
	enum qos_obj_db_level i;

	if (level < QOS_OBJ_DB_LEVEL_MIN || level > QOS_OBJ_DB_LEVEL_MAX ||
	    ids == NULL ||  out_db_obj == NULL || delete_callback == NULL)
		return QOS_OBJ_DB_STATUS_INVARG;

	headp = &qos_obj_db_head;
	for (i = QOS_OBJ_DB_LEVEL_PORT; i <= level; i++) {
		cds_list_for_each_entry(db_obj, headp, peer_list) {
			if (db_obj->id == ids[i])
				break;
		}
		if (&db_obj->peer_list == headp) {
			db_obj = calloc(1, sizeof(struct qos_obj_db_obj));
			if (!db_obj) {
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "out of memory\n");
				return QOS_OBJ_DB_STATUS_NOMEM;
			}
			qos_obj_db_init_obj(db_obj, ids[i]);
			cds_list_add_tail_rcu(&db_obj->peer_list, headp);
			if (i == level) {
				out_str = qos_obj_db_get_ids_string(level, ids,
						QOS_OBJ_DB_MAX_ID_LEN, ids_str);
				DP_DEBUG(QOS, DEBUG, DATAPLANE,
					 "created QoS sw object (%p) id: %s\n",
					 db_obj, out_str);
				db_obj->delete_callback = delete_callback;
				*out_db_obj = db_obj;
				return QOS_OBJ_DB_STATUS_SUCCESS;
			}
		} else {
			if (i == level) {
				out_str = qos_obj_db_get_ids_string(level, ids,
						QOS_OBJ_DB_MAX_ID_LEN, ids_str);
				DP_DEBUG(QOS, ERR, DATAPLANE,
					 "pre-existing QoS sw object (%p) id: "
					 "%s\n", db_obj, out_str);
				return QOS_OBJ_DB_STATUS_OBJEXISTS;
			}
		}
		headp = &db_obj->child_list;
	}

	return ret;
}

enum qos_obj_db_status
qos_obj_db_retrieve(enum qos_obj_db_level level, uint32_t *ids,
		    struct qos_obj_db_obj **out_db_obj)
{
	struct qos_obj_db_obj *db_obj;
	struct cds_list_head *headp;
	char ids_str[QOS_OBJ_DB_MAX_ID_LEN + 1];
	char *out_str;
	enum qos_obj_db_status ret = QOS_OBJ_DB_STATUS_NOTFOUND;
	enum qos_obj_db_level i;

	if (level < QOS_OBJ_DB_LEVEL_MIN || level > QOS_OBJ_DB_LEVEL_MAX ||
	    ids == NULL || out_db_obj == NULL)
		return QOS_OBJ_DB_STATUS_INVARG;

	*out_db_obj = NULL;
	headp = &qos_obj_db_head;
	for (i = QOS_OBJ_DB_LEVEL_PORT; i <= level; i++) {
		cds_list_for_each_entry(db_obj, headp, peer_list) {
			if (db_obj->id == ids[i])
				break;
		}
		if (&db_obj->peer_list == headp)
			return QOS_OBJ_DB_STATUS_NOTFOUND;

		if (i == level) {
			out_str = qos_obj_db_get_ids_string(level, ids,
					QOS_OBJ_DB_MAX_ID_LEN, ids_str);
			/*
			 * The following debug is very chatty for queue level
			 * objects due to the vyatta-dataplane stats polling
			 * thread that retrieves the counters for each queue
			 * about once every five seconds.
			 */
			if (level != QOS_OBJ_DB_LEVEL_QUEUE)
				DP_DEBUG(QOS, DEBUG, DATAPLANE,
					 "found QoS sw object (%p) id: %s\n",
					 db_obj, out_str);

			*out_db_obj = db_obj;
			return QOS_OBJ_DB_STATUS_SUCCESS;
		}
		headp = &db_obj->child_list;
	}

	return ret;
}

void
qos_obj_db_sw_set(struct qos_obj_db_obj *db_obj, enum qos_obj_sw_state sw_state)
{
	assert(db_obj != NULL);

	db_obj->sw_state = sw_state;
}

void
qos_obj_db_sw_get(struct qos_obj_db_obj *db_obj,
		  enum qos_obj_sw_state *sw_state)
{
	assert(db_obj != NULL && sw_state != NULL);

	*sw_state = db_obj->sw_state;
}

void
qos_obj_db_hw_set(struct qos_obj_db_obj *db_obj, enum qos_obj_hw_type hw_type,
		  int32_t hw_status, fal_object_t object_id)
{
	struct qos_obj_hw_obj *hw_obj;

	assert(db_obj != NULL && QOS_OBJ_HW_TYPE_MIN <= hw_type &&
	       hw_type <= QOS_OBJ_HW_TYPE_MAX);

	hw_obj = &db_obj->hw_object[hw_type];
	hw_obj->hw_status = hw_status;
	hw_obj->object_id = object_id;

	DP_DEBUG(QOS, DEBUG, DATAPLANE,
		 "updated QoS object (%p), hw-type: %u, hw-status: %d, "
		 "hw-object: %lx\n", db_obj, hw_type, hw_status,
		 object_id);
}

void
qos_obj_db_hw_get(struct qos_obj_db_obj *db_obj, enum qos_obj_hw_type hw_type,
		  int32_t *hw_status, fal_object_t *hw_object_id)
{
	struct qos_obj_hw_obj *hw_obj;

	assert(db_obj != NULL && QOS_OBJ_HW_TYPE_MIN <= hw_type &&
	       hw_type <= QOS_OBJ_HW_TYPE_MAX && hw_status != NULL &&
	       hw_object_id != NULL);

	hw_obj = &db_obj->hw_object[hw_type];
	*hw_status = hw_obj->hw_status;
	*hw_object_id = hw_obj->object_id;
}

static void
qos_obj_db_object_free(struct rcu_head *head)
{
	struct qos_obj_db_obj *db_obj =
		caa_container_of(head, struct qos_obj_db_obj, obj_rcu);

	free(db_obj);
}

static void
qos_obj_db_delete_children(struct qos_obj_db_obj *parent)
{
	struct qos_obj_db_obj *child;

	cds_list_for_each_entry_rcu(child, &parent->child_list, peer_list) {
		cds_list_del_rcu(&child->peer_list);
		qos_obj_db_delete_children(child);
		if (child->delete_callback != NULL)
			(child->delete_callback)(child);
		call_rcu(&child->obj_rcu, qos_obj_db_object_free);
	}
}

enum qos_obj_db_status
qos_obj_db_delete(enum qos_obj_db_level level, uint32_t *ids)
{
	struct qos_obj_db_obj *db_obj;
	struct cds_list_head *headp;
	enum qos_obj_db_level i;
	enum qos_obj_db_status ret = QOS_OBJ_DB_STATUS_NOTFOUND;

	if (level < QOS_OBJ_DB_LEVEL_MIN || level > QOS_OBJ_DB_LEVEL_MAX ||
	    ids == NULL)
		return QOS_OBJ_DB_STATUS_INVARG;

	headp = &qos_obj_db_head;
	for (i = QOS_OBJ_DB_LEVEL_PORT; i <= level; i++) {
		cds_list_for_each_entry_rcu(db_obj, headp, peer_list) {
			if (db_obj->id == ids[i])
				break;
		}
		if (&db_obj->peer_list == headp)
			return ret;

		if (i == level) {
			char ids_str[QOS_OBJ_DB_MAX_ID_LEN + 1];
			char *out_str;

			out_str = qos_obj_db_get_ids_string(level, ids,
					QOS_OBJ_DB_MAX_ID_LEN, ids_str);
			DP_DEBUG(QOS, DEBUG, DATAPLANE,
				 "delete QoS object (%p) id: %s\n", db_obj,
				 out_str);
			cds_list_del_rcu(&db_obj->peer_list);
			qos_obj_db_delete_children(db_obj);
			if (db_obj->delete_callback != NULL)
				(db_obj->delete_callback)(db_obj);
			call_rcu(&db_obj->obj_rcu, qos_obj_db_object_free);

			/*
			 * This may have been the last child of the parent
			 * in which case we may need to delete the parent too.
			 */
			if (cds_list_empty(headp) &&
			    i > QOS_OBJ_DB_LEVEL_PORT) {
				struct qos_obj_db_obj *parent;

				parent = cds_list_entry(headp,
							struct qos_obj_db_obj,
							child_list);
				/*
				 * If the parent has a null delete callback
				 * function it was created automatically as
				 * an intermediate node by the database code.
				 * Recurse back up the database tree.
				 * qos_obj_db_delete cannot return an error
				 * here as we must have passed all the parent
				 * nodes to get here in the first place.
				 */
				if (parent->delete_callback == NULL)
					(void)qos_obj_db_delete(--i, ids);
			}
			return QOS_OBJ_DB_STATUS_SUCCESS;
		}
		headp = &db_obj->child_list;
	}

	return ret;
}

static enum qos_obj_db_status
qos_obj_db_walk_int(struct cds_list_head *headp, enum qos_obj_db_level level,
		    uint32_t *ids,
		    int (*walk_callback)(void *context,
					 struct qos_obj_db_obj *db_obj,
					 enum qos_obj_db_level level,
					 uint32_t *ids),
		    void *context)
{
	struct qos_obj_db_obj *db_obj;
	enum qos_obj_db_status ret = QOS_OBJ_DB_STATUS_SUCCESS;

	cds_list_for_each_entry_rcu(db_obj, headp, peer_list) {
		/*
		 * Build the id for this entry
		 */
		ids[level] = db_obj->id;

		/*
		 * Call the callback function for this entry
		 */
		if ((*walk_callback)(context, db_obj, level, ids))
			return QOS_OBJ_DB_STATUS_WALKSTOPPED;

		/*
		 * Recurse down this entry's child tree
		 */
		ret = qos_obj_db_walk_int(&db_obj->child_list, level + 1, ids,
					  walk_callback, context);
		if (ret)
			return ret;
	}

	return ret;
}

enum qos_obj_db_status
qos_obj_db_walk(int (*walk_callback)(void *context,
				     struct qos_obj_db_obj *db_obj,
				     enum qos_obj_db_level level,
				     uint32_t *ids),
		void *context)
{
	uint32_t ids[QOS_OBJ_DB_ID_ARRAY_LEN] = { 0 };

	if (!walk_callback)
		return QOS_OBJ_DB_STATUS_INVARG;

	return qos_obj_db_walk_int(&qos_obj_db_head, QOS_OBJ_DB_LEVEL_PORT,
				   ids, walk_callback, context);
}
