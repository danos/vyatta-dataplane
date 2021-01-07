/*-
 * Copyright (c) 2018-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <assert.h>
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

static const char *fal_packet_action_to_str(enum fal_packet_action_t val)
{
	switch (val) {
	case FAL_PACKET_ACTION_DROP:
		return "drop";
	case FAL_PACKET_ACTION_FORWARD:
		return "forward";
	default:
		break;
	};
	assert(0);
	return "ERROR";
}

static const char *fal_policer_mode_to_str(enum fal_policer_mode_type val)
{
	switch (val) {
	case FAL_POLICER_MODE_STORM_CTL:
		return "storm_ctl";
	case FAL_POLICER_MODE_CPP:
		return "cpp";
	default:
		break;
	};
	assert(0);
	return "ERROR";
}

static const char *
fal_policer_meter_type_to_str(enum fal_policer_meter_type val)
{
	switch (val) {
	case FAL_POLICER_METER_TYPE_PACKETS:
		return "packets";
	case FAL_POLICER_METER_TYPE_BYTES:
		return "bytes";
	default:
		break;
	};
	assert(0);
	return "ERROR";
}

static const char *fal_policer_attr_to_str(enum fal_policer_attr_t val)
{
	switch (val) {
	case FAL_POLICER_ATTR_METER_TYPE:
		return "meter_type";
	case FAL_POLICER_ATTR_MODE:
		return "mode";
	case FAL_POLICER_ATTR_CBS:
		return "cbs";
	case FAL_POLICER_ATTR_CIR:
		return "cir";
	case FAL_POLICER_ATTR_EBS:
		return "ebs";
	case FAL_POLICER_ATTR_EIR:
		return "eir";
	case FAL_POLICER_ATTR_RED_PACKET_ACTION:
		return "action";
	default:
		break;
	}
	assert(0);
	return "ERROR";
}

/* convert from kilobits into bytes */
#define RATE_VAL1 (10000000 * (1024 / 8))
#define RATE_VAL2 (2000000 * (1024 / 8))
#define RATE_VAL3 (500000 * (1024 / 8))

/*
 * To aid testing, assume a certain set of transitions for each
 * policer.  If this set is not met then assert. Only do this if the initial
 * rate value for the policer is 100000.
 *
 * A policer should go through the following rate transitions:
 *   RATE_VAL1
 *   RATE_VAL2
 *   RATE_VAL3
 *   delete
 */
__FOR_EXPORT
int fal_plugin_policer_create(uint32_t attr_count,
			      const struct fal_attribute_t *attr_list,
			      fal_object_t *obj)
{
	uint i;
	struct fal_policer *policer;

	policer = fal_calloc(1, sizeof(*policer));
	assert(policer);
	DEBUG("%s start\n", __func__);
	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_POLICER_ATTR_METER_TYPE:
			DEBUG("%s attr: %d  ID: %s VAL: %s\n",
			      __func__, i,
			      fal_policer_attr_to_str(attr_list[i].id),
			      fal_policer_meter_type_to_str(
				      attr_list[i].value.u32));
			policer->meter = attr_list[i].value.u32;
			break;

		case FAL_POLICER_ATTR_MODE:
			DEBUG("%s attr: %d  ID: %s VAL: %s\n",
			      __func__, i,
			      fal_policer_attr_to_str(attr_list[i].id),
			      fal_policer_mode_to_str(attr_list[i].value.u32));
			policer->mode = attr_list[i].value.u32;
			break;

		case FAL_POLICER_ATTR_RED_PACKET_ACTION:
			DEBUG("%s attr: %d  ID: %s VAL: %s\n",
			      __func__, i,
			      fal_policer_attr_to_str(attr_list[i].id),
			      fal_packet_action_to_str(attr_list[i].value.u32));
			policer->action = attr_list[i].value.u32;
			break;

		case FAL_POLICER_ATTR_CIR:
			DEBUG("%s attr: %d  ID: %s VAL: %lu\n",
			      __func__, i,
			      fal_policer_attr_to_str(attr_list[i].id),
			      attr_list[i].value.u64);
			policer->rate = attr_list[i].value.u32;
			break;

		case FAL_POLICER_ATTR_CBS:
			DEBUG("%s attr: %d  ID: %s VAL: %lu\n",
			      __func__, i,
			      fal_policer_attr_to_str(attr_list[i].id),
			      attr_list[i].value.u64);
			policer->burst = attr_list[i].value.u32;
			break;
		}
	}

	assert(policer->meter == FAL_POLICER_METER_TYPE_BYTES ||
	       policer->meter == FAL_POLICER_METER_TYPE_PACKETS);
	assert(policer->mode == FAL_POLICER_MODE_STORM_CTL ||
	       policer->mode == FAL_POLICER_MODE_CPP ||
	       policer->mode == FAL_POLICER_MODE_INGRESS);
	assert(policer->action == FAL_PACKET_ACTION_DROP);

	if (policer->rate == RATE_VAL1)
		policer->assert_transitions = 1;

	DEBUG("%s end  assert_transitions: %d %p\n",
	      __func__, policer->assert_transitions, policer);
	*obj = (uintptr_t)policer;
	return 0;
}

__FOR_EXPORT
int fal_plugin_policer_delete(fal_object_t obj)
{
	struct fal_policer *policer = (struct fal_policer *)obj;

	if (policer->assert_transitions) {
		DEBUG("%s %p assert_transitions on, rate %d\n",
		      __func__, (void *)obj,
		      policer->rate);
		assert(policer->rate == RATE_VAL3);
	}

	DEBUG("%s %p\n", __func__, (void *)obj);
	fal_free_deferred(policer);
	return 0;
}

__FOR_EXPORT
int fal_plugin_policer_set_attr(fal_object_t obj,
				const struct fal_attribute_t *attr)
{
	struct fal_policer *policer = (struct fal_policer *)obj;

	DEBUG("%s %p attr: %d %lu\n",
	      __func__, (void *)obj, attr->id, attr->value.u64);

	assert(attr->id == FAL_POLICER_ATTR_CIR);

	if (policer->assert_transitions) {
		if (policer->rate == RATE_VAL1)
			assert(attr->value.u32 == RATE_VAL2);
		else if (policer->rate == RATE_VAL2)
			assert(attr->value.u32 == RATE_VAL3);
		else
			assert(0);
	}

	policer->rate = attr->value.u32;

	return 0;
}

__FOR_EXPORT
int fal_plugin_policer_get_attr(fal_object_t obj,
				uint32_t attr_count,
				struct fal_attribute_t *attr_list)
{
	struct fal_policer *policer = (struct fal_policer *)obj;
	uint32_t i;

	DEBUG("%s %p\n", __func__, (void *)obj);

	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_POLICER_ATTR_METER_TYPE:
			attr_list[i].value.u32 = policer->meter;
			break;

		case FAL_POLICER_ATTR_MODE:
			attr_list[i].value.u32 = policer->mode;
			break;

		case FAL_POLICER_ATTR_RED_PACKET_ACTION:
			attr_list[i].value.u32 = policer->action;
			break;

		case FAL_POLICER_ATTR_CIR:
			/*
			 * As the chip may give us a different rate to the one
			 * we asked for, do the same here
			 */
			attr_list[i].value.u64 = policer->rate +
						 (10 * (1024 / 8));
						 /* kilobits into bytes */
			break;

		case FAL_POLICER_ATTR_CBS:
			attr_list[i].value.u64 = policer->burst;
			break;
		}
	}

	return 0;
}

__FOR_EXPORT
int fal_plugin_policer_get_stats_ext(fal_object_t obj,
				     uint32_t num_counters,
				     const enum fal_policer_stat_type *cntr_ids,
				     enum fal_stats_mode mode,
				     uint64_t *stats)
{
	uint32_t i;
	DEBUG("%s\n", __func__);

	for (i = 0; i < num_counters; i++)
		stats[i] = 10 + i;
	return 0;
}
