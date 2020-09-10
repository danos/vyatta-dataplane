/*
 * cpp_rate_limiter.c
 *
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include "vplane_debug.h"
#include "soft_ticks.h"
#include "commands.h"
#include "protobuf.h"
#include "protobuf/cpp_rl.pb-c.h"
#include "fal.h"

#define CPP_RL_INFO(args...) \
	DP_DEBUG(CPP_RL, INFO, CPP_RL, args)

#define CPP_RL_ERR(fmt, args...) \
	rte_log(RTE_LOG_ERR, RTE_LOGTYPE_CPP_RL, "CPP_RL: " fmt, ## args)

#define CPP_RL_DEF_BURST_MS	100	/* default burst rate in milliseconds */

/* === cfg-mode === */

struct protocol_stats {
	uint64_t shadow_counts[FAL_POLICER_STAT_MAX];
	uint64_t detection_counts[2][FAL_POLICER_STAT_MAX];
};

static uint64_t cpp_rl_last_detection_time[2];
static fal_object_t limiter_obj_id = FAL_NULL_OBJECT_ID;
static uint32_t num_limiter_policers;
static fal_object_t *l_policer_objs;
static struct fal_attribute_t *l_attr_list;
static struct protocol_stats *l_attr_stats;

#define CPP_RL_DETECTION_DISABLED	0

static uint32_t cpp_rl_detection_interval = CPP_RL_DETECTION_DISABLED;

static struct rte_timer cpp_rl_monitor_tmr;
static bool cpp_rl_monitor_tmr_active;
static int cpp_rl_detect_cnt_store;

static const uint32_t cpp_rl_pb_attr_map[] = {
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_UNKNOWN] =
	0,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_LL_MULTICAST] =
	FAL_CPP_LIMITER_ATTR_LL_MC,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_IPV6_EXT] =
	FAL_CPP_LIMITER_ATTR_IPV6_EXT,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_IPV4_FRAGMENT] =
	FAL_CPP_LIMITER_ATTR_IPV4_FRAGMENT,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_OSPF_MULTICAST] =
	FAL_CPP_LIMITER_ATTR_OSPF_MC,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_OSPF] =
	FAL_CPP_LIMITER_ATTR_OSPF,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_BGP] =
	FAL_CPP_LIMITER_ATTR_BGP,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_ICMP] =
	FAL_CPP_LIMITER_ATTR_ICMP,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_LDP_UDP] =
	FAL_CPP_LIMITER_ATTR_LDP_UDP,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_BFD_UDP] =
	FAL_CPP_LIMITER_ATTR_BFD_UDP,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_RSVP] =
	FAL_CPP_LIMITER_ATTR_RSVP,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_UDP] =
	FAL_CPP_LIMITER_ATTR_UDP,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_TCP] =
	FAL_CPP_LIMITER_ATTR_TCP,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_DEFAULT] =
	FAL_CPP_LIMITER_ATTR_DEFAULT,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_PIM] =
	FAL_CPP_LIMITER_ATTR_PIM,
[CPP_RL__CPP_LIMITER__CPP_ATTRIBUTE__CPP_ATTR_EN__CPP_ATTR_IP_MULTICAST] =
	FAL_CPP_LIMITER_ATTR_IP_MC,
};

static uint32_t cpp_rl_pb_attr_map_size = sizeof(cpp_rl_pb_attr_map) /
					  sizeof(cpp_rl_pb_attr_map[0]);

static enum fal_policer_stat_type policer_cntr_ids[] = {
	FAL_POLICER_STAT_GREEN_PACKETS,
	FAL_POLICER_STAT_GREEN_BYTES,
	FAL_POLICER_STAT_RED_PACKETS,
	FAL_POLICER_STAT_RED_BYTES
};

/* This must correspond to the order of the above policer_cntr_ids */
enum cpp_rl_stats {
	CPP_RL_ACCEPTED_PACKETS,
	CPP_RL_ACCEPTED_BYTES,
	CPP_RL_DROPPED_PACKETS,
	CPP_RL_DROPPED_BYTES
};

static uint32_t num_policer_stats = ARRAY_SIZE(policer_cntr_ids);

static int cpp_rl_pb_attr_to_fal(uint32_t pb_attr, uint32_t *fal_attr)
{
	if (pb_attr >= cpp_rl_pb_attr_map_size)
		return -ENOENT;

	*fal_attr = cpp_rl_pb_attr_map[pb_attr];

	if (*fal_attr == 0)
		return -ENOENT;

	return 0;
}

static const char * const cpp_rl_prot_name[] = {
	[FAL_CPP_LIMITER_ATTR_LL_MC] = "ll-multicast",
	[FAL_CPP_LIMITER_ATTR_IPV6_EXT] = "ipv6-ext",
	[FAL_CPP_LIMITER_ATTR_IPV4_FRAGMENT] = "ipv4-fragment",
	[FAL_CPP_LIMITER_ATTR_OSPF_MC] = "ospf-multicast",
	[FAL_CPP_LIMITER_ATTR_OSPF] = "ospf",
	[FAL_CPP_LIMITER_ATTR_BGP] = "bgp",
	[FAL_CPP_LIMITER_ATTR_ICMP] = "icmp",
	[FAL_CPP_LIMITER_ATTR_LDP_UDP] = "ldp-udp",
	[FAL_CPP_LIMITER_ATTR_BFD_UDP] = "bfd-udp",
	[FAL_CPP_LIMITER_ATTR_RSVP] = "rsvp",
	[FAL_CPP_LIMITER_ATTR_UDP] = "udp",
	[FAL_CPP_LIMITER_ATTR_TCP] = "tcp",
	[FAL_CPP_LIMITER_ATTR_DEFAULT] = "default",
	[FAL_CPP_LIMITER_ATTR_PIM] = "pim",
	[FAL_CPP_LIMITER_ATTR_IP_MC] = "ip-multicast",
};

static uint32_t cpp_rl_prot_name_size = sizeof(cpp_rl_prot_name) /
					sizeof(char *);


static const char *cpp_rl_prot_to_name(uint32_t id)
{
	if (id >= cpp_rl_prot_name_size || cpp_rl_prot_name[id] == NULL)
		return "(unknown)";

	return cpp_rl_prot_name[id];
}

static int cpp_rl_name_to_prot(const char *name, uint32_t *id)
{
	uint32_t i;

	if (name == NULL)
		return -EINVAL;

	for (i = 0; i < cpp_rl_prot_name_size; i++) {
		if (cpp_rl_prot_name[i] &&
		   (strcmp(name, cpp_rl_prot_name[i]) == 0)) {
			*id = i;
			return 0;
		}
	}

	return -ENOENT;
}

static void
cpp_rl_tmr_save_counts(void)
{
	int ret = 0;
	uint32_t i;
	uint64_t cntrs[FAL_POLICER_STAT_MAX];

	if (limiter_obj_id == FAL_NULL_OBJECT_ID)
		return;

	for (i = 0; i < num_limiter_policers; i++) {
		uint32_t stat;

		ret = fal_policer_get_stats_ext(l_attr_list[i].value.objid,
						num_policer_stats,
						policer_cntr_ids,
						FAL_STATS_MODE_READ, cntrs);

		if (ret) {
			CPP_RL_ERR("failed to get policer stats for limiter %d "
				   "(for monitoring)\n", i);
			continue;
		}

		for (stat = 0; stat < num_policer_stats; stat++) {
			l_attr_stats[i].detection_counts
				[cpp_rl_detect_cnt_store][stat] = cntrs[stat];
		}
	}

	cpp_rl_last_detection_time[cpp_rl_detect_cnt_store] = soft_ticks;
}

static void
cpp_rl_tmr_hdlr(struct rte_timer *timer __rte_unused, void *arg __rte_unused)
{
	uint32_t i;
	uint64_t interval;

	if (limiter_obj_id == FAL_NULL_OBJECT_ID)
		return;

	/* Switch stats storage location between 0 and 1. */
	cpp_rl_detect_cnt_store = !cpp_rl_detect_cnt_store;

	cpp_rl_tmr_save_counts();

	if (cpp_rl_detection_interval == CPP_RL_DETECTION_DISABLED)
		return;

	/* get interval in seconds */
	interval = (cpp_rl_last_detection_time[cpp_rl_detect_cnt_store] -
		    cpp_rl_last_detection_time[!cpp_rl_detect_cnt_store])
		   / 1000;

	/* protect against being called twice quickly causing divide by 0 err */
	if (interval == 0)
		return;

	for (i = 0; i < num_limiter_policers; i++) {
		uint64_t pkts_dropped_diff =
			l_attr_stats[i].detection_counts[
			   cpp_rl_detect_cnt_store][CPP_RL_DROPPED_PACKETS] -
			l_attr_stats[i].detection_counts[
			   !cpp_rl_detect_cnt_store][CPP_RL_DROPPED_PACKETS];

		/* access stat FAL_POLICER_STAT_RED_BYTES */
		uint64_t kbits_dropped_diff =
			(l_attr_stats[i].detection_counts[
			   cpp_rl_detect_cnt_store][CPP_RL_DROPPED_BYTES] -
			l_attr_stats[i].detection_counts[
			   !cpp_rl_detect_cnt_store][CPP_RL_DROPPED_BYTES]) *
			   8 / 1024;

		pkts_dropped_diff /= interval;
		kbits_dropped_diff /= interval;

		if (pkts_dropped_diff || kbits_dropped_diff) {
			const char *type = cpp_rl_prot_to_name(
				l_attr_list[i].id);

			RTE_LOG(INFO, DATAPLANE, "Control Plane Protection "
				"Rate Limiter: selector %s: dropped: %lu pps, "
				"%lu kbps\n", type, pkts_dropped_diff,
				kbits_dropped_diff);
		}
	}
}

static void cpp_rl_monitor_stop(void)
{
	if (cpp_rl_monitor_tmr_active)
		rte_timer_stop_sync(&cpp_rl_monitor_tmr);
}

/*
 * Monitor cpp rate limiter statistics for all configured protocols.
 * If the drop counters change from the last snapshot, then emit a syslog .
 */
static void cpp_rl_monitor_restart(void)
{
	cpp_rl_monitor_stop();

	if (cpp_rl_detection_interval == CPP_RL_DETECTION_DISABLED)
		return;

	cpp_rl_tmr_save_counts();

	rte_timer_init(&cpp_rl_monitor_tmr);
	rte_timer_reset_sync(&cpp_rl_monitor_tmr,
			     rte_get_timer_hz() * cpp_rl_detection_interval,
			     PERIODICAL, rte_get_master_lcore(),
			     cpp_rl_tmr_hdlr, NULL);

	cpp_rl_monitor_tmr_active = true;
}


static void
cpp_rl_set_detection_interval(uint32_t interval)
{
	CPP_RL_INFO("change detection interval from %u to %u\n",
		    cpp_rl_detection_interval, interval);

	if (interval != cpp_rl_detection_interval) {
		cpp_rl_detection_interval = interval;
		if (interval == CPP_RL_DETECTION_DISABLED)
			cpp_rl_monitor_stop();
		else {
			if (limiter_obj_id != FAL_NULL_OBJECT_ID)
				cpp_rl_monitor_restart();
		}
	}
}

static void
cpp_rl_cfg_cleanup(void)
{
	int ret;
	uint32_t i;
	struct fal_attribute_t sw_attr;

	if (limiter_obj_id != FAL_NULL_OBJECT_ID) {
		CPP_RL_INFO("delete existing limiter\n");

		sw_attr.id = FAL_SWITCH_ATTR_CPP_RATE_LIMITER;
		sw_attr.value.objid = FAL_NULL_OBJECT_ID;

		ret = fal_set_switch_attr(&sw_attr);
		if (ret)
			CPP_RL_ERR("failed to remove limiter from hardware "
				   "(errno %d)\n", -ret);

		ret = fal_remove_cpp_limiter(limiter_obj_id);

		if (ret)
			CPP_RL_ERR("failed to remove limiter (errno %d)\n",
				   -ret);
	}

	if (l_policer_objs) {
		for (i = 0; i < num_limiter_policers; i++) {
			ret = fal_policer_delete(l_policer_objs[i]);
			if (ret)
				CPP_RL_ERR("failed to remove limiter policer "
					   "%d (errno %d)\n", i, -ret);
		}
		free(l_policer_objs);
		l_policer_objs = NULL;
	}

	if (l_attr_list) {
		free(l_attr_list);
		l_attr_list = NULL;
	}

	if (l_attr_stats) {
		free(l_attr_stats);
		l_attr_stats = NULL;
	}

	num_limiter_policers = 0;
	limiter_obj_id = FAL_NULL_OBJECT_ID;

	cpp_rl_monitor_stop();

	CPP_RL_INFO("successfully deleted existing limiters\n");
}

/*
 * Locates the index of an existing configurable for the given selector.
 *
 * On success, return 0, otherwise return -ENOENT.
 */
static int
cpp_rl_limiter_selector_id(uint32_t fal_selector_attr, uint32_t *id)
{
	uint32_t i;

	for (i = 0; i < num_limiter_policers; i++) {
		if (l_attr_list[i].id == fal_selector_attr) {
			*id = i;
			return 0;
		}
	}

	return -ENOENT;
}

static bool
cpp_rl_limiter_cfg_changed(CppRl__CPPLimiter *cpp_msg)
{
	uint32_t num_new_limiter_policers = 0;
	struct fal_attribute_t lp_attr_list[2];
	int ret;

	/* handle case that there is no existing limiters running */
	if (limiter_obj_id == FAL_NULL_OBJECT_ID) {
		if (cpp_msg->n_attributes)
			return true;	/* creating limiters */
		else
			return false;	/* not creating limiters - no change */
	}

	/* Iterate over attributes, which have entries per-protocol */
	for (uint32_t i = 0; i < cpp_msg->n_attributes; i++) {
		CppRl__CPPLimiter__CPPAttribute *attribute =
			cpp_msg->attributes[i];
		uint32_t fal_attr;
		uint32_t existing_entry_id;

		if (num_new_limiter_policers > num_limiter_policers)
			return true;

		if (!attribute->has_attr) {
			CPP_RL_INFO("check: no attribute %d\n", i);
			continue;
		}

		ret = cpp_rl_pb_attr_to_fal(attribute->attr, &fal_attr);
		if (ret) {
			CPP_RL_ERR("check: failed mapping pb attr %u\n",
				   attribute->attr);
			return true;	/* indicate changed on errors */
		}

		CPP_RL_INFO("check: attribute: %d = %d\n", i, fal_attr);

		ret = cpp_rl_limiter_selector_id(fal_attr, &existing_entry_id);

		if (ret)		/* not found */
			return true;

		/* Iterate over parameters. */
		for (uint32_t j = 0; j < attribute->n_parameters; j++) {
			CppRl__CPPLimiter__CPPAttribute__CPPParameter
				*parameter = attribute->parameters[j];
			CPP_RL_INFO("check: attribute: entry %d (%d), param %d:"
				    " [%s rate_pps], %d, [%s rate_kbps], %d\n",
				    i, fal_attr, j,
				    parameter->has_rate_pps ? "has" : "no",
				    parameter->rate_pps,
				    parameter->has_rate_kbps ? "has" : "no",
				    parameter->rate_kbps);
			if (!parameter->has_rate_pps &&
			    !parameter->has_rate_kbps) {

				CPP_RL_ERR("check: neither pps nor kbps "
					   "attribute entry %d\n", i);
				return true;	/* indicate changed on errors */
			}

			lp_attr_list[0].id = FAL_POLICER_ATTR_METER_TYPE;
			lp_attr_list[1].id = FAL_POLICER_ATTR_CIR;

			ret = fal_policer_get_attr(
			      l_attr_list[existing_entry_id].value.objid,
			      ARRAY_SIZE(lp_attr_list), lp_attr_list);

			if (ret) {
				CPP_RL_ERR("check: failed to get state for "
					   "policer %d\n", existing_entry_id);
				return true;	/* indicate changed on errors */
			}

			if (parameter->has_rate_pps) {
				if (lp_attr_list[0].value.u32 !=
				    FAL_POLICER_METER_TYPE_PACKETS)
					return true;
				if (lp_attr_list[1].value.u64 !=
				    parameter->rate_pps)
					return true;
			}

			if (parameter->has_rate_kbps) {
				if (lp_attr_list[0].value.u32 !=
				    FAL_POLICER_METER_TYPE_BYTES)
					return true;
				/* convert from kilobits into bytes */
				if (lp_attr_list[1].value.u64 !=
				    ((uint64_t)parameter->rate_kbps) *
				    (1024 / 8))
					return true;
			}
		}

		num_new_limiter_policers++;
	}

	if (num_new_limiter_policers != num_limiter_policers)
		return true;

	return false;
}

/*
 * cpp_rl_cfg
 *
 * Return 0 on success, or -errno on failure.
 */
static int
cpp_rl_cfg(struct pb_msg *msg)
{
	int ret = 0;
	CppRl__CPPLimiter *cpp_msg = NULL;
	int detection_interval;

	CPP_RL_INFO("%s\n", __func__);

	if (!msg) {
		CPP_RL_ERR("message payload missing\n");
		return -EINVAL;
	}

	void *payload = (void *)((char *)msg->msg);
	int len = msg->msg_len;
	if (len < 0) {
		CPP_RL_ERR("negative message payload (%d)\n", len);
		return -EINVAL;
	}

	/* First unpack the outer message. */
	cpp_msg = cpp_rl__cpp_limiter__unpack(NULL, len, payload);
	if (!cpp_msg) {
		CPP_RL_ERR("failed to unpack message payload\n");
		return -EINVAL;
	}

	detection_interval = cpp_msg->has_detection_interval ?
		cpp_msg->detection_interval : CPP_RL_DETECTION_DISABLED;

	cpp_rl_set_detection_interval(detection_interval);

	if (!cpp_rl_limiter_cfg_changed(cpp_msg)) {
		CPP_RL_INFO("limiters unchanged in config, so not "
			    "reconstructing them\n");
		goto end;
	}

	/* clean up any existing cpp-rl configuration */
	cpp_rl_cfg_cleanup();

	/*
	 * Now add new limiters.
	 */
	CPP_RL_INFO("%ld attributes:\n", cpp_msg->n_attributes);

	if (!cpp_msg->n_attributes) {
		/* No attributes in the message, indicating deletion */
		CPP_RL_INFO("cpp-rl limiter deletion\n");
		goto end; /* success */
	}

	l_policer_objs = calloc(cpp_msg->n_attributes, sizeof(fal_object_t));
	if (!l_policer_objs) {
		CPP_RL_ERR("policer obj allocation failure\n");
		ret = -ENOMEM;
		goto end;
	}

	l_attr_list = calloc(cpp_msg->n_attributes,
			     sizeof(struct fal_attribute_t));
	if (!l_attr_list) {
		CPP_RL_ERR("attribute list allocation failure\n");
		cpp_rl_cfg_cleanup();
		ret = -ENOMEM;
		goto end;
	}

	l_attr_stats = calloc(cpp_msg->n_attributes,
			     sizeof(struct protocol_stats));
	if (!l_attr_stats) {
		CPP_RL_ERR("stats array allocation failure\n");
		cpp_rl_cfg_cleanup();
		ret = -ENOMEM;
		goto end;
	}

	/* Iterate over attributes. */
	for (uint32_t i = 0; i < cpp_msg->n_attributes; i++) {
		CppRl__CPPLimiter__CPPAttribute *attribute =
			cpp_msg->attributes[i];

		uint32_t fal_attr;
		if (!attribute->has_attr) {
			CPP_RL_ERR("no attribute %d\n", i);
			continue;
		}

		ret = cpp_rl_pb_attr_to_fal(attribute->attr, &fal_attr);
		if (ret) {
			CPP_RL_ERR("failed mapping protobuf attr %u\n",
				   attribute->attr);
			cpp_rl_cfg_cleanup();
			goto end;
		}

		CPP_RL_INFO("attribute: %d = %d\n", i, fal_attr);

		/* Create the limiter policer. */
		struct fal_attribute_t policer_attr_list[] = {
			{ .id = FAL_POLICER_ATTR_METER_TYPE,
			  .value.u32 = UINT32_MAX },
			{ .id = FAL_POLICER_ATTR_MODE,
			  .value.u32 = FAL_POLICER_MODE_CPP },
			{ .id = FAL_POLICER_ATTR_RED_PACKET_ACTION,
			  .value.u32 = FAL_PACKET_ACTION_DROP},
			{ .id = FAL_POLICER_ATTR_CBS,
			  .value.u64 = UINT64_MAX },
			{ .id = FAL_POLICER_ATTR_CIR,
			  .value.u64 = UINT64_MAX }
		};

		/* Iterate over parameters. */
		for (uint32_t j = 0; j < attribute->n_parameters; j++) {
			CppRl__CPPLimiter__CPPAttribute__CPPParameter
				*parameter = attribute->parameters[j];

			CPP_RL_INFO("attribute: entry %d (%d), param %d: "
				    "[%s rate_pps], %d, [%s rate_kbps], %d\n",
				    i, fal_attr, j,
				    parameter->has_rate_pps ? "has" : "no",
				    parameter->rate_pps,
				    parameter->has_rate_kbps ? "has" : "no",
				    parameter->rate_kbps);

			/* One or other, but not both. */
			if (!(parameter->has_rate_pps ^
			      parameter->has_rate_kbps)) {
				CPP_RL_ERR("attribute: entry %d (%d), param %d:"
					   " one and only one of has_rate_pps "
					   "(%d) and has_rate_kbps (%d) can be "
					   "set\n", i, fal_attr, j,
					   parameter->has_rate_pps,
					   parameter->has_rate_kbps);
				ret = -EINVAL;
				cpp_rl_cfg_cleanup();
				goto end;
			}

			if (parameter->has_rate_pps) {
				/* FAL_POLICER_ATTR_METER_TYPE attribute */
				policer_attr_list[0].value.u32 =
					FAL_POLICER_METER_TYPE_PACKETS;

				/* FAL_POLICER_ATTR_CIR attribute */
				policer_attr_list[4].value.u64 =
					parameter->rate_pps;

				/*
				 * FAL_POLICER_ATTR_CBS attribute is
				 * the CIR rate * ms burst size, giving
				 * the packets-per-second burst.
				 */
				policer_attr_list[3].value.u64 =
					policer_attr_list[4].value.u64 *
					CPP_RL_DEF_BURST_MS / 1000;
			}

			if (parameter->has_rate_kbps) {
				/* FAL_POLICER_ATTR_METER_TYPE attribute */
				policer_attr_list[0].value.u32 =
					FAL_POLICER_METER_TYPE_BYTES;

				/* FAL_POLICER_ATTR_CIR attribute */
				/* convert from kilobits into bytes */
				policer_attr_list[4].value.u64 =
					((uint64_t)parameter->rate_kbps)
					* (1024 / 8);

				/*
				 * FAL_POLICER_ATTR_CBS attribute is
				 * the CIR rate * ms burst size, giving
				 * the bytes-per-second burst.
				 */
				policer_attr_list[3].value.u64 =
					policer_attr_list[4].value.u64 *
					CPP_RL_DEF_BURST_MS / 1000;
			}
		}

		if (policer_attr_list[0].value.u64 == UINT64_MAX) {
			/* neither pps nor kbps not configured so fail */
			CPP_RL_ERR("limiter configuration missing rate for "
				   "entry %d, attr %d\n", i, fal_attr);
			cpp_rl_cfg_cleanup();
			ret = -EINVAL;
			goto end;
		}
		/* Create limiter policer from parameter list. */
		ret = fal_policer_create(ARRAY_SIZE(policer_attr_list),
					 policer_attr_list,
					 &l_policer_objs[num_limiter_policers]);

		if (ret) {
			CPP_RL_ERR("failed to create limiter policer for entry "
				   "%d, attr %d (errno %d)\n", i, fal_attr,
				   ret);
			cpp_rl_cfg_cleanup();
			goto end;
		}

		/* Associate the limiter policer with the limiter. */
		l_attr_list[num_limiter_policers].id = fal_attr;
		l_attr_list[num_limiter_policers].value.objid =
			l_policer_objs[num_limiter_policers];
		memset(&l_attr_stats[num_limiter_policers], 0,
		       sizeof(l_attr_stats[num_limiter_policers]));

		num_limiter_policers++;
	}

	/* Create the limiter. */
	ret = fal_create_cpp_limiter(num_limiter_policers, l_attr_list,
				     &limiter_obj_id);
	if (ret) {
		/* Failed to create the limiter; delete the policers. */
		CPP_RL_ERR("failed to allocate limiter (errno %d)\n", -ret);
		cpp_rl_cfg_cleanup();
		goto end;
	}

	CPP_RL_INFO("limiter_obj_id: 0x%" PRIXPTR "\n", limiter_obj_id);

	/* Cause the limiter to be started */
	struct fal_attribute_t sw_attr;

	sw_attr.id = FAL_SWITCH_ATTR_CPP_RATE_LIMITER;
	sw_attr.value.objid = limiter_obj_id;

	ret = fal_set_switch_attr(&sw_attr);
	if (ret) {
		CPP_RL_ERR("failed to commit limiter to hardware (errno %d)\n",
			   -ret);
		cpp_rl_cfg_cleanup();
		goto end;
	}

	CPP_RL_INFO("successfully committed limiter to hardware\n");

	cpp_rl_monitor_restart();

end:
	if (cpp_msg)
		cpp_rl__cpp_limiter__free_unpacked(cpp_msg, NULL);

	return ret;
}

/* cpp-rate-limiter-cfg command handler
 *
 * cpp-rate-limiter-cfg set ATTR UNITS VAL
 * cpp-rate-limiter-cfg del ATTR
 *
 * Return 0 for success, or -1 to cause failure.
 */
static int
cmd_cpp_rl_cfg(struct pb_msg *msg)
{
	/*
	 * Errors from cpp_rl_cfg() are not returned so that the config
	 * command is not failed, which could cause the dataplane to restart.
	 */
	(void) cpp_rl_cfg(msg);

	return 0;
}

PB_REGISTER_CMD(cpp_rl_cfgcmd) = {
	.cmd = "vyatta:cpp-rate-limiter-cfg",
	.handler = cmd_cpp_rl_cfg
};


/* === op-mode === */

/*
 * Returns the CPP rate limiter operation status and statistics information
 * in JSON format.
 */
static int
fal_cpp_rl_state(FILE *fp)
{
	int ret = 0;
	uint32_t i;
	uint64_t cntrs[FAL_POLICER_STAT_MAX];

	struct fal_attribute_t lp_attr_list[2];
	json_writer_t *json;

	if (limiter_obj_id == FAL_NULL_OBJECT_ID) {
		CPP_RL_INFO("no limiter to get state for\n");
		return 0;
	}

	json = jsonw_new(fp);
	if (!json) {
		CPP_RL_ERR("could not allocate json buffer\n");
		return -ENOMEM;
	}

	jsonw_pretty(json, true);

	jsonw_name(json, "limiter");
	jsonw_start_array(json);

	for (i = 0; i < num_limiter_policers; i++) {
		const char *type = cpp_rl_prot_to_name(l_attr_list[i].id);
		uint64_t count[FAL_POLICER_STAT_MAX] = { 0, };
		uint32_t stat;

		ret = fal_policer_get_stats_ext(l_attr_list[i].value.objid,
						num_policer_stats,
						policer_cntr_ids,
						FAL_STATS_MODE_READ, cntrs);

		if (ret) {
			CPP_RL_ERR("failed to get policer stats for limiter "
				   "%d, type %s\n", i, type);
			continue;
		}

		for (stat = 0; stat < num_policer_stats; stat++) {
			count[stat] = cntrs[stat] -
				   l_attr_stats[i].shadow_counts[stat];
		}

		jsonw_start_object(json); /* start of array entry */

		jsonw_string_field(json, "limiter-type", type);

		jsonw_name(json, "state");
		jsonw_start_object(json);

		jsonw_uint_field(json, "packets-accepted",
				 count[CPP_RL_ACCEPTED_PACKETS]);
		jsonw_uint_field(json, "bytes-accepted",
				 count[CPP_RL_ACCEPTED_BYTES]);
		jsonw_uint_field(json, "packets-dropped",
				 count[CPP_RL_DROPPED_PACKETS]);
		jsonw_uint_field(json, "bytes-dropped",
				 count[CPP_RL_DROPPED_BYTES]);

		jsonw_end_object(json); /* end of state */

		/* Also get the type and rate reported by the FAL layer */
		lp_attr_list[0].id = FAL_POLICER_ATTR_METER_TYPE;
		lp_attr_list[1].id = FAL_POLICER_ATTR_CIR;

		ret = fal_policer_get_attr(l_attr_list[i].value.objid,
					   ARRAY_SIZE(lp_attr_list),
					   lp_attr_list);

		if (ret) {
			CPP_RL_ERR("failed to get policer attrs for "
				   "limiter %d, type %s\n", i, type);
		} else {
			uint64_t rate;

			if (lp_attr_list[0].value.u32 ==
			    FAL_POLICER_METER_TYPE_PACKETS) {
				jsonw_name(json, "packets-per-second");
				rate = lp_attr_list[1].value.u64;
			} else { /* == FAL_POLICER_METER_TYPE_BYTES */
				jsonw_name(json, "kilobits-per-second");
				/* convert from bytes to kilobits */
				rate = lp_attr_list[1].value.u64 * 8 / 1024;
			}

			jsonw_start_object(json);

			jsonw_name(json, "state");
			jsonw_start_object(json);

			jsonw_uint_field(json, "rate", rate);

			jsonw_end_object(json); /* end of state */
			jsonw_end_object(json); /* pps or kbps */
		}

		jsonw_end_object(json); /* end of array entry */
	}

	jsonw_end_array(json);  /* end of limiter array */
	jsonw_destroy(&json);

	return ret;
}

/*
 * Clears statistics by getting the current values, which can then
 * be subtracted from the values returned when requesting statistics.
 */
static int fal_cpp_rl_clear(char *param)
{
	int ret = 0;
	uint32_t i;
	uint64_t cntrs[FAL_POLICER_STAT_MAX];
	uint32_t prot_id;
	bool clear_all = false;

	if (limiter_obj_id == FAL_NULL_OBJECT_ID) {
		CPP_RL_INFO("no limiter to clear statistics for\n");
		return 0;
	}

	if (param == NULL || (strcmp(param, "ALL") == 0))
		clear_all = true;
	else {
		ret = cpp_rl_name_to_prot(param, &prot_id);

		if (ret != 0) {
			CPP_RL_ERR("unknown limiter named %s\n", param);
			return ret;
		}
	}

	for (i = 0; i < num_limiter_policers; i++) {
		uint32_t stat;

		if (!clear_all && prot_id != l_attr_list[i].id)
			continue;

		ret = fal_policer_get_stats_ext(l_attr_list[i].value.objid,
						num_policer_stats,
						policer_cntr_ids,
						FAL_STATS_MODE_READ, cntrs);

		if (ret) {
			CPP_RL_ERR("failed to get policer stats for limiter "
				   "%d (for clearing)\n", i);
			continue;
		}

		for (stat = 0; stat < num_policer_stats; stat++)
			l_attr_stats[i].shadow_counts[stat] = cntrs[stat];
	}

	return (ret);
}

/*
 * CPP rate limiter op-mode handler.
 *
 * Return 0 on success, or negative number on error
 */

int
cmd_cpp_rl_op(FILE *fp, int argc, char **argv)
{
	int ret;

	CPP_RL_INFO("%s\n", __func__);

	argv++, argc--;

	if (argc < 1) {
		fprintf(fp, "%s: missing arguments: "
			"got %d arguments", __func__, argc);
		return -EINVAL;
	}

	if (strcmp(argv[0], "get-state") == 0) {
		ret = fal_cpp_rl_state(fp);
	} else if (strcmp(argv[0], "clear-stats") == 0) {
		ret = fal_cpp_rl_clear(argc < 2 ? NULL : argv[1]);
	} else {
		fprintf(fp, "%s: unknown option %s\n", __func__, argv[0]);
		return -EINVAL;
	}

	if (ret)
		fprintf(fp, "%s: failed with error %d\n", __func__, -ret);

	return ret;
}
