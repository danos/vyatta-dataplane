/*-
 * Copyright (c) 2018-2021, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * storm control command handling
 */

#include <errno.h>
#include <rte_jhash.h>
#include <rte_timer.h>

#include "control.h"
#include "commands.h"
#include "dp_event.h"
#include "event.h"
#include "fal.h"
#include "if/bridge/bridge_port.h"
#include "if_var.h"
#include "controller.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "zmq_dp.h"
#include "util.h"

enum dp_storm_ctl_threshold {
	DP_STORM_CTL_THRESHOLD_NONE = 0,
	DP_STORM_CTL_THRESHOLD_ABS,
	DP_STORM_CTL_THRESHOLD_PCT,
	DP_STORM_CTL_THRESHOLD_MAX
};

/*
 * The values here map directly to the values defined
 * in the storm control MIB for ease of use
 */
enum dp_storm_ctl_state {
	/* storm control not enabled */
	DP_STORM_CTL_INACTIVE = 1,

	/* no traffic storm detected */
	DP_STORM_CTL_FORWARDING,

	/* Storm detected. Traffic being dropped */
	DP_STORM_CTL_TRAFFIC_FILTERED,

	/* Storm detected. Interface shut down */
	DP_STORM_CTL_INTF_SHUTDOWN
};

struct dp_storm_ctl_policy {
	uint64_t    threshold_type : 2;  /* dp_storm_ctl_threshold */
	uint64_t    threshold_val  : 32; /* absolute value or percent * 100 */
};

struct storm_ctl_profile {
	struct cds_lfht_node       scp_node;     /* node in profile table */
	char                       *scp_name;
	uint16_t                   scp_recovery_interval;
	uint8_t                    scp_actions;
	struct dp_storm_ctl_policy scp_policies[FAL_TRAFFIC_MAX];
	struct rcu_head            scp_rcu;
	struct cds_list_head       scp_instance_list;
};

#define STORM_CTL_ACTION_SHUTDOWN_INTF    0x01

/* State for storm control applied to an interface, or a vlan on interface */
struct storm_ctl_instance {
	struct cds_lfht_node       sci_node;     /* node in instance table */
	uint16_t                   sci_vlan;
	uint64_t                   sci_pkt_drops[FAL_TRAFFIC_MAX];
	struct dp_storm_ctl_policy sci_policy[FAL_TRAFFIC_MAX];
	fal_object_t               sci_fal_obj[FAL_TRAFFIC_MAX];
	struct storm_ctl_profile   *sci_profile;
	struct ifnet               *sci_ifp;
	struct rcu_head            sci_rcu;
	struct cds_list_head	   sci_profile_list;
};

struct if_storm_ctl_info {
	struct rcu_head            sc_rcu;
	struct rte_timer           sc_recovery_tmr;
	struct cds_lfht            *sc_instance_tbl;
};

static unsigned int storm_ctl_policy_cnt;

#define STORM_CTL_DETECTION_DEFAULT_INTERVAL 5

static unsigned int storm_ctl_detection_interval =
	STORM_CTL_DETECTION_DEFAULT_INTERVAL;
static bool storm_ctl_notification;

#define STORM_CTL_PROFILE_TABLE_MIN 8
#define STORM_CTL_PROFILE_TABLE_MAX 1024

static struct cds_lfht *storm_ctl_profile_tbl;

static bool storm_ctl_monitor_running;

static void storm_ctl_trigger_actions(struct storm_ctl_instance *instance,
				      enum fal_traffic_type tr_type,
				      uint64_t pkt_drops);

static struct rte_timer storm_ctl_monitor_tmr;

static void storm_ctl_compare_stats(struct ifnet *ifp, void *arg __rte_unused)
{
	int rv;
	enum fal_policer_stat_type stat = FAL_POLICER_STAT_RED_PACKETS;
	uint64_t cntr;
	enum fal_traffic_type tr_type;
	struct storm_ctl_instance *instance;
	struct cds_lfht_iter iter;
	fal_object_t fal_obj;

	if (!ifp->sc_info || !ifp->sc_info->sc_instance_tbl)
		return;

	cds_lfht_for_each_entry(ifp->sc_info->sc_instance_tbl, &iter,
				instance, sci_node) {

		for (tr_type = FAL_TRAFFIC_UCAST; tr_type < FAL_TRAFFIC_MAX;
		     tr_type++) {

			if (!instance->sci_policy[tr_type].threshold_val)
				continue;

			fal_obj = rcu_dereference(
				instance->sci_fal_obj[tr_type]);
			if (fal_obj == FAL_NULL_OBJECT_ID)
				continue;

			rv = fal_policer_get_stats_ext(fal_obj, 1, &stat,
						       FAL_STATS_MODE_READ,
						       &cntr);
			if (rv != 0) {
				RTE_LOG(ERR, DATAPLANE,
					"Could not retrieve %s storm control stats for %s\n",
					fal_traffic_type_to_str(tr_type),
					ifp->if_name);
				continue;
			}

			if (cntr != instance->sci_pkt_drops[tr_type]) {
				char vlan_str[13] = "";

				if (instance->sci_vlan)
					snprintf(vlan_str, 13, " (vlan %d)",
						 instance->sci_vlan);
				instance->sci_pkt_drops[tr_type] = cntr;
				RTE_LOG(INFO, DATAPLANE,
					"Traffic storm (%s) detected on %s%s. %lu pkts dropped\n",
					fal_traffic_type_to_str(tr_type),
					ifp->if_name,
					instance->sci_vlan ? vlan_str : "",
					cntr);

				storm_ctl_trigger_actions(instance, tr_type,
							  cntr);
			}
		}
	}
}

static void storm_ctl_tmr_hdlr(struct rte_timer *timer __rte_unused,
			       void *arg __rte_unused)
{
	dp_ifnet_walk(storm_ctl_compare_stats, NULL);
}

/*
 * monitor storm control statistics on all interfaces with
 * active policies. If the counters change from the last snapshot,
 * emit a syslog and trigger any configured actions
 */
static void storm_ctl_monitor_start(void)
{
	rte_timer_init(&storm_ctl_monitor_tmr);
	rte_timer_reset_sync(&storm_ctl_monitor_tmr,
			     rte_get_timer_hz() * storm_ctl_detection_interval,
			     PERIODICAL, rte_get_master_lcore(),
			     storm_ctl_tmr_hdlr, NULL);
	storm_ctl_monitor_running = true;
}

static void storm_ctl_monitor_stop(void)
{
	rte_timer_stop_sync(&storm_ctl_monitor_tmr);
	storm_ctl_monitor_running = false;
}

#define STORM_CTL_INSTANCE_TABLE_MIN 8
#define STORM_CTL_INSTANCE_TABLE_MAX 1024

static int storm_ctl_setup_intf_instance_tbl(const char *if_name,
					     struct if_storm_ctl_info *sc_info)
{
	sc_info->sc_instance_tbl = cds_lfht_new(STORM_CTL_INSTANCE_TABLE_MIN,
						STORM_CTL_INSTANCE_TABLE_MIN,
						STORM_CTL_INSTANCE_TABLE_MAX,
						CDS_LFHT_AUTO_RESIZE,
						NULL);
	if (!sc_info->sc_instance_tbl) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not set up instance table on intf %s\n",
			if_name);
		return -ENOMEM;
	}
	return 0;
}

static inline int storm_ctl_instance_match_fn(struct cds_lfht_node *node,
					      const void *arg)
{
	const uint16_t *vlan = arg;
	const struct storm_ctl_instance *instance;

	instance = caa_container_of(node, const struct storm_ctl_instance,
				    sci_node);
	if (*vlan == instance->sci_vlan)
		return 1;

	return 0;
}

static struct storm_ctl_instance *
storm_ctl_find_instance(struct if_storm_ctl_info *sc_info, uint16_t vlan)
{
	struct storm_ctl_instance *instance = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	if (!sc_info->sc_instance_tbl)
		return NULL;

	cds_lfht_lookup(sc_info->sc_instance_tbl,
			vlan,
			storm_ctl_instance_match_fn,
			&vlan, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		instance = caa_container_of(node,
					    struct storm_ctl_instance,
					    sci_node);
	return instance;
}

static struct storm_ctl_instance *
storm_ctl_add_instance(struct ifnet *ifp,
		       struct if_storm_ctl_info *sc_info,
		       uint16_t vlan,
		       struct storm_ctl_profile *profile)
{
	struct storm_ctl_instance *instance = NULL;

	instance = calloc(1, sizeof(*instance));
	if (!instance) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not allocate instance info for vlan %d\n",
			vlan);
		return NULL;
	}

	if (!sc_info->sc_instance_tbl)
		if (storm_ctl_setup_intf_instance_tbl(ifp->if_name, sc_info)) {
			RTE_LOG(ERR, STORM_CTL,
				"Could not allocate instance table for %s\n",
				ifp->if_name);
			free(instance);
			return NULL;
		}

	instance->sci_vlan = vlan;
	instance->sci_profile = profile;

	cds_list_add_rcu(&instance->sci_profile_list,
			 &profile->scp_instance_list);
	cds_lfht_node_init(&instance->sci_node);
	cds_lfht_add(sc_info->sc_instance_tbl, vlan, &instance->sci_node);
	if (!storm_ctl_policy_cnt)
		storm_ctl_monitor_start();
	storm_ctl_policy_cnt++;
	return instance;
}

static void storm_ctl_free_instance(struct rcu_head *head)
{
	struct storm_ctl_instance *instance;

	instance = caa_container_of(head, struct storm_ctl_instance,
				     sci_rcu);
	free(instance);
}

/* Returns true if should be kept around, or false otherwise */
static bool storm_ctl_cfg_check_profile(struct storm_ctl_profile *profile)
{
	enum fal_traffic_type traf;

	if (profile->scp_recovery_interval ||
	    profile->scp_actions)
		return true;

	for (traf = FAL_TRAFFIC_UCAST; traf < FAL_TRAFFIC_MAX; traf++) {
		if (profile->scp_policies[traf].threshold_val)
			return true;
	}

	if (!cds_list_empty(&profile->scp_instance_list))
		return true;

	return false;
}

static void storm_ctl_free_profile(struct rcu_head *head)
{
	struct storm_ctl_profile *profile;

	profile = caa_container_of(head, struct storm_ctl_profile, scp_rcu);
	free(profile->scp_name);
	free(profile);
}

static void
storm_ctl_delete_profile(struct storm_ctl_profile *profile)
{
	cds_lfht_del(storm_ctl_profile_tbl, &profile->scp_node);
	call_rcu(&profile->scp_rcu, storm_ctl_free_profile);
}

static void
storm_ctl_del_instance_internal(struct cds_lfht *sc_instance_tbl,
				struct storm_ctl_instance *instance)
{
	cds_lfht_del(sc_instance_tbl, &instance->sci_node);
	cds_list_del(&instance->sci_profile_list);
	if (!storm_ctl_cfg_check_profile(instance->sci_profile))
		storm_ctl_delete_profile(instance->sci_profile);

	if (storm_ctl_policy_cnt == 1)
		storm_ctl_monitor_stop();
	storm_ctl_policy_cnt--;
	call_rcu(&instance->sci_rcu, storm_ctl_free_instance);
}

static int storm_ctl_del_instance(struct if_storm_ctl_info *sc_info,
				  uint16_t vlan)
{
	struct storm_ctl_instance *instance = NULL;

	instance = storm_ctl_find_instance(sc_info, vlan);
	if (!instance) {
		RTE_LOG(ERR, STORM_CTL, "Could not find info for vlan %d",
			vlan);
		return -ENOENT;
	}

	storm_ctl_del_instance_internal(sc_info->sc_instance_tbl,
					instance);
	return 0;
}

static bool
storm_control_can_create_in_fal(struct ifnet *ifp, uint16_t vlan)
{
	if (if_check_any_except_emb_feat(
		    ifp, IF_EMB_FEAT_BRIDGE_MEMBER)) {
		DP_DEBUG(STORM_CTL, DEBUG, DATAPLANE,
			 "interface %s not ready for FAL updates due to embellished features\n",
			 ifp->if_name);
		return false;
	}

	if (vlan &&
	    (!ifp->if_brport ||
	     !bridge_port_is_vlan_member(ifp->if_brport, vlan))) {
		DP_DEBUG(STORM_CTL, DEBUG, DATAPLANE,
			 "interface %s vlan %u not ready for FAL updates due to VLAN not created\n",
			 ifp->if_name, vlan);
		return false;
	}

	return true;
}

static enum fal_port_attr_t
fal_traffic_t_to_storm_ctl_type(enum fal_traffic_type traffic)
{
	switch (traffic) {
	case FAL_TRAFFIC_UCAST:
		return FAL_PORT_ATTR_UNICAST_STORM_CONTROL_POLICER_ID;
	case FAL_TRAFFIC_MCAST:
		return FAL_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID;
	case FAL_TRAFFIC_BCAST:
		return FAL_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID;
	default:
		return -1;
	}
}

static enum fal_vlan_feature_attr_t
fal_traffic_t_to_vlan_feat_type(enum fal_traffic_type traffic)
{
	switch (traffic) {
	case FAL_TRAFFIC_UCAST:
		return FAL_VLAN_FEATURE_ATTR_UNICAST_STORM_CONTROL_POLICER_ID;
	case FAL_TRAFFIC_MCAST:
		return FAL_VLAN_FEATURE_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID;
	case FAL_TRAFFIC_BCAST:
		return FAL_VLAN_FEATURE_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID;
	default:
		return -1;
	}
}

static void fal_policer_get_sc_stats(struct storm_ctl_instance *instance,
				     uint32_t num_stats,
				     enum fal_policer_stat_type cntr_ids[],
				     uint64_t cntrs[],
				     enum fal_traffic_type traf)
{
	fal_object_t fal_obj;
	int rv;

	fal_obj = CMM_LOAD_SHARED(instance->sci_fal_obj[traf]);
	if (!fal_obj)
		return;

	rv = fal_policer_get_stats_ext(fal_obj,
				       num_stats,
				       cntr_ids,
				       FAL_STATS_MODE_READ,
				       cntrs);
	if (rv && rv != -EOPNOTSUPP) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not get policer stats for %s on %s %d (%d)\n",
			instance->sci_profile->scp_name,
			instance->sci_ifp->if_name, instance->sci_vlan, rv);
	}
}

static int fal_policer_get_cfg(struct storm_ctl_instance *instance,
			       uint64_t *max_rate, uint64_t *max_burst,
			       enum fal_traffic_type traf)
{
	struct fal_attribute_t policer_attr[2] = {};
	fal_object_t fal_obj;
	int rv;

	fal_obj = CMM_LOAD_SHARED(instance->sci_fal_obj[traf]);
	if (!fal_obj)
		return 0;

	policer_attr[0].id = FAL_POLICER_ATTR_CIR;
	policer_attr[1].id = FAL_POLICER_ATTR_CBS;

	rv = fal_policer_get_attr(fal_obj,
				  ARRAY_SIZE(policer_attr),
				  policer_attr);
	if (rv && rv != -EOPNOTSUPP) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not get policer cfg from fal for %s %d (%d)\n",
			instance->sci_ifp->if_name, instance->sci_vlan, rv);
		return rv;
	}

	*max_rate = BYTES_TO_METRIC_KBITS(policer_attr[0].value.u64);
	*max_burst = BYTES_TO_METRIC_KBITS(policer_attr[1].value.u64);

	return 0;
}

static uint64_t
storm_ctl_policy_get_fal_rate(struct dp_storm_ctl_policy *policy,
			      struct ifnet *ifp)
{
	struct dp_ifnet_link_status link;

	if (policy->threshold_type == DP_STORM_CTL_THRESHOLD_ABS)
		return policy->threshold_val;
	if (policy->threshold_type == DP_STORM_CTL_THRESHOLD_PCT) {
		if (ifp->if_type == IFT_L2VLAN)
			ifp = ifp->if_parent;
		dp_ifnet_link_status(ifp, &link);
		return ((uint64_t)link.link_speed * 1000 *
			policy->threshold_val)/10000;
	}
	return 0;
}

static int fal_policer_apply_profile(struct storm_ctl_profile *profile,
				     uint16_t vlan,
				     struct storm_ctl_instance *instance,
				     enum fal_traffic_type traf)
{
	uint64_t rate = 0;
	/* burst needs to be non 0 to start policer */
	uint64_t burst = METRIC_KBITS_TO_BYTES(1);
	uint64_t kbits;
	int rv = 0;
	struct if_vlan_feat *vlan_feat;
	struct ifnet *ifp;

	struct fal_attribute_t policer_attr[] = {
		{ .id = FAL_POLICER_ATTR_METER_TYPE,
		  .value.u32 = FAL_POLICER_METER_TYPE_BYTES },
		{ .id = FAL_POLICER_ATTR_MODE,
		  .value.u32 = FAL_POLICER_MODE_STORM_CTL },
		{ .id = FAL_POLICER_ATTR_RED_PACKET_ACTION,
		  .value.u32 = FAL_PACKET_ACTION_DROP},
		{ .id = FAL_POLICER_ATTR_CBS,
		  .value.u64 = burst},
		{ .id = FAL_POLICER_ATTR_CIR,
		  .value.u64 = rate}
	};
	struct fal_attribute_t vlan_attr[3] = {
		{ .id = FAL_VLAN_FEATURE_INTERFACE_ID },
		{ .id = FAL_VLAN_FEATURE_VLAN_ID }
	};
	struct fal_attribute_t port_attr;
	fal_object_t fal_obj;

	/* Work out rate. If this is an absolute value then use it */
	kbits = storm_ctl_policy_get_fal_rate(&profile->scp_policies[traf],
					      instance->sci_ifp);
	policer_attr[4].value.u64 = METRIC_KBITS_TO_BYTES(kbits);
	rv = fal_policer_create(ARRAY_SIZE(policer_attr),
				policer_attr,
				&fal_obj);
	if (rv && rv != -EOPNOTSUPP) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not create policer for %s %d in fal (%d)\n",
			instance->sci_ifp->if_name, vlan, rv);
		return rv;
	}
	CMM_STORE_SHARED(instance->sci_fal_obj[traf], fal_obj);

	ifp = instance->sci_ifp;
	if (ifp->if_type == IFT_L2VLAN) {
		vlan = ifp->if_vlan;
		ifp = ifp->if_parent;
	}

	if (vlan) {
		/*
		 * We have to create a vlan_feat, apply the policer to it, and
		 * then apply the vlan_feat to the port directly.
		 */
		vlan_attr[0].value.u32 = ifp->if_index;
		vlan_attr[1].value.u16 = vlan;
		vlan_attr[2].id = fal_traffic_t_to_vlan_feat_type(traf);
		vlan_attr[2].value.objid = instance->sci_fal_obj[traf];

		vlan_feat = if_vlan_feat_get(ifp, vlan);
		if (!vlan_feat) {
			rv = if_vlan_feat_create(ifp, vlan, FAL_NULL_OBJECT_ID);
			if (rv) {
				RTE_LOG(ERR, STORM_CTL,
					"Could not create feature block for intf %s, vlan %d\n",
					ifp->if_name, vlan);
				return rv;
			}
			vlan_feat = if_vlan_feat_get(ifp, vlan);
			if (!vlan_feat)
				return -ENOENT;
			rv = fal_vlan_feature_create(ARRAY_SIZE(vlan_attr),
						     vlan_attr,
						     &vlan_feat->fal_vlan_feat);
			if (rv && rv != -EOPNOTSUPP) {
				RTE_LOG(ERR, STORM_CTL,
					"Could not create vlan_feat for vlan %d in fal (%d)\n",
					vlan, rv);
				if_vlan_feat_delete(ifp, vlan);
				return rv;
			}
		} else {
			rv = fal_vlan_feature_set_attr(vlan_feat->fal_vlan_feat,
						       &vlan_attr[2]);
			if (rv) {
				RTE_LOG(ERR, STORM_CTL,
					"Could not associate %s policer for intf %s vlan %d\n",
					fal_traffic_type_to_str(traf),
					ifp->if_name, vlan);
				return rv;
			}
		}
		vlan_feat->refcount++;
	} else {
		port_attr.id = fal_traffic_t_to_storm_ctl_type(traf);
		port_attr.value.objid = instance->sci_fal_obj[traf];
		fal_l2_upd_port(ifp->if_index, &port_attr);
	}

	return rv;
}

static int fal_policer_unapply_profile(struct ifnet *ifp,
				       uint16_t vlan,
				       struct storm_ctl_instance *instance,
				       enum fal_traffic_type traf)
{
	int rv = 0;
	struct fal_attribute_t port_attr;
	struct if_vlan_feat *vlan_feat = NULL;
	struct fal_attribute_t vlan_attr;

	if (ifp->if_type == IFT_L2VLAN) {
		vlan = ifp->if_vlan;
		ifp = ifp->if_parent;
	}

	if (vlan) {
		vlan_feat = if_vlan_feat_get(ifp, vlan);
		if (!vlan_feat) {
			RTE_LOG(ERR, STORM_CTL,
				"Could not find vlan feat for intf %s vlan %d\n",
				ifp->if_name, vlan);
			return -ENOENT;
		}

		/* Remove the storm control from the vlan feature */
		vlan_attr.id = fal_traffic_t_to_vlan_feat_type(traf);
		vlan_attr.value.objid = FAL_NULL_OBJECT_ID;

		rv = fal_vlan_feature_set_attr(vlan_feat->fal_vlan_feat,
					       &vlan_attr);
		if (rv && rv != -EOPNOTSUPP) {
			RTE_LOG(ERR, STORM_CTL,
				"Could not remove vlan_feat for vlan %d in fal (%d)\n",
				vlan, rv);
			return rv;
		}

		vlan_feat->refcount--;
	} else {
		port_attr.id = fal_traffic_t_to_storm_ctl_type(traf);
		port_attr.value.objid = FAL_NULL_OBJECT_ID;
		fal_l2_upd_port(ifp->if_index, &port_attr);
	}

	rv = fal_policer_delete(instance->sci_fal_obj[traf]);
	if (rv && rv != -EOPNOTSUPP) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not delete policer for %s %d in fal (%d)\n",
			ifp->if_name, vlan, rv);
		return rv;
	}
	CMM_STORE_SHARED(instance->sci_fal_obj[traf], FAL_NULL_OBJECT_ID);

	if (vlan_feat && !vlan_feat->refcount) {
		rv = fal_vlan_feature_delete(vlan_feat->fal_vlan_feat);
		if (rv) {
			RTE_LOG(ERR, STORM_CTL,
				"Could not destroy fal vlan feature obj for %s vlan %d (%d)\n",
				ifp->if_name, vlan, rv);
			return rv;
		}

		rv = if_vlan_feat_delete(ifp, vlan);
		if (rv) {
			RTE_LOG(ERR, STORM_CTL,
				"Could not destroy vlan feature obj for %s vlan %d (%d)\n",
				ifp->if_name, vlan, rv);
			return rv;
		}
		RTE_LOG(INFO, STORM_CTL,
			"Destroyed vlan feature obj for %s vlan %d\n",
			ifp->if_name, vlan);
	}

	return rv;
}

/*
 * The rate has changed, update fal
 */
static int fal_policer_modify_profile(struct storm_ctl_profile *profile,
				      uint16_t vlan,
				      struct storm_ctl_instance *instance,
				      enum fal_traffic_type traf)
{

	struct fal_attribute_t policer_bind_attr = {};
	int rv;
	uint64_t kbits;

	if (!storm_control_can_create_in_fal(instance->sci_ifp, vlan))
		return 0;

	if (!instance->sci_fal_obj[traf])
		return fal_policer_apply_profile(profile, vlan,
						 instance, traf);
	if (instance->sci_fal_obj[traf] &&
		 profile->scp_policies[traf].threshold_type ==
		 DP_STORM_CTL_THRESHOLD_NONE)
		return fal_policer_unapply_profile(instance->sci_ifp, vlan,
						   instance, traf);

	kbits = storm_ctl_policy_get_fal_rate(&profile->scp_policies[traf],
					      instance->sci_ifp);
	policer_bind_attr.id = FAL_POLICER_ATTR_CIR;
	policer_bind_attr.value.u64 = METRIC_KBITS_TO_BYTES(kbits);

	rv = fal_policer_set_attr(instance->sci_fal_obj[traf],
				  &policer_bind_attr);
	if (rv && rv != -EOPNOTSUPP) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not update policer for %s %d in fal (%d)\n",
			instance->sci_ifp->if_name, vlan, rv);
		return rv;
	}
	return rv;
}

static bool storm_ctl_fal_update_needed(struct dp_storm_ctl_policy *prof_pol,
					struct dp_storm_ctl_policy *inst_pol)
{
	if (prof_pol->threshold_type != inst_pol->threshold_type)
		return true;
	if (prof_pol->threshold_val != inst_pol->threshold_val)
		return true;

	return false;
}

/* The profile has changed, update the fal if needed */
static void storm_ctl_fal_update_profile(struct storm_ctl_profile *profile)
{
	struct storm_ctl_instance *instance;
	enum fal_traffic_type i;
	int rv;

	/* For all the places where the profile is bound */
	cds_list_for_each_entry_rcu(instance, &profile->scp_instance_list,
				    sci_profile_list) {

		for (i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
			if (!storm_ctl_fal_update_needed(
				    &profile->scp_policies[i],
				    &instance->sci_policy[i]))
				continue;
			if (storm_control_can_create_in_fal(
				    instance->sci_ifp, instance->sci_vlan)) {
				rv = fal_policer_modify_profile(
					profile, instance->sci_vlan,
					instance, i);
				if (rv) {
					RTE_LOG(ERR, STORM_CTL,
						"Could not update %s threshold for interface %s vlan %d\n",
						fal_traffic_type_to_str(i),
						instance->sci_ifp->if_name,
						instance->sci_vlan);
					continue;
				}
			}
			instance->sci_policy[i] =
				profile->scp_policies[i];
		}
	}
}

static void storm_ctl_recovery_tmr_stop(struct ifnet *ifp)
{
	rte_timer_stop_sync(&ifp->sc_info->sc_recovery_tmr);
}

static void storm_ctl_recovery_hdlr(struct rte_timer *timer __rte_unused,
				    void *arg)
{
	struct ifnet *ifp = arg;

	RTE_LOG(INFO, DATAPLANE,
		"Re-enabling interface %s after forced shutdown\n",
		ifp->if_name);

	if (ifp->if_flags & IFF_UP)
		if_start(ifp);
}

static void storm_ctl_recovery_tmr_start(struct ifnet *ifp, int interval)
{
	rte_timer_reset_sync(&ifp->sc_info->sc_recovery_tmr,
			     rte_get_timer_hz() * interval,
			     SINGLE, rte_get_master_lcore(),
			     storm_ctl_recovery_hdlr, ifp);
}

static void storm_ctl_update_intf_recovery_interval(struct ifnet *ifp,
						    int interval)
{
	bool held_down = false;

	if (rte_timer_pending(&ifp->sc_info->sc_recovery_tmr)) {
		storm_ctl_recovery_tmr_stop(ifp);
		held_down = true;
	}

	if (interval)
		storm_ctl_recovery_tmr_start(ifp, interval);
	else if (held_down && (ifp->if_flags & IFF_UP))
		if_start(ifp);

}
static int storm_ctl_set_recovery_interval(bool set,
					   const char *arg,
					   struct storm_ctl_profile *profile)
{
	struct storm_ctl_instance *instance;
	int interval = 0;

	if (set)
		interval = atoi(arg);

	profile->scp_recovery_interval = interval;

	/* For all the places where the profile is bound */
	cds_list_for_each_entry_rcu(instance, &profile->scp_instance_list,
				    sci_profile_list) {

		if (instance->sci_vlan)
			continue;

		storm_ctl_update_intf_recovery_interval(instance->sci_ifp,
							interval);
	}

	return 0;
}

static void storm_ctl_set_profile_action(bool set,
					 struct storm_ctl_profile *profile)
{
	if (set)
		profile->scp_actions |= STORM_CTL_ACTION_SHUTDOWN_INTF;
	else
		profile->scp_actions &= ~STORM_CTL_ACTION_SHUTDOWN_INTF;
}

/*
 * storm-ctl <SET|DELETE> <ifname> <unicast|multicast|broadcast>
 *           <bandwidth-level|bandwidth-percent> <value>
 */
static int storm_ctl_set_threshold(bool set,
				   enum fal_traffic_type tr_type,
				   enum dp_storm_ctl_threshold bw_type,
				   const char *val,
				   struct storm_ctl_profile *profile)
{
	struct dp_storm_ctl_policy *policy;

	if (set) {
		policy = &profile->scp_policies[tr_type];

		policy->threshold_type = bw_type;
		if (bw_type == DP_STORM_CTL_THRESHOLD_ABS)
			policy->threshold_val = strtol(val, NULL, 10);
		else if (bw_type == DP_STORM_CTL_THRESHOLD_PCT)
			/*
			 * The value is restricted to have 2 fractional
			 * digits in the yang model
			 */
			policy->threshold_val = (unsigned long)
						(strtof(val, NULL) * 100);
	} else {
		profile->scp_policies[tr_type].threshold_type =
			DP_STORM_CTL_THRESHOLD_NONE;
		profile->scp_policies[tr_type].threshold_val = 0;
	}

	storm_ctl_fal_update_profile(profile);

	return 0;
}

/*
 * set up all known storm control policies
 * invoked when interface is brought up
 */
static void storm_ctl_set_policies(struct ifnet *ifp)
{
	struct cds_lfht_iter iter;
	struct storm_ctl_instance *instance;
	enum fal_traffic_type tr_type;
	struct storm_ctl_profile *profile;
	struct if_storm_ctl_info *sc_info = ifp->sc_info;

	if (!sc_info || !sc_info->sc_instance_tbl)
		return;

	cds_lfht_for_each_entry(sc_info->sc_instance_tbl, &iter,
				instance, sci_node) {

		if (!instance->sci_profile)
			continue;

		profile = instance->sci_profile;
		for (tr_type = FAL_TRAFFIC_UCAST;
		     tr_type < FAL_TRAFFIC_MAX;
		     tr_type++) {

			if (!profile->scp_policies[tr_type].threshold_val)
				continue;

			fal_policer_modify_profile(profile,
						   instance->sci_vlan,
						   instance, tr_type);

		}
	}
}

static enum dp_storm_ctl_threshold
storm_ctl_threshold_str_to_type(const char *str)
{
	if (!strcmp(str, "bandwidth-level"))
		return DP_STORM_CTL_THRESHOLD_ABS;
	if (!strcmp(str, "bandwidth-percent"))
		return DP_STORM_CTL_THRESHOLD_PCT;

	return DP_STORM_CTL_THRESHOLD_MAX;
}

static int storm_ctl_setup_profile_table(void)
{
	storm_ctl_profile_tbl = cds_lfht_new(STORM_CTL_PROFILE_TABLE_MIN,
					     STORM_CTL_PROFILE_TABLE_MIN,
					     STORM_CTL_PROFILE_TABLE_MAX,
					     CDS_LFHT_AUTO_RESIZE,
					     NULL);
	if (!storm_ctl_profile_tbl) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not allocate storm control profile table\n");
		return -ENOMEM;
	}
	return 0;
}

static inline uint32_t storm_ctl_profile_name_hash(const char *profile_name)
{
	int len = strlen(profile_name);
	char copy[len+3];

	memcpy(copy, profile_name, len);
	return rte_jhash(copy, len, 0);
}

static inline int storm_ctl_profile_name_match_fn(struct cds_lfht_node *node,
						  const void *arg)
{
	const char *profile_name = arg;
	const struct storm_ctl_profile *profile;

	profile = caa_container_of(node, const struct storm_ctl_profile,
				   scp_node);
	if (strcmp(profile_name, profile->scp_name) == 0)
		return 1;

	return 0;
}

static struct storm_ctl_profile *
storm_ctl_add_profile(const char *name)
{
	struct storm_ctl_profile *profile = NULL;
	unsigned long name_hash;
	struct cds_lfht_node *ret_node;
	int rc;

	if (!storm_ctl_profile_tbl) {
		rc = storm_ctl_setup_profile_table();
		if (rc)
			return NULL;
	}

	profile = calloc(1, sizeof(*profile));
	if (!profile) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not allocate storm control profile %s\n",
			name);
		return NULL;
	}

	profile->scp_name = strdup(name);
	if (!profile->scp_name) {
		free(profile);
		RTE_LOG(ERR, STORM_CTL,
			"Could not allocate storm control profile %s\n",
			name);
		return NULL;
	}

	cds_lfht_node_init(&profile->scp_node);
	name_hash = rte_jhash(name, strlen(name), 0);
	ret_node = cds_lfht_add_unique(storm_ctl_profile_tbl, name_hash,
				       storm_ctl_profile_name_match_fn, name,
				       &profile->scp_node);

	if (ret_node != &profile->scp_node) {
		free(profile->scp_name);
		free(profile);
		profile = caa_container_of(ret_node, struct storm_ctl_profile,
					   scp_node);
	}
	CDS_INIT_LIST_HEAD(&profile->scp_instance_list);

	return profile;
}

static struct storm_ctl_profile *
storm_ctl_find_profile(const char *name)
{
	struct storm_ctl_profile *profile = NULL;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *node;

	if (!storm_ctl_profile_tbl)
		return NULL;

	cds_lfht_lookup(storm_ctl_profile_tbl,
			storm_ctl_profile_name_hash(name),
			storm_ctl_profile_name_match_fn,
			name, &iter);

	node = cds_lfht_iter_get_node(&iter);
	if (node)
		profile = caa_container_of(node, struct storm_ctl_profile,
					   scp_node);

	return profile;
}

static int storm_ctl_set_profile(bool set, FILE *f, int argc, char **argv)
{
	char *profile_name;
	struct storm_ctl_profile *profile;
	enum fal_traffic_type tr_type;
	enum dp_storm_ctl_threshold bw_type;

	if (argc < 5)
		goto error;

	profile_name = argv[3];
	profile = storm_ctl_find_profile(profile_name);

	if (!profile) {
		if (set) {
			profile = storm_ctl_add_profile(profile_name);
			if (!profile) {
				fprintf(f,
					"Could not create storm control profile %s\n",
					profile_name);
				return -ENOMEM;
			}
		} else {
			fprintf(f, "Could not find profile %s\n", profile_name);
			return -ENOENT;
		}
	}

	if (!strcmp(argv[4], "recovery-interval")) {
		if (set && argc == 6)
			storm_ctl_set_recovery_interval(set, argv[5],
							profile);
		else if (!set && argc == 5)
			storm_ctl_set_recovery_interval(set, NULL,
							profile);
		else
			goto error;
	} else if (!strcmp(argv[4], "shutdown"))
		storm_ctl_set_profile_action(set, profile);
	else {
		tr_type = fal_traffic_str_to_type(argv[4]);
		if (tr_type >= FAL_TRAFFIC_MAX) {
			fprintf(f, "Invalid traffic type parameter %s\n",
				argv[4]);
			goto error;
		}
		if (set && argc == 7) {
			bw_type = storm_ctl_threshold_str_to_type(argv[5]);
			return storm_ctl_set_threshold(set, tr_type,
						       bw_type, argv[6],
						       profile);
		}
		if (!set) {
			storm_ctl_set_threshold(set, tr_type,
						DP_STORM_CTL_THRESHOLD_NONE,
						0, profile);
		} else
			goto error;
	}

	/* Delete the profile if this was a delete of the last config in it */
	if (!set && !storm_ctl_cfg_check_profile(profile))
		storm_ctl_delete_profile(profile);

	return 0;

error:
	fprintf(f,
		"Usage: storm-ctl SET profile <name> recovery-interval <val>");
	fprintf(f,
		"Usage: storm-ctl SET profile <name> shutdown");
	fprintf(f,
		"Usage: storm-ctl SET profile <name> <tr-type> <level-spec> <val>");
	fprintf(f,
		"Usage: storm-ctl DELETE profile <name> recovery-interval");
	fprintf(f,
		"Usage: storm-ctl DELETE profile <name> shutdown");
	fprintf(f,
		"Usage: storm-ctl DELETE profile <name> <tr-type>");

	return -EINVAL;
}

static int storm_ctl_alloc_ctx(struct ifnet *ifp)
{
	ifp->sc_info = zmalloc_aligned(sizeof(struct if_storm_ctl_info));
	if (!ifp->sc_info) {
		RTE_LOG(ERR, DATAPLANE,
			"Could not allocate storm ctl info for %s",
			ifp->if_name);
		return -ENOMEM;
	}

	rte_timer_init(&ifp->sc_info->sc_recovery_tmr);

	return 0;
}

static void storm_ctl_free_ctx(struct rcu_head *head)
{
	struct if_storm_ctl_info *sc_info =
		caa_container_of(head, struct if_storm_ctl_info, sc_rcu);

	if (sc_info->sc_instance_tbl)
		dp_ht_destroy_deferred(sc_info->sc_instance_tbl);

	free(sc_info);
}

static void storm_ctl_del_ctx(struct ifnet *ifp)
{
	struct if_storm_ctl_info *sc_info = ifp->sc_info;

	rcu_assign_pointer(ifp->sc_info, NULL);
	call_rcu(&sc_info->sc_rcu, storm_ctl_free_ctx);
}

static bool storm_ctl_intf_cfg_check(struct ifnet *ifp)
{
	struct if_storm_ctl_info *sc_info = ifp->sc_info;
	unsigned long count;
	long dummy;

	if (!sc_info)
		return false;

	if (sc_info->sc_instance_tbl) {
		cds_lfht_count_nodes(sc_info->sc_instance_tbl,
				     &dummy, &count, &dummy);
		if (count)
			return true;
	}

	return false;
}

static int send_storm_ctl_notification(struct storm_ctl_instance *instance,
				       enum fal_traffic_type tr_type,
				       uint64_t pkt_drops)
{
	zmsg_t *msg;
	int result;
	enum dp_storm_ctl_state sc_state;
	char vlan_str[13] = "";

	msg = zmsg_new();
	if (!msg)
		return -ENOMEM;

	result = zmsg_addstr(msg, "StormCtlEvent");
	if (result < 0)
		goto err;

	result = zmsg_addstr(msg, instance->sci_ifp->if_name);
	if (result < 0)
		goto err;

	result = zmsg_addu16(msg, instance->sci_vlan);
	if (result < 0)
		goto err;

	if (!instance->sci_vlan &&
	    rte_timer_pending(&instance->sci_ifp->sc_info->sc_recovery_tmr))
		sc_state = DP_STORM_CTL_INTF_SHUTDOWN;
	else
		sc_state = DP_STORM_CTL_TRAFFIC_FILTERED;

	result = zmsg_addu16(msg, sc_state);
	if (result < 0)
		goto err;

	result = zmsg_addstr(msg, fal_traffic_type_to_str(tr_type));
	if (result < 0)
		goto err;

	result = zmsg_addu64(msg, pkt_drops);
	if (result < 0)
		goto err;

	return dp_send_event_to_vplaned(msg);
err:
	if (instance->sci_vlan)
		snprintf(vlan_str, 13, " (vlan %d)", instance->sci_vlan);
	RTE_LOG(ERR, DATAPLANE,
		"Could not send storm ctl notification for %s%s\n",
		instance->sci_ifp->if_name, vlan_str);
	zmsg_destroy(&msg);
	return result;

}

static void storm_ctl_trigger_actions(struct storm_ctl_instance *instance,
				      enum fal_traffic_type tr_type,
				      uint64_t pkt_drops)
{
	struct ifnet *ifp = instance->sci_ifp;
	int interval;

	if (!instance->sci_vlan) {
		interval = instance->sci_profile->scp_recovery_interval;
		if (instance->sci_profile->scp_actions &
		    STORM_CTL_ACTION_SHUTDOWN_INTF) {
			RTE_LOG(INFO, DATAPLANE,
				"Disabling interface %s for %d seconds due to traffic storm\n",
				ifp->if_name, interval);
			if_stop(ifp);
			storm_ctl_recovery_tmr_start(ifp, interval);
		}
	} else {
		RTE_LOG(ERR, STORM_CTL,
			"Could not find storm-ctl instance for %s",
			ifp->if_name);
	}

	if (storm_ctl_notification)
		send_storm_ctl_notification(instance, tr_type, pkt_drops);
}

static int storm_ctl_set_profile_on_intf(bool set, struct ifnet *ifp,
					 struct storm_ctl_profile *profile,
					 uint16_t vlan)
{
	struct storm_ctl_instance *instance;
	enum fal_traffic_type i;
	int rv = 0;
	char vlan_str[13] = "";
	int interval = 0;

	if (profile)
		interval = profile->scp_recovery_interval;

	if (vlan)
		snprintf(vlan_str, 13, "(vlan %d)", vlan);
	else
		storm_ctl_update_intf_recovery_interval(ifp,
							interval);

	instance = storm_ctl_find_instance(ifp->sc_info, vlan);

	if (set) {
		if (instance && instance->sci_profile == profile)
			/* No change */
			return 0;

		if (instance) {
			/* delete the old then add a new */
			storm_ctl_del_instance(ifp->sc_info, vlan);
		}
		instance = storm_ctl_add_instance(ifp, ifp->sc_info, vlan,
						  profile);
		if (!instance) {
			RTE_LOG(ERR, STORM_CTL,
				"Could not set profile %s on intf %s%s\n",
				profile->scp_name, ifp->if_name, vlan_str);
			return -ENOMEM;
		}

		instance->sci_ifp = ifp;
		/* Copy across the rates from the parent profile */
		for (i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
			if (storm_ctl_fal_update_needed(
				    &profile->scp_policies[i],
				    &instance->sci_policy[i])) {
				if (storm_control_can_create_in_fal(
					    instance->sci_ifp, vlan))
					fal_policer_apply_profile(profile, vlan,
								  instance, i);
				instance->sci_policy[i] =
					profile->scp_policies[i];
			}
		}

		if (rv && rv != -EOPNOTSUPP)
			RTE_LOG(ERR, STORM_CTL,
				"Could not add profile %s to %s (%d)\n",
				profile->scp_name, ifp->if_name, rv);

	} else {
		if (!instance) {
			RTE_LOG(ERR, STORM_CTL,
				"Could not find storm control instance on %s%s\n",
				ifp->if_name, vlan_str);
			return -ENOENT;
		}
		if (!instance->sci_profile) {
			RTE_LOG(ERR, STORM_CTL,
				"Could not remove profile from intf %s%s\n",
				ifp->if_name, vlan_str);
			return -ENOENT;
		}

		for (i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
			/* Delete only if there was a create */
			if (instance->sci_fal_obj[i])
				fal_policer_unapply_profile(ifp, vlan,
							    instance, i);
		}
		storm_ctl_del_instance(ifp->sc_info, vlan);
	}
	return rv;
}

/*
 * storm-ctl SET <ifname> vlan <vlan-id> profile <profile-name>
 * storm-ctl DELETE <ifname> vlan <vlan-id>
 */
static int storm_ctl_set_intf_vlan_cfg(bool set, struct ifnet *ifp,
				       const char *vlan_str,
				       const char *profile_name)
{
	uint16_t vlan;
	struct storm_ctl_profile *profile = NULL;
	struct if_storm_ctl_info *sc_info;
	int rv;

	vlan = atoi(vlan_str);
	sc_info = ifp->sc_info;
	if (set) {
		profile = storm_ctl_find_profile(profile_name);
		if (!profile) {
			profile = storm_ctl_add_profile(profile_name);
			if (!profile) {
				RTE_LOG(ERR, STORM_CTL,
					"Could not create storm control profile %s\n",
					profile_name);
				return -ENOMEM;
			}
		}

		rv = storm_ctl_set_profile_on_intf(set, ifp, profile, vlan);
		if (rv) {
			RTE_LOG(ERR, STORM_CTL,
				"Could not update (%s, %d) with profile %s\n",
				ifp->if_name, vlan, profile->scp_name);
			return rv;
		}
		return 0;
	}

	if (!sc_info)
		return -ENOENT;

	rv = storm_ctl_set_profile_on_intf(set, ifp, NULL, vlan);
	if (rv) {
		RTE_LOG(ERR, STORM_CTL,
			"Could not remove profile from (%s, %d)\n",
			ifp->if_name, vlan);
		return rv;
	}
	return 0;
}

/*
 * storm-ctl <SET> <ifname> profile <profile>
 * storm-ctl <DELETE> <ifname> profile <profile>
 */
static int storm_ctl_set_intf_cfg(bool set, FILE *f, int argc, char **argv)
{
	char *ifname;
	struct ifnet *ifp = NULL;
	struct storm_ctl_profile *profile;
	int rv = 0;

	if (argc < 4)
		goto error;

	ifname = argv[2];
	ifp = dp_ifnet_byifname(ifname);
	if (!ifp) {
		RTE_LOG(ERR, DATAPLANE,
			"Storm control applied, but interface missing %s\n",
			ifname);
		return -1;
	}

	if (ifp->if_type != IFT_ETHER && ifp->if_type != IFT_L2VLAN) {
		fprintf(f, "storm-ctl command not supported on %s",
			ifp->if_name);
		return -1;
	}

	if (!ifp->sc_info) {
		if (set) {
			int rv = storm_ctl_alloc_ctx(ifp);
			if (rv)
				return rv;

		} else {
			RTE_LOG(ERR, DATAPLANE,
				"No storm control block on %s\n",
				ifp->if_name);
			return -EINVAL;
		}
	}

	if (!strcmp(argv[3], "profile")) {
		if (argc != 5)
			goto error;

		if (set) {
			profile = storm_ctl_find_profile(argv[4]);
			if (!profile) {
				profile = storm_ctl_add_profile(argv[4]);
				if (!profile) {
					fprintf(f,
						"Could not create storm control profile %s\n",
						argv[4]);
					goto error;
				}
			}
			return storm_ctl_set_profile_on_intf(set, ifp,
							     profile, 0);
		}
		storm_ctl_set_profile_on_intf(set, ifp, NULL, 0);
		goto check_ifp_sc;
	}

	if (!strcmp(argv[3], "vlan")) {
		if (set && argc == 7) {
			if (strcmp(argv[5], "profile") != 0)
				goto error;
			return storm_ctl_set_intf_vlan_cfg(set, ifp, argv[4],
							   argv[6]);
		}
		if (!set && argc == 5) {
			storm_ctl_set_intf_vlan_cfg(set, ifp, argv[4], argv[6]);
			goto check_ifp_sc;
		} else {
			goto error;
		}
	}

check_ifp_sc:
	if (ifp && !storm_ctl_intf_cfg_check(ifp))
		storm_ctl_del_ctx(ifp);

	return rv;

error:
	fprintf(f,
		"Usage: storm-ctl <op> <ifname> [ vlan <vlan-id> ] profile <name>");
	rv = -1;
	return rv;
}

static int storm_ctl_set_detection_interval(bool set, FILE *f,
					    int argc, char **argv)
{
	int rv = 0;

	if (argc != 4) {
		fprintf(f, "Usage: storm-ctl set detection-interval <value>");
		return -EINVAL;
	}

	if (set)
		storm_ctl_detection_interval = atoi(argv[3]);
	else
		storm_ctl_detection_interval =
			STORM_CTL_DETECTION_DEFAULT_INTERVAL;

	if (storm_ctl_policy_cnt) {
		storm_ctl_monitor_stop();
		storm_ctl_monitor_start();
	}

	return rv;
}

static void storm_ctl_set_notification(bool set)
{
	storm_ctl_notification = set;
}

int cmd_storm_ctl_cfg(FILE *f, int argc, char **argv)
{
	bool set;

	if (argc < 3)
		goto error;

	if (!strcmp(argv[1], "SET"))
		set = true;
	else if (!strcmp(argv[1], "DELETE"))
		set = false;
	else
		goto error;

	if (!strcmp(argv[2], "detection-interval"))
		return storm_ctl_set_detection_interval(set, f, argc, argv);
	if (!strcmp(argv[2], "notification")) {
		storm_ctl_set_notification(set);
		return 0;
	}
	if (!strcmp(argv[2], "profile"))
		return storm_ctl_set_profile(set, f, argc, argv);
	return storm_ctl_set_intf_cfg(set, f, argc, argv);

error:
	fprintf(f, "Usage: storm-ctl <op> < cmd | ifname >");
	return -1;
}

static struct ifnet *storm_ctl_intf_check(char *ifname, FILE *f)
{
	struct ifnet *ifp;

	ifp = dp_ifnet_byifname(ifname);
	if (!ifp) {
		fprintf(f, "Could not find interface %s\n",
			ifname);
		return NULL;
	}

	if (!ifp->sc_info) {
		fprintf(f, "Storm control not configured on %s\n",
			ifname);
		return NULL;
	}
	return ifp;
}

const char *
storm_ctl_traffic_type_to_str(enum fal_traffic_type tr_type)
{
	static const char *traffic_types[FAL_TRAFFIC_MAX] = {
		[FAL_TRAFFIC_UCAST] = "unicast",
		[FAL_TRAFFIC_MCAST] = "multicast",
		[FAL_TRAFFIC_BCAST] = "broadcast"
	};

	if (tr_type >= FAL_TRAFFIC_MAX)
		return "";
	return traffic_types[tr_type];
}

static void storm_ctl_show_instance(json_writer_t *wr,
				    struct storm_ctl_instance *instance)
{
	enum fal_traffic_type i;
	uint64_t cntrs[FAL_POLICER_STAT_MAX];
	uint64_t max_rate, burst_rate;
	static const char *fal_stat_strs[FAL_POLICER_STAT_MAX] = {
		[FAL_POLICER_STAT_GREEN_PACKETS] = "pkts_accepted",
		[FAL_POLICER_STAT_GREEN_BYTES] = "bytes_accepted",
		[FAL_POLICER_STAT_RED_PACKETS] = "pkts_dropped",
		[FAL_POLICER_STAT_RED_BYTES] = "bytes_dropped"
	};
	enum fal_policer_stat_type cntr_ids[] = {
		FAL_POLICER_STAT_GREEN_PACKETS,
		FAL_POLICER_STAT_GREEN_BYTES,
		FAL_POLICER_STAT_RED_PACKETS,
		FAL_POLICER_STAT_RED_BYTES
	};
	uint32_t num_stats = ARRAY_SIZE(cntr_ids);
	enum fal_policer_stat_type j;
	fal_object_t fal_obj;

	jsonw_start_object(wr);
	jsonw_string_field(wr, "profile",
			   instance->sci_profile->scp_name);
	jsonw_uint_field(wr, "vlan", instance->sci_vlan);
	for (i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
		jsonw_name(wr, storm_ctl_traffic_type_to_str(i));
		jsonw_start_object(wr);
		jsonw_uint_field(
			wr, "cfg_rate",
			storm_ctl_policy_get_fal_rate(&instance->sci_policy[i],
						      instance->sci_ifp));

		max_rate = 0;
		burst_rate = 0;
		fal_policer_get_cfg(instance, &max_rate, &burst_rate, i);
		jsonw_uint_field(wr, "max_rate_kbps", max_rate);
		jsonw_uint_field(wr, "burst_kbps", burst_rate);

		fal_obj = CMM_LOAD_SHARED(instance->sci_fal_obj[i]);
		if (fal_obj)
			fal_policer_dump(fal_obj, wr);

		memset(cntrs, 0, sizeof(cntrs));
		fal_policer_get_sc_stats(instance, num_stats, cntr_ids,
					 cntrs, i);

		for (j = 0; j < num_stats; j++)
			jsonw_uint_field(wr, fal_stat_strs[cntr_ids[j]],
					 cntrs[j]);
		jsonw_end_object(wr);
	}
	jsonw_end_object(wr);
}

static void storm_ctl_show_intf_instance_tbl(json_writer_t *wr,
					     struct if_storm_ctl_info *sc_info)
{
	struct storm_ctl_instance *instance;
	struct cds_lfht_iter iter;

	if (!sc_info->sc_instance_tbl)
		return;

	jsonw_name(wr, "vlan_table");
	jsonw_start_array(wr);
	cds_lfht_for_each_entry(sc_info->sc_instance_tbl, &iter,
				instance, sci_node) {
		if (instance->sci_vlan == 0)
			continue;
		storm_ctl_show_instance(wr, instance);
	}
	jsonw_end_array(wr);
}

static void storm_ctl_show_intf(struct ifnet *ifp,
				void *ctx)
{
	json_writer_t *wr = ctx;
	struct if_storm_ctl_info *sc_info;
	struct storm_ctl_instance *instance;

	sc_info = rcu_dereference(ifp->sc_info);
	if (!sc_info || !sc_info->sc_instance_tbl)
		return;

	jsonw_start_object(wr);
	jsonw_string_field(wr, "ifname", ifp->if_name);
	jsonw_uint_field(wr, "held_down",
			 rte_timer_pending(&ifp->sc_info->sc_recovery_tmr) ?
			 1 : 0);

	instance = storm_ctl_find_instance(sc_info, 0);
	if (instance) {
		jsonw_name(wr, "whole_interface");
		storm_ctl_show_instance(wr, instance);
	}

	storm_ctl_show_intf_instance_tbl(wr, sc_info);
	jsonw_end_object(wr);
}

static void storm_ctl_show_profile_policies(json_writer_t *wr,
					    struct storm_ctl_profile *prof)
{
	int i;

	for (i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
		if (prof->scp_policies[i].threshold_val == 0)
			continue;
		jsonw_name(wr, storm_ctl_traffic_type_to_str(i));
		jsonw_start_object(wr);
		switch (prof->scp_policies[i].threshold_type) {
		case DP_STORM_CTL_THRESHOLD_ABS:
			jsonw_uint_field(wr, "bw_level",
					 prof->scp_policies[i].threshold_val);
			break;
		case DP_STORM_CTL_THRESHOLD_PCT:
			jsonw_float_field(
				wr, "bw_percent",
				(float)prof->scp_policies[i].threshold_val
				/ 100);
			break;
		}
		jsonw_end_object(wr);
	}

}

static void storm_ctl_show_profile_tbl(FILE *f)
{
	struct storm_ctl_profile *profile;
	struct cds_lfht_iter iter;
	json_writer_t *wr;

	wr = jsonw_new(f);
	jsonw_pretty(wr, true);
	jsonw_name(wr, "profile_table");
	jsonw_start_array(wr);
	if (storm_ctl_profile_tbl)
		cds_lfht_for_each_entry(storm_ctl_profile_tbl, &iter,
					profile, scp_node) {
			jsonw_start_object(wr);
			jsonw_string_field(wr, "profile_name",
					   profile->scp_name);
			jsonw_uint_field(wr, "recovery_interval",
					 profile->scp_recovery_interval);
			jsonw_uint_field(
				wr, "shutdown",
				(profile->scp_actions &
				 STORM_CTL_ACTION_SHUTDOWN_INTF) ? 1 : 0);
			storm_ctl_show_profile_policies(wr, profile);
			jsonw_end_object(wr);
		}
	jsonw_end_array(wr);
	jsonw_destroy(&wr);
}

/*
 * storm-ctl show [ <ifname> ]
 * storm-ctl show [ <ifname> | profile]
 */
static int cmd_storm_ctl_show(FILE *f, int argc, char **argv)
{
	struct ifnet *ifp = NULL;
	json_writer_t *wr;

	if (argc < 2 || argc > 3)
		goto error;

	if (argc == 3) {
		if (strcmp(argv[2], "profile") == 0) {
			storm_ctl_show_profile_tbl(f);
			return 0;
		}
		ifp = storm_ctl_intf_check(argv[2], f);
		if (!ifp) {
			return -1;
		}
	}

	wr = jsonw_new(f);
	jsonw_pretty(wr, true);
	jsonw_name(wr, "storm_ctl_state");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "detection_interval",
			 storm_ctl_detection_interval);
	jsonw_uint_field(wr, "detection_pending",
			 rte_timer_pending(&storm_ctl_monitor_tmr) ? 1 : 0);
	jsonw_uint_field(wr, "detection_running", storm_ctl_monitor_running);
	jsonw_uint_field(wr, "applied_count", storm_ctl_policy_cnt);
	jsonw_name(wr, "intfs");
	jsonw_start_array(wr);
	if (ifp)
		storm_ctl_show_intf(ifp, wr);
	else
		dp_ifnet_walk(storm_ctl_show_intf, wr);
	jsonw_end_array(wr);
	jsonw_end_object(wr);
	jsonw_destroy(&wr);

	return 0;
error:
	fprintf(f, "Usage: storm-ctl show [<intf>]");
	return -1;
}

static void storm_ctl_clear_intf_stats(struct ifnet *ifp, void *ctx __unused)
{
	int i, rc;
	enum fal_policer_stat_type cntr_ids[] = {
		FAL_POLICER_STAT_GREEN_PACKETS,
		FAL_POLICER_STAT_GREEN_BYTES,
		FAL_POLICER_STAT_RED_PACKETS,
		FAL_POLICER_STAT_RED_BYTES
	};
	uint32_t num_stats = ARRAY_SIZE(cntr_ids);
	struct if_storm_ctl_info *sc_info;
	struct storm_ctl_instance *instance;
	struct cds_lfht_iter iter;
	fal_object_t fal_obj;

	sc_info = rcu_dereference(ifp->sc_info);
	if (!sc_info)
		return;

	cds_lfht_for_each_entry(sc_info->sc_instance_tbl, &iter,
				instance, sci_node) {

		memset(instance->sci_pkt_drops, 0,
		       sizeof(instance->sci_pkt_drops));
		for (i = 0; i < FAL_TRAFFIC_MAX; i++) {
			fal_obj = CMM_LOAD_SHARED(instance->sci_fal_obj[i]);
			if (!fal_obj)
				continue;

			rc = fal_policer_clear_stats(fal_obj,
						     num_stats,
						     cntr_ids);
			if (rc) {
				RTE_LOG(ERR, DATAPLANE,
					"Could not clear %s storm ctl stats on %s\n",
					storm_ctl_traffic_type_to_str(i),
					ifp->if_name);
			}
		}
	}
}

static int cmd_storm_ctl_clear(FILE *f, int argc, char **argv)
{
	struct ifnet *ifp = NULL;

	if (argc < 3)
		goto error;

	if (strcmp(argv[2], "stats") != 0)
		goto error;

	if (argc == 4) {
		ifp = dp_ifnet_byifname(argv[3]);
		if (!ifp) {
			fprintf(f, "Could not find interface %s",
				argv[3]);
			return -1;
		}
	}

	if (ifp)
		storm_ctl_clear_intf_stats(ifp, NULL);
	else
		dp_ifnet_walk(storm_ctl_clear_intf_stats, NULL);

	return 0;

error:
	fprintf(f, "Usage: storm-ctl clear stats [ <intf> ]");
	return -1;
}

/*
 * storm-ctl <show|clear> ...
 */
int cmd_storm_ctl_op(FILE *f, int argc, char **argv)
{
	if (argc < 2)
		goto error;

	if (!strcmp(argv[1], "show"))
		cmd_storm_ctl_show(f, argc, argv);
	else if (!strcmp(argv[1], "clear"))
		cmd_storm_ctl_clear(f, argc, argv);
	else
		goto error;

	return 0;
error:
	fprintf(f, "Usage: storm-ctl <show|clear>");
	return -1;
}

static void
storm_ctl_if_link_change(struct ifnet *ifp, bool up,
			 uint32_t speed __unused)
{
	if (up)
		storm_ctl_set_policies(ifp);
}

static void
storm_ctl_if_vlan_add(struct ifnet *ifp,
		      uint16_t vlan)
{
	struct storm_ctl_instance *instance;

	if (!ifp->sc_info)
		return;

	instance = storm_ctl_find_instance(ifp->sc_info, vlan);
	if (!instance)
		return;

	if (!storm_control_can_create_in_fal(
		    instance->sci_ifp, instance->sci_vlan))
		return;

	/* Apply rates from the profile */
	for (int i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
		fal_policer_apply_profile(instance->sci_profile,
					  vlan, instance, i);
	}
}

static void
storm_ctl_if_vlan_del(struct ifnet *ifp,
		      uint16_t vlan)
{
	struct storm_ctl_instance *instance;

	if (!ifp->sc_info)
		return;

	instance = storm_ctl_find_instance(ifp->sc_info, vlan);
	if (!instance)
		return;

	/* Apply rates from the profile */
	for (int i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
		if (instance->sci_fal_obj[i])
			fal_policer_unapply_profile(instance->sci_ifp, vlan,
						    instance, i);
	}
}

static void
storm_ctl_if_fal_apply(struct ifnet *ifp)
{
	struct storm_ctl_instance *instance;
	struct cds_lfht_iter iter;

	DP_DEBUG(STORM_CTL, DEBUG, DATAPLANE,
		 "trigger FAL apply storm control to interface %s\n",
		 ifp->if_name);

	cds_lfht_for_each_entry(ifp->sc_info->sc_instance_tbl, &iter,
				instance, sci_node) {
		if (instance->sci_vlan &&
		    (!ifp->if_brport ||
		     !bridge_port_is_vlan_member(ifp->if_brport,
						 instance->sci_vlan)))
			continue;
		for (int i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
			if (instance->sci_fal_obj[i])
				continue;
			fal_policer_apply_profile(instance->sci_profile,
						  instance->sci_vlan,
						  instance, i);
		}
	}
}

static void
storm_ctl_if_fal_unapply(struct ifnet *ifp)
{
	struct storm_ctl_instance *instance;
	struct cds_lfht_iter iter;

	DP_DEBUG(STORM_CTL, DEBUG, DATAPLANE,
		 "trigger FAL unapply storm control to interface %s\n",
		 ifp->if_name);

	cds_lfht_for_each_entry(ifp->sc_info->sc_instance_tbl, &iter,
				instance, sci_node) {
		for (int i = FAL_TRAFFIC_UCAST; i < FAL_TRAFFIC_MAX; i++) {
			if (instance->sci_fal_obj[i])
				fal_policer_unapply_profile(instance->sci_ifp,
							    instance->sci_vlan,
							    instance, i);
		}
	}
}

static void
storm_ctl_if_del(struct ifnet *ifp)
{
	struct storm_ctl_instance *instance;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(ifp->sc_info->sc_instance_tbl, &iter,
				instance, sci_node) {
		storm_ctl_del_instance_internal(ifp->sc_info->sc_instance_tbl,
						instance);
	}
	storm_ctl_del_ctx(ifp);
}

static void
storm_ctl_if_feat_mode_change(struct ifnet *ifp,
			     enum if_feat_mode_event event)
{
	if (!ifp->sc_info || !ifp->sc_info->sc_instance_tbl)
		/* nothing to do */
		return;

	switch (event) {
	case IF_FEAT_MODE_EVENT_L2_FAL_ENABLED:
		if (storm_control_can_create_in_fal(ifp, 0))
			storm_ctl_if_fal_apply(ifp);
		break;
	case IF_FEAT_MODE_EVENT_L2_FAL_DISABLED:
		storm_ctl_if_fal_unapply(ifp);
		break;
	case IF_FEAT_MODE_EVENT_EMB_FEAT_CHANGED:
		if (storm_control_can_create_in_fal(ifp, 0))
			storm_ctl_if_fal_apply(ifp);
		else
			storm_ctl_if_fal_unapply(ifp);
		break;
	case IF_FEAT_MODE_EVENT_L2_DELETED:
		DP_DEBUG(STORM_CTL, DEBUG, DATAPLANE,
			 "trigger storm control delete for interface %s\n",
			 ifp->if_name);
		storm_ctl_if_del(ifp);
		break;
	default:
		break;
	}
}

static const struct dp_event_ops storm_ctl_events = {
	.if_link_change = storm_ctl_if_link_change,
	.if_vlan_add = storm_ctl_if_vlan_add,
	.if_vlan_del = storm_ctl_if_vlan_del,
	.if_feat_mode_change = storm_ctl_if_feat_mode_change,
};

DP_STARTUP_EVENT_REGISTER(storm_ctl_events);
