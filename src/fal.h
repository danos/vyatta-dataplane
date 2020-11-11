 /*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef FAL_H
#define FAL_H
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/rtnetlink.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <rte_ether.h>
#include <sys/queue.h>

#include "fal_plugin.h"
#include "if_var.h"
#include "route.h"
#include "netinet/ip_mroute.h"
#include "util.h"
#include "vrf_internal.h"

struct rte_ether_addr;
struct fal_attribute_t;
struct fal_ip_address_t;
struct if_addr;
struct next_hop;
struct fal_ipmc_entry_t;

/*
 * Pluggable message handling. Provides handlers for control messages
 * for multiple receiver types.  A 'hdlr' may be ignored in all calls
 * as will be the case for the default 'software dataplane'.
 */

/*
 * When creating a message_handler, all fields must be filled out
 * or set to NULL.
 */
struct message_handler {
	struct fal_l2_ops *l2;
	struct fal_rif_ops *rif;
	struct fal_tun_ops *tun;
	struct fal_lag_ops *lag;
	struct fal_bridge_ops *bridge;
	struct fal_vlan_ops *vlan;
	struct fal_stp_ops *stp;
	struct fal_ip_ops *ip;
	struct fal_ipmc_ops *ipmc;
	struct fal_acl_ops *acl;
	struct fal_qos_ops *qos;
	struct fal_lacp_ops *lacp;
	struct fal_sys_ops *sys;
	struct fal_policer_ops *policer;
	struct fal_sw_ops *sw;
	struct fal_mirror_ops *mirror;
	struct fal_vlan_feat_ops *vlan_feat;
	struct fal_backplane_ops *backplane;
	struct fal_cpp_rl_ops *cpp_rl;
	struct fal_ptp_ops *ptp;
	struct fal_capture_ops *capture;
	struct fal_bfd_ops *bfd;
	struct fal_mpls_ops *mpls;
	struct fal_vrf_ops *vrf;

	LIST_ENTRY(message_handler) link;
};

/*
 * l2_ops provide an interface for a receiver 'recv' to work with the data
 * parsed from AF_UNSPEC netlink messages.
 */
struct fal_l2_ops {
	void (*new_port)(unsigned int if_index,
			 uint32_t attr_count,
			 const struct fal_attribute_t *attr_list);
	int (*get_attrs)(unsigned int if_index,
			 uint32_t attr_count,
			 struct fal_attribute_t *attr_list);
	int (*upd_port)(unsigned int if_index,
			struct fal_attribute_t *attr);
	void (*del_port)(unsigned int if_index);
	void (*dump_port)(unsigned int if_index, json_writer_t *wr);
	void (*new_addr)(unsigned int if_index,
			 const void *addr,
			 uint32_t attr_count,
			 const struct fal_attribute_t *attr_list);
	void (*upd_addr)(unsigned int if_index,
			 const void *addr,
			 struct fal_attribute_t *attr);
	void (*del_addr)(unsigned int if_index,
			 const void *addr);
};

/*
 * rif_ops provides an interface for controlling (l3) router intf
 */
struct fal_rif_ops {
	int (*create_intf)(uint32_t attr_count,
			   const struct fal_attribute_t *attr,
			   fal_object_t *obj);
	int (*delete_intf)(fal_object_t obj);
	int (*set_attr)(fal_object_t obj,
			const struct fal_attribute_t *attr);
	int (*get_stats)(fal_object_t obj, uint32_t cntr_count,
			 const enum fal_router_interface_stat_t *cntr_ids,
			 uint64_t *cntrs);
	void (*dump)(fal_object_t obj, json_writer_t *wr);
};

/*
 * tun_ops provides an interface for controlling tunnel initiator
 * and terminator
 */
struct fal_tun_ops {
	int (*create_tun)(uint32_t attr_count,
			  const struct fal_attribute_t *attr,
			  fal_object_t *obj);
	int (*delete_tun)(fal_object_t obj);
	int (*set_attr)(fal_object_t obj, uint32_t attr_count,
			const struct fal_attribute_t *attr);
};

/*
 * lag_ops provides an interface for controlling LAG
 */
struct fal_lag_ops {
	int (*create_lag)(uint32_t attr_count,
			  const struct fal_attribute_t *attr,
			  fal_object_t *obj);
	int (*delete_lag)(fal_object_t obj);
	int (*set_lag_attr)(fal_object_t obj, uint32_t attr_count,
			    const struct fal_attribute_t *attr);
	int (*get_lag_attr)(fal_object_t obj,
			    uint32_t attr_count,
			    struct fal_attribute_t *attr_list);
	void (*dump)(fal_object_t obj, json_writer_t *wr);
	int (*create_lag_member)(uint32_t attr_count,
				 const struct fal_attribute_t *attr,
				 fal_object_t *obj);
	int (*delete_lag_member)(fal_object_t obj);
	int (*set_lag_member_attr)(fal_object_t obj,
				   const struct fal_attribute_t *attr);
	int (*get_lag_member_attr)(fal_object_t obj,
				   uint32_t attr_count,
				   struct fal_attribute_t *attr_list);
};

struct fal_stp_ops {
	int (*create)(unsigned int bridge_ifindex, uint32_t attr_count,
		      const struct fal_attribute_t *attr_list,
		      fal_object_t *obj);
	int (*delete)(fal_object_t obj);
	int (*set_attribute)(fal_object_t obj,
			     const struct fal_attribute_t *attr);
	int (*get_attribute)(fal_object_t obj,
			     uint32_t attr_count,
			     struct fal_attribute_t *attr_list);
	int (*set_port_attribute)(unsigned int child_ifindex,
				  uint32_t attr_count,
				  const struct fal_attribute_t *attr_list);
	int (*get_port_attribute)(unsigned int child_ifindex,
				  uint32_t attr_count,
				  struct fal_attribute_t *attr_list);
};

/*
 * bridge_ops provide the ability for a receiver 'hdlr' to work with data
 * parsed from AF_BRIDGE netlink messages.
 */
struct fal_bridge_ops {
	void (*new_port)(unsigned int bridge_ifindex,
			 unsigned int child_ifindex,
			 uint32_t attr_count,
			 const struct fal_attribute_t *attr_list);
	void (*upd_port)(unsigned int child_ifindex,
			 const struct fal_attribute_t *attr_list);
	void (*del_port)(unsigned int bridge_ifindex,
			 unsigned int child_ifindex);
	void (*new_neigh)(unsigned int child_ifindex,
			  uint16_t vlanid,
			  const struct rte_ether_addr *dst,
			  uint32_t attr_count,
			  const struct fal_attribute_t *attr_list);
	void (*upd_neigh)(unsigned int child_ifindex,
			  uint16_t vlanid,
			  const struct rte_ether_addr *dst,
			  struct fal_attribute_t *attr);
	void (*del_neigh)(unsigned int child_ifindex,
			  uint16_t vlanid,
			  const struct rte_ether_addr *dst);
	void (*flush_neigh)(unsigned int bridge_ifindex,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);
	int (*walk_neigh)(unsigned int bridge_ifindex, uint16_t vlanid,
			  const struct rte_ether_addr *dst,
			  unsigned int child_ifindex,
			  fal_br_walk_neigh_fn cb, void *arg);
};

struct fal_vlan_ops {
	int (*get_stats)(uint16_t vlan, uint32_t num_cntrs,
			 const enum fal_vlan_stat_type *cntr_ids,
			 uint64_t *cntrs);
	int (*clear_stats)(uint16_t vlan, uint32_t num_cntrs,
			   const enum fal_vlan_stat_type *cntr_ids);
};

/*
 * ip_ops provide the ability for a receiver 'hdlr' to work with data
 * parsed from AF_INET netlink messages.
 */
struct fal_ip_ops {
	void (*new_addr)(unsigned int if_index,
			 struct fal_ip_address_t *ipaddr,
			 uint8_t prefixlen,
			 uint32_t attr_count,
			 const struct fal_attribute_t *attr_list);
	void (*upd_addr)(unsigned int if_index,
			 struct fal_ip_address_t *ipaddr,
			 uint8_t prefixlen,
			 struct fal_attribute_t *attr);
	void (*del_addr)(unsigned int if_index,
			 struct fal_ip_address_t *ipaddr,
			 uint8_t prefixlen);
	int (*new_neigh)(unsigned int if_index,
			 struct fal_ip_address_t *ipaddr,
			 uint32_t attr_count,
			 const struct fal_attribute_t *attr_list);
	int (*upd_neigh)(unsigned int if_index,
			 struct fal_ip_address_t *ipaddr,
			 struct fal_attribute_t *attr);
	int (*get_neigh_attrs)(unsigned int if_index,
			       struct fal_ip_address_t *ipaddr,
			       uint32_t attr_count,
			       const struct fal_attribute_t *attr_list);
	int (*del_neigh)(unsigned int if_index,
			 struct fal_ip_address_t *ipaddr);
	void (*dump_neigh)(unsigned int if_index,
			   struct fal_ip_address_t *ipaddr,
			   json_writer_t *wr);
	int (*new_route)(uint32_t vrf_id,
			 struct fal_ip_address_t *ipaddr,
			 uint8_t prefixlen,
			 uint32_t tableid,
			 uint32_t attr_count,
			 const struct fal_attribute_t *attr_list);
	int (*upd_route)(uint32_t vrf_id,
			 struct fal_ip_address_t *ipaddr,
			 uint8_t prefixlen,
			 uint32_t tableid,
			 struct fal_attribute_t *attr);
	int (*del_route)(uint32_t vrf_id,
			 struct fal_ip_address_t *ipaddr,
			 uint8_t prefixlen,
			 uint32_t tableid);
	int (*get_route_attrs)(uint32_t vrf_id,
			       struct fal_ip_address_t *ipaddr,
			       uint8_t prefixlen,
			       uint32_t tableid,
			       uint32_t attr_count,
			       const struct fal_attribute_t *attr_list);
	int  (*walk_routes)(fal_plugin_route_walk_fn cb,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    void *arg);
	int (*new_next_hop_group)(uint32_t attr_count,
				  const struct fal_attribute_t *attr_list,
				  fal_object_t *obj);
	int (*upd_next_hop_group)(fal_object_t obj,
				  const struct fal_attribute_t *attr);
	int (*del_next_hop_group)(fal_object_t obj);
	int (*get_next_hop_group_attrs)(
		fal_object_t obj,
		uint32_t attr_count,
		const struct fal_attribute_t *attr_list);
	void (*dump_next_hop_group)(fal_object_t obj, json_writer_t *wr);
	int (*new_next_hops)(uint32_t nh_count,
			     const uint32_t *attr_count,
			     const struct fal_attribute_t **attr_list,
			     fal_object_t *obj_list);
	int (*upd_next_hop)(fal_object_t obj,
			    const struct fal_attribute_t *attr);
	int (*del_next_hops)(uint32_t nh_count,
			     const fal_object_t *obj_list);
	int (*get_next_hop_attrs)(fal_object_t obj,
				  uint32_t attr_count,
				  const struct fal_attribute_t *attr_list);
	void (*dump_next_hop)(fal_object_t obj, json_writer_t *wr);
};

struct fal_acl_ops {
	/* A "table" corresponds to a named "group" */
	int (*create_table)(uint32_t attr_count,
			    const struct fal_attribute_t *attr,
			    fal_object_t *new_table_id);
	int (*delete_table)(fal_object_t table_id);
	int (*set_table_attr)(fal_object_t table_id,
			      const struct fal_attribute_t *attr);
	int (*get_table_attr)(fal_object_t table_id,
			      uint32_t attr_count,
			      struct fal_attribute_t *attr_list);
	/* An "entry" corresponds to a numbered "rule" in a "group" */
	int (*create_entry)(uint32_t attr_count,
			    const struct fal_attribute_t *attr,
			    fal_object_t *new_entry_id);
	int (*delete_entry)(fal_object_t entry_id);
	int (*set_entry_attr)(fal_object_t entry_id,
			      const struct fal_attribute_t *attr);
	int (*get_entry_attr)(fal_object_t entry_id,
			      uint32_t attr_count,
			      struct fal_attribute_t *attr_list);
	/* A "counter" is associated with a "table" (aka named "group") */
	int (*create_counter)(uint32_t attr_count,
			      const struct fal_attribute_t *attr,
			      fal_object_t *new_counter_id);
	int (*delete_counter)(fal_object_t counter_id);
	int (*set_counter_attr)(fal_object_t counter_id,
				const struct fal_attribute_t *attr);
	int (*get_counter_attr)(fal_object_t counter_id,
				uint32_t attr_count,
				struct fal_attribute_t *attr_list);
	/*
	 * We will eventually add "table_group" and "table_group_member" which
	 * correspond to "rulesets" of named "groups" on an "attach point".
	 *
	 * We may eventually add "range".
	 */
};

/*
 * ipmc_ops provide the ability for a receiver 'hdlr' to work with data
 * parsed from AF_INET multicast netlink messages.
 */
struct fal_ipmc_ops {
	int (*create_entry)(const struct fal_ipmc_entry_t *ipmc_entry,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *obj);
	int (*delete_entry)(fal_object_t obj);
	int (*set_entry_attr)(fal_object_t obj,
			      const struct fal_attribute_t *attr);
	int (*get_entry_attr)(fal_object_t obj,
			      uint32_t attr_count,
			      const struct fal_attribute_t *attr_list);
	int (*get_entry_stats)(
		fal_object_t obj,
		uint32_t num_counters,
		const enum fal_ip_mcast_entry_stat_type *cntr_ids,
		uint64_t *cntrs);
	int (*clear_entry_stats)(
		fal_object_t obj,
		uint32_t num_counters,
		const enum fal_ip_mcast_entry_stat_type *cntr_ids);
	int (*create_group)(uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *obj);
	int (*delete_group)(fal_object_t obj);
	int (*set_group_attr)(fal_object_t obj,
			      const struct fal_attribute_t *attr);
	int (*get_group_attr)(fal_object_t obj,
			      uint32_t attr_count,
			      const struct fal_attribute_t *attr_list);
	int (*create_member)(uint32_t attr_count,
			     const struct fal_attribute_t *attr_list,
			     fal_object_t *obj);
	int (*delete_member)(fal_object_t obj);
	int (*set_member_attr)(fal_object_t obj,
			       const struct fal_attribute_t *attr);
	int (*get_member_attr)(fal_object_t obj,
			       uint32_t attr_count,
			       const struct fal_attribute_t *attr_list);
	int (*create_rpf_group)(uint32_t attr_count,
				const struct fal_attribute_t *attr_list,
				fal_object_t *obj);
	int (*delete_rpf_group)(fal_object_t obj);
	int (*set_rpf_group_attr)(fal_object_t obj,
				  const struct fal_attribute_t *attr);
	int (*get_rpf_group_attr)(fal_object_t obj,
				  uint32_t attr_count,
				  const struct fal_attribute_t *attr_list);
	int (*create_rpf_member)(uint32_t attr_count,
				 const struct fal_attribute_t *attr_list,
				 fal_object_t *obj);
	int (*delete_rpf_member)(fal_object_t obj);
	int (*set_rpf_member_attr)(fal_object_t obj,
				   const struct fal_attribute_t *attr);
	int (*get_rpf_member_attr)(fal_object_t obj,
				   uint32_t attr_count,
				   const struct fal_attribute_t *attr_list);
};

/* qos_ops provide ability handle vyatta-dataplane QoS configuration commands */
struct fal_qos_ops {
	/* QoS queue object functions */
	int (*new_queue)(fal_object_t switch_id,
			 uint32_t attr_count,
			 const struct fal_attribute_t *attr_list,
			 fal_object_t *new_queue_id);
	int (*del_queue)(fal_object_t queue_id);
	int (*upd_queue)(fal_object_t queue_id,
			 const struct fal_attribute_t *attr);
	int (*get_queue_attrs)(fal_object_t queue_id,
			       uint32_t attr_count,
			       struct fal_attribute_t *attr_list);
	int (*get_queue_stats)(fal_object_t queue_id,
			       uint32_t number_of_counters,
			       const uint32_t *counter_ids, uint64_t *counters);
	int (*get_queue_stats_ext)(fal_object_t queue_id,
				   uint32_t number_of_counters,
				   const uint32_t *counter_ids,
				   bool read_and_clear, uint64_t *counters);
	int (*clear_queue_stats)(fal_object_t queue_id,
				 uint32_t number_of_counters,
				 const uint32_t *counter_ids);
	/* QoS map object functions */
	int (*new_map)(fal_object_t switch_id,
		       uint32_t attr_count,
		       const struct fal_attribute_t *attr_list,
		       fal_object_t *new_map_id);
	int (*del_map)(fal_object_t map_id);
	int (*upd_map)(fal_object_t map_id,
		       const struct fal_attribute_t *attr);
	int (*get_map_attrs)(fal_object_t map_id,
			     uint32_t attr_count,
			     struct fal_attribute_t *attr_list);
	void (*dump_map)(fal_object_t map_id, json_writer_t *wr);
	/* QoS scheduler object functions */
	int (*new_scheduler)(fal_object_t switch_id,
			     uint32_t attr_count,
			     const struct fal_attribute_t *attr_list,
			     fal_object_t *new_scheduler_id);
	int (*del_scheduler)(fal_object_t scheduler_id);
	int (*upd_scheduler)(fal_object_t scheduler_id,
			     const struct fal_attribute_t *attr);
	int (*get_scheduler_attrs)(fal_object_t scheduler_id,
				   uint32_t attr_count,
				   struct fal_attribute_t *attr_list);
	/* QoS scheduler-group object functions */
	int (*new_sched_group)(fal_object_t switch_id,
			       uint32_t attr_count,
			       const struct fal_attribute_t *attr_list,
			       fal_object_t *new_sched_group_id);
	int (*del_sched_group)(fal_object_t sched_group_id);
	int (*upd_sched_group)(fal_object_t sched_group_id,
			       const struct fal_attribute_t *attr);
	int (*get_sched_group_attrs)(fal_object_t sched_group_id,
				     uint32_t attr_count,
				     struct fal_attribute_t *attr_list);
	void (*dump_sched_group)(fal_object_t sg_id, json_writer_t *wr);
	/* QoS WRED object functions */
	int (*new_wred)(fal_object_t switch_id,
			uint32_t attr_count,
			const struct fal_attribute_t *attr_list,
			fal_object_t *new_wred_id);
	int (*del_wred)(fal_object_t wred_id);
	int (*upd_wred)(fal_object_t wred_id,
			const struct fal_attribute_t *attr);
	int (*get_wred_attrs)(fal_object_t wred_id, uint32_t attr_count,
			      struct fal_attribute_t *attr_list);
	int (*get_counters)(const uint32_t *cntr_ids,
			    uint32_t num_cntrs,
			    uint64_t *cntrs);
	void (*dump_buf_errors)(json_writer_t *wr);
};

struct fal_sw_ops {
	int (*set_attribute)(const struct fal_attribute_t *attr);
	int (*get_attribute)(uint32_t attr_count,
			     struct fal_attribute_t *attr_list);
};

/* sys_ops provide ability to handle system level events */
struct fal_sys_ops {
	void (*cleanup)(void);
	void (*command)(FILE *f, int argc, char **argv);
	int (*command_ret)(FILE *f, int argc, char **argv);
};

/*
 * policer ops are used for setting up storm control and
 * other traffic policing operations.
 */
struct fal_policer_ops {
	/* The policer APIs follow SAI approach */
	int (*create)(uint32_t attr_count,
		      const struct fal_attribute_t *attr_list,
		      fal_object_t *obj);
	int (*delete)(fal_object_t obj);
	int (*set_attr)(fal_object_t obj,
			const struct fal_attribute_t *attr);
	int (*get_attr)(fal_object_t obj,
			uint32_t attr_count,
			struct fal_attribute_t *attr_list);
	int (*get_stats_ext)(fal_object_t obj,
			     uint32_t num_counters,
			     const enum fal_policer_stat_type *cntr_ids,
			     enum fal_stats_mode mode,
			     uint64_t *stats);
	int (*clear_stats)(fal_object_t obj,
			   uint32_t num_counters,
			   const enum fal_policer_stat_type *cntr_ids);
	void (*dump)(fal_object_t obj, json_writer_t *wr);
};

/**
 * Portmirror/portmonitor operations used for setting,updating and
 * deleting portmonitor session
 */
struct fal_mirror_ops {
	int (*session_create)(uint32_t attr_count,
			      const struct fal_attribute_t *attr_list,
			      fal_object_t *mr_obj_id);
	int (*session_delete)(fal_object_t mr_obj_id);
	int (*session_set_attr)(fal_object_t mr_obj_id,
				const struct fal_attribute_t *attr);
	int (*session_get_attr)(fal_object_t mr_obj,
				uint32_t attr_count,
				struct fal_attribute_t *attr_list);
};

/**
 * Vlan_feature operations user for setting, updating and creating a vlan
 * feature.
 */
struct fal_vlan_feat_ops {
	int (*vlan_feature_create)(uint32_t attr_count,
				   const struct fal_attribute_t *attr_list,
				   fal_object_t *fal_obj_id);
	int (*vlan_feature_delete)(fal_object_t fal_obj_id);
	int (*vlan_feature_set_attr)(fal_object_t fal_obj_id,
				     const struct fal_attribute_t *attr);
	int (*vlan_feature_get_attr)(fal_object_t fal_obj_id,
				     uint32_t attr_count,
				     struct fal_attribute_t *attr_list);
};

struct fal_backplane_ops {
	int (*backplane_bind)(unsigned int bp_ifindex, unsigned int ifindex);
	void (*backplane_dump)(unsigned int bp_ifindex, json_writer_t *wr);
};

/*
 * cpp_rl_ops are used for setting up control plane policing rate limiter
 * operations
 */
struct fal_cpp_rl_ops {
	/* CPP rate limiter object functions */
	int (*create)(uint32_t attr_count,
		      const struct fal_attribute_t *attr_list,
		      fal_object_t *new_limiter_id);
	int (*remove)(fal_object_t limiter_id);
	int (*get_attrs)(fal_object_t limiter_id, uint32_t attr_count,
			 struct fal_attribute_t *attr_list);
};

struct fal_ptp_ops {
	int (*create_ptp_clock)(uint32_t attr_count,
				const struct fal_attribute_t *attr_list,
				fal_object_t *clock_obj);
	int (*delete_ptp_clock)(fal_object_t clock_obj);
	int (*dump_ptp_clock)(fal_object_t clock_obj,
			      json_writer_t *wr);
	int (*create_ptp_port)(uint32_t attr_count,
			       const struct fal_attribute_t *attr_list,
			       fal_object_t *port_obj);
	int (*delete_ptp_port)(fal_object_t port_obj);
	int (*create_ptp_peer)(uint32_t attr_count,
			       const struct fal_attribute_t *attr_list,
			       fal_object_t *peer_obj);
	int (*delete_ptp_peer)(fal_object_t peer_obj);
};

struct fal_capture_ops {
	int (*create)(uint32_t attr_count,
		      const struct fal_attribute_t *attr_list,
		      fal_object_t *obj);
	void (*delete)(fal_object_t obj);
	int (*get_stats)(fal_object_t obj,
			 uint32_t num_counters,
			 const enum fal_capture_stat_type *cntr_ids,
			 uint64_t *stats);
};

struct fal_mpls_ops {
	int (*create_route)(const struct fal_mpls_route_t *mpls_route,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);
	int (*delete_route)(const struct fal_mpls_route_t *mpls_route);
	int (*set_route_attr)(const struct fal_mpls_route_t *mpls_route,
			      const struct fal_attribute_t *attr);
	int (*get_route_attr)(const struct fal_mpls_route_t *mpls_route,
			      uint32_t attr_count,
			      struct fal_attribute_t *attr_list);
};

struct fal_vrf_ops {
	int (*create)(uint32_t attr_count,
		      const struct fal_attribute_t *attr_list,
		      fal_object_t *obj);
	int (*delete)(fal_object_t obj);
	int (*set_attr)(fal_object_t obj,
			const struct fal_attribute_t *attr);
	int (*get_attr)(fal_object_t obj,
			uint32_t attr_count,
			struct fal_attribute_t *attr_list);
};

enum fal_rc {
	/* All good */
	FAL_RC_SUCCESS = 0,
	/* Object not required in FAL plugin */
	FAL_RC_NOT_REQ = 1,
};

struct fal_bfd_ops {
	int (*create_session)(fal_object_t *bfd_session_id,
			uint32_t attr_count,
			const struct fal_attribute_t *attr_list);
	int (*delete_session)(fal_object_t bfd_session_id);
	int (*set_session_attr)(fal_object_t bfd_session_id,
			uint32_t attr_count,
			const struct fal_attribute_t *attr_list);
	int (*get_session_attr)(fal_object_t bfd_session_id,
			uint32_t attr_count,
			const struct fal_attribute_t *attr_list);
	int (*get_session_stats)(fal_object_t bfd_session_id,
			uint32_t num_counters,
			const enum fal_bfd_session_stat_t *counter_ids,
			uint64_t *counters);
	int (*dump_session)(fal_object_t bfd_session_id,
			    json_writer_t *wr);
};

void fal_init(void);
void fal_init_plugins(void);
void fal_cleanup(void);
int  cmd_fal(FILE *f, int argc, char **argv);
bool fal_plugins_present(void);
int str_to_fal_ip_address_t(char *str, struct fal_ip_address_t *ipaddr);
const char *fal_ip_address_t_to_str(const struct fal_ip_address_t *ipaddr,
				    char *dst, socklen_t size);
bool fal_is_ipaddr_empty(const struct fal_ip_address_t *ipaddr);
enum fal_ip_addr_family_t addr_family_to_fal_ip_addr_family(int family);

void fal_register_message_handler(struct message_handler *handler);
void fal_delete_message_handler(struct message_handler *handler);

/* Set the ip addr into the given attr */
void fal_attr_set_ip_addr(struct fal_attribute_t *attr,
			  const struct ip_addr *ip);

void fal_l2_new_port(unsigned int if_index,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list);
int fal_l2_get_attrs(unsigned int if_index,
		     uint32_t attr_count,
		     struct fal_attribute_t *attr_list);
int fal_l2_upd_port(unsigned int if_index,
		    struct fal_attribute_t *attr);
void fal_l2_del_port(unsigned int if_index);
void fal_l2_dump_port(unsigned int if_index, json_writer_t *wr);
void fal_l2_new_addr(unsigned int if_index,
		     const struct rte_ether_addr *addr,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list);
void fal_l2_upd_addr(unsigned int if_index,
		     const struct rte_ether_addr *addr,
		     struct fal_attribute_t *attr);
void fal_l2_del_addr(unsigned int if_index,
		     const struct rte_ether_addr *addr);

/* Router Interface related APIs */
int fal_create_router_interface(uint32_t attr_count,
				struct fal_attribute_t *attr_list,
				fal_object_t *obj);
int fal_delete_router_interface(fal_object_t obj);
int fal_set_router_interface_attr(fal_object_t obj,
				  const struct fal_attribute_t *attr);
int
fal_get_router_interface_stats(fal_object_t obj,
			       uint32_t cntr_count,
			       const enum fal_router_interface_stat_t *cntr_ids,
			       uint64_t *cntrs);
void
fal_dump_router_interface(fal_object_t obj, json_writer_t *wr);

/* Tunnel APIs */
int fal_create_tunnel(uint32_t attr_count,
		      struct fal_attribute_t *attr_list,
		      fal_object_t *obj);
int fal_delete_tunnel(fal_object_t obj);
int fal_set_tunnel_attr(fal_object_t obj,
			uint32_t attr_count,
			const struct fal_attribute_t *attr_list);

/* LAG APIs*/
int fal_create_lag(uint32_t attr_count,
		   struct fal_attribute_t *attr_list,
		   fal_object_t *obj);
int fal_delete_lag(fal_object_t obj);
int fal_set_lag_attr(fal_object_t obj,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list);
int fal_get_lag_attr(fal_object_t obj,
		     uint32_t attr_count,
		     struct fal_attribute_t *attr_list);
void fal_dump_lag(fal_object_t obj, json_writer_t *wr);
int fal_create_lag_member(uint32_t attr_count,
			  struct fal_attribute_t *attr_list,
			  fal_object_t *obj);
int fal_delete_lag_member(fal_object_t obj);
int fal_set_lag_member_attr(fal_object_t obj,
			    const struct fal_attribute_t *attr);
int fal_get_lag_member_attr(fal_object_t obj,
			    uint32_t attr_count,
			    struct fal_attribute_t *attr_list);

void fal_br_new_port(unsigned int bridge_ifindex,
		     unsigned int child_ifindex,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list);
void fal_br_upd_port(unsigned int child_ifindex,
		     struct fal_attribute_t *attr);
void fal_br_del_port(unsigned int bridge_ifindex,
		     unsigned int child_ifindex);
void fal_br_new_neigh(unsigned int child_ifindex,
		      uint16_t vlanid,
		      const struct rte_ether_addr *dst,
		      uint32_t attr_count,
		      const struct fal_attribute_t *attr_list);
void fal_br_upd_neigh(unsigned int child_ifindex,
		      uint16_t vlanid,
		      const struct rte_ether_addr *dst,
		      struct fal_attribute_t *attr);
void fal_br_del_neigh(unsigned int child_ifindex,
		      uint16_t vlanid,
		      const struct rte_ether_addr *dst);
void fal_br_flush_neigh(unsigned int bridge_ifindex,
			uint32_t attr_count,
			const struct fal_attribute_t *attr);
void fal_fdb_flush_mac(unsigned int bridge_ifindex, unsigned int child_ifindex,
		       const struct rte_ether_addr *mac);
void fal_fdb_flush(unsigned int bridge_ifindex, unsigned int child_ifindex,
		   uint16_t vlanid, bool only_dynamic);
int fal_br_walk_neigh(unsigned int bridge_ifindex, uint16_t vlanid,
		      const struct rte_ether_addr *dst,
		      unsigned int child_ifindex,
		      fal_br_walk_neigh_fn cb, void *arg);

int fal_vlan_get_stats(uint16_t vlan, uint32_t num_cntrs,
		       const enum fal_vlan_stat_type *cntr_ids,
		       uint64_t *cntrs);
int fal_vlan_clear_stats(uint16_t vlan, uint32_t num_cntrs,
			 const enum fal_vlan_stat_type *cntr_ids);

int fal_stp_create(unsigned int bridge_ifindex, uint32_t attr_count,
		   const struct fal_attribute_t *attr_list,
		   fal_object_t *obj);
int fal_stp_delete(fal_object_t obj);
int fal_stp_set_attribute(fal_object_t obj,
			  const struct fal_attribute_t *attr);
int fal_stp_get_attribute(fal_object_t obj, uint32_t attr_count,
			  struct fal_attribute_t *attr_list);
int fal_stp_set_port_attribute(unsigned int child_ifindex,
			       uint32_t attr_count,
			       const struct fal_attribute_t *attr_list);
int fal_stp_get_port_attribute(unsigned int child_ifindex,
			       uint32_t attr_count,
			       struct fal_attribute_t *attr_list);
int fal_stp_upd_msti(fal_object_t obj, int vlancount, const uint16_t *vlans);
int fal_stp_upd_hw_forwarding(fal_object_t obj, unsigned int if_index,
			      bool hw_forwarding);

int fal_get_switch_attrs(uint32_t attr_count,
			 struct fal_attribute_t *attr_list);

int fal_set_switch_attr(const struct fal_attribute_t *attr);

int fal_ip_new_neigh(unsigned int if_index,
		     const struct sockaddr *sa,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list);
int fal_ip_upd_neigh(unsigned int if_index,
		     const struct sockaddr *sa,
		     const struct fal_attribute_t *attr);
int fal_ip_get_neigh_attrs(unsigned int if_index,
			   const struct sockaddr *sa,
			   uint32_t attr_count,
			   struct fal_attribute_t *attr_list);

int fal_ip4_new_neigh(unsigned int if_index,
		      const struct sockaddr_in *sin,
		      uint32_t attr_count,
		      const struct fal_attribute_t *attr_list);
int fal_ip4_upd_neigh(unsigned int if_index,
		      const struct sockaddr_in *sin,
		      struct fal_attribute_t *attr);
int fal_ip4_del_neigh(unsigned int if_index,
		      const struct sockaddr_in *sin);
void fal_ip4_dump_neigh(unsigned int if_index,
			const struct sockaddr_in *sin,
			json_writer_t *wr);
void fal_ip4_new_addr(unsigned int if_index,
		      const struct if_addr *ifa);
void fal_ip4_upd_addr(unsigned int if_index,
		      const struct if_addr *ifa);
void fal_ip4_del_addr(unsigned int if_index,
		      const struct if_addr *ifa);
int fal_ip_new_next_hops(enum fal_next_hop_group_use use,
			 size_t nhops, const struct next_hop hops[],
			 fal_object_t *nhg_object, fal_object_t *obj);
int fal_ip_del_next_hops(fal_object_t nhg_object, size_t nhops,
			 const fal_object_t *obj);
int fal_ip_upd_next_hop_state(const fal_object_t *nh_list, int index,
			      bool usable);
enum fal_packet_action_t
fal_next_hop_group_packet_action(uint32_t nhops, const struct next_hop hops[]);

int fal_ip4_new_route(vrfid_t vrf_id, in_addr_t addr, uint8_t prefixlen,
		      uint32_t tableid, struct next_hop hops[],
		      size_t nhops, fal_object_t nhg_object);
int fal_ip4_upd_route(vrfid_t vrf_id, in_addr_t addr, uint8_t prefixlen,
		      uint32_t tableid, struct next_hop hops[],
		      size_t nhops, fal_object_t nhg_object);
int fal_ip4_del_route(vrfid_t vrf_id, in_addr_t addr, uint8_t prefixlen,
		      uint32_t tableid);
int fal_ip4_get_route_attrs(vrfid_t vrf_id, in_addr_t addr, uint8_t prefixlen,
			    uint32_t tableid, uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);
int fal_ip6_get_route_attrs(vrfid_t vrf_id, const struct in6_addr *addr,
			    uint8_t prefixlen, uint32_t tableid,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list);
int fal_ip_walk_routes(fal_plugin_route_walk_fn cb,
		       uint32_t attr_cnt,
		       struct fal_attribute_t *attr_list,
		       void *arg);

int fal_create_ipmc_rpf_group(uint32_t *ifindex_list, uint32_t num_int,
			      fal_object_t *rpf_group_id,
			      struct fal_object_list_t **rpf_member_list);
void fal_cleanup_ipmc_rpf_group(fal_object_t *rpf_group_id,
				struct fal_object_list_t
				**rpf_member_list);
int fal_ip4_new_mroute(vrfid_t vrf_id, struct vmfcctl *mfc, struct mfc *rt,
		       struct cds_lfht *iftable);
int fal_ip4_del_mroute(struct mfc *rt);
int fal_ip4_upd_mroute(fal_object_t obj, struct mfc *rt, struct vmfcctl *mfc,
			struct cds_lfht *iftable);
int fal_ip6_new_mroute(vrfid_t vrf_id, struct vmf6cctl *mfc, struct mf6c *rt,
		       struct cds_lfht *iftable);
int fal_ip6_del_mroute(struct mf6c *rt);
int fal_ip6_upd_mroute(fal_object_t obj, struct mf6c *rt, struct vmf6cctl *mfc,
			struct cds_lfht *iftable);

int fal_ip6_new_neigh(unsigned int if_index,
		      const struct sockaddr_in6 *sin6,
		      uint32_t attr_count,
		      const struct fal_attribute_t *attr_list);
int fal_ip6_upd_neigh(unsigned int if_index,
		      const struct sockaddr_in6 *sin6,
		      struct fal_attribute_t *attr);
int fal_ip6_del_neigh(unsigned int if_index,
		      const struct sockaddr_in6 *sin6);
void fal_ip6_dump_neigh(unsigned int if_index,
			const struct sockaddr_in6 *sin6,
			json_writer_t *wr);
void fal_ip6_new_addr(unsigned int if_index,
		      const struct if_addr *ifa);
void fal_ip6_upd_addr(unsigned int if_index,
		      const struct if_addr *ifa);
void fal_ip6_del_addr(unsigned int if_index,
		      const struct if_addr *ifa);
int fal_ip_get_next_hop_group_attrs(fal_object_t nhg_object,
				    uint32_t attr_count,
				    struct fal_attribute_t *attr_list);
void fal_ip_dump_next_hop_group(fal_object_t nhg_object, json_writer_t *wr);
int fal_ip_get_next_hop_attrs(fal_object_t nh_object,
			      uint32_t attr_count,
			      struct fal_attribute_t *attr_list);
void fal_ip_dump_next_hop(fal_object_t nh_object, json_writer_t *wr);
int fal_ip6_new_route(vrfid_t vrf_id, const struct in6_addr *addr,
		      uint8_t prefixlen, uint32_t tableid,
		      struct next_hop hops[], size_t nhops,
		      fal_object_t nhg_object);
int fal_ip6_upd_route(vrfid_t vrf_id, const struct in6_addr *addr,
		      uint8_t prefixlen, uint32_t tableid,
		      struct next_hop hops[], size_t nhops,
		      fal_object_t nhg_object);
int fal_ip6_del_route(vrfid_t vrf_id, const struct in6_addr *addr,
		      uint8_t prefixlen, uint32_t tableid);

int fal_ip_mcast_get_stats(fal_object_t obj, uint32_t num_counters,
			   const enum fal_ip_mcast_entry_stat_type *cntr_ids,
			   uint64_t *cntrs);
int fal_create_ip_mcast_entry(const struct fal_ipmc_entry_t *ipmc_entry,
			      uint32_t attr_count,
			      const struct fal_attribute_t *attr_list,
			      fal_object_t *obj);
int fal_delete_ip_mcast_entry(fal_object_t obj);
int fal_set_ip_mcast_entry_attr(fal_object_t obj,
				const struct fal_attribute_t *attr);
int fal_get_ip_mcast_entry_attr(fal_object_t obj,
				uint32_t attr_count,
				const struct fal_attribute_t *attr_list);

int fal_create_ip_mcast_group(uint32_t attr_count,
			      const struct fal_attribute_t *attr_list,
			      fal_object_t *obj);
int fal_delete_ip_mcast_group(fal_object_t obj);
int fal_set_ip_mcast_group_attr(fal_object_t obj,
				const struct fal_attribute_t *attr);
int fal_get_ip_mcast_group_attr(fal_object_t obj,
				uint32_t attr_count,
				const struct fal_attribute_t *attr_list);

int fal_create_ip_mcast_group_member(uint32_t attr_count,
				     const struct fal_attribute_t *attr_list,
				     fal_object_t *obj);
int fal_delete_ip_mcast_group_member(fal_object_t obj);
int fal_set_ip_mcast_group_member_attr(fal_object_t obj,
				       const struct fal_attribute_t *attr);
int fal_get_ip_mcast_group_member_attr(fal_object_t obj,
				       uint32_t attr_count,
				       const struct fal_attribute_t *attr_list);

int fal_create_rpf_group(uint32_t attr_count,
			 const struct fal_attribute_t *attr_list,
			 fal_object_t *obj);
int fal_delete_rpf_group(fal_object_t obj);
int fal_set_rpf_group_attr(fal_object_t obj,
			   const struct fal_attribute_t *attr);
int fal_get_rpf_group_attr(fal_object_t obj,
			   uint32_t attr_count,
			   const struct fal_attribute_t *attr_list);

int fal_create_rpf_group_member(uint32_t attr_count,
				const struct fal_attribute_t *attr_list,
				fal_object_t *obj);
int fal_delete_rpf_group_member(fal_object_t obj);
int fal_set_rpf_group_member_attr(fal_object_t obj,
				  const struct fal_attribute_t *attr);
int fal_get_rpf_group_member_attr(fal_object_t obj,
				  uint32_t attr_count,
				  const struct fal_attribute_t *attr_list);

const char *fal_traffic_type_to_str(enum fal_traffic_type tr_type);
enum fal_traffic_type fal_traffic_str_to_type(const char *str);

int fal_policer_create(uint32_t attr_count,
		       const struct fal_attribute_t *attr_list,
		       fal_object_t *obj);
int fal_policer_delete(fal_object_t obj);
int fal_policer_set_attr(fal_object_t obj, const struct fal_attribute_t *attr);
int fal_policer_get_attr(fal_object_t obj, uint32_t attr_count,
			 struct fal_attribute_t *attr_list);
int fal_policer_get_stats_ext(fal_object_t obj, uint32_t num_counters,
			      const enum fal_policer_stat_type *cntr_ids,
			      enum fal_stats_mode mode, uint64_t *stats);
int fal_policer_clear_stats(fal_object_t obj,
			    uint32_t num_counters,
			    const enum fal_policer_stat_type *cntr_ids);
void fal_policer_dump(fal_object_t obj, json_writer_t *wr);

/* QoS function prototypes */
int fal_qos_new_queue(fal_object_t switch_id, uint32_t attr_count,
		      const struct fal_attribute_t *attr_list,
		      fal_object_t *new_queue_id);
int fal_qos_del_queue(fal_object_t queue_id);
int fal_qos_upd_queue(fal_object_t queue_id,
		      const struct fal_attribute_t *attr);
int fal_qos_get_queue_stats(fal_object_t queue_id, uint32_t number_of_counters,
			    const uint32_t *counter_ids,
			    uint64_t *counters);
int fal_qos_get_queue_stats_ext(fal_object_t queue_id,
				uint32_t number_of_counters,
				const uint32_t *counter_ids,
				bool read_and_clear, uint64_t *counters);
int fal_qos_clear_queue_stats(fal_object_t queue_id,
			      uint32_t number_of_counters,
			      const uint32_t *counter_ids);
int fal_qos_get_queue_attrs(fal_object_t queue_id, uint32_t attr_count,
			    struct fal_attribute_t *attr_list);
int fal_qos_new_map(fal_object_t switch_id, uint32_t attr_count,
		    const struct fal_attribute_t *attr_list,
		    fal_object_t *new_map_id);
int fal_qos_del_map(fal_object_t map_id);
int fal_qos_upd_map(fal_object_t map_id, const struct fal_attribute_t *attr);
int fal_qos_get_map_attrs(fal_object_t map_id, uint32_t attr_count,
			 struct fal_attribute_t *attr_list);
int fal_qos_new_scheduler(fal_object_t switch_id, uint32_t attr_count,
			  const struct fal_attribute_t *attr_list,
			  fal_object_t *new_sched_id);
int fal_qos_del_scheduler(fal_object_t sched_id);
int fal_qos_upd_scheduler(fal_object_t sched_id,
			  const struct fal_attribute_t *attr);
int fal_qos_get_scheduler_attrs(fal_object_t sched_id, uint32_t attr_count,
			       struct fal_attribute_t *attr_list);
int fal_qos_new_sched_group(fal_object_t switch_id, uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *new_sched_group_id);
int fal_qos_del_sched_group(fal_object_t sched_group_id);
int fal_qos_upd_sched_group(fal_object_t sched_group_id,
			    const struct fal_attribute_t *attr);
int fal_qos_get_sched_group_attrs(fal_object_t sched_group_id,
				  uint32_t attr_count,
				  struct fal_attribute_t *attr_list);
int fal_qos_new_wred(fal_object_t switch_id, uint32_t attr_count,
		     const struct fal_attribute_t *attr_list,
		     fal_object_t *new_wred_id);
int fal_qos_del_wred(fal_object_t wred_id);
int fal_qos_upd_wred(fal_object_t wred_id,  const struct fal_attribute_t *attr);
int fal_qos_get_wred_attrs(fal_object_t wred_id, uint32_t attr_count,
			  struct fal_attribute_t *attr_list);
void fal_qos_dump_map(fal_object_t map, json_writer_t *wr);
void fal_qos_dump_sched_group(fal_object_t sg, json_writer_t *wr);
void fal_qos_dump_buf_errors(json_writer_t *wr);
int fal_qos_get_counters(const uint32_t *cntr_ids, uint32_t num_cntrs,
			uint64_t *cntrs);

int fal_mirror_session_create(uint32_t attr_count,
			      const struct fal_attribute_t *attr_list,
			      fal_object_t *mr_obj_id);
int fal_mirror_session_delete(fal_object_t mr_obj_id);
int fal_mirror_session_set_attr(fal_object_t mr_obj_id,
				const struct fal_attribute_t *attr);
int fal_mirror_session_get_attr(fal_object_t mr_obj, uint32_t attr_count,
				 struct fal_attribute_t *attr_list);

/* Feature storage id for features to access per packet feature data */
uint8_t fal_feat_storageid(void);

int fal_vlan_feature_create(uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *obj);
int fal_vlan_feature_delete(fal_object_t obj);
int fal_vlan_feature_set_attr(fal_object_t obj,
			      const struct fal_attribute_t *attr);
int fal_vlan_feature_get_attr(fal_object_t obj,
			      uint32_t attr_count,
			      struct fal_attribute_t *attr_list);

int fal_backplane_bind(unsigned int bp_ifindex, unsigned int ifindex);
void fal_backplane_dump(unsigned int bp_ifindex, json_writer_t *wr);

int fal_create_cpp_limiter(uint32_t attr_count,
			   const struct fal_attribute_t *attr_list,
			   fal_object_t *new_limiter_id);
int fal_remove_cpp_limiter(fal_object_t limiter_id);
int fal_get_cpp_limiter_attribute(fal_object_t limiter_id, uint32_t attr_count,
				  struct fal_attribute_t *attr_list);

int fal_create_ptp_clock(uint32_t attr_count,
			 const struct fal_attribute_t *attr_list,
			 fal_object_t *clock_obj);
int fal_delete_ptp_clock(fal_object_t clock_obj);
int fal_dump_ptp_clock(fal_object_t clock_obj, json_writer_t *wr);
int fal_create_ptp_port(uint32_t attr_count,
			const struct fal_attribute_t *attr_list,
			fal_object_t *port);
int fal_delete_ptp_port(fal_object_t port);
int fal_create_ptp_peer(uint32_t attr_count,
			const struct fal_attribute_t *attr_list,
			fal_object_t *peer);
int fal_delete_ptp_peer(fal_object_t peer);

/* The various ACL related functions */
int fal_acl_create_table(uint32_t attr_count,
			 const struct fal_attribute_t *attr,
			 fal_object_t *new_table_id);
int fal_acl_delete_table(fal_object_t table_id);
int fal_acl_set_table_attr(fal_object_t table_id,
			   const struct fal_attribute_t *attr);
int fal_acl_get_table_attr(fal_object_t table_id,
			   uint32_t attr_count,
			   struct fal_attribute_t *attr_list);
int fal_acl_create_entry(uint32_t attr_count,
			 const struct fal_attribute_t *attr,
			 fal_object_t *new_entry_id);
int fal_acl_delete_entry(fal_object_t entry_id);
int fal_acl_set_entry_attr(fal_object_t entry_id,
			   const struct fal_attribute_t *attr);
int fal_acl_get_entry_attr(fal_object_t entry_id,
			   uint32_t attr_count,
			   struct fal_attribute_t *attr_list);
int fal_acl_create_counter(uint32_t attr_count,
			   const struct fal_attribute_t *attr,
			   fal_object_t *new_counter_id);
int fal_acl_delete_counter(fal_object_t counter_id);
int fal_acl_set_counter_attr(fal_object_t counter_id,
			     const struct fal_attribute_t *attr);
int fal_acl_get_counter_attr(fal_object_t counter_id,
			     uint32_t attr_count,
			     struct fal_attribute_t *attr_list);
/* End of ACL related functions */

int fal_capture_create(uint32_t attr_count,
		       const struct fal_attribute_t *attr_list,
		       fal_object_t *obj);
void fal_capture_delete(fal_object_t obj);
int fal_capture_get_stats(fal_object_t obj, uint32_t num_counters,
			  const enum fal_capture_stat_type *cntr_ids,
			  uint64_t *stats);

int fal_create_mpls_route(const struct fal_mpls_route_t *mpls_route,
			  uint32_t attr_count,
			  const struct fal_attribute_t *attr_list);
int fal_delete_mpls_route(const struct fal_mpls_route_t *mpls_route);
int fal_set_mpls_route_attr(const struct fal_mpls_route_t *mpls_route,
			    const struct fal_attribute_t *attr);
int fal_get_mpls_route_attr(const struct fal_mpls_route_t *mpls_route,
			    uint32_t attr_count,
			    struct fal_attribute_t *attr_list);

int fal_vrf_create(uint32_t attr_count,
		   const struct fal_attribute_t *attr_list,
		   fal_object_t *obj);
int fal_vrf_delete(fal_object_t obj);
int fal_set_vrf_attr(fal_object_t obj,
		     const struct fal_attribute_t *attr);
int fal_get_vrf_attr(fal_object_t obj,
		     uint32_t attr_count,
		     struct fal_attribute_t *attr_list);

#endif /* FAL_H */
