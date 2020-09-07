/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2016-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <dirent.h>
#include <dlfcn.h>
#include <limits.h>
#include <rte_branch_prediction.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "compiler.h"
#include "fal.h"
#include "fal_plugin.h"
#include "fal_bfd.h"
#include "if_var.h"
#include "ip6_funcs.h"
#include "mpls/mpls.h"
#include "nh_common.h"
#include "route.h"
#include "route_flags.h"
#include "route_v6.h"
#include "vplane_debug.h"
#include "vplane_log.h"
#include "bridge_vlan_set.h"
#include "if/dpdk-eth/hotplug.h"

struct rte_ether_addr;

struct fal_mem {
	struct rcu_head rcu;
	uint8_t data[0];
};


int __externally_visible
fal_port_byifindex(int ifindex, uint16_t *portid)
{
	struct ifnet *ifp = dp_ifnet_byifindex(ifindex);

	if (ifp == NULL || ifp->if_type != IFT_ETHER ||
	    !ifp->if_local_port)
		return -ENODEV;
	*portid = ifp->if_port;
	return 0;
}

void * __externally_visible
fal_malloc(size_t size)
{
	struct fal_mem *fal_mem;

	if (size >= SIZE_MAX - sizeof(*fal_mem))
		return NULL;

	fal_mem = malloc(sizeof(*fal_mem) + size);
	if (!fal_mem)
		return NULL;

	memset(&fal_mem->rcu, 0, sizeof(fal_mem->rcu));

	return &fal_mem->data;
}

void * __externally_visible
fal_calloc(int nmemb, size_t size)
{
	struct fal_mem *fal_mem;
	size_t total_size;

	total_size = nmemb * size;
	if (total_size < size)
		return NULL;
	if (total_size >= SIZE_MAX - sizeof(*fal_mem))
		return NULL;

	fal_mem = calloc(1, sizeof(*fal_mem) + total_size);
	if (!fal_mem)
		return NULL;

	return &fal_mem->data;
}

static void
fal_free_worker(struct rcu_head *head)
{
	struct fal_mem *fal_mem =
		caa_container_of(head, struct fal_mem, rcu);

	free(fal_mem);
}

void __externally_visible
fal_free_deferred(void *ptr)
{
	struct fal_mem *fal_mem;

	if (!ptr)
		return;

	fal_mem = caa_container_of(ptr, struct fal_mem, data);

	call_rcu(&fal_mem->rcu, fal_free_worker);
}

static struct message_handler *fal_handler;

void fal_init(void)
{
}

static struct fal_l2_ops *new_dyn_l2_ops(void *lib)
{
	struct fal_l2_ops *l2_ops = calloc(1, sizeof(struct fal_l2_ops));

	if (!l2_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate l2 ops\n");
		return NULL;
	}

	l2_ops->new_port = dlsym(lib, "fal_plugin_l2_new_port");
	l2_ops->upd_port = dlsym(lib, "fal_plugin_l2_upd_port");
	l2_ops->del_port = dlsym(lib, "fal_plugin_l2_del_port");
	l2_ops->get_attrs = dlsym(lib, "fal_plugin_l2_get_attrs");
	l2_ops->new_addr = dlsym(lib, "fal_plugin_l2_new_addr");
	l2_ops->upd_addr = dlsym(lib, "fal_plugin_l2_upd_addr");
	l2_ops->del_addr = dlsym(lib, "fal_plugin_l2_del_addr");
	return l2_ops;
}

static struct fal_rif_ops *new_dyn_rif_ops(void *lib)
{
	struct fal_rif_ops *rif_ops = calloc(1, sizeof(struct fal_rif_ops));

	if (!rif_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate rif ops\n");
		return NULL;
	}

	rif_ops->create_intf = dlsym(lib, "fal_plugin_create_router_interface");
	rif_ops->delete_intf = dlsym(lib, "fal_plugin_delete_router_interface");
	rif_ops->set_attr = dlsym(lib, "fal_plugin_set_router_interface_attr");
	rif_ops->get_stats = dlsym(lib,
				   "fal_plugin_get_router_interface_stats");
	rif_ops->dump = dlsym(lib, "fal_plugin_dump_router_interface");
	return rif_ops;
}

static struct fal_tun_ops *new_dyn_tun_ops(void *lib)
{
	struct fal_tun_ops *tun_ops = calloc(1, sizeof(struct fal_tun_ops));

	if (!tun_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate tun ops\n");
		return NULL;
	}
	tun_ops->create_tun = dlsym(lib, "fal_plugin_create_tunnel");
	tun_ops->delete_tun = dlsym(lib, "fal_plugin_delete_tunnel");
	tun_ops->set_attr = dlsym(lib, "fal_plugin_set_tunnel_attr");
	return tun_ops;
}

static struct fal_lag_ops *new_dyn_lag_ops(void *lib)
{
	struct fal_lag_ops *lag_ops = calloc(1, sizeof(*lag_ops));

	if (!lag_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate LAG ops\n");
		return NULL;
	}
	lag_ops->create_lag = dlsym(lib, "fal_plugin_create_lag");
	lag_ops->delete_lag = dlsym(lib, "fal_plugin_delete_lag");
	lag_ops->set_lag_attr = dlsym(lib, "fal_plugin_set_lag_attr");
	lag_ops->get_lag_attr = dlsym(lib, "fal_plugin_get_lag_attr");
	lag_ops->dump = dlsym(lib, "fal_plugin_dump_lag");
	lag_ops->create_lag_member = dlsym(lib, "fal_plugin_create_lag_member");
	lag_ops->delete_lag_member = dlsym(lib, "fal_plugin_delete_lag_member");
	lag_ops->set_lag_member_attr =
		dlsym(lib, "fal_plugin_set_lag_member_attr");
	lag_ops->get_lag_member_attr =
		dlsym(lib, "fal_plugin_get_member_lag_attr");
	return lag_ops;
}

static struct fal_bridge_ops *new_dyn_bridge_ops(void *lib)
{
	struct fal_bridge_ops *bridge_ops = calloc(1, sizeof(*bridge_ops));

	if (!bridge_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate bridge ops\n");
		return NULL;
	}

	bridge_ops->new_port = dlsym(lib, "fal_plugin_br_new_port");
	bridge_ops->upd_port = dlsym(lib, "fal_plugin_br_upd_port");
	bridge_ops->del_port = dlsym(lib, "fal_plugin_br_del_port");
	bridge_ops->new_neigh = dlsym(lib, "fal_plugin_br_new_neigh");
	bridge_ops->upd_neigh = dlsym(lib, "fal_plugin_br_upd_neigh");
	bridge_ops->del_neigh = dlsym(lib, "fal_plugin_br_del_neigh");
	bridge_ops->flush_neigh = dlsym(lib, "fal_plugin_br_flush_neigh");
	bridge_ops->walk_neigh = dlsym(lib, "fal_plugin_br_walk_neigh");
	return bridge_ops;
}

static struct fal_vlan_ops *new_dyn_vlan_ops(void *lib)
{
	struct fal_vlan_ops *vlan_ops = calloc(1, sizeof(struct fal_vlan_ops));

	if (!vlan_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate vlan_ops\n");
		return NULL;
	}
	vlan_ops->get_stats = dlsym(lib, "fal_plugin_vlan_get_stats");
	vlan_ops->clear_stats = dlsym(lib, "fal_plugin_vlan_clear_stats");
	return vlan_ops;
}

static struct fal_stp_ops *new_dyn_stp_ops(void *lib)
{
	struct fal_stp_ops *stp_ops = calloc(1, sizeof(struct fal_stp_ops));

	if (!stp_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate stp_ops ops\n");
		return NULL;
	}

	stp_ops->create = dlsym(lib, "fal_plugin_stp_create");
	stp_ops->delete = dlsym(lib, "fal_plugin_stp_delete");
	stp_ops->set_attribute = dlsym(lib, "fal_plugin_stp_set_attribute");
	stp_ops->get_attribute = dlsym(lib, "fal_plugin_stp_get_attribute");
	stp_ops->set_port_attribute = dlsym(
		lib, "fal_plugin_stp_set_port_attribute");
	stp_ops->get_port_attribute = dlsym(
		lib, "fal_plugin_stp_get_port_attribute");
	return stp_ops;
}

static struct fal_ip_ops *new_dyn_ip_ops(void *lib)
{
	struct fal_ip_ops *ip_ops = calloc(1, sizeof(struct fal_ip_ops));

	if (!ip_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate ip ops\n");
		return NULL;
	}

	ip_ops->new_addr = dlsym(lib, "fal_plugin_ip_new_addr");
	ip_ops->upd_addr = dlsym(lib, "fal_plugin_ip_upd_addr");
	ip_ops->del_addr = dlsym(lib, "fal_plugin_ip_del_addr");
	ip_ops->new_neigh = dlsym(lib, "fal_plugin_ip_new_neigh");
	ip_ops->upd_neigh = dlsym(lib, "fal_plugin_ip_upd_neigh");
	ip_ops->get_neigh_attrs = dlsym(lib, "fal_plugin_ip_get_neigh_attrs");
	ip_ops->dump_neigh = dlsym(lib, "fal_plugin_ip_dump_neigh");
	ip_ops->del_neigh = dlsym(lib, "fal_plugin_ip_del_neigh");
	ip_ops->new_route = dlsym(lib, "fal_plugin_ip_new_route");
	ip_ops->upd_route = dlsym(lib, "fal_plugin_ip_upd_route");
	ip_ops->del_route = dlsym(lib, "fal_plugin_ip_del_route");
	ip_ops->get_route_attrs = dlsym(lib, "fal_plugin_ip_get_route_attrs");
	ip_ops->walk_routes = dlsym(lib, "fal_plugin_ip_walk_routes");
	ip_ops->new_next_hop_group = dlsym(
		lib, "fal_plugin_ip_new_next_hop_group");
	ip_ops->upd_next_hop_group = dlsym(
		lib, "fal_plugin_ip_upd_next_hop_group");
	ip_ops->del_next_hop_group = dlsym(
		lib, "fal_plugin_ip_del_next_hop_group");
	ip_ops->get_next_hop_group_attrs = dlsym(
		lib, "fal_plugin_ip_get_next_hop_group_attrs");
	ip_ops->dump_next_hop_group = dlsym(
		lib, "fal_plugin_ip_dump_next_hop_group");
	ip_ops->new_next_hops = dlsym(lib, "fal_plugin_ip_new_next_hops");
	ip_ops->upd_next_hop = dlsym(lib, "fal_plugin_ip_upd_next_hop");
	ip_ops->del_next_hops = dlsym(lib, "fal_plugin_ip_del_next_hops");
	ip_ops->get_next_hop_attrs = dlsym(
		lib, "fal_plugin_ip_get_next_hop_attrs");
	ip_ops->dump_next_hop = dlsym(
		lib, "fal_plugin_ip_dump_next_hop");
	return ip_ops;
}

static struct fal_acl_ops *new_dyn_acl_ops(void *lib)
{
	struct fal_acl_ops *acl_ops = calloc(1, sizeof(struct fal_acl_ops));

	if (!acl_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate acl ops\n");
		return NULL;
	}

	acl_ops->create_table = dlsym(lib, "fal_plugin_acl_create_table");
	acl_ops->delete_table = dlsym(lib, "fal_plugin_acl_delete_table");
	acl_ops->set_table_attr = dlsym(lib, "fal_plugin_acl_set_table_attr");
	acl_ops->get_table_attr = dlsym(lib, "fal_plugin_acl_get_table_attr");

	acl_ops->create_entry = dlsym(lib, "fal_plugin_acl_create_entry");
	acl_ops->delete_entry = dlsym(lib, "fal_plugin_acl_delete_entry");
	acl_ops->set_entry_attr = dlsym(lib, "fal_plugin_acl_set_entry_attr");
	acl_ops->get_entry_attr = dlsym(lib, "fal_plugin_acl_get_entry_attr");

	acl_ops->create_counter = dlsym(lib, "fal_plugin_acl_create_counter");
	acl_ops->delete_counter = dlsym(lib, "fal_plugin_acl_delete_counter");
	acl_ops->set_counter_attr =
		dlsym(lib, "fal_plugin_acl_set_counter_attr");
	acl_ops->get_counter_attr =
		dlsym(lib, "fal_plugin_acl_get_counter_attr");

	return acl_ops;
}

static struct fal_ipmc_ops *new_dyn_ipmc_ops(void *lib)
{
	struct fal_ipmc_ops *ipmc_ops = calloc(1, sizeof(struct fal_ipmc_ops));

	ipmc_ops->create_entry = dlsym(lib, "fal_plugin_create_ip_mcast_entry");
	ipmc_ops->delete_entry = dlsym(lib, "fal_plugin_delete_ip_mcast_entry");
	ipmc_ops->set_entry_attr = dlsym(lib,
				       "fal_plugin_set_ip_mcast_entry_attr");
	ipmc_ops->get_entry_attr = dlsym(lib,
				       "fal_plugin_get_ip_mcast_entry_attr");
	ipmc_ops->get_entry_stats =
		dlsym(lib, "fal_plugin_get_ip_mcast_entry_stats");
	ipmc_ops->clear_entry_stats =
		dlsym(lib, "fal_plugin_clear_ip_mcast_entry_stats");
	ipmc_ops->create_group = dlsym(lib, "fal_plugin_create_ip_mcast_group");
	ipmc_ops->delete_group = dlsym(lib, "fal_plugin_delete_ip_mcast_group");
	ipmc_ops->set_group_attr = dlsym(lib,
				       "fal_plugin_set_ip_mcast_group_attr");
	ipmc_ops->get_group_attr = dlsym(lib,
				       "fal_plugin_get_ip_mcast_group_attr");
	ipmc_ops->create_member = dlsym(
				lib, "fal_plugin_create_ip_mcast_group_member");
	ipmc_ops->delete_member = dlsym(
				lib, "fal_plugin_delete_ip_mcast_group_member");
	ipmc_ops->set_member_attr = dlsym(
			      lib, "fal_plugin_set_ip_mcast_group_member_attr");
	ipmc_ops->get_member_attr = dlsym(
			      lib, "fal_plugin_get_ip_mcast_group_member_attr");
	ipmc_ops->create_rpf_group = dlsym(lib, "fal_plugin_create_rpf_group");
	ipmc_ops->delete_rpf_group = dlsym(lib, "fal_plugin_delete_rpf_group");
	ipmc_ops->set_rpf_group_attr = dlsym(lib,
				       "fal_plugin_set_rpf_group_attr");
	ipmc_ops->get_rpf_group_attr = dlsym(lib,
				       "fal_plugin_get_rpf_group_attr");
	ipmc_ops->create_rpf_member = dlsym(
				lib, "fal_plugin_create_rpf_group_member");
	ipmc_ops->delete_rpf_member = dlsym(
				lib, "fal_plugin_delete_rpf_group_member");
	ipmc_ops->set_rpf_member_attr = dlsym(
				lib, "fal_plugin_set_rpf_group_member_attr");
	ipmc_ops->get_rpf_member_attr = dlsym(
				lib, "fal_plugin_get_rpf_group_member_attr");
	return ipmc_ops;
}

static struct fal_qos_ops *new_dyn_qos_ops(void *lib)
{
	struct fal_qos_ops *qos_ops = calloc(1, sizeof(struct fal_qos_ops));

	if (!qos_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate qos ops\n");
		return NULL;
	}

	qos_ops->new_queue = dlsym(lib, "fal_plugin_qos_new_queue");
	qos_ops->del_queue = dlsym(lib, "fal_plugin_qos_del_queue");
	qos_ops->upd_queue = dlsym(lib, "fal_plugin_qos_upd_queue");
	qos_ops->get_queue_attrs = dlsym(lib, "fal_plugin_qos_get_queue_attrs");
	qos_ops->get_queue_stats = dlsym(lib, "fal_plugin_qos_get_queue_stats");
	qos_ops->get_queue_stats_ext =
		dlsym(lib, "fal_plugin_qos_get_queue_stats_ext");
	qos_ops->clear_queue_stats =
		dlsym(lib, "fal_plugin_qos_clear_queue_stats");
	qos_ops->new_map = dlsym(lib, "fal_plugin_qos_new_map");
	qos_ops->del_map = dlsym(lib, "fal_plugin_qos_del_map");
	qos_ops->upd_map = dlsym(lib, "fal_plugin_qos_upd_map");
	qos_ops->get_map_attrs = dlsym(lib, "fal_plugin_qos_get_map_attrs");
	qos_ops->dump_map = dlsym(lib, "fal_plugin_qos_dump_map");
	qos_ops->new_scheduler =
		dlsym(lib, "fal_plugin_qos_new_scheduler");
	qos_ops->del_scheduler =
		dlsym(lib, "fal_plugin_qos_del_scheduler");
	qos_ops->upd_scheduler =
		dlsym(lib, "fal_plugin_qos_upd_scheduler");
	qos_ops->get_scheduler_attrs =
		dlsym(lib, "fal_plugin_qos_get_scheduler_attrs");
	qos_ops->new_sched_group =
		dlsym(lib, "fal_plugin_qos_new_sched_group");
	qos_ops->del_sched_group =
		dlsym(lib, "fal_plugin_qos_del_sched_group");
	qos_ops->upd_sched_group =
		dlsym(lib, "fal_plugin_qos_upd_sched_group");
	qos_ops->get_sched_group_attrs =
		dlsym(lib, "fal_plugin_qos_get_sched_group_attrs");
	qos_ops->dump_sched_group =
		dlsym(lib, "fal_plugin_qos_dump_sched_group");
	qos_ops->new_wred = dlsym(lib, "fal_plugin_qos_new_wred");
	qos_ops->del_wred = dlsym(lib, "fal_plugin_qos_del_wred");
	qos_ops->upd_wred = dlsym(lib, "fal_plugin_qos_upd_wred");
	qos_ops->get_wred_attrs = dlsym(lib, "fal_plugin_qos_get_wred_attrs");
	qos_ops->get_counters = dlsym(lib, "fal_plugin_qos_get_counters");
	qos_ops->dump_buf_errors =
		dlsym(lib, "fal_plugin_dump_memory_buffer_errors");

	return qos_ops;
}

static struct fal_sw_ops *new_dyn_switch_ops(void *lib)
{
	struct fal_sw_ops *sw_ops = calloc(1, sizeof(*sw_ops));

	if (!sw_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate sw ops\n");
		return NULL;
	}

	sw_ops->get_attribute = dlsym(lib, "fal_plugin_get_switch_attribute");
	sw_ops->set_attribute = dlsym(lib, "fal_plugin_set_switch_attribute");
	return sw_ops;
}

static struct fal_sys_ops *new_dyn_sys_ops(void *lib)
{
	struct fal_sys_ops *sops = calloc(1, sizeof(struct fal_sys_ops));

	if (!sops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate sys ops\n");
		return NULL;
	}

	sops->cleanup = dlsym(lib, "fal_plugin_cleanup");
	sops->command = dlsym(lib, "fal_plugin_command");
	sops->command_ret = dlsym(lib, "fal_plugin_command_ret");
	return sops;
}

static struct fal_policer_ops *new_dyn_policer_ops(void *lib)
{
	struct fal_policer_ops *policer_ops = calloc(1, sizeof(*policer_ops));

	if (!policer_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate policer ops\n");
		return NULL;
	}
	policer_ops->clear_stats = dlsym(lib, "fal_plugin_policer_clear_stats");
	policer_ops->create = dlsym(lib, "fal_plugin_policer_create");
	policer_ops->delete = dlsym(lib, "fal_plugin_policer_delete");
	policer_ops->set_attr =
		dlsym(lib, "fal_plugin_policer_set_attr");
	policer_ops->get_attr =
		dlsym(lib, "fal_plugin_policer_get_attr");
	policer_ops->get_stats_ext = dlsym(lib,
					   "fal_plugin_policer_get_stats_ext");
	policer_ops->dump = dlsym(lib, "fal_plugin_policer_dump");

	return policer_ops;
}

static struct fal_mirror_ops *new_dyn_mirror_ops(void *lib)
{
	struct fal_mirror_ops *mr_ops = calloc(1, sizeof(*mr_ops));

	if (!mr_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate mirror ops\n");
		return NULL;
	}
	mr_ops->session_create = dlsym(lib,
				       "fal_plugin_mirror_session_create");
	mr_ops->session_delete = dlsym(lib,
				       "fal_plugin_mirror_session_delete");
	mr_ops->session_set_attr = dlsym(lib,
					 "fal_plugin_mirror_session_set_attr");
	mr_ops->session_get_attr = dlsym(lib,
					 "fal_plugin_mirror_session_get_attr");
	return mr_ops;
}

static struct fal_vlan_feat_ops *new_dyn_vlan_feat_ops(void *lib)
{
	struct fal_vlan_feat_ops *vlan_feat_ops =
		calloc(1, sizeof(struct fal_vlan_feat_ops));

	if (!vlan_feat_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate vlan_feat ops\n");
		return NULL;
	}
	vlan_feat_ops->vlan_feature_create = dlsym(
		lib, "fal_plugin_vlan_feature_create");
	vlan_feat_ops->vlan_feature_delete = dlsym(
		lib, "fal_plugin_vlan_feature_delete");
	vlan_feat_ops->vlan_feature_set_attr = dlsym(
		lib, "fal_plugin_vlan_feature_set_attr");
	vlan_feat_ops->vlan_feature_get_attr = dlsym(
		lib, "fal_plugin_vlan_feature_get_attr");
	return vlan_feat_ops;
}

static struct fal_backplane_ops *new_dyn_backplane_ops(void *lib)
{
	struct fal_backplane_ops *backplane_ops =
		calloc(1, sizeof(struct fal_backplane_ops));

	if (!backplane_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate backplane ops\n");
		return NULL;
	}

	backplane_ops->backplane_bind = dlsym(lib, "fal_plugin_backplane_bind");
	backplane_ops->backplane_dump = dlsym(lib, "fal_plugin_backplane_dump");

	return backplane_ops;
}

static struct fal_cpp_rl_ops *new_dyn_cpp_rl_ops(void *lib)
{
	struct fal_cpp_rl_ops *cpp_rl_ops = calloc(1, sizeof(*cpp_rl_ops));

	if (!cpp_rl_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate cpp_rl ops\n");
		return NULL;
	}

	cpp_rl_ops->create = dlsym(lib, "fal_plugin_create_cpp_limiter");
	cpp_rl_ops->remove = dlsym(lib, "fal_plugin_remove_cpp_limiter");
	cpp_rl_ops->get_attrs = dlsym(lib,
				      "fal_plugin_get_cpp_limiter_attribute");

	return cpp_rl_ops;
}

static struct fal_ptp_ops *new_dyn_ptp_ops(void *lib)
{
	struct fal_ptp_ops *ptp_ops;

	ptp_ops = calloc(1, sizeof(struct fal_ptp_ops));
	if (!ptp_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate ptp ops\n");
		return NULL;
	}

	ptp_ops->create_ptp_clock =
				dlsym(lib, "fal_plugin_create_ptp_clock");
	ptp_ops->delete_ptp_clock =
				dlsym(lib, "fal_plugin_delete_ptp_clock");
	ptp_ops->dump_ptp_clock =
				dlsym(lib, "fal_plugin_dump_ptp_clock");
	ptp_ops->create_ptp_port = dlsym(lib, "fal_plugin_create_ptp_port");
	ptp_ops->delete_ptp_port = dlsym(lib, "fal_plugin_delete_ptp_port");
	ptp_ops->create_ptp_peer = dlsym(lib, "fal_plugin_create_ptp_peer");
	ptp_ops->delete_ptp_peer = dlsym(lib, "fal_plugin_delete_ptp_peer");

	return ptp_ops;
}

static struct fal_bfd_ops *new_dyn_bfd_ops(void *lib)
{
	struct fal_bfd_ops *bfd_ops;

	bfd_ops = calloc(1, sizeof(*bfd_ops));
	if (!bfd_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate bfd ops\n");
		return NULL;
	}

	bfd_ops->create_session = dlsym(lib, "fal_plugin_bfd_create_session");
	bfd_ops->delete_session = dlsym(lib, "fal_plugin_bfd_delete_session");
	bfd_ops->set_session_attr = dlsym(lib,
		"fal_plugin_bfd_set_session_attribute");
	bfd_ops->get_session_attr = dlsym(lib,
		"fal_plugin_bfd_get_session_attribute");
	bfd_ops->get_session_stats = dlsym(lib,
		"fal_plugin_bfd_get_session_stats");

	return bfd_ops;
}

static struct fal_capture_ops *new_dyn_capture_ops(void *lib)
{
	struct fal_capture_ops *ops;

	ops = calloc(1, sizeof(struct fal_capture_ops));
	if (ops == NULL) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate capture ops\n");
		return NULL;
	}

	ops->create = dlsym(lib, "fal_plugin_capture_create");
	ops->delete = dlsym(lib, "fal_plugin_capture_delete");
	return ops;
}

static struct fal_mpls_ops *new_dyn_mpls_ops(void *lib)
{
	struct fal_mpls_ops *mpls_ops = calloc(1, sizeof(*mpls_ops));

	if (!mpls_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate mpls ops\n");
		return NULL;
	}

	mpls_ops->create_route = dlsym(lib, "fal_plugin_create_mpls_route");
	mpls_ops->delete_route = dlsym(lib, "fal_plugin_delete_mpls_route");
	mpls_ops->set_route_attr = dlsym(lib, "fal_plugin_set_mpls_route_attr");
	mpls_ops->get_route_attr = dlsym(lib, "fal_plugin_get_mpls_route_attr");

	return mpls_ops;
}

static struct fal_vrf_ops *new_dyn_vrf_ops(void *lib)
{
	struct fal_vrf_ops *vrf_ops = calloc(1, sizeof(*vrf_ops));

	if (!vrf_ops) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate vrf ops\n");
		return NULL;
	}

	vrf_ops->create = dlsym(lib, "fal_plugin_create_vrf");
	vrf_ops->delete = dlsym(lib, "fal_plugin_delete_vrf");
	vrf_ops->set_attr = dlsym(lib, "fal_plugin_set_vrf_attr");
	vrf_ops->get_attr = dlsym(lib, "fal_plugin_get_vrf_attr");

	return vrf_ops;
}

static void register_dyn_msg_handlers(void *lib)
{
	struct message_handler *handler =
				calloc(1, sizeof(struct message_handler));

	if (!handler) {
		RTE_LOG(ERR, DATAPLANE, "Could not allocate handler message\n");
		return;
	}

	handler->l2 = new_dyn_l2_ops(lib);
	handler->rif = new_dyn_rif_ops(lib);
	handler->lag = new_dyn_lag_ops(lib);
	handler->tun = new_dyn_tun_ops(lib);
	handler->bridge = new_dyn_bridge_ops(lib);
	handler->vlan = new_dyn_vlan_ops(lib);
	handler->stp = new_dyn_stp_ops(lib);
	handler->ip = new_dyn_ip_ops(lib);
	handler->acl = new_dyn_acl_ops(lib);
	handler->ipmc = new_dyn_ipmc_ops(lib);
	handler->qos = new_dyn_qos_ops(lib);
	handler->sys = new_dyn_sys_ops(lib);
	handler->policer = new_dyn_policer_ops(lib);
	handler->sw = new_dyn_switch_ops(lib);
	handler->mirror = new_dyn_mirror_ops(lib);
	handler->vlan_feat = new_dyn_vlan_feat_ops(lib);
	handler->backplane = new_dyn_backplane_ops(lib);
	handler->cpp_rl = new_dyn_cpp_rl_ops(lib);
	handler->ptp = new_dyn_ptp_ops(lib);
	handler->capture = new_dyn_capture_ops(lib);
	handler->bfd = new_dyn_bfd_ops(lib);
	handler->mpls = new_dyn_mpls_ops(lib);
	handler->vrf = new_dyn_vrf_ops(lib);

	fal_register_message_handler(handler);
}

static int fal_plugin_init_fn(void *lib, const char *name)
{
	int (*init)(void);

	init = dlsym(lib, name);
	if (!init)
		return 0;

	return (*init)();
}

static int plugin_init_log(void *lib)
{
	return fal_plugin_init_fn(lib, "fal_plugin_init_log");
}

static int plugin_init(void *lib)
{
	return fal_plugin_init_fn(lib, "fal_plugin_init");
}

static void fal_setup_plugin_interfaces(void *lib)
{

	void (*setup_interfaces)(void);
	setup_interfaces = dlsym(lib, "fal_plugin_setup_interfaces");
	if (!setup_interfaces)
		return; //nothing to do
	(*setup_interfaces)();
}

static void fal_init_plugin(const char *plugin)
{
	DP_DEBUG(INIT, INFO, FAL, "Initializing plugin: %s\n", plugin);
	void *lib = dlopen(plugin, RTLD_LAZY);
	if (!lib) {
		DP_DEBUG(INIT, ERR, FAL, "%s\n", dlerror());
		return;
	}
	if (plugin_init_log(lib) < 0)
		return;

	if (plugin_init(lib) < 0)
		return;

	register_dyn_msg_handlers(lib);
	fal_setup_plugin_interfaces(lib);
}

void fal_init_plugins(void)
{
	/* load plugin from platform.conf (if set) */
	if (platform_cfg.fal_plugin)
		fal_init_plugin(platform_cfg.fal_plugin);
}

void fal_register_message_handler(struct message_handler *handler)
{
	assert(!fal_handler);
	fal_handler = handler;
}

static void free_message_handler(struct message_handler *handler)
{
	free(handler->l2);
	free(handler->rif);
	free(handler->tun);
	free(handler->bridge);
	free(handler->stp);
	free(handler->ip);
	free(handler->ipmc);
	free(handler->acl);
	free(handler->qos);
	free(handler->lacp);
	free(handler->sys);
	free(handler->sw);
	free(handler->mirror);
	free(handler->vlan_feat);
	free(handler->backplane);
	free(handler->cpp_rl);
	free(handler->capture);
	free(handler->bfd);
	free(handler);
}

void fal_delete_message_handler(struct message_handler *handler __unused)
{
	assert(fal_handler == handler);
	free_message_handler(fal_handler);
	fal_handler = NULL;
}

bool fal_plugins_present(void)
{
	return fal_handler != NULL;
}

#define call_handler(op_type, fn, args...)				\
	{								\
		struct fal_ ## op_type ## _ops *interface = NULL;	\
		if (fal_handler) {					\
			interface = fal_handler->op_type;		\
			if (interface && interface->fn)			\
				interface->fn(args);			\
		}							\
	}

#define call_handler_def_ret(op_type, def_ret, fn, args...)		\
	({								\
		struct fal_ ## op_type ## _ops *interface = NULL;	\
		int ret = def_ret;					\
		if (fal_handler) {					\
			interface = fal_handler->op_type;		\
			if (interface && interface->fn)			\
				ret = interface->fn(args);		\
		}							\
		ret;							\
	})

/* return value defaults to 0 */
#define call_handler_ret(op_type, fn, args...)				\
	call_handler_def_ret(op_type, 0, fn, args)

/* System operations */
void fal_cleanup(void)
{
	call_handler(sys, cleanup);
}

int cmd_fal(FILE *f, int argc, char **argv)
{
	argc--;
	argv++;
	if (argc <= 1)
		return -1;

	if ((streq(argv[0], "plugin"))) {
		argc--;
		argv++;
		/*TODO Implement get_name handlers
		 * and use that to call plugin handlers
		 */
		call_handler(sys, command, f, argc, argv);
		return 0;
	} else if ((streq(argv[0], "plugin_ret"))) {
		argc--;
		argv++;
		/*TODO Implement get_name handlers
		 * and use that to call plugin handlers
		 */
		return call_handler_ret(sys, command_ret, f, argc, argv);
	}

	return -1;
}

/* Layer 2 operatiosn */

void fal_l2_new_port(unsigned int if_index,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list)
{
	call_handler(l2, new_port, if_index, attr_count, attr_list);
}

int fal_l2_get_attrs(unsigned int if_index,
		     uint32_t attr_count,
		     struct fal_attribute_t *attr_list)
{
	struct fal_l2_ops *interface;
	int rc = -1;

	if (fal_handler) {
		interface = fal_handler->l2;
		if (interface && interface->get_attrs)
			rc = interface->get_attrs(if_index,
						  attr_count,
						  attr_list);
	}

	return rc;
}

int fal_l2_upd_port(unsigned int if_index,
		    struct fal_attribute_t *attr)
{
	return call_handler_def_ret(l2, -EOPNOTSUPP, upd_port,
				    if_index, attr);
}

void fal_l2_del_port(unsigned int if_index)
{
	call_handler(l2, del_port, if_index);
}

void fal_l2_new_addr(unsigned int if_index,
		     const struct rte_ether_addr *addr,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list)
{
	call_handler(l2, new_addr, if_index, addr, attr_count, attr_list);
}

void fal_l2_upd_addr(unsigned int if_index,
		     const struct rte_ether_addr *addr,
		     struct fal_attribute_t *attr)
{
	call_handler(l2, upd_addr, if_index, addr, attr);
}

void fal_l2_del_addr(unsigned int if_index, const struct rte_ether_addr *addr)
{
	call_handler(l2, del_addr, if_index, addr);
}

/* Router interface operations */

int
fal_create_router_interface(uint32_t attr_count,
			    struct fal_attribute_t *attr_list,
			    fal_object_t *obj)
{
	return call_handler_def_ret(rif, -EOPNOTSUPP, create_intf,
				    attr_count, attr_list, obj);
}

int
fal_delete_router_interface(fal_object_t obj)
{
	return call_handler_def_ret(rif, -EOPNOTSUPP, delete_intf,
				    obj);
}

int fal_set_router_interface_attr(fal_object_t obj,
				  const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(rif, -EOPNOTSUPP, set_attr,
				    obj, attr);
}

int
fal_get_router_interface_stats(fal_object_t obj,
			       uint32_t cntr_count,
			       const enum fal_router_interface_stat_t *cntr_ids,
			       uint64_t *cntrs)
{
	return call_handler_def_ret(rif, -EOPNOTSUPP, get_stats,
				    obj, cntr_count, cntr_ids, cntrs);
}

void
fal_dump_router_interface(fal_object_t obj, json_writer_t *wr)
{
	call_handler(rif, dump, obj, wr);
}

/* Tunnel operations */

int
fal_create_tunnel(uint32_t attr_count,
		  struct fal_attribute_t *attr_list,
		  fal_object_t *obj)
{
	return call_handler_def_ret(tun, -EOPNOTSUPP, create_tun,
				    attr_count, attr_list, obj);
}

int
fal_delete_tunnel(fal_object_t obj)
{
	return call_handler_def_ret(tun, -EOPNOTSUPP, delete_tun,
				    obj);
}

int fal_set_tunnel_attr(fal_object_t obj,
			uint32_t attr_count,
			const struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(tun, -EOPNOTSUPP, set_attr,
				    obj, attr_count, attr_list);
}

/* LAG operations */
int fal_create_lag(uint32_t attr_count,
		   struct fal_attribute_t *attr_list,
		   fal_object_t *obj)
{
	return call_handler_def_ret(lag, -EOPNOTSUPP, create_lag,
				    attr_count, attr_list, obj);
}

int fal_delete_lag(fal_object_t obj)
{
	return call_handler_def_ret(lag, -EOPNOTSUPP, delete_lag,
				    obj);
}

int fal_set_lag_attr(fal_object_t obj,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(lag, -EOPNOTSUPP, set_lag_attr,
				    obj, attr_count, attr_list);

}

int fal_get_lag_attr(fal_object_t obj,
		     uint32_t attr_count,
		     struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(lag, -EOPNOTSUPP, get_lag_attr,
				    obj, attr_count, attr_list);

}

void
fal_dump_lag(fal_object_t obj, json_writer_t *wr)
{
	call_handler(lag, dump, obj, wr);
}

int fal_create_lag_member(uint32_t attr_count,
			  struct fal_attribute_t *attr_list,
			  fal_object_t *obj)
{
	return call_handler_def_ret(lag, -EOPNOTSUPP, create_lag_member,
				    attr_count, attr_list, obj);
}

int fal_delete_lag_member(fal_object_t obj)
{
	return call_handler_def_ret(lag, -EOPNOTSUPP, delete_lag_member,
				    obj);
}

int fal_set_lag_member_attr(fal_object_t obj,
			    const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(lag, -EOPNOTSUPP, set_lag_member_attr,
				    obj, attr);

}

int fal_get_lag_member_attr(fal_object_t obj,
			    uint32_t attr_count,
			    struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(lag, -EOPNOTSUPP, get_lag_member_attr,
				    obj, attr_count, attr_list);

}

/* Bridge operations */

void fal_br_new_port(unsigned int bridge_ifindex,
		     unsigned int child_ifindex,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list)
{
	call_handler(bridge, new_port,
			  bridge_ifindex, child_ifindex,
			  attr_count, attr_list);
}

void fal_br_upd_port(unsigned int child_ifindex,
		     struct fal_attribute_t *attr)
{
	call_handler(bridge, upd_port, child_ifindex, attr);
}

void fal_br_del_port(unsigned int bridge_ifindex, unsigned int child_ifindex)
{
	call_handler(bridge, del_port, bridge_ifindex, child_ifindex);
}

void fal_br_new_neigh(unsigned int child_ifindex,
		      uint16_t vlanid,
		      const struct rte_ether_addr *dst,
		      uint32_t attr_count,
		      const struct fal_attribute_t *attr_list)
{
	call_handler(bridge, new_neigh, child_ifindex, vlanid, dst,
			  attr_count, attr_list);
}

void fal_br_upd_neigh(unsigned int child_ifindex,
		      uint16_t vlanid,
		      const struct rte_ether_addr *dst,
		      struct fal_attribute_t *attr)
{
	call_handler(bridge, upd_neigh, child_ifindex, vlanid, dst, attr);
}

void fal_br_del_neigh(unsigned int child_ifindex, uint16_t vlanid,
		      const struct rte_ether_addr *dst)
{
	call_handler(bridge, del_neigh, child_ifindex, vlanid, dst);
}

void fal_br_flush_neigh(unsigned int bridge_ifindex,
			uint32_t attr_count,
			const struct fal_attribute_t *attr_list)
{
	call_handler(bridge, flush_neigh, bridge_ifindex,
		     attr_count, attr_list);
}

int fal_br_walk_neigh(unsigned int bridge_ifindex, uint16_t vlanid,
		      const struct rte_ether_addr *dst,
		      unsigned int child_ifindex,
		      fal_br_walk_neigh_fn cb, void *arg)
{
	return call_handler_ret(bridge, walk_neigh, bridge_ifindex, vlanid, dst,
				child_ifindex, cb, arg);
}

void fal_fdb_flush_mac(unsigned int bridge_ifindex,
		       unsigned int child_ifindex,
		       const struct rte_ether_addr *mac)
{
	struct fal_attribute_t attrs[2];
	uint32_t acount = 0;

	if (!fal_plugins_present())
		return;

	if (child_ifindex != 0) {
		attrs[acount].id = FAL_BRIDGE_FDB_FLUSH_PORT;
		attrs[acount].value.u32 = child_ifindex;
		acount++;
	}

	attrs[acount].id = FAL_BRIDGE_FDB_FLUSH_MAC;
	memcpy(&attrs[acount].value.mac, mac, sizeof(attrs[acount].value.mac));
	acount++;

	fal_br_flush_neigh(bridge_ifindex, acount, &attrs[0]);
}

void fal_fdb_flush(unsigned int bridge_ifindex, unsigned int child_ifindex,
		   uint16_t vlanid, bool only_dynamic)
{
	struct fal_attribute_t attrs[3];
	uint32_t acount = 0;

	if (!fal_plugins_present())
		return;

	if (child_ifindex != 0) {
		attrs[acount].id = FAL_BRIDGE_FDB_FLUSH_PORT;
		attrs[acount].value.u32 = child_ifindex;
		acount++;
	}

	if (vlanid != 0) {
		attrs[acount].id = FAL_BRIDGE_FDB_FLUSH_VLAN;
		attrs[acount].value.u16 = vlanid;
		acount++;
	} else if (only_dynamic) {
		attrs[acount].id = FAL_BRIDGE_FDB_FLUSH_TYPE;
		attrs[acount].value.u8 = FAL_BRIDGE_FDB_FLUSH_TYPE_DYNAMIC;
		acount++;
	};

	fal_br_flush_neigh(bridge_ifindex, acount, &attrs[0]);
}

int fal_vlan_get_stats(uint16_t vlan, uint32_t num_cntrs,
		       const enum fal_vlan_stat_type *cntr_ids,
		       uint64_t *cntrs)
{
	return call_handler_ret(vlan, get_stats, vlan, num_cntrs,
				cntr_ids, cntrs);
}

int fal_vlan_clear_stats(uint16_t vlan, uint32_t num_cntrs,
			 const enum fal_vlan_stat_type *cntr_ids)
{
	return call_handler_ret(vlan, clear_stats, vlan, num_cntrs,
				cntr_ids);
}

int fal_stp_create(unsigned int bridge_ifindex,
		   uint32_t attr_count,
		   const struct fal_attribute_t *attr_list,
		   fal_object_t *obj)
{
	return call_handler_ret(stp, create, bridge_ifindex,
				attr_count, attr_list, obj);
}

int fal_stp_delete(fal_object_t obj)
{
	return call_handler_ret(stp, delete, obj);
}

int fal_stp_set_attribute(fal_object_t obj,
			  const struct fal_attribute_t *attr)
{
	return call_handler_ret(stp, set_attribute, obj, attr);
}

int fal_stp_get_attribute(fal_object_t obj, uint32_t attr_count,
			  struct fal_attribute_t *attr_list)
{
	return call_handler_ret(stp, get_attribute, obj, attr_count, attr_list);
}

int fal_stp_set_port_attribute(unsigned int child_ifindex,
			       uint32_t attr_count,
			       const struct fal_attribute_t *attr_list)
{
	return call_handler_ret(stp, set_port_attribute, child_ifindex,
				attr_count, attr_list);
}

int fal_stp_get_port_attribute(unsigned int child_ifindex,
			       uint32_t attr_count,
			       struct fal_attribute_t *attr_list)
{
	return call_handler_ret(stp, get_port_attribute, child_ifindex,
				attr_count, attr_list);
}

int fal_stp_upd_msti(fal_object_t obj, int vlancount, const uint16_t *vlans)
{
	struct fal_attribute_t attrs[1];
	struct bridge_vlan_set *vlanset;
	int i;

	if (!fal_plugins_present())
		return 0;

	vlanset = bridge_vlan_set_create();
	if (vlanset == NULL)
		return -ENOMEM;

	for (i = 0; i < vlancount; i++)
		bridge_vlan_set_add(vlanset, vlans[i]);

	attrs[0].id = FAL_STP_ATTR_MSTP_VLANS;
	attrs[0].value.ptr = vlanset;

	int ret = fal_stp_set_attribute(obj, attrs);

	bridge_vlan_set_free(vlanset);
	return ret;
}

int fal_stp_upd_hw_forwarding(fal_object_t obj, unsigned int if_index,
			      bool hw_forwarding)
{
	if (!fal_plugins_present())
		return 0;

	const struct fal_attribute_t attr_list[2] = {
		{.id = FAL_STP_PORT_ATTR_INSTANCE,
		 .value.objid = obj},
		{.id = FAL_STP_PORT_ATTR_HW_FORWARDING,
		 .value.booldata = hw_forwarding}
	};

	return fal_stp_set_port_attribute(if_index, 2, &attr_list[0]);
}

/* Global switch operations */

int fal_get_switch_attrs(uint32_t attr_count,
			 struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(
		sw, -EOPNOTSUPP, get_attribute, attr_count, attr_list);
}

int fal_set_switch_attr(const struct fal_attribute_t *attr)
{
	return call_handler_ret(sw, set_attribute, attr);
}

/* IP operations */

static void fal_ip_new_addr(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	call_handler(ip, new_addr,
			  if_index, ipaddr, prefixlen,
			  attr_count, attr_list);
}

static void fal_ip_upd_addr(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    struct fal_attribute_t *attr)
{
	call_handler(ip, upd_addr, if_index, ipaddr, prefixlen, attr);
}

static void fal_ip_del_addr(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen)
{
	call_handler(ip, del_addr, if_index, ipaddr, prefixlen);
}

void fal_ip4_new_addr(unsigned int if_index, const struct if_addr *ifa)
{
	struct sockaddr_in *sin = satosin((struct sockaddr *) &ifa->ifa_addr);
	struct sockaddr_in *bsin =
			satosin((struct sockaddr *) &ifa->ifa_broadcast);
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = sin->sin_addr.s_addr
	};
	struct fal_attribute_t attr_list[1] = {
		{ FAL_ADDR_ENTRY_ATTR_BROADCAST, .value.ipaddr = { 0 } },
	};
	int attr_count = 0;

	if (!fal_plugins_present())
		return;

	if (bsin->sin_family) {
		struct fal_ip_address_t *baddr = &attr_list[0].value.ipaddr;

		baddr->addr_family = FAL_IP_ADDR_FAMILY_IPV4;
		baddr->addr.ip4 = bsin->sin_addr.s_addr;
		attr_count = 1;
	}

	fal_ip_new_addr(if_index, &faddr, ifa->ifa_prefixlen,
			attr_count, attr_list);
}

void fal_ip6_new_addr(unsigned int if_index, const struct if_addr *ifa)
{
	struct sockaddr_in6 *sin6 =
				satosin6((struct sockaddr *) &ifa->ifa_addr);
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = sin6->sin6_addr
	};
	struct fal_attribute_t attr_list[1] = {
		{ FAL_ADDR_ENTRY_ATTR_SCOPE, .value.u8 = sin6->sin6_scope_id },
	};
	int attr_count = 1;

	if (!fal_plugins_present())
		return;

	fal_ip_new_addr(if_index, &faddr, ifa->ifa_prefixlen,
			attr_count, attr_list);
}

void fal_ip4_upd_addr(unsigned int if_index, const struct if_addr *ifa)
{
	struct sockaddr_in *sin = satosin((struct sockaddr *) &ifa->ifa_addr);
	struct sockaddr_in *bsin =
			satosin((struct sockaddr *) &ifa->ifa_broadcast);
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = sin->sin_addr.s_addr
	};
	struct fal_attribute_t attr = {
		FAL_ADDR_ENTRY_ATTR_BROADCAST, .value.ipaddr = { 0 } };

	if (!fal_plugins_present())
		return;

	if (bsin->sin_family) {
		struct fal_ip_address_t *baddr = &attr.value.ipaddr;

		baddr->addr_family = FAL_IP_ADDR_FAMILY_IPV4;
		baddr->addr.ip4 = bsin->sin_addr.s_addr;

		fal_ip_upd_addr(if_index, &faddr, ifa->ifa_prefixlen, &attr);
	}
}

void fal_ip6_upd_addr(unsigned int if_index, const struct if_addr *ifa)
{
	struct sockaddr_in6 *sin6 =
				satosin6((struct sockaddr *) &ifa->ifa_addr);
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = sin6->sin6_addr
	};
	struct fal_attribute_t attr = {
		FAL_ADDR_ENTRY_ATTR_SCOPE, .value.u8 = sin6->sin6_scope_id };

	if (!fal_plugins_present())
		return;

	fal_ip_upd_addr(if_index, &faddr, ifa->ifa_prefixlen, &attr);
}

void fal_ip4_del_addr(unsigned int if_index, const struct if_addr *ifa)
{
	struct sockaddr_in *sin = satosin((struct sockaddr *) &ifa->ifa_addr);
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = sin->sin_addr.s_addr
	};

	if (!fal_plugins_present())
		return;

	fal_ip_del_addr(if_index, &faddr, ifa->ifa_prefixlen);
}

void fal_ip6_del_addr(unsigned int if_index, const struct if_addr *ifa)
{
	struct sockaddr_in6 *sin6 =
				satosin6((struct sockaddr *) &ifa->ifa_addr);
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = sin6->sin6_addr
	};

	if (!fal_plugins_present())
		return;

	fal_ip_del_addr(if_index, &faddr, ifa->ifa_prefixlen);
}

static int _fal_ip_new_neigh(unsigned int if_index,
			     struct fal_ip_address_t *ipaddr,
			     uint32_t attr_count,
			     const struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(
		ip, -EOPNOTSUPP, new_neigh, if_index, ipaddr, attr_count,
		attr_list);
}

static int _fal_ip_upd_neigh(unsigned int if_index,
			     struct fal_ip_address_t *ipaddr,
			     const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(
		ip, -EOPNOTSUPP, upd_neigh, if_index, ipaddr,
		(struct fal_attribute_t *)attr);
}

int fal_ip_get_neigh_attrs(unsigned int if_index,
			   const struct sockaddr *sa,
			   uint32_t attr_count,
			   struct fal_attribute_t *attr_list)
{
	struct fal_ip_address_t ipaddr = { 0 };

	if (!fal_plugins_present())
		return -EOPNOTSUPP;

	switch (sa->sa_family) {
	case AF_INET:
		ipaddr.addr_family = FAL_IP_ADDR_FAMILY_IPV4;
		ipaddr.addr.ip4 =
			((const struct sockaddr_in *)sa)->sin_addr.s_addr;
		break;
	case AF_INET6:
		ipaddr.addr_family = FAL_IP_ADDR_FAMILY_IPV6;
		ipaddr.addr.addr6 =
			((const struct sockaddr_in6 *)sa)->sin6_addr;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return call_handler_def_ret(
		ip, -EOPNOTSUPP, get_neigh_attrs, if_index, &ipaddr,
		attr_count, attr_list);
}

int fal_ip_new_neigh(unsigned int if_index,
		     const struct sockaddr *sa,
		     uint32_t attr_count,
		     const struct fal_attribute_t *attr_list)
{
	struct fal_ip_address_t ipaddr = { 0 };

	switch (sa->sa_family) {
	case AF_INET:
		ipaddr.addr_family = FAL_IP_ADDR_FAMILY_IPV4;
		ipaddr.addr.ip4 =
			((const struct sockaddr_in *)sa)->sin_addr.s_addr;
		break;
	case AF_INET6:
		ipaddr.addr_family = FAL_IP_ADDR_FAMILY_IPV6;
		ipaddr.addr.addr6 =
			((const struct sockaddr_in6 *)sa)->sin6_addr;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return _fal_ip_new_neigh(if_index, &ipaddr, attr_count,
				 attr_list);
}


int fal_ip_upd_neigh(unsigned int if_index,
		     const struct sockaddr *sa,
		     const struct fal_attribute_t *attr)
{
	struct fal_ip_address_t ipaddr = { 0 };

	if (!fal_plugins_present())
		return -EOPNOTSUPP;

	switch (sa->sa_family) {
	case AF_INET:
		ipaddr.addr_family = FAL_IP_ADDR_FAMILY_IPV4;
		ipaddr.addr.ip4 =
			((const struct sockaddr_in *)sa)->sin_addr.s_addr;
		break;
	case AF_INET6:
		ipaddr.addr_family = FAL_IP_ADDR_FAMILY_IPV6;
		ipaddr.addr.addr6 =
			((const struct sockaddr_in6 *)sa)->sin6_addr;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return _fal_ip_upd_neigh(if_index, &ipaddr, attr);
}

static int fal_ip_del_neigh(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr)
{
	return call_handler_def_ret(
		ip, -EOPNOTSUPP, del_neigh, if_index, ipaddr);
}

static void fal_ip_dump_neigh(unsigned int if_index,
			     struct fal_ip_address_t *ipaddr,
			     json_writer_t *wr)
{
	call_handler(ip, dump_neigh, if_index, ipaddr, wr);
}

int fal_ip4_new_neigh(unsigned int if_index,
		      const struct sockaddr_in *sin,
		      uint32_t attr_count,
		      const struct fal_attribute_t *attr_list)
{
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = sin->sin_addr.s_addr
	};

	if (!fal_plugins_present())
		return 0;

	return _fal_ip_new_neigh(if_index, &faddr, attr_count, attr_list);
}

int fal_ip6_new_neigh(unsigned int if_index,
		      const struct sockaddr_in6 *sin6,
		      uint32_t attr_count,
		      const struct fal_attribute_t *attr_list)
{
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = sin6->sin6_addr
	};

	if (!fal_plugins_present())
		return 0;

	return _fal_ip_new_neigh(if_index, &faddr, attr_count, attr_list);
}

int fal_ip4_upd_neigh(unsigned int if_index,
		      const struct sockaddr_in *sin,
		      struct fal_attribute_t *attr)
{
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = sin->sin_addr.s_addr,
	};

	if (!fal_plugins_present())
		return 0;

	return _fal_ip_upd_neigh(if_index, &faddr, attr);
}

int fal_ip6_upd_neigh(unsigned int if_index,
		      const struct sockaddr_in6 *sin6,
		      struct fal_attribute_t *attr)
{
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = sin6->sin6_addr
	};

	if (!fal_plugins_present())
		return 0;

	return _fal_ip_upd_neigh(if_index, &faddr, attr);
}

int fal_ip4_del_neigh(unsigned int if_index,
		      const struct sockaddr_in *sin)
{
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = sin->sin_addr.s_addr
	};

	if (!fal_plugins_present())
		return 0;

	return fal_ip_del_neigh(if_index, &faddr);
}

int fal_ip6_del_neigh(unsigned int if_index,
		      const struct sockaddr_in6 *sin6)
{
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = sin6->sin6_addr
	};

	if (!fal_plugins_present())
		return 0;

	return fal_ip_del_neigh(if_index, &faddr);
}

void fal_ip4_dump_neigh(unsigned int if_index,
			const struct sockaddr_in *sin,
			json_writer_t *wr)
{
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = sin->sin_addr.s_addr
	};

	fal_ip_dump_neigh(if_index, &faddr, wr);
}

void fal_ip6_dump_neigh(unsigned int if_index,
			const struct sockaddr_in6 *sin6,
			json_writer_t *wr)
{
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = sin6->sin6_addr
	};

	fal_ip_dump_neigh(if_index, &faddr, wr);
}

static inline bool
is_deagg_nh(struct ifnet *ifp, enum fal_next_hop_group_use use,
	    unsigned int label_count,
	    const union next_hop_outlabels *lbls)
{
	return ifp && is_lo(ifp) && use == FAL_NHG_USE_MPLS_LABEL_SWITCH &&
		(label_count == 0 ||
		 (label_count == 1 &&
		  nh_outlabels_get_value(lbls, 0) == MPLS_IMPLICITNULL));
}

static enum fal_packet_action_t
next_hop_to_packet_action(const struct next_hop *nh)
{
	struct ifnet *ifp;

	if (nh->flags & RTF_BLACKHOLE)
		return FAL_PACKET_ACTION_DROP;

	if (nh->flags & (RTF_LOCAL|RTF_BROADCAST|RTF_SLOWPATH|RTF_REJECT))
		return FAL_PACKET_ACTION_TRAP;

	ifp = dp_nh_get_ifp(nh);
	if (!ifp ||
	    (ifp->fal_l3 == FAL_NULL_OBJECT_ID &&
	     !is_deagg_nh(ifp, FAL_NHG_USE_MPLS_LABEL_SWITCH,
			 nh_outlabels_get_cnt(&nh->outlabels),
			  &nh->outlabels)))
		return FAL_PACKET_ACTION_TRAP;

	return FAL_PACKET_ACTION_FORWARD;
}

static const struct fal_attribute_t **next_hop_to_attr_list(
	fal_object_t nhg_object, size_t nhops,
	const struct next_hop hops[],
	enum fal_next_hop_group_use use, uint32_t **attr_count)
{
	const struct fal_attribute_t **nh_attr_list;
	size_t i;

	nh_attr_list = calloc(nhops, sizeof(*nh_attr_list));
	if (!nh_attr_list)
		return NULL;
	*attr_count = calloc(nhops, sizeof(**attr_count));
	if (!*attr_count) {
		free(nh_attr_list);
		return NULL;
	}

	for (i = 0; i < nhops; i++) {
		const struct next_hop *nh = &hops[i];
		struct fal_attribute_t *nh_attr;
		struct ifnet *ifp;
		unsigned int max_attrs = 7;
		unsigned int nh_attr_count = 0;
		struct fal_u32_list_t *label_list;
		unsigned int label_count =
			nh_outlabels_get_cnt(&nh->outlabels);
		unsigned int label_idx;

		nh_attr_list[i] = nh_attr = calloc(
			1, sizeof(*nh_attr) * max_attrs +
			offsetof(typeof(*label_list),
				 list[label_count]));
		if (!nh_attr) {
			while (i--)
				free((struct fal_attribute_t *)
				     nh_attr_list[i]);
			free(*attr_count);
			free(nh_attr_list);
			return NULL;
		}
		label_list = (struct fal_u32_list_t *)&nh_attr[max_attrs];

		nh_attr[nh_attr_count].id = FAL_NEXT_HOP_ATTR_NEXT_HOP_GROUP;
		nh_attr[nh_attr_count].value.objid = nhg_object;
		nh_attr_count++;
		ifp = dp_nh_get_ifp(nh);
		if (is_deagg_nh(ifp, use, label_count, &nh->outlabels)) {
			nh_attr[nh_attr_count].id =
				FAL_NEXT_HOP_ATTR_VRF_LOOKUP;
			nh_attr[nh_attr_count].value.objid =
				get_vrf(ifp->if_vrfid)->v_fal_obj;
			nh_attr_count++;
		} else {
			nh_attr[nh_attr_count].id = FAL_NEXT_HOP_ATTR_INTF;
			nh_attr[nh_attr_count].value.u32 =
				ifp ? ifp->if_index : 0;
			nh_attr_count++;
			nh_attr[nh_attr_count].id =
				FAL_NEXT_HOP_ATTR_ROUTER_INTF;
			nh_attr[nh_attr_count].value.objid = ifp ? ifp->fal_l3 :
				FAL_NULL_OBJECT_ID;
			nh_attr_count++;
		}
		if (nh->flags & (RTF_GATEWAY | RTF_NEIGH_CREATED)) {
			nh_attr[nh_attr_count].id = FAL_NEXT_HOP_ATTR_IP;
			fal_attr_set_ip_addr(&nh_attr[nh_attr_count],
					     &nh->gateway);
			nh_attr_count++;
		}
		if (nh->flags & RTF_BACKUP) {
			nh_attr[nh_attr_count].id =
				FAL_NEXT_HOP_ATTR_CONFIGURED_ROLE;
			nh_attr[nh_attr_count].value.u32 =
				FAL_NEXT_HOP_CONFIGURED_ROLE_STANDBY;
			nh_attr_count++;
		}
		if (nh->flags & RTF_UNUSABLE) {
			nh_attr[nh_attr_count].id = FAL_NEXT_HOP_ATTR_USABILITY;
			nh_attr[nh_attr_count].value.u32 =
				FAL_NEXT_HOP_UNUSABLE;
			nh_attr_count++;
		}
		if (label_count) {
			nh_attr[nh_attr_count].id =
				FAL_NEXT_HOP_ATTR_MPLS_LABELSTACK;
			nh_attr[nh_attr_count].value.u32list =
				label_list;
			label_list->count = label_count;
			for (label_idx = 0; label_idx < label_count;
			     label_idx++)
				label_list->list[label_idx] =
					nh_outlabels_get_value(
						&nh->outlabels, label_idx);
			nh_attr_count++;
		}
		(*attr_count)[i] = nh_attr_count;
	}

	return nh_attr_list;
}

enum fal_packet_action_t
fal_next_hop_group_packet_action(uint32_t nhops, const struct next_hop hops[])
{
	enum fal_packet_action_t action;
	uint32_t i;

	for (i = 0; i < nhops; i++) {
		action = next_hop_to_packet_action(&hops[i]);
		if (action != FAL_PACKET_ACTION_FORWARD)
			return action;
	}

	return FAL_PACKET_ACTION_FORWARD;
}


int fal_ip_new_next_hops(enum fal_next_hop_group_use use,
			 size_t nhops, const struct next_hop hops[],
			 fal_object_t *nhg_object,
			 fal_object_t *obj_list)
{
	const struct fal_attribute_t **nh_attr_list;
	struct fal_attribute_t nhg_attrs[1];
	uint32_t nhg_attr_count = 0;
	uint32_t *nh_attr_count;
	uint32_t i;
	int ret;
	enum fal_packet_action_t action;

	/* we must have at least one nexthop */
	if (!nhops)
		return -EINVAL;

	if (!fal_plugins_present())
		return -EOPNOTSUPP;

	action = fal_next_hop_group_packet_action(nhops, hops);
	/*
	 * Don't create next_hop_group if there is at least
	 * one nexthop that needs to do something special, since
	 * we can't represent this in the next_hop
	 * attributes. This will be represented instead using
	 * route attributes.
	 */
	if (action != FAL_PACKET_ACTION_FORWARD)
		return FAL_RC_NOT_REQ;

	if (use != FAL_NHG_USE_IP) {
		nhg_attrs[nhg_attr_count].id =
			FAL_NEXT_HOP_GROUP_ATTR_USE;
		nhg_attrs[nhg_attr_count].value.u32 = use;
		nhg_attr_count++;
	}

	ret = call_handler_def_ret(ip, -EOPNOTSUPP,
				   new_next_hop_group, nhg_attr_count,
				   nhg_attrs, nhg_object);
	if (ret < 0)
		return ret;

	nh_attr_list = next_hop_to_attr_list(*nhg_object, nhops, hops,
					     use, &nh_attr_count);
	if (!nh_attr_list) {
		ret = -ENOMEM;
		goto error;
	}

	ret = call_handler_def_ret(ip, -EOPNOTSUPP, new_next_hops,
				   nhops, nh_attr_count, nh_attr_list,
				   obj_list);

	for (i = 0; i < nhops; i++)
		free((struct fal_attribute_t *)nh_attr_list[i]);
	free(nh_attr_list);
	free(nh_attr_count);
	if (ret < 0)
		goto error;

	return ret;

error:
	call_handler_ret(ip, del_next_hop_group, *nhg_object);
	return ret;
}

int fal_ip_del_next_hops(fal_object_t nhg_object, size_t nhops,
			 const fal_object_t *obj_list)
{
	int ret;

	if (!fal_plugins_present())
		return -EOPNOTSUPP;

	ret = call_handler_def_ret(ip, -EOPNOTSUPP, del_next_hops,
				   nhops, obj_list);
	if (ret >= 0)
		ret = call_handler_def_ret(ip, -EOPNOTSUPP,
					   del_next_hop_group,
					   nhg_object);

	return ret;
}

/*
 * The nexthop at 'index' has changed so inform the platforms.
 */
int fal_ip_upd_next_hop_state(const fal_object_t *obj_list,
			      int index, bool usable)
{
	const fal_object_t *nh_obj = &obj_list[index];
	struct fal_attribute_t nh_attr;

	nh_attr.id = FAL_NEXT_HOP_ATTR_USABILITY;
	if (usable)
		nh_attr.value.u32 = FAL_NEXT_HOP_USABLE;
	else
		nh_attr.value.u32 = FAL_NEXT_HOP_UNUSABLE;

	return call_handler_def_ret(ip, -EOPNOTSUPP, upd_next_hop,
				    *nh_obj, &nh_attr);
}

int fal_ip_get_next_hop_group_attrs(fal_object_t nhg_object,
				    uint32_t attr_count,
				    struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(
		ip, -EOPNOTSUPP, get_next_hop_group_attrs, nhg_object,
		attr_count, attr_list);
}

void fal_ip_dump_next_hop_group(fal_object_t nhg_object, json_writer_t *wr)
{
	call_handler(ip, dump_next_hop_group, nhg_object, wr);
}

int fal_ip_get_next_hop_attrs(fal_object_t nh_object,
			      uint32_t attr_count,
			      struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(
		ip, -EOPNOTSUPP, get_next_hop_attrs, nh_object,
		attr_count, attr_list);
}

void fal_ip_dump_next_hop(fal_object_t nh_object, json_writer_t *wr)
{
	call_handler(ip, dump_next_hop, nh_object, wr);
}

static int fal_ip_new_route(unsigned int vrf_id,
			     struct fal_ip_address_t *ipaddr,
			     uint8_t prefixlen,
			     uint32_t tableid,
			     uint32_t attr_count,
			     const struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(
		ip, -EOPNOTSUPP, new_route, vrf_id, ipaddr, prefixlen,
		tableid, attr_count, attr_list);
}

static int fal_ip_upd_route(unsigned int vrf_id,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid,
			    struct fal_attribute_t *attr)
{
	return call_handler_def_ret(
		ip, -EOPNOTSUPP, upd_route, vrf_id, ipaddr, prefixlen,
		tableid, attr);
}

static int fal_ip_del_route(unsigned int vrf_id,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid)
{
	return call_handler_def_ret(
		ip, -EOPNOTSUPP, del_route, vrf_id, ipaddr, prefixlen,
		tableid);
}

static int fal_ip_get_route_attrs(unsigned int vrf_id,
				  struct fal_ip_address_t *ipaddr,
				  uint8_t prefixlen,
				  uint32_t tableid,
				  uint32_t attr_count,
				  const struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(
		ip, -EOPNOTSUPP, get_route_attrs, vrf_id, ipaddr, prefixlen,
		tableid, attr_count, attr_list);
}

int fal_ip_walk_routes(fal_plugin_route_walk_fn cb,
		       uint32_t attr_cnt,
		       struct fal_attribute_t *attr_list,
		       void *arg)
{
	return call_handler_def_ret(ip, -EOPNOTSUPP, walk_routes, cb,
				    attr_cnt, attr_list, arg);
}

int fal_ip4_new_route(vrfid_t vrf_id, in_addr_t addr, uint8_t prefixlen,
		      uint32_t tableid, struct next_hop hops[],
		      size_t nhops, fal_object_t nhg_object)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = addr
	};
	enum fal_packet_action_t action =
		fal_next_hop_group_packet_action(nhops, hops);
	struct fal_attribute_t attr_list[] = {
		{ FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION, .value.u32 = action },
		{ FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP,
		  .value.objid = nhg_object },
	};

	if (!fal_plugins_present())
		return 0;

	return fal_ip_new_route(__vrf_id, &faddr, prefixlen, tableid,
				RTE_DIM(attr_list), attr_list);
}

int fal_ip6_new_route(vrfid_t vrf_id, const struct in6_addr *addr,
		      uint8_t prefixlen, uint32_t tableid,
		      struct next_hop hops[], size_t nhops,
		      fal_object_t nhg_object)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = *addr
	};
	enum fal_packet_action_t action =
		fal_next_hop_group_packet_action(nhops, hops);
	struct fal_attribute_t attr_list[] = {
		{ FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP,
		  .value.objid = nhg_object },
		{ FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION, .value.u32 = action },
	};

	if (!fal_plugins_present())
		return 0;

	return fal_ip_new_route(__vrf_id, &faddr, prefixlen, tableid,
				RTE_DIM(attr_list), attr_list);
}

int fal_ip4_upd_route(vrfid_t vrf_id, in_addr_t addr, uint8_t prefixlen,
		      uint32_t tableid, struct next_hop hops[],
		      size_t nhops, fal_object_t nhg_object)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = addr
	};
	enum fal_packet_action_t action =
		fal_next_hop_group_packet_action(nhops, hops);
	struct fal_attribute_t pa_attr = {
		FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION,
		.value.u32 = action
	};

	int ret = 0;

	if (!fal_plugins_present())
		return 0;

	/*
	 * If this happens then it indicates a bug in the conditions
	 * evaluated by fal_next_hop_group_packet_action, or not
	 * having created the next-hop-group object following a change
	 * in state.
	 */
	if (action == FAL_PACKET_ACTION_FORWARD &&
	    nhg_object == FAL_NULL_OBJECT_ID) {
		RTE_LOG(ERR, ROUTE, "Missing next-hop-group object for route with action of forward\n");
		return -EINVAL;
	}

	ret = fal_ip_upd_route(__vrf_id, &faddr, prefixlen,
			       tableid, &pa_attr);

	if (!ret && action == FAL_PACKET_ACTION_FORWARD) {
		struct fal_attribute_t fnhg_attr = {
				FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP,
				.value.objid = nhg_object };

		ret = fal_ip_upd_route(__vrf_id, &faddr, prefixlen,
				       tableid, &fnhg_attr);
	}

	return ret;
}

int fal_ip6_upd_route(vrfid_t vrf_id, const struct in6_addr *addr,
		      uint8_t prefixlen, uint32_t tableid,
		      struct next_hop hops[], size_t nhops,
		      fal_object_t nhg_object)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = *addr
	};
	int ret = 0;
	enum fal_packet_action_t action =
		fal_next_hop_group_packet_action(nhops, hops);
	struct fal_attribute_t pa_attr = {
		FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION,
		.value.u32 = action
	};

	if (!fal_plugins_present())
		return 0;

	/*
	 * If this happens then it indicates a bug in the conditions
	 * evaluated by fal_next_hop_group_packet_action, or not
	 * having created the next-hop-group object following a change
	 * in state.
	 */
	if (action == FAL_PACKET_ACTION_FORWARD &&
	    nhg_object == FAL_NULL_OBJECT_ID) {
		RTE_LOG(ERR, ROUTE, "Missing next-hop-group object for route with action of forward\n");
		return -EINVAL;
	}

	ret = fal_ip_upd_route(__vrf_id, &faddr, prefixlen,
			       tableid, &pa_attr);

	if (!ret && action == FAL_PACKET_ACTION_FORWARD) {
		struct fal_attribute_t fnhg_attr = {
				FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP,
				.value.objid = nhg_object };

		ret = fal_ip_upd_route(__vrf_id, &faddr, prefixlen,
				       tableid, &fnhg_attr);
	}

	return ret;
}

int fal_ip4_del_route(vrfid_t vrf_id, in_addr_t addr, uint8_t prefixlen,
		      uint32_t tableid)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = addr
	};

	if (!fal_plugins_present())
		return 0;

	return fal_ip_del_route(__vrf_id, &faddr, prefixlen, tableid);
}

int fal_ip6_del_route(vrfid_t vrf_id, const struct in6_addr *addr,
		      uint8_t prefixlen, uint32_t tableid)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = *addr
	};

	if (!fal_plugins_present())
		return 0;

	return fal_ip_del_route(__vrf_id, &faddr, prefixlen, tableid);
}

int fal_ip4_get_route_attrs(vrfid_t vrf_id, in_addr_t addr, uint8_t prefixlen,
			    uint32_t tableid, uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.ip4 = addr
	};

	return fal_ip_get_route_attrs(__vrf_id, &faddr, prefixlen,
				      tableid, attr_count, attr_list);
}

int fal_ip6_get_route_attrs(vrfid_t vrf_id, const struct in6_addr *addr,
			    uint8_t prefixlen, uint32_t tableid,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_ip_address_t faddr = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = *addr
	};

	return fal_ip_get_route_attrs(__vrf_id, &faddr, prefixlen,
				      tableid, attr_count, attr_list);
}

/* IP Multicast operations */
int
fal_create_ip_mcast_entry(const struct fal_ipmc_entry_t *ipmc_entry,
			  uint32_t attr_count,
			  const struct fal_attribute_t *attr_list,
			  fal_object_t *obj)
{
	return call_handler_def_ret(ipmc, -EOPNOTSUPP, create_entry,
				    ipmc_entry, attr_count, attr_list, obj);
}

int
fal_delete_ip_mcast_entry(fal_object_t obj)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, delete_entry,
				    obj);
}

int
fal_set_ip_mcast_entry_attr(fal_object_t obj,
			    const struct fal_attribute_t *attr)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, set_entry_attr,
				    obj, attr);
}

int
fal_get_ip_mcast_entry_attr(fal_object_t obj,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, get_entry_attr,
				    obj, attr_count, attr_list);
}

int
fal_create_ip_mcast_group(uint32_t attr_count,
			  const struct fal_attribute_t *attr_list,
			  fal_object_t *obj)
{
	return call_handler_def_ret(ipmc, -EOPNOTSUPP, create_group,
				    attr_count, attr_list, obj);
}

int
fal_delete_ip_mcast_group(fal_object_t obj)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, delete_group,
				    obj);
}

int
fal_set_ip_mcast_group_attr(fal_object_t obj,
			    const struct fal_attribute_t *attr)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, set_group_attr,
				    obj, attr);
}

int
fal_get_ip_mcast_group_attr(fal_object_t obj,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, get_group_attr,
				    obj, attr_count, attr_list);
}

int
fal_create_ip_mcast_group_member(uint32_t attr_count,
				 const struct fal_attribute_t *attr_list,
				 fal_object_t *obj)
{
	return call_handler_def_ret(ipmc, -EOPNOTSUPP, create_member,
				    attr_count, attr_list, obj);
}

int
fal_delete_ip_mcast_group_member(fal_object_t obj)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, delete_member,
				    obj);
}

int
fal_set_ip_mcast_group_member_attr(fal_object_t obj,
				   const struct fal_attribute_t *attr)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, set_member_attr,
				    obj, attr);
}

int
fal_get_ip_mcast_group_member_attr(fal_object_t obj,
				   uint32_t attr_count,
				   const struct fal_attribute_t *attr_list)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, get_member_attr,
				    obj, attr_count, attr_list);
}

int
fal_create_rpf_group(uint32_t attr_count,
		     const struct fal_attribute_t *attr_list,
		     fal_object_t *obj)
{
	return call_handler_def_ret(ipmc, -EOPNOTSUPP, create_rpf_group,
				    attr_count, attr_list, obj);
}

int
fal_delete_rpf_group(fal_object_t obj)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, delete_rpf_group,
				    obj);
}

int
fal_set_rpf_group_attr(fal_object_t obj,
		       const struct fal_attribute_t *attr)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, set_rpf_group_attr,
				    obj, attr);
}

int
fal_get_rpf_group_attr(fal_object_t obj,
		       uint32_t attr_count,
		       const struct fal_attribute_t *attr_list)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, get_rpf_group_attr,
				    obj, attr_count, attr_list);
}

int
fal_create_rpf_group_member(uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *obj)
{
	return call_handler_def_ret(ipmc, -EOPNOTSUPP, create_rpf_member,
				    attr_count, attr_list, obj);
}

int
fal_delete_rpf_group_member(fal_object_t obj)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, delete_rpf_member,
				    obj);
}

int
fal_set_rpf_group_member_attr(fal_object_t obj,
			      const struct fal_attribute_t *attr)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, set_rpf_member_attr,
				    obj, attr);
}

int
fal_get_rpf_group_member_attr(fal_object_t obj,
			      uint32_t attr_count,
			      const struct fal_attribute_t *attr_list)
{
	if (!obj)
		return 0;

	return call_handler_def_ret(ipmc, -EOPNOTSUPP, get_rpf_member_attr,
				    obj, attr_count, attr_list);
}

void fal_cleanup_ipmc_rpf_group(fal_object_t *rpf_group_id,
				struct fal_object_list_t
				**rpf_member_list)
{
	int ret;
	uint32_t i;

	/* clean up */
	if (*rpf_member_list) {
		for (i = 0; i < (*rpf_member_list)->count; i++) {
			ret = fal_delete_rpf_group_member(
				(*rpf_member_list)->list[i]);
			if (ret != 0)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to delete RPF grp member %d\n",
					 ret);
		}
		free(*rpf_member_list);
		*rpf_member_list = 0;
	}
	if (*rpf_group_id) {
		ret = fal_delete_rpf_group(*rpf_group_id);
		if (ret != 0)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to delete RPF group %d\n", ret);

		*rpf_group_id = 0;
	}
}

int fal_create_ipmc_rpf_group(uint32_t *ifindex_list, uint32_t num_int,
			      fal_object_t *rpf_group_id,
			      struct fal_object_list_t **rpf_member_list)
{
	int ret;
	struct ifnet *ifp;
	struct fal_attribute_t rpf_attr[2] = { { 0 } };
	uint32_t i;

	ret = fal_create_rpf_group(0, NULL, rpf_group_id);

	if (ret) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to create RPF group %d\n", ret);
		return ret;
	}

	*rpf_member_list = calloc(1, sizeof(struct fal_object_list_t) +
				  (num_int * sizeof(fal_object_t)));
	if (!*rpf_member_list) {
		DP_DEBUG(MULTICAST, ERR, MCAST,
			 "FAL failed to create RPF member list.\n");
		ret = -ENOMEM;
		goto cleanup;
	}

	rpf_attr[0].id = FAL_RPF_GROUP_MEMBER_ATTR_RPF_GROUP_ID;
	rpf_attr[0].value.objid = *rpf_group_id;
	for (i = 0; i < num_int; i++) {
		rpf_attr[1].id = FAL_RPF_GROUP_MEMBER_ATTR_RPF_INTERFACE_ID;
		ifp = dp_ifnet_byifindex(ifindex_list[i]);
		if (!ifp || !ifp->fal_l3) {
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to create RPF member bad ifp %s.\n",
				 ifp ? ifp->if_name : "none");
			ret = -EINVAL;
			goto cleanup;
		}
		rpf_attr[1].value.objid = ifp->fal_l3;
		ret = fal_create_rpf_group_member(2, rpf_attr,
						  (*rpf_member_list)->list);
		if (ret) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to create RPF member.\n");
			goto cleanup;
		}
		(*rpf_member_list)->count++;
	}

	return ret;
 cleanup:
	fal_cleanup_ipmc_rpf_group(rpf_group_id, rpf_member_list);
	return ret;
}

static void fal_cleanup_ipmc_olist(struct fal_object_list_t *mlist)
{
	unsigned char i;
	int ret;

	for (i = 0; i < mlist->count; i++) {
		if (mlist->list[i]) {
			ret = fal_delete_ip_mcast_group_member(mlist->list[i]);
			if (ret != 0)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL fail to del ipmc grp mmbr %d\n",
					 ret);

			mlist->list[i] = 0;
		}
	}
	mlist->count = 0;
}

static int fal_ip4_iterate_ipmc_olist(unsigned char count,
				      struct if_set *mfcc_ifset,
				      struct fal_attribute_t *m_attr,
				      struct fal_object_list_t
				      *ipmc_member_list,
				      struct cds_lfht *iftable)
{
	unsigned char i = 0;
	int ret;
	struct vif *vifp;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(iftable, &iter, vifp, node) {
		if (IF_ISSET(vifp->v_vif_index, mfcc_ifset)) {
			if (i >= count) {
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL Too many IPMC members %d(%d).\n",
					 i, count);
				break;
			}
			m_attr[1].id =
				FAL_IPMC_GROUP_MEMBER_ATTR_IPMC_OUTPUT_ID;
			m_attr[1].value.objid = vifp->v_ifp ?
				vifp->v_ifp->fal_l3 : 0;

			if (!m_attr[1].value.objid)
				/* skip: sending NULL breaks our API contract */
				continue;

			ret = fal_create_ip_mcast_group_member
				(2, m_attr, &ipmc_member_list->list[i]);
			if (ret) {
				if (ret != -EOPNOTSUPP)
					DP_DEBUG(MULTICAST, ERR, MCAST,
						 "FAL failed to create IPMC member.\n");
				ipmc_member_list->count = i;
				goto cleanup;
			}
			i++;
		}
	}
	ipmc_member_list->count = i;

	return 0;
 cleanup:
	fal_cleanup_ipmc_olist(ipmc_member_list);
	return ret;
}

static int fal_ip6_iterate_ipmc_olist(unsigned char count,
				      struct if_set *mfc_ifset,
				      struct fal_attribute_t *m_attr,
				      struct fal_object_list_t
				      *ipmc_member_list,
				      struct cds_lfht *iftable)
{
	uint i = 0;
	int ret;
	struct mif6 *mifp;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry(iftable, &iter, mifp, node) {
		if (IF_ISSET(mifp->m6_mif_index, mfc_ifset)) {
			if (i >= count) {
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL Too many IPMC members %d(%d).\n",
					 i, count);
				break;
			}
			m_attr[1].id =
				FAL_IPMC_GROUP_MEMBER_ATTR_IPMC_OUTPUT_ID;
			m_attr[1].value.objid = mifp->m6_ifp ?
				mifp->m6_ifp->fal_l3 : 0;

			if (!m_attr[1].value.objid)
				/* Skip: sending NULL breaks our API contract */
				continue;

			ret = fal_create_ip_mcast_group_member
				(2, m_attr, &ipmc_member_list->list[i]);
			if (ret) {
				if (ret != -EOPNOTSUPP)
					DP_DEBUG(MULTICAST, ERR, MCAST,
						 "FAL failed to create IPMC member.\n");
				ipmc_member_list->count = i;
				goto cleanup;
			}
			i++;
		}
	}
	ipmc_member_list->count = i;
	return 0;
 cleanup:
	fal_cleanup_ipmc_olist(ipmc_member_list);
	return ret;
}

static void fal_cleanup_ipmc_group(fal_object_t *ipmc_group_id,
				   struct fal_object_list_t **ipmc_member_list)
{
	int ret;

	if (*ipmc_member_list) {
		if ((*ipmc_member_list)->count)
			fal_cleanup_ipmc_olist(*ipmc_member_list);
		free(*ipmc_member_list);
		*ipmc_member_list = 0;
	}
	if (*ipmc_group_id) {
		ret = fal_delete_ip_mcast_group(*ipmc_group_id);
		if (ret != 0)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to delete ipmc group %d\n", ret);

		*ipmc_group_id = 0;
	}
}

static int fal_create_ipmc_group(unsigned char count,
				 struct if_set *mfc_ifset,
				 fal_object_t *ipmc_group_id,
				 struct fal_object_list_t **ipmc_member_list,
				 struct cds_lfht *iftable, unsigned char af)
{
	int ret;
	struct fal_attribute_t m_attr[2] = { { 0 } };
	struct fal_attribute_t g_attr[1] = { { 0 } };

	ret = fal_create_ip_mcast_group(0, g_attr, ipmc_group_id);
	if (ret)
		return ret;

	*ipmc_member_list = calloc(1, sizeof(struct fal_object_list_t) +
				 (count * sizeof(fal_object_t)));
	if (!*ipmc_member_list) {
		DP_DEBUG(MULTICAST, ERR, MCAST,
			 "FAL failed to create IPMC member.\n");
		ret = -ENOMEM;
		goto cleanup;
	}

	m_attr[0].id = FAL_IPMC_GROUP_MEMBER_ATTR_IPMC_GROUP_ID;
	m_attr[0].value.objid = *ipmc_group_id;
	if (af == AF_INET) {
		ret = fal_ip4_iterate_ipmc_olist(count,  mfc_ifset, m_attr,
						 *ipmc_member_list, iftable);
		if (ret)
			goto cleanup;
	} else if (af == AF_INET6) {
		ret = fal_ip6_iterate_ipmc_olist(count,  mfc_ifset, m_attr,
						 *ipmc_member_list, iftable);
		if (ret)
			goto cleanup;
	} else {
		ret = -EINVAL;
		goto cleanup;
	}

	return ret;
 cleanup:
	fal_cleanup_ipmc_group(ipmc_group_id, ipmc_member_list);
	return ret;
}

int fal_ip4_new_mroute(vrfid_t vrf_id, struct vmfcctl *mfc, struct mfc *rt,
		       struct cds_lfht *iftable)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_attribute_t ipmc_group_attr[3] =  { { 0 } };
	int ret;
	uint32_t ifindex;

	if (rt->mfc_fal_obj)
		return 0;

	if (!mfc->mfcc_parent || !mfc->if_count)
		/*
		 * No point in creating FAL objects until the mroute
		 * is complete and HW forwarding is possible.  This
		 * avoids creation/deletion churn.
		 */
		return 0;

	ifindex = mfc->mfcc_parent;
	/* create rpf group */
	ret = fal_create_ipmc_rpf_group(&ifindex,
					1,
					&rt->mfc_fal_rpf,
					&rt->mfc_fal_rpf_lst);
	if (ret != 0) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to create RPF group.\n");
		return ret;
	}

	ret = fal_create_ipmc_group(mfc->if_count, &mfc->mfcc_ifset,
				    &rt->mfc_fal_ol, &rt->mfc_fal_ol_lst,
				    iftable, AF_INET);
	if (ret != 0) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to create IPMC group.\n");
		goto cleanup;
	}

	/* create group id attrs */
	ipmc_group_attr[0].id = FAL_IPMC_ENTRY_ATTR_PACKET_ACTION;
	ipmc_group_attr[0].value.u32 = FAL_PACKET_ACTION_FORWARD;
	ipmc_group_attr[1].id = FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID;
	ipmc_group_attr[1].value.objid = rt->mfc_fal_rpf;
	ipmc_group_attr[2].id = FAL_IPMC_ENTRY_ATTR_OUTPUT_GROUP_ID;
	ipmc_group_attr[2].value.objid = rt->mfc_fal_ol;

	/* create entry */
	struct fal_ip_address_t source = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.addr4 = mfc->mfcc_origin
	};
	struct fal_ip_address_t group = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV4,
		.addr.addr4 = mfc->mfcc_mcastgrp
	};

	struct fal_ipmc_entry_t mentry = {
		.type = FAL_IPMC_ENTRY_TYPE_SG,
		.vrf_id = __vrf_id,
		.destination = group,
		.source = source
	};

	ret = fal_create_ip_mcast_entry(&mentry, 3, ipmc_group_attr,
					&rt->mfc_fal_obj);
	if ((ret != 0)) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to create entry.\n");
		goto cleanup;
	}

	return ret;
 cleanup:
	fal_delete_ip_mcast_entry(rt->mfc_fal_obj);
	fal_cleanup_ipmc_rpf_group(&rt->mfc_fal_rpf, &rt->mfc_fal_rpf_lst);
	fal_cleanup_ipmc_group(&rt->mfc_fal_ol, &rt->mfc_fal_ol_lst);
	rt->mfc_fal_obj = 0;
	return ret;
}

int fal_ip4_del_mroute(struct mfc *rt)
{
	int ret;

	if (!rt->mfc_fal_obj)
		return 0;

	ret = fal_delete_ip_mcast_entry(rt->mfc_fal_obj);
	fal_cleanup_ipmc_rpf_group(&rt->mfc_fal_rpf, &rt->mfc_fal_rpf_lst);
	fal_cleanup_ipmc_group(&rt->mfc_fal_ol, &rt->mfc_fal_ol_lst);
	rt->mfc_fal_obj = 0;

	return ret;
}

int fal_ip4_upd_mroute(fal_object_t obj, struct mfc *rt, struct vmfcctl *mfc,
			struct cds_lfht *iftable)
{
	fal_object_t ipmc_group_id = 0, rpf_group_id = 0, group = 0;
	struct fal_object_list_t *ipmc_member_list = NULL, *members = NULL;
	struct fal_object_list_t *rpf_member_list = NULL, *member = NULL;
	struct fal_attribute_t group_attr = {0};
	int ret = 0;
	uint32_t ifindex;

	if (!rt->mfc_fal_obj)
		return 0;

	/* check what changed */
	if (memcmp(&rt->mfc_ifset, &mfc->mfcc_ifset,
		   sizeof(mfc->mfcc_ifset))) {
		/* Output list change - do this first before RPF change */
		ret = fal_create_ipmc_group(mfc->if_count,
					    &mfc->mfcc_ifset,
					    &ipmc_group_id,
					    &ipmc_member_list,
					    iftable, AF_INET);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to create IPMC group.\n");
			return ret;
		}

		ifindex = mfc->mfcc_parent;
		/* An IPMC group change requires an RPF change */
		ret = fal_create_ipmc_rpf_group(&ifindex,
						1,
						&rpf_group_id,
						&rpf_member_list);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to create RPF group.\n");
			goto cleanup;
		}

		group_attr.id = FAL_IPMC_ENTRY_ATTR_OUTPUT_GROUP_ID;
		group_attr.value.objid = ipmc_group_id;
		ret = fal_set_ip_mcast_entry_attr(obj,
						  &group_attr);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to update entry IPMC group.\n");
			goto cleanup;
		}
		group_attr.id = FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID;
		group_attr.value.objid = rpf_group_id;
		ret = fal_set_ip_mcast_entry_attr(obj,
						  &group_attr);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to update entry RPF group.\n");
			goto cleanup;
		}
		/* The old IPMC objects can now be cleaned up */
		members = rt->mfc_fal_ol_lst;
		group = rt->mfc_fal_ol;
		rt->mfc_fal_ol_lst = ipmc_member_list;
		rt->mfc_fal_ol = ipmc_group_id;

		/* cleanup old ipmc group */
		fal_cleanup_ipmc_group(&group, &members);

		/* The old RPF objects can now be cleaned up */
		member = rt->mfc_fal_rpf_lst;
		group = rt->mfc_fal_rpf;
		rt->mfc_fal_rpf_lst = rpf_member_list;
		rt->mfc_fal_rpf = rpf_group_id;

		/* delete old RPF */
		fal_cleanup_ipmc_rpf_group(&group, &member);
	} else if (rt->mfc_parent != mfc->mfcc_parent) {
		/* RPF change */
		ifindex = mfc->mfcc_parent;
		ret = fal_create_ipmc_rpf_group(&ifindex,
						1,
						&rpf_group_id,
						&rpf_member_list);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to create RPF group.\n");
			goto cleanup;
		}

		group_attr.id = FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID;
		group_attr.value.objid = rpf_group_id;
		ret = fal_set_ip_mcast_entry_attr(obj, &group_attr);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to update entry RPF group.\n");
			goto cleanup;
		}

		member = rt->mfc_fal_rpf_lst;
		group = rt->mfc_fal_rpf;
		rt->mfc_fal_rpf_lst = rpf_member_list;
		rt->mfc_fal_rpf = rpf_group_id;

		/* delete old RPF */
		fal_cleanup_ipmc_rpf_group(&group, &member);
	}

	return ret;
 cleanup:
	fal_cleanup_ipmc_rpf_group(&rpf_group_id, &rpf_member_list);
	fal_cleanup_ipmc_group(&ipmc_group_id, &ipmc_member_list);
	return ret;
}

int fal_ip6_new_mroute(vrfid_t vrf_id, struct vmf6cctl *mfc, struct mf6c *rt,
		       struct cds_lfht *iftable)
{
	uint32_t __vrf_id = vrf_id;
	struct fal_attribute_t ipmc_group_attr[3] = { { 0 } };
	int ret;
	uint32_t ifindex;

	if (rt->mf6c_fal_obj)
		return 0;

	if (!mfc->mf6cc_parent || !mfc->if_count)
		/*
		 * No point in creating FAL objects until the mroute
		 * is complete and HW forwarding is possible.  This
		 * avoids creation/deletion churn.
		 */
		return 0;

	/* create rpf group */
	ifindex = mfc->mf6cc_parent;
	ret = fal_create_ipmc_rpf_group(&ifindex,
					1,
					&rt->mf6c_fal_rpf,
					&rt->mf6c_fal_rpf_lst);
	if (ret != 0) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to create RPF group.\n");
		return ret;
	}

	ret = fal_create_ipmc_group(mfc->if_count,
				    &mfc->mf6cc_ifset,
				    &rt->mf6c_fal_ol,
				    &rt->mf6c_fal_ol_lst,
				    iftable, AF_INET6);
	if (ret != 0) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to create IPMC group.\n");
		goto cleanup;
	}

	/* create group id attrs */
	ipmc_group_attr[0].id = FAL_IPMC_ENTRY_ATTR_PACKET_ACTION;
	ipmc_group_attr[0].value.u32 = FAL_PACKET_ACTION_FORWARD;
	ipmc_group_attr[1].id = FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID;
	ipmc_group_attr[1].value.objid = rt->mf6c_fal_rpf;
	ipmc_group_attr[2].id = FAL_IPMC_ENTRY_ATTR_OUTPUT_GROUP_ID;
	ipmc_group_attr[2].value.objid = rt->mf6c_fal_ol;

	/* create entry */
	struct fal_ip_address_t source = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = mfc->mf6cc_origin.sin6_addr
	};
	struct fal_ip_address_t group = {
		.addr_family = FAL_IP_ADDR_FAMILY_IPV6,
		.addr.addr6 = mfc->mf6cc_mcastgrp.sin6_addr
	};

	struct fal_ipmc_entry_t mentry = {
		.type = FAL_IPMC_ENTRY_TYPE_SG,
		.vrf_id = __vrf_id,
		.destination = group,
		.source = source
	};

	ret = fal_create_ip_mcast_entry(&mentry, 3, ipmc_group_attr,
					&rt->mf6c_fal_obj);
	if (ret != 0) {
		if (ret != -EOPNOTSUPP)
			DP_DEBUG(MULTICAST, ERR, MCAST,
				 "FAL failed to create entry.\n");
		goto cleanup;
	}

	return ret;
 cleanup:
	fal_delete_ip_mcast_entry(rt->mf6c_fal_obj);
	fal_cleanup_ipmc_rpf_group(&rt->mf6c_fal_rpf, &rt->mf6c_fal_rpf_lst);
	fal_cleanup_ipmc_group(&rt->mf6c_fal_ol, &rt->mf6c_fal_ol_lst);
	rt->mf6c_fal_obj = 0;
	return ret;
}


int fal_ip6_del_mroute(struct mf6c *rt)
{
	int ret;
	if (!rt->mf6c_fal_obj)
		return 0;

	ret = fal_delete_ip_mcast_entry(rt->mf6c_fal_obj);
	fal_cleanup_ipmc_rpf_group(&rt->mf6c_fal_rpf, &rt->mf6c_fal_rpf_lst);
	fal_cleanup_ipmc_group(&rt->mf6c_fal_ol, &rt->mf6c_fal_ol_lst);
	rt->mf6c_fal_obj = 0;

	return ret;
}

int fal_ip6_upd_mroute(fal_object_t obj, struct mf6c *rt, struct vmf6cctl *mfc,
		       struct cds_lfht *iftable)
{
	fal_object_t ipmc_group_id = 0, rpf_group_id = 0, group;
	struct fal_object_list_t *ipmc_member_list = NULL, *members;
	struct fal_object_list_t *rpf_member_list = NULL, *member;
	struct fal_attribute_t group_attr = {0};
	int ret = 0;
	uint32_t ifindex;

	if (!rt->mf6c_fal_obj)
		return 0;

	/* check what changed */
	if (memcmp(&rt->mf6c_ifset, &mfc->mf6cc_ifset,
		   sizeof(mfc->mf6cc_ifset))) {
		/* Output list change - do this first before RPF change */
		ret = fal_create_ipmc_group(mfc->if_count,
					    &mfc->mf6cc_ifset,
					    &ipmc_group_id,
					    &ipmc_member_list,
					    iftable, AF_INET6);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to create IPMC group.\n");
			return ret;
		}

		/* An IPMC group change requires an RPF change */
		ifindex = mfc->mf6cc_parent;
		ret = fal_create_ipmc_rpf_group(&ifindex,
						1,
						&rpf_group_id,
						&rpf_member_list);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to create RPF group.\n");
			goto cleanup;
		}

		group_attr.id = FAL_IPMC_ENTRY_ATTR_OUTPUT_GROUP_ID;
		group_attr.value.objid = ipmc_group_id;
		ret = fal_set_ip_mcast_entry_attr(obj, &group_attr);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to update entry IPMC group.\n");
			goto cleanup;
		}
		group_attr.id = FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID;
		group_attr.value.objid = rpf_group_id;
		ret = fal_set_ip_mcast_entry_attr(obj, &group_attr);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to update entry RPF group.\n");
			goto cleanup;
		}
		/* The old IPMC objects can now be cleaned up */
		members = rt->mf6c_fal_ol_lst;
		group = rt->mf6c_fal_ol;
		rt->mf6c_fal_ol_lst = ipmc_member_list;
		rt->mf6c_fal_ol = ipmc_group_id;

		/* cleanup old ipmc group */
		fal_cleanup_ipmc_group(&group, &members);

		/* The old RPF objects can now be cleaned up */
		member = rt->mf6c_fal_rpf_lst;
		group = rt->mf6c_fal_rpf;
		rt->mf6c_fal_rpf_lst = rpf_member_list;
		rt->mf6c_fal_rpf = rpf_group_id;

		/* delete old RPF */
		fal_cleanup_ipmc_rpf_group(&group, &member);
	} else if (rt->mf6c_parent != mfc->mf6cc_parent) {
		/* RPF change */
		ifindex = mfc->mf6cc_parent;
		ret = fal_create_ipmc_rpf_group(&ifindex,
						1,
						&rpf_group_id,
						&rpf_member_list);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to create RPF group.\n");
			goto cleanup;
		}

		group_attr.id = FAL_IPMC_ENTRY_ATTR_RPF_GROUP_ID;
		group_attr.value.objid = rpf_group_id;
		ret = fal_set_ip_mcast_entry_attr(obj, &group_attr);
		if (ret != 0) {
			if (ret != -EOPNOTSUPP)
				DP_DEBUG(MULTICAST, ERR, MCAST,
					 "FAL failed to update entry RPF group.\n");
			goto cleanup;

		}

		member = rt->mf6c_fal_rpf_lst;
		group = rt->mf6c_fal_rpf;
		rt->mf6c_fal_rpf_lst = rpf_member_list;
		rt->mf6c_fal_rpf = rpf_group_id;

		/* delete old RPF */
		fal_cleanup_ipmc_rpf_group(&group, &member);
	}
	return ret;
cleanup:
	fal_cleanup_ipmc_rpf_group(&rpf_group_id, &rpf_member_list);
	fal_cleanup_ipmc_group(&ipmc_group_id, &ipmc_member_list);
	return ret;
}

int fal_ip_mcast_get_stats(fal_object_t obj, uint32_t num_counters,
			   const enum fal_ip_mcast_entry_stat_type *cntr_ids,
			   uint64_t *cntrs)
{
	int ret;

	memset(cntrs, 0, num_counters*sizeof(cntrs[0]));
	if (obj == 0)
		return 0;

	ret = call_handler_def_ret(ipmc, -EOPNOTSUPP, get_entry_stats,
				   obj, num_counters, cntr_ids, cntrs);
	if (ret == 0)
		ret = call_handler_def_ret(ipmc, -EOPNOTSUPP,
					   clear_entry_stats,
					   obj, num_counters, cntr_ids);
	return ret;
}

int fal_policer_clear_stats(fal_object_t obj,
			    uint32_t num_counters,
			    const enum fal_policer_stat_type *cntr_ids)
{
	return call_handler_ret(policer, clear_stats, obj, num_counters,
				cntr_ids);
}

/* The following policer APIs follow SAI approach */
int fal_policer_create(uint32_t attr_count,
		       const struct fal_attribute_t *attr_list,
		       fal_object_t *obj)
{
	return call_handler_def_ret(policer, -EOPNOTSUPP, create,
				    attr_count, attr_list, obj);
}

int fal_policer_delete(fal_object_t obj)
{
	return call_handler_def_ret(policer, -EOPNOTSUPP, delete,
				    obj);
}

int fal_policer_set_attr(fal_object_t obj,
			 const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(policer, -EOPNOTSUPP, set_attr,
				    obj, attr);
}

int fal_policer_get_attr(fal_object_t obj, uint32_t attr_count,
			 struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(policer, -EOPNOTSUPP, get_attr,
				    obj, attr_count, attr_list);
}

int fal_policer_get_stats_ext(fal_object_t obj,
			      uint32_t num_counters,
			      const enum fal_policer_stat_type *cntr_ids,
			      enum fal_stats_mode mode,
			      uint64_t *stats)
{
	return call_handler_def_ret(policer, -EOPNOTSUPP, get_stats_ext,
				    obj, num_counters, cntr_ids, mode, stats);
}

void fal_policer_dump(fal_object_t obj, json_writer_t *wr)
{
	call_handler(policer, dump, obj, wr);
}

static const char *traffic_strs[FAL_TRAFFIC_MAX] = {
	[FAL_TRAFFIC_UCAST] = "unicast",
	[FAL_TRAFFIC_MCAST] = "multicast",
	[FAL_TRAFFIC_BCAST] = "broadcast"
};

const char *fal_traffic_type_to_str(enum fal_traffic_type tr_type)
{
	if (tr_type < FAL_TRAFFIC_UCAST || tr_type >= FAL_TRAFFIC_MAX)
		return "";

	return traffic_strs[tr_type];
}

enum fal_traffic_type fal_traffic_str_to_type(const char *str)
{
	enum fal_traffic_type tr_type;

	for (tr_type = FAL_TRAFFIC_UCAST; tr_type < FAL_TRAFFIC_MAX;
	     tr_type++) {
		if (!strcmp(str, traffic_strs[tr_type]))
			return tr_type;
	}
	return FAL_TRAFFIC_MAX;
}

/* The FAL equivalent of inet_pton(). Try to convert the string
 * as IPv4 and if that fails then IPv6.
 *
 * Returns 1 on success and 0 on failure.
 */
int str_to_fal_ip_address_t(char *str, struct fal_ip_address_t *ipaddr)
{
	ipaddr->addr_family = FAL_IP_ADDR_FAMILY_IPV4;
	if (inet_pton(AF_INET, str, &ipaddr->addr.ip4) == 1)
		return 1;

	ipaddr->addr_family = FAL_IP_ADDR_FAMILY_IPV6;
	if (inet_pton(AF_INET6, str, &ipaddr->addr.ip6) == 1)
		return 1;

	return 0;
}

/* The FAL equivalent of inet_ntop(). Try to convert the string
 * as IPv4 and if that fails then IPv6.
 *
 * Returns 1 on success and 0 on failure.
 */
const char *fal_ip_address_t_to_str(const struct fal_ip_address_t *ipaddr,
				    char *dst, socklen_t size)
{
	if (ipaddr->addr_family == FAL_IP_ADDR_FAMILY_IPV4)
		return inet_ntop(AF_INET, &ipaddr->addr.ip4, dst, size);

	if (ipaddr->addr_family == FAL_IP_ADDR_FAMILY_IPV6)
		return inet_ntop(AF_INET6, &ipaddr->addr.ip6, dst, size);

	return NULL;
}

bool fal_is_ipaddr_empty(const struct fal_ip_address_t *ipaddr)
{
	struct fal_ip_address_t empty_ipaddr = { 0 };

	return memcmp(ipaddr, &empty_ipaddr, sizeof(empty_ipaddr)) == 0;
}

enum fal_ip_addr_family_t addr_family_to_fal_ip_addr_family(int family)
{
	switch (family) {
	case AF_INET:
		return FAL_IP_ADDR_FAMILY_IPV4;
	case AF_INET6:
		return FAL_IP_ADDR_FAMILY_IPV6;
	default:
		RTE_LOG(ERR, DATAPLANE, "Invalid address family %d\n",
			family);
		return -1;
	}
}

/* QoS functions */
int fal_qos_new_queue(fal_object_t switch_id, uint32_t attr_count,
		      const struct fal_attribute_t *attr_list,
		      fal_object_t *new_queue_id)
{
	return call_handler_ret(qos, new_queue, switch_id, attr_count,
				attr_list, new_queue_id);
}

int fal_qos_del_queue(fal_object_t queue_id)
{
	return call_handler_ret(qos, del_queue, queue_id);
}

int fal_qos_upd_queue(fal_object_t queue_id, const struct fal_attribute_t *attr)
{
	return call_handler_ret(qos, upd_queue, queue_id, attr);
}

int fal_qos_get_queue_attrs(fal_object_t queue_id, uint32_t attr_count,
			    struct fal_attribute_t *attr_list)
{
	return call_handler_ret(qos, get_queue_attrs, queue_id, attr_count,
				attr_list);
}

int fal_qos_get_queue_stats(fal_object_t queue_id, uint32_t number_of_counters,
			    const uint32_t *counter_ids,
			    uint64_t *counters)
{
	return call_handler_ret(qos, get_queue_stats, queue_id,
				number_of_counters, counter_ids, counters);
}

int fal_qos_get_queue_stats_ext(fal_object_t queue_id,
				uint32_t number_of_counters,
				const uint32_t *counter_ids,
				bool read_and_clear,
				uint64_t *counters)
{
	return call_handler_def_ret(qos, -EOPNOTSUPP, get_queue_stats_ext,
				    queue_id, number_of_counters, counter_ids,
				    read_and_clear, counters);
}

int fal_qos_clear_queue_stats(fal_object_t queue_id,
			      uint32_t number_of_counters,
			      const uint32_t *counter_ids)
{
	return call_handler_ret(qos, clear_queue_stats, queue_id,
				number_of_counters, counter_ids);
}

int fal_qos_new_map(fal_object_t switch_id, uint32_t attr_count,
		    const struct fal_attribute_t *attr_list,
		    fal_object_t *new_map_id)
{
	return call_handler_ret(qos, new_map, switch_id, attr_count, attr_list,
				new_map_id);
}

int fal_qos_del_map(fal_object_t map_id)
{
	return call_handler_ret(qos, del_map, map_id);
}

int fal_qos_upd_map(fal_object_t map_id, const struct fal_attribute_t *attr)
{
	return call_handler_ret(qos, upd_map, map_id, attr);
}

int fal_qos_get_map_attrs(fal_object_t map_id, uint32_t attr_count,
			  struct fal_attribute_t *attr_list)
{
	return call_handler_ret(qos, get_map_attrs, map_id, attr_count,
				attr_list);
}

int fal_qos_new_scheduler(fal_object_t switch_id, uint32_t attr_count,
			  const struct fal_attribute_t *attr_list,
			  fal_object_t *new_sched_id)
{
	return call_handler_ret(qos, new_scheduler, switch_id, attr_count,
				attr_list, new_sched_id);
}

int fal_qos_del_scheduler(fal_object_t sched_id)
{
	return call_handler_ret(qos, del_scheduler, sched_id);
}

int fal_qos_upd_scheduler(fal_object_t sched_id,
			  const struct fal_attribute_t *attr)
{
	return call_handler_ret(qos, upd_scheduler, sched_id, attr);
}

int fal_qos_get_scheduler_attrs(fal_object_t sched_id, uint32_t attr_count,
				struct fal_attribute_t *attr_list)
{
	return call_handler_ret(qos, get_scheduler_attrs, sched_id, attr_count,
				attr_list);
}

int fal_qos_new_sched_group(fal_object_t switch_id, uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *sched_group_id)
{
	return call_handler_ret(qos, new_sched_group, switch_id, attr_count,
				attr_list, sched_group_id);
}

int fal_qos_del_sched_group(fal_object_t sched_group_id)
{
	return call_handler_ret(qos, del_sched_group, sched_group_id);
}

int fal_qos_upd_sched_group(fal_object_t sched_group_id,
			    const struct fal_attribute_t *attr)
{
	return call_handler_ret(qos, upd_sched_group, sched_group_id, attr);
}

int fal_qos_get_sched_group_attrs(fal_object_t sched_group_id,
				  uint32_t attr_count,
				  struct fal_attribute_t *attr_list)
{
	return call_handler_ret(qos, get_sched_group_attrs, sched_group_id,
				attr_count, attr_list);
}

int fal_qos_new_wred(fal_object_t switch_id, uint32_t attr_count,
		     const struct fal_attribute_t *attr_list,
		     fal_object_t *new_wred_id)
{
	return call_handler_ret(qos, new_wred, switch_id, attr_count,
				attr_list, new_wred_id);
}

int fal_qos_del_wred(fal_object_t wred_id)
{
	return call_handler_ret(qos, del_wred, wred_id);
}

int fal_qos_upd_wred(fal_object_t wred_id, const struct fal_attribute_t *attr)
{
	return call_handler_ret(qos, upd_wred, wred_id, attr);
}

int fal_qos_get_wred_attrs(fal_object_t wred_id, uint32_t attr_count,
			   struct fal_attribute_t *attr_list)
{
	return call_handler_ret(qos, get_wred_attrs, wred_id, attr_count,
				attr_list);
}

void fal_qos_dump_map(fal_object_t map, json_writer_t *wr)
{
	call_handler(qos, dump_map, map, wr);
}

void fal_qos_dump_sched_group(fal_object_t sg, json_writer_t *wr)
{
	call_handler(qos, dump_sched_group, sg, wr);
}

int fal_qos_get_counters(const uint32_t *cntr_ids,
				uint32_t num_cntrs,
				uint64_t *cntrs)
{
	return call_handler_def_ret(qos, -EOPNOTSUPP, get_counters,
				cntr_ids, num_cntrs, cntrs);
}

void fal_qos_dump_buf_errors(json_writer_t *wr)
{
	call_handler(qos, dump_buf_errors, wr);
}

int __externally_visible
fal_attach_device(const char *devargs)
{
	return attach_device(devargs);
}

int __externally_visible
fal_detach_device(const char *device)
{
	return detach_device(device);
}

int fal_mirror_session_create(uint32_t attr_count,
			     const struct fal_attribute_t *attr_list,
			     fal_object_t *obj)
{
	return call_handler_def_ret(mirror, -EOPNOTSUPP, session_create,
				    attr_count, attr_list, obj);

}

int fal_mirror_session_delete(fal_object_t obj)
{
	return call_handler_def_ret(mirror, -EOPNOTSUPP, session_delete, obj);
}

int fal_mirror_session_set_attr(fal_object_t obj,
				const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(mirror, -EOPNOTSUPP, session_set_attr, obj,
				    attr);

}

int fal_mirror_session_get_attr(fal_object_t obj, uint32_t attr_count,
				 struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(mirror, -EOPNOTSUPP, session_get_attr, obj,
				attr_count, attr_list);
}

int fal_vlan_feature_create(uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *obj)
{
	return call_handler_def_ret(vlan_feat, -EOPNOTSUPP, vlan_feature_create,
				    attr_count, attr_list, obj);
}

int fal_vlan_feature_delete(fal_object_t obj)
{
	return call_handler_def_ret(vlan_feat, -EOPNOTSUPP, vlan_feature_delete,
				    obj);
}

int fal_vlan_feature_set_attr(fal_object_t obj,
			      const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(vlan_feat, -EOPNOTSUPP,
				    vlan_feature_set_attr, obj, attr);
}

int fal_vlan_feature_get_attr(fal_object_t obj,
			      uint32_t attr_count,
			      struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(vlan_feat, -EOPNOTSUPP,
				    vlan_feature_get_attr, obj, attr_count,
				    attr_list);
}

int fal_backplane_bind(unsigned int bp_ifindex, unsigned int ifindex)
{
	return call_handler_def_ret(backplane, -EOPNOTSUPP, backplane_bind,
				    bp_ifindex, ifindex);
}

void fal_backplane_dump(unsigned int bp_ifindex, json_writer_t *wr)
{
	call_handler(backplane, backplane_dump, bp_ifindex, wr);
}

int fal_create_cpp_limiter(uint32_t attr_count,
			   const struct fal_attribute_t *attr_list,
			   fal_object_t *new_limiter_id)
{
	return call_handler_ret(cpp_rl, create, attr_count,
				attr_list, new_limiter_id);
}

int fal_remove_cpp_limiter(fal_object_t limiter_id)
{
	return call_handler_ret(cpp_rl, remove, limiter_id);
}

int fal_get_cpp_limiter_attribute(fal_object_t limiter_id, uint32_t attr_count,
				  struct fal_attribute_t *attr_list)
{
	return call_handler_ret(cpp_rl, get_attrs, limiter_id, attr_count,
				attr_list);
}

void fal_attr_set_ip_addr(struct fal_attribute_t *attr,
			  const struct ip_addr *ip)
{
	switch (ip->type) {
	case AF_INET:
		attr->value.ipaddr.addr_family = FAL_IP_ADDR_FAMILY_IPV4;
		attr->value.ipaddr.addr.addr4 = ip->address.ip_v4;
		break;

	case AF_INET6:
		if (IN6_IS_ADDR_V4MAPPED(&ip->address.ip_v6)) {
			attr->value.ipaddr.addr_family =
				FAL_IP_ADDR_FAMILY_IPV4;
			attr->value.ipaddr.addr.addr4.s_addr =
				V4MAPPED_IPV6_TO_IPV4(ip->address.ip_v6);
		} else {
			attr->value.ipaddr.addr_family =
				FAL_IP_ADDR_FAMILY_IPV6;
			attr->value.ipaddr.addr.addr6 = ip->address.ip_v6;
		}
		break;
	}
}

int fal_create_ptp_clock(uint32_t attr_count,
			    const struct fal_attribute_t *attr_list,
			    fal_object_t *clock)
{
	return call_handler_def_ret(ptp,
				    -EOPNOTSUPP,
				    create_ptp_clock,
				    attr_count,
				    attr_list,
				    clock);
}

int fal_delete_ptp_clock(fal_object_t clock)
{
	return call_handler_def_ret(ptp,
				    -EOPNOTSUPP,
				    delete_ptp_clock,
				    clock);
}

int fal_dump_ptp_clock(fal_object_t clock, json_writer_t *wr)
{
	return call_handler_def_ret(ptp,
				    -EOPNOTSUPP,
				    dump_ptp_clock,
				    clock,
				    wr);
}

int fal_create_ptp_port(uint32_t attr_count,
			const struct fal_attribute_t *attr_list,
			fal_object_t *port)
{
	return call_handler_def_ret(ptp,
				    -EOPNOTSUPP,
				    create_ptp_port,
				    attr_count,
				    attr_list,
				    port);
}

int fal_delete_ptp_port(fal_object_t port)
{
	return call_handler_def_ret(ptp,
				    -EOPNOTSUPP,
				    delete_ptp_port,
				    port);
}

int fal_create_ptp_peer(uint32_t attr_count,
			const struct fal_attribute_t *attr_list,
			fal_object_t *peer)
{
	return call_handler_def_ret(ptp,
				    -EOPNOTSUPP,
				    create_ptp_peer,
				    attr_count,
				    attr_list,
				    peer);
}

int fal_delete_ptp_peer(fal_object_t peer)
{
	return call_handler_def_ret(ptp,
				    -EOPNOTSUPP,
				    delete_ptp_peer,
				    peer);
}

/* Start of ACL functions */

int fal_acl_create_table(uint32_t attr_count,
			 const struct fal_attribute_t *attr,
			 fal_object_t *new_table_id)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			create_table, attr_count, attr, new_table_id);
}

int fal_acl_delete_table(fal_object_t table_id)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			delete_table, table_id);
}

int fal_acl_set_table_attr(fal_object_t table_id,
			   const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			set_table_attr, table_id, attr);
}

int fal_acl_get_table_attr(fal_object_t table_id,
			   uint32_t attr_count,
			   struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			get_table_attr, table_id, attr_count, attr_list);
}

int fal_acl_create_entry(uint32_t attr_count,
			 const struct fal_attribute_t *attr,
			 fal_object_t *new_entry_id)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			create_entry, attr_count, attr, new_entry_id);
}

int fal_acl_delete_entry(fal_object_t entry_id)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			delete_entry, entry_id);
}

int fal_acl_set_entry_attr(fal_object_t entry_id,
			   const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			set_entry_attr, entry_id, attr);
}

int fal_acl_get_entry_attr(fal_object_t entry_id,
			   uint32_t attr_count,
			   struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			get_entry_attr, entry_id, attr_count, attr_list);
}

int fal_acl_create_counter(uint32_t attr_count,
			   const struct fal_attribute_t *attr,
			   fal_object_t *new_counter_id)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			create_counter, attr_count, attr, new_counter_id);
}

int fal_acl_delete_counter(fal_object_t counter_id)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			delete_counter, counter_id);
}

int fal_acl_set_counter_attr(fal_object_t counter_id,
			     const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			set_counter_attr, counter_id, attr);
}

int fal_acl_get_counter_attr(fal_object_t counter_id,
			     uint32_t attr_count,
			     struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(acl, -EOPNOTSUPP,
			get_counter_attr, counter_id, attr_count, attr_list);
}

/* End of ACL functions */

int fal_capture_create(uint32_t attr_count,
		       const struct fal_attribute_t *attr_list,
		       fal_object_t *obj)
{
	return call_handler_def_ret(capture, -EOPNOTSUPP,
				    create, attr_count,
				    attr_list, obj);
}

void fal_capture_delete(fal_object_t obj)
{
	call_handler(capture, delete, obj);
}

/* Start of BFD functions */

int dp_fal_bfd_create_session(fal_object_t *bfd_session_id,
	uint32_t attr_count, const struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(bfd, -EOPNOTSUPP, create_session,
			bfd_session_id, attr_count, attr_list);
}

int dp_fal_bfd_delete_session(fal_object_t bfd_session_id)
{
	return call_handler_def_ret(bfd, -EOPNOTSUPP, delete_session,
			bfd_session_id);
}

int dp_fal_bfd_set_session_attribute(fal_object_t bfd_session_id,
	uint32_t attr_count, const struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(bfd, -EOPNOTSUPP, set_session_attr,
			bfd_session_id, attr_count, attr_list);
}

int dp_fal_bfd_get_session_attribute(fal_object_t bfd_session_id,
	uint32_t attr_count, struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(bfd, -EOPNOTSUPP, get_session_attr,
			bfd_session_id, attr_count, attr_list);
}

int dp_fal_bfd_get_session_stats(fal_object_t bfd_session_id,
	uint32_t number_of_counters,
	const enum fal_bfd_session_stat_t *counter_ids,
	uint64_t *counters)
{
	return call_handler_def_ret(bfd, -EOPNOTSUPP, get_session_stats,
			bfd_session_id, number_of_counters,
			counter_ids, counters);
}

int dp_fal_bfd_get_switch_attrs(uint32_t attr_count,
	struct fal_attribute_t *attr_list)
{
	return fal_get_switch_attrs(attr_count, attr_list);
}

int dp_fal_bfd_set_switch_attr(const struct fal_attribute_t *attr)
{
	return fal_set_switch_attr(attr);
}

/* End of BFD functions */

int fal_create_mpls_route(const struct fal_mpls_route_t *mpls_route,
			  uint32_t attr_count,
			  const struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(
		mpls, -EOPNOTSUPP, create_route, mpls_route,
		attr_count, attr_list);
}

int fal_delete_mpls_route(const struct fal_mpls_route_t *mpls_route)
{
	return call_handler_def_ret(
		mpls, -EOPNOTSUPP, delete_route, mpls_route);
}

int fal_set_mpls_route_attr(const struct fal_mpls_route_t *mpls_route,
			    const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(
		mpls, -EOPNOTSUPP, set_route_attr, mpls_route,
		attr);
}

int fal_get_mpls_route_attr(const struct fal_mpls_route_t *mpls_route,
			    uint32_t attr_count,
			    struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(
		mpls, -EOPNOTSUPP, get_route_attr, mpls_route,
		attr_count, attr_list);
}

int fal_vrf_create(uint32_t attr_count,
		   const struct fal_attribute_t *attr_list,
		   fal_object_t *obj)
{
	return call_handler_def_ret(vrf, -EOPNOTSUPP, create,
				    attr_count, attr_list, obj);
}

int fal_vrf_delete(fal_object_t obj)
{
	return call_handler_def_ret(vrf, -EOPNOTSUPP, delete, obj);
}

int fal_set_vrf_attr(fal_object_t obj,
		     const struct fal_attribute_t *attr)
{
	return call_handler_def_ret(vrf, -EOPNOTSUPP, set_attr, obj,
				    attr);
}

int fal_get_vrf_attr(fal_object_t obj,
		     uint32_t attr_count,
		     struct fal_attribute_t *attr_list)
{
	return call_handler_def_ret(vrf, -EOPNOTSUPP, get_attr, obj,
				    attr_count, attr_list);
}
