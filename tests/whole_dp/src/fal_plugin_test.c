/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include <arpa/inet.h>
#include <bridge_flags.h>
#include <bridge_vlan_set.h>
#include <fal_plugin.h>
#include <rte_log.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

#include "dp_test_macros.h"
#include "util.h"
#include  "fal_plugin_sw_port.h"

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

#define UNUSED(x) (void)(x)

#include "fal_plugin_test.h"

struct ether_addr;

static fal_object_t fal_test_plugin_next_obj = 1;

int fal_plugin_init(void)
{
	INFO("Initializing test fal plugin\n");
	return 0;
}

int fal_plugin_init_log(void)
{
	DEBUG("%s()\n", __func__);
	return 0;
}

void fal_plugin_setup_interfaces(void)
{
	uint16_t portid;
	int ret;
	struct bridge_vlan_set *set;

	DEBUG("%s()\n", __func__);

	dp_test_fal_plugin_called = true;

	ret = fal_port_byifindex((int) -1, &portid);
	dp_test_fail_unless((ret == -ENODEV),
		"Expected fal_port_byifindex() to return -ENODEV");

	set = bridge_vlan_set_create();
	dp_test_fail_unless((set != NULL),
		"Expected bridge_vlan_set_create() to not return NULL");
	bridge_vlan_set_free(set);

	fal_plugin_sw_ports_create();
}

static const
struct fal_attribute_t *get_attribute(uint32_t id,
				      uint32_t attr_count,
				      const struct fal_attribute_t *attr_list)
{
	int i;

	for (i = 0; i < (int) attr_count; i++)
		if (attr_list[i].id == id)
			return &attr_list[i];

	return NULL;
}

void fal_plugin_l2_new_port(unsigned int if_index,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	const struct fal_attribute_t *attr;

	DEBUG("%s(if_index %d, attr_count %d, ...)\n",
					__func__, if_index, attr_count);
	dp_test_fail_unless((get_attribute(FAL_PORT_ATTR_KIND,
					   attr_count,
					   attr_list) != NULL),
		"Expected FAL_PORT_ATTR_KIND");

	attr = get_attribute(FAL_PORT_ATTR_NAME, attr_count, attr_list);
	dp_test_fail_unless(attr != NULL,
			    "Expected FAL_PORT_ATTR_NAME attribute");
	if (attr != NULL) {
		DEBUG("%s(if_index %d, ...) name %s\n",
		      __func__, if_index, attr->value.if_name);
	}

	attr = get_attribute(FAL_PORT_ATTR_DPDK_PORT, attr_count, attr_list);
	if (attr) {
		DEBUG("%s(if_index %d, ...) port %d\n",
		      __func__, if_index, attr->value.u8);
	}
	attr = get_attribute(FAL_PORT_ATTR_VLAN_ID, attr_count, attr_list);
	if (attr) {
		DEBUG("%s(if_index %d, ...) VLAN_ID %d\n",
		      __func__, if_index, attr->value.u16);
	}
	attr = get_attribute(FAL_PORT_ATTR_PARENT_IFINDEX,
							attr_count, attr_list);
	if (attr) {
		DEBUG("%s(if_index %d, ...) parent if_index %d\n",
		      __func__, if_index, attr->value.u32);
	}
	attr = get_attribute(FAL_PORT_ATTR_MTU, attr_count, attr_list);
	if (attr) {
		DEBUG("%s(if_index %d, ...) MTU %d\n",
		      __func__, if_index, attr->value.u16);
	}
}

int fal_plugin_l2_get_attrs(unsigned int if_index,
			    uint32_t attr_count,
			    struct fal_attribute_t *attr_list)
{
	DEBUG("%s(if_index %d, attr_count %d, ...)\n",
					__func__, if_index, attr_count);

	return -1;
}

static const char *fal_port_attr_t_to_str(enum fal_port_attr_t val)
{
	switch (val) {
	case FAL_PORT_ATTR_KIND:
		return "kind";
	case FAL_PORT_ATTR_IFI_TYPE:
		return "ifi_type";
	case FAL_PORT_ATTR_IFI_FLAGS:
		return "ifi_flags";
	case FAL_PORT_ATTR_VRF_ID:
		return "vrf_id";
	case FAL_PORT_ATTR_DPDK_PORT:
		return "dpdk_port";
	case FAL_PORT_ATTR_VLAN_ID:
		return "vlan_id";
	case FAL_PORT_ATTR_PARENT_IFINDEX:
		return "parent_if_index";
	case FAL_PORT_ATTR_MTU:
		return "mtu";
	case FAL_PORT_ATTR_HW_SWITCH_MODE:
		return "switch_mode";
	case FAL_PORT_ATTR_MAC_ADDRESS:
		return "mac_addr";
	case FAL_PORT_ATTR_POE_ADMIN_STATUS:
		return "poe_admin_status";
	case FAL_PORT_ATTR_POE_OPER_STATUS:
		return "poe_oper_status";
	case FAL_PORT_ATTR_POE_PRIORITY:
		return "poe_priority";
	case FAL_PORT_ATTR_POE_CLASS:
		return "poe_class";
	case FAL_PORT_ATTR_NAME:
		return "name";
	case FAL_PORT_ATTR_BREAKOUT:
		return "breakout";
	case FAL_PORT_ATTR_INGRESS_MIRROR_SESSION:
		return "ingress_mirror_session";
	case FAL_PORT_ATTR_EGRESS_MIRROR_SESSION:
		return "egress_mirror_session";
	case FAL_PORT_ATTR_HW_MIRRORING:
		return "hw_mirroring";
	case FAL_PORT_ATTR_UNICAST_STORM_CONTROL_POLICER_ID:
		return "ucast-storm_ctl";
	case FAL_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID:
		return "broadcast-storm_ctl";
	case FAL_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID:
		return "mcast-storm_ctl";
	case FAL_PORT_ATTR_FDB_AGING_TIME:
		return "fdb-aging-time";
	}
	assert(0);
	return "ERROR";
}

void fal_plugin_l2_upd_port(unsigned int if_index,
			    struct fal_attribute_t *attr)
{
	DEBUG("%s(if_index %d, { id %d %s %p })\n",
	      __func__, if_index, attr->id,
	      fal_port_attr_t_to_str(attr->id),
	      attr->value.ptr);
}

void fal_plugin_l2_del_port(unsigned int if_index)
{
	DEBUG("%s(if_index %d)\n", __func__, if_index);
}

void fal_plugin_l2_new_addr(unsigned int if_index,
			    const struct ether_addr *addr,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	char __addr[19];

	ether_ntoa_r(addr, __addr);
	DEBUG("%s(if_index %d, addr %s, ...)\n", __func__, if_index, __addr);
}

void fal_plugin_l2_upd_addr(unsigned int if_index,
			    const struct ether_addr *addr,
			    struct fal_attribute_t *attr)
{
	char __addr[19];

	ether_ntoa_r(addr, __addr);
	DEBUG("%s(if_index %d, addr %s, ...)\n", __func__, if_index, __addr);
}

void fal_plugin_l2_del_addr(unsigned int if_index,
			    const struct ether_addr *addr)
{
	char __addr[19];

	ether_ntoa_r(addr, __addr);
	DEBUG("%s(if_index %d, addr %p)\n", __func__, if_index, __addr);
}

void fal_plugin_br_new_port(unsigned int bridge_ifindex,
			    unsigned int child_ifindex,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	DEBUG("%s(bridge_ifindex %d, child_ifindex %d, attr_count %d...)\n",
	      __func__, bridge_ifindex, child_ifindex, attr_count);
}

void fal_plugin_br_upd_port(unsigned int if_index,
			    struct fal_attribute_t *attr)
{
	DEBUG("%s(if_index %d, attr { id %d, ... })\n",
				__func__, if_index, attr->id);
}

void fal_plugin_br_del_port(unsigned int bridge_ifindex,
			    unsigned int child_ifindex)
{
	DEBUG("%s(bridge_ifindex %d, child_ifindex %d)\n",
	      __func__, bridge_ifindex, child_ifindex);
}

void fal_plugin_br_new_neigh(unsigned int if_index,
			     uint16_t vlanid,
			     const struct ether_addr *addr,
			     uint32_t attr_count,
			     const struct fal_attribute_t *attr_list)
{
	char __addr[19];

	ether_ntoa_r(addr, __addr);
	DEBUG("%s(if_index %u, vlanid %hu, addr %s, ...)\n", __func__, if_index,
	      vlanid, __addr);

	dp_test_fail_unless((get_attribute(FAL_BRIDGE_NEIGH_ATTR_STATE,
					   attr_count,
					   attr_list) != NULL),
		"Expected FAL_BRIDGE_NEIGH_ATTR_STATE");
}

void fal_plugin_br_upd_neigh(unsigned int if_index,
			     uint16_t vlanid,
			     const struct ether_addr *addr,
			     struct fal_attribute_t *attr)
{
	char __addr[19];

	ether_ntoa_r(addr, __addr);
	DEBUG("%s(if_index %u, vlanid %hu, addr %s, ...)\n", __func__, if_index,
	      vlanid, __addr);
}

void fal_plugin_br_del_neigh(unsigned int if_index,
			     uint16_t vlanid,
			     const struct ether_addr *addr)
{
	char __addr[19];

	ether_ntoa_r(addr, __addr);
	DEBUG("%s(if_index %u, vlanid %hu, addr %p)\n", __func__, if_index,
	      vlanid, __addr);
}

void fal_plugin_br_flush_neigh(unsigned int bridge_ifindex,
			       uint32_t attr_count,
			       const struct fal_attribute_t *attr_list)
{
	const struct fal_attribute_t *attr;
	uint32_t i;
	bool mac = false;
	int vlanid = -1;
	int port = -1;
	int type = -1;

	DEBUG("%s(bridge_ifindex %u, attr_count %u, ...)\n",
	      __func__, bridge_ifindex, attr_count);

	for (i = 0; i < attr_count; i++) {
		attr = &attr_list[i];

		switch (attr->id) {
		case FAL_BRIDGE_FDB_FLUSH_MAC:
			mac = true;
			DEBUG("%s flush MAC\n", __func__);
			break;
		case FAL_BRIDGE_FDB_FLUSH_VLAN:
			vlanid = attr->value.u16;
			DEBUG("%s flush VLAN %u\n", __func__, vlanid);
			break;
		case FAL_BRIDGE_FDB_FLUSH_PORT:
			port = attr->value.u32;
			DEBUG("%s flush PORT %u\n", __func__, port);
			break;
		case FAL_BRIDGE_FDB_FLUSH_TYPE:
			type = attr->value.u8;
			DEBUG("%s flush TYPE %u\n", __func__, type);
			break;
		default:
			dp_test_assert_internal(false);
			break;
		}
	}

	if (mac)
		dp_test_fail_unless(vlanid == -1 &&
				    type == -1,
				    "invalid FLUSH MAC attribute combination");
	if (vlanid != -1)
		dp_test_fail_unless(!mac &&
				    type == -1,
				    "invalid FLUSH VLAN attribute combination");
}

static void fal_ntop(const struct fal_ip_address_t *ipaddr,
		     char *buf, socklen_t size)
{
	if (ipaddr->addr_family == FAL_IP_ADDR_FAMILY_IPV4)
		inet_ntop(AF_INET, &(ipaddr->addr.addr4), buf, size);
	else if (ipaddr->addr_family == FAL_IP_ADDR_FAMILY_IPV6)
		inet_ntop(AF_INET6, &(ipaddr->addr.addr6), buf, size);
}

int fal_plugin_ip_new_neigh(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	char __ipaddr[64];

	fal_ntop(ipaddr, __ipaddr, sizeof(__ipaddr));
	DEBUG("%s(if_index %d, ipaddr %s, ...)\n",
					__func__, if_index, __ipaddr);

	return 0;
}

int fal_plugin_ip_upd_neigh(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    struct fal_attribute_t *attr)
{
	char __ipaddr[64];

	fal_ntop(ipaddr, __ipaddr, sizeof(__ipaddr));
	if (attr->id == FAL_NEIGH_ENTRY_ATTR_DST_MAC_ADDRESS) {
		char eaddr[19];

		ether_ntoa_r(&attr->value.mac, eaddr);
		DEBUG("%s(if_index %d, ipaddr %s, { id %d, mac %s })\n",
				__func__, if_index, __ipaddr, attr->id, eaddr);
	} else
		DEBUG("%s(if_index %d, ipaddr %s, { id %d, ... })\n",
				__func__, if_index, __ipaddr, attr->id);

	return 0;
}

int fal_plugin_ip_del_neigh(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr)
{
	char __ipaddr[64];

	fal_ntop(ipaddr, __ipaddr, sizeof(__ipaddr));
	DEBUG("%s(if_index %d, ipaddr %s)\n", __func__, if_index, __ipaddr);

	return 0;
}

void fal_plugin_ip_new_addr(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	char __ipaddr[64];

	fal_ntop(ipaddr, __ipaddr, sizeof(__ipaddr));
	DEBUG("%s(if_index %d, ipaddr %s/%d, ...)\n",
				__func__, if_index, __ipaddr, prefixlen);
}

void fal_plugin_ip_upd_addr(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    struct fal_attribute_t *attr)
{
	char __ipaddr[64];

	fal_ntop(ipaddr, __ipaddr, sizeof(__ipaddr));

	DEBUG("%s(if_index %d, ipaddr %s/%d, { id %d, ... })\n",
			__func__, if_index, __ipaddr, prefixlen, attr->id);
}

void fal_plugin_ip_del_addr(unsigned int if_index,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen)
{
	char __ipaddr[64];

	fal_ntop(ipaddr, __ipaddr, sizeof(__ipaddr));
	DEBUG("%s(if_index %d, ipaddr %s/%d)\n",
				__func__, if_index, __ipaddr, prefixlen);
}

int fal_plugin_ip_new_next_hop_group(uint32_t attr_count,
				     const struct fal_attribute_t *attr_list,
				     fal_object_t *obj)
{
	*obj = fal_test_plugin_next_obj++;
	DEBUG("%s() <-- 0x%lx\n", __func__, *obj);
	return 0;
}

int fal_plugin_ip_upd_next_hop_group(fal_object_t obj,
				     const struct fal_attribute_t *attr)
{
	DEBUG("%s(0x%lx, { id %d, ... })\n", __func__, obj, attr->id);
	return 0;
}

int fal_plugin_ip_del_next_hop_group(fal_object_t obj)
{
	DEBUG("%s(0x%lx)\n", __func__, obj);
	return 0;
}

int fal_plugin_ip_new_next_hops(uint32_t nh_count,
				const uint32_t *attr_count,
				const struct fal_attribute_t **attr_list,
				fal_object_t *obj)
{
	unsigned int nh_idx;
	unsigned int i;

	DEBUG("%s() nhops %d\n", __func__, nh_count);
	for (nh_idx = 0; nh_idx < nh_count; nh_idx++) {
		const struct fal_attribute_t *nh_attr_list = attr_list[nh_idx];
		char __gateway[64];

		for (i = 0; i < attr_count[nh_idx]; i++) {
			switch (nh_attr_list[i].id) {
			case FAL_NEXT_HOP_ATTR_NEXT_HOP_GROUP:
				DEBUG("%s() %d: group 0x%lx\n", __func__,
				      nh_idx,
				      nh_attr_list[i].value.u64);
				break;
			case FAL_NEXT_HOP_ATTR_INTF:
				DEBUG("%s() %d: intf %d\n", __func__,
				      nh_idx,
				      nh_attr_list[i].value.u32);
				break;
			case FAL_NEXT_HOP_ATTR_IP:
				fal_ntop(&nh_attr_list[i].value.ipaddr,
					 __gateway, sizeof(__gateway));
				DEBUG("%s() %d: ip %s\n", __func__,
				      nh_idx, __gateway);
				break;
			}
		}
	}
	return 0;
}

int fal_plugin_ip_upd_next_hop(fal_object_t obj,
			       const struct fal_attribute_t *attr)
{
	DEBUG("%s(0x%lx, { id %d, ... })\n", __func__, obj, attr->id);

	return 0;
}

int fal_plugin_ip_del_next_hops(uint32_t nh_count,
				const fal_object_t *obj)
{
	DEBUG("%s() nhops %d\n", __func__, nh_count);

	return 0;
}

int fal_plugin_ip_new_route(unsigned int vrfid,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid,
			    uint32_t attr_count,
			    const struct fal_attribute_t *attr_list)
{
	char __ipaddr[64];
	const struct fal_attribute_t *attr;

	fal_ntop(ipaddr, __ipaddr, sizeof(__ipaddr));
	DEBUG("%s(vrfid %d, ipaddr %s/%d, tableid %d, attr_count %d, ...)\n",
			__func__, vrfid, __ipaddr,
			prefixlen, tableid, attr_count);

	attr = get_attribute(FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP,
			     attr_count,
			     attr_list);
	if (attr)
		DEBUG("%s() next-hop-group 0x%lx\n", __func__,
		      attr->value.u64);

	attr = get_attribute(FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION,
			     attr_count,
			     attr_list);
	if (attr)
		DEBUG("%s() packet-action %d\n", __func__,
		      attr->value.u32);

	return 0;
}

int fal_plugin_ip_upd_route(unsigned int vrfid,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid,
			    struct fal_attribute_t *attr)
{
	char __ipaddr[64];

	fal_ntop(ipaddr, __ipaddr, sizeof(__ipaddr));
	DEBUG("%s(vrfid %d, ipaddr %s/%d, "
	      "tableid %d, { id %d, ... })\n",
	      __func__, vrfid, __ipaddr, prefixlen, tableid, attr->id);
	switch (attr->id) {
	case FAL_ROUTE_ENTRY_ATTR_NEXT_HOP_GROUP:
		DEBUG("%s() next-hop-group 0x%lx\n", __func__,
		      attr->value.u64);
		break;
	case FAL_ROUTE_ENTRY_ATTR_PACKET_ACTION:
		DEBUG("%s() packet-action %d\n", __func__,
		      attr->value.u32);
		break;
	}

	return 0;
}

int fal_plugin_ip_del_route(unsigned int vrfid,
			    struct fal_ip_address_t *ipaddr,
			    uint8_t prefixlen,
			    uint32_t tableid)
{
	char __ipaddr[64];

	fal_ntop(ipaddr, __ipaddr, sizeof(__ipaddr));
	DEBUG("%s(vrfid %d, ipaddr %s/%d, tableid %d, ...)\n",
			__func__, vrfid, __ipaddr, prefixlen, tableid);

	return 0;
}

#define STP_INST_CHECK(_inst)						\
	dp_test_fail_unless((_inst >= 0) && (_inst < STP_INST_COUNT),	\
			    "invalid STP instance value: %u", _inst)

int fal_plugin_stp_create(unsigned int bridge_ifindex,
			  uint32_t attr_count,
			  const struct fal_attribute_t *attr_list,
			  fal_object_t *obj)
{
	static fal_object_t fal_test_stp_obj = 1;
	const struct fal_attribute_t *attr;
	uint32_t i;
	int stpinst = -1;
	int mstid = -1;

	dp_test_fail_unless(*obj == 0, "unexpected STP object");
	DEBUG("%s(bridge_ifindex %u, attr_count %d, ...)\n",
	      __func__, bridge_ifindex, attr_count);

	for (i = 0; i < attr_count; i++) {
		attr = &attr_list[i];

		switch (attr->id) {
		case FAL_STP_ATTR_INSTANCE:
			stpinst = attr->value.u8;
			break;
		case FAL_STP_ATTR_MSTI:
			mstid = attr->value.u16;
			break;
		default:
			dp_test_assert_internal(false);
			break;
		}
	}

	STP_INST_CHECK(stpinst);
	dp_test_fail_unless((mstid >= 0) && (mstid < 4095),
			    "invalid MSTI value: %u", mstid);
	*obj = fal_test_stp_obj++;

	DEBUG("%s() <-- 0x%lx\n", __func__, *obj);
	return 0;
}

int fal_plugin_stp_delete(fal_object_t obj)
{
	dp_test_fail_unless(obj != 0, "missing STP object");
	DEBUG("%s(0x%lx)\n", __func__, obj);
	return 0;
}

int fal_plugin_stp_set_attribute(fal_object_t obj,
				 const struct fal_attribute_t *attr_list)
{
	const struct fal_attribute_t *attr;

	dp_test_fail_unless(obj != 0, "missing STP object");
	DEBUG("%s(0x%lx, ...)\n", __func__, obj);

	attr = get_attribute(FAL_STP_ATTR_MSTP_VLANS, 1, attr_list);
	if (attr)
		DEBUG("%s() MSTID VLANS %p\n", __func__, attr->value.ptr);
	return 0;
}

int fal_plugin_stp_get_attribute(fal_object_t obj, uint32_t attr_count,
				 struct fal_attribute_t *attr_list)
{
	dp_test_fail_unless(obj != 0, "missing STP object");
	DEBUG("%s(0x%lx, attr_count %u, ...)\n", __func__, obj, attr_count);
	return 0;
}

int fal_plugin_stp_set_port_attribute(unsigned int child_ifindex,
				      uint32_t attr_count,
				      const struct fal_attribute_t *attr_list)
{
	const struct fal_attribute_t *attr;
	fal_object_t stp = 0;
	uint32_t i;

	DEBUG("%s(child_ifindex %u, attr_count %u, ...)\n",
	      __func__, child_ifindex, attr_count);

	for (i = 0; i < attr_count; i++) {
		attr = &attr_list[i];

		switch (attr->id) {
		case FAL_STP_PORT_ATTR_INSTANCE:
			stp = attr->value.objid;
			break;
		case FAL_STP_PORT_ATTR_STATE:
			DEBUG("%s() state %u\n", __func__,
			      attr->value.u8);
			break;
		case FAL_STP_PORT_ATTR_HW_FORWARDING:
			DEBUG("%s() hw-forwarding %u\n", __func__,
			      attr->value.booldata);
			break;
		default:
			dp_test_assert_internal(false);
			break;
		}
	}

	dp_test_fail_unless(stp != 0, "missing STP object");

	return 0;
}

int fal_plugin_stp_get_port_attribute(unsigned int child_ifindex,
				      uint32_t attr_count,
				      struct fal_attribute_t *attr_list)
{
	DEBUG("%s(child_ifindex %u, attr_count %u, ...)\n",
	      __func__, child_ifindex, attr_count);
	return 0;
}

void fal_plugin_cleanup(void)
{
	DEBUG("%s\n", __func__);
}

void fal_plugin_command(FILE *f, int argc, char **argv)
{
	DEBUG("%s\n", __func__);
}

int fal_plugin_vlan_feature_create(uint32_t attr_count,
				   const struct fal_attribute_t *attr_list,
				   fal_object_t *obj)
{
	struct vlan_feat *vf;
	uint i;

	vf = calloc(1, sizeof(*vf));
	assert(vf);

	DEBUG("%s start\n", __func__);
	for (i = 0; i < attr_count; i++) {
		switch (attr_list[i].id) {
		case FAL_VLAN_FEATURE_INTERFACE_ID:
			vf->ifindex = attr_list[i].value.u32;
			DEBUG("%s attr: Interface: %d\n", __func__, vf->vlan);
			break;
		case FAL_VLAN_FEATURE_VLAN_ID:
			vf->vlan = attr_list[i].value.u16;
			DEBUG("%s attr: VLAN: %d\n", __func__, vf->vlan);
			break;
		case FAL_VLAN_FEATURE_ATTR_UNICAST_STORM_CONTROL_POLICER_ID:
			vf->policer[FAL_TRAFFIC_UCAST] =
				(struct fal_policer *)attr_list[i].value.objid;
			DEBUG("%s attr: UCAST: %p\n",  __func__,
			      vf->policer[FAL_TRAFFIC_UCAST]);
			break;
		case FAL_VLAN_FEATURE_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID:
			vf->policer[FAL_TRAFFIC_BCAST] =
				(struct fal_policer *)attr_list[i].value.objid;
			DEBUG("%s attr: BCAST: %p\n",  __func__,
			      vf->policer[FAL_TRAFFIC_BCAST]);
			break;
		case FAL_VLAN_FEATURE_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID:
			vf->policer[FAL_TRAFFIC_MCAST] =
				(struct fal_policer *)attr_list[i].value.objid;
			DEBUG("%s attr: MCAST: %p\n", __func__,
			      vf->policer[FAL_TRAFFIC_MCAST]);
			break;
		}
	}

	DEBUG("%s end\n", __func__);
	*obj = (uintptr_t) vf;
	return 0;
}

int fal_plugin_vlan_feature_delete(fal_object_t obj)
{
	struct vlan_feat *vf = (struct vlan_feat *)obj;

	DEBUG("%s %p\n", __func__, (void *)obj);
	free(vf);
	return 0;
}

int fal_plugin_vlan_feature_set_attr(fal_object_t obj,
				     const struct fal_attribute_t *attr)
{
	struct vlan_feat *vf = (struct vlan_feat *)obj;

	switch (attr->id) {
	case FAL_VLAN_FEATURE_INTERFACE_ID:
	case FAL_VLAN_FEATURE_VLAN_ID:
		assert(0); /* only allowed on create */
		break;
	case FAL_VLAN_FEATURE_ATTR_UNICAST_STORM_CONTROL_POLICER_ID:
		vf->policer[FAL_TRAFFIC_UCAST] =
			(struct fal_policer *)attr->value.objid;
		DEBUG("%s attr: UCAST: %p\n", __func__,
		      vf->policer[FAL_TRAFFIC_UCAST]);
		break;
	case FAL_VLAN_FEATURE_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID:
		vf->policer[FAL_TRAFFIC_BCAST] =
			(struct fal_policer *)attr->value.objid;
		DEBUG("%s attr: BCAST: %p\n", __func__,
		      vf->policer[FAL_TRAFFIC_BCAST]);
		break;
	case FAL_VLAN_FEATURE_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID:
		vf->policer[FAL_TRAFFIC_MCAST] =
			(struct fal_policer *)attr->value.objid;
		DEBUG("%s attr: MCAST: %p\n", __func__,
		      vf->policer[FAL_TRAFFIC_MCAST]);
		break;
	}
	return 0;
}

static bool vlan_stats_cleared;

int fal_plugin_vlan_get_stats(uint16_t vlan, uint32_t num_cntrs,
			      const enum fal_vlan_stat_type *cntr_ids,
			      uint64_t *cntrs)
{
	static uint64_t vlan_cnts[FAL_VLAN_STAT_MAX] = {
		10000, 10, 9, 1, 0, 0, 20000, 20, 18, 2, 0, 0 };
	static uint64_t vlan_cnts_zero[FAL_VLAN_STAT_MAX] = { 0 };

	uint i;


	for (i = 0; i < num_cntrs; i++) {
		if (vlan_stats_cleared)
			cntrs[i] = vlan_cnts_zero[cntr_ids[i]];
		else
			cntrs[i] = vlan_cnts[cntr_ids[i]];
	}

	if (vlan_stats_cleared)
		vlan_stats_cleared = false;

	return 0;
}

int fal_plugin_vlan_clear_stats(uint16_t vlan, uint32_t num_cntrs,
				const enum fal_vlan_stat_type *cntr_ids)
{
	/*
	 * Cleared stats are shown as zero for the first time only, then
	 * revert back to being set.
	 */
	vlan_stats_cleared = true;
	return 0;
}
