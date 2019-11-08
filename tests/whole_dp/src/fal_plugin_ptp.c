/*-
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2019 AT&T Intellectual Property.
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

#include "json_writer.h"
#include "dp_test_macros.h"
#include "util.h"

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

static fal_object_t fal_test_plugin_ptp_next_obj = 1000;

#define MAX_PTP_PORTS 2
#define MAX_PTP_PEERS 2

static fal_object_t ptp_clock = FAL_NULL_OBJECT_ID;
static int ptp_clock_id;
static int ptp_domain_number;
static int ptp_number_ports;

static struct ptp_port {
	fal_object_t obj_id;
	uint16_t vlan_id;
} ptp_ports[MAX_PTP_PORTS];
static int num_ptp_ports;

static struct ptp_peer {
	fal_object_t obj_id;
	enum fal_ptp_peer_type_t type;
	struct fal_ip_address_t ip;
} ptp_peers[MAX_PTP_PEERS];
static int num_ptp_peers;

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

int fal_plugin_create_ptp_clock(uint32_t attr_count,
				struct fal_attribute_t *attr_list,
				fal_object_t *clock_obj)
{
	const struct fal_attribute_t *attr;

	if (ptp_clock != FAL_NULL_OBJECT_ID)
		return -EEXIST;

	attr = get_attribute(FAL_PTP_CLOCK_CLOCK_NUMBER,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify clock number during create");
	ptp_clock_id = attr->value.u32;

	attr = get_attribute(FAL_PTP_CLOCK_DOMAIN_NUMBER,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify domain number during create");
	ptp_domain_number = attr->value.u8;

	attr = get_attribute(FAL_PTP_CLOCK_NUMBER_PORTS,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify number ports during create");
	ptp_number_ports = attr->value.u16;
	if (ptp_number_ports > MAX_PTP_PORTS)
		return -EINVAL;

	attr = get_attribute(FAL_PTP_CLOCK_CLOCK_IDENTITY,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify clock identity during create");

	attr = get_attribute(FAL_PTP_CLOCK_PRIORITY1,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify priority1 during create");

	attr = get_attribute(FAL_PTP_CLOCK_PRIORITY2,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify priority2 during create");

	*clock_obj = fal_test_plugin_ptp_next_obj++;
	ptp_clock = *clock_obj;

	DEBUG("created PTP clock %d, 0x%lx\n", ptp_clock_id, ptp_clock);
	return 0;
}

int fal_plugin_dump_ptp_clock(fal_object_t clock_obj, json_writer_t *wr)
{
	DEBUG("dump PTP clock 0x%lx\n", clock_obj);
	if (clock_obj != ptp_clock)
		return -ENODEV;

	jsonw_name(wr, "default-dataset");
	jsonw_start_object(wr);
	jsonw_uint_field(wr, "domain-number", ptp_domain_number);
	jsonw_uint_field(wr, "number-ports", ptp_number_ports);
	jsonw_end_object(wr);

	return 0;
}

int fal_plugin_delete_ptp_clock(fal_object_t clock_obj)
{
	DEBUG("deleted PTP clock 0x%lx\n", clock_obj);
	if (clock_obj != ptp_clock)
		return -ENODEV;
	ptp_clock = FAL_NULL_OBJECT_ID;
	return 0;
}

int fal_plugin_create_ptp_port(uint32_t attr_count,
			       struct fal_attribute_t *attr_list,
			       fal_object_t *port_obj)
{
	const struct fal_attribute_t *attr;
	uint16_t vlan_id = 1;

	attr = get_attribute(FAL_PTP_PORT_PORT_NUMBER,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify port number during create");

	attr = get_attribute(FAL_PTP_PORT_PTP_CLOCK,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify clock during create");
	if (attr->value.objid != ptp_clock)
		return -ENODEV;

	attr = get_attribute(FAL_PTP_PORT_UNDERLYING_INTERFACE,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify underlying interface create");

	attr = get_attribute(FAL_PTP_PORT_VLAN_ID,
			     attr_count,
			     attr_list);
	if (attr)
		vlan_id = attr->value.u16;

	if (num_ptp_ports == MAX_PTP_PORTS)
		return -ENOMEM;

	ptp_domain_number = attr->value.u8;
	*port_obj = fal_test_plugin_ptp_next_obj++;
	ptp_ports[num_ptp_ports].obj_id = *port_obj;
	ptp_ports[num_ptp_ports].vlan_id = vlan_id;
	num_ptp_ports++;
	DEBUG("created PTP port 0x%lx\n", *port_obj);
	return 0;
}

static struct ptp_port *
fal_plugin_find_ptp_port(fal_object_t port)
{
	int i;

	for (i = 0; i < MAX_PTP_PORTS; i++) {
		if (ptp_ports[i].obj_id == port)
			return &ptp_ports[i];
	}

	return NULL;
}

int fal_plugin_delete_ptp_port(fal_object_t port_obj)
{
	struct ptp_port *port;

	port = fal_plugin_find_ptp_port(port_obj);
	if (!port)
		return -ENODEV;
	port->obj_id = FAL_NULL_OBJECT_ID;
	num_ptp_ports--;
	return 0;
}

static struct ptp_peer *
fal_plugin_find_ptp_peer(fal_object_t peer)
{
	int i;

	for (i = 0; i < MAX_PTP_PEERS; i++) {
		if (ptp_peers[i].obj_id == peer)
			return &ptp_peers[i];
	}

	return NULL;
}

int fal_plugin_create_ptp_peer(uint32_t attr_count,
			       struct fal_attribute_t *attr_list,
			       fal_object_t *peer_obj)
{
	const struct fal_attribute_t *attr;
	enum fal_ptp_peer_type_t type;
	struct fal_ip_address_t ip;
	struct ptp_peer *peer;

	attr = get_attribute(FAL_PTP_PEER_PTP_PORT,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify port object during peer create");

	attr = get_attribute(FAL_PTP_PEER_TYPE,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify peer type during create");
	type = attr->value.u32;

	attr = get_attribute(FAL_PTP_PEER_IP_ADDRESS,
			     attr_count,
			     attr_list);
	dp_test_fail_unless(attr,
			    "Must specify IP address during peer create");
	ip = attr->value.ipaddr;

	if (num_ptp_peers == MAX_PTP_PEERS)
		return -ENOMEM;

	*peer_obj = fal_test_plugin_ptp_next_obj++;
	peer = &ptp_peers[num_ptp_peers++];
	peer->obj_id = *peer_obj;
	peer->ip = ip;
	peer->type = type;

	DEBUG("created PTP peer 0x%lx\n", *peer_obj);
	return 0;
}

int fal_plugin_delete_ptp_peer(fal_object_t peer_obj)
{
	struct ptp_peer *peer;

	peer = fal_plugin_find_ptp_peer(peer_obj);
	if (!peer)
		return -ENODEV;
	peer->obj_id = FAL_NULL_OBJECT_ID;
	num_ptp_peers--;
	DEBUG("deleted PTP peer 0x%lx\n", peer_obj);
	return 0;
}
