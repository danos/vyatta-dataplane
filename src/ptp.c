/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <rte_ether.h>
#include <rte_timer.h>

#include "control.h"
#include "dp_event.h"
#include "ether.h"
#include "fal.h"
#include "if/bridge/bridge_port.h"
#include "if_llatbl.h"
#include "netinet6/nd6_nbr.h"
#include "ptp.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

struct ptp_clock_t {
	uint32_t clock_id;
	fal_object_t obj_id;	/**< returned FAL object id */

	struct rcu_head rcu;
	struct cds_list_head list;
};

struct ptp_port_t {
	uint16_t port_id;
	struct ifnet *ifp;
	uint16_t vlan_id;
	fal_object_t obj_id;	/**< returned FAL object id */
	struct ptp_clock_t *clock;

	struct rcu_head rcu;
	struct cds_list_head list;
};

struct ptp_peer_t {
	enum fal_ptp_peer_type_t type;
	struct fal_ip_address_t ipaddr;
	fal_object_t obj_id;	/**< returned FAL object id */
	struct ptp_port_t *port;
	struct rte_ether_addr mac;
	bool installed;

	struct rcu_head rcu;
	struct cds_list_head list;
};

static CDS_LIST_HEAD(ptp_clock_list);
static CDS_LIST_HEAD(ptp_port_list);
static CDS_LIST_HEAD(ptp_peer_list);

static struct rte_timer ptp_peer_resolver;
static unsigned int ptp_peer_resolver_period = 15;	/* seconds */
static void ptp_peer_resolver_cb(struct rte_timer *timer, void *arg);

static
struct ptp_clock_t *ptp_find_clock(uint32_t clock_id)
{
	struct ptp_clock_t *clock;

	cds_list_for_each_entry_rcu(clock, &ptp_clock_list, list)
		if (clock->clock_id == clock_id)
			return clock;

	return NULL;
}

static
struct ptp_port_t *ptp_find_port(uint32_t clock_id, uint16_t port_id)
{
	struct ptp_clock_t *clock;
	struct ptp_port_t *port;

	clock = ptp_find_clock(clock_id);
	if (!clock)
		return NULL;

	cds_list_for_each_entry_rcu(port, &ptp_port_list, list) {
		if (rcu_dereference(port->clock) == clock &&
		    port->port_id == port_id)
			return port;
	}

	return NULL;
}

static
struct ptp_peer_t *ptp_find_peer(uint32_t clock_id, uint16_t port_id,
				 enum fal_ptp_peer_type_t type,
				 struct fal_ip_address_t *ipaddr)
{
	struct ptp_port_t *port;
	struct ptp_peer_t *peer;

	port = ptp_find_port(clock_id, port_id);
	if (!port)
		return NULL;

	cds_list_for_each_entry_rcu(peer, &ptp_peer_list, list) {
		if (rcu_dereference(peer->port) == port &&
		    peer->type == type &&
		    memcmp(&peer->ipaddr, ipaddr, sizeof(*ipaddr)) == 0)
			return peer;
	}

	return NULL;
}

static char *check_token(const char *token)
{
	char *str;

	str = strchr(token, '=');
	if (!str)
		return NULL;
	str++;

	return str;
}

static int get_unsigned_token(const char *token, unsigned int *ptr)
{
	char *str;

	str = check_token(token);
	return get_unsigned(str, ptr);
}

static int get_unsigned_short_token(const char *token, unsigned short *ptr)
{
	char *str;

	str = check_token(token);
	return get_unsigned_short(str, ptr);
}

static int get_unsigned_char_token(const char *token, unsigned char *ptr)
{
	char *str;

	str = check_token(token);
	return get_unsigned_char(str, ptr);
}

static int get_signed_char_token(const char *token, signed char *ptr)
{
	char *str;

	str = check_token(token);
	return get_signed_char(str, ptr);
}

static int get_signed_token(const char *token, int *ptr)
{
	char *str;

	str = check_token(token);
	return get_signed(str, ptr);
}

static int get_bool_token(const char *token, bool *ptr)
{
	char *str;

	str = check_token(token);
	return get_bool(str, ptr);
}

static int ptp_clock_create(FILE *f, uint32_t clock_id, int argc, char **argv)
{
	struct ptp_clock_t *clock = NULL;
	struct fal_attribute_t attrs[FAL_PTP_CLOCK_MAX];
	int num_attrs = 0;
	int rc = -EINVAL;

	if (ptp_find_clock(clock_id)) {
		fprintf(f, "ptp: clock %d already exists!\n", clock_id);
		return -EEXIST;
	}

	while (argc) {
		if (strstr(*argv, "domain-number=")) {
			uint8_t domain;

			rc = get_unsigned_char_token(*argv, &domain);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id =
					FAL_PTP_CLOCK_DOMAIN_NUMBER;
			attrs[num_attrs].value.u8 = domain;

		} else if (strstr(*argv, "clock-identity=")) {
			char *clock_ident;
			int rc;

			clock_ident = strchr(*argv, '=') + 1;

			attrs[num_attrs].id =
					FAL_PTP_CLOCK_CLOCK_IDENTITY;
			rc = sscanf(clock_ident,
				    "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				    &attrs[num_attrs].value.eui64[0],
				    &attrs[num_attrs].value.eui64[1],
				    &attrs[num_attrs].value.eui64[2],
				    &attrs[num_attrs].value.eui64[3],
				    &attrs[num_attrs].value.eui64[4],
				    &attrs[num_attrs].value.eui64[5],
				    &attrs[num_attrs].value.eui64[6],
				    &attrs[num_attrs].value.eui64[7]);
			if (rc != 8)
				goto error;

		} else if (strstr(*argv, "number-ports=")) {
			uint16_t num_ports;

			rc = get_unsigned_short_token(*argv, &num_ports);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id = FAL_PTP_CLOCK_NUMBER_PORTS;
			attrs[num_attrs].value.u16 = num_ports;

		} else if (strstr(*argv, "priority1=")) {
			uint8_t priority1;

			rc = get_unsigned_char_token(*argv, &priority1);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id = FAL_PTP_CLOCK_PRIORITY1;
			attrs[num_attrs].value.u8 = priority1;

		} else if (strstr(*argv, "priority2=")) {
			uint8_t priority2;

			rc = get_unsigned_char_token(*argv, &priority2);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id = FAL_PTP_CLOCK_PRIORITY2;
			attrs[num_attrs].value.u8 = priority2;

		} else if (strstr(*argv, "slave-only=")) {
			bool slave_only;

			rc = get_bool_token(*argv, &slave_only);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id = FAL_PTP_CLOCK_SLAVE_ONLY;
			attrs[num_attrs].value.booldata = slave_only;

		} else if (strstr(*argv, "two-step=")) {
			bool two_step;

			rc = get_bool_token(*argv, &two_step);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id = FAL_PTP_CLOCK_TWO_STEP_FLAG;
			attrs[num_attrs].value.booldata = two_step;

		} else if (strstr(*argv, "profile=")) {
			char *profile_string;
			enum fal_ptp_clock_profile_t profile;

			profile_string = strchr(*argv, '=') + 1;

			if (strcmp(profile_string, "default-profile") == 0)
				profile = FAL_PTP_CLOCK_DEFAULT_PROFILE;
			else if (strcmp(profile_string, "g82752-profile") == 0)
				profile = FAL_PTP_CLOCK_G82752_PROFILE;
			else if (strcmp(profile_string,
					"g82752-apts-profile") == 0)
				profile = FAL_PTP_CLOCK_G82752_APTS_PROFILE;
			else if (strcmp(profile_string,
					"g82751-forwardable-profile") == 0)
				profile = FAL_PTP_CLOCK_G82751_FWD_PROFILE;
			else if (strcmp(profile_string,
					"g82751-non-forwardable-profile") == 0)
				profile = FAL_PTP_CLOCK_G82751_NON_FWD_PROFILE;
			else {
				fprintf(f, "ptp: bad profile: %s\n",
					profile_string);
				goto out;
			}

			attrs[num_attrs].id = FAL_PTP_CLOCK_PROFILE;
			attrs[num_attrs].value.u32 = profile;

		} else if (strstr(*argv, "antenna-delay=")) {
			int antenna_delay;

			rc = get_signed_token(*argv, &antenna_delay);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id = FAL_PTP_CLOCK_ANTENNA_DELAY;
			attrs[num_attrs].value.i32 = antenna_delay;

		} else {
			fprintf(f, "ptp: bad option: %s\n", *argv);
			goto out;
		}

		num_attrs++;
		argc--;
		argv++;
	}

	attrs[num_attrs].id = FAL_PTP_CLOCK_CLOCK_NUMBER;
	attrs[num_attrs].value.u32 = clock_id;
	num_attrs++;

	clock = calloc(1, sizeof(*clock));
	if (!clock) {
		fprintf(f, "ptp: clock %d alloc failed!\n", clock_id);
		goto out;
	}

	rc = fal_create_ptp_clock(num_attrs, attrs, &clock->obj_id);
	if (rc < 0) {
		fprintf(f, "ptp: fal_create_ptp_clock failed!\n");
		goto error;
	}

	clock->clock_id = clock_id;
	cds_list_add_rcu(&clock->list, &ptp_clock_list);

	if (!cds_list_empty(&ptp_clock_list)) {
		rte_timer_init(&ptp_peer_resolver);
		rte_timer_reset_sync(&ptp_peer_resolver,
			     rte_get_timer_hz() * ptp_peer_resolver_period,
			     PERIODICAL, rte_get_master_lcore(),
			     ptp_peer_resolver_cb, NULL);
	}

out:
	return rc;

error:
	free(clock);
	goto out;
}

static void ptp_clock_free(struct rcu_head *head)
{
	struct ptp_clock_t *clock;

	clock = caa_container_of(head, struct ptp_clock_t, rcu);
	free(clock);
}

static int ptp_clock_delete(FILE *f, uint32_t clock_id,
		     int argc, char **argv __unused)
{
	struct ptp_clock_t *clock;
	int rc = -EINVAL;

	if (argc > 0)
		goto error;

	clock = ptp_find_clock(clock_id);
	if (!clock) {
		fprintf(f, "ptp: unable to find clock %d\n", clock_id);
		goto error;
	}

	rc = fal_delete_ptp_clock(clock->obj_id);
	if (rc < 0) {
		fprintf(f, "ptp: unable to delete clock %d\n", clock_id);
		goto error;
	}

	cds_list_del_rcu(&clock->list);
	call_rcu(&clock->rcu, ptp_clock_free);

	if (cds_list_empty(&ptp_clock_list))
		rte_timer_stop_sync(&ptp_peer_resolver);

error:
	return rc;
}

static
int ptp_port_create(FILE *f, uint16_t port_id, int argc, char **argv)
{
	uint32_t clock_id;
	struct ptp_clock_t *clock = NULL;
	int rc = -EINVAL;
	struct fal_attribute_t attrs[FAL_PTP_PORT_MAX];
	int num_attrs = 0;
	struct ptp_port_t *port = NULL;

	port = calloc(1, sizeof(*port));
	if (!port) {
		fprintf(f, "ptp: calloc for clock port failed!\n");
		rc = -ENOMEM;
		goto error;
	}

	while (argc) {
		if (strstr(*argv, "clock-id=")) {
			if (get_unsigned_token(*argv, &clock_id) < 0)
				goto error;

			clock = ptp_find_clock(clock_id);
			if (!clock) {
				fprintf(f, "ptp: no clock %d for port %d\n",
					clock_id, port_id);
				goto error;
			}
			attrs[num_attrs].id = FAL_PTP_PORT_PTP_CLOCK;
			attrs[num_attrs].value.objid = clock->obj_id;

		} else if (strstr(*argv, "interface=")) {
			struct ifnet *ifp;
			char *ifname;

			ifname = strchr(*argv, '=') + 1;
			ifp = dp_ifnet_byifname(ifname);
			if (!ifp) {
				// TBD -- create a replay cache
				goto error;
			}
			rcu_assign_pointer(port->ifp, ifp);
			attrs[num_attrs].id = FAL_PTP_PORT_UNDERLYING_INTERFACE;
			attrs[num_attrs].value.u32 = ifp->if_index;

		} else if (strstr(*argv, "vlan-id=")) {
			uint16_t vlan_id;

			rc = get_unsigned_short_token(*argv, &vlan_id);
			if (rc < 0)
				goto error;

			port->vlan_id = vlan_id;
			attrs[num_attrs].id = FAL_PTP_PORT_VLAN_ID;
			attrs[num_attrs].value.u16 = vlan_id;

		} else if (strstr(*argv, "additional-path=")) {
			struct ifnet *ifp;
			char *ifname, *vlan_str;
			uint16_t vlan_id;

			/* additional-path=ifname,vlan-id */

			ifname = strchr(*argv, '=') + 1;
			vlan_str = strchr(ifname, ',');
			if (!vlan_str) {
				rc = -EINVAL;
				goto error;
			}
			*vlan_str++ = '\0';	/* remove ',' from ifname */

			ifp = dp_ifnet_byifname(ifname);
			if (!ifp)
				goto error;

			rc = get_unsigned_short(vlan_str, &vlan_id);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id = FAL_PTP_PORT_ADDITIONAL_PATH;
			attrs[num_attrs].value.ptp_port_path.ifindex = ifp->if_index;
			attrs[num_attrs].value.ptp_port_path.vlan_id = vlan_id;

		} else if (strstr(*argv, "log-min-delay-req-interval=")) {
			int8_t log_min_delay_req_interval;

			rc = get_signed_char_token(*argv,
						   &log_min_delay_req_interval);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id =
					FAL_PTP_PORT_LOG_MIN_DELAY_REQ_INTERVAL;
			attrs[num_attrs].value.i8 = log_min_delay_req_interval;

		} else if (strstr(*argv, "log-announce-interval=")) {
			int8_t log_announce_interval;

			rc = get_signed_char_token(*argv,
						   &log_announce_interval);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id =
					FAL_PTP_PORT_LOG_ANNOUNCE_INTERVAL;
			attrs[num_attrs].value.i8 = log_announce_interval;

		} else if (strstr(*argv, "announce-receipt-timeout=")) {
			int8_t announce_receipt_timeout;

			rc = get_signed_char_token(*argv,
						   &announce_receipt_timeout);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id =
					FAL_PTP_PORT_ANNOUNCE_RECEIPT_TIMEOUT;
			attrs[num_attrs].value.i8 = announce_receipt_timeout;

		} else if (strstr(*argv, "log-min-pdelay-req-interval=")) {
			int8_t log_min_pdelay_req_interval;

			rc = get_signed_char_token(*argv,
					   &log_min_pdelay_req_interval);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id =
				       FAL_PTP_PORT_LOG_MIN_PDELAY_REQ_INTERVAL;
			attrs[num_attrs].value.i8 = log_min_pdelay_req_interval;

		} else if (strstr(*argv, "log-sync-interval=")) {
			int8_t log_sync_interval;

			rc = get_signed_char_token(*argv, &log_sync_interval);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id =
					FAL_PTP_PORT_LOG_SYNC_INTERVAL;
			attrs[num_attrs].value.i8 = log_sync_interval;

		} else if (strstr(*argv, "ip=")) {
			char *ip;
			struct fal_ip_address_t ipaddr;

			ip = strchr(*argv, '=') + 1;
			if (str_to_fal_ip_address_t(ip, &ipaddr) != 1)
				goto error;

			attrs[num_attrs].id = FAL_PTP_PORT_IP_ADDRESS;
			attrs[num_attrs].value.ipaddr = ipaddr;

		} else if (strstr(*argv, "mac=")) {
			char *mac;

			mac = strchr(*argv, '=') + 1;
			if (!ether_aton_r(mac, &attrs[num_attrs].value.mac))
				goto error;
			attrs[num_attrs].id = FAL_PTP_PORT_MAC_ADDRESS;

		} else if (strstr(*argv, "dscp=")) {
			uint8_t dscp;

			rc = get_unsigned_char_token(*argv, &dscp);
			if (rc < 0)
				goto error;

			attrs[num_attrs].id = FAL_PTP_PORT_DSCP;
			attrs[num_attrs].value.u8 = dscp;

		} else {
			fprintf(f, "ptp: bad option: %s\n", *argv);
			goto error;
		}

		num_attrs++;
		argc--;
		argv++;
	}

	/* Must supply at least clock-id= */
	if (!clock) {
		fprintf(f, "ptp: clock-id required for port %d\n", port_id);
		goto error;
	}

	if (ptp_find_port(clock_id, port_id)) {
		fprintf(f, "ptp: clock %d already has a port %d?\n",
			clock_id, port_id);
		goto error;
	}

	attrs[num_attrs].id = FAL_PTP_PORT_PORT_NUMBER;
	attrs[num_attrs].value.u16 = port_id;
	num_attrs++;

	rc = fal_create_ptp_port(num_attrs, attrs, &port->obj_id);
	if (rc < 0) {
		fprintf(f, "ptp: fal_create_ptp_port failed!\n");
		goto error;
	}

	port->port_id = port_id;
	rcu_assign_pointer(port->clock, clock);
	cds_list_add_rcu(&port->list, &ptp_port_list);
	return 0;

error:
	free(port);
	return rc;
}

static void ptp_port_free(struct rcu_head *head)
{
	struct ptp_port_t *port;

	port = caa_container_of(head, struct ptp_port_t, rcu);
	free(port);
}

static int str_to_ptp_peer_type(char *type,
				enum fal_ptp_peer_type_t *peer_type)
{
	if (strcmp(type, "master") == 0)
		*peer_type = FAL_PTP_PEER_MASTER;
	else if (strcmp(type, "slave") == 0)
		*peer_type = FAL_PTP_PEER_SLAVE;
	else if (strcmp(type, "allowed-peer") == 0)
		*peer_type = FAL_PTP_PEER_ALLOWED;
	else
		return -EINVAL;

	return 0;
}

static
int ptp_port_delete(FILE *f, uint16_t port_id, int argc, char **argv)
{
	struct ptp_clock_t *clock = NULL;
	struct ptp_port_t *port;
	uint32_t clock_id;
	int rc = -EINVAL;

	while (argc) {
		if (strstr(*argv, "clock-id=")) {
			if (get_unsigned_token(*argv, &clock_id) < 0)
				goto error;

			clock = ptp_find_clock(clock_id);
			if (!clock) {
				fprintf(f, "ptp: clock %d does not exist\n",
					clock_id);
				rc = -ENODEV;
				goto error;
			}
		} else
			goto error;

		argc--;
		argv++;
	}

	if (!clock) {
		fprintf(f, "ptp: specify clock for port %d\n", port_id);
		goto error;
	}

	port = ptp_find_port(clock_id, port_id);
	if (!port) {
		fprintf(f, "ptp: clock %d has no port %d\n",
			clock_id, port_id);
		goto error;
	}

	rc = fal_delete_ptp_port(port->obj_id);
	if (rc < 0) {
		fprintf(f, "ptp: fal_ptp_port_delete failed!\n");
		goto error;
	}

	rcu_assign_pointer(port->clock, NULL);
	cds_list_del_rcu(&port->list);
	call_rcu(&port->rcu, ptp_port_free);

error:
	return rc;
}

static
int ptp_peer_install(struct ptp_peer_t *peer)
{
	struct fal_attribute_t attrs[FAL_PTP_PEER_MAX];
	struct ptp_port_t *port;
	int num_attrs = 0;
	int rc = -EINVAL;

	port = rcu_dereference(peer->port);
	if (!port)
		goto error;

	attrs[num_attrs].id = FAL_PTP_PEER_TYPE;
	attrs[num_attrs].value.u32 = peer->type;
	num_attrs++;

	attrs[num_attrs].id = FAL_PTP_PEER_IP_ADDRESS;
	attrs[num_attrs].value.ipaddr = peer->ipaddr;
	num_attrs++;

	if (!ether_is_empty(&peer->mac)) {
		attrs[num_attrs].id = FAL_PTP_PEER_MAC_ADDRESS;
		attrs[num_attrs].value.mac = peer->mac;
		num_attrs++;
	}

	attrs[num_attrs].id = FAL_PTP_PEER_PTP_PORT;
	attrs[num_attrs].value.objid = port->obj_id;
	num_attrs++;

	rc = fal_create_ptp_peer(num_attrs, attrs, &peer->obj_id);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"PTP: fal_create_ptp_peer failed!, rc = %d\n", rc);
		goto error;
	}

	peer->installed = true;

error:
	return rc;
}

static
int ptp_peer_uninstall(struct ptp_peer_t *peer)
{
	int rc = 0;

	if (peer->installed) {
		rc = fal_delete_ptp_peer(peer->obj_id);
		peer->installed = false;
	}

	return rc;
}

static
struct ifnet *ptp_port_port_to_vlan(struct ptp_port_t *port)
{
	struct ifnet *ifp;
	struct ifnet *sw_ifp, *vlan_ifp;
	struct bridge_port *brport;

	ifp = rcu_dereference(port->ifp);
	if (!ifp) {
		RTE_LOG(ERR, DATAPLANE, "%s: missing ifp?\n", __func__);
		return NULL;
	}

	brport = rcu_dereference(ifp->if_brport);
	if (!brport) {
		RTE_LOG(ERR, DATAPLANE, "%s: not a bridge port?\n", __func__);
		return NULL;
	}

	sw_ifp = bridge_port_get_bridge(brport);
	if (!sw_ifp) {
		RTE_LOG(ERR, DATAPLANE, "%s: not a member of switch?\n",
			__func__);
		return NULL;
	}

	vlan_ifp = if_vlan_lookup(sw_ifp, port->vlan_id);
	if (!vlan_ifp) {
		RTE_LOG(ERR, DATAPLANE, "%s: no vlan %d on switch?\n",
			__func__, port->vlan_id);
		return NULL;
	}

	return vlan_ifp;
}

/* Find the nexthop interface for the peer if it exists */
static
struct ifnet *ptp_peer_dst_lookup(struct ptp_peer_t *peer, bool *connected)
{
	struct ifnet *nh_ifp = NULL;
	const struct vrf *vrf;

	vrf = get_vrf(VRF_DEFAULT_ID);
	if (!vrf) {
		RTE_LOG(ERR, DATAPLANE, "%s: no default VRF?\n", __func__);
		return NULL;
	}

	*connected = false;
	if (peer->ipaddr.addr_family == FAL_IP_ADDR_FAMILY_IPV4) {
		nh_ifp = nhif_dst_lookup(vrf,
					 peer->ipaddr.addr.ip4,
					 connected);
	} else if (peer->ipaddr.addr_family == FAL_IP_ADDR_FAMILY_IPV6) {
		nh_ifp = nhif_dst_lookup6(vrf,
					  &peer->ipaddr.addr.addr6,
					  connected);
	} else {
		char buf[INET_ADDRSTRLEN];
		const char *ip = fal_ip_address_t_to_str(&peer->ipaddr,
							 buf,
							 sizeof(buf));

		RTE_LOG(ERR, DATAPLANE, "%s: peer %s bad address family?\n",
			__func__, ip);
	}

	return nh_ifp;
}

static
void ptp_peer_dst_resolve(struct ptp_peer_t *peer,
			  struct ifnet *ifp,
			  struct rte_ether_addr *dst)

{
	struct rte_mbuf *m;
	struct llentry *lle;
	struct sockaddr_in taddr;
	char buf[INET_ADDRSTRLEN];
	const char *peerip = fal_ip_address_t_to_str(&peer->ipaddr,
						     buf,
						     sizeof(buf));

	/* Next hop is directly reachable from switch interface. */
	if (peer->ipaddr.addr_family == FAL_IP_ADDR_FAMILY_IPV4)
		lle = in_lltable_find(ifp, peer->ipaddr.addr.ip4);
	else if (peer->ipaddr.addr_family == FAL_IP_ADDR_FAMILY_IPV6)
		lle = in6_lltable_find(ifp, &peer->ipaddr.addr.addr6);
	else {
		RTE_LOG(ERR, DATAPLANE, "%s: bad address family?\n",
			__func__);
		return;
	}

	if (llentry_copy_mac(lle, dst))
		return;

	/* The lle isn't valid (yet), attempt to resolve locally. */

	DP_DEBUG(PTP, ERR, DATAPLANE, "%s: resolving %s...\n",
		 __func__, peerip);

	if (peer->ipaddr.addr_family == FAL_IP_ADDR_FAMILY_IPV4) {
		taddr.sin_family = AF_INET;
		taddr.sin_addr.s_addr = peer->ipaddr.addr.ip4;

		m = arprequest(ifp, (struct sockaddr *) &taddr);
		if (m)
			if_output(ifp, m, NULL, RTE_ETHER_TYPE_ARP);

	} else if (peer->ipaddr.addr_family == FAL_IP_ADDR_FAMILY_IPV6) {
		m = pktmbuf_alloc(mbuf_pool(0), if_vrfid(ifp));
		if (!m) {
			RTE_LOG(ERR, DATAPLANE, "%s: no mbufs for ND\n",
				__func__);
			return;
		}

		if (!nd6_resolve(NULL, ifp, m,
				 &peer->ipaddr.addr.addr6,
				 dst))
			if_output(ifp, m, NULL, RTE_ETHER_TYPE_IPV6);

	} else {
		RTE_LOG(ERR, DATAPLANE,
			"%s: peer %s bad address family?\n",
			__func__, peerip);
	}
}

static
void ptp_peer_update(struct ptp_peer_t *peer)
{
	struct ptp_port_t *port;
	struct ifnet *ifp, *nh_ifp;
	struct rte_ether_addr newmac = { { 0 } };
	char buf[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
	const char *peerip =
		fal_ip_address_t_to_str(&peer->ipaddr, buf2, sizeof(buf2));
	bool connected;

	port = rcu_dereference(peer->port);
	if (!port)
		goto out;

	ifp = ptp_port_port_to_vlan(port);
	if (!ifp)
		goto out;

	nh_ifp = ptp_peer_dst_lookup(peer, &connected);
	if (!nh_ifp)
		goto out;

	if (nh_ifp == ifp && connected) {
		ptp_peer_dst_resolve(peer, ifp, &newmac);
	} else if (nh_ifp) {
		/* Send packets to switch interface for routing. */

		if (!(ifp->if_flags & IFF_UP)) {
			DP_DEBUG(PTP, ERR, DATAPLANE,
				 "%s: switch nexthop interface %s is down!\n",
				 __func__, ifp->if_name);
			goto out;
		}

		DP_DEBUG(PTP, INFO, DATAPLANE,
			 "%s: peer %s routed via switch interface %s.\n",
			 __func__, peerip, nh_ifp->if_name);
		rte_ether_addr_copy(&ifp->eth_addr, &newmac);
	} else {
		DP_DEBUG(PTP, ERR, DATAPLANE,
			 "%s: peer %s is unreachable from clock port %s.\n",
			 __func__, peerip, ifp->if_name);
	}

out:
	/* If the MAC address changed (or finally resolved),
	 * we need to update (or install) the peer in the FAL.
	 */
	if (!rte_ether_addr_equal(&newmac, &peer->mac)) {
		if (ptp_peer_uninstall(peer) < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"%s: ptp_peer_uninstall for %s failed!\n",
				__func__, peerip);
			return;
		}

		rte_ether_addr_copy(&newmac, &peer->mac);
		if (!ether_is_empty(&peer->mac)) {
			DP_DEBUG(PTP, ERR, DATAPLANE, "%s: peer %s is at %s.\n",
				 __func__, peerip, ether_ntoa_r(&newmac, buf));
			ptp_peer_install(peer);
		}
	}
}

static
void ptp_peer_resolver_cb(struct rte_timer *timer __rte_unused,
			  void *arg __rte_unused)
{
	struct ptp_peer_t *peer;

	DP_DEBUG(PTP, DEBUG, DATAPLANE, "%s: started...\n", __func__);

	cds_list_for_each_entry_rcu(peer, &ptp_peer_list, list) {
		if (peer->type == FAL_PTP_PEER_SLAVE ||
		    peer->type == FAL_PTP_PEER_MASTER)
			ptp_peer_update(peer);
	}

	DP_DEBUG(PTP, DEBUG, DATAPLANE, "%s: done!\n", __func__);
}

static
int ptp_peer_create(FILE *f, int argc, char **argv)
{
	uint32_t clock_id = 0;
	uint16_t port_id = 0;
	struct ptp_port_t *port = NULL;
	struct ptp_peer_t *peer = NULL;
	int rc = -EINVAL;
	bool have_clock = false;
	bool have_port = false;
	bool have_peer_type = false;
	bool have_mac = false;

	peer = calloc(1, sizeof(*peer));
	if (!peer) {
		fprintf(f, "ptp: alloc for peer failed!\n");
		rc = -ENOMEM;
		goto error;
	}

	while (argc) {
		if (strstr(*argv, "clock-id=")) {
			rc = get_unsigned_token(*argv, &clock_id);
			if (rc < 0)
				goto error;
			have_clock = true;
			goto next_option;

		} else if (strstr(*argv, "port-id=")) {
			rc = get_unsigned_short_token(*argv, &port_id);
			if (rc < 0)
				goto error;
			have_port = true;
			goto next_option;

		} else if (strstr(*argv, "ip=")) {
			char *ip;

			ip = strchr(*argv, '=') + 1;
			if (str_to_fal_ip_address_t(ip, &peer->ipaddr) != 1) {
				rc = -EINVAL;
				goto error;
			}

		} else if (strstr(*argv, "mac=")) {
			char *mac;

			mac = strchr(*argv, '=') + 1;
			if (!ether_aton_r(mac, &peer->mac)) {
				rc = -EINVAL;
				goto error;
			}
			have_mac = true;

		} else if (strstr(*argv, "type=")) {
			char *str;

			str = strchr(*argv, '=') + 1;
			rc = str_to_ptp_peer_type(str, &peer->type);
			if (rc < 0)
				goto error;
			have_peer_type = true;

		} else {
			fprintf(f, "ptp: bad option: %s\n", *argv);
			goto error;
		}

next_option:
		argc--;
		argv++;
	}

	rc = -EINVAL;

	/* Must supply at least clock-id, port-id, type and ip */
	if (!have_clock) {
		fprintf(f, "ptp: clock-id required for peer\n");
		goto error;
	}

	if (!have_port) {
		fprintf(f, "ptp: port-id required for peer\n");
		goto error;
	}

	if (!have_peer_type) {
		fprintf(f, "ptp: type required for peer\n");
		goto error;
	}

	if (fal_is_ipaddr_empty(&peer->ipaddr)) {
		fprintf(f, "ptp: ip address required for peer\n");
		goto error;
	}

	if (ptp_find_peer(clock_id, port_id, peer->type, &peer->ipaddr)) {
		fprintf(f, "ptp: peer already exists\n");
		rc = -EEXIST;
		goto error;
	}

	port = ptp_find_port(clock_id, port_id);
	if (!port) {
		fprintf(f, "ptp: clock %d port %d doesn't exist\n",
			clock_id, port_id);
		rc = -ENODEV;
		goto error;
	}
	rcu_assign_pointer(peer->port, port);

	/* If we already have a MAC or this is an allowed peer entry,
	 * we can just create it now. Otherwise, put it in the peer
	 * list so we can resolve it later.
	 */
	if (have_mac || peer->type == FAL_PTP_PEER_ALLOWED) {
		rc = ptp_peer_install(peer);
		if (rc < 0) {
			fprintf(f, "ptp: fal_create_ptp_peer failed!\n");
			goto error;
		}
	}

	cds_list_add_rcu(&peer->list, &ptp_peer_list);
	return 0;

error:
	free(peer);
	return rc;
}

static void ptp_peer_free(struct rcu_head *head)
{
	struct ptp_peer_t *peer;

	peer = caa_container_of(head, struct ptp_peer_t, rcu);
	free(peer);
}

static
int ptp_peer_delete(FILE *f, int argc, char **argv)
{
	uint32_t clock_id = 0;
	uint16_t port_id = 0;
	bool have_clock = false;
	bool have_port = false;
	struct ptp_peer_t *peer;
	enum fal_ptp_peer_type_t peer_type = 0;
	bool have_peer_type = false;
	struct fal_ip_address_t ipaddr = { 0 };
	int rc = -EINVAL;

	while (argc) {
		if (strstr(*argv, "clock-id=")) {
			rc = get_unsigned_token(*argv, &clock_id);
			if (rc < 0)
				goto error;
			have_clock = true;

		} else if (strstr(*argv, "port-id=")) {
			rc = get_unsigned_short_token(*argv, &port_id);
			if (rc < 0)
				goto error;
			have_port = true;

		} else if (strstr(*argv, "ip=")) {
			char *ip;

			ip = strchr(*argv, '=') + 1;
			if (str_to_fal_ip_address_t(ip, &ipaddr) != 1) {
				rc = -EINVAL;
				goto error;
			}

		} else if (strstr(*argv, "type=")) {
			char *str;

			str = strchr(*argv, '=') + 1;
			rc = str_to_ptp_peer_type(str, &peer_type);
			if (rc < 0)
				goto error;
			have_peer_type = true;

		} else {
			fprintf(f, "ptp: bad option: %s\n", *argv);
			goto error;
		}

		argc--;
		argv++;
	}

	rc = -EINVAL;

	/* Must supply at least clock-id, port-id, type and ip */
	if (!have_clock) {
		fprintf(f, "ptp: clock-id required for peer\n");
		goto error;
	}

	if (!have_port) {
		fprintf(f, "ptp: port-id required for peer\n");
		goto error;
	}

	if (!have_peer_type) {
		fprintf(f, "ptp: type required for peer\n");
		goto error;
	}

	if (fal_is_ipaddr_empty(&ipaddr)) {
		fprintf(f, "ptp: ip address required for peer\n");
		goto error;
	}

	peer = ptp_find_peer(clock_id, port_id, peer_type, &ipaddr);
	if (!peer) {
		fprintf(f, "ptp: can't find object for peer\n");
		rc = -ENODEV;
		goto error;
	}

	rc = ptp_peer_uninstall(peer);
	if (rc < 0) {
		fprintf(f, "ptp: fal_delete_ptp_peer failed!\n");
		goto error;
	}

	rcu_assign_pointer(peer->port, NULL);
	cds_list_del_rcu(&peer->list);
	call_rcu(&peer->rcu, ptp_peer_free);

error:
	return rc;
}

enum ptp_obj_type {
	PTP_CLOCK,
	PTP_PORT,
	PTP_PEER,
};

int cmd_ptp_op(FILE *f, int argc, char **argv)
{
	struct ptp_clock_t *clock;
	json_writer_t *wr;
	uint32_t clock_id;
	int rc = -EINVAL;

	if (argc < 4)
		goto usage;
	argc--;
	argv++;

	if (strcmp(*argv, "clock") != 0)
		goto usage;
	argc--;
	argv++;

	if (strcmp(*argv, "dump") != 0)
		goto usage;
	argc--;
	argv++;

	if (get_unsigned(*argv, &clock_id) < 0)
		goto error;
	clock = ptp_find_clock(clock_id);
	if (!clock) {
		fprintf(f, "ptp: clock %d does not exist\n", clock_id);
		goto error;
	}

	wr = jsonw_new(f);
	if (!wr) {
		fprintf(f, "ptp: could not create json writer\n");
		goto error;
	}
	jsonw_pretty(wr, true);
	jsonw_name(wr, "ptp clock");
	jsonw_start_array(wr);
	rc = fal_dump_ptp_clock(clock->obj_id, wr);
	jsonw_end_array(wr);
	if (rc < 0) {
		fprintf(f, "ptp: dump failed\n");
		goto error;
	}

	jsonw_destroy(&wr);

error:
	return rc;

usage:
	fprintf(f, "ptp clock dump <clock-id>\n");
	goto error;
}

int cmd_ptp_cfg(FILE *f, int argc, char **argv)
{
	bool is_create;
	unsigned int n;
	int rc = -EINVAL;
	enum ptp_obj_type obj_type;

	if (argc < 4)
		goto error;
	argc--;
	argv++;

	if (strcmp(*argv, "clock") == 0)
		obj_type = PTP_CLOCK;
	else if (strcmp(*argv, "port") == 0)
		obj_type = PTP_PORT;
	else if (strcmp(*argv, "peer") == 0)
		obj_type = PTP_PEER;
	else
		goto error;
	argc--;
	argv++;

	if (strcmp(*argv, "create") == 0)
		is_create = true;
	else if (strcmp(*argv, "delete") == 0)
		is_create = false;
	else
		goto error;
	argc--;
	argv++;

	if (obj_type == PTP_CLOCK || obj_type == PTP_PORT) {
		rc = get_unsigned(*argv, &n);
		if (rc < 0)
			goto error;
		argc--;
		argv++;
	}

	switch (obj_type) {
	case PTP_CLOCK:
		if (is_create)
			rc = ptp_clock_create(f, n, argc, argv);
		else
			rc = ptp_clock_delete(f, n, argc, argv);
		break;
	case PTP_PORT:
		if (is_create)
			rc = ptp_port_create(f, n, argc, argv);
		else
			rc = ptp_port_delete(f, n, argc, argv);
		break;
	case PTP_PEER:
		if (is_create)
			rc = ptp_peer_create(f, argc, argv);
		else
			rc = ptp_peer_delete(f, argc, argv);
		break;
	}

	if (rc)
		goto error;

	return rc;

error:
	fprintf(f, "ptp clock create <clock-id> [[[var1=value1] var2=value2] ...]\n");
	fprintf(f, "ptp clock delete <clock-id>\n");
	fprintf(f, "ptp port create <port> clock-id=<clock-id> [[[var1=value1] var2=value2] ...]\n");
	fprintf(f, "ptp port delete <port> clock-id=<clock-id>\n");
	fprintf(f, "ptp peer create clock-id=<clock-id> port-id=<port-id> ip=<ip-address> [[[var1=value1] var2=value2] ...]\n");
	fprintf(f, "ptp peer delete clock-id=<clock-id> port-id=<port-id> ip=<ip-address>\n");

	return -EINVAL;
}

int cmd_ptp_ut(FILE *f, int argc, char **argv)
{
	return cmd_ptp_cfg(f, argc, argv);
}
