/*-
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
/*
 * Parameters read from /etc/vyatta/dataplane.conf
 */

#ifndef CONFIG_INTERNAL_H
#define CONFIG_INTERNAL_H

#include <rte_ether.h>
#include <rte_pci.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "config.h"
#include "ip_addr.h"

struct rxtx_param;

#define DP_NAME_SIZE 6 /* dpXXX + NULL terminating character */

#define PORTCHECK_INTERVAL	5

#define DEFAULT_UUID "00000000-0000-0000-0000-000000000000"

#define CONFIG_MAX_EP_LEN	128

enum vplane_headless_en {
	VPLANE_HEADLESS_NONE,
	VPLANE_HEADLESS_RESET,
	VPLANE_HEADLESS_CONTINUE,
};

struct config_param {
	uint16_t dp_index;	 /* Dataplane's index number */
	bool local_controller; /* VR or controller via uplink */
	/* fields above this point may be accessed in forwarding plane */
	bool auth_enabled;	 /* true if 0MQ authentication is enabled */
	bool console_url_set;    /* true if console_url is defined in config */
	struct ip_addr local_ip; /* local ip of tunnel */
	struct ip_addr remote_ip;/* controller ip */
	char *console_url;	 /* console url */
	char *console_url_bound; /* bound console url */
	char *publish_url;	 /* publish socket url */
	char *request_url;	 /* snapshot request socket */
	char *ctrl_intf_name;    /* name of control channel interface */
	char *console_url_uplink; /* bound console url, uplink only */
	char *console_url_bound_uplink; /* bound console url, uplink only */
	char *publish_url_uplink; /* publish socket url, uplink only */
	char *request_url_uplink; /* snapshot request socket, uplink only */
	unsigned int port_update; /* port status update interval (secs) */
	const char *backplane;	 /* interface for vxlan */
	char *uuid;		 /* UUID of the dataplane */
	char *vplane_name;	 /* Name used to ID the connected vplane */
	enum vplane_headless_en disconnect_mode; /* Behaviour on controller
						    disconnect */
	char *certificate;	 /* Our 0MQ authentication certificate */
	char *remote_cert;	 /* Remote controller 0MQ certificate */
	struct rte_ether_addr uplink_addr; /* uplink intf perm mac addr */
	struct ip_addr rib_ip;   /* rib ctrl ip */
	char *rib_ctrl_url;	 /* rib control url */
	char *xfrm_push_url;	/* xfrm push from the DP url */
	char *xfrm_pull_url;	/* xfrm pull to the DP url */
	char *sfpd_status_file;	/* Shared status file from SFPd */
	char *sfpd_status_upd_url; /* Push to the dp notfications */
};

struct bkplane_pci {
	LIST_ENTRY(bkplane_pci) link;
	struct rte_pci_addr pci_addr;
	char *name;
};

struct config_pci_entry {
	LIST_ENTRY(config_pci_entry) link;
	struct rte_pci_addr pci_addr;
};

/* Platform parameter structure */
struct platform_param {
	LIST_HEAD(pci_list, bkplane_pci) bp_list; /* backplane pci list */
	char *fal_plugin;		  /* fal_plugin to load (if any) */
	/* whether to use hardware LAG, or otherwise DPDK LAG */
	bool hardware_lag;
	/* management port pci list */
	LIST_HEAD(config_mgmt_pci_list, config_pci_entry) mgmt_list;
};

extern struct config_param config;
extern struct platform_param platform_cfg;

void set_config_file(const char *filename);
void set_platform_cfg_file(const char *filename);
const char *get_platform_cfg_file(void);
void parse_config(void);
void parse_driver_config(struct rxtx_param **driver_param,
			 const char *cfgfile);

/*
 * Are we running as VR or using uplink to a remote controller ?
 * Are controller and dataplane running on same machine ?
 * If so use TAP device (VR) rather than GRE to handle slow path.
 */
static inline bool is_local_controller(void)
{
	return config.local_controller;
}

static inline uint16_t dp_id_from_ifname(const char *if_name)
{
	return strtol(&if_name[2], NULL, 10);
}

uint32_t config_ctrl_ip_af(void);

/* Convert IP address string, result is the same as inet_pton() */
int parse_ipaddress(struct ip_addr *addr, const char *str);
char *addr_to_tcp(const struct ip_addr *addr, uint16_t port);

/* default ZMQ url creation */
char *default_endpoint_dataplane(void);

/* Parse platform configuration */
void parse_platform_config(const char *cfgfile);
/* Cleanup platform configuration */
void platform_config_cleanup(void);

#endif /* CONFIG_INTERNAL_H */
