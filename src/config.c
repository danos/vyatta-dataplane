/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/if.h>

#include <ini.h>
#include <rte_debug.h>
/* rte_eal_devargs_add is deprecated and its replacement is experimental */
#define ALLOW_EXPERIMENTAL_API 1
#include <rte_devargs.h>
#undef ALLOW_EXPERIMENTAL_API
#include <rte_ether.h>
#include <rte_log.h>

#include "config_internal.h"
#include "fal_plugin.h"
#include "main.h"
#include "util.h"
#include "vplane_debug.h"
#include "vplane_log.h"

static const char *config_file = VYATTA_SYSCONF_DIR"/dataplane.conf";
const char *platform_file = PLATFORM_FILE;

#define DEFAULT_CONTROLLER_REQ_PORT	4415
#define DEFAULT_CONTROLLER_REQ_IPC	"ipc:///var/run/vyatta/vplaned.req"

struct config_param config;
struct platform_param platform_cfg;

int parse_ipaddress(struct ip_addr *addr, const char *str)
{
	sa_family_t af;
	int rc;

	af = AF_INET;
	rc = inet_pton(af, str, &addr->address.ip_v4);
	if (rc == 0) {
		af = AF_INET6;
		rc = inet_pton(af, str, &addr->address.ip_v6);
	}
	addr->type = af;
	return rc;
}

static int parse_ipaddr(struct ip_addr *addr, const char *value)
{
	int rc = parse_ipaddress(addr, value);

	if (rc == 1)
		return 1;

	fprintf(stderr, "Invalid IP address: %s\n", value);
	return 0;
}

static int copy_str(char **str_ref, const char *value)
{
	free(*str_ref);
	*str_ref = strdup(value);
	return 1;
}

/* Use ethtool to find PCI bus info */
static int get_eth_pci_addr(const char *ifname, char *addr_str, size_t len)
{
	int ret, fd;
	struct ethtool_drvinfo info = {
		.cmd = ETHTOOL_GDRVINFO,
	};
	struct ifreq ifr = {
		.ifr_data = &info,
	};

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		rte_panic("can't open socket for ethtool\n");

	snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
	ret = ioctl(fd, SIOCETHTOOL, &ifr);
	close(fd);

	if (ret < 0)
		return -1;

	strncpy(addr_str, info.bus_info, len);
	return 0;
}


/* Take list of ethernet device names: "eth2,eth3"
 * and exclude each PCI address.
 *
 * Uses: strtok therefore overwrites argument
 */
static void parse_exclude(char *list)
{
	char *ifname;
	const char sep[] = " ,\t\r\n";

	for (ifname = strtok(list, sep); ifname != NULL;
	     ifname = strtok(NULL, sep)) {
		char addr_str[33];

		if (get_eth_pci_addr(ifname, addr_str, sizeof(addr_str)))
			continue;

		if (rte_devargs_add(RTE_DEVTYPE_BLOCKED,
					addr_str) < 0)
			/* can't use rte_log yet, EAL not started */
			fprintf(stderr,
				"Error: cannot exclude %s %s",
				ifname, addr_str);
	}
}

/*
 * parse_auth_method
 *
 * parse authentication method
 */
static void parse_auth_method(const char *method, struct config_param *cfg)
{
	/*
	 * Authentication is enabled when the method is elliptic-curve
	 */
	if (strcmp(method, "elliptic-curve") == 0)
		cfg->auth_enabled = true;
}

/*
 * Get the controller address family
 */
uint32_t config_ctrl_ip_af(void)
{
	return config.local_ip.type;
}

/*
 * Parse a cpumask in from a list of ranges. Example: "0,2-14".
 * Maximum number of supported CPUs is defined by CPU_SETSIZE (1024),
 * limited by CPU_SET(3).
 */
static void parse_cpumask(cpu_set_t *cpumask, const char *value, const char *key)
{
	int rc;
	char *cpurange;
	static const char sep[] = " ,\t\r\n";
	int start, end;

	CPU_ZERO(cpumask);

	for (cpurange = strtok((char *) value, sep); cpurange != NULL;
	     cpurange = strtok(NULL, sep)) {

		rc = sscanf(cpurange, "%d-%d", &start, &end);
		if (start >= CPU_SETSIZE || end >= CPU_SETSIZE) {
			fprintf(stderr,
				"Error: parsing %s: %s. Maximum of supported CPUs (%u) exceeded\n",
				key, cpurange, CPU_SETSIZE);
			CPU_ZERO(cpumask);
			return;
		}
		if (rc == 2) {
			for (int i = start; i <= end; i++)
				CPU_SET(i, cpumask);

			continue;
		}

		rc = sscanf(cpurange, "%d", &start);
		if (rc != 1) {
			fprintf(stderr, "Error: parsing %s: %s\n", key,
				cpurange);
			return;
		}

		CPU_SET(start, cpumask);
	}

}

/* Callback from inih library for each name value
 * return 0 = error, 1 = ok
 */
static int parse_entry(void *user, const char *section,
		       const char *name, const char *value)
{
	struct config_param *cfg = user;

	if (strcasecmp(section, "authentication") == 0) {
		if (strcmp(name, "method") == 0)
			parse_auth_method(value, cfg);
	} else if (strcasecmp(section, "controller") == 0) {
		if (strcmp(name, "publish") == 0)
			return copy_str(&cfg->publish_url, value);
		if (strcmp(name, "request") == 0)
			return copy_str(&cfg->request_url, value);
		if (strcmp(name, "publish_uplink") == 0)
			return copy_str(&cfg->publish_url_uplink, value);
		if (strcmp(name, "request_uplink") == 0)
			return copy_str(&cfg->request_url_uplink, value);
		if (strcmp(name, "ip") == 0)
			return parse_ipaddr(&cfg->remote_ip, value);
		if (strcmp(name, "certificate") == 0)
			return copy_str(&cfg->remote_cert, value);
	} else if (strcasecmp(section, "dataplane") == 0) {
		if (strcmp(name, "ip") == 0)
			return parse_ipaddr(&cfg->local_ip, value);
		if (strcmp(name, "certificate") == 0)
			return copy_str(&cfg->certificate, value);
		if (strcmp(name, "control") == 0) {
			cfg->console_url_set = true;
			return copy_str(&cfg->console_url, value);
		}
		if (strcmp(name, "control-uplink") == 0)
			return copy_str(&cfg->console_url_uplink, value);
		if (strcmp(name, "control-interface") == 0)
			return copy_str(&cfg->ctrl_intf_name, value);
		if (strcmp(name, "exclude-interfaces") == 0 ||
			 strcmp(name, "blacklist") == 0)
			parse_exclude(strdupa(value));
		else if (strcmp(name, "backplane") == 0)
			cfg->backplane = strdup(value);
		else if (strcmp(name, "update") == 0)
			cfg->port_update = atoi(value);
		else if (strcmp(name, "uuid") == 0)
			return copy_str(&cfg->uuid, value);
		else  if (strcmp(name, "dataplane-id") == 0)
			cfg->dp_index = atoi(value);
		else if (strcmp(name, "uplink-mac") == 0)
			return ether_aton_r(value, &cfg->uplink_addr) != NULL;
		else if (strcmp(name, "control_cpumask") == 0)
			parse_cpumask(&cfg->control_cpumask, value, name);
	} else if (strcasecmp(section, "rib") == 0) {
		if (strcmp(name, "ip") == 0)
			return parse_ipaddr(&cfg->rib_ip, value);
		if (strcmp(name, "control") == 0)
			return copy_str(&cfg->rib_ctrl_url, value);
	} else if (strcasecmp(section, "xfrm_client") == 0) {
		if (strcmp(name, "pull") == 0)
			return copy_str(&cfg->xfrm_pull_url, value);
		if (strcmp(name, "push") == 0)
			return copy_str(&cfg->xfrm_push_url, value);
	} else if (strcasecmp(section, "sfpd_update") == 0) {
		if (strcmp(name, "file") == 0)
			return copy_str(&cfg->sfpd_status_file, value);
		if (strcmp(name, "url") == 0)
			return copy_str(&cfg->sfpd_status_upd_url, value);
	}

	return 1; /* good */
}

/* convert from generic IP address to ZMQ bind URL */
char *addr_to_tcp(const struct ip_addr *addr, uint16_t port)
{
	char abuf[INET6_ADDRSTRLEN];
	char pbuf[32];
	char *ep = NULL;
	int ret;

	inet_ntop(addr->type, &addr->address,
		  abuf, sizeof(abuf));

	if (port == 0)
		strcpy(pbuf, "*");
	else
		snprintf(pbuf, sizeof(pbuf), "%u", port);

	if (addr->type == AF_INET6)
		ret = asprintf(&ep, "tcp://[%s]:%s", abuf, pbuf);
	else
		ret = asprintf(&ep, "tcp://%s:%s", abuf, pbuf);

	return (ret < 0) ? NULL : ep;
}

static char *default_endpoint_controller(void)
{
	if (config.local_controller)
		return strdup(DEFAULT_CONTROLLER_REQ_IPC);

	return addr_to_tcp(&config.remote_ip,
			   DEFAULT_CONTROLLER_REQ_PORT);

}

static char *default_endpoint_controller_uplink(void)
{
	return strdup(DEFAULT_CONTROLLER_REQ_IPC);
}

char *default_endpoint_dataplane(void)
{
	if (config.local_controller)
		return strdup("ipc://*");

	return addr_to_tcp(&config.local_ip, 0);
}

static char *default_endpoint_dataplane_uplink(void)
{
	return strdup("ipc://*");
}

void set_config_file(const char *filename)
{
	config_file = filename;
}

void set_platform_cfg_file(const char *filename)
{
	platform_file = filename;
}

const char *get_platform_cfg_file(void)
{
	return platform_file;
}

/* Load config file and do sanity checks */
void parse_config(void)
{
	FILE *f = fopen(config_file, "r");

	if (f == NULL) {
		perror(config_file);
		exit(EXIT_FAILURE);
	}

	/* non-zero default values */
	config.port_update = PORTCHECK_INTERVAL;

	int rc = ini_parse_file(f, parse_entry, &config);

	if (rc) {
		fprintf(stderr, "Config file format error %s line %d\n",
			config_file, rc);
		exit(EXIT_FAILURE);
	}

	fclose(f);

	config.local_controller = (config.dp_index == 0);

	if (!is_addr_set(&config.remote_ip)) {
		fprintf(stderr, "Controller IP not configured\n");
		exit(EXIT_FAILURE);
	}

	if (config.local_controller) {
		if (!is_addr_set(&config.local_ip)) {
			fprintf(stderr, "Dataplane IP not configured\n");
			exit(EXIT_FAILURE);
		}
		if (config.remote_ip.type != config.local_ip.type) {
			fprintf(stderr, "IP address family mismatch\n");
			exit(EXIT_FAILURE);
		}
		if (config.ctrl_intf_name != NULL) {
			fprintf(stderr, "Dynamic address on %s not supported\n",
				config.ctrl_intf_name);
			exit(EXIT_FAILURE);
		}
		if (config.console_url == NULL) {
			config.console_url = default_endpoint_dataplane();
			if (config.console_url == NULL) {
				fprintf(stderr,
					"Fail allocate default console URL\n");
				exit(EXIT_FAILURE);
			}
		}
	} else {
		if (is_addr_set(&config.local_ip)) {
			fprintf(stderr, "Dataplane IP deprecated\n");
			exit(EXIT_FAILURE);
		}
		if (rte_is_zero_ether_addr(&config.uplink_addr)) {
			fprintf(stderr, "Uplink Mac address not configured\n");
			exit(EXIT_FAILURE);
		}
		if (config.console_url_uplink == NULL) {
			config.console_url_uplink =
				default_endpoint_dataplane_uplink();
			if (config.console_url_uplink == NULL) {
				fprintf(stderr,
				   "Fail allocate default uplink console URL\n");
				exit(EXIT_FAILURE);
			}
		}
		if (config.request_url_uplink == NULL) {
			config.request_url_uplink =
				default_endpoint_controller_uplink();
			if (config.request_url_uplink == NULL) {
				fprintf(stderr,
				   "Failed allocate default uplink request URL\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	if (config.uuid == NULL) {
		config.uuid = strdup(DEFAULT_UUID);
		if (config.uuid == NULL) {
			fprintf(stderr, "Fail allocate default uuid\n");
			exit(EXIT_FAILURE);
		}
	}
	if (config.request_url == NULL) {
		config.request_url = default_endpoint_controller();
		if (config.request_url == NULL) {
			fprintf(stderr,
				"Failed to allocate default request URL\n");
				exit(EXIT_FAILURE);
		}
	}
}

struct str_val {
	const char *str;
	uint64_t   value;
};

struct str_val rx_offload_strs[] = {
	{ "keep_crc", DEV_RX_OFFLOAD_KEEP_CRC },
};

#define MAX_RX_OFFLOAD_STRS (sizeof(rx_offload_strs) / \
						sizeof(rx_offload_strs[0]))

struct str_val tx_offload_strs[] = {
	{ "dev_tx_offload_multi_segs", DEV_TX_OFFLOAD_MULTI_SEGS },
	{ "dev_tx_offload_vlan_insert", DEV_TX_OFFLOAD_VLAN_INSERT },
};

#define MAX_TX_OFFLOAD_STRS (sizeof(tx_offload_strs) / \
						sizeof(tx_offload_strs[0]))

struct str_val dev_flags_strs[] = {
	{ "rte_eth_dev_intr_lsc", RTE_ETH_DEV_INTR_LSC },
};

#define MAX_DEV_FLAGS_STRS (sizeof(dev_flags_strs) / \
						sizeof(dev_flags_strs[0]))

static void parse_option_strs(char *value,
			      struct str_val *option_strs,
			      uint8_t max_option_strs,
			      uint64_t *option_flags,
			      uint64_t *neg_option_flags)
{
	const char sep[] = " ,\t\r\n";
	const char *option_str;

	for (option_str = strtok(value, sep); option_str != NULL;
	     option_str = strtok(NULL, sep)) {
		bool is_negation = false;

		if (option_str[0] == '!') {
			is_negation = true;
			option_str++;
		}

		for (uint8_t i = 0; i < max_option_strs; i++) {
			if (strcmp(option_str, option_strs[i].str) == 0) {
				if (is_negation)
					*neg_option_flags |=
						option_strs[i].value;
				else
					*option_flags |=
						option_strs[i].value;
			}
		}
	}
}

struct str_val rx_mq_mode_strs[] = {
	{ "eth_mq_rx_none", ETH_MQ_RX_NONE },
	{ "eth_mq_rx_rss", ETH_MQ_RX_RSS },
};

#define MAX_RX_MQ_MODE_STRS (sizeof(rx_mq_mode_strs) / \
						sizeof(rx_mq_mode_strs[0]))

static void parse_enum_str(char *value,
			   struct str_val *enum_strs,
			   uint8_t max_enum_strs,
			   uint64_t *enum_flag)
{
	for (uint8_t i = 0; i < max_enum_strs; i++) {
		if (strcmp(value, enum_strs[i].str) == 0)
			*enum_flag = enum_strs[i].value;
	}
}

/*
 * Callback from inih library for each name value
 * return 0 = error, 1 = ok
 */
static int parse_driver_entry(void *user, const char *section,
			      const char *name, const char *value)
{
	unsigned long int val;
	char *end;
	struct rxtx_param **param_p = user;
	struct rxtx_param *param = *param_p;
	bool found = false;
	int count = 0; /* Count of existing entries */
	int required = 0;

	/* Find entry in table, add new one if required */
	while (param && param->match) {
		if (strcasestr(section, param->match)) {
			found = true;
			break;
		}
		param++;
		count++;
	}

	if (!found) {
		/*
		 * Create an array of the correct size, leaving a null
		 * entry on the end to terminate the loop.
		 */
		required = count + 2;

		param = calloc(required, sizeof(*param));
		if (!param)
			rte_panic("Could not allocate driver param table");

		if (*param_p) {
			memcpy(param, *param_p, count * sizeof(*param));
			free(*param_p);
		}
		*param_p = param;
		param = &param[count];
		param->match = strdup(section);
		if (!param->match)
			rte_panic("Could not allocate driver name in table");
	}

	/* Param now points to the correct entry in the array */

	if (strcmp(name, "max_rxq") == 0) {
		val = strtoul(value, &end, 10);
		/* make sure val is sane */
		if (val <= MAX_RX_QUEUE_PER_PORT) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting max rxQ for %s, %lu\n",
				 section, val);
			param->max_rxq = val;
		}
	}
	if (strcmp(name, "max_txq") == 0) {
		val = strtoul(value, &end, 10);
		/* make sure val is sane */
		if (val <= MAX_TX_QUEUE_PER_PORT) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting max txQ for %s, %lu\n",
				 section, val);
			param->max_txq = val;
		}
	}

	if (strcmp(name, "rx_desc") == 0) {
		val = strtoul(value, &end, 10);
		/* make sure val is sane */
		if (val <= MAX_RX_DESC_PER_QUEUE) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting RX bufs for %s, %lu\n",
				 section, val);
			param->rx_desc = val;
		}
	}
	if (strcmp(name, "tx_desc") == 0) {
		val = strtoul(value, &end, 10);
		/* make sure val is sane */
		if (val <= MAX_TX_DESC_PER_QUEUE) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting TX bufs for %s, %lu\n",
				 section, val);
			param->tx_desc = val;
		}
	}
	if (strcmp(name, "extra") == 0) {
		val = strtoul(value, &end, 10);
		/* make sure val is sane */
		if (val <= MAX_RX_DESC_PER_QUEUE) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting extra rx for %s, %lu\n",
				 section, val);
			param->extra = val;
		}
	}
	if (strcmp(name, "limit-txq") == 0) {
		if (strcmp(value, "yes") == 0) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting limit-txq for %s\n",
				 section);
			param->drv_flags |= DRV_PARAM_LIMITTXQ;
		}
	}
	if (strcmp(name, "virtual") == 0) {
		if (strcmp(value, "yes") == 0) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting virtual for %s\n",
				 section);
			param->drv_flags |= DRV_PARAM_VIRTUAL;
		}
	}
	if (strcmp(name, "disable_direct") == 0) {
		if (strcmp(value, "yes") == 0) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting disable_direct for %s\n",
				 section);
			param->drv_flags |= DRV_PARAM_NO_DIRECT;
		}
	}
	if (strcmp(name, "tx_pkt_ring_size") == 0) {
		val = strtoul(value, &end, 10);
		/* make sure val is sane */
		if (val <= MAX_TX_DESC_PER_QUEUE) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting TX queue pkt ring size for %s, %lu\n",
				 section, val);
			param->tx_pkt_ring_size = val;
		}
	}
	if (strcmp(name, "use_all_rxq") == 0) {
		if (strcmp(value, "yes") == 0) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting use_all_rxq for %s\n",
				 section);
			param->drv_flags |= DRV_PARAM_USE_ALL_RXQ;
		}
	}
	if (strcmp(name, "use_all_txq") == 0) {
		if (strcmp(value, "yes") == 0) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting use_all_txq for %s\n",
				 section);
			param->drv_flags |= DRV_PARAM_USE_ALL_TXQ;
		}
	}
	if (strcmp(name, "rx_offloads") == 0) {
		parse_option_strs(strdupa(value), rx_offload_strs,
				  MAX_RX_OFFLOAD_STRS,
				  &param->rx_offloads,
				  &param->neg_rx_offloads);
		DP_DEBUG(INIT, INFO, DATAPLANE,
			 "Set rx offloads for %s, 0x%lx, !0x%lx\n",
			 section, param->rx_offloads, param->neg_rx_offloads);
	}
	if (strcmp(name, "tx_offloads") == 0) {
		parse_option_strs(strdupa(value), tx_offload_strs,
				  MAX_TX_OFFLOAD_STRS,
				  &param->tx_offloads,
				  &param->neg_tx_offloads);
		DP_DEBUG(INIT, INFO, DATAPLANE,
			 "Set tx offloads for %s, 0x%lx, !0x%lx\n",
			 section, param->tx_offloads, param->neg_tx_offloads);
	}
	if (strcmp(name, "rx_mq_mode") == 0) {
		param->rx_mq_mode_set = true;
		parse_enum_str(strdupa(value), rx_mq_mode_strs,
			       MAX_RX_MQ_MODE_STRS,
			       &param->rx_mq_mode);
		DP_DEBUG(INIT, INFO, DATAPLANE,
			 "Set rx mq_mode for %s, 0x%lx\n",
			 section, param->rx_mq_mode);
	}
	if (strcmp(name, "tx_desc_vm_multiplier") == 0) {
		val = strtoul(value, &end, 10);
		/* make sure val is sane */
		if (val <= MAX_TX_DESC_VM_MULTIPLIER) {
			DP_DEBUG(INIT, INFO, DATAPLANE,
				 "Setting TX bufs vm multiplier for %s, %lu\n",
				 section, val);
			param->tx_desc_vm_multiplier = val;
                }
        }
	if (strcmp(name, "dev_flags") == 0) {
		parse_option_strs(strdupa(value), dev_flags_strs,
				  MAX_DEV_FLAGS_STRS,
				  &param->dev_flags,
				  &param->neg_dev_flags);
		DP_DEBUG(INIT, INFO, DATAPLANE,
			 "Set dev flags for %s, 0x%lx, !0x%lx\n",
			 section, param->dev_flags, param->neg_dev_flags);
	}

	return 1; /* good */
}

/*
 * Parse the config for the drivers.
 */
void parse_driver_config(struct rxtx_param **driver_param,
			 const char *cfgfile)
{
	FILE *f = fopen(cfgfile, "r");
	int rc;

	if (f == NULL)
		rte_panic("Could not open driver config file: %s (%s)",
			  cfgfile, strerror(errno));

	DP_DEBUG(INIT, INFO, DATAPLANE,
		 "Parsing driver config file %s\n", cfgfile);

	rc = ini_parse_file(f, parse_driver_entry, driver_param);
	if (rc)
		fprintf(stderr, "Config file format error %s line %d\n",
			cfgfile, rc);

	fclose(f);
}

static void backplane_list_destroy(void)
{
	struct bkplane_pci *bp;

	while ((bp = LIST_FIRST(&platform_cfg.bp_list))) {
		LIST_REMOVE(bp, link);
		free(bp);
	}
}

static bool parse_pci_addr(const char *value, struct rte_pci_addr *pci_addr)
{
	int rc;

	/* Check long PCI format */
	rc = sscanf(value, "%x:%hhx:%hhx.%hhu", &pci_addr->domain,
		    &pci_addr->bus, &pci_addr->devid,
		    &pci_addr->function);
	if (rc == 4)
		return true;

	pci_addr->domain = 0;

	/* Check short PCI format */
	rc = sscanf(value, "%hhx:%hhx.%hhu", &pci_addr->bus,
		    &pci_addr->devid, &pci_addr->function);
	if (rc == 3)
		return true;

	return false;
}

/*
 * Callback from inih library for each name value
 * return 0 = error, 1 = ok
 */
static int parse_platform_entry(void *user, const char *section,
				const char *name, const char *value)
{
	struct platform_param *cfg = user;

	if (strcasecmp(section, "dataplane") == 0) {
		if (strncmp(name, "backplane_port",
			     strlen("backplane_port")) == 0) {
			struct bkplane_pci *bp;
			char *pci_addr_str;
			char *bp_name;

			bp = calloc(1, sizeof(*bp));
			if (!bp)
				goto malloc_failed;
			pci_addr_str = strdup(value);
			if (!pci_addr_str) {
				free(bp);
				goto malloc_failed;
			}

			bp_name = strchr(pci_addr_str, ',');
			if (bp_name) {
				/*
				 * nul-terminate PCI address and skip
				 * over comma separator
				 */
				*bp_name = '\0';
				bp_name++;
			}

			if (!parse_pci_addr(pci_addr_str, &bp->pci_addr)) {
				DP_DEBUG(INIT, ERR, DATAPLANE,
					 "backplane port format error\n");
				free(pci_addr_str);
				free(bp);
				return 0;
			}

			/* Add to backplane port list */
			fprintf(stderr,
				"Backplane %s pci(%x:%hhx:%hhx.%hhu) added\n",
				bp_name ? bp_name : "()",
				bp->pci_addr.domain,
				bp->pci_addr.bus,
				bp->pci_addr.devid,
				bp->pci_addr.function);
			if (bp_name)
				bp->name = strdup(bp_name);
			LIST_INSERT_HEAD(&cfg->bp_list, bp, link);
			free(pci_addr_str);
		} else if (strcmp(name, "fal_plugin") == 0) {
			if (value)
				cfg->fal_plugin = strdup(value);
		} else if (strncmp(name, "mgmt_port",
				   strlen("mgmt_port")) == 0) {
			struct config_pci_entry *pci_entry;

			pci_entry = calloc(1, sizeof(*pci_entry));
			if (!pci_entry)
				goto malloc_failed;

			if (!parse_pci_addr(value, &pci_entry->pci_addr)) {
				DP_DEBUG(INIT, ERR, DATAPLANE,
					 "management port format error: %s\n",
					 value);
				free(pci_entry);
				return 0;
			}
			LIST_INSERT_HEAD(&cfg->mgmt_list, pci_entry, link);
		}
	} else if (strcasecmp(section, "hardware-features") == 0) {
		if (strcmp(name, "bonding.hardware-members-only") == 0) {
			if (value)
				cfg->hardware_lag = atoi(value);
		}
	}
	return 1;

malloc_failed:
	fprintf(stderr,
		"Out of memory during processing of %s:%s config\n",
		section, name);
	return 0;

}

/*
 * Parse platform configuration file
 * Backplane port identified by pci address.
 * Format :
 * [Dataplane]
 * backplane_port<num> = domain:bus:devid.function
 * backplane_port<num> = domain:bus:devid.function
 * fal_plugin = /path/to/shared/library.so
 */
void parse_platform_config(const char *cfgfile)
{
	FILE *f;
	int rc;

	if (!cfgfile)
		return;

	f = fopen(cfgfile, "r");
	if (f == NULL)
		return;
	fprintf(stderr, "Parsing platform config file %s\n",
		cfgfile);
	LIST_INIT(&platform_cfg.bp_list);
	LIST_INIT(&platform_cfg.mgmt_list);

	rc = ini_parse_file(f, parse_platform_entry, &platform_cfg);
	if (rc) {
		fprintf(stderr, "Platform config file %s format error %d\n",
			cfgfile, rc);
		/* Clear any parsed information if file format error */
		platform_config_cleanup();
	}
	fclose(f);
}

void platform_config_cleanup(void)
{
	/* Destroy Backplane interface */
	backplane_list_destroy();

	free(platform_cfg.fal_plugin);
}

int dp_parse_config_files(dp_parse_config_fn *parser_fn,
			  void *arg)
{
	FILE *f;
	int rc;

	/* The main config file must exist */
	f  = fopen(config_file, "r");
	if (f == NULL)
		return -ENOENT;

	rc = ini_parse_file(f, parser_fn, arg);
	fclose(f);
	if (rc)
		return rc;

	/* The platform config file may exist */
	f  = fopen(platform_file, "r");
	if (!f)
		return 0;

	rc = ini_parse_file(f, parser_fn, arg);
	fclose(f);

	return rc;
}
