/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "backplane.h"
#include "if_var.h"
#include "json_writer.h"
#include "lag.h"
#include "util.h"
#include "vplane_log.h"

#ifndef SYSFS_PCI_DEVICES
#define SYSFS_PCI_DEVICES "/sys/bus/pci/devices"
#endif

static bool firmware_is_broken;

/* Read sysfs numeric file attribute */
static bool get_attr(const char *dir, const char *name, unsigned int *val)
{
	FILE *f;
	char path[PATH_MAX];
	char *sval;

	snprintf(path, PATH_MAX, "%s/%s", dir, name);
	f = fopen(path, "r");
	if (!f)
		return false;

	int n = fscanf(f, "%ms", &sval);
	fclose(f);
	if (n == 1) {
		*val = strtoul(sval, NULL, 0);
		free(sval);
	}

	return (n == 1);
}

/* Look for firmware index:
 * ACPI _DSM instance number
 * SMIBIOS type 41 device type
 */
static int __get_firmware_index(const char *dir)
{
	unsigned int index;

	if (get_attr(dir, "acpi_index", &index) ||
	    get_attr(dir, "index", &index))
		return index;

	return -1;
}

static int get_firmware_index(const struct rte_pci_addr *loc)
{
	char devdir[PATH_MAX];

	/* /sys/bus/pci/devices/AAAA:BB:CC.D */
	snprintf(devdir, PATH_MAX,
		 SYSFS_PCI_DEVICES "/" PCI_PRI_FMT,
		 loc->domain, loc->bus, loc->devid, loc->function);

	return __get_firmware_index(devdir);
}

/* Parse the sysfs PCI hotplug directory looking for a device
 * with matching PCI address
 */
static int get_hotplug_slot(const struct rte_pci_addr *loc)
{
	DIR *d;
	struct dirent *ent;
	int slot = -1;

	d = opendir("/sys/bus/pci/slots");
	if (!d) {
		RTE_LOG(INFO, DATAPLANE,
			"PCI hotplug not supported on this platform\n");
		return -1;
	}

	while ((ent = readdir(d)) != NULL) {
		if (*ent->d_name == '.')
			continue;

		char *endp;
		int i = strtol(ent->d_name, &endp, 10);
		if (i < 1)
			continue;

		char dir[PATH_MAX];
		snprintf(dir, sizeof(dir),
			 "/sys/bus/pci/slots/%s/address", ent->d_name);

		FILE *f = fopen(dir, "r");
		if (!f) {
			RTE_LOG(NOTICE, DATAPLANE,
				"Can not open %s: %s\n", dir,
				strerror(errno));
			continue;
		}

		char buf[64];
		if (fgets(buf, sizeof(buf), f) == NULL) {
			RTE_LOG(NOTICE, DATAPLANE,
				"Could not read %s: %s\n", dir, strerror(errno));
			fclose(f);
			break;
		}
		fclose(f);

		struct rte_pci_addr pci;
		/* pci.domain can be 2/4 bytes depending on the DPDK version */
		uint32_t domain;
		if (sscanf(buf, "%x:%hhx:%hhx",
			   &domain, &pci.bus, &pci.devid) == 3 &&
		    domain == loc->domain &&
		    pci.bus == loc->bus &&
		    pci.devid == loc->devid) {
			slot = i;
			break;
		}
	}
	closedir(d);
	return slot;
}

/*
 * Determine if device has multiple functions
 *
 * PCI Config Header Type:
 *   0x00 specifies a general device
 *   0x01 specifies a PCI-to-PCI bridge
 *   0x02 specifies a CardBus bridge
 *
 *   bit 7 of this register is set, the device has multiple functions
 */
static bool is_multifunction(const struct rte_pci_addr *loc)
{
	FILE *f;
	char filename[PATH_MAX];
	uint8_t pci_cfg[64];

	snprintf(filename, PATH_MAX,
		 SYSFS_PCI_DEVICES "/" PCI_PRI_FMT "/config",
		 loc->domain, loc->bus, loc->devid, loc->function);

	f = fopen(filename, "r");
	if (f == NULL)
		return 0;

	if (fread(&pci_cfg, sizeof(pci_cfg), 1, f) != 1) {
		fclose(f);
		return false;
	}
	fclose(f);

	return (pci_cfg[0x0e] & 0x80) != 0;
}

/* dev_port is new in Linux 4.x and only used in
 * multi-port devices that share same PCI address
 * so far this only matters for Mellanox.
 *
 * return 0 on failure
 */
static unsigned int get_dev_port(const struct rte_pci_addr *loc)
{
	char dirname[PATH_MAX];
	unsigned int dev_port;

	snprintf(dirname, PATH_MAX,
		 SYSFS_PCI_DEVICES "/" PCI_PRI_FMT "/dev_port",
		 loc->domain, loc->bus, loc->devid, loc->function);

	if (!get_attr(dirname, "dev_port", &dev_port))
		return 0;

	return dev_port;
}

/* The cxgbe PMD encodes the port in the name
 * of the instance.
 */

static unsigned int get_dev_port_cxgbe(int portid)
{
	const struct rte_eth_dev *dev = &rte_eth_devices[portid];
	char *p;
	int dev_port = 0;

	p = strchr(dev->data->name, '_');
	if (p)
		dev_port = atoi(++p);

	return dev_port;
}

#define PCI_BASE_CLASS_NETWORK 0x02

static bool is_ethernet_device(const char *path)
{
	unsigned int class;

	if (get_attr(path, "class", &class) &&
	    (class >> 16 == PCI_BASE_CLASS_NETWORK))
		return true;

	return false;
}

#ifndef SYSFS_VMBUS_DEVICES
#define SYSFS_VMBUS_DEVICES "/sys/bus/vmbus/devices"
#endif

static unsigned int get_vmbus_id(const char *name)
{
	char dirname[PATH_MAX];
	unsigned int id, sysfs_num;

	/* new PMD name: 7a08391f-f5a0-4ac0-9802-d13fd964f8df */
	snprintf(dirname, PATH_MAX, SYSFS_VMBUS_DEVICES "/%s", name);
	if (get_attr(dirname, "id", &id))
		return id;

	/* older PMD name: 15_1 */
	if (sscanf(name, "%u_%u", &id, &sysfs_num) != 2)
		return -1;
	snprintf(dirname, PATH_MAX, SYSFS_VMBUS_DEVICES "/vmbus_%u",
		 sysfs_num);
	if (get_attr(dirname, "id", &id))
		return id;
	/* try again with even-older VMBUS device name format */
	snprintf(dirname, PATH_MAX, SYSFS_VMBUS_DEVICES "/vmbus_0_%u",
		 sysfs_num);
	if (get_attr(dirname, "id", &id))
		return id;

	return -1;
}

/* Format up a JSON desription of the device
 * which is used by controller to assign name
 */
static void json_bus_info(json_writer_t *wr, portid_t portid,
			  const char *backplane_name)
{
	struct rte_eth_dev_info dev_info;

	rte_eth_dev_info_get(portid, &dev_info);
	if (dev_info.driver_name) {
		jsonw_string_field(wr, "driver", dev_info.driver_name);

		if (strcasestr(dev_info.driver_name, "net_netvsc") != NULL) {
			const struct rte_eth_dev *dev =
				&rte_eth_devices[portid];
			jsonw_uint_field(wr, "slot",
					 get_vmbus_id(dev->data->name));
			return;
		}

		if (strcmp(dev_info.driver_name, "net_xen_netfront") == 0) {
			const struct rte_eth_dev *dev =
				&rte_eth_devices[portid];
			unsigned int devid;
			char buf[PATH_MAX];

			/*
			 * Although the new Xen PMD is no longer using a fake
			 * PCI device the controller expects the device to
			 * have a PCI address. Lets continue what the old Xen
			 * PMD did and place the devid into the busid field.
			 */
			if (sscanf(dev->data->name, "vif-%u", &devid) == 1) {
				snprintf(buf, PATH_MAX, PCI_PRI_FMT,
					 0, 0, devid, 0);
				jsonw_string_field(wr, "pci-address", buf);
				jsonw_uint_field(wr, "slot", devid);
			}

			return;
		}

		if (backplane_name)
			/*
			 * Don't send bus info if we have a name as that will
			 * Cause controller to ignore the name.
			 */
			return;
	}

	const struct rte_bus *bus = rte_bus_find_by_device(dev_info.device);
	struct rte_pci_device *pci = NULL;
	if (bus && streq(bus->name, "pci"))
		pci = RTE_DEV_TO_PCI(dev_info.device);
	if (pci) {
		const struct rte_pci_addr *loc = &pci->addr;
		char buf[PATH_MAX];

		snprintf(buf, PATH_MAX, PCI_PRI_FMT,
			 loc->domain, loc->bus, loc->devid, loc->function);
		jsonw_string_field(wr, "pci-address", buf);

		const struct rte_pci_id *id = &pci->id;
		snprintf(buf, PATH_MAX,
			 "%.4" PRIx16 ":%.4" PRIx16 ":%.4" PRIx16 ":%.4" PRIx16,
			 id->vendor_id, id->device_id,
			 id->subsystem_vendor_id, id->subsystem_device_id);
		jsonw_string_field(wr, "pci-id", buf);

		int index = get_firmware_index(loc);
		if (index > 0 && !firmware_is_broken)
			jsonw_uint_field(wr, "firmware", (unsigned int)index);

		int slot = get_hotplug_slot(loc);
		if (slot >= 0)
			jsonw_uint_field(wr, "slot", (unsigned int)slot);

		int dev_port = get_dev_port(loc);

		if (dev_info.driver_name &&
		    strcasestr(dev_info.driver_name, "net_cxgbe") != NULL)
			dev_port = get_dev_port_cxgbe(portid);

		if (dev_port > 0)
			jsonw_uint_field(wr, "dev-port", (unsigned int)dev_port);

		jsonw_bool_field(wr, "multifunction", is_multifunction(loc));
	}
}

void check_broken_firmware(void)
{
	DIR *devs;
	struct dirent *entry;
	int i, maxdevs = 16, ndevs = 0;
	int *dev_index;

	dev_index = malloc(sizeof(int) * maxdevs);
	if (!dev_index)
		return;

	devs = opendir(SYSFS_PCI_DEVICES);
	if (!devs)
		goto out;

	while ((entry = readdir(devs))) {
		char *dev_path;
		int index;

		if (entry->d_name[0] == '.')
			continue;

		if (asprintf(&dev_path, "%s/%s",
			     SYSFS_PCI_DEVICES, entry->d_name) < 0)
			goto out;
		if (is_ethernet_device(dev_path)) {
			index = __get_firmware_index(dev_path);

			if (index == -1)
				continue;

			for (i = 0; i < ndevs; i++) {
				if (index == dev_index[i]) {
					firmware_is_broken = true;
					free(dev_path);
					goto out;
				}
			}

			dev_index[ndevs++] = index;
			if (ndevs == maxdevs) {
				int *old_dev_index = dev_index;
				maxdevs = maxdevs * 2;
				dev_index = realloc(dev_index,
						    maxdevs * sizeof(int));
				if (!dev_index) {
					free(dev_path);
					free(old_dev_index);
					goto out;
				}
			}
		}
		free(dev_path);
	}

out:
	if (firmware_is_broken)
		RTE_LOG(INFO, DATAPLANE,
			"Some devices have duplicate BIOS indexes!\n");

	free(dev_index);
	if (devs)
		closedir(devs);
}

/* Provide JSON string describing all info about a DPDK port. */
char *if_port_info(const struct ifnet *ifp)
{
	struct rte_eth_dev_info dev_info;
	char name[IFNAMSIZ];
	portid_t port_id = ifp->if_port;
	char *outbuf = NULL;
	size_t outsize = 0;
	struct rte_eth_dev *eth_dev;
	unsigned int if_flags = 0;
	unsigned int mtu = 0;
	char dev_name[RTE_ETH_NAME_MAX_LEN];
	int switch_id;
	char *backplane_name = NULL;

	/* Stdio FILE stream -> memory */
	FILE *f = open_memstream(&outbuf, &outsize);
	if (f == NULL)
		return NULL;

	json_writer_t *wr = jsonw_new(f);
	if (!wr) {
		fclose(f);
		free(outbuf);
		return NULL;
	}

	const char *hypervisor = hypervisor_id();
	if (hypervisor)
		jsonw_string_field(wr, "hypervisor", hypervisor);

	jsonw_uint_field(wr, "port", port_id);

	char ebuf[32];
	jsonw_string_field(wr, "mac", ether_ntoa_r(&ifp->perm_addr, ebuf));

	/* Shouldn't be looking inside DPDK but there is no documented
	 * way to get DPDK name which is used by bond driver.
	 */
	eth_dev = &rte_eth_devices[port_id];
	rte_eth_dev_info_get(port_id, &dev_info);

	if (strcasestr(dev_info.driver_name, "af_packet") &&
	    if_indextoname(dev_info.if_index, name) != NULL) {
		struct ifreq ifr;
		int fd;

		name[IFNAMSIZ - 1] = '\0';
		jsonw_string_field(wr, "name", name);

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd >= 0) {
			memset(&ifr, 0, sizeof(ifr));
			snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
			if (ioctl(fd, SIOCGIFFLAGS, &ifr) == 0) {
				if (ifr.ifr_flags & IFF_POINTOPOINT)
					if_flags |= IFF_POINTOPOINT;
				if (ifr.ifr_flags & IFF_NOARP)
					if_flags |= IFF_NOARP;
			}
			close(fd);
		}
	} else if (!strncmp(eth_dev->data->name, "eth_vhost", 9))
		/* send name as "vhost1" with "eth_" to controller */
		jsonw_string_field(wr, "name", eth_dev->data->name + 4);
	else if (get_switch_dev_info(dev_info.driver_name, eth_dev->data->name,
				     &switch_id, dev_name))
		jsonw_string_field(wr, "name", dev_name);
	else if (!strncmp(eth_dev->data->name,
					  dev_info.driver_name,
					  strlen(dev_info.driver_name)))
		/* strip off the driver prefix for controller */
		jsonw_string_field(wr, "name", eth_dev->data->name +
				strlen(dev_info.driver_name));
	else if (backplane_port_get_name(port_id, &backplane_name) == 0)
		jsonw_string_field(wr, "name", backplane_name);
	else
		jsonw_string_field(wr, "name", eth_dev->data->name);

	/* Backplane ports should be admin UP by default and
	 * configured to the largest possible MTU.
	 */
	if (if_port_is_bkplane(port_id)) {
		if_flags |= IFF_UP;
		/* max_rx_pktlen is the frame size */
		mtu = dev_info.max_rx_pktlen -
		      RTE_ETHER_HDR_LEN -
		      RTE_ETHER_CRC_LEN;
	}

	json_bus_info(wr, port_id, backplane_name);
	jsonw_bool_field(wr, "uplink", if_port_is_uplink(port_id));
	jsonw_bool_field(wr, "backplane", if_port_is_bkplane(port_id));
	if (if_flags)
		jsonw_uint_field(wr, "if_flags", if_flags);
	if (mtu)
		jsonw_uint_field(wr, "mtu", mtu);

	jsonw_destroy(&wr);
	fclose(f);

	return outbuf;
}
