/*
 * Copyright (c) 2017-2018, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */
#include <czmq.h>
#include <errno.h>
#include <linux/capability.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#ifdef HAVE_RTE_ETHDEV_DRIVER_H
#include <rte_ethdev_driver.h>
#endif
#include <rte_log.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/capability.h>

#include "capture.h"
#include "commands.h"
#include "compat.h"
#include "event.h"
#include "hotplug.h"
#include "if_var.h"
#include "main.h"
#include "master.h"
#include "urcu.h"
#include "vplane_log.h"

sigjmp_buf hotplug_jmpbuf;
bool hotplug_inprogress;

/* inproc server address */
static const char dev_inproc[] = "inproc://devserv";

enum {
	ADD,
	REMOVE
};

/* Teardown a device and detach from the DPDK port. */
int detach_device(const char *name)
{
#ifdef HAVE_RTE_DEV_REMOVE
	struct rte_eth_dev_info dev_info;
#else
	char detach_name[RTE_ETH_NAME_MAX_LEN];
#endif
	struct ifnet *ifp;
	portid_t port_id;
	struct rte_eth_dev *dev;
	int ret = 0;

	/* Look for interface by pci string or name */
	if (rte_eth_dev_get_port_by_name(name, &port_id) != 0) {
		dev = rte_eth_dev_allocated(name);
		if (dev)
			port_id = dev->data->port_id;
		else {
			ifp  = ifnet_byifname(name);
			if (!ifp) {
				RTE_LOG(NOTICE, DATAPLANE,
					"detach-device(%s): already unplugged and deleted\n",
					name);
				return 0;
			}
			if (ifp->if_type != IFT_ETHER) {
				RTE_LOG(ERR, DATAPLANE,
					"detach-device(%s): not a DPDK port\n",
					name);
				return -1;
			}
			if (ifp->unplugged) {
				RTE_LOG(NOTICE, DATAPLANE,
					"detach-device(%s): already unplugged\n",
					name);
				return 0;
			}
			port_id = ifp->if_port;
		}
	}

	ifp = ifport_table[port_id];
	if (!ifp) {
		RTE_LOG(ERR, DATAPLANE,
			"detach-device(%s): no ifp for port id %d\n",
			name, port_id);
		return -1;
	}

	CMM_STORE_SHARED(hotplug_inprogress, true);
	if (sigsetjmp(hotplug_jmpbuf, 1))
		RTE_LOG(DEBUG, DATAPLANE,
			"%s: stop_port() failed!\n", __func__);
	else
		stop_port(port_id);

	ifp->unplugged = 1;
	capture_cancel(ifp);
	eth_port_uninit_portid(port_id);
	teardown_interface_portid(port_id);
	ifport_table[port_id] = NULL;

	if (sigsetjmp(hotplug_jmpbuf, 1)) {
		RTE_LOG(DEBUG, DATAPLANE,
			"%s: rte_eth_dev_close() failed!\n", __func__);
	} else
		rte_eth_dev_close(port_id);

	if (sigsetjmp(hotplug_jmpbuf, 1))
		RTE_LOG(DEBUG, DATAPLANE,
			"rte_eth_dev_detach() failed!\n");
	else {
#ifdef HAVE_RTE_DEV_REMOVE
		rte_eth_dev_info_get(port_id, &dev_info);
		if (rte_dev_remove(dev_info.device) != 0) {
#else
		if (rte_eth_dev_detach(port_id, detach_name) != 0) {
#endif
			RTE_LOG(ERR, DATAPLANE,
				"detach-device(%u): detach failed\n", port_id);
			ret = -1;
		}
	}
	CMM_STORE_SHARED(hotplug_inprogress, false);

	return ret;
}

/* Attach to a DPDK port and do setup. */
int attach_device(const char *name)
{
	portid_t port_id;
	struct rte_eth_dev *dev;
	int rv = 0;

	/*
	 * In case of dataplane restart, the device may have been
	 * created earlier due to signaling from the controller.
	 */
	dev = rte_eth_dev_allocated(name);
	if (dev != NULL) {
		RTE_LOG(INFO, DATAPLANE,
			"Re-attached to device %s\n", name);
		return 0;
	}

#ifdef HAVE_RTE_DEV_PROBE
	if (rte_dev_probe(name) != 0) {
#else
	if (rte_eth_dev_attach(name, &port_id) != 0) {
#endif
		RTE_LOG(ERR, DATAPLANE,
			"attach-device(%s): attach failed\n", name);
		return -1;
	}

#ifdef HAVE_RTE_DEV_PROBE
	struct rte_dev_iterator iterator;
	RTE_ETH_FOREACH_MATCHING_DEV(port_id, name, &iterator)
#endif
	rv |= insert_port(port_id);

	if (rv != 0)
		RTE_LOG(ERR, DATAPLANE,
			"attach-device(%s): failed to insert port\n",
			name);
	return rv;
}

/*
 * Add or remove a flag from the effective capability set.
 * Note the flag must already be present in the permitted set.
 */
static int
change_capability(cap_value_t capability, bool on)
{
	cap_t caps;
	cap_value_t cap_flag[1];
	int rc;

	if (!cap_valid(capability)) {
		RTE_LOG(ERR, DATAPLANE,
			"Invalid capability %d\n", capability);
		return -1;
	}

	caps = cap_get_proc();
	if (caps == NULL) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to get current capabilities\n");
		return -1;
	}

	cap_flag[0] = capability;
	rc = cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_flag,
			  on ? CAP_SET : CAP_CLEAR);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"Failed to %s flag for capability %d\n",
			on ? "set" : "clear", capability);
		goto out;
	}

	rc = cap_set_proc(caps);
	if (rc < 0)
		RTE_LOG(ERR, DATAPLANE,
			"Failed to %s capability %d\n",
			on ? "enable" : "disable", capability);

out:
	cap_free(caps);
	return rc;
}

/* Handle device add/remove events. */
static int
handle_device_event(void *arg)
{
	zsock_t *sock = (zsock_t *)arg;
	int rv;
	uint8_t type;
	int *call_rv;
	char *name;

	rv = zsock_brecv(sock, "1sp", &type, &name, &call_rv);
	if (rv < 0) {
		RTE_LOG(ERR, DATAPLANE,
				"device-event: failed to receive event\n");
		return rv;
	}

	*call_rv = 0;

	/*
	 * Add SYS_ADMIN to the effective capability set.
	 * DPDK needs this to read PCI config space on the device.
	 */
	if (change_capability(CAP_SYS_ADMIN, true) < 0)
		goto out;

	switch (type) {
	case ADD:
		*call_rv = attach_device(name);
		break;
	case REMOVE:
		*call_rv = detach_device(name);
		break;
	default:
		RTE_LOG(ERR, DATAPLANE,
			"device-event: unknown event type %d\n", type);
		*call_rv = -EINVAL;
		break;
	}
	change_capability(CAP_SYS_ADMIN, false);

out:
	/*
	 * Note: zsock_signal takes a byte, so we signal the success
	 * or failure of the call separately through the call_rv
	 * parameter.
	 */
	return zsock_signal(sock, 0);
}

/* Send device add/remove to the master thread. */
int
send_device_event(const char *name, bool is_add)
{
	zsock_t *dev_sock;
	int call_rv;
	int rv;

	dev_sock = zsock_new_req(dev_inproc);
	if (!dev_sock)
		return -1;

	rv = zsock_bsend(dev_sock, "1sp", is_add ? ADD : REMOVE, name,
			 &call_rv);
	if (rv < 0) {
		RTE_LOG(ERR, DATAPLANE,
			"device(%s): failed to send event %s\n", name,
			is_add ? "ADD" : "REMOVE");
		goto cleanup;
	}

	rv = zsock_wait(dev_sock);
	if (rv >= 0) {
		rv = call_rv;
		if (rv < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"device(%s): %s request failed\n",
				name,
				is_add ? "ADD" : "REMOVE");
		}
	} else {
		RTE_LOG(ERR, DATAPLANE,
			"device(%s): no ack for %s\n", name,
			is_add ? "ADD" : "REMOVE");
	}

cleanup:
	zsock_destroy(&dev_sock);

	return rv;
}

/* Setup a zmq listener for device add/remove events. */
static zsock_t *dev_server;
void device_server_init(void)
{
	dev_server = zsock_new_rep(dev_inproc);

	if (!dev_server)
		rte_panic("cannot bind to vhost socket\n");

	register_event_socket(zsock_resolve(dev_server),
			      handle_device_event, dev_server);
}

void device_server_destroy(void)
{
	unregister_event_socket(zsock_resolve(dev_server));
	zsock_destroy(&dev_server);
}

/*
 * Command handler for hotplug events (online insertion and removal of network
 * interfaces). The zmq message consists of two parts (strings): action and
 * PCI address:
 *
 * action: "add" or "remove"
 * address: domain:bus:devid.function (XXXX:XXX:XXX.X)
 *
 */
int cmd_hotplug(FILE *f, int argc, char **argv)
{
	bool insert;
	int rc;

	if (argc != 3 || strcmp(argv[0], "hotplug") != 0) {
		fprintf(f, "hotplug: unknown command\n");
		return -1;
	}

	if (strcmp(argv[1], "add") == 0) {
		insert = true;
	} else if (strcmp(argv[1], "remove") == 0) {
		insert = false;
	} else {
		fprintf(f, "hotplug: unknown action '%s'\n", argv[1]);
		return -1;
	}

	rcu_thread_offline();
	rc = send_device_event(argv[2], insert);
	rcu_thread_online();

	return rc;
}
