/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
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
#include <rte_ethdev_driver.h>
#include <rte_log.h>
#include <setjmp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "capture.h"
#include "commands.h"
#include "compat.h"
#include "dpdk_eth_if.h"
#include "event_internal.h"
#include "hotplug.h"
#include "if_var.h"
#include "main.h"
#include "controller.h"
#include "urcu.h"
#include "util.h"
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
	struct rte_eth_dev_info dev_info;
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
			ifp  = dp_ifnet_byifname(name);
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
	CMM_STORE_SHARED(hotplug_inprogress, true);
	if (ifp) {
		/*
		 * The following calls (unassign_queues and
		 * dpdk_eth_if_stop) both call dp_rcu_synchronize(), and
		 * setting unplugged needs to be before that call.
		 */
		ifp->unplugged = 1;
		if (sigsetjmp(hotplug_jmpbuf, 1)) {
			RTE_LOG(DEBUG, DATAPLANE,
				"%s: stop_port() failed!\n", __func__);

			/* if all else fails at least unassign queues */
			unassign_queues(ifp->if_port);
		} else
			dpdk_eth_if_stop_port(ifp);

		if_notify_emb_feat_change(ifp);

		capture_cancel(ifp);
	}

	teardown_interface_portid(port_id);
	shadow_uninit_port(port_id);
	remove_port(port_id);

	rte_eth_dev_info_get(port_id, &dev_info);

	if (sigsetjmp(hotplug_jmpbuf, 1)) {
		RTE_LOG(DEBUG, DATAPLANE,
			"%s: rte_eth_dev_close() failed!\n", __func__);
	} else
		rte_eth_dev_close(port_id);

	if (sigsetjmp(hotplug_jmpbuf, 1))
		RTE_LOG(DEBUG, DATAPLANE,
			"rte_eth_dev_detach() failed!\n");
	else {
		if (rte_dev_remove(dev_info.device) != 0) {
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

	if (rte_dev_probe(name) != 0) {
		RTE_LOG(ERR, DATAPLANE,
			"attach-device(%s): attach failed\n", name);
		return -1;
	}

	struct rte_dev_iterator iterator;
	RTE_ETH_FOREACH_MATCHING_DEV(port_id, name, &iterator) {
		rv = insert_port(port_id);
		if (rv) {
			RTE_LOG(ERR, DATAPLANE,
				"attach-device(%s): failed to insert port %u\n",
				name, port_id);
			break;
		}
		rv = setup_interface_portid(port_id);
		if (rv != 0) {
			RTE_LOG(ERR, DATAPLANE,
				"attach-device(%s): cannot setup interface (port %u)\n",
				name, port_id);
			remove_port(port_id);
			break;
		}
	}

	return rv;
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

/* Send device add/remove to the main thread. */
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

	dp_register_event_socket(zsock_resolve(dev_server),
			      handle_device_event, dev_server);
}

void device_server_destroy(void)
{
	dp_unregister_event_socket(zsock_resolve(dev_server));
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

	dp_rcu_thread_offline();
	rc = send_device_event(argv[2], insert);
	dp_rcu_thread_online();

	return rc;
}
