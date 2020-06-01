/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <poll.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <urcu/list.h>
#include <urcu/uatomic.h>

#include "config_internal.h"
#include "dpdk_eth_if.h"
#include "dp_event.h"
#include "hotplug.h"
#include "if_var.h"
#include "json_writer.h"
#include "main.h"
#include "urcu.h"
#include "util.h"
#include "vhost.h"
#include "vplane_debug.h"
#include "vplane_log.h"

#define QMP_RETURN_BUFSIZE 200

struct vhost_info_private {
	struct rcu_head sc_rcu;	   /**< Linkage for call_rcu */
	struct cds_list_head list; /**< Linkage for vhost_info_private_list */
	char name[IFNAMSIZ];	   /**< DPDK instance name */
	char *qmp_path;		   /**< Path to QMP connection */
	char *qemu_ifname;	   /**< QEMU name for guest interface */
};

struct vhost_transport {
	struct rcu_head vt_rcu;		/**< Linkage for call_rcu */
	struct cds_list_head list;
	char ifname[IFNAMSIZ];
};

struct vhost_info {
	struct cds_list_head transport_links;
					/**< Monitored interfaces -- if any */
};

static struct cds_list_head vhost_info_private_list =
				CDS_LIST_HEAD_INIT(vhost_info_private_list);

/*
 * Vhost event queue
 */
TAILQ_HEAD(vhost_event_list, vhost_event);
struct vhost_event {
	TAILQ_ENTRY(vhost_event) next;
	char *vhost_name;
};
static rte_spinlock_t vhost_ev_list_lock = RTE_SPINLOCK_INITIALIZER;

struct vhost_event_list vhost_ev_list;
static struct cfg_if_list *vhost_cfg_list;

/**
 * Check to see if an ifp is a vhost interface by examining
 * the DPDK PMD driver name.
 */
static bool is_vhost(const struct ifnet *ifp)
{
	if (ifp->if_local_port) {
		struct rte_eth_dev *eth_dev = &rte_eth_devices[ifp->if_port];

		if (strncmp(eth_dev->data->name, "eth_vhost", 9) == 0)
			return true;
	}

	return false;
}

/**
 * Get struct vhost_info from a vhost ifp.
 */
static struct vhost_info *get_vhost_info(const struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *sc;

	assert(is_vhost(ifp) == true);

	sc = rcu_dereference(ifp->if_softc);
	if (!sc)
		return NULL;

	return rcu_dereference(sc->scd_vhost_info);
}

/**
 * Get struct vhost_info_private from a vhost ifp. Note that we
 * might need to strip the dataplane prefix.
 */
static struct vhost_info_private *vhost_info_by_name(const char *if_name)
{
	struct vhost_info_private *vip;
	const char *name;

	name = strstr(if_name, "vhost");
	if (!name)
		return NULL;

	cds_list_for_each_entry(vip, &vhost_info_private_list, list) {
		if (!strcmp(name, vip->name))
			return vip;
	}

	return NULL;
}

static ssize_t read_timeout(int fd, void *buf, size_t count)
{
	struct pollfd poll_fds[1];
	/* Responses are typically << 100ms, use 500ms to be safe */
	int timeout = 500;
	int rc;

	poll_fds[0].fd = fd;
	poll_fds[0].events = POLLIN;

	rc = poll(poll_fds, 1, timeout);
	if (rc < 1) {
		if (!rc)
			RTE_LOG(ERR, DATAPLANE, "timeout talking to QMP\n");
		return -1;
	}

	return read(fd, buf, count);
}

/**
 * Send cmd via QEMU Machine Protocol (QMP).
 */
static void vhost_qmp_command(const char *path, const char *cmd)
{
	int sock;
	struct sockaddr_un server;
	const char *cmd_mode = "{ \"execute\": \"qmp_capabilities\" }";
	char buf[QMP_RETURN_BUFSIZE];
	ssize_t len;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		DP_DEBUG(VHOST, DEBUG, DATAPLANE,
			 "%s: socket() failed\n", __func__);
		return;
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, path);

	if (connect(sock, (struct sockaddr *) &server,
					sizeof(struct sockaddr_un)) < 0) {
		DP_DEBUG(VHOST, DEBUG, DATAPLANE,
			 "%s: connect(%s, ...) failed\n", __func__, path);
		goto done;
	}

	/* Read the initial server message.
	 * See https://wiki.qemu.org/Documentation/QMP for details.
	 */
	len = read_timeout(sock, buf, sizeof(buf));
	if (len < 0) {
		DP_DEBUG(VHOST, DEBUG, DATAPLANE,
			 "%s: read(%s, ...) failed during capability negotiation.\n",
			 __func__, path);
		goto done;
	}

	/* Exit capability negotiation and enter command mode. */
	len = write(sock, cmd_mode, strlen(cmd_mode));
	if (len < 0)
		DP_DEBUG(VHOST, INFO, DATAPLANE,
			 "%s: write(cmd_mode) failed\n", __func__);
	len = read_timeout(sock, buf, sizeof(buf));
	if (len < 0) {
		DP_DEBUG(VHOST, DEBUG, DATAPLANE,
			 "%s: read(%s, ...) failed entering command mode.\n",
			 __func__, path);
		goto done;
	}

	len = write(sock, cmd, strlen(cmd));
	if (len < 0)
		DP_DEBUG(VHOST, INFO, DATAPLANE,
			 "%s: write(set_link) failed\n", __func__);
	len = read_timeout(sock, buf, sizeof(buf));
	if (len < 0)
		DP_DEBUG(VHOST, DEBUG, DATAPLANE,
			 "%s: read(%s, ...) failed after sending command.\n",
			 __func__, path);

done:
	close(sock);
}

/**
 * Set the guest link state using QEMU Machine Protocol (QMP).
 */
static int vhost_set_link_state(struct ifnet *ifp, bool up)
{
#define SET_LINK_CMD_STR "{ \"execute\": \"set_link\", " \
			 "\"arguments\": { \"name\": \"%s\", \"up\" : %s } }"
	struct vhost_info_private *vip;
	char set_link[sizeof(SET_LINK_CMD_STR) + 32 + sizeof("false") + 1];

	vip = vhost_info_by_name(ifp->if_name);
	if (!vip || !vip->qmp_path || !vip->qemu_ifname)
		return -EINVAL;

	snprintf(set_link, sizeof(set_link), SET_LINK_CMD_STR,
		 vip->qemu_ifname, up ? "true" : "false");

	vhost_qmp_command(vip->qmp_path, set_link);
	return 0;
}

/**
 * Create private data for each vhost interface to hold the
 * QEMU information.
 */
static struct vhost_info_private *vhost_info_private_create(char *name)
{
	struct vhost_info_private *vip;

	vip = calloc(1, sizeof(*vip));
	if (!vip)
		return NULL;

	CDS_INIT_LIST_HEAD(&vip->list);
	snprintf(vip->name, IFNAMSIZ, "%s", name);
	cds_list_add_tail_rcu(&vip->list, &vhost_info_private_list);

	return vip;
}

/**
 * RCU callback that finally frees the vhost private info.
 */
static void vhost_info_private_free(struct rcu_head *head)
{
	struct vhost_info_private *vip =
		caa_container_of(head, struct vhost_info_private, sc_rcu);

	free(vip->qmp_path);
	free(vip->qemu_ifname);
	free(vip);
}

/**
 * Delete the vhost private information from global list.
 * and schedule final free after next RCU.
 */
static void vhost_info_private_delete(char *name)
{
	struct vhost_info_private *vi, *next;

	cds_list_for_each_entry_safe(vi, next, &vhost_info_private_list, list) {
		if (!strcmp(name, vi->name)) {
			cds_list_del_rcu(&vi->list);
			call_rcu(&vi->sc_rcu, vhost_info_private_free);
		}
	}
}

/**
 * Allocate the vhost_info used by transport-link logic.
 */
static int vhost_info_alloc(const struct ifnet *ifp)
{
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	struct vhost_info *vi;

	if (sc->scd_vhost_info)
		return 0;

	vi = zmalloc_aligned(sizeof(*vi));
	if (!vi)
		return -ENOMEM;
	CDS_INIT_LIST_HEAD(&vi->transport_links);
	rcu_assign_pointer(sc->scd_vhost_info, vi);

	return 0;
}

/**
 * Free the vhost_info associated with the softc. Called when netlink
 * indicates an interface is going away.
 */
void vhost_info_free(struct vhost_info *vi)
{
	struct vhost_transport *entry, *next;

	cds_list_for_each_entry_safe(entry, next, &vi->transport_links, list)
		free(entry);
	free(vi);
}

void vhost_devinfo(json_writer_t *wr, const struct ifnet *ifp)
{
	struct vhost_info *vi;
	struct vhost_transport *entry;
	struct vhost_info_private *vip;

	vip = vhost_info_by_name(ifp->if_name);
	if (vip) {
		if (vip->qmp_path)
			jsonw_string_field(wr, "qmp_path", vip->qmp_path);
		if (vip->qemu_ifname)
			jsonw_string_field(wr, "qemu_ifname",
					       vip->qemu_ifname);
	}

	jsonw_name(wr, "transport_links");
	jsonw_start_array(wr);
	vi = get_vhost_info(ifp);
	if (vi)
		cds_list_for_each_entry(entry, &vi->transport_links, list)
			jsonw_string(wr, entry->ifname);
	jsonw_end_array(wr);
}

static int cmd_vhost_disable(char *ifname, bool on_main)
{
	int rc;
	char *devargs_p;
	int size;

	DP_DEBUG(VHOST, DEBUG, DATAPLANE,
		"vhost: sending event REMOVE, %s\n",
		ifname);

	size = asprintf(&devargs_p, "dp%d%s", 0, ifname);
	if (size == -1)
		return -1;

	vhost_info_private_delete(ifname);

	if (on_main) {
		rc = detach_device(devargs_p);
	} else {
		rcu_thread_offline();
		rc = send_device_event(devargs_p, false);
		rcu_thread_online();
	}

	free(devargs_p);

	return rc;
}

static const char dev_basename[] = "/run/dataplane/eth_";

/**
 * Set path as the QMP (QEMU Machine Protocol) connection for the vhost ifname.
 */
static int cmd_vhost_set_qmp_path(char *name, char *path)
{
	struct vhost_info_private *vip;

	vip = vhost_info_by_name(name);
	if (!vip)
		return -ENODEV;

	free(vip->qmp_path);
	vip->qmp_path = strdup(path);

	return 0;
}

/**
 * Set path of QMP (QEMU Machine Protocol) connection for the vhost interface.
 */
static int cmd_vhost_set_qemu_ifname(char *name, char *qemu_ifname)
{
	struct vhost_info_private *vip;

	vip = vhost_info_by_name(name);
	if (!vip)
		return -ENODEV;

	free(vip->qemu_ifname);
	vip->qemu_ifname = strdup(qemu_ifname);

	return 0;
}

static int cmd_vhost_enable(char *ifname, char *queues, char *path, char *alias,
			    bool on_main, bool is_client)
{
	int rc;
	char *devargs_p;
	char *pathname;
	char *p;
	int size;

	p = strrchr(ifname, 'v');
	if (!p) {
		RTE_LOG(ERR, DATAPLANE,
			"interface name %s needs to be dpxvhosty\n",
			ifname);
		return -1;
	}

	/* Construct "eth_vhost1,iface=/run/dataplane/eth_vhost1" with */
	size = asprintf(&devargs_p, "eth_%s,iface=%s%s%s%s%s",
			p, dev_basename, p, is_client ? ",client=1" : "",
			queues ? ",queues=" : "", queues ? queues : "");
	if (size == -1)
		return -1;

	DP_DEBUG(VHOST, DEBUG, DATAPLANE,
		"vhost: sending event ADD, %s\n",
		ifname);
	if (on_main) {
		rc = attach_device(devargs_p);
	} else {
		rcu_thread_offline();
		rc = send_device_event(devargs_p, true);
		rcu_thread_online();
	}

	/* vhost interfaces are created synchronously */
	if (!is_client && asprintf(&pathname, "%s%s", dev_basename, p) > 0) {
		if (chmod(pathname, 0770) < 0)
			DP_DEBUG(VHOST, DEBUG, DATAPLANE,
				 "chmod(%s, ...) failed!\n", pathname);
		if (dataplane_gid != 0) {
			if (chown(pathname, dataplane_uid, dataplane_gid) < 0)
				DP_DEBUG(VHOST, DEBUG, DATAPLANE,
					 "chown(%s, ...) failed!\n", pathname);
		}
		free(pathname);
	}

	if (!rc) {
		struct vhost_info_private *vip;

		vip = vhost_info_private_create(ifname);
		if (vip) {
			if (path)
				cmd_vhost_set_qmp_path(ifname, path);
			if (alias)
				cmd_vhost_set_qemu_ifname(ifname, alias);
		} else {
			RTE_LOG(ERR, DATAPLANE,
				"vhost_info_private_create failed for %s, transport-link tracking won't work!\n",
				ifname);
		}
	}

	free(devargs_p);
	return rc;
}

/* An interface isn't "up" even if the PMD link state is valid.
 * We need to wait until the interface reaches IFF_RUNNING (at
 * least) as determined by some layer 2 protocol (like 802.1ag)
 * running over the port.
 */
static bool ifnet_isrunning(struct ifnet *ifp)
{
	return (ifp->if_flags & IFF_RUNNING) && if_port_isup(ifp->if_port);
}


void vhost_event_init(void)
{
	/* Initialize event queue */
	TAILQ_INIT(&vhost_ev_list);
}

static int vhost_set_update_event(struct ifnet *ifp)
{
	struct vhost_event *ev;

	if (!ifp)
		return 0;

	/* If not vhost interface return */
	if (!is_vhost(ifp))
		return 0;

	/* Take the lock to update vhost list structure */
	rte_spinlock_lock(&vhost_ev_list_lock);

	TAILQ_FOREACH(ev, &vhost_ev_list, next) {
		if (streq(ev->vhost_name, ifp->if_name)) {
			/* Release lock */
			rte_spinlock_unlock(&vhost_ev_list_lock);
			return 0;
		}
	}
	ev = malloc(sizeof(*ev));
	if (!ev) {
		RTE_LOG(ERR, DATAPLANE, "vhost %s : Event alloc failed\n",
			ifp->if_name);
		/* Release lock */
		rte_spinlock_unlock(&vhost_ev_list_lock);
		return -1;
	}
	ev->vhost_name = strdup(ifp->if_name);

	/* enqueue vhost event since its not already present */
	TAILQ_INSERT_TAIL(&vhost_ev_list, ev, next);

	/* Release the lock */
	rte_spinlock_unlock(&vhost_ev_list_lock);

	/* Set the event */
	return set_main_worker_vhost_event_fd();
}

/**
 * Walk the interface table and update any vhost interfaces that have
 * the target interface in the transport_links list.  If arg is NULL
 * we need to completely recalculate the state and update the guest.
 */
static void vhost_link_update_core(struct ifnet *ifp, void *arg, bool process)
{
	struct ifnet *updated = arg;
	struct vhost_transport *entry;
	struct vhost_info *vi;
	bool update_guest = false;
	bool up = false; /* assume down */

	if (!is_vhost(ifp))
		return;

	/* vhost interface is down, no updates necessary */
	if (!(ifp->if_flags & IFF_UP)) {
		up = false;
		update_guest = true;
		goto out;
	}

	vi = get_vhost_info(ifp);

	/* No transport links -- The guest's carrier status should be up. */
	if (!vi || cds_list_empty(&vi->transport_links)) {
		up = true;
		update_guest = true;
		goto out;
	}

	/* Iterate once and decide if any of the interfaces are up and
	 * if this update applies to the vhost interface.
	 */
	cds_list_for_each_entry_rcu(entry,
				    &vi->transport_links, list) {
		struct ifnet *transport;

		transport = dp_ifnet_byifname(entry->ifname);
		if (transport && ifnet_isrunning(transport))
			up = true;
		if (!updated || strcmp(updated->if_name, entry->ifname) == 0)
			update_guest = true;
		if (up && update_guest)		/* early exit */
			break;
	}

out:
	if (process)
		vhost_set_link_state(ifp, up);

	else if (update_guest)
		vhost_set_update_event(ifp);
}

static void vhost_link_update(struct ifnet *ifp, void *arg)
{
	vhost_link_update_core(ifp, arg, false);
}

static void vhost_link_update_process(char *vhost_name)
{
	struct ifnet *ifp;

	rcu_read_lock();
	ifp = dp_ifnet_byifname(vhost_name);
	if (!ifp) {
		rcu_read_unlock();
		return;
	}
	vhost_link_update_core(ifp, NULL, true);

	rcu_read_unlock();
}

void vhost_event_handler(void)
{
	struct vhost_event *ev;

	/* Take the lock */
	rte_spinlock_lock(&vhost_ev_list_lock);
	/* while list not empty, get vhost interface to process */
	while (!TAILQ_EMPTY(&vhost_ev_list)) {
		ev = TAILQ_FIRST(&vhost_ev_list);
		TAILQ_REMOVE(&vhost_ev_list, ev, next);
		/* Release lock */
		rte_spinlock_unlock(&vhost_ev_list_lock);

		/* do event processing */
		vhost_link_update_process(ev->vhost_name);

		/*Free ev */
		free(ev->vhost_name);
		free(ev);

		/* take lock */
		rte_spinlock_lock(&vhost_ev_list_lock);
	}
	/* Release the lock */
	rte_spinlock_unlock(&vhost_ev_list_lock);
}

void vhost_update_guests(struct ifnet *ifp)
{
	if (is_vhost(ifp))
		vhost_link_update(ifp, NULL);
	else {
		rcu_read_lock();
		dp_ifnet_walk(vhost_link_update, ifp);
		rcu_read_unlock();
	}
}

static void vhost_transport_free(struct rcu_head *head)
{
	struct vhost_transport *entry =
		caa_container_of(head, struct vhost_transport, vt_rcu);

	free(entry);
}


static void
vhost_event_if_index_set(struct ifnet *ifp);
static void
vhost_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex);

static const struct dp_event_ops vhost_event_ops = {
	.if_index_set = vhost_event_if_index_set,
	.if_index_unset = vhost_event_if_index_unset,
};

static void
vhost_event_if_index_set(struct ifnet *ifp)
{
	struct cfg_if_list_entry *le;

	if (!vhost_cfg_list)
		return;

	le = cfg_if_list_lookup(vhost_cfg_list, ifp->if_name);
	if (!le)
		return;

	DP_DEBUG(VHOST, DEBUG, DATAPLANE,
		 "Replaying (%s) command for interface %s\n",
		le->le_buf, ifp->if_name);

	cmd_vhost_client_cfg(NULL, le->le_argc, le->le_argv);
	cfg_if_list_del(vhost_cfg_list, ifp->if_name);

	if (!vhost_cfg_list->if_list_count)
		cfg_if_list_destroy(&vhost_cfg_list);
}

static void
vhost_event_if_index_unset(struct ifnet *ifp, uint32_t ifindex __unused)
{
	if (!vhost_cfg_list)
		return;

	cfg_if_list_del(vhost_cfg_list, ifp->if_name);
	if (!vhost_cfg_list->if_list_count) {
		dp_event_unregister(&vhost_event_ops);
		cfg_if_list_destroy(&vhost_cfg_list);
	}
}

static int vhost_replay_init(void)
{
	if (!vhost_cfg_list) {
		vhost_cfg_list = cfg_if_list_create();
		if (!vhost_cfg_list)
			return -ENOMEM;

		dp_event_register(&vhost_event_ops);
	}
	return 0;
}

/**
 * Add or remove transport_link to the list of interfaces that name monitors.
 * Expects pre verified string in the following format
 * vhost-client transport-link <vhost_dev> <transport_dev> add|del
 * argv[2]  vhost interface name
 * argv[3]  transport-link interface
 */
static int cmd_vhost_transport_update(int argc, char **argv, bool add)
{
	struct ifnet *ifp;
	struct vhost_transport *entry, *next;
	struct vhost_info *vi;
	int rc;

	ifp = dp_ifnet_byifname(argv[2]);
	if (!ifp) {
		if (vhost_replay_init() < 0) {
			RTE_LOG(ERR, DATAPLANE,
				"Vhost could not set up replay cache\n");
			return -ENOMEM;
		}
		RTE_LOG(DEBUG, DATAPLANE,
			"Caching Vhost transport cmd for %s %s %s\n",
			argv[2], argv[3], argv[4]);
		cfg_if_list_add(vhost_cfg_list,
				argv[2], argc, argv);

		return 0;
	}

	DP_DEBUG(VHOST, DEBUG, DATAPLANE,
		 "vhost %s, transport %s action %s\n",
		 argv[2], argv[3], add ? "ADD" : "DEL");

	rc = vhost_info_alloc(ifp);
	if (rc < 0) {
		RTE_LOG(ERR, DATAPLANE, "vhost_info_alloc: %s\n",
			strerror(rc));
		return rc;
	}

	vi = get_vhost_info(ifp);
	if (!vi)
		return -ENOENT;

	if (add) {
		struct ifnet *transport_ifp;

		entry = malloc(sizeof(*entry));
		if (!entry)
			return -ENOMEM;

		CDS_INIT_LIST_HEAD(&entry->list);
		snprintf(entry->ifname, IFNAMSIZ, "%s", argv[3]);
		cds_list_add_tail_rcu(&entry->list, &vi->transport_links);

		/* We might have added an "up" link. */
		transport_ifp = dp_ifnet_byifname(argv[3]);
		if (transport_ifp)
			vhost_link_update(ifp, transport_ifp);
	} else {
		cds_list_for_each_entry_safe(entry, next,
					     &vi->transport_links, list) {
			if (strcmp(entry->ifname, argv[3]) == 0) {
				cds_list_del_rcu(&entry->list);
				call_rcu(&entry->vt_rcu, vhost_transport_free);
			}
		}

		/* If no transport links left, assume up.  Otherwise, we
		 * might have removed an "up" transport -- set update event
		 */
		vhost_set_update_event(ifp);
	}

	return 0;
}

static int __cmd_vhost(const char *cmd,
		       FILE *f, int argc, char **argv, bool is_client)
{
	char *queues = NULL;
	char *path = NULL;
	char *alias = NULL;
	int rc;

	if (argc < 3)
		goto bad_command;

	if (strcmp(argv[1], "enable") == 0 && argc >= 3) {
		int i = 3;

		while (i < argc) {
			if (strcmp(argv[i], "-q") == 0) {
				i++;
				if (i >= argc)
					goto bad_command;
				queues = argv[i++];
			} else if (strcmp(argv[i], "-p") == 0) {
				i++;
				if (i >= argc)
					goto bad_command;
				path = argv[i++];
			} else if (strcmp(argv[i], "-a") == 0) {
				i++;
				if (i >= argc)
					goto bad_command;
				alias = argv[i++];
			} else
				goto bad_command;
		}

		rc = cmd_vhost_enable(argv[2],
				      queues, path, alias, true, is_client);
	} else if (strcmp(argv[1], "disable") == 0 && argc == 3)
		rc = cmd_vhost_disable(argv[2], false);
	else if (strcmp(argv[1], "set-qmp-path") == 0 && argc == 4)
		rc = cmd_vhost_set_qmp_path(argv[2], argv[3]);
	else if (strcmp(argv[1], "set-qemu-ifname") == 0 && argc == 4)
		rc = cmd_vhost_set_qemu_ifname(argv[2], argv[3]);
	else
		goto bad_command;

	return rc;

bad_command:
	fprintf(f, "usage: %s enable <string> "
		   "[-q queues] [-a alias] [-p path]\n", cmd);
	fprintf(f, "       %s disable <string>\n", cmd);
	fprintf(f, "       %s set-qmp-path name path\n", cmd);
	fprintf(f, "       %s set-qemu-ifname name qemu-ifname\n", cmd);
	return -1;
}

int cmd_vhost(FILE *f, int argc, char **argv)
{
	return __cmd_vhost("vhost", f, argc, argv, false);
}

int cmd_vhost_client(FILE *f, int argc, char **argv)
{
	return __cmd_vhost("vhost-client", f, argc, argv, true);
}

static int __cmd_vhost_cfg(const char *cmd,
			   FILE *f, int argc, char **argv, bool is_client)
{
	char *queues = NULL;
	char *path = NULL;
	char *alias = NULL;
	int rc;

	if (argc < 3)
		goto bad_command;

	if (strcmp(argv[1], "enable") == 0 && argc >= 3) {
		int i = 3;

		while (i < argc) {
			if (strcmp(argv[i], "-q") == 0) {
				i++;
				if (i >= argc)
					goto bad_command;
				queues = argv[i++];
			} else if (strcmp(argv[i], "-p") == 0) {
				i++;
				if (i >= argc)
					goto bad_command;
				path = argv[i++];
			} else if (strcmp(argv[i], "-a") == 0) {
				i++;
				if (i >= argc)
					goto bad_command;
				alias = argv[i++];
			} else
				goto bad_command;
		}

		rc = cmd_vhost_enable(argv[2],
				      queues, path, alias, true, is_client);
	} else if (strcmp(argv[1], "disable") == 0 && argc == 3)
		rc = cmd_vhost_disable(argv[2], true);
	else if (strcmp(argv[1], "transport-link") == 0 && argc == 5) {
		if (strcmp(argv[4], "add") == 0)
			rc = cmd_vhost_transport_update(argc, argv,
							true);
		else if (strcmp(argv[4], "del") == 0)
			rc = cmd_vhost_transport_update(argc, argv,
							false);
		else
			goto bad_command;
	}
	else
		goto bad_command;

	return rc;

bad_command:
	if (f) {
		fprintf(f, "usage: %s enable <string> [-q <queues>]\n", cmd);
		fprintf(f, "       %s disable <string>\n", cmd);
		fprintf(f, "       %s transport-link <vhost_name> "
			   "<transport_name> add|del\n", cmd);
	}
	return -1;
}

int cmd_vhost_cfg(FILE *f, int argc, char **argv)
{
	return __cmd_vhost_cfg("vhost", f, argc, argv, false);
}

int cmd_vhost_client_cfg(FILE *f, int argc, char **argv)
{
	return __cmd_vhost_cfg("vhost-client", f, argc, argv, true);
}

static void
vhost_if_link_change(struct ifnet *ifp, bool up __unused,
		     uint32_t speed __unused)
{
	vhost_update_guests(ifp);
}

static const struct dp_event_ops vhost_events = {
	.if_link_change = vhost_if_link_change,
};

DP_STARTUP_EVENT_REGISTER(vhost_events);
