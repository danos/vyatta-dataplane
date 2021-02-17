/*-
 * Copyright (c) 2019-2020, AT&T Intellectual Property.
 * All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * Port link state events
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eth_vhost.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_timer.h>
#include <rte_version.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bitmask.h"
#include "compiler.h"
#include "config_internal.h"
#include "control.h"
#include "dpdk_eth_if.h"
#include "dpdk_eth_linkwatch.h"
#include "dp_event.h"
#include "event_internal.h"
#include "if_var.h"
#include "ip_forward.h"
#include "l2_rx_fltr.h"
#include "lag.h"
#include "main.h"
#include "rcu.h"
#include "vhost.h"
#include "vplane_debug.h"
#include "vplane_log.h"

bitmask_t linkup_port_mask __hot_data;	/* link is up */
static bitmask_t lsc_irq_mask;		/* link interrupt enabled */
static bitmask_t lsc_irq_pending;	/* link state changed */
static bitmask_t link_reset_pending;	/* link reset pending */
static bitmask_t queue_state_pending;	/* queue state change pending */

/* event file descriptor for link state change */
static void *lsc_arg;

/* decode DPDK definition of duplex */
const char *link_duplexstr(unsigned int duplex)
{
	switch (duplex) {
	case ETH_LINK_HALF_DUPLEX:	return "half";
	case ETH_LINK_FULL_DUPLEX:	return "full";
	default:			return "unknown?";
	}
}

/* notify qos of link state change */
static void notify_port_status(portid_t port,
			       const struct rte_eth_link *link)
{
	struct ifnet *ifp = ifport_table[port];

	if (link->link_status) {
		RTE_LOG(NOTICE, DATAPLANE,
			 "%s Link up at %d Mbps, %s duplex\n",
			 ifp->if_name,
			 link->link_speed,
			 link_duplexstr(link->link_duplex));

		bitmask_set(&linkup_port_mask, port);
		bitmask_and(&active_port_mask, &poll_port_mask,
			    &linkup_port_mask);

		dp_event(DP_EVT_IF_LINK_CHANGE, 0, ifp,
			 link->link_status, link->link_speed, NULL);
	} else {
		RTE_LOG(WARNING, DATAPLANE,
			"%s Link down\n", ifp->if_name);
		bitmask_clear(&linkup_port_mask, port);
		bitmask_and(&active_port_mask, &poll_port_mask,
			    &linkup_port_mask);

		dp_event(DP_EVT_IF_LINK_CHANGE, 0, ifp,
			 link->link_status, link->link_speed, NULL);

		/* Note: it is probably a good idea to drain the pkt
		 * ring and burst at this point to avoid stale packets
		 * going out once the link comes back up. However,
		 * doing the necessary dp_rcu_synchronize() here could
		 * potentially have a negative impact on link changes
		 * for other interfaces and other events so isn't done
		 * for the moment.
		 */
	}
}

/* Timer for peroidic check of link state
 *
 * Note: dp_rcu_read_lock not held here!
 */
void linkwatch_timer(struct rte_timer *tim __rte_unused, void *arg)
{
	struct ifnet *ifp = arg;
	portid_t port = ifp->if_port;
	struct rte_eth_link link;

	/* ignore timer when race with admin down */
	if (dpdk_eth_if_port_started(port)) {
		rte_eth_link_get_nowait(port, &link);
		bitmask_set(&lsc_irq_mask, port);	/* re-enable irq */

		int old_status = if_port_isup(port);
		if (link.link_status != old_status)
			notify_port_status(port, &link);

		send_port_status(port, &link);
	}
}

/* Check link state */
void linkwatch_update_port_status(portid_t port, enum linkwatch_flags flags)
{
	struct rte_eth_link link;
	int old_status;

	rte_eth_link_get_nowait(port, &link);
	/* The kernel needs to be informed that the link is operationally down
	 * when the port is stopped, so intervene in this case as the link state
	 * in some if not all DPDK PMDs remains up.
	 */
	if (flags & LINKWATCH_FLAG_FORCE_LINK_DOWN)
		link.link_status = ETH_LINK_DOWN;

	old_status = if_port_isup(port);
	if (flags & LINKWATCH_FLAG_FORCE_NOTIFY ||
	    link.link_status != old_status)
		notify_port_status(port, &link);

	send_port_status(port, &link);
}

/* Callback from being woken up on link_fd.
 * Runs on main thread (via get_next_event)
 *
 * irq_mask is used to debounce events so that only one link
 * state change between timer interval is possible
 *
 * For ports that use the queue state events, the queue state was read when
 * the callback was received, so now we need to bring the state into line
 * with the configured set of queues here.
 *
 * Note: dp_rcu_read_lock not held here!
 */
static int link_state_event(void *arg)
{
	int lsc_fd = (unsigned long) arg;
	unsigned int port;
	uint64_t seqno;

	if (read(lsc_fd, &seqno, sizeof(seqno)) < 0) {
		if (errno != EINTR)
			RTE_LOG(NOTICE, DATAPLANE,
				"link state event read error: %s\n",
				strerror(errno));
	}

	for (port = 0; port < DATAPLANE_MAX_PORTS; port++) {
		if (!rte_eth_dev_is_valid_port(port))
			continue;

		if (bitmask_isset(&lsc_irq_pending, port)) {
			bitmask_clear(&lsc_irq_pending, port);
			if (dpdk_eth_if_port_started(port))
				linkwatch_update_port_status(
					port, LINKWATCH_FLAG_NONE);
		}

		if (bitmask_isset(&link_reset_pending, port)) {
			bitmask_clear(&link_reset_pending, port);
			if (dpdk_eth_if_port_started(port))
				dpdk_eth_if_reset_port(NULL,
						       ifport_table[port]);
		}

		if (bitmask_isset(&queue_state_pending, port)) {
			bitmask_clear(&queue_state_pending, port);
			dpdk_eth_if_update_port_queue_state(port);
		}
	}

	return 0;
}

static const char *linkscan_source = "linkscan";

static void linkwatch_change_mark_state(portid_t port_id,
					enum dp_rt_path_state state)
{
	struct dp_rt_path_unusable_key key;
	struct ifnet *ifp;

	dp_rcu_register_thread();

	ifp = ifnet_byport(port_id);
	if (ifp) {
		key.ifindex = ifp->if_index;
		key.type = DP_RT_PATH_UNUSABLE_KEY_INTF;
		dp_rt_signal_path_state(linkscan_source, state, &key);
	}

	dp_rcu_thread_offline();
}

static enum dp_rt_path_state
linkwatch_check_path_state(const struct dp_rt_path_unusable_key *key)
{
	struct rte_eth_link link;
	struct ifnet *ifp;

	if (key->type == DP_RT_PATH_UNUSABLE_KEY_INTF) {
		ifp = dp_ifnet_byifindex(key->ifindex);
		if (!ifp)
			return DP_RT_PATH_UNKNOWN;

		if (rte_eth_link_get_nowait(ifp->if_port, &link) < 0)
			return DP_RT_PATH_UNKNOWN;

		if (link.link_status == ETH_LINK_DOWN)
			return DP_RT_PATH_UNUSABLE;
		return DP_RT_PATH_USABLE;
	}

	return DP_RT_PATH_UNKNOWN;
}


/* Open eventfd handle used to notify main thread
 * by callbacks called in interrupt thread.
 */
void link_state_init(void)
{
	int rv;
	int fd = eventfd(0, EFD_NONBLOCK);
	if (fd < 0)
		rte_panic("%s: eventfd failed: %s\n",
			  __func__, strerror(errno));

	lsc_arg = (void *) (unsigned long) fd;
	register_event_fd(fd, link_state_event, lsc_arg);

	rv = dp_rt_register_path_state(linkscan_source,
				       linkwatch_check_path_state);
	if (rv)
		rte_panic("Could not register route state with linkwatch\n");
}

/* Port event occurred.
 *
 *  Called from another Posix thread therefore can't safely update
 *  port state directly, need to wakeup main thread
 */
static int
eth_port_event(portid_t port_id, enum rte_eth_event_type type, void *arg,
	       __unused void *ret_arg)
{
	unsigned long link_fd = (unsigned long) arg;
	static const uint64_t incr = 1;
	bool wakeup = false;
	int rv;

	/* Notify main thread, and debounce */
	if (type == RTE_ETH_EVENT_INTR_LSC) {
		struct rte_eth_link link;

		rv = rte_eth_link_get_nowait(port_id, &link);
		if (rv == 0) {
			if (link.link_status == ETH_LINK_DOWN)
				linkwatch_change_mark_state(
					port_id, DP_RT_PATH_UNUSABLE);
			else
				linkwatch_change_mark_state(port_id,
							    DP_RT_PATH_USABLE);
		}
		/*
		 * If the port uses the queue state events, and it is down
		 * then we have to clear the enabled queues otherwise we
		 * can get into an inconsistent state.
		 */
		if (get_port_uses_queue_state(port_id)) {
			if (rv == 0 && link.link_status == ETH_LINK_DOWN)
				reset_port_enabled_queue_state(port_id);
		}
		if (bitmask_isset(&lsc_irq_mask, port_id)) {
			bitmask_clear(&lsc_irq_mask, port_id);
			bitmask_set(&lsc_irq_pending, port_id);
			wakeup = true;
		}
	}

	if (type == RTE_ETH_EVENT_INTR_RESET &&
	    dpdk_eth_if_port_started(port_id)) {
		bitmask_set(&link_reset_pending, port_id);
		wakeup = true;
	}

	if (type == RTE_ETH_EVENT_QUEUE_STATE) {
		/*
		 * Pull all the events off the queue, and set the
		 * enabled queues correctly. The main thread will then
		 * do the work to actually enable them.
		 */
		struct rte_eth_vhost_queue_event event;

		while (rte_eth_vhost_get_queue_event(port_id, &event) == 0)
			track_port_queue_state(port_id, event.queue_id,
					       event.rx, event.enable);

		bitmask_set(&queue_state_pending, port_id);
		wakeup = true;
	}

	if (wakeup && write(link_fd, &incr, sizeof(incr)) < 0)
		RTE_LOG(NOTICE, DATAPLANE,
			"wakeup of link state thread failed: %s\n",
			strerror(errno));

	return 0;
}

int linkwatch_port_config(portid_t portid)
{
	int ret;

	/* Enable Link State Interrupt */
	ret = rte_eth_dev_callback_register(portid, RTE_ETH_EVENT_INTR_LSC,
					    eth_port_event, lsc_arg);
	if (ret < 0)
		RTE_LOG(WARNING, DATAPLANE,
			"rte_eth_dev_callback_register(lsc): err=%d, port=%u\n",
			ret, portid);

	ret = rte_eth_dev_callback_register(portid, RTE_ETH_EVENT_INTR_RESET,
					    eth_port_event, lsc_arg);
	if (ret < 0)
		RTE_LOG(WARNING, DATAPLANE,
			"rte_eth_dev_callback_register(reset): err=%d, port=%u\n",
			ret, portid);

	if (port_uses_queue_state(portid)) {
		set_port_uses_queue_state(portid, true);
		reset_port_all_queue_state(portid);
		ret = rte_eth_dev_callback_register(portid,
						    RTE_ETH_EVENT_QUEUE_STATE,
						    eth_port_event,
						    lsc_arg);
		if (ret < 0)
			RTE_LOG(WARNING, DATAPLANE,
				"rte_eth_dev_callback_register(queue state): err=%d, port=%u\n",
				ret, portid);

	}

	return 0;
}

void linkwatch_port_unconfig(portid_t portid)
{
	/* Disable Link State Interrupt */
	rte_eth_dev_callback_unregister(portid, RTE_ETH_EVENT_INTR_LSC,
					eth_port_event, lsc_arg);

	/* Disable Port Reset callback */
	rte_eth_dev_callback_unregister(portid, RTE_ETH_EVENT_INTR_RESET,
					eth_port_event, lsc_arg);

	rte_eth_dev_callback_unregister(portid, RTE_ETH_EVENT_QUEUE_STATE,
					eth_port_event, lsc_arg);
	set_port_uses_queue_state(portid, false);
}
