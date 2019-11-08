/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.
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
#include "config.h"
#include "control.h"
#include "dpdk_eth_if.h"
#include "dp_event.h"
#include "event.h"
#include "if_var.h"
#include "l2_rx_fltr.h"
#include "lag.h"
#include "main.h"
#include "qos.h"
#include "urcu.h"
#include "vhost.h"
#include "vplane_debug.h"
#include "vplane_log.h"

static bitmask_t started_port_mask;	/* port has been started */
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
		 * doing the necessary synchronize_rcu() here could
		 * potentially have a negative impact on link changes
		 * for other interfaces and other events so isn't done
		 * for the moment.
		 */
	}
}

/* Timer for peroidic check of link state
 *
 * Note: rcu_read_lock not held here!
 */
static void linkwatch_timer(struct rte_timer *tim __rte_unused, void *arg)
{
	struct ifnet *ifp = arg;
	portid_t port = ifp->if_port;
	struct rte_eth_link link;

	/* ignore timer when race with admin down */
	if (bitmask_isset(&started_port_mask, port)) {
		rte_eth_link_get_nowait(port, &link);
		bitmask_set(&lsc_irq_mask, port);	/* re-enable irq */

		int old_status = if_port_isup(port);
		if (link.link_status != old_status)
			notify_port_status(port, &link);

		send_port_status(port, &link);
	}
}

/* Check link state */
static void update_port_status(portid_t port, bool link_down)
{
	struct rte_eth_link link;

	rte_eth_link_get_nowait(port, &link);
	/* The kernel needs to be informed that the link is operationally down
	 * when the port is stopped, so intervene in this case as the link state
	 * in some if not all DPDK PMDs remains up.
	 */
	if (link_down)
		link.link_status = ETH_LINK_DOWN;
	notify_port_status(port, &link);
	send_port_status(port, &link);
}

static void soft_stop_port(portid_t port)
{
	struct ifnet *ifp = ifport_table[port];
	struct dpdk_eth_if_softc *sc = ifp->if_softc;

	if (!bitmask_isset(&started_port_mask, port))
		return;	 /* already inactive */

	/* if we're about to yank one of the slaves out from under the bonding
	 * driver, stop the bonding interface first.
	 */
	if (ifp->aggregator)
		soft_stop_port(ifp->aggregator->if_port);

	bitmask_clear(&started_port_mask, port);
	rte_eth_led_off(port);

	update_port_status(port, true);

	/* Stop monitoring port */
	rte_timer_stop(&sc->scd_link_timer);

	qos_sched_stop(ifp);

	/* make sure cores have drained */
	synchronize_rcu();

	/* free any leftovers */
	pkt_ring_empty(port);
}

static void soft_start_port(portid_t port)
{
	struct ifnet *ifp = ifport_table[port];
	struct dpdk_eth_if_softc *sc = ifp->if_softc;

	if (bitmask_isset(&started_port_mask, port))
		return;	 /* already active */

	rte_eth_led_on(port);

	bitmask_set(&started_port_mask, port);
	bitmask_set(&lsc_irq_mask, port);
	update_port_status(port, false);

	/* Start timer to send keepalive messages */
	if (rte_timer_reset(&sc->scd_link_timer,
			    config.port_update * rte_get_timer_hz(),
			    PERIODICAL, rte_get_master_lcore(),
			    linkwatch_timer, ifp) < 0)
		RTE_LOG(ERR, DATAPLANE,
			"rte_timer_reset failed for linkwatch timer port:%u\n",
			port);
}

/* Timer for periodic check of link reset
 *
 * Note: rcu_read_lock not held here!
 * This can be run both via directly in response to a link reset interrupt
 * (tim will be NULL) or from an rte_timer callback (tim will be the actual
 * timer). In both cases it will be ran from the master thread.
 */
static void reset_port(struct rte_timer *tim, void *arg)
{
	struct ifnet *ifp = arg;
	portid_t port = ifp->if_port;
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	int ret;
#if RTE_VERSION >= RTE_VERSION_NUM(18, 5, 0, 0)
	struct rte_eth_conf dev_conf;
	struct rte_eth_dev *eth_dev;
#endif

#if RTE_VERSION >= RTE_VERSION_NUM(18,5,0,0)
	stop_port(port);
#else
	soft_stop_port(port);

	/* PF down -> VF down -> VF up -> PF up - when VF comes back up and PF
	 * is still down, rte_eth_dev_start will fail, and the reset will fail
	 * because of that. Only way to fix this case is to run _start before
	 * _reset when PF is back up too.
	 */
	struct rte_eth_link link;
	rte_eth_link_get(port, &link);
	if (!link.link_status) {
		ret = rte_eth_dev_start(port);
		if (ret < 0)
			RTE_LOG(DEBUG, DATAPLANE, "reset_port failed to start "
					"device: port=%u err=%d\n", port, ret);
	}
#endif

#ifdef HAVE_RTE_ETH_DEV_RESET_2_ARGS
	ret = rte_eth_dev_reset(port, 0);
#else
	ret = rte_eth_dev_reset(port);
#endif
	/* Only VF receives interrupt, bonding int will NOT reset. Also if the
	 * port is bonded, the bond interface must be restarted AFTER the
	 * reset call, otherwise bonding will be broken once PF is back up.
	 */
	if (ifp->aggregator) {
		soft_start_port(ifp->aggregator->if_port);
		if (is_team(ifp->aggregator))
			lag_refresh_actor_state(ifp->aggregator);
	}
	if (ret == -ENODEV || ret == -EINVAL) {
		RTE_LOG(ERR, DATAPLANE,
			"rte_eth_dev_reset: invalid port=%u err=%d\n",
			port, ret);
	} else if (ret == -ENOTSUP) {
		RTE_LOG(NOTICE, DATAPLANE,
			"rte_eth_dev_reset: no reset on HW port=%u err=%d\n",
			port, ret);
	} else if (ret == -EAGAIN || ret == -15) {
		RTE_LOG(DEBUG, DATAPLANE,
			"rte_eth_dev_reset: PF still down port=%u err=%d\n",
			port, ret);

		/* reset failed, start timer to check again. If tim is not
		 * NULL then the call is from the timer, so it's already
		 * running, no need to start it again
		 * -15 is a weird IXGBE specific error code
		 */
		if (!tim && rte_timer_reset(&sc->scd_reset_timer,
				    config.port_update * rte_get_timer_hz(),
				    PERIODICAL, rte_get_master_lcore(),
				    reset_port, ifp) < 0)
			RTE_LOG(ERR, DATAPLANE, "rte_timer_reset failed for "
					"reset timer port:%u\n", port);
		return;
	} else if (ret < 0) {
		/* drivers can return weird errors, catch it and log it */
		RTE_LOG(ERR, DATAPLANE,
			"rte_eth_dev_reset: reset failed on HW port=%u err=%d\n",
			port, ret);
	}

	/* Port is inactive, no races are possible. If tim is NULL then this
	 * is the first call on interrupt and the timer is not running.
	 */
	if (tim)
		rte_timer_stop_sync(tim);

#if RTE_VERSION >= RTE_VERSION_NUM(18,5,0,0)
	/* stop_port has to set need_reset if the timer is running, but
	 * setting it from here would cause a loop
	 */
	eth_dev = &rte_eth_devices[ifp->if_port];
	memcpy(&dev_conf, &eth_dev->data->dev_conf, sizeof(dev_conf));

	sc->scd_need_reset = false;
	reconfigure_port(ifp, &dev_conf, NULL);
#else
	soft_start_port(port);
#endif
}

static void update_queue_state(struct ifnet *ifp)
{
	unassign_queues(ifp->if_port);

	set_port_queue_state(ifp->if_port);

	if (bitmask_isset(&started_port_mask, ifp->if_port))
		assign_queues(ifp->if_port);
}

/* Callback from being woken up on link_fd.
 * Runs on master thread (via get_next_event)
 *
 * irq_mask is used to debounce events so that only one link
 * state change between timer interval is possible
 *
 * For ports that use the queue state events, the queue state was read when
 * the callback was received, so now we need to bring the state into line
 * with the configured set of queues here.
 *
 * Note: rcu_read_lock not held here!
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
			if (bitmask_isset(&started_port_mask, port))
				update_port_status(port, false);
		}

		if (bitmask_isset(&link_reset_pending, port)) {
			bitmask_clear(&link_reset_pending, port);
			if (bitmask_isset(&started_port_mask, port))
				reset_port(NULL, ifport_table[port]);
		}

		if (bitmask_isset(&queue_state_pending, port)) {
			bitmask_clear(&queue_state_pending, port);
			update_queue_state(ifport_table[port]);
		}
	}

	return 0;
}

/* Open eventfd handle used to notify master thread
 * by callbacks called in interrupt thread.
 */
void link_state_init(void)
{
	int fd = eventfd(0, EFD_NONBLOCK);
	if (fd < 0)
		rte_panic("%s: eventfd failed: %s\n",
			  __func__, strerror(errno));

	lsc_arg = (void *) (unsigned long) fd;
	register_event_fd(fd, link_state_event, lsc_arg);
}

/* Start device (admin up) */
void start_port(portid_t port, unsigned int flags)
{
	struct ifnet *ifp = ifport_table[port];
	struct dpdk_eth_if_softc *sc = ifp->if_softc;
	int ret;

	if (slave_count(ifp) == 0) {
		/* A bonding interface might not have any slaves yet. Don't
		 * try to start it since this will result in an error from
		 * rte_eth_dev_start().  Instead, lag_slave_add() will start
		 * the interface (if necessary) when the first slave is added.
		 */
		RTE_LOG(DEBUG, DATAPLANE,
			"no slaves on bonding device %s", ifp->if_name);
		return;
	}

	if (bitmask_isset(&started_port_mask, port))
		return;	 /* already active */

	/* bonding driver will start slave device when ready */
	if (!(flags & IFF_SLAVE)) {
		if (assign_queues(port))
			return; /* failure */

		if (sc->scd_need_reset)
			reset_port(NULL, ifp);

		ret = rte_eth_dev_start(port);
		if (ret < 0 && !sc->scd_need_reset) {
			RTE_LOG(ERR, DATAPLANE,
				"rte_eth_dev_start: port=%u err=%d\n",
				port, ret);
			unassign_queues(port);
			return;
		}

		sc->scd_need_reset = false;
	}

	soft_start_port(port);
}

/* Stop device (admin down) */
void stop_port(portid_t port)
{
	struct ifnet *ifp = ifport_table[port];
	struct dpdk_eth_if_softc *sc = ifp->if_softc;

	if (!bitmask_isset(&started_port_mask, port) &&
	    !rte_timer_pending(&sc->scd_reset_timer))
		return;	 /* already inactive */

	/* if the PF is down when the port is stopped, then it will not work
	 * once it restarts unless rte_eth_dev_reset is called.
	 * But if the timer is simply left running then port will be set to UP
	 * when the PF goes back online, even if it should still be stopped
	 */
	if (rte_timer_pending(&sc->scd_reset_timer)) {
		rte_timer_stop_sync(&sc->scd_reset_timer);
		sc->scd_need_reset = true;
	}

	soft_stop_port(port);

	/* if we're about to yank one of the slaves out from under the bonding
	 * driver, stop the bonding interface first.
	 */
	if (ifp->aggregator) {
		rte_eth_dev_stop(ifp->aggregator->if_port);
		unassign_queues(ifp->aggregator->if_port);
	}

	rte_eth_dev_stop(port);

	unassign_queues(port);

	/*
	 * Some drivers require the HW multicast filter to be reprogrammed when
	 * the interface is next brought up after being taken down, regardless
	 * of whether this filter is already active
	 */
	l2_rx_fltr_set_reprogram(ifp);
}

/*
 * Stop a port when the dataplane port state may not be in sync with
 * the dpdk port state, ensuring that either way the dpdk port is
 * stopped on return.
 */
void force_stop_port(portid_t port)
{
	struct ifnet *ifp = ifport_table[port];
	struct dpdk_eth_if_softc *sc = ifp->if_softc;

	if (!bitmask_isset(&started_port_mask, port) &&
	    !rte_timer_pending(&sc->scd_reset_timer))
		rte_eth_dev_stop(port);
	else
		stop_port(port);
}

/* Stop data transfer */
void stop_all_ports(void)
{
	unsigned int port;

	for (port = 0; port < DATAPLANE_MAX_PORTS; port++) {
		if (bitmask_isset(&started_port_mask, port))
			stop_port(port);
	}
}

/* Port event occurred.
 *
 *  Called from another Posix thread therefore can't safely update
 *  port state directly, need to wakeup master thread
 */
static int
eth_port_event(portid_t port_id, enum rte_eth_event_type type, void *arg,
	       __unused void *ret_arg)
{
	unsigned long link_fd = (unsigned long) arg;
	static const uint64_t incr = 1;
	bool wakeup = false;

	/* Notify master thread, and debounce */
	if (type == RTE_ETH_EVENT_INTR_LSC) {
		/*
		 * If the port uses the queue state events, and it is down
		 * then we have to clear the enabled queues otherwise we
		 * can get into an inconsistent state.
		 */
		if (get_port_uses_queue_state(port_id)) {
			struct rte_eth_link link;

			rte_eth_link_get_nowait(port_id, &link);
			if (link.link_status == ETH_LINK_DOWN)
				reset_port_enabled_queue_state(port_id);
		}
		if (bitmask_isset(&lsc_irq_mask, port_id)) {
			bitmask_clear(&lsc_irq_mask, port_id);
			bitmask_set(&lsc_irq_pending, port_id);
			wakeup = true;
		}
	}

	if (type == RTE_ETH_EVENT_INTR_RESET &&
	    bitmask_isset(&started_port_mask, port_id)) {
		bitmask_set(&link_reset_pending, port_id);
		wakeup = true;
	}

	if (type == RTE_ETH_EVENT_QUEUE_STATE) {
		/*
		 * Pull all the events off the queue, and set the
		 * enabled queus correctly. The master thread will then
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
