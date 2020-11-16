/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VYATTA_DATAPLANE_EVENT_H
#define VYATTA_DATAPLANE_EVENT_H

#include <czmq.h>
#include "vrf.h"

struct ifnet;

/*
 * Callback function to process events received on sockets.
 *
 * @param[in, out] arg Argument that was passed when the socket
 *                     was registered.
 *
 * @return 0 for success
 * @return -ve for a failure.
 */
typedef int (*ev_callback_t)(void *arg);

/*
 * Register a socket and a callback function to process messages on that
 * socket. Messages received on the socket will be retrieved and passes
 * to the handler for processing.
 *
 * The processing is always done on the main thread. The main use of
 * this function is to allow events to be sent to the main thread where
 * they will then be processed in turn. No guarantees are given about
 * how quickly these events are processed. Typically the main thread
 * will pull all messages out of a socket before moving on to the next one
 * and so there may be significant delay during busy periods.
 *
 * If there is a failure processing the message (callback returns a
 * -ve number) then no more messages will be read from that socket
 * and it will be unregistered.
 *
 * @param[in] socket The socket to pull events from
 * @param[in] callback The callback function to that processes the events
 * @param[in] arg Argument passed through to the callback
 *
 * @return 0 if successful
 * @return -ve for a failure
 */
int dp_register_event_socket(void *socket, ev_callback_t callback, void *arg);

/*
 * Unregister a previously registered socket
 *
 * @param[in] socket The socket to stop listening to
 *
 * @return 0 if successful
 * @return -ve for a failure
 */
int dp_unregister_event_socket(void *socket);

/*
 * Send an event to vplaned. This function will push appropriate headers
 * and send it to vplaned where it will be processed.
 *
 * @param [in] msg The event message to send.
 *
 * @return 0 if successful
 * @return -ve for a failure
 */
int dp_send_event_to_vplaned(zmsg_t *msg);

/*
 * The set of events that used can register for notification of.
 */
enum dp_event {
	DP_EVENT_VRF_CREATE = 1,
	DP_EVENT_VRF_DELETE,
	DP_EVENT_IF_RENAME,
	DP_EVENT_IF_VRF_SET,
	DP_EVENT_IF_ADDR_ADD,
	DP_EVENT_IF_ADDR_DEL,
	DP_EVENT_IF_CREATE,
	DP_EVENT_IF_DELETE,
};

enum dp_if_lag_event {
	DP_IF_LAG_EVENT_MIN_LINKS_CHANGE,
};

/*
 * Structure that users can use to register callbacks for certain types of
 * events.
 */
struct dp_events_ops {
	/* DP_EVENT_VRF_CREATE */
	void (*vrf_create)(struct vrf *vrf);
	/* DP_EVENT_VRF_DELETE */
	void (*vrf_delete)(struct vrf *vrf);
	/* DP_EVENT_IF_CREATE */
	void (*if_create)(struct ifnet *ifp);
	/* DP_EVENT_IF_DELETE */
	void (*if_delete)(struct ifnet *ifp);
	/* DP_EVENT_IF_RENAME */
	void (*if_rename)(struct ifnet *ifp, const char *old_name);
	/* DP_EVENT_IF_VRF_SET */
	void (*if_vrf_set)(struct ifnet *ifp);
	/* DP_EVENT_IF_ADDR_ADD */
	void (*if_addr_add)(struct ifnet *ifp, uint32_t ifindex, int af,
			    const void *addr);
	/* DP_EVENT_IF_ADDR_DEL */
	void (*if_addr_delete)(struct ifnet *ifp,
			uint32_t ifindex, int af, const void *addr);
	/* DP_EVT_IF_LAG_CHANGE */
	void (*if_lag_change)(struct ifnet *ifp, enum dp_if_lag_event event);
	/* DP_EVT_IF_LAG_ADD_MEMBER */
	void (*if_lag_add_member)(struct ifnet *team,
				  struct ifnet *ifp);
	/* DP_EVT_IF_LAG_DELETE_MEMBER */
	void (*if_lag_delete_member)(struct ifnet *team,
				     struct ifnet *ifp);
};

/*
 * Register an event ops structure with callbacks that will be called for
 * each of the given event types.
 *
 * @param [in] ops The set of callbacks. If a callback is provided then it
 *                 will be called for each event of that type.  Entries
 *                 can be set to NULL if the caller is not interested in
 *                 some of the events.
 *
 * @return 0 if successful
 * @return -ve for a failure
 */
int dp_events_register(const struct dp_events_ops *ops);

/*
 * Unregister a previously registered set of callbacks.
 *
 * @param [in] ops The set of callbacks to unregister
 *
 * @return 0 if successful
 * @return -ve for a failure
 */
int dp_events_unregister(const struct dp_events_ops *ops);

#endif /* VYATTA_DATAPLANE_EVENT_H */
