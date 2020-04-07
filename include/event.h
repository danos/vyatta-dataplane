/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VYATTA_DATAPLANE_EVENT_H
#define VYATTA_DATAPLANE_EVENT_H

#include <czmq.h>

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
 * The processing is always done on the master thread. The main use of
 * this function is to allow events to be sent to the master thread where
 * they will then be processed in turn. No guarantees are given about
 * how quickly these events are processed. Typically the master thread
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

#endif /* VYATTA_DATAPLANE_EVENT_H */
