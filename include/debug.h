/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VYATTA_DATAPLANE_DEBUG_H
#define VYATTA_DATAPLANE_DEBUG_H

#include <rte_log.h>
#include <stdbool.h>

/*
 * Intro
 * =====
 *
 * The dataplane debug is built on top of the dpdk rte_log infra.
 * That provides different users of logging, and features can add
 * themselves to those groups.
 *
 * Logging
 * =======
 *
 * The default logging level is RTE_LOG_INFO, and this can be changed
 * by calling dpdk APIs.
 *
 * The dataplane uses 5 of the dpdk user types as well as the built in
 * dpdk types.
 *
 * RTE_LOGTYPE_USER1 for infrastructure debugs
 * RTE_LOGTYPE_USER2 for layered devices, bridges, tunnels, etc
 * RTE_LOGTYPE_USER3 for routing, arp etc.
 * RTE_LOGTYPE_USER4 for features
 * RTE_LOGTYPE_USER4 for crypto
 *
 * Features can add their own defined user type: For example:
 *
 * #define RTE_LOGTYPE_MY_FEATURE RTE_LOGTYPE_USER4
 *
 * Features can then log by calling the dpdk log function
 * rte_log() and using their own defined user type. If the
 * log level specified is equal or higher that the configured
 * logging level then the log will be shown.
 * There are 2 configured logging levels, a global one and a
 * per type one. Logs are shown if both levels are high enough.
 *
 * For example:
 *     rte_log(RTE_LOG_INFO, RTE_LOGTYPE_MY_FEATURE,
 *             "my feature debug %s", "is on");
 *
 *
 *
 * Debug
 * =====
 *
 * A debug service is also offered where debug for individual 'events' can
 * be registered and enabled/disabled. If the debug bit for the 'event' is
 * not set then there is no call to the log. To make debug arrive at the
 * log the logging level needs to be changed to RTE_LOG_DEBUG.
 */

/*
 * The log type for general dataplane debugs/logs.
 */
#define RTE_LOGTYPE_DATAPLANE	RTE_LOGTYPE_USER1

/*
 * Register an event type. Debug for this event type can then be turned on/off
 * and the ID returned can then be used in calls to the debug macro. If that
 * event is enabled then the debug will be generated, otherwise it will not be.
 * In the case when the debug is not enabled the only cost will be the check
 * to see if that debug type is enabled.
 *
 * This must be called on the master thread.
 *
 * @param[in] event_type A string representing a debug event type.
 * @return A value that has a single bit set. This can then be used as the
 *         event_id in the DP_DEBUG_EVENT macro
 *         0 for failure
 */
uint64_t dp_debug_register(const char *event_type);

/*
 * Enable the given debug type. The type must already be registered.
 *
 * @param[in] event_type An already registered event type.
 * @return 0 for success
 *         -ve for failure
 */
int dp_debug_enable(const char *event_type);

/*
 * Disable the given debug type. The type must already be registered.
 *
 * @param[in] event_type An already registered event type.
 * @return 0 for success
 *         -ve for failure
 */
int dp_debug_disable(const char *event_type);

/*
 * Is the given debug event id enabled.
 *
 * @param[in] event_id An event id returned when registering an event type.
 *
 * @return true is the debug type is enabled
 *         false if the debug type is not enabled
 */
bool dp_debug_is_enabled(uint64_t event_id);

/*
 * Macro to selectively enable logging by feature. If the given debug event
 * is enabled then generate a debug message. This message will only make it
 * to the log if the level specified is equal to or higher than the
 * configured logging levels (the global level and the level for the type).
 *
 * @param[in] event_id The event id returned when registering an event type
 * @param[in] level  The level is between EMERG and DEBUG
 *                   (note does not include the RTE_LOG at the start.
 * @param[in] type The type should be the type defined for this feature,
 *                 for example MY_FEATURE based on the definition of
 *                 RTE_LOGTYPE_MY_FEATURE.
 */
#define DP_DEBUG_EVENT(event_id, level, type, fmt, args...)	do {	\
	if (unlikely(dp_debug_is_enabled(event_id)))		        \
		rte_log(RTE_LOG_##level, RTE_LOGTYPE_##type,	        \
			#type ": " fmt, ## args);		        \
	} while (0)

#endif /* VYATTA_DATAPLANE_DEBUG_H */
