/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef VYATTA_DATAPLANE_LCORE_SCHED_H
#define VYATTA_DATAPLANE_LCORE_SCHED_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Intro
 * =====
 *
 * The dataplane has 2 main types of threads. Those which run on dedicated
 * lcores and are typically used for forwarding packets and are referred to
 * as forwarders.  The second type is those that are used for all other
 * work.
 *
 * Forwarding threads
 * ==================
 *
 * The forwarding threads run on dedicated logical cores (lcores) that have
 * no other processing occurring on them other than some kernel threads that
 * can not be moved. There is one forwarding thread per lcore. If the
 * thread is not being used as there is no work assigned to it then the lcore
 * it is associated with is made available for the rest of the system.
 *
 * The goal of the forwarding threads is to do the packet processing as
 * quickly as possible so that we can process as many packets as possible with
 * very low latency.
 *
 * A forwarding thread can have multiple pieces of work, and in that case
 * it will round robin over each work source checking if there is work to
 * do, and doing it.  The sources of work are
 *  - interface rx queues. Check if packets have arrived and process them
 *  - interface tx queues. Check if there are packets to send, and send them
 *  - crypto. Check if there are packets that have been queued for crypto
 *    processing, and process them.
 *
 * The user can set the lcores that the interface processing should happen
 * on on a system basis, or on a per interface basis. The set of lcores to
 * use for crypto processing can also be specified.  If these are set then
 * they are respected, and these lcores can only be used for the specified
 * work items types.  If these are not set then each work item will be
 * assigned an lcore as it is created. The system assigns weights to each work
 * item and tries to give each lcore an equal workload.
 *
 * There are features other than packet processing that either require
 * significant scale, or low latency that are ideal candidates for running
 * on a dedicated forwarder. API are provided to allow this. When these APIs
 * are used the lcore becomes dedicated to the feature that requests it and
 * will do no further packet processing. An lcore that has configuration
 * specifying either interface or crypto processing on it can not be allocated
 * to a feature.  An lcore doing crypto work due to arbitrary allocation can
 * not be assigned to a feature. An lcore processing interface queues due to
 * an arbitrary allocation can be assigned to a feature, and in that case the
 * interface queue processing will be moved to a different lcore.
 *
 * Other threads
 * =============
 * By default the other threads in the dataplane all run on the 'master' lcore
 * which is lcore 0 by default. This means that they are many threads all
 * sharing the same logical core, and probably sharing it with many other
 * processes too. If there are features that have work to do in a non
 * forwarding lcore, but it is too much for a single lcore to do then the
 * feature can request a forwarding thread where it can do this work.
 */

/*
 * A callback function type for the foreach lcore iterator funcs.
 *
 * @param lcore The id of the lcore the callback is for.
 * @param arg Argument passed through to allow the caller to
 *        provide state to the callback.
 *
 * @return 0 for success, -ve for error.
 */
typedef int (dp_per_lcore_fn)(unsigned int lcore, void *arg);

/*
 * Iterator functions to run a callback for each of the lcores.
 * Depending on the iterator it runs for either all lcores or just the
 * forwarding lcores. (Forwarding lcores are all apart from the master lcore)
 * Note that it will run for all the lcores even those that are not currently
 * active.
 *
 * @param func Callback function to call per lcore
 * @param arg State that is passed through to the callback function.
 *
 * @return 0 for success. If any of the callback functions return a non
 *         zero value then the walk will stop and that value will be returned.
 */
int dp_foreach_lcore(dp_per_lcore_fn *fn, void *arg);
int dp_foreach_forwarding_lcore(dp_per_lcore_fn *fn, void *arg);


/*
 * Is the given lcore active. The master lcore is always active. A forwarding
 * lcore may be active or inactive.
 *
 * @return True if the lcore is active
 * @return False if the lcore is inactive or an invalid lcore id was given.
 */
bool dp_lcore_is_active(unsigned int lcore);

/*
 * Structure holding callbacks that can be used to create/delete feature
 * state when a lcore becomes active/inactive.
 */
struct dp_lcore_events {
	/*
	 * Function called when a new lcore becomes active. The arg is passed
	 * through from the registration call.
	 */
	int (*dp_lcore_events_init_fn)(unsigned int lcore_id, void *arg);
	/*
	 * Function called when a lcore becomes inactive. The arg is passed
	 * through from the registration call.
	 */
	int (*dp_lcore_events_teardown_fn)(unsigned int lcore_id, void *arg);
};

/*
 * Register callbacks to be called for each lcore that is active.
 * As lcores become active/inactive the registered init/teardown funcs will
 * be called. This allows features to have per lcore state where they need
 * to keep stats/state on each lcore.
 *
 * The callback happens on the lcore that has been made active/inactive.
 * The callbacks do not get called for already active lcores. Registration
 * needs to be done before the forwarding lcores are made active if that is
 * required.
 *
 * This function must be called on the master thread.
 *
 * @param[in] events Structure containing the per event callbacks.
 * @param[in, out] arg Argument structure passed through to the callbacks.
 *
 * @return 0 on success
 *         -EINVAL for invalid arguments
 *         -ENOMEM if not enough memory to register the callbacks.
 */
int dp_lcore_events_register(const struct dp_lcore_events *events,
			     void *arg);

/*
 * Unregister a previously registered set of callbacks.
 *
 * This function must be called on the master thread.
 *
 * @param[in] events The set of pointers that were previously registered.
 *
 * @return 0 on success
 *         -EINVAL for invalid arguments
 *         -ENOENT if there was no existing entry
 */
int dp_lcore_events_unregister(const struct dp_lcore_events *events);


/*
 * The possible uses of lcores in the dataplane. There is one master thread
 * that always runs on the master lcore. All threads that this creates also
 * run on the master lcore.  All the other lcores can be used as forwarders
 * or for features.
 */
enum dp_lcore_use {
	/*
	 * The Master thread. This will run on the lowest number lcore,
	 * typically 0, but this can be changed by config.
	 */
	DP_LCORE_MASTER,
	/*
	 * A packet forwarder. This thread should be processing packets
	 * as fast as possible, with low latency. Should avoid syscalls
	 * and long delays. Processes interface and crypto queues.
	 */
	DP_LCORE_FORWARDER,
	/*
	 * An lcore dedicated to a feature because it needs too much processing,
	 * or has certain latency requirements.
	 */
	DP_LCORE_FEATURE,
	/*
	 * An lcore in none of the above states, or perhaps one that doesn't
	 * exist.
	 */
	DP_LCORE_INVALID,
};

/*
 * What is the given lcore being used for
 *
 * @param[in] lcore The lcore to return the state of.
 *
 * @return The state of the given lcore or DP_LCORE_INVALID if not in
 *         any of the other states.
 */
enum dp_lcore_use dp_lcore_get_current_use(unsigned int lcore);

#define DP_LCORE_FEAT_MAX_NAME_SIZE 16
struct dp_lcore_feat {
	/*
	 * The name of the feature that is using this lcore.
	 */
	char name[DP_LCORE_FEAT_MAX_NAME_SIZE];
	/*
	 * Function to run the feature work on the given lcore. This function
	 * is expected to loop doing the feature work. It should return only
	 * when the feature is being unconfigured.
	 *
	 * @param[in] lcore_id The lcore this function is running on. This is
	 *            useful when there is lcore specific state being stored.
	 * @param[in] arg Context argument passed through to function.
	 *
	 * @return 0 on success, -ve on error.
	 */
	int (*dp_lcore_feat_fn)(unsigned int lcore_id, void *arg);
	/*
	 * The dataplane can be asked to report stats on a regular basis.
	 * If the feature wants to report those stats then it should
	 * populate one or both of these functions.
	 *
	 * @param[in] lcore_id The lcore to get the stats for
	 * @param[out] pkts The number of packets rx/tx'ed on this lcore.
	 *
	 * Note: not all features deal in packets/bytes. If the feature needs
	 *       to report something different, for example 'sessions'
	 *       then it should store this in the pkts field and ignore the
	 *       bytes field.
	 */
	void (*dp_lcore_feat_get_rx)(unsigned int lcore_id,
				     uint64_t *pkts);
	void (*dp_lcore_feat_get_tx)(unsigned int lcore_id,
				     uint64_t *pkts);
};


/*
 * Change the given lcore to being a feature lcore. There
 * are some restrictions here:
 *  - Only lcores of type DP_LCORE_FORWARDER can be changed.
 *  - There must be at least one lcore of type DP_LCORE_FORWARDER remaining
 *    after the change.
 *  - lcores doing crypto work can not be changed.
 *
 * @param[in] lcore The lcore to make a DP_LCORE_FEATURE lcore.
 * @param[in] dp_lcore_feat Structure holding function pointers for
 *            this feature.
 *
 * @return 0 for success
 *         -EBUSY if the lcore is a FORWARDER and has been configured
 *          for interface/crypto work
 *         -ve for failure
 */
int
dp_allocate_lcore_to_feature(unsigned int lcore,
			     struct dp_lcore_feat *feat);

/*
 * Change a lcore that has been allocated to features back to being
 * a forwarding lcore.
 *
 * @param[in] lcore The lcore to return back to a forwarder.
 *
 * @return 0 for success
 *         -ve for failure
 */
int dp_unallocate_lcore_from_feature(unsigned int lcore);

/*
 * Set up a per lcore packet bust. A pkt_burst is used to store a batch of
 * packets that are all being sent to the same place, for example out of
 * the same interface.  Each forwarding lcore sends packets to an lcore
 * specific packet burst as an interim step on the way to sending the packet.
 * If the packet burst gets full all the packets in it are immediately sent.
 * If a packet is added to a packet burst and the output interface is
 * different to the previously added packet then the packets in the burst
 * are sent and the new packet it then added as the only packet in the burst.
 * If the burst is not filled, or the interface does not change then the
 * packets in the burst are send within a reasonable timeframe.
 *
 * This is there as an optimisation so that the cost of enqueuing packets onto
 * the output rings of the interfaces is amortised over multiple packets. All
 * lcores that are packet forwarders have their own packet bursts.
 *
 * This API allows a user to create a packet burst on an lcore that is dedicated
 * to a feature. It creates the burst on the lcore it is called on.
 */
void dp_pkt_burst_setup(void);

/*
 * Free the packet burst associated with this lcore.
 */
void dp_pkt_burst_free(void);

/*
 * APIs that send packets out of an interface typically put them on the
 * intermediate pkt_burst for performance reasons.  If a feature has
 * latency requirements and is generating packets then they can force them
 * to be sent to the interface immediately by calling this function. The
 * burst that is flushed is the one that is on the lcore that this call
 * is made on.
 */
void dp_pkt_burst_flush(void);

/**
 * Is this the master thread.
 *
 * @return true if master thread.
 *         false it not the master thread.
 */
bool is_master_thread(void);

/*
 * Assert that this is the master thread. Kill the process if not
 */
#define ASSERT_MASTER() \
{        if (!is_master_thread()) rte_panic("not on master thread\n");	\
}

#endif /* VYATTA_DATAPLANE_LCORE_SCHED_H */
