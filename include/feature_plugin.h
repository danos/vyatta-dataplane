/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef VYATTA_DATAPLANE_FEATURE_PLUGIN_H
#define VYATTA_DATAPLANE_FEATURE_PLUGIN_H

/*
 * Intro
 * =====
 *
 * The feature plugin layer is designed to allow features for the dataplane to
 * be plugged in without having to modify the core dataplane code.
 *
 * Plugin libraries are installed in a known location and the dataplane will
 * search for them when it is starting up.
 *
 * This plugin library functions that the dataplane will call are all in this
 * file. A feature plugin need not implement all of them.
 *
 * There are also various helper APIs in other files in this directory that
 * the plugins can use within its code. These allow access to some of the
 * internals of the dataplane which is necessary for some types of feature.
 *
 * Packet Processing
 * =================
 * A feature may need to do packet processing. If it does then this will all
 * be done via the packet pipeline APIs. The pipeline APIs all allow nodes to
 * be inserted in the pipeline and are described fully in pipeline.h
 *
 * Command Processing
 * ==================
 *
 * A feature is likely to require configuring, and this is done by registering
 * a configuration handler. This handler will be called when messages are
 * received over the configuration channel for the given feature. The format
 * of the messages is expected to be protocol buffers, version2. The handler
 * will be given the protobuf message and it then needs to decode it and make
 * the appropriate changes to the system, for example enabling a node in the
 * packet pipeline.
 *
 * Show commands
 * =============
 *
 * A feature is likely to require show commands, and this is done by
 * registering a show command handler. This handler will be called whenever
 * a request for a feature show command is received over the show commands
 * channel. The format of the show command request is expected to be a
 * string with space delimited words. The return value is expected to be a
 * JSON formatted message.
 */

/*
 * Initialise a new plugin. Each plugin must provide an implementation of
 * this function.
 *
 * This function do any work require to set up the feature plugin. At the
 * stage this is called the feature configuration will not yet have been
 * received by the dataplane.
 *
 * @param[out] name The name of the feature. This will be used in the
 *                  show command output. The feature should fill in this
 *                  name. This name should also be used as the 'plugin_name'
 *                  for any pipeline features that are registered.
 * @return 0 on success
 */
int dp_feature_plugin_init(const char **name);

/*
 * Cleanup the resources a plugin was using. Each plugin should cleanup
 * properly when this is called.
 *
 * @return 0 on success
 */
int dp_feature_plugin_cleanup(void);

#endif /* VYATTA_DATAPLANE_FEATURE_PLUGIN_H */

