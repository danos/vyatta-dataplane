/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/* Internal header for session/isd features */

#ifndef SESSION_FEATURE_H
#define SESSION_FEATURE_H

#include <if_var.h>

#include "session/session.h"

struct ifnet;

/**
 * Init
 *
 * Init the session feature
 */
void session_feature_init(void);

/**
 * Register feature operations.
 *
 * For session syncing (aka: Connsync), feature operations must
 * be registered at feature boot time in order for session syncing
 * to be able to forward the feature to the peer node.
 *
 * Make this call during dataplane initialization.
 *
 * @param type The feature id type.
 *
 * @param ops  The feature operations struct.
 */
void session_feature_register(enum session_feature_type type,
		const struct session_feature_ops *ops);

/**
 * Add a feature datum
 *
 * Adds a session-based, or interface-based feature datum to a
 * session. If the (optional) operations are defined, the
 * 'expire' operation will be called when the session is
 * expired, and the 'destroy' operation will be called when
 * the session is being destroyed.
 *
 * Note if the 'destroy' operation is NULL, then upon destruction 'free()'
 * will be called on the datum.
 *
 * @param s
 * The session
 *
 * @param if_index
 * Interface index for interface-based features.
 * Specify 0 (zero) for session-based.
 *
 * @param type
 * An id for the particular feature.
 *
 * @param data
 * The feature datum.
 *
 */
int session_feature_add(struct session *s, uint32_t if_index,
		enum session_feature_type type, void *data);

/**
 * Feature get.
 *
 * Returns a pointer to the feature datum or NULL.
 *
 * @param s
 * The session.
 *
 * @param if_index
 * Interface index for interface-based features.
 * Specify 0 (zero) for session-based.
 *
 * @param type
 * The id for the feature.
 */
void *session_feature_get(struct session *s, uint32_t if_index,
		enum session_feature_type type);

/*
 * Feature datum request expiration.
 *
 * Request expiration of the feature. The expiration will be performed
 * by the garbage collection thread.
 *
 * @param s
 * The session.
 *
 * @param if_index
 * Interface index for interface-based features.
 * Specify 0 (zero) for session-based.
 *
 * @param type
 * The id of the feature.
 */
int session_feature_request_expiry(struct session *s, uint32_t if_index,
				   enum session_feature_type type);

/**
 * Expiry of features requesting it
 *
 * Called by the GC function if features have requested expiry.
 * It will call the expiry function of each feature requesting it.
 *
 * @param s
 * The session
 */
void session_feature_session_expire_requested(struct session *s);

/**
 * Feature expire
 *
 * Called by session management when a session is expired.  Will
 * traverse all features on this session and request expiry by the GC.
 *
 * @param s
 * The session
 */
void session_feature_session_expire(struct session *s);

/**
 * Feature walk
 *
 * Walk all features for a given session, exeucting the callback
 * for features of a specified 'type'.
 *
 * @param s
 * The session
 *
 * @param type
 * The feature type to match.
 *
 * @param cmd
 * A callback passed the feature datam
 */
typedef int (session_feature_walk_t)(struct session *s,
		struct session_feature *sf, void *data);
int session_feature_walk_session(struct session *s,
		enum session_feature_type type,
		session_feature_walk_t *cb,
		void *data);

#endif /* SESSION_FEATURE_H */
