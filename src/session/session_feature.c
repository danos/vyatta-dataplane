/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2017 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <rte_atomic.h>
#include <stdint.h>
#include <stdlib.h>

#include "compiler.h"
#include "dp_xor_hash.h"
#include "if_var.h"
#include "session.h"
#include "session_feature.h"
#include "urcu.h"
#include "util.h"
#include "session_private.h"

/*
 * session features...
 *
 * Individual features have the ability to add data to a
 * session handle for reference between packets.
 *
 * Features use a well-known enum (session_feature_type) and the datum can
 * be session-specific, or interface-specific.  Only a single feature datum
 * of each kind (per feature type) can be added.
 *
 * Features can register optional callbacks with the datum, and these
 * callbacks are executed as the session changes state.
 *
 * Note if your feature expects to have it mirrored to the peer node during
 * a session sync operation (aka: Connsync) is *must* register its operations.
 * Otherwise the peer node has no idea how to reconstruct your feature datum.
 *
 * If no ops are specified, or no 'destroy' callback in the ops defined,
 * then free() is called on the datum.
 *
 * Features are guaranteed no in-flight access exists when the destroy
 * callback is executed.  Features should NOT call 'call_rcu()' to free
 * their data, they are already in a call_rcu context.
 *
 * Note that two hash tables are used here, one for searching features and
 * the other for searching features by session.  See the comments in
 * session_table.c for the rational.
 *
 * NOTE:
 * Although tempting, we cannot safely walk the feature hash table due to a
 * possible race.  The session GC will destroy features in a call_rcu context,
 * and will execute the feature destroy by nesting the destroy in the same
 * call_rcu context.  This means that feature destroy (via GC) must be
 * considered synchronous w/o an intervening RCU grace period.
 *
 * Consequently a race exists if we were to (directly) walk the feature table.
 * If you need to see all features, walk the session table and do 'get's on
 * the feature type.
 *
 */

/*
 * Array for holding registered session feature operations
 */
const struct session_feature_ops *feature_operations[SESSION_FEATURE_END];

/* Hash table */
#define FHT_INIT 128
#define FHT_MIN	 1024
#define FHT_MAX	 65536
static struct cds_lfht *feature_ht;
static struct cds_lfht *session_ht;

/* Hash for adding features */
static ALWAYS_INLINE
unsigned long sf_hash(struct session *s, uint32_t idx,
		enum session_feature_type type)
{
	return dp_xor_2words(s->se_id, idx, type);
}

/* For session matching */
static ALWAYS_INLINE
int sf_sess_match(struct cds_lfht_node *node, const void *key)
{
	const struct session *s = key;
	struct session_feature *sf = caa_container_of(node,
				struct session_feature, sf_session_node);

	return s == sf->sf_session;
}

/* Match on session/idx/type */
static ALWAYS_INLINE
int sf_match(struct cds_lfht_node *node, const void *key)
{
	const struct session_feature *sf_key = key;
	struct session_feature *sf = caa_container_of(node,
				struct session_feature, sf_node);

	if (sf->sf_type != sf_key->sf_type)
		return 0;
	if (sf->sf_session != sf_key->sf_session)
		return 0;
	/* idx is optional */
	if (sf_key->sf_idx && sf->sf_idx != sf_key->sf_idx)
		return 0;
	return 1;
}

/* RCU destroy a feature */
static void sf_rcu_destroy(struct rcu_head *h)
{
	struct session_feature *sf = caa_container_of(h, struct session_feature,
			sf_rcu_head);

	if (!sf->sf_ops)
		return;

	if (sf->sf_ops->destroy) {
		sf->sf_ops->destroy(sf->sf_session, sf->sf_idx, sf->sf_type,
				sf->sf_data);

	} else
		free(sf->sf_data);

	rte_atomic32_dec(&session_rcu_counter); /* For UT cleanup sync */
	free(sf);
}

/* Expire a feature */
static void sf_expire(struct session_feature *sf)
{
	/* Delete the feature from the feature tables, but only once.  */
	if (cds_lfht_del(feature_ht, &sf->sf_node))
		return;

	rte_atomic16_dec(&sf->sf_session->se_feature_count);

	cds_lfht_del(session_ht, &sf->sf_session_node);

	/* Log the deletion of the session, if enabled */
	if (sf->sf_session->se_log_deletion && sf->sf_ops && sf->sf_ops->log)
		sf->sf_ops->log(SESSION_LOG_DELETION, sf->sf_session, sf);

	/* Call the 'expire' op if present */
	if (sf->sf_ops && sf->sf_ops->expired) {
		sf->sf_ops->expired(sf->sf_session, sf->sf_idx, sf->sf_type,
				sf->sf_data);
	}

	/* Finish up and Destroy */
	rte_atomic32_inc(&session_rcu_counter); /* For UT cleanup sync */
	call_rcu(&sf->sf_rcu_head, sf_rcu_destroy);
}

/* Request that a feature be expired at the next GC call */
static void sf_request_expiry(struct session_feature *sf)
{
	uint16_t exp = sf->sf_flags & ~SESS_FEAT_REQ_EXPIRY;

	if (rte_atomic16_cmpset(&sf->sf_flags, exp,
				(exp | SESS_FEAT_REQ_EXPIRY))) {
		rte_atomic16_inc(&sf->sf_session->se_feature_exp_count);
		sf->sf_expire_time = rte_get_timer_cycles();
	}
}

/* Lookup and return a  feature */
static struct session_feature *sf_lookup(struct session *s,
		uint32_t if_index, enum session_feature_type type)
{
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct session_feature sf;
	unsigned long hash;

	/*
	 * For session-specific feature lookups, if_index == 0.
	 * For interface-specific feature lookups, if_index != 0.
	 */
	sf.sf_idx = if_index;
	sf.sf_session = s;
	sf.sf_type = type;

	hash = sf_hash(s, sf.sf_idx, type);
	cds_lfht_lookup(feature_ht, hash, sf_match, &sf, &iter);
	node = cds_lfht_iter_get_node(&iter);

	return node ? caa_container_of(node, struct session_feature, sf_node) :
		NULL;
}

/* Uniquely add a session feature */
int session_feature_add(struct session *s, uint32_t if_index,
		enum session_feature_type type, void *data)
{
	struct session_feature	*sf;
	struct cds_lfht_node *node;
	unsigned long hash;

	/* Never for an expired session */
	if (s->se_flags & SESSION_EXPIRED)
		return -EINVAL;

	sf = malloc_aligned(sizeof(struct session_feature));
	if (!sf)
		return -ENOMEM;

	cds_lfht_node_init(&sf->sf_node);
	cds_lfht_node_init(&sf->sf_session_node);
	sf->sf_session = s;
	sf->sf_idx = if_index;
	sf->sf_type = type;
	sf->sf_data = data;
	sf->sf_ops = feature_operations[type];
	sf->sf_expire_time = 0;
	sf->sf_flags = 0;

	hash = sf_hash(s, sf->sf_idx, type);
	node = cds_lfht_add_unique(feature_ht, hash, sf_match,
			sf, &sf->sf_node);
	if (node != &sf->sf_node) {
		free(sf);
		return -EEXIST;
	}

	cds_lfht_add(session_ht, s->se_id, &sf->sf_session_node);

	/* Possible race with session expiration, deal with it now */
	if (s->se_flags & SESSION_EXPIRED)
		sf_request_expiry(sf);

	/* Inc counter on session */
	rte_atomic16_inc(&s->se_feature_count);

	return 0;
}

/* Lookup and return a session feature datum */
void *session_feature_get(struct session *s, uint32_t if_index,
		enum session_feature_type type)
{
	struct session_feature *sf;

	/* No point if this session has no feature data */
	if (!rte_atomic16_read(&s->se_feature_count))
		return NULL;

	sf = sf_lookup(s, if_index, type);

	return sf ? sf->sf_data : NULL;
}

/* Request expiry of a specific feature */
int session_feature_request_expiry(struct session *s, uint32_t if_index,
		enum session_feature_type type)
{
	struct session_feature *sf;

	/* No point if this session has no feature data */
	if (!rte_atomic16_read(&s->se_feature_count))
		return -ENOENT;

	sf = sf_lookup(s, if_index, type);
	if (sf) {
		sf_request_expiry(sf);
		return 0;
	}

	return -ENOENT;
}

/* Expire features on this session which requested it */
void session_feature_session_expire_requested(struct session *s)
{
	struct session_feature *sf;
	struct cds_lfht_iter iter;

	cds_lfht_for_each_entry_duplicate(session_ht, s->se_id, sf_sess_match,
			s, &iter, sf, sf_session_node) {

		if (sf->sf_flags & SESS_FEAT_REQ_EXPIRY) {
			sf_expire(sf);
			if (rte_atomic16_dec_and_test(&s->se_feature_exp_count))
				break;
		}
	}

	/* Last one out turns off the lights... */
	if (!rte_atomic16_read(&s->se_feature_count))
		session_expire(s, NULL);
}

/* Expire all features on this session */
void session_feature_session_expire(struct session *s)
{
	struct session_feature *sf;
	struct cds_lfht_iter iter;

	/* Nothing to do */
	if (!rte_atomic16_read(&s->se_feature_count))
		return;

	cds_lfht_for_each_entry_duplicate(session_ht, s->se_id, sf_sess_match,
			s, &iter, sf, sf_session_node)
		sf_request_expiry(sf);
}

/*
 * Walk all features for a given session, executing 'cb' for features
 * of a given 'type'.
 */
int session_feature_walk_session(struct session *s,
		enum session_feature_type type, session_feature_walk_t *cb,
		void *data)
{
	struct session_feature *sf;
	struct cds_lfht_iter iter;
	int rc = 0;

	/* Nothing to do */
	if (!rte_atomic16_read(&s->se_feature_count))
		return rc;

	cds_lfht_for_each_entry_duplicate(session_ht, s->se_id, sf_sess_match,
			s, &iter, sf, sf_session_node) {
		if (type == SESSION_FEATURE_ALL || sf->sf_type == type) {
			rc = cb(s, sf, data);
			if (rc)
				break;
		}
	}
	return rc;
}

void session_feature_register(enum session_feature_type type,
		const struct session_feature_ops *ops)
{
	feature_operations[type] = ops;
}

void session_feature_init(void)
{
	feature_ht = cds_lfht_new(FHT_INIT, FHT_MIN, FHT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
	session_ht = cds_lfht_new(FHT_INIT, FHT_MIN, FHT_MAX,
			CDS_LFHT_AUTO_RESIZE | CDS_LFHT_ACCOUNTING, NULL);
}

