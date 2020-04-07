/*
 * Copyright (c) 2018-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Whole dataplane test npf session library
 */

#ifndef __DP_TEST_SESSION_INTERNAL_LIB_H__
#define __DP_TEST_SESSION_INTERNAL_LIB_H__

#include "session/session.h"
#include "session/session_feature.h"

int _dp_test_session_establish(struct rte_mbuf *m, const struct ifnet *ifp,
		uint32_t timeout, struct session **se, bool *created,
		const char *file, int line);
#define dp_test_session_establish(m, ifp, timeout, se, created) \
	_dp_test_session_establish(m, ifp, timeout, se, created,\
			__FILE__, __LINE__)

int _dp_test_session_lookup(struct rte_mbuf *m, uint32_t if_index,
		struct session **se, bool *forw);
#define dp_test_session_lookup(m, if_index, se, forw)  \
	_dp_test_session_lookup(m, if_index, se, forw)

void _dp_test_session_expire(struct session *se, struct rte_mbuf *m,
		const char *file, int line);
#define dp_test_session_expire(se, m) \
	_dp_test_session_expire(se, m,  __FILE__, __LINE__)

int _dp_test_session_sentry_insert(struct session *se, uint32_t if_index,
		uint16_t flags, uint16_t sid, void *saddr, uint16_t did,
		void *daddr, const char *file, int line);
#define dp_test_session_sentry_insert(se, if_index, flags, sid, saddr, \
		did, daddr)  \
	_dp_test_session_sentry_insert(se, if_index, flags, sid, saddr, \
		did, daddr, __FILE__, __LINE__)

int _dp_test_session_create_from_sentry_packets(struct rte_mbuf *m,
		struct sentry_packet *sp_forw, struct sentry_packet *sp_back,
		const struct ifnet *ifp, uint32_t timeout,
		struct session **se, bool *created, const char *file, int line);
#define dp_test_session_create_from_sentry_packets(m, sp_forw, sp_back,    \
		ifp, timeout, se, created)                                 \
	_dp_test_session_create_from_sentry_packets(m, sp_forw, sp_back,   \
			ifp, timeout, se, created, __FILE__, __LINE__)

int _dp_test_session_init_sentry_packet(struct sentry_packet *sp,
		uint32_t if_index, uint16_t flags, uint8_t proto,
		vrfid_t vrfid, uint16_t sid, void *saddr,
		uint16_t did, void *daddr, const char *file, int line);
#define dp_test_session_init_sentry_packet(sp, if_index, flags, proto,  \
		vrfid, sid, saddr, did, daddr)                \
	_dp_test_session_init_sentry_packet(sp, if_index, flags, proto, \
			vrfid, sid, saddr, did, daddr, __FILE__, __LINE__)


void _dp_test_session_reset(const char *file, int line);
#define dp_test_session_reset() \
		_dp_test_session_reset(__FILE__, __LINE__)

int _dp_test_session_feature_add(struct session *se, uint32_t if_index,
		enum session_feature_type type, void *data,
		const char *file, int line);
#define dp_test_session_feature_add(se, if_index, type, data) \
	_dp_test_session_feature_add(se, if_index, type, data, \
			__FILE__, __LINE__)

void *_dp_test_session_feature_get(struct session *se, uint32_t if_index,
		enum session_feature_type type);
#define dp_test_session_feature_get(se, if_index, type) \
	_dp_test_session_feature_get(se, if_index, type)

int _dp_test_session_feature_request_expiry(struct session *se,
		uint32_t if_index, enum session_feature_type type,
		const char *file, int line);
#define dp_test_session_feature_request_expiry(se, if_index, type) \
	_dp_test_session_feature_request_expiry(se, if_index, type, __FILE__, \
	__LINE__)

int _dp_test_session_link(struct session *parent, struct session *child,
		const char *file, int line);
#define dp_test_session_link(parent, child) \
	_dp_test_session_link(parent, child, __FILE__, __LINE__)

int _dp_test_session_unlink(struct session *se, const char *file, int line);
#define dp_test_session_unlink(parent) \
	_dp_test_session_unlink(parent, __FILE__, __LINE__)

struct session *_dp_test_session_base_parent(struct session *se,
		const char *file, int line);
#define dp_test_session_base_parent(s) \
	_dp_test_session_unlink(s, __FILE__, __LINE__)

void _dp_test_session_gc(const char *file, int line);
#define dp_test_session_gc() \
	_dp_test_session_gc(__FILE__, __LINE__)

void _dp_test_session_unlink_all(struct session *s, const char *file, int line);
#define dp_test_session_unlink_all(s) \
	_dp_test_session_unlink_all(s, __FILE__, __LINE__)


void _dp_test_session_feature_register(enum session_feature_type type,
		const struct session_feature_ops *ops, const char *file,
		int line);
#define dp_test_session_feature_register(type, ops) \
	_dp_test_session_feature_register(type, ops, __FILE__, __LINE__)

#endif  /* __DP_TEST_SESSION_LIB_H__ */

