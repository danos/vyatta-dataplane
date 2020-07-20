/*-
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A library of useful functions for writing dataplane tests.
 */

#ifndef _DP_TEST_LIB_INTERNAL_H_
#define _DP_TEST_LIB_INTERNAL_H_

#define DP_TEST_MAX_PREFIX_STRING_LEN 100
#define DP_TEST_MAX_ROUTE_STRING_LEN 2048

#include <assert.h>
#include <stdbool.h>

#include "if_var.h"

#include "dp_test/dp_test_lib.h"

#include "dp_test_pktmbuf_lib_internal.h"

extern int spath_pipefd[2];
extern int shadow_pipefd[DATAPLANE_MAX_PORTS];

/* Packet for read/readv. This can contain the user provided iov's */
struct dp_read_pkt {
	struct rte_mbuf *pkt;
	portid_t port;
	struct meta {
		uint32_t ifindex;
		uint16_t flags;
	} m;
	struct pi {
		uint16_t proto;
	} p;
};


struct dp_test_expected;

typedef  void (*validate_cb)(struct rte_mbuf *pak,
			     struct ifnet *ifp,
			     struct dp_test_expected *expected,
			     enum dp_test_fwd_result_e fwd_result);

/*
 * Helper function to allow an idiom where we keep extending a string
 * into a fixed size buffer with printf style calls and keep a running
 * total of the number of non-null chars written.
 *
 * We return the number of characters in the string that results from
 * the printf unless the string with its null exactly fills the
 * remaining space at which point were return the remaining space.  So
 * subsequent calls will be given remaining == 0.
 */
int spush(char *s, size_t remaining, const char *format, ...)
	__attribute__ ((__format__(printf, 3, 4)));

void
dp_test_str_trim(char *str, uint16_t start_trim, uint16_t end_trim);

validate_cb dp_test_exp_get_validate_cb(struct dp_test_expected *);

validate_cb dp_test_exp_set_validate_cb(struct dp_test_expected *, validate_cb);

/*
 * Simulate injection of packet into the dataplane from the kernel
 */

void _dp_test_send_slowpath_pkt(struct rte_mbuf *pak,
		struct dp_test_expected *expected,
		const char *file, const char *func, int line);

#define dp_test_send_slowpath_pkt(pak, expected)		\
	_dp_test_send_slowpath_pkt(pak, expected,	\
			__FILE__, __func__, __LINE__)

/* Inject packet on .spath interface from kernel */
void _dp_test_send_spath_pkt(struct rte_mbuf *pak, const char *virt_oif_name,
		struct dp_test_expected *expected,
		const char *file, const char *func, int line);

#define dp_test_send_spath_pkt(pak, virt_oif_name, expected)	\
	_dp_test_send_spath_pkt(pak, virt_oif_name, expected,	\
			__FILE__, __func__, __LINE__)
struct ifnet;
void
dp_test_pak_verify(struct rte_mbuf *pak, struct ifnet *ifp,
		   struct dp_test_expected *expected,
		   enum dp_test_fwd_result_e fwd_result);

/* Read packet context processing functions */
void dp_test_inject_pkt_slow_path(struct rte_mbuf *buf, portid_t port,
		uint32_t ifindex, uint16_t flags, uint16_t proto);
struct rte_mbuf *dp_test_get_read_pkt(void);
uint8_t dp_test_get_read_port(void);
uint16_t dp_test_get_read_meta_flags(void);
uint32_t dp_test_get_read_meta_iif(void);
uint16_t dp_test_get_read_proto(void);
bool dp_test_read_pkt_available(void);

/*
 * Internal error in test framework - will crash notifying the line
 * number that we are currently at.  Do NOT use this for normal test
 * conditions - for those use dp_fail_unless and other services in
 * dp_test/dp_test_macros.h. This is solely for internal unrecoverable errors
 * in the test infra.
 */
#define dp_test_assert_internal(expr)					\
	({								\
		if (!(expr)) {						\
			printf("Internal error: %s:%d\n",		\
			       __func__, __LINE__);			\
		}							\
		assert(expr);						\
	})

/* override soft-ticks time for tests that want to do timer dependent stuff. */
void dp_test_enable_soft_tick_override(void);
void dp_test_disable_soft_tick_override(void);

void dp_test_make_nh_unusable(const char *interface,
			      const char *nexthop);

void dp_test_make_nh_usable(const char *interface,
			    const char *nexthop);

void dp_test_clear_path_unusable(void);

void dp_test_make_nh_unusable_other_thread(pthread_t *nh_unusable_thread,
					   const char *interface,
					   const char *nexthop);

void dp_test_make_nh_usable_other_thread(pthread_t *nh_unusable_thread,
					 const char *interface,
					 const char *nexthop);

#endif /*_DP_TEST_LIB_H_ */
