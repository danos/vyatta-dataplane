/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A library of useful functions for writing dataplane tests.
 */

#ifndef _DP_TEST_LIB_H_
#define _DP_TEST_LIB_H_

#define DP_TEST_MAX_PREFIX_STRING_LEN 100
#define DP_TEST_MAX_ROUTE_STRING_LEN 2048

#include <assert.h>
#include <stdbool.h>

#include "if_var.h"

#include "dp_test_pktmbuf_lib.h"

#define DP_TEST_MAX_NHS 32
#define DP_TEST_MAX_LBLS 16
#define ETHER_TYPE_MPLS 0x8847
typedef uint32_t label_t;

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

struct dp_test_prefix {
	struct dp_test_addr addr;
	uint8_t len;
};

struct dp_test_nh {
	char *nh_int;
	struct dp_test_addr nh_addr;
	uint8_t num_labels;
	label_t labels[DP_TEST_MAX_LBLS];
	bool neigh_created;
	bool neigh_present;
};

struct dp_test_route {
	struct dp_test_prefix prefix;
	uint32_t vrf_id;
	uint32_t tableid;
	uint32_t scope;
	uint32_t mpls_payload_type;
	uint32_t nh_cnt;
	uint32_t type;
	struct dp_test_nh nh[DP_TEST_MAX_NHS];
};

struct dp_test_route *
dp_test_parse_route(const char *route_string);

void dp_test_free_route(struct dp_test_route *route);

bool
dp_test_addr_str_to_addr(const char *addr_str, struct dp_test_addr *addr);

const char *
dp_test_addr_to_str(const struct dp_test_addr *addr, char *addr_str,
		    size_t addr_str_size);

bool
dp_test_prefix_str_to_prefix(const char *prefix, struct dp_test_prefix *pfx);

uint8_t
dp_test_addr_size(const struct dp_test_addr *addr);

uint32_t
dp_test_ipv4_addr_to_network(uint32_t addr, uint8_t prefix_len);

uint32_t
dp_test_ipv4_addr_to_bcast(uint32_t addr, uint8_t prefix_len);

/*
 * Convert an IPv6 address and prefix length to an IPv6 network address
 */
void
dp_test_ipv6_addr_to_network(const struct in6_addr *addr,
			     struct in6_addr *network, uint8_t prefix_len);

#define DP_TEST_PAK_DEFAULT_PROTO IPPROTO_UDP
#define DP_TEST_PAK_DEFAULT_LEN 60
#define DP_TEST_PAK_DEFAULT_TOS 0
#define DP_TEST_PAK_DEFAULT_FRAG_OFF 0
#define DP_TEST_PAK_DEFAULT_ID 0
#define DP_TEST_PAK_DEFAULT_TTL 64
#define DP_TEST_PAK_DEFAULT_IHL 5

/*
 * Functions to setup the data within a packet.
 */
void
dp_test_set_iphdr(struct rte_mbuf *m, const char *src, const char *dst);
void
dp_test_set_tcphdr(struct rte_mbuf *m, uint16_t src_port, uint16_t dst_port);
uint16_t
dp_test_calc_udptcp_chksum(struct rte_mbuf *m);

/*
 *  Forwarding Result enum
 */
enum dp_test_fwd_result_e {
	DP_TEST_FWD_LOCAL,
	DP_TEST_FWD_DROPPED,
	DP_TEST_FWD_CONSUMED,
	DP_TEST_FWD_FORWARDED,
	DP_TEST_FWD_UNDEFINED,
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

/*
 * Tests often need to check the result of forwarding a packet.  These functions
 * allocate a structure that is used to build an expected state, which can
 * be compared against at the end of the packet processing. It takes a test_pak
 * as its argument. This test_pak is the pak that will be processed, and is the
 * pak we are building up the expected state for.
 *
 * Build expected state with the following defaults:
 *  - 1 pak, with same content as test_pak, therefore build test pak first.
 *  - forwarded
 *  - check len is same as test pak
 *  - check offset 0
 *  - free on receive (can't reuse this expected struct again)
 *  - store address of 'test_pak' and compare against the pak that comes out of
 *    processing.
 *
 * Anything that is not default can be set by the API.
 *
 * The _m version builds the specified number of paks instead of the default
 * number (1) and it is then up to the user to modify them as required.
 * The _append version will add the specified paks to an existing
 * dp_test_expected.
 */
struct dp_test_expected *
dp_test_exp_create(struct rte_mbuf *test_pak);
struct dp_test_expected *
dp_test_exp_create_m(struct rte_mbuf *test_pak, int m);
void
dp_test_exp_append_m(struct dp_test_expected *exp, struct rte_mbuf *test_pak,
		     int count);

/*
 * Create an expected state passing in a fully formed
 * packet that we expect to see.
 */
struct dp_test_expected *
dp_test_exp_create_with_packet(struct rte_mbuf *test_pak);

void
dp_test_exp_delete(struct dp_test_expected *exp);

void
dp_test_exp_set_check_len(struct dp_test_expected *exp, uint32_t len);

void
dp_test_exp_set_check_start(struct dp_test_expected *exp, uint32_t start);

void
dp_test_exp_set_fwd_status(struct dp_test_expected *exp, int);

void
dp_test_exp_set_fwd_status_m(struct dp_test_expected *exp,
			     unsigned int packet, int status);

void
dp_test_exp_set_oif_name(struct dp_test_expected *exp, const char *name);

void
dp_test_exp_set_oif_name_m(struct dp_test_expected *exp,
			   unsigned int packet, const char *name);
void
dp_test_exp_set_vlan_tci(struct dp_test_expected *exp, uint16_t vlan);
void
dp_test_exp_set_vlan_tci_m(struct dp_test_expected *exp,
			   unsigned int packet, uint16_t vlan);

void
dp_test_exp_set_cloned(struct dp_test_expected *exp, bool cloned);

struct rte_mbuf *
dp_test_exp_get_sent(struct dp_test_expected *exp, unsigned int packet);

void
dp_test_exp_set_sent(struct dp_test_expected *exp, unsigned int packet,
		     struct rte_mbuf *sent);

struct rte_mbuf *
dp_test_exp_get_pak(struct dp_test_expected *exp);

struct rte_mbuf *
dp_test_exp_get_pak_m(struct dp_test_expected *exp, unsigned int packet);

void
dp_test_exp_set_pak_m(struct dp_test_expected *exp, unsigned int packet,
		      struct rte_mbuf *m);

validate_cb dp_test_exp_get_validate_cb(struct dp_test_expected *);

validate_cb dp_test_exp_set_validate_cb(struct dp_test_expected *, validate_cb);

void *dp_test_exp_get_validate_ctx(struct dp_test_expected *);

void *dp_test_exp_set_validate_ctx(struct dp_test_expected *exp,
				   void *ctx, bool auto_free);

void dp_test_exp_validate_cb_pak_done(struct dp_test_expected *exp,
				      bool correct);

/*
 * Inject pak into interface if_name and check that the forwarding
 * behaviour matches expected or create a test failure referencing
 * the current file, func and line.
 */
#define dp_test_pak_receive(pak, if_name, expected)	   \
	_dp_test_pak_receive(pak, if_name, expected,	   \
			     __FILE__, __func__, __LINE__)
/*
 * Check that we transmit a packet in response to some stimulus that
 * isn't receiving a packet. The tx packet should match the expected
 * or create a test failure referencing the current file, func and line.
 */
#define dp_test_pak_tx_without_rx(expected)	   \
	_dp_test_pak_tx_without_rx(expected,	   \
				   __FILE__, __func__, __LINE__)
/*
 * Same as dp_test_pak_receive but supplying printf style format
 * string and arguments to provide additional information in the test
 * failure report.
 */
#define dp_test_pak_rx_for(pak, if_name, expected, fmt_str, ...)	\
	_dp_test_pak_rx_for(pak, if_name, expected,			\
			    __FILE__, __func__, __LINE__,               \
			    fmt_str, ##__VA_ARGS__)

void
_dp_test_pak_rx_for(struct rte_mbuf *pak, const char *if_name,
		    struct dp_test_expected *expected,
		    const char *file, const char *func, int line,
		    const char *fmt_str, ...)
	__attribute__ ((__format__(printf, 7, 8)));

void
_dp_test_pak_receive(struct rte_mbuf *pak, const char *if_name,
		     struct dp_test_expected *expected,
		     const char *file, const char *func, int line);

void
_dp_test_pak_tx_without_rx(struct dp_test_expected *expected,
			   const char *file, const char *func, int line);

#define dp_test_pak_receive_n(paks, num_paks, if_name, expected)	\
	_dp_test_pak_receive_n(paks, num_paks, if_name, expected,	\
			       __FILE__, __func__, __LINE__)
void
_dp_test_pak_receive_n(struct rte_mbuf **pak, uint32_t num_paks,
		       const char *if_name,
		       struct dp_test_expected *expected,
		       const char *file, const char *func, int line);

void
dp_test_pak_inject(struct rte_mbuf **paks_to_send, uint32_t num_paks,
		   const char *iif_name,
		   struct dp_test_expected *expected, const char *test_type);
void
dp_test_intf_wait_until_processed(struct rte_ring *ring);
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

extern struct dp_test_expected *dp_test_global_expected;

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
 * dp_test_macros.h. This is solely for internal unrecoverable errors
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

#endif /*_DP_TEST_LIB_H_ */
