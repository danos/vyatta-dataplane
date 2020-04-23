/*-
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
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
#include <czmq.h>

#include "dp_test_pktmbuf_lib.h"

#include "protobuf/IPAddress.pb-c.h"

#define DP_TEST_MAX_NHS 32
#define DP_TEST_MAX_LBLS 16
#define RTE_ETHER_TYPE_MPLS 0x8847
typedef uint32_t label_t;

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
	bool backup;
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
dp_test_exp_set_fwd_status(struct dp_test_expected *exp, int status);

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


void *dp_test_exp_get_validate_ctx(struct dp_test_expected *exp);

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

extern struct dp_test_expected *dp_test_global_expected;

enum dp_test_fwd_result_e {
	DP_TEST_FWD_LOCAL,
	DP_TEST_FWD_DROPPED,
	DP_TEST_FWD_CONSUMED,
	DP_TEST_FWD_FORWARDED,
	DP_TEST_FWD_UNDEFINED,
};

/*
 * Create a fully formatted dataplane protobuf config message.
 *
 * @param str         [in] The string representing the type of the data message
 * @param data        [in, out] A formatted protobuf message for a feature. This
 *                              will be freed by this function once sent.
 * @param data_len    [in] The length of the formatted protobuf data
 *
 * Create a dataplane envelope (that all the protobuf messages are packed into).
 * The contents of this are the string which is used to determine the handler
 * at the dataplane and the actual data.
 *
 * @return No return value as it asserts if there is a failure.
 */
void dp_test_lib_pb_wrap_and_send_pb(const char *str,
				     void *data, size_t data_len);
void dp_test_send_config(const char *cmd_fmt_str, ...);
char *dp_test_console_request(const char *request, bool print);

int dp_ut_plugin_init(const char **name);

int dp_test_zmsg_popu32(zmsg_t *msg, uint32_t *p);

typedef unsigned int (dp_test_event_msg_hdlr)(const char *event, zmsg_t *msg);

void dp_test_register_event_msg(dp_test_event_msg_hdlr handler);
void dp_test_unregister_event_msg(void);

#define DP_MAX_EXTRA_CFG_LINES 100
/*
 * Some features need to add lines to the platform config file to allow
 * proper testing. For example a feature that would typically create a
 * tcp session via normal config might want to have code to allow that
 * to be overridden in tests and to create an ipc connections to the
 * test harness. This API allows the features to add platform config
 * within the 'dataplane' section of the config file. Plugins that need
 * this API should call it as part of dp_ut_plugin_init().
 *
 * At most DP_MAX_EXTRA_CFG_LINES can be added.
 *
 * @param [in] argc Count of the number of lines in argv
 * @param [in] argv Array of size argc that contains the lines that the
 *             feature wants to add. They should be of the form
 *             <something>=<something-else>
 *
 * @return 0 on success
 *         -ve on failure
 */
int dp_test_add_to_cfg_file(int argc, char **argv);

/* Helpers to manage interactions with protobufs */

/*
 * Given an ip address (either v4 or v6) in string format, populate
 * the protobuf formatted addr.
 *
 * @param addr        [out] The protobuf address structure to be populated.
 * @param str         [in]  The address, formatted as a string that is to be
 *                          populated into the address.
 * @param data        [out] A scratch buffer of at least 16 bytes that is
 *                          used in the case when the string is a V6 address
 *                          as the addr needs space to store the address.
 *
 * Populate the addr with the address in the string, using the 'data' as the
 * storage for this in the case of an IPv6 address. This is done to avoid
 * having this function doing a malloc for the data and the requirement to
 * then free it.
 */
void dp_test_lib_pb_set_ip_addr(IPAddress *addr, const char *str, void *data);

#endif /*_DP_TEST_LIB_H_ */
