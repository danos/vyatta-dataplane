/**
 *
 * Copyright (c) 2017,2019-2020, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * @file dp_test_lib_pkt.h
 * @brief Dataplane unit-test packet helpers
 *
 * This contains library functions for creating test packets and test expect
 * object.
 *
 * Example usage:
 *
 * @code
 * struct dp_test_pkt_desc_t v4_pkt_desc = {
 *         .text       = "TCP IPv4",
 *         .len        = 20,
 *         .ether_type = ETHER_TYPE_IPv4,
 *         .l3_src     = "1.1.1.11",
 *         .l2_src     = "aa:bb:cc:dd:1:a1",
 *         .l3_dst     = "2.2.2.11",
 *         .l2_dst     = "aa:bb:cc:dd:2:b1",
 *         .source     = &nbr1,
 *         .dest       = &nbr2,
 *         .proto      = IPPROTO_TCP,
 *         .l4         = {
 *                 .tcp = {
 *                          .sport = 1000,
 *                          .dport = 1001,
 *                          .flags = 0
 *                 }
 *         },
 *         .rx_intf    = "dp1T0",
 *         .tx_intf    = "dp2T1"
 * };
 *
 * struct rte_mbuf *test_pak;
 * struct dp_test_expected *test_exp;
 *
 * test_pak = dp_test_v4_pkt_from_desc(&v4_pkt_desc);
 * test_exp = dp_test_exp_from_desc(test_pak, &v4_pkt_desc, nbr2.mac);
 * @endcode
 */

#ifndef __DP_TEST_LIB_PKT_H__
#define __DP_TEST_LIB_PKT_H__

#include <stdint.h>
#include <stdbool.h>
#include "dp_test_lib_intf_internal.h"

/**
 * @brief Packet descriptor
 */
struct dp_test_pkt_desc_t {
	/** Text description */
	const char                  *text;
	/** Payload length */
	int                          len;
	/** Ethernet type. ETHER_TYPE_IPv4 or ETHER_TYPE_IPv6 */
	uint16_t                     ether_type;
	/** IPv4 or IPv6 source address */
	const char                  *l3_src;
	/**
	 * Source MAC addresses.  MAC address of the sending device. This will
	 * be the source host if it is on the same subnet, otherwise it is the
	 * MAC address of the previous hop.
	 */
	const char                  *l2_src;
	/** IPv4 or IPv6 destination address */
	const char                  *l3_dst;
	/**
	 * Used to set the dest MAC address of the packet we expect to see on
	 * the outbound interface.  Used to set the dest MAC address of
	 * inbound bridge packets.  (The dest MAC of inbound routed packets
	 * will be set to the receiving interface MAC.)
	 */
	const char                  *l2_dst;
	/** ToS/Traffic-class field - 6 bits DSCP, 2 bits ECN */
	uint8_t			    traf_class;
	/** Protocol e.g. IPPROTO_TCP */
	uint8_t                      proto;
	union {
		struct {
			/** TCP source port */
			uint16_t     sport;
			/** TCP destination port */
			uint16_t     dport;
			/** TCP flags */
			uint8_t      flags;
			/** TCP tx data seq number */
			uint32_t     seq;
			/** TCP rx data acknowledgment seq number */
			uint32_t     ack;
			/** TCP rx flow control window */
			uint16_t     win;
			/** Pointer to TCP options */
			const uint8_t *opts;
		} tcp;
		struct {
			/** UDP source port */
			uint16_t     sport;
			/** UDP destination port */
			uint16_t     dport;
		} udp;
		struct {
			/** ICMP type */
			uint8_t      type;
			/** ICMP code */
			uint8_t      code;
			/** Type specific field */
			union {
				uint32_t udata32;
				uint16_t udata16[2];
				uint8_t  udata8[4];
			};
		} icmp;
		struct {
			uint16_t prot;
			uint32_t key;
			uint32_t seq;
		} gre;
	} l4;
	/** Input interface desc */
	const char                  *rx_intf;
	/** Outbound interface desc */
	const char                  *tx_intf;
};

/* Echo req (type 8/128) and reply (type 0/129) */
#define dpt_icmp_id      udata16[0]
#define dpt_icmp_seq     udata16[1]

/* Destination Unreachable (type 3), Datagram too big (code 4) */
#define dpt_icmp4_mtu    udata16[1]

/* Packet too big (type 2) */
#define dpt_icmp6_mtu    udata32

/* Redirect (type 5) */
#define dpt_icmp_gateway udata32


/**
 * @brief Create a 'to-be-routed' packet from a packet descriptor.
 *
 * The intention is that the packet will be routed, so the destination MAC
 * address is set to the rx_intf MAC address
 *
 * @param [in] pdesc Pointer to a packet descriptor
 * @return Pointer to an rte_mbuf
 */
struct rte_mbuf *
_dp_test_rt_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
			  const char *file, int line);

#define dp_test_rt_pkt_from_desc(pdesc)				\
	_dp_test_rt_pkt_from_desc(pdesc, __FILE__, __LINE__)

#define dp_test_v4_pkt_from_desc(pdesc)				\
	_dp_test_rt_pkt_from_desc(pdesc, __FILE__, __LINE__)

#define dp_test_v6_pkt_from_desc(pdesc)				\
	_dp_test_rt_pkt_from_desc(pdesc, __FILE__, __LINE__)


/**
 * @brief Create a reverse-flow 'to-be-routed' packet from a packet descriptor
 *
 * @param [in] pdesc Pointer to a packet descriptor
 * @return Pointer to an rte_mbuf
 */
struct rte_mbuf *
_dp_test_reverse_rt_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
				  const char *file, int line);

#define dp_test_reverse_rt_pkt_from_desc(pdesc)				\
	_dp_test_reverse_rt_pkt_from_desc(pdesc, __FILE__, __LINE__)

#define dp_test_reverse_v4_pkt_from_desc(pdesc)				\
	_dp_test_reverse_rt_pkt_from_desc(pdesc, __FILE__, __LINE__)

#define dp_test_reverse_v6_pkt_from_desc(pdesc)				\
	_dp_test_reverse_rt_pkt_from_desc(pdesc, __FILE__, __LINE__)

/**
 * @brief Create a bridge packet from a packet descriptor
 *
 * Source MAC address is set to the packet descriptor l2_src MAC.  Destination
 * MAC is set to the packet descriptor l2_dst MAC.
 *
 * @param [in] pdesc Pointer to a packet descriptor
 * @return Pointer to an rte_mbuf
 */
struct rte_mbuf *
_dp_test_bridge_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
			      const char *file, int line);

#define dp_test_bridge_pkt_from_desc(pdesc)				\
	_dp_test_bridge_pkt_from_desc(pdesc, __FILE__, __LINE__)

/**
 * @brief Create a packet from the slow-path
 *
 * Create a packet from the slow-path, i.e. simulates a packet either
 * originated from the kernel, or forwarded (bridged or routed) by the kernel.
 *
 * Source MAC address is set to l2_src if specified, else it is set to the
 * tx_intf MAC.  Destination MAC is set to the packet descriptor l2_dst MAC.
 *
 * @param [in] pdesc Pointer to a packet descriptor
 * @return Pointer to an rte_mbuf
 */
struct rte_mbuf *
_dp_test_from_spath_pkt_from_desc(const struct dp_test_pkt_desc_t *pdesc,
				  const char *file, int line);

#define dp_test_from_spath_pkt_from_desc(pdesc)				\
	_dp_test_from_spath_pkt_from_desc(pdesc, __FILE__, __LINE__)

#define dp_test_from_spath_v4_pkt_from_desc(pdesc)			\
	_dp_test_from_spath_pkt_from_desc(pdesc, __FILE__, __LINE__)

/**
 * @brief Create an expect object from a packet descriptor and packet mbuf
 *
 * The expect packet is initially a copy of the test packet.  Destination MAC
 * is set to the l2_dst from the packet descriptor.  Source MAC is the
 * outbound interface MAC. The layer 3 TTL is decremented, and checksum
 * recalculated.
 *
 * @param [in] mbuf Pointer to test packet
 * @param [in] pdesc Pointer to a packet descriptor
 * @return Pointer to expect object
 */
struct dp_test_expected *
_dp_test_exp_from_desc(struct rte_mbuf *mbuf,
		       const struct dp_test_pkt_desc_t *pdesc,
		       struct dp_test_expected *exp,
		       uint pktno, bool multiple,
		       const char *file, int line);

#define dp_test_exp_from_desc(mbuf, pdesc)				\
	_dp_test_exp_from_desc(mbuf, pdesc, NULL, 0, false,		\
			       __FILE__, __LINE__)

#define dp_test_exp_from_desc_m(mbuf, pdesc, exp, pktno)		\
	_dp_test_exp_from_desc(mbuf, pdesc, exp, pktno, true,		\
			       __FILE__, __LINE__)

/**
 * @brief Create an expect object from the reverse of a packet descriptor
 *
 * @param [in] mbuf Pointer to test packet
 * @param [in] pdesc Pointer to a packet descriptor
 * @return Pointer to expect object
 */
struct dp_test_expected *
_dp_test_reverse_exp_from_desc(struct rte_mbuf *mbuf,
			      const struct dp_test_pkt_desc_t *pdesc,
			      const char *file, int line);

#define dp_test_reverse_exp_from_desc(mbuf, pdesc)			\
	_dp_test_reverse_exp_from_desc(mbuf, pdesc, __FILE__, __LINE__)

#endif
