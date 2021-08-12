/*-
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * TWAMP Test packet formats:
 *
 * Unauthenticated Sender packet (rfc4656)
 * ---------------------------------------
 *
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Sequence Number                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                          Timestamp                            |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |        Error Estimate         |                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
     |                                                               |
     .                                                               .
     .                         Packet Padding                        .
     .                                                               .
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 *
 * Unauthenticated Response packet (rfc5357)
 * -----------------------------------------
 *
   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Timestamp                            |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Error Estimate        |           MBZ                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Receive Timestamp                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sender Sequence Number                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Sender Timestamp                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Sender Error Estimate    |           MBZ                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Sender TTL   |                                               |
   +-+-+-+-+-+-+-+-+                                               +
   |                                                               |
   .                                                               .
   .                         Packet Padding                        .
   .                                                               .
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 * NOTES:
 *
 *    o The first Timestamp field, of both request & response packets,
 *      is the timestamp of when the packet was sent (departure
 *      time). In the response packet the Receive Timestamp represents
 *      the arrival time of the request packet and the Sender
 *      Timestamp is the timestamp from the received request packet.
 *
 *    o When looking at pcap traces wireshark cannot distinguish
 *      between request & response messages. Consequently they are all
 *      interpreted as response messages, but that means the request
 *      packet display can appear very strange:
 *
 * TwoWay Active Measurement Test Protocol
 *     Sequence Number: 0
 *     Timestamp: Jul  1, 2021 10:43:30.768429516 BST
 *     Error Estimate: 37001 (0x9089), S
 *     MBZ: 29244 (0x723c)
 *     Receive Timestamp: May 17, 1996 05:32:36.665197892 BST
 *     Sender Sequence Number: 2220097002
 *     Sender Timestamp: Feb  9, 2076 10:41:26.959155478 GMT
 *     Sender Error Estimate: 64450 (0xfbc2)
 *     MBZ: 41394 (0xa1b2)
 *     Sender TTL: 15
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/timex.h>

#include "udp_handler.h"
#include "twamp_internal.h"

#include <netinet/ip.h>
#include <netinet/udp.h>

#include "protobuf/TwampResponder.pb-c.h"
#include "if_var.h"
#include "vplane_debug.h"
#include "ip_checksum.h"
#include "ip_funcs.h"
#include "netinet6/ip6_funcs.h"
#include "udp_handler.h"
#include "twamp_internal.h"

/*
 * The NTP time (as used by TWAMP) is based on an epoch of January 1st
 * 1900, the Linux epoch is January 1st 1970. The following is the
 * adjustment needed when moving from Linux time to NTP time.
 */
#define NTP_EPOCH_ADJUST 2208988800L

#define TWAMP_TEST_TX_PKT_IPV4_TTL 255
#define TWAMP_TEST_TX_PKT_IPV6_HOP 255

struct twamp_timestamp {
	uint32_t secs;
	uint32_t fraction;
	uint16_t errest;
};

/*
 * Error estimate associated with the timestamp. Pretty much a direct
 * copy from the corresponding TWAMP function (see
 * OWPTimespecToTimestamp())
 */
static void
tw_clock_geterrorest(uint16_t *errest, const char *what)
{
	struct timex ntp_conf;
	uint8_t multiplier = 1;
	uint8_t scale = 0;
	uint8_t sync = 0;

	memset(&ntp_conf, 0, sizeof(ntp_conf));
	if (ntp_adjtime(&ntp_conf) < 0) {
		DP_DEBUG(TWAMP, DEBUG, TWAMP,
			 "failed to determine %s NTP clock state: %s\n",
			 what, strerror(errno));
		goto finished;
	}

	if ((ntp_conf.status & STA_UNSYNC) == 0) {
		uint64_t esterror = (ntp_conf.esterror << 32)/1000000;

		while (esterror >= 0xFF) {
			esterror >>= 1;
			scale++;
		}

		esterror++;
		multiplier = esterror & 0xFF;
		sync = 0x80;
	}

finished:
	*errest = ((sync | (scale & 0x3f)) << 8) | multiplier;
}

static int
tw_clock_gettime(struct twamp_timestamp *tstamp, bool geterrest,
		 const char *what)
{
	struct timespec ts;
	uint64_t fraction;

	if (clock_gettime(CLOCK_REALTIME, &ts) < 0) {
		RTE_LOG(ERR, TWAMP,
			"failed to determine %s timestamp: %s\n",
			what, strerror(errno));
		return -1;
	}

	tstamp->secs = ts.tv_sec + NTP_EPOCH_ADJUST;

	/*
	 * The TWAMP (NTP) timestamp uses 1/2^32 sec as its unit of
	 * fractional time where as tv_nsec is 1/1000000000
	 * sec. Convert from nano-secs to micro-secs and then convert
	 * to a fraction.
	 *
	 * See:
	 *
	 *    https://stackoverflow.com/questions/29112071/ \
	 *          how-to-convert-ntp-time-to-unix-epoch-time-in-c-language-linux
	 */
	fraction = (ts.tv_nsec/NSEC_PER_USEC) << 32;
	fraction = fraction/1000000;
	tstamp->fraction = fraction;
	if (!geterrest)
		tstamp->errest = 0;
	else
		tw_clock_geterrorest(&tstamp->errest, what);

	return 0;
}

static char *
tw_clock_encode(char *tpkt, struct twamp_timestamp *ts, bool adderrest)
{
	*((uint32_t *)tpkt) = htonl(ts->secs);
	tpkt += sizeof(uint32_t);
	*((uint32_t *)tpkt) = htonl(ts->fraction);
	tpkt += sizeof(uint32_t);
	if (adderrest) {
		*((uint16_t *)tpkt) = htons(ts->errest);
		tpkt += sizeof(uint16_t);
	}

	return tpkt;
}

static int
tw_reflect_crypto(struct rte_mbuf *m __unused, struct udphdr *udp __unused,
		  uint8_t ttl __unused,
		  struct twamp_timestamp *arrival_ts __unused,
		  struct tw_session_entry *entry __unused)
{
	DP_DEBUG(TWAMP, ERR, TWAMP, "unexpected crypto packet received\n");
	return -1;
}

/*
 * Process an un-authenticated ("cleartext") test message:
 *
 *  - extract sequence number & timestamp from inbound message
 *  - overwrite inbound message with response message:
 *     o sequence number
 *     o departure timestamp
 *     o arrival timestamp
 *     o sender sequence number
 *     o sender timestamp
 *     o received TTL/hop-count
 */
static int
tw_reflect_clear(struct rte_mbuf *m, struct udphdr *udp, uint8_t ttl,
		 struct twamp_timestamp *arrival_ts,
		 struct tw_session_entry *entry)
{
	uint32_t sender_seqno;
	uint32_t sender_ts_sec;
	uint32_t sender_ts_msec;
	uint16_t sender_err;
	struct twamp_timestamp departure_ts = {0};
	char *departure_ts_tpkt;
	int udppayloadlen;
	char *tpkt;

	tpkt = (char *)(udp + 1);

	/*
	 * Extract & save the various fields (sequence number &
	 * timestamp) from the sender test packet - they get copied
	 * into the response packet.
	 */
	sender_seqno = *((uint32_t *)tpkt);
	tpkt += sizeof(uint32_t);
	sender_ts_sec = *((uint32_t *)tpkt);
	tpkt += sizeof(uint32_t);
	sender_ts_msec = *((uint32_t *)tpkt);
	tpkt += sizeof(uint32_t);
	sender_err = *((uint16_t *)tpkt);

	udppayloadlen = ntohs(udp->len) - sizeof(*udp);
	if (udppayloadlen < entry->session.txpayloadlen) {
		int padding;

		DP_DEBUG(TWAMP, DEBUG, TWAMP,
			"%s extending mbuf for reflected packet (%d < %d)\n",
			 entry->session.dbgstr, udppayloadlen,
			 entry->session.txpayloadlen);

		padding = entry->session.txpayloadlen - udppayloadlen;
		if (pktmbuf_append_alloc(m, padding) == NULL) {
			DP_DEBUG(TWAMP, ERR, TWAMP,
				 "%s cannot extend mbuf\n",
				 entry->session.dbgstr);
			return -1;
		}

		udp->len = htons(sizeof(*udp) + entry->session.txpayloadlen);
	}

	/*
	 * Using the same mbuf, overwrite the inbound test message
	 * with the corresponding response message.
	 */
	tpkt = (char *)(udp + 1);
	*((uint32_t *)tpkt) = htonl(entry->session.seqno++);
	tpkt += sizeof(uint32_t);

	/*
	 * Skip over departure timestamp fields
	 */
	departure_ts_tpkt = tpkt;
	tpkt = tw_clock_encode(tpkt, &departure_ts, true);
	*((uint16_t *)tpkt) = 0;
	tpkt += sizeof(uint16_t);

	tpkt = tw_clock_encode(tpkt, arrival_ts, false);

	*((uint32_t *)tpkt) = sender_seqno;
	tpkt += sizeof(uint32_t);

	*((uint32_t *)tpkt) = sender_ts_sec;
	tpkt += sizeof(uint32_t);
	*((uint32_t *)tpkt) = sender_ts_msec;
	tpkt += sizeof(uint32_t);

	*((uint16_t *)tpkt) = sender_err;
	tpkt += sizeof(uint16_t);
	*((uint16_t *)tpkt) = 0;
	tpkt += sizeof(uint16_t);

	*((uint8_t *)tpkt) = ttl;

	/*
	 * Go back and add the departure timestamp (and error
	 * estimate)
	 */
	if (tw_clock_gettime(&departure_ts, true, "departure") < 0)
		return -1;

	tw_clock_encode(departure_ts_tpkt, &departure_ts, true);

	return 0;
}

static int
tw_reflect_check_length(const struct udphdr *udp,
			const struct tw_session_entry *entry)
{
	int udppayloadlen = ntohs(udp->len) - sizeof(*udp);

	if (udppayloadlen < entry->session.minrxpktsize) {
		DP_DEBUG(TWAMP, ERR, TWAMP,
			"%s received packet too small (%d < %d)\n",
			 entry->session.dbgstr, udppayloadlen,
			 entry->session.minrxpktsize);
		return -1;
	}

	if (udppayloadlen < entry->session.rxpayloadlen) {
		DP_DEBUG(TWAMP, ERR, TWAMP,
			"%s received packet less than negotiate size (%d < %d)\n",
			 entry->session.dbgstr, udppayloadlen,
			 entry->session.rxpayloadlen);
		return -1;
	}

	return 0;
}

static int
tw_reflect(struct rte_mbuf *m, struct udphdr *udp, uint8_t ttlhop,
	   struct twamp_timestamp *arrival_ts, struct tw_session_entry *entry)
{
	int rc;

	if (tw_reflect_check_length(udp, entry) < 0) {
		entry->session.rx_bad++;
		return -1;
	}

	entry->session.rx_pkts++;

	if (entry->session.mode == TWAMPSESSION_CREATE__MODE__MODE_OPEN)
		rc = tw_reflect_clear(m, udp, ttlhop, arrival_ts, entry);
	else
		rc = tw_reflect_crypto(m, udp, ttlhop, arrival_ts, entry);

	if (rc < 0)
		entry->session.tx_bad++;

	return rc;
}

static uint32_t
tw_hash_l4(vrfid_t vrfid, const struct udphdr *udp)
{
	uint32_t ports = udp->source << 16 | udp->dest;

	return rte_jhash_1word(ports, vrfid);
}

static bool
tw_hash_match_l4(const struct tw_session *tws,
		 const struct tw_hash_match_args *match)
{
	return (tws->lport == match->udp->dest) &&
		(tws->rport == match->udp->source) &&
		(tws->vrfid == match->vrfid);
}

static void
tw_send_ipv4(struct rte_mbuf *m, struct iphdr *ip, struct udphdr *udp)
{
	struct in_addr ipaddr;
	uint16_t port;

	/*
	 * Any stray IP options? If so squish them before generating
	 * the reply header.
	 */
	if (dp_pktmbuf_l3_len(m) != sizeof(*ip)) {
		struct iphdr *newip;
		int trim;

		trim = ((char *)udp - (char *)ip) - sizeof(*ip);
		rte_pktmbuf_adj(m, trim);
		newip = iphdr(m);
		memmove(newip, ip, sizeof(*ip));
		newip->ihl = 5;
		dp_pktmbuf_l3_len(m) = sizeof(*newip);
		ip = newip;
	}

	ipaddr.s_addr = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = ipaddr.s_addr;
	ip->ttl = TWAMP_TEST_TX_PKT_IPV4_TTL;
	ip->tot_len = htons(sizeof(*ip) + ntohs(udp->len));
	ip->id = dp_ip_randomid(0);
	ip->check = 0;
	ip->check = dp_in_cksum_hdr(ip);

	port = udp->dest;
	udp->dest = udp->source;
	udp->source = port;
	if (udp->check != 0) {
		udp->check = 0;
		udp->check = dp_in4_cksum_mbuf(m, ip, udp);
	}
	ip_output(m, false);
}

int
twamp_hash_match_ipv4(struct cds_lfht_node *node, const void *arg)
{
	const struct tw_hash_match_args *match = arg;
	const struct tw_session_entry *entry;
	const struct tw_session *tws;

	entry = caa_container_of(node, struct tw_session_entry, tw_node);
	tws = &entry->session;
	if (tw_hash_match_l4(tws, match) &&
	    (tws->laddr.address.ip_v4.s_addr == match->ip4->daddr) &&
	    (tws->raddr.address.ip_v4.s_addr == match->ip4->saddr))
		return 1;

	return 0;
}

uint32_t
twamp_hash_ipv4(vrfid_t vrfid, const struct iphdr *ip,
		const struct udphdr *udp)
{
	return rte_jhash_2words(ip->saddr, ip->daddr, tw_hash_l4(vrfid, udp));
}

int
twamp_input_ipv4(struct rte_mbuf *m, void *l3hdr,
		 struct udphdr *udp, struct ifnet *ifp)
{
	struct twamp_timestamp arrival_ts;
	struct tw_session_entry *entry;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct iphdr *ip = l3hdr;
	vrfid_t vrfid;
	struct tw_hash_match_args match = {
		.ip4 = ip,
		.udp = udp,
	};

	if (tw_clock_gettime(&arrival_ts, false, "arrival") < 0)
		goto error;

	vrfid = if_vrfid(ifp);
	pktmbuf_set_vrf(m, vrfid);
	match.vrfid = vrfid;

	cds_lfht_lookup(tw_session_table,
			twamp_hash_ipv4(vrfid, ip, udp),
			twamp_hash_match_ipv4, &match,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node == NULL)
		goto error;

	entry = caa_container_of(node, struct tw_session_entry, tw_node);

	if (tw_reflect(m, udp, ip->ttl, &arrival_ts, entry) < 0)
		goto error;

	tw_send_ipv4(m, ip, udp);
	entry->session.tx_pkts++;
	return 0;

error:
	dp_pktmbuf_notify_and_free(m);
	return 0;
}

static void
tw_send_ipv6(struct rte_mbuf *m, struct ip6_hdr *ip6, struct udphdr *udp)
{
	struct in6_addr ip6addr;
	uint16_t port;

	ip6addr = ip6->ip6_src;
	ip6->ip6_src = ip6->ip6_dst;
	ip6->ip6_dst = ip6addr;
	ip6->ip6_hops = TWAMP_TEST_TX_PKT_IPV6_HOP;
	ip6->ip6_plen = udp->len;

	port = udp->dest;
	udp->dest = udp->source;
	udp->source = port;
	udp->check = 0;
	udp->check = dp_in6_cksum_mbuf(m, ip6, udp);

	ip6_output(m, false);
}

int
twamp_hash_match_ipv6(struct cds_lfht_node *node, const void *arg)
{
	const struct tw_hash_match_args *match = arg;
	const struct tw_session_entry *entry;
	const struct tw_session *tws;

	entry = caa_container_of(node, struct tw_session_entry, tw_node);
	tws = &entry->session;
	if (tw_hash_match_l4(tws, match) &&
	    IN6_ARE_ADDR_EQUAL(
		    &match->ip6->ip6_src.s6_addr,
		    &tws->raddr.address.ip_v6.s6_addr) &&
	    IN6_ARE_ADDR_EQUAL(
		    &match->ip6->ip6_dst.s6_addr,
		    &tws->laddr.address.ip_v6.s6_addr))
		return 1;

	return 0;
}

uint32_t
twamp_hash_ipv6(vrfid_t vrfid, const struct ip6_hdr *ip6,
		const struct udphdr *udp)
{
	return rte_jhash_32b((uint32_t *)&ip6->ip6_src,
			     (sizeof(ip6->ip6_src) * 2) / sizeof(uint32_t),
			     tw_hash_l4(vrfid, udp));
}

int
twamp_input_ipv6(struct rte_mbuf *m, void *l3hdr, struct udphdr *udp,
		 struct ifnet *ifp)
{
	struct twamp_timestamp arrival_ts;
	struct tw_session_entry *entry;
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;
	struct ip6_hdr *ip6 = l3hdr;
	vrfid_t vrfid;
	struct tw_hash_match_args match = {
		.ip6 = ip6,
		.udp = udp,
	};

	if (tw_clock_gettime(&arrival_ts, false, "arrival") < 0)
		goto error;

	vrfid = if_vrfid(ifp);
	pktmbuf_set_vrf(m, vrfid);
	match.vrfid = vrfid;

	cds_lfht_lookup(tw_session_table,
			twamp_hash_ipv6(vrfid, ip6, udp),
			twamp_hash_match_ipv6, &match,
			&iter);
	node = cds_lfht_iter_get_node(&iter);
	if (node == NULL)
		goto error;

	entry = caa_container_of(node, struct tw_session_entry, tw_node);

	if (tw_reflect(m, udp, ip6->ip6_hops, &arrival_ts, entry) < 0)
		goto error;

	tw_send_ipv6(m, ip6, udp);
	entry->session.tx_pkts++;
	return 0;

error:
	dp_pktmbuf_notify_and_free(m);
	return 0;
}
