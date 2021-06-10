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
 *     o arrival timestamp
 *     o departure timestamp
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
	struct twamp_timestamp departure_ts;
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

	tpkt = tw_clock_encode(tpkt, arrival_ts, true);
	*((uint16_t *)tpkt) = 0;
	tpkt += sizeof(uint16_t);

	if (tw_clock_gettime(&departure_ts, false, "departure") < 0)
		return -1;

	tpkt = tw_clock_encode(tpkt, &departure_ts, false);

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

int
twamp_input_ipv4(struct rte_mbuf *m, void *l3hdr __unused,
		 struct udphdr *udp __unused, struct ifnet *ifp __unused)
{
	rte_pktmbuf_free(m);
	return 0;
}

int
twamp_input_ipv6(struct rte_mbuf *m, void *l3hdr __unused, struct udphdr *udp __unused,
		 struct ifnet *ifp __unused)
{
	rte_pktmbuf_free(m);
	return 0;
}
