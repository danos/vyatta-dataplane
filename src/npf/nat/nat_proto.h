/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _NAT_PROTO_H_
#define _NAT_PROTO_H_


/*
 * Protocol classification
 *
 * Note that if ICMP is given a unique pool to allocate ID's from,
 * then the NAT64 code needs checked to ensure that the it works as
 * expected, as NAT64 maps between ICMPv4 (protocol 1) and ICMPv6
 * (protocol 58).
 */
enum nat_proto {
	NAT_PROTO_TCP,
	NAT_PROTO_UDP,
	NAT_PROTO_OTHER,
};

#define NAT_PROTO_FIRST	NAT_PROTO_TCP
#define NAT_PROTO_LAST	NAT_PROTO_OTHER
#define NAT_PROTO_COUNT	(NAT_PROTO_LAST + 1)
#define NAT_PROTO_NONE	NAT_PROTO_COUNT

/* Get the nat_proto enum from the protocol number */
static inline uint8_t nat_proto_from_ipproto(uint8_t ipproto)
{
	switch (ipproto) {
	case IPPROTO_TCP:
		return NAT_PROTO_TCP;
	case IPPROTO_UDP:
		return NAT_PROTO_UDP;
	}
	return NAT_PROTO_OTHER;
}

/*
 * Only works for TCP and UDP.  Used for logging.
 */
static inline uint8_t nat_ipproto_from_proto(uint8_t proto)
{
	switch (proto) {
	case NAT_PROTO_TCP:
		return IPPROTO_TCP;
	case NAT_PROTO_UDP:
		return IPPROTO_UDP;
	}
	return 0;
}

static inline const char *nat_proto_str(uint8_t proto)
{
	switch (proto) {
	case NAT_PROTO_TCP:
		return "TCP";
	case NAT_PROTO_UDP:
		return "UDP";
	}
	return "Other";
}

static inline const char *nat_proto_lc_str(uint8_t proto)
{
	switch (proto) {
	case NAT_PROTO_TCP:
		return "tcp";
	case NAT_PROTO_UDP:
		return "udp";
	}
	return "other";
}

#endif
