/*
 * Copyright (c) 2019,2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/*
 * NAT64 rproc
 */

#ifndef __NPF_EXT_NAT64_H__
#define __NPF_EXT_NAT64_H__

#include "npf/npf_apm.h"
#include "npf/npf_nat.h"

/*
 * Is this rule nat64 or nat46?  This is used mainly for show commands.
 */
enum npf_nat64_type {
	N6_NAT64,
	N6_NAT46,
};

/*
 * NPF_NAT64_RFC6052  v4 addrs are extracted from, or added to, v6 addrs
 *                    as per rfc6052
 * NPF_NAT64_ONE2ONE  one-to-one mapping between v4 and v6 addrs
 * NPF_NAT64_OVERLOAD v4 address pool is used for 6-to-4 src addr
 */
enum npf_nat64_map_type {
	NPF_NAT64_NONE,
	NPF_NAT64_RFC6052,
	NPF_NAT64_ONE2ONE,
	NPF_NAT64_OVERLOAD,
};

/*
 * nat64 mapping configuration and state
 */
struct nat64_map {
	enum npf_nat64_map_type nm_type;
	npf_addr_t	nm_addr;
	uint8_t		nm_mask; /* prefix length */
	sa_family_t	nm_af;

	/*
	 * overload/apm for type NPF_NAT64_OVERLOAD.
	 * nm_start_port may also be used for one-to-one dest port mapping.
	 */
	uint32_t	nm_addr_table_id; /* sgroup=ADDRGRP */
	npf_addr_t	nm_start_addr;    /* srange=10.10.1.1-10.10.1.8 */
	npf_addr_t	nm_stop_addr;
	in_port_t	nm_start_port;
	in_port_t	nm_stop_port;
};

/*
 * Nat64 rproc structure.  One per rule.
 */
struct nat64 {
	/* Pointer back to rule */
	npf_rule_t	*n6_rl;

	/* Address mapping */
	struct nat64_map n6_src;
	struct nat64_map n6_dst;

	/* nat46 or nat64? */
	enum npf_nat64_type n6_type;

	/* logging flags */
	uint8_t n6_log;
};

#define N64_LOG_SESSIONS 0x01

#endif /* NPF_EXT_NAT64_H */
