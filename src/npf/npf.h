/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf.h,v 1.21 2012/09/16 13:47:41 rmind Exp $	*/

/*-
 * Copyright (c) 2009-2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef NPF_H
#define NPF_H

/*
 * This contains common npf types and defines.
 */

#include <netinet/in.h>
#include <stdbool.h>
#include <time.h>
#include "soft_ticks.h"
#include "npf/npf_addr.h"

/*
 * Return values from npf_hook_track and npf_hook_notrack.
 *
 * NPF_ACTION_TO_V4 and NPF_ACTION_TO_V6 are never returned by npf_hook_notrack.
 * A tag is never returned by npf_hook_track.
 *
 * The flags returned are from the same set as those passed in.
 */
typedef enum {
	NPF_DECISION_UNKNOWN = 0, /* Must be zero, see session struct */
	NPF_DECISION_BLOCK,
	NPF_DECISION_BLOCK_UNACCOUNTED,
	NPF_DECISION_PASS,
	NPF_DECISION_UNMATCHED,
} npf_decision_t;

typedef enum {
	NPF_ACTION_NORMAL,
	NPF_ACTION_TO_V4,
	NPF_ACTION_TO_V6,
	NPF_ACTION_TO_LOCAL
} npf_action_t;

typedef struct {
	npf_decision_t	decision : 4;
	npf_action_t	action : 4;
	bool		tag_set : 1;	/* .tag has a value */
	bool		icmp_param_prob : 1;
	bool		icmp_dst_unreach : 1;
	uint8_t		_unused : 5;
	uint16_t	flags;		/* NPF_FLAG_xxx */
	uint32_t	tag;
} npf_result_t;

/*
 * npf flags
 *
 * NPF_FLAG_FROM_LOCAL is *only* set for packets from the kernel that also
 * have a local source address.
 *
 * NPF_FLAG_FROM_US is set when the above condition is true, but also for
 * router originated packets.  These may or may not be from the kernel, and
 * may or may not have an input interface set.  Packets marked with this flag
 * are never dropped by the outbound firewall.
 */
#define NPF_FLAG_IN_SESSION      0x0001  /* Pkt matched a session */
#define NPF_FLAG_CACHE_EMPTY     0x0002  /* Cache is empty */
#define NPF_FLAG_FROM_ZONE       0x0004  /* Came from a zone iface */
#define NPF_FLAG_FROM_US         0x0008  /* router originated packet */
#define NPF_FLAG_FROM_LOCAL      0x0010  /* from kernel, with local addr */
#define NPF_FLAG_FROM_IPV6       0x0020  /* Nat64, converted IPv6 pkt */
#define NPF_FLAG_FROM_IPV4       0x0040  /* Nat64, converted IPv4 pkt */
#define NPF_FLAG_ERR_SESSION     0x0080  /* ICMP error, for session pkt */

/* packet filter direction */
#define PFIL_IN				0x01
#define PFIL_OUT			0x02
#define PFIL_ALL			(PFIL_IN|PFIL_OUT)

/*
 * get current monotonic time in approximate seconds (milliseconds/1024)
 */
static inline time_t get_time_uptime(void)
{
	return soft_ticks >> 10;
}

#endif	/* NPF_H */
