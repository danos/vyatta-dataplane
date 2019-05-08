/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf_ncode.h,v 1.10 2012/07/19 21:52:29 spz Exp $	*/

/*-
 * Copyright (c) 2009-2010 The NetBSD Foundation, Inc.
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

/*
 * NPF n-code interface.
 */

#ifndef NPF_NCODE_H
#define NPF_NCODE_H

/* Forward Declarations */
struct rte_mbuf;
typedef struct npf_cache npf_cache_t;
typedef struct npf_rule npf_rule_t;
typedef struct npf_session npf_session_t;

/*
 * N-code processing and validation/
 */
struct ifnet;
int npf_ncode_process(npf_cache_t *npc, const npf_rule_t *rl,
		      const struct ifnet *ifp, int dir,
		      npf_session_t *se, struct rte_mbuf *nbuf);

/* Error codes. */
#define	NPF_ERR_OPCODE		-1	/* Invalid instruction. */
#define	NPF_ERR_JUMP		-2	/* Invalid jump (e.g. out of range). */
#define	NPF_ERR_AF		-3	/* Invalid address family */
#define	NPF_ERR_INVAL		-4	/* Invalid argument value. */
#define	NPF_ERR_RANGE		-5	/* Processing out of range. */
#define	NPF_ERR_TABLE		-6	/* Invalid table ID */
#define	NPF_ERR_PORT		-7	/* Invalid port or range */
#define	NPF_ERR_ALEN		-8	/* Invalid address length */

/* Maximum loop count. */
#define	NPF_LOOP_LIMIT		100

/* Maximum DSCP value. */
#define DSCP_MAX		63

enum npf_opcode_type_enum {
	NPF_OPCODE_RET,
	NPF_OPCODE_BEQ,
	NPF_OPCODE_BNE,
	NPF_OPCODE_PROTO_FINAL,
	NPF_OPCODE_ETHERADDR,
	NPF_OPCODE_ETHERPCP,
	NPF_OPCODE_IP4MASK,
	NPF_OPCODE_TABLE,
	NPF_OPCODE_ICMP4,
	NPF_OPCODE_IP6MASK,
	NPF_OPCODE_ICMP6,
	NPF_OPCODE_FRAGMENT,
	NPF_OPCODE_ADDRFAM,
	NPF_OPCODE_IP6_RT,
	NPF_OPCODE_PORTS,
	NPF_OPCODE_TTL,
	NPF_OPCODE_TCP_FLAGS,
	NPF_OPCODE_MATCHDSCP,
	NPF_OPCODE_ETHERTYPE,
	NPF_OPCODE_RPROC,

	_NPF_OPCODE_LAST
};

#define NPF_OPCODE_MAX (_NPF_OPCODE_LAST - 1)

/*
 * Option values set in an operand
 */
#define NC_MATCH_SRC            0x01
#define NC_MATCH_INVERT         0x02
#define NC_MATCH_ICMP           0x04
#define NC_MATCH_ICMP6          0x08

#define NCODE_IS_INVERTED(opt) ((opt & NC_MATCH_INVERT) ? true : false)

#define NC_ICMP_HAS_TYPE	(1<<31)
#define NC_ICMP_HAS_CODE	(1<<30)
#define NC_ICMP_HAS_CLASS	(1<<29)

#define NC_ICMP_GET_TYPE_FROM_OP(x)	((x >> 8) & 0xFF)
#define NC_ICMP_SET_TYPE_IN_OP(x)	((x & 0xFF) << 8)

#define NC_ICMP_GET_CODE_FROM_OP(x)	(x & 0xFF)
#define NC_ICMP_SET_CODE_IN_OP(x)	(x & 0xFF)

/*
 * NPF_OPCODE_IP6MASK has the most number of operands
 */
#define NPF_NOPERANDS_MAX 6

#endif /* NPF_NCODE_H */
