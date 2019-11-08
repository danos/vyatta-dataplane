/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf_processor.c,v 1.12 2012/07/19 21:52:29 spz Exp $	*/

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
 * NPF n-code processor.
 *	Inspired by the Berkeley Packet Filter.
 *
 * Few major design goals are:
 *
 * - Keep engine lightweight, well abstracted and simple.
 * - Avoid knowledge of internal network buffer structures (e.g. mbuf).
 * - Avoid knowledge of network protocols.
 *
 * There are two instruction sets: RISC-like and CISC-like.  The later are
 * instructions to cover most common filter cases, and reduce interpretation
 * overhead.  These instructions use protocol knowledge and are supposed to
 * be fully optimized.
 *
 * N-code memory address and thus instructions should be word aligned.
 * All processing is done in 32 bit words, since both instructions (their
 * codes) and arguments use 32 bits words.
 */

#include <assert.h>
#include <netinet/in.h>
#include <rte_branch_prediction.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "npf/npf.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_cache.h"
#include "npf/npf_disassemble.h"
#include "npf/npf_instr.h"
#include "npf/npf_ncode.h"
#include "npf/npf_ruleset.h"

struct ifnet;
struct rte_mbuf;

/*
 * nc_fetch_word: fetch a word (32 bits) from the n-code and increase
 * instruction pointer by one word.
 */
static inline const void *
nc_fetch_word(const void *iptr, uint32_t *a)
{
	const uint32_t *tptr = (const uint32_t *)iptr;
	*a = *tptr++;
	return tptr;
}

/*
 * nc_fetch_double: fetch two words (2 x 32 bits) from the n-code and
 * increase instruction pointer by two words.
 */
static inline const void *
nc_fetch_double(const void *iptr, uint32_t *a, uint32_t *b)
{
	const uint32_t *tptr = (const uint32_t *)iptr;
	*a = *tptr++;
	*b = *tptr++;
	return tptr;
}

/*
 * nc_jump: helper function to jump to specified line (32 bit word)
 * in the n-code, fetch a word, and update the instruction pointer.
 */
static inline const void *
nc_jump(const void *iptr, int n, u_int *lcount)
{

	/* Detect infinite loops. */
	if (unlikely(*lcount == 0)) {
		return NULL;
	}
	*lcount = *lcount - 1;
	return (const uint32_t *)iptr + n;
}

/*
 * npf_ncode_process: process n-code using data of the specified packet.
 *
 * => Argument nbuf (network buffer) is opaque to this function.
 * => Chain of nbufs (and their data) should be protected from any change.
 * => N-code memory address and thus instructions should be aligned.
 * => N-code should be protected from any change.
 * => Routine prevents from infinite loop.
 */
int
npf_ncode_process(npf_cache_t *npc, const npf_rule_t *rl,
		  const struct ifnet *ifp, int dir,
		  npf_session_t *se, struct rte_mbuf *nbuf)
{
	/* N-code instruction pointer. */
	const void *i_ptr = npf_get_ncode(rl);

	/* Local, state variables. */
	uint32_t d, i, n;
	int cmpval = 0;
	u_int lcount = NPF_LOOP_LIMIT;
	enum npf_opcode_type_enum opcode;

process_next:
	/*
	 * Loop must always start on instruction, therefore first word
	 * should be an opcode.  Most used instructions are checked first.
	 */
	i_ptr = nc_fetch_word(i_ptr, &d);
	opcode = d;

	switch (opcode) {
	case NPF_OPCODE_BEQ:
		i_ptr = nc_fetch_word(i_ptr, &n);	/* N-code line */
		if (cmpval == 0)
			goto do_jump;
		break;
	case NPF_OPCODE_BNE:
		i_ptr = nc_fetch_word(i_ptr, &n);
		if (cmpval != 0) {
do_jump:
			i_ptr = nc_jump(i_ptr, n - 2, &lcount);
			if (unlikely(i_ptr == NULL))
				goto fail;
		}
		break;
	case NPF_OPCODE_RET:
		(void)nc_fetch_word(i_ptr, &n);		/* Return value */
		return n;
	case NPF_OPCODE_IP4MASK: {
		/* Source/destination, network address, subnet. */
		npf_addr_t addr;

		i_ptr = nc_fetch_word(i_ptr, &d);
		i_ptr = nc_fetch_double(i_ptr, &addr.s6_addr32[0], &n);

		cmpval = npf_match_ip4mask(npc, d, addr.s6_addr32[0],
					   (npf_netmask_t)n);
		break;
	}
	case NPF_OPCODE_IP6MASK: {
		/* Source/destination, network address, subnet. */
		npf_addr_t addr;

		i_ptr = nc_fetch_word(i_ptr, &d);
		i_ptr = nc_fetch_double(i_ptr,
		    &addr.s6_addr32[0], &addr.s6_addr32[1]);
		i_ptr = nc_fetch_double(i_ptr,
		    &addr.s6_addr32[2], &addr.s6_addr32[3]);
		i_ptr = nc_fetch_word(i_ptr, &n);

		cmpval = npf_match_ip6mask(npc, d, &addr, (npf_netmask_t)n);
		break;
	}
	case NPF_OPCODE_TABLE:
		/* Source/destination, NPF table ID. */
		i_ptr = nc_fetch_double(i_ptr, &n, &i);
		cmpval = npf_match_table(npc, n, i);
		break;
	case NPF_OPCODE_PORTS:
		/* Source/destination, port range. */
		i_ptr = nc_fetch_double(i_ptr, &n, &i);
		cmpval = npf_match_ports(npc, n, i);
		break;
	case NPF_OPCODE_TTL:
		/* IPv4 TTL, IPv6 HopLimit. */
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_ttl(npc, n);
		break;
	case NPF_OPCODE_TCP_FLAGS:
		/* TCP flags/mask. */
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_tcpfl(npc, n);
		break;
	case NPF_OPCODE_ICMP4:
		/* ICMP type/code. */
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_icmp4(npc, n);
		break;
	case NPF_OPCODE_ICMP6:
		/* ICMP type/code. */
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_icmp6(npc, n);
		break;
	case NPF_OPCODE_IP6_RT:
		/* ICMP route type */
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_ip6_rt(npc, n);
		break;
	case NPF_OPCODE_PROTO:
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_proto(npc, n);
		break;
	case NPF_OPCODE_ETHERPCP:
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_pcp(nbuf, n);
		break;
	case NPF_OPCODE_ETHERADDR:
	{
		char mac[8];
		i_ptr = nc_fetch_word(i_ptr, &d);
		i_ptr = nc_fetch_double(i_ptr,
					(uint32_t *)&mac[0],
					(uint32_t *)&mac[4]);
		cmpval = npf_match_mac(nbuf, d, mac);
	}
		break;
	case NPF_OPCODE_ADDRFAM:
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_ip_fam(npc, n);
		break;
	case NPF_OPCODE_FRAGMENT:
		cmpval = npf_match_ip_frag(npc);
		break;
	case NPF_OPCODE_MATCHDSCP:
		i_ptr = nc_fetch_double(i_ptr, &n, &i);
		cmpval = npf_match_dscp(npc, ((uint64_t) i) << 32 | n);
		break;
	case NPF_OPCODE_ETHERTYPE:
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_etype(nbuf, n);
		break;
	case NPF_OPCODE_RPROC:
		i_ptr = nc_fetch_word(i_ptr, &n);
		cmpval = npf_match_rproc(npc, nbuf, rl, ifp, dir, se);
		break;
	case _NPF_OPCODE_LAST:
		/* Invalid instruction. */
		goto fail;
	}
	goto process_next;
fail:
	/* Failure case. */
	return -1;
}

/*
 * nc_ptr_check: validate that instruction pointer is not out of range.
 * If not - advance by number of arguments and fetch specified argument.
 */
static int
nc_ptr_check(uintptr_t *iptr, const void *nc, size_t sz,
	     u_int nargs, uint32_t *val)
{
	const uint32_t *tptr = (const uint32_t *)*iptr;
	u_int i;

	if ((uintptr_t)tptr < (uintptr_t)nc)
		return NPF_ERR_JUMP;

	if ((uintptr_t)tptr + (nargs * sizeof(uint32_t)) > (uintptr_t)nc + sz)
		return NPF_ERR_RANGE;

	for (i = 0; i < nargs; i++) {
		if (val)
			val[i] = *tptr;
		tptr++;
	}
	*iptr = (uintptr_t)tptr;
	return 0;
}

static int
nc_noperands_check(uint n1, uint n2)
{
	return (n1 != n2) ? NPF_ERR_INVAL : 0;
}

/*
 * nc_insn_check: validate the instruction and its arguments.
 */
static int
nc_insn_check(const uintptr_t optr, const void *nc, size_t sz,
    size_t *adv, size_t *jmp, bool *ret)
{
	uintptr_t iptr = optr;
	uint32_t opcode;
	uint noperands;
	uint32_t operand[NPF_NOPERANDS_MAX] = {0};
	int error;

	/* Fetch the opcode */
	error = nc_ptr_check(&iptr, nc, sz, 1, &opcode);
	if (error)
		return error;

	noperands = npf_ncode_opcode_noperands(opcode);
	if (noperands > NPF_NOPERANDS_MAX)
		return NPF_ERR_INVAL;

	/* Prefetch the operands */
	error = nc_ptr_check(&iptr, nc, sz, noperands, operand);

	*ret = false;
	*jmp = 0;

	/*
	 * Verify the expected number of operands, and verify operand values
	 * where possible
	 */
	switch (opcode) {
	/*
	 * RISC-like instructions.
	 */
	case NPF_OPCODE_BEQ:
	case NPF_OPCODE_BNE:
		error = nc_noperands_check(noperands, 1);
		if (error)
			break;
		/* Validate jump address. */

		/*
		 * We must check for JMP 0 i.e. to oneself.  Pass the jump
		 * address to the caller, it will validate if it is correct.
		 */
		if (!error && operand[0] == 0)
			error = NPF_ERR_JUMP;
		if (!error)
			*jmp = operand[0] * sizeof(uint32_t);
		break;

	case NPF_OPCODE_RET:
		error = nc_noperands_check(noperands, 1);
		*ret = true;
		break;
	/*
	 * CISC-like instructions.
	 */
	case NPF_OPCODE_IP4MASK:
		error = nc_noperands_check(noperands, 3);
		if (error)
			break;
		if (!operand[2] || (operand[2] > 32 &&
				    operand[2] != NPF_NO_NETMASK))
			error = NPF_ERR_INVAL;
		break;
	case NPF_OPCODE_IP6MASK:
		error = nc_noperands_check(noperands, 6);
		if (error)
			break;
		if (!operand[5] || (operand[5] > NPF_MAX_NETMASK &&
				    operand[5] != NPF_NO_NETMASK))
			error = NPF_ERR_INVAL;
		break;
	case NPF_OPCODE_TABLE:
		error = nc_noperands_check(noperands, 2);
		if (error)
			break;
		if (!npf_addrgrp_tid_valid(operand[1]))
			error = NPF_ERR_TABLE;
		break;
	case NPF_OPCODE_PORTS:
		error = nc_noperands_check(noperands, 2);
		if (error)
			break;
		uint16_t port_start, port_end;

		port_start = operand[1] >> 16;
		port_end = operand[1] & 0xffff;
		if (!port_start || !port_end || port_start > port_end)
			error = NPF_ERR_PORT;
		break;
	case NPF_OPCODE_TCP_FLAGS:
		error = nc_noperands_check(noperands, 1);
		break;
	case NPF_OPCODE_ICMP4:
	case NPF_OPCODE_ICMP6:
	case NPF_OPCODE_IP6_RT:
		error = nc_noperands_check(noperands, 1);
		break;
	case NPF_OPCODE_PROTO:
		error = nc_noperands_check(noperands, 1);
		if (error)
			break;
		uint8_t alen;

		alen = (operand[0] >> 8) & 0xff;

		if (alen != 0 && alen != 4 && alen != 16)
			error = NPF_ERR_ALEN;
		break;
	case NPF_OPCODE_ETHERPCP:
		error = nc_noperands_check(noperands, 1);
		break;
	case NPF_OPCODE_ETHERADDR:
		error = nc_noperands_check(noperands, 3);
		break;
	case NPF_OPCODE_FRAGMENT:
		error = nc_noperands_check(noperands, 0);
		break;
	case NPF_OPCODE_ADDRFAM:
		error = nc_noperands_check(noperands, 1);
		if (operand[0] != AF_INET && operand[0] != AF_INET6)
			error = NPF_ERR_AF;
		break;
	case NPF_OPCODE_MATCHDSCP:
		error = nc_noperands_check(noperands, 2);
		break;
	case NPF_OPCODE_ETHERTYPE:
		error = nc_noperands_check(noperands, 1);
		break;
	case NPF_OPCODE_RPROC:
		error = nc_noperands_check(noperands, 1);
		break;
	case _NPF_OPCODE_LAST:
		/* Invalid instruction. */
		error = NPF_ERR_OPCODE;
	}
	if (error) {
		return error;
	}
	*adv = iptr - optr;
	return 0;
}

/*
 * nc_jmp_check: validate that jump address points to the instruction.
 * Loop from the beginning of n-code until we hit jump address or error.
 */
static inline int
nc_jmp_check(const void *nc, size_t sz, const uintptr_t jaddr)
{
	uintptr_t iaddr = (uintptr_t)nc;
	int error;

	assert(iaddr != jaddr);
	do {
		size_t _jmp, adv;
		bool _ret;

		error = nc_insn_check(iaddr, nc, sz, &adv, &_jmp, &_ret);
		if (error) {
			break;
		}
		iaddr += adv;

	} while (iaddr != jaddr);

	return error;
}

/*
 * npf_ncode_validate: validate n-code.
 * Performs the following operations:
 *
 * - Checks that each instruction is valid (i.e. existing opcode).
 * - Checks that jumps are within n-code and to the instructions.
 * - Checks that n-code returns, and processing is within n-code memory.
 */
int
npf_ncode_validate(const void *nc, size_t sz, int *errat)
{
	const uintptr_t nc_end = (uintptr_t)nc + sz;
	uintptr_t iptr = (uintptr_t)nc;
	int error;
	bool ret;

	do {
		size_t jmp, adv;

		/* Validate instruction and its arguments. */
		error = nc_insn_check(iptr, nc, sz, &adv, &jmp, &ret);
		if (error)
			break;

		/* If jumping, check that address points to the instruction. */
		if (jmp && nc_jmp_check(nc, sz, iptr + jmp)) {
			/* Note: the actual error might be different. */
			return NPF_ERR_JUMP;
		}

		/* Advance and check for the end of n-code memory block. */
		iptr += adv;

	} while (iptr != nc_end);

	if (!error) {
		error = ret ? 0 : NPF_ERR_RANGE;
	}
	*errat = (iptr - (uintptr_t)nc) / sizeof(uint32_t);
	return error;
}
