/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf_ncgen.c,v 1.13 2012/07/19 21:52:29 spz Exp $	*/

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

/*
 * N-code generation interface.
 */

#include <assert.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "compiler.h"
#include "npf/npf.h"
#include "npf/npf_ncgen.h"
#include "npf/npf_ncode.h"
#include "vplane_log.h"

/* Reduce re-allocations by expanding in 64 byte blocks. */
#define	NC_ALLOC_MASK		(64 - 1)
#define	NC_ALLOC_ROUND(x)	(((x) + NC_ALLOC_MASK) & ~NC_ALLOC_MASK)

struct nc_ctx {
	/*
	 * Original buffer address, size of the buffer and instruction
	 * pointer for appending n-code fragments.
	 */
	void		*nc_buf;
	void		*nc_iptr;
	uint32_t	nc_len;
	/* Expected number of words for diagnostic check. */
	uint32_t	nc_expected;
	/* List of jump values, length of the memory and iterator. */
	ptrdiff_t	 *nc_jmp_list;
	uint32_t	nc_jmp_len;
	uint32_t	nc_jmp_it;
	/* Current logical operation for a group and saved iterator. */
	uint32_t	nc_saved_it;
};

/*
 * npf_ncgen_getptr: return the instruction pointer and make sure that
 * buffer is large enough to add a new fragment of a given size.
 */
static uint32_t *
npf_ncgen_getptr(nc_ctx_t *ctx, uint32_t nwords)
{
	uint32_t offset, reqlen;

	/* Save the number of expected words for diagnostic check. */
	assert(ctx->nc_expected == 0);
	ctx->nc_expected = (sizeof(uint32_t) * nwords);

	/*
	 * Calculate the required length.  If buffer size is large enough,
	 * just return the pointer.
	 */
	offset = (uintptr_t)ctx->nc_iptr - (uintptr_t)ctx->nc_buf;
	assert(offset <= ctx->nc_len);
	reqlen = offset + ctx->nc_expected;
	if (reqlen < ctx->nc_len) {
		return ctx->nc_iptr;
	}

	/* Otherwise, re-allocate the buffer and update the pointers. */
	ctx->nc_len = NC_ALLOC_ROUND(reqlen);
	ctx->nc_buf = realloc(ctx->nc_buf, ctx->nc_len);
	ctx->nc_iptr = (uint8_t *)ctx->nc_buf + offset;
	return ctx->nc_iptr;
}

/*
 * npf_ncgen_putptr: perform a diagnostic check whether expected words
 * were appended and save the instruction pointer.
 */
static void
npf_ncgen_putptr(nc_ctx_t *ctx, void *nc)
{
	ptrdiff_t diff = (uintptr_t)nc - (uintptr_t)ctx->nc_iptr;

	if ((ptrdiff_t)ctx->nc_expected != diff) {
		RTE_LOG(ERR, FIREWALL, "unexpected n-code fragment size "
		    "(expected words %u, diff %td)\n", ctx->nc_expected, diff);
		return;
	}
	ctx->nc_expected = 0;
	ctx->nc_iptr = nc;
}

/*
 * npf_ncgen_addjmp: add the compare/jump opcode, dummy value and
 * its pointer into the list.
 */
static void
npf_ncgen_addjmp(nc_ctx_t *ctx, uint32_t **nc_ptr)
{
	uint32_t reqlen, i = ctx->nc_jmp_it++;
	uint32_t *nc = *nc_ptr;

	reqlen = NC_ALLOC_ROUND(ctx->nc_jmp_it * sizeof(ptrdiff_t));

	if (reqlen > NC_ALLOC_ROUND(ctx->nc_jmp_len)) {
		ctx->nc_jmp_list = realloc(ctx->nc_jmp_list, reqlen);
		ctx->nc_jmp_len = reqlen;
	}

	/* Save the offset (note: we cannot save the pointer). */
	ctx->nc_jmp_list[i] = (uintptr_t)nc - (uintptr_t)ctx->nc_buf;

	/* Note: if OR grouping case, BNE will be replaced with BEQ. */
	*nc++ = NPF_OPCODE_BNE;
	*nc++ = 0xdeadbeef;
	*nc_ptr = nc;
}

/*
 * npf_ncgen_create: new n-code generation context.
 */
nc_ctx_t *
npf_ncgen_create(void)
{
	return calloc(sizeof(nc_ctx_t), 1);
}

/*
 * called to free the context due to no longer wanting the ncode
 * (e.g. due to errors or be optimised away).
 */
void
npf_ncgen_free(nc_ctx_t *ctx)
{
	if (ctx) {
		free(ctx->nc_buf);
		free(ctx->nc_jmp_list);
		free(ctx);
	}
}

uint32_t
npf_ncgen_size(nc_ctx_t *ctx)
{
	return (uintptr_t)ctx->nc_iptr - (uintptr_t)ctx->nc_buf;
}

/*
 * npf_ncgen_complete: complete generation, destroy the context and
 * return a pointer to the final buffer containing n-code.
 */
void *
npf_ncgen_complete(nc_ctx_t *ctx, uint32_t *sz)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);
	ptrdiff_t foff;
	uint32_t i;

	assert(ctx->nc_saved_it == 0);

	/* Success path (return 0). */
	*nc++ = NPF_OPCODE_RET;
	*nc++ = 0;

	/* Failure path (return 1). */
	foff = ((uintptr_t)nc - (uintptr_t)ctx->nc_buf) / sizeof(uint32_t);
	*nc++ = NPF_OPCODE_RET;
	*nc++ = 1;

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);

	/* Change the jump values. */
	for (i = 0; i < ctx->nc_jmp_it; i++) {
		ptrdiff_t off = ctx->nc_jmp_list[i] / sizeof(uint32_t);
		uint32_t *jmpop = (uint32_t *)ctx->nc_buf + off;
		uint32_t *jmpval = jmpop + 1;

		assert(foff > off);
		assert(*jmpop == NPF_OPCODE_BNE);
		assert(*jmpval == 0xdeadbeef);
		*jmpval = foff - off;
	}

	/* Return the buffer, destroy the context. */
	void *buf = ctx->nc_buf;
	*sz = (uintptr_t)ctx->nc_iptr - (uintptr_t)ctx->nc_buf;
	free(ctx->nc_jmp_list);
	free(ctx);
	return buf;
}

/*
 * npf_ncgen_group: begin a logical group.
 */
void
npf_ncgen_group(nc_ctx_t *ctx)
{
	assert(ctx->nc_expected == 0);
	assert(ctx->nc_saved_it == 0);
	ctx->nc_saved_it = ctx->nc_jmp_it;
}

/*
 * npf_ncgen_endgroup: end a logical group, fix up the code accordingly.
 */
void
npf_ncgen_endgroup(nc_ctx_t *ctx)
{
	uint32_t *nc;

	/* If there are no fragments or only one - nothing to do. */
	if ((ctx->nc_jmp_it - ctx->nc_saved_it) <= 1) {
		ctx->nc_saved_it = 0;
		return;
	}

	/* Append failure return for OR grouping. */
	nc = npf_ncgen_getptr(ctx, 2 /* words */);
	*nc++ = NPF_OPCODE_RET;
	*nc++ = 1;
	npf_ncgen_putptr(ctx, nc);

	/* Update any group jumps values on success to the current point. */
	uint32_t i;
	for (i = ctx->nc_saved_it; i < ctx->nc_jmp_it; i++) {
		ptrdiff_t off = ctx->nc_jmp_list[i] / sizeof(uint32_t);
		uint32_t *jmpop = (uint32_t *)ctx->nc_buf + off;
		uint32_t *jmpval = jmpop + 1;

		assert(*jmpop == NPF_OPCODE_BNE);
		assert(*jmpval == 0xdeadbeef);

		*jmpop = NPF_OPCODE_BEQ;
		*jmpval = nc - jmpop;
		ctx->nc_jmp_list[i] = 0;
	}

	/* Reset the iterator. */
	ctx->nc_jmp_it = ctx->nc_saved_it;
	ctx->nc_saved_it = 0;
}

/*
 * npf_gennc_v6cidr: fragment to match IPv6 CIDR.
 */
void
npf_gennc_v6cidr(nc_ctx_t *ctx, int opts, const npf_addr_t *netaddr,
		    const npf_netmask_t mask)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 9 /* words */);
	const uint32_t *addr = (const uint32_t *)netaddr;

	assert((mask && mask <= NPF_MAX_NETMASK) || mask == NPF_NO_NETMASK);

	/* OP, direction, netaddr/subnet (7 words) */
	*nc++ = NPF_OPCODE_IP6MASK;
	*nc++ = opts;
	*nc++ = addr[0];
	*nc++ = addr[1];
	*nc++ = addr[2];
	*nc++ = addr[3];
	*nc++ = mask;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 9 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * npf_gennc_v4cidr: fragment to match IPv4 CIDR.
 */
void
npf_gennc_v4cidr(nc_ctx_t *ctx, int opts, const npf_addr_t *netaddr,
		    const npf_netmask_t mask)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 6 /* words */);
	const uint32_t *addr = (const uint32_t *)netaddr;

	assert((mask && mask <= NPF_MAX_NETMASK) || mask == NPF_NO_NETMASK);

	/* OP, direction, netaddr/subnet (4 words) */
	*nc++ = NPF_OPCODE_IP4MASK;
	*nc++ = opts;
	*nc++ = addr[0];
	*nc++ = mask;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 6 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * npf_gennc_mac_addr: match mac address
 */
void
npf_gennc_mac_addr(nc_ctx_t *ctx, int opts, struct rte_ether_addr *addr)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 6 /* words */);

	*nc++ = NPF_OPCODE_ETHERADDR;
	*nc++ = opts;	/* NC_MATCH_SRC set means src, otherwise dst */
	/*
	 * MAC address stored in two 32-bit words, so ensure the
	 * last (unused) bytes are zero.
	 */
	nc[1] = 0;
	memcpy(nc, addr, RTE_ETHER_ADDR_LEN);
	nc += 2;

	npf_ncgen_addjmp(ctx, &nc);

	/*  + 6 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * Match address family
 */
void
npf_gennc_addrfamily(nc_ctx_t *ctx, int family)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);

	*nc++ = NPF_OPCODE_ADDRFAM;
	*nc++ = family;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * Match a packet fragment
 */
void
npf_gennc_ip_frag(nc_ctx_t *ctx)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 3 /* words */);

	/* assign tag here */
	*nc++ = NPF_OPCODE_FRAGMENT;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 3 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * npf_gennc_ports: fragment to match TCP or UDP ports.
 */
void
npf_gennc_ports(nc_ctx_t *ctx, int opts, in_port_t from, in_port_t to)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 5 /* words */);

	/* OP, direction, port range (3 words). */
	*nc++ = NPF_OPCODE_PORTS;
	/* NC_MATCH_INVERT NOTs the port match */
	*nc++ = opts;
	*nc++ = ((uint32_t)from << 16) | to;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 5 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * npf_gennc_ttl: fragment to match (IPv4 TTL / IPv6 HLIM).
 */
void
npf_gennc_ttl(nc_ctx_t *ctx, uint8_t ttl)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);

	/* OP, code, type (2 words) */
	*nc++ = NPF_OPCODE_TTL;
	*nc++ = ttl;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * Fragment to match (IPv4/IPv6) ICMP type and code.
 *
 * This can also match on 'class' of ICMP - 'info' or 'error'.
 * This by having class=true, and treating 'type' as a boolean
 * flag with true meaning 'error'.
 */
void
npf_gennc_icmp(nc_ctx_t *ctx, int type, int code, bool ipv4, bool class)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);
	uint32_t tc = 0;

	/* OP, code, type (2 words) */
	*nc++ = ipv4 ? NPF_OPCODE_ICMP4 : NPF_OPCODE_ICMP6;
	if (class) {
		tc |= NC_ICMP_HAS_CLASS | NC_ICMP_SET_TYPE_IN_OP(type);
	} else {
		if (type != -1)
			tc |= NC_ICMP_HAS_TYPE | NC_ICMP_SET_TYPE_IN_OP(type);
		if (code != -1)
			tc |= NC_ICMP_HAS_CODE | NC_ICMP_SET_CODE_IN_OP(code);
	}
	*nc++ = tc;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * npf_gennc_ip6_rt: match IPv6-route header type
 */
void
npf_gennc_ip6_rt(nc_ctx_t *ctx, uint8_t type)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);

	/* OP, code, type (2 words) */
	*nc++ = NPF_OPCODE_IP6_RT;
	*nc++ = type;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * npf_gennc_tbl: fragment to match IPv4 source/destination address of
 * the packet against table specified by ID.
 */
void
npf_gennc_tbl(nc_ctx_t *ctx, int opts, uint32_t tableid)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 5 /* words */);

	/* OP, direction, table ID (3 words). */
	*nc++ = NPF_OPCODE_TABLE;
	*nc++ = opts;
	*nc++ = tableid;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 5 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * npf_gennc_tcpfl: fragment to match TCP flags/mask.
 */
void
npf_gennc_tcpfl(nc_ctx_t *ctx, uint8_t tf, uint8_t tf_mask)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);

	/* OP, code, type (2 words) */
	*nc++ = NPF_OPCODE_TCP_FLAGS;
	*nc++ = (tf << 8) | tf_mask;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * npf_gennc_proto_final: match the L4 protocol.
 */
void
npf_gennc_proto_final(nc_ctx_t *ctx, uint8_t proto_final)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);

	/* OP, code, type (2 words) */
	*nc++ = NPF_OPCODE_PROTO_FINAL;
	*nc++ = proto_final;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 * npf_gennc_proto_base: match the protocol in IPv4 or IPv6 header
 */
void
npf_gennc_proto_base(nc_ctx_t *ctx, uint8_t proto_base)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);

	/* OP, code, type (2 words) */
	*nc++ = NPF_OPCODE_PROTO_BASE;
	*nc++ = proto_base;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}

void
npf_ncgen_matchdscp(nc_ctx_t *ctx, uint64_t matchdscpset)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 5 /* words */);

	*nc++ = NPF_OPCODE_MATCHDSCP;
	*nc++ = matchdscpset & UINT32_MAX;
	*nc++ = matchdscpset >> 32;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	npf_ncgen_putptr(ctx, nc);
}

void
npf_gennc_etherpcp(nc_ctx_t *ctx, uint8_t pcp)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);

	/* OP, code, type (2 words) */
	*nc++ = NPF_OPCODE_ETHERPCP;
	*nc++ = pcp;

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 *  npf_gennc_ethertype: fragment to match ethertype.
 */
void
npf_gennc_ethertype(nc_ctx_t *ctx, uint16_t etype)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);

	/* OP, code, type (2 words) */
	*nc++ = NPF_OPCODE_ETHERTYPE;
	*nc++ = htons(etype);

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}

/*
 *  npf_gennc_rproc: if the rproc contributes to the match
 */
void
npf_gennc_rproc(nc_ctx_t *ctx, const char *rproc __unused)
{
	uint32_t *nc = npf_ncgen_getptr(ctx, 4 /* words */);

	/* OP, code, type (2 words) */
	*nc++ = NPF_OPCODE_RPROC;
	*nc++ = 0; /* NOTHING RIGHT NOW */

	/* Comparison block (2 words). */
	npf_ncgen_addjmp(ctx, &nc);

	/* + 4 words. */
	npf_ncgen_putptr(ctx, nc);
}
