/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

/*	$NetBSD: npf_disassemble.c,v 1.9 2012/08/13 01:18:32 rmind Exp $ */

/*-
 * Copyright (c) 2012 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: (LGPL-2.1-only AND BSD-2-Clause-NETBSD)
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Christos Zoulas.
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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>

/* add definitions that are in BSD but not in netinet/tcp.h */
#ifndef TH_ECE
#define	TH_ECE	0x40
#endif
#ifndef TH_CWR
#define	TH_CWR	0x80
#endif

#include "json_writer.h"
#include "npf/npf.h"
#include "npf/npf_addrgrp.h"
#include "npf/npf_disassemble.h"
#include "npf/npf_ncode.h"
#include "npf/npf_rule_gen.h"
#include "util.h"

enum npf_operand_type_enum {
	NPF_OPERAND_NONE,
	NPF_OPERAND_RET,
	NPF_OPERAND_VALUE,
	NPF_OPERAND_SD,
	NPF_OPERAND_REL_ADDRESS,
	NPF_OPERAND_NET_ADDRESS4,
	NPF_OPERAND_NET_ADDRESS6,
	NPF_OPERAND_SUBNET,
	NPF_OPERAND_TABLE_ID,
	NPF_OPERAND_ICMP_TYPE_CODE,
	NPF_OPERAND_TCP_FLAGS_MASK,
	NPF_OPERAND_PORT_RANGE,
	NPF_OPERAND_ETHER_ADDRESS,
	NPF_OPERAND_ADDRFAM,
	NPF_OPERAND_ETHERTYPE,
	NPF_OPERAND_RPROC,
	NPF_OPERAND_DSCP_SET,
	_NPF_OPERAND_LAST
};
#define NPF_OPERAND_MAX (_NPF_OPERAND_LAST - 1)

/*
 * Number of words per operand
 */
static const unsigned int npf_operand_nwords[] = {
	[NPF_OPERAND_NONE]           = 0,
	[NPF_OPERAND_RET]            = 1,
	[NPF_OPERAND_VALUE]          = 1,
	[NPF_OPERAND_SD]             = 1,
	[NPF_OPERAND_REL_ADDRESS]    = 1,
	[NPF_OPERAND_NET_ADDRESS4]   = 1,
	[NPF_OPERAND_NET_ADDRESS6]   = 4,
	[NPF_OPERAND_SUBNET]         = 1,
	[NPF_OPERAND_TABLE_ID]       = 1,
	[NPF_OPERAND_ICMP_TYPE_CODE] = 1,
	[NPF_OPERAND_TCP_FLAGS_MASK] = 1,
	[NPF_OPERAND_PORT_RANGE]     = 1,
	[NPF_OPERAND_ETHER_ADDRESS]  = 2,
	[NPF_OPERAND_ADDRFAM]        = 1,
	[NPF_OPERAND_ETHERTYPE]      = 1,
	[NPF_OPERAND_RPROC]          = 1,
	[NPF_OPERAND_DSCP_SET]       = 2,
};

static const struct npf_instruction {
	const char *name;
	uint8_t	    op[4];
} npf_instructions[] = {
	[NPF_OPCODE_RET] = {
		.name = "ret",
		.op = {
			[0] = NPF_OPERAND_RET,
		},
	},
	[NPF_OPCODE_BEQ] = {
		.name = "beq",
		.op = {
			[0] = NPF_OPERAND_REL_ADDRESS,
		},
	},
	[NPF_OPCODE_BNE] = {
		.name = "bne",
		.op = {
			[0] = NPF_OPERAND_REL_ADDRESS,
		},
	},
	[NPF_OPCODE_PROTO_FINAL] = {
		.name = "test proto-final",
		.op = {
			[0] = NPF_OPERAND_VALUE,
		},
	},
	[NPF_OPCODE_PROTO_BASE] = {
		.name = "test proto-base",
		.op = {
			[0] = NPF_OPERAND_VALUE,
		},
	},
	[NPF_OPCODE_ETHERADDR] = {
		.name = "test mac",
		.op = {
			[0] = NPF_OPERAND_SD,
			[1] = NPF_OPERAND_ETHER_ADDRESS
		},
	},
	[NPF_OPCODE_ETHERPCP] = {
		.name = "test pcp",
		.op = {
			[0] = NPF_OPERAND_VALUE,
		},
	},
	[NPF_OPCODE_IP4MASK] = {
		.name = "test ipv4-addr",
		.op = {
			[0] = NPF_OPERAND_SD,
			[1] = NPF_OPERAND_NET_ADDRESS4,
			[2] = NPF_OPERAND_SUBNET,
		},
	},
	[NPF_OPCODE_TABLE] = {
		.name = "test in table",
		.op = {
			[0] = NPF_OPERAND_SD,
			[1] = NPF_OPERAND_TABLE_ID,
		},
	},
	[NPF_OPCODE_ICMP4] = {
		.name = "test icmpv4-type",
		.op = {
			[0] = NPF_OPERAND_ICMP_TYPE_CODE,
		},
	},
	[NPF_OPCODE_IP6MASK] = {
		.name = "test ipv6-addr",
		.op = {
			[0] = NPF_OPERAND_SD,
			[1] = NPF_OPERAND_NET_ADDRESS6,
			[2] = NPF_OPERAND_SUBNET,
		},
	},
	[NPF_OPCODE_ICMP6] = {
		.name = "test icmpv6-type",
		.op = {
			[0] = NPF_OPERAND_ICMP_TYPE_CODE,
		},
	},
	[NPF_OPCODE_FRAGMENT] = {
		.name = "test fragment",
		.op = {
			[0] = NPF_OPERAND_NONE,
		},
	},
	[NPF_OPCODE_ADDRFAM] = {
		.name = "test addr-family",
		.op = {
			[0] = NPF_OPERAND_ADDRFAM,
		},
	},
	[NPF_OPCODE_IP6_RT] = {
		.name = "test ipv6-route",
		.op = {
			[0] = NPF_OPERAND_VALUE,
		},
	},
	[NPF_OPCODE_PORTS] = {
		.name = "test port",
		.op = {
			[0] = NPF_OPERAND_SD,
			[1] = NPF_OPERAND_PORT_RANGE,
		},
	},
	[NPF_OPCODE_TTL] = {
		.name = "test ttl",
		.op = {
			[0] = NPF_OPERAND_VALUE,
		},
	},
	[NPF_OPCODE_TCP_FLAGS] = {
		.name = "test tcp-flags",
		.op = {
			[0] = NPF_OPERAND_TCP_FLAGS_MASK,
		},
	},
	[NPF_OPCODE_MATCHDSCP] = {
		.name = "test dscp",
		.op = {
			[0] = NPF_OPERAND_DSCP_SET,
		},
	},
	[NPF_OPCODE_ETHERTYPE] = {
		.name = "test ether-type",
		.op = {
			[0] = NPF_OPERAND_ETHERTYPE,
		},
	},
	[NPF_OPCODE_RPROC] = {
		.name = "match rproc",
		.op = {
			[0] = NPF_OPERAND_RPROC,
		},
	},
};

static uint npf_instruction_size = ARRAY_SIZE(npf_instructions);

static void
npf_tcpflags2str(char *buf, unsigned int tfl)
{
	int i = 0;

	if (tfl & TH_FIN)
		buf[i++] = 'F';
	if (tfl & TH_SYN)
		buf[i++] = 'S';
	if (tfl & TH_RST)
		buf[i++] = 'R';
	if (tfl & TH_PUSH)
		buf[i++] = 'P';
	if (tfl & TH_ACK)
		buf[i++] = 'A';
	if (tfl & TH_URG)
		buf[i++] = 'U';
	if (tfl & TH_ECE)
		buf[i++] = 'E';
	if (tfl & TH_CWR)
		buf[i++] = 'C';
	buf[i] = '\0';
}

static int
npf_ncode_operand(uint8_t operand, const uint32_t *nc_base,
		  const uint32_t *nc_pc,
		  size_t len, char *buf, size_t *used_buf_len,
		  const size_t total_buf_len)
{
	unsigned int advance;

	if (operand > NPF_OPERAND_MAX) {
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "ERROR: unknown operand %u", operand);
		return -1;
	}

	advance = npf_operand_nwords[operand];

	if (len < sizeof(uint32_t) * advance) {
		buf_app_printf(buf, used_buf_len, total_buf_len,
			      "ERROR: missing bytes in ncode");
		return -1;
	}

	switch (operand) {
	case NPF_OPERAND_NONE:
		break;

	case NPF_OPERAND_RET:
		if (*nc_pc == 0)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "match ");
		else if (*nc_pc == 1)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "no-match ");
		else
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%u ", *nc_pc);
		break;

	case NPF_OPERAND_VALUE:
		buf_app_printf(buf, used_buf_len, total_buf_len, "%u ", *nc_pc);
		break;

	case NPF_OPERAND_SD:
		buf_app_printf(buf, used_buf_len, total_buf_len, "%s%s ",
			       (*nc_pc & NC_MATCH_INVERT) ? "not " : "",
			       (*nc_pc & NC_MATCH_SRC) ? "src" : "dst");
		break;

	case NPF_OPERAND_REL_ADDRESS: {
		uint32_t abs_addr = nc_pc - nc_base + *nc_pc - 1;

		buf_app_printf(buf, used_buf_len, total_buf_len, "%02u: ",
			       abs_addr);
		break;
	}
	case NPF_OPERAND_NET_ADDRESS4: {
		char addr[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, nc_pc, addr, INET_ADDRSTRLEN);
		buf_app_printf(buf, used_buf_len, total_buf_len, "%s",
			       addr);
		break;
	}
	case NPF_OPERAND_NET_ADDRESS6: {
		char addr[INET6_ADDRSTRLEN];

		inet_ntop(AF_INET6, nc_pc, addr, INET6_ADDRSTRLEN);
		buf_app_printf(buf, used_buf_len, total_buf_len, "%s",
			       addr);
		break;
	}
	case NPF_OPERAND_ETHERTYPE:
		buf_app_printf(buf, used_buf_len, total_buf_len, "0x%04X ",
			       ntohs(*nc_pc));
		break;

	case NPF_OPERAND_ETHER_ADDRESS: {
		const uint8_t *c = (const uint8_t *)nc_pc;

		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "%02X:%02X:%02X:%02X:%02X:%02X ",
			       c[0], c[1], c[2], c[3], c[4], c[5]);
		break;
	}
	case NPF_OPERAND_SUBNET:
		if (*nc_pc != NPF_NO_NETMASK)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "/%u", *nc_pc);

		buf_app_printf(buf, used_buf_len, total_buf_len, " ");
		break;

	case NPF_OPERAND_RPROC:
		break;	/* parameter currently not used and always 0 */

	case NPF_OPERAND_TABLE_ID: {
		const uint32_t op = *nc_pc;
		const char *tname = npf_addrgrp_tid2name(op);

		if (tname)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%s - ", tname);
		buf_app_printf(buf, used_buf_len, total_buf_len, "%u ", op);
		break;
	}
	case NPF_OPERAND_ADDRFAM: {
		if (*nc_pc == AF_INET)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "inet ");
		else if (*nc_pc == AF_INET6)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "inet6 ");
		else
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%u ", *nc_pc);
		break;
	}
	case NPF_OPERAND_ICMP_TYPE_CODE: {
		const uint32_t op = *nc_pc;

		if (op & NC_ICMP_HAS_CLASS)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "class=%s",
				       NC_ICMP_GET_TYPE_FROM_OP(op) ?
				       "error" : "info");

		if (op & NC_ICMP_HAS_TYPE)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "%u", NC_ICMP_GET_TYPE_FROM_OP(op));
		else
			buf_app_printf(buf, used_buf_len, total_buf_len, "-");

		if (op & NC_ICMP_HAS_CODE)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       ":%u", NC_ICMP_GET_CODE_FROM_OP(op));

		buf_app_printf(buf, used_buf_len, total_buf_len, " ");
		break;
	}
	case NPF_OPERAND_TCP_FLAGS_MASK: {
		uint8_t tf = *nc_pc >> 8, tf_mask = *nc_pc & 0xff;
		char tf_buf[16], tfm_buf[16];

		npf_tcpflags2str(tf_buf, tf);
		npf_tcpflags2str(tfm_buf, tf_mask);
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "%s/%s ", tf_buf, tfm_buf);
		break;
	}
	case NPF_OPERAND_PORT_RANGE: {
		in_port_t p1 = *nc_pc >> 16, p2 = *nc_pc & 0xffff;

		buf_app_printf(buf, used_buf_len, total_buf_len, "%u", p1);

		if (p1 != p2)
			buf_app_printf(buf, used_buf_len, total_buf_len,
				       "-%u", p2);

		buf_app_printf(buf, used_buf_len, total_buf_len,
			       " ");
		break;
	}
	case NPF_OPERAND_DSCP_SET: {
		uint64_t dscp_set = ((uint64_t) nc_pc[1]) << 32 |
				    nc_pc[0];
		unsigned int val = 0;
		while (dscp_set) {
			if (dscp_set & 1ul)
				buf_app_printf(buf, used_buf_len,
					       total_buf_len, "%d ", val);
			dscp_set >>= 1;
			val++;
		}
		break;
	}
	default:
		buf_app_printf(buf, used_buf_len, total_buf_len,
			       "ERROR: unknown operand %u", operand);
		return -1;
	}

	return advance;
}

void
npf_json_ncode(const void *nc, size_t len, json_writer_t *json)
{
	const uint32_t *nc_base = nc;
	const uint32_t *nc_pc = nc_base;
	char buf[128];

	if (!nc_base)
		return;

	jsonw_name(json, "ncode");
	jsonw_start_array(json);

	while (len) {
		const struct npf_instruction *insn = NULL;
		uint32_t opcode;
		size_t used_buf_len = 0;
		size_t i;

		if (len < sizeof(opcode)) {
			snprintf(buf, sizeof(buf),
				 "ERROR: missing bytes in ncode");
			jsonw_string(json, buf);
			break;
		}

		buf_app_printf(buf, &used_buf_len, sizeof(buf),
			       "%02lu: ", nc_pc - nc_base);
		opcode = *nc_pc;
		if (opcode < npf_instruction_size)
			insn = &npf_instructions[opcode];

		if (insn == NULL || insn->name == NULL) {
			buf_app_printf(buf, &used_buf_len, sizeof(buf),
				 "ERROR: invalid opcode 0x%x", opcode);
			jsonw_string(json, buf);
			break;
		}

		buf_app_printf(buf, &used_buf_len, sizeof(buf),
			       "%s ", insn->name);
		len -= sizeof(opcode);
		nc_pc++;
		for (i = 0; i < ARRAY_SIZE(insn->op); i++) {
			int consumed;

			consumed = npf_ncode_operand(insn->op[i], nc_base,
						     nc_pc, len, buf,
						     &used_buf_len,
						     sizeof(buf));
			if (consumed < 0) {	/* error */
				jsonw_string(json, buf);
				jsonw_end_array(json);
				return;
			}
			len -= consumed * sizeof(*nc_pc);
			nc_pc += consumed;
		}
		buf[used_buf_len - 1] = '\0';	/* remove last space */
		jsonw_string(json, buf);
	}
	jsonw_end_array(json);
}
