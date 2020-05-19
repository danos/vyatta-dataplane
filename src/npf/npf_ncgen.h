/*
 * Copyright (c) 2017-2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 */

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

#ifndef NPF_NCGEN_H
#define NPF_NCGEN_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "npf/npf.h"
#include "util.h"

struct rte_ether_addr;

/*
 * N-code generation interface.
 */

typedef struct nc_ctx nc_ctx_t;

nc_ctx_t *npf_ncgen_create(void);
void npf_ncgen_free(nc_ctx_t *ctx);
uint32_t npf_ncgen_size(nc_ctx_t *ctx);
void *npf_ncgen_complete(nc_ctx_t *ctx, uint32_t *sz);
void npf_ncgen_print(const void *, uint32_t);
void npf_ncgen_group(nc_ctx_t *ctx);
void npf_ncgen_endgroup(nc_ctx_t *ctx);
void npf_gennc_v6cidr(nc_ctx_t *ctx, int opts, const npf_addr_t *netaddr,
		      const npf_netmask_t mask);
void npf_gennc_v4cidr(nc_ctx_t *ctx, int opts, const npf_addr_t *netaddr,
		      const npf_netmask_t mask);
void npf_gennc_mac_addr(nc_ctx_t *ctx, int opts, struct rte_ether_addr *addr);
void npf_gennc_addrfamily(nc_ctx_t *ctx, int family);
void npf_gennc_ip_frag(nc_ctx_t *ctx);
void npf_gennc_ports(nc_ctx_t *ctx, int opts, in_port_t from, in_port_t to);
void npf_gennc_ttl(nc_ctx_t *ctx, uint8_t ttl);
void npf_gennc_icmp(nc_ctx_t *ctx, int type, int code, bool ipv4, bool class);
void npf_gennc_ip6_rt(nc_ctx_t *ctx, uint8_t type);
void npf_gennc_tbl(nc_ctx_t *ctx, int opts, u_int tableid);
void npf_gennc_tcpfl(nc_ctx_t *ctx, uint8_t tf, uint8_t tf_mask);
void npf_gennc_proto(nc_ctx_t *ctx, uint8_t proto);
void npf_ncgen_matchdscp(nc_ctx_t *ctx, uint64_t matchdscpset);
void npf_gennc_etherpcp(nc_ctx_t *ctx, uint8_t pcp);
void npf_gennc_ethertype(nc_ctx_t *ctx, uint16_t etype);
void npf_gennc_rproc(nc_ctx_t *ctx, const char *rproc);
#endif /* _NPF_NCGEN_H_ */
