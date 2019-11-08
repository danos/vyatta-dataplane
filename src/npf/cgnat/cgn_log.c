/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @file cgn_log.c - cgnat logging
 */

#include <errno.h>
#include <netinet/in.h>
#include <linux/if.h>

#include "compiler.h"
#include "if_var.h"
#include "util.h"
#include "soft_ticks.h"
#include "vplane_log.h"

#include "npf/cgnat/cgn.h"
#include "npf/cgnat/cgn_log.h"
#include "npf/cgnat/cgn_source.h"
#include "npf/cgnat/cgn.h"

#define ADDR_CHARS 16

/*
 * Log subscriber session start
 */
void cgn_log_subscriber_start(uint32_t addr)
{
	char str1[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"SUBSCRIBER_START subs-addr=%s start-time=%lu\n",
		cgn_addrstr(addr, str1, ADDR_CHARS),
		cgn_ticks2timestamp(soft_ticks));
}

/*
 * Log subscriber session end
 */
void cgn_log_subscriber_end(uint32_t addr, uint64_t start_time,
			    uint64_t end_time,
			    uint64_t pkts_out, uint64_t bytes_out,
			    uint64_t pkts_in, uint64_t bytes_in,
			    uint64_t sessions)
{
	char str1[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"SUBSCRIBER_END subs-addr=%s start-time=%lu "
		"end-time=%lu sessions=%lu forw=%lu/%lu back=%lu/%lu\n",
		cgn_addrstr(addr, str1, ADDR_CHARS),
		cgn_ticks2timestamp(start_time), cgn_ticks2timestamp(end_time),
		sessions, pkts_out, bytes_out, pkts_in, bytes_in);
}

/*
 * Log subscriber reaching max-blocks-per-user limit.
 *
 * Logged when CGN_MBU_ENOSPC occurs.  Controlled by csp->srp_pb_full.
 */
void cgn_log_subscriber_mbpu_full(uint32_t addr, uint16_t block_count,
				  uint16_t mbpu)
{
	char str1[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"MBPU_FULL subs-addr=%s blocks=%u mbpu=%u\n",
		cgn_addrstr(addr, str1, ADDR_CHARS), block_count, mbpu);
}

void cgn_log_subscriber_mbpu_avail(uint32_t addr, uint16_t block_count,
				   uint16_t mbpu)
{
	char str1[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"MBPU_AVAILABLE subs-addr=%s blocks=%u mbpu=%u\n",
		cgn_addrstr(addr, str1, ADDR_CHARS), block_count, mbpu);
}

/*
 * Log no free blocks on a public address
 *
 * Logged when CGN_BLK_ENOSPC occurs.  Controlled by apm->apm_pb_full
 */
void cgn_log_public_pb_full(uint32_t addr, uint16_t blocks_used,
			    uint16_t nblocks)
{
	char str1[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"PB_FULL pub-addr=%s blocks=%u/%u\n",
		cgn_addrstr(addr, str1, ADDR_CHARS), blocks_used, nblocks);
}

void cgn_log_public_pb_avail(uint32_t addr, uint16_t blocks_used,
			    uint16_t nblocks)
{
	char str1[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"PB_AVAILABLE pub-addr=%s blocks=%u/%u\n",
		cgn_addrstr(addr, str1, ADDR_CHARS), blocks_used, nblocks);
}

/*
 * Log port block allocation and release
 */
void cgn_log_pb_alloc(uint32_t pvt_addr, uint32_t pub_addr,
		      uint16_t port_start, uint16_t port_end,
		      uint64_t start_time)
{
	char str1[ADDR_CHARS];
	char str2[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"PB_ALLOCATED subs-addr=%s pub-addr=%s "
		"port=%u-%u start-time=%lu\n",
		cgn_addrstr(pvt_addr, str1, ADDR_CHARS),
		cgn_addrstr(pub_addr, str2, ADDR_CHARS),
		port_start, port_end, cgn_ticks2timestamp(start_time));
}

void cgn_log_pb_release(uint32_t pvt_addr, uint32_t pub_addr,
			uint16_t port_start, uint16_t port_end,
			uint64_t start_time, uint64_t end_time)
{
	char str1[ADDR_CHARS];
	char str2[ADDR_CHARS];

	RTE_LOG(NOTICE, CGNAT,
		"PB_RELEASED subs-addr=%s pub-addr=%s port=%u-%u "
		"start-time=%lu end-time=%lu\n",
		cgn_addrstr(pvt_addr, str1, ADDR_CHARS),
		cgn_addrstr(pub_addr, str2, ADDR_CHARS),
		port_start, port_end, cgn_ticks2timestamp(start_time),
		cgn_ticks2timestamp(end_time));
}
