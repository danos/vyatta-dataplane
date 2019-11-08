/*
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_LOG_H_
#define _CGN_LOG_H_

/* subscriber session start */
void cgn_log_subscriber_start(uint32_t addr);

/* subscriber session end */
void cgn_log_subscriber_end(uint32_t addr,
			    uint64_t start_time, uint64_t end_time,
			    uint64_t pkts_out, uint64_t bytes_out,
			    uint64_t pkts_in, uint64_t bytes_in,
				    uint64_t sessions);

/*
 * Log subscriber reaching max-blocks-per-user limit.
 *
 * Logged when CGN_MBU_ENOSPC occurs.  Controlled by csp->srp_mbpu_full.
 */
void cgn_log_subscriber_mbpu_full(uint32_t addr, uint16_t block_count,
				  uint16_t mbpu);
void cgn_log_subscriber_mbpu_avail(uint32_t addr, uint16_t block_count,
				   uint16_t mbpu);

/*
 * Log no free blocks on a public address
 *
 * Logged when CGN_BLK_ENOSPC occurs.  Controlled by apm->apm_pb_full
 */
void cgn_log_public_pb_full(uint32_t addr, uint16_t blocks_used,
			    uint16_t nblocks);
void cgn_log_public_pb_avail(uint32_t addr, uint16_t blocks_used,
			     uint16_t nblocks);

/* Port block allocation and release */
void cgn_log_pb_alloc(uint32_t pvt_addr, uint32_t pub_addr,
		      uint16_t port_start, uint16_t port_end,
		      uint64_t start_time);

void cgn_log_pb_release(uint32_t pvt_addr, uint32_t pub_addr,
			uint16_t port_start, uint16_t port_end,
			uint64_t start_time, uint64_t end_time);

#endif
