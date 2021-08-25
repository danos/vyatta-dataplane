/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_RPC_MSG_H_
#define _ALG_RPC_MSG_H_

/*
 * Structs for RPC ALG requests and replies.
 *
 * We only parse what we are interested in, not the full payload.
 * Note that all fields except for xid are in host order for
 * validation against header values
 *
 * An rpc_request structure is contained in the ALG session data.
 *
 * Setting rr_xid to 0 is used to invalidate any stored data in the RPC
 * Request info.
 */
struct rpc_request {
	uint32_t rr_xid;
	uint32_t rr_rpc_version;
	uint32_t rr_program;
	uint32_t rr_program_version;
	uint32_t rr_procedure;
	uint32_t rr_pmap_program;
};

struct rpc_reply {
	uint32_t rp_xid;
	uint32_t rp_reply_state;
	uint32_t rp_accept_state;
	uint32_t rp_port;
};

#endif /* ALG_RPC_MSG_H */
