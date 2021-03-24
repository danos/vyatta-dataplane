/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_RPC_H_
#define _ALG_RPC_H_

struct npf_session;
struct npf_cache;
struct apt_tuple;

/**
 * Setup RPC portmapper ALG parent session.  Called a new npf session is
 * created, and the destination port matches the configured RPC ALG port and
 * protocol is TCP or UDP.
 *
 * @param se Pointer to the parent session
 * @param nt Pointer to the ALG tuple (pinhole) that was matched
 * @return 0 if successful
 */
int rpc_alg_session_init(struct npf_session *se, struct apt_tuple *nt);

#endif
