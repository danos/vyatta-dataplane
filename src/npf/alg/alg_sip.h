/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _ALG_SIP_H_
#define _ALG_SIP_H_

struct npf_session;
struct npf_cache;
struct apt_tuple;

/**
 * Setup SIP ALG parent session.  Called a new npf session is created, and the
 * destination port matches the configured SIP ALG port and protocol is TCP or
 * UDP.
 *
 * @param se Pointer to the parent session
 * @param npc Pointer to the npf packet cache
 * @param nt Pointer to the ALG tuple (pinhole) that was matched
 * @param di Direction of packet relative to interface (in or out)
 * @return 0 if successful else -errno
 */
int sip_alg_session_init(struct npf_session *se, struct npf_cache *npc,
			 struct apt_tuple *nt, const int di);

/**
 * An SIP ALG session is being destroyed
 *
 * @param se Pointer to the session
 */
void sip_alg_session_destroy(struct npf_session *se);

#endif
