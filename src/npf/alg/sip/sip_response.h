/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _SIP_RESPONSE_H_
#define _SIP_RESPONSE_H_

#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"

struct apt_tuple;
struct sip_tuple_data;
struct sip_alg_request;

/*
 * Detach tuple private data from alg tuple context, and release reference.
 */
void sip_tuple_data_detach(struct apt_tuple *nt);

/*
 * Create RTCP tuples.  Called when an RTP tuple is matched and an RTP session
 * created.
 */
void sip_alg_create_rtcp_tuples(npf_session_t *se, npf_cache_t *npc,
				struct sip_tuple_data *td);

int sip_manage_response(npf_session_t *se, npf_cache_t *npc,
			struct sip_alg_request *sr,
			struct sip_alg_request *tsr, npf_nat_t *nat);

#endif /* SIP_RESPONSE_H */
