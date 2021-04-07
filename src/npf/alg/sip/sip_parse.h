/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _SIP_PARSE_H_
#define _SIP_PARSE_H_

#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"

struct sip_alg_request;
struct rte_mbuf;

int sip_alg_sdp_set_rtcp_attribute(struct sip_alg_request *sr,
				   int pos, npf_addr_t *taddr, uint8_t alen,
				   in_port_t tport);

/*
 * Parse the SDP "c=" and "m=" strings, and (if not in 'inspect' path)
 * translate the "c=" address.
 */
int sip_alg_manage_media(npf_session_t *se, npf_nat_t *nat,
			 struct sip_alg_request *sr);

/*
 * Parse a sip packet using the osip library.  We are only interested in
 * packets containing an SDP message. Returns a sip_alg_request structure if
 * successful.
 */
struct sip_alg_request *sip_alg_parse(struct npf_session *se,
				      npf_cache_t *npc, struct rte_mbuf *nbuf);

#endif
