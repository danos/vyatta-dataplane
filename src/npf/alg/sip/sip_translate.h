/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _SIP_TRANSLATE_H_
#define _SIP_TRANSLATE_H_

#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"

struct sip_alg_request;
struct sip_alg_media;
struct rte_mbuf;

/*
 * Translates the media in the SDP "m=" strings
 */
int sip_alg_translate_media(struct sip_alg_request *sr,
			    struct sip_alg_media *m, int pos);

/*
 * Translates the media address in the SDP "c=" string
 */
void sip_alg_update_session_media(struct sip_alg_request *sr);

void sip_init_nat(struct sip_alg_request *sr, bool forw,
		  const npf_addr_t *taddr, const npf_addr_t *oaddr,
		  uint8_t alen, in_port_t tport, const int di);

/*
 * Translate a SIP packet
 */
int sip_alg_translate_packet(npf_session_t *se, npf_cache_t *npc,
			     npf_nat_t *ns, struct rte_mbuf *nbuf,
			     struct npf_alg *sip, const int di);

#endif /* _SIP_TRANSLATE_H_ */
