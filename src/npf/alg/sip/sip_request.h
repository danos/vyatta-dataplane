/*
 * Copyright (c) 2020-2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _SIP_REQUEST_H_
#define _SIP_REQUEST_H_

#include "npf/npf.h"
#include "npf/alg/alg.h"
#include "npf/npf_cache.h"
#include "npf/npf_nat.h"
#include "npf/npf_session.h"

struct sip_alg_request;
struct sip_alg_media;
struct sip_private;
struct rte_mbuf;
struct npf_alg;

/*
 * SIP media list
 */
struct sip_alg_media *sip_media_alloc(npf_session_t *se,
				      struct sip_alg_request *sr,
				      int m_proto);
void sip_media_free(struct sip_alg_media *m);
int sip_media_count(struct cds_list_head *h);

/*
 * SIP request alloc and free
 */
struct sip_alg_request *sip_alg_request_alloc(bool init_sip,
					      uint32_t if_idx);
void sip_alg_request_free(const struct npf_alg *sip,
			  struct sip_alg_request *sr);

void sip_expire_session_request(npf_session_t *se);
void sip_flush_session_request(struct npf_session *se);

/*
 * Manage SIP request
 */
int sip_manage_request(npf_session_t *se, npf_cache_t *npc,
		       struct sip_alg_request *sr,
		       struct sip_alg_request *tsr,
		       npf_nat_t *nat, bool *consumed);

/*
 * SIP request hash table
 */
struct sip_alg_request *sip_request_lookup_by_call_id(const struct npf_alg *sip,
						      uint32_t if_idx,
						      osip_call_id_t *call_id);
struct sip_alg_request *sip_request_lookup(const struct npf_alg *sip,
					   struct sip_alg_request *incoming);
void sip_request_lookup_and_expire(const struct npf_alg *sip,
				   struct sip_alg_request *incoming);
void sip_request_expire(struct sip_alg_request *sr);
void sip_destroy_ht(struct npf_alg *sip);
int sip_ht_create(struct sip_private *sp);
void sip_ht_gc(struct npf_alg *sip);


#endif
