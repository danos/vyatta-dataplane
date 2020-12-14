/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CRYPTO_SADB_H
#define CRYPTO_SADB_H

#include <stdint.h>
#include <linux/xfrm.h>
#include <openssl/evp.h>

#include "crypto_internal.h"
#include "util.h"

struct crypto_sadb_stats {
	uint64_t bytes;
	uint64_t packets;
};

struct crypto_vrf_ctx;
struct ifnet;
struct sadb_sa;

int crypto_sadb_init(void);
int crypto_sadb_vrf_init(struct crypto_vrf_ctx *vrf_ctx);
void crypto_sadb_vrf_clean(struct crypto_vrf_ctx *vrf_ctx);

void crypto_sadb_new_sa(const struct xfrm_usersa_info *sa_info,
			const struct xfrm_algo *crypto_algo,
			const struct xfrm_algo_auth *auth_trunc_algo,
			const struct xfrm_algo *auth_algo,
			const struct xfrm_encap_tmpl *tmpl,
			uint32_t mark_val, uint32_t extra_flags,
			vrfid_t vrf_id);

void crypto_sadb_del_sa(const struct xfrm_usersa_info *sa_info, vrfid_t vrfid);
void crypto_sadb_flush_vrf(struct crypto_vrf_ctx *vrf_ctx);

struct sadb_sa *sadb_lookup_inbound(uint32_t spi);

uint32_t crypto_sadb_get_mark_val(struct sadb_sa *sa);

void crypto_sadb_increment_counters(struct sadb_sa *sa,
				    uint32_t bytes,
				    uint32_t packets);

uint32_t crypto_sadb_get_reqid(struct sadb_sa *sa);
uint32_t crypto_sadb_get_family(struct sadb_sa *sa);
xfrm_address_t crypto_sadb_get_dst(struct sadb_sa *sa);

void crypto_sadb_mark_as_blocked(struct sadb_sa *sa);

void crypto_sadb_seq_drop_inc(struct sadb_sa *sa);
struct sadb_sa *sadb_lookup_sa_by_spi_in(uint32_t spi);
struct sadb_sa *sadb_lookup_sa_outbound(vrfid_t vrfid,
					const xfrm_address_t *dst,
					uint16_t family, uint32_t spi);
int crypto_spi_to_pmd_dev_id(uint32_t spi);
void crypto_sadb_feat_attach_in(uint32_t reqid, struct ifnet *ifp);
void crypto_incmpl_sa_init(void);
void crypto_incmpl_xfrm_sa_add(uint32_t ifindex, const struct nlmsghdr *nlh,
			       const struct xfrm_usersa_info *sa_info);
void crypto_incmpl_xfrm_sa_del(uint32_t ifindex, const struct nlmsghdr *nlh,
			       const struct xfrm_usersa_info  *sa_info);
void crypto_incmpl_sa_make_complete(void);

bool crypto_sadb_get_stats(vrfid_t vrf_id, xfrm_address_t addr,
			   uint16_t family, uint32_t spi,
			   struct crypto_sadb_stats *sa);
#endif /* CRYPTO_SADB_H */
