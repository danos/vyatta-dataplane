/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CRYPTO_POLICY_H
#define CRYPTO_POLICY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/xfrm.h>

#include "util.h"

struct ifnet;
struct rte_mbuf;

/*
 * Policy tag map hash table size parameters. These must be powers of two.
 * Since we expect a small number policies, we keep the initial size of
 * the hash table small.
 */
#define POLICY_RULE_HT_MAX_BUCKETS 64
#define POLICY_RULE_HT_MIN_BUCKETS  8

int crypto_policy_add(const struct xfrm_userpolicy_info *usr_policy,
		      const xfrm_address_t *dst,
		      const struct xfrm_user_tmpl *tmpl,
		      const struct xfrm_mark *mark, vrfid_t vrfid);
int crypto_policy_update(const struct xfrm_userpolicy_info *usr_policy,
			 const xfrm_address_t *dst,
			 const struct xfrm_user_tmpl *tmpl,
			 const struct xfrm_mark *mark, vrfid_t vrfid);
void crypto_policy_delete(const struct xfrm_userpolicy_id *id,
			  const struct xfrm_mark *mark, vrfid_t vrfid);
struct crypto_vrf_ctx;
void crypto_policy_flush_vrf(struct crypto_vrf_ctx *vrf_ctx);
void crypto_policy_update_pending_if(struct ifnet *ifp);

int crypto_policy_init(void);

/*
 * Check if outbound policy is active  and return af/address if true
 */
bool crypto_policy_outbound_active(struct ifnet *in_ifp, struct rte_mbuf **mbuf,
				   uint32_t *af, void **addr,
				   uint16_t eth_type);

void crypto_incmpl_policy_init(void);
void crypto_incmpl_xfrm_policy_add(uint32_t ifindex, const struct nlmsghdr *nlh,
				   const struct xfrm_selector *sel,
				   const struct xfrm_mark *mark);
void crypto_incmpl_xfrm_policy_del(uint32_t ifindex, const struct nlmsghdr *nlh,
				   const struct xfrm_selector *sel,
				   const struct xfrm_mark *mark);
void crypto_incmpl_policy_make_complete(void);

void policy_feat_flush_vrf(struct crypto_vrf_ctx *vrf_ctx);
#endif /* CRYPTO_POLICY_H */
