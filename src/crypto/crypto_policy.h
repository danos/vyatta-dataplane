/*-
 * Copyright (c) 2017-2021, AT&T Intellectual Property. All rights reserved.
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
 * Policy hash table size parameters. These must be powers of two.
 */
#define POLICY_RULE_HT_MAX_BUCKETS (1 << 19)
#define POLICY_RULE_HT_MIN_BUCKETS (1 << 10)

int crypto_policy_add(const struct xfrm_userpolicy_info *usr_policy,
		      const xfrm_address_t *dst,
		      const struct xfrm_user_tmpl *tmpl,
		      const struct xfrm_mark *mark, vrfid_t vrfid,
		      uint32_t seq, bool *send_ack);
int crypto_policy_update(const struct xfrm_userpolicy_info *usr_policy,
			 const xfrm_address_t *dst,
			 const struct xfrm_user_tmpl *tmpl,
			 const struct xfrm_mark *mark, vrfid_t vrfid,
			 uint32_t seq, bool *send_ack);
int crypto_policy_delete(const struct xfrm_userpolicy_id *id,
			 const struct xfrm_mark *mark, vrfid_t vrfid,
			 uint32_t seq, bool *send_ack);
struct crypto_vrf_ctx;
void crypto_policy_flush_vrf(struct crypto_vrf_ctx *vrf_ctx);
void crypto_policy_update_pending_if(struct ifnet *ifp);

int crypto_policy_init(void);

void crypto_incmpl_policy_init(void);
void crypto_incmpl_xfrm_policy_add(uint32_t ifindex, const struct nlmsghdr *nlh,
				   const struct xfrm_selector *sel,
				   const struct xfrm_mark *mark);
void crypto_incmpl_xfrm_policy_del(uint32_t ifindex, const struct nlmsghdr *nlh,
				   const struct xfrm_selector *sel,
				   const struct xfrm_mark *mark);
void crypto_incmpl_policy_make_complete(void);

void policy_feat_flush_vrf(struct crypto_vrf_ctx *vrf_ctx);

void crypto_npf_cfg_commit_flush(void);

#endif /* CRYPTO_POLICY_H */
