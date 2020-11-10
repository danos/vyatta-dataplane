/*-
 * Copyright (c) 2017-2019, AT&T Intellectual Property. All rights reserved.
 * Copyright (c) 2015-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef CRYPTO_FORWARD_H
#define CRYPTO_FORWARD_H

#include <rte_ring.h>
#include <stdbool.h>

#include "nh_common.h"

/*
 * crypto_policy_check_outbound()
 *
 * Check to see whether a packet matches an IPsec policy and,
 * if so, handle it. For a match on an input policy, the packet
 * will be dropped if it is not marked as having been decrypted.
 * If the packet matches an output policy, it will be queued to
 * the crypto thread for encryption. If a feature attachment
 * point is configured, then a next hop pointing to the attach
 * point interface is returned and the output policy rule is
 * stored in packet metadata.
 *
 * This function returns true if the packet was consumed.
 * A return value of false indicates that the caller should
 * continue to process the packet.
 */
bool crypto_policy_check_outbound(struct ifnet *in_ifp,
				  struct rte_mbuf **mbuf,
				  uint32_t tbl_id,
				  uint16_t eth_type,
				  struct next_hop **nh);

/*
 * Call crypto_policy_check_inbound() for locally terminating
 * packets excluding IKE.
 */
bool crypto_policy_check_inbound_terminating(struct ifnet *in_ifp,
					     struct rte_mbuf **mbuf,
					     uint16_t eth_type);
/*
 * crypto_policy_post_features_outbound
 *
 * Encrypt and output a packet on a s2s feature attachment point interface.
 */
void crypto_policy_post_features_outbound(struct ifnet *vfp_ifp,
					  struct ifnet *in_ifp,
					  struct rte_mbuf *mbuf,
					  uint16_t proto);

#endif /* CRYPTO_FORWARD_H */
