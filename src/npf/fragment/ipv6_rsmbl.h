/*
 * Copyright (c) 2017-2021, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2011-2016 by Brocade Communications Systems, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef IPV6_RSMBL_H
#define IPV6_RSMBL_H

#include <stdint.h>

#include "ipv4_rsmbl.h"  /* LAST_FRAG_IDX etc. */
#include "vrf_internal.h"

struct rte_mbuf;

/*
 * Max number of fragments per fragment set.  Must be at least 3.  8
 * would allow an MTU of 9000. 16 is the default value used by Cisco.
 */
#define IPV6_MAX_FRAGS_PER_SET  16

struct rte_mbuf *ipv6_handle_fragment(struct rte_mbuf *, uint16_t *npf_flag);

#endif /* IPV6_RSMBL_H */
