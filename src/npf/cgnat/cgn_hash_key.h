/*
 * Copyright (c) 2019-2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#ifndef _CGN_HASH_KEY_H_
#define _CGN_HASH_KEY_H_

#include <stdint.h>

/*
 * Key for CGNAT 3-tuple hash table
 *
 * The expired flag is included in the hash key since we do *not* want to
 * match on expired sessions.
 *
 * k_ifindex should be set from cgn_if_key_index() when the key is used to
 * create or lookup sessions.   This may be different than ifp->if_index.
 *
 * Note that any op-mode commands that use a key structure to filter sessions
 * should set k_ifindex to ifp->if_index since it will be compared with
 * cs_ifindex in the sessions.
 */
struct cgn_3tuple_key {
	uint32_t  k_addr;     /* Address (net order) */
	uint32_t  k_ifindex;  /* Interface or intf group index */
	uint16_t  k_port;     /* port or id (net order) */
	uint8_t	  k_ipproto;  /* not cgn_proto */
	bool	  k_expired;  /* Expired session */
} __attribute__((__packed__));

/*
 * Key for CGNAT 2-tuple hash table
 *
 * The expired flag is included in the hash key since we do *not* want to
 * match on expired sessions.
 */
struct cgn_2tuple_key {
	uint32_t  k_addr;     /* Address (net order) */
	uint16_t  k_port;     /* port or id (net order) */
	bool	  k_expired;  /* Expired session */
	uint8_t   k_pad;      /* pad to multiple of 4 bytes */
} __attribute__((__packed__));

#endif /* _CGN_HASH_KEY_H_ */
