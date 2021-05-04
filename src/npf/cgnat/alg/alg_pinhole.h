/*
 * Copyright (c) 2021, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * alg_pinhole.h - ALG Pinhole table
 */

#ifndef ALG_PINHOLE_H
#define ALG_PINHOLE_H

#include <stdint.h>

#include "npf/cgnat/cgn_dir.h"
#include "npf/cgnat/cgn_map.h"
#include "npf/cgnat/alg/alg_defs.h"

struct alg_pinhole;
struct cgn_session;

/*
 * pinhole hash table key.  Ports and addresses are in network byte order.
 *
 * Must be multiple of 4-bytes since rte_jhash_32b is used to hash the key.
 */
struct alg_pinhole_key {
	uint32_t	pk_daddr;	/* Dest address */
	uint32_t	pk_saddr;	/* Src address */
	uint16_t	pk_did;		/* Dest port/ID */
	uint16_t	pk_sid;		/* Src port/ID */
	uint32_t	pk_vrfid;	/* VRF ID */
	uint8_t		pk_ipproto;	/* IP protocol */
	uint8_t		pk_expired;
	uint16_t	pk_pad1;
	uint32_t	pk_pad2;
};

static_assert((sizeof(struct alg_pinhole_key) % 4) == 0,
	      "struct alg_pinhole_key not multiple of 4");

/**
 * Create and add a CGNAT ALG pinhole table entry
 *
 * @param key 5 or 6 tuple pinhole key
 * @param cse Session pointer
 * @param alg_id ALG identifier
 * @param dir Direction in which pinhole expects to match a packet
 * @param timeout Timeout in seconds.  May be 0 in which case a default is
 *        used.
 * @param error Returns any error code to caller
 * @return Returns a pointer to the new pinhole
 */
struct alg_pinhole *alg_pinhole_add(const struct alg_pinhole_key *key,
				    struct cgn_session *cse,
				    enum cgn_alg_id alg_id, enum cgn_dir dir,
				    uint16_t timeout, int *error);

/**
 * Activate a new pinhole so that it is findable by packets
 *
 * @param Pointer to the new pinhole
 */
void cgn_alg_pinhole_activate(struct alg_pinhole *ap);

/**
 * Accessor to pinhole ALG ID
 */
enum cgn_alg_id alg_pinhole_alg_id(struct alg_pinhole *ap);

/**
 * Accessor to pinhole session pointer
 */
struct cgn_session *alg_pinhole_cse(struct alg_pinhole *ap);

/**
 * Accessor to pinhole direction
 */
enum cgn_dir alg_pinhole_dir(struct alg_pinhole *ap);

/**
 * Create pinhole table
 */
int alg_pinhole_init(void);

/**
 * Destroy pinhole table
 */
void alg_pinhole_uninit(void);

#endif /* ALG_PINHOLE_H */
