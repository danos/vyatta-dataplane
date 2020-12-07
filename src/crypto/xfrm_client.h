/*
 * Copyright (c) 2020, AT&T Intellectual Property.  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#ifndef XFRM_CLIENT_H
#define XFRM_CLIENT_H

#include <czmq.h>
#include <linux/xfrm.h>
#include "control.h"
#include "crypto/crypto_sadb.h"

extern bool xfrm_direct;

struct xfrm_client_aux_data {
	vrfid_t  *vrf;
	bool ack_msg;
	uint32_t seq;
};

/*
 * Close all the client sockets for this source.
 */
void xfrm_client_unsubscribe(void);

int xfrm_client_init(void);

int xfrm_client_send_ack(uint32_t seq, int err);
int xfrm_client_send_sa_stats(uint32_t seq, uint32_t spi,
			      struct crypto_sadb_stats *stats);
int xfrm_client_send_expire(xfrm_address_t *dst, uint16_t family, uint32_t spi,
			    uint32_t reqid, uint8_t proto, uint8_t hard);
#endif /* XFRM_CLIENT_H */
